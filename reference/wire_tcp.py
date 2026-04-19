"""Wire-level TCP conformance commands (E2E IFAC interop harness).

Unlike behavioral_transport.py (MockInterface, zero-wire), this module spins
up a *real* Reticulum instance with a real TCP interface. Two bridges — one
server-role, one client-role — connect over loopback TCP with matching IFAC
configuration. Announces on one side are only observable on the other if
each side's IFAC bytes verify on the peer.

Motivated by reticulum-kt#29: Kotlin's native IFAC produced wire bytes that
Python's IFAC unmasker silently rejected. Byte-level primitive tests
(see tests/test_ifac.py) cover HKDF + Ed25519 + mask algorithm equality.
This module covers the layer above: full packet flow through a real RNS
instance and real TCP framing, reproducing the issue-#29 symptom end-to-end.

Commands:
  wire_start_tcp_server(network_name, passphrase, bind_port=0)
    -> {handle, port, identity_hash}
  wire_start_tcp_client(network_name, passphrase, target_host, target_port)
    -> {handle, identity_hash}
  wire_announce(handle, app_name, aspects=[], app_data="")
    -> {destination_hash, identity_hash}
  wire_poll_path(handle, destination_hash, timeout_ms=5000)
    -> {found: bool, hops: int | None}
  wire_stop(handle) -> {stopped: bool}

Each bridge process hosts at most one wire RNS singleton. Attempting a second
wire_start on the same bridge raises — spawn a fresh bridge subprocess for
the second peer. The pytest `wire_peers` fixture does exactly this.
"""

import os
import secrets
import shutil
import socket
import tempfile
import threading
import time


_shared_wire_rns = None
_shared_wire_config_dir = None

_instances = {}
_instances_lock = threading.Lock()


def _get_rns():
    """Return the real (not stub) RNS module.

    Imported lazily for the same reason behavioral_transport does it —
    the crypto-only code paths stub out RNS with fake modules, so we
    route through the bridge's full-RNS helper.
    """
    from bridge_server import _get_full_rns
    return _get_full_rns()


def _allocate_free_port() -> int:
    """Bind a loopback socket to port 0, read the OS-assigned port, close.

    There's a tiny race window between close and re-bind, but on localhost
    with a single test it's essentially never-observed. Same trick pytest-xdist
    and most network test frameworks use.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _write_ifac_ini(
    config_dir: str,
    iface_name: str,
    iface_block: str,
    network_name: str,
    passphrase: str,
):
    """Write a minimal RNS config with a single interface.

    `iface_block` is the full interface type/target/port block; this helper
    adds the `[reticulum]` header, the shared IFAC fields (if any), and
    wraps the interface block.
    """
    os.makedirs(config_dir, exist_ok=True)
    config_file = os.path.join(config_dir, "config")

    ifac_lines = ""
    if network_name:
        ifac_lines += f"    network_name = {network_name}\n"
    if passphrase:
        ifac_lines += f"    passphrase = {passphrase}\n"

    with open(config_file, "w") as f:
        f.write(
            "[reticulum]\n"
            "  enable_transport = Yes\n"
            "  share_instance = No\n"
            "  respond_to_probes = No\n"
            "\n"
            "[interfaces]\n"
            f"  [[{iface_name}]]\n"
            f"{iface_block}"
            f"{ifac_lines}"
        )


def _ensure_wire_rns_started(config_dir: str):
    """Start the wire-mode Reticulum singleton once per bridge process.

    Second calls with the same config are no-ops; second calls with a
    different config raise (RNS.Reticulum is a process-wide singleton).
    """
    global _shared_wire_rns, _shared_wire_config_dir
    RNS = _get_rns()

    if _shared_wire_rns is not None:
        if _shared_wire_config_dir != config_dir:
            raise RuntimeError(
                f"wire bridge already initialised with config_dir="
                f"{_shared_wire_config_dir}; cannot reconfigure to "
                f"{config_dir}. Spawn a fresh bridge subprocess for the "
                f"other peer role."
            )
        return _shared_wire_rns

    _shared_wire_config_dir = config_dir
    RNS.loglevel = RNS.LOG_CRITICAL
    _shared_wire_rns = RNS.Reticulum(
        configdir=config_dir,
        loglevel=RNS.LOG_CRITICAL,
    )
    return _shared_wire_rns


def cmd_wire_start_tcp_server(params):
    """Bring up RNS with a single TCPServerInterface on 127.0.0.1.

    If bind_port=0 (default), pre-allocates a free port OS-side so both
    impls can use the same "tell me a usable port" contract. The
    returned `port` is what the client peer should connect to.
    """
    network_name = params.get("network_name") or ""
    passphrase = params.get("passphrase") or ""
    bind_port = int(params.get("bind_port", 0))

    if bind_port == 0:
        bind_port = _allocate_free_port()

    config_dir = tempfile.mkdtemp(prefix="rns_wire_server_")
    iface_block = (
        "    type = TCPServerInterface\n"
        "    enabled = Yes\n"
        "    listen_ip = 127.0.0.1\n"
        f"    listen_port = {bind_port}\n"
    )
    _write_ifac_ini(
        config_dir,
        "Wire TCP Server",
        iface_block,
        network_name,
        passphrase,
    )

    RNS = _get_rns()
    rns = _ensure_wire_rns_started(config_dir)
    identity_hash = RNS.Transport.identity.hash

    handle = secrets.token_hex(8)
    with _instances_lock:
        _instances[handle] = {
            "rns": rns,
            "config_dir": config_dir,
            "identity_hash": identity_hash,
            "role": "server",
            "port": bind_port,
            "destinations": [],
        }

    return {
        "handle": handle,
        "port": bind_port,
        "identity_hash": identity_hash.hex(),
    }


def cmd_wire_start_tcp_client(params):
    """Bring up RNS with a single TCPClientInterface pointing at a remote."""
    network_name = params.get("network_name") or ""
    passphrase = params.get("passphrase") or ""
    target_host = params["target_host"]
    target_port = int(params["target_port"])

    config_dir = tempfile.mkdtemp(prefix="rns_wire_client_")
    iface_block = (
        "    type = TCPClientInterface\n"
        "    enabled = Yes\n"
        f"    target_host = {target_host}\n"
        f"    target_port = {target_port}\n"
    )
    _write_ifac_ini(
        config_dir,
        "Wire TCP Client",
        iface_block,
        network_name,
        passphrase,
    )

    RNS = _get_rns()
    rns = _ensure_wire_rns_started(config_dir)
    identity_hash = RNS.Transport.identity.hash

    handle = secrets.token_hex(8)
    with _instances_lock:
        _instances[handle] = {
            "rns": rns,
            "config_dir": config_dir,
            "identity_hash": identity_hash,
            "role": "client",
            "target_host": target_host,
            "target_port": target_port,
            "destinations": [],
        }

    return {"handle": handle, "identity_hash": identity_hash.hex()}


def cmd_wire_announce(params):
    """Create a fresh destination and announce it on all attached interfaces.

    Each announce uses a newly-generated Identity (separate from the
    Transport identity). That's the common pattern in production apps
    and avoids conflating the announcer with the interface operator.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    app_data_hex = params.get("app_data") or ""

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        app_name,
        *aspects,
    )

    app_data = bytes.fromhex(app_data_hex) if app_data_hex else None
    destination.announce(app_data=app_data)
    # Keep a reference so the destination/identity aren't GC'd before the
    # TX loop picks up the announce packet.
    inst["destinations"].append((identity, destination))

    return {
        "destination_hash": destination.hash.hex(),
        "identity_hash": identity.hash.hex(),
    }


def cmd_wire_poll_path(params):
    """Poll Transport.has_path until found or timeout.

    Returns {found: True, hops: N} as soon as the destination appears in
    the local path table. The presence of the path entry is the
    observable proof that the remote's announce arrived AND passed IFAC
    verification on this side.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    timeout_ms = int(params.get("timeout_ms", 5000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    deadline = time.time() + (timeout_ms / 1000.0)
    while time.time() < deadline:
        if RNS.Transport.has_path(destination_hash):
            hops = RNS.Transport.hops_to(destination_hash)
            return {"found": True, "hops": int(hops)}
        time.sleep(0.05)

    return {"found": False, "hops": None}


def cmd_wire_listen(params):
    """Register an IN SINGLE destination that accepts incoming Links.

    On link establishment, attach a packet callback that buffers received
    bytes into an in-memory queue keyed by destination_hash. Tests poll
    via wire_link_poll.

    Intended for the receiver-side peer in multi-hop link tests. The
    sender uses wire_link_open (below) to establish the link.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", [])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    identity = RNS.Identity()
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        app_name,
        *aspects,
    )

    # Per-destination receive buffer: list of raw bytes, appended on each
    # link-data callback. Protected by the instance's own state lock.
    recv_buffer = []
    recv_lock = threading.Lock()

    def on_link_established(link):
        def on_packet(message, packet):
            with recv_lock:
                recv_buffer.append(bytes(message))
        link.set_packet_callback(on_packet)

    destination.set_link_established_callback(on_link_established)

    # Announce immediately so the sender can learn a path via the transport.
    destination.announce()

    inst.setdefault("listeners", {})[destination.hash] = {
        "destination": destination,
        "identity": identity,
        "recv_buffer": recv_buffer,
        "recv_lock": recv_lock,
    }
    # Keep strong reference so it isn't garbage collected.
    inst["destinations"].append((identity, destination))

    return {
        "destination_hash": destination.hash.hex(),
        "identity_hash": identity.hash.hex(),
    }


def cmd_wire_link_open(params):
    """Open an outbound Link to a remote IN destination and wait for active.

    Requires the remote's identity to be known (via a received announce).
    Returns only after the link reaches ACTIVE state, or raises on timeout.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    timeout_ms = int(params.get("timeout_ms", 10000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    identity = RNS.Identity.recall(destination_hash)
    if identity is None:
        raise RuntimeError(
            f"No identity known for {destination_hash.hex()}; "
            f"ensure an announce for this destination was received first."
        )

    out_destination = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        app_name,
        *aspects,
    )

    established = threading.Event()
    closed_reason = [None]

    def on_established(_link):
        established.set()

    def on_closed(link):
        closed_reason[0] = getattr(link, "teardown_reason", "unknown")
        established.set()  # unblock the wait regardless of outcome

    link = RNS.Link(out_destination)
    link.set_link_established_callback(on_established)
    link.set_link_closed_callback(on_closed)

    if not established.wait(timeout=timeout_ms / 1000.0):
        raise TimeoutError(
            f"Link to {destination_hash.hex()} did not become active within "
            f"{timeout_ms}ms (teardown_reason={closed_reason[0]})"
        )
    if getattr(link, "status", None) != RNS.Link.ACTIVE:
        raise RuntimeError(
            f"Link to {destination_hash.hex()} closed before becoming active "
            f"(teardown_reason={closed_reason[0]}, status={getattr(link, 'status', None)})"
        )

    inst.setdefault("out_links", {})[link.link_id] = link
    return {"link_id": link.link_id.hex()}


def cmd_wire_link_send(params):
    """Send bytes over an established outbound Link.

    Python RNS doesn't expose `link.send(data)` directly — arbitrary
    link data is sent by constructing a Packet whose destination is
    the Link object itself and calling its .send(). That's the same
    path link.send_keepalive and link.send_request use internally.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", ""))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    packet = RNS.Packet(link, payload)
    packet.send()
    return {"sent": True}


def cmd_wire_link_poll(params):
    """Poll the receive buffer for a listening destination.

    Returns all packets received since the last poll (drained). Blocks up
    to timeout_ms waiting for at least one packet; returns whatever is
    present at deadline even if empty.
    """
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    timeout_ms = int(params.get("timeout_ms", 5000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    listener = inst.get("listeners", {}).get(destination_hash)
    if listener is None:
        raise ValueError(
            f"No listener registered for destination_hash={destination_hash.hex()}"
        )

    deadline = time.time() + (timeout_ms / 1000.0)
    while time.time() < deadline:
        with listener["recv_lock"]:
            if listener["recv_buffer"]:
                out = [p.hex() for p in listener["recv_buffer"]]
                listener["recv_buffer"].clear()
                return {"packets": out}
        time.sleep(0.05)

    with listener["recv_lock"]:
        out = [p.hex() for p in listener["recv_buffer"]]
        listener["recv_buffer"].clear()
    return {"packets": out}


def cmd_wire_stop(params):
    """Release resources for a wire-mode instance handle.

    Note: Python RNS.Reticulum is a process-wide singleton and cannot be
    fully torn down in-process, so we clean up bookkeeping and the
    tempdir but leave the singleton alive. Intended pattern: one wire
    test per bridge subprocess; the bridge dies with the fixture.
    """
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.pop(handle, None)
    if inst is None:
        return {"stopped": False}

    config_dir = inst.get("config_dir")
    if config_dir and os.path.isdir(config_dir):
        shutil.rmtree(config_dir, ignore_errors=True)

    return {"stopped": True}


WIRE_COMMANDS = {
    "wire_start_tcp_server": cmd_wire_start_tcp_server,
    "wire_start_tcp_client": cmd_wire_start_tcp_client,
    "wire_announce": cmd_wire_announce,
    "wire_poll_path": cmd_wire_poll_path,
    "wire_listen": cmd_wire_listen,
    "wire_link_open": cmd_wire_link_open,
    "wire_link_send": cmd_wire_link_send,
    "wire_link_poll": cmd_wire_link_poll,
    "wire_stop": cmd_wire_stop,
}
