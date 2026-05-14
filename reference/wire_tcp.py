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
  wire_start_tcp_server(network_name, passphrase, bind_port=0, mode=None)
    -> {handle, port, identity_hash}
  wire_start_tcp_client(network_name, passphrase, target_host, target_port, mode=None)
    -> {handle, identity_hash}
  wire_set_interface_mode(handle, mode) -> {mode: str}
    Runtime mutation of the configured interface's mode (and its
    spawned children). Prefer the `mode=` param of wire_start_* when
    possible — that avoids a race between startup and first packet.
  wire_announce(handle, app_name, aspects=[], app_data="")
    -> {destination_hash, identity_hash}
  wire_poll_path(handle, destination_hash, timeout_ms=5000)
    -> {found: bool, hops: int | None}
  wire_request_path(handle, destination_hash) -> {sent: bool}
    Fire a path-request packet for dest_hash immediately (no early-skip
    guards), matching RNS.Transport.request_path's unconditional send.
  wire_read_path_entry(handle, destination_hash)
    -> {found, timestamp, expires, hops, next_hop, receiving_interface_name}
    Read the local path_table entry. timestamp/expires are milliseconds-
    since-epoch for symmetry with the Kotlin bridge.
  wire_has_discovery_path_request(handle, destination_hash) -> {found: bool}
    Membership test on RNS.Transport.discovery_path_requests — observable
    proof that a mode-gated recursive forward was triggered.
  wire_has_announce_table_entry(handle, destination_hash) -> {found: bool}
    Membership test on RNS.Transport.announce_table — observable for
    "a cached-announce re-emission has been scheduled".
  wire_read_path_random_hash(handle, destination_hash)
    -> {found: bool, random_hash: hex}
    Extract the 10-byte random_hash segment of the cached announce.
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


_ALLOWED_INTERFACE_MODES = frozenset({
    "full",
    "access_point",
    "accesspoint",
    "ap",
    "point_to_point",
    "pointtopoint",
    "ptp",
    "roaming",
    "boundary",
    "gateway",
    "gw",
})


def _normalize_mode(raw: str | None) -> str | None:
    """Normalize a free-form mode string to Python RNS's config-recognized
    synonyms. Returns None if the input was empty / unset.

    Raises ValueError for a non-empty value that isn't in the accepted set —
    silently falling back to FULL on typos would make a test that expected
    ROAMING semantics pass vacuously under FULL behavior.
    """
    if raw is None:
        return None
    s = raw.strip().lower()
    if not s:
        return None
    if s not in _ALLOWED_INTERFACE_MODES:
        raise ValueError(f"Unknown interface mode: {raw!r}")
    return s


def _write_ifac_ini(
    config_dir: str,
    iface_name: str | None,
    iface_block: str | None,
    network_name: str,
    passphrase: str,
    share_instance: bool = False,
    instance_name: str | None = None,
    mode: str | None = None,
    shared_instance_type: str | None = None,
    shared_instance_port: int | None = None,
    instance_control_port: int | None = None,
    rpc_key: str | None = None,
    enable_transport: bool = True,
):
    """Write a minimal RNS config.

    `iface_block` is the full interface type/target/port block; this helper
    adds the `[reticulum]` header, the shared IFAC fields (if any), and
    wraps the interface block. Pass `iface_name=None, iface_block=None` to
    omit the `[interfaces]` section entirely — used by the
    shared-instance-only client config (no on-wire interface, just attaches
    to a local master via TCP loopback).

    share_instance=True publishes this RNS as a shared instance so external
    daemons (lxmd) or other in-process bridge peers can attach. When
    shared_instance_type="tcp", the master listens on
    127.0.0.1:shared_instance_port and clients connect by setting the same
    type+port (cross-impl interop, since reticulum-kt's LocalClientInterface
    is TCP-based on Android/macOS). When shared_instance_type is unset (or
    "unix"), Python uses AF_UNIX abstract sockets keyed by instance_name —
    that path is fine for Python↔Python but not portable to reticulum-kt.

    enable_transport=False is required for shared-instance-client configs:
    Python forbids enabling transport on a process that's connecting to an
    upstream shared instance (Reticulum.py:418 sets __transport_enabled=False
    after attach), and the config-time check there would otherwise refuse
    the attach.
    """
    os.makedirs(config_dir, exist_ok=True)
    config_file = os.path.join(config_dir, "config")

    ifac_lines = ""
    if network_name:
        ifac_lines += f"    network_name = {network_name}\n"
    if passphrase:
        ifac_lines += f"    passphrase = {passphrase}\n"
    if mode:
        # Python RNS's config reader at Reticulum.py:619-647 has a bug in
        # the `interface_mode` branch: inside `if "interface_mode" in c`,
        # the final `elif` references `c["mode"]` (not `c["interface_mode"]`),
        # which KeyErrors when the config only sets `interface_mode` and not
        # `mode`. The `elif "mode" in c` fallback branch at line 634 is
        # internally consistent, so we write `mode = <name>` to avoid the
        # buggy code path entirely. The semantics are identical on both
        # sides — the same MODE_* constant is assigned.
        ifac_lines += f"    mode = {mode}\n"

    if share_instance and not instance_name and shared_instance_type != "tcp":
        raise ValueError(
            "share_instance=True requires instance_name (AF_UNIX); leaving "
            "it at the default 'default' would collide with parallel bridge "
            "processes. shared_instance_type='tcp' is the alternative — port "
            "is the namespace there."
        )

    share_value = "Yes" if share_instance else "No"
    instance_line = (
        f"  instance_name = {instance_name}\n"
        if share_instance and instance_name and shared_instance_type != "tcp"
        else ""
    )
    type_line = (
        f"  shared_instance_type = {shared_instance_type}\n"
        if share_instance and shared_instance_type
        else ""
    )
    port_line = (
        f"  shared_instance_port = {shared_instance_port}\n"
        if share_instance and shared_instance_port
        else ""
    )
    # instance_control_port pins the RPC listener Python brings up at
    # Reticulum.py:339 when is_shared_instance=True and use_af_unix=False.
    # Default 37429 collides across parallel master processes — same
    # rationale as the bind_port allocation, just for a different listener.
    control_port_line = (
        f"  instance_control_port = {instance_control_port}\n"
        if share_instance and instance_control_port
        else ""
    )
    # rpc_key pins the multiprocessing.connection authkey both sides use
    # for the shared-instance RPC channel (Reticulum.py:1132). Without
    # this, master and client derive distinct keys from their distinct
    # transport identities (line 336-337) and the client's first RPC call
    # — _used_destination_data, fired during link establishment — fails
    # with AuthenticationError. In production this is invisible because
    # the auto-detect path has both peers share a single configdir, hence
    # a single transport identity, hence a matching derived key. Tests
    # spawn the peers in distinct configdirs (separate bridge processes)
    # so we have to pin the key explicitly.
    rpc_key_line = (
        f"  rpc_key = {rpc_key}\n"
        if rpc_key
        else ""
    )
    transport_value = "Yes" if enable_transport else "No"

    interfaces_section = ""
    if iface_name and iface_block:
        interfaces_section = (
            "\n[interfaces]\n"
            f"  [[{iface_name}]]\n"
            f"{iface_block}"
            f"{ifac_lines}"
        )

    with open(config_file, "w") as f:
        f.write(
            "[reticulum]\n"
            f"  enable_transport = {transport_value}\n"
            f"  share_instance = {share_value}\n"
            f"{instance_line}"
            f"{type_line}"
            f"{port_line}"
            f"{control_port_line}"
            f"{rpc_key_line}"
            "  respond_to_probes = No\n"
            f"{interfaces_section}"
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
    # Default loglevel=CRITICAL keeps the bridge's stderr clean. Setting
    # CONFORMANCE_WIRE_DEBUG=1 bumps it to DEBUG, useful when tracking
    # down "topology didn't converge" style issues (are announces even
    # being forwarded?). Opt-in so the vast majority of tests stay quiet.
    debug_wire = bool(os.environ.get("CONFORMANCE_WIRE_DEBUG"))
    ll = RNS.LOG_DEBUG if debug_wire else RNS.LOG_CRITICAL
    RNS.loglevel = ll
    _shared_wire_rns = RNS.Reticulum(
        configdir=config_dir,
        loglevel=ll,
    )
    return _shared_wire_rns


def cmd_wire_start_tcp_server(params):
    """Bring up RNS with a single TCPServerInterface on 127.0.0.1.

    If bind_port=0 (default), pre-allocates a free port OS-side so both
    impls can use the same "tell me a usable port" contract. The
    returned `port` is what the client peer should connect to.

    share_instance (bool, default False): publish this RNS as a shared
    instance so external daemons (lxmd) or wire local-client peers can
    attach without spinning up their own Reticulum. The default mode is
    AF_UNIX abstract sockets keyed by an auto-generated `instance_name`
    (the LXMF-propagation use case). For cross-impl interop with
    reticulum-kt — whose LocalClientInterface only speaks TCP loopback —
    pass `share_instance_type="tcp"`; the master then listens on a
    second free port that the response surfaces as `shared_instance_port`,
    which `wire_start_local_client` consumes.
    """
    network_name = params.get("network_name") or ""
    passphrase = params.get("passphrase") or ""
    bind_port = int(params.get("bind_port", 0))
    share_instance = bool(params.get("share_instance", False))
    share_instance_type = params.get("share_instance_type")
    if share_instance_type is not None:
        share_instance_type = str(share_instance_type).lower()
        if share_instance_type not in ("tcp", "unix"):
            raise ValueError(
                f"share_instance_type must be 'tcp' or 'unix' (got {share_instance_type!r})"
            )
    mode = _normalize_mode(params.get("mode"))

    if bind_port == 0:
        bind_port = _allocate_free_port()

    # Allocate free ports for both the shared-instance LocalServerInterface
    # (data path) and the RPC control listener (Reticulum.py:340) so parallel
    # test runs don't collide. Python ignores these when use_af_unix=True
    # (the AF_UNIX path keys by instance_name instead). On macOS / wherever
    # use_af_unix() returns False, the defaults (37428/37429) are global and
    # any second master would EADDRINUSE on the control port even if
    # shared_instance_port was allocated freshly.
    #
    # rpc_key: the master and any local-client peer must use the same
    # multiprocessing.connection authkey or the client's first RPC call
    # (_used_destination_data, fired during link setup) raises
    # AuthenticationError. Generate fresh per-master and surface it so
    # wire_start_local_client can write it into the client's config.
    shared_instance_port = None
    instance_control_port = None
    rpc_key_hex: str | None = None
    if share_instance and share_instance_type == "tcp":
        shared_instance_port = _allocate_free_port()
        instance_control_port = _allocate_free_port()
        rpc_key_hex = secrets.token_hex(32)

    config_dir = tempfile.mkdtemp(prefix="rns_wire_server_")
    # instance_name must be unique per bridge process: the AF_UNIX abstract
    # namespace (\0rns/<name>) is global. Use the tail of the config dir
    # so it's stable within this process but distinct across parallel ones.
    instance_name = f"wire_{os.path.basename(config_dir)}"
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
        share_instance=share_instance,
        instance_name=instance_name if share_instance else None,
        mode=mode,
        shared_instance_type=share_instance_type,
        shared_instance_port=shared_instance_port,
        instance_control_port=instance_control_port,
        rpc_key=rpc_key_hex,
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
            "share_instance": share_instance,
            "instance_name": instance_name if share_instance else None,
            "share_instance_type": share_instance_type,
            "shared_instance_port": shared_instance_port,
            "instance_control_port": instance_control_port,
            "rpc_key": rpc_key_hex,
        }

    response = {
        "handle": handle,
        "port": bind_port,
        "identity_hash": identity_hash.hex(),
    }
    if share_instance:
        response["instance_name"] = instance_name
        if share_instance_type:
            response["share_instance_type"] = share_instance_type
        if shared_instance_port:
            response["shared_instance_port"] = shared_instance_port
        if instance_control_port:
            response["instance_control_port"] = instance_control_port
        if rpc_key_hex:
            response["rpc_key"] = rpc_key_hex
    return response


def cmd_wire_start_local_client(params):
    """Bring up RNS as a shared-instance client of an already-running master.

    No on-wire interface is configured; the client's only attachment is the
    local socket to the master. This is the originator side of the
    `[local client] → [shared master + TCP] → [remote dest]` topology used
    to exercise the master's transport-mode forwarding when a LINKREQUEST
    arrives via a LocalServerInterface.

    Required params:
      shared_instance_port (int): the master's TCP shared-instance port,
        as returned by wire_start_tcp_server when share_instance_type="tcp".

    Optional params:
      instance_control_port (int): the master's RPC control port. If
        unset the client falls through to Python's default (37429), which
        will collide with any other RNS process using defaults. Always
        plumb the master's value through for parallel-test isolation.
      rpc_key (hex str): the master's multiprocessing.connection authkey.
        Without this, the client's first RPC call to the master fails with
        AuthenticationError because both peers derived distinct keys from
        their distinct transport identities. Always plumb the master's
        rpc_key through.

    Python's __start_local_interface (Reticulum.py:373) auto-detects the
    role by trying LocalServerInterface first and falling back to
    LocalClientInterface on bind failure — so the master MUST be started
    before this is called, otherwise this peer would itself become the
    master and the test topology would be wrong. The bridge sanity-checks
    that the connect succeeded by asserting is_connected_to_shared_instance
    after start; mismatch raises a clear error rather than letting a
    silently-master-roled client confuse the test.
    """
    shared_instance_port = params.get("shared_instance_port")
    if not shared_instance_port:
        raise ValueError(
            "wire_start_local_client requires shared_instance_port (the "
            "master's TCP port from wire_start_tcp_server's response)"
        )
    shared_instance_port = int(shared_instance_port)
    instance_control_port = params.get("instance_control_port")
    if instance_control_port is not None:
        instance_control_port = int(instance_control_port)
    rpc_key = params.get("rpc_key")
    if rpc_key is not None:
        rpc_key = str(rpc_key)

    config_dir = tempfile.mkdtemp(prefix="rns_wire_localclient_")
    _write_ifac_ini(
        config_dir,
        iface_name=None,
        iface_block=None,
        network_name="",
        passphrase="",
        share_instance=True,
        shared_instance_type="tcp",
        shared_instance_port=shared_instance_port,
        instance_control_port=instance_control_port,
        rpc_key=rpc_key,
        enable_transport=False,
    )

    RNS = _get_rns()
    rns = _ensure_wire_rns_started(config_dir)

    if not getattr(rns, "is_connected_to_shared_instance", False):
        raise RuntimeError(
            f"wire_start_local_client expected to attach as a shared-instance "
            f"client on TCP port {shared_instance_port}, but ended up in role "
            f"is_shared_instance={getattr(rns, 'is_shared_instance', None)} / "
            f"is_standalone_instance={getattr(rns, 'is_standalone_instance', None)}. "
            f"The master likely wasn't started first."
        )

    identity_hash = RNS.Transport.identity.hash

    handle = secrets.token_hex(8)
    with _instances_lock:
        _instances[handle] = {
            "rns": rns,
            "config_dir": config_dir,
            "identity_hash": identity_hash,
            "role": "local_client",
            "shared_instance_port": shared_instance_port,
            "destinations": [],
        }

    return {
        "handle": handle,
        "identity_hash": identity_hash.hex(),
    }


def cmd_wire_start_tcp_client(params):
    """Bring up RNS with a single TCPClientInterface pointing at a remote."""
    network_name = params.get("network_name") or ""
    passphrase = params.get("passphrase") or ""
    target_host = params["target_host"]
    target_port = int(params["target_port"])
    mode = _normalize_mode(params.get("mode"))

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
        mode=mode,
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
    bytes into an in-memory queue keyed by destination_hash. Also accept
    any Resource transfers on the link and buffer their reassembled data.
    Tests poll via wire_link_poll (single-packet data) or
    wire_resource_poll (completed resources).

    Intended for the receiver-side peer in multi-hop link tests. The
    sender uses wire_link_open to establish the link, then either
    wire_link_send (single packet) or wire_resource_send (arbitrary-size
    data chunked via the Resource API).
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

    # Per-destination receive buffers.
    recv_buffer = []         # single-packet link data
    resource_buffer = []     # completed resources (bytes)
    recv_lock = threading.Lock()

    def on_link_established(link):
        def on_packet(message, packet):
            with recv_lock:
                recv_buffer.append(bytes(message))
        def on_resource_concluded(resource):
            # resource.data is a BytesIO-like object on complete resources.
            if getattr(resource, "status", None) == RNS.Resource.COMPLETE:
                data_blob = resource.data
                if hasattr(data_blob, "read"):
                    try:
                        data_blob.seek(0)
                    except Exception:
                        pass
                    payload = data_blob.read()
                else:
                    payload = bytes(data_blob)
                with recv_lock:
                    resource_buffer.append(payload)
        link.set_packet_callback(on_packet)
        # Accept any incoming Resource; buffer its data on completion.
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_concluded_callback(on_resource_concluded)

    destination.set_link_established_callback(on_link_established)

    # Announce immediately so the sender can learn a path via the transport.
    destination.announce()

    inst.setdefault("listeners", {})[destination.hash] = {
        "destination": destination,
        "identity": identity,
        "recv_buffer": recv_buffer,
        "resource_buffer": resource_buffer,
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

    # Pass callbacks at construction time so they're wired up before RNS's
    # background handshake thread can dispatch them — otherwise an immediate
    # reject (which can happen on fast loopback) would never be observed.
    link = RNS.Link(
        out_destination,
        established_callback=on_established,
        closed_callback=on_closed,
    )

    try:
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
    except BaseException:
        # Tear down on any failure path so the link doesn't linger in
        # Transport's link_table for the rest of the bridge process's
        # lifetime — otherwise a retry for the same destination would
        # create a second concurrent Link and confuse RNS's path lookup.
        try:
            link.teardown()
        except Exception:
            pass
        raise

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


def cmd_wire_resource_send(params):
    """Send arbitrary-size bytes over an established outbound Link via the
    Resource API, blocking until the transfer completes or times out.

    This exercises the same code path LXMF uses for image/file/media
    attachments in apps like Columba and Sideband. Data > link.mdu gets
    chunked into multiple link DATA packets and reassembled at the
    receiver. The receiver must have accepted resources on the link
    (wire_listen wires this up automatically).

    Returns {success, status, size}. `status` is the RNS Resource status
    code (COMPLETE=6, FAILED=7) at completion / timeout.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", ""))
    timeout_ms = int(params.get("timeout_ms", 30000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    done = threading.Event()
    final_status = [None]

    def on_done(resource):
        final_status[0] = getattr(resource, "status", None)
        done.set()

    resource = RNS.Resource(payload, link, callback=on_done)

    if not done.wait(timeout=timeout_ms / 1000.0):
        # Cancel the outbound resource so its worker threads / callbacks
        # don't continue touching `final_status` / `done` after we
        # return. Harmless under the current fresh-bridge-per-test
        # fixture, but prevents interference if a future fixture reuses
        # a bridge process across tests on the same link.
        try:
            resource.cancel()
        except Exception:
            pass
        raw_status = getattr(resource, "status", None)
        return {
            "success": False,
            # Use explicit None check rather than `... or -1` — a genuine
            # status of 0 (Resource.NONE) is falsy and would coerce to
            # -1 under the truthiness fallback.
            "status": int(raw_status) if raw_status is not None else -1,
            "size": len(payload),
            "timed_out": True,
        }

    status_value = final_status[0]
    success = status_value == RNS.Resource.COMPLETE
    return {
        "success": bool(success),
        "status": int(status_value) if status_value is not None else -1,
        "size": len(payload),
        "timed_out": False,
    }


def cmd_wire_resource_create(params):
    """Construct a real RNS.Resource on an established outbound Link and
    report its observable attributes — WITHOUT advertising or sending it.

    This is the honest, delegating replacement for the deleted synthetic
    resource_hash / resource_proof / resource_map_hash / resource_flags /
    resource_build_hashmap / resource_adv_* / resource_find_part /
    hashmap_pack commands. Those hand-rolled the hash compositions on top
    of hashlib because the byte-level bridge can't reach RNS.Resource; two
    of them had drifted from upstream (wrong operand order, truncated
    proof) and the conformance suite stayed green anyway. This command
    constructs the real object — real link, full real __init__ lifecycle —
    and reads what RNS itself computed. Nothing here is recomputed.

    `advertise=False` lets __init__ run to completion (random_hash + hash +
    truncated_hash + expected_proof + the hashmap of real packed parts)
    while keeping it inert — no advertisement, no transfer, no worker
    threads, nothing on the wire.

    Resource generates its own random_hash AND a separate data-stream
    random prefix internally and fresh, so two calls with byte-identical
    `data` return a different `hash` and different `parts`. The invariant
    tests in tests/wire/test_resource_invariants.py assert exactly that —
    on both the reference and the SUT.
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

    # Real RNS.Resource, real established link, full __init__ — just no
    # advertise/send. Every field below is read straight off the object.
    resource = RNS.Resource(payload, link, advertise=False)

    return {
        "hash": resource.hash.hex(),
        "truncated_hash": resource.truncated_hash.hex(),
        "random_hash": resource.random_hash.hex(),
        "expected_proof": resource.expected_proof.hex(),
        "hashmap": resource.hashmap.hex(),
        "num_parts": len(resource.parts),
        "encrypted": bool(resource.encrypted),
        "compressed": bool(resource.compressed),
        "split": bool(resource.split),
        "size": resource.size,
        "total_size": resource.total_size,
        # Packed wire bytes of each part — for the "two resources from
        # byte-identical input produce different encrypted output"
        # invariant (the data-stream random prefix + per-token IV).
        "parts": [p.raw.hex() for p in resource.parts],
    }


def cmd_wire_resource_poll(params):
    """Drain all completed Resource payloads received on a listener.

    Blocks up to timeout_ms for at least one completed resource; returns
    whatever's present at deadline. Paired with wire_listen, which sets
    up the listener to accept any resource and buffer completed ones.
    """
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    timeout_ms = int(params.get("timeout_ms", 30000))

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
            if listener["resource_buffer"]:
                out = [p.hex() for p in listener["resource_buffer"]]
                listener["resource_buffer"].clear()
                return {"resources": out}
        time.sleep(0.1)

    with listener["recv_lock"]:
        out = [p.hex() for p in listener["resource_buffer"]]
        listener["resource_buffer"].clear()
    return {"resources": out}


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


def _mode_string_to_int(mode: str):
    """Map a config-string mode to an RNS.Interfaces.Interface.MODE_* int.

    Python RNS's config parser does this same mapping in Reticulum.py:619-647;
    reproduced here so `wire_set_interface_mode` can mutate a running
    interface's mode field (which is an int constant, not a string).
    """
    RNS = _get_rns()
    IM = RNS.Interfaces.Interface.Interface
    mapping = {
        "full": IM.MODE_FULL,
        "access_point": IM.MODE_ACCESS_POINT,
        "accesspoint": IM.MODE_ACCESS_POINT,
        "ap": IM.MODE_ACCESS_POINT,
        "point_to_point": IM.MODE_POINT_TO_POINT,
        "pointtopoint": IM.MODE_POINT_TO_POINT,
        "ptp": IM.MODE_POINT_TO_POINT,
        "roaming": IM.MODE_ROAMING,
        "boundary": IM.MODE_BOUNDARY,
        "gateway": IM.MODE_GATEWAY,
        "gw": IM.MODE_GATEWAY,
    }
    return mapping[mode]


def _interfaces_matching_handle(rns, role: str):
    """Return the live RNS.Transport.interfaces entries that belong to this
    bridge's wire handle.

    A bridge process hosts at most one wire RNS singleton with exactly one
    configured interface (TCPServerInterface or TCPClientInterface) — plus
    any spawned children. This returns the configured interface AND all of
    its spawned children so `wire_set_interface_mode` can mutate every
    relevant mode field in one call (matching the Kotlin bridge's
    symmetric propagation to spawnedInterfaces).

    Python's `str(iface)` returns "TCPServerInterface[<name>/<addr>:<port>]"
    and the spawned child's `.name` is "Client on <parent name>". Match by
    the `.name` attribute directly — `str(iface)` wraps the name in a
    class-prefixed + address-suffixed form that breaks string prefix
    matching.
    """
    RNS = _get_rns()
    results = []
    for iface in list(RNS.Transport.interfaces):
        iface_name = getattr(iface, "name", "") or ""
        # Primary interface names set by cmd_wire_start_* are exactly
        # "Wire TCP Server" or "Wire TCP Client" (see the `iface_name`
        # argument to _write_ifac_ini). Spawned children (Python only:
        # TCPInterface.py:586) are named "Client on <parent.name>".
        if iface_name == "Wire TCP Server" or iface_name == "Wire TCP Client":
            results.append(iface)
            continue
        parent = getattr(iface, "parent_interface", None)
        parent_name = getattr(parent, "name", "") if parent is not None else ""
        if parent_name in ("Wire TCP Server", "Wire TCP Client"):
            results.append(iface)
    return results


def cmd_wire_set_interface_mode(params):
    """Runtime-mutate the mode of this bridge's configured wire interface.

    Preferred usage is to set the mode at `wire_start_tcp_*` time via the
    `mode` parameter (which lands in the config file before the interface
    starts). This command exists for tests that need to flip a mode after
    startup — e.g., to exercise a transition.

    Propagates to spawned child interfaces so that `receiving_interface`
    for already-established peer connections also reports the new mode.
    """
    handle = params["handle"]
    mode_str = _normalize_mode(params["mode"])
    if mode_str is None:
        raise ValueError("mode parameter is required and must be non-empty")
    mode_int = _mode_string_to_int(mode_str)

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    ifaces = _interfaces_matching_handle(inst["rns"], inst["role"])
    if not ifaces:
        raise RuntimeError(
            f"No live interfaces found for handle {handle} "
            f"(role={inst['role']}); cannot apply mode"
        )
    for iface in ifaces:
        iface.mode = mode_int

    return {"mode": mode_str}


def cmd_wire_request_path(params):
    """Send a raw path-request packet for `destination_hash`.

    Thin synchronous wrapper around RNS.Transport.request_path. Unlike the
    Kotlin `Transport.requestPath` which has `hasPath` / `too recent`
    guards, Python's `request_path` sends unconditionally — matching this
    command's contract of "always emit a packet on the wire".
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    RNS.Transport.request_path(destination_hash)
    return {"sent": True}


def cmd_wire_read_path_entry(params):
    """Return the path_table entry for `destination_hash`, or found=False.

    Fields mirror Python's IDX_PT_* layout, converted to the same field
    names the Kotlin bridge uses:
      timestamp, expires (both in milliseconds since epoch for cross-impl
      symmetry), hops, next_hop (hex), receiving_interface_name.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    entry = RNS.Transport.path_table.get(destination_hash)
    if entry is None:
        return {"found": False}

    # IDX_PT_TIMESTAMP = 0, IDX_PT_NEXT_HOP = 1, IDX_PT_HOPS = 2,
    # IDX_PT_EXPIRES = 3, IDX_PT_RANDBLOBS = 4, IDX_PT_RVCD_IF = 5,
    # IDX_PT_PACKET = 6 — see Transport.py:3274-3280.
    timestamp_sec = entry[0]
    next_hop = entry[1]
    hops = entry[2]
    expires_sec = entry[3]
    rvcd_if = entry[5]

    iface_name = str(rvcd_if) if rvcd_if is not None else None
    return {
        "found": True,
        # Python stores seconds-since-epoch floats; Kotlin stores
        # milliseconds-since-epoch longs. Normalize to ms here so the
        # cross-impl tests can compare expires - timestamp in the same
        # unit on both sides.
        "timestamp": int(timestamp_sec * 1000),
        "expires": int(expires_sec * 1000),
        "hops": int(hops),
        "next_hop": next_hop.hex() if next_hop is not None else "",
        "receiving_interface_name": iface_name,
    }


def cmd_wire_has_discovery_path_request(params):
    """Observable: has this transport forwarded a path request for dest?

    Exposes RNS.Transport.discovery_path_requests[dest] membership as a
    boolean so `test_discover_paths_for_mode_gating` can assert whether
    the interface's mode triggered the recursive-forwarding branch.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    return {
        "found": destination_hash in RNS.Transport.discovery_path_requests,
    }


def cmd_wire_has_announce_table_entry(params):
    """Membership test on `RNS.Transport.announce_table[dest]`.

    Path-request answering enqueues the cached announce into
    announce_table (Transport.py:2781) for re-transmission after
    PATH_REQUEST_GRACE. Absence immediately after a PR is the observable
    for "this transport refused to answer" (e.g., ROAMING loop-
    prevention, Transport.py:2731).
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    return {"found": destination_hash in RNS.Transport.announce_table}


def cmd_wire_tx_bytes(params):
    """Return sum of TX bytes across this bridge's configured interface
    and spawned children.

    Used as a model-agnostic "did this peer emit any wire traffic"
    signal for tests where introspecting internal announce_table /
    held_announces timing is impl-sensitive (Kotlin and Python restore
    held_announces entries at different points in the PR-answer flow,
    so a timestamp-based observable is unreliable across impls).
    """
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    ifaces = _interfaces_matching_handle(inst["rns"], inst["role"])
    total = sum(getattr(iface, "txb", 0) for iface in ifaces)
    return {"tx_bytes": int(total)}


def cmd_wire_read_announce_table_timestamp(params):
    """Return the `timestamp` field of RNS.Transport.announce_table[dest]
    as ms-since-epoch, or found=False.

    Unlike `wire_has_announce_table_entry` (pure membership), the
    timestamp lets tests distinguish "entry is the ORIGINAL announce
    rebroadcast slot that's still being retried" from "entry was
    REPLACED by a path-request answer". The path_request answering
    path inserts a fresh entry (Transport.py:2781) with `now` in the
    timestamp slot; unchanged timestamp means the PR's answer path
    was skipped (e.g., ROAMING loop-prevention).

    Python stores seconds-since-epoch floats; we scale to ms to match
    the Kotlin bridge's return type and `read_path_entry` convention.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    entry = RNS.Transport.announce_table.get(destination_hash)
    if entry is None:
        return {"found": False}
    # IDX_AT_TIMESTAMP = 0 (Transport.py:1755)
    return {"found": True, "timestamp": int(entry[0] * 1000)}


def cmd_wire_read_path_random_hash(params):
    """Extract the 10-byte random_hash from the cached announce packet
    stored against this destination's path entry.

    Proves cached-announce byte-identity for `test_path_response_reuses_
    cached_announce`: when B re-emits a cached announce in response to a
    path request, the random_hash bytes in the re-emitted announce MUST
    be the same bytes that were in the original announce — any
    regeneration would replace them with fresh random + fresh timestamp.

    Announce data layout (Identity.py, Destination.py):
      public_key[0:64] + name_hash[64:74] + random_hash[74:84] + ...
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    entry = RNS.Transport.path_table.get(destination_hash)
    if entry is None:
        return {"found": False}

    # IDX_PT_PACKET is a misleading constant name upstream: entry[6]
    # stores the announce's *packet hash* (bytes), NOT the Packet object
    # itself. Verified against upstream RNS.Transport.py:3027 where the
    # same slot is extracted into a local also named `packet_hash` and
    # passed to `get_cached_packet(...)` (which takes a hash).
    # Using an unambiguous name here to prevent readers from assuming
    # it's a Packet object and mis-debugging a future layout change.
    cached_announce_hash = entry[6]  # IDX_PT_PACKET (slot name, not contents)
    packet = RNS.Transport.get_cached_packet(cached_announce_hash, packet_type="announce")
    if packet is None:
        return {"found": False}
    packet.unpack()
    data = packet.data
    if len(data) < 84:
        raise RuntimeError(
            f"Cached announce data too short ({len(data)} < 84) for "
            f"{destination_hash.hex()}"
        )
    random_hash = data[74:84]
    return {"found": True, "random_hash": random_hash.hex()}


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
    "wire_start_local_client": cmd_wire_start_local_client,
    "wire_set_interface_mode": cmd_wire_set_interface_mode,
    "wire_announce": cmd_wire_announce,
    "wire_poll_path": cmd_wire_poll_path,
    "wire_request_path": cmd_wire_request_path,
    "wire_read_path_entry": cmd_wire_read_path_entry,
    "wire_has_discovery_path_request": cmd_wire_has_discovery_path_request,
    "wire_has_announce_table_entry": cmd_wire_has_announce_table_entry,
    "wire_read_announce_table_timestamp": cmd_wire_read_announce_table_timestamp,
    "wire_tx_bytes": cmd_wire_tx_bytes,
    "wire_read_path_random_hash": cmd_wire_read_path_random_hash,
    "wire_listen": cmd_wire_listen,
    "wire_link_open": cmd_wire_link_open,
    "wire_link_send": cmd_wire_link_send,
    "wire_link_poll": cmd_wire_link_poll,
    "wire_resource_send": cmd_wire_resource_send,
    "wire_resource_create": cmd_wire_resource_create,
    "wire_resource_poll": cmd_wire_resource_poll,
    "wire_stop": cmd_wire_stop,
}
