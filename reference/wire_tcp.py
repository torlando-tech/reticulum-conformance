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

  --- Resource (segmentation / HMU / compression coverage) ---
  wire_resource_create(handle, link_id, data, force_sdu=None,
                       include_parts=True, auto_compress=True)
    -> {hash, truncated_hash, random_hash, expected_proof, hashmap, num_parts,
        total_segments, segment_index, encrypted, compressed, split, size,
        total_size, sdu, parts?}
    Builds a real RNS.Resource (advertise=False) and reads its attributes.
    force_sdu forces >74 parts (HMU threshold); a >1 MiB payload yields
    total_segments>1; a compressible payload yields compressed=True.

  --- Link lifecycle (status / STALE / teardown / keepalive) ---
  wire_link_status(handle, link_id)
    -> {status, status_name, teardown_reason, teardown_reason_name,
        no_inbound_for_ms, last_keepalive_ago_ms, keepalive_s, stale_time_s, rtt}
  wire_link_set_watchdog(handle, link_id, keepalive_s=None, stale_time_s=None)
    -> {keepalive_s, stale_time_s}   (compress timings; keepalive_s>=stale_time_s
       forces a deterministic ACTIVE->STALE->CLOSED/TIMEOUT teardown)
  wire_link_await_status(handle, link_id, target_status, timeout_ms=15000)
    -> link_status fields + {reached: bool}   (>= ordering; STALE also matches CLOSED)
  wire_link_teardown(handle, link_id) -> {torn_down: bool}   (graceful initiator close)
  wire_listener_link_status(handle, destination_hash, timeout_ms=0)
    -> link_status fields + {found, link_count}   (receiver-side inbound link)
  wire_set_proof_strategy(handle, destination_hash, strategy)
    -> {strategy, proof_strategy}   (strategy in {"all","app","none"})

  --- Channel (out-of-order / duplicate / window) ---
  wire_channel_inject(handle, link_id, envelopes=[{sequence:int, data:hex}])
    -> {injected: [int]}   (feeds crafted envelopes into Channel._receive)
  wire_channel_received(handle, link_id) -> {messages: [hex]}   (delivery order)
  wire_channel_window(handle, link_id)
    -> {window, window_min, window_max, window_flexibility,
        next_rx_sequence, next_sequence, rx_ring, tx_ring}

  --- GROUP destination symmetric crypto ---
  wire_group_create(handle, app_name, aspects=[], key=None)
    -> {destination_hash, key}
  wire_group_encrypt(handle, destination_hash, plaintext) -> {ciphertext}
  wire_group_decrypt(handle, destination_hash, ciphertext)
    -> {plaintext: hex|None, decrypted: bool}

  --- Identity ratchet crypto (enforce_ratchets rejection) ---
  wire_identity_keypair() -> {private_key, public_key, hash}
  wire_ratchet_keypair() -> {private_key, public_key}   (X25519)
  wire_identity_encrypt(public_key, plaintext, ratchet_pub=None) -> {ciphertext}
  wire_identity_decrypt(private_key, ciphertext, ratchets=[], enforce_ratchets=False)
    -> {plaintext: hex|None, decrypted: bool}

  --- IFAC (issue-29 golden vector via genuine RNS) ---
  wire_ifac_compute(handle, packet_data, ifac_size=None)
    -> {ifac_key, ifac_size, signature, ifac}
    Reads the live interface's RNS-derived ifac_identity/ifac_key and signs
    packet_data (Transport.transmit's exact computation).

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
    # enable_transport (default True) lets a test bring up a transport-DISABLED
    # shared master — the rnsd default posture, and the only way to exercise R3
    # (CONFORMANCE_GAPS.md §3): local-client forwarding BYPASSES transport_enabled
    # (Transport.py:1536/:1884/:2172/:2254). With this False + share_instance=True,
    # an attached local client's announces/links must still reach a TCP peer even
    # though Reticulum.transport_enabled() is False on the master; an impl that
    # gates local-client forwarding on transport_enabled black-holes them.
    enable_transport = bool(params.get("enable_transport", True))
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
        enable_transport=enable_transport,
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
            "enable_transport": enable_transport,
        }

    response = {
        "handle": handle,
        "port": bind_port,
        "identity_hash": identity_hash.hex(),
        # Surface the resolved transport posture so a test can assert it took
        # (and so wire_start_tcp_server(enable_transport=False) is self-
        # documenting in logs). RNS.Reticulum.transport_enabled() is the
        # ground-truth observable a test should pin, but echoing the config
        # value here lets the fixture record it without a second round-trip.
        "transport_enabled": bool(enable_transport),
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


def _pipe_command(read_fifo: str, write_fifo: str) -> str:
    """Build the PipeInterface `command` that bridges this peer to another via
    a pair of named FIFOs.

    PipeInterface writes RNS's OUTGOING bytes to the spawned command's STDIN
    and reads INCOMING bytes from its STDOUT. So the command must:
      - copy STDIN (RNS outgoing) into `write_fifo` (this peer -> other peer)
      - copy `read_fifo` (other peer -> this peer) into STDOUT (RNS incoming)
    The peer on the other end uses the same template with read/write swapped,
    so the two FIFOs cross-connect the two processes. Validated to carry
    announces + link establishment between two separate RNS processes over
    loopback (the only inter-process channel available to the separate-bridge-
    subprocess wire harness, which has no shared in-process Transport).
    """
    return f"bash -c 'cat {read_fifo} & cat > {write_fifo}'"


def _write_pipe_relay_config(
    config_dir: str,
    pipe_iface_name: str,
    read_fifo: str,
    write_fifo: str,
    tcp_listen_port: int | None,
    network_name: str,
    passphrase: str,
    enable_transport: bool,
):
    """Write an RNS config with a PipeInterface and (optionally) a
    TCPServerInterface in the SAME instance — the mixed interface-type relay
    used to exercise the in-transit link-MTU strip (CONFORMANCE_GAPS.md §2c).

    When tcp_listen_port is None this is a pipe-ONLY leaf peer (the A end);
    when set, this is the relay (the B middle) bridging a PipeInterface (to A)
    and a TCPServerInterface (to C). PipeInterface inherits Interface's
    AUTOCONFIGURE_MTU=False / FIXED_MTU=False, so a LINKREQUEST forwarded OUT
    the pipe has its 3-byte LINK_MTU_SIZE signalling field stripped.
    """
    os.makedirs(config_dir, exist_ok=True)
    ifac_lines = ""
    if network_name:
        ifac_lines += f"      network_name = {network_name}\n"
    if passphrase:
        ifac_lines += f"      passphrase = {passphrase}\n"

    pipe_block = (
        f"  [[{pipe_iface_name}]]\n"
        "    type = PipeInterface\n"
        "    enabled = Yes\n"
        f"    command = {_pipe_command(read_fifo, write_fifo)}\n"
        f"{ifac_lines}"
    )
    tcp_block = ""
    if tcp_listen_port is not None:
        tcp_block = (
            f"  [[{pipe_iface_name} TCP]]\n"
            "    type = TCPServerInterface\n"
            "    enabled = Yes\n"
            "    listen_ip = 127.0.0.1\n"
            f"    listen_port = {tcp_listen_port}\n"
            f"{ifac_lines}"
        )

    transport_value = "Yes" if enable_transport else "No"
    with open(os.path.join(config_dir, "config"), "w") as f:
        f.write(
            "[reticulum]\n"
            f"  enable_transport = {transport_value}\n"
            "  share_instance = No\n"
            "  respond_to_probes = No\n\n"
            "[interfaces]\n"
            f"{pipe_block}"
            f"{tcp_block}"
        )


def cmd_wire_start_pipe_peer(params):
    """Bring up RNS with a single PipeInterface bridged to a peer via FIFOs.

    The leaf (A) end of the mixed pipe<->TCP relay topology. read_fifo and
    write_fifo are named-FIFO paths the test fixture created; the peer on the
    other end of the pipe (the relay) uses the same two FIFOs with read/write
    swapped. enable_transport defaults False (a leaf host, not a transport
    node). Returns {handle, identity_hash}.
    """
    network_name = params.get("network_name") or ""
    passphrase = params.get("passphrase") or ""
    read_fifo = params["read_fifo"]
    write_fifo = params["write_fifo"]
    enable_transport = bool(params.get("enable_transport", False))

    config_dir = tempfile.mkdtemp(prefix="rns_wire_pipe_")
    _write_pipe_relay_config(
        config_dir,
        pipe_iface_name="Wire Pipe Peer",
        read_fifo=read_fifo,
        write_fifo=write_fifo,
        tcp_listen_port=None,
        network_name=network_name,
        passphrase=passphrase,
        enable_transport=enable_transport,
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
            "role": "pipe_peer",
            "destinations": [],
        }
    return {"handle": handle, "identity_hash": identity_hash.hex()}


def cmd_wire_start_pipe_tcp_relay(params):
    """Bring up RNS as a transport relay bridging a PipeInterface (to A) and a
    TCPServerInterface (to C) — the mixed interface-type middle node B.

    A LINKREQUEST arriving on one interface and forwarded out the other crosses
    interface types. When forwarded OUT the PipeInterface (which does not
    support MTU autoconfiguration), RNS strips the 3-byte LINK_MTU_SIZE
    signalling field (Transport.py:1593-1600) so the destination's link falls
    back to Reticulum.MTU (500). enable_transport defaults True (this node MUST
    be a transport node to forward). If bind_port=0 a free TCP port is
    allocated. Returns {handle, port, identity_hash}.
    """
    network_name = params.get("network_name") or ""
    passphrase = params.get("passphrase") or ""
    read_fifo = params["read_fifo"]
    write_fifo = params["write_fifo"]
    bind_port = int(params.get("bind_port", 0))
    enable_transport = bool(params.get("enable_transport", True))
    if bind_port == 0:
        bind_port = _allocate_free_port()

    config_dir = tempfile.mkdtemp(prefix="rns_wire_piperelay_")
    _write_pipe_relay_config(
        config_dir,
        pipe_iface_name="Wire Pipe Relay",
        read_fifo=read_fifo,
        write_fifo=write_fifo,
        tcp_listen_port=bind_port,
        network_name=network_name,
        passphrase=passphrase,
        enable_transport=enable_transport,
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
            "role": "pipe_tcp_relay",
            "port": bind_port,
            "destinations": [],
        }
    return {
        "handle": handle,
        "port": bind_port,
        "identity_hash": identity_hash.hex(),
    }


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


def cmd_wire_identity_recall(params):
    """Recall an Identity by destination hash from this instance's
    received-announces table.

    Delegates to real RNS.Identity.recall — the same static method apps
    (Columba's NomadNet browser, Sideband's conversation lookup, LXMF's
    LXMessage source/destination resolution) call after observing an
    announce. Returns the recalled identity's public_key (and hash) when
    found, or {found: False} when the destination hash is unknown to this
    instance (no announce received).

    Optionally polls Transport.has_path first, so the test can express
    "wait until the announce has been received, then recall." Without the
    poll the caller would have to sleep on raw timing.
    """
    RNS = _get_rns()
    handle = params["handle"]
    target_hash = bytes.fromhex(params["destination_hash"])
    timeout_ms = int(params.get("timeout_ms", 0))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    deadline = time.time() + (timeout_ms / 1000.0)
    identity = None
    while True:
        identity = RNS.Identity.recall(target_hash)
        if identity is not None:
            break
        if time.time() >= deadline:
            break
        time.sleep(0.05)

    if identity is None:
        return {"found": False}
    return {
        "found": True,
        "public_key": identity.get_public_key().hex(),
        "hash": identity.hash.hex(),
    }


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
    inbound_links = []        # RNS.Link objects accepted on this destination
    recv_lock = threading.Lock()

    def on_link_established(link):
        # Keep a reference to the inbound (receiver-side) Link so lifecycle
        # tests can observe its status / teardown_reason after the initiator
        # tears it down (DESTINATION/INITIATOR_CLOSED is only observable on
        # the *peer* of whoever called teardown). See wire_listener_link_status.
        with recv_lock:
            inbound_links.append(link)
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
        "inbound_links": inbound_links,
        "recv_lock": recv_lock,
    }
    # Keep strong reference so it isn't garbage collected.
    inst["destinations"].append((identity, destination))

    return {
        "destination_hash": destination.hash.hex(),
        "identity_hash": identity.hash.hex(),
        # public_key surfaces the listening identity's raw key so recall
        # tests can assert byte-identity (recalled.public_key == this), not
        # just length (N-M3). The hash above is a truncated SHA-256 of this
        # key, so asserting both pins the full key material end-to-end.
        "public_key": identity.get_public_key().hex(),
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

    Optional params for the segmentation / HMU / compression coverage cases
    (CONFORMANCE_REAUDIT.md §5 "Resource"):
      force_sdu (int): temporarily override the link's transfer SDU so a
        modest payload produces >74 parts, the threshold above which RNS
        sends the hashmap across multiple advertisements (HMU,
        ResourceAdvertisement.HASHMAP_MAX_LEN=74). The override is applied
        only for the duration of this construction and then restored, so the
        live link is left untouched. Lets a test assert num_parts>74 without
        moving a megabyte of data.
      include_parts (bool, default True): when False, omit the per-part
        `parts` list from the response. Set False for >1 MiB multi-segment
        payloads, where the first segment alone is thousands of parts and
        hex-encoding them all would bloat the JSON pipe.
      auto_compress (bool, default True): pass-through to RNS.Resource; the
        compressible-payload case relies on the default to observe
        compressed=True.

    A payload exceeding RNS.Resource.MAX_EFFICIENT_SIZE (1 MiB - 1) makes RNS
    split the transfer into total_segments>1; this command reports the first
    segment's attributes plus total_segments/segment_index, which is the
    observable a multi-segment test pins.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", ""))
    force_sdu = params.get("force_sdu")
    include_parts = bool(params.get("include_parts", True))
    auto_compress = bool(params.get("auto_compress", True))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    # Forced-small-MDU path: RNS.Resource derives its per-part SDU from the
    # link as `link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE` (Resource.py
    # __init__). Temporarily shrinking link.mtu to force_sdu + that overhead
    # makes the resource chunk at force_sdu bytes/part, so e.g. a 4 KiB
    # payload at force_sdu=50 exceeds the 74-part HMU threshold. mtu must
    # stay a valid int (RNS.Packet construction reads it), so we shrink it
    # rather than null it, and restore it after — the live link's negotiated
    # MTU is untouched once this returns.
    saved_mtu = None
    restore_link = False
    if force_sdu is not None:
        force_sdu = int(force_sdu)
        overhead = RNS.Reticulum.HEADER_MAXSIZE + RNS.Reticulum.IFAC_MIN_SIZE
        saved_mtu = link.mtu
        restore_link = True
        link.mtu = force_sdu + overhead

    try:
        # Real RNS.Resource, real established link, full __init__ — just no
        # advertise/send. Every field below is read straight off the object.
        resource = RNS.Resource(payload, link, advertise=False, auto_compress=auto_compress)
    finally:
        if restore_link:
            link.mtu = saved_mtu

    out = {
        "hash": resource.hash.hex(),
        "truncated_hash": resource.truncated_hash.hex(),
        "random_hash": resource.random_hash.hex(),
        "expected_proof": resource.expected_proof.hex(),
        "hashmap": resource.hashmap.hex(),
        "num_parts": len(resource.parts),
        "encrypted": bool(resource.encrypted),
        "compressed": bool(resource.compressed),
        "split": bool(resource.split),
        # total_segments>1 is the observable that a >1 MiB payload triggered
        # multi-segment transfer (Resource.py: total_segments derived from
        # total_size // MAX_EFFICIENT_SIZE). segment_index is which segment
        # this object represents (1-based).
        "total_segments": int(resource.total_segments),
        "segment_index": int(resource.segment_index),
        "size": resource.size,
        "total_size": resource.total_size,
        "sdu": int(resource.sdu),
    }
    if include_parts:
        # Packed wire bytes of each part — for the "two resources from
        # byte-identical input produce different encrypted output"
        # invariant (the data-stream random prefix + per-token IV).
        out["parts"] = [p.raw.hex() for p in resource.parts]
    return out


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


def _find_destination_by_hash(inst, dest_hash):
    """Linear scan inst["destinations"] for a destination matching hash.

    The destinations list holds (identity, destination) tuples (see
    cmd_wire_listen). Tests rarely register more than a handful of
    destinations per peer, so a scan is fine.
    """
    for _identity, destination in inst.get("destinations", []):
        if destination.hash == dest_hash:
            return destination
    return None


# Per-(handle, dest_hash, path) request handler state. The fixed response
# bytes the generator returns, plus a log of invocations so tests can
# verify the handler ran with the expected request data.
_request_handler_responses = {}
_request_handler_log = {}


def cmd_wire_register_request_handler(params):
    """Register a Destination request handler that returns fixed bytes.

    Delegates to real RNS.Destination.register_request_handler. The handler
    receives a real RNS request invocation (path, data, request_id,
    link_id, remote_identity, requested_at) from the real Link request
    machinery — we just plug in a generator that returns the test-supplied
    response and records the invocation for later assertion.

    Optional auth policy: pass `allow` as "all" (default) or "list" plus
    `allowed_identity_hashes` (list of hex strings). RNS rejects requests
    from un-listed identities before the generator runs — the invocation
    log will not record those, which is exactly what the ALLOW_LIST
    negative-control test asserts.
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    path = params["path"]
    response = bytes.fromhex(params["response"]) if params.get("response") else b""
    allow_param = params.get("allow", "all")
    allowed_list_hex = params.get("allowed_identity_hashes", []) or []

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    destination = _find_destination_by_hash(inst, dest_hash)
    if destination is None:
        raise ValueError(
            f"No registered destination with hash {dest_hash.hex()} on "
            f"handle {handle}; call wire_listen first."
        )

    if allow_param == "all":
        allow = RNS.Destination.ALLOW_ALL
        allowed_list = None
    elif allow_param == "list":
        allow = RNS.Destination.ALLOW_LIST
        allowed_list = [bytes.fromhex(h) for h in allowed_list_hex]
    else:
        raise ValueError(f"unsupported allow: {allow_param!r} (use 'all' or 'list')")

    key = (handle, dest_hash, path)
    _request_handler_responses[key] = response
    _request_handler_log.setdefault(key, [])

    def _generator(req_path, data, request_id, link_id, remote_identity, requested_at):
        _request_handler_log[key].append({
            "data": data if isinstance(data, (bytes, bytearray)) else b"",
            "request_id": request_id,
            "link_id": link_id,
            "remote_identity_hash": getattr(remote_identity, "hash", None),
            "requested_at": requested_at,
        })
        return _request_handler_responses[key]

    destination.register_request_handler(
        path, response_generator=_generator, allow=allow, allowed_list=allowed_list,
    )
    return {"registered": True}


def cmd_wire_link_identify(params):
    """Identify the link initiator to the remote peer via real
    RNS.Link.identify. Required for ALLOW_LIST request handlers — the
    handler's remote_identity argument is None unless the requester
    identifies first. This is the path LXMF's lxmd uses for
    propagation-node sync (identity-gated request handlers).
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    private_key = bytes.fromhex(params["private_key"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    link.identify(identity)
    return {"identified": True, "identity_hash": identity.hash.hex()}


def cmd_wire_link_request(params):
    """Issue a request over an established outbound Link, wait for the
    response, return it.

    Delegates to real RNS.Link.request. Polls RequestReceipt.get_status()
    until READY (response back), FAILED, or timeout. Returns the response
    bytes on success.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    path = params["path"]
    data = bytes.fromhex(params["data"]) if params.get("data") else None
    timeout_ms = int(params.get("timeout_ms", 10000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    timeout_s = timeout_ms / 1000.0
    receipt = link.request(path, data=data, timeout=timeout_s)
    # +0.5s slack so the receipt's own internal timeout fires first if
    # the network really stalled — that gives us the FAILED status
    # rather than our own poll-loop timeout returning ambiguous results.
    deadline = time.time() + timeout_s + 0.5
    while time.time() < deadline:
        status = receipt.get_status()
        if status == RNS.RequestReceipt.READY:
            response = receipt.get_response()
            return {
                "status": "ready",
                "response": (
                    response.hex() if isinstance(response, (bytes, bytearray)) else None
                ),
                "response_time_s": receipt.get_response_time(),
            }
        if status == RNS.RequestReceipt.FAILED:
            return {"status": "failed", "response": None}
        time.sleep(0.05)
    return {"status": "timeout", "response": None}


def cmd_wire_get_request_log(params):
    """Drain the request-handler invocation log for a (destination, path).

    Returns one entry per request that arrived at the handler — used by
    tests to assert "the handler fired with the expected data."
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    path = params["path"]
    key = (handle, dest_hash, path)
    entries = _request_handler_log.get(key, [])
    return {
        "count": len(entries),
        "entries": [
            {
                "data": (e["data"].hex() if isinstance(e["data"], (bytes, bytearray)) else ""),
                "request_id": (
                    e["request_id"].hex()
                    if isinstance(e["request_id"], (bytes, bytearray)) else None
                ),
                "link_id": (
                    e["link_id"].hex()
                    if isinstance(e["link_id"], (bytes, bytearray)) else None
                ),
                "remote_identity_hash": (
                    e["remote_identity_hash"].hex()
                    if isinstance(e["remote_identity_hash"], (bytes, bytearray)) else None
                ),
                "requested_at": e["requested_at"],
            }
            for e in entries
        ],
    }


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


# ---------------------------------------------------------------------------
# Link lifecycle observation (status / STALE / teardown / keepalive)
#
# All values are read straight off the real RNS.Link instance — RNS's own
# watchdog (Link.__watchdog_job) drives the ACTIVE→STALE→CLOSED transitions
# and sets teardown_reason; these commands only observe.
# ---------------------------------------------------------------------------

_LINK_STATUS_NAMES = {0: "PENDING", 1: "HANDSHAKE", 2: "ACTIVE", 3: "STALE", 4: "CLOSED"}
# Link.TIMEOUT=1, Link.INITIATOR_CLOSED=2, Link.DESTINATION_CLOSED=3
_LINK_TEARDOWN_NAMES = {1: "TIMEOUT", 2: "INITIATOR_CLOSED", 3: "DESTINATION_CLOSED"}


def _link_status_dict(link):
    """Snapshot the observable lifecycle fields of an RNS.Link.

    keepalive observation: when a link is healthy, RNS's watchdog sends a
    keepalive every `keepalive_s` and the peer's response refreshes
    last_inbound, so `no_inbound_for_ms` stays small. A link that has lost
    its peer shows no_inbound_for_ms climbing past keepalive_s, then transits
    to STALE/CLOSED with teardown_reason=TIMEOUT.
    """
    status = getattr(link, "status", None)
    reason = getattr(link, "teardown_reason", None)
    last_inbound = getattr(link, "last_inbound", 0) or 0
    last_keepalive = getattr(link, "last_keepalive", 0) or 0
    now = time.time()
    return {
        "status": int(status) if status is not None else None,
        "status_name": _LINK_STATUS_NAMES.get(status),
        "teardown_reason": int(reason) if reason is not None else None,
        "teardown_reason_name": _LINK_TEARDOWN_NAMES.get(reason),
        "no_inbound_for_ms": int(max(0.0, now - last_inbound) * 1000) if last_inbound else None,
        "last_keepalive_ago_ms": int(max(0.0, now - last_keepalive) * 1000) if last_keepalive else None,
        "keepalive_s": getattr(link, "keepalive", None),
        "stale_time_s": getattr(link, "stale_time", None),
        "rtt": getattr(link, "rtt", None),
    }


def cmd_wire_link_status(params):
    """Return the lifecycle snapshot of an outbound link (initiator side).

    Fields: status / status_name (PENDING/HANDSHAKE/ACTIVE/STALE/CLOSED),
    teardown_reason / teardown_reason_name (TIMEOUT/INITIATOR_CLOSED/
    DESTINATION_CLOSED), no_inbound_for_ms, last_keepalive_ago_ms,
    keepalive_s, stale_time_s, rtt. All read off the real RNS.Link.
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")
    return _link_status_dict(link)


def cmd_wire_link_set_watchdog(params):
    """Compress an established link's keepalive / stale timings so the
    ACTIVE→STALE→CLOSED watchdog path is observable inside a test timeout.

    RNS's full defaults are keepalive=360s / stale_time=720s; even the
    loopback-negotiated values (~5s / ~10s) are slow for a tight test.
    Setting these small lets a test exercise keepalive churn and, if the peer
    actually stops answering, reach STALE→CLOSED/TIMEOUT quickly.

    Teardown-reason reality (validated reference-vs-reference over loopback):
      - INITIATOR_CLOSED / DESTINATION_CLOSED come from an explicit
        teardown or a clean disconnect and fire immediately, *independent*
        of these timings.
      - TIMEOUT requires inbound to go *silent* (a stalled, not cleanly
        closed, peer) for stale_time. A clean TCP disconnect propagates as
        DESTINATION_CLOSED instead. While the peer keeps answering
        keepalives, last_inbound is refreshed every watchdog pass and the
        link never goes STALE — so this knob alone cannot force TIMEOUT;
        it only shortens the window once inbound genuinely ceases.
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    keepalive_s = params.get("keepalive_s")
    stale_time_s = params.get("stale_time_s")
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")
    if keepalive_s is not None:
        link.keepalive = float(keepalive_s)
    if stale_time_s is not None:
        link.stale_time = float(stale_time_s)
    return {"keepalive_s": link.keepalive, "stale_time_s": link.stale_time}


def cmd_wire_link_await_status(params):
    """Block until an outbound link reaches at least `target_status`, or
    timeout. Returns the final lifecycle snapshot plus `reached`.

    `target_status` accepts an int or a name ("STALE"/"CLOSED"/...). The
    comparison is `link.status >= target` on the PENDING(0) < HANDSHAKE(1) <
    ACTIVE(2) < STALE(3) < CLOSED(4) ordering, so awaiting STALE also returns
    if the link has already raced through STALE to CLOSED (STALE is a
    short-lived transitional state in RNS's watchdog).
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    target = params["target_status"]
    timeout_ms = int(params.get("timeout_ms", 15000))
    if isinstance(target, str):
        name_to_int = {v: k for k, v in _LINK_STATUS_NAMES.items()}
        if target.upper() not in name_to_int:
            raise ValueError(f"Unknown target_status name: {target!r}")
        target_int = name_to_int[target.upper()]
    else:
        target_int = int(target)

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    deadline = time.time() + timeout_ms / 1000.0
    reached = False
    while time.time() < deadline:
        status = getattr(link, "status", None)
        if status is not None and int(status) >= target_int:
            reached = True
            break
        time.sleep(0.05)
    out = _link_status_dict(link)
    out["reached"] = reached
    return out


def cmd_wire_link_teardown(params):
    """Gracefully tear down an outbound link from the initiator side
    (real RNS.Link.teardown). The *peer* observes this as a CLOSED link
    with teardown_reason=INITIATOR_CLOSED (observe via
    wire_listener_link_status on the receiver).
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")
    link.teardown()
    return {"torn_down": True}


def cmd_wire_listener_link_status(params):
    """Observe the *receiver-side* (inbound) link a wire_listen destination
    accepted, by destination_hash. Optionally polls up to timeout_ms for the
    inbound link to appear (link establishment is asynchronous).

    Returns the lifecycle snapshot of the most recently accepted inbound
    link plus `link_count`. This is how a test sees teardown_reason on the
    side that did NOT initiate the close (e.g. INITIATOR_CLOSED after the
    initiator calls wire_link_teardown).
    """
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    timeout_ms = int(params.get("timeout_ms", 0))
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    listener = inst.get("listeners", {}).get(destination_hash)
    if listener is None:
        raise ValueError(
            f"No listener registered for destination_hash={destination_hash.hex()}"
        )
    deadline = time.time() + timeout_ms / 1000.0
    while True:
        with listener["recv_lock"]:
            links = list(listener.get("inbound_links", []))
        if links or time.time() >= deadline:
            break
        time.sleep(0.05)
    if not links:
        return {"found": False, "link_count": 0}
    out = _link_status_dict(links[-1])
    out["found"] = True
    out["link_count"] = len(links)
    return out


_PROOF_STRATEGY_MAP = {
    "all": "PROVE_ALL",
    "app": "PROVE_APP",
    "none": "PROVE_NONE",
}


def cmd_wire_set_proof_strategy(params):
    """Set a listening destination's packet-proof strategy
    (real RNS.Destination.set_proof_strategy). Replaces the dead
    rns_set_proof_strategy bridge command (CONFORMANCE_REAUDIT.md §5,
    "Dead-but-counted surface").

    strategy: "all" (PROVE_ALL), "app" (PROVE_APP) or "none" (PROVE_NONE).
    Returns the resolved constant so a test can assert the strategy took on
    the real destination object.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    strategy = str(params["strategy"]).lower()
    if strategy not in _PROOF_STRATEGY_MAP:
        raise ValueError(f"strategy must be one of {sorted(_PROOF_STRATEGY_MAP)} (got {strategy!r})")
    const = getattr(RNS.Destination, _PROOF_STRATEGY_MAP[strategy])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _find_destination_by_hash(inst, destination_hash)
    if destination is None:
        raise ValueError(
            f"No registered destination with hash {destination_hash.hex()} on "
            f"handle {handle}; call wire_listen first."
        )
    destination.set_proof_strategy(const)
    return {
        "strategy": strategy,
        "proof_strategy": int(destination.proof_strategy),
    }


# ---------------------------------------------------------------------------
# Transport posture, link MTU, and single-packet PacketReceipt observation
#
# These three unblock CONFORMANCE_GAPS.md §3 (R3 transport-off bypass,
# proof_for_local_client receipt return) and §2c (in-transit link-MTU strip).
# All read straight off the real RNS objects — nothing is recomputed.
# ---------------------------------------------------------------------------

def cmd_wire_transport_enabled(params):
    """Return the GROUND-TRUTH RNS.Reticulum.transport_enabled() for this peer.

    This is the discriminating observable for R3: a shared master started with
    enable_transport=False must report transport_enabled() == False here, yet
    an attached local client's announces/links must still reach a TCP peer
    (local-client forwarding bypasses the transport gate). Asserting the config
    value alone would be vacuous — this reads the live process-wide flag RNS
    set at Reticulum.__init__ time, so a test can pin "transport really is off"
    independently of whether forwarding happened.
    """
    RNS = _get_rns()
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    return {
        "transport_enabled": bool(RNS.Reticulum.transport_enabled()),
        # is_connected_to_shared_instance / is_shared_instance let a test
        # disambiguate the peer's role without inferring it from the handle.
        "is_shared_instance": bool(getattr(inst["rns"], "is_shared_instance", False)),
        "is_connected_to_shared_instance": bool(
            getattr(inst["rns"], "is_connected_to_shared_instance", False)
        ),
    }


def _find_link_by_id(inst, link_id):
    """Locate a real RNS.Link by its 16-byte link_id on this peer.

    Checks both outbound links opened via wire_link_open (the initiator side)
    AND inbound links accepted by any wire_listen destination (the receiver
    side). The in-transit link-MTU strip (Transport.py:1593-1600) is observed
    on the DESTINATION side — the receiver's inbound link carries the reduced
    mtu — so wire_link_mtu must be able to read a listener's inbound link too,
    not just an initiator's outbound one.
    """
    link = inst.get("out_links", {}).get(link_id)
    if link is not None:
        return link
    for listener in inst.get("listeners", {}).values():
        with listener["recv_lock"]:
            inbound = list(listener.get("inbound_links", []))
        for lk in inbound:
            if getattr(lk, "link_id", None) == link_id:
                return lk
    return None


def cmd_wire_link_mtu(params):
    """Read the negotiated MTU (and MDU / mode) of an established link.

    Returns {mtu, mdu, mode, status, status_name}. mtu is link.mtu read
    straight off the real RNS.Link — the value the link-MTU-discovery
    signalling settled on. On a direct loopback TCP link this is the large
    autoconfigured value (TCP HW_MTU); when an in-transit relay forwarded the
    LINKREQUEST out a next-hop interface that does NOT support MTU
    autoconfiguration, RNS strips the 3-byte LINK_MTU_SIZE signalling field
    (Transport.py:1593-1600) and the destination's link falls back to
    Reticulum.MTU (500). So a test that establishes a link across a mixed
    interface-type relay can assert link.mtu == 500 here to prove the strip
    happened.

    link_id may be either an outbound link (initiator side) or an inbound
    link accepted by a wire_listen destination (receiver side). get_mtu()/
    get_mdu() return None until the link is ACTIVE, so we read the raw .mtu/
    .mdu fields (always populated post-establishment) and also surface status
    so a test can gate on ACTIVE.
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = _find_link_by_id(inst, link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")
    status = getattr(link, "status", None)
    return {
        "mtu": int(link.mtu) if getattr(link, "mtu", None) is not None else None,
        "mdu": int(link.mdu) if getattr(link, "mdu", None) is not None else None,
        "mode": int(link.mode) if getattr(link, "mode", None) is not None else None,
        "status": int(status) if status is not None else None,
        "status_name": _LINK_STATUS_NAMES.get(status),
    }


def cmd_wire_send_packet(params):
    """Send a single SINGLE-destination DATA Packet with a tracked PacketReceipt.

    Distinct from wire_link_send (which sends over an established Link): this is
    the raw single-packet path. The receiver's destination, if it has
    proof_strategy == PROVE_ALL, returns a PROOF; RNS validates it against the
    originating PacketReceipt, which then transitions SENT -> DELIVERED. The
    return path is the discriminating observable for proof_for_local_client
    (CONFORMANCE_GAPS.md §3): when the originator sits behind a shared master,
    the PROOF is routed back to it via the master's reverse_table
    (Transport.py:2254-2261) because the reverse entry's received-iface is a
    local-client iface — a path NOT exercised by any LRPROOF/link_table test.

    Requires the destination identity to be known (via a received announce), as
    with wire_link_open. Builds an OUT SINGLE Destination from the recalled
    identity + the supplied app_name/aspects, constructs a Packet with
    create_receipt=True (the default), sends it, and stashes the returned
    PacketReceipt under a fresh receipt_id for wire_packet_receipt_status to
    poll. Returns {receipt_id, sent, hops}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    payload = bytes.fromhex(params.get("data", ""))
    create_receipt = bool(params.get("create_receipt", True))

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

    packet = RNS.Packet(out_destination, payload, create_receipt=create_receipt)
    receipt = packet.send()
    # packet.send() returns the PacketReceipt when create_receipt=True, None
    # when create_receipt=False, or False when the send itself failed (no
    # path / outbound rejected). Distinguish those for a clear test signal.
    if receipt is False:
        return {"sent": False, "receipt_id": None, "hops": None}

    hops = int(RNS.Transport.hops_to(destination_hash))
    receipt_id = None
    if receipt is not None:
        receipt_id = secrets.token_hex(8)
        inst.setdefault("receipts", {})[receipt_id] = receipt
    # Keep the OUT destination referenced so it isn't GC'd before the proof
    # round-trips and the receipt callback fires.
    inst["destinations"].append((identity, out_destination))
    return {"sent": True, "receipt_id": receipt_id, "hops": hops}


_PACKET_RECEIPT_STATUS_NAMES = {0x00: "FAILED", 0x01: "SENT", 0x02: "DELIVERED", 0xFF: "CULLED"}


def cmd_wire_packet_receipt_status(params):
    """Poll a tracked PacketReceipt until it concludes, or timeout.

    Returns {status, status_name, delivered, proved}. status is the real
    RNS.PacketReceipt.status int (SENT=0x01, DELIVERED=0x02, FAILED=0x00,
    CULLED=0xFF). `delivered` is True iff status == DELIVERED, the observable
    a proof_for_local_client test asserts: the single packet's PROOF made it
    all the way back to the originator. Polls up to timeout_ms (blocking the
    bridge thread, same pattern as wire_poll_path) so the test doesn't have to
    sleep on raw timing; returns the current status immediately when
    timeout_ms == 0.
    """
    RNS = _get_rns()
    handle = params["handle"]
    receipt_id = params["receipt_id"]
    timeout_ms = int(params.get("timeout_ms", 0))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    receipt = inst.get("receipts", {}).get(receipt_id)
    if receipt is None:
        raise ValueError(f"Unknown receipt_id: {receipt_id}")

    DELIVERED = RNS.PacketReceipt.DELIVERED
    FAILED = RNS.PacketReceipt.FAILED
    CULLED = RNS.PacketReceipt.CULLED
    deadline = time.time() + (timeout_ms / 1000.0)
    while True:
        status = receipt.get_status()
        if status in (DELIVERED, FAILED, CULLED):
            break
        if time.time() >= deadline:
            break
        time.sleep(0.05)

    status = receipt.get_status()
    return {
        "status": int(status),
        "status_name": _PACKET_RECEIPT_STATUS_NAMES.get(status),
        "delivered": status == DELIVERED,
        "proved": bool(getattr(receipt, "proved", False)),
    }


# ---------------------------------------------------------------------------
# Channel out-of-order / duplicate injection + window observation
#
# RNS.Channel reorders and de-duplicates received envelopes by sequence
# (Channel._receive / _emplace_envelope). These commands feed crafted
# envelopes straight into the real channel's receive path and observe the
# order in which the channel delivers them to its message handler — testing
# RNS's reassembly logic without needing the wire to deliver out of order.
# ---------------------------------------------------------------------------

_WIRE_CHANNEL_MSGTYPE = 0x0101
_channel_message_class = None


def _get_channel_message_class():
    """A minimal MessageBase whose payload is opaque bytes, registered on
    the channel so RNS's Envelope.unpack can reconstruct injected messages.
    """
    global _channel_message_class
    if _channel_message_class is None:
        from RNS.Channel import MessageBase

        class _WireChannelMessage(MessageBase):
            MSGTYPE = _WIRE_CHANNEL_MSGTYPE

            def __init__(self, data=b""):
                self.data = bytes(data)

            def pack(self):
                return self.data

            def unpack(self, raw):
                self.data = bytes(raw)

        _channel_message_class = _WireChannelMessage
    return _channel_message_class


def _ensure_channel_state(inst, link_id):
    """Lazily wire a recording message handler onto a link's real Channel."""
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")
    channels = inst.setdefault("channels", {})
    state = channels.get(link_id)
    if state is not None:
        return state

    channel = link.get_channel()
    msgclass = _get_channel_message_class()
    received = []
    rlock = threading.Lock()
    try:
        channel.register_message_type(msgclass)
    except Exception:
        # Already registered on this channel — fine.
        pass

    def _on_message(message):
        with rlock:
            received.append(bytes(getattr(message, "data", b"")))
        return True  # consume

    channel.add_message_handler(_on_message)
    state = {"channel": channel, "received": received, "lock": rlock}
    channels[link_id] = state
    return state


def cmd_wire_channel_inject(params):
    """Feed crafted envelopes into a link's real RNS.Channel receive path.

    envelopes: list of {sequence: int, data: hex}. Each is packed into a real
    RNS.Channel.Envelope (struct ">HHH" MSGTYPE/sequence/len + payload) and
    handed to Channel._receive — exactly the bytes the channel would see off
    the wire. RNS then reorders by sequence and drops duplicates; delivered
    payloads (in delivery order) are observable via wire_channel_received.
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    envelopes = params.get("envelopes", []) or []
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    state = _ensure_channel_state(inst, link_id)
    channel = state["channel"]
    msgclass = _get_channel_message_class()
    from RNS.Channel import Envelope

    injected = []
    for env in envelopes:
        seq = int(env["sequence"])
        data = bytes.fromhex(env.get("data", ""))
        message = msgclass(data)
        envelope = Envelope(outlet=channel._outlet, message=message, sequence=seq)
        raw = envelope.pack()
        channel._receive(raw)
        injected.append(seq)
    return {"injected": injected}


def cmd_wire_channel_received(params):
    """Drain the in-order payloads the channel has delivered to its handler.

    Returns {messages: [hex, ...]} in the exact order RNS delivered them —
    which for out-of-order injection is the reassembled sequence order, and
    for duplicates excludes the dropped copy.
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    state = inst.get("channels", {}).get(link_id)
    if state is None:
        return {"messages": []}
    with state["lock"]:
        out = [d.hex() for d in state["received"]]
        state["received"].clear()
    return {"messages": out}


def cmd_wire_channel_window(params):
    """Report a link channel's real window + sequence state.

    Fields read straight off RNS.Channel: window / window_min / window_max /
    window_flexibility, next_rx_sequence (the low edge of the receive
    window — advances as contiguous envelopes are delivered), next_sequence
    (tx), and the current rx/tx ring depths.
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    state = _ensure_channel_state(inst, link_id)
    ch = state["channel"]
    return {
        "window": int(ch.window),
        "window_min": int(ch.window_min),
        "window_max": int(ch.window_max),
        "window_flexibility": int(ch.window_flexibility),
        "next_rx_sequence": int(ch._next_rx_sequence),
        "next_sequence": int(ch._next_sequence),
        "rx_ring": len(ch._rx_ring),
        "tx_ring": len(ch._tx_ring),
    }


# ---------------------------------------------------------------------------
# GROUP destination symmetric encrypt / decrypt
# ---------------------------------------------------------------------------

def cmd_wire_group_create(params):
    """Create a real RNS.Destination of type GROUP and either generate or
    load its symmetric key (RNS.Destination.create_keys / load_private_key).

    Returns the destination_hash (a handle for subsequent encrypt/decrypt on
    this peer) and the symmetric `key` (hex). GROUP encryption is symmetric
    and identity-independent, so a second peer that loads the same key can
    decrypt; a peer with a different key cannot.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", []) or []
    key_hex = params.get("key")

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    destination = RNS.Destination(
        None, RNS.Destination.IN, RNS.Destination.GROUP, app_name, *aspects
    )
    if key_hex:
        destination.load_private_key(bytes.fromhex(key_hex))
    else:
        destination.create_keys()

    inst.setdefault("group_dests", {})[destination.hash] = destination
    # Strong ref so it isn't GC'd (identity slot is None for GROUP).
    inst["destinations"].append((None, destination))
    return {
        "destination_hash": destination.hash.hex(),
        "key": destination.get_private_key().hex(),
    }


def cmd_wire_group_encrypt(params):
    """Encrypt plaintext for a GROUP destination (real Destination.encrypt → Token)."""
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    plaintext = bytes.fromhex(params.get("plaintext", ""))
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = inst.get("group_dests", {}).get(destination_hash)
    if destination is None:
        raise ValueError(f"No GROUP destination {destination_hash.hex()} on handle {handle}")
    ciphertext = destination.encrypt(plaintext)
    return {"ciphertext": ciphertext.hex()}


def cmd_wire_group_decrypt(params):
    """Decrypt ciphertext for a GROUP destination (real Destination.decrypt).

    Returns {plaintext: hex|None, decrypted: bool}. A wrong key yields
    decrypted=False (RNS returns None on Token auth failure).
    """
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    ciphertext = bytes.fromhex(params.get("ciphertext", ""))
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = inst.get("group_dests", {}).get(destination_hash)
    if destination is None:
        raise ValueError(f"No GROUP destination {destination_hash.hex()} on handle {handle}")
    plaintext = destination.decrypt(ciphertext)
    return {
        "plaintext": plaintext.hex() if plaintext is not None else None,
        "decrypted": plaintext is not None,
    }


# ---------------------------------------------------------------------------
# Identity ratchet encrypt / decrypt (enforce_ratchets rejection support)
#
# Pure RNS crypto — no started wire instance required.
# ---------------------------------------------------------------------------

def cmd_wire_identity_keypair(params):
    """Generate a fresh RNS.Identity; return its private/public key + hash."""
    RNS = _get_rns()
    identity = RNS.Identity()
    return {
        "private_key": identity.get_private_key().hex(),
        "public_key": identity.get_public_key().hex(),
        "hash": identity.hash.hex(),
    }


def cmd_wire_ratchet_keypair(params):
    """Generate a fresh X25519 ratchet keypair (RNS.Cryptography.X25519).

    The public bytes are passed to wire_identity_encrypt(ratchet_pub=...);
    the private bytes go into wire_identity_decrypt(ratchets=[...]).
    """
    _get_rns()
    from RNS.Cryptography import X25519PrivateKey
    k = X25519PrivateKey.generate()
    return {
        "private_key": k.private_bytes().hex(),
        "public_key": k.public_key().public_bytes().hex(),
    }


def cmd_wire_identity_encrypt(params):
    """Encrypt for an identity's public key (real RNS.Identity.encrypt).

    When `ratchet_pub` is supplied the message is encrypted to that ratchet
    public key (forward secrecy); otherwise to the identity's base key.
    """
    RNS = _get_rns()
    public_key = bytes.fromhex(params["public_key"])
    plaintext = bytes.fromhex(params.get("plaintext", ""))
    ratchet_pub = params.get("ratchet_pub")
    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(public_key)
    if ratchet_pub:
        ciphertext = identity.encrypt(plaintext, ratchet=bytes.fromhex(ratchet_pub))
    else:
        ciphertext = identity.encrypt(plaintext)
    return {"ciphertext": ciphertext.hex()}


def cmd_wire_identity_decrypt(params):
    """Decrypt for an identity's private key (real RNS.Identity.decrypt),
    with full ratchet-enforcement support.

    ratchets: list of ratchet PRIVATE keys (hex) to try. enforce_ratchets:
    when True, RNS REJECTS (returns None) any ciphertext that none of the
    supplied ratchets can decrypt — even though the identity's base key
    could — which is the forward-secrecy guarantee. Returns {plaintext:
    hex|None, decrypted: bool}.
    """
    RNS = _get_rns()
    private_key = bytes.fromhex(params["private_key"])
    ciphertext = bytes.fromhex(params["ciphertext"])
    ratchets_hex = params.get("ratchets", []) or []
    enforce = bool(params.get("enforce_ratchets", False))
    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    ratchets = [bytes.fromhex(r) for r in ratchets_hex] or None
    plaintext = identity.decrypt(ciphertext, ratchets=ratchets, enforce_ratchets=enforce)
    return {
        "plaintext": plaintext.hex() if plaintext is not None else None,
        "decrypted": plaintext is not None,
    }


# ---------------------------------------------------------------------------
# IFAC (issue-29 golden vector) — computed from the ifac_key RNS itself
# derived for this peer's configured interface; nothing is re-derived here.
# ---------------------------------------------------------------------------

def cmd_wire_ifac_compute(params):
    """Compute the IFAC access code RNS.Transport.transmit (Transport.py:1054)
    would prepend, using the live interface's RNS-derived ifac_identity /
    ifac_key.

    The peer must have been started with network_name + passphrase so RNS
    derived an IFAC key during config parse (Reticulum._add_interface). This
    command reads `interface.ifac_identity` / `interface.ifac_key` straight
    off the live interface and signs `packet_data` with it — i.e. the exact
    Ed25519 sign + trailing-bytes slice RNS uses — so the reticulum-kt#29
    golden vector (network=testnet, pass=testpass, packet=bytes(range(64)))
    is reproduced via genuine RNS, not a hand-rolled HKDF/Ed25519.

    Returns ifac_key (hex), the full 64-byte Ed25519 signature, the ifac_size
    used, and the `ifac` tag (signature[-ifac_size:]).
    """
    handle = params["handle"]
    packet_data = bytes.fromhex(params["packet_data"])
    ifac_size_override = params.get("ifac_size")
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    ifac_iface = None
    for iface in _interfaces_matching_handle(inst["rns"], inst["role"]):
        if getattr(iface, "ifac_identity", None) is not None:
            ifac_iface = iface
            break
    if ifac_iface is None:
        raise RuntimeError(
            "No IFAC-configured interface on this handle. Start the peer with "
            "network_name + passphrase so RNS derives an ifac_key."
        )

    size = int(ifac_size_override) if ifac_size_override is not None else int(ifac_iface.ifac_size)
    signature = ifac_iface.ifac_identity.sign(packet_data)
    return {
        "ifac_key": ifac_iface.ifac_key.hex(),
        "ifac_size": size,
        "signature": signature.hex(),
        "ifac": signature[-size:].hex(),
    }


WIRE_COMMANDS = {
    "wire_start_tcp_server": cmd_wire_start_tcp_server,
    "wire_start_tcp_client": cmd_wire_start_tcp_client,
    "wire_start_local_client": cmd_wire_start_local_client,
    "wire_start_pipe_peer": cmd_wire_start_pipe_peer,
    "wire_start_pipe_tcp_relay": cmd_wire_start_pipe_tcp_relay,
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
    "wire_identity_recall": cmd_wire_identity_recall,
    "wire_register_request_handler": cmd_wire_register_request_handler,
    "wire_link_identify": cmd_wire_link_identify,
    "wire_link_request": cmd_wire_link_request,
    "wire_get_request_log": cmd_wire_get_request_log,
    "wire_listen": cmd_wire_listen,
    "wire_link_open": cmd_wire_link_open,
    "wire_link_send": cmd_wire_link_send,
    "wire_link_poll": cmd_wire_link_poll,
    "wire_resource_send": cmd_wire_resource_send,
    "wire_resource_create": cmd_wire_resource_create,
    "wire_resource_poll": cmd_wire_resource_poll,
    # Link lifecycle observation
    "wire_link_status": cmd_wire_link_status,
    "wire_link_set_watchdog": cmd_wire_link_set_watchdog,
    "wire_link_await_status": cmd_wire_link_await_status,
    "wire_link_teardown": cmd_wire_link_teardown,
    "wire_listener_link_status": cmd_wire_listener_link_status,
    "wire_set_proof_strategy": cmd_wire_set_proof_strategy,
    # Transport posture / link MTU / single-packet PacketReceipt observation
    "wire_transport_enabled": cmd_wire_transport_enabled,
    "wire_link_mtu": cmd_wire_link_mtu,
    "wire_send_packet": cmd_wire_send_packet,
    "wire_packet_receipt_status": cmd_wire_packet_receipt_status,
    # Channel out-of-order / duplicate injection + window observation
    "wire_channel_inject": cmd_wire_channel_inject,
    "wire_channel_received": cmd_wire_channel_received,
    "wire_channel_window": cmd_wire_channel_window,
    # GROUP destination symmetric crypto
    "wire_group_create": cmd_wire_group_create,
    "wire_group_encrypt": cmd_wire_group_encrypt,
    "wire_group_decrypt": cmd_wire_group_decrypt,
    # Identity ratchet crypto (enforce_ratchets rejection)
    "wire_identity_keypair": cmd_wire_identity_keypair,
    "wire_ratchet_keypair": cmd_wire_ratchet_keypair,
    "wire_identity_encrypt": cmd_wire_identity_encrypt,
    "wire_identity_decrypt": cmd_wire_identity_decrypt,
    # IFAC issue-29 golden vector
    "wire_ifac_compute": cmd_wire_ifac_compute,
    "wire_stop": cmd_wire_stop,
}
