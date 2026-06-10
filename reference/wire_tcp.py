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

# Receiver-side ceiling applied to every inbound Resource's decompression bound
# (RNS default is Resource.AUTO_COMPRESS_MAX_SIZE = 64 MiB, Resource.py:124/:364).
# Lowered here so the bz2 decompression-bomb guard (Resource.py:686-689) can be
# tripped by a SINGLE-segment crafted payload (a Resource only splits above
# MAX_EFFICIENT_SIZE ~= 1 MiB, and each segment decompresses to <= that, so the
# bound MUST sit below 1 MiB to be trippable without splitting). 256 KiB keeps
# the bomb cheap/bounded. SAFE for the existing suite: every current wire
# transfer either sends incompressible random bytes (compressed=False, the
# decompressor never runs) or a sub-KiB compressible payload — all far below
# this ceiling, so legitimate transfers are unaffected.
_WIRE_RX_MAX_DECOMPRESSED = 256 * 1024

# Resource status code -> name (Resource.py:142-152). Note REJECTED == NONE == 0
# upstream; a sender whose Resource was RESOURCE_RCL-rejected lands here at 0.
_RESOURCE_STATUS_NAMES = {
    0x00: "NONE",
    0x01: "QUEUED",
    0x02: "ADVERTISED",
    0x03: "TRANSFERRING",
    0x04: "AWAITING_PROOF",
    0x05: "ASSEMBLING",
    0x06: "COMPLETE",
    0x07: "FAILED",
    0x08: "CORRUPT",
}

# Fixed stream id used by the Buffer (RawChannelReader/Writer) streaming path on
# both peers — a Channel is per-Link, so a single shared stream id suffices.
_WIRE_BUFFER_STREAM_ID = 0


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
    ifac_size: int | None = None,
    bitrate: int | None = None,
    respond_to_probes: bool = False,
    use_implicit_proof: bool | None = None,
    enable_remote_management: bool = False,
    remote_management_allowed: list | None = None,
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
    # ifac_size (in BITS) and bitrate are per-interface options. RNS parses
    # them in Reticulum._add_interface's config pass (Reticulum.py:719-723 for
    # ifac_size -> //8 with the IFAC_MIN_SIZE*8 floor; :765-768 for bitrate
    # with the MINIMUM_BITRATE floor). Writing them as plain ini text lets a
    # test pin the floor/divide logic by reading the resulting
    # interface.ifac_size / interface.bitrate back off the live interface.
    if ifac_size is not None:
        ifac_lines += f"    ifac_size = {int(ifac_size)}\n"
    if bitrate is not None:
        ifac_lines += f"    bitrate = {int(bitrate)}\n"
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

    # [reticulum]-level posture knobs. RNS parses each in __apply_config
    # (Reticulum.py:528-545, :555-558): respond_to_probes -> __allow_probes,
    # enable_remote_management -> __remote_management_enabled,
    # use_implicit_proof -> __use_implicit_proof. Default-omitting a knob keeps
    # RNS's own default (probes off, remote-mgmt off, implicit-proof on), which
    # is exactly the negative control a test wants.
    probes_line = f"  respond_to_probes = {'Yes' if respond_to_probes else 'No'}\n"
    remote_mgmt_line = (
        "  enable_remote_management = Yes\n" if enable_remote_management else ""
    )
    remote_allowed_line = ""
    if remote_management_allowed:
        joined = ", ".join(str(h) for h in remote_management_allowed)
        remote_allowed_line = f"  remote_management_allowed = {joined}\n"
    implicit_proof_line = ""
    if use_implicit_proof is not None:
        implicit_proof_line = (
            f"  use_implicit_proof = {'Yes' if use_implicit_proof else 'No'}\n"
        )

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
            f"{probes_line}"
            f"{remote_mgmt_line}"
            f"{remote_allowed_line}"
            f"{implicit_proof_line}"
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
    # fixed_mtu pins the TCPInterface to a small fixed link MTU
    # (TCPInterface.py:110-116: disables AUTOCONFIGURE_MTU, sets HW_MTU). Both
    # peers of a link must use the same value so the negotiated link SDU stays
    # small on BOTH ends — the only way a modest Resource chunks into >74 parts
    # and drives the real on-wire HMU handshake. Must be >= Reticulum.MTU (500).
    fixed_mtu = params.get("fixed_mtu")
    # Per-interface / per-instance config knobs (all optional). These let a
    # test bring up a peer whose floored/derived config value is then read
    # back off the live RNS objects (interface.ifac_size, interface.bitrate,
    # RNS.Reticulum.probe_destination_enabled(), etc.) — see the read-back
    # commands further down. None means "omit the knob, keep RNS's default".
    ifac_size = params.get("ifac_size")
    bitrate = params.get("bitrate")
    respond_to_probes = bool(params.get("respond_to_probes", False))
    use_implicit_proof = params.get("use_implicit_proof")
    if use_implicit_proof is not None:
        use_implicit_proof = bool(use_implicit_proof)
    enable_remote_management = bool(params.get("enable_remote_management", False))
    remote_management_allowed = params.get("remote_management_allowed")
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
    if fixed_mtu is not None:
        iface_block += f"    fixed_mtu = {int(fixed_mtu)}\n"
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
        ifac_size=ifac_size,
        bitrate=bitrate,
        respond_to_probes=respond_to_probes,
        use_implicit_proof=use_implicit_proof,
        enable_remote_management=enable_remote_management,
        remote_management_allowed=remote_management_allowed,
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
    # fixed_mtu: pin the link MTU small on this end too (must match the server's).
    fixed_mtu = params.get("fixed_mtu")

    config_dir = tempfile.mkdtemp(prefix="rns_wire_client_")
    iface_block = (
        "    type = TCPClientInterface\n"
        "    enabled = Yes\n"
        f"    target_host = {target_host}\n"
        f"    target_port = {target_port}\n"
    )
    if fixed_mtu is not None:
        iface_block += f"    fixed_mtu = {int(fixed_mtu)}\n"
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

    enable_ratchets (bool, default False): enable per-destination ratchets
    (Destination.enable_ratchets, Destination.py:466-489) BEFORE announcing,
    so the announce carries the latest ratchet public key (context flag set,
    Destination.py:284-287/:310-311) and the destination grows a real ratchet
    store. This is the "A enables ratchets + announces" precondition for the
    destination-level ratchet gaps (latest_ratchet_id / rotation-interval /
    retained-cap / file-roundtrip). A unique ratchet file is created under the
    instance config dir; the destination object (with its live ratchet state)
    is reachable by hash via the wire_*_ratchet* commands below.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    app_data_hex = params.get("app_data") or ""
    # app_data_empty distinguishes an explicit empty-but-present app_data (b"")
    # from an omitted one. Without it, an empty app_data_hex is indistinguishable
    # from absent, so the announce always collapses to app_data=None and the
    # None-vs-empty recall distinction (Identity.validate_announce, Identity.py:
    # 542/560-561: ratchetless no-app_data -> None, ratcheted no-app_data -> b"")
    # cannot be exercised from the wire side.
    app_data_empty = bool(params.get("app_data_empty", False))
    enable_ratchets = bool(params.get("enable_ratchets", False))

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

    ratchets_enabled = False
    if enable_ratchets:
        ratchets_path = os.path.join(
            inst.get("config_dir") or tempfile.gettempdir(),
            f"ratchets_{destination.hash.hex()}_{secrets.token_hex(4)}",
        )
        ratchets_enabled = bool(destination.enable_ratchets(ratchets_path))

    if app_data_hex:
        app_data = bytes.fromhex(app_data_hex)
    elif app_data_empty:
        app_data = b""
    else:
        app_data = None
    destination.announce(app_data=app_data)
    # Keep a reference so the destination/identity aren't GC'd before the
    # TX loop picks up the announce packet.
    inst["destinations"].append((identity, destination))

    response = {
        "destination_hash": destination.hash.hex(),
        "identity_hash": identity.hash.hex(),
    }
    if enable_ratchets:
        response["ratchets_enabled"] = ratchets_enabled
        response["current_ratchet_id"] = _current_ratchet_id(destination)
        response["ratchet_count"] = len(destination.ratchets) if destination.ratchets is not None else 0
    return response


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
    announce. Returns the recalled identity's public_key, hash, and the
    last-heard app_data (Identity.py:138/:149/:161-174) when found, or
    {found: False} when the hash is unknown to this instance (no announce
    received) — which is also the recall_app_data(unknown) -> None case.

    from_identity_hash (bool, default False): when True, `destination_hash`
    is interpreted as an IDENTITY hash and RNS.Identity.recall searches
    known_destinations by identity hash instead (Identity.py:129-141). The
    recalled identity's app_data is surfaced in both modes.

    Optionally polls Transport.has_path first, so the test can express
    "wait until the announce has been received, then recall." Without the
    poll the caller would have to sleep on raw timing. The path poll is
    skipped for from_identity_hash (has_path keys on destination hashes).
    """
    RNS = _get_rns()
    handle = params["handle"]
    target_hash = bytes.fromhex(params["destination_hash"])
    timeout_ms = int(params.get("timeout_ms", 0))
    from_identity_hash = bool(params.get("from_identity_hash", False))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    deadline = time.time() + (timeout_ms / 1000.0)
    identity = None
    while True:
        identity = RNS.Identity.recall(target_hash, from_identity_hash=from_identity_hash)
        if identity is not None:
            break
        if time.time() >= deadline:
            break
        time.sleep(0.05)

    if identity is None:
        return {"found": False, "app_data": None}
    # identity.app_data is the last-heard app_data RNS.Identity.recall copies
    # off the known_destinations entry (Identity.py:138/:149/:156); it equals
    # RNS.Identity.recall_app_data(destination_hash) for the dest-hash path.
    app_data = getattr(identity, "app_data", None)
    return {
        "found": True,
        "public_key": identity.get_public_key().hex(),
        "hash": identity.hash.hex(),
        "app_data": app_data.hex() if isinstance(app_data, (bytes, bytearray)) else None,
    }


_RESOURCE_APP_ACCEPT_MAX_SIZE = 4096  # ACCEPT_APP boundary (advertised data size)


def cmd_wire_listen(params):
    """Register an IN SINGLE destination that accepts incoming Links.

    On link establishment, attach a packet callback that buffers received
    bytes into an in-memory queue keyed by destination_hash, set the inbound
    Link's Resource accept strategy, and wire up the receiver-side
    observation hooks the §4b Resource/Channel/Buffer gaps need:

      * resource accept strategy (`resource_strategy` param, default 'all'):
        - 'all'  -> RNS.Link.ACCEPT_ALL (every Resource accepted).
        - 'none' -> RNS.Link.ACCEPT_NONE (no parts flow; sender ends FAILED).
        - 'app'  -> RNS.Link.ACCEPT_APP with a deterministic predicate: accept
          iff the advertised uncompressed data size (ResourceAdvertisement.d)
          is <= _RESOURCE_APP_ACCEPT_MAX_SIZE (4096). A larger Resource is
          rejected (RESOURCE_RCL -> sender status REJECTED, Link.py:1094/:1140).
      * a resource_started hook that captures every inbound Resource, lowers
        its decompression bound to _WIRE_RX_MAX_DECOMPRESSED (so the bz2-bomb
        guard can trip cheaply) and counts the HMU handshake observables
        (hmu_requests_sent / hashmap_updates_received) — read via
        wire_resource_receiver_status.
      * a Channel on the inbound link with a recording handler, so the peer
        PROVES received CHANNEL packets (Link.py:1165-1173) — required for
        wire_channel_send delivery/window growth — and delivered messages are
        observable via wire_channel_received.
      * a RawChannelReader (Buffer) on the inbound link's Channel that
        reassembles a StreamDataMessage stream and detects the MAX_CHUNK_LEN
        decompression-bomb abort — read via wire_buffer_received.

    enable_ratchets (bool, default False): enable per-destination ratchets
    (Destination.enable_ratchets, Destination.py:466-489) on the IN SINGLE
    destination BEFORE its immediate announce, exactly as cmd_wire_announce
    does — so the listening destination carries the latest ratchet public key
    and grows a real ratchet store. This lets the destination-level ratchet
    observables (wire_read_ratchets / wire_destination_latest_ratchet_id /
    wire_rotate_ratchet / wire_set_ratchet_interval / wire_set_retained_ratchets
    / wire_ratchet_file_roundtrip) operate on a destination that also accepts
    Links. Default False leaves the destination non-ratcheted (unchanged).

    Tests poll via wire_link_poll (single-packet data), wire_resource_poll
    (completed resource payloads), wire_resource_receiver_status (inbound
    Resource state), wire_channel_received, or wire_buffer_received.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    resource_strategy = str(params.get("resource_strategy") or "all").lower()
    if resource_strategy not in ("all", "none", "app"):
        raise ValueError(
            f"resource_strategy must be 'all', 'none' or 'app' (got {resource_strategy!r})"
        )
    enable_ratchets = bool(params.get("enable_ratchets", False))
    # open_channel (default True): whether on_link_established calls
    # link.get_channel() on the inbound link. False reproduces a peer with NO
    # local channel, so an inbound CHANNEL-context packet is dropped WITHOUT a
    # proof (Link.py:1166-1167) — observable via the proof log below.
    open_channel = bool(params.get("open_channel", True))
    # buffer_stream_ids (default None): extra receiver-relative stream ids to
    # register RawChannelReaders for, in addition to the default stream. Drives
    # the multi-reader stream-id filtering gap.
    extra_stream_ids = [int(s) for s in (params.get("buffer_stream_ids") or [])]

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

    # Enable ratchets BEFORE the immediate announce below, mirroring
    # cmd_wire_announce (so the announce carries the latest ratchet public key
    # and the destination owns a real ratchet store).
    ratchets_enabled = False
    if enable_ratchets:
        ratchets_path = os.path.join(
            inst.get("config_dir") or tempfile.gettempdir(),
            f"ratchets_{destination.hash.hex()}_{secrets.token_hex(4)}",
        )
        ratchets_enabled = bool(destination.enable_ratchets(ratchets_path))

    # Per-destination receive buffers.
    recv_buffer = []         # single-packet link data
    resource_buffer = []     # completed resources (bytes)
    inbound_links = []        # RNS.Link objects accepted on this destination
    incoming_resources = []   # receiver-side Resource observation records
    channel_received = []     # decoded Channel message payloads (bytes)
    proof_log = []            # context byte of every inbound packet the receiver
                              # PROVED (link.prove_packet) — CHANNEL==0x0E entries
                              # appear only when a channel is open (Link.py:1166-1173)
    buffer_state = {          # Buffer (RawChannelReader) stream reassembly state
        "reader": None,       # default-stream reader (back-compat)
        "readers": {},        # {stream_id: RawChannelReader}
        "aborted": False,
        "error": None,
    }
    recv_lock = threading.Lock()

    strategy_const = {
        "all": RNS.Link.ACCEPT_ALL,
        "none": RNS.Link.ACCEPT_NONE,
        "app": RNS.Link.ACCEPT_APP,
    }[resource_strategy]

    def on_resource_concluded(resource):
        # Capture the reassembled payload + metadata for the matching
        # incoming-resource record (the final-segment conclusion callback).
        payload = None
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
        meta = getattr(resource, "metadata", None)
        with recv_lock:
            for rec in incoming_resources:
                if rec["resource"] is resource:
                    if payload is not None:
                        rec["data"] = payload
                    if isinstance(meta, (bytes, bytearray)):
                        rec["metadata"] = bytes(meta)
                    break

    def on_resource_started(resource):
        # Lower the decompression bound so the bz2-bomb guard trips cheaply
        # (Resource.py:686-689) and install per-instance counters for the HMU
        # handshake (Resource.py:483-503). request_next() / hashmap_update_packet
        # are shadowed on the instance, so RNS's own internal self.request_next()
        # calls go through the counting wrappers.
        rec = {
            "resource": resource,
            "hmu_requests_sent": 0,
            "hashmap_updates_received": 0,
            "data": None,
            "metadata": None,
        }
        try:
            resource.max_decompressed_size = _WIRE_RX_MAX_DECOMPRESSED
        except Exception:
            pass
        try:
            orig_hmu_packet = resource.hashmap_update_packet

            def counted_hmu_packet(plaintext, _orig=orig_hmu_packet, _rec=rec):
                _rec["hashmap_updates_received"] += 1
                return _orig(plaintext)

            resource.hashmap_update_packet = counted_hmu_packet

            orig_request_next = resource.request_next

            def counted_request_next(_orig=orig_request_next, _res=resource, _rec=rec):
                before = bool(getattr(_res, "waiting_for_hmu", False))
                result = _orig()
                if bool(getattr(_res, "waiting_for_hmu", False)) and not before:
                    _rec["hmu_requests_sent"] += 1
                return result

            resource.request_next = counted_request_next
        except Exception:
            pass
        with recv_lock:
            incoming_resources.append(rec)

    def on_link_established(link):
        # Keep a reference to the inbound (receiver-side) Link so lifecycle
        # tests can observe its status / teardown_reason after the initiator
        # tears it down (DESTINATION/INITIATOR_CLOSED is only observable on
        # the *peer* of whoever called teardown). See wire_listener_link_status.
        with recv_lock:
            inbound_links.append(link)

        # Receiver-proves log: wrap the inbound Link's prove_packet so every
        # proof the receiver emits records the proved packet's context byte.
        # A CHANNEL packet (context 0x0E) is proved ONLY when a channel is open
        # (Link.py:1172 packet.prove()); with no channel the receiver logs and
        # drops it WITHOUT proving (Link.py:1166-1167), so no 0x0E entry appears.
        try:
            _orig_prove = link.prove_packet

            def logging_prove(packet, _orig=_orig_prove):
                try:
                    with recv_lock:
                        proof_log.append(int(getattr(packet, "context", -1)))
                except Exception:
                    pass
                return _orig(packet)

            link.prove_packet = logging_prove
        except Exception:
            pass

        def on_packet(message, packet):
            with recv_lock:
                recv_buffer.append(bytes(message))

        link.set_packet_callback(on_packet)
        link.set_resource_strategy(strategy_const)
        link.set_resource_concluded_callback(on_resource_concluded)
        link.set_resource_started_callback(on_resource_started)
        if resource_strategy == "app":
            def app_accept(advertisement):
                try:
                    return advertisement.get_data_size() <= _RESOURCE_APP_ACCEPT_MAX_SIZE
                except Exception:
                    return False
            link.set_resource_callback(app_accept)

        # Channel: opening it (get_channel) makes the receiver PROVE inbound
        # CHANNEL packets (Link.py:1166-1169) — without this the sender's
        # receipts never deliver. Register the recording message type + handler
        # so wire_channel_received can observe delivered messages. When
        # open_channel is False the receiver has NO channel, so an inbound
        # CHANNEL packet is dropped unproven (the no-channel-no-proof gate).
        if not open_channel:
            return
        try:
            channel = link.get_channel()
            msgclass = _get_channel_message_class()
            try:
                channel.register_message_type(msgclass)
            except Exception:
                pass

            def on_channel_message(message, _msgclass=msgclass):
                # Only consume the wire channel message type; let other types
                # (notably Buffer's StreamDataMessage) fall through to the
                # RawChannelReader handler added below (run_callbacks stops at
                # the first handler returning True).
                if isinstance(message, _msgclass):
                    with recv_lock:
                        channel_received.append(bytes(getattr(message, "data", b"")))
                    return True
                return False

            channel.add_message_handler(on_channel_message)

            # Buffer (RawChannelReader): reassemble a StreamDataMessage stream
            # and detect the MAX_CHUNK_LEN decompression-bomb abort. Register
            # the default-stream reader plus any extra receiver-relative stream
            # ids the test requested (multi-reader stream-id filtering).
            _ensure_buffer_reader(channel, buffer_state, recv_lock)
            for sid in extra_stream_ids:
                _ensure_buffer_reader(channel, buffer_state, recv_lock, stream_id=sid)
        except Exception:
            pass

    destination.set_link_established_callback(on_link_established)

    # Announce immediately so the sender can learn a path via the transport.
    destination.announce()

    inst.setdefault("listeners", {})[destination.hash] = {
        "destination": destination,
        "identity": identity,
        "recv_buffer": recv_buffer,
        "resource_buffer": resource_buffer,
        "inbound_links": inbound_links,
        "incoming_resources": incoming_resources,
        "channel_received": channel_received,
        "proof_log": proof_log,
        "buffer_state": buffer_state,
        "recv_lock": recv_lock,
        "resource_strategy": resource_strategy,
        "open_channel": open_channel,
    }
    # Keep strong reference so it isn't garbage collected.
    inst["destinations"].append((identity, destination))

    response = {
        "destination_hash": destination.hash.hex(),
        "identity_hash": identity.hash.hex(),
        # public_key surfaces the listening identity's raw key so recall
        # tests can assert byte-identity (recalled.public_key == this), not
        # just length (N-M3). The hash above is a truncated SHA-256 of this
        # key, so asserting both pins the full key material end-to-end.
        "public_key": identity.get_public_key().hex(),
        "resource_strategy": resource_strategy,
    }
    if enable_ratchets:
        response["ratchets_enabled"] = ratchets_enabled
        response["current_ratchet_id"] = _current_ratchet_id(destination)
        response["ratchet_count"] = (
            len(destination.ratchets) if destination.ratchets is not None else 0
        )
    return response


def _make_detecting_stream_message_class(buffer_state):
    """A StreamDataMessage subclass whose unpack records the bz2 decompression-
    bomb abort (Buffer.py:95-97 raises IOError when a compressed chunk would
    exceed RawChannelWriter.MAX_CHUNK_LEN) onto buffer_state before re-raising,
    so the receiver can observe `aborted` even though Channel._receive swallows
    the exception.
    """
    from RNS.Buffer import StreamDataMessage

    class _DetectingStreamDataMessage(StreamDataMessage):
        def unpack(self, raw):
            try:
                return super().unpack(raw)
            except Exception as e:
                buffer_state["aborted"] = True
                buffer_state["error"] = str(e)
                raise

    return _DetectingStreamDataMessage


def _ensure_buffer_reader(channel, buffer_state, recv_lock, stream_id=None):
    """Create a RawChannelReader on `channel` (idempotent per stream_id) and swap
    in the bomb-detecting StreamDataMessage factory. Stores each reader on
    buffer_state["readers"][stream_id]; the default stream's reader is also kept
    under buffer_state["reader"] for backward compatibility.

    A second reader at a DISTINCT stream_id pins receiver-relative stream
    addressing (Buffer.py RawChannelReader._handle_message:152 only buffers a
    StreamDataMessage whose stream_id matches; a non-matching reader returns
    False and lets the message propagate to the next handler).
    """
    if stream_id is None:
        stream_id = _WIRE_BUFFER_STREAM_ID
    readers = buffer_state.setdefault("readers", {})
    if stream_id in readers:
        return readers[stream_id]
    from RNS.Buffer import RawChannelReader, StreamDataMessage

    reader = RawChannelReader(stream_id, channel)
    # RawChannelReader.__init__ registered the plain StreamDataMessage; replace
    # the factory with the detecting subclass so over-bound chunks are recorded.
    try:
        channel._message_factories[StreamDataMessage.MSGTYPE] = (
            _make_detecting_stream_message_class(buffer_state)
        )
    except Exception:
        pass
    readers[stream_id] = reader
    if stream_id == _WIRE_BUFFER_STREAM_ID:
        buffer_state["reader"] = reader
    return reader


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
    _track_keepalive_emissions(inst, link)
    return {"link_id": link.link_id.hex()}


def _track_keepalive_emissions(inst, link):
    """Record the last keepalive byte a link emits via send_keepalive (the
    initiator's 0xFF, Link.py:848-849). The non-initiator's 0xFE answer is
    inline in Link.receive, so it's captured by wire_send_keepalive_probe
    instead. Idempotent per link. Stored under inst['keepalive_payloads'].
    """
    store = inst.setdefault("keepalive_payloads", {})
    try:
        link_id = link.link_id
    except Exception:
        return
    if getattr(link, "_wire_keepalive_wrapped", False):
        return
    orig_send_keepalive = link.send_keepalive

    def wrapped_send_keepalive(_orig=orig_send_keepalive, _lid=link_id):
        try:
            store[_lid] = b"\xff"
        except Exception:
            pass
        return _orig()

    try:
        link.send_keepalive = wrapped_send_keepalive
        link._wire_keepalive_wrapped = True
    except Exception:
        pass


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


def _resource_info(resource):
    """Read the construction-time observables off an outbound RNS.Resource
    (set synchronously in __init__, so valid even mid-transfer)."""
    info = {}
    try:
        info["original_hash"] = resource.original_hash.hex()
    except Exception:
        info["original_hash"] = None
    try:
        info["hash"] = resource.hash.hex()
    except Exception:
        info["hash"] = None
    try:
        info["total_segments"] = int(resource.total_segments)
    except Exception:
        info["total_segments"] = None
    try:
        info["segment_index"] = int(resource.segment_index)
    except Exception:
        info["segment_index"] = None
    try:
        info["parts"] = int(resource.total_parts)
    except Exception:
        info["parts"] = None
    info["compressed"] = bool(getattr(resource, "compressed", False))
    info["has_metadata"] = bool(getattr(resource, "has_metadata", False))
    info["split"] = bool(getattr(resource, "split", False))
    return info


def cmd_wire_resource_send(params):
    """Send arbitrary-size bytes over an established outbound Link via the
    Resource API.

    This exercises the same code path LXMF uses for image/file/media
    attachments in apps like Columba and Sideband. Data > link.mdu gets
    chunked into multiple link DATA packets and reassembled at the
    receiver. The receiver must have accepted resources on the link
    (wire_listen wires this up automatically).

    Params:
      metadata (hex, optional): packed into the Resource 'x' metadata field
        (Resource.py:260-268) as a bytes object, so it round-trips byte-exact.
        Sets has_metadata=True.
      wait (bool, default True): when True, block until the transfer concludes
        or times out and return {success, status, ...}. When False, start the
        transfer on RNS's background threads and return immediately with
        {resource_id, started, ...} so the caller can abort it mid-flight via
        wire_resource_cancel (the only way to drive RESOURCE_ICL).

    Returns (wait=True): {success, status, size, timed_out, resource_id,
      original_hash, total_segments, parts, compressed, has_metadata}.
    Returns (wait=False): {started, resource_id, size, original_hash,
      total_segments, parts, compressed, has_metadata}.
    `status` is the RNS Resource status code (COMPLETE=6, FAILED=7, REJECTED=0).
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", ""))
    timeout_ms = int(params.get("timeout_ms", 30000))
    wait = bool(params.get("wait", True))
    metadata_hex = params.get("metadata")
    metadata = bytes.fromhex(metadata_hex) if metadata_hex else None

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    # NOTE: to chunk a transfer into >74 parts (HMU) or slow it for a mid-flight
    # cancel, establish the link with a small fixed MTU (wire_start_tcp_*
    # fixed_mtu=...) so BOTH peers share the same small per-part SDU. Shrinking
    # only the sender's link.mtu here would desync the receiver's part count and
    # break reassembly — so it is deliberately not offered.
    done = threading.Event()
    final_status = [None]

    def on_done(resource):
        final_status[0] = getattr(resource, "status", None)
        done.set()

    resource = RNS.Resource(payload, link, metadata=metadata, callback=on_done)

    resource_id = secrets.token_hex(8)
    with _instances_lock:
        inst.setdefault("out_resources", {})[resource_id] = {
            "resource": resource,
            "link": link,
        }
    info = _resource_info(resource)

    if not wait:
        # Non-blocking: leave the transfer running so wire_resource_cancel can
        # abort it mid-flight (RESOURCE_ICL). The link MTU was already restored
        # right after construction. Returns immediately with the handle.
        return {
            "started": True,
            "resource_id": resource_id,
            "size": len(payload),
            **info,
        }

    if not done.wait(timeout=timeout_ms / 1000.0):
        try:
            resource.cancel()
        except Exception:
            pass
        raw_status = getattr(resource, "status", None)
        return {
            "success": False,
            # Explicit None check — a genuine status of 0 (NONE/REJECTED) is
            # falsy and would coerce to -1 under a truthiness fallback.
            "status": int(raw_status) if raw_status is not None else -1,
            "size": len(payload),
            "timed_out": True,
            "resource_id": resource_id,
            **info,
        }

    status_value = final_status[0]
    success = status_value == RNS.Resource.COMPLETE
    return {
        "success": bool(success),
        "status": int(status_value) if status_value is not None else -1,
        "size": len(payload),
        "timed_out": False,
        "resource_id": resource_id,
        **info,
    }


def cmd_wire_resource_cancel(params):
    """Abort an in-flight outbound Resource started by wire_resource_send(wait
    =False). Calls RNS.Resource.cancel (Resource.py:1075): the initiator sends a
    RESOURCE_ICL to the receiver (Link.py:1131), whose inbound Resource then
    cancels (status FAILED). Returns {cancelled, resource_id, status}.
    """
    handle = params["handle"]
    resource_id = params["resource_id"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    record = inst.get("out_resources", {}).get(resource_id)
    if record is None:
        raise ValueError(f"Unknown resource_id: {resource_id}")
    resource = record["resource"]
    cancelled = False
    try:
        resource.cancel()
        cancelled = True
    except Exception:
        cancelled = False
    status = getattr(resource, "status", None)
    return {
        "cancelled": cancelled,
        "resource_id": resource_id,
        "status": int(status) if status is not None else -1,
    }


def cmd_wire_resource_send_bomb(params):
    """Send a crafted compressible Resource whose decompressed payload exceeds
    the receiver's decompression bound, tripping the bz2 decompression-bomb
    guard (Resource.py:686-689): the receiver's
    BZ2Decompressor.decompress(max_length=...) stops short of EOF, so RNS marks
    the inbound Resource CORRUPT and tears the link down (Resource.py:1081-1084).

    The receiver's per-Resource bound is lowered to _WIRE_RX_MAX_DECOMPRESSED by
    wire_listen, so a few-MiB of zeros (compresses tiny, decompresses past the
    bound) is enough — we cap the crafted size for cheapness regardless of the
    requested `decompressed_size`. The sender's own transfer ends FAILED.
    Returns {success, status, size, resource_id}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    requested = int(params.get("decompressed_size", _WIRE_RX_MAX_DECOMPRESSED + 1024 * 1024))
    timeout_ms = int(params.get("timeout_ms", 30000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    # Craft a payload that decompresses just past the receiver bound. Zeros
    # compress to a few bytes (so the WIRE transfer stays tiny) but inflate back
    # to `crafted` bytes. The crafted size stays BELOW MAX_EFFICIENT_SIZE so the
    # Resource is a single (non-split) compressed segment whose decompressed size
    # exceeds the receiver's lowered bound — the cleanest way to trip the guard.
    floor = _WIRE_RX_MAX_DECOMPRESSED + 1
    ceil = min(_WIRE_RX_MAX_DECOMPRESSED * 2, RNS.Resource.MAX_EFFICIENT_SIZE - 1)
    crafted = max(floor, min(requested, ceil))
    payload = bytes(crafted)  # zeros; bz2-compresses to a tiny advertised payload

    done = threading.Event()
    final_status = [None]

    def on_done(resource):
        final_status[0] = getattr(resource, "status", None)
        done.set()

    # auto_compress default (True) compresses since crafted < AUTO_COMPRESS_MAX_SIZE,
    # so the receiver receives a compressed Resource and must decompress it.
    resource = RNS.Resource(payload, link, callback=on_done)
    resource_id = secrets.token_hex(8)
    with _instances_lock:
        inst.setdefault("out_resources", {})[resource_id] = {
            "resource": resource, "link": link,
        }

    done.wait(timeout=timeout_ms / 1000.0)
    status_value = getattr(resource, "status", None)
    if not done.is_set():
        try:
            resource.cancel()
        except Exception:
            pass
        status_value = getattr(resource, "status", None)
    else:
        status_value = final_status[0]
    return {
        "success": status_value == RNS.Resource.COMPLETE,
        "status": int(status_value) if status_value is not None else -1,
        "size": crafted,
        "resource_id": resource_id,
    }


def cmd_wire_resource_receiver_status(params):
    """Read the receiver-side state of the most recent inbound Resource on a
    listening destination — the discriminating observable for the HMU handshake,
    metadata round-trip, cancel (RESOURCE_ICL) and bz2-bomb (CORRUPT) cases.

    Returns {found, status, status_name, corrupt, hmu_requests_sent,
    hashmap_updates_received, hashmap_height, has_metadata, metadata, data,
    resource_count}. `metadata`/`data` are hex (or None). Optionally polls up to
    timeout_ms for an inbound Resource to appear / reach a terminal status
    (COMPLETE/FAILED/CORRUPT).
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

    terminal = {0x06, 0x07, 0x08}  # COMPLETE / FAILED / CORRUPT
    deadline = time.time() + timeout_ms / 1000.0
    while True:
        with listener["recv_lock"]:
            recs = list(listener.get("incoming_resources", []))
        if recs:
            status = getattr(recs[-1]["resource"], "status", None)
            if status in terminal or time.time() >= deadline:
                break
        elif time.time() >= deadline:
            break
        time.sleep(0.05)

    with listener["recv_lock"]:
        recs = list(listener.get("incoming_resources", []))
    if not recs:
        return {"found": False, "resource_count": 0}
    rec = recs[-1]
    resource = rec["resource"]
    status = getattr(resource, "status", None)
    metadata = rec.get("metadata")
    data = rec.get("data")
    return {
        "found": True,
        "resource_count": len(recs),
        "status": int(status) if status is not None else -1,
        "status_name": _RESOURCE_STATUS_NAMES.get(status),
        "corrupt": status == 0x08,
        "hmu_requests_sent": int(rec.get("hmu_requests_sent", 0)),
        "hashmap_updates_received": int(rec.get("hashmap_updates_received", 0)),
        "hashmap_height": int(getattr(resource, "hashmap_height", 0) or 0),
        "max_decompressed_size": int(getattr(resource, "max_decompressed_size", -1) or -1),
        "compressed": bool(getattr(resource, "compressed", False)),
        "has_metadata": bool(getattr(resource, "has_metadata", False)),
        "metadata": metadata.hex() if isinstance(metadata, (bytes, bytearray)) else None,
        "data": data.hex() if isinstance(data, (bytes, bytearray)) else None,
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
    # metadata (hex bytes) -> packed into the Resource 'x' field (Resource.py:
    # 260-268); passed as a bytes object so umsgpack round-trips it byte-exact.
    metadata_hex = params.get("metadata")
    metadata = bytes.fromhex(metadata_hex) if metadata_hex else None

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
        resource = RNS.Resource(
            payload, link, metadata=metadata, advertise=False, auto_compress=auto_compress
        )
    finally:
        if restore_link:
            link.mtu = saved_mtu

    # ResourceAdvertisement flags byte (Resource.py:1307) packs has_metadata at
    # bit 5: `f = ... | x<<5 | ...`. Surfacing it lets a metadata test pin "flag
    # bit 5 set" without reconstructing the byte.
    flags = None
    try:
        flags = int(RNS.ResourceAdvertisement(resource).f)
    except Exception:
        flags = None

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
        # original_hash is the pre-segmentation hash RNS chains multi-segment
        # transfers against (Resource.py:445-448); == hash for segment 1.
        "original_hash": resource.original_hash.hex(),
        "has_metadata": bool(resource.has_metadata),
        "flags": flags,
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

    Optional auth policy: pass `allow` as "all" (default), "list" plus
    `allowed_identity_hashes` (list of hex strings), or "none". RNS rejects
    requests from un-listed identities (ALLOW_LIST) or every request
    (ALLOW_NONE) before the generator runs (Link.py:868-873) — the invocation
    log will not record those, which is exactly what the ALLOW_LIST /
    ALLOW_NONE negative-control tests assert (the requester's RequestReceipt
    never reaches READY).
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
    elif allow_param == "none":
        allow = RNS.Destination.ALLOW_NONE
        allowed_list = None
    else:
        raise ValueError(f"unsupported allow: {allow_param!r} (use 'all', 'list' or 'none')")

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


def cmd_wire_link_request_large(params):
    """Issue a Link request whose response exceeds the link MDU.

    Identical mechanics to wire_link_request, but documents/serves the >MDU
    case: a handler returning ~50 KB cannot answer in a single RESPONSE packet,
    so RNS delivers the response as a Resource (Link.handle_request:898-901) and
    the RequestReceipt only reaches READY once that response Resource fully
    transfers (Link.py:496-517/:939-952). The default timeout is generous to
    cover the resource transfer. Returns {status, response, response_time_s}
    with `status == "ready"` and the full byte-exact response (hex).
    """
    params = dict(params)
    params.setdefault("timeout_ms", 30000)
    return cmd_wire_link_request(params)


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
    # get_mtu()/get_mdu() return None until the link is ACTIVE (Link.py:609/:618);
    # get_mode() always returns the negotiated mode constant (Link.py:636). These
    # are the negotiated-parameter read-backs the §4b "Link MTU/MDU/mode" gap needs.
    try:
        mtu = link.get_mtu()
    except Exception:
        mtu = None
    try:
        mdu = link.get_mdu()
    except Exception:
        mdu = None
    try:
        mode = link.get_mode()
    except Exception:
        mode = None
    # get_remote_identity() (Link.py:683-687) returns the remote peer's Identity
    # only once that peer has independently called identify() — observable on the
    # receiver-side (inbound) link after the initiator wire_link_identify's.
    remote_identity = None
    try:
        remote_identity = link.get_remote_identity()
    except Exception:
        remote_identity = None
    remote_identity_hash = (
        remote_identity.hash.hex()
        if remote_identity is not None and getattr(remote_identity, "hash", None) is not None
        else None
    )
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
        "mtu": int(mtu) if mtu is not None else None,
        "mdu": int(mdu) if mdu is not None else None,
        "mode": int(mode) if mode is not None else None,
        "remote_identity_hash": remote_identity_hash,
        "remote_identified": remote_identity is not None,
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

    For "app", a deterministic proof_requested callback is installed
    (Destination.set_proof_requested_callback, consulted at Link.py:1002-1006):
    it PROVES iff the inbound packet's decrypted payload begins with byte 0x01,
    and declines otherwise. So a link-DATA test can drive PROVE_APP both ways by
    sending a payload starting with 0x01 (proof -> receipt DELIVERED) versus one
    starting with any other byte (no proof -> receipt never DELIVERS). The
    callback decrypts via the destination's links, so it works on the encrypted
    packet RNS hands it.
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
    if strategy == "app":
        def proof_requested(packet, _dest=destination):
            # Decide on the decrypted payload: prove iff it starts with 0x01.
            for link in list(getattr(_dest, "links", [])):
                try:
                    plaintext = link.decrypt(packet.data)
                except Exception:
                    plaintext = None
                if plaintext is not None and len(plaintext) >= 1:
                    return plaintext[0:1] == b"\x01"
            return False
        destination.set_proof_requested_callback(proof_requested)
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


def cmd_wire_send_link_data(params):
    """Send a DATA packet OVER an established Link with a tracked PacketReceipt.

    Distinct from wire_link_send (fire-and-forget over a Link) and
    wire_send_packet (single SINGLE-destination packet): this drives the
    link-DATA proof path (Link.py:999-1008). The receiver proves the packet per
    its destination's proof strategy (set via wire_set_proof_strategy); the
    returning PROOF validates the receipt, making PROVE_ALL/NONE/APP observable:
      'all'  -> receipt reaches DELIVERED,
      'none' -> no proof, receipt never DELIVERS (eventually FAILED),
      'app'  -> DELIVERED only when the callback returns True (payload[0]==0x01).
    Returns {sent, receipt_id}; poll via wire_packet_receipt_status (stashed in
    the same receipts table as wire_send_packet).
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", ""))
    create_receipt = bool(params.get("create_receipt", True))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    packet = RNS.Packet(link, payload, create_receipt=create_receipt)
    receipt = packet.send()
    if receipt is False:
        return {"sent": False, "receipt_id": None}
    receipt_id = None
    if receipt is not None:
        receipt_id = secrets.token_hex(8)
        with _instances_lock:
            inst.setdefault("receipts", {})[receipt_id] = receipt
    return {"sent": True, "receipt_id": receipt_id}


def cmd_wire_send_over_closed_link(params):
    """Drive real RNS.Packet.send() over a CLOSED link and report that nothing
    was transmitted (Packet.py:280-286).

    RNS.Packet.send short-circuits when the destination is a Link in state
    CLOSED: it sets self.sent=False, self.receipt=None and returns False
    WITHOUT incrementing the link's txbytes or handing the packet to any
    interface. This builds a real RNS.Packet bound to the (already torn-down)
    link, snapshots link.txbytes, calls the real send(), and reports the
    boolean RNS returned plus the txbytes delta so a test can assert send()==
    False AND bytes_transmitted==0.

    The caller must first drive the link to CLOSED (e.g. wire_link_teardown).
    Returns {link_status, link_status_name, sent, bytes_transmitted}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", "")) or b"after-close"

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    status_names = {
        RNS.Link.PENDING: "PENDING", RNS.Link.HANDSHAKE: "HANDSHAKE",
        RNS.Link.ACTIVE: "ACTIVE", RNS.Link.STALE: "STALE",
        RNS.Link.CLOSED: "CLOSED",
    }
    tx_before = int(getattr(link, "txbytes", 0))
    packet = RNS.Packet(link, payload, create_receipt=True)
    result = packet.send()
    tx_after = int(getattr(link, "txbytes", 0))
    return {
        "link_status": int(link.status),
        "link_status_name": status_names.get(link.status, str(link.status)),
        # send() returns False on a closed link, else a receipt or None.
        "sent": result is not False,
        "bytes_transmitted": tx_after - tx_before,
    }


def cmd_wire_send_keepalive_probe(params):
    """Inject a decrypted 0xFF keepalive into a link's receive path and report
    the link's response — making the keepalive byte protocol observable
    (Link.py:848-849/:974/:1149-1153).

    On a NON-initiator (a listener's inbound link) RNS answers a 0xFF with
    bytes([0xFE]) (Link.py:1151) and updates last_keepalive/last_inbound but NOT
    last_data; the captured response is "fe". On an INITIATOR link the receive
    guard (Link.py:974) drops the link's own 0xFF echo entirely — no answer,
    last_inbound/last_data unchanged. Returns {response, answered, initiator,
    last_inbound_advanced, last_data_advanced, status_before, status_after}.
    Pass `value` (hex, default "ff") to inject a different keepalive byte.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    value = bytes.fromhex(params.get("value", "ff"))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = _find_link_by_id(inst, link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    store = inst.setdefault("keepalive_payloads", {})

    # Build a properly-framed inbound keepalive packet (unencrypted — KEEPALIVE
    # ciphertext == data, Packet.py:206-209), then feed it through link.receive
    # as if it arrived on the link's attached interface.
    out_packet = RNS.Packet(link, value, context=RNS.Packet.KEEPALIVE)
    out_packet.pack()
    rx = RNS.Packet(None, out_packet.raw)
    if not rx.unpack():
        raise RuntimeError("could not unpack crafted keepalive packet")
    rx.receiving_interface = link.attached_interface

    # Capture the link's own keepalive emission (the 0xFE answer) during receive.
    captured = []
    orig_send = RNS.Packet.send

    def capturing_send(pkt_self, _orig=orig_send):
        try:
            if (getattr(pkt_self, "context", None) == RNS.Packet.KEEPALIVE
                    and getattr(pkt_self, "destination", None) is link):
                captured.append(bytes(pkt_self.data))
        except Exception:
            pass
        return _orig(pkt_self)

    last_inbound_before = getattr(link, "last_inbound", 0) or 0
    last_data_before = getattr(link, "last_data", 0) or 0
    status_before = getattr(link, "status", None)

    RNS.Packet.send = capturing_send
    try:
        link.receive(rx)
    finally:
        RNS.Packet.send = orig_send

    response = captured[-1] if captured else None
    if response is not None:
        store[link_id] = response

    return {
        "response": response.hex() if response is not None else None,
        "answered": bool(captured),
        "initiator": bool(getattr(link, "initiator", False)),
        "last_inbound_advanced": (getattr(link, "last_inbound", 0) or 0) > last_inbound_before,
        "last_data_advanced": (getattr(link, "last_data", 0) or 0) > last_data_before,
        "status_before": int(status_before) if status_before is not None else None,
        "status_after": int(getattr(link, "status", -1)),
    }


def cmd_wire_last_keepalive(params):
    """Return the last keepalive byte this link emitted/answered (hex), or
    payload=None. "ff" for an initiator's own keepalive (captured by wrapping
    send_keepalive in wire_link_open), "fe" for a non-initiator's answer
    (captured by wire_send_keepalive_probe). Lets a test assert the exact
    keepalive byte values rather than only the timing (Link.py:848-849/:1151).
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    payload = inst.get("keepalive_payloads", {}).get(link_id)
    return {"payload": payload.hex() if isinstance(payload, (bytes, bytearray)) else None}


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

    envelopes: list of {sequence: int, data: hex, msgtype?: int}. Each is packed
    into a real RNS.Channel.Envelope (struct ">HHH" MSGTYPE/sequence/len +
    payload) and handed to Channel._receive — exactly the bytes the channel would
    see off the wire. RNS then reorders by sequence and drops duplicates;
    delivered payloads (in delivery order) are observable via
    wire_channel_received.

    `msgtype` (optional, per envelope) overrides the Channel MSGTYPE. Omitted (or
    equal to the registered wire msgtype) -> the normal registered message type.
    Any other value packs an envelope whose MSGTYPE is NOT in the channel's
    message factories, so RNS drops it without advancing the rx sequence — the
    observable for the unregistered-msgtype-dropped rule. The packing always goes
    through real RNS Envelope.pack; only the message class's MSGTYPE differs.
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
    default_msgclass = _get_channel_message_class()
    from RNS.Channel import Envelope, MessageBase

    def _msgclass_for(msgtype):
        if msgtype is None or int(msgtype) == _WIRE_CHANNEL_MSGTYPE:
            return default_msgclass

        class _AdHocChannelMessage(MessageBase):
            MSGTYPE = int(msgtype)

            def __init__(self, data=b""):
                self.data = bytes(data)

            def pack(self):
                return self.data

            def unpack(self, raw):
                self.data = bytes(raw)

        return _AdHocChannelMessage

    injected = []
    for env in envelopes:
        if env.get("raw") is not None:
            # Raw-override: feed crafted envelope bytes verbatim to the live
            # Channel._receive, bypassing Envelope.pack entirely. The receiver
            # parses the `>HHH` header off these exact bytes — used to drive a
            # deliberately-wrong length field (the receiver ignores it and
            # delivers raw[6:] regardless). The crafted bytes originate in the
            # test (not assembled here); the bridge only hands them to RNS.
            raw = bytes.fromhex(env["raw"])
            channel._receive(raw)
            injected.append(int(env.get("sequence", -1)))
            continue
        seq = int(env["sequence"])
        data = bytes.fromhex(env.get("data", ""))
        msgclass = _msgclass_for(env.get("msgtype"))
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
    # Initiator side: messages recorded by _ensure_channel_state on an out_link.
    state = inst.get("channels", {}).get(link_id)
    if state is not None:
        with state["lock"]:
            out = [d.hex() for d in state["received"]]
            state["received"].clear()
        return {"messages": out}
    # Receiver side: messages recorded by the wire_listen channel handler on the
    # inbound link whose link_id matches (the same value on both peers).
    for listener in inst.get("listeners", {}).values():
        with listener["recv_lock"]:
            inbound = list(listener.get("inbound_links", []))
        if any(getattr(lk, "link_id", None) == link_id for lk in inbound):
            with listener["recv_lock"]:
                out = [d.hex() for d in listener.get("channel_received", [])]
                listener["channel_received"].clear()
            return {"messages": out}
    return {"messages": []}


def cmd_wire_channel_window(params):
    """Report a link channel's real window + sequence state.

    Fields read straight off RNS.Channel: window / window_min / window_max /
    window_flexibility, next_rx_sequence (the low edge of the receive
    window — advances as contiguous envelopes are delivered), next_sequence
    (tx), and the current rx/tx ring depths. `tx_tries` is the max retransmit
    count across in-flight tx envelopes and `tx_envelopes` lists each
    in-flight envelope's {sequence, tries} — the observable for the Channel
    retransmission-backoff / 5-try-teardown gap (Channel.py:555-584).
    """
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    state = _ensure_channel_state(inst, link_id)
    ch = state["channel"]
    tx_envelopes = []
    max_tries = 0
    try:
        for env in list(ch._tx_ring):
            tries = int(getattr(env, "tries", 0) or 0)
            tx_envelopes.append({"sequence": int(getattr(env, "sequence", -1)), "tries": tries})
            if tries > max_tries:
                max_tries = tries
    except Exception:
        pass
    return {
        "window": int(ch.window),
        "window_min": int(ch.window_min),
        "window_max": int(ch.window_max),
        "window_flexibility": int(ch.window_flexibility),
        "next_rx_sequence": int(ch._next_rx_sequence),
        "next_sequence": int(ch._next_sequence),
        "rx_ring": len(ch._rx_ring),
        "tx_ring": len(ch._tx_ring),
        "tx_tries": max_tries,
        "tx_envelopes": tx_envelopes,
        # Channel.mdu (Channel.py:642-655): outlet.mdu - 6, capped at 0xFFFF.
        "mdu": int(ch.mdu),
        # The uncapped outlet (link) MDU the ME_TOO_BIG guard actually compares
        # against (Channel.send checks len(raw) > outlet.mdu, NOT channel.mdu).
        "outlet_mdu": int(ch._outlet.mdu),
    }


def cmd_wire_channel_send(params):
    """Perform a REAL RNS.Channel.send over an established link — the honest
    replacement for the dead cmd_rns_channel_send (zero callers).

    The Channel is keyed by its Link, so `channel_id` (or `link_id`) carries the
    link id. Sends a _WireChannelMessage; by default waits for the send receipt
    to DELIVER (the peer proves the CHANNEL packet, Link.py:1165-1173) or the
    link to be torn down.

    drop_acks (default False): neuter THIS message's receipt so the peer's PROOF
    can't validate it. RNS then retransmits with an increasing timeout window
    and, after _max_tries (5) unanswered tries, tears the link down and shrinks
    the window (Channel.py:555-584). The neutering is applied inside the outlet
    send — before any proof can round-trip — so it is race-free; resends reuse
    the same (neutered) receipt.

    msgtype (optional): request a specific Channel MSGTYPE. A value >= 0xf000 is
    system-reserved (Channel.py:328-345) and must be rejected — returns
    {rejected: True, error} without sending.

    Returns {sent, delivered, tries, sequence, window, window_max, link_status}
    (or {rejected, error} for a reserved msgtype). timeout_ms bounds the wait.
    """
    RNS = _get_rns()
    from RNS.Channel import MessageState

    handle = params["handle"]
    link_id_hex = params.get("link_id") or params.get("channel_id")
    if not link_id_hex:
        raise ValueError("wire_channel_send requires link_id (or channel_id)")
    link_id = bytes.fromhex(link_id_hex)
    payload = bytes.fromhex(params.get("data", ""))
    drop_acks = bool(params.get("drop_acks", False))
    fail_outlet = bool(params.get("fail_outlet", False))
    msgtype = params.get("msgtype")
    timeout_ms = int(params.get("timeout_ms", 20000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    # Reserved-MSGTYPE rejection (construction-time guard, Channel.py:336-338).
    if msgtype is not None and int(msgtype) >= 0xF000:
        state = _ensure_channel_state(inst, link_id)
        channel = state["channel"]
        from RNS.Channel import MessageBase, ChannelException

        class _ReservedMessage(MessageBase):
            MSGTYPE = int(msgtype)

            def pack(self):
                return b""

            def unpack(self, raw):
                pass

        try:
            channel.register_message_type(_ReservedMessage)
            return {"rejected": False, "error": None, "sent": False}
        except ChannelException as e:
            return {"rejected": True, "error": str(e), "sent": False}

    state = _ensure_channel_state(inst, link_id)
    channel = state["channel"]
    link = inst.get("out_links", {}).get(link_id)
    msgclass = _get_channel_message_class()
    message = msgclass(payload)

    # Wait until the channel can accept a send (window not saturated).
    deadline = time.time() + timeout_ms / 1000.0
    while not channel.is_ready_to_send() and time.time() < deadline:
        time.sleep(0.02)
    if not channel.is_ready_to_send():
        return {
            "sent": False, "delivered": False, "tries": 0, "sequence": None,
            "window": int(channel.window), "window_max": int(channel.window_max),
            "ready": False,
        }

    if drop_acks:
        # Persistently neuter the receipt of EVERY (re)send on this outlet so the
        # returning proof can never validate it. Transport.outbound creates a
        # FRESH receipt on each resend (Transport.py:1112), so neutering only the
        # first would let a retransmit's receipt deliver — we must wrap both send
        # and resend. The neutering is applied synchronously inside the outlet
        # call (before any proof can round-trip), so it is race-free. No restore:
        # the link is torn down after _max_tries, ending this outlet's life.
        outlet = channel._outlet
        if not getattr(outlet, "_wire_drop_acks", False):
            orig_send = outlet.send
            orig_resend = outlet.resend

            def _neuter(packet):
                try:
                    if packet is not None and getattr(packet, "receipt", None) is not None:
                        packet.receipt.validate_proof = lambda *a, **k: False
                        packet.receipt.validate_proof_packet = lambda *a, **k: False
                except Exception:
                    pass
                return packet

            def dropping_send(raw, _orig=orig_send):
                return _neuter(_orig(raw))

            def dropping_resend(packet, _orig=orig_resend):
                return _neuter(_orig(packet))

            outlet.send = dropping_send
            outlet.resend = dropping_resend
            outlet._wire_drop_acks = True

    from RNS.Channel import ChannelException

    if fail_outlet:
        # Fault-injection: make the outlet's transmit return None for THIS send
        # so Channel.send hits its "outlet did not transmit" branch — which
        # RESTORES the reserved _next_sequence and raises ME_LINK_NOT_READY
        # (Channel.py:619-626). Restored synchronously, then the wrapper is
        # removed so a subsequent normal send reuses the freed sequence.
        outlet = channel._outlet
        orig_send = outlet.send
        outlet.send = lambda raw: None
        try:
            channel.send(message)
            outlet.send = orig_send
            return {"sent": True, "rejected": False, "error": None,
                    "next_sequence": int(channel._next_sequence)}
        except ChannelException as e:
            outlet.send = orig_send
            return {
                "sent": False, "rejected": True, "delivered": False,
                "error": str(e), "ce_type": int(e.type),
                "next_sequence": int(channel._next_sequence),
                "window": int(channel.window), "window_max": int(channel.window_max),
            }

    try:
        envelope = channel.send(message)
    except ChannelException as e:
        # ME_TOO_BIG and any other channel-layer rejection: the message was
        # NOT transmitted and (for ME_TOO_BIG) _next_sequence was not advanced
        # (the size guard runs before the increment, Channel.py:614-617).
        return {
            "sent": False, "rejected": True, "delivered": False,
            "error": str(e), "ce_type": int(e.type),
            "next_sequence": int(channel._next_sequence),
            "window": int(channel.window), "window_max": int(channel.window_max),
        }

    # Observe the outcome: delivery (non-drop) or retransmit/teardown (drop).
    def _delivered():
        pkt = getattr(envelope, "packet", None)
        if pkt is None:
            return False
        try:
            return channel._outlet.get_packet_state(pkt) == MessageState.MSGSTATE_DELIVERED
        except Exception:
            return False

    link_closed = lambda: (link is not None and getattr(link, "status", None) == RNS.Link.CLOSED)
    while time.time() < deadline:
        if _delivered() or link_closed():
            break
        time.sleep(0.05)

    return {
        "sent": True,
        "rejected": False,
        "delivered": _delivered(),
        "tries": int(getattr(envelope, "tries", 0) or 0),
        "sequence": int(getattr(envelope, "sequence", -1)),
        "next_sequence": int(channel._next_sequence),
        "window": int(channel.window),
        "window_max": int(channel.window_max),
        "link_status": int(getattr(link, "status", -1)) if link is not None else None,
    }


def cmd_wire_channel_register(params):
    """Drive RNS.Channel message-type registration validation on a real channel.

    `kind` selects a crafted message class fed to the live
    Channel._register_message_type / Channel.register_message_type
    (Channel.py:318-345), returning {accepted, error, ce_type} — the
    ChannelException code RNS raised (or None on accept). Kinds:

      valid             — a well-formed MessageBase subclass; accepted.
      non_message_base  — a plain class (not a MessageBase subclass).
      msgtype_none      — a MessageBase subclass whose MSGTYPE is None.
      reserved          — a MessageBase subclass with MSGTYPE >= 0xf000.
      not_constructible — a MessageBase subclass whose __init__ requires args
                          (so message_class() raises during validation).

    The special kind `envelope_pack_no_msgtype` instead exercises
    Envelope.pack's ME_NO_MSG_TYPE guard (Channel.py:193-194): it packs a real
    Envelope wrapping a MSGTYPE-None message and returns the raised ce_type.

    All exceptions come from real RNS; the bridge only constructs the crafted
    classes and reports what RNS did.
    """
    RNS = _get_rns()
    from RNS.Channel import MessageBase, ChannelException, Envelope

    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    kind = params["kind"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    state = _ensure_channel_state(inst, link_id)
    channel = state["channel"]

    if kind == "envelope_pack_no_msgtype":
        class _NoTypeMessage(MessageBase):
            MSGTYPE = None

            def pack(self):
                return b""

            def unpack(self, raw):
                pass

        try:
            Envelope(outlet=None, message=_NoTypeMessage(), sequence=0).pack()
            return {"accepted": True, "error": None, "ce_type": None}
        except ChannelException as e:
            return {"accepted": False, "error": str(e), "ce_type": int(e.type)}

    if kind == "non_message_base":
        class _NotAMessage:  # deliberately NOT a MessageBase subclass
            MSGTYPE = 0x0303

        message_class = _NotAMessage
    elif kind == "msgtype_none":
        class _NoneType(MessageBase):
            MSGTYPE = None

            def pack(self):
                return b""

            def unpack(self, raw):
                pass

        message_class = _NoneType
    elif kind == "reserved":
        class _Reserved(MessageBase):
            MSGTYPE = 0xF001

            def pack(self):
                return b""

            def unpack(self, raw):
                pass

        message_class = _Reserved
    elif kind == "not_constructible":
        class _NeedsArg(MessageBase):
            MSGTYPE = 0x0404

            def __init__(self, required):  # no default -> () construction fails
                self.required = required

            def pack(self):
                return b""

            def unpack(self, raw):
                pass

        message_class = _NeedsArg
    elif kind == "valid":
        class _Valid(MessageBase):
            MSGTYPE = 0x0505

            def __init__(self, data=b""):
                self.data = bytes(data)

            def pack(self):
                return self.data

            def unpack(self, raw):
                self.data = bytes(raw)

        message_class = _Valid
    else:
        raise ValueError(f"Unknown register kind: {kind}")

    try:
        channel.register_message_type(message_class)
        return {"accepted": True, "error": None, "ce_type": None}
    except ChannelException as e:
        return {"accepted": False, "error": str(e), "ce_type": int(e.type)}


def cmd_wire_channel_envelope_pack(params):
    """Pack a Channel.Envelope via REAL RNS and return its wire bytes.

    A pure-function delegation (no link/handle needed): builds a minimal
    MessageBase subclass whose MSGTYPE == the requested `msgtype` and whose
    pack() returns the requested `data`, wraps it in a real
    RNS.Channel.Envelope at the requested `sequence`, and returns
    Envelope.pack() — i.e. the exact `>HHH`(MSGTYPE, sequence, length) + data
    header layout RNS itself emits (Channel.py:192-198). The test then asserts
    the returned bytes equal an INDEPENDENT struct.pack of that header, pinning
    the 6-byte big-endian envelope header. All byte assembly happens inside
    real RNS Envelope.pack; the bridge never constructs wire bytes itself.
    """
    RNS = _get_rns()
    from RNS.Channel import Envelope, MessageBase

    msgtype = int(params["msgtype"])
    sequence = int(params["sequence"])
    data = bytes.fromhex(params.get("data", ""))

    class _PackMessage(MessageBase):
        MSGTYPE = msgtype

        def __init__(self, payload=b""):
            self.payload = bytes(payload)

        def pack(self):
            return self.payload

        def unpack(self, raw):
            self.payload = bytes(raw)

    envelope = Envelope(outlet=None, message=_PackMessage(data), sequence=sequence)
    raw = envelope.pack()
    return {"raw": raw.hex(), "sequence": int(envelope.sequence)}


def cmd_wire_buffer_pack(params):
    """Pack (or unpack) a Buffer StreamDataMessage via REAL RNS.

    Pure-function delegation over RNS.Buffer.StreamDataMessage (Buffer.py:44-97):

      pack mode (default): construct StreamDataMessage(stream_id, data, eof,
      compressed) and return {raw, msgtype}. raw is StreamDataMessage.pack() —
      the 2-byte big-endian header (eof bit 0x8000, compressed bit 0x4000,
      14-bit stream id 0x3fff) followed by the payload, all assembled inside
      RNS. msgtype is StreamDataMessage.MSGTYPE (SMT_STREAM_DATA). A stream_id
      above STREAM_ID_MAX (0x3fff) surfaces the constructor ValueError as
      {error}.

      unpack mode (when `unpack_raw` is supplied): construct an empty
      StreamDataMessage and call its real unpack() on the supplied bytes,
      returning the decoded {stream_id, eof, compressed, data} — pinning the
      header bit-field decode and the `& 0x3fff` stream-id masking.
    """
    RNS = _get_rns()
    from RNS.Buffer import StreamDataMessage

    if params.get("unpack_raw") is not None:
        raw = bytes.fromhex(params["unpack_raw"])
        message = StreamDataMessage()
        try:
            message.unpack(raw)
        except Exception as e:
            return {"error": str(e)}
        return {
            "stream_id": int(message.stream_id),
            "eof": bool(message.eof),
            "compressed": bool(message.compressed),
            "data": (message.data or b"").hex(),
        }

    stream_id = int(params["stream_id"])
    data = bytes.fromhex(params.get("data", ""))
    eof = bool(params.get("eof", False))
    compressed = bool(params.get("compressed", False))
    try:
        message = StreamDataMessage(stream_id, data, eof=eof, compressed=compressed)
        raw = message.pack()
    except ValueError as e:
        return {"error": str(e)}
    return {"raw": raw.hex(), "msgtype": int(StreamDataMessage.MSGTYPE)}


# ---------------------------------------------------------------------------
# Buffer (RawChannelReader / RawChannelWriter) streaming
# ---------------------------------------------------------------------------

def cmd_wire_buffer_stream(params):
    """Stream bytes over a link via RNS.Buffer (RawChannelWriter).

    Writes `data` through a RawChannelWriter on the out-link's Channel; the
    payload is chunked into StreamDataMessages (Channel SMT_STREAM_DATA 0xff00,
    MAX_DATA_LEN per send, MAX_CHUNK_LEN=16 KiB per write) and reassembled by the
    peer's RawChannelReader (created at link establishment by wire_listen). A
    payload spanning several chunks + a partial final chunk exercises multi-chunk
    reassembly + EOF; read it back with wire_buffer_received on the receiver.

    stream_id (default _WIRE_BUFFER_STREAM_ID): the RECEIVER-relative stream id
    the writer targets — drive a non-default id to exercise multi-reader
    stream-id filtering (Buffer.py:152).

    bomb (default False): instead of `data`, send a single crafted chunk whose
    compressed body decompresses to `bomb_decompressed_len` bytes (default
    MAX_CHUNK_LEN*4). The receiver's StreamDataMessage.unpack accepts a chunk
    that inflates to exactly MAX_CHUNK_LEN (16384) but aborts with IOError when
    it would exceed it (Buffer.py:95-97) — observable via wire_buffer_received
    aborted / the receiver channel's _next_rx_sequence (wire_listener_channel_rx).
    The crafted chunk is a real bz2.compress of bytes(N) wrapped in a real
    StreamDataMessage and sent through the real channel; no wire bytes are
    assembled here.

    Per-message manifest: this command always returns `manifest`, the list of
    {bytes, compressed, eof, sequence} for every StreamDataMessage the writer
    emitted (captured by reading each sent message's own attributes + the real
    Envelope sequence returned by Channel.send), and `write_returns`, the
    per-write() processed-length the RawChannelWriter reported. These pin the
    MAX_DATA_LEN chunk cap, the compression decision, and the per-write return
    semantics (Buffer.py RawChannelWriter.write).

    EOF mode (default: empty trailing eof message): set `eof_with_data` to flag
    EOF on the FINAL data-bearing message (data + eof together), or `use_close`
    to terminate via RawChannelWriter.close() (which drains the tx ring before
    flushing the empty eof, Buffer.py close path). `tx_ring_after` reports the
    channel tx-ring depth once delivery settles.

    Returns {written, eof, manifest, write_returns, max_data_len, max_chunk_len,
    compression_tries, tx_ring_after, bomb?, sequence?}.
    """
    RNS = _get_rns()
    import bz2
    from RNS.Buffer import StreamDataMessage, RawChannelWriter

    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    data = bytes.fromhex(params.get("data", ""))
    bomb = bool(params.get("bomb", False))
    bomb_len = params.get("bomb_decompressed_len")
    stream_id = int(params.get("stream_id", _WIRE_BUFFER_STREAM_ID))
    eof_with_data = bool(params.get("eof_with_data", False))
    use_close = bool(params.get("use_close", False))
    timeout_ms = int(params.get("timeout_ms", 30000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    channel = link.get_channel()
    deadline = time.time() + timeout_ms / 1000.0

    def _wait_ready():
        while not channel.is_ready_to_send() and time.time() < deadline:
            time.sleep(0.02)
        return channel.is_ready_to_send()

    # Capture every StreamDataMessage the channel actually transmits by reading
    # the message's own attributes plus the real Envelope sequence Channel.send
    # returns — the manifest is observation, never reconstruction.
    manifest = []
    orig_send = channel.send

    def capturing_send(message, _orig=orig_send):
        env = _orig(message)
        try:
            if isinstance(message, StreamDataMessage):
                manifest.append({
                    "bytes": len(message.data or b""),
                    "compressed": bool(message.compressed),
                    "eof": bool(message.eof),
                    "sequence": int(getattr(env, "sequence", -1)),
                })
        except Exception:
            pass
        return env

    channel.send = capturing_send
    try:
        if bomb:
            # A real bz2 compression of bytes(N) wrapped in a real
            # StreamDataMessage. N == MAX_CHUNK_LEN inflates to exactly the bound
            # and is accepted; N > MAX_CHUNK_LEN aborts the receiver's unpack.
            oversize = (
                int(bomb_len) if bomb_len is not None
                else RawChannelWriter.MAX_CHUNK_LEN * 4
            )
            compressed = bz2.compress(bytes(oversize))
            if len(compressed) >= StreamDataMessage.MAX_DATA_LEN:
                raise RuntimeError("crafted bomb chunk does not fit a single message")
            # eof=True so an ACCEPTED chunk concludes the receiver stream cleanly;
            # an aborted chunk never reaches the eof handling (unpack raises first).
            message = StreamDataMessage(stream_id, compressed, eof=True, compressed=True)
            if not _wait_ready():
                return {"written": 0, "eof": False, "ready": False, "manifest": manifest}
            env = channel.send(message)
            return {
                "written": 0,
                "eof": True,
                "bomb": True,
                "decompressed_len": oversize,
                "sequence": int(getattr(env, "sequence", -1)),
                "manifest": manifest,
                "max_chunk_len": int(RawChannelWriter.MAX_CHUNK_LEN),
            }

        writer = RawChannelWriter(stream_id, channel)
        remaining = data
        total = 0
        write_returns = []
        while remaining and time.time() < deadline:
            if not channel.is_ready_to_send():
                time.sleep(0.02)
                continue
            # eof_with_data: flag EOF on the final data-bearing write so its
            # StreamDataMessage carries both payload and the EOF marker. The
            # final write is the one whose remaining fits a single message.
            if eof_with_data and len(remaining) <= StreamDataMessage.MAX_DATA_LEN:
                writer._eof = True
            n = writer.write(remaining)
            if n and n > 0:
                remaining = remaining[n:]
                total += n
                write_returns.append(int(n))
            else:
                time.sleep(0.02)

        if use_close:
            # RawChannelWriter.close drains the tx ring (waits for is_ready)
            # then flushes an empty EOF message.
            try:
                writer.close()
            except Exception:
                pass
        elif not eof_with_data:
            # Default: flush an empty EOF message once the ring drains.
            _wait_ready()
            writer._eof = True
            try:
                writer.write(b"")
            except Exception:
                pass

        # Let delivery settle so tx_ring_after reflects a drained ring (every
        # emitted envelope proved and removed from the tx ring).
        _wait_ready()
        while time.time() < deadline:
            try:
                if len(channel._tx_ring) == 0:
                    break
            except Exception:
                break
            time.sleep(0.05)
        try:
            tx_ring_after = len(channel._tx_ring)
        except Exception:
            tx_ring_after = -1

        return {
            "written": total,
            "eof": True,
            "manifest": manifest,
            "write_returns": write_returns,
            "max_data_len": int(StreamDataMessage.MAX_DATA_LEN),
            "max_chunk_len": int(RawChannelWriter.MAX_CHUNK_LEN),
            "compression_tries": int(RawChannelWriter.COMPRESSION_TRIES),
            "tx_ring_after": tx_ring_after,
        }
    finally:
        try:
            del channel.send
        except Exception:
            channel.send = orig_send


def cmd_wire_buffer_received(params):
    """Drain what a listener's RawChannelReader reassembled from a stream.

    Pairs with wire_buffer_stream on the sender. Blocks up to timeout_ms for the
    stream to conclude (EOF) or abort (bz2-bomb). Returns {data, eof, aborted,
    error}: `data` is the byte-exact reassembly across all chunks (hex), `eof`
    True once the writer's EOF marker was seen, `aborted` True iff the reader hit
    the MAX_CHUNK_LEN decompression bound (Buffer.py:95-97), `error` the abort
    reason when aborted.
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

    buffer_state = listener.get("buffer_state") or {}
    recv_lock = listener["recv_lock"]
    # stream_id (default _WIRE_BUFFER_STREAM_ID): which receiver-relative
    # RawChannelReader to drain. A reader registered for stream A sees nothing
    # of a stream sent to B (Buffer.py:152) — read each id to pin that.
    sid_param = params.get("stream_id")

    def _reader():
        if sid_param is not None:
            return (buffer_state.get("readers") or {}).get(int(sid_param))
        return buffer_state.get("reader")

    # Accumulate the reassembled stream as a hex string (the RawChannelReader
    # already holds the protocol-decoded bytes; we only concatenate the drained
    # chunks, never reconstruct any wire structure here). MAX_READ caps a single
    # _read() at 1 MiB (== 1 << 20).
    MAX_READ = 1048576
    data_hex = ""
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        reader = _reader()
        chunk = None
        if reader is not None:
            try:
                chunk = reader._read(MAX_READ)
            except Exception:
                chunk = None
        if chunk:
            data_hex += chunk.hex()
            continue
        eof = bool(reader is not None and getattr(reader, "_eof", False))
        aborted = bool(buffer_state.get("aborted"))
        if eof or aborted:
            break
        time.sleep(0.05)

    reader = _reader()
    # Final drain.
    if reader is not None:
        try:
            tail = reader._read(MAX_READ)
            while tail:
                data_hex += tail.hex()
                tail = reader._read(MAX_READ)
        except Exception:
            pass
    return {
        "data": data_hex,
        "eof": bool(reader is not None and getattr(reader, "_eof", False)),
        "aborted": bool(buffer_state.get("aborted")),
        "error": buffer_state.get("error"),
    }


def cmd_wire_channel_emit_capture(params):
    """Send a REAL Channel message and capture the CONTEXT byte of the Packet
    the Channel's outlet actually emits.

    Wraps the link's LinkChannelOutlet.send to read the packet.context of every
    packet it transmits (the packet is built by RNS itself —
    LinkChannelOutlet.send does ``RNS.Packet(link, raw, context=RNS.Packet.CHANNEL)``,
    Channel.py:669-670 — so this only READS the attribute), performs a real
    Channel.send of a recording message, and returns {context, packet_hash,
    delivered, channel_context}. `channel_context` is RNS.Packet.CHANNEL read
    off the live module (the external ground-truth value the emit must equal).
    """
    RNS = _get_rns()
    from RNS.Channel import MessageState

    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", ""))
    timeout_ms = int(params.get("timeout_ms", 15000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    state = _ensure_channel_state(inst, link_id)
    channel = state["channel"]
    outlet = channel._outlet

    captured = []
    orig_send = outlet.send

    def capturing_send(raw, _orig=orig_send):
        packet = _orig(raw)
        try:
            if packet is not None:
                captured.append({
                    "context": int(getattr(packet, "context", -1)),
                    "packet_type": int(getattr(packet, "packet_type", -1)),
                    "hash": (packet.packet_hash.hex()
                             if getattr(packet, "packet_hash", None) else None),
                })
        except Exception:
            pass
        return packet

    outlet.send = capturing_send
    try:
        deadline = time.time() + timeout_ms / 1000.0
        while not channel.is_ready_to_send() and time.time() < deadline:
            time.sleep(0.02)
        msgclass = _get_channel_message_class()
        envelope = channel.send(msgclass(payload))

        def _delivered():
            pkt = getattr(envelope, "packet", None)
            if pkt is None:
                return False
            try:
                return outlet.get_packet_state(pkt) == MessageState.MSGSTATE_DELIVERED
            except Exception:
                return False

        while time.time() < deadline and not _delivered():
            time.sleep(0.05)
        last = captured[-1] if captured else {}
        return {
            "context": last.get("context"),
            "packet_type": last.get("packet_type"),
            "packet_hash": last.get("hash"),
            "delivered": _delivered(),
            "channel_context": int(RNS.Packet.CHANNEL),
            "data_context": int(RNS.Packet.NONE),
        }
    finally:
        try:
            del outlet.send
        except Exception:
            outlet.send = orig_send


def cmd_wire_listener_proof_log(params):
    """Return the receiver-side proof log for a listening destination.

    {contexts: [int,...], channel_proofs: int}. `contexts` is the context byte
    of every inbound packet the receiver PROVED (its inbound Link.prove_packet),
    in order; `channel_proofs` counts the CHANNEL-context (0x0E) proofs. A peer
    with NO open channel proves ZERO CHANNEL packets (Link.py:1166-1167 drops
    them unproven); a peer with a channel proves them (Link.py:1172).
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    listener = inst.get("listeners", {}).get(destination_hash)
    if listener is None:
        raise ValueError(
            f"No listener registered for destination_hash={destination_hash.hex()}"
        )
    with listener["recv_lock"]:
        contexts = list(listener.get("proof_log", []))
    channel_ctx = int(RNS.Packet.CHANNEL)
    return {
        "contexts": contexts,
        "channel_proofs": sum(1 for c in contexts if c == channel_ctx),
        "channel_context": channel_ctx,
    }


def cmd_wire_listener_channel_rx(params):
    """Read the receiver-side Channel rx state for a listening destination.

    Returns {next_rx_sequence, next_sequence, rx_ring} read straight off the
    inbound Link's real RNS.Channel. The receive sequence advances only when a
    StreamDataMessage/Envelope unpacks cleanly (Channel._receive); a chunk that
    aborts the decompression bound never advances it (Buffer.py:95-97 raises in
    unpack, before the sequence bump).
    """
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    listener = inst.get("listeners", {}).get(destination_hash)
    if listener is None:
        raise ValueError(
            f"No listener registered for destination_hash={destination_hash.hex()}"
        )
    buffer_state = listener.get("buffer_state") or {}
    reader = buffer_state.get("reader")
    channel = None
    if reader is not None:
        channel = getattr(reader, "_channel", None)
    if channel is None:
        with listener["recv_lock"]:
            links = list(listener.get("inbound_links", []))
        if links:
            channel = links[0].get_channel()
    if channel is None:
        raise ValueError("no inbound channel on this listener")
    return {
        "next_rx_sequence": int(channel._next_rx_sequence),
        "next_sequence": int(channel._next_sequence),
        "rx_ring": len(channel._rx_ring),
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


# ---------------------------------------------------------------------------
# Destination-level ratchets (latest_ratchet_id / rotation-interval gating /
# retained-cap / file persistence / Identity ratchet expiry)
#
# All drive the REAL RNS.Destination / RNS.Identity ratchet machinery on a
# ratchet-enabled SINGLE destination (created via wire_announce
# enable_ratchets=True). Timestamps are manipulated deterministically — no
# real sleeps — to make rotation-interval and expiry gating observable.
# ---------------------------------------------------------------------------

def _ratchet_id_hex(RNS, private_bytes):
    """ratchet_id (Identity.py:410-411) of a ratchet PRIVATE key, as hex."""
    pub = RNS.Identity._ratchet_public_bytes(private_bytes)
    return RNS.Identity._get_ratchet_id(pub).hex()


def _current_ratchet_id(destination):
    """Hex ratchet_id of the newest (index 0) ratchet, or None."""
    from bridge_server import _get_full_rns
    RNS = _get_full_rns()
    if not getattr(destination, "ratchets", None):
        return None
    return _ratchet_id_hex(RNS, destination.ratchets[0])


def _previous_ratchet_id(destination):
    """Hex ratchet_id of the second-newest (index 1) ratchet, or None."""
    from bridge_server import _get_full_rns
    RNS = _get_full_rns()
    rs = getattr(destination, "ratchets", None)
    if not rs or len(rs) < 2:
        return None
    return _ratchet_id_hex(RNS, rs[1])


def _ratchet_dest_or_raise(inst, dest_hash, handle):
    """Locate a ratchet-ENABLED SINGLE destination by hash, or raise.

    The destination must have been created with wire_announce
    enable_ratchets=True (so destination.ratchets is a list, not None).
    """
    destination = _find_destination_by_hash(inst, dest_hash)
    if destination is None:
        raise ValueError(
            f"No registered destination with hash {dest_hash.hex()} on "
            f"handle {handle}; call wire_announce(enable_ratchets=True) first."
        )
    if getattr(destination, "ratchets", None) is None:
        raise ValueError(
            f"Destination {dest_hash.hex()} does not have ratchets enabled; "
            f"call wire_announce(enable_ratchets=True)."
        )
    return destination


def _ratchet_snapshot(destination):
    """Read-only snapshot of a ratchet-enabled destination's ratchet state."""
    rs = getattr(destination, "ratchets", None)
    latest = getattr(destination, "latest_ratchet_id", None)
    return {
        "ratchet_count": len(rs) if rs is not None else 0,
        "current_ratchet_id": _current_ratchet_id(destination),
        "previous_ratchet_id": _previous_ratchet_id(destination),
        "ratchet_interval": int(destination.ratchet_interval),
        "retained_ratchets": int(destination.retained_ratchets),
        "latest_ratchet_id": latest.hex() if isinstance(latest, (bytes, bytearray)) else None,
        "latest_ratchet_time": destination.latest_ratchet_time,
    }


def cmd_wire_read_ratchets(params):
    """Read the current ratchet state of a ratchet-enabled destination.

    Returns {ratchet_count, current_ratchet_id, previous_ratchet_id,
    ratchet_interval, retained_ratchets, latest_ratchet_id,
    latest_ratchet_time}. The current/previous ids + count are the
    observables for the rotation-interval gating test (Destination.py:227-241).
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _ratchet_dest_or_raise(inst, dest_hash, handle)
    return _ratchet_snapshot(destination)


def cmd_wire_set_ratchet_interval(params):
    """Set a destination's minimum ratchet-rotation interval in seconds
    (real RNS.Destination.set_ratchet_interval, Destination.py:519-531).

    Returns {ok, ratchet_interval}. `ok` is False for a non-positive / non-int
    value (RNS rejects it and leaves the interval unchanged).
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    seconds = params["seconds"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _ratchet_dest_or_raise(inst, dest_hash, handle)
    # Pass int (RNS requires isinstance int); a float arg is coerced so the
    # command is forgiving, but a non-positive value is forwarded as-is so the
    # rejection (returns False) stays observable.
    arg = seconds if not isinstance(seconds, bool) and isinstance(seconds, int) else int(seconds)
    ok = bool(destination.set_ratchet_interval(arg))
    return {"ok": ok, "ratchet_interval": int(destination.ratchet_interval)}


def cmd_wire_rotate_ratchet(params):
    """Trigger a ratchet rotation and observe the rotation-INTERVAL gate
    (Destination.py:227-241) WITHOUT a real wait.

    rotate_ratchets() only inserts a new ratchet when
    now > latest_ratchet_time + ratchet_interval. Pass
    last_rotation_ago_s to deterministically backdate latest_ratchet_time
    (so the gate either opens or stays shut): a value < ratchet_interval
    leaves the count unchanged (gated); a value > ratchet_interval inserts a
    new newest ratchet (the prior current becomes previous).

    Returns {rotated, before_count, after_count, before_current_id,
    current_ratchet_id, previous_ratchet_id, ratchet_interval,
    latest_ratchet_time}. `rotated` is after_count > before_count.
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    last_rotation_ago_s = params.get("last_rotation_ago_s")
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _ratchet_dest_or_raise(inst, dest_hash, handle)

    if last_rotation_ago_s is not None:
        destination.latest_ratchet_time = time.time() - float(last_rotation_ago_s)

    before_count = len(destination.ratchets)
    before_current = _current_ratchet_id(destination)
    destination.rotate_ratchets()
    after_count = len(destination.ratchets)
    return {
        "rotated": after_count > before_count,
        "before_count": before_count,
        "after_count": after_count,
        "before_current_id": before_current,
        "current_ratchet_id": _current_ratchet_id(destination),
        "previous_ratchet_id": _previous_ratchet_id(destination),
        "ratchet_interval": int(destination.ratchet_interval),
        "latest_ratchet_time": destination.latest_ratchet_time,
    }


def cmd_wire_set_retained_ratchets(params):
    """Set the retained-ratchets cap and observe RATCHET_COUNT truncation
    (real RNS.Destination.set_retained_ratchets, Destination.py:504-517).

    set_retained_ratchets(n) sets retained_ratchets and runs _clean_ratchets
    (Destination.py:205-208), which truncates the list to Destination.
    RATCHET_COUNT (512) when len exceeds the retained cap. To make the cap
    observable cheaply, pass pad_to=N to first inflate the ratchets list with
    N real freshly-generated ratchets (RNS.Identity._generate_ratchet) before
    applying the cap.

    Returns {ok, retained_ratchets, ratchet_count, ratchet_count_cap}.
    `ok` is False for a non-positive / non-int n (RNS rejects it).
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    n = params["n"]
    pad_to = params.get("pad_to")
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _ratchet_dest_or_raise(inst, dest_hash, handle)

    if pad_to is not None:
        pad_to = int(pad_to)
        while len(destination.ratchets) < pad_to:
            destination.ratchets.append(RNS.Identity._generate_ratchet())

    arg = n if not isinstance(n, bool) and isinstance(n, int) else int(n)
    ok = bool(destination.set_retained_ratchets(arg))
    return {
        "ok": ok,
        "retained_ratchets": int(destination.retained_ratchets),
        "ratchet_count": len(destination.ratchets),
        "ratchet_count_cap": int(RNS.Destination.RATCHET_COUNT),
    }


def cmd_wire_ratchet_file_roundtrip(params):
    """Persist + reload a destination's ratchet store and confirm the signed
    on-disk store round-trips (Destination.py:210-225 _persist_ratchets /
    :426-464 _reload_ratchets).

    Drives a fresh Destination._persist_ratchets (which writes the signed
    on-disk blob), clears the in-memory ratchet list, then reloads via
    Destination._reload_ratchets. _reload_ratchets validates the embedded
    signature against the destination identity and only repopulates
    destination.ratchets when it verifies (raising otherwise, :432-437/:450-458).
    A successful reload that reproduces the ratchet list byte-exact therefore
    proves the persisted store carried a valid signature over the well-formed
    format -- the bridge does NOT re-implement or hand-parse the on-disk format;
    the validation is RNS's own.

    Returns {ratchets_path_set, reload_ok, ratchet_count_before,
    ratchet_count_after, roundtrip_match, ratchet_ids}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _ratchet_dest_or_raise(inst, dest_hash, handle)
    if not destination.ratchets_path:
        raise ValueError(
            f"Destination {dest_hash.hex()} has no ratchets_path; ratchets must "
            f"be enabled with a file path (wire_announce enable_ratchets=True)."
        )

    def _ratchet_ids(ratchets):
        return [_ratchet_id_hex(RNS, r) for r in ratchets]

    before_ratchets = list(destination.ratchets)
    ratchet_count_before = len(before_ratchets)
    ids_before = _ratchet_ids(before_ratchets)
    ratchets_path = destination.ratchets_path

    # Force a fresh signed write to disk.
    destination._persist_ratchets()

    # Reload from disk into a clean in-memory list. _reload_ratchets validates
    # the embedded signature against the destination identity and only sets
    # destination.ratchets when it verifies; reload_ok therefore reflects that
    # the persisted signature was valid and the format well-formed (an invalid
    # signature or malformed blob makes RNS raise here).
    destination.ratchets = None
    reload_ok = True
    try:
        destination._reload_ratchets(ratchets_path)
    except Exception:
        reload_ok = False
    after_ratchets = list(destination.ratchets) if destination.ratchets is not None else []
    ratchet_count_after = len(after_ratchets)
    ids_after = _ratchet_ids(after_ratchets)

    return {
        "ratchets_path_set": True,
        "reload_ok": reload_ok,
        "ratchet_count_before": ratchet_count_before,
        "ratchet_count_after": ratchet_count_after,
        "roundtrip_match": ids_before == ids_after and ratchet_count_before == ratchet_count_after,
        "ratchet_ids": ids_after,
    }


def cmd_wire_destination_latest_ratchet_id(params):
    """Drive a real Destination.encrypt + Destination.decrypt round-trip on a
    ratchet-enabled SINGLE destination and expose latest_ratchet_id
    (Destination.py:595-643).

    encrypt() selects the current ratchet via RNS.Identity.get_ratchet and
    sets destination.latest_ratchet_id to that ratchet's id (Destination.py:
    596-599). decrypt() re-derives it via ratchet_id_receiver=self
    (Identity.py:889-890). Both should equal the current ratchet id — the
    discriminating observable that the SINGLE auto-ratchet path actually
    tracked a ratchet (not None) for an app-level message.

    Returns {decrypted, plaintext, latest_ratchet_id, encrypt_ratchet_id,
    current_ratchet_id, match, ratchet_count}.
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    probe = bytes.fromhex(params.get("data", "")) or b"ratchet-probe"
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _ratchet_dest_or_raise(inst, dest_hash, handle)

    ciphertext = destination.encrypt(probe)
    enc_id = getattr(destination, "latest_ratchet_id", None)
    plaintext = destination.decrypt(ciphertext)
    dec_id = getattr(destination, "latest_ratchet_id", None)
    decrypted = plaintext == probe
    return {
        "decrypted": bool(decrypted),
        "plaintext": plaintext.hex() if isinstance(plaintext, (bytes, bytearray)) else None,
        "latest_ratchet_id": dec_id.hex() if isinstance(dec_id, (bytes, bytearray)) else None,
        "encrypt_ratchet_id": enc_id.hex() if isinstance(enc_id, (bytes, bytearray)) else None,
        "current_ratchet_id": _current_ratchet_id(destination),
        "match": bool(
            isinstance(enc_id, (bytes, bytearray))
            and isinstance(dec_id, (bytes, bytearray))
            and enc_id == dec_id
        ),
        "ratchet_count": len(destination.ratchets) if destination.ratchets is not None else 0,
    }


# ---------------------------------------------------------------------------
# Receiver-side ratchet ADOPTION (a peer that heard a ratcheted announce) and
# adoption-driven sender-side target-key selection. These delegate entirely to
# RNS.Identity.get_ratchet / recall / encrypt and RNS.Destination.decrypt — the
# same code Destination.encrypt uses to pick an ECDH target (Destination.py:
# 595-599) — so a test can prove peer B adopts peer A's announced ratchet and
# then encrypts to A under that ratchet (not A's static X25519 key).
# ---------------------------------------------------------------------------

def cmd_wire_get_adopted_ratchet(params):
    """Report the ratchet this peer ADOPTED for a REMOTE destination after
    hearing that destination's ratcheted announce (receiver-side adoption,
    RNS.Identity.get_ratchet / _get_ratchet_id, Identity.py:396-411,499-520).

    When peer B receives peer A's announce with the ratchet context flag set,
    RNS.Transport validates it and Identity._remember_ratchet caches A's
    announced ratchet PUBLIC key under A's destination hash. This surfaces that
    adopted ratchet (32-byte public + its 10-byte ratchet id) so a test can
    assert B adopted A's announced ratchet, that a newer announce REPLACES it,
    and that an unknown / never-announced destination yields nothing.

    Returns {found, ratchet_public, ratchet_id}.
    """
    RNS = _get_rns()
    destination_hash = bytes.fromhex(params["destination_hash"])
    ratchet_public = RNS.Identity.get_ratchet(destination_hash)
    if not ratchet_public:
        return {"found": False, "ratchet_public": None, "ratchet_id": None}
    ratchet_id = RNS.Identity._get_ratchet_id(ratchet_public)
    return {
        "found": True,
        "ratchet_public": ratchet_public.hex(),
        "ratchet_id": ratchet_id.hex(),
    }


def cmd_wire_encrypt_to_remote(params):
    """Encrypt a plaintext to a REMOTE destination, auto-selecting the ratchet
    this peer ADOPTED from that destination's announce — the same target-key
    choice Destination.encrypt makes (Destination.py:595-599), via
    RNS.Identity.recall + get_ratchet + Identity.encrypt(ratchet=...).

    B recalls A's Identity from the received announce, looks up the ratchet it
    adopted for A (get_ratchet), and encrypts to that ratchet public key. With
    use_ratchet=False the static X25519 key is used instead (the negative
    control), so a test can prove the adopted-ratchet ciphertext decrypts under
    A's ratchet PRIVATE key rather than A's static key.

    Returns {ciphertext, used_ratchet, ratchet_id, ratchet_public}.
    """
    RNS = _get_rns()
    destination_hash = bytes.fromhex(params["destination_hash"])
    plaintext = bytes.fromhex(params.get("plaintext", ""))
    use_ratchet = bool(params.get("use_ratchet", True))

    identity = RNS.Identity.recall(destination_hash)
    if identity is None:
        raise RuntimeError(
            f"No identity known for {destination_hash.hex()}; ensure an "
            f"announce for this destination was received first."
        )
    ratchet_public = (
        RNS.Identity.get_ratchet(destination_hash) if use_ratchet else None
    )
    ciphertext = identity.encrypt(plaintext, ratchet=ratchet_public)
    ratchet_id = (
        RNS.Identity._get_ratchet_id(ratchet_public) if ratchet_public else None
    )
    return {
        "ciphertext": ciphertext.hex(),
        "used_ratchet": ratchet_public is not None,
        "ratchet_id": ratchet_id.hex() if ratchet_id is not None else None,
        "ratchet_public": ratchet_public.hex() if ratchet_public else None,
    }


def cmd_wire_destination_decrypt(params):
    """Decrypt a ciphertext on a local SINGLE destination, exposing WHICH ratchet
    (if any) decrypted it (real RNS.Destination.decrypt, Destination.py:611-643).

    Destination.decrypt passes ratchet_id_receiver=self, so Identity.decrypt sets
    destination.latest_ratchet_id to the id of the ratchet that succeeded, or to
    None when the message was decrypted with the static private key instead
    (Identity.py:886-913). This is the discriminator that proves an inbound
    ciphertext was encrypted to this destination's adopted ratchet (id set) vs
    its static key (id None).

    Returns {decrypted, plaintext, latest_ratchet_id}.
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    ciphertext = bytes.fromhex(params["ciphertext"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _find_destination_by_hash(inst, dest_hash)
    if destination is None:
        raise ValueError(
            f"No registered destination with hash {dest_hash.hex()} on handle {handle}."
        )
    # Clear any stale tracking from a previous decrypt so the read-back reflects
    # only this call (Destination.decrypt re-sets it via ratchet_id_receiver).
    destination.latest_ratchet_id = None
    plaintext = destination.decrypt(ciphertext)
    latest = getattr(destination, "latest_ratchet_id", None)
    return {
        "decrypted": plaintext is not None,
        "plaintext": (
            plaintext.hex() if isinstance(plaintext, (bytes, bytearray)) else None
        ),
        "latest_ratchet_id": (
            latest.hex() if isinstance(latest, (bytes, bytearray)) else None
        ),
    }


def cmd_wire_reannounce(params):
    """Re-announce an already-registered SINGLE IN destination (real
    RNS.Destination.announce, Destination.py:265-311).

    For a ratchet-enabled destination, announce() rotates the ratchet (gated by
    the rotation interval) and carries the new latest ratchet public key, then
    Identity._remember_ratchet caches it, so a receiver re-adopts the newer
    ratchet. Pass rotate_ago_s to backdate latest_ratchet_time so the rotation
    gate opens deterministically (Destination.rotate_ratchets, Destination.py:
    227-241), forcing a genuinely NEW ratchet for the "newer announce replaces
    the adopted ratchet" case.

    Returns {announced, current_ratchet_id}.
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    app_data_hex = params.get("app_data") or ""
    rotate_ago_s = params.get("rotate_ago_s")
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _find_destination_by_hash(inst, dest_hash)
    if destination is None:
        raise ValueError(
            f"No registered destination with hash {dest_hash.hex()} on handle {handle}."
        )
    if rotate_ago_s is not None and getattr(destination, "ratchets", None) is not None:
        destination.latest_ratchet_time = time.time() - float(rotate_ago_s)
    app_data = bytes.fromhex(app_data_hex) if app_data_hex else None
    destination.announce(app_data=app_data)
    return {
        "announced": True,
        "current_ratchet_id": _current_ratchet_id(destination),
    }


def cmd_wire_set_proof_implicit(params):
    """Toggle this instance's implicit-vs-explicit single-packet PROOF policy
    (RNS.Reticulum.should_use_implicit_proof, Reticulum.py:555-558,1699-1705).

    With enabled=False the PROVER emits the EXPLICIT proof form
    (packet_hash(32) || signature(64) = EXPL_LENGTH bytes) instead of the
    implicit signature-only form (Identity.prove, Identity.py:959-970). Set on
    the destination owner (the prover) before the proof is requested, so a test
    can drive and validate the 96-byte explicit layout end-to-end.

    Returns {implicit_proof}.
    """
    RNS = _get_rns()
    enabled = bool(params.get("enabled", True))
    # should_use_implicit_proof() reads the (name-mangled) class attribute set
    # in Reticulum.__init__; flip it directly so the prover's emit path branches.
    RNS.Reticulum._Reticulum__use_implicit_proof = enabled
    return {"implicit_proof": bool(RNS.Reticulum.should_use_implicit_proof())}


# ---------------------------------------------------------------------------
# Single-packet PROOF emission (implicit vs explicit), PLAIN no-op crypto,
# request-handler deregister, known-public-key-mismatch rejection, and the
# two deferred Link edges (forged LINKCLOSE, identify on a PENDING link).
# ---------------------------------------------------------------------------

def cmd_wire_send_packet_with_proof_request(params):
    """Send a single SINGLE-destination DATA packet (tracked PacketReceipt)
    and capture the PROOF the receiver returns (Destination.py:359-368,
    Identity.py:959-970, Transport.py:2155-2165).

    When the receiver's destination has proof_strategy PROVE_ALL/PROVE_APP it
    emits a PROOF; RNS validates it against the originating receipt using the
    receiver's public key (Packet.py:498-537), setting receipt.proved and
    stashing receipt.proof_packet. This command waits for that, then surfaces
    the proof bytes and whether RNS used an IMPLICIT (signature only,
    IMPL_LENGTH) or EXPLICIT (packet_hash+signature, EXPL_LENGTH) proof per
    RNS.Reticulum.should_use_implicit_proof().

    Returns {sent, receipt_id, hops, delivered, proved, implicit_proof_config,
    proof_data, proof_len, proof_is_implicit, proof_is_explicit,
    impl_length, expl_length}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    payload = bytes.fromhex(params.get("data", ""))
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
        identity, RNS.Destination.OUT, RNS.Destination.SINGLE, app_name, *aspects,
    )
    packet = RNS.Packet(out_destination, payload, create_receipt=True)
    receipt = packet.send()
    if receipt is False:
        return {"sent": False, "receipt_id": None, "hops": None, "delivered": False}

    hops = int(RNS.Transport.hops_to(destination_hash))
    inst["destinations"].append((identity, out_destination))

    DELIVERED = RNS.PacketReceipt.DELIVERED
    FAILED = RNS.PacketReceipt.FAILED
    CULLED = RNS.PacketReceipt.CULLED
    deadline = time.time() + (timeout_ms / 1000.0)
    while time.time() < deadline:
        st = receipt.get_status()
        if st in (DELIVERED, FAILED, CULLED):
            break
        time.sleep(0.05)

    receipt_id = secrets.token_hex(8)
    inst.setdefault("receipts", {})[receipt_id] = receipt

    proof_packet = getattr(receipt, "proof_packet", None)
    proof_data = getattr(proof_packet, "data", None) if proof_packet is not None else None
    proof_len = len(proof_data) if isinstance(proof_data, (bytes, bytearray)) else None
    impl_len = int(RNS.PacketReceipt.IMPL_LENGTH)
    expl_len = int(RNS.PacketReceipt.EXPL_LENGTH)
    # Capture the RAW wire frame of the PROOF the receiver emitted (the bytes
    # RNS received and unpacked into proof_packet) so a test can assert the
    # proof packet's flag-byte shape — PROOF type, context NONE, HEADER_1,
    # hops, and the SINGLE destination-type bits — and that it is addressed to
    # the truncated hash of the proved packet (ProofDestination.hash,
    # Packet.py:336-339). proved_packet_hash is the receipt's full packet hash;
    # the proof's destination_hash is its first TRUNCATED_HASHLENGTH//8 bytes.
    proof_raw = getattr(proof_packet, "raw", None) if proof_packet is not None else None
    proved_packet_hash = getattr(receipt, "hash", None)
    return {
        "sent": True,
        "receipt_id": receipt_id,
        "hops": hops,
        "delivered": receipt.get_status() == DELIVERED,
        "proved": bool(getattr(receipt, "proved", False)),
        "implicit_proof_config": bool(RNS.Reticulum.should_use_implicit_proof()),
        "proof_data": proof_data.hex() if isinstance(proof_data, (bytes, bytearray)) else None,
        "proof_len": proof_len,
        "proof_is_implicit": proof_len == impl_len if proof_len is not None else None,
        "proof_is_explicit": proof_len == expl_len if proof_len is not None else None,
        "impl_length": impl_len,
        "expl_length": expl_len,
        "proof_raw": proof_raw.hex() if isinstance(proof_raw, (bytes, bytearray)) else None,
        "proved_packet_hash": (
            proved_packet_hash.hex()
            if isinstance(proved_packet_hash, (bytes, bytearray)) else None
        ),
    }


def cmd_wire_deregister_request_handler(params):
    """Deregister a request handler by path (real RNS.Destination.
    deregister_request_handler, Destination.py:389-401).

    Returns {deregistered} — True if a handler for the path existed and was
    removed, False otherwise. After this, a request to the same path is no
    longer answered (the requester's RequestReceipt never reaches READY),
    which is the discriminating control versus a still-registered handler.
    """
    handle = params["handle"]
    dest_hash = bytes.fromhex(params["destination_hash"])
    path = params["path"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    destination = _find_destination_by_hash(inst, dest_hash)
    if destination is None:
        raise ValueError(
            f"No registered destination with hash {dest_hash.hex()} on handle {handle}."
        )
    deregistered = bool(destination.deregister_request_handler(path))
    # Drop the local response mapping so a later re-register starts clean; the
    # invocation log is left intact so prior-call assertions still work.
    _request_handler_responses.pop((handle, dest_hash, path), None)
    return {"deregistered": deregistered}


def _plain_destination(RNS, inst, app_name, aspects):
    """Get-or-create a cached PLAIN IN destination on this instance.

    A PLAIN destination holds no keys; encrypt/decrypt are identity no-ops
    (Destination.py:592-593/:618-619). Cached per (app_name, aspects) so
    repeated calls don't churn Transport.destinations.
    """
    key = (app_name, tuple(aspects))
    cache = inst.setdefault("plain_dests", {})
    dest = cache.get(key)
    if dest is None:
        dest = RNS.Destination(
            None, RNS.Destination.IN, RNS.Destination.PLAIN, app_name, *aspects,
        )
        cache[key] = dest
        inst["destinations"].append((None, dest))
    return dest


def cmd_wire_plain_encrypt(params):
    """Encrypt via a PLAIN destination — a no-op passthrough that returns the
    plaintext unchanged (Destination.py:592-593). Returns {ciphertext,
    passthrough} where passthrough is ciphertext == plaintext.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    plaintext = bytes.fromhex(params.get("plaintext", ""))
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    dest = _plain_destination(RNS, inst, app_name, aspects)
    ciphertext = dest.encrypt(plaintext)
    return {
        "ciphertext": ciphertext.hex(),
        "passthrough": ciphertext == plaintext,
    }


def cmd_wire_plain_decrypt(params):
    """Decrypt via a PLAIN destination — a no-op passthrough that returns the
    ciphertext unchanged (Destination.py:618-619). Returns {plaintext,
    passthrough} where passthrough is plaintext == ciphertext.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    ciphertext = bytes.fromhex(params.get("ciphertext", ""))
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    dest = _plain_destination(RNS, inst, app_name, aspects)
    plaintext = dest.decrypt(ciphertext)
    return {
        "plaintext": plaintext.hex(),
        "passthrough": plaintext == ciphertext,
    }


def cmd_wire_known_key_validate(params):
    """Validate a real signed announce against a planted known public key for
    the same destination hash, exercising the known-key-mismatch rejection
    (Identity.py:583-589).

    Builds a genuine SINGLE destination + signed announce, then seeds
    Identity.known_destinations[dest_hash] with a chosen public key before
    calling RNS.Identity.validate_announce:
      plant='mismatch' -> a DIFFERENT key is stored: the announce's valid key
        != stored key, so validate_announce REJECTS (returns False).
      plant='match'    -> the announce's own key is stored: accepted (True).
      plant='none'     -> no prior entry: accepted (True).
    The same announce flips accept/reject solely on the stored key — that
    divergence is the property.

    Returns {validated, destination_hash, public_key, planted_public_key, plant}.
    """
    RNS = _get_rns()
    from RNS.vendor import umsgpack  # noqa: F401  (parity with RNS internals)
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = params.get("aspects", []) or []
    plant = str(params.get("plant", "mismatch")).lower()
    if plant not in ("mismatch", "match", "none"):
        raise ValueError(f"plant must be 'mismatch', 'match' or 'none' (got {plant!r})")
    app_data_hex = params.get("app_data") or ""
    app_data = bytes.fromhex(app_data_hex) if app_data_hex else None
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    identity = RNS.Identity()
    destination = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, *aspects,
    )
    real_pub = identity.get_public_key()
    dest_hash = destination.hash

    # Build a genuine signed announce and re-parse it as a received packet.
    announce_packet = destination.announce(app_data=app_data, send=False)
    announce_packet.pack()
    rx = RNS.Packet(None, announce_packet.raw)
    if not rx.unpack():
        raise RuntimeError("could not unpack crafted announce packet")

    planted = None
    if plant == "match":
        planted = real_pub
    elif plant == "mismatch":
        planted = RNS.Identity().get_public_key()  # a different, valid key

    Identity = RNS.Identity
    with Identity.known_destinations_lock:
        Identity.known_destinations.pop(dest_hash, None)
        if planted is not None:
            # known_destinations entry layout: [packet_hash, received, public_key, app_data]
            Identity.known_destinations[dest_hash] = [rx.get_hash(), time.time(), planted, app_data]

    validated = bool(Identity.validate_announce(rx))
    # Keep refs alive until validation finished.
    inst["destinations"].append((identity, destination))
    return {
        "validated": validated,
        "destination_hash": dest_hash.hex(),
        "public_key": real_pub.hex(),
        "planted_public_key": planted.hex() if planted is not None else None,
        "plant": plant,
    }


def cmd_wire_send_forged_link_close(params):
    """Inject a LINKCLOSE carrying a forged (wrong) link_id over an established
    link and report whether it tore the link down (Link.py:710-722).

    teardown_packet only closes the link when the decrypted payload equals the
    link's own link_id. A forged id (forged_id != link_id) must be ignored —
    the link stays ACTIVE. Passing the real link_id as forged_id is the
    positive control (the link DOES close). The crafted packet is built and
    encrypted to the real link, then fed through link.receive on the link's
    own attached interface (so the unexpected-interface guard, Link.py:975,
    does not pre-empt the teardown check).

    Returns {torn_down, status_before, status_after, status_name_after,
    forged_id, real_link_id}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    forged_id = bytes.fromhex(params["forged_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = _find_link_by_id(inst, link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    status_before = getattr(link, "status", None)
    # LINKCLOSE payloads ARE encrypted to the link (Packet.py:215-216), unlike
    # KEEPALIVE; build + pack so link.decrypt(packet.data) yields forged_id.
    out_packet = RNS.Packet(link, forged_id, context=RNS.Packet.LINKCLOSE)
    out_packet.pack()
    rx = RNS.Packet(None, out_packet.raw)
    if not rx.unpack():
        raise RuntimeError("could not unpack crafted LINKCLOSE packet")
    rx.receiving_interface = link.attached_interface
    link.receive(rx)

    status_after = getattr(link, "status", None)
    return {
        "torn_down": status_after == RNS.Link.CLOSED,
        "status_before": int(status_before) if status_before is not None else None,
        "status_after": int(status_after) if status_after is not None else None,
        "status_name_after": _LINK_STATUS_NAMES.get(status_after),
        "forged_id": forged_id.hex(),
        "real_link_id": link.link_id.hex(),
    }


def cmd_wire_inject_crafted_proof(params):
    """Adversarial single-packet PROOF injector.

    Crafts a PROOF of a chosen `variant` against a pending PacketReceipt and
    feeds it through the REAL RNS.PacketReceipt.validate_proof gate (Packet.py):
    a 96-byte EXPLICIT proof is packet_hash(32)||signature(64), a 64-byte
    IMPLICIT proof is signature(64), any OTHER length is rejected outright, and
    the signature is validated against the receipt destination's identity. This
    drives the proof-acceptance rules the ordinary harness can't reach — a
    forged signature, a wrong proof-hash, or a disallowed length.

    The receiver's private key lives in a different bridge process (the peers
    talk over real TCP), so a genuinely-valid proof cannot be signed here — the
    positive control is the real receiver proving over the wire (PROVE_ALL).
    Every variant below is a REJECTION case, none of which needs the receiver
    key:
      forged_implicit / forged_explicit — a structurally valid Ed25519 signature
        under a THROWAWAY (wrong) key; the length is correct but the signature
        must fail validation against the receipt destination's identity.
      wrong_hash_explicit — a random proof-hash prefix (!= receipt.hash) with a
        throwaway signature; the explicit proof-hash check rejects it before the
        signature is even considered.
      wrong_length_short / wrong_length_mid / wrong_length_long — random bytes of
        32 / 65 / 97 bytes (none equal to IMPL_LENGTH=64 or EXPL_LENGTH=96),
        exercising the length gate.

    Calls receipt.validate_proof(proof) directly (the exact gate Transport hands
    an inbound PROOF to) and returns {variant, validated, status, status_name,
    proved, proof_len}. Reusable for any pending PacketReceipt.
    """
    RNS = _get_rns()
    handle = params["handle"]
    receipt_id = params["receipt_id"]
    variant = params["variant"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    receipt = inst.get("receipts", {}).get(receipt_id)
    if receipt is None:
        raise ValueError(f"Unknown receipt_id: {receipt_id}")

    proven_hash = receipt.hash
    HASHLEN = RNS.Identity.HASHLENGTH // 8   # 32
    SIGLEN = RNS.Identity.SIGLENGTH // 8     # 64

    if variant == "forged_implicit":
        proof = RNS.Identity().sign(proven_hash)
    elif variant == "forged_explicit":
        proof = proven_hash + RNS.Identity().sign(proven_hash)
    elif variant == "wrong_hash_explicit":
        proof = secrets.token_bytes(HASHLEN) + RNS.Identity().sign(proven_hash)
    elif variant == "wrong_length_short":
        proof = secrets.token_bytes(HASHLEN)               # 32B
    elif variant == "wrong_length_mid":
        proof = secrets.token_bytes(SIGLEN + 1)            # 65B
    elif variant == "wrong_length_long":
        proof = secrets.token_bytes(HASHLEN + SIGLEN + 1)  # 97B
    else:
        raise ValueError(f"unknown proof variant: {variant!r}")

    proof = bytes(proof)
    validated = bool(receipt.validate_proof(proof))
    status = receipt.get_status()
    return {
        "variant": variant,
        "validated": validated,
        "status": int(status),
        "status_name": _PACKET_RECEIPT_STATUS_NAMES.get(status),
        "proved": bool(getattr(receipt, "proved", False)),
        "proof_len": len(proof),
    }


def cmd_wire_inject_tampered_link_data(params):
    """Adversarial tampered-token injector for an ACTIVE link.

    Builds a real DATA packet encrypted to an established link (the same path
    cmd_wire_send_forged_link_close uses for LINKCLOSE), optionally CORRUPTS it,
    and feeds it through the link's real receive path (link.receive), reporting
    whether the decrypted message reached the link's packet handler.

    The link layer's RNS Token verifies its HMAC over IV||ciphertext BEFORE
    decrypting (Token.decrypt), so any tamper makes link.decrypt return None and
    the packet is silently dropped — no handler call, link stays ACTIVE. An
    impl that decrypts without verifying the HMAC (or ignores the auth failure)
    would deliver forged/garbage data.

    corruption:
      none       — a pristine packet; MUST be delivered (positive control).
      ciphertext — flip a byte inside IV/ciphertext -> HMAC mismatch -> drop.
      hmac       — flip the trailing HMAC byte -> mismatch -> drop.
      truncate   — drop the last byte -> malformed token -> drop.
      foreign_interface — a PRISTINE packet, but presented on an interface that
                 is NOT link.attached_interface -> Link.receive's interface-bind
                 check (Link.py:975) rejects it before decrypt -> not delivered.

    Run this on the RECEIVER peer (it owns the inbound link + its packet
    handler). Returns {corruption, unpacked, delivered, link_active,
    status_name}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", ""))
    corruption = params.get("corruption", "none")

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = _find_link_by_id(inst, link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    # Find the listener whose inbound link this is, so we can read its packet
    # handler's delivery buffer (set_packet_callback -> recv_buffer in
    # cmd_wire_listen) before and after the injection.
    listener = None
    for cand in inst.get("listeners", {}).values():
        with cand["recv_lock"]:
            ids = [getattr(x, "link_id", None) for x in cand.get("inbound_links", [])]
        if link_id in ids:
            listener = cand
            break
    if listener is None:
        raise ValueError(
            f"link_id {link_id.hex()} is not an inbound link of any listener on "
            f"this peer (run the injector on the RECEIVER peer)"
        )

    with listener["recv_lock"]:
        before = len(listener["recv_buffer"])

    # Build a real DATA packet encrypted to the link, then corrupt it.
    out_packet = RNS.Packet(link, payload, context=RNS.Packet.NONE)
    out_packet.pack()
    raw = bytearray(out_packet.raw)
    # HEADER_1 link packet: flags(1)+hops(1)+link_id(16)+context(1) = 19, then
    # the encrypted token (IV(16)||ciphertext||HMAC(32)).
    # Damage one byte (arithmetic change, not protocol assembly) — enough to
    # make the link's Token HMAC mismatch. The packet itself was produced by
    # real RNS; we only corrupt it.
    payload_off = 19
    if corruption == "ciphertext":
        raw[payload_off + 4] = (raw[payload_off + 4] + 1) % 256
    elif corruption == "hmac":
        raw[-1] = (raw[-1] + 1) % 256
    elif corruption == "truncate":
        raw = raw[:-1]
    elif corruption in ("none", "foreign_interface"):
        pass  # packet stays pristine; foreign_interface only changes rx iface
    else:
        raise ValueError(f"unknown corruption: {corruption!r}")

    rx = RNS.Packet(None, bytes(raw))
    unpacked = rx.unpack()
    if unpacked:
        if corruption == "foreign_interface":
            # A real interface object that is NOT this link's attached one, so
            # the bind check rejects an otherwise-valid packet. Any live
            # interface on this handle other than the link's works; fall back
            # to a sentinel object if none is available.
            foreign = None
            for cand in _interfaces_matching_handle(inst["rns"], inst["role"]):
                if cand is not link.attached_interface:
                    foreign = cand
                    break
            rx.receiving_interface = foreign if foreign is not None else object()
        else:
            rx.receiving_interface = link.attached_interface
        link.receive(rx)
    # The packet handler runs synchronously in link.receive, but allow a tiny
    # settle margin for any deferred dispatch.
    time.sleep(0.05)

    with listener["recv_lock"]:
        after = len(listener["recv_buffer"])
    status_after = getattr(link, "status", None)
    return {
        "corruption": corruption,
        "unpacked": bool(unpacked),
        "delivered": after > before,
        "link_active": status_after == RNS.Link.ACTIVE,
        "status_name": _LINK_STATUS_NAMES.get(status_after),
    }


def cmd_wire_inject_crafted_resource_part(params):
    """Adversarial resource-part injector (part acceptance, receiver side).

    A Resource receiver accepts an incoming part only if its map hash —
    get_map_hash(part.data) = full_hash(part.data || random_hash)[:MAPHASH_LEN] —
    matches an entry in the expected hashmap window (Resource.receive_part). A
    part with any other map hash (a corrupted-in-flight or forged part) is
    silently dropped. A receiver that reassembles whatever arrives accepts
    forged content.

    Self-contained: builds a real sender Resource on the link (advertise=False),
    constructs the receiver from the sender's real ResourceAdvertisement via the
    real Resource.accept, then feeds a real RESOURCE part through the real
    Resource.receive_part — reporting whether the part was inserted. Variants:
      valid           — the sender's own first part; its map hash matches the
                        hashmap, so it MUST be accepted (positive control).
      forged_map_hash — random part data, whose map hash is not in the hashmap;
                        must be DROPPED (not inserted).

    Returns {variant, accepted, parts_before, parts_after, total_parts}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    variant = params["variant"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    sender = RNS.Resource(secrets.token_bytes(2000), link, advertise=False)
    advertisement = RNS.ResourceAdvertisement(sender)
    adv_plaintext = advertisement.pack()

    # Feed the real advertisement bytes + link to the real Resource.accept, which
    # unpacks the advertisement and builds the receiver Resource itself.
    adv_packet = RNS.Packet(link, adv_plaintext, context=RNS.Packet.RESOURCE_ADV)
    adv_packet.plaintext = adv_plaintext
    adv_packet.link = link
    receiver = RNS.Resource.accept(adv_packet)

    def _received(resource):
        return sum(1 for part in resource.parts if part is not None)

    parts_before = _received(receiver)

    if variant == "valid":
        part_data = sender.parts[0].data
    elif variant == "forged_map_hash":
        part_data = secrets.token_bytes(len(sender.parts[0].data))
    else:
        raise ValueError(f"unknown resource-part variant: {variant!r}")

    part_packet = RNS.Packet(link, part_data, context=RNS.Packet.RESOURCE)
    part_packet.pack()
    rx = RNS.Packet(None, part_packet.raw)
    if rx.unpack():
        receiver.receive_part(rx)

    parts_after = _received(receiver)
    try:
        receiver.cancel()
    except Exception:
        pass
    return {
        "variant": variant,
        "accepted": parts_after > parts_before,
        "parts_before": parts_before,
        "parts_after": parts_after,
        "total_parts": len(receiver.parts),
    }


def cmd_wire_inject_crafted_resource_proof(params):
    """Adversarial RESOURCE_PRF injector (resource proof validation, sender side).

    When a Resource transfer completes, the receiver returns a RESOURCE_PRF of
    exactly hash(32)||proof(32) == 64 bytes, where proof == full_hash(data||hash)
    (Resource.prove). The SENDER validates it (Resource.validate_proof): it
    concludes the resource as COMPLETE ONLY if the proof is exactly 64 bytes and
    its trailing 32 bytes equal the sender's expected_proof; anything else is
    silently dropped. A sender that concludes on any 64-byte blob would accept a
    forged delivery confirmation.

    Self-contained: builds a real sender Resource on an established link
    (exposing a real expected_proof), then calls the real
    Resource.validate_proof with a crafted proof of `variant`, reporting whether
    the resource concluded (status COMPLETE). One fresh Resource per call (a
    valid proof mutates status). Variants:
      valid              — random(32)||expected_proof; MUST conclude (COMPLETE).
      wrong_proof        — random(32)||random(32); trailing 32 != expected_proof.
      wrong_length_short — 32 bytes (!= 64); length gate.
      wrong_length_long  — 96 bytes (!= 64); length gate.

    Returns {variant, concluded, status, status_name, proof_len}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    variant = params["variant"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    resource = RNS.Resource(secrets.token_bytes(200), link, advertise=False)
    expected_proof = resource.expected_proof
    hash_len = RNS.Identity.HASHLENGTH // 8  # 32

    if variant == "valid":
        proof_data = secrets.token_bytes(hash_len) + expected_proof
    elif variant == "wrong_proof":
        proof_data = secrets.token_bytes(hash_len) + secrets.token_bytes(hash_len)
    elif variant == "wrong_length_short":
        proof_data = secrets.token_bytes(hash_len)            # 32B
    elif variant == "wrong_length_long":
        proof_data = secrets.token_bytes(hash_len * 3)        # 96B
    else:
        raise ValueError(f"unknown resource-proof variant: {variant!r}")

    try:
        resource.validate_proof(proof_data)
    except Exception:
        pass
    status_after = getattr(resource, "status", None)
    concluded = status_after == RNS.Resource.COMPLETE
    try:
        resource.cancel()
    except Exception:
        pass
    return {
        "variant": variant,
        "concluded": concluded,
        "status": int(status_after) if status_after is not None else None,
        "status_name": _RESOURCE_STATUS_NAMES.get(status_after),
        "proof_len": len(proof_data),
    }


def cmd_wire_resource_constants(params):
    """Read the Resource / ResourceAdvertisement protocol constants straight off
    the real RNS classes (no reconstruction — every value is the class attribute
    RNS itself uses to drive the transfer state machine).

    These govern the windowed part-request handshake, the hashmap-advertisement
    chunking (HASHMAP_MAX_LEN), the collision-guard scan width, the segmentation
    threshold and the retry budgets. A cross-impl test pins each against its spec
    literal; an impl with any divergent value windows/chunks/segments differently
    and breaks interop. Returns the constant set.
    """
    RNS = _get_rns()
    return {
        "WINDOW": int(RNS.Resource.WINDOW),
        "WINDOW_MIN": int(RNS.Resource.WINDOW_MIN),
        "WINDOW_MAX": int(RNS.Resource.WINDOW_MAX),
        "MAPHASH_LEN": int(RNS.Resource.MAPHASH_LEN),
        "RANDOM_HASH_SIZE": int(RNS.Resource.RANDOM_HASH_SIZE),
        "HASHMAP_MAX_LEN": int(RNS.ResourceAdvertisement.HASHMAP_MAX_LEN),
        "COLLISION_GUARD_SIZE": int(RNS.ResourceAdvertisement.COLLISION_GUARD_SIZE),
        "MAX_EFFICIENT_SIZE": int(RNS.Resource.MAX_EFFICIENT_SIZE),
        "METADATA_MAX_SIZE": int(RNS.Resource.METADATA_MAX_SIZE),
        "MAX_RETRIES": int(RNS.Resource.MAX_RETRIES),
        "MAX_ADV_RETRIES": int(RNS.Resource.MAX_ADV_RETRIES),
        "HASHMAP_IS_EXHAUSTED": int(RNS.Resource.HASHMAP_IS_EXHAUSTED),
        "HASHMAP_IS_NOT_EXHAUSTED": int(RNS.Resource.HASHMAP_IS_NOT_EXHAUSTED),
    }


def cmd_wire_inject_crafted_resource_request(params):
    """Adversarial RESOURCE_REQ injector (sender-side part-request handling).

    A Resource SENDER, once advertised, serves parts in response to RESOURCE_REQ
    packets the receiver emits (Resource.request, Resource.py:982). A request can
    also carry the hashmap-exhausted flag (0xFF) with a last-known map hash,
    asking the sender to emit the NEXT hashmap segment (HMU). The sender resolves
    that last map hash to an absolute part index and REQUIRES the index to fall
    on a HASHMAP_MAX_LEN (74) boundary; a misaligned index is a sequencing error
    that cancels the transfer (Resource.py:1040-1042). An impl that skips that
    gate would emit a desynchronised hashmap segment.

    Self-contained: builds a real sender Resource on the established outbound link
    (advertise=False, so __init__ runs the full hashmap build but nothing goes on
    the wire), primes it as if advertised (status TRANSFERRING, adv_sent set), and
    feeds a crafted RESOURCE_REQ plaintext — assembled ONLY from genuine
    RNS-produced bytes (the sender's own .hash and real part .map_hash values,
    prefixed with the RNS HASHMAP_IS_* marker constant) — straight into the real
    Resource.request. Variants:

      misaligned_hmu — exhausted flag + the map hash of part 0; resolves to
                       part_index 1, 1 % 74 != 0 -> sequencing error -> CANCELLED.
      aligned        — exhausted flag + the map hash of part 73; resolves to
                       part_index 74, 74 % 74 == 0 -> NO cancel (HMU emitted).
      serve_all      — a NOT_EXHAUSTED request naming EVERY part's map hash; the
                       sender serves all parts and, once sent_parts == len(parts),
                       transitions to AWAITING_PROOF (Resource.py:1066). Re-feeding
                       the identical request resends byte-identical part bytes.

    Returns (hmu variants): {variant, cancelled, status, status_name}.
    Returns (serve_all): {variant, served_indices, sent_parts, total_parts,
      identical_on_resend, status_name}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    variant = params["variant"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    if variant in ("misaligned_hmu", "aligned"):
        # Need >=74 parts so part index 73 (the aligned 74th part) exists. Shrink
        # the link MTU for the construction only (restored immediately after) so a
        # modest payload chunks into many small parts (same trick as
        # cmd_wire_resource_create's force_sdu).
        overhead = RNS.Reticulum.HEADER_MAXSIZE + RNS.Reticulum.IFAC_MIN_SIZE
        saved_mtu = link.mtu
        link.mtu = 50 + overhead
        try:
            sender = RNS.Resource(secrets.token_bytes(6000), link, advertise=False)
        finally:
            link.mtu = saved_mtu
        if len(sender.parts) < 74:
            raise ValueError(
                f"need >=74 parts for HMU alignment test, got {len(sender.parts)}"
            )

        # Prime the sender as if it had advertised: request() reads adv_sent and
        # only spawns its watchdog when status != TRANSFERRING, so pre-setting
        # TRANSFERRING keeps the call thread-clean.
        sender.adv_sent = time.time()
        sender.status = RNS.Resource.TRANSFERRING

        exhausted = RNS.Resource.HASHMAP_IS_EXHAUSTED.to_bytes(1, "big")
        part_index = 0 if variant == "misaligned_hmu" else 73
        last_map_hash = sender.parts[part_index].map_hash  # genuine RNS bytes
        # request_data layout mirrors Resource.request_next (Resource.py:965):
        # [exhausted_flag(1)] [last_map_hash(4)] [resource hash(32)] [requested...]
        request_data = exhausted + last_map_hash + sender.hash

        try:
            sender.request(request_data)
        except Exception:
            pass
        status = getattr(sender, "status", None)
        out = {
            "variant": variant,
            "cancelled": status == RNS.Resource.FAILED,
            "status": int(status) if status is not None else None,
            "status_name": _RESOURCE_STATUS_NAMES.get(status),
        }
        try:
            sender.cancel()
        except Exception:
            pass
        return out

    elif variant == "serve_all":
        # A handful of parts so every one is served in a single request and the
        # sender reaches AWAITING_PROOF. Shrink the link MTU for the construction
        # only so a modest payload chunks into several small parts (a large
        # negotiated TCP MDU would otherwise make it a single part).
        overhead = RNS.Reticulum.HEADER_MAXSIZE + RNS.Reticulum.IFAC_MIN_SIZE
        saved_mtu = link.mtu
        link.mtu = 200 + overhead
        try:
            sender = RNS.Resource(secrets.token_bytes(1500), link, advertise=False)
        finally:
            link.mtu = saved_mtu
        sender.adv_sent = time.time()
        sender.status = RNS.Resource.TRANSFERRING

        not_exhausted = RNS.Resource.HASHMAP_IS_NOT_EXHAUSTED.to_bytes(1, "big")
        # sender.hashmap IS RNS's own concatenation of every part's map hash, in
        # part order (Resource.py:471) — naming all of them requests all parts.
        requested = sender.hashmap
        request_data = not_exhausted + sender.hash + requested

        sender.request(request_data)
        served_indices = [i for i, p in enumerate(sender.parts) if getattr(p, "sent", False)]
        sent_parts = int(getattr(sender, "sent_parts", 0))
        status_after = getattr(sender, "status", None)

        # Resend: feed the identical request again; already-sent parts go through
        # part.resend(), which must transmit byte-identical raw bytes.
        raws_before = [p.raw for p in sender.parts]
        sender.status = RNS.Resource.TRANSFERRING  # avoid re-spawning the watchdog
        sender.request(request_data)
        raws_after = [p.raw for p in sender.parts]
        identical_on_resend = raws_before == raws_after

        out = {
            "variant": variant,
            "served_indices": served_indices,
            "sent_parts": sent_parts,
            "total_parts": len(sender.parts),
            "identical_on_resend": bool(identical_on_resend),
            "status_name": _RESOURCE_STATUS_NAMES.get(status_after),
        }
        try:
            sender.cancel()
        except Exception:
            pass
        return out

    raise ValueError(f"unknown resource-request variant: {variant!r}")


def cmd_wire_resource_force_collision(params):
    """Drive the Resource hashmap collision-guard remap loop (Resource.py:436-472).

    While building its hashmap, a sender appends each part's map hash to a
    collision_guard_list; if a map hash repeats within COLLISION_GUARD_SIZE (224)
    parts it abandons the whole hashmap, regenerates a fresh random_hash, and
    rebuilds from scratch (the `while not hashmap_ok` loop). This guards against
    two parts sharing a map hash (which would make the receiver unable to tell
    them apart).

    Forces that path by monkeypatching Resource.get_map_hash so the FIRST build
    pass returns the same (genuine) map hash for parts 0 and 1 — a collision —
    then passes through to the real get_map_hash on the rebuild pass. Every value
    returned is RNS's own computed map hash; the patch only repeats one to trip
    the guard, it does not fabricate bytes. Reports the random_hash before/after
    the remap (they MUST differ — a fresh one is drawn) so a test can pin that the
    guard actually regenerated and rebuilt. Returns {remapped, random_hash_before,
    random_hash_after, hashmap_changed, num_parts}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    real_get_map_hash = RNS.Resource.get_map_hash
    state = {"phase1_done": False, "call": 0, "rh_first": None,
             "rh_second": None, "collide": None}

    def _patched(self, data):
        if not state["phase1_done"]:
            state["rh_first"] = self.random_hash
            state["call"] += 1
            if state["call"] == 1:
                # Genuine map hash of part 0 — reused below to force the collision.
                state["collide"] = real_get_map_hash(self, data)
                return state["collide"]
            # Second part: return part 0's map hash -> collision -> remap.
            state["phase1_done"] = True
            return state["collide"]
        state["rh_second"] = self.random_hash
        return real_get_map_hash(self, data)

    # Shrink the link MTU for the construction only so the payload chunks into
    # several parts (a single-part resource cannot collide). Restored after.
    overhead = RNS.Reticulum.HEADER_MAXSIZE + RNS.Reticulum.IFAC_MIN_SIZE
    saved_mtu = link.mtu
    link.mtu = 200 + overhead
    RNS.Resource.get_map_hash = _patched
    try:
        resource = RNS.Resource(secrets.token_bytes(4000), link, advertise=False)
    finally:
        RNS.Resource.get_map_hash = real_get_map_hash
        link.mtu = saved_mtu

    rh_before = state["rh_first"]
    rh_after = state["rh_second"]
    remapped = rh_before is not None and rh_after is not None and rh_before != rh_after
    return {
        "remapped": bool(remapped),
        "random_hash_before": rh_before.hex() if rh_before else None,
        "random_hash_after": rh_after.hex() if rh_after else None,
        # The hashmap is derived from random_hash, so a fresh random_hash means a
        # fresh hashmap; we also confirm the final object adopted rh_after.
        "hashmap_changed": bool(remapped and resource.random_hash == rh_after),
        "num_parts": len(resource.parts),
    }


def cmd_wire_resource_outgoing_queue_state(params):
    """Pin the one-outgoing-resource-at-a-time rule (Link.ready_for_new_resource,
    Link.py:1328-1329; Resource.__advertise_job QUEUED branch, Resource.py:522-524).

    A Link admits a new outgoing Resource only when it has zero outgoing
    resources in flight; a second Resource advertised while one is registered
    spins in the QUEUED state until the first concludes. An impl that advertises
    two concurrently would interleave two part streams on one link.

    Self-contained and deterministic (no receiver race): builds a first Resource
    inert (advertise=False) and registers it as the link's outgoing resource via
    the real Link.register_outgoing_resource, then advertises a SECOND Resource
    and polls its real status until it reaches QUEUED. Reports
    ready_for_new_resource() with zero vs one outgoing (the positive/negative
    control) and the second resource's status. Returns {ready_empty,
    ready_with_one, first_status, first_status_name, second_status,
    second_status_name, queued}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    timeout_ms = int(params.get("timeout_ms", 5000))
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = inst.get("out_links", {}).get(link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    # Positive control: an idle link with no outgoing resources admits a new one.
    ready_empty = bool(link.ready_for_new_resource())

    first = RNS.Resource(secrets.token_bytes(800), link, advertise=False)
    link.register_outgoing_resource(first)  # genuine RNS registration
    # Negative control: with one registered, the link refuses a new resource.
    ready_with_one = bool(link.ready_for_new_resource())

    second = RNS.Resource(secrets.token_bytes(800), link, advertise=True)
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        if getattr(second, "status", None) == RNS.Resource.QUEUED:
            break
        time.sleep(0.02)

    first_status = getattr(first, "status", None)
    second_status = getattr(second, "status", None)
    out = {
        "ready_empty": ready_empty,
        "ready_with_one": ready_with_one,
        "first_status": int(first_status) if first_status is not None else None,
        "first_status_name": _RESOURCE_STATUS_NAMES.get(first_status),
        "second_status": int(second_status) if second_status is not None else None,
        "second_status_name": _RESOURCE_STATUS_NAMES.get(second_status),
        "queued": second_status == RNS.Resource.QUEUED,
    }
    # Cleanup: cancel the queued second (it loops in its advertise thread) and
    # unregister the inert first.
    try:
        second.cancel()
    except Exception:
        pass
    try:
        link.cancel_outgoing_resource(first)
    except Exception:
        pass
    return out


def cmd_wire_inject_crafted_lrproof(params):
    """Adversarial LRPROOF injector (link-establishment proof validation).

    A link INITIATOR, after sending its LINKREQUEST, sits PENDING until the
    destination returns an LRPROOF: signature(64)||ephemeral_pub(32), where the
    signature is the DESTINATION identity's over link_id||ephemeral_pub||
    destination_signing_pub (Link.prove). The initiator validates it
    (Link.validate_proof): the signature MUST verify against the destination's
    identity, or the link is NOT activated. A forged LRPROOF that activated the
    link would let any on-path attacker complete a link as the destination.

    Self-contained: creates a destination from a fresh identity it controls,
    opens an initiator link to it (PENDING), crafts an LRPROOF of `variant`, and
    feeds it through the real Link.validate_proof — reporting whether the link
    reached ACTIVE. Every byte is real RNS (the destination identity signs a
    valid proof; a throwaway key forges one; the ephemeral key is a real X25519
    keypair). Variants:
      valid             — destination identity signs link_id||eph_pub||dest_sig_pub;
                          MUST activate the link.
      forged_signature  — a DIFFERENT (throwaway) identity signs; must NOT activate.
      wrong_signed_data — the destination identity signs UNRELATED data; must NOT
                          activate.

    Returns {variant, activated, status, status_name}.
    """
    RNS = _get_rns()
    from RNS.Cryptography import X25519

    handle = params["handle"]
    variant = params["variant"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    dest_identity = RNS.Identity()
    out_destination = RNS.Destination(
        dest_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "conformance", "lrproof",
    )
    link = RNS.Link(out_destination)
    link.status = RNS.Link.PENDING

    ec_half = RNS.Link.ECPUBSIZE // 2
    ephemeral = X25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes()
    dest_sig_pub = dest_identity.get_public_key()[ec_half:RNS.Link.ECPUBSIZE]
    signed_data = link.link_id + ephemeral_pub + dest_sig_pub

    if variant == "valid":
        signature = dest_identity.sign(signed_data)
    elif variant == "forged_signature":
        signature = RNS.Identity().sign(signed_data)  # signed by the WRONG key
    elif variant == "wrong_signed_data":
        signature = dest_identity.sign(secrets.token_bytes(96))  # sig over unrelated data
    else:
        raise ValueError(f"unknown lrproof variant: {variant!r}")

    proof_data = signature + ephemeral_pub
    out_packet = RNS.Packet(
        link, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF,
    )
    out_packet.pack()
    rx = RNS.Packet(None, out_packet.raw)
    if rx.unpack():
        rx.receiving_interface = None
        try:
            link.validate_proof(rx)
        except Exception:
            pass

    status_after = getattr(link, "status", None)
    activated = status_after == RNS.Link.ACTIVE
    try:
        link.teardown()
    except Exception:
        pass
    return {
        "variant": variant,
        "activated": activated,
        "status": int(status_after) if status_after is not None else None,
        "status_name": _LINK_STATUS_NAMES.get(status_after),
    }


def cmd_wire_inject_crafted_link_identify(params):
    """Adversarial LINKIDENTIFY injector.

    The initiator of a link can reveal its identity to the non-initiator with a
    LINKIDENTIFY packet whose encrypted payload is public_key(64)||signature(64),
    where the signature is over link_id||public_key (Link.identify). The
    non-initiator validates it (Link.receive LINKIDENTIFY branch): non-initiator
    only, exactly KEYSIZE//8 + SIGLENGTH//8 == 128 plaintext bytes, and the
    signature MUST verify against the CLAIMED public key — otherwise the identity
    is NOT adopted (remote_identity stays None). The existing identify test only
    drives a VALIDLY-signed identify from an unlisted identity (a policy check),
    never the cryptographic rejection.

    This injector crafts the LINKIDENTIFY of a chosen `variant`, encrypts it to
    the established link, and feeds it through the real link.receive on the
    NON-INITIATOR peer, reporting whether the claimed identity was adopted.
    Every part is real RNS: a freshly-generated claimed identity signs (or a
    throwaway key forges) the payload, and link.receive runs RNS's own
    validation. Variants:
      valid             — claimed identity signs link_id||pubkey; MUST be adopted.
      forged_signature  — a DIFFERENT (throwaway) identity signs; must be rejected.
      wrong_signed_data — the claimed identity signs UNRELATED data; rejected.
      wrong_length      — a 96-byte plaintext (!= 128); rejected by the length gate.

    Run on the NON-INITIATOR peer (the one holding the inbound link). Returns
    {variant, claimed_identity_hash, remote_identity_after, adopted, initiator}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    variant = params["variant"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = _find_link_by_id(inst, link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    claimed = RNS.Identity()
    public_key = claimed.get_public_key()
    signed_data = link.link_id + public_key

    if variant == "valid":
        signature = claimed.sign(signed_data)
        payload = public_key + signature
    elif variant == "forged_signature":
        signature = RNS.Identity().sign(signed_data)  # signed by the WRONG key
        payload = public_key + signature
    elif variant == "wrong_signed_data":
        signature = claimed.sign(secrets.token_bytes(96))  # sig over unrelated data
        payload = public_key + signature
    elif variant == "wrong_length":
        signature = claimed.sign(signed_data)
        payload = public_key + signature[: RNS.Identity.SIGLENGTH // 16]  # 96B total
    else:
        raise ValueError(f"unknown link-identify variant: {variant!r}")

    out_packet = RNS.Packet(link, payload, RNS.Packet.DATA, context=RNS.Packet.LINKIDENTIFY)
    out_packet.pack()
    rx = RNS.Packet(None, out_packet.raw)
    if rx.unpack():
        rx.receiving_interface = link.attached_interface
        link.receive(rx)
    time.sleep(0.05)

    remote_after = link.get_remote_identity()
    return {
        "variant": variant,
        "claimed_identity_hash": claimed.hash.hex(),
        "remote_identity_after": remote_after.hash.hex() if remote_after is not None else None,
        "adopted": remote_after is not None and remote_after.hash == claimed.hash,
        "initiator": bool(getattr(link, "initiator", False)),
    }


def cmd_wire_link_identify_pending(params):
    """Call RNS.Link.identify on a PENDING (pre-ACTIVE) link and assert it is a
    no-op that does not crash (Link.py:459-475/:468).

    identify only acts when self.initiator and self.status == Link.ACTIVE; on
    a PENDING link it must silently do nothing (no LINKIDENTIFY packet emitted,
    remote_identity unchanged). This builds an initiator Link to the recalled
    destination, forces it to PENDING deterministically (so timing can't race
    it to ACTIVE), wraps Packet.send to detect any LINKIDENTIFY emission, and
    calls identify. The link is torn down afterward.

    Returns {crashed, identify_packet_sent, status, status_name, initiator}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    app_name = params["app_name"]
    aspects = params.get("aspects", [])
    private_key = bytes.fromhex(params["private_key"])
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
        identity, RNS.Destination.OUT, RNS.Destination.SINGLE, app_name, *aspects,
    )
    ident = RNS.Identity.from_bytes(private_key)
    if ident is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")

    link = RNS.Link(out_destination)
    # Force PENDING so identify's ACTIVE-only guard is deterministically hit,
    # regardless of any concurrent handshake progress.
    link.status = RNS.Link.PENDING

    captured = []
    orig_send = RNS.Packet.send

    def capturing_send(pkt_self, _orig=orig_send):
        try:
            if (getattr(pkt_self, "context", None) == RNS.Packet.LINKIDENTIFY
                    and getattr(pkt_self, "destination", None) is link):
                captured.append(True)
        except Exception:
            pass
        return _orig(pkt_self)

    crashed = False
    RNS.Packet.send = capturing_send
    try:
        link.identify(ident)
    except Exception:
        crashed = True
    finally:
        RNS.Packet.send = orig_send

    status_after = getattr(link, "status", None)
    try:
        link.teardown()
    except Exception:
        pass

    return {
        "crashed": crashed,
        "identify_packet_sent": bool(captured),
        "status": int(status_after) if status_after is not None else None,
        "status_name": _LINK_STATUS_NAMES.get(status_after),
        "initiator": bool(getattr(link, "initiator", False)),
    }


# ---------------------------------------------------------------------------
# reticulum_config read-backs: live-instance / live-interface observables for
# config-driven posture & derivation. Every one of these DELEGATES to a real
# RNS static method or reads an attribute RNS set during config parse —
# nothing is recomputed here. They exist so a test can pin the FLOORED /
# DERIVED / DEFAULTED value RNS landed on against an external spec literal.
# ---------------------------------------------------------------------------

def _primary_wire_interface(inst):
    """Return this handle's single configured wire interface (not a spawned
    child), or None. Mirrors the name match in _interfaces_matching_handle."""
    for iface in _interfaces_matching_handle(inst["rns"], inst["role"]):
        if getattr(iface, "name", "") in ("Wire TCP Server", "Wire TCP Client"):
            return iface
    return None


def cmd_wire_ifac_signature(params):
    """Return the live interface's IFAC identifier signature.

    Reads `interface.ifac_signature` / `interface.ifac_key` / `interface.ifac_size`
    straight off the IFAC-configured interface (the value RNS produced at
    Reticulum.py:916: `interface.ifac_signature = interface.ifac_identity.sign(
    RNS.Identity.full_hash(interface.ifac_key))`). Nothing is re-derived here —
    a test independently re-signs full_hash(ifac_key) via wire_ifac_compute and
    checks the two match. `default_ifac_size` is the interface CLASS default
    (TCPServerInterface.DEFAULT_IFAC_SIZE == 16) so the per-type default and the
    configured-floor logic can both be pinned against the RNS source.
    """
    handle = params["handle"]
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
            "network_name + passphrase so RNS derives an ifac_identity."
        )
    return {
        "ifac_signature": ifac_iface.ifac_signature.hex(),
        "ifac_key": ifac_iface.ifac_key.hex(),
        "ifac_size": int(ifac_iface.ifac_size),
        "default_ifac_size": int(type(ifac_iface).DEFAULT_IFAC_SIZE),
    }


def cmd_wire_instance_posture(params):
    """Return the GROUND-TRUTH process-wide posture flags RNS resolved at
    Reticulum.__init__ / __apply_config time.

    Every field is the return of an RNS static accessor (Reticulum.py:1707-1750)
    or RNS.Transport.remote_management_allowed — the live config-derived state,
    not the echoed config value. A shared-instance local CLIENT forces
    transport/remote-management/probes all False (Reticulum.py:429-431); a
    standalone node reflects its own config knobs. should_use_implicit_proof
    defaults True; probe/remote-management default False.
    """
    RNS = _get_rns()
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    return {
        "transport_enabled": bool(RNS.Reticulum.transport_enabled()),
        "remote_management_enabled": bool(RNS.Reticulum.remote_management_enabled()),
        "respond_to_probes": bool(RNS.Reticulum.probe_destination_enabled()),
        "should_use_implicit_proof": bool(RNS.Reticulum.should_use_implicit_proof()),
        "link_mtu_discovery": bool(RNS.Reticulum.link_mtu_discovery()),
        "remote_management_allowed": [
            h.hex() for h in RNS.Transport.remote_management_allowed
        ],
        "is_shared_instance": bool(
            getattr(inst["rns"], "is_shared_instance", False)
        ),
        "is_connected_to_shared_instance": bool(
            getattr(inst["rns"], "is_connected_to_shared_instance", False)
        ),
    }


def cmd_wire_interface_bitrate(params):
    """Return the live interface's effective bitrate after config parse.

    Reads `interface.bitrate`. RNS only applies a configured `bitrate` when it
    is >= Reticulum.MINIMUM_BITRATE (Reticulum.py:765-768); a sub-minimum value
    is silently ignored and the interface keeps its class BITRATE_GUESS
    (TCPServerInterface.BITRATE_GUESS == 10_000_000). Returning both the live
    bitrate and the class guess + the MINIMUM_BITRATE constant lets a test pin
    the floor without recomputing anything.
    """
    RNS = _get_rns()
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    iface = _primary_wire_interface(inst)
    if iface is None:
        raise RuntimeError("No configured wire interface on this handle.")
    return {
        "bitrate": int(iface.bitrate),
        "bitrate_guess": int(type(iface).BITRATE_GUESS),
        "minimum_bitrate": int(RNS.Reticulum.MINIMUM_BITRATE),
    }


def cmd_wire_rpc_authkey(params):
    """Return the derived RPC authkey and the transport identity private key.

    When no rpc_key is configured, RNS derives the multiprocessing RPC authkey
    as RNS.Identity.full_hash(RNS.Transport.identity.get_private_key())
    (Reticulum.py:347-348). This reads the resolved `rns.rpc_key` plus the live
    transport private key so a test can independently recompute SHA-256 over the
    private key (full_hash IS SHA-256) and confirm the derivation.
    """
    RNS = _get_rns()
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    rpc_key = inst["rns"].rpc_key
    if rpc_key is None:
        raise RuntimeError("rpc_key not yet derived on this instance.")
    return {
        "rpc_key": rpc_key.hex(),
        "transport_private_key": RNS.Transport.identity.get_private_key().hex(),
    }


def cmd_wire_first_hop_timeout(params):
    """Return RNS.Transport.first_hop_timeout(destination_hash) for this peer.

    Delegates to the real static (Transport.py:2697-2701): with no known path
    to the destination the per-byte latency is None and the function returns
    exactly Reticulum.DEFAULT_PER_HOP_TIMEOUT (== 6). Returning the constant
    alongside lets a test anchor the unknown-destination case on the spec
    literal.
    """
    RNS = _get_rns()
    handle = params["handle"]
    destination_hash = bytes.fromhex(params["destination_hash"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    return {
        "timeout": RNS.Transport.first_hop_timeout(destination_hash),
        "default_per_hop_timeout": RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT,
    }


# ---------------------------------------------------------------------------
# Link establishment internals: request-payload layout, signalling-byte
# encoding, LINKREQUEST size/mode validation, the destination accept gate,
# ephemeral-key purge on close, and closed/foreign-interface link-receive
# rejection. Every one of these DRIVES real RNS.Link / RNS.Destination code —
# the request_data assembly in Link.__init__, the static Link.signalling_bytes
# / Link.validate_request gates, Destination.receive's accept gate, and the
# link_closed() key purge — and reads back what RNS computed. Nothing here
# reconstructs a wire field by hand (the one exception, the bad-mode signalling
# byte in cmd_wire_inject_crafted_link_request, is registered in the audit's
# ADVERSARIAL_CORRUPTORS).
# ---------------------------------------------------------------------------

def _any_handle_interface(inst):
    """Return any live interface on this handle (for a plausible
    receiving_interface on a crafted inbound packet), or None."""
    try:
        ifaces = list(_interfaces_matching_handle(inst["rns"], inst["role"]))
    except Exception:
        ifaces = []
    return ifaces[0] if ifaces else None


def _build_initiator_request_data(RNS, app_name, aspects):
    """Build a real initiator RNS.Link to a fresh self-controlled OUT
    destination WITHOUT putting a LINKREQUEST on the wire (Packet.send is
    patched to a no-op for the construction), and return
    (link, request_data). The request_data is exactly what Link.__init__
    assembled at Link.py:316 — pub_bytes||sig_pub_bytes||signalling_bytes —
    every byte produced by real RNS. Caller must teardown the link."""
    dest_identity = RNS.Identity()
    out_destination = RNS.Destination(
        dest_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        app_name, *aspects,
    )
    orig_send = RNS.Packet.send

    def _noop_send(_pkt_self):
        return None

    RNS.Packet.send = _noop_send
    try:
        link = RNS.Link(out_destination)
    finally:
        RNS.Packet.send = orig_send
    return link, link.request_data


def cmd_wire_link_request_payload(params):
    """Capture an initiator's real LINKREQUEST payload WITHOUT sending it.

    Builds a genuine initiator RNS.Link (Packet.send patched off so nothing
    hits the wire) and returns the request_data RNS assembled at Link.py:316
    plus its constituent fields. Lets a test pin the unencrypted LINKREQUEST
    layout = pub_bytes(X25519, 32) || sig_pub_bytes(Ed25519, 32) ||
    signalling_bytes(3), i.e. ECPUBSIZE(64) + LINK_MTU_SIZE(3) = 67 bytes
    (validate_request also accepts the bare 64-byte ECPUBSIZE form). Every
    field is read off the live Link — pub_bytes/sig_pub_bytes are the freshly
    generated X25519/Ed25519 public keys, signalling_bytes is the tail RNS
    appended via Link.signalling_bytes.

    Called twice (fresh Link each time) a test can also assert the keys differ
    between two requests to the same destination (fresh ephemeral X25519 +
    Ed25519 per request, Link.py:240-258).

    Returns {request_data_hex, pub_bytes, sig_pub_bytes, signalling_bytes,
    mtu, mode, len, ecpubsize, link_mtu_size, reticulum_mtu}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params.get("app_name", "conformance")
    aspects = params.get("aspects", ["link-payload"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    link, request_data = _build_initiator_request_data(RNS, app_name, aspects)
    try:
        ecpubsize = int(RNS.Link.ECPUBSIZE)
        link_mtu_size = int(RNS.Link.LINK_MTU_SIZE)
        # Split per the documented layout. pub_bytes/sig_pub_bytes are read
        # straight off the live Link (not re-sliced from request_data) so the
        # field accessors are pinned independently of the concatenation.
        result = {
            "request_data_hex": request_data.hex(),
            "pub_bytes": link.pub_bytes.hex(),
            "sig_pub_bytes": link.sig_pub_bytes.hex(),
            "signalling_bytes": request_data[ecpubsize:].hex(),
            "mtu": int(link.mtu),
            "mode": int(link.mode),
            "len": len(request_data),
            "ecpubsize": ecpubsize,
            "link_mtu_size": link_mtu_size,
            "reticulum_mtu": int(RNS.Reticulum.MTU),
        }
    finally:
        try:
            link.teardown()
        except Exception:
            pass
    return result


def cmd_wire_link_signalling_bytes(params):
    """Delegate to the static RNS.Link.signalling_bytes(mtu, mode).

    Returns the 3-byte signalling field RNS encodes for an ENABLED mode, or
    {raised: True} when the mode is not in Link.ENABLED_MODES (signalling_bytes
    raises TypeError for any non-enabled mode, Link.py:148-151). Surfaces the
    bytemasks / enabled-mode list / default so a test can independently
    recompute the (mtu&MTU_BYTEMASK)+(((mode<<5)&MODE_BYTEMASK)<<16) packing and
    pin both the positive encoding and the non-enabled-mode rejection.

    Returns {mtu, mode, signalling_bytes|None, raised, mtu_bytemask,
    mode_bytemask, enabled_modes, mode_default, link_mtu_size}.
    """
    RNS = _get_rns()
    mtu = int(params["mtu"])
    mode = int(params["mode"])
    raised = False
    signalling = None
    try:
        signalling = RNS.Link.signalling_bytes(mtu, mode)
    except TypeError:
        raised = True
    return {
        "mtu": mtu,
        "mode": mode,
        "signalling_bytes": signalling.hex() if signalling is not None else None,
        "raised": raised,
        "mtu_bytemask": int(RNS.Link.MTU_BYTEMASK),
        "mode_bytemask": int(RNS.Link.MODE_BYTEMASK),
        "enabled_modes": [int(m) for m in RNS.Link.ENABLED_MODES],
        "mode_default": int(RNS.Link.MODE_DEFAULT),
        "link_mtu_size": int(RNS.Link.LINK_MTU_SIZE),
    }


def _craft_link_request_packet(RNS, owner_identity, app_name, aspects, data, hops):
    """Pack a genuine LINKREQUEST packet carrying `data` (addressed to an OUT
    destination of owner_identity) and return the unpacked rx packet with hops
    set. The packet is produced entirely by RNS.Packet.pack — only the carried
    `data` (a real-RNS-derived payload, possibly sliced/empty) is chosen by the
    caller."""
    out_owner = RNS.Destination(
        owner_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        app_name, *aspects,
    )
    pkt = RNS.Packet(out_owner, data, packet_type=RNS.Packet.LINKREQUEST)
    pkt.pack()
    rx = RNS.Packet(None, pkt.raw)
    rx.unpack()
    rx.hops = int(hops)
    return rx


def cmd_wire_inject_crafted_link_request(params):
    """Adversarial LINKREQUEST payload-validation injector (receiver side).

    Self-contained: creates a fresh IN SINGLE destination it owns and feeds a
    crafted LINKREQUEST of `variant` through the real Link.validate_request
    (Link.py:185-209), reporting whether an inbound link was created. Pins that
    ONLY a 64-byte (ECPUBSIZE) or 67-byte (ECPUBSIZE+LINK_MTU_SIZE) payload
    yields a link; every other size is silently dropped, and a payload whose
    signalling mode byte is a non-enabled link mode is rejected by the
    handshake's mode gate (Link.handshake raises for any mode not AES128/256-CBC,
    Link.signalling_bytes/prove reject any non-ENABLED mode).

    Variants (the 64/67-byte base is a real initiator's request_data; the size
    variants are slices of it / empty; bad_mode overwrites the signalling mode
    byte with a reserved mode — the ONLY hand-set wire byte, hence this command
    is registered in the audit's ADVERSARIAL_CORRUPTORS):
      valid64  — request_data[:ECPUBSIZE]            -> link created.
      valid67  — full request_data (ECPUBSIZE+3)     -> link created.
      size_63  — request_data[:63]                   -> dropped.
      size_66  — request_data[:66]                   -> dropped.
      size_0   — empty payload                       -> dropped.
      bad_mode — 67-byte payload, signalling mode byte set to reserved mode 3
                 -> handshake mode gate rejects, no link created.

    `hops` (default 0) sets the crafted packet's hop count so a test can pin the
    inbound establishment_timeout == ESTABLISHMENT_TIMEOUT_PER_HOP*max(1,hops) +
    KEEPALIVE (Link.py:207). Returns {variant, data_len, accepted,
    inbound_link_created, establishment_timeout, mode, establishment_timeout_per_hop,
    keepalive}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    variant = params["variant"]
    hops = int(params.get("hops", 0))
    app_name = params.get("app_name", "conformance")
    aspects = params.get("aspects", ["lr-validate"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    owner_identity = RNS.Identity()
    owner = RNS.Destination(
        owner_identity, RNS.Destination.IN, RNS.Destination.SINGLE,
        app_name, *aspects,
    )

    base_link, base = _build_initiator_request_data(RNS, app_name, aspects)
    ecpubsize = int(RNS.Link.ECPUBSIZE)
    try:
        if variant == "valid64":
            data = base[:ecpubsize]
        elif variant == "valid67":
            data = base
        elif variant == "size_63":
            data = base[:63]
        elif variant == "size_66":
            data = base[:66]
        elif variant == "size_0":
            data = b""
        elif variant == "bad_mode":
            corrupted = list(base)
            # Set the signalling mode bits (top 3 bits of the first signalling
            # byte) to reserved mode 3 (0x03 << 5 == 0x60). The low MTU bits in
            # this byte are 0 for the default MTU, so this isolates the mode.
            corrupted[ecpubsize] = 0x60
            data = bytes(corrupted)
        else:
            raise ValueError(f"unknown link-request variant: {variant!r}")
    finally:
        try:
            base_link.teardown()
        except Exception:
            pass

    rx = _craft_link_request_packet(RNS, owner_identity, app_name, aspects, data, hops)
    rx.receiving_interface = _any_handle_interface(inst)
    # Transport normally resolves packet.destination before Destination.receive;
    # set it to the owner so validate_request's `link.destination = packet.destination`
    # has a real destination to bind.
    rx.destination = owner

    link = RNS.Link.validate_request(owner, rx.data, rx)
    accepted = link is not None
    establishment_timeout = None
    mode = None
    if accepted:
        establishment_timeout = getattr(link, "establishment_timeout", None)
        mode = int(link.mode) if getattr(link, "mode", None) is not None else None
        try:
            link.teardown()
        except Exception:
            pass

    return {
        "variant": variant,
        "data_len": len(data),
        "accepted": accepted,
        "inbound_link_created": accepted,
        "establishment_timeout": establishment_timeout,
        "mode": mode,
        "establishment_timeout_per_hop": int(RNS.Link.ESTABLISHMENT_TIMEOUT_PER_HOP),
        "keepalive": int(RNS.Link.KEEPALIVE),
    }


def cmd_wire_link_accept_gate(params):
    """Pin Destination's link-accept gate (Destination.receive -> only answers a
    LINKREQUEST when accept_link_requests is set, Destination.py:420-423).

    Self-contained: creates a fresh IN SINGLE destination, sets its accept gate
    via the real Destination.accepts_links(accepts), feeds a genuine 67-byte
    LINKREQUEST through the real Destination.receive, and reports whether an
    inbound link was appended to destination.links. With the gate OFF no link is
    created (validate_request is never reached); with it ON exactly one link is
    created — the positive control.

    Returns {accepts, links_before, links_after, link_created}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    accepts = bool(params["accepts"])
    app_name = params.get("app_name", "conformance")
    aspects = params.get("aspects", ["accept-gate"])
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    owner_identity = RNS.Identity()
    owner = RNS.Destination(
        owner_identity, RNS.Destination.IN, RNS.Destination.SINGLE,
        app_name, *aspects,
    )
    owner.accepts_links(accepts)

    base_link, base = _build_initiator_request_data(RNS, app_name, aspects)
    try:
        rx = _craft_link_request_packet(
            RNS, owner_identity, app_name, aspects, base, 0,
        )
    finally:
        try:
            base_link.teardown()
        except Exception:
            pass
    rx.receiving_interface = _any_handle_interface(inst)
    rx.destination = owner

    links_before = len(owner.links)
    owner.receive(rx)
    links_after = len(owner.links)
    # Clean up any link the gate created.
    for lk in list(owner.links):
        try:
            lk.teardown()
        except Exception:
            pass
    return {
        "accepts": accepts,
        "links_before": links_before,
        "links_after": links_after,
        "link_created": links_after > links_before,
    }


def cmd_wire_link_key_material(params):
    """Report which ephemeral-key fields an established link currently holds.

    Reads the live RNS.Link's prv / pub / shared_key / derived_key. An ACTIVE
    link holds all four (the X25519 ephemeral private/public + the ECDH shared
    secret + the HKDF-derived link key). After Link.teardown the link_closed()
    purge (Link.py:728-733) nulls prv/pub/shared_key/derived_key, so the same
    link reports all None — pinning forward-secret ephemeral-key purge on close
    with no persistence.

    Returns {status, status_name, derived_key_present, shared_key_present,
    prv_present, pub_present}.
    """
    RNS = _get_rns()
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
        "status": int(status) if status is not None else None,
        "status_name": _LINK_STATUS_NAMES.get(status),
        "derived_key_present": getattr(link, "derived_key", None) is not None,
        "shared_key_present": getattr(link, "shared_key", None) is not None,
        "prv_present": getattr(link, "prv", None) is not None,
        "pub_present": getattr(link, "pub", None) is not None,
    }


def cmd_wire_inject_closed_link_data(params):
    """Pin that a CLOSED link silently drops all link-associated traffic
    (Link.receive's `if not self.status == Link.CLOSED` guard, Link.py:974).

    Builds a PRISTINE DATA packet encrypted to the still-ACTIVE inbound link
    (RNS.Packet.pack, while the link key still exists), caches its raw bytes,
    then tears the link down (Link.teardown, which purges derived_key so no new
    packet could be encrypted post-close), and finally feeds the cached packet
    through the real link.receive. The packet must NOT be delivered because
    receive returns immediately once status == CLOSED. Run on the RECEIVER peer.

    Returns {delivered_before, delivered, status_name, link_closed}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    link_id = bytes.fromhex(params["link_id"])
    payload = bytes.fromhex(params.get("data", "")) or secrets.token_bytes(16)
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    link = _find_link_by_id(inst, link_id)
    if link is None:
        raise ValueError(f"Unknown link_id: {link_id.hex()}")

    listener = None
    for cand in inst.get("listeners", {}).values():
        with cand["recv_lock"]:
            ids = [getattr(x, "link_id", None) for x in cand.get("inbound_links", [])]
        if link_id in ids:
            listener = cand
            break
    if listener is None:
        raise ValueError(
            f"link_id {link_id.hex()} is not an inbound link of any listener on "
            f"this peer (run on the RECEIVER peer)"
        )

    # Build + pack a pristine DATA packet BEFORE teardown (the link key is
    # purged on close, so this MUST happen while the link is still ACTIVE).
    out_packet = RNS.Packet(link, payload, context=RNS.Packet.NONE)
    out_packet.pack()
    cached_raw = out_packet.raw

    with listener["recv_lock"]:
        before = len(listener["recv_buffer"])

    # Now close the link, then replay the cached packet into receive.
    try:
        link.teardown()
    except Exception:
        pass
    time.sleep(0.05)

    rx = RNS.Packet(None, cached_raw)
    if rx.unpack():
        rx.receiving_interface = link.attached_interface
        link.receive(rx)
    time.sleep(0.05)

    with listener["recv_lock"]:
        after = len(listener["recv_buffer"])
    status_after = getattr(link, "status", None)
    return {
        "delivered_before": False,
        "delivered": after > before,
        "status_name": _LINK_STATUS_NAMES.get(status_after),
        "link_closed": status_after == RNS.Link.CLOSED,
    }


def cmd_wire_capture_lrproof_frame(params):
    """Capture the RAW outbound LRPROOF (link-request-proof) frame and surface
    its flag-byte shape + on-wire layout (the link-accepting peer's Link.prove,
    Link.py:371-380; Packet.get_packed_flags / Packet.pack, Packet.py:169-184).

    get_packed_flags SPECIAL-CASES context==LRPROOF: it forces the destination-
    type bits to RNS.Destination.LINK (0b11) and pack() then writes the link_id
    in the destination-address position instead of a destination hash. The
    reference link-establishment path never exposes these bytes, so the LRPROOF's
    flag shape was unobservable.

    Self-contained: creates a destination from a fresh identity, opens an
    initiator Link to it (so it owns a real link_id / pub_bytes / signalling
    bytes), and builds the LRPROOF exactly as Link.prove does — a genuine
    RNS.Packet(link, signature||pub||signalling, packet_type=PROOF,
    context=LRPROOF) packed by real RNS. Returns the raw frame plus the link_id
    so a test can decode raw[0]'s dest-type/packet-type/header bits and confirm
    the 16 destination-position bytes equal the link_id (not a dest hash).

    Returns {raw, flags, link_id, packet_type, context, expected_link_dest_type,
    truncated_hashlength}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    dest_identity = RNS.Identity()
    out_destination = RNS.Destination(
        dest_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "conformance", "lrproof-shape",
    )
    link = RNS.Link(out_destination)

    # Build the LRPROOF body exactly as Link.prove (Link.py:371-377): the
    # signature over link_id||pub||sig_pub||signalling, then signature||pub||
    # signalling as the proof payload. Real RNS keys throughout.
    signalling_bytes = RNS.Link.signalling_bytes(link.mtu, link.mode)
    signed_data = link.link_id + link.pub_bytes + link.sig_pub_bytes + signalling_bytes
    # The destination identity signs the proof (Link.prove signs with the
    # accepting owner's identity; an initiator-side Link has no owner, so the
    # controlled destination identity stands in — the signature content does not
    # affect the flag-byte shape this command captures).
    signature = dest_identity.sign(signed_data)
    proof_data = signature + link.pub_bytes + signalling_bytes

    proof = RNS.Packet(
        link, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF,
    )
    proof.pack()
    raw = proof.raw
    try:
        link.teardown()
    except Exception:
        pass
    return {
        "raw": raw.hex(),
        "flags": int(proof.flags),
        "link_id": link.link_id.hex(),
        "packet_type": int(RNS.Packet.PROOF),
        "context": int(RNS.Packet.LRPROOF),
        "expected_link_dest_type": int(RNS.Destination.LINK),
        "truncated_hashlength": int(RNS.Reticulum.TRUNCATED_HASHLENGTH // 8),
    }


def cmd_wire_inject_crafted_link_proof(params):
    """Adversarial / positive LINK-DATA packet-proof injector (link packet proofs
    are EXPLICIT-only; PacketReceipt.validate_link_proof, Packet.py:450-495).

    A link DATA packet's proof is validated by validate_link_proof, which — unlike
    the single-packet validate_proof — accepts ONLY the 96-byte EXPLICIT form
    (packet_hash(32)||signature(64)); the 64-byte IMPLICIT branch is disabled
    (Packet.py:478-493 `pass`), so a valid-signature implicit proof is STILL
    rejected. The ordinary harness only ever sees the receiver's genuine explicit
    proof, so the implicit-rejection branch was untested.

    Self-contained: creates a fresh Link and gives it a self-consistent signing
    keypair (peer_sig_pub := its own sig_pub) so the REAL link.sign produces a
    signature the REAL link.validate verifies — no cross-process key needed. A
    real RNS.PacketReceipt over a packed SINGLE-destination packet supplies a
    genuine packet hash. Each variant is run on its OWN fresh receipt (a valid
    proof mutates status):
      valid_explicit   — receipt.hash || link.sign(receipt.hash) (96B): MUST
                         validate (DELIVERED) — the positive 96-byte-explicit
                         acceptance.
      implicit_valid_sig — link.sign(receipt.hash) alone (64B, VALID signature):
                         MUST be rejected (links are explicit-only), proving the
                         FORM is enforced, not merely the signature.
      implicit_random  — 64 random bytes: rejected (length/disabled-branch).
      wrong_length_short — 32 bytes (!= 64/96): rejected by the length gate.

    Returns {variant, validated, status, status_name, proof_len, expl_length,
    impl_length}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    variant = params["variant"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    dest_identity = RNS.Identity()
    out_destination = RNS.Destination(
        dest_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "conformance", "link-proof",
    )
    link = RNS.Link(out_destination)
    # Self-consistent signing keypair: validate against the link's OWN sig pub
    # so a real link.sign() yields a signature real link.validate() accepts.
    link.peer_sig_pub = link.sig_pub
    link.peer_sig_pub_bytes = link.sig_pub_bytes

    # A real packed SINGLE-destination packet supplies a genuine packet hash.
    base_packet = RNS.Packet(out_destination, secrets.token_bytes(20), create_receipt=True)
    base_packet.pack()
    receipt = RNS.PacketReceipt(base_packet)

    impl_len = int(RNS.PacketReceipt.IMPL_LENGTH)
    expl_len = int(RNS.PacketReceipt.EXPL_LENGTH)
    sig_len = RNS.Identity.SIGLENGTH // 8  # 64

    if variant == "valid_explicit":
        proof = receipt.hash + link.sign(receipt.hash)
    elif variant == "implicit_valid_sig":
        proof = link.sign(receipt.hash)               # 64B, valid signature
    elif variant == "implicit_random":
        proof = secrets.token_bytes(sig_len)          # 64B random
    elif variant == "wrong_length_short":
        proof = secrets.token_bytes(sig_len // 2)     # 32B
    else:
        raise ValueError(f"unknown link-proof variant: {variant!r}")

    proof = bytes(proof)
    try:
        validated = bool(receipt.validate_link_proof(proof, link, None))
    except Exception:
        validated = False
    status = receipt.get_status()
    try:
        link.teardown()
    except Exception:
        pass
    return {
        "variant": variant,
        "validated": validated,
        "status": int(status),
        "status_name": _PACKET_RECEIPT_STATUS_NAMES.get(status),
        "proof_len": len(proof),
        "expl_length": expl_len,
        "impl_length": impl_len,
    }


def cmd_wire_inject_single_proof_format(params):
    """Positive / negative single-packet (non-link) PROOF FORMAT injector
    (PacketReceipt.validate_proof, Packet.py:498-549).

    For a SINGLE-destination receipt, validate_proof accepts a spec-conformant
    EXPLICIT proof (packet_hash(32)||signature(64) == 96B) and a spec-conformant
    IMPLICIT proof (signature(64) == 64B), in both cases verifying the signature
    with the destination's identity over the receipt's packet hash. The ordinary
    cross-process harness can never sign a VALID proof (the receiver's private
    key lives on the other peer), so the positive 96-byte-explicit acceptance was
    untested — the existing crafted-proof injector only covers rejections.

    Self-contained: builds the destination from a fresh identity it CONTROLS, so
    it can sign a genuinely-valid proof per the spec format. Each variant on its
    own fresh receipt:
      valid_explicit — receipt.hash || identity.sign(receipt.hash) (96B): MUST
                       validate (DELIVERED) — the positive 96-byte EXPLICIT
                       acceptance.
      valid_implicit — identity.sign(receipt.hash) (64B): MUST validate
                       (non-link receipts honor the implicit form too).
      forged_explicit — receipt.hash || WRONG-key signature (96B): rejected.
      wrong_hash_explicit — random(32) || valid signature (96B): the leading
                       proof-hash != receipt.hash, rejected before the signature.

    Returns {variant, validated, status, status_name, proof_len, expl_length,
    impl_length}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    variant = params["variant"]
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    identity = RNS.Identity()
    out_destination = RNS.Destination(
        identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "conformance", "proof-format",
    )
    base_packet = RNS.Packet(out_destination, secrets.token_bytes(20), create_receipt=True)
    base_packet.pack()
    receipt = RNS.PacketReceipt(base_packet)

    impl_len = int(RNS.PacketReceipt.IMPL_LENGTH)
    expl_len = int(RNS.PacketReceipt.EXPL_LENGTH)
    hash_len = RNS.Identity.HASHLENGTH // 8  # 32

    if variant == "valid_explicit":
        proof = receipt.hash + identity.sign(receipt.hash)
    elif variant == "valid_implicit":
        proof = identity.sign(receipt.hash)
    elif variant == "forged_explicit":
        proof = receipt.hash + RNS.Identity().sign(receipt.hash)   # wrong key
    elif variant == "wrong_hash_explicit":
        proof = secrets.token_bytes(hash_len) + identity.sign(receipt.hash)
    else:
        raise ValueError(f"unknown single-proof-format variant: {variant!r}")

    proof = bytes(proof)
    try:
        validated = bool(receipt.validate_proof(proof))
    except Exception:
        validated = False
    status = receipt.get_status()
    return {
        "variant": variant,
        "validated": validated,
        "status": int(status),
        "status_name": _PACKET_RECEIPT_STATUS_NAMES.get(status),
        "proof_len": len(proof),
        "expl_length": expl_len,
        "impl_length": impl_len,
    }


def cmd_wire_packet_receipt_generation(params):
    """Report whether RNS actually creates a PacketReceipt for a packet of a
    given destination-type / context, even with create_receipt=True
    (Transport.outbound's generate_receipt gate, Transport.py:1094-1113).

    The gate suppresses receipts unless the packet is DATA, the destination is
    NOT PLAIN, the context is NOT a link-control context (KEEPALIVE 0xFA ..
    LRPROOF 0xFF), and NOT a resource context (RESOURCE 0x01 .. RESOURCE_RCL
    0x07). This command builds a real RNS.Packet(create_receipt=True) of the
    requested shape, sends it out the peer's live interface (so the REAL gate
    runs in Transport.outbound's packet_sent), and reports whether RNS attached a
    receipt — nothing is recomputed; packet.receipt is read straight off RNS.

    dest_type: "single" (SINGLE) or "plain" (PLAIN). context: int (default NONE).
    Note: an LRPROOF (0xFF) context can only be packed on a LINK destination, so
    the 0xFA-0xFF band is exercised here via its non-link-only packable members
    (e.g. KEEPALIVE 0xFA, LRRTT 0xFE).

    Returns {dest_type, context, sent, has_receipt, create_receipt_flag}.
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest_type = str(params.get("dest_type", "single")).lower()
    context = int(params.get("context", RNS.Packet.NONE))
    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    if dest_type == "single":
        identity = RNS.Identity()
        destination = RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
            "conformance", "receipt-gen",
        )
    elif dest_type == "plain":
        destination = RNS.Destination(
            None, RNS.Destination.OUT, RNS.Destination.PLAIN,
            "conformance", "receipt-gen",
        )
    else:
        raise ValueError(f"dest_type must be 'single' or 'plain' (got {dest_type!r})")

    packet = RNS.Packet(
        destination, secrets.token_bytes(12), context=context, create_receipt=True,
    )
    packet.send()
    # Give Transport.outbound's packet_sent a moment to run on the live instance.
    deadline = time.time() + 1.0
    while not getattr(packet, "sent", False) and time.time() < deadline:
        time.sleep(0.02)
    return {
        "dest_type": dest_type,
        "context": context,
        "sent": bool(getattr(packet, "sent", False)),
        "has_receipt": getattr(packet, "receipt", None) is not None,
        "create_receipt_flag": bool(getattr(packet, "create_receipt", False)),
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
    "wire_deregister_request_handler": cmd_wire_deregister_request_handler,
    "wire_link_identify": cmd_wire_link_identify,
    "wire_link_identify_pending": cmd_wire_link_identify_pending,
    "wire_link_request": cmd_wire_link_request,
    "wire_link_request_large": cmd_wire_link_request_large,
    "wire_get_request_log": cmd_wire_get_request_log,
    "wire_listen": cmd_wire_listen,
    "wire_link_open": cmd_wire_link_open,
    "wire_link_send": cmd_wire_link_send,
    "wire_link_poll": cmd_wire_link_poll,
    "wire_resource_send": cmd_wire_resource_send,
    "wire_resource_send_bomb": cmd_wire_resource_send_bomb,
    "wire_resource_cancel": cmd_wire_resource_cancel,
    "wire_resource_create": cmd_wire_resource_create,
    "wire_resource_poll": cmd_wire_resource_poll,
    "wire_resource_receiver_status": cmd_wire_resource_receiver_status,
    # Link lifecycle observation
    "wire_link_status": cmd_wire_link_status,
    "wire_link_set_watchdog": cmd_wire_link_set_watchdog,
    "wire_link_await_status": cmd_wire_link_await_status,
    "wire_link_teardown": cmd_wire_link_teardown,
    "wire_listener_link_status": cmd_wire_listener_link_status,
    "wire_set_proof_strategy": cmd_wire_set_proof_strategy,
    # Link DATA proof strategy / keepalive byte values
    "wire_send_link_data": cmd_wire_send_link_data,
    "wire_send_over_closed_link": cmd_wire_send_over_closed_link,
    "wire_send_keepalive_probe": cmd_wire_send_keepalive_probe,
    "wire_last_keepalive": cmd_wire_last_keepalive,
    # Transport posture / link MTU / single-packet PacketReceipt observation
    "wire_transport_enabled": cmd_wire_transport_enabled,
    "wire_link_mtu": cmd_wire_link_mtu,
    "wire_send_packet": cmd_wire_send_packet,
    "wire_packet_receipt_status": cmd_wire_packet_receipt_status,
    # Channel out-of-order / duplicate injection + window observation
    "wire_channel_inject": cmd_wire_channel_inject,
    "wire_channel_received": cmd_wire_channel_received,
    "wire_channel_window": cmd_wire_channel_window,
    "wire_channel_send": cmd_wire_channel_send,
    "wire_channel_emit_capture": cmd_wire_channel_emit_capture,
    "wire_channel_register": cmd_wire_channel_register,
    "wire_listener_proof_log": cmd_wire_listener_proof_log,
    "wire_listener_channel_rx": cmd_wire_listener_channel_rx,
    "wire_channel_envelope_pack": cmd_wire_channel_envelope_pack,
    "wire_buffer_pack": cmd_wire_buffer_pack,
    # Buffer (RawChannelReader/Writer) streaming
    "wire_buffer_stream": cmd_wire_buffer_stream,
    "wire_buffer_received": cmd_wire_buffer_received,
    # GROUP destination symmetric crypto
    "wire_group_create": cmd_wire_group_create,
    "wire_group_encrypt": cmd_wire_group_encrypt,
    "wire_group_decrypt": cmd_wire_group_decrypt,
    # Identity ratchet crypto (enforce_ratchets rejection)
    "wire_identity_keypair": cmd_wire_identity_keypair,
    "wire_ratchet_keypair": cmd_wire_ratchet_keypair,
    "wire_identity_encrypt": cmd_wire_identity_encrypt,
    "wire_identity_decrypt": cmd_wire_identity_decrypt,
    # Destination-level ratchets (latest_ratchet_id / rotation-interval /
    # retained-cap / file persistence)
    "wire_read_ratchets": cmd_wire_read_ratchets,
    "wire_set_ratchet_interval": cmd_wire_set_ratchet_interval,
    "wire_rotate_ratchet": cmd_wire_rotate_ratchet,
    "wire_set_retained_ratchets": cmd_wire_set_retained_ratchets,
    "wire_ratchet_file_roundtrip": cmd_wire_ratchet_file_roundtrip,
    "wire_destination_latest_ratchet_id": cmd_wire_destination_latest_ratchet_id,
    # Receiver-side ratchet adoption + adoption-driven target-key selection
    "wire_get_adopted_ratchet": cmd_wire_get_adopted_ratchet,
    "wire_encrypt_to_remote": cmd_wire_encrypt_to_remote,
    "wire_destination_decrypt": cmd_wire_destination_decrypt,
    "wire_reannounce": cmd_wire_reannounce,
    "wire_set_proof_implicit": cmd_wire_set_proof_implicit,
    # Single-packet PROOF emission (implicit vs explicit)
    "wire_send_packet_with_proof_request": cmd_wire_send_packet_with_proof_request,
    # PLAIN destination no-op encrypt/decrypt
    "wire_plain_encrypt": cmd_wire_plain_encrypt,
    "wire_plain_decrypt": cmd_wire_plain_decrypt,
    # Known-public-key-mismatch rejection
    "wire_known_key_validate": cmd_wire_known_key_validate,
    # Deferred Link edges (forged LINKCLOSE / identify on PENDING link)
    "wire_send_forged_link_close": cmd_wire_send_forged_link_close,
    "wire_inject_crafted_proof": cmd_wire_inject_crafted_proof,
    "wire_inject_tampered_link_data": cmd_wire_inject_tampered_link_data,
    "wire_inject_crafted_link_identify": cmd_wire_inject_crafted_link_identify,
    "wire_inject_crafted_lrproof": cmd_wire_inject_crafted_lrproof,
    "wire_inject_crafted_resource_proof": cmd_wire_inject_crafted_resource_proof,
    "wire_inject_crafted_resource_part": cmd_wire_inject_crafted_resource_part,
    # Packet-proof capture: LRPROOF flag-shape, link explicit-only proofs,
    # single-packet explicit/implicit proof FORMAT acceptance, receipt-gen gate
    "wire_capture_lrproof_frame": cmd_wire_capture_lrproof_frame,
    "wire_inject_crafted_link_proof": cmd_wire_inject_crafted_link_proof,
    "wire_inject_single_proof_format": cmd_wire_inject_single_proof_format,
    "wire_packet_receipt_generation": cmd_wire_packet_receipt_generation,
    # Link establishment internals (request-payload layout / signalling-byte
    # encoding / LINKREQUEST size+mode validation / accept gate / key purge /
    # closed-link drop)
    "wire_link_request_payload": cmd_wire_link_request_payload,
    "wire_link_signalling_bytes": cmd_wire_link_signalling_bytes,
    "wire_inject_crafted_link_request": cmd_wire_inject_crafted_link_request,
    "wire_link_accept_gate": cmd_wire_link_accept_gate,
    "wire_link_key_material": cmd_wire_link_key_material,
    "wire_inject_closed_link_data": cmd_wire_inject_closed_link_data,
    "wire_resource_constants": cmd_wire_resource_constants,
    "wire_inject_crafted_resource_request": cmd_wire_inject_crafted_resource_request,
    "wire_resource_force_collision": cmd_wire_resource_force_collision,
    "wire_resource_outgoing_queue_state": cmd_wire_resource_outgoing_queue_state,
    # IFAC issue-29 golden vector
    "wire_ifac_compute": cmd_wire_ifac_compute,
    # reticulum_config posture / config-derivation read-backs
    "wire_ifac_signature": cmd_wire_ifac_signature,
    "wire_instance_posture": cmd_wire_instance_posture,
    "wire_interface_bitrate": cmd_wire_interface_bitrate,
    "wire_rpc_authkey": cmd_wire_rpc_authkey,
    "wire_first_hop_timeout": cmd_wire_first_hop_timeout,
    "wire_stop": cmd_wire_stop,
}
