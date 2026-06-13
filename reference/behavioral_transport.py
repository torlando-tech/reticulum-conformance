"""
Behavioral Transport conformance commands.

Black-box harness for testing RNS Transport semantics across implementations.
Everything is observable on the wire: inject raw bytes on a mock interface,
drain emitted bytes from any interface, assert on the bytes.

No internal state introspection. If a property matters for correctness, it's
visible in what the Transport emits — otherwise it's an implementation detail.

Commands added:
  behavioral_start(identity_seed, enable_transport=True,
                   announce_rate_target=None, announce_rate_grace=0,
                   announce_rate_penalty=0, announce_cap=None, bitrate=None)
      -> {handle, identity_hash}
      (the announce_* / bitrate args become per-instance defaults applied to
       every interface attached afterward; see N-M9 throttle coverage.)
  behavioral_stop(handle) -> {}
  behavioral_attach_mock_interface(handle, name, mode='FULL', mtu=500,
                                   local_client=False,
                                   announce_rate_target=..., announce_rate_grace=...,
                                   announce_rate_penalty=..., announce_cap=..., bitrate=...)
      -> {iface_id, interface_hash}
      (each throttle knob overrides the instance default for this interface.
       local_client=True registers the interface as a local-client interface
       behind a shared-instance master: a parent MockInterface with
       is_local_shared_instance=True is created (once per instance), the child's
       parent_interface is set to it, and the child is appended to
       Transport.local_client_interfaces so Transport.is_local_client_interface
       returns True for it — the predicate at Transport.py:3058-3066. This is the
       master-side topology (A local-client -> B shared master) used by R1/R4/R5,
       PLAIN-broadcast fanout and proof_for_local_client.)
  behavioral_inject(handle, iface_id, raw_hex) -> {}
  behavioral_drain_tx(handle, iface_id) -> {packets: [raw_hex, ...]}
  behavioral_read_path_table(handle, dest) -> {found, hops, next_hop, timestamp,
       expires, random_blobs[], receiving_interface, receiving_interface_hash,
       packet_hash}  (decomposed RNS.Transport.path_table[dest] entry; H5/N-H1)
  behavioral_packet_filter(handle, raw, remember=True)
      -> {accepted, packet_hash, remembered}
      (runs the real Transport.packet_filter gate + add_packet_hash remember
       step; identical packet twice -> True then False = hashlist replay drop.
       Accepts ARBITRARY raw packets — HEADER_2-with-transport_id, PLAIN, GROUP,
       context-tagged — since it delegates to the real RNS.Packet.unpack +
       Transport.packet_filter; covers the transport_id "other instance" drop
       (Transport.py:1340-1343), PLAIN/GROUP hops>1 TTL drop (:1352-1369) and
       the KEEPALIVE/RESOURCE*/CACHE_REQUEST/CHANNEL context bypasses (:1345-1350).)
  behavioral_read_reverse_table(handle, dest=None)
      -> {found, received_if, outbound_if, received_if_hash, outbound_if_hash,
          timestamp}  when dest (a reverse-table key = forwarded packet's
          getTruncatedHash) is given; otherwise
      -> {entries: [{key, received_if, outbound_if, ...}, ...]}
      (decomposes RNS.Transport.reverse_table; IDX_RT_RCVD_IF/IDX_RT_OUTB_IF at
       Transport.py:3554-3556, insert :1625-1631, pop+return-route :2254-2263.
       received_if/outbound_if are the iface_id the test attached, so a single-
       packet PROOF return-routing test can assert the correct outbound iface.)
  behavioral_read_announce_table(handle, dest)
      -> {found, retries, hops, timestamp, retransmit_timeout, local_rebroadcasts,
          block_rebroadcasts, received_from, attached_interface, packet_hash}
      (decomposes RNS.Transport.announce_table[dest]; IDX_AT_* at
       Transport.py:3559-3567 — drives the LOCAL_REBROADCASTS_MAX retransmit /
       heard-rebroadcast cancel state machine, :580/:1719-1736.)
  behavioral_read_tunnels(handle)
      -> {tunnels: [{tunnel_id, interface_hash, interface_id, expires, num_paths}]}
      (decomposes RNS.Transport.tunnels; IDX_TT_* at Transport.py:3581-3584. After
       injecting a synthesize packet the validated tunnel appears here — handler
       Transport.py:2306-2327 -> handle_tunnel :2336-2345.)
  behavioral_synthesize_tunnel(handle, iface_id)
      -> {iface_id, tunnel_id}
      (calls Transport.synthesize_tunnel(iface), :2282-2303 — emits the PLAIN
       pubkey||iface_hash||random_hash||sig packet onto the iface, drainable via
       drain_tx; returns the locally-computed tunnel_id == full_hash(pubkey||
       iface_hash) so the test can assert the emitted bytes decompose to it.)
  behavioral_set_path_timestamp(handle, dest, timestamp)
      -> {set}  (sets path_table[dest][IDX_PT_TIMESTAMP]; for deterministic
       path-expiry eviction WITHOUT real sleeps — pair with force_cull.)
  behavioral_set_announce_timestamp(handle, dest, retransmit_timeout=None,
                                    timestamp=None)
      -> {set}  (sets announce_table[dest][IDX_AT_RTRNS_TMO]/[IDX_AT_TIMESTAMP];
       lets a test age an announce so the next forced jobs() tick fires a
       retransmit deterministically — no real sleeps.)
  behavioral_force_cull(handle)
      -> {culled}  (rewinds tables_last_culled + announces_last_checked to 0 then
       runs Transport.jobs() ONCE synchronously, exercising the real table-cull
       (:662-932) and announce-retransmit (:573-636) job branches with no sleep.)
  behavioral_detach_interface(handle, iface_id)
      -> {detached}  (detaches and removes one iface from Transport.interfaces
       (and local_client_interfaces); for the path_table missing-interface
       eviction test, :782-785, which needs no clock.)
"""

import os
import secrets
import tempfile
import threading
from collections import deque


# One entry per running behavioral Transport. Keyed by opaque handle.
# Each entry: {'rns': RNS.Reticulum, 'identity_hash': bytes, 'interfaces': {iface_id: MockInterface}}
_instances = {}
_instances_lock = threading.Lock()


def _get_rns():
    """Lazy-import real RNS via the bridge's cached full-RNS helper.

    The bridge stubs out RNS for crypto-only commands with fake modules that
    lack `LOG_CRITICAL` and friends — we need the full, actual RNS module for
    behavioral tests. The bridge exposes `_get_full_rns()` which does the
    proper clear-and-reimport.
    """
    # Imported here rather than at module top so behavioral_transport can be
    # loaded even before bridge_server.py finishes initializing.
    from bridge_server import _get_full_rns
    return _get_full_rns()


# Path-table entry indices. RNS exposes `RNS.Transport` as the Transport CLASS,
# so the module-level IDX_PT_* globals (RNS/Transport.py:3545-3551) are NOT
# reachable as class attributes. Resolve them from the real module, with a
# fallback pinned to RNS 1.3.1 in case the module object is ever shadowed.
_IDX_PT_FALLBACK = {
    "IDX_PT_TIMESTAMP": 0,
    "IDX_PT_NEXT_HOP": 1,
    "IDX_PT_HOPS": 2,
    "IDX_PT_EXPIRES": 3,
    "IDX_PT_RANDBLOBS": 4,
    "IDX_PT_RVCD_IF": 5,
    "IDX_PT_PACKET": 6,
}


def _pt_indices():
    """Return the path_table tuple indices used by the installed RNS."""
    RNS = _get_rns()
    import importlib
    try:
        mod = importlib.import_module(RNS.Transport.__module__)
    except Exception:
        mod = None
    out = {}
    for name, default in _IDX_PT_FALLBACK.items():
        out[name] = getattr(mod, name, default) if mod is not None else default
    return out


def _make_mock_interface_class():
    """Build the MockInterface class lazily so it can subclass RNS.Interfaces.Interface.Interface.

    We defer the class definition until RNS is imported because the base class isn't
    available at module import time (the bridge imports RNS lazily to avoid polluting
    the crypto-only test paths with networking state).
    """
    RNS = _get_rns()
    BaseInterface = RNS.Interfaces.Interface.Interface

    class MockInterface(BaseInterface):
        """Zero-wire Interface. Transmitted bytes land in a thread-safe queue
        drainable by tests; injected bytes drive Transport.inbound directly."""

        def __init__(self, name, mode_name="FULL", mtu=500,
                     announce_rate_target=None, announce_rate_grace=0,
                     announce_rate_penalty=0, announce_cap=None, bitrate=None):
            super().__init__()
            self.IN = True
            self.OUT = True
            self.FWD = False
            self.RPT = False
            self.name = name
            self.online = True
            # 10 Mbit/s default keeps announce egress-spacing math negligible
            # unless a test deliberately lowers bitrate / announce_cap.
            self.bitrate = 10_000_000 if bitrate is None else int(bitrate)

            mode_map = {
                "FULL": BaseInterface.MODE_FULL,
                "POINT_TO_POINT": BaseInterface.MODE_POINT_TO_POINT,
                "ACCESS_POINT": BaseInterface.MODE_ACCESS_POINT,
                "ROAMING": BaseInterface.MODE_ROAMING,
                "BOUNDARY": BaseInterface.MODE_BOUNDARY,
                "GATEWAY": BaseInterface.MODE_GATEWAY,
            }
            self.mode = mode_map.get(mode_name, BaseInterface.MODE_FULL)

            self.HW_MTU = mtu
            self.ifac_size = 0
            self.ifac_identity = None
            self.ifac_key = None

            # Thread-safe TX capture queue (raw bytes emitted by Transport)
            self._tx_queue = deque()
            self._tx_lock = threading.Lock()

            # Inbound announce-rate limiting (RNS Transport.py:1836-1858). The
            # base Interface does NOT define these, and Transport reads
            # receiving_interface.announce_rate_target on every accepted
            # announce, so they MUST exist. Default None = rate limiting OFF
            # (preserves prior behavior); a test can enable per-destination
            # inbound throttling by passing a target (seconds), grace (count),
            # and penalty (seconds).
            self.announce_rate_target = announce_rate_target
            self.announce_rate_grace = int(announce_rate_grace or 0)
            self.announce_rate_penalty = int(announce_rate_penalty or 0)

            # Outbound announce bandwidth cap (RNS Transport.py:1250-1258,
            # Interface.process_announce_queue). announce_cap is a FRACTION of
            # link bandwidth (RNS configures real interfaces with
            # Reticulum.ANNOUNCE_CAP/100.0 = 0.02). Only set it when a test
            # supplies a value; otherwise RNS lazily defaults it, matching the
            # un-configured path. Smaller cap -> longer egress spacing.
            if announce_cap is not None:
                self.announce_cap = float(announce_cap)

        def process_outgoing(self, data):
            """Called by Transport.transmit when emitting bytes on this interface.
            Instead of putting them on a wire, buffer for the test to drain."""
            with self._tx_lock:
                self._tx_queue.append(bytes(data))
            self.txb += len(data)

        def drain_tx(self):
            """Return and clear all buffered emissions."""
            with self._tx_lock:
                out = list(self._tx_queue)
                self._tx_queue.clear()
            return out

        def inject(self, raw):
            """Simulate receive: hand the bytes to Transport as if they'd arrived
            on the wire."""
            self.rxb += len(raw)
            RNS.Transport.inbound(raw, self)

        def detach(self):
            self.online = False

        def __str__(self):
            return f"MockInterface[{self.name}]"

    return MockInterface


# Single shared RNS instance. RNS.Reticulum is a singleton — re-init throws.
# We share one instance across behavioral tests and reset state per-handle.
_shared_rns_instance = None
_shared_config_dir = None


def _reset_transport_state():
    """Zero out Transport's in-memory tables so a new test starts clean.

    Does NOT destroy the Transport thread / identity — those are fine to
    reuse. Does NOT change the `enable_transport` flag (that's a singleton
    property, set at first `RNS.Reticulum.__init__` and not mutable after;
    see `_ensure_rns_started` for the mismatch guard).
    """
    RNS = _get_rns()
    T = RNS.Transport
    T.path_table.clear() if hasattr(T.path_table, "clear") else T.path_table.update({})
    T.announce_table.clear() if hasattr(T.announce_table, "clear") else None
    T.link_table.clear() if hasattr(T.link_table, "clear") else None
    T.packet_hashlist.clear() if hasattr(T.packet_hashlist, "clear") else None
    T.tunnels.clear() if hasattr(T.tunnels, "clear") else None
    T.reverse_table.clear() if hasattr(T.reverse_table, "clear") else None
    # local_client_interfaces is a process-wide list. In behavioral mode it only
    # ever holds OUR mock children (share_instance=No, so RNS never spawns a real
    # LocalServerInterface). Clearing it prevents a child registered by a previous
    # handle from leaking into the next test's is_local_client_interface predicate.
    if hasattr(T, "local_client_interfaces") and hasattr(T.local_client_interfaces, "clear"):
        T.local_client_interfaces.clear()
    if hasattr(T, "announce_rate_table"):
        T.announce_rate_table.clear()


_shared_enable_transport: bool | None = None


def _ensure_rns_started(config_dir, enable_transport):
    """Start (or reuse) the process-wide Reticulum instance.

    `enable_transport` is a config-file property that Python RNS reads at
    `Reticulum.__init__` time and cannot change after. Since the bridge
    hosts a single singleton for its lifetime, the first `behavioral_start`
    call fixes `enable_transport` for every subsequent call in the same
    bridge process.

    If a later call requests a different `enable_transport`, raise loudly so
    the caller can spawn a fresh bridge process (what pytest's session
    fixture does) rather than silently running with the previous value —
    which would produce false-positive test passes.
    """
    global _shared_rns_instance, _shared_config_dir, _shared_enable_transport
    RNS = _get_rns()

    if _shared_rns_instance is not None:
        if _shared_enable_transport != enable_transport:
            raise RuntimeError(
                f"behavioral_start requested enable_transport={enable_transport} "
                f"but the bridge's Reticulum singleton was initialized with "
                f"enable_transport={_shared_enable_transport}. Python RNS can't "
                f"switch this flag after init. Restart the bridge process "
                f"(e.g. via a session-scoped pytest fixture with --forked) to "
                f"change it."
            )
        _reset_transport_state()
        return _shared_rns_instance

    _shared_config_dir = config_dir
    _shared_enable_transport = enable_transport
    config_file = os.path.join(config_dir, "config")
    if not os.path.isfile(config_file):
        os.makedirs(config_dir, exist_ok=True)
        with open(config_file, "w") as f:
            f.write(
                "[reticulum]\n"
                "  enable_transport = {}\n"
                "  share_instance = No\n"
                "  respond_to_probes = No\n\n"
                "[interfaces]\n".format("Yes" if enable_transport else "No")
            )

    RNS.loglevel = RNS.LOG_CRITICAL
    _shared_rns_instance = RNS.Reticulum(configdir=config_dir, loglevel=RNS.LOG_CRITICAL)
    return _shared_rns_instance


def cmd_behavioral_start(params):
    """Start a Transport instance with a deterministic identity seed.

    The bridge process hosts a single RNS.Reticulum singleton for its lifetime
    (RNS can't be re-initialized in-process). Per-test state is reset on each
    call. See `_ensure_rns_started` for the `enable_transport` compatibility
    contract.
    """
    RNS = _get_rns()

    identity_seed_hex = params.get("identity_seed")
    enable_transport = bool(params.get("enable_transport", True))

    # Instance-level announce-throttle defaults. These flow down to every
    # interface attached after start unless that attach overrides them. They
    # are exposed here (rather than only on attach) so a test can configure
    # the throttle posture for the whole instance up front; see N-M9
    # (announce_rate inbound suppression / announce_cap egress spacing).
    iface_defaults = {
        "announce_rate_target": params.get("announce_rate_target"),
        "announce_rate_grace": params.get("announce_rate_grace", 0),
        "announce_rate_penalty": params.get("announce_rate_penalty", 0),
        "announce_cap": params.get("announce_cap"),
        "bitrate": params.get("bitrate"),
    }

    # Only allocate a config dir on the first call; subsequent calls reuse
    # the singleton and would leave the new dir orphaned.
    config_dir = (
        _shared_config_dir
        if _shared_rns_instance is not None
        else tempfile.mkdtemp(prefix="rns_behavioral_")
    )
    rns = _ensure_rns_started(config_dir, enable_transport)

    # Inject an identity from the seed if provided; otherwise use whatever RNS
    # generated during startup.
    if identity_seed_hex:
        seed = bytes.fromhex(identity_seed_hex)
        if len(seed) != 64:
            raise ValueError("identity_seed must be 64 bytes (32 enc + 32 sig)")
        identity = RNS.Identity(create_keys=False)
        identity.load_private_key(seed)
        RNS.Transport.identity = identity
    else:
        identity = RNS.Transport.identity

    handle = secrets.token_hex(8)
    with _instances_lock:
        _instances[handle] = {
            "rns": rns,
            "config_dir": config_dir,
            "identity_hash": identity.hash,
            "interfaces": {},
            "mock_interface_class": _make_mock_interface_class(),
            "iface_defaults": iface_defaults,
        }

    return {"handle": handle, "identity_hash": identity.hash.hex()}


def cmd_behavioral_stop(params):
    """Stop a Transport instance. Detaches mock interfaces and clears state for
    reuse by the next test. The process-wide RNS singleton stays alive."""
    RNS = _get_rns()
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.pop(handle, None)
    if inst is None:
        return {"stopped": False}

    for iface in inst["interfaces"].values():
        iface.detach()
        if iface in RNS.Transport.interfaces:
            RNS.Transport.interfaces.remove(iface)
        if iface in RNS.Transport.local_client_interfaces:
            RNS.Transport.local_client_interfaces.remove(iface)

    _reset_transport_state()
    return {"stopped": True}


def cmd_behavioral_attach_mock_interface(params):
    """Attach a MockInterface to the given Transport instance."""
    RNS = _get_rns()

    handle = params["handle"]
    name = params["name"]
    mode = params.get("mode", "FULL")
    mtu = int(params.get("mtu", 500))
    local_client = bool(params.get("local_client", False))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    # Per-interface announce-throttle knobs. Each falls back to the instance
    # default captured at behavioral_start, which in turn defaults to "off".
    defaults = inst.get("iface_defaults", {})

    def _knob(key):
        return params[key] if key in params else defaults.get(key)

    MockInterface = inst["mock_interface_class"]
    iface = MockInterface(
        name=name, mode_name=mode, mtu=mtu,
        announce_rate_target=_knob("announce_rate_target"),
        announce_rate_grace=_knob("announce_rate_grace") or 0,
        announce_rate_penalty=_knob("announce_rate_penalty") or 0,
        announce_cap=_knob("announce_cap"),
        bitrate=_knob("bitrate"),
    )
    iface_id = secrets.token_hex(6)

    if local_client:
        # Build (once per instance) the shared-instance MASTER sentinel. The
        # real RNS LocalServerInterface carries is_local_shared_instance=True
        # (LocalInterface.py:403/412) and OUT=False (:390); the child
        # LocalClientInterface points its parent_interface at it
        # (:447/:473) and is appended to Transport.local_client_interfaces
        # (:461/:477). Transport.is_local_client_interface only inspects
        # child.parent_interface for the is_local_shared_instance attribute
        # (Transport.py:3058-3066) — it does NOT require the master to be in
        # Transport.interfaces — so we keep the master OUT of the interface
        # list to avoid it being iterated as an egress target. The child IS a
        # normal OUT-capable interface in Transport.interfaces so the master's
        # rewrite-to-local-clients (Transport.py:1933-1976) and PLAIN fanout
        # (:1529-1530) land on it, drainable via drain_tx.
        parent = inst.get("local_parent")
        if parent is None:
            parent = MockInterface(name=f"{name}@shared-master", mode_name="FULL", mtu=mtu)
            parent.is_local_shared_instance = True
            parent.OUT = False
            parent.IN = True
            parent.online = True
            parent.clients = 0
            inst["local_parent"] = parent
        iface.parent_interface = parent
        parent.clients += 1
        if iface not in RNS.Transport.local_client_interfaces:
            RNS.Transport.local_client_interfaces.append(iface)

    inst["interfaces"][iface_id] = iface
    RNS.Transport.interfaces.append(iface)

    return {"iface_id": iface_id, "interface_hash": iface.get_hash().hex()}


def cmd_behavioral_inject(params):
    """Inject raw bytes on the named mock interface as if received from the wire."""
    handle = params["handle"]
    iface_id = params["iface_id"]
    raw = bytes.fromhex(params["raw"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    iface = inst["interfaces"].get(iface_id)
    if iface is None:
        raise ValueError(f"Unknown iface_id: {iface_id}")

    iface.inject(raw)
    return {}


def cmd_behavioral_drain_tx(params):
    """Drain all bytes emitted on the named mock interface since the last call."""
    handle = params["handle"]
    iface_id = params["iface_id"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    iface = inst["interfaces"].get(iface_id)
    if iface is None:
        raise ValueError(f"Unknown iface_id: {iface_id}")

    packets = iface.drain_tx()
    return {"packets": [p.hex() for p in packets]}


def cmd_behavioral_read_path_table(params):
    """Read this Transport's PATH TABLE entry for a destination.

    Surfaces RNS.Transport.path_table[dest] decomposed into its fields so a
    test can assert the *cached path* an impl actually holds — not merely what
    it re-emits. The path table is otherwise wire-observable only via a
    path-request answer (Transport.py:2954); exposing it directly lets the
    path-replacement test (H5 / N-H1) verify the surviving entry's hop count
    rather than the announce_table retransmit hops (which can diverge from the
    path table in a buggy impl).

    Each SUT bridge implements this against its OWN path table, so the check
    stays cross-implementation. Delegates entirely to the real RNS table;
    field indices come from RNS/Transport.py (IDX_PT_*).

    params: handle, dest (destination hash hex)
    returns: {found, hops, next_hop, timestamp, expires, random_blobs[],
              receiving_interface, receiving_interface_hash, packet_hash}
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    idx = _pt_indices()
    table = RNS.Transport.path_table
    if dest not in table:
        return {"found": False}

    entry = table[dest]
    rvcd_if = entry[idx["IDX_PT_RVCD_IF"]]
    try:
        rvcd_if_hash = rvcd_if.get_hash().hex()
    except Exception:
        rvcd_if_hash = None
    next_hop = entry[idx["IDX_PT_NEXT_HOP"]]
    packet_hash = entry[idx["IDX_PT_PACKET"]]
    random_blobs = entry[idx["IDX_PT_RANDBLOBS"]]

    return {
        "found": True,
        "hops": int(entry[idx["IDX_PT_HOPS"]]),
        "next_hop": next_hop.hex() if isinstance(next_hop, (bytes, bytearray)) else None,
        "timestamp": float(entry[idx["IDX_PT_TIMESTAMP"]]),
        "expires": float(entry[idx["IDX_PT_EXPIRES"]]),
        "random_blobs": [
            b.hex() for b in random_blobs if isinstance(b, (bytes, bytearray))
        ],
        "receiving_interface": str(rvcd_if),
        "receiving_interface_hash": rvcd_if_hash,
        "packet_hash": packet_hash.hex() if isinstance(packet_hash, (bytes, bytearray)) else None,
    }


def cmd_behavioral_packet_filter(params):
    """Run a raw packet through RNS's duplicate/replay filter and report the
    verdict, mirroring exactly what Transport.inbound does at its gate.

    Transport.inbound (Transport.py:1484-1504) accepts a packet only if
    Transport.packet_filter(packet) returns True, then — for packets it should
    remember — records the hash via add_packet_hash so a subsequent identical
    packet is dropped (Transport.py:1374). This command reproduces that gate so
    a test can inject an identical packet twice and observe True-then-False
    (the hashlist replay/loop drop, the branch's namesake). It does NOT clear
    packet_hashlist — that is the whole point.

    Both calls delegate to the real RNS staticmethods (packet_filter,
    add_packet_hash); no filtering logic is reimplemented here. A correct impl
    returns True for a novel packet and False on replay; an impl with no
    duplicate detection returns True twice and fails the test.

    Note: per RNS, SINGLE-destination ANNOUNCE packets are deliberately NOT
    deduplicated by the hashlist (they have their own random_blob replay
    protection), so replay tests must use a non-announce DATA packet to a
    SINGLE destination.

    params: handle, raw (hex), remember (default True)
    returns: {accepted, packet_hash, remembered}
    """
    RNS = _get_rns()
    handle = params["handle"]
    raw = bytes.fromhex(params["raw"])
    remember = bool(params.get("remember", True))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    packet = RNS.Packet(None, raw)
    if not packet.unpack():
        raise ValueError("packet failed to unpack")

    accepted = bool(RNS.Transport.packet_filter(packet))
    remembered = False
    if accepted and remember:
        # Mirror inbound's remember step (Transport.py:1503-1504) so a
        # subsequent identical packet is filtered as a duplicate.
        RNS.Transport.add_packet_hash(packet.packet_hash)
        remembered = True

    return {
        "accepted": accepted,
        "packet_hash": packet.packet_hash.hex(),
        "remembered": remembered,
    }


# Reverse / announce / tunnel table indices, resolved from the installed RNS
# module the same way _pt_indices does (RNS.Transport is the CLASS, so the
# module-level IDX_* globals at RNS/Transport.py:3545-3584 aren't class attrs).
_IDX_RT_FALLBACK = {"IDX_RT_RCVD_IF": 0, "IDX_RT_OUTB_IF": 1, "IDX_RT_TIMESTAMP": 2}
_IDX_AT_FALLBACK = {
    "IDX_AT_TIMESTAMP": 0, "IDX_AT_RTRNS_TMO": 1, "IDX_AT_RETRIES": 2,
    "IDX_AT_RCVD_IF": 3, "IDX_AT_HOPS": 4, "IDX_AT_PACKET": 5,
    "IDX_AT_LCL_RBRD": 6, "IDX_AT_BLCK_RBRD": 7, "IDX_AT_ATTCHD_IF": 8,
}
_IDX_TT_FALLBACK = {
    "IDX_TT_TUNNEL_ID": 0, "IDX_TT_IF": 1, "IDX_TT_PATHS": 2, "IDX_TT_EXPIRES": 3,
}


def _idx(fallback):
    """Resolve a group of IDX_* table-field constants from the installed RNS
    Transport module, falling back to the RNS 1.3.1 values if shadowed."""
    RNS = _get_rns()
    import importlib
    try:
        mod = importlib.import_module(RNS.Transport.__module__)
    except Exception:
        mod = None
    return {
        name: (getattr(mod, name, default) if mod is not None else default)
        for name, default in fallback.items()
    }


def _iface_descriptor(inst, iface_obj):
    """Map an interface OBJECT back to {iface_id, hash, name} for an instance.

    iface_id is the opaque handle the test attached with (so assertions read
    naturally); hash is iface.get_hash().hex() (matches attach's
    interface_hash). Returns Nones if the object isn't one of ours."""
    iface_id = None
    for k, v in inst.get("interfaces", {}).items():
        if v is iface_obj:
            iface_id = k
            break
    try:
        ihash = iface_obj.get_hash().hex()
    except Exception:
        ihash = None
    name = getattr(iface_obj, "name", None)
    return {"iface_id": iface_id, "hash": ihash, "name": name}


def cmd_behavioral_read_reverse_table(params):
    """Read RNS.Transport.reverse_table entries (single-packet proof return-route).

    The reverse table is keyed by the forwarded DATA packet's truncated hash
    (Transport.py:1631, `getTruncatedHash()`); each entry is
    [received_interface, outbound_interface, timestamp] (IDX_RT_*,
    :3554-3556). When a PROOF arrives whose destination_hash equals that key
    and on the correct (outbound) interface, Transport routes it back out the
    received interface (:2254-2263). Exposing the table lets a test seed a path,
    relay a DATA packet, then assert the reverse entry's outbound/received ifaces
    so the proof return-routing is observable.

    params: handle, dest (optional reverse-table key hex). With dest, returns the
            single entry; without, returns all entries (so a test can discover
            the truncated-hash key to build its PROOF against).
    returns: {found, received_if, outbound_if, received_if_hash, outbound_if_hash,
              timestamp}  OR  {entries: [...]}
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    idx = _idx(_IDX_RT_FALLBACK)
    table = RNS.Transport.reverse_table

    def _decompose(key, entry):
        rcvd = _iface_descriptor(inst, entry[idx["IDX_RT_RCVD_IF"]])
        outb = _iface_descriptor(inst, entry[idx["IDX_RT_OUTB_IF"]])
        return {
            "key": key.hex() if isinstance(key, (bytes, bytearray)) else key,
            "received_if": rcvd["iface_id"],
            "outbound_if": outb["iface_id"],
            "received_if_hash": rcvd["hash"],
            "outbound_if_hash": outb["hash"],
            "received_if_name": rcvd["name"],
            "outbound_if_name": outb["name"],
            "timestamp": float(entry[idx["IDX_RT_TIMESTAMP"]]),
        }

    dest = params.get("dest")
    if dest is not None:
        key = bytes.fromhex(dest)
        if key not in table:
            return {"found": False}
        d = _decompose(key, table[key])
        d["found"] = True
        return d

    return {"entries": [_decompose(k, v) for k, v in table.items()]}


def cmd_behavioral_read_announce_table(params):
    """Read RNS.Transport.announce_table[dest] (the local-rebroadcast / retransmit
    state machine).

    Entry layout (IDX_AT_*, Transport.py:3559-3567):
      [timestamp, retransmit_timeout, retries, received_from, hops, packet,
       local_rebroadcasts, block_rebroadcasts, attached_interface]
    NB: IDX_AT_RCVD_IF (index 3) is misleadingly named — it holds `received_from`,
    a HASH (packet.transport_id when present, else packet.destination_hash;
    Transport.py:1714/:1739), NOT an interface object — so it is surfaced as a hex
    hash. `attached_interface` (index 8) IS an interface (or None) and is mapped
    back to its iface_id. Surfaces `retries` and `hops` so a test can drive the
    LOCAL_REBROADCASTS_MAX completion (:580) and the heard-rebroadcast cancel
    branch (:1719-1736).

    params: handle, dest (destination hash hex)
    returns: {found, retries, hops, timestamp, retransmit_timeout,
              local_rebroadcasts, block_rebroadcasts, received_from,
              attached_interface, packet_hash}
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    idx = _idx(_IDX_AT_FALLBACK)
    table = RNS.Transport.announce_table
    if dest not in table:
        return {"found": False}

    entry = table[dest]
    received_from = entry[idx["IDX_AT_RCVD_IF"]]
    attached_obj = entry[idx["IDX_AT_ATTCHD_IF"]]
    attached = _iface_descriptor(inst, attached_obj) if attached_obj is not None else None
    packet = entry[idx["IDX_AT_PACKET"]]
    packet_hash = getattr(packet, "packet_hash", None)

    return {
        "found": True,
        "retries": int(entry[idx["IDX_AT_RETRIES"]]),
        "hops": int(entry[idx["IDX_AT_HOPS"]]),
        "timestamp": float(entry[idx["IDX_AT_TIMESTAMP"]]),
        "retransmit_timeout": float(entry[idx["IDX_AT_RTRNS_TMO"]]),
        "local_rebroadcasts": int(entry[idx["IDX_AT_LCL_RBRD"]]),
        "block_rebroadcasts": bool(entry[idx["IDX_AT_BLCK_RBRD"]]),
        "received_from": received_from.hex() if isinstance(received_from, (bytes, bytearray)) else None,
        "attached_interface": attached["iface_id"] if attached else None,
        "packet_hash": packet_hash.hex() if isinstance(packet_hash, (bytes, bytearray)) else None,
    }


def cmd_behavioral_read_tunnels(params):
    """Read RNS.Transport.tunnels (the tunnel handshake observable).

    Entry layout (IDX_TT_*, Transport.py:3581-3584):
      [tunnel_id, interface, paths, expires]
    After a synthesize packet is injected and validated, handle_tunnel
    (:2336-2345) inserts an entry here, so a test can assert a tunnel with the
    expected tunnel_id == full_hash(pubkey||iface_hash) was established.

    params: handle
    returns: {tunnels: [{tunnel_id, interface_hash, interface_id, expires,
                         num_paths}]}
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    idx = _idx(_IDX_TT_FALLBACK)
    out = []
    for tunnel_id, entry in RNS.Transport.tunnels.items():
        iface_obj = entry[idx["IDX_TT_IF"]]
        desc = _iface_descriptor(inst, iface_obj) if iface_obj is not None else {"iface_id": None, "hash": None}
        paths = entry[idx["IDX_TT_PATHS"]]
        out.append({
            "tunnel_id": tunnel_id.hex() if isinstance(tunnel_id, (bytes, bytearray)) else tunnel_id,
            "interface_hash": desc["hash"],
            "interface_id": desc["iface_id"],
            "expires": float(entry[idx["IDX_TT_EXPIRES"]]),
            "num_paths": len(paths) if hasattr(paths, "__len__") else 0,
        })
    return {"tunnels": out}


def cmd_behavioral_synthesize_tunnel(params):
    """Emit a tunnel-synthesize packet on an interface (Transport.py:2282-2303).

    Calls the real Transport.synthesize_tunnel(iface), which constructs a PLAIN
    broadcast packet carrying pubkey||iface_hash||random_hash||sig to the
    rnstransport/tunnel/synthesize destination and sends it on the interface.
    The bytes are captured in the MockInterface TX queue (drain_tx). Returns the
    locally-computed tunnel_id (full_hash(pubkey||iface_hash)) so the test can
    assert the emitted packet's payload decomposes to it.

    params: handle, iface_id
    returns: {iface_id, tunnel_id}
    """
    RNS = _get_rns()
    handle = params["handle"]
    iface_id = params["iface_id"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    iface = inst["interfaces"].get(iface_id)
    if iface is None:
        raise ValueError(f"Unknown iface_id: {iface_id}")

    tunnel_id_data = RNS.Transport.identity.get_public_key() + iface.get_hash()
    tunnel_id = RNS.Identity.full_hash(tunnel_id_data)

    RNS.Transport.synthesize_tunnel(iface)

    return {"iface_id": iface_id, "tunnel_id": tunnel_id.hex()}


def cmd_behavioral_set_path_timestamp(params):
    """Set path_table[dest][IDX_PT_TIMESTAMP] for deterministic expiry tests.

    Path-table cull (Transport.py:771-785) evicts entries once
    time.time() > timestamp + {AP,ROAMING,DESTINATION}_PATH_TIME. Rewinding the
    timestamp into the past, then calling behavioral_force_cull, evicts the path
    WITHOUT any real sleep.

    params: handle, dest (hex), timestamp (float epoch seconds)
    returns: {set}
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])
    ts = float(params["timestamp"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    idx = _pt_indices()
    table = RNS.Transport.path_table
    if dest not in table:
        return {"set": False}
    table[dest][idx["IDX_PT_TIMESTAMP"]] = ts
    return {"set": True}


def cmd_behavioral_set_announce_timestamp(params):
    """Age an announce_table[dest] entry for deterministic retransmit tests.

    The announce-retransmit job (Transport.py:587) fires when
    time.time() > entry[IDX_AT_RTRNS_TMO]. Setting that into the past, then
    calling behavioral_force_cull (which also runs the announce job branch),
    triggers a retransmit deterministically — no real sleep needed to observe
    retries incrementing.

    params: handle, dest (hex), retransmit_timeout (optional float),
            timestamp (optional float)
    returns: {set}
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    idx = _idx(_IDX_AT_FALLBACK)
    table = RNS.Transport.announce_table
    if dest not in table:
        return {"set": False}
    entry = table[dest]
    if params.get("retransmit_timeout") is not None:
        entry[idx["IDX_AT_RTRNS_TMO"]] = float(params["retransmit_timeout"])
    if params.get("timestamp") is not None:
        entry[idx["IDX_AT_TIMESTAMP"]] = float(params["timestamp"])
    return {"set": True}


def cmd_behavioral_force_cull(params):
    """Run RNS.Transport.jobs() once, forcing the time-gated cull + announce
    branches WITHOUT real sleeps.

    Rewinds Transport.tables_last_culled and Transport.announces_last_checked to
    0 so the table-cull (:662-932) and announce-retransmit (:573-636) branches
    both execute on this synchronous jobs() pass. jobs() takes jobs_lock, so it
    is safe to call alongside the background jobloop. Use after
    behavioral_set_path_timestamp / behavioral_set_announce_timestamp to make
    eviction / retransmit deterministic.

    params: handle
    returns: {culled}
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    RNS.Transport.tables_last_culled = 0
    RNS.Transport.announces_last_checked = 0
    RNS.Transport.jobs()
    return {"culled": True}


def cmd_behavioral_detach_interface(params):
    """Detach one interface and remove it from Transport's interface lists.

    Mirrors what RNS does on interface teardown: the interface leaves
    Transport.interfaces (and local_client_interfaces if it was a local client).
    The path-table cull then evicts any path whose attached_interface is no
    longer in Transport.interfaces (:782-785) — the missing-interface eviction
    path, which needs no clock. The iface stays in this instance's bookkeeping
    so behavioral_stop still tears it down cleanly.

    params: handle, iface_id
    returns: {detached}
    """
    RNS = _get_rns()
    handle = params["handle"]
    iface_id = params["iface_id"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    iface = inst["interfaces"].get(iface_id)
    if iface is None:
        raise ValueError(f"Unknown iface_id: {iface_id}")

    iface.detach()
    if iface in RNS.Transport.interfaces:
        RNS.Transport.interfaces.remove(iface)
    if iface in RNS.Transport.local_client_interfaces:
        RNS.Transport.local_client_interfaces.remove(iface)
    return {"detached": True}


BEHAVIORAL_COMMANDS = {
    "behavioral_start": cmd_behavioral_start,
    "behavioral_stop": cmd_behavioral_stop,
    "behavioral_attach_mock_interface": cmd_behavioral_attach_mock_interface,
    "behavioral_inject": cmd_behavioral_inject,
    "behavioral_drain_tx": cmd_behavioral_drain_tx,
    "behavioral_read_path_table": cmd_behavioral_read_path_table,
    "behavioral_packet_filter": cmd_behavioral_packet_filter,
    "behavioral_read_reverse_table": cmd_behavioral_read_reverse_table,
    "behavioral_read_announce_table": cmd_behavioral_read_announce_table,
    "behavioral_read_tunnels": cmd_behavioral_read_tunnels,
    "behavioral_synthesize_tunnel": cmd_behavioral_synthesize_tunnel,
    "behavioral_set_path_timestamp": cmd_behavioral_set_path_timestamp,
    "behavioral_set_announce_timestamp": cmd_behavioral_set_announce_timestamp,
    "behavioral_force_cull": cmd_behavioral_force_cull,
    "behavioral_detach_interface": cmd_behavioral_detach_interface,
}
