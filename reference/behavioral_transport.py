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
    # Blackholed-identity table is process-wide (Transport.blackholed_identities).
    # A handle that blackholes an identity must not leak that into the next
    # handle's validate_announce gate (Identity.py:567-569), so clear it here.
    if hasattr(T, "blackholed_identities") and hasattr(T.blackholed_identities, "clear"):
        T.blackholed_identities.clear()
    # Externally-registered announce handlers are a process-wide list
    # (Transport.announce_handlers). A handler registered by one handle must not
    # leak into the next handle's announce dispatch (Transport.py:2034-2087).
    if hasattr(T, "announce_handlers") and hasattr(T.announce_handlers, "clear"):
        T.announce_handlers.clear()
    # Pending path-request bookkeeping (Transport.path_requests /
    # discovery_path_requests). request_path records the requested destination
    # here; left over, it would make the unknown-destination ingress-limit
    # carve-out (Transport.py:1699-1701) skip for a later handle's announce.
    for attr in ("path_requests", "discovery_path_requests"):
        tbl = getattr(T, attr, None)
        if tbl is not None and hasattr(tbl, "clear"):
            tbl.clear()
    # Path-state map (STATE_UNRESPONSIVE et al., Transport.path_states) backs
    # mark_path_unresponsive / path_is_unresponsive — clear so an unresponsive
    # mark from one handle doesn't bias the next handle's path-replacement
    # equal-emission branch (Transport.py:1818-1823).
    if hasattr(T, "path_states") and hasattr(T.path_states, "clear"):
        T.path_states.clear()
    # Restore the standalone-master posture: the shared-instance predicate is a
    # plain attribute on Transport.owner that one handle may have flipped True
    # (cmd_behavioral_start connected_to_shared_instance). Reset so the next
    # handle starts as a normal filtering node (Transport.py:1337/:1376).
    if getattr(T, "owner", None) is not None:
        T.owner.is_connected_to_shared_instance = False


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
    connected_to_shared_instance = bool(params.get("connected_to_shared_instance", False))

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

    # Shared-instance predicate (Transport.py:1337 short-circuit in packet_filter,
    # and the add_packet_hash guard at :1376). On a real node this flips True only
    # when RNS connects this process to a separate shared master over a
    # LocalClientInterface; the behavioral harness always runs a standalone master
    # (share_instance=No), so the flag is otherwise always False and the
    # "shared instance handles filtering, so don't filter here" branch is never
    # taken. Setting it on Transport.owner (the Reticulum instance, a plain bool
    # attribute) lets a test exercise that branch. _reset_transport_state restores
    # False so it never leaks into the next handle.
    RNS.Transport.owner.is_connected_to_shared_instance = connected_to_shared_instance

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

    # Deregister any local destinations this handle registered so they don't
    # leak into the next handle's Transport.destinations_map (the local-
    # destination announce carve-out, Transport.py:1707-1712).
    for destination in inst.get("destinations", []):
        try:
            RNS.Transport.deregister_destination(destination)
        except Exception:
            pass

    # Deregister any recording announce handlers this handle registered so they
    # don't leak into the next handle's Transport.announce_handlers dispatch
    # (Transport.py:2034-2087).
    for handler in inst.get("announce_handlers", {}).values():
        try:
            RNS.Transport.deregister_announce_handler(handler)
        except Exception:
            pass

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
    ifac_netname = params.get("ifac_netname")
    ifac_netkey = params.get("ifac_netkey")
    ifac_size = params.get("ifac_size")

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

    # Configure IFAC (Interface Access Codes) on this interface exactly as
    # RNS.Reticulum._add_interface does (Reticulum.py:1060-1078) when an
    # interface block carries network_name/passphrase. Everything is derived by
    # real RNS primitives (Identity.full_hash, Cryptography.hkdf,
    # Identity.from_bytes); we only assign the results onto the interface, which
    # is exactly what RNS itself does. This arms the IFAC authentication branch
    # in Transport.inbound (Transport.py:1399-1445) — the MockInterface defaults
    # ifac_size=0/ifac_identity=None, so without this the branch is never taken.
    computed_ifac_size = 0
    if ifac_netname is not None or ifac_netkey is not None:
        ifac_origin = b""
        if ifac_netname is not None:
            ifac_origin += RNS.Identity.full_hash(ifac_netname.encode("utf-8"))
        if ifac_netkey is not None:
            ifac_origin += RNS.Identity.full_hash(ifac_netkey.encode("utf-8"))
        ifac_origin_hash = RNS.Identity.full_hash(ifac_origin)
        iface.ifac_key = RNS.Cryptography.hkdf(
            length=64,
            derive_from=ifac_origin_hash,
            salt=RNS.Reticulum.IFAC_SALT,
            context=None,
        )
        iface.ifac_identity = RNS.Identity.from_bytes(iface.ifac_key)
        iface.ifac_signature = iface.ifac_identity.sign(
            RNS.Identity.full_hash(iface.ifac_key)
        )
        # ifac_size defaults to the TCP/UDP DEFAULT_IFAC_SIZE (16); RNS derives
        # this per interface subclass (Reticulum.py:1049-1050). Allow override.
        iface.ifac_size = int(ifac_size) if ifac_size is not None else 16
        computed_ifac_size = iface.ifac_size

    inst["interfaces"][iface_id] = iface
    RNS.Transport.interfaces.append(iface)

    return {
        "iface_id": iface_id,
        "interface_hash": iface.get_hash().hex(),
        "ifac_size": computed_ifac_size,
    }


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


def cmd_behavioral_ifac_mask(params):
    """IFAC-mask a genuine RNS packet for a given interface and return the
    on-wire (masked) bytes.

    Delegates entirely to RNS.Transport.transmit (Transport.py:1050-1085): the
    interface must have an ifac_identity configured (via
    behavioral_attach_mock_interface ifac_netname/ifac_netkey). transmit signs
    the raw with the interface's ifac_identity, derives the HKDF mask, sets the
    IFAC header flag, inserts the access code and masks the payload — the exact
    bytes RNS would put on the wire. The MockInterface buffers them in its TX
    queue; we drain and return them. No masking is reimplemented here.

    The returned masked frame, injected back on the SAME interface, round-trips
    through the inbound IFAC-authentication branch (Transport.py:1399-1432): RNS
    unmasks it, recomputes the expected access code and accepts it. Truncating it
    to <= 2+ifac_size exercises the "too short to contain the IFAC" silent drop
    (Transport.py:1402, the `else: return`).

    params: handle, iface_id, raw (hex of a genuine unmasked packet)
    returns: {masked} (hex)
    """
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
    if getattr(iface, "ifac_identity", None) is None:
        raise ValueError("interface has no IFAC identity configured")

    RNS = _get_rns()
    # Clear any pending TX so we return only the masked frame.
    iface.drain_tx()
    RNS.Transport.transmit(iface, raw)
    emitted = iface.drain_tx()
    if len(emitted) != 1:
        raise RuntimeError(f"expected exactly one masked frame, got {len(emitted)}")
    return {"masked": emitted[0].hex()}


def cmd_behavioral_inbound_remembered(params):
    """Run the FULL RNS.Transport.inbound on a raw frame and report whether the
    packet's hash was recorded in Transport.packet_hashlist.

    behavioral_packet_filter only runs the packet_filter gate + an unconditional
    add_packet_hash; it CANNOT observe the inbound-side deferrals at
    Transport.py:1496-1504, where remember_packet_hash is forced False when the
    destination is in Transport.link_table, or when the packet is a PROOF with
    context==LRPROOF. This command drives the real inbound() end to end and then
    inspects packet_hashlist, so those deferrals (and the IFAC gate at
    :1399-1445, which runs before any hashing) become observable.

    Observables:
      hashlist_before / hashlist_after — size of Transport.packet_hashlist around
        the inbound() call. hashlist_grew == (after > before) is the
        implementation-independent "this frame caused a packet to be remembered"
        signal — robust even when the frame is dropped in the IFAC gate before a
        packet_hash can be computed.
      packet_hash / in_hashlist — when the frame is independently unpackable, the
        precise hash and its membership (computed from the supplied raw, whose
        hops field is excluded from the hash, so it matches the hash inbound
        stores even though inbound increments hops).

    All hashing/filtering is RNS's; this command never decides accept/remember.

    params: handle, iface_id, raw (hex)
    returns: {hashlist_before, hashlist_after, hashlist_grew, unpackable,
              packet_hash, in_hashlist}
    """
    RNS = _get_rns()
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

    # Independently determine the packet hash (if the frame is a valid packet).
    # Uses RNS.Packet.unpack — the same parse inbound runs. The packet hash
    # excludes the hops byte (get_hashable_part), so it equals the hash inbound
    # stores even though inbound bumps hops by one.
    packet_hash = None
    probe = RNS.Packet(None, raw)
    try:
        unpackable = bool(probe.unpack())
    except Exception:
        unpackable = False
    if unpackable:
        packet_hash = probe.packet_hash

    before = len(RNS.Transport.packet_hashlist)
    iface.inject(raw)
    after = len(RNS.Transport.packet_hashlist)

    in_hashlist = bool(packet_hash is not None and packet_hash in RNS.Transport.packet_hashlist)

    return {
        "hashlist_before": before,
        "hashlist_after": after,
        "hashlist_grew": after > before,
        "unpackable": unpackable,
        "packet_hash": packet_hash.hex() if packet_hash is not None else None,
        "in_hashlist": in_hashlist,
    }


def cmd_behavioral_seed_link_table(params):
    """Seed Transport.link_table[dest] so the inbound link-table deferral
    (Transport.py:1496-1498) can be exercised on a single injected packet.

    Transport.inbound forces remember_packet_hash=False when an inbound packet's
    destination_hash is already a key in Transport.link_table — a relayed link
    can be seen on a shared-medium interface "before it would normally reach us",
    and remembering it early would break link transport. There is no single-packet
    way to populate link_table without driving a full multi-hop LINKREQUEST relay,
    so this command installs a correctly-shaped entry directly (mirroring the
    RNS link_entry layout at Transport.py:1600-1620, IDX_LT_* at :3570-3578).

    The entry's next-hop and received interfaces are real attached MockInterfaces.
    REM_HOPS/HOPS default to a value that will NOT match the injected packet's
    hops, so the later link-transport branch (:1644-1679) does not re-add the
    hash either — isolating the deferral as the sole reason the packet is not
    remembered. (Set matching hops to instead drive the relay re-add path.)

    params: handle, dest (hex), nh_iface_id, rcvd_iface_id, rem_hops (default 99),
            hops (default 99)
    returns: {seeded, dest}
    """
    import time
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    nh_iface = inst["interfaces"].get(params["nh_iface_id"])
    rcvd_iface = inst["interfaces"].get(params["rcvd_iface_id"])
    if nh_iface is None or rcvd_iface is None:
        raise ValueError("nh_iface_id / rcvd_iface_id must reference attached interfaces")

    rem_hops = int(params.get("rem_hops", 99))
    hops = int(params.get("hops", 99))
    now = time.time()

    # link_entry layout (Transport.py IDX_LT_*): [timestamp, next_hop_transport_id,
    # next_hop_interface, remaining_hops, received_interface, hops, dest_hash,
    # validated, proof_timeout].
    link_entry = [now, None, nh_iface, rem_hops, rcvd_iface, hops, dest, True, now + 60.0]
    with RNS.Transport.link_table_lock:
        RNS.Transport.link_table[dest] = link_entry

    return {"seeded": True, "dest": dest.hex()}


def cmd_behavioral_register_destination(params):
    """Register a real local IN/SINGLE destination on this Transport instance.

    Constructs an RNS.Destination(identity, IN, SINGLE, app_name, *aspects) from
    the supplied 64-byte Identity private key. RNS.Destination.__init__ calls
    Transport.register_destination(self) (Destination.py:196), which appends the
    destination to Transport.destinations and inserts it into
    Transport.destinations_map (Transport.py:2415-2426) — exactly the table the
    inbound announce path consults for the local-destination carve-out
    (Transport.py:1707-1712). Everything is RNS's own construction/registration;
    we only retain the object so behavioral_stop can deregister it.

    The destination_hash equals RNS.Destination.hash(identity, app_name,
    *aspects), so a test can build an announce for the SAME identity+app+aspects
    (via announce_build) and inject it: because the hash is already a local
    destination, Transport.inbound must NOT process it into the path/announce
    tables (route-hijack defense).

    params: handle, app_name, aspects (list), identity_seed (64-byte private key hex)
    returns: {destination_hash}
    """
    RNS = _get_rns()
    handle = params["handle"]
    app_name = params["app_name"]
    aspects = list(params.get("aspects", []))
    seed = bytes.fromhex(params["identity_seed"])
    if len(seed) != 64:
        raise ValueError("identity_seed must be 64 bytes (32 enc + 32 sig)")

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(seed)
    destination = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, *aspects
    )
    inst.setdefault("destinations", []).append(destination)
    return {"destination_hash": destination.hash.hex()}


def cmd_behavioral_read_announce_rate(params):
    """Read RNS.Transport.announce_rate_table[dest] (the inbound announce-rate
    limiter state, Transport.py:1830-1860).

    Each entry is a dict {"last", "rate_violations", "blocked_until",
    "timestamps":[...]} built and mutated entirely by Transport.inbound: a new
    entry on the first should-add announce for a destination on a rate-limited
    interface, then per-announce timestamp appends, a sliding cap at
    MAX_RATE_TIMESTAMPS=16, grace-counter increment/decrement, and a
    blocked_until = last + rate_target + rate_penalty penalty window. This is a
    pure read of RNS's own table — no rate logic is reimplemented here.

    params: handle, dest (destination hash hex)
    returns: {found, last, rate_violations, blocked_until, timestamps:[...]}
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    table = RNS.Transport.announce_rate_table
    if dest not in table:
        return {"found": False}
    entry = table[dest]
    return {
        "found": True,
        "last": float(entry["last"]),
        "rate_violations": int(entry["rate_violations"]),
        "blocked_until": float(entry["blocked_until"]),
        "timestamps": [float(t) for t in entry["timestamps"]],
    }


def cmd_behavioral_set_path_expires(params):
    """Set path_table[dest][IDX_PT_EXPIRES] for deterministic path-replacement
    tests (Transport.py:1789 path_expires read).

    The larger-hop announce replacement logic (Transport.py:1785-1823) reads the
    path entry's EXPIRES field (index 3), NOT the TIMESTAMP field that
    behavioral_set_path_timestamp rewinds. Rewinding EXPIRES into the past makes
    `now >= path_expires` true, so a subsequent larger-hop announce with a novel
    random_blob is accepted (branch a). This only assigns a float to RNS's own
    table entry; no replacement logic is reimplemented.

    params: handle, dest (hex), expires (float epoch seconds)
    returns: {set}
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])
    expires = float(params["expires"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    idx = _pt_indices()
    table = RNS.Transport.path_table
    if dest not in table:
        return {"set": False}
    table[dest][idx["IDX_PT_EXPIRES"]] = expires
    return {"set": True}


def cmd_behavioral_mark_path_unresponsive(params):
    """Mark a path as unresponsive via real Transport.mark_path_unresponsive
    (Transport.py:2719-2724).

    Sets Transport.path_states[dest] = STATE_UNRESPONSIVE, which the
    equal-emission announce-replacement branch reads through
    Transport.path_is_unresponsive (Transport.py:1818-1823): an announce with
    larger hops and an emission timestamp EQUAL to the stored path's is accepted
    only when the existing path was previously marked unresponsive. Delegates
    entirely to the real staticmethod.

    params: handle, dest (hex)
    returns: {marked}  (False if there is no path_table entry for dest)
    """
    RNS = _get_rns()
    handle = params["handle"]
    dest = bytes.fromhex(params["dest"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    marked = bool(RNS.Transport.mark_path_unresponsive(dest))
    return {"marked": marked}


def cmd_behavioral_request_path(params):
    """Drive the impl's OWN Transport.request_path and let the test drain the
    emitted path-request packet (Transport.py:2769-2812).

    Calls the real Transport.request_path(dest, on_interface=iface, tag=...),
    which builds a PLAIN DATA broadcast packet to the rnstransport.path.request
    control destination with payload `dest [|| Transport.identity.hash] || tag`
    (transport_id present only when transport is enabled) and sends it on the
    given interface. The MockInterface buffers the on-wire bytes (drain_tx), so a
    test can byte-assert the header flags and payload split. No path-request wire
    bytes are assembled here — RNS.Packet.pack produces them.

    params: handle, iface_id, dest (hex), tag (optional hex)
    returns: {tag}  (the request tag actually used, hex)
    """
    RNS = _get_rns()
    handle = params["handle"]
    iface_id = params["iface_id"]
    dest = bytes.fromhex(params["dest"])
    tag = bytes.fromhex(params["tag"]) if params.get("tag") else None

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    iface = inst["interfaces"].get(iface_id)
    if iface is None:
        raise ValueError(f"Unknown iface_id: {iface_id}")

    # If no tag is supplied, RNS mints a random one internally; supply a tag for
    # deterministic payload-length assertions.
    used_tag = tag if tag is not None else RNS.Identity.get_random_hash()
    RNS.Transport.request_path(dest, on_interface=iface, tag=used_tag)
    return {"tag": used_tag.hex()}


def cmd_behavioral_blackhole_identity(params):
    """Blackhole an identity via real Transport.blackhole_identity
    (Transport.py:3406-3428).

    Inserts identity_hash into Transport.blackholed_identities (and persists +
    drops any associated paths, exactly as RNS does). Once present,
    Identity.validate_announce invalidates and drops any announce whose
    announced identity hash is blackholed (Identity.py:567-569), so an injected
    announce from that identity creates no path entry. Delegates to the real
    staticmethod; _reset_transport_state clears the table between handles.

    Optional `until` (unix timestamp float) and `reason` (str) are passed
    straight through to Transport.blackhole_identity so the recorded entry
    carries them, exactly as `rnpath -B --duration/--reason` would
    (rnpath.py:214-215). This lets a test assert the {source, until, reason}
    entry schema the /list handler and rnpath consumer rely on.

    params: handle, identity_hash (hex), until (optional float), reason (optional str)
    returns: {blackholed}
    """
    RNS = _get_rns()
    handle = params["handle"]
    identity_hash = bytes.fromhex(params["identity_hash"])
    until = params.get("until")
    reason = params.get("reason")

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    result = RNS.Transport.blackhole_identity(identity_hash, until=until, reason=reason)
    return {"blackholed": bool(result)}


def cmd_behavioral_unblackhole_identity(params):
    """Lift a blackhole via real Transport.unblackhole_identity (Transport.py:3431).

    Delegates to the real staticmethod, which pops the identity from
    Transport.blackholed_identities and re-persists the local list. Returns
    {lifted} (True if it was present, False/None otherwise).

    params: handle, identity_hash (hex)
    returns: {lifted}
    """
    RNS = _get_rns()
    handle = params["handle"]
    identity_hash = bytes.fromhex(params["identity_hash"])

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    result = RNS.Transport.unblackhole_identity(identity_hash)
    return {"lifted": bool(result)}


def _serialize_blackhole_entry(identity_hash, entry):
    """Decompose one Transport.blackholed_identities item into a JSON-safe dict.

    Reads the real RNS entry fields straight off the dict RNS populated
    (entry["source"]/["until"]/["reason"]); no protocol bytes are constructed.
    """
    source = entry.get("source")
    return {
        "identity_hash": identity_hash.hex(),
        "source": source.hex() if isinstance(source, (bytes, bytearray)) else None,
        "until": entry.get("until"),
        "reason": entry.get("reason"),
    }


def cmd_behavioral_read_blackhole_table(params):
    """Read RNS.Transport.blackholed_identities as a JSON-safe list.

    Surfaces the live blackhole table (the exact dict the /list request handler
    returns and that Transport.reload_blackhole / persist_blackhole maintain) so
    a test can assert the per-entry schema {source, until, reason} and the keys.
    Reads RNS state only — nothing is reconstructed.

    params: handle
    returns: {count, entries: [{identity_hash, source, until, reason}, ...]}
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    table = RNS.Transport.blackholed_identities
    entries = [_serialize_blackhole_entry(h, table[h]) for h in table.copy()]
    return {"count": len(entries), "entries": entries}


def cmd_behavioral_blackhole_list_handler(params):
    """Invoke the REAL Transport.blackhole_list_handler — the response_generator
    registered on the rnstransport.info.blackhole '/list' request destination
    (Transport.py:262, :3514) — and report its result.

    This is the exact callable a remote `rnpath -L` fetch reaches over a Link
    (Discovery.BlackholeUpdater). Driving it directly (with the handler's real
    6-arg request signature) exercises the publish path without needing a live
    wire link. The handler returns Transport.blackholed_identities verbatim, so
    we report whether the returned object IS that dict plus its serialized
    entries for schema assertions.

    params: handle
    returns: {is_blackhole_table, count, entries: [...]}
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    result = RNS.Transport.blackhole_list_handler(
        "/list", None, None, None, None, None
    )
    is_table = result is RNS.Transport.blackholed_identities
    entries = []
    if isinstance(result, dict):
        entries = [_serialize_blackhole_entry(h, result[h]) for h in dict(result)]
    return {"is_blackhole_table": is_table, "count": len(entries), "entries": entries}


def cmd_behavioral_blackhole_reload(params):
    """Run the real Transport.reload_blackhole() (Transport.py:3453).

    reload_blackhole rescans <configdir>/storage/blackhole/*, loading each
    trusted source file (filename 'local' => own identity; otherwise a
    hex source-identity hash that must be in Reticulum.blackhole_sources()),
    skipping expired (until < now) entries and never overwriting a locally
    sourced entry, then calls remove_blackholed_paths(). Pure delegation.

    params: handle
    returns: {count}  (size of Transport.blackholed_identities afterward)
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    RNS.Transport.reload_blackhole()
    return {"count": len(RNS.Transport.blackholed_identities)}


def cmd_behavioral_blackhole_clear(params):
    """Empty the in-memory Transport.blackholed_identities table (NOT the
    on-disk storage). Lets a test prove that reload_blackhole repopulates it
    purely from the persisted source files. Mirrors what
    _reset_transport_state does between handles; exposed so a single test can
    clear-then-reload deterministically.

    params: handle
    returns: {cleared}
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    RNS.Transport.blackholed_identities.clear()
    return {"cleared": True}


def cmd_behavioral_blackhole_storage_files(params):
    """List the files RNS keeps under <configdir>/storage/blackhole.

    Reads RNS.Reticulum.blackholepath (the real persistence directory) and
    returns each filename + size so a test can assert the persistence file
    naming contract: the local list is 'local', and every fetched/remote source
    list is named by the hex of its source identity hash
    (Transport.reload_blackhole filename handling, Transport.py:3457-3465;
    persist_blackhole writes 'local', Transport.py:3531). Directory listing
    only — no file contents are decoded here.

    params: handle
    returns: {dir, files: [{name, size}, ...]}
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    path = RNS.Reticulum.blackholepath
    files = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if os.path.isfile(full):
            files.append({"name": name, "size": os.path.getsize(full)})
    return {"dir": path, "files": files}


def cmd_behavioral_blackhole_clear_storage(params):
    """Delete every file under <configdir>/storage/blackhole so a test starts
    from a clean persistence directory (the dir is process-wide and survives
    _reset_transport_state, which only clears the in-memory table).

    params: handle
    returns: {removed}  (number of files unlinked)
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    path = RNS.Reticulum.blackholepath
    removed = 0
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if os.path.isfile(full):
            os.remove(full)
            removed += 1
    return {"removed": removed}


def cmd_behavioral_blackhole_rename_storage(params):
    """Rename a file inside <configdir>/storage/blackhole.

    The bytes are NEVER touched — only the directory entry is renamed via
    os.rename. This lets a test repurpose the RNS-written 'local' list (whose
    umsgpack payload RNS itself produced via persist_blackhole) as a *remote*
    source file named by a source-identity hex, so reload_blackhole's
    remote-source path (hex-name validation, trusted-source gating, local
    precedence) can be exercised without a live fetch link and without the
    harness ever serializing a blackhole list itself.

    params: handle, src (filename), dst (filename)
    returns: {renamed}
    """
    RNS = _get_rns()
    handle = params["handle"]
    src = params["src"]
    dst = params["dst"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    path = RNS.Reticulum.blackholepath
    os.rename(os.path.join(path, src), os.path.join(path, dst))
    return {"renamed": True}


def cmd_behavioral_blackhole_set_sources(params):
    """Replace RNS's trusted blackhole-source list (the identity hashes a node
    is configured to accept remote blackhole lists from, normally parsed from
    the `blackhole_sources` config option, Reticulum.py:575-582).

    Mutates the real list returned by RNS.Reticulum.blackhole_sources() in
    place so reload_blackhole's trusted-source gate (Transport.py:3463 —
    `if source not in Reticulum.blackhole_sources(): skip`) sees the test's
    chosen sources. Reads/writes RNS state only.

    params: handle, sources (list of hex identity hashes)
    returns: {count}
    """
    RNS = _get_rns()
    handle = params["handle"]
    sources = [bytes.fromhex(s) for s in params.get("sources", [])]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    trusted = RNS.Reticulum.blackhole_sources()
    trusted.clear()
    trusted.extend(sources)
    return {"count": len(trusted)}


def cmd_behavioral_hold_and_release_announce(params):
    """Hold a set of real announce packets on an interface's ingress-control
    queue, then run ONE release pass and report which destination was released.

    This exposes the lowest-hops-FIRST release decision in
    Interface.process_held_announces (Interfaces/Interface.py:234-253) without
    any real clock dependence:

      * Each raw announce is turned into a genuine RNS.Packet exactly as
        Transport.inbound does (`RNS.Packet(None, raw)` + `packet.unpack()`,
        Transport.py:1451-1452), its receiving_interface pointed at the mock
        interface, and handed to the REAL `interface.hold_announce(packet)`
        (Interface.py:228-232) — the same call Transport.inbound makes at
        :1704. The harness reimplements no hold/selection logic.
      * `interface.ic_held_release` is backdated to 0 so the release gate
        (`time.time() > ic_held_release`) is open with no sleep — the same
        backdating technique the rest of the suite uses for time-gated jobs.
      * `interface.process_held_announces()` is then called ONCE. It selects the
        held announce with the FEWEST hops, pops it from `held_announces`, and
        re-injects it on a daemon thread. We read `held_announces` keys before
        and after (the pop is synchronous) to report exactly which destination
        was released. The re-injection does NOT re-hold the announce: a fresh
        mock interface has ic_burst_active False and incoming_announce_frequency
        0, so should_ingress_limit() is False (Interface.py:145-165), the branch
        that would re-hold it (Transport.py:1703-1704) is not taken.

    params:
        handle, iface_id, announces (list of raw announce hex)
    returns:
        held_before (list of dest_hash hex), held_after (list), released (list),
        hops ({dest_hash hex: hop count})
    """
    RNS = _get_rns()
    handle = params["handle"]
    iface_id = params["iface_id"]
    announces = params["announces"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")
    iface = inst["interfaces"].get(iface_id)
    if iface is None:
        raise ValueError(f"Unknown iface_id: {iface_id}")

    hops_map = {}
    for raw_hex in announces:
        raw = bytes.fromhex(raw_hex)
        # Build the Packet exactly as Transport.inbound does, then hold it via
        # the real ingress-control API.
        packet = RNS.Packet(None, raw)
        if not packet.unpack():
            raise ValueError("could not unpack supplied announce packet")
        packet.receiving_interface = iface
        iface.hold_announce(packet)
        hops_map[packet.destination_hash.hex()] = int(packet.hops)

    held_before = [dh.hex() for dh in iface.held_announces.keys()]
    # Open the release gate deterministically (no sleep).
    iface.ic_held_release = 0
    iface.process_held_announces()
    held_after = [dh.hex() for dh in iface.held_announces.keys()]
    released = [dh for dh in held_before if dh not in held_after]

    return {
        "held_before": held_before,
        "held_after": held_after,
        "released": released,
        "hops": hops_map,
    }


def _make_recording_announce_handler(aspect_filter, receive_path_responses,
                                     num_params, raise_on_call, omit_aspect_filter):
    """Build a real announce-handler object for RNS.Transport.register_announce_handler.

    The object exposes exactly the duck-typed surface RNS requires
    (Transport.register_announce_handler / Transport.inbound:2034-2087): an
    `aspect_filter` attribute, an optional `receive_path_responses` attribute,
    and a `received_announce(...)` callable whose parameter COUNT (3 or 4)
    selects which RNS dispatch arm fires. RNS itself does all the matching
    (hash_from_name_and_identity), path-response gating, and threaded dispatch;
    this handler only RECORDS the values RNS hands it (destination_hash,
    announced_identity.hash, app_data, announce_packet_hash) — no protocol bytes
    are reconstructed here.
    """
    calls = []
    lock = threading.Lock()

    def _record(destination_hash, announced_identity, app_data,
                announce_packet_hash=None):
        rec = {
            "destination_hash": destination_hash.hex()
                if isinstance(destination_hash, (bytes, bytearray)) else None,
            "announced_identity_hash": getattr(announced_identity, "hash", None).hex()
                if getattr(announced_identity, "hash", None) is not None else None,
            "app_data": app_data.hex()
                if isinstance(app_data, (bytes, bytearray)) else None,
        }
        if announce_packet_hash is not None:
            rec["announce_packet_hash"] = announce_packet_hash.hex() \
                if isinstance(announce_packet_hash, (bytes, bytearray)) else None
        with lock:
            calls.append(rec)

    if num_params == 4:
        def received_announce(destination_hash, announced_identity, app_data,
                              announce_packet_hash):
            _record(destination_hash, announced_identity, app_data,
                    announce_packet_hash)
            if raise_on_call:
                raise RuntimeError("recording announce handler deliberately raised")
    else:
        def received_announce(destination_hash, announced_identity, app_data):
            _record(destination_hash, announced_identity, app_data)
            if raise_on_call:
                raise RuntimeError("recording announce handler deliberately raised")

    class _RecordingAnnounceHandler:
        pass

    handler = _RecordingAnnounceHandler()
    # Per the rule under test, RNS.Transport.register_announce_handler only
    # registers a handler that HAS an aspect_filter attribute; omit it to drive
    # the rejection branch.
    if not omit_aspect_filter:
        handler.aspect_filter = aspect_filter
    if receive_path_responses is not None:
        handler.receive_path_responses = bool(receive_path_responses)
    handler.received_announce = received_announce
    handler._recorded_calls = calls
    handler._recorded_lock = lock
    return handler


def cmd_behavioral_register_announce_handler(params):
    """Register a real recording announce-handler on this Transport instance.

    Delegates to RNS.Transport.register_announce_handler (Transport.py:2465) with
    a duck-typed handler whose received_announce only records the arguments RNS
    dispatches to it. The dispatch decision (aspect_filter match via
    Destination.hash_from_name_and_identity, the PATH_RESPONSE/
    receive_path_responses gate, the 3-vs-4-parameter signature arm, and the
    per-handler exception isolation) is ENTIRELY RNS's — see Transport.inbound
    :2034-2087. The test reads back the recorded calls via
    behavioral_read_announce_handler_calls.

    params: handle, aspect_filter (str|None), receive_path_responses (bool|None),
            num_params (3|4, default 3), raise_on_call (bool),
            omit_aspect_filter (bool)
    returns: {handler_id, registered}  (registered=False iff RNS declined the
             handler because it lacked an aspect_filter attribute)
    """
    RNS = _get_rns()
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    aspect_filter = params.get("aspect_filter")
    receive_path_responses = params.get("receive_path_responses")
    num_params = int(params.get("num_params", 3))
    raise_on_call = bool(params.get("raise_on_call", False))
    omit_aspect_filter = bool(params.get("omit_aspect_filter", False))

    handler = _make_recording_announce_handler(
        aspect_filter, receive_path_responses, num_params, raise_on_call,
        omit_aspect_filter,
    )
    RNS.Transport.register_announce_handler(handler)
    registered = handler in RNS.Transport.announce_handlers

    handler_id = secrets.token_hex(8)
    inst.setdefault("announce_handlers", {})[handler_id] = handler
    return {"handler_id": handler_id, "registered": registered}


def cmd_behavioral_read_announce_handler_calls(params):
    """Return the calls a registered recording announce-handler has received.

    Pure read of the list the handler's received_announce (driven by real RNS
    dispatch) appended to. See cmd_behavioral_register_announce_handler.

    params: handle, handler_id
    returns: {calls: [{destination_hash, announced_identity_hash, app_data
                       [, announce_packet_hash]}], registered}
    """
    RNS = _get_rns()
    handle = params["handle"]
    handler_id = params["handler_id"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    handler = inst.get("announce_handlers", {}).get(handler_id)
    if handler is None:
        raise ValueError(f"Unknown announce handler_id: {handler_id}")

    with handler._recorded_lock:
        calls = [dict(c) for c in handler._recorded_calls]
    return {
        "calls": calls,
        "registered": handler in RNS.Transport.announce_handlers,
    }


BEHAVIORAL_COMMANDS = {
    "behavioral_register_destination": cmd_behavioral_register_destination,
    "behavioral_hold_and_release_announce": cmd_behavioral_hold_and_release_announce,
    "behavioral_read_announce_rate": cmd_behavioral_read_announce_rate,
    "behavioral_set_path_expires": cmd_behavioral_set_path_expires,
    "behavioral_mark_path_unresponsive": cmd_behavioral_mark_path_unresponsive,
    "behavioral_request_path": cmd_behavioral_request_path,
    "behavioral_blackhole_identity": cmd_behavioral_blackhole_identity,
    "behavioral_unblackhole_identity": cmd_behavioral_unblackhole_identity,
    "behavioral_read_blackhole_table": cmd_behavioral_read_blackhole_table,
    "behavioral_blackhole_list_handler": cmd_behavioral_blackhole_list_handler,
    "behavioral_blackhole_reload": cmd_behavioral_blackhole_reload,
    "behavioral_blackhole_clear": cmd_behavioral_blackhole_clear,
    "behavioral_blackhole_storage_files": cmd_behavioral_blackhole_storage_files,
    "behavioral_blackhole_clear_storage": cmd_behavioral_blackhole_clear_storage,
    "behavioral_blackhole_rename_storage": cmd_behavioral_blackhole_rename_storage,
    "behavioral_blackhole_set_sources": cmd_behavioral_blackhole_set_sources,
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
    "behavioral_ifac_mask": cmd_behavioral_ifac_mask,
    "behavioral_inbound_remembered": cmd_behavioral_inbound_remembered,
    "behavioral_seed_link_table": cmd_behavioral_seed_link_table,
    "behavioral_register_announce_handler": cmd_behavioral_register_announce_handler,
    "behavioral_read_announce_handler_calls": cmd_behavioral_read_announce_handler_calls,
}
