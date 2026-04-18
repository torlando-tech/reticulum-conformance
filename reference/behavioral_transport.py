"""
Behavioral Transport conformance commands.

Black-box harness for testing RNS Transport semantics across implementations.
Everything is observable on the wire: inject raw bytes on a mock interface,
drain emitted bytes from any interface, assert on the bytes.

No internal state introspection. If a property matters for correctness, it's
visible in what the Transport emits — otherwise it's an implementation detail.

Commands added:
  behavioral_start(identity_seed, enable_transport=True) -> {handle, identity_hash}
  behavioral_stop(handle) -> {}
  behavioral_attach_mock_interface(handle, name, mode='FULL', mtu=500) -> {iface_id}
  behavioral_inject(handle, iface_id, raw_hex) -> {}
  behavioral_drain_tx(handle, iface_id) -> {packets: [raw_hex, ...]}
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

        def __init__(self, name, mode_name="FULL", mtu=500):
            super().__init__()
            self.IN = True
            self.OUT = True
            self.FWD = False
            self.RPT = False
            self.name = name
            self.online = True
            self.bitrate = 10_000_000

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

            # Frequency-tracking attributes the base class expects
            self.announce_rate_target = None
            self.announce_rate_grace = 0
            self.announce_rate_penalty = 0

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
    reuse. Does reset the `enable_transport` flag based on the current test's
    desired config (Reticulum reads it from config_dir, so we write a fresh
    config before calling this).
    """
    RNS = _get_rns()
    T = RNS.Transport
    T.path_table.clear() if hasattr(T.path_table, "clear") else T.path_table.update({})
    T.announce_table.clear() if hasattr(T.announce_table, "clear") else None
    T.link_table.clear() if hasattr(T.link_table, "clear") else None
    T.packet_hashlist.clear() if hasattr(T.packet_hashlist, "clear") else None
    T.tunnels.clear() if hasattr(T.tunnels, "clear") else None
    T.reverse_table.clear() if hasattr(T.reverse_table, "clear") else None
    if hasattr(T, "announce_rate_table"):
        T.announce_rate_table.clear()


def _ensure_rns_started(config_dir, enable_transport):
    """Start (or reuse) the process-wide Reticulum instance. Writes config
    before starting so share_instance=No / enable_transport flags apply.

    If an instance already exists we reset its Transport state but keep the
    singleton alive, since RNS.Reticulum can't be re-initialized in the same
    process. enable_transport is a config-file property, so it cannot be
    changed after first init — document this as a known harness limitation
    and warn if a test asks for a different value.
    """
    global _shared_rns_instance, _shared_config_dir
    RNS = _get_rns()

    if _shared_rns_instance is not None:
        _reset_transport_state()
        return _shared_rns_instance

    _shared_config_dir = config_dir
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

    Each instance lives in its own config directory. Multiple instances can run
    concurrently in the same bridge process, each with its own path_table and
    mock interfaces."""
    RNS = _get_rns()

    identity_seed_hex = params.get("identity_seed")
    enable_transport = bool(params.get("enable_transport", True))

    config_dir = tempfile.mkdtemp(prefix="rns_behavioral_")
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

    _reset_transport_state()
    return {"stopped": True}


def cmd_behavioral_attach_mock_interface(params):
    """Attach a MockInterface to the given Transport instance."""
    RNS = _get_rns()

    handle = params["handle"]
    name = params["name"]
    mode = params.get("mode", "FULL")
    mtu = int(params.get("mtu", 500))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    MockInterface = inst["mock_interface_class"]
    iface = MockInterface(name=name, mode_name=mode, mtu=mtu)
    iface_id = secrets.token_hex(6)

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


BEHAVIORAL_COMMANDS = {
    "behavioral_start": cmd_behavioral_start,
    "behavioral_stop": cmd_behavioral_stop,
    "behavioral_attach_mock_interface": cmd_behavioral_attach_mock_interface,
    "behavioral_inject": cmd_behavioral_inject,
    "behavioral_drain_tx": cmd_behavioral_drain_tx,
}
