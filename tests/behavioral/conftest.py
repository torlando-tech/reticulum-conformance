"""
Behavioral-test fixtures.

These tests use the `behavioral_*` bridge commands (see
reference/behavioral_transport.py). Each test gets a FRESH bridge
process — unlike the session-scoped `sut` fixture used by byte-level
tests — because Python RNS's Reticulum singleton state can't be
reset in-process, and reusing a singleton across tests with different
`enable_transport` values silently produces false-positive passes.
"""

import os
import secrets

import pytest

from _rns_paths import resolve_rns_path
from bridge_client import BridgeClient
from conftest import get_impl_list, resolve_command


def pytest_generate_tests(metafunc):
    """Parametrize behavioral tests with the same impl list as the rest of
    the suite. We do this independently of the root conftest's `sut`-based
    parametrization because behavioral tests don't use `sut` directly
    (they use `behavioral`, which spawns a fresh bridge per-test).
    """
    if "behavioral_impl" in metafunc.fixturenames:
        impls = get_impl_list(metafunc.config) or ["reference"]
        metafunc.parametrize("behavioral_impl", impls, scope="function")


@pytest.fixture
def behavioral_impl(request):
    """Name of the impl under test (reference/kotlin/swift).

    Parametrized by `pytest_generate_tests` above.
    """
    return request.param


@pytest.fixture
def behavioral(behavioral_impl):
    """Helper bound to a FRESHLY-SPAWNED bridge process per test."""
    cmd = resolve_command(behavioral_impl)
    env = (
        {"PYTHON_RNS_PATH": resolve_rns_path()}
        if behavioral_impl == "reference"
        else {}
    )
    client = BridgeClient(cmd, env=env)
    harness = _BehavioralHarness(client)
    try:
        yield harness
    finally:
        # Run harness.cleanup() first to stop any remaining instances on
        # the bridge side before we close the pipe. Tests typically call
        # cleanup themselves in a finally, but doing it here too makes
        # sure a test that raises before reaching its finally still
        # tears down cleanly.
        try:
            harness.cleanup()
        except Exception:
            pass
        client.close()


class _BehavioralHarness:
    def __init__(self, bridge):
        self.bridge = bridge
        self._handles = []

    def start(self, identity_seed_hex=None, enable_transport=True,
              announce_rate_target=None, announce_rate_grace=None,
              announce_rate_penalty=None, announce_cap=None, bitrate=None,
              connected_to_shared_instance=False):
        if identity_seed_hex is None:
            identity_seed_hex = secrets.token_bytes(64).hex()
        kwargs = {}
        # Flip the shared-instance predicate (Transport.owner.is_connected_to_
        # shared_instance) so the packet_filter / add_packet_hash short-circuits
        # at Transport.py:1337/:1376 are reachable. Default False keeps the
        # standalone-master posture for every existing test.
        if connected_to_shared_instance:
            kwargs["connected_to_shared_instance"] = True
        # Only forward throttle knobs that were explicitly set, so the bridge
        # keeps its "off by default" posture for unset values.
        if announce_rate_target is not None:
            kwargs["announce_rate_target"] = announce_rate_target
        if announce_rate_grace is not None:
            kwargs["announce_rate_grace"] = announce_rate_grace
        if announce_rate_penalty is not None:
            kwargs["announce_rate_penalty"] = announce_rate_penalty
        if announce_cap is not None:
            kwargs["announce_cap"] = announce_cap
        if bitrate is not None:
            kwargs["bitrate"] = bitrate
        resp = self.bridge.execute(
            "behavioral_start",
            identity_seed=identity_seed_hex,
            enable_transport=enable_transport,
            **kwargs,
        )
        handle = resp["handle"]
        self._handles.append(handle)
        return Instance(self.bridge, handle, bytes.fromhex(resp["identity_hash"]))

    def cleanup(self):
        for h in self._handles:
            try:
                self.bridge.execute("behavioral_stop", handle=h)
            except Exception:
                pass


class Instance:
    def __init__(self, bridge, handle, identity_hash):
        self.bridge = bridge
        self.handle = handle
        self.identity_hash = identity_hash

    def attach_mock_interface(self, name, mode="FULL", mtu=500,
                              local_client=False,
                              announce_rate_target=None, announce_rate_grace=None,
                              announce_rate_penalty=None, announce_cap=None,
                              bitrate=None):
        """Attach a MockInterface. With local_client=True the interface is
        registered as a local-client interface behind a shared-instance master
        (parent is_local_shared_instance=True, child appended to
        Transport.local_client_interfaces), so Transport.is_local_client_interface
        returns True for it — the topology used by the hop-0 / shared-instance
        rules (R1/R4/R5, PLAIN fanout, proof_for_local_client)."""
        kwargs = {}
        # Forward only explicitly-set knobs; unset ones fall back to the
        # instance defaults captured at behavioral_start (themselves "off").
        if local_client:
            kwargs["local_client"] = True
        if announce_rate_target is not None:
            kwargs["announce_rate_target"] = announce_rate_target
        if announce_rate_grace is not None:
            kwargs["announce_rate_grace"] = announce_rate_grace
        if announce_rate_penalty is not None:
            kwargs["announce_rate_penalty"] = announce_rate_penalty
        if announce_cap is not None:
            kwargs["announce_cap"] = announce_cap
        if bitrate is not None:
            kwargs["bitrate"] = bitrate
        resp = self.bridge.execute(
            "behavioral_attach_mock_interface",
            handle=self.handle, name=name, mode=mode, mtu=mtu, **kwargs,
        )
        return resp["iface_id"]

    def attach_ifac_interface(self, name, ifac_netname=None, ifac_netkey=None,
                              ifac_size=None, mode="FULL", mtu=500):
        """Attach a MockInterface with IFAC (Interface Access Codes) configured
        from a network name + passphrase, exactly as RNS._add_interface derives
        ifac_identity/ifac_key/ifac_size for a real interface
        (Reticulum.py:1060-1078). Returns the full {iface_id, interface_hash,
        ifac_size} dict so the test can size the access-code field. See
        behavioral_attach_mock_interface (ifac_netname/ifac_netkey/ifac_size)."""
        kwargs = {"handle": self.handle, "name": name, "mode": mode, "mtu": mtu}
        if ifac_netname is not None:
            kwargs["ifac_netname"] = ifac_netname
        if ifac_netkey is not None:
            kwargs["ifac_netkey"] = ifac_netkey
        if ifac_size is not None:
            kwargs["ifac_size"] = ifac_size
        return self.bridge.execute("behavioral_attach_mock_interface", **kwargs)

    def ifac_mask(self, iface_id, raw):
        """IFAC-mask `raw` (a genuine unmasked packet) for `iface_id` via real
        RNS.Transport.transmit and return the on-wire masked bytes. See
        behavioral_ifac_mask."""
        resp = self.bridge.execute(
            "behavioral_ifac_mask",
            handle=self.handle, iface_id=iface_id, raw=raw.hex(),
        )
        return bytes.fromhex(resp["masked"])

    def inbound_remembered(self, iface_id, raw):
        """Run the FULL Transport.inbound on `raw` arriving at `iface_id` and
        report {hashlist_before, hashlist_after, hashlist_grew, unpackable,
        packet_hash, in_hashlist} — i.e. whether the packet's hash was recorded
        in Transport.packet_hashlist (observing the IFAC gate + the link-table /
        LRPROOF inbound deferrals). See behavioral_inbound_remembered."""
        return self.bridge.execute(
            "behavioral_inbound_remembered",
            handle=self.handle, iface_id=iface_id, raw=raw.hex(),
        )

    def seed_link_table(self, dest, nh_iface_id, rcvd_iface_id,
                        rem_hops=99, hops=99):
        """Install a correctly-shaped Transport.link_table[dest] entry so the
        inbound link-table deferral (Transport.py:1496-1498) can be exercised
        on a single injected packet. See behavioral_seed_link_table."""
        return self.bridge.execute(
            "behavioral_seed_link_table",
            handle=self.handle, dest=dest.hex(),
            nh_iface_id=nh_iface_id, rcvd_iface_id=rcvd_iface_id,
            rem_hops=rem_hops, hops=hops,
        )

    def inject(self, iface_id, raw):
        self.bridge.execute(
            "behavioral_inject",
            handle=self.handle, iface_id=iface_id, raw=raw.hex(),
        )

    def drain_tx(self, iface_id):
        resp = self.bridge.execute(
            "behavioral_drain_tx",
            handle=self.handle, iface_id=iface_id,
        )
        return [bytes.fromhex(p) for p in resp["packets"]]

    def read_path_table(self, dest):
        """Return this Transport's path_table entry for `dest` (bytes) as a
        decomposed dict, or {'found': False} if absent. See
        behavioral_read_path_table in reference/behavioral_transport.py."""
        return self.bridge.execute(
            "behavioral_read_path_table",
            handle=self.handle, dest=dest.hex(),
        )

    def packet_filter(self, raw, remember=True):
        """Run `raw` (bytes) through RNS's duplicate/replay filter and report
        {accepted, packet_hash, remembered}. With remember=True an accepted
        packet's hash is recorded, so a subsequent identical packet is dropped
        (accepted=False) — the hashlist replay drop. Accepts arbitrary raw
        packets (HEADER_2-with-transport_id, PLAIN, GROUP, context-tagged)."""
        return self.bridge.execute(
            "behavioral_packet_filter",
            handle=self.handle, raw=raw.hex(), remember=remember,
        )

    def read_reverse_table(self, dest=None):
        """Read Transport.reverse_table. With `dest` (bytes; a reverse-table key
        = the forwarded packet's truncated hash) return that single entry's
        {found, received_if, outbound_if, ...}; without it return
        {entries: [...]} listing every reverse entry so the test can discover
        the truncated-hash key to build its PROOF against. received_if/outbound_if
        are the iface_id the test attached. See behavioral_read_reverse_table."""
        kwargs = {"handle": self.handle}
        if dest is not None:
            kwargs["dest"] = dest.hex()
        return self.bridge.execute("behavioral_read_reverse_table", **kwargs)

    def read_announce_table(self, dest):
        """Read Transport.announce_table[dest] (bytes) as a decomposed dict, or
        {'found': False} if absent. Surfaces retries/hops for the local-rebroadcast
        retransmit state machine. See behavioral_read_announce_table."""
        return self.bridge.execute(
            "behavioral_read_announce_table", handle=self.handle, dest=dest.hex(),
        )

    def read_tunnels(self):
        """Read Transport.tunnels as {tunnels: [{tunnel_id, interface_hash,
        interface_id, expires, num_paths}]}. See behavioral_read_tunnels."""
        return self.bridge.execute("behavioral_read_tunnels", handle=self.handle)

    def synthesize_tunnel(self, iface_id):
        """Emit a tunnel-synthesize packet on `iface_id` (drainable via
        drain_tx). Returns {iface_id, tunnel_id} with the locally-computed
        tunnel_id == full_hash(pubkey||iface_hash). See
        behavioral_synthesize_tunnel."""
        return self.bridge.execute(
            "behavioral_synthesize_tunnel", handle=self.handle, iface_id=iface_id,
        )

    def set_path_timestamp(self, dest, timestamp):
        """Set path_table[dest][timestamp] (epoch seconds). Rewind into the past
        then call force_cull for deterministic, sleep-free path-expiry eviction.
        See behavioral_set_path_timestamp."""
        return self.bridge.execute(
            "behavioral_set_path_timestamp",
            handle=self.handle, dest=dest.hex(), timestamp=timestamp,
        )

    def set_announce_timestamp(self, dest, retransmit_timeout=None, timestamp=None):
        """Age an announce_table[dest] entry by setting its retransmit_timeout
        and/or timestamp. Combined with force_cull, fires a retransmit
        deterministically without real sleeps. See
        behavioral_set_announce_timestamp."""
        kwargs = {"handle": self.handle, "dest": dest.hex()}
        if retransmit_timeout is not None:
            kwargs["retransmit_timeout"] = retransmit_timeout
        if timestamp is not None:
            kwargs["timestamp"] = timestamp
        return self.bridge.execute("behavioral_set_announce_timestamp", **kwargs)

    def force_cull(self):
        """Run Transport.jobs() once with the table-cull and announce-retransmit
        time gates rewound, so culling/retransmit happen synchronously with no
        real sleep. See behavioral_force_cull."""
        return self.bridge.execute("behavioral_force_cull", handle=self.handle)

    def detach_interface(self, iface_id):
        """Detach `iface_id` and remove it from Transport.interfaces (and
        local_client_interfaces). Enables the path-table missing-interface
        eviction test. See behavioral_detach_interface."""
        return self.bridge.execute(
            "behavioral_detach_interface", handle=self.handle, iface_id=iface_id,
        )
