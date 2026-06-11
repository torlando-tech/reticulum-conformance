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

    def read_link_table(self, link_id=None):
        """Read Transport.link_table. With `link_id` (bytes) return that single
        entry's decomposed dict {found, timestamp, next_hop_transport_id,
        next_hop_if, remaining_hops, received_if, hops, destination_hash,
        validated, proof_timeout}; without it return {entries: [...]} listing
        every link entry. See behavioral_read_link_table."""
        kwargs = {"handle": self.handle}
        if link_id is not None:
            kwargs["link_id"] = link_id.hex()
        return self.bridge.execute("behavioral_read_link_table", **kwargs)

    def hold_and_release_announce(self, iface_id, announces):
        """Hold a set of real announce packets on the interface's ingress-control
        queue and run ONE release pass; returns {held_before, held_after,
        released, hops} (dest_hash hex). See
        behavioral_hold_and_release_announce — exposes the lowest-hops-first
        release decision (Interface.process_held_announces)."""
        return self.bridge.execute(
            "behavioral_hold_and_release_announce",
            handle=self.handle,
            iface_id=iface_id,
            announces=[a.hex() if isinstance(a, (bytes, bytearray)) else a
                       for a in announces],
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

    def register_destination(self, app_name, aspects, identity_seed):
        """Register a real local IN/SINGLE destination from a 64-byte Identity
        private key, so its hash enters Transport.destinations_map (the local-
        destination announce carve-out, Transport.py:1707-1712). Returns the
        destination hash as bytes. See behavioral_register_destination."""
        resp = self.bridge.execute(
            "behavioral_register_destination",
            handle=self.handle, app_name=app_name, aspects=list(aspects),
            identity_seed=identity_seed.hex(),
        )
        return bytes.fromhex(resp["destination_hash"])

    def register_announce_handler(self, aspect_filter=None,
                                  receive_path_responses=None, num_params=3,
                                  raise_on_call=False, omit_aspect_filter=False):
        """Register a real recording announce handler on this Transport via
        RNS.Transport.register_announce_handler. Returns {handler_id, registered}.
        The handler records every (destination_hash, announced_identity, app_data
        [, announce_packet_hash]) RNS dispatches to it; read them back with
        read_announce_handler_calls. See behavioral_register_announce_handler."""
        kwargs = {"handle": self.handle, "num_params": num_params}
        if aspect_filter is not None:
            kwargs["aspect_filter"] = aspect_filter
        if receive_path_responses is not None:
            kwargs["receive_path_responses"] = receive_path_responses
        if raise_on_call:
            kwargs["raise_on_call"] = True
        if omit_aspect_filter:
            kwargs["omit_aspect_filter"] = True
        return self.bridge.execute("behavioral_register_announce_handler", **kwargs)

    def read_announce_handler_calls(self, handler_id):
        """Return {calls: [...], registered} for a recording announce handler.
        See behavioral_read_announce_handler_calls."""
        return self.bridge.execute(
            "behavioral_read_announce_handler_calls",
            handle=self.handle, handler_id=handler_id,
        )

    def read_announce_rate(self, dest):
        """Read Transport.announce_rate_table[dest] (bytes) as {found, last,
        rate_violations, blocked_until, timestamps[]} or {'found': False}. See
        behavioral_read_announce_rate."""
        return self.bridge.execute(
            "behavioral_read_announce_rate", handle=self.handle, dest=dest.hex(),
        )

    def set_path_expires(self, dest, expires):
        """Set path_table[dest][IDX_PT_EXPIRES] (epoch seconds). Rewind into the
        past to make `now >= path_expires` for the larger-hop expired-path
        replacement branch (Transport.py:1789). See behavioral_set_path_expires."""
        return self.bridge.execute(
            "behavioral_set_path_expires",
            handle=self.handle, dest=dest.hex(), expires=expires,
        )

    def mark_path_unresponsive(self, dest):
        """Mark path_table[dest] unresponsive via real
        Transport.mark_path_unresponsive (Transport.py:2719). Returns the
        command result {'marked': bool}. See behavioral_mark_path_unresponsive."""
        return self.bridge.execute(
            "behavioral_mark_path_unresponsive", handle=self.handle, dest=dest.hex(),
        )

    def request_path(self, iface_id, dest, tag=None):
        """Drive real Transport.request_path(dest, on_interface=iface, tag=tag);
        the emitted path-request packet is drainable via drain_tx(iface_id).
        Returns the request tag actually used (bytes). See
        behavioral_request_path."""
        kwargs = {"handle": self.handle, "iface_id": iface_id, "dest": dest.hex()}
        if tag is not None:
            kwargs["tag"] = tag.hex()
        resp = self.bridge.execute("behavioral_request_path", **kwargs)
        return bytes.fromhex(resp["tag"])

    def blackhole_identity(self, identity_hash, until=None, reason=None):
        """Blackhole an identity via real Transport.blackhole_identity
        (Transport.py:3406). Subsequent announces from it are invalidated in
        Identity.validate_announce (Identity.py:567). Optional until/reason are
        recorded into the entry. See behavioral_blackhole_identity."""
        kwargs = {"handle": self.handle, "identity_hash": identity_hash.hex()}
        if until is not None:
            kwargs["until"] = until
        if reason is not None:
            kwargs["reason"] = reason
        return self.bridge.execute("behavioral_blackhole_identity", **kwargs)

    def unblackhole_identity(self, identity_hash):
        """Lift a blackhole via real Transport.unblackhole_identity
        (Transport.py:3431). See behavioral_unblackhole_identity."""
        return self.bridge.execute(
            "behavioral_unblackhole_identity",
            handle=self.handle, identity_hash=identity_hash.hex(),
        )

    def read_blackhole_table(self):
        """Read RNS.Transport.blackholed_identities as
        {count, entries:[{identity_hash, source, until, reason}]}. See
        behavioral_read_blackhole_table."""
        return self.bridge.execute(
            "behavioral_read_blackhole_table", handle=self.handle,
        )

    def blackhole_list_handler(self):
        """Invoke the real Transport.blackhole_list_handler (the /list
        response_generator) and return {is_blackhole_table, count, entries}.
        See behavioral_blackhole_list_handler."""
        return self.bridge.execute(
            "behavioral_blackhole_list_handler", handle=self.handle,
        )

    def blackhole_reload(self):
        """Run real Transport.reload_blackhole(); returns {count}. See
        behavioral_blackhole_reload."""
        return self.bridge.execute(
            "behavioral_blackhole_reload", handle=self.handle,
        )

    def blackhole_clear(self):
        """Empty the in-memory Transport.blackholed_identities table (not the
        on-disk storage). See behavioral_blackhole_clear."""
        return self.bridge.execute(
            "behavioral_blackhole_clear", handle=self.handle,
        )

    def blackhole_storage_files(self):
        """List <configdir>/storage/blackhole files as {dir, files:[{name,
        size}]}. See behavioral_blackhole_storage_files."""
        return self.bridge.execute(
            "behavioral_blackhole_storage_files", handle=self.handle,
        )

    def blackhole_clear_storage(self):
        """Delete all blackhole storage files; returns {removed}. See
        behavioral_blackhole_clear_storage."""
        return self.bridge.execute(
            "behavioral_blackhole_clear_storage", handle=self.handle,
        )

    def blackhole_rename_storage(self, src, dst):
        """Rename a blackhole storage file (directory entry only). See
        behavioral_blackhole_rename_storage."""
        return self.bridge.execute(
            "behavioral_blackhole_rename_storage",
            handle=self.handle, src=src, dst=dst,
        )

    def blackhole_set_sources(self, sources):
        """Replace RNS's trusted blackhole-source list with `sources` (iterable
        of identity-hash bytes); returns {count}. See
        behavioral_blackhole_set_sources."""
        return self.bridge.execute(
            "behavioral_blackhole_set_sources",
            handle=self.handle, sources=[s.hex() for s in sources],
        )
