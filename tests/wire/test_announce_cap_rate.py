"""Announce-throttle coverage: announce_cap egress spacing + announce_rate
inbound suppression (N-M9).

RNS has THREE distinct announce-throttle mechanisms. The ingress-control burst
path is covered by test_announce_burst_throttle.py; this module covers the
other two, both of which are interface-level knobs:

  * ``announce_cap`` — OUTBOUND bandwidth cap. A forwarded announce (hops > 0)
    sets ``announce_allowed_at = now + (tx_time / announce_cap)`` on the egress
    interface; further forwarded announces that arrive before that time are
    parked in ``Interface.announce_queue`` and drained one-per-spacing-interval
    by ``Interface.process_announce_queue`` (Transport.py:1248-1311,
    Interface.py:323-358). A SMALLER cap (it is a fraction of link bandwidth;
    real interfaces use Reticulum.ANNOUNCE_CAP/100 = 0.02) and/or a lower
    ``bitrate`` widen the spacing, so fewer announces egress per unit time.

  * ``announce_rate_target`` — INBOUND per-destination rate limit. When set on
    the receiving interface, ``Transport`` tracks each destination's announce
    cadence in ``announce_rate_table``; once a destination re-announces faster
    than the target more than ``announce_rate_grace`` times, its rebroadcast is
    BLOCKED (``rate_blocked``) and the announce is NOT inserted into the
    announce table for retransmission (Transport.py:1835-1906).

Neither knob is reachable through the live-TCP wire harness (it exposes no way
to set them), so this coverage is built on the behavioral MockInterface command
surface — inject raw announce bytes, drain the bytes an interface emits — which
is the only harness that exposes the throttle knobs (behavioral_start /
behavioral_attach_mock_interface, reference/behavioral_transport.py). The file
lives alongside the other announce wire tests for cataloguing; it is validated
reference-vs-reference like every other test here.
"""

import secrets
import time

import pytest

from _rns_paths import resolve_rns_path
from bridge_client import BridgeClient
from conftest import get_impl_list, resolve_command
from conformance import conformance_case
from tests.behavioral.packet_builders import (
    build_announce_from_destination,
    is_announce,
    parse_packet_header,
)


__category_title__ = "Wire Interop"
__category_order__ = 18


# Announce payload layout (no ratchet — build_announce_from_destination uses
# ratchet=None): public_key(64) + name_hash(10) + random_hash(10) + sig(64).
# Matches RNS/Destination.py and tests/behavioral/packet_builders.py.
_KEYSIZE_BYTES = 64
_NAME_HASH_BYTES = 10
_RANDOM_HASH_BYTES = 10


def pytest_generate_tests(metafunc):
    """Parametrize over the same impl list as the rest of the suite, defaulting
    to reference (so ``--reference-only`` runs exactly one parametrization).

    These tests drive the behavioral command surface directly rather than the
    wire fixtures, so they use their own impl axis instead of wire_pair /
    wire_shared_trio. The wire conftest's pytest_generate_tests is a no-op for
    them (they request none of its fixtures).
    """
    if "cap_rate_impl" in metafunc.fixturenames:
        impls = get_impl_list(metafunc.config) or ["reference"]
        metafunc.parametrize("cap_rate_impl", impls, scope="function")


@pytest.fixture
def cap_rate_impl(request):
    return request.param


class _Instance:
    """One behavioral Transport handle plus the MockInterface verbs the
    throttle tests need. Thin wrappers over the bridge command surface; method
    names mirror the bridge aliases (``start``/``inject``/``drain_tx``/...) so
    the conformance drift guard can attribute commands statically.
    """

    def __init__(self, bridge, handle):
        self.bridge = bridge
        self.handle = handle

    def attach_mock_interface(self, name, mode="FULL", mtu=500, **knobs):
        # Forward only explicitly-set throttle knobs; unset ones keep the
        # bridge's "off by default" posture.
        kwargs = {k: v for k, v in knobs.items() if v is not None}
        resp = self.bridge.execute(
            "behavioral_attach_mock_interface",
            handle=self.handle, name=name, mode=mode, mtu=mtu, **kwargs,
        )
        return resp["iface_id"]

    def inject(self, iface_id, raw):
        self.bridge.execute(
            "behavioral_inject", handle=self.handle, iface_id=iface_id, raw=raw.hex()
        )

    def drain_tx(self, iface_id):
        resp = self.bridge.execute(
            "behavioral_drain_tx", handle=self.handle, iface_id=iface_id
        )
        return [bytes.fromhex(p) for p in resp["packets"]]

    def read_path_table(self, dest):
        return self.bridge.execute(
            "behavioral_read_path_table", handle=self.handle, dest=dest.hex()
        )

    def stop(self):
        self.bridge.execute("behavioral_stop", handle=self.handle)


class _Harness:
    """Owns a bridge subprocess; starts/tears down behavioral instances.

    behavioral_start reuses a process-wide RNS singleton, and behavioral_stop
    resets Transport's in-memory tables and detaches the instance's interfaces
    (reference/behavioral_transport.py). So scenarios are run SEQUENTIALLY —
    stop one before starting the next — to keep their interfaces and path
    tables from bleeding together.
    """

    def __init__(self, bridge):
        self.bridge = bridge
        self._instances = []

    def start(self, enable_transport=True):
        resp = self.bridge.execute(
            "behavioral_start",
            identity_seed=secrets.token_bytes(64).hex(),
            enable_transport=enable_transport,
        )
        inst = _Instance(self.bridge, resp["handle"])
        self._instances.append(inst)
        return inst

    def cleanup(self):
        for inst in self._instances:
            try:
                inst.stop()
            except Exception:
                pass
        self._instances = []


@pytest.fixture
def transport(cap_rate_impl):
    """A freshly-spawned bridge driving the behavioral MockInterface harness."""
    cmd = resolve_command(cap_rate_impl)
    env = {"PYTHON_RNS_PATH": resolve_rns_path()} if cap_rate_impl == "reference" else {}
    bridge = BridgeClient(cmd, env=env)
    harness = _Harness(bridge)
    try:
        yield harness
    finally:
        try:
            harness.cleanup()
        except Exception:
            pass
        bridge.close()


def _announce_random_hash(raw):
    """The 10-byte random_hash that uniquely identifies an announce instance.

    Two announce_build calls (even for the same destination) yield distinct
    random_hashes, so this is a stable per-announce identity for telling apart
    which announce(s) an interface actually re-emitted.
    """
    data = parse_packet_header(raw)["data"]
    off = _KEYSIZE_BYTES + _NAME_HASH_BYTES
    return data[off:off + _RANDOM_HASH_BYTES]


def _emission_ts(random_hash):
    """The 5-byte big-endian emission timestamp embedded in a random_hash
    (RNS/Destination.py:1427-1434)."""
    return int.from_bytes(random_hash[5:10], "big")


def _forward_burst(harness, n, out_knobs):
    """Inject ``n`` distinct forwarded announces and report egress on the OUT
    interface configured with ``out_knobs`` (announce_cap / bitrate).

    Each announce is for a fresh destination at wire_hops=1 (so the Transport
    treats it as a hops>0 forward, subject to announce_cap on egress). Returns
    {egress: <#announces emitted on OUT within the window>,
     in_path_table: <#of the n dests learned into the path table>}.
    """
    inst = harness.start(enable_transport=True)
    try:
        iface_in = inst.attach_mock_interface("in")
        iface_out = inst.attach_mock_interface("out", **out_knobs)

        base = int(time.time())
        dests = []
        for i in range(n):
            raw, dest, _pub = build_announce_from_destination(
                harness.bridge,
                identity_private_key=secrets.token_bytes(64),
                app_name=f"cap{i}",
                aspects=["throttle"],
                wire_hops=1,
                emission_ts=base + i,
            )
            dests.append(dest)
            inst.inject(iface_in, raw)
            # Space injections so each forward lands in its own retransmit
            # round — otherwise even an un-throttled interface batches them.
            time.sleep(0.6)

        # Let the retransmit timers fire (PATHFINDER_RW ≈ 0.5 s) and any
        # un-throttled queue drain, while staying well inside a tight cap's
        # multi-second spacing window.
        time.sleep(2.0)

        egress = sum(1 for p in inst.drain_tx(iface_out) if is_announce(p))
        in_pt = sum(1 for d in dests if inst.read_path_table(d).get("found"))
        return {"egress": egress, "in_path_table": in_pt}
    finally:
        inst.stop()
        harness._instances.remove(inst)


def _rate_sequence(harness, in_knobs):
    """Inject two announces for the SAME destination (emission t0, then t0+10)
    and report which ones the OUT interface re-emitted.

    The receiving (IN) interface carries ``in_knobs`` (announce_rate_target /
    grace). Announce #2's emission timestamp is strictly later so it passes the
    path-replacement freshness gate and actually reaches the rate check. Returns
    {dest_known, e1_egressed, e2_egressed, distinct} where e1/e2 mark whether
    the t0 / t0+10 announce was re-emitted (identified by emission timestamp,
    which is robust to retransmit timing), and distinct is the number of
    distinct announces re-emitted.
    """
    inst = harness.start(enable_transport=True)
    try:
        iface_in = inst.attach_mock_interface("in", **in_knobs)
        iface_out = inst.attach_mock_interface("out")

        priv = secrets.token_bytes(64)
        base = int(time.time())
        emissions = set()

        def _drain_accumulate():
            for p in inst.drain_tx(iface_out):
                if is_announce(p):
                    emissions.add(_emission_ts(_announce_random_hash(p)))

        raw1, dest, _ = build_announce_from_destination(
            harness.bridge, identity_private_key=priv,
            app_name="rate", aspects=["throttle"], wire_hops=1, emission_ts=base,
        )
        inst.inject(iface_in, raw1)
        for _ in range(3):
            time.sleep(0.6)
            _drain_accumulate()

        raw2, dest2, _ = build_announce_from_destination(
            harness.bridge, identity_private_key=priv,
            app_name="rate", aspects=["throttle"], wire_hops=1, emission_ts=base + 10,
        )
        assert dest2 == dest, "same identity/app/aspects must hash to one destination"
        inst.inject(iface_in, raw2)
        for _ in range(3):
            time.sleep(0.6)
            _drain_accumulate()

        return {
            "dest_known": bool(inst.read_path_table(dest).get("found")),
            "e1_egressed": base in emissions,
            "e2_egressed": (base + 10) in emissions,
            "distinct": len(emissions),
        }
    finally:
        inst.stop()
        harness._instances.remove(inst)


@conformance_case(
    commands=[
        "start", "attach_mock_interface", "inject", "drain_tx",
        "read_path_table", "stop", "announce_build",
    ],
    verifies="A tight per-interface announce_cap (low fractional cap + low bitrate) spaces out forwarded-announce egress: of 4 fresh forwarded announces (all received into the path table) at most half re-emit on the capped interface within the window (one in practice) while the rest are egress-queued, whereas with no cap all four re-emit (positive control)",
)
def test_announce_cap_spaces_forwarded_announce_egress(transport):
    """announce_cap throttles OUTBOUND announce egress, not reception.

    Throttled scenario: announce_cap=0.005 with bitrate=2000 yields a per-
    announce spacing of (len*8/2000)/0.005 ≈ tens of seconds, so after the
    first forwarded announce egresses the rest sit in the interface's
    announce_queue. Un-throttled control: announce_cap=1.0 with a high bitrate
    makes the spacing negligible, so every forwarded announce egresses.

    The reception side is identical in both: all 4 destinations are learned
    into the path table regardless, proving the cap delays EGRESS rather than
    dropping or refusing the announce.
    """
    n = 4
    throttled = _forward_burst(
        transport, n, out_knobs=dict(announce_cap=0.005, bitrate=2000)
    )
    unthrottled = _forward_burst(
        transport, n, out_knobs=dict(announce_cap=1.0, bitrate=1_000_000_000)
    )

    # Reception is unaffected by the egress cap: every announce is received and
    # added to the path table in BOTH scenarios.
    assert throttled["in_path_table"] == n, (
        f"throttled: only {throttled['in_path_table']}/{n} announces reached the "
        f"path table — announce_cap must throttle egress, not reception."
    )
    assert unthrottled["in_path_table"] == n, (
        f"control: only {unthrottled['in_path_table']}/{n} announces reached the "
        f"path table."
    )

    # Positive control: announces ARE forwarded (topology alive), and WITHOUT a
    # cap every received announce re-emits within the same window — so the
    # held-back announces in the throttled run are due to announce_cap, not a
    # broken forward path.
    assert throttled["egress"] >= 1, (
        "throttled: no forwarded announce egressed at all — cannot attribute "
        "the shortfall to announce_cap if nothing forwards."
    )
    assert unthrottled["egress"] == n, (
        f"control: expected all {n} announces to egress with no cap, got "
        f"{unthrottled['egress']} — the gap below is not solely the cap's doing."
    )

    # The discriminator: a tight announce_cap spaces egress out so far fewer
    # announces leave the interface within the window than without it.
    assert throttled["egress"] < unthrottled["egress"], (
        f"announce_cap did not space egress: throttled emitted "
        f"{throttled['egress']} vs control {unthrottled['egress']}."
    )
    assert throttled["egress"] <= n // 2, (
        f"announce_cap held back fewer than half the forwarded announces: "
        f"throttled emitted {throttled['egress']}/{n}."
    )


@conformance_case(
    commands=[
        "start", "attach_mock_interface", "inject", "drain_tx",
        "read_path_table", "stop", "announce_build",
    ],
    verifies="With announce_rate_target set (grace 0) on the receiving interface, a second announce for the same destination arriving within the target window is NOT rebroadcast (only the first re-emits), whereas with no target both announces rebroadcast — inbound per-destination announce_rate suppression",
)
def test_announce_rate_suppresses_duplicate_dest_rebroadcast(transport):
    """announce_rate_target suppresses rapid same-destination rebroadcasts.

    Two announces for one destination are injected back-to-back (the second
    with a later emission timestamp so it clears the path-replacement freshness
    gate and reaches the rate check). With announce_rate_target=60 s and
    grace=0, the second trips the rate limit and is NOT rebroadcast; only the
    first re-emits. With no target, both re-emit. The announces are told apart
    by their embedded emission timestamp, so the result is independent of
    retransmit timing.
    """
    limited = _rate_sequence(
        transport, in_knobs=dict(announce_rate_target=60, announce_rate_grace=0)
    )
    free = _rate_sequence(transport, in_knobs=dict())

    # The destination is learned in both cases (announce #1 is always processed).
    assert limited["dest_known"], "rate-limited: destination was never learned"
    assert free["dest_known"], "control: destination was never learned"

    # Positive control: the FIRST announce re-emits in both cases — forwarding
    # works, so a missing second emission below is suppression, not a dead path.
    assert limited["e1_egressed"], (
        "rate-limited: even the first announce failed to rebroadcast — "
        "forwarding is broken, suppression result is vacuous."
    )
    assert free["e1_egressed"], "control: first announce failed to rebroadcast"

    # The discriminator: the second (rapid, same-dest) announce rebroadcasts
    # WITHOUT a target but is SUPPRESSED with announce_rate_target set.
    assert free["e2_egressed"], (
        "control: without announce_rate_target the second rapid same-dest "
        "announce should still rebroadcast."
    )
    assert not limited["e2_egressed"], (
        "announce_rate_target (grace 0) must suppress the rebroadcast of a "
        "second same-destination announce arriving within the target window."
    )

    # Distinct announces re-emitted: both without the limit, only the first with it.
    assert free["distinct"] == 2, (
        f"control: expected both announces to rebroadcast, got "
        f"{free['distinct']} distinct."
    )
    assert limited["distinct"] == 1, (
        f"rate-limited: expected only the first announce to rebroadcast, got "
        f"{limited['distinct']} distinct."
    )
