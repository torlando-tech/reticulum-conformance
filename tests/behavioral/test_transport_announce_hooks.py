"""
Behavioral conformance tests for additional Transport announce-intake rules.

These close gaps the rest of the suite leaves open around the announce path in
RNS Transport.py:

  * the local-destination announce carve-out (route-hijack defense),
  * the inbound announce-rate limiter state machine,
  * the larger-hop path-replacement branches (expired path / equal-emission +
    unresponsive),
  * the path-request wire format emitted by the impl's own Transport.request_path,
  * the blackholed-identity announce drop.

Every test drives the REAL RNS.Transport.inbound / request_path / blackhole path
through the behavioral bridge and asserts on observables (path_table /
announce_table / announce_rate_table / drained wire bytes). No transport logic is
reimplemented in the harness.

Each rule is anchored on an INDEPENDENT value — a spec literal read from RNS
source, a wire hop count the test itself injected, or a penalty value derived
from the rate knobs the test set — never impl-vs-itself, and is checked
positively AND negatively.
"""

import secrets
import time

import pytest

from conformance import conformance_case
from tests.behavioral import packet_builders as pb
from tests.behavioral.packet_builders import (
    CONTEXT_PATH_RESPONSE,
    DESTINATION_TYPE_PLAIN,
    HEADER_1,
    PACKET_TYPE_ANNOUNCE,
    PACKET_TYPE_DATA,
    PATH_REQUEST_DESTINATION_NAME,
    TRANSPORT_BROADCAST,
    TRUNCATED_HASH_BYTES,
    build_announce_from_destination,
    parse_packet_header,
)


__category_title__ = "Transport Announce Hooks"
__category_order__ = 20


# RNS spec literals, verified against the installed RNS 1.3.1 source:
_MAX_RATE_TIMESTAMPS = 16  # Transport.MAX_RATE_TIMESTAMPS (Transport.py:96)
_IDENTITY_HASH_BYTES = 16  # Reticulum.TRUNCATED_HASHLENGTH//8


# ---------------------------------------------------------------------------
# local-destination-announce-ignored: an announce whose destination_hash is a
# destination registered LOCALLY on this node is NOT processed into the path or
# announce tables — the route-hijack defense (Transport.py:1707-1712, the
# `local_destination == None` guard before any announce processing).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "register_destination",
              "announce_build", "inject", "read_path_table",
              "read_announce_table"],
    verifies=(
        "An ANNOUNCE whose destination_hash equals a destination registered "
        "locally on this node (present in Transport.destinations_map) is dropped "
        "by Transport.inbound BEFORE any processing (Transport.py:1707-1712 "
        "local_destination carve-out): it creates NO path_table entry and NO "
        "announce_table retransmit entry, defending against a peer trying to "
        "hijack the route to one of our own destinations. A byte-identical-shape "
        "announce for a DIFFERENT, non-local destination IS processed (path entry "
        "at hops==1), proving the drop is the local-destination guard and not a "
        "vacuous 'announce never processed'."
    ),
)
def test_local_destination_announce_ignored(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        # Register a local IN/SINGLE destination, then build an announce for the
        # SAME identity+app+aspects so its dest_hash equals the registered one.
        local_priv = secrets.token_bytes(64)
        local_dest = inst.register_destination(
            app_name="testapp", aspects=["localdest"], identity_seed=local_priv,
        )
        ann_raw, ann_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=local_priv,
            app_name="testapp", aspects=["localdest"],
            emission_ts=1_000_000_100, wire_hops=0,
        )
        assert ann_dest == local_dest, (
            "announce dest_hash must equal the registered local destination hash "
            "for this test to exercise the carve-out"
        )

        inst.inject(iface, ann_raw)
        time.sleep(0.2)

        assert inst.read_path_table(local_dest)["found"] is False, (
            "an announce for a LOCAL destination created a path_table entry — the "
            "local-destination carve-out is absent (Transport.py:1707-1712)"
        )
        assert inst.read_announce_table(local_dest)["found"] is False, (
            "an announce for a LOCAL destination was scheduled for rebroadcast — "
            "it must be dropped before reaching the announce_table"
        )

        # Positive control: an announce for a NON-local destination IS learned,
        # so the negatives above are the carve-out at work.
        ext_priv = secrets.token_bytes(64)
        ext_raw, ext_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=ext_priv,
            app_name="testapp", aspects=["externaldest"],
            emission_ts=1_000_000_101, wire_hops=0,
        )
        assert ext_dest != local_dest
        inst.inject(iface, ext_raw)
        time.sleep(0.2)
        pt = inst.read_path_table(ext_dest)
        assert pt["found"] and pt["hops"] == 1, (
            f"a non-local announce was NOT learned (got {pt}) — the drop "
            f"assertions above would be vacuous"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# announce-rate-limiting: an inbound announce on a rate-limited interface drives
# the Transport.announce_rate_table state machine (Transport.py:1830-1860): a
# grace-counter that blocks once rate_violations exceeds the grace, a
# blocked_until = last + rate_target + rate_penalty penalty window, a
# MAX_RATE_TIMESTAMPS=16 sliding cap, and the PATH_RESPONSE exemption.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_announce_rate", "read_path_table"],
    verifies=(
        "On an interface with announce_rate_target set, repeated should-add "
        "announces for one destination drive Transport.announce_rate_table "
        "(Transport.py:1830-1860): with grace=0 the SECOND announce trips a "
        "violation (rate_violations==1) and sets blocked_until exactly "
        "last + rate_target + rate_penalty (independently derived from the knobs "
        "the test set: 60 + 120 = 180 s), and the per-destination timestamps list "
        "is capped at MAX_RATE_TIMESTAMPS=16 (not the 20 announces injected). A "
        "rate-blocked announce STILL updates the path table (the block only "
        "suppresses rebroadcast). A PATH_RESPONSE-context announce is EXEMPT from "
        "rate limiting and creates NO rate-table entry, while a same-shaped "
        "non-PATH_RESPONSE announce does — proving the exemption is real."
    ),
)
def test_announce_rate_limiting(behavioral, behavioral_impl):
    if behavioral_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#announce-rate-state-machine: "
            "rate_violations/blocked_until/MAX_RATE_TIMESTAMPS announce-rate "
            "state machine + per-interface knobs unported. "
            "Refs Transport.py:1830-1860."
        )
    RATE_TARGET = 60
    RATE_PENALTY = 120
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface(
            "a", mode="FULL",
            announce_rate_target=RATE_TARGET, announce_rate_grace=0,
            announce_rate_penalty=RATE_PENALTY,
        )

        priv = secrets.token_bytes(64)
        TOTAL = 20
        dest = None
        for i in range(TOTAL):
            raw, dest, _ = build_announce_from_destination(
                behavioral.bridge,
                identity_private_key=priv,
                app_name="testapp", aspects=["ratelim"],
                emission_ts=1_000_000_000 + i,  # strictly newer -> each should-add
                wire_hops=0,
            )
            inst.inject(iface, raw)  # Transport.inbound is synchronous
        time.sleep(0.2)

        rate = inst.read_announce_rate(dest)
        assert rate["found"] is True, (
            "no announce_rate_table entry was created on a rate-limited interface"
        )
        assert rate["rate_violations"] == 1, (
            f"rate_violations={rate['rate_violations']} != 1 — with grace=0 the "
            f"second announce should trip exactly one violation then stay blocked "
            f"(Transport.py:1849-1858)"
        )
        assert len(rate["timestamps"]) == _MAX_RATE_TIMESTAMPS, (
            f"announce_rate timestamps list has {len(rate['timestamps'])} entries "
            f"after {TOTAL} announces — must be capped at MAX_RATE_TIMESTAMPS="
            f"{_MAX_RATE_TIMESTAMPS} (Transport.py:1846)"
        )
        penalty_window = rate["blocked_until"] - rate["last"]
        assert abs(penalty_window - (RATE_TARGET + RATE_PENALTY)) < 0.01, (
            f"blocked_until - last = {penalty_window} != rate_target + "
            f"rate_penalty = {RATE_TARGET + RATE_PENALTY} (Transport.py:1854)"
        )

        # A rate-blocked announce still updates the path table.
        pt = inst.read_path_table(dest)
        assert pt["found"] and pt["hops"] == 1, (
            f"a rate-blocked destination has no/incorrect path entry (got {pt}) — "
            f"the rate block must suppress only rebroadcast, not path learning"
        )

        # PATH_RESPONSE exemption: a PATH_RESPONSE-context announce for a fresh
        # destination creates NO rate entry, while a same-shaped non-PATH_RESPONSE
        # one does. Each control runs on its OWN fresh rate-limited interface so
        # the preceding 20-announce burst's per-interface ingress limiting (which
        # would hold a new unknown-destination announce, Transport.py:1699-1701)
        # cannot confound the comparison.
        iface_pr = inst.attach_mock_interface(
            "pr", mode="FULL",
            announce_rate_target=RATE_TARGET, announce_rate_grace=0,
            announce_rate_penalty=RATE_PENALTY,
        )
        iface_ctrl = inst.attach_mock_interface(
            "ctrl", mode="FULL",
            announce_rate_target=RATE_TARGET, announce_rate_grace=0,
            announce_rate_penalty=RATE_PENALTY,
        )
        pr_priv = secrets.token_bytes(64)
        pr_raw, pr_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=pr_priv,
            app_name="testapp", aspects=["ratelim-pr"],
            emission_ts=1_000_000_500, wire_hops=0,
            context=CONTEXT_PATH_RESPONSE,
        )
        inst.inject(iface_pr, pr_raw)
        time.sleep(0.1)
        assert inst.read_announce_rate(pr_dest)["found"] is False, (
            "a PATH_RESPONSE announce created an announce_rate_table entry — it "
            "must be exempt from rate limiting (Transport.py:1851)"
        )
        # ...while a same-shaped NON-PATH_RESPONSE announce for a fresh dest does.
        ctrl_priv = secrets.token_bytes(64)
        ctrl_raw, ctrl_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=ctrl_priv,
            app_name="testapp", aspects=["ratelim-ctrl"],
            emission_ts=1_000_000_501, wire_hops=0,
        )
        inst.inject(iface_ctrl, ctrl_raw)
        time.sleep(0.1)
        assert inst.read_announce_rate(ctrl_dest)["found"] is True, (
            "a non-PATH_RESPONSE announce did not create a rate-table entry — the "
            "exemption assertion above would be vacuous"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# path-replace-more-hops (branch a): a larger-hop announce REPLACES an existing
# path only when the existing path has expired (Transport.py:1785-1801): an
# announce with a novel random_blob and more hops is accepted once
# now >= path_expires, otherwise rejected.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_path_table", "set_path_expires"],
    verifies=(
        "A larger-hop announce REPLACES an existing path-table entry only when "
        "the stored path has expired (Transport.py:1789-1801). With a learned "
        "path at hops==1, a second announce at hops==3 (wire_hops=2) with an "
        "OLDER emission is REJECTED while the path is unexpired (hops stays 1). "
        "After rewinding the entry's EXPIRES field into the past (now >= "
        "path_expires), re-injecting that same larger-hop announce (novel "
        "random_blob) IS accepted and the path is replaced to hops==3 — proving "
        "expiry is the deciding factor."
    ),
)
def test_path_replace_expired_path_larger_hops(behavioral):
    # Transport disabled: path learning still runs, no retransmit churn.
    inst = behavioral.start(enable_transport=False)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        priv = secrets.token_bytes(64)

        a_raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="testapp", aspects=["replace-a"],
            emission_ts=1_000_001_000, wire_hops=0,  # -> reception hops 1
        )
        inst.inject(iface, a_raw)
        time.sleep(0.1)
        assert inst.read_path_table(dest)["hops"] == 1

        # Larger hops (reception 3), OLDER emission, path NOT expired -> rejected.
        b_raw, b_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="testapp", aspects=["replace-a"],
            emission_ts=1_000_000_999, wire_hops=2,
        )
        assert b_dest == dest
        inst.inject(iface, b_raw)
        time.sleep(0.1)
        assert inst.read_path_table(dest)["hops"] == 1, (
            "a larger-hop, older-emission announce replaced an UNEXPIRED path — "
            "the expiry guard at Transport.py:1789 is absent"
        )

        # Expire the path, then re-inject the same larger-hop announce -> accepted.
        inst.set_path_expires(dest, 1.0)  # epoch 1s, far in the past
        inst.inject(iface, b_raw)
        time.sleep(0.1)
        assert inst.read_path_table(dest)["hops"] == 3, (
            "a larger-hop announce with a novel blob was NOT accepted after the "
            "path expired (Transport.py:1795-1801)"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# path-replace-more-hops (branch c): a larger-hop announce with an emission
# EQUAL to the stored path's is accepted only when the existing path was marked
# unresponsive (Transport.py:1818-1823).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_path_table", "mark_path_unresponsive"],
    verifies=(
        "A larger-hop announce whose emission timestamp EQUALS the stored path's "
        "is accepted only when the existing path was previously marked "
        "unresponsive (Transport.py:1818-1823 path_is_unresponsive). With a "
        "learned path at hops==1, a second announce at hops==3 with the SAME "
        "emission_ts is REJECTED (hops stays 1) while the path is responsive; "
        "after Transport.mark_path_unresponsive, re-injecting that same announce "
        "IS accepted and the path is replaced to hops==3."
    ),
)
def test_path_replace_equal_emission_unresponsive(behavioral):
    inst = behavioral.start(enable_transport=False)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        priv = secrets.token_bytes(64)
        EMISSION = 1_000_002_000

        a_raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="testapp", aspects=["replace-c"],
            emission_ts=EMISSION, wire_hops=0,  # -> reception hops 1
        )
        inst.inject(iface, a_raw)
        time.sleep(0.1)
        assert inst.read_path_table(dest)["hops"] == 1

        # Larger hops (reception 3), SAME emission, path responsive -> rejected.
        b_raw, b_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="testapp", aspects=["replace-c"],
            emission_ts=EMISSION, wire_hops=2,
        )
        assert b_dest == dest
        inst.inject(iface, b_raw)
        time.sleep(0.1)
        assert inst.read_path_table(dest)["hops"] == 1, (
            "an equal-emission larger-hop announce replaced a RESPONSIVE path — "
            "the unresponsive guard at Transport.py:1818-1823 is absent"
        )

        # Mark the path unresponsive, then re-inject -> accepted.
        assert inst.mark_path_unresponsive(dest)["marked"] is True
        inst.inject(iface, b_raw)
        time.sleep(0.1)
        assert inst.read_path_table(dest)["hops"] == 3, (
            "an equal-emission larger-hop announce was NOT accepted after the "
            "path was marked unresponsive (Transport.py:1820-1823)"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# path-request-wire-format: the impl's OWN Transport.request_path emits a PLAIN
# DATA broadcast packet to the rnstransport.path.request control destination,
# with payload dest [|| transport_id] || tag (transport_id present only when
# transport is enabled). Transport.py:2769-2812.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "request_path", "drain_tx",
              "packet_unpack", "name_hash", "truncated_hash"],
    verifies=(
        "Transport.request_path on a TRANSPORT-ENABLED node emits a PLAIN "
        "(destination_type==2) DATA (packet_type==0) HEADER_1 BROADCAST packet "
        "addressed to the rnstransport.path.request control destination "
        "(address independently derived as truncated_hash(name_hash(name))), "
        "carrying a 48-byte payload == requested_dest(16) || "
        "Transport.identity.hash(16) || tag(16) (Transport.py:2783). The wire "
        "destination, the dest field of the payload, the embedded transport "
        "identity hash, and the supplied 16-byte tag all match independently."
    ),
)
def test_path_request_wire_format_transport_enabled(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        target = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        tag = secrets.token_bytes(TRUNCATED_HASH_BYTES)

        used_tag = inst.request_path(iface, target, tag=tag)
        assert used_tag == tag
        time.sleep(0.1)
        packets = inst.drain_tx(iface)
        assert len(packets) == 1, (
            f"request_path emitted {len(packets)} packets on the interface, "
            f"expected exactly one"
        )
        hdr = parse_packet_header(packets[0])
        assert hdr["header_type"] == HEADER_1
        assert hdr["destination_type"] == DESTINATION_TYPE_PLAIN
        assert hdr["packet_type"] == PACKET_TYPE_DATA
        assert hdr["transport_type"] == TRANSPORT_BROADCAST

        pr_dest = pb._plain_destination_hash(
            behavioral.bridge, PATH_REQUEST_DESTINATION_NAME
        )
        assert hdr["destination_hash"] == pr_dest, (
            "path request is not addressed to the rnstransport.path.request "
            "control destination"
        )

        payload = hdr["data"]
        assert len(payload) == 3 * TRUNCATED_HASH_BYTES, (
            f"transport-enabled path-request payload is {len(payload)} bytes, "
            f"expected 48 (dest + transport_id + tag) (Transport.py:2783)"
        )
        assert payload[:TRUNCATED_HASH_BYTES] == target, (
            "path-request payload does not start with the requested dest hash"
        )
        assert payload[TRUNCATED_HASH_BYTES:2 * TRUNCATED_HASH_BYTES] == inst.identity_hash, (
            "transport-enabled path-request omits the requesting transport "
            "identity hash (Transport.py:2783)"
        )
        assert payload[2 * TRUNCATED_HASH_BYTES:] == tag, (
            "path-request payload does not end with the supplied tag"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "request_path", "drain_tx",
              "packet_unpack", "name_hash", "truncated_hash"],
    verifies=(
        "Transport.request_path on a TRANSPORT-DISABLED node omits the transport "
        "identity hash: it emits a PLAIN DATA broadcast to the "
        "rnstransport.path.request destination with a 32-byte payload == "
        "requested_dest(16) || tag(16) only (Transport.py:2784). The shorter "
        "payload (32 vs the transport-enabled 48) is the discriminating "
        "observable for the transport_id presence rule."
    ),
)
def test_path_request_wire_format_transport_disabled(behavioral):
    inst = behavioral.start(enable_transport=False)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        target = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        tag = secrets.token_bytes(TRUNCATED_HASH_BYTES)

        inst.request_path(iface, target, tag=tag)
        time.sleep(0.1)
        packets = inst.drain_tx(iface)
        assert len(packets) == 1
        hdr = parse_packet_header(packets[0])
        assert hdr["destination_type"] == DESTINATION_TYPE_PLAIN
        assert hdr["packet_type"] == PACKET_TYPE_DATA

        pr_dest = pb._plain_destination_hash(
            behavioral.bridge, PATH_REQUEST_DESTINATION_NAME
        )
        assert hdr["destination_hash"] == pr_dest

        payload = hdr["data"]
        assert len(payload) == 2 * TRUNCATED_HASH_BYTES, (
            f"transport-disabled path-request payload is {len(payload)} bytes, "
            f"expected 32 (dest + tag, NO transport_id) (Transport.py:2784)"
        )
        assert payload[:TRUNCATED_HASH_BYTES] == target
        assert payload[TRUNCATED_HASH_BYTES:] == tag
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# blackholed-identity-announce-drop: an announce from a blackholed identity is
# invalidated and dropped in Identity.validate_announce (Identity.py:567-569),
# so it creates no path entry.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "identity_from_private_key",
              "blackhole_identity", "announce_build", "inject",
              "read_path_table"],
    verifies=(
        "After Transport.blackhole_identity records an identity hash, an announce "
        "from that identity is invalidated and dropped inside "
        "Identity.validate_announce (Identity.py:567-569): it creates NO "
        "path_table entry. An announce from a DIFFERENT, non-blackholed identity "
        "injected the same way IS learned (path entry at hops==1), proving the "
        "drop is the blackhole gate and not a vacuous 'announce never learned'."
    ),
)
def test_blackholed_identity_announce_dropped(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        bad_priv = secrets.token_bytes(64)
        bad_id_hash = bytes.fromhex(
            behavioral.bridge.execute(
                "identity_from_private_key", private_key=bad_priv.hex()
            )["hash"]
        )
        assert len(bad_id_hash) == _IDENTITY_HASH_BYTES
        assert inst.blackhole_identity(bad_id_hash)["blackholed"] is True

        bad_raw, bad_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=bad_priv,
            app_name="testapp", aspects=["blackholed"],
            emission_ts=1_000_003_000, wire_hops=0,
        )
        inst.inject(iface, bad_raw)
        time.sleep(0.2)
        assert inst.read_path_table(bad_dest)["found"] is False, (
            "an announce from a blackholed identity created a path entry — the "
            "blackhole gate in Identity.validate_announce is absent "
            "(Identity.py:567-569)"
        )

        # Positive control: a non-blackholed identity's announce is learned.
        good_priv = secrets.token_bytes(64)
        good_raw, good_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=good_priv,
            app_name="testapp", aspects=["not-blackholed"],
            emission_ts=1_000_003_001, wire_hops=0,
        )
        inst.inject(iface, good_raw)
        time.sleep(0.2)
        pt = inst.read_path_table(good_dest)
        assert pt["found"] and pt["hops"] == 1, (
            f"a non-blackholed announce was NOT learned (got {pt}) — the drop "
            f"assertion above would be vacuous"
        )
    finally:
        behavioral.cleanup()
