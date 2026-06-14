"""
Behavioral test: path-table replacement rules.

Python `Transport.py:1762-1823` admits an announce into the PATH TABLE under
strict rules:
  * a same-or-fewer-hop announce is admitted only if its random_blob is novel
    AND its emission timestamp is strictly newer than the timebase of the path
    we already hold; while
  * a MORE-hops announce is admitted only if the existing path has expired or
    the new announce was emitted more recently (still requiring a novel blob).

A stale PATH_RESPONSE — re-emitted from a cache, so it carries a *novel*
random_blob but an *older* emission timestamp and *more* hops — fails every
branch and must be rejected.

Reticulum-kt's initial port checked only random_blob novelty, which let exactly
such a stale PATH_RESPONSE overwrite a fresh direct path. This test catches that
drift by reading the PATH TABLE directly (`behavioral_read_path_table`).

Why not observe the announce_table retransmit (as an earlier version did)?
Because a PATH_RESPONSE-context announce is *never* scheduled for retransmit
(Transport.py:1884 gates the announce_table insert on `context != PATH_RESPONSE`),
so the retransmit observable could never reveal a corrupted path table — it
passed even if cross-impl path replacement was fully broken (re-audit N-H1/N-H2).
Reading the path table is the only observable that actually verifies the rule.
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    CONTEXT_PATH_RESPONSE,
    build_announce_from_destination,
    context_offset,
)


__category_title__ = "Transport Behavior"
__category_order__ = 19


def _blob_emission_ts(blob_hex: str) -> int:
    """Decode the 5-byte big-endian emission timebase from a random_hash hex
    (bytes [5:10]); mirrors RNS `Transport.timebase_from_random_blob`."""
    return int.from_bytes(bytes.fromhex(blob_hex)[5:10], "big")


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "read_path_table",
              "announce_build"],
    verifies=(
        "A stale PATH_RESPONSE announce (context byte 0x0B, novel random_blob, "
        "older emission timestamp, larger hop count) does NOT overwrite a fresh "
        "direct path in the Transport PATH TABLE: behavioral_read_path_table "
        "reports hops==1 and the retained random_blob's emission timebase "
        "unchanged from the fresh announce after the stale inject. A positive "
        "control confirms a genuinely newer-emission announce DOES replace the "
        "entry"
    ),
)
def test_stale_path_response_does_not_overwrite_fresh_path(behavioral):
    """A PATH_RESPONSE-contextual announce with an older emission timestamp and
    more hops must NOT replace a fresh direct announce in the PATH TABLE.

    Observed directly via `behavioral_read_path_table`: the surviving entry's
    hop count and random_blob emission-timebase must stay those of the fresh
    announce. A positive control then shows a legitimately newer-emission
    announce IS admitted, proving the read is live (it would have revealed the
    stale announce winning) and that the replacement rule is selective rather
    than "reject everything"."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")

        announcer_private = secrets.token_bytes(64)

        # 1. Fresh direct announce: wire_hops=0 (becomes path hops=1 after the
        #    +1-on-receive increment), with the newest emission timestamp.
        FRESH_TS = 1_000_000_100
        fresh, dest_hash, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl"],
            random_prefix=b"\xA1\xA1\xA1\xA1\xA1",
            emission_ts=FRESH_TS,
            wire_hops=0,
        )
        inst.inject(iface_a, fresh)
        time.sleep(0.2)  # path_table write is synchronous; small settle margin

        # Positive baseline: the fresh path is actually in the table at hops=1.
        # This proves the announce was processed AND gives the "unchanged"
        # assertion below a concrete reference point.
        pt_fresh = inst.read_path_table(dest_hash)
        assert pt_fresh["found"], "fresh announce did not create a path-table entry"
        assert pt_fresh["hops"] == 1, (
            f"fresh path should be 1 hop (wire 0 + receive increment), "
            f"got {pt_fresh['hops']}"
        )
        assert len(pt_fresh["random_blobs"]) == 1
        assert _blob_emission_ts(pt_fresh["random_blobs"][0]) == FRESH_TS

        # 2. Stale PATH_RESPONSE: older emission timestamp, MORE hops, a novel
        #    random_blob (as if re-emitted from a cache). RNS admits a
        #    larger-hop announce only if the path expired or the new emission is
        #    more recent — the stale one is neither, so it must be rejected. An
        #    impl that checks only random_blob novelty (the reticulum-kt drift)
        #    would wrongly accept it.
        STALE_TS = 1_000_000_050
        stale, stale_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl"],
            random_prefix=b"\xA0\xA0\xA0\xA0\xA0",
            emission_ts=STALE_TS,
            wire_hops=4,
            context=CONTEXT_PATH_RESPONSE,
        )
        assert stale_dest == dest_hash, "builder should produce same dest hash"
        # Precondition (re-audit N-H2): the builder must actually stamp the
        # PATH_RESPONSE context byte, otherwise the scenario silently degrades
        # to a plain announce and no longer tests what the name claims.
        assert stale[context_offset(stale)] == CONTEXT_PATH_RESPONSE, (
            "stale packet is not a PATH_RESPONSE: context byte "
            f"0x{stale[context_offset(stale)]:02x} != 0x{CONTEXT_PATH_RESPONSE:02x}"
        )
        inst.inject(iface_a, stale)
        time.sleep(0.2)

        # 3. The PATH TABLE entry must be unchanged — still the fresh path.
        pt_after = inst.read_path_table(dest_hash)
        assert pt_after["found"], "path entry vanished after stale inject"
        assert pt_after["hops"] == 1, (
            f"stale PATH_RESPONSE overwrote the fresh path: path-table "
            f"hops={pt_after['hops']} (expected 1=fresh; 5 would mean the stale "
            f"4-hop announce won)"
        )
        # Every retained random_blob must still encode the FRESH emission
        # timebase, never the stale one — proving the fresh announce's data
        # survived rather than the entry having been rewritten by the stale one.
        retained_ts = [_blob_emission_ts(b) for b in pt_after["random_blobs"]]
        assert all(ts == FRESH_TS for ts in retained_ts), (
            f"path table retained a non-fresh emission timebase: {retained_ts}"
        )
        assert STALE_TS not in retained_ts, (
            "path table absorbed the stale announce's emission timebase"
        )

        # 4. Positive control: a genuinely NEWER-emission announce DOES replace
        #    the entry. This proves read_path_table is live (it would have shown
        #    the change had the stale announce won) and that the replacement rule
        #    is selective, not a blanket "reject everything".
        NEWER_TS = 1_000_000_200
        newer, _, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl"],
            random_prefix=b"\xA2\xA2\xA2\xA2\xA2",
            emission_ts=NEWER_TS,
            wire_hops=2,
        )
        inst.inject(iface_a, newer)
        time.sleep(0.2)
        pt_newer = inst.read_path_table(dest_hash)
        assert pt_newer["hops"] == 3, (
            f"newer-emission announce (wire 2 + receive increment) should "
            f"replace the path at hops=3, got {pt_newer['hops']} — the path "
            f"table is not tracking valid replacements"
        )
        assert NEWER_TS in [_blob_emission_ts(b) for b in pt_newer["random_blobs"]], (
            "replacement did not record the newer announce's emission timebase"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "read_path_table",
              "announce_build"],
    verifies=(
        "Isolates the emission-time gate in the SAME-hop branch "
        "(Transport.py:1762-1769): a novel-random_blob announce with the SAME hop "
        "count as the held path but an OLDER emission timestamp does NOT replace "
        "the entry — hop count is identical, so only the emission comparison can "
        "justify rejection. A newer-emission same-hop announce then DOES replace, "
        "proving the gate admits on emission recency rather than blanket-rejecting"
    ),
)
def test_stale_same_hops_announce_does_not_overwrite_fresh_path(behavioral):
    """Companion to the more-hops case: isolates the emission-time gate where hop
    count gives no cover.

    The sibling test injects a *more*-hops stale announce, so a correct impl could
    reject it on hop count alone — it does not prove the emission comparison runs.
    Here every announce is wire_hops=0 (path hops=1), so the existing and incoming
    hop counts are EQUAL: RNS's same-or-fewer-hops branch admits only when the
    random_blob is novel AND `announce_emitted > path_timebase`
    (Transport.py:1769). An older-emission announce is novel but not newer, so it
    must be rejected — and the ONLY thing that can reject it is the emission gate,
    not hop count. An impl that checks only random_blob novelty (the reticulum-kt
    drift) wrongly admits it and overwrites the fresh path's emission timebase.
    """
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        announcer_private = secrets.token_bytes(64)

        # Fresh announce, hops=1, newest emission.
        FRESH_TS = 1_000_000_100
        fresh, dest_hash, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl-eq"],
            random_prefix=b"\xB1\xB1\xB1\xB1\xB1",
            emission_ts=FRESH_TS,
            wire_hops=0,
        )
        inst.inject(iface_a, fresh)
        time.sleep(0.2)
        pt_fresh = inst.read_path_table(dest_hash)
        assert pt_fresh["found"] and pt_fresh["hops"] == 1
        assert _blob_emission_ts(pt_fresh["random_blobs"][0]) == FRESH_TS

        # SAME-hop (wire_hops=0 -> path hops=1, EQUAL to held), novel blob, OLDER
        # emission. Hop count is identical, so a hop-count check can't reject it;
        # only the emission gate can. Must be rejected.
        EQUAL_STALE_TS = 1_000_000_050
        equal_stale, eq_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl-eq"],
            random_prefix=b"\xB0\xB0\xB0\xB0\xB0",
            emission_ts=EQUAL_STALE_TS,
            wire_hops=0,
        )
        assert eq_dest == dest_hash
        inst.inject(iface_a, equal_stale)
        time.sleep(0.2)
        pt_after = inst.read_path_table(dest_hash)
        assert pt_after["found"] and pt_after["hops"] == 1
        retained_ts = [_blob_emission_ts(b) for b in pt_after["random_blobs"]]
        assert all(ts == FRESH_TS for ts in retained_ts), (
            f"same-hop older-emission announce overwrote the fresh path's emission "
            f"timebase: {retained_ts} (emission gate not enforced on equal hops)"
        )
        assert EQUAL_STALE_TS not in retained_ts, (
            "path table absorbed the older-emission same-hop announce"
        )

        # Positive control: a NEWER-emission same-hop announce DOES replace —
        # proving the gate admits on emission recency, not a blanket reject.
        NEWER_TS = 1_000_000_200
        newer, _, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl-eq"],
            random_prefix=b"\xB2\xB2\xB2\xB2\xB2",
            emission_ts=NEWER_TS,
            wire_hops=0,
        )
        inst.inject(iface_a, newer)
        time.sleep(0.2)
        pt_newer = inst.read_path_table(dest_hash)
        assert pt_newer["found"] and pt_newer["hops"] == 1
        assert NEWER_TS in [_blob_emission_ts(b) for b in pt_newer["random_blobs"]], (
            "newer-emission same-hop announce was not admitted by the emission gate"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "read_path_table",
              "announce_build"],
    verifies=(
        "An announce's emission timestamp (carried in the 10-byte random_hash) "
        "is 5 random bytes followed by the 5-byte big-endian Unix emission time: "
        "for a controlled emission_ts T, the stored path random_blob is exactly "
        "10 bytes whose trailing 5 bytes equal T packed big-endian, and two "
        "announces (distinct destinations) emitted at the SAME T carry the same "
        "trailing 5 bytes but DIFFERENT leading 5 random bytes — pinning the "
        "5-random || 5-BE-timestamp layout against a literal, not just a "
        "round-trip"
    ),
)
def test_announce_emission_timestamp_byte_structure(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        emission_ts = 1_234_567_890  # a fixed, known Unix time
        expected_ts_bytes = emission_ts.to_bytes(5, "big")

        blobs = []
        for aspect in ("ts_struct_a", "ts_struct_b"):
            raw, dest, _ = build_announce_from_destination(
                behavioral.bridge,
                identity_private_key=secrets.token_bytes(64),
                app_name="testapp", aspects=[aspect],
                emission_ts=emission_ts, wire_hops=0,
            )
            inst.inject(iface, raw)
            time.sleep(0.15)
            entry = inst.read_path_table(dest)
            assert entry["found"], f"announce for {aspect} did not create a path entry"
            blob = bytes.fromhex(entry["random_blobs"][0])
            assert len(blob) == 10, f"random_hash must be 10 bytes, got {len(blob)}"
            # Trailing 5 bytes are the big-endian emission timestamp (literal pin).
            assert blob[5:10] == expected_ts_bytes, (
                f"random_hash[5:10] must equal the 5-byte BE emission time "
                f"{expected_ts_bytes.hex()}, got {blob[5:10].hex()}"
            )
            blobs.append(blob)

        # Same emission timestamp -> identical trailing 5 bytes ...
        assert blobs[0][5:10] == blobs[1][5:10]
        # ... but the leading 5 bytes are freshly random per announce.
        assert blobs[0][0:5] != blobs[1][0:5], (
            "the leading 5 bytes of the random_hash were identical across two "
            "announces — they must be fresh randomness, not derived from the time"
        )
    finally:
        behavioral.cleanup()
