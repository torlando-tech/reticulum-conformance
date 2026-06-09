"""
Behavioral test: packet-hashlist replay / loop drop (§5 CORE).

RNS Transport keeps a hashlist of recently-seen packet hashes
(`Transport.packet_hashlist`). `Transport.packet_filter` (Transport.py:1374)
accepts a packet only if its hash is not already in that list; a second,
byte-identical packet is therefore dropped. This is the mechanism that breaks
routing loops and rejects naive replays — and it is the namesake of the branch
this suite was re-audited on (the re-audit flagged it as untested everywhere,
because the behavioral harness used to *clear* the hashlist; the dedicated
`behavioral_packet_filter` command exists to close that gap without clearing).

There is one deliberate carve-out: SINGLE-destination ANNOUNCE packets are NOT
deduplicated by the hashlist (Transport.py:1376-1378). They carry their own
random_blob-based replay protection, and the path-replacement rules (see
`test_path_replacement.py`) decide whether a re-heard announce is acted on. So a
replayed announce stays "accepted" by packet_filter, whereas a replayed
non-announce DATA packet to a SINGLE destination is dropped.

Both tests drive the real RNS `Transport.packet_filter` + `add_packet_hash` gate
via `behavioral_packet_filter` — no filtering logic is reimplemented in the
harness, and the harness does NOT clear the hashlist between the two sightings.
"""

import secrets

from conformance import conformance_case
from tests.behavioral.packet_builders import build_announce_from_destination


__category_title__ = "Transport Behavior"
__category_order__ = 19


@conformance_case(
    commands=["start", "packet_build", "packet_filter"],
    verifies=(
        "A byte-identical non-announce SINGLE-destination DATA packet run "
        "through the Transport packet-hashlist filter twice is accepted the "
        "first time (and its hash remembered) and DROPPED the second time "
        "(replay/loop drop); a fresh DATA packet with a different hash is still "
        "accepted afterward (positive control)"
    ),
)
def test_duplicate_data_packet_is_dropped_on_replay(behavioral):
    """First sighting of a SINGLE DATA packet is accepted and its hash
    remembered; the identical packet seen again is dropped by the hashlist
    (Transport.py:1374 -> 1383). A different, fresh DATA packet is still
    accepted, proving the filter drops on packet-hash identity, not by call
    order."""
    inst = behavioral.start()
    try:
        # A non-announce DATA packet to a SINGLE destination is the case the
        # hashlist actually dedups (PLAIN/GROUP short-circuit on hops; SINGLE
        # announces are carved out — see the sibling test).
        built = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=0,
            data=secrets.token_bytes(16).hex(),
        )
        raw = bytes.fromhex(built["raw"])

        first = inst.packet_filter(raw, remember=True)
        assert first["accepted"] is True, (
            "first sighting of a novel DATA packet must be accepted"
        )
        assert first["remembered"] is True, (
            "an accepted packet's hash must be recorded for replay detection"
        )

        replay = inst.packet_filter(raw, remember=True)
        assert replay["packet_hash"] == first["packet_hash"], (
            "replay must be the same packet (identical hash)"
        )
        assert replay["accepted"] is False, (
            "byte-identical DATA packet replay was NOT dropped — packet-hashlist "
            "replay/loop protection is absent"
        )
        assert replay["remembered"] is False, (
            "a dropped packet must not be re-recorded"
        )

        # Positive control: a genuinely different DATA packet (distinct hash) is
        # still accepted, so the drop above is hash-specific — not a blanket
        # "reject everything after the first call".
        built2 = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=0,
            data=secrets.token_bytes(16).hex(),
        )
        raw2 = bytes.fromhex(built2["raw"])
        fresh = inst.packet_filter(raw2, remember=True)
        assert fresh["packet_hash"] != first["packet_hash"], (
            "control packet must have a distinct hash"
        )
        assert fresh["accepted"] is True, (
            "a fresh DATA packet was dropped — the filter is rejecting by call "
            "order rather than by packet-hash identity"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "announce_build", "packet_filter"],
    verifies=(
        "A byte-identical SINGLE-destination ANNOUNCE packet run through the "
        "Transport packet-hashlist filter twice is accepted BOTH times — "
        "packet_filter deliberately does NOT hashlist-deduplicate SINGLE "
        "announces (Transport.py:1376-1378); announce replay protection is "
        "handled separately by random_blob/path rules"
    ),
)
def test_duplicate_single_announce_is_not_deduplicated(behavioral):
    """The hashlist carve-out: a replayed SINGLE announce stays accepted, so the
    path-replacement rules (not the hashlist) govern re-heard announces. This is
    the discriminating counterpart to the DATA-drop test — it pins that the
    dedup is specific to non-announce packets, catching an impl that
    over-aggressively drops every repeated packet (which would also break
    legitimate announce propagation)."""
    inst = behavioral.start()
    try:
        announcer_private = secrets.token_bytes(64)
        raw, _dest, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["replay"],
            emission_ts=1_000_000_000,
            wire_hops=0,
        )

        first = inst.packet_filter(raw, remember=True)
        assert first["accepted"] is True, "first announce sighting must be accepted"
        assert first["remembered"] is True

        replay = inst.packet_filter(raw, remember=True)
        assert replay["packet_hash"] == first["packet_hash"], (
            "replay must be the same packet (identical hash)"
        )
        assert replay["accepted"] is True, (
            "a replayed SINGLE announce was dropped by the hashlist — RNS "
            "deliberately exempts SINGLE announces (Transport.py:1376-1378)"
        )
    finally:
        behavioral.cleanup()
