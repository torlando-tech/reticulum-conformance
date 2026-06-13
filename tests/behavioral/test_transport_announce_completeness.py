"""
Behavioral completeness tests for Transport announce handling.

Closes gaps the rest of the suite leaves open around the announce intake path
in RNS Transport.py (validate-before-process precheck, rebroadcast wire form,
the random-blob retention cap, the wall-clock emission timestamp, and the
same-level heard-rebroadcast counter). Every test drives the REAL
RNS.Transport.inbound / jobs path through the behavioral bridge and asserts on
observables (path_table / announce_table / drained wire bytes) — no transport
logic is reimplemented in the harness.

Each rule is anchored on an independent value (a SPEC LITERAL read from RNS
source, the real system wall clock, or a value derived a different way) and is
checked positively AND negatively.
"""

import secrets
import time

import pytest

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    HEADER_2,
    PACKET_TYPE_ANNOUNCE,
    TRANSPORT_TRANSPORT,
    TRUNCATED_HASH_BYTES,
    _promote_to_header2,
    build_announce_from_destination,
    is_announce,
    parse_packet_header,
)


__category_title__ = "Transport Behavior"
__category_order__ = 19


# RNS spec literals (verified against the installed RNS 1.3.1 source):
#   Identity.KEYSIZE//8 = 64, NAME_HASH_LENGTH//8 = 10, random_hash = 10 bytes
#   -> the announce signature begins 84 bytes into packet.data (no ratchet/app
#      data). HEADER_1 announce payload starts at byte 19, so the signature's
#      first byte is at raw[19+84] (Identity.validate_announce layout).
_KEYSIZE = 64
_NAME_HASH_LEN = 10
_RANDOM_HASH_LEN = 10
_SIG_OFFSET_IN_DATA = _KEYSIZE + _NAME_HASH_LEN + _RANDOM_HASH_LEN  # 84
_HEADER_1_DATA_START = 19  # flags + hops + dest(16) + context

# Transport.MAX_RANDOM_BLOBS (Transport.py:98). Pinned here as the value an
# implementation must enforce; the test fails if the impl keeps more or fewer.
_MAX_RANDOM_BLOBS = 64

# Transport.PATHFINDER_R (the "transmit immediately, once" preset; not used as a
# literal here — referenced only for context).


def _blob_emission_ts(blob_hex: str) -> int:
    """Decode the 5-byte big-endian emission timebase from a random_hash hex
    (bytes [5:10]); mirrors RNS Transport.timebase_from_random_blobs."""
    return int.from_bytes(bytes.fromhex(blob_hex)[5:10], "big")


def _find_announce_for(packets, dest):
    """Return the parsed header of the first announce in `packets` addressed to
    `dest` (bytes), or None."""
    for raw in packets:
        if is_announce(raw):
            hdr = parse_packet_header(raw)
            if hdr["destination_hash"] == dest:
                return hdr
    return None


# ---------------------------------------------------------------------------
# announce-signature-precheck: an invalid-signature announce is dropped before
# ANY Transport processing (no path entry, no retransmit entry).
# Transport.py:1689 — only_validate_signature precheck returns early.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_path_table", "read_announce_table"],
    verifies=(
        "An ANNOUNCE whose Ed25519 signature has been tampered (one byte flipped "
        "in the 64-byte signature inside packet.data) is dropped by "
        "Transport.inbound BEFORE any processing (Transport.py:1689 "
        "validate_announce(only_validate_signature=True) -> return): it creates "
        "NO path_table entry and NO announce_table retransmit entry. A "
        "byte-identical-shape announce with an intact signature, injected the same "
        "way, IS processed (path_table entry at hops==1 and, with transport "
        "enabled, an announce_table entry) — proving the drop is the signature "
        "precheck, not a vacuous 'announce never processed'."
    ),
)
def test_invalid_signature_announce_not_processed(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        # Negative: a valid announce with one byte of its signature flipped.
        bad_priv = secrets.token_bytes(64)
        bad_raw, bad_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=bad_priv,
            app_name="testapp",
            aspects=["sigprecheck-bad"],
            emission_ts=1_000_000_100,
            wire_hops=0,
        )
        tampered = bytearray(bad_raw)
        # Middle of the 64-byte signature: raw[19 + 84 + 30]. Flipping a
        # signature byte leaves the dest hash / public key / name hash intact, so
        # the only thing that can reject it is the signature check itself.
        sig_byte_index = _HEADER_1_DATA_START + _SIG_OFFSET_IN_DATA + 30
        tampered[sig_byte_index] ^= 0x01
        inst.inject(iface, bytes(tampered))
        time.sleep(0.2)

        assert inst.read_path_table(bad_dest)["found"] is False, (
            "a tampered-signature announce created a path_table entry — the "
            "validate-before-process signature precheck is absent "
            "(Transport.py:1689)"
        )
        assert inst.read_announce_table(bad_dest)["found"] is False, (
            "a tampered-signature announce was scheduled for retransmit — it must "
            "be dropped before reaching the announce_table"
        )

        # Positive control: the SAME announce with its signature intact IS
        # processed, so the negatives above are the precheck at work, not a
        # mechanism that never learns anything.
        good_priv = secrets.token_bytes(64)
        good_raw, good_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=good_priv,
            app_name="testapp",
            aspects=["sigprecheck-good"],
            emission_ts=1_000_000_101,
            wire_hops=0,
        )
        assert good_dest != bad_dest
        inst.inject(iface, good_raw)
        time.sleep(0.2)

        pt = inst.read_path_table(good_dest)
        assert pt["found"] and pt["hops"] == 1, (
            f"an intact-signature announce was NOT learned (got {pt}) — the drop "
            f"assertions above would be vacuous"
        )
        assert inst.read_announce_table(good_dest)["found"] is True, (
            "an intact-signature announce did not enter the retransmit table with "
            "transport enabled"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# announce-rebroadcast-wire-format: the general announce_table rebroadcast is a
# HEADER_2 / TRANSPORT packet carrying THIS instance's transport_id, the
# reception hop count (NOT reset to 0), and the original context_flag (ratchet
# presence) preserved. Transport.py:606-620.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "set_announce_timestamp", "force_cull"],
    verifies=(
        "A Transport node rebroadcasting an announce from its announce_table emits "
        "a HEADER_2 packet with transport_type=TRANSPORT, transport_id equal to "
        "this instance's own identity hash, hops equal to the reception count "
        "(wire 3 + receive increment = 4, NOT reset to 0), and the original "
        "announce's context_flag preserved (Transport.py:606-620). Verified both "
        "ways for the context_flag: a RATCHETED announce (context_flag set) is "
        "rebroadcast with context_flag==1, while a plain announce is rebroadcast "
        "with context_flag==0."
    ),
)
def test_announce_rebroadcast_wire_format(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        WIRE_HOPS = 3  # -> reception count 4 after the +1 receive increment

        # Ratcheted announce (context_flag set) and a plain announce (unset).
        ratchet_raw, ratchet_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="testapp", aspects=["rebcast-ratchet"],
            emission_ts=1_000_000_200, wire_hops=WIRE_HOPS,
            ratchet=b"\x00",  # non-None -> announce_build enables ratchets
        )
        plain_raw, plain_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="testapp", aspects=["rebcast-plain"],
            emission_ts=1_000_000_200, wire_hops=WIRE_HOPS,
        )
        # Precondition: the injected announces actually differ in context_flag,
        # otherwise the preservation check below would be vacuous.
        assert parse_packet_header(ratchet_raw)["context_flag"] == 1, (
            "ratcheted announce did not carry context_flag=1 on the wire"
        )
        assert parse_packet_header(plain_raw)["context_flag"] == 0, (
            "plain announce unexpectedly carried context_flag=1"
        )

        inst.inject(iface_a, ratchet_raw)
        inst.inject(iface_a, plain_raw)

        # Force the announce_table rebroadcast deterministically: make both
        # entries due (retransmit_timeout=0) and run one jobs() pass. The
        # outgoing announces are sent on a worker thread, so collect drained
        # bytes from iface_b over a short window.
        inst.set_announce_timestamp(ratchet_dest, retransmit_timeout=0)
        inst.set_announce_timestamp(plain_dest, retransmit_timeout=0)
        inst.force_cull()

        collected = []
        ratchet_hdr = plain_hdr = None
        for _ in range(30):
            time.sleep(0.1)
            collected.extend(inst.drain_tx(iface_b))
            ratchet_hdr = ratchet_hdr or _find_announce_for(collected, ratchet_dest)
            plain_hdr = plain_hdr or _find_announce_for(collected, plain_dest)
            if ratchet_hdr and plain_hdr:
                break

        assert ratchet_hdr is not None, (
            "the ratcheted announce was never rebroadcast on iface_b"
        )
        assert plain_hdr is not None, (
            "the plain announce was never rebroadcast on iface_b"
        )

        for label, hdr, expected_flag in (
            ("ratcheted", ratchet_hdr, 1),
            ("plain", plain_hdr, 0),
        ):
            assert hdr["header_type"] == HEADER_2, (
                f"{label} rebroadcast is not HEADER_2 (Transport.py:608)"
            )
            assert hdr["transport_type"] == TRANSPORT_TRANSPORT, (
                f"{label} rebroadcast transport_type is not TRANSPORT"
            )
            assert hdr["transport_id"] == inst.identity_hash, (
                f"{label} rebroadcast transport_id is not this instance's own "
                f"identity hash (Transport.py:613)"
            )
            assert hdr["packet_type"] == PACKET_TYPE_ANNOUNCE
            assert hdr["hops"] == WIRE_HOPS + 1, (
                f"{label} rebroadcast hops={hdr['hops']} — reception count "
                f"{WIRE_HOPS + 1} must be preserved, not reset to 0 "
                f"(Transport.py:615)"
            )
            assert hdr["context_flag"] == expected_flag, (
                f"{label} rebroadcast context_flag={hdr['context_flag']} != "
                f"{expected_flag} — the ratchet-presence flag was not preserved "
                f"across the rebroadcast (Transport.py:616)"
            )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# random-blob-history: per-destination random_blob list is capped at
# MAX_RANDOM_BLOBS=64 (Transport.py:98 / :1882 random_blobs[-MAX:]).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_path_table"],
    verifies=(
        "The per-destination random_blob history is retained up to "
        "MAX_RANDOM_BLOBS=64 and then truncated to the most-recent 64 "
        "(Transport.py:1882 random_blobs[-MAX_RANDOM_BLOBS:]). Injecting 70 "
        "successively-newer same-hop announces for one destination grows the "
        "stored random_blobs to exactly 64 (not 70, not unbounded), and the "
        "retained blobs are the 64 most-recently-emitted ones (the first 6 are "
        "dropped). A positive control after the first 10 announces shows the list "
        "growing 1:1 (length 10) before the cap is reached."
    ),
)
def test_random_blob_history_capped_at_64(behavioral):
    # Transport disabled: path learning + random_blob retention still run
    # (Transport.py:1880-1882 is before the transport-gated announce_table
    # insert), but no retransmit machinery churns — faster and cleaner.
    inst = behavioral.start(enable_transport=False)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        priv = secrets.token_bytes(64)
        BASE_TS = 1_000_000_000
        TOTAL = 70

        dest = None
        for i in range(TOTAL):
            raw, dest, _ = build_announce_from_destination(
                behavioral.bridge,
                identity_private_key=priv,
                app_name="testapp", aspects=["blobcap"],
                emission_ts=BASE_TS + i,  # strictly increasing -> each accepted
                wire_hops=0,              # constant hops -> same-hop branch
            )
            inst.inject(iface, raw)  # inbound is synchronous (Transport.inbound)
            if i == 9:
                # Positive growth control: 10 accepted announces -> 10 blobs.
                grow = inst.read_path_table(dest)
                assert grow["found"], "announces are not being learned at all"
                assert len(grow["random_blobs"]) == 10, (
                    f"random_blob list should grow 1:1 below the cap; after 10 "
                    f"announces it has {len(grow['random_blobs'])} entries"
                )

        entry = inst.read_path_table(dest)
        assert entry["found"]
        blobs = entry["random_blobs"]
        assert len(blobs) == _MAX_RANDOM_BLOBS, (
            f"random_blob history is {len(blobs)} entries after {TOTAL} announces "
            f"— must be capped at MAX_RANDOM_BLOBS={_MAX_RANDOM_BLOBS} "
            f"(Transport.py:1882)"
        )
        emissions = sorted(_blob_emission_ts(b) for b in blobs)
        # Retained = the 64 most-recently-emitted (i = 6..69); first 6 dropped.
        assert emissions[0] == BASE_TS + (TOTAL - _MAX_RANDOM_BLOBS), (
            f"oldest retained emission {emissions[0]} != expected "
            f"{BASE_TS + (TOTAL - _MAX_RANDOM_BLOBS)} — the cap dropped the wrong "
            f"end of the history"
        )
        assert emissions[-1] == BASE_TS + (TOTAL - 1), (
            f"newest retained emission {emissions[-1]} != expected "
            f"{BASE_TS + (TOTAL - 1)}"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# outgoing-announce-hop-ordering: announces becoming due in one job round are
# emitted in ascending hop-count order. Transport.py:1046-1047
# (handle_outgoing_announces sorts the outgoing list by p.hops).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "set_announce_timestamp", "force_cull",
              "read_announce_table"],
    verifies=(
        "When several queued announce rebroadcasts become due in the same job "
        "round, they are emitted in ascending hop-count order "
        "(Transport.py:1046-1047 sorted(outgoing, key=p.hops)). Three announces "
        "injected at wire_hops 5/1/3 (reception hop counts 6/2/4) and made due "
        "together egress on the forwarding interface in the order hops 2,4,6 — "
        "lowest hop count first — regardless of their injection/queue order."
    ),
)
def test_batched_rebroadcasts_emitted_in_hop_order(behavioral, behavioral_impl):
    if behavioral_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#announce-retransmit-table-loop: AnnounceEntry.retransmits "
            "is never incremented; no cull-pass announce-retransmit job; "
            "per-interface re-emit model; no PATHFINDER_R local-client preset; no "
            "hop-sorted batched egress. Refs Transport.py:560-650/1046-1047/"
            "1718-1736/1889-1893."
        )
    inst = behavioral.start(enable_transport=True)
    try:
        # Each announce arrives on its OWN receiving interface so per-interface
        # ingress-burst limiting (which would hold the 2nd/3rd rapid announce on
        # a shared interface) never trips. The rebroadcast egresses on every
        # interface in the same sorted order, so a dedicated egress interface
        # that receives nothing is a clean ordering observatory.
        iface_egress = inst.attach_mock_interface("egress", mode="FULL")

        # Inject in a deliberately NON-sorted wire-hop order so the assertion
        # tests sorting, not incidental insertion order. reception hops = wire+1.
        # Freeze each entry's retransmit_timeout into the far future immediately
        # after injecting, so the background job loop cannot fire (and advance/
        # complete) any of them before we release them together.
        specs = [("hi", 5), ("lo", 1), ("mid", 3)]  # -> reception 6, 2, 4
        dest_by_hops = {}
        for idx, (aspect, wire_hops) in enumerate(specs):
            rx = inst.attach_mock_interface(f"rx{idx}", mode="FULL")
            raw, dest, _ = build_announce_from_destination(
                behavioral.bridge,
                identity_private_key=secrets.token_bytes(64),
                app_name="testapp", aspects=[f"hoporder-{aspect}"],
                emission_ts=1_000_000_300, wire_hops=wire_hops,
            )
            inst.inject(rx, raw)
            inst.set_announce_timestamp(dest, retransmit_timeout=_FAR)
            dest_by_hops[wire_hops + 1] = dest

        # All three must be queued and untouched (retries==0) before release.
        for hops, dest in dest_by_hops.items():
            e = inst.read_announce_table(dest)
            assert e["found"] and e["retries"] == 0, (
                f"announce for reception-hops {hops} not cleanly queued: {e}"
            )

        # Release every queued announce in the SAME jobs() pass, then fire once.
        for dest in dest_by_hops.values():
            inst.set_announce_timestamp(dest, retransmit_timeout=0)
        inst.force_cull()

        collected = []
        for _ in range(30):
            time.sleep(0.1)
            collected.extend(inst.drain_tx(iface_egress))
            seen = [h for h in (parse_packet_header(p) for p in collected)
                    if h["packet_type"] == PACKET_TYPE_ANNOUNCE]
            if len({h["destination_hash"] for h in seen}) >= 3:
                break

        emitted = [parse_packet_header(p) for p in collected if is_announce(p)]
        # Reduce to the first sighting of each of our three destinations, in
        # egress order.
        order = []
        seen_dests = set()
        for h in emitted:
            d = h["destination_hash"]
            if d in dest_by_hops.values() and d not in seen_dests:
                seen_dests.add(d)
                order.append(h["hops"])
        assert len(order) == 3, (
            f"expected all three announces to egress on iface_b, saw hop sequence "
            f"{order}"
        )
        assert order == sorted(order), (
            f"batched announce rebroadcasts were not emitted in ascending "
            f"hop-count order: got {order} (expected [2, 4, 6]) — "
            f"Transport.py:1046-1047"
        )
        assert order == [2, 4, 6], (
            f"hop-ordered egress sequence {order} != [2, 4, 6]"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# announce-emission-timestamp-semantics: a naturally-emitted announce (no pinned
# clock) stamps the CURRENT unix time into random_hash[5:10].
# Transport.timebase generator side, anchored on the real wall clock.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_path_table"],
    verifies=(
        "A naturally-emitted announce (no monkeypatched clock) stamps the current "
        "Unix wall-clock time into the 5-byte big-endian emission field of its "
        "random_hash (random_hash[5:10]): the decoded emission timebase of the "
        "stored path random_blob is within a few seconds of the test process's "
        "own time.time(). Anchored on the real system clock (an external "
        "standard), not on a value the impl chose."
    ),
)
def test_natural_announce_stamps_current_walltime(behavioral):
    inst = behavioral.start(enable_transport=False)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        before = int(time.time())
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="testapp", aspects=["natural-ts"],
            wire_hops=0,  # emission_ts left default (0) -> RNS uses real time
        )
        inst.inject(iface, raw)
        after = int(time.time())
        time.sleep(0.15)

        entry = inst.read_path_table(dest)
        assert entry["found"], "natural announce did not create a path entry"
        decoded = _blob_emission_ts(entry["random_blobs"][0])
        # The stamp is taken inside the bridge at build time, bracketed by the
        # test's own clock reads. Allow a small slop for clock granularity.
        assert before - 2 <= decoded <= after + 2, (
            f"naturally-emitted announce timebase {decoded} is not the current "
            f"wall-clock time (test window [{before}, {after}]) — the emission "
            f"timestamp is not stamped from the real clock"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# announce-passed-on-cancellation (same-level branch): hearing a rebroadcast at
# the SAME effective level (packet.hops-1 == entry.hops) increments the
# local_rebroadcast counter, and the in-flight entry is completed once the
# counter reaches LOCAL_REBROADCASTS_MAX=2. Transport.py:1718-1726.
# ---------------------------------------------------------------------------
# Frozen-future retransmit_timeout: at retries==1 with this value every
# retransmit-job branch is inert, so the background loop can't mutate the entry
# between our observations (mirrors test_transport_routing._FAR).
_FAR = 10 ** 12


def _drive_to_stable_single_retry(inst, dest):
    """Drive announce_table[dest] to a STABLE retries==1 entry with its
    retransmit_timeout frozen far in the future (deterministic, sleep-free).
    Mirrors the helper in test_transport_routing.py."""
    inst.set_announce_timestamp(dest, retransmit_timeout=_FAR)
    entry = inst.read_announce_table(dest)
    assert entry["found"], "announce did not enter the retransmit table"
    guard = 0
    while entry["retries"] < 1:
        guard += 1
        assert guard <= 4, f"could not advance announce retries (stuck at {entry})"
        inst.set_announce_timestamp(dest, retransmit_timeout=0)
        inst.force_cull()
        inst.set_announce_timestamp(dest, retransmit_timeout=_FAR)
        entry = inst.read_announce_table(dest)
        assert entry["found"], "retransmit entry vanished while advancing retries"
    assert entry["retries"] == 1
    return entry


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_announce_table", "set_announce_timestamp", "force_cull",
              "packet_unpack"],
    verifies=(
        "Same-level heard-rebroadcast counting: while an announce is in-flight "
        "(retries>0), hearing a HEADER_2 announce for the same destination from "
        "another transport instance at the SAME effective level "
        "(packet.hops-1 == entry.hops) increments the entry's local_rebroadcasts "
        "counter WITHOUT removing the entry, and the entry is completed (removed) "
        "only once local_rebroadcasts reaches LOCAL_REBROADCASTS_MAX=2 "
        "(Transport.py:1718-1726). After ONE such heard rebroadcast the entry "
        "survives with local_rebroadcasts==1 (this distinguishes the same-level "
        "branch from the passed-on branch, which removes on a single heard "
        "announce); after a SECOND it is removed. A twin destination that hears "
        "no rebroadcast keeps its entry throughout (positive control)."
    ),
)
def test_same_level_heard_rebroadcast_counts_toward_limit(behavioral, behavioral_impl):
    if behavioral_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#announce-retransmit-table-loop: AnnounceEntry.retransmits "
            "is never incremented; no cull-pass announce-retransmit job; "
            "per-interface re-emit model; no PATHFINDER_R local-client preset; no "
            "hop-sorted batched egress. Refs Transport.py:560-650/1046-1047/"
            "1718-1736/1889-1893."
        )
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        priv_count = secrets.token_bytes(64)
        priv_control = secrets.token_bytes(64)

        ann_count, dest_count, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_count,
            app_name="testapp", aspects=["samelevel"],
            emission_ts=1_000_000_100, wire_hops=0,
        )
        ann_control, dest_control, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_control,
            app_name="testapp", aspects=["control"],
            emission_ts=1_000_000_100, wire_hops=0,
        )
        inst.inject(iface_a, ann_count)
        inst.inject(iface_a, ann_control)

        e_count = _drive_to_stable_single_retry(inst, dest_count)
        e_control = _drive_to_stable_single_retry(inst, dest_control)
        assert e_count["hops"] == 1 and e_control["hops"] == 1
        assert e_count["local_rebroadcasts"] == 0, (
            f"unexpected starting local_rebroadcasts: {e_count}"
        )

        # Build a SAME-LEVEL heard rebroadcast: wire_hops=1 -> packet.hops=2 on
        # receive, so packet.hops-1 (1) == entry.hops (1). Older emission + more
        # hops -> it is NOT re-admitted to the path table, isolating the
        # local_rebroadcasts increment. HEADER_2 with a foreign transport_id.
        heard_h1, heard_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_count,
            app_name="testapp", aspects=["samelevel"],
            emission_ts=1_000_000_050, wire_hops=1,
        )
        assert heard_dest == dest_count
        foreign_tid = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        heard = _promote_to_header2(heard_h1, foreign_tid)
        parsed = behavioral.bridge.execute("packet_unpack", raw=heard.hex())
        assert parsed["unpacked"] and parsed["header_type"] == HEADER_2
        assert parsed["transport_id"] == foreign_tid.hex()
        assert parsed["destination_hash"] == dest_count.hex()

        # First heard rebroadcast: counter 0 -> 1, entry SURVIVES (1 < 2). This is
        # the discriminating observable: the passed-on branch would have removed
        # the entry on a single heard announce.
        inst.inject(iface_b, heard)
        after_one = inst.read_announce_table(dest_count)
        assert after_one["found"] is True, (
            "a single SAME-LEVEL heard rebroadcast removed the entry — that is "
            "the passed-on branch (hops-1 == entry.hops+1), not the same-level "
            "counting branch (Transport.py:1718-1726)"
        )
        assert after_one["local_rebroadcasts"] == 1, (
            f"local_rebroadcasts did not increment on a same-level heard "
            f"rebroadcast (got {after_one['local_rebroadcasts']})"
        )

        # Second heard rebroadcast (announces bypass the dup filter, so the
        # identical bytes are processed again): counter 1 -> 2 >= MAX -> removed.
        inst.inject(iface_b, heard)
        after_two = inst.read_announce_table(dest_count)
        assert after_two["found"] is False, (
            "the entry was not completed once local_rebroadcasts reached "
            "LOCAL_REBROADCASTS_MAX=2 (Transport.py:1722-1726)"
        )

        # Positive control: the twin destination, which heard no rebroadcast,
        # still has its in-flight entry — the removal above is attributable to
        # the heard rebroadcasts, not elapsed time.
        ctrl = inst.read_announce_table(dest_control)
        assert ctrl["found"] is True and ctrl["local_rebroadcasts"] == 0, (
            f"control entry changed without any heard rebroadcast: {ctrl}"
        )
    finally:
        behavioral.cleanup()
