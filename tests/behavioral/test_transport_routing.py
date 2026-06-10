"""
Behavioral tests: Transport core routing state machines (§4a).

These close five confirmed-untested Transport-core gaps, each driven entirely
through the real RNS `Transport.inbound` / `Transport.jobs` paths via the
behavioral harness (inject raw bytes on a MockInterface, observe the resulting
table state / emitted bytes). No RNS internals are reimplemented in the test;
the bridge plays every role, so the whole file passes reference-vs-reference.

Gaps covered (RNS 1.3.1 refs into
RNS/Transport.py):

  * reverse_table single-packet PROOF return-routing — insert :1625-1631,
    pop + correct-interface check + transmit-back :2254-2263. The multihop
    LINKREQUEST tests only exercise the link_table ACCEPT path; the
    reverse_table (used for ordinary single-packet PacketReceipt proofs) is
    never driven. Test relays a HEADER_2 SINGLE DATA packet to seed a reverse
    entry, then proves a PROOF on the OUTBOUND interface is transported back out
    the RECEIVED interface, while a PROOF on the wrong interface is NOT.

  * announce random_blob replay-forge rejection — :1769 / :1880-1882. A
    re-heard byte-identical announce carries a random_blob already in the path
    table, so `not random_blob in random_blobs` is False and the announce is
    NOT re-admitted: no fresh retransmit is scheduled. A genuinely newer
    announce (novel blob, later emission) IS admitted (positive control).

  * announce retransmit completion + heard-rebroadcast cancel SM —
    LOCAL_REBROADCASTS_MAX=2 completion :580 / :583, and the passed-on
    heard-rebroadcast cancel :1731-1736. Both require `retries > 0`, reached
    only after at least one local retransmit.

  * path_table missing-interface eviction — :782-785. A path whose receiving
    interface has been detached (and removed from Transport.interfaces) is
    culled on the next table-cull pass, with no clock dependence; a path on a
    still-attached interface survives (positive control).

  * path-request tag dedup — :2887-2904 (`unique_tag = dest + tag`; a duplicate
    tag is ignored). A second path request with the SAME tag is a no-op, while
    one with a DIFFERENT tag is acted on, isolating the per-tag dedup from the
    per-destination dedup.

Determinism: the announce-retransmit retry counter is normally advanced by the
background job loop (Transport.jobloop, every job_interval=0.250s; the
announce-retransmit sub-job is gated to ~1/s). Tests never sleep to age
entries. Instead `_drive_to_stable_single_retry` freezes an entry's
retransmit_timeout far in the future (so the background loop's
`time > retransmit_timeout` gate at :587 never fires AND the
`retries >= LOCAL_REBROADCASTS_MAX` completion at :580 stays False at
retries==1), then advances the retry counter by exactly one with a single
forced jobs() pass — leaving the entry in a stable, observable state.
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    CONTEXT_PATH_RESPONSE,
    HEADER_2,
    PACKET_TYPE_PROOF,
    TRUNCATED_HASH_BYTES,
    _promote_to_header2,
    build_announce_from_destination,
    build_data_packet,
    build_path_request,
    build_proof,
    parse_packet_header,
)


__category_title__ = "Transport Behavior"
__category_order__ = 19


# Absolute epoch (year ~33658) used to freeze an announce_table entry's
# retransmit_timeout so the background job loop cannot advance/complete it
# between observations. time.time() (~1.7e9) is always < _FAR.
_FAR = 10 ** 12
# A retransmit_timeout below this threshold means the entry was (re)admitted
# with a fresh, near-now timeout (Transport.py:1871, now + rand*PATHFINDER_RW),
# i.e. an announce was accepted for rebroadcast; _FAR is far above it.
_ADMITTED_RTMO_CEILING = 10 ** 11


def _drive_to_stable_single_retry(inst, dest):
    """Drive announce_table[dest] to a STABLE state of retries==1 with its
    retransmit_timeout frozen far in the future, deterministically.

    The caller must already have injected an announce that created the entry.
    At retries==1 with retransmit_timeout=_FAR every retransmit-job branch is
    inert (Transport.py:580 `1>=2` False, :583 `1>1` False, :587 `now>_FAR`
    False), so the background loop leaves the entry untouched and later
    observations are race-free. Returns the stable entry dict."""
    # Freeze first so the background loop can't fire while we advance.
    inst.set_announce_timestamp(dest, retransmit_timeout=_FAR)
    entry = inst.read_announce_table(dest)
    assert entry["found"], "announce did not enter the retransmit (announce) table"
    guard = 0
    while entry["retries"] < 1:
        guard += 1
        assert guard <= 4, f"could not advance announce retries (stuck at {entry})"
        # Make the entry due, fire exactly one retransmit pass (which also sets
        # announces_last_checked=now -> background loop quiet for ~1s), then
        # re-freeze well inside that quiet window.
        inst.set_announce_timestamp(dest, retransmit_timeout=0)
        inst.force_cull()
        inst.set_announce_timestamp(dest, retransmit_timeout=_FAR)
        entry = inst.read_announce_table(dest)
        assert entry["found"], "retransmit entry vanished while advancing retries"
    assert entry["retries"] == 1, (
        f"expected a stable retries==1 entry, got retries={entry['retries']}"
    )
    return entry


# ---------------------------------------------------------------------------
# 1. reverse_table single-packet PROOF return-routing (CORE)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "drain_tx",
              "read_reverse_table", "read_path_table", "announce_build",
              "packet_build", "packet_unpack", "packet_hash", "identity_sign"],
    verifies=(
        "Single-packet PROOF return-routing via Transport.reverse_table: after "
        "a HEADER_2 SINGLE DATA packet addressed to this transport (transport_id "
        "== own identity) is relayed for a known destination, a reverse_table "
        "entry [received_if, outbound_if] is created keyed by the forwarded "
        "packet's truncated hash. A PROOF addressed to that key, received on the "
        "OUTBOUND interface, is transmitted back out the RECEIVED interface; the "
        "same PROOF received on the wrong (received) interface is NOT "
        "transported (negative case with the positive case as its control)."
    ),
)
def test_reverse_table_proof_return_routing(behavioral):
    """Seed a path to D (received on iface_b), relay a single DATA packet for D
    that arrived on iface_a -> reverse_table entry {received_if: iface_a,
    outbound_if: iface_b}. A PROOF whose destination_hash equals that entry's
    key (the forwarded packet's truncated hash), arriving on iface_b (the
    outbound interface, == reverse_entry[IDX_RT_OUTB_IF]), must be transmitted
    back on iface_a (reverse_entry[IDX_RT_RCVD_IF], Transport.py:2256-2261). A
    PROOF for a second relayed packet, arriving on the WRONG interface (iface_a),
    must NOT be transported (Transport.py:2262-2263). The positive case is the
    discriminating control for the negative one: an impl that ignores the
    received==outbound interface check would (wrongly) transport both."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        # Seed a path to D received on iface_b. PATH_RESPONSE context so no
        # forward retransmit is scheduled (Transport.py:1884) — keeps the TX
        # queues clean — while the path table entry is still created.
        announcer_priv = secrets.token_bytes(64)
        seed, dest, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_priv,
            app_name="testapp",
            aspects=["revroute"],
            emission_ts=1_000_000_000,
            wire_hops=0,
            context=CONTEXT_PATH_RESPONSE,
        )
        inst.inject(iface_b, seed)
        pt = inst.read_path_table(dest)
        assert pt["found"] and pt["hops"] == 1, (
            f"seed announce did not create a 1-hop path to D: {pt}"
        )
        inst.drain_tx(iface_a)
        inst.drain_tx(iface_b)

        # --- Positive case: relay a DATA packet for D, proof on correct iface.
        data1 = build_data_packet(
            behavioral.bridge, dest,
            header_type=HEADER_2, transport_id=inst.identity_hash,
            destination_type="single", payload=secrets.token_bytes(12),
        )
        full_hash1 = bytes.fromhex(
            behavioral.bridge.execute("packet_hash", raw=data1.hex())["hash"]
        )
        inst.inject(iface_a, data1)

        # The relay emits the (header-stripped) DATA on the outbound interface.
        relayed = inst.drain_tx(iface_b)
        assert any(parse_packet_header(p)["destination_hash"] == dest for p in relayed), (
            "relayed DATA packet was not transmitted on the outbound interface"
        )
        assert inst.drain_tx(iface_a) == [], (
            "DATA packet was unexpectedly echoed back on its receiving interface"
        )

        entries = inst.read_reverse_table()["entries"]
        assert len(entries) == 1, f"expected exactly one reverse entry, got {entries}"
        rev = entries[0]
        key1 = bytes.fromhex(rev["key"])
        assert key1 == full_hash1[:TRUNCATED_HASH_BYTES], (
            "reverse_table key is not the forwarded packet's truncated hash"
        )
        assert rev["received_if"] == iface_a and rev["outbound_if"] == iface_b, (
            f"reverse entry routed wrong way: {rev}"
        )

        # PROOF addressed to key1, arriving on the OUTBOUND interface (iface_b):
        # must be transported back out the RECEIVED interface (iface_a).
        proof1 = build_proof(behavioral.bridge, full_hash1)
        inst.inject(iface_b, proof1)
        back = inst.drain_tx(iface_a)
        assert any(parse_packet_header(p)["packet_type"] == PACKET_TYPE_PROOF
                   for p in back), (
            "PROOF received on the correct (outbound) interface was NOT "
            "transported back out the received interface"
        )
        assert inst.drain_tx(iface_b) == [], (
            "PROOF was re-emitted on the interface it arrived on"
        )
        # The reverse entry is consumed exactly once.
        assert inst.read_reverse_table(dest=key1)["found"] is False
        assert inst.read_reverse_table()["entries"] == []

        # --- Negative case: same routing, but the PROOF arrives on the WRONG
        # interface (iface_a). RNS pops the reverse entry, then declines to
        # transport because received != outbound (Transport.py:2256/2262).
        data2 = build_data_packet(
            behavioral.bridge, dest,
            header_type=HEADER_2, transport_id=inst.identity_hash,
            destination_type="single", payload=secrets.token_bytes(12),
        )
        full_hash2 = bytes.fromhex(
            behavioral.bridge.execute("packet_hash", raw=data2.hex())["hash"]
        )
        inst.inject(iface_a, data2)
        inst.drain_tx(iface_a)
        inst.drain_tx(iface_b)
        key2 = full_hash2[:TRUNCATED_HASH_BYTES]
        assert inst.read_reverse_table(dest=key2)["found"] is True, (
            "second relay did not create its reverse entry"
        )

        proof2 = build_proof(behavioral.bridge, full_hash2)
        inst.inject(iface_a, proof2)  # WRONG interface (outbound is iface_b)
        assert inst.drain_tx(iface_a) == [], (
            "PROOF on the wrong interface was transported anyway (interface "
            "check at Transport.py:2256 not enforced)"
        )
        assert inst.drain_tx(iface_b) == [], (
            "PROOF on the wrong interface leaked out the outbound interface"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 2. announce random_blob replay-forge rejection (IMPORTANT)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "read_path_table",
              "read_announce_table", "set_announce_timestamp", "force_cull",
              "announce_build"],
    verifies=(
        "A byte-identical re-injected announce is rejected by the random_blob "
        "replay guard (Transport.py:1769): the path table is unchanged (still "
        "one blob, hops unchanged) AND no fresh retransmit is scheduled — an "
        "in-flight announce_table entry frozen at retries==1 stays at retries==1 "
        "with its (far-future) retransmit_timeout intact. A genuinely newer "
        "announce (novel blob, later emission) IS admitted, replacing the entry "
        "with a fresh near-now retransmit_timeout (positive control)."
    ),
)
def test_announce_random_blob_replay_is_rejected(behavioral):
    """RNS protects against announce replay-forging by remembering each
    destination's random_blobs and refusing a re-heard blob
    (Transport.py:1769 `not random_blob in random_blobs`). The discriminating
    observable is that a replayed announce schedules NO new rebroadcast: with
    the existing announce_table entry frozen at retries==1, a correct impl
    leaves it untouched, whereas an impl that re-admits the replay overwrites it
    with a fresh retries==0 entry and a near-now retransmit_timeout. The path
    table is asserted unchanged as a sanity check; the positive control proves
    the read distinguishes admission from rejection."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        inst.attach_mock_interface("b", mode="FULL")

        announcer_priv = secrets.token_bytes(64)
        original, dest, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_priv,
            app_name="testapp",
            aspects=["replayforge"],
            emission_ts=1_000_000_100,
            wire_hops=0,
        )
        inst.inject(iface_a, original)

        pt = inst.read_path_table(dest)
        assert pt["found"] and pt["hops"] == 1
        assert len(pt["random_blobs"]) == 1
        blob_x = pt["random_blobs"][0]

        # Bring the in-flight retransmit entry to a stable retries==1 state.
        stable = _drive_to_stable_single_retry(inst, dest)
        assert stable["retransmit_timeout"] == float(_FAR)

        # Re-inject the BYTE-IDENTICAL announce. SINGLE announces are exempt
        # from the hashlist drop (so this is processed, not silently filtered),
        # but the random_blob is already known -> should_add is False -> the
        # announce_table entry must be untouched.
        inst.inject(iface_a, original)

        replayed = inst.read_announce_table(dest)
        assert replayed["found"], "announce_table entry vanished after replay"
        assert replayed["retries"] == 1, (
            f"replayed announce reset the retransmit retry counter to "
            f"{replayed['retries']} — a forged/replayed announce was wrongly "
            f"re-admitted and would trigger a second rebroadcast"
        )
        assert replayed["retransmit_timeout"] == float(_FAR), (
            "replayed announce rescheduled the retransmit (timeout no longer "
            "frozen) — replay was not rejected"
        )
        pt_after = inst.read_path_table(dest)
        assert pt_after["hops"] == 1 and pt_after["random_blobs"] == [blob_x], (
            f"replay altered the held path: {pt_after}"
        )

        # Positive control: a genuinely newer announce (novel blob, later
        # emission) IS admitted -> the entry is replaced with a fresh, near-now
        # retransmit_timeout (well below _FAR).
        newer, dest2, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_priv,
            app_name="testapp",
            aspects=["replayforge"],
            emission_ts=1_000_000_200,
            wire_hops=0,
        )
        assert dest2 == dest
        inst.inject(iface_a, newer)
        admitted = inst.read_announce_table(dest)
        assert admitted["found"], "newer announce was not scheduled for rebroadcast"
        assert admitted["retransmit_timeout"] < _ADMITTED_RTMO_CEILING, (
            "a legitimately newer announce was NOT re-admitted — the replay "
            "guard is rejecting everything, so the rejection above is vacuous"
        )
        pt_newer = inst.read_path_table(dest)
        assert blob_x in pt_newer["random_blobs"] and len(pt_newer["random_blobs"]) == 2, (
            f"newer announce did not add its novel blob: {pt_newer}"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 3a. announce retransmit completion at LOCAL_REBROADCASTS_MAX (IMPORTANT)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "announce_build",
              "read_announce_table", "set_announce_timestamp", "force_cull"],
    verifies=(
        "Announce retransmit completion: an in-flight announce_table entry at "
        "retries==1 is still present (not completed), but once its retries reach "
        "LOCAL_REBROADCASTS_MAX (2) the entry is removed from the announce table "
        "on the next retransmit pass (Transport.py:580) — the rebroadcast state "
        "machine terminates rather than re-broadcasting forever."
    ),
)
def test_announce_retransmit_completes_at_rebroadcast_limit(behavioral):
    """Drive the announce retransmit counter deterministically and assert the
    completion boundary: present at retries==1 (control — an impl that completes
    too early fails here), removed once retries exceed LOCAL_REBROADCASTS_MAX
    (an impl that never completes keeps the entry and fails the final
    assertion)."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        inst.attach_mock_interface("b", mode="FULL")

        announcer_priv = secrets.token_bytes(64)
        original, dest, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_priv,
            app_name="testapp",
            aspects=["complete"],
            emission_ts=1_000_000_000,
            wire_hops=0,
        )
        inst.inject(iface_a, original)

        # Control: stable at retries==1 -> NOT yet completed.
        _drive_to_stable_single_retry(inst, dest)
        assert inst.read_announce_table(dest)["found"], (
            "announce retransmit completed prematurely at retries==1 "
            "(before LOCAL_REBROADCASTS_MAX)"
        )

        # Advance to retries==2 (one more retransmit pass); the entry is still
        # present after the pass that bumps it (the >=MAX check runs at the top
        # of the NEXT pass).
        inst.set_announce_timestamp(dest, retransmit_timeout=0)
        inst.force_cull()
        bumped = inst.read_announce_table(dest)
        assert bumped["found"] and bumped["retries"] == 2, (
            f"expected retries==2 after one more retransmit, got {bumped}"
        )

        # Next retransmit pass sees retries >= LOCAL_REBROADCASTS_MAX and
        # completes (removes) the entry.
        inst.set_announce_timestamp(dest, retransmit_timeout=0)
        inst.force_cull()
        assert inst.read_announce_table(dest)["found"] is False, (
            "announce retransmit did NOT complete after reaching "
            "LOCAL_REBROADCASTS_MAX — the entry would rebroadcast forever"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 3b. announce retransmit cancel on heard rebroadcast (IMPORTANT)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "announce_build",
              "read_announce_table", "read_path_table", "set_announce_timestamp",
              "force_cull", "packet_unpack"],
    verifies=(
        "Heard-rebroadcast cancel: while an announce is in-flight in the "
        "retransmit table (retries>0), hearing a HEADER_2 announce for the same "
        "destination from another transport instance at hop count one greater "
        "than our entry (packet.hops-1 == entry.hops+1) cancels the pending "
        "retransmit (Transport.py:1731-1736) — the announce_table entry is "
        "removed. A twin destination with no such heard rebroadcast keeps its "
        "entry (positive control), and the held path is left intact."
    ),
)
def test_announce_retransmit_cancelled_by_heard_rebroadcast(behavioral):
    """A peer rebroadcasting our in-flight announce one hop further along signals
    that no further local retries are needed; RNS cancels the pending
    retransmit (Transport.py:1731-1736). Two destinations are set up identically
    (each stable at retries==1); only D_cancel receives the matching heard
    rebroadcast (HEADER_2, foreign transport_id, hops such that
    packet.hops-1 == entry.hops+1). D_cancel's entry must be removed while
    D_control's survives — proving the cancel is triggered by the heard
    rebroadcast and not by elapsed time. The heard announce carries an OLDER
    emission and MORE hops, so it does not re-admit D_cancel via the path
    replacement rules; the held 1-hop path is asserted intact."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        priv_cancel = secrets.token_bytes(64)
        priv_control = secrets.token_bytes(64)

        ann_c, dest_cancel, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_cancel,
            app_name="testapp", aspects=["cancel"],
            emission_ts=1_000_000_100, wire_hops=0,
        )
        ann_t, dest_control, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_control,
            app_name="testapp", aspects=["control"],
            emission_ts=1_000_000_100, wire_hops=0,
        )
        inst.inject(iface_a, ann_c)
        inst.inject(iface_a, ann_t)

        # Both stable at retries==1, entry.hops==1.
        e_cancel = _drive_to_stable_single_retry(inst, dest_cancel)
        e_control = _drive_to_stable_single_retry(inst, dest_control)
        assert e_cancel["hops"] == 1 and e_control["hops"] == 1

        # Heard rebroadcast for D_cancel: HEADER_2 announce from another
        # transport instance (foreign transport_id), wire_hops=2 -> packet.hops
        # becomes 3 on receive, so packet.hops-1 (2) == entry.hops (1) + 1.
        heard_h1, heard_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_cancel,
            app_name="testapp", aspects=["cancel"],
            emission_ts=1_000_000_050,  # older than original -> no re-admit
            wire_hops=2,
        )
        assert heard_dest == dest_cancel
        foreign_transport_id = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        heard = _promote_to_header2(heard_h1, foreign_transport_id)
        parsed = behavioral.bridge.execute("packet_unpack", raw=heard.hex())
        assert parsed["unpacked"] and parsed["header_type"] == HEADER_2
        assert parsed["transport_id"] == foreign_transport_id.hex()
        assert parsed["destination_hash"] == dest_cancel.hex()

        inst.inject(iface_b, heard)

        assert inst.read_announce_table(dest_cancel)["found"] is False, (
            "heard rebroadcast did NOT cancel the pending retransmit "
            "(Transport.py:1731-1736)"
        )
        assert inst.read_announce_table(dest_control)["found"] is True, (
            "the control entry vanished on its own — the cancel above is not "
            "attributable to the heard rebroadcast"
        )
        # The held path to D_cancel is untouched (the older, more-hops heard
        # announce was not absorbed into the path table).
        pt = inst.read_path_table(dest_cancel)
        assert pt["found"] and pt["hops"] == 1, (
            f"heard rebroadcast corrupted the held path: {pt}"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 4. path_table missing-interface eviction (IMPORTANT)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "announce_build",
              "read_path_table", "detach_interface", "force_cull"],
    verifies=(
        "Path-table missing-interface eviction (Transport.py:782-785): a path "
        "whose receiving interface has been detached and removed from "
        "Transport.interfaces is culled on the next table-cull pass (no clock "
        "dependence). A path on a still-attached interface survives the same "
        "cull pass (positive control)."
    ),
)
def test_path_table_missing_interface_eviction(behavioral):
    """Learn a path to D on iface_a and a path to D2 on iface_b, detach iface_a,
    and run the table-cull. D's path is evicted because its attached interface
    is no longer in Transport.interfaces (Transport.py:782); D2's path survives
    because iface_b is still attached — proving the cull is interface-specific
    rather than a blanket flush (and that it isn't merely an expiry effect, as
    neither path is time-expired)."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        priv_a = secrets.token_bytes(64)
        priv_b = secrets.token_bytes(64)
        ann_a, dest_a, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_a,
            app_name="testapp", aspects=["evict"],
            emission_ts=1_000_000_000, wire_hops=0,
        )
        ann_b, dest_b, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_b,
            app_name="testapp", aspects=["survive"],
            emission_ts=1_000_000_000, wire_hops=0,
        )
        inst.inject(iface_a, ann_a)
        inst.inject(iface_b, ann_b)
        assert inst.read_path_table(dest_a)["found"], "path to D not learned"
        assert inst.read_path_table(dest_b)["found"], "path to D2 not learned"

        # Detach iface_a (removes it from Transport.interfaces) and cull.
        inst.detach_interface(iface_a)
        inst.force_cull()

        assert inst.read_path_table(dest_a)["found"] is False, (
            "path whose receiving interface was detached was NOT evicted "
            "(Transport.py:782-785)"
        )
        assert inst.read_path_table(dest_b)["found"] is True, (
            "path on a still-attached interface was wrongly evicted — the cull "
            "is not interface-specific"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 5. path-request tag dedup (IMPORTANT)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "announce_build",
              "packet_build", "packet_unpack", "name_hash", "truncated_hash",
              "read_path_table", "read_announce_table", "set_announce_timestamp",
              "force_cull", "drain_tx"],
    verifies=(
        "Path-request tag dedup (Transport.py:2887-2904): for a known "
        "destination, a path request answers by scheduling the cached announce "
        "into the announce table. A SECOND path request with the SAME tag is a "
        "no-op (unique_tag = dest+tag already seen -> ignored), so no answer is "
        "scheduled; a path request with a DIFFERENT tag IS acted on and "
        "schedules an answer — isolating the per-tag dedup from per-destination "
        "behaviour."
    ),
)
def test_path_request_tag_dedup(behavioral):
    """Seed a known path to D, then drive three path requests through the
    rnstransport/path/request control destination. PR(D, T1) answers (schedules
    a cached-announce rebroadcast into the announce table with block_rebroadcasts
    set and the answering interface attached). After clearing that entry,
    PR(D, T1) AGAIN is deduplicated (unique_tag dest+T1 already seen) and
    schedules nothing; PR(D, T2) with a fresh tag is acted on again. An impl
    with no tag dedup answers the repeat; an impl that dedups on destination
    only fails to answer the fresh-tag request — both fail this test."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        announcer_priv = secrets.token_bytes(64)
        # Seed via PATH_RESPONSE so no forward retransmit pollutes the
        # announce_table; the path (and its cached announce) is still created.
        seed, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=announcer_priv,
            app_name="testapp", aspects=["tagdedup"],
            emission_ts=1_000_000_000, wire_hops=0,
            context=CONTEXT_PATH_RESPONSE,
        )
        inst.inject(iface_b, seed)
        assert inst.read_path_table(dest)["found"], "seed path not created"
        assert inst.read_announce_table(dest)["found"] is False, (
            "seeding unexpectedly scheduled a retransmit"
        )

        transport_id = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        tag1 = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        tag2 = secrets.token_bytes(TRUNCATED_HASH_BYTES)

        # PR #1 (tag1) -> answered: a cached-announce rebroadcast is scheduled
        # on the interface the request arrived on, with block_rebroadcasts set.
        pr1 = build_path_request(behavioral.bridge, dest,
                                 transport_id=transport_id, tag=tag1)
        inst.inject(iface_a, pr1)
        ans = inst.read_announce_table(dest)
        assert ans["found"] and ans["block_rebroadcasts"] is True, (
            f"PR with a fresh tag was not answered (no scheduled rebroadcast): {ans}"
        )
        assert ans["attached_interface"] == iface_a, (
            "path-request answer scheduled on the wrong interface"
        )

        # Clear the scheduled answer so we can observe PR #2's (non-)effect.
        guard = 0
        while inst.read_announce_table(dest)["found"]:
            guard += 1
            assert guard <= 6, "could not drain the scheduled answer"
            inst.set_announce_timestamp(dest, retransmit_timeout=0)
            inst.force_cull()
        inst.drain_tx(iface_a)
        inst.drain_tx(iface_b)

        # PR #2 (SAME tag) -> duplicate unique_tag -> ignored -> nothing scheduled.
        pr2 = build_path_request(behavioral.bridge, dest,
                                 transport_id=transport_id, tag=tag1)
        inst.inject(iface_a, pr2)
        assert inst.read_announce_table(dest)["found"] is False, (
            "a path request with a duplicate tag was acted on — per-tag dedup "
            "(Transport.py:2895) is absent"
        )

        # PR #3 (DIFFERENT tag) -> acted on -> answer scheduled again.
        pr3 = build_path_request(behavioral.bridge, dest,
                                 transport_id=transport_id, tag=tag2)
        inst.inject(iface_a, pr3)
        ans3 = inst.read_announce_table(dest)
        assert ans3["found"] and ans3["block_rebroadcasts"] is True, (
            "a path request with a fresh tag was NOT acted on — dedup is keyed "
            "on destination only, ignoring the tag (Transport.py:2891)"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "announce_build", "behavioral_attach_mock_interface",
              "behavioral_inject", "behavioral_read_path_table"],
    verifies=(
        "Transport.inbound gates an announce on its Ed25519 signature BEFORE any "
        "state change: a genuine announce injected on an interface creates a "
        "path-table entry (positive control), but a byte-for-byte identical "
        "announce with a single tampered signature byte creates NO path-table "
        "entry — validate_announce fails and the announce is dropped before the "
        "path table is touched (Transport.py announce_signature gate). An impl "
        "that learns paths from unverified announces is trivially route-poisoned"
    ),
)
def test_announce_signature_gate_blocks_state_change(behavioral):
    """Inject a valid announce -> path learned; inject the same announce with a
    corrupted signature -> path NOT learned. Discriminating both ways: an impl
    that skips the signature check learns the tampered path (fails the negative);
    one that drops all announces never learns the valid path (fails the positive
    control). Two fresh Transport instances so the negative starts from a clean
    table and cannot inherit the positive control's entry."""
    # Positive control: a genuine announce is admitted into the path table.
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        valid, dest_hash, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="conformance",
            aspects=["sig_gate"],
            wire_hops=0,
        )
        inst.inject(iface, valid)
        time.sleep(0.2)
        assert inst.read_path_table(dest_hash)["found"] is True, (
            "a valid announce did not create a path-table entry (positive control)"
        )
    finally:
        behavioral.cleanup()

    # Negative: the SAME announce with one tampered signature byte must be
    # dropped before any path-table write. The signature is the last 64 bytes of
    # an announce that carries no ratchet and no app_data.
    inst2 = behavioral.start(enable_transport=True)
    try:
        iface2 = inst2.attach_mock_interface("a", mode="FULL")
        valid2, dest_hash2, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="conformance",
            aspects=["sig_gate"],
            wire_hops=0,
        )
        tampered = bytearray(valid2)
        tampered[-1] ^= 0x01  # flip a bit in the trailing Ed25519 signature
        inst2.inject(iface2, bytes(tampered))
        time.sleep(0.2)
        assert inst2.read_path_table(dest_hash2)["found"] is False, (
            "a tampered-signature announce created a path-table entry — the "
            "inbound signature gate did not fire before the state change"
        )
    finally:
        behavioral.cleanup()
