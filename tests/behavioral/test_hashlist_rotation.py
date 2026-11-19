"""
Behavioral test: packet-hashlist rotation, bounded retention, one live
previous generation (§5 CORE).

The dedup window is not free: every implementation must BOUND the hashes it
remembers, or a long-running node grows an unbounded set and dies. RNS keeps
two generations and rotates the active one once it exceeds half the budget
(`hashlist_maxsize // 2`): the old generation becomes the previous one, and
the generation before that is forgotten. Eviction is what bounds memory —
columba#1222 was an implementation whose budget was the flat desktop constant
instead of the platform budget, so the window outgrew a 201 MB-heap Android
device and the transport process OOMed (reticulum-kt#102).

The rotation TRIGGER is an implementation detail (RNS 1.3.1 rotates inside
`Transport.jobs()`; reticulum-kt rotates inside `add_packet_hash`), so nothing
here asserts WHEN rotation runs. The commands drive the observable state:
`behavioral_hashlist_limit` pins a small budget and resets both generations,
`behavioral_hashlist_stats` reports per-generation entry counts, and
`behavioral_force_cull` runs one synchronous `jobs()` pass so a reference-style
implementation rotates too. The packet traffic itself is real
`behavioral_packet_filter` calls (the hash gate plus the remember step).

Both tests SKIP — never pass vacuously — when a bridge does not expose the
budget seam, and fail on any behavioral difference once it does.
"""

import secrets

import pytest

from bridge_client import BridgeError
from conformance import conformance_case


__category_title__ = "Transport Behavior"
__category_order__ = 19

# Total budget for BOTH generations. Rotation happens at BUDGET // 2, so a
# generation after rotation holds at most BUDGET // 2 + 1 entries and the two
# generations together stay within BUDGET + 2.
BUDGET = 32
HALF = BUDGET // 2
BATCH = HALF + 2  # > HALF, so a single batch forces at least one rotation


def _set_budget(inst):
    """Pin the window budget and reset both generations.

    Skips (does not pass) when the bridge does not implement the seam: a bridge
    that cannot be told what its budget is cannot be measured on it, and
    pretending it passed would be a false conformance claim. Surface gaps are
    reported authoritatively by tools/kotlin_gap.py; once a bridge exposes the
    seam, every assertion below is enforced.
    """
    try:
        pinned = inst.hashlist_limit(BUDGET)
        inst.hashlist_stats()
    except BridgeError as exc:
        message = str(exc).lower()
        if "unknown" in message and "command" in message:
            pytest.skip(
                "bridge exposes no packet-hashlist window seam "
                f"(behavioral_hashlist_limit/stats): {exc}"
            )
        raise
    return pinned


def _feed(inst, count):
    """Send `count` distinct DATA packets to a SINGLE destination through the
    real packet filter, oldest first. Each is fresh, so each must be accepted
    and remembered; the returned raws replay those exact packets later."""
    raws = []
    for _ in range(count):
        built = inst.bridge.execute(
            "packet_build", dest_type="single", packet_type=0,
            data=secrets.token_bytes(16).hex(),
        )
        raw = bytes.fromhex(built["raw"])
        accepted = inst.packet_filter(raw, remember=True)
        assert accepted["accepted"] is True, (
            "a fresh packet was dropped inside the window — the hashlist is "
            "not being reset by behavioral_hashlist_limit"
        )
        raws.append(raw)
    return raws


@conformance_case(
    commands=["start", "packet_build", "packet_filter", "hashlist_limit",
              "hashlist_stats", "force_cull"],
    verifies=(
        "After the active generation exceeds half the configured budget and a "
        "jobs() pass runs, the previous generation is still consulted for "
        "duplicates: a packet seen before the rotation is DROPPED on replay "
        "(one live previous generation, not a flush)"
    ),
)
def test_hashlist_rotation_keeps_previous_generation_deduped(behavioral):
    """A rotation must not orphan the generation it just retired: the retired
    hashes stay in the previous generation and keep rejecting replays until the
    *next* rotation. An implementation that flushes instead of aging out would
    re-accept a packet it already saw."""
    inst = behavioral.start()
    try:
        _set_budget(inst)

        batch = _feed(inst, BATCH)
        inst.force_cull()  # reference-style impls rotate inside jobs()

        stats = inst.hashlist_stats()
        assert stats["previous"] > 0, (
            "no previous generation after exceeding half the budget — the "
            "window is not aging out, it is being flushed or never rotated"
        )
        assert stats["total"] <= BUDGET + 2, (
            f"retained {stats['total']} hashes for a budget of {stats['limit']} "
            "— at most one generation past the active window may survive"
        )

        replay = inst.packet_filter(batch[0], remember=True)
        assert replay["accepted"] is False, (
            "the oldest packet in the previous generation was re-accepted — a "
            "rotation dropped the history it is required to keep"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "packet_build", "packet_filter", "hashlist_limit",
              "hashlist_stats", "force_cull"],
    verifies=(
        "Two rotations with a budget of 32: the oldest packet of the first "
        "batch is evicted (accepted again) while the newest and second-newest "
        "packets of the second batch stay deduplicated, and total retention "
        "stays within budget + 2 — an unbounded or mis-sized window (columba"
        "#1222 / reticulum-kt#102) fails the retention bound"
    ),
)
def test_hashlist_rotation_evicts_oldest_and_bounds_retention(behavioral):
    """Eviction is the point of the rotation: hashes older than the previous
    generation MUST be forgotten, so retention tracks the budget instead of
    process history. Sending two batches drives a second rotation; the first
    batch falls out of both generations while the second batch stays live."""
    inst = behavioral.start()
    try:
        _set_budget(inst)

        first = _feed(inst, BATCH)
        inst.force_cull()
        second = _feed(inst, BATCH)
        inst.force_cull()

        stats = inst.hashlist_stats()
        assert stats["total"] <= BUDGET + 2, (
            f"retained {stats['total']} hashes for a budget of {stats['limit']} "
            "across two rotations — the window is not bounded by its budget"
        )

        oldest = inst.packet_filter(first[0], remember=True)
        assert oldest["accepted"] is True, (
            "the first batch is still deduplicated two rotations later — the "
            "window exceeds its configured budget and never evicts"
        )

        newest = inst.packet_filter(second[-1], remember=True)
        assert newest["accepted"] is False, (
            "the newest packet was forgotten immediately — the window must "
            "retain the active generation in full"
        )

        retained = inst.packet_filter(second[1], remember=True)
        assert retained["accepted"] is False, (
            "a packet from the previous generation was forgotten before the "
            "next rotation — eviction is running one generation too early"
        )
    finally:
        behavioral.cleanup()
