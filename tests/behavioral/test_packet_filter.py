"""
Behavioral tests: Transport.packet_filter gating + the announce hop ceiling
(§2b / §4a CORE + IMPORTANT).

`Transport.packet_filter` (RNS Transport.py:1334-1384) is the inbound gate
every received packet must clear before Transport will act on it. Beyond the
hashlist replay/loop drop already covered by `test_replay_dedup.py`, it encodes
several discriminating protocol rules that the rest of the suite never asserts:

  * transport_id "other transport instance" drop — a HEADER_2 (transport-relayed)
    non-announce packet whose `transport_id` is not THIS instance's identity hash
    is dropped (it was relayed toward a different transport), Transport.py:1340-1343.
  * PLAIN / GROUP non-announce TTL ceiling — these destination types are
    single-hop-ish: a non-announce PLAIN/GROUP packet with hops > 1 is dropped,
    Transport.py:1352-1369. (packet_filter reads the wire `hops` value directly;
    the +1 receive increment happens in inbound BEFORE the filter, so this command
    — which calls packet_filter on the raw packet — sees exactly the wire hops.)
  * context-bypass exemptions — RESOURCE / CHANNEL (and KEEPALIVE / RESOURCE_REQ /
    RESOURCE_PRF / CACHE_REQUEST) packets are accepted BEFORE the hashlist check,
    so they are never subject to the replay/loop drop, Transport.py:1345-1350.

A separate but adjacent rule is the announce hop ceiling (PATHFINDER_M = 128,
Transport.py:63/1748): an announce is admitted into the path table only while
`packet.hops < PATHFINDER_M + 1`. Because inbound applies the +1 receive
increment first, a wire announce at 127 hops becomes a 128-hop path entry (the
last admissible value) and one at 128 hops becomes 129 and is rejected. This is
observed via `read_path_table` rather than packet_filter (packet_filter itself
does not enforce the ceiling for SINGLE announces — the admission gate does).

Every test drives the real RNS `Transport.packet_filter` / inbound path through
the bridge; no filtering logic is reimplemented in the harness.
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    CONTEXT_CHANNEL,
    CONTEXT_NONE,
    CONTEXT_RESOURCE,
    HEADER_2,
    build_announce_from_destination,
    build_data_packet,
)


__category_title__ = "Transport Behavior"
__category_order__ = 19


@conformance_case(
    commands=["start", "packet_build", "packet_unpack", "packet_filter"],
    verifies=(
        "A HEADER_2 (transport-relayed) non-announce SINGLE DATA packet whose "
        "transport_id is NOT this instance's identity hash is DROPPED by "
        "Transport.packet_filter (accepted False — 'packet for another transport "
        "instance', Transport.py:1340-1343); a byte-identical-shape packet whose "
        "transport_id EQUALS this instance's identity hash is accepted True "
        "(positive control)"
    ),
)
def test_transport_id_other_instance_drop(behavioral):
    """The 'other transport instance' filter: a relayed (HEADER_2) non-announce
    packet carrying a transport_id that is not ours is meant for a different
    transport and must be dropped; one carrying our own identity hash as the
    transport_id is for us and passes the filter.

    Discriminating both ways: an impl that omits the transport_id filter accepts
    the foreign-id packet (fails the negative); an impl that blanket-drops every
    HEADER_2 packet rejects the own-id packet (fails the positive control)."""
    inst = behavioral.start()
    try:
        dest_hash = secrets.token_bytes(16)

        # Negative: transport_id of a DIFFERENT transport instance.
        other_tid = secrets.token_bytes(16)
        assert other_tid != inst.identity_hash, "random transport_id collided with own"
        foreign = build_data_packet(
            behavioral.bridge,
            dest_hash,
            header_type=HEADER_2,
            transport_id=other_tid,
            destination_type="single",
            hops=1,
            payload=secrets.token_bytes(8),
        )
        # remember=False so the verdict is purely the transport_id gate, with no
        # hashlist interaction (the two packets hash identically — transport_id
        # is excluded from the packet hash).
        verdict = inst.packet_filter(foreign, remember=False)
        assert verdict["accepted"] is False, (
            "HEADER_2 non-announce packet for ANOTHER transport instance was NOT "
            "dropped — the 'other transport instance' filter is absent "
            "(Transport.py:1340-1343)"
        )

        # Positive control: transport_id == our own identity hash → passes the
        # filter (it is addressed to us).
        ours = build_data_packet(
            behavioral.bridge,
            dest_hash,
            header_type=HEADER_2,
            transport_id=inst.identity_hash,
            destination_type="single",
            hops=1,
            payload=secrets.token_bytes(8),
        )
        verdict_ok = inst.packet_filter(ours, remember=False)
        assert verdict_ok["accepted"] is True, (
            "HEADER_2 non-announce packet whose transport_id IS this instance's "
            "identity hash was dropped — the filter is over-rejecting relayed "
            "packets meant for us"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_path_table"],
    verifies=(
        "The PATHFINDER_M=128 announce hop ceiling: an announce injected at "
        "wire_hops=128 (129 after the +1 receive increment) is NOT admitted to "
        "the path table (read_path_table found False), while a distinct fresh "
        "destination's announce at wire_hops=127 IS admitted at hops==128 (the "
        "last admissible value) — Transport.py:1748"
    ),
)
def test_pathfinder_m_hop_ceiling(behavioral):
    """The max-hop ceiling (Transport.py:1748: local_and_hops_condition requires
    `packet.hops < PATHFINDER_M+1`). inbound increments hops by 1 on receive
    (Transport.py:1454), so a wire announce at 128 hops is evaluated at 129 and
    rejected, whereas one at 127 hops is evaluated at 128 and admitted.

    Two distinct fresh identities are used so the drop and the admit are
    independent path-table entries — the admit is the positive control proving
    the same inject mechanism DOES learn a sub-ceiling announce, so the drop is
    the ceiling at work and not a vacuous 'announce never processed'."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")

        # Over the ceiling: wire_hops=128 -> 129 after +1 increment -> rejected.
        over_priv = secrets.token_bytes(64)
        over_raw, over_dest, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=over_priv,
            app_name="testapp",
            aspects=["ceiling-over"],
            emission_ts=1_000_000_200,
            wire_hops=128,
        )
        inst.inject(iface_a, over_raw)

        # At the ceiling: wire_hops=127 -> 128 after +1 increment -> admitted.
        at_priv = secrets.token_bytes(64)
        at_raw, at_dest, _pub2 = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=at_priv,
            app_name="testapp",
            aspects=["ceiling-at"],
            emission_ts=1_000_000_201,
            wire_hops=127,
        )
        assert at_dest != over_dest, "fresh identities must yield distinct dests"
        inst.inject(iface_a, at_raw)

        # The announce path-table write is synchronous in inbound; a small
        # settle margin (not aging) matches the sibling path-table tests.
        time.sleep(0.2)

        over_pt = inst.read_path_table(over_dest)
        assert over_pt["found"] is False, (
            "announce at wire_hops=128 (129 after +1) was admitted to the path "
            "table — the PATHFINDER_M hop ceiling is not enforced "
            "(Transport.py:1748)"
        )

        at_pt = inst.read_path_table(at_dest)
        assert at_pt["found"] is True, (
            "announce at wire_hops=127 (128 after +1) was NOT admitted — the "
            "ceiling check is rejecting the last admissible hop count (the drop "
            "assertion above would be vacuous)"
        )
        assert at_pt["hops"] == 128, (
            f"path learned at the ceiling should be 128 hops (wire 127 + receive "
            f"increment), got {at_pt['hops']}"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "packet_build", "packet_unpack", "packet_filter"],
    verifies=(
        "A non-announce PLAIN DATA packet with hops==2 is DROPPED by "
        "Transport.packet_filter (accepted False — PLAIN TTL ceiling, "
        "Transport.py:1352-1358), while the same-shape packet with hops==1 is "
        "accepted True (positive control)"
    ),
)
def test_plain_nonannounce_hops_gt1_drop(behavioral):
    """PLAIN non-announce packets are dropped once hops > 1. packet_filter reads
    the wire hops directly (the +1 receive increment happens earlier in inbound),
    so a hops==2 packet is dropped and a hops==1 packet is accepted.

    Discriminating both ways: an impl missing the PLAIN TTL drop accepts the
    hops==2 packet (fails the negative); an impl that drops ALL PLAIN packets
    rejects the hops==1 packet (fails the positive control)."""
    inst = behavioral.start()
    try:
        dest_hash = secrets.token_bytes(16)

        drop = build_data_packet(
            behavioral.bridge,
            dest_hash,
            destination_type="plain",
            hops=2,
            payload=secrets.token_bytes(8),
        )
        verdict = inst.packet_filter(drop, remember=False)
        assert verdict["accepted"] is False, (
            "PLAIN non-announce packet with hops=2 was NOT dropped — the PLAIN "
            "hops>1 TTL ceiling is absent (Transport.py:1352-1358)"
        )

        keep = build_data_packet(
            behavioral.bridge,
            dest_hash,
            destination_type="plain",
            hops=1,
            payload=secrets.token_bytes(8),
        )
        verdict_ok = inst.packet_filter(keep, remember=False)
        assert verdict_ok["accepted"] is True, (
            "PLAIN non-announce packet with hops=1 was dropped — the filter is "
            "rejecting in-budget PLAIN packets"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "packet_build", "packet_unpack", "packet_filter"],
    verifies=(
        "A non-announce GROUP DATA packet with hops==2 is DROPPED by "
        "Transport.packet_filter (accepted False — GROUP TTL ceiling, "
        "Transport.py:1363-1369), while the same-shape packet with hops==1 is "
        "accepted True (positive control)"
    ),
)
def test_group_nonannounce_hops_gt1_drop(behavioral):
    """GROUP non-announce packets are dropped once hops > 1 — the GROUP twin of
    the PLAIN TTL ceiling. Exercises the bridge's `group` packet_build branch.

    Discriminating both ways: an impl missing the GROUP TTL drop accepts the
    hops==2 packet (fails the negative); an impl that drops ALL GROUP packets
    rejects the hops==1 packet (fails the positive control)."""
    inst = behavioral.start()
    try:
        dest_hash = secrets.token_bytes(16)

        drop = build_data_packet(
            behavioral.bridge,
            dest_hash,
            destination_type="group",
            hops=2,
            payload=secrets.token_bytes(8),
        )
        verdict = inst.packet_filter(drop, remember=False)
        assert verdict["accepted"] is False, (
            "GROUP non-announce packet with hops=2 was NOT dropped — the GROUP "
            "hops>1 TTL ceiling is absent (Transport.py:1363-1369)"
        )

        keep = build_data_packet(
            behavioral.bridge,
            dest_hash,
            destination_type="group",
            hops=1,
            payload=secrets.token_bytes(8),
        )
        verdict_ok = inst.packet_filter(keep, remember=False)
        assert verdict_ok["accepted"] is True, (
            "GROUP non-announce packet with hops=1 was dropped — the filter is "
            "rejecting in-budget GROUP packets"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "packet_build", "packet_unpack", "packet_filter"],
    verifies=(
        "Context-bypass exemption: a SINGLE DATA packet with context=RESOURCE "
        "(0x01) and one with context=CHANNEL (0x0E), each run through "
        "Transport.packet_filter TWICE with remember=True, are accepted BOTH "
        "times — these contexts are exempted before the hashlist replay drop "
        "(Transport.py:1345-1350); a context=NONE SINGLE DATA control run the "
        "same way is accepted then DROPPED on replay, proving the exemption is "
        "the difference"
    ),
)
def test_context_bypass_exempts_from_hashlist(behavioral):
    """RESOURCE / CHANNEL (and the other four bypass contexts) return True from
    packet_filter BEFORE the packet-hashlist check, so a byte-identical replay
    of such a packet is still accepted even though its hash was remembered. The
    context=NONE SINGLE DATA contrast — accepted then dropped under the identical
    twice-with-remember pattern — is the positive control that pins the True/True
    result to the context exemption rather than a filter that never drops.

    Discriminating: an impl missing the bypass would hashlist-drop the second
    RESOURCE/CHANNEL sighting (fails True-both-times); an impl that never dedups
    would accept the second NONE sighting (fails the contrast)."""
    inst = behavioral.start()
    try:
        # Build each raw packet ONCE and filter the same bytes twice, so the
        # second sighting is a genuine byte-identical replay (same packet hash).
        for ctx, label in ((CONTEXT_RESOURCE, "RESOURCE"), (CONTEXT_CHANNEL, "CHANNEL")):
            raw = build_data_packet(
                behavioral.bridge,
                secrets.token_bytes(16),
                destination_type="single",
                context=ctx,
                hops=0,
                payload=secrets.token_bytes(8),
            )
            first = inst.packet_filter(raw, remember=True)
            assert first["accepted"] is True, (
                f"first sighting of a context={label} packet must be accepted"
            )
            assert first["remembered"] is True, (
                f"context={label} packet hash should be recorded with remember=True"
            )
            replay = inst.packet_filter(raw, remember=True)
            assert replay["packet_hash"] == first["packet_hash"], (
                "replay must be the same packet (identical hash)"
            )
            assert replay["accepted"] is True, (
                f"a replayed context={label} packet was DROPPED by the hashlist — "
                f"RNS exempts this context before the replay check "
                f"(Transport.py:1345-1350)"
            )

        # Contrast / positive control: a context=NONE SINGLE DATA packet under
        # the identical twice-with-remember pattern IS dropped on replay. This
        # proves the True-both-times results above are the context exemption at
        # work, not a filter that accepts everything.
        none_raw = build_data_packet(
            behavioral.bridge,
            secrets.token_bytes(16),
            destination_type="single",
            context=CONTEXT_NONE,
            hops=0,
            payload=secrets.token_bytes(8),
        )
        none_first = inst.packet_filter(none_raw, remember=True)
        assert none_first["accepted"] is True, (
            "first sighting of a context=NONE SINGLE DATA packet must be accepted"
        )
        assert none_first["remembered"] is True
        none_replay = inst.packet_filter(none_raw, remember=True)
        assert none_replay["packet_hash"] == none_first["packet_hash"]
        assert none_replay["accepted"] is False, (
            "a replayed context=NONE SINGLE DATA packet was NOT dropped — the "
            "contrast control proves nothing about the RESOURCE/CHANNEL exemption "
            "if the filter never drops"
        )
    finally:
        behavioral.cleanup()
