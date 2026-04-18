"""
Behavioral test: per-hop +1 arithmetic on announce receive.

When an announce arrives on the wire at hops=N, the receiving Transport must
treat it as being N+1 hops from the sender. The observable effect: if the
Transport then re-emits that announce on another interface (which happens when
enable_transport=True and the received announce is from an external interface),
the emitted bytes must carry hops=N+1.

This is the minimum behavioral sanity check. Every other Transport behavior
depends on this being correct.
"""

import secrets
import time

import pytest

from tests.behavioral.packet_builders import (
    build_announce_from_destination,
    first_announce,
)


def test_hop_increment_on_receive(behavioral):
    """Inject announce with wire_hops=3 on iface_a with transport enabled;
    the retransmission on iface_b should carry hops=4 (the received value
    after the +1 increment)."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        # Build a valid announce from a fresh identity
        announcer_private = secrets.token_bytes(64)
        raw, dest_hash, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["behav"],
            random_prefix=b"\x00" * 5,
            emission_ts=1_000_000_000,
            wire_hops=3,
        )

        inst.inject(iface_a, raw)

        # Python RNS processes announce retransmits on a timer loop
        # (PATHFINDER_RW ≈ 2s random wait + job loop interval). Sleep long enough
        # for the announce to propagate through the queue. Once we add a
        # test-controlled clock + tick, this becomes deterministic.
        time.sleep(3.0)

        # Drain both interfaces. iface_a should NOT see a retransmit of its own
        # received packet; iface_b should see the forwarded announce with hops=4.
        a_emissions = inst.drain_tx(iface_a)
        b_emissions = inst.drain_tx(iface_b)

        # Python RNS's announce-table broadcast does NOT skip the receiving
        # interface — duplicate suppression is the receiver's job via the
        # packet hashlist. So iface_a may also see the retransmit. What we
        # assert is that wherever the retransmit lands, it carries hops=4
        # (post +1-increment-on-receive from wire_hops=3).
        forwarded = first_announce(b_emissions) or first_announce(a_emissions)
        assert forwarded is not None, (
            "Transport did not re-emit the announce on any interface"
        )
        assert forwarded["hops"] == 4, (
            f"Expected hops=4 after +1 increment, got hops={forwarded['hops']}"
        )
        assert forwarded["destination_hash"] == dest_hash, (
            "Forwarded announce targets wrong destination hash"
        )
        # iface_b MUST see the retransmit (it's an OUT interface distinct
        # from the receiving one) — that's the real "forwarded" evidence.
        on_b = first_announce(b_emissions)
        assert on_b is not None, (
            "Expected announce retransmit on iface_b, got nothing"
        )
        assert on_b["hops"] == 4, (
            f"Expected hops=4 on iface_b, got hops={on_b['hops']}"
        )
    finally:
        behavioral.cleanup()


def test_hop_increment_when_transport_disabled(behavioral):
    """With enable_transport=False and no local clients, Transport should NOT
    re-emit received announces on any other interface. (This is the gate
    Python `Transport.py:1741` and reticulum-kt's corresponding line enforce.)
    """
    inst = behavioral.start(enable_transport=False)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        announcer_private = secrets.token_bytes(64)
        raw, _dest, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["behav"],
            random_prefix=b"\x01" * 5,
            emission_ts=1_000_000_001,
            wire_hops=0,
        )

        inst.inject(iface_a, raw)

        # Wait past the PATHFINDER_RW retransmit window before draining.
        # Without this sleep the test would pass even if transport were
        # actually enabled (the retransmit hasn't fired yet at inject time),
        # producing a false positive. Sleeping ensures that if Transport is
        # going to emit at all, it has done so before we drain.
        time.sleep(3.0)

        assert first_announce(inst.drain_tx(iface_a)) is None
        assert first_announce(inst.drain_tx(iface_b)) is None, (
            "Announce was rebroadcast with transport disabled and no local clients"
        )
    finally:
        behavioral.cleanup()
