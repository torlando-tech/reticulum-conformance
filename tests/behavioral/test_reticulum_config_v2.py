"""Behavioral conformance — held-announce release ORDER (reticulum_config V2).

Closes the held-announce-release-order gap. When an interface is ingress-rate
limiting, inbound announces for unknown destinations are HELD rather than
processed (Transport.py:1703-1704 -> Interface.hold_announce). They are released
one at a time by Interface.process_held_announces (Interfaces/Interface.py:
234-253), which on each pass selects the held announce with the FEWEST hops:

    min_hops = PATHFINDER_M
    for destination_hash in self.held_announces:
        if announce_packet.hops < min_hops:
            min_hops = announce_packet.hops
            selected_announce_packet = announce_packet

This lowest-hops-first ordering is pure decision logic (no clock): the closest
destinations are surfaced first when the network calms down. The harness holds
several genuine announces at distinct hop counts via the REAL hold_announce API,
runs the REAL release pass (with ic_held_release backdated to open the time gate,
no sleep), and observes which destination was released — never reimplementing the
selection. The release order is anchored on the hop counts the test ITSELF
stamped into each announce header, not on the impl echoing anything.

The 5-second release CADENCE is a timing ceiling (deferred); only the ORDERING
decision is exercised here.
"""

import secrets

from conformance import conformance_case
from tests.behavioral.packet_builders import build_announce_from_destination


__category_title__ = "Transport Announce Hooks"
__category_order__ = 20


def _build_announce(bridge, hops, aspect):
    """Build a genuine signed announce for a fresh identity with `hops` already
    stamped into its header (raw[1]), via the honest announce_build path."""
    raw, dest, _pub = build_announce_from_destination(
        bridge,
        identity_private_key=secrets.token_bytes(64),
        app_name="testapp", aspects=[aspect],
        wire_hops=hops,
    )
    return raw, dest


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build",
              "hold_and_release_announce"],
    verifies=(
        "Interface.process_held_announces releases held announces LOWEST-HOPS "
        "FIRST (Interfaces/Interface.py:240-251). Three genuine announces are "
        "held at hops 5, 2 and 8 (inserted in that order); the first release "
        "pass selects the hops==2 destination — NOT the first-inserted hops==5 "
        "one — proving the selection is by hop count, not insertion order "
        "(positive + discriminator). The hops 5 and 8 destinations REMAIN held "
        "(negative — only one, the minimum, is released per pass). A second pass "
        "then releases hops 5 before hops 8, pinning the full ascending ORDER. "
        "Hop counts are the values the test stamped into each announce header"
    ),
)
def test_held_announce_release_is_lowest_hops_first(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        # Insertion order deliberately != hop order, so "first released" can only
        # be explained by the minimum-hops rule, not by ordering of insertion.
        a5, d5 = _build_announce(behavioral.bridge, hops=5, aspect="h5")
        a2, d2 = _build_announce(behavioral.bridge, hops=2, aspect="h2")
        a8, d8 = _build_announce(behavioral.bridge, hops=8, aspect="h8")
        assert len({d5, d2, d8}) == 3, "announces must target distinct destinations"

        first = inst.hold_and_release_announce(iface, [a5, a2, a8])

        # The harness re-read the hop counts off the real held packets; confirm
        # they match what we stamped (so the assertion below is meaningful).
        assert first["hops"] == {d5.hex(): 5, d2.hex(): 2, d8.hex(): 8}, (
            f"held packet hop counts not as injected: {first['hops']}"
        )
        assert set(first["held_before"]) == {d5.hex(), d2.hex(), d8.hex()}, (
            f"all three announces should be held before release: {first['held_before']}"
        )
        # POSITIVE + discriminator: the minimum-hops (2) destination is released,
        # even though hops-5 was inserted first.
        assert first["released"] == [d2.hex()], (
            f"first release must be the lowest-hops (hops=2) destination "
            f"{d2.hex()}, got {first['released']}"
        )
        # NEGATIVE: the two higher-hops announces stay held — only ONE (the
        # minimum) is released per pass.
        assert set(first["held_after"]) == {d5.hex(), d8.hex()}, (
            f"higher-hops announces must remain held, got {first['held_after']}"
        )

        # ORDER: a second pass over the remaining held set releases hops-5 next
        # (still lower than hops-8), leaving hops-8 held last.
        second = inst.hold_and_release_announce(iface, [])
        assert second["released"] == [d5.hex()], (
            f"second release must be the next-lowest (hops=5) destination "
            f"{d5.hex()}, got {second['released']}"
        )
        assert set(second["held_after"]) == {d8.hex()}, (
            f"only the highest-hops (hops=8) announce should remain held, got "
            f"{second['held_after']}"
        )
    finally:
        behavioral.cleanup()
