"""
Behavioral test: path-table replacement rules.

Python `Transport.py:1620-1631` accepts a same-or-better-hop announce into the
path table only when BOTH:
  (a) random_blob is new (replay protection), AND
  (b) announce_emitted > path_timebase (strictly newer than anything we've seen)

Reticulum-kt's initial port checked only (a), which let stale PATH_RESPONSE
announces — carrying an older emission timestamp but a novel random_blob
(because they're re-emitted from a cache) — overwrite a fresh direct path.

This scenario catches that drift: inject a fresh direct announce, then inject
a stale PATH_RESPONSE carrying an older emission timestamp, then ask the
Transport for its current path — the answer (visible via what it re-emits on
a retransmit) should carry the hop count from the fresh announce, not the
stale one.
"""

import secrets
import time

from tests.behavioral.packet_builders import (
    build_announce_from_destination,
    first_announce,
)


def test_stale_path_response_does_not_overwrite_fresh_path(behavioral):
    """A PATH_RESPONSE-contextual announce with an older emission timestamp
    and more hops must NOT replace a fresh direct announce in the path table.

    Observable via the retransmitted announce on a second interface: its hops
    value reflects whichever path the impl has cached. If the stale one won,
    we'd see hops=4+1=5 retransmitted. If the fresh one won (correct), we see
    hops=0+1=1 retransmitted."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        iface_b = inst.attach_mock_interface("b", mode="FULL")

        announcer_private = secrets.token_bytes(64)

        # 1. Fresh direct announce: wire_hops=0, random=R1, ts=1_000_000_100
        fresh, dest_hash, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl"],
            random_prefix=b"\xA1\xA1\xA1\xA1\xA1",
            emission_ts=1_000_000_100,
            wire_hops=0,
        )
        inst.inject(iface_a, fresh)
        time.sleep(0.5)  # let the announce settle into announce_table

        # 2. Stale PATH_RESPONSE: wire_hops=4, random=R0, ts=1_000_000_050 (older)
        stale, stale_dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=announcer_private,
            app_name="testapp",
            aspects=["pathrepl"],
            random_prefix=b"\xA0\xA0\xA0\xA0\xA0",
            emission_ts=1_000_000_050,
            wire_hops=4,
            context=0x0B,  # CONTEXT_PATH_RESPONSE
        )
        assert stale_dest == dest_hash, "builder should produce same dest hash"
        inst.inject(iface_a, stale)

        # Wait long enough for retransmit window (PATHFINDER_RW ~2s)
        time.sleep(3.0)

        # Drain iface_b. The retransmit should reflect the WINNING path entry.
        b_emissions = inst.drain_tx(iface_b)
        forwarded = first_announce(b_emissions)
        assert forwarded is not None, (
            f"no announce retransmit on iface_b; got {len(b_emissions)} packets"
        )
        # With the Python replacement rule, the stale PATH_RESPONSE (older ts)
        # does NOT replace the fresh entry. The retransmitted hops is therefore
        # 0+1 = 1 (fresh), not 4+1 = 5 (stale).
        assert forwarded["hops"] == 1, (
            f"path table retained stale PATH_RESPONSE: got hops={forwarded['hops']}, "
            f"expected 1 (fresh) or 5 (stale-won). Value {forwarded['hops']} "
            f"implies the impl chose the stale/older announce."
        )
    finally:
        behavioral.cleanup()
