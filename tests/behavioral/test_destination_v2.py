"""Behavioral V2 destination gaps: inbound type-match gate.

Transport.inbound delivers a packet to a registered destination ONLY if the
destination's type equals the packet's flag destination-type
(Transport.py:2155: `if destination and destination.type == packet.destination_type`).
A packet whose flag dest-type differs from the registered destination's type is
silently dropped before delivery. No prior test injected a wrong-type packet to a
registered destination hash.
"""

import secrets

from conformance import conformance_case
from tests.behavioral.packet_builders import build_data_packet


__category_title__ = "Transport Behavior"
__category_order__ = 19


@conformance_case(
    commands=["start", "behavioral_attach_mock_interface", "behavioral_inject",
              "behavioral_register_destination",
              "behavioral_read_destination_deliveries",
              "packet_build", "packet_unpack"],
    verifies=(
        "Transport delivers an inbound packet to a registered destination only "
        "when the packet's flag destination-type matches the destination's type "
        "(Transport.py:2155). A PLAIN destination receives a PLAIN-typed DATA "
        "packet addressed to its hash (delivered to the packet callback — "
        "positive control), but a SINGLE-typed DATA packet addressed to the SAME "
        "hash is silently dropped (not delivered), because SINGLE != PLAIN. An "
        "impl that delivers on a hash match alone, ignoring the type bits, would "
        "mis-route cross-type traffic"
    ),
)
def test_inbound_destination_type_match_required(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        # A PLAIN destination (cleartext, no decryption) so delivery is observable
        # without needing to encrypt to its key.
        dest = inst.register_destination(
            app_name="conformance", aspects=["dest_type_match"], type="plain",
        )

        # Positive control: a PLAIN DATA packet to this hash IS delivered.
        payload = secrets.token_bytes(24)
        plain_pkt = build_data_packet(
            behavioral.bridge, dest, destination_type="plain", hops=0, payload=payload,
        )
        inst.inject(iface, plain_pkt)
        import time
        time.sleep(0.15)
        after_plain = inst.read_destination_deliveries(dest)
        assert after_plain["count"] == 1, (
            f"a matching-type (PLAIN) packet was not delivered: {after_plain!r}"
        )
        assert after_plain["deliveries"][0] == payload.hex(), (
            f"delivered payload mismatch: {after_plain!r}"
        )

        # Negative: a SINGLE-typed DATA packet to the SAME hash is dropped
        # (SINGLE != PLAIN) — the delivery count does not increase.
        single_pkt = build_data_packet(
            behavioral.bridge, dest, destination_type="single", hops=0,
            payload=secrets.token_bytes(24),
        )
        inst.inject(iface, single_pkt)
        time.sleep(0.15)
        after_single = inst.read_destination_deliveries(dest)
        assert after_single["count"] == 1, (
            f"a SINGLE-typed packet was delivered to a PLAIN destination — the "
            f"inbound type-match gate (Transport.py:2155) did not fire: {after_single!r}"
        )
    finally:
        behavioral.cleanup()
