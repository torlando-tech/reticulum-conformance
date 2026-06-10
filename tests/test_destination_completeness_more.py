"""Destination conformance — additional completeness gaps (Opus).

Two RNS.Destination wire-encoding behaviors that the existing destination /
announce suite left partial. Both are anchored on the fixed RNS wire CODE-POINTS
(restated here as external literals) and cross-checked by having ONE impl build
the bytes and the OTHER impl decode them — never a field compared to itself.

  * dest-type-bits-on-wire (SINGLE half) — the destination-type flag bits encode
    SINGLE=0, GROUP=1, PLAIN=2, LINK=3 (Packet.get_packed_flags reads
    destination.type, Packet.py:173). The existing suite pins GROUP==1
    (test_destination.py::test_dest_type_bits_group_on_wire) and PLAIN==2
    (test_dest_hash_no_identity_derivation), but the SINGLE==0 code-point is
    never asserted on the wire. A real SINGLE-destination DATA packet must
    report destination_type==0 and a flags byte of 0x00, and the peer must
    decode the same — an impl that mis-numbered SINGLE would diverge.

  * dest-announce-packet-type-context — Destination.announce() emits a packet of
    packet_type ANNOUNCE (==1) with context NONE (==0); the PATH_RESPONSE
    context (==11) is reserved for the path-response branch only
    (Destination.py: announce_context = NONE unless path_response). A regular
    announce decoded by the OTHER impl must report packet_type==ANNOUNCE,
    context==NONE (NOT PATH_RESPONSE), HEADER_1, and destination_type==SINGLE —
    pinning that announces are typed ANNOUNCE/NONE rather than DATA or a
    path-response context.
"""

import pytest

from bridge_client import BridgeError
from conftest import random_hex
from conformance import conformance_case


__category_title__ = "Destination"
__category_order__ = 4


# RNS wire code-points (Destination.* / Packet.*), independently restated as
# external spec literals so the assertions anchor on the standard, not on a
# value read back out of the same impl that produced it.
_DEST_TYPE_SINGLE = 0
_DEST_TYPE_GROUP = 1
_DEST_TYPE_PLAIN = 2
_PACKET_TYPE_DATA = 0
_PACKET_TYPE_ANNOUNCE = 1
_CONTEXT_NONE = 0
_CONTEXT_PATH_RESPONSE = 11
_HEADER_1 = 0


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="SINGLE destination type encodes to flag bits 3-2 == 0 on the wire (SINGLE=0, GROUP=1, PLAIN=2, LINK=3): a real SINGLE-destination DATA packet built by RNS reports destination_type==0 with a flags byte of 0x00 (no other flag bits set), and the OTHER impl decodes raw[0] back to destination_type==0 — completing the on-wire type-bit matrix (GROUP==1 and PLAIN==2 are pinned elsewhere) so an impl that mis-numbered the SINGLE code-point fails",
)
def test_dest_type_bits_single_on_wire(sut, reference):
    for builder, unpacker, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "packet_build", dest_type="single", packet_type=_PACKET_TYPE_DATA,
            context=0, context_flag=0, hops=0, data=random_hex(8),
        )
        assert built["destination_type"] == _DEST_TYPE_SINGLE, (
            f"{label}: builder SINGLE bits != 0"
        )
        # First-principles flags byte for a HEADER_1 BROADCAST DATA packet on a
        # SINGLE destination: (SINGLE=0 << 2) | DATA=0 == 0x00, every other flag
        # bit (header_type, context_flag, transport_type) clear.
        assert built["flags"] == (_DEST_TYPE_SINGLE << 2), (
            f"{label}: SINGLE DATA flags byte != 0x00, got {built['flags']:#04x}"
        )
        parsed = unpacker.execute("packet_unpack", raw=built["raw"])
        assert parsed["unpacked"] is True, f"{label}: SINGLE packet unpack rejected"
        assert parsed["destination_type"] == _DEST_TYPE_SINGLE, (
            f"{label}: decoded SINGLE bits != 0"
        )
        # Negative: the decoded SINGLE code-point must not collide with the
        # GROUP/PLAIN code-points it is distinguished from on the wire.
        assert parsed["destination_type"] not in (_DEST_TYPE_GROUP, _DEST_TYPE_PLAIN), (
            f"{label}: SINGLE decoded as a non-SINGLE type code-point"
        )


@conformance_case(
    commands=["announce_build", "packet_unpack"],
    verifies="Destination.announce() emits a packet typed ANNOUNCE (packet_type==1) with context NONE (==0), HEADER_1, and destination_type SINGLE (==0): a regular (non-path-response) announce built by one impl and decoded by the OTHER reports packet_type==ANNOUNCE and context==NONE — NOT DATA (0) and NOT the PATH_RESPONSE context (11), which is reserved for path responses. Pins that announces carry the ANNOUNCE type and NONE context an impl could otherwise mislabel",
)
def test_announce_packet_type_and_context(sut, reference):
    priv = random_hex(64)
    for builder, unpacker, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
        )
        parsed = unpacker.execute("packet_unpack", raw=built["raw"])
        assert parsed["unpacked"] is True, f"{label}: announce unpack rejected"

        # Announce is typed ANNOUNCE, not DATA.
        assert parsed["packet_type"] == _PACKET_TYPE_ANNOUNCE, (
            f"{label}: announce packet_type {parsed['packet_type']} != ANNOUNCE (1)"
        )
        assert parsed["packet_type"] != _PACKET_TYPE_DATA, (
            f"{label}: announce was typed DATA"
        )
        # Regular announce uses NONE context; PATH_RESPONSE (11) is the
        # path-response-only special case and must NOT appear here.
        assert parsed["context"] == _CONTEXT_NONE, (
            f"{label}: announce context {parsed['context']} != NONE (0)"
        )
        assert parsed["context"] != _CONTEXT_PATH_RESPONSE, (
            f"{label}: a non-path-response announce carried the PATH_RESPONSE context"
        )
        # Announces are SINGLE-destination, single-hop HEADER_1 packets.
        assert parsed["destination_type"] == _DEST_TYPE_SINGLE, (
            f"{label}: announce destination_type != SINGLE (0)"
        )
        assert parsed["header_type"] == _HEADER_1, (
            f"{label}: announce header_type != HEADER_1 (0)"
        )
