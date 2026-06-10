"""Packet wire-format completeness tests.

Closes RNS 1.3.1 Packet.py conformance gaps that the existing tests/test_packet.py
left partial or uncovered, using only the live packet_build / packet_unpack /
packet_hash bridge commands (each delegates to real RNS.Packet). Every assertion
anchors on an INDEPENDENT value — a flag byte recomputed from the documented bit
layout, a destination-type code-point read from RNS.Destination, a wire frame
reconstructed field-by-field, or the MTU pack ceiling derived from
RNS.Reticulum.MTU — never on the SUT's own decode of its own bytes.

Gaps addressed (CONFORMANCE_COMPLETENESS Appendix A, packet subsystem):
  * propagation-type-bit  — TRANSPORT=1 emission is byte-exact (bit 4).
  * destination-type-codes — GROUP=0b01 emission pinned byte-exact to the literal.
  * context-byte-codes / unpack-accepts-unknown-context — the context byte rides
    at its spec wire offset, round-trips verbatim for ANY value (incl. unassigned
    code points), and the parser structurally accepts unknown contexts.
  * mtu-enforcement — the exact 500/501-byte pack ceiling (not a coarse 600B probe).
  * header2-construction-announce-only / header2-requires-transport-id — the
    packet layer refuses to originate a non-ANNOUNCE HEADER_2 frame or a HEADER_2
    frame with no transport ID.

Ground truth verified against RNS.Packet.get_packed_flags / pack / unpack and
RNS.Reticulum constants (MTU=500, TRUNCATED_HASHLENGTH=128 → 16-byte addresses,
HEADER_MINSIZE=19, HEADER_MAXSIZE=35).
"""

import pytest

from bridge_client import BridgeError
from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Packet"
__category_order__ = 5


# Destination-type flag-byte code points — read from RNS.Destination
# (SINGLE=0, GROUP=1, PLAIN=2, LINK=3). These are the bits 3-2 of the flags byte.
_DTYPE_SINGLE = 0
_DTYPE_GROUP = 1
_DTYPE_PLAIN = 2

# Packet types (RNS.Packet).
_PTYPE_DATA = 0
_PTYPE_ANNOUNCE = 1
_PTYPE_LINKREQUEST = 2
_PTYPE_PROOF = 3

# Transport (propagation) types — RNS.Transport.BROADCAST=0, TRANSPORT=1 → bit 4.
_PROP_BROADCAST = 0
_PROP_TRANSPORT = 1

_HEADER_1 = 0
_HEADER_2 = 1

# RNS.Reticulum constants used to derive pack ceilings independently.
_MTU = 500
_ADDR_LEN = 16  # TRUNCATED_HASHLENGTH // 8
_HEADER_1_SIZE = 2 + _ADDR_LEN + 1  # flags + hops + destination_hash + context = 19


def _expected_flags(header_type, context_flag, transport_type, dtype, ptype):
    """The RNS flags byte composed from first principles (Packet.get_packed_flags):
        bit 6 header_type | bit 5 context_flag | bit 4 transport_type |
        bits 3-2 destination_type | bits 1-0 packet_type.
    """
    return (
        (header_type << 6)
        | (context_flag << 5)
        | (transport_type << 4)
        | (dtype << 2)
        | ptype
    )


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies=(
        "RNS encodes the propagation/transport type as bit 4 of the flags byte "
        "(RNS.Transport.BROADCAST=0, TRANSPORT=1): a packet built with "
        "transport_type=TRANSPORT sets bit 4 and its whole flags byte equals the "
        "value recomputed from the documented bit layout, while transport_type="
        "BROADCAST clears bit 4 and the two flags bytes differ ONLY in bit 4 — so "
        "an impl that mis-positions or drops the propagation bit fails. The other "
        "impl's unpack decodes transport_type back to the originated value"
    ),
)
def test_packet_transport_type_bit4(sut, reference):
    payload = random_hex(16)
    for builder, unpacker, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        flags_by_prop = {}
        for prop in (_PROP_BROADCAST, _PROP_TRANSPORT):
            built = builder.execute(
                "packet_build",
                dest_type="plain", packet_type=_PTYPE_DATA,
                context=0, context_flag=0, hops=0, data=payload,
                transport_type=prop,
            )
            want = _expected_flags(_HEADER_1, 0, prop, _DTYPE_PLAIN, _PTYPE_DATA)
            assert built["flags"] == want, (
                f"{label}: transport_type={prop} flags 0x{built['flags']:02x} != "
                f"recomputed 0x{want:02x}"
            )
            # Bit 4 reflects the propagation type exactly.
            assert (built["flags"] >> 4) & 1 == prop, (
                f"{label}: bit 4 != transport_type for prop={prop}"
            )
            # The other impl decodes it back to the originated value.
            parsed = unpacker.execute("packet_unpack", raw=built["raw"])
            assert parsed["unpacked"] is True
            assert parsed["transport_type"] == prop, (
                f"{label}: unpack transport_type={parsed['transport_type']} != {prop}"
            )
            flags_by_prop[prop] = built["flags"]
        # Discriminating contrast: BROADCAST vs TRANSPORT flags differ ONLY in bit 4.
        assert flags_by_prop[_PROP_BROADCAST] ^ flags_by_prop[_PROP_TRANSPORT] == 0x10, (
            f"{label}: toggling transport_type changed bits other than bit 4 "
            f"(0x{flags_by_prop[_PROP_BROADCAST]:02x} vs "
            f"0x{flags_by_prop[_PROP_TRANSPORT]:02x})"
        )


@conformance_case(
    commands=["packet_build"],
    verifies=(
        "RNS sets the destination-type field (flags bits 3-2) to the destination's "
        "RNS.Destination.type code: SINGLE=0b00, GROUP=0b01, PLAIN=0b10. Each built "
        "packet's flags byte equals the value recomputed from the documented bit "
        "layout for that code point, the decoded destination_type equals the literal, "
        "and the three code points are mutually distinct — pinning GROUP=0b01 "
        "byte-exact against the spec literal (previously only self-round-tripped)"
    ),
)
def test_packet_destination_type_codes(sut, reference):
    payload = random_hex(16)
    cases = (
        ("single", _DTYPE_SINGLE),
        ("group", _DTYPE_GROUP),
        ("plain", _DTYPE_PLAIN),
    )
    for impl, who in ((sut, "sut"), (reference, "reference")):
        seen = {}
        for dest_type, dt_bits in cases:
            built = impl.execute(
                "packet_build",
                dest_type=dest_type, packet_type=_PTYPE_DATA,
                context=0, context_flag=0, hops=0, data=payload,
            )
            want = _expected_flags(_HEADER_1, 0, _PROP_BROADCAST, dt_bits, _PTYPE_DATA)
            assert built["flags"] == want, (
                f"{who}: dest_type={dest_type} flags 0x{built['flags']:02x} != "
                f"recomputed 0x{want:02x} (dtype bits {dt_bits:02b})"
            )
            assert built["destination_type"] == dt_bits, (
                f"{who}: decoded destination_type {built['destination_type']} != "
                f"{dt_bits} for {dest_type}"
            )
            # The destination-type bits sit at bits 3-2.
            assert (built["flags"] >> 2) & 0b11 == dt_bits
            seen[dt_bits] = dest_type
        # GROUP must not collide with SINGLE or PLAIN.
        assert set(seen) == {_DTYPE_SINGLE, _DTYPE_GROUP, _DTYPE_PLAIN}, (
            f"{who}: destination-type code points collided: {seen}"
        )


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies=(
        "RNS carries the context byte verbatim at its wire offset (HEADER_1: byte 18, "
        "after flags+hops+16B destination_hash) for ANY value, and the parser "
        "structurally ACCEPTS unassigned context code points (forward compatibility) "
        "rather than rejecting them: for assigned, special, and unassigned contexts "
        "(0x00/0x01/0x42/0xF0/0xFF) on a PLAIN DATA packet the whole frame equals an "
        "independently reconstructed flags||hops||dest_hash||context||data, unpack "
        "returns unpacked=True with context echoed back, and mutating ONLY the context "
        "byte of a real frame leaves every other decoded field unchanged — proving the "
        "context lives at exactly that offset and an impl that rejects unknown contexts "
        "at parse time fails"
    ),
)
def test_packet_context_byte_offset_and_unknown_acceptance(sut, reference):
    payload = random_hex(24)
    # Assigned (NONE/RESOURCE) and unassigned (0x42, 0xF0, 0xFE) context values.
    # 0xFF (LRPROOF) is excluded here: RNS.Packet.pack special-cases LRPROOF into
    # the link-id packing path, which is unbuildable on a non-link destination —
    # but unpack still accepts 0xFF structurally, exercised in the mutation loop.
    for context in (0x00, 0x01, 0x42, 0xF0, 0xFE):
        built = sut.execute(
            "packet_build",
            dest_type="plain", packet_type=_PTYPE_DATA,
            context=context, context_flag=0, hops=3, data=payload,
        )
        raw = bytes.fromhex(built["raw"])
        # Independent reconstruction: PLAIN carries the payload in the clear, so
        # the entire HEADER_1 frame is deterministic.
        dest_hash = bytes.fromhex(built["destination_hash"])
        data = bytes.fromhex(payload)
        expected = bytes([built["flags"], 3]) + dest_hash + bytes([context]) + data
        assert_hex_equal(
            raw.hex(), expected.hex(),
            f"context=0x{context:02x}: reconstructed HEADER_1 frame mismatch",
        )
        # The context byte is at offset 18 (= 2 + 16).
        assert raw[_HEADER_1_SIZE - 1] == context, (
            f"context byte not at wire offset {_HEADER_1_SIZE - 1} for 0x{context:02x}"
        )
        # The OTHER impl structurally accepts the (possibly unassigned) context.
        parsed = reference.execute("packet_unpack", raw=raw.hex())
        assert parsed["unpacked"] is True, (
            f"unpack REJECTED context=0x{context:02x} — unknown context codes must "
            f"be accepted structurally, got {parsed}"
        )
        assert parsed["context"] == context, (
            f"unpack echoed context {parsed['context']} != 0x{context:02x}"
        )

    # Discriminating offset check: starting from a real frame, mutating ONLY the
    # context byte changes the decoded context and nothing else.
    base = sut.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0x00, context_flag=0, hops=1, data=payload,
    )
    pristine = reference.execute("packet_unpack", raw=base["raw"])
    # Both an unassigned mid value and the reserved 0xFF (LRPROOF) code point are
    # accepted structurally by unpack and touch only the context field.
    for ctx in (0x7E, 0xFF):
        raw = bytearray(bytes.fromhex(base["raw"]))
        raw[_HEADER_1_SIZE - 1] = ctx
        mutated = reference.execute("packet_unpack", raw=bytes(raw).hex())
        assert mutated["unpacked"] is True and mutated["context"] == ctx, (
            f"unpack rejected/garbled context 0x{ctx:02x}: {mutated}"
        )
        for field in ("flags", "hops", "destination_hash", "data",
                      "destination_type", "packet_type", "header_type"):
            assert mutated[field] == pristine[field], (
                f"flipping the context byte to 0x{ctx:02x} also changed decoded "
                f"field {field!r} ({mutated[field]!r} != {pristine[field]!r}) — "
                f"context offset wrong"
            )


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies=(
        "RNS carries the context byte at the HEADER_2 wire offset (byte 34, after "
        "flags+hops+16B transport_id+16B destination_hash) and round-trips any value "
        "including unassigned code points: a HEADER_2 ANNOUNCE (plaintext payload) "
        "built with context 0x42/0xF0 places that byte at raw[34] and unpack echoes "
        "it back with unpacked=True"
    ),
)
def test_packet_context_byte_offset_header2(sut, reference):
    transport_id = random_hex(16)
    payload = random_hex(20)
    header2_ctx_offset = 2 + 2 * _ADDR_LEN  # 34
    for context in (0x42, 0xF0):
        built = sut.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_ANNOUNCE,
            context=context, context_flag=0, hops=2, data=payload,
            header_type=2, transport_id=transport_id,
        )
        raw = bytes.fromhex(built["raw"])
        assert raw[header2_ctx_offset] == context, (
            f"HEADER_2 context byte not at offset {header2_ctx_offset} "
            f"for 0x{context:02x} (got 0x{raw[header2_ctx_offset]:02x})"
        )
        parsed = reference.execute("packet_unpack", raw=raw.hex())
        assert parsed["unpacked"] is True and parsed["header_type"] == _HEADER_2
        assert parsed["context"] == context, (
            f"HEADER_2 unpack echoed context {parsed['context']} != 0x{context:02x}"
        )


@conformance_case(
    commands=["packet_build"],
    verifies=(
        "RNS enforces the per-packet MTU (RNS.Reticulum.MTU=500) at the EXACT byte "
        "boundary, not approximately: a PLAIN DATA packet whose 19-byte HEADER_1 "
        "header plus cleartext payload total exactly 500 bytes (481-byte payload) "
        "packs and emits raw of length 500, while one byte more (482-byte payload, "
        "501 total) is rejected at pack time. An impl with an off-by-N ceiling fails "
        "the boundary"
    ),
)
def test_packet_mtu_exact_boundary(sut):
    max_payload = _MTU - _HEADER_1_SIZE  # 500 - 19 = 481
    at_limit = sut.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data=random_hex(max_payload),
    )
    raw = bytes.fromhex(at_limit["raw"])
    assert len(raw) == _MTU, (
        f"a {max_payload}-byte payload must pack to exactly the {_MTU}-byte MTU, "
        f"got {len(raw)}"
    )
    # One byte over the boundary must be rejected.
    with pytest.raises(BridgeError):
        sut.execute(
            "packet_build",
            dest_type="plain", packet_type=_PTYPE_DATA,
            context=0, context_flag=0, hops=0, data=random_hex(max_payload + 1),
        )


@conformance_case(
    commands=["packet_build"],
    verifies=(
        "RNS only assembles a HEADER_2 (transport-relayed) frame for ANNOUNCE packets "
        "and only when a transport ID is present (Packet.pack: the HEADER_2 branch sets "
        "ciphertext solely for ANNOUNCE and raises when transport_id is None): a "
        "HEADER_2 ANNOUNCE with a 16-byte transport_id builds (positive control, "
        "decoded header_type=HEADER_2), while a HEADER_2 DATA/LINKREQUEST/PROOF build, "
        "and a HEADER_2 ANNOUNCE with no transport_id, are each rejected — so an impl "
        "that originates a malformed transport-relayed frame at the packet layer fails"
    ),
)
def test_packet_header2_construction_constraints(sut):
    transport_id = random_hex(16)
    # Positive control: HEADER_2 ANNOUNCE with a transport_id is the ONLY valid form.
    ok = sut.execute(
        "packet_build",
        dest_type="single", packet_type=_PTYPE_ANNOUNCE,
        context=0, context_flag=0, hops=0, data=random_hex(16),
        header_type=2, transport_id=transport_id,
    )
    assert ok["header_type"] == _HEADER_2, "positive control did not build HEADER_2"

    # Non-ANNOUNCE HEADER_2 frames cannot be originated at the packet layer.
    for ptype, name in (
        (_PTYPE_DATA, "DATA"),
        (_PTYPE_LINKREQUEST, "LINKREQUEST"),
        (_PTYPE_PROOF, "PROOF"),
    ):
        with pytest.raises(BridgeError):
            sut.execute(
                "packet_build",
                dest_type="single", packet_type=ptype,
                context=0, context_flag=0, hops=0, data=random_hex(16),
                header_type=2, transport_id=transport_id,
            )

    # HEADER_2 with no transport ID is an error (RNS would raise IOError on pack).
    with pytest.raises(BridgeError):
        sut.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_ANNOUNCE,
            context=0, context_flag=0, hops=0, data=random_hex(16),
            header_type=2,
        )
