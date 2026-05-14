"""Packet conformance tests.

Tests packet flag encoding/decoding, packet packing/unpacking, and
header parsing by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Packet"
__category_order__ = 5


@conformance_case(
    commands=["packet_flags"],
    verifies="RNS `packet_flags` byte encoding for a basic DATA packet (all bit-fields zero) is byte-identical",
)
def test_packet_flags(sut, reference):
    ref = reference.execute(
        "packet_flags",
        header_type=0,
        context_flag=0,
        transport_type=0,
        destination_type=0,
        packet_type=0,
    )
    res = sut.execute(
        "packet_flags",
        header_type=0,
        context_flag=0,
        transport_type=0,
        destination_type=0,
        packet_type=0,
    )
    assert res["flags"] == ref["flags"]


@conformance_case(
    commands=["packet_flags"],
    verifies="RNS `packet_flags` byte encoding for an ANNOUNCE packet (`context_flag=1`, `packet_type=1` → byte `0x21`) is byte-identical",
)
def test_packet_flags_announce(sut, reference):
    ref = reference.execute(
        "packet_flags",
        header_type=0,
        context_flag=1,
        transport_type=0,
        destination_type=0,
        packet_type=1,
    )
    res = sut.execute(
        "packet_flags",
        header_type=0,
        context_flag=1,
        transport_type=0,
        destination_type=0,
        packet_type=1,
    )
    assert res["flags"] == ref["flags"]


@conformance_case(
    commands=["packet_parse_flags"],
    verifies="RNS `packet_parse_flags` decodes 6 distinct flag bytes (`0x00`, `0x21`, `0x41`, `0x15`, `0x0A`, `0x7F`) covering every value of every bit-field; all decoded fields (`header_type`, `context_flag`, `transport_type`, `destination_type`, `packet_type`) match the reference",
)
def test_packet_parse_flags(sut, reference):
    # Enumerates every value of every bit-field in the flag byte:
    #   0x00 = all zeros (H1, ctx=0, tx=0, dest=SINGLE, pkt=DATA)
    #   0x21 = H1 + context_flag=1, dest=SINGLE, pkt=ANNOUNCE
    #   0x41 = H2 + dest=SINGLE, pkt=ANNOUNCE
    #   0x15 = H1 + transport_type=1, dest=GROUP, pkt=ANNOUNCE
    #   0x0A = H1 + dest=PLAIN, pkt=LINKREQUEST  (closes the
    #          PLAIN/LINKREQUEST coverage gap left by the original 5)
    #   0x7F = H2 + ctx=1, tx=1, dest=LINK, pkt=PROOF  (all-fields-max)
    for flags_byte in [0x00, 0x21, 0x41, 0x15, 0x0A, 0x7F]:
        ref = reference.execute("packet_parse_flags", flags=flags_byte)
        res = sut.execute("packet_parse_flags", flags=flags_byte)
        assert res["header_type"] == ref["header_type"]
        assert res["context_flag"] == ref["context_flag"]
        assert res["transport_type"] == ref["transport_type"]
        assert res["destination_type"] == ref["destination_type"]
        assert res["packet_type"] == ref["packet_type"]


@conformance_case(
    commands=["packet_parse_flags"],
    verifies="RNS `packet_parse_flags` ignores the IFAC flag (bit 7): for every curated flag byte, decoding `byte | 0x80` yields fields byte-identical to decoding `byte` on both impls — bit 7 is the masking layer's concern, not the packet decoder's. Catches bit-7 bleed even when both impls share the bug.",
)
def test_packet_parse_flags_ignores_ifac_bit(sut, reference):
    """Bit 7 of the flag byte is the IFAC flag — set by the IFAC masking
    layer when wrapping a packet for an authenticated interface. It is not
    part of packet_parse_flags' five-field contract; decoders must mask it
    out (or simply ignore the high nibble's top bit). This test asserts
    three things at once for the same 6 curated bytes test_packet_parse_flags
    uses:
      1. cross-impl: SUT and reference produce identical fields for the
         bit-7-set input (`base | 0x80`),
      2. within reference: setting bit 7 does not change any of the 5
         named fields,
      3. within SUT: same.
    (2) and (3) together rule out a "both impls bleed bit 7 into header_type"
    failure mode that a pure SUT==reference check would miss.
    """
    fields = (
        "header_type", "context_flag", "transport_type",
        "destination_type", "packet_type",
    )
    for base_byte in [0x00, 0x21, 0x41, 0x15, 0x0A, 0x7F]:
        ifac_set = base_byte | 0x80
        ref_clear = reference.execute("packet_parse_flags", flags=base_byte)
        sut_clear = sut.execute("packet_parse_flags", flags=base_byte)
        ref_set = reference.execute("packet_parse_flags", flags=ifac_set)
        sut_set = sut.execute("packet_parse_flags", flags=ifac_set)
        for f in fields:
            # (1) cross-impl at bit-7-set
            assert sut_set[f] == ref_set[f], (
                f"SUT/reference diverge at flags=0x{ifac_set:02x} on {f}"
            )
            # (2) reference: bit 7 doesn't bleed
            assert ref_set[f] == ref_clear[f], (
                f"reference: setting bit 7 changed {f} (base=0x{base_byte:02x})"
            )
            # (3) SUT: bit 7 doesn't bleed
            assert sut_set[f] == sut_clear[f], (
                f"SUT: setting bit 7 changed {f} (base=0x{base_byte:02x})"
            )


@conformance_case(
    commands=["packet_parse_flags"],
    verifies="RNS `packet_parse_flags` exhaustive sweep: for every flag byte value `0x00`–`0x7F` (all 128 combinations of the 5 named fields, IFAC bit clear), SUT and reference decode byte-identically. Pairs with the curated `test_packet_parse_flags` (which documents WHICH byte covers what) — together they catch every per-byte miswiring SUT could possibly have.",
)
def test_packet_parse_flags_exhaustive(sut, reference):
    """All 128 valid (IFAC-clear) flag byte values. Combined with
    test_packet_parse_flags (representative subset, every-value-of-every-
    field, documented) and test_packet_parse_flags_ignores_ifac_bit (bit 7
    behavior), this gives complete enumeration: any byte the SUT will ever
    see on the wire decodes the same as reference.
    """
    fields = (
        "header_type", "context_flag", "transport_type",
        "destination_type", "packet_type",
    )
    for byte in range(0x80):
        ref = reference.execute("packet_parse_flags", flags=byte)
        res = sut.execute("packet_parse_flags", flags=byte)
        for f in fields:
            assert res[f] == ref[f], (
                f"diverge at flags=0x{byte:02x} on field {f}: "
                f"SUT={res[f]!r} reference={ref[f]!r}"
            )


@conformance_case(
    commands=["packet_pack", "packet_unpack"],
    verifies="RNS packet pack/unpack round-trip (HEADER_1 layout — no `transport_id`): packing is byte-identical and unpacking recovers `hops`, `destination_hash`, and data",
)
def test_packet_pack_unpack_header1(sut, reference):
    dest = random_hex(16)
    data = random_hex(32)
    ref = reference.execute(
        "packet_pack",
        header_type=0,
        context_flag=0,
        transport_type=0,
        destination_type=0,
        packet_type=0,
        hops=3,
        destination_hash=dest,
        context=0,
        data=data,
    )
    res = sut.execute(
        "packet_pack",
        header_type=0,
        context_flag=0,
        transport_type=0,
        destination_type=0,
        packet_type=0,
        hops=3,
        destination_hash=dest,
        context=0,
        data=data,
    )
    assert_hex_equal(res["raw"], ref["raw"])
    # Unpack
    ref_u = reference.execute("packet_unpack", raw=ref["raw"])
    res_u = sut.execute("packet_unpack", raw=ref["raw"])
    assert res_u["hops"] == ref_u["hops"]
    assert_hex_equal(res_u["destination_hash"], ref_u["destination_hash"])
    assert_hex_equal(res_u["data"], ref_u["data"])


@conformance_case(
    commands=["packet_pack", "packet_unpack"],
    verifies="RNS packet pack/unpack round-trip for HEADER_2 layout (includes `transport_id` for multi-hop routing): packing is byte-identical and unpacking recovers `hops`, `transport_id`, `destination_hash`, and data",
)
def test_packet_pack_unpack_header2(sut, reference):
    dest = random_hex(16)
    transport_id = random_hex(16)
    data = random_hex(32)
    ref = reference.execute(
        "packet_pack",
        header_type=1,
        context_flag=0,
        transport_type=1,
        destination_type=0,
        packet_type=0,
        hops=2,
        destination_hash=dest,
        transport_id=transport_id,
        context=0,
        data=data,
    )
    res = sut.execute(
        "packet_pack",
        header_type=1,
        context_flag=0,
        transport_type=1,
        destination_type=0,
        packet_type=0,
        hops=2,
        destination_hash=dest,
        transport_id=transport_id,
        context=0,
        data=data,
    )
    assert_hex_equal(res["raw"], ref["raw"])
    # Unpack — HEADER_2 specifically should round-trip transport_id too,
    # which HEADER_1 (test_packet_pack_unpack_header1) doesn't have.
    ref_u = reference.execute("packet_unpack", raw=ref["raw"])
    res_u = sut.execute("packet_unpack", raw=ref["raw"])
    assert res_u["hops"] == ref_u["hops"]
    assert_hex_equal(res_u["transport_id"], ref_u["transport_id"])
    assert_hex_equal(res_u["destination_hash"], ref_u["destination_hash"])
    assert_hex_equal(res_u["data"], ref_u["data"])


@conformance_case(
    commands=["packet_pack", "packet_parse_header"],
    verifies="RNS `packet_parse_header` extracts `header_type`, `hops`, `destination_hash`, and context byte-identically from a packed packet",
)
def test_packet_parse_header(sut, reference):
    dest = random_hex(16)
    data = random_hex(32)
    ref_pkt = reference.execute(
        "packet_pack",
        header_type=0,
        context_flag=1,
        transport_type=0,
        destination_type=2,
        packet_type=1,
        hops=5,
        destination_hash=dest,
        context=11,
        data=data,
    )
    ref = reference.execute("packet_parse_header", raw=ref_pkt["raw"])
    res = sut.execute("packet_parse_header", raw=ref_pkt["raw"])
    assert res["header_type"] == ref["header_type"]
    assert res["hops"] == ref["hops"]
    assert_hex_equal(res["destination_hash"], ref["destination_hash"])
    assert res["context"] == ref["context"]
