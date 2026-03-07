"""Packet conformance tests.

Tests packet flag encoding/decoding, packet packing/unpacking, and
header parsing by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


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


def test_packet_parse_flags(sut, reference):
    for flags_byte in [0x00, 0x21, 0x41, 0x15, 0x7F]:
        ref = reference.execute("packet_parse_flags", flags=flags_byte)
        res = sut.execute("packet_parse_flags", flags=flags_byte)
        assert res["header_type"] == ref["header_type"]
        assert res["context_flag"] == ref["context_flag"]
        assert res["transport_type"] == ref["transport_type"]
        assert res["destination_type"] == ref["destination_type"]
        assert res["packet_type"] == ref["packet_type"]


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


def test_packet_pack_header2(sut, reference):
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
