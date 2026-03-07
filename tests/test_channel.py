"""Channel conformance tests.

Tests envelope packing/unpacking and stream message packing/unpacking
by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_envelope_pack_unpack(sut, reference):
    msgtype = 0x0001
    sequence = 0
    data = random_hex(32)
    ref = reference.execute(
        "envelope_pack", msgtype=msgtype, sequence=sequence, data=data
    )
    res = sut.execute(
        "envelope_pack", msgtype=msgtype, sequence=sequence, data=data
    )
    assert_hex_equal(res["envelope"], ref["envelope"])
    # Unpack
    ref_u = reference.execute("envelope_unpack", envelope=ref["envelope"])
    res_u = sut.execute("envelope_unpack", envelope=ref["envelope"])
    assert res_u["msgtype"] == ref_u["msgtype"]
    assert_hex_equal(res_u["data"], ref_u["data"])


def test_stream_msg_pack_unpack(sut, reference):
    stream_id = 42
    data = random_hex(64)
    ref = reference.execute(
        "stream_msg_pack", stream_id=stream_id, data=data, eof=False, compressed=False
    )
    res = sut.execute(
        "stream_msg_pack", stream_id=stream_id, data=data, eof=False, compressed=False
    )
    assert_hex_equal(res["message"], ref["message"])
    # Unpack
    ref_u = reference.execute("stream_msg_unpack", message=ref["message"])
    res_u = sut.execute("stream_msg_unpack", message=ref["message"])
    assert res_u["stream_id"] == ref_u["stream_id"]
    assert_hex_equal(res_u["data"], ref_u["data"])
