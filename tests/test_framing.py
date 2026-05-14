"""Framing conformance tests.

Tests HDLC and KISS escape encoding and frame construction by comparing
SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Framing"
__category_order__ = 6
__category_description__ = (
    "HDLC and KISS are byte-stuffing protocols for framing variable-length "
    "data on a serial link. Both pick two special bytes — a frame delimiter "
    "(FLAG=`0x7E` for HDLC, FEND=`0xC0` for KISS) and an escape byte "
    "(ESC=`0x7D`, FESC=`0xDB`). When the payload contains either special "
    "byte, it's escaped: HDLC writes ESC + (byte XOR `0x20`); KISS writes "
    "FESC + the byte's transposed value (TFEND=`0xDC` for FEND, "
    "TFESC=`0xDD` for FESC). RNS uses HDLC over direct serial interfaces "
    "and KISS to talk to TNCs."
)


@conformance_case(
    commands=["hdlc_escape"],
    verifies="HDLC byte-stuffing of random data (XOR-with-`0x20` escape for FLAG=`0x7E` and ESC=`0x7D`) is byte-identical",
)
def test_hdlc_escape(sut, reference):
    data = random_hex(32)
    ref = reference.execute("hdlc_escape", data=data)
    res = sut.execute("hdlc_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


@conformance_case(
    commands=["hdlc_escape"],
    verifies="HDLC byte-stuffing of data that contains the special FLAG (`0x7E`) and ESC (`0x7D`) bytes — verifies the escape transform actually fires on the bytes it's designed to escape, not just random data that mostly doesn't trigger it",
)
def test_hdlc_escape_special_bytes(sut, reference):
    # Data containing FLAG (0x7e) and ESC (0x7d)
    data = "007e7d00ff7e"
    ref = reference.execute("hdlc_escape", data=data)
    res = sut.execute("hdlc_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


@conformance_case(
    commands=["hdlc_frame"],
    verifies="Full HDLC frame (FLAG sentinel + escaped payload + FLAG sentinel) is byte-identical",
)
def test_hdlc_frame(sut, reference):
    data = random_hex(32)
    ref = reference.execute("hdlc_frame", data=data)
    res = sut.execute("hdlc_frame", data=data)
    assert_hex_equal(res["framed"], ref["framed"])


@conformance_case(
    commands=["kiss_escape"],
    verifies="KISS byte-stuffing of random data (transposed-byte escape: FEND=`0xC0`→TFEND, FESC=`0xDB`→TFESC) is byte-identical",
)
def test_kiss_escape(sut, reference):
    data = random_hex(32)
    ref = reference.execute("kiss_escape", data=data)
    res = sut.execute("kiss_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


@conformance_case(
    commands=["kiss_escape"],
    verifies="KISS byte-stuffing of data that contains the special FEND (`0xC0`) and FESC (`0xDB`) bytes — verifies the escape transform actually fires on the bytes it's designed to escape",
)
def test_kiss_escape_special_bytes(sut, reference):
    # Data containing FEND (0xc0) and FESC (0xdb)
    data = "00c0db00ffc0"
    ref = reference.execute("kiss_escape", data=data)
    res = sut.execute("kiss_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


@conformance_case(
    commands=["kiss_frame"],
    verifies="Full KISS frame (FEND + CMD_DATA + escaped payload + FEND) is byte-identical",
)
def test_kiss_frame(sut, reference):
    data = random_hex(32)
    ref = reference.execute("kiss_frame", data=data)
    res = sut.execute("kiss_frame", data=data)
    assert_hex_equal(res["framed"], ref["framed"])
