"""Framing conformance tests.

Tests HDLC and KISS escape encoding and frame construction by comparing
SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_hdlc_escape(sut, reference):
    data = random_hex(32)
    ref = reference.execute("hdlc_escape", data=data)
    res = sut.execute("hdlc_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


def test_hdlc_escape_special_bytes(sut, reference):
    # Data containing FLAG (0x7e) and ESC (0x7d)
    data = "007e7d00ff7e"
    ref = reference.execute("hdlc_escape", data=data)
    res = sut.execute("hdlc_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


def test_hdlc_frame(sut, reference):
    data = random_hex(32)
    ref = reference.execute("hdlc_frame", data=data)
    res = sut.execute("hdlc_frame", data=data)
    assert_hex_equal(res["framed"], ref["framed"])


def test_kiss_escape(sut, reference):
    data = random_hex(32)
    ref = reference.execute("kiss_escape", data=data)
    res = sut.execute("kiss_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


def test_kiss_escape_special_bytes(sut, reference):
    # Data containing FEND (0xc0) and FESC (0xdb)
    data = "00c0db00ffc0"
    ref = reference.execute("kiss_escape", data=data)
    res = sut.execute("kiss_escape", data=data)
    assert_hex_equal(res["escaped"], ref["escaped"])


def test_kiss_frame(sut, reference):
    data = random_hex(32)
    ref = reference.execute("kiss_frame", data=data)
    res = sut.execute("kiss_frame", data=data)
    assert_hex_equal(res["framed"], ref["framed"])
