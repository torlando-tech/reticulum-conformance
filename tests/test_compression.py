"""Compression conformance tests.

Tests BZ2 compression and decompression by comparing SUT output
against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_bz2_compress(sut, reference):
    data = random_hex(100)
    ref = reference.execute("bz2_compress", data=data)
    res = sut.execute("bz2_compress", data=data)
    assert_hex_equal(res["compressed"], ref["compressed"])


def test_bz2_decompress(sut, reference):
    data = random_hex(100)
    ref_c = reference.execute("bz2_compress", data=data)
    ref = reference.execute("bz2_decompress", compressed=ref_c["compressed"])
    res = sut.execute("bz2_decompress", compressed=ref_c["compressed"])
    assert_hex_equal(res["decompressed"], ref["decompressed"])
    assert_hex_equal(res["decompressed"], data)


def test_bz2_cross_decompress(sut, reference):
    """Compress with SUT, decompress with reference."""
    data = random_hex(200)
    res_c = sut.execute("bz2_compress", data=data)
    ref_d = reference.execute("bz2_decompress", compressed=res_c["compressed"])
    assert_hex_equal(ref_d["decompressed"], data)
