"""Compression conformance tests.

bz2's compressed output is not required to be byte-identical across
implementations — the format allows legitimate variation in block size,
Huffman tree selection, and bitstream packing. What IS required is that
a compressor and a decompressor from any pair of conformant implementations
interoperate (both directions). That's the guarantee tested here:

- `test_bz2_compress`: SUT produces valid bz2 bytes (magic header) AND can
  self-roundtrip (SUT.compress then SUT.decompress returns input).
- `test_bz2_decompress`: SUT decodes bytes produced by the reference.
- `test_bz2_cross_decompress`: reference decodes bytes produced by the SUT.

Together these pin the interop contract without asserting byte-identity
against a specific reference output. A previous `assert_hex_equal` on
SUT vs reference compressed bytes appeared to pass only because the old
global `CONFORMANCE_BRIDGE_CMD` override made SUT and reference the same
bridge (Kotlin-vs-Kotlin). With per-impl bridges the assertion surfaced
its true nature as an implementation-detail check, not a conformance one.
"""

from conftest import random_hex, assert_hex_equal

# bz2 file magic: "BZh" (0x425a68) per https://en.wikipedia.org/wiki/Bzip2#File_format
_BZ2_MAGIC_HEX = "425a68"


def test_bz2_compress(sut):
    data = random_hex(100)
    compressed = sut.execute("bz2_compress", data=data)["compressed"]
    # Case-insensitive magic check: bridges may return mixed-case hex, and
    # the rest of the suite normalises via assert_hex_equal for the same
    # reason.
    assert compressed.lower().startswith(_BZ2_MAGIC_HEX), (
        f"SUT bz2_compress output does not begin with bz2 magic "
        f"{_BZ2_MAGIC_HEX!r}: got {compressed[:16]!r}"
    )
    roundtrip = sut.execute("bz2_decompress", compressed=compressed)["decompressed"]
    assert_hex_equal(roundtrip, data)


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
