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

The random-payload cases above (`random_hex`) are *incompressible* — bz2
expands them by a header/overhead margin — so they exercise the codec but
never the case where compression actually shrinks the input. `test_bz2_compressible_both_directions`
adds a highly-compressible payload and asserts (a) the compressor actually
reduces size and (b) the compressed bytes cross-decompress in BOTH
directions (reference->SUT and SUT->reference).

NOT covered here (deliberately deferred / gap):

- The RNS 1.3.1 bz2 decompression-bomb guard (N-M13). RNS bounds decompression
  at the Resource layer (`Resource.assemble`: `BZ2Decompressor.decompress(max_length=AUTO_COMPRESS_MAX_SIZE)`
  then `not eof -> status=CORRUPT`, Resource.py:686-691) and the Channel/Buffer
  layer (`StreamDataMessage.unpack`: `max_length=RawChannelWriter.MAX_CHUNK_LEN`
  (16 KiB) then `not eof -> raise IOError`, Buffer.py:95-97). The bridge's
  `bz2_decompress` is a RAW, UNBOUNDED `bz2.decompress` primitive that mirrors
  no guarded RNS receive path, so it cannot exercise the guard, and there is no
  bounded decompress / resource-assemble / buffer-chunk-unpack command to drive
  reference-vs-reference. Adding one lives in bridge_server.py (not owned here);
  the gap is recorded in the re-audit deliverable (unresolved).
- The Resource-level `compressed` flag (whether RNS chose to compress a
  transfer) is a wire-resource concern, surfaced by the wire harness's
  resource fixture; it is covered in t-wireresource, not at this primitive layer.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Compression"
__category_order__ = 14

# bz2 file magic: "BZh" (0x425a68) per https://en.wikipedia.org/wiki/Bzip2#File_format
_BZ2_MAGIC_HEX = "425a68"


def _compressible_hex(byte_len):
    """A highly-compressible payload of `byte_len` bytes, as a hex string.

    A short repeating pattern (not random) so bz2 shrinks it dramatically —
    the opposite of the incompressible ``random_hex`` payloads, which bz2
    expands. Used to assert the compressor actually reduces size and that the
    compressed bitstream cross-decompresses both directions.
    """
    pattern = bytes(range(8))  # 00 01 .. 07, repeats compress to near-nothing
    body = (pattern * ((byte_len // len(pattern)) + 1))[:byte_len]
    return body.hex()


@conformance_case(
    commands=["bz2_compress", "bz2_decompress"],
    verifies="SUT bz2 output begins with the bz2 magic header and self-roundtrips (compress then decompress returns input)",
)
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


@conformance_case(
    commands=["bz2_compress", "bz2_decompress"],
    verifies="SUT decompression of reference-compressed bytes recovers the original input",
)
def test_bz2_decompress(sut, reference):
    data = random_hex(100)
    ref_c = reference.execute("bz2_compress", data=data)
    ref = reference.execute("bz2_decompress", compressed=ref_c["compressed"])
    res = sut.execute("bz2_decompress", compressed=ref_c["compressed"])
    assert_hex_equal(res["decompressed"], ref["decompressed"])
    assert_hex_equal(res["decompressed"], data)


@conformance_case(
    commands=["bz2_compress", "bz2_decompress"],
    verifies="Cross-impl: SUT-compressed bytes decompressed by reference recovers the original input",
)
def test_bz2_cross_decompress(sut, reference):
    """Compress with SUT, decompress with reference."""
    data = random_hex(200)
    res_c = sut.execute("bz2_compress", data=data)
    ref_d = reference.execute("bz2_decompress", compressed=res_c["compressed"])
    assert_hex_equal(ref_d["decompressed"], data)


@conformance_case(
    commands=["bz2_compress", "bz2_decompress"],
    verifies="On a highly-compressible payload the SUT compressor produces fewer bytes than its input, and the compressed bytes cross-decompress in both directions (reference-compressed->SUT-decompressed and SUT-compressed->reference-decompressed) recovering the original",
)
def test_bz2_compressible_both_directions(sut, reference):
    """Highly-compressible payload: assert compression shrinks it AND both
    cross-decompression directions recover the original.

    The other cases use incompressible random data (bz2 expands it), so this is
    the only case that exercises a payload bz2 actually compresses. Size is
    measured from the returned hex (2 chars/byte), independent of any optional
    `ratio`/`compressed_size` metadata fields, so a stub "compressor" that
    echoes its input unchanged fails the size assertion.
    """
    data = _compressible_hex(4096)

    # SUT compresses; the result must be strictly smaller than the input.
    sut_c = sut.execute("bz2_compress", data=data)["compressed"]
    assert len(sut_c) // 2 < len(data) // 2, (
        f"SUT bz2_compress did not reduce a highly-compressible {len(data)//2}-byte "
        f"payload: compressed to {len(sut_c)//2} bytes"
    )

    # Direction 1 (sut_compress -> reference_decompress): cross-impl recover.
    ref_d = reference.execute("bz2_decompress", compressed=sut_c)["decompressed"]
    assert_hex_equal(ref_d, data, "SUT-compressed -> reference-decompressed")

    # Direction 2 (reference_compress -> sut_decompress): cross-impl recover.
    ref_c = reference.execute("bz2_compress", data=data)["compressed"]
    assert len(ref_c) // 2 < len(data) // 2, (
        "reference (positive control) bz2_compress did not reduce a "
        "highly-compressible payload"
    )
    sut_d = sut.execute("bz2_decompress", compressed=ref_c)["decompressed"]
    assert_hex_equal(sut_d, data, "reference-compressed -> SUT-decompressed")
