"""Resource construction completeness — advertisement flags byte, compression
decision gates, metadata length-prefix encoding, and size/SDU accounting.

These close the partial gaps the completeness eval (CONFORMANCE_COMPLETENESS.md
Appendix A, subsystem `resource`) left on the SENDER-side construction path:

  * adv-flags-bit-layout — only the metadata (x) bit was ever pinned at its
    exact position; e/c/s were constrained only transitively via cross-impl
    transfer. Here the whole ResourceAdvertisement flags byte is pinned against
    spec-literal byte values (Resource.py:1307,
    f = x<<5 | p<<4 | u<<3 | s<<2 | c<<1 | e).
  * compression-decision — the existing compressibility test only toggles the
    default auto_compress path; the auto_compress=False gate and the
    strictly-smaller gate are pinned here against an INDEPENDENT bz2.compress.
  * metadata-encoding — the 3-byte big-endian length prefix + msgpack packing
    of the metadata block is pinned by the exact growth of total_size, derived
    from the msgpack spec (bin8) and struct.pack(">I",n)[1:] (Resource.py:266).
  * size-accounting / part-slicing-sdu — t (per-segment encrypted size),
    d (total uncompressed size across segments), n (per-segment part count),
    and the SDU formula sdu = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE
    (Resource.py:338) are pinned directly rather than only transitively.

Every assertion anchors on an EXTERNAL standard (the msgpack bin8 wire format,
Python's own bz2) or a SPEC LITERAL read from RNS source (the flags-byte bit
positions, the 36-byte SDU overhead, MAX_EFFICIENT_SIZE), never on the same
object's own restatement of the value. The client (which opens the outbound
Link and builds the Resource) is the implementation under test; wire_resource_create
runs the full RNS.Resource __init__ with advertise=False, so nothing hits the
wire — these are pure construction-time pins.

Runs reference-vs-reference; no SUT binary required.
"""

import bz2
import math
import os
import struct

import pytest

from RNS.vendor import umsgpack

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "rescomplete"
_ASPECTS = ["test"]

# Spec literals (Reticulum.py / Resource.py). Hardcoded on purpose: the test
# encodes the spec, so an implementation — the reference included — that
# diverges from these is itself a finding.
_HEADER_MAXSIZE = 35        # RNS.Reticulum.HEADER_MAXSIZE
_IFAC_MIN_SIZE = 1          # RNS.Reticulum.IFAC_MIN_SIZE
_SDU_OVERHEAD = _HEADER_MAXSIZE + _IFAC_MIN_SIZE   # Resource.py:338 -> 36
_MAX_EFFICIENT_SIZE = 1048575   # Resource.py:116 (1 MiB - 1)
_METADATA_LEN_PREFIX = 3        # struct.pack(">I", n)[1:] -> 3 bytes (Resource.py:266)


def _predicted_metadata_size(metadata: bytes) -> int:
    """Independently predict resource.metadata_size for a `bytes` metadata
    payload from the wire spec, NOT from the RNS object.

    RNS packs metadata as: struct.pack(">I", len(packb))[1:] || umsgpack.packb(
    metadata) (Resource.py:266). The 3-byte slice is the big-endian length
    prefix; umsgpack encodes a `bytes` value in msgpack `bin` format. For a
    payload of 1..255 bytes that is bin8: marker 0xC4, a 1-byte length, then the
    raw bytes — i.e. 2 + len(metadata). So metadata_size == 3 + 2 + len(metadata).
    """
    packed = umsgpack.packb(metadata)
    return _METADATA_LEN_PREFIX + len(packed)


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_create",
    ],
    verifies=(
        "The ResourceAdvertisement flags byte packs each property at its "
        "spec-mandated bit position (Resource.py:1307, f = x<<5|p<<4|u<<3|s<<2|"
        "c<<1|e): an incompressible single-segment no-metadata Resource has "
        "flags == 0x01 (only e); a compressible one has 0x03 (e|c); a "
        "metadata-bearing one has 0x21 (e|x); compressible+metadata 0x23; and a "
        ">MAX_EFFICIENT_SIZE split Resource 0x05 (e|s). Each byte is also "
        "reconstructed from the impl's own encrypted/compressed/split/has_metadata "
        "booleans at those positions — pinning that no bit is mis-placed"
    ),
)
def test_advertisement_flags_byte_bit_layout(wire_link_setup):
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    def _flags_consistent(info):
        # Reconstruct the byte from the four boolean attributes at the spec
        # bit positions; u/p are 0 for a non request/response Resource.
        e = 1 if info["encrypted"] else 0
        c = 1 if info["compressed"] else 0
        s = 1 if info["split"] else 0
        x = 1 if info["has_metadata"] else 0
        return x << 5 | 0 << 4 | 0 << 3 | s << 2 | c << 1 | e

    incompressible = os.urandom(4096)        # bz2 cannot shrink -> c=0
    compressible = bytes(4096)               # zeros -> bz2 shrinks -> c=1
    metadata = b"resource-metadata-block"

    # e only: incompressible, no metadata, single segment.
    a = client.resource_create(link_id, incompressible)
    assert (a["compressed"], a["split"], a["has_metadata"], a["encrypted"]) == (
        False, False, False, True), f"unexpected attrs for plain resource: {a!r}"
    assert a["flags"] == 0x01, f"plain Resource flags must be 0x01 (only e): {a!r}"
    assert a["flags"] == _flags_consistent(a), f"flags byte inconsistent: {a!r}"

    # e|c: compressible payload.
    b = client.resource_create(link_id, compressible)
    assert b["compressed"] is True, f"zeros must compress: {b!r}"
    assert b["flags"] == 0x03, f"compressible Resource flags must be 0x03 (e|c): {b!r}"
    assert b["flags"] == _flags_consistent(b), f"flags byte inconsistent: {b!r}"

    # e|x: metadata, incompressible.
    c = client.resource_create(link_id, incompressible, metadata=metadata)
    assert c["has_metadata"] is True and c["compressed"] is False, f"{c!r}"
    assert c["flags"] == 0x21, f"metadata Resource flags must be 0x21 (e|x): {c!r}"
    assert c["flags"] == _flags_consistent(c), f"flags byte inconsistent: {c!r}"

    # e|c|x: compressible payload + metadata.
    d = client.resource_create(link_id, compressible, metadata=metadata)
    assert d["has_metadata"] is True and d["compressed"] is True, f"{d!r}"
    assert d["flags"] == 0x23, f"compressible+metadata flags must be 0x23 (e|c|x): {d!r}"
    assert d["flags"] == _flags_consistent(d), f"flags byte inconsistent: {d!r}"

    # e|s: a >MAX_EFFICIENT_SIZE incompressible payload splits (s bit set, bit 2).
    split_payload = os.urandom(_MAX_EFFICIENT_SIZE + 1)
    sp = client.resource_create(link_id, split_payload, include_parts=False)
    assert sp["split"] is True and sp["total_segments"] == 2, f"must split into 2: {sp!r}"
    assert sp["compressed"] is False, f"random split payload must not compress: {sp!r}"
    assert sp["flags"] == 0x05, f"split Resource flags must be 0x05 (e|s): {sp!r}"
    assert sp["flags"] == _flags_consistent(sp), f"flags byte inconsistent: {sp!r}"


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_create",
    ],
    verifies=(
        "The Resource bz2 compression decision honors both gates (Resource.py:"
        "390/400): compression is applied iff auto_compress is set AND the bz2 "
        "result is strictly smaller than the input. A compressible payload with "
        "auto_compress=True compresses; the SAME payload with auto_compress=False "
        "does not (auto_compress gate); an incompressible (random) payload with "
        "auto_compress=True does not (strictly-smaller gate). The expected "
        "decision is computed from an INDEPENDENT bz2.compress in-test"
    ),
)
def test_compression_decision_gates(wire_link_setup):
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    compressible = bytes(4096)         # zeros: bz2 strictly smaller
    incompressible = os.urandom(4096)  # random: bz2 not smaller

    def _bz2_smaller(payload: bytes) -> bool:
        # Independent recompute via Python's own bz2 — the same algorithm RNS
        # uses (Resource.py:392), computed a different way (not read off the
        # Resource object).
        return len(bz2.compress(payload)) < len(payload)

    assert _bz2_smaller(compressible) is True, "test setup: zeros must bz2-shrink"
    assert _bz2_smaller(incompressible) is False, "test setup: random must not bz2-shrink"

    # auto_compress=True + strictly smaller -> compressed.
    on = client.resource_create(link_id, compressible, auto_compress=True)
    assert on["compressed"] is True, (
        f"compressible payload with auto_compress=True must compress: {on!r}"
    )

    # auto_compress=False -> never compressed even though bz2 would shrink it.
    off = client.resource_create(link_id, compressible, auto_compress=False)
    assert off["compressed"] is False, (
        f"auto_compress=False must disable compression regardless of "
        f"compressibility (auto_compress gate): {off!r}"
    )

    # Strictly-smaller gate: random data does not compress even with auto_compress.
    rnd = client.resource_create(link_id, incompressible, auto_compress=True)
    assert rnd["compressed"] is False, (
        f"incompressible payload must NOT compress — bz2 was not strictly "
        f"smaller (strictly-smaller gate): {rnd!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_create",
    ],
    verifies=(
        "Resource metadata is encoded as a 3-byte big-endian length prefix "
        "followed by the umsgpack-packed metadata (Resource.py:266), prepended "
        "to the segment-1 plaintext, and counted into total_size (d). The "
        "total_size of a metadata-bearing Resource exceeds the no-metadata "
        "baseline by EXACTLY 3 + len(umsgpack.packb(metadata)) — the prefix plus "
        "the msgpack bin encoding — for two distinct metadata lengths, while "
        "the no-metadata total_size equals the raw payload length"
    ),
)
def test_metadata_length_prefix_encoding(wire_link_setup):
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    payload = os.urandom(1000)

    base = client.resource_create(link_id, payload, include_parts=False)
    assert base["has_metadata"] is False, f"baseline must carry no metadata: {base!r}"
    assert base["total_size"] == len(payload), (
        f"no-metadata total_size (d) must equal the raw payload length "
        f"{len(payload)}: {base!r}"
    )

    for meta_len in (10, 200):
        metadata = os.urandom(meta_len)
        expected_block = _predicted_metadata_size(metadata)
        # Cross-check the prediction matches the documented structure for the
        # small-bytes (bin8) case: 3-byte prefix + 2-byte bin8 header + body.
        assert expected_block == _METADATA_LEN_PREFIX + 2 + meta_len, (
            f"metadata-block prediction drifted from msgpack bin8 spec for "
            f"len={meta_len}: {expected_block}"
        )

        withmeta = client.resource_create(
            link_id, payload, metadata=metadata, include_parts=False
        )
        assert withmeta["has_metadata"] is True, f"metadata not flagged: {withmeta!r}"
        grew = withmeta["total_size"] - base["total_size"]
        assert grew == expected_block, (
            f"metadata of {meta_len} bytes grew total_size by {grew}, expected "
            f"exactly {expected_block} (3-byte BE length prefix + "
            f"umsgpack.packb): {withmeta!r}"
        )
        # And the absolute value: d == payload + metadata block.
        assert withmeta["total_size"] == len(payload) + expected_block, (
            f"total_size must be payload + metadata block: {withmeta!r}"
        )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_create", "link_mtu",
    ],
    verifies=(
        "Resource size accounting is pinned directly: the per-part SDU is "
        "link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE (= mtu - 36, Resource.py:338, "
        "read against the link's reported MTU); the part count n is exactly "
        "ceil(size/sdu) (Resource.py:432); d (total_size) equals the raw "
        "uncompressed payload length for a single segment; and for a "
        ">MAX_EFFICIENT_SIZE payload t (size, per-segment encrypted) is strictly "
        "less than d (total across segments) with segment_index 1 of 2"
    ),
)
def test_size_accounting_and_sdu_formula(wire_link_setup, wire_pair):
    _server_impl, client_impl = wire_pair
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    mtu = client.link_mtu(link_id)["mtu"]
    payload = os.urandom(16384)   # multi-part at any sane MTU
    info = client.resource_create(link_id, payload, include_parts=False)

    # SDU formula (Resource.py:338): sdu = link.mtu - 35 - 1.
    assert info["sdu"] == mtu - _SDU_OVERHEAD, (
        f"sdu must be link.mtu({mtu}) - {_SDU_OVERHEAD} = {mtu - _SDU_OVERHEAD}, "
        f"got {info['sdu']}"
    )

    # Part count n = ceil(encrypted_size / sdu) (Resource.py:432).
    expected_parts = math.ceil(info["size"] / info["sdu"])
    assert info["num_parts"] == expected_parts, (
        f"num_parts (n) must be ceil(size/sdu) = ceil({info['size']}/"
        f"{info['sdu']}) = {expected_parts}, got {info['num_parts']}"
    )
    assert info["num_parts"] >= 2, f"16 KiB payload must be multi-part: {info!r}"

    # d (total_size) is the uncompressed total — for a single incompressible
    # segment with no metadata that is the raw payload length.
    assert info["total_segments"] == 1 and info["split"] is False, f"{info!r}"
    assert info["total_size"] == len(payload), (
        f"single-segment total_size (d) must equal payload length "
        f"{len(payload)}: {info!r}"
    )
    # t (size) is the ENCRYPTED transfer size: a 4-byte random prefix plus the
    # payload, link-encrypted, so it strictly exceeds the plaintext payload.
    assert info["size"] > len(payload), (
        f"encrypted size (t) must exceed the {len(payload)}-byte plaintext "
        f"(random prefix + token overhead): {info!r}"
    )

    # Multi-segment: t is the FIRST segment's encrypted size, d is the TOTAL
    # uncompressed size across both segments — so t < d, and d == full payload.
    big_payload = os.urandom(_MAX_EFFICIENT_SIZE + 200000)
    big = client.resource_create(link_id, big_payload, include_parts=False)
    assert big["total_segments"] == 2 and big["segment_index"] == 1, (
        f"a >MAX_EFFICIENT_SIZE payload must be segment 1 of 2: {big!r}"
    )
    assert big["total_size"] == len(big_payload), (
        f"multi-segment total_size (d) must be the FULL payload length "
        f"{len(big_payload)}: {big!r}"
    )
    # The per-segment-t < total-d invariant requires the sender to TRUNCATE the
    # first segment at MAX_EFFICIENT_SIZE. The kotlin SUT reports the full
    # encrypted payload as the first segment's size, so this is the assertion
    # the architectural multi-segment gap breaks. Reference (and a reference
    # client paired with a kotlin server) has already run every assertion above.
    if client_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#multi-segment-send: sender never truncates per "
            "MAX_EFFICIENT_SIZE (Resource.kt:419/454); prepareNextSegment needs "
            "an inputFile byte-array sends never set; receiver has no "
            "segment-append. Multi-segment SEND/RECEIVE unimplemented. Refs "
            "Resource.py:285-323/445-448."
        )
    assert big["size"] < big["total_size"], (
        f"per-segment t ({big['size']}) must be smaller than total d "
        f"({big['total_size']}) for a split transfer: {big!r}"
    )
