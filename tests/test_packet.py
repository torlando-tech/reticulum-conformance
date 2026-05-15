"""Packet conformance tests.

Tests the RNS packet wire format by building real RNS.Packet objects on
real Destinations and cross-unpacking the resulting raw bytes between
implementations. There is no standalone "format these arbitrary header
fields" RNS API — wire-format conformance is what one impl produces and
another impl can parse, which is exactly what these tests exercise.

HEADER_2 (transport-relayed) DATA packets cannot be packed standalone (RNS
only produces them inside Transport while relaying); their wire format is
covered by the live multi-hop tests in tests/wire/test_link_multihop.py.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Packet"
__category_order__ = 5


# Destination types — the flag-byte values RNS encodes for each.
_DTYPE_SINGLE = 0
_DTYPE_PLAIN = 2

# Packet types.
_PTYPE_DATA = 0
_PTYPE_ANNOUNCE = 1


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="RNS packet wire-format cross-impl interop on a PLAIN destination: a packet built by either impl unpacks on the other to byte-identical hops/destination_hash/context/data, and the flags byte itself agrees — PLAIN carries the payload in the clear so the full wire bytes round-trip exactly",
)
def test_packet_plain_wire_format_roundtrip(sut, reference):
    payload = random_hex(32)
    for builder, unpacker, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "packet_build",
            dest_type="plain", packet_type=_PTYPE_DATA,
            context=0, context_flag=0, hops=3, data=payload,
        )
        parsed = unpacker.execute("packet_unpack", raw=built["raw"])
        assert parsed["unpacked"] is True, f"{label}: unpack rejected"
        assert parsed["flags"] == built["flags"], f"{label}: flags mismatch"
        assert parsed["hops"] == built["hops"] == 3, f"{label}: hops mismatch"
        assert parsed["destination_type"] == _DTYPE_PLAIN, f"{label}: dest_type"
        assert parsed["packet_type"] == _PTYPE_DATA, f"{label}: packet_type"
        assert_hex_equal(parsed["destination_hash"], built["destination_hash"])
        assert_hex_equal(parsed["data"], payload)  # PLAIN: data round-trips clear


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="RNS packet wire-format cross-impl interop on a SINGLE destination ANNOUNCE packet: announce payloads are not encrypted, so the full wire bytes round-trip; destination_type=SINGLE and packet_type=ANNOUNCE are recovered on the other impl",
)
def test_packet_announce_wire_format_roundtrip(sut, reference):
    payload = random_hex(40)
    for builder, unpacker, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_ANNOUNCE,
            context=0, context_flag=0, hops=0, data=payload,
        )
        parsed = unpacker.execute("packet_unpack", raw=built["raw"])
        assert parsed["unpacked"] is True, f"{label}: unpack rejected"
        assert parsed["flags"] == built["flags"], f"{label}: flags mismatch"
        assert parsed["destination_type"] == _DTYPE_SINGLE, f"{label}: dest_type"
        assert parsed["packet_type"] == _PTYPE_ANNOUNCE, f"{label}: packet_type"
        assert_hex_equal(parsed["destination_hash"], built["destination_hash"])
        # Announce packets are not encrypted, so the payload survives.
        assert_hex_equal(parsed["data"], payload)


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="RNS packet header round-trip on a SINGLE destination DATA packet: the header fields (flags, hops, destination_hash, context) parse identically across impls. Payload is encrypted-with-fresh-IV per call, so the wire bytes are non-deterministic and only the header is asserted",
)
def test_packet_single_data_header_roundtrip(sut, reference):
    payload = random_hex(16)
    for builder, unpacker, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_DATA,
            context=5, context_flag=1, hops=2, data=payload,
        )
        parsed = unpacker.execute("packet_unpack", raw=built["raw"])
        assert parsed["unpacked"] is True, f"{label}: unpack rejected"
        assert parsed["flags"] == built["flags"], f"{label}: flags mismatch"
        assert parsed["hops"] == 2, f"{label}: hops"
        assert parsed["context"] == 5, f"{label}: context"
        assert parsed["context_flag"] == 1, f"{label}: context_flag"
        assert parsed["destination_type"] == _DTYPE_SINGLE, f"{label}: dest_type"
        assert parsed["packet_type"] == _PTYPE_DATA, f"{label}: packet_type"
        assert_hex_equal(parsed["destination_hash"], built["destination_hash"])
        # Data is encrypted; payload is non-deterministic. Do not compare.


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="RNS flag byte composition for every packet kind buildable standalone (PLAIN/SINGLE × DATA/ANNOUNCE/LINKREQUEST/PROOF, both context_flag values): the flags byte raw[0] computed by RNS.Packet.pack composes to the same value both impls produce, and parse_flags decodes back to identical five-field tuples",
)
def test_packet_flags_byte_by_kind(sut, reference):
    """The RNS flag byte layout is
        bit 6: header_type (always HEADER_1 here — HEADER_2 DATA is Transport-only)
        bit 5: context_flag
        bit 4: transport_type (always BROADCAST here — TRANSPORT is Transport-only)
        bits 3-2: destination_type
        bits 1-0: packet_type
    For each combination of (dest_type, packet_type, context_flag) that builds
    standalone, RNS.Packet.pack must compose those bits the same way on both
    impls.
    """
    payload = random_hex(8)
    for dest_type, dt_bits in (("plain", _DTYPE_PLAIN), ("single", _DTYPE_SINGLE)):
        for packet_type in (0, 1, 2, 3):  # DATA, ANNOUNCE, LINKREQUEST, PROOF
            for context_flag in (0, 1):
                ref = reference.execute(
                    "packet_build",
                    dest_type=dest_type, packet_type=packet_type,
                    context=0, context_flag=context_flag, hops=0, data=payload,
                )
                res = sut.execute(
                    "packet_build",
                    dest_type=dest_type, packet_type=packet_type,
                    context=0, context_flag=context_flag, hops=0, data=payload,
                )
                assert res["flags"] == ref["flags"], (
                    f"flags byte diverged for dest_type={dest_type} "
                    f"packet_type={packet_type} context_flag={context_flag}: "
                    f"sut=0x{res['flags']:02x} ref=0x{ref['flags']:02x}"
                )
                # Same five-field decomposition on each impl.
                for f in (
                    "header_type", "context_flag", "transport_type",
                    "destination_type", "packet_type",
                ):
                    assert res[f] == ref[f], (
                        f"field {f} diverged for dest_type={dest_type} "
                        f"packet_type={packet_type} context_flag={context_flag}"
                    )
                assert res["destination_type"] == dt_bits
                assert res["packet_type"] == packet_type
                assert res["context_flag"] == context_flag


@conformance_case(
    commands=["packet_build", "packet_hash"],
    verifies="RNS packet hash (the transport-dedup key, computed over the hashable part with hops byte and HEADER_2 transport_id masked out) is byte-identical when both impls hash the same raw packet — the same call site impls hit for hashlist insertion",
)
def test_packet_hash_matches_across_impls(sut, reference):
    ref_built = reference.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=7, data=random_hex(24),
    )
    ref_h = reference.execute("packet_hash", raw=ref_built["raw"])
    res_h = sut.execute("packet_hash", raw=ref_built["raw"])
    assert_hex_equal(res_h["hash"], ref_h["hash"])
    # The hash RNS computed at pack-time (via Packet.update_hash inside pack)
    # must match the hash a receiver gets from unpack — the field name
    # "hash" on the built result is exactly that.
    assert_hex_equal(ref_built["hash"], ref_h["hash"])
