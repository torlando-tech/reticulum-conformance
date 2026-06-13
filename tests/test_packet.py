"""Packet conformance tests.

Tests the RNS packet wire format by building real RNS.Packet objects on
real Destinations and cross-unpacking the resulting raw bytes between
implementations. There is no standalone "format these arbitrary header
fields" RNS API — wire-format conformance is what one impl produces and
another impl can parse, which is exactly what these tests exercise.

HEADER_2 (transport-relayed) DATA packets cannot be packed standalone (RNS
only produces them inside Transport while relaying); their wire format is
covered by the live multi-hop tests in tests/wire/test_link_multihop.py.
HEADER_2 ANNOUNCE packets, however, ARE buildable standalone (RNS.Packet.pack
assembles a HEADER_2 header for announces) and are exercised directly here.
"""

import pytest

from bridge_client import BridgeError
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

# Header types — the RNS.Packet constants (HEADER_1 == 0, HEADER_2 == 1), which
# are also what RNS.Packet.unpack reports back in the `header_type` field.
_HEADER_1 = 0
_HEADER_2 = 1

# RNS.Reticulum.MTU (bytes) — the per-packet wire-size ceiling Packet.pack
# enforces. Asserted in the oversize-rejection test below.
_MTU = 500


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="RNS packet wire-format cross-impl interop on a PLAIN destination: a packet built by either impl unpacks on the other to byte-identical hops/destination_hash/context/data, the flags byte equals its first-principles value (PLAIN<<2 | DATA), and the other impl decodes that byte into the same five header fields the builder intended — PLAIN carries the payload in the clear so the full wire bytes round-trip exactly",
)
def test_packet_plain_wire_format_roundtrip(sut, reference):
    payload = random_hex(32)
    # First-principles flags byte for a HEADER_1 / BROADCAST / PLAIN / DATA
    # packet with context_flag=0: only the destination_type bits are set.
    expected_flags = (_DTYPE_PLAIN << 2) | _PTYPE_DATA
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
        # L7: the prior `parsed["flags"] == built["flags"]` compared raw[0] to
        # itself (both impls just read byte 0 of the IDENTICAL wire bytes), so
        # it asserted nothing. Pin the builder's flags byte to its known value,
        # then assert the OTHER impl decodes raw[0] into the same five header
        # fields the builder did — the real cross-impl flag-decode interop check.
        assert built["flags"] == expected_flags, (
            f"{label}: builder flags 0x{built['flags']:02x} != "
            f"0x{expected_flags:02x}"
        )
        for field, want in (
            ("header_type", _HEADER_1), ("context_flag", 0),
            ("transport_type", 0), ("destination_type", _DTYPE_PLAIN),
            ("packet_type", _PTYPE_DATA),
        ):
            assert parsed[field] == built[field] == want, (
                f"{label}: flag field {field} diverged "
                f"(parsed={parsed[field]} built={built[field]} want={want})"
            )
        assert parsed["hops"] == built["hops"] == 3, f"{label}: hops mismatch"
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
    verifies="RNS packet hash (the transport-dedup / hashlist key): in BOTH build directions, the other impl computing packet_hash on the builder's raw bytes reproduces the hash the builder itself reported, and the hash is invariant to the hops byte (mutating raw[1] does not change it) — confirming the hops byte is masked out of the hashable part, as RNS does so a packet keeps one hashlist identity as it propagates",
)
def test_packet_hash_matches_across_impls(sut, reference):
    for builder, hasher, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "packet_build",
            dest_type="plain", packet_type=_PTYPE_DATA,
            context=0, context_flag=0, hops=7, data=random_hex(24),
        )
        # L8: the prior second assert compared the reference's own build-time
        # hash to its own packet_hash (both reference, both via unpack ->
        # get_hash on the same bytes), so it always passed and never touched
        # the SUT. The discriminating check is cross-impl: the OTHER impl
        # hashing the builder's wire bytes must reproduce the hash the builder
        # reported. (Both `built["hash"]` and packet_hash come from a real
        # unpack -> get_hash; there is no separate pack-time hash to compare.)
        cross = hasher.execute("packet_hash", raw=built["raw"])
        assert_hex_equal(
            cross["hash"], built["hash"],
            f"{label}: cross-impl packet_hash != builder-reported hash",
        )
        # The hops byte (raw[1]) is excluded from the hashable part. Bump it and
        # the hash must not move; an impl that hashed the hops byte would lose
        # dedup identity on every relay and diverge here.
        raw = bytes.fromhex(built["raw"])
        bumped = (raw[:1] + bytes([(raw[1] + 1) & 0xFF]) + raw[2:]).hex()
        bumped_h = hasher.execute("packet_hash", raw=bumped)
        assert_hex_equal(
            bumped_h["hash"], built["hash"],
            f"{label}: packet hash changed when the hops byte was mutated",
        )


@conformance_case(
    commands=["packet_build", "packet_hash"],
    verifies="RNS get_hashable_part masks the mutable/interface-scoped flag bits out of the packet hash: starting from a PLAIN DATA packet, flipping bit 7 (IFAC), bit 5 (context_flag) or bit 4 (propagation/transport_type) in the flags byte leaves packet_hash UNCHANGED (these bits are excluded via raw[0] & 0x0f), while flipping a low-nibble bit (packet_type) DOES change the hash — so a relayed/interface-rescoped packet keeps one hashlist identity. Complements the hops-byte and transport_id masking already pinned",
)
def test_packet_hash_masks_flag_bits_7_5_4(sut):
    built = sut.execute(
        "packet_build", dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data=random_hex(24),
    )
    raw = bytes.fromhex(built["raw"])
    base = sut.execute("packet_hash", raw=raw.hex())["hash"]
    # Bits 7 (IFAC), 5 (context_flag) and 4 (propagation/transport_type) are
    # masked out of get_hashable_part; mutating any of them must not move the hash.
    for bit, name in ((0x80, "IFAC bit7"), (0x20, "context_flag bit5"),
                      (0x10, "propagation bit4")):
        mutated = bytearray(raw)
        mutated[0] ^= bit
        h = sut.execute("packet_hash", raw=bytes(mutated).hex())["hash"]
        assert_hex_equal(h, base, f"flipping {name} changed the packet hash (not masked)")
    # Contrast: a low-nibble bit (packet_type, bit 0) IS part of the hashable
    # part, so flipping it MUST change the hash — proving the hash isn't constant.
    contrast = bytearray(raw)
    contrast[0] ^= 0x01
    assert sut.execute("packet_hash", raw=bytes(contrast).hex())["hash"] != base, (
        "flipping a low-nibble flag bit did not change the hash — the hashable "
        "part is not actually covering the packet_type bits"
    )


@conformance_case(
    commands=["packet_build", "packet_unpack", "packet_hash"],
    verifies="RNS HEADER_2 (transport-relayed) ANNOUNCE wire format: the 16-byte transport_id placed between the hops byte and the destination_hash round-trips through the other impl's unpack byte-for-byte, and the transport_id is masked OUT of the packet hash — hashing the HEADER_1-equivalent bytes (transport_id stripped at raw[2:18], header_type bit cleared) yields the identical hash, exactly as RNS.Packet.get_hashable_part skips raw[2:18] for HEADER_2 so a relayed announce keeps the originator's hashlist identity",
)
def test_packet_header2_transport_id_roundtrip_and_hash_masking(sut, reference):
    transport_id = random_hex(16)  # TRUNCATED_HASHLENGTH // 8 == 16 bytes
    payload = random_hex(40)
    for builder, unpacker, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_ANNOUNCE,
            context=0, context_flag=0, hops=4, data=payload,
            header_type=2, transport_id=transport_id,
        )
        # The transport_id rides in the header; the other impl must recover it
        # byte-for-byte, and decode the header as a HEADER_2 SINGLE announce.
        parsed = unpacker.execute("packet_unpack", raw=built["raw"])
        assert parsed["unpacked"] is True, f"{label}: HEADER_2 unpack rejected"
        assert parsed["header_type"] == _HEADER_2, f"{label}: not HEADER_2"
        assert parsed["destination_type"] == _DTYPE_SINGLE, f"{label}: dest_type"
        assert parsed["packet_type"] == _PTYPE_ANNOUNCE, f"{label}: packet_type"
        assert_hex_equal(
            parsed["transport_id"], transport_id,
            f"{label}: transport_id did not round-trip",
        )
        assert_hex_equal(parsed["destination_hash"], built["destination_hash"])

        # transport_id is masked out of the hash. Derive the HEADER_1-equivalent
        # wire bytes from the SAME packet: clear the header_type bit (0x40) and
        # drop the 16-byte transport_id at raw[2:18]. RNS get_hashable_part is
        # (raw[0] & 0x0f) + raw[18:] for HEADER_2 and (raw[0] & 0x0f) + raw[2:]
        # for HEADER_1 — identical bytes here — so the two hashes must agree.
        raw = bytes.fromhex(built["raw"])
        assert_hex_equal(
            raw[2:18].hex(), transport_id,
            f"{label}: transport_id not at the HEADER_2 wire offset raw[2:18]",
        )
        h1_equiv = (bytes([raw[0] & ~0x40]) + raw[1:2] + raw[18:]).hex()
        h2_hash = unpacker.execute("packet_hash", raw=built["raw"])
        h1_hash = unpacker.execute("packet_hash", raw=h1_equiv)
        assert_hex_equal(
            h1_hash["hash"], h2_hash["hash"],
            f"{label}: HEADER_2 hash != HEADER_1-equivalent — transport_id "
            f"leaked into the hashable part",
        )
        # And the builder's own reported hash matches the hasher's computation.
        assert_hex_equal(
            h2_hash["hash"], built["hash"],
            f"{label}: cross-impl HEADER_2 hash != builder-reported hash",
        )


@conformance_case(
    commands=["packet_build"],
    verifies="RNS enforces the per-packet MTU (RNS.Reticulum.MTU == 500 bytes) at pack time: building a packet whose payload pushes the wire size past the MTU is rejected (Packet.pack raises), while a payload that comfortably fits is accepted (positive control) — so an impl that silently emits oversize packets fails",
)
def test_packet_build_rejects_oversize_mtu(sut):
    # Positive control: a small payload packs to wire bytes well under the MTU.
    fits = sut.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data=random_hex(64),
    )
    assert len(bytes.fromhex(fits["raw"])) <= _MTU, "positive control over MTU"

    # Negative: a 600-byte payload (raw ~619B) exceeds the 500B MTU and must be
    # rejected at pack time, not silently truncated or emitted oversize.
    with pytest.raises(BridgeError):
        sut.execute(
            "packet_build",
            dest_type="plain", packet_type=_PTYPE_DATA,
            context=0, context_flag=0, hops=0, data=random_hex(600),
        )


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="RNS rejects malformed/truncated packets: feeding raw bytes shorter than the minimum HEADER_1 header (flags+hops+16B destination_hash+context = 19 bytes), including empty input, to packet_unpack returns unpacked=False rather than fabricating header fields, while a well-formed packet unpacks (positive control)",
)
def test_packet_unpack_rejects_truncated(sut, reference):
    # Positive control: a real packet unpacks cleanly.
    built = reference.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data=random_hex(16),
    )
    good = sut.execute("packet_unpack", raw=built["raw"])
    assert good["unpacked"] is True, "positive control: valid packet must unpack"

    # Negative: inputs shorter than the 19-byte HEADER_1 minimum must be
    # rejected, not parsed into bogus fields.
    raw = bytes.fromhex(built["raw"])
    for bad, why in (
        (b"", "empty"),
        (raw[:1], "flags byte only"),
        (raw[:10], "truncated mid destination_hash"),
        (raw[:18], "one byte short of the full header"),
    ):
        rejected = sut.execute("packet_unpack", raw=bad.hex())
        assert rejected["unpacked"] is False, (
            f"truncated input ({why}) must be rejected, got {rejected}"
        )


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="RNS rejects truncated HEADER_2 (transport-relayed) frames: a HEADER_2 announce needs at least 35 bytes (flags+hops+16B transport_id+16B destination_hash+context), so feeding any 19–34 byte frame that has the HEADER_2 bit set to packet_unpack returns unpacked=False rather than fabricating a transport_id or destination from bytes that aren't there, while the full HEADER_2 frame unpacks (positive control). Pins the HEADER_2_MIN_SIZE gate the suite previously enforced only in the harness parser",
)
def test_packet_unpack_rejects_truncated_header2(sut):
    transport_id = random_hex(16)
    built = sut.execute(
        "packet_build",
        dest_type="single", packet_type=_PTYPE_ANNOUNCE,
        context=0, context_flag=0, hops=0, data=random_hex(40),
        header_type=2, transport_id=transport_id,
    )
    raw = bytes.fromhex(built["raw"])
    # Positive control: the full HEADER_2 frame unpacks and is reported HEADER_2.
    good = sut.execute("packet_unpack", raw=raw.hex())
    assert good["unpacked"] is True and good["header_type"] == _HEADER_2
    # The header_type bit is set, so the parser MUST require >=35 bytes. Any
    # frame in [19, 34] with that bit set lacks room for transport_id+dest.
    for length in (19, 24, 33, 34):
        truncated = raw[:length]
        # Confirm the HEADER_2 bit survives the truncation (it lives in raw[0]).
        assert (truncated[0] & 0x40) >> 6 == _HEADER_2
        rejected = sut.execute("packet_unpack", raw=truncated.hex())
        assert rejected["unpacked"] is False, (
            f"a {length}-byte HEADER_2 frame must be rejected (< 35-byte minimum), "
            f"got {rejected}"
        )
