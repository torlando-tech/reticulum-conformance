"""Reticulum global-constant completeness tests (core commands).

Pins the wire-size constants declared in RNS.Reticulum (Reticulum.py:91-151)
that the existing Packet suite only constrains loosely:

  * MTU            = 500              (Reticulum.py:92)
  * TRUNCATED_HASHLENGTH = 128 bits   (Reticulum.py:144)
  * HEADER_MINSIZE = 2+1+16 = 19      (Reticulum.py:146)
  * HEADER_MAXSIZE = 2+1+32 = 35      (Reticulum.py:147)
  * IFAC_MIN_SIZE  = 1               (Reticulum.py:148)
  * MDU            = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE = 464 (Reticulum.py:151)

These are pinned against EXTERNAL spec literals (the constants above, read out
of the RNS source) by measuring the wire bytes RNS actually produces through
Packet.pack() / Packet.unpack() — never by comparing an impl's output to its
own re-parse of the same bytes. Every header-overhead and boundary assertion
anchors on a fixed integer, with a positive (accepted) and negative (rejected)
side, so an impl whose MTU or header layout diverges fails here even though the
loose oversize test (tests/test_packet.py) passes for any MTU in ~470..618.
"""

import pytest

from bridge_client import BridgeError
from conftest import random_hex
from conformance import conformance_case


__category_title__ = "Reticulum Config"
__category_order__ = 6


# Packet/header constants (RNS spec literals, ground truth RNS 1.3.1).
_PTYPE_DATA = 0
_PTYPE_ANNOUNCE = 1
_DTYPE_PLAIN = 2

# RNS.Reticulum constants — the exact integers this file pins.
_MTU = 500                      # Reticulum.MTU
_TRUNCATED_HASH_BYTES = 16      # TRUNCATED_HASHLENGTH // 8 == 128 // 8
_HEADER_MINSIZE = 19            # 2 + 1 + 16
_HEADER_MAXSIZE = 35            # 2 + 1 + 32
_IFAC_MIN_SIZE = 1
_MDU = 464                      # MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE


@conformance_case(
    commands=["packet_build"],
    verifies="RNS.Reticulum.MTU is exactly 500 bytes, enforced at Packet.pack: on a PLAIN HEADER_1 destination (19-byte header) the largest payload that packs is 481 bytes, producing a wire frame of EXACTLY 500 bytes (==MTU, not merely <=MTU), and a payload one byte larger is rejected (raw would be 501 > MTU). Pins the exact ceiling — an impl with MTU 499 or 501 fails — unlike the loose oversize test that any MTU in ~470..618 satisfies",
)
def test_mtu_is_exactly_500_at_pack_boundary(sut):
    # PLAIN HEADER_1 header overhead is 19 bytes (pinned independently below),
    # so a 481-byte payload packs to exactly 19 + 481 == 500 == MTU.
    at_ceiling = sut.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data=random_hex(_MTU - _HEADER_MINSIZE),
    )
    raw_len = len(bytes.fromhex(at_ceiling["raw"]))
    assert raw_len == _MTU, (
        f"largest-accepted PLAIN frame is {raw_len} bytes; the per-packet "
        f"ceiling (RNS.Reticulum.MTU) must be exactly {_MTU}"
    )

    # One byte more pushes the wire frame to 501 > MTU and must be rejected at
    # pack time (Packet.pack raises IOError, surfaced as BridgeError), not
    # silently truncated or emitted oversize.
    with pytest.raises(BridgeError):
        sut.execute(
            "packet_build",
            dest_type="plain", packet_type=_PTYPE_DATA,
            context=0, context_flag=0, hops=0,
            data=random_hex(_MTU - _HEADER_MINSIZE + 1),
        )


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="HEADER_MINSIZE == 19 (2 flags/hops bytes + 1 context byte + a 16-byte == TRUNCATED_HASHLENGTH//8 destination hash): a PLAIN HEADER_1 frame's wire length minus its payload length is exactly 19 for several payload sizes, an empty-payload frame is exactly 19 bytes and unpacks, and truncating that frame to 18 bytes is rejected — pinning the minimum header size exactly (an impl with a 18- or 20-byte minimum fails)",
)
def test_header1_minsize_is_19(sut, reference):
    # Overhead is constant at 19 regardless of payload (independent derivation:
    # wire_len - payload_len), measured on both impls.
    for builder, label in ((sut, "sut"), (reference, "reference")):
        for payload_bytes in (0, 1, 16, 64):
            built = builder.execute(
                "packet_build",
                dest_type="plain", packet_type=_PTYPE_DATA,
                context=0, context_flag=0, hops=0, data=random_hex(payload_bytes),
            )
            raw_len = len(bytes.fromhex(built["raw"]))
            assert raw_len - payload_bytes == _HEADER_MINSIZE, (
                f"{label}: PLAIN HEADER_1 overhead is {raw_len - payload_bytes} "
                f"for a {payload_bytes}-byte payload; HEADER_MINSIZE must be "
                f"{_HEADER_MINSIZE}"
            )

    # The empty-payload frame is exactly the minimum header (19 bytes) and must
    # unpack (positive: an impl requiring >=20 bytes fails here)...
    minimal = sut.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data="",
    )
    raw = bytes.fromhex(minimal["raw"])
    assert len(raw) == _HEADER_MINSIZE, (
        f"empty-payload PLAIN frame is {len(raw)} bytes; must equal "
        f"HEADER_MINSIZE == {_HEADER_MINSIZE}"
    )
    accepted = sut.execute("packet_unpack", raw=raw.hex())
    assert accepted["unpacked"] is True, (
        f"a minimal {_HEADER_MINSIZE}-byte HEADER_1 frame must unpack"
    )

    # ...while one byte short of the minimum header is rejected (negative).
    rejected = sut.execute("packet_unpack", raw=raw[:_HEADER_MINSIZE - 1].hex())
    assert rejected["unpacked"] is False, (
        f"an {_HEADER_MINSIZE - 1}-byte frame (one short of HEADER_MINSIZE) "
        f"must be rejected, got {rejected}"
    )


@conformance_case(
    commands=["packet_build"],
    verifies="HEADER_MAXSIZE == 35 (2 + 1 + 32, i.e. HEADER_MINSIZE plus a second 16-byte truncated hash for the transport_id): a HEADER_2 announce's wire length minus its payload length is exactly 35, and that overhead exceeds the HEADER_1 overhead (19) by exactly 16 == TRUNCATED_HASHLENGTH//8 — pinning the transport_id field width and the maximum header size",
)
def test_header2_maxsize_is_35(sut):
    transport_id = random_hex(_TRUNCATED_HASH_BYTES)
    for payload_bytes in (0, 1, 32):
        built = sut.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_ANNOUNCE,
            context=0, context_flag=0, hops=0, data=random_hex(payload_bytes),
            header_type=2, transport_id=transport_id,
        )
        raw_len = len(bytes.fromhex(built["raw"]))
        assert raw_len - payload_bytes == _HEADER_MAXSIZE, (
            f"HEADER_2 announce overhead is {raw_len - payload_bytes} for a "
            f"{payload_bytes}-byte payload; HEADER_MAXSIZE must be "
            f"{_HEADER_MAXSIZE}"
        )

    # The HEADER_2 - HEADER_1 overhead delta is exactly the transport_id width:
    # one extra 16-byte truncated hash (TRUNCATED_HASHLENGTH // 8).
    h1 = sut.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data="",
    )
    h1_overhead = len(bytes.fromhex(h1["raw"]))
    assert _HEADER_MAXSIZE - h1_overhead == _TRUNCATED_HASH_BYTES, (
        f"HEADER_2 ({_HEADER_MAXSIZE}) exceeds HEADER_1 ({h1_overhead}) by "
        f"{_HEADER_MAXSIZE - h1_overhead}; the transport_id must add exactly "
        f"{_TRUNCATED_HASH_BYTES} bytes (TRUNCATED_HASHLENGTH // 8)"
    )


@conformance_case(
    commands=["packet_build"],
    verifies="MDU == 464 derives from the SUT-observed MTU and HEADER_MAXSIZE as MDU = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE (Reticulum.py:151): observing MTU==500 (max accepted PLAIN frame) and HEADER_MAXSIZE==35 (HEADER_2 overhead), and with the spec literal IFAC_MIN_SIZE==1, the maximum data unit is exactly 464. An impl whose MTU or worst-case header diverges yields a different MDU and fails",
)
def test_mdu_derivation(sut):
    # MTU observed as the exact size of the largest accepted PLAIN frame.
    ceiling = sut.execute(
        "packet_build",
        dest_type="plain", packet_type=_PTYPE_DATA,
        context=0, context_flag=0, hops=0, data=random_hex(_MTU - _HEADER_MINSIZE),
    )
    observed_mtu = len(bytes.fromhex(ceiling["raw"]))
    assert observed_mtu == _MTU

    # HEADER_MAXSIZE observed as the HEADER_2 announce overhead.
    h2 = sut.execute(
        "packet_build",
        dest_type="single", packet_type=_PTYPE_ANNOUNCE,
        context=0, context_flag=0, hops=0, data="",
        header_type=2, transport_id=random_hex(_TRUNCATED_HASH_BYTES),
    )
    observed_header_max = len(bytes.fromhex(h2["raw"]))
    assert observed_header_max == _HEADER_MAXSIZE

    derived_mdu = observed_mtu - observed_header_max - _IFAC_MIN_SIZE
    assert derived_mdu == _MDU, (
        f"MDU = MTU({observed_mtu}) - HEADER_MAXSIZE({observed_header_max}) - "
        f"IFAC_MIN_SIZE({_IFAC_MIN_SIZE}) = {derived_mdu}; must be {_MDU}"
    )
