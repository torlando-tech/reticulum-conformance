"""Framing conformance tests (HDLC / KISS deframing).

RNS frames variable-length data on serial / TCP links with two classic
byte-stuffing schemes:

  * **HDLC** (used by ``TCPInterface`` and direct serial links): a frame is
    ``FLAG + HDLC.escape(payload) + FLAG`` where ``FLAG = 0x7E``. Any ``FLAG``
    or ``ESC (0x7D)`` byte inside the payload is escaped to
    ``ESC + (byte XOR 0x20)`` (``ESC`` is replaced first, then ``FLAG``).
  * **KISS** (used by ``KISSInterface`` to talk to TNCs): a frame is
    ``FEND + CMD_DATA + KISS.escape(payload) + FEND`` where ``FEND = 0xC0`` and
    ``CMD_DATA = 0x00``. Any ``FEND`` or ``FESC (0xDB)`` byte is transposed to
    ``FESC + TFEND/TFESC`` (``FESC`` replaced first, then ``FEND``).

The bridge exposes only the *receive* side — ``hdlc_deframe`` / ``kiss_deframe``
— because RNS itself has no standalone framer (the send-side escape and the
receive-side un-stuffing are inlined in each interface's read loop). These
tests therefore build a canonical frame here and assert the SUT's deframer
recovers the exact original bytes, byte-for-byte, in agreement with the
reference.

Following the suite convention (see tests/behavioral/packet_builders.py) the
test harness does NOT import RNS — the bridge is the only RNS-aware component.
The frame builders below duplicate RNS's framing constants and replacement
order; they were validated byte-for-byte against the real
``RNS.Interfaces.TCPInterface.HDLC.escape`` and
``RNS.Interfaces.KISSInterface.KISS.escape`` for random and special-byte
payloads, so the frames fed to the deframers are spec-canonical.
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
    "byte it is escaped: HDLC writes ESC + (byte XOR `0x20`); KISS writes "
    "FESC + the byte's transposed value (TFEND=`0xDC` for FEND, "
    "TFESC=`0xDD` for FESC). RNS frames with HDLC over TCP/serial interfaces "
    "and with KISS to talk to TNCs; the bridge's `hdlc_deframe`/`kiss_deframe` "
    "commands reverse that framing by delegating to RNS's own interface "
    "framing classes, so these tests assert a canonically-framed payload is "
    "recovered byte-for-byte."
)


# ---------------------------------------------------------------------------
# RNS framing constants (from RNS/Interfaces/TCPInterface.py::HDLC and
# RNS/Interfaces/KISSInterface.py::KISS). Duplicated here so the test harness
# does not import RNS (bridge is the only RNS-aware component). Validated to
# reproduce RNS's escape output byte-for-byte.
# ---------------------------------------------------------------------------
HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_ESC_MASK = 0x20

KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD
KISS_CMD_DATA = 0x00


def _hdlc_escape(data: bytes) -> bytes:
    """Mirror RNS HDLC.escape: replace ESC first, then FLAG (order matters)."""
    data = data.replace(
        bytes([HDLC_ESC]), bytes([HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK])
    )
    data = data.replace(
        bytes([HDLC_FLAG]), bytes([HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK])
    )
    return data


def _hdlc_frame(data: bytes) -> bytes:
    """Wrap a payload as RNS would on a TCP/serial interface."""
    return bytes([HDLC_FLAG]) + _hdlc_escape(data) + bytes([HDLC_FLAG])


def _kiss_escape(data: bytes) -> bytes:
    """Mirror RNS KISS.escape: replace FESC first, then FEND (order matters)."""
    data = data.replace(bytes([KISS_FESC]), bytes([KISS_FESC, KISS_TFESC]))
    data = data.replace(bytes([KISS_FEND]), bytes([KISS_FESC, KISS_TFEND]))
    return data


def _kiss_frame(data: bytes) -> bytes:
    """Wrap a payload as RNS would on a KISS TNC interface."""
    return (
        bytes([KISS_FEND, KISS_CMD_DATA]) + _kiss_escape(data) + bytes([KISS_FEND])
    )


# ---------------------------------------------------------------------------
# HDLC
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["hdlc_deframe"],
    verifies="`hdlc_deframe` recovers the exact original bytes from a 64-byte random payload wrapped in canonical HDLC framing (FLAG + byte-stuffed payload + FLAG); reference and SUT agree byte-for-byte",
)
def test_hdlc_deframe_random(sut, reference):
    payload = random_hex(64)
    framed = _hdlc_frame(bytes.fromhex(payload)).hex()
    ref = reference.execute("hdlc_deframe", framed=framed)
    res = sut.execute("hdlc_deframe", framed=framed)
    assert_hex_equal(res["data"], ref["data"])
    assert_hex_equal(res["data"], payload)


@conformance_case(
    commands=["hdlc_deframe"],
    verifies="`hdlc_deframe` correctly un-stuffs a payload that contains the HDLC special bytes FLAG (`0x7E`) and ESC (`0x7D`) — the test asserts the frame actually expanded (escape transform fired) and that both impls recover the original byte-for-byte",
)
def test_hdlc_deframe_special_bytes(sut, reference):
    # Payload deliberately contains FLAG (0x7e) and ESC (0x7d), plus a random
    # tail, so the byte-stuffing transform is exercised rather than passed
    # through untouched.
    payload_bytes = bytes([0x00, HDLC_FLAG, HDLC_ESC, 0x00, 0xFF, HDLC_FLAG]) + bytes.fromhex(random_hex(16))
    payload = payload_bytes.hex()
    framed_bytes = _hdlc_frame(payload_bytes)
    # Positive control: escaping must have expanded the payload, otherwise this
    # test would not actually exercise the un-stuffing path. A bare frame is
    # FLAG + payload + FLAG == len(payload)+2; any expansion proves a special
    # byte was escaped.
    assert len(framed_bytes) > len(payload_bytes) + 2, (
        "frame did not expand: special bytes were not escaped, so this test "
        "is not exercising HDLC byte-stuffing"
    )
    framed = framed_bytes.hex()
    ref = reference.execute("hdlc_deframe", framed=framed)
    res = sut.execute("hdlc_deframe", framed=framed)
    assert_hex_equal(res["data"], ref["data"])
    assert_hex_equal(res["data"], payload)


@conformance_case(
    commands=["hdlc_deframe"],
    verifies="Bidirectional cross-impl HDLC round-trip: a special-byte payload, fed as a canonical HDLC frame, survives sequential deframing in both orderings (reference→SUT and SUT→reference) and is recovered byte-for-byte each time",
)
def test_hdlc_deframe_cross_impl_roundtrip(sut, reference):
    payload_bytes = bytes([HDLC_ESC, HDLC_FLAG, HDLC_FLAG, HDLC_ESC]) + bytes.fromhex(random_hex(24))
    payload = payload_bytes.hex()

    # Direction 1: reference deframes the canonical frame, the recovered bytes
    # are re-framed canonically, then the SUT deframes — payload must survive.
    mid_ref = reference.execute("hdlc_deframe", framed=_hdlc_frame(payload_bytes).hex())["data"]
    out_ref_then_sut = sut.execute(
        "hdlc_deframe", framed=_hdlc_frame(bytes.fromhex(mid_ref)).hex()
    )["data"]
    assert_hex_equal(out_ref_then_sut, payload)

    # Direction 2: SUT first, then reference.
    mid_sut = sut.execute("hdlc_deframe", framed=_hdlc_frame(payload_bytes).hex())["data"]
    out_sut_then_ref = reference.execute(
        "hdlc_deframe", framed=_hdlc_frame(bytes.fromhex(mid_sut)).hex()
    )["data"]
    assert_hex_equal(out_sut_then_ref, payload)


# ---------------------------------------------------------------------------
# KISS
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["kiss_deframe"],
    verifies="`kiss_deframe` recovers the exact original bytes from a 64-byte random payload wrapped in canonical KISS framing (FEND + CMD_DATA + transposed payload + FEND); reference and SUT agree byte-for-byte",
)
def test_kiss_deframe_random(sut, reference):
    payload = random_hex(64)
    framed = _kiss_frame(bytes.fromhex(payload)).hex()
    ref = reference.execute("kiss_deframe", framed=framed)
    res = sut.execute("kiss_deframe", framed=framed)
    assert_hex_equal(res["data"], ref["data"])
    assert_hex_equal(res["data"], payload)


@conformance_case(
    commands=["kiss_deframe"],
    verifies="`kiss_deframe` correctly un-transposes a payload that contains the KISS special bytes FEND (`0xC0`) and FESC (`0xDB`) — the test asserts the frame actually expanded (transpose fired) and that both impls recover the original byte-for-byte",
)
def test_kiss_deframe_special_bytes(sut, reference):
    # Payload deliberately contains FEND (0xc0) and FESC (0xdb), plus a random
    # tail, so the transpose transform is exercised rather than passed through.
    payload_bytes = bytes([0x00, KISS_FEND, KISS_FESC, 0x00, 0xFF, KISS_FEND]) + bytes.fromhex(random_hex(16))
    payload = payload_bytes.hex()
    framed_bytes = _kiss_frame(payload_bytes)
    # Positive control: a bare KISS frame is FEND + CMD_DATA + payload + FEND
    # == len(payload)+3; any expansion proves a special byte was transposed.
    assert len(framed_bytes) > len(payload_bytes) + 3, (
        "frame did not expand: special bytes were not transposed, so this "
        "test is not exercising KISS byte-stuffing"
    )
    framed = framed_bytes.hex()
    ref = reference.execute("kiss_deframe", framed=framed)
    res = sut.execute("kiss_deframe", framed=framed)
    assert_hex_equal(res["data"], ref["data"])
    assert_hex_equal(res["data"], payload)


@conformance_case(
    commands=["kiss_deframe"],
    verifies="Bidirectional cross-impl KISS round-trip: a special-byte payload, fed as a canonical KISS frame, survives sequential deframing in both orderings (reference→SUT and SUT→reference) and is recovered byte-for-byte each time",
)
def test_kiss_deframe_cross_impl_roundtrip(sut, reference):
    payload_bytes = bytes([KISS_FESC, KISS_FEND, KISS_FEND, KISS_FESC]) + bytes.fromhex(random_hex(24))
    payload = payload_bytes.hex()

    # Direction 1: reference then SUT.
    mid_ref = reference.execute("kiss_deframe", framed=_kiss_frame(payload_bytes).hex())["data"]
    out_ref_then_sut = sut.execute(
        "kiss_deframe", framed=_kiss_frame(bytes.fromhex(mid_ref)).hex()
    )["data"]
    assert_hex_equal(out_ref_then_sut, payload)

    # Direction 2: SUT then reference.
    mid_sut = sut.execute("kiss_deframe", framed=_kiss_frame(payload_bytes).hex())["data"]
    out_sut_then_ref = reference.execute(
        "kiss_deframe", framed=_kiss_frame(bytes.fromhex(mid_sut)).hex()
    )["data"]
    assert_hex_equal(out_sut_then_ref, payload)
