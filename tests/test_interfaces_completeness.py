"""Interface framing completeness tests (HDLC / KISS stream parsing).

These tests extend ``tests/test_framing.py`` to pin the *stream-parsing*
semantics of RNS's HDLC and KISS read loops — the facets the existing
deframe tests do not exercise because they feed exactly one isolated,
clean, canonical frame.

Ground truth is the real RNS 1.3.1 read loop in
``RNS/Interfaces/TCPInterface.py``:

  * **HDLC** (``TCPInterface.py:384-394`` "standard HDLC framing" branch)::

        frame_start = frame_buffer.find(HDLC.FLAG)        # first FLAG wins
        frame_end   = frame_buffer.find(HDLC.FLAG, ...)    # next FLAG closes
        frame       = frame_buffer[frame_start+1:frame_end]

    so (a) any bytes *before* the first FLAG are skipped, and (b) a frame is
    exactly the bytes between the first two FLAGs — trailing bytes (including
    a whole following frame) after the closing FLAG do not bleed into it.

  * **KISS** (``TCPInterface.py:353-368`` kiss_framing branch): the same
    delimiter-scan semantics with FEND (``0xC0``) as the delimiter and a
    leading CMD byte after the opening FEND.

The bridge's ``hdlc_deframe`` / ``kiss_deframe`` commands mirror exactly that
slice-between-first-two-delimiters behaviour (``reference/bridge_server.py``
``cmd_hdlc_deframe`` / ``cmd_kiss_deframe`` both do ``find(FLAG)`` then
``find(FLAG, start+1)``), so these tests assert that property at the byte
level with an independent payload anchor and reference/SUT agreement.

Following the suite convention the harness does NOT import RNS; the frame
builders below duplicate RNS's framing constants and replacement order and
were validated byte-for-byte against the real ``HDLC.escape`` /
``KISS.escape`` (see ``tests/test_framing.py`` for the same constants).
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Framing"
__category_order__ = 6
__category_description__ = (
    "Stream-level HDLC/KISS frame extraction: a frame is the bytes between "
    "the first two delimiters, bytes before the first delimiter are skipped, "
    "and trailing bytes after the closing delimiter (including a following "
    "frame) do not bleed into the recovered frame. Exercises the receive-side "
    "parsing semantics of the RNS TCPInterface read loop via the bridge's "
    "`hdlc_deframe`/`kiss_deframe` commands."
)


# ---------------------------------------------------------------------------
# RNS framing constants (RNS/Interfaces/TCPInterface.py::HDLC and
# RNS/Interfaces/KISSInterface.py::KISS). Duplicated so the harness does not
# import RNS; identical to the values validated in tests/test_framing.py.
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
    return bytes([HDLC_FLAG]) + _hdlc_escape(data) + bytes([HDLC_FLAG])


def _kiss_escape(data: bytes) -> bytes:
    """Mirror RNS KISS.escape: replace FESC first, then FEND (order matters)."""
    data = data.replace(bytes([KISS_FESC]), bytes([KISS_FESC, KISS_TFESC]))
    data = data.replace(bytes([KISS_FEND]), bytes([KISS_FESC, KISS_TFEND]))
    return data


def _kiss_frame(data: bytes) -> bytes:
    return (
        bytes([KISS_FEND, KISS_CMD_DATA]) + _kiss_escape(data) + bytes([KISS_FEND])
    )


# ---------------------------------------------------------------------------
# HDLC stream parsing
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["hdlc_deframe"],
    verifies=(
        "HDLC frame boundary: when two complete frames are concatenated into "
        "one stream (FLAG p1 FLAG p2 FLAG), the deframer recovers EXACTLY the "
        "first frame's payload p1 — bytes between the first two FLAGs — and "
        "neither the second frame p2 nor the concatenation p1||p2 leaks in "
        "(RNS TCPInterface read loop slices frame_buffer[start+1:end])"
    ),
)
def test_hdlc_frame_boundary_between_first_two_flags(sut, reference):
    # Two independent payloads. p1 is the first frame; p2 follows the shared
    # FLAG. Use bytes that include a 0x00 so an off-by-one boundary error would
    # produce an observably different (longer) result.
    p1 = bytes.fromhex(random_hex(24))
    p2 = bytes([0x00, 0xFF]) + bytes.fromhex(random_hex(8))
    stream = _hdlc_frame(p1)[:-1] + _hdlc_frame(p2)  # FLAG p1 FLAG p2 FLAG
    # Sanity: the stream really contains exactly three FLAG delimiters, so the
    # "first frame = between first two FLAGs" rule is actually under test.
    assert stream.count(bytes([HDLC_FLAG])) == 3, "stream is not two shared-FLAG frames"

    ref = reference.execute("hdlc_deframe", framed=stream.hex())
    res = sut.execute("hdlc_deframe", framed=stream.hex())
    assert_hex_equal(res["data"], ref["data"])
    # Positive: exactly the first frame.
    assert_hex_equal(res["data"], p1.hex())
    # Negative: the boundary is respected — p2 and p1||p2 must NOT appear.
    assert res["data"] != p2.hex(), "deframer returned the second frame, not the first"
    assert res["data"] != (p1 + p2).hex(), (
        "deframer swallowed the closing FLAG and concatenated both frames"
    )


@conformance_case(
    commands=["hdlc_deframe"],
    verifies=(
        "HDLC leading-garbage skip: non-FLAG bytes before the first FLAG are "
        "ignored (RNS scans with frame_buffer.find(FLAG)). A garbage-prefixed "
        "frame deframes to the SAME payload as the clean frame, and the "
        "garbage bytes never appear in the output"
    ),
)
def test_hdlc_deframe_skips_leading_garbage(sut, reference):
    payload = bytes.fromhex(random_hex(40))
    # Pre-FLAG noise that deliberately contains the ESC byte (0x7D) but NOT a
    # FLAG (0x7E) — proving the scan keys on FLAG specifically and is not
    # confused by a stray escape byte before any frame opens.
    garbage = bytes([0x11, HDLC_ESC, 0x22, 0x33])
    assert HDLC_FLAG not in garbage, "garbage must not contain a FLAG"
    clean = _hdlc_frame(payload)
    dirty = garbage + clean

    clean_out = sut.execute("hdlc_deframe", framed=clean.hex())["data"]
    dirty_out = sut.execute("hdlc_deframe", framed=dirty.hex())["data"]
    ref_out = reference.execute("hdlc_deframe", framed=dirty.hex())["data"]

    assert_hex_equal(dirty_out, ref_out)
    # Positive: garbage skipped, exact payload recovered, identical to clean.
    assert_hex_equal(dirty_out, payload.hex())
    assert_hex_equal(dirty_out, clean_out)
    # Negative: the garbage prefix was not prepended to the output.
    assert dirty_out != (garbage + payload).hex(), (
        "leading garbage leaked into the recovered frame"
    )


# ---------------------------------------------------------------------------
# KISS stream parsing
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["kiss_deframe"],
    verifies=(
        "KISS frame boundary: two concatenated KISS frames (FEND CMD p1 FEND "
        "CMD p2 FEND) deframe to EXACTLY the first payload p1 — bytes between "
        "the first two FEND delimiters, minus the leading CMD byte — and the "
        "second frame p2 / concatenation does not leak in"
    ),
)
def test_kiss_frame_boundary_between_first_two_fends(sut, reference):
    p1 = bytes.fromhex(random_hex(24))
    p2 = bytes([0x00, 0xFF]) + bytes.fromhex(random_hex(8))
    # FEND CMD esc(p1) FEND CMD esc(p2) FEND : drop the trailing FEND of frame1
    # so its closing FEND is shared as frame2's opener (RNS reuses delimiters).
    stream = _kiss_frame(p1)[:-1] + _kiss_frame(p2)
    assert stream.count(bytes([KISS_FEND])) == 3, "stream is not two shared-FEND frames"

    ref = reference.execute("kiss_deframe", framed=stream.hex())
    res = sut.execute("kiss_deframe", framed=stream.hex())
    assert_hex_equal(res["data"], ref["data"])
    # Positive: exactly the first frame's payload.
    assert_hex_equal(res["data"], p1.hex())
    # Negative: boundary respected.
    assert res["data"] != p2.hex(), "deframer returned the second frame, not the first"
    assert res["data"] != (p1 + p2).hex(), (
        "deframer swallowed the closing FEND and concatenated both frames"
    )


@conformance_case(
    commands=["kiss_deframe"],
    verifies=(
        "KISS leading-garbage skip: non-FEND bytes before the first FEND are "
        "ignored (RNS scans for FEND to open a frame). A garbage-prefixed KISS "
        "frame deframes to the SAME payload as the clean frame, and the "
        "garbage never appears in the output"
    ),
)
def test_kiss_deframe_skips_leading_garbage(sut, reference):
    payload = bytes.fromhex(random_hex(40))
    # Pre-FEND noise containing the FESC byte (0xDB) but NOT a FEND (0xC0).
    garbage = bytes([0x11, KISS_FESC, 0x22, 0x33])
    assert KISS_FEND not in garbage, "garbage must not contain a FEND"
    clean = _kiss_frame(payload)
    dirty = garbage + clean

    clean_out = sut.execute("kiss_deframe", framed=clean.hex())["data"]
    dirty_out = sut.execute("kiss_deframe", framed=dirty.hex())["data"]
    ref_out = reference.execute("kiss_deframe", framed=dirty.hex())["data"]

    assert_hex_equal(dirty_out, ref_out)
    # Positive: garbage skipped, exact payload, identical to clean frame.
    assert_hex_equal(dirty_out, payload.hex())
    assert_hex_equal(dirty_out, clean_out)
    # Negative: garbage prefix not reflected in output.
    assert dirty_out != (garbage + payload).hex(), (
        "leading garbage leaked into the recovered frame"
    )
