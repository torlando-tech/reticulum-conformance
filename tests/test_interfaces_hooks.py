"""Interface-layer conformance: transmit framing, receive de-framing read-loop
rules, AutoInterface peer-auth token, and per-type HW_MTU.

These tests drive bridge commands that run the REAL RNS interface read/write
loops (``TCPClientInterface.process_outgoing`` / ``read_loop``) and AutoInterface
peer-auth hashing, then anchor every assertion on an EXTERNAL ground truth — the
documented RNS framing constants and spec literals, plus an independent SHA-256
oracle (stdlib ``hashlib``) — never the implementation-under-test's own output.

Following the suite convention (see tests/test_framing.py) the harness does NOT
import RNS; the framing constants below are duplicated from
``RNS/Interfaces/TCPInterface.py`` (HDLC/KISS) and ``RNS/Reticulum.py``
(HEADER_MINSIZE) and were validated byte-for-byte against live RNS.
"""

import hashlib

import pytest

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Interface Hooks"
__category_order__ = 13


# ---------------------------------------------------------------------------
# External ground-truth constants (RNS 1.3.1 spec literals — NOT read from the
# impl). HDLC/KISS from RNS/Interfaces/TCPInterface.py; HEADER_MINSIZE from
# RNS/Reticulum.py; HW_MTU values from each interface class.
# ---------------------------------------------------------------------------
HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_ESC_MASK = 0x20

KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD
KISS_CMD_DATA = 0x00

HEADER_MINSIZE = 19          # frames of len <= 19 are silently dropped on RX

HW_MTU_TCP = 262144          # TCPInterface.HW_MTU (1.3.1)
HW_MTU_AUTO = 1196           # AutoInterface.HW_MTU
HW_MTU_BACKBONE = 1048576    # BackboneInterface.HW_MTU


def _hdlc_escape(data: bytes) -> bytes:
    """Independent oracle: RNS HDLC.escape — replace ESC first, then FLAG."""
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
    """Independent oracle: RNS KISS.escape — replace FESC first, then FEND."""
    data = data.replace(bytes([KISS_FESC]), bytes([KISS_FESC, KISS_TFESC]))
    data = data.replace(bytes([KISS_FEND]), bytes([KISS_FESC, KISS_TFEND]))
    return data


def _kiss_frame(data: bytes, command: int = KISS_CMD_DATA) -> bytes:
    return (
        bytes([KISS_FEND, command]) + _kiss_escape(data) + bytes([KISS_FEND])
    )


# ===========================================================================
# Transmit framing — hdlc_frame / kiss_frame (real process_outgoing)
# ===========================================================================
@conformance_case(
    commands=["hdlc_frame"],
    verifies="`hdlc_frame` (RNS TCPClientInterface.process_outgoing) frames a payload byte-for-byte as FLAG(0x7E) + HDLC.escape(payload) + FLAG, matching an independent HDLC framer for a random and a special-byte payload; reference and SUT agree byte-for-byte",
)
def test_hdlc_frame_matches_oracle(sut, reference):
    for payload_bytes in (
        bytes.fromhex(random_hex(64)),
        bytes([0x00, HDLC_FLAG, HDLC_ESC, 0xFF, HDLC_FLAG]) + bytes.fromhex(random_hex(16)),
    ):
        expected = _hdlc_frame(payload_bytes).hex()
        ref = reference.execute("hdlc_frame", data=payload_bytes.hex())["framed"]
        res = sut.execute("hdlc_frame", data=payload_bytes.hex())["framed"]
        assert_hex_equal(res, expected, "SUT HDLC frame != independent oracle")
        assert_hex_equal(ref, expected, "reference HDLC frame != independent oracle")


@conformance_case(
    commands=["hdlc_frame"],
    verifies="`hdlc_frame` escapes ESC (0x7D) BEFORE FLAG (0x7E): payload 0x7D 0x7E frames to exactly 7e 7d5d 7d5e 7e (ESC->ESC,0x5D then FLAG->ESC,0x5E). The FLAG-first ordering would double-escape the inserted ESC and yield a different frame, which the SUT must NOT produce",
)
def test_hdlc_frame_escape_order_discriminator(sut, reference):
    payload = bytes([HDLC_ESC, HDLC_FLAG])  # 0x7d 0x7e
    correct = "7e7d5d7d5e7e"
    # FLAG-first ordering (the wrong order) double-escapes the inserted ESC:
    flag_first = payload.replace(bytes([HDLC_FLAG]), bytes([HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK]))
    flag_first = flag_first.replace(bytes([HDLC_ESC]), bytes([HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK]))
    wrong = (bytes([HDLC_FLAG]) + flag_first + bytes([HDLC_FLAG])).hex()
    assert wrong != correct, "test setup: orderings must differ"
    for impl, label in ((reference, "ref"), (sut, "sut")):
        framed = impl.execute("hdlc_frame", data=payload.hex())["framed"]
        assert_hex_equal(framed, correct, f"{label}: HDLC frame escape order")
        assert framed != wrong, f"{label}: produced FLAG-first (wrong) escape order"


@conformance_case(
    commands=["kiss_frame"],
    verifies="`kiss_frame` (RNS TCPClientInterface.process_outgoing, kiss_framing) frames a payload byte-for-byte as FEND(0xC0) + CMD_DATA(0x00) + KISS.escape(payload) + FEND, matching an independent KISS framer for a random and a special-byte payload; reference and SUT agree",
)
def test_kiss_frame_matches_oracle(sut, reference):
    for payload_bytes in (
        bytes.fromhex(random_hex(48)),
        bytes([0x00, KISS_FEND, KISS_FESC, 0xFF, KISS_FEND]) + bytes.fromhex(random_hex(16)),
    ):
        expected = _kiss_frame(payload_bytes).hex()
        ref = reference.execute("kiss_frame", data=payload_bytes.hex())["framed"]
        res = sut.execute("kiss_frame", data=payload_bytes.hex())["framed"]
        assert_hex_equal(res, expected, "SUT KISS frame != independent oracle")
        assert_hex_equal(ref, expected, "reference KISS frame != independent oracle")


# ===========================================================================
# Receive de-framing — hdlc_deframe_stream (real read_loop)
# ===========================================================================
@conformance_case(
    commands=["hdlc_deframe_stream"],
    verifies="RNS's HDLC read loop applies the `len(frame) > HEADER_MINSIZE (19)` runt filter: a 19-byte frame and an empty (FLAG-FLAG) frame are silently dropped (zero frames delivered), while a 20-byte frame on the boundary is delivered. Anchored on the spec literal HEADER_MINSIZE=19",
)
def test_hdlc_deframe_stream_runt_drop(sut, reference):
    # Safe (non-special) payload bytes so the de-stuffed frame length equals the
    # payload length exactly, pinning the drop boundary at 19 vs 20.
    runt = _hdlc_frame(b"A" * HEADER_MINSIZE).hex()           # 19 bytes -> dropped
    boundary = _hdlc_frame(b"A" * (HEADER_MINSIZE + 1)).hex()  # 20 bytes -> kept
    empty = _hdlc_frame(b"").hex()                            # 0 bytes  -> dropped
    for impl, label in ((reference, "ref"), (sut, "sut")):
        assert impl.execute("hdlc_deframe_stream", stream=runt)["frames"] == [], (
            f"{label}: 19-byte frame was not dropped"
        )
        assert impl.execute("hdlc_deframe_stream", stream=empty)["frames"] == [], (
            f"{label}: empty frame was not dropped"
        )
        kept = impl.execute("hdlc_deframe_stream", stream=boundary)["frames"]
        assert kept == ["41" * 20], f"{label}: 20-byte boundary frame not delivered"


@conformance_case(
    commands=["hdlc_deframe_stream"],
    verifies="RNS's HDLC read loop extracts multiple frames from a single stream using shared-FLAG buffer retention: two distinct 20-byte frames concatenated are both delivered, in order, while an interleaved runt between them is dropped",
)
def test_hdlc_deframe_stream_multi_frame(sut, reference):
    a = b"A" * 20
    b = b"B" * 20
    runt = b"C" * 5
    stream = (_hdlc_frame(a) + _hdlc_frame(runt) + _hdlc_frame(b)).hex()
    for impl, label in ((reference, "ref"), (sut, "sut")):
        frames = impl.execute("hdlc_deframe_stream", stream=stream)["frames"]
        assert frames == [a.hex(), b.hex()], (
            f"{label}: multi-frame extraction / runt drop wrong: {frames}"
        )


# ===========================================================================
# Receive de-framing — kiss_deframe_stream (real read_loop, kiss_framing)
# ===========================================================================
@conformance_case(
    commands=["kiss_deframe_stream"],
    verifies="RNS's KISS read loop strips the leading port nibble (command = byte & 0x0F): a frame whose command byte is 0x10 (low nibble 0) is accepted as CMD_DATA and its payload delivered byte-for-byte, matching an independent KISS de-framer",
)
def test_kiss_deframe_stream_port_nibble_accepted(sut, reference):
    payload = bytes([0x00, KISS_FESC, 0xAB, KISS_FEND, 0x11]) + bytes.fromhex(random_hex(16))
    # Port nibble 0x10: high nibble = port 1, low nibble = CMD_DATA(0).
    stream = _kiss_frame(payload, command=0x10).hex()
    for impl, label in ((reference, "ref"), (sut, "sut")):
        frames = impl.execute("kiss_deframe_stream", stream=stream)["frames"]
        assert frames == [payload.hex()], (
            f"{label}: port-nibble 0x10 frame not accepted/delivered: {frames}"
        )


@conformance_case(
    commands=["kiss_deframe_stream"],
    verifies="RNS's KISS read loop silently ignores frames whose command (after nibble strip) != CMD_DATA: a frame with command byte 0x11 (low nibble 1) yields zero delivered frames, while the identical payload under command 0x00 is delivered (positive control)",
)
def test_kiss_deframe_stream_non_cmd_data_ignored(sut, reference):
    payload = bytes.fromhex(random_hex(20))
    ignored = _kiss_frame(payload, command=0x11).hex()   # nibble 1 -> not CMD_DATA
    accepted = _kiss_frame(payload, command=0x00).hex()
    for impl, label in ((reference, "ref"), (sut, "sut")):
        assert impl.execute("kiss_deframe_stream", stream=ignored)["frames"] == [], (
            f"{label}: non-CMD_DATA frame was not ignored"
        )
        assert impl.execute("kiss_deframe_stream", stream=accepted)["frames"] == [payload.hex()], (
            f"{label}: positive-control CMD_DATA frame not delivered"
        )


# ===========================================================================
# AutoInterface peer-authentication token
# ===========================================================================
@conformance_case(
    commands=["auto_discovery_token"],
    verifies="AutoInterface peer-auth token == SHA-256(group_id || link_local_addr.utf8), matching an independent stdlib SHA-256 oracle and exactly 32 bytes; a different source address yields a different token (negative), so a spoofed address fails authentication",
)
def test_auto_discovery_token_matches_sha256(sut, reference):
    group_id = bytes.fromhex(random_hex(9))   # e.g. b"reticulum"-length payload
    addr = "fe80::1ff:fe23:4567:890a"
    other_addr = "fe80::1ff:fe23:4567:890b"
    # hashlib.new("sha256", ...) (not hashlib.sha256) so the independent oracle's
    # method name does not collide with the bridge `sha256` command in the drift
    # guard's static command-usage scan — this test drives no bridge sha256.
    expected = hashlib.new("sha256", group_id + addr.encode("utf-8")).hexdigest()
    expected_other = hashlib.new("sha256", group_id + other_addr.encode("utf-8")).hexdigest()
    assert expected != expected_other, "test setup: addresses must differ"
    for impl, label in ((reference, "ref"), (sut, "sut")):
        tok = impl.execute("auto_discovery_token", group_id=group_id.hex(), link_local_addr=addr)["token"]
        assert_hex_equal(tok, expected, f"{label}: token != SHA-256(group_id||addr)")
        assert len(bytes.fromhex(tok)) == 32, f"{label}: token not 32 bytes"
        tok_other = impl.execute("auto_discovery_token", group_id=group_id.hex(), link_local_addr=other_addr)["token"]
        assert tok_other != tok, f"{label}: distinct addresses produced same token"


# ===========================================================================
# Per-type HW_MTU
# ===========================================================================
@conformance_case(
    commands=["interface_hw_mtu"],
    verifies="Class-level HW_MTU per interface matches the RNS 1.3.1 spec literals: TCPInterface=262144, AutoInterface=1196, BackboneInterface=1048576 (all distinct); an unsupported interface type returns an error rather than a silent value",
)
def test_interface_hw_mtu_per_type(sut, reference, sut_impl_name):
    expected = {
        "TCPInterface": HW_MTU_TCP,
        "AutoInterface": HW_MTU_AUTO,
        "BackboneInterface": HW_MTU_BACKBONE,
    }
    assert len(set(expected.values())) == 3, "test setup: MTUs must be distinct"
    for impl, label in ((reference, "ref"), (sut, "sut")):
        if label == "sut" and sut_impl_name == "kotlin":
            pytest.xfail(
                "reticulum-kt#kotlin-no-backbone-interface: no BackboneInterface "
                "class exists in reticulum-kt (the bridge interface_hw_mtu command "
                "cannot report it)."
            )
        for itype, mtu in expected.items():
            res = impl.execute("interface_hw_mtu", type=itype)
            assert res.get("hw_mtu") == mtu, f"{label}: {itype} HW_MTU != {mtu}"
        bad = impl.execute("interface_hw_mtu", type="UDPInterface")
        assert "error" in bad and "hw_mtu" not in bad, (
            f"{label}: per-instance HW_MTU type should error, got {bad}"
        )
