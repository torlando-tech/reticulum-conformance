"""RNS Channel.Envelope / Buffer.StreamDataMessage wire-format conformance.

These pin the two pure binary container formats the channel_buffer subsystem is
built on, independently of any link:

  * ``Channel.Envelope`` (Channel.py:192-198) frames every channel message with a
    fixed 6-byte big-endian header ``>HHH`` = (MSGTYPE, sequence, length),
    followed by the message payload. The `channel_envelope_pack` command packs a
    real ``RNS.Channel.Envelope`` and returns its bytes; each test re-derives the
    expected header with an INDEPENDENT ``struct.pack`` (the external wire-format
    ground truth, not read from the impl) and asserts byte equality.

  * ``Buffer.StreamDataMessage`` (Buffer.py:44-97) frames each stream chunk with a
    2-byte big-endian header packing an EOF flag (bit 0x8000), a compressed flag
    (bit 0x4000), and a 14-bit stream id (0x3fff), followed by the chunk bytes,
    and uses the system-reserved message type ``SMT_STREAM_DATA`` (0xff00). The
    `buffer_pack` command packs/unpacks a real ``StreamDataMessage``; tests pin
    the msgtype, the header bit layout, the 0..16383 stream-id range guard, and
    the ``& 0x3fff`` stream-id mask on decode.

Both commands are pure delegations to real RNS (no link / handle), so every
assertion holds identically under ``--reference-only``.
"""

import struct

from conformance import conformance_case


__category_title__ = "Channel & Buffer Format"
__category_order__ = 19


# External spec literals (NOT read from the impl).
_SMT_STREAM_DATA = 0xFF00      # SystemMessageTypes.SMT_STREAM_DATA (Channel.py:46)
_STREAM_ID_MAX = 0x3FFF        # StreamDataMessage.STREAM_ID_MAX (Buffer.py:51)
_EOF_BIT = 0x8000
_COMPRESSED_BIT = 0x4000


@conformance_case(
    commands=["channel_envelope_pack"],
    verifies=(
        "RNS.Channel.Envelope.pack frames a message with the fixed 6-byte "
        "big-endian header >HHH = (MSGTYPE, sequence, length) followed by the "
        "payload (Channel.py:192-198): for several (msgtype, sequence, payload) "
        "triples the packed bytes equal an independent struct.pack('>HHH', "
        "msgtype, sequence, len(data)) + data exactly, the header is exactly 6 "
        "bytes (raw[6:] == payload), and the length field reflects len(payload) "
        "(0 for an empty payload) — an impl using a different header width, byte "
        "order, or field order diverges here"
    ),
)
def test_channel_envelope_header_format(sut):
    cases = [
        (0x0101, 0, b""),
        (0x0101, 7, b"hello"),
        (0xABCD, 0xFFFF, b"\x00\x01\x02\x03"),
        (0x0001, 258, bytes(range(40))),
    ]
    for msgtype, sequence, payload in cases:
        r = sut.execute(
            "wire_channel_envelope_pack",
            msgtype=msgtype,
            sequence=sequence,
            data=payload.hex(),
        )
        raw = bytes.fromhex(r["raw"])
        expected = struct.pack(">HHH", msgtype, sequence, len(payload)) + payload
        assert raw == expected, (
            f"envelope header mismatch for ({hex(msgtype)},{sequence},"
            f"{payload.hex()}): got {raw.hex()}, expected {expected.hex()}"
        )
        # The header is exactly 6 bytes; payload follows verbatim.
        assert raw[6:] == payload, f"payload not appended verbatim: {raw.hex()}"
        # The length field (bytes 4..6) equals the payload length.
        assert struct.unpack(">H", raw[4:6])[0] == len(payload), (
            f"length field != len(payload) for {raw.hex()}"
        )
        # MSGTYPE/sequence fields decode back to the inputs.
        got_type, got_seq, got_len = struct.unpack(">HHH", raw[:6])
        assert (got_type, got_seq, got_len) == (msgtype, sequence, len(payload))

    # Negative discrimination: two payloads of different length must differ
    # ONLY by their length field + trailing bytes, never by reusing a header.
    a = bytes.fromhex(
        sut.execute("wire_channel_envelope_pack", msgtype=0x0101, sequence=3,
                    data=b"AB".hex())["raw"]
    )
    b = bytes.fromhex(
        sut.execute("wire_channel_envelope_pack", msgtype=0x0101, sequence=3,
                    data=b"ABCD".hex())["raw"]
    )
    assert a[:4] == b[:4], "MSGTYPE+sequence should be identical for same inputs"
    assert struct.unpack(">H", a[4:6])[0] == 2
    assert struct.unpack(">H", b[4:6])[0] == 4, "length field did not track payload"


@conformance_case(
    commands=["buffer_pack"],
    verifies=(
        "RNS.Buffer.StreamDataMessage uses the system-reserved message type "
        "SMT_STREAM_DATA == 0xff00 (Channel.py:46, Buffer.py:45): buffer_pack "
        "reports msgtype 0xff00 for any chunk, and the value sits in the "
        "reserved band (>= 0xf000), distinguishing it from an ordinary "
        "user-registrable channel msgtype"
    ),
)
def test_stream_data_msgtype(sut):
    r = sut.execute("wire_buffer_pack", stream_id=0, data=b"x".hex(),
                    eof=False, compressed=False)
    assert r["msgtype"] == _SMT_STREAM_DATA, (
        f"StreamDataMessage.MSGTYPE={hex(r['msgtype'])}, expected "
        f"{hex(_SMT_STREAM_DATA)} (SMT_STREAM_DATA)"
    )
    # It is a system-reserved type (>= 0xf000), not a user msgtype (negative).
    assert r["msgtype"] >= 0xF000, "SMT_STREAM_DATA must be in the reserved band"


@conformance_case(
    commands=["buffer_pack"],
    verifies=(
        "RNS.Buffer.StreamDataMessage.pack frames a chunk as a 2-byte "
        "big-endian header (EOF bit 0x8000 | compressed bit 0x4000 | 14-bit "
        "stream id 0x3fff) followed by the chunk bytes (Buffer.py:80-85): for "
        "every (stream_id, eof, compressed) combination the first two bytes "
        "equal an independent struct.pack('>H', (0x3fff & stream_id) | (0x8000 "
        "if eof) | (0x4000 if compressed)) and raw[2:] == data; setting EOF or "
        "compressed flips exactly its own bit and nothing else (negative "
        "control)"
    ),
)
def test_stream_data_header_format(sut):
    payload = b"\xde\xad\xbe\xef"
    for stream_id in (0, 1, 0x1234, _STREAM_ID_MAX):
        for eof in (False, True):
            for compressed in (False, True):
                r = sut.execute(
                    "wire_buffer_pack", stream_id=stream_id, data=payload.hex(),
                    eof=eof, compressed=compressed,
                )
                raw = bytes.fromhex(r["raw"])
                header_val = (
                    (0x3FFF & stream_id)
                    | (_EOF_BIT if eof else 0)
                    | (_COMPRESSED_BIT if compressed else 0)
                )
                assert raw[:2] == struct.pack(">H", header_val), (
                    f"header mismatch (sid={stream_id}, eof={eof}, "
                    f"comp={compressed}): got {raw[:2].hex()}, expected "
                    f"{struct.pack('>H', header_val).hex()}"
                )
                assert raw[2:] == payload, f"chunk bytes not appended: {raw.hex()}"

    # Negative control: EOF flips ONLY bit 0x8000 relative to the plain frame.
    plain = bytes.fromhex(
        sut.execute("wire_buffer_pack", stream_id=7, data=payload.hex(),
                    eof=False, compressed=False)["raw"]
    )
    eofd = bytes.fromhex(
        sut.execute("wire_buffer_pack", stream_id=7, data=payload.hex(),
                    eof=True, compressed=False)["raw"]
    )
    diff = struct.unpack(">H", plain[:2])[0] ^ struct.unpack(">H", eofd[:2])[0]
    assert diff == _EOF_BIT, f"EOF must flip only bit 0x8000, flipped {hex(diff)}"
    assert plain[2:] == eofd[2:] == payload, "payload must be unaffected by EOF"


@conformance_case(
    commands=["buffer_pack"],
    verifies=(
        "RNS.Buffer.StreamDataMessage enforces the 14-bit stream-id range on "
        "both encode and decode: constructing with stream_id > 0x3fff raises "
        "ValueError('stream_id must be 0-16383', Buffer.py:73-74) — surfaced as "
        "{error} — while 0x3fff packs cleanly (boundary positive); and "
        "unpacking a header whose EOF/compressed bits are set masks the decoded "
        "stream_id back to 0..0x3fff via & 0x3fff (Buffer.py:91), so a frame "
        "carrying stream_id 5 with the EOF bit set decodes to stream_id 5 (not "
        "0x8005), eof True"
    ),
)
def test_stream_id_range_and_mask(sut):
    # Encode guard: above STREAM_ID_MAX is rejected; the boundary value is fine.
    over = sut.execute("wire_buffer_pack", stream_id=_STREAM_ID_MAX + 1,
                       data="", eof=False, compressed=False)
    assert "error" in over and "16383" in over["error"], (
        f"stream_id 0x4000 should raise the range ValueError, got {over!r}"
    )
    boundary = sut.execute("wire_buffer_pack", stream_id=_STREAM_ID_MAX,
                           data=b"ok".hex(), eof=False, compressed=False)
    assert "raw" in boundary, f"stream_id 0x3fff must pack cleanly: {boundary!r}"
    assert struct.unpack(">H", bytes.fromhex(boundary["raw"])[:2])[0] == _STREAM_ID_MAX

    # Decode mask: a header value with the EOF (high) bit set above the 14-bit
    # id field must mask the stream id back into range, extracting eof
    # separately. raw built independently (test-side struct.pack).
    raw = struct.pack(">H", _EOF_BIT | 5) + b"payload"
    u = sut.execute("wire_buffer_pack", unpack_raw=raw.hex())
    assert u["stream_id"] == 5, (
        f"decoded stream_id={u['stream_id']}, expected 5 after & 0x3fff mask "
        f"(impl that forgot the mask would report {hex(_EOF_BIT | 5)})"
    )
    assert u["eof"] is True, "EOF bit not decoded from the masked-off high bit"
    assert u["compressed"] is False
    assert bytes.fromhex(u["data"]) == b"payload"
