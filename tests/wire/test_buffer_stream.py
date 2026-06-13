"""RNS.Buffer (RawChannelWriter / RawChannelReader) streaming conformance.

`RNS.Buffer` layers a byte-stream abstraction on top of a Link's `RNS.Channel`.
A `RawChannelWriter` slices an arbitrary payload into `StreamDataMessage`s
(Channel system message type `SMT_STREAM_DATA` = 0xff00), each carrying at most
`RawChannelWriter.MAX_CHUNK_LEN` (16 KiB) bytes — optionally bz2-compressed —
and the peer's `RawChannelReader` reassembles them, in Channel sequence order,
back into the original byte stream, signalling end-of-stream via the EOF flag on
the final (empty) message.

The audit (CONFORMANCE_GAPS.md §4b "Buffer / RawChannelReader /
RawChannelWriter streaming") flagged this whole layer as confirmed-untested: no
Buffer object was ever constructed by the prior suite. Two distinct behaviours
matter and are pinned here:

  1. Multi-chunk reassembly + EOF — a payload larger than one MAX_CHUNK_LEN
     chunk (so the writer emits several `StreamDataMessage`s) plus a partial
     final chunk must arrive byte-exact, with the reader observing EOF and NOT
     aborting. This is the positive control.

  2. Decompression-bomb bound (Buffer.py:95-97) — `StreamDataMessage.unpack`
     decompresses a compressed chunk with `max_length=MAX_CHUNK_LEN` and raises
     `IOError("Decompressed buffer chunk exceeds maximum legitimate size")` if
     the bz2 stream would expand past that bound. A conformant reader must
     abort the stream rather than silently truncate or hand the caller a short
     read. This is the negative case.

How these tests drive the stream: the wire harness `buffer_stream` command runs
a real `RawChannelWriter` on the link initiator's `Channel` (the established
Link from `wire_link_setup`), and `buffer_received` drains what the listener's
`RawChannelReader` (created at link establishment by the listen handler)
reassembled. Both peers are reference implementations under `--reference-only`,
so every assertion holds reference-vs-reference; the SUT is never required.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("buffer",)
_LINK_TIMEOUT_MS = 15000
_PATH_TIMEOUT_MS = 10000

# RawChannelWriter.MAX_CHUNK_LEN (RNS.Buffer.py:216): the per-chunk ceiling and,
# crucially, the bz2 decompression bound (Buffer.py:95-97). Hardcoded (rather
# than imported) to keep the test process free of an RNS dependency, mirroring
# how test_channel pins the Channel sequence constants.
_MAX_CHUNK_LEN = 1024 * 16  # 16 KiB

# A payload that spans 3 full MAX_CHUNK_LEN chunks plus a deliberately partial
# final chunk, so the writer must emit several StreamDataMessages and the reader
# must stitch a non-chunk-aligned tail. High-entropy (seeded, reproducible) so
# the bytes are effectively uncompressible — exercising the raw (uncompressed)
# StreamDataMessage path end-to-end while still proving byte-exact reassembly.
_PARTIAL_TAIL = 5000
_PAYLOAD_LEN = 3 * _MAX_CHUNK_LEN + _PARTIAL_TAIL  # 54152 bytes


def _make_payload(n: int) -> bytes:
    import random

    return random.Random(0xB0FFE2).randbytes(n)


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "buffer_stream", "buffer_received",
    ],
    verifies=(
        "RNS.Buffer RawChannelWriter->RawChannelReader streaming over an "
        "established Link reassembles a multi-chunk payload byte-exact: a "
        "54152-byte payload spanning 3 full MAX_CHUNK_LEN (16 KiB) "
        "StreamDataMessage chunks plus a partial 5000-byte final chunk is "
        "received identical to what was written, the writer reports all bytes "
        "written with EOF flushed, and the receiver observes EOF with no "
        "decompression-bound abort"
    ),
)
def test_buffer_stream_multichunk_roundtrip(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP,
        aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS,
        path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    payload = _make_payload(_PAYLOAD_LEN)
    # Self-check the fixture data really is multi-chunk with a partial tail, so
    # the test cannot silently degenerate into a single-chunk transfer.
    assert len(payload) > 2 * _MAX_CHUNK_LEN, "payload must span several chunks"
    assert len(payload) % _MAX_CHUNK_LEN != 0, "payload must have a partial final chunk"

    # client is the link initiator (holds the outbound Link / its Channel), so
    # it writes; server is the listener whose RawChannelReader reassembles.
    stream = client.buffer_stream(link_id, payload, timeout_ms=20000)
    assert stream.get("written") == len(payload), (
        f"writer reported {stream.get('written')} bytes written, "
        f"expected the full {len(payload)}"
    )
    assert stream.get("eof") is True, (
        f"writer did not flush EOF: {stream!r}"
    )

    received = server.buffer_received(dest_hash, timeout_ms=20000)
    assert received["aborted"] is False, (
        f"a legitimate multi-chunk stream must not trip the decompression "
        f"bound, but the reader aborted: error={received['error']!r}"
    )
    assert received["eof"] is True, (
        "receiver never observed EOF — the stream did not conclude"
    )
    assert received["data"] == payload, (
        f"reassembled stream is not byte-exact: got {len(received['data'])} "
        f"bytes (expected {len(payload)}); "
        f"first divergence-safe check len-only mismatch={len(received['data']) != len(payload)}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "buffer_stream", "buffer_received",
    ],
    verifies=(
        "RNS.Buffer RawChannelReader aborts at the MAX_CHUNK_LEN (16 KiB) bz2 "
        "decompression bound (Buffer.py:95-97): a crafted compressed "
        "StreamDataMessage whose body decompresses past 16 KiB causes the "
        "receiver's reader to abort (aborted=True with a non-empty IOError "
        "reason) and deliver zero stream bytes, rather than silently "
        "truncating or short-reading"
    ),
)
def test_buffer_stream_decompression_bomb_aborts(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP,
        aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS,
        path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # bomb=True sends a single crafted StreamDataMessage whose advertised
    # compressed body inflates well past MAX_CHUNK_LEN. Confirm the harness
    # actually put the bomb on the wire before asserting the receiver's reaction
    # (a not-ready channel would have written nothing, which is not what we
    # mean to test).
    stream = client.buffer_stream(link_id, b"", bomb=True, timeout_ms=20000)
    assert stream.get("bomb") is True, (
        f"bomb chunk was not sent (channel never became ready?): {stream!r}"
    )
    assert stream.get("written") == 0, (
        f"bomb path must write no stream payload, got {stream.get('written')}"
    )

    received = server.buffer_received(dest_hash, timeout_ms=20000)
    assert received["aborted"] is True, (
        "reader did NOT abort on an over-bound decompressed chunk — it must "
        "raise/abort at the MAX_CHUNK_LEN bound, not silently accept it "
        f"({received!r})"
    )
    assert received["error"], (
        f"abort must carry a non-empty reason string, got {received['error']!r}"
    )
    # Silent truncation (delivering a partial decompressed chunk) is exactly the
    # failure mode the bound guards against, so no stream bytes may surface.
    assert received["data"] == b"", (
        f"aborted reader delivered {len(received['data'])} bytes; an over-bound "
        f"chunk must yield no stream data"
    )
