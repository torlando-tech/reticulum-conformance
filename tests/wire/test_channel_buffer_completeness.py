"""RNS Channel / Buffer completeness gaps (TX sequence, RX wrap window, dedup
under real retransmission, single-channel-per-link, compressed streaming).

This module closes the residual `channel_buffer` gaps that the existing
`test_channel.py` / `test_channel_flow.py` / `test_buffer_stream.py` suites left
*partial* or *uncovered*, using only the existing wire harness commands
(`channel_inject` / `channel_received` / `channel_window` / `channel_send` /
`buffer_stream` / `buffer_received`). Every assertion is anchored on a value
derived INDEPENDENTLY of the reference's own round-trip:

  * TX sequence assignment (`sequence-assignment`): the per-direction sequence
    starts at 0 and increments by 1 (Channel.send reserves `self._next_sequence`
    then advances it, Channel.py:611-617). We send four delivered messages and
    assert the returned/observed sequences are exactly 0,1,2,3 — the literal
    arithmetic the rule demands, not whatever the reference echoes back.

  * RX wrap-window boundary (`rx-stale-sequence-rejection`) and multi-buffered
    wrap insertion (`rx-ring-wraparound-insertion`): with the receive counter
    driven to 0xFFFF, the stale-drop guard computes
    `window_overflow = (next_rx + WINDOW_MAX) % 0x10000` with the CLASS constant
    `WINDOW_MAX = 48` (Channel.py:261,432) — so at next_rx=0xFFFF the accept
    edge is sequence 47 (47 not > 47 -> accepted) and 48 is dropped (48 > 47).
    The exact 47-vs-48 split pins WINDOW_MAX=48 (any other constant moves the
    edge). The subsequent `0xFFFF` completes a contiguous run that crosses the
    modulus and releases the buffered `0` in front of the still-buffered `47`,
    pinning the half-space modular ordering across the wrap. The expected
    delivery order is hand-derived from the published `_receive`/
    `_emplace_envelope` algorithm (Channel.py:392-466), not read back from RNS.

  * Exactly-once delivery under REAL link retransmission
    (`retransmission-same-envelope-new-ciphertext`): a `drop_acks` send is
    physically retransmitted 5x (same sequence, same plaintext) before the link
    tears down; the RECEIVER must channel-dedup all 5 copies down to a single
    handler delivery. We read the *server-side* `channel_received` (never read by
    the drop_acks tests in test_channel_flow.py) and assert exactly one copy.

  * Single Channel per Link (`single-channel-per-link`): `link.get_channel()` is
    a singleton sharing ONE per-direction sequence space. A `channel_send`
    (sequence 0) followed by a `buffer_stream` (several StreamDataMessages on the
    SAME channel) followed by another `channel_send` must yield a sequence
    strictly greater than 1 and equal to the channel's `next_sequence` — proving
    the two APIs draw from one shared counter. A separate-channel impl would
    hand the second `channel_send` sequence 1.

  * Compressed stream round-trip (`stream-compression-bz2`): a highly
    compressible payload exercises the writer's bz2 compression decision
    (Buffer.py:243-252) AND the reader's *successful* bz2 decompression path
    (Buffer.py:94-97) — the positive counterpart to the bomb-abort negative in
    test_buffer_stream.py, which only exercises the reader's decompression on a
    failing (over-bound) chunk. Anchored on byte-exact reassembly of a known
    input.

Both Link peers are reference implementations under `--reference-only`; every
assertion holds reference-vs-reference.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("channel",)
_LINK_TIMEOUT_MS = 15000
_PATH_TIMEOUT_MS = 10000
_SEND_TIMEOUT_MS = 12000
_DROP_TIMEOUT_MS = 20000

# RNS Channel sequence space (Channel.py:278-279).
_SEQ_MAX = 0xFFFF        # Channel.SEQ_MAX
_SEQ_MODULUS = 0x10000   # Channel.SEQ_MODULUS

# The CLASS-level receive window the stale-drop guard uses (Channel.WINDOW_MAX =
# WINDOW_MAX_FAST = 48, Channel.py:257,261,432). NOT the per-channel instance
# `window_max` (which is 5 on a fresh slow-profile loopback link) — the guard at
# Channel.py:432 reads the class constant.
_RX_WINDOW_MAX = 48

# RNS.Link.CLOSED (Link.py) — the status a link reports once torn down.
_LINK_CLOSED = 0x04
_MAX_TRIES = 5  # Channel._max_tries


def _drive_rx_to(client, link_id, target):
    """Deliver every sequence 0..target-1 in order so the channel's receive
    counter (`next_rx_sequence`) advances to `target`, draining as we go so the
    rx ring stays bounded. Returns the number of delivered messages.
    """
    batch_size = 8192
    delivered = 0
    seq = 0
    while seq < target:
        end = min(seq + batch_size, target)
        client.channel_inject(
            link_id, [{"sequence": s, "data": b""} for s in range(seq, end)]
        )
        delivered += len(client.channel_received(link_id))
        seq = end
    return delivered


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "channel_window",
    ],
    verifies=(
        "RNS Channel assigns per-direction transmit sequence numbers starting at "
        "0 and incrementing by exactly 1 per sent message (Channel.send reserves "
        "self._next_sequence then sets it to (reserved+1) % 0x10000, "
        "Channel.py:611-617): on a fresh channel (next_sequence==0) four "
        "successive delivered channel_send calls return sequence 0,1,2,3 in "
        "order, and the channel's next_sequence advances 1,2,3,4 in lockstep — "
        "the literal arithmetic the rule mandates, independent of any value the "
        "reference echoes"
    ),
)
def test_channel_send_assigns_sequential_sequences(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    pre = client.channel_window(link_id)
    assert pre["next_sequence"] == 0, (
        f"precondition: a fresh channel must start its tx sequence at 0, got "
        f"{pre['next_sequence']}"
    )

    for expected_seq in range(4):
        r = client.channel_send(
            link_id, f"seq-{expected_seq}".encode(), timeout_ms=_SEND_TIMEOUT_MS
        )
        assert r.get("sent") is True and r.get("delivered") is True, (
            f"send {expected_seq} did not deliver: {r!r}"
        )
        assert r.get("sequence") == expected_seq, (
            f"channel_send returned sequence {r.get('sequence')}, expected "
            f"{expected_seq} (sequences start at 0 and increment by 1)"
        )
        w = client.channel_window(link_id)
        assert w["next_sequence"] == expected_seq + 1, (
            f"after assigning sequence {expected_seq}, next_sequence="
            f"{w['next_sequence']}, expected {expected_seq + 1} "
            f"((reserved+1) % 0x10000)"
        )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies=(
        "RNS Channel pins the receive stale-drop window to the CLASS constant "
        "WINDOW_MAX=48 and the half-space modular insertion order across the "
        "0xFFFF->0 wrap (Channel._receive/_emplace_envelope, Channel.py:431-466 / "
        "392-413). With next_rx_sequence driven to 0xFFFF, window_overflow = "
        "(0xFFFF + 48) % 0x10000 = 47, so an injected sequence 48 is dropped "
        "(48 > 47, stale) leaving the rx ring empty, sequence 1000 is likewise "
        "dropped, but sequence 47 is accepted/buffered (47 not > 47 — the exact "
        "WINDOW_MAX=48 accept edge) and sequence 0 is accepted/buffered (deep in "
        "the post-wrap window) — none delivered while 0xFFFF is still missing. "
        "Injecting 0xFFFF then completes the contiguous run, delivering exactly "
        "[0xFFFF, 0] in that modular order (the half-space rule orders the "
        "buffered 0 AFTER 0xFFFF, and the inner wrap loop releases it) while the "
        "still-buffered 47 remains — discriminating WINDOW_MAX=48 from any other "
        "window and pinning multi-element straddle ordering"
    ),
)
def test_channel_wrap_window_boundary_and_straddle_insertion(wire_peers):
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )
    dest_hash = server.listen(app_name=_APP, aspects=list(_ASPECTS))
    assert client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        "client never learned a path to the server destination"
    )
    link_id = client.link_open(
        dest_hash, app_name=_APP, aspects=list(_ASPECTS),
        timeout_ms=_LINK_TIMEOUT_MS,
    )

    # Drive the receive counter to 0xFFFF (delivering 0..0xFFFE in order).
    delivered = _drive_rx_to(client, link_id, _SEQ_MAX)
    assert delivered == _SEQ_MAX, (
        f"setup delivered {delivered} pre-wrap messages, expected {_SEQ_MAX}"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == _SEQ_MAX and w["rx_ring"] == 0, (
        f"setup left next_rx_sequence={w['next_rx_sequence']}, "
        f"rx_ring={w['rx_ring']}; expected 0xFFFF / 0"
    )

    # window_overflow = (0xFFFF + 48) % 0x10000 = 47. Sequence 48 is one past the
    # accept edge -> dropped as stale; the ring stays empty.
    assert (_SEQ_MAX + _RX_WINDOW_MAX) % _SEQ_MODULUS == 47, "constant self-check"
    client.channel_inject(link_id, [{"sequence": 48, "data": b"drop-48"}])
    assert client.channel_received(link_id) == [], "seq 48 must not be delivered"
    w = client.channel_window(link_id)
    assert w["rx_ring"] == 0, (
        f"seq 48 (> window_overflow 47) must be dropped, not buffered: "
        f"rx_ring={w['rx_ring']}"
    )

    # A far-stale sequence well past the edge is also dropped.
    client.channel_inject(link_id, [{"sequence": 1000, "data": b"drop-1000"}])
    assert client.channel_received(link_id) == [], "seq 1000 must not be delivered"
    assert client.channel_window(link_id)["rx_ring"] == 0, (
        "seq 1000 must be dropped, not buffered"
    )

    # Sequence 47 is exactly AT the accept edge (47 not > 47) -> accepted and
    # buffered (not contiguous with the missing 0xFFFF), so the ring grows to 1.
    client.channel_inject(link_id, [{"sequence": 47, "data": b"buf-47"}])
    assert client.channel_received(link_id) == [], (
        "seq 47 is in-window but non-contiguous; it must buffer, not deliver"
    )
    w = client.channel_window(link_id)
    assert w["rx_ring"] == 1, (
        f"seq 47 (the WINDOW_MAX=48 accept edge) must be accepted/buffered: "
        f"rx_ring={w['rx_ring']} (if 47 were dropped the window would be < 48)"
    )

    # Sequence 0 is deep in the post-wrap window -> accepted and buffered; ring 2.
    payload_zero = b"the-wrapped-zero"
    client.channel_inject(link_id, [{"sequence": 0, "data": payload_zero}])
    assert client.channel_received(link_id) == [], "seq 0 must buffer, not deliver"
    assert client.channel_window(link_id)["rx_ring"] == 2, (
        "seq 0 must be buffered alongside seq 47 (two straddling envelopes)"
    )

    # Now 0xFFFF arrives: it is the next expected sequence, so the contiguous run
    # delivers 0xFFFF and crosses the modulus to release the buffered 0 — in that
    # exact modular order [0xFFFF, 0]. The buffered 47 is NOT released (the inner
    # wrap loop only advances through sequence 0), so it stays in the ring.
    payload_last = b"the-last-sequence"
    client.channel_inject(link_id, [{"sequence": _SEQ_MAX, "data": payload_last}])
    boundary = client.channel_received(link_id)
    assert boundary == [payload_last, payload_zero], (
        f"wrap delivery order wrong: got {[b.hex() for b in boundary]!r}, "
        f"expected {[payload_last.hex(), payload_zero.hex()]!r} "
        f"(half-space rule orders buffered 0 after 0xFFFF)"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == 1, (
        f"counter did not advance to 1 after the wrap: {w['next_rx_sequence']}"
    )
    assert w["rx_ring"] == 1, (
        f"the buffered seq 47 must remain (inner wrap loop only releases 0): "
        f"rx_ring={w['rx_ring']}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "channel_received", "link_status",
    ],
    verifies=(
        "RNS Channel delivers a physically-retransmitted message to the receiver "
        "EXACTLY ONCE: a drop_acks channel_send is retransmitted _max_tries=5 "
        "times (same sequence, same plaintext) before the link tears down, yet "
        "the receiver's Channel dedups all five duplicate-sequence copies down to "
        "a single handler delivery. The server-side channel_received reports the "
        "payload exactly once (never 0, never 5), pinning channel-layer "
        "exactly-once delivery under REAL link retransmission (Channel._receive "
        "duplicate drop), distinct from the synthetic-injection dedup test"
    ),
)
def test_channel_retransmission_delivers_exactly_once(wire_link_setup):
    import time

    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    payload = b"RETRANSMIT-EXACTLY-ONCE"
    r = client.channel_send(
        link_id, payload, drop_acks=True, timeout_ms=_DROP_TIMEOUT_MS
    )
    # The send physically transmits and retransmits to exhaustion, then the link
    # tears down — that is what puts 5 duplicate copies on the wire.
    assert r["sent"] is True, f"the un-acked send must still transmit: {r!r}"
    assert r["delivered"] is False, (
        f"a send whose ack is dropped must never DELIVER: {r!r}"
    )
    assert r["tries"] == _MAX_TRIES, (
        f"expected exactly {_MAX_TRIES} transmissions, got {r['tries']}"
    )
    assert r["link_status"] == _LINK_CLOSED, (
        f"link not torn down after {_MAX_TRIES} tries: status={r['link_status']}"
    )

    # The receiver proved every copy but its Channel must dedup by sequence, so
    # the handler saw the payload exactly once despite 5 transmissions. Poll
    # briefly for the (single) delivery to settle.
    deadline = time.time() + 5.0
    received = []
    while time.time() < deadline:
        received = server.channel_received(link_id)
        if received:
            break
        time.sleep(0.05)
    assert received == [payload], (
        f"receiver delivered {len(received)} copies "
        f"({[m.hex() for m in received]!r}); a 5x-retransmitted message must be "
        f"channel-deduped to exactly one delivery of {payload.hex()}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "channel_window", "buffer_stream",
    ],
    verifies=(
        "RNS exposes ONE Channel per Link (link.get_channel() singleton) sharing "
        "a single per-direction transmit sequence space across message types: a "
        "channel_send (sequence 0) followed by a buffer_stream (several "
        "StreamDataMessages drawn from the SAME channel's sequence counter) "
        "followed by a second channel_send yields a sequence strictly greater "
        "than 1 and equal to the channel's current next_sequence — proving "
        "channel messages and Buffer stream messages share one counter. A "
        "two-channels-per-link impl would hand the second channel_send sequence 1"
    ),
)
def test_single_channel_per_link_shared_sequence_space(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=("buffer",),
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    assert client.channel_window(link_id)["next_sequence"] == 0, (
        "precondition: fresh channel next_sequence must be 0"
    )

    first = client.channel_send(link_id, b"first-channel-msg", timeout_ms=_SEND_TIMEOUT_MS)
    assert first.get("delivered") is True, f"first channel_send stalled: {first!r}"
    assert first.get("sequence") == 0, (
        f"first channel_send must take sequence 0, got {first.get('sequence')}"
    )
    after_send = client.channel_window(link_id)["next_sequence"]
    assert after_send == 1, (
        f"after one channel_send next_sequence must be 1, got {after_send}"
    )

    # Stream a payload over the SAME link's Channel. If get_channel() is a
    # singleton, these StreamDataMessages consume the same sequence counter,
    # pushing next_sequence well past 1.
    stream = client.buffer_stream(link_id, b"stream-over-the-same-channel", timeout_ms=20000)
    assert stream.get("eof") is True, f"buffer stream did not complete: {stream!r}"

    next_seq = client.channel_window(link_id)["next_sequence"]
    assert next_seq > 1, (
        f"after a buffer_stream the channel's next_sequence is {next_seq}; if "
        f"streaming shared the channel it must exceed 1 — a value of 1 means the "
        f"stream used a SEPARATE channel (not the get_channel singleton)"
    )

    # A second channel_send must continue from the SHARED counter, not restart.
    second = client.channel_send(link_id, b"second-channel-msg", timeout_ms=_SEND_TIMEOUT_MS)
    assert second.get("delivered") is True, f"second channel_send stalled: {second!r}"
    assert second.get("sequence") == next_seq, (
        f"the second channel_send took sequence {second.get('sequence')}, but the "
        f"shared channel's next_sequence was {next_seq} — channel and buffer "
        f"traffic must draw from one sequence space (single channel per link)"
    )
    assert second.get("sequence") > 1, (
        f"second channel_send sequence {second.get('sequence')} must exceed 1; "
        f"sequence 1 would prove a separate per-API channel"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "buffer_stream", "buffer_received",
    ],
    verifies=(
        "RNS.Buffer round-trips a COMPRESSED stream: a highly compressible "
        "multi-chunk payload drives the writer's bz2 compression decision "
        "(Buffer.py:243-252 — compress when the result is smaller than both "
        "MAX_DATA_LEN and the raw chunk) and the reader's SUCCESSFUL bz2 "
        "decompression path (Buffer.py:94-97), reassembling byte-exact with EOF "
        "and no decompression-bound abort — the positive counterpart to the "
        "bomb-abort negative, which only exercises the reader's decompression on "
        "a failing chunk"
    ),
)
def test_buffer_stream_compressible_roundtrip(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=("buffer",),
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # A deterministic, highly compressible payload spanning multiple 16 KiB
    # chunks so the writer compresses full chunks and the reader decompresses
    # them. bz2 shrinks this to a tiny fraction, so the writer's compression
    # branch (compressed_length < raw) is taken on every chunk.
    payload = (b"reticulum-conformance-compressible-block-" * 2000)[:40000]
    assert len(payload) == 40000

    stream = client.buffer_stream(link_id, payload, timeout_ms=20000)
    assert stream.get("written") == len(payload), (
        f"writer reported {stream.get('written')} bytes, expected {len(payload)}"
    )
    assert stream.get("eof") is True, f"writer did not flush EOF: {stream!r}"

    received = server.buffer_received(dest_hash, timeout_ms=20000)
    assert received["aborted"] is False, (
        f"a legitimate compressible stream must not trip the decompression "
        f"bound: error={received['error']!r}"
    )
    assert received["eof"] is True, "receiver never observed EOF"
    assert received["data"] == payload, (
        f"compressed stream did not reassemble byte-exact: got "
        f"{len(received['data'])} bytes, expected {len(payload)}"
    )
