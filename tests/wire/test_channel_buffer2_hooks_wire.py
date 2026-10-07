"""RNS Channel CHANNEL-context emit + Buffer streaming conformance (wave 2).

Second-wave Channel/Buffer gaps reached in the first harness pass but deferred
for an extra hook. Each pins a contract against an EXTERNAL ground-truth literal
read from the RNS source, with a positive AND a negative side:

  * CHANNEL CONTEXT (0x0E) — every packet a Channel emits is a DATA packet
    carrying context RNS.Packet.CHANNEL (Channel.py:669-670 LinkChannelOutlet.send
    does ``RNS.Packet(link, raw, context=RNS.Packet.CHANNEL)``). A non-CHANNEL
    DATA packet (context NONE) is routed to the link packet callback, NOT into
    the channel (Link.receive, Link.py:986-1173).

  * NO CHANNEL -> NO PROOF — an inbound CHANNEL packet delivered to a Link with
    no open channel is dropped WITHOUT a proof (Link.py:1166-1167); a Link WITH
    a channel proves it (Link.py:1172). Observable via the receiver proof log.

  * DECOMPRESSION-BOMB BOUND — StreamDataMessage.unpack accepts a compressed
    chunk that inflates to exactly MAX_CHUNK_LEN (16384) but aborts one byte
    over (Buffer.py:95-97), and the aborted chunk does NOT advance the receiver
    channel's _next_rx_sequence (the unpack raises before the sequence bump).

  * WRITE CHUNKING + COMPRESSION DECISION — RawChannelWriter.write caps each raw
    chunk at MAX_DATA_LEN (RNS.Link.MDU - 8 = 423), tries compression
    (COMPRESSION_TRIES=4) and emits one StreamDataMessage per write, returning
    the processed length (Buffer.py RawChannelWriter.write).

  * EOF SEMANTICS — a non-empty EOF-flagged message carries data + EOF together;
    the default path and RawChannelWriter.close() emit a separate empty EOF
    message; reads after EOF return buffered-then-empty; close() drains the tx
    ring (Buffer.py close path).

  * STREAM-ID FILTERING — a RawChannelReader registered for stream id A
    reassembles a stream sent to A while a reader for B sees nothing
    (Buffer.py:152 RawChannelReader._handle_message returns False on a
    non-matching stream id).

Both Link peers are reference instances under ``--reference-only``.
"""

import math
import os
import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("chanbuf2",)
_LINK_TIMEOUT_MS = 15000
_PATH_TIMEOUT_MS = 10000
_SEND_TIMEOUT_MS = 12000

# External ground-truth literals (RNS source). Asserted == the live RNS values
# the bridge returns, then used to anchor behaviour.
_PKT_CHANNEL = 0x0E          # RNS.Packet.CHANNEL (Packet.py)
_PKT_DATA_TYPE = 0x00        # RNS.Packet.DATA packet_type
_MAX_DATA_LEN = 423          # RNS.Link.MDU(431) - StreamDataMessage.OVERHEAD(8)
_MAX_CHUNK_LEN = 16384       # RawChannelWriter.MAX_CHUNK_LEN (1024*16)
_COMPRESSION_TRIES = 4       # RawChannelWriter.COMPRESSION_TRIES
_SEQ_MODULUS = 0x10000       # Channel.SEQ_MODULUS


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_emit_capture", "channel_received",
        "link_send", "link_poll",
    ],
    verifies=(
        "Every packet an RNS Channel emits is a DATA packet carrying context "
        "RNS.Packet.CHANNEL (0x0E) — LinkChannelOutlet.send builds "
        "RNS.Packet(link, raw, context=RNS.Packet.CHANNEL) (Channel.py:669-670) "
        "— and the receiver routes the 0x0E packet INTO its channel "
        "(channel_received), while a non-CHANNEL DATA packet (context NONE) is "
        "routed to the link packet callback (link_poll) and is NOT delivered to "
        "the channel (Link.receive context dispatch, Link.py:986-1173). The live "
        "RNS.Packet.CHANNEL value is asserted == the external literal 0x0E"
    ),
)
def test_channel_emits_channel_context_and_routing(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    probe = b"channel-ctx-probe"
    emit = client.channel_emit_capture(link_id, probe, timeout_ms=_SEND_TIMEOUT_MS)

    # The live RNS.Packet.CHANNEL equals the external literal — pins the constant.
    assert emit["channel_context"] == _PKT_CHANNEL, (
        f"RNS.Packet.CHANNEL={emit['channel_context']}, expected {_PKT_CHANNEL:#x}"
    )
    # The emitted packet carried CHANNEL context and DATA packet type.
    assert emit["context"] == _PKT_CHANNEL, (
        f"channel emitted a packet with context {emit['context']}, expected "
        f"CHANNEL ({_PKT_CHANNEL:#x})"
    )
    assert emit["packet_type"] == _PKT_DATA_TYPE, (
        f"channel packet_type={emit['packet_type']}, expected DATA "
        f"({_PKT_DATA_TYPE})"
    )
    assert emit["delivered"] is True, (
        f"the CHANNEL packet was not proved/delivered by the receiver: {emit!r}"
    )

    # The 0x0E packet was routed INTO the receiver's channel.
    routed = []
    for _ in range(20):
        routed = server.channel_received(link_id)
        if routed:
            break
    assert routed == [probe], (
        f"the CHANNEL-context packet was not routed into the receiver channel: "
        f"got {[r.hex() for r in routed]!r}, expected {[probe.hex()]!r}"
    )

    # Negative: a plain link DATA packet (context NONE) goes to the packet
    # callback (link_poll), NOT into the channel.
    plain = b"plain-link-data-not-channel"
    client.link_send(link_id, plain)
    got = []
    for _ in range(20):
        got = server.link_poll(dest_hash, timeout_ms=1500)
        if plain in got:
            break
    assert plain in got, (
        f"the plain DATA packet never reached the link packet callback: {got!r}"
    )
    assert server.channel_received(link_id) == [], (
        "a non-CHANNEL DATA packet must NOT be routed into the channel"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "listener_proof_log",
    ],
    verifies=(
        "An inbound CHANNEL packet delivered to a Link with NO open channel is "
        "dropped WITHOUT a proof (Link.py:1166-1167 logs 'Channel data received "
        "without open channel' and never calls packet.prove()), so the sender's "
        "send never delivers; a Link WITH an open channel proves the CHANNEL "
        "packet (Link.py:1172) and the send delivers. The receiver proof log "
        "shows ZERO CHANNEL-context (0x0E) proofs for the no-channel listener "
        "and >=1 for the channel listener — a clean positive/negative around the "
        "open-channel gate"
    ),
)
def test_no_channel_no_proof(wire_link_setup):
    # Negative listener: accepts the link WITHOUT opening a channel.
    server, client, dest_no, link_no = wire_link_setup(
        app_name=_APP, aspects=("nochan",), open_channel=False,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Positive control listener on the SAME pair: opens a channel and proves.
    dest_yes = server.listen(app_name=_APP, aspects=("haschan",), open_channel=True)
    assert client.poll_path(dest_yes, timeout_ms=_PATH_TIMEOUT_MS), (
        "client never learned a path to the channel listener"
    )
    link_yes = client.link_open(
        dest_yes, app_name=_APP, aspects=("haschan",), timeout_ms=_LINK_TIMEOUT_MS
    )

    # Positive: the channel listener proves the CHANNEL packet -> delivered.
    ok = client.channel_send(link_yes, b"prove-me", timeout_ms=_SEND_TIMEOUT_MS)
    assert ok.get("delivered") is True, (
        f"a CHANNEL packet to a channel-open listener must deliver: {ok!r}"
    )
    plog_yes = server.listener_proof_log(dest_yes)
    assert plog_yes["channel_context"] == _PKT_CHANNEL, (
        f"live RNS.Packet.CHANNEL={plog_yes['channel_context']}, "
        f"expected {_PKT_CHANNEL:#x}"
    )
    assert plog_yes["channel_proofs"] >= 1, (
        f"the channel listener must prove the CHANNEL packet at least once: "
        f"{plog_yes!r}"
    )

    # Negative: the no-channel listener drops the CHANNEL packet unproven, so the
    # send never delivers and the receiver proves ZERO CHANNEL packets.
    no = client.channel_send(link_no, b"drop-me", timeout_ms=_SEND_TIMEOUT_MS)
    assert no.get("delivered") is False, (
        f"a CHANNEL packet to a no-channel listener must NOT deliver "
        f"(it is dropped unproven): {no!r}"
    )
    plog_no = server.listener_proof_log(dest_no)
    assert plog_no["channel_proofs"] == 0, (
        f"the no-channel listener must prove ZERO CHANNEL packets "
        f"(Link.py:1166-1167 drops them unproven): {plog_no!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "buffer_stream", "buffer_received", "listener_channel_rx",
    ],
    verifies=(
        "RNS StreamDataMessage.unpack pins MAX_CHUNK_LEN=16384 exactly: a "
        "compressed chunk that inflates to EXACTLY 16384 bytes is accepted "
        "(decompressor reaches eof within the max_length bound), while a chunk "
        "that would inflate to 16385 bytes aborts with IOError (Buffer.py:95-97) "
        "— and the aborted chunk does NOT advance the receiver channel's "
        "_next_rx_sequence (Channel._receive unpacks before the sequence bump, "
        "so a raising unpack leaves the sequence untouched), whereas the "
        "accepted chunk advances it by exactly one"
    ),
)
def test_decompression_bomb_exact_bound(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    rx0 = server.listener_channel_rx(dest_hash)["next_rx_sequence"]

    # Accepted: inflates to exactly MAX_CHUNK_LEN (16384).
    acc = client.buffer_stream(
        link_id, b"", bomb=True, bomb_decompressed_len=_MAX_CHUNK_LEN,
        timeout_ms=_SEND_TIMEOUT_MS,
    )
    assert acc["max_chunk_len"] == _MAX_CHUNK_LEN, (
        f"live MAX_CHUNK_LEN={acc['max_chunk_len']}, expected {_MAX_CHUNK_LEN}"
    )
    recv_acc = client_wait_accepted(server, dest_hash)
    assert recv_acc["aborted"] is False, (
        f"a chunk inflating to exactly {_MAX_CHUNK_LEN} must be accepted, not "
        f"aborted: {recv_acc!r}"
    )
    assert len(recv_acc["data"]) == _MAX_CHUNK_LEN, (
        f"the accepted chunk must reassemble to exactly {_MAX_CHUNK_LEN} bytes, "
        f"got {len(recv_acc['data'])}"
    )
    rx1 = server.listener_channel_rx(dest_hash)["next_rx_sequence"]
    assert rx1 == (rx0 + 1) % _SEQ_MODULUS, (
        f"the accepted chunk must advance the receive sequence by one: "
        f"{rx0} -> {rx1}"
    )

    # Aborted: one byte over the bound (16385).
    client.buffer_stream(
        link_id, b"", bomb=True, bomb_decompressed_len=_MAX_CHUNK_LEN + 1,
        timeout_ms=_SEND_TIMEOUT_MS,
    )
    aborted = _poll_until(
        lambda r: r["aborted"],
        lambda: server.buffer_received(dest_hash, timeout_ms=500),
        timeout_s=30.0,
    )["aborted"]
    assert aborted, (
        f"a chunk inflating to {_MAX_CHUNK_LEN + 1} (one over the bound) must "
        f"abort the receiver's unpack with IOError"
    )
    rx2 = server.listener_channel_rx(dest_hash)["next_rx_sequence"]
    assert rx2 == rx1, (
        f"the ABORTED chunk must NOT advance the receive sequence "
        f"(unpack raises before the bump): {rx1} -> {rx2}"
    )


def _poll_until(pred, poll, timeout_s):
    """Poll ``poll()`` until ``pred(value)`` is true or ``timeout_s`` elapses
    (wall-clock). Returns the last observed value.

    The receiver-side flags these tests wait on (eof / aborted) are set on the
    receiving peer's own thread, so the wait is async. A fixed iteration budget
    (e.g. 40 x 500ms) is fragile: each ``poll`` call is a ceiling, not a floor,
    and the loop can exhaust before a load-starved receive thread (30+ minutes
    into a serial CI suite) surfaces the flag - the flake this removes. A
    wall-clock deadline guarantees the full budget (it runs the whole
    ``timeout_s`` regardless of how fast each poll returns) while still
    returning as soon as the flag appears, so it adds no latency in the common
    case. ``timeout_s`` is a generous floor, not a target: it must exceed the
    suite's worst-case receiver delay, and 30s does so with headroom (the test
    normally concludes in well under a second).
    """
    last = None
    deadline = time.monotonic() + timeout_s
    while True:
        last = poll()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            return last
        # Small sleep between polls keeps CPU load down without materially
        # shortening the effective wait; the deadline, not the sleep, bounds it.
        time.sleep(0.05)


def client_wait_accepted(server, dest_hash):
    """Poll the receiver until the accepted bomb concludes (eof)."""
    last = {"data": b"", "eof": False, "aborted": False, "error": None}
    last = _poll_until(
        lambda r: r["eof"] or r["aborted"] or r["data"],
        lambda: server.buffer_received(dest_hash, timeout_ms=500),
        timeout_s=30.0,
    )
    return last


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "buffer_stream",
    ],
    verifies=(
        "RNS RawChannelWriter.write caps each raw (incompressible) chunk and emits "
        "one StreamDataMessage per write. RNS 1.3.1 capped at the fixed "
        "StreamDataMessage.MAX_DATA_LEN (RNS.Link.MDU - 8 = 423); RNS 1.5.5 "
        "(commit df801810 'Utilize full link MDU in RawChannelWriter') caps at the "
        "LIVE link MDU (writer._mdu = channel.mdu - HEADER_LEN), which is larger on "
        "a high-MTU link. The live fixed constant (423) and COMPRESSION_TRIES (4) "
        "are asserted == the external literals; an INCOMPRESSIBLE payload of N "
        "bytes then produces ceil(N / live_cap) data messages, each bytes<=live_cap, "
        "compressed=False, per-write processed lengths summing to N; a "
        "HIGHLY-COMPRESSIBLE payload collapses to a single compressed message whose "
        "body is < the input (the COMPRESSION_TRIES=4 decision)."
    ),
)
def test_stream_write_chunking_and_compression(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Incompressible payload -> raw chunking.
    n = 1000
    payload = os.urandom(n)
    res = client.buffer_stream(link_id, payload, timeout_ms=_SEND_TIMEOUT_MS)

    # The FIXED constant is still the external ground-truth literal (1.5.5 keeps
    # the StreamDataMessage.MAX_DATA_LEN definition; it just no longer uses it as
    # the raw-write cap). Pin that, then drive the chunk math from the LIVE cap
    # the writer actually used (1.5.5's df801810 change).
    assert res["fixed_max_data_len"] == _MAX_DATA_LEN, (
        f"fixed StreamDataMessage.MAX_DATA_LEN={res['fixed_max_data_len']}, "
        f"expected {_MAX_DATA_LEN}"
    )
    live_cap = res["max_data_len"]
    assert live_cap > 0, f"live chunk cap must be positive: {res!r}"
    # RNS 1.5.5 (df801810) derives the raw-write cap from the LIVE link MDU:
    # writer._mdu = channel.mdu - StreamDataMessage.HEADER_LEN (HEADER_LEN=2).
    # Pin the exact formula from bridge-reported values (channel_mdu - cap == 2).
    # A 1.3.1-style writer (capped at the fixed 423 constant) does NOT satisfy
    # this on a high-MTU link: it reports cap=423 while channel_mdu is large.
    assert res["channel_mdu"] - live_cap == 2, (
        f"1.5.5 raw-write cap must be channel_mdu - HEADER_LEN (2): "
        f"channel_mdu={res['channel_mdu']}, cap={live_cap} "
        f"(diff={res['channel_mdu'] - live_cap})"
    )
    assert live_cap >= _MAX_DATA_LEN, (
        f"the live chunk cap must be >= the 1.3.1 fixed constant "
        f"{_MAX_DATA_LEN}: got {live_cap}"
    )
    assert res["compression_tries"] == _COMPRESSION_TRIES, (
        f"live COMPRESSION_TRIES={res['compression_tries']}, "
        f"expected {_COMPRESSION_TRIES}"
    )

    manifest = res["manifest"]
    data_msgs = [m for m in manifest if m["bytes"] > 0]
    expected_msgs = math.ceil(n / live_cap)
    assert len(data_msgs) == expected_msgs, (
        f"incompressible {n} bytes must chunk into ceil({n}/{live_cap})="
        f"{expected_msgs} data messages, got {len(data_msgs)}: {manifest!r}"
    )
    assert all(m["bytes"] <= live_cap for m in manifest), (
        f"every emitted chunk must be <= live cap={live_cap}: {manifest!r}"
    )
    assert all(not m["compressed"] for m in data_msgs), (
        f"incompressible chunks must not be flagged compressed: {data_msgs!r}"
    )
    # Per-write processed lengths sum to the payload size (write returns the
    # number of bytes it consumed from the buffer).
    assert sum(res["write_returns"]) == n, (
        f"per-write processed lengths must sum to {n}: {res['write_returns']!r}"
    )
    assert all(r <= live_cap for r in res["write_returns"]), (
        f"each incompressible write consumes <= live cap {live_cap} bytes: "
        f"{res['write_returns']!r}"
    )
    # Channel sequences are contiguous across the emitted messages.
    seqs = [m["sequence"] for m in manifest]
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs))), (
        f"emitted channel sequences must be contiguous: {seqs!r}"
    )

    # Highly-compressible payload -> a single compressed message (the
    # compression decision succeeds on the first try and covers the whole input).
    comp = client.buffer_stream(link_id, bytes(n), timeout_ms=_SEND_TIMEOUT_MS)
    comp_data = [m for m in comp["manifest"] if m["bytes"] > 0]
    assert len(comp_data) == 1, (
        f"a highly-compressible {n}-byte payload must collapse to ONE compressed "
        f"message, got {len(comp_data)}: {comp['manifest']!r}"
    )
    assert comp_data[0]["compressed"] is True, (
        f"the collapsed message must be flagged compressed: {comp_data[0]!r}"
    )
    assert comp_data[0]["bytes"] < n and comp_data[0]["bytes"] <= live_cap, (
        f"the compressed body must be smaller than the input and fit a message "
        f"(live cap {live_cap}): {comp_data[0]!r}"
    )
    assert comp["write_returns"] == [n], (
        f"a single compressed write must consume the whole {n}-byte input: "
        f"{comp['write_returns']!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "buffer_stream", "buffer_received",
    ],
    verifies=(
        "RNS Buffer EOF semantics: a NON-empty EOF-flagged write carries data + "
        "EOF in the SAME StreamDataMessage (the final manifest entry has bytes>0 "
        "and eof=True, with no separate empty-EOF message), the receiver "
        "delivers that data and then reports EOF, and a read after EOF returns "
        "buffered-then-empty; the DEFAULT path and RawChannelWriter.close() each "
        "emit a SEPARATE empty EOF message (bytes==0, eof=True), and close() "
        "drains the tx ring (tx_ring_after==0) so no payload is lost"
    ),
)
def test_stream_eof_semantics(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS, buffer_stream_ids=[10, 20],
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # (a) Non-empty EOF: data + EOF in one message on stream 10.
    pa = os.urandom(900)
    ra = client.buffer_stream(
        link_id, pa, stream_id=10, eof_with_data=True, timeout_ms=_SEND_TIMEOUT_MS
    )
    assert ra["manifest"][-1]["eof"] is True and ra["manifest"][-1]["bytes"] > 0, (
        f"eof_with_data must flag EOF on the final DATA-bearing message: "
        f"{ra['manifest']!r}"
    )
    assert all(m["bytes"] > 0 for m in ra["manifest"]), (
        f"eof_with_data must NOT emit a separate empty-EOF message: "
        f"{ra['manifest']!r}"
    )
    rcv_a = server.buffer_received(dest_hash, stream_id=10, timeout_ms=_SEND_TIMEOUT_MS)
    assert rcv_a["data"] == pa and rcv_a["eof"] is True, (
        f"the data accompanying EOF must be delivered before EOF takes effect: "
        f"len(data)={len(rcv_a['data'])}, eof={rcv_a['eof']}"
    )
    # Read after EOF: buffered-then-empty (no more data, EOF still reported).
    rcv_a2 = server.buffer_received(dest_hash, stream_id=10, timeout_ms=1500)
    assert rcv_a2["data"] == b"" and rcv_a2["eof"] is True, (
        f"a read after EOF must return empty with EOF still set: {rcv_a2!r}"
    )

    # (b) close() path on stream 20: a separate empty EOF + tx ring drained.
    pb = os.urandom(900)
    rb = client.buffer_stream(
        link_id, pb, stream_id=20, use_close=True, timeout_ms=_SEND_TIMEOUT_MS
    )
    assert any(m["bytes"] == 0 and m["eof"] for m in rb["manifest"]), (
        f"close() must emit a separate empty EOF message: {rb['manifest']!r}"
    )
    assert rb["tx_ring_after"] == 0, (
        f"close() must drain the tx ring (every envelope proved): "
        f"tx_ring_after={rb['tx_ring_after']}"
    )
    rcv_b = server.buffer_received(dest_hash, stream_id=20, timeout_ms=_SEND_TIMEOUT_MS)
    assert rcv_b["data"] == pb and rcv_b["eof"] is True, (
        f"close() must drain so the full payload is delivered: "
        f"len(data)={len(rcv_b['data'])}, eof={rcv_b['eof']}"
    )

    # (c) Default path on stream 0: a separate empty EOF message (contrast).
    pc = os.urandom(900)
    rc = client.buffer_stream(link_id, pc, timeout_ms=_SEND_TIMEOUT_MS)
    assert rc["manifest"][-1]["bytes"] == 0 and rc["manifest"][-1]["eof"] is True, (
        f"the default path must terminate with a separate empty EOF message: "
        f"{rc['manifest']!r}"
    )
    rcv_c = server.buffer_received(dest_hash, timeout_ms=_SEND_TIMEOUT_MS)
    assert rcv_c["data"] == pc and rcv_c["eof"] is True, (
        f"the default path must deliver the full payload + EOF: "
        f"len(data)={len(rcv_c['data'])}, eof={rcv_c['eof']}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "buffer_stream", "buffer_received",
    ],
    verifies=(
        "RNS Buffer stream addressing is receiver-relative: with two "
        "RawChannelReaders registered at distinct stream ids A and B on the same "
        "Channel, a stream sent to A is reassembled ONLY by reader A "
        "(RawChannelReader._handle_message buffers iff message.stream_id == "
        "self._stream_id, Buffer.py:152); reader B returns False on every "
        "non-matching StreamDataMessage and sees nothing — no data and no EOF"
    ),
)
def test_stream_id_filtering(wire_link_setup):
    sid_a, sid_b = 100, 200
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS, buffer_stream_ids=[sid_a, sid_b],
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    payload = os.urandom(500)
    client.buffer_stream(
        link_id, payload, stream_id=sid_a, timeout_ms=_SEND_TIMEOUT_MS
    )

    rcv_a = server.buffer_received(dest_hash, stream_id=sid_a, timeout_ms=_SEND_TIMEOUT_MS)
    assert rcv_a["data"] == payload and rcv_a["eof"] is True, (
        f"reader A (stream {sid_a}) must reassemble the stream sent to it: "
        f"len(data)={len(rcv_a['data'])}, eof={rcv_a['eof']}"
    )

    # Reader B saw a non-matching stream id on every message -> nothing buffered.
    rcv_b = server.buffer_received(dest_hash, stream_id=sid_b, timeout_ms=2000)
    assert rcv_b["data"] == b"", (
        f"reader B (stream {sid_b}) must NOT reassemble a stream addressed to A: "
        f"got {rcv_b['data'].hex()}"
    )
    assert rcv_b["eof"] is False, (
        f"reader B must not see EOF for a stream it was not addressed: {rcv_b!r}"
    )
