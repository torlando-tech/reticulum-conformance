"""RNS Channel reassembly / flow-control conformance.

`RNS.Channel` (obtained from an established Link via `link.get_channel()`)
provides reliable, ordered, de-duplicated, bi-directional message delivery on
top of a Link. Received envelopes carry a 16-bit sequence number (the `>HHH`
MSGTYPE/sequence/length header, Channel.Envelope.pack); the channel reorders
out-of-order arrivals, drops duplicates, and delivers contiguous runs to its
registered message handler in sequence order — including correctly crossing
the 0xFFFF->0 sequence-modulus boundary (Channel._receive /
Channel._emplace_envelope).

These are the paths RNS.Buffer / RawChannelReader/Writer streaming relies on,
and the audit (CONFORMANCE_REAUDIT.md §5 CORE) flagged them as untested: the
prior suite had only a single in-order 3-message channel test, exercising none
of the reorder / dedup / wraparound logic.

How these tests drive the channel: the wire harness `channel_inject` command
packs each {sequence, payload} into a real `RNS.Channel.Envelope` and hands its
bytes straight to the live `Channel._receive` on the client's outbound link —
exactly the bytes the channel would see off the wire, but delivered in an
arbitrary order we control. `channel_received` drains the payloads the channel
delivered to its handler, in delivery order; `channel_window` reports the live
window / sequence state read straight off the `RNS.Channel` object. Because the
injection bypasses the wire, every assertion here runs identically under
`--reference-only` (reference plays both link peers).

This module owns the RX-side reassembly contract: reorder, duplicate drop,
16-bit wraparound, and the true-stale sequence drop (the four
`channel_inject`-driven behaviours). `test_channel_initial_window` additionally
asserts the *initial* window constants (the static half of the window
contract). The TX-side flow-control behaviours that fire on channel *send* —
window growth on ack, window/window_max shrink + 5-try teardown on loss
(Channel._packet_tx_op / _packet_timeout), and the MSGTYPE>=0xf000 registration
rejection (Channel._register_message_type) — live in the sibling
`test_channel_flow.py`, which drives the real `channel_send` command (the honest
replacement for the dead cmd_rns_channel_send).
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["channel"]
_LINK_TIMEOUT_MS = 15000
_PATH_POLL_TIMEOUT_MS = 10000

# RNS sequence space is 16-bit: SEQ_MAX=0xFFFF, SEQ_MODULUS=0x10000
# (Channel.SEQ_MAX / Channel.SEQ_MODULUS).
_SEQ_MAX = 0xFFFF


def _open_channel_link(wire_peers):
    """Stand up a TCP server/client pair, establish an outbound Link from the
    client to the server's listening destination, and return
    (server, client, server_dest, link_id).

    The channel under test is the one on the client's outbound link; nothing
    is required of the server beyond accepting the link, because injection
    feeds the client's local Channel._receive directly rather than crossing
    the wire.
    """
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )
    server_dest = server.listen(app_name=_APP, aspects=_ASPECTS)
    assert client.poll_path(server_dest, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — a channel needs an established link first."
    )
    link_id = client.link_open(
        server_dest, app_name=_APP, aspects=_ASPECTS, timeout_ms=_LINK_TIMEOUT_MS,
    )
    return server, client, server_dest, link_id


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies="RNS Channel reorders out-of-order received envelopes by sequence before delivery: injecting sequences [1,0,2] (each carrying a distinct payload) into Channel._receive delivers them to the message handler in ascending sequence order [0,1,2], and advances the receive-sequence counter to 3 with an empty receive ring",
)
def test_channel_out_of_order_receive_insertion(wire_peers):
    server, client, server_dest, link_id = _open_channel_link(wire_peers)

    # Distinct payloads keyed to the intended delivery position so a wrong
    # ordering is obvious in the failure message (and so an impl that delivers
    # in arrival order rather than sequence order is caught).
    payloads = {0: b"seq-zero", 1: b"seq-one", 2: b"seq-two"}
    # Inject deliberately out of order: 1, then 0, then 2.
    client.channel_inject(
        link_id,
        [
            {"sequence": 1, "data": payloads[1]},
            {"sequence": 0, "data": payloads[0]},
            {"sequence": 2, "data": payloads[2]},
        ],
    )

    delivered = client.channel_received(link_id)
    assert delivered == [payloads[0], payloads[1], payloads[2]], (
        f"channel did not reassemble in sequence order: got "
        f"{[d.hex() for d in delivered]!r}, expected "
        f"{[payloads[s].hex() for s in (0, 1, 2)]!r}"
    )

    # The receive window's low edge must have advanced past all three, with
    # nothing left buffered — confirms the contiguous run was fully drained.
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == 3, (
        f"next_rx_sequence={w['next_rx_sequence']}, expected 3 after delivering [0,1,2]"
    )
    assert w["rx_ring"] == 0, (
        f"rx_ring={w['rx_ring']}, expected empty after contiguous delivery"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies="RNS Channel drops a duplicate-sequence envelope: injecting sequences [1,1,0] where the two seq=1 envelopes carry different payloads delivers each sequence exactly once, in order [0,1], retaining the first-seen seq=1 payload and discarding the later duplicate",
)
def test_channel_duplicate_sequence_dropped(wire_peers):
    server, client, server_dest, link_id = _open_channel_link(wire_peers)

    first_seq1 = b"first-one"     # the copy that should survive
    dup_seq1 = b"dup-one"         # the duplicate that must be dropped
    seq0 = b"the-zero"           # positive control: a NON-duplicate that IS delivered
    assert first_seq1 != dup_seq1

    # seq=1 arrives twice (held in the ring while seq=0 is missing), then
    # seq=0 arrives and unblocks contiguous delivery of [0,1].
    client.channel_inject(
        link_id,
        [
            {"sequence": 1, "data": first_seq1},
            {"sequence": 1, "data": dup_seq1},
            {"sequence": 0, "data": seq0},
        ],
    )

    delivered = client.channel_received(link_id)
    # Exactly two deliveries: seq 0 and seq 1 — never three, and the duplicate
    # payload never surfaces.
    assert delivered == [seq0, first_seq1], (
        f"duplicate sequence not handled correctly: got "
        f"{[d.hex() for d in delivered]!r}, expected "
        f"{[seq0.hex(), first_seq1.hex()]!r}"
    )
    assert dup_seq1 not in delivered, "duplicate seq=1 payload was delivered"

    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == 2, (
        f"next_rx_sequence={w['next_rx_sequence']}, expected 2 after delivering [0,1]"
    )
    assert w["rx_ring"] == 0, f"rx_ring={w['rx_ring']}, expected empty"


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies="RNS Channel handles 16-bit receive-sequence wraparound across the 0xFFFF->0 modulus boundary: after the receive counter reaches 0xFFFF, an early-arriving seq=0 is held (not rejected as stale and not yet delivered) until seq=0xFFFF arrives, then both are delivered in order [0xFFFF, 0] and the counter wraps to 1",
)
def test_channel_sequence_wraparound(wire_peers):
    server, client, server_dest, link_id = _open_channel_link(wire_peers)

    # Drive the receive-sequence counter up to 0xFFFF by delivering every
    # sequence 0..0xFFFE in order. Each batch is injected then drained so the
    # rx ring (and the delivered-payload buffer) stay bounded.
    batch_size = 8192
    delivered_count = 0
    seq = 0
    while seq < _SEQ_MAX:
        end = min(seq + batch_size, _SEQ_MAX)
        client.channel_inject(
            link_id, [{"sequence": s, "data": b""} for s in range(seq, end)]
        )
        delivered_count += len(client.channel_received(link_id))
        seq = end

    # All 0..0xFFFE (= 0xFFFF sequences) delivered in order; counter now 0xFFFF.
    assert delivered_count == _SEQ_MAX, (
        f"delivered {delivered_count} pre-wrap messages, expected {_SEQ_MAX}"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == _SEQ_MAX, (
        f"next_rx_sequence={w['next_rx_sequence']}, expected 0xFFFF before the wrap"
    )

    # seq=0 is the NEXT logical sequence after 0xFFFF, but numerically less than
    # the current counter. A correct impl recognises it as in-window (not a
    # stale replay) and holds it, delivering nothing yet.
    last = b"\xff-wrap-edge"
    zero = b"\x00-after-wrap"
    client.channel_inject(link_id, [{"sequence": 0, "data": zero}])
    held = client.channel_received(link_id)
    assert held == [], (
        f"seq=0 was delivered before seq=0xFFFF: {[h.hex() for h in held]!r}"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == _SEQ_MAX, (
        f"early seq=0 wrongly advanced the counter to {w['next_rx_sequence']}"
    )
    assert w["rx_ring"] == 1, (
        f"seq=0 should be buffered (rx_ring=1), got rx_ring={w['rx_ring']}"
    )

    # Now seq=0xFFFF arrives, completing the contiguous run; the channel must
    # deliver 0xFFFF then continue across the modulus boundary into the held
    # seq=0, yielding [0xFFFF, 0] and wrapping the counter to 1.
    client.channel_inject(link_id, [{"sequence": _SEQ_MAX, "data": last}])
    boundary = client.channel_received(link_id)
    assert boundary == [last, zero], (
        f"wraparound delivery wrong: got {[b.hex() for b in boundary]!r}, "
        f"expected {[last.hex(), zero.hex()]!r}"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == 1, (
        f"counter did not wrap to 1: next_rx_sequence={w['next_rx_sequence']}"
    )
    assert w["rx_ring"] == 0, f"rx_ring={w['rx_ring']}, expected empty after wrap delivery"


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_window",
    ],
    verifies="RNS Channel initializes its flow-control window to the documented constants on a non-degenerate (loopback) RTT link: window=2 (WINDOW), window_min=2 (WINDOW_MIN), window_max=5 (WINDOW_MAX_SLOW), window_flexibility=4 (WINDOW_FLEXIBILITY)",
)
def test_channel_initial_window(wire_peers):
    server, client, server_dest, link_id = _open_channel_link(wire_peers)

    # The window profile is chosen from the link RTT at channel creation.
    # Loopback RTT is far below Channel.RTT_SLOW (1.45s), so the standard
    # (non-degenerate) slow-link profile applies; the degenerate window==1
    # profile (rtt > RTT_SLOW) is unreachable here. Window *growth* (on send
    # ack) and *shrink* (on retransmit timeout) are TX-side and not driven by
    # this suite — see the module docstring.
    w = client.channel_window(link_id)
    assert w["window"] == 2, f"initial window={w['window']}, expected 2 (Channel.WINDOW)"
    assert w["window_min"] == 2, (
        f"window_min={w['window_min']}, expected 2 (Channel.WINDOW_MIN)"
    )
    assert w["window_max"] == 5, (
        f"window_max={w['window_max']}, expected 5 (Channel.WINDOW_MAX_SLOW)"
    )
    assert w["window_flexibility"] == 4, (
        f"window_flexibility={w['window_flexibility']}, expected 4 "
        f"(Channel.WINDOW_FLEXIBILITY)"
    )
    # The transmit-sequence counter starts at 0 on a fresh channel.
    assert w["next_sequence"] == 0, (
        f"next_sequence={w['next_sequence']}, expected 0 on a fresh channel"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies="RNS Channel unconditionally drops a truly-stale received sequence in the normal (non-wrapped) window region: after delivering [0,1,2] (next_rx_sequence=3, far below the 0xFFFF modulus so the receive window does not wrap), injecting already-delivered sequences 0 and 1 (each < next_rx_sequence) delivers nothing and leaves next_rx_sequence=3 with an empty rx ring, while the still-expected sequence 3 injected afterward IS delivered and advances next_rx_sequence to 4 — discriminating the stale-drop else-branch (Channel.py:431-439, where envelope.sequence < next_rx_sequence and the window does not wrap) from both ring-dedup and the wraparound forward-window hold the other tests cover",
)
def test_channel_true_stale_sequence_dropped(wire_peers):
    server, client, server_dest, link_id = _open_channel_link(wire_peers)

    # Establish a normal (non-wrapped) receive position: deliver 0,1,2 in order
    # so next_rx_sequence advances to 3 and the ring drains. Distinct payloads
    # keep the setup self-checking.
    client.channel_inject(
        link_id, [{"sequence": s, "data": bytes([s])} for s in range(3)]
    )
    drained = client.channel_received(link_id)
    assert drained == [b"\x00", b"\x01", b"\x02"], (
        f"setup did not deliver [0,1,2] in order: {[d.hex() for d in drained]!r}"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == 3 and w["rx_ring"] == 0, (
        f"setup left next_rx_sequence={w['next_rx_sequence']}, rx_ring={w['rx_ring']}; "
        f"expected 3 / 0 before the stale injection"
    )

    # Inject already-delivered sequences below next_rx_sequence. With
    # next_rx_sequence=3, the forward window (next_rx + WINDOW_MAX) does NOT wrap
    # the modulus, so RNS takes the unconditional stale-drop else-branch: these
    # are dropped before reaching the ring (never delivered, never buffered).
    client.channel_inject(
        link_id,
        [
            {"sequence": 0, "data": b"stale-zero"},
            {"sequence": 1, "data": b"stale-one"},
        ],
    )
    stale_delivered = client.channel_received(link_id)
    assert stale_delivered == [], (
        f"truly-stale sequences were delivered: "
        f"{[d.hex() for d in stale_delivered]!r}"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == 3, (
        f"stale injection advanced next_rx_sequence to {w['next_rx_sequence']}, "
        f"expected it to stay 3"
    )
    assert w["rx_ring"] == 0, (
        f"stale injection buffered into rx_ring={w['rx_ring']} instead of dropping"
    )

    # Positive control: the channel is NOT dead — the still-expected next
    # sequence (3) is accepted and delivered, advancing next_rx_sequence to 4.
    client.channel_inject(link_id, [{"sequence": 3, "data": b"live-three"}])
    live = client.channel_received(link_id)
    assert live == [b"live-three"], (
        f"the live next-sequence was not delivered after the stale drop: "
        f"{[d.hex() for d in live]!r}"
    )
    w = client.channel_window(link_id)
    assert w["next_rx_sequence"] == 4, (
        f"live delivery did not advance next_rx_sequence to 4: "
        f"got {w['next_rx_sequence']}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies="RNS Channel drops a received envelope whose MSGTYPE is not registered, WITHOUT advancing the receive sequence: injecting an envelope at the next expected sequence carrying an unregistered MSGTYPE (0x0202) delivers nothing and leaves next_rx_sequence unchanged, so a subsequently-injected REGISTERED envelope at that SAME sequence is delivered normally and advances the sequence (positive control). An impl that advances the rx sequence on an unhandled msgtype would permanently stall the channel at that gap",
)
def test_channel_unregistered_msgtype_dropped(wire_peers):
    server, client, server_dest, link_id = _open_channel_link(wire_peers)

    pre = client.channel_window(link_id)
    seq = pre["next_rx_sequence"]

    # Inject an envelope at the next expected sequence with an UNREGISTERED
    # MSGTYPE — the channel only registers the wire message type, so 0x0202 has
    # no constructor and the envelope must be dropped.
    client.channel_inject(
        link_id, [{"sequence": seq, "data": b"unregistered-payload", "msgtype": 0x0202}]
    )
    assert client.channel_received(link_id) == [], (
        "an envelope with an unregistered MSGTYPE was delivered to the handler"
    )
    mid = client.channel_window(link_id)
    assert mid["next_rx_sequence"] == seq, (
        f"the rx sequence advanced ({seq} -> {mid['next_rx_sequence']}) on an "
        f"unregistered-msgtype envelope — the channel will stall permanently"
    )

    # Positive control: a REGISTERED envelope at the SAME sequence is delivered
    # and advances the sequence — proving the drop above was the msgtype, not a
    # dead channel.
    payload = b"registered-payload"
    client.channel_inject(link_id, [{"sequence": seq, "data": payload}])
    assert client.channel_received(link_id) == [payload], (
        "a registered envelope at the previously-dropped sequence was not delivered"
    )
    post = client.channel_window(link_id)
    assert post["next_rx_sequence"] == (seq + 1) % 0x10000, (
        f"rx sequence did not advance after a valid envelope: {post!r}"
    )
