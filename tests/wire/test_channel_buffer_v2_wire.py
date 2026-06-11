"""RNS Channel V2 gap-closure: per-direction sequence independence, truncated-
envelope resilience, post-teardown shutdown state, the retransmit-timeout
formula, the degenerate / medium window profiles, ordered handler dispatch, and
spurious-proof / stale-timeout robustness.

Each test pins a contract the prior channel_buffer suites left *partial* or
*uncovered* (V2 re-evaluation worklist). Every assertion is anchored on an
EXTERNAL standard — a published RNS source formula/constant or an INDEPENDENT
derivation — never on a value the reference merely echoes back:

  * PER-DIRECTION SEQUENCE INDEPENDENCE (`per-direction-sequence-independence`):
    RNS.Channel keeps two SEPARATE 16-bit counters, `_next_sequence` (transmit)
    and `_next_rx_sequence` (receive) (Channel.py:285-286). Driving the receive
    counter forward via injection must NOT move the transmit counter, and a
    transmit must NOT move the receive counter — a shared-counter impl would
    desync any bidirectional channel.

  * TRUNCATED-ENVELOPE RESILIENCE (`malformed-envelope-resilience`): a raw frame
    shorter than the 6-byte header makes Envelope.unpack's
    `struct.unpack(">HHH", raw[:6])` raise struct.error, caught by
    Channel._receive's outer guard (Channel.py:425-466); the channel drops it
    WITHOUT advancing the receive sequence and survives (a following valid
    envelope still delivers).

  * SHUTDOWN ON TEARDOWN (`channel-shutdown-on-teardown`): after the 5-try
    retransmission teardown, Channel._shutdown clears the message handlers and
    both rings (Channel.py:374-390), and a send on the torn-down channel fails
    cleanly with ME_LINK_NOT_READY via the no-receipt branch (the CLOSED link's
    outlet transmits nothing, so the packet has no receipt, Channel.py:619-626).

  * PACKET TIMEOUT FORMULA (`packet-timeout-formula`):
    Channel._get_packet_timeout_time(tries) ==
    `pow(1.5, tries-1) * max(rtt*2.5, 0.025) * (len(tx_ring)+1.5)`
    (Channel.py:545-547) — the exponential 1.5^(tries-1) backoff, the 25 ms
    floor, and the tx-ring scaling — re-derived independently and asserted equal.

  * DEGENERATE / SLOW WINDOW PROFILE (`window-initial-values`): Channel.__init__
    selects the degenerate all-1 window profile when rtt > RTT_SLOW (1.45) and
    the standard 2 / WINDOW_MIN 2 / WINDOW_MAX_SLOW 5 / WINDOW_FLEXIBILITY 4
    profile otherwise (Channel.py:297-308) — loopback RTT can never exceed
    RTT_SLOW, so the degenerate branch needs an rtt-spoof hook.

  * MEDIUM RATE UPGRADE (`window-rate-upgrade-medium`): with rtt in the medium
    band (RTT_FAST 0.18 < rtt <= RTT_MEDIUM 0.75), Channel._packet_tx_op counts
    `medium_rate_rounds` per delivered envelope and at FAST_RATE_THRESHOLD (10)
    promotes the window to WINDOW_MAX_MEDIUM 12 / WINDOW_MIN_LIMIT_MEDIUM 5
    (Channel.py:511-524).

  * ORDERED HANDLER DISPATCH (`handler-dispatch-stops-on-true`):
    Channel._run_callbacks invokes handlers in registration order, STOPS the
    chain when one returns True, and CONTINUES past a handler that raises
    (Channel.py:415-422).

  * SPURIOUS PROOF / STALE TIMEOUT (`spurious-proof-ignored`): a duplicate/late
    proof for an already-delivered (ring-removed) packet hits the "Spurious
    message received" branch and must NOT grow the window; a late timeout on a
    delivered packet and a timeout for a never-tracked packet early-return
    without tearing the link down (Channel._packet_tx_op / _packet_timeout,
    Channel.py:490-568).

Both Link peers are reference instances under ``--reference-only``; every
assertion holds reference-vs-reference.
"""

import math

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("channel",)
_LINK_TIMEOUT_MS = 15000
_PATH_TIMEOUT_MS = 10000
_SEND_TIMEOUT_MS = 12000
_DROP_TIMEOUT_MS = 20000

# External RNS literals (read from the published source, pinned here so the test
# process needs no RNS import — mirroring the sibling channel suites).
_SEQ_MODULUS = 0x10000     # Channel.SEQ_MODULUS

# Window profile constants (Channel.py:241-276).
_WINDOW = 2                # Channel.WINDOW
_WINDOW_MIN = 2            # Channel.WINDOW_MIN
_WINDOW_MAX_SLOW = 5       # Channel.WINDOW_MAX_SLOW
_WINDOW_FLEXIBILITY = 4    # Channel.WINDOW_FLEXIBILITY
_WINDOW_MAX_MEDIUM = 12    # Channel.WINDOW_MAX_MEDIUM
_WINDOW_MIN_MEDIUM = 5     # Channel.WINDOW_MIN_LIMIT_MEDIUM
_FAST_RATE_THRESHOLD = 10  # Channel.FAST_RATE_THRESHOLD

# RTT bands (Channel.py:268-272).
_RTT_FAST = 0.18           # Channel.RTT_FAST
_RTT_MEDIUM = 0.75         # Channel.RTT_MEDIUM
_RTT_SLOW = 1.45           # Channel.RTT_SLOW

# CEType numeric codes (Channel.py:109-114).
_ME_LINK_NOT_READY = 3     # CEType.ME_LINK_NOT_READY

# RNS.Link.CLOSED (Link.py).
_LINK_CLOSED = 0x04
_MAX_TRIES = 5             # Channel._max_tries


# ---------------------------------------------------------------------------
# per-direction-sequence-independence
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_send",
        "channel_window",
    ],
    verifies=(
        "RNS Channel keeps the transmit (_next_sequence) and receive "
        "(_next_rx_sequence) counters fully INDEPENDENT (Channel.py:285-286): on "
        "a fresh channel both are 0; injecting received sequences 0,1,2 advances "
        "ONLY next_rx_sequence to 3 while next_sequence stays 0; a delivered "
        "channel_send then takes the unchanged transmit sequence 0 (not 3) and "
        "advances ONLY next_sequence to 1, leaving next_rx_sequence at 3; "
        "injecting received sequence 3 advances ONLY next_rx_sequence to 4 "
        "(next_sequence stays 1); and a second channel_send takes transmit "
        "sequence 1 and advances next_sequence to 2 (next_rx_sequence stays 4). "
        "A shared-counter impl would have the first send take sequence 3, or a "
        "receive advance the transmit counter — desyncing any bidirectional "
        "channel"
    ),
)
def test_per_direction_sequence_independence(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    pre = client.channel_window(link_id)
    assert pre["next_sequence"] == 0 and pre["next_rx_sequence"] == 0, (
        f"precondition: a fresh channel must have both counters at 0, got "
        f"tx={pre['next_sequence']} rx={pre['next_rx_sequence']}"
    )

    # Drive the RECEIVE counter forward with injected envelopes 0,1,2.
    client.channel_inject(
        link_id, [{"sequence": s, "data": bytes([s])} for s in range(3)]
    )
    assert client.channel_received(link_id) == [b"\x00", b"\x01", b"\x02"], (
        "setup: injected receive run [0,1,2] must deliver in order"
    )
    after_rx = client.channel_window(link_id)
    assert after_rx["next_rx_sequence"] == 3, (
        f"receive counter must advance to 3 after delivering [0,1,2], got "
        f"{after_rx['next_rx_sequence']}"
    )
    assert after_rx["next_sequence"] == 0, (
        f"driving the RECEIVE counter to 3 wrongly moved the TRANSMIT counter to "
        f"{after_rx['next_sequence']} — the two sequence spaces are not "
        f"independent (a shared-counter impl)"
    )

    # A transmit takes the UNCHANGED transmit sequence 0 (not 3) and advances
    # only the transmit counter.
    first = client.channel_send(link_id, b"tx-0", timeout_ms=_SEND_TIMEOUT_MS)
    assert first.get("delivered") is True, f"first channel_send stalled: {first!r}"
    assert first.get("sequence") == 0, (
        f"the first channel_send took transmit sequence {first.get('sequence')}; "
        f"it must take 0 (the transmit counter, untouched by the receive run) — "
        f"a value of 3 proves a shared counter"
    )
    mid = client.channel_window(link_id)
    assert mid["next_sequence"] == 1, (
        f"transmit counter must advance to 1 after one send, got "
        f"{mid['next_sequence']}"
    )
    assert mid["next_rx_sequence"] == 3, (
        f"a transmit wrongly moved the RECEIVE counter ({mid['next_rx_sequence']} "
        f"!= 3) — the two sequence spaces are not independent"
    )

    # Another inbound envelope advances only the receive counter.
    client.channel_inject(link_id, [{"sequence": 3, "data": b"rx-3"}])
    assert client.channel_received(link_id) == [b"rx-3"], (
        "injected receive sequence 3 must deliver"
    )
    after_rx2 = client.channel_window(link_id)
    assert after_rx2["next_rx_sequence"] == 4, (
        f"receive counter must advance to 4, got {after_rx2['next_rx_sequence']}"
    )
    assert after_rx2["next_sequence"] == 1, (
        f"the inbound envelope wrongly moved the transmit counter to "
        f"{after_rx2['next_sequence']} (expected it pinned at 1)"
    )

    # A second transmit continues the transmit counter from 1, not from the
    # receive counter's 4.
    second = client.channel_send(link_id, b"tx-1", timeout_ms=_SEND_TIMEOUT_MS)
    assert second.get("delivered") is True, f"second channel_send stalled: {second!r}"
    assert second.get("sequence") == 1, (
        f"the second channel_send took transmit sequence {second.get('sequence')}, "
        f"expected 1 (continuing the transmit counter, not the receive counter's 4)"
    )
    post = client.channel_window(link_id)
    assert post["next_sequence"] == 2 and post["next_rx_sequence"] == 4, (
        f"final counters tx={post['next_sequence']} rx={post['next_rx_sequence']}, "
        f"expected tx=2 / rx=4 (each advanced only by its own direction)"
    )


# ---------------------------------------------------------------------------
# malformed-envelope-resilience (truncated < 6-byte frame)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies=(
        "RNS Channel survives a TRUNCATED raw frame shorter than the 6-byte "
        "envelope header: Envelope.unpack does struct.unpack('>HHH', raw[:6]) "
        "(Channel.py:178), which raises struct.error for a <6-byte frame; "
        "Channel._receive's outer try/except (Channel.py:425-466) swallows it, so "
        "a 3-byte injected frame delivers NOTHING, does NOT advance "
        "next_rx_sequence, and is NOT buffered (rx_ring stays 0) — and a "
        "subsequent VALID envelope at the still-expected sequence delivers "
        "normally, proving the channel was not stalled or crashed by the "
        "truncated frame"
    ),
)
def test_truncated_envelope_dropped_without_advance(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    pre = client.channel_window(link_id)
    seq0 = pre["next_rx_sequence"]

    # A 3-byte frame: too short for the 6-byte >HHH header. Fed verbatim to the
    # live Channel._receive via the raw-override (the bytes originate here).
    client.channel_inject(link_id, [{"raw": b"\x01\x02\x03", "sequence": seq0}])
    assert client.channel_received(link_id) == [], (
        "a truncated (<6-byte) frame must not deliver anything"
    )
    mid = client.channel_window(link_id)
    assert mid["next_rx_sequence"] == seq0, (
        f"the truncated frame advanced next_rx_sequence ({seq0} -> "
        f"{mid['next_rx_sequence']}); a struct.error in unpack must leave the "
        f"sequence untouched"
    )
    assert mid["rx_ring"] == 0, (
        f"the truncated frame was buffered (rx_ring={mid['rx_ring']}) instead of "
        f"dropped"
    )

    # Positive control: a valid envelope at the still-expected sequence delivers,
    # proving the channel survived the truncated frame.
    payload = b"survived-the-truncation"
    client.channel_inject(link_id, [{"sequence": seq0, "data": payload}])
    assert client.channel_received(link_id) == [payload], (
        "the channel did not deliver a valid envelope after a truncated frame — "
        "the truncated frame stalled or broke the channel"
    )
    post = client.channel_window(link_id)
    assert post["next_rx_sequence"] == (seq0 + 1) % _SEQ_MODULUS, (
        f"the valid envelope did not advance the sequence: {post!r}"
    )


# ---------------------------------------------------------------------------
# channel-shutdown-on-teardown
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "channel_window", "link_status",
    ],
    verifies=(
        "After RNS Channel tears the Link down on retransmission exhaustion "
        "(5 tries), Channel._shutdown clears the message handlers AND both rings "
        "(Channel.py:374-390) and a subsequent send fails cleanly with "
        "ChannelException(ME_LINK_NOT_READY, code 3): a drop_acks send reaches "
        "tries=5 and leaves the link CLOSED; the post-teardown channel reports "
        "rx_ring==0, tx_ring==0 and message_handlers==0 (the recording handler "
        "was cleared); and a normal send on the torn-down channel returns "
        "rejected with ce_type 3 and sent=False (the CLOSED link's outlet "
        "transmits nothing, so the packet has no receipt — the no-receipt branch, "
        "Channel.py:619-626)"
    ),
)
def test_channel_shutdown_state_after_teardown(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    pre = client.channel_window(link_id)
    assert pre["message_handlers"] >= 1, (
        f"precondition: the live channel must carry a recording handler before "
        f"teardown, got message_handlers={pre['message_handlers']}"
    )

    # Drive the 5-try retransmission teardown.
    r = client.channel_send(
        link_id, b"un-acked", drop_acks=True, timeout_ms=_DROP_TIMEOUT_MS
    )
    assert r["sent"] is True and r["delivered"] is False, (
        f"the un-acked send must transmit but never deliver: {r!r}"
    )
    assert r["tries"] == _MAX_TRIES, (
        f"expected exactly {_MAX_TRIES} tries before teardown, got {r['tries']}"
    )
    assert r["link_status"] == _LINK_CLOSED, (
        f"link not torn down after {_MAX_TRIES} tries: status={r['link_status']}"
    )

    # Post-shutdown state: rings drained, handlers cleared.
    post = client.channel_window(link_id)
    assert post["tx_ring"] == 0, (
        f"_shutdown must drain the tx ring, got tx_ring={post['tx_ring']}"
    )
    assert post["rx_ring"] == 0, (
        f"_shutdown must drain the rx ring, got rx_ring={post['rx_ring']}"
    )
    assert post["message_handlers"] == 0, (
        f"_shutdown must clear the message handlers, got "
        f"message_handlers={post['message_handlers']} (Channel.py:374-377)"
    )

    # A send on the torn-down channel fails cleanly via the no-receipt branch.
    dead = client.channel_send(link_id, b"after-teardown", timeout_ms=_SEND_TIMEOUT_MS)
    assert dead.get("sent") is False, (
        f"a send on a torn-down channel must not transmit: {dead!r}"
    )
    assert dead.get("rejected") is True, (
        f"a send on a torn-down channel must be rejected: {dead!r}"
    )
    assert dead.get("ce_type") == _ME_LINK_NOT_READY, (
        f"a send on a torn-down channel must raise ME_LINK_NOT_READY (code "
        f"{_ME_LINK_NOT_READY}); got ce_type={dead.get('ce_type')} "
        f"error={dead.get('error')!r}"
    )

    status = client.link_status(link_id)
    assert status["status"] == _LINK_CLOSED, (
        f"independent link_status confirms CLOSED expected, got "
        f"{status['status_name']} ({status['status']})"
    )


# ---------------------------------------------------------------------------
# packet-timeout-formula
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_timeout_formula",
    ],
    verifies=(
        "RNS Channel._get_packet_timeout_time(tries) == pow(1.5, tries-1) * "
        "max(rtt*2.5, 0.025) * (len(tx_ring)+1.5) (Channel.py:545-547): the value "
        "RNS computes equals an INDEPENDENT re-derivation of that expression "
        "across tries 1..5 (the exponential 1.5^(tries-1) backoff), tx-ring "
        "depths 0 and 4 (the (depth+1.5) scaling), an rtt above the floor "
        "(rtt*2.5 used) and an rtt below it (the 25 ms = 0.025 floor used) — "
        "discriminating each factor of the formula"
    ),
)
def test_packet_timeout_formula(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    def expected(rtt, tries, depth):
        return pow(1.5, tries - 1) * max(rtt * 2.5, 0.025) * (depth + 1.5)

    # rtt above the 0.025 floor: rtt*2.5 dominates. Sweep tries (exponential)
    # and tx-ring depth (linear).
    rtt = 0.5
    for tries in (1, 2, 3, 5):
        for depth in (0, 4):
            r = client.channel_timeout_formula(
                link_id, rtt=rtt, tries=tries, ring_depth=depth
            )
            assert r["ring_depth"] == depth, (
                f"hook did not pad the tx ring to depth {depth}: {r!r}"
            )
            exp = expected(rtt, tries, depth)
            assert math.isclose(r["timeout"], exp, rel_tol=1e-9), (
                f"_get_packet_timeout_time(tries={tries}, depth={depth}, "
                f"rtt={rtt}) = {r['timeout']}, expected {exp} "
                f"(pow(1.5,{tries-1}) * max({rtt}*2.5,0.025) * ({depth}+1.5))"
            )

    # rtt BELOW the floor (0.001*2.5 = 0.0025 < 0.025): the 25 ms floor is used.
    low = client.channel_timeout_formula(link_id, rtt=0.001, tries=1, ring_depth=0)
    exp_floor = expected(0.001, 1, 0)
    assert math.isclose(exp_floor, 0.025 * 1.5, rel_tol=1e-12), "floor self-check"
    assert math.isclose(low["timeout"], exp_floor, rel_tol=1e-9), (
        f"below-floor rtt must use the 0.025 floor: got {low['timeout']}, "
        f"expected {exp_floor}"
    )

    # rtt JUST above the floor boundary (0.02*2.5 = 0.05 > 0.025): rtt*2.5 used,
    # distinguishing it from the floor case above.
    near = client.channel_timeout_formula(link_id, rtt=0.02, tries=1, ring_depth=0)
    exp_near = expected(0.02, 1, 0)
    assert math.isclose(exp_near, 0.05 * 1.5, rel_tol=1e-12), "boundary self-check"
    assert math.isclose(near["timeout"], exp_near, rel_tol=1e-9), (
        f"above-floor rtt must use rtt*2.5: got {near['timeout']}, "
        f"expected {exp_near} (not the floor {exp_floor})"
    )
    assert near["timeout"] > low["timeout"], (
        "an above-floor rtt must yield a strictly larger timeout than the floor"
    )


# ---------------------------------------------------------------------------
# window-initial-values (degenerate profile)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_profile",
    ],
    verifies=(
        "RNS Channel.__init__ selects the window profile from the link RTT "
        "(Channel.py:297-308): rtt > RTT_SLOW (1.45) yields the DEGENERATE all-1 "
        "profile (window/window_min/window_max/window_flexibility all == 1), "
        "while rtt <= RTT_SLOW yields the standard profile (window 2, window_min "
        "2, window_max 5 = WINDOW_MAX_SLOW, window_flexibility 4). Asserted at "
        "rtt 0.5 and at the boundary rtt 1.45 (standard, since the gate is strict "
        "'>') and at rtt 1.46 and 5.0 (degenerate), with the live RNS.Channel."
        "RTT_SLOW cross-checked == the external literal 1.45 — the degenerate "
        "branch loopback RTT can never reach"
    ),
)
def test_window_profile_degenerate_and_standard(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Standard profile at a sub-RTT_SLOW rtt.
    std = client.channel_profile(link_id, rtt=0.5)
    assert std["rtt_slow"] == _RTT_SLOW, (
        f"live RNS.Channel.RTT_SLOW={std['rtt_slow']}, expected {_RTT_SLOW}"
    )
    assert (
        std["window"] == _WINDOW
        and std["window_min"] == _WINDOW_MIN
        and std["window_max"] == _WINDOW_MAX_SLOW
        and std["window_flexibility"] == _WINDOW_FLEXIBILITY
    ), (
        f"rtt 0.5 must select the standard profile "
        f"(2/{_WINDOW_MIN}/{_WINDOW_MAX_SLOW}/{_WINDOW_FLEXIBILITY}), got {std!r}"
    )

    # Boundary: rtt EXACTLY RTT_SLOW is still standard (the gate is strict '>').
    boundary = client.channel_profile(link_id, rtt=_RTT_SLOW)
    assert (
        boundary["window"] == _WINDOW
        and boundary["window_max"] == _WINDOW_MAX_SLOW
    ), (
        f"rtt == RTT_SLOW ({_RTT_SLOW}) must remain standard (gate is '> "
        f"RTT_SLOW'), got {boundary!r}"
    )

    # Degenerate: rtt just past RTT_SLOW collapses the window to all-1.
    for rtt in (1.46, 5.0):
        deg = client.channel_profile(link_id, rtt=rtt)
        assert (
            deg["window"] == 1
            and deg["window_min"] == 1
            and deg["window_max"] == 1
            and deg["window_flexibility"] == 1
        ), (
            f"rtt {rtt} (> RTT_SLOW {_RTT_SLOW}) must select the degenerate "
            f"all-1 profile, got {deg!r}"
        )


# ---------------------------------------------------------------------------
# window-rate-upgrade-medium
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_set_rtt", "channel_send", "channel_window",
    ],
    verifies=(
        "RNS Channel promotes to the MEDIUM-rate window after FAST_RATE_THRESHOLD "
        "(10) delivered rounds with rtt in the medium band (RTT_FAST 0.18 < rtt "
        "<= RTT_MEDIUM 0.75): starting from the slow profile (window_max 5, "
        "window_min 2, medium_rate_rounds 0), with link.rtt spoofed to 0.5, each "
        "delivered channel_send increments medium_rate_rounds by 1, and at "
        "exactly round 10 window_max jumps to WINDOW_MAX_MEDIUM 12 and window_min "
        "to WINDOW_MIN_LIMIT_MEDIUM 5 (Channel._packet_tx_op, Channel.py:511-524) "
        "— while fast_rate_rounds stays 0 throughout (rtt > RTT_FAST forbids the "
        "fast promotion). Before round 10 window_max is still 5"
    ),
)
def test_window_rate_upgrade_medium(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Spoof the link RTT into the medium band BEFORE the channel sends, so every
    # delivered round counts a medium_rate_round. 0.18 < 0.5 <= 0.75.
    assert _RTT_FAST < 0.5 <= _RTT_MEDIUM, "test rtt must sit in the medium band"
    client.link_set_rtt(link_id, 0.5)

    pre = client.channel_window(link_id)
    assert pre["window_max"] == _WINDOW_MAX_SLOW and pre["window_min"] == _WINDOW_MIN, (
        f"precondition: the fresh channel must start on the slow profile "
        f"(window_max {_WINDOW_MAX_SLOW}, window_min {_WINDOW_MIN}), got {pre!r}"
    )
    assert pre["medium_rate_rounds"] == 0, (
        f"precondition: medium_rate_rounds must start at 0, got "
        f"{pre['medium_rate_rounds']}"
    )

    promoted_at = None
    last = pre
    for i in range(1, 16):
        r = client.channel_send(link_id, b"medium", timeout_ms=_SEND_TIMEOUT_MS)
        assert r.get("delivered") is True, (
            f"medium warm-up send {i} did not deliver: {r!r}"
        )
        w = client.channel_window(link_id)
        assert w["fast_rate_rounds"] == 0, (
            f"fast_rate_rounds advanced to {w['fast_rate_rounds']} at send {i}; "
            f"rtt 0.5 > RTT_FAST {_RTT_FAST} must forbid fast promotion"
        )
        if w["window_max"] == _WINDOW_MAX_MEDIUM and promoted_at is None:
            promoted_at = i
            # The promotion fires at exactly FAST_RATE_THRESHOLD medium rounds.
            assert w["medium_rate_rounds"] == _FAST_RATE_THRESHOLD, (
                f"medium promotion fired at medium_rate_rounds="
                f"{w['medium_rate_rounds']}, expected exactly "
                f"{_FAST_RATE_THRESHOLD}"
            )
            assert w["window_min"] == _WINDOW_MIN_MEDIUM, (
                f"medium promotion must raise window_min to {_WINDOW_MIN_MEDIUM}, "
                f"got {w['window_min']}"
            )
            break
        # Before promotion the slow ceiling holds.
        assert w["window_max"] == _WINDOW_MAX_SLOW, (
            f"before the medium promotion window_max must stay "
            f"{_WINDOW_MAX_SLOW}, got {w['window_max']} at send {i}"
        )
        last = w

    assert promoted_at is not None, (
        f"the channel never promoted to the medium window in 15 delivered sends; "
        f"last window state: {last!r}"
    )
    assert promoted_at == _FAST_RATE_THRESHOLD, (
        f"medium promotion must occur on the {_FAST_RATE_THRESHOLD}th delivered "
        f"round (one medium_rate_round per delivery), got round {promoted_at}"
    )


# ---------------------------------------------------------------------------
# handler-dispatch-stops-on-true
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_handler_chain",
    ],
    verifies=(
        "RNS Channel._run_callbacks (Channel.py:415-422) invokes message "
        "handlers in REGISTRATION ORDER, STOPS the chain when one returns True "
        "(later handlers do not fire), and CONTINUES past a handler that RAISES "
        "(the exception is caught and logged). For an ordered chain of recording "
        "handlers on one received envelope: [False,False] fires both -> log "
        "[0,1]; [True,False] fires only handler 0 (the True shadows the later "
        "handler) -> log [0]; [raise,False] fires both (the raiser does not abort "
        "dispatch) -> log [0,1]; and [False,True,False] fires 0 then 1 and stops "
        "at the True (handler 2 never runs) -> log [0,1] — pinning order, "
        "stop-on-True, and exception-continuation in one observable chain"
    ),
)
def test_handler_chain_dispatch(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Propagation on False (control): every handler runs, in order.
    r = client.channel_handler_chain(link_id, ["false", "false"])
    assert r["log"] == [0, 1], (
        f"a chain of False-returning handlers must all fire in order: log={r['log']}"
    )
    assert r["handler_count"] == 2, f"both handlers must register: {r!r}"
    assert r["next_rx_sequence"] == 1, (
        f"the delivered envelope must advance next_rx_sequence to 1 regardless of "
        f"handler returns, got {r['next_rx_sequence']}"
    )

    # Stop on True: handler 0 returns True and SHADOWS the later handler 1.
    r = client.channel_handler_chain(link_id, ["true", "false"])
    assert r["log"] == [0], (
        f"a handler returning True must STOP the chain (handler 1 must not fire): "
        f"log={r['log']}"
    )

    # Exception continuation: handler 0 raises, handler 1 still fires.
    r = client.channel_handler_chain(link_id, ["raise", "false"])
    assert r["log"] == [0, 1], (
        f"a handler that RAISES must not abort dispatch — the next handler must "
        f"still fire: log={r['log']}"
    )

    # Order + stop combined: stops at the True at index 1; index 2 never runs.
    r = client.channel_handler_chain(link_id, ["false", "true", "false"])
    assert r["log"] == [0, 1], (
        f"dispatch must run 0 then 1 (in order) and STOP at the True (index 2 "
        f"must not fire): log={r['log']}"
    )


# ---------------------------------------------------------------------------
# spurious-proof-ignored
# ---------------------------------------------------------------------------
@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_spurious_proof",
    ],
    verifies=(
        "RNS Channel ignores a spurious/late proof and a stale timeout "
        "(Channel._packet_tx_op / _packet_timeout, Channel.py:490-568): after a "
        "genuine delivered send (which grows the window and removes the envelope "
        "from the tx ring), re-firing the delivered packet's proof callback hits "
        "the no-matching-envelope 'Spurious message received' branch and must NOT "
        "grow the window; re-firing its timeout callback (the MSGSTATE_DELIVERED "
        "guard) and firing a timeout/proof for a never-tracked packet (the "
        "envelope-is-None early return) must NOT tear the link down and must NOT "
        "raise. The window is identical before and after every spurious callback, "
        "the link stays open, and no exception is raised — a wrong impl that grew "
        "the window or crashed on a late/duplicate proof would fail here"
    ),
)
def test_spurious_proof_and_stale_timeout_ignored(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    r = client.channel_spurious_proof(link_id, timeout_ms=_SEND_TIMEOUT_MS)

    assert r["delivered"] is True, (
        f"precondition: the genuine send must deliver before the spurious "
        f"callbacks are fired: {r!r}"
    )
    assert r["tx_ring_before"] == 0, (
        f"precondition: the delivered envelope must have been removed from the tx "
        f"ring, got tx_ring_before={r['tx_ring_before']}"
    )
    assert r["errors"] == [], (
        f"no spurious/stale callback may raise — RNS must swallow them: "
        f"errors={r['errors']!r}"
    )
    assert r["window_after_duplicate"] == r["window_before"], (
        f"a DUPLICATE/late proof grew the window ({r['window_before']} -> "
        f"{r['window_after_duplicate']}); the spurious branch must not grow it"
    )
    assert r["window_final"] == r["window_before"], (
        f"a spurious/stale callback moved the window ({r['window_before']} -> "
        f"{r['window_final']}); none may"
    )
    assert r["link_closed"] is False, (
        f"a late timeout / spurious proof must NOT tear the link down: "
        f"link_status={r['link_status']}"
    )
