"""RNS Channel TX flow-control conformance (send-side window + retransmission).

`RNS.Channel` (obtained from an established Link via `link.get_channel()`) runs
a sliding-window reliable-send protocol on top of the Link. Every sent message
is wrapped in an `Envelope`, transmitted as a `CHANNEL`-context Link packet with
a `PacketReceipt`, and held in the TX ring until the peer's PROOF validates the
receipt. The flow-control window adapts to delivery success/failure:

  * GROWTH (`Channel._packet_tx_op`, Channel.py:504-505): each delivered
    envelope grows `window` by 1, capped at `window_max`.
  * SHRINK + RETRANSMIT + TEARDOWN (`Channel._packet_timeout`,
    Channel.py:555-584): if a receipt times out, the envelope is resent with an
    exponentially increasing timeout (`_get_packet_timeout_time`, pow(1.5,
    tries-1)*...) and the window shrinks by 1 (floored at `window_min`; and
    `window_max` shrinks too, but ONLY while `window_max > window_min +
    window_flexibility`). After `_max_tries` (5) unanswered tries the Channel
    tears the whole Link down (`_outlet.timed_out()` -> `link.teardown`).
  * RESERVED MSGTYPE (`Channel._register_message_type`, Channel.py:336-338):
    registering a message class whose `MSGTYPE >= 0xf000` (the system-reserved
    band) raises `ChannelException` rather than being accepted.

The audit (CONFORMANCE_GAPS.md §4b "Channel TX retransmission backoff + 5-try
teardown" and "Channel window growth/shrink (numeric)") flagged these as
confirmed-/partially-untested: the prior suite only injected RX envelopes
(`test_channel.py`) and could not drive a real ack'd/un-ack'd send. The dead
`cmd_rns_channel_send` had zero callers and could not drop acks. These tests
drive the real `RNS.Channel.send` through the wire harness `channel_send`
command over an established Link:

  * `channel_send(link_id, data)` performs a real send and waits for the peer's
    PROOF to DELIVER it — exercising the GROWTH path. `channel_window` reads the
    live `window`/`window_max` straight off the `RNS.Channel`.
  * `channel_send(link_id, data, drop_acks=True)` neuters THIS message's receipt
    so the returning PROOF can never validate it (race-free: applied inside the
    outlet send before any proof round-trips, and re-applied to every resend).
    RNS then retransmits with growing backoff and, after 5 tries, tears the link
    down — making the SHRINK + 5-try-teardown path observable via the returned
    `{tries, link_status}` and the post-teardown `channel_window`.
  * `channel_send(link_id, data, msgtype=0xf000)` asks the channel to register a
    reserved MSGTYPE and surfaces the resulting `ChannelException` as
    `{rejected: True}`.

Both Link peers are reference implementations under `--reference-only` (the
listener PROVEs inbound CHANNEL packets, so a non-dropped send genuinely
delivers), so every assertion holds reference-vs-reference; no SUT binary is
required. The RX-side reorder/dedup/wraparound/stale-drop behaviours live in the
sibling `test_channel.py`.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("channel",)
_LINK_TIMEOUT_MS = 15000
_PATH_TIMEOUT_MS = 10000

# How long a single delivered send may take to round-trip its proof on loopback.
_SEND_TIMEOUT_MS = 12000
# A dropped-ack send must out-last the full 5-try backoff (~0.8s on loopback)
# before the link tears down; give it generous headroom.
_DROP_TIMEOUT_MS = 20000

# RNS.Link.CLOSED (Link.py:114) — the status a link reports once torn down.
_LINK_CLOSED = 0x04

# Channel window constants (Channel.py:242-276), pinned here to keep the test
# process free of an RNS import, mirroring how test_channel pins the sequence
# constants.
_WINDOW = 2            # Channel.WINDOW (initial window on a non-degenerate link)
_WINDOW_MAX_SLOW = 5   # Channel.WINDOW_MAX_SLOW
_WINDOW_MIN = 2        # Channel.WINDOW_MIN
_WINDOW_MAX_FAST = 48  # Channel.WINDOW_MAX_FAST
_WINDOW_MIN_FAST = 16  # Channel.WINDOW_MIN_LIMIT_FAST
_MAX_TRIES = 5         # Channel._max_tries


def _poll_window(client, link_id, field, expected, *, timeout_s=8.0):
    """Poll `channel_window` until `field` reaches `expected` (or timeout).

    Window growth fires in the receipt's delivery callback, which on loopback
    completes microseconds after the harness observes DELIVERED — a brief poll
    removes that race without a fixed sleep. Returns the last observed value.
    """
    import time

    deadline = time.time() + timeout_s
    val = None
    while time.time() < deadline:
        val = client.channel_window(link_id)[field]
        if val == expected:
            return val
        time.sleep(0.02)
    return val


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "channel_window",
    ],
    verifies=(
        "RNS Channel grows its send window by exactly 1 per delivered (proof-"
        "ack'd) message and caps it at window_max: on a fresh channel "
        "(window=2, window_max=5 on the loopback slow-RTT profile) four "
        "successive delivered channel_send calls drive window through 3, 4, 5, "
        "5 — i.e. +1 per ack until it saturates window_max=5 and holds there — "
        "while window_max itself stays 5 (no fast-rate promotion within 4 "
        "rounds), exercising Channel._packet_tx_op (Channel.py:504-505)"
    ),
)
def test_channel_window_grows_on_ack_up_to_max(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP,
        aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS,
        path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    pre = client.channel_window(link_id)
    assert pre["window"] == _WINDOW, (
        f"precondition: fresh channel window={pre['window']}, expected "
        f"{_WINDOW} (Channel.WINDOW on a non-degenerate loopback link)"
    )
    assert pre["window_max"] == _WINDOW_MAX_SLOW, (
        f"precondition: window_max={pre['window_max']}, expected "
        f"{_WINDOW_MAX_SLOW} (Channel.WINDOW_MAX_SLOW)"
    )

    # window: 2 -> 3 -> 4 -> 5 (cap at window_max) -> 5 (held at cap).
    expected_windows = [3, 4, 5, 5]
    for i, want in enumerate(expected_windows, start=1):
        r = client.channel_send(
            link_id, f"grow-{i}".encode(), timeout_ms=_SEND_TIMEOUT_MS
        )
        assert r.get("sent") is True and r.get("delivered") is True, (
            f"send {i} did not deliver (window growth requires a real ack): {r!r}"
        )
        got = _poll_window(client, link_id, "window", want)
        assert got == want, (
            f"after {i} delivered send(s) window={got}, expected {want} "
            f"(+1 per ack, capped at window_max={_WINDOW_MAX_SLOW})"
        )
        # window_max must not change over these few rounds (fast-rate promotion
        # needs 10 sustained rounds), proving the growth was the window, not the
        # ceiling.
        wmax = client.channel_window(link_id)["window_max"]
        assert wmax == _WINDOW_MAX_SLOW, (
            f"window_max moved to {wmax} after {i} sends; expected it pinned at "
            f"{_WINDOW_MAX_SLOW} (no fast-rate promotion in <10 rounds)"
        )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "channel_window", "link_status",
    ],
    verifies=(
        "RNS Channel retransmits an un-ack'd send up to _max_tries=5 times then "
        "tears the Link down, shrinking the window on the way: after growing "
        "window to 5 via 3 delivered sends, a send whose receipt is suppressed "
        "(drop_acks) never delivers, reaches exactly tries=5, leaves the link "
        "CLOSED (status 0x04) and shrinks window 5->2 (floored at window_min=2) "
        "while window_max stays 5 (the slow-profile flexibility guard "
        "window_max>window_min+window_flexibility=6 is not met) — exercising "
        "Channel._packet_timeout teardown + window shrink (Channel.py:555-584)"
    ),
)
def test_channel_retransmission_teardown_and_window_shrink(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP,
        aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS,
        path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Warm the window above window_min so the loss-driven shrink is observable
    # (the shrink branch is gated on window > window_min; a fresh window==2 ==
    # window_min would never shrink, so without this the shrink is unprovable).
    for i in range(3):
        r = client.channel_send(
            link_id, f"warm-{i}".encode(), timeout_ms=_SEND_TIMEOUT_MS
        )
        assert r.get("delivered") is True, f"warm-up send {i} did not deliver: {r!r}"
    pre_window = _poll_window(client, link_id, "window", _WINDOW_MAX_SLOW)
    assert pre_window == _WINDOW_MAX_SLOW, (
        f"warm-up should grow window to window_max={_WINDOW_MAX_SLOW}, got {pre_window}"
    )
    pre = client.channel_window(link_id)
    assert pre["window_max"] == _WINDOW_MAX_SLOW, (
        f"precondition window_max={pre['window_max']}, expected {_WINDOW_MAX_SLOW}"
    )

    # Suppress the peer's ack of THIS send: the receipt can never validate, so
    # RNS retransmits with growing backoff and tears the link down after 5 tries.
    r = client.channel_send(
        link_id, b"un-acked", drop_acks=True, timeout_ms=_DROP_TIMEOUT_MS
    )
    assert r["sent"] is True, f"the un-acked send must still transmit: {r!r}"
    assert r["delivered"] is False, (
        f"a send whose ack is dropped must never DELIVER, got delivered={r['delivered']}"
    )
    assert r["tries"] == _MAX_TRIES, (
        f"expected exactly _max_tries={_MAX_TRIES} transmissions before teardown, "
        f"got tries={r['tries']}"
    )
    assert r["link_status"] == _LINK_CLOSED, (
        f"link not torn down after {_MAX_TRIES} unanswered tries: "
        f"status={r['link_status']}, expected CLOSED ({_LINK_CLOSED})"
    )

    # The window shrank one step per retransmit timeout (5->4->3->2), floored at
    # window_min=2; window_max held at 5 because the slow-profile flexibility
    # guard (window_max > window_min + window_flexibility, i.e. 5 > 6) is false.
    post = client.channel_window(link_id)
    assert post["window"] == _WINDOW_MIN, (
        f"window did not shrink to window_min={_WINDOW_MIN} under repeated loss, "
        f"got {post['window']} (started at {pre_window})"
    )
    assert post["window_max"] == _WINDOW_MAX_SLOW, (
        f"window_max changed to {post['window_max']}; on the slow profile it must "
        f"stay {_WINDOW_MAX_SLOW} (flexibility guard 5 !> window_min+flex=6)"
    )

    # Independent confirmation the teardown is real (not just the send's snapshot).
    status = client.link_status(link_id)
    assert status["status"] == _LINK_CLOSED, (
        f"link_status reports {status['status_name']} ({status['status']}); "
        f"expected CLOSED after channel retransmission exhaustion"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send", "channel_window", "link_status",
    ],
    verifies=(
        "RNS Channel shrinks window_max (not just window) under loss once the "
        "fast-rate profile is reached: after enough delivered sends to promote "
        "the channel to the fast profile (window_max=48, window_min=16) and grow "
        "window above window_min, a drop_acks send reaches tries=5 and tears the "
        "link down (status CLOSED), and the post-teardown window_max is strictly "
        "less than before AND window is strictly less than before — the "
        "window_max-- branch (Channel.py:577) fires because window_max(48) > "
        "window_min(16)+window_flexibility(4)=20, unlike the slow profile"
    ),
)
def test_channel_window_max_shrinks_on_fast_profile(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP,
        aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS,
        path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Drive delivered sends until BOTH conditions for a window_max shrink hold:
    #   (a) the fast-rate profile is active (window_max==48, window_min==16),
    #       which RNS promotes after FAST_RATE_THRESHOLD=10 sustained low-RTT
    #       delivery rounds; and
    #   (b) window has grown strictly above window_min (the shrink branch, and
    #       the window_max-- nested inside it, only run while window>window_min).
    # Loopback RTT (~1ms) is far below RTT_FAST=0.18s, so the promotion is
    # deterministic; the bound is generous headroom over the ~22 sends observed.
    max_sends = 60
    reached = False
    for i in range(max_sends):
        r = client.channel_send(link_id, b"warm", timeout_ms=_SEND_TIMEOUT_MS)
        assert r.get("delivered") is True, f"fast-profile warm-up send {i} stalled: {r!r}"
        w = client.channel_window(link_id)
        if w["window_max"] == _WINDOW_MAX_FAST and w["window"] > w["window_min"]:
            reached = True
            break
    assert reached, (
        f"never reached the fast-rate profile with window>window_min in "
        f"{max_sends} delivered sends — loopback RTT should promote within ~22"
    )

    pre = client.channel_window(link_id)
    assert pre["window_max"] == _WINDOW_MAX_FAST and pre["window_min"] == _WINDOW_MIN_FAST, (
        f"precondition: expected fast profile (window_max={_WINDOW_MAX_FAST}, "
        f"window_min={_WINDOW_MIN_FAST}), got {pre!r}"
    )
    assert pre["window"] > pre["window_min"], (
        f"precondition: window ({pre['window']}) must exceed window_min "
        f"({pre['window_min']}) for the shrink branch to run"
    )
    pre_window = pre["window"]
    pre_window_max = pre["window_max"]

    # Now lose the acks: each retransmit timeout shrinks window by 1 AND, on the
    # fast profile (window_max 48 > window_min+flex 20), window_max by 1 too.
    r = client.channel_send(
        link_id, b"un-acked", drop_acks=True, timeout_ms=_DROP_TIMEOUT_MS
    )
    assert r["delivered"] is False, f"dropped-ack send must not deliver: {r!r}"
    assert r["tries"] == _MAX_TRIES, f"expected tries={_MAX_TRIES}, got {r['tries']}"
    assert r["link_status"] == _LINK_CLOSED, (
        f"link not torn down: status={r['link_status']}"
    )

    post = client.channel_window(link_id)
    assert post["window"] < pre_window, (
        f"window did not shrink under loss on the fast profile: "
        f"{pre_window} -> {post['window']}"
    )
    assert post["window_max"] < pre_window_max, (
        f"window_max did not shrink under loss on the fast profile (the "
        f"window_max-- branch at Channel.py:577 should fire because 48>20): "
        f"{pre_window_max} -> {post['window_max']}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_send",
    ],
    verifies=(
        "RNS Channel rejects registration of a system-reserved message type "
        "(MSGTYPE >= 0xf000): channel_send with msgtype=0xf000 and msgtype=0xffff "
        "each returns rejected=True / sent=False with a 'system-reserved' "
        "ChannelException (Channel.py:336-338), while the positive control — a "
        "normal non-reserved send — is accepted and DELIVERS, proving the "
        "rejection is specific to the reserved band and not a dead channel"
    ),
)
def test_channel_reserved_msgtype_rejected(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP,
        aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS,
        path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Positive control: a normal (non-reserved) channel send is accepted and
    # delivers — so a rejection below is specifically the reserved-band guard.
    ok = client.channel_send(link_id, b"normal", timeout_ms=_SEND_TIMEOUT_MS)
    assert ok.get("rejected") is not True, (
        f"a non-reserved channel send must not be rejected: {ok!r}"
    )
    assert ok.get("sent") is True and ok.get("delivered") is True, (
        f"positive-control send did not deliver: {ok!r}"
    )

    # 0xf000 is the bottom of the reserved band; 0xffff the top. Both rejected.
    for mt in (0xF000, 0xFFFF):
        r = client.channel_send(
            link_id, b"reserved", msgtype=mt, timeout_ms=_SEND_TIMEOUT_MS
        )
        assert r.get("rejected") is True, (
            f"msgtype {hex(mt)} (>= 0xf000) must be rejected at registration: {r!r}"
        )
        assert r.get("sent") is False, (
            f"a rejected reserved msgtype {hex(mt)} must not be sent: {r!r}"
        )
        err = (r.get("error") or "").lower()
        assert "reserved" in err, (
            f"msgtype {hex(mt)} rejection should cite the system-reserved type, "
            f"got error={r.get('error')!r}"
        )
