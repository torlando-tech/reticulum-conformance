"""RNS Link lifecycle conformance: keepalive, ACTIVE→STALE→CLOSED watchdog,
teardown reasons, proof strategy, and request-handler default-deny.

The honesty-rework deleted ``tests/test_link.py`` (−297 lines), dropping all
Link byte/behaviour pinning with no live replacement. CONFORMANCE_REAUDIT.md
§5 lists these as CORE/important capabilities untested *anywhere* vs RNS
1.3.1:

  * keepalive bytes + the ACTIVE→STALE→CLOSED watchdog + TIMEOUT teardown
    (Link.py:99/746/699/769);
  * proof strategies PROVE_ALL/PROVE_APP/PROVE_NONE (the bridge command
    ``rns_set_proof_strategy`` was registered but exercised by zero tests —
    now wired through ``wire_set_proof_strategy``); and
  * request-handler default-deny (Destination.py:74/370).

Everything here drives REAL ``RNS.Link`` objects over a loopback TCP pair via
the wire bridge and reads back the live lifecycle fields RNS computes — no
reimplementation. Every test passes reference-vs-reference (the reference
bridge plays both peers).

Lifecycle reality, validated against RNS 1.3.1 and encoded in the assertions:

  * Keepalives are emitted by the *initiator* only (Link.__watchdog_job:
    ``if self.initiator and now >= self.last_keepalive + self.keepalive``).
    While the peer answers them, ``last_inbound`` is refreshed every watchdog
    pass and the link stays ACTIVE.
  * A graceful ``Link.teardown()`` (or clean peer disconnect) closes the link
    *immediately* with INITIATOR_CLOSED / DESTINATION_CLOSED — independent of
    the keepalive/stale timings.
  * TIMEOUT only fires when inbound genuinely *ceases* (a stalled, not cleanly
    closed, peer): the watchdog drives ACTIVE→STALE→CLOSED with
    teardown_reason=TIMEOUT. We reproduce that by SIGKILLing the peer process
    so its TCP socket drops without a teardown packet ever being sent.
"""

import secrets
import time

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["link-lifecycle"]
_PATH = "/echo"
_LINK_TIMEOUT_MS = 15000
_PATH_POLL_TIMEOUT_MS = 10000
_REQUEST_TIMEOUT_MS = 15000

# RNS.Link constants pinned as known-answers (RNS 1.3.1). The wire harness
# deliberately does not import RNS (the bridge is the only RNS-aware
# component), so the expected values are pinned here rather than read from a
# live import.
_STALE_FACTOR = 2  # RNS.Link.STALE_FACTOR — stale_time == keepalive * 2

# RNS.Destination proof-strategy constants (RNS 1.3.1).
_PROVE_ALL = 35   # RNS.Destination.PROVE_ALL
_PROVE_APP = 34   # RNS.Destination.PROVE_APP
_PROVE_NONE = 33  # RNS.Destination.PROVE_NONE


def _bring_up_link(server, client):
    """Wire the pair together and open a link from client to server's
    listening destination. Returns (server_dest, link_id).
    """
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )
    server_dest = server.listen(app_name=_APP, aspects=_ASPECTS)
    assert client.poll_path(server_dest, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — lifecycle tests need the link first."
    )
    link_id = client.link_open(
        server_dest, app_name=_APP, aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    return server_dest, link_id


def _await_listener_close(server, server_dest, timeout_ms=8000):
    """Poll the receiver-side inbound link until it reports CLOSED, returning
    the final snapshot. Link close propagates to the peer asynchronously (the
    teardown packet has to arrive), so a single read can race ahead of it.
    """
    deadline = time.time() + timeout_ms / 1000.0
    snap = server.listener_link_status(server_dest, timeout_ms=timeout_ms)
    while time.time() < deadline:
        if snap.get("found") and snap.get("status_name") == "CLOSED":
            return snap
        time.sleep(0.1)
        snap = server.listener_link_status(server_dest, timeout_ms=0)
    return snap


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_status",
    ],
    verifies="A freshly-established RNS Link is ACTIVE and carries the watchdog timings RNS negotiated: keepalive_s > 0, stale_time_s == keepalive_s * STALE_FACTOR (2 in RNS 1.3.1), and a measured RTT >= 0",
)
def test_active_link_reports_negotiated_watchdog_timings(wire_peers):
    server, client = wire_peers
    _server_dest, link_id = _bring_up_link(server, client)

    snap = client.link_status(link_id)
    assert snap["status_name"] == "ACTIVE", (
        f"link did not reach ACTIVE after link_open: {snap!r}"
    )
    keepalive = snap["keepalive_s"]
    stale = snap["stale_time_s"]
    assert keepalive is not None and keepalive > 0, (
        f"ACTIVE link reported a non-positive keepalive_s={keepalive!r}"
    )
    # RNS derives stale_time as keepalive * STALE_FACTOR (Link.__init__).
    assert stale == keepalive * _STALE_FACTOR, (
        f"stale_time_s ({stale!r}) is not keepalive_s ({keepalive!r}) * "
        f"STALE_FACTOR ({_STALE_FACTOR}); RNS 1.3.1 pins this relationship "
        f"(Link.STALE_FACTOR=2)."
    )
    assert isinstance(snap["rtt"], (int, float)) and snap["rtt"] >= 0, (
        f"ACTIVE link reported no measured RTT: rtt={snap['rtt']!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_status",
    ],
    verifies="The initiator's watchdog emits a keepalive once per keepalive interval and the peer answers it: after one keepalive period the link is still ACTIVE, last_keepalive_ago_ms is set (a keepalive was sent), and inbound was refreshed within stale_time (the peer's keepalive response kept the link alive)",
)
def test_initiator_keepalive_holds_active_link(wire_peers):
    server, client = wire_peers
    _server_dest, link_id = _bring_up_link(server, client)

    initial = client.link_status(link_id)
    keepalive_s = initial["keepalive_s"]
    stale_s = initial["stale_time_s"]
    assert keepalive_s and stale_s, f"missing watchdog timings: {initial!r}"

    # Wait through one full keepalive interval plus headroom so the watchdog
    # has fired at least one keepalive and seen the peer's response.
    time.sleep(keepalive_s + 3.0)

    snap = client.link_status(link_id)
    assert snap["status_name"] == "ACTIVE", (
        f"link left ACTIVE while the peer was alive and answering "
        f"keepalives: {snap!r}"
    )
    assert snap["last_keepalive_ago_ms"] is not None, (
        f"initiator never emitted a keepalive within {keepalive_s + 3.0}s "
        f"(last_keepalive_ago_ms is None): {snap!r}. The watchdog keepalive "
        f"path (0xFF/0xFE) is not running."
    )
    # The peer answered the keepalive, so inbound stayed fresh — well inside
    # stale_time. If inbound had genuinely ceased the link would be heading
    # to STALE instead.
    assert snap["no_inbound_for_ms"] is not None, (
        f"no inbound observed on an ACTIVE link: {snap!r}"
    )
    assert snap["no_inbound_for_ms"] < stale_s * 1000, (
        f"inbound idle ({snap['no_inbound_for_ms']}ms) exceeded stale_time "
        f"({stale_s * 1000}ms) on a link whose peer is alive — the peer is "
        f"not answering keepalives: {snap!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_teardown", "link_status", "listener_link_status",
    ],
    verifies="A graceful Link.teardown() by the initiator closes the link on both endpoints with teardown_reason INITIATOR_CLOSED: the initiator's link is immediately CLOSED, and the receiver-side inbound link transitions to CLOSED/INITIATOR_CLOSED once the teardown packet arrives",
)
def test_initiator_teardown_closes_both_endpoints(wire_peers):
    server, client = wire_peers
    server_dest, link_id = _bring_up_link(server, client)

    # Make sure the receiver has actually accepted the inbound link before we
    # tear down, so the observation below isn't racing establishment.
    pre = server.listener_link_status(server_dest, timeout_ms=5000)
    assert pre.get("found") and pre.get("link_count", 0) >= 1, (
        f"receiver never accepted the inbound link before teardown: {pre!r}"
    )

    client.link_teardown(link_id)

    initiator = client.link_status(link_id)
    assert initiator["status_name"] == "CLOSED", (
        f"initiator link did not close after teardown: {initiator!r}"
    )
    assert initiator["teardown_reason_name"] == "INITIATOR_CLOSED", (
        f"initiator teardown_reason should be INITIATOR_CLOSED, got "
        f"{initiator['teardown_reason_name']!r}: {initiator!r}"
    )

    listener = _await_listener_close(server, server_dest)
    assert listener.get("status_name") == "CLOSED", (
        f"receiver-side link never observed the initiator's teardown: "
        f"{listener!r}"
    )
    assert listener.get("teardown_reason_name") == "INITIATOR_CLOSED", (
        f"receiver-side teardown_reason should be INITIATOR_CLOSED (the "
        f"initiator closed it), got {listener.get('teardown_reason_name')!r}: "
        f"{listener!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_set_watchdog", "link_await_status",
    ],
    verifies="A stalled peer (its process killed, so its TCP drops with no teardown packet) drives the initiator's link through the watchdog ACTIVE→STALE→CLOSED path: link_await_status reaches CLOSED with teardown_reason TIMEOUT (distinct from a clean disconnect's DESTINATION_CLOSED)",
)
def test_silent_peer_times_out_active_link(wire_peers):
    server, client = wire_peers
    _server_dest, link_id = _bring_up_link(server, client)

    # Compress the watchdog window so STALE→CLOSED is reachable inside the
    # test budget once inbound ceases.
    client.link_set_watchdog(link_id, keepalive_s=1.0, stale_time_s=3.0)

    # Kill the peer process abruptly (SIGKILL) so no graceful teardown packet
    # is ever sent — the only way to produce a genuine TIMEOUT rather than a
    # clean DESTINATION_CLOSED. (Reaching into the BridgeClient subprocess is
    # the only way to simulate a stalled peer; the wire command surface has
    # no "go silent" verb by design.)
    #
    # bridge.kill() reaps the bridge's whole process GROUP, not just
    # bridge._proc. BridgeClient launches string commands via the shell
    # (shell=True); on platforms/loads where the shell does not exec-replace
    # itself with the Python RNS process, bridge._proc is the shell, and
    # SIGKILLing only it would orphan a still-living RNS process that keeps
    # answering this link's keepalives — so the link's no_inbound never climbs
    # and it never reaches the STALE->CLOSED/TIMEOUT path this test asserts
    # (observed as a flaky failure under xdist on slower runners).
    server.bridge.kill()
    # Prevent the fixture finalizer from issuing wire_stop to the dead process.
    server.handle = None

    result = client.link_await_status(link_id, "CLOSED", timeout_ms=30000)
    assert result["reached"] and result["status_name"] == "CLOSED", (
        f"initiator link did not reach CLOSED after the peer went silent: "
        f"{result!r}"
    )
    assert result["teardown_reason_name"] == "TIMEOUT", (
        f"a silent (stalled) peer must close the link with teardown_reason "
        f"TIMEOUT via the ACTIVE→STALE→CLOSED watchdog, got "
        f"{result['teardown_reason_name']!r}: {result!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_await_status",
    ],
    verifies="Positive control distinguishing a clean close from a timeout: when the peer shuts down gracefully (its Reticulum exit handler sends a link teardown), the initiator's link closes with teardown_reason DESTINATION_CLOSED — NOT TIMEOUT",
)
def test_clean_peer_disconnect_closes_destination_closed(wire_peers, wire_pair):
    server_impl, client_impl = wire_pair
    server, client = wire_peers
    _server_dest, link_id = _bring_up_link(server, client)

    # A peer that broadcasts a graceful link teardown on shutdown (the
    # reference's Reticulum exit handler) closes the initiator IMMEDIATELY with
    # DESTINATION_CLOSED, independent of the watchdog. A peer that does NOT
    # (reticulum-kt clears interfaces without tearing links down — see the
    # xfail below) leaves the initiator to discover the close only via the
    # watchdog ACTIVE→STALE→CLOSED/TIMEOUT path. At RNS's default loopback
    # timings that path takes stale_time (keepalive * STALE_FACTOR == 10s) +
    # one watchdog poll (~12.9s measured here), right against this test's
    # budget — and the clock (last_inbound) RESTARTS every time the still-
    # shutting-down peer answers one more keepalive during the close handshake.
    # Under xdist CPU contention the watchdog sleeps overshoot / a late
    # keepalive resets the clock and CLOSED slips past the deadline, leaving the
    # link ACTIVE (observed as a flaky failure under load on slower runners).
    # Compress the window on the timeout-only leg so TIMEOUT lands well inside
    # the budget. The reference leg closes via the teardown packet and never
    # reaches the watchdog, so it is deliberately left at default timings:
    # compressing it would risk a STALE/TIMEOUT racing ahead of a load-delayed
    # teardown and masking the DESTINATION_CLOSED this positive control asserts.
    peer_closes_via_watchdog = server_impl == "kotlin"
    if peer_closes_via_watchdog:
        client.link_set_watchdog(link_id, keepalive_s=1.0, stale_time_s=3.0)

    # Graceful peer shutdown: closing the bridge subprocess's stdin runs its
    # Reticulum exit handler, which sends a link teardown packet before the
    # TCP socket drops — so the initiator learns the destination closed
    # deliberately (DESTINATION_CLOSED), as opposed to a stalled peer
    # (TIMEOUT). (wire_stop alone only frees bookkeeping; the RNS singleton
    # stays up, so a real process exit is required to model a clean close.)
    server.bridge.close()
    server.handle = None  # keep the fixture finalizer from poking a dead proc

    # 30s budget (vs the compressed ~3s STALE window / ~13s default path) gives
    # generous slack on a contended runner. link_await_status returns as soon as
    # CLOSED is reached, so the wider budget never slows the passing case.
    result = client.link_await_status(link_id, "CLOSED", timeout_ms=30000)
    assert result["reached"] and result["status_name"] == "CLOSED", (
        f"initiator link did not close after the peer shut down cleanly: "
        f"{result!r}"
    )
    if server_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#graceful-shutdown-link-teardown: on graceful "
            "shutdown kotlin never broadcasts LINKCLOSE; Reticulum.shutdown() "
            "clears interfaces without tearing down active/pending links (cf. "
            "Transport.detach_interfaces, Transport.py:3076-3088), so the "
            "initiator closes via watchdog TIMEOUT instead of "
            "DESTINATION_CLOSED."
        )
    assert result["teardown_reason_name"] == "DESTINATION_CLOSED", (
        f"a clean peer shutdown must close the link with DESTINATION_CLOSED, "
        f"got {result['teardown_reason_name']!r}: {result!r}. (TIMEOUT here "
        f"would mean the teardown packet was lost and the watchdog had to "
        f"time the link out instead.)"
    )


@conformance_case(
    commands=["start_tcp_server", "listen", "set_proof_strategy"],
    verifies="Destination.set_proof_strategy stores the requested packet-proof strategy on the real destination: 'all'/'app'/'none' read back as RNS.Destination.PROVE_ALL (35) / PROVE_APP (34) / PROVE_NONE (33) respectively, and the three are distinct",
)
def test_proof_strategy_sets_destination_constant(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")
    dest = server.listen(app_name=_APP, aspects=_ASPECTS)

    expected = {"all": _PROVE_ALL, "app": _PROVE_APP, "none": _PROVE_NONE}
    observed = {}
    for name, want in expected.items():
        resp = server.set_proof_strategy(dest, name)
        observed[name] = resp["proof_strategy"]
        assert resp["proof_strategy"] == want, (
            f"set_proof_strategy({name!r}) read back proof_strategy="
            f"{resp['proof_strategy']!r} off the real destination, expected "
            f"{want} (RNS.Destination.PROVE_{name.upper()})."
        )
    assert len(set(observed.values())) == 3, (
        f"the three proof strategies must map to distinct constants, got "
        f"{observed!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "link_request",
        "get_request_log",
    ],
    verifies="Request-handler default-deny: an ALLOW_LIST handler with no admissible identity (the requester never called Link.identify, so remote_identity is None and matches no entry) denies the request before the generator runs — the request times out / fails AND the invocation log stays empty. A handler that runs regardless bypasses propagation-node auth.",
)
def test_unidentified_requester_denied_by_allow_list(wire_peers):
    server, client = wire_peers
    server_dest, link_id = _bring_up_link(server, client)

    # ALLOW_LIST with an empty allowed list: nothing is admissible. This is
    # the closest default-deny posture the harness exposes (it cannot register
    # a handler with allow=ALLOW_NONE directly — see this module's notes /
    # the run's unresolved list).
    server.register_request_handler(
        server_dest, _PATH, secrets.token_bytes(32),
        allow="list", allowed_identity_hashes=[],
    )

    # Deliberately do NOT call client.link_identify(...): remote_identity is
    # None, so RNS's handle_request gate rejects before the generator runs.
    result = client.link_request(
        link_id, _PATH, data=b"", timeout_ms=5000,
    )
    assert result["status"] in ("failed", "timeout"), (
        f"an un-identified requester against a deny-all ALLOW_LIST handler "
        f"completed READY — the destination served an unauthorised request. "
        f"status={result['status']!r}, response={result['response']!r}"
    )
    entries = server.get_request_log(server_dest, _PATH)
    assert len(entries) == 0, (
        f"handler ran ({len(entries)} invocations) for a requester that was "
        f"never admitted — RNS did not enforce the deny before dispatching "
        f"to the generator. entries={entries!r}"
    )
