"""Path discovery conformance: path request, path response, mode-gated
discovery forwarding, ROAMING loop prevention, and mode-specific path
expiry assignment.

Tests here pin concrete, externally-observable guarantees that the
path layer makes. They're deliberately 2-peer or 3-peer where the
observable is tight enough to distinguish "rule fired" from "rule did
not fire" without any timing slop.

References (line numbers against installed Python RNS 1.3.1 Transport.py):
  - request_path:                    2769
  - path_request_handler:            2864
  - path_request:                    2909
  - cached-announce re-emission:     2949-3013 (announce_table set at 3000)
  - ROAMING loop-prevention drop:    2949 (cached received_from read at 2944)
  - DISCOVER_PATHS_FOR gating:       2916 (Interface.py:54)
  - per-mode expiry assignment:      1874-1878 (timestamp `now` stamped once at
                                     1832; entry stored at 2011 with the SAME
                                     `now`, so expires - timestamp is exact)
  - path expiry constants:           71-73 (PATHFINDER_E / AP_PATH_TIME /
                                     ROAMING_PATH_TIME)

Kotlin mirrors (rns-core/src/main/kotlin/network/reticulum/transport/
Transport.kt):
  - DISCOVER_PATHS_FOR:              214
  - processPathRequest:              2255
  - requestPath:                     2031 (has early-skip guards that
                                     don't exist on the Python side —
                                     this test suite routes through
                                     `wire_request_path` which sends
                                     unconditionally to match Python's
                                     observable behaviour)
  - AnnounceFilter.pathExpiryForMode:    AnnounceFilter.kt:59
"""

import secrets
import time

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


# Path expiry constants, in milliseconds since epoch (both sides agreed).
# Matches Python Transport.PATHFINDER_E / AP_PATH_TIME / ROAMING_PATH_TIME
# and Kotlin TransportConstants.{PATHFINDER_E, AP_PATH_TIME, ROAMING_PATH_TIME}
# in their respective time bases — normalized to ms by the bridge side.
_PATHFINDER_E_MS = 7 * 24 * 60 * 60 * 1000  # 7d
_AP_PATH_TIME_MS = 1 * 24 * 60 * 60 * 1000  # 1d
_ROAMING_PATH_TIME_MS = 6 * 60 * 60 * 1000  # 6h

# Settle budgets:
# - PATHFINDER_RW (rebroadcast random window) is 0.5s on Python, similar
#   on Kotlin; waiting 1.5s after an announce is the proven pattern from
#   test_link_multihop.py and guarantees the rebroadcast fires (or
#   doesn't — we need it to have fired + completed so C's connection
#   doesn't catch the rebroadcast).
# - PATH_REQUEST_GRACE is 0.4s — answers to a PR are scheduled with that
#   grace before retransmit. Poll budgets must exceed this.
_SETTLE_SEC = 1.5
_POLL_TIMEOUT_MS = 5000
# After a path request, give answer-path enough time to reach the
# requester: PATH_REQUEST_GRACE (0.4s) + wire RTT. 2s is generous.
_PR_ANSWER_SETTLE_SEC = 2.0
# Short settle for "did the transport enqueue a response yet" — this is
# a local state check on the transport side, not an observation of wire
# traffic, so a small window catches the state-set before cull.
_LOCAL_STATE_SETTLE_SEC = 0.3
# How long to watch B's TX after a PR (L12). This MUST exceed the worst-case
# answer latency, otherwise the negative (suppress) test can't be told apart
# from a merely-delayed answer. A roaming/AP answer is scheduled at
# now + PATH_REQUEST_GRACE (0.4s) and emitted on the announce-loop tick
# (announces_check_interval ~1s) plus a rebroadcast random window
# (PATHFINDER_RW 0.5s) and wire RTT — a worst case near ~2.9s. 4.0s clears
# that with headroom, so if B were going to answer at all, the bytes appear
# inside the window.
_PR_OBSERVE_SEC = 4.0


def _start_three_peer_topology(
    wire_3peer,
    transport_mode: str | None = None,
    sender_mode: str | None = None,
    receiver_mode: str | None = None,
):
    """Bring up the A → B → C topology with caller-selected interface modes.

    A = sender (TCPClient), B = transport (TCPServer, enable_transport=True),
    C = receiver (TCPClient). All three connect on loopback.

    `transport_mode` is applied to B's server and (via TCPServerInterface's
    spawn-time mode propagation, Python RNS 1.3.1 TCPInterface.py:625
    `spawned_interface.mode = self.mode`) to the child interfaces spawned
    per peer connection, so B's
    `receiving_interface` for packets from either A or C reports the
    configured mode.

    Returns (sender, transport, receiver) `_WirePeer` objects. Caller
    drives the rest of the topology assembly (announce / listen / etc).
    """
    sender, transport, receiver = wire_3peer

    port = transport.start_tcp_server(
        network_name="", passphrase="", mode=transport_mode
    )
    receiver.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=port,
        mode=receiver_mode,
    )
    sender.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=port,
        mode=sender_mode,
    )
    time.sleep(_SETTLE_SEC)
    return sender, transport, receiver


# ---------------------------------------------------------------------------
# Test 1: Cached announce re-emission (byte-identity of random_hash)
# ---------------------------------------------------------------------------


_ISSUE_46_REASON = (
    "reticulum-kt TCPServerInterface fans out inbound packets to all other "
    "connected clients, so C's PR leaks to A and A generates a fresh announce "
    "with a new random_hash that overwrites B's cached entry. "
    "See https://github.com/torlando-tech/reticulum-kt/issues/46."
)


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "request_path", "poll_path", "read_path_entry", "read_path_random_hash"],
    verifies="When B answers a path request for a destination it cached, the re-emitted announce's random_hash bytes are byte-identical to the cached announce's (no regeneration on re-emit)",
)
def test_path_response_reuses_cached_announce(wire_trio, wire_3peer):
    """When B (transport) answers a PR for a destination it has cached,
    the re-emitted announce MUST be the cached announce — identifiable
    by the 10-byte random_hash segment being byte-identical on B's side
    and on the requester's side after the answer arrives.

    Rationale: a fresh announce generated on B would have fresh random
    bytes + fresh timestamp in the random_hash slot, and C's path_table
    entry would contain different bytes. Any regeneration instead of
    cached-packet re-emission breaks this invariant.

    Topology: A announces, B caches, C (fresh, not yet connected when A
    announced) requests a path. B replies with the cached announce.
    """
    sender, transport, receiver = wire_3peer

    port = transport.start_tcp_server(network_name="", passphrase="")
    sender.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    # Let A connect and settle before announcing.
    time.sleep(_SETTLE_SEC)

    dest_hash = sender.announce(app_name="pathdiscovery", aspects=["test"])
    # Wait for A's announce to propagate through B and for B's
    # retransmit window (PATHFINDER_RW ~0.5s) to close. Any retransmit
    # after C connects would muddy the "C only saw the cached-response
    # reply" invariant.
    time.sleep(_SETTLE_SEC)

    # Snapshot the random_hash on B's side — the announce B will
    # re-emit in response to C's PR uses precisely this cached packet.
    cached_random_hash_on_b = transport.read_path_random_hash(dest_hash)
    assert cached_random_hash_on_b is not None and len(cached_random_hash_on_b) == 10, (
        f"B ({transport.role_label}) did not cache the announce with a "
        f"valid 10-byte random_hash; got {cached_random_hash_on_b!r}. "
        f"The 3-peer topology's caching side is broken; later "
        f"assertions would be meaningless."
    )

    # Now bring up C — intentionally late, so C has no prior path to A.
    receiver.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    time.sleep(_SETTLE_SEC)

    # Sanity: C must not have learned about A yet. On Python, B does
    # not spontaneously retransmit cached announces on new connections,
    # so this holds. On Kotlin, B's TCPServerInterface fans out every
    # announce received from any peer to every other peer — the
    # `sender->kotlin-server->receiver` topology may leak A's original
    # announce to C on connect, which would short-circuit this test.
    # We only assert this precondition AFTER the positive-side setup
    # (A announced, B cached) so a vacuous-pass if xfail-below lands is
    # impossible.
    prior_entry = receiver.read_path_entry(dest_hash)

    # reticulum-kt#46: Kotlin's TCPServerInterface fan-out leaks C's PR
    # to A, triggering A to generate a fresh announce that overwrites
    # B's cached entry. This violates the cached-packet invariant the
    # test asserts. See issue for full trace + fix proposal.
    _sender_impl, transport_impl, _receiver_impl = wire_trio
    if transport_impl == "kotlin":
        pytest.xfail(_ISSUE_46_REASON)

    assert prior_entry is None, (
        f"C ({receiver.role_label}) already has a path to "
        f"{dest_hash.hex()} before requesting one — B is broadcasting "
        f"cached announces on new connections, which would short-circuit "
        f"this test. Re-examine the fixture's timing."
    )

    # C requests a path. B hits the cached-announce re-emission branch.
    receiver.request_path(dest_hash)

    # Poll until C observes the path response.
    assert receiver.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS), (
        f"C ({receiver.role_label}) did not learn a path to "
        f"{dest_hash.hex()} within {_POLL_TIMEOUT_MS}ms of calling "
        f"request_path. The path-request → path-response exchange "
        f"failed to complete."
    )

    received_random_hash_on_c = receiver.read_path_random_hash(dest_hash)
    assert received_random_hash_on_c is not None and len(received_random_hash_on_c) == 10, (
        f"C's path_table has an entry for {dest_hash.hex()} but its "
        f"cached announce's random_hash is invalid: "
        f"{received_random_hash_on_c!r}"
    )

    # The actual assertion: random_hash must be byte-identical. A fresh
    # regeneration would differ in both the 5-byte random part and the
    # 5-byte timestamp part.
    assert received_random_hash_on_c == cached_random_hash_on_b, (
        f"C received a path response for {dest_hash.hex()}, but its "
        f"random_hash differs from the one B cached. B: "
        f"{cached_random_hash_on_b.hex()}; C: "
        f"{received_random_hash_on_c.hex()}. This indicates B "
        f"regenerated the announce instead of re-emitting the cached "
        f"one, violating the path_response cached-packet contract."
    )


# ---------------------------------------------------------------------------
# Test 2: DISCOVER_PATHS_FOR mode gating on recursive PR forwarding
# ---------------------------------------------------------------------------


_DISCOVER_PATHS_FOR_MODES = {"access_point", "gateway", "roaming"}
_NON_DISCOVER_MODES = {"full", "point_to_point", "boundary"}

_ALL_MODES_FOR_GATING = sorted(_DISCOVER_PATHS_FOR_MODES | _NON_DISCOVER_MODES)


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "request_path", "has_discovery_path_request"],
    verifies="B forwards path requests for unknown destinations only when its receiving interface's mode is in DISCOVER_PATHS_FOR={access_point, gateway, roaming}, gated correctly for every parametrized mode",
)
@pytest.mark.parametrize("transport_mode", _ALL_MODES_FOR_GATING)
def test_discover_paths_for_mode_gating(wire_3peer, transport_mode):
    """When C sends a PR for an UNKNOWN destination to B, B must only
    forward the request to its other interfaces if B's receiving
    interface mode is in DISCOVER_PATHS_FOR = {ACCESS_POINT, GATEWAY,
    ROAMING}.

    Observable: `B.has_discovery_path_request(UNKNOWN)` — a membership
    test on `Transport.discovery_path_requests`. That dict is populated
    at the exact spot in path_request() where the mode-gated forwarding
    branch runs (Python RNS 1.3.1 Transport.py:3030, reached only via the
    `should_search_for_unknown` gate set at 2916; Kotlin
    Transport.kt:processPathRequest case 2).

    Tight assertion: `assert has == expected_forwarded`. Not `>= 1`; the
    observable is a bool and we're asserting its exact value.
    """
    sender, transport, receiver = _start_three_peer_topology(
        wire_3peer, transport_mode=transport_mode
    )

    # C asks for a destination neither A nor B has ever seen. The
    # destination hash must be exactly the 16 bytes Reticulum uses for
    # truncated destination hashes.
    unknown_hash = secrets.token_bytes(16)

    # Fire the PR. Kotlin's request_path has early-skip guards; the
    # bridge's wire_request_path bypasses them by sending a raw packet.
    receiver.request_path(unknown_hash)

    # Give the packet a moment to land on B and run the mode-gating
    # branch. We're observing LOCAL state on B (the discovery_path_
    # requests dict), which is set synchronously in path_request — no
    # cross-wire wait needed beyond inbound processing.
    time.sleep(_LOCAL_STATE_SETTLE_SEC)

    observed = transport.has_discovery_path_request(unknown_hash)
    expected = transport_mode in _DISCOVER_PATHS_FOR_MODES

    assert observed == expected, (
        f"B ({transport.role_label}) with mode={transport_mode} "
        f"{'forwarded' if observed else 'did not forward'} a PR for "
        f"unknown destination {unknown_hash.hex()}; expected "
        f"{'forward' if expected else 'no forward'} because "
        f"{transport_mode} is "
        f"{'in' if expected else 'NOT in'} DISCOVER_PATHS_FOR "
        f"(= {sorted(_DISCOVER_PATHS_FOR_MODES)})."
    )


# ---------------------------------------------------------------------------
# Test 3: ROAMING loop-prevention drop when next-hop == receiving iface
# ---------------------------------------------------------------------------


def _tx_delta_after_pr(requester, transport_peer, dest_hash):
    """Helper: send a path request from `requester` and return how many
    bytes `transport_peer` emits within the full worst-case answer window.

    TX-byte deltas are the model-agnostic "did B send anything" signal;
    they don't depend on impl-specific held_announces restore timing or
    announce_table observability.

    Timing budget (L12): Python schedules the answer at now +
    PATH_REQUEST_GRACE (0.4s) and the announce loop checks every ~1s
    (Transport.announces_check_interval), so an actual answer usually lands
    around 0.8-1.0s but worst-cases near ~2.9s. We wait _PR_OBSERVE_SEC
    (4.0s) so a merely-delayed answer cannot masquerade as suppression in
    the negative test.
    """
    tx_before = transport_peer.tx_bytes()
    requester.request_path(dest_hash)
    time.sleep(_PR_OBSERVE_SEC)
    return transport_peer.tx_bytes() - tx_before


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "request_path", "tx_bytes", "read_path_entry"],
    verifies="Under ROAMING mode, B refuses to answer a path request when the cached path's next-hop is the same interface that received the PR (loop-prevention rule fires)",
)
def test_roaming_no_answer_when_next_hop_on_same_interface(wire_peers):
    """ROAMING loop prevention: when a PR arrives on an interface that
    is itself the `received_from` of the cached path, B must refuse to
    answer.

    The rule (Python RNS 1.3.1 Transport.py:2949 / Kotlin
    Transport.kt:processPathRequest's roaming branch) prevents a PR and
    its response from ping-ponging on a single shared-medium ROAMING
    link. The mode bit matters: the same topology under FULL mode DOES
    answer (see the companion positive test below).

    Setup: 2-peer. A (TCPClient, ROAMING) connects to B (TCPServer,
    ROAMING). A announces D1. B caches path to D1 with
    `received_from = spawned-child-for-A`. A then fires a PR for D1 —
    B's attached_interface (the same spawned child) == received_from,
    mode == ROAMING → rule fires → B does NOT emit an answer packet.

    Observable: B's outbound TX byte count — a near-zero delta over the
    full worst-case answer window (_PR_OBSERVE_SEC) means no packet left
    B's wire (suppression, not delay). A separate companion test asserts
    the positive case (FULL mode → a genuine-answer-sized delta),
    catching any regression that makes this test vacuously pass.
    """
    server, client = wire_peers

    port = server.start_tcp_server(network_name="", passphrase="", mode="roaming")
    client.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=port,
        mode="roaming",
    )
    time.sleep(_SETTLE_SEC)

    # A announces; B caches path to D1 via its A-spawned child interface.
    dest_hash = client.announce(app_name="pathdiscovery", aspects=["roaming"])
    time.sleep(_SETTLE_SEC)

    # Precondition: B must have cached the announce, otherwise the
    # "answer with cached re-emit" branch wouldn't even be reachable
    # and the test would pass vacuously.
    entry_before = server.read_path_entry(dest_hash)
    assert entry_before is not None, (
        f"B ({server.role_label}) did not cache A's ({client.role_label}) "
        f"announce for {dest_hash.hex()} within {_SETTLE_SEC}s — the "
        f"roaming loop-prevention test precondition failed."
    )

    # A issues a PR for its own destination. In the 2-peer topology B's
    # attached_interface (spawned child for A) == received_from for D1's
    # cached announce, and both are ROAMING mode → loop-prevention fires.
    tx_delta = _tx_delta_after_pr(client, server, dest_hash)

    # The key invariant: no answer packet was emitted. Tolerate a
    # small byte budget for idle-link framing / keep-alive traffic;
    # any real response packet is ≥~130 bytes (path-response announce
    # with signature + random + app_data), so <20 reliably
    # distinguishes "no answer" from "answer emitted" without being
    # brittle to future RNS background-traffic changes.
    assert tx_delta < 20, (
        f"B ({server.role_label}) emitted {tx_delta} bytes after A's "
        f"PR for {dest_hash.hex()} under ROAMING mode (above idle-"
        f"traffic budget, observed over {_PR_OBSERVE_SEC}s which exceeds "
        f"the worst-case answer latency — so this is suppression, not a "
        f"delayed answer). The roaming loop-prevention rule "
        f"(Transport.py:2949 / Transport.kt:processPathRequest's "
        f"roaming-mode branch) should have skipped the answer path "
        f"entirely — B's A-facing interface IS the `received_from` "
        f"for D1's cached path, and both are ROAMING."
    )


# Floor for "B actually answered the PR" (L13). A FULL-mode answer is the
# cached announce re-emitted as a HEADER_2 path response: empirically ~370
# bytes on the reference (signature + random_hash + app_data + framing). We
# require the delta to clear the negative test's <20-byte idle budget by a
# wide margin so the positive control is symmetric with — and strictly
# stronger than — the negative's "<20 = no answer" boundary. 100 sits well
# above idle framing yet far below the real ~370 answer, so it is robust to
# MTU / keepalive-framing differences without weakening to a bare `> 0`.
_PR_ANSWER_FLOOR_BYTES = 100


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "request_path", "tx_bytes", "read_path_entry"],
    verifies="Under FULL mode (companion to the ROAMING test) B answers the PR with a genuine-answer-sized burst (>=100 bytes, vs the ROAMING test's <20 idle budget) — proves the ROAMING suppression test isn't vacuously passing because B never answers",
)
def test_roaming_loop_prevention_positive_companion(wire_peers):
    """Companion to the negative test above. Same 2-peer topology, but
    under FULL mode the loop-prevention rule does NOT apply, so B must
    emit an answer packet. Without this companion, the negative test
    would vacuously pass if B simply never responds to any PR (e.g.,
    a broken path_request handler).
    """
    server, client = wire_peers

    port = server.start_tcp_server(network_name="", passphrase="", mode="full")
    client.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=port,
        mode="full",
    )
    time.sleep(_SETTLE_SEC)

    dest_hash = client.announce(app_name="pathdiscovery", aspects=["full"])
    time.sleep(_SETTLE_SEC)

    assert server.read_path_entry(dest_hash) is not None, (
        f"B ({server.role_label}) did not cache A's announce — the "
        f"positive companion precondition failed."
    )

    tx_delta = _tx_delta_after_pr(client, server, dest_hash)

    # Under FULL, B re-emits the cached announce as a HEADER_2 path
    # response (~370 bytes on the reference). Requiring >= 100 makes this
    # floor symmetric with — and strictly stronger than — the negative
    # test's `< 20` idle budget, so the pair brackets the same observable:
    # < 20 == "no answer", >= 100 == "genuine answer". A bare `> 0` floor
    # (the prior L13 weakness) could be satisfied by a few bytes of idle
    # framing and would not actually prove B answered.
    assert tx_delta >= _PR_ANSWER_FLOOR_BYTES, (
        f"B ({server.role_label}) emitted only {tx_delta} bytes in "
        f"response to A's PR for {dest_hash.hex()} under FULL mode "
        f"(floor={_PR_ANSWER_FLOOR_BYTES}). A genuine cached-announce "
        f"path response is hundreds of bytes; a sub-floor delta means the "
        f"positive path is broken, which would make the negative test's "
        f"observable unreliable."
    )


# ---------------------------------------------------------------------------
# Test 4: Mode-specific path expiry assignment
# ---------------------------------------------------------------------------


_EXPIRY_EXPECTATIONS = [
    # (mode_string, expected_expires_minus_timestamp_ms, label)
    ("full", _PATHFINDER_E_MS, "PATHFINDER_E (7d)"),
    ("access_point", _AP_PATH_TIME_MS, "AP_PATH_TIME (1d)"),
    ("roaming", _ROAMING_PATH_TIME_MS, "ROAMING_PATH_TIME (6h)"),
]

# L14: RNS stamps the path entry from a SINGLE `now = time.time()`
# (Transport.py:1832); both the stored timestamp (entry[0], line 2011) and
# `expires` (now + the per-mode constant, lines 1874-1878) derive from that
# same `now`, so `expires - timestamp` is mathematically EXACTLY the constant
# (in seconds). The only slack is the bridge's float-seconds -> int-ms
# truncation (int(expires*1000) - int(timestamp*1000)); since the per-mode
# constant is a whole number of seconds, that subtraction is exact to the
# millisecond except for sub-ULP float error near a ms boundary. Empirically
# the delta is exact (diff=0) for all three modes; ±2ms is a safe, justified
# bound (vs the prior unjustified ±1000ms, which would have hidden a constant
# applied wrongly by up to a second).
_EXPIRY_JITTER_MS = 2


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "read_path_entry"],
    verifies="Stored path-entry expiry equals timestamp + the per-mode constant (PATHFINDER_E for FULL, AP_PATH_TIME for ACCESS_POINT, ROAMING_PATH_TIME for ROAMING) within jitter",
)
@pytest.mark.parametrize(
    "mode,expected_delta_ms,label", _EXPIRY_EXPECTATIONS,
    ids=[label for _mode, _delta, label in _EXPIRY_EXPECTATIONS],
)
def test_mode_specific_path_expiry_assignment(
    wire_peers, mode, expected_delta_ms, label
):
    """Path table entries store an `expires` field whose value is
    `timestamp + delta` where delta is selected from the RECEIVING
    interface's mode:
        ACCESS_POINT → AP_PATH_TIME (1d)
        ROAMING      → ROAMING_PATH_TIME (6h)
        everything else → PATHFINDER_E (7d)

    (Python RNS 1.3.1 Transport.py:1874-1878; Kotlin
    AnnounceFilter.pathExpiryForMode.)

    We don't need clock control for this: send an announce and
    immediately read the stored entry. expires - timestamp must equal
    the per-mode delta (both sides in ms, no tz assumptions).
    """
    server, client = wire_peers

    # Only set the mode on the server side (the receiving side). The
    # expiry-assignment branch at Transport.py:1873-1878 keys off
    # `packet.receiving_interface.mode`, and that's the server-spawned
    # child that inherits the server's configured mode (Kotlin propagates
    # via TCPServerInterface:149, Python via TCPInterface.py:625
    # `spawned_interface.mode = self.mode`). Setting the client's mode too
    # would, in AP mode, block A's outbound announce (Transport.py:1191-1195)
    # and the test would see no path entry for reasons unrelated to expiry
    # assignment.
    port = server.start_tcp_server(network_name="", passphrase="", mode=mode)
    client.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=port,
    )
    time.sleep(_SETTLE_SEC)

    dest_hash = client.announce(app_name="pathdiscovery", aspects=["expiry", mode])
    time.sleep(_SETTLE_SEC)

    entry = server.read_path_entry(dest_hash)
    assert entry is not None, (
        f"B ({server.role_label}) did not cache A's announce for "
        f"{dest_hash.hex()} under mode={mode} within {_SETTLE_SEC}s — "
        f"cannot assert expiry delta."
    )

    delta = entry["expires"] - entry["timestamp"]

    # Exact bound: on Python both timestamp and expires come from the SAME
    # `now` (Transport.py:1832), so expires - timestamp is exactly the
    # per-mode constant; the ±2ms only absorbs float-seconds -> int-ms
    # truncation (see _EXPIRY_JITTER_MS). On Kotlin
    # System.currentTimeMillis() is likewise read once, so the contract is
    # symmetric.
    lower = expected_delta_ms - _EXPIRY_JITTER_MS
    upper = expected_delta_ms + _EXPIRY_JITTER_MS
    assert lower <= delta <= upper, (
        f"Under mode={mode} ({label}), B ({server.role_label}) stored a "
        f"path entry with expires-timestamp = {delta}ms; expected "
        f"{expected_delta_ms}ms ±{_EXPIRY_JITTER_MS}ms. This indicates "
        f"either the wrong expiry constant was applied (check "
        f"AnnounceFilter.pathExpiryForMode on Kotlin / lines 1874-1878 "
        f"on Python) or the interface mode wasn't applied correctly "
        f"to the receiving interface."
    )
