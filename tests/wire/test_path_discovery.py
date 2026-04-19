"""Path discovery conformance: path request, path response, mode-gated
discovery forwarding, ROAMING loop prevention, and mode-specific path
expiry assignment.

Tests here pin concrete, externally-observable guarantees that the
path layer makes. They're deliberately 2-peer or 3-peer where the
observable is tight enough to distinguish "rule fired" from "rule did
not fire" without any timing slop.

References (line numbers against Python Reticulum Transport.py):
  - request_path:                    2541
  - path_request_handler:            2646
  - path_request:                    2696
  - cached-announce re-emission:     2724, 2735-2781
  - ROAMING loop-prevention drop:    2731-2732
  - DISCOVER_PATHS_FOR gating:       2700 (Interface.py:54)
  - per-mode expiry assignment:      1730-1735
  - path expiry constants:           70-72 (PATHFINDER_E / AP_PATH_TIME /
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
    spawn-time mode propagation mirrored from Python TCPInterface.py:619)
    to the child interfaces spawned per peer connection, so B's
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


@pytest.mark.parametrize("transport_mode", _ALL_MODES_FOR_GATING)
def test_discover_paths_for_mode_gating(wire_3peer, transport_mode):
    """When C sends a PR for an UNKNOWN destination to B, B must only
    forward the request to its other interfaces if B's receiving
    interface mode is in DISCOVER_PATHS_FOR = {ACCESS_POINT, GATEWAY,
    ROAMING}.

    Observable: `B.has_discovery_path_request(UNKNOWN)` — a membership
    test on `Transport.discovery_path_requests`. That dict is populated
    at the exact spot in path_request() where the mode-gated forwarding
    branch runs (Python Transport.py:2800, Kotlin
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
    bytes `transport_peer` emits within PATH_REQUEST_GRACE + the
    announce-loop tick interval.

    TX-byte deltas are the model-agnostic "did B send anything" signal;
    they don't depend on impl-specific held_announces restore timing or
    announce_table observability.

    Timing budget: Python schedules the answer at now + PATH_REQUEST_GRACE
    (0.4s) and the announce loop checks every ~1s
    (Transport.announces_check_interval), so the first actual send
    usually lands around 0.8-1.0s after the PR. 2.5s covers both sides'
    grace + first tick + wire RTT with headroom.
    """
    tx_before = transport_peer.tx_bytes()
    requester.request_path(dest_hash)
    time.sleep(2.5)
    return transport_peer.tx_bytes() - tx_before


def test_roaming_no_answer_when_next_hop_on_same_interface(wire_peers):
    """ROAMING loop prevention: when a PR arrives on an interface that
    is itself the `received_from` of the cached path, B must refuse to
    answer.

    The rule (Python Transport.py:2731-2732 / Kotlin
    Transport.kt:processPathRequest's roaming branch) prevents a PR and
    its response from ping-ponging on a single shared-medium ROAMING
    link. The mode bit matters: the same topology under FULL mode DOES
    answer (see the companion positive test below).

    Setup: 2-peer. A (TCPClient, ROAMING) connects to B (TCPServer,
    ROAMING). A announces D1. B caches path to D1 with
    `received_from = spawned-child-for-A`. A then fires a PR for D1 —
    B's attached_interface (the same spawned child) == received_from,
    mode == ROAMING → rule fires → B does NOT emit an answer packet.

    Observable: B's outbound TX byte count — a delta of zero during
    the post-PR grace window means no packet left B's wire. A separate
    companion test asserts the positive case (FULL mode → non-zero
    delta), catching any regression that makes this test vacuously
    pass.
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
        f"traffic budget). The roaming loop-prevention rule "
        f"(Transport.py:2731 / Transport.kt:processPathRequest's "
        f"roaming-mode branch) should have skipped the answer path "
        f"entirely — B's A-facing interface IS the `received_from` "
        f"for D1's cached path, and both are ROAMING."
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

    # Under FULL, B must emit at least the HEADER_2-wrapped cached
    # announce (~160 bytes for a minimal destination + signature). A
    # non-zero delta is the positive signal; the exact byte count isn't
    # asserted here (MTU varies, keepalive framing overhead differs
    # across impls).
    assert tx_delta > 0, (
        f"B ({server.role_label}) did not emit any bytes in response "
        f"to A's PR for {dest_hash.hex()} under FULL mode "
        f"(tx_delta={tx_delta}). The positive path is broken, which "
        f"means the negative test's observable is unreliable."
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

# Allow tiny jitter between when the bridge stamps `timestamp` and when
# Transport stamps `expires` — these are a couple of function calls
# apart, well below 1 second in practice. Expanding this window should
# not be needed; if the delta drifts, investigate whether clocks are
# being read from different sources on the two sides.
_EXPIRY_JITTER_MS = 1000


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

    (Python Transport.py:1730-1735; Kotlin AnnounceFilter.pathExpiryForMode.)

    We don't need clock control for this: send an announce and
    immediately read the stored entry. expires - timestamp must equal
    the per-mode delta (both sides in ms, no tz assumptions).
    """
    server, client = wire_peers

    # Only set the mode on the server side (the receiving side). The
    # expiry-assignment branch at Transport.py:1730 keys off
    # `packet.receiving_interface.mode`, and that's the server-spawned
    # child that inherits the server's configured mode (Kotlin propagates
    # via TCPServerInterface:149, Python via TCPInterface.py:619).
    # Setting the client's mode too would, in AP mode, block A's outbound
    # announce (Transport.py:1042) and the test would see no path entry
    # for reasons unrelated to expiry assignment.
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

    # Tight bound: the delta should equal the expected constant exactly.
    # Small jitter is allowed because on Python `timestamp` and `expires`
    # are stamped by two distinct `time.time()` calls (Transport.py:1663
    # and 1731) a few microseconds apart. On Kotlin
    # (Transport.kt:3317) `System.currentTimeMillis()` is called once
    # but the jitter bound keeps the cross-impl contract symmetric.
    lower = expected_delta_ms - _EXPIRY_JITTER_MS
    upper = expected_delta_ms + _EXPIRY_JITTER_MS
    assert lower <= delta <= upper, (
        f"Under mode={mode} ({label}), B ({server.role_label}) stored a "
        f"path entry with expires-timestamp = {delta}ms; expected "
        f"{expected_delta_ms}ms ±{_EXPIRY_JITTER_MS}ms. This indicates "
        f"either the wrong expiry constant was applied (check "
        f"AnnounceFilter.pathExpiryForMode on Kotlin / lines 1730-1735 "
        f"on Python) or the interface mode wasn't applied correctly "
        f"to the receiving interface."
    )
