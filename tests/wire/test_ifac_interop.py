"""End-to-end IFAC wire-interop tests.

Reproduces the exact failure mode from reticulum-kt#29:

  Two Reticulum instances configured with the same (network_name, passphrase),
  connected over a single TCPClient↔TCPServer link, cannot see each other's
  announces because one side's IFAC bytes don't verify on the other side.

Unlike byte-level IFAC tests (tests/test_ifac.py) that compare primitives in
isolation, this test exercises the FULL transmit→mask→wire→unmask→validate
pipeline end-to-end. A failure here means announces aren't crossing the
IFAC boundary in at least one direction — the production symptom.

Parametrized over (server_impl, client_impl) pairs by `pytest_generate_tests`
in the local conftest. That yields, for a [reference, kotlin] impl list:
  - reference ↔ reference  (sanity baseline — must pass)
  - reference ↔ kotlin     (issue-#29 direction A)
  - kotlin ↔ reference     (issue-#29 direction B)
  - kotlin ↔ kotlin        (Kotlin self-interop baseline)
"""

import secrets
import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


def _fresh_credentials() -> tuple[str, str]:
    """Random but deterministic-looking (network_name, passphrase) pair.

    Using a fresh pair per test avoids any accidental cross-contamination
    with a real Reticulum network on the machine running the tests.
    """
    return (
        f"conftest-{secrets.token_hex(4)}",
        secrets.token_hex(16),
    )


# How long to wait between starting the client and triggering the announce.
# The TCPClient connect is asynchronous and announces before the connection
# is up will be silently dropped by the unconnected interface.
_CONNECT_SETTLE_SEC = 0.75

# Upper bound on how long an announce should take to traverse the link and
# populate the peer's path table. Announces are sent immediately; path
# learning is synchronous on inbound — so this mostly tolerates scheduler
# jitter, not real transport latency.
_POLL_TIMEOUT_MS = 5000


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "poll_path", "read_path_entry"],
    verifies="An announce from a TCP client with matching IFAC credentials populates the server's path table at a deterministic 1 hop (reticulum-kt#29 forward direction)",
)
def test_announce_propagates_with_ifac(wire_peers):
    """A client's announce must land in the server's path table when both
    sides have matching IFAC credentials.

    Failure semantic: "IFAC bytes produced by <client_impl> cannot be
    verified by <server_impl>, so the server silently dropped the announce."
    This is the headline reticulum-kt#29 interop break.
    """
    server, client = wire_peers
    network_name, passphrase = _fresh_credentials()

    port = server.start_tcp_server(network_name, passphrase)
    client.start_tcp_client(network_name, passphrase, "127.0.0.1", port)

    time.sleep(_CONNECT_SETTLE_SEC)

    dest_hash = client.announce(
        app_name="interop",
        aspects=["ifac", "test"],
        app_data=b"hello",
    )

    found = server.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert found, (
        f"{server.role_label} did not learn path to destination announced "
        f"by {client.role_label} within {_POLL_TIMEOUT_MS}ms. Both sides "
        f"configured matching IFAC ({network_name=}). The most likely "
        f"cause is that {client.role_label}'s IFAC wire bytes did not "
        f"pass {server.role_label}'s IFAC unmask — i.e. reticulum-kt#29 "
        f"reproduces for this direction."
    )

    # The announce crossed exactly one interface hop, so the path is
    # deterministically 1 hop. Asserting it (L15) turns the bare boolean
    # "found" into a check that the receiver also recorded the right
    # distance — an impl that learns the path but mis-counts hops fails.
    entry = server.read_path_entry(dest_hash)
    assert entry is not None and entry["hops"] == 1, (
        f"{server.role_label} learned the announced path but recorded "
        f"hops={entry['hops'] if entry else None}; a direct 1-hop announce "
        f"across the IFAC link must store hops==1."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "poll_path"],
    verifies="Reverse-direction IFAC: server-initiated announce reaches the TCP client (exercises TCPServerInterface child-interface IFAC inheritance)",
)
def test_announce_bidirectional(wire_peers):
    """Additionally verify the reverse direction: server announces, client
    learns the path. The one-direction test above covers client→server; this
    covers server→client, which exercises the TCP spawn-on-accept code path
    that Python's TCPServerInterface uses (child interfaces inherit IFAC —
    see RNS/Interfaces/TCPInterface.py:588-590).
    """
    server, client = wire_peers
    network_name, passphrase = _fresh_credentials()

    port = server.start_tcp_server(network_name, passphrase)
    client.start_tcp_client(network_name, passphrase, "127.0.0.1", port)

    time.sleep(_CONNECT_SETTLE_SEC)

    dest_hash = server.announce(
        app_name="interop",
        aspects=["reverse"],
        app_data=b"reverse",
    )

    found = client.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert found, (
        f"{client.role_label} did not learn path to destination announced "
        f"by {server.role_label} within {_POLL_TIMEOUT_MS}ms. This is the "
        f"reverse-direction failure mode: the server's IFAC bytes did not "
        f"pass the client's IFAC unmask."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "tx_bytes", "poll_path"],
    verifies="Negative control: when network_names match but passphrases differ, the client's tx_bytes anchor proves it DID emit the announce onto the wire, yet the server's IFAC unmask rejects it and no path is learned — distinguishing 'rejected on receipt' from 'never sent'",
)
def test_mismatched_ifac_blocks_announce(wire_peers):
    """Negative-control: when network_names match but passphrases differ,
    the link MUST NOT propagate announces. This protects us against a
    regression where one side stops enforcing IFAC entirely — which would
    make the positive tests above pass for the wrong reason.

    Server uses (network_name, "pass-A"); client uses (network_name,
    "pass-B"). The matching network_name keeps both interfaces in the same
    nominal network so the connection establishes; only the diverging
    passphrase makes the derived IFAC keys differ.

    N-M14: a bare `not poll_path` cannot tell "the server rejected a sent
    announce" apart from "the client never emitted one" (e.g. a broken
    announce, or a client that silently no-ops on IFAC mismatch). We snapshot
    the client's tx_bytes around the announce as a positive emit anchor: the
    byte count MUST rise (the masked announce really hit the wire), and only
    THEN is "server learned no path" attributable to IFAC rejection.
    """
    server, client = wire_peers
    network_name = _fresh_credentials()[0]

    port = server.start_tcp_server(network_name, "pass-A")
    client.start_tcp_client(network_name, "pass-B", "127.0.0.1", port)

    time.sleep(_CONNECT_SETTLE_SEC)

    tx_before = client.tx_bytes()
    dest_hash = client.announce(
        app_name="interop",
        aspects=["neg"],
        app_data=b"neg",
    )
    # Let the announce flush to the socket before sampling tx_bytes.
    time.sleep(_CONNECT_SETTLE_SEC)
    tx_after = client.tx_bytes()

    # Emit anchor: the announce must have left the client. A real announce
    # packet is well over 100 bytes; any positive delta proves emission.
    assert tx_after > tx_before, (
        f"{client.role_label} did NOT emit any bytes around its announce "
        f"(tx {tx_before} -> {tx_after}). The negative result below would "
        f"then be vacuous — 'no path learned' could just mean nothing was "
        f"sent. The IFAC-rejection claim requires the announce to have been "
        f"transmitted in the first place."
    )

    # Use a shorter timeout; we're asserting NOT found, so waiting the full
    # budget just adds latency without changing the outcome.
    found = server.poll_path(dest_hash, timeout_ms=2000)
    assert not found, (
        f"{server.role_label} learned a path for an announce signed with a "
        f"different IFAC passphrase. Either {server.role_label} is not "
        f"enforcing IFAC at all, or both sides derived the same key from "
        f"different passphrases (HKDF collision — effectively impossible). "
        f"This would make the positive-direction interop tests meaningless."
    )


# ---------------------------------------------------------------------------
# IFAC issue-29 golden vector (byte-level pin)
# ---------------------------------------------------------------------------
#
# The end-to-end tests above only observe "did the announce cross the IFAC
# boundary" — a boolean. A self-consistent but WRONG derivation adopted by
# both sides (the exact reticulum-kt#29 failure) is invisible to a boolean
# check. N-M14 / the §4 regression list call for restoring the one faithful
# byte-pin lost when tests/test_ifac.py was deleted.
#
# Derivation (RNS Reticulum.py:1060-1078, ground truth RNS 1.3.1), reproduced
# independently here from RNS primitives:
#   ifac_origin      = full_hash("testnet") || full_hash("testpass")
#   ifac_origin_hash = full_hash(ifac_origin)
#   ifac_key         = hkdf(length=64, derive_from=ifac_origin_hash,
#                           salt=Reticulum.IFAC_SALT)
#   ifac_identity    = Identity.from_bytes(ifac_key)
#   signature        = ifac_identity.sign(bytes(range(64)))   # deterministic
#   ifac             = signature[-ifac_size:]                 # ifac_size=16 (TCP)
#
# RNS's Ed25519 sign is deterministic (RFC 8032), so the signature — and thus
# the IFAC tag — is a stable byte vector. The bridge computes it via the LIVE
# interface's RNS-derived ifac_identity (wire_ifac_compute reads
# interface.ifac_identity / .ifac_key straight off the interface and signs),
# so this pins the genuine RNS derivation, not a hand-rolled HKDF/Ed25519.
_ISSUE_29_NETWORK = "testnet"
_ISSUE_29_PASSPHRASE = "testpass"
_ISSUE_29_PACKET = bytes(range(64))
# TCPInterface.DEFAULT_IFAC_SIZE = 16 (RNS Interfaces/TCPInterface.py:77); the
# bridge writes no explicit ifac_size, so the interface uses this default.
_ISSUE_29_IFAC_SIZE = 16
_ISSUE_29_IFAC_KEY = bytes.fromhex(
    "2894b3f7f9b192ccb912d5b6515b33e8386490956f18f103e20ae89554e3b52b"
    "0c35dd1c5e5ce895c3e7ce5eaeeaae77b9de89bc791070f7c71bf9672f881197"
)
_ISSUE_29_SIGNATURE = bytes.fromhex(
    "07ced7e5693e50d41c1c54cf014cee5970bbe607468e9177926174bbb29a6497"
    "80c692473f3838c359df879fc80f3d15f9ab19091f5b6d8bf96e31d0604e1400"
)
_ISSUE_29_IFAC = bytes.fromhex("f9ab19091f5b6d8bf96e31d0604e1400")  # signature[-16:]


@conformance_case(
    commands=["start_tcp_server", "ifac_compute"],
    verifies="reticulum-kt#29 golden vector: a TCP interface configured with network_name='testnet'/passphrase='testpass' derives the exact 64-byte IFAC key 2894..1197, and signing bytes(range(64)) with the derived ifac_identity yields the exact deterministic Ed25519 signature 07ce..1400 whose trailing 16 bytes f9ab..1400 are the IFAC access code RNS prepends",
)
def test_ifac_issue_29_golden_vector(wire_peers):
    """Byte-level pin of the IFAC derivation against the reticulum-kt#29
    repro inputs. A regression that derives a self-consistent but WRONG
    ifac_key (the issue-29 failure) — invisible to the boolean end-to-end
    tests above — fails here on exact byte mismatch.

    Only the server peer is exercised; the IFAC key is derived at interface
    config time, independent of any connection, so no client is needed.
    """
    server, _client = wire_peers
    server.start_tcp_server(_ISSUE_29_NETWORK, _ISSUE_29_PASSPHRASE)

    result = server.ifac_compute(_ISSUE_29_PACKET)

    assert result["ifac_size"] == _ISSUE_29_IFAC_SIZE, (
        f"TCP interface ifac_size is {result['ifac_size']}; expected "
        f"{_ISSUE_29_IFAC_SIZE} (TCPInterface.DEFAULT_IFAC_SIZE)."
    )
    assert result["ifac_key"] == _ISSUE_29_IFAC_KEY, (
        f"IFAC key derived from ('{_ISSUE_29_NETWORK}', "
        f"'{_ISSUE_29_PASSPHRASE}') diverges from the RNS 1.3.1 golden "
        f"vector. got={result['ifac_key'].hex()} "
        f"expected={_ISSUE_29_IFAC_KEY.hex()}. The HKDF/origin-hash "
        f"derivation is wrong — this is the reticulum-kt#29 root cause."
    )
    assert result["signature"] == _ISSUE_29_SIGNATURE, (
        f"Ed25519 signature over bytes(range(64)) diverges from the golden "
        f"vector. got={result['signature'].hex()} "
        f"expected={_ISSUE_29_SIGNATURE.hex()}. Either the ifac_identity "
        f"differs or the signing is non-deterministic (RNS uses RFC-8032 "
        f"deterministic Ed25519, so a fixed key+message must reproduce)."
    )
    assert result["ifac"] == _ISSUE_29_IFAC, (
        f"IFAC tag (trailing {_ISSUE_29_IFAC_SIZE} signature bytes) "
        f"diverges. got={result['ifac'].hex()} expected={_ISSUE_29_IFAC.hex()}"
    )
    # The tag is exactly the trailing ifac_size bytes of the full signature.
    assert result["ifac"] == result["signature"][-_ISSUE_29_IFAC_SIZE:], (
        "ifac is not the trailing ifac_size bytes of the signature — the "
        "tag-slicing convention diverges from RNS."
    )
