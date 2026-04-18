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

import pytest


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


@pytest.mark.parametrize(
    "server_secret,client_secret",
    [
        ("right-netname", "right-pass"),   # baseline — both right
    ],
    ids=["matching-credentials"],
)
def test_mismatched_ifac_blocks_announce(wire_peers, server_secret, client_secret):
    """Negative-control: when network_names match but passphrases differ,
    the link MUST NOT propagate announces. This protects us against a
    regression where one side stops enforcing IFAC entirely — which would
    make the positive tests above pass for the wrong reason.

    Server uses (server_secret, "pass-A"); client uses (server_secret, "pass-B").
    """
    server, client = wire_peers

    port = server.start_tcp_server(server_secret, "pass-A")
    client.start_tcp_client(server_secret, "pass-B", "127.0.0.1", port)

    time.sleep(_CONNECT_SETTLE_SEC)

    dest_hash = client.announce(
        app_name="interop",
        aspects=["neg"],
        app_data=b"neg",
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
