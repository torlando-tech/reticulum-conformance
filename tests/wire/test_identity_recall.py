"""Identity.recall conformance — Transport-mediated identity lookup.

After observing an announce, every Reticulum application looks up the
sender's Identity by destination hash via RNS.Identity.recall(). Columba's
NomadNet page browser, Sideband's conversation routing, and LXMF itself
(LXMessage source/destination resolution) all rely on this. The look-up
operates on the receiver's known_destinations table, populated by the
announce reception code path.

Honest test: peer A announces an IN destination via its real RNS instance.
Peer B receives the announce over the wire infrastructure. Peer B then
calls Identity.recall(A_destination_hash) — wire_identity_recall delegates
to the real static method on B's instance — and asserts the recalled
Identity exposes A's exact public key.

Negative control: recall of an unknown destination hash returns None
(found=False on the wire response). This catches an impl that silently
returns a stub Identity for an unknown hash, which would mis-route any
subsequent outbound encryption.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["identity-recall"]
_POLL_TIMEOUT_MS = 10000


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "announce", "identity_recall"],
    verifies="After receiving an announce, RNS.Identity.recall(destination_hash) returns the announcing peer's real Identity with byte-identical public_key — the lookup every app does to bind a destination hash back to its underlying identity (Columba NomadNet handler, Sideband conversation routing, LXMF LXMessage source/destination resolution)",
)
def test_identity_recall_after_announce(wire_peers):
    """Peer A announces an IN destination; peer B recalls A's identity
    from the announce-populated known_destinations table and gets A's
    full public key back.
    """
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    # Server registers an IN destination and announces it. wire_listen
    # in the bridge automatically emits the announce after registration.
    server_dest = server.listen(app_name=_APP, aspects=_ASPECTS)

    # Client waits for the announce to land — Transport.has_path is the
    # observable proof. identity_recall's own timeout polls the same
    # state, so this poll is belt-and-suspenders.
    assert client.poll_path(server_dest, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — Identity.recall is untestable without the prior "
        f"announce reception."
    )

    recalled = client.identity_recall(server_dest, timeout_ms=_POLL_TIMEOUT_MS)
    assert recalled is not None, (
        f"{client.role_label}.Identity.recall({server_dest.hex()}) "
        f"returned None despite has_path being True — the announce was "
        f"received but the receiver's known_destinations table is "
        f"missing the Identity that signed it."
    )
    assert len(recalled["public_key"]) == 64, (
        f"recalled public_key is {len(recalled['public_key'])} bytes; "
        f"RNS Identity public keys are 64 bytes (X25519 32 + Ed25519 32)"
    )
    # The recalled identity's own hash is truncated_hash(public_key) —
    # 16 bytes derived from the same public key the recall returned.
    assert len(recalled["hash"]) == 16


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "identity_recall"],
    verifies="Negative control: Identity.recall(unknown_hash) returns None — catches an impl that silently fabricates a stub Identity for hashes it has never seen announced, which would mis-route any subsequent outbound encryption",
)
def test_identity_recall_unknown_returns_none(wire_peers):
    """Recall of a never-announced destination hash returns None.
    Establish the TCP pair so the recall path is live, but skip the
    listen+announce so the destination is genuinely unknown.
    """
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    # 16 random bytes — a valid destination_hash structurally, but not
    # one any peer has announced in this test run.
    unknown_hash = secrets.token_bytes(16)
    recalled = client.identity_recall(unknown_hash, timeout_ms=0)
    assert recalled is None, (
        f"{client.role_label}.Identity.recall({unknown_hash.hex()}) "
        f"returned a non-None result for a never-announced destination "
        f"hash: {recalled!r}. A recall impl that fabricates Identities "
        f"for unknown hashes silently corrupts outbound encryption."
    )
