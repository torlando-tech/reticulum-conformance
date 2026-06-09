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
    commands=["start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path", "read_path_entry", "identity_recall"],
    verifies="After receiving an announce over a 1-hop link, RNS.Identity.recall(destination_hash) returns the announcing peer's real Identity whose public_key AND identity hash are byte-identical to the listening peer's announced identity (asserted against the identity wire_listen surfaces, not merely 64/16-byte length); the learned path is a deterministic 1 hop — the lookup every app does to bind a destination hash back to its underlying identity (Columba NomadNet handler, Sideband conversation routing, LXMF LXMessage source/destination resolution)",
)
def test_identity_recall_after_announce(wire_peers):
    """Peer A announces an IN destination; peer B recalls A's identity
    from the announce-populated known_destinations table and gets back
    A's exact public key (byte-for-byte, N-M3) and identity hash.
    """
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    # Server registers an IN destination and announces it. wire_listen
    # in the bridge automatically emits the announce after registration,
    # and surfaces the listening identity (hash + raw public_key) so the
    # recall below can be asserted byte-identical, not merely length-shaped.
    server_dest = server.listen(app_name=_APP, aspects=_ASPECTS)
    announced = server.listening_identity(server_dest)
    assert announced["public_key"] is not None, (
        f"wire_listen did not surface the listening identity's public_key "
        f"for {server_dest.hex()}; byte-identity recall (N-M3) is "
        f"unassertable. Update the bridge's wire_listen to return public_key."
    )

    # Client waits for the announce to land — Transport.has_path is the
    # observable proof. identity_recall's own timeout polls the same
    # state, so this poll is belt-and-suspenders.
    assert client.poll_path(server_dest, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — Identity.recall is untestable without the prior "
        f"announce reception."
    )

    # The announce traversed exactly one interface hop (A's TCP client ->
    # B's spawned child), so the learned path is deterministically 1 hop.
    # Asserting it (L15) catches an impl that mis-counts hops on a direct
    # link — which would mis-rank this path against any alternate route.
    entry = client.read_path_entry(server_dest)
    assert entry is not None and entry["hops"] == 1, (
        f"{client.role_label} learned a path to {server_dest.hex()} but "
        f"recorded hops={entry['hops'] if entry else None}; a direct "
        f"1-hop announce must store hops==1."
    )

    recalled = client.identity_recall(server_dest, timeout_ms=_POLL_TIMEOUT_MS)
    assert recalled is not None, (
        f"{client.role_label}.Identity.recall({server_dest.hex()}) "
        f"returned None despite has_path being True — the announce was "
        f"received but the receiver's known_destinations table is "
        f"missing the Identity that signed it."
    )
    # N-M3: byte-identity, not length. The recalled public_key must be the
    # SAME 64 bytes the server announced; a wrong-but-64-byte key (e.g. a
    # fabricated stub, or the wrong identity recalled for this hash) would
    # pass a length-only check but fail here.
    assert recalled["public_key"] == announced["public_key"], (
        f"recalled public_key for {server_dest.hex()} is not byte-identical "
        f"to the announced one. recalled={recalled['public_key'].hex()} "
        f"announced={announced['public_key'].hex()}. Identity.recall bound "
        f"the destination hash to the WRONG public key — outbound "
        f"encryption to this destination would go to the wrong key."
    )
    # The recalled identity's own hash is truncated_hash(public_key); it must
    # equal the hash of the identity the server announced.
    assert recalled["hash"] == announced["identity_hash"], (
        f"recalled identity hash {recalled['hash'].hex()} != announced "
        f"identity hash {announced['identity_hash'].hex()} for "
        f"{server_dest.hex()}."
    )


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
