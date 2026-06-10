"""Announce app_data None-vs-empty recall distinction (identity subsystem).

RNS's announce validator (RNS.Identity.validate_announce, Identity.py:542 +
:560-561) initialises the heard app_data to b"" and only overrides it to None
when the announce is a RATCHETLESS announce carrying no trailing app_data bytes:

    app_data = b""                                    # :542 / :554
    ...
    if not len(packet.data) > KEYSIZE + NAME_HASH + 10 + SIG:  # :560
        app_data = None                                        # :561

The length threshold on :560 is exactly the ratchetless no-app_data layout, so:

  * a RATCHETLESS announce with no app_data  -> recall_app_data() returns None
  * a RATCHETED  announce with no app_data  -> recall_app_data() returns b""
    (the announce is longer than the threshold because it carries the ratchet
    public key, so the b"" initialiser is never replaced with None)

This is a real, observable distinction every app inherits: a peer that has only
ever heard a ratchetless announce with no payload recalls None, whereas a
ratcheted one recalls an empty-but-present b"". An impl that collapses both to
None (or both to b"") loses it.

Because appending an empty app_data is a no-op on the wire
(Destination.announce, Destination.py: ``if app_data != None: announce_data +=
app_data``), an explicitly-sent empty app_data (b"") is byte-identical on the
wire to omitting it — so the recall result is governed solely by ratchet
presence, NOT by whether the announcer passed None or b"". Both arms are
exercised here.

Honest test: peer A announces fresh SINGLE destinations over a real 1-hop TCP
link; peer B receives them and calls RNS.Identity.recall, whose stored app_data
(== recall_app_data) is asserted against the spec rule above — never against the
implementation echoing itself.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["appdata-none-empty"]
_POLL_TIMEOUT_MS = 10000


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "poll_path", "identity_recall"],
    verifies="Announce None-vs-empty app_data recall distinction (Identity.validate_announce, Identity.py:542/:560-561): a RATCHETLESS announce carrying no app_data is recalled as None, whereas a RATCHETED announce carrying no app_data is recalled as an empty-but-present b\"\" (the announce exceeds the ratchetless length threshold because it carries the ratchet key, so the b\"\" initialiser is never nulled). An impl that collapses both cases to the same value loses a real observable distinction.",
)
def test_recall_app_data_none_vs_empty(wire_peers):
    """Ratchetless no-app_data recalls None; ratcheted no-app_data recalls b""."""
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    # Ratchetless announce, no app_data -> recall_app_data must be None.
    ratchetless_dest = server.announce(app_name=_APP, aspects=_ASPECTS)
    assert client.poll_path(ratchetless_dest, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to the ratchetless "
        f"destination {ratchetless_dest.hex()}; recall is untestable."
    )
    rl = client.identity_recall(ratchetless_dest, timeout_ms=_POLL_TIMEOUT_MS)
    assert rl is not None, (
        f"{client.role_label}.Identity.recall({ratchetless_dest.hex()}) "
        f"returned None despite the path being learned."
    )
    assert rl["app_data"] is None, (
        f"a ratchetless announce with no app_data must recall app_data=None "
        f"(Identity.py:561), got {rl['app_data']!r}. An impl that stores b\"\" "
        f"here cannot be distinguished from a ratcheted no-app_data announce."
    )

    # Ratcheted announce, no app_data -> recall_app_data must be b"" (present
    # but empty), NOT None: the announce carries a ratchet, so its length
    # exceeds the ratchetless threshold and the b"" initialiser survives.
    ratcheted_dest = server.announce(
        app_name=_APP, aspects=_ASPECTS, enable_ratchets=True,
    )
    assert client.poll_path(ratcheted_dest, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to the ratcheted "
        f"destination {ratcheted_dest.hex()}; recall is untestable."
    )
    rt = client.identity_recall(ratcheted_dest, timeout_ms=_POLL_TIMEOUT_MS)
    assert rt is not None, (
        f"{client.role_label}.Identity.recall({ratcheted_dest.hex()}) "
        f"returned None despite the path being learned."
    )
    assert rt["app_data"] == b"" and rt["app_data"] is not None, (
        f"a ratcheted announce with no app_data must recall an empty-but-"
        f"present b\"\" (Identity.py:542+:560), got {rt['app_data']!r}. The "
        f"recalled value must be empty bytes, distinct from the ratchetless "
        f"None case above."
    )

    # The discriminating cross-check: the two recalls must NOT be equal.
    assert rl["app_data"] != rt["app_data"], (
        f"ratchetless (None) and ratcheted (b\"\") no-app_data announces must "
        f"recall DISTINCT values; both came back as {rl['app_data']!r}."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "announce", "poll_path", "identity_recall"],
    verifies="An explicitly-sent EMPTY app_data (b\"\") is byte-identical on the wire to an omitted one (Destination.announce only appends app_data when it is not None, and appending b\"\" is a no-op), so the recall result is governed solely by ratchet presence: ratchetless+explicit-empty -> None, ratcheted+explicit-empty -> b\"\". This proves the None-vs-empty distinction is a wire/length property, not a property of which sentinel the announcer passed.",
)
def test_explicit_empty_app_data_matches_omitted(wire_peers):
    """Explicit b"" app_data recalls identically to omitting app_data: the
    distinction is driven by ratchet presence, not the announcer's sentinel."""
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    # Ratchetless, explicit empty app_data -> still recalls None (the empty
    # append is a no-op, so the wire bytes match the omitted case).
    rl_empty = server.announce(
        app_name=_APP, aspects=_ASPECTS, app_data_empty=True,
    )
    assert client.poll_path(rl_empty, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {rl_empty.hex()}."
    )
    rl = client.identity_recall(rl_empty, timeout_ms=_POLL_TIMEOUT_MS)
    assert rl is not None and rl["app_data"] is None, (
        f"ratchetless announce with EXPLICIT empty app_data must recall None "
        f"(empty app_data is a wire no-op, indistinguishable from omitted); "
        f"got {None if rl is None else rl['app_data']!r}."
    )

    # Ratcheted, explicit empty app_data -> recalls b"" exactly like the
    # ratcheted omitted case in the test above.
    rt_empty = server.announce(
        app_name=_APP, aspects=_ASPECTS, app_data_empty=True,
        enable_ratchets=True,
    )
    assert client.poll_path(rt_empty, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {rt_empty.hex()}."
    )
    rt = client.identity_recall(rt_empty, timeout_ms=_POLL_TIMEOUT_MS)
    assert rt is not None and rt["app_data"] == b"" and rt["app_data"] is not None, (
        f"ratcheted announce with EXPLICIT empty app_data must recall b\"\"; "
        f"got {None if rt is None else rt['app_data']!r}."
    )
