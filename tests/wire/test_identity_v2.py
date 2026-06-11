"""Identity known-destinations table semantics — V2 gap closure.

Two behaviours the prior recall suite leaves untested, both keyed on the
receiver-side known_destinations table that RNS.Identity.recall reads
(Identity.py:101-159):

  * remember-update-refreshes-existing-entry — RNS.Identity.remember
    (Identity.py:106-113) UPDATES an existing entry in place when a SECOND
    announce arrives for an already-known destination: entry[3] (app_data)
    is overwritten with the newly-announced bytes. This is the mechanism by
    which a peer's changed display name / LXMF stamp blob propagates. The
    existing ratchet-replacement test proves a second announce is accepted
    and its RATCHET re-adopted, but never reads back the refreshed app_data;
    an impl that pinned the first app_data for a known destination (treating
    re-announces as no-ops once a destination is known) would pass every
    existing test yet silently freeze peer labels. Discriminator: announce
    with app_data A, recall == A; re-announce the SAME destination with a
    DIFFERENT app_data B, recall must converge to B (and B != A).

  * recall-local-registered-destination-fallback — RNS.Identity.recall
    (Identity.py:151-159) has a SECOND lookup stage: when a destination hash
    is NOT in known_destinations, it scans RNS.Transport.destinations and,
    if the hash matches a LOCALLY-registered destination, returns that
    destination's own identity (app_data None). An instance never receives
    its own announces, so a destination it registered is absent from its own
    known_destinations — the only way recall of one's own destination hash
    resolves is this fallback. LXMF source resolution on the announcing node
    depends on it. An impl that only consults known_destinations returns None
    here where Python RNS returns the local identity. Discriminator: register
    a destination, recall its hash on the SAME instance, get the local
    identity back (byte-identical public key); a never-registered random hash
    returns None.

Both tests anchor on the bytes/keys the test itself supplies (the app_data
literals, the registered identity's own announced public key), never on
impl-vs-itself output.
"""

import secrets
import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["identity-v2"]
_POLL_TIMEOUT_MS = 10000
_CONVERGE_TIMEOUT_S = 10.0

# Two distinct, present-and-non-empty app_data payloads. These stand in for a
# peer's display-name / label blob: the first announce carries A, a later
# announce changes it to B. B differs from A so "entry was refreshed" is not
# confusable with "entry never changed".
_APP_DATA_A = b"display-name-first"
_APP_DATA_B = b"display-name-CHANGED"


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "announce", "poll_path",
        "identity_recall", "reannounce",
    ],
    verifies=(
        "RNS.Identity.remember UPDATES an existing known_destinations entry in "
        "place on a re-announce (Identity.py:106-113: the else-branch overwrites "
        "entry[3]=app_data for an already-known destination). After B receives a "
        "first announce carrying app_data A, RNS.Identity.recall(dest).app_data "
        "== A; after A re-announces the SAME destination with a DIFFERENT "
        "app_data B (RNS.Destination.announce again, Destination.py:265-311), B's "
        "recall converges to B — byte-identical to the bytes A passed, and "
        "distinct from A. An impl that treats a re-announce of a KNOWN "
        "destination as a no-op (pinning the first app_data) never converges, so "
        "every peer's display-name/label change would be silently frozen"
    ),
)
def test_reannounce_refreshes_recalled_app_data(wire_peers):
    """A announces dest with app_data A; B recalls A. A re-announces the SAME
    dest with app_data B; B's recall must update to B (entry refreshed, not
    pinned).
    """
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    # First announce carries app_data A. wire_announce registers the destination
    # (so reannounce can find it) and passes app_data straight to announce().
    dest_hash = server.announce(
        app_name=_APP, aspects=_ASPECTS, app_data=_APP_DATA_A,
    )
    assert client.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {dest_hash.hex()} — the "
        f"first announce was not received, so the refresh cannot be observed."
    )

    first = client.identity_recall(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert first is not None and first["app_data"] == _APP_DATA_A, (
        f"after the first announce, recalled app_data for {dest_hash.hex()} is "
        f"{first['app_data'] if first else None!r}, expected {_APP_DATA_A!r}; "
        f"the baseline known_destinations write did not store the announced "
        f"app_data, so the refresh below is unassertable."
    )

    # A re-announces the SAME registered destination with a DIFFERENT app_data.
    # No ratchet rotation needed — the plain re-announce produces a new announce
    # packet whose validate_announce -> remember() overwrites entry[3].
    re = server.reannounce(dest_hash, app_data=_APP_DATA_B)
    assert re["announced"], (
        f"re-announce of {dest_hash.hex()} did not fire: {re!r}"
    )

    # B must converge on the NEW app_data. recall reads the in-place-updated
    # entry; poll until the second announce has been processed.
    deadline = time.time() + _CONVERGE_TIMEOUT_S
    refreshed = first
    while time.time() < deadline:
        refreshed = client.identity_recall(dest_hash, timeout_ms=0)
        if refreshed is not None and refreshed["app_data"] == _APP_DATA_B:
            break
        time.sleep(0.1)

    assert refreshed is not None and refreshed["app_data"] == _APP_DATA_B, (
        f"after re-announcing {dest_hash.hex()} with new app_data {_APP_DATA_B!r}, "
        f"recalled app_data is still {refreshed['app_data'] if refreshed else None!r} "
        f"— RNS.Identity.remember did not refresh the existing entry's app_data. "
        f"A peer changing its display name would never propagate."
    )
    # The refreshed value must genuinely differ from the first; this rules out a
    # test that would pass if remember had simply kept A (A != B by construction).
    assert refreshed["app_data"] != _APP_DATA_A, (
        f"recalled app_data did not change from the first announce ({_APP_DATA_A!r}); "
        f"the entry was pinned, not refreshed."
    )
    # The recalled public key must remain the announcer's key across the refresh
    # (entry[2] is rewritten with the same key); a refresh must not rebind the
    # destination to a different identity.
    assert refreshed["public_key"] == first["public_key"], (
        f"recalled public_key changed across the app_data refresh for "
        f"{dest_hash.hex()}: {first['public_key'].hex()} -> "
        f"{refreshed['public_key'].hex()}; the same destination must keep its key."
    )


@conformance_case(
    commands=["start_tcp_server", "listen", "identity_recall"],
    verifies=(
        "RNS.Identity.recall's locally-registered-destination fallback "
        "(Identity.py:151-159): a destination hash absent from known_destinations "
        "is matched against RNS.Transport.destinations, and when it equals a "
        "LOCALLY-registered destination's hash, recall returns that destination's "
        "own Identity (load_public_key(registered.identity.get_public_key()), "
        "app_data None). An instance never receives its own announces, so its own "
        "registered destination is NOT in its known_destinations — this fallback "
        "is the ONLY path by which recall of one's own destination hash resolves "
        "(LXMF source resolution on the announcing node relies on it). The "
        "recalled public key is byte-identical to the registered identity's, and "
        "a never-registered random hash returns None. An impl that consults only "
        "known_destinations returns None for its own destination and breaks "
        "self-resolution"
    ),
)
def test_recall_local_registered_destination_fallback(wire_peers):
    """Recall of a locally-registered (never-received-by-self) destination
    resolves to the local identity via the Transport.destinations fallback;
    an unregistered hash returns None.
    """
    server, _client = wire_peers
    # A running instance is required to register an IN destination; no peer is
    # connected, so the immediate announce goes nowhere and is never received
    # back — the registered destination stays out of this instance's own
    # known_destinations, forcing recall down the Transport.destinations fallback.
    server.start_tcp_server(network_name="", passphrase="")

    dest_hash = server.listen(app_name=_APP, aspects=_ASPECTS)
    registered = server.listening_identity(dest_hash)
    assert registered["public_key"] is not None, (
        f"wire_listen did not surface the registered identity's public_key for "
        f"{dest_hash.hex()}; the byte-identity fallback assertion is unassertable."
    )

    # timeout_ms=0: the fallback resolves synchronously off Transport.destinations
    # (no announce reception / path needed), so a single recall call suffices.
    recalled = server.identity_recall(dest_hash, timeout_ms=0)
    assert recalled is not None, (
        f"recall of locally-registered {dest_hash.hex()} on the SAME instance "
        f"returned None — the destination is absent from this instance's "
        f"known_destinations (own announces are never received), so an impl "
        f"lacking the Transport.destinations fallback fails to self-resolve."
    )
    # Byte-identity, not length: the fallback must return THIS destination's
    # registered identity, not a fabricated stub.
    assert recalled["public_key"] == registered["public_key"], (
        f"fallback recall of {dest_hash.hex()} bound to the WRONG public key: "
        f"got {recalled['public_key'].hex()}, expected "
        f"{registered['public_key'].hex()}."
    )
    assert recalled["hash"] == registered["identity_hash"], (
        f"fallback-recalled identity hash {recalled['hash'].hex()} != the "
        f"registered identity hash {registered['identity_hash'].hex()}."
    )
    # The fallback branch sets app_data = None explicitly (Identity.py:156),
    # distinct from the known_destinations branch which would surface a stored
    # app_data — proving this resolved via the local-registration fallback.
    assert recalled["app_data"] is None, (
        f"fallback recall of {dest_hash.hex()} surfaced app_data "
        f"{recalled['app_data']!r}; the local-registration fallback returns "
        f"app_data None (the entry came from Transport.destinations, not a "
        f"received announce)."
    )

    # Negative control: a random hash that was never registered nor announced
    # is in neither known_destinations NOR Transport.destinations -> None.
    unknown_hash = secrets.token_bytes(16)
    assert server.identity_recall(unknown_hash, timeout_ms=0) is None, (
        f"recall of never-registered {unknown_hash.hex()} returned non-None; the "
        f"fallback must only resolve hashes of actually-registered destinations."
    )
