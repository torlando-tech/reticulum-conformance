"""Identity known-destinations / received-ratchet persistence — V2 gap closure.

Four behaviours the prior recall/ratchet suites leave untested. The first two
key on the receiver-side known_destinations table that RNS.Identity.recall reads
(Identity.py:101-159); the last two on the IDENTITY-side on-disk stores
(received-ratchet files and the known_destinations table) round-tripped through
RNS's own serializer (no bridge-side msgpack):

  * remember-update-refreshes-existing-entry — re-announce updates the recalled
    app_data in place (test_reannounce_refreshes_recalled_app_data).
  * recall-local-registered-destination-fallback — recall of a locally-registered
    destination resolves via Transport.destinations
    (test_recall_local_registered_destination_fallback).
  * ratchet-persistence-format — the IDENTITY-side received-ratchet file
    (_remember_ratchet atomic write -> cold-cache get_ratchet load -> _clean_ratchets
    not-in-use cleanup); the RATCHET_EXPIRY/size-rejection sub-rules are deferred
    (LIMITS.md) (test_identity_received_ratchet_persistence).
  * known-destinations-persistence — the whole-table save/recombine/load round-trip
    and 5-element record shape; the 16-byte-key-skip / legacy upgrade load branches
    are deferred (LIMITS.md) (test_known_destinations_save_reload_roundtrip).

The first two, keyed on the receiver-side known_destinations table that
RNS.Identity.recall reads (Identity.py:101-159):

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

import pytest

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


# RATCHETSIZE is 256 bits (RNS spec constant, Identity.py:64); the persisted /
# accepted ratchet length is therefore exactly 32 bytes. Anchored here as an
# external literal, independent of whatever the bridge echoes back.
_RATCHET_BYTES = 32


@conformance_case(
    commands=["start_tcp_server", "identity_ratchet_persist"],
    verifies=(
        "IDENTITY-side received-ratchet persistence (RNS.Identity._remember_ratchet "
        "/ get_ratchet / _clean_ratchets, Identity.py:424-522), the receiver path "
        "distinct from the DESTINATION's own signed store: (1) _remember_ratchet "
        "writes the ratchet to a temp '<hash>.out' then os.replace's it to the "
        "final '<hash>' path (ATOMIC temp-file write, Identity.py:445-449) — the "
        "final file exists and no '.out' temp is left behind; (2) get_ratchet "
        "loads the on-disk {ratchet, received} msgpack back BYTE-IDENTICALLY when "
        "the in-memory cache is cold, and the accepted ratchet length is "
        "RATCHETSIZE//8 == 32 bytes (Identity.py:508); (3) _clean_ratchets removes "
        "a ratchet file whose destination is NOT in known_destinations (the "
        "not-in-use housekeeping branch, Identity.py:484-489). The bridge never "
        "builds or parses the on-disk msgpack — RNS's own writer+reader round-trip "
        "it. The RATCHET_EXPIRY (received+30d) back-dating branch needs a "
        "clock-injection API RNS does not expose and is deferred (LIMITS.md)"
    ),
)
def test_identity_received_ratchet_persistence(wire_peers):
    """A received ratchet round-trips through RNS's IDENTITY-side on-disk store
    (atomic write -> cold-cache reload, byte-identical, 32 bytes), and the
    not-in-use file is cleaned. The bridge only inspects the file via os.path;
    RNS writes and reads the msgpack.
    """
    server, _client = wire_peers
    # A running instance gives RNS a real storagepath for the ratchets dir.
    server.start_tcp_server(network_name="", passphrase="")

    res = server.identity_ratchet_persist()

    # (1) Atomic temp-file write: the final ratchet file landed and no '.out'
    # temp survived the os.replace.
    assert res["file_written"], (
        f"_remember_ratchet did not produce the final ratchet file for "
        f"{res['dest_hash']}; the IDENTITY-side received-ratchet store never "
        f"persisted (atomic temp-file write path, Identity.py:445-449)."
    )
    assert not res["tmp_leftover"], (
        f"a '.out' temp ratchet file for {res['dest_hash']} survived; the write "
        f"must os.replace the temp to the final path, leaving no temp behind."
    )

    # The persisted material is genuine 32-byte (RATCHETSIZE//8) ratchet bytes.
    assert res["ratchet_len"] == _RATCHET_BYTES, (
        f"persisted ratchet length is {res['ratchet_len']}, expected "
        f"{_RATCHET_BYTES} (RATCHETSIZE//8); a wrong size would be rejected on "
        f"load (Identity.py:508 len==RATCHETSIZE//8 check)."
    )
    assert res["accepted_size"] == _RATCHET_BYTES, (
        f"RNS's accepted-on-load ratchet size is {res['accepted_size']}, expected "
        f"{_RATCHET_BYTES} (RATCHETSIZE//8)."
    )

    # (2) Cold-cache load round-trip: get_ratchet read the on-disk msgpack and
    # returned the SAME 32 bytes _remember_ratchet wrote.
    assert res["reload_match"], (
        f"get_ratchet did not reload the persisted ratchet for {res['dest_hash']} "
        f"byte-identically from disk; the IDENTITY-side {{ratchet, received}} "
        f"on-disk format did not round-trip through RNS's own writer+reader."
    )
    assert res["reloaded_len"] == _RATCHET_BYTES, (
        f"reloaded ratchet length is {res['reloaded_len']}, expected "
        f"{_RATCHET_BYTES}."
    )

    # (3) _clean_ratchets not-in-use housekeeping: the random dest hash is absent
    # from known_destinations, so its ratchet file is removed.
    assert res["cleaned_removed"], (
        f"_clean_ratchets left the ratchet file for {res['dest_hash']} in place; "
        f"a file whose destination is not in known_destinations must be removed "
        f"(not-in-use branch, Identity.py:484-489)."
    )


# known_destinations entries are 5-element records [time, packet_hash,
# public_key, app_data, used_marker] (RNS spec, Identity.py:107). Anchored as an
# external literal.
_KNOWN_DEST_ENTRY_ELEMENTS = 5


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "announce", "poll_path",
        "identity_recall", "known_destinations_roundtrip",
    ],
    verifies=(
        "On-disk known_destinations persistence (RNS.Identity.save_known_destinations "
        "/ load_known_destinations, Identity.py:176-265): after B receives an "
        "announce carrying app_data, B saves the table to "
        "{storagepath}/known_destinations (whole-table umsgpack, recombining disk "
        "entries), CLEARS its in-memory table — recall then MISSES (the received "
        "dest is not locally registered, so the Transport.destinations fallback "
        "cannot resolve it) — and RELOADS from disk: recall HITS again with "
        "byte-identical app_data and a 5-element entry [time, packet_hash, "
        "public_key, app_data, used_marker]. The bridge never builds or parses the "
        "on-disk msgpack — RNS's own writer+reader round-trip it. An impl whose "
        "save/load drops or reshapes the record would fail the reload or the entry "
        "shape. (The 16-byte-key-skip and legacy 4->5-element upgrade load branches "
        "need a hand-built malformed file and are deferred, LIMITS.md.)"
    ),
)
def test_known_destinations_save_reload_roundtrip(wire_peers, wire_pair):
    """B persists, clears, and reloads its known_destinations table; a received
    destination survives the disk round-trip byte-identically as a 5-element
    record. The clear proving the reload (not residual memory) restores it.
    """
    server, client = wire_peers
    server_impl, client_impl = wire_pair
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    dest_hash = server.announce(
        app_name=_APP, aspects=_ASPECTS, app_data=_APP_DATA_A,
    )
    assert client.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {dest_hash.hex()} — the "
        f"announce was not received, so there is nothing to persist."
    )
    # Make sure the entry is genuinely in B's known_destinations before saving.
    pre = client.identity_recall(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert pre is not None and pre["app_data"] == _APP_DATA_A, (
        f"{client.role_label} did not learn the announced app_data for "
        f"{dest_hash.hex()} before the persistence round-trip: {pre!r}."
    )

    rt = client.known_destinations_roundtrip(dest_hash)

    assert rt["present_before_save"], (
        f"{dest_hash.hex()} was not in {client.role_label}'s known_destinations "
        f"before the save — the received announce never populated the table."
    )
    # The clear must actually empty the entry: recall misses on the cleared table.
    # This proves the reload (not leftover memory) is what restores it below.
    assert not rt["recall_after_clear_found"], (
        f"after clearing the in-memory table, recall of {dest_hash.hex()} still "
        f"found an entry — the clear did not take, so the reload assertion would "
        f"not prove on-disk persistence."
    )
    # The reload from disk restores the entry.
    assert rt["recall_after_load_found"], (
        f"after reloading known_destinations from disk, recall of {dest_hash.hex()} "
        f"missed — save/load did not persist the received destination."
    )
    # Byte-identical app_data survived the umsgpack round-trip.
    app_after = (
        bytes.fromhex(rt["app_data_after_load"])
        if rt["app_data_after_load"] is not None else None
    )
    assert app_after == _APP_DATA_A, (
        f"reloaded app_data for {dest_hash.hex()} is {app_after!r}, expected "
        f"{_APP_DATA_A!r}; the on-disk record garbled the app_data field."
    )
    # The persisted record is the canonical 5-element shape. The reference arm
    # has already pinned every behaviour above (presence, clear, reload, and
    # byte-identical app_data round-trip); only the 5th `used` LRU marker is the
    # kotlin gap, so xfail the kotlin client arm here, immediately before the
    # entry-shape assertion that the gap breaks.
    if client_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#known-destinations-used-marker: IdentityData is a "
            "4-field record and lacks the 5th `used` LRU marker RNS 1.3.1 stores "
            "([time,packet_hash,public_key,app_data,used], Identity.py:107); the "
            "bridge honestly reports 4."
        )
    assert rt["entry_len_after_load"] == _KNOWN_DEST_ENTRY_ELEMENTS, (
        f"reloaded known_destinations entry for {dest_hash.hex()} has "
        f"{rt['entry_len_after_load']} elements, expected "
        f"{_KNOWN_DEST_ENTRY_ELEMENTS} [time, packet_hash, public_key, app_data, "
        f"used_marker]."
    )
