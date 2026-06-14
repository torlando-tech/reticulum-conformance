"""
Behavioral conformance tests for RNS Transport blackhole semantics.

These close gaps the rest of the suite leaves open around the blackhole
subsystem in RNS Transport.py / Discovery.py:

  * the /list request-handler response (the dict a remote `rnpath -L` fetch
    receives over a Link) and its per-entry {source, until, reason} schema,
  * removal of an already-learned path when its associated identity is
    blackholed (Transport.remove_blackholed_paths),
  * persistence to <configdir>/storage/blackhole and repopulation via
    Transport.reload_blackhole, including the expired-entry skip,
  * remote-source file naming (hex of the source identity hash), trusted-source
    gating, hex-name validation, and local-list precedence over a fetched list.

Every test drives the REAL RNS.Transport blackhole staticmethods + persistence
through the behavioral bridge and asserts on observables (the live
blackholed_identities table, the /list handler result, the on-disk storage
filenames, the path_table). No blackhole logic is reimplemented in the harness;
the harness never serializes a blackhole list itself — remote source files are
produced by renaming the file RNS's own persist_blackhole wrote.

Each rule is anchored on an INDEPENDENT value — the transport identity hash and
the until/reason the test itself chose, a spec literal read from RNS source, or
a source-identity hash the test minted — never impl-vs-itself, and is checked
positively AND negatively.
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    build_announce_from_destination,
)


__category_title__ = "Transport Blackhole Hooks"
__category_order__ = 21


# RNS spec literals, verified against the installed RNS 1.3.1 source:
_IDENTITY_HASH_BYTES = 16  # Reticulum.TRUNCATED_HASHLENGTH//8
_SOURCE_NAME_HEXLEN = 32   # (TRUNCATED_HASHLENGTH//8)*2, Transport.py:3456
# The exact per-entry keys the rnpath consumer reads off each blackhole entry
# (rnpath.py:186-188: entry["until"], entry["reason"], entry["source"]).
_ENTRY_KEYS = {"source", "until", "reason"}


# ---------------------------------------------------------------------------
# blackhole-list-response-format: Transport.blackhole_list_handler (the
# response_generator registered on the rnstransport.info.blackhole '/list'
# request destination, Transport.py:262/:3514) returns the live
# Transport.blackholed_identities dict. Each entry is
# {"source": <identity hash>, "until": <ts|None>, "reason": <str|None>}
# (Transport.blackhole_identity, Transport.py:3418) — the schema the remote
# `rnpath -L` consumer reads (rnpath.py:186-199).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "blackhole_identity", "unblackhole_identity",
              "read_blackhole_table", "blackhole_list_handler"],
    verifies=(
        "Transport.blackhole_list_handler — the /list request response_generator "
        "a remote rnpath fetch reaches — returns the live "
        "Transport.blackholed_identities object. After blackholing an identity "
        "with a chosen until + reason, that entry carries EXACTLY the three keys "
        "the rnpath consumer reads (source, until, reason): source == THIS "
        "transport's own identity hash (the locally-sourced marker, "
        "Transport.py:3418), until/reason == the independent values the test set. "
        "A never-blackholed identity is absent, and after unblackhole_identity the "
        "entry is removed — proving the list reflects real table membership, not a "
        "static fixture."
    ),
)
def test_blackhole_list_response_schema(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        ident = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        other = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        until = float(int(time.time()) + 7200)
        reason = "spam-source-evidence-42"

        assert inst.blackhole_identity(ident, until=until, reason=reason)["blackholed"] is True

        # The /list handler returns the live table object verbatim.
        lr = inst.blackhole_list_handler()
        assert lr["is_blackhole_table"] is True, (
            "blackhole_list_handler did not return the live "
            "Transport.blackholed_identities object — the /list response_generator "
            "contract is broken (Transport.py:3514)"
        )

        by_hash = {e["identity_hash"]: e for e in lr["entries"]}
        assert ident.hex() in by_hash, "blackholed identity missing from /list response"
        assert other.hex() not in by_hash, (
            "an identity that was never blackholed appears in the /list response — "
            "the list is not reflecting real table membership"
        )

        entry = by_hash[ident.hex()]
        present_keys = {k for k in _ENTRY_KEYS if entry.get(k) is not None or k in entry}
        assert present_keys == _ENTRY_KEYS, (
            f"blackhole entry keys {present_keys} != rnpath-consumer schema {_ENTRY_KEYS} "
            f"(rnpath.py:186-188)"
        )
        # source == this transport's OWN identity hash (independent anchor: the
        # hash returned by behavioral_start), until/reason == values we chose.
        assert entry["source"] == inst.identity_hash.hex(), (
            f"locally-blackholed entry source {entry['source']} != this transport "
            f"identity {inst.identity_hash.hex()} (Transport.py:3418)"
        )
        assert entry["until"] == until, f"until round-trip mismatch: {entry['until']} != {until}"
        assert entry["reason"] == reason, f"reason round-trip mismatch: {entry['reason']!r}"

        # read_blackhole_table must agree with the /list handler view.
        rt = inst.read_blackhole_table()
        assert {e["identity_hash"] for e in rt["entries"]} == {ident.hex()}

        # Negative: lifting the blackhole removes it from the /list response.
        assert inst.unblackhole_identity(ident)["lifted"] is True
        lr2 = inst.blackhole_list_handler()
        assert all(e["identity_hash"] != ident.hex() for e in lr2["entries"]), (
            "unblackholed identity still present in /list response — the handler is "
            "not reflecting live table membership"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# blackhole-path-removal: blackholing an identity drops any already-learned
# path_table entry whose associated identity is that identity
# (Transport.remove_blackholed_paths, Transport.py:3492, called from
# blackhole_identity). A DIFFERENT identity's path is untouched.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "identity_from_private_key", "read_path_table",
              "blackhole_identity"],
    verifies=(
        "After a valid announce establishes a path_table entry (hops==1), "
        "blackholing the announcing identity removes that path entry via "
        "Transport.remove_blackholed_paths (Transport.py:3492/:3420): the entry "
        "is gone. A second, non-blackholed identity's path learned the same way "
        "SURVIVES — proving removal is keyed on the blackholed identity (recalled "
        "from the destination hash) and is not a blanket path-table flush."
    ),
)
def test_blackhole_removes_existing_path(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        # Two distinct identities, each announces a SINGLE destination → path.
        bad_priv = secrets.token_bytes(64)
        bad_id_hash = bytes.fromhex(
            behavioral.bridge.execute(
                "identity_from_private_key", private_key=bad_priv.hex()
            )["hash"]
        )
        good_priv = secrets.token_bytes(64)

        bad_raw, bad_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=bad_priv,
            app_name="testapp", aspects=["victim"],
            emission_ts=1_000_004_000, wire_hops=0,
        )
        good_raw, good_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=good_priv,
            app_name="testapp", aspects=["bystander"],
            emission_ts=1_000_004_001, wire_hops=0,
        )
        inst.inject(iface, bad_raw)
        inst.inject(iface, good_raw)
        time.sleep(0.2)

        # Both paths must be learned first, else the removal assertion is vacuous.
        assert inst.read_path_table(bad_dest)["found"] is True, (
            "the to-be-blackholed identity's announce did not establish a path — "
            "removal assertion would be vacuous"
        )
        assert inst.read_path_table(good_dest)["found"] is True

        assert inst.blackhole_identity(bad_id_hash)["blackholed"] is True

        # Positive: the blackholed identity's path is removed.
        assert inst.read_path_table(bad_dest)["found"] is False, (
            "blackholing an identity did NOT remove its already-learned path entry "
            "(Transport.remove_blackholed_paths absent, Transport.py:3492)"
        )
        # Negative control: the other identity's path is untouched.
        assert inst.read_path_table(good_dest)["found"] is True, (
            "blackholing one identity removed an unrelated identity's path — removal "
            "is not keyed on the blackholed identity"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# blackhole-persistence-and-reload: blackhole_identity persists the local list
# to <configdir>/storage/blackhole/local (umsgpack, Transport.persist_blackhole
# :3531); reload_blackhole repopulates from it. An entry whose `until` is in the
# past is SKIPPED on reload (Transport.py:3482, `until == None or now < until`).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "blackhole_identity", "blackhole_storage_files",
              "read_blackhole_table", "blackhole_clear", "blackhole_reload"],
    verifies=(
        "blackhole_identity persists the locally-sourced list to the file named "
        "exactly 'local' under storage/blackhole (Transport.persist_blackhole, "
        "Transport.py:3531). After clearing the in-memory table, "
        "Transport.reload_blackhole repopulates a non-expired entry from that file "
        "with source == this transport's identity hash (the filename=='local' "
        "branch, Transport.py:3458). An entry whose `until` is already in the past "
        "is NOT reloaded (the `until == None or now < until` guard, "
        "Transport.py:3482) — expiry purge on reload. Anchored on independent "
        "values: the chosen identity hashes and a past-vs-future until."
    ),
)
def test_blackhole_persist_reload_and_expiry(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        live_id = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        expired_id = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        future = float(int(time.time()) + 7200)
        past = float(int(time.time()) - 7200)

        assert inst.blackhole_identity(live_id, until=future)["blackholed"] is True
        assert inst.blackhole_identity(expired_id, until=past)["blackholed"] is True

        # persist_blackhole wrote a file named exactly 'local'.
        files = {f["name"] for f in inst.blackhole_storage_files()["files"]}
        assert "local" in files, (
            f"persist_blackhole did not write the 'local' list file (saw {files}) — "
            f"Transport.persist_blackhole naming contract (Transport.py:3531)"
        )

        # Drop the in-memory table, then reload purely from disk.
        inst.blackhole_clear()
        assert inst.read_blackhole_table()["count"] == 0
        inst.blackhole_reload()

        reloaded = {e["identity_hash"]: e for e in inst.read_blackhole_table()["entries"]}
        # Positive: the non-expired entry comes back, sourced 'local' (== our hash).
        assert live_id.hex() in reloaded, (
            "a non-expired locally-persisted entry was NOT restored by "
            "reload_blackhole (Transport.py:3482)"
        )
        assert reloaded[live_id.hex()]["source"] == inst.identity_hash.hex(), (
            "reloaded local entry source != this transport identity hash — the "
            "filename=='local' source attribution is wrong (Transport.py:3458)"
        )
        # Negative: the past-`until` entry is purged on reload, not restored.
        assert expired_id.hex() not in reloaded, (
            "an entry whose `until` is in the past was reloaded — the expiry skip "
            "(Transport.py:3482) is absent"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# blackhole-remote-source-trust: reload_blackhole loads a fetched source list
# from a file named by the HEX of the source identity hash (Discovery writes
# RNS.hexrep(source.hash, delimit=False); reload validates len==32 + bytes.fromhex,
# Transport.py:3456-3465), only if that source is in Reticulum.blackhole_sources()
# (trusted-source gate, Transport.py:3463), and never overwrites a locally
# sourced entry (precedence, Transport.py:3473-3475).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "blackhole_identity", "blackhole_storage_files",
              "blackhole_rename_storage", "blackhole_set_sources",
              "blackhole_clear", "blackhole_reload", "read_blackhole_table"],
    verifies=(
        "reload_blackhole sources a remote/fetched blackhole list from a file "
        "named by the hex of the source identity hash (32 hex chars; "
        "Transport.py:3456-3460). The file RNS's own persist_blackhole wrote is "
        "renamed to a minted source-hash hex to stand in for a fetched list "
        "(the harness never serializes one). (1) When that source is TRUSTED "
        "(in Reticulum.blackhole_sources()), the entry loads with source == the "
        "filename-derived source hash. (2) When the source is NOT trusted, the "
        "file is skipped (Transport.py:3463). (3) A file whose name is not a "
        "valid 32-char hex source hash is skipped (len/hex validation). (4) A "
        "still-in-memory locally-sourced entry is NOT overwritten by the trusted "
        "remote copy (local precedence, Transport.py:3473-3475)."
    ),
)
def test_blackhole_remote_source_naming_and_trust(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        target = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        source_hash = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        source_name = source_hash.hex()
        assert len(source_name) == _SOURCE_NAME_HEXLEN

        # Blackhole target locally → persist writes 'local'; then repurpose that
        # RNS-produced file as a fetched list from `source_hash` by renaming it.
        assert inst.blackhole_identity(target, until=float(int(time.time()) + 7200))["blackholed"] is True
        names = {f["name"] for f in inst.blackhole_storage_files()["files"]}
        assert "local" in names
        inst.blackhole_rename_storage("local", source_name)

        # (1) Trusted source → entry loads, sourced by the filename hash.
        inst.blackhole_set_sources([source_hash])
        inst.blackhole_clear()
        inst.blackhole_reload()
        reloaded = {e["identity_hash"]: e for e in inst.read_blackhole_table()["entries"]}
        assert target.hex() in reloaded, (
            "a trusted remote source file was not loaded by reload_blackhole "
            "(Transport.py:3463 trusted-source gate)"
        )
        assert reloaded[target.hex()]["source"] == source_name, (
            "remote-sourced entry source != filename-derived source hash — the "
            "fetched-list source attribution is wrong (Transport.py:3481)"
        )

        # (2) Untrusted source → file is skipped entirely.
        inst.blackhole_set_sources([])
        inst.blackhole_clear()
        inst.blackhole_reload()
        assert inst.read_blackhole_table()["count"] == 0, (
            "a blackhole source file whose source is NOT in blackhole_sources() was "
            "loaded — the trusted-source gate is absent (Transport.py:3463)"
        )

        # (3) Invalid (non-hex / wrong-length) filename → skipped even if the
        # source were trusted. Rename to a name that fails len==32 validation.
        inst.blackhole_rename_storage(source_name, "not-a-valid-source-name")
        inst.blackhole_set_sources([source_hash])
        inst.blackhole_clear()
        inst.blackhole_reload()
        assert inst.read_blackhole_table()["count"] == 0, (
            "a file with an invalid (non-hex-source-hash) name was loaded — the "
            "filename validation is absent (Transport.py:3460-3461)"
        )

        # (4) Local precedence (isolated): a locally-sourced `target` is held in
        # memory AND a TRUSTED remote source file also lists `target`, with NO
        # 'local' file on disk. reload must keep the local entry, not overwrite it
        # with the remote copy. Re-blackhole writes a fresh 'local' file; rename it
        # OVER the remote name so the only file on disk is the (identical-content)
        # remote source list, while the in-memory entry stays locally sourced.
        inst.blackhole_rename_storage("not-a-valid-source-name", source_name)
        inst.blackhole_clear()
        assert inst.blackhole_identity(target, until=float(int(time.time()) + 7200))["blackholed"] is True
        assert inst.read_blackhole_table()["entries"][0]["source"] == inst.identity_hash.hex()
        inst.blackhole_rename_storage("local", source_name)  # only the remote file remains
        on_disk = {f["name"] for f in inst.blackhole_storage_files()["files"]}
        assert on_disk == {source_name}, f"expected only the remote source file, saw {on_disk}"
        inst.blackhole_set_sources([source_hash])
        inst.blackhole_reload()  # NOTE: memory NOT cleared — local entry must win
        after = {e["identity_hash"]: e for e in inst.read_blackhole_table()["entries"]}
        assert after[target.hex()]["source"] == inst.identity_hash.hex(), (
            "a locally-sourced blackhole entry was overwritten by a trusted remote "
            "source list — local precedence is absent (Transport.py:3473-3475)"
        )
    finally:
        behavioral.cleanup()
