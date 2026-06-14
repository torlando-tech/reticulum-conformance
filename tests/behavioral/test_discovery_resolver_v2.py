"""Blackhole V2 gap closure — the until=None (permanent) default.

The existing blackhole suite (test_blackhole_hooks.py) exercises reload/expiry
only with explicit future/past `until` floats, so the DEFAULT until=None path is
unobserved. until=None is the default of Transport.blackhole_identity and means
"never expires": on reload the entry is kept by the `until == None or now < until`
guard (Transport.py:3482), exactly the branch a reimpl that treats None as
already-expired (purging every default blackhole on reload/restart) would get
wrong. This test pins that default-blackhole permanence, contrasted against a
past-`until` entry that IS purged on reload.

Drives the REAL Transport.blackhole_identity / persist_blackhole /
reload_blackhole through the behavioral bridge and asserts on the live
blackholed_identities table. No blackhole logic is reimplemented; the harness
never serializes a blackhole list itself (persist_blackhole writes it). Anchored
on independent values: a freshly-minted identity hash and a chosen past timestamp.
"""

import secrets
import time

from conformance import conformance_case


__category_title__ = "Discovery / Resolver V2 (Behavioral)"
__category_order__ = 24


_IDENTITY_HASH_BYTES = 16  # Reticulum.TRUNCATED_HASHLENGTH//8


@conformance_case(
    commands=["start", "blackhole_identity", "blackhole_clear_storage",
              "blackhole_storage_files", "read_blackhole_table",
              "blackhole_clear", "blackhole_reload"],
    verifies=(
        "until=None is the DEFAULT of Transport.blackhole_identity (Transport.py:"
        "3407,3418) and means no expiry: the recorded entry's until is None, and "
        "after persist_blackhole + clearing the in-memory table, reload_blackhole "
        "RESTORES it because the reload guard is `until == None or now < until` "
        "(Transport.py:3482). A second entry whose until is in the PAST is NOT "
        "restored by the same reload — proving None is treated as permanent, not "
        "as already-expired. Anchored on independent minted identity hashes and a "
        "chosen past timestamp."
    ),
)
def test_blackhole_permanent_until_none(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        # Isolate the on-disk 'local' list to exactly the entries this test writes.
        inst.blackhole_clear_storage()

        permanent = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        expired = secrets.token_bytes(_IDENTITY_HASH_BYTES)
        past = float(int(time.time()) - 7200)

        # Default blackhole: no `until` supplied -> until is None (permanent).
        assert inst.blackhole_identity(permanent)["blackholed"] is True
        assert inst.blackhole_identity(expired, until=past)["blackholed"] is True

        # The recorded permanent entry's until is literally None.
        table = {e["identity_hash"]: e for e in inst.read_blackhole_table()["entries"]}
        assert table[permanent.hex()]["until"] is None, (
            "default blackhole entry must record until=None (Transport.py:3418)")

        # persist_blackhole wrote the locally-sourced list to 'local'.
        assert "local" in {f["name"] for f in inst.blackhole_storage_files()["files"]}

        # Drop the in-memory table, reload purely from disk.
        inst.blackhole_clear()
        assert inst.read_blackhole_table()["count"] == 0
        inst.blackhole_reload()

        reloaded = {e["identity_hash"]: e for e in inst.read_blackhole_table()["entries"]}
        # Positive: the until=None entry is permanent — restored on reload.
        assert permanent.hex() in reloaded, (
            "a default (until=None) blackhole entry was NOT restored by "
            "reload_blackhole — None is being treated as expired (Transport.py:3482)")
        assert reloaded[permanent.hex()]["until"] is None
        assert reloaded[permanent.hex()]["source"] == inst.identity_hash.hex()
        # Negative control: the past-`until` entry IS purged on reload.
        assert expired.hex() not in reloaded, (
            "a past-`until` entry was restored — the reload expiry guard is absent")
    finally:
        behavioral.cleanup()
