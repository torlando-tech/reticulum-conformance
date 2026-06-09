"""Forward-secrecy via ratchets — enforce_ratchets rejection + the
destination-level ratchet machinery apps actually drive.

Reticulum's forward secrecy outside a Link rests on ratchets: a destination
rotates a short-lived X25519 ratchet key, advertises the latest public ratchet
in its announces, and senders encrypt to that ratchet instead of the static
identity key. The guarantee only holds if the receiver REFUSES to fall back to
its static key when ratchet enforcement is on — `RNS.Identity.decrypt`
(Identity.py:897-901) returns None for a ciphertext none of the supplied
ratchets can decrypt *before* it would otherwise try the static key
(Identity.py:903-905). An implementation that silently ignores the
`enforce_ratchets` flag still decrypts every message (its tests stay green) yet
quietly loses forward secrecy — exactly the blind spot the conformance audit
flagged (CONFORMANCE_GAPS.md §4c: plumbing fully built, zero callers).

The discriminating property is the DIVERGENCE on a *single* ciphertext: the
same bytes + the same (non-matching) ratchet decrypt to the plaintext with
enforce_ratchets=False (the static fallback) but to None with
enforce_ratchets=True (the rejection). A positive control pins that
enforcement is not blanket — a ciphertext encrypted TO a ratchet is still
accepted when the matching ratchet private key is supplied.

This module also covers the destination-LEVEL ratchet path apps use, distinct
from the directly-tested Identity.encrypt(ratchet=...):

  * SINGLE outbound auto-ratchet selection + inbound latest_ratchet_id tracking
    (Destination.py:595-643): Destination.encrypt auto-selects the current
    ratchet and records latest_ratchet_id; decrypt re-derives it. It is None
    until a real encrypt/decrypt happens.
  * ratchet rotation-INTERVAL gating (Destination.py:227-241): rotate_ratchets
    only inserts a new ratchet once now > latest_ratchet_time + ratchet_interval.

The rotation interval is made observable WITHOUT real sleeps by deterministically
backdating the last-rotation timestamp through the bridge.

(Identity.get_ratchet RATCHET_EXPIRY gating, Identity.py:499-522, is NOT covered
here: get_ratchet only applies the expiry on the on-disk path, and RNS exposes no
API to write a ratchet file with a back-dated `received` timestamp — the only
writer, Identity._remember_ratchet, always stamps time.time(). Asserting it would
require the bridge to hand-build the on-disk msgpack format, which the delegation
audit correctly rejects; it remains a P2/clock-injection gap.)

Harness note: these destination-level commands are driven through
`peer.bridge.execute(...)` directly rather than the _WirePeer wrappers. The
existing wrappers diverge from the registered handlers (see the module-level
gaps recorded for this workflow): `listen(enable_ratchets=True)` is a no-op
(cmd_wire_listen ignores it — ratchet-bearing destinations come from
wire_announce(enable_ratchets=True)); `rotate_ratchet`/`destination_latest_
ratchet_id` read response keys the handlers don't emit (or call a command name
that isn't registered). Calling the registered commands directly keeps these
tests honest against the real RNS machinery.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["enforce-ratchets"]


def _start_ratchet_destination(peer, app_name=_APP, aspects=_ASPECTS):
    """Bring up a real RNS instance on `peer` and create a ratchet-ENABLED
    SINGLE destination via wire_announce(enable_ratchets=True).

    Enabling ratchets sets latest_ratchet_time=0; the immediate announce then
    rotate_ratchets() once (gate open, 0+interval < now) so the destination
    owns exactly one ratchet whose public key is remembered for itself
    (Destination.announce -> Identity._remember_ratchet). Returns the
    destination hash (bytes).

    enable_ratchets is honored by cmd_wire_announce (wire_tcp.py:853-890), NOT
    cmd_wire_listen, and the conftest `announce` wrapper has no enable_ratchets
    parameter — hence the direct execute.
    """
    peer.start_tcp_server(network_name="", passphrase="")
    resp = peer.bridge.execute(
        "wire_announce",
        handle=peer.handle,
        app_name=app_name,
        aspects=list(aspects),
        enable_ratchets=True,
    )
    assert resp.get("ratchets_enabled") is True, (
        f"wire_announce(enable_ratchets=True) did not enable ratchets on "
        f"{peer.role_label}: {resp!r}. The destination-level ratchet "
        f"observables require a ratchet-bearing destination."
    )
    assert int(resp.get("ratchet_count", 0)) >= 1, (
        f"a ratchet-enabled destination must own at least one ratchet after "
        f"announcing (announce rotates the first one); got {resp!r}."
    )
    return bytes.fromhex(resp["destination_hash"])


@conformance_case(
    commands=["identity_keypair", "ratchet_keypair", "identity_encrypt", "identity_decrypt"],
    verifies=(
        "enforce_ratchets forward-secrecy REJECTION (Identity.py:897-901, before "
        "the static fallback :903-905): a ciphertext encrypted to identity I's "
        "BASE key decrypts byte-exact to the plaintext with the base key alone, "
        "AND with a NON-matching ratchet when enforce_ratchets=False (the "
        "static-key fallback recovers it); but the SAME ciphertext + SAME "
        "wrong ratchet decrypts to None when enforce_ratchets=True. The "
        "divergence on one ciphertext with only the flag flipped is the "
        "property — an impl that ignores enforce_ratchets silently keeps the "
        "fallback and loses forward secrecy"
    ),
)
def test_enforce_ratchets_rejects_base_key_ciphertext(wire_peers):
    """Same base-key ciphertext: enforce=False -> plaintext (fallback),
    enforce=True -> None (rejection). Crypto commands are handle-free, so no
    interface needs to be started.
    """
    peer, _client = wire_peers
    ident = peer.identity_keypair()
    wrong = peer.ratchet_keypair()
    plaintext = b"forward-secrecy-probe-" + secrets.token_bytes(8)

    # Encrypt to I's BASE key (no ratchet) — what a non-ratcheting sender, or a
    # sender that never heard I's ratchet announce, produces.
    ciphertext = peer.identity_encrypt(ident["public_key"], plaintext)

    # Baseline: I's base private key decrypts its own base-key ciphertext.
    baseline = peer.identity_decrypt(ident["private_key"], ciphertext)
    assert baseline == plaintext, (
        f"base-key decryption of a base-key ciphertext must round-trip; "
        f"got {baseline!r} != {plaintext!r}."
    )

    # Positive control / fallback: a WRONG ratchet cannot decrypt, but with
    # enforce_ratchets=False RNS falls through to the static key and recovers
    # the plaintext.
    fallback = peer.identity_decrypt(
        ident["private_key"],
        ciphertext,
        ratchets=[wrong["private_key"]],
        enforce_ratchets=False,
    )
    assert fallback == plaintext, (
        f"with enforce_ratchets=False a non-matching ratchet must fall back to "
        f"the static key and recover the plaintext; got {fallback!r}. Without "
        f"this positive control the rejection below could be a no-op."
    )

    # Rejection: the SAME ciphertext + SAME wrong ratchet, only the flag
    # flipped -> the static fallback is refused and decryption returns None.
    rejected = peer.identity_decrypt(
        ident["private_key"],
        ciphertext,
        ratchets=[wrong["private_key"]],
        enforce_ratchets=True,
    )
    assert rejected is None, (
        f"with enforce_ratchets=True a ciphertext that no supplied ratchet can "
        f"decrypt MUST be rejected (return None) BEFORE the static-key "
        f"fallback; got {rejected!r}. This is forward secrecy — an impl that "
        f"still returns the plaintext here has silently disabled it."
    )


@conformance_case(
    commands=["identity_keypair", "ratchet_keypair", "identity_encrypt", "identity_decrypt"],
    verifies=(
        "enforce_ratchets positive control (Identity.py:891-901): with "
        "enforce_ratchets=True a ciphertext encrypted TO a ratchet public key "
        "IS decrypted byte-exact when the matching ratchet private key is "
        "supplied (enforcement is not blanket), while the SAME ciphertext under "
        "only a non-matching ratchet returns None — pinning that enforcement "
        "accepts iff one of the retained ratchets decrypts"
    ),
)
def test_enforce_ratchets_accepts_matching_ratchet(wire_peers):
    """A ratchet-encrypted ciphertext is accepted under enforce_ratchets=True
    with the matching ratchet, and rejected with only a wrong one.
    """
    peer, _client = wire_peers
    ident = peer.identity_keypair()
    good = peer.ratchet_keypair()
    wrong = peer.ratchet_keypair()
    plaintext = b"ratchet-encrypted-" + secrets.token_bytes(8)

    # Encrypt to the ratchet public key (forward-secret send).
    ciphertext = peer.identity_encrypt(
        ident["public_key"], plaintext, ratchet_pub=good["public_key"]
    )

    # enforce_ratchets=True + the matching ratchet private key -> accepted.
    accepted = peer.identity_decrypt(
        ident["private_key"],
        ciphertext,
        ratchets=[good["private_key"]],
        enforce_ratchets=True,
    )
    assert accepted == plaintext, (
        f"with enforce_ratchets=True a ciphertext encrypted to a ratchet MUST "
        f"decrypt when the matching ratchet private key is supplied; got "
        f"{accepted!r}. A blanket rejection would fail here — enforcement must "
        f"accept a message a retained ratchet can read."
    )

    # enforce_ratchets=True + only a non-matching ratchet -> rejected, even
    # though this ciphertext was NOT base-key encrypted.
    rejected = peer.identity_decrypt(
        ident["private_key"],
        ciphertext,
        ratchets=[wrong["private_key"]],
        enforce_ratchets=True,
    )
    assert rejected is None, (
        f"with enforce_ratchets=True a ratchet ciphertext that the supplied "
        f"(wrong) ratchet cannot decrypt MUST be rejected; got {rejected!r}."
    )


@conformance_case(
    commands=["start_tcp_server", "announce", "read_ratchets", "destination_latest_ratchet_id"],
    verifies=(
        "Destination SINGLE outbound auto-ratchet selection + inbound "
        "latest_ratchet_id tracking (Destination.py:595-643): a ratchet-enabled "
        "SINGLE destination has latest_ratchet_id == None until a real "
        "Destination.encrypt/decrypt happens; after one round trip encrypt "
        "auto-selected the current ratchet (latest_ratchet_id is non-None, "
        "equals the encrypt-time id, equals the current ratchet id, and equals "
        "the ratchet the announce created) and the packet decrypted — the "
        "ratchet path apps use, distinct from Identity.encrypt(ratchet=...)"
    ),
)
def test_destination_single_auto_ratchet_latest_id(wire_peers):
    """latest_ratchet_id is None before any encrypt, then tracks the current
    ratchet after a real Destination.encrypt/decrypt round trip.
    """
    server, _client = wire_peers
    dest_hash = _start_ratchet_destination(server)

    # Baseline: announce rotated a ratchet into existence (count >= 1) but no
    # encrypt/decrypt has run, so latest_ratchet_id is still None.
    before = server.bridge.execute(
        "wire_read_ratchets", handle=server.handle, destination_hash=dest_hash.hex()
    )
    assert before["latest_ratchet_id"] is None, (
        f"latest_ratchet_id must be None before any Destination.encrypt/decrypt; "
        f"got {before['latest_ratchet_id']!r}."
    )
    assert before["ratchet_count"] >= 1
    assert before["current_ratchet_id"] is not None

    # One real encrypt+decrypt round trip on the destination.
    r = server.bridge.execute(
        "wire_destination_latest_ratchet_id",
        handle=server.handle,
        destination_hash=dest_hash.hex(),
    )
    assert r["decrypted"] is True, (
        f"the auto-ratcheted Destination.encrypt/decrypt round trip must "
        f"recover the plaintext; got {r!r}."
    )
    assert r["latest_ratchet_id"] is not None, (
        f"after a real ratcheted encrypt/decrypt latest_ratchet_id MUST be set "
        f"(the SINGLE auto-ratchet path actually selected a ratchet); got None. "
        f"{r!r}"
    )
    assert r["encrypt_ratchet_id"] is not None
    # encrypt recorded a ratchet id and decrypt re-derived the SAME one.
    assert r["match"] is True, (
        f"the ratchet id selected at encrypt time must equal the one decrypt "
        f"re-derived; got encrypt={r['encrypt_ratchet_id']!r} "
        f"decrypt={r['latest_ratchet_id']!r}."
    )
    # The selected ratchet is the destination's current (newest) ratchet, which
    # is the one the announce created.
    assert r["latest_ratchet_id"] == r["current_ratchet_id"]
    assert r["latest_ratchet_id"] == before["current_ratchet_id"], (
        f"the auto-selected ratchet must be the one the destination announced; "
        f"selected={r['latest_ratchet_id']!r} announced="
        f"{before['current_ratchet_id']!r}."
    )
    assert r["ratchet_count"] >= 1


@conformance_case(
    commands=["start_tcp_server", "announce", "set_ratchet_interval", "rotate_ratchet"],
    verifies=(
        "Ratchet rotation-INTERVAL gating (Destination.py:227-241): with "
        "ratchet_interval set to 100s, a rotate attempt whose last-rotation "
        "timestamp is backdated 200s (> interval) inserts a NEW ratchet "
        "(after_count == before_count+1, the new current differs from the old "
        "and the old becomes previous); a rotate backdated only 50s (< interval) "
        "is gated and leaves the ratchet list and current id unchanged — "
        "deterministic via a backdated latest_ratchet_time, no real wait"
    ),
)
def test_ratchet_rotation_interval_gating(wire_peers):
    """rotate_ratchets inserts a ratchet only once the interval has elapsed;
    backdating latest_ratchet_time makes both sides of the gate observable.
    """
    server, _client = wire_peers
    dest_hash = _start_ratchet_destination(server)

    interval = server.bridge.execute(
        "wire_set_ratchet_interval",
        handle=server.handle,
        destination_hash=dest_hash.hex(),
        seconds=100,
    )
    assert interval["ok"] is True
    assert interval["ratchet_interval"] == 100

    # Eligible: last rotation 200s ago (> 100s interval) -> a new ratchet.
    elig = server.bridge.execute(
        "wire_rotate_ratchet",
        handle=server.handle,
        destination_hash=dest_hash.hex(),
        last_rotation_ago_s=200,
    )
    assert elig["rotated"] is True, (
        f"a rotate whose last rotation was 200s ago with a 100s interval must "
        f"insert a new ratchet; got {elig!r}."
    )
    assert elig["after_count"] == elig["before_count"] + 1, (
        f"an eligible rotation must grow the ratchet list by exactly one; "
        f"before={elig['before_count']} after={elig['after_count']}."
    )
    assert elig["current_ratchet_id"] != elig["before_current_id"], (
        f"an eligible rotation must produce a genuinely NEW current ratchet; "
        f"current still == previous-current ({elig['current_ratchet_id']!r})."
    )
    assert elig["previous_ratchet_id"] == elig["before_current_id"], (
        f"after rotation the prior current ratchet must become the previous; "
        f"previous={elig['previous_ratchet_id']!r} "
        f"prior-current={elig['before_current_id']!r}."
    )

    # Gated: last rotation only 50s ago (< 100s interval) -> NO new ratchet.
    gated = server.bridge.execute(
        "wire_rotate_ratchet",
        handle=server.handle,
        destination_hash=dest_hash.hex(),
        last_rotation_ago_s=50,
    )
    assert gated["rotated"] is False, (
        f"a rotate whose last rotation was only 50s ago with a 100s interval "
        f"must be gated (no new ratchet); got {gated!r}."
    )
    assert gated["after_count"] == gated["before_count"], (
        f"a gated rotation must leave the ratchet count unchanged; "
        f"before={gated['before_count']} after={gated['after_count']}."
    )
    assert gated["current_ratchet_id"] == elig["current_ratchet_id"], (
        f"a gated rotation must not change the current ratchet; "
        f"{gated['current_ratchet_id']!r} != {elig['current_ratchet_id']!r}."
    )
