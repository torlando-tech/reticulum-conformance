"""Destination-protocol wire tests (CONFORMANCE_GAPS.md §4c).

Closes the remaining Identity / Destination coverage gaps that need two live
Reticulum instances (or a single live instance) rather than byte-vector
fixtures:

  * Proof-strategy ACTUAL emission for a single (non-link) packet — a receiver
    set to PROVE_ALL returns a PROOF that validates against its public key and
    whose implicit/explicit form matches RNS.should_use_implicit_proof();
    PROVE_NONE returns none (Transport.py:2158, Destination.py:359-368,
    Identity.py:959-970).
  * PLAIN-destination no-op encrypt/decrypt (Destination.py:592-593/:618-619).
  * Known-public-key mismatch rejection in validate_announce
    (Identity.py:583-589).
  * create_keys randomness — independently generated identities are distinct.
  * Destination retained-ratchets RATCHET_COUNT cap (Destination.py:504-517)
    and the on-disk ratchet-file persistence format round-trip
    (Destination.py:210-225/:426-464).

These run reference-vs-reference (no SUT binary required); the wire_pair
parametrization collapses to (reference, reference) under --reference-only.

Every bridge command is driven through its _WirePeer wrapper
(send_packet_with_proof_request, known_key_validate, announce(enable_ratchets=
True), set_retained_ratchets, rotate_ratchet, ratchet_file_roundtrip); each
forwards to the matching registered wire_* command and surfaces exactly the
response fields these tests assert on.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["destination-protocol"]
_PATH_POLL_TIMEOUT_MS = 10000

# RNS 1.3.1 known-answers, pinned here (the wire harness never imports RNS; the
# bridge subprocess is the only RNS-aware component).
_RATCHET_COUNT = 512           # RNS.Destination.RATCHET_COUNT (retained cap)
_PUBLIC_KEY_LEN = 64           # RNS.Identity.KEYSIZE//8 (X25519 32 + Ed25519 32)
_PRIVATE_KEY_LEN = 64          # X25519 priv 32 + Ed25519 priv 32
_HASH_LEN = 16                 # RNS.Identity TRUNCATED_HASHLENGTH//8


# ---------------------------------------------------------------------------
# Proof-strategy ACTUAL emission (single, non-link packet)
# ---------------------------------------------------------------------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "set_proof_strategy", "send_packet_with_proof_request",
    ],
    verifies=(
        "Single-packet PROOF emission per Destination proof strategy "
        "(Transport.py:2158, Destination.py:359-368, Identity.py:959-970): with "
        "the receiver destination set to PROVE_ALL a single SINGLE-destination "
        "DATA packet sent with a tracked PacketReceipt gets a PROOF back that "
        "validates against the receiver public key (receipt.proved True and the "
        "receipt reaches DELIVERED), and the returned proof form matches "
        "RNS.Reticulum.should_use_implicit_proof() — proof_is_implicit equals "
        "the implicit-proof config and proof_is_explicit its negation, exactly "
        "one form is set, and proof_len equals the matching IMPL_LENGTH/"
        "EXPL_LENGTH. With PROVE_NONE on the SAME destination no proof returns: "
        "the receipt is neither proved nor DELIVERED and no proof bytes are "
        "captured. PROVE_ALL is the positive control for the PROVE_NONE negative."
    ),
)
def test_single_packet_proof_emitted_under_prove_all_not_under_prove_none(
    wire_link_setup,
):
    # wire_link_setup brings up the TCP pair, has the client learn a path to the
    # server's SINGLE destination (poll_path) — which also recalls the server
    # identity, the precondition send_packet_with_proof_request needs — and
    # opens a link. The single-packet proof path is independent of that link.
    server, client, dest_hash, _link_id = wire_link_setup(_APP, _ASPECTS)

    # send_packet_with_proof_request surfaces the full proof read-back
    # (proof_data / proved / proof_is_implicit / implicit_proof_config /
    # impl_length / expl_length) straight off the real PacketReceipt.
    def _proof(strategy, timeout_ms):
        server.set_proof_strategy(dest_hash, strategy)
        return client.send_packet_with_proof_request(
            dest_hash,
            data=secrets.token_bytes(20),
            app_name=_APP,
            aspects=list(_ASPECTS),
            timeout_ms=timeout_ms,
        )

    # PROVE_ALL: a PROOF returns, validates, and the receipt reaches DELIVERED.
    allr = _proof("all", timeout_ms=8000)
    assert allr["sent"] is True, f"packet was not sent: {allr!r}"
    assert allr["delivered"] is True, (
        f"PROVE_ALL: the receiver must prove the single DATA packet so the "
        f"sender's receipt reaches DELIVERED, got {allr!r}"
    )
    assert allr["proved"] is True, (
        f"PROVE_ALL: the returned PROOF must validate against the receiver "
        f"public key (receipt.proved), got {allr!r}"
    )
    assert allr["proof_data"] is not None and allr["proof_len"], (
        f"PROVE_ALL: a non-empty proof must have been captured, got {allr!r}"
    )

    # The proof FORM matches should_use_implicit_proof() — and exactly one form.
    cfg_implicit = allr["implicit_proof_config"]
    assert allr["proof_is_implicit"] == cfg_implicit, (
        f"proof form must match should_use_implicit_proof()={cfg_implicit}, "
        f"got proof_is_implicit={allr['proof_is_implicit']!r}"
    )
    assert allr["proof_is_explicit"] == (not cfg_implicit), (
        f"proof_is_explicit must be the negation of the implicit config, got "
        f"{allr!r}"
    )
    assert allr["proof_is_implicit"] != allr["proof_is_explicit"], (
        f"a proof is implicit XOR explicit, never both/neither: {allr!r}"
    )
    expected_len = allr["impl_length"] if cfg_implicit else allr["expl_length"]
    assert allr["proof_len"] == expected_len, (
        f"proof_len must equal the configured form's length ({expected_len}), "
        f"got {allr['proof_len']!r}"
    )

    # PROVE_NONE on the same destination: no proof, so the receipt cannot
    # deliver. (The PROVE_ALL delivery above proves the return path works, so
    # this non-delivery is a meaningful negative, not a dead path.)
    noner = _proof("none", timeout_ms=3000)
    assert noner["sent"] is True, f"packet was not sent: {noner!r}"
    assert noner["delivered"] is False, (
        f"PROVE_NONE: the receiver must NOT prove the packet, so the receipt "
        f"must never reach DELIVERED, got {noner!r}"
    )
    assert noner["proved"] is False, (
        f"PROVE_NONE: receipt.proved must stay False, got {noner!r}"
    )
    assert noner["proof_data"] is None, (
        f"PROVE_NONE: no proof bytes must be captured, got {noner!r}"
    )


# ---------------------------------------------------------------------------
# PLAIN destination no-op encrypt / decrypt
# ---------------------------------------------------------------------------

@conformance_case(
    commands=["start_tcp_server", "plain_encrypt", "plain_decrypt"],
    verifies=(
        "PLAIN-destination encrypt/decrypt are identity no-ops "
        "(Destination.py:592-593/:618-619): Destination.encrypt(pt) on a PLAIN "
        "destination returns pt unchanged (ciphertext byte-identical to "
        "plaintext) and Destination.decrypt(ct) returns ct unchanged, for both "
        "a random 48-byte payload and the empty payload. The asserted property "
        "is encrypt(pt)==pt and decrypt(ct)==ct (passthrough), not merely a "
        "round-trip."
    ),
)
def test_plain_destination_encrypt_decrypt_are_passthrough(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")

    payload = secrets.token_bytes(48)
    # encrypt(pt) == pt: a real SINGLE/GROUP encrypt would NOT equal the
    # plaintext (it prepends ephemeral key material / IV + AEAD tag).
    ciphertext = server.plain_encrypt(payload, app_name=_APP, aspects=_ASPECTS)
    assert ciphertext == payload, (
        f"PLAIN encrypt must be a no-op passthrough: ciphertext != plaintext "
        f"({ciphertext.hex()} != {payload.hex()})"
    )
    # decrypt(ct) == ct, independent of the encrypt call above.
    plaintext = server.plain_decrypt(ciphertext, app_name=_APP, aspects=_ASPECTS)
    assert plaintext == ciphertext, (
        f"PLAIN decrypt must be a no-op passthrough: plaintext != ciphertext "
        f"({plaintext.hex()} != {ciphertext.hex()})"
    )

    # Empty payload: still a passthrough (no framing is added).
    assert server.plain_encrypt(b"", app_name=_APP, aspects=_ASPECTS) == b""
    assert server.plain_decrypt(b"", app_name=_APP, aspects=_ASPECTS) == b""


# ---------------------------------------------------------------------------
# Known-public-key mismatch rejection (validate_announce)
# ---------------------------------------------------------------------------

@conformance_case(
    commands=["start_tcp_server", "known_key_validate"],
    verifies=(
        "Known-public-key mismatch rejection (RNS.Identity.validate_announce, "
        "Identity.py:583-589): a genuinely-signed announce is REJECTED "
        "(validate_announce returns False) when the destination hash is already "
        "bound to a DIFFERENT public key (plant='mismatch', planted key != the "
        "announce's own key), but ACCEPTED when the same key is already known "
        "(plant='match' -> True) or no key is known yet (plant='none' -> True). "
        "The identical announce flips accept/reject solely on the stored key; "
        "match and none are the positive controls for the mismatch rejection."
    ),
)
def test_validate_announce_rejects_known_key_mismatch(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")

    def _validate(plant):
        return server.known_key_validate(
            app_name=_APP, aspects=list(_ASPECTS), plant=plant
        )

    mismatch = _validate("mismatch")
    assert mismatch["validated"] is False, (
        f"a valid announce whose key differs from the known key for its hash "
        f"must be REJECTED, got {mismatch!r}"
    )
    # The divergence is purely the stored key: the announce's own key is valid,
    # the planted key is a different valid key.
    assert mismatch["planted_public_key"] is not None
    assert mismatch["planted_public_key"] != mismatch["public_key"], (
        f"the mismatch case must plant a DIFFERENT key than the announce's own, "
        f"got {mismatch!r}"
    )

    match = _validate("match")
    assert match["validated"] is True, (
        f"a re-announce with the SAME known key must be accepted, got {match!r}"
    )
    assert match["planted_public_key"] == match["public_key"], (
        f"the match case must plant the announce's own key, got {match!r}"
    )

    none = _validate("none")
    assert none["validated"] is True, (
        f"a first announce (no key known yet) must be accepted, got {none!r}"
    )
    assert none["planted_public_key"] is None, (
        f"the none case must not plant any key, got {none!r}"
    )


# ---------------------------------------------------------------------------
# create_keys randomness
# ---------------------------------------------------------------------------

@conformance_case(
    commands=["start_tcp_server", "identity_keypair"],
    verifies=(
        "create_keys randomness (RNS.Identity()): three independently generated "
        "identities have pairwise-distinct private keys, public keys, and "
        "identity hashes (no key reuse or deterministic collision). Each public "
        "and private key is 64 bytes (KEYSIZE 512 bits = X25519 32 + Ed25519 "
        "32) and each identity hash is 16 bytes (TRUNCATED_HASHLENGTH 128 bits)."
    ),
)
def test_create_keys_yields_distinct_identities(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")

    kps = [server.identity_keypair() for _ in range(3)]

    privs = [kp["private_key"] for kp in kps]
    pubs = [kp["public_key"] for kp in kps]
    hashes = [kp["hash"] for kp in kps]

    # Pairwise distinctness across all three identities (a broken RNG or a
    # deterministic keygen would collide here).
    assert len(set(privs)) == 3, f"private keys not all distinct: {privs}"
    assert len(set(pubs)) == 3, f"public keys not all distinct: {pubs}"
    assert len(set(hashes)) == 3, f"identity hashes not all distinct: {hashes}"

    # Key/hash sizes pin the RNS 1.3.1 key geometry.
    for kp in kps:
        assert len(kp["private_key"]) == _PRIVATE_KEY_LEN, kp
        assert len(kp["public_key"]) == _PUBLIC_KEY_LEN, kp
        assert len(kp["hash"]) == _HASH_LEN, kp


# ---------------------------------------------------------------------------
# Retained-ratchets RATCHET_COUNT cap
# ---------------------------------------------------------------------------

def _announce_ratcheted_destination(peer):
    """Create a ratchet-bearing SINGLE destination on `peer` and return its hash.

    announce(enable_ratchets=True) calls Destination.enable_ratchets before
    announcing; the wrapper stashes the bridge response on peer.last_announce so
    the ratchets_enabled precondition stays assertable.
    """
    dest_hash = peer.announce(
        app_name=_APP, aspects=list(_ASPECTS), app_data=b"", enable_ratchets=True
    )
    assert peer.last_announce.get("ratchets_enabled") is True, (
        f"enable_ratchets did not take on the announced destination: "
        f"{peer.last_announce!r}"
    )
    return dest_hash


@conformance_case(
    commands=["start_tcp_server", "announce", "set_retained_ratchets"],
    verifies=(
        "Destination retained-ratchets cap (RNS.Destination.set_retained_"
        "ratchets / _clean_ratchets, Destination.py:504-517/:205-208): "
        "set_retained_ratchets(8) succeeds (ok True) and reads retained_ratchets "
        "back as 8; set_retained_ratchets(0) is rejected (ok False) and leaves "
        "retained_ratchets unchanged at 8; and after padding the ratchet list "
        "past Destination.RATCHET_COUNT (512) and applying the cap, the in-memory "
        "ratchet list is truncated to exactly RATCHET_COUNT (ratchet_count == "
        "ratchet_count_cap == 512)."
    ),
)
def test_retained_ratchets_capped_at_ratchet_count(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")
    dest_hash = _announce_ratcheted_destination(server)

    def _set(n, pad_to=None):
        return server.set_retained_ratchets(dest_hash, n, pad_to=pad_to)

    # Valid positive cap read-back.
    r1 = _set(8)
    assert r1["ok"] is True, f"set_retained_ratchets(8) must succeed: {r1!r}"
    assert r1["retained_ratchets"] == 8, (
        f"retained_ratchets must read back as the value set: {r1!r}"
    )

    # Non-positive value is rejected and leaves the cap unchanged.
    r2 = _set(0)
    assert r2["ok"] is False, (
        f"set_retained_ratchets(0) must be rejected by RNS: {r2!r}"
    )
    assert r2["retained_ratchets"] == 8, (
        f"a rejected set must leave retained_ratchets unchanged: {r2!r}"
    )

    # Cap enforcement: inflate the list past RATCHET_COUNT, then apply the cap.
    r3 = _set(_RATCHET_COUNT, pad_to=_RATCHET_COUNT + 8)
    assert r3["ok"] is True, f"set_retained_ratchets({_RATCHET_COUNT}) must succeed: {r3!r}"
    assert r3["ratchet_count_cap"] == _RATCHET_COUNT, (
        f"the RATCHET_COUNT cap constant must be 512 in RNS 1.3.1: {r3!r}"
    )
    assert r3["ratchet_count"] == r3["ratchet_count_cap"], (
        f"a ratchet list inflated past the cap must be truncated to "
        f"RATCHET_COUNT={_RATCHET_COUNT}, got ratchet_count={r3['ratchet_count']!r}"
    )


# ---------------------------------------------------------------------------
# Ratchet-file persistence format round-trip
# ---------------------------------------------------------------------------

@conformance_case(
    commands=[
        "start_tcp_server", "announce", "rotate_ratchet", "ratchet_file_roundtrip",
    ],
    verifies=(
        "Ratchet-file persistence round-trip via RNS's own persist/reload "
        "(Destination._persist_ratchets/_reload_ratchets, Destination.py:210-225/"
        ":426-464): after a real ratchet rotation, Destination._persist_ratchets "
        "writes the signed on-disk store and Destination._reload_ratchets reloads "
        "it successfully (reload_ok True) reproducing the in-memory ratchet list "
        "byte-exact (roundtrip_match True; ratchet_count_after == "
        "ratchet_count_before >= 1; ratchet_ids count matches). _reload_ratchets "
        "validates the embedded signature against the destination identity and "
        "only repopulates the ratchet list when it verifies (raising otherwise, "
        ":432-437/:450-458), so a successful reload proves the persisted store "
        "carried a valid signature over a well-formed format -- asserted through "
        "RNS's own validation, not a bridge re-parse of the on-disk bytes."
    ),
)
def test_ratchet_file_persistence_roundtrip(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")
    dest_hash = _announce_ratcheted_destination(server)

    # Guarantee a non-empty, freshly-persisted store: back-date the last-rotation
    # timestamp far enough that the interval gate opens, so rotate inserts a new
    # ratchet and persists it (no real wait).
    rot = server.rotate_ratchet(dest_hash, last_rotation_ago_s=10_000_000)
    assert rot["rotated"] is True, (
        f"back-dated rotation must open the interval gate and insert a ratchet: "
        f"{rot!r}"
    )
    assert rot["after_count"] >= 1, f"rotation must leave >=1 ratchet: {rot!r}"

    rt = server.ratchet_file_roundtrip(dest_hash)
    assert rt["ratchets_path_set"] is True, rt
    assert rt["ratchet_count_before"] >= 1, (
        f"the store must contain at least the rotated ratchet: {rt!r}"
    )
    # The discriminating property: RNS's own _reload_ratchets accepted the
    # persisted store. It validates the embedded signature and raises (leaving
    # ratchets None / reload_ok False) on a bad signature or malformed blob, so
    # reload_ok True means the signed on-disk format round-tripped.
    assert rt["reload_ok"] is True, (
        f"Destination._reload_ratchets must accept the just-persisted store "
        f"(valid signature, well-formed format) and not raise: {rt!r}"
    )
    assert rt["ratchet_count_after"] == rt["ratchet_count_before"], (
        f"reload must reproduce the same ratchet count: {rt!r}"
    )
    assert rt["roundtrip_match"] is True, (
        f"the reloaded ratchet ids must match the persisted ones byte-exact: "
        f"{rt!r}"
    )
    assert len(rt["ratchet_ids"]) == rt["ratchet_count_after"], (
        f"ratchet_ids count must equal ratchet_count_after: {rt!r}"
    )
