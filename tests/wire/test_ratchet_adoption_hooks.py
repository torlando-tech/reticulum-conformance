"""Receiver-side ratchet ADOPTION + adoption-driven target-key selection
(Opus wave-2, gap-closing).

Four RNS ratchet/proof rules the first harness pass reached but could not
observe end-to-end without an extra adoption observable. Each runs reference-
vs-reference over the two-real-instance wire fixtures (peer A announces with
ratchets enabled, peer B hears it over a real TCP interface), and every
assertion anchors on an EXTERNAL standard — the RNS ratchet-id derivation
(SHA-256(ratchet_public)[:NAME_HASH_LENGTH//8]), the latest_ratchet_id
ratchet-vs-static discriminator, or the explicit-proof wire layout
(packet_hash||signature) — not on the implementation reading back its own bytes:

  * announce-ratchet-adoption — when B hears A's announce with the ratchet
    context flag set, RNS.Transport validates it and Identity._remember_ratchet
    caches A's announced ratchet PUBLIC key under A's destination hash
    (Identity.validate_announce / get_ratchet, Identity.py:499-520,617). B's
    adopted ratchet id must equal A's destination's own current ratchet id (an
    independent subsystem) and the SHA-256 derivation of the adopted public key;
    a never-heard destination yields nothing; a NEWER announce REPLACES it.
  * encrypt-target-key-selection — encrypting to a REMOTE destination uses the
    ratchet learned from its announce as the ECDH target, not the static X25519
    key (Identity.encrypt(ratchet=...), Destination.encrypt, Destination.py:
    595-599). The ciphertext must decrypt under A's ratchet PRIVATE key — proven
    by A's Destination.decrypt setting latest_ratchet_id to the adopted id — and
    a static-key control sets latest_ratchet_id None (Identity.decrypt:886-913).
  * announce-ratchet-caching — the received ratchet was cached and reused for
    outbound encryption (used_ratchet True, id == the announced ratchet id).
  * proof-data-format — with implicit proofs disabled the prover emits the
    EXPLICIT 96-byte proof packet_hash(32)||signature(64) instead of the
    implicit 64-byte signature-only form (Identity.prove, Identity.py:959-970;
    Reticulum.should_use_implicit_proof), and it validates and delivers.
"""

import os
import time
from hashlib import sha256 as _sha256

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


# --- RNS ratchet / proof constants (external ground truth, restated) --------
_RATCHET_PUBLIC_LEN = 32      # RNS.Identity.RATCHETSIZE // 8  (X25519 pub)
_RATCHET_ID_LEN = 10          # RNS.Identity.NAME_HASH_LENGTH // 8
_EXPL_LENGTH = 96             # RNS.Identity.HASHLENGTH//8 + SIGLENGTH//8
_IMPL_LENGTH = 64             # RNS.Identity.SIGLENGTH // 8
_FULL_HASH_LEN = 32           # SHA-256 digest


def _expected_ratchet_id(ratchet_public: bytes) -> bytes:
    """Restate RNS.Identity._get_ratchet_id (Identity.py:410-411): the ratchet
    id is the first NAME_HASH_LENGTH//8 bytes of SHA-256(ratchet_public)."""
    return _sha256(ratchet_public).digest()[:_RATCHET_ID_LEN]


def _setup_ratcheted_announce(server, client, app="conformance", aspects=("wire",)):
    """Bring up a direct TCP pair and have the SERVER (peer A) announce a
    ratchet-enabled SINGLE destination that the CLIENT (peer B) hears.

    Returns (dest_hash, a_current_ratchet_id) where a_current_ratchet_id is read
    off A's OWN destination ratchet store — an independent source from B's
    adoption path.
    """
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port,
    )
    time.sleep(1.0)
    dest_hash = server.listen(app_name=app, aspects=list(aspects), enable_ratchets=True)
    assert client.poll_path(dest_hash, timeout_ms=10000), (
        "peer B never heard peer A's ratcheted announce"
    )
    a_state = server.read_ratchets(dest_hash)
    a_current = a_state["current_ratchet_id"]
    assert a_current is not None, f"peer A grew no ratchet: {a_state!r}"
    return dest_hash, a_current


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "read_ratchets", "get_adopted_ratchet",
    ],
    verifies=(
        "When peer B hears peer A's announce carrying a ratchet (context flag "
        "set), RNS validates it and Identity._remember_ratchet caches A's "
        "announced ratchet PUBLIC key under A's destination hash, so B ADOPTS it "
        "(Identity.validate_announce -> _remember_ratchet -> get_ratchet, "
        "Identity.py:499-520,617). B's adopted ratchet is a 32-byte X25519 "
        "public key whose 10-byte ratchet id (SHA-256(public)[:10], "
        "Identity._get_ratchet_id) equals A's OWN destination current ratchet id "
        "(an independent subsystem). A destination B has never heard an announce "
        "for yields no adopted ratchet. An impl that ignored the announce ratchet "
        "or derived the id differently would diverge on one of these"
    ),
)
def test_receiver_adopts_announced_ratchet(wire_peers):
    server, client = wire_peers
    dest_hash, a_current = _setup_ratcheted_announce(server, client)

    adopted = client.get_adopted_ratchet(dest_hash)
    assert adopted["found"], f"peer B adopted no ratchet for A: {adopted!r}"

    pub = adopted["ratchet_public"]
    rid = adopted["ratchet_id"]
    assert isinstance(pub, (bytes, bytearray)) and len(pub) == _RATCHET_PUBLIC_LEN, (
        f"adopted ratchet public key must be 32 bytes: {adopted!r}"
    )
    assert isinstance(rid, (bytes, bytearray)) and len(rid) == _RATCHET_ID_LEN, (
        f"adopted ratchet id must be 10 bytes: {adopted!r}"
    )

    # Cross-subsystem: B's adopted id == A's own destination's current id.
    assert rid == a_current, (
        f"B adopted ratchet id {rid.hex()} != A's announced current id "
        f"{a_current.hex()}"
    )
    # External derivation: id == SHA-256(public)[:10], independent of the impl.
    assert rid == _expected_ratchet_id(pub), (
        f"adopted ratchet id is not SHA-256(public)[:10]: {rid.hex()} != "
        f"{_expected_ratchet_id(pub).hex()}"
    )

    # Negative control: a destination never announced yields no adopted ratchet.
    never_heard = client.get_adopted_ratchet(os.urandom(16))
    assert not never_heard["found"], (
        f"B claims to have adopted a ratchet for an unheard destination: "
        f"{never_heard!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "read_ratchets", "get_adopted_ratchet", "encrypt_to_remote",
        "destination_decrypt",
    ],
    verifies=(
        "Encrypting to a REMOTE destination selects the ratchet learned from "
        "its announce as the ECDH target, not the static X25519 key "
        "(Identity.encrypt(ratchet=...), the same choice Destination.encrypt "
        "makes, Destination.py:595-599). The adopted-ratchet ciphertext decrypts "
        "under A's ratchet PRIVATE key — proven by A's Destination.decrypt "
        "setting latest_ratchet_id to the adopted ratchet id (Identity.decrypt "
        "ratchet branch, Identity.py:886-893) — while a static-key control "
        "ciphertext decrypts with latest_ratchet_id None (static branch, "
        "Identity.py:899-900). The chosen ratchet id also equals A's own current "
        "ratchet id (announce-ratchet-caching: the heard ratchet was cached and "
        "reused). An impl that always used the static key would set "
        "latest_ratchet_id None for both, collapsing the discriminator"
    ),
)
def test_encrypt_to_remote_uses_adopted_ratchet(wire_peers):
    server, client = wire_peers
    dest_hash, a_current = _setup_ratcheted_announce(server, client)

    plaintext = b"adoption-driven target key selection"

    # B encrypts to A, auto-selecting A's adopted ratchet as the ECDH target.
    enc = client.encrypt_to_remote(dest_hash, plaintext)
    assert enc["used_ratchet"], (
        f"B did not encrypt to A's adopted ratchet (announce-ratchet-caching): "
        f"{enc!r}"
    )
    assert enc["ratchet_id"] == a_current, (
        f"B encrypted to ratchet {enc['ratchet_id']!r}, not A's announced "
        f"current ratchet {a_current.hex()}"
    )
    assert enc["ratchet_id"] == _expected_ratchet_id(enc["ratchet_public"]), (
        "encrypt target ratchet id is not SHA-256(public)[:10]"
    )

    # A decrypts: the ciphertext must come back under A's ratchet PRIVATE key,
    # so the destination records latest_ratchet_id == the adopted id.
    dec = server.destination_decrypt(dest_hash, enc["ciphertext"])
    assert dec["decrypted"] and dec["plaintext"] == plaintext, (
        f"A could not decrypt B's ratchet ciphertext: {dec!r}"
    )
    assert dec["latest_ratchet_id"] == a_current, (
        f"A decrypted under the wrong key: latest_ratchet_id "
        f"{dec['latest_ratchet_id']!r} != adopted ratchet {a_current.hex()} "
        f"(a static-key decrypt would be None)"
    )

    # Negative control: encrypt to A's STATIC key instead. It still decrypts (A
    # holds the static private key) but with NO ratchet, so latest_ratchet_id is
    # None — proving the positive path genuinely used the ratchet target.
    static_enc = client.encrypt_to_remote(dest_hash, plaintext, use_ratchet=False)
    assert not static_enc["used_ratchet"] and static_enc["ratchet_id"] is None, (
        f"static-key control still selected a ratchet: {static_enc!r}"
    )
    static_dec = server.destination_decrypt(dest_hash, static_enc["ciphertext"])
    assert static_dec["decrypted"] and static_dec["plaintext"] == plaintext, (
        f"A could not decrypt the static-key control ciphertext: {static_dec!r}"
    )
    assert static_dec["latest_ratchet_id"] is None, (
        f"static-key ciphertext must decrypt with latest_ratchet_id None, got "
        f"{static_dec['latest_ratchet_id']!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "read_ratchets", "get_adopted_ratchet", "reannounce",
    ],
    verifies=(
        "A NEWER announce replaces a previously adopted ratchet: when A rotates "
        "its ratchet and re-announces (Destination.announce rotates and carries "
        "the new latest ratchet, Destination.py:282-287), B re-adopts the new "
        "ratchet via Identity._remember_ratchet's replace path (Identity.py:"
        "424-433). B's adopted id transitions from the first announced id to the "
        "second (both 10-byte SHA-256(public)[:10] derivations), and the second "
        "matches A's new current ratchet id. An impl that pinned the first "
        "adopted ratchet would never converge on the replacement"
    ),
)
def test_newer_announce_replaces_adopted_ratchet(wire_peers):
    server, client = wire_peers
    dest_hash, first_a_current = _setup_ratcheted_announce(server, client)

    first = client.get_adopted_ratchet(dest_hash)
    assert first["found"] and first["ratchet_id"] == first_a_current, (
        f"B did not adopt A's first ratchet: {first!r}"
    )

    # A rotates its ratchet (gate forced open) and re-announces the SAME dest.
    re = server.reannounce(dest_hash, rotate_ago_s=99999)
    second_a_current = re["current_ratchet_id"]
    assert second_a_current is not None and second_a_current != first_a_current, (
        f"re-announce did not produce a new ratchet: {re!r}"
    )

    # B should converge on the newer ratchet within a few seconds.
    deadline = time.time() + 10.0
    adopted = first
    while time.time() < deadline:
        adopted = client.get_adopted_ratchet(dest_hash)
        if adopted["found"] and adopted["ratchet_id"] == second_a_current:
            break
        time.sleep(0.2)

    assert adopted["found"] and adopted["ratchet_id"] == second_a_current, (
        f"B never re-adopted A's newer ratchet {second_a_current.hex()}: "
        f"{adopted!r}"
    )
    assert adopted["ratchet_id"] != first_a_current, (
        "newer adopted ratchet id must differ from the first"
    )
    assert adopted["ratchet_id"] == _expected_ratchet_id(adopted["ratchet_public"]), (
        "replacement ratchet id is not SHA-256(public)[:10]"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "set_proof_strategy", "set_proof_implicit", "send_packet_with_proof_request",
    ],
    verifies=(
        "With implicit proofs DISABLED the prover emits the EXPLICIT single-"
        "packet proof form packet_hash(32)||signature(64) = 96 bytes "
        "(EXPL_LENGTH), instead of the default implicit 64-byte signature-only "
        "form (Identity.prove branching on Reticulum.should_use_implicit_proof, "
        "Identity.py:959-970). The explicit proof's first 32 bytes are exactly "
        "the proved packet's hash and it validates+delivers "
        "(PacketReceipt.validate_proof explicit branch, Packet.py:498-521); the "
        "implicit control is 64 bytes with no hash prefix. An impl that emitted "
        "the wrong layout, or whose explicit proof did not lead with the packet "
        "hash, would fail validation or the structural check"
    ),
)
def test_explicit_proof_format(wire_peers):
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port,
    )
    time.sleep(1.0)
    dest_hash = server.listen(app_name="conformance", aspects=["wire"])
    server.set_proof_strategy(dest_hash, "all")
    assert client.poll_path(dest_hash, timeout_ms=10000), (
        "client never heard the server's announce"
    )

    # Force the PROVER (server) to emit the EXPLICIT proof form.
    toggled = server.set_proof_implicit(False)
    assert toggled.get("implicit_proof") is False, (
        f"server did not switch to explicit proofs: {toggled!r}"
    )

    res = client.send_packet_with_proof_request(
        dest_hash, data=b"prove-me-explicitly",
        app_name="conformance", aspects=["wire"], timeout_ms=12000,
    )
    assert res["sent"] and res["proved"], (
        f"explicit proof was not produced/validated: {res!r}"
    )
    assert res["expl_length"] == _EXPL_LENGTH and res["impl_length"] == _IMPL_LENGTH, (
        f"RNS proof-length constants drifted: {res!r}"
    )
    assert res["proof_len"] == _EXPL_LENGTH, (
        f"explicit proof must be 96 bytes: {res!r}"
    )
    assert res["proof_is_explicit"] is True and res["proof_is_implicit"] is False, (
        f"proof not classified explicit: {res!r}"
    )

    proof = res["proof_data"]
    pkt_hash = res["proved_packet_hash"]
    assert isinstance(proof, (bytes, bytearray)) and len(proof) == _EXPL_LENGTH
    assert isinstance(pkt_hash, (bytes, bytearray)) and len(pkt_hash) == _FULL_HASH_LEN
    # Explicit layout: first 32 bytes ARE the proved packet's hash.
    assert proof[:_FULL_HASH_LEN] == pkt_hash, (
        f"explicit proof does not lead with the packet hash: "
        f"{proof[:_FULL_HASH_LEN].hex()} != {pkt_hash.hex()}"
    )
    assert len(proof[_FULL_HASH_LEN:]) == _IMPL_LENGTH, (
        "explicit proof tail must be a 64-byte signature"
    )

    # Negative control: switch back to implicit and confirm the FORM changes to
    # the 64-byte signature-only proof with no leading packet hash.
    back = server.set_proof_implicit(True)
    assert back.get("implicit_proof") is True, f"toggle back failed: {back!r}"
    impl_res = client.send_packet_with_proof_request(
        dest_hash, data=b"prove-me-implicitly",
        app_name="conformance", aspects=["wire"], timeout_ms=12000,
    )
    assert impl_res["sent"] and impl_res["proved"], (
        f"implicit control proof not produced/validated: {impl_res!r}"
    )
    assert impl_res["proof_len"] == _IMPL_LENGTH, (
        f"implicit proof must be 64 bytes: {impl_res!r}"
    )
    assert impl_res["proof_is_implicit"] is True and impl_res["proof_is_explicit"] is False, (
        f"control proof not classified implicit: {impl_res!r}"
    )
    assert impl_res["proof_data"][:_FULL_HASH_LEN] != impl_res["proved_packet_hash"], (
        "implicit proof must NOT lead with the packet hash (it is signature-only)"
    )
