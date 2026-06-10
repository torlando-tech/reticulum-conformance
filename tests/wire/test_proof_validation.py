"""Adversarial single-packet PROOF validation conformance.

A sender that requests a delivery proof holds a real `RNS.PacketReceipt`. When a
PROOF arrives, RNS hands it to `PacketReceipt.validate_proof` (Packet.py) — the
security gate that decides whether the packet counts as DELIVERED. That gate
enforces three rules a non-conformant sender can silently get wrong (and then
accept any 64-byte blob as a delivery confirmation):

  * LENGTH — a proof is either 96 bytes (EXPLICIT: packet_hash(32)||signature(64))
    or 64 bytes (IMPLICIT: signature(64)); any other length is rejected outright.
  * SIGNATURE — the signature must verify, with the receipt destination's
    identity, over the receipt's packet hash. A forgery under the wrong key fails.
  * PROOF-HASH (explicit form) — the leading 32 bytes must equal the receipt's
    packet hash, else the proof is rejected.

The ordinary harness can only ever produce a *correct* proof (the real receiver
proves), so these rejection branches were entirely untested
(CONFORMANCE_COMPLETENESS.md §4 "forged packet-receipt PROOF against a waiting
sender"; gaps receipt-reject-other-proof-lengths /
receipt-implicit-proof-validation). The `wire_inject_crafted_proof` adversarial
injector crafts each malformed/forged variant and runs it through the real
`validate_proof`; a genuine PROVE_ALL delivery over the wire is the positive
control, so the rejections are pinned against a working accept path.

Runs reference-vs-reference; no SUT binary required. (The peers are separate
bridge processes, so a genuinely-valid proof can only come from the real
receiver over the wire — hence PROVE_ALL as the positive control rather than a
locally-signed valid proof.)
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["proof-validation"]


# Every forged/malformed variant and the validate_proof branch it must trip.
_REJECTED_VARIANTS = (
    ("wrong_length_short", "32-byte proof (neither 64 nor 96) — length gate"),
    ("wrong_length_mid", "65-byte proof — length gate"),
    ("wrong_length_long", "97-byte proof — length gate"),
    ("forged_implicit", "64-byte signature under the WRONG key — signature check"),
    ("forged_explicit", "96-byte hash||sig with a wrong-key signature — signature check"),
    ("wrong_hash_explicit", "96-byte proof whose hash != receipt hash — proof-hash check"),
)


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "send_packet", "inject_crafted_proof", "set_proof_strategy",
        "send_packet_with_proof_request",
    ],
    verifies=(
        "RNS.PacketReceipt.validate_proof REJECTS every malformed or forged "
        "single-packet PROOF against a waiting sender — a wrong length (32/65/97 "
        "bytes, neither IMPL_LENGTH=64 nor EXPL_LENGTH=96), a correct-length "
        "signature forged under the wrong key (implicit and explicit), and an "
        "explicit proof whose leading hash != the receipt's packet hash — "
        "leaving the receipt SENT (never DELIVERED, proved=False). A genuine "
        "PROVE_ALL delivery over the wire is then accepted (receipt DELIVERED, "
        "proved=True) as the positive control. A sender that skips the "
        "length/signature/hash checks would accept a forged proof and wrongly "
        "report delivery"
    ),
)
def test_single_packet_proof_validation_rejects_forgeries(wire_link_setup):
    server, client, dest_hash, _link_id = wire_link_setup(_APP, _ASPECTS)

    # The listening destination defaults to PROVE_NONE, so the receiver never
    # emits a real proof — the receipt stays SENT and we control the proof.
    sent = client.send_packet(
        dest_hash, data=secrets.token_bytes(20), app_name=_APP, aspects=_ASPECTS,
    )
    receipt_id = sent["receipt_id"]
    assert sent["sent"] is True and receipt_id, f"send failed: {sent!r}"

    # Negatives: each forged/malformed proof must be rejected and leave the
    # receipt undelivered. They run on the SAME receipt because a rejected proof
    # does not conclude it.
    for variant, why in _REJECTED_VARIANTS:
        res = client.inject_crafted_proof(receipt_id, variant)
        assert res["validated"] is False, (
            f"{variant} ({why}) was ACCEPTED by validate_proof: {res!r}"
        )
        assert res["status_name"] == "SENT", (
            f"{variant}: receipt must stay SENT after a rejected proof, got {res!r}"
        )
        assert res["proved"] is False, f"{variant}: receipt.proved must stay False: {res!r}"

    # Positive control: a GENUINE proof, emitted by the real receiver under
    # PROVE_ALL, is accepted — the receipt delivers and is proved. This pins the
    # rejections above against a working accept path (validate_proof is not
    # rejecting everything).
    server.set_proof_strategy(dest_hash, "all")
    ok = client.send_packet_with_proof_request(
        dest_hash, data=secrets.token_bytes(20),
        app_name=_APP, aspects=list(_ASPECTS), timeout_ms=8000,
    )
    assert ok["delivered"] is True and ok["proved"] is True, (
        f"a genuine PROVE_ALL proof was not accepted (positive control): {ok!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_tampered_link_data",
    ],
    verifies=(
        "Link DATA is authenticated before delivery: a pristine DATA packet "
        "encrypted to an established link is delivered to the receiver's packet "
        "handler (positive control), but the same packet with ANY tamper — a "
        "flipped ciphertext/IV byte, a flipped trailing HMAC byte, or a "
        "truncated token — is silently dropped (not delivered) because the RNS "
        "Token verifies its HMAC over IV||ciphertext before decrypting, and the "
        "link stays ACTIVE through every attempt. An impl that decrypts without "
        "verifying the HMAC would deliver forged link data"
    ),
)
def test_link_data_tamper_silently_dropped(wire_link_setup):
    # The client is the initiator; the server holds the inbound link and its
    # packet handler, so the injector runs on the SERVER peer.
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Positive control: a pristine packet IS delivered, link stays ACTIVE.
    ok = server.inject_tampered_link_data(link_id, b"genuine-link-data", corruption="none")
    assert ok["unpacked"] is True, f"pristine packet failed to unpack: {ok!r}"
    assert ok["delivered"] is True, (
        f"a pristine link DATA packet was not delivered to the handler "
        f"(positive control): {ok!r}"
    )
    assert ok["link_active"] is True, f"link not ACTIVE after a valid packet: {ok!r}"

    # Negatives: each tamper must be dropped (not delivered) and leave the link
    # ACTIVE (silent drop, not teardown).
    for corruption in ("ciphertext", "hmac", "truncate"):
        res = server.inject_tampered_link_data(
            link_id, b"genuine-link-data", corruption=corruption,
        )
        assert res["delivered"] is False, (
            f"a {corruption}-tampered link DATA packet was DELIVERED — the link "
            f"layer decrypted without verifying the token HMAC: {res!r}"
        )
        assert res["link_active"] is True, (
            f"a {corruption} tamper tore the link down instead of silently "
            f"dropping the packet: {res!r}"
        )
