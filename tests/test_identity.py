"""Identity conformance tests.

Tests identity creation from private keys, identity hashing,
signing/verification, and encrypt/decrypt by comparing SUT output
against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Identity"
__category_order__ = 2


@conformance_case(
    commands=["identity_from_private_key"],
    verifies="Deriving an RNS Identity from its 64-byte private key (32-byte X25519 encryption + 32-byte Ed25519 signing halves) yields a byte-identical public key and 16-byte identity_hash cross-impl, and the Identity's hexhash is exactly the lowercase-hex string form of that 16-byte hash (within-impl invariant)",
)
def test_identity_from_private_key(sut, reference):
    priv = random_hex(64)  # 32B encryption + 32B signing
    ref = reference.execute("identity_from_private_key", private_key=priv)
    res = sut.execute("identity_from_private_key", private_key=priv)
    assert_hex_equal(res["public_key"], ref["public_key"])
    assert_hex_equal(res["hash"], ref["hash"])
    # I1: hash and hexhash are the SAME hex string, so comparing res["hexhash"]
    # to ref["hexhash"] only re-asserts the hash equality just checked. Instead
    # pin the actual hexhash contract: it is the lowercase-hex rendering of the
    # 16-byte hash bytes (an impl whose hexhash diverges from hexlify(hash) —
    # e.g. uppercase, or a different field — is caught here).
    assert res["hexhash"] == res["hash"].lower(), (
        f"sut hexhash {res['hexhash']!r} is not the lowercase-hex form of its "
        f"own hash {res['hash']!r}"
    )


@conformance_case(
    commands=["identity_from_private_key", "identity_hash"],
    verifies="RNS's `identity_hash` (truncated SHA-256 of the concatenated encryption + signing public keys) is byte-identical",
)
def test_identity_hash(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    ref = reference.execute("identity_hash", public_key=ref_id["public_key"])
    res = sut.execute("identity_hash", public_key=ref_id["public_key"])
    assert_hex_equal(res["hash"], ref["hash"])


@conformance_case(
    commands=["identity_sign", "identity_from_private_key", "identity_verify"],
    verifies="RNS Identity sign+verify: signatures are byte-identical and both impls verify each other's signatures",
)
def test_identity_sign_verify(sut, reference):
    priv = random_hex(64)
    message = random_hex(128)
    ref = reference.execute("identity_sign", private_key=priv, message=message)
    res = sut.execute("identity_sign", private_key=priv, message=message)
    assert_hex_equal(res["signature"], ref["signature"])
    # Verify with both implementations
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    ref_v = reference.execute(
        "identity_verify",
        public_key=ref_id["public_key"],
        message=message,
        signature=ref["signature"],
    )
    res_v = sut.execute(
        "identity_verify",
        public_key=ref_id["public_key"],
        message=message,
        signature=ref["signature"],
    )
    assert ref_v["valid"] is True
    assert res_v["valid"] is True


@conformance_case(
    commands=["identity_sign", "identity_from_private_key", "identity_verify"],
    verifies="Negative control (with positive control): identity_verify returns valid=True for a genuine Ed25519 signature, valid=False for a single-bit-flipped signature, and valid=False for a tampered message — so a stub verifier that always returns True (or ignores the message) is caught. Both assertions run on each impl.",
)
def test_identity_verify_rejects_forgery(sut, reference):
    priv = random_hex(64)
    message = random_hex(128)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]
    sig = reference.execute(
        "identity_sign", private_key=priv, message=message
    )["signature"]

    # Flip the lowest bit of the first signature byte -> invalid signature.
    sig_bytes = bytearray.fromhex(sig)
    sig_bytes[0] ^= 0x01
    forged_sig = sig_bytes.hex()
    # Flip the lowest bit of the first message byte -> signature no longer
    # covers the message that is presented to validate().
    msg_bytes = bytearray.fromhex(message)
    msg_bytes[0] ^= 0x01
    tampered_msg = msg_bytes.hex()

    for impl, label in ((reference, "reference"), (sut, "sut")):
        # Positive control: a genuine signature must verify (guards against a
        # verifier that always returns False, which would make the negative
        # assertions below vacuously pass).
        good = impl.execute(
            "identity_verify", public_key=pub, message=message, signature=sig
        )
        assert good["valid"] is True, (
            f"{label} rejected a genuine Ed25519 signature (positive control "
            f"failed) — the negative assertions below would be meaningless"
        )
        # Negative: a single-bit-flipped signature must NOT verify.
        flipped = impl.execute(
            "identity_verify", public_key=pub, message=message, signature=forged_sig
        )
        assert flipped["valid"] is False, (
            f"{label} accepted a signature with one flipped bit as valid"
        )
        # Negative: a genuine signature over a different message must NOT verify.
        wrong = impl.execute(
            "identity_verify", public_key=pub, message=tampered_msg, signature=sig
        )
        assert wrong["valid"] is False, (
            f"{label} accepted a signature against a tampered message as valid"
        )


@conformance_case(
    commands=["identity_from_private_key", "identity_encrypt", "identity_decrypt"],
    verifies="Negative control (with positive control): a genuine ciphertext decrypts to the original plaintext, but a ciphertext with one flipped bit in its trailing HMAC tag fails authentication — RNS.Identity.decrypt yields plaintext=None (and an impl that raises is also accepted), never attacker-controlled plaintext. Both paths run on each impl.",
)
def test_identity_decrypt_rejects_forged_ciphertext(sut, reference):
    priv = random_hex(64)
    plaintext = random_hex(48)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]
    ciphertext = reference.execute(
        "identity_encrypt", public_key=pub, plaintext=plaintext
    )["ciphertext"]

    # Flip the lowest bit of the final byte. RNS Identity ciphertext is
    # ephemeral-pubkey(32) || Token(IV || AES-CBC ciphertext || HMAC-SHA256),
    # so the last byte lies in the HMAC tag: decryption must fail authentication.
    ct_bytes = bytearray.fromhex(ciphertext)
    ct_bytes[-1] ^= 0x01
    forged = ct_bytes.hex()

    for impl, label in ((reference, "reference"), (sut, "sut")):
        # Positive control: the genuine ciphertext decrypts (guards against a
        # decryptor that always returns None / always raises).
        good = impl.execute(
            "identity_decrypt", private_key=priv, ciphertext=ciphertext
        )
        assert_hex_equal(
            good["plaintext"], plaintext, msg=f"{label} positive control"
        )
        # Negative: the forged ciphertext must NOT yield plaintext. Acceptable
        # outcomes are plaintext=None (RNS.Identity.decrypt) or a surfaced error
        # (an impl that raises on HMAC failure). The wrong behavior — silently
        # returning forged/garbage plaintext — fails both branches.
        try:
            bad = impl.execute(
                "identity_decrypt", private_key=priv, ciphertext=forged
            )
        except BridgeError:
            continue  # raised on authentication failure — acceptable
        assert bad["plaintext"] is None, (
            f"{label} returned non-None plaintext {bad['plaintext']!r} for a "
            f"ciphertext with a flipped HMAC byte — the authentication tag is "
            f"not being enforced (forgery accepted)"
        )


@conformance_case(
    commands=["identity_from_private_key", "identity_encrypt", "identity_decrypt"],
    verifies="RNS Identity encrypt/decrypt cross-impl round-trip in both directions — exercises the X25519+HKDF+AES composition used for unicast encryption",
)
def test_identity_encrypt_decrypt(sut, reference):
    priv = random_hex(64)
    plaintext = random_hex(48)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    # Encrypt with reference, decrypt with SUT
    ref_enc = reference.execute(
        "identity_encrypt",
        public_key=ref_id["public_key"],
        plaintext=plaintext,
    )
    res_dec = sut.execute(
        "identity_decrypt",
        private_key=priv,
        ciphertext=ref_enc["ciphertext"],
    )
    assert_hex_equal(res_dec["plaintext"], plaintext)
    # Encrypt with SUT, decrypt with reference
    res_enc = sut.execute(
        "identity_encrypt",
        public_key=ref_id["public_key"],
        plaintext=plaintext,
    )
    ref_dec = reference.execute(
        "identity_decrypt",
        private_key=priv,
        ciphertext=res_enc["ciphertext"],
    )
    assert_hex_equal(ref_dec["plaintext"], plaintext)


@conformance_case(
    commands=["identity_from_private_key", "identity_encrypt", "identity_decrypt"],
    verifies="Invariant: two encryptions of byte-identical plaintext for the same Identity produce different ciphertext (RNS draws a fresh ephemeral X25519 key + AES IV per call), and both still decrypt back to the original",
)
def test_identity_encrypt_is_fresh_per_call(sut, reference):
    priv = random_hex(64)
    plaintext = random_hex(48)
    ident = sut.execute("identity_from_private_key", private_key=priv)

    first = sut.execute(
        "identity_encrypt", public_key=ident["public_key"], plaintext=plaintext
    )
    second = sut.execute(
        "identity_encrypt", public_key=ident["public_key"], plaintext=plaintext
    )
    assert first["ciphertext"] != second["ciphertext"], (
        "two encryptions of identical plaintext produced identical ciphertext "
        "— the ephemeral key / IV is not fresh per call, which leaks plaintext "
        "equality to an observer"
    )
    # Both must still decrypt back — freshness must not break correctness.
    for enc in (first, second):
        dec = sut.execute(
            "identity_decrypt", private_key=priv, ciphertext=enc["ciphertext"]
        )
        assert_hex_equal(dec["plaintext"], plaintext)


# ---------------------------------------------------------------------------
# Identity verification is a total predicate; announce validation never crashes
# (Opus completeness gaps: verify-boolean, announce-malformed-rejected-no-crash)
# ---------------------------------------------------------------------------


@conformance_case(
    commands=["identity_from_private_key", "identity_sign", "identity_verify"],
    verifies="RNS.Identity.validate is a TOTAL boolean predicate: a genuine signature verifies True (positive anchor), but a structurally malformed signature — wrong length (63 bytes, 65 bytes) or empty (0 bytes) — verifies False, returned as a boolean rather than raised. An SUT that throws on a malformed signature instead of rejecting it fails",
)
def test_identity_verify_malformed_signature_returns_false(sut, reference):
    priv = random_hex(64)
    idn = reference.execute("identity_from_private_key", private_key=priv)
    message = random_hex(48)
    sig = sut.execute("identity_sign", private_key=priv, message=message)["signature"]
    # Positive anchor.
    assert sut.execute(
        "identity_verify", public_key=idn["public_key"], message=message, signature=sig
    )["valid"] is True
    # Negatives: malformed lengths must all verify False without raising.
    for bad, why in ((sig[:-2], "63-byte"), (sig + "00", "65-byte"), ("", "0-byte")):
        v = sut.execute(
            "identity_verify", public_key=idn["public_key"], message=message, signature=bad
        )
        assert v["valid"] is False, f"malformed signature ({why}) must verify False, got {v}"


@conformance_case(
    commands=["announce_build", "announce_validate"],
    verifies="RNS.Identity.validate_announce rejects malformed announces by returning False and never crashes: a genuine announce validates True (positive anchor), but an announce whose BODY is truncated (signature/key slices fall short) or whose public-key bytes are corrupted validates False — exercising the body-truncation and undecodable-key paths the suite previously only hit at packet unpack",
)
def test_announce_validate_rejects_malformed_body(sut):
    info = sut.execute(
        "announce_build",
        private_key=random_hex(64),
        app_name="conformance",
        aspects=["identity_malformed"],
        app_data="",
        enable_ratchets=False,
    )
    raw = bytes.fromhex(info["raw"])
    # Positive anchor.
    assert sut.execute("announce_validate", raw=raw.hex())["valid"] is True
    # Negative: truncated announce bodies (still long enough to unpack as a packet,
    # but the announce field slices fall short) validate False, no crash.
    for cut in (5, 40, 80):
        truncated = raw[:-cut]
        v = sut.execute("announce_validate", raw=truncated.hex())
        assert v["valid"] is False, f"truncated announce (-{cut} bytes) must validate False, got {v}"
    # Negative: corrupt a byte inside the announced public key (data starts at
    # offset 19 in a HEADER_1 packet) -> derived destination_hash + signature both
    # fail; validate False without raising.
    corrupted = bytearray(raw)
    corrupted[25] ^= 0xFF
    v = sut.execute("announce_validate", raw=bytes(corrupted).hex())
    assert v["valid"] is False, f"corrupted-pubkey announce must validate False, got {v}"
