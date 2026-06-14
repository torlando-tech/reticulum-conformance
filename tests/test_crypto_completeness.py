"""Cryptographic primitive completeness tests (gap-closing).

This module closes coverage gaps in the `crypto` subsystem that the existing
``tests/test_crypto.py`` / ``tests/test_token.py`` / ``tests/test_identity.py``
do not pin. Every rule here is anchored to an EXTERNAL standard or to a SPEC
LITERAL read straight out of the installed RNS 1.3.1 source tree — never an
impl-vs-itself tautology:

  * HKDF output-length validation         -> RNS Cryptography/HKDF.py:41-42
        (``if length == None or length < 1: raise ValueError``)
  * PKCS7 lax unpad ACCEPT boundary       -> RNS Cryptography/PKCS7.py:38-44
        (``n = data[-1]; if n > bs: raise else: return data[:l-n]`` — the
        trailing-byte CONTENT is never validated, and ``n == 0`` strips nothing)
  * Token post-HMAC decrypt failure       -> RNS Cryptography/Token.py:106-114
        (HMAC is verified FIRST; a body that passes HMAC but fails AES/PKCS7
        is rejected with ``Could not decrypt token``, never partially returned)
  * Token too-short rejection             -> RNS Cryptography/Token.py:78
        (``if len(token) <= 32: raise ValueError``)
  * X25519 32-byte length validation      -> RNS Cryptography/X25519.py:66-69
        (``_unpack_number``: ``if len(s) != 32: raise``)
  * Ed25519 verify is a total predicate   -> wrong-length public key -> False,
        not an exception (bridge wraps the verify in try/except -> boolean)
  * Identity ECIES 80-byte overhead +     -> RNS Identity.py:875 boundary
        sub-33-byte ciphertext rejection      (``len(ciphertext) > KEYSIZE//8//2``
        with KEYSIZE==512 -> must exceed 32 bytes) and the
        ephemeral-pub(32) + Token-overhead(48) = 80-byte composite overhead.

The negative side of each rule carries a positive control so a test that
vacuously rejects everything cannot pass green.
"""

import pytest

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Cryptographic Primitives"
__category_order__ = 1


# --- HKDF output-length validation (gap: hkdf-input-validation) ---------------


@conformance_case(
    commands=["hkdf"],
    verifies="HKDF enforces a positive output length per RNS HKDF.py:41-42 "
    "(`if length == None or length < 1: raise ValueError`): length=1 derives "
    "exactly one byte (positive control) while length=0 and length=-1 are "
    "rejected on both impls — an impl that returns empty/garbage for a "
    "non-positive length instead of raising fails",
)
def test_hkdf_rejects_nonpositive_length(sut, reference):
    ikm = random_hex(32)
    salt = random_hex(16)
    for impl in (reference, sut):
        # Positive control: the smallest valid length yields exactly one byte.
        ok = impl.execute("hkdf", length=1, ikm=ikm, salt=salt)
        assert len(bytes.fromhex(ok["derived_key"])) == 1
        # Negative: length 0 and length -1 are below the >=1 floor.
        for bad_len in (0, -1):
            with pytest.raises(BridgeError):
                impl.execute("hkdf", length=bad_len, ikm=ikm, salt=salt)


# --- PKCS7 lax unpad ACCEPT boundary (gap: pkcs7-unpad-lax-validation) --------


@conformance_case(
    commands=["pkcs7_pad", "pkcs7_unpad"],
    verifies="RNS PKCS7.unpad (PKCS7.py:38-44) is intentionally LAX: it strips "
    "`data[-1]` bytes and only rejects when that count exceeds the 16-byte "
    "block — it never checks that the stripped bytes actually equal the pad "
    "value. A block of 15x0xAA + 0x05 unpads to the first 11 0xAA bytes "
    "(content of the pad is ignored), and a block ending in 0x00 strips "
    "nothing and returns all 16 bytes. A stricter impl that validates pad "
    "content would diverge from the reference on these inputs",
)
def test_pkcs7_unpad_is_content_lax(sut, reference):
    # Independent anchors: the exact bytes RNS's strip-n rule must yield.
    # n = last byte = 0x05 -> strip 5; content (0xAA, not 0x05) is NOT checked.
    mismatched = "aa" * 15 + "05"
    expect_mismatched = "aa" * 11
    # n = last byte = 0x00 -> strip nothing; full 16 bytes returned verbatim.
    zero_terminated = "aa" * 15 + "00"
    expect_zero = "aa" * 15 + "00"
    for impl in (reference, sut):
        # Positive control: a genuinely padded block still round-trips.
        data = random_hex(10)
        padded = impl.execute("pkcs7_pad", data=data)["padded"]
        assert_hex_equal(impl.execute("pkcs7_unpad", data=padded)["unpadded"], data)
        # Lax accept: pad-content mismatch is tolerated, n bytes are stripped.
        assert_hex_equal(
            impl.execute("pkcs7_unpad", data=mismatched)["unpadded"],
            expect_mismatched,
            "PKCS7.unpad must strip 5 bytes regardless of pad content",
        )
        # n == 0 strips nothing.
        assert_hex_equal(
            impl.execute("pkcs7_unpad", data=zero_terminated)["unpadded"],
            expect_zero,
            "PKCS7.unpad of a 0x00-terminated block must return all 16 bytes",
        )


# --- Token: post-HMAC decrypt failure rejection -------------------------------
# (gap: token-decrypt-failure-rejection)


@conformance_case(
    commands=["token_encrypt", "token_decrypt", "token_verify_hmac", "hmac_sha256"],
    verifies="RNS Token authenticates BEFORE decrypting and rejects a body that "
    "passes the HMAC gate but fails AES/PKCS7 (Token.py:106-114, `raise "
    "ValueError('Could not decrypt token')`). A forged token whose ciphertext "
    "region is a non-block-multiple length is given a VALID HMAC over IV||ct "
    "with the signing half of the key (so token_verify_hmac returns True — the "
    "auth gate is passed), yet token_decrypt rejects it rather than returning "
    "partial/garbage plaintext. A real token_encrypt token is the positive "
    "control",
)
def test_token_post_hmac_decrypt_failure_rejected(sut):
    key = random_hex(64)                      # 64 bytes -> AES-256 Token mode
    signing_key = key[:64]                    # key[0:32] in hex chars
    # Positive control: a genuine token verifies and decrypts.
    plaintext = random_hex(40)
    good_token = sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"]
    assert sut.execute("token_verify_hmac", key=key, token=good_token)["valid"] is True
    assert_hex_equal(
        sut.execute("token_decrypt", key=key, token=good_token)["plaintext"], plaintext
    )
    # Forge a token with a structurally-valid HMAC but an undecryptable body:
    # ciphertext is 10 bytes (NOT a multiple of the 16-byte AES block), so AES
    # decryption raises after the HMAC check passes.
    iv = random_hex(16)
    bad_ciphertext = random_hex(10)           # non-block-multiple -> AES fails
    signed_parts = iv + bad_ciphertext        # IV || ciphertext
    mac = sut.execute("hmac_sha256", key=signing_key, message=signed_parts)["hmac"]
    forged = signed_parts + mac
    # The HMAC gate is genuinely passed...
    assert sut.execute("token_verify_hmac", key=key, token=forged)["valid"] is True
    # ...but the post-HMAC AES/PKCS7 stage rejects the token.
    with pytest.raises(BridgeError):
        sut.execute("token_decrypt", key=key, token=forged)


# --- Token: too-short token rejection -----------------------------------------
# (gap: token-hmac-verify-before-decrypt remainder)


@conformance_case(
    commands=["token_encrypt", "token_decrypt", "token_verify_hmac"],
    verifies="RNS Token rejects any token of 32 bytes or fewer before "
    "attempting decryption (Token.py:78, `if len(token) <= 32: raise "
    "ValueError`) — there is no room for both a 32-byte HMAC and a body. A "
    "20-byte and an exactly-32-byte token are rejected by both verify_hmac and "
    "decrypt, while a genuine token_encrypt token (>32 bytes) is accepted "
    "(positive control)",
)
def test_token_rejects_too_short_token(sut):
    key = random_hex(64)
    # Positive control: a real token is longer than 32 bytes and decrypts.
    plaintext = random_hex(16)
    good = sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"]
    assert len(bytes.fromhex(good)) > 32
    assert sut.execute("token_verify_hmac", key=key, token=good)["valid"] is True
    # Negative: tokens of <= 32 bytes cannot carry an HMAC-protected body.
    for nbytes in (20, 32):
        short = random_hex(nbytes)
        with pytest.raises(BridgeError):
            sut.execute("token_verify_hmac", key=key, token=short)
        with pytest.raises(BridgeError):
            sut.execute("token_decrypt", key=key, token=short)


# --- X25519 32-byte length validation (gap: x25519-length-validation) ---------


@conformance_case(
    commands=["x25519_generate", "x25519_public_from_private", "x25519_exchange"],
    verifies="X25519 keys/peer values must be EXACTLY 32 bytes per RNS "
    "X25519.py:66-69 (`_unpack_number`: `if len(s) != 32: raise "
    "ValueError('Curve25519 values must be 32 bytes')`). A 32-byte seed "
    "generates a keypair (positive control), but 31-byte and 33-byte private "
    "or peer-public values are rejected rather than silently truncated or "
    "zero-extended — across x25519_generate, x25519_public_from_private and "
    "x25519_exchange",
)
def test_x25519_rejects_non_32_byte_values(sut, reference):
    for impl in (reference, sut):
        # Positive control: a 32-byte seed yields a 32-byte public key.
        good = impl.execute("x25519_generate", seed=random_hex(32))
        assert len(bytes.fromhex(good["public_key"])) == 32
        good_priv = good["private_key"]
        good_pub = good["public_key"]
        for nbytes in (31, 33):
            wrong = random_hex(nbytes)
            # Wrong-length seed into key generation.
            with pytest.raises(BridgeError):
                impl.execute("x25519_generate", seed=wrong)
            # Wrong-length private key into public-key derivation.
            with pytest.raises(BridgeError):
                impl.execute("x25519_public_from_private", private_key=wrong)
            # Wrong-length peer public key into the exchange.
            with pytest.raises(BridgeError):
                impl.execute(
                    "x25519_exchange", private_key=good_priv, peer_public_key=wrong
                )
            # Wrong-length private scalar into the exchange.
            with pytest.raises(BridgeError):
                impl.execute(
                    "x25519_exchange", private_key=wrong, peer_public_key=good_pub
                )


# --- Ed25519 verify total predicate on wrong-length public key ----------------
# (gap: ed25519-verify-accept-reject remainder)


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Ed25519 verification is a TOTAL predicate over its public-key "
    "input: a valid signature verifies True under its correct 32-byte public "
    "key (positive anchor), but presenting a wrong-LENGTH public key (31 or 33 "
    "bytes) returns valid=False as a boolean — NOT raised — so an impl that "
    "crashes on a malformed public key instead of rejecting it fails",
)
def test_ed25519_verify_wrong_length_public_key_returns_false(sut, reference):
    seed = random_hex(32)
    message = random_hex(48)
    keys = reference.execute("ed25519_generate", seed=seed)
    sig = reference.execute(
        "ed25519_sign", private_key=keys["private_key"], message=message
    )["signature"]
    # Positive anchor: correct 32-byte key verifies True.
    assert sut.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=sig
    )["valid"] is True
    # Negative: wrong-length public keys return a boolean False, never raise.
    for nbytes, why in ((31, "one short"), (33, "one long")):
        bad_pub = random_hex(nbytes)
        v = sut.execute(
            "ed25519_verify", public_key=bad_pub, message=message, signature=sig
        )
        assert v["valid"] is False, f"{why} public key must verify False, got {v}"


# --- Identity ECIES composite: 80-byte overhead + short-ciphertext reject -----
# (gap: identity-ecies-composite remainder)


@conformance_case(
    commands=[
        "identity_from_private_key",
        "identity_encrypt",
        "identity_decrypt",
        "pkcs7_pad",
    ],
    verifies="RNS Identity ECIES output carries a fixed 80-byte overhead over "
    "the PKCS7-padded plaintext — 32-byte ephemeral X25519 public key + the "
    "48-byte Token overhead (IV 16 + HMAC 32). For a 40-byte plaintext (padded "
    "to 48) the ciphertext is exactly 128 bytes, and for empty plaintext "
    "(padded to 16) exactly 96 bytes, both == pkcs7_pad(plaintext) length + 80. "
    "Decryption inverts it (positive control), while a 32-byte ciphertext is "
    "rejected with plaintext=None per Identity.py:875 "
    "(`len(ciphertext) > KEYSIZE//8//2` with KEYSIZE==512 requires > 32 bytes)",
)
def test_identity_ecies_overhead_and_short_ciphertext_reject(sut):
    private_key = random_hex(64)              # 64-byte RNS Identity private key
    pub = sut.execute("identity_from_private_key", private_key=private_key)["public_key"]
    for plaintext in (random_hex(40), ""):
        padded = sut.execute("pkcs7_pad", data=plaintext)["padded"]
        padded_len = len(bytes.fromhex(padded))
        enc = sut.execute("identity_encrypt", public_key=pub, plaintext=plaintext)
        ct = bytes.fromhex(enc["ciphertext"])
        # Independent overhead derivation: 32 (ephemeral) + 16 (IV) + 32 (HMAC).
        assert len(ct) == padded_len + 80, (
            f"ECIES overhead must be 80 bytes over the padded plaintext; "
            f"got ciphertext {len(ct)} for padded {padded_len}"
        )
        # Positive control: it decrypts back to the original plaintext.
        dec = sut.execute(
            "identity_decrypt", private_key=private_key, ciphertext=enc["ciphertext"]
        )
        assert_hex_equal(dec["plaintext"] or "", plaintext, allow_empty=True)
    # Exact 40-byte case pins the absolute length, not just the formula.
    enc40 = sut.execute("identity_encrypt", public_key=pub, plaintext=random_hex(40))
    assert len(bytes.fromhex(enc40["ciphertext"])) == 128
    # Negative: a 32-byte ciphertext is at/below the KEYSIZE//8//2 boundary and
    # must be rejected (decrypt returns None), with no room for ephemeral+token.
    short = sut.execute(
        "identity_decrypt", private_key=private_key, ciphertext=random_hex(32)
    )
    assert short["plaintext"] is None
