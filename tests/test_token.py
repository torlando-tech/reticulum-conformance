"""Token (Fernet-like) conformance tests.

Tests RNS Token encryption, decryption, and HMAC verification. RNS Token
generates the AES IV internally and fresh per call, so tokens are
non-deterministic — these tests round-trip through decrypt rather than
byte-comparing ciphertext.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Token Encryption"
__category_order__ = 3


@conformance_case(
    commands=["token_encrypt", "token_decrypt"],
    verifies="RNS Token encrypt/decrypt round-trip (Fernet-like AES-256-CBC + HMAC-SHA256): a token encrypted by an impl decrypts back to the original plaintext on that same impl",
)
def test_token_encrypt_decrypt(sut, reference):
    key = random_hex(64)  # 32B signing + 32B encryption
    plaintext = random_hex(48)
    for impl in (reference, sut):
        enc = impl.execute("token_encrypt", key=key, plaintext=plaintext)
        dec = impl.execute("token_decrypt", key=key, token=enc["token"])
        assert_hex_equal(dec["plaintext"], plaintext)


@conformance_case(
    commands=["token_encrypt", "token_verify_hmac"],
    verifies="Both impls verify the HMAC tag on a well-formed RNS Token as valid — positive control on the verify path",
)
def test_token_verify_hmac(sut, reference):
    key = random_hex(64)
    plaintext = random_hex(32)
    ref = reference.execute("token_encrypt", key=key, plaintext=plaintext)
    ref_v = reference.execute("token_verify_hmac", key=key, token=ref["token"])
    res_v = sut.execute("token_verify_hmac", key=key, token=ref["token"])
    assert ref_v["valid"] is True
    assert res_v["valid"] is True


@conformance_case(
    commands=["token_encrypt", "token_verify_hmac"],
    verifies="Negative control (with positive control): token_verify_hmac returns valid=True for a well-formed RNS Token and valid=False for a token with one flipped bit in its trailing HMAC-SHA256 tag — so a stub verifier that always returns True is caught. Both assertions run on each impl.",
)
def test_token_verify_hmac_rejects_tampered(sut, reference):
    key = random_hex(64)
    plaintext = random_hex(32)
    token = reference.execute(
        "token_encrypt", key=key, plaintext=plaintext
    )["token"]

    # Token layout is IV(16) || AES-256-CBC ciphertext || HMAC-SHA256(32);
    # flipping the final byte tampers the HMAC tag, which verify must reject.
    tok_bytes = bytearray.fromhex(token)
    tok_bytes[-1] ^= 0x01
    tampered = tok_bytes.hex()

    for impl, label in ((reference, "reference"), (sut, "sut")):
        # Positive control: a well-formed token's HMAC must verify (guards
        # against a verifier that always returns False).
        good = impl.execute("token_verify_hmac", key=key, token=token)
        assert good["valid"] is True, (
            f"{label} rejected a well-formed token HMAC (positive control "
            f"failed) — the negative assertion below would be meaningless"
        )
        # Negative: a flipped HMAC byte must NOT verify.
        bad = impl.execute("token_verify_hmac", key=key, token=tampered)
        assert bad["valid"] is False, (
            f"{label} accepted a token with a flipped HMAC byte as valid"
        )


@conformance_case(
    commands=["token_encrypt", "token_decrypt"],
    verifies="Negative control (with positive control): a well-formed token decrypts to its plaintext, but decrypting a token with one flipped bit in its HMAC tag fails authentication — RNS Token.decrypt raises ('Token HMAC was invalid'), which the bridge surfaces as an error, rather than returning forged plaintext. Both paths run on each impl.",
)
def test_token_decrypt_rejects_tampered(sut, reference):
    key = random_hex(64)
    plaintext = random_hex(32)
    token = reference.execute(
        "token_encrypt", key=key, plaintext=plaintext
    )["token"]

    tok_bytes = bytearray.fromhex(token)
    tok_bytes[-1] ^= 0x01  # flip a byte in the trailing HMAC tag
    tampered = tok_bytes.hex()

    for impl, label in ((reference, "reference"), (sut, "sut")):
        # Positive control: the well-formed token decrypts (guards against a
        # decryptor that always raises / always returns None).
        dec = impl.execute("token_decrypt", key=key, token=token)
        assert_hex_equal(dec["plaintext"], plaintext, msg=f"{label} positive control")
        # Negative: the tampered token must NOT yield plaintext. RNS Token
        # raises on HMAC failure, surfaced as a BridgeError. Silently returning
        # any plaintext for a forged HMAC is the failure mode caught here.
        try:
            res = impl.execute("token_decrypt", key=key, token=tampered)
        except BridgeError:
            continue  # raised on authentication failure — expected
        raise AssertionError(
            f"{label} decrypted a token with a flipped HMAC byte instead of "
            f"failing authentication: {res!r}"
        )


@conformance_case(
    commands=["token_encrypt", "token_decrypt"],
    verifies="RNS Token cross-impl interop: tokens produced by either impl decrypt to the original plaintext on the other",
)
def test_token_cross_decrypt(sut, reference):
    """Encrypt with SUT, decrypt with reference and vice versa."""
    key = random_hex(64)
    plaintext = random_hex(100)
    # SUT encrypt -> reference decrypt
    res_enc = sut.execute("token_encrypt", key=key, plaintext=plaintext)
    ref_dec = reference.execute("token_decrypt", key=key, token=res_enc["token"])
    assert_hex_equal(ref_dec["plaintext"], plaintext)
    # Reference encrypt -> SUT decrypt
    ref_enc = reference.execute("token_encrypt", key=key, plaintext=plaintext)
    res_dec = sut.execute("token_decrypt", key=key, token=ref_enc["token"])
    assert_hex_equal(res_dec["plaintext"], plaintext)


@conformance_case(
    commands=["token_encrypt"],
    verifies="Invariant: two RNS Tokens encrypted from byte-identical key+plaintext differ (RNS draws a fresh AES IV per call) — a deterministic token would reuse the IV and leak plaintext equality",
)
def test_token_encrypt_is_fresh_per_call(sut, reference):
    key = random_hex(64)
    plaintext = random_hex(48)
    first = sut.execute("token_encrypt", key=key, plaintext=plaintext)
    second = sut.execute("token_encrypt", key=key, plaintext=plaintext)
    assert first["token"] != second["token"], (
        "two encryptions of identical plaintext produced identical tokens — "
        "the AES IV is being reused, which leaks plaintext equality"
    )
