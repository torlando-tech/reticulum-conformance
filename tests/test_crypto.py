"""Cryptographic primitive conformance tests.

Tests SHA-256, SHA-512, HMAC-SHA256, truncated hash, HKDF, AES-CBC,
PKCS7 padding, X25519 key exchange, and Ed25519 signatures by comparing
SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Cryptographic Primitives"
__category_order__ = 1


@conformance_case(
    commands=["sha256"],
    verifies="SHA-256 of 64 random bytes is byte-identical across impls",
)
def test_sha256(sut, reference):
    data = random_hex(64)
    ref = reference.execute("sha256", data=data)
    res = sut.execute("sha256", data=data)
    assert_hex_equal(res["hash"], ref["hash"])


@conformance_case(
    commands=["sha512"],
    verifies="SHA-512 of 64 random bytes is byte-identical across impls",
)
def test_sha512(sut, reference):
    data = random_hex(64)
    ref = reference.execute("sha512", data=data)
    res = sut.execute("sha512", data=data)
    assert_hex_equal(res["hash"], ref["hash"])


@conformance_case(
    commands=["hmac_sha256"],
    verifies="HMAC-SHA256 of a random 32-byte key + 48-byte message is byte-identical",
)
def test_hmac_sha256(sut, reference):
    key = random_hex(32)
    message = random_hex(48)
    ref = reference.execute("hmac_sha256", key=key, message=message)
    res = sut.execute("hmac_sha256", key=key, message=message)
    assert_hex_equal(res["hmac"], ref["hmac"])


@conformance_case(
    commands=["truncated_hash"],
    verifies="RNS's 16-byte `truncated_hash` (`SHA-256[:16]`) is byte-identical — the building block for destination, packet, and ratchet IDs",
)
def test_truncated_hash(sut, reference):
    data = random_hex(64)
    ref = reference.execute("truncated_hash", data=data)
    res = sut.execute("truncated_hash", data=data)
    assert_hex_equal(res["hash"], ref["hash"])


@conformance_case(
    commands=["hkdf"],
    verifies="HKDF with a salt, 64-byte output is byte-identical",
)
def test_hkdf(sut, reference):
    ikm = random_hex(32)
    salt = random_hex(16)
    ref = reference.execute("hkdf", length=64, ikm=ikm, salt=salt)
    res = sut.execute("hkdf", length=64, ikm=ikm, salt=salt)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


@conformance_case(
    commands=["hkdf"],
    verifies="HKDF with **no salt** (zero-salt path), 32-byte output is byte-identical",
)
def test_hkdf_no_salt(sut, reference):
    ikm = random_hex(32)
    ref = reference.execute("hkdf", length=32, ikm=ikm)
    res = sut.execute("hkdf", length=32, ikm=ikm)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


@conformance_case(
    commands=["hkdf"],
    verifies="HKDF with salt **and an info-context label**, 48-byte output is byte-identical",
)
def test_hkdf_with_info(sut, reference):
    ikm = random_hex(32)
    salt = random_hex(16)
    info = random_hex(8)
    ref = reference.execute("hkdf", length=48, ikm=ikm, salt=salt, info=info)
    res = sut.execute("hkdf", length=48, ikm=ikm, salt=salt, info=info)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


@conformance_case(
    commands=["aes_encrypt", "aes_decrypt"],
    verifies="AES-256-CBC round-trip: with both impls given the same key, IV, and plaintext, encryption produces byte-identical ciphertext and decryption recovers the original",
)
def test_aes_encrypt_decrypt(sut, reference):
    plaintext = random_hex(48)
    key = random_hex(32)
    iv = random_hex(16)
    ref = reference.execute("aes_encrypt", plaintext=plaintext, key=key, iv=iv)
    res = sut.execute("aes_encrypt", plaintext=plaintext, key=key, iv=iv)
    assert_hex_equal(res["ciphertext"], ref["ciphertext"])
    # Also test decrypt
    ref_dec = reference.execute("aes_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv)
    res_dec = sut.execute("aes_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv)
    assert_hex_equal(res_dec["plaintext"], ref_dec["plaintext"])
    assert_hex_equal(res_dec["plaintext"], plaintext)


@conformance_case(
    commands=["pkcs7_pad", "pkcs7_unpad"],
    verifies="PKCS7 pad/unpad round-trip on non-aligned data: padding is byte-identical and unpadding recovers the original",
)
def test_pkcs7_pad_unpad(sut, reference):
    data = random_hex(13)  # Not a multiple of 16
    ref = reference.execute("pkcs7_pad", data=data)
    res = sut.execute("pkcs7_pad", data=data)
    assert_hex_equal(res["padded"], ref["padded"])
    # Unpad
    ref_unpad = reference.execute("pkcs7_unpad", data=ref["padded"])
    res_unpad = sut.execute("pkcs7_unpad", data=ref["padded"])
    assert_hex_equal(res_unpad["unpadded"], ref_unpad["unpadded"])
    assert_hex_equal(res_unpad["unpadded"], data)


@conformance_case(
    commands=["x25519_generate"],
    verifies="X25519 keypair generation from a deterministic seed yields byte-identical public key",
)
def test_x25519_generate(sut, reference):
    seed = random_hex(32)
    ref = reference.execute("x25519_generate", seed=seed)
    res = sut.execute("x25519_generate", seed=seed)
    assert_hex_equal(res["public_key"], ref["public_key"])


@conformance_case(
    commands=["x25519_generate", "x25519_public_from_private"],
    verifies="Deriving an X25519 public key from a **raw private key** (no seed path) yields byte-identical output",
)
def test_x25519_public_from_private(sut, reference):
    seed = random_hex(32)
    ref = reference.execute("x25519_generate", seed=seed)
    res = sut.execute("x25519_public_from_private", private_key=ref["private_key"])
    ref2 = reference.execute("x25519_public_from_private", private_key=ref["private_key"])
    assert_hex_equal(res["public_key"], ref2["public_key"])


@conformance_case(
    commands=["x25519_generate", "x25519_exchange"],
    verifies="X25519 ECDH between two keypairs produces a byte-identical shared secret — the basis of link key derivation",
)
def test_x25519_exchange(sut, reference):
    seed_a = random_hex(32)
    seed_b = random_hex(32)
    ref_a = reference.execute("x25519_generate", seed=seed_a)
    ref_b = reference.execute("x25519_generate", seed=seed_b)
    ref = reference.execute(
        "x25519_exchange",
        private_key=ref_a["private_key"],
        peer_public_key=ref_b["public_key"],
    )
    res = sut.execute(
        "x25519_exchange",
        private_key=ref_a["private_key"],
        peer_public_key=ref_b["public_key"],
    )
    assert_hex_equal(res["shared_secret"], ref["shared_secret"])


@conformance_case(
    commands=["ed25519_generate"],
    verifies="Ed25519 keypair generation from a deterministic seed yields byte-identical public key",
)
def test_ed25519_generate(sut, reference):
    seed = random_hex(32)
    ref = reference.execute("ed25519_generate", seed=seed)
    res = sut.execute("ed25519_generate", seed=seed)
    assert_hex_equal(res["public_key"], ref["public_key"])


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Ed25519 sign+verify: signing is deterministic per RFC 8032 (same input → byte-identical signature) and both impls verify each other's signatures",
)
def test_ed25519_sign_verify(sut, reference):
    seed = random_hex(32)
    message = random_hex(64)
    ref_keys = reference.execute("ed25519_generate", seed=seed)
    ref = reference.execute(
        "ed25519_sign", private_key=ref_keys["private_key"], message=message
    )
    res = sut.execute(
        "ed25519_sign", private_key=ref_keys["private_key"], message=message
    )
    assert_hex_equal(res["signature"], ref["signature"])
    # Verify
    ref_v = reference.execute(
        "ed25519_verify",
        public_key=ref_keys["public_key"],
        message=message,
        signature=ref["signature"],
    )
    res_v = sut.execute(
        "ed25519_verify",
        public_key=ref_keys["public_key"],
        message=message,
        signature=ref["signature"],
    )
    assert ref_v["valid"] is True
    assert res_v["valid"] is True


@conformance_case(
    commands=["ed25519_generate", "ed25519_verify"],
    verifies="Negative control: both impls reject a random (forged) Ed25519 signature",
)
def test_ed25519_verify_bad_sig(sut, reference):
    seed = random_hex(32)
    message = random_hex(64)
    ref_keys = reference.execute("ed25519_generate", seed=seed)
    bad_sig = random_hex(64)
    ref_v = reference.execute(
        "ed25519_verify",
        public_key=ref_keys["public_key"],
        message=message,
        signature=bad_sig,
    )
    res_v = sut.execute(
        "ed25519_verify",
        public_key=ref_keys["public_key"],
        message=message,
        signature=bad_sig,
    )
    assert ref_v["valid"] is False
    assert res_v["valid"] is False
