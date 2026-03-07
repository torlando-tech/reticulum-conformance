"""Cryptographic primitive conformance tests.

Tests SHA-256, SHA-512, HMAC-SHA256, truncated hash, HKDF, AES-CBC,
PKCS7 padding, X25519 key exchange, and Ed25519 signatures by comparing
SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_sha256(sut, reference):
    data = random_hex(64)
    ref = reference.execute("sha256", data=data)
    res = sut.execute("sha256", data=data)
    assert_hex_equal(res["hash"], ref["hash"])


def test_sha512(sut, reference):
    data = random_hex(64)
    ref = reference.execute("sha512", data=data)
    res = sut.execute("sha512", data=data)
    assert_hex_equal(res["hash"], ref["hash"])


def test_hmac_sha256(sut, reference):
    key = random_hex(32)
    message = random_hex(48)
    ref = reference.execute("hmac_sha256", key=key, message=message)
    res = sut.execute("hmac_sha256", key=key, message=message)
    assert_hex_equal(res["hmac"], ref["hmac"])


def test_truncated_hash(sut, reference):
    data = random_hex(64)
    ref = reference.execute("truncated_hash", data=data)
    res = sut.execute("truncated_hash", data=data)
    assert_hex_equal(res["hash"], ref["hash"])


def test_hkdf(sut, reference):
    ikm = random_hex(32)
    salt = random_hex(16)
    ref = reference.execute("hkdf", length=64, ikm=ikm, salt=salt)
    res = sut.execute("hkdf", length=64, ikm=ikm, salt=salt)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


def test_hkdf_no_salt(sut, reference):
    ikm = random_hex(32)
    ref = reference.execute("hkdf", length=32, ikm=ikm)
    res = sut.execute("hkdf", length=32, ikm=ikm)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


def test_hkdf_with_info(sut, reference):
    ikm = random_hex(32)
    salt = random_hex(16)
    info = random_hex(8)
    ref = reference.execute("hkdf", length=48, ikm=ikm, salt=salt, info=info)
    res = sut.execute("hkdf", length=48, ikm=ikm, salt=salt, info=info)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


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


def test_x25519_generate(sut, reference):
    seed = random_hex(32)
    ref = reference.execute("x25519_generate", seed=seed)
    res = sut.execute("x25519_generate", seed=seed)
    assert_hex_equal(res["public_key"], ref["public_key"])


def test_x25519_public_from_private(sut, reference):
    seed = random_hex(32)
    ref = reference.execute("x25519_generate", seed=seed)
    res = sut.execute("x25519_public_from_private", private_key=ref["private_key"])
    ref2 = reference.execute("x25519_public_from_private", private_key=ref["private_key"])
    assert_hex_equal(res["public_key"], ref2["public_key"])


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


def test_ed25519_generate(sut, reference):
    seed = random_hex(32)
    ref = reference.execute("ed25519_generate", seed=seed)
    res = sut.execute("ed25519_generate", seed=seed)
    assert_hex_equal(res["public_key"], ref["public_key"])


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
