"""Cryptographic primitive conformance tests.

Tests SHA-256, SHA-512, HMAC-SHA256, truncated hash, HKDF, AES-CBC,
PKCS7 padding, X25519 key exchange, and Ed25519 signatures by comparing
SUT output against a reference implementation.

In addition to the differential (SUT-vs-reference) checks, this suite carries
a set of published known-answer vectors (RFC 8032 Ed25519, RFC 7748 X25519,
RFC 5869 HKDF, and the empty-string SHA-256/512 digests). Those anchor BOTH
impls to a fixed external constant, so a shared drift between the SUT and the
single reference can no longer pass green (audit finding L1).
"""

import pytest

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Cryptographic Primitives"
__category_order__ = 1


# --- Published known-answer vectors (self-anchoring; finding L1) -------------
#
# These are external RFC / FIPS constants, not values copied from any impl.
# Asserting both the SUT and the reference against them means a reference that
# silently drifts from the standard is caught, instead of both sides agreeing
# on a wrong answer.

# FIPS 180-4 — digest of the empty string.
SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA512_EMPTY = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)

# RFC 5869 — HKDF-SHA256, Test Case 1.
HKDF_RFC5869_TC1_IKM = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"  # 22 bytes
HKDF_RFC5869_TC1_SALT = "000102030405060708090a0b0c"  # 13 bytes
HKDF_RFC5869_TC1_INFO = "f0f1f2f3f4f5f6f7f8f9"  # 10 bytes
HKDF_RFC5869_TC1_LEN = 42
HKDF_RFC5869_TC1_OKM = (
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)

# RFC 7748 — X25519, first test vector (section 5.2).
X25519_RFC7748_SCALAR = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
X25519_RFC7748_U = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
X25519_RFC7748_OUTPUT = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

# RFC 4231 — HMAC-SHA256 known-answer vectors.
#   TC2: a short ASCII key ("Jefe") + message.
#   TC6: a 131-byte key (LONGER than the 64-byte SHA-256 block) — pins the
#        RFC 2104 rule that an over-long key is hashed down first.
HMAC_RFC4231_TC2_KEY = "4a656665"  # "Jefe"
HMAC_RFC4231_TC2_MSG = b"what do ya want for nothing?".hex()
HMAC_RFC4231_TC2_MAC = (
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
)
HMAC_RFC4231_TC6_KEY = "aa" * 131  # 131 bytes > 64-byte block size
HMAC_RFC4231_TC6_MSG = (
    b"Test Using Larger Than Block-Size Key - Hash Key First".hex()
)
HMAC_RFC4231_TC6_MAC = (
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
)

# NIST SP 800-38A, F.2.5 — CBC-AES256.Encrypt known-answer vector. Block-aligned
# (4 × 16-byte blocks), so it drives the RAW block cipher with no PKCS7 padding.
AES256_CBC_NIST_KEY = (
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
AES256_CBC_NIST_IV = "000102030405060708090a0b0c0d0e0f"
AES256_CBC_NIST_PT = (
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
AES256_CBC_NIST_CT = (
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    "9cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461"
    "b2eb05e2c39be9fcda6c19078c6a9d1b"
)

# RFC 8032 — Ed25519, Test 1 (section 7.1). Message is the empty string.
ED25519_RFC8032_T1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
ED25519_RFC8032_T1_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
ED25519_RFC8032_T1_MESSAGE = ""  # 0-byte message
ED25519_RFC8032_T1_SIGNATURE = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901"
    "555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def _flip_first_bit(hex_str):
    """Flip the lowest bit of the first byte of a hex string."""
    b = bytearray.fromhex(hex_str)
    b[0] ^= 0x01
    return b.hex()


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
    commands=["sha256"],
    verifies="Known-answer: SHA-256 of the empty string equals the FIPS 180-4 constant e3b0c442… on both the SUT and the reference",
)
def test_sha256_empty_string_kat(sut, reference):
    ref = reference.execute("sha256", data="")
    res = sut.execute("sha256", data="")
    # Anchor BOTH sides to the published constant, not just to each other.
    assert_hex_equal(ref["hash"], SHA256_EMPTY)
    assert_hex_equal(res["hash"], SHA256_EMPTY)


@conformance_case(
    commands=["sha512"],
    verifies="Known-answer: SHA-512 of the empty string equals the FIPS 180-4 constant cf83e135… on both the SUT and the reference",
)
def test_sha512_empty_string_kat(sut, reference):
    ref = reference.execute("sha512", data="")
    res = sut.execute("sha512", data="")
    assert_hex_equal(ref["hash"], SHA512_EMPTY)
    assert_hex_equal(res["hash"], SHA512_EMPTY)


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
    commands=["hkdf"],
    verifies="Known-answer: HKDF-SHA256 RFC 5869 Test Case 1 (IKM/salt/info fixed, L=42) yields the published 42-byte OKM 3cb25f25… on both the SUT and the reference",
)
def test_hkdf_rfc5869_test_case_1(sut, reference):
    ref = reference.execute(
        "hkdf",
        length=HKDF_RFC5869_TC1_LEN,
        ikm=HKDF_RFC5869_TC1_IKM,
        salt=HKDF_RFC5869_TC1_SALT,
        info=HKDF_RFC5869_TC1_INFO,
    )
    res = sut.execute(
        "hkdf",
        length=HKDF_RFC5869_TC1_LEN,
        ikm=HKDF_RFC5869_TC1_IKM,
        salt=HKDF_RFC5869_TC1_SALT,
        info=HKDF_RFC5869_TC1_INFO,
    )
    assert_hex_equal(ref["derived_key"], HKDF_RFC5869_TC1_OKM)
    assert_hex_equal(res["derived_key"], HKDF_RFC5869_TC1_OKM)
    assert len(res["derived_key"]) == HKDF_RFC5869_TC1_LEN * 2


@conformance_case(
    commands=["aes_encrypt", "aes_decrypt"],
    verifies="`aes_encrypt`/`aes_decrypt` are the AES-256-CBC **+ PKCS7** composite (RNS's Token layer), NOT the bare block cipher: a 48-byte (block-aligned) plaintext is grown by a full 16-byte PKCS7 pad block to 64 bytes of ciphertext, which is byte-identical across impls and round-trips back to the original",
)
def test_aes_encrypt_decrypt(sut, reference):
    plaintext = random_hex(48)  # 3 full AES blocks — PKCS7 still appends a block
    key = random_hex(32)
    iv = random_hex(16)
    ref = reference.execute("aes_encrypt", plaintext=plaintext, key=key, iv=iv)
    res = sut.execute("aes_encrypt", plaintext=plaintext, key=key, iv=iv)
    assert_hex_equal(res["ciphertext"], ref["ciphertext"])
    # PKCS7 grows block-aligned input by a whole block: 48 -> 64 bytes.
    assert len(res["ciphertext"]) == 64 * 2
    # Also test decrypt
    ref_dec = reference.execute("aes_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv)
    res_dec = sut.execute("aes_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv)
    assert_hex_equal(res_dec["plaintext"], ref_dec["plaintext"])
    assert_hex_equal(res_dec["plaintext"], plaintext)


@conformance_case(
    commands=["aes_256_cbc_encrypt", "aes_256_cbc_decrypt"],
    verifies="Raw AES-256-CBC (no padding): a block-aligned 32-byte plaintext encrypts to **exactly 32 bytes** of ciphertext (no PKCS7 growth), byte-identical across impls, and decrypts back to the original — distinguishing the bare block cipher from the `aes_encrypt` PKCS7 composite",
)
def test_aes_256_cbc_raw_no_padding(sut, reference):
    plaintext = random_hex(32)  # exactly 2 AES blocks; raw cipher requires alignment
    key = random_hex(32)
    iv = random_hex(16)
    ref = reference.execute("aes_256_cbc_encrypt", plaintext=plaintext, key=key, iv=iv)
    res = sut.execute("aes_256_cbc_encrypt", plaintext=plaintext, key=key, iv=iv)
    assert_hex_equal(res["ciphertext"], ref["ciphertext"])
    # Raw block cipher: ciphertext length == plaintext length, NO padding growth.
    assert len(res["ciphertext"]) == len(plaintext)
    assert len(res["ciphertext"]) == 32 * 2
    ref_dec = reference.execute("aes_256_cbc_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv)
    res_dec = sut.execute("aes_256_cbc_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv)
    assert_hex_equal(res_dec["plaintext"], ref_dec["plaintext"])
    assert_hex_equal(res_dec["plaintext"], plaintext)


@conformance_case(
    commands=["aes_encrypt", "aes_decrypt"],
    verifies="AES-**128**-CBC mode (`mode=AES_128_CBC`, 16-byte key) PKCS7 round-trip: ciphertext is byte-identical across impls and decryption recovers the original plaintext",
)
def test_aes_128_cbc_mode(sut, reference):
    plaintext = random_hex(48)
    key = random_hex(16)  # 128-bit key
    iv = random_hex(16)
    ref = reference.execute("aes_encrypt", plaintext=plaintext, key=key, iv=iv, mode="AES_128_CBC")
    res = sut.execute("aes_encrypt", plaintext=plaintext, key=key, iv=iv, mode="AES_128_CBC")
    assert_hex_equal(res["ciphertext"], ref["ciphertext"])
    ref_dec = reference.execute("aes_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv, mode="AES_128_CBC")
    res_dec = sut.execute("aes_decrypt", ciphertext=ref["ciphertext"], key=key, iv=iv, mode="AES_128_CBC")
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
    commands=["pkcs7_pad", "pkcs7_unpad"],
    verifies="PKCS7 on **block-aligned** input (16 bytes): a full 16-byte padding block of 0x10 is appended (padded length 32, byte-identical across impls) and unpadding strips exactly that block to recover the original",
)
def test_pkcs7_pad_unpad_block_aligned(sut, reference):
    data = random_hex(16)  # exactly one block — PKCS7 must append a WHOLE pad block
    ref = reference.execute("pkcs7_pad", data=data)
    res = sut.execute("pkcs7_pad", data=data)
    assert_hex_equal(res["padded"], ref["padded"])
    assert len(res["padded"]) == 32 * 2  # 16 data + 16 pad bytes
    # The appended block is 16 copies of 0x10 (the pad length).
    assert_hex_equal(res["padded"][32:], "10" * 16)
    ref_unpad = reference.execute("pkcs7_unpad", data=ref["padded"])
    res_unpad = sut.execute("pkcs7_unpad", data=ref["padded"])
    assert_hex_equal(res_unpad["unpadded"], data)
    assert_hex_equal(ref_unpad["unpadded"], data)


@conformance_case(
    commands=["pkcs7_pad", "pkcs7_unpad"],
    verifies="Negative control: PKCS7 unpad REJECTS a block whose declared padding length (0x11 = 17) exceeds the 16-byte block size — both impls raise an error — while a validly padded block (positive control) unpads cleanly",
)
def test_pkcs7_unpad_rejects_oversized_padding(sut, reference):
    # Positive control: a validly padded block must still unpad on both impls.
    data = random_hex(10)
    ref_padded = reference.execute("pkcs7_pad", data=data)["padded"]
    sut_padded = sut.execute("pkcs7_pad", data=data)["padded"]
    assert_hex_equal(reference.execute("pkcs7_unpad", data=ref_padded)["unpadded"], data)
    assert_hex_equal(sut.execute("pkcs7_unpad", data=sut_padded)["unpadded"], data)
    # Negative: last byte 0x11 (17) > block size 16 -> invalid padding length.
    bad = "00" * 15 + "11"
    with pytest.raises(BridgeError):
        reference.execute("pkcs7_unpad", data=bad)
    with pytest.raises(BridgeError):
        sut.execute("pkcs7_unpad", data=bad)


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
    commands=["x25519_generate", "x25519_public_from_private"],
    verifies="Round-trip of the SUT's OWN generated X25519 private key: deriving the public key from the private key the SUT itself produced reproduces the SUT's own public key, and matches the reference for the same seed",
)
def test_x25519_public_from_own_private(sut, reference):
    seed = random_hex(32)
    sut_kp = sut.execute("x25519_generate", seed=seed)
    ref_kp = reference.execute("x25519_generate", seed=seed)
    # Feed the SUT its OWN private key back in — not the reference's.
    sut_pub2 = sut.execute("x25519_public_from_private", private_key=sut_kp["private_key"])
    assert_hex_equal(sut_pub2["public_key"], sut_kp["public_key"])
    # Cross-impl anchor for the same seed.
    assert_hex_equal(sut_pub2["public_key"], ref_kp["public_key"])


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
    commands=["x25519_generate", "x25519_exchange"],
    verifies="X25519 ECDH symmetry on the SUT's OWN keypairs: a·B == b·A (privA×pubB equals privB×pubA), and that shared secret matches the reference for the same seed pair",
)
def test_x25519_ecdh_symmetry(sut, reference):
    seed_a = random_hex(32)
    seed_b = random_hex(32)
    sut_a = sut.execute("x25519_generate", seed=seed_a)
    sut_b = sut.execute("x25519_generate", seed=seed_b)
    ref_a = reference.execute("x25519_generate", seed=seed_a)
    ref_b = reference.execute("x25519_generate", seed=seed_b)
    # SUT computes the secret both directions using ITS OWN private keys.
    sut_ab = sut.execute(
        "x25519_exchange", private_key=sut_a["private_key"], peer_public_key=sut_b["public_key"]
    )["shared_secret"]
    sut_ba = sut.execute(
        "x25519_exchange", private_key=sut_b["private_key"], peer_public_key=sut_a["public_key"]
    )["shared_secret"]
    # Symmetry: a·B == b·A.
    assert_hex_equal(sut_ab, sut_ba)
    # Cross-impl anchor.
    ref_ab = reference.execute(
        "x25519_exchange", private_key=ref_a["private_key"], peer_public_key=ref_b["public_key"]
    )["shared_secret"]
    assert_hex_equal(sut_ab, ref_ab)


@conformance_case(
    commands=["x25519_exchange"],
    verifies="Known-answer: X25519 RFC 7748 §5.2 test vector 1 (fixed scalar + u-coordinate) yields the published shared secret c3da5537… on both the SUT and the reference",
)
def test_x25519_rfc7748_test_vector_1(sut, reference):
    ref = reference.execute(
        "x25519_exchange",
        private_key=X25519_RFC7748_SCALAR,
        peer_public_key=X25519_RFC7748_U,
    )
    res = sut.execute(
        "x25519_exchange",
        private_key=X25519_RFC7748_SCALAR,
        peer_public_key=X25519_RFC7748_U,
    )
    assert_hex_equal(ref["shared_secret"], X25519_RFC7748_OUTPUT)
    assert_hex_equal(res["shared_secret"], X25519_RFC7748_OUTPUT)


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
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Round-trip of the SUT's OWN generated Ed25519 private key: signing with the private key the SUT itself produced yields the RFC 8032 deterministic signature (matching the reference for the same seed) and verifies True under the SUT's own public key",
)
def test_ed25519_sign_with_own_private_key(sut, reference):
    seed = random_hex(32)
    message = random_hex(64)
    sut_keys = sut.execute("ed25519_generate", seed=seed)
    ref_keys = reference.execute("ed25519_generate", seed=seed)
    # Sign with the SUT's OWN private key (not the reference's).
    sut_sig = sut.execute(
        "ed25519_sign", private_key=sut_keys["private_key"], message=message
    )["signature"]
    ref_sig = reference.execute(
        "ed25519_sign", private_key=ref_keys["private_key"], message=message
    )["signature"]
    # Deterministic Ed25519: same seed+message -> same signature across impls.
    assert_hex_equal(sut_sig, ref_sig)
    # Verifies under the SUT's own public key on both impls.
    sut_v = sut.execute(
        "ed25519_verify", public_key=sut_keys["public_key"], message=message, signature=sut_sig
    )
    ref_v = reference.execute(
        "ed25519_verify", public_key=sut_keys["public_key"], message=message, signature=sut_sig
    )
    assert sut_v["valid"] is True
    assert ref_v["valid"] is True


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Known-answer: Ed25519 RFC 8032 §7.1 Test 1 (fixed seed, empty message) reproduces the published public key d75a9801… and signature e5564300…; both impls produce those exact bytes and verify them True",
)
def test_ed25519_rfc8032_test_1(sut, reference):
    ref_keys = reference.execute("ed25519_generate", seed=ED25519_RFC8032_T1_SEED)
    sut_keys = sut.execute("ed25519_generate", seed=ED25519_RFC8032_T1_SEED)
    assert_hex_equal(ref_keys["public_key"], ED25519_RFC8032_T1_PUBLIC)
    assert_hex_equal(sut_keys["public_key"], ED25519_RFC8032_T1_PUBLIC)
    ref_sig = reference.execute(
        "ed25519_sign",
        private_key=ref_keys["private_key"],
        message=ED25519_RFC8032_T1_MESSAGE,
    )
    sut_sig = sut.execute(
        "ed25519_sign",
        private_key=sut_keys["private_key"],
        message=ED25519_RFC8032_T1_MESSAGE,
    )
    assert_hex_equal(ref_sig["signature"], ED25519_RFC8032_T1_SIGNATURE)
    assert_hex_equal(sut_sig["signature"], ED25519_RFC8032_T1_SIGNATURE)
    # The published signature must verify against the published public key.
    ref_v = reference.execute(
        "ed25519_verify",
        public_key=ED25519_RFC8032_T1_PUBLIC,
        message=ED25519_RFC8032_T1_MESSAGE,
        signature=ED25519_RFC8032_T1_SIGNATURE,
    )
    sut_v = sut.execute(
        "ed25519_verify",
        public_key=ED25519_RFC8032_T1_PUBLIC,
        message=ED25519_RFC8032_T1_MESSAGE,
        signature=ED25519_RFC8032_T1_SIGNATURE,
    )
    assert ref_v["valid"] is True
    assert sut_v["valid"] is True


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


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Negative control with positive anchor: a valid Ed25519 signature verifies True, but flipping a single bit of the **message** makes the same signature verify False on both impls (tampered-message detection)",
)
def test_ed25519_verify_tampered_message(sut, reference):
    seed = random_hex(32)
    message = random_hex(64)
    keys = reference.execute("ed25519_generate", seed=seed)
    sig = reference.execute(
        "ed25519_sign", private_key=keys["private_key"], message=message
    )["signature"]
    # Positive control: the untampered message verifies True on both impls.
    assert reference.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=sig
    )["valid"] is True
    assert sut.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=sig
    )["valid"] is True
    # Negative: one-bit message tamper must invalidate the signature on both.
    tampered = _flip_first_bit(message)
    assert reference.execute(
        "ed25519_verify", public_key=keys["public_key"], message=tampered, signature=sig
    )["valid"] is False
    assert sut.execute(
        "ed25519_verify", public_key=keys["public_key"], message=tampered, signature=sig
    )["valid"] is False


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Negative control with positive anchor: a valid Ed25519 signature verifies True, but flipping a single bit of the **signature** makes it verify False on both impls (tampered-signature detection)",
)
def test_ed25519_verify_tampered_signature(sut, reference):
    seed = random_hex(32)
    message = random_hex(64)
    keys = reference.execute("ed25519_generate", seed=seed)
    sig = reference.execute(
        "ed25519_sign", private_key=keys["private_key"], message=message
    )["signature"]
    # Positive control.
    assert reference.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=sig
    )["valid"] is True
    assert sut.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=sig
    )["valid"] is True
    # Negative: one-bit signature tamper must invalidate verification on both.
    tampered_sig = _flip_first_bit(sig)
    assert reference.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=tampered_sig
    )["valid"] is False
    assert sut.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=tampered_sig
    )["valid"] is False


# --- HMAC-SHA256 RFC 4231 known-answer vectors (gap: hmac-sha256-rfc2104) -----


@conformance_case(
    commands=["hmac_sha256"],
    verifies="Known-answer: HMAC-SHA256 RFC 4231 Test Case 2 (key 'Jefe', message 'what do ya want for nothing?') yields the published MAC 5bdcc146… on both the SUT and the reference — anchors the HMAC to RFC 2104/4231, not just to the other impl",
)
def test_hmac_sha256_rfc4231_tc2(sut, reference):
    ref = reference.execute("hmac_sha256", key=HMAC_RFC4231_TC2_KEY, message=HMAC_RFC4231_TC2_MSG)
    res = sut.execute("hmac_sha256", key=HMAC_RFC4231_TC2_KEY, message=HMAC_RFC4231_TC2_MSG)
    assert_hex_equal(ref["hmac"], HMAC_RFC4231_TC2_MAC)
    assert_hex_equal(res["hmac"], HMAC_RFC4231_TC2_MAC)


@conformance_case(
    commands=["hmac_sha256"],
    verifies="Known-answer: HMAC-SHA256 RFC 4231 Test Case 6 uses a 131-byte key — LONGER than SHA-256's 64-byte block — and must reproduce the published MAC 60e43159…, pinning the RFC 2104 rule that an over-length key is hashed down to the block size first (an impl that truncates or pads the long key instead diverges)",
)
def test_hmac_sha256_rfc4231_tc6_larger_than_block_key(sut, reference):
    ref = reference.execute("hmac_sha256", key=HMAC_RFC4231_TC6_KEY, message=HMAC_RFC4231_TC6_MSG)
    res = sut.execute("hmac_sha256", key=HMAC_RFC4231_TC6_KEY, message=HMAC_RFC4231_TC6_MSG)
    assert_hex_equal(ref["hmac"], HMAC_RFC4231_TC6_MAC)
    assert_hex_equal(res["hmac"], HMAC_RFC4231_TC6_MAC)


# --- AES-256-CBC semantics (gap: aes-cbc-semantics) ---------------------------


@conformance_case(
    commands=["aes_256_cbc_encrypt", "aes_256_cbc_decrypt"],
    verifies="Known-answer: raw AES-256-CBC matches NIST SP 800-38A §F.2.5 (fixed key/IV, 4 block-aligned plaintext blocks) byte-for-byte (ciphertext f58c4c04…) on both impls, and decrypt inverts it back to the NIST plaintext — pins the block cipher to FIPS-197/SP800-38A rather than to the other impl",
)
def test_aes256_cbc_nist_sp800_38a_kat(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        ct = impl.execute(
            "aes_256_cbc_encrypt",
            plaintext=AES256_CBC_NIST_PT, key=AES256_CBC_NIST_KEY, iv=AES256_CBC_NIST_IV,
        )["ciphertext"]
        assert_hex_equal(ct, AES256_CBC_NIST_CT, f"{label}: NIST CBC-AES256 ciphertext")
        pt = impl.execute(
            "aes_256_cbc_decrypt",
            ciphertext=AES256_CBC_NIST_CT, key=AES256_CBC_NIST_KEY, iv=AES256_CBC_NIST_IV,
        )["plaintext"]
        assert_hex_equal(pt, AES256_CBC_NIST_PT, f"{label}: NIST CBC-AES256 decrypt")


@conformance_case(
    commands=["aes_256_cbc_encrypt"],
    verifies="AES-256-CBC enforces its operand lengths: a correct 32-byte key + 16-byte IV encrypts (positive control), but a wrong-length key (16 bytes) or a wrong-length IV (8 bytes) is rejected rather than silently producing ciphertext under a mis-sized operand",
)
def test_aes256_cbc_rejects_wrong_key_and_iv_lengths(sut):
    block = random_hex(16)
    good_key = random_hex(32)
    good_iv = random_hex(16)
    # Positive control: correctly-sized operands encrypt.
    ok = sut.execute("aes_256_cbc_encrypt", plaintext=block, key=good_key, iv=good_iv)
    assert len(bytes.fromhex(ok["ciphertext"])) == 16
    # Negative: a 16-byte (AES-128-sized) key must be rejected for AES-256.
    with pytest.raises(BridgeError):
        sut.execute("aes_256_cbc_encrypt", plaintext=block, key=random_hex(16), iv=good_iv)
    # Negative: a wrong-length IV (must be one 16-byte block) is rejected.
    with pytest.raises(BridgeError):
        sut.execute("aes_256_cbc_encrypt", plaintext=block, key=good_key, iv=random_hex(8))


# --- RNS Token: key split, mode selection, IV freshness, HMAC-before-decrypt --
# (gaps: token-key-split-and-mode-selection, aes256-default-in-1-3,
#  token-iv-csprng-unique, token-hmac-verify-before-decrypt)


@conformance_case(
    commands=["token_encrypt", "aes_encrypt", "hmac_sha256"],
    verifies="RNS Token with a 64-byte key selects AES-256-CBC and splits the key signing-first: the emitted token decomposes to IV(16) || ciphertext || HMAC(32) where ciphertext == AES-256-CBC+PKCS7(plaintext) under key[32:64] and HMAC == HMAC-SHA256(key[0:32], IV||ciphertext). Decomposing against the AES/HMAC primitives pins the exact split + mode + the 48-byte overhead, so an impl that swaps the halves or uses AES-128 for a 256-bit key fails",
)
def test_token_key_split_and_mode_aes256(sut):
    key = random_hex(64)            # 512 bits -> AES-256 path
    plaintext = random_hex(40)
    token = bytes.fromhex(sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"])
    iv, ciphertext, mac = token[:16], token[16:-32], token[-32:]
    assert len(token) - len(ciphertext) == 48, "Token overhead must be IV(16)+HMAC(32)=48"
    assert len(ciphertext) % 16 == 0 and len(ciphertext) > 0
    kb = bytes.fromhex(key)
    expected_ct = sut.execute(
        "aes_encrypt", plaintext=plaintext, key=kb[32:].hex(), iv=iv.hex(), mode="AES_256_CBC",
    )["ciphertext"]
    assert_hex_equal(ciphertext.hex(), expected_ct, "ciphertext not AES-256-CBC under key[32:64]")
    expected_mac = sut.execute("hmac_sha256", key=kb[:32].hex(), message=(iv + ciphertext).hex())["hmac"]
    assert_hex_equal(mac.hex(), expected_mac, "HMAC not HMAC-SHA256(key[0:32], IV||ct)")


@conformance_case(
    commands=["token_encrypt", "aes_encrypt", "hmac_sha256"],
    verifies="RNS Token with a 32-byte key selects AES-128-CBC and splits signing-first over the smaller halves: the token decomposes to IV(16) || ciphertext || HMAC(32) where ciphertext == AES-128-CBC+PKCS7(plaintext) under key[16:32] and HMAC == HMAC-SHA256(key[0:16], IV||ciphertext) — pins that a 128-bit key still maps to AES-128 (1.3.x retains AES-128 accept) with the 16/16 split",
)
def test_token_key_split_and_mode_aes128(sut):
    key = random_hex(32)            # 256 bits -> AES-128 path
    plaintext = random_hex(40)
    token = bytes.fromhex(sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"])
    iv, ciphertext, mac = token[:16], token[16:-32], token[-32:]
    kb = bytes.fromhex(key)
    expected_ct = sut.execute(
        "aes_encrypt", plaintext=plaintext, key=kb[16:].hex(), iv=iv.hex(), mode="AES_128_CBC",
    )["ciphertext"]
    assert_hex_equal(ciphertext.hex(), expected_ct, "ciphertext not AES-128-CBC under key[16:32]")
    expected_mac = sut.execute("hmac_sha256", key=kb[:16].hex(), message=(iv + ciphertext).hex())["hmac"]
    assert_hex_equal(mac.hex(), expected_mac, "HMAC not HMAC-SHA256(key[0:16], IV||ct)")


@conformance_case(
    commands=["token_encrypt", "token_decrypt"],
    verifies="RNS Token keys must be exactly 128 or 256 bits: 32-byte and 64-byte keys encrypt+round-trip (positive controls), while a 48-byte key (any other length) is rejected at construction — pins the mode-selection length gate",
)
def test_token_rejects_invalid_key_length(sut):
    plaintext = random_hex(24)
    for klen in (32, 64):
        key = random_hex(klen)
        tok = sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"]
        assert_hex_equal(sut.execute("token_decrypt", key=key, token=tok)["plaintext"], plaintext)
    with pytest.raises(BridgeError):
        sut.execute("token_encrypt", key=random_hex(48), plaintext=plaintext)


@conformance_case(
    commands=["token_encrypt", "token_decrypt"],
    verifies="RNS Token IVs come from a CSPRNG fresh per encryption: two encryptions of the SAME plaintext under the SAME key produce different tokens AND different leading 16-byte IVs, yet both decrypt back to the original plaintext — an impl that reuses or zeroes the IV produces identical tokens and fails",
)
def test_token_iv_fresh_per_encryption(sut):
    key = random_hex(64)
    plaintext = random_hex(32)
    t1 = bytes.fromhex(sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"])
    t2 = bytes.fromhex(sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"])
    assert t1 != t2, "two encryptions of identical input produced identical tokens (IV reuse)"
    assert t1[:16] != t2[:16], "the 16-byte IVs were identical across encryptions"
    assert_hex_equal(sut.execute("token_decrypt", key=key, token=t1.hex())["plaintext"], plaintext)
    assert_hex_equal(sut.execute("token_decrypt", key=key, token=t2.hex())["plaintext"], plaintext)


@conformance_case(
    commands=["token_encrypt", "token_decrypt", "token_verify_hmac"],
    verifies="RNS Token authenticates before decrypting: an untampered token verifies HMAC True and decrypts (positive control), but flipping any bit of the ciphertext region OR the trailing HMAC makes verify_hmac return False and token_decrypt reject the token (raise) rather than returning forged/garbage plaintext — pins the verify-HMAC-before-decrypt rule",
)
def test_token_hmac_verify_before_decrypt(sut):
    key = random_hex(64)
    plaintext = random_hex(40)
    token = bytearray(bytes.fromhex(sut.execute("token_encrypt", key=key, plaintext=plaintext)["token"]))
    # Positive control.
    assert sut.execute("token_verify_hmac", key=key, token=token.hex())["valid"] is True
    assert_hex_equal(sut.execute("token_decrypt", key=key, token=token.hex())["plaintext"], plaintext)
    # Negative: tamper a ciphertext byte (offset 20 is inside IV||ct, before the HMAC).
    ct_tampered = bytearray(token)
    ct_tampered[20] ^= 0x01
    assert sut.execute("token_verify_hmac", key=key, token=ct_tampered.hex())["valid"] is False
    with pytest.raises(BridgeError):
        sut.execute("token_decrypt", key=key, token=ct_tampered.hex())
    # Negative: tamper the trailing HMAC.
    mac_tampered = bytearray(token)
    mac_tampered[-1] ^= 0x01
    assert sut.execute("token_verify_hmac", key=key, token=mac_tampered.hex())["valid"] is False
    with pytest.raises(BridgeError):
        sut.execute("token_decrypt", key=key, token=mac_tampered.hex())


# --- X25519 scalar clamping (gap: x25519-rfc7748) -----------------------------


@conformance_case(
    commands=["x25519_exchange"],
    verifies="X25519 clamps the scalar per RFC 7748: the low 3 bits of the first byte are cleared before the scalar multiply, so a scalar and the same scalar with those low bits forced to 1 produce the IDENTICAL shared secret. An impl that skips clamping yields a different result for the modified scalar and fails",
)
def test_x25519_scalar_clamping(sut):
    scalar = bytearray(bytes.fromhex(X25519_RFC7748_SCALAR))
    base = sut.execute(
        "x25519_exchange", private_key=scalar.hex(), peer_public_key=X25519_RFC7748_U,
    )["shared_secret"]
    # Anchor the unmodified result to the published RFC 7748 vector.
    assert_hex_equal(base, X25519_RFC7748_OUTPUT)
    # Force the low 3 bits of byte 0 (cleared by clamping) -> must not change output.
    scalar[0] |= 0x07
    clamped = sut.execute(
        "x25519_exchange", private_key=scalar.hex(), peer_public_key=X25519_RFC7748_U,
    )["shared_secret"]
    assert_hex_equal(clamped, base, "scalar low-3-bit change altered the result — clamping skipped")


# --- Ed25519 verify is total: invalid inputs return False, never raise --------
# (gap: ed25519-verify-accept-reject)


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Ed25519 verification is a total predicate: a valid 64-byte signature verifies True (positive anchor), but a wrong-length signature (63 or 65 bytes) verifies False — returned as a boolean, NOT raised — so an impl that crashes on a malformed signature instead of rejecting it fails",
)
def test_ed25519_verify_wrong_length_signature_returns_false(sut, reference):
    seed = random_hex(32)
    message = random_hex(48)
    keys = reference.execute("ed25519_generate", seed=seed)
    sig = reference.execute("ed25519_sign", private_key=keys["private_key"], message=message)["signature"]
    assert sut.execute(
        "ed25519_verify", public_key=keys["public_key"], message=message, signature=sig
    )["valid"] is True
    for bad, why in ((sig[:-2], "63-byte (one short)"), (sig + "00", "65-byte (one long)")):
        v = sut.execute("ed25519_verify", public_key=keys["public_key"], message=message, signature=bad)
        assert v["valid"] is False, f"wrong-length signature ({why}) must verify False, got {v}"


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="Ed25519 rejects a valid signature presented under the WRONG public key: the signature verifies True under its own key (positive anchor) but False under an unrelated public key — pins that verification binds signature to the specific signing key",
)
def test_ed25519_verify_wrong_public_key_returns_false(sut, reference):
    msg = random_hex(48)
    signer = reference.execute("ed25519_generate", seed=random_hex(32))
    other = reference.execute("ed25519_generate", seed=random_hex(32))
    sig = reference.execute("ed25519_sign", private_key=signer["private_key"], message=msg)["signature"]
    assert sut.execute(
        "ed25519_verify", public_key=signer["public_key"], message=msg, signature=sig
    )["valid"] is True
    assert sut.execute(
        "ed25519_verify", public_key=other["public_key"], message=msg, signature=sig
    )["valid"] is False
