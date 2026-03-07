"""Ratchet conformance tests.

Tests ratchet ID computation, public key derivation, key derivation,
and encrypt/decrypt by comparing SUT output against a reference
implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_ratchet_id(sut, reference):
    pub = random_hex(32)
    ref = reference.execute("ratchet_id", ratchet_public=pub)
    res = sut.execute("ratchet_id", ratchet_public=pub)
    assert_hex_equal(res["ratchet_id"], ref["ratchet_id"])


def test_ratchet_public_from_private(sut, reference):
    priv = random_hex(32)
    ref = reference.execute("ratchet_public_from_private", ratchet_private=priv)
    res = sut.execute("ratchet_public_from_private", ratchet_private=priv)
    assert_hex_equal(res["ratchet_public"], ref["ratchet_public"])


def test_ratchet_derive_key(sut, reference):
    # Generate proper X25519 keypairs via reference to ensure valid keys
    eph_seed = random_hex(32)
    eph_keys = reference.execute("x25519_generate", seed=eph_seed)
    eph_priv = eph_keys["private_key"]
    ratchet_seed = random_hex(32)
    ratchet_keys = reference.execute("x25519_generate", seed=ratchet_seed)
    ratchet_pub = ratchet_keys["public_key"]
    identity_hash = random_hex(16)
    ref = reference.execute(
        "ratchet_derive_key",
        ephemeral_private=eph_priv,
        ratchet_public=ratchet_pub,
        identity_hash=identity_hash,
    )
    res = sut.execute(
        "ratchet_derive_key",
        ephemeral_private=eph_priv,
        ratchet_public=ratchet_pub,
        identity_hash=identity_hash,
    )
    assert_hex_equal(res["shared_key"], ref["shared_key"])
    assert_hex_equal(res["derived_key"], ref["derived_key"])


def test_ratchet_encrypt_decrypt(sut, reference):
    ratchet_priv = random_hex(32)
    ref_pub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )
    ratchet_pub = ref_pub["ratchet_public"]
    identity_hash = random_hex(16)
    plaintext = random_hex(48)
    # Encrypt with reference, decrypt with SUT
    ref_enc = reference.execute(
        "ratchet_encrypt",
        ratchet_public=ratchet_pub,
        identity_hash=identity_hash,
        plaintext=plaintext,
    )
    res_dec = sut.execute(
        "ratchet_decrypt",
        ratchet_private=ratchet_priv,
        identity_hash=identity_hash,
        ciphertext=ref_enc["ciphertext"],
    )
    assert_hex_equal(res_dec["plaintext"], plaintext)
