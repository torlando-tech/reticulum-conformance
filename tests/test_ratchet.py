"""Ratchet conformance tests.

Tests ratchet ID computation, public key derivation, and the
encrypt/decrypt round-trip against RNS.Identity's real ratchet path. The
prior synthetic test for the internal ratchet KDF (`ratchet_derive_key`)
was removed — RNS exposes no standalone KDF entry point, so the bridge
had to reimplement the composition; the property the KDF test pinned is
now covered transitively by the encrypt/decrypt round-trip (if the KDF
diverges, decrypt fails).
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Ratchet"
__category_order__ = 10


@conformance_case(
    commands=["ratchet_id"],
    verifies="RNS ratchet ID (truncated_hash(ratchet_public)[:NAME_HASH_LENGTH//8] = 10 bytes) is byte-identical across impls",
)
def test_ratchet_id(sut, reference):
    pub = random_hex(32)
    ref = reference.execute("ratchet_id", ratchet_public=pub)
    res = sut.execute("ratchet_id", ratchet_public=pub)
    assert_hex_equal(res["ratchet_id"], ref["ratchet_id"])


@conformance_case(
    commands=["ratchet_public_from_private"],
    verifies="X25519 public key derivation from ratchet private key matches",
)
def test_ratchet_public_from_private(sut, reference):
    priv = random_hex(32)
    ref = reference.execute("ratchet_public_from_private", ratchet_private=priv)
    res = sut.execute("ratchet_public_from_private", ratchet_private=priv)
    assert_hex_equal(res["ratchet_public"], ref["ratchet_public"])


@conformance_case(
    commands=[
        "identity_from_private_key",
        "ratchet_public_from_private",
        "ratchet_encrypt",
        "ratchet_decrypt",
    ],
    verifies="RNS ratchet encrypt/decrypt cross-impl round-trip: a message encrypted on either impl using RNS.Identity.encrypt(ratchet=...) decrypts to the original on the other via RNS.Identity.decrypt(ratchets=[...]) — the full ratcheted unicast path",
)
def test_ratchet_encrypt_decrypt(sut, reference):
    identity_priv = random_hex(64)
    ratchet_priv = random_hex(32)
    ref_id = reference.execute("identity_from_private_key", private_key=identity_priv)
    ref_rpub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )
    public_key = ref_id["public_key"]
    ratchet_public = ref_rpub["ratchet_public"]
    plaintext = random_hex(48)

    # Encrypt on reference, decrypt on SUT
    ref_enc = reference.execute(
        "ratchet_encrypt",
        public_key=public_key,
        ratchet_public=ratchet_public,
        plaintext=plaintext,
    )
    res_dec = sut.execute(
        "ratchet_decrypt",
        private_key=identity_priv,
        ratchet_private=ratchet_priv,
        ciphertext=ref_enc["ciphertext"],
    )
    assert_hex_equal(res_dec["plaintext"], plaintext)

    # Encrypt on SUT, decrypt on reference
    res_enc = sut.execute(
        "ratchet_encrypt",
        public_key=public_key,
        ratchet_public=ratchet_public,
        plaintext=plaintext,
    )
    ref_dec = reference.execute(
        "ratchet_decrypt",
        private_key=identity_priv,
        ratchet_private=ratchet_priv,
        ciphertext=res_enc["ciphertext"],
    )
    assert_hex_equal(ref_dec["plaintext"], plaintext)


@conformance_case(
    commands=["identity_from_private_key", "ratchet_public_from_private", "ratchet_encrypt"],
    verifies="Invariant: two ratchet encryptions of byte-identical plaintext for the same Identity + ratchet produce different ciphertext (RNS draws a fresh ephemeral X25519 key + AES IV per call) — deterministic ciphertext would leak plaintext equality",
)
def test_ratchet_encrypt_is_fresh_per_call(sut, reference):
    identity_priv = random_hex(64)
    ratchet_priv = random_hex(32)
    ident = sut.execute("identity_from_private_key", private_key=identity_priv)
    rpub = sut.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )
    plaintext = random_hex(48)
    first = sut.execute(
        "ratchet_encrypt",
        public_key=ident["public_key"],
        ratchet_public=rpub["ratchet_public"],
        plaintext=plaintext,
    )
    second = sut.execute(
        "ratchet_encrypt",
        public_key=ident["public_key"],
        ratchet_public=rpub["ratchet_public"],
        plaintext=plaintext,
    )
    assert first["ciphertext"] != second["ciphertext"], (
        "two ratchet encryptions of identical plaintext produced identical "
        "ciphertext — the ephemeral key / IV is being reused"
    )
