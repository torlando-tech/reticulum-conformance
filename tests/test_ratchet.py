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


@conformance_case(
    commands=[
        "identity_from_private_key",
        "ratchet_public_from_private",
        "ratchet_encrypt",
        "ratchet_decrypt",
    ],
    verifies="Rotation forward-secrecy negative control: after a ratchet rotation (two distinct ratchet keypairs A and B for the same Identity), a message encrypted to ratchet A's public key cannot be decrypted with ratchet B's private key, and vice versa — RNS.Identity.decrypt returns None for the cross-epoch ciphertext (it does not silently fall back to the static identity key and recover the plaintext). Positive controls decrypt each ciphertext with its own ratchet, proving the ciphertexts are well-formed and the None values are genuine rejections.",
)
def test_ratchet_rotation_isolates_epochs(sut, reference):
    identity_priv = random_hex(64)
    ratchet_a_priv = random_hex(32)
    ratchet_b_priv = random_hex(32)  # the rotated-to ratchet
    ident = reference.execute(
        "identity_from_private_key", private_key=identity_priv
    )
    public_key = ident["public_key"]
    ra_pub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_a_priv
    )["ratchet_public"]
    rb_pub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_b_priv
    )["ratchet_public"]
    assert ra_pub != rb_pub, "two rotation ratchets must have distinct public keys"

    plaintext = random_hex(48)
    ct_a = reference.execute(
        "ratchet_encrypt",
        public_key=public_key, ratchet_public=ra_pub, plaintext=plaintext,
    )["ciphertext"]
    ct_b = reference.execute(
        "ratchet_encrypt",
        public_key=public_key, ratchet_public=rb_pub, plaintext=plaintext,
    )["ciphertext"]

    for impl, label in ((reference, "ref"), (sut, "sut")):
        # Positive controls: each epoch decrypts its own message.
        ok_a = impl.execute(
            "ratchet_decrypt",
            private_key=identity_priv, ratchet_private=ratchet_a_priv, ciphertext=ct_a,
        )
        assert_hex_equal(ok_a["plaintext"], plaintext, f"{label}: ratchet A failed to decrypt its own message")
        ok_b = impl.execute(
            "ratchet_decrypt",
            private_key=identity_priv, ratchet_private=ratchet_b_priv, ciphertext=ct_b,
        )
        assert_hex_equal(ok_b["plaintext"], plaintext, f"{label}: ratchet B failed to decrypt its own message")

        # Negatives: cross-epoch decryption is rejected (None), not leaked.
        wrong_a = impl.execute(
            "ratchet_decrypt",
            private_key=identity_priv, ratchet_private=ratchet_b_priv, ciphertext=ct_a,
        )
        assert wrong_a["plaintext"] is None, (
            f"{label}: rotated-to ratchet B decrypted a message meant for ratchet A "
            f"— rotation does not isolate ratchet epochs"
        )
        wrong_b = impl.execute(
            "ratchet_decrypt",
            private_key=identity_priv, ratchet_private=ratchet_a_priv, ciphertext=ct_b,
        )
        assert wrong_b["plaintext"] is None, (
            f"{label}: predecessor ratchet A decrypted a message meant for ratchet B "
            f"— rotation does not isolate ratchet epochs"
        )


@conformance_case(
    commands=[
        "identity_from_private_key",
        "ratchet_public_from_private",
        "ratchet_encrypt",
        "ratchet_decrypt",
        "identity_decrypt",
    ],
    verifies="Forward-secrecy property: a ratchet-encrypted message is decryptable with the ratchet private key but NOT with the Identity's static private key alone — RNS.Identity.decrypt() without ratchets (identity_decrypt) returns None for ciphertext produced by encrypt(ratchet=...). This is the property ratchet enforcement protects: holding the long-term identity key does not reveal ratcheted traffic. Positive control: ratchet_decrypt with the matching ratchet recovers the plaintext.",
)
def test_ratchet_message_requires_ratchet_not_base_key(sut, reference):
    identity_priv = random_hex(64)
    ratchet_priv = random_hex(32)
    ident = reference.execute(
        "identity_from_private_key", private_key=identity_priv
    )
    public_key = ident["public_key"]
    ratchet_public = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )["ratchet_public"]
    plaintext = random_hex(48)
    ciphertext = reference.execute(
        "ratchet_encrypt",
        public_key=public_key, ratchet_public=ratchet_public, plaintext=plaintext,
    )["ciphertext"]

    for impl, label in ((reference, "ref"), (sut, "sut")):
        # Positive control: with the ratchet private key the message decrypts.
        ok = impl.execute(
            "ratchet_decrypt",
            private_key=identity_priv, ratchet_private=ratchet_priv, ciphertext=ciphertext,
        )
        assert_hex_equal(ok["plaintext"], plaintext, f"{label}: ratchet decrypt failed (positive control)")

        # Negative: the static identity key ALONE (no ratchet) cannot read it.
        base = impl.execute(
            "identity_decrypt", private_key=identity_priv, ciphertext=ciphertext,
        )
        assert base["plaintext"] is None, (
            f"{label}: ratchet-encrypted message was decrypted by the static identity "
            f"key alone — no forward secrecy"
        )
