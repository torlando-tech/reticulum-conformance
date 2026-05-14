"""Identity conformance tests.

Tests identity creation from private keys, identity hashing,
signing/verification, and encrypt/decrypt by comparing SUT output
against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Identity"
__category_order__ = 2


@conformance_case(
    commands=["identity_from_private_key"],
    verifies="Deriving an RNS Identity from its 64-byte private key (32-byte encryption + 32-byte signing halves) yields byte-identical public key, `identity_hash`, and `hexhash` string",
)
def test_identity_from_private_key(sut, reference):
    priv = random_hex(64)  # 32B encryption + 32B signing
    ref = reference.execute("identity_from_private_key", private_key=priv)
    res = sut.execute("identity_from_private_key", private_key=priv)
    assert_hex_equal(res["public_key"], ref["public_key"])
    assert_hex_equal(res["hash"], ref["hash"])
    assert res["hexhash"] == ref["hexhash"]


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
    commands=["identity_from_private_key", "identity_encrypt", "identity_decrypt"],
    verifies="RNS Identity encrypt/decrypt cross-impl round-trip in both directions — exercises the X25519+HKDF+AES composition used for unicast encryption",
)
def test_identity_encrypt_decrypt(sut, reference):
    priv = random_hex(64)
    plaintext = random_hex(48)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    identity_hash = ref_id["hash"]
    # Encrypt with reference, decrypt with SUT
    ref_enc = reference.execute(
        "identity_encrypt",
        public_key=ref_id["public_key"],
        plaintext=plaintext,
        identity_hash=identity_hash,
    )
    res_dec = sut.execute(
        "identity_decrypt",
        private_key=priv,
        ciphertext=ref_enc["ciphertext"],
        identity_hash=identity_hash,
    )
    assert_hex_equal(res_dec["plaintext"], plaintext)
    # Encrypt with SUT, decrypt with reference
    res_enc = sut.execute(
        "identity_encrypt",
        public_key=ref_id["public_key"],
        plaintext=plaintext,
        identity_hash=identity_hash,
    )
    ref_dec = reference.execute(
        "identity_decrypt",
        private_key=priv,
        ciphertext=res_enc["ciphertext"],
        identity_hash=identity_hash,
    )
    assert_hex_equal(ref_dec["plaintext"], plaintext)
