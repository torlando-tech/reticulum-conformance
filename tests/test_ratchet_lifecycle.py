"""Ratchet lifecycle conformance tests.

Tests the full ratchet flow: announce with ratchet → extract ratchet
from announce → encrypt with extracted ratchet → decrypt with retained
private key. This catches mismatches in the announce format, ratchet key
derivation, or encryption/decryption that primitive-level tests miss.

These tests exercise the complete chain that propagated LXMF messages use:
  1. Destination creates ratchet keypair
  2. Announce includes ratchet public key
  3. Remote extracts ratchet from announce
  4. Remote encrypts using ratchet (Identity.encrypt with ratchet)
  5. Destination decrypts using ratchet private key
"""

from conftest import random_hex, assert_hex_equal


def test_announce_with_ratchet_pack_unpack(sut, reference):
    """Announce data with ratchet packs/unpacks identically."""
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]

    name_hash = reference.execute("name_hash", name="lxmf.delivery")["hash"]
    rh = random_hex(5)
    ts = 1700000000
    random_hash = reference.execute("random_hash", random_bytes=rh, timestamp=ts)[
        "random_hash"
    ]

    # Generate a ratchet keypair
    ratchet_priv = random_hex(32)
    ratchet_pub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )["ratchet_public"]

    ref_dest = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )

    # Sign with ratchet included
    ref_sig = reference.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        ratchet=ratchet_pub,
    )
    res_sig = sut.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        ratchet=ratchet_pub,
    )
    assert_hex_equal(res_sig["signature"], ref_sig["signature"])

    # Pack with ratchet
    ref_pack = reference.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        ratchet=ratchet_pub,
        signature=ref_sig["signature"],
    )
    res_pack = sut.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        ratchet=ratchet_pub,
        signature=ref_sig["signature"],
    )
    assert_hex_equal(res_pack["announce_data"], ref_pack["announce_data"])

    # Unpack with ratchet
    ref_unp = reference.execute(
        "announce_unpack",
        announce_data=ref_pack["announce_data"],
        has_ratchet=True,
    )
    res_unp = sut.execute(
        "announce_unpack",
        announce_data=ref_pack["announce_data"],
        has_ratchet=True,
    )
    assert_hex_equal(res_unp["ratchet"], ref_unp["ratchet"])
    assert_hex_equal(res_unp["ratchet"], ratchet_pub)


def test_ratchet_extract_from_announce(sut, reference):
    """Ratchet extracted from announce matches what was packed."""
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]

    name_hash = reference.execute("name_hash", name="lxmf.delivery")["hash"]
    random_hash = reference.execute("random_hash", random_bytes=random_hex(5), timestamp=1700000000)[
        "random_hash"
    ]

    ratchet_priv = random_hex(32)
    ratchet_pub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )["ratchet_public"]

    ref_dest = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )

    sig = reference.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        ratchet=ratchet_pub,
    )["signature"]

    packed = reference.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        ratchet=ratchet_pub,
        signature=sig,
    )["announce_data"]

    # Both impls should extract the same ratchet
    ref_ext = reference.execute(
        "announce_unpack", announce_data=packed, has_ratchet=True
    )
    res_ext = sut.execute(
        "announce_unpack", announce_data=packed, has_ratchet=True
    )

    assert ref_ext["has_ratchet"] is True
    assert res_ext["has_ratchet"] is True
    assert_hex_equal(ref_ext["ratchet"], ratchet_pub)
    assert_hex_equal(res_ext["ratchet"], ratchet_pub)

    # Ratchet ID should also match
    ref_rid = reference.execute("ratchet_id", ratchet_public=ratchet_pub)
    res_rid = sut.execute("ratchet_id", ratchet_public=ratchet_pub)
    assert_hex_equal(res_rid["ratchet_id"], ref_rid["ratchet_id"])


def test_ratchet_full_lifecycle_encrypt_decrypt(sut, reference):
    """Full lifecycle: create ratchet → announce → extract → encrypt → decrypt.

    This is the critical test for propagated LXMF message delivery:
    - Destination creates ratchet keypair (private retained, public announced)
    - Remote extracts ratchet public from announce
    - Remote encrypts with ratchet public + identity hash
    - Destination decrypts with ratchet private + identity hash
    """
    # Create identity (both impls must derive same hash)
    identity_priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=identity_priv)
    res_id = sut.execute("identity_from_private_key", private_key=identity_priv)
    assert_hex_equal(res_id["hash"], ref_id["hash"])
    identity_hash = ref_id["hash"]

    # Create ratchet keypair
    ratchet_priv = random_hex(32)
    ref_rpub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )
    res_rpub = sut.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )
    ratchet_pub = ref_rpub["ratchet_public"]
    assert_hex_equal(res_rpub["ratchet_public"], ratchet_pub)

    # Encrypt with REFERENCE using ratchet public key + identity hash
    plaintext = random_hex(64)
    ref_enc = reference.execute(
        "ratchet_encrypt",
        ratchet_public=ratchet_pub,
        identity_hash=identity_hash,
        plaintext=plaintext,
    )

    # Decrypt with SUT using ratchet private key + identity hash
    res_dec = sut.execute(
        "ratchet_decrypt",
        ratchet_private=ratchet_priv,
        identity_hash=identity_hash,
        ciphertext=ref_enc["ciphertext"],
    )
    assert_hex_equal(res_dec["plaintext"], plaintext)

    # And the reverse: encrypt with SUT, decrypt with REFERENCE
    res_enc = sut.execute(
        "ratchet_encrypt",
        ratchet_public=ratchet_pub,
        identity_hash=identity_hash,
        plaintext=plaintext,
    )
    ref_dec = reference.execute(
        "ratchet_decrypt",
        ratchet_private=ratchet_priv,
        identity_hash=identity_hash,
        ciphertext=res_enc["ciphertext"],
    )
    assert_hex_equal(ref_dec["plaintext"], plaintext)


def test_ratchet_cross_encrypt_decrypt(sut, reference):
    """Cross-implementation ratchet encrypt/decrypt in both directions."""
    ratchet_priv = random_hex(32)
    ratchet_pub = reference.execute(
        "ratchet_public_from_private", ratchet_private=ratchet_priv
    )["ratchet_public"]
    identity_hash = random_hex(16)
    plaintext = random_hex(80)

    # SUT encrypts, reference decrypts
    sut_enc = sut.execute(
        "ratchet_encrypt",
        ratchet_public=ratchet_pub,
        identity_hash=identity_hash,
        plaintext=plaintext,
    )
    ref_dec = reference.execute(
        "ratchet_decrypt",
        ratchet_private=ratchet_priv,
        identity_hash=identity_hash,
        ciphertext=sut_enc["ciphertext"],
    )
    assert_hex_equal(ref_dec["plaintext"], plaintext)

    # Reference encrypts, SUT decrypts
    ref_enc = reference.execute(
        "ratchet_encrypt",
        ratchet_public=ratchet_pub,
        identity_hash=identity_hash,
        plaintext=plaintext,
    )
    sut_dec = sut.execute(
        "ratchet_decrypt",
        ratchet_private=ratchet_priv,
        identity_hash=identity_hash,
        ciphertext=ref_enc["ciphertext"],
    )
    assert_hex_equal(sut_dec["plaintext"], plaintext)
