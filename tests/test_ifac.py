"""IFAC (Interface Authentication Code) conformance tests.

Covers the IFAC interface-authentication layer across implementations:
  - HKDF key derivation from (network_name, passphrase) via IFAC_SALT
  - Ed25519 signature-tag computation
  - Wire-format masking and unmasking transforms

Motivated by reticulum-kt issue #29: Kotlin's native IFAC produces wire
bytes that Python RNS cannot verify, causing silent drops at the receiving
side's IFAC check. No error surfaces to the user because a failing IFAC
verify is indistinguishable from "not addressed to me".

IFAC is pure deterministic crypto (HKDF + RFC 8032 Ed25519) — no timing,
no state — so byte-equality across impls is the correct assertion.
"""

import hashlib

from conftest import random_hex, assert_hex_equal


def _ifac_origin_hex(network_name: str, passphrase: str) -> str:
    """ifac_origin = SHA256(network_name) || SHA256(passphrase).

    Computed test-side rather than via the bridge so the test author controls
    the input domain — the bridge takes the origin already assembled.
    """
    return (
        hashlib.sha256(network_name.encode()).digest()
        + hashlib.sha256(passphrase.encode()).digest()
    ).hex()


def test_ifac_derive_key(sut, reference):
    """HKDF-derived 64-byte IFAC key must match byte-for-byte.

    The bridge's derive_key uses the fixed IFAC_SALT baked into both
    implementations. A mismatch here would point at HKDF, HMAC, or the
    salt constant diverging.
    """
    origin = _ifac_origin_hex("testnet", "testpass")
    ref = reference.execute("ifac_derive_key", ifac_origin=origin)
    res = sut.execute("ifac_derive_key", ifac_origin=origin)
    assert_hex_equal(res["ifac_key"], ref["ifac_key"])
    assert_hex_equal(res["ifac_salt"], ref["ifac_salt"])


def test_ifac_compute_issue_29_vector(sut, reference):
    """Exact repro vector from reticulum-kt#29: ("testnet", "testpass",
    packet=bytes(range(64))). The reporter showed Kotlin's bytes diverge
    from Python's here. Failure of this test is the headline symptom.
    """
    origin = _ifac_origin_hex("testnet", "testpass")
    key_info = reference.execute("ifac_derive_key", ifac_origin=origin)
    ifac_key = key_info["ifac_key"]
    packet = bytes(range(64)).hex()

    ref = reference.execute("ifac_compute", ifac_key=ifac_key, packet_data=packet)
    res = sut.execute("ifac_compute", ifac_key=ifac_key, packet_data=packet)
    assert_hex_equal(
        res["signature"], ref["signature"],
        "Ed25519 signatures diverge — RFC 8032 requires bit-identical output",
    )
    assert_hex_equal(res["ifac"], ref["ifac"])


def test_ifac_compute_random(sut, reference):
    """Fuzz ifac_compute with random key+packet inputs.

    Ed25519 is deterministic, so any divergence across impls is a bug.
    """
    ifac_key = random_hex(64)
    packet = random_hex(48)
    ref = reference.execute("ifac_compute", ifac_key=ifac_key, packet_data=packet)
    res = sut.execute("ifac_compute", ifac_key=ifac_key, packet_data=packet)
    assert_hex_equal(res["ifac"], ref["ifac"])
    assert_hex_equal(res["signature"], ref["signature"])


def test_ifac_compute_variable_size(sut, reference):
    """ifac_size selects how many trailing signature bytes form the tag.
    Both impls must agree for every size production might use.
    """
    ifac_key = random_hex(64)
    packet = random_hex(24)
    for size in (1, 8, 16, 32, 64):
        ref = reference.execute(
            "ifac_compute", ifac_key=ifac_key, packet_data=packet, ifac_size=size
        )
        res = sut.execute(
            "ifac_compute", ifac_key=ifac_key, packet_data=packet, ifac_size=size
        )
        assert_hex_equal(
            res["ifac"], ref["ifac"],
            f"ifac_compute diverges at ifac_size={size}",
        )


def test_ifac_verify_cross_impl(sut, reference):
    """End-to-end interop check: SUT-computed tag must validate under the
    reference, and vice-versa. This is the test that most directly models
    what fails in production — a tag arrives on the wire from one impl and
    is handed to the other's verifier.
    """
    ifac_key = random_hex(64)
    packet = random_hex(32)

    # SUT computes tag; reference verifies.
    sut_compute = sut.execute("ifac_compute", ifac_key=ifac_key, packet_data=packet)
    ref_verify = reference.execute(
        "ifac_verify",
        ifac_key=ifac_key,
        packet_data=packet,
        expected_ifac=sut_compute["ifac"],
    )
    assert ref_verify["valid"] is True, (
        "Reference rejected SUT-produced IFAC tag. This is the exact "
        "failure mode described in reticulum-kt#29 — Python won't "
        "accept the Kotlin wire bytes, producing silent drops."
    )

    # Reference computes tag; SUT verifies.
    ref_compute = reference.execute(
        "ifac_compute", ifac_key=ifac_key, packet_data=packet
    )
    sut_verify = sut.execute(
        "ifac_verify",
        ifac_key=ifac_key,
        packet_data=packet,
        expected_ifac=ref_compute["ifac"],
    )
    assert sut_verify["valid"] is True, (
        "SUT rejected reference-produced IFAC tag — SUT cannot verify "
        "Python's wire bytes."
    )


def test_ifac_mask_packet(sut, reference):
    """Full wire-format masking transform byte-equality.

    Covers: Ed25519 signing + header-flag toggle + IFAC insertion + HKDF
    mask derivation (salt=ifac_key, ikm=ifac) + XOR-mask application.
    Any divergence in any step produces different masked bytes.

    Uses a 2-byte header with the IFAC flag clear (0x00) so the mask
    transform runs end-to-end. Real packets vary the low bits of byte 0,
    but the flag bit (0x80) must be clear on input.
    """
    ifac_key = random_hex(64)
    header = bytes([0x00, 0x00]).hex()
    payload = random_hex(32)
    packet = header + payload

    ref = reference.execute(
        "ifac_mask_packet", ifac_key=ifac_key, packet_data=packet
    )
    res = sut.execute("ifac_mask_packet", ifac_key=ifac_key, packet_data=packet)
    assert_hex_equal(res["ifac"], ref["ifac"])
    assert_hex_equal(
        res["masked_packet"], ref["masked_packet"],
        "Masked-packet bytes diverge — the on-wire bytes the SUT would "
        "emit cannot be parsed by Python's IFAC unmasker.",
    )
