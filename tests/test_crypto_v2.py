"""V2 gap-closure for the `crypto` subsystem.

Every rule here is anchored to an EXTERNAL standard (RFC 5869, RFC 7748,
RFC 8032) or to a SPEC LITERAL read straight out of the installed RNS 1.3.1
source tree — never an impl-vs-itself tautology. Each closes a specific V2
gap the existing suite left open:

  * hkdf-input-validation (remainder) -> RNS Cryptography/HKDF.py:44-45
        The empty-input gate is `if derive_from == None or derive_from == "":`.
        Because b"" != "" in Python, an EMPTY-BYTES ikm is NOT rejected — RNS
        derives a key from it. We pin that lax acceptance against an INDEPENDENT
        RFC 5869 HKDF-SHA256 implementation (stdlib hmac/hashlib in the test),
        so a stricter SUT that rejects empty-bytes ikm is caught.

  * x25519-rfc7748 (TV2 masking) -> RFC 7748 §5 / §5.2 test vector 2
        RFC 7748 §5 MANDATES masking the most-significant bit of the final byte
        of a received u-coordinate. TV2's u (…a493) has that bit SET; correctly
        masked it yields the published output 95cbde94…. The RNS PyCA/OpenSSL
        backend masks (matches TV2) and treats MSB-set and MSB-clear u as
        identical. Exercises the masking path no prior vector reached (every
        other suite u has bit 255 clear).

  * x25519-zero-shared-secret-provider-divergence -> RFC 7748 §6.1 contributory
        Low-order u-coordinates (u=0, u=1) drive the shared secret to all-zero.
        RNS's two backends DIVERGE on this attacker-controlled wire input: the
        pure-Python internal backend returns the all-zero secret; the PyCA/
        OpenSSL backend REJECTS the all-zero output (the optional contributory-
        behaviour guard). Both documented profiles are pinned.

  * ed25519-noncanonical-provider-divergence -> RFC 8032 §5.1.7 canonical S
        A signature with S replaced by S+L (≡ S mod L, non-canonical, malleable)
        is REJECTED by the PyCA/OpenSSL backend (enforces S ∈ [0,L)) but ACCEPTED
        by the pure-Python internal backend (no range check). Both accept the
        canonical signature (positive control).

  * ed25519-seed-length-validation -> RNS pure25519/ed25519_oop.py:105-110
        `SigningKey` raises ValueError('SigningKey takes 32-byte seed or 64-byte
        string') for any other length. Wrong-length seeds/keys are rejected, not
        silently truncated or padded under a different key.
"""

import hashlib
import hmac as _hmac

import pytest

from conftest import random_hex
from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Cryptographic Primitives (V2)"
__category_order__ = 10


_PROVIDERS = ("internal", "pyca")

# RFC 7748 §5.2 test vector 2 — the input u-coordinate's final byte is 0x93, so
# bit 255 is SET and §5 requires it be masked before the scalar multiply.
_TV2_SCALAR = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
_TV2_U_MSB_SET = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
# The same u with bit 255 cleared (0x93 -> 0x13); §5 says both must behave alike.
_TV2_U_MSB_CLEAR = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413"
_TV2_OUTPUT = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

# RFC 7748 §6.1 — a normal (non-degenerate) DH vector, the positive control.
_RFC7748_A_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
_RFC7748_B_PUB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
_RFC7748_SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

# Known low-order Curve25519 u-coordinates that force an all-zero shared secret.
_LOW_ORDER_U = ("00" * 32, "01" + "00" * 31)
_ALL_ZERO = "00" * 32

# RFC 8032 §5.1 — the order L of the Ed25519 group (the canonical-S bound).
_ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493


def _rfc5869_hkdf_sha256(length, ikm, salt, info=b""):
    """An INDEPENDENT RFC 5869 HKDF-SHA256 (stdlib), used as external ground
    truth — never reads anything back from the impl under test."""
    if salt is None or len(salt) == 0:
        salt = bytes(32)
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm, i = b"", b"", 0
    while len(okm) < length:
        i += 1
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# --- HKDF empty-bytes ikm is accepted (lax) -----------------------------------
# (gap: hkdf-input-validation remainder)


@conformance_case(
    commands=["hkdf"],
    verifies="RNS HKDF's empty-input gate is `derive_from == None or "
    "derive_from == \"\"` (HKDF.py:44-45); because b\"\" != \"\" in Python an "
    "EMPTY-BYTES ikm is NOT rejected — RNS derives a key from it. The derived "
    "key matches an INDEPENDENT RFC 5869 HKDF-SHA256 computation (stdlib "
    "hmac/hashlib) over the same empty ikm + salt, and a non-empty ikm also "
    "matches the independent reference (positive control). A stricter SUT that "
    "rejected empty-bytes ikm, or computed HKDF differently, is caught.",
)
def test_hkdf_accepts_empty_bytes_ikm(sut, reference):
    salt = random_hex(16)
    salt_b = bytes.fromhex(salt)
    length = 40
    # External anchors derived without touching the impl.
    expect_empty = _rfc5869_hkdf_sha256(length, b"", salt_b).hex()
    nonempty = random_hex(24)
    expect_nonempty = _rfc5869_hkdf_sha256(length, bytes.fromhex(nonempty), salt_b).hex()
    for impl in (reference, sut):
        # Lax accept: empty-bytes ikm derives a key (does NOT raise) ...
        got_empty = impl.execute("hkdf", length=length, ikm="", salt=salt)["derived_key"]
        # ... and that key equals the independent RFC 5869 derivation.
        assert got_empty == expect_empty, (
            "HKDF over empty-bytes ikm must match the independent RFC 5869 "
            f"reference {expect_empty}, got {got_empty}"
        )
        # Positive control: a non-empty ikm also matches the external reference.
        got_nonempty = impl.execute(
            "hkdf", length=length, ikm=nonempty, salt=salt
        )["derived_key"]
        assert got_nonempty == expect_nonempty


# --- X25519 RFC 7748 §5 u-coordinate MSB masking (TV2) ------------------------
# (gap: x25519-rfc7748 — u-coordinate bit-255 mask)


@conformance_case(
    commands=["crypto_provider_op"],
    verifies="RFC 7748 §5 requires the most-significant bit of a received "
    "u-coordinate's final byte be masked before scalar multiplication. The "
    "§5.2 test-vector-2 u (…a493) has that bit SET; masked correctly it yields "
    "the published output 95cbde94…. The RNS PyCA/OpenSSL backend reproduces "
    "TV2 exactly (proving the mask is applied — the unmasked value gives a "
    "different result), and exchanging against the same u with bit 255 cleared "
    "(…a413) gives the IDENTICAL secret. An impl that mis-decodes or rejects an "
    "MSB-set peer key — a wire-reachable attacker-controlled input — fails.",
)
def test_x25519_rfc7748_tv2_msb_masking(sut):
    # Positive RFC anchor: masked MSB-set u reproduces the published TV2 output.
    got_set = sut.execute(
        "crypto_provider_op", op="x25519_exchange", provider="pyca",
        private_key=_TV2_SCALAR, peer_public_key=_TV2_U_MSB_SET,
    )["result"]
    assert got_set == _TV2_OUTPUT, (
        f"PyCA X25519 must reproduce RFC 7748 §5.2 TV2 output {_TV2_OUTPUT} for "
        f"the MSB-set u (proving bit-255 masking); got {got_set}"
    )
    # §5 equivalence: MSB-set and MSB-clear u yield the same shared secret.
    got_clear = sut.execute(
        "crypto_provider_op", op="x25519_exchange", provider="pyca",
        private_key=_TV2_SCALAR, peer_public_key=_TV2_U_MSB_CLEAR,
    )["result"]
    assert got_clear == got_set, (
        "RFC 7748 §5: an MSB-set u must behave identically to the same u with "
        "bit 255 cleared — the high bit is masked, not part of the coordinate"
    )


# --- X25519 low-order point -> all-zero shared secret (provider divergence) ----
# (gap: x25519-zero-shared-secret-provider-divergence)


@conformance_case(
    commands=["crypto_provider_op"],
    verifies="A low-order u-coordinate (u=0 or u=1) drives X25519 to an all-zero "
    "shared secret. RNS's two backends DIVERGE on this attacker-controlled wire "
    "input: the pure-Python INTERNAL backend returns the 32-byte all-zero secret "
    "(no contributory-behaviour check), while the PyCA/OpenSSL backend REJECTS "
    "the all-zero output per the RFC 7748 §6.1 NOTE (raises). A normal RFC 7748 "
    "§6.1 exchange succeeds with a non-zero secret on BOTH backends (positive "
    "control). Pins both documented accept/reject profiles.",
)
def test_x25519_low_order_zero_secret_provider_divergence(sut):
    # Positive control: a non-degenerate exchange yields the same non-zero secret
    # on both backends (RFC 7748 §6.1 vector).
    for provider in _PROVIDERS:
        ok = sut.execute(
            "crypto_provider_op", op="x25519_exchange", provider=provider,
            private_key=_RFC7748_A_PRIV, peer_public_key=_RFC7748_B_PUB,
        )["result"]
        assert ok == _RFC7748_SHARED
        assert ok != _ALL_ZERO
    for u in _LOW_ORDER_U:
        # INTERNAL: returns the all-zero shared secret (no rejection).
        internal = sut.execute(
            "crypto_provider_op", op="x25519_exchange", provider="internal",
            private_key=_RFC7748_A_PRIV, peer_public_key=u,
        )["result"]
        assert internal == _ALL_ZERO, (
            f"internal X25519 against low-order u={u[:2]}… must yield the "
            f"all-zero shared secret; got {internal}"
        )
        # PyCA/OpenSSL: rejects the all-zero output (contributory guard).
        with pytest.raises(BridgeError):
            sut.execute(
                "crypto_provider_op", op="x25519_exchange", provider="pyca",
                private_key=_RFC7748_A_PRIV, peer_public_key=u,
            )


# --- Ed25519 non-canonical S (malleable) — provider divergence -----------------
# (gap: ed25519-noncanonical-provider-divergence)


@conformance_case(
    commands=["crypto_provider_op", "ed25519_generate"],
    verifies="RFC 8032 §5.1.7 requires a verifier check S ∈ [0,L). RNS's two "
    "backends DIVERGE: replacing a valid signature's S with S+L (≡ S mod L — a "
    "non-canonical, malleable encoding) is REJECTED by the PyCA/OpenSSL backend "
    "(enforces the canonical bound) but ACCEPTED by the pure-Python internal "
    "backend (no S range check). Both backends accept the original canonical "
    "signature (positive control). Pins both documented profiles on this "
    "wire-reachable malleability input.",
)
def test_ed25519_noncanonical_s_provider_divergence(sut):
    seed = random_hex(32)
    message = random_hex(20)
    pub = sut.execute("ed25519_generate", seed=seed)["public_key"]
    # A genuine, canonical signature from real RNS Ed25519.
    sig = sut.execute(
        "crypto_provider_op", op="ed25519_sign", provider="internal",
        private_key=seed, message=message,
    )["result"]
    sig_b = bytes.fromhex(sig)
    # Construct the non-canonical twin by ARITHMETIC on the genuine artifact:
    # S' = S + L (little-endian), R left intact. S < L so S+L < 2**253 fits 32B.
    r_half = sig_b[:32]
    s_val = int.from_bytes(sig_b[32:], "little")
    malleable = (r_half + (s_val + _ED25519_L).to_bytes(32, "little")).hex()
    for provider in _PROVIDERS:
        # Positive control: the canonical signature verifies on every backend.
        assert sut.execute(
            "crypto_provider_op", op="ed25519_verify", provider=provider,
            public_key=pub, message=message, signature=sig,
        )["valid"] is True, f"{provider}: canonical signature must verify"
    # Divergence on the non-canonical (S+L) signature.
    assert sut.execute(
        "crypto_provider_op", op="ed25519_verify", provider="internal",
        public_key=pub, message=message, signature=malleable,
    )["valid"] is True, "internal Ed25519 must accept S+L (no canonical-S check)"
    assert sut.execute(
        "crypto_provider_op", op="ed25519_verify", provider="pyca",
        public_key=pub, message=message, signature=malleable,
    )["valid"] is False, "PyCA Ed25519 must reject S>=L per RFC 8032 §5.1.7"


# --- Ed25519 seed/key length validation ----------------------------------------
# (gap: ed25519-seed-length-validation)


@conformance_case(
    commands=["ed25519_generate", "ed25519_sign", "ed25519_verify"],
    verifies="RNS Ed25519 SigningKey accepts only a 32-byte seed or a 64-byte "
    "seed+pubkey string and raises ValueError otherwise "
    "(pure25519/ed25519_oop.py:105-110). A 32-byte seed generates a keypair and "
    "a 64-byte private key signs (positive controls), while 31/33-byte seeds are "
    "rejected by ed25519_generate and 31/33/63/65-byte private keys are rejected "
    "by ed25519_sign — never silently truncated or padded under a different key.",
)
def test_ed25519_rejects_wrong_length_seed(sut, reference):
    for impl in (reference, sut):
        seed = random_hex(32)
        message = random_hex(16)
        # Positive control: 32-byte seed -> keypair, signature verifies.
        keys = impl.execute("ed25519_generate", seed=seed)
        assert len(bytes.fromhex(keys["public_key"])) == 32
        sig = impl.execute(
            "ed25519_sign", private_key=seed, message=message
        )["signature"]
        assert impl.execute(
            "ed25519_verify", public_key=keys["public_key"],
            message=message, signature=sig,
        )["valid"] is True
        # Positive control: a 64-byte private key (seed+pubkey) also signs.
        priv64 = seed + keys["public_key"]
        assert len(bytes.fromhex(priv64)) == 64
        impl.execute("ed25519_sign", private_key=priv64, message=message)
        # Negative: wrong-length seeds into key generation.
        for nbytes in (31, 33):
            with pytest.raises(BridgeError):
                impl.execute("ed25519_generate", seed=random_hex(nbytes))
        # Negative: wrong-length private keys into signing (neither 32 nor 64).
        for nbytes in (31, 33, 63, 65):
            with pytest.raises(BridgeError):
                impl.execute(
                    "ed25519_sign", private_key=random_hex(nbytes), message=message
                )
