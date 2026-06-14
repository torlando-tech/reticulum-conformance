"""Crypto primitive conformance: Token key generation and provider equivalence.

Two gaps the rest of the suite cannot reach:

* `Token.generate_key` was only ever exercised implicitly through GROUP key
  creation in the default (AES-256) mode, so the documented AES-128 key length
  and the invalid-mode rejection were never observed. `token_generate_key`
  drives `RNS.Cryptography.Token.Token.generate_key(mode)` directly.

* RNS picks its crypto backend once, at import time (`Provider.py`): the
  pure-Python primitives (`PROVIDER_INTERNAL`) or the OpenSSL/PyCA bindings
  (`PROVIDER_PYCA`). Every other command exercises only whichever the install
  selected, so the two backends are never compared. The interop requirement is
  that they are byte-for-byte drop-in equivalent. `crypto_provider_op` runs the
  SAME input through a NAMED provider's real RNS implementation, and these
  tests anchor BOTH outputs on published external test vectors (RFC 7748 for
  X25519, RFC 8032 for Ed25519, NIST SP 800-38A for AES-256-CBC) — so the two
  independent implementations (pure-Python djb port vs OpenSSL) are pinned to
  the same external ground truth, not to each other.
"""

import pytest

from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Crypto Hooks"
__category_order__ = 9


# --- External spec literals (NOT read from the impl) --------------------------

# Token.py:53-56 — a Token key is split into a signing half and an encryption
# half. AES-128 needs 16+16 = 32 bytes; AES-256 needs 32+32 = 64 bytes.
_AES128_KEY_LEN = 32
_AES256_KEY_LEN = 64

# RFC 7748 section 6.1 — X25519 Diffie-Hellman test vector.
_RFC7748_A_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
_RFC7748_B_PUB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
_RFC7748_SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

# NIST SP 800-38A F.2.5 — CBC-AES256.Encrypt, first block.
_NIST_AES256_KEY = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
_NIST_AES256_IV = "000102030405060708090a0b0c0d0e0f"
_NIST_AES256_PT = "6bc1bee22e409f96e93d7e117393172a"
_NIST_AES256_CT = "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

# RFC 8032 section 7.1 TEST 1 — Ed25519 (empty message). public key + signature
# are external truth; the seed is not needed to anchor the verify path.
_RFC8032_T1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
_RFC8032_T1_MSG = ""  # empty message
_RFC8032_T1_SIG = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

# Ed25519 signature length (RNS SIGLENGTH = 512 bits).
_ED25519_SIG_LEN = 64

_PROVIDERS = ("internal", "pyca")


@conformance_case(
    commands=["token_generate_key"],
    verifies="RNS.Cryptography.Token.Token.generate_key returns a key sized for the requested AES mode: AES_128_CBC -> exactly 32 bytes (16-byte signing + 16-byte encryption half) and AES_256_CBC (also the default when no mode is given) -> exactly 64 bytes (Token.py:53-56). Keys are drawn from os.urandom, so successive calls differ. An impl that returns a single fixed length regardless of mode, or a repeating/short key, fails.",
)
def test_token_generate_key_lengths(sut):
    k128 = bytes.fromhex(sut.execute("token_generate_key", mode="AES_128_CBC")["key"])
    assert len(k128) == _AES128_KEY_LEN, f"AES-128 token key must be {_AES128_KEY_LEN} bytes"

    k256 = bytes.fromhex(sut.execute("token_generate_key", mode="AES_256_CBC")["key"])
    assert len(k256) == _AES256_KEY_LEN, f"AES-256 token key must be {_AES256_KEY_LEN} bytes"

    # No mode argument -> default is AES_256_CBC (64 bytes).
    kdef = bytes.fromhex(sut.execute("token_generate_key")["key"])
    assert len(kdef) == _AES256_KEY_LEN, "default token key must be the 64-byte AES-256 length"

    # Randomness: a sample of generated keys must all differ.
    seen = {sut.execute("token_generate_key", mode="AES_256_CBC")["key"] for _ in range(8)}
    assert len(seen) == 8, "token keys repeated across calls — not random"


@conformance_case(
    commands=["token_generate_key"],
    verifies="RNS.Cryptography.Token.Token.generate_key raises TypeError for any mode that is not AES_128_CBC or AES_256_CBC (Token.py:56) — the bridge surfaces this as a BridgeError naming the invalid token mode. An impl that silently falls back to a default key instead of rejecting fails.",
)
def test_token_generate_key_invalid_mode_rejected(sut):
    with pytest.raises(BridgeError) as exc:
        sut.execute("token_generate_key", mode="AES_512_GCM")
    assert "token mode" in str(exc.value).lower(), (
        "invalid token mode must be rejected with an identifying error"
    )


@conformance_case(
    commands=["crypto_provider_op"],
    verifies="X25519 ECDH is byte-identical across RNS's internal pure-Python backend and the PyCA/OpenSSL backend, and both match the RFC 7748 section 6.1 test vector: priv=77076d0a... exchanged with pub=de9edb7d... yields shared=4a5d9d5b... Both independent implementations are pinned to the published vector, so a backend that diverges (different curve constants / clamping) fails.",
)
def test_provider_equivalence_x25519(sut):
    results = {}
    for provider in _PROVIDERS:
        r = sut.execute(
            "crypto_provider_op",
            op="x25519_exchange",
            provider=provider,
            private_key=_RFC7748_A_PRIV,
            peer_public_key=_RFC7748_B_PUB,
        )["result"]
        assert r == _RFC7748_SHARED, f"{provider}: X25519 must match RFC 7748 shared secret"
        results[provider] = r
    assert results["internal"] == results["pyca"], "X25519 backends diverge"


@conformance_case(
    commands=["crypto_provider_op"],
    verifies="Raw AES-256-CBC is byte-identical across RNS's internal pure-Python backend and the PyCA/OpenSSL backend, and both match the NIST SP 800-38A F.2.5 CBC-AES256 vector: key=603deb10..., IV=000102..., plaintext block 6bc1bee2... -> ciphertext f58c4c04... A backend with a wrong block cipher / CBC chaining fails against the external vector.",
)
def test_provider_equivalence_aes256(sut):
    results = {}
    for provider in _PROVIDERS:
        r = sut.execute(
            "crypto_provider_op",
            op="aes_256_cbc_encrypt",
            provider=provider,
            plaintext=_NIST_AES256_PT,
            key=_NIST_AES256_KEY,
            iv=_NIST_AES256_IV,
        )["result"]
        assert r == _NIST_AES256_CT, f"{provider}: AES-256-CBC must match NIST SP 800-38A vector"
        results[provider] = r
    assert results["internal"] == results["pyca"], "AES-256-CBC backends diverge"


@conformance_case(
    commands=["crypto_provider_op", "ed25519_generate"],
    verifies="Ed25519 signing is deterministic per RFC 8032 (synthetic nonce), so RNS's internal pure-Python backend and the PyCA/OpenSSL backend produce the BYTE-IDENTICAL 64-byte signature for the same seed and message — two independent implementations agreeing on the deterministic output. The signature also cross-verifies: a signature made under one backend verifies True under BOTH, and a single-byte change to the message verifies False under both.",
)
def test_provider_equivalence_ed25519_sign(sut):
    seed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    msg = "deadbeefcafe"
    sigs = {}
    for provider in _PROVIDERS:
        s = sut.execute(
            "crypto_provider_op",
            op="ed25519_sign",
            provider=provider,
            private_key=seed,
            message=msg,
        )["result"]
        assert len(bytes.fromhex(s)) == _ED25519_SIG_LEN, f"{provider}: Ed25519 sig must be 64 bytes"
        sigs[provider] = s
    assert sigs["internal"] == sigs["pyca"], (
        "Ed25519 deterministic signatures diverge across backends"
    )

    # Derive the public key (internal path) and cross-verify the signature.
    pub = sut.execute("ed25519_generate", seed=seed)["public_key"]
    sig = sigs["internal"]
    for provider in _PROVIDERS:
        ok = sut.execute(
            "crypto_provider_op",
            op="ed25519_verify",
            provider=provider,
            public_key=pub,
            message=msg,
            signature=sig,
        )["valid"]
        assert ok is True, f"{provider}: valid Ed25519 signature must verify"
        bad = sut.execute(
            "crypto_provider_op",
            op="ed25519_verify",
            provider=provider,
            public_key=pub,
            message="deadbeefcaff",  # one byte changed
            signature=sig,
        )["valid"]
        assert bad is False, f"{provider}: tampered message must fail verification"


@conformance_case(
    commands=["crypto_provider_op", "ed25519_generate"],
    verifies="Ed25519 verification matches the RFC 8032 section 7.1 TEST 1 vector on BOTH RNS backends: public key d75a9801..., empty message, signature e5564300...100b verifies True, while the same signature against a non-empty message verifies False. Both the internal and PyCA backends accept the published-valid signature and reject the altered message.",
)
def test_provider_ed25519_verify_kat(sut):
    for provider in _PROVIDERS:
        ok = sut.execute(
            "crypto_provider_op",
            op="ed25519_verify",
            provider=provider,
            public_key=_RFC8032_T1_PUB,
            message=_RFC8032_T1_MSG,
            signature=_RFC8032_T1_SIG,
        )["valid"]
        assert ok is True, f"{provider}: RFC 8032 TEST 1 signature must verify"

        bad = sut.execute(
            "crypto_provider_op",
            op="ed25519_verify",
            provider=provider,
            public_key=_RFC8032_T1_PUB,
            message="00",  # not the empty message the signature covers
            signature=_RFC8032_T1_SIG,
        )["valid"]
        assert bad is False, f"{provider}: signature must not verify over a different message"
