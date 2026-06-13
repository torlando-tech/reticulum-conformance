"""Identity completeness tests — gaps not covered by tests/test_identity.py.

This file closes the `decrypt-token-parse-and-min-length` completeness gap:
RNS.Identity.decrypt parses the FIRST 32 bytes of a ciphertext token as the
peer's ephemeral X25519 public key (`ciphertext_token[:KEYSIZE//8//2]`,
Identity.py:878), and rejects any token that is not strictly longer than that
32-byte prefix (`if len(ciphertext_token) > Identity.KEYSIZE//8//2`,
Identity.py:875; the else branch logs "token size was invalid" and returns
None, Identity.py:917-919).

The 32-byte boundary is anchored INDEPENDENTLY, not against the impl: an X25519
public key is exactly 32 bytes (RFC 7748 §5 / Curve25519 u-coordinate width),
and RNS pins it via KEYSIZE = 256*2 bits -> KEYSIZE//8//2 = 32 bytes
(Identity.py:59). A token of only the 32-byte ephemeral prefix (or shorter)
carries ZERO Token payload (no IV/ciphertext/HMAC) and therefore cannot
authenticate, so it MUST be rejected.

The required contract is a GRACEFUL rejection: RNS.Identity.decrypt returns None
(never raises, never returns attacker-controlled/garbage plaintext) on an
undersized token. The bridge surfaces that as plaintext=None; an impl that
crashes on a short token would instead raise a BridgeError, which these tests
forbid.
"""

import pytest

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Identity"
__category_order__ = 2


# X25519 public keys are 32 bytes (RFC 7748). This is the exact prefix
# RNS.Identity.decrypt slices off as the peer ephemeral key, and the strict
# minimum a ciphertext token must EXCEED to be parsed at all.
_EPHEMERAL_PUBKEY_LEN = 32

# RNS Token overhead = IV(16) + HMAC-SHA256(32) = 48 bytes, plus at least one
# 16-byte AES/PKCS7 block. With the 32-byte ephemeral prefix, the smallest
# possible well-formed Identity ciphertext is 32 + 48 + 16 = 96 bytes.
_MIN_IDENTITY_CIPHERTEXT_LEN = _EPHEMERAL_PUBKEY_LEN + 48 + 16


def _decrypt_is_none_no_raise(impl, priv, token_hex, label):
    """Assert impl.identity_decrypt(token) -> plaintext None, never raising.

    The graceful-rejection contract permits exactly plaintext=None. A raised
    BridgeError (impl crashed on a short token) or any non-None plaintext
    (forged/garbage acceptance) both fail.
    """
    try:
        res = impl.execute("identity_decrypt", private_key=priv, ciphertext=token_hex)
    except BridgeError as e:  # pragma: no cover - failure path
        pytest.fail(
            f"{label}: identity_decrypt raised on an undersized token "
            f"({len(token_hex)//2} bytes) instead of returning None gracefully: {e}"
        )
    assert res["plaintext"] is None, (
        f"{label}: identity_decrypt of an undersized token "
        f"({len(token_hex)//2} bytes) returned non-None plaintext "
        f"{res['plaintext']!r} — the min-length / ephemeral-prefix parse guard "
        f"is missing (a short token must never yield plaintext)"
    )


@conformance_case(
    commands=["identity_from_private_key", "identity_encrypt", "identity_decrypt"],
    verifies=(
        "RNS.Identity.decrypt rejects tokens that do not exceed the 32-byte "
        "ephemeral-X25519-pubkey prefix (Identity.py:875, len > KEYSIZE//8//2 "
        "= 32): a genuine ciphertext decrypts (positive control), but tokens of "
        "length 0, 16, and exactly 32 bytes — at or below the prefix width, "
        "carrying no Token payload — all yield plaintext=None gracefully (never "
        "raise, never return garbage). The boundary 32 is anchored to RFC 7748 "
        "X25519 key width, not to the impl"
    ),
)
def test_identity_decrypt_rejects_token_at_or_below_ephemeral_prefix(sut, reference):
    priv = random_hex(64)
    plaintext = random_hex(40)
    pub = sut.execute("identity_from_private_key", private_key=priv)["public_key"]
    genuine = sut.execute("identity_encrypt", public_key=pub, plaintext=plaintext)["ciphertext"]

    for impl, label in ((reference, "reference"), (sut, "sut")):
        # Positive control: the full genuine token decrypts back to the original.
        good = impl.execute("identity_decrypt", private_key=priv, ciphertext=genuine)
        assert_hex_equal(good["plaintext"], plaintext, msg=f"{label} positive control")
        # Negatives: every token length <= 32 (the ephemeral prefix width) must
        # be rejected with a graceful None. 32 bytes is the exact boundary RNS
        # tests with a STRICT greater-than, so 32 itself is rejected.
        for nbytes in (0, 16, _EPHEMERAL_PUBKEY_LEN):
            token = genuine[: nbytes * 2]  # hex chars
            assert len(token) == nbytes * 2
            _decrypt_is_none_no_raise(impl, priv, token, f"{label}/len={nbytes}")


@conformance_case(
    commands=["identity_from_private_key", "identity_encrypt", "identity_decrypt"],
    verifies=(
        "RNS.Identity.decrypt is total over undersized tokens just ABOVE the "
        "32-byte prefix: a genuine ciphertext is >= 96 bytes (32 ephemeral + "
        "IV16 + HMAC32 + one AES block) and decrypts (positive control), but "
        "tokens of 33, 50, and 79 bytes — long enough to clear the size guard "
        "yet too short to hold a valid Token (truncated IV/ciphertext/HMAC) — "
        "fail authentication and return plaintext=None on both impls, never "
        "raising and never surfacing forged plaintext"
    ),
)
def test_identity_decrypt_rejects_truncated_token_above_prefix(sut, reference):
    priv = random_hex(64)
    plaintext = random_hex(40)
    pub = sut.execute("identity_from_private_key", private_key=priv)["public_key"]
    genuine = sut.execute("identity_encrypt", public_key=pub, plaintext=plaintext)["ciphertext"]

    # Independent structural anchor on the encrypt-side output size: a genuine
    # Identity ciphertext is ephemeral(32) || Token(>=64), so >= 96 bytes.
    assert len(genuine) // 2 >= _MIN_IDENTITY_CIPHERTEXT_LEN, (
        f"genuine Identity ciphertext was {len(genuine)//2} bytes, below the "
        f"{_MIN_IDENTITY_CIPHERTEXT_LEN}-byte minimum (32 ephemeral + 48 Token "
        f"overhead + 16 AES block)"
    )

    for impl, label in ((reference, "reference"), (sut, "sut")):
        good = impl.execute("identity_decrypt", private_key=priv, ciphertext=genuine)
        assert_hex_equal(good["plaintext"], plaintext, msg=f"{label} positive control")
        # 33/50/79 bytes: above the 32-byte size guard but below a complete
        # Token — must fail authentication gracefully (None), not crash.
        for nbytes in (33, 50, 79):
            token = genuine[: nbytes * 2]
            _decrypt_is_none_no_raise(impl, priv, token, f"{label}/len={nbytes}")


@conformance_case(
    commands=["identity_from_private_key", "identity_encrypt", "identity_decrypt"],
    verifies=(
        "RNS.Identity.decrypt parses bytes [0:32] of the token as the peer "
        "ephemeral X25519 key and bytes [32:] as the Token (Identity.py:878-880): "
        "corrupting a byte INSIDE the 32-byte ephemeral prefix of an otherwise "
        "genuine ciphertext makes the recovered shared secret wrong, so the Token "
        "HMAC fails and decrypt returns plaintext=None — while the same ciphertext "
        "untouched decrypts (positive control). Pins that the ephemeral key is "
        "taken from the leading 32 bytes, not elsewhere"
    ),
)
def test_identity_decrypt_ephemeral_prefix_is_leading_32_bytes(sut, reference):
    priv = random_hex(64)
    plaintext = random_hex(40)
    pub = sut.execute("identity_from_private_key", private_key=priv)["public_key"]
    genuine = sut.execute("identity_encrypt", public_key=pub, plaintext=plaintext)["ciphertext"]

    # Corrupt byte index 5 — inside the [0:32] ephemeral-pubkey prefix.
    gb = bytearray.fromhex(genuine)
    assert 5 < _EPHEMERAL_PUBKEY_LEN
    gb[5] ^= 0x01
    corrupted_prefix = gb.hex()

    for impl, label in ((reference, "reference"), (sut, "sut")):
        # Positive control.
        good = impl.execute("identity_decrypt", private_key=priv, ciphertext=genuine)
        assert_hex_equal(good["plaintext"], plaintext, msg=f"{label} positive control")
        # Negative: a flipped bit in the ephemeral prefix changes the ECDH peer
        # key -> wrong shared key -> HMAC fails -> None (or a surfaced error).
        try:
            bad = impl.execute("identity_decrypt", private_key=priv, ciphertext=corrupted_prefix)
        except BridgeError:
            continue  # authentication failure surfaced as error — acceptable
        assert bad["plaintext"] is None, (
            f"{label}: corrupting the leading ephemeral-key prefix still yielded "
            f"plaintext {bad['plaintext']!r} — the ephemeral key is not being "
            f"read from token bytes [0:32]"
        )
