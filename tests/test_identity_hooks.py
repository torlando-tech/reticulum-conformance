"""Identity-subsystem conformance: ratchet trial order, the remember()
public-key length gate, and the keyless-Identity KeyError contract.

These pin three behaviours in RNS.Identity that the rest of the suite only ever
exercised on their happy path:

  * ``Identity.decrypt(..., ratchets=[...])`` trials a LIST of candidate ratchet
    private keys IN ORDER, first success wins, and reports the WINNING ratchet id
    on its receiver (Identity.py:882-895). The prior bridge command only ever
    passed a single-element list, so the multi-ratchet trial loop and the
    ``enforce_ratchets`` rejection path were never driven.
  * ``Identity.remember`` rejects any public key whose length is not exactly
    ``KEYSIZE//8 == 64`` bytes (Identity.py:101-102).
  * ``Identity.decrypt`` / ``sign`` / ``encrypt`` raise ``KeyError`` when the
    Identity holds no key (Identity.py:852/921/939).

Every assertion anchors on an EXTERNAL ground truth — the RNS 1.3.1 spec literal
(KEYSIZE//8 == 64 bytes; ratchet id == ``sha256(ratchet_public)[:10]`` per
NAME_HASH_LENGTH == 80 bits == 10 bytes) or the documented API contract
(keyless op raises KeyError) — never impl-vs-itself.
"""

import hashlib

import pytest

from conformance import conformance_case


__category_title__ = "Identity Hooks"
__category_order__ = 8


# RNS 1.3.1 spec literals (external ground truth, NOT read from the impl).
_KEYSIZE_BYTES = 64          # KEYSIZE//8 == (256+256)//8: full public key length
_RATCHET_ID_LEN = 10         # NAME_HASH_LENGTH//8 == 80 bits == 10 bytes


def _ratchet_id_external(ratchet_public_hex):
    """Independent derivation of a ratchet id: the first NAME_HASH_LENGTH//8
    bytes of SHA-256 over the ratchet public key (Identity._get_ratchet_id =
    full_hash(public)[:10], and full_hash is SHA-256). Computed here in the
    test, with no reliance on the bridge, so it is a true external anchor."""
    digest = hashlib.new("sha256", bytes.fromhex(ratchet_public_hex)).digest()
    return digest[:_RATCHET_ID_LEN].hex()


def _make_identity(impl, x_seed, ed_seed):
    """Build a 64-byte Identity private key (X25519 half || Ed25519 half) from
    two deterministic seeds and return (private_hex, public_hex)."""
    xk = impl.execute("x25519_generate", seed=x_seed)
    ed = impl.execute("ed25519_generate", seed=ed_seed)
    prv = xk["private_key"] + ed["private_key"]
    fid = impl.execute("identity_from_private_key", private_key=prv)
    return prv, fid["public_key"]


def _make_ratchet(impl, seed):
    """Return (ratchet_private_hex, ratchet_public_hex) for a seed."""
    rp = impl.execute("x25519_generate", seed=seed)["private_key"]
    pub = impl.execute("ratchet_public_from_private", ratchet_private=rp)["ratchet_public"]
    return rp, pub


@conformance_case(
    commands=[
        "x25519_generate", "ed25519_generate", "identity_from_private_key",
        "ratchet_public_from_private", "ratchet_encrypt", "ratchet_decrypt",
    ],
    verifies="Identity.decrypt trials a multi-element ratchet list in order, the "
             "first matching ratchet (here the 2nd of 3) decrypts, and the reported "
             "latest_ratchet_id equals the independently-derived sha256(ratchet_public)[:10] "
             "of that winning ratchet — not of the non-matching ratchets that precede/follow it",
)
def test_ratchet_trial_order_reports_winning_id(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        prv, pub = _make_identity(impl, "44" * 32, "33" * 32)
        rw1, _ = _make_ratchet(impl, "01" * 32)
        rc, rc_pub = _make_ratchet(impl, "02" * 32)
        rw2, _ = _make_ratchet(impl, "03" * 32)

        ct = impl.execute("ratchet_encrypt", public_key=pub,
                          ratchet_public=rc_pub, plaintext=b"trial-order".hex())["ciphertext"]

        res = impl.execute("ratchet_decrypt", private_key=prv, ciphertext=ct,
                          ratchet_privates=[rw1, rc, rw2])

        assert res["plaintext"] == b"trial-order".hex(), f"{label}: correct ratchet must decrypt"
        expected = _ratchet_id_external(rc_pub)
        assert res["latest_ratchet_id"] == expected, (
            f"{label}: must report the WINNING ratchet id {expected}, got {res['latest_ratchet_id']}")
        # Negative: the id must NOT be that of either non-matching ratchet.
        for wrong_priv in (rw1, rw2):
            wrong_pub = impl.execute("ratchet_public_from_private",
                                     ratchet_private=wrong_priv)["ratchet_public"]
            assert res["latest_ratchet_id"] != _ratchet_id_external(wrong_pub), (
                f"{label}: reported id must not be a non-matching ratchet's id")


@conformance_case(
    commands=[
        "x25519_generate", "ed25519_generate", "identity_from_private_key",
        "ratchet_public_from_private", "ratchet_encrypt", "identity_encrypt",
        "ratchet_decrypt",
    ],
    verifies="enforce_ratchets forbids the static-key fallback: a token encrypted to "
             "the static X25519 key decrypts when no ratchet matches AND enforcement is "
             "off (latest_ratchet_id null), but yields None under enforcement; while a "
             "ratchet-encrypted token whose ratchet is absent yields None in BOTH modes",
)
def test_ratchet_enforcement_blocks_static_fallback(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        prv, pub = _make_identity(impl, "44" * 32, "33" * 32)
        wrong_priv, _ = _make_ratchet(impl, "09" * 32)

        # Token encrypted to the STATIC key (no ratchet).
        static_ct = impl.execute("identity_encrypt", public_key=pub,
                                 plaintext=b"static".hex())["ciphertext"]
        no_enforce = impl.execute("ratchet_decrypt", private_key=prv, ciphertext=static_ct,
                                  ratchet_privates=[wrong_priv], enforce_ratchets=False)
        assert no_enforce["plaintext"] == b"static".hex(), (
            f"{label}: static fallback must succeed when enforcement off")
        assert no_enforce["latest_ratchet_id"] is None, (
            f"{label}: static fallback must report no ratchet id")

        enforced = impl.execute("ratchet_decrypt", private_key=prv, ciphertext=static_ct,
                                ratchet_privates=[wrong_priv], enforce_ratchets=True)
        assert enforced["plaintext"] is None, (
            f"{label}: enforcement must forbid the static fallback")
        assert enforced["latest_ratchet_id"] is None

        # Token encrypted to a ratchet whose private key is NOT supplied.
        _, absent_pub = _make_ratchet(impl, "0a" * 32)
        ratchet_ct = impl.execute("ratchet_encrypt", public_key=pub,
                                  ratchet_public=absent_pub, plaintext=b"x".hex())["ciphertext"]
        for enforce in (False, True):
            r = impl.execute("ratchet_decrypt", private_key=prv, ciphertext=ratchet_ct,
                            ratchet_privates=[wrong_priv], enforce_ratchets=enforce)
            assert r["plaintext"] is None, (
                f"{label}: absent ratchet must not decrypt (enforce={enforce})")


@conformance_case(
    commands=["identity_remember"],
    verifies="Identity.remember enforces the exact public-key length gate KEYSIZE//8 == 64 "
             "bytes: a 64-byte key is accepted (and recalls), while 63- and 65-byte keys "
             "are rejected with TypeError",
)
def test_remember_public_key_length_gate(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        # Positive: exactly 64 bytes is accepted.
        ok = impl.execute("identity_remember", packet_hash="11" * 16,
                         destination_hash="22" * 16, public_key="ab" * _KEYSIZE_BYTES,
                         app_data=None)
        assert ok["ok"] is True, f"{label}: 64-byte public key must be accepted"
        assert ok["public_key_len"] == _KEYSIZE_BYTES
        assert ok["recalled"] is True, f"{label}: remembered key must recall"

        # Negative: one byte short and one byte long are both rejected.
        for n, tag in ((_KEYSIZE_BYTES - 1, "63"), (_KEYSIZE_BYTES + 1, "65")):
            bad = impl.execute("identity_remember", packet_hash="11" * 16,
                              destination_hash=(tag * 16)[:32], public_key="ab" * n,
                              app_data=None)
            assert bad["ok"] is False, f"{label}: {n}-byte key must be rejected"
            assert bad["error"] == "TypeError", f"{label}: rejection must be TypeError ({n})"


@conformance_case(
    commands=["identity_keyless_op"],
    verifies="A keyless RNS.Identity (create_keys=False, no key loaded) raises KeyError "
             "for decrypt, sign AND encrypt — it never silently returns the input or a "
             "fabricated result",
)
def test_keyless_identity_ops_raise_keyerror(sut, reference, sut_impl_name):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        if label == "sut" and sut_impl_name == "kotlin":
            # The reference arm above has already been asserted. reticulum-kt
            # cannot drive this op at all: Identity's private constructor
            # requires key material, so the keyless state python guards with a
            # runtime KeyError is unrepresentable (a stronger, compile-time
            # form of the same never-fabricate-a-result guarantee).
            # TODO(file reticulum-kt issue): track formally sanctioning this.
            pytest.xfail(
                "reticulum-kt: keyless Identity is unrepresentable by "
                "construction; the python-only create_keys=False runtime state "
                "cannot be honestly exercised"
            )
        for op in ("decrypt", "sign", "encrypt"):
            res = impl.execute("identity_keyless_op", op=op, data="00" * 40)
            assert res["raised"] == "KeyError", (
                f"{label}: keyless {op} must raise KeyError, got {res!r}")
