"""Destination conformance — completeness gaps (Opus).

Closes three RNS.Destination behaviors that the existing destination/announce
suite left partial or uncovered, each anchored on an INDEPENDENT value rather
than an impl-vs-itself field comparison:

  * dest-hash-identity-material-validation — RNS.Destination.hash rejects
    identity material that is neither an Identity instance nor exactly
    TRUNCATED_HASHLENGTH//8 (16) bytes (Destination.py:122-128). Pinned by
    feeding wrong-length identity bytes through `destination_hash` and asserting
    rejection, with the 16-byte form as the positive control.

  * dest-announce-signature-composition — the announce Ed25519 signature covers
    destination_hash + public_key + name_hash + random_hash + ratchet + app_data
    in THAT order (Identity.validate_announce:559). Every term is covered
    individually elsewhere, but no existing test builds an announce with BOTH a
    ratchet AND app_data, so the "ratchet precedes app_data" ordering is never
    exercised. Here we reconstruct the signed stream independently and verify
    RNS's own signature against it; swapping ratchet/app_data must break it.

  * dest-announce-random-hash-format (freshness half) — random_hash is
    get_random_hash()[0:5] + int(time.time()).to_bytes(5,"big")
    (Destination.py:282), so the leading 5 bytes are fresh per announce and the
    trailing 5 are a big-endian unix timestamp. The existing suite pins the
    10-byte length and an injected emission_ts, but never that two announces of
    the SAME destination carry different random material — an impl that froze the
    random_hash would pass. Here two back-to-back announces must differ in their
    random 5 bytes, and the timestamp tail must match wall-clock independently.
"""

import time

import pytest

from bridge_client import BridgeError
from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Destination"
__category_order__ = 4


# RNS spec literals (RNS.Reticulum / RNS.Identity), independently restated here.
_TRUNCATED_HASHLEN = 16   # TRUNCATED_HASHLENGTH // 8
_KEYSIZE = 64             # Identity.KEYSIZE // 8
_NAME_HASH_LEN = 10       # Identity.NAME_HASH_LENGTH // 8
_RANDOM_HASH_LEN = 10
_RATCHET_LEN = 32         # Identity.RATCHETSIZE // 8


@conformance_case(
    commands=["identity_from_private_key", "destination_hash"],
    verifies="RNS.Destination.hash accepts identity material ONLY as an Identity instance or exactly TRUNCATED_HASHLENGTH//8 (16) bytes, else raises TypeError (Destination.py:122-128): a 16-byte identity hash derives the address, but 15-byte, 17-byte and empty identity material are all rejected — an impl that truncates/pads wrong-length material instead of rejecting it would derive a silently-different address and still pass a positive-only suite",
)
def test_dest_hash_rejects_wrong_length_identity_material(sut):
    """The destination_hash bridge command passes the raw identity bytes
    straight to RNS.Destination.hash, so a wrong-length value reaches the real
    length check (len(identity) == TRUNCATED_HASHLENGTH//8). The 16-byte
    positive control proves the rejection is specific to the length, not a
    blanket failure of the command.
    """
    idn = sut.execute("identity_from_private_key", private_key=random_hex(64))
    identity_hash = idn["hash"]
    assert len(bytes.fromhex(identity_hash)) == _TRUNCATED_HASHLEN

    # Positive control: the correct 16-byte identity material derives an address.
    ok = sut.execute(
        "destination_hash",
        identity_hash=identity_hash, app_name="lxmf", aspects=["delivery"],
    )
    assert len(bytes.fromhex(ok["destination_hash"])) == _TRUNCATED_HASHLEN

    # Wrong-length identity material must be rejected (TypeError -> BridgeError).
    for bad_len in (_TRUNCATED_HASHLEN - 1, _TRUNCATED_HASHLEN + 1, 0):
        with pytest.raises(BridgeError):
            sut.execute(
                "destination_hash",
                identity_hash=random_hex(bad_len),
                app_name="lxmf", aspects=["delivery"],
            )


@conformance_case(
    commands=["announce_build", "identity_verify"],
    verifies="The announce Ed25519 signature covers destination_hash || public_key || name_hash || random_hash || ratchet || app_data in THAT order, with the ratchet BEFORE app_data (Identity.validate_announce:559). For an announce built with BOTH a ratchet and app_data, RNS's own signature verifies against the independently-reassembled stream in ratchet-then-app_data order and FAILS against the app_data-then-ratchet order — pinning the both-present ordering no single-term test reaches",
)
def test_announce_signature_orders_ratchet_before_app_data(sut, reference):
    priv = random_hex(64)
    app_data = b"completeness-app-data".hex()

    for builder, verifier, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "announce_build",
            private_key=priv, app_name="lxmf", aspects=["delivery"],
            enable_ratchets=True, app_data=app_data,
        )
        assert built["has_ratchet"] is True, f"{label}: expected a ratchet"
        assert len(bytes.fromhex(built["ratchet"])) == _RATCHET_LEN
        assert bytes.fromhex(built["app_data"]) != b"", f"{label}: app_data missing"

        dh = built["destination_hash"]
        pk = built["public_key"]
        nh = built["name_hash"]
        rh = built["random_hash"]
        rt = built["ratchet"]
        ad = built["app_data"]
        sig = built["signature"]

        # Independent reassembly in the spec order (ratchet before app_data).
        signed = dh + pk + nh + rh + rt + ad
        v_ok = verifier.execute(
            "identity_verify", public_key=pk, message=signed, signature=sig,
        )
        assert v_ok["valid"] is True, (
            f"{label}: RNS announce signature did not verify against "
            "dest_hash||pubkey||name_hash||random_hash||ratchet||app_data"
        )

        # Negative: swap ratchet and app_data -> the signed stream changes ->
        # the same signature must NOT verify. This is what isolates the ORDER.
        swapped = dh + pk + nh + rh + ad + rt
        v_bad = verifier.execute(
            "identity_verify", public_key=pk, message=swapped, signature=sig,
        )
        assert v_bad["valid"] is False, (
            f"{label}: signature verified with app_data BEFORE ratchet — "
            "the ratchet/app_data ordering is not enforced"
        )


@conformance_case(
    commands=["announce_build"],
    verifies="Announce random_hash = 5 fresh random bytes || 5-byte big-endian int(time.time()) (Destination.py:282): two back-to-back announces of the SAME destination carry DIFFERENT leading-5 random bytes (freshness — an impl freezing the random_hash fails), the field is exactly 10 bytes, and the trailing-5 big-endian timestamp matches the test's own wall clock within a tolerance window (independent time anchor, not impl-vs-itself)",
)
def test_announce_random_hash_is_fresh_and_timestamped(sut):
    priv = random_hex(64)

    before = int(time.time())
    a1 = sut.execute(
        "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
    )
    a2 = sut.execute(
        "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
    )
    after = int(time.time())

    rh1 = bytes.fromhex(a1["random_hash"])
    rh2 = bytes.fromhex(a2["random_hash"])
    assert len(rh1) == _RANDOM_HASH_LEN and len(rh2) == _RANDOM_HASH_LEN

    # Freshness: the leading 5 random bytes must differ between two announces of
    # the same destination (collision probability 2**-40).
    assert rh1[:5] != rh2[:5], (
        "random_hash leading 5 bytes did not change across two announces — "
        "the random portion is frozen"
    )

    # Timestamp tail: big-endian unix seconds, anchored on the test's own clock.
    for rh in (rh1, rh2):
        ts = int.from_bytes(rh[5:10], "big")
        assert before - 2 <= ts <= after + 2, (
            f"random_hash timestamp {ts} not within wall-clock window "
            f"[{before - 2}, {after + 2}]"
        )
