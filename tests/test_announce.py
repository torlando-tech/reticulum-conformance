"""Announce conformance tests.

Tests RNS announce packets built and validated through real
RNS.Destination.announce(send=False) and real RNS.Identity.validate_announce.
The prior hand-rolled commands (announce_pack/unpack/sign/verify + random_hash
with injectable inputs) reimplemented the announce field layout and Ed25519
signing on top of pure25519 + hashlib — any drift in RNS's signed-data scope
(e.g. reordering fields, changing what app_data is signed, changing ratchet
inclusion under context_flag) would have been invisible because the bridge
mirrored its own copy. Now the reference produces what real RNS produces.

The positive cases (well-formed announce round-trips) are also covered
transitively by the live wire announce tests in tests/wire/ — but the negative
controls below (tampered signature, tampered destination hash) catch a
validate_announce that wrongly accepts malformed announces, which the
propagation tests can't trigger.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Announce"
__category_order__ = 8


_KEYSIZE = 64
_NAME_HASH_LEN = 10
_RANDOM_HASH_LEN = 10
_SIG_LEN = 64


@conformance_case(
    commands=["announce_build", "announce_validate"],
    verifies="A well-formed RNS announce built by either impl validates as TRUE on the other — RNS.Identity.validate_announce accepts the cross-impl wire bytes including destination_hash, name_hash, random_hash and the Ed25519 signature over the (dest_hash + pubkey + name_hash + random_hash + ratchet + app_data) blob",
)
def test_announce_build_validate_roundtrip(sut, reference):
    priv = random_hex(64)
    for builder, validator, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
        )
        v = validator.execute("announce_validate", raw=built["raw"])
        assert v["valid"] is True, f"{label}: validate_announce rejected a well-formed announce"
        assert_hex_equal(v["destination_hash"], built["destination_hash"])
        # Structural sanity on the announce_data: pubkey/name_hash/random_hash
        # widths come from the RNS spec.
        assert len(bytes.fromhex(built["public_key"])) == _KEYSIZE
        assert len(bytes.fromhex(built["name_hash"])) == _NAME_HASH_LEN
        assert len(bytes.fromhex(built["random_hash"])) == _RANDOM_HASH_LEN
        assert len(bytes.fromhex(built["signature"])) == _SIG_LEN


@conformance_case(
    commands=["announce_build", "announce_validate"],
    verifies="An RNS announce carrying app_data round-trips cross-impl: app_data is part of what the signature covers, so a validator accepting the announce proves both impls agree on app_data inclusion in the signed scope",
)
def test_announce_with_app_data(sut, reference):
    priv = random_hex(64)
    app_data = random_hex(32)
    for builder, validator, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "announce_build",
            private_key=priv, app_name="lxmf", aspects=["delivery"], app_data=app_data,
        )
        v = validator.execute("announce_validate", raw=built["raw"])
        assert v["valid"] is True, f"{label}: announce-with-app_data rejected"
        assert_hex_equal(built["app_data"], app_data)


@conformance_case(
    commands=["announce_build", "announce_validate"],
    verifies="An RNS announce carrying a ratchet round-trips cross-impl: context_flag=1, ratchet is 32 bytes inserted between random_hash and signature in the signed scope, and validate_announce accepts it as TRUE",
)
def test_announce_with_ratchet(sut, reference):
    priv = random_hex(64)
    for builder, validator, label in (
        (reference, sut, "ref->sut"),
        (sut, reference, "sut->ref"),
    ):
        built = builder.execute(
            "announce_build",
            private_key=priv,
            app_name="lxmf", aspects=["delivery"],
            enable_ratchets=True,
        )
        assert built["has_ratchet"] is True, f"{label}: expected has_ratchet"
        assert len(bytes.fromhex(built["ratchet"])) == 32

        v = validator.execute("announce_validate", raw=built["raw"])
        assert v["valid"] is True, f"{label}: ratcheted announce rejected"
        assert v["has_ratchet"] is True
        # The validator extracts the same ratchet bytes the builder put in.
        assert_hex_equal(v["ratchet"], built["ratchet"])


@conformance_case(
    commands=["announce_build", "announce_validate"],
    verifies="Negative control: an announce whose Ed25519 signature byte is flipped is rejected by both impls (validate_announce returns False) — catches a validator that silently accepts a bad signature, which the propagation tests can't trigger",
)
def test_announce_validate_rejects_tampered_signature(sut, reference):
    priv = random_hex(64)
    built = reference.execute(
        "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
    )
    raw = bytearray(bytes.fromhex(built["raw"]))
    # The signature lives inside packet.data. Packet header (HEADER_1, no
    # transport_id) is 19 bytes: flags(1) + hops(1) + dest(16) + context(1).
    # Inside data: pubkey(64) + name_hash(10) + random_hash(10) [+ ratchet(32)
    # if context_flag set] + signature(64). Flip a byte in the middle of the
    # signature — guaranteed to break validation regardless of layout details.
    sig_offset_in_data = _KEYSIZE + _NAME_HASH_LEN + _RANDOM_HASH_LEN
    if built["has_ratchet"]:
        sig_offset_in_data += 32
    sig_byte_index = 19 + sig_offset_in_data + 30  # middle of the 64-byte sig
    raw[sig_byte_index] ^= 0x01
    tampered = bytes(raw).hex()

    ref_v = reference.execute("announce_validate", raw=tampered)
    sut_v = sut.execute("announce_validate", raw=tampered)
    assert ref_v["valid"] is False, "reference accepted a tampered-sig announce"
    assert sut_v["valid"] is False, "SUT accepted a tampered-sig announce"


@conformance_case(
    commands=["announce_build", "announce_validate"],
    verifies="Negative control: an announce whose destination_hash header byte is altered fails validation on both impls — validate_announce recomputes the expected destination_hash from the announce body and rejects the mismatch; catches a validator that trusts the header dest_hash without recomputing",
)
def test_announce_validate_rejects_tampered_destination_hash(sut, reference):
    priv = random_hex(64)
    built = reference.execute(
        "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
    )
    raw = bytearray(bytes.fromhex(built["raw"]))
    # destination_hash sits at bytes 2..18 in a HEADER_1 packet (after flags +
    # hops). Flip a byte in the middle — keeps the packet structure valid so
    # unpack succeeds; validate_announce must catch the mismatch.
    raw[2 + 8] ^= 0x01
    tampered = bytes(raw).hex()

    ref_v = reference.execute("announce_validate", raw=tampered)
    sut_v = sut.execute("announce_validate", raw=tampered)
    assert ref_v["valid"] is False, "reference accepted an announce with tampered dest_hash"
    assert sut_v["valid"] is False, "SUT accepted an announce with tampered dest_hash"
