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
controls below catch a validate_announce that wrongly accepts malformed
announces, which the propagation tests can't trigger. The negatives cover the
three independent rejection paths RNS.Identity.validate_announce exposes:

  * a flipped signature byte           -> Ed25519 signature check fails;
  * a swapped public key               -> signature is verified against the
                                          ANNOUNCED key, so it fails too;
  * an altered (unsigned) dest_hash    -> dest_hash is the FIRST signed term,
                                          so the flip breaks the signature
                                          (rejection still fires at the sig
                                          check, not the later recompute);
  * a forged + RE-SIGNED dest_hash     -> the only case that clears the
                                          signature check and reaches the
                                          separate dest-hash recompute branch
                                          (destination_hash vs
                                          full_hash(name_hash + identity.hash)).
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
    verifies="Negative control: an announce whose destination_hash header byte is altered (without re-signing) fails validation on both impls. destination_hash is the FIRST term of the Ed25519 signed_data (destination_hash + public_key + name_hash + random_hash + ratchet + app_data), so altering it breaks the signature and validate_announce rejects at the signature check — it never reaches the later dest-hash recompute branch (which the companion forged + re-signed test exercises).",
)
def test_announce_validate_rejects_tampered_destination_hash(sut, reference):
    priv = random_hex(64)
    built = reference.execute(
        "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
    )
    raw = bytearray(bytes.fromhex(built["raw"]))
    # destination_hash sits at bytes 2..18 in a HEADER_1 packet (after flags +
    # hops). Flip a byte in the middle — keeps the packet structure valid so
    # unpack succeeds. Because dest_hash is the first term of the signed_data,
    # the flip invalidates the Ed25519 signature; validate_announce rejects at
    # the signature check and never reaches the dest-hash recompute branch.
    raw[2 + 8] ^= 0x01
    tampered = bytes(raw).hex()

    ref_v = reference.execute("announce_validate", raw=tampered)
    sut_v = sut.execute("announce_validate", raw=tampered)
    assert ref_v["valid"] is False, "reference accepted an announce with tampered dest_hash"
    assert sut_v["valid"] is False, "SUT accepted an announce with tampered dest_hash"


@conformance_case(
    commands=["announce_build", "identity_from_private_key", "announce_validate"],
    verifies="Negative control: an announce whose embedded public key is replaced with a different identity's public key is rejected by both impls. validate_announce verifies the Ed25519 signature against the ANNOUNCED public key, so a substituted key fails the signature check (the original signature was produced by the original key over the original key bytes) — catches a validator that verifies against a trusted/cached key instead of the announced one.",
)
def test_announce_validate_rejects_wrong_public_key(sut, reference):
    priv = random_hex(64)
    other_priv = random_hex(64)
    built = reference.execute(
        "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
    )
    # Positive anchor: the untouched announce validates, so a False below is a
    # genuine rejection of the swap, not a build artifact.
    assert reference.execute("announce_validate", raw=built["raw"])["valid"] is True

    other = reference.execute(
        "identity_from_private_key", private_key=other_priv,
    )
    other_pub = bytes.fromhex(other["public_key"])
    assert len(other_pub) == _KEYSIZE

    raw = bytearray(bytes.fromhex(built["raw"]))
    announce_data = bytes.fromhex(built["announce_data"])
    header_len = len(raw) - len(announce_data)
    # The public key is the first KEYSIZE bytes of the announce body. Swap in a
    # different (valid) identity's public key; everything else (dest_hash,
    # name_hash, random_hash, signature) is left intact.
    raw[header_len:header_len + _KEYSIZE] = other_pub
    forged = bytes(raw).hex()

    ref_v = reference.execute("announce_validate", raw=forged)
    sut_v = sut.execute("announce_validate", raw=forged)
    assert ref_v["valid"] is False, "reference accepted an announce with a swapped public key"
    assert sut_v["valid"] is False, "SUT accepted an announce with a swapped public key"


@conformance_case(
    commands=["announce_build", "identity_sign", "identity_verify", "announce_validate"],
    verifies="Negative control reaching the destination-hash RECOMPUTE branch: an announce whose header destination_hash is forged AND re-signed (so the Ed25519 signature over the forged signed_data is valid) is still rejected by both impls. validate_announce recomputes expected_hash = full_hash(name_hash + identity.hash)[:TRUNCATED_HASHLENGTH//8] and rejects the destination mismatch even though the signature verifies. A positive control (identity_verify accepts the re-signed signature on both impls) proves rejection comes from the dest-hash recompute, not the signature check.",
)
def test_announce_validate_rejects_forged_resigned_destination_hash(sut, reference):
    priv = random_hex(64)
    built = reference.execute(
        "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"],
    )
    # This recompute-branch construction assumes the no-ratchet body layout
    # (pubkey + name_hash + random_hash + signature [+ app_data]); assert it.
    assert built["has_ratchet"] is False, "expected a non-ratchet announce for the recompute-branch case"

    pubkey = bytes.fromhex(built["public_key"])
    name_hash = bytes.fromhex(built["name_hash"])
    random_hash = bytes.fromhex(built["random_hash"])
    app_data = bytes.fromhex(built["app_data"]) if built["app_data"] else b""
    raw = bytearray(bytes.fromhex(built["raw"]))
    real_dest = bytes(raw[2:18])
    assert_hex_equal(built["destination_hash"], real_dest.hex())

    # Forge the destination hash by flipping a byte. The genuine dest_hash IS
    # full_hash(name_hash + identity.hash)[:16], so any change guarantees the
    # recompute branch sees a mismatch.
    forged_dest = bytearray(real_dest)
    forged_dest[8] ^= 0x01
    forged_dest = bytes(forged_dest)

    # Re-sign over the forged signed_data so the SIGNATURE check passes.
    # signed_data layout mirrors RNS.Identity.validate_announce:
    # destination_hash + public_key + name_hash + random_hash + ratchet(none)
    # + app_data.
    signed_data = (forged_dest + pubkey + name_hash + random_hash + app_data).hex()
    new_sig = reference.execute(
        "identity_sign", private_key=priv, message=signed_data,
    )["signature"]

    # Positive control: the re-signed signature is valid on BOTH impls. This
    # proves a validator clears the signature check, so the rejection below
    # must originate in the dest-hash recompute branch.
    for impl, label in ((reference, "ref"), (sut, "sut")):
        v = impl.execute(
            "identity_verify",
            public_key=built["public_key"], message=signed_data, signature=new_sig,
        )
        assert v["valid"] is True, (
            f"{label}: re-signed forged signed_data failed signature verification "
            f"(positive control) — the negative below would not isolate the recompute branch"
        )

    # Reassemble the raw announce with the forged dest_hash + new signature.
    header_len = len(raw) - len(bytes.fromhex(built["announce_data"]))
    new_body = pubkey + name_hash + random_hash + bytes.fromhex(new_sig) + app_data
    raw[2:18] = forged_dest
    raw[header_len:] = new_body
    forged_raw = bytes(raw).hex()

    ref_v = reference.execute("announce_validate", raw=forged_raw)
    sut_v = sut.execute("announce_validate", raw=forged_raw)
    assert ref_v["valid"] is False, "reference accepted a forged + re-signed dest_hash announce"
    assert sut_v["valid"] is False, "SUT accepted a forged + re-signed dest_hash announce"
