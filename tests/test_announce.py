"""Announce conformance tests.

Tests random hash generation, announce packing/unpacking, signing,
and verification by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Announce"
__category_order__ = 7
__category_description__ = (
    "An RNS announce is how a destination tells the network it exists. The "
    "packet bundles the destination's identity public keys (encryption + "
    "signing), a `name_hash`, a `random_hash` (freshness token from random "
    "bytes + timestamp), optionally a ratchet public key and `app_data`, "
    "plus an Ed25519 signature over the whole payload. These tests exercise "
    "the cryptographic primitives at the bytes level: sign, pack, unpack, "
    "verify. The wire-level propagation rules — transport nodes selectively "
    "forward subject to per-interface mode gating, bandwidth caps "
    "(default 2%), deduplication, and a 128-hop limit; this is *not* simple "
    "flooding — live in Wire Interop and Transport Behavior."
)


@conformance_case(
    commands=["random_hash"],
    verifies="RNS `random_hash` generation with explicit `random_bytes` + timestamp inputs produces a byte-identical 10-byte hash and `timestamp_bytes` — exercising the deterministic path of the function (production uses random inputs each announce)",
)
def test_random_hash_with_params(sut, reference):
    rb = random_hex(5)
    ts = 1700000000
    ref = reference.execute("random_hash", random_bytes=rb, timestamp=ts)
    res = sut.execute("random_hash", random_bytes=rb, timestamp=ts)
    assert_hex_equal(res["random_hash"], ref["random_hash"])
    assert_hex_equal(res["timestamp_bytes"], ref["timestamp_bytes"])


@conformance_case(
    commands=[
        "identity_from_private_key",
        "name_hash",
        "random_hash",
        "destination_hash",
        "announce_sign",
        "announce_pack",
        "announce_unpack",
    ],
    verifies="RNS announce lifecycle round-trip: sign → pack → unpack. Signature is byte-identical, `announce_data` is byte-identical, and unpacking recovers `public_key`, `name_hash`, `random_hash`, and signature byte-for-byte across impls",
)
def test_announce_pack_unpack(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]
    name_hash = reference.execute("name_hash", name="lxmf.delivery")["hash"]
    rh = random_hex(5)
    ts = 1700000000
    ref_rh = reference.execute("random_hash", random_bytes=rh, timestamp=ts)
    random_hash = ref_rh["random_hash"]
    # Sign
    ref_dest = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    ref_sig = reference.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
    )
    res_sig = sut.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
    )
    assert_hex_equal(res_sig["signature"], ref_sig["signature"])
    # Pack
    ref_pack = reference.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=ref_sig["signature"],
    )
    res_pack = sut.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=ref_sig["signature"],
    )
    assert_hex_equal(res_pack["announce_data"], ref_pack["announce_data"])
    # Unpack
    ref_unp = reference.execute(
        "announce_unpack",
        announce_data=ref_pack["announce_data"],
        has_ratchet=False,
    )
    res_unp = sut.execute(
        "announce_unpack",
        announce_data=ref_pack["announce_data"],
        has_ratchet=False,
    )
    assert_hex_equal(res_unp["public_key"], ref_unp["public_key"])
    assert_hex_equal(res_unp["name_hash"], ref_unp["name_hash"])
    assert_hex_equal(res_unp["random_hash"], ref_unp["random_hash"])
    assert_hex_equal(res_unp["signature"], ref_unp["signature"])


@conformance_case(
    commands=[
        "identity_from_private_key",
        "name_hash",
        "random_hash",
        "destination_hash",
        "announce_sign",
        "announce_pack",
        "announce_unpack",
    ],
    verifies="RNS announce lifecycle round-trip with non-empty `app_data` (the trailing variable-length field, inside the signed payload). In LXMF a delivery destination's `app_data` is a msgpack `[display_name, stamp_cost]` pair — the user's nickname and the proof-of-work cost they require for inbound messages. Confirms `app_data` is signed, packs into the trailing bytes, unpacks back byte-identical, and the signature still verifies — closes the gap test_announce_pack_unpack leaves by always sending empty `app_data`",
)
def test_announce_with_app_data(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]
    name_hash = reference.execute("name_hash", name="lxmf.delivery")["hash"]
    random_hash = reference.execute(
        "random_hash", random_bytes=random_hex(5), timestamp=1700000000
    )["random_hash"]
    # Non-empty trailing app_data. The conformance layer is announce-format,
    # not LXMF-format, so raw bytes are fine here — what matters is that a
    # non-empty app_data is signed, survives pack/unpack, and the signature
    # still verifies. In production this slot carries LXMF's msgpack
    # [display_name, stamp_cost] pair.
    app_data = random_hex(24)
    ref_dest = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    # Sign WITH app_data — app_data is part of the signed payload.
    ref_sig = reference.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        app_data=app_data,
    )
    res_sig = sut.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        app_data=app_data,
    )
    assert_hex_equal(res_sig["signature"], ref_sig["signature"])
    # Pack WITH app_data.
    ref_pack = reference.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=ref_sig["signature"],
        app_data=app_data,
    )
    res_pack = sut.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=res_sig["signature"],
        app_data=app_data,
    )
    assert_hex_equal(res_pack["announce_data"], ref_pack["announce_data"])
    # Unpack — app_data must come back byte-identical.
    ref_unp = reference.execute(
        "announce_unpack", announce_data=ref_pack["announce_data"], has_ratchet=False
    )
    res_unp = sut.execute(
        "announce_unpack", announce_data=ref_pack["announce_data"], has_ratchet=False
    )
    assert_hex_equal(res_unp["app_data"], ref_unp["app_data"])
    assert_hex_equal(res_unp["app_data"], app_data)
    # Signature still verifies with app_data present.
    ref_v = reference.execute(
        "announce_verify",
        announce_data=ref_pack["announce_data"],
        destination_hash=ref_dest["destination_hash"],
    )
    res_v = sut.execute(
        "announce_verify",
        announce_data=res_pack["announce_data"],
        destination_hash=ref_dest["destination_hash"],
    )
    assert ref_v["valid"] is True
    assert res_v["valid"] is True


@conformance_case(
    commands=[
        "identity_from_private_key",
        "name_hash",
        "random_hash",
        "destination_hash",
        "announce_sign",
        "announce_pack",
        "announce_verify",
    ],
    verifies="Both impls verify a signed announce as valid — `announce_verify` reconstructs the signed payload from `announce_data` + `destination_hash` and checks the Ed25519 signature; cross-impl verification confirms the signature is interoperable",
)
def test_announce_verify(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]
    name_hash = reference.execute("name_hash", name="lxmf.delivery")["hash"]
    rh = random_hex(5)
    ts = 1700000000
    ref_rh = reference.execute("random_hash", random_bytes=rh, timestamp=ts)
    random_hash = ref_rh["random_hash"]
    ref_dest = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    ref_sig = reference.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=ref_dest["destination_hash"],
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
    )
    ref_pack = reference.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=ref_sig["signature"],
    )
    ref_v = reference.execute(
        "announce_verify",
        public_key=pub,
        announce_data=ref_pack["announce_data"],
        destination_hash=ref_dest["destination_hash"],
        signature=ref_sig["signature"],
    )
    res_v = sut.execute(
        "announce_verify",
        public_key=pub,
        announce_data=ref_pack["announce_data"],
        destination_hash=ref_dest["destination_hash"],
        signature=ref_sig["signature"],
    )
    assert ref_v["valid"] is True
    assert res_v["valid"] is True


@conformance_case(
    commands=[
        "identity_from_private_key",
        "name_hash",
        "random_hash",
        "destination_hash",
        "announce_pack",
        "announce_verify",
    ],
    verifies="Negative control: both impls reject an announce with a forged (random) Ed25519 signature — verify returns false. Mirrors test_ed25519_verify_bad_sig but at the announce composition layer",
)
def test_announce_verify_bad_sig(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]
    name_hash = reference.execute("name_hash", name="lxmf.delivery")["hash"]
    random_hash = reference.execute(
        "random_hash", random_bytes=random_hex(5), timestamp=1700000000
    )["random_hash"]
    ref_dest = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    # Pack an announce with a FORGED signature — 64 random bytes that were
    # never produced by Ed25519 signing. destination_hash is the correct
    # canonical one, so this isolates the signature-check failure.
    bad_sig = random_hex(64)
    ref_pack = reference.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=bad_sig,
    )
    res_pack = sut.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=bad_sig,
    )
    ref_v = reference.execute(
        "announce_verify",
        announce_data=ref_pack["announce_data"],
        destination_hash=ref_dest["destination_hash"],
    )
    res_v = sut.execute(
        "announce_verify",
        announce_data=res_pack["announce_data"],
        destination_hash=ref_dest["destination_hash"],
    )
    # Both impls reject it, and both attribute the failure to the signature
    # (not the destination hash, which is correct here).
    assert ref_v["valid"] is False
    assert res_v["valid"] is False
    assert ref_v["signature_valid"] is False
    assert res_v["signature_valid"] is False


@conformance_case(
    commands=[
        "identity_from_private_key",
        "name_hash",
        "random_hash",
        "announce_sign",
        "announce_pack",
        "announce_verify",
    ],
    verifies="Negative control: an announce with a valid signature but a `destination_hash` that doesn't equal `truncated_hash(name_hash + identity_hash)` is rejected — exercises the dest-hash binding check that stops a node from claiming an unrelated destination's hash for an authentically-signed announce",
)
def test_announce_verify_dest_hash_mismatch(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    pub = ref_id["public_key"]
    name_hash = reference.execute("name_hash", name="lxmf.delivery")["hash"]
    random_hash = reference.execute(
        "random_hash", random_bytes=random_hex(5), timestamp=1700000000
    )["random_hash"]
    # Sign with a destination_hash that is NOT the canonical hash for this
    # identity + name_hash — an attacker-chosen 16-byte value. The signature
    # will be internally valid (it covers exactly the bytes we signed,
    # destination_hash included), but the dest-hash binding check must
    # reject it: destination_hash must equal truncated_hash(name_hash +
    # identity_hash), and a random value won't.
    lying_dest_hash = random_hex(16)
    ref_sig = reference.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=lying_dest_hash,
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
    )
    res_sig = sut.execute(
        "announce_sign",
        private_key=priv,
        destination_hash=lying_dest_hash,
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
    )
    assert_hex_equal(res_sig["signature"], ref_sig["signature"])
    ref_pack = reference.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=ref_sig["signature"],
    )
    res_pack = sut.execute(
        "announce_pack",
        public_key=pub,
        name_hash=name_hash,
        random_hash=random_hash,
        signature=res_sig["signature"],
    )
    # validate_dest_hash defaults True. The signature is valid for what was
    # signed, but the destination hash doesn't bind to the identity.
    ref_v = reference.execute(
        "announce_verify",
        announce_data=ref_pack["announce_data"],
        destination_hash=lying_dest_hash,
    )
    res_v = sut.execute(
        "announce_verify",
        announce_data=res_pack["announce_data"],
        destination_hash=lying_dest_hash,
    )
    assert ref_v["signature_valid"] is True
    assert res_v["signature_valid"] is True
    assert ref_v["dest_hash_valid"] is False
    assert res_v["dest_hash_valid"] is False
    assert ref_v["valid"] is False
    assert res_v["valid"] is False
