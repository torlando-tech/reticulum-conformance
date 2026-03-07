"""Announce conformance tests.

Tests random hash generation, announce packing/unpacking, signing,
and verification by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_random_hash_with_params(sut, reference):
    rb = random_hex(5)
    ts = 1700000000
    ref = reference.execute("random_hash", random_bytes=rb, timestamp=ts)
    res = sut.execute("random_hash", random_bytes=rb, timestamp=ts)
    assert_hex_equal(res["random_hash"], ref["random_hash"])
    assert_hex_equal(res["timestamp_bytes"], ref["timestamp_bytes"])


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
