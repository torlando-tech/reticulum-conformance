"""Destination conformance tests.

Tests name hashing, destination hash computation, and packet hashing
by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_name_hash(sut, reference):
    ref = reference.execute("name_hash", name="lxmf.delivery")
    res = sut.execute("name_hash", name="lxmf.delivery")
    assert_hex_equal(res["hash"], ref["hash"])


def test_name_hash_single_aspect(sut, reference):
    ref = reference.execute("name_hash", name="nomadnetwork.node")
    res = sut.execute("name_hash", name="nomadnetwork.node")
    assert_hex_equal(res["hash"], ref["hash"])


def test_destination_hash(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    ref = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    res = sut.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    assert_hex_equal(res["destination_hash"], ref["destination_hash"])
    assert_hex_equal(res["name_hash"], ref["name_hash"])


def test_packet_hash(sut, reference):
    dest = random_hex(16)
    data = random_hex(32)
    ref_pkt = reference.execute(
        "packet_pack",
        header_type=0,
        context_flag=0,
        transport_type=0,
        destination_type=0,
        packet_type=0,
        hops=0,
        destination_hash=dest,
        context=0,
        data=data,
    )
    ref = reference.execute("packet_hash", raw=ref_pkt["raw"])
    res = sut.execute("packet_hash", raw=ref_pkt["raw"])
    assert_hex_equal(res["hash"], ref["hash"])
    assert_hex_equal(res["hashable_part"], ref["hashable_part"])
