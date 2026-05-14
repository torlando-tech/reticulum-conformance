"""Destination conformance tests.

Tests name hashing, destination hash computation, and packet hashing
by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Destination"
__category_order__ = 4


@conformance_case(
    commands=["name_hash"],
    verifies='RNS `name_hash` of `"lxmf.delivery"` (the canonical LXMF delivery destination) is byte-identical across impls',
)
def test_name_hash(sut, reference):
    ref = reference.execute("name_hash", name="lxmf.delivery")
    res = sut.execute("name_hash", name="lxmf.delivery")
    assert_hex_equal(res["hash"], ref["hash"])


@conformance_case(
    commands=["identity_from_private_key", "destination_hash"],
    verifies="RNS `destination_hash` composition: takes an `identity_hash` + `app_name` + `aspects`, computes the `name_hash`, then truncated-hashes `name_hash + identity_hash` into the 16-byte destination address — asserts both the intermediate `name_hash` and the final address",
)
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


@conformance_case(
    commands=["packet_pack", "packet_hash"],
    verifies='RNS `packet_hash` (SHA-256 of the "hashable part" of a packet — hops byte and HEADER_2 transport_id masked out): byte-identical hash and `hashable_part` slice. This is the dedup key in the packet hashlist, deliberately stable as packets propagate through transports',
)
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
