"""Resource transfer conformance tests.

Tests resource hashing, flag encoding/decoding, map hash computation,
hashmap building, advertisement packing/unpacking, and resource proof
by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_resource_hash(sut, reference):
    data = random_hex(100)
    rh = random_hex(4)
    ref = reference.execute("resource_hash", data=data, random_hash=rh)
    res = sut.execute("resource_hash", data=data, random_hash=rh)
    assert_hex_equal(res["hash"], ref["hash"])


def test_resource_flags_encode(sut, reference):
    ref = reference.execute(
        "resource_flags",
        mode="encode",
        encrypted=True,
        compressed=False,
        split=False,
        is_request=False,
        is_response=True,
        has_metadata=False,
    )
    res = sut.execute(
        "resource_flags",
        mode="encode",
        encrypted=True,
        compressed=False,
        split=False,
        is_request=False,
        is_response=True,
        has_metadata=False,
    )
    assert res["flags"] == ref["flags"]


def test_resource_flags_decode(sut, reference):
    ref = reference.execute("resource_flags", mode="decode", flags=0x11)
    res = sut.execute("resource_flags", mode="decode", flags=0x11)
    assert res["encrypted"] == ref["encrypted"]
    assert res["compressed"] == ref["compressed"]
    assert res["split"] == ref["split"]
    assert res["is_request"] == ref["is_request"]
    assert res["is_response"] == ref["is_response"]
    assert res["has_metadata"] == ref["has_metadata"]


def test_resource_map_hash(sut, reference):
    part_data = random_hex(64)
    rh = random_hex(4)
    ref = reference.execute("resource_map_hash", part_data=part_data, random_hash=rh)
    res = sut.execute("resource_map_hash", part_data=part_data, random_hash=rh)
    assert_hex_equal(res["map_hash"], ref["map_hash"])


def test_resource_build_hashmap(sut, reference):
    parts = [random_hex(32) for _ in range(5)]
    rh = random_hex(4)
    ref = reference.execute("resource_build_hashmap", parts=parts, random_hash=rh)
    res = sut.execute("resource_build_hashmap", parts=parts, random_hash=rh)
    assert_hex_equal(res["hashmap"], ref["hashmap"])
    assert res["num_parts"] == ref["num_parts"]


def test_resource_proof(sut, reference):
    data = random_hex(100)
    resource_hash = random_hex(32)
    ref = reference.execute("resource_proof", data=data, resource_hash=resource_hash)
    res = sut.execute("resource_proof", data=data, resource_hash=resource_hash)
    assert_hex_equal(res["proof"], ref["proof"])
