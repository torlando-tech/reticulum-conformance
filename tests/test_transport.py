"""Transport conformance tests.

Tests path request packing/unpacking, packet hashlist packing/unpacking,
and IFAC key derivation/computation/verification by comparing SUT output
against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_path_request_pack_unpack(sut, reference):
    dest = random_hex(16)
    ref = reference.execute("path_request_pack", destination_hash=dest)
    res = sut.execute("path_request_pack", destination_hash=dest)
    assert_hex_equal(res["data"], ref["data"])
    ref_u = reference.execute("path_request_unpack", data=ref["data"])
    res_u = sut.execute("path_request_unpack", data=ref["data"])
    assert_hex_equal(res_u["destination_hash"], ref_u["destination_hash"])


def test_packet_hashlist_pack_unpack(sut, reference):
    hashes = [random_hex(32) for _ in range(5)]
    ref = reference.execute("packet_hashlist_pack", hashes=hashes)
    res = sut.execute("packet_hashlist_pack", hashes=hashes)
    assert_hex_equal(res["serialized"], ref["serialized"])
    ref_u = reference.execute("packet_hashlist_unpack", serialized=ref["serialized"])
    res_u = sut.execute("packet_hashlist_unpack", serialized=ref["serialized"])
    assert len(res_u["hashes"]) == len(ref_u["hashes"])
    for r, e in zip(res_u["hashes"], ref_u["hashes"]):
        assert_hex_equal(r, e)


def test_ifac_derive_key(sut, reference):
    ifac_origin = ("testnet" + "secret123").encode("utf-8").hex()
    ref = reference.execute("ifac_derive_key", ifac_origin=ifac_origin)
    res = sut.execute("ifac_derive_key", ifac_origin=ifac_origin)
    assert_hex_equal(res["ifac_key"], ref["ifac_key"])


def test_ifac_compute_verify(sut, reference):
    ifac_origin = ("testnet" + "pass").encode("utf-8").hex()
    ref_key = reference.execute("ifac_derive_key", ifac_origin=ifac_origin)
    key = ref_key["ifac_key"]
    packet_data = random_hex(64)
    ref = reference.execute("ifac_compute", ifac_key=key, packet_data=packet_data)
    res = sut.execute("ifac_compute", ifac_key=key, packet_data=packet_data)
    assert_hex_equal(res["ifac"], ref["ifac"])
    # Verify
    ref_v = reference.execute(
        "ifac_verify",
        ifac_key=key,
        packet_data=packet_data,
        expected_ifac=ref["ifac"],
    )
    res_v = sut.execute(
        "ifac_verify",
        ifac_key=key,
        packet_data=packet_data,
        expected_ifac=ref["ifac"],
    )
    assert ref_v["valid"] is True
    assert res_v["valid"] is True
