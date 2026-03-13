"""Transport conformance tests.

Tests path request packing/unpacking, packet hashlist packing/unpacking,
and IFAC key derivation/computation/verification by comparing SUT output
against a reference implementation.
"""

import os

from conftest import random_hex, assert_hex_equal


def random_packet_hex(length):
    """Generate random packet data with bit 7 of byte 0 cleared.

    Real Reticulum packets never have bit 7 set in the first header byte —
    that bit is reserved for the IFAC flag and is only set by the masking
    transform. Using fully random data would cause roundtrip failures
    because the unmasking step clears bit 7 unconditionally.
    """
    raw = bytearray(os.urandom(length))
    raw[0] &= 0x7F
    return raw.hex()


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


def test_ifac_mask_packet(sut, reference):
    """IFAC masking produces identical wire-format packets."""
    ifac_origin = ("meshnet" + "hunter2").encode("utf-8").hex()
    key = reference.execute("ifac_derive_key", ifac_origin=ifac_origin)["ifac_key"]
    # Build a realistic 2-byte header + payload (bit 7 of byte 0 must be clear)
    packet_data = random_packet_hex(64)
    ref = reference.execute("ifac_mask_packet", ifac_key=key, packet_data=packet_data)
    res = sut.execute("ifac_mask_packet", ifac_key=key, packet_data=packet_data)
    assert_hex_equal(res["masked_packet"], ref["masked_packet"])
    assert_hex_equal(res["ifac"], ref["ifac"])
    # Masked packet should have IFAC flag set
    masked = bytes.fromhex(ref["masked_packet"])
    assert masked[0] & 0x80 == 0x80, "IFAC flag not set in masked packet"
    # Masked packet should be longer by ifac_size
    assert len(masked) == len(bytes.fromhex(packet_data)) + 16


def test_ifac_unmask_packet(sut, reference):
    """IFAC unmasking recovers original packet and validates tag."""
    ifac_origin = ("meshnet" + "hunter2").encode("utf-8").hex()
    key = reference.execute("ifac_derive_key", ifac_origin=ifac_origin)["ifac_key"]
    packet_data = random_packet_hex(64)
    # Mask with reference
    masked = reference.execute("ifac_mask_packet", ifac_key=key, packet_data=packet_data)
    # Unmask with both — should recover original
    ref = reference.execute(
        "ifac_unmask_packet", ifac_key=key, masked_packet=masked["masked_packet"]
    )
    res = sut.execute(
        "ifac_unmask_packet", ifac_key=key, masked_packet=masked["masked_packet"]
    )
    assert ref["valid"] is True
    assert res["valid"] is True
    assert_hex_equal(ref["packet_data"], packet_data)
    assert_hex_equal(res["packet_data"], packet_data)


def test_ifac_cross_mask_unmask(sut, reference):
    """SUT-masked packets can be unmasked by reference, and vice versa."""
    ifac_origin = ("crosstest" + "key456").encode("utf-8").hex()
    key = reference.execute("ifac_derive_key", ifac_origin=ifac_origin)["ifac_key"]
    packet_data = random_packet_hex(48)
    # SUT masks -> reference unmasks
    sut_masked = sut.execute("ifac_mask_packet", ifac_key=key, packet_data=packet_data)
    ref_unmasked = reference.execute(
        "ifac_unmask_packet", ifac_key=key, masked_packet=sut_masked["masked_packet"]
    )
    assert ref_unmasked["valid"] is True
    assert_hex_equal(ref_unmasked["packet_data"], packet_data)
    # Reference masks -> SUT unmasks
    ref_masked = reference.execute("ifac_mask_packet", ifac_key=key, packet_data=packet_data)
    sut_unmasked = sut.execute(
        "ifac_unmask_packet", ifac_key=key, masked_packet=ref_masked["masked_packet"]
    )
    assert sut_unmasked["valid"] is True
    assert_hex_equal(sut_unmasked["packet_data"], packet_data)


def test_ifac_wrong_key_rejected(sut, reference):
    """Packet masked with one key is rejected when unmasked with a different key."""
    origin_a = ("netA" + "passA").encode("utf-8").hex()
    origin_b = ("netB" + "passB").encode("utf-8").hex()
    key_a = reference.execute("ifac_derive_key", ifac_origin=origin_a)["ifac_key"]
    key_b = reference.execute("ifac_derive_key", ifac_origin=origin_b)["ifac_key"]
    packet_data = random_packet_hex(64)
    # Mask with key_a
    masked = reference.execute("ifac_mask_packet", ifac_key=key_a, packet_data=packet_data)
    # Unmask with key_b — should fail
    ref = reference.execute(
        "ifac_unmask_packet", ifac_key=key_b, masked_packet=masked["masked_packet"]
    )
    res = sut.execute(
        "ifac_unmask_packet", ifac_key=key_b, masked_packet=masked["masked_packet"]
    )
    assert ref["valid"] is False
    assert res["valid"] is False


def test_ifac_mask_small_ifac_size(sut, reference):
    """IFAC masking works with 8-byte IFAC (radio interfaces)."""
    ifac_origin = ("rnode" + "radiokey").encode("utf-8").hex()
    key = reference.execute("ifac_derive_key", ifac_origin=ifac_origin)["ifac_key"]
    packet_data = random_packet_hex(32)
    ref = reference.execute(
        "ifac_mask_packet", ifac_key=key, packet_data=packet_data, ifac_size=8
    )
    res = sut.execute(
        "ifac_mask_packet", ifac_key=key, packet_data=packet_data, ifac_size=8
    )
    assert_hex_equal(res["masked_packet"], ref["masked_packet"])
    # Packet should be 8 bytes longer
    assert len(bytes.fromhex(ref["masked_packet"])) == len(bytes.fromhex(packet_data)) + 8
    # Unmask with both
    ref_u = reference.execute(
        "ifac_unmask_packet", ifac_key=key, masked_packet=ref["masked_packet"], ifac_size=8
    )
    res_u = sut.execute(
        "ifac_unmask_packet", ifac_key=key, masked_packet=ref["masked_packet"], ifac_size=8
    )
    assert ref_u["valid"] is True
    assert res_u["valid"] is True
    assert_hex_equal(ref_u["packet_data"], packet_data)
    assert_hex_equal(res_u["packet_data"], packet_data)
