"""Link conformance tests.

Tests link key derivation, link encryption/decryption, signalling byte
encoding/parsing, link request packing/unpacking, RTT packing/unpacking,
and link ID computation by comparing SUT output against a reference
implementation.
"""

from conftest import random_hex, assert_hex_equal


def test_link_derive_key(sut, reference):
    shared_key = random_hex(32)
    link_id = random_hex(32)
    ref = reference.execute(
        "link_derive_key", shared_key=shared_key, link_id=link_id
    )
    res = sut.execute("link_derive_key", shared_key=shared_key, link_id=link_id)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


def test_link_encrypt_decrypt(sut, reference):
    derived_key = random_hex(64)
    plaintext = random_hex(32)
    iv = random_hex(16)
    ref = reference.execute(
        "link_encrypt", derived_key=derived_key, plaintext=plaintext, iv=iv
    )
    res = sut.execute(
        "link_encrypt", derived_key=derived_key, plaintext=plaintext, iv=iv
    )
    assert_hex_equal(res["ciphertext"], ref["ciphertext"])
    # Decrypt
    ref_dec = reference.execute(
        "link_decrypt", derived_key=derived_key, ciphertext=ref["ciphertext"]
    )
    res_dec = sut.execute(
        "link_decrypt", derived_key=derived_key, ciphertext=ref["ciphertext"]
    )
    assert_hex_equal(res_dec["plaintext"], ref_dec["plaintext"])
    assert_hex_equal(res_dec["plaintext"], plaintext)


def test_link_signalling_bytes(sut, reference):
    for mtu in [500, 1196, 8192, 262144]:
        ref = reference.execute("link_signalling_bytes", mtu=mtu)
        res = sut.execute("link_signalling_bytes", mtu=mtu)
        assert_hex_equal(res["signalling_bytes"], ref["signalling_bytes"])
        assert res["decoded_mtu"] == ref["decoded_mtu"]


def test_link_parse_signalling(sut, reference):
    sig = "2001f4"  # Mode 1, MTU 500
    ref = reference.execute("link_parse_signalling", signalling_bytes=sig)
    res = sut.execute("link_parse_signalling", signalling_bytes=sig)
    assert res["mtu"] == ref["mtu"]
    assert res["mode"] == ref["mode"]


def test_link_request_pack_unpack(sut, reference):
    timestamp = 1700000000.0
    path_hash = random_hex(16)
    data = random_hex(32)
    ref = reference.execute(
        "link_request_pack", timestamp=timestamp, path_hash=path_hash, data=data
    )
    res = sut.execute(
        "link_request_pack", timestamp=timestamp, path_hash=path_hash, data=data
    )
    assert_hex_equal(res["packed"], ref["packed"])
    # Unpack
    ref_u = reference.execute("link_request_unpack", packed=ref["packed"])
    res_u = sut.execute("link_request_unpack", packed=ref["packed"])
    assert abs(res_u["timestamp"] - ref_u["timestamp"]) < 0.001
    assert_hex_equal(res_u["path_hash"], ref_u["path_hash"])


def test_link_rtt_pack_unpack(sut, reference):
    rtt = 0.123
    ref = reference.execute("link_rtt_pack", rtt=rtt)
    res = sut.execute("link_rtt_pack", rtt=rtt)
    assert_hex_equal(res["packed"], ref["packed"])
    # Unpack
    ref_u = reference.execute("link_rtt_unpack", packed=ref["packed"])
    res_u = sut.execute("link_rtt_unpack", packed=ref["packed"])
    assert abs(res_u["rtt"] - ref_u["rtt"]) < 0.001


def test_link_id_from_packet(sut, reference):
    dest = random_hex(16)
    pub = random_hex(64)
    sig_bytes = "2001f4"
    # Link request data = public_key + signalling_bytes (raw concatenation)
    link_req_data = pub + sig_bytes
    ref_pkt = reference.execute(
        "packet_pack",
        header_type=0,
        context_flag=0,
        transport_type=0,
        destination_type=3,
        packet_type=2,
        hops=0,
        destination_hash=dest,
        context=0,
        data=link_req_data,
    )
    ref = reference.execute("link_id_from_packet", raw=ref_pkt["raw"])
    res = sut.execute("link_id_from_packet", raw=ref_pkt["raw"])
    assert_hex_equal(res["link_id"], ref["link_id"])
