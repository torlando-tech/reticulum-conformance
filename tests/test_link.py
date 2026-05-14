"""Link conformance tests.

Tests link key derivation, link encryption/decryption, signalling byte
encoding/parsing, link request/response packing/unpacking, RTT
packing/unpacking, link ID computation, and the link-proof handshake
by comparing SUT output against a reference implementation.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Link"
__category_order__ = 8
__category_description__ = (
    "An RNS Link is an encrypted, authenticated session between two "
    "destinations — established by a handshake (LINKREQUEST → link proof), "
    "then used for ongoing exchange with forward secrecy. These tests cover "
    "the cryptographic and wire-format primitives a link is built from: key "
    "derivation from the ECDH handshake, the AES link cipher, the signalling "
    "bytes that negotiate MTU, the link-request / response / RTT framing, and "
    "the link-proof signature. The full multi-hop establishment handshake is "
    "tested in Wire Interop."
)


@conformance_case(
    commands=["link_derive_key"],
    verifies="RNS link key derivation: HKDF over the ECDH shared secret (`shared_key` as input key material, `link_id` as salt) produces a byte-identical 64-byte derived key",
)
def test_link_derive_key(sut, reference):
    shared_key = random_hex(32)
    link_id = random_hex(32)
    ref = reference.execute(
        "link_derive_key", shared_key=shared_key, link_id=link_id
    )
    res = sut.execute("link_derive_key", shared_key=shared_key, link_id=link_id)
    assert_hex_equal(res["derived_key"], ref["derived_key"])


@conformance_case(
    commands=["link_encrypt", "link_decrypt"],
    verifies="RNS link-layer AES-256-CBC encrypt/decrypt round-trip: with both impls given the same derived key, IV, and plaintext, encryption produces byte-identical ciphertext and decryption recovers the original",
)
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


@conformance_case(
    commands=["link_signalling_bytes"],
    verifies="RNS link signalling-byte encoding for 4 MTU values (500, 1196, 8192, 262144 bytes): the 3-byte signalling field is byte-identical and the round-tripped `decoded_mtu` matches — spans the small-frame to large-frame range",
)
def test_link_signalling_bytes(sut, reference):
    for mtu in [500, 1196, 8192, 262144]:
        ref = reference.execute("link_signalling_bytes", mtu=mtu)
        res = sut.execute("link_signalling_bytes", mtu=mtu)
        assert_hex_equal(res["signalling_bytes"], ref["signalling_bytes"])
        assert res["decoded_mtu"] == ref["decoded_mtu"]


@conformance_case(
    commands=["link_signalling_bytes", "link_parse_signalling"],
    verifies="RNS link signalling-byte decoding: parses the fixed vector `0x2001F4` (mode 1, MTU 500) and round-trips all 4 MTU values from test_link_signalling_bytes — every parsed `mtu` + link `mode` matches the reference",
)
def test_link_parse_signalling(sut, reference):
    # Fixed-vector anchor: 0x2001F4 = mode 1, MTU 500. Hardcoded so the parse
    # path is pinned to a known constant, independent of the encoder.
    fixed = reference.execute("link_parse_signalling", signalling_bytes="2001f4")
    sut_fixed = sut.execute("link_parse_signalling", signalling_bytes="2001f4")
    assert sut_fixed["mtu"] == fixed["mtu"] == 500
    assert sut_fixed["mode"] == fixed["mode"]
    # Round-trip every MTU that test_link_signalling_bytes encodes — parse the
    # reference encoder's output and confirm SUT parses it identically. (The
    # reference encoder is ground truth; test_link_signalling_bytes already
    # pins SUT's encoder to it, so this isolates the parse path.)
    for mtu in [500, 1196, 8192, 262144]:
        sig = reference.execute("link_signalling_bytes", mtu=mtu)["signalling_bytes"]
        ref = reference.execute("link_parse_signalling", signalling_bytes=sig)
        res = sut.execute("link_parse_signalling", signalling_bytes=sig)
        assert res["mtu"] == ref["mtu"]
        assert res["mode"] == ref["mode"]


@conformance_case(
    commands=["link_request_pack", "link_request_unpack"],
    verifies="RNS link-request pack/unpack round-trip: the msgpack array (`timestamp`, `path_hash`, `data`) packs byte-identically and unpacking recovers `timestamp` and `path_hash`",
)
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


@conformance_case(
    commands=["link_response_pack", "link_response_unpack"],
    verifies="RNS link-response pack/unpack round-trip: the msgpack `[request_id, response_data]` array packs byte-identically and unpacking recovers both fields. Pairs with test_link_request_pack_unpack — request and response are the two halves of the link request/response exchange",
)
def test_link_response_pack_unpack(sut, reference):
    request_id = random_hex(16)
    response_data = random_hex(48)
    ref = reference.execute(
        "link_response_pack", request_id=request_id, response_data=response_data
    )
    res = sut.execute(
        "link_response_pack", request_id=request_id, response_data=response_data
    )
    assert_hex_equal(res["packed"], ref["packed"])
    # Unpack
    ref_u = reference.execute("link_response_unpack", packed=ref["packed"])
    res_u = sut.execute("link_response_unpack", packed=ref["packed"])
    assert_hex_equal(res_u["request_id"], ref_u["request_id"])
    assert_hex_equal(res_u["response_data"], ref_u["response_data"])


@conformance_case(
    commands=["link_rtt_pack", "link_rtt_unpack"],
    verifies="RNS link RTT pack/unpack round-trip: the round-trip-time value packs as a msgpack float64 byte-identically and unpacks back to the original",
)
def test_link_rtt_pack_unpack(sut, reference):
    rtt = 0.123
    ref = reference.execute("link_rtt_pack", rtt=rtt)
    res = sut.execute("link_rtt_pack", rtt=rtt)
    assert_hex_equal(res["packed"], ref["packed"])
    # Unpack
    ref_u = reference.execute("link_rtt_unpack", packed=ref["packed"])
    res_u = sut.execute("link_rtt_unpack", packed=ref["packed"])
    assert abs(res_u["rtt"] - ref_u["rtt"]) < 0.001


@conformance_case(
    commands=["packet_pack", "link_id_from_packet"],
    verifies="RNS `link_id` derivation from a LINKREQUEST packet (truncated hash of the packet's hashable part) is byte-identical — this is the identifier both ends of a link must agree on",
)
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


@conformance_case(
    commands=[
        "identity_from_private_key",
        "x25519_generate",
        "ed25519_generate",
        "link_signalling_bytes",
        "link_prove",
        "link_verify_proof",
    ],
    verifies="RNS link proof (LRPROOF) round-trip: the destination signs `link_id + receiver_pub + receiver_sig_pub + signalling_bytes` with its Ed25519 key; the signature is byte-identical across impls and each impl verifies the other's proof — this is the handshake step that lets a link initiator confirm it's talking to the real destination",
)
def test_link_prove_verify(sut, reference):
    # The destination's identity proves the link.
    identity_priv = random_hex(64)
    identity_pub = reference.execute(
        "identity_from_private_key", private_key=identity_priv
    )["public_key"]
    # The initiator's ephemeral X25519 + Ed25519 public keys, the link_id,
    # and the negotiated signalling bytes all go into the signed payload.
    link_id = random_hex(16)
    receiver_pub = reference.execute(
        "x25519_generate", seed=random_hex(32)
    )["public_key"]
    receiver_sig_pub = reference.execute(
        "ed25519_generate", seed=random_hex(32)
    )["public_key"]
    signalling = reference.execute(
        "link_signalling_bytes", mtu=500
    )["signalling_bytes"]
    # Sign on both impls — the Ed25519 proof signature must be byte-identical.
    ref_proof = reference.execute(
        "link_prove",
        identity_private=identity_priv,
        link_id=link_id,
        receiver_pub=receiver_pub,
        receiver_sig_pub=receiver_sig_pub,
        signalling_bytes=signalling,
    )
    res_proof = sut.execute(
        "link_prove",
        identity_private=identity_priv,
        link_id=link_id,
        receiver_pub=receiver_pub,
        receiver_sig_pub=receiver_sig_pub,
        signalling_bytes=signalling,
    )
    assert_hex_equal(res_proof["signature"], ref_proof["signature"])
    # Cross-impl verify: each impl accepts the other's proof.
    ref_v = reference.execute(
        "link_verify_proof",
        identity_public=identity_pub,
        link_id=link_id,
        receiver_pub=receiver_pub,
        receiver_sig_pub=receiver_sig_pub,
        signalling_bytes=signalling,
        signature=res_proof["signature"],
    )
    res_v = sut.execute(
        "link_verify_proof",
        identity_public=identity_pub,
        link_id=link_id,
        receiver_pub=receiver_pub,
        receiver_sig_pub=receiver_sig_pub,
        signalling_bytes=signalling,
        signature=ref_proof["signature"],
    )
    assert ref_v["valid"] is True
    assert res_v["valid"] is True


@conformance_case(
    commands=[
        "identity_from_private_key",
        "x25519_generate",
        "ed25519_generate",
        "link_verify_proof",
    ],
    verifies="Negative control: both impls reject a link proof carrying a forged (random) Ed25519 signature — `link_verify_proof` returns false. Confirms the link handshake can't be spoofed by an attacker who doesn't hold the destination's signing key",
)
def test_link_prove_verify_bad_sig(sut, reference):
    identity_priv = random_hex(64)
    identity_pub = reference.execute(
        "identity_from_private_key", private_key=identity_priv
    )["public_key"]
    link_id = random_hex(16)
    receiver_pub = reference.execute(
        "x25519_generate", seed=random_hex(32)
    )["public_key"]
    receiver_sig_pub = reference.execute(
        "ed25519_generate", seed=random_hex(32)
    )["public_key"]
    # 64 random bytes that were never produced by Ed25519 signing.
    bad_sig = random_hex(64)
    ref_v = reference.execute(
        "link_verify_proof",
        identity_public=identity_pub,
        link_id=link_id,
        receiver_pub=receiver_pub,
        receiver_sig_pub=receiver_sig_pub,
        signature=bad_sig,
    )
    res_v = sut.execute(
        "link_verify_proof",
        identity_public=identity_pub,
        link_id=link_id,
        receiver_pub=receiver_pub,
        receiver_sig_pub=receiver_sig_pub,
        signature=bad_sig,
    )
    assert ref_v["valid"] is False
    assert res_v["valid"] is False
