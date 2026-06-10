"""Link-establishment internals conformance (RNS.Link).

These cases pin the parts of the link layer that the ordinary establish-a-link
harness never exercises directly, each anchored on an EXTERNAL spec literal or
an independent re-derivation — never impl-vs-itself:

  * the unencrypted LINKREQUEST payload layout (pub(32)||sigpub(32)||
    signalling(3)) and the fresh-ephemeral-key-per-request property
    (Link.__init__, Link.py:240-316);
  * the signalling-byte packing (mtu in the low 21 bits, mode in the top 3 bits)
    and its rejection of any non-enabled link mode (Link.signalling_bytes,
    Link.py:148-151);
  * the LINKREQUEST size gate — only a 64-byte (ECPUBSIZE) or 67-byte
    (ECPUBSIZE+LINK_MTU_SIZE) payload creates an inbound link, and a reserved
    link mode is rejected by the handshake (Link.validate_request, Link.py:185-209);
  * the negotiated inbound establishment_timeout formula
    (ESTABLISHMENT_TIMEOUT_PER_HOP*max(1,hops)+KEEPALIVE, Link.py:207);
  * the destination link-accept gate (Destination.receive only answers a
    LINKREQUEST when accept_link_requests is set, Destination.py:420-423);
  * forward-secret ephemeral-key purge on close (link_closed nulls
    prv/pub/shared_key/derived_key, Link.py:728-733);
  * a CLOSED link dropping all traffic and the interface-binding check on
    link.receive (Link.py:974-975).

Runs reference-vs-reference; no SUT binary required. Self-contained injectors
build every artifact from real RNS (a genuine initiator's request_data, a real
LINKREQUEST packed by RNS.Packet, the static Link.signalling_bytes), so the
accept/reject branches are pinned against a working positive control.
"""

import struct

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["link-hooks"]

# Spec literals (RNS.Link).
_ECPUBSIZE = 64          # X25519 pub (32) + Ed25519 sig pub (32)
_LINK_MTU_SIZE = 3       # signalling field width
_MODE_AES256_CBC = 0x01  # the only ENABLED mode / MODE_DEFAULT
_MTU_BYTEMASK = 0x1FFFFF
_MODE_BYTEMASK = 0xE0
_ESTABLISHMENT_TIMEOUT_PER_HOP = 6   # == Reticulum.DEFAULT_PER_HOP_TIMEOUT
_KEEPALIVE = 360                     # == Link.KEEPALIVE (KEEPALIVE_MAX)
_RETICULUM_MTU = 500


def _spec_signalling(mtu: int, mode: int) -> bytes:
    """Independent re-derivation of Link.signalling_bytes (Link.py:148-151):
    a 3-byte big-endian field, mtu in the low 21 bits, mode<<5 in the top
    3 bits of the leading byte."""
    value = (mtu & _MTU_BYTEMASK) + (((mode << 5) & _MODE_BYTEMASK) << 16)
    return struct.pack(">I", value)[1:]


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "link_request_payload"],
    verifies=(
        "A link initiator assembles its LINKREQUEST request_data as "
        "pub_bytes(X25519, 32) || sig_pub_bytes(Ed25519, 32) || "
        "signalling_bytes(3) == 67 bytes (ECPUBSIZE=64 + LINK_MTU_SIZE=3), "
        "unencrypted, with the default link mode AES256_CBC (0x01). Two "
        "requests to the same destination carry DISTINCT ephemeral X25519 and "
        "Ed25519 public keys (fresh keypair per request — forward secrecy)."
    ),
)
def test_link_request_payload_layout_and_fresh_keys(wire_pair_started):
    _server, client = wire_pair_started

    p = client.link_request_payload(_APP, _ASPECTS)

    # Layout: the field widths and the concatenation order are the external
    # spec; the individual fields are read off the live Link independently of
    # request_data, so the equality below pins the ORDER, not the bridge's copy.
    assert p["ecpubsize"] == _ECPUBSIZE, p
    assert p["link_mtu_size"] == _LINK_MTU_SIZE, p
    assert p["len"] == _ECPUBSIZE + _LINK_MTU_SIZE == 67, p
    pub = bytes.fromhex(p["pub_bytes"])
    sigpub = bytes.fromhex(p["sig_pub_bytes"])
    signalling = bytes.fromhex(p["signalling_bytes"])
    assert len(pub) == 32, p
    assert len(sigpub) == 32, p
    assert len(signalling) == _LINK_MTU_SIZE, p
    assert bytes.fromhex(p["request_data_hex"]) == pub + sigpub + signalling, p
    assert pub != sigpub, "X25519 and Ed25519 public keys must differ"
    assert p["mode"] == _MODE_AES256_CBC, p

    # The signalling tail must encode the link mode and the (no-path baseline)
    # Reticulum.MTU, independently re-derived.
    assert signalling == _spec_signalling(p["mtu"], p["mode"]), p
    assert p["mtu"] == _RETICULUM_MTU, p

    # Fresh ephemeral keys per request.
    p2 = client.link_request_payload(_APP, _ASPECTS)
    assert p2["pub_bytes"] != p["pub_bytes"], (
        "X25519 ephemeral key reused across two link requests"
    )
    assert p2["sig_pub_bytes"] != p["sig_pub_bytes"], (
        "Ed25519 signing key reused across two link requests"
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "link_signalling_bytes"],
    verifies=(
        "Link.signalling_bytes packs the link MTU into the low 21 bits and the "
        "link mode into the top 3 bits of a 3-byte big-endian field, and RAISES "
        "for any mode not in ENABLED_MODES (AES128_CBC=0x00 and the reserved "
        "modes 0x03-0x07 are all rejected; only AES256_CBC=0x01 is encodable)."
    ),
)
def test_signalling_bytes_encoding_and_mode_rejection(wire_pair_started):
    _server, client = wire_pair_started

    # Positive: the enabled mode encodes byte-for-byte to the independent
    # re-derivation, across a spread of MTUs spanning the 21-bit field.
    for mtu in (250, 500, 1500, 0x1FFFFF):
        res = client.link_signalling_bytes(mtu, _MODE_AES256_CBC)
        assert res["raised"] is False, res
        sig = bytes.fromhex(res["signalling_bytes"])
        assert sig == _spec_signalling(mtu, _MODE_AES256_CBC), (mtu, res)
        # Decode it back: mode in the top 3 bits, mtu in the low 21 bits.
        decoded_mode = sig[0] >> 5
        decoded_mtu = ((sig[0] << 16) + (sig[1] << 8) + sig[2]) & _MTU_BYTEMASK
        assert decoded_mode == _MODE_AES256_CBC, (mtu, res)
        assert decoded_mtu == (mtu & _MTU_BYTEMASK), (mtu, res)
        assert res["mtu_bytemask"] == _MTU_BYTEMASK, res
        assert res["mode_bytemask"] == _MODE_BYTEMASK, res

    # Negative: a non-enabled mode (AES128_CBC=0) and a reserved mode (3) both
    # make signalling_bytes raise.
    for bad_mode in (0x00, 0x03, 0x07):
        res = client.link_signalling_bytes(500, bad_mode)
        assert res["raised"] is True, (bad_mode, res)
        assert res["signalling_bytes"] is None, (bad_mode, res)
    # The only enabled mode is the default.
    assert client.link_signalling_bytes(500, _MODE_AES256_CBC)["enabled_modes"] == [
        _MODE_AES256_CBC
    ]


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "inject_crafted_link_request",
    ],
    verifies=(
        "Link.validate_request creates an inbound link ONLY for a 64-byte "
        "(ECPUBSIZE) or 67-byte (ECPUBSIZE+LINK_MTU_SIZE) LINKREQUEST payload; "
        "63/66/0-byte payloads are silently dropped. A 67-byte payload whose "
        "signalling mode byte names a reserved (non-enabled) link mode is "
        "rejected by the handshake mode gate, so no inbound link is created — "
        "while a valid 64/67-byte enabled-mode payload is the positive control."
    ),
)
def test_link_request_size_and_mode_validation(wire_pair_started):
    _server, client = wire_pair_started

    # Positive controls: the two accepted payload sizes.
    for variant in ("valid64", "valid67"):
        res = client.inject_crafted_link_request(variant)
        assert res["accepted"] is True, (variant, res)
        assert res["inbound_link_created"] is True, (variant, res)
    assert client.inject_crafted_link_request("valid64")["data_len"] == _ECPUBSIZE
    assert client.inject_crafted_link_request("valid67")["data_len"] == (
        _ECPUBSIZE + _LINK_MTU_SIZE
    )

    # Negatives: every off-size payload is dropped.
    for variant, expect_len in (("size_63", 63), ("size_66", 66), ("size_0", 0)):
        res = client.inject_crafted_link_request(variant)
        assert res["data_len"] == expect_len, (variant, res)
        assert res["accepted"] is False, (variant, res)
        assert res["inbound_link_created"] is False, (variant, res)

    # Mode rejection: a 67-byte payload carrying a reserved mode is rejected
    # even though its size is valid.
    bad = client.inject_crafted_link_request("bad_mode")
    assert bad["data_len"] == _ECPUBSIZE + _LINK_MTU_SIZE, bad
    assert bad["accepted"] is False, bad
    assert bad["inbound_link_created"] is False, bad


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "inject_crafted_link_request",
    ],
    verifies=(
        "An accepted inbound link's establishment_timeout is "
        "ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops) + KEEPALIVE, with "
        "ESTABLISHMENT_TIMEOUT_PER_HOP == 6 (Reticulum.DEFAULT_PER_HOP_TIMEOUT) "
        "and KEEPALIVE == 360 (Link.py:207)."
    ),
)
def test_inbound_establishment_timeout_formula(wire_pair_started):
    _server, client = wire_pair_started

    for hops in (0, 1, 3, 7):
        res = client.inject_crafted_link_request("valid67", hops=hops)
        assert res["accepted"] is True, (hops, res)
        assert res["establishment_timeout_per_hop"] == _ESTABLISHMENT_TIMEOUT_PER_HOP
        assert res["keepalive"] == _KEEPALIVE, res
        expected = _ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops) + _KEEPALIVE
        assert res["establishment_timeout"] == expected, (hops, res)


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "link_accept_gate"],
    verifies=(
        "A destination only answers a LINKREQUEST when its accept_link_requests "
        "gate is set: with the gate OFF, Destination.receive creates no inbound "
        "link (validate_request is never reached); with it ON, exactly one "
        "inbound link is created (Destination.py:420-423)."
    ),
)
def test_destination_accept_gate(wire_pair_started):
    _server, client = wire_pair_started

    off = client.link_accept_gate(False)
    assert off["link_created"] is False, off
    assert off["links_after"] == off["links_before"] == 0, off

    on = client.link_accept_gate(True)
    assert on["link_created"] is True, on
    assert on["links_before"] == 0 and on["links_after"] == 1, on


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_key_material", "link_teardown",
    ],
    verifies=(
        "An ACTIVE link holds all four ephemeral-key fields (X25519 prv/pub, the "
        "ECDH shared_key, and the HKDF-derived derived_key); after Link.teardown "
        "the link_closed() purge nulls all four (Link.py:728-733), pinning "
        "forward-secret key purge on close with no persistence."
    ),
)
def test_ephemeral_key_purge_on_close(wire_link_setup):
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    before = client.link_key_material(link_id)
    assert before["status_name"] == "ACTIVE", before
    assert before["prv_present"] is True, before
    assert before["pub_present"] is True, before
    assert before["shared_key_present"] is True, before
    assert before["derived_key_present"] is True, before

    client.link_teardown(link_id)

    after = client.link_key_material(link_id)
    assert after["status_name"] == "CLOSED", after
    assert after["prv_present"] is False, after
    assert after["pub_present"] is False, after
    assert after["shared_key_present"] is False, after
    assert after["derived_key_present"] is False, after


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "inject_tampered_link_data", "inject_closed_link_data",
    ],
    verifies=(
        "A CLOSED link drops all link-associated traffic: a DATA packet that is "
        "delivered to the receiver's handler while the link is ACTIVE (positive "
        "control) is NOT delivered when the SAME pristine packet is replayed "
        "after Link.teardown — Link.receive returns immediately once "
        "status == CLOSED (Link.py:974)."
    ),
)
def test_closed_link_ignores_traffic(wire_link_setup):
    server, _client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Positive control: a pristine DATA packet IS delivered while ACTIVE.
    live = server.inject_tampered_link_data(link_id, b"open-link-data", "none")
    assert live["delivered"] is True, live

    # Now close the link and replay a pristine packet built pre-close.
    closed = server.inject_closed_link_data(link_id)
    assert closed["link_closed"] is True, closed
    assert closed["delivered"] is False, closed


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "inject_tampered_link_data",
    ],
    verifies=(
        "Link.receive enforces interface binding: a pristine DATA packet "
        "presented on the link's attached_interface is delivered (positive "
        "control), but the SAME packet presented on a different interface is "
        "rejected before decrypt and not delivered, while the link stays ACTIVE "
        "(Link.py:975)."
    ),
)
def test_link_interface_binding(wire_link_setup):
    server, _client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    ok = server.inject_tampered_link_data(link_id, b"bound-iface", "none")
    assert ok["delivered"] is True, ok

    foreign = server.inject_tampered_link_data(
        link_id, b"foreign-iface", "foreign_interface"
    )
    assert foreign["delivered"] is False, foreign
    assert foreign["link_active"] is True, foreign
