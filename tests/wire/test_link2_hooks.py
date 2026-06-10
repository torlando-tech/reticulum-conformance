"""Second-wave Link conformance hooks (hook-family "link2").

These exercise four deferred Link-layer gaps that the first wire pass reached
but could not pin without an extra observable:

  * request-timeout-default  — the RequestReceipt default timeout formula
    (rtt*6 + 11.25) when Link.request is called without an explicit timeout.
  * response-wire-encoding   — the raw RESPONSE packet (context 0x0A) carrying
    msgpack [request_id, response], and the >MDU fork to a response Resource.
  * mtu-discovery-config     — link MTU discovery (default ON) signals the
    next-hop interface HW MTU, so the negotiated link MTU equals it (and is
    elevated above the 500-byte baseline).
  * link-packet-mtu-bound    — a single link DATA packet is bounded by the
    NEGOTIATED link MTU, not the global Reticulum.MTU (500).

Every assertion anchors on an RNS 1.3.1 spec literal pinned below or on an
independent derivation from a value the link itself reports — never on the
bridge's own copy of any logic. The wire harness deliberately does not import
RNS; msgpack decoding of captured plaintext uses the generic umsgpack codec
(an external standard), and the response wire layout [request_id, response] is
the RNS spec literal under test.
"""

import secrets

import umsgpack

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["link2"]
_PATH = "/echo"
_LINK_TIMEOUT_MS = 15000
_PATH_POLL_TIMEOUT_MS = 10000

# ---- RNS 1.3.1 spec literals (read from RNS source, pinned as known-answers) ----
# Link.TRAFFIC_TIMEOUT_FACTOR == 6; Resource.RESPONSE_MAX_GRACE_TIME == 10.
# Link.request default timeout (Link.py:493-494):
#   timeout = rtt * 6 + 10 * 1.125  ==  rtt*6 + 11.25
_TRAFFIC_TIMEOUT_FACTOR = 6
_RESPONSE_GRACE = 10 * 1.125  # == 11.25

# Packet context bytes (Packet.py:74/:82).
_CTX_RESOURCE_ADV = 0x02
_CTX_RESPONSE = 0x0A

# Reticulum.MTU baseline (Reticulum.py).
_RETICULUM_MTU = 500
# TCP interface BITRATE_GUESS is 10 Mbps (TCPInterface.py:76). With
# AUTOCONFIGURE_MTU, Interface.optimise_mtu (Interface.py:198-221) maps the
# bitrate to a hardware MTU: 10_000_000 is NOT > 10_000_000 but IS > 5_000_000,
# so it lands in the 8192 branch. The class-level TCPInterface.HW_MTU constant
# (262144) is the pre-autoconfigure ceiling, not the live value.
_TCP_HW_MTU = 8192

# RNS.Reticulum.TRUNCATED_HASHLENGTH == 128 bits -> request_id is 16 bytes.
_TRUNC_HASH_BYTES = 16

# A small fixed MTU keeps the negotiated link MDU small (~431 B) so a modest
# response crosses it and RNS must fork to a Resource.
_FIXED_MTU = 500
_LARGE_RESPONSE_LEN = 50000  # >> MDU -> response Resource (RESOURCE_ADV, no RESPONSE)


def _establish(server, client, *, fixed_mtu=None):
    """Bring up a direct TCP server/client pair and open one link from the
    client (initiator) to the server's listening destination. Returns
    (server_dest, link_id)."""
    port = server.start_tcp_server(network_name="", passphrase="", fixed_mtu=fixed_mtu)
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port, fixed_mtu=fixed_mtu,
    )
    server_dest = server.listen(app_name=_APP, aspects=_ASPECTS)
    assert client.poll_path(server_dest, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — the link could not be opened."
    )
    link_id = client.link_open(
        server_dest, app_name=_APP, aspects=_ASPECTS, timeout_ms=_LINK_TIMEOUT_MS,
    )
    return server_dest, link_id


# ---------------------------------------------------------------------------
# request-timeout-default
# ---------------------------------------------------------------------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_request_timeout",
    ],
    verifies="RequestReceipt default timeout (Link.py:493-494): when Link.request is called with no explicit timeout, RNS derives it as rtt*TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME*1.125 == rtt*6 + 11.25. The receipt.timeout equals this independent derivation from the link's own reported rtt; passing an explicit timeout bypasses the formula and is used verbatim.",
)
def test_request_default_timeout_follows_rtt_formula(wire_peers):
    server, client = wire_peers
    _server_dest, link_id = _establish(server, client)

    # Default (no explicit timeout) -> RNS computes the formula timeout.
    res = client.link_request_timeout(link_id, _PATH)
    rtt = res["rtt"]
    assert rtt is not None and rtt > 0, (
        f"link reported no usable rtt ({rtt!r}); the default-timeout formula "
        f"derives from it."
    )
    expected = rtt * _TRAFFIC_TIMEOUT_FACTOR + _RESPONSE_GRACE
    assert abs(res["receipt_timeout"] - expected) < 1e-6, (
        f"RequestReceipt default timeout {res['receipt_timeout']!r} != "
        f"rtt*6 + 11.25 = {expected!r} (rtt={rtt!r}). The formula is "
        f"Link.py:493-494."
    )

    # Negative control: an explicit timeout is used verbatim, NOT the formula.
    explicit_ms = 3000
    res2 = client.link_request_timeout(link_id, _PATH, timeout_ms=explicit_ms)
    assert abs(res2["receipt_timeout"] - 3.0) < 1e-9, (
        f"explicit timeout was not honored verbatim: got "
        f"{res2['receipt_timeout']!r}, expected 3.0s."
    )
    formula_now = res2["rtt"] * _TRAFFIC_TIMEOUT_FACTOR + _RESPONSE_GRACE
    assert abs(res2["receipt_timeout"] - formula_now) > 1.0, (
        f"explicit timeout {res2['receipt_timeout']!r} coincided with the "
        f"formula value {formula_now!r}; the explicit-override path is not "
        f"distinguishable. Choose an explicit timeout far from the formula."
    )


# ---------------------------------------------------------------------------
# response-wire-encoding
# ---------------------------------------------------------------------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "capture_response_packet",
    ],
    verifies="Link response wire encoding (Link.py:897-899): a handler response that fits the link MDU is delivered as a single RESPONSE packet (context 0x0A) whose decrypted plaintext is msgpack [request_id, response]. The captured request_id is a 16-byte truncated hash and the response element is byte-exact what the handler returned.",
)
def test_response_packet_context_and_msgpack_layout(wire_peers):
    server, client = wire_peers
    server_dest, link_id = _establish(server, client)

    response_payload = secrets.token_bytes(64)
    server.register_request_handler(server_dest, _PATH, response_payload)

    request_data = secrets.token_bytes(16)
    cap = client.capture_response_packet(link_id, _PATH, data=request_data)
    assert cap["status"] == "ready", (
        f"link.request did not conclude READY: status={cap['status']!r}"
    )
    assert bytes.fromhex(cap["response"]) == response_payload, (
        "the response RNS delivered did not match the handler's return bytes."
    )

    responses = [e for e in cap["captured"] if e["context"] == _CTX_RESPONSE]
    assert len(responses) == 1, (
        f"expected exactly one RESPONSE (context 0x0A) packet for a sub-MDU "
        f"response, captured={cap['captured']!r}"
    )
    entry = responses[0]
    assert entry["plaintext"] is not None, "RESPONSE packet plaintext was not captured"
    unpacked = umsgpack.unpackb(bytes.fromhex(entry["plaintext"]))
    assert isinstance(unpacked, list) and len(unpacked) == 2, (
        f"RESPONSE plaintext is not msgpack [request_id, response]: {unpacked!r}"
    )
    request_id, response_field = unpacked[0], unpacked[1]
    assert isinstance(request_id, (bytes, bytearray)) and len(request_id) == _TRUNC_HASH_BYTES, (
        f"request_id element is not a {_TRUNC_HASH_BYTES}-byte truncated hash: "
        f"{request_id!r}"
    )
    assert bytes(response_field) == response_payload, (
        "the msgpack response element did not match the handler's return bytes."
    )
    # No fork to a Resource for a sub-MDU response.
    assert not any(e["context"] == _CTX_RESOURCE_ADV for e in cap["captured"]), (
        "a sub-MDU response should NOT fork to a Resource (no RESOURCE_ADV)."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "capture_response_packet",
    ],
    verifies="Link response >MDU fork (Link.py:901): a handler response larger than the negotiated link MDU is NOT sent as a single RESPONSE packet — RNS forks it into a response Resource, observable on the initiator as a RESOURCE_ADV (context 0x02) with no RESPONSE (0x0A) packet, while the response still round-trips byte-exact.",
)
def test_large_response_forks_to_resource_not_response_packet(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        _APP, _ASPECTS, fixed_mtu=_FIXED_MTU,
    )

    response_payload = secrets.token_bytes(_LARGE_RESPONSE_LEN)
    server.register_request_handler(dest_hash, _PATH, response_payload)

    cap = client.capture_response_packet(
        link_id, _PATH, data=secrets.token_bytes(8), timeout_ms=45000,
    )
    assert cap["status"] == "ready", (
        f"a >MDU response did not conclude READY: status={cap['status']!r}"
    )
    assert bytes.fromhex(cap["response"]) == response_payload, (
        "the ~50 KB resource-backed response did not round-trip byte-exact."
    )
    assert not any(e["context"] == _CTX_RESPONSE for e in cap["captured"]), (
        f"a >MDU response must NOT arrive as a single RESPONSE (0x0A) packet; "
        f"captured={[e['context'] for e in cap['captured']]!r}"
    )
    assert any(e["context"] == _CTX_RESOURCE_ADV for e in cap["captured"]), (
        f"a >MDU response must fork to a Resource (RESOURCE_ADV 0x02); "
        f"captured contexts={[e['context'] for e in cap['captured']]!r}"
    )


# ---------------------------------------------------------------------------
# mtu-discovery-config
# ---------------------------------------------------------------------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "interface_hw_mtu", "link_mtu",
    ],
    verifies="Link MTU discovery (Link.py:309-314, Reticulum.LINK_MTU_DISCOVERY default True): with discovery ON the initiator signals its next-hop interface HW MTU (autoconfigured to 8192 from the 10 Mbps TCP bitrate per Interface.optimise_mtu) and the negotiated link MTU settles on exactly that value — elevated above the 500-byte Reticulum.MTU baseline used when discovery is off.",
)
def test_discovery_on_negotiates_link_mtu_to_hw_mtu(wire_peers):
    server, client = wire_peers
    _server_dest, link_id = _establish(server, client)

    cfg = client.interface_hw_mtu()
    assert cfg["link_mtu_discovery"] is True, (
        "link_mtu_discovery should default ON (Reticulum.LINK_MTU_DISCOVERY=True)"
    )
    assert cfg["reticulum_mtu"] == _RETICULUM_MTU, (
        f"Reticulum.MTU baseline expected {_RETICULUM_MTU}, got {cfg['reticulum_mtu']!r}"
    )
    assert cfg["hw_mtu"] == _TCP_HW_MTU, (
        f"autoconfigured TCP interface HW MTU expected {_TCP_HW_MTU} (10 Mbps -> "
        f"8192 branch of Interface.optimise_mtu), got {cfg['hw_mtu']!r}"
    )
    assert cfg["autoconfigure_mtu"] is True and cfg["fixed_mtu"] is False, (
        f"default TCP interface should autoconfigure MTU (not fixed): {cfg!r}"
    )

    link = client.link_mtu(link_id)
    assert link["mtu"] == cfg["hw_mtu"], (
        f"negotiated link MTU {link['mtu']!r} != signalled next-hop HW MTU "
        f"{cfg['hw_mtu']!r} — discovery should settle the link MTU on the HW MTU."
    )
    # Negative: discovery elevated the link MTU above the 500-byte OFF baseline.
    assert link["mtu"] > _RETICULUM_MTU, (
        f"with discovery ON the negotiated link MTU ({link['mtu']!r}) must be "
        f"elevated above the {_RETICULUM_MTU}-byte baseline."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "interface_hw_mtu", "link_mtu",
    ],
    verifies="Link MTU discovery tracks a configured fixed_mtu: a fixed-MTU interface reports HW MTU == fixed_mtu (FIXED_MTU True, AUTOCONFIGURE_MTU False), and the negotiated link MTU settles on that fixed value — proving the link MTU is the signalled HW MTU, not a hardcoded constant.",
)
def test_discovery_tracks_fixed_interface_mtu(wire_peers):
    server, client = wire_peers
    fixed = 1500
    _server_dest, link_id = _establish(server, client, fixed_mtu=fixed)

    cfg = client.interface_hw_mtu()
    assert cfg["hw_mtu"] == fixed, (
        f"fixed-MTU interface HW MTU expected {fixed}, got {cfg['hw_mtu']!r}"
    )
    assert cfg["fixed_mtu"] is True and cfg["autoconfigure_mtu"] is False, (
        f"a configured fixed_mtu interface should report FIXED_MTU True / "
        f"AUTOCONFIGURE_MTU False: {cfg!r}"
    )

    link = client.link_mtu(link_id)
    assert link["mtu"] == fixed, (
        f"negotiated link MTU {link['mtu']!r} != configured fixed_mtu {fixed} — "
        f"the link MTU should track the signalled interface HW MTU, not a "
        f"hardcoded {_TCP_HW_MTU}."
    )


# ---------------------------------------------------------------------------
# link-packet-mtu-bound
# ---------------------------------------------------------------------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "send_oversize_link_packet",
    ],
    verifies="A single link DATA packet is MTU-bounded by the NEGOTIATED link MTU, not the global Reticulum.MTU (Packet.py:153-154/:235-236): over a high-MTU link a payload that would blow the 500-byte global MTU still sends, while a payload above the negotiated link MTU is rejected with an IOError citing that link MTU.",
)
def test_link_packet_bounded_by_negotiated_mtu_not_global(wire_peers):
    server, client = wire_peers
    _server_dest, link_id = _establish(server, client)

    # 600 bytes exceeds the 500-byte global MTU but is well under the high
    # negotiated link MTU -> must send (bound is the link MTU, not global).
    ok = client.send_oversize_link_packet(link_id, 600)
    assert ok["sent"] and not ok["rejected"], (
        f"a 600-byte link packet (> global {_RETICULUM_MTU}) was rejected over a "
        f"high-MTU link: {ok!r}. Link packets are bounded by the link MTU."
    )
    link_mtu = ok["mtu"]
    assert ok["packet_mtu"] == link_mtu and link_mtu > _RETICULUM_MTU, (
        f"the link packet's MTU bound ({ok['packet_mtu']!r}) should equal the "
        f"negotiated link MTU ({link_mtu!r}) and exceed the global "
        f"{_RETICULUM_MTU}-byte MTU."
    )

    # A payload above the negotiated link MTU IS rejected, at the link MTU.
    big = client.send_oversize_link_packet(link_id, link_mtu + 5000)
    assert big["rejected"] and not big["sent"], (
        f"a payload above the negotiated link MTU ({link_mtu!r}) should be "
        f"rejected: {big!r}"
    )
    assert big["error"] and str(link_mtu) in big["error"], (
        f"the rejection error should cite the negotiated link MTU {link_mtu!r}: "
        f"{big['error']!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "send_oversize_link_packet",
    ],
    verifies="Over a link negotiated to a small fixed MTU (500), a single link DATA packet whose packed size exceeds that MTU is rejected (Packet.pack IOError) while a sub-MDU payload sends — the SAME 600-byte payload that succeeds over a high-MTU link, proving the bound is the per-link negotiated MTU.",
)
def test_oversize_link_packet_rejected_at_small_fixed_mtu(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(
        _APP, _ASPECTS, fixed_mtu=_FIXED_MTU,
    )

    # A sub-MDU payload sends fine.
    small = client.send_oversize_link_packet(link_id, 100)
    assert small["sent"] and not small["rejected"], (
        f"a 100-byte payload (< link MDU {small.get('mdu')!r}) should send over "
        f"a {_FIXED_MTU}-byte link: {small!r}"
    )
    assert small["mtu"] == _FIXED_MTU, (
        f"link negotiated MTU should be the fixed {_FIXED_MTU}, got {small['mtu']!r}"
    )

    # The same 600-byte payload that succeeds on a high-MTU link is rejected here.
    big = client.send_oversize_link_packet(link_id, 600)
    assert big["rejected"] and not big["sent"], (
        f"a 600-byte payload over a {_FIXED_MTU}-byte link should be rejected: {big!r}"
    )
    assert big["error"] and str(_FIXED_MTU) in big["error"], (
        f"the rejection error should cite the {_FIXED_MTU}-byte link MTU: "
        f"{big['error']!r}"
    )
