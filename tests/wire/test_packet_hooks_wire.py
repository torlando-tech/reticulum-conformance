"""Single-packet PROOF wire-shape conformance (Opus, gap-closing).

When a receiver under PROVE_ALL answers a tracked SINGLE-destination DATA packet,
RNS emits a PROOF packet whose wire shape is fixed (Packet.py: prove ->
Identity.prove -> ProofDestination): packet_type PROOF, context NONE, HEADER_1,
hops 0 at the first hop, SINGLE destination-type bits, and a destination_hash
equal to the truncated hash of the proved packet (ProofDestination.hash =
proved_packet.get_hash()[:TRUNCATED_HASHLENGTH//8], Packet.py:336-339).

The reference proof-acceptance path matches a returning proof on packet
type + receipt hash only, so the proof packet's flag-byte shape and its
truncated-hash addressing were never observed. The send_packet_with_proof_request
hook now captures the RAW emitted proof frame (proof_raw) plus the proved
packet's full hash (proved_packet_hash); this test unpacks the frame and pins
every flag-byte field against the spec, independently of how the receipt matched.

Runs reference-vs-reference over loopback TCP; the proof can only come from the
real receiver on the other peer.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["proof-wire-shape"]

# RNS wire constants (external ground truth, restated — not read from the impl).
_HEADER_1 = 0                 # RNS.Packet.HEADER_1
_PROOF = 0x03                 # RNS.Packet.PROOF packet-type bits
_CONTEXT_NONE = 0x00          # RNS.Packet.NONE
_DEST_SINGLE = 0x00           # RNS.Destination.SINGLE destination-type bits
_TRUNCATED_HASHLEN = 16       # RNS.Reticulum.TRUNCATED_HASHLENGTH // 8


def _decode_header1(raw: bytes) -> dict:
    """Decode an RNS HEADER_1 frame's fixed fields straight off the wire bytes
    (mirrors RNS.Packet.unpack's bit layout, Packet.py:243-266).

    Done in the TEST (not the bridge) so the assertion anchors on the spec's
    documented bit positions rather than on a field RNS itself re-derived.
    """
    flags = raw[0]
    return {
        "header_type": (flags & 0b01000000) >> 6,
        "transport_type": (flags & 0b00010000) >> 4,
        "destination_type": (flags & 0b00001100) >> 2,
        "packet_type": (flags & 0b00000011),
        "hops": raw[1],
        "destination_hash": raw[2:2 + _TRUNCATED_HASHLEN],
        "context": raw[2 + _TRUNCATED_HASHLEN],
    }


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "set_proof_strategy", "send_packet_with_proof_request",
    ],
    verifies=(
        "A genuine single-packet PROOF emitted by a PROVE_ALL receiver has the "
        "RNS-mandated wire shape: HEADER_1, packet-type PROOF (0x03), context "
        "NONE (0x00), hops 0 at the first hop, and SINGLE destination-type bits — "
        "and it is addressed to the TRUNCATED hash of the proved packet "
        "(destination_hash == proved_packet.get_hash()[:16], ProofDestination, "
        "Packet.py:336-339). Decoding the captured raw proof frame and pinning "
        "each flag-byte field against the spec catches an impl that emits the "
        "proof with the wrong type/context/header or mis-addresses it"
    ),
)
def test_single_packet_proof_wire_shape(wire_link_setup):
    server, client, dest_hash, _link_id = wire_link_setup(_APP, _ASPECTS)

    server.set_proof_strategy(dest_hash, "all")
    res = client.send_packet_with_proof_request(
        dest_hash, data=b"prove-my-shape", app_name=_APP, aspects=list(_ASPECTS),
        timeout_ms=8000,
    )
    assert res["delivered"] is True and res["proved"] is True, (
        f"PROVE_ALL proof was not accepted (no proof to inspect): {res!r}"
    )
    raw = res["proof_raw"]
    assert isinstance(raw, (bytes, bytearray)) and len(raw) >= 2 + _TRUNCATED_HASHLEN + 1, (
        f"no raw proof frame captured: {res!r}"
    )
    proved_hash = res["proved_packet_hash"]
    assert isinstance(proved_hash, (bytes, bytearray)) and len(proved_hash) == 32, (
        f"proved packet hash missing/wrong length: {res!r}"
    )

    f = _decode_header1(raw)
    assert f["packet_type"] == _PROOF, f"proof packet-type bits != PROOF: {f!r}"
    assert f["context"] == _CONTEXT_NONE, f"proof context != NONE: {f!r}"
    assert f["header_type"] == _HEADER_1, f"proof must be HEADER_1: {f!r}"
    assert f["hops"] == 0, f"first-hop proof must have hops 0: {f!r}"
    assert f["destination_type"] == _DEST_SINGLE, (
        f"proof destination-type bits != SINGLE: {f!r}"
    )
    # Addressing: the proof is directed to the truncated hash of the proved
    # packet, independently recomputed from the proved packet's full hash.
    assert f["destination_hash"] == proved_hash[:_TRUNCATED_HASHLEN], (
        f"proof not addressed to truncated proved-packet hash: "
        f"{f['destination_hash'].hex()} != {proved_hash[:_TRUNCATED_HASHLEN].hex()}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "send_link_data", "link_teardown", "link_await_status",
        "send_over_closed_link",
    ],
    verifies=(
        "RNS.Packet.send refuses to transmit over a CLOSED link "
        "(Packet.py:280-286): once a link is torn down, send() returns False and "
        "transmits nothing (the link's txbytes does not advance). A DATA packet "
        "sent over the SAME link while it was ACTIVE transmits >0 bytes (positive "
        "control). An impl that keeps emitting on a closed link would leak "
        "packets to a dead peer / orphaned route"
    ),
)
def test_send_blocked_on_closed_link(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Positive control: while ACTIVE, a DATA packet over the link is accepted.
    active = client.send_link_data(link_id, b"while-active", create_receipt=True)
    assert active["sent"] is True, f"link send while ACTIVE should succeed: {active!r}"

    # Tear the link down (initiator close) and confirm it reaches CLOSED.
    client.link_teardown(link_id)
    closed = client.link_await_status(link_id, "CLOSED", timeout_ms=8000)
    assert closed.get("reached") is True, f"link did not reach CLOSED: {closed!r}"

    # Negative: send() over the CLOSED link must refuse and transmit nothing.
    res = client.send_over_closed_link(link_id, data=b"after-close")
    assert res["link_status_name"] == "CLOSED", (
        f"link must be CLOSED before the send attempt: {res!r}"
    )
    assert res["sent"] is False, (
        f"send() over a CLOSED link must return False: {res!r}"
    )
    assert res["bytes_transmitted"] == 0, (
        f"a CLOSED-link send must transmit nothing, got {res['bytes_transmitted']}"
    )
