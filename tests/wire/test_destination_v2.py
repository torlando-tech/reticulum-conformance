"""Wire V2 destination gap: no proof on decrypt failure.

Transport.inbound gates BOTH the inbound packet callback AND the PROVE_ALL
auto-proof on `Destination.receive(packet)` returning truthy
(Transport.py:2156-2157). For a SINGLE destination, receive() decrypts the
packet; an undecryptable packet makes receive() return False, so a PROVE_ALL
destination must emit no proof (and never dispatch its callback). A receiver
that proves whatever it receives leaks an ack for data it never read.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18

_APP = "conformance"
_ASPECTS = ["dest-decrypt-fail"]


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "set_proof_strategy", "send_packet_with_proof_request",
        "send_undecryptable", "packet_receipt_status",
    ],
    verifies=(
        "A PROVE_ALL SINGLE destination emits a proof ONLY when the packet "
        "decrypts: a genuine packet round-trips a PROOF (sender receipt "
        "DELIVERED + proved — positive control), but the SAME packet with a "
        "damaged ciphertext byte yields NO proof (sender receipt never "
        "DELIVERED, proved=False), because Transport gates prove() on a truthy "
        "Destination.receive() (Transport.py:2157) and receive() returns False "
        "on the decrypt failure — the same gate that suppresses the packet "
        "callback. A receiver that proves an undecryptable packet fails the "
        "negative"
    ),
)
def test_no_proof_on_decrypt_failure(wire_link_setup):
    server, client, dest_hash, _link_id = wire_link_setup(_APP, _ASPECTS)
    server.set_proof_strategy(dest_hash, "all")

    # Positive control: a genuine packet is proved (receipt DELIVERED).
    ok = client.send_packet_with_proof_request(
        dest_hash, data=secrets.token_bytes(20), app_name=_APP,
        aspects=list(_ASPECTS), timeout_ms=8000,
    )
    assert ok["delivered"] is True and ok["proved"] is True, (
        f"a genuine packet to a PROVE_ALL destination was not proved "
        f"(positive control): {ok!r}"
    )

    # Negative: the same send with a damaged ciphertext byte must yield no proof
    # (prove() is gated on receive(), which fails the decrypt).
    sent = client.send_undecryptable(
        dest_hash, data=secrets.token_bytes(20), app_name=_APP, aspects=list(_ASPECTS),
    )
    assert sent["sent"] is True and sent["receipt_id"], f"send failed: {sent!r}"
    status = client.packet_receipt_status(sent["receipt_id"], timeout_ms=3000)
    assert status["delivered"] is False, (
        f"an undecryptable packet was PROVED — the receiver emitted a proof "
        f"despite Destination.receive() failing to decrypt: {status!r}"
    )
    assert status["proved"] is False, f"undecryptable packet marked proved: {status!r}"
