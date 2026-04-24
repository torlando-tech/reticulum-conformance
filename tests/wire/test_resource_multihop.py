"""Multi-hop Resource transfer E2E test.

The Resource API is how RNS sends arbitrary-size payloads over a Link
(chunked into multiple link DATA packets with reassembly + proof on the
receiver). This is the code path LXMF takes for image, audio, and file
attachments — exactly what was failing for Columba's image send that
prompted this test.

Observed production symptom (Columba → rnsd → Sideband over IFAC):
  Link handshake completes (my earlier link-multihop fix works fine).
  RESOURCE_REQ from Sideband reaches Columba.
  Columba sends 2 × 8175-byte RESOURCE packets.
  Sideband never acks with RESOURCE_PROOF.
  Sideband re-requests the same resource → retry cycle until fallback
  to LXMF PROPAGATED delivery.

The simplest in-suite reproducer: send a payload big enough to need
chunking (a few × link MDU) via wire_resource_send and assert the
receiver got the full byte sequence back. If the bug is reticulum-kt
sender-side, the kotlin→reference→reference triple will fail. If
it's a Kotlin receive-side issue, ref→ref→kotlin or equivalents fail.

Parametrized across the same (sender_impl, transport_impl,
receiver_impl) triples the link-multihop test uses.
"""

import secrets
import time



_SETTLE_SEC = 1.5
_LINK_TIMEOUT_MS = 15000
_RESOURCE_TIMEOUT_MS = 30000
_PATH_POLL_TIMEOUT_MS = 10000

_APP_NAME = "resourceinterop"
_ASPECTS = ["test"]


def _setup_three_peer_topology(wire_3peer, *, ifac: bool = False):
    """Bring up sender/transport/receiver and establish a Link from
    sender to receiver via transport. Returns (sender, receiver,
    dest_hash, link_id).

    If ifac=True, all three peers use a matching network_name +
    passphrase so every packet on the wire carries a 16-byte IFAC
    tag and is XOR-masked. This mirrors Columba's production config
    where images are sent over IFAC-protected interfaces.
    """
    sender, transport, receiver = wire_3peer

    if ifac:
        netname = "resourcetest"
        passphrase = secrets.token_hex(16)
    else:
        netname = ""
        passphrase = ""

    port = transport.start_tcp_server(network_name=netname, passphrase=passphrase)
    receiver.start_tcp_client(
        network_name=netname, passphrase=passphrase,
        target_host="127.0.0.1", target_port=port,
    )
    sender.start_tcp_client(
        network_name=netname, passphrase=passphrase,
        target_host="127.0.0.1", target_port=port,
    )
    time.sleep(_SETTLE_SEC)

    dest_hash = receiver.listen(app_name=_APP_NAME, aspects=_ASPECTS)

    assert sender.poll_path(dest_hash, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{sender.role_label} did not learn a path to "
        f"{receiver.role_label}'s destination via {transport.role_label} — "
        f"the topology didn't converge, later assertions would be moot."
    )

    link_id = sender.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    return sender, receiver, dest_hash, link_id


def test_small_resource_multihop(wire_trio, wire_3peer):
    """A sub-MDU resource: exercises the Resource API without chunking.

    Even a small Resource goes through RESOURCE_ADV → RESOURCE_REQ →
    one or more RESOURCE data packets → RESOURCE_PROOF. If this fails,
    the Resource API round-trip is broken even in the trivial case.
    """
    sender, receiver, dest_hash, link_id = _setup_three_peer_topology(wire_3peer)

    payload = secrets.token_bytes(256)
    send_resp = sender.resource_send(
        link_id, payload, timeout_ms=_RESOURCE_TIMEOUT_MS
    )
    assert send_resp["success"], (
        f"{sender.role_label} resource send failed: {send_resp!r}"
    )

    received = receiver.resource_poll(dest_hash, timeout_ms=_RESOURCE_TIMEOUT_MS)
    assert received == [payload], (
        f"{receiver.role_label} did not receive the 256-byte resource "
        f"from {sender.role_label}. Got {len(received)} resource(s): "
        f"{[r[:20].hex() + '...' for r in received]}."
    )


def test_chunked_resource_multihop(wire_trio, wire_3peer):
    """A larger resource that definitely requires chunking across
    multiple link DATA packets. ~16 KB mirrors the size Columba was
    sending when the image bug surfaced (2 × 8175-byte chunks).
    """
    sender, receiver, dest_hash, link_id = _setup_three_peer_topology(wire_3peer)

    payload = secrets.token_bytes(16 * 1024)
    send_resp = sender.resource_send(
        link_id, payload, timeout_ms=_RESOURCE_TIMEOUT_MS
    )
    assert send_resp["success"], (
        f"{sender.role_label} resource send of {len(payload)} bytes did not "
        f"complete: {send_resp!r}. This is the chunked-transfer failure mode "
        f"that matches the Columba image-send symptom."
    )

    received = receiver.resource_poll(dest_hash, timeout_ms=_RESOURCE_TIMEOUT_MS)
    assert received == [payload], (
        f"{receiver.role_label} did not reassemble the {len(payload)}-byte "
        f"resource from {sender.role_label}. Sender reported "
        f"success={send_resp.get('success')} status={send_resp.get('status')}, "
        f"so if the bytes aren't here the loss happened on the wire or in "
        f"the receiver's reassembly."
    )


def test_chunked_resource_with_ifac_multihop(wire_trio, wire_3peer):
    """Same as test_chunked_resource_multihop but with IFAC enabled on
    every peer. Every on-wire packet gets a 16-byte IFAC tag and XOR
    mask. Mirrors Columba's production config where the interface
    carrying images is IFAC-protected (network_name + passphrase set).

    This is the bug that shows up in production for Columba image
    sends.
    """
    sender, receiver, dest_hash, link_id = _setup_three_peer_topology(
        wire_3peer, ifac=True
    )

    payload = secrets.token_bytes(16 * 1024)
    send_resp = sender.resource_send(
        link_id, payload, timeout_ms=_RESOURCE_TIMEOUT_MS
    )
    assert send_resp["success"], (
        f"{sender.role_label} resource send of {len(payload)} bytes via "
        f"IFAC-protected link did not complete: {send_resp!r}. If the "
        f"non-IFAC variant passes but this one fails, the bug is in the "
        f"per-packet IFAC masking code path for Resource chunks."
    )

    received = receiver.resource_poll(dest_hash, timeout_ms=_RESOURCE_TIMEOUT_MS)
    assert received == [payload], (
        f"{receiver.role_label} did not reassemble the {len(payload)}-byte "
        f"IFAC-protected resource from {sender.role_label}."
    )


def test_large_resource_multihop(wire_trio, wire_3peer):
    """A resource large enough to guarantee many link DATA packets even
    at the TCP interface's large MTU. 256 KB split into chunks of
    ~8 KB MDU ≈ 32 packets, stress-tests back-to-back link DATA
    transmission + reassembly.
    """
    sender, receiver, dest_hash, link_id = _setup_three_peer_topology(wire_3peer)

    payload = secrets.token_bytes(256 * 1024)
    send_resp = sender.resource_send(
        link_id, payload, timeout_ms=60_000
    )
    assert send_resp["success"], (
        f"{sender.role_label} resource send of {len(payload)} bytes did not "
        f"complete: {send_resp!r}. At this payload size, the resource must "
        f"span many link DATA packets; failure here points at burst-handling "
        f"in the send or receive path."
    )

    received = receiver.resource_poll(dest_hash, timeout_ms=60_000)
    assert received == [payload], (
        f"{receiver.role_label} did not reassemble the {len(payload)}-byte "
        f"resource from {sender.role_label}."
    )
