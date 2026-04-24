"""Hub routing isolation conformance test.

Proves that a transport/hub node delivers packets **only** to the peer(s)
they are destined for, and does NOT fan them out to every connected peer.

The bug this test was written to detect is reticulum-kt#46 /
reticulum-kt PR #52: the Kotlin `TCPServerInterface` had two separate
fan-out loops (inbound per-child echo + outbound parent replay) not
present in Python RNS. When triggered, any peer connected to the same
hub would receive a copy of a packet addressed to a different peer.

That specific fan-out is not just a Kotlin bug — it's a wire-level
conformance hazard. Any future port (Swift, Rust, Go, JS) could
re-introduce the same pattern. This test defends against all of them
by observing the wire at a peer that SHOULD NOT receive the traffic.

Topology (see the `wire_hub_isolation` fixture)::

        sender (TCPClient, reference)
              |
              v
        transport (TCPServer, wire_hub_impl)   <-- impl under test
              ^ ^
             /   \\
   receiver      witness
   (TCPClient,   (TCPClient,
    reference)    reference)

The witness is a bystander: it shares the transport with sender and
receiver but has no destination the sender is addressing. A correctly-
implemented hub **never** delivers packets destined for `receiver` to
the `witness` socket.

The fixture pins sender / receiver / witness to the reference impl and
parameterizes only the hub (`wire_hub_impl`). What we're probing is a
property of the hub's routing logic, so the leaves being stable makes
the oracle unambiguous.

Two scenarios are covered, each targeting a distinct class of fan-out:

  1. Link DATA — the symptom seen in production (rnsd-equivalent hub
                 duplicating in-link app traffic to every peer).
  2. Path-response — metadata path-response fan-out would leak which
                 destinations are reachable where. The sender fires a
                 PR for receiver's dest; a correct hub replies only to
                 the asker, so no path-response for receiver should
                 land at the witness.

Each scenario asserts: the witness's tap buffer contains zero packets
whose raw_hex embeds the receiver's destination-hash bytes OR the
unique payload marker. Exact-match assertions (not membership) to
catch silent duplicate deliveries.
"""

import secrets
import time


_SETTLE_SEC = 1.5
_LINK_TIMEOUT_MS = 15000
_POLL_TIMEOUT_MS = 10000
_APP_NAME = "hubiso"
_ASPECTS = ["test"]


def _setup_four_peer_topology(wire_hub_isolation):
    """Wire up sender + receiver + witness around a single transport hub
    and return (sender, transport, receiver, witness, dest_hash) with a
    confirmed path from sender → receiver.

    The witness starts a TCP client to the hub but registers no IN
    destination — it's passively observing whatever the hub chooses to
    hand it. After setup, the sender's path table must point at the
    receiver's dest via the transport, otherwise later assertions would
    be vacuous (no packets to leak because no traffic flows).
    """
    sender, transport, receiver, witness = wire_hub_isolation

    port = transport.start_tcp_server(network_name="", passphrase="")
    receiver.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    witness.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    sender.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )

    time.sleep(_SETTLE_SEC)

    dest_hash = receiver.listen(app_name=_APP_NAME, aspects=_ASPECTS)

    assert sender.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{sender.role_label} did not learn a path to "
        f"{receiver.role_label} via {transport.role_label}. Topology did "
        f"not converge — hub-isolation assertions would be vacuous."
    )

    return sender, transport, receiver, witness, dest_hash


def _assert_no_leak(
    witness,
    forbidden_bytes_sets,
    description,
    since_seq=0,
):
    """Assert the witness has seen zero packets whose raw_hex contains any
    of the given forbidden hex markers.

    `forbidden_bytes_sets` is a list of bytes objects; if ANY appears as
    a hex substring in ANY witness-received packet's raw_hex, that's a
    leak. A helpful failure message lists the offending packets so a
    future regressor can identify which impl+interface leaked.
    """
    resp = witness.get_received_packets(since_seq=since_seq)
    packets = resp.get("packets", [])
    leaks = []
    forbidden_hex = [b.hex() for b in forbidden_bytes_sets]
    for pkt in packets:
        raw_hex = pkt.get("raw_hex", "")
        for marker in forbidden_hex:
            if marker and marker in raw_hex:
                leaks.append((marker, pkt))
                break
    assert not leaks, (
        f"{witness.role_label} received {len(leaks)} packet(s) that should "
        f"not have been delivered to it ({description}). The hub is "
        f"fanning out traffic to peers that are not the intended "
        f"destination. Offending entries (first 3):\n"
        + "\n".join(
            f"  seq={pkt['seq']} type={pkt.get('packet_type')} "
            f"iface={pkt.get('interface_name')} marker={marker} "
            f"raw={pkt['raw_hex'][:160]}..."
            for marker, pkt in leaks[:3]
        )
    )


def test_link_data_does_not_leak_to_witness(wire_hub_isolation):
    """Scenario 1 — Link DATA exclusivity.

    After sender and receiver establish a Link through the hub, any DATA
    packets the sender transmits on that Link must arrive at the receiver
    and ONLY the receiver. A 32-byte random marker payload is used so we
    can search for an exact byte pattern that can only have come from the
    in-flight link data (collisions with unrelated packets ~2^-256).
    """
    sender, transport, receiver, witness, dest_hash = _setup_four_peer_topology(
        wire_hub_isolation
    )

    # Snapshot the witness tap seq BEFORE any Link traffic so we only
    # consider packets delivered after this point. Announces from the
    # earlier listen() step legitimately fan out to the witness (they're
    # network-wide broadcast semantics) and would otherwise create noise.
    baseline = witness.get_received_packets(since_seq=0)
    since_seq = int(baseline.get("highest_seq", 0))

    link_id = sender.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )

    # Unique, long-enough payload that its exact bytes are vanishingly
    # unlikely to appear in any unrelated wire frame.
    payload = secrets.token_bytes(32)
    sender.link_send(link_id, payload)

    received = receiver.link_poll(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert payload in received, (
        f"{receiver.role_label} did not receive the expected payload via "
        f"{transport.role_label} — cannot assess leak to witness because "
        f"the happy path didn't work. Got: {[r.hex() for r in received]!r}."
    )

    # Now assert the exclusivity property: no witness packet carries
    # either the payload bytes OR the receiver's destination hash.
    _assert_no_leak(
        witness,
        forbidden_bytes_sets=[payload, dest_hash],
        description="link DATA or receiver dest-hash appeared in a packet "
        "delivered to witness after the link was established",
        since_seq=since_seq,
    )


def test_path_request_response_does_not_leak_to_witness(wire_hub_isolation):
    """Scenario 2 — Path-response exclusivity.

    When the sender issues a PR for the receiver's destination, the
    transport should respond directly to the sender (the asker). A
    witness that never asked for this path must not see the path-
    response packet.

    The receiver's destination hash is used as the forbidden marker —
    any cached announce re-emitted as a path-response will embed it.
    """
    sender, transport, receiver, witness, dest_hash = _setup_four_peer_topology(
        wire_hub_isolation
    )

    # The sender already has the path from the earlier listen-driven
    # announce. Wait a moment for that to quiesce, then snapshot the
    # witness buffer so we only look at post-PR traffic.
    time.sleep(0.5)
    baseline = witness.get_received_packets(since_seq=0)
    since_seq = int(baseline.get("highest_seq", 0))

    sender.request_path(dest_hash)

    # Give the transport time to compose and emit a response, plus a
    # margin for any bogus fan-out to land at the witness.
    time.sleep(1.5)

    _assert_no_leak(
        witness,
        forbidden_bytes_sets=[dest_hash],
        description="receiver's dest-hash appeared in a packet delivered "
        "to witness after sender fired a path-request (expected: hub "
        "should reply only to the asker, the sender)",
        since_seq=since_seq,
    )


# Note: an earlier draft of this file had a third scenario that tried to
# detect announce fan-out by counting duplicate announces at the witness.
# It was dropped because announces broadcast legitimately, and the
# buggy fan-out copies arrived with different raw bytes than the
# broadcast copy (transport layering bumps hops/wrapping), so a
# raw_hex-keyed dedup can't distinguish fan-out from legit broadcast
# without impl-specific parsing. The two scenarios above already
# catch the fan-out by detecting leaks of receiver-addressed DATA and
# path-response bytes at the witness — which is the concrete harm the
# fan-out caused. Leaving this note so a future contributor doesn't
# re-derive the same vacuous test.
