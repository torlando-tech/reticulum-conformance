"""Multi-hop Link data transmission E2E test.

Reproduces a real-world failure where Columba (reticulum-kt) establishes
a Link through rnsd to Sideband (Python RNS), the link-establishment
handshake completes successfully, but subsequent data packets over the
established link are silently dropped by rnsd with log message
    "Ignored packet <...> in transport for other transport instance"

Root cause (confirmed via code trace):

  reticulum-kt's Transport.registerLinkPath stores the path for the
  linkId with `nextHop = linkId` and `hops = packet.hops` where
  packet.hops > 1 for a multi-hop link. When the sender then transmits
  a link DATA packet, Transport.outbound sees hops > 1 and wraps with
  HEADER_2 using `linkId` as the transport_id. The intermediate
  transport node then receives a HEADER_2 packet whose transport_id
  doesn't match its own identity, and drops it.

  The correct behavior is either:
   - use the original path's next_hop (the intermediate transport's
     identity) as the HEADER_2 transport_id, so the transport accepts
     the packet and forwards it based on the inner destination
     (which is the linkId, findable in its link_table); or
   - treat link DATA packets as HEADER_1 and route them directly by
     destination_hash = linkId.

Topology (see the wire_3peer fixture):

    sender (TCPClient) --\\                              //-- receiver (TCPClient)
                          \\--> transport (TCPServer) <--/
                               enable_transport=True

Observable assertion: bytes sent by `sender.link_send(link_id, payload)`
must arrive at `receiver.link_poll(destination_hash)`. If the bug
exists, the data is dropped at the transport and poll returns empty.

Parametrized across (sender_impl, transport_impl, receiver_impl). The
homogeneous Python triple is the sanity baseline (must pass); the
Kotlin-sender triples are the diagnostic targets.
"""

import secrets
import time

import pytest


def _xfail_kotlin_receiver_multihop(wire_trio, reason_suffix=""):
    """Mark the test as expected-to-fail when Kotlin is the receiver in a
    multi-hop link topology.

    Under burst transmission (multiple link data packets in rapid
    succession), reticulum-kt's Link-inbound handler currently loses
    packets (e.g., 4/5 arrive). This is a separate bug from the
    sender-side HEADER_2 wrapping issue this test's primary variant
    targets, and has not been fixed here.
    """
    _sender, _transport, receiver = wire_trio
    if receiver == "kotlin":
        pytest.xfail(
            f"reticulum-kt Link-inbound packet loss on multi-hop receive "
            f"(separate from the sender-side fix){reason_suffix}"
        )


# Allow generous time budgets — link establishment involves multiple
# round-trips plus the default RNS handshake timing (PATHFINDER + link
# PROOF grace + RTT probe).
_SETTLE_SEC = 1.5
_LINK_TIMEOUT_MS = 15000
_POLL_TIMEOUT_MS = 10000

_APP_NAME = "linkinterop"
_ASPECTS = ["test"]


def _setup_three_peer_topology(wire_3peer):
    """Wire up the standard sender/transport/receiver topology and return
    the sender/receiver/destination_hash triple. Any test that starts with
    this setup can then do its own link + send + poll assertions.
    """
    sender, transport, receiver = wire_3peer

    port = transport.start_tcp_server(network_name="", passphrase="")
    receiver.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    sender.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )

    # Wait for both TCP links to come up and for transport state to settle.
    time.sleep(_SETTLE_SEC)

    # Receiver registers an IN destination and announces it. The transport
    # forwards the announce to the sender; the sender's path table now has
    # a 2-hop path to the receiver via the transport.
    dest_hash = receiver.listen(app_name=_APP_NAME, aspects=_ASPECTS)

    # Wait for the sender's path table to learn the destination.
    assert sender.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{sender.role_label} did not learn a path to "
        f"{receiver.role_label}'s destination via {transport.role_label}. "
        f"The 3-peer topology didn't converge — later assertions would be "
        f"meaningless."
    )

    return sender, transport, receiver, dest_hash


def test_link_establishes_multihop(wire_3peer):
    """Baseline: a 2-hop Link must establish successfully across a transport.

    This is a lighter-weight check than data delivery. If this FAILS,
    link establishment itself is broken (which would suggest a deeper
    transport issue than the data-routing bug). If this PASSES but the
    data test below fails, the bug is specifically in how post-
    establishment DATA packets get routed — exactly the
    registerLinkPath/transport_id symptom.
    """
    sender, transport, receiver, dest_hash = _setup_three_peer_topology(wire_3peer)

    link_id = sender.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    assert link_id and len(link_id) == 16, (
        f"{sender.role_label} opened link to {receiver.role_label} via "
        f"{transport.role_label}, but link_id is unexpected: {link_id!r}"
    )


def test_link_data_reaches_receiver_multihop(wire_trio, wire_3peer):
    """The real test: once the link is established, sent bytes must
    arrive at the receiver.

    If the sender's Transport.registerLinkPath produces a path entry
    with the wrong transport_id, the transport peer drops every data
    packet as "in transport for other transport instance" and the
    receiver's link packet callback never fires. link_poll then
    returns empty.
    """
    _xfail_kotlin_receiver_multihop(wire_trio)
    sender, transport, receiver, dest_hash = _setup_three_peer_topology(wire_3peer)

    link_id = sender.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )

    # Random but fixed-length payload. Small enough to fit in a single
    # link packet (LINK_MTU default is 8KB-ish on TCP) so we're testing
    # single-packet link data, not resource fragmentation.
    payload = secrets.token_bytes(32)
    sender.link_send(link_id, payload)

    # Receiver polls the buffered link data. A pass means the bytes
    # traversed sender → transport → receiver intact.
    received = receiver.link_poll(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert received, (
        f"{receiver.role_label} did not receive any link data from "
        f"{sender.role_label} via {transport.role_label} within "
        f"{_POLL_TIMEOUT_MS}ms. Link was established (link_open returned "
        f"{link_id.hex()}), but subsequent DATA packets never arrived. "
        f"Expected root cause: sender wrote HEADER_2 packets with "
        f"transport_id = linkId instead of the transport's identity, so "
        f"the transport dropped them as 'in transport for other "
        f"transport instance'."
    )
    assert payload in received, (
        f"{receiver.role_label} received link data, but the payload does "
        f"not match what {sender.role_label} sent. Got: "
        f"{[r.hex() for r in received]!r}; expected: {payload.hex()}."
    )


def test_link_data_roundtrip_multiple_packets(wire_trio, wire_3peer):
    """Extension: multiple consecutive sends must all arrive. This
    catches regressions where only the first post-establishment packet
    gets routed correctly (e.g. if a fix only updated the first TX but
    not later ones via an outdated path cache entry).
    """
    _xfail_kotlin_receiver_multihop(wire_trio, " under burst send")
    sender, transport, receiver, dest_hash = _setup_three_peer_topology(wire_3peer)

    link_id = sender.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )

    payloads = [secrets.token_bytes(16 + i * 8) for i in range(5)]
    for payload in payloads:
        sender.link_send(link_id, payload)
        # Small inter-send gap — production link senders don't typically
        # batch synchronously, so we want to mirror that.
        time.sleep(0.05)

    received = receiver.link_poll(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    # Order of reception isn't strictly guaranteed for link data across a
    # transport (it usually is, but we avoid asserting an invariant the
    # protocol doesn't make), so compare as sets.
    assert set(received) == set(payloads), (
        f"{receiver.role_label} got {len(received)} packets from "
        f"{sender.role_label} (expected {len(payloads)}). "
        f"Missing: {set(payloads) - set(received)!r}. "
        f"Extra: {set(received) - set(payloads)!r}."
    )
