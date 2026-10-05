"""F1.2: a node with transport disabled must not relay data between interfaces.

Topology (``wire_3peer_middle``)::

              sender (TCPClient, reference)
                        \
                         v
                middle (TCPServer, impl under test, transport DISABLED)
                        ^
                        |
              receiver (TCPClient, reference)

The receiver announces a destination, so the middle records a 1-hop path
to it (direct-announce path learning is not gated on transport in either
implementation). The sender announces nothing the test uses; it exists to
give the middle a second, distinct interface - the shape a relay must
cross (received on one interface, forwarded out another).

The probe packet is a genuine HEADER_1 (transport_id null) DATA packet
addressed to the receiver's destination, built by the middle itself
(``wire_build_data_packet``) and pushed through the middle's OWN inbound
path on its parent server interface (``inject_external``). That packet
shape is the discriminator:

  * It is NOT a natural multi-hop flow. A normal sender->receiver packet
    is HEADER_2 with the middle's identity as transport_id, and a
    transport-disabled middle already drops those (the general transport
    block is gated on ``transport_enabled() or from_local_client or ...``
    on both implementations - the middle's own ``processData`` returns
    early on ``transport_id == myHash``). So the natural 3-node flow
    never reaches the divergent code.
  * It is a foreign direct (HEADER_1) packet: the middle is neither the
    destination nor the transport hop. Python's DATA dispatch
    (Transport.py:2122) only delivers to locally-registered destinations;
    with transport disabled the general relay block
    (``if RNS.Reticulum.transport_enabled() or from_local_client or
    for_local_client or for_local_client_link:``, Transport.py:1997) is
    closed, and the packet is dropped. A node with transport disabled
    must never forward traffic between its interfaces.
  * The Kotlin port additionally re-forwards in the DATA dispatch itself
    (``Transport.processData``, the "Check if we have a path to forward
    this packet" path-table relay) with no transport-enabled or
    from-local-client check, so it transmits the packet out the
    receiver-facing interface even with transport off.

The receiver's inbound tap is the wire-level observable: it records the
packet if and only if the middle actually transmitted it to the
receiver's socket. The positive control (a genuine 1-hop direct data
send from the middle to the receiver, which a transport-disabled node
MUST deliver to its own attached peer) proves the tap and the data path
work on both implementations, so an empty tap on the probe is a drop,
not a broken path.
"""

import secrets
import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18

_APP = "relay"
_ASPECTS = ["f12"]
_SETTLE_SEC = 1.5


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen",
        "read_path_entry", "build_data_packet", "inject_raw_frame",
        "send_packet", "get_received_packets", "transport_enabled",
    ],
    verifies=(
        "A node with transport disabled does not relay data between its "
        "interfaces. With the middle node started enable_transport=False, "
        "the receiver announces (so the middle records a 1-hop path to it, "
        "which is not transport-gated), then the middle pushes a genuine "
        "HEADER_1 (transport_id null) DATA packet addressed to the "
        "receiver's destination through its OWN inbound path on the "
        "parent server interface - a foreign direct packet the middle is "
        "neither the destination nor the transport hop for. Python drops "
        "it (the DATA dispatch delivers locally only and the general "
        "relay block is gated on transport_enabled() or a local-client "
        "origin, Transport.py:1997), so the receiver's tap gains no "
        "packet; an impl whose DATA dispatch re-forwards via the path "
        "table with no transport gate transmits it to the receiver's "
        "socket instead, and the receiver's tap records it. A genuine "
        "1-hop direct data send from the middle to the receiver (which a "
        "transport-disabled node must still deliver to its own attached "
        "peer) is the positive control and is recorded by the tap on "
        "both implementations"
    ),
)
def test_disabled_transport_middle_does_not_relay_data(wire_3peer_middle):
    sender, middle, receiver = wire_3peer_middle

    port = middle.start_tcp_server(
        network_name="", passphrase="", enable_transport=False,
    )
    sender.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )
    receiver.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    # Ground truth: the middle's transport really is off (assert the live
    # flag, not the config echo).
    assert middle.transport_enabled()["transport_enabled"] is False, (
        f"{middle.role_label} must start with transport disabled: "
        f"{middle.transport_enabled()!r}"
    )
    time.sleep(_SETTLE_SEC)

    receiver_dest = receiver.listen(app_name=_APP, aspects=list(_ASPECTS))
    time.sleep(_SETTLE_SEC)

    # Relay precondition: the middle recorded a 1-hop path to the
    # receiver (direct-announce path learning; not transport-gated).
    path = middle.read_path_entry(receiver_dest)
    assert path is not None, (
        f"{middle.role_label} never learned a path to "
        f"{receiver.role_label}'s destination - the relay precondition is "
        f"missing and the probe below would be vacuous."
    )
    assert path["hops"] == 1, (
        f"expected a 1-hop direct path from {middle.role_label} to "
        f"{receiver.role_label}, got {path!r}"
    )

    # Positive control FIRST: a genuine 1-hop direct data send from the
    # middle to the receiver. A transport-disabled node MUST still
    # deliver to its own attached peer (no relay involved). Proves the
    # data path and the receiver's tap work on this implementation, so
    # an empty tap on the probe packet is a drop, not a broken path.
    control_before = receiver.get_received_packets()["highest_seq"]
    control = middle.send_packet(
        receiver_dest, data=secrets.token_bytes(32),
        app_name=_APP, aspects=list(_ASPECTS),
    )
    assert control["sent"] is True, f"positive control send failed: {control!r}"
    time.sleep(_SETTLE_SEC)
    control_new = receiver.get_received_packets(since_seq=control_before)["packets"]
    control_hits = [
        p for p in control_new
        if p.get("packet_type") == 0 and p.get("destination_hash_hex") == receiver_dest.hex()
    ]
    assert control_hits, (
        f"the genuine 1-hop direct data send was not recorded by "
        f"{receiver.role_label}'s tap (positive control) - the tap or the "
        f"data path is broken, the probe assertions would be vacuous: "
        f"{control_new!r}"
    )

    # The probe: a genuine HEADER_1 (transport_id null) DATA packet
    # addressed to the receiver's destination, built by the middle
    # itself, injected through the middle's OWN inbound path on the
    # parent (open) interface. The receiver's child interface is the
    # only interface the middle's path table can forward it out, so a
    # relay is observable at the receiver's socket - and nothing else.
    probe = middle.build_data_packet(
        receiver_dest, app_name=_APP, aspects=list(_ASPECTS),
        data=secrets.token_bytes(32),
    )
    raw = bytes.fromhex(probe["raw"])
    # Sanity: the frame really is a HEADER_1 DATA packet to the
    # receiver (header bits 0-1 = DATA=0, bits 6-7 = HEADER_1=0,
    # destination field = receiver dest).
    assert (raw[0] & 0b00000011) == 0, (
        f"probe frame is not a DATA packet: flags 0x{raw[0]:02x}"
    )
    assert ((raw[0] >> 6) & 0b11) == 0, (
        f"probe frame is not HEADER_1: flags 0x{raw[0]:02x}"
    )
    assert raw[2:18] == receiver_dest, "probe frame is not addressed to the receiver"

    probe_before = receiver.get_received_packets()["highest_seq"]
    middle.inject_raw_frame(
        "inject_external", raw=raw, dest_hash=receiver_dest,
    )
    time.sleep(_SETTLE_SEC)
    probe_new = receiver.get_received_packets(since_seq=probe_before)["packets"]
    probe_hits = [
        p for p in probe_new
        if p.get("packet_type") == 0 and p.get("destination_hash_hex") == receiver_dest.hex()
    ]
    assert not probe_hits, (
        f"a transport-disabled {middle.role_label} RELAYED a foreign "
        f"HEADER_1 DATA packet between its interfaces: "
        f"{receiver.role_label}'s tap recorded {len(probe_hits)} DATA "
        f"packet(s) addressed to it that the middle injected on its own "
        f"parent interface. Python gates all forwarding on "
        f"transport_enabled() or a local-client origin "
        f"(Transport.py:1997); this impl's DATA dispatch re-forwards via "
        f"the path table with no transport gate (the "
        f"'Check if we have a path to forward this packet' relay), so it "
        f"transmits the packet out the receiver-facing interface with "
        f"transport off. {probe_hits!r}"
    )
