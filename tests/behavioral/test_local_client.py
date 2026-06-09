"""
Behavioral tests: shared-instance / local-client (hop=0) byte-level handling.

These exercise the master-side rules a Reticulum shared instance applies to the
interfaces of its locally-connected clients. The topology is built with the
behavioral harness's `local_client=True` interface: a parent MockInterface with
`is_local_shared_instance=True` is created and the child interface is appended to
`Transport.local_client_interfaces`, so `Transport.is_local_client_interface`
returns True for it (predicate at RNS Transport.py:3058-3066) — i.e. this
Transport plays the SHARED MASTER and the `lc` interface is one of its local
clients.

Rules covered (RNS 1.3.1, ground truth at
RNS/Transport.py):

  R1  Hop decrement for announces arriving on a local-client interface
      (Transport.py:1455 `hops += 1` then :1479-1480 `hops -= 1`, net 0), so a
      local app's destination is stored at hops==0 and looks master-originated.
  R4  A remote announce (heard on a non-local interface) is re-emitted to each
      local client rewritten to HEADER_2 / TRANSPORT with the master's own
      identity as the transport_id (Transport.py:1933-1976).
  R5  An inbound DATA packet for a hops==0 local destination is routed to that
      destination's local-client interface — the master regenerates the
      transport_id that was stripped on the previous hop (Transport.py:1545-1546)
      so the normal transport machinery delivers it (:1557-1581). On the wire the
      re-emission is HEADER_1 (the remaining_hops==0 branch strips transport
      headers back out, :1575-1579) with the hop count incremented.
  PLAIN broadcast fanout (Transport.py:1516-1530): a PLAIN BROADCAST from a
      local client is repeated on every OTHER interface (never re-injected into
      the originator); a PLAIN BROADCAST heard on a normal interface is pushed to
      the local-client interfaces only.

NOTE on R8 (the client-side outbound HEADER_2 wrap to a hops==1 destination,
Transport.py:1146-1164): that path is gated on
`Transport.owner.is_connected_to_shared_instance` and is driven by an
*originated* outbound Packet. The behavioral harness models the MASTER side
(it populates `local_client_interfaces`, not `is_connected_to_shared_instance`)
and exposes only inject/drain — there is no command to originate an outbound
Packet from a local destination. R8 is therefore not covered here; see the
agent's unresolved report.
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    HEADER_1,
    HEADER_2,
    TRANSPORT_BROADCAST,
    TRANSPORT_TRANSPORT,
    DESTINATION_TYPE_PLAIN,
    PACKET_TYPE_DATA,
    PACKET_TYPE_ANNOUNCE,
    build_announce_from_destination,
    build_data_packet,
    parse_packet_header,
    is_announce,
)


__category_title__ = "Transport Behavior"
__category_order__ = 19


# How long to wait after an inject for RNS's synchronous inbound handling to
# finish. The master-side rewrites under test (R1 path insert, R4 announce
# re-emit to local clients, R5 DATA routing, PLAIN fanout) all happen inline in
# Transport.inbound, so a short settle is plenty; we never wait on a timer-driven
# retransmit here.
_SETTLE = 0.3


def _announces(packets):
    return [p for p in packets if is_announce(p)]


def _matching_data(packets, dest):
    """Parsed headers of DATA packets in `packets` addressed to `dest`."""
    out = []
    for raw in packets:
        hd = parse_packet_header(raw)
        if hd["packet_type"] == PACKET_TYPE_DATA and hd["destination_hash"] == dest:
            out.append(hd)
    return out


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "drain_tx",
              "read_path_table", "announce_build"],
    verifies=(
        "An announce arriving on a local-client interface is stored in the path "
        "table at hops==0 (the per-hop +1 increment is cancelled by the "
        "local-client -1 decrement), while a byte-for-byte equivalent announce "
        "from a fresh identity arriving at the same wire_hops=0 on a normal "
        "interface in the same instance is stored at hops==1 — pinning that the "
        "decrement is specific to local-client interfaces"
    ),
)
def test_r1_local_client_announce_hop_decrement(behavioral):
    """R1: hops += 1 then -= 1 for a local-client-sourced announce, net 0.

    Positive control in the SAME instance: a normal-interface announce at the
    same wire_hops=0 is stored at hops==1. An impl that omits the local-client
    decrement would store the local-client destination at hops==1 too, failing
    the contrast."""
    inst = behavioral.start(enable_transport=True)
    try:
        lc = inst.attach_mock_interface("lc", local_client=True)
        up = inst.attach_mock_interface("up", mode="FULL")

        raw_lc, dest_lc, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="testapp", aspects=["lc"],
            random_prefix=b"\x11" * 5, emission_ts=1_000_000_050, wire_hops=0,
        )
        raw_up, dest_up, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="testapp", aspects=["up"],
            random_prefix=b"\x12" * 5, emission_ts=1_000_000_051, wire_hops=0,
        )

        inst.inject(lc, raw_lc)
        inst.inject(up, raw_up)
        time.sleep(_SETTLE)

        pt_lc = inst.read_path_table(dest_lc)
        pt_up = inst.read_path_table(dest_up)

        assert pt_lc["found"], "local-client announce was not learned into the path table"
        assert pt_lc["hops"] == 0, (
            f"local-client announce (wire_hops=0) must store hops==0 after the "
            f"+1/-1 net-zero, got {pt_lc['hops']}"
        )

        # Positive control: same wire_hops, normal interface -> +1 only.
        assert pt_up["found"], "control announce on the normal interface was not learned"
        assert pt_up["hops"] == 1, (
            f"normal-interface announce (wire_hops=0) must store hops==1 (no "
            f"local-client decrement), got {pt_up['hops']}"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "drain_tx",
              "announce_build"],
    verifies=(
        "A remote announce heard on a normal interface is re-emitted to a "
        "local-client interface exactly once, rewritten to HEADER_2 with "
        "transport_type==TRANSPORT and transport_id equal to the master's own "
        "identity hash, carrying the incremented hop count (wire_hops=1 -> "
        "hops==2) and the announced destination hash"
    ),
)
def test_r4_remote_announce_rewritten_to_local_client_header2(behavioral):
    """R4: the master injects its own identity as transport_id when relaying a
    heard announce to its local clients (Transport.py:1933-1976), so clients see
    the destination as reachable via the master."""
    inst = behavioral.start(enable_transport=True)
    master_id = inst.identity_hash
    try:
        lc = inst.attach_mock_interface("lc", local_client=True)
        up = inst.attach_mock_interface("up", mode="FULL")

        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="testapp", aspects=["r4"],
            random_prefix=b"\x05" * 5, emission_ts=1_000_000_030, wire_hops=1,
        )
        inst.inject(up, raw)
        time.sleep(_SETTLE)

        lc_announces = _announces(inst.drain_tx(lc))
        assert len(lc_announces) == 1, (
            f"expected exactly one announce re-emitted to the local client, "
            f"got {len(lc_announces)}"
        )
        hd = parse_packet_header(lc_announces[0])
        assert hd["packet_type"] == PACKET_TYPE_ANNOUNCE
        assert hd["destination_hash"] == dest, "rewritten announce targets the wrong destination"
        assert hd["header_type"] == HEADER_2, (
            f"announce to local client must be rewritten to HEADER_2, got header_type={hd['header_type']}"
        )
        assert hd["transport_type"] == TRANSPORT_TRANSPORT, (
            f"announce to local client must carry transport_type==TRANSPORT, got {hd['transport_type']}"
        )
        assert hd["transport_id"] == master_id, (
            f"announce to local client must carry the master's identity as "
            f"transport_id; got {hd['transport_id'].hex() if hd['transport_id'] else None}, "
            f"expected {master_id.hex()}"
        )
        assert hd["hops"] == 2, (
            f"wire_hops=1 -> +1 receive increment -> hops==2 on the rewritten "
            f"announce, got {hd['hops']}"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "drain_tx",
              "read_path_table", "announce_build", "packet_build",
              "packet_unpack"],
    verifies=(
        "An inbound HEADER_1 DATA packet (no transport_id) for a destination "
        "held at hops==0 via a local-client interface is routed to that "
        "local-client interface — the master regenerates the stripped "
        "transport_id internally so the packet is delivered — emitted once as "
        "HEADER_1 with the hop count incremented, and is NOT re-broadcast on the "
        "interface it arrived on"
    ),
)
def test_r5_data_for_local_client_routed_to_client(behavioral):
    """R5: for_local_client transport_id regeneration (Transport.py:1545-1546).

    A HEADER_1 DATA packet carries no transport_id, so the general transport
    relay (Transport.py:1557) would skip it; the only reason it reaches the
    local client is the for_local_client special case that re-inserts the
    master's transport_id. The remaining_hops==0 relay branch strips transport
    headers back out, so the wire re-emission is HEADER_1. Discriminating: an
    impl that does not recognise the hops==0 local destination as
    for_local_client drops the packet (it is in neither the transport nor the
    link table)."""
    inst = behavioral.start(enable_transport=True)
    try:
        lc = inst.attach_mock_interface("lc", local_client=True)
        up = inst.attach_mock_interface("up", mode="FULL")

        # Learn a local destination at hops==0 via a local-client announce.
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=secrets.token_bytes(64),
            app_name="testapp", aspects=["r5"],
            random_prefix=b"\x13" * 5, emission_ts=1_000_000_052, wire_hops=0,
        )
        inst.inject(lc, raw)
        time.sleep(_SETTLE)

        pt = inst.read_path_table(dest)
        assert pt["found"] and pt["hops"] == 0, (
            "precondition: local destination must be held at hops==0 "
            f"(found={pt.get('found')}, hops={pt.get('hops')}); the routing "
            "assertions below would be vacuous otherwise"
        )

        # Drain any announce-side traffic so the only thing we observe next is
        # the DATA re-emission.
        inst.drain_tx(lc)
        inst.drain_tx(up)

        # Inject a HEADER_1 DATA packet for that destination on the NON-local
        # interface. SINGLE payload is opaque ciphertext — only the routing
        # matters here.
        data_raw = build_data_packet(
            behavioral.bridge, dest,
            destination_type="single", hops=0, payload=b"payload",
        )
        inst.inject(up, data_raw)
        time.sleep(_SETTLE)

        lc_data = _matching_data(inst.drain_tx(lc), dest)
        up_data = _matching_data(inst.drain_tx(up), dest)

        assert len(lc_data) == 1, (
            f"DATA for a hops==0 local destination must be routed to its "
            f"local-client interface exactly once, got {len(lc_data)} copies"
        )
        hd = lc_data[0]
        assert hd["header_type"] == HEADER_1, (
            f"the remaining_hops==0 relay strips transport headers, so the "
            f"re-emission must be HEADER_1, got header_type={hd['header_type']}"
        )
        assert hd["hops"] == 1, (
            f"forwarded DATA must carry the incremented hop count (0 -> 1), got {hd['hops']}"
        )
        assert not up_data, (
            "DATA for a local client must be directed to the client interface, "
            "not re-broadcast on the interface it arrived on"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "drain_tx",
              "packet_build", "packet_unpack"],
    verifies=(
        "A PLAIN BROADCAST packet received on a local-client interface is "
        "repeated byte-for-byte on every OTHER interface and is never re-injected "
        "on the originating local-client interface"
    ),
)
def test_plain_broadcast_from_local_client_fans_out(behavioral):
    """PLAIN fanout, local-client origin (Transport.py:1522-1525): sent on all
    interfaces except the originator, never injected into transport."""
    inst = behavioral.start(enable_transport=True)
    try:
        lc = inst.attach_mock_interface("lc", local_client=True)
        up1 = inst.attach_mock_interface("up1", mode="FULL")
        up2 = inst.attach_mock_interface("up2", mode="FULL")

        target = secrets.token_bytes(16)
        praw = build_data_packet(
            behavioral.bridge, target,
            destination_type="plain", hops=0, payload=b"bcast",
        )
        # Sanity: this really is a PLAIN broadcast (the fanout's precondition).
        phd = parse_packet_header(praw)
        assert phd["destination_type"] == DESTINATION_TYPE_PLAIN
        assert phd["transport_type"] == TRANSPORT_BROADCAST

        inst.inject(lc, praw)
        time.sleep(_SETTLE)

        lc_em = inst.drain_tx(lc)
        up1_em = inst.drain_tx(up1)
        up2_em = inst.drain_tx(up2)

        assert lc_em == [], (
            "PLAIN broadcast from a local client must NOT be re-emitted on the "
            f"originating interface, got {len(lc_em)} packet(s)"
        )
        assert up1_em == [praw], (
            "PLAIN broadcast from a local client must be repeated byte-for-byte "
            "on every other interface (up1)"
        )
        assert up2_em == [praw], (
            "PLAIN broadcast from a local client must be repeated byte-for-byte "
            "on every other interface (up2)"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "drain_tx",
              "packet_build", "packet_unpack"],
    verifies=(
        "A PLAIN BROADCAST packet received on a normal interface is pushed "
        "byte-for-byte to every local-client interface only, and is NOT emitted "
        "on the normal interface it arrived on"
    ),
)
def test_plain_broadcast_to_local_clients_from_normal_iface(behavioral):
    """PLAIN fanout, non-local origin (Transport.py:1528-1530): pushed to local
    clients only, not back out the normal interfaces."""
    inst = behavioral.start(enable_transport=True)
    try:
        lc1 = inst.attach_mock_interface("lc1", local_client=True)
        lc2 = inst.attach_mock_interface("lc2", local_client=True)
        up = inst.attach_mock_interface("up", mode="FULL")

        target = secrets.token_bytes(16)
        praw = build_data_packet(
            behavioral.bridge, target,
            destination_type="plain", hops=0, payload=b"bcast2",
        )
        inst.inject(up, praw)
        time.sleep(_SETTLE)

        lc1_em = inst.drain_tx(lc1)
        lc2_em = inst.drain_tx(lc2)
        up_em = inst.drain_tx(up)

        assert lc1_em == [praw], (
            "PLAIN broadcast from a normal interface must be pushed byte-for-byte "
            "to each local-client interface (lc1)"
        )
        assert lc2_em == [praw], (
            "PLAIN broadcast from a normal interface must be pushed byte-for-byte "
            "to each local-client interface (lc2)"
        )
        assert up_em == [], (
            "PLAIN broadcast from a normal interface must go to local clients "
            f"only, not back out the normal interface, got {len(up_em)} packet(s)"
        )
    finally:
        behavioral.cleanup()
