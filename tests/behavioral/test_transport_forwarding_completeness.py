"""
Behavioral completeness tests for Transport inbound forwarding (transport_forwarding
subsystem). These close gaps the existing behavioral suite leaves open against
RNS 1.3.1 RNS/Transport.py — specifically the inbound length / IFAC-flag / unpack
drop gates (Transport.py:1398-1452) and the mid-path HEADER_2 relay rewrite /
transport-gating branches (Transport.py:1536-1579).

Every test drives the REAL RNS Transport.inbound path through the behavioral
bridge (behavioral_inject) and asserts on what Transport actually emits
(behavioral_drain_tx) or learns (behavioral_read_path_table). No forwarding or
filtering logic is reimplemented in the harness.

Anchoring discipline (suite is run reference-vs-reference, so every assertion
anchors on an INDEPENDENT value, not on the impl's own output):

  * The mid-path rewrite KATs pin each rewritten byte field against an
    independently-known value: the flags byte equals the INJECTED flags byte
    (preservation), the hop byte equals injected_wire_hops + 1 (the receive
    increment, Transport.py:1455), the rewritten next-hop field equals the path
    table's next_hop (read back via read_path_table, a value established by a
    SEPARATE announce, NOT by the forwarded packet), and the destination /
    context / payload tail equals the injected tail (preservation). The rewrite
    is proven to have happened because the forwarded transport-id field differs
    from the injected one (which carried OUR identity hash, not the next hop).

  * The HEADER_1 strip KAT pins the structural collapse: header_type bit cleared
    (HEADER_2 -> HEADER_1), transport bit cleared (-> BROADCAST), low nibble
    (destination_type|packet_type) preserved, transport_id field removed
    (length shrinks by exactly TRUNCATED_HASHLENGTH//8 = 16 bytes).

  * Drop gates assert NO emission AND NO path-table mutation, each paired with a
    positive control on the SAME inject mechanism (a valid announce that IS
    learned) so the negative is never vacuous.
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    HEADER_1,
    HEADER_2,
    TRUNCATED_HASH_BYTES,
    build_announce_from_destination,
    build_data_packet,
)


__category_title__ = "Transport Behavior"
__category_order__ = 19


# Flag-byte bit masks (RNS/Packet.py pack/unpack; mirrored in packet_builders).
IFAC_FLAG_BIT = 0x80          # raw[0] & 0x80 — interface-access-code flag
HEADER_TYPE_BIT = 0x40        # raw[0] & 0x40 — 1 => HEADER_2
TRANSPORT_TYPE_BIT = 0x10     # raw[0] & 0x10 — 1 => TRANSPORT (relayed)
LOW_NIBBLE = 0x0F             # destination_type (<<2) | packet_type


def _learn_path(inst, bridge, iface_id, *, aspect, wire_hops):
    """Inject a signed announce so `inst` learns a path to a fresh destination.

    Returns (destination_hash, path_entry). The announce arrives on `iface_id`,
    so the learned path's receiving interface (egress for forwarding) is that
    interface, and — because announce_build emits a HEADER_1 announce with no
    transport_id — the path's next_hop is the destination_hash itself
    (received_from = packet.destination_hash, Transport.py:1739). The path hop
    count is wire_hops + 1 (the +1 receive increment, Transport.py:1455).
    """
    priv = secrets.token_bytes(64)
    raw, dest, _pub = build_announce_from_destination(
        bridge,
        identity_private_key=priv,
        app_name="conformance",
        aspects=[aspect],
        emission_ts=int(time.time()),
        wire_hops=wire_hops,
    )
    inst.inject(iface_id, raw)
    # The path-table write is synchronous in inbound; a small settle margin
    # matches the sibling path-table tests.
    time.sleep(0.2)
    entry = inst.read_path_table(dest)
    return dest, entry


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table", "packet_build", "packet_unpack"],
    verifies=(
        "Mid-path HEADER_2 relay with remaining_hops > 1 (Transport.py:1563-1568): "
        "a HEADER_2 SINGLE DATA packet whose transport_id is THIS instance and "
        "whose destination has a learned path of hops>1 is forwarded out ONLY the "
        "path's receiving interface, with the flags byte preserved, the hop byte "
        "incremented by exactly 1, the 16-byte transport-id field REWRITTEN to the "
        "path next_hop (read independently from the path table, != the injected "
        "transport_id which was our own identity hash), and the destination / "
        "context / payload tail carried over unchanged"
    ),
)
def test_midpath_header2_rewrite_remaining_hops_gt1(behavioral):
    """remaining_hops > 1 branch: Transport rewrites only the hop byte and the
    transport-id (next-hop) field, leaving flags, destination, context and
    payload intact, and egresses on the single path interface.

    Discriminating: an impl that strips the transport headers (the remaining==1
    branch) produces a shorter HEADER_1 packet and fails the next_hop-field /
    length checks; an impl that forwards on every interface fails the
    single-egress check; an impl that forgets the +1 increment fails the hop
    byte; an impl that leaves the transport_id unchanged fails the rewrite check
    (forwarded transport-id would still equal our identity hash)."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_eg = inst.attach_mock_interface("egress", mode="FULL")
        iface_in = inst.attach_mock_interface("ingress", mode="FULL")

        # Learn a path with hops>1 (wire 2 -> 3 after +1 increment) via iface_eg.
        dest, path = _learn_path(
            inst, behavioral.bridge, iface_eg, aspect="midpath-gt1", wire_hops=2,
        )
        assert path["found"] is True, "path-setup announce was not learned"
        assert path["hops"] == 3, f"expected path hops 3, got {path['hops']}"
        next_hop = bytes.fromhex(path["next_hop"])
        assert len(next_hop) == TRUNCATED_HASH_BYTES

        # Clear any echo from the announce so the forward drain is clean.
        inst.drain_tx(iface_eg)
        inst.drain_tx(iface_in)

        # Inject a HEADER_2 DATA packet addressed to us as the next transport hop.
        data_wire_hops = 3
        injected = build_data_packet(
            behavioral.bridge,
            dest,
            header_type=HEADER_2,
            transport_id=inst.identity_hash,
            destination_type="single",
            hops=data_wire_hops,
            payload=secrets.token_bytes(12),
        )
        inst.inject(iface_in, injected)
        time.sleep(0.2)

        # Single-interface egress: forwarded out the path's receiving interface
        # (iface_eg) and NOT the ingress interface.
        eg = inst.drain_tx(iface_eg)
        ing = inst.drain_tx(iface_in)
        assert len(eg) == 1, (
            f"expected exactly one forwarded packet on the path interface, got {len(eg)}"
        )
        assert ing == [], (
            "packet was re-emitted on the ingress interface — relay must egress "
            "only on the path's outbound interface"
        )
        fwd = eg[0]

        # Flags byte preserved (remaining_hops>1 keeps raw[0:1]).
        assert fwd[0] == injected[0], (
            f"flags byte changed on relay: {fwd[0]:#04x} != injected {injected[0]:#04x}"
        )
        # Hop byte = injected wire hops + 1 (receive increment).
        assert fwd[1] == data_wire_hops + 1, (
            f"hop byte {fwd[1]} != injected_wire_hops+1 ({data_wire_hops + 1})"
        )
        # transport-id field (bytes 2..18) rewritten to the path next_hop.
        assert fwd[2:2 + TRUNCATED_HASH_BYTES] == next_hop, (
            "transport-id field was not rewritten to the path next_hop"
        )
        assert fwd[2:2 + TRUNCATED_HASH_BYTES] != injected[2:2 + TRUNCATED_HASH_BYTES], (
            "transport-id field is unchanged — the next-hop rewrite did not happen "
            "(injected carried our identity hash, not the next hop)"
        )
        # Destination + context + payload tail carried over unchanged.
        assert fwd[2 + TRUNCATED_HASH_BYTES:] == injected[2 + TRUNCATED_HASH_BYTES:], (
            "destination/context/payload tail was altered during relay"
        )
        assert fwd[2 + TRUNCATED_HASH_BYTES:2 + 2 * TRUNCATED_HASH_BYTES] == dest, (
            "destination_hash was not preserved at its post-transport-id offset"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table", "packet_build", "packet_unpack"],
    verifies=(
        "Last-hop HEADER_2 relay with remaining_hops == 1 (Transport.py:1569-1574): "
        "the transport headers are STRIPPED — flags become HEADER_1/BROADCAST with "
        "the destination_type|packet_type nibble preserved, the 16-byte "
        "transport-id field is removed (length shrinks by exactly 16), the hop byte "
        "is incremented by 1, and destination/context/payload follow immediately "
        "after the hop byte unchanged"
    ),
)
def test_lasthop_header2_strip_remaining_hops_eq1(behavioral):
    """remaining_hops == 1 branch: Transport rewrites the packet to its HEADER_1
    final-delivery form, stripping the transport_id.

    Complement to the remaining_hops>1 rewrite test: an impl that always rewrites
    (keeps HEADER_2) fails the header-bit / length checks here, while one that
    always strips fails the >1 test — so the pair pins the branch selection on
    the path's remaining hop count."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_eg = inst.attach_mock_interface("egress", mode="FULL")
        iface_in = inst.attach_mock_interface("ingress", mode="FULL")

        # Learn a path with hops==1 (wire 0 -> 1 after +1 increment) via iface_eg.
        dest, path = _learn_path(
            inst, behavioral.bridge, iface_eg, aspect="lasthop-eq1", wire_hops=0,
        )
        assert path["found"] is True, "path-setup announce was not learned"
        assert path["hops"] == 1, f"expected path hops 1, got {path['hops']}"

        inst.drain_tx(iface_eg)
        inst.drain_tx(iface_in)

        data_wire_hops = 2
        injected = build_data_packet(
            behavioral.bridge,
            dest,
            header_type=HEADER_2,
            transport_id=inst.identity_hash,
            destination_type="single",
            hops=data_wire_hops,
            payload=secrets.token_bytes(12),
        )
        inst.inject(iface_in, injected)
        time.sleep(0.2)

        eg = inst.drain_tx(iface_eg)
        ing = inst.drain_tx(iface_in)
        assert len(eg) == 1, (
            f"expected exactly one forwarded packet on the path interface, got {len(eg)}"
        )
        assert ing == [], "packet must not be re-emitted on the ingress interface"
        fwd = eg[0]

        # Header collapsed to HEADER_1 / BROADCAST, low nibble preserved.
        assert fwd[0] & HEADER_TYPE_BIT == 0, "header_type bit not cleared to HEADER_1"
        assert fwd[0] & TRANSPORT_TYPE_BIT == 0, "transport bit not cleared to BROADCAST"
        assert fwd[0] & LOW_NIBBLE == injected[0] & LOW_NIBBLE, (
            "destination_type|packet_type nibble was not preserved on strip"
        )
        # Hop byte incremented by 1.
        assert fwd[1] == data_wire_hops + 1, (
            f"hop byte {fwd[1]} != injected_wire_hops+1 ({data_wire_hops + 1})"
        )
        # transport_id removed: length shrinks by exactly 16 bytes.
        assert len(fwd) == len(injected) - TRUNCATED_HASH_BYTES, (
            f"stripped packet length {len(fwd)} != injected - 16 "
            f"({len(injected) - TRUNCATED_HASH_BYTES})"
        )
        # destination + context + payload now follow the hop byte directly and
        # equal the injected tail (which sat after the 16-byte transport_id).
        assert fwd[2:2 + TRUNCATED_HASH_BYTES] == dest, (
            "destination_hash not placed directly after the hop byte on strip"
        )
        assert fwd[2:] == injected[2 + TRUNCATED_HASH_BYTES:], (
            "destination/context/payload tail altered during header strip"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table", "packet_build", "packet_unpack"],
    verifies=(
        "Transport-gating (Transport.py:1536): a transport-DISABLED instance that "
        "HAS a known path (hops>1) to a destination still refuses to forward a "
        "third-party HEADER_2 DATA packet addressed to it as next hop — nothing is "
        "emitted on any interface — even though the path is known (read_path_table "
        "found True), proving the non-forward is the transport gate and not a "
        "missing path. The sibling enabled-instance test forwards the identical "
        "packet shape, so the two together pin forwarding on the transport flag"
    ),
)
def test_transport_disabled_does_not_forward_thirdparty(behavioral):
    """enable_transport=False, no local-client involvement: the general transport
    block (Transport.py:1536) is skipped, so a relayed third-party packet is
    dropped rather than forwarded — while path learning itself still happens
    (the path_table insert at :2012 is unconditional).

    Discriminating: an impl that forwards regardless of the transport flag emits
    the relayed packet (fails the no-emission assertion); the in-test
    path-learned control rules out 'no path' as the reason for the drop."""
    inst = behavioral.start(enable_transport=False)
    try:
        iface_eg = inst.attach_mock_interface("egress", mode="FULL")
        iface_in = inst.attach_mock_interface("ingress", mode="FULL")

        dest, path = _learn_path(
            inst, behavioral.bridge, iface_eg, aspect="gate-off", wire_hops=2,
        )
        # Control: the path IS learned even with transport disabled.
        assert path["found"] is True, (
            "transport-disabled instance failed to learn the path — the drop "
            "assertion below would be vacuous (no path to forward along)"
        )
        assert path["hops"] == 3

        inst.drain_tx(iface_eg)
        inst.drain_tx(iface_in)

        injected = build_data_packet(
            behavioral.bridge,
            dest,
            header_type=HEADER_2,
            transport_id=inst.identity_hash,
            destination_type="single",
            hops=3,
            payload=secrets.token_bytes(12),
        )
        inst.inject(iface_in, injected)
        time.sleep(0.2)

        assert inst.drain_tx(iface_eg) == [], (
            "transport-DISABLED instance forwarded a third-party relayed packet on "
            "the path interface — the transport gate (Transport.py:1536) is not "
            "enforced"
        )
        assert inst.drain_tx(iface_in) == [], (
            "transport-DISABLED instance echoed the relayed packet on the ingress "
            "interface"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table"],
    verifies=(
        "Inbound minimum-length drop (Transport.py:1398/1447): frames of 0, 1 and "
        "2 bytes are silently discarded — no emission, no path-table mutation, no "
        "crash — while a full-length valid announce on the same interface IS "
        "processed (path learned), the positive control"
    ),
)
def test_inbound_min_length_drop(behavioral):
    """Transport.inbound returns immediately for len(raw) <= 2 (the `if len(raw)
    > 2: ... else: return` gate). Injecting sub-minimum frames must not crash the
    Transport, mutate any table, or emit anything; a subsequent valid announce
    proves inbound is still live and the drop was the length gate.

    Discriminating: an impl that mis-handles a runt frame (crashes, or treats two
    bytes as a packet) diverges from the silent-drop-then-still-works behavior."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        for runt in (b"", b"\x00", b"\x00\x00"):
            inst.inject(iface, runt)
            assert inst.drain_tx(iface) == [], (
                f"a {len(runt)}-byte runt frame produced an emission — frames of "
                f"<=2 bytes must be silently dropped (Transport.py:1398/1447)"
            )

        # Positive control: a full valid announce IS processed after the runts.
        dest, path = _learn_path(
            inst, behavioral.bridge, iface, aspect="minlen-control", wire_hops=0,
        )
        assert path["found"] is True, (
            "a valid announce was not learned after the runt frames — inbound did "
            "not survive the sub-minimum-length drops"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table"],
    verifies=(
        "Inbound unparseable-packet drop (Transport.py:1451-1452): a >2-byte frame "
        "that RNS.Packet.unpack rejects (truncated header) is silently dropped — no "
        "emission, no path-table entry, no crash — while a valid announce on the "
        "same interface IS learned (positive control)"
    ),
)
def test_inbound_unparseable_drop(behavioral):
    """inbound builds a Packet and returns on `not packet.unpack()`. A frame too
    short to carry a destination/context (but longer than the 2-byte length gate,
    and with the IFAC flag clear so it reaches the unpack step, not the IFAC gate)
    must be dropped without side effects.

    Discriminating: an impl that processes a malformed frame, or learns a path
    from it, diverges; the valid-announce control proves the drop is the unpack
    rejection, not a dead interface."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        # flags=0x00 (IFAC bit clear, HEADER_1/SINGLE/DATA) + hops + 5 stray bytes:
        # only 5 of the 16 destination bytes are present, so the context slice is
        # empty and Packet.unpack raises -> caught -> returns False.
        garbage = bytes([0x00, 0x00]) + secrets.token_bytes(5)
        assert len(garbage) > 2 and (garbage[0] & IFAC_FLAG_BIT) == 0
        inst.inject(iface, garbage)
        assert inst.drain_tx(iface) == [], (
            "an unparseable frame produced an emission — RNS drops packets that "
            "fail unpack (Transport.py:1451-1452)"
        )

        dest, path = _learn_path(
            inst, behavioral.bridge, iface, aspect="unparse-control", wire_hops=0,
        )
        assert path["found"] is True, (
            "a valid announce was not learned after the unparseable frame — inbound "
            "did not survive the unpack-rejection drop"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table"],
    verifies=(
        "IFAC-flag gating on a non-IFAC interface (Transport.py:1444-1445): a packet "
        "whose IFAC flag (raw[0] & 0x80) is SET, arriving on an interface with no "
        "IFAC identity, is silently dropped (no path learned); the byte-identical "
        "announce with the IFAC flag CLEAR is learned on the same interface "
        "(positive control), proving the drop is the IFAC-flag check, not a "
        "malformed announce"
    ),
)
def test_inbound_ifac_flag_on_non_ifac_interface_dropped(behavioral):
    """A non-IFAC interface (ifac_identity is None) must drop any packet that
    arrives with the IFAC flag set — it cannot have legitimately come from an
    IFAC-protected peer. We take a single valid announce, learn its path with the
    flag clear (control), then flip ONLY the IFAC flag bit and confirm a fresh
    destination's announce is dropped.

    Discriminating: an impl that ignores the IFAC flag on a plain interface would
    learn the flagged announce's path (fails the negative); one that drops all
    announces fails the clear-flag control."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        # Negative: a valid announce to a FRESH destination, with the IFAC flag set.
        priv = secrets.token_bytes(64)
        raw, flagged_dest, _pub = build_announce_from_destination(
            behavioral.bridge,
            identity_private_key=priv,
            app_name="conformance",
            aspects=["ifac-flagged"],
            emission_ts=int(time.time()),
            wire_hops=0,
        )
        assert (raw[0] & IFAC_FLAG_BIT) == 0, "announce already had the IFAC flag set"
        flagged = bytes([raw[0] | IFAC_FLAG_BIT]) + raw[1:]
        inst.inject(iface, flagged)
        time.sleep(0.2)
        assert inst.drain_tx(iface) == [], (
            "an IFAC-flagged packet on a non-IFAC interface produced an emission"
        )
        assert inst.read_path_table(flagged_dest)["found"] is False, (
            "an IFAC-flagged packet on a non-IFAC interface was processed (path "
            "learned) — the IFAC-flag drop (Transport.py:1444-1445) is absent"
        )

        # Positive control: a DISTINCT valid announce with the flag clear IS learned.
        _dest, path = _learn_path(
            inst, behavioral.bridge, iface, aspect="ifac-clear", wire_hops=0,
        )
        assert path["found"] is True, (
            "a flag-clear announce was not learned — the negative above would be "
            "vacuous if no announce is ever processed on this interface"
        )
    finally:
        behavioral.cleanup()
