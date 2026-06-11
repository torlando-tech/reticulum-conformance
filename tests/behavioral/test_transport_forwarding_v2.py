"""
Behavioral V2 completeness tests for Transport forwarding (transport_forwarding
subsystem). These close gaps the prior behavioral suite left open against
RNS 1.3.1 RNS/Transport.py, driving every assertion through the REAL
Transport.inbound path (behavioral_inject) and observing real emissions
(behavioral_drain_tx) / real table state (behavioral_read_link_table).

Gaps closed (V2 worklist ids):

  * forward-no-path-silent-drop (CORE) — a HEADER_2 SINGLE DATA packet addressed
    to THIS node as the next transport hop, for a destination with NO path-table
    entry, produces ZERO emissions (Transport.py:1636-1640, the `else` of the
    next-hop path lookup). The positive control (same packet shape, but a learned
    path) IS forwarded, so the drop is attributable to the missing path and not a
    general refusal to forward.

  * link-routing-hop-count-check (CORE) — the link-transport routing branch only
    forwards when packet.hops equals the expected hop count for the receiving
    interface (Transport.py:1660-1667): a relay that forwards link traffic with
    ANY hop byte is non-conformant. Seeded link_table entry; wrong-hops link DATA
    is NOT forwarded, right-hops link DATA IS — in BOTH cross-interface
    directions.

  * link-id-packet-routing (partial) — the same-interface repeat case
    (Transport.py:1651-1655), the byte-identity-except-hops of forwarded link
    frames (:1675-1677), and the link-entry timestamp refresh (:1679). Asserted
    via read_link_table (before < after) and a single-interface egress check.

  * plain-broadcast-shared-instance-relay (partial) — the control-destination
    carve-out (Transport.py:1519): a PLAIN BROADCAST addressed to a
    Transport.control_hashes destination (here rnstransport/tunnel/synthesize) is
    NOT fanned out by the shared-instance relay rule, while a PLAIN BROADCAST to a
    non-control destination IS (the discriminating control).

  * tunnel-synthesis-validation (partial) — the exact-length gate in
    Transport.tunnel_synthesize_handler (Transport.py:2308-2309): only a payload
    of EXACTLY 176 bytes (KEYSIZE/8 + HASHLENGTH/8 + TRUNCATED_HASHLENGTH/8 +
    SIGLENGTH/8) is processed; a 177-byte payload whose first 176 bytes are a
    fully-valid synthesize packet, and a 175-byte truncation, are BOTH silently
    ignored (no tunnel), while the exact 176-byte packet establishes one.

Anchoring discipline (suite is run reference-vs-reference, so every assertion
anchors on an INDEPENDENT value, not on the impl's own output):

  * Hop expectations are seeded by the test (REM/HOPS), and the on-wire hop a
    packet must carry to match is derived from the +1 receive increment
    (Transport.py:1455), a spec constant — never read back from the impl.
  * The forward byte-identity is checked against the INJECTED bytes (independent)
    plus the +1 hop increment.
  * The 176-byte tunnel gate is the spec sum 64+32+16+64, computed here, not the
    impl's notion of length.
  * The control-hash carve-out anchors on the control destination's address,
    derived independently from its dotted name via real RNS hashing.
"""

import secrets

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    DESTINATION_TYPE_LINK,
    HEADER_2,
    PACKET_TYPE_LINKREQUEST,
    TRUNCATED_HASH_BYTES,
    TUNNEL_SYNTHESIZE_DESTINATION_NAME,
    _plain_destination_hash,
    build_announce_from_destination,
    build_data_packet,
    build_link_request_packet,
    build_link_transport_packet,
    build_tunnel_synthesize,
    parse_packet_header,
)


# RNS link-establishment constants (RNS/Link.py, RNS/Reticulum.py), used to
# verify the relay's proof-timeout formula independently of the impl's output.
_ESTABLISHMENT_TIMEOUT_PER_HOP = 6  # RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
_RETICULUM_MTU = 500                # RNS.Reticulum.MTU (for extra_link_proof_timeout)


__category_title__ = "Transport Behavior"
__category_order__ = 19


# The tunnel-synthesize payload length gate (Transport.py:2308):
#   KEYSIZE//8 (64) + HASHLENGTH//8 (32) + TRUNCATED_HASHLENGTH//8 (16)
#   + SIGLENGTH//8 (64) == 176. Computed here as a spec literal, independent of
# the impl, so the over/under cases discriminate the EXACT-equality check.
_SYNTHESIZE_EXPECTED_LEN = 64 + 32 + 16 + 64


def _learn_path(inst, bridge, iface_id, *, aspect, wire_hops):
    """Inject a signed announce so `inst` learns a path to a fresh destination.

    Returns (destination_hash, path_entry). The announce arrives on `iface_id`,
    so the learned path's receiving interface (the forwarding egress) is that
    interface, and the path hop count is wire_hops + 1 (the +1 receive increment,
    Transport.py:1455).
    """
    import time

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
    time.sleep(0.2)
    return dest, inst.read_path_table(dest)


# ---------------------------------------------------------------------------
# 1. forward-no-path-silent-drop (CORE)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table", "packet_build", "packet_unpack"],
    verifies=(
        "Next-hop with no known path is a silent drop (Transport.py:1636-1640): a "
        "HEADER_2 SINGLE DATA packet whose transport_id is THIS instance, for a "
        "destination with NO path-table entry, produces zero emissions on every "
        "interface — and no path/link/reverse state. The byte-identical-shape "
        "packet for a destination WITH a learned path (hops>1) IS forwarded "
        "(positive control), so the drop is attributable to the missing path, not "
        "a general refusal to forward."
    ),
)
def test_header2_next_hop_no_path_silent_drop(behavioral):
    """RNS reaches the next-hop branch (transport_id == own identity) but finds no
    path_table entry, so it logs and drops with no emission. Discriminating: an
    impl that forwards (e.g. broadcasts) a next-hop packet it has no path for
    emits something and fails the no-emission assertion; the learned-path control
    rules out 'this node never forwards' as the explanation."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_in = inst.attach_mock_interface("in", mode="FULL")
        iface_eg = inst.attach_mock_interface("eg", mode="FULL")

        # Negative: a fresh destination we hold NO path to.
        unknown_dest = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        assert inst.read_path_table(unknown_dest)["found"] is False, (
            "the 'no path' precondition is violated — destination already known"
        )
        no_path = build_data_packet(
            behavioral.bridge, unknown_dest,
            header_type=HEADER_2, transport_id=inst.identity_hash,
            destination_type="single", hops=3, payload=secrets.token_bytes(12),
        )
        inst.inject(iface_in, no_path)
        assert inst.drain_tx(iface_in) == [], (
            "a next-hop DATA packet with no known path was echoed on its ingress "
            "interface"
        )
        assert inst.drain_tx(iface_eg) == [], (
            "a next-hop DATA packet with no known path was forwarded despite there "
            "being no path-table entry (Transport.py:1636-1640)"
        )

        # Positive control: the SAME shape, but for a destination with a learned
        # path (hops>1), IS forwarded out the path's interface.
        known_dest, path = _learn_path(
            inst, behavioral.bridge, iface_eg, aspect="np-control", wire_hops=2,
        )
        assert path["found"] and path["hops"] == 3, (
            f"control path was not learned with hops==3: {path}"
        )
        inst.drain_tx(iface_in)
        inst.drain_tx(iface_eg)

        with_path = build_data_packet(
            behavioral.bridge, known_dest,
            header_type=HEADER_2, transport_id=inst.identity_hash,
            destination_type="single", hops=3, payload=secrets.token_bytes(12),
        )
        inst.inject(iface_in, with_path)
        forwarded = inst.drain_tx(iface_eg)
        assert len(forwarded) == 1, (
            "the no-path drop above is vacuous: an identical-shape packet WITH a "
            "known path was also not forwarded"
        )
        assert parse_packet_header(forwarded[0])["destination_hash"] == known_dest
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 1b. linkrequest-forward-creates-link-entry (CORE)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "drain_tx", "read_path_table", "read_link_table", "packet_build",
              "packet_unpack", "packet_hash"],
    verifies=(
        "Forwarding a LINKREQUEST creates a correctly-keyed, correctly-populated "
        "link_table entry (Transport.py:1583-1623). A HEADER_2 LINKREQUEST aimed "
        "at THIS node as next hop, for a destination with a known path (hops>1), "
        "is keyed by link_id == truncated_hash(get_hashable_part) (== packet_hash "
        "first 16 bytes), with next_hop_transport_id = the path's next hop, "
        "next_hop interface = the path's interface, received interface = the "
        "ingress, remaining_hops = the path hop count, taken_hops = packet.hops, "
        "validated = False, and proof_timeout = now + 6s/remaining_hop + the "
        "per-interface extra ((8/bitrate)*MTU). The LR is also relayed out the "
        "path interface."
    ),
)
def test_linkrequest_forward_creates_link_entry(behavioral):
    """Relay a LINKREQUEST and read back the link_table entry RNS built. Every
    field is anchored on an independent value: link_id on the packet's own
    truncated hash (computed via packet_hash, not read from the table), next_hop
    on the path table (established by a SEPARATE announce), remaining_hops on the
    path hop count, taken_hops on the +1 receive increment, and proof_timeout on
    the spec formula 6s/hop + (8/bitrate)*MTU bracketed around the inject. An impl
    that mis-keys the entry, miscounts hops, marks it validated, or bungles the
    proof-timeout formula is caught."""
    import time

    inst = behavioral.start(enable_transport=True)
    try:
        iface_in = inst.attach_mock_interface("in", mode="FULL")
        iface_eg = inst.attach_mock_interface("eg", mode="FULL")

        # Learn a path to D with hops>1 (wire 2 -> 3) via the egress interface.
        dest, path = _learn_path(
            inst, behavioral.bridge, iface_eg, aspect="lr-entry", wire_hops=2,
        )
        assert path["found"] and path["hops"] == 3, f"path not learned hops==3: {path}"
        path_next_hop = path["next_hop"]
        assert path_next_hop is not None
        inst.drain_tx(iface_in)
        inst.drain_tx(iface_eg)

        # Build a HEADER_2 LINKREQUEST to D, naming us as the next transport hop.
        lr_wire_hops = 4
        lr_raw, _req = build_link_request_packet(
            behavioral.bridge, dest,
            transport_id=inst.identity_hash, hops=lr_wire_hops,
        )
        # link_id the relay will key on: truncated_hash(get_hashable_part) ==
        # packet_hash[:16] for a 64-byte (ECPUBSIZE) body. Derived independently.
        full_hash = bytes.fromhex(
            behavioral.bridge.execute("packet_hash", raw=lr_raw.hex())["hash"]
        )
        expected_link_id = full_hash[:TRUNCATED_HASH_BYTES]

        t0 = time.time()
        inst.inject(iface_in, lr_raw)
        t1 = time.time()

        # The LR is relayed out the path interface (HEADER_2, remaining_hops>1).
        relayed = inst.drain_tx(iface_eg)
        assert any(parse_packet_header(p)["packet_type"] == PACKET_TYPE_LINKREQUEST
                   for p in relayed), (
            "the LINKREQUEST was not relayed out the path interface"
        )
        assert inst.drain_tx(iface_in) == [], "LR echoed on its ingress interface"

        entry = inst.read_link_table(expected_link_id)
        assert entry["found"], (
            "no link_table entry was keyed by truncated_hash(get_hashable_part) — "
            "the relay either dropped the LR or keyed the entry incorrectly"
        )
        # next-hop transport id / interface come from the path table (independent).
        assert entry["next_hop_transport_id"] == path_next_hop, (
            f"link entry next-hop {entry['next_hop_transport_id']} != path next-hop "
            f"{path_next_hop}"
        )
        assert entry["next_hop_if"] == iface_eg, (
            "link entry next-hop interface is not the path's interface"
        )
        assert entry["received_if"] == iface_in, (
            "link entry received interface is not the LR's ingress interface"
        )
        assert entry["remaining_hops"] == 3, (
            f"link entry remaining_hops {entry['remaining_hops']} != path hops 3"
        )
        # taken hops == packet.hops on receive == wire hops + 1 (receive increment).
        assert entry["hops"] == lr_wire_hops + 1, (
            f"link entry taken-hops {entry['hops']} != injected wire hops + 1 "
            f"({lr_wire_hops + 1})"
        )
        assert entry["validated"] is False, (
            "a freshly-relayed link entry must be unvalidated (validated only on "
            "the returning LRPROOF)"
        )
        assert entry["destination_hash"] == dest.hex(), (
            "link entry destination_hash is not the LR's destination"
        )

        # proof_timeout = extra_link_proof_timeout(ingress) + now
        #                 + 6 * max(1, remaining_hops). extra = (8/bitrate)*MTU.
        extra = (8.0 / 10_000_000) * _RETICULUM_MTU  # MockInterface default bitrate
        base = _ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, 3) + extra
        assert (t0 + base) - 0.5 <= entry["proof_timeout"] <= (t1 + base) + 0.5, (
            f"proof_timeout {entry['proof_timeout']} not within the spec window "
            f"[{t0 + base:.3f}, {t1 + base:.3f}] (6s/hop * 3 + per-interface extra)"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 2. link-routing-hop-count-check (CORE)
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "seed_link_table", "inject",
              "drain_tx", "packet_build", "packet_unpack"],
    verifies=(
        "Link-transport routing enforces the per-interface hop count "
        "(Transport.py:1660-1667): for a link entry with distinct received/next-hop "
        "interfaces, a link DATA packet received on the next-hop interface is "
        "forwarded out the received interface ONLY when packet.hops == "
        "remaining_hops, and one received on the received interface is forwarded "
        "out the next-hop interface ONLY when packet.hops == taken_hops. A packet "
        "with the wrong hop byte (on either interface) is NOT forwarded. Both "
        "directions are tested with a matching positive and a wrong-hops negative."
    ),
)
def test_link_transport_cross_interface_hop_count_check(behavioral):
    """Seed a cross-interface link entry (rem_hops=4, taken_hops=2). The hop a
    packet must carry to be forwarded is derived from the seeded values plus the
    +1 receive increment (so wire_hops = expected-1), an independent value. An
    impl that omits the hop-count gate forwards the wrong-hops packets too and
    fails the negative assertions; the matching positives rule out a relay that
    forwards nothing."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface_nh = inst.attach_mock_interface("nh", mode="FULL")
        iface_rcvd = inst.attach_mock_interface("rcvd", mode="FULL")

        link_id = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        REM, TAKEN = 4, 2  # remaining vs taken hops; distinct so the two checks differ
        inst.seed_link_table(
            link_id, nh_iface_id=iface_nh, rcvd_iface_id=iface_rcvd,
            rem_hops=REM, hops=TAKEN,
        )
        inst.drain_tx(iface_nh)
        inst.drain_tx(iface_rcvd)

        # Direction A: received on the NEXT-HOP interface -> out the RECEIVED
        # interface iff packet.hops == REM. wire_hops = REM-1 (the +1 increment).
        good_a = build_link_transport_packet(
            behavioral.bridge, link_id, hops=REM - 1, payload=secrets.token_bytes(8),
        )
        inst.inject(iface_nh, good_a)
        assert len(inst.drain_tx(iface_rcvd)) == 1, (
            "a link DATA packet with the matching remaining-hops count, received "
            "on the next-hop interface, was NOT forwarded out the received "
            "interface (Transport.py:1662-1663)"
        )
        assert inst.drain_tx(iface_nh) == [], "link DATA echoed on its ingress interface"

        # Negative A: wrong hops on the next-hop interface -> NOT forwarded.
        bad_a = build_link_transport_packet(
            behavioral.bridge, link_id, hops=REM + 3, payload=secrets.token_bytes(8),
        )
        inst.inject(iface_nh, bad_a)
        assert inst.drain_tx(iface_rcvd) == [], (
            "a link DATA packet with the WRONG hop count was forwarded anyway — "
            "the per-interface hop-count gate (Transport.py:1662) is absent"
        )
        assert inst.drain_tx(iface_nh) == []

        # Direction B: received on the RECEIVED interface -> out the NEXT-HOP
        # interface iff packet.hops == TAKEN. wire_hops = TAKEN-1.
        good_b = build_link_transport_packet(
            behavioral.bridge, link_id, hops=TAKEN - 1, payload=secrets.token_bytes(8),
        )
        inst.inject(iface_rcvd, good_b)
        assert len(inst.drain_tx(iface_nh)) == 1, (
            "a link DATA packet with the matching taken-hops count, received on "
            "the received interface, was NOT forwarded out the next-hop interface "
            "(Transport.py:1666-1667)"
        )
        assert inst.drain_tx(iface_rcvd) == []

        # Negative B: wrong hops on the received interface -> NOT forwarded.
        bad_b = build_link_transport_packet(
            behavioral.bridge, link_id, hops=TAKEN + 4, payload=secrets.token_bytes(8),
        )
        inst.inject(iface_rcvd, bad_b)
        assert inst.drain_tx(iface_nh) == [], (
            "a link DATA packet with the WRONG hop count (received interface "
            "direction) was forwarded anyway (Transport.py:1666)"
        )
        assert inst.drain_tx(iface_rcvd) == []
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 3. link-id-packet-routing (partial): same-interface repeat, byte-identity,
#    timestamp refresh
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "seed_link_table",
              "read_link_table", "inject", "drain_tx", "packet_build",
              "packet_unpack"],
    verifies=(
        "Same-interface link repeat (Transport.py:1651-1655): when a link entry's "
        "next-hop and received interfaces are identical, a link DATA packet whose "
        "hops match EITHER the remaining or the taken hop count is repeated on "
        "that interface (and only that interface). The forwarded frame is "
        "byte-identical to the received frame except the hop byte (= received "
        "hops, the +1 increment; :1675-1677), and the link entry's timestamp is "
        "refreshed to now (:1679, observed via read_link_table: after > before). A "
        "packet whose hops match NEITHER value is not repeated."
    ),
)
def test_link_transport_same_interface_repeat_and_timestamp_refresh(behavioral):
    """Seed a same-interface link entry (nh_if == rcvd_if). The forward is
    asserted byte-for-byte against the injected packet (independent) with only the
    hop byte advanced by the spec +1 increment; the timestamp refresh is anchored
    on before < after (the seed timestamp is independent of the forward). An impl
    that egresses on a second interface, mangles the frame, or fails to refresh
    the timestamp is caught."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        iface_other = inst.attach_mock_interface("other", mode="FULL")

        link_id = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        REM, TAKEN = 5, 3
        inst.seed_link_table(
            link_id, nh_iface_id=iface, rcvd_iface_id=iface, rem_hops=REM, hops=TAKEN,
        )
        before = inst.read_link_table(link_id)
        assert before["found"] and before["next_hop_if"] == before["received_if"] == iface, (
            f"seed did not produce a same-interface entry: {before}"
        )
        ts_before = before["timestamp"]
        inst.drain_tx(iface)
        inst.drain_tx(iface_other)

        # hops == TAKEN matches the same-interface repeat (REM or TAKEN).
        pkt = build_link_transport_packet(
            behavioral.bridge, link_id, hops=TAKEN - 1, payload=secrets.token_bytes(8),
        )
        inst.inject(iface, pkt)
        out = inst.drain_tx(iface)
        assert len(out) == 1, (
            "a same-interface link DATA packet with a matching hop count was not "
            "repeated on its interface (Transport.py:1651-1655)"
        )
        assert inst.drain_tx(iface_other) == [], (
            "link DATA was repeated on a second interface — same-interface repeat "
            "must egress only on the link's interface"
        )
        fwd = out[0]
        # Byte-identity except the hop byte (= received hops = wire TAKEN-1 + 1).
        assert fwd[0] == pkt[0], "flags byte changed on link repeat"
        assert fwd[1] == TAKEN, (
            f"forwarded hop byte {fwd[1]} != received hops {TAKEN} (wire {TAKEN - 1} + 1)"
        )
        assert fwd[2:] == pkt[2:], (
            "link repeat altered the destination/context/payload tail"
        )

        after = inst.read_link_table(link_id)
        assert after["found"], "link entry vanished after a repeat"
        assert after["timestamp"] > ts_before, (
            "the link entry timestamp was not refreshed on repeat "
            f"(Transport.py:1679): before={ts_before}, after={after['timestamp']}"
        )

        # Negative: hops matching NEITHER REM nor TAKEN -> not repeated.
        bad = build_link_transport_packet(
            behavioral.bridge, link_id, hops=REM + 2, payload=secrets.token_bytes(8),
        )
        inst.inject(iface, bad)
        assert inst.drain_tx(iface) == [], (
            "a same-interface link DATA packet with a non-matching hop count was "
            "repeated anyway"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 4. plain-broadcast-shared-instance-relay (partial): control-hash carve-out
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "drain_tx",
              "packet_build", "packet_unpack", "name_hash", "truncated_hash"],
    verifies=(
        "Control-destination carve-out in the PLAIN-broadcast shared-instance "
        "relay (Transport.py:1519): a PLAIN BROADCAST from a local client whose "
        "destination is a Transport.control_hashes destination "
        "(rnstransport/tunnel/synthesize) is NOT fanned out to the node's other "
        "interfaces, while a PLAIN BROADCAST to a NON-control destination IS fanned "
        "out byte-for-byte (the discriminating control). An impl missing the "
        "carve-out re-broadcasts control traffic (path-request/synthesize/"
        "discovery) network-wide."
    ),
)
def test_plain_broadcast_control_hash_not_relayed(behavioral):
    """Local-client origin: the fanout rule sends a PLAIN broadcast on every other
    interface, EXCEPT when the destination is a control hash. The control
    destination address is derived independently from its dotted name (real RNS
    hashing), and the non-control control case proves the fanout path is live, so
    the no-fanout for the control hash is attributable to the carve-out."""
    inst = behavioral.start(enable_transport=True)
    try:
        lc = inst.attach_mock_interface("lc", local_client=True)
        other = inst.attach_mock_interface("b", mode="FULL")

        # Positive control: a PLAIN broadcast to a non-control destination from a
        # local client fans out to the other interface byte-for-byte.
        noncontrol_dest = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        good = build_data_packet(
            behavioral.bridge, noncontrol_dest, destination_type="plain",
            payload=secrets.token_bytes(8), hops=0,
        )
        inst.inject(lc, good)
        fan = inst.drain_tx(other)
        assert any(p == good for p in fan), (
            "a PLAIN broadcast from a local client was NOT fanned out to the other "
            "interface — the relay path is dead, so the carve-out check below "
            "would be vacuous"
        )
        inst.drain_tx(lc)
        inst.drain_tx(other)

        # Negative: a PLAIN broadcast to a CONTROL destination must NOT be fanned
        # out. Payload length != 176 so the synthesize handler is a no-op (no
        # emission of its own to confound the assertion).
        control_dest = _plain_destination_hash(
            behavioral.bridge, TUNNEL_SYNTHESIZE_DESTINATION_NAME,
        )
        assert control_dest != noncontrol_dest
        control = build_data_packet(
            behavioral.bridge, control_dest, destination_type="plain",
            payload=secrets.token_bytes(8), hops=0,
        )
        inst.inject(lc, control)
        assert inst.drain_tx(other) == [], (
            "a PLAIN broadcast addressed to a control destination was fanned out — "
            "the control-hash carve-out (Transport.py:1519) is not enforced"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# 5. tunnel-synthesis-validation (partial): exact-length gate
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "inject", "read_tunnels",
              "identity_from_private_key", "identity_sign", "truncated_hash",
              "name_hash", "packet_build", "packet_unpack"],
    verifies=(
        "Tunnel-synthesize exact-length gate (Transport.py:2308-2309): the handler "
        "processes a synthesize payload ONLY when len(data) == 176 "
        "(KEYSIZE/8 + HASHLENGTH/8 + TRUNCATED_HASHLENGTH/8 + SIGLENGTH/8). A "
        "177-byte payload whose first 176 bytes are a fully-valid synthesize "
        "packet, and a 175-byte truncation of a valid packet, are BOTH silently "
        "ignored (their tunnel_ids never appear), while the exact 176-byte packet "
        "establishes its tunnel (the discriminating control). An impl using >= or "
        "<= instead of == would establish the over/under tunnels."
    ),
)
def test_tunnel_synthesize_exact_length_gate(behavioral):
    """Build three independent synthesize packets (distinct key material -> distinct
    tunnel_ids). The valid 176-byte one establishes; the 177-byte (valid prefix +
    1 byte) and 175-byte (valid minus last byte) ones do not. The exact length is
    the spec sum computed in-test, so the test discriminates the EXACT-equality
    gate, not merely 'too short' or 'too long'."""
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("rx", mode="FULL")

        # Exact 176-byte valid packet (positive control).
        good = build_tunnel_synthesize(behavioral.bridge)
        assert len(good["signed_data"] + good["signature"]) == _SYNTHESIZE_EXPECTED_LEN, (
            "builder produced a payload that is not the spec 176-byte length"
        )

        # Over: a DIFFERENT valid 176-byte payload + 1 trailing byte (177). Its
        # first 176 bytes are a complete, valid synthesize packet, so an impl that
        # checks len >= 176 (slicing the prefix) would establish over's tunnel.
        over_src = build_tunnel_synthesize(behavioral.bridge)
        over_payload = over_src["signed_data"] + over_src["signature"] + b"\x42"
        assert len(over_payload) == _SYNTHESIZE_EXPECTED_LEN + 1
        over_raw = build_data_packet(
            behavioral.bridge, over_src["destination_hash"],
            destination_type="plain", payload=over_payload, hops=0,
        )

        # Under: a DIFFERENT valid 176-byte payload truncated by one byte (175).
        under_src = build_tunnel_synthesize(behavioral.bridge)
        under_payload = (under_src["signed_data"] + under_src["signature"])[:-1]
        assert len(under_payload) == _SYNTHESIZE_EXPECTED_LEN - 1
        under_raw = build_data_packet(
            behavioral.bridge, under_src["destination_hash"],
            destination_type="plain", payload=under_payload, hops=0,
        )

        # All three tunnel_ids are distinct, so establishment of any one is
        # individually attributable.
        ids = {good["tunnel_id"].hex(), over_src["tunnel_id"].hex(),
                under_src["tunnel_id"].hex()}
        assert len(ids) == 3, "fresh builders must mint distinct key material"

        inst.inject(iface, over_raw)
        inst.inject(iface, under_raw)
        inst.inject(iface, good["raw"])

        established = {t["tunnel_id"] for t in inst.read_tunnels()["tunnels"]}
        assert good["tunnel_id"].hex() in established, (
            "the exact 176-byte synthesize packet did NOT establish a tunnel — the "
            "over/under negatives below would be vacuous"
        )
        assert over_src["tunnel_id"].hex() not in established, (
            "a 177-byte synthesize payload (valid 176-byte prefix + 1 byte) "
            "established a tunnel — the exact-length gate (Transport.py:2309) "
            "accepts over-length payloads"
        )
        assert under_src["tunnel_id"].hex() not in established, (
            "a 175-byte (truncated) synthesize payload established a tunnel — the "
            "exact-length gate accepts under-length payloads"
        )
    finally:
        behavioral.cleanup()
