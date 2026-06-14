"""
Behavioral tests: Transport inbound forwarding gates that previously had no
bridge observable (transport_forwarding subsystem).

Three RNS Transport.inbound / packet_filter behaviors are covered, each verified
against the RNS 1.3.1 source (Transport.py) and exercised end-to-end through the
real RNS.Transport.inbound — no filtering / masking / hashing logic is
reimplemented in the harness:

  * inbound-ifac-gating (Transport.py:1399-1445) — when an interface has IFAC
    (Interface Access Codes) configured, every received frame must carry the
    IFAC header flag AND be long enough to contain the access code, and the
    embedded access code must match the one RNS recomputes from the unmasked
    frame. A correctly IFAC-masked frame is accepted; a frame whose length is
    <= 2+ifac_size is silently dropped (the `else: return` at :1402); an
    unmasked (flag-clear) frame on an IFAC interface is dropped (the `else:
    return` at :1435). The identical unmasked frame on a NON-IFAC interface is
    accepted, proving it is the IFAC gate — not the packet itself — doing the
    dropping.

  * dedup-deferral / LRPROOF (Transport.py:1496-1504) — inbound forces
    remember_packet_hash=False for a PROOF packet whose context is LRPROOF, so
    its hash is NOT added to Transport.packet_hashlist; a normal DATA packet IS
    remembered. (A link-request proof must not be filtered until the routing
    chain is resolved.)

  * dedup-deferral / link-table (Transport.py:1496-1498) — inbound forces
    remember_packet_hash=False when the destination is already a key in
    Transport.link_table (the packet may be seen on a shared-medium interface
    before it would normally reach us); a DATA packet to a non-link destination
    IS remembered.

  * shared-client-no-filtering (Transport.py:1337/:1376) — when
    Transport.owner.is_connected_to_shared_instance is True, packet_filter
    short-circuits to True (the shared master does the filtering) and
    add_packet_hash is a no-op, so a replayed DATA packet and a foreign-
    transport_id HEADER_2 packet that a standalone node DROPS are both accepted.

All assertions are anchored on the RNS spec literals above (accept vs drop, the
specific drop site, and the standalone counter-behavior), never on
implementation-vs-itself.
"""

import secrets

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    context_offset,
    HEADER_2,
    TRANSPORT_TRANSPORT,
    TRUNCATED_HASH_BYTES,
)


__category_title__ = "Transport Behavior"
__category_order__ = 19


# RNS.Packet context for a link-request proof (RNS/Packet.py: LRPROOF == 0xFF).
# Verified at runtime: RNS.Packet.LRPROOF == 255.
LRPROOF = 0xFF

# RNS.Packet types (RNS/Packet.py).
PACKET_TYPE_DATA = 0
PACKET_TYPE_PROOF = 3


def _promote_to_header2(raw: bytes, transport_id: bytes) -> bytes:
    """Reshape a packed HEADER_1 packet into the HEADER_2 transport-relay form
    (flags|hops|transport_id(16)|dest(16)|ctx|data), the exact layout RNS emits
    when relaying a packet to a next hop (RNS/Packet.py pack:206-229). Header
    reshuffle only; the packet hash (excludes hops + transport_id) is unchanged.
    This is pure test-side byte work — the underlying packet was produced by real
    RNS.Packet.pack via the bridge's packet_build."""
    assert len(transport_id) == TRUNCATED_HASH_BYTES
    flags = (raw[0] | (HEADER_2 << 6) | (TRANSPORT_TRANSPORT << 4)) & 0xFF
    return bytes([flags, raw[1]]) + bytes(transport_id) + raw[2:]


@conformance_case(
    commands=["start", "attach_mock_interface", "packet_build", "ifac_mask",
              "inbound_remembered"],
    verifies=(
        "On an interface with IFAC configured (network_name+passphrase), a "
        "correctly IFAC-masked frame is accepted by Transport.inbound while a "
        "frame whose length is <= 2+ifac_size is silently dropped "
        "(Transport.py:1402) and an unmasked (IFAC-flag-clear) frame is dropped "
        "(Transport.py:1435); the identical unmasked frame on a non-IFAC "
        "interface is accepted, isolating the IFAC gate as the cause"
    ),
)
def test_ifac_gate_accepts_masked_drops_short_and_unmasked(behavioral):
    """Transport.inbound IFAC authentication (Transport.py:1399-1445). The
    accept signal is that a SINGLE DATA packet, once it clears the IFAC gate, is
    remembered in Transport.packet_hashlist (hashlist grows); a dropped frame
    never reaches the hashing step."""
    inst = behavioral.start()
    try:
        ifac = inst.attach_ifac_interface(
            "ifac-net", ifac_netname="conformance-net", ifac_netkey="s3cr3t",
        )
        ifac_id = ifac["iface_id"]
        ifac_size = ifac["ifac_size"]
        assert ifac_size > 0, "IFAC interface must report a non-zero access-code size"
        plain_id = inst.attach_mock_interface("plain-net")

        # A genuine SINGLE DATA packet, built by real RNS.Packet.pack.
        built = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
            data=secrets.token_bytes(16).hex(),
        )
        raw = bytes.fromhex(built["raw"])

        # Mask it for the IFAC interface via real RNS.Transport.transmit.
        masked = inst.ifac_mask(ifac_id, raw)
        assert masked[0] & 0x80 == 0x80, (
            "RNS.Transport.transmit must set the IFAC header flag on a masked frame"
        )
        assert len(masked) == len(raw) + ifac_size, (
            "masked frame must grow by exactly ifac_size (the inserted access code)"
        )

        # POSITIVE: the correctly-masked frame clears the IFAC gate and is
        # processed (its hash is remembered).
        accepted = inst.inbound_remembered(ifac_id, masked)
        assert accepted["hashlist_grew"] is True, (
            "a correctly IFAC-masked frame was NOT accepted by inbound on its "
            "IFAC interface (IFAC authentication wrongly rejected a valid frame)"
        )

        # NEGATIVE 1: truncate the masked frame to <= 2+ifac_size. Transport.py
        # :1402 takes the `else: return` (too short to contain the IFAC) BEFORE
        # any hashing, so nothing is remembered.
        short = masked[: 2 + ifac_size]
        dropped_short = inst.inbound_remembered(ifac_id, short)
        assert dropped_short["hashlist_grew"] is False, (
            "a frame too short to contain the IFAC (len <= 2+ifac_size) must be "
            "silently dropped at Transport.py:1402, not processed"
        )

        # NEGATIVE 2: an unmasked, IFAC-flag-clear frame on the IFAC interface.
        # Transport.py:1435 `else: return` drops it (flag not set, but required).
        built2 = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
            data=secrets.token_bytes(16).hex(),
        )
        raw2 = bytes.fromhex(built2["raw"])
        assert raw2[0] & 0x80 == 0, "control packet must not have the IFAC flag set"
        dropped_unmasked = inst.inbound_remembered(ifac_id, raw2)
        assert dropped_unmasked["hashlist_grew"] is False, (
            "an unmasked (IFAC-flag-clear) frame on an IFAC interface must be "
            "dropped at Transport.py:1435"
        )

        # CONTROL: the SAME unmasked frame on a NON-IFAC interface is accepted —
        # proving the drop above is the IFAC gate, not the packet itself.
        accepted_plain = inst.inbound_remembered(plain_id, raw2)
        assert accepted_plain["hashlist_grew"] is True, (
            "the identical unmasked frame was rejected on a non-IFAC interface "
            "too — the packet is malformed rather than IFAC-gated"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "packet_build",
              "inbound_remembered"],
    verifies=(
        "Transport.inbound does NOT remember the hash of a PROOF packet whose "
        "context is LRPROOF (link-request-proof deferral, Transport.py:1499-"
        "1504), while it DOES remember a normal DATA packet's hash"
    ),
)
def test_lrproof_hash_is_deferred_data_is_remembered(behavioral):
    """The LRPROOF inbound deferral (Transport.py:1499-1504): a link-request
    proof must not be added to packet_hashlist until the routing chain is
    resolved, so its hash is NOT remembered; a DATA packet is. Anchored on the
    structural rule (packet_type==PROOF and context==LRPROOF), with a DATA
    control packet to prove inbound otherwise remembers."""
    inst = behavioral.start()
    try:
        iface_id = inst.attach_mock_interface("i1")

        # Control: a normal SINGLE DATA packet IS remembered by inbound.
        data_built = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
            data=secrets.token_bytes(16).hex(),
        )
        data_raw = bytes.fromhex(data_built["raw"])
        data_res = inst.inbound_remembered(iface_id, data_raw)
        assert data_res["in_hashlist"] is True and data_res["hashlist_grew"] is True, (
            "a normal DATA packet's hash must be remembered by inbound "
            "(Transport.py:1502-1503)"
        )

        # A PROOF packet with its context byte patched to LRPROOF. The context
        # is a header-only field (offset 18 for HEADER_1); patching it in the
        # test does not touch the bytes RNS.Packet.pack produced for the rest of
        # the packet. inbound must NOT remember it.
        proof_built = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=PACKET_TYPE_PROOF,
            data=(b"\x00" * 96).hex(),
        )
        proof_raw = bytearray(bytes.fromhex(proof_built["raw"]))
        proof_raw[context_offset(proof_raw)] = LRPROOF
        proof_raw = bytes(proof_raw)

        lrproof_res = inst.inbound_remembered(iface_id, proof_raw)
        assert lrproof_res["unpackable"] is True, (
            "the LRPROOF packet must still be a well-formed packet"
        )
        assert lrproof_res["in_hashlist"] is False and lrproof_res["hashlist_grew"] is False, (
            "a PROOF packet with context==LRPROOF must NOT be added to the "
            "packet_hashlist (deferral at Transport.py:1499-1504); this impl "
            "remembered it, which would break link transport"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "attach_mock_interface", "packet_build",
              "seed_link_table", "inbound_remembered"],
    verifies=(
        "Transport.inbound does NOT remember the hash of a DATA packet whose "
        "destination is already a key in Transport.link_table (link-transport "
        "deferral, Transport.py:1496-1498), while a DATA packet to a non-link "
        "destination IS remembered"
    ),
)
def test_link_table_destination_packet_is_deferred(behavioral):
    """The link-table inbound deferral (Transport.py:1496-1498): a packet whose
    destination is in link_table may be seen on a shared-medium interface before
    it would normally reach us, so its hash is deferred (not remembered) at the
    initial filter step. Seeded with hop counts that do NOT match the injected
    packet, so the later link-transport branch (Transport.py:1644-1679) does not
    re-add the hash either — isolating the deferral as the sole reason."""
    inst = behavioral.start()
    try:
        nh_id = inst.attach_mock_interface("nh")
        rcvd_id = inst.attach_mock_interface("rcvd")

        # Build a SINGLE DATA packet and aim it at a link destination by
        # overwriting the (header-only, unsigned) 16-byte destination_hash.
        built = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
            data=secrets.token_bytes(16).hex(),
        )
        link_dest = secrets.token_bytes(TRUNCATED_HASH_BYTES)
        raw = bytearray(bytes.fromhex(built["raw"]))
        raw[2 : 2 + TRUNCATED_HASH_BYTES] = link_dest
        raw = bytes(raw)

        # Control: BEFORE seeding link_table, this packet IS remembered.
        before = inst.inbound_remembered(nh_id, raw)
        assert before["in_hashlist"] is True and before["hashlist_grew"] is True, (
            "a DATA packet to a non-link destination must be remembered by "
            "inbound (control for the deferral)"
        )

        # Now seed link_table[link_dest] and inject a FRESH packet to the same
        # destination. The deferral must keep it out of the hashlist.
        inst.seed_link_table(link_dest, nh_id, rcvd_id, rem_hops=99, hops=99)
        built2 = behavioral.bridge.execute(
            "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
            data=secrets.token_bytes(16).hex(),
        )
        raw2 = bytearray(bytes.fromhex(built2["raw"]))
        raw2[2 : 2 + TRUNCATED_HASH_BYTES] = link_dest
        raw2 = bytes(raw2)

        deferred = inst.inbound_remembered(nh_id, raw2)
        assert deferred["in_hashlist"] is False and deferred["hashlist_grew"] is False, (
            "a DATA packet whose destination is in link_table must NOT be "
            "remembered at the inbound filter step (deferral at "
            "Transport.py:1496-1498); this impl remembered it"
        )
    finally:
        behavioral.cleanup()


@conformance_case(
    commands=["start", "packet_build", "packet_unpack", "packet_filter"],
    verifies=(
        "When Transport.owner.is_connected_to_shared_instance is True, "
        "packet_filter short-circuits to True (Transport.py:1337): a replayed "
        "DATA packet and a foreign-transport_id HEADER_2 packet are BOTH "
        "accepted, whereas a standalone node drops the replay (hashlist) and "
        "the foreign-transport_id packet (Transport.py:1340-1343)"
    ),
)
def test_shared_instance_bypasses_packet_filter(behavioral):
    """The shared-instance bypass (Transport.py:1337/:1376). A standalone node
    filters: it drops a byte-identical DATA replay and a HEADER_2 packet whose
    transport_id is not ours. A node connected to a shared instance defers all
    filtering to the master, so packet_filter returns True for both. The two
    starts are sequential (the predicate lives on the shared Transport.owner);
    all standalone assertions complete before the shared instance flips it."""
    # --- standalone node: filtering is ACTIVE ---
    standalone = behavioral.start()

    data_built = behavioral.bridge.execute(
        "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
        data=secrets.token_bytes(16).hex(),
    )
    data_raw = bytes.fromhex(data_built["raw"])

    # Foreign-transport_id HEADER_2 DATA packet (transport_id != our identity).
    h2_built = behavioral.bridge.execute(
        "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
        data=secrets.token_bytes(16).hex(),
    )
    foreign_tid = secrets.token_bytes(TRUNCATED_HASH_BYTES)
    h2_raw = _promote_to_header2(bytes.fromhex(h2_built["raw"]), foreign_tid)
    parsed = behavioral.bridge.execute("packet_unpack", raw=h2_raw.hex())
    assert parsed["unpacked"] and parsed["transport_id"] == foreign_tid.hex(), (
        "HEADER_2 promotion must yield a packet RNS unpacks with the foreign "
        "transport_id"
    )

    first = standalone.packet_filter(data_raw, remember=True)
    replay = standalone.packet_filter(data_raw, remember=True)
    assert first["accepted"] is True and replay["accepted"] is False, (
        "standalone node must drop a byte-identical DATA replay (hashlist)"
    )
    foreign_standalone = standalone.packet_filter(h2_raw, remember=False)
    assert foreign_standalone["accepted"] is False, (
        "standalone node must drop a HEADER_2 packet addressed to another "
        "transport instance (Transport.py:1340-1343)"
    )

    # --- shared instance: filtering is BYPASSED ---
    shared = behavioral.start(connected_to_shared_instance=True)

    shared_data = behavioral.bridge.execute(
        "packet_build", dest_type="single", packet_type=PACKET_TYPE_DATA,
        data=secrets.token_bytes(16).hex(),
    )
    shared_data_raw = bytes.fromhex(shared_data["raw"])

    s_first = shared.packet_filter(shared_data_raw, remember=True)
    s_replay = shared.packet_filter(shared_data_raw, remember=True)
    assert s_first["accepted"] is True and s_replay["accepted"] is True, (
        "a node connected to a shared instance must NOT hashlist-dedup; "
        "packet_filter must return True on replay (Transport.py:1337/:1376)"
    )
    foreign_shared = shared.packet_filter(h2_raw, remember=False)
    assert foreign_shared["accepted"] is True, (
        "a node connected to a shared instance must accept a foreign-"
        "transport_id packet (filtering deferred to the master, "
        "Transport.py:1337)"
    )
    behavioral.cleanup()
