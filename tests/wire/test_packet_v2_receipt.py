"""PacketReceipt — V2 gap-closing (timeout arithmetic + non-DATA suppression).

Two RNS 1.3.1 PacketReceipt / Transport.outbound rules the V2 re-evaluation left
uncovered or partial, observed on a live instance via the
packet_receipt_timeout / packet_receipt_generation bridge commands (each builds a
real RNS.Packet / RNS.PacketReceipt and reads the field straight off RNS). Every
assertion anchors on an EXTERNAL spec literal — the documented timeout formula and
its constituent constants, or the documented gate clauses — never on the impl
reading back its own output.

Gaps addressed (CONFORMANCE_COMPLETENESS_V2 §4, packet subsystem):
  * receipt-timeout-defaults — a non-link PacketReceipt's timeout is
    get_first_hop_timeout(dest) + Packet.TIMEOUT_PER_HOP * Transport.hops_to(dest)
    (Packet.py:433-434); for a fresh path-less destination on a standalone
    instance that is DEFAULT_PER_HOP_TIMEOUT(6) + TIMEOUT_PER_HOP(6) *
    PATHFINDER_M(128) == 774. The timeout==-1 -> CULLED vs (finite) -> FAILED
    transition in check_timeout (Packet.py:561-565) is pinned alongside.
  * receipt-generation-conditions (packet_type clause) — Transport.outbound's
    generate_receipt gate requires the packet to be DATA (Transport.py:1097): an
    ANNOUNCE / LINKREQUEST / PROOF packet with create_receipt=True gets NO receipt
    even on a SINGLE destination with a non-special context and a real transmit.

Runs reference-vs-reference; the receipt/timeout values come from real RNS on the
peer, and every assertion pins them against the restated spec.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


# RNS 1.3.1 spec literals (the EXTERNAL ground truth, NOT read from the impl).
_DEFAULT_PER_HOP_TIMEOUT = 6     # RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
_TIMEOUT_PER_HOP = 6             # RNS.Packet.TIMEOUT_PER_HOP (== DEFAULT_PER_HOP_TIMEOUT)
_PATHFINDER_M = 128             # RNS.Transport.PATHFINDER_M (max hops / unknown-path)
_EXPECTED_DEFAULT_TIMEOUT = _DEFAULT_PER_HOP_TIMEOUT + _TIMEOUT_PER_HOP * _PATHFINDER_M  # 774

_STATUS_FAILED = 0x00            # RNS.PacketReceipt.FAILED
_STATUS_SENT = 0x01             # RNS.PacketReceipt.SENT
_STATUS_CULLED = 0xFF           # RNS.PacketReceipt.CULLED

# Packet-type code points (RNS.Packet) for the non-DATA suppression clause.
_PT_ANNOUNCE = 0x01
_PT_LINKREQUEST = 0x02
_PT_PROOF = 0x03
_CTX_NONE = 0x00


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "packet_receipt_timeout"],
    verifies=(
        "A non-link RNS.PacketReceipt computes its timeout as "
        "get_first_hop_timeout(dest) + Packet.TIMEOUT_PER_HOP * "
        "Transport.hops_to(dest) (Packet.py:433-434). For a fresh, path-less "
        "destination on a standalone instance the constituents are pinned to their "
        "spec literals — get_first_hop_timeout == DEFAULT_PER_HOP_TIMEOUT(6) (no "
        "learned latency) and hops_to == PATHFINDER_M(128) (path unknown) — so the "
        "receipt timeout equals 6 + 6*128 == 774 exactly, recomputed from the "
        "documented formula and constants, not read back from the impl. The "
        "receipt also starts SENT, and check_timeout drives a timed-out receipt to "
        "CULLED iff timeout==-1 and to FAILED for a finite timeout "
        "(Packet.py:561-565). An impl with a different per-hop timeout, hop-cap, or "
        "CULLED/FAILED rule diverges"
    ),
)
def test_packet_receipt_timeout_defaults(wire_pair_started):
    _server, client = wire_pair_started

    base = client.packet_receipt_timeout()

    # The instance must be standalone for the default arithmetic to hold (a shared
    # instance would RPC a learned first-hop timeout instead of the default).
    assert base["is_connected_to_shared"] is False, (
        f"expected a standalone instance for the default timeout: {base!r}"
    )
    assert base["is_link"] is False, f"expected a non-link receipt: {base!r}"

    # Constituent constants match the spec literals.
    assert base["default_per_hop_timeout"] == _DEFAULT_PER_HOP_TIMEOUT, base
    assert base["timeout_per_hop"] == _TIMEOUT_PER_HOP, base
    assert base["pathfinder_m"] == _PATHFINDER_M, base
    # A fresh destination has no learned path: first-hop falls back to the default
    # per-hop timeout and hops_to falls back to the max-hop sentinel.
    assert base["first_hop_timeout"] == _DEFAULT_PER_HOP_TIMEOUT, (
        f"path-less first_hop_timeout must be DEFAULT_PER_HOP_TIMEOUT: {base!r}"
    )
    assert base["hops_to"] == _PATHFINDER_M, (
        f"path-less hops_to must be PATHFINDER_M: {base!r}"
    )
    # The receipt timeout equals the documented formula evaluated on the literals.
    assert base["timeout"] == _EXPECTED_DEFAULT_TIMEOUT, (
        f"PacketReceipt.timeout must be DEFAULT_PER_HOP_TIMEOUT + TIMEOUT_PER_HOP * "
        f"PATHFINDER_M = {_EXPECTED_DEFAULT_TIMEOUT}, got {base['timeout']}"
    )
    # Independent reconstruction from THIS receipt's own reported constituents
    # (proves the value is the formula, not a coincidence at 774).
    assert base["timeout"] == (
        base["first_hop_timeout"] + base["timeout_per_hop"] * base["hops_to"]
    ), f"timeout != first_hop_timeout + TIMEOUT_PER_HOP * hops_to: {base!r}"
    # A fresh receipt starts SENT.
    assert base["status"] == _STATUS_SENT, f"fresh receipt not SENT: {base!r}"

    # check_timeout: timeout == -1 -> CULLED.
    culled = client.packet_receipt_timeout(force_timeout=-1)
    assert culled["status_culled"] == _STATUS_CULLED, culled
    assert culled["forced_status"] == _STATUS_CULLED, (
        f"a timed-out receipt with timeout==-1 must become CULLED: {culled!r}"
    )

    # check_timeout: a finite (timed-out) timeout -> FAILED, NOT CULLED.
    failed = client.packet_receipt_timeout(force_timeout=0)
    assert failed["status_failed"] == _STATUS_FAILED, failed
    assert failed["forced_status"] == _STATUS_FAILED, (
        f"a timed-out receipt with a finite timeout must become FAILED: {failed!r}"
    )
    assert failed["forced_status"] != culled["forced_status"], (
        "the CULLED(timeout==-1) and FAILED(finite) branches must differ"
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "packet_receipt_generation"],
    verifies=(
        "Transport.outbound's generate_receipt gate requires the packet to be DATA "
        "(Transport.py:1097): with create_receipt=True on a SINGLE destination and "
        "the NONE context, a DATA packet DOES get a PacketReceipt, but an ANNOUNCE, "
        "a LINKREQUEST, and a PROOF packet each get NO receipt — even though every "
        "one is actually transmitted (sent=True), so the absent receipt is the "
        "packet-type clause firing, not a failed send. An impl that attached a "
        "receipt to an announce/link-request/proof would track deliveries that "
        "never produce a proof"
    ),
)
def test_receipt_generation_packet_type_clause(wire_pair_started):
    _server, client = wire_pair_started

    # Positive control: a SINGLE DATA NONE packet gets a receipt (and transmits).
    base = client.packet_receipt_generation(dest_type="single", context=_CTX_NONE)
    assert base["sent"] is True, f"SINGLE DATA NONE was not transmitted: {base!r}"
    assert base["create_receipt_flag"] is True, f"create_receipt not set: {base!r}"
    assert base["has_receipt"] is True, (
        f"a SINGLE DATA NONE packet must get a PacketReceipt: {base!r}"
    )

    # Negatives: a non-DATA packet on the SAME SINGLE destination + NONE context
    # gets NO receipt, while still being transmitted.
    for packet_type, name in (
        (_PT_ANNOUNCE, "ANNOUNCE"),
        (_PT_LINKREQUEST, "LINKREQUEST"),
        (_PT_PROOF, "PROOF"),
    ):
        res = client.packet_receipt_generation(
            dest_type="single", context=_CTX_NONE, packet_type=packet_type,
        )
        assert res["packet_type"] == packet_type, (
            f"{name}: bridge built the wrong packet_type: {res!r}"
        )
        assert res["sent"] is True, (
            f"{name}: packet must still be transmitted (else has_receipt is "
            f"meaningless): {res!r}"
        )
        assert res["create_receipt_flag"] is True, (
            f"{name}: create_receipt must be set: {res!r}"
        )
        assert res["has_receipt"] is False, (
            f"{name}: Transport.outbound must NOT attach a receipt to a non-DATA "
            f"packet: {res!r}"
        )
