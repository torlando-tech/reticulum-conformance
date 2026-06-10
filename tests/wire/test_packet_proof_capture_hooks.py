"""Packet-proof capture conformance (Opus wave-2, gap-closing).

Four RNS proof-path rules that the first harness pass reached but could not
observe without an extra capture/inject hook. Each anchors on an EXTERNAL spec
literal (the RNS wire layout / proof-format / receipt-generation rules), not on
the implementation reading back its own output:

  * lrproof-special-packing — RNS.Packet.get_packed_flags special-cases an
    LRPROOF (context 0xFF): it forces the destination-type bits to LINK (0b11)
    and pack() writes the link_id in the destination-address position instead of
    a destination hash (Packet.py:169-184). The reference link-establishment path
    never exposes these bytes.
  * link-packet-proofs-explicit-only — a link DATA packet's proof is validated by
    PacketReceipt.validate_link_proof, which accepts ONLY the 96-byte EXPLICIT
    form; the 64-byte IMPLICIT branch is disabled (Packet.py:478-493), so even a
    valid-signature implicit proof is rejected.
  * explicit-proof-format — the single-packet validate_proof ACCEPTS a spec-
    conformant 96-byte EXPLICIT proof (packet_hash||signature) signed by the
    destination's identity (Packet.py:498-521); the cross-process harness can
    never sign a valid one, so this positive acceptance was untested.
  * receipt-generation-conditions — Transport.outbound suppresses a PacketReceipt
    (even with create_receipt=True) for PLAIN destinations and for link-control /
    resource contexts (Transport.py:1094-1113).

Runs reference-vs-reference; the proof/receipt bytes come from real RNS on the
peer, and every assertion pins them against the restated spec.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


# --- RNS wire / proof constants (external ground truth, restated) -----------
_HEADER_1 = 0                 # RNS.Packet.HEADER_1
_PT_PROOF = 0x03              # RNS.Packet.PROOF packet-type bits
_CTX_LRPROOF = 0xFF           # RNS.Packet.LRPROOF
_CTX_NONE = 0x00              # RNS.Packet.NONE
_CTX_KEEPALIVE = 0xFA         # RNS.Packet.KEEPALIVE (low end of the link band)
_CTX_LRRTT = 0xFE             # RNS.Packet.LRRTT (high end, packable on non-link)
_CTX_RESOURCE = 0x01          # RNS.Packet.RESOURCE (low end of the resource band)
_DEST_LINK = 0x03             # RNS.Destination.LINK destination-type bits
_EXPL_LENGTH = 96             # RNS.Identity.HASHLENGTH//8 + SIGLENGTH//8
_IMPL_LENGTH = 64             # RNS.Identity.SIGLENGTH//8


def _decode_flags(flags: int) -> dict:
    """Decode the fixed bit fields of an RNS flag byte (Packet.py:243-251)."""
    return {
        "header_type": (flags & 0b01000000) >> 6,
        "destination_type": (flags & 0b00001100) >> 2,
        "packet_type": (flags & 0b00000011),
    }


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "capture_lrproof_frame"],
    verifies=(
        "An LRPROOF (link-request proof) frame has the RNS-mandated special wire "
        "shape (Packet.get_packed_flags / pack, Packet.py:169-184): the flag "
        "byte's destination-type bits are forced to LINK (0b11) and the packet-"
        "type bits are PROOF, the header is HEADER_1, the context byte is 0xFF "
        "(LRPROOF), and the 16 bytes in the destination-address position are the "
        "link_id (not a truncated destination hash). An impl that packs an "
        "LRPROOF with the underlying destination's type bits or writes a dest "
        "hash instead of the link_id would mis-shape the frame"
    ),
)
def test_lrproof_special_packing(wire_pair_started):
    _server, client = wire_pair_started

    cap = client.capture_lrproof_frame()
    raw = cap["raw"]
    assert isinstance(raw, (bytes, bytearray)) and len(raw) >= 2 + 16 + 1, (
        f"no LRPROOF frame captured: {cap!r}"
    )

    # The bridge echoes the SUT's own constants; pin them to the spec literals
    # so the decode below is anchored externally, not on the impl's values.
    assert cap["packet_type"] == _PT_PROOF, f"PROOF type bits != 0x03: {cap!r}"
    assert cap["context"] == _CTX_LRPROOF, f"LRPROOF context != 0xFF: {cap!r}"
    assert cap["expected_link_dest_type"] == _DEST_LINK, (
        f"RNS.Destination.LINK != 0x03: {cap!r}"
    )
    assert cap["truncated_hashlength"] == 16, f"TRUNCATED_HASHLENGTH//8 != 16: {cap!r}"

    f = _decode_flags(raw[0])
    assert f["destination_type"] == _DEST_LINK, (
        f"LRPROOF dest-type bits != LINK (0b11): {f!r} (raw flags 0x{raw[0]:02x})"
    )
    assert f["packet_type"] == _PT_PROOF, f"LRPROOF packet-type bits != PROOF: {f!r}"
    assert f["header_type"] == _HEADER_1, f"LRPROOF must be HEADER_1: {f!r}"

    # Context byte sits after flags(1) || hops(1) || link_id(16).
    assert raw[2 + 16] == _CTX_LRPROOF, (
        f"context byte after the link_id != 0xFF: got 0x{raw[2 + 16]:02x}"
    )
    # The destination-address position holds the link_id, not a dest hash.
    assert raw[2:2 + 16] == cap["link_id"], (
        f"LRPROOF destination-position bytes != link_id: "
        f"{raw[2:2 + 16].hex()} != {cap['link_id'].hex()}"
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "inject_crafted_link_proof"],
    verifies=(
        "Link DATA packet proofs are EXPLICIT-only "
        "(PacketReceipt.validate_link_proof, Packet.py:450-495): a 96-byte "
        "EXPLICIT proof (packet_hash||signature) with a valid signature is "
        "ACCEPTED and drives the receipt to DELIVERED, but a 64-byte IMPLICIT "
        "proof — even one carrying a genuinely VALID signature over the same "
        "packet hash — is REJECTED (the implicit branch is disabled), as is a "
        "32-byte under-length proof, leaving the receipt SENT. Pairing the "
        "valid-signature implicit rejection with the explicit acceptance proves "
        "it is the proof FORM being enforced, not merely the signature. An impl "
        "that honored implicit link proofs would accept a short forged blob"
    ),
)
def test_link_packet_proofs_explicit_only(wire_pair_started):
    _server, client = wire_pair_started

    # Positive: a genuine 96-byte EXPLICIT proof validates and delivers.
    ok = client.inject_crafted_link_proof("valid_explicit")
    assert ok["expl_length"] == _EXPL_LENGTH and ok["impl_length"] == _IMPL_LENGTH, (
        f"RNS proof-length constants drifted: {ok!r}"
    )
    assert ok["proof_len"] == _EXPL_LENGTH, f"explicit proof must be 96B: {ok!r}"
    assert ok["validated"] is True, (
        f"a valid 96-byte EXPLICIT link proof was not accepted: {ok!r}"
    )
    assert ok["status_name"] == "DELIVERED", (
        f"explicit link proof must drive the receipt to DELIVERED: {ok!r}"
    )

    # Negative 1: a 64-byte IMPLICIT proof with a VALID signature is rejected —
    # links require the explicit form regardless of signature validity.
    impl = client.inject_crafted_link_proof("implicit_valid_sig")
    assert impl["proof_len"] == _IMPL_LENGTH, f"implicit proof must be 64B: {impl!r}"
    assert impl["validated"] is False, (
        f"a 64-byte implicit link proof (valid sig) was ACCEPTED — the link "
        f"layer is not enforcing the explicit-only form: {impl!r}"
    )
    assert impl["status_name"] == "SENT", (
        f"receipt must stay SENT after a rejected implicit proof: {impl!r}"
    )

    # Negative 2/3: random 64-byte and 32-byte proofs are rejected too.
    for variant, why in (
        ("implicit_random", "64 random bytes"),
        ("wrong_length_short", "32-byte under-length"),
    ):
        res = client.inject_crafted_link_proof(variant)
        assert res["validated"] is False, f"{variant} ({why}) was accepted: {res!r}"
        assert res["status_name"] == "SENT", (
            f"{variant}: receipt must stay SENT: {res!r}"
        )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "inject_single_proof_format"],
    verifies=(
        "RNS.PacketReceipt.validate_proof ACCEPTS a spec-conformant single-packet "
        "PROOF for a SINGLE destination (Packet.py:498-549): a 96-byte EXPLICIT "
        "proof (packet_hash(32)||signature(64)) and a 64-byte IMPLICIT proof "
        "(signature(64)), both signed by the destination's identity over the "
        "receipt's packet hash, validate and drive the receipt to DELIVERED. The "
        "same explicit proof signed under the WRONG key, or one whose leading "
        "32-byte proof-hash != the receipt hash, is REJECTED. This pins the "
        "positive 96-byte EXPLICIT acceptance the cross-process harness can never "
        "sign; an impl that rejected a valid explicit proof would never confirm "
        "delivery"
    ),
)
def test_explicit_proof_format_accepted(wire_pair_started):
    _server, client = wire_pair_started

    # Positive: a genuinely-valid 96-byte EXPLICIT proof is accepted.
    expl = client.inject_single_proof_format("valid_explicit")
    assert expl["expl_length"] == _EXPL_LENGTH and expl["impl_length"] == _IMPL_LENGTH, (
        f"RNS proof-length constants drifted: {expl!r}"
    )
    assert expl["proof_len"] == _EXPL_LENGTH, f"explicit proof must be 96B: {expl!r}"
    assert expl["validated"] is True, (
        f"a valid 96-byte EXPLICIT single-packet proof was not accepted: {expl!r}"
    )
    assert expl["status_name"] == "DELIVERED", (
        f"explicit proof must drive the receipt to DELIVERED: {expl!r}"
    )

    # Positive: the implicit form is also honored for a non-link receipt.
    impl = client.inject_single_proof_format("valid_implicit")
    assert impl["proof_len"] == _IMPL_LENGTH, f"implicit proof must be 64B: {impl!r}"
    assert impl["validated"] is True, (
        f"a valid 64-byte IMPLICIT single-packet proof was not accepted: {impl!r}"
    )
    assert impl["status_name"] == "DELIVERED", (
        f"implicit proof must drive the receipt to DELIVERED: {impl!r}"
    )

    # Negatives: wrong-key signature and wrong proof-hash are rejected.
    for variant, why in (
        ("forged_explicit", "96-byte proof signed under the WRONG key"),
        ("wrong_hash_explicit", "96-byte proof whose hash != receipt hash"),
    ):
        res = client.inject_single_proof_format(variant)
        assert res["validated"] is False, f"{variant} ({why}) was accepted: {res!r}"
        assert res["status_name"] == "SENT", (
            f"{variant}: receipt must stay SENT after rejection: {res!r}"
        )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "packet_receipt_generation"],
    verifies=(
        "Transport.outbound suppresses a PacketReceipt — even with "
        "create_receipt=True — for packets that are not eligible "
        "(Transport.py:1094-1113): a SINGLE DATA NONE packet DOES get a receipt, "
        "but a PLAIN destination gets none, and the link-control contexts "
        "(KEEPALIVE 0xFA .. LRPROOF 0xFF) and resource contexts (RESOURCE 0x01 .. "
        "RESOURCE_RCL 0x07) get none. Every packet is actually transmitted "
        "(sent=True), so the absent receipt is the gate firing, not a failed "
        "send. An impl that attaches a receipt to a PLAIN or link/resource packet "
        "would track deliveries that never produce a proof"
    ),
)
def test_receipt_generation_conditions(wire_pair_started):
    _server, client = wire_pair_started

    # Positive control: a SINGLE DATA NONE packet gets a receipt (and transmits).
    base = client.packet_receipt_generation(dest_type="single", context=_CTX_NONE)
    assert base["sent"] is True, f"SINGLE NONE packet was not transmitted: {base!r}"
    assert base["create_receipt_flag"] is True, f"create_receipt not set: {base!r}"
    assert base["has_receipt"] is True, (
        f"a SINGLE DATA NONE packet must get a PacketReceipt: {base!r}"
    )

    # Negatives: PLAIN destination + link-control + resource contexts get none,
    # while still being transmitted (so has_receipt False is the gate, not a
    # dropped send).
    cases = (
        ("plain", _CTX_NONE, "PLAIN destination"),
        ("single", _CTX_KEEPALIVE, "KEEPALIVE 0xFA (link-control band)"),
        ("single", _CTX_LRRTT, "LRRTT 0xFE (link-control band)"),
        ("single", _CTX_RESOURCE, "RESOURCE 0x01 (resource band)"),
    )
    for dest_type, context, why in cases:
        res = client.packet_receipt_generation(dest_type=dest_type, context=context)
        assert res["sent"] is True, (
            f"{why}: packet must still be transmitted (else has_receipt is "
            f"meaningless): {res!r}"
        )
        assert res["has_receipt"] is False, (
            f"{why}: Transport.outbound must NOT attach a receipt here: {res!r}"
        )
