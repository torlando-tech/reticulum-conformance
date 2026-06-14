"""docs_normative V2 gap-closure — wire-captured link-establishment sizes.

Closes the LRPROOF half of doc-link-cost-297. The documented link-establishment
cost table (3 packets) is stale for RNS 1.3.1; the LINKREQUEST half (67-byte LR
data) is already pinned in test_link_hooks. This pins the SECOND packet — the
link-request PROOF (LRPROOF) — at its real 1.3.1 total wire size of 118 bytes,
captured from a genuine RNS Link.prove / Packet.pack on a live peer and checked
against an INDEPENDENT component-width derivation (not the impl's own byte count
read back).

The third packet (the encrypted LRRTT round-trip-time report, 83 bytes in 1.3.1)
is left to LIMITS: its size depends on the link's AES/Token encryption of a
msgpacked float, which cannot be derived independently without reconstructing the
crypto layer the audit forbids.
"""

from conformance import conformance_case


__category_title__ = "Docs Normative (V2 gap closure)"
__category_order__ = 33


# --- EXTERNAL ground-truth spec literals (RNS 1.3.1 — NOT read from the impl) ---
HEADER_1_MINSIZE = 19      # Reticulum.HEADER_MINSIZE: flags(1)+hops(1)+link_id(16)+ctx(1)
SIG_BYTES = 64             # Identity.SIGLENGTH//8 — the Ed25519 link-proof signature
X25519_PUB_BYTES = 32      # the link ephemeral X25519 public key (ECPUBSIZE//2)
SIGNALLING_BYTES = 3       # Link.signalling_bytes: a 24-bit mtu/mode field

# proof_data = signature(64) + pub(32) + signalling(3) = 99; frame = header(19) + 99
LRPROOF_WIRE_SIZE = 118    # documented-table-stale; actual RNS 1.3.1 total


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "capture_lrproof_frame"],
    verifies=(
        "The link-request PROOF (LRPROOF) — the second of the three link-"
        "establishment packets — is EXACTLY 118 bytes on the wire in RNS 1.3.1: "
        "the 19-byte HEADER_1 header (flags+hops+16-byte link_id+context) + a "
        "64-byte Ed25519 signature + the 32-byte X25519 link public key + 3 "
        "signalling bytes. The frame is produced by a genuine RNS Link.prove / "
        "Packet.pack on a live peer; its length is pinned against an independent "
        "component-width sum (the stale doc cost-table lists 115)."
    ),
)
def test_lrproof_total_wire_size_is_118(wire_pair_started):
    _server, client = wire_pair_started

    cap = client.capture_lrproof_frame()
    raw = cap["raw"]
    assert isinstance(raw, (bytes, bytearray)), f"no LRPROOF frame captured: {cap!r}"

    derived = HEADER_1_MINSIZE + SIG_BYTES + X25519_PUB_BYTES + SIGNALLING_BYTES
    assert derived == LRPROOF_WIRE_SIZE  # test-internal sanity on the literals

    assert len(raw) == LRPROOF_WIRE_SIZE == derived, (
        f"LRPROOF wire frame must be exactly {LRPROOF_WIRE_SIZE} bytes "
        f"(19 header + 64 sig + 32 pub + 3 signalling); got {len(raw)}"
    )

    # The captured frame's 16-byte destination-position field is the link_id
    # (already pinned by the lrproof-special-packing test), so the 19-byte
    # header accounting above is the genuine HEADER_1 + link_id layout, not a
    # coincidental length match.
    assert cap["truncated_hashlength"] == 16, (
        f"link_id width (TRUNCATED_HASHLENGTH//8) must be 16: {cap!r}"
    )
    assert raw[2:2 + 16] == cap["link_id"], (
        f"LRPROOF destination-position bytes must be the link_id: "
        f"{raw[2:2 + 16].hex()} != {cap['link_id'].hex()}"
    )
