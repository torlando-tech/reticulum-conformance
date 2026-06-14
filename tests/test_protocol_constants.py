"""Protocol wire-constant and forward-primitive conformance.

Reticulum's wire format is governed by a set of exact constants — the MTU, the
header sizes, the per-destination-type MDUs, the hash/signature/key lengths.
Interop depends on every implementation agreeing on them to the byte. These tests
pin each against its documented spec literal (read from live RNS via
`packet_constants`), plus their defining arithmetic relationships, so an impl
that derives a different MDU (and would fragment/pad differently) fails.

Also pins two forward primitives the suite previously only exercised inversely:
`Identity.get_random_hash` (length + non-repetition) and the HDLC send-side
byte-stuffing order (`HDLC.escape`, ESC-before-FLAG), with a round-trip through
`hdlc_deframe` as the positive control.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Protocol Constants"
__category_order__ = 7


# RNS 1.3.1 spec literals (NOT read from the impl — the external ground truth).
_MTU = 500
_HEADER_MINSIZE = 19          # HEADER_1: flags + hops + dest_hash(16) + context
_HEADER_MAXSIZE = 35          # HEADER_2: + transport_id(16)
_IFAC_MIN_SIZE = 1
_MDU = 464                    # MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
_ENCRYPTED_MDU = 383          # single-packet encrypted (SINGLE) payload ceiling
_PLAIN_MDU = 464
_LINK_MDU = 431               # floor((MTU-1-19-48)/16)*16 - 1
_HASHLENGTH = 256             # bits (SHA-256)
_SIGLENGTH = 512              # bits (Ed25519 signature = 64 bytes)
_TRUNCATED_HASHLENGTH = 128   # bits (16-byte addresses)
_KEYSIZE = 512                # bits (X25519 pub 32 + Ed25519 pub 32)
_NAME_HASH_LENGTH = 80        # bits (10-byte name hash)


@conformance_case(
    commands=["packet_constants"],
    verifies="RNS wire constants match the spec literals exactly: MTU=500, HEADER_MINSIZE=19, HEADER_MAXSIZE=35, MDU=464, IFAC_MIN_SIZE=1, ENCRYPTED_MDU=383, PLAIN_MDU=464, link MDU=431, and the hash/sig/key bit-lengths (256/512/128/512/80) — plus the defining relationship MDU == MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE. An impl with any divergent constant fragments/pads/addresses differently and breaks interop",
)
def test_packet_constants_match_spec(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        c = impl.execute("packet_constants")
        assert c["mtu"] == _MTU, f"{label}: MTU"
        assert c["header_minsize"] == _HEADER_MINSIZE, f"{label}: HEADER_MINSIZE"
        assert c["header_maxsize"] == _HEADER_MAXSIZE, f"{label}: HEADER_MAXSIZE"
        assert c["mdu"] == _MDU, f"{label}: MDU"
        assert c["ifac_min_size"] == _IFAC_MIN_SIZE, f"{label}: IFAC_MIN_SIZE"
        assert c["packet_mdu"] == _MDU, f"{label}: Packet.MDU"
        assert c["packet_plain_mdu"] == _PLAIN_MDU, f"{label}: PLAIN_MDU"
        assert c["packet_encrypted_mdu"] == _ENCRYPTED_MDU, f"{label}: ENCRYPTED_MDU"
        assert c["link_mdu"] == _LINK_MDU, f"{label}: Link.MDU"
        assert c["hashlength"] == _HASHLENGTH, f"{label}: HASHLENGTH"
        assert c["siglength"] == _SIGLENGTH, f"{label}: SIGLENGTH"
        assert c["truncated_hashlength"] == _TRUNCATED_HASHLENGTH, f"{label}: TRUNCATED_HASHLENGTH"
        assert c["keysize"] == _KEYSIZE, f"{label}: KEYSIZE"
        assert c["name_hash_length"] == _NAME_HASH_LENGTH, f"{label}: NAME_HASH_LENGTH"
        # Defining relationship, not just the stored value.
        assert c["mdu"] == c["mtu"] - c["header_maxsize"] - c["ifac_min_size"], (
            f"{label}: MDU must equal MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE"
        )


@conformance_case(
    commands=["identity_random_hash"],
    verifies="RNS.Identity.get_random_hash returns a 16-byte (TRUNCATED_HASHLENGTH//8) value that differs across calls: 8 successive samples are each 16 bytes and all distinct, pinning the random-hash format and non-repetition (an impl returning a fixed or short value fails)",
)
def test_identity_random_hash_format(sut):
    seen = set()
    for _ in range(8):
        h = sut.execute("identity_random_hash")["random_hash"]
        b = bytes.fromhex(h)
        assert len(b) == 16, f"random hash must be 16 bytes, got {len(b)}"
        seen.add(h)
    assert len(seen) == 8, "random hashes repeated across calls — not random"


@conformance_case(
    commands=["hdlc_escape", "hdlc_deframe"],
    verifies="RNS HDLC send-side byte-stuffing escapes ESC (0x7D) BEFORE FLAG (0x7E): escaping the payload 0x7D 0x7E yields exactly 7d5d7d5e (ESC->ESC,0x5D then FLAG->ESC,0x5E) — an impl that escapes FLAG first would double-escape the inserted ESC bytes and diverge — and a canonical frame FLAG||escape(payload)||FLAG round-trips through hdlc_deframe to the original (positive control)",
)
def test_hdlc_escape_order_and_roundtrip(sut, reference):
    # Order pin: ESC-before-FLAG is the only ordering that yields this literal.
    for impl, label in ((reference, "ref"), (sut, "sut")):
        esc = impl.execute("hdlc_escape", data="7d7e")["escaped"]
        assert_hex_equal(esc, "7d5d7d5e", f"{label}: HDLC escape order/values")

    # Round-trip: a canonically framed special-byte payload deframes to itself.
    payload = bytes([0x00, 0x7E, 0x7D, 0xFF]) + bytes.fromhex(random_hex(16))
    escaped = bytes.fromhex(sut.execute("hdlc_escape", data=payload.hex())["escaped"])
    assert len(escaped) > len(payload), "escape did not expand the special bytes"
    framed = bytes([0x7E]) + escaped + bytes([0x7E])
    recovered = sut.execute("hdlc_deframe", framed=framed.hex())["data"]
    assert_hex_equal(recovered, payload.hex(), "framed special-byte payload did not round-trip")
