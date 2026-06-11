"""Packet subsystem — V2 gap-closing (context code points + CACHE_REQUEST bypass).

Closes two RNS 1.3.1 Packet.py conformance gaps the V2 re-evaluation left partial,
using only the live packet_context_constants / packet_build / packet_unpack bridge
commands (each delegates to real RNS.Packet). Every assertion anchors on an
EXTERNAL spec literal — a context code point read from RNS/Packet.py:72-92, or a
wire frame reconstructed field-by-field — never on the impl's own decode of its
own bytes.

Gaps addressed (CONFORMANCE_COMPLETENESS_V2 §4, packet subsystem):
  * context-byte-codes — the named context code points are byte-pinned against
    their spec literals (RNS.Packet.* read live), and the ones the protocol
    previously only IMPLIED through interop — COMMAND 0x0C, COMMAND_STATUS 0x0D,
    the resource hashmap/cancel codes RESOURCE_HMU 0x04 / RESOURCE_ICL 0x06 /
    RESOURCE_RCL 0x07, and the link-control codes LINKIDENTIFY 0xFB / LINKCLOSE
    0xFC / LINKPROOF 0xFD — are additionally placed on the wire and shown to ride
    at the context byte offset and round-trip verbatim.
  * plaintext-resource-keepalive-cache (CACHE_REQUEST clause) — a SINGLE DATA
    CACHE_REQUEST (0x08) packet rides its payload in the CLEAR (Packet.py:210-212
    bypasses encryption), proven against the same payload on the same SINGLE
    destination with the NONE context (which IS encrypted: longer ciphertext that
    differs from the plaintext).

Ground truth verified against RNS.Packet (context constants + pack's per-context
encryption gate) on the installed Python RNS 1.3.1.
"""

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Packet"
__category_order__ = 5


# RNS 1.3.1 context code points — the EXTERNAL ground truth (RNS/Packet.py:72-92),
# NOT read from the impl. The command below reads the impl's named constants; the
# test asserts each equals the corresponding literal here.
_CONTEXT_LITERALS = {
    "NONE": 0x00,
    "RESOURCE": 0x01,
    "RESOURCE_ADV": 0x02,
    "RESOURCE_REQ": 0x03,
    "RESOURCE_HMU": 0x04,
    "RESOURCE_PRF": 0x05,
    "RESOURCE_ICL": 0x06,
    "RESOURCE_RCL": 0x07,
    "CACHE_REQUEST": 0x08,
    "RESPONSE": 0x0A,
    "PATH_RESPONSE": 0x0B,
    "COMMAND": 0x0C,
    "COMMAND_STATUS": 0x0D,
    "CHANNEL": 0x0E,
    "KEEPALIVE": 0xFA,
    "LINKIDENTIFY": 0xFB,
    "LINKCLOSE": 0xFC,
    "LINKPROOF": 0xFD,
    "LRRTT": 0xFE,
    "LRPROOF": 0xFF,
}

# The code points the V2 audit flagged as never byte-pinned — interop-implied only.
# Each is BUILDABLE on a PLAIN DATA packet (none is special-cased in pack except
# LRPROOF 0xFF, which is excluded — it forces the LINK destination address path).
_NEWLY_PINNED = (
    "RESOURCE_HMU", "RESOURCE_ICL", "RESOURCE_RCL",
    "COMMAND", "COMMAND_STATUS",
    "LINKIDENTIFY", "LINKCLOSE", "LINKPROOF",
)

_PTYPE_DATA = 0
_ADDR_LEN = 16
_HEADER_1_SIZE = 2 + _ADDR_LEN + 1  # flags + hops + dest_hash + context = 19
_CTX_CACHE_REQUEST = 0x08
_CTX_NONE = 0x00


@conformance_case(
    commands=["packet_context_constants", "packet_build", "packet_unpack"],
    verifies=(
        "RNS assigns the documented context-byte code points (RNS.Packet, "
        "Packet.py:72-92): every named context constant read live off RNS equals "
        "its spec literal (NONE 0x00 .. LRPROOF 0xFF), the assignment is a "
        "bijection (20 distinct code points), and the code points the protocol "
        "previously only IMPLIED — COMMAND 0x0C, COMMAND_STATUS 0x0D, the resource "
        "hashmap/cancel codes RESOURCE_HMU 0x04 / RESOURCE_ICL 0x06 / RESOURCE_RCL "
        "0x07, and the link-control codes LINKIDENTIFY 0xFB / LINKCLOSE 0xFC / "
        "LINKPROOF 0xFD — additionally ride at the HEADER_1 context byte offset "
        "(byte 18) of a real PLAIN DATA frame and round-trip verbatim through "
        "unpack. An impl that renumbers any context byte mis-routes that packet "
        "class and breaks interop"
    ),
)
def test_packet_context_code_points(sut, reference):
    for impl, who in ((reference, "ref"), (sut, "sut")):
        consts = impl.execute("packet_context_constants")
        # 1) Every named context equals its external spec literal.
        for name, literal in _CONTEXT_LITERALS.items():
            assert consts.get(name) == literal, (
                f"{who}: RNS.Packet.{name} = {consts.get(name)!r} != "
                f"spec literal 0x{literal:02x}"
            )
        # 2) The code-point assignment is a bijection (no two contexts collide).
        values = [consts[name] for name in _CONTEXT_LITERALS]
        assert len(set(values)) == len(_CONTEXT_LITERALS), (
            f"{who}: context code points collided: {sorted(values)}"
        )

    # 3) The previously interop-implied code points ride on the wire byte-exact.
    payload = random_hex(24)
    for name in _NEWLY_PINNED:
        context = _CONTEXT_LITERALS[name]
        built = sut.execute(
            "packet_build",
            dest_type="plain", packet_type=_PTYPE_DATA,
            context=context, context_flag=0, hops=2, data=payload,
        )
        raw = bytes.fromhex(built["raw"])
        # Independent reconstruction: PLAIN carries the payload in the clear, so
        # the whole HEADER_1 frame is deterministic.
        dest_hash = bytes.fromhex(built["destination_hash"])
        expected = (
            bytes([built["flags"], 2]) + dest_hash
            + bytes([context]) + bytes.fromhex(payload)
        )
        assert_hex_equal(
            raw.hex(), expected.hex(),
            f"{name} (0x{context:02x}): reconstructed HEADER_1 frame mismatch",
        )
        assert raw[_HEADER_1_SIZE - 1] == context, (
            f"{name}: context byte not at wire offset {_HEADER_1_SIZE - 1} "
            f"(got 0x{raw[_HEADER_1_SIZE - 1]:02x}, want 0x{context:02x})"
        )
        # The other impl decodes the (interop-implied) context back verbatim.
        parsed = reference.execute("packet_unpack", raw=raw.hex())
        assert parsed["unpacked"] is True and parsed["context"] == context, (
            f"{name} (0x{context:02x}): unpack did not echo the context: {parsed}"
        )


@conformance_case(
    commands=["packet_build"],
    verifies=(
        "RNS bypasses packet encryption for a CACHE_REQUEST (context 0x08) packet "
        "even on a SINGLE destination — its payload rides in the CLEAR "
        "(Packet.pack, Packet.py:210-212: `elif self.context == CACHE_REQUEST: "
        "ciphertext = self.data`). A SINGLE DATA CACHE_REQUEST packet's on-wire "
        "payload (the bytes after the 19-byte HEADER_1) equals the cleartext input "
        "byte-for-byte and is exactly the input length, whereas the SAME payload on "
        "the SAME SINGLE destination with the NONE context IS encrypted: its on-"
        "wire body differs from the plaintext and is longer (carries the ephemeral "
        "key + token overhead). An impl that encrypted a cache request — or left a "
        "normal SINGLE DATA packet in the clear — fails the contrast"
    ),
)
def test_cache_request_payload_plaintext_on_single(sut, reference):
    payload = random_hex(32)
    plain = bytes.fromhex(payload)
    for impl, who in ((sut, "sut"), (reference, "ref")):
        # CACHE_REQUEST: the body rides in the clear, byte-for-byte == plaintext.
        cr = impl.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_DATA,
            context=_CTX_CACHE_REQUEST, context_flag=0, hops=0, data=payload,
        )
        cr_body = bytes.fromhex(cr["raw"])[_HEADER_1_SIZE:]
        assert cr_body == plain, (
            f"{who}: CACHE_REQUEST body is not the plaintext payload "
            f"({cr_body.hex()} != {payload}) — encryption was NOT bypassed"
        )
        assert len(cr_body) == len(plain), (
            f"{who}: CACHE_REQUEST body length {len(cr_body)} != plaintext "
            f"length {len(plain)} (no encryption overhead expected)"
        )

        # Contrast: the SAME payload on the SAME SINGLE destination with NONE is
        # ENCRYPTED — the body differs from the plaintext and is longer.
        nn = impl.execute(
            "packet_build",
            dest_type="single", packet_type=_PTYPE_DATA,
            context=_CTX_NONE, context_flag=0, hops=0, data=payload,
        )
        nn_body = bytes.fromhex(nn["raw"])[_HEADER_1_SIZE:]
        assert nn_body != plain, (
            f"{who}: SINGLE DATA NONE body equals the plaintext — encryption was "
            f"NOT applied (the CACHE_REQUEST contrast is meaningless)"
        )
        assert len(nn_body) > len(plain), (
            f"{who}: SINGLE DATA NONE body ({len(nn_body)}B) is not longer than the "
            f"plaintext ({len(plain)}B) — expected ephemeral-key + token overhead"
        )
