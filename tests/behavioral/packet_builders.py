"""
Helpers for constructing valid RNS packets from first principles in tests.

Tests inject raw bytes onto MockInterfaces. Those bytes need to parse and
validate as real RNS packets (correct flags, valid signature, etc). The
helper round-trips through the bridge's honest `announce_build` command,
which constructs a real RNS.Destination.announce(send=False) inside the
bridge process — RNS itself produces the wire bytes, signature, and
random_hash. The behavioral test then patches the `hops` byte in place to
the value it wants to inject (announce_build always emits hops=0; transport
behavior tests need to simulate an announce arriving with N hops already).
"""

import secrets
import struct
from typing import Optional


# RNS packet/header constants (from RNS/Packet.py and RNS/Destination.py).
# Duplicating here so tests don't import RNS directly — bridge is the only
# RNS-aware component.
HEADER_1 = 0  # << 6
HEADER_2 = 1  # << 6

TRANSPORT_BROADCAST = 0  # << 4
TRANSPORT_TRANSPORT = 1  # << 4

CONTEXT_FLAG_UNSET = 0  # << 5
CONTEXT_FLAG_SET = 1  # << 5

DESTINATION_TYPE_SINGLE = 0  # << 2
DESTINATION_TYPE_GROUP = 1  # << 2
DESTINATION_TYPE_PLAIN = 2  # << 2
DESTINATION_TYPE_LINK = 3  # << 2

PACKET_TYPE_DATA = 0
PACKET_TYPE_ANNOUNCE = 1
PACKET_TYPE_LINKREQUEST = 2
PACKET_TYPE_PROOF = 3

CONTEXT_NONE = 0x00
CONTEXT_PATH_RESPONSE = 0x0B

KEYSIZE_BYTES = 64
NAME_HASH_BYTES = 10
RANDOM_HASH_BYTES = 10
SIG_BYTES = 64
RATCHET_BYTES = 32
TRUNCATED_HASH_BYTES = 16
FULL_HASH_BYTES = 32  # RNS.Identity.HASHLENGTH // 8 (full SHA-256 truncation length)
# The 16-byte random_hash carried in a tunnel-synthesize packet is
# RNS.Identity.get_random_hash() == TRUNCATED_HASHLENGTH // 8 (Transport.py:2284,
# read back by tunnel_synthesize_handler at Transport.py:2313). Distinct from the
# 10-byte announce random_hash above (RANDOM_HASH_BYTES).
TUNNEL_RANDOM_HASH_BYTES = TRUNCATED_HASH_BYTES

# RNS Packet context values used by the builders / their callers. Verified
# against RNS 1.3.1 RNS.Packet.* (NOT the values quoted in the gap report — e.g.
# RESOURCE is 0x01, not 0x07). The six contexts that Transport.packet_filter
# accepts BEFORE the hashlist/TTL checks (Transport.py:1345-1350) are
# RESOURCE_REQ, RESOURCE_PRF, RESOURCE, CACHE_REQUEST, CHANNEL and KEEPALIVE.
CONTEXT_RESOURCE = 0x01       # RNS.Packet.RESOURCE       (packet_filter bypass)
CONTEXT_RESOURCE_REQ = 0x03   # RNS.Packet.RESOURCE_REQ   (packet_filter bypass)
CONTEXT_RESOURCE_PRF = 0x05   # RNS.Packet.RESOURCE_PRF   (packet_filter bypass)
CONTEXT_CACHE_REQUEST = 0x08  # RNS.Packet.CACHE_REQUEST  (packet_filter bypass)
CONTEXT_CHANNEL = 0x0E        # RNS.Packet.CHANNEL        (packet_filter bypass)
CONTEXT_KEEPALIVE = 0xFA      # RNS.Packet.KEEPALIVE      (packet_filter bypass)

# PROOF sizes (RNS/Packet.py PacketReceipt.EXPL_LENGTH / IMPL_LENGTH).
PROOF_EXPL_LENGTH = FULL_HASH_BYTES + SIG_BYTES  # 96: packet_hash || signature
PROOF_IMPL_LENGTH = SIG_BYTES                    # 64: signature only

# The two PLAIN control destinations Transport registers on startup
# (Transport.py:242 / :247). Their addresses are
# truncated_hash(name_hash(dotted_name)) with no identity material, matching
# RNS.Destination.hash(None, app_name, *aspects).
PATH_REQUEST_DESTINATION_NAME = "rnstransport.path.request"
TUNNEL_SYNTHESIZE_DESTINATION_NAME = "rnstransport.tunnel.synthesize"

# Maps the builder's destination_type keyword to (bridge dest_type, flag bits).
_DEST_TYPE_TO_BRIDGE = {
    "single": "single",
    "plain": "plain",
    "group": "group",
}
_DEST_TYPE_TO_FLAG = {
    "single": DESTINATION_TYPE_SINGLE,
    "plain": DESTINATION_TYPE_PLAIN,
    "group": DESTINATION_TYPE_GROUP,
}


def compose_flags(
    header_type: int = HEADER_1,
    context_flag: int = CONTEXT_FLAG_UNSET,
    transport_type: int = TRANSPORT_BROADCAST,
    destination_type: int = DESTINATION_TYPE_SINGLE,
    packet_type: int = PACKET_TYPE_DATA,
) -> int:
    """Build the single flags byte for a Reticulum packet."""
    return (
        (header_type << 6)
        | (context_flag << 5)
        | (transport_type << 4)
        | (destination_type << 2)
        | packet_type
    )


def build_random_hash(random_prefix: bytes, emission_ts: int) -> bytes:
    """10-byte random_hash: 5 random bytes + 5 bytes big-endian emission timestamp
    (seconds since epoch). Matches RNS/Destination.py:1427-1434."""
    if len(random_prefix) < 5:
        raise ValueError("random_prefix must be >= 5 bytes")
    ts_bytes = struct.pack(">Q", emission_ts)[-5:]  # lower 5 bytes, big-endian
    return random_prefix[:5] + ts_bytes


def context_offset(raw: bytes) -> int:
    """Byte offset of the single context field in a packed RNS packet.

    HEADER_1: flags(1) + hops(1) + dest_hash(16) -> context at 18.
    HEADER_2: flags(1) + hops(1) + transport_id(16) + dest_hash(16) -> 34.
    Mirrors RNS/Packet.py pack/unpack field layout.
    """
    header_type = (raw[0] & 0b01000000) >> 6
    if header_type == HEADER_2:
        return 2 + 2 * TRUNCATED_HASH_BYTES
    return 2 + TRUNCATED_HASH_BYTES


def build_announce_from_destination(
    bridge,
    identity_private_key: bytes,
    app_name: str,
    aspects: list,
    random_prefix: bytes = b"",   # advisory only — see note below
    emission_ts: int = 0,         # honored via announce_build (RNS stamps it)
    wire_hops: int = 0,
    context: int = CONTEXT_NONE,
    ratchet: Optional[bytes] = None,
    app_data: bytes = b"",
) -> tuple:
    """Build a signed announce packet via the bridge's honest announce_build.

    announce_build calls real RNS.Destination.announce(send=False) inside the
    bridge process — RNS produces the full wire bytes (flags, header,
    signature, random_hash, ratchet field). We then patch two header bytes
    in-place. Both are header-only fields that lie OUTSIDE the announce's
    signed_data (RNS signs dest_hash+public_key+name_hash+random_hash+ratchet+
    app_data — see Identity.validate_announce / Destination.announce:297), so
    patching them does NOT invalidate the signature:

      * hops    (raw[1]) — simulate an announce that already crossed N hops.
      * context (raw[context_offset]) — set the packet context, e.g.
        CONTEXT_PATH_RESPONSE (0x0B), so transport-behavior tests can inject a
        genuine PATH_RESPONSE-contextual announce. RNS's own
        Destination.announce only sets this when path_response=True; the bridge
        does not expose that flag, so we set the header byte directly. Verified
        against RNS 1.3.1: validate_announce still returns True afterwards.

    Returns (raw_bytes, destination_hash, identity_public_key).

    Parameter notes:
      * emission_ts IS honored: announce_build monkey-patches time.time for one
        announce() call so RNS itself stamps emission_ts into the random_hash
        and path-response timestamp. Lets callers build "fresh" vs "stale"
        announces with controlled emission timebases in the same test.
      * context IS honored (patched in-place as described above).
      * random_prefix is ADVISORY ONLY. The 5 random bytes of the random_hash
        are part of the announce's signed_data, so RNS — not this helper —
        generates them inside the bridge. Two announce_build calls already
        yield distinct random_blobs (~2**-40 collision), which is all the
        path-replacement / replay tests require. Fully pinning these bytes
        would need a `random_prefix` parameter on the bridge's announce_build.
    """
    extra = {}
    if emission_ts:
        # Pin wall-clock time so callers can build "fresh" and "stale"
        # announces in the same test run; announce_build monkey-patches
        # time.time for one call so RNS itself stamps emission_ts into the
        # random_hash and path-response timestamp.
        extra["emission_ts"] = int(emission_ts)
    info = bridge.execute(
        "announce_build",
        private_key=identity_private_key.hex(),
        app_name=app_name,
        aspects=list(aspects),
        app_data=app_data.hex() if app_data else "",
        enable_ratchets=ratchet is not None,
        **extra,
    )
    raw = bytearray(bytes.fromhex(info["raw"]))
    # announce_build sets hops=0 (real Destination.announce starts at 0); patch
    # to the value this test wants to simulate.
    raw[1] = wire_hops & 0xFF
    # Patch the context byte if a non-NONE context was requested. This is a
    # header-only field outside signed_data, so the signature stays valid.
    if context != CONTEXT_NONE:
        raw[context_offset(raw)] = context & 0xFF
    destination_hash = bytes.fromhex(info["destination_hash"])
    public_key = bytes.fromhex(info["public_key"])
    return bytes(raw), destination_hash, public_key


HEADER_1_MIN_SIZE = 2 + TRUNCATED_HASH_BYTES + 1  # flags + hops + dest_hash + ctx = 19
HEADER_2_MIN_SIZE = 2 + 2 * TRUNCATED_HASH_BYTES + 1  # + transport_id before dest = 35


def parse_packet_header(raw: bytes) -> dict:
    """Parse just the outer packet header bytes. Does not validate signatures.

    HEADER_1 packets need at least 19 bytes (flags + hops + dest_hash + context).
    HEADER_2 packets have an additional 16-byte transport_id inserted between
    hops and dest_hash, so need at least 35 bytes.
    """
    if len(raw) < HEADER_1_MIN_SIZE:
        raise ValueError(f"raw too short to be a packet: {len(raw)} < {HEADER_1_MIN_SIZE}")
    flags = raw[0]
    hops = raw[1]
    header_type = (flags & 0b01000000) >> 6
    context_flag = (flags & 0b00100000) >> 5
    transport_type = (flags & 0b00010000) >> 4
    destination_type = (flags & 0b00001100) >> 2
    packet_type = flags & 0b00000011

    if header_type == HEADER_2:
        if len(raw) < HEADER_2_MIN_SIZE:
            raise ValueError(
                f"HEADER_2 packet too short: {len(raw)} < {HEADER_2_MIN_SIZE}"
            )
        transport_id = raw[2 : 2 + TRUNCATED_HASH_BYTES]
        dest_hash = raw[2 + TRUNCATED_HASH_BYTES : 2 + 2 * TRUNCATED_HASH_BYTES]
        context = raw[2 + 2 * TRUNCATED_HASH_BYTES]
        data = raw[2 + 2 * TRUNCATED_HASH_BYTES + 1 :]
    else:
        transport_id = None
        dest_hash = raw[2 : 2 + TRUNCATED_HASH_BYTES]
        context = raw[2 + TRUNCATED_HASH_BYTES]
        data = raw[2 + TRUNCATED_HASH_BYTES + 1 :]

    return {
        "flags": flags,
        "hops": hops,
        "header_type": header_type,
        "context_flag": context_flag,
        "transport_type": transport_type,
        "destination_type": destination_type,
        "packet_type": packet_type,
        "transport_id": transport_id,
        "destination_hash": dest_hash,
        "context": context,
        "data": data,
    }


def is_announce(raw: bytes) -> bool:
    if len(raw) < 19:
        return False
    return (raw[0] & 0b00000011) == PACKET_TYPE_ANNOUNCE


def first_announce(packets: list) -> Optional[dict]:
    """Return parsed header of the first announce packet in a list, or None."""
    for raw in packets:
        if is_announce(raw):
            return parse_packet_header(raw)
    return None


# ---------------------------------------------------------------------------
# DATA / PROOF / PATH-REQUEST / TUNNEL-SYNTHESIZE builders
#
# These wrap the bridge's honest `packet_build` (real RNS.Packet.pack on a real
# Destination) for byte assembly, then patch the destination-address field and —
# where RNS.Packet.pack has no entry point for it — synthesise the HEADER_2
# transport relay form. Every builder validates its output by round-tripping
# through the bridge's `packet_unpack` (real RNS.Packet.unpack), so a malformed
# layout fails loudly at build time rather than silently injecting garbage.
#
# Why patch instead of building the packet entirely through `packet_build`:
#   * `packet_build` mints its OWN throwaway destination, so the wire
#     destination_hash is not the address a transport-behaviour test needs the
#     packet aimed at (a specific path-table entry, the reverse-table key, or a
#     control destination). The 16-byte destination_hash is a header-only field
#     (no signature covers a DATA/PROOF packet), so overwriting it in place is
#     wire-faithful — unpack confirms RNS reads back the patched address.
#   * `packet_build` refuses HEADER_2 for any non-ANNOUNCE packet (RNS only
#     assembles a HEADER_2 header for announces, Packet.py:220-229), but the
#     transport_id "other instance" drop (Transport.py:1340-1343) and the
#     reverse_table proof-routing path (Transport.py:1625-1631) both require a
#     HEADER_2 SINGLE DATA packet. We build the HEADER_1 form and promote it to
#     the HEADER_2 relay layout, which is a pure header reshuffle
#     (flags|hops|TRANSPORT_ID|dest|ctx|data, Packet.py:222-224).
# ---------------------------------------------------------------------------


def _unpack(bridge, raw: bytes) -> dict:
    """Round-trip raw bytes through the bridge's real RNS.Packet.unpack and
    fail loudly if RNS rejects them."""
    parsed = bridge.execute("packet_unpack", raw=raw.hex())
    if not parsed.get("unpacked"):
        raise ValueError("RNS.Packet.unpack rejected the built packet bytes")
    return parsed


def _plain_destination_hash(bridge, dotted_name: str) -> bytes:
    """Address of a no-identity PLAIN destination from its dotted full name.

    Mirrors RNS.Destination.hash(None, app_name, *aspects): the name hash is
    full_hash(name)[:NAME_HASH_LENGTH//8] and the address is
    full_hash(name_hash)[:TRUNCATED_HASHLENGTH//8]. Both digests come from the
    bridge (real RNS.Identity.full_hash) — nothing about the lengths is
    hand-rolled here.
    """
    name_hash = bytes.fromhex(bridge.execute("name_hash", name=dotted_name)["hash"])
    return bytes.fromhex(
        bridge.execute("truncated_hash", data=name_hash.hex())["hash"]
    )


def _promote_to_header2(raw: bytes, transport_id: bytes) -> bytes:
    """Convert a packed HEADER_1 packet into its HEADER_2 transport-relay form.

    HEADER_1 layout: flags | hops | dest(16) | ctx | data
    HEADER_2 layout: flags | hops | transport_id(16) | dest(16) | ctx | data
    (RNS/Packet.py pack:206-229 / unpack:251-259). The flags byte gains the
    HEADER_2 bit and the TRANSPORT transport-type bit — exactly the form RNS
    emits when relaying a packet to a next hop. The destination_hash and
    context/data bytes are carried over unchanged, so the packet hash
    (get_hashable_part excludes hops + transport_id, Packet.py:347-353) is
    unaffected.
    """
    if len(transport_id) != TRUNCATED_HASH_BYTES:
        raise ValueError(
            f"transport_id must be {TRUNCATED_HASH_BYTES} bytes, "
            f"got {len(transport_id)}"
        )
    flags = raw[0]
    # transport_type is a 1-bit field at bit 4 (RNS Packet.py:249,
    # `(flags & 0b00010000) >> 4`); bit 5 is the separate context_flag and bit 6
    # is header_type. So clear ONLY bit 4 here — do NOT widen this to ~(3 << 4),
    # which would also zero bit 5 and clobber context_flag.
    flags = (flags & ~(1 << 6)) | (HEADER_2 << 6)
    flags = (flags & ~(1 << 4)) | (TRANSPORT_TRANSPORT << 4)
    hops = raw[1]
    dest = raw[2 : 2 + TRUNCATED_HASH_BYTES]
    rest = raw[2 + TRUNCATED_HASH_BYTES :]  # context byte + payload
    return bytes([flags & 0xFF, hops]) + bytes(transport_id) + bytes(dest) + bytes(rest)


def build_data_packet(
    bridge,
    dest_hash: bytes,
    *,
    header_type: int = HEADER_1,
    transport_id: Optional[bytes] = None,
    destination_type: str = "single",
    context: int = CONTEXT_NONE,
    context_flag: int = CONTEXT_FLAG_UNSET,
    hops: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Build a non-announce DATA packet aimed at a specific destination address.

    Delegates the flag-byte assembly and (for SINGLE/GROUP) payload encryption
    to the bridge's real RNS.Packet.pack via `packet_build`, then overwrites the
    16-byte destination_hash with `dest_hash` and, when `header_type=HEADER_2`,
    promotes the packet to the transport-relay layout with `transport_id`
    inserted. The produced bytes are validated through real RNS.Packet.unpack.

    destination_type:
        "plain"  — payload travels in the clear (PLAIN.encrypt is a no-op), so
                   `payload` is byte-for-byte the wire data field.
        "single" / "group" — RNS encrypts the payload to the bridge's throwaway
                   destination, so only the header fields (and the *presence* of
                   a payload) are controllable; the ciphertext bytes are opaque.
                   This is sufficient for packet_filter / relay tests, which
                   never decrypt the body.

    header_type=HEADER_2 requires a 16-byte `transport_id` and sets the
    transport-type flag to TRANSPORT (the relay form). `transport_id` is invalid
    for HEADER_1.

    Returns the raw packet bytes.
    """
    if destination_type not in _DEST_TYPE_TO_BRIDGE:
        raise ValueError(
            f"unsupported destination_type: {destination_type!r} "
            "(use 'single', 'plain' or 'group')"
        )
    if header_type not in (HEADER_1, HEADER_2):
        raise ValueError(
            f"header_type must be HEADER_1 ({HEADER_1}) or HEADER_2 ({HEADER_2})"
        )
    if len(dest_hash) != TRUNCATED_HASH_BYTES:
        raise ValueError(
            f"dest_hash must be {TRUNCATED_HASH_BYTES} bytes, got {len(dest_hash)}"
        )
    if not 0 <= int(hops) <= 0xFF:
        raise ValueError("hops must fit in one byte (0..255)")
    if header_type == HEADER_2:
        if transport_id is None:
            raise ValueError("HEADER_2 packets require a 16-byte transport_id")
    elif transport_id is not None:
        raise ValueError("transport_id is only valid with header_type=HEADER_2")

    # Build the HEADER_1 base honestly through RNS.Packet.pack. `packet_build`
    # rejects HEADER_2 for non-announce packets, so HEADER_2 is synthesised by
    # promotion below rather than requested here. The bridge's `header_type`
    # param uses the human "1"/"2" convention (NOT the module's HEADER_1==0).
    built = bridge.execute(
        "packet_build",
        dest_type=_DEST_TYPE_TO_BRIDGE[destination_type],
        packet_type=PACKET_TYPE_DATA,
        header_type=1,
        context=context,
        context_flag=context_flag,
        transport_type=TRANSPORT_BROADCAST,
        hops=int(hops),
        data=payload.hex(),
    )
    raw = bytearray(bytes.fromhex(built["raw"]))
    # Overwrite the destination address (HEADER_1: flags|hops|dest(16)|ctx|data).
    raw[2 : 2 + TRUNCATED_HASH_BYTES] = dest_hash
    raw = bytes(raw)

    if header_type == HEADER_2:
        raw = _promote_to_header2(raw, transport_id)

    # Validate the final layout against real RNS and assert the discriminating
    # header fields survived patching/promotion intact.
    parsed = _unpack(bridge, raw)
    assert parsed["destination_hash"] == dest_hash.hex(), (
        "patched destination_hash did not round-trip through RNS.Packet.unpack"
    )
    assert parsed["destination_type"] == _DEST_TYPE_TO_FLAG[destination_type]
    assert parsed["packet_type"] == PACKET_TYPE_DATA
    assert parsed["header_type"] == header_type
    assert parsed["hops"] == int(hops)
    assert parsed["context"] == context
    if header_type == HEADER_2:
        assert parsed["transport_id"] == transport_id.hex()
        assert parsed["transport_type"] == TRANSPORT_TRANSPORT
    if destination_type == "plain":
        # PLAIN payloads are unencrypted, so the wire data is exactly `payload`.
        assert parsed["data"] == payload.hex(), (
            "PLAIN payload did not survive on the wire unchanged"
        )
    return raw


def build_link_transport_packet(
    bridge,
    link_id: bytes,
    *,
    hops: int = 0,
    context: int = CONTEXT_NONE,
    payload: bytes = b"",
) -> bytes:
    """Build a HEADER_1 DATA packet of destination_type LINK addressed to a
    `link_id` (the key Transport.link_table is keyed by).

    Real link traffic carries destination_type == LINK; the link-transport
    routing branch (Transport.py:1644-1679) keys on destination_hash membership
    in link_table together with packet_type == DATA and context != LRPROOF — it
    does NOT re-encrypt or inspect the body, so the payload is opaque to the
    relay. We build a SINGLE DATA packet honestly via packet_build
    (RNS.Packet.pack), overwrite the 16-byte destination address with `link_id`
    (a header-only field) and flip the 2-bit destination_type subfield
    SINGLE -> LINK in the unsigned flags byte (no signature covers a DATA
    packet's header). The final layout is validated through real
    RNS.Packet.unpack, which confirms RNS reads destination_type == LINK and the
    patched address back.
    """
    if len(link_id) != TRUNCATED_HASH_BYTES:
        raise ValueError(
            f"link_id must be {TRUNCATED_HASH_BYTES} bytes, got {len(link_id)}"
        )
    raw = bytearray(
        build_data_packet(
            bridge, link_id, destination_type="single",
            context=context, hops=hops, payload=payload,
        )
    )
    # flags low nibble = (destination_type << 2) | packet_type. SINGLE==0 -> LINK==3.
    raw[0] = (raw[0] & ~(0b11 << 2)) | (DESTINATION_TYPE_LINK << 2)
    out = bytes(raw)
    parsed = _unpack(bridge, out)
    assert parsed["destination_type"] == DESTINATION_TYPE_LINK, (
        "destination_type was not patched to LINK"
    )
    assert parsed["packet_type"] == PACKET_TYPE_DATA
    assert parsed["header_type"] == HEADER_1
    assert parsed["destination_hash"] == link_id.hex()
    assert parsed["hops"] == int(hops)
    assert parsed["context"] == context
    return out


LINK_ECPUBSIZE = 64  # RNS.Link.ECPUBSIZE (X25519 32 + Ed25519 32)


def build_link_request_packet(
    bridge,
    dest_hash: bytes,
    *,
    transport_id: bytes,
    hops: int = 0,
    request_data: Optional[bytes] = None,
) -> tuple:
    """Build a HEADER_2 LINKREQUEST packet addressed to `dest_hash` via
    `transport_id` (the relay form: transport_type==TRANSPORT).

    A link request to a SINGLE destination carries the initiator's cleartext
    public-key bytes (ECPUBSIZE=64) as its data field — RNS does NOT encrypt a
    LINKREQUEST body (the responder needs the keys to derive the link). For the
    transport RELAY path (Transport.py:1583-1623) the body is opaque: the relay
    computes link_id = truncated_hash(get_hashable_part()) and, for a 64-byte
    body, does no MTU parsing (mtu_from_lr_packet needs 67 bytes), so 64 arbitrary
    bytes are a valid relayable request. We compose the flags directly (no
    signature covers a LINKREQUEST header), assemble the HEADER_1 base, promote it
    to the HEADER_2 relay layout with `transport_id`, and validate the final
    bytes through real RNS.Packet.unpack.

    Returns (raw_bytes, request_data). The link_id the relay will key the
    link_table by is truncated_hash(get_hashable_part()) == packet_hash[:16] for a
    64-byte body, derivable independently via the bridge's packet_hash.
    """
    if len(dest_hash) != TRUNCATED_HASH_BYTES:
        raise ValueError(
            f"dest_hash must be {TRUNCATED_HASH_BYTES} bytes, got {len(dest_hash)}"
        )
    if len(transport_id) != TRUNCATED_HASH_BYTES:
        raise ValueError(
            f"transport_id must be {TRUNCATED_HASH_BYTES} bytes, got {len(transport_id)}"
        )
    if request_data is None:
        request_data = secrets.token_bytes(LINK_ECPUBSIZE)
    if len(request_data) != LINK_ECPUBSIZE:
        raise ValueError(
            f"request_data must be {LINK_ECPUBSIZE} bytes (ECPUBSIZE), "
            f"got {len(request_data)}"
        )
    flags = compose_flags(
        header_type=HEADER_1,
        context_flag=CONTEXT_FLAG_UNSET,
        transport_type=TRANSPORT_BROADCAST,
        destination_type=DESTINATION_TYPE_SINGLE,
        packet_type=PACKET_TYPE_LINKREQUEST,
    )
    h1 = (
        bytes([flags, int(hops)])
        + bytes(dest_hash)
        + bytes([CONTEXT_NONE])
        + bytes(request_data)
    )
    raw = _promote_to_header2(h1, transport_id)

    parsed = _unpack(bridge, raw)
    assert parsed["packet_type"] == PACKET_TYPE_LINKREQUEST
    assert parsed["header_type"] == HEADER_2
    assert parsed["transport_type"] == TRANSPORT_TRANSPORT
    assert parsed["destination_hash"] == dest_hash.hex()
    assert parsed["transport_id"] == transport_id.hex()
    assert parsed["data"] == bytes(request_data).hex()
    return raw, bytes(request_data)


def build_path_request(
    bridge,
    dest_hash: bytes,
    transport_id: Optional[bytes] = None,
    tag: Optional[bytes] = None,
    hops: int = 0,
) -> bytes:
    """Build a raw PLAIN path request aimed at the `rnstransport/path/request`
    control destination (Transport.py:242, Transport.path_request_handler at
    :2860-2908).

    The PLAIN payload is `dest_hash [|| transport_id] [|| tag]`:
      * `dest_hash`      — the 16-byte address whose path is being requested.
      * `transport_id`   — the 16-byte requesting transport instance id. RNS
                           only parses it when len(payload) > 32
                           (Transport.py:2874-2877); pass None to omit it.
      * `tag`            — 1..16 bytes; RNS truncates to 16. A tagged request is
                           deduplicated by `unique_tag = dest_hash + tag`
                           (Transport.py:2887-2904). RNS ignores a *tagless*
                           request (pass None to exercise that path).

    Returns the raw packet bytes (PLAIN DATA, HEADER_1, cleartext payload).
    """
    if len(dest_hash) != TRUNCATED_HASH_BYTES:
        raise ValueError(
            f"dest_hash must be {TRUNCATED_HASH_BYTES} bytes, got {len(dest_hash)}"
        )
    if transport_id is not None and len(transport_id) != TRUNCATED_HASH_BYTES:
        raise ValueError(
            f"transport_id must be {TRUNCATED_HASH_BYTES} bytes when supplied, "
            f"got {len(transport_id)}"
        )
    payload = bytes(dest_hash)
    if transport_id is not None:
        payload += bytes(transport_id)
    if tag is not None:
        payload += bytes(tag)

    pr_dest = _plain_destination_hash(bridge, PATH_REQUEST_DESTINATION_NAME)
    return build_data_packet(
        bridge,
        pr_dest,
        destination_type="plain",
        payload=payload,
        hops=hops,
    )


def build_proof(
    bridge,
    proven_packet_hash: bytes,
    *,
    prover_private_key: Optional[bytes] = None,
    implicit: bool = False,
    hops: int = 0,
) -> bytes:
    """Build a packet PROOF returning to the sender of a proven packet.

    Mirrors RNS.Identity.prove (Identity.py:959-970): the proof signs the
    proven packet's full 32-byte hash and is addressed to the special
    ProofDestination, whose address is `proven_packet_hash[:16]`
    (Packet.py:391-396). That 16-byte address equals the proven packet's
    `getTruncatedHash()`, which is exactly the key Transport stores in its
    reverse_table (Transport.py:1631) — so injecting this proof drives the
    single-packet proof return-routing path (Transport.py:2254-2263).

    Proof body:
      * explicit (default) — packet_hash(32) || signature(64) == 96 bytes
        (PacketReceipt.EXPL_LENGTH); RNS extracts proof_hash from the first 32
        bytes to match a receipt (Transport.py:2251).
      * implicit           — signature(64) only (PacketReceipt.IMPL_LENGTH).

    `prover_private_key` (64-byte RNS Identity key) produces a real Ed25519
    signature over the packet hash via the bridge's real RNS.Identity.sign. When
    omitted, a 64-byte zero placeholder is used — sufficient for the reverse_table
    routing test, which keys purely on the address and receiving interface and
    does NOT validate the signature before transporting the proof.

    PROOF packets are NOT encrypted (ProofDestination.encrypt is a no-op,
    Packet.py:395-396), so the body is assembled in the clear and the flags byte
    is composed directly; the bytes are validated through real RNS.Packet.unpack.
    """
    if len(proven_packet_hash) != FULL_HASH_BYTES:
        raise ValueError(
            f"proven_packet_hash must be the full {FULL_HASH_BYTES}-byte packet "
            f"hash, got {len(proven_packet_hash)}"
        )
    if not 0 <= int(hops) <= 0xFF:
        raise ValueError("hops must fit in one byte (0..255)")

    if prover_private_key is not None:
        signature = bytes.fromhex(
            bridge.execute(
                "identity_sign",
                private_key=bytes(prover_private_key).hex(),
                message=proven_packet_hash.hex(),
            )["signature"]
        )
    else:
        signature = b"\x00" * SIG_BYTES
    if len(signature) != SIG_BYTES:
        raise ValueError(f"signature must be {SIG_BYTES} bytes, got {len(signature)}")

    proof_data = signature if implicit else (bytes(proven_packet_hash) + signature)
    proof_dest = bytes(proven_packet_hash)[:TRUNCATED_HASH_BYTES]

    flags = compose_flags(
        header_type=HEADER_1,
        context_flag=CONTEXT_FLAG_UNSET,
        transport_type=TRANSPORT_BROADCAST,
        destination_type=DESTINATION_TYPE_SINGLE,  # ProofDestination.type == SINGLE
        packet_type=PACKET_TYPE_PROOF,
    )
    raw = bytes([flags, int(hops)]) + proof_dest + bytes([CONTEXT_NONE]) + proof_data

    parsed = _unpack(bridge, raw)
    assert parsed["packet_type"] == PACKET_TYPE_PROOF
    assert parsed["destination_type"] == DESTINATION_TYPE_SINGLE
    assert parsed["destination_hash"] == proof_dest.hex()
    assert parsed["data"] == proof_data.hex()
    expected_len = PROOF_IMPL_LENGTH if implicit else PROOF_EXPL_LENGTH
    assert len(proof_data) == expected_len, (
        f"proof body is {len(proof_data)} bytes, expected {expected_len}"
    )
    return raw


def build_tunnel_synthesize(
    bridge,
    transport_private_key: Optional[bytes] = None,
    interface_hash: Optional[bytes] = None,
    random_hash: Optional[bytes] = None,
    hops: int = 0,
) -> dict:
    """Build a tunnel-synthesize packet (Transport.synthesize_tunnel,
    Transport.py:2282-2303) addressed to the `rnstransport/tunnel/synthesize`
    PLAIN control destination (Transport.py:247).

    Payload layout (read back by tunnel_synthesize_handler, Transport.py:2306-2327):
        public_key(64) || interface_hash(32) || random_hash(16) || signature(64)
    where signed_data = public_key || interface_hash || random_hash and the
    signature is the transport identity's Ed25519 signature over signed_data.
    The derived tunnel_id is full_hash(public_key || interface_hash).

    Everything cryptographic is done by the bridge (real RNS.Identity public-key
    derivation, sign, and full_hash) so the emitted packet validates in a
    receiver's handler. A random transport identity / interface_hash / random_hash
    are generated when not supplied.

    Returns a dict:
        raw              — the raw packet bytes (PLAIN DATA, HEADER_1, cleartext)
        tunnel_id        — full_hash(public_key || interface_hash) (32 bytes)
        public_key       — the transport identity public key (64 bytes)
        interface_hash   — (32 bytes)
        random_hash      — (16 bytes)
        signature        — (64 bytes)
        signed_data      — public_key || interface_hash || random_hash
        destination_hash — the tunnel-synthesize control destination address
        private_key      — the transport identity private key used (so a cross-
                           impl test can drive both sides with the same key)
    """
    if transport_private_key is None:
        transport_private_key = secrets.token_bytes(KEYSIZE_BYTES)
    if interface_hash is None:
        interface_hash = secrets.token_bytes(FULL_HASH_BYTES)
    if random_hash is None:
        random_hash = secrets.token_bytes(TUNNEL_RANDOM_HASH_BYTES)
    if len(interface_hash) != FULL_HASH_BYTES:
        raise ValueError(
            f"interface_hash must be {FULL_HASH_BYTES} bytes, got {len(interface_hash)}"
        )
    if len(random_hash) != TUNNEL_RANDOM_HASH_BYTES:
        raise ValueError(
            f"random_hash must be {TUNNEL_RANDOM_HASH_BYTES} bytes, "
            f"got {len(random_hash)}"
        )

    info = bridge.execute(
        "identity_from_private_key", private_key=bytes(transport_private_key).hex()
    )
    public_key = bytes.fromhex(info["public_key"])
    if len(public_key) != KEYSIZE_BYTES:
        raise ValueError(
            f"derived public_key is {len(public_key)} bytes, expected {KEYSIZE_BYTES}"
        )

    tunnel_id_data = public_key + bytes(interface_hash)
    signed_data = tunnel_id_data + bytes(random_hash)
    signature = bytes.fromhex(
        bridge.execute(
            "identity_sign",
            private_key=bytes(transport_private_key).hex(),
            message=signed_data.hex(),
        )["signature"]
    )
    payload = signed_data + signature
    tunnel_id = bytes.fromhex(
        bridge.execute("truncated_hash", data=tunnel_id_data.hex())["full_hash"]
    )

    dest = _plain_destination_hash(bridge, TUNNEL_SYNTHESIZE_DESTINATION_NAME)
    raw = build_data_packet(
        bridge,
        dest,
        destination_type="plain",
        payload=payload,
        hops=hops,
    )
    return {
        "raw": raw,
        "tunnel_id": tunnel_id,
        "public_key": public_key,
        "interface_hash": bytes(interface_hash),
        "random_hash": bytes(random_hash),
        "signature": signature,
        "signed_data": signed_data,
        "destination_hash": dest,
        "private_key": bytes(transport_private_key),
    }
