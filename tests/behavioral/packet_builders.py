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


def build_announce_from_destination(
    bridge,
    identity_private_key: bytes,
    app_name: str,
    aspects: list,
    random_prefix: bytes = b"",   # unused: real Destination.announce generates its own random_hash
    emission_ts: int = 0,         # unused: real Destination.announce stamps current time
    wire_hops: int = 0,
    context: int = CONTEXT_NONE,
    ratchet: Optional[bytes] = None,
    app_data: bytes = b"",
) -> tuple:
    """Build a signed announce packet via the bridge's honest announce_build.

    announce_build calls real RNS.Destination.announce(send=False) inside the
    bridge process — RNS produces the full wire bytes (flags, header,
    signature, random_hash, ratchet field). We then patch the hops byte
    in-place so transport-behavior tests can inject an announce that looks
    like it has already crossed N hops.

    Returns (raw_bytes, destination_hash, identity_public_key).

    The `random_prefix`, `emission_ts`, and `context` parameters are
    retained for caller compatibility but ignored — RNS owns those.
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
