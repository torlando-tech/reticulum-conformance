"""
Helpers for constructing valid RNS packets from first principles in tests.

Tests inject raw bytes onto MockInterfaces. Those bytes need to parse and
validate as real RNS packets (correct flags, valid signature, etc). Rather
than spin up a full RNS instance in the test process, we use the bridge's
crypto + pack primitives to build them: `identity_sign`, `announce_pack`,
`packet_pack`, `random_hash`.

This keeps test-side construction purely a byte-level exercise with no state.
"""

import hashlib
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


def build_announce_raw(
    bridge,
    identity_public_key: bytes,
    identity_private_key: bytes,
    destination_hash: bytes,
    random_prefix: bytes,
    emission_ts: int,
    wire_hops: int = 0,
    context: int = CONTEXT_NONE,
    ratchet: Optional[bytes] = None,
    app_data: bytes = b"",
    transport_id: Optional[bytes] = None,
) -> bytes:
    """Build a valid HEADER_1 announce packet's raw wire bytes via the bridge.

    The signature is computed over destination_hash + public_key + name_hash +
    random_hash + ratchet + app_data, matching RNS/Destination.py:1463-1465.

    name_hash is derived from the destination hash layout. For tests we invert
    the usual derivation: the caller tells us the destination_hash, and we
    use the first 10 bytes of full_hash(dest_hash + public_key) as a stand-in
    name_hash — not cryptographically identical to real name_hash derivation,
    but RNS's announce validation rebuilds the dest_hash from the name_hash +
    identity_hash and compares. So for a realistic test, derive name_hash + the
    dest hash together via the bridge's `destination_hash` command.

    For now we accept that tests which need signature-verifying announces must
    use a pre-computed (name_hash, destination_hash) pair via
    build_announce_from_destination().
    """
    raise NotImplementedError(
        "Use build_announce_from_destination() — full announce construction needs "
        "a real name/aspect derivation which flows through bridge.destination_hash."
    )


def build_announce_from_destination(
    bridge,
    identity_private_key: bytes,
    app_name: str,
    aspects: list,
    random_prefix: bytes,
    emission_ts: int,
    wire_hops: int = 0,
    context: int = CONTEXT_NONE,
    ratchet: Optional[bytes] = None,
    app_data: bytes = b"",
) -> tuple:
    """Build a signed announce packet by round-tripping through the bridge.

    Returns (raw_bytes, destination_hash, identity_public_key).

    Bridge commands used:
      identity_from_private_key -> public_key, identity_hash
      name_hash                 -> 10-byte name_hash from app_name + aspects
      destination_hash          -> 16-byte destination_hash
      identity_sign             -> 64-byte signature
      announce_pack             -> packed announce_data
      packet_pack               -> final raw packet bytes
    """
    id_info = bridge.execute(
        "identity_from_private_key",
        private_key=identity_private_key.hex(),
    )
    public_key = bytes.fromhex(id_info["public_key"])
    identity_hash = bytes.fromhex(id_info["hash"])

    # name_hash = sha256("app_name.aspect1.aspect2…")[:10]
    # (matches cmd_destination_hash in bridge_server.py)
    full_name = ".".join([app_name] + list(aspects))
    name_hash = hashlib.sha256(full_name.encode("utf-8")).digest()[:NAME_HASH_BYTES]

    dest_info = bridge.execute(
        "destination_hash",
        identity_hash=identity_hash.hex(),
        app_name=app_name,
        aspects=list(aspects),  # JSON array — Python accepts list OR string,
                                # Kotlin bridge only accepts array.
    )
    destination_hash = bytes.fromhex(dest_info["destination_hash"])

    random_hash = build_random_hash(random_prefix, emission_ts)

    # Signed data: destination_hash + public_key + name_hash + random_hash + ratchet + app_data
    ratchet_bytes = ratchet if ratchet else b""
    signed_data = destination_hash + public_key + name_hash + random_hash + ratchet_bytes + app_data

    sig_info = bridge.execute(
        "identity_sign",
        private_key=identity_private_key.hex(),
        message=signed_data.hex(),
    )
    signature = bytes.fromhex(sig_info["signature"])

    # Pack announce data via the bridge to match exactly what the bridge expects
    ann_info = bridge.execute(
        "announce_pack",
        public_key=public_key.hex(),
        name_hash=name_hash.hex(),
        random_hash=random_hash.hex(),
        ratchet=ratchet.hex() if ratchet else "",
        signature=signature.hex(),
        app_data=app_data.hex(),
    )
    announce_data = bytes.fromhex(ann_info["announce_data"])

    # Build raw HEADER_1 packet: [flags][hops][dest_hash][context][data]
    context_flag = CONTEXT_FLAG_SET if ratchet else CONTEXT_FLAG_UNSET
    flags = compose_flags(
        header_type=HEADER_1,
        context_flag=context_flag,
        transport_type=TRANSPORT_BROADCAST,
        destination_type=DESTINATION_TYPE_SINGLE,
        packet_type=PACKET_TYPE_ANNOUNCE,
    )

    raw = bytes([flags, wire_hops & 0xFF]) + destination_hash + bytes([context]) + announce_data

    return raw, destination_hash, public_key


def parse_packet_header(raw: bytes) -> dict:
    """Parse just the outer packet header bytes. Does not validate signatures."""
    if len(raw) < 19:
        raise ValueError("raw too short to be a packet")
    flags = raw[0]
    hops = raw[1]
    header_type = (flags & 0b01000000) >> 6
    context_flag = (flags & 0b00100000) >> 5
    transport_type = (flags & 0b00010000) >> 4
    destination_type = (flags & 0b00001100) >> 2
    packet_type = flags & 0b00000011

    if header_type == HEADER_2:
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
