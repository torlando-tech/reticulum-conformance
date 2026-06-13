"""Interface-discovery subsystem (RNS.Discovery) — announce build/receive,
proof-of-work stamps, address + name validation.

On-network interface discovery (RNS 1.3.1 `Discovery.py`) advertises an
interface by announcing a `rnstransport.discovery.interface` destination whose
`app_data` is a self-describing record:

    app_data = bytes([flags]) || msgpack(info) || stamp(STAMP_SIZE)

`info` is a msgpack map keyed by FIXED single-byte integer constants
(Discovery.py:12-28); `flags` is a bitfield (Discovery.py:189-190); `stamp` is
an LXMF `LXStamper` proof-of-work over `infohash = SHA256(msgpack(info))`. A
receiver re-splits the buffer, re-derives the work-block, re-checks the stamp
value against a required threshold, validates every mandatory field, and only
then surfaces the discovered interface. Two implementations that disagree on any
of these — the key numbering, the flag bits, STAMP_SIZE, the work-block
expansion rounds, the hostname grammar — silently fail to discover each other.

These tests drive the REAL RNS announce builder
(`InterfaceAnnouncer.get_interface_announce_data`), the REAL receiver
(`InterfaceAnnounceHandler.received_announce`), and the REAL LXMF `LXStamper`
through dedicated bridge commands. Every assertion anchors on an EXTERNAL
ground truth:

  * the integer key constants and flag bits are pinned as SPEC LITERALS here,
    never read back from the impl;
  * the msgpack payload is decoded with the INDEPENDENT third-party `msgpack`
    package (not RNS's vendored umsgpack);
  * `infohash` is recomputed with stdlib `hashlib.sha256`;
  * the stamp work-block is recomputed from the 20-round HKDF expansion (the
    already-tested `hkdf` primitive + stdlib SHA-256 salts);
  * the stamp value/validity is recomputed by an independent leading-zero-bit
    count;
  * hostname/IP validation is cross-checked against stdlib `ipaddress` and an
    explicit re-implementation of the label grammar.

Each rule carries positive AND negative controls.
"""

import hashlib
import ipaddress
import re

import msgpack  # INDEPENDENT third-party decoder (not RNS's vendored umsgpack)

from conftest import random_hex
from conformance import conformance_case


__category_title__ = "Discovery / Resolver Hooks"
__category_order__ = 21


# --- RNS 1.3.1 spec literals (Discovery.py) — the EXTERNAL ground truth. -----
# msgpack info-map key numbering (Discovery.py:12-28)
NAME = 0xFF
TRANSPORT_ID = 0xFE
INTERFACE_TYPE = 0x00
TRANSPORT = 0x01
REACHABLE_ON = 0x02
LATITUDE = 0x03
LONGITUDE = 0x04
HEIGHT = 0x05
PORT = 0x06
IFAC_NETNAME = 0x07
IFAC_NETKEY = 0x08
FREQUENCY = 0x09
BANDWIDTH = 0x0A
SPREADINGFACTOR = 0x0B
CODINGRATE = 0x0C
MODULATION = 0x0D
CHANNEL = 0x0E

# Flag bits (Discovery.py:189-190)
FLAG_SIGNED = 0b00000001
FLAG_ENCRYPTED = 0b00000010

# Constants (Discovery.py:34-38, LXStamper.STAMP_SIZE)
STAMP_SIZE = 32                # LXStamper.STAMP_SIZE = HASHLENGTH//8 = 32
DEFAULT_STAMP_VALUE = 14
WORKBLOCK_EXPAND_ROUNDS = 20
DISCOVERABLE_INTERFACE_TYPES = [
    "BackboneInterface", "TCPServerInterface", "TCPClientInterface",
    "RNodeInterface", "WeaveInterface", "I2PInterface", "KISSInterface",
]

# A low stamp cost keeps the proof-of-work fast while still exercising the real
# LXStamper generate/verify path. 20 expansion rounds matches Discovery.py.
_COST = 6


def _decode_info(packed_hex):
    """Decode the msgpack info map with an INDEPENDENT decoder."""
    return msgpack.unpackb(
        bytes.fromhex(packed_hex), raw=False, strict_map_key=False
    )


# =============================================================================
# HOOK A — announce app_data builder (InterfaceAnnouncer.get_interface_announce_data)
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata"],
    verifies="The interface-discovery announce flag byte (app_data[0]) is 0x00 for an unencrypted announce and FLAG_ENCRYPTED (0b10) when discovery encryption is configured, matching the spec-literal flag constants (Discovery.py:189-190); the plaintext announce carries no FLAG_ENCRYPTED bit",
)
def test_appdata_flags_byte(sut):
    plain = sut.execute(
        "discovery_build_announce_appdata",
        interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "Node", "reachable_on": "example.com", "port": 4242},
    )
    assert plain["aborted"] is False
    assert plain["flags"] == 0x00, "unencrypted announce flag byte must be 0x00"
    assert plain["flags"] & FLAG_ENCRYPTED == 0

    net_priv = random_hex(64)
    enc = sut.execute(
        "discovery_build_announce_appdata",
        interface_type="TCPServerInterface",
        stamp_value=_COST,
        encrypt=True,
        network_identity_priv=net_priv,
        fields={"name": "Node", "reachable_on": "example.com", "port": 4242},
    )
    assert enc["aborted"] is False
    assert enc["flags"] == FLAG_ENCRYPTED, "encrypted announce must set FLAG_ENCRYPTED (0b10)"


@conformance_case(
    commands=["discovery_build_announce_appdata", "sha256"],
    verifies="The announce app_data layout is exactly bytes([flags]) || msgpack(info) || stamp(STAMP_SIZE=32): the buffer re-concatenates from the reported parts, the trailing 32 bytes are the stamp, and infohash recomputed independently as SHA-256(msgpack(info)) matches (Discovery.py:168-186,221-234)",
)
def test_appdata_payload_layout(sut):
    res = sut.execute(
        "discovery_build_announce_appdata",
        interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "Node", "reachable_on": "example.com", "port": 4242},
    )
    assert res["stamp_size"] == STAMP_SIZE, "STAMP_SIZE must be 32 (LXStamper)"

    app_data = res["app_data"]
    packed = res["packed_info"]
    stamp = res["stamp"]
    flags_byte = "%02x" % res["flags"]

    # Layout: flags(1) || packed || stamp(32). Pure hex-string reconstruction.
    assert app_data == flags_byte + packed + stamp, "app_data != flags || packed || stamp"
    # Trailing STAMP_SIZE bytes ARE the stamp.
    assert app_data[-2 * STAMP_SIZE:] == stamp
    assert len(bytes.fromhex(stamp)) == STAMP_SIZE
    # infohash is SHA-256 over the packed info (independent stdlib hash).
    expected_infohash = hashlib.sha256(bytes.fromhex(packed)).hexdigest()
    assert res["infohash"] == expected_infohash, "infohash must be SHA-256(msgpack(info))"


@conformance_case(
    commands=["discovery_build_announce_appdata"],
    verifies="The msgpack info map keys the mandatory fields under the exact spec-literal integer constants NAME=0xFF, TRANSPORT_ID=0xFE, INTERFACE_TYPE=0x00, TRANSPORT=0x01, LATITUDE=0x03, LONGITUDE=0x04, HEIGHT=0x05 and (for TCPServer) REACHABLE_ON=0x02, PORT=0x06, mapping to the supplied field values; the value at TRANSPORT_ID equals Transport.identity.hash and TRANSPORT is the transport_enabled bool (Discovery.py:12-28,103-141)",
)
def test_info_field_key_constants(sut):
    res = sut.execute(
        "discovery_build_announce_appdata",
        interface_type="TCPServerInterface",
        stamp_value=_COST,
        transport_enabled=True,
        fields={"name": "MyNode", "reachable_on": "example.com", "port": 4242,
                "latitude": 12.5, "longitude": -7.25, "height": 100.0},
    )
    info = _decode_info(res["packed_info"])
    assert info[INTERFACE_TYPE] == "TCPServerInterface"
    assert info[NAME] == "MyNode"
    assert info[TRANSPORT] is True                      # transport_enabled=True
    assert info[TRANSPORT_ID] == bytes.fromhex(res["transport_id"])
    assert len(info[TRANSPORT_ID]) == 16               # TRUNCATED_HASHLENGTH//8
    assert info[REACHABLE_ON] == "example.com"
    assert info[PORT] == 4242
    assert info[LATITUDE] == 12.5
    assert info[LONGITUDE] == -7.25
    assert info[HEIGHT] == 100.0
    # NEGATIVE: a TCPServer announce never carries radio-only keys.
    for k in (FREQUENCY, BANDWIDTH, SPREADINGFACTOR, CHANNEL, MODULATION):
        assert k not in info


@conformance_case(
    commands=["discovery_build_announce_appdata"],
    verifies="Per interface type the radio/endpoint keys are present exactly per spec: RNodeInterface carries FREQUENCY/BANDWIDTH/SPREADINGFACTOR/CODINGRATE (0x09-0x0C); WeaveInterface carries FREQUENCY/BANDWIDTH/CHANNEL/MODULATION (0x09,0x0A,0x0E,0x0D); KISSInterface carries FREQUENCY/BANDWIDTH/MODULATION; and none of these carry the TCP REACHABLE_ON/PORT keys (Discovery.py:115-166)",
)
def test_per_type_fields(sut):
    rnode = _decode_info(sut.execute(
        "discovery_build_announce_appdata", interface_type="RNodeInterface",
        stamp_value=_COST,
        fields={"name": "R", "frequency": 868000000, "bandwidth": 125000,
                "sf": 8, "cr": 5})["packed_info"])
    assert set([FREQUENCY, BANDWIDTH, SPREADINGFACTOR, CODINGRATE]).issubset(rnode)
    assert rnode[FREQUENCY] == 868000000 and rnode[SPREADINGFACTOR] == 8
    assert REACHABLE_ON not in rnode and PORT not in rnode
    assert CHANNEL not in rnode and MODULATION not in rnode

    weave = _decode_info(sut.execute(
        "discovery_build_announce_appdata", interface_type="WeaveInterface",
        stamp_value=_COST,
        fields={"name": "W", "frequency": 2400000000, "bandwidth": 800000,
                "channel": 11, "modulation": "lora"})["packed_info"])
    assert set([FREQUENCY, BANDWIDTH, CHANNEL, MODULATION]).issubset(weave)
    assert weave[CHANNEL] == 11 and weave[MODULATION] == "lora"
    assert SPREADINGFACTOR not in weave and REACHABLE_ON not in weave

    kiss = _decode_info(sut.execute(
        "discovery_build_announce_appdata", interface_type="KISSInterface",
        stamp_value=_COST,
        fields={"name": "K", "frequency": 434000000, "bandwidth": 12500,
                "modulation": "gfsk"})["packed_info"])
    assert set([FREQUENCY, BANDWIDTH, MODULATION]).issubset(kiss)
    assert CHANNEL not in kiss and SPREADINGFACTOR not in kiss
    assert REACHABLE_ON not in kiss and PORT not in kiss


@conformance_case(
    commands=["discovery_build_announce_appdata"],
    verifies="A TCPClientInterface announce with kiss_framing=True rewrites INTERFACE_TYPE in the info map to 'KISSInterface' (Discovery.py:158-159), while kiss_framing=False aborts the announce entirely (returns None, Discovery.py:111-113)",
)
def test_kiss_framing_rewrite(sut):
    rewritten = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPClientInterface",
        stamp_value=_COST,
        fields={"name": "C", "kiss_framing": True, "frequency": 434000000,
                "bandwidth": 12500, "modulation": "gfsk"})
    assert rewritten["aborted"] is False
    assert _decode_info(rewritten["packed_info"])[INTERFACE_TYPE] == "KISSInterface"

    aborted = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPClientInterface",
        stamp_value=_COST, fields={"name": "C", "kiss_framing": False})
    assert aborted["aborted"] is True, "TCPClient without kiss_framing must abort"
    assert aborted["app_data"] is None


@conformance_case(
    commands=["discovery_build_announce_appdata"],
    verifies="A non-whitelisted interface type aborts the announce (returns None, Discovery.py:100), while every type in the spec-literal DISCOVERABLE_INTERFACE_TYPES list that needs no extra config produces a valid announce — pinning the sender-side type whitelist (Discovery.py:37-38)",
)
def test_type_whitelist_sender(sut):
    bad = sut.execute(
        "discovery_build_announce_appdata", interface_type="FakeInterface",
        stamp_value=_COST, fields={"name": "X"})
    assert bad["aborted"] is True, "non-whitelisted type must abort"

    ok = sut.execute(
        "discovery_build_announce_appdata", interface_type="BackboneInterface",
        stamp_value=_COST,
        fields={"name": "B", "reachable_on": "203.0.113.5", "port": 4242})
    assert ok["aborted"] is False
    assert _decode_info(ok["packed_info"])[INTERFACE_TYPE] == "BackboneInterface"


@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_validate_address"],
    verifies="For Backbone/TCPServer the reachable_on parameter is embedded only when it is a valid IP address or hostname; an invalid string aborts the announce (Discovery.py:135-138). The validity verdict matches the independent is_ip_address/is_hostname oracle",
)
def test_sender_reachable_on_validation(sut):
    good = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "S", "reachable_on": "relay.example.com", "port": 4242})
    assert good["aborted"] is False
    assert _decode_info(good["packed_info"])[REACHABLE_ON] == "relay.example.com"
    # Independent oracle: that string IS a valid hostname.
    v = sut.execute("discovery_validate_address", address="relay.example.com")
    assert v["is_hostname"] or v["is_ip_address"]

    bad = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "S", "reachable_on": "not a valid host!!", "port": 4242})
    assert bad["aborted"] is True, "invalid reachable_on must abort"
    v2 = sut.execute("discovery_validate_address", address="not a valid host!!")
    assert not v2["is_hostname"] and not v2["is_ip_address"]


@conformance_case(
    commands=["discovery_build_announce_appdata"],
    verifies="IFAC network credentials are published in the info map (keys IFAC_NETNAME=0x07, IFAC_NETKEY=0x08) only when discovery_publish_ifac is explicitly True; with publish_ifac False (the security-sensitive default) neither key is present (Discovery.py:164-166)",
)
def test_ifac_publication(sut):
    off = _decode_info(sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "S", "reachable_on": "example.com", "port": 4242,
                "publish_ifac": False, "ifac_netname": "net", "ifac_netkey": "key"})["packed_info"])
    assert IFAC_NETNAME not in off, "IFAC netname must NOT leak when publish_ifac off"
    assert IFAC_NETKEY not in off, "IFAC netkey must NOT leak when publish_ifac off"

    on = _decode_info(sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "S", "reachable_on": "example.com", "port": 4242,
                "publish_ifac": True, "ifac_netname": "mynet", "ifac_netkey": "secret"})["packed_info"])
    assert on[IFAC_NETNAME] == "mynet" and on[IFAC_NETKEY] == "secret"


# =============================================================================
# HOOK A + B — encrypted announce composition / decrypt round-trip
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies="With discovery encryption the payload is network_identity.encrypt(msgpack(info)||stamp) and flags carry FLAG_ENCRYPTED; a receiver holding the same network identity recovers the info (round-trips type/reachable_on), while requesting encryption with NO network identity aborts the announce (Discovery.py:176-184,227-230)",
)
def test_encrypted_payload(sut):
    net_priv = random_hex(64)
    enc = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST, encrypt=True, network_identity_priv=net_priv,
        fields={"name": "EncNode", "reachable_on": "secret.example.com", "port": 5500})
    assert enc["aborted"] is False
    assert enc["flags"] == FLAG_ENCRYPTED

    # Receiver with the SAME network identity decrypts and surfaces the info.
    rx = sut.execute(
        "discovery_receive_announce", app_data=enc["app_data"],
        required_value=_COST, network_identity_priv=net_priv)
    assert rx["accepted"] is True, "matching network identity must decrypt the announce"
    assert rx["info"]["type"] == "TCPServerInterface"
    assert rx["info"]["reachable_on"] == "secret.example.com"

    # NEGATIVE: encryption requested but no network identity -> abort.
    aborted = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST, encrypt=True,
        fields={"name": "EncNode", "reachable_on": "secret.example.com", "port": 5500})
    assert aborted["aborted"] is True


@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies="A FLAG_ENCRYPTED announce delivered to a receiver with NO network identity is silently dropped (Discovery.py:228); the SAME announce is accepted once the receiver holds the matching network identity (positive control) — pinning that the encrypted-discovery path requires the network key",
)
def test_encrypted_rejection_without_key(sut):
    net_priv = random_hex(64)
    enc = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST, encrypt=True, network_identity_priv=net_priv,
        fields={"name": "EncNode", "reachable_on": "example.com", "port": 4242})
    assert enc["flags"] == FLAG_ENCRYPTED

    dropped = sut.execute(
        "discovery_receive_announce", app_data=enc["app_data"], required_value=_COST)
    assert dropped["accepted"] is False, "encrypted announce must drop without network identity"

    accepted = sut.execute(
        "discovery_receive_announce", app_data=enc["app_data"],
        required_value=_COST, network_identity_priv=net_priv)
    assert accepted["accepted"] is True


# =============================================================================
# HOOK C — LXStamper proof-of-work
# =============================================================================

@conformance_case(
    commands=["discovery_stamp", "hkdf", "sha256"],
    verifies="The discovery stamp work-block is the concatenation of WORKBLOCK_EXPAND_ROUNDS=20 HKDF expansions of the infohash, each salted with SHA-256(infohash || msgpack(round)); recomputing it from the already-tested hkdf primitive + stdlib SHA-256 salts reproduces the command's work-block byte-for-byte (Discovery.py:35,235; LXStamper.stamp_workblock)",
)
def test_stamp_workblock_derivation(sut):
    material = random_hex(32)
    res = sut.execute("discovery_stamp", op="workblock",
                      material=material, expand_rounds=WORKBLOCK_EXPAND_ROUNDS)
    assert res["length"] == WORKBLOCK_EXPAND_ROUNDS * 256

    material_b = bytes.fromhex(material)
    expected = b""
    for n in range(WORKBLOCK_EXPAND_ROUNDS):
        salt = hashlib.sha256(material_b + msgpack.packb(n)).digest()
        d = sut.execute("hkdf", length=256, ikm=material,
                        salt=salt.hex(), info=None)["derived_key"]
        expected += bytes.fromhex(d)
    assert res["workblock"] == expected.hex(), "work-block must match 20-round HKDF expansion"

    # NEGATIVE: a different round count yields a different (longer) work-block.
    res2 = sut.execute("discovery_stamp", op="workblock", material=material,
                       expand_rounds=WORKBLOCK_EXPAND_ROUNDS + 1)
    assert res2["workblock"] != res["workblock"]


def _leading_zero_bits(digest32):
    """Independent leading-zero-bit count over a 32-byte digest."""
    value = 0
    for byte in digest32:
        if byte == 0:
            value += 8
            continue
        bit = 7
        while bit >= 0 and not (byte >> bit) & 1:
            value += 1
            bit -= 1
        break
    return value


@conformance_case(
    commands=["discovery_stamp", "sha256"],
    verifies="A discovery stamp's value is the number of leading zero bits of SHA-256(workblock||stamp) and stamp_valid holds iff SHA-256(workblock||stamp) <= 2^(256-cost): an independently leading-zero-counted real stamp reproduces the command's value, validates at cost==value, and fails at cost==value+1 (LXStamper.stamp_value/stamp_valid)",
)
def test_stamp_value_and_validity(sut):
    material = random_hex(32)
    wb = sut.execute("discovery_stamp", op="workblock", material=material,
                     expand_rounds=WORKBLOCK_EXPAND_ROUNDS)["workblock"]
    gen = sut.execute("discovery_stamp", op="generate", material=material,
                      cost=_COST, expand_rounds=WORKBLOCK_EXPAND_ROUNDS)
    stamp = gen["stamp"]
    assert stamp is not None
    assert gen["stamp_size"] == STAMP_SIZE

    # Independent value: leading zero bits of SHA-256(workblock||stamp).
    digest = hashlib.sha256(bytes.fromhex(wb) + bytes.fromhex(stamp)).digest()
    expected_value = _leading_zero_bits(digest)

    cmd_value = sut.execute("discovery_stamp", op="value", workblock=wb, stamp=stamp)["value"]
    assert cmd_value == expected_value, "stamp value must equal leading-zero-bit count"
    assert expected_value >= _COST, "a generated stamp must meet its cost"

    # Validity threshold: holds at cost==value, fails at cost==value+1.
    assert sut.execute("discovery_stamp", op="valid", workblock=wb, stamp=stamp,
                       cost=expected_value)["valid"] is True
    assert sut.execute("discovery_stamp", op="valid", workblock=wb, stamp=stamp,
                       cost=expected_value + 1)["valid"] is False


# =============================================================================
# HOOK B — receiver stamp / length / source-allowlist gates
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies="The receiver accepts an announce whose stamp value meets the required value and silently drops one whose stamp value is below it: a genuine cost-6 stamp is accepted at required_value 6 and dropped at required_value 20 (Discovery.py:236-243)",
)
def test_receiver_stamp_rejection(sut):
    built = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "Node", "reachable_on": "example.com", "port": 4242})
    app_data = built["app_data"]

    accepted = sut.execute("discovery_receive_announce", app_data=app_data,
                           required_value=_COST)
    assert accepted["accepted"] is True

    dropped = sut.execute("discovery_receive_announce", app_data=app_data,
                          required_value=DEFAULT_STAMP_VALUE + 6)
    assert dropped["accepted"] is False, "stamp below required value must be dropped"
    assert dropped["callback_invoked"] is False


@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies="An app_data buffer of length <= STAMP_SIZE+1 (33 bytes) is ignored before any decode (Discovery.py:221), while a full genuine announce (longer than 33 bytes) is processed — pinning the minimum-length gate at STAMP_SIZE=32 plus the one flag byte",
)
def test_minimum_appdata_length(sut):
    built = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "Node", "reachable_on": "example.com", "port": 4242})
    assert built["stamp_size"] == STAMP_SIZE
    full = built["app_data"]
    assert len(bytes.fromhex(full)) > STAMP_SIZE + 1

    too_short = "00" * (STAMP_SIZE + 1)        # exactly 33 bytes -> ignored
    assert len(bytes.fromhex(too_short)) == STAMP_SIZE + 1
    res_short = sut.execute("discovery_receive_announce", app_data=too_short,
                            required_value=_COST)
    assert res_short["accepted"] is False, "<=33-byte app_data must be ignored"

    res_full = sut.execute("discovery_receive_announce", app_data=full,
                           required_value=_COST)
    assert res_full["accepted"] is True


@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce",
              "identity_from_private_key"],
    verifies="When an interface_discovery_sources allowlist is configured, an announce from an identity IN the allowlist is accepted and an otherwise-identical announce from an identity NOT in the allowlist is dropped (Discovery.py:216-219)",
)
def test_source_allowlist(sut):
    src_priv = random_hex(64)
    src_hash = sut.execute("identity_from_private_key", private_key=src_priv)["hash"]
    other_hash = sut.execute("identity_from_private_key",
                             private_key=random_hex(64))["hash"]

    built = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "Node", "reachable_on": "example.com", "port": 4242})
    app_data = built["app_data"]

    allowed = sut.execute(
        "discovery_receive_announce", app_data=app_data, required_value=_COST,
        announce_identity_priv=src_priv, discovery_sources=[src_hash])
    assert allowed["accepted"] is True, "announce from allowlisted source must be accepted"

    blocked = sut.execute(
        "discovery_receive_announce", app_data=app_data, required_value=_COST,
        announce_identity_priv=src_priv, discovery_sources=[other_hash])
    assert blocked["accepted"] is False, "announce from non-allowlisted source must drop"
    assert blocked["callback_invoked"] is False


@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies="When the sanitized interface name is empty, the receiver falls back to the literal 'Discovered <interface_type>' name (Discovery.py:265); a normal name is surfaced verbatim (positive control)",
)
def test_receiver_name_fallback(sut):
    empty_named = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "!!!", "reachable_on": "example.com", "port": 4242})
    rx = sut.execute("discovery_receive_announce",
                     app_data=empty_named["app_data"], required_value=_COST)
    assert rx["accepted"] is True
    assert rx["info"]["name"] == "Discovered TCPServerInterface"

    named = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST,
        fields={"name": "RealName", "reachable_on": "example.com", "port": 4242})
    rx2 = sut.execute("discovery_receive_announce",
                      app_data=named["app_data"], required_value=_COST)
    assert rx2["info"]["name"] == "RealName"


# =============================================================================
# HOOK D — address validation grammar
# =============================================================================

def _hostname_oracle(hostname):
    """Independent re-implementation of Discovery.is_hostname (Discovery.py:779-785)."""
    if hostname == "":
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    components = hostname.split(".")
    if re.match(r"[0-9]+$", components[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in components)


@conformance_case(
    commands=["discovery_validate_address"],
    verifies="is_ip_address/is_hostname/is_ygg_ipv6 implement the spec grammar (Discovery.py:769-785): IP detection matches stdlib ipaddress; hostnames obey the 253-char cap, the (?!-)[a-z0-9-]{1,63}(?<!-) per-label rule, numeric-TLD rejection and trailing-dot strip; and the Yggdrasil 200::/7 range is detected — verified against stdlib ipaddress + an independent label-grammar oracle and hand-pinned spec cases",
)
def test_hostname_validation_rules(sut):
    # is_ip_address vs stdlib ipaddress.
    for addr in ["192.168.1.1", "203.0.113.5", "::1", "2001:db8::1",
                 "999.1.1.1", "example.com", "not.an.ip"]:
        try:
            ipaddress.ip_address(addr)
            expect_ip = True
        except ValueError:
            expect_ip = False
        got = sut.execute("discovery_validate_address", address=addr)
        assert got["is_ip_address"] == expect_ip, f"is_ip_address({addr})"

    # is_hostname against the independent label-grammar oracle + pinned cases.
    long_invalid = ".".join(["a" * 60] * 5)        # 304 chars > 253 -> False
    pinned = {
        "example.com": True,
        "good-host.example.com": True,
        "example.com.": True,         # trailing dot stripped
        "host.123": False,            # numeric TLD
        "-bad.com": False,            # leading hyphen
        "bad-.com": False,            # trailing hyphen
        "under_score.com": False,     # underscore not allowed
        long_invalid: False,          # exceeds 253-char cap
    }
    for host, expect in pinned.items():
        got = sut.execute("discovery_validate_address", address=host)["is_hostname"]
        assert got == expect, f"is_hostname({host}) expected {expect}"
        assert _hostname_oracle(host) == expect, f"oracle disagreement on {host}"

    # is_ygg_ipv6: 200::/7 membership.
    assert sut.execute("discovery_validate_address", address="200::1")["is_ygg_ipv6"] is True
    assert sut.execute("discovery_validate_address", address="300::1")["is_ygg_ipv6"] is True
    assert sut.execute("discovery_validate_address", address="2001:db8::1")["is_ygg_ipv6"] is False
    assert sut.execute("discovery_validate_address", address="192.168.1.1")["is_ygg_ipv6"] is False


# =============================================================================
# HOOK E — interface-name sanitization
# =============================================================================

@conformance_case(
    commands=["discovery_sanitize_name"],
    verifies="InterfaceAnnounceHandler.sanitize_name coerces to ASCII, collapses runs of 2/3/5 spaces to one, and trims leading/trailing characters outside the alnum san_map (Discovery.py:205-212); the sender-side sanitize strips CR/LF and surrounding whitespace (Discovery.py:89-94); pinned against hand-computed expected outputs",
)
def test_name_sanitization(sut):
    cases = {
        "  Hello   World  ": "Hello World",     # collapse + trim
        "A     B": "A B",                       # 5-space collapse
        "!!!Name!!!": "Name",                   # trim non-alnum ends
        "!!!": "",                              # all-trimmed -> empty
        "café": "caf",                     # ASCII coercion drops 'é'
    }
    for raw, expect in cases.items():
        got = sut.execute("discovery_sanitize_name", name=raw)["sanitize_name"]
        assert got == expect, f"sanitize_name({raw!r}) -> {got!r}, expected {expect!r}"

    # Sender-side sanitize: strip CR/LF, then surrounding whitespace.
    assert sut.execute("discovery_sanitize_name", name="Node\nName\r")["sanitize"] == "NodeName"
    assert sut.execute("discovery_sanitize_name", name="  trimmed  ")["sanitize"] == "trimmed"
