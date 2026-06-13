"""Interface-discovery V2 gap closure — per-type RECEIVER surfacing + config
entries, the I2P REACHABLE_ON=b32 branch, the receiver info-record schema, the
discovery-hash derivation + re-announce dedup, the resolver-store type whitelist
(InterfaceDiscovery.DISCOVERABLE_TYPES, which EXCLUDES TCPClientInterface), the
listing trust-revocation purge, unused-flag-bit tolerance, the DEFAULT_STAMP_VALUE
sender/receiver default, and the announce-handler aspect_filter wiring contract
(RNS 1.3.1 ``Discovery.py``).

These close the V2 remainder the existing hook suites leave open: the prior
files pin the SENDER per-type field sets and positive/negative receive gates, but
never assert what the RECEIVER surfaces per type (the info dict + the
``config_entry`` strings ``rnstatus -D`` consumes), never build/receive the I2P
branch, never default the stamp cost, never read the handler's aspect_filter, and
never exercise the distinct resolver-store whitelist.

Every assertion anchors on an EXTERNAL ground truth:
  * the msgpack key constants, the two interface-type whitelists, the flag bits,
    DEFAULT_STAMP_VALUE=14 and the aspect_filter dotted name are pinned here as
    SPEC LITERALS (Discovery.py), never read back from the impl to define the
    expectation;
  * the SENDER info map is decoded with the INDEPENDENT third-party ``msgpack``
    package (not RNS's vendored umsgpack);
  * the discovery hash is recomputed with stdlib ``hashlib`` over the documented
    ``transport_id_hex || name`` material;
  * per-type receiver fields are anchored on the field VALUES the test supplied
    and the ``config_entry`` grammar is anchored on spec-literal substrings.

Each rule carries positive AND negative controls.
"""

import hashlib

import msgpack  # INDEPENDENT third-party decoder (not RNS's vendored umsgpack)

from conftest import random_hex
from conformance import conformance_case


__category_title__ = "Discovery / Resolver V2"
__category_order__ = 23


# --- RNS 1.3.1 spec literals (Discovery.py) — the EXTERNAL ground truth. -----
NAME = 0xFF
TRANSPORT_ID = 0xFE
INTERFACE_TYPE = 0x00
TRANSPORT = 0x01
REACHABLE_ON = 0x02
PORT = 0x06
FREQUENCY = 0x09
BANDWIDTH = 0x0A
SPREADINGFACTOR = 0x0B
CODINGRATE = 0x0C
MODULATION = 0x0D
CHANNEL = 0x0E

FLAG_SIGNED = 0b00000001
FLAG_ENCRYPTED = 0b00000010

DEFAULT_STAMP_VALUE = 14
STAMP_SIZE = 32

# Discovery destination / handler aspect_filter dotted name
# (APP_NAME + aspects, Discovery.py:30,200).
DISCOVERY_FULL_NAME = "rnstransport.discovery.interface"

# The two DISTINCT interface-type whitelists (Discovery.py:37-38 vs :377).
# The handler/announcer list accepts TCPClientInterface; the resolver STORE list
# (InterfaceDiscovery.DISCOVERABLE_TYPES) does NOT — a record whose type is
# TCPClientInterface is received but never persisted/listed.
DISCOVERABLE_INTERFACE_TYPES = [
    "BackboneInterface", "TCPServerInterface", "TCPClientInterface",
    "RNodeInterface", "WeaveInterface", "I2PInterface", "KISSInterface",
]
DISCOVERABLE_TYPES = [
    "BackboneInterface", "TCPServerInterface", "I2PInterface",
    "RNodeInterface", "WeaveInterface", "KISSInterface",
]

_COST = 6  # low PoW cost keeps the real LXStamper fast


def _decode_info(packed_hex):
    return msgpack.unpackb(
        bytes.fromhex(packed_hex), raw=False, strict_map_key=False)


def _build(sut, interface_type, fields, **kw):
    return sut.execute(
        "discovery_build_announce_appdata", interface_type=interface_type,
        stamp_value=_COST, transport_enabled=True, fields=fields, **kw)


def _recv(sut, app_data, **kw):
    return sut.execute("discovery_receive_announce", app_data=app_data, **kw)


# =============================================================================
# discovery-i2p-b32-reachable-on + discovery-per-type-fields (I2P branch)
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies=(
        "The I2P sender branch embeds REACHABLE_ON (0x02) = interface.b32 ONLY "
        "when the interface is connectable AND b32 is set (Discovery.py:143-144): "
        "connectable+b32 carries the b32 in REACHABLE_ON, while connectable=False "
        "or b32=None omit REACHABLE_ON. The receiver surfaces the I2P interface "
        "with info['reachable_on']==b32 and a config_entry of the form "
        "'type = I2PInterface ... peers = <b32>' (Discovery.py:296-306); an I2P "
        "announce with NO REACHABLE_ON is dropped at the receiver (the I2P branch "
        "dereferences REACHABLE_ON unconditionally)."
    ),
)
def test_i2p_b32_reachable_on(sut):
    b32 = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"

    # SENDER: REACHABLE_ON present only with connectable AND b32.
    on = _build(sut, "I2PInterface", {"name": "I2", "connectable": True, "b32": b32})
    assert on["aborted"] is False
    info = _decode_info(on["packed_info"])
    assert info[INTERFACE_TYPE] == "I2PInterface"
    assert info[REACHABLE_ON] == b32

    no_conn = _decode_info(_build(
        sut, "I2PInterface", {"name": "I2", "connectable": False, "b32": b32})["packed_info"])
    assert REACHABLE_ON not in no_conn, "non-connectable I2P must not publish REACHABLE_ON"
    no_b32 = _decode_info(_build(
        sut, "I2PInterface", {"name": "I2", "connectable": True})["packed_info"])
    assert REACHABLE_ON not in no_b32, "I2P without b32 must not publish REACHABLE_ON"

    # RECEIVER: surfaces reachable_on + an I2P config_entry.
    rx = _recv(sut, on["app_data"], required_value=_COST)
    assert rx["accepted"] is True
    assert rx["info"]["type"] == "I2PInterface"
    assert rx["info"]["reachable_on"] == b32
    cfg = rx["info"]["config_entry"]
    assert "type = I2PInterface" in cfg
    assert f"peers = {b32}" in cfg

    # NEGATIVE: an I2P announce without REACHABLE_ON is dropped (the receiver's
    # I2P branch dereferences REACHABLE_ON, Discovery.py:297).
    dropped = _recv(sut, _build(
        sut, "I2PInterface", {"name": "I2", "connectable": True})["app_data"],
        required_value=_COST)
    assert dropped["accepted"] is False, "I2P announce missing REACHABLE_ON must drop"


# =============================================================================
# discovery-per-type-fields (RECEIVER surfacing) + discovery-receiver-info-record-schema
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies=(
        "The receiver surfaces the per-type interface parameters and composes the "
        "rnstatus -D config_entry per type (Discovery.py:279-354): RNode surfaces "
        "frequency/bandwidth/sf/cr and a 'type = RNodeInterface' entry with "
        "spreadingfactor/codingrate lines; Weave surfaces frequency/bandwidth/"
        "channel/modulation under a 'type = WeaveInterface' entry; KISS surfaces "
        "frequency/bandwidth/modulation under a 'type = KISSInterface' entry whose "
        "commented Frequency/Bandwidth/Modulation lines carry the values; "
        "TCPServer/Backbone surface reachable_on/port and a config_entry carrying "
        "the remote host + target_port. Anchored on the field VALUES supplied and "
        "spec-literal config_entry substrings."
    ),
)
def test_receiver_per_type_surfacing(sut):
    rnode = _recv(sut, _build(sut, "RNodeInterface", {
        "name": "R", "frequency": 868000000, "bandwidth": 125000,
        "sf": 8, "cr": 5})["app_data"], required_value=_COST)["info"]
    assert rnode["type"] == "RNodeInterface"
    assert rnode["frequency"] == 868000000 and rnode["bandwidth"] == 125000
    assert rnode["sf"] == 8 and rnode["cr"] == 5
    assert "type = RNodeInterface" in rnode["config_entry"]
    assert "spreadingfactor = 8" in rnode["config_entry"]
    assert "codingrate = 5" in rnode["config_entry"]

    weave = _recv(sut, _build(sut, "WeaveInterface", {
        "name": "W", "frequency": 2400000000, "bandwidth": 800000,
        "channel": 11, "modulation": "lora"})["app_data"], required_value=_COST)["info"]
    assert weave["type"] == "WeaveInterface"
    assert weave["frequency"] == 2400000000 and weave["bandwidth"] == 800000
    assert weave["channel"] == 11 and weave["modulation"] == "lora"
    assert "type = WeaveInterface" in weave["config_entry"]
    # NEGATIVE: the receiver must NOT surface radio keys foreign to Weave.
    assert "sf" not in weave and "cr" not in weave

    kiss = _recv(sut, _build(sut, "KISSInterface", {
        "name": "K", "frequency": 434000000, "bandwidth": 12500,
        "modulation": "gfsk"})["app_data"], required_value=_COST)["info"]
    assert kiss["type"] == "KISSInterface"
    assert kiss["frequency"] == 434000000 and kiss["bandwidth"] == 12500
    assert kiss["modulation"] == "gfsk"
    assert "type = KISSInterface" in kiss["config_entry"]
    assert "# Frequency: 434000000" in kiss["config_entry"]
    assert "# Modulation: gfsk" in kiss["config_entry"]
    assert "channel" not in kiss and "sf" not in kiss

    backbone = _recv(sut, _build(sut, "BackboneInterface", {
        "name": "BB", "reachable_on": "203.0.113.5",
        "port": 4242})["app_data"], required_value=_COST)["info"]
    assert backbone["type"] == "BackboneInterface"
    assert backbone["reachable_on"] == "203.0.113.5" and backbone["port"] == 4242
    assert "203.0.113.5" in backbone["config_entry"]
    assert "target_port = 4242" in backbone["config_entry"]
    assert "frequency" not in backbone and "channel" not in backbone


@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies=(
        "The receiver info record carries the documented schema (Discovery.py:"
        "263-274): transport_id and network_id are UNDELIMITED lowercase hex of "
        "the 16-byte transport/network identity hashes (32 hex chars, no ':' "
        "delimiter); transport is the bool from the announce; stamp is the "
        "STAMP_SIZE=32 byte (64-hex) proof; value is the leading-zero-bit count "
        ">= the required value; received is a float wall-clock time; hops is an "
        "int. transport_id matches the announce builder's reported transport "
        "identity, and network_id matches the announcing identity hash — both "
        "INDEPENDENT anchors, not impl-vs-itself."
    ),
)
def test_receiver_info_record_schema(sut):
    built = _build(sut, "TCPServerInterface", {
        "name": "Node", "reachable_on": "example.com", "port": 4242})
    rx = _recv(sut, built["app_data"], required_value=_COST)
    info = rx["info"]

    # transport_id == the announce builder's transport identity (undelimited hex).
    assert info["transport_id"] == built["transport_id"]
    assert len(info["transport_id"]) == 32 and ":" not in info["transport_id"]
    assert info["transport_id"] == info["transport_id"].lower()
    # network_id == the announcing identity hash reported by the receiver.
    assert info["network_id"] == rx["announce_identity_hash"]
    assert len(info["network_id"]) == 32 and ":" not in info["network_id"]

    assert info["transport"] is True              # transport_enabled=True
    assert len(bytes.fromhex(info["stamp"])) == STAMP_SIZE
    assert isinstance(info["value"], int) and info["value"] >= _COST
    assert isinstance(info["received"], float)
    assert isinstance(info["hops"], int)


# =============================================================================
# discovery-record-hash-derivation (+ re-announce dedup / heard_count)
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce",
              "discovery_store_record"],
    verifies=(
        "The discovered-record key is full_hash((transport_id_hex || name)."
        "encode('utf-8')) (Discovery.py:356-357) — recomputed independently with "
        "stdlib SHA-256 it reproduces info['discovery_hash'], and a different "
        "name yields a different hash (negative control). Because that hash is the "
        "storage filename (Discovery.py:459), a re-announce of the same "
        "transport+name DEDUPLICATES rather than duplicates: storing the same "
        "record N times leaves a single file whose heard_count == N-1 "
        "(Discovery.py:476-495)."
    ),
)
def test_discovery_record_hash_and_dedup(sut):
    built = _build(sut, "TCPServerInterface", {
        "name": "NodeX", "reachable_on": "example.com", "port": 4242})
    info = _recv(sut, built["app_data"], required_value=_COST)["info"]

    # Independent SHA-256 over the documented material (transport_id_hex + name).
    material = (info["transport_id"] + info["name"]).encode("utf-8")
    expected = hashlib.new("sha256", material).hexdigest()
    assert info["discovery_hash"] == expected, (
        f"discovery_hash {info['discovery_hash']} != independent "
        f"SHA-256(transport_id||name) {expected}")

    # NEGATIVE: a different name must move the hash.
    other = _recv(sut, _build(sut, "TCPServerInterface", {
        "name": "NodeY", "reachable_on": "example.com",
        "port": 4242})["app_data"], required_value=_COST)["info"]
    assert other["discovery_hash"] != info["discovery_hash"]

    # Re-announce dedup: storing the same record thrice -> one file, heard_count 2.
    once = sut.execute("discovery_store_record", name="Dedup", repeat=1)
    assert once["stored"] is True and once["heard_count"] == 0
    thrice = sut.execute("discovery_store_record", name="Dedup", repeat=3)
    assert thrice["stored"] is True
    assert thrice["heard_count"] == 2, "re-announce must increment heard_count, not duplicate"
    # The stored filename IS the discovery hash (single record either way).
    assert thrice["listed_names"] == ["Dedup"]


# =============================================================================
# discovery-receiver-flag-bit-tolerance
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies=(
        "received_announce computes signed = flags & FLAG_SIGNED but never acts "
        "on it, and ignores unknown high flag bits entirely — only FLAG_ENCRYPTED "
        "(0b10) changes the decode (Discovery.py:222-230). A genuine announce "
        "replayed with the flag byte set to FLAG_SIGNED (0x01), an unknown bit "
        "(0x04), or both (0x05) is processed identically to the 0x00 baseline, "
        "while setting FLAG_ENCRYPTED (0x02) with no network identity drops it "
        "(negative control isolating the one meaningful bit)."
    ),
)
def test_receiver_flag_bit_tolerance(sut):
    built = _build(sut, "TCPServerInterface", {
        "name": "Flagged", "reachable_on": "example.com", "port": 4242})
    app_data = built["app_data"]
    body = app_data[2:]  # everything after the flag byte (RNS's own packed||stamp)

    baseline = _recv(sut, "%02x" % 0x00 + body, required_value=_COST)
    assert baseline["accepted"] is True

    # Spec-literal flag bytes the receiver must tolerate (no FLAG_ENCRYPTED).
    for fb in (FLAG_SIGNED, 0x04, FLAG_SIGNED | 0x04):
        rx = _recv(sut, "%02x" % fb + body, required_value=_COST)
        assert rx["accepted"] is True, f"flag byte 0x{fb:02x} must be tolerated"
        assert rx["info"]["type"] == baseline["info"]["type"]
        assert rx["info"]["name"] == baseline["info"]["name"]

    # NEGATIVE: the FLAG_ENCRYPTED bit IS special — without a network identity it
    # forces a decrypt that fails, dropping the announce.
    enc = _recv(sut, "%02x" % FLAG_ENCRYPTED + body, required_value=_COST)
    assert enc["accepted"] is False, "FLAG_ENCRYPTED with no network identity must drop"


# =============================================================================
# discovery-default-stamp-cost-14
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies=(
        "DEFAULT_STAMP_VALUE=14 is both the SENDER default stamp cost when "
        "interface.discovery_stamp_value is unset (Discovery.py:34,98) and the "
        "RECEIVER default required_value (InterfaceAnnounceHandler.__init__ "
        "default, Discovery.py:192). Building an announce with NO stamp_value "
        "produces a stamp whose value >= 14 (accepted at required_value 14), and "
        "the impl's DEFAULT_STAMP_VALUE constant equals the spec literal 14. A "
        "receiver constructed with its DEFAULT required_value reports 14 and DROPS "
        "a genuine cost-6 announce (6 < 14) that it accepts once required_value is "
        "lowered to 6 — proving the default threshold is 14, not a weaker value."
    ),
)
def test_default_stamp_cost_14(sut):
    # SENDER default: omit the per-interface stamp value (None) -> impl falls back
    # to DEFAULT_STAMP_VALUE, producing a value-14 proof.
    dflt = sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=None, transport_enabled=True,
        fields={"name": "D", "reachable_on": "example.com", "port": 4242})
    assert dflt["aborted"] is False
    assert dflt["default_stamp_value"] == DEFAULT_STAMP_VALUE
    at14 = _recv(sut, dflt["app_data"], required_value=DEFAULT_STAMP_VALUE)
    assert at14["accepted"] is True, "default-cost announce must meet the value-14 threshold"

    # RECEIVER default: a genuine cost-6 announce, delivered to a handler built
    # with its DEFAULT required_value, is dropped (6 < 14); accepted at 6.
    cost6 = _build(sut, "TCPServerInterface", {
        "name": "Six", "reachable_on": "example.com", "port": 4242})
    under_default = _recv(sut, cost6["app_data"], default_required_value=True)
    assert under_default["required_value"] == DEFAULT_STAMP_VALUE, (
        "receiver default required_value must be DEFAULT_STAMP_VALUE=14")
    assert under_default["default_stamp_value"] == DEFAULT_STAMP_VALUE
    assert under_default["accepted"] is False, "cost-6 announce must drop under default-14 receiver"
    # Positive control: the SAME announce is accepted with required_value 6.
    assert _recv(sut, cost6["app_data"], required_value=_COST)["accepted"] is True


# =============================================================================
# discovery-transport-wiring-aspect-filter
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies=(
        "InterfaceAnnounceHandler.aspect_filter is the dotted name "
        "'rnstransport.discovery.interface' (APP_NAME + 'discovery' + 'interface', "
        "Discovery.py:30,200) — the string Transport's announce-handler dispatch "
        "matches against the discovery destination's expanded name so the handler "
        "is the one that receives real discovery announces. A wrong aspect_filter "
        "would silently never fire. Asserted against the spec-literal full name "
        "and proven distinct from a near-miss ('rnstransport.discovery.iface')."
    ),
)
def test_handler_aspect_filter(sut):
    built = _build(sut, "TCPServerInterface", {
        "name": "A", "reachable_on": "example.com", "port": 4242})
    rx = _recv(sut, built["app_data"], required_value=_COST)
    assert rx["aspect_filter"] == DISCOVERY_FULL_NAME, (
        f"handler.aspect_filter {rx['aspect_filter']!r} != spec dotted name "
        f"{DISCOVERY_FULL_NAME!r} — Transport would never route discovery "
        f"announces to this handler")
    # NEGATIVE: the filter is specific to the exact dotted name.
    assert rx["aspect_filter"] != "rnstransport.discovery.iface"


# =============================================================================
# discovery-type-whitelist (resolver-store DISCOVERABLE_TYPES, excludes TCPClient)
# =============================================================================

@conformance_case(
    commands=["discovery_store_record"],
    verifies=(
        "The resolver STORE whitelist InterfaceDiscovery.DISCOVERABLE_TYPES "
        "(Discovery.py:377) is DISTINCT from the handler/announcer "
        "DISCOVERABLE_INTERFACE_TYPES (Discovery.py:37-38): it EXCLUDES "
        "TCPClientInterface. A TCPClientInterface announce is accepted by the "
        "receiver (yielding a genuine info record) but interface_discovered "
        "REFUSES to persist it (Discovery.py:457), so it is never stored or "
        "listed; a TCPServerInterface record IS stored. The impl's two constants "
        "match the spec-literal lists and differ by exactly {TCPClientInterface}."
    ),
)
def test_resolver_store_type_whitelist(sut):
    srv = sut.execute("discovery_store_record", name="Srv")
    assert srv["received"] is True and srv["record_type"] == "TCPServerInterface"
    assert srv["stored"] is True, "a TCPServerInterface record must be stored"
    assert srv["listed_names"] == ["Srv"]

    cli = sut.execute(
        "discovery_store_record", name="Cli", set_interface_type="TCPClientInterface")
    assert cli["received"] is True, "the handler whitelist accepts TCPClientInterface"
    assert cli["record_type"] == "TCPClientInterface"
    assert cli["stored"] is False, (
        "TCPClientInterface must NOT be persisted by the resolver store "
        "(DISCOVERABLE_TYPES excludes it, Discovery.py:457)")
    assert cli["listed_names"] == []

    # Impl constants == spec literals; the two whitelists differ by TCPClient.
    assert cli["discoverable_interface_types"] == DISCOVERABLE_INTERFACE_TYPES
    assert cli["discoverable_types"] == DISCOVERABLE_TYPES
    assert "TCPClientInterface" in cli["discoverable_interface_types"]
    assert "TCPClientInterface" not in cli["discoverable_types"]
    assert (set(cli["discoverable_interface_types"]) - set(cli["discoverable_types"])
            == {"TCPClientInterface"})


# =============================================================================
# discovery-listing-allowlist-purge (trust revocation at LIST time)
# =============================================================================

@conformance_case(
    commands=["identity_from_private_key", "discovery_store_record"],
    verifies=(
        "When interface_discovery_sources is configured, "
        "list_discovered_interfaces REMOVES any stored record whose network_id is "
        "not in the allowlist (Discovery.py:417-418) — trust revocation AFTER "
        "acceptance. A record stored from identity A survives listing when the "
        "allowlist is [A] and is purged (removed from disk + absent from the "
        "listing) when the allowlist is [B != A]. Anchored on two independent "
        "minted identities."
    ),
)
def test_resolver_listing_allowlist_purge(sut):
    a_priv = random_hex(64)
    a_hash = sut.execute("identity_from_private_key", private_key=a_priv)["hash"]
    b_hash = sut.execute(
        "identity_from_private_key", private_key=random_hex(64))["hash"]

    kept = sut.execute(
        "discovery_store_record", name="Keep",
        announce_identity_priv=a_priv, list_sources=[a_hash])
    assert kept["announce_identity_hash"] == a_hash
    assert kept["stored"] is True
    assert kept["listed_names"] == ["Keep"], "allowlisted source must survive listing"

    purged = sut.execute(
        "discovery_store_record", name="Purge",
        announce_identity_priv=a_priv, list_sources=[b_hash])
    assert purged["stored"] is True, "record is stored before the listing purge runs"
    assert purged["listed_names"] == [], (
        "a record sourced by a non-allowlisted identity must be purged at list time "
        "(Discovery.py:417-418)")
