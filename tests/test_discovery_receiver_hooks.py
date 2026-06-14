"""Interface-discovery RECEIVER hardening — mandatory-field presence, field
type/length validation, the receiver-side interface-type whitelist, the
announce-destination identity selection, the opt-in feature defaults and the
discovered-record staleness thresholds (RNS 1.3.1 ``Discovery.py``).

These close the deferred second-wave receiver gaps. They drive the REAL
receive path (`InterfaceAnnounceHandler.received_announce`,
`InterfaceDiscovery.list_discovered_interfaces`, `InterfaceAnnouncer.__init__`)
through dedicated bridge commands. Malformed announces are produced by
`discovery_craft_announce`, which mutates ONE field of a GENUINE RNS-built,
RNS-serialised, real-LXStamper-stamped announce and replays it — so each
rejection is attributable to the mutation, never to a hand-rolled forgery.

Every assertion anchors on an EXTERNAL ground truth:
  * the mandatory msgpack key constants and the DISCOVERABLE_INTERFACE_TYPES
    whitelist are pinned here as SPEC LITERALS (Discovery.py:12-28,37-38),
    never read back from the impl;
  * the discovery destination's identity selection is cross-checked against the
    independent naming oracle `hash_from_name_and_identity` and the spec-literal
    full name ``rnstransport.discovery.interface``;
  * the staleness thresholds (24h/72h/168h) and status codes (1000/100/0) are
    pinned as spec literals and the impl's own constants are asserted equal.

Each rule carries positive AND negative controls.
"""

from conftest import random_hex
from conformance import conformance_case


__category_title__ = "Discovery / Receiver Hardening"
__category_order__ = 22


# --- RNS 1.3.1 spec literals (Discovery.py) — the EXTERNAL ground truth. -----
NAME = 0xFF
TRANSPORT_ID = 0xFE
INTERFACE_TYPE = 0x00
TRANSPORT = 0x01
REACHABLE_ON = 0x02
LATITUDE = 0x03
LONGITUDE = 0x04
HEIGHT = 0x05

# The seven mandatory fields the receiver dereferences unconditionally
# (Discovery.py:247-274). Absence of any of them aborts the decode.
MANDATORY_FIELDS = {
    "INTERFACE_TYPE": INTERFACE_TYPE,
    "TRANSPORT": TRANSPORT,
    "TRANSPORT_ID": TRANSPORT_ID,
    "NAME": NAME,
    "LATITUDE": LATITUDE,
    "LONGITUDE": LONGITUDE,
    "HEIGHT": HEIGHT,
}

# Receiver-side interface-type whitelist (Discovery.py:37-38).
DISCOVERABLE_INTERFACE_TYPES = [
    "BackboneInterface", "TCPServerInterface", "TCPClientInterface",
    "RNodeInterface", "WeaveInterface", "I2PInterface", "KISSInterface",
]

# Staleness thresholds (Discovery.py:365-367) and status codes (372-374).
THRESHOLD_UNKNOWN = 24 * 60 * 60
THRESHOLD_STALE = 3 * 24 * 60 * 60
THRESHOLD_REMOVE = 7 * 24 * 60 * 60
STATUS_AVAILABLE = 1000
STATUS_UNKNOWN = 100
STATUS_STALE = 0

# Discovery destination spec name (APP_NAME + aspects, Discovery.py:30,57-58).
DISCOVERY_FULL_NAME = "rnstransport.discovery.interface"

_COST = 6                      # low PoW cost keeps the real LXStamper fast
_TCP_FIELDS = {"name": "Node", "reachable_on": "example.com", "port": 4242}


def _craft(sut, **mut):
    """Build a mutated-but-genuinely-stamped TCPServer announce."""
    return sut.execute(
        "discovery_craft_announce", interface_type="TCPServerInterface",
        stamp_value=_COST, transport_enabled=True, fields=dict(_TCP_FIELDS),
        **mut)


def _build(sut, fields):
    return sut.execute(
        "discovery_build_announce_appdata", interface_type="TCPServerInterface",
        stamp_value=_COST, transport_enabled=True, fields=fields)


def _recv(sut, app_data):
    return sut.execute(
        "discovery_receive_announce", app_data=app_data, required_value=_COST)


# =============================================================================
# Mandatory-field presence (Discovery.py:247-274)
# =============================================================================

@conformance_case(
    commands=["discovery_craft_announce", "discovery_receive_announce"],
    verifies="The receiver dereferences seven mandatory info-map fields unconditionally (INTERFACE_TYPE=0x00, TRANSPORT=0x01, TRANSPORT_ID=0xFE, NAME=0xFF, LATITUDE=0x03, LONGITUDE=0x04, HEIGHT=0x05); an announce missing ANY one is silently discarded (KeyError path, or the INTERFACE_TYPE-absent callback(None) path), while the same announce with the full field set is accepted (Discovery.py:247-274)",
)
def test_mandatory_fields_required(sut):
    # Positive control: an unmutated genuine announce is accepted.
    pristine = _craft(sut)
    assert pristine["aborted"] is False
    assert _recv(sut, pristine["app_data"])["accepted"] is True

    # NEGATIVE: dropping any single mandatory key aborts the decode.
    for label, key in MANDATORY_FIELDS.items():
        crafted = _craft(sut, drop_field=key)
        assert crafted["aborted"] is False, f"craft for missing {label} failed"
        res = _recv(sut, crafted["app_data"])
        assert res["accepted"] is False, f"missing {label} must be discarded"
        assert not res["info_present"], f"missing {label} must surface no info"
        if key == INTERFACE_TYPE:
            # INTERFACE_TYPE absent -> info stays None -> callback(None) fires.
            assert res["callback_info_none"] is True
        else:
            # Any other missing key raises before the callback is reached.
            assert res["callback_invoked"] is False


# =============================================================================
# Field type / length validation (Discovery.py:251-261)
# =============================================================================

@conformance_case(
    commands=["discovery_build_announce_appdata", "discovery_receive_announce"],
    verifies="The receiver rejects the whole announce when LATITUDE/LONGITUDE/HEIGHT (0x03-0x05) are present but not None-or-float (ValueError, Discovery.py:252-254); genuine float coordinates are accepted (positive control)",
)
def test_coordinate_type_validation(sut):
    good = _build(sut, {**_TCP_FIELDS, "latitude": 12.5,
                        "longitude": -7.25, "height": 100.0})
    assert _recv(sut, good["app_data"])["accepted"] is True

    for field in ("latitude", "longitude", "height"):
        bad = _build(sut, {**_TCP_FIELDS, field: "not-a-float"})
        assert _recv(sut, bad["app_data"])["accepted"] is False, \
            f"non-float {field} must be rejected"


@conformance_case(
    commands=["discovery_craft_announce", "discovery_receive_announce"],
    verifies="The receiver rejects a non-bool TRANSPORT (0x01), a TRANSPORT_ID (0xFE) whose length is not TRUNCATED_HASHLENGTH//8=16 bytes, and a REACHABLE_ON (0x02) that is neither a valid IP nor hostname (ValueError, Discovery.py:251,255,259-261); the unmutated announce is accepted (positive control)",
)
def test_field_type_and_length_validation(sut):
    assert _recv(sut, _craft(sut)["app_data"])["accepted"] is True

    # TRANSPORT must be a bool — a string is rejected.
    transport_str = _craft(sut, set_fields=[
        {"key": TRANSPORT, "kind": "str", "value": "yes"}])
    assert _recv(sut, transport_str["app_data"])["accepted"] is False

    # TRANSPORT_ID must be exactly 16 bytes.
    tid_short = _craft(sut, set_fields=[
        {"key": TRANSPORT_ID, "kind": "bytes", "value": "aabbccdd"}])
    assert _recv(sut, tid_short["app_data"])["accepted"] is False
    tid_long = _craft(sut, set_fields=[
        {"key": TRANSPORT_ID, "kind": "bytes", "value": "ab" * 20}])
    assert _recv(sut, tid_long["app_data"])["accepted"] is False

    # REACHABLE_ON must validate as IP or hostname.
    bad_host = _craft(sut, set_fields=[
        {"key": REACHABLE_ON, "kind": "str", "value": "not a valid host!!"}])
    assert _recv(sut, bad_host["app_data"])["accepted"] is False


# =============================================================================
# Receiver-side interface-type whitelist (Discovery.py:37-38,256-257)
# =============================================================================

@conformance_case(
    commands=["discovery_craft_announce", "discovery_receive_announce"],
    verifies="An announce whose INTERFACE_TYPE (0x00) is not in the spec-literal DISCOVERABLE_INTERFACE_TYPES whitelist is rejected at the receiver (ValueError, Discovery.py:256-257), while a whitelisted interface type with otherwise-identical fields is accepted — pinning the receiver-side type whitelist",
)
def test_receiver_type_whitelist(sut):
    # Positive control: the whitelisted base type is accepted.
    assert _recv(sut, _craft(sut)["app_data"])["accepted"] is True

    # NEGATIVE: a non-whitelisted type name is rejected.
    for evil in ("FakeInterface", "EvilInterface", "LocalInterface"):
        crafted = _craft(sut, set_interface_type=evil)
        res = _recv(sut, crafted["app_data"])
        assert res["accepted"] is False, f"{evil} must be rejected"
        assert evil not in DISCOVERABLE_INTERFACE_TYPES

    # Positive: re-stamping the base type under a DIFFERENT whitelisted name the
    # receiver requires no extra config for (BackboneInterface) is accepted —
    # the base announce already carries REACHABLE_ON/PORT.
    backbone = _craft(sut, set_interface_type="BackboneInterface")
    assert "BackboneInterface" in DISCOVERABLE_INTERFACE_TYPES
    assert _recv(sut, backbone["app_data"])["accepted"] is True


# =============================================================================
# Discovery destination identity selection (Discovery.py:54-58)
# =============================================================================

@conformance_case(
    commands=["discovery_announce_identity", "hash_from_name_and_identity"],
    verifies="The interface-discovery Destination is built under the network identity when has_network_identity() is True, else under the transport identity (Discovery.py:54-58). For both branches the resulting destination hash equals the independent naming oracle hash_from_name_and_identity('rnstransport.discovery.interface', chosen_identity_hash) and DIFFERS from the hash derived from the non-selected identity",
)
def test_announce_identity_selection(sut):
    net_priv = random_hex(64)
    tx_priv = random_hex(64)

    # Branch 1: has_network_identity() True -> built under network identity.
    net_sel = sut.execute(
        "discovery_announce_identity", has_network_identity=True,
        network_identity_priv=net_priv, identity_priv=tx_priv)
    assert net_sel["chosen_identity_hash"] == net_sel["network_identity_hash"]
    oracle_net = sut.execute(
        "hash_from_name_and_identity", full_name=DISCOVERY_FULL_NAME,
        identity_hash=net_sel["network_identity_hash"])["destination_hash"]
    assert net_sel["discovery_destination_hash"] == oracle_net
    # Independently derived under the transport identity it would be different.
    oracle_tx = sut.execute(
        "hash_from_name_and_identity", full_name=DISCOVERY_FULL_NAME,
        identity_hash=net_sel["identity_hash"])["destination_hash"]
    assert net_sel["discovery_destination_hash"] != oracle_tx

    # Branch 2: has_network_identity() False -> built under transport identity.
    tx_sel = sut.execute(
        "discovery_announce_identity", has_network_identity=False,
        network_identity_priv=net_priv, identity_priv=tx_priv)
    assert tx_sel["chosen_identity_hash"] == tx_sel["identity_hash"]
    assert tx_sel["discovery_destination_hash"] == oracle_tx
    # The two branches address DIFFERENT destinations.
    assert tx_sel["discovery_destination_hash"] != net_sel["discovery_destination_hash"]
    # Spec name literal anchors the app_name reported by the impl.
    assert net_sel["app_name"] == "rnstransport"


# =============================================================================
# Opt-in feature defaults (Interface.py:105-106; Reticulum.py:259,1802-1807)
# =============================================================================

@conformance_case(
    commands=["discovery_feature_defaults"],
    verifies="Interface discovery is opt-in: a fresh base Interface has discoverable=False and supports_discovery=False (Interface.py:105-106), and a freshly-initialised Reticulum has the master discover_interfaces gate False (Reticulum.py:259) and should_autoconnect_discovered_interfaces() False (Reticulum.py:260,1802) — every discovery feature defaults OFF",
)
def test_discovery_features_default_off(sut):
    d = sut.execute("discovery_feature_defaults")
    assert d["interface_discoverable"] is False
    assert d["interface_supports_discovery"] is False
    assert d["discover_interfaces"] is False
    assert d["should_autoconnect_discovered_interfaces"] is False
    assert not d["max_autoconnected_interfaces"]


# =============================================================================
# Discovered-record staleness thresholds (Discovery.py:365-447)
# =============================================================================

@conformance_case(
    commands=["discovery_inject_records"],
    verifies="list_discovered_interfaces assigns status by heard-delta against the spec-literal thresholds: available when <=24h, unknown when >24h, stale when >72h, and removes the record entirely when >168h (Discovery.py:416,428-430); status codes are STATUS_AVAILABLE=1000/UNKNOWN=100/STALE=0 (Discovery.py:372-374). The impl's own threshold constants are asserted equal to the spec literals",
)
def test_record_staleness_thresholds(sut):
    H = 60 * 60
    res = sut.execute("discovery_inject_records", records=[
        {"name": "Fresh", "age_seconds": 1 * H},
        {"name": "Unknown", "age_seconds": 30 * H},     # >24h
        {"name": "Stale", "age_seconds": 80 * H},       # >72h
        {"name": "Removed", "age_seconds": 200 * H},    # >168h -> gone
    ])

    # Impl constants must equal the spec-literal thresholds / codes.
    assert res["threshold_unknown"] == THRESHOLD_UNKNOWN
    assert res["threshold_stale"] == THRESHOLD_STALE
    assert res["threshold_remove"] == THRESHOLD_REMOVE
    assert res["status_available"] == STATUS_AVAILABLE
    assert res["status_unknown"] == STATUS_UNKNOWN
    assert res["status_stale"] == STATUS_STALE

    by_name = {r["name"]: r for r in res["listed"]}
    assert "Removed" not in by_name, "record >168h old must be removed"
    assert by_name["Fresh"]["status"] == "available"
    assert by_name["Fresh"]["status_code"] == STATUS_AVAILABLE
    assert by_name["Unknown"]["status"] == "unknown"
    assert by_name["Unknown"]["status_code"] == STATUS_UNKNOWN
    assert by_name["Stale"]["status"] == "stale"
    assert by_name["Stale"]["status_code"] == STATUS_STALE


@conformance_case(
    commands=["discovery_inject_records"],
    verifies="list_discovered_interfaces sorts discovered interfaces by (status_code, value, last_heard) descending (Discovery.py:447): a more-available interface outranks a staler one regardless of stamp value, and within the same status a higher stamp value outranks a lower one",
)
def test_record_sort_order(sut):
    H = 60 * 60
    res = sut.execute("discovery_inject_records", records=[
        {"name": "AvailLow", "age_seconds": 1 * H, "value": 5},
        {"name": "AvailHigh", "age_seconds": 1 * H, "value": 50},
        {"name": "StaleHigh", "age_seconds": 80 * H, "value": 99},
    ])
    order = [r["name"] for r in res["listed"]]

    # status_code dominates: both available records precede the stale one.
    assert order.index("AvailHigh") < order.index("StaleHigh")
    assert order.index("AvailLow") < order.index("StaleHigh")
    # within the same (available) status, higher stamp value sorts first.
    assert order.index("AvailHigh") < order.index("AvailLow")
