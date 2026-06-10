"""Reticulum interface config-parsing conformance.

Every Reticulum node configures its interfaces from a text config file, which
RNS parses with its vendored ConfigObj and then turns into live interface
attributes in ``Reticulum._synthesize_interface`` (Reticulum.py:685-1034). A
handful of config-derived RULES are security/interop relevant and are pinned
here against EXTERNAL RNS 1.3.1 spec literals (not the impl's own output):

  * discoverable = true forces a discovery-capable interface_mode. An interface
    that is discoverable but configured without gateway/access_point mode is
    auto-promoted to GATEWAY (non-RNode types) so it actually relays
    (Reticulum.py:841-848). An explicitly-set gateway/AP mode is preserved.
  * the discovery announce interval has a hard 5-minute floor and a 6-hour
    default (Reticulum.py:824-828).
  * bitrate below Reticulum.MINIMUM_BITRATE is rejected (left unconfigured),
    a valid bitrate is stored (Reticulum.py:765-768).
  * announce_cap is accepted only in (0, 100] and stored as a fraction;
    out-of-range values fall back to the 2% default (Reticulum.py:791-794).
  * ifac_size below IFAC_MIN_SIZE*8 bits is rejected (falls back to the
    interface's DEFAULT_IFAC_SIZE); a valid value is stored as bytes
    (Reticulum.py:719-722).

The bridge command ``config_parse_interface`` feeds a raw config string straight
through RNS's real parser + ``_synthesize_interface`` onto a no-op probe
interface, then reads the stored attrs back. Each assertion below anchors on the
spec constant, never on the implementation echoing itself.
"""

from conformance import conformance_case


__category_title__ = "Config Parsing Hooks"
__category_order__ = 31


# --- EXTERNAL ground-truth spec literals (RNS 1.3.1 — NOT read from the impl) ---
MODE_FULL = 0x01          # Interface.MODE_FULL
MODE_ACCESS_POINT = 0x03  # Interface.MODE_ACCESS_POINT
MODE_GATEWAY = 0x06       # Interface.MODE_GATEWAY

MINIMUM_BITRATE = 5       # Reticulum.MINIMUM_BITRATE
ANNOUNCE_CAP_DEFAULT = 2 / 100.0   # Reticulum.ANNOUNCE_CAP/100
IFAC_MIN_SIZE_BITS = 1 * 8         # Reticulum.IFAC_MIN_SIZE*8

DISCOVERY_INTERVAL_FLOOR = 5 * 60      # 5-minute floor (seconds)
DISCOVERY_INTERVAL_DEFAULT = 6 * 60 * 60  # 6-hour default (seconds)

_PROBE_TYPE = "ConfigParseProbeInterface"


def _config(body: str, name: str = "probe") -> str:
    """Build a one-interface config text using the no-op probe interface type."""
    lines = [
        "[interfaces]",
        f"  [[{name}]]",
        f"    type = {_PROBE_TYPE}",
        "    interface_enabled = true",
    ]
    for line in body.strip("\n").splitlines():
        lines.append("    " + line.strip())
    return "\n".join(lines) + "\n"


def _parse(impl, body: str) -> dict:
    res = impl.execute(
        "config_parse_interface",
        interface_name="probe",
        config_text=_config(body),
    )
    assert "error" not in res, f"config_parse_interface errored: {res}"
    return res


@conformance_case(
    commands=["config_parse_interface"],
    verifies="discoverable=true forces a discovery-capable interface_mode: a discoverable interface configured WITHOUT gateway/access_point mode is auto-promoted to GATEWAY (0x06) for non-RNode types (Reticulum.py:841-848), while a non-discoverable interface keeps the FULL (0x01) default — an interface that stayed FULL while discoverable would advertise itself for discovery yet not relay",
)
def test_discoverable_forces_gateway_mode(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        forced = _parse(impl, "discoverable = true")
        assert forced["mode"] == MODE_GATEWAY, (
            f"{label}: discoverable=true without an explicit mode must force "
            f"GATEWAY ({MODE_GATEWAY:#x}); got {forced['mode']:#x}"
        )
        assert forced["discoverable"] is True, (
            f"{label}: discoverable flag not stored: {forced}"
        )
        # The forcing is conditional on discoverable — the default interface
        # mode is FULL and must be left untouched when not discoverable.
        plain = _parse(impl, "discoverable = false")
        assert plain["mode"] == MODE_FULL, (
            f"{label}: non-discoverable interface must keep FULL "
            f"({MODE_FULL:#x}); got {plain['mode']:#x}"
        )
        assert plain["discoverable"] is False


@conformance_case(
    commands=["config_parse_interface"],
    verifies="The discoverable mode-forcing does NOT override an explicitly configured discovery-capable mode: discoverable=true with mode=access_point stays ACCESS_POINT (0x03) and with mode=gateway stays GATEWAY (0x06) — the auto-promotion only fires for interfaces that are discoverable but lack a relay-capable mode (Reticulum.py:841)",
)
def test_explicit_discovery_mode_preserved(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        ap = _parse(impl, "discoverable = true\nmode = access_point")
        assert ap["mode"] == MODE_ACCESS_POINT, (
            f"{label}: explicit access_point mode must be preserved under "
            f"discoverable=true; got {ap['mode']:#x}"
        )
        gw = _parse(impl, "discoverable = true\nmode = gateway")
        assert gw["mode"] == MODE_GATEWAY, (
            f"{label}: explicit gateway mode must be preserved under "
            f"discoverable=true; got {gw['mode']:#x}"
        )


@conformance_case(
    commands=["config_parse_interface"],
    verifies="Discovery announce interval bounds (Reticulum.py:824-828): a configured announce_interval (minutes) below the 5-minute floor is clamped UP to 300s; a value above the floor is kept (announce_interval=10 -> 600s); and an omitted interval defaults to the 6-hour (21600s) period — a sub-floor interval would let a discoverable node flood the network with announces",
)
def test_discovery_announce_interval_floor_and_default(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        floored = _parse(impl, "discoverable = true\nannounce_interval = 1")
        assert floored["discovery_announce_interval"] == DISCOVERY_INTERVAL_FLOOR, (
            f"{label}: announce_interval=1min must clamp UP to the 5-minute "
            f"floor ({DISCOVERY_INTERVAL_FLOOR}s); got "
            f"{floored['discovery_announce_interval']}"
        )
        above = _parse(impl, "discoverable = true\nannounce_interval = 10")
        assert above["discovery_announce_interval"] == 10 * 60, (
            f"{label}: announce_interval=10min must be 600s; got "
            f"{above['discovery_announce_interval']}"
        )
        default = _parse(impl, "discoverable = true")
        assert default["discovery_announce_interval"] == DISCOVERY_INTERVAL_DEFAULT, (
            f"{label}: omitted announce_interval must default to the 6-hour "
            f"period ({DISCOVERY_INTERVAL_DEFAULT}s); got "
            f"{default['discovery_announce_interval']}"
        )


@conformance_case(
    commands=["config_parse_interface"],
    verifies="bitrate bound (Reticulum.py:765-768): a configured bitrate below Reticulum.MINIMUM_BITRATE (5 bps) is rejected (configured_bitrate stays None — RNS keeps the interface default), while a bitrate >= MINIMUM_BITRATE is stored verbatim — silently honoring a sub-minimum bitrate would mis-size MTU/timeout math across the link",
)
def test_bitrate_minimum_bound(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        below = _parse(impl, f"bitrate = {MINIMUM_BITRATE - 1}")
        assert below["configured_bitrate"] is None, (
            f"{label}: bitrate {MINIMUM_BITRATE - 1} < MINIMUM_BITRATE must be "
            f"rejected (configured_bitrate None); got {below['configured_bitrate']}"
        )
        ok = _parse(impl, "bitrate = 1200")
        assert ok["configured_bitrate"] == 1200, (
            f"{label}: bitrate 1200 must be stored; got {ok['configured_bitrate']}"
        )
        assert ok["bitrate"] == 1200, (
            f"{label}: a valid configured bitrate must be applied to the "
            f"interface; got interface.bitrate={ok['bitrate']}"
        )
        # Exactly at the minimum is accepted (inclusive bound).
        at_min = _parse(impl, f"bitrate = {MINIMUM_BITRATE}")
        assert at_min["configured_bitrate"] == MINIMUM_BITRATE, (
            f"{label}: bitrate == MINIMUM_BITRATE ({MINIMUM_BITRATE}) is inclusive "
            f"and must be accepted; got {at_min['configured_bitrate']}"
        )


@conformance_case(
    commands=["config_parse_interface"],
    verifies="announce_cap bound (Reticulum.py:791-794): announce_cap is accepted only in (0, 100] and stored as a FRACTION (announce_cap=50 -> 0.5); values <=0 or >100 fall back to the 2% (0.02) default — an out-of-range cap silently disabling/uncapping announce bandwidth limiting would let a node monopolize a slow link",
)
def test_announce_cap_bound(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        valid = _parse(impl, "announce_cap = 50")
        assert abs(valid["announce_cap"] - 0.5) < 1e-9, (
            f"{label}: announce_cap=50 must store as the fraction 0.5; got "
            f"{valid['announce_cap']}"
        )
        for bad in ("0", "150"):
            res = _parse(impl, f"announce_cap = {bad}")
            assert abs(res["announce_cap"] - ANNOUNCE_CAP_DEFAULT) < 1e-9, (
                f"{label}: announce_cap={bad} is out of (0,100] and must fall "
                f"back to the {ANNOUNCE_CAP_DEFAULT} default; got "
                f"{res['announce_cap']}"
            )


@conformance_case(
    commands=["config_parse_interface"],
    verifies="ifac_size bound (Reticulum.py:719-722): a configured ifac_size (bits) >= IFAC_MIN_SIZE*8 is stored as BYTES (ifac_size=64 -> 8 bytes); a value below the floor is rejected and falls back to the interface's DEFAULT_IFAC_SIZE — accepting an under-minimum IFAC field would shrink the authentication tag below the protocol minimum",
)
def test_ifac_size_minimum_bound(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        valid = _parse(impl, "ifac_size = 64")
        assert valid["ifac_size"] == 64 // 8, (
            f"{label}: ifac_size=64 bits must store as {64 // 8} bytes; got "
            f"{valid['ifac_size']}"
        )
        # 64 bits -> 8 bytes must be distinguishable from the default fallback
        # (16) for this assertion to discriminate.
        assert valid["ifac_size"] != valid["default_ifac_size"], (
            f"{label}: test setup — chosen ifac_size collides with the default"
        )
        below = _parse(impl, f"ifac_size = {IFAC_MIN_SIZE_BITS - 1}")
        assert below["ifac_size"] == below["default_ifac_size"], (
            f"{label}: ifac_size {IFAC_MIN_SIZE_BITS - 1} bits < IFAC_MIN_SIZE*8 "
            f"must be rejected and fall back to DEFAULT_IFAC_SIZE "
            f"({below['default_ifac_size']}); got {below['ifac_size']}"
        )
