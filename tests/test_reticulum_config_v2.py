"""Reticulum config-parsing conformance — V2 gap closure (reticulum_config).

These extend the config-parse coverage in test_config_parse_hooks.py with three
rules the prior passes left open, all anchored on EXTERNAL RNS 1.3.1 spec
literals (never the impl echoing its own config back):

  * ifac-size-defaults-and-config — the serial/framed-media interface classes
    (Serial/KISS/AX25KISS/RNode/Pipe) default to an 8-byte IFAC tag, while the
    packet/IP classes (TCP/UDP) default to 16 (SerialInterface.py:53 etc.,
    TCPInterface.py:77). The prior pass only ever asserted the 16-byte TCP
    class; an impl that used 16-byte IFAC on serial-class media passes the whole
    suite yet partitions itself from conformant peers on those networks.
  * config-mode-key-aliases-and-precedence — the `interface_mode` key, its alias
    spellings, and its precedence over the legacy `mode` key
    (Reticulum.py:689-717). Includes the documented upstream quirk that
    interface_mode=gateway WITHOUT a mode key KeyErrors (Reticulum.py:701
    consults c["mode"], not c["interface_mode"]).
  * config-ifac-credential-aliases-and-empty-string — networkname/network_name
    and passphrase/pass_phrase aliases both feed the IFAC, and an explicit
    empty-string value means UNSET (no IFAC derived), Reticulum.py:724-738.
    An impl that derived an IFAC from networkname="" would silently partition
    itself from open-interface peers.

The bridge commands delegate to real RNS: `config_parse_interface` pushes raw
config text through RNS's own ConfigObj + `_synthesize_interface`, and
`interface_default_ifac_size` reads the DEFAULT_IFAC_SIZE class constants off the
interface classes themselves.
"""

import pytest

from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Config Parsing Hooks"
__category_order__ = 31


# --- EXTERNAL ground-truth spec literals (RNS 1.3.1 — NOT read from the impl) ---
MODE_FULL = 0x01            # Interface.MODE_FULL
MODE_POINT_TO_POINT = 0x02  # Interface.MODE_POINT_TO_POINT
MODE_ACCESS_POINT = 0x03    # Interface.MODE_ACCESS_POINT
MODE_ROAMING = 0x04         # Interface.MODE_ROAMING
MODE_BOUNDARY = 0x05        # Interface.MODE_BOUNDARY
MODE_GATEWAY = 0x06         # Interface.MODE_GATEWAY

# DEFAULT_IFAC_SIZE per interface class (bytes). Serial/framed media use an
# 8-byte IFAC tag; packet/IP media use 16 (the protocol minimum is 1 byte).
SERIAL_CLASS_IFAC = 8
PACKET_CLASS_IFAC = 16
SERIAL_CLASS_INTERFACES = (
    "SerialInterface", "KISSInterface", "AX25KISSInterface",
    "RNodeInterface", "PipeInterface",
)
PACKET_CLASS_INTERFACES = (
    "TCPServerInterface", "TCPClientInterface", "UDPInterface",
)

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
    commands=["interface_default_ifac_size"],
    verifies=(
        "DEFAULT_IFAC_SIZE is a per-interface-class constant: the serial/framed "
        "media classes Serial/KISS/AX25KISS/RNode/Pipe default to an 8-byte IFAC "
        "authentication tag (SerialInterface.py:53, KISSInterface.py:63, "
        "AX25KISSInterface.py:70, RNodeInterface.py:110, PipeInterface.py:57), "
        "while the packet/IP classes TCP/UDP default to 16 "
        "(TCPInterface.py:77, UDPInterface.py:42). Both classes of value are >= "
        "IFAC_MIN_SIZE (1 byte). Pinning the 8-byte serial default catches an "
        "impl that uniformly uses 16-byte IFAC and would silently partition "
        "itself from conformant peers on serial-class networks (negative: the "
        "two defaults are distinct, so neither is a copy of the other)"
    ),
)
def test_default_ifac_size_per_interface_class(sut, reference, sut_impl_name):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        if label == "sut" and sut_impl_name == "kotlin":
            pytest.xfail(
                "reticulum-kt#kotlin-no-serial-kiss-interfaces: no "
                "SerialInterface/KISSInterface/AX25KISSInterface classes exist "
                "in reticulum-kt (default_ifac_size has no entries for them)."
            )
        res = impl.execute("interface_default_ifac_size")
        sizes = res["default_ifac_size"]
        # POSITIVE: serial/framed-media classes default to the 8-byte tag.
        for name in SERIAL_CLASS_INTERFACES:
            assert sizes[name] == SERIAL_CLASS_IFAC, (
                f"{label}: {name}.DEFAULT_IFAC_SIZE must be {SERIAL_CLASS_IFAC} "
                f"(serial/framed media), got {sizes[name]}"
            )
        # POSITIVE: packet/IP classes default to the 16-byte tag.
        for name in PACKET_CLASS_INTERFACES:
            assert sizes[name] == PACKET_CLASS_IFAC, (
                f"{label}: {name}.DEFAULT_IFAC_SIZE must be {PACKET_CLASS_IFAC} "
                f"(packet/IP media), got {sizes[name]}"
            )
        # NEGATIVE: the serial and packet defaults are genuinely different —
        # an impl that collapsed them to a single value fails here.
        assert SERIAL_CLASS_IFAC != PACKET_CLASS_IFAC
        assert sizes["SerialInterface"] != sizes["TCPServerInterface"], (
            f"{label}: serial-class IFAC size must differ from the TCP default; "
            f"both reported {sizes['SerialInterface']}"
        )
        # Both classes' defaults sit at or above the protocol minimum.
        assert res["ifac_min_size"] == 1, (
            f"{label}: IFAC_MIN_SIZE must be 1 byte, got {res['ifac_min_size']}"
        )
        assert SERIAL_CLASS_IFAC >= res["ifac_min_size"]


@conformance_case(
    commands=["config_parse_interface"],
    verifies=(
        "The `interface_mode` config key (Reticulum.py:689-702) selects the "
        "interface mode with these spellings: full->FULL(0x01), "
        "access_point/accesspoint/ap->ACCESS_POINT(0x03), pointtopoint/ptp->"
        "POINT_TO_POINT(0x02), roaming->ROAMING(0x04), boundary->BOUNDARY(0x05). "
        "interface_mode takes PRECEDENCE over the legacy `mode` key: with "
        "interface_mode=access_point AND mode=full the result is ACCESS_POINT, "
        "not FULL (the `elif \"mode\" in c` branch is only consulted when "
        "interface_mode is absent). Negative: a bare `mode=full` (no "
        "interface_mode) yields FULL, confirming precedence is real and not a "
        "coincidence"
    ),
)
def test_interface_mode_aliases_and_precedence(sut, reference, sut_impl_name):
    cases = [
        ("interface_mode = full", MODE_FULL),
        ("interface_mode = access_point", MODE_ACCESS_POINT),
        ("interface_mode = accesspoint", MODE_ACCESS_POINT),
        ("interface_mode = ap", MODE_ACCESS_POINT),
        ("interface_mode = pointtopoint", MODE_POINT_TO_POINT),
        ("interface_mode = ptp", MODE_POINT_TO_POINT),
        ("interface_mode = roaming", MODE_ROAMING),
        ("interface_mode = boundary", MODE_BOUNDARY),
    ]
    for impl, label in ((reference, "ref"), (sut, "sut")):
        if label == "sut" and sut_impl_name == "kotlin":
            pytest.xfail(
                "reticulum-kt#config-ini-parser: kotlin has no ConfigObj INI "
                "parser / Reticulum._synthesize_interface; the bridge "
                "config_parse_interface command is deliberately unimplemented. "
                "No stub warranted (a fake parser would test nothing)."
            )
        for body, expected in cases:
            res = _parse(impl, body)
            assert res["mode"] == expected, (
                f"{label}: {body!r} must select mode {expected:#x}, got "
                f"{res['mode']:#x}"
            )
        # PRECEDENCE: interface_mode wins over a conflicting mode key.
        pre = _parse(impl, "interface_mode = access_point\nmode = full")
        assert pre["mode"] == MODE_ACCESS_POINT, (
            f"{label}: interface_mode=access_point must take precedence over "
            f"mode=full (ACCESS_POINT {MODE_ACCESS_POINT:#x}), got {pre['mode']:#x}"
        )
        # NEGATIVE control: with no interface_mode, the legacy mode key applies,
        # so the precedence above is a genuine override (FULL when mode=full).
        legacy = _parse(impl, "mode = full")
        assert legacy["mode"] == MODE_FULL, (
            f"{label}: bare mode=full must yield FULL ({MODE_FULL:#x}), got "
            f"{legacy['mode']:#x}"
        )


@conformance_case(
    commands=["config_parse_interface"],
    verifies=(
        "Upstream quirk (intentionally pinned): the gateway arm of the "
        "interface_mode branch consults c[\"mode\"] rather than "
        "c[\"interface_mode\"] (Reticulum.py:701), so interface_mode=gateway "
        "WITHOUT a mode key raises KeyError at parse time. A faithful reimpl "
        "must reproduce (raise) or explicitly document this. With BOTH "
        "interface_mode=gateway and mode=gateway present, parsing succeeds and "
        "yields GATEWAY(0x06) — the positive control showing the key is "
        "otherwise honoured"
    ),
)
def test_interface_mode_gateway_keyerror_quirk(sut, reference, sut_impl_name):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        if label == "sut" and sut_impl_name == "kotlin":
            pytest.xfail(
                "reticulum-kt#config-ini-parser: kotlin has no ConfigObj INI "
                "parser / Reticulum._synthesize_interface; the bridge "
                "config_parse_interface command is deliberately unimplemented. "
                "No stub warranted (a fake parser would test nothing)."
            )
        # NEGATIVE: interface_mode=gateway alone trips the c["mode"] lookup.
        with pytest.raises(BridgeError):
            impl.execute(
                "config_parse_interface",
                interface_name="probe",
                config_text=_config("interface_mode = gateway"),
            )
        # POSITIVE control: supplying mode=gateway too makes the lookup succeed.
        ok = _parse(impl, "interface_mode = gateway\nmode = gateway")
        assert ok["mode"] == MODE_GATEWAY, (
            f"{label}: interface_mode=gateway with mode=gateway must yield "
            f"GATEWAY ({MODE_GATEWAY:#x}), got {ok['mode']:#x}"
        )


@conformance_case(
    commands=["config_parse_interface"],
    verifies=(
        "IFAC credential resolution (Reticulum.py:724-738, :895-916): the "
        "network-name aliases `networkname` and `network_name` both populate "
        "ifac_netname, and the passphrase aliases `passphrase` and `pass_phrase` "
        "both populate ifac_netkey; whenever either is non-None RNS derives a "
        "real IFAC identity (ifac_active True). The later alias wins when both "
        "are present (network_name is checked after networkname). An explicit "
        "EMPTY-STRING value means UNSET: networkname=\"\" leaves ifac_netname "
        "None and derives NO IFAC (ifac_active False) — an impl that derived an "
        "IFAC from the empty string would partition itself from open-interface "
        "peers. Negative control: a non-empty value DOES derive an IFAC"
    ),
)
def test_ifac_credential_aliases_and_empty_string(sut, reference, sut_impl_name):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        if label == "sut" and sut_impl_name == "kotlin":
            pytest.xfail(
                "reticulum-kt#config-ini-parser: kotlin has no ConfigObj INI "
                "parser / Reticulum._synthesize_interface; the bridge "
                "config_parse_interface command is deliberately unimplemented. "
                "No stub warranted (a fake parser would test nothing)."
            )
        # network-name aliases both feed ifac_netname and arm an IFAC.
        a = _parse(impl, "networkname = alpha")
        assert a["ifac_netname"] == "alpha" and a["ifac_active"] is True, (
            f"{label}: networkname=alpha must set ifac_netname and arm an IFAC: {a}"
        )
        b = _parse(impl, "network_name = beta")
        assert b["ifac_netname"] == "beta" and b["ifac_active"] is True, (
            f"{label}: network_name=beta (alias) must set ifac_netname: {b}"
        )
        # passphrase aliases both feed ifac_netkey and arm an IFAC.
        p = _parse(impl, "passphrase = secretp")
        assert p["ifac_netkey"] == "secretp" and p["ifac_active"] is True, (
            f"{label}: passphrase=secretp must set ifac_netkey and arm an IFAC: {p}"
        )
        q = _parse(impl, "pass_phrase = secretq")
        assert q["ifac_netkey"] == "secretq" and q["ifac_active"] is True, (
            f"{label}: pass_phrase=secretq (alias) must set ifac_netkey: {q}"
        )
        # Alias precedence: network_name is evaluated after networkname, so it
        # wins; likewise pass_phrase wins over passphrase.
        pr = _parse(impl, "networkname = nn\nnetwork_name = wins")
        assert pr["ifac_netname"] == "wins", (
            f"{label}: network_name must override networkname when both set: {pr}"
        )
        # EMPTY-STRING means unset -> NO IFAC derived (the partition trap).
        e1 = _parse(impl, "networkname =")
        assert e1["ifac_netname"] is None and e1["ifac_active"] is False, (
            f"{label}: networkname=\"\" must be treated as UNSET (no IFAC): {e1}"
        )
        e2 = _parse(impl, "passphrase =")
        assert e2["ifac_netkey"] is None and e2["ifac_active"] is False, (
            f"{label}: passphrase=\"\" must be treated as UNSET (no IFAC): {e2}"
        )
        # Empty network_name with a non-empty passphrase still arms an IFAC via
        # the passphrase alone (netname None, netkey set).
        e3 = _parse(impl, "networkname =\npassphrase = onlykey")
        assert e3["ifac_netname"] is None and e3["ifac_netkey"] == "onlykey", (
            f"{label}: empty networkname + passphrase must keep netname None: {e3}"
        )
        assert e3["ifac_active"] is True, (
            f"{label}: a non-empty passphrase alone must still arm an IFAC: {e3}"
        )
