"""Interface-layer V2 conformance: config-derived interface_mode mapping (all
six modes + short aliases), the AUTOCONFIGURE_MTU bitrate->HW_MTU tier table,
per-interface ingress-control (ic_*) config overrides, and the KISS read-loop
HW_MTU in-frame byte cap.

Every assertion anchors on an EXTERNAL RNS 1.3.1 spec literal — the
``Interface.MODE_*`` constants, the ``Interface.optimise_mtu`` bitrate tiers,
the ``Interface`` ingress-control class constants, and the KISS read-loop
``len(data_buffer) < self.HW_MTU`` append gate — never on the implementation
echoing its own output. Each rule is exercised positive AND negative.

The bridge commands drive REAL RNS:

  * ``config_parse_interface`` -> RNS's vendored ConfigObj + the live
    ``Reticulum._synthesize_interface`` (Reticulum.py:685-1034), reading the
    parsed ``interface.mode`` / ``interface.ic_*`` straight off the genuine
    interface object.
  * ``interface_optimise_mtu`` -> the unbound ``Interface.optimise_mtu``
    (Interface.py:198-221) over a stand-in carrying only the attributes that
    method reads/writes.
  * ``kiss_deframe_stream`` / ``hdlc_deframe_stream`` -> the real
    ``TCPClientInterface.read_loop`` (TCPInterface.py:337-398), whose KISS path
    appends an in-frame byte only while ``len(data_buffer) < self.HW_MTU``.
"""

from conformance import conformance_case


__category_title__ = "Interface V2"
__category_order__ = 13


# ---------------------------------------------------------------------------
# External ground-truth spec literals (RNS 1.3.1 — NOT read from the impl).
# Interface.MODE_* (Interfaces/Interface.py:45-50).
# ---------------------------------------------------------------------------
MODE_FULL = 0x01
MODE_POINT_TO_POINT = 0x02
MODE_ACCESS_POINT = 0x03
MODE_ROAMING = 0x04
MODE_BOUNDARY = 0x05
MODE_GATEWAY = 0x06

# Interface ingress-control class constants (Interfaces/Interface.py:70-82) —
# the default-fallback values when no per-interface ic_* knob is configured.
MAX_HELD_ANNOUNCES = 256
IC_BURST_FREQ = 10
IC_BURST_FREQ_NEW = 3
IC_BURST_HOLD = 15
IC_BURST_PENALTY = 15
IC_HELD_RELEASE_INTERVAL = 5
IC_NEW_TIME = 2 * 60 * 60  # 7200

_PROBE_TYPE = "ConfigParseProbeInterface"

# KISS framing constants (Interfaces/KISSInterface.py::KISS) — duplicated so the
# harness never imports RNS; identical to tests/test_framing.py.
KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD
KISS_CMD_DATA = 0x00

HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_ESC_MASK = 0x20


def _config(body: str, name: str = "probe") -> str:
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
        "config_parse_interface", interface_name="probe", config_text=_config(body)
    )
    assert "error" not in res, f"config_parse_interface errored: {res}"
    return res


def _kiss_escape(data: bytes) -> bytes:
    data = data.replace(bytes([KISS_FESC]), bytes([KISS_FESC, KISS_TFESC]))
    data = data.replace(bytes([KISS_FEND]), bytes([KISS_FESC, KISS_TFEND]))
    return data


def _kiss_frame(data: bytes) -> bytes:
    return bytes([KISS_FEND, KISS_CMD_DATA]) + _kiss_escape(data) + bytes([KISS_FEND])


def _hdlc_escape(data: bytes) -> bytes:
    data = data.replace(bytes([HDLC_ESC]), bytes([HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK]))
    data = data.replace(bytes([HDLC_FLAG]), bytes([HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK]))
    return data


def _hdlc_frame(data: bytes) -> bytes:
    return bytes([HDLC_FLAG]) + _hdlc_escape(data) + bytes([HDLC_FLAG])


# ===========================================================================
# interface_mode config mapping — all six modes + short aliases
# ===========================================================================
@conformance_case(
    commands=["config_parse_interface"],
    verifies="RNS config `mode` maps to the Interface.MODE_* constants for the three modes the existing suite never pins numerically: pointtopoint/ptp -> MODE_POINT_TO_POINT (0x02), roaming -> MODE_ROAMING (0x04), boundary -> MODE_BOUNDARY (0x05). Read off interface.mode (and the section's selected_interface_mode) after RNS's real _synthesize_interface, anchored on the spec literals — an impl using the wrong byte for any mode would mis-route relative to a conformant peer",
)
def test_mode_constants_ptp_roaming_boundary(sut, reference):
    cases = {
        "pointtopoint": MODE_POINT_TO_POINT,
        "ptp": MODE_POINT_TO_POINT,
        "roaming": MODE_ROAMING,
        "boundary": MODE_BOUNDARY,
    }
    # The spec bytes are all distinct, so a confusion between modes is observable.
    assert len({MODE_POINT_TO_POINT, MODE_ROAMING, MODE_BOUNDARY, MODE_FULL}) == 4
    for impl, label in ((reference, "ref"), (sut, "sut")):
        for token, expected in cases.items():
            res = _parse(impl, f"mode = {token}")
            assert res["mode"] == expected, (
                f"{label}: mode={token} must map to {expected:#04x}; got "
                f"{res['mode']:#04x}"
            )
            assert res["selected_interface_mode"] == expected, (
                f"{label}: selected_interface_mode for mode={token} != "
                f"{expected:#04x}; got {res['selected_interface_mode']}"
            )


@conformance_case(
    commands=["config_parse_interface"],
    verifies="RNS config accepts the short mode aliases ap/accesspoint == access_point -> MODE_ACCESS_POINT (0x03) and gw == gateway -> MODE_GATEWAY (0x06): every alias for a given mode resolves to the SAME spec byte (Reticulum.py:708-717). An impl that recognised only the long form would silently fall back to FULL on a peer configured with the short alias",
)
def test_mode_short_aliases_access_point_gateway(sut, reference):
    alias_groups = {
        MODE_ACCESS_POINT: ["access_point", "accesspoint", "ap"],
        MODE_GATEWAY: ["gateway", "gw"],
    }
    for impl, label in ((reference, "ref"), (sut, "sut")):
        for expected, aliases in alias_groups.items():
            for token in aliases:
                res = _parse(impl, f"mode = {token}")
                assert res["mode"] == expected, (
                    f"{label}: alias mode={token} must resolve to {expected:#04x}; "
                    f"got {res['mode']:#04x}"
                )


@conformance_case(
    commands=["config_parse_interface"],
    verifies="An unrecognised mode token silently falls back to MODE_FULL (0x01): RNS's parser recognises pointtopoint/ptp for MODE_POINT_TO_POINT but NOT the underscored 'point_to_point' (Reticulum.py:710), so that token (and an arbitrary garbage token) yields FULL — pinning both the default and that ptp is the ONLY hyphen-free spelling. A negative control for the alias mapping above",
)
def test_unrecognised_mode_falls_back_to_full(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        # ptp IS recognised (positive control) ...
        good = _parse(impl, "mode = ptp")
        assert good["mode"] == MODE_POINT_TO_POINT, (
            f"{label}: control — ptp must map to POINT_TO_POINT"
        )
        # ... but the underscored spelling and pure garbage are NOT, and fall
        # back to FULL rather than erroring or silently picking ptp.
        for bad in ("point_to_point", "nonsense_mode_xyz"):
            res = _parse(impl, f"mode = {bad}")
            assert res["mode"] == MODE_FULL, (
                f"{label}: unrecognised mode={bad!r} must fall back to FULL "
                f"({MODE_FULL:#04x}); got {res['mode']:#04x}"
            )


# ===========================================================================
# AUTOCONFIGURE_MTU bitrate -> HW_MTU tier table (Interface.optimise_mtu)
# ===========================================================================
@conformance_case(
    commands=["interface_optimise_mtu"],
    verifies="Interface.optimise_mtu maps bitrate to HW_MTU by the RNS 1.3.1 tier table (Interface.py:198-221): a representative in-tier bitrate yields the spec HW_MTU for every tier — >=1Gbps:524288, >750M:262144, >400M:131072, >200M:65536, >100M:32768, >10M:16384, >5M:8192, >2M:4096, >1M:2048, >62500:1024, else:None. Driven through the real optimise_mtu, anchored on the documented per-tier literals",
)
def test_optimise_mtu_tier_table(sut, reference):
    # (representative in-tier bitrate, expected HW_MTU). Values are chosen well
    # inside each tier so only the tier's own literal can match.
    table = [
        (2_000_000_000, 524288),
        (1_000_000_000, 524288),  # exactly the >=1Gbps inclusive boundary
        (800_000_000, 262144),
        (500_000_000, 131072),
        (250_000_000, 65536),
        (150_000_000, 32768),
        (50_000_000, 16384),
        (8_000_000, 8192),
        (3_000_000, 4096),
        (1_500_000, 2048),
        (100_000, 1024),
        (10_000, None),
    ]
    for impl, label in ((reference, "ref"), (sut, "sut")):
        for bitrate, expected in table:
            res = impl.execute("interface_optimise_mtu", bitrate=bitrate)
            assert res["unchanged"] is False, (
                f"{label}: autoconfigure tier mapping must set HW_MTU for "
                f"bitrate={bitrate}; got unchanged"
            )
            assert res["hw_mtu"] == expected, (
                f"{label}: bitrate={bitrate} must map to HW_MTU {expected}; got "
                f"{res['hw_mtu']}"
            )


@conformance_case(
    commands=["interface_optimise_mtu"],
    verifies="The optimise_mtu tier comparisons are STRICT > except the top tier (>=): exactly 750_000_000 lands in the 131072 tier (NOT 262144), exactly 5_000_000 lands in 4096 (NOT 8192), and exactly 62_500 falls below the lowest tier to None (NOT 1024); while exactly 1_000_000_000 is included in the top 524288 tier (>=). Each boundary discriminates the strict-vs-inclusive comparison and is anchored on the spec literal",
)
def test_optimise_mtu_tier_boundaries(sut, reference):
    boundaries = [
        (1_000_000_000, 524288),  # >= top tier: inclusive
        (750_000_000, 131072),    # > 750M is strict -> next tier down
        (5_000_000, 4096),        # > 5M is strict -> next tier down
        (62_501, 1024),           # just above the lowest cutoff
        (62_500, None),           # > 62500 is strict -> below lowest tier
    ]
    for impl, label in ((reference, "ref"), (sut, "sut")):
        for bitrate, expected in boundaries:
            res = impl.execute("interface_optimise_mtu", bitrate=bitrate)
            assert res["hw_mtu"] == expected, (
                f"{label}: boundary bitrate={bitrate} must map to {expected} "
                f"(strict-> vs >= boundary); got {res['hw_mtu']}"
            )


@conformance_case(
    commands=["interface_optimise_mtu"],
    verifies="optimise_mtu only fires for AUTOCONFIGURE_MTU interfaces: with autoconfigure False, RNS leaves HW_MTU untouched (the pre-seeded sentinel is returned unchanged) even at a bitrate that would otherwise select a tier — so a fixed-MTU interface is never silently re-sized by the tier table",
)
def test_optimise_mtu_noop_when_not_autoconfigured(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        # Same bitrate that maps to 8192 under autoconfigure ...
        on = impl.execute("interface_optimise_mtu", bitrate=8_000_000)
        assert on["hw_mtu"] == 8192 and on["unchanged"] is False, (
            f"{label}: control — autoconfigure ON at 8Mbps must select 8192"
        )
        # ... must leave HW_MTU unchanged when autoconfigure is OFF.
        off = impl.execute(
            "interface_optimise_mtu", bitrate=8_000_000, autoconfigure=False
        )
        assert off["unchanged"] is True, (
            f"{label}: autoconfigure OFF must leave HW_MTU unchanged; got {off}"
        )


# ===========================================================================
# Per-interface ingress-control (ic_*) config overrides
# ===========================================================================
@conformance_case(
    commands=["config_parse_interface"],
    verifies="Per-interface ic_* config knobs override the seeded defaults (Reticulum.py:744-892 -> interface.ic_*): a [[interface]] setting ic_max_held_announces/ic_burst_freq/ic_new_time/ic_held_release_interval is stored verbatim on the live interface, distinct from the Interface class-constant defaults — an impl that hardcoded the class constants would ignore the operator's configured ingress-control policy",
)
def test_ic_overrides_stored_verbatim(sut, reference):
    body = (
        "ic_max_held_announces = 7\n"
        "ic_burst_freq = 4.5\n"
        "ic_new_time = 99\n"
        "ic_held_release_interval = 1"
    )
    # Chosen overrides all differ from the class-constant defaults so the
    # assertion discriminates override-applied from default-fallback.
    assert 7 != MAX_HELD_ANNOUNCES and 99 != IC_NEW_TIME
    for impl, label in ((reference, "ref"), (sut, "sut")):
        res = _parse(impl, body)
        assert res["ic_max_held_announces"] == 7, (
            f"{label}: ic_max_held_announces override not stored: "
            f"{res['ic_max_held_announces']}"
        )
        assert abs(res["ic_burst_freq"] - 4.5) < 1e-9, (
            f"{label}: ic_burst_freq override not stored: {res['ic_burst_freq']}"
        )
        assert res["ic_new_time"] == 99, (
            f"{label}: ic_new_time override not stored: {res['ic_new_time']}"
        )
        assert res["ic_held_release_interval"] == 1, (
            f"{label}: ic_held_release_interval override not stored: "
            f"{res['ic_held_release_interval']}"
        )


@conformance_case(
    commands=["config_parse_interface"],
    verifies="When NO ic_* knob is configured, the interface seeds each from the Interface class constant default (Interface.py:120-130 via Reticulum._default_ic_*): ic_max_held_announces=256, ic_burst_freq=10, ic_burst_freq_new=3, ic_burst_hold=15, ic_burst_penalty=15, ic_held_release_interval=5, ic_new_time=7200. Anchored on the spec constants — the negative control for the override test",
)
def test_ic_defaults_match_class_constants(sut, reference):
    expected = {
        "ic_max_held_announces": MAX_HELD_ANNOUNCES,
        "ic_burst_freq": IC_BURST_FREQ,
        "ic_burst_freq_new": IC_BURST_FREQ_NEW,
        "ic_burst_hold": IC_BURST_HOLD,
        "ic_burst_penalty": IC_BURST_PENALTY,
        "ic_held_release_interval": IC_HELD_RELEASE_INTERVAL,
        "ic_new_time": IC_NEW_TIME,
    }
    for impl, label in ((reference, "ref"), (sut, "sut")):
        # A config with no ic_* lines at all.
        res = _parse(impl, "bitrate = 1200")
        for key, value in expected.items():
            assert res[key] == value, (
                f"{label}: default {key} must equal the class constant {value}; "
                f"got {res[key]}"
            )


# ===========================================================================
# KISS read-loop HW_MTU in-frame byte cap (TCPInterface.read_loop)
# ===========================================================================
@conformance_case(
    commands=["kiss_deframe_stream"],
    verifies="RNS's KISS read loop appends an in-frame byte only while len(data_buffer) < self.HW_MTU (TCPInterface.py:362): a KISS frame whose payload exceeds HW_MTU is TRUNCATED to exactly HW_MTU bytes (the leading prefix), while a payload at/under HW_MTU is delivered whole. Anchored on the HW_MTU cap value passed in, with clean non-escape bytes so the byte count is exact",
)
def test_kiss_stream_truncates_at_hw_mtu(sut, reference):
    hw_mtu = 20
    over = b"A" * 40        # 2x HW_MTU -> truncated to the first 20 bytes
    under = b"B" * 12       # below the cap -> delivered whole
    at = b"C" * hw_mtu      # exactly the cap -> delivered whole
    for impl, label in ((reference, "ref"), (sut, "sut")):
        f_over = impl.execute(
            "kiss_deframe_stream", stream=_kiss_frame(over).hex(), hw_mtu=hw_mtu
        )["frames"]
        assert f_over == [(b"A" * hw_mtu).hex()], (
            f"{label}: over-HW_MTU KISS payload must truncate to {hw_mtu} bytes "
            f"(the leading prefix); got lengths "
            f"{[len(bytes.fromhex(x)) for x in f_over]}"
        )
        f_under = impl.execute(
            "kiss_deframe_stream", stream=_kiss_frame(under).hex(), hw_mtu=hw_mtu
        )["frames"]
        assert f_under == [under.hex()], (
            f"{label}: under-HW_MTU KISS payload must be delivered whole; got "
            f"{f_under}"
        )
        f_at = impl.execute(
            "kiss_deframe_stream", stream=_kiss_frame(at).hex(), hw_mtu=hw_mtu
        )["frames"]
        assert f_at == [at.hex()], (
            f"{label}: at-HW_MTU KISS payload ({hw_mtu} bytes) must be delivered "
            f"whole; got lengths {[len(bytes.fromhex(x)) for x in f_at]}"
        )


@conformance_case(
    commands=["hdlc_deframe_stream", "kiss_deframe_stream"],
    verifies="The HW_MTU in-frame cap is a KISS-path property, not HDLC: the standard-HDLC read loop (TCPInterface.py:380-398) has no per-byte HW_MTU gate, so an over-HW_MTU HDLC frame is delivered whole, whereas the identical-size payload under KISS is truncated to HW_MTU — pinning that the cap lives only in the byte-oriented KISS/Serial parser",
)
def test_hdlc_stream_not_capped_by_hw_mtu(sut, reference):
    hw_mtu = 20
    payload = b"A" * 40  # 2x HW_MTU
    for impl, label in ((reference, "ref"), (sut, "sut")):
        hdlc = impl.execute(
            "hdlc_deframe_stream", stream=_hdlc_frame(payload).hex(), hw_mtu=hw_mtu
        )["frames"]
        assert hdlc == [payload.hex()], (
            f"{label}: HDLC read loop must NOT cap at HW_MTU — the full "
            f"{len(payload)}-byte frame should be delivered; got lengths "
            f"{[len(bytes.fromhex(x)) for x in hdlc]}"
        )
        kiss = impl.execute(
            "kiss_deframe_stream", stream=_kiss_frame(payload).hex(), hw_mtu=hw_mtu
        )["frames"]
        assert kiss == [(b"A" * hw_mtu).hex()], (
            f"{label}: same payload under KISS must truncate to {hw_mtu} bytes — "
            f"the cap is KISS-only; got lengths "
            f"{[len(bytes.fromhex(x)) for x in kiss]}"
        )
