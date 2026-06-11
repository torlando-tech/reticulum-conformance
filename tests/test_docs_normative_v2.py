"""docs_normative V2 gap-closure conformance tests.

These tests close the byte-level / constant-literal gaps left PARTIAL by the V2
re-evaluation of the docs_normative subsystem. Each assertion anchors on an
EXTERNAL RNS 1.3.1 documented literal or an independent component-width
derivation — never on the implementation echoing its own value back.

Gaps closed here (vs CONFORMANCE_COMPLETENESS_V2):
  * doc-announce-size-167 — the assembled minimal announce frame is exactly
    167 bytes on the wire (199 with a ratchet); only the component widths were
    pinned before, never the assembled total.
  * doc-ifac-size-config-range — the 512-bit (full-signature) UPPER bound of
    the 8-512 bit configurable IFAC range; only the floor was exercised.
  * doc-ingress-control-announce-defaults — the documented per-interface
    ingress-control default literals (ic_max_held_announces=256, burst
    hold/penalty=15, burst freqs=3/10, held-release interval=5).
  * doc-discovery-stamp-default-cost-14 — the impl's OWN default discovery
    proof-of-work cost read back and asserted == 14 (was only a test-file
    constant before).
  * doc-announce-bandwidth-cap — the MAX_QUEUED_ANNOUNCES=16384 egress-queue
    ceiling and the 24h (QUEUED_ANNOUNCE_LIFE) queued-announce lifetime.
  * doc-probe-responder-optin — the well-known `rnstransport.probe` responder
    destination naming.

Every command below delegates to real RNS: the announce is produced by
RNS.Destination.announce(send=False).pack(); the interface attrs come from
RNS's real config parser + _synthesize_interface; the constants are read
straight off RNS.Reticulum / RNS.Discovery; the destination address is derived
by RNS.Destination.hash. The reference-vs-reference harness runs each impl
(sut == reference in --reference-only mode) so both bridges are pinned to the
same external literal.
"""

from conftest import random_hex
from conformance import conformance_case


__category_title__ = "Docs Normative (V2 gap closure)"
__category_order__ = 33


# --- EXTERNAL ground-truth spec literals (RNS 1.3.1 — NOT read from the impl) ---
HEADER_1_MINSIZE = 19            # Reticulum.HEADER_MINSIZE (flags+hops+addr16+ctx)
KEY_BYTES = 64                   # Identity.KEYSIZE//8  (X25519(32)+Ed25519(32))
NAME_HASH_BYTES = 10             # Identity.NAME_HASH_LENGTH//8
RANDOM_HASH_BYTES = 10           # 5 random + 5 big-endian timestamp
SIG_BYTES = 64                   # Identity.SIGLENGTH//8  (full Ed25519 signature)
RATCHET_BYTES = 32               # Identity.RATCHETSIZE//8

MINIMAL_ANNOUNCE_SIZE = 167      # documented minimal announce wire size
RATCHET_ANNOUNCE_SIZE = 199      # minimal + 32-byte ratchet

IFAC_512_BYTES = 512 // 8        # 64 — top of the 8-512 bit IFAC range
TCP_DEFAULT_IFAC_BYTES = 16      # ConfigParseProbe/TCP DEFAULT_IFAC_SIZE

# Documented per-interface ingress-control defaults (Interface.py:70-82).
IC_MAX_HELD_ANNOUNCES = 256
IC_BURST_FREQ_NEW = 3
IC_BURST_FREQ = 10
IC_BURST_HOLD = 15
IC_BURST_PENALTY = 15
IC_HELD_RELEASE_INTERVAL = 5

DEFAULT_STAMP_VALUE = 14         # Discovery.py:34 InterfaceAnnouncer.DEFAULT_STAMP_VALUE

MAX_QUEUED_ANNOUNCES = 16384     # Reticulum.MAX_QUEUED_ANNOUNCES
QUEUED_ANNOUNCE_LIFE = 60 * 60 * 24  # Reticulum.QUEUED_ANNOUNCE_LIFE (24h)
ANNOUNCE_CAP = 2                 # Reticulum.ANNOUNCE_CAP (percent)

# The well-known interface-probe responder destination (Transport.py:397):
# RNS.Destination(Transport.identity, IN, SINGLE, Transport.APP_NAME, "probe")
PROBE_APP_NAME = "rnstransport"  # Transport.APP_NAME
PROBE_ASPECT = "probe"
PROBE_FULL_NAME = "rnstransport.probe"

_PROBE_TYPE = "ConfigParseProbeInterface"


def _config(body: str) -> str:
    """Build a one-interface config text using the no-op probe interface type."""
    lines = [
        "[interfaces]",
        "  [[probe]]",
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


# =============================================================================
# doc-announce-size-167 — assembled minimal announce frame is 167 / 199 bytes
# =============================================================================

@conformance_case(
    commands=["announce_build"],
    verifies=(
        "The assembled minimal RNS announce frame is EXACTLY 167 bytes on the "
        "wire — the 19-byte HEADER_1 header + 64-byte public key + 10-byte "
        "name_hash + 10-byte random_hash + 64-byte Ed25519 signature, with no "
        "ratchet and no app_data — and a ratchet-bearing announce is exactly "
        "199 bytes (the same frame + a 32-byte ratchet). The byte total comes "
        "straight from RNS.Destination.announce(send=False).pack(), pinning the "
        "documented 167-byte minimal announce size against an independent "
        "component-width sum, not just the field widths in isolation."
    ),
)
def test_minimal_announce_wire_size_is_167(sut, reference):
    derived = (
        HEADER_1_MINSIZE + KEY_BYTES + NAME_HASH_BYTES + RANDOM_HASH_BYTES + SIG_BYTES
    )
    assert derived == MINIMAL_ANNOUNCE_SIZE  # test-internal sanity on the literals

    for impl, label in ((reference, "ref"), (sut, "sut")):
        priv = random_hex(64)
        built = impl.execute(
            "announce_build", private_key=priv, app_name="lxmf", aspects=["delivery"]
        )
        raw = bytes.fromhex(built["raw"])
        assert built["has_ratchet"] is False, f"{label}: minimal announce must carry no ratchet"
        assert not built["app_data"], f"{label}: minimal announce must carry no app_data"
        assert len(raw) == MINIMAL_ANNOUNCE_SIZE == derived, (
            f"{label}: minimal announce wire frame must be exactly "
            f"{MINIMAL_ANNOUNCE_SIZE} bytes; got {len(raw)}"
        )

        # Ratchet variant: same frame + a 32-byte ratchet inserted before the
        # signature -> 199 bytes. Fresh identity so the ratchet is genuinely
        # generated by RNS (enable_ratchets + first rotate inside announce()).
        rbuilt = impl.execute(
            "announce_build", private_key=random_hex(64), app_name="lxmf",
            aspects=["delivery"], enable_ratchets=True,
        )
        rraw = bytes.fromhex(rbuilt["raw"])
        assert rbuilt["has_ratchet"] is True, f"{label}: ratchet announce must set the context flag"
        assert len(rraw) == RATCHET_ANNOUNCE_SIZE == MINIMAL_ANNOUNCE_SIZE + RATCHET_BYTES, (
            f"{label}: ratchet announce wire frame must be exactly "
            f"{RATCHET_ANNOUNCE_SIZE} bytes (167 + 32); got {len(rraw)}"
        )


# =============================================================================
# doc-ifac-size-config-range — 512-bit (full-signature) upper bound
# =============================================================================

@conformance_case(
    commands=["config_parse_interface"],
    verifies=(
        "ifac_size configured at the documented 512-bit UPPER bound resolves to "
        "a 64-byte IFAC authentication tag (512 // 8), which is exactly the full "
        "Ed25519 signature length (Identity.SIGLENGTH // 8 == 64) an IFAC mask is "
        "derived from — pinning the top of the 8-512 bit configurable range "
        "(Reticulum.py:719-722). The 64-byte result is distinct from the "
        "interface's 16-byte DEFAULT_IFAC_SIZE so the assertion discriminates."
    ),
)
def test_ifac_size_512bit_upper_bound(sut, reference):
    assert IFAC_512_BYTES == SIG_BYTES == 64  # the 512-bit ceiling IS the full signature

    for impl, label in ((reference, "ref"), (sut, "sut")):
        res = _parse(impl, "ifac_size = 512")
        assert res["ifac_size"] == IFAC_512_BYTES, (
            f"{label}: ifac_size=512 bits must store as {IFAC_512_BYTES} bytes "
            f"(512//8); got {res['ifac_size']}"
        )
        assert res["ifac_size"] == SIG_BYTES, (
            f"{label}: the 512-bit IFAC ceiling must equal the full Ed25519 "
            f"signature length ({SIG_BYTES}); got {res['ifac_size']}"
        )
        assert res["default_ifac_size"] == TCP_DEFAULT_IFAC_BYTES, (
            f"{label}: probe/TCP DEFAULT_IFAC_SIZE must be {TCP_DEFAULT_IFAC_BYTES}; "
            f"got {res['default_ifac_size']}"
        )
        assert res["ifac_size"] != res["default_ifac_size"], (
            f"{label}: 512-bit result must be distinguishable from the default fallback"
        )


# =============================================================================
# doc-ingress-control-announce-defaults — documented per-interface ic defaults
# =============================================================================

@conformance_case(
    commands=["config_parse_interface"],
    verifies=(
        "An interface synthesized with no ingress-control overrides carries the "
        "documented ic_* default literals straight off RNS (Interface.py:70-82): "
        "ic_max_held_announces=256, ic_burst_freq_new=3, ic_burst_freq=10, "
        "ic_burst_hold=15, ic_burst_penalty=15, ic_held_release_interval=5. A "
        "config that explicitly overrides ic_max_held_announces=99 / "
        "ic_held_release_interval=7 stores those instead — proving 256/5 are "
        "genuine read-back defaults, not values the bridge hardcodes."
    ),
)
def test_ingress_control_announce_default_literals(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        # Defaults (a bitrate line only, no ic_* keys).
        d = _parse(impl, "bitrate = 1200")
        assert d["ic_max_held_announces"] == IC_MAX_HELD_ANNOUNCES, (
            f"{label}: default ic_max_held_announces must be {IC_MAX_HELD_ANNOUNCES}; "
            f"got {d['ic_max_held_announces']}"
        )
        assert d["ic_burst_freq_new"] == IC_BURST_FREQ_NEW, f"{label}: {d}"
        assert d["ic_burst_freq"] == IC_BURST_FREQ, f"{label}: {d}"
        assert d["ic_burst_hold"] == IC_BURST_HOLD, f"{label}: {d}"
        assert d["ic_burst_penalty"] == IC_BURST_PENALTY, f"{label}: {d}"
        assert d["ic_held_release_interval"] == IC_HELD_RELEASE_INTERVAL, f"{label}: {d}"

        # Override path: the defaults are configurable, so a different config
        # value must come back verbatim (proving the read-back is live, not fixed).
        o = _parse(impl, "ic_max_held_announces = 99\nic_held_release_interval = 7")
        assert o["ic_max_held_announces"] == 99, (
            f"{label}: ic_max_held_announces override must store 99; got "
            f"{o['ic_max_held_announces']}"
        )
        assert o["ic_held_release_interval"] == 7, (
            f"{label}: ic_held_release_interval override must store 7; got "
            f"{o['ic_held_release_interval']}"
        )
        assert o["ic_max_held_announces"] != IC_MAX_HELD_ANNOUNCES, (
            f"{label}: override must differ from the default to discriminate"
        )


# =============================================================================
# doc-discovery-stamp-default-cost-14 — impl's OWN default PoW cost == 14
# =============================================================================

@conformance_case(
    commands=["discovery_stamp"],
    verifies=(
        "The impl's OWN default interface-discovery proof-of-work cost is read "
        "back and equals the documented literal 14: the sender-side "
        "InterfaceAnnouncer.DEFAULT_STAMP_VALUE (Discovery.py:34) AND the "
        "receiver-side InterfaceAnnounceHandler default required_value "
        "(Discovery.py:192) are both 14, so the cost a receiver enforces by "
        "default matches the cost a sender targets by default."
    ),
)
def test_discovery_stamp_default_cost_is_14(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        res = impl.execute("discovery_stamp", op="default_cost")
        assert res["default_stamp_value"] == DEFAULT_STAMP_VALUE, (
            f"{label}: InterfaceAnnouncer.DEFAULT_STAMP_VALUE must be "
            f"{DEFAULT_STAMP_VALUE}; got {res['default_stamp_value']}"
        )
        assert res["handler_default_required_value"] == DEFAULT_STAMP_VALUE, (
            f"{label}: receiver default required_value must be "
            f"{DEFAULT_STAMP_VALUE}; got {res['handler_default_required_value']}"
        )


# =============================================================================
# doc-announce-bandwidth-cap — egress-queue ceiling + queued-announce lifetime
# =============================================================================

@conformance_case(
    commands=["announce_queue_constants"],
    verifies=(
        "The per-interface announce egress-queue constants match their "
        "documented literals straight off RNS.Reticulum: MAX_QUEUED_ANNOUNCES == "
        "16384 (the queue depth past which forwarded announces are dropped, "
        "Transport.py:1262), QUEUED_ANNOUNCE_LIFE == 86400 == 24h (a queued "
        "announce is purged as stale after a day, Interface.py:332), and the 2%% "
        "default ANNOUNCE_CAP == 2 — pinning the queue-cap and lifetime the "
        "bandwidth-cap spacing tests only infer."
    ),
)
def test_announce_queue_cap_and_lifetime_literals(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        c = impl.execute("announce_queue_constants")
        assert c["max_queued_announces"] == MAX_QUEUED_ANNOUNCES, (
            f"{label}: MAX_QUEUED_ANNOUNCES must be {MAX_QUEUED_ANNOUNCES}; "
            f"got {c['max_queued_announces']}"
        )
        assert c["queued_announce_life"] == QUEUED_ANNOUNCE_LIFE == 60 * 60 * 24, (
            f"{label}: QUEUED_ANNOUNCE_LIFE must be 24h ({QUEUED_ANNOUNCE_LIFE}s); "
            f"got {c['queued_announce_life']}"
        )
        assert c["announce_cap"] == ANNOUNCE_CAP, (
            f"{label}: ANNOUNCE_CAP must be {ANNOUNCE_CAP} (percent); got "
            f"{c['announce_cap']}"
        )


# =============================================================================
# doc-probe-responder-optin — well-known rnstransport.probe destination naming
# =============================================================================

@conformance_case(
    commands=[
        "identity_from_private_key", "destination_construct",
        "hash_from_name_and_identity", "app_and_aspects_from_name",
    ],
    verifies=(
        "The well-known interface-probe responder lives at the SINGLE/IN "
        "destination named 'rnstransport.probe' (Transport.APP_NAME + 'probe' "
        "aspect, Transport.py:397). A destination built from app_name="
        "'rnstransport' / aspect 'probe' expands its name to "
        "'rnstransport.probe.<identity hexhash>', its address equals the address "
        "RNS independently derives from the literal full name "
        "'rnstransport.probe' + the responder identity hash, and that full name "
        "decomposes back to app_name='rnstransport' / aspects=['probe'] — pinning "
        "the documented probe-destination naming convention."
    ),
)
def test_probe_responder_destination_naming(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        priv = random_hex(64)
        idinfo = impl.execute("identity_from_private_key", private_key=priv)
        id_hash = idinfo["hash"]
        id_hexhash = idinfo["hexhash"]

        dest = impl.execute(
            "destination_construct", identity_private_key=priv,
            app_name=PROBE_APP_NAME, aspects=[PROBE_ASPECT],
            type="single", direction="in",
        )
        # The SINGLE destination's expanded name is the well-known full name with
        # the responder identity's hexhash appended.
        assert dest["name"] == f"{PROBE_FULL_NAME}.{id_hexhash}", (
            f"{label}: probe destination name must expand to "
            f"'{PROBE_FULL_NAME}.<hexhash>'; got {dest['name']!r}"
        )

        # The probe address is fully determined by the literal well-known name
        # plus the responder identity hash — derived through an INDEPENDENT RNS
        # entry point (hash_from_name_and_identity over the literal string).
        indep = impl.execute(
            "hash_from_name_and_identity",
            full_name=PROBE_FULL_NAME, identity_hash=id_hash,
        )
        assert indep["destination_hash"] == dest["destination_hash"], (
            f"{label}: probe destination address must equal the address derived "
            f"from the literal '{PROBE_FULL_NAME}' + identity hash; "
            f"{indep['destination_hash']} != {dest['destination_hash']}"
        )

        # And the well-known name decomposes back to its app_name / aspect.
        parts = impl.execute("app_and_aspects_from_name", full_name=PROBE_FULL_NAME)
        assert parts["app_name"] == PROBE_APP_NAME, f"{label}: {parts}"
        assert list(parts["aspects"]) == [PROBE_ASPECT], f"{label}: {parts}"
