"""Behavioral test: INTERNAL interface mode (RNS 1.3.6+) is a distinct mode
constant that participates in path discovery, with the announce attributes the
re-broadcast gate switches on.

The reference implementation (Python RNS) defines INTERNAL as its own mode
constant, `Interface.MODE_INTERNAL = 0x07` (RNS/Interfaces/Interface.py:51),
and includes it in `DISCOVER_PATHS_FOR` (Interface.py:55) - so an internal-mode
interface runs path discovery like ACCESS_POINT / GATEWAY / ROAMING, unlike
FULL / POINT_TO_POINT / BOUNDARY. The base `Interface.__init__` defaults the
two announce attributes the internal-mode announce re-broadcast gate reads
(`announces_from_internal = True`, `announces_to_internal = None`,
Interface.py:122-123); the gate at Transport.py:1471-1490 branches on both the
mode constant and those attributes to decide whether an internal-mode interface
re-broadcasts foreign announces.

This is a HARD-FAIL conformance capture of that behavior. The reference bridge
resolves the `"INTERNAL"` mode string to the real `MODE_INTERNAL` constant, so
on the Python transport this test PASSES: the attached interface reports
mode == 0x07, `announces_from_internal` True, `announces_to_internal` None, and
`discover_paths` True. On the Kotlin transport it FAILS, because reticulum-kt's
`InterfaceMode` enum has no INTERNAL value and the conformance bridge's
`parseMode` rejects the mode string ("Unknown interface mode: INTERNAL") at
attach time. That red arm is intentional and is the whole point of the capture:
it pins the expected INTERNAL-mode behavior now, and it stays red until
reticulum-kt grows the INTERNAL enum value + a matching bridge mode + the
`behavioral_read_interface_mode` observation seam. Once that Kotlin work lands
on reticulum-kt main and the SUT bridge is rebuilt, this test turns green with
no edit here.

Ordering is deliberate: the INTERNAL attach runs FIRST, before any readback, so
that a port which cannot express INTERNAL fails at the attach (the honest gap)
rather than later at a command the port's bridge has not yet implemented. A
FULL-mode positive control follows (Python arm only in the pre-fix state): it
proves the readback is not vacuous - a conformant port reports the FULL constant
(0x01) and no path discovery for a FULL-mode interface, so a port that silently
coerces every mode to a single value would still fail the INTERNAL assertions.
"""

from conformance import conformance_case

# Reference-implementation mode constants (RNS/Interfaces/Interface.py:45-51).
# Pinned as spec literals so the test does not depend on the bridge importing
# the same module - the assertion is against the documented byte values, and a
# port using a different byte for INTERNAL (or confusing it with another mode)
# would diverge from a conformant peer.
MODE_FULL = 0x01
MODE_INTERNAL = 0x07


__category_title__ = "Interface Mode (Behavioral)"
__category_order__ = 25


@conformance_case(
    commands=["start", "attach_mock_interface", "read_interface_mode"],
    verifies=(
        "INTERNAL is a distinct interface mode (constant 0x07, RNS 1.3.6+) that "
        "participates in path discovery (DISCOVER_PATHS_FOR, Interface.py:55) with "
        "the base announce attributes the re-broadcast gate reads (Interface.py:122-123, "
        "Transport.py:1471-1490): an INTERNAL-mode interface reports mode=0x07, "
        "announces_from_internal=True, announces_to_internal=None, discover_paths=True, "
        "distinct from FULL (0x01, no path discovery)"
    ),
)
def test_internal_mode_constant_and_discovery(behavioral):
    """Attach an INTERNAL-mode interface and assert its effective mode constant,
    the announce attributes the gate reads, and its path-discovery membership.

    PASSes on the Python transport (the reference resolves INTERNAL to 0x07).
    FAILs on the Kotlin transport until reticulum-kt adds the INTERNAL enum
    value + bridge mode (the bridge's parseMode rejects the string today).
    """
    inst = behavioral.start(enable_transport=True)
    try:
        # INTERNAL-mode differential, first: on the Kotlin transport this
        # attach raises (the bridge's parseMode rejects "INTERNAL") -> hard
        # fail at the attach, the honest gap. On the Python transport it
        # resolves to the real 0x07 constant and proceeds to the readback.
        internal_id = inst.attach_mock_interface("internal", mode="INTERNAL")
        internal = inst.read_interface_mode(internal_id)

        assert internal["mode"] == MODE_INTERNAL, (
            f"INTERNAL-mode interface reported mode {internal['mode']}, expected "
            f"{MODE_INTERNAL} (0x07, RNS 1.3.6+). A port that coerces INTERNAL to "
            f"FULL (0x01) or another constant is not conformant."
        )
        # The announce attributes the internal-mode re-broadcast gate reads,
        # defaulting from Interface.__init__ (Interface.py:122-123).
        assert internal["announces_from_internal"] is True, (
            f"INTERNAL-mode interface should default announces_from_internal=True "
            f"(Interface.py:122), got {internal['announces_from_internal']}"
        )
        assert internal["announces_to_internal"] is None, (
            f"INTERNAL-mode interface should default announces_to_internal=None "
            f"(Interface.py:123), got {internal['announces_to_internal']}"
        )
        # INTERNAL participates in path discovery (Interface.py:55).
        assert internal["discover_paths"] is True, (
            f"INTERNAL-mode interface should run path discovery (DISCOVER_PATHS_FOR, "
            f"Interface.py:55), got discover_paths={internal['discover_paths']}"
        )

        # Positive control (reached on the conformant / Python transport): a
        # FULL-mode interface must report the FULL constant (0x01) and NOT
        # participate in path discovery. This proves the readback genuinely
        # distinguishes modes - a port that coerces every mode to one value
        # would fail the INTERNAL assertions even though this control passes -
        # and anchors the differential: INTERNAL must differ from FULL on both
        # the constant and the discovery membership.
        full_id = inst.attach_mock_interface("full", mode="FULL")
        full = inst.read_interface_mode(full_id)
        assert full["mode"] == MODE_FULL, (
            f"FULL-mode interface reported mode {full['mode']}, expected "
            f"{MODE_FULL}; the readback mechanism is not observing the "
            f"configured mode"
        )
        assert full["discover_paths"] is False, (
            f"FULL-mode interface should not run path discovery, got "
            f"discover_paths={full['discover_paths']}"
        )
        assert internal["mode"] != full["mode"], (
            "INTERNAL and FULL interfaces report the same mode constant; INTERNAL "
            "is not a distinct mode"
        )
    finally:
        behavioral.cleanup()
