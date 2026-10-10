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

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    build_announce_from_destination,
    first_announce,
    HEADER_2,
    DESTINATION_TYPE_SINGLE,
    PACKET_TYPE_ANNOUNCE,
)

# Transport-type nibble for a transport relay packet (RNS/Transport.py:102,
# TRANSPORT = 0x01). Pinned as a spec literal like the other RNS constants here
# so the test does not depend on the bridge importing the module.
TRANSPORT_TYPE_TRANSPORT = 0x01

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


@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_path_table", "read_announce_table", "read_interface_mode",
              "set_announce_timestamp", "force_cull", "drain_tx"],
    verifies=(
        "The internal-mode announce re-broadcast rule (Transport.py:1479-1490): "
        "when the announce re-broadcast gate evaluates an INTERNAL-mode egress "
        "interface for a non-local announce whose next hop is a BOUNDARY-mode "
        "interface, it BLOCKS the re-broadcast, while a BOUNDARY-mode egress "
        "interface (Transport.py:1505-1516, which blocks only ROAMING next-hops) "
        "re-broadcasts the same announce - so INTERNAL egress is distinguishable "
        "from BOUNDARY egress on a BOUNDARY next hop"
    ),
)
def test_internal_egress_blocks_boundary_next_hop_rebroadcast(behavioral):
    """Drive one announce retransmit whose next hop is BOUNDARY and observe the
    per-egress-interface decision of the internal-mode re-broadcast gate.

    Setup: an announce arrives on `boundary` (a BOUNDARY-mode interface), which
    learns a path to the announcer whose received-on (next-hop) interface is
    `boundary` itself and schedules a local retransmit. Making the entry due and
    running one jobs() pass fires the retransmit: it is a re-broadcast
    (attached_interface=None), so it fans out to every OUT egress interface and
    the per-interface announce gate (Transport.py:1459) runs for each. The next
    hop interface is `boundary` (BOUNDARY mode), which is the gate's
    from_interface.

    Expected: the INTERNAL egress interface blocks the re-broadcast (the
    INTERNAL branch, Transport.py:1479-1490: from_interface is BOUNDARY ->
    should_transmit=False), while the second BOUNDARY egress interface
    re-broadcasts it (the BOUNDARY branch, Transport.py:1505-1516, blocks only
    ROAMING next-hops) - the positive control proving the retransmit actually
    fired and the block is specific to INTERNAL egress.

    HARD-FAIL capture: passes on the Python transport (the reference resolves
    INTERNAL to 0x07 and implements the gate); fails on the Kotlin transport at
    the INTERNAL attach (reticulum-kt's InterfaceMode enum has no INTERNAL and
    the bridge's parseMode rejects the string) until that work lands on
    reticulum-kt main, at which point the real gate assertion runs and the test
    self-clears with no edit here.
    """
    inst = behavioral.start(enable_transport=True)
    try:
        # `boundary` is the ingress AND the path's next hop (received-on).
        # `boundary2` and `internal` are the two egress probes: a BOUNDARY
        # positive control and the INTERNAL subject under test. Distinct
        # per-interface announce ingress-burst control is avoided because only
        # ONE announce is injected.
        boundary = inst.attach_mock_interface("boundary", mode="BOUNDARY")
        boundary2 = inst.attach_mock_interface("boundary2", mode="BOUNDARY")
        internal = inst.attach_mock_interface("internal", mode="INTERNAL")

        # Inject a real announce on `boundary`: learns the path (next hop =
        # boundary, BOUNDARY mode) and schedules the local retransmit with
        # attached_interface=None (the re-broadcast form).
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=secrets.token_bytes(64),
            app_name="intgate", aspects=["egress"], emission_ts=1_000_000_100,
            wire_hops=1,
        )
        inst.inject(boundary, raw)
        path = inst.read_path_table(dest)
        assert path["found"], "announce did not learn a path"
        # The crux precondition: the path's next hop (IDX_PT_RVCD_IF) MUST be
        # the BOUNDARY ingress interface - that is the gate's from_interface, and
        # the INTERNAL branch (Transport.py:1479-1490) only BLOCKS when the next
        # hop is BOUNDARY. Verify it explicitly rather than assuming it from the
        # single-interface setup: if the next hop were a different interface the
        # INTERNAL assertion below would be testing a different next-hop mode, or
        # (if the next hop were None) the announce would be blocked at
        # Transport.py:1467 "next hop interface doesn't exist" and the INTERNAL
        # assertion would pass for the wrong reason.
        boundary_hash = inst.read_interface_mode(boundary)["interface_hash"]
        assert path["receiving_interface_hash"] == boundary_hash, (
            f"the announce's learned path has next hop "
            f"{path['receiving_interface_hash']!r}, not the BOUNDARY ingress "
            f"interface {boundary_hash!r}; the re-broadcast gate's "
            f"from_interface would not be BOUNDARY-mode, so this would not "
            f"exercise the INTERNAL branch (Transport.py:1479)"
        )
        ann = inst.read_announce_table(dest)
        assert ann["found"], "announce did not schedule a local retransmit"

        # Make the retransmit due and fire exactly one jobs() pass. The retransmit
        # is emitted on a spawned thread (Transport.py:1222-1223 ->
        # handle_outgoing_announces), so poll the egress queues on a wall-clock
        # deadline rather than reading once.
        inst.set_announce_timestamp(dest, retransmit_timeout=0)
        inst.force_cull()

        def _poll_emitted(iface_id, deadline_s=10.0):
            """Return the egress bytes on `iface_id` once at least one announce is
            present or the wall-clock deadline elapses (whichever first)."""
            deadline = time.time() + deadline_s
            while True:
                got = inst.drain_tx(iface_id)
                if first_announce(got) is not None:
                    return got
                if time.time() >= deadline:
                    return got
                time.sleep(0.05)

        # Positive control: the BOUNDARY egress re-broadcasts the announce
        # (the BOUNDARY branch blocks only ROAMING next-hops; the next hop is
        # BOUNDARY). This proves the retransmit actually fired, so a missing
        # emission on the INTERNAL egress is a real block, not a no-op pass.
        boundary2_out = _poll_emitted(boundary2)
        reemit = first_announce(boundary2_out)
        assert reemit is not None, (
            "positive control failed: the BOUNDARY egress interface did not "
            "re-broadcast the announce whose next hop is BOUNDARY; the "
            "retransmit did not fire (or the egress model diverges), so the "
            "INTERNAL-block assertion below would be vacuous"
        )
        # The re-emitted bytes must be the SAME announce in the transport relay
        # form, not a coincidental emission. The retransmit rebuilds the packet
        # as a HEADER_2 TRANSPORT announce (Transport.py:800-810) carrying:
        #   - destination_hash = the announcer's destination (the one we learned
        #     a path to);
        #   - transport_id = THIS node's identity (Transport.identity.hash) -
        #     the re-broadcasting node stamps itself as the transport relay;
        #   - hops = received hops + 1 (the per-hop +1 on receive; wire_hops=1
        #     in -> 2 out);
        #   - header_type=HEADER_2 (transport), transport_type=TRANSPORT,
        #     packet_type=ANNOUNCE, destination_type=SINGLE.
        # Asserting the transport_id == our identity and the destination_hash ==
        # the announcer's dest pins that this is the re-broadcast of the exact
        # injected announce, not an unrelated one that happened to flow.
        assert reemit["destination_hash"] == dest, (
            f"re-emitted announce targets {reemit['destination_hash'].hex()} but "
            f"the learned announcer is {dest.hex()}; the positive control is not "
            f"re-broadcasting the injected announce"
        )
        assert reemit["transport_id"] == inst.identity_hash, (
            f"re-emitted announce transport_id {reemit['transport_id'].hex()} is "
            f"not this node's identity {inst.identity_hash.hex()}; the "
            f"re-broadcast must be stamped with the re-broadcasting node "
            f"(Transport.identity.hash, Transport.py:807)"
        )
        assert reemit["hops"] == 2, (
            f"re-emitted announce carries hops={reemit['hops']}; the +1-on-receive "
            f"increment (injected wire_hops=1 -> 2 out) must hold"
        )
        assert reemit["header_type"] == HEADER_2, (
            f"re-emitted announce header_type={reemit['header_type']}; a "
            f"transport re-broadcast must be HEADER_2 (the relay form)"
        )
        assert reemit["transport_type"] == TRANSPORT_TYPE_TRANSPORT, (
            f"re-emitted announce transport_type={reemit['transport_type']}; a "
            f"transport re-broadcast must carry transport_type=TRANSPORT"
        )
        assert reemit["packet_type"] == PACKET_TYPE_ANNOUNCE, (
            f"re-emitted announce packet_type={reemit['packet_type']}; must be "
            f"ANNOUNCE"
        )
        assert reemit["destination_type"] == DESTINATION_TYPE_SINGLE, (
            f"re-emitted announce destination_type={reemit['destination_type']}; "
            f"must be SINGLE"
        )

        # The distinctive INTERNAL rule: the INTERNAL egress interface does NOT
        # re-broadcast the same announce (the INTERNAL branch sees a BOUNDARY
        # next hop and blocks). A short deadline suffices here (vs the positive
        # control's): the re-broadcast fans out to every egress interface in a
        # single send() pass (Transport.handle_outgoing_announces), so once the
        # positive control above observed the emission, this interface's
        # (non-)emission was decided in that same pass - any 3s is orders of
        # magnitude past the spawned thread's queue append.
        internal_out = _poll_emitted(internal, deadline_s=3.0)
        assert first_announce(internal_out) is None, (
            "INTERNAL egress re-broadcast an announce whose next hop is a "
            "BOUNDARY-mode interface; the internal-mode re-broadcast gate "
            "(Transport.py:1479-1490) must block BOUNDARY next-hops on an "
            "INTERNAL-mode interface"
        )
    finally:
        behavioral.cleanup()
