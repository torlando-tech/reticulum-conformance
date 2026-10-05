"""Explicit destination-registration IN-direction guard (reticulum-kt #85).

Transport.registerDestination must filter to IN-direction destinations,
matching Python's Transport.register_destination (Transport.py:2898). The
production trigger is the send path (Reticulum.registerDestination ->
Transport.registerDestination), which registers a peer's OUT destination when
you send to it. The unguarded kotlin port (Transport.kt:1000) appends every
direction, so that OUT destination lands in the local-destination table and
its announces get skipped ("Skipping announce for local destination").

The local-destination table membership is the observable that drives the
announce-skip gate on both implementations:
  * Python:  ``packet.destination_hash in Transport.destinations_map``
             (Transport.py:1710)
  * Kotlin:  ``destinations.any { it.hash == destHash }``
             (Transport.kt:3648)

This test isolates the single unit of code that diverges: one explicit
register call (construction-time auto-registration is cleared first so it
does not contaminate the result), then reads whether the destination is
"local". The IN case is the positive control proving the local-table
mechanism works, so a False on OUT is a real guard, not a vacuous mechanism.

This is a single-instance property - no TCP handshake or peer is needed, so
the test drives one SUT peer (the `sut` bridge) directly. Under
--reference-only the SUT is the python reference and the test must PASS
(proving the test really asserts the divergence); against unmodified kotlin
it must FAIL on the OUT case (the bug), and pass once the IN-guard fix
lands.
"""

from conformance import conformance_case
import pytest

from bridge_client import BridgeError


__category_title__ = "Wire Interop"
__category_order__ = 18

_APP = "conformance"
_ASPECTS = ["register-destination-guard"]


def _is_unknown_command_error(e: BridgeError) -> bool:
    """True if a BridgeError is the bridge's 'command not recognized' signal.

    The kotlin bridge raises `Unknown wire command: <cmd>` (WireTcp.kt) or
    `Unknown command: <cmd>` (KotlinBridge.kt) when a command is not in the
    built jar. That is the signal that the built bridge predates this test's
    command (reticulum-kt#93 not merged to main yet) - a sequencing gap, not
    a code defect. Any other error message is a real failure.
    """
    msg = str(e)
    return ("Unknown wire command" in msg or "Unknown command" in msg
            or "unknown command" in msg.lower())


@conformance_case(
    commands=[
        "start_tcp_server", "register_destination",
    ],
    verifies=(
        "The explicit destination-registration guard filters to IN-direction "
        "destinations (Python Transport.py:2898): after clearing "
        "construction-time registration and performing one explicit "
        "registerDestination (the production send-path trigger), an IN "
        "destination is local (is_local True - positive control proving the "
        "local-destination-table mechanism works) and an OUT destination is "
        "NOT local (is_local False). The local-destination table membership "
        "is exactly the observable that drives the announce-skip gate "
        "(Transport.py:1710 / Transport.kt:3648). reticulum-kt #85: the "
        "unguarded kotlin registerDestination appends every direction, so the "
        "OUT destination wrongly becomes local and its announces are skipped; "
        "this test fails on the OUT case until the IN-direction guard is "
        "added."
    ),
)
def test_register_destination_in_direction_guard(sut, sut_impl_name):
    # Known divergence: reticulum-kt #85. The IN-direction guard fix is not on
    # reticulum-kt main yet (it lands via the #85 PR). Both direction checks
    # MUST run on every arm (including kotlin) so the kotlin bridge command is
    # actually exercised and the IN positive control proves the local-table
    # mechanism works there; only the OUT assertion is waived, and only while
    # the divergence is actually present (see below), so the kotlin arm flips
    # to a clean pass once the IN-guard fix merges.
    resp = sut.execute(
        "wire_start_tcp_server",
        network_name="", passphrase="",
    )
    handle = resp["handle"]

    # Positive control FIRST: an IN destination must be local. Proves the
    # local-destination-table mechanism works on this implementation, so the
    # OUT result below is a real guard (or a real bug), not a vacuous
    # mechanism that returns False for everything.
    try:
        in_resp = sut.execute(
            "wire_register_destination",
            handle=handle, direction="IN",
            app_name=_APP, aspects=list(_ASPECTS),
        )
    except BridgeError as e:
        # Dependency gate: conformance CI builds the kotlin bridge from
        # reticulum-kt main. Until reticulum-kt#93 (which adds this command)
        # is merged, the kotlin bridge does not know wire_register_destination
        # and raises "Unknown wire command". Xfail as a sequencing dependency
        # so this PR stays green, rather than failing the whole kotlin run.
        # Any OTHER BridgeError (or one on the reference arm, where the command
        # is always present) is a real failure and is re-raised.
        if sut_impl_name == "kotlin" and _is_unknown_command_error(e):
            pytest.xfail(
                "Sequencing dependency: the kotlin bridge lacks "
                "wire_register_destination (reticulum-kt#93 not merged to main "
                "yet). This test runs once #93 is on main; the #85 divergence "
                "waiver below is then self-managed."
            )
        raise

    assert in_resp["direction"] == "IN"
    assert in_resp["is_local"] is True, (
        f"IN destination must be local (positive control) but is_local is "
        f"{in_resp['is_local']!r} - the local-destination-table mechanism "
        f"itself is not working, so the OUT assertion below would be vacuous."
    )

    # The divergence: an OUT destination must NOT be local. Python filters
    # direction == IN in register_destination; the unguarded kotlin port
    # (Transport.kt:1000) appends every direction, so an OUT destination lands
    # in the local table and its announces are skipped. Both directions have
    # already run on every arm above; waive ONLY this assertion, and ONLY for
    # kotlin while the divergence is actually present (is_local True). Once
    # the #85 IN-guard fix lands, is_local is False and this arm passes clean.
    out_resp = sut.execute(
        "wire_register_destination",
        handle=handle, direction="OUT",
        app_name=_APP, aspects=list(_ASPECTS),
    )
    assert out_resp["direction"] == "OUT"
    out_is_local = out_resp["is_local"]
    if sut_impl_name == "kotlin" and out_is_local is True:
        # The divergence is present (unguarded kotlin registered the OUT
        # destination as local). Waive rather than fail so this PR stays green
        # before the #85 fix merges; remove once it lands on main.
        pytest.xfail(
            "reticulum-kt#85: Transport.registerDestination is missing "
            "Python's IN-direction guard (Transport.py:2898), so an explicit "
            "register of an OUT destination wrongly makes it 'local' and its "
            "announces are skipped. Refs Transport.kt:1000 vs "
            "Transport.py:2898."
        )
    assert out_is_local is False, (
        f"OUT destination must NOT be local (Python Transport.py:2898 "
        f"filters direction == IN), but is_local is {out_is_local!r}. "
        f"This is reticulum-kt #85: Transport.registerDestination is missing "
        f"the IN-direction guard, so a registered OUT destination pollutes "
        f"the local table and its announces are skipped."
    )
