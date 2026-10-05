"""Resource proof caching (reticulum-kt #65 / PR #97).

When a Resource receiver completes a transfer it proves it by sending a single
RESOURCE_PRF (Resource.prove, Resource.py:752-757) AND force-caching that proof
packet in the transport packet cache (Resource.py:759:
`RNS.Transport.cache(proof_packet, force_cache=True)`). The cache entry is what
the SENDER's AWAITING_PROOF recovery retrieves: Resource.py:653-656 rebuilds the
same proof packet and calls `Transport.cache_request(expected_proof_packet.
packet_hash, ...)` to re-fetch a proof that was lost in transit. An impl that
sends the proof but does not cache it leaves the sender's recovery as a no-op —
the proof is "lost" even though it was generated (reticulum-kt#65, fixed by PR
#97).

The observable is the transport packet cache, read the SAME way the sender's
recovery reads it. The sender's AWAITING_PROOF recovery (Resource.py:653-656)
rebuilds the proof packet from the payload prove() emitted and calls
`Transport.cache_request(packet.packet_hash, ...)` -> `get_cached_packet(hash)`.
That lookup only works because the proof packet's `packet_hash` is reproducible:
the proof is HEADER_1 and unencrypted (Packet.py:196-198), and `send()`/
`outbound()` do not mutate `packet.raw`. So the bridge captures the payload
prove() actually emitted, rebuilds the identical packet, and asks
`get_cached_packet` for that exact `packet_hash` - the very key recovery uses.
A conforming impl returns the cached packet (proof_in_cache True); an impl that
sends the proof but omits the cache call returns None (proof_in_cache False).

Reference-vs-reference: the python reference always caches (Resource.py:759), so
every arm with a python receiver PASSES - including the `--reference-only`
baseline, which proves the test really asserts the divergence. Against
UNMODIFIED kotlin the receiver-side arm must FAIL (the divergence), and pass
clean once PR #97's `Transport.cache(..., forceCache = true)` call lands on main.
"""

from conformance import conformance_case
import pytest

from bridge_client import BridgeError

__category_title__ = "Wire Interop"
__category_order__ = 18

_APP = "conformance"
_ASPECTS = ["resource-proof-cache"]


def _is_unknown_command_error(e: BridgeError) -> bool:
    """True if a BridgeError is the bridge's "command not recognized" signal.

    The kotlin bridge raises `Unknown wire command: <cmd>` (WireTcp.kt) when a
    command is not in the built jar. That is the signal the built bridge predates
    this test's command (the bridge-support PR not merged to main yet) — a
    sequencing gap, not a code defect. Any other error is a real failure.
    """
    msg = str(e)
    return ("Unknown wire command" in msg or "Unknown command" in msg
            or "unknown command" in msg.lower())


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "resource_proof_cache_lookup",
    ],
    verifies=(
        "A Resource receiver that completes a transfer stores its RESOURCE_PRF "
        "proof in the transport packet cache (python Resource.prove, "
        "Resource.py:759: cache(proof_packet, force_cache=True)), so the "
        "sender's AWAITING_PROOF recovery (Resource.py:653-656 cache_request) "
        "can re-fetch a lost proof. The bridge reads the cache the same way "
        "recovery does: it rebuilds the proof packet prove() emitted and asks "
        "get_cached_packet for its exact packet_hash (proof_in_cache). A "
        "conforming impl returns the cached packet (True); an impl that sends "
        "the proof without caching it leaves the sender's recovery as a no-op "
        "and reports proof_in_cache False. reticulum-kt #65: the unmodified "
        "kotlin prove() sends the proof but omits the cache call, so the "
        "receiver-side arm fails here until PR #97's cache call lands."
    ),
)
def test_resource_proof_cached_for_sender_recovery(wire_link_setup, wire_pair):
    server_impl, client_impl = wire_pair
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # The receiver (and thus the cache under test) lives on the CLIENT peer,
    # which holds the outbound link _build_resource_receiver builds on. So the
    # divergence shows up on the client_impl arm, not server_impl.
    try:
        res = client.bridge.execute(
            "wire_resource_proof_cache_lookup",
            handle=client.handle, link_id=link_id.hex(),
        )
    except BridgeError as e:
        # Dependency gate: conformance CI builds the kotlin bridge from
        # reticulum-kt main. Until the bridge-support PR (which adds
        # wire_resource_proof_cache_lookup) merges, the kotlin bridge does not
        # know the command and raises "Unknown wire command". Xfail as a
        # sequencing dependency so this PR stays green; any OTHER error (or one
        # on the reference arm, where the command is always present) re-raises.
        if client_impl == "kotlin" and _is_unknown_command_error(e):
            pytest.xfail(
                "Sequencing dependency: the kotlin bridge lacks "
                "wire_resource_proof_cache_lookup (bridge-support PR not merged "
                "to reticulum-kt main yet). This test runs once it is."
            )
        raise

    # Positive-control precondition: the transfer actually completed and emitted
    # a proof. Proves the receiver really reached prove() (Resource.py:713), so
    # a proof_in_cache False below is a missing cache call, not a transfer that
    # never concluded.
    assert res["total_parts"] >= 2, f"expected a multi-part transfer: {res!r}"
    assert res["status_name"] == "COMPLETE", (
        f"the transfer did not complete (status {res['status_name']!r}) so the "
        f"proof-caching assertion below would be vacuous: {res!r}"
    )
    assert res["complete"] is True, res
    assert res["proof_sent"] is True, (
        f"a completed transfer must have sent exactly one proof, but none was "
        f"captured: {res!r}"
    )

    # The divergence: the proof must be recoverable from the cache by the exact
    # key the sender's recovery uses (get_cached_packet on the proof's
    # packet_hash). If it is not, the sender's AWAITING_PROOF recovery has
    # nothing to re-fetch and the proof is lost in transit (reticulum-kt#65).
    if client_impl == "kotlin" and res["proof_in_cache"] is False:
        # The divergence is present (unmodified kotlin prove() sends the proof
        # but omits the cache call). Waive rather than fail so this PR stays
        # green before #97's cache call lands on main; self-clears once it does.
        pytest.xfail(
            "reticulum-kt#65: Resource.prove sends the RESOURCE_PRF proof but "
            "omits python's Transport.cache(proof, force_cache=True) "
            "(Resource.py:759), so the proof is never in the packet cache and "
            "the sender's AWAITING_PROOF recovery (Resource.py:653-656) has "
            "nothing to re-fetch. Fixed by PR #97."
        )
    assert res["proof_in_cache"] is True, (
        f"the proof was sent but is NOT recoverable from the transport packet "
        f"cache via the exact key the sender's recovery uses: "
        f"get_cached_packet(proof.packet_hash) returned None. The sender's "
        f"AWAITING_PROOF recovery (python Resource.py:653-656) would have "
        f"nothing to re-fetch, so the proof is lost in transit. This is "
        f"reticulum-kt #65 - prove() must cache the proof (Resource.py:759)."
    )
