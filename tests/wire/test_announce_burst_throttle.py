"""Reproduce the ingress-burst-throttle path from RNS 1.2.x against reference.

When `Interface.ingress_control = True` and incoming_announce_frequency
exceeds IC_BURST_FREQ_NEW (3 announces in the rolling sample window for
a sub-2-hour-old interface), the receiving interface enters burst mode
and STARTS HOLDING announces in `Interface.held_announces`. Held
announces with the same destination_hash overwrite each other, so a
chatty source can starve a slower one out of the held queue.

This is exactly the failure pattern observed in production against
Sideband 1.9.4: the FIRST announce after attach is delivered (queue
not yet primed), then bursting from neighbouring destinations on the
same TCP interface trips the threshold and subsequent announces of
the destination we care about (rrcd's hub) get held + overwritten.

Two distinct destinations C-side announcing rapidly should expose
this: by the 4th-5th announce within the rolling window, threshold is
exceeded; one of the dests should stop reaching A.
"""

import time
import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "burst_throttle"
_ASPECTS = ["test"]
_SETTLE_SEC = 1.5
_PATH_TIMEOUT_MS = 5000


def _bring_up_topology(wire_shared_3peer):
    local_client, master, remote = wire_shared_3peer
    master.start_tcp_server(network_name="", passphrase="", share_instance=True, share_instance_type="tcp")
    remote.start_tcp_client(network_name="", passphrase="", target_host="127.0.0.1", target_port=master.port)
    local_client.start_local_client(
        shared_instance_port=master.shared_instance_port,
        instance_control_port=master.instance_control_port,
        rpc_key=master.rpc_key,
    )
    time.sleep(_SETTLE_SEC)
    return local_client, master, remote


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "announce", "poll_path"],
    verifies="When 12 rapid announces exceed IC_BURST_FREQ_NEW on an ingress-controlled TCP server, at least one is held by burst-mode throttling rather than reaching the downstream local client",
)
def test_burst_throttle_holds_subsequent_announces(wire_shared_3peer):
    """C announces several destinations rapidly enough to trip
    ingress_control burst mode on B's TCP server interface. After
    threshold is crossed, B should HOLD subsequent announces
    rather than forwarding them to A.

    Expectation: with default IC_BURST_FREQ_NEW=3, sending 6
    distinct announces in quick succession (within a 5s window)
    should activate burst mode at B's TCP receiver. The first
    few reach A, but at least one of the later announces is held
    and never reaches A (or arrives so much later than expected
    that poll_path times out at 5s).
    """
    local_client, master, remote = _bring_up_topology(wire_shared_3peer)

    n = 12
    dest_hashes = []
    for i in range(n):
        # Each call creates a fresh destination with a fresh identity.
        dest_hash = remote.announce(
            app_name=f"{_APP_NAME}_{i}",
            aspects=_ASPECTS,
        )
        dest_hashes.append(dest_hash)
        # Rapid bursting: 0.5s between announces. After 3 announces
        # in the rolling window, IC_BURST_FREQ_NEW=3 trips.
        time.sleep(0.15)

    # Wait briefly for any in-flight announces.
    time.sleep(2)

    # Count how many actually reached A within a short window.
    received = []
    missed = []
    for i, dest_hash in enumerate(dest_hashes):
        if local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS):
            received.append(i)
        else:
            missed.append(i)

    print(f"\n*** received {len(received)}/{n} announces (indices: {received})")
    print(f"*** held/missed {len(missed)}/{n} announces (indices: {missed})")

    # If ingress control is working, we expect at least one to be
    # held — i.e., not all 6 should arrive within the poll window.
    # If all 6 arrive, the throttle isn't being hit by this burst rate.
    assert len(missed) > 0, (
        f"Expected ingress_control burst-mode to hold at least one announce "
        f"out of {n} rapid announces, but ALL reached A. Either the burst "
        f"threshold isn't tripping at this rate, or held_announces is being "
        f"released faster than expected."
    )
