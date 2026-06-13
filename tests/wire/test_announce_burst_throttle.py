"""Reproduce the ingress-burst-throttle path from RNS against reference.

When `Interface.ingress_control = True`, the receiving interface tracks the
incoming announce FREQUENCY (a rate in Hz, computed as samples/span over a
rolling deque — see Interface.incoming_announce_frequency, Interface.py:279).
`IC_BURST_FREQ_NEW` is that frequency THRESHOLD, not a count: its default
value 3 means "3 Hz" for a sub-IC_NEW_TIME (default 7200 s ≈ 2 h) old
interface (older interfaces use the higher `IC_BURST_FREQ`, default 10 Hz).
When the measured frequency EXCEEDS the threshold, `should_ingress_limit()`
flips the interface into burst mode (`ic_burst_active = True`) and from then
on announces for destinations NOT yet in the path table are diverted to
`Interface.held_announces` instead of being forwarded (Transport.py:1694-1705).
Held announces sharing a destination_hash overwrite each other, so a chatty
source can starve a slower one out of the held queue.

This is the failure pattern observed in production against Sideband 1.9.4:
the first announces after attach are delivered (the rolling deque has too few
samples to compute a rate yet — incoming_announce_frequency returns 0 until it
holds more than IC_DEQUE_MIN_SAMPLE=2 samples), then bursting from neighbouring
destinations on the same TCP interface pushes the rate over the threshold and
subsequent fresh-destination announces get held rather than forwarded to the
downstream local client.

A single TCP remote announcing many distinct (fresh-identity) destinations
faster than the 3 Hz threshold exposes this: the first two announces are
forwarded (deque too small to trip), then once the rate is measurable and
exceeds 3 Hz, later announces are held and do not reach A within its
path-discovery poll window.
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
    verifies="A TCP remote announcing 12 fresh destinations at ~6.6 Hz (above the 3 Hz IC_BURST_FREQ_NEW threshold) on an ingress-controlled master: the first two announces (sent before the rolling rate sample can trip) reach the downstream local client, while at least one later announce does not arrive within the poll window — and with throttling off all would arrive (positive control)",
)
def test_burst_throttle_holds_subsequent_announces(wire_shared_3peer):
    """C announces 12 distinct fresh-identity destinations fast enough to
    trip ingress_control burst mode on B's TCP server interface, then we
    measure which ones reach A.

    Rate: announces are spaced 0.15 s apart (~6.6 Hz), comfortably above the
    3 Hz `IC_BURST_FREQ_NEW` threshold a <2-hour-old interface uses
    (Interface.should_ingress_limit, Interface.py:145-165). The 0.5 s figure
    an earlier revision cited would only be ~2 Hz — BELOW the threshold — and
    would not trip the throttle, so the spacing must stay tight.

    Expectation, validated reference-vs-reference:
      * Indices 0 and 1 ALWAYS reach A. They are processed before B's rolling
        announce deque holds more than IC_DEQUE_MIN_SAMPLE=2 samples, so
        incoming_announce_frequency() still returns 0 and burst mode cannot
        have activated yet.
      * Once the deque can measure a rate (>3 Hz here), burst mode activates
        and later fresh-destination announces are diverted to held_announces
        at B instead of being forwarded, so at least one of indices 2..11 does
        NOT reach A within its poll window.

    The exact post-threshold split is timing-dependent and intentionally not
    pinned; the assertions below check the threshold-robust invariants only.
    """
    local_client, master, remote = _bring_up_topology(wire_shared_3peer)

    n = 12
    dest_hashes = []
    for i in range(n):
        # Each call creates a fresh destination with a fresh identity, so every
        # announce is for a path-table-UNKNOWN destination — the case burst-mode
        # ingress control diverts to held_announces (Transport.py:1703-1705).
        dest_hash = remote.announce(
            app_name=f"{_APP_NAME}_{i}",
            aspects=_ASPECTS,
        )
        dest_hashes.append(dest_hash)
        # ~6.6 Hz: tight enough to push incoming_announce_frequency over the
        # 3 Hz IC_BURST_FREQ_NEW threshold once the deque has >2 samples.
        time.sleep(0.15)

    # Wait briefly for any in-flight announces.
    time.sleep(2)

    # Count how many actually reached A within the poll window.
    received = []
    missed = []
    for i, dest_hash in enumerate(dest_hashes):
        if local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS):
            received.append(i)
        else:
            missed.append(i)

    print(f"\n*** received {len(received)}/{n} announces (indices: {received})")
    print(f"*** held/missed {len(missed)}/{n} announces (indices: {missed})")

    # Positive control (N-M7): the topology actually delivers announces. Without
    # this, `len(missed) > 0` is vacuously true on a DEAD topology (if nothing
    # ever reaches A, every index is "missed" and the throttle claim is unproven).
    assert len(received) > 0, (
        f"No announce reached {local_client.role_label} at all — the "
        f"shared-instance master forwarded NONE of {n} announces. The "
        f"burst-throttle finding is vacuous on a dead topology; fix the "
        f"topology before reading the throttle result."
    )

    # Pre-burst announces MUST arrive. Indices 0 and 1 are processed while B's
    # rolling deque holds <=2 samples, so incoming_announce_frequency() returns
    # 0 and burst mode cannot have tripped — these can never be held.
    assert {0, 1}.issubset(set(received)), (
        f"Pre-burst announces (indices 0,1) did not both reach "
        f"{local_client.role_label}; received={received}. These are sent "
        f"before B can measure an announce rate, so they must be forwarded — "
        f"their loss indicates broken fanout, not throttling."
    )

    # Post-threshold throttling MUST hold at least one announce: once the
    # measured rate exceeds 3 Hz, later fresh-destination announces are held at
    # B and do not reach A within the poll window.
    assert len(missed) > 0, (
        f"Expected ingress_control burst-mode to hold at least one of {n} "
        f"announces sent at ~6.6 Hz, but ALL reached A. Either the burst "
        f"threshold isn't tripping at this rate, or held_announces is being "
        f"released faster than expected."
    )

    # Everything held is from the post-threshold region. Indices 0 and 1 can
    # never be held (deque too small to measure a rate), so every missed index
    # must be >= 2 — proving the throttle engaged AFTER the pre-burst announces,
    # not that delivery is simply flaky.
    assert all(idx >= 2 for idx in missed), (
        f"A pre-burst announce (index < 2) was held: missed={missed}. Burst "
        f"mode cannot activate until B has measured a rate (>2 deque samples), "
        f"so indices 0/1 must always be forwarded."
    )
