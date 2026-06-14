"""Steady-state ingress: multiple announces from C must all reach A.

This is the diagnostic for the bug observed against Sideband 1.9.4: the
first announce (or path-table cache flush at attach time) reaches the
local client, but subsequent live announces do not. The existing
test_announce_remote_to_local checks only ONE announce — passing there
does not prove ongoing fanout works.

If reference passes this test, python RNS's local-client fanout is
correct and Sideband's failure is in app-layer code (or a bundled-RNS
version mismatch). If reference fails this test, the conformance
suite has reproduced the bug against vanilla python RNS.
"""

import time

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "shared_master_announce_steady"
_ASPECTS = ["test"]
_SETTLE_SEC = 1.5
_PATH_TIMEOUT_MS = 10000


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
    verifies="Three distinct announces from a TCP remote spaced 10s apart each reach the local client via the shared-instance master — no fanout regression after the first announce",
)
def test_steady_state_announce_three_in_a_row(wire_shared_3peer):
    """C announces THREE distinct destinations spaced 10s apart.
    Each must reach A within the path-discovery timeout.

    Spacing: 10s mimics rrcd's 60s production cadence loosely while
    keeping the test fast. The relevant property is "the fanout
    continues working after the first announce", not the exact rate.
    """
    local_client, master, remote = _bring_up_topology(wire_shared_3peer)

    dest_hashes = []
    for i in range(3):
        # Each call to announce() generates a fresh destination with a
        # fresh identity, so the random_blob and packet_hash are different
        # each time — no dedup confusion.
        dest_hash = remote.announce(
            app_name=f"{_APP_NAME}_{i}",
            aspects=_ASPECTS,
        )
        dest_hashes.append(dest_hash)
        time.sleep(10)

    # Verify all three reached A
    for i, dest_hash in enumerate(dest_hashes):
        assert local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
            f"announce {i+1}/3 of {dest_hash.hex()} from {remote.role_label} "
            f"did not reach {local_client.role_label} via {master.role_label} "
            f"within {_PATH_TIMEOUT_MS}ms — steady-state fanout broke after "
            f"announce {i}/3 had succeeded."
        )
