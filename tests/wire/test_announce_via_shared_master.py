"""Announce ingress and egress through a shared-instance master.

Topology (same as test_link_via_shared_master.py):

    local_client (A) ── shared instance ──▶ master (B, SUT)
                                              │
                                              │  TCP loopback
                                              ▼
                                         remote (C, TCP)

Two directions, two tests:

1. **egress** (test_announce_local_to_remote):
   A registers a destination D and announces it. Master B forwards the
   announce to its TCP-attached remote C. C's path table must learn a
   route to D.
   Exercises: master receiving an announce on a LocalServerInterface and
   re-broadcasting it on its TCPInterface.

2. **ingress** (test_announce_remote_to_local):
   C registers a destination D and announces it. Master B receives the
   announce on its TCPInterface and re-broadcasts to its
   LocalServerInterface clients. A's path table must learn a route to D.
   Exercises: master receiving an announce on a TCPInterface and pushing
   it down to local-instance clients (the "spoof" path Python documents
   at Transport.py:1486 — master inserts itself as transport_id when
   forwarding to clients so they see the dest as 1-hop reachable).

Either direction failing for the kotlin master would be a real bug —
the Eridanus integration relies on both. They're a useful baseline
above and beyond the link_id test: even if linkIds were correct,
broken announce propagation would break discovery.

Per-impl expectation: both directions should pass for both
master_impl=reference and master_impl=kotlin.
"""

import time

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "shared_master_announce"
_ASPECTS = ["test"]

_SETTLE_SEC = 1.5
_PATH_TIMEOUT_MS = 10000


def _bring_up_topology(wire_shared_3peer):
    """Standard A→B(master)←C topology, returns the three peers settled."""
    local_client, master, remote = wire_shared_3peer

    master.start_tcp_server(
        network_name="",
        passphrase="",
        share_instance=True,
        share_instance_type="tcp",
    )
    remote.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=master.port,
    )
    local_client.start_local_client(
        shared_instance_port=master.shared_instance_port,
        instance_control_port=master.instance_control_port,
        rpc_key=master.rpc_key,
    )

    time.sleep(_SETTLE_SEC)
    return local_client, master, remote


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "announce", "poll_path"],
    verifies="A shared-instance local client's announce reaches a TCP-attached remote peer through the master (egress: LocalServerInterface → TCPInterface)",
)
def test_announce_local_to_remote(wire_shared_3peer):
    """Announce from local client A reaches the TCP remote C.

    A's LocalClientInterface is its only outbound interface, so the
    announce ALL goes through master B. B must:
      1. Receive the announce on its LocalServerInterface (from A).
      2. Re-broadcast it on its TCPInterface (to C).

    If step 2 is broken on the master, C never learns A's destination
    and `remote.poll_path(dest_hash)` times out. Fails for the same
    class of "shared-instance master fails to bridge local→remote
    traffic" symptoms as the link test, but at the simpler announce
    layer (no link-state to confuse the diagnosis).
    """
    local_client, master, remote = _bring_up_topology(wire_shared_3peer)

    dest_hash = local_client.announce(
        app_name=_APP_NAME, aspects=_ASPECTS
    )

    assert remote.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{remote.role_label} did not learn a path to "
        f"{local_client.role_label}'s destination {dest_hash.hex()} via "
        f"{master.role_label} within {_PATH_TIMEOUT_MS}ms. The master "
        f"didn't re-broadcast the announce it received on its "
        f"LocalServerInterface to its TCPInterface — local→remote "
        f"announce egress is broken."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "announce", "poll_path"],
    verifies="A TCP remote's announce reaches a shared-instance local client through the master (ingress: TCPInterface → LocalServerInterface with master-as-transport_id spoof)",
)
def test_announce_remote_to_local(wire_shared_3peer):
    """Announce from TCP remote C reaches local client A.

    Symmetric to the egress case. B must:
      1. Receive the announce on its TCPInterface (from C).
      2. Re-broadcast it to its LocalServerInterface clients (to A).

    Python additionally synthesizes the master's identity as the
    transport_id when forwarding to clients (Transport.py:1486 spoof
    comment), so clients see the dest as 1-hop via their
    LocalClientInterface. If this step is broken or omitted on the
    master, A's path table stays empty for C's destination and any
    follow-on discovery / link operation fails.
    """
    local_client, master, remote = _bring_up_topology(wire_shared_3peer)

    dest_hash = remote.announce(app_name=_APP_NAME, aspects=_ASPECTS)

    assert local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{local_client.role_label} did not learn a path to "
        f"{remote.role_label}'s destination {dest_hash.hex()} via "
        f"{master.role_label} within {_PATH_TIMEOUT_MS}ms. The master "
        f"didn't push the TCP-received announce down to its local-client "
        f"interfaces — remote→local announce ingress is broken."
    )
