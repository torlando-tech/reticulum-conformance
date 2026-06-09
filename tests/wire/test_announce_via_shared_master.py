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
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "announce", "poll_path", "read_path_entry"],
    verifies="A shared-instance local client's announce reaches a TCP-attached remote peer through the master (egress: LocalServerInterface → TCPInterface), and the master stores the local-client destination at hops==0 (R1 net-zero hop decrement / R2 for_local_client sentinel)",
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

    R1+R2 (CONFORMANCE_GAPS.md §3): the master must store A's destination
    in its path_table at hops==0. RNS increments hops on inbound
    (Transport.py:1455) then decrements again because the receiving
    interface IS a local-client interface (Transport.py:1479-1480), netting
    zero — so an app behind the shared instance looks master-originated
    (the for_local_client hops==0 sentinel, Transport.py:1511/:2011). An
    impl that omits the local-client decrement would store hops==1.
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

    # R1/R2: the master's own path_table entry for the local-client
    # destination must be at hops==0 (the local app looks master-
    # originated). This is the highest-leverage cheapest shared-instance
    # assertion — it needs no harness change beyond read_path_entry.
    master_entry = master.read_path_entry(dest_hash)
    assert master_entry is not None, (
        f"{master.role_label} has no path_table entry for "
        f"{local_client.role_label}'s destination {dest_hash.hex()} even "
        f"though {remote.role_label} learned it — the master must store the "
        f"local-client destination it forwarded."
    )
    assert master_entry["hops"] == 0, (
        f"{master.role_label} stored {local_client.role_label}'s local "
        f"destination {dest_hash.hex()} at hops=={master_entry['hops']}, "
        f"expected hops==0. RNS increments hops on inbound then decrements "
        f"again on a local-client interface (Transport.py:1479-1480), so a "
        f"destination hosted by an attached local client must look "
        f"0-hop/master-originated (the for_local_client sentinel, "
        f"Transport.py:1511/:2011). hops==1 means the local-client hop "
        f"decrement was omitted."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "announce", "poll_path", "read_path_entry"],
    verifies="A TCP remote's announce reaches a shared-instance local client through the master (ingress: TCPInterface → LocalServerInterface), and the client stores the remote destination at hops==1 with next_hop==master.identity_hash (R4/R5 master-as-transport_id rewrite, R9 client-side hop decrement)",
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

    R4/R5/R9 (CONFORMANCE_GAPS.md §3): the master rewrites the forwarded
    announce to HEADER_2/TRANSPORT with its OWN identity as transport_id
    (Transport.py:1933-1976), so the client's path_table entry must record
    next_hop == master.identity_hash. And because the client receives over
    an interface-to-shared-instance, it increments hops on inbound then
    decrements again (Transport.py:1455 then :1482), so the stored value is
    hops==1 (master 1 hop away). An impl that omits the master-as-
    transport_id rewrite records the wrong next_hop; one that omits the
    client-side decrement stores hops==2.
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

    # R4/R5/R9: the client's path entry must point its next_hop at the
    # master (the master inserts itself as transport_id when forwarding to
    # local clients) and record exactly 1 hop.
    client_entry = local_client.read_path_entry(dest_hash)
    assert client_entry is not None, (
        f"{local_client.role_label} polled a path to {dest_hash.hex()} but "
        f"read_path_entry returned None — inconsistent path_table state."
    )
    assert client_entry["next_hop"] == master.identity_hash.hex(), (
        f"{local_client.role_label}'s path entry for {dest_hash.hex()} has "
        f"next_hop={client_entry['next_hop']}, expected the master's "
        f"identity hash {master.identity_hash.hex()}. The master must "
        f"rewrite the forwarded announce to HEADER_2/TRANSPORT inserting "
        f"its own identity as transport_id (Transport.py:1933-1976) so the "
        f"client routes return traffic back through it."
    )
    assert client_entry["hops"] == 1, (
        f"{local_client.role_label}'s path entry for {dest_hash.hex()} has "
        f"hops=={client_entry['hops']}, expected hops==1. The client "
        f"increments hops on inbound then decrements once for the "
        f"interface-to-shared-instance (Transport.py:1455/:1482); a stored "
        f"hops==2 means the client-side decrement was omitted (R9)."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "transport_enabled", "announce", "poll_path"],
    verifies="R3: with the shared master's transport DISABLED, a local client's announce still reaches a TCP-attached remote — local-client announce forwarding bypasses the transport_enabled gate (Transport.py:1884)",
)
def test_announce_egress_with_transport_off(wire_shared_3peer):
    """The single most discriminating local-client rule (CONFORMANCE_GAPS.md
    §3 R3): local-client forwarding BYPASSES Reticulum.transport_enabled().

    rnsd's default posture is transport OFF. A shared-instance master with
    transport off must STILL forward an attached local client's announce
    out to a TCP peer, because the announce-table insertion gate is
    `(transport_enabled() or is_from_local_client)` (Transport.py:1884) —
    the `is_from_local_client` disjunct keeps it flowing. An implementation
    that gates local-client forwarding on transport_enabled black-holes the
    announce, so C never learns A's destination.

    Ground truth first: we pin `master.transport_enabled()` is actually
    False, so a master that silently left transport ON can't pass this
    vacuously. Then the discriminating assertion: A's announce reaches C.
    """
    local_client, master, remote = wire_shared_3peer

    # Master with transport DISABLED but still a shared instance.
    master.start_tcp_server(
        network_name="",
        passphrase="",
        share_instance=True,
        share_instance_type="tcp",
        enable_transport=False,
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

    # Ground truth: the master must really have transport off, else the
    # bypass isn't what's being exercised.
    posture = master.transport_enabled()
    assert posture["transport_enabled"] is False, (
        f"{master.role_label} reports transport_enabled="
        f"{posture['transport_enabled']}; this R3 test requires it OFF so "
        f"that only the local-client forwarding bypass can carry the "
        f"announce. Posture: {posture}."
    )
    assert posture["is_shared_instance"] is True, (
        f"{master.role_label} is not a shared instance ({posture}); the "
        f"local-client bypass under test only applies to a shared master."
    )

    dest_hash = local_client.announce(app_name=_APP_NAME, aspects=_ASPECTS)

    assert remote.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{remote.role_label} did not learn a path to "
        f"{local_client.role_label}'s destination {dest_hash.hex()} within "
        f"{_PATH_TIMEOUT_MS}ms, even though the master is a shared instance. "
        f"With transport OFF the announce only reaches C via the "
        f"is_from_local_client bypass of the announce-table gate "
        f"(Transport.py:1884). A black-holed announce here means the impl "
        f"wrongly gates local-client forwarding on transport_enabled."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "listen", "announce", "read_path_entry", "request_path", "poll_path"],
    verifies="R6/R10: a path request issued by a shared-instance local client for a TCP-hosted destination it does NOT yet know resolves through the master (the master answers the local client's PR), with a verified before=unknown precondition",
)
def test_local_client_path_request_resolves_remote_dest(wire_shared_3peer):
    """A local client's `request_path` for a destination it has not yet
    learned must resolve through the shared master (CONFORMANCE_GAPS.md §3
    R6/R10 — local-client path discovery).

    To make the path-request mechanism the ONLY way A can learn the route
    (not a passively-received announce), C announces D_c BEFORE A attaches
    to the master. The reference master does not replay its path_table to a
    newly-attached local client, so A starts with no path to D_c — verified
    as a precondition. A then issues `request_path(D_c)`; the master, which
    cached D_c's announce, answers the local client's path request
    (Transport.py path_request `is_from_local_client` handling), and A
    resolves. An impl that drops path requests at the local-client boundary
    leaves A unresolved.
    """
    local_client, master, remote = wire_shared_3peer

    master.start_tcp_server(
        network_name="",
        passphrase="",
        share_instance=True,
        share_instance_type="tcp",
    )
    # C attaches and announces D_c FIRST, while A is not yet a client.
    remote.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=master.port,
    )
    time.sleep(0.5)
    dest_hash = remote.listen(app_name=_APP_NAME, aspects=_ASPECTS)
    remote.announce(app_name=_APP_NAME, aspects=_ASPECTS)
    # Let the announce reach + be cached by the master before A joins.
    time.sleep(_SETTLE_SEC)

    # A joins LATE — it misses C's announce entirely.
    local_client.start_local_client(
        shared_instance_port=master.shared_instance_port,
        instance_control_port=master.instance_control_port,
        rpc_key=master.rpc_key,
    )
    time.sleep(_SETTLE_SEC)

    # Precondition: A genuinely has no path yet (the master did not replay
    # the cached announce on attach). If this ever fails, the topology is
    # leaking announces and the resolve-after-request assertion below would
    # be vacuous — so we assert it rather than silently rely on it.
    assert local_client.read_path_entry(dest_hash) is None, (
        f"{local_client.role_label} already has a path to {dest_hash.hex()} "
        f"before issuing request_path — the master replayed a cached "
        f"announce on attach, which would make the path-discovery assertion "
        f"vacuous. Re-examine the attach ordering."
    )

    local_client.request_path(dest_hash)

    assert local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{local_client.role_label} did not learn a path to "
        f"{remote.role_label}'s destination {dest_hash.hex()} within "
        f"{_PATH_TIMEOUT_MS}ms of calling request_path through "
        f"{master.role_label}. The master failed to answer the local "
        f"client's path request — local-client path discovery (R6/R10) is "
        f"broken."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "listen", "announce", "read_path_entry", "request_path", "poll_path"],
    verifies="R7/R10: a path request from a TCP remote for a destination hosted by a shared-instance local client resolves — the master fans the PR to its local clients and the local client's PATH_RESPONSE returns to the remote, with a verified before=unknown precondition",
)
def test_remote_path_request_resolves_local_client_dest(wire_shared_3peer):
    """A TCP remote's `request_path` for a destination hosted behind the
    shared master (on a local client) must resolve (CONFORMANCE_GAPS.md §3
    R7/R10 — the master fans path requests to/from local clients).

    Mirror of the previous test. A (local client) announces D_a BEFORE C
    attaches, so when C joins it has no path to D_a (the master does not
    push cached announces to a newly-attached TCP peer) — verified as a
    precondition. C then issues `request_path(D_a)`; the master, whose
    cached path for D_a points at a local-client interface, fans the
    request to A and answers C, so C resolves. An impl that does not route
    path requests across the local-client boundary leaves C unresolved.
    """
    local_client, master, remote = wire_shared_3peer

    master.start_tcp_server(
        network_name="",
        passphrase="",
        share_instance=True,
        share_instance_type="tcp",
    )
    # A attaches and announces D_a FIRST, while C is not yet connected.
    local_client.start_local_client(
        shared_instance_port=master.shared_instance_port,
        instance_control_port=master.instance_control_port,
        rpc_key=master.rpc_key,
    )
    time.sleep(0.5)
    dest_hash = local_client.listen(app_name=_APP_NAME, aspects=_ASPECTS)
    local_client.announce(app_name=_APP_NAME, aspects=_ASPECTS)
    time.sleep(_SETTLE_SEC)

    # C joins LATE — it misses A's announce.
    remote.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=master.port,
    )
    time.sleep(_SETTLE_SEC)

    # Precondition: C genuinely lacks the path before requesting it.
    assert remote.read_path_entry(dest_hash) is None, (
        f"{remote.role_label} already has a path to {dest_hash.hex()} "
        f"before issuing request_path — the master pushed a cached announce "
        f"on connect, which would make the assertion below vacuous."
    )

    remote.request_path(dest_hash)

    assert remote.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{remote.role_label} did not learn a path to "
        f"{local_client.role_label}'s destination {dest_hash.hex()} within "
        f"{_PATH_TIMEOUT_MS}ms of calling request_path. The master failed to "
        f"fan the path request to its local clients and relay the "
        f"PATH_RESPONSE back (R7/R10) — cross-boundary path discovery is "
        f"broken."
    )
