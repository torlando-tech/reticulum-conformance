"""Link establishment through a shared-instance master.

Topology:

    local_client (A) ── shared instance (loopback) ──▶ master (B, SUT)
                                                         │
                                                         │  TCP loopback
                                                         ▼
                                                    remote (C, hosts D)

A opens a Link to a destination D announced by C. The LINKREQUEST goes
A → [LocalServerInterface @ B] → [TCP @ B] → C. C responds with an LRPROOF
that travels C → [TCP @ B] → [LocalClientInterface @ A].

What this catches that the existing TCP-only multi-hop tests miss
--------------------------------------------------------------------
`test_link_multihop.py` already runs link establishment through a
parametrized transport relay, but the relay there receives the LINKREQUEST
on a TCPInterface — not a LocalServerInterface. reticulum-kt's transport
has a special H1→H2 synthesis path in `Transport.kt::processInbound`
guarded by `fromLocalClient && !forLocalClient && transportId == null`
(see Transport.kt:2768-2794) that only fires when the inbound packet
arrives via a local-client interface. That synthesis path mutates
`packet.raw` in place to insert the master's identity as transport_id
while leaving the cached `Packet.headerType` field stale at HEADER_1.
Subsequent `linkIdFromLrPacket(packet) → getHashablePart()` then slices
the modified raw using the H1 layout, accidentally including the freshly
inserted transport_id in the hash input and producing a link_id that
diverges from what the originator (A) and the destination host (C) saw.
The LRPROOF on the way back lands in the master's link_table under a
different key and is silently dropped — A times out.

Python doesn't deviate this way: `Transport.py:1488-1489` only sets
`packet.transport_id` (the field), never mutates `packet.raw`, so its
get_hashable_part() stays consistent with what the originator hashed.

Per-impl expectation
--------------------
- master_impl=reference: must pass (this is the upstream-conformant path).
- master_impl=kotlin:    currently fails until the H1→H2 synthesis stops
  desynchronizing packet.raw and Packet.headerType.
"""

import time

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "shared_master_link"
_ASPECTS = ["test"]

# Generous timeouts: shared-instance attach + TCP connect + announce
# propagation + path discovery + RTT-probe-laden link establishment.
_SETTLE_SEC = 1.5
_LINK_TIMEOUT_MS = 20000
_PATH_TIMEOUT_MS = 10000


def _setup_shared_master_topology(wire_shared_3peer):
    """Wire up the standard topology and return
    (local_client, master, remote, dest_hash).

    Order of operations matters and is documented inline; tests can call
    this and then proceed to `local_client.link_open(...)` without
    re-deriving it.
    """
    local_client, master, remote = wire_shared_3peer

    # 1. Master comes up first: TCP server for `remote` plus a shared-instance
    #    listener for `local_client`. share_instance_type="tcp" forces a
    #    TCP-loopback shared instance (default Python AF_UNIX would not
    #    interoperate with reticulum-kt's TCP-only LocalClientInterface).
    master.start_tcp_server(
        network_name="",
        passphrase="",
        share_instance=True,
        share_instance_type="tcp",
    )
    assert master.port is not None
    assert master.shared_instance_port is not None, (
        f"{master.role_label} returned no shared_instance_port from "
        f"start_tcp_server(share_instance=True). The bridge must surface "
        f"the LocalServerInterface's loopback port for this fixture to "
        f"chain a local-client peer onto it."
    )

    # 2. Remote attaches over TCP. `enable_transport=True` is implicit on
    #    both ends in the wire bridges.
    remote.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=master.port,
    )

    # 3. Local-client attaches AFTER the master is up, otherwise Python's
    #    auto-detect path would have it become its own master. Plumb the
    #    master's RPC control port and rpc_key through so the client's
    #    first _used_destination_data RPC (fired during link setup) can
    #    actually authenticate against the master's listener.
    local_client.start_local_client(
        shared_instance_port=master.shared_instance_port,
        instance_control_port=master.instance_control_port,
        rpc_key=master.rpc_key,
    )

    # Settle: shared-instance clients spawn after a brief connect+handshake
    # period. Without this gap, the next announce-related step can race
    # the master's first read from the LocalServerInterface accept thread.
    time.sleep(_SETTLE_SEC)

    # 4. Remote announces its destination D. The announce traverses
    #    C → [TCP] → B → [LocalServerInterface] → A. A's path table now
    #    has a route to D via its LocalClientInterface.
    dest_hash = remote.listen(app_name=_APP_NAME, aspects=_ASPECTS)
    remote.announce(app_name=_APP_NAME, aspects=_ASPECTS)

    # Wait for A to learn the path before we ask it to open a link. If
    # this poll fails, the topology hasn't converged and the link test
    # below would be misdiagnosed as a transport-mode bug when in fact
    # the announce never propagated.
    assert local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{local_client.role_label} did not learn a path to "
        f"{remote.role_label}'s destination via {master.role_label}. "
        f"The shared-instance topology didn't converge — later assertions "
        f"would be uninterpretable."
    )

    return local_client, master, remote, dest_hash


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "listen", "announce", "poll_path", "link_open"],
    verifies="A Link from a shared-instance local client to a TCP-attached destination establishes successfully via the master — catches the H1→H2 synthesis link_id-desynchronization bug",
)
def test_link_establishes_via_shared_master(wire_shared_3peer):
    """A.link_open(D_on_C) must succeed within a reasonable timeout.

    If the master miscomputes link_id when forwarding the LINKREQUEST
    out via TCP, the LRPROOF coming back from C lands on a key that
    isn't in the master's link_table and gets dropped. The originator's
    link_open then times out.

    Historical context: this test was originally introduced xfail(strict)
    on the kotlin-master parametrize variant to catch a two-bug stack —
    (1) manually-constructed LocalClientInterface registrations didn't
    flip Transport.isConnectedToSharedInstance, so kotlin clients sent
    HEADER_1 outbound where python clients send HEADER_2; (2) the
    master's H1→H2 compensation mutated packet.raw in place while leaving
    Packet.headerType (a `val`) stale, breaking getHashablePart() and
    producing a divergent link_id. Both bugs were fixed in reticulum-kt
    by widening the global flag at registerInterface time and deleting
    the master-side mutation block. See reticulum-kt's port-deviations.md
    entries dated 2026-05-10 for the full trail.
    """
    local_client, master, _remote, dest_hash = _setup_shared_master_topology(
        wire_shared_3peer
    )

    link_id = local_client.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )

    assert link_id and len(link_id) == 16, (
        f"{local_client.role_label} attempted to open a link to a "
        f"destination behind {master.role_label}'s TCP interface, but the "
        f"link_id returned was unexpected: {link_id!r}. "
        f"Expected behavior: link_open returns a 16-byte link_id within "
        f"{_LINK_TIMEOUT_MS}ms. Most likely failure is a timeout — see the "
        f"docstring at the top of this file for what that diagnoses."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "transport_enabled", "listen", "announce", "poll_path", "link_open"],
    verifies="R3: with the shared master's transport DISABLED, a local client still opens a Link to a TCP-hosted destination — local-client LINKREQUEST forwarding and LRPROOF return bypass the transport_enabled gate (Transport.py:1536/:2172)",
)
def test_link_establishes_with_transport_off(wire_shared_3peer):
    """R3 link half (CONFORMANCE_GAPS.md §3): the transport-off bypass must
    carry a full Link establishment, not just an announce.

    rnsd defaults to transport OFF. With the shared master transport-
    disabled, A must still be able to (1) learn C's destination via the
    master's unconditional fan-out of received announces to local clients,
    and (2) open a Link to it: the outbound LINKREQUEST is forwarded out
    TCP because general transport handling runs when `from_local_client`
    (Transport.py:1536), and the returning LRPROOF is forwarded back to A
    because `for_local_client_link` holds (Transport.py:2172). An impl that
    gates either step on transport_enabled black-holes the link and
    link_open times out.

    Ground truth: we pin the master's transport_enabled() is False so a
    master that silently kept transport on cannot pass vacuously.
    """
    local_client, master, remote = wire_shared_3peer

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

    posture = master.transport_enabled()
    assert posture["transport_enabled"] is False, (
        f"{master.role_label} reports transport_enabled="
        f"{posture['transport_enabled']}; this R3 link test requires it OFF "
        f"so that only the local-client forwarding bypass can carry the "
        f"LINKREQUEST/LRPROOF. Posture: {posture}."
    )

    # C hosts and announces D_c; the master fans the announce to A
    # unconditionally (independent of transport_enabled), so A learns it.
    dest_hash = remote.listen(app_name=_APP_NAME, aspects=_ASPECTS)
    remote.announce(app_name=_APP_NAME, aspects=_ASPECTS)
    assert local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{local_client.role_label} did not learn a path to "
        f"{remote.role_label}'s destination {dest_hash.hex()} through the "
        f"transport-off master within {_PATH_TIMEOUT_MS}ms — the precondition "
        f"for the link test did not converge."
    )

    link_id = local_client.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    assert link_id and len(link_id) == 16, (
        f"{local_client.role_label} could not open a link to {dest_hash.hex()} "
        f"behind the transport-OFF master; link_id={link_id!r}. With "
        f"transport off, the LINKREQUEST is forwarded out TCP only via the "
        f"from_local_client bypass (Transport.py:1536) and the LRPROOF "
        f"returns only via for_local_client_link (Transport.py:2172). A "
        f"timeout here means the impl gates one of those on transport_enabled."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "start_local_client", "listen", "announce", "poll_path", "set_proof_strategy", "send_packet", "packet_receipt_status"],
    verifies="proof_for_local_client: a single SINGLE-destination Packet sent by a shared-instance local client to a TCP-hosted destination reaches DELIVERED — the returning PROOF is routed back to the local client via the master's reverse_table (Transport.py:2254-2261), a path distinct from the LRPROOF/link_table path",
)
def test_single_packet_proof_returns_to_local_client(wire_shared_3peer):
    """The PacketReceipt/reverse_table proof return path through a shared
    master (CONFORMANCE_GAPS.md §3 proof_for_local_client).

    The existing link test exercises the LRPROOF/link_table path; this one
    exercises the OTHER proof-routing table. A local client sends a single
    SINGLE-destination DATA Packet (with a tracked PacketReceipt) to a
    destination hosted on the TCP remote C. The master records a
    reverse_table entry whose received-interface is A's local-client
    interface. C (proof strategy PROVE_ALL) returns a PROOF; the master
    pops the reverse entry and, because `proof_for_local_client` holds
    (Transport.py:2254-2261), transports the PROOF back down to A even
    though A looks 0-hop. The receipt on A must reach DELIVERED.

    Discriminating: an impl that doesn't route proofs back via reverse_table
    to local clients leaves the receipt stuck at SENT (never DELIVERED).
    """
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

    # C hosts D_c and proves every received packet, then announces so A can
    # learn the identity needed to address a single packet to it.
    dest_hash = remote.listen(app_name=_APP_NAME, aspects=_ASPECTS)
    remote.set_proof_strategy(dest_hash, "all")
    remote.announce(app_name=_APP_NAME, aspects=_ASPECTS)
    assert local_client.poll_path(dest_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{local_client.role_label} did not learn a path to "
        f"{remote.role_label}'s destination {dest_hash.hex()} — cannot send "
        f"a single packet without a known identity/path."
    )

    sent = local_client.send_packet(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        data=b"proof-return-probe",
        create_receipt=True,
    )
    assert sent["sent"] is True and sent["receipt_id"], (
        f"{local_client.role_label} could not send the single packet to "
        f"{dest_hash.hex()} (resp={sent}); the proof-return path can't be "
        f"observed without a tracked receipt."
    )

    status = local_client.packet_receipt_status(
        sent["receipt_id"], timeout_ms=_LINK_TIMEOUT_MS
    )
    assert status["delivered"] is True, (
        f"{local_client.role_label}'s PacketReceipt for the single packet to "
        f"{dest_hash.hex()} ended at status={status.get('status_name')} "
        f"(delivered={status.get('delivered')}, proved={status.get('proved')}), "
        f"expected DELIVERED. C's PROOF did not make it back to the local "
        f"client — the master failed to route the proof via reverse_table "
        f"(proof_for_local_client, Transport.py:2254-2261)."
    )
