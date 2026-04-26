"""Auto-proof conformance for opportunistic SINGLE-destination delivery.

Pins two wire-format invariants that the receiver-side auto-proof emission
MUST satisfy when an opportunistic DATA packet is delivered to a local
SINGLE destination. Both bugs were observed in reticulum-swift and fixed
in reticulum-swift PR #11 / commit 19fe812; this conformance coverage is
the cross-impl complement to the Swift unit tests added in 79edcb9.

Invariants under test
---------------------

A. Proof packet wire-format destination-type bits MUST be SINGLE (0b00).

   Python RNS constructs the proof destination as
       ProofDestination.type = RNS.Destination.SINGLE
   (Reticulum/RNS/Packet.py:393). The flag byte that the receiver of the
   proof unpacks is set from those bits.

   In the current Python and Swift PROOF inbound paths, the proof_hash
   in proof.data is what gates `pending_receipts` matching, NOT the
   destination-type bits — so the destinationType bug alone doesn't
   cause Python or Swift senders to drop the proof. But the moment any
   future RNS implementation strict-checks the destination-type field
   (or any IFAC validation hooks key off it), a `.plain` proof for a
   SINGLE-destination DATA packet becomes a silent interop break. This
   conformance test pins the bits independently of receipt-resolution
   behavior — exactly the kind of invariant a conformance suite exists
   to lock down.

   Pre-fix Swift code path: ReticulumTransport.handleRegularData
   constructed the proof header with `destinationType: .plain` while
   Python and Swift both author proofs with `.single` bits.

B. Proof bytes MUST be sent through the same applyIFAC pipeline that
   carries every other packet on an IFAC-configured interface.

   The receiver runs an IFAC-checking validator on every inbound frame
   on an IFAC-configured interface (Reticulum/RNS/Transport.py:1339-1379).
   A proof emitted via raw `interface.send(encoded)` (skipping
   applyIFAC) lacks the 16-byte IFAC tag and XOR mask, so the validator
   silently drops the frame. The sender's PacketReceipt times out and
   opportunistic-delivery confirmation breaks across every IFAC link.

   Pre-fix Swift code path: ReticulumTransport.handleRegularData called
   `iface.send(encoded)` directly instead of `sendToInterface(...)`.

Test design
-----------

Test A inspects the received proof packet's flag byte via the inbound
tap on the sender side (only available on the reference bridge — the
Swift bridge has no such tap, so the test parametrization restricts
the sender to reference and varies the receiver). The "swift receiver"
arm of this parametrization catches the destinationType bug directly.

Test B sends an opportunistic DATA packet over an IFAC-protected
interface and asserts the sender's PacketReceipt resolves DELIVERED
within a real wall-clock budget. A receipt only resolves DELIVERED when
the receiver's auto-proof is constructed and IFAC-applied correctly,
emitted on the right interface, and matches a pending receipt by
truncated hash. With the pre-fix Swift bridge as the receiver, Python's
IFAC validator drops the unwrapped proof and the receipt times out.

Parametrization reuses the existing 2-peer `wire_pair` fixture. The
homogeneous `[reference-to-reference]` arm is the sanity baseline (must
always pass — Python's auto-proof has been correct for years).

References
----------

- reticulum-swift fix:           commit 19fe812
- reticulum-swift unit tests:    Tests/ReticulumSwiftTests/AutoProofTests.swift
- Python proof emission:         Reticulum/RNS/Transport.py:2096
- Python proof construction:     Reticulum/RNS/Packet.py:380-396
- IFAC pipeline (Python):        Reticulum/RNS/Transport.py:1339-1379
"""

import secrets
import time

import pytest


# Settle budgets:
# - Announce learning: matches what the link-multihop tests use (1.5s
#   covers the 0.5s rebroadcast random window plus loopback latency).
# - Path-poll: 5s is enough for the announce + path entry to land.
# - Receipt wait: 5s is generous over loopback. Python's per-hop receipt
#   internal timeout is several seconds; we want our wait to be longer
#   than the proof RTT but shorter than the receipt's internal timeout
#   so a "no proof arrived" condition surfaces as a test-side timeout
#   rather than RNS marking the receipt CULLED first.
_SETTLE_SEC = 1.5
_PATH_POLL_TIMEOUT_MS = 5000
_RECEIPT_TIMEOUT_MS = 5000

_APP_NAME = "autoproofinterop"
_ASPECTS = ["test"]


# Wire-format constants (Packet.py flag byte, bits 3-2):
# - SINGLE = 0b00 → masked value 0x00
# - GROUP  = 0b01 → masked value 0x04
# - PLAIN  = 0b10 → masked value 0x08
# - LINK   = 0b11 → masked value 0x0c
_DEST_TYPE_MASK = 0b00001100
_DEST_TYPE_SINGLE = 0b00000000
_DEST_TYPE_PLAIN = 0b00001000

# Packet type bits (low 2 bits of flag byte):
# DATA=0, ANNOUNCE=1, LINKREQUEST=2, PROOF=3.
_PACKET_TYPE_MASK = 0b00000011
_PACKET_TYPE_PROOF = 0b00000011


def _xfail_kotlin_receiver(wire_pair, reason_suffix: str = ""):
    """Same xfail pattern as test_resource_multihop: known Kotlin
    receive-side gaps (link/inbound) are out of scope for THIS conformance
    point, and shipping a hard-failing test for them would obscure the
    Swift-receiver signal we're adding it for.

    If/when reticulum-kt grows symmetric SINGLE-DATA auto-proof, drop
    the xfail.
    """
    _server, _client = wire_pair
    receiver = _server  # mapping documented in _setup_two_peer_topology
    if receiver == "kotlin":
        pytest.xfail(
            f"reticulum-kt SINGLE auto-proof emission not yet covered by "
            f"this conformance point{reason_suffix}"
        )


def _setup_two_peer_topology(wire_peers, *, ifac: bool):
    """Bring up server (receiver) + client (sender) on loopback.

    Mirrors test_path_discovery's two-peer setup. With ifac=True both
    peers configure the same network_name + passphrase so the interface
    runs IFAC; the proof must round-trip the IFAC pipeline to be valid.

    Returns (sender, receiver, dest_hash) where dest_hash is the
    receiver's SINGLE destination registered via wire_listen with the
    auto-proof strategy enabled (Python receiver) or implied (Swift
    receiver auto-proves SINGLE DATA by default).
    """
    server, client = wire_peers
    sender = client      # the side issuing the opportunistic DATA
    receiver = server    # the side that must auto-emit the proof

    if ifac:
        netname = "autoprooftest"
        passphrase = secrets.token_hex(16)
    else:
        netname = ""
        passphrase = ""

    port = receiver.start_tcp_server(network_name=netname, passphrase=passphrase)
    sender.start_tcp_client(
        network_name=netname,
        passphrase=passphrase,
        target_host="127.0.0.1",
        target_port=port,
    )
    time.sleep(_SETTLE_SEC)

    # Listener registers a SINGLE destination AND announces it.
    # proof_strategy="all" only matters when the receiver bridge is the
    # Python reference (whose per-destination default is PROVE_NONE);
    # the Swift bridge auto-proves every SINGLE-destination DATA packet
    # unconditionally as part of handleRegularData (Sources/.../
    # ReticulumTransport.swift), so it ignores the param. That asymmetry
    # is the entire point of this conformance test — Swift's auto-prove
    # must produce a wire-correct, IFAC-applied proof or the sender's
    # PacketReceipt never resolves.
    dest_hash = receiver.listen(
        app_name=_APP_NAME, aspects=_ASPECTS, proof_strategy="all"
    )

    assert sender.poll_path(dest_hash, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{sender.role_label} did not learn a path to "
        f"{receiver.role_label}'s destination — the announce never crossed "
        f"the loopback link. Test would be moot regardless of proof handling."
    )

    return sender, receiver, dest_hash


def test_opportunistic_proof_destination_type(wire_pair, wire_peers):
    """Proof packet wire-format destination-type bits = SINGLE (0b00).

    Drives an opportunistic SINGLE DATA packet from sender to receiver,
    waits for the receiver's auto-proof to come back, and inspects the
    received proof's flag byte to assert destination-type bits = SINGLE.
    Pre-fix Swift wrote `.plain` (0b10) bits there.

    Parametrization restricted to `client == reference` because the
    inbound-tap observable (`wire_get_received_packets`) is only
    implemented on the Python bridge. The receiver side, where the
    bug-under-test lives, varies across `[*-to-reference]` and
    `[*-to-swift]` parametrizations. Skip when client is not reference.
    """
    server_impl, client_impl = wire_pair
    if client_impl != "reference":
        # Inbound-tap is only on the Python bridge today. For the
        # receiver-implementation matrix we care about, restricting
        # the sender to reference is sufficient: the proof emitter is
        # the receiver, which is what server_impl identifies, and that
        # parameterization fully covers `[*-to-swift]` and
        # `[*-to-reference]` arms.
        pytest.skip(
            "wire_get_received_packets is reference-only; this test pins a "
            "wire-bytes invariant via the sender-side tap, so it only runs "
            "with sender=reference. Receiver still varies across impls."
        )
    _xfail_kotlin_receiver(wire_pair)
    sender, _receiver, dest_hash = _setup_two_peer_topology(wire_peers, ifac=False)

    # Snapshot the sender-side tap's high-water-mark before send, so we
    # only inspect packets received *after* the DATA emission. This
    # avoids picking up the receiver's announce ANNOUNCE packet (which
    # also has destination-type bits but encodes a different invariant).
    pre = sender.bridge.execute("wire_get_received_packets", since_seq=0)
    base_seq = int(pre.get("highest_seq", 0))

    payload = b"opportunistic-proof-no-ifac"
    resp = sender.send_opportunistic(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        data=payload,
        timeout_ms=_RECEIPT_TIMEOUT_MS,
    )

    assert resp["sent"], (
        f"{sender.role_label}'s wire_send_opportunistic reported the packet "
        f"was never dispatched: {resp!r}. The bug under test is on the "
        f"receiver side; if the sender can't even emit the DATA packet, "
        f"the harness or path setup is broken."
    )
    # The receipt MAY OR MAY NOT resolve here, depending on whether the
    # destination-type-bit fix is in place. In current Python and Swift
    # PROOF handlers, the proof_hash gates receipt-match, not the
    # destination-type bits — so a malformed `.plain` proof can still
    # match a receipt and the receipt resolves DELIVERED. We don't
    # assert on `resp["delivered"]` here; the receipt fact is covered by
    # the IFAC test below. THIS test only pins the wire bits.

    # Pull the proof packet from the sender's tap. Filter to:
    #   1. seq > base_seq (post-emission)
    #   2. packet_type == PROOF (low 2 bits of byte 0 = 0b11)
    #   3. destination_hash equals truncated hash of the original packet
    #      (16 bytes; the proof's destination IS the original packet's
    #      truncated hash by construction — see Packet.ProofDestination)
    #
    # The truncated-hash filter is what disambiguates this proof from
    # any incidental announce-PROOF traffic. We don't have the original
    # packet hash directly, but the proof's destination_hash is the
    # only 16-byte field on a PROOF packet — so we look for any PROOF
    # whose dest hash isn't a known incidental hash and assert there's
    # exactly one. In practice on a 2-peer no-traffic loopback that's
    # the proof we sent.
    found = sender.bridge.execute(
        "wire_get_received_packets", since_seq=base_seq
    )
    proofs = [
        pkt for pkt in found.get("packets", [])
        if (pkt.get("packet_type") == _PACKET_TYPE_PROOF)
    ]
    assert len(proofs) >= 1, (
        f"{sender.role_label} expected at least one PROOF packet on the "
        f"inbound tap after sending opportunistic DATA, found "
        f"{len(proofs)}. Receiver did not emit a proof at all — either "
        f"its auto-proof pathway is disabled (Python without "
        f"proof_strategy='all'), or the listener never received the DATA "
        f"to trigger it. tap_state={found!r}"
    )

    # In the homogeneous reference-to-reference baseline the inbound
    # tap may also capture announce-PROOF traffic on first connect.
    # Filter further by the original destination's truncated hash to
    # isolate the proof of OUR DATA packet. By RNS spec the
    # ProofDestination.hash IS the original packet's full 16-byte
    # truncated hash, NOT the destination identity hash; we don't
    # know the truncated hash here so we accept any PROOF whose flag
    # byte we can extract.
    bad_bits = []
    good_bits = []
    for pkt in proofs:
        raw_hex = pkt.get("raw_hex", "")
        if not raw_hex or len(raw_hex) < 2:
            continue
        flag_byte = int(raw_hex[:2], 16)
        dest_type_bits = flag_byte & _DEST_TYPE_MASK
        if dest_type_bits == _DEST_TYPE_SINGLE:
            good_bits.append(pkt)
        else:
            bad_bits.append((pkt, dest_type_bits, flag_byte))

    # We assert that EVERY proof received carries SINGLE bits. Pre-fix
    # Swift would emit at least one with PLAIN bits, which surfaces here.
    assert not bad_bits, (
        f"{sender.role_label} received {len(bad_bits)} PROOF packet(s) "
        f"with wrong destination-type bits. Expected SINGLE (0b00 in "
        f"bits 3-2 of flag byte 0). Got:\n"
        + "\n".join(
            f"  flag_byte=0x{flag:02x} dest_type_bits=0b{bits:08b} "
            f"raw[:8]={pkt.get('raw_hex', '')[:16]}"
            for pkt, bits, flag in bad_bits
        )
        + f"\n\nThis is the reticulum-swift PR #11 destination-type bug if "
        f"the receiver is Swift: handleRegularData built the proof header "
        f"with `destinationType: .plain` instead of `.single`. The fix "
        f"changes `.plain` to `.single` so the wire bits match what every "
        f"other RNS impl emits for ProofDestination."
    )
    # Also require we actually inspected at least one proof — without
    # the affirmative case the assertion above is vacuously true.
    assert good_bits, (
        f"{sender.role_label} found no PROOF packets with extractable "
        f"flag bytes; tap returned empty raw_hex strings? "
        f"raw_proofs={proofs!r}"
    )


def test_opportunistic_proof_through_ifac(wire_pair, wire_peers):
    """Proof packet round-trips correctly on an IFAC-configured interface.

    Pre-fix Swift bypassed applyIFAC for the auto-proof, so on any
    network_name + passphrase interface the proof bytes lacked the
    16-byte IFAC tag and XOR mask. Receivers (especially Python with its
    strict IFAC validator at Transport.py:1339-1379) silently dropped
    the unwrapped proof and the sender's PacketReceipt timed out.

    Parametrization restricted to `client == reference` because
    wire_send_opportunistic is only implemented on the Python bridge
    today — adding it to other bridges is a separate piece of work
    (would land in those bridges' repos, not the conformance suite).
    The receiver side, where the bug-under-test lives, varies across
    `[*-to-reference]` and `[*-to-swift]` parametrizations. The
    `[swift-to-reference]` arm is the diagnostic case: Python sender
    against a Swift receiver — pre-fix Swift returns an unwrapped
    proof, Python's IFAC validator silently drops it, the receipt
    times out.

    Expectation: PacketReceipt resolves DELIVERED in every running
    parametrization. The IFAC tag-and-mask pipeline applies
    symmetrically to inbound DATA and outbound PROOF.
    """
    server_impl, client_impl = wire_pair
    if client_impl != "reference":
        pytest.skip(
            "wire_send_opportunistic is reference-only; receiver-side "
            "auto-proof emission is what's under test, so pinning sender "
            "to reference fully covers `[*-to-reference]` and `[*-to-swift]` "
            "arms (receiver impl varies)."
        )
    _xfail_kotlin_receiver(wire_pair, " (IFAC variant)")
    sender, _receiver, dest_hash = _setup_two_peer_topology(wire_peers, ifac=True)

    payload = b"opportunistic-proof-with-ifac"
    resp = sender.send_opportunistic(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        data=payload,
        timeout_ms=_RECEIPT_TIMEOUT_MS,
    )

    assert resp["sent"], (
        f"{sender.role_label}'s wire_send_opportunistic reported the packet "
        f"was never dispatched on the IFAC link: {resp!r}. If the non-IFAC "
        f"variant passes but this assertion fails, the bug is in IFAC-path "
        f"send setup, not the proof handling under test."
    )
    assert resp["delivered"], (
        f"{sender.role_label} sent an opportunistic DATA packet over the "
        f"IFAC-protected link to {dest_hash.hex()[:16]}... but its "
        f"PacketReceipt did not resolve DELIVERED within "
        f"{_RECEIPT_TIMEOUT_MS}ms (status={resp['status']!r}). Most likely "
        f"cause: receiver's auto-proof skipped the applyIFAC pipeline, so "
        f"the sender's IFAC validator dropped the proof before it could "
        f"reach pending_receipts. This is the reticulum-swift PR #11 IFAC "
        f"bug if the receiver is Swift: handleRegularData called "
        f"`iface.send(encoded)` directly instead of `sendToInterface(...)`, "
        f"bypassing applyIFAC."
    )
