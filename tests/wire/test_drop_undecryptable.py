"""Negative-path conformance: undecryptable packets MUST be dropped.

The rest of the opportunistic-delivery coverage is positive-only — it
sends a *valid* packet and proves the receiver dispatches it and proves
it. That can't distinguish a correct receiver from a broken one that
fires its callback and emits a proof for *anything* it receives. This
file closes that gap (CONFORMANCE_AUDIT "positive-only verifiers"): it
sends a packet the receiver cannot decrypt and pins both halves of the
drop invariant.

Invariant under test
--------------------

When a SINGLE-destination DATA packet arrives whose ciphertext does not
decrypt under the destination's identity, the receiver MUST:

  A. NOT fire the destination's packet callback, and
  B. NOT emit a delivery proof.

In Python RNS both fall out of one branch: `Destination.receive` calls
`self.decrypt(packet.data)`, gets `None`, and returns `False`
(Reticulum/RNS/Destination.py:418-429). That `False` short-circuits the
caller in `Transport.inbound` *before* the PROVE_ALL auto-proof block
(Reticulum/RNS/Transport.py:1996-2001) — so a correct impl proves
nothing and dispatches nothing. A buggy impl that proves/dispatches
pre-decrypt would fail here.

Test design (differential)
--------------------------

A bare "the corrupted packet didn't deliver" assertion is dangerously
vacuous — it would also pass if the path never converged, the address
were wrong, or the packet were never sent. So each test first runs a
POSITIVE CONTROL over the same sender/destination/path: a valid packet
that MUST deliver and MUST surface on the receiver's opportunistic
buffer. Only then does it send the corrupted packet and assert the
opposite. Same everything but the ciphertext; if both behave the same,
the test fails.

Parametrization reuses the 2-peer `wire_pair` fixture. It is restricted
to `client == reference` because `wire_send_opportunistic` /
`wire_send_undecryptable` are reference-only today; the receiver side —
where the drop decision is actually made — varies across `[*-to-*]`
arms. The homogeneous `[reference-to-reference]` arm is the sanity
baseline.

Two drop layers
---------------

The test parametrizes over two ways to make the packet undecryptable,
which exercise drops at *different* layers:

  "ciphertext" — a structurally valid DATA packet whose Token HMAC byte
    is flipped. It routes normally, reaches Transport.inbound, and is
    dropped at `Destination.receive` when decrypt returns None. This is
    the canonical "undecryptable" case.
  "truncate"   — the ciphertext is stripped, leaving a header-only frame.
    It is rejected at the interface deframing / parse layer *before*
    Transport.inbound is reached, so it never makes it to the decrypt
    step. A coarser malformed-input drop, but the no-proof / no-callback
    invariant must still hold.

For a reference receiver with the "ciphertext" corruption we additionally
assert, via the inbound tap, that the corrupted DATA packet really did
reach the receiver's Transport — making "no callback / no proof" mean
"received and dropped at decrypt" rather than "never arrived". That
arrival check is skipped for "truncate", which is dropped before the tap
point; its non-vacuity rests on the positive control plus the `sent`
confirmation instead.
"""

import secrets
import time

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


# Settle/timeout budgets mirror test_opportunistic_proof. The negative
# assertion waits out a receipt timeout, so keep it modest — a conformant
# receiver never proves, and a buggy one proves fast, so a short wait is
# enough to tell them apart without dragging the suite.
_SETTLE_SEC = 1.5
_PATH_POLL_TIMEOUT_MS = 5000
_GOOD_RECEIPT_TIMEOUT_MS = 5000
_DROP_RECEIPT_TIMEOUT_MS = 2500
_POLL_TIMEOUT_MS = 1500

_APP_NAME = "dropundecryptable"
_ASPECTS = ["test"]

# Packet type bits (low 2 bits of flag byte): DATA=0. The inbound tap
# already stores packet_type pre-masked, so we compare against this value.
_PACKET_TYPE_DATA = 0b00000000


def _xfail_kotlin_receiver(wire_pair):
    """Kotlin's receive-side opportunistic-DATA path isn't covered by this
    conformance point yet (same carve-out as test_opportunistic_proof /
    test_resource_multihop). Shipping a hard failure for it would bury the
    reference/swift signal this test exists for.
    """
    server, _client = wire_pair  # server == receiver (see _setup)
    if server == "kotlin":
        pytest.xfail(
            "reticulum-kt opportunistic receive-side drop behaviour not yet "
            "covered by this conformance point"
        )


def _setup_two_peer_topology(wire_peers):
    """Bring up server (receiver) + client (sender) on loopback, no IFAC.

    Returns (sender, receiver, dest_hash). The receiver registers a SINGLE
    destination with proof_strategy="all" so that a *valid* packet WOULD
    be proven — which is exactly what makes the negative case meaningful:
    the receiver is configured to prove everything it can decrypt, so a
    missing proof can only mean the decrypt failed and the packet was
    dropped.
    """
    server, client = wire_peers
    sender = client
    receiver = server

    port = receiver.start_tcp_server(network_name="", passphrase="")
    sender.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=port,
    )
    time.sleep(_SETTLE_SEC)

    dest_hash = receiver.listen(
        app_name=_APP_NAME, aspects=_ASPECTS, proof_strategy="all"
    )

    assert sender.poll_path(dest_hash, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{sender.role_label} did not learn a path to "
        f"{receiver.role_label}'s destination — the announce never crossed "
        f"the loopback link. The drop assertion would be vacuous."
    )
    return sender, receiver, dest_hash


def _skip_if_sender_not_reference(client_impl):
    if client_impl != "reference":
        pytest.skip(
            "wire_send_undecryptable / wire_send_opportunistic are "
            "reference-only; the drop decision under test is on the "
            "receiver, so pinning sender=reference fully covers the "
            "[*-to-reference] and [*-to-swift] receiver arms."
        )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "send_opportunistic", "opportunistic_poll", "get_received_packets",
        "send_undecryptable",
    ],
    verifies=(
        "A SINGLE-destination opportunistic DATA packet whose ciphertext does "
        "not decrypt MUST be dropped: the receiver fires no packet callback "
        "(opportunistic buffer stays empty) and emits no delivery proof (the "
        "sender's PacketReceipt never resolves DELIVERED), because "
        "Destination.receive returns False on the decrypt failure and "
        "short-circuits the PROVE_ALL auto-proof. Each corruption mode "
        "(HMAC-byte flip dropped at decrypt, ciphertext-strip dropped at parse) "
        "is gated by a valid positive control that MUST deliver and surface, so "
        "the drop assertion is non-vacuous"
    ),
)
@pytest.mark.parametrize("corruption", ["ciphertext", "truncate"])
def test_undecryptable_opportunistic_is_dropped(wire_pair, wire_peers, corruption):
    """Undecryptable opportunistic DATA: no proof returns, no callback fires.

    Runs a positive control (valid packet delivers + surfaces) then the
    negative assertion (corrupted packet does neither) over the same
    sender/destination/path. Parametrized over two ways to make the
    packet undecryptable (corrupt the HMAC vs strip the ciphertext).
    """
    _server_impl, client_impl = wire_pair
    _skip_if_sender_not_reference(client_impl)
    _xfail_kotlin_receiver(wire_pair)

    sender, receiver, dest_hash = _setup_two_peer_topology(wire_peers)
    receiver_is_reference = (_server_impl == "reference")

    # ---- Positive control: a VALID packet must deliver AND be dispatched.
    # Without this, the negative assertion below could pass for the wrong
    # reason (path never converged, wrong address, send no-op'd).
    good_payload = b"valid-control-" + secrets.token_hex(4).encode()
    good = sender.send_opportunistic(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        data=good_payload,
        timeout_ms=_GOOD_RECEIPT_TIMEOUT_MS,
    )
    assert good["sent"], (
        f"positive control: {sender.role_label} could not even dispatch a "
        f"valid opportunistic DATA packet ({good!r}); topology/path is "
        f"broken, so the drop assertion would be meaningless."
    )
    assert good["delivered"], (
        f"positive control FAILED: a VALID opportunistic packet to "
        f"{dest_hash.hex()[:16]}... did not resolve DELIVERED "
        f"(status={good['status']!r}). The receiver isn't proving valid "
        f"packets, so a later 'no proof' result wouldn't prove the drop "
        f"path — it'd just mean nothing ever gets proven."
    )
    control_seen = receiver.opportunistic_poll(
        dest_hash, timeout_ms=_POLL_TIMEOUT_MS
    )
    assert good_payload in control_seen, (
        f"positive control FAILED: receiver's opportunistic callback did "
        f"not surface the VALID payload (saw {control_seen!r}). The "
        f"callback path is what the negative case asserts stays silent, so "
        f"it must demonstrably fire for a good packet first."
    )

    # ---- Negative case: an UNDECRYPTABLE packet must be dropped.
    # Snapshot the receiver's inbound tap so we can later prove the
    # corrupted packet actually reached its Transport. Only valid for a
    # reference receiver with "ciphertext" corruption — "truncate" is
    # dropped at the parse layer before Transport.inbound (the tap point).
    check_arrival = receiver_is_reference and corruption == "ciphertext"
    if check_arrival:
        pre = receiver.get_received_packets(since_seq=0)
        base_seq = int(pre.get("highest_seq", 0))

    bad_payload = b"undecryptable-" + secrets.token_hex(4).encode()
    bad = sender.send_undecryptable(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        data=bad_payload,
        corruption=corruption,
        timeout_ms=_DROP_RECEIPT_TIMEOUT_MS,
    )
    assert bad["sent"], (
        f"{sender.role_label} failed to dispatch the corrupted packet "
        f"({bad!r}); the negative case can't run if the packet never left "
        f"the sender."
    )

    # Invariant B: no proof. The receiver must NOT have proven a packet it
    # could not decrypt, so the sender's receipt must not resolve.
    assert not bad["delivered"], (
        f"DROP INVARIANT VIOLATED (no-proof half): an UNDECRYPTABLE "
        f"packet (corruption={corruption!r}) to {dest_hash.hex()[:16]}... "
        f"resolved DELIVERED (status={bad['status']!r}). The receiver "
        f"emitted a delivery proof for a packet it cannot decrypt — it is "
        f"proving before (or instead of) verifying decryption. A correct "
        f"receiver returns False from Destination.receive on decrypt "
        f"failure, short-circuiting the PROVE_ALL auto-proof."
    )

    # Invariant A: no callback. The receiver's opportunistic buffer must
    # stay empty for the corrupted payload.
    seen = receiver.opportunistic_poll(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert bad_payload not in seen, (
        f"DROP INVARIANT VIOLATED (no-callback half): receiver dispatched "
        f"an UNDECRYPTABLE payload (corruption={corruption!r}) to its "
        f"packet callback. opportunistic_poll returned {seen!r}, which "
        f"contains the corrupted payload. A correct receiver never calls "
        f"the callback for a packet that failed to decrypt."
    )
    # Belt-and-suspenders: nothing at all should surface here. The control
    # payload was already drained above, so any bytes now are a leak.
    assert seen == [], (
        f"receiver surfaced unexpected opportunistic data after an "
        f"undecryptable send: {seen!r} (expected empty — the only valid "
        f"packet was the control, already drained)."
    )

    # For a reference receiver with structurally-valid (ciphertext-
    # corrupted) input, prove the corrupted packet genuinely reached
    # Transport.inbound — so "no callback / no proof" means "received and
    # dropped at decrypt", not "never arrived".
    if check_arrival:
        post = receiver.get_received_packets(since_seq=base_seq)
        data_to_dest = [
            pkt for pkt in post.get("packets", [])
            if (pkt.get("packet_type") == _PACKET_TYPE_DATA)
            and (pkt.get("destination_hash_hex") == dest_hash.hex())
        ]
        assert data_to_dest, (
            f"the corrupted DATA packet never reached the receiver's "
            f"Transport.inbound (tap saw no DATA packet for "
            f"{dest_hash.hex()[:16]}... after seq {base_seq}). The drop "
            f"assertions would be vacuous — the packet must arrive to be "
            f"meaningfully dropped. tap={post!r}"
        )
