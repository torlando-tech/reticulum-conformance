"""Deterministic regression test for the receiver-side post-prove invariant.

Locks in the fix from reticulum-kt#54: by the time `link.prove()` returns
on the receiver side, ALL bookkeeping required for inbound link DATA
dispatch must already have happened. Specifically:

- `Transport.registerLink(link)` must have added the link to `activeLinks`
  before LRPROOF goes on the wire, so any DATA arriving immediately after
  the sender sees ACTIVE finds the link in `activeLinks` and is dispatched
  to `Link.receive(packet)` instead of being dropped at Transport's
  `processData` lookup.

- All other inbound-dispatch dependencies (attachedInterfaceHash, link
  encryption keys via handshake(), etc.) must likewise be ready.

Methodology: the receiver bridge sets a test-only race inducer that
sleeps for `_INDUCER_DELAY_MS` immediately AFTER `link.prove()` returns
(but inside `validateRequest`, before any further bookkeeping could
happen). The sender then opens a link and sends DATA immediately. While
the receiver is "stuck" in the post-prove sleep, the sender's first DATA
packet arrives at the receiver. If all dispatch dependencies are
satisfied by the moment prove() returns, the DATA is delivered. If any
required setup happens AFTER prove(), the DATA is dropped.

Pre-#54 (registerLink after prove): test fails deterministically.
Post-#54 (registerLink before prove): test passes deterministically.

The test is parameterized on (sender_impl, transport_impl) but pins the
receiver to kotlin — the inducer is Kotlin-only, so verifying the
invariant on a Python receiver would be vacuous (no inducer fires).
"""

import secrets
import time


_APP_NAME = "linkpostprove"
_ASPECTS = ["test"]
_SETTLE_SEC = 1.5
_LINK_TIMEOUT_MS = 15000
_POLL_TIMEOUT_MS = 10000
_INDUCER_DELAY_MS = 2000
_POST_INDUCER_BUFFER_MS = 3000


def _setup_three_peer_topology(wire_3peer):
    """Mirrors test_link_multihop._setup_three_peer_topology — duplicated
    here rather than imported because pytest test files in the same dir
    don't import each other cleanly without conftest plumbing.
    """
    sender, transport, receiver = wire_3peer
    port = transport.start_tcp_server(network_name="", passphrase="")
    receiver.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    sender.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    time.sleep(_SETTLE_SEC)
    dest_hash = receiver.listen(app_name=_APP_NAME, aspects=_ASPECTS)
    assert sender.poll_path(dest_hash, timeout_ms=_POLL_TIMEOUT_MS), (
        f"{sender.role_label} did not learn a path to "
        f"{receiver.role_label}'s destination via {transport.role_label}."
    )
    return sender, transport, receiver, dest_hash


import pytest


_RESIDUAL_BUG_URL = "https://github.com/torlando-tech/reticulum-kt/issues/56"
_RESIDUAL_BUG_REASON = (
    "reticulum-kt#56 residual: destination.linkEstablished callback fires "
    "in thread(isDaemon = true) at Link.kt:1888-1911 instead of "
    "synchronously from rttPacket. Read loop processes DATA before the "
    "daemon thread wires link.setPacketCallback, so DATA is silently "
    "dropped. Reproduces 5/5 with a 2s inducer. See: " + _RESIDUAL_BUG_URL
)


@pytest.mark.xfail(strict=False, reason=_RESIDUAL_BUG_REASON)
def test_first_data_arrives_during_induced_post_prove_window(wire_trio, wire_3peer):
    # Inducer is Kotlin-only — Python receiver no-ops the bridge command,
    # so verifying the invariant on a Python receiver would be vacuous.
    _sender_impl, _transport_impl, receiver_impl = wire_trio
    if receiver_impl != "kotlin":
        pytest.skip("post-prove inducer is Kotlin-only; skipping non-kotlin receiver")
    """Sender sends DATA immediately after link establishment; receiver is
    stuck in a 500ms post-prove sleep. The DATA must still be delivered.

    Regression test for reticulum-kt#54. Pre-fix, registerLink ran AFTER
    prove() — so the link was not in activeLinks during the induced window
    and the DATA was dropped. Post-fix, registerLink runs BEFORE prove() —
    so the link is in activeLinks before the LRPROOF leaves the wire and
    the DATA is dispatched correctly even though validateRequest is still
    sleeping.
    """
    # Standard 3-peer setup: sender announces a path to receiver via
    # transport, sender opens a link to receiver's destination.
    sender, transport, receiver, dest_hash = _setup_three_peer_topology(
        wire_3peer
    )

    # Set the inducer AFTER the bridges are up but BEFORE link establishment.
    # The static is process-wide on the bridge side, so any link established
    # after this point will hit the sleep at the post-prove seam.
    receiver.set_race_inducer(seam="post-prove", delay_ms=_INDUCER_DELAY_MS)

    try:

        link_id = sender.link_open(
            dest_hash,
            app_name=_APP_NAME,
            aspects=_ASPECTS,
            timeout_ms=_LINK_TIMEOUT_MS + _INDUCER_DELAY_MS,
        )

        # Send the first DATA packet IMMEDIATELY after link_open returns.
        # On the sender side, link_open returns when status==ACTIVE, which
        # happens upon LRPROOF receipt. At that exact moment the receiver
        # is mid-sleep in validateRequest's post-prove inducer.
        payload = secrets.token_bytes(32)
        sender.link_send(link_id, payload)

        # Wait long enough for the inducer to release plus the round trip
        # for the DATA to be observed by the receiver's link callback.
        received = receiver.link_poll(
            dest_hash,
            timeout_ms=_INDUCER_DELAY_MS + _POST_INDUCER_BUFFER_MS,
        )

        assert received == [payload], (
            f"{receiver.role_label} did not receive the DATA packet that "
            f"arrived during the induced {_INDUCER_DELAY_MS}ms post-prove "
            f"window. Got {len(received)} packet(s). This means some "
            f"bookkeeping needed for inbound link-DATA dispatch was deferred "
            f"to AFTER link.prove() returned, violating the invariant fixed "
            f"in reticulum-kt#54."
        )
    finally:
        # Reset inducer so subsequent tests run with default behaviour.
        receiver.set_race_inducer(seam="post-prove", delay_ms=0)
