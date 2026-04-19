"""LXMF PROPAGATED delivery — end-to-end conformance test.

Exercises the minimal end-to-end propagation topology:

    sender → propagation_node → receiver

Sender submits a PROPAGATED LXMessage via its LXMRouter. The message
travels over the TCP wire + IFAC-free network to the propagation node
(real lxmd subprocess), gets stored there, and the receiver later pulls
it down with request_messages_from_propagation_node (driven by
lxmf_sync_inbound on the bridge).

Parametrized over the cartesian product of {reference, kotlin} for
sender + receiver — 4 trios total with --impl=kotlin. The middle slot
is always "lxmd" (the Python lxmd daemon) to keep the propagation-node
path architecturally realistic.

Scope intentionally tight:
  - Single-packet text content (fits in one link DATA packet).
  - No attachments, no IFAC, no stamp cost.
"""

import secrets
import time


_TITLE = "Propagation test"


def test_propagated_delivery_round_trip(lxmf_trio, lxmf_3peer):
    """Sender → lxmd propagation node → receiver, with three tight
    assertions: (1) B's storage shows exactly 1 message, (2) C's
    sync pulls exactly 1 message, (3) C's inbox is exactly 1 entry
    with matching content / title / source.
    """
    sender, propagation_node, receiver = lxmf_3peer

    # Random-tail content so a bug that reports cached / previous-run
    # messages can't accidentally fake a pass. The fixture creates fresh
    # bridge processes per test, so this is belt-and-suspenders — but
    # cheap, and it makes the assertion genuinely unique per run.
    content = f"MVP propagated message {secrets.token_hex(8)}"

    message_hash = sender.send_propagated(
        recipient_delivery_dest_hash=receiver.delivery_dest_hash,
        content=content,
        title=_TITLE,
    )
    assert message_hash, (
        f"{sender.role_label}.send_propagated returned empty message_hash; "
        f"the sender did not finish packing the outbound LXMessage."
    )

    # Assertion 1: B's storage shows exactly 1 message. Bounded wait
    # — the sender → propagation-node transfer takes up to ~25s on
    # loopback when the Kotlin sender is generating a PROPAGATION_COST=16
    # stamp (~65k attempts). Add the link-setup + resource-transfer +
    # file-write latency on top and 30s is a comfortable ceiling that
    # still fails fast if the path is actually broken. Tight equality
    # on the FINAL count catches both under- and over-storage.
    assert propagation_node.wait_for_stored_message_count(
        expected=1, timeout_s=30.0
    ), (
        f"lxmd storage never reached exactly 1 stored message; final "
        f"count = {propagation_node.stored_message_count()}. "
        f"0 = sender→node transfer broken; >1 = the sender/router sent "
        f"the message multiple times or lxmd duplicated on disk."
    )

    # Assertion 2: C's sync_inbound returns exactly 1 message pulled.
    synced = receiver.sync_inbound(timeout_s=15.0)
    assert synced == 1, (
        f"{receiver.role_label}.sync_inbound returned {synced} messages "
        f"received, expected exactly 1. 0 = pull path broken "
        f"(link/list/request); >1 = sync reported duplicates."
    )

    # Assertion 3: C's poll_inbox is exactly length 1 with matching
    # content, title, source. Tight equality per feedback memo.
    inbox = receiver.poll_inbox()
    assert len(inbox) == 1, (
        f"{receiver.role_label} inbox has {len(inbox)} entries, expected "
        f"exactly 1. Inbox: {inbox!r}. "
        f"0 = sync reported success but delivery callback never fired; "
        f">1 = duplicate delivery."
    )
    assert inbox[0]["content"] == content, (
        f"content mismatch: got {inbox[0]['content']!r}, "
        f"expected {content!r}"
    )
    assert inbox[0]["title"] == _TITLE, (
        f"title mismatch: got {inbox[0]['title']!r}, "
        f"expected {_TITLE!r}"
    )
    # Sender hash on the inbox entry is the sender's delivery dest hash
    # (what Python sets as source_hash on the received message). This
    # catches a class of bugs where the encryption-for-recipient step
    # mangles the source attribution.
    assert inbox[0]["source"] == sender.delivery_dest_hash.hex(), (
        f"source mismatch: got {inbox[0]['source']!r}, "
        f"expected {sender.delivery_dest_hash.hex()!r}"
    )
