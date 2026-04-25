"""LXMF DIRECT delivery — end-to-end conformance test.

Direct delivery:
  - sender opens a Link to the recipient's delivery destination
  - content <= LINK_PACKET_MAX_CONTENT (~319 bytes) goes as a single
    LINK packet
  - larger payloads use a Resource for multi-packet chunked transfer
    (same path as image / file attachments in Columba / Sideband)

Topology: sender -> [plain transport] -> receiver. Same
lxmf_transport_3peer fixture as test_opportunistic.

Parametrized 4 ways via lxmf_trio: {reference, kotlin} x {reference,
kotlin} for sender + receiver.
"""

import secrets



# LXMF FIELD_FILE_ATTACHMENTS: key 5 per LXMF spec. Canonical wire shape
# (see memory/lxmf-attachment-format-variance.md): list of 2-element
# positional tuples, [[filename_str, data_bytes], ...]. This test
# deliberately uses shape #1 from the memo — the format that actually
# travels over the wire between Python LXMF / Sideband / Columba.
_FIELD_FILE_ATTACHMENTS = 5
_TITLE_TEXT = "Direct text test"
_TITLE_FILE = "Direct file attachment test"

# Payload size for the multi-packet attachment test. Must be > 319 bytes
# (LINK_PACKET_MAX_CONTENT) so the message uses Resource transfer
# instead of single-packet. 2 KiB comfortably exceeds that and matches
# the "small image" class of attachments Columba handles. Deterministic
# per test run via secrets.token_bytes so exact-bytes assertions work.
_ATTACHMENT_SIZE_BYTES = 2048


# LXMF-kt#8 (DIRECT multi-packet double-delivery) was fixed by
# LXMF-kt#14 + #16, included from v0.0.8 of the LXMF-kt artifact that
# reticulum-kt's conformance-bridge consumes. The receiver=kotlin
# variants of test_direct_with_file_attachment_multipacket below now
# pass without the prior xfail gate.


def test_direct_text_round_trip(lxmf_trio, lxmf_transport_3peer):
    """Sender -> transport -> receiver, text-only direct-delivery
    message. Mirrors the opportunistic text test but goes over a
    link instead of a single packet. The content size is well under
    the single-link-packet cap so no Resource is involved on this
    case — we test the Resource path in
    test_direct_with_file_attachment_multipacket below.
    """
    sender, receiver = lxmf_transport_3peer

    content = f"direct text {secrets.token_hex(8)}"

    message_hash = sender.send_direct(
        recipient_delivery_dest_hash=receiver.delivery_dest_hash,
        content=content,
        title=_TITLE_TEXT,
    )
    assert message_hash, (
        f"{sender.role_label}.send_direct returned empty message_hash; "
        f"sender didn't finish packing the outbound LXMessage."
    )

    # Direct delivery requires link establishment (round-trip), so the
    # settle budget is a bit longer than opportunistic. 30s is the same
    # default as the wire-layer link tests.
    inbox = receiver.wait_for_inbox_count(expected=1, timeout_s=30.0)

    assert inbox[0]["content"] == content, (
        f"content mismatch: got {inbox[0]['content']!r}, "
        f"expected {content!r}"
    )
    assert inbox[0]["title"] == _TITLE_TEXT, (
        f"title mismatch: got {inbox[0]['title']!r}, "
        f"expected {_TITLE_TEXT!r}"
    )
    assert inbox[0]["source"] == sender.delivery_dest_hash.hex(), (
        f"source mismatch: got {inbox[0]['source']!r}, "
        f"expected {sender.delivery_dest_hash.hex()!r}"
    )
    assert inbox[0]["fields"] == {}, (
        f"expected empty fields dict, got {inbox[0]['fields']!r}"
    )


def test_direct_with_file_attachment_multipacket(lxmf_trio, lxmf_transport_3peer):
    """Send a FIELD_FILE_ATTACHMENTS payload big enough to trigger
    Resource transfer. Asserts the exact filename + exact attachment
    bytes land on the receiver.

    This is the test that would catch the Columba FIELD_FILE_ATTACHMENTS
    bugs described in memory/lxmf-attachment-format-variance.md:
    if an impl mis-handles the 2-element positional tuple on unpack,
    the payload either doesn't appear in the inbox fields at all or
    the filename / bytes get swapped / truncated, and the exact-match
    assertion below flips red.

    Uses shape #1 from the attachment-variance memo:
      [[filename_str, data_bytes], ...]
    the canonical wire format that all LXMF impls agree on when
    encoding attachments for transport.
    """
    sender, receiver = lxmf_transport_3peer

    content = f"direct file {secrets.token_hex(4)}"
    filename = f"conformance-{secrets.token_hex(4)}.bin"
    attachment_bytes = secrets.token_bytes(_ATTACHMENT_SIZE_BYTES)

    message_hash = sender.send_direct(
        recipient_delivery_dest_hash=receiver.delivery_dest_hash,
        content=content,
        title=_TITLE_FILE,
        fields={
            # Tagged-dict shape — see _decode_field_value_from_params.
            # List-of-lists at the outer level (attachments are
            # positionally indexed), each inner list is
            # [filename_str, data_bytes] with the bytes wrapped in
            # the {"bytes": "<hex>"} tag.
            str(_FIELD_FILE_ATTACHMENTS): [
                [
                    {"str": filename},
                    {"bytes": attachment_bytes.hex()},
                ],
            ],
        },
    )
    assert message_hash, (
        f"{sender.role_label}.send_direct returned empty message_hash "
        f"on multipacket attachment test."
    )

    # Resource transfer of 2 KiB over a fresh link on loopback is fast
    # (<2s steady-state), but the link setup + fragment-carrier setup
    # takes a few seconds. 45s is the same budget the wire-layer
    # resource tests use.
    inbox = receiver.wait_for_inbox_count(expected=1, timeout_s=45.0)

    assert inbox[0]["content"] == content, (
        f"content mismatch: got {inbox[0]['content']!r}, "
        f"expected {content!r}"
    )
    assert inbox[0]["title"] == _TITLE_FILE, (
        f"title mismatch: got {inbox[0]['title']!r}, "
        f"expected {_TITLE_FILE!r}"
    )
    assert inbox[0]["source"] == sender.delivery_dest_hash.hex(), (
        f"source mismatch: got {inbox[0]['source']!r}, "
        f"expected {sender.delivery_dest_hash.hex()!r}"
    )

    # Exact-shape field check on FIELD_FILE_ATTACHMENTS.
    # Serialization path (applied on both impls):
    #   [[filename_str, data_bytes]]    native
    #    -> [[filename_str, data_hex]]  after recursive hex-encode
    expected_field = [[filename, attachment_bytes.hex()]]
    assert inbox[0]["fields"] == {
        str(_FIELD_FILE_ATTACHMENTS): expected_field
    }, (
        f"FIELD_FILE_ATTACHMENTS payload mismatch: "
        f"got {inbox[0]['fields']!r}, "
        f"expected {{{str(_FIELD_FILE_ATTACHMENTS)!r}: {expected_field!r}}}"
    )
