"""LXMF OPPORTUNISTIC delivery — end-to-end conformance test.

Opportunistic delivery:
  - single encrypted packet, unicast, no link, no propagation node
  - capped at LXMF.LXMessage.ENCRYPTED_PACKET_MAX_CONTENT (~295 bytes of
    content + fields combined on the Python reference; LXMF-kt uses the
    same cap). Oversized content silently upgrades to DIRECT on both
    impls — the bridge send commands reject up-front so the conformance
    tests stay scoped to the single-packet case; an oversized-opportunistic
    test would need to assert "silent upgrade happened" explicitly, which
    is a separate class of test.

Topology: sender -> [plain transport] -> receiver. The middle peer is
JUST an RNS transport (enable_transport=true); no lxmd, no LXMRouter of
its own. Sender submits the message via its in-process LXMRouter; the
delivery packet hops through the transport to the receiver's RNS, which
decrypts it and fires the receiver's delivery callback.

Parametrized over the cartesian product of {reference, kotlin} for
sender + receiver — 4 trios total with --impl=kotlin. Mirrors the
propagation-test pattern.
"""

import secrets

import pytest


# LXMF field key for images. FIELD_IMAGE = 6 per LXMF spec (see
# LXMF/Fields.py in the Python reference). Values are a 2-element
# positional list: [format_str, data_bytes].
_FIELD_IMAGE = 6
_TITLE_TEXT = "Opportunistic text test"
_TITLE_IMAGE = "Opportunistic image test"


def test_opportunistic_text_round_trip(lxmf_trio, lxmf_transport_3peer):
    """Sender -> plain transport -> receiver, text-only opportunistic
    message. Three tight assertions: (1) send returns a message hash,
    (2) receiver's inbox is exactly length 1 after the delivery
    callback fires, (3) content / title / source match the sender
    exactly.
    """
    sender, receiver = lxmf_transport_3peer

    # Random-tail content so a bug that reports cached / previous-run
    # messages can't accidentally fake a pass. Short enough that total
    # content + msgpack framing stays under ENCRYPTED_PACKET_MAX_CONTENT
    # (~295 bytes); the send command rejects up-front if we overflow.
    content = f"opp text {secrets.token_hex(8)}"

    message_hash = sender.send_opportunistic(
        recipient_delivery_dest_hash=receiver.delivery_dest_hash,
        content=content,
        title=_TITLE_TEXT,
    )
    assert message_hash, (
        f"{sender.role_label}.send_opportunistic returned empty "
        f"message_hash; sender didn't finish packing the outbound "
        f"LXMessage."
    )

    # wait_for_inbox_count drains + accumulates until count reaches 1,
    # then lingers to catch duplicates. Tight equality, per feedback memo.
    inbox = receiver.wait_for_inbox_count(expected=1, timeout_s=20.0)

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
    # Fields should be empty dict — no fields were sent.
    assert inbox[0]["fields"] == {}, (
        f"expected empty fields dict, got {inbox[0]['fields']!r}"
    )


def test_opportunistic_with_image_field(lxmf_trio, lxmf_transport_3peer):
    """Send a short text message with a FIELD_IMAGE attached. Asserts
    exact field payload on receipt.

    Field shape: FIELD_IMAGE (key = 6) is a 2-element positional list
    [format_str, data_bytes]. Mirrors the canonical Python-LXMF wire
    shape and the lxmf-kt side serialization. Kept small so the whole
    packed message still fits in a single opportunistic packet.
    """
    sender, receiver = lxmf_transport_3peer

    content = f"opp image {secrets.token_hex(4)}"
    # ~64 bytes of "image" — synthetic, deterministic, and small enough
    # to keep the packed message under ENCRYPTED_PACKET_MAX_CONTENT
    # after accounting for msgpack field framing + stamp overhead.
    image_bytes = secrets.token_bytes(64)
    image_format = "jpg"

    message_hash = sender.send_opportunistic(
        recipient_delivery_dest_hash=receiver.delivery_dest_hash,
        content=content,
        title=_TITLE_IMAGE,
        fields={
            # Field values use the tagged shape — see
            # _decode_field_value_from_params in lxmf_bridge.py and
            # lxmfFieldValueFromJson in Lxmf.kt.
            str(_FIELD_IMAGE): [
                {"str": image_format},
                {"bytes": image_bytes.hex()},
            ],
        },
    )
    assert message_hash, (
        f"{sender.role_label}.send_opportunistic returned empty "
        f"message_hash on image-field test."
    )

    inbox = receiver.wait_for_inbox_count(expected=1, timeout_s=20.0)

    assert inbox[0]["content"] == content, (
        f"content mismatch: got {inbox[0]['content']!r}, "
        f"expected {content!r}"
    )
    assert inbox[0]["title"] == _TITLE_IMAGE, (
        f"title mismatch: got {inbox[0]['title']!r}, "
        f"expected {_TITLE_IMAGE!r}"
    )
    assert inbox[0]["source"] == sender.delivery_dest_hash.hex(), (
        f"source mismatch: got {inbox[0]['source']!r}, "
        f"expected {sender.delivery_dest_hash.hex()!r}"
    )

    # Exact-shape field check. The bridge serialises:
    #   - top-level key as the int converted to str ("6")
    #   - value as a 2-element list [format_str, data_hex]
    #     (bytes are hex-encoded at every nesting level; see the
    #     _encode_field_value_for_inbox / lxmfFieldValueToJson pair)
    expected_field = [image_format, image_bytes.hex()]
    assert inbox[0]["fields"] == {str(_FIELD_IMAGE): expected_field}, (
        f"FIELD_IMAGE payload mismatch: got {inbox[0]['fields']!r}, "
        f"expected {{{str(_FIELD_IMAGE)!r}: {expected_field!r}}}"
    )
