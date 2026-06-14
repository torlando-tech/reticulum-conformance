"""RNS Channel receive-length / MDU / sequence-reservation conformance (wire).

These drive a real ``RNS.Channel`` on an established Link to pin three
contracts the byte-level format tests cannot reach:

  * RECEIVE LENGTH FIELD IGNORED — ``Channel.Envelope.unpack`` (Channel.py:180)
    reads (MSGTYPE, sequence, length) off the 6-byte header but uses only
    ``raw[6:]`` as the payload; the on-wire length field is never consulted on
    receive. Injecting a crafted envelope whose length field is deliberately
    wrong still delivers the full ``raw[6:]`` payload.

  * CHANNEL MDU + ME_TOO_BIG — ``Channel.mdu`` (Channel.py:642-655) is
    ``outlet.mdu - 6`` capped at 0xFFFF, and ``Channel.send`` rejects a message
    that would exceed ``outlet.mdu`` with ``ChannelException(ME_TOO_BIG)``
    BEFORE advancing the transmit sequence (Channel.py:614-617).

  * SEQUENCE RESERVATION RESTORE — if the outlet fails to transmit,
    ``Channel.send`` restores the reserved ``_next_sequence`` and raises
    ``ME_LINK_NOT_READY`` (Channel.py:619-626), so the next successful send
    reuses that exact sequence with no gap.

Both Link peers are reference instances under ``--reference-only``.
"""

import struct

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("channel",)
_LINK_TIMEOUT_MS = 15000
_PATH_TIMEOUT_MS = 10000
_SEND_TIMEOUT_MS = 12000

# The Channel MSGTYPE the wire harness registers on every channel (wire_tcp.py
# _WIRE_CHANNEL_MSGTYPE). Crafted raw envelopes must carry it to be delivered.
_WIRE_CHANNEL_MSGTYPE = 0x0101

# Channel envelope header overhead: sizeof(MSGTYPE)+sizeof(sequence)+
# sizeof(length) = 2+2+2 (Channel.py:652). Channel.mdu caps at 0xFFFF.
_ENVELOPE_OVERHEAD = 6
_MDU_CAP = 0xFFFF

# CEType numeric codes (Channel.py:109-114) — external ground truth, pinned as
# literals to keep the test process free of an RNS import (mirroring how
# test_channel_flow pins the window constants).
_ME_NO_MSG_TYPE = 0       # CEType.ME_NO_MSG_TYPE
_ME_INVALID_MSG_TYPE = 1  # CEType.ME_INVALID_MSG_TYPE
_ME_LINK_NOT_READY = 3    # CEType.ME_LINK_NOT_READY
_ME_TOO_BIG = 5           # CEType.ME_TOO_BIG


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_inject", "channel_received", "channel_window",
    ],
    verifies=(
        "RNS Channel ignores the envelope length field on receive "
        "(Channel.Envelope.unpack uses raw[6:], never the header length, "
        "Channel.py:180-181): a crafted envelope at the next expected sequence "
        "whose 6-byte >HHH header advertises a WRONG length (1, far short of "
        "the real payload) still delivers the full raw[6:] payload to the "
        "handler and advances the receive sequence; a positive control with a "
        "CORRECT length field at the following sequence delivers identically — "
        "proving delivery is length-field-independent, not a coincidence of a "
        "matching length"
    ),
)
def test_channel_receive_ignores_length_field(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    pre = client.channel_window(link_id)
    seq0 = pre["next_rx_sequence"]

    # Crafted envelope: header length field = 1, but payload is 16 bytes. The
    # raw bytes are assembled HERE (test side), then fed verbatim to the live
    # Channel._receive via the channel_inject raw-override.
    payload_a = b"length-mismatch!"  # 16 bytes, != the advertised length 1
    assert len(payload_a) != 1
    raw_wrong = struct.pack(">HHH", _WIRE_CHANNEL_MSGTYPE, seq0, 1) + payload_a
    client.channel_inject(link_id, [{"raw": raw_wrong, "sequence": seq0}])

    delivered = client.channel_received(link_id)
    assert delivered == [payload_a], (
        f"channel did not deliver the full raw[6:] payload despite a wrong "
        f"length field: got {[d.hex() for d in delivered]!r}, expected "
        f"{[payload_a.hex()]!r}"
    )
    mid = client.channel_window(link_id)
    assert mid["next_rx_sequence"] == (seq0 + 1) % 0x10000, (
        f"receive sequence did not advance after the wrong-length envelope: "
        f"{seq0} -> {mid['next_rx_sequence']}"
    )

    # Positive control: a CORRECT length field at the next sequence delivers
    # the same way — so the wrong-length delivery above was the contract, not
    # a fluke of matching lengths.
    seq1 = mid["next_rx_sequence"]
    payload_b = b"correct-length-frame"
    raw_right = struct.pack(
        ">HHH", _WIRE_CHANNEL_MSGTYPE, seq1, len(payload_b)
    ) + payload_b
    client.channel_inject(link_id, [{"raw": raw_right, "sequence": seq1}])
    assert client.channel_received(link_id) == [payload_b], (
        "positive control (correct length) was not delivered"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_register",
    ],
    verifies=(
        "RNS Channel.register_message_type rejects malformed message classes "
        "with ChannelException(ME_INVALID_MSG_TYPE, code 1) (Channel.py:328-345): "
        "a class that is not a MessageBase subclass, a MessageBase subclass with "
        "MSGTYPE=None, a MessageBase subclass with a system-reserved MSGTYPE "
        ">=0xf000, and a MessageBase subclass that cannot be default-constructed "
        "are each rejected with code 1, while a well-formed class is accepted "
        "(positive control); and Envelope.pack raises "
        "ChannelException(ME_NO_MSG_TYPE, code 0) for a MSGTYPE-None message "
        "(Channel.py:193-194), a distinct code from the registration guard"
    ),
)
def test_channel_msgtype_registration_validation(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    # Each malformed kind is rejected at registration with ME_INVALID_MSG_TYPE.
    for kind in ("non_message_base", "msgtype_none", "reserved", "not_constructible"):
        r = client.channel_register(link_id, kind)
        assert r.get("accepted") is False, (
            f"register kind {kind!r} must be rejected: {r!r}"
        )
        assert r.get("ce_type") == _ME_INVALID_MSG_TYPE, (
            f"register kind {kind!r} should raise ME_INVALID_MSG_TYPE (code "
            f"{_ME_INVALID_MSG_TYPE}), got ce_type={r.get('ce_type')} "
            f"error={r.get('error')!r}"
        )

    # Positive control: a well-formed MessageBase subclass IS accepted — proving
    # the rejections above are specific to the defect, not a dead registrar.
    ok = client.channel_register(link_id, "valid")
    assert ok.get("accepted") is True, (
        f"a well-formed message class must be accepted: {ok!r}"
    )

    # Envelope.pack uses a DISTINCT code (ME_NO_MSG_TYPE) for a MSGTYPE-None
    # message — the pack-time guard, separate from the registration guard.
    nopack = client.channel_register(link_id, "envelope_pack_no_msgtype")
    assert nopack.get("accepted") is False, (
        f"Envelope.pack of a MSGTYPE-None message must raise: {nopack!r}"
    )
    assert nopack.get("ce_type") == _ME_NO_MSG_TYPE, (
        f"Envelope.pack should raise ME_NO_MSG_TYPE (code {_ME_NO_MSG_TYPE}), "
        f"got ce_type={nopack.get('ce_type')}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_window", "channel_send", "link_mtu",
    ],
    verifies=(
        "RNS Channel.mdu == min(outlet.mdu - 6, 0xFFFF) (Channel.py:642-655), "
        "cross-checked against the independently-read link MDU (link_mtu), and "
        "Channel.send rejects an oversized message with "
        "ChannelException(ME_TOO_BIG, code 5) WITHOUT transmitting it or "
        "advancing the transmit sequence (Channel.py:614-617): a send of "
        "outlet_mdu-5 bytes (one over the limit) returns rejected with ce_type "
        "5 and leaves next_sequence unchanged, while the positive control — a "
        "send of exactly channel.mdu bytes (the largest that fits) — is "
        "accepted and advances next_sequence"
    ),
)
def test_channel_mdu_and_too_big_rejection(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS, fixed_mtu=500,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    w = client.channel_window(link_id)
    outlet_mdu = w["outlet_mdu"]
    channel_mdu = w["mdu"]

    # Channel.mdu is the link MDU minus the 6-byte envelope overhead, capped at
    # 0xFFFF — pinned via the documented formula (the constants are external).
    assert channel_mdu == min(outlet_mdu - _ENVELOPE_OVERHEAD, _MDU_CAP), (
        f"channel.mdu={channel_mdu}, expected "
        f"min(outlet_mdu({outlet_mdu})-{_ENVELOPE_OVERHEAD}, {_MDU_CAP})"
    )
    # Cross-check outlet_mdu against the independently-read link MDU.
    link_mdu = client.link_mtu(link_id)["mdu"]
    assert outlet_mdu == link_mdu, (
        f"channel outlet mdu ({outlet_mdu}) != link.mdu ({link_mdu})"
    )

    pre_seq = w["next_sequence"]

    # One byte over the wire limit: 6 + (outlet_mdu-5) = outlet_mdu+1 > outlet_mdu.
    oversized = b"\x00" * (outlet_mdu - 5)
    r = client.channel_send(link_id, oversized, timeout_ms=_SEND_TIMEOUT_MS)
    assert r.get("rejected") is True, (
        f"an oversized channel send must be rejected: {r!r}"
    )
    assert r.get("ce_type") == _ME_TOO_BIG, (
        f"oversized send should raise ME_TOO_BIG (code {_ME_TOO_BIG}), got "
        f"ce_type={r.get('ce_type')} error={r.get('error')!r}"
    )
    assert r.get("sent") is False, "an ME_TOO_BIG send must not transmit"
    assert r.get("next_sequence") == pre_seq, (
        f"ME_TOO_BIG advanced the transmit sequence ({pre_seq} -> "
        f"{r.get('next_sequence')}); the size guard runs before the increment"
    )

    # Positive control: exactly channel.mdu bytes is the largest that fits
    # (6 + channel.mdu == outlet.mdu) and is accepted, advancing the sequence.
    fits = b"\x01" * channel_mdu
    ok = client.channel_send(link_id, fits, timeout_ms=_SEND_TIMEOUT_MS)
    assert ok.get("rejected") is not True, (
        f"a send of exactly channel.mdu={channel_mdu} bytes must be accepted: {ok!r}"
    )
    assert ok.get("sent") is True, f"the max-fitting send did not transmit: {ok!r}"
    post = client.channel_window(link_id)
    assert post["next_sequence"] == (pre_seq + 1) % 0x10000, (
        f"accepted send did not advance next_sequence: {pre_seq} -> "
        f"{post['next_sequence']}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "channel_window", "channel_send",
    ],
    verifies=(
        "RNS Channel.send restores the reserved transmit sequence when the "
        "outlet fails to transmit (Channel.py:619-626): a fault-injected send "
        "whose outlet returns None raises ChannelException(ME_LINK_NOT_READY, "
        "code 3), leaves next_sequence at its pre-send value (the reservation "
        "is rolled back, not consumed), and the NEXT successful send reuses "
        "that exact sequence with no gap — an impl that leaked the reservation "
        "would skip a sequence and stall the peer's receive window"
    ),
)
def test_channel_sequence_restored_on_failed_send(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP, aspects=_ASPECTS,
        link_timeout_ms=_LINK_TIMEOUT_MS, path_timeout_ms=_PATH_TIMEOUT_MS,
    )

    pre = client.channel_window(link_id)
    reserved = pre["next_sequence"]

    # Fault-inject: the outlet returns None, so Channel.send hits the
    # "outlet did not transmit" branch, restores _next_sequence, and raises.
    r = client.channel_send(
        link_id, b"will-fail", fail_outlet=True, timeout_ms=_SEND_TIMEOUT_MS
    )
    assert r.get("rejected") is True, (
        f"a failed-outlet send must surface a ChannelException: {r!r}"
    )
    assert r.get("ce_type") == _ME_LINK_NOT_READY, (
        f"failed-outlet send should raise ME_LINK_NOT_READY (code "
        f"{_ME_LINK_NOT_READY}), got ce_type={r.get('ce_type')}"
    )
    assert r.get("next_sequence") == reserved, (
        f"the reserved sequence {reserved} was not restored after the failed "
        f"send: next_sequence={r.get('next_sequence')}"
    )

    mid = client.channel_window(link_id)
    assert mid["next_sequence"] == reserved, (
        f"channel_window shows next_sequence={mid['next_sequence']} after the "
        f"failed send, expected the restored {reserved}"
    )

    # The next successful send reuses the freed sequence (no gap).
    ok = client.channel_send(link_id, b"now-ok", timeout_ms=_SEND_TIMEOUT_MS)
    assert ok.get("sent") is True, f"the follow-up send did not transmit: {ok!r}"
    assert ok.get("sequence") == reserved, (
        f"the follow-up send used sequence {ok.get('sequence')}, expected it to "
        f"reuse the freed reservation {reserved} (no gap)"
    )
    post = client.channel_window(link_id)
    assert post["next_sequence"] == (reserved + 1) % 0x10000, (
        f"after the reused send next_sequence={post['next_sequence']}, expected "
        f"{(reserved + 1) % 0x10000}"
    )
