"""
Channel integration tests focused on proof-driven send window recovery.

A broken implementation can still deliver one or two channel messages while
failing to validate the returned link proofs locally. In that case, the sender's
channel window never reopens, so a later channel send stalls or the link is
closed.

This test makes that sender-side forward progress observable from the outside.
"""
import threading
import time

import pytest

from .pipe_session import PipeSession


class BridgeMessageFactory:
    @staticmethod
    def make(RNS):
        class BridgeMessage(RNS.Channel.MessageBase):
            MSGTYPE = 0x0101

            def __init__(self, data=b""):
                self.data = data

            def pack(self):
                return self.data

            def unpack(self, raw):
                self.data = raw

        return BridgeMessage


@pytest.fixture(scope="module")
def session(peer_cmd, rns_path):
    s = PipeSession(peer_cmd=peer_cmd, rns_path=rns_path)
    s.start(peer_action="channel_serve")
    ready = s.wait_for_ready(timeout=20)
    assert ready is not None, "Target did not emit 'ready'"
    yield s
    s.stop()


@pytest.fixture(scope="module")
def target_dest(session):
    announced = session.wait_for_announced(timeout=15)
    if announced is None:
        error = session.wait_for_error(timeout=1)
        if error and "Unknown action" in error.get("message", ""):
            pytest.skip(f"Pipe peer does not support channel_serve: {error['message']}")
        pytest.fail("Target did not emit 'announced'")

    dest_hash = announced["destination_hash"]
    deadline = time.time() + 15
    while time.time() < deadline:
        if session.python_has_path(dest_hash):
            break
        time.sleep(0.2)

    assert session.python_has_path(dest_hash), (
        f"Python should learn path to target destination {dest_hash}"
    )
    return announced


@pytest.fixture
def active_link(session, target_dest):
    RNS = session.RNS
    dest_hash = target_dest["destination_hash"]
    identity = RNS.Identity.recall(bytes.fromhex(dest_hash))
    assert identity is not None, "Should have identity from announce"

    dest = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "pipetest",
        "routing",
    )
    link = RNS.Link(dest)

    deadline = time.time() + 15
    while time.time() < deadline:
        if link.status == RNS.Link.ACTIVE:
            break
        time.sleep(0.1)

    assert link.status == RNS.Link.ACTIVE, (
        f"Link should become ACTIVE, got status {link.status}"
    )

    established = session.wait_for_link_established(timeout=15)
    assert established is not None, "Target should emit link_established"

    yield link

    if link.status == RNS.Link.ACTIVE:
        link.teardown()
        time.sleep(0.5)


class TestChannelSendWindow:
    def test_target_reopens_channel_window_after_proofs(self, session, active_link):
        RNS = session.RNS
        BridgeMessage = BridgeMessageFactory.make(RNS)
        channel = active_link.get_channel()
        channel.register_message_type(BridgeMessage)

        received = []
        cond = threading.Condition()

        def on_channel_message(message):
            if isinstance(message, BridgeMessage):
                with cond:
                    received.append(bytes(message.data))
                    cond.notify_all()
                return True
            return False

        channel.add_message_handler(on_channel_message)

        expected = [b"channel-one", b"channel-two", b"channel-three"]
        deadline = time.time() + 15
        with cond:
            while time.time() < deadline and len(received) < len(expected):
                cond.wait(timeout=min(deadline - time.time(), 0.5))

        assert received[:3] == expected, (
            f"Expected proof-gated channel sequence {expected}, got {received}"
        )
        assert active_link.status == RNS.Link.ACTIVE, (
            "Link should remain active after the channel proof exchange"
        )
        assert session.wait_for_error(timeout=1.5) is None, (
            "Target should not report a stalled channel send"
        )
        assert session.wait_for_link_closed(timeout=1.5) is None, (
            "Target should not close the link during the channel sequence"
        )
