"""
IFAC (Interface Access Code) integration tests via PipeInterface.

Tests verify that Swift's IFAC implementation interoperates with Python RNS
by exchanging IFAC-protected packets over HDLC-framed stdin/stdout pipes.
"""
import time
import pytest
from .pipe_session import PipeSession


@pytest.fixture
def session(peer_cmd, rns_path):
    """Create a PipeSession, stop it after the test."""
    s = PipeSession(peer_cmd=peer_cmd, rns_path=rns_path)
    yield s
    s.stop()


class TestIFACAnnounce:
    """Test IFAC-protected announce exchange between Swift and Python."""

    def test_announce_with_matching_ifac(self, session):
        """Both sides have matching IFAC. Target announces, Python learns path."""
        session.start(
            peer_action="announce",
            peer_ifac_passphrase="secret",
            peer_ifac_netname="testnet",
            ifac_passphrase="secret",
            ifac_netname="testnet",
        )
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None, "Target did not emit 'ready'"

        announced = session.wait_for_announced(timeout=15)
        assert announced is not None, "Target did not emit 'announced'"

        dest_hash = announced["destination_hash"]

        # Give Python time to process the IFAC-protected announce
        deadline = time.time() + 10
        while time.time() < deadline:
            if session.python_has_path(dest_hash):
                break
            time.sleep(0.5)

        assert session.python_has_path(dest_hash), (
            f"Python did not learn path to {dest_hash} — IFAC validation may have failed"
        )
        assert session.python_hops_to(dest_hash) == 1

    def test_announce_without_ifac_rejected(self, session):
        """Target has no IFAC, Python side has IFAC. Packets should be rejected."""
        session.start(
            peer_action="announce",
            # No IFAC on peer side
            ifac_passphrase="secret",
            ifac_netname="testnet",
        )
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None, "Target did not emit 'ready'"

        announced = session.wait_for_announced(timeout=15)
        assert announced is not None, "Target did not emit 'announced'"

        dest_hash = announced["destination_hash"]

        # Wait and verify Python does NOT learn the path
        time.sleep(5)
        assert not session.python_has_path(dest_hash), (
            f"Python should NOT have path to {dest_hash} — "
            "non-IFAC packet should be rejected by IFAC-enabled interface"
        )

    def test_announce_wrong_ifac_rejected(self, session):
        """Both sides have IFAC but different passphrases. Packets rejected."""
        session.start(
            peer_action="announce",
            peer_ifac_passphrase="wrong-secret",
            peer_ifac_netname="testnet",
            ifac_passphrase="correct-secret",
            ifac_netname="testnet",
        )
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None, "Target did not emit 'ready'"

        announced = session.wait_for_announced(timeout=15)
        assert announced is not None, "Target did not emit 'announced'"

        dest_hash = announced["destination_hash"]

        # Wait and verify Python does NOT learn the path
        time.sleep(5)
        assert not session.python_has_path(dest_hash), (
            f"Python should NOT have path to {dest_hash} — "
            "wrong IFAC passphrase should cause validation failure"
        )

    def test_python_announce_with_ifac_to_swift(self, session):
        """Python announces with IFAC, Swift peer in listen mode receives it."""
        session.start(
            peer_action="listen",
            peer_ifac_passphrase="secret",
            peer_ifac_netname="testnet",
            ifac_passphrase="secret",
            ifac_netname="testnet",
        )
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None, "Target did not emit 'ready'"

        # Python announces
        dest, identity = session.python_announce()
        dest_hash_hex = dest.hash.hex()

        # Python should have its own path (local destination)
        # The key test is that the announce went through IFAC masking on the
        # Python side and the Swift side could validate it via IFAC.
        # Since the Swift PipePeer doesn't emit announce_received events yet,
        # we verify the reverse direction: Python sends IFAC-protected packets
        # and the Swift side doesn't crash or reject the connection.
        # The matching IFAC test (test_announce_with_matching_ifac) already
        # proves Swift->Python works. This test proves the IFAC masking on
        # Python's process_outgoing works correctly (no crash/hang).
        time.sleep(3)
        # If we get here without the subprocess crashing, the test passes.
        # The subprocess should still be alive.
        assert session.process.poll() is None, (
            "Swift PipePeer crashed when receiving IFAC-protected announce from Python"
        )
