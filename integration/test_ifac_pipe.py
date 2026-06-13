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

    def test_python_announce_with_ifac_to_target(self, session):
        """Python announces with IFAC; matching-IFAC target validates and receives it."""
        session.start(
            peer_action="listen",
            peer_ifac_passphrase="secret",
            peer_ifac_netname="testnet",
            ifac_passphrase="secret",
            ifac_netname="testnet",
        )
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None, "Target did not emit 'ready'"

        # Python announces over the IFAC-masked interface.
        dest, identity = session.python_announce()
        dest_hash_hex = dest.hash.hex()

        # The target (matching IFAC) must validate the IFAC mask on Python's
        # process_outgoing output and actually deliver the announce — a real
        # receipt, not just "the subprocess didn't crash". A wrong IFAC mask on
        # either side would cause the target to drop the packet and emit nothing.
        msg = session.wait_for_announce_received(dest_hash=dest_hash_hex, timeout=15)
        assert msg is not None, (
            f"Target did not receive Python's IFAC-protected announce for {dest_hash_hex}"
        )
        assert msg["identity_hash"] == identity.hash.hex(), (
            f"Target recalled wrong identity: {msg['identity_hash']} != {identity.hash.hex()}"
        )
        assert msg["hops"] == 1, f"Expected 1 hop over direct pipe, got {msg['hops']}"
        # And the link is intact.
        assert session.process.poll() is None, (
            "Target crashed when receiving IFAC-protected announce from Python"
        )
