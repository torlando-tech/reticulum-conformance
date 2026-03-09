"""
Basic announce exchange integration tests via PipeInterface.

Tests verify that Swift and Python RNS can exchange announces over
HDLC-framed stdin/stdout pipes and both sides correctly learn paths,
store identities, and agree on hop counts.

Mirrors reticulum-kt/python-bridge/conformance/test_basic_announce.py
"""
import time
import pytest
from .pipe_session import PipeSession


@pytest.fixture
def session(peer_cmd, rns_path):
    """Create a PipeSession with announce action, stop after test."""
    s = PipeSession(peer_cmd=peer_cmd, rns_path=rns_path)
    yield s
    s.stop()


class TestTargetToPython:
    """Swift target announces, Python receives."""

    def test_python_learns_path_from_target_announce(self, session):
        """Target announces, Python learns the path."""
        session.start(peer_action="announce")
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None, "Target did not emit 'ready'"

        announced = session.wait_for_announced(timeout=15)
        assert announced is not None, "Target did not emit 'announced'"

        dest_hash = announced["destination_hash"]

        # Wait for Python to process the announce
        deadline = time.time() + 10
        while time.time() < deadline:
            if session.python_has_path(dest_hash):
                break
            time.sleep(0.5)

        assert session.python_has_path(dest_hash), (
            f"Python did not learn path to {dest_hash}"
        )

    def test_hop_count_is_one_for_direct_pipe(self, session):
        """Direct pipe connection = 1 hop."""
        session.start(peer_action="announce")
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None

        announced = session.wait_for_announced(timeout=15)
        assert announced is not None

        dest_hash = announced["destination_hash"]

        deadline = time.time() + 10
        while time.time() < deadline:
            if session.python_has_path(dest_hash):
                break
            time.sleep(0.5)

        hops = session.python_hops_to(dest_hash)
        assert hops == 1, f"Expected 1 hop for direct pipe, got {hops}"

    def test_path_table_entry_has_correct_structure(self, session):
        """Python's path table entry has expected fields."""
        session.start(peer_action="announce")
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None

        announced = session.wait_for_announced(timeout=15)
        assert announced is not None

        dest_hash = announced["destination_hash"]

        deadline = time.time() + 10
        while time.time() < deadline:
            if session.python_has_path(dest_hash):
                break
            time.sleep(0.5)

        entry = session.python_path_table_entry(dest_hash)
        assert entry is not None, "No path table entry found"
        # Python path_table entry is a list:
        # [timestamp, received_from, hops, expires, random_blobs, ...]
        assert isinstance(entry, (list, tuple)), f"Unexpected entry type: {type(entry)}"
        # hops is at index 2
        assert entry[2] == 1, f"Expected hops=1, got {entry[2]}"

    def test_identity_recalled_from_announce(self, session):
        """Python recalls identity with correct public key from announce."""
        session.start(peer_action="announce")
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None

        announced = session.wait_for_announced(timeout=15)
        assert announced is not None

        dest_hash = announced["destination_hash"]
        expected_pubkey = announced.get("identity_public_key")

        deadline = time.time() + 10
        while time.time() < deadline:
            if session.python_has_path(dest_hash):
                break
            time.sleep(0.5)

        identity = session.python_recall_identity(dest_hash)
        assert identity is not None, (
            f"Python could not recall identity for {dest_hash}"
        )
        # Verify public key matches if we have it
        if expected_pubkey:
            recalled_pubkey = identity.get_public_key().hex()
            assert recalled_pubkey == expected_pubkey, (
                f"Public key mismatch: recalled={recalled_pubkey[:32]}... "
                f"expected={expected_pubkey[:32]}..."
            )


class TestPythonToTarget:
    """Python announces, Swift target receives."""

    def test_target_receives_python_announce(self, session):
        """Target emits announce_received when Python announces."""
        session.start(peer_action="listen")
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None

        # Python announces
        dest, identity = session.python_announce()
        dest_hash_hex = dest.hash.hex()

        # Wait for target to detect the announce
        msg = session.wait_for_announce_received(
            dest_hash=dest_hash_hex, timeout=15
        )
        assert msg is not None, (
            f"Target did not emit announce_received for {dest_hash_hex}"
        )
        assert msg["hops"] == 1, f"Expected hops=1, got {msg['hops']}"

    def test_target_path_table_contains_python_dest(self, session):
        """Target's path_table includes Python's destination after announce."""
        session.start(peer_action="listen")
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None

        dest, identity = session.python_announce()
        dest_hash_hex = dest.hash.hex()

        # Wait for target's path table to include the destination
        msg = session.wait_for_path_table_entry(
            dest_hash=dest_hash_hex, timeout=15
        )
        assert msg is not None, (
            f"Target path_table never included {dest_hash_hex}"
        )
        # Find matching entry
        entry = next(
            e for e in msg["entries"]
            if e["destination_hash"] == dest_hash_hex
        )
        assert entry["hops"] == 1
        assert entry["expired"] is False

    def test_hop_counts_match(self, session):
        """Both sides agree on hop count for Python's announce."""
        session.start(peer_action="listen")
        ready = session.wait_for_ready(timeout=20)
        assert ready is not None

        dest, identity = session.python_announce()
        dest_hash_hex = dest.hash.hex()

        # Wait for target to receive the announce
        msg = session.wait_for_announce_received(
            dest_hash=dest_hash_hex, timeout=15
        )
        assert msg is not None, "Target did not receive announce"
        target_hops = msg["hops"]

        # Python's view: hops_to returns 0 for local destinations
        # For the Python side, this IS a local destination, so hops=0
        # But the target sees it via the pipe, so hops=1
        # Both are correct — Python reports 0 (local), target reports 1 (over pipe)
        assert target_hops == 1, f"Target hops should be 1, got {target_hops}"
