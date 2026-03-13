"""
Path request conformance tests (3-node topology).

Tests that an implementation can both SEND and RESPOND TO path requests
through a transport relay.

Topology:
    Node A (announces dest D) ──[pipe 0]──▶ Node B (transport) ◀──[pipe 1]── Node C (requests path to D)

Two test perspectives on the same topology:

1. **B as SUT (responder)**: Swift runs as Node B (transport relay).
   A (Python) announces, B caches the path, C (Python) sends path request,
   B responds from cache. Tests handlePathRequest + respondWithCachedPath.

2. **C as SUT (requester)**: Swift runs as Node C (path requester).
   A (Python) announces, B (Python transport) caches the path,
   C (Swift) sends path request, B responds, C discovers path.
   Tests requestPath + path response handling.

Both perspectives also have Python-only baselines.
"""
import os
import tempfile
import pytest
from .three_node_session import ThreeNodeSession


@pytest.fixture(scope="session")
def local_peer_cmd():
    """Path to the local conformance pipe_peer with path_request support."""
    path = os.path.join(os.path.dirname(__file__), "pipe_peer_local.py")
    assert os.path.exists(path), f"pipe_peer_local.py not found at {path}"
    return f"python3 {path}"


@pytest.fixture(scope="session")
def target_cmd(request):
    """Target command for the SUT (None = Python, or Swift path)."""
    if request.config.getoption("--python-only"):
        return None
    cmd = request.config.getoption("--peer-cmd")
    if cmd:
        return cmd
    home = os.path.expanduser("~")
    swift_peer = os.path.join(home, "repos/reticulum-swift-lib/.build/release/PipePeer")
    if os.path.exists(swift_peer):
        return swift_peer
    return None


# ─── Perspective 1: B (transport relay) is the SUT ──────────────────────────


class TestPathRequestResponder:
    """B is SUT: receives path request from C, responds with cached path from A's announce.

    Flow:
    1. A announces destination D → B (SUT) caches path
    2. C sends path request for D
    3. B (SUT) finds D in path table, responds with cached announce
    4. C discovers path to D

    This tests the SUT's handlePathRequest + respondWithCachedPath.
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,  # B is SUT
            pipe_peer_cmd=local_peer_cmd,
        )
        # A announces, C sends path request.
        # C's interface on B is full — B has the path cached from A's announce
        # and should respond from cache (no DISCOVER_PATHS_FOR needed).
        s.start(
            b_mode_a="full", b_mode_c="full",
            a_action="announce",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_action="path_request",
            c_cmd=local_peer_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_sut_responds_to_path_request_from_cache(self, session):
        """SUT (B) responds to path request with cached path."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None, "A should emit ready"
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None, "C should emit ready"

        if session.target_cmd is not None:
            b_ready = session.wait_for_b_ready(timeout=20)
            assert b_ready is not None, "B (SUT) should emit ready"

        # A announces — B learns the path
        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None, "A should emit announced"
        dest_hash = announced["destination_hash"]

        # C sends path request → B responds from cache → C discovers
        discovered = session.peer_c.wait_for_path_discovered(
            dest_hash=dest_hash, timeout=30
        )
        assert discovered is not None, (
            f"B (SUT) should respond to path request from cache. "
            f"C should discover path to {dest_hash}"
        )
        assert discovered["hops"] >= 1, "Path should have at least 1 hop (through B)"


# ─── Perspective 2: C (path requester) is the SUT ───────────────────────────


class TestPathRequestRequester:
    """C is SUT: sends path request through B, discovers path to A's destination.

    Flow:
    1. A announces destination D → B (Python transport) caches path
    2. C (SUT) sends path request for D
    3. B responds with cached announce
    4. C (SUT) discovers path to D

    This tests the SUT's requestPath + path response handling (awaitPath).
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=None,  # B is Python (transport relay)
            pipe_peer_cmd=local_peer_cmd,
        )
        # A announces (Python), B is Python transport, C is SUT with path_request.
        # For C as SUT, we override c_cmd to use the target binary.
        c_cmd = target_cmd
        if c_cmd is None:
            # Python-only mode: C is also Python
            c_cmd = local_peer_cmd

        s.start(
            b_mode_a="full", b_mode_c="full",
            a_action="announce",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_action="path_request",
            c_cmd=c_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_sut_discovers_path_via_request(self, session):
        """SUT (C) requests path and discovers it through relay B."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None, "A should emit ready"
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None, "C (SUT) should emit ready"

        # A announces — B (Python transport) caches the path
        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None, "A should emit announced"
        dest_hash = announced["destination_hash"]

        # C (SUT) sends path request → B responds → C discovers
        discovered = session.peer_c.wait_for_path_discovered(
            dest_hash=dest_hash, timeout=30
        )
        assert discovered is not None, (
            f"C (SUT) should discover path via path request. "
            f"Expected path to {dest_hash}"
        )
        assert discovered["hops"] >= 1, "Path should have at least 1 hop (through B)"


# ─── Combined: SUT as both B and C ──────────────────────────────────────────


class TestPathRequestBothSUT:
    """Both B and C are SUT: A (Python) announces, B (SUT transport) caches,
    C (SUT) requests path, B responds.

    When a target binary is available, both B and C run as Swift.
    In python-only mode, all three nodes are Python (sanity check).
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        # B is target (Swift or Python in-process)
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,  # B is SUT when target exists, else Python
            pipe_peer_cmd=local_peer_cmd,
        )
        # C is target when available, else Python
        c_cmd = target_cmd if target_cmd is not None else local_peer_cmd

        s.start(
            b_mode_a="full", b_mode_c="full",
            a_action="announce",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_action="path_request",
            c_cmd=c_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_both_sut_path_request_roundtrip(self, session):
        """B responds, C discovers — full path request roundtrip."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None, "A should emit ready"
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None, "C should emit ready"

        if session.target_cmd is not None:
            b_ready = session.wait_for_b_ready(timeout=20)
            assert b_ready is not None, "B (SUT) should emit ready"

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None, "A should emit announced"
        dest_hash = announced["destination_hash"]

        discovered = session.peer_c.wait_for_path_discovered(
            dest_hash=dest_hash, timeout=30
        )
        assert discovered is not None, (
            f"C should discover path to {dest_hash} via B"
        )
        assert discovered["hops"] >= 1
