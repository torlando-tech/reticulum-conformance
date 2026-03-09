"""
Path discovery forwarding tests (DISCOVER_PATHS_FOR).

Tests that a transport node proactively forwards path requests from
gateway/AP/roaming interfaces to other interfaces, and does NOT forward
from full/boundary/p2p interfaces.

Python reference: Interface.DISCOVER_PATHS_FOR = [MODE_ACCESS_POINT, MODE_GATEWAY, MODE_ROAMING]
Note: MODE_FULL is NOT in DISCOVER_PATHS_FOR.

Topology:
    A (has destination D) ──[pipe 0]──▶ B (transport) ◀──[pipe 1]── C (sends path request)

Flow for "discover" tests (unknown path):
    1. A creates destination D (no announce) → reports hash → writes to temp file
    2. C reads hash from temp file → sends path request for D
    3. B receives request on C's interface:
       - If C's mode is in DISCOVER_PATHS_FOR: B forwards request to A
         A's RNS auto-announces D → announce propagates → C discovers path
       - If C's mode is NOT in DISCOVER_PATHS_FOR: B ignores request
         C never discovers path (path_not_found)

Both A and C use pipe_peer_local.py (local conformance peer with destination_only
and path_request actions).
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
def kt_peer_cmd():
    """Path to the Kotlin pipe_peer.py."""
    path = os.path.expanduser("~/repos/reticulum-kt/python-bridge/pipe_peer.py")
    if not os.path.exists(path):
        pytest.skip("pipe_peer.py not found")
    return f"python3 {path}"


@pytest.fixture(scope="session")
def target_cmd(request):
    """Target command for Node B (None = Python, or Swift path)."""
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


class TestDiscoverPathsGateway:
    """Gateway interface triggers proactive path discovery.

    C's interface on B is gateway (in DISCOVER_PATHS_FOR).
    A has destination D but hasn't announced.
    C sends path request for D.
    B should forward the request to A → A auto-announces → C discovers path.
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, kt_peer_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=kt_peer_cmd,
        )
        s.start(
            b_mode_a="full", b_mode_c="gateway",
            a_action="destination_only", c_action="path_request",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_cmd=local_peer_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_gateway_discovers_unknown_path(self, session):
        """Gateway mode: B forwards path request → A responds → C discovers path."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None, "A should emit ready"
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None, "C should emit ready"

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        # A creates destination and writes hash to file
        dest_msg = session.peer_a.wait_for_destination_created(timeout=15)
        assert dest_msg is not None, "A should emit destination_created"
        dest_hash = dest_msg["destination_hash"]

        # C reads hash from file, sends path request, B forwards (gateway mode)
        # A auto-announces in response → C discovers the path
        discovered = session.peer_c.wait_for_path_discovered(
            dest_hash=dest_hash, timeout=30
        )
        assert discovered is not None, (
            f"Gateway mode should trigger path discovery forwarding. "
            f"C should discover path to {dest_hash}"
        )
        assert discovered["hops"] >= 1


class TestDiscoverPathsAP:
    """Access Point interface triggers proactive path discovery.

    Same as gateway test but with AP mode on C's interface.
    AP is in DISCOVER_PATHS_FOR.
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, kt_peer_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=kt_peer_cmd,
        )
        s.start(
            b_mode_a="full", b_mode_c="ap",
            a_action="destination_only", c_action="path_request",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_cmd=local_peer_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_ap_discovers_unknown_path(self, session):
        """AP mode: B forwards path request → A responds → C discovers path."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        dest_msg = session.peer_a.wait_for_destination_created(timeout=15)
        assert dest_msg is not None
        dest_hash = dest_msg["destination_hash"]

        discovered = session.peer_c.wait_for_path_discovered(
            dest_hash=dest_hash, timeout=30
        )
        assert discovered is not None, (
            f"AP mode should trigger path discovery forwarding. "
            f"C should discover path to {dest_hash}"
        )


class TestDiscoverPathsRoaming:
    """Roaming interface triggers proactive path discovery.

    Roaming is in DISCOVER_PATHS_FOR.
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, kt_peer_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=kt_peer_cmd,
        )
        s.start(
            b_mode_a="full", b_mode_c="roaming",
            a_action="destination_only", c_action="path_request",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_cmd=local_peer_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_roaming_discovers_unknown_path(self, session):
        """Roaming mode: B forwards path request → A responds → C discovers path."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        dest_msg = session.peer_a.wait_for_destination_created(timeout=15)
        assert dest_msg is not None
        dest_hash = dest_msg["destination_hash"]

        discovered = session.peer_c.wait_for_path_discovered(
            dest_hash=dest_hash, timeout=30
        )
        assert discovered is not None, (
            f"Roaming mode should trigger path discovery forwarding. "
            f"C should discover path to {dest_hash}"
        )


class TestDiscoverPathsFullBlocked:
    """Full interface does NOT trigger proactive path discovery.

    C's interface on B is full (NOT in DISCOVER_PATHS_FOR).
    A has destination D but hasn't announced.
    C sends path request for D.
    B should NOT forward the request → C never discovers path.
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, kt_peer_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=kt_peer_cmd,
        )
        s.start(
            b_mode_a="full", b_mode_c="full",
            a_action="destination_only", c_action="path_request",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_cmd=local_peer_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_full_does_not_discover_unknown_path(self, session):
        """Full mode: B ignores path request → C never discovers path."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        dest_msg = session.peer_a.wait_for_destination_created(timeout=15)
        assert dest_msg is not None
        dest_hash = dest_msg["destination_hash"]

        # C sends path request but B should NOT forward it (full mode)
        # C should get path_not_found
        not_found = session.peer_c.wait_for_path_not_found(
            dest_hash=dest_hash, timeout=30
        )
        assert not_found is not None, (
            f"Full mode should NOT trigger path discovery forwarding. "
            f"C should get path_not_found for {dest_hash}"
        )


class TestDiscoverPathsBoundaryBlocked:
    """Boundary interface does NOT trigger proactive path discovery.

    Boundary is NOT in DISCOVER_PATHS_FOR.
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, kt_peer_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=kt_peer_cmd,
        )
        s.start(
            b_mode_a="full", b_mode_c="boundary",
            a_action="destination_only", c_action="path_request",
            a_cmd=local_peer_cmd,
            a_env={"PIPE_PEER_HASH_OUTPUT_FILE": hash_file_path},
            c_cmd=local_peer_cmd,
            c_env={"PIPE_PEER_PATH_REQUEST_DEST_FILE": hash_file_path},
        )
        yield s
        s.stop()
        try:
            os.unlink(hash_file_path)
        except OSError:
            pass

    def test_boundary_does_not_discover_unknown_path(self, session):
        """Boundary mode: B ignores path request → C never discovers path."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        dest_msg = session.peer_a.wait_for_destination_created(timeout=15)
        assert dest_msg is not None
        dest_hash = dest_msg["destination_hash"]

        not_found = session.peer_c.wait_for_path_not_found(
            dest_hash=dest_hash, timeout=30
        )
        assert not_found is not None, (
            f"Boundary mode should NOT trigger path discovery forwarding. "
            f"C should get path_not_found for {dest_hash}"
        )


class TestKnownPathResponse:
    """B knows the path and responds from cache — works for ALL modes.

    This is the baseline: A announces, B learns path, C requests path,
    B responds from cache. This should work regardless of C's interface mode
    because B already knows the path (no DISCOVER_PATHS_FOR needed).
    """

    @pytest.fixture
    def session(self, rns_path, target_cmd, kt_peer_cmd, local_peer_cmd):
        hash_file = tempfile.NamedTemporaryFile(
            prefix="dest_hash_", suffix=".txt", delete=False
        )
        hash_file.close()
        hash_file_path = hash_file.name

        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=kt_peer_cmd,
        )
        # A announces (B learns path), C sends path request.
        # C's interface is full — announce forwarding full→full works,
        # so C would learn the path via announce. But the path_request
        # should also work (B answers from cache).
        # Use AP on C's side to block the announce but still test
        # known-path response.
        s.start(
            b_mode_a="full", b_mode_c="ap",
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

    def test_known_path_response(self, session):
        """B responds to path request from cache even on AP interface."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        # B learned the path from A's announce. C sends path request.
        # Even though C's interface is AP, B should respond from cache.
        # (DISCOVER_PATHS_FOR only gates unknown-path forwarding.)
        discovered = session.peer_c.wait_for_path_discovered(
            dest_hash=dest_hash, timeout=30
        )
        assert discovered is not None, (
            f"B should respond to path request from cache (known path). "
            f"C should discover path to {dest_hash}"
        )
