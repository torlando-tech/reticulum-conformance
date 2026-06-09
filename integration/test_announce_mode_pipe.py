"""
Announce mode filtering integration tests.

Tests the AnnounceFilter decision table from Python Transport.py:1040-1084.

Topology:
    A (announce) ──[pipe 0]──▶ B (transport, SUT) ◀──[pipe 1]── C (listen)

A announces a destination. B is a transport node with configurable interface
modes on its two interfaces. C checks whether the announce propagated through B.

The decision table for outgoing interface mode vs incoming interface mode:

    | Outgoing (C-side) | Source (A-side) | Forwarded? |
    |-------------------|-----------------|------------|
    | ACCESS_POINT      | any             | NO         |
    | ROAMING           | FULL            | YES        |
    | ROAMING           | ROAMING         | NO         |
    | ROAMING           | BOUNDARY        | NO         |
    | BOUNDARY          | FULL            | YES        |
    | BOUNDARY          | BOUNDARY        | YES        |
    | BOUNDARY          | ROAMING         | NO         |
    | FULL              | any             | YES        |

When target_cmd is None (default), B is a Python RNS transport node.
When --peer-cmd is provided, B is the Swift PipePeer.
"""
import os
import time
import pytest
from .three_node_session import ThreeNodeSession


@pytest.fixture(scope="session")
def local_peer_cmd():
    """Command to launch the in-repo conformance pipe peer.

    The announce-mode matrix runs entirely against the in-process Python
    transport (Node B) plus two pipe_peer_local.py subprocesses (A and C);
    no external Swift/Kotlin binary is required under --python-only.
    """
    path = os.path.join(os.path.dirname(__file__), "pipe_peer_local.py")
    assert os.path.exists(path), f"pipe_peer_local.py not found at {path}"
    return f"python3 {path}"


@pytest.fixture(scope="session")
def target_cmd(request):
    """Resolve the target command for Node B.

    --python-only: returns None (in-process Python B)
    --peer-cmd X: returns X
    Otherwise: auto-detect Swift PipePeer, fallback to None (Python B)
    """
    if request.config.getoption("--python-only"):
        return None
    cmd = request.config.getoption("--peer-cmd")
    if cmd:
        return cmd
    home = os.path.expanduser("~")
    swift_peer = os.path.join(home, "repos/reticulum-swift-lib/.build/release/PipePeer")
    if os.path.exists(swift_peer):
        return swift_peer
    return None  # Python-only fallback


def _assert_propagated(peer_c, announced, expected_hops=2, timeout=15):
    """Assert C received A's announce forwarded by B.

    Verifies not just that an announce arrived, but that B forwarded it as a
    relayed (transport) announce: the hop count at C is A→B→C == 2, and the
    identity C recalled is byte-identical to the one A announced (so a SUT that
    leaks a wrong/garbled identity or mis-counts hops fails).
    """
    dest_hash = announced["destination_hash"]
    msg = peer_c.wait_for_announce_received(dest_hash=dest_hash, timeout=timeout)
    assert msg is not None, f"C should receive A's forwarded announce ({dest_hash})"
    assert msg["hops"] == expected_hops, (
        f"Forwarded announce should be {expected_hops} hops at C (A->B->C), "
        f"got {msg['hops']}"
    )
    assert msg.get("identity_hash") == announced.get("identity_hash"), (
        f"C should recall the identity A announced "
        f"({announced.get('identity_hash')}), got {msg.get('identity_hash')}"
    )
    return msg


def _assert_no_propagation(peer_c, dest_hash, wait_time=5):
    """Assert that C does NOT receive an announce for dest_hash."""
    msg = peer_c.wait_for_announce_received(dest_hash=dest_hash, timeout=wait_time)
    assert msg is None, (
        f"C should NOT have received announce for {dest_hash}, but got: {msg}"
    )


# ─── Control: FULL → FULL (always forwards) ─────────────────────────────

class TestFullToFull:
    """FULL mode on both interfaces: announces always forwarded (control test)."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="full", b_mode_c="full", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_propagates_full_to_full(self, session):
        """A's announce reaches C through B when both interfaces are FULL."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None, "A did not become ready"
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None, "C did not become ready"

        if session.target_cmd is not None:
            b_ready = session.wait_for_b_ready(timeout=20)
            assert b_ready is not None, "B (target) did not become ready"

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None, "A did not announce"
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


# ─── ACCESS_POINT outgoing: always blocked ───────────────────────────────

class TestFullToAP:
    """AP mode on outgoing interface: announces never forwarded."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="full", b_mode_c="ap", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_blocked_on_ap_outgoing(self, session):
        """A's announce does NOT reach C when B's C-side interface is AP."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_no_propagation(session.peer_c, dest_hash)


# ─── ROAMING outgoing + FULL source: forwarded ──────────────────────────

class TestFullToRoaming:
    """ROAMING outgoing, FULL source: announce forwarded."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="full", b_mode_c="roaming", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_forwarded_full_to_roaming(self, session):
        """FULL source → ROAMING outgoing: announce IS forwarded."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


# ─── ROAMING outgoing + ROAMING source: blocked ─────────────────────────

class TestRoamingToRoaming:
    """ROAMING outgoing, ROAMING source: announce blocked."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="roaming", b_mode_c="roaming", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_blocked_roaming_to_roaming(self, session):
        """ROAMING source → ROAMING outgoing: announce is blocked."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_no_propagation(session.peer_c, dest_hash)


# ─── ROAMING outgoing + BOUNDARY source: blocked ────────────────────────

class TestBoundaryToRoaming:
    """ROAMING outgoing, BOUNDARY source: announce blocked."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="boundary", b_mode_c="roaming", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_blocked_boundary_to_roaming(self, session):
        """BOUNDARY source → ROAMING outgoing: announce is blocked."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_no_propagation(session.peer_c, dest_hash)


# ─── GATEWAY outgoing: allows everything (same as FULL) ─────────────────

class TestFullToGateway:
    """GATEWAY outgoing, FULL source: announce forwarded (gateway = full)."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="full", b_mode_c="gateway", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_forwarded_full_to_gateway(self, session):
        """FULL source → GATEWAY outgoing: announce IS forwarded."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


class TestRoamingToGateway:
    """GATEWAY outgoing, ROAMING source: announce forwarded (gateway allows all)."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="roaming", b_mode_c="gateway", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_forwarded_roaming_to_gateway(self, session):
        """ROAMING source → GATEWAY outgoing: announce IS forwarded."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


# ─── GATEWAY source: treated as FULL/GW/P2P group ───────────────────────

class TestGatewayToRoaming:
    """ROAMING outgoing, GATEWAY source: announce forwarded (GW is in FULL/GW/P2P group)."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="gateway", b_mode_c="roaming", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_forwarded_gateway_to_roaming(self, session):
        """GATEWAY source → ROAMING outgoing: announce IS forwarded."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


class TestGatewayToBoundary:
    """BOUNDARY outgoing, GATEWAY source: announce forwarded (GW is in FULL/GW/P2P group)."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="gateway", b_mode_c="boundary", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_forwarded_gateway_to_boundary(self, session):
        """GATEWAY source → BOUNDARY outgoing: announce IS forwarded."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


class TestGatewayToAP:
    """AP outgoing, GATEWAY source: announce blocked (AP blocks everything)."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="gateway", b_mode_c="ap", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_blocked_gateway_to_ap(self, session):
        """GATEWAY source → AP outgoing: announce is blocked (AP blocks all)."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_no_propagation(session.peer_c, dest_hash)


# ─── BOUNDARY outgoing + FULL source: forwarded ─────────────────────────

class TestFullToBoundary:
    """BOUNDARY outgoing, FULL source: announce forwarded."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="full", b_mode_c="boundary", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_forwarded_full_to_boundary(self, session):
        """FULL source → BOUNDARY outgoing: announce IS forwarded."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


# ─── BOUNDARY outgoing + BOUNDARY source: forwarded ─────────────────────

class TestBoundaryToBoundary:
    """BOUNDARY outgoing, BOUNDARY source: announce forwarded."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="boundary", b_mode_c="boundary", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_forwarded_boundary_to_boundary(self, session):
        """BOUNDARY source → BOUNDARY outgoing: announce IS forwarded."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_propagated(session.peer_c, announced)


# ─── BOUNDARY outgoing + ROAMING source: blocked ────────────────────────

class TestRoamingToBoundary:
    """BOUNDARY outgoing, ROAMING source: announce blocked."""

    @pytest.fixture
    def session(self, rns_path, target_cmd, local_peer_cmd):
        s = ThreeNodeSession(
            rns_path=rns_path,
            target_cmd=target_cmd,
            pipe_peer_cmd=local_peer_cmd,
        )
        s.start(b_mode_a="roaming", b_mode_c="boundary", a_action="announce", c_action="listen")
        yield s
        s.stop()

    def test_announce_blocked_roaming_to_boundary(self, session):
        """ROAMING source → BOUNDARY outgoing: announce is blocked."""
        a_ready = session.peer_a.wait_for_ready(timeout=20)
        assert a_ready is not None
        c_ready = session.peer_c.wait_for_ready(timeout=20)
        assert c_ready is not None

        if session.target_cmd is not None:
            session.wait_for_b_ready(timeout=20)

        announced = session.peer_a.wait_for_announced(timeout=15)
        assert announced is not None
        dest_hash = announced["destination_hash"]

        _assert_no_propagation(session.peer_c, dest_hash)
