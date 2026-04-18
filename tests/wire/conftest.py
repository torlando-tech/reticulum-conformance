"""Wire-level (E2E) fixtures.

Unlike byte-level tests (one bridge as sut, one as reference, each fed test
vectors) and unlike behavioral tests (one bridge with MockInterface-buffered
packets), wire tests pair TWO live Reticulum instances over a loopback TCP
link and observe the result of real packet exchange.

The `wire_peers` fixture spawns two bridge subprocesses — one server-role,
one client-role — with caller-selectable impls. Each bridge is fresh per
test (Python RNS is a process-singleton; Kotlin's Reticulum.stop() works
but the bridge boundary is simpler to reason about with fresh processes).

See reference/wire_tcp.py and conformance-bridge/src/main/kotlin/WireTcp.kt
for the `wire_*` command surface these fixtures drive.
"""

import os
import secrets

import pytest

from bridge_client import BridgeClient
from conftest import get_impl_list, resolve_command


def _env_for(impl: str) -> dict:
    """Env vars the reference Python bridge needs; Kotlin ignores them."""
    if impl != "reference":
        return {}
    return {
        "PYTHON_RNS_PATH": os.environ.get(
            "PYTHON_RNS_PATH",
            os.path.expanduser("~/repos/Reticulum"),
        ),
        "PYTHON_LXMF_PATH": os.environ.get(
            "PYTHON_LXMF_PATH",
            os.path.expanduser("~/repos/LXMF"),
        ),
    }


def pytest_generate_tests(metafunc):
    """Parametrize wire tests over EVERY (server_impl, client_impl) pair.

    For impls ["reference", "kotlin"] that's 4 pairs per test. The
    homogeneous pairs (reference↔reference, kotlin↔kotlin) are useful
    smoke tests: they isolate whether a failure is interop-specific vs.
    just broken end-to-end on one side. The heterogeneous pairs are the
    real cross-impl assertion.
    """
    if "wire_pair" in metafunc.fixturenames:
        impls = get_impl_list(metafunc.config) or []
        # Always include the reference so a cross-impl test actually tests
        # something; a single-impl run (e.g. --impl kotlin with no reference
        # in the impl list) would otherwise skip the whole interop point.
        peers = sorted(set(impls) | {"reference"})
        pairs = [(a, b) for a in peers for b in peers]
        ids = [f"{a}-to-{b}" for a, b in pairs]
        metafunc.parametrize("wire_pair", pairs, ids=ids, scope="function")


class _WirePeer:
    """Thin convenience wrapper around a BridgeClient.

    Holds the peer's handle and exposes the five wire_* commands as methods.
    Each method just forwards to `bridge.execute` and returns the decoded
    response fields the tests care about.
    """

    def __init__(self, bridge: BridgeClient, role_label: str):
        self.bridge = bridge
        self.role_label = role_label  # purely for error messages
        self.handle: str | None = None
        self.identity_hash: bytes | None = None
        self.port: int | None = None

    def start_tcp_server(self, network_name: str, passphrase: str) -> int:
        resp = self.bridge.execute(
            "wire_start_tcp_server",
            network_name=network_name,
            passphrase=passphrase,
        )
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])
        self.port = int(resp["port"])
        return self.port

    def start_tcp_client(
        self, network_name: str, passphrase: str, target_host: str, target_port: int
    ):
        resp = self.bridge.execute(
            "wire_start_tcp_client",
            network_name=network_name,
            passphrase=passphrase,
            target_host=target_host,
            target_port=target_port,
        )
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])

    def announce(self, app_name: str, aspects: list, app_data: bytes = b"") -> bytes:
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_announce",
            handle=self.handle,
            app_name=app_name,
            aspects=list(aspects),
            app_data=app_data.hex(),
        )
        return bytes.fromhex(resp["destination_hash"])

    def poll_path(self, destination_hash: bytes, timeout_ms: int = 5000) -> bool:
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_poll_path",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            timeout_ms=timeout_ms,
        )
        return bool(resp.get("found"))

    def stop(self):
        if self.handle is None:
            return
        try:
            self.bridge.execute("wire_stop", handle=self.handle)
        except Exception:
            pass
        self.handle = None


@pytest.fixture
def wire_pair(request):
    """Return (server_impl, client_impl) tuple from pytest_generate_tests."""
    return request.param


@pytest.fixture
def wire_peers(wire_pair):
    """Two freshly-spawned bridge subprocesses, one server-role, one client-role.

    Yields (server, client) as `_WirePeer` objects. Caller is responsible for
    calling `server.start_tcp_server(...)` and `client.start_tcp_client(...)`
    with the port the server returns. Both bridges are torn down in the
    fixture finalizer regardless of whether the test raised.
    """
    server_impl, client_impl = wire_pair
    server_bridge = BridgeClient(
        resolve_command(server_impl), env=_env_for(server_impl)
    )
    client_bridge = BridgeClient(
        resolve_command(client_impl), env=_env_for(client_impl)
    )
    server = _WirePeer(server_bridge, role_label=f"server({server_impl})")
    client = _WirePeer(client_bridge, role_label=f"client({client_impl})")

    try:
        yield server, client
    finally:
        # Stop both peers before tearing down the pipe — mirrors the
        # behavioral fixture pattern so an in-process teardown hook on
        # the bridge side (e.g. Reticulum.stop) gets a chance to run
        # cleanly before its stdin closes.
        for peer in (server, client):
            try:
                peer.stop()
            except Exception:
                pass
        for b in (server_bridge, client_bridge):
            try:
                b.close()
            except Exception:
                pass
