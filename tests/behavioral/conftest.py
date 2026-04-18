"""
Behavioral-test fixtures.

These tests use the `behavioral_*` bridge commands (see
reference/behavioral_transport.py). Each test gets a FRESH bridge
process — unlike the session-scoped `sut` fixture used by byte-level
tests — because Python RNS's Reticulum singleton state can't be
reset in-process, and reusing a singleton across tests with different
`enable_transport` values silently produces false-positive passes.
"""

import os
import secrets

import pytest

from bridge_client import BridgeClient
from conftest import get_impl_list, resolve_command


def pytest_generate_tests(metafunc):
    """Parametrize behavioral tests with the same impl list as the rest of
    the suite. We do this independently of the root conftest's `sut`-based
    parametrization because behavioral tests don't use `sut` directly
    (they use `behavioral`, which spawns a fresh bridge per-test).
    """
    if "behavioral_impl" in metafunc.fixturenames:
        impls = get_impl_list(metafunc.config) or ["reference"]
        metafunc.parametrize("behavioral_impl", impls, scope="function")


@pytest.fixture
def behavioral_impl(request):
    """Name of the impl under test (reference/kotlin/swift).

    Parametrized by `pytest_generate_tests` above.
    """
    return request.param


@pytest.fixture
def behavioral(behavioral_impl):
    """Helper bound to a FRESHLY-SPAWNED bridge process per test."""
    cmd = resolve_command(behavioral_impl)
    env = (
        {
            "PYTHON_RNS_PATH": os.environ.get(
                "PYTHON_RNS_PATH",
                os.path.expanduser("~/repos/Reticulum"),
            ),
            "PYTHON_LXMF_PATH": os.environ.get(
                "PYTHON_LXMF_PATH",
                os.path.expanduser("~/repos/LXMF"),
            ),
        }
        if behavioral_impl == "reference"
        else {}
    )
    client = BridgeClient(cmd, env=env)
    try:
        yield _BehavioralHarness(client)
    finally:
        client.close()


class _BehavioralHarness:
    def __init__(self, bridge):
        self.bridge = bridge
        self._handles = []

    def start(self, identity_seed_hex=None, enable_transport=True):
        if identity_seed_hex is None:
            identity_seed_hex = secrets.token_bytes(64).hex()
        resp = self.bridge.execute(
            "behavioral_start",
            identity_seed=identity_seed_hex,
            enable_transport=enable_transport,
        )
        handle = resp["handle"]
        self._handles.append(handle)
        return Instance(self.bridge, handle, bytes.fromhex(resp["identity_hash"]))

    def cleanup(self):
        for h in self._handles:
            try:
                self.bridge.execute("behavioral_stop", handle=h)
            except Exception:
                pass


class Instance:
    def __init__(self, bridge, handle, identity_hash):
        self.bridge = bridge
        self.handle = handle
        self.identity_hash = identity_hash

    def attach_mock_interface(self, name, mode="FULL", mtu=500):
        resp = self.bridge.execute(
            "behavioral_attach_mock_interface",
            handle=self.handle, name=name, mode=mode, mtu=mtu,
        )
        return resp["iface_id"]

    def inject(self, iface_id, raw):
        self.bridge.execute(
            "behavioral_inject",
            handle=self.handle, iface_id=iface_id, raw=raw.hex(),
        )

    def drain_tx(self, iface_id):
        resp = self.bridge.execute(
            "behavioral_drain_tx",
            handle=self.handle, iface_id=iface_id,
        )
        return [bytes.fromhex(p) for p in resp["packets"]]
