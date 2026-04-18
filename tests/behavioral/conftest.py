"""
Behavioral-test fixtures.

These tests use the `behavioral_*` bridge commands (see
reference/behavioral_transport.py). Each test gets a fresh Transport
instance per impl with a deterministic identity seed so runs are
reproducible across the matrix.
"""

import secrets

import pytest


@pytest.fixture
def behavioral(sut):
    """Helper bound to the system-under-test bridge.

    Parametrized via pytest's `sut` fixture — `--impl=kotlin` targets the
    Kotlin bridge, `--impl=swift` the Swift bridge, `--reference-only` runs
    against the Python reference as a sanity check.
    """
    return _BehavioralHarness(sut)


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
