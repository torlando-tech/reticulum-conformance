"""
Pytest configuration for Reticulum conformance tests.

Provides fixtures for the reference implementation and system under test (SUT).
Tests compare SUT output against reference output to verify conformance.
"""

import os
import pytest

from bridge_client import BridgeClient

# Bridge commands for each implementation
# Override with CONFORMANCE_BRIDGE_CMD environment variable for custom bridges
BRIDGE_COMMANDS = {
    "reference": "python3 {root}/reference/bridge_server.py",
    "swift": "{root}/impls/swift/.build/release/SwiftBridge",
    "kotlin": "java -jar {root}/impls/kotlin/build/libs/KotlinBridge.jar",
}

# Root directory of the conformance suite
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve_command(impl_name):
    """Resolve bridge command for an implementation."""
    cmd = os.environ.get("CONFORMANCE_BRIDGE_CMD")
    if cmd:
        return cmd
    if impl_name not in BRIDGE_COMMANDS:
        raise ValueError(f"Unknown implementation: {impl_name}")
    return BRIDGE_COMMANDS[impl_name].format(root=ROOT_DIR)


def pytest_addoption(parser):
    parser.addoption(
        "--impl",
        action="store",
        default=None,
        help="Run tests for a specific implementation only (e.g., swift, kotlin)",
    )
    parser.addoption(
        "--reference-only",
        action="store_true",
        default=False,
        help="Run tests against reference implementation only (sanity check)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow")


def get_impl_list(config):
    """Get list of implementations to test."""
    impl = config.getoption("--impl")
    if impl:
        return [impl]
    if config.getoption("--reference-only"):
        return []
    # Default: test all registered implementations except reference
    impls = []
    for name in BRIDGE_COMMANDS:
        if name == "reference":
            continue
        cmd = resolve_command(name)
        # Check if the bridge executable/JAR exists
        if name == "swift":
            if os.path.exists(cmd):
                impls.append(name)
        elif name == "kotlin":
            jar_path = os.path.join(ROOT_DIR, "impls/kotlin/build/libs/KotlinBridge.jar")
            if os.path.exists(jar_path):
                impls.append(name)
        else:
            impls.append(name)
    return impls


@pytest.fixture(scope="session")
def reference():
    """Reference implementation bridge (Python RNS)."""
    cmd = resolve_command("reference")
    env = {
        "PYTHON_RNS_PATH": os.environ.get(
            "PYTHON_RNS_PATH",
            os.path.expanduser("~/repos/Reticulum"),
        ),
        "PYTHON_LXMF_PATH": os.environ.get(
            "PYTHON_LXMF_PATH",
            os.path.expanduser("~/repos/LXMF"),
        ),
    }
    client = BridgeClient(cmd, env=env)
    yield client
    client.close()


def pytest_generate_tests(metafunc):
    """Parametrize tests with SUT implementations."""
    if "sut" in metafunc.fixturenames:
        impls = get_impl_list(metafunc.config)
        if not impls:
            # reference-only mode: use reference as SUT
            impls = ["reference"]
        metafunc.parametrize("sut_impl", impls, indirect=True, scope="session")


@pytest.fixture(scope="session")
def sut_impl(request):
    """System under test bridge."""
    impl_name = request.param
    cmd = resolve_command(impl_name)
    env = {}
    if impl_name == "reference":
        env = {
            "PYTHON_RNS_PATH": os.environ.get(
                "PYTHON_RNS_PATH",
                os.path.expanduser("~/repos/Reticulum"),
            ),
            "PYTHON_LXMF_PATH": os.environ.get(
                "PYTHON_LXMF_PATH",
                os.path.expanduser("~/repos/LXMF"),
            ),
        }
    client = BridgeClient(cmd, env=env)
    yield client
    client.close()


@pytest.fixture
def sut(sut_impl):
    """Alias for sut_impl to use in tests."""
    return sut_impl


# Utility functions for tests
def random_hex(n):
    """Generate n random bytes as hex string."""
    return os.urandom(n).hex()


def assert_hex_equal(actual, expected, msg=""):
    """Assert two hex strings are equal (case-insensitive)."""
    actual_lower = actual.lower() if actual else ""
    expected_lower = expected.lower() if expected else ""
    assert actual_lower == expected_lower, (
        f"{msg}: expected {expected_lower}, got {actual_lower}"
    )
