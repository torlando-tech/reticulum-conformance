"""
Pytest configuration for Reticulum conformance tests.

Provides fixtures for the reference implementation and system under test (SUT).
Tests compare SUT output against reference output to verify conformance.
"""

import os
import pytest

from bridge_client import BridgeClient

# Bridge commands for each implementation.
#
# Per-impl env overrides take precedence over the defaults below — this is
# how CI injects freshly-built bridges without hardcoding repo layouts.
#
# The legacy CONFORMANCE_BRIDGE_CMD override applies to ALL impls. This
# silently breaks cross-impl parametrization: tests that think they're
# running `reference->reference->reference` actually run the override bridge
# for every peer, masking any xfail keyed off transport_impl == "kotlin".
# Scheduled for removal once downstream CI migrates to the per-impl vars.
BRIDGE_COMMANDS = {
    "reference": "python3 {root}/reference/bridge_server.py",
    "swift": "{root}/../reticulum-swift-lib/.build/release/ConformanceBridge",
    "kotlin": "java -jar {root}/../reticulum-kt/conformance-bridge/build/libs/ConformanceBridge.jar",
}

# Per-impl env var names. When set, override BRIDGE_COMMANDS[impl].
PER_IMPL_CMD_ENV = {
    "reference": "CONFORMANCE_REFERENCE_BRIDGE_CMD",
    "swift": "CONFORMANCE_SWIFT_BRIDGE_CMD",
    "kotlin": "CONFORMANCE_KOTLIN_BRIDGE_CMD",
}

# Root directory of the conformance suite
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve_command(impl_name):
    """Resolve bridge command for an implementation.

    Precedence (highest first):
      1. Per-impl env var (CONFORMANCE_{IMPL}_BRIDGE_CMD)
      2. Legacy CONFORMANCE_BRIDGE_CMD (DEPRECATED — applies to every impl,
         which breaks cross-impl parametrization; a deprecation warning is
         emitted so CI migrations are visible)
      3. Default from BRIDGE_COMMANDS with {root} substitution
    """
    per_impl_var = PER_IMPL_CMD_ENV.get(impl_name)
    if per_impl_var:
        per_impl_cmd = os.environ.get(per_impl_var)
        if per_impl_cmd:
            return per_impl_cmd

    legacy_cmd = os.environ.get("CONFORMANCE_BRIDGE_CMD")
    if legacy_cmd:
        import warnings
        warnings.warn(
            "CONFORMANCE_BRIDGE_CMD is deprecated because it applies to "
            f"every peer regardless of impl (peer requested: {impl_name!r}). "
            "Set per-impl vars instead: "
            + ", ".join(sorted(PER_IMPL_CMD_ENV.values()))
            + ". See conftest.py:resolve_command for migration details.",
            DeprecationWarning,
            stacklevel=2,
        )
        return legacy_cmd

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
        if name in ("swift", "kotlin"):
            if os.path.exists(cmd.split()[-1]):
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
