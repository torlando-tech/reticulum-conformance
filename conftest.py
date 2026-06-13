"""
Pytest configuration for Reticulum conformance tests.

Provides fixtures for the reference implementation and system under test (SUT).
Tests compare SUT output against reference output to verify conformance.
"""

import os
import warnings

import pytest

from _rns_paths import resolve_rns_path
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
    "swift": "{root}/../reticulum-swift/.build/release/ConformanceBridge",
    "kotlin": "java -jar {root}/../reticulum-kt/conformance-bridge/build/libs/ConformanceBridge.jar",
    "microreticulum": "{root}/impls/microreticulum/build/microReticulumBridge",
}

# Per-impl env var names. When set, override BRIDGE_COMMANDS[impl].
PER_IMPL_CMD_ENV = {
    "reference": "CONFORMANCE_REFERENCE_BRIDGE_CMD",
    "swift": "CONFORMANCE_SWIFT_BRIDGE_CMD",
    "kotlin": "CONFORMANCE_KOTLIN_BRIDGE_CMD",
    "microreticulum": "CONFORMANCE_MICRORETICULUM_BRIDGE_CMD",
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
    """Get list of implementations to test.

    Returns the impls to parametrize `sut` over. `--reference-only` is the
    EXPLICIT escape that makes the reference its own SUT (a sanity run);
    `--impl=X` selects one impl. With neither flag, the default is every
    registered non-reference impl whose bridge is actually built on disk —
    which may be EMPTY. An empty default result is NOT silently mapped to
    reference (that was the false-confidence hole, V3 §7.4); pytest_generate_tests
    hard-fails on it so a certification run can never self-certify by accident.
    """
    impl = config.getoption("--impl")
    if impl:
        return [impl]
    if config.getoption("--reference-only"):
        # Explicit operator choice: run the reference as its own SUT.
        return ["reference"]
    # Default: test every registered implementation (except reference) whose
    # bridge binary/JAR is actually present on disk. The existence gate applies
    # uniformly to all non-reference impls (swift, kotlin, microreticulum, ...):
    # a registered-but-unbuilt impl must NOT be parametrized in, or the suite
    # fails at subprocess spawn instead of cleanly skipping. The last
    # whitespace-split token of the resolved command is the executable/JAR path
    # (this also handles the `java -jar X.jar` form).
    impls = []
    for name in BRIDGE_COMMANDS:
        if name == "reference":
            continue
        cmd = resolve_command(name)
        if os.path.exists(cmd.split()[-1]):
            impls.append(name)
    return impls


@pytest.fixture(scope="session")
def reference():
    """Reference implementation bridge (Python RNS)."""
    cmd = resolve_command("reference")
    env = {
        "PYTHON_RNS_PATH": resolve_rns_path(),
    }
    client = BridgeClient(cmd, env=env)
    yield client
    client.close()


def pytest_generate_tests(metafunc):
    """Parametrize tests with SUT implementations."""
    if "sut" in metafunc.fixturenames:
        impls = get_impl_list(metafunc.config)
        if not impls:
            # Collection-only passes execute NO tests, so they need no SUT
            # bridge: the @conformance_case drift guard
            # (tools/check_conformance_decorated.py) and the TESTS.md generator
            # (tools/generate_tests_md.py) both run `pytest --collect-only` with
            # no --impl and may run where no bridge is built (e.g. the `honesty`
            # CI job, which installs no bridge). §7.4's anti-self-certification
            # gate is about RUNS, not metadata enumeration — so exempt
            # --collect-only and parametrize a harmless placeholder (never spawned
            # under --collect-only) so test items still generate for the guard.
            if metafunc.config.getoption("collectonly", False):
                metafunc.parametrize(
                    "sut_impl", ["reference"], indirect=True, scope="session"
                )
                return
            # No --impl, no --reference-only, and no built bridge on disk. Do
            # NOT silently fall back to reference-as-SUT — that lets a
            # certification run self-certify (V3 §7.4). Hard-fail with an
            # actionable message; --reference-only is the explicit escape for a
            # reference-vs-reference sanity run.
            checked = ", ".join(
                f"{name} ({resolve_command(name).split()[-1]})"
                for name in BRIDGE_COMMANDS
                if name != "reference"
            )
            raise pytest.UsageError(
                "No system-under-test bridge resolved: --impl was not given, "
                "--reference-only was not set, and no registered bridge is built "
                f"on disk (checked: {checked}). A certification run must target a "
                "real implementation. Pass --impl=<name>, build a bridge, or pass "
                "--reference-only to explicitly run reference-as-SUT."
            )
        metafunc.parametrize("sut_impl", impls, indirect=True, scope="session")


@pytest.fixture(scope="session")
def sut_impl(request):
    """System under test bridge."""
    impl_name = request.param
    cmd = resolve_command(impl_name)
    env = {}
    if impl_name == "reference":
        env = {
            "PYTHON_RNS_PATH": resolve_rns_path(),
        }
    client = BridgeClient(cmd, env=env)
    yield client
    client.close()


@pytest.fixture
def sut(sut_impl):
    """Alias for sut_impl to use in tests."""
    return sut_impl


@pytest.fixture
def sut_impl_name(request):
    """The impl name this test's `sut` is parametrized with ('reference',
    'kotlin', ...). For impl-keyed xfails: assert the reference arm FIRST,
    then xfail the SUT arm, so the waiver never weakens reference pinning."""
    # `callspec` is None for a non-parametrized item. Every current caller also
    # requests `sut` (so pytest_generate_tests parametrizes sut_impl and sets
    # callspec), but guard anyway so a future caller without `sut` cleanly
    # defaults to "reference" rather than crashing with AttributeError at
    # collection.
    callspec = getattr(request.node, "callspec", None)
    if callspec is None:
        return "reference"
    return callspec.params.get("sut_impl", "reference")


# Utility functions for tests
def random_hex(n):
    """Generate n random bytes as hex string."""
    return os.urandom(n).hex()


def assert_hex_equal(actual, expected, msg="", allow_empty=False):
    """Assert two hex strings are equal (case-insensitive).

    By default this REFUSES the both-empty / both-None case: two absent
    optional fields (e.g. a missing ``transport_id`` on a HEADER_1 packet)
    would otherwise each coalesce to ``""`` and compare equal, so the
    assertion would vacuously pass while asserting nothing (audit finding L6).
    Pass ``allow_empty=True`` only when an empty value on both sides is the
    intended, meaningful assertion.
    """
    actual_lower = actual.lower() if actual else ""
    expected_lower = expected.lower() if expected else ""
    if not allow_empty:
        assert actual_lower or expected_lower, (
            f"{msg}: refusing to compare two empty/None hex values "
            f"(actual={actual!r}, expected={expected!r}); both sides are "
            f"absent so this comparison would vacuously pass. Pass "
            f"allow_empty=True if an empty value is the intended assertion."
        )
    assert actual_lower == expected_lower, (
        f"{msg}: expected {expected_lower}, got {actual_lower}"
    )
