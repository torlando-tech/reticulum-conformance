"""
Integration test fixtures for pipe-based conformance tests.

Tests connect a target implementation (subprocess) to the Python RNS reference
via PipeInterface (HDLC-framed stdin/stdout).
"""
import os
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--peer-cmd",
        default=None,
        help="Command to launch the target pipe peer binary.",
    )
    parser.addoption(
        "--python-only",
        action="store_true",
        default=False,
        help="Run three-node tests with Python-only SUT (no Swift binary needed).",
    )


@pytest.fixture(scope="session")
def peer_cmd(request):
    """Resolve the command to launch the target pipe peer."""
    cmd = request.config.getoption("--peer-cmd")
    if cmd:
        return cmd
    # Try auto-detect Swift PipePeer
    home = os.path.expanduser("~")
    swift_peer = os.path.join(home, "repos/reticulum-swift-lib/.build/release/PipePeer")
    if os.path.exists(swift_peer):
        return swift_peer
    pytest.skip("No pipe peer binary found. Build with: swift build -c release --product PipePeer")


@pytest.fixture(scope="session")
def rns_path():
    """Find the Python RNS reference implementation."""
    env = os.environ.get("PYTHON_RNS_PATH")
    if env:
        return env
    home = os.path.expanduser("~")
    for candidate in [
        os.path.join(home, "repos/Reticulum"),
        os.path.join(home, "repos/public/Reticulum"),
    ]:
        if os.path.isdir(candidate) and os.path.isdir(os.path.join(candidate, "RNS")):
            return candidate
    try:
        import importlib.util
        spec = importlib.util.find_spec("RNS")
        if spec and spec.origin:
            return os.path.dirname(os.path.dirname(spec.origin))
    except (ImportError, ValueError):
        pass
    pytest.skip("Cannot find Python RNS. Install with: pip install rns")
