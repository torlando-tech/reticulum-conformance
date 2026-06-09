"""
Integration test fixtures for pipe-based conformance tests.

Tests connect a target implementation (subprocess) to the Python RNS reference
via PipeInterface (HDLC-framed stdin/stdout).
"""
import os
import pytest

from _rns_paths import resolve_rns_path


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
    """Resolve the command to launch the target pipe peer.

    --python-only: use the in-repo pipe_peer_local.py so PipeSession-based
    tests (announce / IFAC / channel) exercise the reference end-to-end with
    no external Swift/Kotlin binary required.
    --peer-cmd X: use X (typically a built SUT binary).
    Otherwise: auto-detect a Swift PipePeer build, else skip.
    """
    if request.config.getoption("--python-only"):
        local = os.path.join(os.path.dirname(__file__), "pipe_peer_local.py")
        return f"python3 {local}"
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
    """Find the Python RNS reference implementation.

    Skip (rather than fail) if RNS can't be located — the integration suite
    treats Python RNS as an optional reference for pipe-based tests.
    """
    try:
        return resolve_rns_path()
    except RuntimeError as e:
        pytest.skip(str(e))
