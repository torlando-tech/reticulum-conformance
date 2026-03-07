"""
Bridge client for communicating with implementation bridge servers.

Each implementation provides a CLI executable that speaks a JSON protocol
over stdin/stdout. This client manages the subprocess lifecycle and
provides a clean API for sending commands and receiving responses.
"""

import json
import subprocess
import os
import signal
import time


class BridgeError(Exception):
    """Error returned by bridge server."""

    def __init__(self, message, command=None):
        super().__init__(message)
        self.command = command


class BridgeClient:
    """Client for communicating with a bridge server subprocess."""

    def __init__(self, command, timeout=30, env=None):
        """
        Start a bridge server subprocess.

        Args:
            command: Shell command to start the bridge (string or list)
            timeout: Seconds to wait for READY signal
            env: Optional environment variables dict (merged with os.environ)
        """
        self.command = command
        self._req_counter = 0

        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)

        if isinstance(command, str):
            shell = True
        else:
            shell = False

        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
            env=proc_env,
            text=True,
            bufsize=1,
        )

        # Wait for READY signal
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self._proc.stdout.readline().strip()
            if line == "READY":
                return
            if not line and self._proc.poll() is not None:
                stderr = self._proc.stderr.read()
                raise BridgeError(
                    f"Bridge process exited before READY: {stderr}"
                )
        raise BridgeError(f"Bridge did not send READY within {timeout}s")

    def execute(self, command, **params):
        """
        Send a command and return the result.

        Args:
            command: Command name (e.g., "sha256")
            **params: Command parameters

        Returns:
            Result dict from bridge server

        Raises:
            BridgeError: If the bridge returns an error
        """
        self._req_counter += 1
        req_id = f"req-{self._req_counter}"

        request = {
            "id": req_id,
            "command": command,
            "params": params,
        }

        line = json.dumps(request) + "\n"
        self._proc.stdin.write(line)
        self._proc.stdin.flush()

        # Read lines until we get a JSON response (skip non-JSON output
        # like warnings from underlying libraries)
        while True:
            response_line = self._proc.stdout.readline()
            if not response_line:
                stderr = self._proc.stderr.read()
                raise BridgeError(
                    f"Bridge closed stdout (stderr: {stderr})", command=command
                )
            if response_line.strip().startswith("{"):
                break

        response = json.loads(response_line)

        if not response.get("success"):
            error_msg = response.get("error", "Unknown error")
            raise BridgeError(error_msg, command=command)

        return response.get("result", {})

    def close(self):
        """Shut down the bridge server subprocess."""
        if self._proc and self._proc.poll() is None:
            self._proc.stdin.close()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
