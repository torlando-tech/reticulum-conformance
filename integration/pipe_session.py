"""
Pipe peer session management for integration tests.

Manages the lifecycle of:
  1. A Python RNS instance (reference implementation)
  2. A target implementation subprocess (connected via PipeInterface)

Both communicate via HDLC-framed stdin/stdout. The Python side has direct
access to RNS internals for assertions. The target side reports state via
JSON on stderr.

Adapted from reticulum-kt/python-bridge/conformance/pipe_session.py with
IFAC support added.
"""
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time


class PipeSession:
    """
    Manages a Python RNS <-> target implementation pipe connection.

    Usage:
        session = PipeSession(peer_cmd=".build/release/PipePeer", rns_path="...")
        session.start(action="announce", ifac_passphrase="secret", ifac_netname="testnet")
        # ... run assertions ...
        session.stop()
    """

    def __init__(self, peer_cmd, rns_path, peer_env=None):
        self.peer_cmd = peer_cmd
        self.rns_path = rns_path
        self.peer_env = peer_env or {}

        # Python RNS state
        self.RNS = None
        self.reticulum = None
        self.pipe_iface = None
        self.identity = None
        self.destination = None
        self._config_path = None

        # Target subprocess
        self.process = None
        self._stderr_thread = None
        self._stderr_messages = []
        self._stderr_lock = threading.Lock()
        self._stderr_cond = threading.Condition(self._stderr_lock)

    def start(
        self,
        action="listen",
        app_name="pipetest",
        aspects="routing",
        enable_transport=False,
        peer_action="listen",
        peer_app_name="pipetest",
        peer_aspects="routing",
        peer_transport=False,
        peer_mode="full",
        ifac_passphrase=None,
        ifac_netname=None,
        peer_ifac_passphrase=None,
        peer_ifac_netname=None,
    ):
        """Start both Python RNS and the target subprocess.

        IFAC params:
            ifac_passphrase/ifac_netname: IFAC config for the Python side
            peer_ifac_passphrase/peer_ifac_netname: IFAC config for the target side
        """
        self._start_python_rns(action, app_name, aspects, enable_transport)
        self._start_peer(
            peer_action, peer_app_name, peer_aspects, peer_transport, peer_mode,
            peer_ifac_passphrase, peer_ifac_netname,
        )
        self._configure_ifac(ifac_passphrase, ifac_netname)

    def stop(self):
        """Shut down both sides."""
        if self.pipe_iface:
            self.pipe_iface.online = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.reticulum:
            self.RNS.Reticulum.exit_handler()
            self.RNS.Reticulum._Reticulum__instance = None
            self.RNS.Transport.interfaces = []
            self.RNS.Transport.destinations = []
            self.RNS.Transport.announce_handlers = []
            self.RNS.Transport.path_table = {}
            self.RNS.Transport.packet_hashlist = set()
            self.RNS.Transport.identity = None
            self.reticulum = None
        if self._config_path:
            import shutil
            shutil.rmtree(self._config_path, ignore_errors=True)

    # --- Python RNS Setup ---

    def _start_python_rns(self, action, app_name, aspects, enable_transport):
        sys.path.insert(0, self.rns_path)
        import RNS
        self.RNS = RNS

        RNS.loglevel = RNS.LOG_CRITICAL

        self._config_path = tempfile.mkdtemp(prefix="rns_conformance_py_")
        config_file = os.path.join(self._config_path, "config")
        os.makedirs(self._config_path, exist_ok=True)
        with open(config_file, "w") as f:
            f.write("[reticulum]\n")
            f.write(f"  enable_transport = {'Yes' if enable_transport else 'No'}\n")
            f.write("  share_instance = No\n")
            f.write("\n[interfaces]\n")

        self.reticulum = RNS.Reticulum(configdir=self._config_path, loglevel=RNS.LOG_CRITICAL)

    def _configure_ifac(self, passphrase, netname):
        """Configure IFAC on the Python-side pipe interface."""
        if passphrase is None and netname is None:
            return
        if self.pipe_iface is None:
            return

        RNS = self.RNS

        # Derive IFAC key exactly as Python Reticulum._add_interface does
        ifac_origin = b""
        if netname is not None:
            ifac_origin += RNS.Identity.full_hash(netname.encode("utf-8"))
        if passphrase is not None:
            ifac_origin += RNS.Identity.full_hash(passphrase.encode("utf-8"))

        ifac_origin_hash = RNS.Identity.full_hash(ifac_origin)
        ifac_key = RNS.Cryptography.hkdf(
            length=64,
            derive_from=ifac_origin_hash,
            salt=RNS.Reticulum.IFAC_SALT,
            context=None,
        )

        self.pipe_iface.ifac_key = ifac_key
        self.pipe_iface.ifac_identity = RNS.Identity.from_bytes(ifac_key)
        self.pipe_iface.ifac_size = 16

    def _create_pipe_interface(self):
        """Create StdioPipeInterface connected to subprocess stdin/stdout."""
        from RNS.Interfaces.Interface import Interface as BaseInterface

        process = self.process

        class _StdioPipe(BaseInterface):
            FLAG = 0x7E
            ESC = 0x7D
            ESC_MASK = 0x20

            def __init__(self):
                super().__init__()
                self.HW_MTU = 1064
                self.name = "ConformancePipe"
                self.online = False
                self.bitrate = 1000000
                self.IN = True
                self.OUT = True
                self._pin = process.stdout
                self._pout = process.stdin
                self.online = True
                threading.Thread(target=self._read_loop, daemon=True).start()

            def process_outgoing(self, data):
                if not self.online:
                    return
                escaped = data.replace(bytes([self.ESC]), bytes([self.ESC, self.ESC ^ self.ESC_MASK]))
                escaped = escaped.replace(bytes([self.FLAG]), bytes([self.ESC, self.FLAG ^ self.ESC_MASK]))
                frame = bytes([self.FLAG]) + escaped + bytes([self.FLAG])
                try:
                    self._pout.write(frame)
                    self._pout.flush()
                    self.txb += len(data)
                except (BrokenPipeError, OSError):
                    self.online = False

            def _read_loop(self):
                try:
                    in_frame = False
                    escape = False
                    buf = b""
                    while self.online:
                        chunk = self._pin.read(1)
                        if not chunk:
                            break
                        byte = chunk[0]
                        if in_frame and byte == self.FLAG:
                            in_frame = False
                            if buf:
                                self.process_incoming(buf)
                        elif byte == self.FLAG:
                            in_frame = True
                            buf = b""
                        elif in_frame and len(buf) < self.HW_MTU:
                            if byte == self.ESC:
                                escape = True
                            else:
                                if escape:
                                    if byte == self.FLAG ^ self.ESC_MASK:
                                        byte = self.FLAG
                                    elif byte == self.ESC ^ self.ESC_MASK:
                                        byte = self.ESC
                                    escape = False
                                buf += bytes([byte])
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    self.online = False

            def process_incoming(self, data):
                self.rxb += len(data)
                if hasattr(self, "owner") and self.owner is not None:
                    self.owner.inbound(data, self)

            def __str__(self):
                return "ConformancePipe"

        iface = _StdioPipe()
        iface.owner = self.RNS.Transport
        self.reticulum._add_interface(iface)
        self.pipe_iface = iface
        return iface

    # --- Target Subprocess ---

    def _start_peer(self, action, app_name, aspects, transport, mode,
                    ifac_passphrase=None, ifac_netname=None):
        env = os.environ.copy()
        env["PIPE_PEER_ACTION"] = action
        env["PIPE_PEER_APP_NAME"] = app_name
        env["PIPE_PEER_ASPECTS"] = aspects
        env["PIPE_PEER_TRANSPORT"] = "true" if transport else "false"
        env["PIPE_PEER_MODE"] = mode
        if ifac_passphrase is not None:
            env["PIPE_PEER_IFAC_PASSPHRASE"] = ifac_passphrase
        if ifac_netname is not None:
            env["PIPE_PEER_IFAC_NETNAME"] = ifac_netname
        if "PYTHON_RNS_PATH" not in env:
            env["PYTHON_RNS_PATH"] = self.rns_path
        env.update(self.peer_env)

        self.process = subprocess.Popen(
            shlex.split(self.peer_cmd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

        # Connect pipe interface AFTER process is started
        self._create_pipe_interface()

        # Start stderr reader
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()

    def _read_stderr(self):
        try:
            for line in self.process.stderr:
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    with self._stderr_cond:
                        self._stderr_messages.append(msg)
                        self._stderr_cond.notify_all()
                except json.JSONDecodeError:
                    pass
        except (ValueError, OSError):
            pass

    # --- Message Waiting ---

    def wait_for_message(self, msg_type, timeout=15, predicate=None):
        """Wait for a specific message type from the target's stderr."""
        deadline = time.time() + timeout
        with self._stderr_cond:
            while time.time() < deadline:
                for msg in self._stderr_messages:
                    if msg.get("type") == msg_type:
                        if predicate is None or predicate(msg):
                            self._stderr_messages.remove(msg)
                            return msg
                remaining = deadline - time.time()
                if remaining > 0:
                    self._stderr_cond.wait(timeout=min(remaining, 0.5))
        return None

    def wait_for_ready(self, timeout=20):
        return self.wait_for_message("ready", timeout=timeout)

    def wait_for_announced(self, timeout=15):
        return self.wait_for_message("announced", timeout=timeout)

    # --- Python-side Actions ---

    def python_announce(self, app_name="pipetest", aspects=("routing",)):
        """Create a Python destination and announce it."""
        self.identity = self.RNS.Identity()
        self.destination = self.RNS.Destination(
            self.identity,
            self.RNS.Destination.IN,
            self.RNS.Destination.SINGLE,
            app_name,
            *aspects,
        )
        self.destination.announce()
        return self.destination, self.identity

    def python_has_path(self, dest_hash_hex):
        """Check if Python RNS has a path to the given destination."""
        dest_bytes = bytes.fromhex(dest_hash_hex)
        return self.RNS.Transport.has_path(dest_bytes)

    def python_hops_to(self, dest_hash_hex):
        """Get hops to destination from Python's perspective."""
        dest_bytes = bytes.fromhex(dest_hash_hex)
        if self.RNS.Transport.has_path(dest_bytes):
            return self.RNS.Transport.hops_to(dest_bytes)
        return None

    def python_path_table_entry(self, dest_hash_hex):
        """Get raw path table entry from Python RNS Transport for a destination."""
        dest_bytes = bytes.fromhex(dest_hash_hex)
        return self.RNS.Transport.path_table.get(dest_bytes)

    def python_recall_identity(self, dest_hash_hex):
        """Recall an identity from Python's identity storage by destination hash."""
        dest_bytes = bytes.fromhex(dest_hash_hex)
        return self.RNS.Identity.recall(dest_bytes)

    # --- Target Message Waiters ---

    def wait_for_announce_received(self, dest_hash=None, timeout=15):
        """Wait for target to emit an announce_received message."""
        def predicate(msg):
            if dest_hash is not None:
                return msg.get("destination_hash") == dest_hash
            return True
        return self.wait_for_message("announce_received", timeout=timeout, predicate=predicate)

    def wait_for_path_table_entry(self, dest_hash, timeout=15):
        """Wait for target's path_table to contain a specific destination."""
        def predicate(msg):
            entries = msg.get("entries", [])
            return any(e.get("destination_hash") == dest_hash for e in entries)
        return self.wait_for_message("path_table", timeout=timeout, predicate=predicate)
