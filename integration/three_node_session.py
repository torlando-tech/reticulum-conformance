"""
Three-node pipe session for announce mode filtering tests.

Topology:
    Node A (subprocess) ──[pipe 0]──▶ Node B (SUT transport) ◀──[pipe 1]── Node C (subprocess)

Node B is the system under test — a transport node with two interfaces.
Each interface can have a different mode (full, roaming, boundary, ap).

Node A and Node C are Python pipe_peer.py subprocesses that announce
destinations and report via stderr JSON messages.

For all-Python validation:
  B is an in-process Python RNS instance. Its two interfaces are created
  directly with specified modes.

For Swift validation:
  B is the Swift PipePeer subprocess with PIPE_PEER_NUM_IFACES=2 and
  per-interface mode environment variables.
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time


# Default path to the Kotlin pipe_peer.py (works on this machine)
_DEFAULT_PIPE_PEER = os.path.expanduser(
    "~/repos/reticulum-kt/python-bridge/pipe_peer.py"
)


class _SubprocessPeer:
    """A pipe_peer.py subprocess connected via a pipe pair."""

    def __init__(self, cmd, env):
        self.cmd = cmd
        self.env = env
        self.process = None
        self._messages = []
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._thread = None

    def start(self, fd_in, fd_out):
        """Start the subprocess with given fd pair for stdin/stdout."""
        self.process = subprocess.Popen(
            shlex.split(self.cmd),
            stdin=fd_in,
            stdout=fd_out,
            stderr=subprocess.PIPE,
            env=self.env,
        )
        self._thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._thread.start()

    def _read_stderr(self):
        try:
            for line in self.process.stderr:
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    with self._cond:
                        self._messages.append(msg)
                        self._cond.notify_all()
                except json.JSONDecodeError:
                    pass
        except (ValueError, OSError):
            pass

    def wait_for_message(self, msg_type, timeout=15, predicate=None):
        deadline = time.time() + timeout
        with self._cond:
            while time.time() < deadline:
                for msg in self._messages:
                    if msg.get("type") == msg_type:
                        if predicate is None or predicate(msg):
                            self._messages.remove(msg)
                            return msg
                remaining = deadline - time.time()
                if remaining > 0:
                    self._cond.wait(timeout=min(remaining, 0.5))
        return None

    def wait_for_ready(self, timeout=20):
        return self.wait_for_message("ready", timeout=timeout)

    def wait_for_announced(self, timeout=15):
        return self.wait_for_message("announced", timeout=timeout)

    def wait_for_announce_received(self, dest_hash=None, timeout=15):
        def predicate(msg):
            if dest_hash is not None:
                return msg.get("destination_hash") == dest_hash
            return True
        return self.wait_for_message(
            "announce_received", timeout=timeout, predicate=predicate
        )

    def wait_for_path_table_entry(self, dest_hash, timeout=15):
        def predicate(msg):
            entries = msg.get("entries", [])
            return any(e.get("destination_hash") == dest_hash for e in entries)
        return self.wait_for_message(
            "path_table", timeout=timeout, predicate=predicate
        )

    def wait_for_destination_created(self, timeout=15):
        return self.wait_for_message("destination_created", timeout=timeout)

    def wait_for_path_discovered(self, dest_hash=None, timeout=20):
        def predicate(msg):
            if dest_hash is not None:
                return msg.get("destination_hash") == dest_hash
            return True
        return self.wait_for_message(
            "path_discovered", timeout=timeout, predicate=predicate
        )

    def wait_for_path_not_found(self, dest_hash=None, timeout=25):
        def predicate(msg):
            if dest_hash is not None:
                return msg.get("destination_hash") == dest_hash
            return True
        return self.wait_for_message(
            "path_not_found", timeout=timeout, predicate=predicate
        )

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


class ThreeNodeSession:
    """
    Three-node test harness: A ↔ B(transport) ↔ C

    When target_cmd is None, B is a Python RNS instance (all-Python mode).
    When target_cmd is set, B is the target subprocess (e.g. Swift PipePeer).
    """

    def __init__(self, rns_path, target_cmd=None, pipe_peer_cmd=None):
        self.rns_path = rns_path
        self.target_cmd = target_cmd
        if pipe_peer_cmd:
            self.pipe_peer_cmd = pipe_peer_cmd
        else:
            self.pipe_peer_cmd = f"python3 {_DEFAULT_PIPE_PEER}"

        # Python RNS (for in-process B)
        self.RNS = None
        self.b_reticulum = None
        self.b_pipe_a = None  # B's interface facing A
        self.b_pipe_c = None  # B's interface facing C
        self._b_config_path = None

        # Swift/target subprocess (when target_cmd is set)
        self.b_process = None
        self._b_stderr_thread = None
        self._b_messages = []
        self._b_lock = threading.Lock()
        self._b_cond = threading.Condition(self._b_lock)

        # Subprocess peers
        self.peer_a = None
        self.peer_c = None

    def start(
        self,
        b_mode_a="full",
        b_mode_c="full",
        a_action="announce",
        c_action="listen",
        a_env=None,
        c_env=None,
        a_cmd=None,
        c_cmd=None,
    ):
        """
        Start the three-node topology.

        b_mode_a: mode for B's interface facing A
        b_mode_c: mode for B's interface facing C
        a_action: what Node A does (announce/listen)
        c_action: what Node C does (announce/listen)
        """
        # Pipe pair 1: A ↔ B
        a_to_b_r, a_to_b_w = os.pipe()
        b_to_a_r, b_to_a_w = os.pipe()

        # Pipe pair 2: C ↔ B
        c_to_b_r, c_to_b_w = os.pipe()
        b_to_c_r, b_to_c_w = os.pipe()

        if self.target_cmd is None:
            # All-Python mode: B is in-process
            self._start_python_b(
                b_mode_a, b_mode_c,
                a_to_b_r, b_to_a_w,
                c_to_b_r, b_to_c_w,
            )
        else:
            # Target subprocess mode (Swift)
            self._start_target_b(
                b_mode_a, b_mode_c,
                a_to_b_r, b_to_a_w,
                c_to_b_r, b_to_c_w,
            )

        # Start peer A: reads from b_to_a_r, writes to a_to_b_w
        self.peer_a = self._make_peer(a_action, extra_env=a_env, cmd_override=a_cmd)
        self.peer_a.start(b_to_a_r, a_to_b_w)
        # Close these fds in parent — peer inherited them
        os.close(b_to_a_r)
        os.close(a_to_b_w)

        # Start peer C: reads from b_to_c_r, writes to c_to_b_w
        self.peer_c = self._make_peer(c_action, extra_env=c_env, cmd_override=c_cmd)
        self.peer_c.start(b_to_c_r, c_to_b_w)
        os.close(b_to_c_r)
        os.close(c_to_b_w)

    def stop(self):
        if self.peer_a:
            self.peer_a.stop()
        if self.peer_c:
            self.peer_c.stop()
        if self.b_pipe_a:
            self.b_pipe_a.online = False
        if self.b_pipe_c:
            self.b_pipe_c.online = False
        if self.b_process:
            self.b_process.terminate()
            try:
                self.b_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.b_process.kill()
                self.b_process.wait()
        if self.b_reticulum:
            self.RNS.Reticulum.exit_handler()
            self.RNS.Reticulum._Reticulum__instance = None
            T = self.RNS.Transport
            T.interfaces = []
            T.destinations = []
            T.announce_handlers = []
            T.path_table = {}
            T.packet_hashlist = set()
            T.identity = None
            T.announce_table = {}
            T.reverse_table = {}
            T.link_table = {}
            T.held_announces = {}
            T.discovery_path_requests = {}
            T.pending_local_path_requests = {}
            T.local_client_interfaces = []
            T.local_client_rssi_cache = []
            T.local_client_snr_cache = []
            T.local_client_q_cache = []
            if hasattr(T, 'rate_table'):
                T.rate_table = {}
            self.b_reticulum = None
        if self._b_config_path:
            import shutil
            shutil.rmtree(self._b_config_path, ignore_errors=True)

    # ─── Peer Factory ────────────────────────────────────────────────────

    def _make_peer(self, action, extra_env=None, cmd_override=None):
        env = os.environ.copy()
        env["PIPE_PEER_ACTION"] = action
        env["PIPE_PEER_APP_NAME"] = "pipetest"
        env["PIPE_PEER_ASPECTS"] = "routing"
        env["PIPE_PEER_TRANSPORT"] = "false"
        env["PIPE_PEER_MODE"] = "full"
        if "PYTHON_RNS_PATH" not in env:
            env["PYTHON_RNS_PATH"] = self.rns_path
        if extra_env:
            env.update(extra_env)
        cmd = cmd_override or self.pipe_peer_cmd
        return _SubprocessPeer(cmd, env)

    # ─── Python B (in-process transport) ─────────────────────────────────

    def _start_python_b(self, mode_a, mode_c,
                        a_to_b_r, b_to_a_w,
                        c_to_b_r, b_to_c_w):
        sys.path.insert(0, self.rns_path)
        import RNS
        self.RNS = RNS
        RNS.loglevel = RNS.LOG_CRITICAL

        self._b_config_path = tempfile.mkdtemp(prefix="rns_node_b_")
        config_file = os.path.join(self._b_config_path, "config")
        with open(config_file, "w") as f:
            f.write("[reticulum]\n")
            f.write("  enable_transport = Yes\n")
            f.write("  share_instance = No\n")
            f.write("\n[interfaces]\n")

        self.b_reticulum = RNS.Reticulum(
            configdir=self._b_config_path, loglevel=RNS.LOG_CRITICAL
        )

        from RNS.Interfaces.Interface import Interface as BaseInterface
        mode_map = {
            "full": BaseInterface.MODE_FULL,
            "ap": BaseInterface.MODE_ACCESS_POINT,
            "access_point": BaseInterface.MODE_ACCESS_POINT,
            "roaming": BaseInterface.MODE_ROAMING,
            "boundary": BaseInterface.MODE_BOUNDARY,
            "gateway": BaseInterface.MODE_GATEWAY,
            "p2p": BaseInterface.MODE_POINT_TO_POINT,
        }

        # Interface facing A
        self.b_pipe_a = self._make_hdlc_pipe(
            "B_facing_A",
            os.fdopen(a_to_b_r, 'rb', buffering=0),
            os.fdopen(b_to_a_w, 'wb', buffering=0),
            mode_map.get(mode_a.lower(), BaseInterface.MODE_FULL),
        )
        self.b_pipe_a.owner = RNS.Transport
        self.b_reticulum._add_interface(
            self.b_pipe_a, mode=mode_map.get(mode_a.lower(), BaseInterface.MODE_FULL)
        )

        # Interface facing C
        self.b_pipe_c = self._make_hdlc_pipe(
            "B_facing_C",
            os.fdopen(c_to_b_r, 'rb', buffering=0),
            os.fdopen(b_to_c_w, 'wb', buffering=0),
            mode_map.get(mode_c.lower(), BaseInterface.MODE_FULL),
        )
        self.b_pipe_c.owner = RNS.Transport
        self.b_reticulum._add_interface(
            self.b_pipe_c, mode=mode_map.get(mode_c.lower(), BaseInterface.MODE_FULL)
        )

    # ─── Target B (subprocess, e.g. Swift) ───────────────────────────────

    def _start_target_b(self, mode_a, mode_c,
                        a_to_b_r, b_to_a_w,
                        c_to_b_r, b_to_c_w):
        env = os.environ.copy()
        env["PIPE_PEER_ACTION"] = "listen"
        env["PIPE_PEER_TRANSPORT"] = "true"
        env["PIPE_PEER_NUM_IFACES"] = "2"
        env["PIPE_PEER_IFACE_0_FD_IN"] = str(a_to_b_r)
        env["PIPE_PEER_IFACE_0_FD_OUT"] = str(b_to_a_w)
        env["PIPE_PEER_IFACE_0_MODE"] = mode_a
        env["PIPE_PEER_IFACE_1_FD_IN"] = str(c_to_b_r)
        env["PIPE_PEER_IFACE_1_FD_OUT"] = str(b_to_c_w)
        env["PIPE_PEER_IFACE_1_MODE"] = mode_c

        pass_fds = (a_to_b_r, b_to_a_w, c_to_b_r, b_to_c_w)

        self.b_process = subprocess.Popen(
            shlex.split(self.target_cmd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            pass_fds=pass_fds,
            env=env,
        )

        # Close B's fds in parent
        os.close(a_to_b_r)
        os.close(b_to_a_w)
        os.close(c_to_b_r)
        os.close(b_to_c_w)

        self._b_stderr_thread = threading.Thread(
            target=self._read_b_stderr, daemon=True
        )
        self._b_stderr_thread.start()

    def _read_b_stderr(self):
        try:
            for line in self.b_process.stderr:
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    with self._b_cond:
                        self._b_messages.append(msg)
                        self._b_cond.notify_all()
                except json.JSONDecodeError:
                    pass
        except (ValueError, OSError):
            pass

    def wait_for_b_ready(self, timeout=20):
        deadline = time.time() + timeout
        with self._b_cond:
            while time.time() < deadline:
                for msg in self._b_messages:
                    if msg.get("type") == "ready":
                        self._b_messages.remove(msg)
                        return msg
                remaining = deadline - time.time()
                if remaining > 0:
                    self._b_cond.wait(timeout=min(remaining, 0.5))
        return None

    # ─── HDLC Pipe (reusable) ────────────────────────────────────────────

    @staticmethod
    def _make_hdlc_pipe(name, pin, pout, mode_const):
        from RNS.Interfaces.Interface import Interface as BaseInterface

        class _HdlcPipe(BaseInterface):
            FLAG = 0x7E
            ESC = 0x7D
            ESC_MASK = 0x20

            def __init__(self, iname, ipin, ipout, imode):
                super().__init__()
                self.HW_MTU = 1064
                self.name = iname
                self.online = False
                self.bitrate = 1000000
                self.IN = True
                self.OUT = True
                self.mode = imode
                self._pin = ipin
                self._pout = ipout
                self.online = True
                threading.Thread(target=self._read_loop, daemon=True).start()

            def process_outgoing(self, data):
                if not self.online:
                    return
                escaped = data.replace(
                    bytes([self.ESC]), bytes([self.ESC, self.ESC ^ self.ESC_MASK])
                )
                escaped = escaped.replace(
                    bytes([self.FLAG]), bytes([self.ESC, self.FLAG ^ self.ESC_MASK])
                )
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
                return self.name

        return _HdlcPipe(name, pin, pout, mode_const)
