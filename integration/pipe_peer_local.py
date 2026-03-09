#!/usr/bin/env python3
"""
Local conformance pipe peer with path request and destination-only support.

Actions:
  - "announce": Create destination, announce it, report hash, run path table dumper.
  - "listen": Just listen for announces and report path table changes.
  - "path_request": Send path request for a destination hash (from env or file).
  - "destination_only": Create destination (don't announce), report hash. RNS
    auto-announces when a path request arrives for local destinations.

Environment variables:
  PIPE_PEER_ACTION: Action to perform (default: "listen")
  PIPE_PEER_APP_NAME: RNS app name (default: "pipetest")
  PIPE_PEER_ASPECTS: Comma-separated aspects (default: "routing")
  PIPE_PEER_TRANSPORT: Enable transport (default: "false")
  PIPE_PEER_MODE: Interface mode (default: "full")
  PIPE_PEER_PATH_REQUEST_DEST: Hex destination hash for path_request action
  PIPE_PEER_PATH_REQUEST_DEST_FILE: File to poll for destination hash (path_request)
  PYTHON_RNS_PATH: Path to Python RNS source (default: ~/repos/Reticulum)
"""
import sys
import os
import json
import time
import threading
import tempfile

# Add RNS to path
rns_path = os.environ.get('PYTHON_RNS_PATH',
    os.path.expanduser('~/repos/Reticulum'))
sys.path.insert(0, rns_path)


def emit(msg):
    sys.stderr.write(json.dumps(msg) + "\n")
    sys.stderr.flush()


def main():
    import RNS
    from RNS.Interfaces.Interface import Interface as BaseInterface

    action = os.environ.get("PIPE_PEER_ACTION", "listen")
    app_name = os.environ.get("PIPE_PEER_APP_NAME", "pipetest")
    aspects = os.environ.get("PIPE_PEER_ASPECTS", "routing").split(",")
    enable_transport = os.environ.get("PIPE_PEER_TRANSPORT", "false").lower() == "true"
    mode_str = os.environ.get("PIPE_PEER_MODE", "full").lower()

    RNS.loglevel = RNS.LOG_CRITICAL

    config_path = tempfile.mkdtemp(prefix="rns_local_peer_")
    config_file = os.path.join(config_path, "config")
    with open(config_file, "w") as f:
        f.write("[reticulum]\n")
        f.write(f"  enable_transport = {'Yes' if enable_transport else 'No'}\n")
        f.write("  share_instance = No\n")
        f.write("\n[interfaces]\n")

    reticulum = RNS.Reticulum(configdir=config_path, loglevel=RNS.LOG_CRITICAL)

    mode_map = {
        "full": BaseInterface.MODE_FULL,
        "ap": BaseInterface.MODE_ACCESS_POINT,
        "access_point": BaseInterface.MODE_ACCESS_POINT,
        "roaming": BaseInterface.MODE_ROAMING,
        "boundary": BaseInterface.MODE_BOUNDARY,
        "gateway": BaseInterface.MODE_GATEWAY,
        "p2p": BaseInterface.MODE_POINT_TO_POINT,
    }
    iface_mode = mode_map.get(mode_str, BaseInterface.MODE_FULL)

    # Create pipe interface on stdin/stdout
    pipe_iface = _create_pipe_interface(RNS, sys.stdin.buffer, sys.stdout.buffer, "StdioPipe")
    pipe_iface.owner = RNS.Transport
    reticulum._add_interface(pipe_iface, mode=iface_mode)

    # Register announce handler
    handler = _AnnounceHandler(RNS)
    RNS.Transport.register_announce_handler(handler)

    emit({"type": "ready", "identity_hash": ""})

    if action == "announce":
        identity = RNS.Identity()
        destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE,
            app_name, *aspects
        )
        destination.announce()
        dest_hash_hex = destination.hash.hex()
        emit({
            "type": "announced",
            "destination_hash": dest_hash_hex,
            "identity_hash": identity.hash.hex(),
            "identity_public_key": identity.get_public_key().hex(),
        })

        # Write hash to output file if specified (for cross-process coordination)
        hash_output_file = os.environ.get("PIPE_PEER_HASH_OUTPUT_FILE", "")
        if hash_output_file:
            with open(hash_output_file, "w") as f:
                f.write(dest_hash_hex)

        _path_table_dumper(RNS)

    elif action == "listen":
        _path_table_dumper(RNS)

    elif action == "destination_only":
        # Create a destination but do NOT announce it.
        # When a path request arrives for this destination, Python RNS
        # automatically announces it in response (Transport.py:2718-2720).
        identity = RNS.Identity()
        destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE,
            app_name, *aspects
        )
        dest_hash_hex = destination.hash.hex()
        emit({
            "type": "destination_created",
            "destination_hash": dest_hash_hex,
            "identity_hash": identity.hash.hex(),
            "identity_public_key": identity.get_public_key().hex(),
        })

        # Write hash to output file if specified (for cross-process coordination)
        hash_output_file = os.environ.get("PIPE_PEER_HASH_OUTPUT_FILE", "")
        if hash_output_file:
            with open(hash_output_file, "w") as f:
                f.write(dest_hash_hex)

        _path_table_dumper(RNS)

    elif action == "path_request":
        # Send a path request for a specific destination hash.
        # Hash can come from env var or by polling a file.
        dest_hash_hex = os.environ.get("PIPE_PEER_PATH_REQUEST_DEST", "")

        if not dest_hash_hex:
            # Poll a file for the destination hash
            dest_file = os.environ.get("PIPE_PEER_PATH_REQUEST_DEST_FILE", "")
            if dest_file:
                emit({"type": "waiting_for_dest_file", "file": dest_file})
                deadline = time.time() + 30
                while time.time() < deadline:
                    if os.path.exists(dest_file):
                        with open(dest_file, "r") as f:
                            dest_hash_hex = f.read().strip()
                        if dest_hash_hex:
                            break
                    time.sleep(0.5)

        if not dest_hash_hex:
            emit({"type": "error", "message": "No destination hash (set PIPE_PEER_PATH_REQUEST_DEST or PIPE_PEER_PATH_REQUEST_DEST_FILE)"})
            _path_table_dumper(RNS)
            return

        dest_hash = bytes.fromhex(dest_hash_hex)
        emit({"type": "path_request_queued", "destination_hash": dest_hash_hex})

        # Wait a moment for the pipe to be fully connected
        time.sleep(1)

        # Send the path request
        RNS.Transport.request_path(dest_hash)
        emit({"type": "path_request_sent", "destination_hash": dest_hash_hex})

        # Wait for path to be discovered
        deadline = time.time() + 20
        while time.time() < deadline:
            if RNS.Transport.has_path(dest_hash):
                hops = RNS.Transport.hops_to(dest_hash)
                emit({
                    "type": "path_discovered",
                    "destination_hash": dest_hash_hex,
                    "hops": hops,
                })
                break
            time.sleep(0.5)
        else:
            emit({
                "type": "path_not_found",
                "destination_hash": dest_hash_hex,
            })

        _path_table_dumper(RNS)

    else:
        emit({"type": "error", "message": f"Unknown action: {action}"})
        _path_table_dumper(RNS)


class _AnnounceHandler:
    def __init__(self, RNS):
        self.aspect_filter = None
        self._RNS = RNS

    def received_announce(self, destination_hash, announced_identity, app_data):
        RNS = self._RNS
        hops = RNS.Transport.hops_to(destination_hash) if RNS.Transport.has_path(destination_hash) else -1
        emit({
            "type": "announce_received",
            "destination_hash": destination_hash.hex(),
            "identity_hash": announced_identity.hash.hex() if announced_identity else "",
            "hops": hops,
        })


def _path_table_dumper(RNS):
    last_dump = ""
    try:
        while True:
            time.sleep(1)
            entries = []
            for dest_hash in RNS.Transport.path_table:
                entry = RNS.Transport.path_table[dest_hash]
                entries.append({
                    "destination_hash": dest_hash.hex(),
                    "hops": entry[2],
                    "next_hop": entry[1].hex() if isinstance(entry[1], bytes) else str(entry[1]),
                })
            current = json.dumps(entries, sort_keys=True)
            if current != last_dump:
                emit({"type": "path_table", "entries": entries})
                last_dump = current
    except (KeyboardInterrupt, BrokenPipeError):
        pass


def _create_pipe_interface(RNS, pin, pout, name="StdioPipe"):
    from RNS.Interfaces.Interface import Interface as BaseInterface

    class StreamPipeInterface(BaseInterface):
        FLAG = 0x7E
        ESC = 0x7D
        ESC_MASK = 0x20

        def __init__(self):
            super().__init__()
            self.HW_MTU = 1064
            self.name = name
            self.online = False
            self.bitrate = 1000000
            self.IN = True
            self.OUT = True
            self._stdin = pin
            self._stdout = pout
            self.online = True
            threading.Thread(target=self._read_loop, daemon=True).start()

        def process_outgoing(self, data):
            if self.online:
                escaped = data.replace(
                    bytes([self.ESC]), bytes([self.ESC, self.ESC ^ self.ESC_MASK])
                )
                escaped = escaped.replace(
                    bytes([self.FLAG]), bytes([self.ESC, self.FLAG ^ self.ESC_MASK])
                )
                frame = bytes([self.FLAG]) + escaped + bytes([self.FLAG])
                try:
                    self._stdout.write(frame)
                    self._stdout.flush()
                    self.txb += len(data)
                except (BrokenPipeError, OSError):
                    self.online = False

        def _read_loop(self):
            try:
                in_frame = False
                escape = False
                buf = b""
                while self.online:
                    chunk = self._stdin.read(1)
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
            return f"StreamPipeInterface[{name}]"

    return StreamPipeInterface()


if __name__ == "__main__":
    main()
