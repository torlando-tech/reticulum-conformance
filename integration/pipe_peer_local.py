#!/usr/bin/env python3
"""
Local conformance pipe peer with path request, destination-only, and channel serve support.

Actions:
  - "announce": Create destination, announce it, report hash, run path table dumper.
  - "listen": Just listen for announces and report path table changes.
  - "path_request": Send path request for a destination hash (from env or file).
  - "destination_only": Create destination (don't announce), report hash. RNS
    auto-announces when a path request arrives for local destinations.
  - "channel_serve": Create a destination, accept an incoming link, and send a
    proof-dependent three-message channel sequence.

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
import json
import os
import sys
import tempfile
import threading
import time

# Add RNS to path
rns_path = os.environ.get("PYTHON_RNS_PATH", os.path.expanduser("~/repos/Reticulum"))
sys.path.insert(0, rns_path)


_BridgeMessageClass = None


def emit(msg):
    sys.stderr.write(json.dumps(msg) + "\n")
    sys.stderr.flush()



def _get_bridge_message_class():
    import RNS

    global _BridgeMessageClass
    if _BridgeMessageClass is None:
        class BridgeMessage(RNS.Channel.MessageBase):
            MSGTYPE = 0x0101

            def __init__(self, data=b""):
                self.data = data

            def pack(self):
                return self.data

            def unpack(self, raw):
                self.data = raw

        _BridgeMessageClass = BridgeMessage

    return _BridgeMessageClass



def _link_closed(link):
    emit({
        "type": "link_closed",
        "link_id": link.link_id.hex() if link.link_id else "",
        "destination_hash": link.destination.hash.hex() if link.destination else "",
    })



def _setup_channel_peer(link, send_sequence=False):
    BridgeMessage = _get_bridge_message_class()
    channel = link.get_channel()
    channel.register_message_type(BridgeMessage)

    def on_channel_message(message):
        if isinstance(message, BridgeMessage):
            data = bytes(message.data)
            emit({
                "type": "channel_data",
                "link_id": link.link_id.hex() if link.link_id else "",
                "data_hex": data.hex(),
                "data_utf8": data.decode("utf-8", errors="replace"),
            })
            return True
        return False

    channel.add_message_handler(on_channel_message)

    if not send_sequence:
        return

    def send_messages():
        time.sleep(1.0)
        for payload in (b"channel-one", b"channel-two", b"channel-three"):
            deadline = time.time() + 5.0
            while (
                time.time() < deadline
                and link.status == link.ACTIVE
                and not channel.is_ready_to_send()
            ):
                time.sleep(0.05)

            if link.status != link.ACTIVE:
                emit({"type": "error", "message": "Link became inactive before channel send"})
                return

            if not channel.is_ready_to_send():
                emit({"type": "error", "message": "Channel never became ready for next send"})
                return

            try:
                channel.send(BridgeMessage(payload))
                emit({
                    "type": "channel_sent",
                    "link_id": link.link_id.hex() if link.link_id else "",
                    "data_hex": payload.hex(),
                })
            except Exception as e:
                emit({"type": "error", "message": f"Channel send failed: {e}"})
                return

    threading.Thread(target=send_messages, daemon=True).start()



def _channel_serve_established(link):
    emit({
        "type": "link_established",
        "link_id": link.link_id.hex() if link.link_id else "",
        "destination_hash": link.destination.hash.hex() if link.destination else "",
    })
    link.set_link_closed_callback(_link_closed)
    _setup_channel_peer(link, send_sequence=True)



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

    pipe_iface = _create_pipe_interface(RNS, sys.stdin.buffer, sys.stdout.buffer, "StdioPipe")
    pipe_iface.owner = RNS.Transport
    reticulum._add_interface(pipe_iface, mode=iface_mode)

    handler = _AnnounceHandler(RNS)
    RNS.Transport.register_announce_handler(handler)

    emit({"type": "ready", "identity_hash": ""})

    if action == "announce":
        identity = RNS.Identity()
        destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            app_name,
            *aspects,
        )
        destination.announce()
        dest_hash_hex = destination.hash.hex()
        emit({
            "type": "announced",
            "destination_hash": dest_hash_hex,
            "identity_hash": identity.hash.hex(),
            "identity_public_key": identity.get_public_key().hex(),
        })

        hash_output_file = os.environ.get("PIPE_PEER_HASH_OUTPUT_FILE", "")
        if hash_output_file:
            with open(hash_output_file, "w") as f:
                f.write(dest_hash_hex)

        _path_table_dumper(RNS)

    elif action == "listen":
        _path_table_dumper(RNS)

    elif action == "destination_only":
        identity = RNS.Identity()
        destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            app_name,
            *aspects,
        )
        dest_hash_hex = destination.hash.hex()
        emit({
            "type": "destination_created",
            "destination_hash": dest_hash_hex,
            "identity_hash": identity.hash.hex(),
            "identity_public_key": identity.get_public_key().hex(),
        })

        hash_output_file = os.environ.get("PIPE_PEER_HASH_OUTPUT_FILE", "")
        if hash_output_file:
            with open(hash_output_file, "w") as f:
                f.write(dest_hash_hex)

        _path_table_dumper(RNS)

    elif action == "path_request":
        dest_hash_hex = os.environ.get("PIPE_PEER_PATH_REQUEST_DEST", "")

        if not dest_hash_hex:
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
            emit({
                "type": "error",
                "message": "No destination hash (set PIPE_PEER_PATH_REQUEST_DEST or PIPE_PEER_PATH_REQUEST_DEST_FILE)",
            })
            _path_table_dumper(RNS)
            return

        dest_hash = bytes.fromhex(dest_hash_hex)
        emit({"type": "path_request_queued", "destination_hash": dest_hash_hex})

        time.sleep(1)

        RNS.Transport.request_path(dest_hash)
        emit({"type": "path_request_sent", "destination_hash": dest_hash_hex})

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

    elif action == "channel_serve":
        identity = RNS.Identity()
        destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            app_name,
            *aspects,
        )
        destination.set_link_established_callback(_channel_serve_established)
        destination.announce()
        emit({
            "type": "announced",
            "destination_hash": destination.hash.hex(),
            "identity_hash": identity.hash.hex(),
            "identity_public_key": identity.get_public_key().hex(),
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
        # Required by RNS.Reticulum._add_interface (Reticulum.py:966).
        # See the matching attribute on three_node_session._HdlcPipe.
        # Without this, A's `_add_interface` call raises AttributeError
        # silently before A reaches `emit({"type": "ready"})`, and the
        # session-level "A should emit ready" assertion fails after a
        # 20s timeout. Match the serial-class default of 8 since this
        # is a stdio pipe, not a UDP-style network interface.
        DEFAULT_IFAC_SIZE = 8

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
