"""Wire-level (E2E) fixtures.

Unlike byte-level tests (one bridge as sut, one as reference, each fed test
vectors) and unlike behavioral tests (one bridge with MockInterface-buffered
packets), wire tests pair TWO live Reticulum instances over a loopback TCP
link and observe the result of real packet exchange.

The `wire_peers` fixture spawns two bridge subprocesses — one server-role,
one client-role — with caller-selectable impls. Each bridge is fresh per
test (Python RNS is a process-singleton; Kotlin's Reticulum.stop() works
but the bridge boundary is simpler to reason about with fresh processes).

See reference/wire_tcp.py and conformance-bridge/src/main/kotlin/WireTcp.kt
for the `wire_*` command surface these fixtures drive.
"""

import os
import secrets
import shutil
import tempfile

import pytest

from _rns_paths import resolve_rns_path
from bridge_client import BridgeClient
from conftest import get_impl_list, resolve_command


def _env_for(impl: str) -> dict:
    """Env vars the reference Python bridge needs; Kotlin ignores them."""
    if impl != "reference":
        return {}
    return {
        "PYTHON_RNS_PATH": resolve_rns_path(),
    }


def pytest_generate_tests(metafunc):
    """Parametrize wire tests over EVERY (server_impl, client_impl) pair
    for 2-peer fixtures, and EVERY (sender, transport, receiver) triple
    for 3-peer fixtures.

    For impls ["reference", "kotlin"] that's 4 pairs / 8 triples per test.
    The homogeneous combos (reference-only, kotlin-only) are sanity
    baselines — they isolate "is anything broken end-to-end on one side"
    from "is interop broken". The heterogeneous combos (e.g.
    kotlin → reference → reference) are the real cross-impl assertions;
    that specific triple is the Columba → rnsd → Sideband topology.
    """
    if "wire_pair" in metafunc.fixturenames:
        impls = get_impl_list(metafunc.config) or []
        # Always include the reference so a cross-impl test actually tests
        # something; a single-impl run (e.g. --impl kotlin with no reference
        # in the impl list) would otherwise skip the whole interop point.
        peers = sorted(set(impls) | {"reference"})
        pairs = [(a, b) for a in peers for b in peers]
        ids = [f"{a}-to-{b}" for a, b in pairs]
        metafunc.parametrize("wire_pair", pairs, ids=ids, scope="function")

    _parametrize_wire_trio(metafunc)
    _parametrize_wire_shared_trio(metafunc)


class _WirePeer:
    """Thin convenience wrapper around a BridgeClient.

    Holds the peer's handle and exposes the five wire_* commands as methods.
    Each method just forwards to `bridge.execute` and returns the decoded
    response fields the tests care about.
    """

    def __init__(self, bridge: BridgeClient, role_label: str):
        self.bridge = bridge
        self.role_label = role_label  # purely for error messages
        self.handle: str | None = None
        self.identity_hash: bytes | None = None
        self.port: int | None = None
        # destination_hash -> {"identity_hash": bytes, "public_key": bytes}
        # for each wire_listen registered on this peer (N-M3: lets recall
        # tests assert byte-identity against the listening identity).
        self.listen_identities: dict[bytes, dict] = {}

    def start_tcp_server(
        self,
        network_name: str,
        passphrase: str,
        mode: str | None = None,
        share_instance: bool = False,
        share_instance_type: str | None = None,
        enable_transport: bool = True,
    ) -> int:
        """Bring up a TCPServerInterface on this peer.

        share_instance=True additionally publishes this peer as a shared
        Reticulum instance so other bridge processes (started via
        `start_local_client(shared_instance_port=...)`) can attach as
        local clients. The kotlin bridge only supports
        share_instance_type='tcp' (LocalServerInterface listening on a
        loopback port); the Python reference defaults to AF_UNIX and you
        must pass share_instance_type='tcp' explicitly to make a master
        that kotlin local-client peers can interop with.

        When share_instance is True, the returned `shared_instance_port`
        is stored on the peer (`self.shared_instance_port`) for the test
        to pass into the local-client peer's start.

        enable_transport (default True) controls whether this peer enables
        transport. Set False to bring up a transport-DISABLED shared master
        (the rnsd default posture) — the only way to exercise R3
        (CONFORMANCE_GAPS.md §3): local-client forwarding bypasses the
        transport gate, so an attached local client's announces/links must
        still reach a TCP peer even with transport off. The resolved posture
        is recorded on `self.configured_transport_enabled`; assert the GROUND
        TRUTH via the `transport_enabled()` method
        (RNS.Reticulum.transport_enabled()) rather than this echoed config value.
        """
        kwargs: dict = {"network_name": network_name, "passphrase": passphrase}
        if mode is not None:
            kwargs["mode"] = mode
        if share_instance:
            kwargs["share_instance"] = True
            if share_instance_type is not None:
                kwargs["share_instance_type"] = share_instance_type
        if not enable_transport:
            kwargs["enable_transport"] = False
        resp = self.bridge.execute("wire_start_tcp_server", **kwargs)
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])
        self.port = int(resp["port"])
        # Echoed config posture; the ground-truth observable is the
        # transport_enabled() METHOD below. Named distinctly so it does not
        # shadow that method on the instance.
        self.configured_transport_enabled: bool = bool(
            resp.get("transport_enabled", True)
        )
        # Surface the shared-instance state for tests that need to chain a
        # local-client peer onto this master. All None when
        # share_instance=False or share_instance_type != "tcp".
        self.shared_instance_port: int | None = (
            int(resp["shared_instance_port"])
            if "shared_instance_port" in resp
            else None
        )
        self.instance_control_port: int | None = (
            int(resp["instance_control_port"])
            if "instance_control_port" in resp
            else None
        )
        self.rpc_key: str | None = resp.get("rpc_key")
        return self.port

    def start_local_client(
        self,
        shared_instance_port: int,
        instance_control_port: int | None = None,
        rpc_key: str | None = None,
    ):
        """Attach this peer as a shared-instance client of an already-running
        master.

        The master must have been brought up via
        `start_tcp_server(share_instance=True, share_instance_type='tcp')`
        — pass `master_peer.shared_instance_port`,
        `master_peer.instance_control_port`, and `master_peer.rpc_key`
        through. The control port and rpc_key are required for cross-
        process Python↔Python topologies (the master's RPC listener is on
        a non-default port and uses an authkey derived from a transport
        identity the client doesn't share); without them, link
        establishment fails with AuthenticationError on the client's first
        _used_destination_data RPC. Kotlin clients don't make RPC calls so
        these are no-ops on that side, but plumbing them through keeps the
        helper polymorphic across impls.

        Order matters: starting this peer before the master would result in
        the connect attempt failing (Python falls back to standalone /
        becomes its own master, kotlin throws).

        No on-wire interface is configured for this peer; the only
        attachment is the LocalClientInterface to the master. Outbound
        announces, link requests, etc. exit through the master's TCP
        interface (mirrors how Eridanus runs on a phone hosting Sideband).
        """
        kwargs: dict = {"shared_instance_port": int(shared_instance_port)}
        if instance_control_port is not None:
            kwargs["instance_control_port"] = int(instance_control_port)
        if rpc_key is not None:
            kwargs["rpc_key"] = rpc_key
        resp = self.bridge.execute("wire_start_local_client", **kwargs)
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])
        self.shared_instance_port: int | None = int(shared_instance_port)

    def start_pipe_peer(
        self,
        read_fifo: str,
        write_fifo: str,
        network_name: str = "",
        passphrase: str = "",
        enable_transport: bool = False,
    ):
        """Bring up this peer as a PipeInterface leaf bridged via a FIFO pair.

        The A end of the mixed pipe<->TCP relay topology. The relay peer on
        the other end of the pipe uses the SAME two FIFOs with read/write
        swapped. enable_transport defaults False (a leaf host).
        """
        kwargs: dict = {
            "read_fifo": read_fifo,
            "write_fifo": write_fifo,
            "network_name": network_name,
            "passphrase": passphrase,
        }
        if not enable_transport:
            kwargs["enable_transport"] = False
        resp = self.bridge.execute("wire_start_pipe_peer", **kwargs)
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])

    def start_pipe_tcp_relay(
        self,
        read_fifo: str,
        write_fifo: str,
        network_name: str = "",
        passphrase: str = "",
        enable_transport: bool = True,
    ) -> int:
        """Bring up this peer as the mixed relay B: a PipeInterface (to A) plus
        a TCPServerInterface (to C), transport ON.

        A LINKREQUEST forwarded OUT the PipeInterface (non-autoconfigure) has
        its 3-byte LINK_MTU_SIZE field stripped, so the destination's link
        falls back to Reticulum.MTU=500. Returns and stores the TCP port C
        connects to (`self.port`).
        """
        kwargs: dict = {
            "read_fifo": read_fifo,
            "write_fifo": write_fifo,
            "network_name": network_name,
            "passphrase": passphrase,
        }
        if not enable_transport:
            kwargs["enable_transport"] = False
        resp = self.bridge.execute("wire_start_pipe_tcp_relay", **kwargs)
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])
        self.port = int(resp["port"])
        return self.port

    def start_tcp_client(
        self,
        network_name: str,
        passphrase: str,
        target_host: str,
        target_port: int,
        mode: str | None = None,
    ):
        kwargs: dict = {
            "network_name": network_name,
            "passphrase": passphrase,
            "target_host": target_host,
            "target_port": target_port,
        }
        if mode is not None:
            kwargs["mode"] = mode
        resp = self.bridge.execute("wire_start_tcp_client", **kwargs)
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])

    def set_interface_mode(self, mode: str):
        """Runtime-mutate the configured interface's mode on this peer.

        Applies to the primary interface and any currently-spawned
        children (server case). Prefer passing `mode=` to `start_tcp_*`
        where possible — this helper is for tests that need a mode
        transition mid-test.
        """
        assert self.handle, "start_* must be called first"
        self.bridge.execute(
            "wire_set_interface_mode",
            handle=self.handle,
            mode=mode,
        )

    def request_path(self, destination_hash: bytes):
        """Fire a path-request packet for `destination_hash` unconditionally."""
        assert self.handle, "start_* must be called first"
        self.bridge.execute(
            "wire_request_path",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )

    def read_path_entry(self, destination_hash: bytes) -> dict | None:
        """Return the path_table entry as a dict, or None if absent.

        Dict keys: timestamp, expires (both ms-since-epoch), hops,
        next_hop (hex str), receiving_interface_name (str or None).
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_read_path_entry",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )
        if not resp.get("found"):
            return None
        return {
            "timestamp": int(resp["timestamp"]),
            "expires": int(resp["expires"]),
            "hops": int(resp["hops"]),
            "next_hop": resp["next_hop"],
            "receiving_interface_name": resp.get("receiving_interface_name"),
        }

    def has_discovery_path_request(self, destination_hash: bytes) -> bool:
        """Observable: has this transport forwarded a path request for dest?"""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_has_discovery_path_request",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )
        return bool(resp.get("found"))

    def has_announce_table_entry(self, destination_hash: bytes) -> bool:
        """Observable: is there a scheduled re-emission in announce_table?

        Used to detect whether a cached-announce path-response was
        enqueued (presence) or refused (absence) in response to a PR.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_has_announce_table_entry",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )
        return bool(resp.get("found"))

    def read_announce_table_timestamp(self, destination_hash: bytes) -> int | None:
        """Return announce_table[dest].timestamp (ms), or None if absent.

        Path-request answering replaces the entry with a fresh timestamp.
        Comparing before/after distinguishes "B answered the PR" (ts
        advances) from "B refused / loop-prevention fired" (ts unchanged).

        Note: Python and Kotlin restore held_announces at different points
        in the PR-answer flow, so this observable is impl-sensitive. Prefer
        `tx_bytes` for cross-impl "did B send anything" checks.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_read_announce_table_timestamp",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )
        if not resp.get("found"):
            return None
        return int(resp["timestamp"])

    def tx_bytes(self) -> int:
        """Return total TX bytes across this peer's configured interface
        and its spawned children. Model-agnostic "did this peer emit?"
        signal, independent of announce_table timing quirks.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute("wire_tx_bytes", handle=self.handle)
        return int(resp["tx_bytes"])

    def read_path_random_hash(self, destination_hash: bytes) -> bytes | None:
        """Return the cached announce's 10-byte random_hash, or None if no path."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_read_path_random_hash",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )
        if not resp.get("found"):
            return None
        return bytes.fromhex(resp["random_hash"])

    def announce(self, app_name: str, aspects: list, app_data: bytes = b"") -> bytes:
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_announce",
            handle=self.handle,
            app_name=app_name,
            aspects=list(aspects),
            app_data=app_data.hex(),
        )
        return bytes.fromhex(resp["destination_hash"])

    def poll_path(self, destination_hash: bytes, timeout_ms: int = 5000) -> bool:
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_poll_path",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            timeout_ms=timeout_ms,
        )
        return bool(resp.get("found"))

    def register_request_handler(
        self,
        destination_hash: bytes,
        path: str,
        response: bytes,
        allow: str = "all",
        allowed_identity_hashes: list | None = None,
    ) -> None:
        """Register a fixed-response request handler on a listening
        destination — the bridge plugs in a generator that returns the
        given bytes when a request for `path` arrives.

        `allow="list"` plus `allowed_identity_hashes=[<16-byte hash>, ...]`
        gates the handler on the requester's identified Identity, mirroring
        the LXMF lxmd SYNC_REQUEST_PATH authentication model.
        """
        assert self.handle, "start_* must be called first"
        params = {
            "handle": self.handle,
            "destination_hash": destination_hash.hex(),
            "path": path,
            "response": response.hex(),
            "allow": allow,
        }
        if allowed_identity_hashes:
            params["allowed_identity_hashes"] = [
                h.hex() if isinstance(h, (bytes, bytearray)) else str(h)
                for h in allowed_identity_hashes
            ]
        self.bridge.execute("wire_register_request_handler", **params)

    def link_identify(self, link_id: bytes, private_key: bytes) -> bytes:
        """Identify the link initiator to the remote peer.

        Returns the identity_hash (16 bytes) that the remote sees on the
        request handler's `remote_identity` argument.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_link_identify",
            handle=self.handle,
            link_id=link_id.hex(),
            private_key=private_key.hex(),
        )
        return bytes.fromhex(resp["identity_hash"])

    def link_request(
        self,
        link_id: bytes,
        path: str,
        data: bytes = b"",
        timeout_ms: int = 10000,
    ) -> dict:
        """Issue link.request over an established outbound link and
        wait for the response. Returns {status, response, response_time_s}.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_request",
            handle=self.handle,
            link_id=link_id.hex(),
            path=path,
            data=data.hex(),
            timeout_ms=timeout_ms,
        )

    def get_request_log(self, destination_hash: bytes, path: str) -> list:
        """Drain the handler-invocation log for (destination, path).

        Returns the list of recorded invocations; each entry holds the
        request data + link_id + remote_identity_hash + requested_at the
        handler observed. Used by tests to verify the handler fired with
        the expected request data.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_get_request_log",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            path=path,
        )
        return list(resp.get("entries", []))

    def identity_recall(
        self, destination_hash: bytes, timeout_ms: int = 5000,
    ) -> dict | None:
        """Look up the Identity associated with a destination hash.

        Returns a dict {public_key, hash} when this peer has received
        an announce for the destination, or None when unknown. Optional
        timeout polls Transport state — without it, the call returns
        immediately based on the current known_destinations table.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_identity_recall",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            timeout_ms=timeout_ms,
        )
        if not resp.get("found"):
            return None
        return {
            "public_key": bytes.fromhex(resp["public_key"]),
            "hash": bytes.fromhex(resp["hash"]),
        }

    def listen(self, app_name: str, aspects: list) -> bytes:
        """Register an IN destination that accepts incoming Links.

        Returns the destination_hash. The listening identity's hash and raw
        public_key are recorded on the peer (see `listening_identity`) so
        recall tests can assert the recalled key is byte-identical to the
        announced one (N-M3), not merely the right length.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_listen",
            handle=self.handle,
            app_name=app_name,
            aspects=list(aspects),
        )
        dest_hash = bytes.fromhex(resp["destination_hash"])
        self.listen_identities[dest_hash] = {
            "identity_hash": bytes.fromhex(resp["identity_hash"]),
            # public_key was added to wire_listen for byte-identity asserts;
            # tolerate older bridges that don't return it yet.
            "public_key": (
                bytes.fromhex(resp["public_key"]) if resp.get("public_key") else None
            ),
        }
        return dest_hash

    def listening_identity(self, destination_hash: bytes) -> dict:
        """Return {identity_hash, public_key} for a destination this peer is
        listening on. Raises if `listen` was not called for it first.
        """
        if destination_hash not in self.listen_identities:
            raise KeyError(
                f"No listen() recorded for {destination_hash.hex()} on {self.role_label}"
            )
        return self.listen_identities[destination_hash]

    def link_open(
        self,
        destination_hash: bytes,
        app_name: str,
        aspects: list,
        timeout_ms: int = 10000,
    ) -> bytes:
        """Open an outbound Link to a remote IN destination."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_link_open",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            app_name=app_name,
            aspects=list(aspects),
            timeout_ms=timeout_ms,
        )
        return bytes.fromhex(resp["link_id"])

    def link_send(self, link_id: bytes, data: bytes):
        assert self.handle, "start_* must be called first"
        self.bridge.execute(
            "wire_link_send",
            handle=self.handle,
            link_id=link_id.hex(),
            data=data.hex(),
        )

    def link_poll(self, destination_hash: bytes, timeout_ms: int = 5000) -> list:
        """Drain all link data received on `destination_hash` since last poll."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_link_poll",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            timeout_ms=timeout_ms,
        )
        return [bytes.fromhex(p) for p in resp.get("packets", [])]

    def resource_send(
        self, link_id: bytes, data: bytes, timeout_ms: int = 30000
    ) -> dict:
        """Send arbitrary-size bytes via the RNS Resource API.

        Returns the bridge's response dict with `success`, `status`,
        `size`, `timed_out`. Used to exercise multi-packet chunked
        transfer over a Link (the path LXMF uses for image/file
        attachments).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_send",
            handle=self.handle,
            link_id=link_id.hex(),
            data=data.hex(),
            timeout_ms=timeout_ms,
        )

    def resource_create(
        self,
        link_id: bytes,
        data: bytes,
        force_sdu: int | None = None,
        include_parts: bool = True,
        auto_compress: bool = True,
    ) -> dict:
        """Construct a real RNS.Resource on an established Link and report
        the attributes the implementation computed — WITHOUT advertising or
        sending it.

        The honest, delegating replacement for the deleted synthetic
        resource_* primitive commands: the bridge builds a real
        RNS.Resource (full __init__, advertise=False so nothing hits the
        wire) and reads back `hash`, `truncated_hash`, `random_hash`,
        `expected_proof`, `hashmap`, `parts`, `num_parts`, `total_segments`,
        `segment_index`, and the size/flag fields — nothing is recomputed.

        Coverage knobs (CONFORMANCE_REAUDIT.md §5 Resource):
          force_sdu: force a small per-part SDU so a modest payload exceeds
            the 74-part HMU threshold (assert num_parts>74).
          include_parts=False: omit the per-part `parts` list (use for >1 MiB
            multi-segment payloads where total_segments>1 is the observable).
          auto_compress: leave True to observe compressed=True on a
            compressible payload.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "link_id": link_id.hex(),
            "data": data.hex(),
            "include_parts": include_parts,
            "auto_compress": auto_compress,
        }
        if force_sdu is not None:
            params["force_sdu"] = int(force_sdu)
        return self.bridge.execute("wire_resource_create", **params)

    # --- Link lifecycle observation ---------------------------------------

    def link_status(self, link_id: bytes) -> dict:
        """Lifecycle snapshot of an outbound link: status/status_name,
        teardown_reason/teardown_reason_name, no_inbound_for_ms,
        last_keepalive_ago_ms, keepalive_s, stale_time_s, rtt.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_status", handle=self.handle, link_id=link_id.hex()
        )

    def link_set_watchdog(
        self,
        link_id: bytes,
        keepalive_s: float | None = None,
        stale_time_s: float | None = None,
    ) -> dict:
        """Compress a link's keepalive/stale timings to fit a test window.

        Note: small timings alone do NOT force TIMEOUT — RNS only goes
        STALE→CLOSED/TIMEOUT once inbound genuinely ceases (a stalled peer).
        An explicit teardown or clean disconnect yields INITIATOR_CLOSED /
        DESTINATION_CLOSED immediately regardless of these values.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {"handle": self.handle, "link_id": link_id.hex()}
        if keepalive_s is not None:
            params["keepalive_s"] = float(keepalive_s)
        if stale_time_s is not None:
            params["stale_time_s"] = float(stale_time_s)
        return self.bridge.execute("wire_link_set_watchdog", **params)

    def link_await_status(
        self, link_id: bytes, target_status, timeout_ms: int = 15000
    ) -> dict:
        """Block until the link reaches at least `target_status` (int or name
        like "STALE"/"CLOSED"), or timeout. Returns the snapshot + `reached`.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_await_status",
            handle=self.handle,
            link_id=link_id.hex(),
            target_status=target_status,
            timeout_ms=timeout_ms,
        )

    def link_teardown(self, link_id: bytes) -> None:
        """Gracefully tear down an outbound link (initiator side)."""
        assert self.handle, "start_* must be called first"
        self.bridge.execute(
            "wire_link_teardown", handle=self.handle, link_id=link_id.hex()
        )

    def listener_link_status(
        self, destination_hash: bytes, timeout_ms: int = 0
    ) -> dict:
        """Observe the receiver-side (inbound) link accepted on a listening
        destination. Returns the snapshot + {found, link_count}; optionally
        polls up to timeout_ms for the inbound link to appear.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_listener_link_status",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            timeout_ms=timeout_ms,
        )

    def set_proof_strategy(self, destination_hash: bytes, strategy: str) -> dict:
        """Set a listening destination's proof strategy: "all"/"app"/"none".
        Returns {strategy, proof_strategy} read back off the real destination.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_set_proof_strategy",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            strategy=strategy,
        )

    # --- Transport posture / link MTU / single-packet PacketReceipt -------

    def transport_enabled(self) -> dict:
        """Read the GROUND-TRUTH transport posture of this peer.

        Returns {transport_enabled, is_shared_instance,
        is_connected_to_shared_instance}. Use this to pin "the master really
        has transport off" in an R3 test, independently of whether
        local-client forwarding happened.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute("wire_transport_enabled", handle=self.handle)

    def link_mtu(self, link_id: bytes) -> dict:
        """Read an established link's negotiated MTU/MDU/mode.

        Returns {mtu, mdu, mode, status, status_name}. `link_id` may be an
        outbound link (from link_open) or an inbound link accepted by a
        listening destination — the in-transit link-MTU strip is observed on
        the destination's inbound link (mtu falls back to Reticulum.MTU=500
        when a relay forwarded the LINKREQUEST out a non-autoconfigure
        next-hop interface).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_mtu", handle=self.handle, link_id=link_id.hex()
        )

    def send_packet(
        self,
        destination_hash: bytes,
        app_name: str,
        aspects: list,
        data: bytes = b"",
        create_receipt: bool = True,
    ) -> dict:
        """Send a single SINGLE-destination DATA packet with a tracked receipt.

        Distinct from link_send (over a Link): this is the raw single-packet
        path whose returning PROOF drives a PacketReceipt to DELIVERED. Returns
        {sent, receipt_id, hops}; pass receipt_id to packet_receipt_status to
        observe delivery (the proof_for_local_client return path). The
        destination identity must already be known via a received announce.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_send_packet",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            app_name=app_name,
            aspects=list(aspects),
            data=data.hex(),
            create_receipt=bool(create_receipt),
        )

    def packet_receipt_status(
        self, receipt_id: str, timeout_ms: int = 0
    ) -> dict:
        """Poll a tracked PacketReceipt until it concludes, or timeout.

        Returns {status, status_name, delivered, proved}. `delivered` is True
        iff the returning PROOF validated against the receipt — the
        proof_for_local_client observable.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_packet_receipt_status",
            handle=self.handle,
            receipt_id=receipt_id,
            timeout_ms=timeout_ms,
        )

    # --- Channel out-of-order / duplicate / window ------------------------

    def channel_inject(self, link_id: bytes, envelopes: list) -> list:
        """Feed crafted envelopes into a link's real Channel receive path.

        envelopes: list of {"sequence": int, "data": bytes}. Returns the
        injected sequence list.
        """
        assert self.handle, "start_* must be called first"
        wire_envelopes = [
            {
                "sequence": int(e["sequence"]),
                "data": (
                    e["data"].hex()
                    if isinstance(e.get("data"), (bytes, bytearray))
                    else (e.get("data") or "")
                ),
            }
            for e in envelopes
        ]
        resp = self.bridge.execute(
            "wire_channel_inject",
            handle=self.handle,
            link_id=link_id.hex(),
            envelopes=wire_envelopes,
        )
        return list(resp.get("injected", []))

    def channel_received(self, link_id: bytes) -> list:
        """Drain the in-order payloads the channel delivered (bytes list)."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_channel_received", handle=self.handle, link_id=link_id.hex()
        )
        return [bytes.fromhex(m) for m in resp.get("messages", [])]

    def channel_window(self, link_id: bytes) -> dict:
        """Report the channel's window + sequence state (window, window_min,
        window_max, window_flexibility, next_rx_sequence, next_sequence,
        rx_ring, tx_ring).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_channel_window", handle=self.handle, link_id=link_id.hex()
        )

    # --- GROUP destination symmetric crypto -------------------------------

    def group_create(
        self, app_name: str, aspects: list, key: bytes | None = None
    ) -> dict:
        """Create a GROUP destination; generate (key=None) or load a key.
        Returns {destination_hash: bytes, key: bytes}.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "app_name": app_name,
            "aspects": list(aspects),
        }
        if key is not None:
            params["key"] = key.hex()
        resp = self.bridge.execute("wire_group_create", **params)
        return {
            "destination_hash": bytes.fromhex(resp["destination_hash"]),
            "key": bytes.fromhex(resp["key"]),
        }

    def group_encrypt(self, destination_hash: bytes, plaintext: bytes) -> bytes:
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_group_encrypt",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            plaintext=plaintext.hex(),
        )
        return bytes.fromhex(resp["ciphertext"])

    def group_decrypt(self, destination_hash: bytes, ciphertext: bytes) -> bytes | None:
        """Decrypt for a GROUP destination. Returns plaintext bytes, or None
        when decryption failed (e.g. wrong key).
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_group_decrypt",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            ciphertext=ciphertext.hex(),
        )
        if not resp.get("decrypted"):
            return None
        return bytes.fromhex(resp["plaintext"])

    # --- Identity ratchet crypto (enforce_ratchets rejection) -------------

    def identity_keypair(self) -> dict:
        """Generate an RNS.Identity. Returns {private_key, public_key, hash}."""
        resp = self.bridge.execute("wire_identity_keypair")
        return {
            "private_key": bytes.fromhex(resp["private_key"]),
            "public_key": bytes.fromhex(resp["public_key"]),
            "hash": bytes.fromhex(resp["hash"]),
        }

    def ratchet_keypair(self) -> dict:
        """Generate an X25519 ratchet keypair. Returns {private_key, public_key}."""
        resp = self.bridge.execute("wire_ratchet_keypair")
        return {
            "private_key": bytes.fromhex(resp["private_key"]),
            "public_key": bytes.fromhex(resp["public_key"]),
        }

    def identity_encrypt(
        self, public_key: bytes, plaintext: bytes, ratchet_pub: bytes | None = None
    ) -> bytes:
        """Encrypt for an identity's public key; optionally to a ratchet
        public key (forward secrecy).
        """
        params: dict = {"public_key": public_key.hex(), "plaintext": plaintext.hex()}
        if ratchet_pub is not None:
            params["ratchet_pub"] = ratchet_pub.hex()
        resp = self.bridge.execute("wire_identity_encrypt", **params)
        return bytes.fromhex(resp["ciphertext"])

    def identity_decrypt(
        self,
        private_key: bytes,
        ciphertext: bytes,
        ratchets: list | None = None,
        enforce_ratchets: bool = False,
    ) -> bytes | None:
        """Decrypt for an identity's private key with ratchet enforcement.

        `ratchets` is a list of ratchet PRIVATE keys (bytes). With
        enforce_ratchets=True, RNS returns None for any ciphertext none of
        those ratchets can decrypt (forward-secrecy rejection). Returns the
        plaintext bytes, or None when decryption was rejected/failed.
        """
        params: dict = {
            "private_key": private_key.hex(),
            "ciphertext": ciphertext.hex(),
            "enforce_ratchets": bool(enforce_ratchets),
        }
        if ratchets:
            params["ratchets"] = [r.hex() for r in ratchets]
        resp = self.bridge.execute("wire_identity_decrypt", **params)
        if not resp.get("decrypted"):
            return None
        return bytes.fromhex(resp["plaintext"])

    # --- IFAC issue-29 golden vector --------------------------------------

    def ifac_compute(self, packet_data: bytes, ifac_size: int | None = None) -> dict:
        """Compute the IFAC tag RNS would prepend, using this peer's live
        RNS-derived ifac_identity/ifac_key. Returns {ifac_key: bytes,
        ifac_size: int, signature: bytes, ifac: bytes}. The peer must have
        been started with network_name + passphrase.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {"handle": self.handle, "packet_data": packet_data.hex()}
        if ifac_size is not None:
            params["ifac_size"] = int(ifac_size)
        resp = self.bridge.execute("wire_ifac_compute", **params)
        return {
            "ifac_key": bytes.fromhex(resp["ifac_key"]),
            "ifac_size": int(resp["ifac_size"]),
            "signature": bytes.fromhex(resp["signature"]),
            "ifac": bytes.fromhex(resp["ifac"]),
        }

    def resource_poll(
        self, destination_hash: bytes, timeout_ms: int = 30000
    ) -> list:
        """Drain all reassembled Resource payloads received on a listener."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_resource_poll",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            timeout_ms=timeout_ms,
        )
        return [bytes.fromhex(p) for p in resp.get("resources", [])]

    def stop(self):
        if self.handle is None:
            return
        try:
            self.bridge.execute("wire_stop", handle=self.handle)
        except Exception:
            pass
        self.handle = None


@pytest.fixture
def wire_pair(request):
    """Return (server_impl, client_impl) tuple from pytest_generate_tests."""
    return request.param


def _parametrize_wire_shared_trio(metafunc):
    """Parametrize 3-peer shared-instance tests.

    Topology: A (local-client of B) → B (shared-instance master + TCP server,
    SUT) ← C (TCP client + destination host).

    The interesting axis is the master_impl (B) — the bug class we're
    hunting (reticulum-kt's transport-mode H1→H2 mutation breaking
    link_id) only triggers when a packet arrives at B's
    LocalServerInterface and exits via TCP.

    Pairing rule: local_client matches master_impl. The Python local-
    client makes RPC calls to the master (`_used_destination_data` is
    fired during link establishment, Reticulum.py:1135) which require a
    Python-compatible multiprocessing.connection RPC listener on the
    master — reticulum-kt doesn't have one, so a python-client →
    kotlin-master pairing fails on AuthenticationError before the on-wire
    link logic ever runs. That's a real feature gap but a different
    investigation than the linkId one this test covers; pinning local_client
    to the master's impl avoids confounding the two failure modes.
    Remote stays on reference because the destination host's role (receive
    LR, validate, respond LRPROOF) is well-trodden ground that's already
    covered by the homogeneous-reference baseline.
    """
    if "wire_shared_trio" not in metafunc.fixturenames:
        return
    impls = get_impl_list(metafunc.config) or []
    peers = sorted(set(impls) | {"reference"})
    trios = [(master, master, "reference") for master in peers]
    ids = [f"{master}-->{master}-->ref" for master, _, _ in trios]
    metafunc.parametrize("wire_shared_trio", trios, ids=ids, scope="function")


def _parametrize_wire_trio(metafunc):
    """Parametrize 3-peer multi-hop tests.

    Each test runs with (sender_impl, transport_impl, receiver_impl).
    The homogeneous reference-only triple is the sanity baseline; the
    (kotlin, reference, reference) case is the diagnostic topology
    where a Kotlin sender routes link data through a Python transport
    to a Python receiver — reproducing what Columba does over rnsd
    to Sideband.
    """
    if "wire_trio" not in metafunc.fixturenames:
        return
    impls = get_impl_list(metafunc.config) or []
    peers = sorted(set(impls) | {"reference"})
    trios = [(a, b, c) for a in peers for b in peers for c in peers]
    ids = [f"{a}->{b}->{c}" for a, b, c in trios]
    metafunc.parametrize("wire_trio", trios, ids=ids, scope="function")


@pytest.fixture
def wire_trio(request):
    """(sender_impl, transport_impl, receiver_impl) from parametrization."""
    return request.param


@pytest.fixture
def wire_3peer(wire_trio):
    """Three freshly-spawned bridge subprocesses arranged as
    sender → transport → receiver.

    Topology:

        sender (TCPClient)                 receiver (TCPClient)
               \\                                 /
                `----> transport (TCPServer) <---'
                       enable_transport=True

    The transport is the only peer that listens; the other two connect
    outbound to its port. Both sender and receiver share the transport
    as their only interface, so any packet from sender to receiver must
    cross the transport, making this the minimum topology for a
    multi-hop test.

    Yields (sender, transport, receiver) as `_WirePeer` objects. Caller
    sets up any listeners/announces/links they need.
    """
    sender_impl, transport_impl, receiver_impl = wire_trio
    bridges = [
        BridgeClient(resolve_command(sender_impl), env=_env_for(sender_impl)),
        BridgeClient(resolve_command(transport_impl), env=_env_for(transport_impl)),
        BridgeClient(resolve_command(receiver_impl), env=_env_for(receiver_impl)),
    ]
    sender = _WirePeer(bridges[0], role_label=f"sender({sender_impl})")
    transport = _WirePeer(bridges[1], role_label=f"transport({transport_impl})")
    receiver = _WirePeer(bridges[2], role_label=f"receiver({receiver_impl})")

    try:
        yield sender, transport, receiver
    finally:
        for peer in (sender, transport, receiver):
            try:
                peer.stop()
            except Exception:
                pass
        for b in bridges:
            try:
                b.close()
            except Exception:
                pass


@pytest.fixture
def wire_peers(wire_pair):
    """Two freshly-spawned bridge subprocesses, one server-role, one client-role.

    Yields (server, client) as `_WirePeer` objects. Caller is responsible for
    calling `server.start_tcp_server(...)` and `client.start_tcp_client(...)`
    with the port the server returns. Both bridges are torn down in the
    fixture finalizer regardless of whether the test raised.
    """
    server_impl, client_impl = wire_pair
    server_bridge = BridgeClient(
        resolve_command(server_impl), env=_env_for(server_impl)
    )
    client_bridge = BridgeClient(
        resolve_command(client_impl), env=_env_for(client_impl)
    )
    server = _WirePeer(server_bridge, role_label=f"server({server_impl})")
    client = _WirePeer(client_bridge, role_label=f"client({client_impl})")

    try:
        yield server, client
    finally:
        # Stop both peers before tearing down the pipe — mirrors the
        # behavioral fixture pattern so an in-process teardown hook on
        # the bridge side (e.g. Reticulum.stop) gets a chance to run
        # cleanly before its stdin closes.
        for peer in (server, client):
            try:
                peer.stop()
            except Exception:
                pass
        for b in (server_bridge, client_bridge):
            try:
                b.close()
            except Exception:
                pass


@pytest.fixture
def wire_mixed_relay_3peer():
    """Mixed interface-type relay: A (PipeInterface leaf) <-pipe-> B (Pipe+TCP
    relay, transport ON) <-TCP-> C (TCP client).

    Topology:

        a_leaf (A, PipeInterface, hosts D)
                 \\
                  v  named-FIFO pair (loopback byte bridge)
        relay   (B, PipeInterface + TCPServerInterface, transport ON)
                  ^
                  |  TCP loopback
        c_tcp   (C, TCPClientInterface)

    Purpose: exercise the in-transit link-MTU strip (CONFORMANCE_GAPS.md §2c,
    Transport.py:1593-1600). When C opens a Link to D, the LINKREQUEST is
    forwarded by B OUT the PipeInterface to A; PipeInterface is
    non-autoconfigure, so RNS strips the 3-byte LINK_MTU_SIZE signalling field
    and A's inbound link.mtu falls back to Reticulum.MTU (500). A test reads
    A's inbound link mtu via `a_leaf.link_mtu(link_id)` and asserts == 500;
    a direct TCP link (the positive control) negotiates a larger MTU.

    Reference-only (NOT impl-parametrized): PipeInterface FIFO-bridging is a
    Python-RNS construct (the separate-bridge-subprocess wire harness has no
    shared in-process Transport, so the only inter-process channel is the FIFO
    pair). The pipe hop is what makes the next-hop non-autoconfigure; a
    TCP-only relay cannot reproduce the strip (TCP is AUTOCONFIGURE_MTU=True).

    Start order: bring up the relay first, then the leaf and the TCP client
    (the FIFO `cat` commands block until both pipe ends are present, so the
    relay and leaf rendezvous once both are spawned). Call:
        port = relay.start_pipe_tcp_relay(relay.pipe_read_fifo,
                                          relay.pipe_write_fifo)
        a_leaf.start_pipe_peer(a_leaf.pipe_read_fifo, a_leaf.pipe_write_fifo)
        c_tcp.start_tcp_client(..., target_port=port)
    The FIFO paths are pre-created and attached to a_leaf / relay (swapped).

    Yields (a_leaf, relay, c_tcp) as `_WirePeer` objects.
    """
    fifodir = tempfile.mkdtemp(prefix="wire_mixed_fifos_")
    f_relay2a = os.path.join(fifodir, "relay2a")  # relay writes, leaf reads
    f_a2relay = os.path.join(fifodir, "a2relay")   # leaf writes, relay reads
    os.mkfifo(f_relay2a)
    os.mkfifo(f_a2relay)

    bridges = [
        BridgeClient(resolve_command("reference"), env=_env_for("reference")),
        BridgeClient(resolve_command("reference"), env=_env_for("reference")),
        BridgeClient(resolve_command("reference"), env=_env_for("reference")),
    ]
    a_leaf = _WirePeer(bridges[0], role_label="a_leaf(reference)")
    relay = _WirePeer(bridges[1], role_label="relay(reference)")
    c_tcp = _WirePeer(bridges[2], role_label="c_tcp(reference)")

    # Pre-wire the FIFO paths (read/write swapped between the two pipe ends).
    a_leaf.pipe_read_fifo = f_relay2a
    a_leaf.pipe_write_fifo = f_a2relay
    relay.pipe_read_fifo = f_a2relay
    relay.pipe_write_fifo = f_relay2a

    try:
        yield a_leaf, relay, c_tcp
    finally:
        for peer in (a_leaf, c_tcp, relay):
            try:
                peer.stop()
            except Exception:
                pass
        for b in bridges:
            try:
                b.close()
            except Exception:
                pass
        shutil.rmtree(fifodir, ignore_errors=True)


@pytest.fixture
def wire_shared_trio(request):
    """(local_client_impl, master_impl, remote_impl) from parametrization."""
    return request.param


@pytest.fixture
def wire_shared_3peer(wire_shared_trio):
    """Three freshly-spawned bridges arranged as
    [local-client A] → [shared-instance master B (SUT)] ← [TCP-client C].

    Topology:

        local_client (A, LocalClientInterface)
                          \\
                           v   AF_UNIX/TCP loopback (shared instance)
        shared_master (B, LocalServerInterface + TCPServerInterface)
                           ^
                           |   TCP loopback
        remote_host (C, TCPClientInterface)

    Mirrors the production case where Eridanus (A) connects via Carina or
    Sideband (B, the shared-instance master on the phone) which then routes
    out over a TCP interface to a remote rrcd hub on a Mac (C).

    This fixture is opinionated about start order: B must be up before A
    can attach as a client (otherwise A would either fail to connect, or
    on Python's auto-detect path become its own master and silently break
    the test topology). The fixture does not start anything for the caller
    — call `master.start_tcp_server(share_instance=True,
    share_instance_type='tcp')` first, then `local_client.start_local_client(
    shared_instance_port=master.shared_instance_port)`, then `remote.
    start_tcp_client(target_port=master.port)`.

    Yields (local_client, master, remote) as `_WirePeer` objects.
    """
    local_impl, master_impl, remote_impl = wire_shared_trio
    bridges = [
        BridgeClient(resolve_command(local_impl), env=_env_for(local_impl)),
        BridgeClient(resolve_command(master_impl), env=_env_for(master_impl)),
        BridgeClient(resolve_command(remote_impl), env=_env_for(remote_impl)),
    ]
    local_client = _WirePeer(
        bridges[0], role_label=f"local_client({local_impl})"
    )
    master = _WirePeer(bridges[1], role_label=f"master({master_impl})")
    remote = _WirePeer(bridges[2], role_label=f"remote({remote_impl})")

    try:
        yield local_client, master, remote
    finally:
        # Tear down in reverse start-order so the local client doesn't
        # observe the master vanishing mid-stop and emit error logs.
        for peer in (local_client, remote, master):
            try:
                peer.stop()
            except Exception:
                pass
        for b in bridges:
            try:
                b.close()
            except Exception:
                pass
