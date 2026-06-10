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
import time

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
        # Full bridge response from the most recent announce(); lets a caller
        # that enabled ratchets read back the echoed ratchets_enabled /
        # ratchet_count without a second round trip.
        self.last_announce: dict | None = None

    def start_tcp_server(
        self,
        network_name: str,
        passphrase: str,
        mode: str | None = None,
        share_instance: bool = False,
        share_instance_type: str | None = None,
        enable_transport: bool = True,
        fixed_mtu: int | None = None,
        ifac_size: int | None = None,
        bitrate: int | None = None,
        respond_to_probes: bool = False,
        use_implicit_proof: bool | None = None,
        enable_remote_management: bool = False,
        remote_management_allowed: list | None = None,
    ) -> int:
        """Bring up a TCPServerInterface on this peer.

        ifac_size (BITS), bitrate (bps), respond_to_probes, use_implicit_proof,
        enable_remote_management, remote_management_allowed (list of hex hashes)
        are optional reticulum_config knobs written into this peer's config so a
        test can read the floored/derived/posture value back off the live RNS
        objects. Omit a knob to keep RNS's own default.

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

        fixed_mtu (int, optional): pin the interface to a fixed link MTU so the
        negotiated link SDU stays small. With a small enough MTU a modest
        Resource payload chunks into >74 parts and the real on-wire HMU
        handshake (Resource.py:140/:483-495, Link.py:1100/:1122) is driven —
        unlike resource_create(force_sdu=...), which only forces the per-part
        SDU at construction time without sending anything. Both peers of a link
        must use the same fixed_mtu for the small SDU to survive negotiation.
        """
        kwargs: dict = {"network_name": network_name, "passphrase": passphrase}
        if mode is not None:
            kwargs["mode"] = mode
        if fixed_mtu is not None:
            kwargs["fixed_mtu"] = int(fixed_mtu)
        if share_instance:
            kwargs["share_instance"] = True
            if share_instance_type is not None:
                kwargs["share_instance_type"] = share_instance_type
        if not enable_transport:
            kwargs["enable_transport"] = False
        if ifac_size is not None:
            kwargs["ifac_size"] = int(ifac_size)
        if bitrate is not None:
            kwargs["bitrate"] = int(bitrate)
        if respond_to_probes:
            kwargs["respond_to_probes"] = True
        if use_implicit_proof is not None:
            kwargs["use_implicit_proof"] = bool(use_implicit_proof)
        if enable_remote_management:
            kwargs["enable_remote_management"] = True
        if remote_management_allowed is not None:
            kwargs["remote_management_allowed"] = list(remote_management_allowed)
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
        fixed_mtu: int | None = None,
    ):
        """Bring up a TCPClientInterface pointing at a remote.

        fixed_mtu (int, optional): mirror of start_tcp_server(fixed_mtu=...).
        Both ends of a link must pin the same fixed MTU for the small link SDU
        to survive negotiation and drive a >74-part Resource into the on-wire
        HMU handshake.
        """
        kwargs: dict = {
            "network_name": network_name,
            "passphrase": passphrase,
            "target_host": target_host,
            "target_port": target_port,
        }
        if mode is not None:
            kwargs["mode"] = mode
        if fixed_mtu is not None:
            kwargs["fixed_mtu"] = int(fixed_mtu)
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

    def announce(
        self,
        app_name: str,
        aspects: list,
        app_data: bytes = b"",
        enable_ratchets: bool = False,
        app_data_empty: bool = False,
    ) -> bytes:
        """Create and announce a fresh SINGLE IN destination; return its hash.

        enable_ratchets (bool, default False): enable per-destination ratchets
        (Destination.enable_ratchets) BEFORE announcing, so the announce carries
        the latest ratchet public key and the destination grows a real ratchet
        store. cmd_wire_announce honors this (wire_tcp.py) — it is the
        "A enables ratchets + announces" precondition for the destination-level
        ratchet observables (read_ratchets / destination_latest_ratchet_id /
        rotate_ratchet / set_ratchet_interval / set_retained_ratchets /
        ratchet_file_roundtrip).

        The full bridge response is stashed on `self.last_announce`, so a caller
        that enabled ratchets can assert the echoed `ratchets_enabled` /
        `ratchet_count` without a second round trip.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "app_name": app_name,
            "aspects": list(aspects),
            "app_data": app_data.hex(),
        }
        if enable_ratchets:
            params["enable_ratchets"] = True
        # app_data_empty requests an explicit b"" app_data (present-but-empty),
        # distinct from omitting app_data; cmd_wire_announce only treats an empty
        # app_data as present when this flag is set, otherwise it sends None.
        if app_data_empty:
            params["app_data_empty"] = True
        resp = self.bridge.execute("wire_announce", **params)
        self.last_announce = resp
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
        strategy: str | None = None,
    ) -> None:
        """Register a fixed-response request handler on a listening
        destination — the bridge plugs in a generator that returns the
        given bytes when a request for `path` arrives.

        `allow` (the request policy / strategy, Destination.register_request_handler,
        Destination.py:370-401):
          - "all"  -> RNS.Destination.ALLOW_ALL  (default).
          - "list" -> RNS.Destination.ALLOW_LIST, gated on the requester's
            identified Identity (`allowed_identity_hashes=[<16-byte hash>, ...]`),
            mirroring the LXMF lxmd SYNC_REQUEST_PATH authentication model.
          - "none" -> RNS.Destination.ALLOW_NONE: every request is refused, so a
            Link.request for `path` gets no response (status FAILED). Register a
            second ALLOW_ALL path as the positive control.

        `strategy` is an explicit alias for `allow` (the contract names this
        policy the request "strategy"); when given it overrides `allow`. Both
        map to the wire command's `allow` parameter.
        """
        assert self.handle, "start_* must be called first"
        effective_allow = strategy if strategy is not None else allow
        params = {
            "handle": self.handle,
            "destination_hash": destination_hash.hex(),
            "path": path,
            "response": response.hex(),
            "allow": effective_allow,
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

    def link_request_large(
        self,
        link_id: bytes,
        path: str,
        data: bytes = b"",
        timeout_ms: int = 30000,
    ) -> dict:
        """Issue link.request expecting a response larger than the link MDU.

        A handler returning ~50 KB cannot answer in a single packet, so RNS
        delivers the response as a Resource and the RequestReceipt only reaches
        READY once that Resource has fully transferred (Link.py:496-517/:898-901/
        :939-952). This variant blocks long enough for the resource-backed
        response to complete and returns {status, response, response_time_s}
        with `status == "ready"` and `response` the full byte-exact response
        (hex). Register the large response first via register_request_handler;
        the >MDU request-data path is exercised by passing a large `data`.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_request_large",
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
        self,
        destination_hash: bytes,
        timeout_ms: int = 5000,
        from_identity_hash: bool = False,
    ) -> dict | None:
        """Look up the Identity associated with a destination hash.

        Returns a dict {public_key, hash, app_data} when this peer has received
        an announce for the destination, or None when unknown. Optional
        timeout polls Transport state — without it, the call returns
        immediately based on the current known_destinations table.

        app_data (bytes | None): the last app_data heard for this destination
        (RNS.Identity.recall_app_data, Identity.py:161-174). It is byte-exact
        the app_data the announcer passed to announce(app_data=...); None when
        the announce carried no app_data, and the whole call returns None for an
        unknown hash (the negative control for recall_app_data).

        from_identity_hash (bool, default False): when True, `destination_hash`
        is interpreted as an IDENTITY hash and the lookup matches on the
        truncated identity hash instead of the destination hash
        (RNS.Identity.recall(..., from_identity_hash=True), Identity.py:129-141).
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "destination_hash": destination_hash.hex(),
            "timeout_ms": timeout_ms,
        }
        if from_identity_hash:
            params["from_identity_hash"] = True
        resp = self.bridge.execute("wire_identity_recall", **params)
        if not resp.get("found"):
            return None
        # app_data is hex when present; "" decodes to b"" (announce carried an
        # empty app_data), absent/None stays None (no app_data heard).
        app_data_hex = resp.get("app_data")
        app_data = (
            bytes.fromhex(app_data_hex) if app_data_hex is not None else None
        )
        return {
            "public_key": bytes.fromhex(resp["public_key"]),
            "hash": bytes.fromhex(resp["hash"]),
            "app_data": app_data,
        }

    def listen(
        self,
        app_name: str,
        aspects: list,
        resource_strategy: str | None = None,
        enable_ratchets: bool = False,
        open_channel: bool = True,
        buffer_stream_ids: list | None = None,
    ) -> bytes:
        """Register an IN destination that accepts incoming Links.

        Returns the destination_hash. The listening identity's hash and raw
        public_key are recorded on the peer (see `listening_identity`) so
        recall tests can assert the recalled key is byte-identical to the
        announced one (N-M3), not merely the right length.

        enable_ratchets (bool, default False): register the destination with
        ratchets enabled (Destination.enable_ratchets) so the destination-level
        ratchet observables — read_ratchets, destination_latest_ratchet_id,
        rotate_ratchet, set_ratchet_interval, set_retained_ratchets,
        ratchet_file_roundtrip — operate on a ratchet-bearing destination
        (CONFORMANCE_GAPS.md §4c). cmd_wire_listen honors this param
        (wire_tcp.py), enabling ratchets on the IN destination before its
        immediate announce, exactly as cmd_wire_announce does.

        resource_strategy ('all'|'none'|'app', default None -> bridge default
        of 'all'): how an inbound Link accepts incoming Resources
        (Link.set_resource_strategy, Link.py:1087-1098).
          - 'all'  -> RNS.Link.ACCEPT_ALL: every Resource is accepted.
          - 'none' -> RNS.Link.ACCEPT_NONE: no parts flow; the sender's
            transfer ends FAILED.
          - 'app'  -> RNS.Link.ACCEPT_APP: a per-Resource callback decides;
            it returns True for some advertised payloads and False for others,
            so a rejected Resource drives RESOURCE_RCL back to the sender
            (status REJECTED) while an accepted one transfers normally. The
            accept/reject predicate is defined deterministically by the wire
            command handler (see [wire-cmds] wire_listen) — keep test payloads
            on the two sides of whatever boundary it advertises.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "app_name": app_name,
            "aspects": list(aspects),
        }
        if resource_strategy is not None:
            params["resource_strategy"] = str(resource_strategy)
        if enable_ratchets:
            params["enable_ratchets"] = True
        # open_channel=False makes the inbound link accept WITHOUT a channel, so
        # an inbound CHANNEL packet is dropped unproven (no-channel-no-proof).
        if not open_channel:
            params["open_channel"] = False
        # buffer_stream_ids registers extra receiver-relative RawChannelReaders
        # for the multi-reader stream-id filtering test.
        if buffer_stream_ids:
            params["buffer_stream_ids"] = [int(s) for s in buffer_stream_ids]
        resp = self.bridge.execute("wire_listen", **params)
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
        self,
        link_id: bytes,
        data: bytes,
        timeout_ms: int = 30000,
        metadata: bytes | None = None,
        wait: bool = True,
    ) -> dict:
        """Send arbitrary-size bytes via the RNS Resource API.

        Returns the bridge's response dict. Used to exercise multi-packet
        chunked transfer over a Link (the path LXMF uses for image/file
        attachments).

        metadata (bytes, optional): packed into the Resource's 'x' metadata
        field (Resource.py:260-268 — 3-byte BE length + body; flag bit 5 set,
        Resource.py:207-208). When present the response reports
        has_metadata=True and the receiver round-trips both the payload and
        the metadata. None omits the field entirely (has_metadata=False).

        wait (bool, default True): when True the bridge blocks until the
        transfer concludes and returns {success, status, size, timed_out}
        (plus original_hash / total_segments / parts / compressed /
        has_metadata, all read off the real RNS.Resource). When False the
        bridge starts the transfer on a background thread and returns
        immediately with {resource_id, started} so the test can abort it
        mid-flight via resource_cancel(resource_id) — the only way to drive
        RESOURCE_ICL (a blocking send can't be cancelled on the same bridge
        connection).
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "link_id": link_id.hex(),
            "data": data.hex(),
            "timeout_ms": timeout_ms,
        }
        if metadata is not None:
            params["metadata"] = metadata.hex()
        if not wait:
            params["wait"] = False
        return self.bridge.execute("wire_resource_send", **params)

    def resource_create(
        self,
        link_id: bytes,
        data: bytes,
        force_sdu: int | None = None,
        include_parts: bool = True,
        auto_compress: bool = True,
        metadata: bytes | None = None,
    ) -> dict:
        """Construct a real RNS.Resource on an established Link and report
        the attributes the implementation computed — WITHOUT advertising or
        sending it.

        The honest, delegating replacement for the deleted synthetic
        resource_* primitive commands: the bridge builds a real
        RNS.Resource (full __init__, advertise=False so nothing hits the
        wire) and reads back `hash`, `truncated_hash`, `random_hash`,
        `expected_proof`, `hashmap`, `parts`, `num_parts`, `total_segments`,
        `segment_index`, `original_hash`, `compressed`, `has_metadata`, and
        the size/flag fields — nothing is recomputed.

        metadata (bytes, optional): packed into the Resource's 'x' metadata
        field (Resource.py:260-268). When present the response reports
        has_metadata=True and the flag's bit 5 is set; None omits it
        (has_metadata=False). `original_hash` is the pre-segmentation hash RNS
        chains multi-segment transfers against (Resource.py:445-448), surfaced
        so a >2-segment chaining test can pin it.

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
        if metadata is not None:
            params["metadata"] = metadata.hex()
        return self.bridge.execute("wire_resource_create", **params)

    def resource_cancel(self, resource_id: str) -> dict:
        """Abort an in-flight outbound Resource transfer (RNS.Resource.cancel).

        `resource_id` is the handle returned by a non-blocking
        resource_send(..., wait=False). Cancelling mid-transfer is the only way
        to drive RESOURCE_ICL (initiator cancel, Link.py:1131): the receiver's
        inbound Resource concludes with status FAILED and its accepting Link
        observes the ICL. Returns {cancelled} (and echoes resource_id).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_cancel",
            handle=self.handle,
            resource_id=resource_id,
        )

    def resource_receiver_status(
        self, destination_hash: bytes, timeout_ms: int = 0
    ) -> dict:
        """Read the receiver-side state of the most recent inbound Resource on
        a listening destination.

        The discriminating observable for the HMU and bz2-bomb cases:
          hmu_requests_sent       -> count of hashmap-update requests the
            receiver issued (request_next over the >74-part hashmap,
            Resource.py:483-495/:503),
          hashmap_updates_received-> hashmap segments the receiver took in
            (Resource.hashmap_height, Resource.py:492-499),
          status / status_name    -> the inbound Resource's RNS status int
            (TRANSFERRING=3 / ASSEMBLING=5 / COMPLETE=6 / FAILED=7 /
            CORRUPT=8),
          corrupt                 -> True iff status == CORRUPT (the
            decompression-bomb / over-bound guard fired, Resource.py:686-689).
        Optionally polls up to timeout_ms for an inbound Resource to appear /
        conclude. Pair with listener_link_status to confirm the link was torn
        down after a CORRUPT verdict.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_receiver_status",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            timeout_ms=timeout_ms,
        )

    def resource_send_bomb(
        self, link_id: bytes, decompressed_size: int, timeout_ms: int = 30000
    ) -> dict:
        """Send a crafted Resource whose advertised compressed payload expands
        past the receiver's decompression bound (Resource.py:686-687,
        max_length=AUTO_COMPRESS_MAX_SIZE).

        Drives the decompression-bomb guard on the real receive path: the
        receiver's BZ2Decompressor.decompress(max_length=...) stops short of
        EOF, so RNS marks the Resource CORRUPT and tears the link down. The
        sender's return dict reports {success, status} (the transfer ends
        FAILED on the sender); observe the CORRUPT verdict via
        resource_receiver_status and the teardown via listener_link_status on
        the receiver. `decompressed_size` sets how far over the bound the
        crafted payload inflates.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_send_bomb",
            handle=self.handle,
            link_id=link_id.hex(),
            decompressed_size=int(decompressed_size),
            timeout_ms=timeout_ms,
        )

    # --- Link lifecycle observation ---------------------------------------

    def link_status(self, link_id: bytes) -> dict:
        """Lifecycle snapshot of an outbound link: status/status_name,
        teardown_reason/teardown_reason_name, no_inbound_for_ms,
        last_keepalive_ago_ms, keepalive_s, stale_time_s, rtt.

        Also surfaces the negotiated link parameters (Link.py:148-151/:405-406/
        :609/:618/:636) once the link is established:
          mtu  -> link.mtu (None before ACTIVE),
          mdu  -> link.mdu (the update_mdu floor),
          mode -> link.mode (1 == MODE_AES256_CBC),
          remote_identity_hash -> hex of the remote Identity once identified,
            else None (Link.get_remote_identity),
          remote_identified    -> bool (Link.py:683-687/:1022-1024).
        remote_identity_hash is returned as a hex string (or None) — decode
        with bytes.fromhex when comparing against an identity hash.
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

    def link_request_timeout(
        self,
        link_id: bytes,
        path: str,
        data: bytes = b"",
        timeout_ms: int | None = None,
    ) -> dict:
        """Issue link.request and read back the RequestReceipt's computed
        timeout WITHOUT waiting for a response.

        With timeout_ms=None, RNS derives the timeout from the link RTT
        (rtt*6 + 11.25); pass an explicit timeout_ms to bypass the formula.
        Returns {receipt_timeout, rtt, traffic_timeout_factor,
        response_max_grace_time, explicit_timeout}.
        """
        assert self.handle, "start_* must be called first"
        params = dict(
            handle=self.handle, link_id=link_id.hex(), path=path, data=data.hex()
        )
        if timeout_ms is not None:
            params["timeout_ms"] = int(timeout_ms)
        return self.bridge.execute("wire_link_request_timeout", **params)

    def capture_response_packet(
        self,
        link_id: bytes,
        path: str,
        data: bytes = b"",
        timeout_ms: int = 15000,
    ) -> dict:
        """Issue link.request and capture the raw RESPONSE / RESOURCE_ADV
        packets RNS delivers on the initiator's link.

        Returns {status, response, captured:[{context, plaintext}...]} where
        plaintext is the decrypted RESPONSE packet payload (hex) and context
        is the packet's context byte (RESPONSE=0x0A, RESOURCE_ADV=0x02).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_capture_response_packet",
            handle=self.handle,
            link_id=link_id.hex(),
            path=path,
            data=data.hex(),
            timeout_ms=int(timeout_ms),
        )

    def interface_hw_mtu(self) -> dict:
        """Read this peer's wire interface HW_MTU + the link_mtu_discovery
        config flag.

        Returns {hw_mtu, link_mtu_discovery, reticulum_mtu, autoconfigure_mtu,
        fixed_mtu, class_hw_mtu}.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute("wire_interface_hw_mtu", handle=self.handle)

    def send_oversize_link_packet(self, link_id: bytes, size: int) -> dict:
        """Attempt a single link DATA packet of `size` bytes; report whether
        RNS accepts or rejects it at the negotiated link MTU bound.

        Returns {sent, rejected, error, mtu, mdu, packet_mtu, raw_len, size}.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_send_oversize_link_packet",
            handle=self.handle,
            link_id=link_id.hex(),
            size=int(size),
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

    # --- Link DATA proof strategy / keepalive byte values -----------------

    def send_link_data(
        self, link_id: bytes, data: bytes, create_receipt: bool = True
    ) -> dict:
        """Send a DATA packet OVER an established Link with a tracked receipt.

        Distinct from link_send (fire-and-forget over a Link) and send_packet
        (single SINGLE-destination packet): this drives the link-DATA proof
        path (Link.py:999-1008). With create_receipt=True the returning PROOF —
        emitted per the destination's proof strategy — drives a PacketReceipt
        to DELIVERED, which makes PROVE_ALL / PROVE_NONE / PROVE_APP observable:
          set_proof_strategy('all')  -> receipt reaches DELIVERED,
          set_proof_strategy('none') -> no proof, receipt never DELIVERS,
          set_proof_strategy('app')  -> DELIVERED only when the callback
            returns True for the packet.
        Returns {sent, receipt_id}; poll the receipt via packet_receipt_status
        (the bridge stashes it in the same receipts table as send_packet).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_send_link_data",
            handle=self.handle,
            link_id=link_id.hex(),
            data=data.hex(),
            create_receipt=bool(create_receipt),
        )

    def send_over_closed_link(self, link_id: bytes, data: bytes = b"") -> dict:
        """Attempt RNS.Packet.send() over a CLOSED link (Packet.py:280-286).

        The link must already be torn down (call link_teardown first). Returns
        {link_status, link_status_name, sent, bytes_transmitted}: a closed link
        yields sent=False and bytes_transmitted=0 (RNS transmits nothing).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_send_over_closed_link",
            handle=self.handle,
            link_id=link_id.hex(),
            data=data.hex(),
        )

    def send_keepalive_probe(self, link_id: bytes) -> dict:
        """Inject a decrypted 0xFF keepalive into a link's receive path.

        RNS keepalive is a single byte: the initiator emits 0xFF and a
        NON-initiator answers with 0xFE (Link.py:848-849/:1149-1151/:974). On a
        listener's inbound link (the non-initiator) this injects the 0xFF the
        initiator would send and reports the link's response so the 0xFE answer
        is observable; on an initiator's link it exercises the "don't bump
        last_data on my own 0xFF echo" branch. Returns {response} where
        `response` is the hex of the byte the link emitted in reply (e.g. "fe"
        for a non-initiator), plus whether last_inbound/last_data advanced.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_send_keepalive_probe",
            handle=self.handle,
            link_id=link_id.hex(),
        )

    def last_keepalive(self, link_id: bytes) -> dict:
        """Read the last keepalive payload byte this link emitted/answered.

        Returns {payload} (hex of the last keepalive byte, or None if none
        yet): "ff" for an initiator's probe, "fe" for a non-initiator's answer
        (Link.py:848-849/:1149-1151). Lets a test assert the exact keepalive
        byte values rather than only the timing observed by link_status'
        last_keepalive_ago_ms.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_last_keepalive",
            handle=self.handle,
            link_id=link_id.hex(),
        )

    # --- Channel out-of-order / duplicate / window ------------------------

    def channel_inject(self, link_id: bytes, envelopes: list) -> list:
        """Feed crafted envelopes into a link's real Channel receive path.

        envelopes: list of {"sequence": int, "data": bytes}. Returns the
        injected sequence list.
        """
        assert self.handle, "start_* must be called first"
        wire_envelopes = []
        for e in envelopes:
            if e.get("raw") is not None:
                # Raw-override: crafted envelope bytes fed verbatim to
                # Channel._receive (bypassing Envelope.pack) — e.g. a wrong
                # length field. sequence is informational only.
                raw = e["raw"]
                env = {
                    "raw": raw.hex() if isinstance(raw, (bytes, bytearray)) else raw,
                    "sequence": int(e.get("sequence", -1)),
                }
                wire_envelopes.append(env)
                continue
            env = {
                "sequence": int(e["sequence"]),
                "data": (
                    e["data"].hex()
                    if isinstance(e.get("data"), (bytes, bytearray))
                    else (e.get("data") or "")
                ),
            }
            if e.get("msgtype") is not None:
                env["msgtype"] = int(e["msgtype"])
            wire_envelopes.append(env)
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

    def channel_register(self, link_id: bytes, kind: str) -> dict:
        """Drive Channel message-type registration validation on a real channel.

        kind selects a crafted message class (non_message_base, msgtype_none,
        reserved, not_constructible, valid) or the special
        envelope_pack_no_msgtype path. Returns {accepted, error, ce_type}.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_channel_register",
            handle=self.handle,
            link_id=link_id.hex(),
            kind=kind,
        )

    def channel_send(
        self,
        link_id: bytes,
        data: bytes,
        drop_acks: bool = False,
        fail_outlet: bool = False,
        msgtype: int | None = None,
        timeout_ms: int = 20000,
    ) -> dict:
        """Perform a REAL Channel.send over an established link.

        The honest replacement for the dead cmd_rns_channel_send (zero callers).
        Sends a message through the link's real RNS.Channel (Channel.py:551-584)
        and, by default, waits for it to DELIVER or fail.

        channel_id contract: RNS has no separate channel id — a Channel is
        identified by its Link — so the wire command's `channel_id` parameter
        carries this link_id. Both keys are sent for robustness against either
        spelling on the handler side.

        drop_acks (default False): suppress the peer's ack of THIS message so
        the send receipt never DELIVERS. RNS then retransmits with an
        increasing timeout window and, after 5 unanswered tries, tears the link
        down (Channel.py:555-584/:295/:707) and shrinks the window. The return
        dict surfaces {sent, delivered, tries, sequence}; observe the resulting
        window shrink via channel_window (window/window_max decrement) and the
        teardown via link_status (status CLOSED).

        msgtype (optional): request a specific Channel MSGTYPE. A value
        >= 0xf000 is reserved (Channel.py:328-345) and must be rejected — the
        return dict reports {rejected, error} instead of sending.

        timeout_ms bounds how long the bridge waits for the delivery/teardown
        outcome before returning the current state.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            # A Channel is keyed by its Link; send under both the contract's
            # `channel_id` name and the `link_id` name the other channel_*
            # commands use, so the handler resolves it regardless of spelling.
            "channel_id": link_id.hex(),
            "link_id": link_id.hex(),
            "data": data.hex(),
            "drop_acks": bool(drop_acks),
            "fail_outlet": bool(fail_outlet),
            "timeout_ms": int(timeout_ms),
        }
        if msgtype is not None:
            params["msgtype"] = int(msgtype)
        return self.bridge.execute("wire_channel_send", **params)

    # --- Buffer / RawChannelReader / RawChannelWriter streaming -----------

    def buffer_stream(
        self,
        link_id: bytes,
        data: bytes,
        bomb: bool = False,
        bomb_decompressed_len: int | None = None,
        stream_id: int | None = None,
        eof_with_data: bool = False,
        use_close: bool = False,
        timeout_ms: int = 30000,
    ) -> dict:
        """Stream bytes over a link via RNS.Buffer (RawChannelWriter).

        Writes `data` through a RawChannelWriter on the link's Channel; the
        payload is chunked into StreamDataMessages (Channel SMT_STREAM_DATA
        0xff00) and reassembled by the peer's RawChannelReader. Drive a payload
        spanning several MAX_CHUNK_LEN (16 KiB) chunks plus a partial final
        chunk to exercise multi-chunk reassembly + EOF; read the result back
        with buffer_received on the receiver.

        bomb (default False): instead of `data`, write a single crafted chunk
        whose advertised compressed body decompresses past MAX_CHUNK_LEN
        (Buffer.py:95-97). The reader must abort (IOError, not silent
        truncation); buffer_received reports {aborted: True}.

        Returns {written, eof} (bytes written + whether EOF was flushed).
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "link_id": link_id.hex(),
            "data": data.hex(),
            "bomb": bool(bomb),
            "eof_with_data": bool(eof_with_data),
            "use_close": bool(use_close),
            "timeout_ms": int(timeout_ms),
        }
        if bomb_decompressed_len is not None:
            params["bomb_decompressed_len"] = int(bomb_decompressed_len)
        if stream_id is not None:
            params["stream_id"] = int(stream_id)
        return self.bridge.execute("wire_buffer_stream", **params)

    def buffer_received(
        self,
        destination_hash: bytes,
        timeout_ms: int = 30000,
        stream_id: int | None = None,
    ) -> dict:
        """Drain what a listener's RawChannelReader reassembled from a stream.

        Pairs with buffer_stream on the sender. Blocks up to timeout_ms for the
        stream to conclude (EOF) or abort. Returns {data, eof, aborted, error}:
          data    -> bytes reassembled byte-exact across all chunks,
          eof     -> True once the writer's EOF was seen,
          aborted -> True iff the reader hit the MAX_CHUNK_LEN decompression
            bound (the bz2-bomb case, Buffer.py:95-97),
          error   -> the abort reason string when aborted, else None.
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "destination_hash": destination_hash.hex(),
            "timeout_ms": int(timeout_ms),
        }
        if stream_id is not None:
            params["stream_id"] = int(stream_id)
        resp = self.bridge.execute("wire_buffer_received", **params)
        return {
            "data": bytes.fromhex(resp["data"]) if resp.get("data") else b"",
            "eof": bool(resp.get("eof", False)),
            "aborted": bool(resp.get("aborted", False)),
            "error": resp.get("error"),
        }

    def channel_emit_capture(
        self, link_id: bytes, data: bytes = b"", timeout_ms: int = 15000
    ) -> dict:
        """Send a real Channel message and capture the emitted Packet's context.

        Returns {context, packet_type, packet_hash, delivered, channel_context,
        data_context} — context is the context byte of the Packet the Channel
        outlet transmitted (must equal channel_context == RNS.Packet.CHANNEL).
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_channel_emit_capture",
            handle=self.handle,
            link_id=link_id.hex(),
            data=data.hex(),
            timeout_ms=int(timeout_ms),
        )

    def listener_proof_log(self, destination_hash: bytes) -> dict:
        """Return the receiver-side proof log {contexts, channel_proofs,
        channel_context} for a listening destination."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_listener_proof_log",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )

    def listener_channel_rx(self, destination_hash: bytes) -> dict:
        """Return the receiver-side Channel rx state {next_rx_sequence,
        next_sequence, rx_ring} for a listening destination."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_listener_channel_rx",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
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

    # --- Request-handler deregistration (ALLOW_NONE control) --------------

    def deregister_request_handler(self, destination_hash: bytes, path: str) -> bool:
        """Remove a previously-registered request handler
        (Destination.deregister_request_handler, Destination.py:389-401).

        Returns True if a handler for `path` was present and removed, False if
        there was none. The discriminating sequence: register_request_handler +
        a SUCCESSFUL link_request for `path` (positive control), then
        deregister_request_handler -> a subsequent link_request for the same
        path gets no response.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_deregister_request_handler",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            path=path,
        )
        return bool(resp.get("deregistered"))

    # --- Destination-level ratchets (real Destination.encrypt/decrypt) ----

    def read_ratchets(self, destination_hash: bytes) -> dict:
        """Read a ratchet-enabled destination's current ratchet state
        (wire_read_ratchets — Destination ratchet snapshot).

        Returns {ratchet_count, current_ratchet_id, previous_ratchet_id,
        ratchet_interval, retained_ratchets, latest_ratchet_id,
        latest_ratchet_time}; the three ratchet ids are decoded to bytes (or
        None). current/previous id + count are the rotation-gating observables;
        latest_ratchet_id is None until a real Destination.encrypt/decrypt has
        happened on the destination.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_read_ratchets",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )

        def _id(key):
            v = resp.get(key)
            return bytes.fromhex(v) if v else None

        return {
            "ratchet_count": int(resp.get("ratchet_count", 0)),
            "current_ratchet_id": _id("current_ratchet_id"),
            "previous_ratchet_id": _id("previous_ratchet_id"),
            "ratchet_interval": resp.get("ratchet_interval"),
            "retained_ratchets": resp.get("retained_ratchets"),
            "latest_ratchet_id": _id("latest_ratchet_id"),
            "latest_ratchet_time": resp.get("latest_ratchet_time"),
        }

    def destination_latest_ratchet_id(self, destination_hash: bytes) -> dict:
        """Drive a real Destination.encrypt+decrypt round trip on a ratchet-
        enabled destination and report the latest_ratchet_id tracking
        (Destination.py:595-643).

        Destination.encrypt auto-selects the current ratchet and records
        latest_ratchet_id; decrypt re-derives it. It is None until a real
        encrypt/decrypt happens. The destination must have been registered with
        ratchets enabled (announce(enable_ratchets=True) /
        listen(enable_ratchets=True)).

        Returns {decrypted, plaintext, latest_ratchet_id, encrypt_ratchet_id,
        current_ratchet_id, match, ratchet_count}; the three ratchet ids are
        decoded to bytes (or None) and plaintext to bytes (or None).
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_destination_latest_ratchet_id",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )

        def _id(key):
            v = resp.get(key)
            return bytes.fromhex(v) if v else None

        return {
            "decrypted": bool(resp.get("decrypted", False)),
            "plaintext": _id("plaintext"),
            "latest_ratchet_id": _id("latest_ratchet_id"),
            "encrypt_ratchet_id": _id("encrypt_ratchet_id"),
            "current_ratchet_id": _id("current_ratchet_id"),
            "match": bool(resp.get("match", False)),
            "ratchet_count": int(resp.get("ratchet_count", 0)),
        }

    def set_ratchet_interval(self, destination_hash: bytes, seconds: int) -> dict:
        """Set a ratchet-enabled destination's minimum rotation interval in
        seconds (real RNS.Destination.set_ratchet_interval, Destination.py:
        519-531).

        Returns {ok, ratchet_interval}: `ok` is False for a non-positive /
        non-int value (RNS rejects it and leaves the interval unchanged). To
        make INTERVAL gating observable without a real wait, pass
        rotate_ratchet(last_rotation_ago_s=...) to backdate the last-rotation
        timestamp at rotation time.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_set_ratchet_interval",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            seconds=int(seconds),
        )

    def rotate_ratchet(
        self, destination_hash: bytes, last_rotation_ago_s: float | None = None
    ) -> dict:
        """Attempt a ratchet rotation and observe the rotation-INTERVAL gate
        (Destination.rotate_ratchets, Destination.py:227-241) without a real
        wait.

        last_rotation_ago_s (optional): deterministically backdate the
        destination's latest_ratchet_time this many seconds into the past so the
        interval gate is open (value > ratchet_interval -> a new ratchet) or
        shut (value < ratchet_interval -> gated), no real sleep required.

        Returns {rotated, before_count, after_count, before_current_id,
        current_ratchet_id, previous_ratchet_id, ratchet_interval,
        latest_ratchet_time}:
          rotated             -> True iff a new ratchet was inserted
            (after_count > before_count); False iff the interval gated it.
          before_count/after_count -> len(destination.ratchets) around the
            attempt (read to assert the retained-ratchets cap).
          before_current_id   -> the newest ratchet id before this call (bytes)
            or None.
          current_ratchet_id  -> the newest ratchet id after this call (bytes)
            or None — differs from before_current_id on a real rotation.
          previous_ratchet_id -> the second-newest ratchet id after this call
            (bytes) or None; equals before_current_id after a rotation.
        The three ratchet ids are decoded to bytes (or None).
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "destination_hash": destination_hash.hex(),
        }
        if last_rotation_ago_s is not None:
            params["last_rotation_ago_s"] = float(last_rotation_ago_s)
        resp = self.bridge.execute("wire_rotate_ratchet", **params)

        def _id(key):
            v = resp.get(key)
            return bytes.fromhex(v) if v else None

        return {
            "rotated": bool(resp.get("rotated", False)),
            "before_count": int(resp.get("before_count", 0)),
            "after_count": int(resp.get("after_count", 0)),
            "before_current_id": _id("before_current_id"),
            "current_ratchet_id": _id("current_ratchet_id"),
            "previous_ratchet_id": _id("previous_ratchet_id"),
            "ratchet_interval": resp.get("ratchet_interval"),
            "latest_ratchet_time": resp.get("latest_ratchet_time"),
        }

    def get_adopted_ratchet(self, destination_hash: bytes) -> dict:
        """Report the ratchet this peer ADOPTED for a REMOTE destination after
        hearing its ratcheted announce (wire_get_adopted_ratchet ->
        RNS.Identity.get_ratchet / _get_ratchet_id, Identity.py:396-411,499-520).

        Returns {found, ratchet_public, ratchet_id}; ratchet_public (32 bytes)
        and ratchet_id (10 bytes) are decoded to bytes (or None when this peer
        has not adopted a ratchet for the destination).
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_get_adopted_ratchet",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )
        pub = resp.get("ratchet_public")
        rid = resp.get("ratchet_id")
        return {
            "found": bool(resp.get("found", False)),
            "ratchet_public": bytes.fromhex(pub) if pub else None,
            "ratchet_id": bytes.fromhex(rid) if rid else None,
        }

    def encrypt_to_remote(
        self, destination_hash: bytes, plaintext: bytes, use_ratchet: bool = True
    ) -> dict:
        """Encrypt to a REMOTE destination, auto-selecting the ratchet this peer
        ADOPTED from its announce (wire_encrypt_to_remote -> RNS.Identity.recall
        + get_ratchet + Identity.encrypt, mirroring Destination.encrypt's target
        choice, Destination.py:595-599).

        use_ratchet=False forces the static X25519 key (negative control).
        Returns {ciphertext, used_ratchet, ratchet_id, ratchet_public}; bytes
        fields decoded (ratchet_id/ratchet_public None when no ratchet used).
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_encrypt_to_remote",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            plaintext=plaintext.hex(),
            use_ratchet=bool(use_ratchet),
        )
        rid = resp.get("ratchet_id")
        pub = resp.get("ratchet_public")
        return {
            "ciphertext": bytes.fromhex(resp["ciphertext"]),
            "used_ratchet": bool(resp.get("used_ratchet", False)),
            "ratchet_id": bytes.fromhex(rid) if rid else None,
            "ratchet_public": bytes.fromhex(pub) if pub else None,
        }

    def destination_decrypt(
        self, destination_hash: bytes, ciphertext: bytes
    ) -> dict:
        """Decrypt a ciphertext on a local SINGLE destination and report which
        ratchet decrypted it (wire_destination_decrypt -> RNS.Destination.decrypt,
        Destination.py:611-643).

        latest_ratchet_id is the id of the ratchet that succeeded, or None when
        the static private key decrypted it (Identity.decrypt, Identity.py:886-913).
        Returns {decrypted, plaintext, latest_ratchet_id} (bytes decoded).
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_destination_decrypt",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            ciphertext=ciphertext.hex(),
        )
        pt = resp.get("plaintext")
        rid = resp.get("latest_ratchet_id")
        return {
            "decrypted": bool(resp.get("decrypted", False)),
            "plaintext": bytes.fromhex(pt) if pt else None,
            "latest_ratchet_id": bytes.fromhex(rid) if rid else None,
        }

    def reannounce(
        self,
        destination_hash: bytes,
        app_data: bytes | None = None,
        rotate_ago_s: float | None = None,
    ) -> dict:
        """Re-announce an already-registered IN destination (wire_reannounce ->
        RNS.Destination.announce, Destination.py:265-311).

        rotate_ago_s backdates latest_ratchet_time so the rotation gate opens and
        a genuinely NEW ratchet is announced (the "newer announce replaces the
        adopted ratchet" driver). Returns {announced, current_ratchet_id} (id
        decoded to bytes or None).
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "destination_hash": destination_hash.hex(),
        }
        if app_data is not None:
            params["app_data"] = app_data.hex()
        if rotate_ago_s is not None:
            params["rotate_ago_s"] = float(rotate_ago_s)
        resp = self.bridge.execute("wire_reannounce", **params)
        rid = resp.get("current_ratchet_id")
        return {
            "announced": bool(resp.get("announced", False)),
            "current_ratchet_id": bytes.fromhex(rid) if rid else None,
        }

    def set_proof_implicit(self, enabled: bool) -> dict:
        """Toggle this instance's implicit-vs-explicit single-packet PROOF policy
        (wire_set_proof_implicit -> RNS.Reticulum.should_use_implicit_proof,
        Reticulum.py:1699-1705). With enabled=False the prover emits the explicit
        packet_hash||signature proof form. Returns {implicit_proof}.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_set_proof_implicit",
            handle=self.handle,
            enabled=bool(enabled),
        )

    def set_retained_ratchets(
        self, destination_hash: bytes, n: int, pad_to: int | None = None
    ) -> dict:
        """Set how many past ratchets a destination retains and read the cap
        back (real RNS.Destination.set_retained_ratchets / _clean_ratchets,
        Destination.py:504-517/:205-208).

        set_retained_ratchets(n) sets retained_ratchets and runs _clean_ratchets,
        which truncates destination.ratchets to Destination.RATCHET_COUNT when
        the list exceeds the cap.

        pad_to (optional): first inflate the ratchet list with that many real
        freshly-generated ratchets before applying the cap, so RATCHET_COUNT
        truncation is observable cheaply.

        Returns {ok, retained_ratchets, ratchet_count, ratchet_count_cap}; `ok`
        is False for a non-positive / non-int n (RNS rejects it and leaves
        retained_ratchets unchanged).
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "destination_hash": destination_hash.hex(),
            "n": int(n),
        }
        if pad_to is not None:
            params["pad_to"] = int(pad_to)
        return self.bridge.execute("wire_set_retained_ratchets", **params)

    def ratchet_file_roundtrip(self, destination_hash: bytes) -> dict:
        """Persist + reload a destination's ratchet store via RNS's own
        persist/reload (Destination._persist_ratchets/_reload_ratchets,
        Destination.py:210-225/:426-464).

        The handler drives Destination._persist_ratchets (signed on-disk write),
        clears the in-memory list, then reloads via Destination._reload_ratchets
        -- which validates the embedded signature and only repopulates the
        ratchet list when it verifies (raising otherwise). Returns
        {ratchets_path_set, reload_ok, ratchet_count_before, ratchet_count_after,
        roundtrip_match, ratchet_ids}; reload_ok True (with roundtrip_match True)
        means RNS accepted the just-persisted signed store and reproduced the
        ratchet list byte-exact. The bridge does not re-parse the on-disk format.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_ratchet_file_roundtrip",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )

    # --- PROOF emission for a single (non-link) packet --------------------

    def send_packet_with_proof_request(
        self,
        destination_hash: bytes,
        data: bytes = b"",
        app_name: str = "conformance",
        aspects: list | None = None,
        timeout_ms: int = 10000,
    ) -> dict:
        """Send a single SINGLE-destination DATA packet (tracked PacketReceipt)
        and capture the PROOF the receiver returns per its proof strategy
        (Destination.py:359-368, Identity.py:959-970).

        Returns the read-back straight off the real PacketReceipt/proof:
        {sent, receipt_id, hops, delivered, proved, implicit_proof_config,
        proof_data, proof_len, proof_is_implicit, proof_is_explicit,
        impl_length, expl_length}. `proof_data` is decoded to bytes (or None
        when no proof returned); proof_is_implicit/proof_is_explicit reflect
        whether the captured proof matches RNS's IMPL_LENGTH/EXPL_LENGTH, and
        implicit_proof_config is RNS.Reticulum.should_use_implicit_proof(). The
        destination identity must already be known via a received announce.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_send_packet_with_proof_request",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            data=data.hex(),
            app_name=app_name,
            aspects=list(aspects if aspects is not None else ("wire",)),
            timeout_ms=int(timeout_ms),
        )
        proof_hex = resp.get("proof_data")
        return {
            "sent": bool(resp.get("sent", False)),
            "receipt_id": resp.get("receipt_id"),
            "hops": resp.get("hops"),
            "delivered": bool(resp.get("delivered", False)),
            "proved": bool(resp.get("proved", False)),
            "implicit_proof_config": resp.get("implicit_proof_config"),
            "proof_data": bytes.fromhex(proof_hex) if proof_hex else None,
            "proof_len": resp.get("proof_len"),
            "proof_is_implicit": resp.get("proof_is_implicit"),
            "proof_is_explicit": resp.get("proof_is_explicit"),
            "impl_length": resp.get("impl_length"),
            "expl_length": resp.get("expl_length"),
            # Raw wire frame of the emitted PROOF + the proved packet's full
            # hash, so a test can pin the proof packet's flag-byte shape and
            # its truncated-hash destination addressing.
            "proof_raw": (
                bytes.fromhex(resp["proof_raw"]) if resp.get("proof_raw") else None
            ),
            "proved_packet_hash": (
                bytes.fromhex(resp["proved_packet_hash"])
                if resp.get("proved_packet_hash") else None
            ),
        }

    # --- PLAIN destination no-op encrypt / decrypt ------------------------

    def plain_encrypt(
        self,
        plaintext: bytes,
        app_name: str = "conformance",
        aspects: list | None = None,
    ) -> bytes:
        """PLAIN-destination encrypt: a no-op passthrough (Destination.py:592-593).

        Destination.encrypt on a PLAIN-type destination returns the plaintext
        unchanged. Returns the ciphertext bytes, which a conforming impl makes
        byte-identical to the plaintext (pair with plain_decrypt; the property
        is encrypt(pt) == pt and decrypt(ct) == ct, not merely a round-trip).
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_plain_encrypt",
            handle=self.handle,
            plaintext=plaintext.hex(),
            app_name=app_name,
            aspects=list(aspects if aspects is not None else ("plain",)),
        )
        return bytes.fromhex(resp["ciphertext"])

    def plain_decrypt(
        self,
        ciphertext: bytes,
        app_name: str = "conformance",
        aspects: list | None = None,
    ) -> bytes:
        """PLAIN-destination decrypt: a no-op passthrough (Destination.py:618-619).

        Destination.decrypt on a PLAIN-type destination returns the ciphertext
        unchanged. Returns the plaintext bytes, byte-identical to the input.
        """
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_plain_decrypt",
            handle=self.handle,
            ciphertext=ciphertext.hex(),
            app_name=app_name,
            aspects=list(aspects if aspects is not None else ("plain",)),
        )
        return bytes.fromhex(resp["plaintext"])

    # --- Known-public-key mismatch rejection ------------------------------

    def known_key_validate(
        self,
        app_name: str,
        aspects: list | None = None,
        plant: str = "mismatch",
        app_data: bytes | None = None,
    ) -> dict:
        """Validate a genuinely-signed announce against a planted known public
        key for the same destination hash (Identity.validate_announce known-key
        guard, Identity.py:583-589).

        validate_announce rejects an otherwise-valid announce when the
        destination hash is already bound to a DIFFERENT public key (the
        anti-path-hijack / hash-collision guard). The handler builds a real
        SINGLE destination + signed announce, then seeds
        Identity.known_destinations[dest_hash] per `plant` before validating:
          plant='mismatch' -> a DIFFERENT valid key is stored (announce REJECTED),
          plant='match'    -> the announce's own key is stored (accepted),
          plant='none'     -> no prior entry (accepted).
        The same announce flips accept/reject solely on the stored key.

        Returns {validated, destination_hash, public_key, planted_public_key,
        plant}; the destination hash and the two public keys are decoded to
        bytes (planted_public_key is None for plant='none').
        """
        assert self.handle, "start_* must be called first"
        params: dict = {
            "handle": self.handle,
            "app_name": app_name,
            "aspects": list(aspects if aspects is not None else ()),
            "plant": plant,
        }
        if app_data is not None:
            params["app_data"] = app_data.hex()
        resp = self.bridge.execute("wire_known_key_validate", **params)

        def _b(key):
            v = resp.get(key)
            return bytes.fromhex(v) if v else None

        return {
            "validated": bool(resp.get("validated", False)),
            "destination_hash": _b("destination_hash"),
            "public_key": _b("public_key"),
            "planted_public_key": _b("planted_public_key"),
            "plant": resp.get("plant"),
        }

    # --- Link teardown forgery / identify-before-ACTIVE (deferred edges) --

    def send_forged_link_close(self, link_id: bytes, forged_id: bytes) -> dict:
        """Inject a LINKCLOSE over an established link whose embedded link_id is
        WRONG, and report whether the link survived (Link.teardown_packet,
        Link.py:710-722).

        Link.teardown_packet only closes the link when the decrypted payload
        equals the link's own link_id; a LINKCLOSE carrying `forged_id` (a
        different 16-byte link id) must be ignored. `link_id` is the real
        established link being attacked; `forged_id` is the bogus id embedded in
        the forged close. Returns {sent, torn_down, status, status_name}: a
        conforming impl reports torn_down=False (link still ACTIVE) for a
        mismatched id. The positive control is a genuine link_teardown, which
        DOES close the link.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_send_forged_link_close",
            handle=self.handle,
            link_id=link_id.hex(),
            forged_id=forged_id.hex(),
        )

    def send_packet(
        self,
        destination_hash: bytes,
        data: bytes,
        app_name: str,
        aspects: list,
        create_receipt: bool = True,
    ) -> dict:
        """Send a single SINGLE-destination DATA packet with a tracked
        PacketReceipt and return {sent, receipt_id, hops} immediately (the
        non-blocking counterpart to send_packet_with_proof_request). Poll the
        receipt with packet_receipt_status, or drive it adversarially with
        inject_crafted_proof."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_send_packet",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            data=data.hex(),
            app_name=app_name,
            aspects=list(aspects),
            create_receipt=create_receipt,
        )

    def packet_receipt_status(self, receipt_id: str, timeout_ms: int = 0) -> dict:
        """Poll a tracked PacketReceipt; returns {status, status_name,
        delivered, proved}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_packet_receipt_status",
            handle=self.handle,
            receipt_id=receipt_id,
            timeout_ms=timeout_ms,
        )

    def inject_crafted_proof(self, receipt_id: str, variant: str) -> dict:
        """Adversarial PROOF injector: craft a forged/malformed PROOF of
        `variant` against the pending PacketReceipt `receipt_id` and run it
        through the real RNS.PacketReceipt.validate_proof gate, reporting
        {validated, status, status_name, proved, proof_len}.

        All variants are REJECTION cases (forged_implicit, forged_explicit,
        wrong_hash_explicit, wrong_length_short/mid/long) — see
        wire_inject_crafted_proof. A genuinely-valid proof can't be signed
        cross-process, so the positive control is a real PROVE_ALL delivery."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_proof",
            handle=self.handle, receipt_id=receipt_id, variant=variant,
        )

    def inject_tampered_link_data(
        self, link_id: bytes, data: bytes, corruption: str = "none",
    ) -> dict:
        """Adversarial tampered-token injector: build a DATA packet encrypted to
        an established link, optionally corrupt it (`corruption` ∈ none /
        ciphertext / hmac / truncate), and feed it through the link's real
        receive path, reporting {corruption, unpacked, delivered, link_active,
        status_name}. Run on the RECEIVER peer (it owns the inbound link's
        packet handler). A tampered packet must NOT be delivered and the link
        must stay ACTIVE; `corruption='none'` is the positive control."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_tampered_link_data",
            handle=self.handle, link_id=link_id.hex(),
            data=data.hex(), corruption=corruption,
        )

    def inject_crafted_link_identify(self, link_id: bytes, variant: str) -> dict:
        """Adversarial LINKIDENTIFY injector: craft an identify packet of
        `variant` (valid / forged_signature / wrong_signed_data / wrong_length),
        encrypt it to the established link, and feed it through the real
        link.receive on THIS (non-initiator) peer, reporting {variant,
        claimed_identity_hash, remote_identity_after, adopted, initiator}. Run on
        the peer holding the INBOUND link. A valid identify is adopted; every
        forgery leaves remote_identity None."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_link_identify",
            handle=self.handle, link_id=link_id.hex(), variant=variant,
        )

    def inject_crafted_resource_part(self, link_id: bytes, variant: str) -> dict:
        """Adversarial resource-part injector: build a real sender Resource +
        receiver (via Resource.accept), then feed a part of `variant` (valid /
        forged_map_hash) through the real Resource.receive_part, reporting
        {variant, accepted, parts_before, parts_after, total_parts}. The sender's
        own part is accepted; a forged-map-hash part is dropped."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_resource_part",
            handle=self.handle, link_id=link_id.hex(), variant=variant,
        )

    def inject_crafted_resource_proof(self, link_id: bytes, variant: str) -> dict:
        """Adversarial RESOURCE_PRF injector: build a real sender Resource on the
        link and run a crafted proof of `variant` (valid / wrong_proof /
        wrong_length_short / wrong_length_long) through the real
        Resource.validate_proof, reporting {variant, concluded, status,
        status_name, proof_len}. A valid 64-byte proof concludes the resource;
        anything else does not."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_resource_proof",
            handle=self.handle, link_id=link_id.hex(), variant=variant,
        )

    def resource_constants(self) -> dict:
        """Read the real Resource / ResourceAdvertisement protocol constants off
        RNS (WINDOW/WINDOW_MIN/WINDOW_MAX/MAPHASH_LEN/HASHMAP_MAX_LEN/
        COLLISION_GUARD_SIZE/MAX_EFFICIENT_SIZE/METADATA_MAX_SIZE/MAX_RETRIES/
        MAX_ADV_RETRIES/...). For pinning each against its spec literal."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute("wire_resource_constants", handle=self.handle)

    def inject_crafted_resource_request(self, link_id: bytes, variant: str) -> dict:
        """Adversarial RESOURCE_REQ injector: build a real sender Resource on the
        link and feed a crafted request of `variant` (misaligned_hmu / aligned /
        serve_all) into the real Resource.request, reporting the sequencing-error
        cancel (misaligned), the aligned-HMU non-cancel, or the served-parts /
        AWAITING_PROOF / byte-identical-resend behaviour (serve_all)."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_resource_request",
            handle=self.handle, link_id=link_id.hex(), variant=variant,
        )

    def inject_corrupt_assembled_resource(self, link_id: bytes, variant: str) -> dict:
        """Assembly-time hash check: build a real sender + receiver, fill the
        receiver buffer with genuine part bytes (variant 'valid') or corrupt one
        slot (variant 'corrupt'), run the real Resource.assemble, and report
        {variant, status_name, complete, corrupt, proof_sent, proof_calls}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_corrupt_assembled_resource",
            handle=self.handle, link_id=link_id.hex(), variant=variant,
        )

    def inject_duplicate_resource_adv(self, link_id: bytes) -> dict:
        """Duplicate RESOURCE_ADV de-dup: drive one genuine advertisement through
        the real Resource.accept twice and report {first_accepted, second_created,
        incoming_count}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_duplicate_resource_adv",
            handle=self.handle, link_id=link_id.hex(),
        )

    def inject_malformed_resource_adv(self, link_id: bytes, variant: str) -> dict:
        """Malformed RESOURCE_ADV drop: feed undecodable msgpack ('garbage') or a
        valid-but-missing-key ('missing_key') advertisement through the real
        Resource.accept and report {variant, inbound_started, crashed}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_malformed_resource_adv",
            handle=self.handle, link_id=link_id.hex(), variant=variant,
        )

    def inject_resource_adv_flags(self, link_id: bytes, variant: str) -> dict:
        """Request/response advertisement accept logic: drive a request /
        response / plain advertisement through the real Link.receive dispatcher
        under a given resource_strategy and report {variant, accepted, strategy}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_resource_adv_flags",
            handle=self.handle, link_id=link_id.hex(), variant=variant,
        )

    def resource_receiver_request_state(self, link_id: bytes, n: int = 2) -> dict:
        """Inbound Resource window / consecutive-height read-back: build a real
        receiver, feed `n` genuine parts in order, and report window/window_min/
        window_max/consecutive_height_*/hashmap_height_*/received_count."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_receiver_request_state",
            handle=self.handle, link_id=link_id.hex(), n=n,
        )

    def inject_hashmap_update(self, link_id: bytes) -> dict:
        """HMU idempotence: apply the same later hashmap segment twice to a
        >74-part receiver through the real Resource.hashmap_update and report
        {height_after_advert, height_after_first, height_after_duplicate,
        grew_on_first, grew_on_duplicate}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_hashmap_update",
            handle=self.handle, link_id=link_id.hex(),
        )

    def resource_receiver_proof_count(self, link_id: bytes) -> dict:
        """Per-part proof suppression: count proofs as parts arrive and assert
        exactly one is emitted after assembly. Reports {proofs_before_final,
        proofs_after_assembly, status_name, complete}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_receiver_proof_count",
            handle=self.handle, link_id=link_id.hex(),
        )

    def resource_force_collision(self, link_id: bytes) -> dict:
        """Drive the hashmap collision-guard remap: force a map-hash collision on
        the first build pass and report {remapped, random_hash_before,
        random_hash_after, hashmap_changed, num_parts}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_force_collision",
            handle=self.handle, link_id=link_id.hex(),
        )

    def resource_outgoing_queue_state(self, link_id: bytes) -> dict:
        """Pin one-outgoing-resource-at-a-time: register one outgoing resource,
        advertise a second, and report {ready_empty, ready_with_one,
        first_status*, second_status*, queued}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_outgoing_queue_state",
            handle=self.handle, link_id=link_id.hex(),
        )

    def inject_crafted_lrproof(self, variant: str) -> dict:
        """Adversarial LRPROOF injector: on this peer, create a self-contained
        initiator link to a fresh controlled destination, craft an LRPROOF of
        `variant` (valid / forged_signature / wrong_signed_data) and feed it
        through the real Link.validate_proof, reporting {variant, activated,
        status, status_name}. A valid proof activates the link; a forged one
        does not."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_lrproof", handle=self.handle, variant=variant,
        )

    def capture_lrproof_frame(self) -> dict:
        """Capture a genuine outbound LRPROOF frame's raw bytes + flag shape.

        Self-contained on this peer: builds a real RNS LRPROOF (Link.prove /
        Packet.pack with context=LRPROOF) and returns {raw, flags, link_id,
        packet_type, context, expected_link_dest_type, truncated_hashlength}.
        get_packed_flags forces the LINK destination-type bits for an LRPROOF and
        pack() writes the link_id in the destination-address position; the test
        decodes raw[0] and pins both against the spec."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute("wire_capture_lrproof_frame", handle=self.handle)
        return {
            "raw": bytes.fromhex(resp["raw"]),
            "flags": int(resp["flags"]),
            "link_id": bytes.fromhex(resp["link_id"]),
            "packet_type": int(resp["packet_type"]),
            "context": int(resp["context"]),
            "expected_link_dest_type": int(resp["expected_link_dest_type"]),
            "truncated_hashlength": int(resp["truncated_hashlength"]),
        }

    def inject_crafted_link_proof(self, variant: str) -> dict:
        """Self-contained LINK-DATA packet-proof injector: links accept ONLY the
        96-byte EXPLICIT proof (PacketReceipt.validate_link_proof). Variants
        valid_explicit (96B valid sig -> validates) / implicit_valid_sig (64B
        VALID sig -> rejected, proving form is enforced) / implicit_random /
        wrong_length_short. Returns {variant, validated, status, status_name,
        proof_len, expl_length, impl_length}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_link_proof", handle=self.handle, variant=variant,
        )

    def inject_single_proof_format(self, variant: str) -> dict:
        """Self-contained single-packet (non-link) PROOF FORMAT injector. Builds
        the destination from an identity it controls, so it can sign a genuinely-
        valid proof per the spec. Variants valid_explicit (96B -> validates) /
        valid_implicit (64B -> validates) / forged_explicit (wrong key ->
        rejected) / wrong_hash_explicit (hash != receipt -> rejected). Returns
        {variant, validated, status, status_name, proof_len, expl_length,
        impl_length}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_single_proof_format", handle=self.handle, variant=variant,
        )

    def packet_receipt_generation(
        self, dest_type: str = "single", context: int = 0,
    ) -> dict:
        """Report whether RNS actually creates a PacketReceipt for a packet of the
        given dest_type ('single'|'plain') / context, with create_receipt=True
        (the Transport.outbound generate_receipt gate). Sends a real packet out
        this peer's interface and reads packet.receipt straight off RNS. Returns
        {dest_type, context, sent, has_receipt, create_receipt_flag}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_packet_receipt_generation",
            handle=self.handle, dest_type=dest_type, context=int(context),
        )

    def link_request_payload(
        self, app_name: str = "conformance", aspects: list | None = None,
    ) -> dict:
        """Capture a real initiator LINKREQUEST payload WITHOUT sending it
        (Packet.send patched off in the bridge), reporting the request_data and
        its pub_bytes/sig_pub_bytes/signalling_bytes/mtu/mode/len fields read off
        the live RNS.Link (Link.py:316). Lets a test pin the unencrypted layout
        and the fresh-ephemeral-key property."""
        assert self.handle, "start_* must be called first"
        kwargs: dict = {"handle": self.handle, "app_name": app_name}
        if aspects is not None:
            kwargs["aspects"] = list(aspects)
        return self.bridge.execute("wire_link_request_payload", **kwargs)

    def link_signalling_bytes(self, mtu: int, mode: int) -> dict:
        """Delegate to the static RNS.Link.signalling_bytes(mtu, mode), returning
        the 3-byte signalling field for an enabled mode or {raised: True} for a
        non-enabled mode, plus the bytemasks / enabled-mode list for independent
        recomputation."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_signalling_bytes", handle=self.handle,
            mtu=int(mtu), mode=int(mode),
        )

    def inject_crafted_link_request(self, variant: str, hops: int = 0) -> dict:
        """Adversarial LINKREQUEST size/mode injector: feed a crafted payload of
        `variant` (valid64 / valid67 / size_63 / size_66 / size_0 / bad_mode)
        through the real Link.validate_request on a fresh self-owned IN
        destination, reporting {variant, data_len, accepted, inbound_link_created,
        establishment_timeout, mode, ...}. Only 64/67-byte enabled-mode payloads
        create a link. `hops` sets the crafted packet's hop count for the
        establishment_timeout derivation."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_crafted_link_request",
            handle=self.handle, variant=variant, hops=int(hops),
        )

    def link_accept_gate(self, accepts: bool) -> dict:
        """Drive Destination.accepts_links(accepts) then feed a genuine
        LINKREQUEST through Destination.receive on a fresh self-owned IN
        destination, reporting {accepts, links_before, links_after,
        link_created}. Gate OFF -> no link; gate ON -> exactly one."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_accept_gate", handle=self.handle, accepts=bool(accepts),
        )

    def link_key_material(self, link_id: bytes) -> dict:
        """Report which ephemeral-key fields (derived_key/shared_key/prv/pub) the
        live RNS.Link currently holds. An ACTIVE link holds all four; after
        Link.teardown the link_closed() purge nulls them all."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_key_material", handle=self.handle, link_id=link_id.hex(),
        )

    def inject_closed_link_data(self, link_id: bytes) -> dict:
        """Cache a pristine DATA packet encrypted to the still-ACTIVE inbound
        link, tear the link down, then replay the cached packet through
        link.receive — reporting {delivered, status_name, link_closed}. A CLOSED
        link drops all traffic (Link.receive guard). Run on the RECEIVER peer."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_inject_closed_link_data", handle=self.handle,
            link_id=link_id.hex(),
        )

    def link_identify_pending(
        self,
        destination_hash: bytes,
        app_name: str,
        aspects: list,
        private_key: bytes,
    ) -> dict:
        """Build a fresh PENDING (pre-ACTIVE) initiator link to the recalled
        destination and call Link.identify on it, asserting it no-ops without
        crashing (Link.identify ACTIVE-only guard, Link.py:459-475/:468).

        Link.identify only acts when initiator and status == ACTIVE; on a
        PENDING link it must be a silent no-op — no LINKIDENTIFY packet emitted,
        no exception. The handler recalls the destination identity, builds an
        initiator Link forced to PENDING, and calls identify with an Identity
        from `private_key`. Returns {crashed, identify_packet_sent, status,
        status_name, initiator} read off the real Link: a conforming impl
        reports crashed=False, identify_packet_sent=False, status PENDING,
        initiator True. The destination identity must already be known via a
        received announce.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_link_identify_pending",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
            app_name=app_name,
            aspects=list(aspects),
            private_key=private_key.hex(),
        )

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

    # --- reticulum_config posture / config-derivation read-backs ----------

    def ifac_signature(self) -> dict:
        """Read this peer's live interface IFAC identifier signature. Returns
        {ifac_signature: bytes, ifac_key: bytes, ifac_size: int,
        default_ifac_size: int}. Peer must have network_name + passphrase."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute("wire_ifac_signature", handle=self.handle)
        return {
            "ifac_signature": bytes.fromhex(resp["ifac_signature"]),
            "ifac_key": bytes.fromhex(resp["ifac_key"]),
            "ifac_size": int(resp["ifac_size"]),
            "default_ifac_size": int(resp["default_ifac_size"]),
        }

    def instance_posture(self) -> dict:
        """Read the ground-truth process-wide posture flags RNS resolved."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute("wire_instance_posture", handle=self.handle)

    def interface_bitrate(self) -> dict:
        """Read this peer's effective interface bitrate + class guess +
        MINIMUM_BITRATE. Returns {bitrate, bitrate_guess, minimum_bitrate}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute("wire_interface_bitrate", handle=self.handle)

    def rpc_authkey(self) -> dict:
        """Read the derived RPC authkey + transport private key. Returns
        {rpc_key: bytes, transport_private_key: bytes}."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute("wire_rpc_authkey", handle=self.handle)
        return {
            "rpc_key": bytes.fromhex(resp["rpc_key"]),
            "transport_private_key": bytes.fromhex(resp["transport_private_key"]),
        }

    def first_hop_timeout(self, destination_hash: bytes) -> dict:
        """Read RNS.Transport.first_hop_timeout for a destination hash. Returns
        {timeout, default_per_hop_timeout}."""
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_first_hop_timeout",
            handle=self.handle,
            destination_hash=destination_hash.hex(),
        )

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
def wire_pair_started(wire_peers):
    """A server/client TCP pair, both STARTED (interfaces up, settled), but with
    NO destination/link opened.

    For self-contained link-internals injectors that drive real RNS.Link /
    RNS.Destination code on a peer's live instance without needing an
    established wire link (request-payload capture, signalling-byte encoding,
    LINKREQUEST size/mode validation, the destination accept gate). Yields
    (server, client) ready to take wire_* commands.
    """
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port,
    )
    time.sleep(0.5)
    return server, client


@pytest.fixture
def wire_link_setup(wire_peers):
    """Factory fixture: bring up a direct server/client TCP pair and open one
    established Link from the client to the server's IN destination.

    Yields a callable `setup(**opts) -> (server, client, dest_hash, link_id)`
    so each phase-2 test can pick the link's parameters without duplicating the
    start/listen/poll/open boilerplate (the repeated `_establish_link` /
    `_open_channel_link` helpers across the resource/channel suites). The client
    is the link initiator (the implementation under test under the wire_pair
    parametrization); the server anchors the Link.

    Options:
      app_name (str="conformance"), aspects (seq=("wire",)): the link's
        destination naming.
      fixed_mtu (int|None): pin both interfaces to a small fixed link MTU so a
        modest Resource chunks into >74 parts and drives the on-wire HMU
        handshake / small-SDU paths. None uses the negotiated (large) TCP MTU.
      resource_strategy ('all'|'none'|'app'|None): the listener's inbound
        Resource accept strategy (see _WirePeer.listen). The ACCEPT_APP listener
        the audit calls for is `resource_strategy='app'`.
      proof_strategy ('all'|'app'|'none'|None): set the listening destination's
        packet-proof strategy before the link opens (for send_link_data tests).
      enable_ratchets (bool): register the listening destination with ratchets
        enabled (the destination-level ratchet gaps, CONFORMANCE_GAPS.md §4c).
        See the wire_ratcheted_link fixture, which defaults this True.
      link_timeout_ms / path_timeout_ms / settle_sec: timing knobs.

    Teardown is handled by the underlying wire_peers finalizer.
    """
    server, client = wire_peers

    def _setup(
        app_name: str = "conformance",
        aspects=("wire",),
        *,
        fixed_mtu: int | None = None,
        resource_strategy: str | None = None,
        proof_strategy: str | None = None,
        enable_ratchets: bool = False,
        open_channel: bool = True,
        buffer_stream_ids: list | None = None,
        link_timeout_ms: int = 15000,
        path_timeout_ms: int = 10000,
        settle_sec: float = 1.0,
    ):
        aspects = list(aspects)
        port = server.start_tcp_server(
            network_name="", passphrase="", fixed_mtu=fixed_mtu
        )
        client.start_tcp_client(
            network_name="",
            passphrase="",
            target_host="127.0.0.1",
            target_port=port,
            fixed_mtu=fixed_mtu,
        )
        if settle_sec:
            time.sleep(settle_sec)
        dest_hash = server.listen(
            app_name=app_name,
            aspects=aspects,
            resource_strategy=resource_strategy,
            enable_ratchets=enable_ratchets,
            open_channel=open_channel,
            buffer_stream_ids=buffer_stream_ids,
        )
        if proof_strategy is not None:
            server.set_proof_strategy(dest_hash, proof_strategy)
        assert client.poll_path(dest_hash, timeout_ms=path_timeout_ms), (
            f"{client.role_label} never learned a path to {server.role_label}'s "
            f"destination — the Link could not be opened."
        )
        link_id = client.link_open(
            dest_hash,
            app_name=app_name,
            aspects=aspects,
            timeout_ms=link_timeout_ms,
        )
        return server, client, dest_hash, link_id

    return _setup


@pytest.fixture
def wire_ratcheted_link(wire_link_setup):
    """Factory: a server/client TCP link whose SERVER destination has ratchets
    enabled, for the destination-level ratchet gaps (CONFORMANCE_GAPS.md §4c).

    Yields setup(**opts) -> (server, client, dest_hash, link_id) — identical to
    wire_link_setup but with enable_ratchets defaulted True on the listening
    destination, so read_ratchets / destination_latest_ratchet_id /
    rotate_ratchet / set_ratchet_interval / set_retained_ratchets /
    ratchet_file_roundtrip all operate on the (ratchet-bearing) `dest_hash`.

    Note: latest_ratchet_id is None until the server destination performs a
    real Destination.encrypt/decrypt. After the link is up, drive one by sending
    the server an encrypted packet — e.g. client.send_packet_with_proof_request(
    dest_hash, ...) or a link DATA the server decrypts — THEN read
    server.destination_latest_ratchet_id(dest_hash).

    Teardown is handled by the underlying wire_peers finalizer.
    """

    def _setup(**opts):
        opts.setdefault("enable_ratchets", True)
        return wire_link_setup(**opts)

    return _setup


@pytest.fixture
def wire_allow_none_link(wire_link_setup):
    """Factory: a server/client TCP link with an ALLOW_NONE request handler
    registered, plus a positive-control ALLOW_ALL handler (Destination.py:
    370-401).

    Yields setup(**opts) -> (server, client, dest_hash, link_id, none_path,
    all_path, response). The server registers two handlers on `dest_hash`:
      none_path ('deny')  -> allow="none" (ALLOW_NONE): a Link.request must get
        no response (status FAILED) — the negative control.
      all_path  ('allow') -> allow="all": a Link.request returns `response` —
        the positive control proving the link itself works.
    A test asserts the deny path fails while the allow path succeeds, and (with
    deregister_request_handler) that removing the allow handler then fails it
    too. opts are forwarded to wire_link_setup (e.g. settle_sec, timeouts).

    Teardown is handled by the underlying wire_peers finalizer.
    """

    def _setup(**opts):
        server, client, dest_hash, link_id = wire_link_setup(**opts)
        response = b"allow-none-control"
        none_path = "deny"
        all_path = "allow"
        server.register_request_handler(dest_hash, none_path, response, allow="none")
        server.register_request_handler(dest_hash, all_path, response, allow="all")
        return server, client, dest_hash, link_id, none_path, all_path, response

    return _setup


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
