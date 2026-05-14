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

import pytest

from _rns_paths import resolve_lxmf_path, resolve_rns_path
from bridge_client import BridgeClient
from conftest import get_impl_list, resolve_command


def _env_for(impl: str) -> dict:
    """Env vars the reference Python bridge needs; Kotlin ignores them."""
    if impl != "reference":
        return {}
    return {
        "PYTHON_RNS_PATH": resolve_rns_path(),
        "PYTHON_LXMF_PATH": resolve_lxmf_path(),
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

    def start_tcp_server(
        self,
        network_name: str,
        passphrase: str,
        mode: str | None = None,
        share_instance: bool = False,
        share_instance_type: str | None = None,
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
        """
        kwargs: dict = {"network_name": network_name, "passphrase": passphrase}
        if mode is not None:
            kwargs["mode"] = mode
        if share_instance:
            kwargs["share_instance"] = True
            if share_instance_type is not None:
                kwargs["share_instance_type"] = share_instance_type
        resp = self.bridge.execute("wire_start_tcp_server", **kwargs)
        self.handle = resp["handle"]
        self.identity_hash = bytes.fromhex(resp["identity_hash"])
        self.port = int(resp["port"])
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

    def listen(self, app_name: str, aspects: list) -> bytes:
        """Register an IN destination that accepts incoming Links."""
        assert self.handle, "start_* must be called first"
        resp = self.bridge.execute(
            "wire_listen",
            handle=self.handle,
            app_name=app_name,
            aspects=list(aspects),
        )
        return bytes.fromhex(resp["destination_hash"])

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

    def resource_create(self, link_id: bytes, data: bytes) -> dict:
        """Construct a real RNS.Resource on an established Link and report
        the attributes the implementation computed — WITHOUT advertising or
        sending it.

        The honest, delegating replacement for the deleted synthetic
        resource_* primitive commands: the bridge builds a real
        RNS.Resource (full __init__, advertise=False so nothing hits the
        wire) and reads back `hash`, `truncated_hash`, `random_hash`,
        `expected_proof`, `hashmap`, `parts`, and the size/flag fields —
        nothing is recomputed. Used by tests/wire/test_resource_invariants.py.
        """
        assert self.handle, "start_* must be called first"
        return self.bridge.execute(
            "wire_resource_create",
            handle=self.handle,
            link_id=link_id.hex(),
            data=data.hex(),
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
