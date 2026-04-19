"""LXMF-layer (E2E) fixtures.

Layered on top of tests/wire/. The wire layer spins up a real Reticulum +
TCP interface per bridge; the LXMF layer attaches an LXMRouter to that
same RNS instance and exercises all three delivery methods.

Two 3-peer topologies live here:

    1) lxmf_3peer (PROPAGATED delivery, middle = lxmd subprocess):

         sender (TCPClient)                    receiver (TCPClient)
                \\                                   /
                 `----> transport (TCPServer) <----'
                        enable_transport=true
                        share_instance=true
                            └── lxmd subprocess (propagation node)

       The middle peer wears two hats: its bridge process is the RNS TCP
       transport, and a SEPARATE lxmd subprocess attached to the same
       shared Reticulum is the LXMF propagation node. Matches production
       (see fleet/yggdrasil/reticulum-node.yaml — rnsd + lxmd in the
       same container, sharing /root/.reticulum).

    2) lxmf_transport_3peer (OPPORTUNISTIC and DIRECT delivery, middle
       = plain transport, NO lxmd):

         sender (TCPClient)                    receiver (TCPClient)
                \\                                   /
                 `----> transport (TCPServer) <----'
                        enable_transport=true

       The middle is JUST a packet mover. sender and receiver run
       in-process LXMRouters against their own bridge RNS; the middle
       has no LXMF state of its own. This matches how LXMF works when
       both peers are online and there's a transport hop between them
       (the typical Columba ↔ rnsd ↔ Sideband path).

Both fixtures share the lxmf_start + announce-stagger + path-convergence
logic in _setup_lxmf_peers_on_transport — only the middle-peer role
configuration differs.

Parametrization emits 4 combos for each fixture via lxmf_trio:
(kotlin|reference) × (kotlin|reference) on the sender/receiver slots. The
middle is always "lxmd" for propagation and always "reference" for
transport (lxmf-kt has no equivalent transport-mode node distinct from
enable_transport=true anyway).

See reference/lxmf_bridge.py and conformance-bridge/src/main/kotlin/
Lxmf.kt for the command surface these fixtures drive.
"""

import os
import secrets
import shutil
import time

import pytest

from bridge_client import BridgeClient
from conftest import BRIDGE_COMMANDS, ROOT_DIR, get_impl_list, resolve_command

# Reuse the wire-layer machinery: the LXMF layer sits on top of a real
# wire-level Reticulum and doesn't need to re-implement start_tcp_* /
# poll_path. These symbols live in tests/wire/conftest.py; pytest has
# already inserted the tests/ dir into sys.path for the rootdir
# conftest.py pattern, but the wire conftest is in a subpackage so we
# import it by package path.
from tests.wire.conftest import _WirePeer, _env_for


def _resolve_command_for_trio(impl: str) -> str:
    """Resolve the bridge command for an LXMF trio peer.

    Why this exists: the root conftest's resolve_command honors the
    CONFORMANCE_BRIDGE_CMD env var globally — it returns that command
    for EVERY impl name, including "reference". That's fine for the
    wire-layer tests (they test interop by mis-labeling — a
    "reference-to-kotlin" pair just runs kotlin twice when the env
    override is the kotlin bridge), but it breaks the LXMF fixture,
    which needs the reference Python bridge for the propagation_node
    slot regardless of which impl is on sender/receiver.

    Resolution rules:
      - If impl == "kotlin" (the SUT), honor CONFORMANCE_BRIDGE_CMD via
        resolve_command — this is how CI points at a freshly-built
        shadowJar. Same mechanism works for the sender-kotlin and the
        receiver-kotlin slots independently.
      - If impl == "reference" or "lxmd", bypass the env override and
        use BRIDGE_COMMANDS["reference"] directly. This lets a run with
        CONFORMANCE_BRIDGE_CMD=<kotlin jar> still exercise reference-on-
        reference sanity combos with a real Python bridge driving lxmd.
    """
    if impl == "kotlin":
        return resolve_command(impl)
    if impl in ("reference", "lxmd"):
        return BRIDGE_COMMANDS["reference"].format(root=ROOT_DIR)
    if impl not in BRIDGE_COMMANDS:
        raise ValueError(f"Unknown implementation: {impl}")
    return BRIDGE_COMMANDS[impl].format(root=ROOT_DIR)


# Settle times — propagation requires announces to traverse the TCP hop
# and be processed by Transport on all three peers. These are measured
# empirically against the Python reference impl; tighten if they start
# holding CI back, but don't loosen in the trio assertions (we want
# tight assertions to actually flip red on regressions, per the
# tight-assertions feedback doc).
_SETTLE_SEC = 2.0
_ANNOUNCE_PROPAGATION_SEC = 5.0
_INTER_ANNOUNCE_STAGGER_SEC = 3.0
_SYNC_TIMEOUT_MS = 30_000


def pytest_generate_tests(metafunc):
    """Parametrize LXMF tests over (sender_impl, middle_impl, receiver_impl).

    The middle slot depends on which fixture is in use:
      - lxmf_3peer (PROPAGATED): middle = "lxmd" (separate Python
        subprocess running the real lxmd daemon, not an in-router-mode
        LXMRouter). Future-proof: if LXMF-kt ever ships a daemon, the
        middle could become "lxmd-kt".
      - lxmf_transport_3peer (OPPORTUNISTIC / DIRECT): middle =
        "reference" (plain Python transport, no LXMF state of its own).
        LXMF-kt has no equivalent transport-mode node distinct from the
        wire bridge's enable_transport=true — sticking with reference
        for the middle keeps Phase 1 scope focused on the cross-impl
        sender/receiver matrix.

    Cartesian product over impls ∪ {"reference"} for sender + receiver:
    with --impl=kotlin this emits 4 combos per fixture (reference and
    kotlin on each end). Mirrors the wire-layer
    `_parametrize_wire_trio` pattern so the matrix shape is consistent
    across test categories.

    The reference-only combo is the end-to-end sanity baseline (does
    the delivery method work AT ALL when both ends are Python?). The
    kotlin-on-sender combo exercises LXMF-kt's send path. The
    kotlin-on-receiver combo exercises LXMF-kt's inbound decrypt +
    delivery callback. The homogeneous kotlin combo exercises both ends
    of the Kotlin LXMF implementation simultaneously — the most
    regression-prone path.
    """
    if "lxmf_trio" not in metafunc.fixturenames:
        return

    impls = get_impl_list(metafunc.config) or []
    # Always include the reference — otherwise a --impl=kotlin-only run
    # would skip the interop assertions entirely, which defeats the
    # point of cross-impl testing. Same pattern as tests/wire/conftest.py.
    peers = sorted(set(impls) | {"reference"})

    # Decide which middle-slot label to emit based on the fixture the
    # test asked for. A test that pulls in BOTH fixtures (not a real
    # pattern, but defensive) would get the propagation-appropriate
    # label because lxmd is the more-constrained case.
    if "lxmf_3peer" in metafunc.fixturenames:
        middle = "lxmd"
    elif "lxmf_transport_3peer" in metafunc.fixturenames:
        middle = "reference"
    else:
        # Test took lxmf_trio but neither topology fixture — fall back
        # to the propagation label so the test's fixture choice is the
        # thing that fails, not the parametrization.
        middle = "lxmd"

    trios = [(sender, middle, receiver) for sender in peers for receiver in peers]

    ids = [f"{a}->{b}->{c}" for a, b, c in trios]
    metafunc.parametrize("lxmf_trio", trios, ids=ids, scope="function")


def _require_lxmd():
    """Skip the current test if the `lxmd` binary is not on PATH.

    lxmd is packaged with the LXMF python distribution as a console
    entrypoint — `pip install lxmf` installs it. We don't install it as
    part of the test setup (the conformance suite avoids side effects on
    the host); the CI workflow must handle that. Skipping cleanly here
    makes dev-loop failures self-explain rather than look like hangs.
    """
    if not shutil.which("lxmd"):
        pytest.skip(
            "lxmd binary not on PATH; install with `pip install lxmf`. "
            "The LXMF propagation conformance suite requires a real lxmd "
            "daemon for the middle peer, matching production deployments."
        )


@pytest.fixture
def lxmf_trio(request):
    """(sender_impl, propagation_node_impl, receiver_impl) tuple from
    pytest_generate_tests."""
    return request.param


class _LxmfPeer:
    """Thin wrapper around a BridgeClient that adds LXMF commands on top
    of the wire-layer surface.

    Owns its own wire handle (via the `_wire` attribute). Sender/receiver
    peers also own an in-process LXMRouter via `lxmf_handle`. The middle
    (propagation-node) peer does NOT call `lxmf_start` — it delegates
    the entire LXMF role to a separate lxmd subprocess spawned via
    `spawn_daemon_propagation_node`, which shares the wire bridge's RNS
    via the AF_UNIX shared-instance mechanism.
    """

    def __init__(self, bridge: BridgeClient, role_label: str):
        self.bridge = bridge
        self.role_label = role_label
        self._wire = _WirePeer(bridge, role_label)

        self.lxmf_handle: str | None = None
        self.delivery_dest_hash: bytes | None = None
        self.lxmf_identity_hash: bytes | None = None
        self.propagation_node_dest_hash: bytes | None = None
        # True iff this peer spawned an lxmd subprocess — teardown calls
        # lxmf_stop_daemon_propagation_node to reap it.
        self._lxmd_running = False
        # Filesystem path to lxmd's messagestore (only populated for the
        # middle / propagation-node peer). Used by stored_message_count()
        # to assert on the prop node's on-disk state without routing a
        # query through the bridge.
        self._messagestore_dir: str | None = None

    # --- Wire-layer pass-throughs (so tests don't have to juggle both). ---

    def start_tcp_server(
        self, network_name: str = "", passphrase: str = "",
        share_instance: bool = False,
    ) -> int:
        # Propagation-node role needs share_instance=True so lxmd can
        # attach. For sender/receiver the flag must stay False — otherwise
        # multiple bridge subprocesses in the same test would fight over
        # the AF_UNIX abstract socket namespace.
        if share_instance:
            resp = self.bridge.execute(
                "wire_start_tcp_server",
                network_name=network_name,
                passphrase=passphrase,
                share_instance=True,
            )
            self._wire.handle = resp["handle"]
            self._wire.identity_hash = bytes.fromhex(resp["identity_hash"])
            self._wire.port = int(resp["port"])
            return self._wire.port
        return self._wire.start_tcp_server(network_name, passphrase)

    def start_tcp_client(
        self, network_name: str = "", passphrase: str = "",
        target_host: str = "127.0.0.1", target_port: int = 0,
    ):
        self._wire.start_tcp_client(network_name, passphrase, target_host, target_port)

    def poll_path(self, destination_hash: bytes, timeout_ms: int = 5000) -> bool:
        return self._wire.poll_path(destination_hash, timeout_ms=timeout_ms)

    @property
    def wire_handle(self) -> str | None:
        return self._wire.handle

    # --- LXMF-layer commands. ---

    def lxmf_start(self, display_name: str | None = None) -> bytes:
        """Attach an in-process LXMRouter to this peer's wire RNS.

        Sender/receiver call this. The middle peer doesn't — it uses
        lxmd as a separate subprocess via spawn_daemon_propagation_node.
        """
        assert self._wire.handle, "start_tcp_* must be called before lxmf_start"
        params = {"wire_handle": self._wire.handle}
        if display_name is not None:
            params["display_name"] = display_name
        resp = self.bridge.execute("lxmf_start", **params)
        self.lxmf_handle = resp["handle"]
        self.delivery_dest_hash = bytes.fromhex(resp["delivery_dest_hash"])
        self.lxmf_identity_hash = bytes.fromhex(resp["identity_hash"])
        return self.delivery_dest_hash

    def spawn_daemon_propagation_node(
        self,
        display_name: str = "conformance-prop-node",
        startup_timeout_sec: float = 30.0,
    ) -> bytes:
        """Spawn an lxmd subprocess that runs as this peer's propagation
        node. The wire bridge must have been started with
        share_instance=True so lxmd can attach to its Reticulum.

        Returns the propagation destination hash that sender/receiver
        peers pass to set_outbound_propagation_node.
        """
        assert self._wire.handle, "start_tcp_server must be called first"
        resp = self.bridge.execute(
            "lxmf_spawn_daemon_propagation_node",
            wire_handle=self._wire.handle,
            display_name=display_name,
            startup_timeout_sec=startup_timeout_sec,
        )
        self.propagation_node_dest_hash = bytes.fromhex(
            resp["propagation_node_dest_hash"]
        )
        self._messagestore_dir = resp.get("messagestore_dir")
        self._lxmd_running = True
        return self.propagation_node_dest_hash

    def stored_message_count(self) -> int:
        """Count lxmd's on-disk stored propagation messages.

        Each message lxmd accepts lands as a single file named
        `{transient_id_hex}_{received}[_{stamp_value}]` in the
        messagestore dir (see LXMF/LXMRouter.py line 2329). Count is
        exact — no subdirectories, no sidecars, just one file per
        stored message. If lxmd hasn't yet created the directory
        (can happen in the brief window between spawn and the first
        stored message), return 0 rather than raising.

        Only valid on the middle peer — the sender/receiver peers
        don't own a messagestore dir.
        """
        assert self._messagestore_dir is not None, (
            f"stored_message_count() is only valid on the propagation-node "
            f"peer ({self.role_label} has no messagestore dir — call "
            f"spawn_daemon_propagation_node first)"
        )
        if not os.path.isdir(self._messagestore_dir):
            # Dir doesn't exist yet — LXMRouter creates it lazily on
            # first propagated-message receive (see LXMRouter.py line
            # 540: `if not os.path.isdir(self.messagepath): os.makedirs
            # (self.messagepath)`). Returning 0 here lets the caller's
            # wait-loop continue polling until lxmd creates the dir
            # and writes the file.
            return 0
        # Plain listing: LXMRouter writes one file per stored message
        # directly in messagepath, no nested dirs. Filter to files only
        # (defensive against stray subdirs in unusual configurations).
        entries = os.listdir(self._messagestore_dir)
        return sum(
            1
            for name in entries
            if os.path.isfile(os.path.join(self._messagestore_dir, name))
        )

    def wait_for_stored_message_count(
        self, expected: int, timeout_s: float = 15.0
    ) -> bool:
        """Poll stored_message_count() until it reaches `expected` or
        `timeout_s` elapses. Returns True iff the FINAL count (after the
        poll loop exits) equals expected — callers assert on the return
        value so a "reached expected then went past it" scenario still
        fails loudly (tight assertion per the feedback memo).

        The message-settle gap between sender.handle_outbound completing
        and lxmd writing the file is measured in sub-seconds on loopback;
        the default 15s is generous enough for CI jitter + slow stamp
        generation while still failing fast when propagation is broken.
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self.stored_message_count() == expected:
                # Linger past the poll cadence (0.2s) to make sure a
                # just-arriving duplicate would still fail the FINAL
                # equality check. 1s gives >=5x the poll interval so a
                # duplicate landing within a full cycle after we first
                # hit `expected` still registers. Costs <1s on the
                # happy path (negligible vs. ~25s total test wall).
                time.sleep(1.0)
                return self.stored_message_count() == expected
            time.sleep(0.2)
        return self.stored_message_count() == expected

    def set_outbound_propagation_node(self, propagation_node_dest_hash: bytes):
        assert self.lxmf_handle, "lxmf_start must be called first"
        self.bridge.execute(
            "lxmf_set_outbound_propagation_node",
            handle=self.lxmf_handle,
            propagation_node_dest_hash=propagation_node_dest_hash.hex(),
        )

    def send_propagated(
        self, recipient_delivery_dest_hash: bytes, content: str, title: str = "",
    ) -> bytes:
        assert self.lxmf_handle, "lxmf_start must be called first"
        resp = self.bridge.execute(
            "lxmf_send_propagated",
            handle=self.lxmf_handle,
            recipient_delivery_dest_hash=recipient_delivery_dest_hash.hex(),
            content=content,
            title=title,
        )
        return bytes.fromhex(resp["message_hash"]) if resp.get("message_hash") else b""

    def send_opportunistic(
        self,
        recipient_delivery_dest_hash: bytes,
        content: str,
        title: str = "",
        fields: dict | None = None,
    ) -> bytes:
        """Send an LXMessage with OPPORTUNISTIC delivery (single-packet).

        The bridge accepts the same tagged-dict field shape as
        send_direct. Bytes inside field values use the ``{"bytes":
        "<hex>"}`` wrapper; see lxmfFieldValueFromJson (Kotlin) /
        _decode_field_value_from_params (Python) for the full shape.
        """
        assert self.lxmf_handle, "lxmf_start must be called first"
        params = {
            "handle": self.lxmf_handle,
            "recipient_delivery_dest_hash": recipient_delivery_dest_hash.hex(),
            "content": content,
            "title": title,
        }
        if fields is not None:
            params["fields"] = fields
        resp = self.bridge.execute("lxmf_send_opportunistic", **params)
        return bytes.fromhex(resp["message_hash"]) if resp.get("message_hash") else b""

    def send_direct(
        self,
        recipient_delivery_dest_hash: bytes,
        content: str,
        title: str = "",
        fields: dict | None = None,
    ) -> bytes:
        """Send an LXMessage with DIRECT delivery (link-based; payloads
        > MDU use a Resource for multi-packet chunked transfer)."""
        assert self.lxmf_handle, "lxmf_start must be called first"
        params = {
            "handle": self.lxmf_handle,
            "recipient_delivery_dest_hash": recipient_delivery_dest_hash.hex(),
            "content": content,
            "title": title,
        }
        if fields is not None:
            params["fields"] = fields
        resp = self.bridge.execute("lxmf_send_direct", **params)
        return bytes.fromhex(resp["message_hash"]) if resp.get("message_hash") else b""

    def sync_inbound(self, timeout_s: float = _SYNC_TIMEOUT_MS / 1000.0) -> int:
        """Ask the LXMRouter to fetch messages from its active propagation
        node. Blocks until the router's transfer state machine settles or
        the timeout elapses. Returns the number of messages transferred
        (propagation_transfer_last_result)."""
        assert self.lxmf_handle, "lxmf_start must be called first"
        resp = self.bridge.execute(
            "lxmf_sync_inbound",
            handle=self.lxmf_handle,
            timeout_ms=int(timeout_s * 1000),
        )
        return int(resp.get("messages_received", 0))

    def poll_inbox(self) -> list:
        """Drain all delivered LXMessages since the last poll. Returns a
        list of dicts with keys: hash, source, destination, title,
        content, fields."""
        assert self.lxmf_handle, "lxmf_start must be called first"
        resp = self.bridge.execute("lxmf_poll_inbox", handle=self.lxmf_handle)
        return list(resp.get("messages", []))

    def wait_for_inbox_count(
        self, expected: int, timeout_s: float = 30.0
    ) -> list:
        """Poll the inbox (non-draining) until it has exactly ``expected``
        messages, then drain and return them.

        Why non-draining on the probe: opportunistic / direct delivery
        doesn't have a sync_inbound call to block on. The router's
        delivery callback enqueues onto the inbox asynchronously after
        packet reception / link transfer completes. A naive poll_inbox
        would drain mid-arrival and report 0 before the delivery
        callback has fired.

        The shape here mirrors wait_for_stored_message_count from the
        propagation path: wait until the count is exactly ``expected``,
        linger briefly to catch duplicates, then drain + return. A
        duplicate that arrives WITHIN the linger window flips the
        count to expected+1 and the final check fails — which is what
        we want, per the tight-assertions memo.

        Implementation detail: the bridge's lxmf_poll_inbox drains
        atomically, so we can't "peek at count" without draining.
        Instead we drain-and-accumulate in a local buffer; once the
        accumulated count matches ``expected``, we linger and do ONE
        more drain to catch duplicates.

        Returns the accumulated list on success. Raises AssertionError
        on timeout or on count!=expected after the final check; tests
        that need a non-raising variant can catch and inspect.
        """
        assert self.lxmf_handle, "lxmf_start must be called first"
        accumulated: list = []
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            fresh = self.poll_inbox()
            accumulated.extend(fresh)
            if len(accumulated) >= expected:
                break
            time.sleep(0.2)

        # Linger for a poll cycle (>0.2s) so any just-arriving duplicate
        # still lands and flips the final count. 1s gives ~5x the poll
        # cadence. Costs <1s on happy path.
        time.sleep(1.0)
        accumulated.extend(self.poll_inbox())

        assert len(accumulated) == expected, (
            f"{self.role_label} inbox count = {len(accumulated)}, "
            f"expected exactly {expected} within {timeout_s}s. "
            f"Inbox: {accumulated!r}"
        )
        return accumulated

    def stop(self):
        # Teardown order: lxmd subprocess first (if any), then in-process
        # LXMRouter, then the wire singleton. lxmd-first matters because
        # lxmd's LocalClientInterface disconnect is cleaner while the
        # shared-instance server is still alive.
        if self._lxmd_running and self._wire.handle is not None:
            try:
                self.bridge.execute(
                    "lxmf_stop_daemon_propagation_node",
                    wire_handle=self._wire.handle,
                )
            except Exception:
                pass
            self._lxmd_running = False
        if self.lxmf_handle is not None:
            try:
                self.bridge.execute("lxmf_stop", handle=self.lxmf_handle)
            except Exception:
                pass
            self.lxmf_handle = None
        self._wire.stop()


def _start_lxmf_peers_and_wait_for_paths(
    sender: "_LxmfPeer",
    receiver: "_LxmfPeer",
    extra_path_hashes: tuple[bytes, ...] = (),
):
    """Bring up in-process LXMRouters on the two endpoint peers,
    stagger their announces, and wait for path convergence.

    Extracted so `lxmf_3peer` (propagation) and `lxmf_transport_3peer`
    (opportunistic / direct) can share this core without copy-paste.
    The only difference between the two topologies is what the middle
    peer is doing (lxmd subprocess vs. plain transport) — the
    endpoint announce sequencing is identical.

    Args:
        sender: the peer that will send LXMessages (already wired at
            the TCP layer via start_tcp_client).
        receiver: the peer that will receive LXMessages (already
            wired at the TCP layer via start_tcp_client).
        extra_path_hashes: additional destination hashes both endpoints
            must learn paths to (e.g. the propagation node hash).
            The receiver's delivery hash is always waited on for the
            sender, so it doesn't need to be in here.

    Raises:
        AssertionError: if any path fails to converge within
            _SYNC_TIMEOUT_MS.

    Why stagger the lxmf_start calls: if both announces hit the middle
    peer in the same tick, RNS's Transport rate-limiter on the spawned
    TCPInterface for each client queues the second-direction
    rebroadcast. In the specific sequence "sender announces then
    receiver announces in the same jiffy" the receiver's announce
    never reaches the sender's spawned interface queue before the
    rebroadcast retry limit fires. Empirically a 3s gap is enough for
    the rebroadcast chain to complete cleanly; tighter gaps (<1s) leave
    the sender without a path to the receiver. Matches the wire-layer
    multihop fixtures.
    """
    sender.lxmf_start(display_name="conformance-sender")
    time.sleep(_INTER_ANNOUNCE_STAGGER_SEC)
    receiver.lxmf_start(display_name="conformance-receiver")

    # Let announces settle on all sides. The sender needs the
    # receiver's delivery announce so Identity.recall succeeds in
    # lxmf_send_*. The propagation path convergence, if requested,
    # needs the lxmd announce to traverse LocalClientInterface ->
    # LocalServerInterface -> TCPServerInterface -> both clients, so
    # give it a generous window.
    time.sleep(_ANNOUNCE_PROPAGATION_SEC)

    # Sender must know the receiver's delivery destination.
    assert sender.poll_path(
        receiver.delivery_dest_hash, timeout_ms=_SYNC_TIMEOUT_MS
    ), (
        f"{sender.role_label} did not learn a path to "
        f"{receiver.role_label}'s delivery destination "
        f"({receiver.delivery_dest_hash.hex()}) within "
        f"{_SYNC_TIMEOUT_MS}ms; topology didn't converge."
    )

    # Opportunistic isn't 100% symmetric — the sender emits a delivery
    # packet addressed to the receiver, which doesn't require the
    # receiver to have a reverse path. But DIRECT requires a link,
    # which involves round-trips; and the direct/opportunistic tests
    # share a fixture, so wait for a reverse path too. (For the
    # propagation fixture, the receiver's reverse-path requirement is
    # implicit in sync_inbound's link to the prop node; reference
    # doesn't need the receiver to know about the sender directly.)
    assert receiver.poll_path(
        sender.delivery_dest_hash, timeout_ms=_SYNC_TIMEOUT_MS
    ), (
        f"{receiver.role_label} did not learn a path to "
        f"{sender.role_label}'s delivery destination "
        f"({sender.delivery_dest_hash.hex()}) within "
        f"{_SYNC_TIMEOUT_MS}ms; topology didn't converge."
    )

    for h in extra_path_hashes:
        assert sender.poll_path(h, timeout_ms=_SYNC_TIMEOUT_MS), (
            f"{sender.role_label} did not learn a path to "
            f"{h.hex()} within {_SYNC_TIMEOUT_MS}ms."
        )
        assert receiver.poll_path(h, timeout_ms=_SYNC_TIMEOUT_MS), (
            f"{receiver.role_label} did not learn a path to "
            f"{h.hex()} within {_SYNC_TIMEOUT_MS}ms."
        )


@pytest.fixture
def lxmf_3peer(lxmf_trio):
    """Three bridge subprocesses wired up as sender → prop_node ← receiver,
    with sender/receiver running in-process LXMRouters and the middle peer
    running a real `lxmd` subprocess attached via shared-instance.

    Setup sequence (order matters — announces must propagate before
    identity.recall can succeed on the recipient side):

      1. prop_node brings up TCPServer with share_instance=True; note
         the port. This publishes its RNS as an AF_UNIX shared instance.
      2. sender + receiver bring up TCPClient targeting that port.
      3. prop_node.spawn_daemon_propagation_node. An lxmd subprocess
         starts, attaches to the shared RNS, and announces its
         propagation destination over TCP to sender + receiver.
      4. sender.lxmf_start, receiver.lxmf_start — each attaches an
         in-process LXMRouter and announces its delivery destination.
      5. Sleep to let all announces settle on all three peers.
      6. sender.set_outbound_propagation_node(pn_hash).
      7. receiver.set_outbound_propagation_node(pn_hash).

    Yields (sender, prop_node, receiver) as `_LxmfPeer` objects.
    """
    _require_lxmd()

    sender_impl, pn_impl, receiver_impl = lxmf_trio

    # Sanity: middle slot is always "lxmd" (the Python lxmd subprocess).
    # If a follow-up parametrization ever ships an lxmd-kt variant, the
    # spawn command needs to be dispatched by pn_impl; until then, fail
    # loudly if it drifts.
    if pn_impl != "lxmd":
        pytest.fail(
            f"lxmf_3peer fixture only supports pn_impl='lxmd', got "
            f"{pn_impl!r}. Add the new impl to the non-SUT resolver "
            f"before parametrizing over it."
        )

    bridges = [
        BridgeClient(
            _resolve_command_for_trio(sender_impl),
            env=_env_for(sender_impl),
        ),
        BridgeClient(
            # Middle peer is always the Python reference bridge: it
            # orchestrates lxmd as a subprocess and owns the shared-
            # instance RNS.
            _resolve_command_for_trio("reference"),
            env=_env_for("reference"),
        ),
        BridgeClient(
            _resolve_command_for_trio(receiver_impl),
            env=_env_for(receiver_impl),
        ),
    ]
    sender = _LxmfPeer(bridges[0], role_label=f"sender({sender_impl})")
    prop_node = _LxmfPeer(bridges[1], role_label=f"prop_node({pn_impl})")
    receiver = _LxmfPeer(bridges[2], role_label=f"receiver({receiver_impl})")

    try:
        # Step 1-2: wire layer. prop_node uses share_instance=True so
        # the lxmd subprocess can attach to its Reticulum.
        port = prop_node.start_tcp_server(share_instance=True)
        sender.start_tcp_client(target_port=port)
        receiver.start_tcp_client(target_port=port)
        time.sleep(_SETTLE_SEC)

        # Step 3: spawn lxmd. This blocks until lxmd logs the
        # "LXMF Propagation Node started on <hex>" line (or timeout).
        # The announce goes out over TCP as part of lxmd's startup.
        pn_hash = prop_node.spawn_daemon_propagation_node(
            display_name="conformance-prop-node",
            startup_timeout_sec=30.0,
        )

        # Steps 4-5: endpoint LXMRouter startup + announce + path
        # convergence. Shared with lxmf_transport_3peer. Propagation
        # needs BOTH endpoints to know the prop-node hash; pass it as
        # an extra wait target.
        _start_lxmf_peers_and_wait_for_paths(
            sender, receiver, extra_path_hashes=(pn_hash,)
        )

        # Step 6-7: point sender + receiver at the propagation node.
        sender.set_outbound_propagation_node(pn_hash)
        receiver.set_outbound_propagation_node(pn_hash)

        yield sender, prop_node, receiver
    finally:
        for peer in (sender, prop_node, receiver):
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
def lxmf_transport_3peer(lxmf_trio):
    """Three bridge subprocesses wired up as sender → transport → receiver
    with the middle peer acting as a plain RNS transport (no lxmd, no
    propagation node). Exercises OPPORTUNISTIC and DIRECT delivery.

    Topology:

        sender (TCPClient)                 receiver (TCPClient)
               \\                                  /
                `----> transport (TCPServer) <---'
                       enable_transport=true

    The middle peer doesn't run an LXMRouter of its own — it's JUST a
    packet mover. Any delivery between sender and receiver flows
    through its Transport layer, exactly like Columba traffic crossing
    an rnsd transport hop to reach Sideband.

    Setup sequence:
      1. transport brings up TCPServer (share_instance=False, plain
         transport-mode RNS).
      2. sender + receiver bring up TCPClients targeting that port.
      3. sender.lxmf_start, receiver.lxmf_start (staggered) — each
         attaches an in-process LXMRouter and announces its delivery
         destination.
      4. Wait for paths between endpoints to converge.

    Yields (sender, receiver) — the middle peer is NOT yielded because
    the opportunistic/direct tests don't assert on it (unlike the
    propagation fixture, which yields prop_node for stored-message
    count assertions). The transport peer still exists inside the
    fixture scope and is torn down in the finalizer.
    """
    sender_impl, middle_impl, receiver_impl = lxmf_trio

    # Transport fixture uses a plain Python reference middle. If the
    # parametrization hands us anything else, fail loud — a follow-up
    # PR that widens this would need to extend the resolver, not just
    # sneak a different impl label past this guard.
    if middle_impl != "reference":
        pytest.fail(
            f"lxmf_transport_3peer fixture only supports "
            f"middle_impl='reference', got {middle_impl!r}."
        )

    bridges = [
        BridgeClient(
            _resolve_command_for_trio(sender_impl),
            env=_env_for(sender_impl),
        ),
        BridgeClient(
            _resolve_command_for_trio("reference"),
            env=_env_for("reference"),
        ),
        BridgeClient(
            _resolve_command_for_trio(receiver_impl),
            env=_env_for(receiver_impl),
        ),
    ]
    sender = _LxmfPeer(bridges[0], role_label=f"sender({sender_impl})")
    transport = _LxmfPeer(bridges[1], role_label=f"transport({middle_impl})")
    receiver = _LxmfPeer(bridges[2], role_label=f"receiver({receiver_impl})")

    try:
        # Step 1-2: wire layer. Transport middle is a plain
        # enable_transport=true RNS; no share_instance, no lxmd.
        port = transport.start_tcp_server(share_instance=False)
        sender.start_tcp_client(target_port=port)
        receiver.start_tcp_client(target_port=port)
        time.sleep(_SETTLE_SEC)

        # Steps 3-4: endpoint LXMRouter startup + announce + path
        # convergence. No extra hashes beyond the endpoints themselves.
        _start_lxmf_peers_and_wait_for_paths(sender, receiver)

        yield sender, receiver
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
