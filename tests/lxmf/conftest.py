"""LXMF-layer (propagation E2E) fixtures.

Layered on top of tests/wire/. The wire layer spins up a real Reticulum +
TCP interface per bridge; the LXMF layer attaches an LXMRouter to that
same RNS instance and exercises PROPAGATED delivery across three peers:

    sender (TCPClient)                    receiver (TCPClient)
           \\                                   /
            `----> transport (TCPServer) <----'
                   enable_transport=True
                   share_instance=True
                       └── lxmd subprocess (propagation node)

The middle peer wears two hats: its bridge process is the RNS TCP
transport, and a SEPARATE `lxmd` subprocess attached to the same shared
Reticulum is the LXMF propagation node. This matches how production
deployments run propagation nodes (see fleet/yggdrasil/reticulum-node.yaml
— rnsd + lxmd in the same container, sharing `/root/.reticulum`).

MVP emits a single parametrization: (kotlin, lxmd, reference). The middle
slot is "lxmd" (not "reference") to make it architecturally explicit that
it's a separate daemon process, not an in-router mode. If LXMF-kt ever
grows a daemon equivalent, the slot could become "lxmd-kt".

See reference/lxmf_bridge.py and conformance-bridge/src/main/kotlin/
Lxmf.kt for the command surface these fixtures drive.
"""

import glob
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
    """Parametrize LXMF tests over (sender_impl, prop_node_impl, receiver_impl).

    The middle slot is always "lxmd" — architecturally a Python subprocess
    running the real lxmd daemon (not an in-router-mode LXMRouter). The
    tuple shape is kept future-proof: if LXMF-kt ever ships a daemon, the
    middle could become "lxmd-kt". Today, "lxmd" is the only value that
    makes sense for a separate-process propagation node.

    Cartesian product over impls ∪ {"reference"} for sender + receiver:
    with --impl=kotlin this emits 4 combos (reference and kotlin on each
    end). Mirrors the wire-layer `_parametrize_wire_trio` pattern so the
    matrix shape is consistent across test categories.

    The reference-only combo is the end-to-end sanity baseline (does
    propagation work AT ALL when both ends are Python?). The kotlin-on-
    sender combo exercises LXMF-kt's stamp generation + link-layer
    message delivery. The kotlin-on-receiver combo exercises LXMF-kt's
    two-phase propagation pull (listMessages + requestMessages). The
    homogeneous kotlin combo exercises both ends of the Kotlin LXMF
    implementation simultaneously — the most regression-prone path.
    """
    if "lxmf_trio" not in metafunc.fixturenames:
        return

    impls = get_impl_list(metafunc.config) or []
    # Always include the reference — otherwise a --impl=kotlin-only run
    # would skip the interop assertions entirely, which defeats the
    # point of cross-impl testing. Same pattern as tests/wire/conftest.py.
    peers = sorted(set(impls) | {"reference"})
    # Middle slot is pinned to "lxmd" (the Python lxmd subprocess).
    trios = [(sender, "lxmd", receiver) for sender in peers for receiver in peers]

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
                # Linger a hair to make sure a just-arriving duplicate
                # would still fail the FINAL equality check below.
                time.sleep(0.2)
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

        # Step 4: sender + receiver in-process LXMRouters. Each announces
        # its delivery destination as part of lxmf_start. We STAGGER these:
        # if both announces hit the middle peer in the same tick, RNS's
        # Transport rate-limiter on the spawned TCPInterface for each
        # client ends up queuing the second-direction rebroadcast, and in
        # the specific sequence "sender announces then receiver announces
        # in the same jiffy" the receiver's announce never reaches the
        # sender's spawned interface queue before the rebroadcast retry
        # limit fires. Empirically a 3s gap between the two lxmf_start
        # calls is enough for the rebroadcast chain to complete cleanly;
        # tighter gaps (<1s) leave sender without a path to receiver.
        sender.lxmf_start(display_name="conformance-sender")
        time.sleep(_INTER_ANNOUNCE_STAGGER_SEC)
        receiver.lxmf_start(display_name="conformance-receiver")

        # Step 5: let announces settle on all sides. The sender needs
        # the receiver's delivery announce so Identity.recall succeeds
        # in lxmf_send_propagated. The sender and receiver both need
        # the propagation node's announce so set_outbound_propagation_node
        # can find its identity for link establishment. The propagation
        # node's announce has to traverse lxmd → LocalClientInterface →
        # LocalServerInterface (wire bridge) → TCPServerInterface → both
        # clients, so give it a generous window.
        time.sleep(_ANNOUNCE_PROPAGATION_SEC)

        # Guard: if the sender's path table never learned the receiver's
        # delivery hash, the test below is going to fail for a
        # meaningless reason (no path, not "propagation didn't work").
        # Surface this explicitly so the failure diagnosis is crisp.
        assert sender.poll_path(
            receiver.delivery_dest_hash, timeout_ms=_SYNC_TIMEOUT_MS
        ), (
            f"{sender.role_label} did not learn a path to "
            f"{receiver.role_label}'s delivery destination "
            f"({receiver.delivery_dest_hash.hex()}) within "
            f"{_SYNC_TIMEOUT_MS}ms; topology didn't converge."
        )
        assert sender.poll_path(
            pn_hash, timeout_ms=_SYNC_TIMEOUT_MS
        ), (
            f"{sender.role_label} did not learn a path to the "
            f"propagation node ({pn_hash.hex()}) within {_SYNC_TIMEOUT_MS}ms."
        )
        assert receiver.poll_path(
            pn_hash, timeout_ms=_SYNC_TIMEOUT_MS
        ), (
            f"{receiver.role_label} did not learn a path to the "
            f"propagation node ({pn_hash.hex()}) within {_SYNC_TIMEOUT_MS}ms."
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
