"""LXMF conformance commands (E2E propagation interop harness).

Layered ON TOP of the wire_tcp layer. The pattern:

  1. `wire_start_tcp_*` brings up a real RNS + TCP interface. For the
     middle peer, wire_start_tcp_server is called with share_instance=True
     so the RNS is published as an AF_UNIX shared instance.
  2. `lxmf_start(wire_handle=...)` binds an LXMF router to the RNS instance
     that wire_tcp already started. Sender/receiver use this for their
     in-process LXMRouter.
  3. Middle peer: `lxmf_spawn_daemon_propagation_node` spawns a real
     `lxmd` subprocess that attaches to the shared RNS and runs the
     propagation node. This matches how production deployments run
     propagation nodes (see fleet/yggdrasil/reticulum-node.yaml).
  4. Sender/receiver peers: `lxmf_set_outbound_propagation_node` points
     them at lxmd's propagation destination.
  5. Sender: `lxmf_send_propagated(recipient=receiver_delivery_hash, ...)`.
  6. Receiver: `lxmf_sync_inbound()` pulls anything queued for it; then
     `lxmf_poll_inbox()` drains what actually got delivered.

The MVP scope is a single happy-path test (kotlin → lxmd → reference);
these commands are symmetric so follow-up PRs can widen the parametrization
matrix without bridge-surface changes.

See the companion conformance-bridge/src/main/kotlin/Lxmf.kt for the Kotlin
side. For the MVP, the Kotlin side only implements the sender commands
(lxmf_start / lxmf_set_outbound_propagation_node / lxmf_send_propagated /
lxmf_stop). `lxmf_spawn_daemon_propagation_node` is Python-only — Kotlin
has no lxmd-equivalent daemon, so it's not on the Kotlin bridge at all.
`lxmf_sync_inbound` and `lxmf_poll_inbox` throw NotImplementedError on
Kotlin until a follow-up PR adds receiver-side parametrization.
"""

import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time


_instances = {}
_instances_lock = threading.Lock()


def _get_rns():
    """Return the real (not stub) RNS module, matching wire_tcp.py.

    We route through the bridge's full-RNS helper because earlier
    crypto-only code paths install fake RNS modules that shadow the real
    one; lxmf_bridge runs in the same process as those stubs.
    """
    from bridge_server import _get_full_rns
    return _get_full_rns()


def _get_lxmf():
    """Return the LXMF top-level module.

    Imported lazily so `--reference-only` bridge startup doesn't pay the
    LXMF import cost for non-LXMF tests.
    """
    import LXMF
    return LXMF


def _wire_instance(wire_handle: str):
    """Look up a wire_tcp bridge instance by its handle.

    Duplicates nothing — the wire_tcp module owns the RNS singleton;
    we just borrow its Reticulum to attach an LXMF router to.
    """
    wire_instances, wire_lock = _wire_lock_pair()
    with wire_lock:
        return wire_instances.get(wire_handle)


def _wire_lock_pair():
    """Return the (dict, lock) pair owned by wire_tcp so we can protect
    reads/writes of the wire_inst dicts consistently with wire_tcp's
    own discipline. Imported lazily so this module can load even if
    wire_tcp isn't importable (e.g., minimal CI for a different layer).
    """
    from wire_tcp import _instances as wire_instances, _instances_lock as wire_lock
    return wire_instances, wire_lock


def cmd_lxmf_start(params):
    """Bring up an LXMF router bound to an already-started wire RNS peer.

    params:
        wire_handle (str): the handle returned by wire_start_tcp_server /
            wire_start_tcp_client on this same bridge process. lxmf_start
            attaches the LXMRouter to that same Reticulum instance (LXMF
            needs a live Transport layer; it does not spin up its own).
        display_name (str, optional): announced display name for the
            delivery destination.

    Returns:
        handle (str): opaque handle for subsequent lxmf_* commands.
        delivery_dest_hash (hex): the LXMF delivery destination hash.
            This is what other peers address when sending messages to
            this peer (what ends up in message.destination_hash).
        identity_hash (hex): the LXMF router identity hash.
    """
    wire_handle = params["wire_handle"]
    display_name = params.get("display_name")

    wire_inst = _wire_instance(wire_handle)
    if wire_inst is None:
        raise ValueError(f"Unknown wire_handle: {wire_handle}")

    RNS = _get_rns()
    LXMF = _get_lxmf()

    # Use a dedicated LXMF Identity (separate from the Transport identity),
    # same pattern as production apps. The delivery destination is then
    # announced on this identity's behalf.
    identity = RNS.Identity()
    storage_path = tempfile.mkdtemp(prefix="lxmf_conf_")

    router = LXMF.LXMRouter(identity=identity, storagepath=storage_path)
    delivery_destination = router.register_delivery_identity(
        identity, display_name=display_name
    )

    # Per-instance inbox: messages delivered via the router's
    # register_delivery_callback land here, and lxmf_poll_inbox drains
    # this list atomically.
    inbox = []
    inbox_lock = threading.Lock()

    def delivery_callback(message):
        # Keep the serialized shape stable — downstream tests assert on
        # exact key presence (== not in). See the tight-assertions feedback
        # memo: loose membership/try-get has let duplicate-delivery and
        # missing-field bugs slip past in the past.
        entry = {
            "hash": message.hash.hex() if getattr(message, "hash", None) else "",
            "source": (
                message.source_hash.hex()
                if getattr(message, "source_hash", None)
                else ""
            ),
            "destination": (
                message.destination_hash.hex()
                if getattr(message, "destination_hash", None)
                else ""
            ),
            "title": (
                message.title.decode("utf-8", errors="replace")
                if isinstance(message.title, bytes)
                else (message.title or "")
            ),
            "content": (
                message.content.decode("utf-8", errors="replace")
                if isinstance(message.content, bytes)
                else (message.content or "")
            ),
        }
        # Fields are opaque bytes/values; serialize them as hex for bytes
        # and keep primitives as-is so tests can assert on them directly.
        fields = {}
        for k, v in (getattr(message, "fields", None) or {}).items():
            fields[str(k)] = v.hex() if isinstance(v, bytes) else v
        entry["fields"] = fields
        with inbox_lock:
            inbox.append(entry)

    router.register_delivery_callback(delivery_callback)

    handle = secrets.token_hex(8)
    with _instances_lock:
        _instances[handle] = {
            "wire_handle": wire_handle,
            "router": router,
            "identity": identity,
            "delivery_destination": delivery_destination,
            "storage_path": storage_path,
            "inbox": inbox,
            "inbox_lock": inbox_lock,
            "propagation_enabled": False,
        }

    # Announce the delivery destination so the other peers can route to it.
    delivery_destination.announce()

    return {
        "handle": handle,
        "delivery_dest_hash": delivery_destination.hash.hex(),
        "identity_hash": identity.hash.hex(),
    }


# Matches the "LXMF Propagation Node started on <hex>" line lxmd logs once
# the propagation destination is live. `prettyhexrep` wraps the hex in
# angle brackets, e.g. "<abcdef1234567890>" — 20 hex chars for the
# TRUNCATED_HASHLENGTH=10 default. Regex kept tight (exactly that prefix
# + angle-bracketed hex) to avoid matching unrelated log lines.
_LXMD_PROP_DEST_RE = re.compile(
    r"LXMF Propagation Node started on <([0-9a-f]+)>"
)


def cmd_lxmf_spawn_daemon_propagation_node(params):
    """Spawn a real lxmd subprocess as this peer's propagation node.

    Architecture: the middle peer's wire_start_tcp_server call must have
    set share_instance=True. That publishes the RNS as an AF_UNIX shared
    instance. This command:

      1. Writes an lxmd config file with [propagation] enable_node=yes,
         pointing at the same rnsconfig dir the wire bridge created.
      2. Spawns `lxmd --rnsconfig <rns_config_dir> --config <lxmd_dir>
         --propagation-node -v`. We drop -s (service mode) so stdout/
         stderr are capturable for debugging.
      3. Tails stdout until lxmd logs "LXMF Propagation Node started on
         <hex>" — that's the propagation destination the sender/receiver
         need to target.
      4. Stores the Popen handle on the peer's state so lxmf_stop
         can terminate it cleanly.

    Matches how production deployments run lxmd (see
    fleet/yggdrasil/reticulum-node.yaml) rather than flipping an
    in-process LXMRouter into propagation-node mode. The in-process path
    is a test-harness hack that doesn't exercise the real
    separate-process, shared-instance code path, which is what actual
    deployments hit.

    params:
        wire_handle (str): the wire bridge handle for the middle peer.
            Must have been created with share_instance=True.
        display_name (str, optional): lxmd config display_name. Defaults
            to "conformance-prop-node".
        startup_timeout_sec (float, optional): how long to wait for lxmd
            to log "Propagation Node started" before giving up. Defaults
            to 30s — lxmd at stamp_cost_target=13 (the minimum enforced
            by LXMRouter.PROPAGATION_COST_MIN) typically takes <5s to
            start, but first-launch subsystem init (storage, ratchets,
            identity generation) can push past 10s on slow CI runners.

    Returns:
        propagation_node_dest_hash (hex): lxmd's propagation destination
            hash, to be passed to sender/receiver
            lxmf_set_outbound_propagation_node calls.
        stamp_cost (int): the actual stamp cost lxmd will require
            (floor is PROPAGATION_COST_MIN=13; a lower value in the
            config is clamped up by LXMF itself).

    Raises:
        FileNotFoundError: if `lxmd` is not on PATH.
        RuntimeError: if lxmd exits before emitting the propagation
            destination line, or if the timeout elapses without the
            line being logged.
        ValueError: if the wire handle is unknown or its RNS wasn't
            started with share_instance=True (lxmd would spin up its
            own competing Reticulum otherwise, fragmenting the network).
    """
    wire_handle = params["wire_handle"]
    display_name = params.get("display_name") or "conformance-prop-node"
    startup_timeout_sec = float(params.get("startup_timeout_sec", 30.0))

    # Verify lxmd is installed up front so the failure mode is
    # FileNotFoundError at fixture time rather than a mysterious hang.
    lxmd_path = shutil.which("lxmd")
    if not lxmd_path:
        raise FileNotFoundError(
            "lxmd binary not found on PATH. Install with `pip install lxmf` "
            "(the LXMF package ships lxmd as a console_script entrypoint)."
        )

    wire_inst = _wire_instance(wire_handle)
    if wire_inst is None:
        raise ValueError(f"Unknown wire_handle: {wire_handle}")

    if not wire_inst.get("share_instance"):
        raise ValueError(
            f"wire_handle {wire_handle} was not started with share_instance=True. "
            f"lxmd needs to attach to a shared RNS instance; otherwise it "
            f"would spawn its own Reticulum and the three-peer topology "
            f"wouldn't converge."
        )

    rns_config_dir = wire_inst["config_dir"]

    # Write the lxmd config. Shape mirrors the production
    # fleet/yggdrasil/lxmf-config.yaml ConfigMap. Key choices:
    #   - announce_at_start = Yes: emit the propagation announce
    #     immediately so sender/receiver can resolve the node without
    #     waiting for the periodic announce timer.
    #   - announce_interval omitted for node: we only need the startup
    #     announce for the MVP test window (~60s).
    #   - message_storage_limit=100: cap store size; fixture is ephemeral
    #     so this is belt-and-suspenders.
    #   - propagation_stamp_cost_target not set: defaults to
    #     PROPAGATION_COST (16); we use it as-is. LXMF-kt's sender reads
    #     the cost from the node's announce and generates a matching
    #     stamp. At cost=16 that's ~65k attempts (~2-5s) — acceptable.
    # All resource allocation from here through reader_thread.start() is
    # wrapped in a single guard: if anything raises (Popen EPERM despite
    # shutil.which succeeding, log-file open EACCES, Thread.start()
    # ENOMEM), we reverse-unwind whatever has already been allocated so
    # the caller sees the original exception without leaking tempdirs,
    # file handles, or subprocess pipes.
    lxmd_config_dir = tempfile.mkdtemp(prefix="lxmd_conf_")
    lxmd_proc = None
    lxmd_logfile = None
    try:
        lxmd_config_path = os.path.join(lxmd_config_dir, "config")
        # CONFORMANCE_LXMD_LOGLEVEL overrides the default loglevel (4=Notice).
        # Set to 7 (EXTREME) when debugging announce forwarding / path convergence
        # issues — matches RNS.LOG_EXTREME and surfaces the "Sending announce"
        # lines lxmd emits at that level.
        lxmd_loglevel = int(os.environ.get("CONFORMANCE_LXMD_LOGLEVEL", "4"))
        with open(lxmd_config_path, "w") as f:
            f.write(
                "[lxmf]\n"
                f"  display_name = {display_name}\n"
                "  announce_at_start = Yes\n"
                "\n"
                "[logging]\n"
                f"  loglevel = {lxmd_loglevel}\n"
                "\n"
                "[propagation]\n"
                "  enable_node = Yes\n"
                f"  node_name = {display_name}\n"
                "  announce_at_start = Yes\n"
                "  message_storage_limit = 100\n"
                "  propagation_message_max_accepted_size = 25000\n"
                "  propagation_sync_max_accepted_size = 102400\n"
            )

        # Spawn lxmd. Drop -s so stdout/stderr are text streams we can tail.
        # --propagation-node is redundant with enable_node=Yes in the config
        # but matches the production invocation and is belt-and-suspenders.
        #
        # PYTHONUNBUFFERED=1 is essential: when stdout is piped (not a tty),
        # CPython buffers full blocks, which means the "Propagation Node
        # started on <hex>" line won't reach our reader until lxmd emits
        # several more log lines — and in practice lxmd goes quiet after
        # startup, so without this we hit the 30s timeout even though lxmd
        # is healthy. `text=True, bufsize=1` alone doesn't fix this because
        # bufsize controls OUR pipe, not the child's internal stdio buffer.
        child_env = dict(os.environ)
        child_env["PYTHONUNBUFFERED"] = "1"
        lxmd_proc = subprocess.Popen(
            [
                lxmd_path,
                "--rnsconfig", rns_config_dir,
                "--config", lxmd_config_dir,
                "--propagation-node",
                "-v",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # interleaved so the regex match wins
            text=True,
            bufsize=1,  # line-buffered on OUR pipe
            env=child_env,
        )

        # Drain lxmd's stdout in a background thread so its pipe buffer can't
        # fill and deadlock the child. We only actually care about the
        # "Propagation Node started on <hex>" line; everything else is tee'd
        # into a ring buffer for teardown-time diagnostics.
        recent_output: list[str] = []
        prop_dest_hex = [None]  # captured by the thread; single-slot mailbox
        started_event = threading.Event()
        reader_done = threading.Event()

        # Optional file-tee for debugging: if CONFORMANCE_LXMD_LOG is set, we
        # also mirror lxmd's output there. Useful for diagnosing "lxmd is up
        # but topology didn't converge" failures where the stderr/stdout ring
        # buffer is discarded on success.
        lxmd_logfile_path = os.environ.get("CONFORMANCE_LXMD_LOG")
        lxmd_logfile = open(lxmd_logfile_path, "a") if lxmd_logfile_path else None
        if lxmd_logfile:
            lxmd_logfile.write(f"\n=== lxmd spawn (wire_handle={wire_handle}) ===\n")
            lxmd_logfile.flush()

        def _tail_lxmd():
            try:
                for line in lxmd_proc.stdout:
                    line = line.rstrip("\n")
                    recent_output.append(line)
                    if lxmd_logfile:
                        lxmd_logfile.write(line + "\n")
                        lxmd_logfile.flush()
                    # Cap the buffer at ~200 lines so a long-running test
                    # doesn't gradually eat memory. 200 lines is plenty
                    # for "why did lxmd fail to start" diagnostics.
                    if len(recent_output) > 200:
                        del recent_output[:50]
                    if prop_dest_hex[0] is None:
                        m = _LXMD_PROP_DEST_RE.search(line)
                        if m:
                            prop_dest_hex[0] = m.group(1)
                            started_event.set()
            finally:
                if lxmd_logfile:
                    try:
                        lxmd_logfile.close()
                    except Exception:
                        pass
                reader_done.set()

        reader_thread = threading.Thread(
            target=_tail_lxmd, name=f"lxmd-tail-{wire_handle}", daemon=True
        )
        reader_thread.start()
    except Exception:
        # Reverse-unwind: file handle → subprocess → tempdir. Each step
        # is idempotent on None so the guard works at any failure point.
        if lxmd_logfile is not None:
            try:
                lxmd_logfile.close()
            except Exception:
                pass
        if lxmd_proc is not None:
            _terminate_lxmd(lxmd_proc)
        _cleanup_lxmd_dir(lxmd_config_dir)
        raise

    # Wait for the startup line, the process exiting early, or timeout.
    deadline = time.time() + startup_timeout_sec
    while time.time() < deadline:
        if started_event.wait(timeout=0.25):
            break
        # If lxmd died without emitting the line, fail fast rather than
        # running the timeout clock to zero.
        if lxmd_proc.poll() is not None:
            reader_done.wait(timeout=1.0)
            tail = "\n".join(recent_output[-50:])
            _cleanup_lxmd_dir(lxmd_config_dir)
            raise RuntimeError(
                f"lxmd exited with code {lxmd_proc.returncode} before "
                f"emitting the propagation-node-started line.\n"
                f"Last lxmd output:\n{tail}"
            )

    if prop_dest_hex[0] is None:
        # Timeout. Kill lxmd so we don't leak it.
        _terminate_lxmd(lxmd_proc)
        reader_done.wait(timeout=1.0)
        tail = "\n".join(recent_output[-50:])
        _cleanup_lxmd_dir(lxmd_config_dir)
        raise RuntimeError(
            f"lxmd did not log 'LXMF Propagation Node started on <hex>' "
            f"within {startup_timeout_sec:.1f}s.\n"
            f"Last lxmd output:\n{tail}"
        )

    prop_dest_bytes = bytes.fromhex(prop_dest_hex[0])

    # Park the subprocess on the wire instance's state so teardown reaches
    # it. We attach to the wire handle (not an lxmf_start handle) because
    # the middle peer never calls lxmf_start — it has no LXMRouter of its
    # own; lxmd IS the router for this peer.
    #
    # The wire_inst dict is owned by wire_tcp._instances and must be
    # mutated under wire_tcp's own lock to stay consistent with how
    # wire_tcp protects the same dict (see cmd_wire_* handlers). Using
    # this module's _instances_lock here would not synchronize against
    # wire_tcp's route-table and listener-accept threads.
    _, wire_lock = _wire_lock_pair()
    with wire_lock:
        wire_inst["lxmd_proc"] = lxmd_proc
        wire_inst["lxmd_config_dir"] = lxmd_config_dir
        wire_inst["lxmd_reader_thread"] = reader_thread
        wire_inst["lxmd_reader_done"] = reader_done
        wire_inst["lxmd_recent_output"] = recent_output

    # Stamp cost: query lxmd's effective value via the announce app_data
    # so tests can log what was actually used. Best-effort — if the
    # announce hasn't propagated to our RNS yet, fall back to the config
    # value (LXMF's MIN floor makes the actual value >= 13).
    RNS = _get_rns()
    stamp_cost = 16  # LXMRouter.PROPAGATION_COST default
    try:
        import msgpack
        app_data = RNS.Identity.recall_app_data(prop_dest_bytes)
        if app_data:
            cfg = msgpack.unpackb(app_data)
            # Schema reference (LXMF/LXMRouter.py get_propagation_node_app_data):
            #   cfg[0] = legacy LXMF PN support (bool)
            #   cfg[1] = node timebase (int epoch)
            #   cfg[2] = propagation node state (bool)
            #   cfg[3] = per-transfer limit (kB)
            #   cfg[4] = per-sync limit
            #   cfg[5] = [propagation_stamp_cost, flexibility, peering_cost]
            #   cfg[6] = metadata dict
            # cfg[5][0] is the advertised stamp cost. If LXMF changes this
            # layout, the broad except below catches the resulting
            # IndexError / TypeError and falls back to PROPAGATION_COST
            # (16) — which remains the correct tests-default, but means a
            # schema drift goes undetected rather than surfacing as an
            # error. Re-audit against LXMRouter.get_propagation_node_app_data
            # when bumping the pinned LXMF version.
            stamp_cost = int(cfg[5][0])
    except Exception:
        pass  # fall through to the default

    return {
        "propagation_node_dest_hash": prop_dest_hex[0],
        "stamp_cost": stamp_cost,
        # Expose the on-disk storage dir so the fixture can assert on
        # the propagation node's stored-message count directly (via
        # filesystem glob) rather than routing a count query through
        # the bridge. Path derivation (verified empirically — the
        # extra "/lxmf" is added by LXMRouter internally, not lxmd):
        #   lxmd.py:     storagedir   = configdir + "/storage"
        #   lxmd.py:     LXMRouter(storagepath=storagedir)
        #   LXMRouter:   self.storagepath  = storagepath + "/lxmf"
        #   LXMRouter:   self.messagepath  = self.storagepath + "/messagestore"
        # Net result: messages land at <configdir>/storage/lxmf/messagestore.
        # See LXMF/LXMRouter.py lines 121 + 535; LXMF/Utilities/lxmd.py line 319.
        "lxmd_config_dir": lxmd_config_dir,
        "messagestore_dir": os.path.join(
            lxmd_config_dir, "storage", "lxmf", "messagestore"
        ),
    }


def _terminate_lxmd(proc: subprocess.Popen, timeout_sec: float = 5.0):
    """SIGTERM lxmd, wait, SIGKILL fallback. Idempotent on already-exited
    processes."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout_sec)
    except Exception:
        # Best-effort teardown; a lingering lxmd across test runs is
        # annoying but not catastrophic (the abstract socket namespace
        # clears when the shared-instance server dies).
        pass


def _cleanup_lxmd_dir(lxmd_config_dir: str):
    """Remove lxmd's config + storage tempdir. Idempotent."""
    if lxmd_config_dir and os.path.isdir(lxmd_config_dir):
        shutil.rmtree(lxmd_config_dir, ignore_errors=True)


def cmd_lxmf_set_outbound_propagation_node(params):
    """Point this peer's LXMRouter at a remote propagation node.

    The peer must already have a path + identity for the propagation
    destination (either via a received announce or an explicit
    Identity.recall). Assertion on the presence of the path is deferred
    to the caller — if this bridge doesn't yet know the propagation
    node, LXMF will still set the hash and fail later when it tries to
    open a link.

    params:
        handle (str): lxmf_start handle.
        propagation_node_dest_hash (hex): the value returned by the
            other peer's lxmf_enable_propagation_node.

    Returns:
        success (bool)
    """
    handle = params["handle"]
    pn_hash_hex = params["propagation_node_dest_hash"]
    pn_hash = bytes.fromhex(pn_hash_hex)

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    router = inst["router"]
    router.set_outbound_propagation_node(pn_hash)

    return {"success": True}


def cmd_lxmf_send_propagated(params):
    """Build + submit an LXMessage with PROPAGATED delivery.

    Requires the recipient's identity to be recallable (i.e. a delivery
    announce from the recipient has been observed on this peer's RNS
    instance). The caller is responsible for sequencing the announces.

    params:
        handle (str): lxmf_start handle for the sender.
        recipient_delivery_dest_hash (hex): recipient's delivery hash,
            as returned by the recipient's lxmf_start.
        content (str): UTF-8 message content.
        title (str, optional): UTF-8 title, defaults to "".
        fields (dict, optional): string-keyed int fields mapped to
            hex-encoded values (same convention as the LXMF send_direct
            command already in the bridge). Deferred for MVP — tests
            only use (content, title).

    Returns:
        message_hash (hex): LXMessage hash.
    """
    handle = params["handle"]
    recipient_hash_hex = params["recipient_delivery_dest_hash"]
    content = params["content"]
    title = params.get("title", "")

    recipient_hash = bytes.fromhex(recipient_hash_hex)

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    RNS = _get_rns()
    LXMF = _get_lxmf()

    # Rely on the recipient's delivery announce already having been
    # observed — this is the sequencing the lxmf_3peer fixture enforces.
    # If it hasn't, recall returns None and we surface that as an
    # explicit error rather than letting LXMF silently fail downstream
    # (which would show up as "message sent, never arrives" and is
    # exactly the class of bug loose assertions have let slip).
    recipient_identity = RNS.Identity.recall(recipient_hash)
    if recipient_identity is None:
        raise RuntimeError(
            f"No identity known for recipient {recipient_hash.hex()}. "
            f"Ensure the recipient announced its delivery destination "
            f"before calling lxmf_send_propagated."
        )

    recipient_destination = RNS.Destination(
        recipient_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery",
    )

    message = LXMF.LXMessage(
        destination=recipient_destination,
        source=inst["delivery_destination"],
        content=content,
        title=title,
        desired_method=LXMF.LXMessage.PROPAGATED,
    )

    router = inst["router"]

    # LXMessage defaults BOTH defer_stamp and defer_propagation_stamp to
    # True (see LXMF/LXMessage.py lines 170-171). For PROPAGATED delivery
    # with defer_propagation_stamp=True, handle_outbound parks the
    # message in pending_deferred_stamps and relies on the jobloop to
    # process it. In practice, the deferred-stamp jobloop is designed
    # for interactive app usage and does NOT reliably fire within the
    # ~30s window of a tight conformance test — reference→lxmd→receiver
    # silently loses the message because the stamp never gets generated
    # in time.
    #
    # Do the stamp generation synchronously here so handle_outbound hits
    # the non-deferred path (line 1673 of LXMRouter.py). The stamp is
    # attached via the LXMessage.propagation_stamp field. After that,
    # toggle BOTH defer flags off so the outbound-processing conditional
    # doesn't re-deflect us back to pending_deferred_stamps.
    #
    # Kotlin's LXMF-kt sender already does the equivalent — its
    # handleOutbound path generates the propagation stamp synchronously
    # before handing off to the link layer.
    target_cost = router.get_outbound_propagation_cost()
    if target_cost is None:
        raise RuntimeError(
            "Could not resolve propagation node stamp cost. The "
            "propagation node's announce app_data is not cached on "
            "this peer's RNS — ensure the fixture's path-convergence "
            "guards succeeded before calling lxmf_send_propagated."
        )
    generated_stamp = message.get_propagation_stamp(target_cost=target_cost)
    if generated_stamp is None:
        raise RuntimeError(
            f"Failed to generate propagation stamp for {message.transient_id!r} "
            f"at cost {target_cost}. LXStamper.generate_stamp returned None."
        )
    message.propagation_stamp = generated_stamp
    message.propagation_stamp_valid = True
    message.defer_stamp = False
    message.defer_propagation_stamp = False
    # pack() must be re-run after the stamp is attached (LXMessage.pack
    # bundles the stamp into the outbound payload). Clear `packed` so
    # handle_outbound's `if not lxmessage.packed: lxmessage.pack()`
    # regenerates the wire-format blob.
    message.packed = None

    router.handle_outbound(message)

    return {
        "message_hash": message.hash.hex() if message.hash else "",
    }


def cmd_lxmf_sync_inbound(params):
    """Ask this peer's LXMRouter to fetch stored messages from its
    configured outbound propagation node.

    Blocks until the transfer finishes (COMPLETE / FAILED / timeout) AND
    the delivery callbacks for the transferred messages have populated
    the inbox — so callers can immediately poll_inbox and see the full
    set of received messages without racing the router's worker threads.

    params:
        handle (str): lxmf_start handle.
        timeout_ms (int, optional): deadline for the transfer state to
            leave LINK_ESTABLISHED / REQUESTING_MESSAGES. Defaults to
            30s to match RNS's default link RTT budget.

    Returns:
        messages_received (int): propagation_transfer_last_result.
        state (str): final propagation_transfer_state name.
    """
    handle = params["handle"]
    timeout_ms = int(params.get("timeout_ms", 30000))

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    LXMF = _get_lxmf()
    router = inst["router"]

    # Python LXMF's state names are prefixed PR_* as module-level ints.
    terminal_states = {
        LXMF.LXMRouter.PR_COMPLETE,
        LXMF.LXMRouter.PR_FAILED,
        LXMF.LXMRouter.PR_NO_IDENTITY_RCVD,
        LXMF.LXMRouter.PR_NO_ACCESS,
    }

    # Snapshot the inbox size BEFORE we kick off the transfer. The poll
    # loop below waits for new messages to actually land in the inbox,
    # not just for the transfer state machine to report a count — this
    # closes two races at once:
    #   1. Stale terminal state: `propagation_transfer_state` may still
    #      be PR_COMPLETE from a previous sync. Even though LXMRouter.
    #      request_messages_from_propagation_node synchronously
    #      transitions the state on the common path (link active or
    #      re-establishing), a fast first poll otherwise has no guard
    #      against reading the previous transfer's PR_COMPLETE.
    #   2. Callback drain: delivery callbacks run on the router's own
    #      threads; the transfer reaching PR_COMPLETE doesn't guarantee
    #      the callbacks have fired yet. The previous `time.sleep(0.3)`
    #      after the state settled was an empirical constant with no
    #      guaranteed relationship to callback completion time.
    with inst["inbox_lock"]:
        inbox_size_before = len(inst["inbox"])

    # Snapshot the pre-call state. A terminal state that DIFFERS from
    # this pre-call value means the state machine actually transitioned
    # (e.g. PR_COMPLETE -> PR_FAILED on an immediately-rejected link),
    # so we don't need to see a non-terminal state first to accept it.
    # This closes a slow-failure path where LXMF goes straight to a
    # terminal state without ever leaving the initial one — previously
    # the loop burned the full timeout_ms before returning the failure.
    state_before = router.propagation_transfer_state

    router.request_messages_from_propagation_node(inst["identity"])

    deadline = time.time() + (timeout_ms / 1000.0)
    observed_non_terminal = False
    while time.time() < deadline:
        state = router.propagation_transfer_state
        if state not in terminal_states:
            observed_non_terminal = True
        # Only consider a terminal state final if either:
        #   (a) we've observed the transfer leave the initial state at
        #       least once (common happy path: state goes
        #       LINK_ESTABLISHED -> REQUESTING_MESSAGES -> PR_COMPLETE,
        #       defeating the stale PR_COMPLETE race), or
        #   (b) the current terminal state differs from the one observed
        #       before request_messages_from_propagation_node was called
        #       — this catches fast-failure paths that go straight to a
        #       new terminal state without passing through any
        #       non-terminal state first, so we fail fast instead of
        #       burning the full timeout budget.
        if state in terminal_states and (observed_non_terminal or state != state_before):
            last_result = int(router.propagation_transfer_last_result or 0)
            expected_inbox_size = inbox_size_before + last_result
            with inst["inbox_lock"]:
                current_inbox_size = len(inst["inbox"])
            # Wait for the delivery callbacks to have caught up with the
            # transfer count. This is the callback-drain guarantee (2):
            # we return only when poll_inbox will actually see the
            # messages that sync_inbound reports.
            if current_inbox_size >= expected_inbox_size:
                break
        time.sleep(0.05)

    final_state = router.propagation_transfer_state
    last_result = int(router.propagation_transfer_last_result or 0)

    return {
        "messages_received": last_result,
        "state": str(final_state),
    }


def cmd_lxmf_poll_inbox(params):
    """Drain delivered LXMessages accumulated by the delivery callback.

    The inbox holds everything the router has successfully decrypted and
    delivered since lxmf_start (or the last poll). Draining is atomic
    — tests that want exact-count semantics can call this once and
    assert on the length directly (mirrors wire_link_poll).

    params:
        handle (str): lxmf_start handle.

    Returns:
        messages (list[dict]): each with hash, source, destination,
            title, content, fields. Fields values are hex-encoded if
            bytes, passthrough otherwise.
    """
    handle = params["handle"]

    with _instances_lock:
        inst = _instances.get(handle)
    if inst is None:
        raise ValueError(f"Unknown handle: {handle}")

    with inst["inbox_lock"]:
        drained = list(inst["inbox"])
        inst["inbox"].clear()

    return {"messages": drained}


def cmd_lxmf_stop(params):
    """Tear down an LXMF router instance.

    Does NOT stop the underlying wire RNS singleton (wire_stop handles
    that). Safe to call multiple times.
    """
    handle = params["handle"]
    with _instances_lock:
        inst = _instances.pop(handle, None)
    if inst is None:
        return {"stopped": False}

    # LXMRouter doesn't expose a clean stop() API on the Python side;
    # the router's background threads are daemons and will die with the
    # process. We just clean up our own bookkeeping here.
    storage_path = inst.get("storage_path")
    if storage_path and os.path.isdir(storage_path):
        shutil.rmtree(storage_path, ignore_errors=True)

    return {"stopped": True}


def cmd_lxmf_stop_daemon_propagation_node(params):
    """Terminate the lxmd subprocess started for this wire handle.

    Idempotent — safe to call if no daemon was ever started (returns
    stopped=False) or if the daemon already exited. The fixture calls
    this in teardown to guarantee no lxmd lingers across test runs.

    params:
        wire_handle (str): the wire handle that owns the lxmd subprocess.

    Returns:
        stopped (bool): True if a running lxmd was terminated, False if
            none was present or it had already exited.
    """
    wire_handle = params["wire_handle"]
    # Look up and pop under wire_tcp's lock — the wire_inst dict is
    # owned by wire_tcp and mutating it outside wire_lock races with
    # wire_tcp's own accessors. We do the actual subprocess termination
    # + reader-join OUTSIDE the lock because _terminate_lxmd blocks on
    # wait() (up to 5s) and we don't want to hold a module-wide lock
    # that long.
    wire_instances, wire_lock = _wire_lock_pair()
    with wire_lock:
        wire_inst = wire_instances.get(wire_handle)
        if wire_inst is None:
            return {"stopped": False}
        proc = wire_inst.pop("lxmd_proc", None)
        lxmd_config_dir = wire_inst.pop("lxmd_config_dir", None)
        reader_done = wire_inst.pop("lxmd_reader_done", None)
        wire_inst.pop("lxmd_reader_thread", None)
        wire_inst.pop("lxmd_recent_output", None)

    was_running = proc is not None and proc.poll() is None
    if proc is not None:
        _terminate_lxmd(proc)
    if reader_done is not None:
        reader_done.wait(timeout=2.0)
    _cleanup_lxmd_dir(lxmd_config_dir)

    return {"stopped": was_running}


LXMF_COMMANDS = {
    "lxmf_start": cmd_lxmf_start,
    "lxmf_spawn_daemon_propagation_node": cmd_lxmf_spawn_daemon_propagation_node,
    "lxmf_stop_daemon_propagation_node": cmd_lxmf_stop_daemon_propagation_node,
    "lxmf_set_outbound_propagation_node": cmd_lxmf_set_outbound_propagation_node,
    "lxmf_send_propagated": cmd_lxmf_send_propagated,
    "lxmf_sync_inbound": cmd_lxmf_sync_inbound,
    "lxmf_poll_inbox": cmd_lxmf_poll_inbox,
    "lxmf_stop": cmd_lxmf_stop,
}
