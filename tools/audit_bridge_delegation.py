#!/usr/bin/env python3
"""Audit bridge command delegation — find handlers that hand-roll protocol
logic instead of delegating to the real implementation, and the conformance
tests that consequently test the bridge's reimplementation rather than the
implementation under test.

The antipattern (same one that the resource family had — see
tests/wire/test_resource_invariants.py): a bridge command handler that, instead
of calling into real RNS/LXMF, reconstructs the protocol logic itself with
struct / umsgpack / byte concatenation / composite hashing. The test built on
that command then passes or fails based on the *bridge's* copy of the logic.
If the copy has drifted from upstream (the deleted resource_proof command had
a truncated proof; cmd_resource_hash had the operands in the wrong order) the
suite stays green while testing the wrong thing.

Classification (per bridge command handler, by AST analysis):

  GENUINE    Thin wrapper over a real loaded crypto primitive (X25519, HMAC,
             HKDF, PKCS7, AES, Token, LXStamper, bz2, or sha256/sha512 which
             *are* the primitive). Nothing protocol-specific is reconstructed.

  LIVE       Drives a real RNS/LXMF instance — _get_full_rns / _get_rns / a
             real `import RNS` / live-instance globals. The wire_* commands and
             the rns_* / lxmf_* networking commands. This is honest delegation.

  HANDROLLED Reconstructs RNS/LXMF composite logic in the bridge: struct.pack,
             umsgpack, framing escapes, composite hashing (hashlib outside the
             sha256/sha512 primitives), protocol bit-layout, or concatenation
             of protocol fields. A test whose command is HANDROLLED is
             exercising this file, not the implementation under test.

  REVIEW     Looks like a thin wrapper, but the *arguments* it passes encode
             protocol-specific knowledge (e.g. an HKDF call whose salt is a
             link id). The AST heuristic can't see that; flagged for a human.

  MIRRORED   Faithfully reproduces a piece of RNS logic RNS does NOT expose as a
             callable (the inline HDLC/KISS receive de-escape). Honest by
             exception: constants are read off live RNS and the tests are
             known-answer round-trips against the GENUINE forward primitive.
             Tiny, documented (MIRRORS_RNS_RECEIVE) and rot-guarded; NOT counted
             dishonest. Anything reconstructing protocol bytes that is NOT pinned
             here is still HANDROLLED.

  ADVERSARIAL Damages a GENUINE RNS-produced artifact (a real packed packet) and
             feeds it back through a REAL RNS receive/validate path to prove that
             path rejects the forgery. The byte-corruption uses buffer idioms the
             heuristic scores asm:*, but no protocol is ASSEMBLED — every
             protocol byte came from RNS, and the logic under test is RNS's.
             Honest by exception, same bar as MIRRORED: tiny, documented
             (ADVERSARIAL_CORRUPTORS), rot-guarded; NOT counted dishonest.

  DEAD       Defined but shadowed by a later def of the same name, or
             registered in no COMMANDS dict. Dead weight, not callable.

A test is DISHONEST if any command in its @conformance_case(commands=...) is
HANDROLLED, REVIEW, or UNKNOWN. Wire/behavioral tests use _*Peer method names
that drop the module prefix; those resolve to wire_*/behavioral_* commands and
inherit that command's real classification. A token that resolves to nothing is
UNKNOWN (never optimistically LIVE).

main() returns a non-zero exit status if ANY command is HANDROLLED/REVIEW/UNKNOWN,
ANY test is dishonest, or ANY override-set pin is stale — so CI can fail on it.

Run:  python tools/audit_bridge_delegation.py            # exit 1 on any violation
      python tools/audit_bridge_delegation.py --verbose   # per-command evidence
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from generate_tests_md import _categorize, collect_items  # noqa: E402

# Command-module files and the registry dict each one defines.
COMMAND_MODULES = {
    "bridge_server.py": "COMMANDS",
    "wire_tcp.py": "WIRE_COMMANDS",
    "behavioral_transport.py": "BEHAVIORAL_COMMANDS",
}

# Module-global names whose presence in a handler body means it is operating on
# a live RNS instance rather than reconstructing anything.
LIVE_GLOBALS = {
    "_rns_instance", "_rns_module", "_instances", "_instances_lock",
}
LIVE_CALLS = {"_get_full_rns", "_get_rns", "_ensure_minimal_rns"}

# Named hash primitives — sha256/sha512 ARE the primitive, and
# truncated_hash is RNS.Identity.truncated_hash (full_hash(data)[:16]), a
# byte-identical named primitive with no composite input. A hashlib call in
# any *other* handler means composite hashing → handrolled.
HASH_PRIMITIVES = {"cmd_sha256", "cmd_sha512", "cmd_truncated_hash"}

# Handlers the AST heuristic scores GENUINE because they are a single call into
# a real loaded module — but the call's *arguments* encode RNS protocol
# knowledge (which salt, which context, which length) that the bridge should be
# getting from real RNS, not hardcoding. The heuristic genuinely cannot see
# this; listing them here keeps the audit honest instead of silently passing
# them. Each is a candidate for conversion to a live-instance command.
#
# Currently empty: the previous entries (cmd_link_derive_key, cmd_ifac_derive_key,
# cmd_ratchet_derive_key) named handlers that no longer exist — that KDF logic is
# now driven through live RNS commands. Stale names here are worse than useless:
# REVIEW could never be emitted, so the whole-program "a test using a REVIEW
# command is dishonest" guard silently became dead code. build_command_index now
# *validates* that every name below resolves to a real handler (fails the audit
# otherwise), so this set can't rot unnoticed again.
KDF_PROTOCOL_REVIEW: set[str] = set()

# Handlers that hand-roll a composite by applying a real primitive and then
# slicing a protocol-specific portion out of the result — e.g. IFAC is "the
# last N bytes of the Ed25519 signature of the packet". The math is genuine,
# the "take last N bytes" rule is RNS interface logic. A lone slice of a
# primitive's output is too noisy a signal to detect by AST without false
# positives, so these are pinned by hand.
#
# Currently empty: the previous entries (cmd_ifac_compute, cmd_ifac_verify) named
# handlers that no longer exist. Like KDF_PROTOCOL_REVIEW above, the names here
# are validated against real handlers by build_command_index.
HEURISTIC_MISS_HANDROLLED: set[str] = set()

# Handlers that faithfully MIRROR a piece of RNS receive-path logic that RNS
# does not expose as a standalone callable. RNS's de-framing (HDLC/KISS
# de-escape) lives INLINE inside each interface read loop (e.g.
# TCPInterface.py:389-391 does two literal frame.replace(...) calls); there is no
# RNS.*.deframe() to delegate to, unlike the forward direction (TCPInterface.HDLC
# .escape / KISSInterface.KISS.escape are real exposed staticmethods, used by the
# GENUINE hdlc_escape/kiss_escape commands). These handlers reproduce RNS's exact
# inverse using constants read off the live RNS interface classes, and the tests
# that use them are KNOWN-ANSWER round-trips: deframe(FLAG + RNS.escape(x) + FLAG)
# must equal the original x (ground truth), framed via the GENUINE forward
# primitive — so they are NOT "tests of the bridge's own reimplementation."
# This set is deliberately tiny and is rot-guarded (build_command_index fails the
# audit if any name here stops backing a real handler), so it cannot silently
# accumulate the way the previous override sets did. Anything NOT listed here that
# reconstructs protocol bytes is still HANDROLLED and fails the build.
MIRRORS_RNS_RECEIVE: dict[str, str] = {
    "cmd_hdlc_deframe": "RNS exposes no standalone HDLC de-escape; mirrors "
                        "TCPInterface.py:389-391 inverse-of-HDLC.escape, "
                        "constants read off RNS; round-trip KAT vs RNS HDLC.escape.",
    "cmd_kiss_deframe": "RNS exposes no standalone KISS de-escape; mirrors "
                        "KISSInterface read-loop TFEND/TFESC un-transpose, "
                        "constants read off RNS; round-trip KAT vs RNS KISS.escape.",
}

# Adversarial corruptors: handlers that take a GENUINE RNS-produced artifact
# (a packet packed by real RNS, encrypted with a real link key), DAMAGE it, and
# feed it back through a REAL RNS receive/validate path — to prove that path
# REJECTS the forgery. RNS exposes no "corrupt this packet" API, so the damage
# (a one-byte change, a truncation) is necessarily expressed with byte-buffer
# idioms the heuristic scores `asm:*`. But the bridge here is NOT reconstructing
# protocol bytes — it destroys a few of them; every protocol-bearing byte was
# produced by real RNS, and the logic UNDER TEST (decrypt / HMAC-verify /
# signature-check / teardown decision) is 100% RNS. The tests are
# known-discriminators: the pristine artifact is accepted (positive control) and
# the damaged one is rejected, so they test real RNS rejection branches, not the
# bridge's reimplementation (there is none). Held to the same bar as
# MIRRORS_RNS_RECEIVE: tiny, documented per-entry, and rot-guarded
# (build_command_index fails the audit if a name here stops backing a real
# handler). Anything that ASSEMBLES protocol bytes is still HANDROLLED.
ADVERSARIAL_CORRUPTORS: dict[str, str] = {
    "cmd_wire_send_undecryptable":
        "Builds a real SINGLE DATA packet to the recalled OUT destination via "
        "RNS.Packet.pack (genuine RNS encryption + receipt), then DAMAGES only "
        "the ciphertext — either bumping one Token HMAC tail byte (decrypt fails, "
        "dropped at Destination.receive) or stripping the ciphertext entirely "
        "(rejected at the deframe/parse layer). Asserts the receiver delivers "
        "nothing and emits no proof — the real decrypt/reject path is under test; "
        "no protocol is assembled here (truncation removes bytes, it adds none).",
    "cmd_wire_inject_tampered_link_data":
        "Packs a real DATA packet to an established link via RNS.Packet.pack, "
        "damages one byte (or truncates), and feeds it to the real link.receive; "
        "asserts the genuine packet is delivered and the tampered one is dropped "
        "by RNS's own token-HMAC-before-decrypt — no protocol assembled here.",
    "cmd_wire_inject_crafted_lrproof":
        "Builds a link-establishment PROOF and replays it through the real "
        "Link.validate_proof (the oracle that decides ACTIVE / PENDING / CLOSED). "
        "The signatures are genuine RNS crypto (real Identity.sign by the "
        "destination key, a throwaway key, or over unrelated data) and the body "
        "is concatenated exactly as Link.prove builds it; the mode_mismatch "
        "variant signs a GENUINE full-MTU proof (real Link.signalling_bytes at "
        "the link's own mode) and then flips ONLY the mode field of one "
        "signalling byte, and wrong_size truncates a genuine 96-byte proof — both "
        "are single-artifact corruptions, not hand-assembled protocol. No "
        "validation logic is reimplemented; RNS's own validate_proof judges every "
        "variant.",
    "cmd_wire_inject_crafted_link_request":
        "Feeds a crafted LINKREQUEST payload through the real "
        "Link.validate_request. The 64/67-byte and size variants are slices of "
        "a real initiator's request_data; the bad_mode variant overwrites the "
        "single signalling mode byte of that real payload with a reserved mode "
        "to prove the handshake mode gate rejects it — no protocol assembled.",
    "cmd_wire_inject_malformed_resource_adv":
        "Takes a GENUINE ResourceAdvertisement from real RNS (real "
        "ResourceAdvertisement.pack), unpacks its info map with RNS's OWN "
        "vendored umsgpack, drops ONE mandatory key ('h'), re-packs with that "
        "same serializer (garbage variant is just random bytes), then replays it "
        "through the real Resource.accept to prove the malformed advertisement is "
        "dropped (no inbound Resource, no crash). The only asm:* signal is "
        "umsgpack — RNS's own serializer round-tripping an RNS dict; no protocol "
        "field is reconstructed by hand.",
    "cmd_discovery_craft_announce":
        "Takes a GENUINE announce from the real InterfaceAnnouncer builder, "
        "unpacks its info map with RNS's OWN vendored umsgpack, mutates ONE "
        "decoded field (drop a mandatory key / wrong-type a field / set a "
        "non-whitelisted INTERFACE_TYPE), re-packs with that same serializer "
        "and re-stamps with real LXStamper, then replays it through the real "
        "received_announce to prove the malformation is rejected. The only "
        "asm:* signal is umsgpack — RNS's own serializer round-tripping an RNS "
        "dict; the field numbering, flag byte and stamp PoW are all RNS's/LXMF's.",
}

# Live-instance accessors / RNS loaders. A handler that *calls* one of these is
# definitionally driving real RNS (it earns a live: signal). Their bodies are
# bridge infrastructure for loading and reusing the RNS singleton — not protocol
# reconstruction — so the helper-recursion pass does NOT descend into them. (If
# it did, any stray buffer idiom inside the loader would, under the
# HANDROLLED-before-LIVE precedence, wrongly flip every LIVE handler that touches
# RNS to HANDROLLED.)
# Reference-bridge observability helpers invoked purely for side-effect by the
# LIVE wire_start_* path: _install_inbound_tap wraps RNS.Transport.inbound to
# RECORD every received packet (forwarding to the real inbound), and
# _record_and_forward is that wrapper body. Their incidental header bit-parsing
# (packet_type via `raw[0] & 0b11`, for the reference-only wire_get_received_packets
# observable) is introspection, NOT protocol reconstruction by the command under
# test — wire_start_* drive a live RNS.Reticulum. So their asm:* signals must not
# propagate up and falsely flip the live start commands to HANDROLLED. Excluded
# from transitive recursion, same as the live-instance loaders.
OBSERVABILITY_HELPERS = {"_install_inbound_tap", "_record_and_forward"}
NO_RECURSE_HELPERS = LIVE_CALLS | OBSERVABILITY_HELPERS


def _dotted(node: ast.AST) -> str | None:
    """Render an ast.Name / ast.Attribute call target as a dotted string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _flatten_add(node: ast.AST) -> list[ast.AST]:
    """Flatten a left-nested chain of `+` BinOps into its operand terms."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _is_int_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, int)


def _annotation_node_ids(func: ast.AST) -> set[int]:
    """id()s of every AST node sitting inside a type annotation in `func`.

    Annotations are the one place a bitwise operator appears without being a
    real bit-twiddle: PEP-604 `str | None` parses as `BinOp(BitOr)`. Skipping
    annotation subtrees during signal extraction kills that false positive at
    the root (no per-operator special-casing) and is robust for return,
    parameter, and variable (`x: T = ...`) annotations alike.
    """
    excluded: set[int] = set()
    roots: list[ast.AST] = []
    for node in ast.walk(func):
        if isinstance(node, ast.AnnAssign) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, ast.FunctionDef) and node.returns is not None:
            roots.append(node.returns)
    for root in roots:
        for sub in ast.walk(root):
            excluded.add(id(sub))
    return excluded


def _scan_function(
    func: ast.FunctionDef, funcs_by_name: dict, suppress_hashlib: bool
) -> tuple[set[str], set[str], set[str]]:
    """Scan ONE function body. Returns (signals, called-cmd-handlers, helper-refs).

    helper-refs are names of *non-cmd_* module functions referenced in the body
    — whether called (`_helper()`) or passed by reference as a thread/callback
    target (`Thread(target=_helper)`). classify_handler folds the signals of
    those helpers in, so protocol logic factored out of a cmd_ handler into a
    private helper or thread target is still attributed to the handler.
    """
    signals: set[str] = set()
    called_cmds: set[str] = set()
    helper_refs: set[str] = set()
    excluded = _annotation_node_ids(func)

    # Track which local names hold bytes — propagating from hex_to_bytes(...)
    # inputs through slices and bytes-concatenation assignments. Used by two
    # signals:
    #   asm:fieldslice — slicing a bytes local into a wire-format sub-range.
    #   asm:concat     — adding 2+ bytes-typed values into a wire structure
    #                    (e.g. `signed_data = link_id + receiver_pub + sig`).
    # Refining `+` to only fire when operands are bytes-typed is what stops
    # numeric offset arithmetic like `keysize + name_hash_len` (which is
    # pervasive inside honest parsers that read a known RNS layout) from
    # being mistaken for byte concatenation.

    def _is_bytes_typed(node, hex_locals):
        if isinstance(node, ast.Name):
            return node.id in hex_locals
        if isinstance(node, ast.Constant):
            return isinstance(node.value, bytes)
        if isinstance(node, ast.Call):
            return _dotted(node.func) == "hex_to_bytes"
        if isinstance(node, ast.Subscript):
            return _is_bytes_typed(node.value, hex_locals)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return all(
                _is_bytes_typed(t, hex_locals) for t in _flatten_add(node)
            )
        return False

    hex_locals: set[str] = set()
    # Iterative propagation: a name is bytes-typed if assigned from any
    # bytes-typed expression. Fixpoint terminates in O(passes) where each
    # pass adds at least one new name; the handler bodies are tiny.
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and _is_bytes_typed(node.value, hex_locals):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id not in hex_locals:
                        hex_locals.add(target.id)
                        changed = True

    for node in ast.walk(func):
        if id(node) in excluded:
            continue
        if isinstance(node, ast.Call):
            callee = _dotted(node.func)
            if callee in LIVE_CALLS:
                signals.add("live:get_rns")
            if callee in ("struct.pack", "struct.unpack"):
                signals.add("asm:struct")
            if callee in ("umsgpack.packb", "umsgpack.unpackb"):
                signals.add("asm:umsgpack")
            if callee and callee.startswith("hashlib.") and not suppress_hashlib:
                signals.add("asm:hashlib")
            if callee and callee.startswith("cmd_"):
                called_cmds.add(callee)
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr == "replace":
                    signals.add("asm:replace")
                # int wire-serialization: `n.to_bytes(2, "big")` /
                # `int.from_bytes(buf, "big")`. Exclude RNS/LXMF-rooted calls —
                # `RNS.Identity.from_bytes(...)` is real delegation, not a
                # hand-rolled integer codec.
                elif attr in ("to_bytes", "from_bytes"):
                    root = callee.split(".")[0] if callee else None
                    if root not in ("RNS", "LXMF"):
                        signals.add("asm:intbytes")
                # b"".join(parts) assembles a wire buffer by hand. Only fires on
                # a *bytes-constant* separator — "".join (str) and
                # os.path.join (Attribute receiver) are excluded.
                elif (
                    attr == "join"
                    and isinstance(node.func.value, ast.Constant)
                    and isinstance(node.func.value.value, bytes)
                ):
                    signals.add("asm:join")
            # bytearray(...) / bytes([...]) buffer construction.
            if callee == "bytearray":
                signals.add("asm:bytesbuf")
            elif callee == "bytes" and len(node.args) == 1 and isinstance(
                node.args[0], (ast.List, ast.ListComp, ast.Tuple)
            ):
                signals.add("asm:bytesbuf")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            if any(n.split(".")[0] in ("RNS", "LXMF") for n in names):
                signals.add("live:import")
        elif isinstance(node, ast.Name):
            if node.id in LIVE_GLOBALS:
                signals.add("live:global")
            # Reference to another module function (called or passed by
            # reference). Non-cmd_ helpers are recursed into by
            # classify_handler; cmd_ delegation is handled by the transitive
            # pass; the live-instance loaders are deliberately not descended.
            if (
                node.id in funcs_by_name
                and not node.id.startswith("cmd_")
                and node.id not in NO_RECURSE_HELPERS
            ):
                helper_refs.add(node.id)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Slice)
            and isinstance(node.value, ast.Name)
            and node.value.id in hex_locals
        ):
            signals.add("asm:fieldslice")
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.op, (ast.LShift, ast.RShift, ast.BitOr,
                                    ast.BitAnd, ast.BitXor)):
                signals.add("asm:bitop")
        elif isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.LShift, ast.RShift, ast.BitOr,
                                    ast.BitAnd, ast.BitXor)):
                signals.add("asm:bitop")
            elif isinstance(node.op, ast.Add):
                terms = _flatten_add(node)
                # Byte concatenation of 2+ bytes-typed operands (e.g.
                # `signed_data = link_id + receiver_pub + sig`) builds a
                # wire structure by hand. Numeric arithmetic like
                # `keysize + name_hash_len` doesn't trip this — neither
                # operand traces back to bytes (hex_to_bytes / slice / bytes
                # literal / bytes-typed Add).
                if len(terms) >= 2 and all(
                    _is_bytes_typed(t, hex_locals) for t in terms
                ):
                    signals.add("asm:concat")

    return signals, called_cmds, helper_refs


def classify_handler(
    func: ast.FunctionDef, funcs_by_name: dict
) -> tuple[str, set[str], set[str]]:
    """Return (classification, evidence-signals, called-cmd-handlers).

    Pure AST analysis of the handler body *and* every non-cmd_ helper / thread
    target it transitively references (the live-instance loaders excepted) — see
    the module docstring for what each classification means.

    Precedence: pinned exceptions (MIRRORED, ADVERSARIAL — honest-by-exception,
    matched by name first) > HANDROLLED > LIVE > REVIEW > GENUINE. HANDROLLED is
    checked BEFORE LIVE on purpose: protocol reconstruction in this codebase happens
    inside handlers that *also* touch a live RNS instance, so scoring LIVE on the
    first live: signal would structurally hide exactly the hand-rolling this tool
    exists to catch. The KDF_PROTOCOL_REVIEW override then demotes a few
    GENUINE-looking handlers; both override sets are validated against real
    handlers in build_command_index.

    The called-cmd-handlers set feeds the transitive pass in parse_module: a
    handler that calls a handrolled cmd_ handler is itself handrolled.
    """
    suppress_hashlib = func.name in HASH_PRIMITIVES
    signals: set[str] = set()
    called_cmds: set[str] = set()

    # Breadth-first over the handler and the non-cmd_ helpers it references,
    # folding every scanned function's signals together. visited is keyed by
    # function name (cycle guard for mutually-recursive helpers).
    visited: set[str] = {func.name}
    queue: list[ast.FunctionDef] = [func]
    while queue:
        fn = queue.pop()
        fsig, fcmds, frefs = _scan_function(fn, funcs_by_name, suppress_hashlib)
        signals |= fsig
        called_cmds |= fcmds
        for ref in frefs:
            if ref not in visited:
                visited.add(ref)
                target = funcs_by_name.get(ref)
                if target is not None:
                    queue.append(target)

    if func.name in MIRRORS_RNS_RECEIVE:
        return "MIRRORED", signals | {"pinned:mirrors-rns-receive"}, called_cmds
    if func.name in ADVERSARIAL_CORRUPTORS:
        return "ADVERSARIAL", signals | {"pinned:adversarial-corruptor"}, called_cmds
    if func.name in HEURISTIC_MISS_HANDROLLED:
        return "HANDROLLED", signals | {"pinned:primitive-then-slice"}, called_cmds
    if any(s.startswith("asm:") for s in signals):
        return "HANDROLLED", signals, called_cmds
    if any(s.startswith("live:") for s in signals):
        return "LIVE", signals, called_cmds
    if func.name in KDF_PROTOCOL_REVIEW:
        return "REVIEW", signals | {"pinned:kdf-params"}, called_cmds
    return "GENUINE", signals, called_cmds


def parse_module(path: Path):
    """Parse one command-module file. Returns (handlers, registry, dead, funcs).

    handlers: {funcname: (classification, signals)} — last def of each name wins
              (Python semantics), so a shadowed earlier def never appears here.
    registry: {command_name: funcname} from the module's *_COMMANDS dict.
    dead:     [funcname] — functions shadowed by a later def of the same name.
    funcs:    {funcname: FunctionDef} for EVERY function in the module — the
              helper map classify_handler recurses through (last def wins).
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    defs: dict[str, list[ast.FunctionDef]] = defaultdict(list)
    funcs_by_name: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            funcs_by_name[node.name] = node  # last def of a name wins
            if node.name.startswith("cmd_"):
                defs[node.name].append(node)

    handlers: dict[str, tuple[str, set[str]]] = {}
    called: dict[str, set[str]] = {}
    for name, nodes in defs.items():
        classification, signals, called_cmds = classify_handler(
            nodes[-1], funcs_by_name
        )
        handlers[name] = (classification, signals)
        called[name] = called_cmds

    # Transitive hand-rolling: a handler that calls a handrolled handler is
    # only as honest as the worst thing it delegates to (e.g.
    # lxmf_unpack_with_fields just post-processes lxmf_unpack's output). Run
    # to a fixpoint; LIVE handlers are left alone — they fundamentally drive
    # a real instance even if they touch a helper.
    changed = True
    while changed:
        changed = False
        for name, callees in called.items():
            cls, signals = handlers[name]
            if cls in ("HANDROLLED", "LIVE"):
                continue
            if any(handlers.get(c, ("", None))[0] == "HANDROLLED" for c in callees):
                handlers[name] = ("HANDROLLED", signals | {"transitive:calls-handrolled"})
                changed = True

    dead = [name for name, nodes in defs.items() if len(nodes) > 1]

    registry: dict[str, str] = {}
    registry_name = COMMAND_MODULES[path.name]
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == registry_name for t in node.targets)
            and isinstance(node.value, ast.Dict)
        ):
            for key, val in zip(node.value.keys, node.value.values):
                if isinstance(key, ast.Constant) and isinstance(val, ast.Name):
                    registry[key.value] = val.id
    return handlers, registry, dead, funcs_by_name


def build_command_index():
    """Classify every registered bridge command across all command modules.

    Returns (commands, dead_handlers, override_rot):
      commands: {command_name: (classification, funcname, module, signals)}
      dead_handlers: {module: [funcname, ...]}
      override_rot: sorted [name] in an override set that no real handler backs
                    (stale pins → fail the audit; see main()).
    """
    commands: dict[str, tuple] = {}
    dead_handlers: dict[str, list[str]] = {}
    all_handlers: set[str] = set()
    for filename in COMMAND_MODULES:
        path = REPO_ROOT / "reference" / filename
        handlers, registry, dead, _funcs = parse_module(path)
        all_handlers.update(handlers)
        dead_handlers[filename] = sorted(dead)
        for cmd_name, funcname in registry.items():
            classification, signals = handlers.get(funcname, ("DEAD", set()))
            commands[cmd_name] = (classification, funcname, filename, signals)
        # Registered handler names that no def backs, or defs that nothing
        # registers, are both dead weight — surface the unregistered ones.
        registered_funcs = set(registry.values())
        for funcname in handlers:
            if funcname not in registered_funcs and funcname not in dead:
                dead_handlers[filename].append(f"{funcname} (unregistered)")

    # Override-set integrity: every pinned name MUST back a real handler.
    # A stale name silently disables its branch (REVIEW could never be emitted
    # once KDF_PROTOCOL_REVIEW rotted), which is exactly how part of "0
    # dishonest" became vacuously true. Surface stale pins so main() can fail.
    override_rot = sorted(
        (KDF_PROTOCOL_REVIEW | HEURISTIC_MISS_HANDROLLED
         | set(MIRRORS_RNS_RECEIVE) | set(ADVERSARIAL_CORRUPTORS))
        - all_handlers
    )
    return commands, dead_handlers, override_rot


def resolve_command(name: str, commands: dict) -> tuple[str, str]:
    """Resolve a @conformance_case command token to (classification, resolved).

    Tests under tests/ (root) name bridge commands directly. Tests under
    tests/wire and tests/behavioral name _*Peer methods that drop the module
    prefix (`inject` → `behavioral_inject`, `listen` → `wire_listen`); resolve
    those by trying the `wire_` and `behavioral_` prefixes against the real
    registry, so the token inherits its backing command's *actual*
    classification.

    A token that resolves to nothing is genuinely UNKNOWN (loud) — never
    optimistically LIVE. The previous version returned LIVE for any unresolved
    token under tests/wire|behavioral, which meant the honesty metric was
    computed over optimistically-defaulted input and could never surface a
    typo'd or removed command.
    """
    if name in commands:
        return commands[name][0], name
    for prefix in ("wire_", "behavioral_"):
        if f"{prefix}{name}" in commands:
            return commands[f"{prefix}{name}"][0], f"{prefix}{name}"
    return "UNKNOWN", name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--verbose", action="store_true",
        help="print per-command classification with AST evidence",
    )
    args = parser.parse_args()

    commands, dead_handlers, override_rot = build_command_index()

    # Diagnostic: the wire/behavioral command modules are expected to be
    # all-LIVE. If one ever contributes a HANDROLLED/REVIEW/DEAD command, the
    # short-prefix peer-method tokens in its test dir resolve to that (now
    # non-LIVE) command — warn so it's visible. The command itself is already
    # counted in by_class below and fails the audit on its own.
    for filename, test_dir in (
        ("wire_tcp.py", "tests/wire/"),
        ("behavioral_transport.py", "tests/behavioral/"),
    ):
        module_classes = {
            cls for _n, (cls, _fn, mod, _sig) in commands.items() if mod == filename
        }
        dishonest = module_classes & {"HANDROLLED", "REVIEW", "DEAD"}
        if dishonest:
            print(f"  WARNING: {filename} contributes {sorted(dishonest)} command(s) "
                  f"— {test_dir} peer tokens may resolve to non-LIVE commands",
                  file=sys.stderr)

    by_class: dict[str, list[str]] = defaultdict(list)
    for name, (classification, *_rest) in commands.items():
        by_class[classification].append(name)

    print("=" * 78)
    print("BRIDGE COMMAND DELEGATION AUDIT")
    print("=" * 78)
    print()
    total = len(commands)
    for cls in ("GENUINE", "LIVE", "MIRRORED", "ADVERSARIAL", "HANDROLLED", "REVIEW", "DEAD", "UNKNOWN"):
        n = len(by_class.get(cls, []))
        if n:
            print(f"  {cls:11s} {n:3d}  ({n / total * 100:4.1f}% of {total} registered commands)")
    print()

    dead_total = sum(len(v) for v in dead_handlers.values())
    if dead_total:
        print(f"  DEAD CODE: {dead_total} shadowed/unregistered handler(s):")
        for module, names in dead_handlers.items():
            for name in names:
                print(f"    - {module}: {name}")
        print()

    # --- handrolled commands grouped by family prefix --------------------
    print("-" * 78)
    print("HANDROLLED COMMANDS (bridge reconstructs the protocol logic itself)")
    print("-" * 78)
    families: dict[str, list[str]] = defaultdict(list)
    for name in sorted(by_class.get("HANDROLLED", [])):
        families[name.split("_")[0]].append(name)
    for family, names in sorted(families.items()):
        print(f"  {family + '_*':22s} {', '.join(names)}")
    if by_class.get("REVIEW"):
        print()
        print("  REVIEW (thin wrapper, but arguments encode protocol knowledge):")
        for name in sorted(by_class["REVIEW"]):
            print(f"    - {name}  [{commands[name][1]}]")
    print()

    # --- MIRRORED: justified faithful copies of non-exposed RNS receive logic ---
    if by_class.get("MIRRORED"):
        print("-" * 78)
        print("MIRRORED COMMANDS (faithful copy of RNS logic RNS exposes no callable for)")
        print("-" * 78)
        print("  Honest by exception: round-trip KAT against the GENUINE forward")
        print("  primitive; constants read off live RNS. Not counted as dishonest.")
        for name in sorted(by_class["MIRRORED"]):
            funcname = commands[name][1]
            justification = MIRRORS_RNS_RECEIVE.get(funcname, "")
            print(f"    - {name}  [{funcname}]")
            if justification:
                print(f"        {justification}")
        print()

    # --- ADVERSARIAL: corruptors that damage a genuine RNS artifact ---
    if by_class.get("ADVERSARIAL"):
        print("-" * 78)
        print("ADVERSARIAL COMMANDS (damage a genuine RNS artifact to test a real")
        print("                      RNS rejection path; assemble no protocol)")
        print("-" * 78)
        print("  Honest by exception: the packet is built + the receive path run by")
        print("  real RNS; the bridge only corrupts a byte. Not counted as dishonest.")
        for name in sorted(by_class["ADVERSARIAL"]):
            funcname = commands[name][1]
            justification = ADVERSARIAL_CORRUPTORS.get(funcname, "")
            print(f"    - {name}  [{funcname}]")
            if justification:
                print(f"        {justification}")
        print()

    if args.verbose:
        print("-" * 78)
        print("PER-COMMAND EVIDENCE")
        print("-" * 78)
        for name in sorted(commands):
            classification, funcname, module, signals = commands[name]
            sig = ",".join(sorted(signals)) if signals else "-"
            print(f"  {classification:11s} {name:34s} {sig}")
        print()

    # --- cross-reference: which tests are dishonest ----------------------
    print("=" * 78)
    print("TEST HONESTY BY CATEGORY")
    print("=" * 78)
    print("  A test is DISHONEST if any command it uses is HANDROLLED/REVIEW/UNKNOWN —")
    print("  it is testing the bridge's reimplementation, not the real impl.")
    print()

    items = collect_items()
    categories = _categorize(items)

    cat_dishonest: list[tuple[str, list]] = []
    grand_honest = grand_dishonest = 0
    for title, _desc, files in categories:
        dishonest_in_cat = []
        honest = dishonest = 0
        for rel_path, rows in files:
            for fn_name, case in rows:
                verdicts = [
                    resolve_command(c, commands) for c in case.commands
                ]
                bad = [
                    (resolved, cls)
                    for cls, resolved in verdicts
                    if cls in ("HANDROLLED", "REVIEW", "UNKNOWN")
                ]
                if bad:
                    dishonest += 1
                    dishonest_in_cat.append((rel_path, fn_name, bad))
                else:
                    honest += 1
        grand_honest += honest
        grand_dishonest += dishonest
        flag = "  <-- all dishonest" if honest == 0 and dishonest else ""
        print(f"  {title:38s} {honest:3d} honest / {dishonest:3d} dishonest{flag}")
        if dishonest_in_cat:
            cat_dishonest.append((title, dishonest_in_cat))

    print()
    print(f"  TOTAL: {grand_honest} honest / {grand_dishonest} dishonest "
          f"({grand_dishonest / (grand_honest + grand_dishonest) * 100:.0f}% dishonest)")
    print()

    print("-" * 78)
    print("DISHONEST TESTS (and the handrolled commands they depend on)")
    print("-" * 78)
    for title, dishonest_in_cat in cat_dishonest:
        print(f"\n  ## {title}")
        for rel_path, fn_name, bad in dishonest_in_cat:
            offenders = ", ".join(f"{r} [{c}]" for r, c in bad)
            print(f"    {fn_name}")
            print(f"        {rel_path} -> {offenders}")
    print()

    # --- exit status: non-zero on ANY honesty violation -------------------
    # This is what lets CI fail the build. A clean suite (every command LIVE
    # or GENUINE, every test honest, no stale override pins) returns 0; any
    # HANDROLLED/REVIEW/UNKNOWN command, any dishonest test, or any rotted
    # override pin returns 1.
    failures: list[str] = []
    for cls in ("HANDROLLED", "REVIEW", "UNKNOWN"):
        n = len(by_class.get(cls, []))
        if n:
            failures.append(f"{n} {cls} command(s): {', '.join(sorted(by_class[cls]))}")
    if grand_dishonest:
        failures.append(f"{grand_dishonest} dishonest test(s)")
    if override_rot:
        failures.append(
            "stale override-set pin(s) backing no handler: "
            + ", ".join(override_rot)
        )

    if failures:
        print("=" * 78)
        print("AUDIT FAILED")
        print("=" * 78)
        for f in failures:
            print(f"  - {f}")
        print()
        return 1

    print("=" * 78)
    print("AUDIT PASSED  (every command LIVE/GENUINE, every test honest)")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
