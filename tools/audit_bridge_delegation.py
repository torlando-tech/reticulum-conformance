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

  DEAD       Defined but shadowed by a later def of the same name, or
             registered in no COMMANDS dict. Dead weight, not callable.

A test is DISHONEST if any command in its @conformance_case(commands=...) is
HANDROLLED (or REVIEW). Wire-test commands use _WirePeer method names; those
resolve to wire_* commands, which are all LIVE.

Run:  python tools/audit_bridge_delegation.py
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
KDF_PROTOCOL_REVIEW = {
    "cmd_link_derive_key",     # salt = link_id, context = None, len by mode — RNS.Link.
    "cmd_ifac_derive_key",     # salt = IFAC_SALT — RNS interface authentication.
    "cmd_ratchet_derive_key",  # salt = identity_hash — RNS ratchet KDF.
}

# Handlers that hand-roll a composite by applying a real primitive and then
# slicing a protocol-specific portion out of the result — e.g. IFAC is "the
# last N bytes of the Ed25519 signature of the packet". The math is genuine,
# the "take last N bytes" rule is RNS interface logic. A lone slice of a
# primitive's output is too noisy a signal to detect by AST without false
# positives, so these are pinned by hand.
HEURISTIC_MISS_HANDROLLED = {
    "cmd_ifac_compute",  # ifac = ed25519_sign(packet)[-ifac_size:]
    "cmd_ifac_verify",   # recomputes the same and compares
}


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


def classify_handler(func: ast.FunctionDef) -> tuple[str, set[str], set[str]]:
    """Return (classification, evidence-signals, called-cmd-handlers).

    Pure AST analysis of the function body — see the module docstring for what
    each classification means. Precedence: LIVE > HANDROLLED > GENUINE, then
    the KDF_PROTOCOL_REVIEW override demotes a few GENUINE-looking handlers.
    The called-cmd-handlers set feeds the transitive pass in parse_module: a
    handler that calls a handrolled handler is itself handrolled.
    """
    signals: set[str] = set()
    called_cmds: set[str] = set()
    is_hash_primitive = func.name in HASH_PRIMITIVES

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
        if isinstance(node, ast.Call):
            callee = _dotted(node.func)
            if callee in LIVE_CALLS:
                signals.add("live:get_rns")
            if callee in ("struct.pack", "struct.unpack"):
                signals.add("asm:struct")
            if callee in ("umsgpack.packb", "umsgpack.unpackb"):
                signals.add("asm:umsgpack")
            if callee and callee.startswith("hashlib.") and not is_hash_primitive:
                signals.add("asm:hashlib")
            if callee and callee.startswith("cmd_"):
                called_cmds.add(callee)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
                signals.add("asm:replace")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            if any(n.split(".")[0] in ("RNS", "LXMF") for n in names):
                signals.add("live:import")
        elif isinstance(node, ast.Name) and node.id in LIVE_GLOBALS:
            signals.add("live:global")
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Slice)
            and isinstance(node.value, ast.Name)
            and node.value.id in hex_locals
        ):
            signals.add("asm:fieldslice")
        elif isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.LShift, ast.RShift, ast.BitOr, ast.BitAnd)):
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

    if any(s.startswith("live:") for s in signals):
        return "LIVE", signals, called_cmds
    if func.name in HEURISTIC_MISS_HANDROLLED:
        return "HANDROLLED", signals | {"pinned:primitive-then-slice"}, called_cmds
    if any(s.startswith("asm:") for s in signals):
        return "HANDROLLED", signals, called_cmds
    if func.name in KDF_PROTOCOL_REVIEW:
        return "REVIEW", signals | {"pinned:kdf-params"}, called_cmds
    return "GENUINE", signals, called_cmds


def parse_module(path: Path):
    """Parse one command-module file. Returns (handlers, registry, dead).

    handlers: {funcname: (classification, signals)} — last def of each name wins
              (Python semantics), so a shadowed earlier def never appears here.
    registry: {command_name: funcname} from the module's *_COMMANDS dict.
    dead:     [funcname] — functions shadowed by a later def of the same name.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    defs: dict[str, list[ast.FunctionDef]] = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("cmd_"):
            defs[node.name].append(node)

    handlers: dict[str, tuple[str, set[str]]] = {}
    called: dict[str, set[str]] = {}
    for name, nodes in defs.items():
        classification, signals, called_cmds = classify_handler(nodes[-1])
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
    return handlers, registry, dead


def build_command_index():
    """Classify every registered bridge command across all command modules.

    Returns (commands, dead_handlers):
      commands: {command_name: (classification, funcname, module, signals)}
      dead_handlers: {module: [funcname, ...]}
    """
    commands: dict[str, tuple] = {}
    dead_handlers: dict[str, list[str]] = {}
    for filename in COMMAND_MODULES:
        path = REPO_ROOT / "reference" / filename
        handlers, registry, dead = parse_module(path)
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
    return commands, dead_handlers


def resolve_command(
    name: str, commands: dict, test_relpath: str, live_backed_dirs: tuple[str, ...]
) -> tuple[str, str]:
    """Resolve a @conformance_case command token to (classification, resolved).

    Tests under tests/ (root) name bridge commands directly. Tests under
    tests/wire, tests/lxmf and tests/behavioral name _*Peer methods, which are
    thin wrappers over command modules verified all-LIVE at startup — so a
    token there that doesn't resolve directly is a peer helper over LIVE
    commands, not dishonesty. Anything else is genuinely UNKNOWN (loud).
    """
    if name in commands:
        return commands[name][0], name
    if f"wire_{name}" in commands:
        return commands[f"wire_{name}"][0], f"wire_{name}"
    if any(test_relpath.startswith(d) for d in live_backed_dirs):
        return "LIVE", f"{name} (peer method over LIVE commands)"
    return "UNKNOWN", name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--verbose", action="store_true",
        help="print per-command classification with AST evidence",
    )
    args = parser.parse_args()

    commands, dead_handlers = build_command_index()

    # The peer-method shortcut in resolve_command is only safe for test dirs
    # whose backing command module contributes nothing but LIVE commands.
    # Verify that invariant rather than assuming it.
    live_backed_dirs: list[str] = []
    for filename, test_dir in (
        ("wire_tcp.py", "tests/wire/"),
        ("behavioral_transport.py", "tests/behavioral/"),
    ):
        module_classes = {
            cls for _n, (cls, _fn, mod, _sig) in commands.items() if mod == filename
        }
        dishonest = module_classes & {"HANDROLLED", "REVIEW", "DEAD"}
        if module_classes and not dishonest:
            live_backed_dirs.append(test_dir)
        else:
            print(f"  WARNING: {filename} contributes {sorted(dishonest)} commands "
                  f"— {test_dir} tokens will fall through to UNKNOWN", file=sys.stderr)
    live_backed_dirs = tuple(live_backed_dirs)

    by_class: dict[str, list[str]] = defaultdict(list)
    for name, (classification, *_rest) in commands.items():
        by_class[classification].append(name)

    print("=" * 78)
    print("BRIDGE COMMAND DELEGATION AUDIT")
    print("=" * 78)
    print()
    total = len(commands)
    for cls in ("GENUINE", "LIVE", "HANDROLLED", "REVIEW", "DEAD", "UNKNOWN"):
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
    print("  A test is DISHONEST if any command it uses is HANDROLLED/REVIEW —")
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
                    resolve_command(c, commands, rel_path, live_backed_dirs)
                    for c in case.commands
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
