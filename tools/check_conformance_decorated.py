#!/usr/bin/env python3
"""CI drift guard: keep @conformance_case decorators honest.

Two independent checks run; a violation in EITHER yields a non-zero exit, so
this is safe to wire into CI ahead of the conformance suite proper.

1. PRESENCE — every test collected under ``tests/`` must carry a
   ``@conformance_case`` decorator. A contributor who forgets it is caught
   here, rather than being silently dropped from TESTS.md by the generator.

2. COMMANDS SUPERSET (N-M6 / N-H6) — the decorator's declared
   ``commands=[...]`` list must be a SUPERSET of the bridge commands the test
   actually exercises. That list is rendered into the public "Commands Used"
   column of TESTS.md / TESTS.html and feeds the delegation-honesty math, so a
   stale list is a machine-readable false claim. Previously the guard only
   checked that the decorator *existed* (check_conformance_decorated.py:34 in
   the old version); the declared list was never validated against the body,
   and a cross-check found >=4 stale lists (e.g. ``test_bz2_compress`` omits
   ``bz2_decompress``; ``test_hop_increment*`` omit ``announce_build``;
   ``test_identity_recall_after_announce`` omits ``poll_path``;
   ``test_path_response_reuses_cached_announce`` omits ``read_path_entry``).

   How "used" is recovered (the documented mechanism — pure static AST, no
   bridge process required):

     * ``<obj>.execute("<cmd>", ...)``  -> ``<cmd>``. Primitive (byte-level)
       tests call the bridge directly; the command is the first positional
       string literal, however deeply the call is nested.

     * ``<obj>.<method>(...)``          -> ``<method>``, but ONLY when
       ``<method>`` is a known bridge command (see VOCABULARY). Wire and
       behavioral tests drive the bridge through thin wrapper objects
       (``_WirePeer`` in tests/wire/conftest.py, the behavioral harness in
       tests/behavioral/conftest.py) whose method names ARE the command
       aliases the decorators declare — e.g. ``client.poll_path(...)`` is the
       ``poll_path`` command, ``inst.inject(...)`` is ``inject``. The
       VOCABULARY gate is what keeps ordinary method calls such as ``.hex()``,
       ``.lower()``, ``.startswith()`` from being mistaken for bridge verbs.

     * bare ``helper(...)`` calls       -> the tool recurses into helper
       functions defined in the test's module or imported from a sibling
       suite module (e.g. tests/behavioral/packet_builders.py) and folds in
       whatever commands THEY drive. This is how indirect commands like
       ``announce_build`` — fired inside ``build_announce_from_destination``,
       never named in the test body — are attributed to the calling test.

   Command names are normalized by stripping the ``wire_`` / ``behavioral_``
   namespace prefix, so the raw verb ``wire_poll_path`` and the wrapper method
   ``poll_path`` (which is also how the decorator declares it) compare equal.

   VOCABULARY (used solely to decide whether a *method name* denotes a bridge
   command) is the union, after normalization, of:
     * every ``.execute("<literal>")`` string found anywhere in the suite —
       the real, exhaustive client-side command surface, including the
       wrapper bodies in the conftests; and
     * every command declared in any ``@conformance_case`` in the suite.

SCOPE — ``integration/`` is deliberately EXCLUDED from both checks; see
INTEGRATION_EXCLUSION_RATIONALE below.

Reuses the same pytest collection logic as the generator
(tools/generate_tests_md.py) so the two never disagree on which tests are in
scope.
"""

from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from generate_tests_md import collect_items  # noqa: E402


# --- integration/ scope decision (N-M6 asks us to decide and document) ------
#
# integration/ is EXCLUDED from the @conformance_case requirement and the
# commands-superset check, for three reasons:
#
#   1. The public catalog generator (tools/generate_tests_md.py) only walks
#      tests/, so a decorator on an integration test would never render into
#      TESTS.md / TESTS.html — it would be dead metadata.
#
#   2. Integration tests don't drive the bridge `.execute` command surface at
#      all. They stand up REAL in-process Reticulum instances over pipe /
#      three-node sessions (`pytest integration/ --python-only`) and assert on
#      live RNS behavior. The `commands=[...]` concept (bridge protocol verbs)
#      has no meaning there, so a superset check would be vacuous.
#
#   3. Integration has its own enforcement axis: a dedicated
#      `integration/ --python-only` CI job with a min-passed guard (N-H3).
#
# This is enforced, not merely assumed: collect_items() scopes to tests/ (so
# integration tests are never required to be decorated), and _stray_integration
# _decorators() below FAILS the guard if a @conformance_case ever appears under
# integration/ — that would be a scope mistake (silently-ignored metadata), so
# we surface it loudly rather than let it rot.
INTEGRATION_EXCLUSION_RATIONALE = (
    "integration/ tests drive real in-process RNS (pipe / three-node "
    "sessions), not the bridge .execute command surface, and are not rendered "
    "into TESTS.md; they are covered by the integration --python-only CI job."
)

# Bridge command namespace prefixes. Wire/behavioral commands are registered
# under these prefixes on the bridge, but the wrapper methods and the
# decorators both use the bare alias — normalizing makes them comparable.
_NAMESPACE_PREFIXES = ("wire_", "behavioral_")


def _normalize(cmd: str) -> str:
    """Strip a single bridge-namespace prefix so wrapper aliases and raw verbs
    compare equal (``wire_poll_path`` -> ``poll_path``; ``poll_path`` -> same).
    """
    for prefix in _NAMESPACE_PREFIXES:
        if cmd.startswith(prefix):
            return cmd[len(prefix):]
    return cmd


# --- AST helpers (cached per file) ------------------------------------------

_parse_cache: dict[Path, ast.Module | None] = {}
_helpers_cache: dict[Path, dict[str, ast.AST]] = {}
_imports_cache: dict[Path, dict[str, tuple[Path, str]]] = {}


def _parse(path) -> ast.Module | None:
    path = Path(path)
    if path not in _parse_cache:
        try:
            _parse_cache[path] = ast.parse(path.read_text(), filename=str(path))
        except (OSError, SyntaxError):
            _parse_cache[path] = None
    return _parse_cache[path]


def _resolve_module_file(modname: str) -> Path | None:
    """Map a dotted absolute module name to a file inside the repo, or None."""
    rel = modname.replace(".", "/")
    for cand in (REPO_ROOT / f"{rel}.py", REPO_ROOT / rel / "__init__.py"):
        if cand.exists():
            return cand
    return None


def _module_helpers(path) -> dict[str, ast.AST]:
    """Module-level function definitions keyed by name."""
    path = Path(path)
    if path not in _helpers_cache:
        tree = _parse(path)
        out: dict[str, ast.AST] = {}
        if tree is not None:
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.setdefault(node.name, node)
        _helpers_cache[path] = out
    return _helpers_cache[path]


def _module_imports(path) -> dict[str, tuple[Path, str]]:
    """`from <repo-module> import <name>` bindings: local-name -> (file, orig).

    Only absolute imports that resolve to a file inside the repo are kept, so
    stdlib / third-party imports are never followed.
    """
    path = Path(path)
    if path not in _imports_cache:
        tree = _parse(path)
        out: dict[str, tuple[Path, str]] = {}
        if tree is not None:
            for node in tree.body:
                if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    target = _resolve_module_file(node.module)
                    if target is not None:
                        for alias in node.names:
                            local = alias.asname or alias.name
                            out[local] = (target, alias.name)
        _imports_cache[path] = out
    return _imports_cache[path]


def _resolve_helper(name: str, module_path) -> tuple[Path, ast.AST] | None:
    """Resolve a bare-name call to a helper function (module-local or imported
    from a sibling suite module), returning (file, func_node) or None."""
    helpers = _module_helpers(module_path)
    if name in helpers:
        return Path(module_path), helpers[name]
    imports = _module_imports(module_path)
    if name in imports:
        target_path, orig = imports[name]
        target_helpers = _module_helpers(target_path)
        if orig in target_helpers:
            return target_path, target_helpers[orig]
    return None


def _execute_literal(node: ast.AST) -> str | None:
    """If `node` is `<x>.execute("<literal>", ...)`, return the literal."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
        and node.args
    ):
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _find_func_node(module_path, fn_name: str) -> ast.AST | None:
    """Locate the module-level def named `fn_name`, preferring a decorated one."""
    tree = _parse(module_path)
    if tree is None:
        return None
    candidates = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn_name
    ]
    if not candidates:
        return None
    for node in candidates:
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Name)
                and dec.func.id == "conformance_case"
            ):
                return node
    return candidates[0]


def _used_commands(func_node, module_path, vocab: set[str], seen: set) -> set[str]:
    """Set of normalized bridge commands a function exercises, following bare
    helper calls into sibling suite modules (with a cycle guard)."""
    used: set[str] = set()
    for stmt in func_node.body:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute):
                literal = _execute_literal(node)
                if literal is not None:
                    used.add(_normalize(literal))
                else:
                    method = _normalize(func.attr)
                    if method in vocab:
                        used.add(method)
            elif isinstance(func, ast.Name):
                target = _resolve_helper(func.id, module_path)
                if target is not None:
                    target_path, target_node = target
                    key = (str(target_path), target_node.name)
                    if key not in seen:
                        seen.add(key)
                        used |= _used_commands(target_node, target_path, vocab, seen)
    return used


def _iter_repo_py_files():
    for path in REPO_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or ".git" in path.parts:
            continue
        yield path


def _build_vocabulary(declared_all: set[str]) -> set[str]:
    """Every command the suite could legitimately name: all `.execute()`
    literals found anywhere (the real client-side surface, including conftest
    wrappers) plus everything any decorator declares — all normalized."""
    vocab = set(declared_all)
    for path in _iter_repo_py_files():
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            literal = _execute_literal(node)
            if literal is not None:
                vocab.add(_normalize(literal))
    return vocab


def _stray_integration_decorators() -> list[str]:
    """@conformance_case occurrences under integration/ (a scope mistake)."""
    integration = REPO_ROOT / "integration"
    if not integration.exists():
        return []
    stray: list[str] = []
    for path in integration.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    func = dec.func if isinstance(dec, ast.Call) else dec
                    if isinstance(func, ast.Name) and func.id == "conformance_case":
                        rel = path.resolve().relative_to(REPO_ROOT).as_posix()
                        stray.append(f"{rel}::{node.name}")
    return stray


def _relpath(path) -> str:
    try:
        return Path(path).resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def main() -> int:
    items = collect_items()  # tests/ scope only — integration/ excluded by design

    seen_fns: set[int] = set()
    missing: list[str] = []
    decorated: list[tuple] = []  # (fn, case)

    for item in items:
        fn = getattr(item, "function", None)
        if fn is None or id(fn) in seen_fns:
            continue
        seen_fns.add(id(fn))
        case = getattr(fn, "__conformance__", None)
        if case is None:
            missing.append(item.nodeid)
        else:
            decorated.append((fn, case))

    # Build the command vocabulary once from the whole suite.
    declared_all: set[str] = set()
    for _fn, case in decorated:
        declared_all.update(_normalize(c) for c in case.commands)
    vocab = _build_vocabulary(declared_all)

    superset_violations: list[tuple[str, list[str], list[str]]] = []
    unanalyzable: list[str] = []

    for fn, case in decorated:
        declared = {_normalize(c) for c in case.commands}
        src = inspect.getsourcefile(fn) or inspect.getfile(fn)
        node = _find_func_node(src, fn.__name__) if src else None
        if node is None:
            unanalyzable.append(f"{_relpath(src) if src else '?'}::{fn.__name__}")
            continue
        used = _used_commands(node, src, vocab, set())
        undeclared = used - declared
        if undeclared:
            label = f"{_relpath(src)}::{fn.__name__}"
            superset_violations.append(
                (label, sorted(undeclared), sorted(declared))
            )

    stray = _stray_integration_decorators()

    rc = 0

    if missing:
        rc = 1
        print(
            f"FAIL: {len(missing)} test(s) missing @conformance_case "
            f"(see conformance.py for usage):",
            file=sys.stderr,
        )
        for nodeid in missing:
            print(f"  - {nodeid}", file=sys.stderr)

    if superset_violations:
        rc = 1
        print(
            f"\nFAIL: {len(superset_violations)} test(s) declare a "
            f"commands=[...] list that is NOT a superset of the bridge "
            f"commands they actually call (N-M6). The declared list renders "
            f"into the public TESTS.md 'Commands Used' column, so it must be "
            f"complete:",
            file=sys.stderr,
        )
        for label, undeclared, declared in superset_violations:
            print(f"  - {label}", file=sys.stderr)
            print(f"      uses but does NOT declare: {undeclared}", file=sys.stderr)
            print(f"      currently declares:        {declared}", file=sys.stderr)

    if stray:
        rc = 1
        print(
            f"\nFAIL: {len(stray)} @conformance_case decorator(s) under "
            f"integration/ — that directory is out of scope and the metadata "
            f"is silently ignored. Move the test under tests/ or drop the "
            f"decorator. ({INTEGRATION_EXCLUSION_RATIONALE})",
            file=sys.stderr,
        )
        for label in stray:
            print(f"  - {label}", file=sys.stderr)

    if unanalyzable:
        # Non-fatal: we could not statically locate the function body (e.g. a
        # dynamically generated test). Report it so the gap is visible rather
        # than silently skipping the superset check.
        print(
            f"\nWARNING: {len(unanalyzable)} decorated test(s) could not be "
            f"statically analyzed for command usage (superset check skipped):",
            file=sys.stderr,
        )
        for label in unanalyzable:
            print(f"  - {label}", file=sys.stderr)

    if rc == 0:
        print(
            f"OK: all {len(decorated)} collected tests are decorated and their "
            f"commands=[...] lists are supersets of the commands they call.\n"
            f"(integration/ excluded by design: {INTEGRATION_EXCLUSION_RATIONALE})"
        )
    return rc


if __name__ == "__main__":
    sys.exit(main())
