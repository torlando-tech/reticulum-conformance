#!/usr/bin/env python3
"""Authoritative SUT-bridge command-gap report.

Computes the set of bridge commands the test suite actually invokes
(every ``.execute("<literal>", ...)`` first-arg string constant found by
AST-walking ``tests/`` including the per-dir conftests) and diffs it
against the dispatch arms of a Kotlin bridge (every ``"name" ->`` arm in
the bridge's .kt files).

The ``commands=[...]`` lists on @conformance_case decorators are NOT used:
they carry prefix-stripped case names (``poll_path`` for ``wire_poll_path``,
per tools/check_conformance_decorated.py's normalization), which would
produce phantom gaps. The ``.execute()`` literals are the wire truth.

Usage:
    python3 tools/kotlin_gap.py [--kt-dir ../reticulum-kt] [--list]

Exit code 0 when no commands are missing, 1 otherwise — usable as a CI
gate once the surface is complete.
"""

import argparse
import ast
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Files whose .execute() calls define the required surface. tests/ covers
# the per-dir conftest helpers (tests/wire/conftest.py _WirePeer wrappers,
# tests/behavioral/conftest.py Instance methods); conformance.py and
# bridge_client.py at the root contain no test-facing execute literals of
# their own but are included defensively.
SCAN_DIRS = ["tests"]
SCAN_FILES = ["conformance.py", "bridge_client.py"]

# A `when` arm may carry MULTIPLE comma-separated literals before `->`
# (e.g. `"wire_link_request", "wire_link_request_large" -> {`). Match the whole
# literal group immediately preceding `->`, then pull every literal out of it,
# so a multi-literal arm counts all its commands (the old single-literal regex
# only saw the last one, producing a phantom "missing" for the others).
KT_ARM_RE = re.compile(r'((?:"[a-z][a-z0-9_]*"\s*,\s*)*"[a-z][a-z0-9_]*")\s*->')
KT_LITERAL_RE = re.compile(r'"([a-z][a-z0-9_]*)"')


def suite_commands():
    """All string-literal first args of any .execute(...) call under tests/."""
    cmds = set()
    paths = []
    for d in SCAN_DIRS:
        for dirpath, _dirnames, filenames in os.walk(os.path.join(ROOT, d)):
            if "__pycache__" in dirpath:
                continue
            paths.extend(
                os.path.join(dirpath, f) for f in filenames if f.endswith(".py")
            )
    paths.extend(
        os.path.join(ROOT, f)
        for f in SCAN_FILES
        if os.path.exists(os.path.join(ROOT, f))
    )
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            try:
                tree = ast.parse(fh.read(), filename=path)
            except SyntaxError as exc:  # pragma: no cover - broken test file
                print(f"WARN: cannot parse {path}: {exc}", file=sys.stderr)
                continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                cmds.add(node.args[0].value)
    return cmds


def kotlin_commands(kt_dir):
    """All when-arm command literals in the Kotlin bridge sources."""
    src_dir = os.path.join(kt_dir, "conformance-bridge", "src", "main", "kotlin")
    if not os.path.isdir(src_dir):
        sys.exit(f"ERROR: kotlin bridge source dir not found: {src_dir}")
    cmds = set()
    for dirpath, _dirnames, filenames in os.walk(src_dir):
        for f in filenames:
            if not f.endswith(".kt"):
                continue
            with open(os.path.join(dirpath, f), "r", encoding="utf-8") as fh:
                text = fh.read()
            for group in KT_ARM_RE.findall(text):
                cmds.update(KT_LITERAL_RE.findall(group))
    return cmds


# Commands the suite invokes that reticulum-kt CANNOT implement without a
# feature it genuinely lacks — not a porting oversight. Each is mapped to the
# reticulum-kt# slug under which its tests are keyed-xfailed, so the gap is
# DOCUMENTED here rather than silently tolerated. The CI gate fails only on
# UNEXPECTED gaps (a newly-invoked command with no dispatch arm); an allowlisted
# command stays reported but does not fail the gate.
#   - config_parse_interface: kotlin has no ConfigObj INI parser /
#     Reticulum._synthesize_interface (reticulum-kt#config-ini-parser).
#   - wire_mgmt_destinations: kotlin has no probe-responder / remote-management
#     destination registration (reticulum-kt#kotlin-no-probe-remote-mgmt).
#   - wire_send_opportunistic / wire_opportunistic_poll: the kotlin conformance
#     bridge has no opportunistic SINGLE-destination send + receive-proof
#     observability commands (the reference-only opportunistic-delivery harness).
#     The tests that use them already skip/xfail on kotlin
#     (tests/wire/test_opportunistic_proof.py), so this only documents the
#     command-surface gap (reticulum-kt#wire-opportunistic-send).
KNOWN_UNIMPLEMENTED = {
    "config_parse_interface": "reticulum-kt#config-ini-parser",
    "wire_mgmt_destinations": "reticulum-kt#kotlin-no-probe-remote-mgmt",
    "wire_send_opportunistic": "reticulum-kt#wire-opportunistic-send",
    "wire_opportunistic_poll": "reticulum-kt#wire-opportunistic-send",
}


def family(cmd):
    for prefix in ("behavioral_", "wire_", "discovery_", "destination_",
                   "identity_", "packet_", "announce_", "interface_",
                   "lxmf_", "rns_", "config_", "token_", "ratchet_"):
        if cmd.startswith(prefix):
            return prefix.rstrip("_")
    return "(other)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kt-dir", default=os.path.join(ROOT, "..", "reticulum-kt"))
    ap.add_argument("--list", action="store_true",
                    help="print every missing command, not just counts")
    args = ap.parse_args()

    used = suite_commands()
    have = kotlin_commands(os.path.abspath(args.kt_dir))
    missing = sorted(used - have)

    allowlisted = [c for c in missing if c in KNOWN_UNIMPLEMENTED]
    unexpected = [c for c in missing if c not in KNOWN_UNIMPLEMENTED]

    by_family = defaultdict(list)
    for c in unexpected:
        by_family[family(c)].append(c)

    print(f"suite-invoked commands     : {len(used)}")
    print(f"kotlin dispatch arms       : {len(have)}")
    print(f"missing from kotlin        : {len(missing)}")
    print(f"  intentionally unimplemented (allowlisted): {len(allowlisted)}")
    print(f"  UNEXPECTED (gate-failing) : {len(unexpected)}")
    print()
    if allowlisted:
        print("Intentionally unimplemented (documented architectural gaps):")
        for c in allowlisted:
            print(f"      {c:28s} {KNOWN_UNIMPLEMENTED[c]}")
        print()
    for fam in sorted(by_family, key=lambda f: -len(by_family[f])):
        print(f"  {fam:12s} {len(by_family[fam]):4d}")
        if args.list:
            for c in by_family[fam]:
                print(f"      {c}")
    # Exit non-zero ONLY for unexpected gaps; allowlisted absences are documented
    # and do not fail the gate.
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
