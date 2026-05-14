#!/usr/bin/env python3
"""CI drift guard: every collected test must carry @conformance_case.

Exits 1 if any test in tests/ lacks the decorator, listing the offenders.
Reuses the same pytest collection logic as the generator (tools/generate_tests_md.py)
so the two never disagree on which tests are in scope.

Intended to run in CI before the conformance suite proper, so a contributor
adding a test forgets the decorator immediately rather than discovering the
omission later when TESTS.md is regenerated.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from generate_tests_md import collect_items  # noqa: E402


def main() -> int:
    items = collect_items()
    seen_fns: set[int] = set()
    missing: list[str] = []

    for item in items:
        fn = getattr(item, "function", None)
        if fn is None or id(fn) in seen_fns:
            continue
        seen_fns.add(id(fn))
        if not hasattr(fn, "__conformance__"):
            missing.append(item.nodeid)

    if missing:
        print(
            f"FAIL: {len(missing)} test(s) missing @conformance_case "
            f"(see conformance.py for usage):",
            file=sys.stderr,
        )
        for nodeid in missing:
            print(f"  - {nodeid}", file=sys.stderr)
        return 1

    print(f"OK: all {len(seen_fns)} collected tests are decorated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
