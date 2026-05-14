#!/usr/bin/env python3
"""Generate TESTS.md from @conformance_case decorators.

Walks tests/ via pytest collection, reads __conformance__ off each test
function and __category_title__ / __category_order__ off the containing
module, groups by category, numbers per-category (1.1, 1.2, ..., 2.1, ...),
and writes TESTS.md at the repo root.

Run: python tools/generate_tests_md.py
     python tools/generate_tests_md.py --stdout
     python tools/generate_tests_md.py --output some/other.md

Categorization rules:
  * A module without __category_title__ is skipped entirely (warning).
  * A test without @conformance_case is skipped silently — the drift guard
    (tools/check_conformance_decorated.py) is responsible for catching that.
  * Category order: __category_order__ asc, then title alphabetical.
  * Within a category, tests render in pytest collection order (source order).

The intent is for this file to be regeneration output that you can commit
or not at your discretion — the drift guard does not depend on a checked-in
copy. Run the generator manually when you want a fresh snapshot.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from collections import defaultdict
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "TESTS.md"


class _CollectPlugin:
    """Pytest plugin that captures the collection result without executing tests."""

    def __init__(self):
        self.items: list = []

    def pytest_collection_modifyitems(self, items):
        self.items.extend(items)


def collect_items(*, tests_dir: Path | None = None):
    """Run `pytest --collect-only` and return the collected items.

    Stdout from pytest is suppressed; collection failures propagate via the
    exit code (we exit the process on hard failure rather than returning a
    partial list — silent partial-render is worse than a loud abort).
    """
    plugin = _CollectPlugin()
    args = [
        "--collect-only",
        "-q",
        "-p", "no:cacheprovider",
        str(tests_dir or (REPO_ROOT / "tests")),
    ]
    with contextlib.redirect_stdout(io.StringIO()):
        rc = pytest.main(args, plugins=[plugin])
    if rc not in (pytest.ExitCode.OK, pytest.ExitCode.NO_TESTS_COLLECTED):
        print(f"pytest collection failed (exit {rc})", file=sys.stderr)
        sys.exit(int(rc))
    return plugin.items


def _plural(n: int, noun: str) -> str:
    """Render `n noun` with naive English pluralisation (`s` suffix). Used only
    for the test-count parenthetical, so naive is fine."""
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _categorize(items):
    """Group decorated items by (order, title) → per-file rows.

    Returns: [(title, description_md_or_None,
               [(rel_path, [(fn_name, case), ...]), ...]), ...]

    Multiple test files can share a `__category_title__` — each contributes
    its own sub-section. The optional `__category_description__` module
    constant from any one file in the category seeds the section blurb
    (first non-None wins, in pytest collection order).
    """
    by_category: dict = defaultdict(lambda: defaultdict(list))
    descriptions: dict[tuple, str | None] = {}
    seen_fns: set[int] = set()

    for item in items:
        fn = getattr(item, "function", None)
        if fn is None or id(fn) in seen_fns:
            continue
        case = getattr(fn, "__conformance__", None)
        if case is None:
            continue
        module = item.module
        title = getattr(module, "__category_title__", None)
        if title is None:
            continue
        seen_fns.add(id(fn))

        order = getattr(module, "__category_order__", 10_000)
        rel_path = Path(module.__file__).resolve().relative_to(REPO_ROOT).as_posix()
        by_category[(order, title)][rel_path].append((fn.__name__, case))
        cat_key = (order, title)
        if descriptions.get(cat_key) is None:
            descriptions[cat_key] = getattr(module, "__category_description__", None)

    sorted_keys = sorted(by_category.keys(), key=lambda k: (k[0], k[1].lower()))
    return [
        (
            title,
            descriptions.get((order, title)),
            sorted(by_category[(order, title)].items(), key=lambda p: p[0]),
        )
        for (order, title) in sorted_keys
    ]


def render(items) -> str:
    categories = _categorize(items)

    out: list[str] = []
    out.append("# Conformance Test Cases")
    out.append("")

    for cat_idx, (title, description_md, files) in enumerate(categories, start=1):
        total_in_cat = sum(len(rows) for _, rows in files)
        out.append(f"## {cat_idx}. {title} ({_plural(total_in_cat, 'test')})")
        out.append("")
        if description_md and description_md.strip():
            out.append(description_md.strip())
            out.append("")

        multi_file = len(files) > 1
        if not multi_file:
            rel_path, _ = files[0]
            out.append(f"**File:** `{rel_path}`")
            out.append("")

        sub_idx = 0  # numbering continues across files within a category
        for rel_path, rows in files:
            if multi_file:
                out.append(f"### `{rel_path}` ({_plural(len(rows), 'test')})")
                out.append("")
            out.append("| # | Test | Commands Used | What It Verifies |")
            out.append("|---|------|--------------|-----------------|")
            for fn_name, case in rows:
                sub_idx += 1
                cmds = (", ".join(f"`{c}`" for c in case.commands)
                        if case.commands else "—")
                out.append(
                    f"| {cat_idx}.{sub_idx} | `{fn_name}` | {cmds} | {case.verifies} |"
                )
            out.append("")

    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="write to stdout instead of TESTS.md",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"output path (default: {DEFAULT_OUTPUT.relative_to(REPO_ROOT)})",
    )
    args = parser.parse_args()

    items = collect_items()
    rendered = render(items)

    if args.stdout:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered)
        # Count UNIQUE decorated functions (dedupe parametrize variants by
        # function identity) so this matches the number of rows we actually
        # rendered, not pytest's collection-item count.
        seen_fns: set[int] = set()
        decorated = 0
        for item in items:
            fn = getattr(item, "function", None)
            if fn is None or id(fn) in seen_fns:
                continue
            seen_fns.add(id(fn))
            if hasattr(fn, "__conformance__"):
                decorated += 1
        print(
            f"Wrote {decorated} decorated tests ({len(items)} collected items) "
            f"to {args.output.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
