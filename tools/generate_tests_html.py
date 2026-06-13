#!/usr/bin/env python3
"""Generate TESTS.html from @conformance_case decorators.

Sibling to tools/generate_tests_md.py. Produces a self-contained single-file
HTML inventory that's easier to browse than the markdown:

  * Sticky TOC sidebar
  * Live text filter that hides non-matching rows and empty categories
  * Each row is a <details> accordion — click to expand and read:
      - the test method source (open by default),
      - the source of every pytest fixture the test takes as a parameter
        (sut, reference, wire_3peer, …) — resolved via the same fixture
        registry pytest itself uses,
      - the "module context" (everything else in the file: docstring,
        imports, module-level constants, helper functions) with all
        @conformance_case-decorated tests stripped out so the preamble
        reads cleanly.
  * Per-test anchor links; hashchange auto-opens enclosing accordions
  * Light/dark mode via prefers-color-scheme; Pygments syntax highlighting
    for both palettes

Source extraction is deterministic. `inspect.getsource(fn)` reads the
actual on-disk source. The AST locates and removes @conformance_case-
decorated FunctionDefs from the module preamble. Fixtures resolve via
`item._fixtureinfo.name2fixturedefs` — the same path `pytest --fixtures`
uses. No copy-paste, no LLM involvement; regenerate when anything
changes and the file updates in lockstep.

Run: python tools/generate_tests_html.py
     python tools/generate_tests_html.py --stdout
     python tools/generate_tests_html.py --output some/other.html
"""

from __future__ import annotations

import argparse
import ast
import functools
import html
import inspect
import re
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import PythonLexer

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "TESTS.html"

# Reuse collection from the markdown generator. We do not reuse its
# `_categorize` because the html renderer needs item/fn references for
# fixture resolution; we build a parallel categorization that carries
# the extra references through.
sys.path.insert(0, str(REPO_ROOT / "tools"))
from generate_tests_md import collect_items  # noqa: E402


# ── acronym glossary (renders as <abbr title="…">acronym</abbr> in HTML) ──
#
# Word-boundary matched so compounds like HMAC-SHA256 / AES-256-CBC stay
# untouched (the `(?<![\w-])` / `(?![\w-])` lookarounds reject any acronym
# that's part of a hyphenated identifier). Grow as new categories surface
# new jargon — see `Cat N` chat history for what's been reviewed.
_ABBR_GLOSSARY: dict[str, str] = {
    # crypto
    "IV": "Initialization Vector",
    "HKDF": "HMAC-based Key Derivation Function",
    "ECDH": "Elliptic Curve Diffie-Hellman",
    # framing (HDLC + KISS byte-stuffing protocols)
    "HDLC": "High-Level Data Link Control",
    "KISS": "Keep It Simple, Stupid (TNC framing protocol)",
    "TNC": "Terminal Node Controller (packet-radio modem)",
    "FLAG": "HDLC frame delimiter byte (0x7E)",
    "ESC": "HDLC escape byte (0x7D)",
    "FEND": "Frame END — KISS frame delimiter byte (0xC0)",
    "FESC": "Frame ESCape — KISS escape byte (0xDB)",
    "TFEND": "Transposed FEND (0xDC) — what FEND becomes after escaping",
    "TFESC": "Transposed FESC (0xDD) — what FESC becomes after escaping",
    # link
    "MTU": "Maximum Transmission Unit",
    "RTT": "Round-Trip Time",
}


def _wrap_abbreviations(escaped_text: str) -> str:
    """Wrap each glossary acronym in an `<abbr>` tag with `data-tip` + `aria-label`.

    Deliberately NOT using the `title` attribute — Safari's native title-tooltip
    has a multi-second hover delay, which makes the inventory feel sluggish to
    skim. Instead we render the expansion via a CSS `:hover::after` pseudo
    element keyed off `data-tip`, which is instant. `aria-label` carries the
    expansion for screen readers, so we keep accessibility.

    Input is assumed already HTML-escaped; this function emits tag markup
    directly. We split on existing tags first so we never wrap acronyms that
    happen to live inside another tag's attribute value (e.g. "TNC" inside
    `<abbr data-tip="Keep It Simple, Stupid (TNC framing protocol)">…`).
    Single-pass over the alternation prevents recursive nesting too.
    """
    if not _ABBR_GLOSSARY:
        return escaped_text

    combined = (
        r"(?<![\w-])(?:"
        + "|".join(re.escape(a) for a in _ABBR_GLOSSARY)
        + r")(?![\w-])"
    )

    def _replace(match: re.Match) -> str:
        acronym = match.group(0)
        full = _ABBR_GLOSSARY[acronym]
        full_attr = html.escape(full, quote=True)
        return (
            f'<abbr data-tip="{full_attr}" aria-label="{full_attr}">'
            f"{acronym}</abbr>"
        )

    # Even indices in `parts` are outside-tag text; odd indices are tags
    # (kept verbatim). Acronym wrap only touches even indices.
    parts = re.split(r"(<[^>]+>)", escaped_text)
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(combined, _replace, parts[i])
    return "".join(parts)


def _render_inline_markdown(escaped_text: str) -> str:
    """Convert a small subset of markdown to HTML — `` `inline code` `` →
    `<code>...</code>`, `**bold**` → `<strong>...</strong>`. Input must
    already be html.escape()'d; this only adds known-safe tags.

    Inline code goes first so any bold-like sequences inside backticks
    stay literal (which matches markdown spec).
    """
    text = re.sub(r"`([^`]+?)`", r"<code>\1</code>", escaped_text)
    text = re.sub(r"\*\*([^*]+?)\*\*", r"<strong>\1</strong>", text)
    return text


def _haystack_expansions(verifies: str) -> list[str]:
    """Return acronym expansions that should join the filter haystack
    for a given verifies string — so typing 'initialization vector' finds
    the IV row even though IV isn't spelled out in the prose."""
    out: list[str] = []
    for acronym, full in _ABBR_GLOSSARY.items():
        if re.search(rf'(?<![\w-]){re.escape(acronym)}(?![\w-])', verifies):
            out.append(full)
    return out


# ── pytest built-in fixtures we don't try to dump source for ──────────
_BUILTIN_FIXTURES = frozenset({
    "request", "tmp_path", "tmp_path_factory", "tmpdir", "tmpdir_factory",
    "monkeypatch", "capfd", "capfdbinary", "capsys", "capsysbinary",
    "caplog", "recwarn", "doctest_namespace", "cache", "pytestconfig",
    "record_property", "record_xml_attribute", "record_testsuite_property",
    "testdir", "pytester",
})


# ── Pygments highlighting ─────────────────────────────────────────────


_LEXER = PythonLexer()
_FORMATTER = HtmlFormatter(nowrap=True)


@functools.lru_cache(maxsize=4096)
def _hl(src: str) -> str:
    """Cache Pygments output by exact source. Most fixtures repeat across
    tests, so caching cuts render time noticeably."""
    return highlight(src, _LEXER, _FORMATTER)


def _pygments_css() -> str:
    """Light-mode + dark-mode Pygments CSS, scoped to `.hl` and gated by
    prefers-color-scheme."""
    light = HtmlFormatter(style="default").get_style_defs(".hl")
    dark = HtmlFormatter(style="monokai").get_style_defs(".hl")
    dark_indented = "\n".join("  " + ln for ln in dark.splitlines())
    return (
        f"{light}\n"
        f"@media (prefers-color-scheme: dark) {{\n"
        f"{dark_indented}\n"
        f"}}\n"
    )


# ── source extraction ─────────────────────────────────────────────────


def _extract_def_body(fn) -> str:
    """Return the function's source with leading decorators stripped.

    Caller gets a self-contained `def …:` slab, ready to highlight.
    """
    try:
        raw = inspect.getsource(fn)
    except (OSError, TypeError):
        return "# (source unavailable)"

    raw = textwrap.dedent(raw)
    lines = raw.splitlines()
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("def ") or stripped.startswith("async def "):
            return "\n".join(lines[i:])
    return raw


def _extract_fixture_source(fn) -> str:
    """Return a fixture's full source — including its `@pytest.fixture`
    decorator(s). The decorator clarifies scope/params, so we keep it."""
    try:
        raw = inspect.getsource(fn)
    except (OSError, TypeError):
        return "# (source unavailable)"
    return textwrap.dedent(raw)


def _is_conformance_case_decorator(node: ast.expr) -> bool:
    """True iff `node` is `conformance_case(...)` or bare `conformance_case`."""
    if isinstance(node, ast.Call):
        return _is_conformance_case_decorator(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr == "conformance_case"
    if isinstance(node, ast.Name):
        return node.id == "conformance_case"
    return False


@functools.lru_cache(maxsize=64)
def _module_preamble(file_path: str) -> str:
    """Return the file's contents with every @conformance_case-decorated
    top-level function definition (including its decorators) removed.

    Cached per-file path so a 14-test file is parsed once.
    """
    text = Path(file_path).read_text()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text  # don't fail the whole generator on one weird file

    skip_lines: set[int] = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_conformance_case_decorator(d) for d in node.decorator_list):
            continue
        # Span from the first decorator's lineno through the function's
        # end_lineno (inclusive, 1-indexed).
        start = min(
            (d.lineno for d in node.decorator_list),
            default=node.lineno,
        )
        end = node.end_lineno or node.lineno
        for ln in range(start, end + 1):
            skip_lines.add(ln)

    kept = [
        line for i, line in enumerate(text.splitlines(), start=1)
        if i not in skip_lines
    ]
    # Collapse 3+ consecutive blank lines into 2 — keeps the preamble
    # legible after we punch holes in it.
    collapsed: list[str] = []
    blank_run = 0
    for line in kept:
        if not line.strip():
            blank_run += 1
            if blank_run <= 2:
                collapsed.append(line)
        else:
            blank_run = 0
            collapsed.append(line)
    return "\n".join(collapsed).strip("\n") + "\n"


def _resolve_direct_fixtures(item) -> list[tuple[str, str, str]]:
    """Return [(fixture_name, source, rel_path_of_definition_file), ...]
    for every parameter the test function declares that pytest knows about
    (i.e. excludes built-in fixtures and parametrize values that don't
    appear in the fixture registry).
    """
    fn = item.function
    info = getattr(item, "_fixtureinfo", None)
    if info is None:
        return []
    name2defs = getattr(info, "name2fixturedefs", None) or {}

    out: list[tuple[str, str, str]] = []
    try:
        params = list(inspect.signature(fn).parameters)
    except (ValueError, TypeError):
        return []
    for name in params:
        if name in _BUILTIN_FIXTURES:
            continue
        defs = name2defs.get(name)
        if not defs:
            continue  # parametrize value or unresolved — skip silently
        fdef = defs[-1]
        func = getattr(fdef, "func", None)
        if func is None:
            continue
        # Skip pytest-internal pseudo-fixtures. Directly-parametrized params
        # (e.g. @pytest.mark.parametrize("mode", ...)) appear in the fixture
        # registry backed by `_pytest.python.get_direct_param_fixture_func`.
        # They are not project fixtures, and inspect.getsourcefile resolves
        # them to an absolute install path — rendering them embeds a
        # machine-specific path (`/opt/homebrew/...`, `site-packages/...`)
        # in the committed HTML, making it non-reproducible (N-M15).
        if (getattr(func, "__module__", "") or "").split(".", 1)[0] == "_pytest":
            continue
        try:
            src = _extract_fixture_source(func)
            src_file = inspect.getsourcefile(func) or ""
        except (OSError, TypeError):
            continue
        if not src_file:
            continue
        try:
            rel = Path(src_file).resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            # Source lives outside the repo (pytest plugin, stdlib,
            # site-packages). Skip rather than emit an absolute path: that
            # would embed a machine-specific location and break the
            # reproducibility guarantee this generator is meant to provide
            # (N-M15).
            continue
        out.append((name, src, rel))
    return out


# ── categorization with item references ───────────────────────────────


def _categorize_with_items(items):
    """Like generate_tests_md._categorize but tuples carry (fn_name, case,
    item) so the renderer can resolve fixtures and source per item.

    Returns: [(category_title, description_md_or_None,
               [(rel_path, [(fn_name, case, item), ...]), ...])]

    `description_md_or_None` is the first non-None `__category_description__`
    module-level constant encountered in pytest collection order across all
    files in the category — multi-file categories can set it on any one
    file (convention: put it on the alphabetically-first file).
    Sorted by (__category_order__, lowercased-title); files within a
    category sorted by path; tests within a file in pytest collection order.
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
        module = getattr(item, "module", None)
        title = getattr(module, "__category_title__", None) if module else None
        if title is None:
            continue
        seen_fns.add(id(fn))
        order = getattr(module, "__category_order__", 10_000)
        rel_path = Path(module.__file__).resolve().relative_to(REPO_ROOT).as_posix()
        by_category[(order, title)][rel_path].append((fn.__name__, case, item))
        # First non-None description for this category wins
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


# ── helpers ───────────────────────────────────────────────────────────


def _cmd_chips(commands: tuple[str, ...]) -> str:
    if not commands:
        return '<span class="muted">—</span>'
    return "".join(
        f'<span class="cmd-chip">{html.escape(c)}</span>' for c in commands
    )


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _display_path(p: Path) -> str:
    """Render `p` relative to REPO_ROOT when possible, else its resolved
    absolute form.

    `Path.relative_to(REPO_ROOT)` raises `ValueError` for paths outside the
    repo and for bare-relative paths (a relative path is never relative to an
    absolute one). Resolving first lets bare-relative `--output` values work
    when run from inside the repo, and the fallback keeps a custom out-of-repo
    `--output` from crashing the generator after it has already written the
    file (L16) — important for CI regen-and-diff.
    """
    try:
        return p.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(p.resolve())


# ── CSS / JS ──────────────────────────────────────────────────────────


_CSS_BASE = """
:root {
  --bg: #ffffff;
  --fg: #1a1a1a;
  --muted: #6b7280;
  --border: #e5e7eb;
  --accent: #2563eb;
  --row-hover: #f3f4f6;
  --row-open: #eff6ff;
  --code-bg: #f3f4f6;
  --code-fg: #111827;
  --code-block-bg: #fafafa;
  --sidebar-bg: #f9fafb;
  --section-bg: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1115;
    --fg: #e5e7eb;
    --muted: #9ca3af;
    --border: #2a2e36;
    --accent: #60a5fa;
    --row-hover: #1a1d23;
    --row-open: #1c2332;
    --code-bg: #1a1d23;
    --code-fg: #e5e7eb;
    --code-block-bg: #14171c;
    --sidebar-bg: #14171c;
    --section-bg: #0f1115;
  }
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
}
.layout {
  display: grid;
  grid-template-columns: 280px 1fr;
  min-height: 100vh;
}
@media (max-width: 900px) {
  .layout { grid-template-columns: 1fr; }
  aside.toc { position: static; height: auto; max-height: 40vh; }
}
aside.toc {
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  background: var(--sidebar-bg);
  border-right: 1px solid var(--border);
  padding: 1rem;
}
aside.toc h2 {
  margin: 0 0 0.75rem 0;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
}
aside.toc ol { list-style: none; padding: 0; margin: 0; font-size: 13px; }
aside.toc li { margin: 0.15rem 0; }
aside.toc a {
  color: var(--fg);
  text-decoration: none;
  display: block;
  padding: 0.2rem 0.4rem;
  border-radius: 4px;
}
aside.toc a:hover { background: var(--row-hover); color: var(--accent); }
aside.toc .count {
  color: var(--muted);
  font-variant-numeric: tabular-nums;
  margin-left: 0.4rem;
}
main { padding: 1.5rem 2rem; max-width: 1200px; }
header.page {
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}
header.page h1 { margin: 0 0 0.4rem 0; font-size: 22px; }
header.page .stats { color: var(--muted); font-size: 13px; }
.filter-bar {
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--bg);
  padding: 0.75rem 0;
  margin-bottom: 0.5rem;
  border-bottom: 1px solid var(--border);
}
.filter-bar input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  font-size: 14px;
  background: var(--sidebar-bg);
  color: var(--fg);
  border: 1px solid var(--border);
  border-radius: 6px;
  outline: none;
}
.filter-bar input:focus { border-color: var(--accent); }
.filter-bar .help { color: var(--muted); font-size: 12px; margin-top: 0.25rem; }
.filter-bar .help.hidden { display: none; }
details.category { margin: 0.5rem 0 1.5rem 0; background: var(--section-bg); }
details.category > summary {
  cursor: pointer;
  list-style: none;
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--border);
  font-size: 18px;
  font-weight: 600;
  user-select: none;
}
details.category > summary::-webkit-details-marker { display: none; }
details.category > summary::before {
  content: "▾ "; color: var(--muted); font-weight: normal;
}
details.category:not([open]) > summary::before { content: "▸ "; }
details.category > summary .count {
  color: var(--muted);
  font-weight: normal;
  font-size: 14px;
  margin-left: 0.5rem;
}
/* Category-level educational blurb — sourced from each test file's
   `__category_description__` module constant. Subtle styling so it
   reads as ambient context, not an alert. */
.category-description {
  background: var(--code-block-bg);
  border-left: 3px solid var(--accent);
  padding: 0.75rem 1rem;
  margin: 0.6rem 0 0.75rem 0;
  border-radius: 0 6px 6px 0;
  font-size: 13px;
  line-height: 1.55;
  color: var(--muted);
}
.category-description strong { color: var(--fg); font-weight: 600; }
.category-description code {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 12.5px;
}

.file-section { margin-top: 0.75rem; }
.file-label {
  font-size: 12px;
  color: var(--muted);
  margin: 0.5rem 0 0.25rem 0;
}
.file-label code {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 1px 6px;
  border-radius: 4px;
}

.tests-list { border-top: 1px solid var(--border); }
.row { display: flex; align-items: stretch; border-bottom: 1px solid var(--border); }
.row.header > span {
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 0.5rem 0.6rem;
}
details.test-detail { display: block; }
details.test-detail > summary {
  display: flex;
  cursor: pointer;
  list-style: none;
  width: 100%;
  border-bottom: 1px solid var(--border);
  user-select: none;
}
details.test-detail > summary::-webkit-details-marker { display: none; }
details.test-detail:hover > summary { background: var(--row-hover); }
details.test-detail[open] > summary { background: var(--row-open); }
.col {
  padding: 0.5rem 0.6rem;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 2px;
}
.col.num {
  flex: 0 0 4em;
  font-variant-numeric: tabular-nums;
  color: var(--muted);
  white-space: nowrap;
}
.col.name { flex: 0 0 18em; min-width: 12em; }
.col.cmds { flex: 0 0 18em; }
.col.ver { flex: 1 1 auto; min-width: 14em; }
.col.name code {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 13px;
}
.cmd-chip {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 1px 6px;
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12px;
}
/* Acronym tooltip — instant CSS pseudo-element tooltip; bypasses Safari's
   multi-second native title-tooltip delay. The data-tip attribute carries
   the expansion (rendered via `attr()` in the ::after content); aria-label
   carries the same string for screen readers. */
abbr[data-tip] {
  position: relative;
  border-bottom: 1px dotted var(--muted);
  cursor: help;
  text-decoration: none;
}
abbr[data-tip]:hover::after,
abbr[data-tip]:focus-visible::after {
  content: attr(data-tip);
  position: absolute;
  bottom: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%);
  background: var(--fg);
  color: var(--bg);
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
  pointer-events: none;
  z-index: 100;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}
details.test-detail > .code-wrap {
  background: var(--code-block-bg);
  padding: 0.6rem 1rem 1rem 1rem;
  border-bottom: 1px solid var(--border);
}
.code-meta {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 0.4rem;
}
.code-meta code {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 1px 6px;
  border-radius: 4px;
}
.code-meta a { color: var(--accent); text-decoration: none; }
.code-meta a:hover { text-decoration: underline; }

/* Nested context accordions (Test method / Fixture / Module context) */
details.ctx { margin: 0.5rem 0; }
details.ctx > summary {
  cursor: pointer;
  list-style: none;
  user-select: none;
  font-size: 13px;
  color: var(--muted);
  padding: 4px 0;
}
details.ctx > summary::-webkit-details-marker { display: none; }
details.ctx > summary::before { content: "▾ "; }
details.ctx:not([open]) > summary::before { content: "▸ "; }
details.ctx > summary .ctx-label {
  font-weight: 600;
  color: var(--fg);
  margin-right: 0.4rem;
}
details.ctx > summary code {
  background: var(--code-bg);
  color: var(--code-fg);
  padding: 1px 5px;
  border-radius: 3px;
  margin-right: 0.3rem;
}
details.ctx > pre.code-block { margin-top: 0.3rem; }

pre.code-block {
  margin: 0;
  padding: 0.75rem 1rem;
  background: var(--code-bg);
  color: var(--code-fg);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 12.5px;
  line-height: 1.5;
  overflow-x: auto;
  border-radius: 6px;
  border: 1px solid var(--border);
}
.no-results {
  display: none;
  padding: 2rem;
  text-align: center;
  color: var(--muted);
  font-style: italic;
}
.no-results.shown { display: block; }
"""


_JS = """
(function() {
  const input = document.getElementById('filter');
  const noResults = document.getElementById('no-results');
  const helpLine = document.getElementById('filter-help');

  function normalize(s) { return (s || '').toLowerCase(); }

  function applyFilter() {
    const q = normalize(input.value).trim();
    helpLine.classList.toggle('hidden', q.length > 0);
    let totalVisible = 0;
    document.querySelectorAll('details.category').forEach(cat => {
      let catVisible = 0;
      cat.querySelectorAll('.file-section').forEach(fs => {
        let fsVisible = 0;
        fs.querySelectorAll('details.test-detail').forEach(row => {
          const haystack = row.dataset.search || '';
          const match = !q || haystack.indexOf(q) !== -1;
          row.style.display = match ? '' : 'none';
          if (match) fsVisible++;
        });
        fs.style.display = fsVisible ? '' : 'none';
        catVisible += fsVisible;
      });
      cat.style.display = catVisible ? '' : 'none';
      if (catVisible && q.length > 0) cat.open = true;
      totalVisible += catVisible;
    });
    noResults.classList.toggle('shown', totalVisible === 0 && q.length > 0);
  }

  input.addEventListener('input', applyFilter);

  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      input.focus();
      input.select();
    } else if (e.key === '/' && document.activeElement !== input
               && !(e.target.closest && e.target.closest('input, textarea'))) {
      e.preventDefault();
      input.focus();
    } else if (e.key === 'Escape' && document.activeElement === input) {
      input.value = '';
      applyFilter();
      input.blur();
    }
  });

  function focusFromHash() {
    const hash = window.location.hash;
    if (!hash || hash.length < 2) return;
    let el;
    try { el = document.querySelector(hash); } catch (_) { return; }
    if (!el) return;
    let cursor = el;
    while (cursor) {
      if (cursor.tagName === 'DETAILS') cursor.open = true;
      cursor = cursor.parentElement;
    }
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  window.addEventListener('hashchange', focusFromHash);
  window.addEventListener('load', focusFromHash);
})();
"""


# ── render ────────────────────────────────────────────────────────────


def _render_test_body(item, fn_name: str, rel_path: str, row_id: str) -> str:
    """Render the expandable body for one test row: test method (open),
    fixtures (collapsed), module context (collapsed)."""
    fn = item.function
    parts: list[str] = []
    parts.append('<div class="code-wrap">')
    parts.append(
        f'<div class="code-meta">'
        f'<span><code>{html.escape(rel_path)}</code></span>'
        f'<a href="#{row_id}">¶ permalink</a>'
        f"</div>"
    )

    # 1) Test method — open by default.
    method_src = _extract_def_body(fn)
    parts.append('<details class="ctx" open>')
    parts.append(
        '<summary><span class="ctx-label">Test method</span></summary>'
    )
    parts.append(
        f'<pre class="code-block"><code class="hl">'
        f"{_hl(method_src)}</code></pre>"
    )
    parts.append("</details>")

    # 2) Fixtures used by this test — collapsed.
    for fix_name, fix_src, fix_rel in _resolve_direct_fixtures(item):
        parts.append('<details class="ctx">')
        parts.append(
            f'<summary><span class="ctx-label">Fixture</span>'
            f"<code>{html.escape(fix_name)}</code>"
            f"<code>{html.escape(fix_rel)}</code>"
            f"</summary>"
        )
        parts.append(
            f'<pre class="code-block"><code class="hl">'
            f"{_hl(fix_src)}</code></pre>"
        )
        parts.append("</details>")

    # 3) Module context (everything in this file except the conformance
    # tests themselves) — collapsed.
    try:
        module_file = inspect.getsourcefile(fn)
    except TypeError:
        module_file = None
    if module_file:
        preamble = _module_preamble(module_file)
        if preamble.strip():
            parts.append('<details class="ctx">')
            parts.append(
                f'<summary><span class="ctx-label">Module context</span>'
                f"<code>{html.escape(rel_path)}</code>"
                f"</summary>"
            )
            parts.append(
                f'<pre class="code-block"><code class="hl">'
                f"{_hl(preamble)}</code></pre>"
            )
            parts.append("</details>")

    parts.append("</div>")
    return "".join(parts)


def render(items) -> str:
    categories = _categorize_with_items(items)
    total = sum(
        len(rows) for _, _, files in categories for _, rows in files
    )
    n_cats = len(categories)

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append("<title>Conformance Test Cases</title>")
    parts.append("<style>")
    parts.append(_CSS_BASE)
    parts.append(_pygments_css())
    parts.append("</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append('<div class="layout">')

    # Sidebar TOC
    parts.append('<aside class="toc">')
    parts.append("<h2>Categories</h2>")
    parts.append("<ol>")
    for cat_idx, (title, _desc, files) in enumerate(categories, start=1):
        n = sum(len(rows) for _, rows in files)
        parts.append(
            f'<li><a href="#cat-{cat_idx}">'
            f"{cat_idx}. {html.escape(title)}"
            f'<span class="count">{n}</span>'
            f"</a></li>"
        )
    parts.append("</ol>")
    parts.append("</aside>")

    # Main
    parts.append("<main>")
    parts.append('<header class="page">')
    parts.append("<h1>Conformance Test Cases</h1>")
    cat_word = "category" if n_cats == 1 else "categories"
    parts.append(
        f'<div class="stats">{_plural(total, "test")} across '
        f'{n_cats} {cat_word} · click any row to view the test source, '
        f"its fixtures, and the rest of the module · generated from "
        f"<code>@conformance_case</code> decorators</div>"
    )
    parts.append("</header>")

    # Filter bar
    parts.append('<div class="filter-bar">')
    parts.append(
        '<input id="filter" type="search" autocomplete="off" '
        'placeholder="Filter tests by name, command, or description" '
        'aria-label="Filter tests">'
    )
    parts.append(
        '<div class="help" id="filter-help">'
        "Press <code>/</code> or <code>⌘K</code> to focus · "
        "<code>Esc</code> to clear · filter matches test name, commands, "
        "and description"
        "</div>"
    )
    parts.append("</div>")
    parts.append(
        '<div class="no-results" id="no-results">'
        "No tests match the filter."
        "</div>"
    )

    # Categories
    for cat_idx, (title, description_md, files) in enumerate(categories, start=1):
        n = sum(len(rows) for _, rows in files)
        parts.append(
            f'<details class="category" id="cat-{cat_idx}" open>'
            f"<summary>{cat_idx}. {html.escape(title)}"
            f'<span class="count">{_plural(n, "test")}</span>'
            f"</summary>"
        )

        # Optional category-level educational blurb. Rendered as a styled
        # box with minimal markdown (inline code + bold) and the same
        # glossary-acronym tooltips the test rows get.
        if description_md and description_md.strip():
            desc_html = _wrap_abbreviations(
                _render_inline_markdown(html.escape(description_md.strip()))
            )
            parts.append(
                f'<div class="category-description">{desc_html}</div>'
            )

        sub_idx = 0
        for rel_path, rows in files:
            parts.append('<div class="file-section">')
            parts.append(
                f'<div class="file-label">File: '
                f"<code>{html.escape(rel_path)}</code>"
                f" · {_plural(len(rows), 'test')}"
                f"</div>"
            )
            parts.append('<div class="tests-list">')
            parts.append(
                '<div class="row header">'
                '<span class="col num">#</span>'
                '<span class="col name">Test</span>'
                '<span class="col cmds">Commands</span>'
                '<span class="col ver">What it verifies</span>'
                "</div>"
            )
            for fn_name, case, item in rows:
                sub_idx += 1
                row_id = f"t-{cat_idx}-{sub_idx}"
                # Searchable: test name + commands + verifies prose + the
                # full-form expansion of any glossary acronym that appears
                # in this row's prose (so "initialization vector" finds IV).
                haystack_terms = [fn_name, *case.commands, case.verifies]
                haystack_terms.extend(_haystack_expansions(case.verifies))
                haystack = html.escape(" ".join(haystack_terms).lower())
                verifies_html = _wrap_abbreviations(
                    _render_inline_markdown(html.escape(case.verifies))
                )
                body = _render_test_body(item, fn_name, rel_path, row_id)
                parts.append(
                    f'<details class="test-detail" id="{row_id}" '
                    f'data-search="{haystack}">'
                    f"<summary>"
                    f'<span class="col num">{cat_idx}.{sub_idx}</span>'
                    f'<span class="col name"><code>'
                    f'{html.escape(fn_name)}</code></span>'
                    f'<span class="col cmds">{_cmd_chips(case.commands)}</span>'
                    f'<span class="col ver">{verifies_html}</span>'
                    f"</summary>"
                    f"{body}"
                    f"</details>"
                )
            parts.append("</div>")  # tests-list
            parts.append("</div>")  # file-section
        parts.append("</details>")  # category

    parts.append("</main>")
    parts.append("</div>")  # layout
    parts.append(f"<script>{_JS}</script>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--stdout", action="store_true",
        help="write to stdout instead of TESTS.html",
    )
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT,
        help=f"output path (default: {_display_path(DEFAULT_OUTPUT)})",
    )
    args = parser.parse_args()

    items = collect_items()
    rendered = render(items)

    if args.stdout:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered)
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
            f"to {_display_path(args.output)}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
