"""Centralized resolution for the upstream Python `RNS` and `LXMF` packages.

Every conftest/script that needs to point a bridge subprocess (or this
process) at the reference Python implementation calls into here. The
single resolver replaces six previously-duplicated copies of
`os.environ.get("PYTHON_X_PATH", os.path.expanduser("~/repos/X"))` —
the home-path fallback was Torlando-specific and violated the
no-environment-PII-in-source rule.

Resolution order (option C — env first, then conventional layouts):

  1. The `{ENV_VAR}` environment variable. If it points at a directory
     containing the expected package dir (e.g. `RNS/` for RNS), use it.
     This is what CI sets explicitly (see `.github/workflows/`).
  2. A sibling checkout at `<repo_root>/../{pkg}`. Works for any
     contributor with side-by-side git clones; no user-specific paths.
  3. `importlib.util.find_spec({pkg})`. If the current Python
     environment can already import the package (pip install, editable
     install, etc.), use its site-packages parent. Subprocesses that
     inherit the same Python env will resolve it the same way.

All three miss → raise `RuntimeError` with actionable guidance.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent


def _is_source_checkout(path: Path, pkg: str) -> bool:
    """A "source-checkout" path is valid iff it contains `<path>/<pkg>/`."""
    return path.is_dir() and (path / pkg).is_dir()


def resolve_package_path(pkg: str, env_var: str) -> str:
    """Return a directory whose presence on `sys.path` makes `import {pkg}` work.

    Raises:
        RuntimeError: if `{env_var}` is set but invalid, or if all three
            resolution steps miss.
    """
    # 1) Explicit env var. If set, it MUST be valid — silently falling back
    # to a sibling or pip install when the user explicitly pointed somewhere
    # broken would mask the misconfiguration.
    env_val = os.environ.get(env_var)
    if env_val:
        path = Path(os.path.expanduser(env_val))
        if _is_source_checkout(path, pkg):
            return str(path)
        raise RuntimeError(
            f"{env_var}={env_val!r} but no {pkg}/ directory was found there. "
            f"Either fix the path, unset the variable to let auto-discovery "
            f"try a sibling checkout / pip install, or `pip install {pkg}`."
        )

    # 2) Sibling checkout — e.g. `<repos>/Reticulum/` next to this repo.
    sibling = _REPO_ROOT.parent / pkg
    if _is_source_checkout(sibling, pkg):
        return str(sibling)

    # 3) Importable from the current Python env (pip / editable / etc.).
    spec = importlib.util.find_spec(pkg)
    if spec is not None and spec.origin:
        # spec.origin = <site-packages>/<pkg>/__init__.py
        # parent.parent = <site-packages>, which is what `sys.path` needs.
        return str(Path(spec.origin).resolve().parent.parent)

    raise RuntimeError(
        f"Could not locate Python {pkg}. Either set {env_var} to a "
        f"source checkout, place a {pkg}/ checkout beside this repo "
        f"(expected at {sibling}), or `pip install {pkg.lower()}`."
    )


def resolve_rns_path() -> str:
    """Resolve the path to the upstream `RNS` package (see option C above)."""
    return resolve_package_path("RNS", "PYTHON_RNS_PATH")


def resolve_lxmf_path() -> str:
    """Resolve the path to the upstream `LXMF` package (see option C above)."""
    return resolve_package_path("LXMF", "PYTHON_LXMF_PATH")
