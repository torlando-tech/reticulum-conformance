#!/usr/bin/env python3
"""Assert CI is pinned to the audited RNS/LXMF ground-truth versions.

Shared by the kotlin and reference conformance jobs so the version guard lives
in ONE place. A pin drift in either job's checkout (the ref: pins in
tests.yml) would silently let CI validate against a non-audited RNS/LXMF, so a
mismatch is a hard failure regardless of which job is inspected first.

Reads __version__ from each checkout's _version.py - the definitive source of
RNS.__version__ / LXMF.__version__ - without a full `import RNS` (which would
need cryptography/pyserial that these jobs do not always pip-install).

The audited release tags come from the repo's single source of truth,
`reference-pins.env`; bump them there, not here.
"""
import os
import sys

import _rns_paths as p

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PINS_FILE = os.path.join(REPO_ROOT, "reference-pins.env")


def read_pins(path=PINS_FILE):
    """Parse `KEY=value` lines (comments/blank lines allowed)."""
    pins = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            pins[key.strip()] = value.strip()
    if "RNS" not in pins or "LXMF" not in pins:
        print(f"::error::{path} must define RNS and LXMF", file=sys.stderr)
        sys.exit(1)
    return pins


EXPECTED_RNS = read_pins()["RNS"]
EXPECTED_LXMF = read_pins()["LXMF"]


def version_of(pkg, env_var):
    base = p.resolve_package_path(pkg, env_var)
    vfile = os.path.join(base, pkg, "_version.py")
    ns = {}
    exec(compile(open(vfile).read(), vfile, "exec"), ns)
    return ns["__version__"]


def main():
    rns_v = version_of("RNS", "PYTHON_RNS_PATH")
    lxmf_v = version_of("LXMF", "PYTHON_LXMF_PATH")
    print(f"resolved RNS {rns_v} (from {p.resolve_rns_path()})")
    print(f"resolved LXMF {lxmf_v}")
    errs = []
    if rns_v != EXPECTED_RNS:
        errs.append(f"RNS {rns_v} != {EXPECTED_RNS}")
    if lxmf_v != EXPECTED_LXMF:
        errs.append(f"LXMF {lxmf_v} != {EXPECTED_LXMF}")
    if errs:
        print(
            "::error::CI not pinned to audited ground truth: " + "; ".join(errs)
        )
        sys.exit(1)
    print(f"OK: RNS {EXPECTED_RNS} / LXMF {EXPECTED_LXMF} (audited ground truth)")


if __name__ == "__main__":
    main()
