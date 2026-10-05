#!/usr/bin/env python3
"""Assert CI is pinned to the audited RNS/LXMF ground-truth versions.

Shared by the kotlin and reference conformance jobs so the version guard lives
in ONE place. A pin drift in either job's checkout (the ref: pins in
tests.yml) would silently let CI validate against a non-audited RNS/LXMF, so a
mismatch is a hard failure regardless of which job is inspected first.

Reads __version__ from each checkout's _version.py - the definitive source of
RNS.__version__ / LXMF.__version__ - without a full `import RNS` (which would
need cryptography/pyserial that these jobs do not always pip-install).
"""
import os
import sys

import _rns_paths as p

# The audited ground-truth release tags. Bump here (and the ref: pins in
# tests.yml) together when re-auditing against a new RNS/LXMF release.
EXPECTED_RNS = "1.3.1"
EXPECTED_LXMF = "0.9.9"


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
