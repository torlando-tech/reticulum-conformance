"""Conformance test metadata.

Every test in tests/ must carry a @conformance_case decorator so the
inventory in TESTS.md can be regenerated deterministically. The CI drift
guard (tools/check_conformance_decorated.py) refuses to let an undecorated
test land; the generator (tools/generate_tests_md.py) reads the decorated
metadata into TESTS.md.

Sibling module-level constants control rendering:
    __category_title__: str   # required — section header in TESTS.md
    __category_order__: int   # optional — explicit category ordering
                              # (default: 10_000 → sorted alphabetically last)
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ConformanceCase:
    """Inventory metadata for one conformance test.

    Attributes:
        commands: bridge protocol verbs the test exercises (e.g. ("sha256",)).
                  Rendered in the "Commands Used" column of TESTS.md, so the
                  list must be COMPLETE: it must be a superset of every bridge
                  command the test actually drives, INCLUDING setup/teardown
                  plumbing reached through fixtures' wrapper methods or helper
                  functions (e.g. a test that calls a `_setup_topology()`
                  helper which does `peer.poll_path(...)` must list
                  ``poll_path``). The drift guard
                  (tools/check_conformance_decorated.py) statically verifies
                  this superset relation and fails CI on any omission (N-M6).

                  Naming convention: declare the bare command alias without
                  the ``wire_`` / ``behavioral_`` namespace prefix — i.e. the
                  same name the fixture wrapper method uses
                  (``poll_path``, not ``wire_poll_path``).
        verifies: a single English sentence describing what the test asserts,
                  rendered in the "What It Verifies" column.
    """

    commands: tuple[str, ...]
    verifies: str


def conformance_case(*, commands, verifies):
    """Attach conformance metadata to a test function.

    `commands` must be a SUPERSET of the bridge commands the test actually
    invokes (see ConformanceCase.commands); the drift guard enforces this.
    This decorator only validates shape at import time — the superset relation
    is checked statically by tools/check_conformance_decorated.py.

    Example:
        @conformance_case(
            commands=["sha256"],
            verifies="SHA-256 hash of 64 random bytes matches",
        )
        def test_sha256(sut, reference): ...
    """
    if not isinstance(commands, (list, tuple)):
        raise TypeError("commands must be a list or tuple of strings")
    if any(not isinstance(c, str) or not c.strip() for c in commands):
        raise ValueError("every command must be a non-empty string")
    if not isinstance(verifies, str) or not verifies.strip():
        raise ValueError("verifies must be a non-empty string")

    case = ConformanceCase(tuple(commands), verifies.strip())

    def _decorate(fn):
        fn.__conformance__ = case
        return fn

    return _decorate
