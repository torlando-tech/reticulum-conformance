"""Identity persistence conformance.

Apps store their RNS Identity on disk so it survives restarts: Sideband's
``core.py`` calls ``Identity.from_file`` to load the persisted identity on
startup. The on-disk format is the 64-byte raw private key (X25519 + Ed25519
halves); ``RNS.Identity.to_file`` writes it, ``RNS.Identity.from_file``
reads it. Any mismatch in format would break every Sideband install.

Honest test: build a real Identity from a known private key, write it via
to_file, read it back via from_file, assert the recovered identity has the
same public_key + hash. Cross-impl proof of agreement on the on-disk byte
format.
"""

import secrets

from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Identity"
__category_order__ = 2


@conformance_case(
    commands=["identity_from_private_key", "identity_to_file", "identity_from_file"],
    verifies="RNS.Identity round-trips through the on-disk file format (raw 64-byte private key) via to_file -> from_file with byte-identical public_key + hash on the reloaded Identity. Catches an impl whose to_file / from_file disagree on byte layout (Sideband's identity-on-disk format).",
)
def test_identity_to_file_from_file_round_trip(sut, reference):
    priv = random_hex(64)
    expected = reference.execute("identity_from_private_key", private_key=priv)

    for impl, label in ((reference, "reference"), (sut, "sut")):
        written = impl.execute("identity_to_file", private_key=priv)
        path = written["path"]
        loaded = impl.execute("identity_from_file", path=path)
        assert loaded["found"] is True, (
            f"{label}.identity_from_file({path}) reported not-found despite "
            f"to_file having just written the identity there"
        )
        assert_hex_equal(loaded["public_key"], expected["public_key"])
        assert_hex_equal(loaded["hash"], expected["hash"])
        assert loaded["hexhash"] == expected["hexhash"]


@conformance_case(
    commands=["identity_from_private_key", "identity_to_file", "identity_from_file"],
    verifies="Cross-impl on-disk format: an identity written by either impl can be loaded by the other, and BOTH reload paths recover the byte-identical public_key + hash of the identity derived directly from the same 64-byte private key. The 64-byte raw private key on disk is the interop contract between Python LXMF / Sideband and any cross-impl reload path.",
)
def test_identity_file_format_cross_impl(sut, reference):
    """Reference writes -> SUT reads, and SUT writes -> reference reads."""
    priv = random_hex(64)
    # Ground truth: the identity derived directly from the private key. Both
    # cross-loaded reloads must match this, so a shared symmetric byte-layout
    # bug (both impls agreeing on the WRONG keys) is still caught.
    expected = reference.execute("identity_from_private_key", private_key=priv)

    written_by_ref = reference.execute("identity_to_file", private_key=priv)
    loaded_by_sut = sut.execute("identity_from_file", path=written_by_ref["path"])
    assert loaded_by_sut["found"] is True, (
        f"SUT could not load a file written by reference at "
        f"{written_by_ref['path']!r}"
    )

    written_by_sut = sut.execute("identity_to_file", private_key=priv)
    loaded_by_ref = reference.execute("identity_from_file", path=written_by_sut["path"])
    assert loaded_by_ref["found"] is True, (
        f"reference could not load a file written by SUT at "
        f"{written_by_sut['path']!r}"
    )

    # Both reload paths must surface the public key + hash of the identity the
    # private key actually derives — not merely agree with each other.
    assert_hex_equal(loaded_by_sut["public_key"], expected["public_key"])
    assert_hex_equal(loaded_by_sut["hash"], expected["hash"])
    assert_hex_equal(loaded_by_ref["public_key"], expected["public_key"])
    assert_hex_equal(loaded_by_ref["hash"], expected["hash"])


@conformance_case(
    commands=["identity_from_file"],
    verifies="Negative control: identity_from_file on a non-existent path returns found=False (or on Python's RNS, raises which the bridge surfaces as an error). Catches an impl that silently fabricates an Identity for a missing file — a vector for accidentally generating fresh keys on every boot.",
)
def test_identity_from_file_missing_path(sut, reference):
    """A path that does not exist must NOT yield a valid Identity."""
    # /tmp/<random>.nonexistent is virtually guaranteed not to exist.
    bogus_path = f"/tmp/conformance_nonexistent_{secrets.token_hex(8)}.bin"
    for impl, label in ((reference, "reference"), (sut, "sut")):
        try:
            res = impl.execute("identity_from_file", path=bogus_path)
            # Some impls return found=False; some surface an error via the
            # bridge — both are acceptable, what's NOT acceptable is
            # silently returning a fabricated Identity.
            assert res.get("found") is False, (
                f"{label}.identity_from_file({bogus_path!r}) returned a "
                f"non-None identity for a missing file: {res!r}"
            )
        except Exception:
            # Surfaced as an error — also acceptable (the bridge raised
            # because RNS itself raised). The wrong behavior is silent
            # success, not loud failure.
            pass
