"""IFAC single-credential activation completeness tests (wire harness).

Pins the distinctive RNS claim that IFAC is enabled when EITHER network_name
OR passphrase is set — each alone suffices — and that the single-credential
ifac_origin is built from just the present half (Reticulum.py:898-916):

    ifac_origin = b""
    if ifac_netname is not None: ifac_origin += full_hash(ifac_netname.utf8)
    if ifac_netkey  is not None: ifac_origin += full_hash(ifac_netkey.utf8)
    ifac_origin_hash = full_hash(ifac_origin)
    ifac_key = hkdf(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT)

Every other IFAC test in the suite sets BOTH credentials, so an impl that
requires both, or that pads/normalises the absent half, passes all of them.
Here a TCP interface is brought up with ONLY a network_name (then ONLY a
passphrase); the bridge reads the live RNS-derived ifac_key off the interface
and we compare it against a fully INDEPENDENT RFC-5869 HKDF / RFC-6234 SHA-256
derivation computed in this file (no RNS, no bridge crypto). The single-input
key must equal that independent value AND differ from the both-input key —
proving activation on one credential and correct empty-half handling.
"""

import hmac
import secrets
# Imported as a bare name (not `hashlib.sha256`) so this independent SHA-256 /
# HKDF derivation does NOT look like a call to the bridge's `sha256` command to
# the conformance-decorator linter: every hash here is pure-Python stdlib, never
# the bridge. The whole point is an impl-independent oracle.
from hashlib import sha256 as _sha256

from conformance import conformance_case


__category_title__ = "Reticulum Config"
__category_order__ = 6


# RNS.Reticulum.IFAC_SALT (Reticulum.py:149), a fixed spec literal.
_IFAC_SALT = bytes.fromhex(
    "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
)
# TCPInterface.DEFAULT_IFAC_SIZE (Interfaces/TCPInterface.py); the bridge writes
# no explicit ifac_size so a TCP interface uses this default of 16 bytes.
_TCP_DEFAULT_IFAC_SIZE = 16
# Length of the derived IFAC key (Reticulum.py:909 hkdf length=64).
_IFAC_KEY_LEN = 64


def _full_hash(data: bytes) -> bytes:
    """RNS.Identity.full_hash == SHA-256 (independent of the bridge)."""
    return _sha256(data).digest()


def _hkdf_sha256(length: int, derive_from: bytes, salt: bytes) -> bytes:
    """Standalone RFC-5869 HKDF-SHA256 (extract+expand, empty info).

    Reproduces RNS.Cryptography.hkdf without calling RNS, so the expected key
    is an INDEPENDENT derivation rather than the impl's own output.
    """
    if salt is None or len(salt) == 0:
        salt = b"\x00" * 32  # SHA-256 digest size
    prk = hmac.new(salt, derive_from, _sha256).digest()
    okm = b""
    block = b""
    counter = 0
    while len(okm) < length:
        counter += 1
        block = hmac.new(prk, block + bytes([counter]), _sha256).digest()
        okm += block
    return okm[:length]


def _expected_ifac_key(network_name: str | None, passphrase: str | None) -> bytes:
    """Independent RNS-1.3.1 ifac_key derivation (Reticulum.py:898-913)."""
    ifac_origin = b""
    if network_name is not None:
        ifac_origin += _full_hash(network_name.encode("utf-8"))
    if passphrase is not None:
        ifac_origin += _full_hash(passphrase.encode("utf-8"))
    ifac_origin_hash = _full_hash(ifac_origin)
    return _hkdf_sha256(_IFAC_KEY_LEN, ifac_origin_hash, _IFAC_SALT)


# Arbitrary probe bytes for ifac_compute; the ifac_KEY (not the signature) is
# what these tests pin, so the packet content is irrelevant.
_PROBE = bytes(range(32))


@conformance_case(
    commands=["start_tcp_server", "ifac_compute"],
    verifies="IFAC activates on network_name ALONE (no passphrase): a TCP interface configured with only network_name derives a live 64-byte ifac_key equal to an independent RFC-5869 HKDF over full_hash(network_name) with the fixed IFAC_SALT — proving (a) one credential is sufficient to enable IFAC and (b) the absent passphrase contributes nothing (ifac_origin is full_hash(netname) only, not padded). The same-network_name two-credential key differs, confirming the empty half is genuinely omitted",
)
def test_ifac_activates_on_network_name_only(wire_peers):
    server, _client = wire_peers
    network_name = f"ncfg-{secrets.token_hex(4)}"

    # passphrase="" -> the bridge writes no passphrase line, so ifac_netkey is
    # None and only network_name drives the derivation.
    server.start_tcp_server(network_name, "")
    result = server.ifac_compute(_PROBE)

    assert len(result["ifac_key"]) == _IFAC_KEY_LEN, (
        f"derived ifac_key is {len(result['ifac_key'])} bytes; must be "
        f"{_IFAC_KEY_LEN} (hkdf length)"
    )
    expected = _expected_ifac_key(network_name, None)
    assert result["ifac_key"] == expected, (
        "network_name-only ifac_key diverges from the independent HKDF over "
        f"full_hash(network_name). got={result['ifac_key'].hex()} "
        f"expected={expected.hex()}. Either IFAC did not activate on "
        "network_name alone, or the absent passphrase was not omitted cleanly."
    )

    # Negative discrimination: had the impl required/synthesised a passphrase,
    # the key would match a two-credential derivation. It must not.
    both = _expected_ifac_key(network_name, "some-passphrase")
    assert result["ifac_key"] != both, (
        "network_name-only ifac_key collides with a two-credential key; the "
        "passphrase half is not being omitted from ifac_origin."
    )

    # TCP interface default IFAC size sanity (the slice width RNS would apply).
    assert result["ifac_size"] == _TCP_DEFAULT_IFAC_SIZE


@conformance_case(
    commands=["start_tcp_server", "ifac_compute"],
    verifies="IFAC activates on passphrase ALONE (no network_name): a TCP interface configured with only a passphrase derives a live 64-byte ifac_key equal to an independent RFC-5869 HKDF over full_hash(passphrase) with the fixed IFAC_SALT — proving the passphrase alone enables IFAC and the absent network_name contributes nothing (ifac_origin is full_hash(passphrase) only). The same-passphrase two-credential key differs",
)
def test_ifac_activates_on_passphrase_only(wire_peers):
    server, _client = wire_peers
    passphrase = secrets.token_hex(16)

    # network_name="" -> no network_name line, so ifac_netname is None.
    server.start_tcp_server("", passphrase)
    result = server.ifac_compute(_PROBE)

    expected = _expected_ifac_key(None, passphrase)
    assert result["ifac_key"] == expected, (
        "passphrase-only ifac_key diverges from the independent HKDF over "
        f"full_hash(passphrase). got={result['ifac_key'].hex()} "
        f"expected={expected.hex()}. Either IFAC did not activate on the "
        "passphrase alone, or the absent network_name was not omitted cleanly."
    )

    # Negative discrimination: a two-credential key with the same passphrase
    # (a network_name prepended to ifac_origin) must differ.
    both = _expected_ifac_key("some-network", passphrase)
    assert result["ifac_key"] != both, (
        "passphrase-only ifac_key collides with a two-credential key; the "
        "network_name half is not being omitted from ifac_origin."
    )

    # NOTE (RNS behavior, deliberately NOT asserted as distinct): because the
    # absent half contributes nothing, network_name='x'/no-passphrase and
    # no-network_name/passphrase='x' produce the SAME ifac_origin == full_hash(x)
    # and therefore the SAME ifac_key. The credential halves are positionally
    # ordered only when BOTH are present; a single credential is field-agnostic.
    assert result["ifac_key"] == _expected_ifac_key(passphrase, None), (
        "passphrase-only key must equal the network_name-only key over the "
        "same string (single-credential ifac_origin is field-agnostic)."
    )
