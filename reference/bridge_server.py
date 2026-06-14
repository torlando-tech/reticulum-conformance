#!/usr/bin/env python3
"""
Python Bridge Server for Kotlin Reticulum Interop Testing.

This server receives JSON commands over stdin, executes them against
the Python RNS library, and returns JSON responses over stdout.

Protocol:
    Request:  {"id": "...", "command": "...", "params": {...}}
    Response: {"id": "...", "success": true, "result": {...}}
    Error:    {"id": "...", "success": false, "error": "..."}

All byte arrays are hex-encoded strings.
"""

import sys
import os
import json
import traceback

# Add RNS Cryptography to path directly (bypass RNS __init__.py).
#
# Resolve the upstream RNS location through the shared `_rns_paths` helper
# (repo root) instead of a hardcoded `../../../Reticulum` default. This
# guarantees the GENUINE crypto primitives loaded standalone below come from
# the SAME RNS that the LIVE handlers import via `_get_full_rns()` — closing
# the version-skew trap where, run bare (no PYTHON_RNS_PATH), the two halves of
# the bridge would load different RNS versions (e.g. an old 1.1.3 sibling vs a
# pip-installed 1.3.1). `_rns_paths.resolve_rns_path()` still honours
# PYTHON_RNS_PATH first, then a sibling checkout, then the importable install.
# (N-M9)
_BRIDGE_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_BRIDGE_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from _rns_paths import resolve_rns_path

rns_path = resolve_rns_path()
sys.path.insert(0, os.path.join(rns_path, 'RNS', 'Cryptography'))
sys.path.insert(0, rns_path)

import hashlib

# Import umsgpack from RNS vendor
sys.path.insert(0, os.path.join(rns_path, 'RNS', 'vendor'))
import umsgpack

# Import cryptography modules directly from the Cryptography directory
# This bypasses RNS/__init__.py which would load all interfaces
import importlib.util

def load_module_from_path(name, path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

# Load cryptography modules directly
crypto_path = os.path.join(rns_path, 'RNS', 'Cryptography')

# Load HMAC first (needed by others)
HMAC = load_module_from_path('RNS_HMAC', os.path.join(crypto_path, 'HMAC.py'))

# Load X25519
X25519 = load_module_from_path('RNS_X25519', os.path.join(crypto_path, 'X25519.py'))

# Load HKDF (depends on HMAC)
# We need to patch the import
hkdf_code = open(os.path.join(crypto_path, 'HKDF.py')).read()
hkdf_code = hkdf_code.replace('from RNS.Cryptography import HMAC', '')
hkdf_module = type(sys)('RNS_HKDF')
hkdf_module.HMAC = HMAC
exec(compile(hkdf_code, 'HKDF.py', 'exec'), hkdf_module.__dict__)
sys.modules['RNS_HKDF'] = hkdf_module
HKDF = hkdf_module

# Load PKCS7 (functions are in PKCS7.PKCS7 class)
PKCS7_module = load_module_from_path('RNS_PKCS7', os.path.join(crypto_path, 'PKCS7.py'))
PKCS7 = PKCS7_module.PKCS7

# Load internal pure Python AES implementation
aes128_module = load_module_from_path('RNS_AES128', os.path.join(crypto_path, 'aes', 'aes128.py'))
aes256_module = load_module_from_path('RNS_AES256', os.path.join(crypto_path, 'aes', 'aes256.py'))

class AES_128_CBC:
    @staticmethod
    def encrypt(plaintext, key, iv):
        if len(key) != 16:
            raise ValueError(f"Invalid key length {len(key)*8} for AES-128")
        cipher = aes128_module.AES128(key)
        return cipher.encrypt(plaintext, iv)

    @staticmethod
    def decrypt(ciphertext, key, iv):
        if len(key) != 16:
            raise ValueError(f"Invalid key length {len(key)*8} for AES-128")
        cipher = aes128_module.AES128(key)
        return cipher.decrypt(ciphertext, iv)

class AES_256_CBC:
    @staticmethod
    def encrypt(plaintext, key, iv):
        if len(key) != 32:
            raise ValueError(f"Invalid key length {len(key)*8} for AES-256")
        cipher = aes256_module.AES256(key)
        return cipher.encrypt_cbc(plaintext, iv)

    @staticmethod
    def decrypt(ciphertext, key, iv):
        if len(key) != 32:
            raise ValueError(f"Invalid key length {len(key)*8} for AES-256")
        cipher = aes256_module.AES256(key)
        return cipher.decrypt_cbc(ciphertext, iv)

# Load Token (depends on HMAC, PKCS7, AES)
token_code = open(os.path.join(crypto_path, 'Token.py')).read()
token_module = type(sys)('RNS_Token')
token_module.os = os
token_module.time = __import__('time')
token_module.HMAC = HMAC
token_module.PKCS7 = PKCS7
token_module.AES = type(sys)('AES')
token_module.AES.AES_128_CBC = AES_128_CBC
token_module.AES.AES_256_CBC = AES_256_CBC
token_module.AES_128_CBC = AES_128_CBC
token_module.AES_256_CBC = AES_256_CBC
# Remove import statements and execute
import re
token_code = re.sub(r'^from RNS\.Cryptography.*$', '', token_code, flags=re.MULTILINE)
token_code = re.sub(r'^import (?:os|time)$', '', token_code, flags=re.MULTILINE)
exec(compile(token_code, 'Token.py', 'exec'), token_module.__dict__)
sys.modules['RNS_Token'] = token_module
Token = token_module

# Pre-register a fake RNS.Cryptography.Hashes module to satisfy eddsa.py import
# This prevents triggering the full RNS import chain for the crypto-only path.
#
# CONDITIONAL: only install the stub when a real, fully-initialised RNS is NOT
# already resident. This file is executed under TWO module identities — as
# `__main__` (run as a script) and as `bridge_server` (`from bridge_server
# import ...` inside wire_tcp.py). The SECOND execution would otherwise clobber
# sys.modules['RNS'] — which the first identity's startup pre-warm already
# populated with the genuine full RNS — back down to this stub. That forces the
# second identity's `_get_full_rns()` to wipe + reimport the LIVE RNS module
# tree (RNS.Channel / RNS.Buffer), which races RNS's background callback threads
# (their lazy `from RNS.Channel import ...`) on CPython's import lock ->
# `_DeadlockError` / "partially initialized module 'RNS.Channel'". Leaving the
# real RNS in place lets `_get_full_rns()` adopt it instead of re-importing.
# (The real RNS exposes the genuine RNS.Cryptography.Hashes.sha512, so the
# crypto-only path is satisfied either way.)
_existing_rns = sys.modules.get('RNS')
if _existing_rns is None or getattr(_existing_rns, 'Channel', None) is None:
    fake_rns = type(sys)('RNS')
    fake_crypto = type(sys)('RNS.Cryptography')
    fake_hashes = type(sys)('RNS.Cryptography.Hashes')
    fake_hashes.sha512 = lambda data: hashlib.sha512(data).digest()
    sys.modules['RNS'] = fake_rns
    sys.modules['RNS.Cryptography'] = fake_crypto
    sys.modules['RNS.Cryptography.Hashes'] = fake_hashes
    fake_rns.Cryptography = fake_crypto
    fake_crypto.Hashes = fake_hashes



def hex_to_bytes(hex_str):
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data):
    """Convert bytes to hex string."""
    return data.hex()


def _maybe_num(value):
    """Pass a numeric RNS attribute straight through for JSON, preserving None.

    RNS stores the ingress-control knobs as plain ints/floats; this only
    normalises the absence case (None) and avoids leaking any non-number type
    into the JSON response. No value is computed here — the number is read
    verbatim off the live RNS interface object."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return value if isinstance(value, (int, float)) else float(value)


# Command handlers

def cmd_x25519_generate(params):
    """Generate X25519 keypair from seed."""
    seed = hex_to_bytes(params['seed'])
    priv = X25519.X25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key()
    return {
        'private_key': bytes_to_hex(priv.private_bytes()),
        'public_key': bytes_to_hex(pub.public_bytes())
    }


def cmd_x25519_public_from_private(params):
    """Derive public key from private key."""
    private_key = hex_to_bytes(params['private_key'])
    priv = X25519.X25519PrivateKey.from_private_bytes(private_key)
    pub = priv.public_key()
    return {
        'public_key': bytes_to_hex(pub.public_bytes())
    }


def cmd_x25519_exchange(params):
    """Perform X25519 key exchange."""
    private_key = hex_to_bytes(params['private_key'])
    peer_public_key = hex_to_bytes(params['peer_public_key'])

    priv = X25519.X25519PrivateKey.from_private_bytes(private_key)
    pub = X25519.X25519PublicKey.from_public_bytes(peer_public_key)
    shared = priv.exchange(pub)

    return {
        'shared_secret': bytes_to_hex(shared)
    }


def cmd_ed25519_generate(params):
    """Generate Ed25519 keypair from seed."""
    seed = hex_to_bytes(params['seed'])

    # Use the pure25519 implementation (from Cryptography path)
    from pure25519.ed25519_oop import SigningKey
    sk = SigningKey(seed)

    return {
        'private_key': bytes_to_hex(seed),
        'public_key': bytes_to_hex(sk.vk_s)
    }


def cmd_ed25519_sign(params):
    """Sign message with Ed25519."""
    private_key = hex_to_bytes(params['private_key'])
    message = hex_to_bytes(params['message'])

    from pure25519.ed25519_oop import SigningKey
    sk = SigningKey(private_key)
    signature = sk.sign(message)

    return {
        'signature': bytes_to_hex(signature)
    }


def cmd_ed25519_verify(params):
    """Verify Ed25519 signature."""
    public_key = hex_to_bytes(params['public_key'])
    message = hex_to_bytes(params['message'])
    signature = hex_to_bytes(params['signature'])

    from pure25519.ed25519_oop import VerifyingKey
    try:
        vk = VerifyingKey(public_key)
        vk.verify(signature, message)
        return {'valid': True}
    except Exception:
        return {'valid': False}


def cmd_sha256(params):
    """Compute SHA-256 hash."""
    data = hex_to_bytes(params['data'])
    hash_result = hashlib.sha256(data).digest()
    return {
        'hash': bytes_to_hex(hash_result)
    }


def cmd_sha512(params):
    """Compute SHA-512 hash."""
    data = hex_to_bytes(params['data'])
    hash_result = hashlib.sha512(data).digest()
    return {
        'hash': bytes_to_hex(hash_result)
    }


def cmd_hmac_sha256(params):
    """Compute HMAC-SHA256."""
    key = hex_to_bytes(params['key'])
    data = hex_to_bytes(params['message'])

    hmac_result = HMAC.new(key, data).digest()
    return {
        'hmac': bytes_to_hex(hmac_result)
    }


def cmd_hkdf(params):
    """Derive key using HKDF."""
    length = int(params['length'])
    ikm = hex_to_bytes(params['ikm'])
    salt = hex_to_bytes(params['salt']) if params.get('salt') else None
    info = hex_to_bytes(params['info']) if params.get('info') else None

    derived = HKDF.hkdf(length=length, derive_from=ikm, salt=salt, context=info)
    return {
        'derived_key': bytes_to_hex(derived)
    }


def cmd_pkcs7_pad(params):
    """Apply PKCS7 padding."""
    data = hex_to_bytes(params['data'])
    padded = PKCS7.pad(data)
    return {
        'padded': bytes_to_hex(padded)
    }


def cmd_pkcs7_unpad(params):
    """Remove PKCS7 padding."""
    data = hex_to_bytes(params['data'])
    unpadded = PKCS7.unpad(data)
    return {
        'unpadded': bytes_to_hex(unpadded)
    }


def cmd_aes_encrypt(params):
    """Encrypt with AES-CBC."""
    plaintext = hex_to_bytes(params['plaintext'])
    key = hex_to_bytes(params['key'])
    iv = hex_to_bytes(params['iv'])
    mode = params.get('mode', 'AES_256_CBC')

    # Pad plaintext
    padded = PKCS7.pad(plaintext)

    if mode == 'AES_128_CBC':
        ciphertext = AES_128_CBC.encrypt(padded, key, iv)
    else:
        ciphertext = AES_256_CBC.encrypt(padded, key, iv)

    return {
        'ciphertext': bytes_to_hex(ciphertext)
    }


def cmd_aes_decrypt(params):
    """Decrypt with AES-CBC."""
    ciphertext = hex_to_bytes(params['ciphertext'])
    key = hex_to_bytes(params['key'])
    iv = hex_to_bytes(params['iv'])
    mode = params.get('mode', 'AES_256_CBC')

    if mode == 'AES_128_CBC':
        plaintext = AES_128_CBC.decrypt(ciphertext, key, iv)
    else:
        plaintext = AES_256_CBC.decrypt(ciphertext, key, iv)

    # Unpad
    unpadded = PKCS7.unpad(plaintext)
    return {
        'plaintext': bytes_to_hex(unpadded)
    }


def cmd_aes_256_cbc_encrypt(params):
    """Raw AES-256-CBC block-cipher encryption — NO padding.

    Delegates to real RNS.Cryptography.AES.AES_256_CBC.encrypt, routing
    through RNS's own provider dispatch (PYCA or the internal pure-Python
    AES, whichever the install selected). This is the bare block cipher: the
    plaintext MUST already be a multiple of the 16-byte AES block size, and
    the ciphertext is exactly the same length as the plaintext (no PKCS7
    growth). Distinct from `aes_encrypt`, which is the PKCS7+CBC composite
    that RNS's Token layer uses and which grows the input to the next block
    boundary. RNS does no padding in AES.py itself (AES.py:77-95); padding
    lives only in Token.py. (N-M2)
    """
    RNS = _get_full_rns()
    from RNS.Cryptography.AES import AES_256_CBC as _RNS_AES_256_CBC
    plaintext = hex_to_bytes(params['plaintext'])
    key = hex_to_bytes(params['key'])
    iv = hex_to_bytes(params['iv'])
    return {
        'ciphertext': bytes_to_hex(_RNS_AES_256_CBC.encrypt(plaintext, key, iv))
    }


def cmd_aes_256_cbc_decrypt(params):
    """Raw AES-256-CBC block-cipher decryption — NO unpadding.

    Delegates to real RNS.Cryptography.AES.AES_256_CBC.decrypt. Returns the
    raw decrypted blocks verbatim; it does NOT strip PKCS7 padding (that is
    `aes_decrypt`'s job). Round-trips `aes_256_cbc_encrypt` byte-for-byte.
    """
    RNS = _get_full_rns()
    from RNS.Cryptography.AES import AES_256_CBC as _RNS_AES_256_CBC
    ciphertext = hex_to_bytes(params['ciphertext'])
    key = hex_to_bytes(params['key'])
    iv = hex_to_bytes(params['iv'])
    return {
        'plaintext': bytes_to_hex(_RNS_AES_256_CBC.decrypt(ciphertext, key, iv))
    }


def cmd_token_encrypt(params):
    """Encrypt plaintext into an RNS Token (Fernet-like: AES-256-CBC + HMAC).

    Delegates to real RNS Token.encrypt. RNS generates the AES IV internally
    and fresh per call, so this is non-deterministic by construction — two
    calls with identical key+plaintext return different tokens. Tests must
    round-trip through token_decrypt, not byte-compare. (The old IV-injection
    branch hand-assembled iv+ciphertext+hmac to fake a deterministic token;
    there is no honest way to inject the IV into real Token.encrypt.)
    """
    key = hex_to_bytes(params['key'])
    plaintext = hex_to_bytes(params['plaintext'])
    token_obj = Token.Token(key)
    return {'token': bytes_to_hex(token_obj.encrypt(plaintext))}


def cmd_token_decrypt(params):
    """Decrypt using Token."""
    key = hex_to_bytes(params['key'])
    token_bytes = hex_to_bytes(params['token'])

    token_obj = Token.Token(key)
    plaintext = token_obj.decrypt(token_bytes)

    return {
        'plaintext': bytes_to_hex(plaintext)
    }


def cmd_token_verify_hmac(params):
    """Verify Token HMAC."""
    key = hex_to_bytes(params['key'])
    token_bytes = hex_to_bytes(params['token'])

    token_obj = Token.Token(key)
    valid = token_obj.verify_hmac(token_bytes)

    return {
        'valid': valid
    }


def cmd_token_generate_key(params):
    """Generate a Token key for a chosen AES mode via real RNS.

    Delegates to RNS.Cryptography.Token.Token.generate_key(mode), mapping the
    `mode` string to the genuine RNS AES class object that generate_key
    dispatches on (Token.py:53-56). This pins the documented key lengths —
    AES_128_CBC -> 32 bytes (a 16-byte signing key + 16-byte encryption key),
    AES_256_CBC (the default) -> 64 bytes (32+32) — and the TypeError RNS
    raises for any unrecognised mode. Previously generate_key was reachable
    only implicitly through GROUP key creation in the default mode, so neither
    the 128-bit length nor the invalid-mode path was observable. (N-Mcrypto)
    """
    RNS = _get_full_rns()
    from RNS.Cryptography.AES import AES_128_CBC as _AES128, AES_256_CBC as _AES256
    from RNS.Cryptography.Token import Token as _Token

    mode_name = params.get('mode', 'AES_256_CBC')
    # Map the request string onto the REAL RNS AES class generate_key compares
    # against. An unknown string is forwarded verbatim so RNS itself raises the
    # TypeError (we do not synthesise the error ourselves).
    mode_map = {'AES_128_CBC': _AES128, 'AES_256_CBC': _AES256}
    mode_arg = mode_map.get(mode_name, mode_name)
    key = _Token.generate_key(mode_arg)
    return {'key': bytes_to_hex(key)}


def cmd_crypto_provider_op(params):
    """Run one primitive through a CHOSEN RNS crypto provider (internal|pyca).

    RNS selects its crypto backend once at import time (Provider.py): the
    pure-Python primitives (PROVIDER_INTERNAL) or the OpenSSL/PyCA bindings
    (PROVIDER_PYCA). Every other bridge command exercises only whichever the
    install happens to pick, so the two providers are never compared. This
    command drives the SAME input through a NAMED provider's REAL RNS
    implementation so a test can assert byte-identical output across both
    backends (the conformance requirement that the two providers are drop-in
    equivalent on the wire).

    No protocol bytes are assembled here — every value is produced by a genuine
    RNS class:
      * X25519/Ed25519 dispatch on distinct classes — internal lives in
        RNS.Cryptography.X25519/.Ed25519, PyCA in RNS.Cryptography.Proxies — so
        we import the chosen pair directly.
      * AES_256_CBC dispatches INSIDE RNS.Cryptography.AES on Provider.PROVIDER;
        we temporarily set that flag and reload the module so RNS's own dispatch
        selects the requested backend, then restore it. (N-Mcrypto)
    """
    RNS = _get_full_rns()
    import importlib
    import RNS.Cryptography.Provider as _cp

    op = params['op']
    provider = params['provider']
    if provider not in ('internal', 'pyca'):
        raise ValueError(f"Unknown provider: {provider}")

    if op == 'x25519_exchange':
        if provider == 'internal':
            from RNS.Cryptography.X25519 import X25519PrivateKey as Priv, X25519PublicKey as Pub
        else:
            from RNS.Cryptography.Proxies import (
                X25519PrivateKeyProxy as Priv, X25519PublicKeyProxy as Pub)
        priv = Priv.from_private_bytes(hex_to_bytes(params['private_key']))
        peer = Pub.from_public_bytes(hex_to_bytes(params['peer_public_key']))
        return {'result': bytes_to_hex(priv.exchange(peer))}

    if op == 'ed25519_sign':
        if provider == 'internal':
            from RNS.Cryptography.Ed25519 import Ed25519PrivateKey as Priv
        else:
            from RNS.Cryptography.Proxies import Ed25519PrivateKeyProxy as Priv
        priv = Priv.from_private_bytes(hex_to_bytes(params['private_key']))
        return {'result': bytes_to_hex(priv.sign(hex_to_bytes(params['message'])))}

    if op == 'ed25519_verify':
        if provider == 'internal':
            from RNS.Cryptography.Ed25519 import Ed25519PublicKey as Pub
        else:
            from RNS.Cryptography.Proxies import Ed25519PublicKeyProxy as Pub
        pub = Pub.from_public_bytes(hex_to_bytes(params['public_key']))
        try:
            pub.verify(hex_to_bytes(params['signature']), hex_to_bytes(params['message']))
            return {'valid': True}
        except Exception:
            return {'valid': False}

    if op == 'aes_256_cbc_encrypt':
        import RNS.Cryptography.AES as _AESmod
        target = _cp.PROVIDER_INTERNAL if provider == 'internal' else _cp.PROVIDER_PYCA
        saved = _cp.PROVIDER
        try:
            _cp.PROVIDER = target
            importlib.reload(_AESmod)
            ct = _AESmod.AES_256_CBC.encrypt(
                hex_to_bytes(params['plaintext']),
                hex_to_bytes(params['key']),
                hex_to_bytes(params['iv']))
        finally:
            _cp.PROVIDER = saved
            importlib.reload(_AESmod)
        return {'result': bytes_to_hex(ct)}

    raise ValueError(f"Unknown op: {op}")


def cmd_identity_from_private_key(params):
    """Derive public key + hash from a 64-byte Identity private key.

    Delegates to real RNS.Identity.from_bytes — no hand-rolled key split or
    hash composition. RNS.Identity splits the 64-byte key into its X25519(32)
    + Ed25519(32) halves, derives both public keys, and computes
    hash = truncated_hash(public_key) itself.
    """
    RNS = _get_full_rns()
    private_key = hex_to_bytes(params['private_key'])
    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    return {
        'public_key': bytes_to_hex(identity.get_public_key()),
        'hash': bytes_to_hex(identity.hash),
        'hexhash': identity.hexhash,
    }


def cmd_identity_encrypt(params):
    """Encrypt plaintext for an Identity's public key.

    Delegates to real RNS.Identity.encrypt. RNS generates the ephemeral
    X25519 key and the AES IV internally and fresh per call — there is no
    honest way to inject them, so this command is non-deterministic by
    construction (two calls with identical input return different
    ciphertext). Tests must round-trip through identity_decrypt.
    """
    RNS = _get_full_rns()
    public_key = hex_to_bytes(params['public_key'])
    plaintext = hex_to_bytes(params['plaintext'])
    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(public_key)
    return {'ciphertext': bytes_to_hex(identity.encrypt(plaintext))}


def cmd_identity_decrypt(params):
    """Decrypt a ciphertext token with an Identity's 64-byte private key.

    Delegates to real RNS.Identity.decrypt. Returns plaintext=None if the
    token does not authenticate (RNS.Identity.decrypt returns None).
    """
    RNS = _get_full_rns()
    private_key = hex_to_bytes(params['private_key'])
    ciphertext = hex_to_bytes(params['ciphertext'])
    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    plaintext = identity.decrypt(ciphertext)
    return {'plaintext': bytes_to_hex(plaintext) if plaintext is not None else None}


def cmd_identity_sign(params):
    """Sign a message with an Identity's 64-byte private key.

    Delegates to real RNS.Identity.sign (Ed25519, deterministic).
    """
    RNS = _get_full_rns()
    private_key = hex_to_bytes(params['private_key'])
    message = hex_to_bytes(params['message'])
    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    return {'signature': bytes_to_hex(identity.sign(message))}


def cmd_identity_verify(params):
    """Verify an Ed25519 signature against an Identity's public key.

    Delegates to real RNS.Identity.validate.
    """
    RNS = _get_full_rns()
    public_key = hex_to_bytes(params['public_key'])
    message = hex_to_bytes(params['message'])
    signature = hex_to_bytes(params['signature'])
    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(public_key)
    return {'valid': bool(identity.validate(signature, message))}


def cmd_identity_hash(params):
    """Compute the Identity hash of a 64-byte public key.

    Delegates to real RNS.Identity — the hash is truncated_hash(public_key),
    computed by RNS.Identity.update_hashes when the public key is loaded.
    """
    RNS = _get_full_rns()
    public_key = hex_to_bytes(params['public_key'])
    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(public_key)
    return {'hash': bytes_to_hex(identity.hash)}


def cmd_identity_to_file(params):
    """Persist an Identity (from 64-byte private key) to a temp file on
    disk via real RNS.Identity.to_file, and return the path.

    Delegates straight to RNS.Identity.from_bytes(...).to_file(...) —
    no hand-rolled file format. The path is in a per-bridge tempdir so
    repeated calls don't collide. Tests pair this with identity_from_file
    to round-trip the on-disk identity format Sideband + other apps use.
    """
    import tempfile
    RNS = _get_full_rns()
    private_key = hex_to_bytes(params['private_key'])
    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    path = tempfile.NamedTemporaryFile(
        prefix='conformance_identity_', suffix='.bin', delete=False
    ).name
    if not identity.to_file(path):
        raise IOError(f"RNS.Identity.to_file returned False for path {path}")
    return {'path': path}


def cmd_identity_from_file(params):
    """Load an Identity from a file on disk via real RNS.Identity.from_file.

    Returns the recovered identity's public_key + hash + hexhash on
    success, or {found: False} when from_file returns None (corrupt /
    invalid file).
    """
    RNS = _get_full_rns()
    path = params['path']
    identity = RNS.Identity.from_file(path)
    if identity is None:
        return {'found': False}
    return {
        'found': True,
        'public_key': bytes_to_hex(identity.get_public_key()),
        'hash': bytes_to_hex(identity.hash),
        'hexhash': identity.hexhash,
    }


def cmd_destination_hash(params):
    """Compute the 16-byte destination address for an identity + app_name +
    aspects.

    Delegates to real RNS.Destination.hash, which accepts the 16-byte
    identity hash directly. No hand-rolled name expansion or hash
    composition — RNS.Destination.hash does the expand_name -> name_hash ->
    truncated_hash(name_hash + identity_hash) chain itself.
    """
    RNS = _get_full_rns()
    identity_hash = hex_to_bytes(params['identity_hash'])
    app_name = params['app_name']
    aspects_param = params.get('aspects', '')
    if isinstance(aspects_param, list):
        aspects = aspects_param
    elif aspects_param:
        aspects = aspects_param.split(',')
    else:
        aspects = []
    dest_hash = RNS.Destination.hash(identity_hash, app_name, *aspects)
    return {'destination_hash': bytes_to_hex(dest_hash)}


def cmd_truncated_hash(params):
    """Compute the RNS truncated hash of arbitrary data.

    Delegates to real RNS.Identity.truncated_hash, which is
    full_hash(data)[:TRUNCATED_HASHLENGTH//8] (16 bytes in RNS 1.3.1). The
    previous implementation hardcoded `sha256(data)[:16]`; byte-identical
    today, but it would silently fail to track an RNS change to the hash
    algorithm or TRUNCATED_HASHLENGTH constant. full_hash is also reported,
    sourced from RNS.Identity.full_hash, so nothing about the length or the
    digest is hardcoded here.
    """
    RNS = _get_full_rns()
    data = hex_to_bytes(params['data'])
    return {
        'hash': bytes_to_hex(RNS.Identity.truncated_hash(data)),
        'full_hash': bytes_to_hex(RNS.Identity.full_hash(data)),
    }


def cmd_name_hash(params):
    """Compute the RNS name hash of a (dotted) destination name.

    Delegates to real RNS.Identity.full_hash and the real
    RNS.Identity.NAME_HASH_LENGTH constant — the name hash is
    full_hash(name)[:NAME_HASH_LENGTH//8], exactly as RNS.Destination.hash
    computes it internally. Nothing about the length is hardcoded here.
    """
    RNS = _get_full_rns()
    name = params['name']
    name_hash = RNS.Identity.full_hash(name.encode('utf-8'))[
        : RNS.Identity.NAME_HASH_LENGTH // 8
    ]
    return {'hash': bytes_to_hex(name_hash)}


def cmd_packet_build(params):
    """Build a real RNS.Packet on a real Destination, pack it, and report
    the wire bytes plus the fields RNS itself parsed back out.

    Honest replacement for the synthetic packet_pack / packet_flags commands,
    which hand-assembled the header and bit-packed the flags byte. RNS only
    produces a packet's wire format through Packet.pack() against a real
    Destination — there is no "format these arbitrary header fields" entry
    point. dest_type selects the destination kind ('plain', 'single' or
    'group'), which sets the destination_type flag bits and decides whether the
    payload is encrypted: PLAIN carries the payload in the clear so the wire
    bytes round-trip exactly, SINGLE encrypts non-announce data with the
    recipient identity so only the header bytes do, and GROUP encrypts
    non-announce data with a symmetric Token key (same "header-only" round-trip
    as SINGLE).

    header_type selects the wire header format and accepts either the
    human-friendly numbers 1 / 2 (default 1 = HEADER_1) or the strings
    "HEADER_1" / "HEADER_2":

      * HEADER_1 (default) — the normal single-hop header (flags, hops,
        destination_hash, context, payload).
      * HEADER_2 — the transport-relayed header that carries a 16-byte
        transport_id between the hops byte and the destination_hash. RNS
        only assembles a HEADER_2 packet through Packet.pack() for ANNOUNCE
        packets (Packet.py:220-229), so HEADER_2 requires packet_type ==
        ANNOUNCE and a 16-byte `transport_id` param; any other packet_type
        is rejected with a clear error rather than crashing on RNS's
        internal "must have a transport ID" / unset-ciphertext path. The
        returned `hash` excludes the transport_id (Packet.get_hash masks it
        out, Packet.py:356-360) so a HEADER_2 announce hashes identically to
        its HEADER_1 equivalent — which the conformance tests assert. (N-M10)
    """
    RNS = _get_full_rns()
    dest_type = params.get('dest_type', 'plain')
    packet_type = int(params.get('packet_type', RNS.Packet.DATA))
    context = int(params.get('context', 0))
    context_flag = int(params.get('context_flag', 0))
    transport_type = int(params.get('transport_type', RNS.Transport.BROADCAST))
    hops = int(params.get('hops', 0))
    data = hex_to_bytes(params.get('data', ''))

    # Resolve header_type from the human "1"/"2" or "HEADER_1"/"HEADER_2"
    # convention to the RNS constant. (RNS values are HEADER_1=0, HEADER_2=1,
    # which would collide with the human "1"; the param is the human form.)
    header_type_param = params.get('header_type', 1)
    header_type_map = {
        1: RNS.Packet.HEADER_1, 2: RNS.Packet.HEADER_2,
        "1": RNS.Packet.HEADER_1, "2": RNS.Packet.HEADER_2,
        "HEADER_1": RNS.Packet.HEADER_1, "HEADER_2": RNS.Packet.HEADER_2,
    }
    if header_type_param not in header_type_map:
        raise ValueError(
            f"unsupported header_type: {header_type_param!r} "
            "(use 1 / 2 or 'HEADER_1' / 'HEADER_2')"
        )
    header_type = header_type_map[header_type_param]

    transport_id = None
    if header_type == RNS.Packet.HEADER_2:
        if packet_type != RNS.Packet.ANNOUNCE:
            raise ValueError(
                "HEADER_2 packets are only buildable for ANNOUNCE packet_type "
                f"({RNS.Packet.ANNOUNCE}); RNS.Packet.pack only assembles a "
                "HEADER_2 header for announces (Packet.py:220-229)."
            )
        if 'transport_id' not in params or params['transport_id'] is None:
            raise ValueError("HEADER_2 packets require a 16-byte transport_id")
        transport_id = hex_to_bytes(params['transport_id'])
        if len(transport_id) != RNS.Identity.TRUNCATED_HASHLENGTH // 8:
            raise ValueError(
                f"transport_id must be {RNS.Identity.TRUNCATED_HASHLENGTH // 8} "
                f"bytes, got {len(transport_id)}"
            )

    if dest_type == 'plain':
        destination = RNS.Destination(
            None, RNS.Destination.OUT, RNS.Destination.PLAIN,
            "conformance", "packet",
        )
    elif dest_type == 'single':
        destination = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE,
            "conformance", "packet",
        )
    elif dest_type == 'group':
        # GROUP destinations are symmetric-key. RNS forbids an outbound
        # destination of any non-PLAIN type without identity material
        # (Destination.py:178-179), and the GROUP encrypt path raises unless a
        # symmetric key exists (Destination.py:601-609), so build with an
        # Identity and call create_keys() to mint the Token key before pack().
        # The GROUP destination_type bits (RNS.Destination.GROUP == 0x01) are
        # set by get_packed_flags from destination.type (Packet.py:173); a DATA
        # packet's payload is then encrypted by destination.encrypt, exactly as
        # for SINGLE, so only the header bytes round-trip through unpack().
        destination = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.GROUP,
            "conformance", "packet",
        )
        destination.create_keys()
    else:
        raise ValueError(
            f"unsupported dest_type: {dest_type!r} "
            "(use 'plain', 'single' or 'group')"
        )

    packet = RNS.Packet(
        destination, data,
        packet_type=packet_type,
        context=context,
        transport_type=transport_type,
        header_type=header_type,
        transport_id=transport_id,
        context_flag=context_flag,
        create_receipt=False,
    )
    packet.hops = hops
    packet.pack()
    raw = packet.raw

    # Read the fields back the way any receiver does — via a real unpack.
    parsed = RNS.Packet(None, None)
    parsed.raw = raw
    parsed.unpack()
    return {
        'raw': bytes_to_hex(raw),
        'flags': raw[0],
        'hops': parsed.hops,
        'header_type': parsed.header_type,
        'context_flag': parsed.context_flag,
        'transport_type': parsed.transport_type,
        'destination_type': parsed.destination_type,
        'packet_type': parsed.packet_type,
        'destination_hash': bytes_to_hex(parsed.destination_hash),
        'transport_id': (
            bytes_to_hex(parsed.transport_id)
            if parsed.transport_id is not None else None
        ),
        'context': parsed.context,
        'data': bytes_to_hex(parsed.data),
        'hash': bytes_to_hex(parsed.get_hash()),
    }


def cmd_packet_unpack(params):
    """Unpack raw packet bytes into their wire-format fields.

    Delegates to real RNS.Packet.unpack — exactly the parse a receiver runs.
    Returns every field RNS populated on the packet, plus the raw flags byte
    and the packet hash.
    """
    RNS = _get_full_rns()
    raw = hex_to_bytes(params['raw'])
    packet = RNS.Packet(None, None)
    packet.raw = raw
    if not packet.unpack():
        return {'unpacked': False}
    return {
        'unpacked': True,
        'flags': raw[0],
        'hops': packet.hops,
        'header_type': packet.header_type,
        'context_flag': packet.context_flag,
        'transport_type': packet.transport_type,
        'destination_type': packet.destination_type,
        'packet_type': packet.packet_type,
        'destination_hash': bytes_to_hex(packet.destination_hash),
        'transport_id': (
            bytes_to_hex(packet.transport_id)
            if packet.transport_id is not None else None
        ),
        'context': packet.context,
        'data': bytes_to_hex(packet.data),
        'hash': bytes_to_hex(packet.get_hash()),
    }


def cmd_packet_hash(params):
    """Compute the hash of a raw packet.

    Delegates to real RNS.Packet — unpack the raw bytes, then read get_hash(),
    which RNS itself uses to populate the dedup hashlist. The hashable part
    deliberately excludes the hops byte and HEADER_2 transport_id so the
    hash stays stable as the packet propagates through transports.
    """
    RNS = _get_full_rns()
    raw = hex_to_bytes(params['raw'])
    packet = RNS.Packet(None, None)
    packet.raw = raw
    if not packet.unpack():
        raise ValueError("malformed packet — RNS.Packet.unpack rejected it")
    return {'hash': bytes_to_hex(packet.get_hash())}


def cmd_packet_build_raw_header2(params):
    """Build a HEADER_2 packet and call RNS.Packet.pack() WITHOUT any
    pre-validation, surfacing RNS's OWN failure.

    Unlike packet_build (which guards HEADER_2 in the harness before pack),
    this constructs the real RNS.Packet exactly as the caller asks — including
    omitting the transport_id (transport_id=None) or asking for a non-ANNOUNCE
    HEADER_2 — and lets RNS.Packet.pack() decide. RNS.Packet.pack
    (Packet.py:220-229) raises IOError("Packet with header type 2 must have a
    transport ID") when transport_id is None, and for a non-ANNOUNCE HEADER_2 it
    never assigns self.ciphertext, so .raw assembly raises AttributeError. Either
    way the failure comes from RNS, not the harness.

    Params: {packet_type (int, default ANNOUNCE), transport_id (optional hex),
    data (hex, optional)}. Returns {raw, raw_len} on a successful pack, or
    {error: <RNS exception message>, error_type: <exception class name>} when
    RNS refuses.
    """
    RNS = _get_full_rns()
    packet_type = int(params.get('packet_type', RNS.Packet.ANNOUNCE))
    data = hex_to_bytes(params.get('data', '')) or b'\x00'
    transport_id = (
        hex_to_bytes(params['transport_id'])
        if params.get('transport_id') is not None else None
    )
    # A SINGLE OUT destination supplies destination.hash for the HEADER_2 body.
    destination = RNS.Destination(
        RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE,
        "conformance", "packet",
    )
    packet = RNS.Packet(
        destination, data,
        packet_type=packet_type,
        header_type=RNS.Packet.HEADER_2,
        transport_id=transport_id,
        create_receipt=False,
    )
    try:
        packet.pack()
    except Exception as e:
        return {'error': str(e), 'error_type': type(e).__name__}
    return {'raw': bytes_to_hex(packet.raw), 'raw_len': len(packet.raw)}


def cmd_packet_resend_observe(params):
    """Pack a packet, then drive real RNS.Packet.resend() and report whether the
    re-pack produced fresh wire bytes.

    RNS.Packet.resend (Packet.py:305-323) re-packs the packet before
    re-transmitting precisely so an encrypted destination gets fresh ephemeral
    key material / IV on every attempt. This builds a real RNS.Packet for the
    requested dest_type, packs it (raw_1/hash_1), marks it sent (resend's
    precondition), then calls the real resend() — which internally calls
    self.pack() again — and reads raw_2/hash_2 straight off the packet RNS
    mutated. No interface is attached, so resend()'s Transport.outbound returns
    False, but the re-pack (the byte-generation under test) still runs.

    Params: {dest_type: 'single'|'plain'|'group', data (hex)}. Returns
    {raw_1, hash_1, raw_2, hash_2}.
    """
    RNS = _get_full_rns()
    dest_type = params.get('dest_type', 'single')
    data = hex_to_bytes(params.get('data', '')) or b'conformance-resend'
    if dest_type == 'plain':
        destination = RNS.Destination(
            None, RNS.Destination.OUT, RNS.Destination.PLAIN,
            "conformance", "packet",
        )
    elif dest_type == 'group':
        destination = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.GROUP,
            "conformance", "packet",
        )
        destination.create_keys()
    else:
        destination = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE,
            "conformance", "packet",
        )
    packet = RNS.Packet(destination, data, create_receipt=False)
    packet.pack()
    raw_1 = bytes_to_hex(packet.raw)
    hash_1 = bytes_to_hex(packet.get_hash())
    # resend() requires the packet to have been sent already; RNS sets .sent in
    # send(). We set it so resend's precondition passes and the real re-pack runs.
    packet.sent = True
    packet.resend()
    raw_2 = bytes_to_hex(packet.raw)
    hash_2 = bytes_to_hex(packet.get_hash())
    return {'raw_1': raw_1, 'hash_1': hash_1, 'raw_2': raw_2, 'hash_2': hash_2}
# Announce operations

def cmd_announce_build(params):
    """Build a real RNS announce packet without putting it on the wire.

    Delegates to real RNS.Destination.announce(send=False), which returns the
    fully-constructed announce Packet (signed by the destination's Identity,
    with ratchet embedded if Destination.ratchets is non-empty, with
    context_flag bookkeeping). Packs it and returns the wire bytes plus the
    parsed announce_data fields a receiver would extract. Requires a running
    Reticulum instance to register an IN destination — the bridge spins up a
    minimal no-interface one lazily.

    The previous synthetic announce_pack / announce_sign / announce_unpack
    hand-rolled the field concatenation, the signed-data layout, and the
    Ed25519 signing on top of pure25519. Their output happened to match RNS
    so the suite stayed green, but any drift in the announce signed-data
    layout (e.g. RNS reordering fields, changing what app_data scope is
    signed) would be invisible because the bridge mirrored its own copy.
    """
    RNS = _ensure_minimal_rns()
    private_key = hex_to_bytes(params['private_key'])
    app_name = params['app_name']
    aspects_param = params.get('aspects', [])
    if isinstance(aspects_param, list):
        aspects = aspects_param
    elif aspects_param:
        aspects = aspects_param.split(',')
    else:
        aspects = []
    app_data = hex_to_bytes(params['app_data']) if params.get('app_data') else None
    enable_ratchets = bool(params.get('enable_ratchets', False))
    emission_ts = params.get('emission_ts')  # optional: int seconds-since-epoch

    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    # Reuse an existing registered destination if the same identity+name has
    # already been announced through this bridge — RNS raises KeyError
    # ("Attempt to register an already registered destination") on a second
    # construction, but real workflows re-announce the same destination
    # repeatedly. announce_build is called once per test, so the lifetime
    # match between tests in the same bridge process is identity+name.
    expected_hash = RNS.Destination.hash(identity, app_name, *aspects)
    destination = None
    for existing in RNS.Transport.destinations:
        if existing.hash == expected_hash:
            destination = existing
            break
    if destination is None:
        destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, *aspects
        )
    if enable_ratchets:
        # RNS controls the ratchet lifecycle via Destination.enable_ratchets
        # against a state file; on enable() + the first rotate_ratchets()
        # inside announce() it generates a fresh ratchet and writes it. We
        # use a fresh path (no file yet — _reload_ratchets initialises a new
        # one) to honour that contract; the bridge does not inject a
        # specific ratchet, tests must read what RNS produced.
        import tempfile
        ratchet_dir = tempfile.mkdtemp(prefix='rns_announce_ratchets_')
        destination.enable_ratchets(os.path.join(ratchet_dir, 'ratchets.bin'))

    # An optional `emission_ts` lets a caller pin the announce's wall-clock
    # time — RNS embeds `int(time.time()).to_bytes(5, "big")` in the
    # random_hash and stamps `now = time.time()` on the path response. The
    # behavioral path-replacement tests rely on this to compare fresh and
    # stale announces. Rather than synthesise the embed by hand we patch
    # `time.time` for the duration of one announce() call, so RNS still does
    # all the real work — it just sees the wall-clock value we pin.
    import time as _time
    if emission_ts is not None:
        _orig_time = _time.time
        _time.time = lambda: float(emission_ts)
        try:
            packet = destination.announce(app_data=app_data, send=False)
        finally:
            _time.time = _orig_time
    else:
        packet = destination.announce(app_data=app_data, send=False)
    packet.pack()
    raw = packet.raw

    # Parse what RNS just produced — the field layout RNS itself wrote.
    keysize = RNS.Identity.KEYSIZE // 8
    name_hash_len = RNS.Identity.NAME_HASH_LENGTH // 8
    ratchet_size = RNS.Identity.RATCHETSIZE // 8
    sig_len = RNS.Identity.SIGLENGTH // 8
    has_ratchet = packet.context_flag == RNS.Packet.FLAG_SET
    data = packet.data
    pubkey = data[:keysize]
    name_hash = data[keysize:keysize + name_hash_len]
    # The random_hash slice is 10 bytes — Destination.announce produces it as
    # 5 bytes of random + 5 bytes big-endian timestamp; the slice length is
    # the part of the wire format that is not yet a named RNS constant.
    random_hash_len = 10
    random_hash_off = keysize + name_hash_len
    random_hash = data[random_hash_off:random_hash_off + random_hash_len]
    cursor = random_hash_off + random_hash_len
    if has_ratchet:
        ratchet = data[cursor:cursor + ratchet_size]
        cursor += ratchet_size
    else:
        ratchet = b""
    signature = data[cursor:cursor + sig_len]
    cursor += sig_len
    app_data_out = data[cursor:]

    return {
        'raw': bytes_to_hex(raw),
        'destination_hash': bytes_to_hex(destination.hash),
        'announce_data': bytes_to_hex(data),
        'public_key': bytes_to_hex(pubkey),
        'name_hash': bytes_to_hex(name_hash),
        'random_hash': bytes_to_hex(random_hash),
        'ratchet': bytes_to_hex(ratchet) if ratchet else "",
        'signature': bytes_to_hex(signature),
        'app_data': bytes_to_hex(app_data_out),
        'has_ratchet': has_ratchet,
    }


def cmd_announce_validate(params):
    """Validate a real RNS announce packet.

    Delegates to real RNS.Identity.validate_announce, which checks the
    Ed25519 signature over (destination_hash + public_key + name_hash +
    random_hash + ratchet + app_data) and confirms the destination_hash in
    the header matches the one derived from the public_key + name_hash. The
    previous hand-rolled announce_verify reimplemented both checks on top of
    pure25519 + hashlib; if validate_announce's signed-data layout ever
    drifted (e.g. app_data scope, ratchet inclusion under context_flag) the
    bridge wouldn't follow.

    Returns the validation verdict plus the extracted ratchet (RNS's
    validate_announce returns only True/False, so the ratchet — when
    present — is read off packet.data at the offsets RNS itself parses to).
    """
    RNS = _ensure_minimal_rns()
    raw = hex_to_bytes(params['raw'])
    packet = RNS.Packet(None, None)
    packet.raw = raw
    if not packet.unpack():
        return {'valid': False, 'error': 'unpack_failed'}
    if packet.packet_type != RNS.Packet.ANNOUNCE:
        return {'valid': False, 'error': 'not_an_announce'}

    valid = bool(RNS.Identity.validate_announce(packet))
    result = {
        'valid': valid,
        'destination_hash': bytes_to_hex(packet.destination_hash),
        'has_ratchet': packet.context_flag == RNS.Packet.FLAG_SET,
    }
    if result['has_ratchet']:
        keysize = RNS.Identity.KEYSIZE // 8
        name_hash_len = RNS.Identity.NAME_HASH_LENGTH // 8
        ratchet_size = RNS.Identity.RATCHETSIZE // 8
        ratchet_off = keysize + name_hash_len + 10
        result['ratchet'] = bytes_to_hex(packet.data[ratchet_off:ratchet_off + ratchet_size])
    return result


# Ratchet operations

def cmd_ratchet_id(params):
    """Compute the 10-byte ratchet ID for a ratchet public key.

    Delegates to real RNS — the ratchet ID is
    RNS.Identity.full_hash(public)[:NAME_HASH_LENGTH//8], exactly what
    Identity._get_ratchet_id computes internally. Nothing here hardcodes
    the truncation length; it is read off the RNS constant.
    """
    RNS = _get_full_rns()
    ratchet_public = hex_to_bytes(params['ratchet_public'])
    rid = RNS.Identity.full_hash(ratchet_public)[: RNS.Identity.NAME_HASH_LENGTH // 8]
    return {'ratchet_id': bytes_to_hex(rid)}


def cmd_ratchet_public_from_private(params):
    """Derive public key from ratchet private key."""
    ratchet_private = hex_to_bytes(params['ratchet_private'])

    # Create X25519 key pair from private key
    ratchet_prv = X25519.X25519PrivateKey.from_private_bytes(ratchet_private)
    ratchet_pub = ratchet_prv.public_key()
    ratchet_pub_bytes = ratchet_pub.public_bytes()

    return {
        'ratchet_public': bytes_to_hex(ratchet_pub_bytes)
    }


def cmd_ratchet_encrypt(params):
    """Encrypt plaintext for an Identity, using a ratchet public key.

    Delegates to real RNS.Identity.encrypt(plaintext, ratchet=ratchet_public).
    RNS performs the ECDH-with-ratchet, HKDF (salt = identity's own hash),
    and Token encryption itself; the previous hand-rolled path took an
    injected identity_hash as the salt and reassembled iv+ciphertext+hmac
    by hand. Non-deterministic (fresh ephemeral key + IV per call) — tests
    must round-trip through ratchet_decrypt.
    """
    RNS = _get_full_rns()
    public_key = hex_to_bytes(params['public_key'])
    ratchet_public = hex_to_bytes(params['ratchet_public'])
    plaintext = hex_to_bytes(params['plaintext'])
    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(public_key)
    return {
        'ciphertext': bytes_to_hex(identity.encrypt(plaintext, ratchet=ratchet_public))
    }


def cmd_ratchet_decrypt(params):
    """Decrypt a ratchet-encrypted ciphertext with the Identity's private key,
    trialling one OR MORE candidate ratchet private keys.

    Delegates to real RNS.Identity.decrypt. The multi-ratchet trial loop
    (Identity.py:882-895) iterates the supplied ratchet list IN ORDER, first
    success wins, swallowing per-ratchet failures; and on success it writes the
    winning ratchet id onto the caller-supplied `ratchet_id_receiver`. We expose
    that by passing a tiny receiver object straight through and surfacing its
    `latest_ratchet_id` field — RNS computes the id (via Identity._get_ratchet_id),
    we only read it back.

    Params:
      private_key (hex)             — 64-byte Identity private key.
      ciphertext (hex)              — the ratchet-encrypted token.
      ratchet_privates (list[hex])  — ordered trial list (preferred).
      ratchet_private (hex)         — single-key back-compat shorthand.
      enforce_ratchets (bool)       — if true, fall-back to the static X25519
                                      key is forbidden (Identity returns None
                                      when no ratchet matches).
    """
    RNS = _get_full_rns()
    private_key = hex_to_bytes(params['private_key'])
    ciphertext = hex_to_bytes(params['ciphertext'])
    enforce = bool(params.get('enforce_ratchets', False))

    if params.get('ratchet_privates') is not None:
        ratchets = [hex_to_bytes(r) for r in params['ratchet_privates']]
    elif params.get('ratchet_private') is not None:
        ratchets = [hex_to_bytes(params['ratchet_private'])]
    else:
        ratchets = None

    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")

    class _RatchetIdReceiver:
        latest_ratchet_id = None

    receiver = _RatchetIdReceiver()
    plaintext = identity.decrypt(
        ciphertext,
        ratchets=ratchets,
        enforce_ratchets=enforce,
        ratchet_id_receiver=receiver,
    )
    return {
        'plaintext': bytes_to_hex(plaintext) if plaintext is not None else None,
        'latest_ratchet_id': bytes_to_hex(receiver.latest_ratchet_id)
                             if receiver.latest_ratchet_id is not None else None,
    }


def cmd_identity_remember(params):
    """Plant a known destination via real RNS.Identity.remember, surfacing the
    KEYSIZE//8 (64-byte) public-key length gate (Identity.py:101-102).

    Delegates entirely to RNS.Identity.remember — RNS itself raises TypeError
    when len(public_key) != Identity.KEYSIZE//8. We do not pre-check the length;
    we let RNS enforce it and report whether it accepted the key.

    Params: packet_hash(hex), destination_hash(hex), public_key(hex),
            app_data(hex|null).
    """
    RNS = _get_full_rns()
    packet_hash = hex_to_bytes(params['packet_hash'])
    destination_hash = hex_to_bytes(params['destination_hash'])
    public_key = hex_to_bytes(params['public_key'])
    app_data = hex_to_bytes(params['app_data']) if params.get('app_data') else None
    try:
        RNS.Identity.remember(packet_hash, destination_hash, public_key, app_data)
    except TypeError as e:
        return {'ok': False, 'error': 'TypeError', 'public_key_len': len(public_key)}
    # Confirm the plant took by recalling through real RNS (_no_use avoids
    # touching a running Reticulum instance's usage bookkeeping).
    recalled = RNS.Identity.recall(destination_hash, _no_use=True)
    return {
        'ok': True,
        'public_key_len': len(public_key),
        'recalled': recalled is not None,
    }


def cmd_identity_keyless_op(params):
    """Drive a crypto op on an Identity that holds NO key, pinning the KeyError
    path (Identity.decrypt:921 / sign:939 / encrypt:852).

    Delegates to real RNS: builds RNS.Identity(create_keys=False) and loads no
    key, then invokes the requested op so RNS itself decides to raise. We report
    the raised exception type rather than fabricating a result.

    Params: op ('decrypt'|'sign'|'encrypt'), data(hex).
    """
    RNS = _get_full_rns()
    op = params['op']
    data = hex_to_bytes(params['data'])
    identity = RNS.Identity(create_keys=False)
    try:
        if op == 'decrypt':
            result = identity.decrypt(data)
        elif op == 'sign':
            result = identity.sign(data)
        elif op == 'encrypt':
            result = identity.encrypt(data)
        else:
            raise ValueError(f"unknown op {op!r}")
    except KeyError as e:
        return {'raised': 'KeyError', 'message': str(e)}
    return {'raised': None, 'result': bytes_to_hex(result) if result is not None else None}



# Compression operations
def cmd_bz2_compress(params):
    """Compress data using BZ2.

    Returns compressed data and compression ratio.
    """
    import bz2

    data = hex_to_bytes(params['data'])

    compressed = bz2.compress(data)

    return {
        'compressed': bytes_to_hex(compressed),
        'original_size': len(data),
        'compressed_size': len(compressed),
        'ratio': len(compressed) / len(data) if len(data) > 0 else 0
    }


def cmd_bz2_decompress(params):
    """Decompress BZ2 data.

    Returns decompressed data.
    """
    import bz2

    compressed = hex_to_bytes(params['compressed'])

    decompressed = bz2.decompress(compressed)

    return {
        'decompressed': bytes_to_hex(decompressed),
        'size': len(decompressed)
    }


# ============================================================================
# Interface framing (HDLC / KISS deframing)
# ============================================================================
# These commands reverse the on-the-wire framing RNS applies in its serial /
# TCP interfaces, so a conformance test can frame a payload with RNS's own
# escaping and confirm an implementation recovers the exact original bytes.
# Both use the real RNS framing classes for their constants and the documented
# inverse of RNS's own send-side escape — there is no separate "deframe" entry
# point in RNS (the receive logic is inlined in each interface's read loop), so
# the un-stuffing here mirrors the exact byte-replacements those loops perform
# (e.g. TCPInterface.py:389-391).


def cmd_hdlc_deframe(params):
    """Strip HDLC framing and reverse byte-stuffing from a framed payload.

    Reverses RNS's HDLC framing (the framing TCPInterface uses:
    FLAG + HDLC.escape(data) + FLAG). Extracts the bytes between the first two
    FLAG (0x7E) delimiters, then undoes the byte-stuffing with the exact two
    replacements RNS's TCP read loop performs (TCPInterface.py:389-391):
    ESC+(FLAG^0x20) -> FLAG, then ESC+(ESC^0x20) -> ESC. Constants are read
    off the real RNS.Interfaces.TCPInterface.HDLC class, so a change to FLAG /
    ESC / ESC_MASK upstream is tracked rather than hardcoded.
    """
    RNS = _get_full_rns()
    from RNS.Interfaces.TCPInterface import HDLC
    framed = hex_to_bytes(params['framed'])
    start = framed.find(HDLC.FLAG)
    if start == -1:
        raise ValueError("no HDLC FLAG (0x7E) delimiter found in framed input")
    end = framed.find(HDLC.FLAG, start + 1)
    if end == -1:
        raise ValueError("unterminated HDLC frame: only one FLAG delimiter")
    frame = framed[start + 1:end]
    frame = frame.replace(
        bytes([HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK]), bytes([HDLC.FLAG])
    )
    frame = frame.replace(
        bytes([HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK]), bytes([HDLC.ESC])
    )
    return {'data': bytes_to_hex(frame)}


def cmd_kiss_deframe(params):
    """Strip KISS framing and reverse the TFEND/TFESC transpose.

    Reverses RNS's KISS framing (the framing KISSInterface uses:
    FEND + CMD_DATA + KISS.escape(data) + FEND). Extracts the bytes between
    the first two FEND (0xC0) delimiters, verifies the leading command byte is
    CMD_DATA (0x00), then undoes the transpose with the inverse of RNS's
    send-side escape: FESC+TFEND -> FEND, then FESC+TFESC -> FESC. Constants
    are read off the real RNS.Interfaces.KISSInterface.KISS class.
    """
    RNS = _get_full_rns()
    from RNS.Interfaces.KISSInterface import KISS
    framed = hex_to_bytes(params['framed'])
    start = framed.find(KISS.FEND)
    if start == -1:
        raise ValueError("no KISS FEND (0xC0) delimiter found in framed input")
    end = framed.find(KISS.FEND, start + 1)
    if end == -1:
        raise ValueError("unterminated KISS frame: only one FEND delimiter")
    inner = framed[start + 1:end]
    if len(inner) < 1:
        raise ValueError("empty KISS frame: no command byte")
    command = inner[0]
    if command != KISS.CMD_DATA:
        raise ValueError(
            f"unexpected KISS command byte {command:#04x}, expected "
            f"CMD_DATA ({KISS.CMD_DATA:#04x})"
        )
    payload = inner[1:]
    payload = payload.replace(
        bytes([KISS.FESC, KISS.TFEND]), bytes([KISS.FEND])
    )
    payload = payload.replace(
        bytes([KISS.FESC, KISS.TFESC]), bytes([KISS.FESC])
    )
    return {'data': bytes_to_hex(payload)}


# ============================================================================
# Interface framing/deframing driven through the REAL RNS interface read/write
# loops (not a bridge re-implementation).
#
# RNS does not expose its on-wire framing as standalone callables — the TX
# framing is inline in TCPClientInterface.process_outgoing (TCPInterface.py:
# 312-329) and the RX de-framing is inline in TCPClientInterface.read_loop
# (TCPInterface.py:337-398). Rather than mirror those byte-replacements in the
# bridge (which would be HANDROLLED), the two helpers below DRIVE the real RNS
# methods directly: they build a minimal stand-in object carrying exactly the
# attributes each method reads, hand it a capture/feed socket, and let RNS
# produce/parse every protocol byte. The bridge assembles no wire bytes itself,
# so these commands are honest live delegation to the implementation under test.


def _capture_interface_tx(kiss_framing, data):
    """Frame `data` exactly as RNS's TCPClientInterface.process_outgoing does.

    Calls the real (unbound) RNS transmit method with a stand-in whose socket
    captures the framed bytes RNS hands to sendall. All FLAG/FEND delimiting and
    byte-stuffing is RNS's (TCPInterface.py:312-329); the bridge only reads back
    what RNS produced."""
    _get_full_rns()
    from RNS.Interfaces.TCPInterface import TCPClientInterface
    import types

    class _CaptureSocket:
        def __init__(self):
            self.frames = []

        def sendall(self, payload):
            self.frames.append(payload)

    sock = _CaptureSocket()
    stand_in = types.SimpleNamespace(
        online=True, detached=False, writing=False,
        kiss_framing=kiss_framing, socket=sock, txb=0, parent_interface=None,
    )
    TCPClientInterface.process_outgoing(stand_in, data)
    if not sock.frames:
        raise RuntimeError("RNS process_outgoing produced no framed output")
    return sock.frames[0]


def _drive_interface_rx(kiss_framing, stream, hw_mtu):
    """Run RNS's real TCPClientInterface.read_loop over `stream`, returning the
    list of frames it delivers to process_incoming.

    The entire de-framing — FLAG/FEND scan, byte-stuffing reversal, the
    `len(frame) > HEADER_MINSIZE` runt drop, shared-FLAG buffer retention, KISS
    port-nibble strip and non-CMD_DATA ignore (TCPInterface.py:337-398) — is run
    by RNS. The bridge supplies only a feed socket (yields the stream once, then
    an empty read to end the loop) and a capturing process_incoming; it parses
    no protocol bytes itself."""
    _get_full_rns()
    from RNS.Interfaces.TCPInterface import TCPClientInterface
    import types

    delivered = []

    class _FeedSocket:
        def __init__(self, chunk):
            self.pending = [chunk]

        def recv(self, _n):
            if self.pending:
                return self.pending.pop(0)
            return b""

    stand_in = types.SimpleNamespace(
        online=True, detached=False, initiator=False,
        kiss_framing=kiss_framing, socket=_FeedSocket(stream), HW_MTU=hw_mtu,
    )
    stand_in.process_incoming = lambda frame: delivered.append(frame)
    stand_in.teardown = lambda: None
    TCPClientInterface.read_loop(stand_in)
    return delivered


def cmd_hdlc_frame(params):
    """Frame a payload with RNS's HDLC transmit framing (FLAG + escape + FLAG).

    Delegates to TCPClientInterface.process_outgoing (kiss_framing=False) and
    returns the captured wire bytes, so tests can pin the FLAG-delimited output
    and the ESC-before-FLAG escape order byte-for-byte."""
    data = hex_to_bytes(params['data'])
    return {'framed': bytes_to_hex(_capture_interface_tx(False, data))}


def cmd_kiss_frame(params):
    """Frame a payload with RNS's KISS transmit framing (FEND + CMD_DATA +
    escape + FEND), via TCPClientInterface.process_outgoing (kiss_framing=True)."""
    data = hex_to_bytes(params['data'])
    return {'framed': bytes_to_hex(_capture_interface_tx(True, data))}


def cmd_hdlc_deframe_stream(params):
    """Deframe a TCP/HDLC byte stream through RNS's real read loop.

    Returns every frame RNS delivers. Exercises the runt-drop rule
    (frames <= RNS.Reticulum.HEADER_MINSIZE == 19 bytes are silently dropped),
    multi-frame extraction and shared-FLAG buffer retention from one stream."""
    _get_full_rns()
    stream = hex_to_bytes(params['stream'])
    hw_mtu = int(params.get('hw_mtu', 262144))
    frames = _drive_interface_rx(False, stream, hw_mtu)
    return {'frames': [bytes_to_hex(f) for f in frames]}


def cmd_kiss_deframe_stream(params):
    """Deframe a TCP/KISS byte stream through RNS's real read loop.

    Mirrors the TCPInterface kiss_framing path: the leading byte's port nibble
    is stripped (command = byte & 0x0F, so 0x10/0x20 with low nibble 0 are
    accepted as CMD_DATA) and frames whose command != CMD_DATA are silently
    ignored (no frame delivered)."""
    _get_full_rns()
    stream = hex_to_bytes(params['stream'])
    hw_mtu = int(params.get('hw_mtu', 262144))
    frames = _drive_interface_rx(True, stream, hw_mtu)
    return {'frames': [bytes_to_hex(f) for f in frames]}


def cmd_auto_discovery_token(params):
    """Compute AutoInterface's peer-authentication token for a source address.

    Delegates to RNS.Identity.full_hash exactly as AutoInterface.discovery_handler
    does (AutoInterface.py:365): full_hash(group_id + ipv6_src.encode('utf-8')).
    The bridge performs no hashing itself."""
    RNS = _get_full_rns()
    group_id = hex_to_bytes(params['group_id'])
    addr = params['link_local_addr']
    token = RNS.Identity.full_hash(group_id + addr.encode("utf-8"))
    return {'token': bytes_to_hex(token)}


# Interface classes that fix HW_MTU at class scope (readable without opening a
# device). The serial-family interfaces (UDP/Pipe/Serial/KISS/RNode) set
# self.HW_MTU per-instance inside __init__ and cannot be read this way.
_CLASS_HW_MTU_INTERFACES = {
    'TCPInterface': ('RNS.Interfaces.TCPInterface', 'TCPInterface'),
    'AutoInterface': ('RNS.Interfaces.AutoInterface', 'AutoInterface'),
    'BackboneInterface': ('RNS.Interfaces.BackboneInterface', 'BackboneInterface'),
}


def cmd_interface_hw_mtu(params):
    """Read the class-level HW_MTU constant an RNS interface advertises.

    Returns RNS's own declared HW_MTU for the named interface class (read off
    the live class, not hardcoded in the bridge), letting tests pin the per-type
    fixed MTUs against the documented spec values."""
    _get_full_rns()
    import importlib
    itype = params['type']
    if itype not in _CLASS_HW_MTU_INTERFACES:
        return {'error': f"unsupported interface type {itype!r} "
                f"(class-level HW_MTU only: {sorted(_CLASS_HW_MTU_INTERFACES)})"}
    module_name, class_name = _CLASS_HW_MTU_INTERFACES[itype]
    cls = getattr(importlib.import_module(module_name), class_name)
    return {'hw_mtu': int(cls.HW_MTU)}


# ============================================================================
# Live Reticulum Networking Commands
# ============================================================================
# These commands start actual Reticulum instances for end-to-end
# interoperability testing. Unlike the crypto-only commands above, these
# use the full RNS import and manage network state.

# Global state for live networking
_rns_instance = None
_rns_module = None  # Cached RNS module

# Serialises the one-shot real `import RNS`. The genuine first load clears the
# standalone crypto shims (RNS_HMAC, ...) and any half-imported RNS.* before
# importing RNS cleanly; the lock makes that check-then-import atomic so two
# threads cannot both decide to wipe+reimport concurrently.
import threading as _threading
_rns_import_lock = _threading.Lock()


def _get_full_rns():
    """Return the process-wide real RNS module, importing it once if needed.

    Why this is careful about NOT re-importing once RNS is resident:

    This file is loaded under TWO distinct module identities — as ``__main__``
    (run as a script) and as ``bridge_server`` (``from bridge_server import
    _get_full_rns`` inside wire_tcp.py and friends). Each identity has its own
    ``_rns_module`` global, so a naive "wipe sys.modules + import RNS" runs
    ONCE PER IDENTITY. The second wipe lands AFTER the first identity has
    already started a live Reticulum (background read_loop / jobloop /
    watchdog / TCP serve_forever threads). Tearing RNS.Channel / RNS.Buffer out
    of sys.modules and re-importing them while those threads run their lazy
    ``from RNS.Channel import ...`` / ``from RNS.Buffer import ...`` races
    CPython's per-module import lock -> ``_frozen_importlib._DeadlockError`` or
    ``ImportError: cannot import name 'Channel' from partially initialized
    module 'RNS.Channel' (circular import)`` — the conformance flake.

    Fix: if a FULLY-initialised RNS is already resident in sys.modules (loaded
    by the startup pre-warm or by the other module identity), adopt it verbatim
    — never wipe+reimport a live module tree. The destructive clear only runs
    on the genuine first load, under the lock, which by construction happens
    before any Reticulum thread exists.
    """
    global _rns_module

    if _rns_module is not None:
        return _rns_module

    import importlib  # noqa: F401  (kept for parity with historical callers)
    import sys

    with _rns_import_lock:
        # Re-check under the lock — another thread may have completed the load.
        if _rns_module is not None:
            return _rns_module

        # If a real, fully-initialised RNS is already resident (startup
        # pre-warm, or the other __main__/bridge_server identity loaded it),
        # adopt it. A fully-initialised RNS has its Channel/Buffer submodules
        # bound on the package AND present in sys.modules.
        existing = sys.modules.get('RNS')
        if (
            existing is not None
            and getattr(existing, 'Channel', None) is not None
            and getattr(existing, 'Buffer', None) is not None
            and 'RNS.Channel' in sys.modules
            and 'RNS.Buffer' in sys.modules
        ):
            _rns_module = existing
            return existing

        # Genuine first load (or recovering from a partially-imported RNS):
        # drop the standalone crypto shims (RNS_HMAC, ...) and the fake
        # RNS / RNS.Cryptography stub so `import RNS` runs against a clean
        # slate. Safe here because no Reticulum thread can exist before the
        # first full import.
        #
        # Deliberately does NOT touch LXMF.*. Wiping a (possibly mid-import)
        # LXMF out of sys.modules races a concurrent `from LXMF import
        # LXStamper` on a handler/callback thread -> the exact "partially
        # initialized module" / "No module named 'LXMF'" import race this
        # clear was introduced to avoid for RNS. LXMF is instead pre-warmed
        # once in main() (before READY, before any thread), so every later
        # import just adopts the resident module. LXMF has no bearing on the
        # crypto-shim swap above, so leaving it resident is always correct.
        for mod in [
            k for k in list(sys.modules.keys())
            if k.startswith('RNS')
        ]:
            sys.modules.pop(mod, None)

        import RNS
        _rns_module = RNS
        return RNS


def _ensure_minimal_rns():
    """Ensure a real RNS.Reticulum instance exists, creating a minimal,
    no-interface, no-transport one if none does. Required for any operation
    that registers a destination — RNS.Destination(__init__) calls
    Transport.register_destination, which crashes without a Reticulum owner.

    Reuses the live _rns_instance set by cmd_rns_start when present (RNS
    Reticulum is a process-wide singleton, so a second `Reticulum(...)` call
    returns the existing one regardless of the configdir passed). For the
    static announce_* commands that need a destination but no network, a
    minimal instance with `enable_transport = no` and no interfaces is
    enough — and is much faster to start than the full cmd_rns_start path.
    """
    global _rns_instance
    RNS = _get_full_rns()
    if _rns_instance is None:
        import tempfile
        cfg = tempfile.mkdtemp(prefix='rns_minimal_')
        cfg_file = os.path.join(cfg, "config")
        if not os.path.isfile(cfg_file):
            os.makedirs(cfg, exist_ok=True)
            with open(cfg_file, "w") as f:
                f.write(
                    "[reticulum]\n"
                    "enable_transport = no\n"
                    "share_instance = no\n"
                    "\n"
                    "[interfaces]\n"
                )
        RNS.loglevel = int(
            os.environ.get("CONFORMANCE_RNS_LOGLEVEL", str(RNS.LOG_CRITICAL))
        )
        _rns_instance = RNS.Reticulum(configdir=cfg)
    return RNS


def _ensure_minimal_rns_on(rns_module):
    """Ensure a minimal Reticulum instance exists on the GIVEN RNS module object.

    `_ensure_minimal_rns` creates the instance on the bridge's CACHED RNS handle
    (`_rns_module`). Across a long session that handle can diverge from
    `sys.modules['RNS']`, which is what `from RNS import X` rebinds a submodule's
    own `import RNS` to. A command that creates the instance via
    `_ensure_minimal_rns` but then reaches RNS through such a submodule (e.g.
    `Discovery.RNS`) sees `Reticulum.get_instance() == None` on that other module
    and fails. Creating the instance on the EXACT module the submodule reads
    keeps them consistent. No-op when that module already has a live instance.
    """
    if rns_module.Reticulum.get_instance() is None:
        import tempfile
        cfg = tempfile.mkdtemp(prefix="rns_minimal_")
        cfg_file = os.path.join(cfg, "config")
        with open(cfg_file, "w") as f:
            f.write(
                "[reticulum]\nenable_transport = no\nshare_instance = no\n\n[interfaces]\n"
            )
        rns_module.loglevel = int(
            os.environ.get("CONFORMANCE_RNS_LOGLEVEL", str(rns_module.LOG_CRITICAL))
        )
        rns_module.Reticulum(configdir=cfg)
    return rns_module


def cmd_rns_start(params):
    """Start Reticulum with TCP server interface.

    params:
        tcp_port (int): Port for TCP server interface
        config_path (str, optional): Config directory path (default: temp dir)

    Returns:
        identity_hash (hex): Hash of the transport identity
        ready (bool): True if started successfully
    """
    global _rns_instance

    import tempfile

    tcp_port = int(params['tcp_port'])
    config_path = params.get('config_path')

    if not config_path:
        config_path = tempfile.mkdtemp(prefix='rns_test_')

    # Get full RNS
    RNS = _get_full_rns()

    # Suppress RNS logging to avoid polluting JSON output on stdout
    # RNS logs go to stdout by default which breaks the bridge protocol
    RNS.loglevel = int(os.environ.get("CONFORMANCE_RNS_LOGLEVEL", str(RNS.LOG_CRITICAL)))

    # Pre-create config file to:
    # 1. Prevent Reticulum from detecting/connecting to any running shared instance
    #    (which makes _add_interface a no-op and causes AttributeError on ifac_size)
    # 2. Enable transport so this instance routes packets
    # 3. Avoid the 1.5s sleep that happens when creating the default config
    config_file = os.path.join(config_path, "config")
    if not os.path.isfile(config_file):
        os.makedirs(config_path, exist_ok=True)
        with open(config_file, "w") as f:
            f.write("[reticulum]\n")
            f.write("  enable_transport = Yes\n")
            f.write("  share_instance = No\n")
            f.write("\n[interfaces]\n")

    # Start Reticulum with transport enabled (loglevel env-overridable)
    _rns_instance = RNS.Reticulum(
        configdir=config_path,
        loglevel=int(os.environ.get("CONFORMANCE_RNS_LOGLEVEL", str(RNS.LOG_CRITICAL)))
    )

    # Create TCP server interface using configuration dict
    # This matches how RNS loads interfaces from config
    config = {
        "name": "TestTCPServer",
        "listen_ip": "127.0.0.1",
        "listen_port": tcp_port,
        "i2p_tunneled": False,
        "prefer_ipv6": False
    }

    tcp_interface = RNS.Interfaces.TCPInterface.TCPServerInterface(
        RNS.Transport,
        config
    )

    # Use _add_interface() to properly initialize all required attributes
    # This is the same method Reticulum uses when loading interfaces from config
    _rns_instance._add_interface(tcp_interface)

    # Get transport identity hash
    identity_hash = RNS.Transport.identity.hash if RNS.Transport.identity else b'\x00' * 16

    return {
        'identity_hash': bytes_to_hex(identity_hash),
        'ready': 'true',
        'config_path': config_path
    }


def cmd_rns_stop(params):
    """Stop Reticulum instance.

    Performs clean shutdown of Transport and interfaces.
    """
    global _rns_instance

    RNS = _get_full_rns()

    try:
        RNS.Transport.exit_handler()
    except:
        pass

    _rns_instance = None

    return {
        'stopped': True
    }




# ============================================================================
# Live RNS Protocol Commands (Link, Resource, Ratchet)
# ============================================================================
# These commands operate on live Reticulum instances for E2E protocol testing.
# They manage link establishment, resource transfers, and ratchet operations.

# Global state for live protocol testing
_link_destination = None
_link_identity = None
_established_link = None
_received_link_packets = []
_received_resources = []


def cmd_rns_create_destination(params):
    """Create a Destination that accepts link requests.

    params:
        app_name (str): Application name (e.g. 'testapp')
        aspects (list[str]): Destination aspects (e.g. ['link', 'test'])

    Returns:
        destination_hash (hex): Hash of the destination
        identity_hash (hex): Hash of the identity
        identity_public_key (hex): Public key of the identity (64 bytes)

    Side effect: stores _link_destination, _link_identity, sets link_established_callback
    """
    global _link_destination, _link_identity, _established_link
    global _received_link_packets, _received_resources

    RNS = _get_full_rns()

    app_name = params.get('app_name', 'testapp')
    aspects = params.get('aspects', ['link', 'test'])

    # Create identity and destination
    _link_identity = RNS.Identity()
    _link_destination = RNS.Destination(
        _link_identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        app_name,
        *aspects
    )

    # Reset state
    _established_link = None
    _received_link_packets = []
    _received_resources = []

    # Set link established callback
    def link_established(link):
        global _established_link, _received_link_packets, _received_resources
        _established_link = link
        _received_link_packets = []
        _received_resources = []

        # Set packet callback
        def packet_callback(data, packet):
            global _received_link_packets
            _received_link_packets.append(data)

        link.set_packet_callback(packet_callback)

        # Set resource strategy to accept all
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)

        # Set resource callbacks
        def resource_started(resource):
            resource.progress_callback = lambda r: None  # no-op progress

        def resource_concluded(resource):
            global _received_resources
            if resource.status == RNS.Resource.COMPLETE:
                _received_resources.append({
                    'hash': bytes_to_hex(resource.hash),
                    'data': bytes_to_hex(resource.data.read()) if resource.data else '',
                    'size': resource.total_size,
                })

        link.set_resource_callback(resource_started)
        link.set_resource_concluded_callback(resource_concluded)

    _link_destination.set_link_established_callback(link_established)

    return {
        'destination_hash': bytes_to_hex(_link_destination.hash),
        'identity_hash': bytes_to_hex(_link_identity.hash),
        'identity_public_key': bytes_to_hex(_link_identity.get_public_key()),
    }


def cmd_rns_get_established_link(params):
    """Poll for an established link (set by callback from create_destination).

    Returns:
        status (str): 'active', 'closed', or 'none'
        link_id (hex|null): Link ID if active
        rtt (float|null): Round-trip time if available
    """
    global _established_link

    if _established_link is None:
        return {
            'status': 'none',
            'link_id': None,
            'rtt': None,
        }

    RNS = _get_full_rns()

    status_map = {
        RNS.Link.PENDING: 'pending',
        RNS.Link.HANDSHAKE: 'handshake',
        RNS.Link.ACTIVE: 'active',
        RNS.Link.STALE: 'stale',
        RNS.Link.CLOSED: 'closed',
    }

    link_status = status_map.get(_established_link.status, 'unknown')

    return {
        'status': link_status,
        'link_id': bytes_to_hex(_established_link.link_id) if _established_link.link_id else None,
        'rtt': _established_link.rtt if hasattr(_established_link, 'rtt') else None,
    }


def cmd_rns_link_send(params):
    """Send raw data over an established link as a packet.

    params:
        data (hex): Data to send

    Returns:
        sent (bool): Whether data was sent
    """
    global _established_link

    if _established_link is None:
        return {'sent': False, 'error': 'No established link'}

    RNS = _get_full_rns()

    data = hex_to_bytes(params['data'])

    if _established_link.status != RNS.Link.ACTIVE:
        return {'sent': False, 'error': 'Link not active'}

    packet = RNS.Packet(_established_link, data)
    receipt = packet.send()

    return {
        'sent': receipt is not None,
    }


def cmd_rns_link_get_packets(params):
    """Get packets received over the link.

    Returns:
        packets (list[hex]): List of received packet data as hex strings
        count (int): Number of packets
    """
    global _received_link_packets

    return {
        'packets': [bytes_to_hex(p) for p in _received_link_packets],
        'count': len(_received_link_packets),
    }


def cmd_rns_link_clear_packets(params):
    """Clear received packets list."""
    global _received_link_packets
    _received_link_packets = []
    return {'cleared': True}


def cmd_rns_link_close(params):
    """Close the established link.

    Returns:
        closed (bool): Whether the link was closed
    """
    global _established_link

    if _established_link is None:
        return {'closed': False, 'error': 'No established link'}

    _established_link.teardown()

    return {'closed': True}


def cmd_rns_resource_send(params):
    """Send a Resource over the established link.

    params:
        data (hex): Data to send as resource
        compress (bool, optional): Whether to compress (default: true)

    Returns:
        sent (bool): Whether resource was initiated
        resource_hash (hex|null): Hash of the resource
        size (int): Size of the data
    """
    global _established_link

    if _established_link is None:
        return {'sent': False, 'error': 'No established link'}

    RNS = _get_full_rns()

    data = hex_to_bytes(params['data'])
    compress = params.get('compress', True)

    if _established_link.status != RNS.Link.ACTIVE:
        return {'sent': False, 'error': 'Link not active'}

    # Pass raw bytes directly — BytesIO lacks .name which Resource expects
    resource = RNS.Resource(
        data,
        _established_link,
        auto_compress=compress
    )

    return {
        'sent': True,
        'resource_hash': bytes_to_hex(resource.hash) if resource.hash else None,
        'size': len(data),
    }


def cmd_rns_resource_get_received(params):
    """Get resources received over the link.

    Returns:
        resources (list): List of received resource info
        count (int): Number of resources
    """
    global _received_resources

    return {
        'resources': _received_resources,
        'count': len(_received_resources),
    }


def cmd_rns_enable_ratchets(params):
    """Enable ratchets on the link destination.

    params:
        ratchet_path (str, optional): Path for ratchet storage

    Returns:
        enabled (bool): Whether ratchets were enabled
        ratchet_id (hex|null): Current ratchet ID if available
    """
    global _link_destination

    if _link_destination is None:
        return {'enabled': False, 'error': 'No destination created'}

    RNS = _get_full_rns()

    import tempfile
    # enable_ratchets expects a FILE path, not a directory
    ratchet_path = params.get('ratchet_path')
    if not ratchet_path:
        tmpdir = tempfile.mkdtemp(prefix='rns_ratchet_')
        ratchet_path = os.path.join(tmpdir, 'ratchets')

    _link_destination.enable_ratchets(ratchet_path)
    # Set interval to 0 for testing so rotation always works immediately
    _link_destination.ratchet_interval = 0

    ratchet_id = None
    if hasattr(_link_destination, 'hash') and RNS.Identity.current_ratchet_id(_link_destination.hash):
        ratchet_id = bytes_to_hex(RNS.Identity.current_ratchet_id(_link_destination.hash))

    return {
        'enabled': True,
        'ratchet_id': ratchet_id,
    }


def cmd_rns_rotate_ratchet(params):
    """Force ratchet rotation and re-announce.

    Returns:
        new_ratchet_id (hex|null): New ratchet ID
        announced (bool): Whether announce was sent
    """
    global _link_destination

    if _link_destination is None:
        return {'announced': False, 'error': 'No destination created'}

    RNS = _get_full_rns()

    # Force rotation to proceed regardless of interval
    _link_destination.latest_ratchet_time = 0
    _link_destination.rotate_ratchets()
    _link_destination.announce()

    new_ratchet_id = None
    if RNS.Identity.current_ratchet_id(_link_destination.hash):
        new_ratchet_id = bytes_to_hex(RNS.Identity.current_ratchet_id(_link_destination.hash))

    return {
        'new_ratchet_id': new_ratchet_id,
        'announced': True,
    }


def cmd_rns_get_ratchet_info(params):
    """Get current ratchet state for the link destination.

    Returns:
        ratchet_id (hex|null): Current ratchet ID
        has_ratchets (bool): Whether ratchets are enabled
    """
    global _link_destination

    if _link_destination is None:
        return {'error': 'No destination created', 'has_ratchets': False}

    RNS = _get_full_rns()

    ratchet_id = None
    if RNS.Identity.current_ratchet_id(_link_destination.hash):
        ratchet_id = bytes_to_hex(RNS.Identity.current_ratchet_id(_link_destination.hash))

    has_ratchets = _link_destination.ratchets is not None

    return {
        'ratchet_id': ratchet_id,
        'has_ratchets': has_ratchets,
    }


def cmd_rns_announce_destination(params):
    """Announce the link destination.

    Returns:
        announced (bool): Whether announcement was sent
        destination_hash (hex): Hash of the destination
    """
    global _link_destination

    if _link_destination is None:
        return {'announced': False, 'error': 'No destination created'}

    _link_destination.announce()

    return {
        'announced': True,
        'destination_hash': bytes_to_hex(_link_destination.hash),
    }


# ─── Channel Messaging ────────────────────────────────────────────

_channel_messages_received = []
_BridgeMessageClass = None

def _get_bridge_message_class():
    """Lazily create BridgeMessage as a subclass of RNS.Channel.MessageBase.

    RNS is lazy-loaded, so we can't inherit from MessageBase at module level.
    This creates the class once after RNS is available.
    """
    global _BridgeMessageClass
    if _BridgeMessageClass is None:
        RNS = _get_full_rns()

        class BridgeMessage(RNS.Channel.MessageBase):
            """Simple channel message for interop testing."""
            MSGTYPE = 0x0101

            def __init__(self, data=None):
                super().__init__()
                self.data = data or b""

            def pack(self):
                return self.data if isinstance(self.data, bytes) else self.data.encode('utf-8')

            def unpack(self, raw):
                self.data = raw

        _BridgeMessageClass = BridgeMessage
    return _BridgeMessageClass


def cmd_rns_channel_setup(params):
    """Set up a channel on the established link with message type registration.

    Side effect: registers BridgeMessage (0x0101) and adds a handler that
    collects received messages into _channel_messages_received.

    Returns:
        ready (bool): Whether channel is set up
    """
    global _established_link, _channel_messages_received

    if _established_link is None:
        return {'ready': False, 'error': 'No established link'}

    RNS = _get_full_rns()

    if _established_link.status != RNS.Link.ACTIVE:
        return {'ready': False, 'error': 'Link not active'}

    _channel_messages_received = []

    BridgeMessage = _get_bridge_message_class()
    channel = _established_link.get_channel()
    channel.register_message_type(BridgeMessage)

    def message_handler(message):
        global _channel_messages_received
        if isinstance(message, _get_bridge_message_class()):
            _channel_messages_received.append(bytes_to_hex(message.data))
            return True
        return False

    channel.add_message_handler(message_handler)

    return {'ready': True}


def cmd_rns_channel_send(params):
    """Send a message over the channel.

    params:
        data (hex): Message data as hex string

    Returns:
        sent (bool): Whether message was sent
    """
    global _established_link

    if _established_link is None:
        return {'sent': False, 'error': 'No established link'}

    RNS = _get_full_rns()

    if _established_link.status != RNS.Link.ACTIVE:
        return {'sent': False, 'error': 'Link not active'}

    data = hex_to_bytes(params['data'])
    channel = _established_link.get_channel()

    if not channel.is_ready_to_send():
        return {'sent': False, 'error': 'Channel not ready'}

    BridgeMessage = _get_bridge_message_class()
    msg = BridgeMessage(data)
    channel.send(msg)

    return {'sent': True}


def cmd_rns_channel_get_messages(params):
    """Get channel messages received on the Python side.

    Returns:
        messages (list[hex]): List of received message data as hex strings
        count (int): Number of messages
    """
    global _channel_messages_received

    return {
        'messages': list(_channel_messages_received),
        'count': len(_channel_messages_received),
    }


def cmd_rns_channel_clear_messages(params):
    """Clear received channel messages."""
    global _channel_messages_received
    _channel_messages_received = []
    return {'cleared': True}


# ─── Link Request/Response ─────────────────────────────────────────

_request_responses_received = []

def cmd_rns_register_request_handler(params):
    """Register a request handler on the Python destination.

    params:
        path (str): Request path (e.g., "/test/echo")
        response_data (hex, optional): Static response data to return.
            If not provided, echoes the request data back.
        large_response_size (int, optional): If set, returns a payload of
            this many bytes instead of response_data.

    Returns:
        registered (bool): Whether handler was registered
    """
    global _link_destination

    if _link_destination is None:
        return {'registered': False, 'error': 'No destination created'}

    RNS = _get_full_rns()

    path = params.get('path', '/test/echo')
    static_response = params.get('response_data', None)
    large_size = params.get('large_response_size', None)

    def response_generator(path, data, request_id, link_id, remote_identity, requested_at):
        if large_size is not None:
            # Return a deterministic payload of the requested size
            return bytes(range(256)) * (large_size // 256 + 1)
        if static_response is not None:
            return hex_to_bytes(static_response)
        # Echo mode: return the request data
        return data

    _link_destination.register_request_handler(
        path,
        response_generator=response_generator,
        allow=RNS.Destination.ALLOW_ALL
    )

    return {'registered': True}


def cmd_rns_link_request(params):
    """Send a request from the Python side over the established link.

    params:
        path (str): Request path
        data (hex, optional): Request data

    Returns:
        sent (bool): Whether request was sent
        request_id (hex|null): Request ID if sent
    """
    global _established_link, _request_responses_received

    if _established_link is None:
        return {'sent': False, 'error': 'No established link'}

    RNS = _get_full_rns()

    if _established_link.status != RNS.Link.ACTIVE:
        return {'sent': False, 'error': 'Link not active'}

    path = params.get('path', '/test/echo')
    data_hex = params.get('data', None)
    data = hex_to_bytes(data_hex) if data_hex else None

    def got_response(request_receipt):
        global _request_responses_received
        response = request_receipt.response
        if isinstance(response, bytes):
            _request_responses_received.append({
                'request_id': bytes_to_hex(request_receipt.request_id),
                'response': bytes_to_hex(response),
                'size': len(response),
            })
        elif response is not None:
            resp_bytes = str(response).encode('utf-8')
            _request_responses_received.append({
                'request_id': bytes_to_hex(request_receipt.request_id),
                'response': bytes_to_hex(resp_bytes),
                'size': len(resp_bytes),
            })

    def request_failed(request_receipt):
        global _request_responses_received
        _request_responses_received.append({
            'request_id': bytes_to_hex(request_receipt.request_id) if request_receipt.request_id else None,
            'response': None,
            'failed': True,
        })

    receipt = _established_link.request(
        path,
        data=data,
        response_callback=got_response,
        failed_callback=request_failed,
    )

    if receipt and receipt != False:
        return {
            'sent': True,
            'request_id': bytes_to_hex(receipt.request_id) if receipt.request_id else None,
        }
    else:
        return {'sent': False, 'error': 'Request failed to send'}


def cmd_rns_get_request_responses(params):
    """Get responses received from requests sent by Python.

    Returns:
        responses (list): List of response info
        count (int): Number of responses
    """
    global _request_responses_received

    return {
        'responses': list(_request_responses_received),
        'count': len(_request_responses_received),
    }


def cmd_rns_clear_request_responses(params):
    """Clear received request responses."""
    global _request_responses_received
    _request_responses_received = []
    return {'cleared': True}


# ─── Proof Strategy ────────────────────────────────────────────────

def cmd_rns_set_proof_strategy(params):
    """Set the proof strategy on the Python destination.

    params:
        strategy (str): One of 'prove_all', 'prove_none', 'prove_app'

    Returns:
        set (bool): Whether strategy was set
    """
    global _link_destination

    if _link_destination is None:
        return {'set': False, 'error': 'No destination created'}

    RNS = _get_full_rns()

    strategy_map = {
        'prove_all': RNS.Destination.PROVE_ALL,
        'prove_none': RNS.Destination.PROVE_NONE,
        'prove_app': RNS.Destination.PROVE_APP,
    }

    strategy_name = params.get('strategy', 'prove_none')
    strategy = strategy_map.get(strategy_name)
    if strategy is None:
        return {'set': False, 'error': f'Unknown strategy: {strategy_name}'}

    _link_destination.set_proof_strategy(strategy)

    return {'set': True, 'strategy': strategy_name}


# ─── Destination constructor / lifecycle (Destination.py) ────────────
#
# These commands drive RNS.Destination directly so the constructor guards,
# announce()/encrypt()/set_proof_strategy()/rotate_ratchets() validation paths,
# and the static name-helpers are observable. Everything delegates to real RNS:
# no wire bytes are assembled here, RNS does all the hashing / signing / packing.

def _resolve_dest_type(RNS, value):
    """Map a friendly type keyword to the real RNS.Destination type constant,
    or pass an integer straight through so RNS's own `type in types` guard can
    reject an out-of-range value."""
    mapping = {
        'single': RNS.Destination.SINGLE,
        'group': RNS.Destination.GROUP,
        'plain': RNS.Destination.PLAIN,
        'link': RNS.Destination.LINK,
    }
    if isinstance(value, str):
        return mapping[value]
    return value


def _resolve_dest_direction(RNS, value):
    """Map a friendly direction keyword to the real RNS.Destination direction
    constant, or pass an integer through for RNS's own guard to reject."""
    mapping = {'in': RNS.Destination.IN, 'out': RNS.Destination.OUT}
    if isinstance(value, str):
        return mapping[value]
    return value


def _coerce_aspects(value):
    if isinstance(value, list):
        return value
    if value:
        return value.split(',')
    return []


def _make_destination(RNS, params, default_direction='in', default_type='single'):
    """Construct a real RNS.Destination from request params, reusing an
    already-registered destination with the same address (RNS raises KeyError
    on a duplicate Transport.register_destination, but the conformance bridge
    is a long-lived process that may construct the same destination across
    tests). Validation errors (ValueError/TypeError) propagate so the caller
    surfaces them as a BridgeError."""
    type_val = _resolve_dest_type(RNS, params.get('type', default_type))
    dir_val = _resolve_dest_direction(RNS, params.get('direction', default_direction))
    app_name = params['app_name']
    aspects = _coerce_aspects(params.get('aspects', []))
    pk = params.get('identity_private_key')
    identity = RNS.Identity.from_bytes(hex_to_bytes(pk)) if pk else None
    try:
        return RNS.Destination(identity, dir_val, type_val, app_name, *aspects)
    except KeyError:
        # Duplicate registration — find and reuse the live destination.
        if identity is not None and type_val != RNS.Destination.PLAIN:
            expected = RNS.Destination.hash(identity, app_name, *aspects)
        else:
            expected = RNS.Destination.hash(None, app_name, *aspects)
        for existing in RNS.Transport.destinations:
            if existing.hash == expected:
                return existing
        raise


def cmd_destination_construct(params):
    """Construct a real RNS.Destination and report the address material RNS
    derived, plus the auto-generated identity for the IN/non-PLAIN/no-identity
    branch (Destination.__init__ appends `identity.hexhash` as an extra aspect
    before computing name_hash). Drives the constructor guards directly:

      * OUT + non-PLAIN + no identity -> ValueError
      * PLAIN + identity -> TypeError
      * out-of-range type/direction int -> ValueError

    All such errors propagate to the bridge dispatcher as a BridgeError.
    """
    RNS = _ensure_minimal_rns()
    had_identity = bool(params.get('identity_private_key'))
    dest = _make_destination(RNS, params)
    result = {
        'destination_hash': bytes_to_hex(dest.hash),
        'name': dest.name,
        'name_hash': bytes_to_hex(dest.name_hash),
        'proof_strategy': dest.proof_strategy,
        'type': dest.type,
        'direction': dest.direction,
    }
    # IN, non-PLAIN, no supplied identity: RNS generated one and folded its
    # hexhash into the aspect list. Report it so a test can assert the auto
    # aspect is part of the name_hash preimage.
    if not had_identity and dest.identity is not None:
        result['auto_identity_hexhash'] = dest.identity.hexhash
    return result


def cmd_destination_announce_attempt(params):
    """Construct a destination and call announce(send=False). RNS raises
    TypeError('Only SINGLE destination types can be announced') for
    GROUP/PLAIN/LINK and TypeError('Only IN destination types can be
    announced') for OUT — both surface as a BridgeError. A valid IN SINGLE
    returns ok=True after RNS builds (but does not send) the announce packet.
    """
    RNS = _ensure_minimal_rns()
    dest = _make_destination(RNS, params)
    dest.announce(send=False)
    return {'ok': True, 'destination_hash': bytes_to_hex(dest.hash)}


def cmd_app_and_aspects_from_name(params):
    """Delegate to RNS.Destination.app_and_aspects_from_name: split a dotted
    full name into (app_name, [aspects...]) — the first component is the app
    name, the rest are aspects."""
    RNS = _get_full_rns()
    app_name, aspects = RNS.Destination.app_and_aspects_from_name(params['full_name'])
    return {'app_name': app_name, 'aspects': list(aspects)}


def cmd_hash_from_name_and_identity(params):
    """Delegate to RNS.Destination.hash_from_name_and_identity: derive the
    16-byte destination address from a dotted full name + a 16-byte identity
    hash (RNS splits the name and feeds it through Destination.hash)."""
    RNS = _get_full_rns()
    identity_hash = hex_to_bytes(params['identity_hash'])
    dest_hash = RNS.Destination.hash_from_name_and_identity(
        params['full_name'], identity_hash
    )
    return {'destination_hash': bytes_to_hex(dest_hash)}


def cmd_destination_expand_name(params):
    """Delegate to RNS.Destination.expand_name. With an identity, RNS appends
    `'.' + identity.hexhash` to the dotted app/aspects join; without one it
    returns the bare dotted join. Lets a test observe the trailing-identity
    suffix form that no other command exposes."""
    RNS = _get_full_rns()
    app_name = params['app_name']
    aspects = _coerce_aspects(params.get('aspects', []))
    pk = params.get('identity_private_key')
    identity = RNS.Identity.from_bytes(hex_to_bytes(pk)) if pk else None
    name = RNS.Destination.expand_name(identity, app_name, *aspects)
    out = {'name': name}
    if identity is not None:
        out['identity_hexhash'] = identity.hexhash
    return out


def cmd_destination_set_proof_strategy_raw(params):
    """Construct a destination and call set_proof_strategy with the raw value
    so RNS's own validation runs: a strategy not in Destination.proof_strategies
    raises TypeError('Unsupported proof strategy') -> BridgeError. The three
    valid strategy constants are accepted and reflected back."""
    RNS = _ensure_minimal_rns()
    dest = _make_destination(RNS, params)
    dest.set_proof_strategy(params['strategy_value'])
    return {'set': True, 'proof_strategy': dest.proof_strategy}


def cmd_destination_rotate_ratchets(params):
    """Construct a destination and call rotate_ratchets(). Without
    enable_ratchets first, self.ratchets is None and RNS raises
    SystemError('Cannot rotate ratchet ... ratchets are not enabled') ->
    BridgeError. With enable=True, RNS initialises a ratchet file and the
    rotation succeeds."""
    RNS = _ensure_minimal_rns()
    dest = _make_destination(RNS, params)
    if params.get('enable'):
        import tempfile
        rdir = tempfile.mkdtemp(prefix='rns_dest_ratchets_')
        dest.enable_ratchets(os.path.join(rdir, 'ratchets.bin'))
        dest.ratchet_interval = 0
    rotated = dest.rotate_ratchets()
    return {'rotated': bool(rotated), 'has_ratchets': dest.ratchets is not None}


def cmd_destination_group_encrypt(params):
    """Construct a GROUP destination and call encrypt(). Without create_keys()
    the GROUP path has no symmetric Token key and RNS raises ValueError('No
    private key held by GROUP destination') -> BridgeError. With create_keys
    RNS generates a key and the encryption succeeds (and round-trips through
    decrypt)."""
    RNS = _ensure_minimal_rns()
    params = dict(params)
    params['type'] = 'group'
    params['direction'] = params.get('direction', 'in')
    dest = _make_destination(RNS, params)
    if params.get('create_keys'):
        dest.create_keys()
    plaintext = hex_to_bytes(params['plaintext'])
    ciphertext = dest.encrypt(plaintext)
    roundtrip = dest.decrypt(ciphertext)
    return {
        'ciphertext': bytes_to_hex(ciphertext),
        'roundtrip': bytes_to_hex(roundtrip) if roundtrip is not None else None,
        'has_key': hasattr(dest, 'prv') and dest.prv is not None,
    }


def cmd_destination_default_app_data(params):
    """Set a destination's default_app_data, then announce(send=False) with
    app_data=None so RNS substitutes Destination.default_app_data into the
    signed/announce stream (Destination.py:289-295 — bytes are used directly, a
    callable is invoked and its bytes return value used). The app_data carried
    on the wire is read back off the RNS-produced announce_data at the offsets
    RNS itself wrote, so a test can assert the default was folded in.

    default_kind selects: 'bytes' (use default_value), 'callable' (a function
    returning default_value), or 'none' (no default set). override_app_data, if
    given, is passed explicitly to announce() and must take precedence.
    """
    RNS = _ensure_minimal_rns()
    dest = _make_destination(RNS, params)

    default_kind = params.get('default_kind', 'bytes')
    default_value = hex_to_bytes(params['default_value']) if params.get('default_value') else b""
    if default_kind == 'bytes':
        dest.set_default_app_data(default_value)
    elif default_kind == 'callable':
        dest.set_default_app_data(lambda: default_value)
    # 'none' -> leave default_app_data as None

    override = hex_to_bytes(params['override_app_data']) if params.get('override_app_data') else None
    packet = dest.announce(app_data=override, send=False)
    packet.pack()

    # Read app_data off the announce_data tail using live RNS field sizes — the
    # same offsets cmd_announce_build parses. No bytes are assembled here.
    keysize = RNS.Identity.KEYSIZE // 8
    name_hash_len = RNS.Identity.NAME_HASH_LENGTH // 8
    ratchet_size = RNS.Identity.RATCHETSIZE // 8
    sig_len = RNS.Identity.SIGLENGTH // 8
    random_hash_len = 10
    data = packet.data
    cursor = keysize + name_hash_len + random_hash_len
    if packet.context_flag == RNS.Packet.FLAG_SET:
        cursor += ratchet_size
    cursor += sig_len
    app_data_on_wire = data[cursor:]

    return {
        'app_data': bytes_to_hex(app_data_on_wire),
        'default_app_data_set': dest.default_app_data is not None,
    }


def cmd_destination_register_request_handler_validate(params):
    """Construct a destination and call register_request_handler with
    caller-controlled argument validity so RNS's own checks run:

      * empty/None path -> ValueError('Invalid path specified')
      * non-callable response_generator -> ValueError('Invalid response generator specified')
      * allow policy not in request_policies -> ValueError('Invalid request policy')

    All surface as a BridgeError; a fully-valid registration returns ok.
    """
    RNS = _ensure_minimal_rns()
    dest = _make_destination(RNS, params)
    path = params.get('path', '/test/echo')
    if params.get('generator_valid', True):
        def response_generator(p, data, request_id, link_id, remote_identity, requested_at):
            return data
        gen = response_generator
    else:
        gen = None
    allow = params.get('allow', RNS.Destination.ALLOW_ALL)
    dest.register_request_handler(path, response_generator=gen, allow=allow)
    return {'registered': True, 'handler_count': len(dest.request_handlers)}


def cmd_destination_path_response_cache(params):
    """Drive Destination.announce(path_response=True, tag=...) twice and report
    whether RNS reused the cached announce_data (path_responses[tag]) on the
    second call. RNS evicts entries older than PR_TAG_WINDOW seconds at the top
    of announce(), so pinning the wall-clock advance between the two calls lets
    a test assert both the cache-hit branch (advance=0 -> identical data) and
    the eviction branch (advance>PR_TAG_WINDOW -> fresh data rebuilt).

    Time is pinned by patching time.time for the duration of each announce()
    call, so RNS still does all the real signing/packing — it just sees the
    wall-clock value we pin. No wire bytes are assembled here.
    """
    RNS = _ensure_minimal_rns()
    dest = _make_destination(RNS, params)
    tag = hex_to_bytes(params['tag'])
    advance = float(params.get('advance_seconds', 0))
    base = 1_000_000.0

    import time as _time

    def announce_at(ts):
        orig = _time.time
        _time.time = lambda: float(ts)
        try:
            return dest.announce(path_response=True, tag=tag, send=False)
        finally:
            _time.time = orig

    p1 = announce_at(base)
    p2 = announce_at(base + advance)
    return {
        'first_announce_data': bytes_to_hex(p1.data),
        'second_announce_data': bytes_to_hex(p2.data),
        'reused': p1.data == p2.data,
        'cache_size': len(dest.path_responses),
        'pr_tag_window': RNS.Destination.PR_TAG_WINDOW,
        'first_is_path_response': p1.context == RNS.Packet.PATH_RESPONSE,
    }


def cmd_packet_constants(params):
    """Return the live RNS wire-size / header constants so tests can pin them
    against the spec literals (not against another read of the same value).

    Every field is read straight off real RNS (RNS.Reticulum.*, RNS.Packet.*,
    RNS.Link.*, RNS.Identity.*) — no arithmetic is reconstructed here, the test
    asserts each against its documented literal.
    """
    RNS = _get_full_rns()
    R = RNS.Reticulum
    P = RNS.Packet
    L = RNS.Link
    I = RNS.Identity
    return {
        'mtu': int(R.MTU),
        'header_minsize': int(R.HEADER_MINSIZE),
        'header_maxsize': int(R.HEADER_MAXSIZE),
        'mdu': int(R.MDU),
        'ifac_min_size': int(R.IFAC_MIN_SIZE),
        'packet_mdu': int(P.MDU),
        'packet_plain_mdu': int(P.PLAIN_MDU),
        'packet_encrypted_mdu': int(P.ENCRYPTED_MDU),
        'link_mdu': int(L.MDU),
        'hashlength': int(I.HASHLENGTH),
        'siglength': int(I.SIGLENGTH),
        'truncated_hashlength': int(I.TRUNCATED_HASHLENGTH),
        'keysize': int(I.KEYSIZE),
        'name_hash_length': int(I.NAME_HASH_LENGTH),
        'token_overhead': int(I.TOKEN_OVERHEAD),
        'aes128_blocksize': int(I.AES128_BLOCKSIZE),
    }


def cmd_packet_context_constants(params):
    """Return the live RNS.Packet context-byte code points so a test can pin each
    named context against its spec literal (not against another read of the same
    value).

    Every value is read straight off real RNS.Packet.* — no byte is reconstructed.
    These are the assignments at RNS/Packet.py:72-92; the conformance test asserts
    each against its documented literal (e.g. COMMAND == 0x0C), which together with
    a packet_build that places the byte on the wire byte-pins the whole context
    code-point table — including the link-control (LINKIDENTIFY/LINKCLOSE/LINKPROOF)
    and resource (RESOURCE_HMU/ICL/RCL) and command (COMMAND/COMMAND_STATUS) codes
    that the protocol otherwise only implies through interop.
    """
    RNS = _get_full_rns()
    P = RNS.Packet
    return {
        'NONE': int(P.NONE),
        'RESOURCE': int(P.RESOURCE),
        'RESOURCE_ADV': int(P.RESOURCE_ADV),
        'RESOURCE_REQ': int(P.RESOURCE_REQ),
        'RESOURCE_HMU': int(P.RESOURCE_HMU),
        'RESOURCE_PRF': int(P.RESOURCE_PRF),
        'RESOURCE_ICL': int(P.RESOURCE_ICL),
        'RESOURCE_RCL': int(P.RESOURCE_RCL),
        'CACHE_REQUEST': int(P.CACHE_REQUEST),
        'RESPONSE': int(P.RESPONSE),
        'PATH_RESPONSE': int(P.PATH_RESPONSE),
        'COMMAND': int(P.COMMAND),
        'COMMAND_STATUS': int(P.COMMAND_STATUS),
        'CHANNEL': int(P.CHANNEL),
        'KEEPALIVE': int(P.KEEPALIVE),
        'LINKIDENTIFY': int(P.LINKIDENTIFY),
        'LINKCLOSE': int(P.LINKCLOSE),
        'LINKPROOF': int(P.LINKPROOF),
        'LRRTT': int(P.LRRTT),
        'LRPROOF': int(P.LRPROOF),
    }


def cmd_announce_queue_constants(params):
    """Return the live RNS announce-bandwidth / per-interface egress-queue
    constants so a test can pin them against the documented spec literals (not
    against another read of the same value).

    Every field is read straight off real RNS.Reticulum.* — no value is
    reconstructed here. These govern the 2% default announce bandwidth cap
    (ANNOUNCE_CAP), the per-interface queue depth ceiling before announces are
    dropped (MAX_QUEUED_ANNOUNCES, Transport.py:1262 / Interface.process_announce_queue),
    and how long a queued announce survives before it is purged as stale
    (QUEUED_ANNOUNCE_LIFE, Interface.py:332). The conformance test asserts each
    against its documented literal (16384, 86400 == 24h, 2)."""
    RNS = _get_full_rns()
    R = RNS.Reticulum
    return {
        'announce_cap': int(R.ANNOUNCE_CAP),
        'max_queued_announces': int(R.MAX_QUEUED_ANNOUNCES),
        'queued_announce_life': int(R.QUEUED_ANNOUNCE_LIFE),
    }


def cmd_identity_random_hash(params):
    """Return one RNS.Identity.get_random_hash() value (hex).

    Delegates to real RNS; the test asserts it is the documented length and that
    repeated calls differ (non-repetition over a sample)."""
    RNS = _get_full_rns()
    return {'random_hash': bytes_to_hex(RNS.Identity.get_random_hash())}


def cmd_hdlc_escape(params):
    """Apply RNS's HDLC send-side byte-stuffing (the forward primitive
    RNS.Interfaces.TCPInterface.HDLC.escape) to a payload.

    Delegates entirely to the real exposed staticmethod — the inverse
    (hdlc_deframe) is already tested as a round-trip; this exposes the forward
    direction so the ESC-before-FLAG escape order can be pinned directly."""
    RNS = _get_full_rns()
    from RNS.Interfaces.TCPInterface import HDLC
    data = hex_to_bytes(params['data'])
    return {'escaped': bytes_to_hex(HDLC.escape(data))}


# ---------------------------------------------------------------------------
# Interface-discovery subsystem (RNS.Discovery) — pure-function KATs.
#
# These commands drive the REAL RNS.Discovery announce builder / receiver and
# the REAL LXMF LXStamper proof-of-work used by on-network interface discovery.
# Nothing about the msgpack info layout, the flag byte, the stamp, or the
# address validation is reconstructed here: the announce bytes come straight
# out of InterfaceAnnouncer.get_interface_announce_data, the receive decision
# out of InterfaceAnnounceHandler.received_announce, and the stamp out of
# LXMF.LXStamper. The commands only set up the environmental RNS state the real
# code reads (Transport.identity, transport_enabled, network_identity,
# interface_discovery_sources) and split/report the buffers the real code
# returns.
# ---------------------------------------------------------------------------

def cmd_discovery_build_announce_appdata(params):
    """Build interface-discovery announce app_data via the REAL
    RNS.Discovery.InterfaceAnnouncer.get_interface_announce_data
    (Discovery.py:96-186).

    A lightweight stand-in interface object (a dynamically-named class so
    ``type(iface).__name__ == interface_type`` — exactly what RNS keys on)
    carries the ``discovery_*`` attributes RNS reads. The announce bytes, the
    msgpack ``info`` dict, the LXStamper proof-of-work stamp and the flag byte
    are ALL produced by real RNS / real LXMF. This command only splits the
    returned buffer at ``LXStamper.STAMP_SIZE`` and reports the parts — it
    assembles no protocol bytes itself.
    """
    # Bind to the EXACT RNS module object the announce builder reads through its
    # own `import RNS` (Discovery.RNS). _get_full_rns() only guarantees the real
    # (non-stub) RNS is loaded; across a long session its cached handle can
    # diverge from the live sys.modules['RNS'] that `from RNS import Discovery`
    # rebinds Discovery.RNS to, so setting transport_enabled / Transport.identity
    # on the cached handle would be invisible to get_interface_announce_data.
    _get_full_rns()
    from RNS import Discovery
    from LXMF import LXStamper
    RNS = Discovery.RNS

    interface_type = params['interface_type']
    fields = params.get('fields') or {}
    stamp_value = params.get('stamp_value', 14)
    encrypt = bool(params.get('encrypt', False))

    # Environmental RNS state the announce builder reads: the TRANSPORT field
    # (Reticulum.transport_enabled()) and the TRANSPORT_ID field
    # (Transport.identity.hash). Set on real RNS; not reconstructed.
    transport_enabled = bool(params.get('transport_enabled', False))
    setattr(RNS.Reticulum, '_Reticulum__transport_enabled', transport_enabled)
    if params.get('transport_identity_priv'):
        RNS.Transport.identity = RNS.Identity.from_bytes(
            hex_to_bytes(params['transport_identity_priv']))
    elif RNS.Transport.identity is None:
        RNS.Transport.identity = RNS.Identity()

    net_identity = None
    if params.get('network_identity_priv'):
        net_identity = RNS.Identity.from_bytes(
            hex_to_bytes(params['network_identity_priv']))

    class _Owner:
        def has_network_identity(self_o):
            return net_identity is not None
    owner = _Owner()
    owner.network_identity = net_identity
    owner.identity = None

    # Real InterfaceAnnouncer, bypassing __init__ (which only builds the
    # discovery Destination / starts networking we do not need here).
    announcer = Discovery.InterfaceAnnouncer.__new__(Discovery.InterfaceAnnouncer)
    announcer.owner = owner
    announcer.stamp_cache = {}
    announcer.stamper = LXStamper

    iface = type(interface_type, (), {})()
    iface.discovery_stamp_value = stamp_value
    iface.discovery_name = fields.get('name')
    iface.discovery_latitude = fields.get('latitude')
    iface.discovery_longitude = fields.get('longitude')
    iface.discovery_height = fields.get('height')
    iface.discovery_publish_ifac = bool(fields.get('publish_ifac', False))
    iface.ifac_netname = fields.get('ifac_netname')
    iface.ifac_netkey = fields.get('ifac_netkey')
    iface.discovery_encrypt = encrypt
    iface.kiss_framing = bool(fields.get('kiss_framing', False))
    iface.reachable_on = fields.get('reachable_on')
    iface.bind_port = fields.get('port')
    iface.connectable = bool(fields.get('connectable', False))
    iface.b32 = fields.get('b32')
    iface.frequency = fields.get('frequency')
    iface.bandwidth = fields.get('bandwidth')
    iface.sf = fields.get('sf')
    iface.cr = fields.get('cr')
    iface.discovery_frequency = fields.get('frequency')
    iface.discovery_bandwidth = fields.get('bandwidth')
    iface.discovery_channel = fields.get('channel')
    iface.discovery_modulation = fields.get('modulation')

    app_data = announcer.get_interface_announce_data(iface)
    if app_data is None:
        return {'aborted': True, 'app_data': None}

    stamp_size = LXStamper.STAMP_SIZE
    flags = app_data[0]
    packed = app_data[1:-stamp_size]
    stamp = app_data[-stamp_size:]
    infohash = RNS.Identity.full_hash(packed)
    return {
        'aborted': False,
        'app_data': bytes_to_hex(app_data),
        'flags': flags,
        'packed_info': bytes_to_hex(packed),
        'stamp': bytes_to_hex(stamp),
        'infohash': bytes_to_hex(infohash),
        'stamp_size': stamp_size,
        'transport_id': bytes_to_hex(RNS.Transport.identity.hash),
        'transport_enabled': transport_enabled,
        # Pure read of the sender default-stamp constant (Discovery.py:34) so a
        # test can pin it without the cost passing through this command's own
        # 14-fallback default.
        'default_stamp_value': Discovery.InterfaceAnnouncer.DEFAULT_STAMP_VALUE,
    }


def cmd_discovery_receive_announce(params):
    """Feed an app_data buffer to the REAL
    RNS.Discovery.InterfaceAnnounceHandler.received_announce
    (Discovery.py:214-362) and report whether RNS accepted it (callback fired
    with a populated ``info`` dict) or silently dropped it.

    All the receive-path decisions — minimum length, source allowlist, stamp
    validity / value threshold, FLAG_ENCRYPTED decrypt, field-type validation,
    interface-type whitelist — are made by real RNS. This command only sets the
    environmental state RNS reads and captures the callback.
    """
    # Bind to the EXACT RNS module object received_announce reads through its
    # own `import RNS` (Discovery.RNS) — see cmd_discovery_build_announce_appdata
    # for why the cached _get_full_rns() handle is not used directly here.
    _get_full_rns()
    from RNS import Discovery
    RNS = Discovery.RNS

    app_data = hex_to_bytes(params['app_data'])
    required_value = params.get('required_value', 14)

    setattr(RNS.Reticulum, '_Reticulum__transport_enabled',
            bool(params.get('transport_enabled', False)))

    if params.get('network_identity_priv'):
        RNS.Transport.network_identity = RNS.Identity.from_bytes(
            hex_to_bytes(params['network_identity_priv']))
    else:
        RNS.Transport.network_identity = None

    sources = params.get('discovery_sources')
    if sources is None:
        setattr(RNS.Reticulum, '_Reticulum__interface_sources', [])
    else:
        setattr(RNS.Reticulum, '_Reticulum__interface_sources',
                [hex_to_bytes(s) for s in sources])

    if params.get('announce_identity_priv'):
        announced = RNS.Identity.from_bytes(
            hex_to_bytes(params['announce_identity_priv']))
    else:
        announced = RNS.Identity()

    if params.get('destination_hash'):
        dest_hash = hex_to_bytes(params['destination_hash'])
    else:
        dest_hash = announced.hash

    captured = {}
    invoked = {'n': 0, 'info_none': False}

    def _cb(info):
        invoked['n'] += 1
        if info is None:
            invoked['info_none'] = True
        else:
            captured.update(info)

    # When default_required_value is requested, build the handler WITHOUT
    # passing required_value so the impl's own default
    # (InterfaceAnnounceHandler.__init__ default = InterfaceAnnouncer.
    # DEFAULT_STAMP_VALUE) applies — lets a test pin the receiver's default
    # acceptance threshold rather than an explicitly-supplied one.
    if params.get('default_required_value'):
        handler = Discovery.InterfaceAnnounceHandler(callback=_cb)
    else:
        handler = Discovery.InterfaceAnnounceHandler(
            required_value=required_value, callback=_cb)
    handler.received_announce(dest_hash, announced, app_data)

    out = {
        'callback_invoked': invoked['n'] > 0,
        'callback_info_none': invoked['info_none'],
        'info_present': bool(captured),
        'accepted': bool(captured),
        'announce_identity_hash': bytes_to_hex(announced.hash),
        # Pure reads off the real handler / announcer for receiver-wiring and
        # default-threshold assertions (Discovery.py:200,192,34).
        'aspect_filter': handler.aspect_filter,
        'required_value': handler.required_value,
        'default_stamp_value': Discovery.InterfaceAnnouncer.DEFAULT_STAMP_VALUE,
    }
    if captured:
        safe = {}
        for k, v in captured.items():
            safe[k] = bytes_to_hex(v) if isinstance(v, bytes) else v
        out['info'] = safe
    return out


def cmd_discovery_stamp(params):
    """Expose the LXMF LXStamper proof-of-work primitives used by interface
    discovery (Discovery.py:172,235-237): stamp_workblock / stamp_value /
    stamp_valid / generate_stamp. Thin delegation to real LXMF.LXStamper.
    """
    from LXMF import LXStamper
    op = params['op']
    if op == 'workblock':
        material = hex_to_bytes(params['material'])
        rounds = params.get('expand_rounds', 20)
        wb = LXStamper.stamp_workblock(material, expand_rounds=rounds)
        return {'workblock': bytes_to_hex(wb), 'length': len(wb)}
    elif op == 'value':
        wb = hex_to_bytes(params['workblock'])
        stamp = hex_to_bytes(params['stamp'])
        return {'value': LXStamper.stamp_value(wb, stamp)}
    elif op == 'valid':
        wb = hex_to_bytes(params['workblock'])
        stamp = hex_to_bytes(params['stamp'])
        cost = params['cost']
        return {'valid': bool(LXStamper.stamp_valid(stamp, cost, wb))}
    elif op == 'generate':
        material = hex_to_bytes(params['material'])
        cost = params['cost']
        rounds = params.get('expand_rounds', 20)
        stamp, value = LXStamper.generate_stamp(
            material, stamp_cost=cost, expand_rounds=rounds)
        return {
            'stamp': bytes_to_hex(stamp) if stamp else None,
            'value': value,
            'stamp_size': LXStamper.STAMP_SIZE,
        }
    elif op == 'default_cost':
        # Read the impl's OWN documented default proof-of-work cost for
        # interface-discovery announce stamps straight off real RNS
        # (Discovery.py:34, InterfaceAnnouncer.DEFAULT_STAMP_VALUE). The
        # receiver-side InterfaceAnnounceHandler defaults its required_value to
        # the SAME constant (Discovery.py:192), so we surface both — read
        # directly off the class attribute and off the real constructor
        # signature default — so a test can pin that the cost the receiver
        # enforces by default == the cost the sender targets by default,
        # against the documented literal 14.
        import inspect as _inspect
        from RNS import Discovery
        ia_default = int(Discovery.InterfaceAnnouncer.DEFAULT_STAMP_VALUE)
        handler_default = _inspect.signature(
            Discovery.InterfaceAnnounceHandler.__init__
        ).parameters['required_value'].default
        return {
            'default_stamp_value': ia_default,
            'handler_default_required_value': int(handler_default),
        }
    else:
        raise ValueError(f"unknown discovery_stamp op: {op}")


def cmd_discovery_validate_address(params):
    """Expose RNS.Discovery.is_ip_address / is_hostname / is_ygg_ipv6
    (Discovery.py:769-785). Thin delegation to real RNS.
    """
    RNS = _get_full_rns()
    from RNS import Discovery
    addr = params['address']
    out = {
        'is_ip_address': bool(Discovery.is_ip_address(addr)),
        'is_ygg_ipv6': bool(Discovery.is_ygg_ipv6(addr)),
    }
    try:
        out['is_hostname'] = bool(Discovery.is_hostname(addr))
    except Exception:
        out['is_hostname'] = False
    return out


def cmd_discovery_sanitize_name(params):
    """Expose RNS interface-name sanitization: the receiver-side
    InterfaceAnnounceHandler.sanitize_name (Discovery.py:205-212) and the
    sender-side InterfaceAnnouncer.sanitize newline/CR strip (Discovery.py:89-94).
    Thin delegation to real RNS.
    """
    RNS = _get_full_rns()
    from RNS import Discovery
    name = params.get('name')
    announcer = Discovery.InterfaceAnnouncer.__new__(Discovery.InterfaceAnnouncer)
    return {
        'sanitize_name': Discovery.InterfaceAnnounceHandler.sanitize_name(name),
        'sanitize': announcer.sanitize(name),
    }


def cmd_discovery_craft_announce(params):
    """ADVERSARIAL announce crafter for the interface-discovery receive path.

    Starts from a GENUINE announce produced by the real
    InterfaceAnnouncer.get_interface_announce_data (via
    cmd_discovery_build_announce_appdata), unpacks its info map with RNS's OWN
    vendored umsgpack (RNS.vendor.umsgpack — the exact serializer RNS uses for
    this record), applies ONE semantic mutation to the decoded dict, then
    re-packs with that SAME serializer and re-stamps with the real LXMF
    LXStamper proof-of-work before re-emitting app_data for replay through the
    real received_announce.

    Supported mutations (each exercises a distinct receive-path rejection
    branch, Discovery.py:247-261):
      * drop_field        -> remove a mandatory msgpack key (KeyError / the
                             INTERFACE_TYPE-absent callback(None) path)
      * set_interface_type-> overwrite INTERFACE_TYPE with a non-whitelisted
                             string (ValueError at the DISCOVERABLE list gate)
      * set_fields        -> wrong-type / wrong-length a field (TRANSPORT,
                             TRANSPORT_ID, REACHABLE_ON, ...) for the type gates

    No protocol logic is reconstructed: the field-key numbering, the flag byte,
    the msgpack framing and the stamp PoW all come from real RNS / real LXMF;
    only the *decoded dict* is edited. The byte buffer is `b"\\x00" + packed +
    stamp` — the flag byte is the spec-literal 0x00 RNS emits for an unencrypted
    announce and the parts are RNS's own. Used purely to prove the real receiver
    REJECTS the malformation; pinned in ADVERSARIAL_CORRUPTORS.
    """
    _get_full_rns()
    from RNS import Discovery
    from RNS.vendor import umsgpack
    from LXMF import LXStamper
    RNS = Discovery.RNS

    base = cmd_discovery_build_announce_appdata(params)
    if base.get('aborted'):
        return {'aborted': True, 'app_data': None}

    # Decode the genuine RNS-produced info map with RNS's own serializer.
    packed = hex_to_bytes(base['packed_info'])
    info = umsgpack.unpackb(packed)

    drop = params.get('drop_field')
    if drop is not None:
        info.pop(int(drop), None)

    set_type = params.get('set_interface_type')
    if set_type is not None:
        info[Discovery.INTERFACE_TYPE] = set_type

    for spec in (params.get('set_fields') or []):
        key = int(spec['key'])
        kind = spec.get('kind', 'str')
        val = spec['value']
        if kind == 'bytes':
            val = hex_to_bytes(val)
        elif kind == 'int':
            val = int(val)
        elif kind == 'float':
            val = float(val)
        elif kind == 'bool':
            val = bool(val)
        info[key] = val

    # Re-pack with RNS's own serializer and re-stamp with real LXStamper, so the
    # mutated announce still clears the genuine stamp gate and the rejection is
    # attributable to the mutation alone.
    new_packed = umsgpack.packb(info)
    infohash = RNS.Identity.full_hash(new_packed)
    stamp_value = params.get('stamp_value', 14)
    rounds = Discovery.InterfaceAnnouncer.WORKBLOCK_EXPAND_ROUNDS
    stamp, value = LXStamper.generate_stamp(
        infohash, stamp_cost=stamp_value, expand_rounds=rounds)
    if not stamp:
        return {'aborted': True, 'app_data': None}

    # Layout: flags(0x00, unencrypted) || packed || stamp — flag literal and
    # parts are RNS's; nothing protocol-specific assembled.
    app_data = b"\x00" + new_packed + stamp
    return {
        'aborted': False,
        'app_data': bytes_to_hex(app_data),
        'stamp_value': value,
        'stamp_size': LXStamper.STAMP_SIZE,
    }


def cmd_discovery_announce_identity(params):
    """Run the REAL InterfaceAnnouncer.__init__ identity selection
    (Discovery.py:54-58) and report which identity the discovery Destination is
    built under.

    A lightweight owner stand-in carries `has_network_identity()`,
    `network_identity` and `identity`; the real constructor picks the network
    identity when has_network_identity() is True else the transport identity,
    and builds the real RNS.Destination(identity, IN, SINGLE, "rnstransport",
    "discovery", "interface"). The destination hash is read off that real
    Destination — not recomputed here. Returns the chosen identity hash and both
    candidate hashes so a test can anchor the selection against the naming
    oracle (hash_from_name_and_identity).
    """
    # A real Reticulum instance must exist: InterfaceAnnouncer.__init__ builds a
    # real Destination, whose registration needs Transport.owner set. Bind to the
    # EXACT module Discovery reads (Discovery.RNS) and ensure the instance lives
    # there — the cached _ensure_minimal_rns handle can diverge across a session.
    _get_full_rns()
    from RNS import Discovery
    RNS = Discovery.RNS
    _ensure_minimal_rns_on(RNS)

    has_net = bool(params.get('has_network_identity'))
    net_priv = params.get('network_identity_priv')
    id_priv = params.get('identity_priv')
    net_identity = (RNS.Identity.from_bytes(hex_to_bytes(net_priv))
                    if net_priv else None)
    base_identity = (RNS.Identity.from_bytes(hex_to_bytes(id_priv))
                     if id_priv else None)

    class _Owner:
        def has_network_identity(self_o):
            return has_net
    owner = _Owner()
    owner.network_identity = net_identity
    owner.identity = base_identity

    announcer = Discovery.InterfaceAnnouncer(owner)
    dest = announcer.discovery_destination
    chosen = net_identity if has_net else base_identity
    return {
        'discovery_destination_hash': bytes_to_hex(dest.hash),
        'chosen_identity_hash': bytes_to_hex(chosen.hash),
        'network_identity_hash': (bytes_to_hex(net_identity.hash)
                                  if net_identity else None),
        'identity_hash': (bytes_to_hex(base_identity.hash)
                          if base_identity else None),
        'app_name': Discovery.APP_NAME,
    }


def cmd_discovery_feature_defaults(params):
    """Report the interface-discovery opt-in gates for a freshly-initialised
    node, read straight off real RNS:

      * a fresh base RNS Interface's `discoverable` / `supports_discovery`
        (Interface.py:105-106)
      * Reticulum's master `discover_interfaces` gate (Reticulum.py:259)
      * should_autoconnect_discovered_interfaces() / max_autoconnected_
        interfaces() (Reticulum.py:1802-1807)

    Lets a test assert every discovery feature defaults OFF (opt-in). Pure
    attribute / getter reads on real RNS — nothing reconstructed.
    """
    # Bind to the live RNS module (== Discovery.RNS) and ensure the instance is
    # on it, so Interface() / should_autoconnect see a live get_instance().
    _get_full_rns()
    from RNS import Discovery
    RNS = Discovery.RNS
    _ensure_minimal_rns_on(RNS)
    Interface = RNS.Interfaces.Interface.Interface
    iface = Interface()
    return {
        'interface_discoverable': iface.discoverable,
        'interface_supports_discovery': iface.supports_discovery,
        'discover_interfaces': getattr(
            RNS.Reticulum, '_Reticulum__discover_interfaces'),
        'should_autoconnect_discovered_interfaces':
            RNS.Reticulum.should_autoconnect_discovered_interfaces(),
        'max_autoconnected_interfaces':
            RNS.Reticulum.max_autoconnected_interfaces(),
    }


def cmd_discovery_inject_records(params):
    """Drive the REAL InterfaceDiscovery.list_discovered_interfaces
    (Discovery.py:402-448) over genuine discovery records with controlled ages.

    For each requested record this builds a GENUINE announce, runs it through
    the real received_announce to obtain the real `info` dict, back-dates only
    its `last_heard`/`received` timestamp (and optionally overrides the stamp
    `value` for the sort key), and writes it via the real
    InterfaceDiscovery.interface_discovered — which msgpack-serialises and
    stores the record itself. list_discovered_interfaces is then invoked and its
    real status assignment / staleness removal / sort order reported. The bridge
    only chooses each record's age and reads back RNS's verdict; the threshold
    comparisons, status codes and sort are 100% RNS.
    """
    _get_full_rns()
    from RNS import Discovery
    RNS = Discovery.RNS
    _ensure_minimal_rns_on(RNS)
    import time as _time

    # No source allowlist configured -> the allowlist removal branch is inert.
    setattr(RNS.Reticulum, '_Reticulum__interface_sources', [])
    setattr(RNS.Reticulum, '_Reticulum__transport_enabled', True)

    disc = Discovery.InterfaceDiscovery(discover_interfaces=False)

    def _clean():
        for fn in os.listdir(disc.storagepath):
            try:
                os.unlink(os.path.join(disc.storagepath, fn))
            except OSError:
                pass

    _clean()

    now = _time.time()
    requested = []
    for rec in params['records']:
        name = rec['name']
        age = float(rec['age_seconds'])
        built = cmd_discovery_build_announce_appdata({
            'interface_type': 'TCPServerInterface',
            'stamp_value': rec.get('stamp_value', 6),
            'transport_enabled': True,
            'fields': {'name': name, 'reachable_on': 'example.com',
                       'port': 4242},
        })
        app_data = hex_to_bytes(built['app_data'])
        captured = {}

        def _cb(info, _c=captured):
            if info:
                _c.update(info)

        handler = Discovery.InterfaceAnnounceHandler(
            required_value=rec.get('stamp_value', 6), callback=_cb)
        announced = RNS.Identity()
        handler.received_announce(announced.hash, announced, app_data)
        if not captured:
            raise ValueError(f"could not build genuine record for {name!r}")

        captured['received'] = now - age
        if 'value' in rec:
            captured['value'] = int(rec['value'])
        disc.interface_discovered(captured)
        requested.append({
            'name': name,
            'discovery_hash': bytes_to_hex(captured['discovery_hash']),
        })

    listed = disc.list_discovered_interfaces()
    out_records = []
    for info in listed:
        out_records.append({
            'name': info.get('name'),
            'status': info.get('status'),
            'status_code': info.get('status_code'),
            'value': info.get('value'),
            'last_heard': info.get('last_heard'),
            'discovery_hash': bytes_to_hex(info['discovery_hash'])
            if isinstance(info.get('discovery_hash'), bytes)
            else info.get('discovery_hash'),
        })

    _clean()
    return {
        'requested': requested,
        'listed': out_records,
        'threshold_unknown': Discovery.InterfaceDiscovery.THRESHOLD_UNKNOWN,
        'threshold_stale': Discovery.InterfaceDiscovery.THRESHOLD_STALE,
        'threshold_remove': Discovery.InterfaceDiscovery.THRESHOLD_REMOVE,
        'status_available': Discovery.InterfaceDiscovery.STATUS_AVAILABLE,
        'status_unknown': Discovery.InterfaceDiscovery.STATUS_UNKNOWN,
        'status_stale': Discovery.InterfaceDiscovery.STATUS_STALE,
    }


def cmd_discovery_store_record(params):
    """Drive the REAL InterfaceDiscovery storage/listing whitelist + dedup paths
    over a GENUINE discovery record.

    Exercises three resolver-store decisions that are made entirely by RNS:
      * the storage-acceptance type whitelist in interface_discovered — a record
        whose type is NOT in InterfaceDiscovery.DISCOVERABLE_TYPES (notably
        TCPClientInterface, which the handler-level DISCOVERABLE_INTERFACE_TYPES
        DOES accept) is received but never written to disk (Discovery.py:457);
      * the re-announce dedup / heard_count increment for a repeated record
        (same transport_id+name -> same discovery_hash filename, Discovery.py:
        356-357,476-495);
      * the listing trust-revocation purge — with an interface_discovery_sources
        allowlist applied at LIST time, a stored record whose network_id is not
        in the allowlist is removed (Discovery.py:417-418).

    The record is a real announce built by get_interface_announce_data (and, when
    set_interface_type forces a type the sender would otherwise rewrite,
    re-stamped through the real craft path), received through real
    received_announce to obtain the genuine info dict, then stored via real
    interface_discovered. The bridge reconstructs no storage logic; it only
    chooses the type/repeat/source allowlist and reads RNS's verdict back: stored
    is a filesystem existence check on the record file RNS wrote, and heard_count
    is read off the info dict real list_discovered_interfaces returns.
    """
    _get_full_rns()
    from RNS import Discovery
    RNS = Discovery.RNS
    _ensure_minimal_rns_on(RNS)

    setattr(RNS.Reticulum, '_Reticulum__transport_enabled', True)
    # Source allowlist seen by received_announce while building the record.
    recv_sources = params.get('recv_sources')
    setattr(RNS.Reticulum, '_Reticulum__interface_sources',
            [hex_to_bytes(s) for s in recv_sources] if recv_sources else [])

    disc = Discovery.InterfaceDiscovery(discover_interfaces=False)

    def _clean():
        for fn in os.listdir(disc.storagepath):
            try:
                os.unlink(os.path.join(disc.storagepath, fn))
            except OSError:
                pass

    _clean()

    set_type = params.get('set_interface_type')
    repeat = int(params.get('repeat', 1))
    stamp_value = params.get('stamp_value', 6)
    fields = params.get('fields') or {
        'name': params.get('name', 'Node'),
        'reachable_on': 'example.com', 'port': 4242}

    if params.get('announce_identity_priv'):
        announced = RNS.Identity.from_bytes(
            hex_to_bytes(params['announce_identity_priv']))
    else:
        announced = RNS.Identity()

    base = {'interface_type': 'TCPServerInterface', 'stamp_value': stamp_value,
            'transport_enabled': True, 'fields': fields}
    if set_type:
        crafted = cmd_discovery_craft_announce({**base, 'set_interface_type': set_type})
        app_data = hex_to_bytes(crafted['app_data'])
    else:
        built = cmd_discovery_build_announce_appdata(base)
        app_data = hex_to_bytes(built['app_data'])

    record_type = None
    discovery_hash = None
    received_ok = False
    for _ in range(repeat):
        captured = {}

        def _cb(info, _c=captured):
            if info:
                _c.update(info)

        handler = Discovery.InterfaceAnnounceHandler(
            required_value=stamp_value, callback=_cb)
        handler.received_announce(announced.hash, announced, app_data)
        if not captured:
            break
        received_ok = True
        record_type = captured.get('type')
        discovery_hash = captured.get('discovery_hash')
        disc.interface_discovered(captured)

    fname = RNS.hexrep(discovery_hash, delimit=False) if discovery_hash else None
    fpath = os.path.join(disc.storagepath, fname) if fname else None
    stored = bool(fpath and os.path.isfile(fpath))

    # Optional trust-revocation purge: apply a (possibly different) allowlist at
    # LIST time and let list_discovered_interfaces enforce it.
    if 'list_sources' in params:
        ls = params['list_sources']
        setattr(RNS.Reticulum, '_Reticulum__interface_sources',
                [hex_to_bytes(s) for s in (ls or [])])
    listed = disc.list_discovered_interfaces()
    listed_names = [i.get('name') for i in listed]

    # heard_count comes off the info dict RNS's list_discovered_interfaces
    # returns (it unpacks the stored record itself); never decoded in-bridge.
    heard_count = None
    for i in listed:
        ih = i.get('discovery_hash')
        if discovery_hash is not None and ih == discovery_hash:
            heard_count = i.get('heard_count')
            break

    _clean()
    return {
        'received': received_ok,
        'record_type': record_type,
        'stored': stored,
        'heard_count': heard_count,
        'discovery_hash': bytes_to_hex(discovery_hash) if discovery_hash else None,
        'listed_names': listed_names,
        'announce_identity_hash': bytes_to_hex(announced.hash),
        'discoverable_types': list(Discovery.InterfaceDiscovery.DISCOVERABLE_TYPES),
        'discoverable_interface_types':
            list(Discovery.InterfaceAnnouncer.DISCOVERABLE_INTERFACE_TYPES),
    }


# Probe interface source: a minimal real RNS Interface subclass that opens no
# sockets/hardware. Loaded via RNS's own external-interface mechanism
# (Reticulum._synthesize_interface -> exec of a module exporting interface_class,
# Reticulum.py:999-1021) so that the full real config-parsing pipeline
# (mode-forcing, bitrate/announce_cap/ifac_size bound checks, discovery-interval
# floor) runs and writes its results onto a genuine interface object we can read.
_CONFIG_PARSE_PROBE_SRC = '''
class ConfigParseProbeInterface(Interface):
    AUTOCONFIGURE_MTU = False
    DEFAULT_IFAC_SIZE = 16
    def __init__(self, owner, configuration):
        super().__init__()
        self.owner = owner
        self.online = False
        self.IN = True
        self.OUT = True
        self.bitrate = 62500
    def process_outgoing(self, data):
        pass
    def __str__(self):
        return "ConfigParseProbeInterface[probe]"
interface_class = ConfigParseProbeInterface
'''

_CONFIG_PARSE_PROBE_TYPE = "ConfigParseProbeInterface"


def _ensure_config_parse_probe(RNS):
    """Write the no-op probe interface module into the live instance's
    interfacepath so RNS's external-interface loader can instantiate it."""
    path = os.path.join(RNS.Reticulum.interfacepath,
                        f"{_CONFIG_PARSE_PROBE_TYPE}.py")
    if not os.path.isfile(path):
        os.makedirs(RNS.Reticulum.interfacepath, exist_ok=True)
        with open(path, "w") as f:
            f.write(_CONFIG_PARSE_PROBE_SRC)


_MODE_NAMES = {
    0x01: "full", 0x02: "pointtopoint", 0x03: "access_point",
    0x04: "roaming", 0x05: "boundary", 0x06: "gateway",
}


def cmd_config_parse_interface(params):
    """Push a raw RNS config string through RNS's OWN interface config parser
    and read back the stored interface attributes.

    Delegates entirely to real RNS: the raw text is parsed by RNS's vendored
    ConfigObj (the exact parser Reticulum uses on its config file), and the
    resulting section is handed to the live Reticulum instance's real
    `_synthesize_interface` (Reticulum.py:685-1034). That method performs all
    the config-derived decisions under test — interface_mode selection and the
    discoverable=true mode-forcing (Reticulum.py:807-848), the
    bitrate>=MINIMUM_BITRATE bound (:765-768), the announce_cap (0,100] bound
    (:791-794), the ifac_size>=IFAC_MIN_SIZE*8 bound (:719-722), and the
    discovery announce-interval 5-minute floor / 6h default (:824-828) — and
    writes them onto a genuine Interface object. The interface is the no-op
    ConfigParseProbeInterface (a real RNS Interface subclass that opens nothing),
    loaded through RNS's external-interface mechanism, so no sockets/hardware are
    touched. We then read the stored attrs straight off RNS and detach the probe.

    params:
        config_text (str): raw config text containing a single [interfaces]
            subsection; the interface `type` must be ConfigParseProbeInterface.
        interface_name (str): the subsection name to synthesize.
    """
    RNS = _ensure_minimal_rns()
    from RNS.vendor.configobj import ConfigObj
    import io as _io

    name = params['interface_name']
    config_text = params['config_text']
    _ensure_config_parse_probe(RNS)

    co = ConfigObj(_io.StringIO(config_text))
    if 'interfaces' not in co or name not in co['interfaces']:
        return {'error': f'config_text has no [[{name}]] under [interfaces]'}
    section = co['interfaces'][name]

    inst = _rns_instance
    before = set(id(i) for i in RNS.Transport.interfaces)
    inst._synthesize_interface(section, name)
    created = [i for i in RNS.Transport.interfaces if id(i) not in before]

    result = {
        # selected_interface_mode and configured_bitrate are written back into
        # the config section by _synthesize_interface (Reticulum.py:925-926).
        'selected_interface_mode': section.get('selected_interface_mode'),
        'configured_bitrate': section.get('configured_bitrate'),
    }
    iface = created[0] if created else None
    if iface is not None:
        mode = int(iface.mode)
        result.update({
            'mode': mode,
            'mode_name': _MODE_NAMES.get(mode),
            'bitrate': int(iface.bitrate),
            'announce_cap': float(iface.announce_cap),
            'ifac_size': int(iface.ifac_size),
            'default_ifac_size': int(iface.DEFAULT_IFAC_SIZE),
            'discoverable': bool(iface.discoverable),
            'discovery_announce_interval': iface.discovery_announce_interval,
            # IFAC credential resolution (Reticulum.py:724-738, :895-916). RNS
            # stores the resolved network name / passphrase straight onto the
            # interface; an empty-string config value resolves to None (unset),
            # and the networkname/network_name and passphrase/pass_phrase aliases
            # both feed the same attribute. ifac_active reflects whether RNS
            # actually derived an IFAC identity (interface.ifac_identity is set
            # iff netname or netkey is non-None).
            'ifac_netname': getattr(iface, 'ifac_netname', None),
            'ifac_netkey': getattr(iface, 'ifac_netkey', None),
            'ifac_active': getattr(iface, 'ifac_identity', None) is not None,
            # Per-interface ingress-control (ic_*) knobs. RNS 1.3.1's
            # Interface.__init__ seeds these from Reticulum.get_instance().
            # _default_ic_* (Interface.py:120-130, falling back to the
            # Interface class constants), and _synthesize_interface overrides
            # them from the [[interface]] config when present
            # (Reticulum.py:744-892). We read them straight off the live
            # interface object so tests can pin both the override path and the
            # class-constant default fallback.
            'ic_max_held_announces': _maybe_num(getattr(iface, 'ic_max_held_announces', None)),
            'ic_burst_hold': _maybe_num(getattr(iface, 'ic_burst_hold', None)),
            'ic_burst_freq_new': _maybe_num(getattr(iface, 'ic_burst_freq_new', None)),
            'ic_burst_freq': _maybe_num(getattr(iface, 'ic_burst_freq', None)),
            'ic_new_time': _maybe_num(getattr(iface, 'ic_new_time', None)),
            'ic_burst_penalty': _maybe_num(getattr(iface, 'ic_burst_penalty', None)),
            'ic_held_release_interval': _maybe_num(getattr(iface, 'ic_held_release_interval', None)),
        })
        RNS.Transport.remove_interface(iface)
    return result


def cmd_interface_default_ifac_size(params):
    """Return the per-class DEFAULT_IFAC_SIZE constants for the RNS interface
    types, read straight off the interface CLASS objects.

    Delegates entirely to real RNS: each value is the class attribute
    `<Interface>.DEFAULT_IFAC_SIZE` (e.g. SerialInterface.py:53 == 8,
    TCPInterface.py:77 == 16). These are static class constants, so the classes
    are merely imported and the attribute read — no instance is built and no
    device/socket is opened (the serial/KISS/RNode classes only touch hardware
    at __init__, which we never call). This pins the spec rule that
    low-bandwidth, framed-serial media (Serial/KISS/AX25KISS/RNode/Pipe) default
    to an 8-byte IFAC authentication tag while packet/IP media (TCP/UDP/Auto)
    default to 16 — an impl that used 16 on serial-class media would partition
    itself from conformant peers on those networks.
    """
    RNS = _ensure_minimal_rns()
    from RNS.Interfaces.SerialInterface import SerialInterface
    from RNS.Interfaces.KISSInterface import KISSInterface
    from RNS.Interfaces.AX25KISSInterface import AX25KISSInterface
    from RNS.Interfaces.RNodeInterface import RNodeInterface
    from RNS.Interfaces.PipeInterface import PipeInterface
    from RNS.Interfaces.TCPInterface import TCPServerInterface, TCPClientInterface
    from RNS.Interfaces.UDPInterface import UDPInterface

    classes = {
        "SerialInterface": SerialInterface,
        "KISSInterface": KISSInterface,
        "AX25KISSInterface": AX25KISSInterface,
        "RNodeInterface": RNodeInterface,
        "PipeInterface": PipeInterface,
        "TCPServerInterface": TCPServerInterface,
        "TCPClientInterface": TCPClientInterface,
        "UDPInterface": UDPInterface,
    }
    return {
        "default_ifac_size": {
            name: int(cls.DEFAULT_IFAC_SIZE) for name, cls in classes.items()
        },
        "ifac_min_size": int(RNS.Reticulum.IFAC_MIN_SIZE),
    }


def cmd_interface_optimise_mtu(params):
    """Run RNS's real Interface.optimise_mtu bitrate->HW_MTU tier mapping.

    Delegates to the live (unbound) RNS.Interfaces.Interface.optimise_mtu
    (Interface.py:198-221), driven over a stand-in carrying exactly the two
    attributes that method reads (AUTOCONFIGURE_MTU, bitrate) and the HW_MTU
    slot it writes — the same stand-in pattern used by the framing read/write
    hooks. The bridge computes no MTU itself: RNS picks the bitrate tier and
    assigns HW_MTU. When autoconfigure is False, RNS leaves HW_MTU untouched
    (the pre-seeded sentinel is returned), pinning that the tier table only
    fires for AUTOCONFIGURE_MTU interfaces.

    params:
        bitrate (int): the interface bitrate (bps) to map.
        autoconfigure (bool, default True): the AUTOCONFIGURE_MTU flag.
    """
    _get_full_rns()
    import types
    from RNS.Interfaces.Interface import Interface

    bitrate = int(params['bitrate'])
    autoconfigure = bool(params.get('autoconfigure', True))
    # Sentinel HW_MTU so a no-op (autoconfigure off) is observable as unchanged.
    sentinel = -1
    stand_in = types.SimpleNamespace(
        AUTOCONFIGURE_MTU=autoconfigure, bitrate=bitrate, HW_MTU=sentinel,
    )
    Interface.optimise_mtu(stand_in)
    return {
        'hw_mtu': stand_in.HW_MTU,
        'unchanged': stand_in.HW_MTU == sentinel,
    }


# Command dispatcher
COMMANDS = {
    'x25519_generate': cmd_x25519_generate,
    'x25519_public_from_private': cmd_x25519_public_from_private,
    'x25519_exchange': cmd_x25519_exchange,
    'ed25519_generate': cmd_ed25519_generate,
    'ed25519_sign': cmd_ed25519_sign,
    'ed25519_verify': cmd_ed25519_verify,
    'sha256': cmd_sha256,
    'sha512': cmd_sha512,
    'hmac_sha256': cmd_hmac_sha256,
    'hkdf': cmd_hkdf,
    'pkcs7_pad': cmd_pkcs7_pad,
    'pkcs7_unpad': cmd_pkcs7_unpad,
    'aes_encrypt': cmd_aes_encrypt,
    'aes_decrypt': cmd_aes_decrypt,
    'aes_256_cbc_encrypt': cmd_aes_256_cbc_encrypt,
    'aes_256_cbc_decrypt': cmd_aes_256_cbc_decrypt,
    'token_encrypt': cmd_token_encrypt,
    'token_decrypt': cmd_token_decrypt,
    'token_verify_hmac': cmd_token_verify_hmac,
    'token_generate_key': cmd_token_generate_key,
    'crypto_provider_op': cmd_crypto_provider_op,
    'identity_from_private_key': cmd_identity_from_private_key,
    'identity_encrypt': cmd_identity_encrypt,
    'identity_decrypt': cmd_identity_decrypt,
    'identity_sign': cmd_identity_sign,
    'identity_verify': cmd_identity_verify,
    'identity_hash': cmd_identity_hash,
    'identity_to_file': cmd_identity_to_file,
    'identity_from_file': cmd_identity_from_file,
    'destination_hash': cmd_destination_hash,
    'truncated_hash': cmd_truncated_hash,
    'name_hash': cmd_name_hash,
    'packet_build': cmd_packet_build,
    'packet_unpack': cmd_packet_unpack,
    'packet_hash': cmd_packet_hash,
    'packet_constants': cmd_packet_constants,
    'packet_context_constants': cmd_packet_context_constants,
    'announce_queue_constants': cmd_announce_queue_constants,
    'packet_build_raw_header2': cmd_packet_build_raw_header2,
    'packet_resend_observe': cmd_packet_resend_observe,
    'identity_random_hash': cmd_identity_random_hash,
    'hdlc_escape': cmd_hdlc_escape,
    # Ratchet operations
    'ratchet_id': cmd_ratchet_id,
    'ratchet_public_from_private': cmd_ratchet_public_from_private,
    'ratchet_encrypt': cmd_ratchet_encrypt,
    'ratchet_decrypt': cmd_ratchet_decrypt,
    'identity_remember': cmd_identity_remember,
    'identity_keyless_op': cmd_identity_keyless_op,
    # Announce operations
    'announce_build': cmd_announce_build,
    'announce_validate': cmd_announce_validate,
    # Compression operations
    'bz2_compress': cmd_bz2_compress,
    'bz2_decompress': cmd_bz2_decompress,
    # Interface framing (HDLC / KISS deframing)
    'hdlc_deframe': cmd_hdlc_deframe,
    'kiss_deframe': cmd_kiss_deframe,
    # Interface framing driven through the real RNS read/write loops
    'hdlc_frame': cmd_hdlc_frame,
    'kiss_frame': cmd_kiss_frame,
    'hdlc_deframe_stream': cmd_hdlc_deframe_stream,
    'kiss_deframe_stream': cmd_kiss_deframe_stream,
    'auto_discovery_token': cmd_auto_discovery_token,
    'interface_hw_mtu': cmd_interface_hw_mtu,
    'rns_start': cmd_rns_start,
    'rns_stop': cmd_rns_stop,
    # Live RNS protocol operations (link, resource, ratchet)
    'rns_create_destination': cmd_rns_create_destination,
    'rns_get_established_link': cmd_rns_get_established_link,
    'rns_link_send': cmd_rns_link_send,
    'rns_link_get_packets': cmd_rns_link_get_packets,
    'rns_link_clear_packets': cmd_rns_link_clear_packets,
    'rns_link_close': cmd_rns_link_close,
    'rns_resource_send': cmd_rns_resource_send,
    'rns_resource_get_received': cmd_rns_resource_get_received,
    'rns_enable_ratchets': cmd_rns_enable_ratchets,
    'rns_rotate_ratchet': cmd_rns_rotate_ratchet,
    'rns_get_ratchet_info': cmd_rns_get_ratchet_info,
    'rns_announce_destination': cmd_rns_announce_destination,
    # Channel messaging
    'rns_channel_setup': cmd_rns_channel_setup,
    'rns_channel_send': cmd_rns_channel_send,
    'rns_channel_get_messages': cmd_rns_channel_get_messages,
    'rns_channel_clear_messages': cmd_rns_channel_clear_messages,
    # Link request/response
    'rns_register_request_handler': cmd_rns_register_request_handler,
    'rns_link_request': cmd_rns_link_request,
    'rns_get_request_responses': cmd_rns_get_request_responses,
    'rns_clear_request_responses': cmd_rns_clear_request_responses,
    # Proof strategy
    'rns_set_proof_strategy': cmd_rns_set_proof_strategy,
    # Destination constructor / lifecycle (Destination.py)
    'destination_construct': cmd_destination_construct,
    'destination_announce_attempt': cmd_destination_announce_attempt,
    'app_and_aspects_from_name': cmd_app_and_aspects_from_name,
    'hash_from_name_and_identity': cmd_hash_from_name_and_identity,
    'destination_expand_name': cmd_destination_expand_name,
    'destination_set_proof_strategy_raw': cmd_destination_set_proof_strategy_raw,
    'destination_rotate_ratchets': cmd_destination_rotate_ratchets,
    'destination_group_encrypt': cmd_destination_group_encrypt,
    'destination_default_app_data': cmd_destination_default_app_data,
    'destination_register_request_handler_validate': cmd_destination_register_request_handler_validate,
    'destination_path_response_cache': cmd_destination_path_response_cache,
    # Interface-discovery subsystem (Discovery.py) — pure-function KATs
    'discovery_build_announce_appdata': cmd_discovery_build_announce_appdata,
    'discovery_receive_announce': cmd_discovery_receive_announce,
    'discovery_stamp': cmd_discovery_stamp,
    'discovery_validate_address': cmd_discovery_validate_address,
    'discovery_sanitize_name': cmd_discovery_sanitize_name,
    'discovery_craft_announce': cmd_discovery_craft_announce,
    'discovery_announce_identity': cmd_discovery_announce_identity,
    'discovery_feature_defaults': cmd_discovery_feature_defaults,
    'discovery_inject_records': cmd_discovery_inject_records,
    'discovery_store_record': cmd_discovery_store_record,
    # Reticulum config parsing — raw config string through RNS's own parser
    'config_parse_interface': cmd_config_parse_interface,
    'interface_default_ifac_size': cmd_interface_default_ifac_size,
    'interface_optimise_mtu': cmd_interface_optimise_mtu,
}

# Behavioral conformance commands (black-box Transport tests).
# See behavioral_transport.py for the rationale and command spec.
try:
    from behavioral_transport import BEHAVIORAL_COMMANDS
    COMMANDS.update(BEHAVIORAL_COMMANDS)
except ImportError:
    # Module not present (older bridge); skip silently
    pass

# Wire-level TCP interop commands (E2E IFAC tests).
# See wire_tcp.py for the rationale and command spec.
try:
    from wire_tcp import WIRE_COMMANDS
    COMMANDS.update(WIRE_COMMANDS)
except ImportError:
    pass


def handle_request(request):
    """Process a single request and return response."""
    req_id = request.get('id', 'unknown')
    command = request.get('command')
    params = request.get('params', {})

    if command not in COMMANDS:
        return {
            'id': req_id,
            'success': False,
            'error': f"Unknown command: {command}"
        }

    try:
        result = COMMANDS[command](params)
        return {
            'id': req_id,
            'success': True,
            'result': result
        }
    except Exception as e:
        return {
            'id': req_id,
            'success': False,
            'error': f"{type(e).__name__}: {str(e)}",
            'traceback': traceback.format_exc()
        }


def main():
    """Main server loop."""
    # Pre-warm the FULL real RNS once, single-threaded, before READY — i.e.
    # before any command runs and before any Reticulum background thread can
    # exist. `import RNS` transitively loads RNS.Channel + RNS.Buffer (its
    # __init__ does `from .Channel import ...` / `from .Buffer import ...`),
    # which is what the wire/channel/buffer handlers pull in lazily
    # (`from RNS.Channel import ...`) on RNS callback threads.
    #
    # Crucially we route through `_get_full_rns()` rather than a bare
    # `import RNS.Channel`: that POPULATES the module cache AND, by leaving a
    # fully-initialised RNS resident in sys.modules, makes every later
    # `_get_full_rns()` — including the SEPARATE `bridge_server` module-identity
    # copy used by wire_tcp — ADOPT this RNS instead of wiping+reimporting it.
    # The old bare-import pre-warm cached nothing, so the first wire command
    # still wiped (single-threaded) and a later __main__ command wiped AGAIN
    # while Reticulum threads ran — the import-lock race that produced the
    # flaky `_DeadlockError` / "partially initialized module 'RNS.Channel'".
    #
    # Best-effort: a resolution failure must not abort the bridge. If the load
    # genuinely fails it leaves no fully-initialised RNS resident, so the first
    # real command's `_get_full_rns()` recovers it (still single-threaded,
    # before any thread) via the clean-slate path.
    try:
        _get_full_rns()
    except Exception:
        pass

    # Pre-warm the FULL real LXMF once, single-threaded, before READY — same
    # rationale as the RNS pre-warm above. The interface-discovery commands
    # (cmd_discovery_stamp / cmd_discovery_build_announce_appdata / ...) lazily
    # do `from LXMF import LXStamper` while RNS background threads run. LXMF's
    # package __init__ is a HEAVY transitive import (LXMessage, LXMRouter,
    # LXMF.LXStamper, and a wide slice of RNS). Importing it for the first time
    # on a handler thread under parallel CPU contention races itself / the RNS
    # submodule loader -> "partially initialized module 'LXMF'" / "No module
    # named 'LXMF'" (the LXMF twin of the RNS.Channel import race). Loading it
    # here — after real RNS is resident, before any thread exists — makes every
    # later `from LXMF import ...` a pure sys.modules lookup. Best-effort: a
    # failure must not abort the bridge; the command path imports on demand.
    try:
        import LXMF.LXStamper  # noqa: F401
    except Exception:
        pass

    # Signal ready
    print("READY", flush=True)

    # After READY, reroute stdout to stderr so RNS.log() (which writes to
    # sys.stdout by default) doesn't pollute the JSON-RPC channel — and
    # so its diagnostics are actually visible when wrapping the bridge
    # for stderr capture.
    _stdout_for_rpc = sys.stdout
    sys.stdout = sys.stderr

    # Process commands
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response), flush=True, file=_stdout_for_rpc)
        except json.JSONDecodeError as e:
            error_response = {
                'id': 'parse_error',
                'success': False,
                'error': f"JSON parse error: {e}"
            }
            print(json.dumps(error_response), flush=True, file=_stdout_for_rpc)


if __name__ == '__main__':
    main()
