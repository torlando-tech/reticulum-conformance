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
import multiprocessing

# Patch multiprocessing.set_start_method to be no-op after first call
# This is needed because LXMF.LXStamper calls it without force=True,
# which fails on Python 3.14+ if context is already set
_original_set_start_method = multiprocessing.set_start_method
_start_method_set = False

def _patched_set_start_method(method, force=False):
    global _start_method_set
    if _start_method_set and not force:
        return  # Silently ignore if already set
    _original_set_start_method(method, force=True)
    _start_method_set = True

multiprocessing.set_start_method = _patched_set_start_method
multiprocessing.set_start_method("fork")  # Pre-set to fork

# Add RNS Cryptography to path directly (bypass RNS __init__.py)
rns_path = os.environ.get('PYTHON_RNS_PATH', '../../../Reticulum')
# Convert to absolute path
rns_path = os.path.abspath(rns_path)
sys.path.insert(0, os.path.join(rns_path, 'RNS', 'Cryptography'))
sys.path.insert(0, rns_path)

# Add LXMF to path
lxmf_path = os.path.abspath(os.environ.get('PYTHON_LXMF_PATH', '../../../LXMF'))
sys.path.insert(0, lxmf_path)

import hashlib

# Import umsgpack from RNS vendor
sys.path.insert(0, os.path.join(rns_path, 'RNS', 'vendor'))
import umsgpack

# Import LXMF stamper (used for stamp generation/validation)
import LXMF.LXStamper as LXStamper

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
# This prevents triggering the full RNS import chain
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
    """Compute truncated hash (first 16 bytes of SHA256)."""
    data = hex_to_bytes(params['data'])
    full_hash = hashlib.sha256(data).digest()
    truncated = full_hash[:16]

    return {
        'hash': bytes_to_hex(truncated),
        'full_hash': bytes_to_hex(full_hash)
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
    point. dest_type selects the destination kind (which sets the
    destination_type flag bits and decides whether the payload is encrypted:
    PLAIN carries the payload in the clear so the wire bytes round-trip
    exactly, SINGLE encrypts non-announce data so only the header bytes do).

    HEADER_2 (transport-relayed) DATA packets are not buildable here — RNS
    only produces them inside Transport while relaying, so their wire format
    is covered by the live multi-hop tests in
    tests/wire/test_link_multihop.py, not synthetically.
    """
    RNS = _get_full_rns()
    dest_type = params.get('dest_type', 'plain')
    packet_type = int(params.get('packet_type', RNS.Packet.DATA))
    context = int(params.get('context', 0))
    context_flag = int(params.get('context_flag', 0))
    transport_type = int(params.get('transport_type', RNS.Transport.BROADCAST))
    hops = int(params.get('hops', 0))
    data = hex_to_bytes(params.get('data', ''))

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
    else:
        raise ValueError(
            f"unsupported dest_type: {dest_type!r} (use 'plain' or 'single')"
        )

    packet = RNS.Packet(
        destination, data,
        packet_type=packet_type,
        context=context,
        transport_type=transport_type,
        header_type=RNS.Packet.HEADER_1,
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
    """Decrypt a ratchet-encrypted ciphertext with the Identity's private key
    and the matching ratchet private key.

    Delegates to real RNS.Identity.decrypt(ciphertext, ratchets=[ratchet_private]).
    """
    RNS = _get_full_rns()
    private_key = hex_to_bytes(params['private_key'])
    ratchet_private = hex_to_bytes(params['ratchet_private'])
    ciphertext = hex_to_bytes(params['ciphertext'])
    identity = RNS.Identity.from_bytes(private_key)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes rejected the private key")
    plaintext = identity.decrypt(ciphertext, ratchets=[ratchet_private])
    return {'plaintext': bytes_to_hex(plaintext) if plaintext is not None else None}



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


def cmd_lxmf_stamp_workblock(params):
    """Generate stamp workblock from message ID.

    Uses LXStamper.stamp_workblock() for exact Python compatibility.
    Default expand_rounds=3000 for standard LXMF stamps.
    """
    message_id = hex_to_bytes(params['message_id'])
    expand_rounds = int(params.get('expand_rounds', 3000))

    workblock = LXStamper.stamp_workblock(message_id, expand_rounds=expand_rounds)

    return {
        'workblock': bytes_to_hex(workblock),
        'size': len(workblock)
    }


def cmd_lxmf_stamp_valid(params):
    """Validate stamp against target cost and workblock.

    Uses LXStamper.stamp_valid() and stamp_value() for exact Python compatibility.
    """
    stamp = hex_to_bytes(params['stamp'])
    target_cost = int(params['target_cost'])
    workblock = hex_to_bytes(params['workblock'])

    valid = LXStamper.stamp_valid(stamp, target_cost, workblock)
    value = LXStamper.stamp_value(workblock, stamp) if valid else 0

    return {
        'valid': valid,
        'value': value
    }


def cmd_lxmf_stamp_generate(params):
    """Generate stamp meeting target cost.

    Uses LXStamper.generate_stamp() for exact Python compatibility.
    WARNING: Can be slow for high costs. Use expand_rounds=25 for quick tests.
    """
    message_id = hex_to_bytes(params['message_id'])
    stamp_cost = int(params['stamp_cost'])
    expand_rounds = int(params.get('expand_rounds', 3000))

    stamp, value = LXStamper.generate_stamp(message_id, stamp_cost, expand_rounds=expand_rounds)

    return {
        'stamp': bytes_to_hex(stamp) if stamp else None,
        'value': value
    }


# ============================================================================
# Live Reticulum/LXMF Networking Commands
# ============================================================================
# These commands start actual Reticulum instances and LXMF routers for
# end-to-end interoperability testing. Unlike the crypto-only commands above,
# these use the full RNS import and manage network state.

# Global state for live networking
_rns_instance = None
_lxmf_router = None
_lxmf_identity = None
_lxmf_destination = None
_received_messages = []
_rns_module = None  # Cached RNS module


def _get_full_rns():
    """Import full RNS module for networking.

    Returns the cached RNS module, or imports it if not already done.
    IMPORTANT: This clears ALL RNS-related modules and reimports cleanly.
    """
    global _rns_module

    if _rns_module is not None:
        return _rns_module

    import importlib
    import sys

    # Remove ALL RNS-related modules to get a clean slate
    # This includes fake modules (RNS_HMAC, etc.) and any partial imports
    modules_to_remove = [k for k in list(sys.modules.keys())
                         if k.startswith('RNS') or k.startswith('LXMF')]
    for mod in modules_to_remove:
        try:
            del sys.modules[mod]
        except KeyError:
            pass

    # Import real RNS fresh
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


def cmd_lxmf_start_router(params):
    """Start LXMF router with delivery destination.

    params:
        identity_hex (str, optional): 64-byte private key hex (X25519 + Ed25519)
        display_name (str, optional): Display name for announcements

    Returns:
        identity_hash (hex): Hash of the router identity
        destination_hash (hex): Hash of the delivery destination
    """
    global _lxmf_router, _lxmf_identity, _lxmf_destination, _received_messages

    import tempfile

    identity_hex = params.get('identity_hex')
    display_name = params.get('display_name')

    RNS = _get_full_rns()
    import LXMF

    # Create or restore identity
    if identity_hex:
        private_key = hex_to_bytes(identity_hex)
        _lxmf_identity = RNS.Identity.from_bytes(private_key)
    else:
        _lxmf_identity = RNS.Identity()

    # Create storage path
    storage_path = tempfile.mkdtemp(prefix='lxmf_test_')

    # Create LXMF router
    _lxmf_router = LXMF.LXMRouter(
        identity=_lxmf_identity,
        storagepath=storage_path
    )

    # Register delivery identity
    _lxmf_destination = _lxmf_router.register_delivery_identity(
        _lxmf_identity,
        display_name=display_name
    )

    # Clear received messages
    _received_messages = []

    # Set delivery callback
    def delivery_callback(message):
        global _received_messages
        msg_data = {
            'source_hash': bytes_to_hex(message.source_hash),
            'destination_hash': bytes_to_hex(message.destination_hash),
            'content': message.content.decode('utf-8') if isinstance(message.content, bytes) else message.content,
            'title': message.title.decode('utf-8') if isinstance(message.title, bytes) else message.title,
            'timestamp': message.timestamp,
            'fields': {}
        }
        if hasattr(message, 'hash') and message.hash:
            msg_data['hash'] = bytes_to_hex(message.hash)
        if hasattr(message, 'fields') and message.fields:
            for k, v in message.fields.items():
                if isinstance(v, bytes):
                    msg_data['fields'][str(k)] = bytes_to_hex(v)
                else:
                    msg_data['fields'][str(k)] = v
        _received_messages.append(msg_data)

    _lxmf_router.register_delivery_callback(delivery_callback)

    return {
        'identity_hash': bytes_to_hex(_lxmf_identity.hash),
        'destination_hash': bytes_to_hex(_lxmf_destination.hash),
        'identity_public_key': bytes_to_hex(_lxmf_identity.get_public_key())
    }


def cmd_lxmf_get_messages(params):
    """Get received LXMF messages.

    Returns list of received messages with decoded content.
    """
    global _received_messages

    return {
        'messages': _received_messages,
        'count': len(_received_messages)
    }


def cmd_lxmf_clear_messages(params):
    """Clear received messages list."""
    global _received_messages
    _received_messages = []

    return {
        'cleared': True
    }


def cmd_lxmf_announce(params):
    """Announce the LXMF delivery destination.

    This makes the LXMF destination known on the network so other nodes
    can discover it and send messages.

    Returns:
        announced (bool): True if announced successfully
        destination_hash (hex): Hash of the announced destination
    """
    global _lxmf_router, _lxmf_destination

    if not _lxmf_router or not _lxmf_destination:
        return {
            'announced': False,
            'error': 'LXMF router not started'
        }

    # Announce the delivery destination
    _lxmf_router.announce(_lxmf_destination.hash)

    return {
        'announced': True,
        'destination_hash': bytes_to_hex(_lxmf_destination.hash)
    }


def cmd_lxmf_send_direct(params):
    """Send LXMF message via DIRECT delivery.

    params:
        destination_hash (hex): Destination hash (16 bytes)
        content (str): Message content
        title (str, optional): Message title
        fields (dict, optional): Additional fields

    Returns:
        sent (bool): True if message was queued
        message_hash (hex): Hash of the sent message
        status (str): Status of the send operation

    Note: This command requires that the destination has been announced
    and is known to the transport layer. For testing, announce the
    destination first before trying to send.
    """
    global _lxmf_router, _lxmf_identity, _lxmf_destination

    if not _lxmf_router:
        return {
            'sent': False,
            'status': 'error',
            'error': 'LXMF router not started'
        }

    RNS = _get_full_rns()
    import LXMF

    destination_hash = hex_to_bytes(params['destination_hash'])
    content = params['content']
    title = params.get('title', '')
    fields = params.get('fields', {})

    # Convert string field keys to int
    if fields:
        fields = {int(k): v for k, v in fields.items()}

    # Try to find the identity for this destination from recalled identities
    # This is needed because LXMF requires a proper Destination object
    identity = RNS.Identity.recall(destination_hash)
    if identity is None:
        # Check if we have a path at least
        has_path = RNS.Transport.has_path(destination_hash)
        return {
            'sent': False,
            'status': 'no_identity',
            'error': f'No identity recalled for destination {destination_hash.hex()}',
            'has_path': has_path
        }

    # Create an LXMF delivery destination from the recalled identity
    # LXMF uses "lxmf" app name and "delivery" aspect
    destination = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery"
    )

    # Create a message with DIRECT method
    message = LXMF.LXMessage(
        destination=destination,
        source=_lxmf_destination,  # Our delivery destination as source
        content=content,
        title=title,
        fields=fields if fields else None,
        desired_method=LXMF.LXMessage.DIRECT
    )

    # Send via router
    _lxmf_router.handle_outbound(message)

    return {
        'sent': True,
        'status': 'queued',
        'message_hash': bytes_to_hex(message.hash) if message.hash else None
    }


def cmd_lxmf_send_opportunistic(params):
    """Send LXMF message via OPPORTUNISTIC delivery.

    params:
        destination_hash (hex): Destination hash (16 bytes)
        content (str): Message content
        title (str, optional): Message title
        fields (dict, optional): Additional fields

    Returns:
        sent (bool): True if message was queued
        message_hash (hex): Hash of the sent message
        method (str): "opportunistic"

    Note: This command requires that the destination has been announced
    and the identity is known to the transport layer.
    """
    global _lxmf_router, _lxmf_identity, _lxmf_destination

    if not _lxmf_router:
        return {
            'sent': False,
            'error': 'LXMF router not started'
        }

    RNS = _get_full_rns()
    import LXMF

    destination_hash = hex_to_bytes(params['destination_hash'])
    content = params['content']
    title = params.get('title', '')
    fields = params.get('fields', {})

    # Convert string field keys to int
    if fields:
        fields = {int(k): v for k, v in fields.items()}

    # Recall identity from destination hash
    identity = RNS.Identity.recall(destination_hash)
    if identity is None:
        return {
            'sent': False,
            'error': f'Cannot recall identity for {destination_hash.hex()}'
        }

    # Create outbound destination
    destination = RNS.Destination(
        identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery"
    )

    # Create LXMF message with OPPORTUNISTIC method
    message = LXMF.LXMessage(
        destination=destination,
        source=_lxmf_destination,
        content=content,
        title=title,
        fields=fields if fields else None,
        desired_method=LXMF.LXMessage.OPPORTUNISTIC
    )

    # Handle outbound
    _lxmf_router.handle_outbound(message)

    return {
        'sent': True,
        'message_hash': bytes_to_hex(message.hash) if message.hash else None,
        'method': 'opportunistic'
    }


def cmd_propagation_node_start(params):
    """Start propagation node with configurable stamp cost.

    params:
        stamp_cost (int, optional): Required stamp cost (default 8 for fast tests)
        stamp_flexibility (int, optional): Stamp cost flexibility (default 0)

    Returns:
        propagation_hash (hex): Hash of the propagation destination
        stamp_cost (int): Configured stamp cost
        stamp_flexibility (int): Configured flexibility
        identity_hash (hex): Hash of the router identity
        identity_public_key (hex): Public key of the router identity
    """
    global _lxmf_router

    if _lxmf_router is None:
        return {'error': 'LXMF router not started'}

    stamp_cost = int(params.get('stamp_cost', 8))
    stamp_flexibility = int(params.get('stamp_flexibility', 0))

    # Configure stamp cost before enabling propagation
    _lxmf_router.propagation_stamp_cost = stamp_cost
    _lxmf_router.propagation_stamp_cost_flexibility = stamp_flexibility

    # Enable propagation node functionality
    _lxmf_router.enable_propagation()

    # Get the propagation destination hash
    propagation_hash = _lxmf_router.propagation_destination.hash

    return {
        'propagation_hash': bytes_to_hex(propagation_hash),
        'stamp_cost': stamp_cost,
        'stamp_flexibility': stamp_flexibility,
        'identity_hash': bytes_to_hex(_lxmf_router.identity.hash),
        'identity_public_key': bytes_to_hex(_lxmf_router.identity.get_public_key())
    }


def cmd_propagation_node_get_messages(params):
    """Get list of messages stored on propagation node.

    Returns:
        messages (list): List of stored messages with transient_id, destination_hash, etc.
        count (int): Number of messages stored
    """
    global _lxmf_router

    if _lxmf_router is None:
        return {'error': 'LXMF router not started'}

    if not _lxmf_router.propagation_node:
        return {'error': 'Propagation not enabled'}

    messages = []
    for transient_id, entry in _lxmf_router.propagation_entries.items():
        # entry = [dest_hash, filepath, received_time, size, handled_peers, unhandled_peers, stamp_value]
        messages.append({
            'transient_id': bytes_to_hex(transient_id),
            'destination_hash': bytes_to_hex(entry[0]),
            'received_time': entry[2],
            'size': entry[3],
            'stamp_value': entry[6] if len(entry) > 6 else 0
        })

    return {'messages': messages, 'count': len(messages)}


def cmd_propagation_node_submit_for_recipient(params):
    """Store a test message for a recipient on the propagation node.

    This creates an LXMF message from the router's identity addressed to the
    specified recipient and stores it directly in the propagation node's
    message store for retrieval testing.

    params:
        recipient_hash (hex): Destination hash of the recipient (16 bytes)
        content (str): Message content
        title (str, optional): Message title
        image_hex (hex, optional): Image content as hex string
        image_extension (str, optional): Image file extension (e.g. "png")

    Returns:
        submitted (bool): True if message was stored
        transient_id (hex): Transient ID of the stored message
    """
    global _lxmf_router, _lxmf_identity, _lxmf_destination

    if _lxmf_router is None:
        return {'error': 'LXMF router not started', 'submitted': False}

    if not _lxmf_router.propagation_node:
        return {'error': 'Propagation not enabled', 'submitted': False}

    RNS = _get_full_rns()
    import LXMF

    recipient_hash = hex_to_bytes(params['recipient_hash'])
    content = params.get('content', 'Test message for propagation')
    title = params.get('title', '')

    # Recall identity for the recipient or create a fake destination
    # For test purposes, we need to create a message that can be stored
    recipient_identity = RNS.Identity.recall(recipient_hash)

    if recipient_identity is None:
        # Create a temporary identity for encryption if recipient not known
        # This is a test scenario - in production the recipient would be announced
        return {
            'error': f'Cannot recall identity for recipient {recipient_hash.hex()}. Announce the recipient first.',
            'submitted': False
        }

    # Create destination for recipient
    recipient_destination = RNS.Destination(
        recipient_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery"
    )

    # Create LXMF message with PROPAGATED method
    message = LXMF.LXMessage(
        destination=recipient_destination,
        source=_lxmf_destination,
        content=content,
        title=title,
        desired_method=LXMF.LXMessage.PROPAGATED
    )

    # Add image field if provided
    image_hex = params.get('image_hex', None)
    image_extension = params.get('image_extension', None)
    if image_hex and image_extension:
        image_bytes = bytes.fromhex(image_hex)
        message.fields = {
            LXMF.FIELD_IMAGE: [
                image_extension.encode('utf-8'),
                image_bytes
            ]
        }

    # Pack the message for propagation format
    # This encrypts it for the recipient and creates the propagation format
    message.pack()

    # Get the propagation-formatted data
    # For propagation, the message is encrypted for the destination
    lxmf_data = message.propagation_packed
    if lxmf_data is None:
        # Fallback: manually create propagation format
        # propagation format = dest_hash + encrypted(source_hash + sig + payload)
        encrypted_data = recipient_destination.encrypt(message.packed[LXMF.LXMessage.DESTINATION_LENGTH:])
        lxmf_data = message.packed[:LXMF.LXMessage.DESTINATION_LENGTH] + encrypted_data

    # Extract just the message data (without timebase wrapper)
    # lxmf_propagation expects raw lxmf_data, not the propagation_packed wrapper
    import time
    transient_id = RNS.Identity.full_hash(lxmf_data)

    # Store directly using lxmf_propagation method
    # This handles all the storage logic including peer distribution
    result = _lxmf_router.lxmf_propagation(
        lxmf_data,
        stamp_value=0,  # No stamp required for test messages
        stamp_data=b''
    )

    if result:
        return {
            'submitted': True,
            'transient_id': bytes_to_hex(transient_id),
            'message_hash': bytes_to_hex(message.hash) if message.hash else None
        }
    else:
        return {
            'submitted': False,
            'error': 'Failed to store message in propagation node'
        }


def cmd_propagation_node_announce(params):
    """Announce the propagation node destination.

    This makes the propagation node discoverable on the network.

    Returns:
        announced (bool): True if announced
        propagation_hash (hex): Hash of the propagation destination
    """
    global _lxmf_router

    if _lxmf_router is None:
        return {'error': 'LXMF router not started', 'announced': False}

    if not _lxmf_router.propagation_node:
        return {'error': 'Propagation not enabled', 'announced': False}

    # Announce the propagation destination
    _lxmf_router.announce_propagation_node()

    return {
        'announced': True,
        'propagation_hash': bytes_to_hex(_lxmf_router.propagation_destination.hash)
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


# ─── Local Client Reader ───────────────────────────────────────────
# Raw TCP socket that connects to Kotlin's LocalServerInterface as a passive
# packet reader. Used by E2E tests to inspect forwarded announce headers.

_local_client_socket = None
_local_client_thread = None
_local_client_packets = []      # list of bytes (deframed packets)
_local_client_lock = __import__('threading').Lock()
_local_client_running = False


def _local_client_read_loop(sock):
    """Background thread: read HDLC-framed packets from the socket."""
    import socket as _socket
    global _local_client_running
    buf = bytearray()
    in_frame = False

    try:
        while _local_client_running:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break

            for b in chunk:
                if b == HDLC_FLAG:
                    if in_frame and len(buf) > 0:
                        # End of frame — unescape and store
                        unescaped = bytearray()
                        i = 0
                        while i < len(buf):
                            if buf[i] == HDLC_ESC and i + 1 < len(buf):
                                unescaped.append(buf[i + 1] ^ HDLC_ESC_MASK)
                                i += 2
                            else:
                                unescaped.append(buf[i])
                                i += 1
                        with _local_client_lock:
                            _local_client_packets.append(bytes(unescaped))
                    # Start new frame
                    buf = bytearray()
                    in_frame = True
                elif in_frame:
                    buf.append(b)
    except Exception:
        pass
    finally:
        _local_client_running = False


def cmd_local_client_connect(params):
    """Connect a raw TCP socket to a LocalServerInterface as a passive reader.

    params:
        host (str): hostname (default '127.0.0.1')
        port (int): TCP port
    returns:
        connected (bool)
    """
    import socket
    import threading

    global _local_client_socket, _local_client_thread
    global _local_client_packets, _local_client_running

    host = params.get('host', '127.0.0.1')
    port = int(params['port'])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    sock.settimeout(1.0)        # non-blocking-ish for read loop

    _local_client_socket = sock
    _local_client_running = True
    with _local_client_lock:
        _local_client_packets.clear()

    _local_client_thread = threading.Thread(
        target=_local_client_read_loop, args=(sock,), daemon=True
    )
    _local_client_thread.start()

    return {'connected': True}


def cmd_local_client_disconnect(params):
    """Close the local client socket."""
    global _local_client_socket, _local_client_thread, _local_client_running

    _local_client_running = False

    if _local_client_socket:
        try:
            _local_client_socket.close()
        except Exception:
            pass
        _local_client_socket = None

    if _local_client_thread:
        _local_client_thread.join(timeout=2.0)
        _local_client_thread = None

    return {'disconnected': True}


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
    'token_encrypt': cmd_token_encrypt,
    'token_decrypt': cmd_token_decrypt,
    'token_verify_hmac': cmd_token_verify_hmac,
    'identity_from_private_key': cmd_identity_from_private_key,
    'identity_encrypt': cmd_identity_encrypt,
    'identity_decrypt': cmd_identity_decrypt,
    'identity_sign': cmd_identity_sign,
    'identity_verify': cmd_identity_verify,
    'identity_hash': cmd_identity_hash,
    'destination_hash': cmd_destination_hash,
    'truncated_hash': cmd_truncated_hash,
    'name_hash': cmd_name_hash,
    'packet_build': cmd_packet_build,
    'packet_unpack': cmd_packet_unpack,
    'packet_hash': cmd_packet_hash,
    # Ratchet operations
    'ratchet_id': cmd_ratchet_id,
    'ratchet_public_from_private': cmd_ratchet_public_from_private,
    'ratchet_encrypt': cmd_ratchet_encrypt,
    'ratchet_decrypt': cmd_ratchet_decrypt,
    # Announce operations
    'announce_build': cmd_announce_build,
    'announce_validate': cmd_announce_validate,
    # Compression operations
    'bz2_compress': cmd_bz2_compress,
    'bz2_decompress': cmd_bz2_decompress,
    # LXMF stamp operations (real LXStamper delegation)
    'lxmf_stamp_workblock': cmd_lxmf_stamp_workblock,
    'lxmf_stamp_valid': cmd_lxmf_stamp_valid,
    'lxmf_stamp_generate': cmd_lxmf_stamp_generate,
    # Live Reticulum/LXMF networking
    'rns_start': cmd_rns_start,
    'rns_stop': cmd_rns_stop,
    'lxmf_start_router': cmd_lxmf_start_router,
    'lxmf_get_messages': cmd_lxmf_get_messages,
    'lxmf_clear_messages': cmd_lxmf_clear_messages,
    'lxmf_announce': cmd_lxmf_announce,
    'lxmf_send_direct': cmd_lxmf_send_direct,
    'lxmf_send_opportunistic': cmd_lxmf_send_opportunistic,
    # Propagation node operations
    'propagation_node_start': cmd_propagation_node_start,
    'propagation_node_get_messages': cmd_propagation_node_get_messages,
    'propagation_node_submit_for_recipient': cmd_propagation_node_submit_for_recipient,
    'propagation_node_announce': cmd_propagation_node_announce,
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
    # Local client reader (raw socket for E2E announce forwarding tests)
    'local_client_connect': cmd_local_client_connect,
    'local_client_disconnect': cmd_local_client_disconnect,
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

# LXMF-layer conformance commands (propagation E2E tests). Layered on top
# of wire_tcp — lxmf_start binds to an existing wire handle rather than
# reinitializing RNS. See lxmf_bridge.py for the rationale.
try:
    from lxmf_bridge import LXMF_COMMANDS
    COMMANDS.update(LXMF_COMMANDS)
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
