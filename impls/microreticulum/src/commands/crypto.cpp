// Crypto commands. Each delegates to microReticulum's RNS::Cryptography
// namespace where it has a clean wrapper, and to the underlying rweather
// Crypto headers (SHA256, AES, Curve25519, Ed25519) where it doesn't.

#include "../bridge.h"

// microReticulum crypto headers — Bytes.h is included transitively.
#include "Bytes.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/HMAC.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/AES.h"
#include "Cryptography/PKCS7.h"
#include "Cryptography/X25519.h"
#include "Cryptography/Ed25519.h"

#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace {

// Convert std::vector<uint8_t> <-> RNS::Bytes for crossings into microRet.
inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

// Raw AES-256-CBC block cipher with operand-length enforcement.
//
// rweather's CBC<AES256> setKey()/setIV() do NOT throw on a mis-sized operand —
// they silently return false and then encrypt/decrypt under a zeroed (or
// otherwise garbage) key, producing output rather than an error. RNS's own
// AES-256 path is fixed-width by construction, so we pin the AES-256 invariants
// here (32-byte key, 16-byte IV) and reject anything else. No padding is
// applied: RNS.Cryptography.AES does none either (PKCS7 lives only in Token),
// so ciphertext length == plaintext length and the plaintext must already be
// block-aligned.
inline RNS::Bytes aes256_cbc_encrypt(const bridge::Bytes& plaintext,
                                     const bridge::Bytes& key,
                                     const bridge::Bytes& iv) {
    if (key.size() != 32) {
        throw std::runtime_error("aes_256_cbc: key must be 32 bytes");
    }
    if (iv.size() != 16) {
        throw std::runtime_error("aes_256_cbc: iv must be 16 bytes");
    }
    return RNS::Cryptography::AES_256_CBC::encrypt(to_rns(plaintext), to_rns(key), to_rns(iv));
}
inline RNS::Bytes aes256_cbc_decrypt(const bridge::Bytes& ciphertext,
                                     const bridge::Bytes& key,
                                     const bridge::Bytes& iv) {
    if (key.size() != 32) {
        throw std::runtime_error("aes_256_cbc: key must be 32 bytes");
    }
    if (iv.size() != 16) {
        throw std::runtime_error("aes_256_cbc: iv must be 16 bytes");
    }
    return RNS::Cryptography::AES_256_CBC::decrypt(to_rns(ciphertext), to_rns(key), to_rns(iv));
}

}  // namespace

// === Hashing ===

REGISTER_COMMAND(sha256, {
    auto data = bridge::hex_param(p, "data");
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::json{{"hash", bridge::to_hex(from_rns(h))}};
})

REGISTER_COMMAND(sha512, {
    auto data = bridge::hex_param(p, "data");
    auto h = RNS::Cryptography::sha512(to_rns(data));
    return bridge::json{{"hash", bridge::to_hex(from_rns(h))}};
})

REGISTER_COMMAND(hmac_sha256, {
    // BUG WORKAROUND: RNS::Cryptography::digest() at HMAC.h:103 calls
    // hmac.update(msg) AFTER passing msg into the constructor (which already
    // called update(msg)) — so the message gets HMAC'd twice. We avoid the
    // bug by constructing with empty msg and calling update() once.
    auto key = bridge::hex_param(p, "key");
    auto msg = bridge::hex_param(p, "message");
    RNS::Cryptography::HMAC hmac(to_rns(key), RNS::Bytes(), RNS::Cryptography::HMAC::DIGEST_SHA256);
    hmac.update(to_rns(msg));
    auto h = hmac.digest();
    return bridge::json{{"hmac", bridge::to_hex(from_rns(h))}};
})

REGISTER_COMMAND(truncated_hash, {
    // Reticulum's "truncated hash" = first 16 bytes of SHA-256.
    auto data = bridge::hex_param(p, "data");
    auto full = RNS::Cryptography::sha256(to_rns(data));
    bridge::Bytes truncated(full.data(), full.data() + 16);
    return bridge::json{{"hash", bridge::to_hex(truncated)}};
})

// === Key derivation ===

REGISTER_COMMAND(hkdf, {
    int length = bridge::int_param(p, "length");
    // Mirror Python RNS/Cryptography/HKDF.py:41 — reject length < 1.
    // Without this guard a negative `int` silently wraps to a huge `size_t`
    // when cast below, asking the HKDF impl to allocate exabytes.
    if (length <= 0) {
        throw std::runtime_error("hkdf: length must be a positive integer");
    }
    auto ikm = bridge::hex_param(p, "ikm");
    auto salt = bridge::hex_param_or_empty(p, "salt");
    auto info = bridge::hex_param_or_empty(p, "info");
    auto derived = RNS::Cryptography::hkdf(
        (size_t)length, to_rns(ikm), to_rns(salt), to_rns(info));
    return bridge::json{{"derived_key", bridge::to_hex(from_rns(derived))}};
})

// === AES (key length picks AES-128 vs AES-256) ===

// `aes_encrypt` / `aes_decrypt` are the PKCS7+CBC COMPOSITE the reference
// exposes (bridge_server.cmd_aes_encrypt pads via RNS PKCS7 before CBC, and
// cmd_aes_decrypt unpads after) — the same primitive RNS's Token layer uses.
// The bare, no-padding block cipher is `aes_256_cbc_encrypt`/`decrypt` below.
// Padding uses the bridge's spec-correct PKCS7 (the fork's PKCS7::pad has a
// zero-fill bug), which is byte-identical to RNS PKCS7 — see test_token.
REGISTER_COMMAND(aes_encrypt, {
    auto plaintext = bridge::hex_param(p, "plaintext");
    auto key = bridge::hex_param(p, "key");
    auto iv = bridge::hex_param(p, "iv");
    auto padded = bridge::pkcs7_pad(plaintext);
    // Mirror Python RNS/Cryptography/AES.py — AES_128_CBC requires len(key)==16,
    // AES_256_CBC requires len(key)==32. Reject anything else (including
    // 24-byte AES-192 attempts) rather than silently routing to AES-256
    // and reading past the end of the supplied buffer.
    RNS::Bytes ct;
    if (key.size() == 16) {
        ct = RNS::Cryptography::AES_128_CBC::encrypt(to_rns(padded), to_rns(key), to_rns(iv));
    } else if (key.size() == 32) {
        ct = RNS::Cryptography::AES_256_CBC::encrypt(to_rns(padded), to_rns(key), to_rns(iv));
    } else {
        throw std::runtime_error("aes_encrypt: key must be 16 or 32 bytes");
    }
    return bridge::json{{"ciphertext", bridge::to_hex(from_rns(ct))}};
})

REGISTER_COMMAND(aes_decrypt, {
    auto ciphertext = bridge::hex_param(p, "ciphertext");
    auto key = bridge::hex_param(p, "key");
    auto iv = bridge::hex_param(p, "iv");
    // See aes_encrypt above — same key-length invariant.
    RNS::Bytes pt;
    if (key.size() == 16) {
        pt = RNS::Cryptography::AES_128_CBC::decrypt(to_rns(ciphertext), to_rns(key), to_rns(iv));
    } else if (key.size() == 32) {
        pt = RNS::Cryptography::AES_256_CBC::decrypt(to_rns(ciphertext), to_rns(key), to_rns(iv));
    } else {
        throw std::runtime_error("aes_decrypt: key must be 16 or 32 bytes");
    }
    auto unpadded = bridge::pkcs7_unpad(from_rns(pt));
    return bridge::json{{"plaintext", bridge::to_hex(unpadded)}};
})

// === Raw AES-256-CBC (explicit, no padding) ===
//
// The bare block cipher, distinct from `aes_encrypt`/`aes_decrypt` (the PKCS7
// composite RNS's Token layer uses). Mirrors RNS.Cryptography.AES.AES_256_CBC:
// no PKCS7 growth, ciphertext length == plaintext length, and it round-trips
// `aes_256_cbc_encrypt` byte-for-byte. The plaintext MUST be a multiple of the
// 16-byte AES block size.

REGISTER_COMMAND(aes_256_cbc_encrypt, {
    auto plaintext = bridge::hex_param(p, "plaintext");
    auto key = bridge::hex_param(p, "key");
    auto iv = bridge::hex_param(p, "iv");
    auto ct = aes256_cbc_encrypt(plaintext, key, iv);
    return bridge::json{{"ciphertext", bridge::to_hex(from_rns(ct))}};
})

REGISTER_COMMAND(aes_256_cbc_decrypt, {
    auto ciphertext = bridge::hex_param(p, "ciphertext");
    auto key = bridge::hex_param(p, "key");
    auto iv = bridge::hex_param(p, "iv");
    auto pt = aes256_cbc_decrypt(ciphertext, key, iv);
    return bridge::json{{"plaintext", bridge::to_hex(from_rns(pt))}};
})

// === PKCS7 padding ===

// BUG WORKAROUND: RNS::Cryptography::PKCS7::pad() at PKCS7.h:37 fills the
// pad buffer with zeros and only sets the LAST byte to padlen — producing
// [0,0,...,0,padlen] instead of standard PKCS7 [padlen,...,padlen]. We
// compute the correct padding directly here.
REGISTER_COMMAND(pkcs7_pad, {
    auto data = bridge::hex_param(p, "data");
    constexpr size_t bs = 16;
    size_t padlen = bs - (data.size() % bs);
    bridge::Bytes padded = data;
    padded.insert(padded.end(), padlen, (uint8_t)padlen);
    return bridge::json{{"padded", bridge::to_hex(padded)}};
})

REGISTER_COMMAND(pkcs7_unpad, {
    // Delegate to the bridge helper so the spec-correct full-padding check
    // (every byte == padlen) is applied here too. Inlining the check would
    // drift from the helper.
    auto data = bridge::hex_param(p, "data");
    auto unpadded = bridge::pkcs7_unpad(data);
    return bridge::json{{"unpadded", bridge::to_hex(unpadded)}};
})

// === X25519 (Curve25519 ECDH) ===

REGISTER_COMMAND(x25519_generate, {
    // Conformance protocol: deterministic generation from a 32-byte seed.
    // RNS::X25519PrivateKey::from_private_bytes applies clamping and derives
    // the public key automatically. The clamped scalar is what we report.
    auto seed = bridge::hex_param(p, "seed");
    if (seed.size() != 32) {
        throw std::runtime_error("x25519_generate: seed must be 32 bytes");
    }
    auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(seed));
    auto pub = priv->public_key();
    return bridge::json{
        {"private_key", bridge::to_hex(from_rns(priv->private_bytes()))},
        {"public_key",  bridge::to_hex(from_rns(pub->public_bytes()))},
    };
})

REGISTER_COMMAND(x25519_public_from_private, {
    auto priv_bytes = bridge::hex_param(p, "private_key");
    // Curve25519 values must be exactly 32 bytes (RNS X25519.py:66-69) — reject
    // anything else rather than silently truncating/zero-extending.
    if (priv_bytes.size() != 32) {
        throw std::runtime_error("x25519_public_from_private: private_key must be 32 bytes");
    }
    auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(priv_bytes));
    auto pub = priv->public_key();
    return bridge::json{{"public_key", bridge::to_hex(from_rns(pub->public_bytes()))}};
})

REGISTER_COMMAND(x25519_exchange, {
    auto priv_bytes = bridge::hex_param(p, "private_key");
    auto peer_pub_bytes = bridge::hex_param(p, "peer_public_key");
    // Both the private scalar and the peer public point must be exactly 32
    // bytes (RNS X25519.py:66-69).
    if (priv_bytes.size() != 32) {
        throw std::runtime_error("x25519_exchange: private_key must be 32 bytes");
    }
    if (peer_pub_bytes.size() != 32) {
        throw std::runtime_error("x25519_exchange: peer_public_key must be 32 bytes");
    }
    auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(priv_bytes));
    auto shared = priv->exchange(to_rns(peer_pub_bytes));
    return bridge::json{{"shared_secret", bridge::to_hex(from_rns(shared))}};
})

// === Ed25519 ===

REGISTER_COMMAND(ed25519_generate, {
    // Conformance protocol: deterministic from 32-byte seed.
    // RNS::Ed25519PrivateKey::from_private_bytes calls Ed25519::derivePublicKey
    // and stores both. (Header comment in Ed25519.h says "doesn't support
    // generation from seed", but that's stale — from_private_bytes does work.)
    auto seed = bridge::hex_param(p, "seed");
    if (seed.size() != 32) {
        throw std::runtime_error("ed25519_generate: seed must be 32 bytes");
    }
    auto priv = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(seed));
    auto pub = priv->public_key();
    return bridge::json{
        {"private_key", bridge::to_hex(from_rns(priv->private_bytes()))},
        {"public_key",  bridge::to_hex(from_rns(pub->public_bytes()))},
    };
})

REGISTER_COMMAND(ed25519_sign, {
    auto priv_bytes = bridge::hex_param(p, "private_key");
    auto message = bridge::hex_param(p, "message");
    // RNS Ed25519 signing keys are a 32-byte seed; a 64-byte private key is the
    // seed||public form RNS stores, of which only the first 32 (the seed) are
    // used. Any other length is rejected rather than fed to the primitive,
    // which would read past the buffer.
    if (priv_bytes.size() == 64) {
        priv_bytes.assign(priv_bytes.begin(), priv_bytes.begin() + 32);
    } else if (priv_bytes.size() != 32) {
        throw std::runtime_error("ed25519_sign: private_key must be 32 or 64 bytes");
    }
    auto priv = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(priv_bytes));
    auto sig = priv->sign(to_rns(message));
    return bridge::json{{"signature", bridge::to_hex(from_rns(sig))}};
})

REGISTER_COMMAND(ed25519_verify, {
    auto pub_bytes = bridge::hex_param(p, "public_key");
    auto message = bridge::hex_param(p, "message");
    auto signature = bridge::hex_param(p, "signature");
    // RNS.Identity.validate is a total boolean predicate: a structurally
    // malformed signature (Ed25519 signatures are exactly 64 bytes) or a
    // wrong-length public key (32 bytes) verifies False, never raises.
    if (signature.size() != 64 || pub_bytes.size() != 32) {
        return bridge::json{{"valid", false}};
    }
    auto pub = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(to_rns(pub_bytes));
    bool ok = pub->verify(to_rns(signature), to_rns(message));
    return bridge::json{{"valid", ok}};
})

// === Crypto provider dispatch ===
//
// In RNS the crypto backend is chosen once at import time — the pure-Python
// primitives (PROVIDER_INTERNAL) or the OpenSSL/PyCA bindings (PROVIDER_PYCA).
// The reference bridge exposes BOTH so a conformance test can drive the same
// input through each named provider and assert byte-identical output (the two
// backends are required to be drop-in equivalent on the wire).
//
// microReticulum has a SINGLE coherent crypto backend (the attermann/Crypto
// primitives wrapped by RNS::Cryptography), so "internal" and "pyca" name the
// exact same code path. We therefore ignore the provider name (after validating
// it, to match the reference contract) and dispatch the requested op to the
// same RNS::Cryptography primitives the dedicated commands already wrap. No
// protocol bytes are hand-assembled — every value is produced by a real RNS
// class. Because both names route to one backend, the provider-divergence tests
// observe a single consistent profile and pass on the coherent-single-backend
// branch.
REGISTER_COMMAND(crypto_provider_op, {
    std::string op = bridge::str_param(p, "op");
    std::string provider = bridge::str_param(p, "provider");
    if (provider != "internal" && provider != "pyca") {
        throw std::runtime_error("Unknown provider: " + provider);
    }

    if (op == "x25519_exchange") {
        auto priv_bytes = bridge::hex_param(p, "private_key");
        auto peer_pub_bytes = bridge::hex_param(p, "peer_public_key");
        auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(priv_bytes));
        auto shared = priv->exchange(to_rns(peer_pub_bytes));
        return bridge::json{{"result", bridge::to_hex(from_rns(shared))}};
    }

    if (op == "ed25519_sign") {
        auto priv_bytes = bridge::hex_param(p, "private_key");
        auto message = bridge::hex_param(p, "message");
        // Mirror the standalone ed25519_sign command: a 64-byte key is the
        // seed||public form RNS stores; only the first 32 (the seed) feed the
        // primitive. Any other length is rejected rather than read past.
        if (priv_bytes.size() == 64) {
            priv_bytes.assign(priv_bytes.begin(), priv_bytes.begin() + 32);
        } else if (priv_bytes.size() != 32) {
            throw std::runtime_error("ed25519_sign: private_key must be 32 or 64 bytes");
        }
        auto priv = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(priv_bytes));
        auto sig = priv->sign(to_rns(message));
        return bridge::json{{"result", bridge::to_hex(from_rns(sig))}};
    }

    if (op == "ed25519_verify") {
        auto pub_bytes = bridge::hex_param(p, "public_key");
        auto message = bridge::hex_param(p, "message");
        auto signature = bridge::hex_param(p, "signature");
        auto pub = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(to_rns(pub_bytes));
        bool ok = pub->verify(to_rns(signature), to_rns(message));
        return bridge::json{{"valid", ok}};
    }

    if (op == "aes_256_cbc_encrypt") {
        auto plaintext = bridge::hex_param(p, "plaintext");
        auto key = bridge::hex_param(p, "key");
        auto iv = bridge::hex_param(p, "iv");
        auto ct = aes256_cbc_encrypt(plaintext, key, iv);
        return bridge::json{{"result", bridge::to_hex(from_rns(ct))}};
    }

    throw std::runtime_error("Unknown op: " + op);
})
