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

REGISTER_COMMAND(aes_encrypt, {
    auto plaintext = bridge::hex_param(p, "plaintext");
    auto key = bridge::hex_param(p, "key");
    auto iv = bridge::hex_param(p, "iv");
    // Mirror Python RNS/Cryptography/AES.py — AES_128_CBC requires len(key)==16,
    // AES_256_CBC requires len(key)==32. Reject anything else (including
    // 24-byte AES-192 attempts) rather than silently routing to AES-256
    // and reading past the end of the supplied buffer.
    RNS::Bytes ct;
    if (key.size() == 16) {
        ct = RNS::Cryptography::AES_128_CBC::encrypt(to_rns(plaintext), to_rns(key), to_rns(iv));
    } else if (key.size() == 32) {
        ct = RNS::Cryptography::AES_256_CBC::encrypt(to_rns(plaintext), to_rns(key), to_rns(iv));
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
    auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(priv_bytes));
    auto pub = priv->public_key();
    return bridge::json{{"public_key", bridge::to_hex(from_rns(pub->public_bytes()))}};
})

REGISTER_COMMAND(x25519_exchange, {
    auto priv_bytes = bridge::hex_param(p, "private_key");
    auto peer_pub_bytes = bridge::hex_param(p, "peer_public_key");
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
    auto priv = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(priv_bytes));
    auto sig = priv->sign(to_rns(message));
    return bridge::json{{"signature", bridge::to_hex(from_rns(sig))}};
})

REGISTER_COMMAND(ed25519_verify, {
    auto pub_bytes = bridge::hex_param(p, "public_key");
    auto message = bridge::hex_param(p, "message");
    auto signature = bridge::hex_param(p, "signature");
    auto pub = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(to_rns(pub_bytes));
    bool ok = pub->verify(to_rns(signature), to_rns(message));
    return bridge::json{{"valid", ok}};
})
