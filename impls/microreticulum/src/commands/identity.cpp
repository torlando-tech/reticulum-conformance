// Identity commands. Reticulum identities are 64-byte private keys split as
// X25519(32) + Ed25519(32). Public key is the same concat. Identity hash is
// the truncated SHA-256 of the public key.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/AES.h"
#include "Cryptography/PKCS7.h"
#include "Cryptography/HMAC.h"
#include "Cryptography/X25519.h"
#include "Cryptography/Ed25519.h"

#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

bridge::Bytes truncated_sha256(const bridge::Bytes& data, size_t bytes) {
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + bytes);
}

}  // namespace

REGISTER_COMMAND(identity_from_private_key, {
    auto priv = bridge::hex_param(p, "private_key");
    if (priv.size() != 64) {
        throw std::runtime_error("identity_from_private_key: private_key must be 64 bytes");
    }
    bridge::Bytes x25519_priv(priv.begin(), priv.begin() + 32);
    bridge::Bytes ed25519_priv(priv.begin() + 32, priv.end());

    auto x25519_priv_obj = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(x25519_priv));
    auto x25519_pub = from_rns(x25519_priv_obj->public_key()->public_bytes());

    auto ed25519_priv_obj = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed25519_priv));
    auto ed25519_pub = from_rns(ed25519_priv_obj->public_key()->public_bytes());

    bridge::Bytes public_key;
    public_key.insert(public_key.end(), x25519_pub.begin(), x25519_pub.end());
    public_key.insert(public_key.end(), ed25519_pub.begin(), ed25519_pub.end());

    auto identity_hash = truncated_sha256(public_key, 16);
    auto hex_hash = bridge::to_hex(identity_hash);

    return bridge::json{
        {"public_key", bridge::to_hex(public_key)},
        {"hash",       hex_hash},
        {"hexhash",    hex_hash},
    };
})

REGISTER_COMMAND(identity_hash, {
    auto pub = bridge::hex_param(p, "public_key");
    auto hash = truncated_sha256(pub, 16);
    return bridge::json{{"hash", bridge::to_hex(hash)}};
})

REGISTER_COMMAND(identity_sign, {
    auto priv = bridge::hex_param(p, "private_key");
    auto message = bridge::hex_param(p, "message");
    if (priv.size() != 64) {
        throw std::runtime_error("identity_sign: private_key must be 64 bytes");
    }
    bridge::Bytes ed25519_priv(priv.begin() + 32, priv.end());
    auto sk = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed25519_priv));
    auto sig = sk->sign(to_rns(message));
    return bridge::json{{"signature", bridge::to_hex(from_rns(sig))}};
})

REGISTER_COMMAND(identity_verify, {
    auto pub = bridge::hex_param(p, "public_key");
    auto message = bridge::hex_param(p, "message");
    auto signature = bridge::hex_param(p, "signature");
    if (pub.size() != 64) {
        throw std::runtime_error("identity_verify: public_key must be 64 bytes");
    }
    bridge::Bytes ed25519_pub(pub.begin() + 32, pub.end());
    auto vk = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(to_rns(ed25519_pub));
    bool ok = vk->verify(to_rns(signature), to_rns(message));
    return bridge::json{{"valid", ok}};
})

// identity_encrypt / identity_decrypt: ephemeral X25519 ECDH + Token (Fernet).
// Ciphertext = ephemeral_public(32) || token_bytes. Token is keyed by HKDF
// of the ECDH shared secret, with identity_hash as salt.
REGISTER_COMMAND(identity_encrypt, {
    auto pub = bridge::hex_param(p, "public_key");
    auto plaintext = bridge::hex_param(p, "plaintext");
    if (pub.size() != 64) {
        throw std::runtime_error("identity_encrypt: public_key must be 64 bytes");
    }
    bridge::Bytes x25519_pub(pub.begin(), pub.begin() + 32);

    // Ephemeral key — caller may provide for determinism; otherwise generate.
    bridge::Bytes ephemeral_priv;
    if (p.contains("ephemeral_private") && !p["ephemeral_private"].is_null()) {
        ephemeral_priv = bridge::from_hex(p["ephemeral_private"].get<std::string>());
    } else {
        // Generate from a deterministic seed for repeatability across runs
        // when caller doesn't pass one. Conformance tests pass ephemeral_private.
        throw std::runtime_error("identity_encrypt: ephemeral_private is required");
    }

    auto eph = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(ephemeral_priv));
    auto eph_pub = from_rns(eph->public_key()->public_bytes());
    auto shared = eph->exchange(to_rns(x25519_pub));

    // Identity hash from full public_key — used as HKDF salt.
    auto id_hash = truncated_sha256(pub, 16);
    auto derived = RNS::Cryptography::hkdf(64, shared, to_rns(id_hash), RNS::Bytes());

    // Token = AES-256-CBC over plaintext with HMAC-SHA256 prefix.
    // Materialise the derived key once before slicing — calling
    // from_rns(derived) twice would produce two distinct heap-allocated
    // temporaries and the range constructor would cross allocation
    // boundaries (UB).
    bridge::Bytes derived_key = from_rns(derived);
    bridge::Bytes signing_key(derived_key.begin(), derived_key.begin() + 32);
    bridge::Bytes encryption_key(derived_key.begin() + 32, derived_key.end());

    auto iv = bridge::hex_param_or_empty(p, "iv");
    if (iv.size() != 16) {
        throw std::runtime_error("identity_encrypt: iv must be 16 bytes");
    }

    auto padded = bridge::pkcs7_pad(plaintext);
    auto ct = RNS::Cryptography::AES_256_CBC::encrypt(to_rns(padded), to_rns(encryption_key), to_rns(iv));

    bridge::Bytes signed_parts;
    signed_parts.insert(signed_parts.end(), iv.begin(), iv.end());
    signed_parts.insert(signed_parts.end(), ct.data(), ct.data() + ct.size());

    auto hmac = bridge::hmac_sha256(signing_key, signed_parts);
    bridge::Bytes token = signed_parts;
    token.insert(token.end(), hmac.begin(), hmac.end());

    bridge::Bytes ciphertext;
    ciphertext.insert(ciphertext.end(), eph_pub.begin(), eph_pub.end());
    ciphertext.insert(ciphertext.end(), token.begin(), token.end());

    return bridge::json{
        {"ciphertext", bridge::to_hex(ciphertext)},
        {"ephemeral_public", bridge::to_hex(eph_pub)},
    };
})

REGISTER_COMMAND(identity_decrypt, {
    auto priv = bridge::hex_param(p, "private_key");
    auto ciphertext = bridge::hex_param(p, "ciphertext");
    if (priv.size() != 64) {
        throw std::runtime_error("identity_decrypt: private_key must be 64 bytes");
    }
    if (ciphertext.size() < 32 + 16 + 32) {
        throw std::runtime_error("identity_decrypt: ciphertext too short");
    }

    bridge::Bytes x25519_priv(priv.begin(), priv.begin() + 32);
    bridge::Bytes eph_pub(ciphertext.begin(), ciphertext.begin() + 32);
    bridge::Bytes token(ciphertext.begin() + 32, ciphertext.end());

    // Reconstruct identity hash from our public key.
    auto x25519_priv_obj = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(x25519_priv));
    auto x25519_pub = from_rns(x25519_priv_obj->public_key()->public_bytes());
    bridge::Bytes ed25519_priv(priv.begin() + 32, priv.end());
    auto ed25519_priv_obj = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed25519_priv));
    auto ed25519_pub = from_rns(ed25519_priv_obj->public_key()->public_bytes());

    bridge::Bytes our_pub;
    our_pub.insert(our_pub.end(), x25519_pub.begin(), x25519_pub.end());
    our_pub.insert(our_pub.end(), ed25519_pub.begin(), ed25519_pub.end());
    auto id_hash = truncated_sha256(our_pub, 16);

    auto shared = x25519_priv_obj->exchange(to_rns(eph_pub));
    auto derived = RNS::Cryptography::hkdf(64, shared, to_rns(id_hash), RNS::Bytes());

    // Materialise the derived key once before slicing — see identity_encrypt
    // for the same UB-avoidance pattern.
    bridge::Bytes derived_key = from_rns(derived);
    bridge::Bytes signing_key(derived_key.begin(), derived_key.begin() + 32);
    bridge::Bytes encryption_key(derived_key.begin() + 32, derived_key.end());

    if (token.size() < 16 + 32) {
        throw std::runtime_error("identity_decrypt: token too short");
    }
    bridge::Bytes iv(token.begin(), token.begin() + 16);
    bridge::Bytes ct(token.begin() + 16, token.end() - 32);
    bridge::Bytes hmac_recv(token.end() - 32, token.end());

    bridge::Bytes signed_parts(token.begin(), token.end() - 32);
    auto hmac_calc = bridge::hmac_sha256(signing_key, signed_parts);
    bool hmac_ok = (hmac_recv.size() == hmac_calc.size()) &&
                   bridge::consttime_memequal(hmac_recv.data(), hmac_calc.data(), hmac_recv.size());
    if (!hmac_ok) {
        throw std::runtime_error("identity_decrypt: HMAC verification failed");
    }

    auto pt_padded = from_rns(RNS::Cryptography::AES_256_CBC::decrypt(
        to_rns(ct), to_rns(encryption_key), to_rns(iv)));
    auto pt = bridge::pkcs7_unpad(pt_padded);

    return bridge::json{{"plaintext", bridge::to_hex(pt)}};
})
