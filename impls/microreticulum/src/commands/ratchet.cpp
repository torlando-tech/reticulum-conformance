// Ratchet commands. Forward-secrecy ratchets in Reticulum are ephemeral
// X25519 keypairs; encryption mirrors Identity.encrypt but keys off the
// ratchet public key instead of the destination identity, with the
// destination's identity hash used as the HKDF salt.
//
//   ratchet_id:                 SHA-256(ratchet_public)[:10]
//   ratchet_public_from_private: X25519 public from private
//   ratchet_derive_key:         ECDH(ephemeral, ratchet) -> HKDF(64, salt=id_hash)
//   ratchet_encrypt/decrypt:    ephemeral_public(32) || Token(derived_key, pt)
//
// All crypto delegates to microReticulum's RNS::Cryptography primitives and
// the shared bridge Token helpers.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/X25519.h"

#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

// ECDH + HKDF(64, salt=identity_hash, info=empty). Matches reference
// cmd_ratchet_derive_key / Identity ratchet key derivation.
bridge::Bytes derive(const bridge::Bytes& shared, const bridge::Bytes& identity_hash) {
    auto derived = RNS::Cryptography::hkdf(64, to_rns(shared), to_rns(identity_hash), RNS::Bytes());
    return from_rns(derived);
}

}  // namespace

REGISTER_COMMAND(ratchet_id, {
    auto ratchet_public = bridge::hex_param(p, "ratchet_public");
    auto full = RNS::Cryptography::sha256(to_rns(ratchet_public));
    bridge::Bytes ratchet_id(full.data(), full.data() + 10);  // NAME_HASH_LENGTH = 80 bits
    return bridge::json{
        {"ratchet_id", bridge::to_hex(ratchet_id)},
        {"full_hash", bridge::to_hex(from_rns(full))},
    };
})

REGISTER_COMMAND(ratchet_public_from_private, {
    auto ratchet_private = bridge::hex_param(p, "ratchet_private");
    auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(ratchet_private));
    auto pub = priv->public_key();
    return bridge::json{{"ratchet_public", bridge::to_hex(from_rns(pub->public_bytes()))}};
})

REGISTER_COMMAND(ratchet_derive_key, {
    auto ephemeral_private = bridge::hex_param(p, "ephemeral_private");
    auto ratchet_public = bridge::hex_param(p, "ratchet_public");
    auto identity_hash = bridge::hex_param(p, "identity_hash");

    auto eph = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(ephemeral_private));
    auto shared = from_rns(eph->exchange(to_rns(ratchet_public)));
    auto derived_key = derive(shared, identity_hash);

    return bridge::json{
        {"shared_key", bridge::to_hex(shared)},
        {"derived_key", bridge::to_hex(derived_key)},
    };
})

REGISTER_COMMAND(ratchet_encrypt, {
    auto ratchet_public = bridge::hex_param(p, "ratchet_public");
    auto plaintext = bridge::hex_param(p, "plaintext");
    auto identity_hash = bridge::hex_param(p, "identity_hash");

    // Caller may pin the ephemeral key and IV for determinism; otherwise
    // generate them (random ephemeral + random IV), exactly like RNS Token.
    bridge::Bytes ephemeral_private = bridge::hex_param_or_empty(p, "ephemeral_private");
    if (ephemeral_private.empty()) ephemeral_private = bridge::random_bytes(32);
    bridge::Bytes iv = bridge::hex_param_or_empty(p, "iv");
    if (iv.empty()) iv = bridge::random_bytes(16);

    auto eph = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(ephemeral_private));
    auto eph_pub = from_rns(eph->public_key()->public_bytes());
    auto shared = from_rns(eph->exchange(to_rns(ratchet_public)));
    auto derived_key = derive(shared, identity_hash);

    auto token = bridge::token_seal(derived_key, plaintext, iv);
    bridge::Bytes out;
    out.insert(out.end(), eph_pub.begin(), eph_pub.end());
    out.insert(out.end(), token.begin(), token.end());

    return bridge::json{
        {"ciphertext", bridge::to_hex(out)},
        {"ephemeral_public", bridge::to_hex(eph_pub)},
        {"shared_key", bridge::to_hex(shared)},
        {"derived_key", bridge::to_hex(derived_key)},
    };
})

REGISTER_COMMAND(ratchet_decrypt, {
    auto ratchet_private = bridge::hex_param(p, "ratchet_private");
    auto ciphertext = bridge::hex_param(p, "ciphertext");
    auto identity_hash = bridge::hex_param(p, "identity_hash");
    if (ciphertext.size() <= 32) {
        throw std::runtime_error("ratchet_decrypt: ciphertext too short");
    }

    bridge::Bytes eph_pub(ciphertext.begin(), ciphertext.begin() + 32);
    bridge::Bytes token(ciphertext.begin() + 32, ciphertext.end());

    auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(ratchet_private));
    auto shared = from_rns(priv->exchange(to_rns(eph_pub)));
    auto derived_key = derive(shared, identity_hash);

    auto pt = bridge::token_open(derived_key, token);
    return bridge::json{
        {"plaintext", bridge::to_hex(pt)},
        {"shared_key", bridge::to_hex(shared)},
        {"derived_key", bridge::to_hex(derived_key)},
    };
})
