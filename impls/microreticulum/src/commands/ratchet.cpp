// Ratchet commands. Forward-secrecy ratchets in Reticulum are ephemeral
// X25519 keypairs; encryption mirrors Identity.encrypt but keys off the
// ratchet public key instead of the destination identity, with the
// destination's identity hash used as the HKDF salt.
//
//   ratchet_id:                  SHA-256(ratchet_public)[:10]  (NAME_HASH_LENGTH)
//   ratchet_public_from_private: X25519 public from private
//   ratchet_derive_key:          ECDH(ephemeral, ratchet) -> HKDF(64, salt=id_hash)
//   ratchet_encrypt:             ephemeral_public(32) || Token(derived_key, pt)
//   ratchet_decrypt:             trial a list of ratchet privates in order,
//                                then (unless enforce_ratchets) the static key
//
// Encrypt takes the identity PUBLIC key and decrypt the identity PRIVATE key —
// the identity hash used as the HKDF salt is derived from them, exactly as
// RNS.Identity.encrypt/decrypt do. All crypto delegates to microReticulum's
// RNS::Cryptography primitives and the shared bridge Token helpers.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/X25519.h"
#include "Cryptography/Ed25519.h"

#include <stdexcept>
#include <vector>

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

// The HKDF salt RNS uses for ratchet (and static) encryption is the identity's
// own 16-byte hash == truncated SHA-256 of its 64-byte public key.
bridge::Bytes identity_hash_from_public(const bridge::Bytes& public_key) {
    if (public_key.size() != 64) {
        throw std::runtime_error("ratchet: public_key must be 64 bytes");
    }
    return truncated_sha256(public_key, 16);
}

// Derive the 64-byte public key (X25519 pub || Ed25519 pub) from a 64-byte
// private key (X25519 priv || Ed25519 seed), then its identity hash.
bridge::Bytes identity_hash_from_private(const bridge::Bytes& private_key) {
    if (private_key.size() != 64) {
        throw std::runtime_error("ratchet: private_key must be 64 bytes");
    }
    bridge::Bytes x_priv(private_key.begin(), private_key.begin() + 32);
    bridge::Bytes ed_priv(private_key.begin() + 32, private_key.end());
    auto x_pub = from_rns(RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(x_priv))
                              ->public_key()->public_bytes());
    auto ed_pub = from_rns(RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed_priv))
                               ->public_key()->public_bytes());
    bridge::Bytes pub;
    pub.insert(pub.end(), x_pub.begin(), x_pub.end());
    pub.insert(pub.end(), ed_pub.begin(), ed_pub.end());
    return truncated_sha256(pub, 16);
}

// ECDH(scalar, point) -> HKDF(64, salt=identity_hash, info=empty). Matches
// RNS Identity ratchet key derivation.
bridge::Bytes derive(const bridge::Bytes& x25519_private,
                     const bridge::Bytes& peer_public,
                     const bridge::Bytes& identity_hash) {
    auto priv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(x25519_private));
    auto shared = from_rns(priv->exchange(to_rns(peer_public)));
    return from_rns(RNS::Cryptography::hkdf(64, to_rns(shared), to_rns(identity_hash), RNS::Bytes()));
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
    auto derived_key = from_rns(
        RNS::Cryptography::hkdf(64, to_rns(shared), to_rns(identity_hash), RNS::Bytes()));

    return bridge::json{
        {"shared_key", bridge::to_hex(shared)},
        {"derived_key", bridge::to_hex(derived_key)},
    };
})

REGISTER_COMMAND(ratchet_encrypt, {
    auto public_key = bridge::hex_param(p, "public_key");
    auto ratchet_public = bridge::hex_param(p, "ratchet_public");
    auto plaintext = bridge::hex_param(p, "plaintext");
    auto identity_hash = identity_hash_from_public(public_key);

    // Caller may pin the ephemeral key and IV for determinism; otherwise
    // generate them (random ephemeral + random IV), exactly like RNS Token.
    bridge::Bytes ephemeral_private = bridge::hex_param_or_empty(p, "ephemeral_private");
    if (ephemeral_private.empty()) ephemeral_private = bridge::random_bytes(32);
    bridge::Bytes iv = bridge::hex_param_or_empty(p, "iv");
    if (iv.empty()) iv = bridge::random_bytes(16);

    auto eph = RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(ephemeral_private));
    auto eph_pub = from_rns(eph->public_key()->public_bytes());
    auto derived_key = derive(ephemeral_private, ratchet_public, identity_hash);

    auto token = bridge::token_seal(derived_key, plaintext, iv);
    bridge::Bytes out;
    out.insert(out.end(), eph_pub.begin(), eph_pub.end());
    out.insert(out.end(), token.begin(), token.end());

    return bridge::json{
        {"ciphertext", bridge::to_hex(out)},
        {"ephemeral_public", bridge::to_hex(eph_pub)},
    };
})

REGISTER_COMMAND(ratchet_decrypt, {
    auto private_key = bridge::hex_param(p, "private_key");
    auto ciphertext = bridge::hex_param(p, "ciphertext");
    bool enforce = false;
    if (p.contains("enforce_ratchets") && !p["enforce_ratchets"].is_null()) {
        enforce = p["enforce_ratchets"].get<bool>();
    }
    auto identity_hash = identity_hash_from_private(private_key);

    // The ciphertext is ephemeral_public(32) || token. Anything shorter cannot
    // carry an ephemeral key + an authenticated body — yield None.
    if (ciphertext.size() <= 32) {
        return bridge::json{{"plaintext", nullptr}, {"latest_ratchet_id", nullptr}};
    }
    bridge::Bytes eph_pub(ciphertext.begin(), ciphertext.begin() + 32);
    bridge::Bytes token(ciphertext.begin() + 32, ciphertext.end());

    // Build the ordered trial list: ratchet_privates (preferred) or the single
    // ratchet_private shorthand.
    std::vector<bridge::Bytes> ratchets;
    if (p.contains("ratchet_privates") && p["ratchet_privates"].is_array()) {
        for (const auto& r : p["ratchet_privates"]) {
            ratchets.push_back(bridge::from_hex(r.get<std::string>()));
        }
    } else if (p.contains("ratchet_private") && !p["ratchet_private"].is_null()) {
        ratchets.push_back(bridge::from_hex(p["ratchet_private"].get<std::string>()));
    }

    // Trial each ratchet IN ORDER; the first that authenticates wins, and we
    // report the winning ratchet's id (sha256(ratchet_public)[:10]).
    for (const auto& rp : ratchets) {
        bridge::Bytes derived_key;
        try {
            derived_key = derive(rp, eph_pub, identity_hash);
        } catch (const std::exception&) {
            continue;  // malformed ratchet scalar — skip it
        }
        try {
            auto pt = bridge::token_open(derived_key, token);
            auto rp_pub = from_rns(
                RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(rp))
                    ->public_key()->public_bytes());
            auto rid = truncated_sha256(rp_pub, 10);
            return bridge::json{
                {"plaintext", bridge::to_hex(pt)},
                {"latest_ratchet_id", bridge::to_hex(rid)},
            };
        } catch (const std::exception&) {
            continue;  // wrong ratchet — try the next
        }
    }

    // No ratchet matched. Unless enforcement forbids it, fall back to the
    // static identity X25519 key (RNS.Identity.decrypt's default path). The
    // static fallback reports no ratchet id.
    if (!enforce) {
        bridge::Bytes x25519_priv(private_key.begin(), private_key.begin() + 32);
        try {
            auto derived_key = derive(x25519_priv, eph_pub, identity_hash);
            auto pt = bridge::token_open(derived_key, token);
            return bridge::json{
                {"plaintext", bridge::to_hex(pt)},
                {"latest_ratchet_id", nullptr},
            };
        } catch (const std::exception&) {
            // fall through to the None result
        }
    }

    return bridge::json{{"plaintext", nullptr}, {"latest_ratchet_id", nullptr}};
})
