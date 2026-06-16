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

#include <cstdio>
#include <stdexcept>
#include <string>
#include <unistd.h>

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
    // RNS.Identity.validate is a TOTAL boolean predicate: a wrong-length public
    // key (64 bytes) or a structurally malformed signature (Ed25519 signatures
    // are exactly 64 bytes) verifies False, never raises.
    if (pub.size() != 64 || signature.size() != 64) {
        return bridge::json{{"valid", false}};
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

    // Ephemeral key — caller may pin it for determinism; otherwise generate a
    // fresh one (real Identity.encrypt always uses a random ephemeral key).
    bridge::Bytes ephemeral_priv;
    if (p.contains("ephemeral_private") && !p["ephemeral_private"].is_null()) {
        ephemeral_priv = bridge::from_hex(p["ephemeral_private"].get<std::string>());
    } else {
        ephemeral_priv = bridge::random_bytes(32);
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
    if (iv.empty()) iv = bridge::random_bytes(16);
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
    // RNS.Identity.decrypt is a GRACEFUL-rejection primitive: any token that
    // does not authenticate (too short, wrong key, corrupt body) yields
    // plaintext=None — it never raises and never returns garbage. A
    // ratchet-encrypted (or otherwise wrong-key) ciphertext therefore reads
    // back None under the static identity key. The smallest decryptable blob
    // is ephemeral_public(32) + iv(16) + one AES block(16) + hmac(32).
    if (ciphertext.size() < 32 + 16 + 16 + 32) {
        return bridge::json{{"plaintext", nullptr}};
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
    bridge::Bytes derived_key = from_rns(derived);

    // token_open authenticates before decrypting; on any failure (HMAC
    // mismatch, undecryptable body) we surface plaintext=None rather than
    // raising, matching RNS.Identity.decrypt.
    try {
        auto pt = bridge::token_open(derived_key, token);
        return bridge::json{{"plaintext", bridge::to_hex(pt)}};
    } catch (const std::exception&) {
        return bridge::json{{"plaintext", nullptr}};
    }
})

// On-disk Identity format (RNS.Identity.to_file / from_file): the raw 64-byte
// private key, X25519 half(32) || Ed25519 seed(32). The build sets RNS_NO_FS so
// the fork's own file I/O is unavailable; we use host fopen for the blob and
// derive the public material with the same Cryptography primitives the rest of
// this file uses. This is the interop format Sideband + LXMF persist.
REGISTER_COMMAND(identity_to_file, {
    auto priv = bridge::hex_param(p, "private_key");
    if (priv.size() != 64) {
        throw std::runtime_error("identity_to_file: private_key must be 64 bytes");
    }
    // Per-process temp path so repeated calls don't collide.
    static int counter = 0;
    std::string path = "/tmp/conformance_mrn_identity_" +
                       std::to_string((unsigned long)::getpid()) + "_" +
                       std::to_string(counter++) + ".bin";
    FILE* f = ::fopen(path.c_str(), "wb");
    if (f == nullptr) {
        throw std::runtime_error("identity_to_file: could not open " + path);
    }
    size_t written = ::fwrite(priv.data(), 1, priv.size(), f);
    ::fclose(f);
    if (written != priv.size()) {
        throw std::runtime_error("identity_to_file: short write to " + path);
    }
    return bridge::json{{"path", path}};
})

REGISTER_COMMAND(identity_from_file, {
    auto path = bridge::str_param(p, "path");
    FILE* f = ::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        return bridge::json{{"found", false}};
    }
    bridge::Bytes priv(64);
    size_t read = ::fread(priv.data(), 1, priv.size(), f);
    // Reject a file that is not exactly the 64-byte private-key blob (a longer
    // file would have leftover bytes; a shorter one is truncated).
    int extra = ::fgetc(f);
    ::fclose(f);
    if (read != 64 || extra != EOF) {
        return bridge::json{{"found", false}};
    }
    // identity_to_file writes a fresh per-call temp blob that is only ever read
    // once (the round-trip / cross-impl tests each load a given path a single
    // time). Remove it now that we hold its 64 bytes so a long CI run does not
    // leak one /tmp file per identity. The round-trip contract is unaffected:
    // the bytes are already in `priv`.
    ::unlink(path.c_str());

    bridge::Bytes x25519_priv(priv.begin(), priv.begin() + 32);
    bridge::Bytes ed25519_priv(priv.begin() + 32, priv.end());
    auto x25519_pub = from_rns(
        RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(x25519_priv))
            ->public_key()->public_bytes());
    auto ed25519_pub = from_rns(
        RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed25519_priv))
            ->public_key()->public_bytes());

    bridge::Bytes public_key;
    public_key.insert(public_key.end(), x25519_pub.begin(), x25519_pub.end());
    public_key.insert(public_key.end(), ed25519_pub.begin(), ed25519_pub.end());
    auto hex_hash = bridge::to_hex(truncated_sha256(public_key, 16));

    return bridge::json{
        {"found",      true},
        {"public_key", bridge::to_hex(public_key)},
        {"hash",       hex_hash},
        {"hexhash",    hex_hash},
    };
})

REGISTER_COMMAND(identity_random_hash, {
    // RNS.Identity.get_random_hash() == truncated_hash(random(TRUNCATED_HASHLENGTH/8))
    // == first 16 bytes of SHA-256 over 16 random bytes (Identity.h:279).
    auto rnd = bridge::random_bytes(16);
    auto h = truncated_sha256(rnd, 16);
    return bridge::json{{"random_hash", bridge::to_hex(h)}};
})
