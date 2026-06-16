// Token (Fernet-like) commands.
//
// Token wire format (matches Python RNS Token):
//   token = iv(16) || aes_cbc(plaintext + pkcs7) || hmac_sha256(iv||ct)
//
// The key is 32 bytes (AES-128: signing(16) || encryption(16)) or 64 bytes
// (AES-256: signing(32) || encryption(32)); the mode is chosen from the key
// length. token_seal / token_open (bridge.cpp) carry the seal/open logic and
// the spec-correct PKCS7; the commands here are thin wrappers plus the
// HMAC-verify and key-generation surface.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Token.h"

#include <cstring>
#include <stdexcept>

namespace {

// Split a Token key into (signing, encryption) the same way bridge::token_*
// does: 32-byte key -> AES-128 (16+16), 64-byte key -> AES-256 (32+32).
void split_key(const bridge::Bytes& key, bridge::Bytes& signing,
               bridge::Bytes& encryption) {
    if (key.size() == 32) {
        signing.assign(key.begin(), key.begin() + 16);
        encryption.assign(key.begin() + 16, key.end());
    } else if (key.size() == 64) {
        signing.assign(key.begin(), key.begin() + 32);
        encryption.assign(key.begin() + 32, key.end());
    } else {
        throw std::runtime_error(
            "token: key must be 32 (AES-128) or 64 (AES-256) bytes");
    }
}

}  // namespace

REGISTER_COMMAND(token_encrypt, {
    auto key = bridge::hex_param(p, "key");
    auto plaintext = bridge::hex_param(p, "plaintext");
    // A pinned IV gives deterministic, cross-impl-comparable output; when the
    // caller omits it we generate a random IV like a real RNS Token does, so
    // SUT-encrypt -> reference-decrypt round trips still work.
    auto iv = bridge::hex_param_or_empty(p, "iv");
    if (iv.empty()) iv = bridge::random_bytes(16);
    if (iv.size() != 16) {
        throw std::runtime_error("token_encrypt: iv must be 16 bytes");
    }
    auto token = bridge::token_seal(key, plaintext, iv);
    return bridge::json{{"token", bridge::to_hex(token)}};
})

REGISTER_COMMAND(token_decrypt, {
    auto key = bridge::hex_param(p, "key");
    auto token = bridge::hex_param(p, "token");
    // token_open authenticates BEFORE decrypting and throws (surfaced as a
    // BridgeError) on a too-short token, HMAC mismatch, or an undecryptable
    // body — matching RNS Token.decrypt's reject-don't-leak contract.
    auto pt = bridge::token_open(key, token);
    return bridge::json{{"plaintext", bridge::to_hex(pt)}};
})

REGISTER_COMMAND(token_verify_hmac, {
    auto key = bridge::hex_param(p, "key");
    auto token = bridge::hex_param(p, "token");
    bridge::Bytes signing_key, encryption_key;
    split_key(key, signing_key, encryption_key);

    // RNS rejects any token of 32 bytes or fewer before the HMAC gate
    // (Token.py:78) — there is no room for both a 32-byte HMAC and a body.
    if (token.size() <= 32) {
        throw std::runtime_error("token_verify_hmac: token too short");
    }
    bridge::Bytes hmac_recv(token.end() - 32, token.end());
    bridge::Bytes signed_parts(token.begin(), token.end() - 32);
    auto hmac_calc = bridge::hmac_sha256(signing_key, signed_parts);
    bool ok = bridge::consttime_memequal(hmac_recv.data(), hmac_calc.data(), 32);
    return bridge::json{{"valid", ok}};
})

REGISTER_COMMAND(token_generate_key, {
    // Generate a Token key for the requested AES mode, delegating the actual
    // generation (length + randomness) to the fork's
    // RNS::Cryptography::Token::generate_key — AES_128_CBC -> 32 bytes,
    // AES_256_CBC (the default) -> 64 bytes. An unrecognised mode is rejected
    // here with an identifying error BEFORE reaching the fork's generate_key
    // (whose own invalid-mode path throws a raw pointer), matching the
    // reference's TypeError-for-unknown-mode contract.
    std::string mode = "AES_256_CBC";
    if (p.contains("mode") && !p["mode"].is_null()) {
        mode = p["mode"].get<std::string>();
    }
    namespace TM = RNS::Type::Cryptography::Token;
    TM::token_mode mode_arg;
    if (mode == "AES_128_CBC") {
        mode_arg = TM::MODE_AES_128_CBC;
    } else if (mode == "AES_256_CBC") {
        mode_arg = TM::MODE_AES_256_CBC;
    } else {
        throw std::runtime_error("token_generate_key: invalid token mode: " + mode);
    }
    auto key = RNS::Cryptography::Token::generate_key(mode_arg);
    return bridge::json{
        {"key", bridge::to_hex(bridge::Bytes(key.data(), key.data() + key.size()))}};
})
