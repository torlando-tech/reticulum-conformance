// Token (Fernet-like) commands.
//
// Token wire format (matches Python RNS Token):
//   token = iv(16) || aes256cbc(plaintext + pkcs7) || hmac_sha256(iv||ct)
//
// Key is 64 bytes split as signing_key(32) || encryption_key(32).
// NOTE: any failures here are likely downstream of the microReticulum
// PKCS7::pad bug (writes [0,...,0,padlen] instead of padlen-repeated).

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/AES.h"
#include "Cryptography/PKCS7.h"
#include "Cryptography/HMAC.h"

#include <cstring>
#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

void split_key(const bridge::Bytes& key, bridge::Bytes& signing, bridge::Bytes& encryption) {
    if (key.size() != 64) {
        throw std::runtime_error("token: key must be 64 bytes (32 signing + 32 encryption)");
    }
    signing.assign(key.begin(), key.begin() + 32);
    encryption.assign(key.begin() + 32, key.end());
}

}  // namespace

REGISTER_COMMAND(token_encrypt, {
    auto key = bridge::hex_param(p, "key");
    auto plaintext = bridge::hex_param(p, "plaintext");
    auto iv = bridge::hex_param_or_empty(p, "iv");
    if (iv.empty()) {
        throw std::runtime_error("token_encrypt: iv is required for deterministic output");
    }
    if (iv.size() != 16) {
        throw std::runtime_error("token_encrypt: iv must be 16 bytes");
    }

    bridge::Bytes signing_key, encryption_key;
    split_key(key, signing_key, encryption_key);

    auto padded = bridge::pkcs7_pad(plaintext);
    auto ct = RNS::Cryptography::AES_256_CBC::encrypt(to_rns(padded), to_rns(encryption_key), to_rns(iv));

    bridge::Bytes signed_parts;
    signed_parts.insert(signed_parts.end(), iv.begin(), iv.end());
    signed_parts.insert(signed_parts.end(), ct.data(), ct.data() + ct.size());

    auto hmac = bridge::hmac_sha256(signing_key, signed_parts);
    bridge::Bytes token = signed_parts;
    token.insert(token.end(), hmac.begin(), hmac.end());

    return bridge::json{{"token", bridge::to_hex(token)}};
})

REGISTER_COMMAND(token_decrypt, {
    auto key = bridge::hex_param(p, "key");
    auto token = bridge::hex_param(p, "token");
    if (token.size() < 16 + 32) {
        throw std::runtime_error("token_decrypt: token too short");
    }
    bridge::Bytes signing_key, encryption_key;
    split_key(key, signing_key, encryption_key);

    bridge::Bytes iv(token.begin(), token.begin() + 16);
    bridge::Bytes ct(token.begin() + 16, token.end() - 32);
    bridge::Bytes hmac_recv(token.end() - 32, token.end());
    bridge::Bytes signed_parts(token.begin(), token.end() - 32);

    auto hmac_calc = bridge::hmac_sha256(signing_key, signed_parts);
    if (memcmp(hmac_recv.data(), hmac_calc.data(), 32) != 0) {
        throw std::runtime_error("token_decrypt: HMAC verification failed");
    }

    auto pt_padded_rns = RNS::Cryptography::AES_256_CBC::decrypt(to_rns(ct), to_rns(encryption_key), to_rns(iv));
    auto pt_padded = from_rns(pt_padded_rns);
    auto pt = bridge::pkcs7_unpad(pt_padded);
    return bridge::json{{"plaintext", bridge::to_hex(pt)}};
})

REGISTER_COMMAND(token_verify_hmac, {
    auto key = bridge::hex_param(p, "key");
    auto token = bridge::hex_param(p, "token");
    if (token.size() < 16 + 32) {
        return bridge::json{{"valid", false}};
    }
    bridge::Bytes signing_key, encryption_key;
    split_key(key, signing_key, encryption_key);

    bridge::Bytes hmac_recv(token.end() - 32, token.end());
    bridge::Bytes signed_parts(token.begin(), token.end() - 32);
    auto hmac_calc = bridge::hmac_sha256(signing_key, signed_parts);
    bool ok = memcmp(hmac_recv.data(), hmac_calc.data(), 32) == 0;
    return bridge::json{{"valid", ok}};
})
