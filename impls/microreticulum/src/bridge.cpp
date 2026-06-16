#include "bridge.h"

#include "Bytes.h"
#include "Cryptography/HMAC.h"
#include "Cryptography/AES.h"

#include <random>
#include <stdexcept>

namespace bridge {

std::string to_hex(const uint8_t* data, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0xF]);
    }
    return out;
}

std::string to_hex(const Bytes& b) {
    return to_hex(b.data(), b.size());
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    throw std::runtime_error(std::string("Invalid hex char: ") + c);
}

Bytes from_hex(const std::string& s) {
    if (s.size() % 2 != 0) {
        throw std::runtime_error("Hex string has odd length");
    }
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back((uint8_t)((hex_nibble(s[i]) << 4) | hex_nibble(s[i + 1])));
    }
    return out;
}

Bytes hex_param(const json& p, const char* key) {
    if (!p.contains(key) || p[key].is_null()) {
        throw std::runtime_error(std::string("Missing param: ") + key);
    }
    return from_hex(p[key].get<std::string>());
}

Bytes hex_param_or_empty(const json& p, const char* key) {
    if (!p.contains(key) || p[key].is_null()) return {};
    return from_hex(p[key].get<std::string>());
}

int int_param(const json& p, const char* key) {
    if (!p.contains(key) || p[key].is_null()) {
        throw std::runtime_error(std::string("Missing param: ") + key);
    }
    return p[key].get<int>();
}

std::string str_param(const json& p, const char* key) {
    if (!p.contains(key) || p[key].is_null()) {
        throw std::runtime_error(std::string("Missing param: ") + key);
    }
    return p[key].get<std::string>();
}

bool bool_param(const json& p, const char* key) {
    if (!p.contains(key) || p[key].is_null()) {
        throw std::runtime_error(std::string("Missing param: ") + key);
    }
    return p[key].get<bool>();
}

Bytes pkcs7_pad(const Bytes& data, size_t block_size) {
    size_t padlen = block_size - (data.size() % block_size);
    Bytes padded = data;
    padded.insert(padded.end(), padlen, (uint8_t)padlen);
    return padded;
}

Bytes pkcs7_unpad(const Bytes& data, size_t block_size) {
    if (data.empty()) throw std::runtime_error("pkcs7_unpad: empty input");
    // RNS PKCS7.unpad (RNS/Cryptography/PKCS7.py): rejects a declared padding
    // length greater than the block size, otherwise returns data[:len-n] WITHOUT
    // validating the stripped bytes' content. So:
    //   * n > block_size (16) -> raise (test_pkcs7_unpad_rejects_oversized_padding)
    //   * n == 0             -> strip nothing, return verbatim
    //   * 1 <= n <= 16       -> strip n bytes, content NOT checked
    //                          (test_pkcs7_unpad_is_content_lax)
    // A stricter full-content check would diverge from the reference.
    size_t n = data.back();
    if (n > block_size) {
        throw std::runtime_error("pkcs7_unpad: invalid padding length");
    }
    if (n == 0 || n > data.size()) {
        return data;
    }
    return Bytes(data.begin(), data.end() - n);
}

bool consttime_memequal(const uint8_t* a, const uint8_t* b, size_t n) {
    // OR-accumulate per-byte XOR so the loop runs to completion regardless
    // of where the first mismatch occurs. Mirrors hmac.compare_digest's
    // constant-time guarantee — important when this comparison happens
    // against attacker-influenced bytes (HMAC tags, IFAC tags, etc.).
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

Bytes hmac_sha256(const Bytes& key, const Bytes& msg) {
    // BUG WORKAROUND for HMAC.h:103 — construct with empty msg, update once.
    RNS::Bytes rkey(key.data(), key.size());
    RNS::Cryptography::HMAC hmac(rkey, RNS::Bytes(),
                                  RNS::Cryptography::HMAC::DIGEST_SHA256);
    hmac.update(RNS::Bytes(msg.data(), msg.size()));
    auto h = hmac.digest();
    return Bytes(h.data(), h.data() + h.size());
}

Bytes random_bytes(size_t n) {
    Bytes out(n);
    std::random_device rd;
    for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)(rd() & 0xFF);
    return out;
}

namespace {
// Split a Token key into (signing, encryption) halves and pick the AES mode.
// RNS Token keys are either 32 bytes (AES-128: signing[0:16] || enc[16:32]) or
// 64 bytes (AES-256: signing[0:32] || enc[32:64]) — Token.py:53-69. Anything
// else is rejected (matches RNS raising on a wrong-length key).
void split_token_key(const Bytes& key, Bytes& signing, Bytes& encryption,
                     bool& aes256) {
    if (key.size() == 32) {
        aes256 = false;
        signing.assign(key.begin(), key.begin() + 16);
        encryption.assign(key.begin() + 16, key.end());
    } else if (key.size() == 64) {
        aes256 = true;
        signing.assign(key.begin(), key.begin() + 32);
        encryption.assign(key.begin() + 32, key.end());
    } else {
        throw std::runtime_error(
            "token: key must be 32 (AES-128) or 64 (AES-256) bytes");
    }
}

RNS::Bytes aes_cbc_encrypt(bool aes256, const Bytes& pt, const Bytes& key,
                           const Bytes& iv) {
    RNS::Bytes rpt(pt.data(), pt.size());
    RNS::Bytes rkey(key.data(), key.size());
    RNS::Bytes riv(iv.data(), iv.size());
    return aes256 ? RNS::Cryptography::AES_256_CBC::encrypt(rpt, rkey, riv)
                  : RNS::Cryptography::AES_128_CBC::encrypt(rpt, rkey, riv);
}

RNS::Bytes aes_cbc_decrypt(bool aes256, const Bytes& ct, const Bytes& key,
                           const Bytes& iv) {
    RNS::Bytes rct(ct.data(), ct.size());
    RNS::Bytes rkey(key.data(), key.size());
    RNS::Bytes riv(iv.data(), iv.size());
    return aes256 ? RNS::Cryptography::AES_256_CBC::decrypt(rct, rkey, riv)
                  : RNS::Cryptography::AES_128_CBC::decrypt(rct, rkey, riv);
}
}  // namespace

Bytes token_seal(const Bytes& key, const Bytes& plaintext, const Bytes& iv) {
    if (iv.size() != 16) {
        throw std::runtime_error("token_seal: iv must be 16 bytes");
    }
    Bytes signing_key, encryption_key;
    bool aes256;
    split_token_key(key, signing_key, encryption_key, aes256);

    Bytes padded = pkcs7_pad(plaintext);
    RNS::Bytes ct = aes_cbc_encrypt(aes256, padded, encryption_key, iv);

    Bytes signed_parts(iv);
    signed_parts.insert(signed_parts.end(), ct.data(), ct.data() + ct.size());
    Bytes mac = hmac_sha256(signing_key, signed_parts);

    Bytes token = signed_parts;
    token.insert(token.end(), mac.begin(), mac.end());
    return token;
}

Bytes token_open(const Bytes& key, const Bytes& token) {
    Bytes signing_key, encryption_key;
    bool aes256;
    split_token_key(key, signing_key, encryption_key, aes256);

    // RNS rejects any token of 32 bytes or fewer before decrypting
    // (Token.py:78) — no room for both the 32-byte HMAC and a body.
    if (token.size() <= 32) {
        throw std::runtime_error("token_open: token too short");
    }
    Bytes mac_recv(token.end() - 32, token.end());
    Bytes signed_parts(token.begin(), token.end() - 32);
    // Need at least a full 16-byte IV in the signed region.
    if (signed_parts.size() < 16) {
        throw std::runtime_error("token_open: token too short");
    }

    Bytes mac_calc = hmac_sha256(signing_key, signed_parts);
    if (!consttime_memequal(mac_recv.data(), mac_calc.data(), 32)) {
        throw std::runtime_error("token_open: HMAC verification failed");
    }

    // Authenticated — now decrypt. The ciphertext must be a positive multiple
    // of the AES block size; otherwise the body is undecryptable and RNS
    // raises ValueError("Could not decrypt token") (Token.py:106-114).
    Bytes iv(signed_parts.begin(), signed_parts.begin() + 16);
    Bytes ct(signed_parts.begin() + 16, signed_parts.end());
    if (ct.empty() || ct.size() % 16 != 0) {
        throw std::runtime_error("token_open: could not decrypt token");
    }

    RNS::Bytes pt_padded = aes_cbc_decrypt(aes256, ct, encryption_key, iv);
    return pkcs7_unpad(Bytes(pt_padded.data(), pt_padded.data() + pt_padded.size()));
}

}  // namespace bridge
