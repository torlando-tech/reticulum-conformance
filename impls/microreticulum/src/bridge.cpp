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

Bytes pkcs7_unpad(const Bytes& data) {
    if (data.empty()) throw std::runtime_error("pkcs7_unpad: empty input");
    size_t padlen = data.back();
    if (padlen == 0 || padlen > 16 || padlen > data.size()) {
        throw std::runtime_error("pkcs7_unpad: invalid padding");
    }
    // PKCS7 spec: every padding byte must equal padlen. Trusting only
    // data.back() would silently accept ciphertext with corrupt interior
    // padding (e.g., [..., 0x00, 0x03] would pass as 3-byte padding).
    for (size_t i = data.size() - padlen; i < data.size(); ++i) {
        if (data[i] != (uint8_t)padlen) {
            throw std::runtime_error("pkcs7_unpad: corrupt padding bytes");
        }
    }
    return Bytes(data.begin(), data.end() - padlen);
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

Bytes token_seal(const Bytes& key64, const Bytes& plaintext, const Bytes& iv) {
    if (key64.size() != 64) {
        throw std::runtime_error("token_seal: key must be 64 bytes");
    }
    if (iv.size() != 16) {
        throw std::runtime_error("token_seal: iv must be 16 bytes");
    }
    Bytes signing_key(key64.begin(), key64.begin() + 32);
    Bytes encryption_key(key64.begin() + 32, key64.end());

    Bytes padded = pkcs7_pad(plaintext);
    RNS::Bytes ct = RNS::Cryptography::AES_256_CBC::encrypt(
        RNS::Bytes(padded.data(), padded.size()),
        RNS::Bytes(encryption_key.data(), encryption_key.size()),
        RNS::Bytes(iv.data(), iv.size()));

    Bytes signed_parts(iv);
    signed_parts.insert(signed_parts.end(), ct.data(), ct.data() + ct.size());
    Bytes mac = hmac_sha256(signing_key, signed_parts);

    Bytes token = signed_parts;
    token.insert(token.end(), mac.begin(), mac.end());
    return token;
}

Bytes token_open(const Bytes& key64, const Bytes& token) {
    if (key64.size() != 64) {
        throw std::runtime_error("token_open: key must be 64 bytes");
    }
    // iv(16) + at least one AES-CBC block(16) + hmac(32).
    if (token.size() < 16 + 16 + 32) {
        throw std::runtime_error("token_open: token too short");
    }
    Bytes signing_key(key64.begin(), key64.begin() + 32);
    Bytes encryption_key(key64.begin() + 32, key64.end());

    Bytes iv(token.begin(), token.begin() + 16);
    Bytes ct(token.begin() + 16, token.end() - 32);
    Bytes mac_recv(token.end() - 32, token.end());
    Bytes signed_parts(token.begin(), token.end() - 32);

    Bytes mac_calc = hmac_sha256(signing_key, signed_parts);
    if (!consttime_memequal(mac_recv.data(), mac_calc.data(), 32)) {
        throw std::runtime_error("token_open: HMAC verification failed");
    }

    RNS::Bytes pt_padded = RNS::Cryptography::AES_256_CBC::decrypt(
        RNS::Bytes(ct.data(), ct.size()),
        RNS::Bytes(encryption_key.data(), encryption_key.size()),
        RNS::Bytes(iv.data(), iv.size()));
    return pkcs7_unpad(Bytes(pt_padded.data(), pt_padded.data() + pt_padded.size()));
}

}  // namespace bridge
