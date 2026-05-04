#include "bridge.h"

#include "Bytes.h"
#include "Cryptography/HMAC.h"

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
    return Bytes(data.begin(), data.end() - padlen);
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

}  // namespace bridge
