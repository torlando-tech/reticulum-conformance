// microReticulum bridge — JSON-RPC stdio harness for reticulum-conformance.
//
// One executable, one stdin reader loop, one command registry. Every command
// handler takes a parsed JSON params object and returns a result object.
// Errors are thrown and converted to {"success": false, "error": ...}.

#pragma once

#include "json.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace bridge {

using nlohmann::json;
using Bytes = std::vector<uint8_t>;
using Handler = std::function<json(const json&)>;

// Registry singleton — populated at static init time by REGISTER_COMMAND().
class Registry {
public:
    static Registry& instance() {
        static Registry r;
        return r;
    }

    void add(const std::string& name, Handler handler) {
        _commands[name] = std::move(handler);
    }

    const Handler* find(const std::string& name) const {
        auto it = _commands.find(name);
        return it == _commands.end() ? nullptr : &it->second;
    }

private:
    std::unordered_map<std::string, Handler> _commands;
};

// Helper: declare + register a command in one shot at file scope. Variadic
// so commas inside the body don't break preprocessor expansion (the preproc
// doesn't treat `{}` as balancing brackets, but `()` and `__VA_ARGS__` are
// fine).
#define REGISTER_COMMAND(name, ...)                                            \
    namespace {                                                                \
        struct _reg_##name {                                                   \
            _reg_##name() {                                                    \
                ::bridge::Registry::instance().add(                            \
                    #name,                                                     \
                    [](const ::bridge::json& p) -> ::bridge::json __VA_ARGS__  \
                );                                                             \
            }                                                                  \
        };                                                                     \
        static _reg_##name _reg_##name##_instance;                             \
    }

// Hex helpers — every binary field in the JSON-RPC protocol is lowercase hex.
std::string to_hex(const Bytes& b);
std::string to_hex(const uint8_t* data, size_t n);
Bytes from_hex(const std::string& s);

// Param accessors. Throw std::runtime_error("Missing param: <key>") if absent.
Bytes hex_param(const json& p, const char* key);
Bytes hex_param_or_empty(const json& p, const char* key);    // null/missing -> {}
int int_param(const json& p, const char* key);
std::string str_param(const json& p, const char* key);
bool bool_param(const json& p, const char* key);

// Spec-correct PKCS7 padding. (microReticulum's PKCS7::pad has a bug — see
// crypto.cpp pkcs7_pad WORKAROUND. Use this helper for any chained ops.)
Bytes pkcs7_pad(const Bytes& data, size_t block_size = 16);
Bytes pkcs7_unpad(const Bytes& data);

// Spec-correct HMAC-SHA256. (microReticulum's RNS::Cryptography::digest()
// double-feeds the message — see crypto.cpp hmac_sha256 WORKAROUND.)
Bytes hmac_sha256(const Bytes& key, const Bytes& msg);

}  // namespace bridge
