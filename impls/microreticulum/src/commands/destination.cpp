// Destination + name-hash commands. Pure SHA-256 truncations.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"

#include <stdexcept>
#include <string>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}

bridge::Bytes truncated_sha256_str(const std::string& s, size_t bytes) {
    bridge::Bytes data(s.begin(), s.end());
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + bytes);
}

bridge::Bytes truncated_sha256(const bridge::Bytes& data, size_t bytes) {
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + bytes);
}

}  // namespace

REGISTER_COMMAND(name_hash, {
    auto name = bridge::str_param(p, "name");
    auto hash = truncated_sha256_str(name, 10);   // 10 bytes per Reticulum spec
    return bridge::json{{"hash", bridge::to_hex(hash)}};
})

REGISTER_COMMAND(destination_hash, {
    auto identity_hash = bridge::hex_param(p, "identity_hash");
    auto app_name = bridge::str_param(p, "app_name");

    // aspects can be a comma-separated string or a list of strings.
    std::vector<std::string> aspects;
    if (p.contains("aspects") && !p["aspects"].is_null()) {
        const auto& a = p["aspects"];
        if (a.is_array()) {
            for (const auto& item : a) aspects.push_back(item.get<std::string>());
        } else if (a.is_string()) {
            std::string s = a.get<std::string>();
            if (!s.empty()) {
                size_t start = 0, comma;
                while ((comma = s.find(',', start)) != std::string::npos) {
                    aspects.push_back(s.substr(start, comma - start));
                    start = comma + 1;
                }
                aspects.push_back(s.substr(start));
            }
        }
    }

    std::string full_name = app_name;
    for (const auto& asp : aspects) {
        full_name += ".";
        full_name += asp;
    }

    auto name_hash = truncated_sha256_str(full_name, 10);

    bridge::Bytes addr_material;
    addr_material.insert(addr_material.end(), name_hash.begin(), name_hash.end());
    addr_material.insert(addr_material.end(), identity_hash.begin(), identity_hash.end());
    auto dest_hash = truncated_sha256(addr_material, 16);

    return bridge::json{
        {"name_hash", bridge::to_hex(name_hash)},
        {"destination_hash", bridge::to_hex(dest_hash)},
        {"full_name", full_name},
    };
})
