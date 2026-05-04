// Resource pack commands. Stateless wire-format pieces — Resource state
// machine + advertisement msgpack are Tier 2B.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"

#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}

bridge::Bytes truncated_sha256(const bridge::Bytes& data, size_t bytes) {
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + bytes);
}

}  // namespace

REGISTER_COMMAND(resource_hash, {
    auto data = bridge::hex_param(p, "data");
    auto random_hash = bridge::hex_param(p, "random_hash");
    bridge::Bytes material;
    material.insert(material.end(), random_hash.begin(), random_hash.end());
    material.insert(material.end(), data.begin(), data.end());

    auto h = RNS::Cryptography::sha256(to_rns(material));
    bridge::Bytes truncated(h.data(), h.data() + 16);
    bridge::Bytes full(h.data(), h.data() + h.size());
    return bridge::json{
        {"hash", bridge::to_hex(truncated)},
        {"full_hash", bridge::to_hex(full)},
    };
})

REGISTER_COMMAND(resource_map_hash, {
    auto part_data = bridge::hex_param(p, "part_data");
    auto random_hash = bridge::hex_param(p, "random_hash");
    bridge::Bytes material;
    material.insert(material.end(), part_data.begin(), part_data.end());
    material.insert(material.end(), random_hash.begin(), random_hash.end());
    auto map_hash = truncated_sha256(material, 4);
    return bridge::json{{"map_hash", bridge::to_hex(map_hash)}};
})

REGISTER_COMMAND(resource_flags, {
    std::string mode = (p.contains("mode") && !p["mode"].is_null())
                          ? p["mode"].get<std::string>() : "encode";
    if (mode == "encode") {
        auto get_bool = [&](const char* k) -> bool {
            return p.contains(k) && !p[k].is_null() && p[k].get<bool>();
        };
        int flags = 0;
        if (get_bool("encrypted"))    flags |= 0x01;
        if (get_bool("compressed"))   flags |= 0x02;
        if (get_bool("split"))        flags |= 0x04;
        if (get_bool("is_request"))   flags |= 0x08;
        if (get_bool("is_response"))  flags |= 0x10;
        if (get_bool("has_metadata")) flags |= 0x20;
        return bridge::json{{"flags", flags}};
    } else {
        int flags = bridge::int_param(p, "flags");
        return bridge::json{
            {"encrypted",     (flags & 0x01) == 0x01},
            {"compressed",    ((flags >> 1) & 0x01) == 0x01},
            {"split",         ((flags >> 2) & 0x01) == 0x01},
            {"is_request",    ((flags >> 3) & 0x01) == 0x01},
            {"is_response",   ((flags >> 4) & 0x01) == 0x01},
            {"has_metadata",  ((flags >> 5) & 0x01) == 0x01},
        };
    }
})

REGISTER_COMMAND(resource_build_hashmap, {
    auto random_hash = bridge::hex_param(p, "random_hash");
    if (!p.contains("parts") || !p["parts"].is_array()) {
        throw std::runtime_error("resource_build_hashmap: 'parts' must be a hex array");
    }
    bridge::Bytes hashmap;
    int num_parts = 0;
    for (const auto& part_hex : p["parts"]) {
        auto part = bridge::from_hex(part_hex.get<std::string>());
        bridge::Bytes material;
        material.insert(material.end(), part.begin(), part.end());
        material.insert(material.end(), random_hash.begin(), random_hash.end());
        auto h = truncated_sha256(material, 4);
        hashmap.insert(hashmap.end(), h.begin(), h.end());
        ++num_parts;
    }
    return bridge::json{
        {"hashmap", bridge::to_hex(hashmap)},
        {"num_parts", num_parts},
    };
})

REGISTER_COMMAND(resource_proof, {
    auto data = bridge::hex_param(p, "data");
    auto resource_hash = bridge::hex_param(p, "resource_hash");
    bridge::Bytes material;
    material.insert(material.end(), data.begin(), data.end());
    material.insert(material.end(), resource_hash.begin(), resource_hash.end());
    auto proof = truncated_sha256(material, 16);
    return bridge::json{{"proof", bridge::to_hex(proof)}};
})
