// Packet pack/unpack/flags/hash. Pure byte juggling — no microReticulum
// classes needed (microReticulum's Packet.cpp pulls in MsgPack which we
// excluded from the build). Implementing the wire format directly here.
//
// Wire format:
//   byte 0:    flags = (header_type<<6) | (context_flag<<5) | (transport_type<<4) | (destination_type<<2) | packet_type
//   byte 1:    hops
//   bytes 2..: HEADER_1 → destination_hash(16) || context(1) || data(N)
//              HEADER_2 → transport_id(16) || destination_hash(16) || context(1) || data(N)

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"

#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}

constexpr size_t DST_LEN = 16;

}  // namespace

REGISTER_COMMAND(packet_flags, {
    int header_type = bridge::int_param(p, "header_type");
    int context_flag = bridge::int_param(p, "context_flag");
    int transport_type = bridge::int_param(p, "transport_type");
    int destination_type = bridge::int_param(p, "destination_type");
    int packet_type = bridge::int_param(p, "packet_type");
    int flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4)
                | (destination_type << 2) | packet_type;
    char hex[3];
    std::snprintf(hex, sizeof(hex), "%02x", flags);
    return bridge::json{{"flags", flags}, {"flags_hex", std::string(hex)}};
})

REGISTER_COMMAND(packet_parse_flags, {
    int flags = bridge::int_param(p, "flags");
    return bridge::json{
        {"header_type",      (flags & 0b01000000) >> 6},
        {"context_flag",     (flags & 0b00100000) >> 5},
        {"transport_type",   (flags & 0b00010000) >> 4},
        {"destination_type", (flags & 0b00001100) >> 2},
        {"packet_type",       flags & 0b00000011},
    };
})

REGISTER_COMMAND(packet_pack, {
    int header_type = bridge::int_param(p, "header_type");
    int context_flag = bridge::int_param(p, "context_flag");
    int transport_type = bridge::int_param(p, "transport_type");
    int destination_type = bridge::int_param(p, "destination_type");
    int packet_type = bridge::int_param(p, "packet_type");
    int hops = p.contains("hops") && !p["hops"].is_null() ? p["hops"].get<int>() : 0;
    auto destination_hash = bridge::hex_param(p, "destination_hash");
    auto transport_id = bridge::hex_param_or_empty(p, "transport_id");
    int context = p.contains("context") && !p["context"].is_null() ? p["context"].get<int>() : 0;
    auto data = bridge::hex_param(p, "data");

    int flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4)
                | (destination_type << 2) | packet_type;

    bridge::Bytes raw;
    raw.push_back((uint8_t)flags);
    raw.push_back((uint8_t)hops);
    if (header_type == 1) {
        if (transport_id.size() != DST_LEN) {
            throw std::runtime_error("packet_pack: HEADER_2 requires 16-byte transport_id");
        }
        raw.insert(raw.end(), transport_id.begin(), transport_id.end());
    }
    if (destination_hash.size() != DST_LEN) {
        throw std::runtime_error("packet_pack: destination_hash must be 16 bytes");
    }
    raw.insert(raw.end(), destination_hash.begin(), destination_hash.end());
    raw.push_back((uint8_t)context);
    raw.insert(raw.end(), data.begin(), data.end());

    return bridge::json{{"raw", bridge::to_hex(raw)}};
})

REGISTER_COMMAND(packet_unpack, {
    auto raw = bridge::hex_param(p, "raw");
    if (raw.size() < 2) throw std::runtime_error("packet_unpack: too short");

    uint8_t flags = raw[0];
    uint8_t hops = raw[1];
    int header_type = (flags & 0b01000000) >> 6;
    int context_flag = (flags & 0b00100000) >> 5;
    int transport_type = (flags & 0b00010000) >> 4;
    int destination_type = (flags & 0b00001100) >> 2;
    int packet_type = flags & 0b00000011;

    bridge::Bytes transport_id, destination_hash, data;
    int context = 0;
    if (header_type == 1) {
        if (raw.size() < 2 + DST_LEN + DST_LEN + 1) {
            throw std::runtime_error("packet_unpack: HEADER_2 too short");
        }
        transport_id.assign(raw.begin() + 2, raw.begin() + 2 + DST_LEN);
        destination_hash.assign(raw.begin() + 2 + DST_LEN, raw.begin() + 2 + 2*DST_LEN);
        context = raw[2 + 2*DST_LEN];
        data.assign(raw.begin() + 3 + 2*DST_LEN, raw.end());
    } else {
        if (raw.size() < 2 + DST_LEN + 1) {
            throw std::runtime_error("packet_unpack: HEADER_1 too short");
        }
        destination_hash.assign(raw.begin() + 2, raw.begin() + 2 + DST_LEN);
        context = raw[2 + DST_LEN];
        data.assign(raw.begin() + 3 + DST_LEN, raw.end());
    }

    bridge::json result = {
        {"flags", flags},
        {"hops", hops},
        {"header_type", header_type},
        {"context_flag", context_flag},
        {"transport_type", transport_type},
        {"destination_type", destination_type},
        {"packet_type", packet_type},
        {"destination_hash", bridge::to_hex(destination_hash)},
        {"context", context},
        {"data", bridge::to_hex(data)},
    };
    if (header_type == 1) {
        result["transport_id"] = bridge::to_hex(transport_id);
    } else {
        result["transport_id"] = nullptr;
    }
    return result;
})

REGISTER_COMMAND(packet_parse_header, {
    auto raw = bridge::hex_param(p, "raw");
    if (raw.size() < 2) throw std::runtime_error("packet_parse_header: too short");

    uint8_t flags = raw[0];
    uint8_t hops = raw[1];
    int header_type = (flags >> 6) & 0x01;
    int context_flag = (flags >> 5) & 0x01;
    int transport_type = (flags >> 4) & 0x01;
    int destination_type = (flags >> 2) & 0x03;
    int packet_type = flags & 0x03;

    bridge::json result = {
        {"flags", flags},
        {"hops", hops},
        {"header_type", header_type},
        {"context_flag", context_flag},
        {"transport_type", transport_type},
        {"destination_type", destination_type},
        {"packet_type", packet_type},
    };
    if (header_type == 1) {
        if (raw.size() < 2 + DST_LEN + DST_LEN + 1) {
            throw std::runtime_error("packet_parse_header: HEADER_2 too short");
        }
        bridge::Bytes transport_id(raw.begin() + 2, raw.begin() + 2 + DST_LEN);
        bridge::Bytes destination_hash(raw.begin() + 2 + DST_LEN, raw.begin() + 2 + 2*DST_LEN);
        result["transport_id"] = bridge::to_hex(transport_id);
        result["destination_hash"] = bridge::to_hex(destination_hash);
        result["context"] = raw[2 + 2*DST_LEN];
    } else {
        if (raw.size() < 2 + DST_LEN + 1) {
            throw std::runtime_error("packet_parse_header: HEADER_1 too short");
        }
        bridge::Bytes destination_hash(raw.begin() + 2, raw.begin() + 2 + DST_LEN);
        result["transport_id"] = nullptr;
        result["destination_hash"] = bridge::to_hex(destination_hash);
        result["context"] = raw[2 + DST_LEN];
    }
    return result;
})

REGISTER_COMMAND(packet_hash, {
    auto raw = bridge::hex_param(p, "raw");
    if (raw.size() < 2) throw std::runtime_error("packet_hash: too short");
    uint8_t flags = raw[0];
    int header_type = (flags & 0b01000000) >> 6;
    uint8_t masked = flags & 0b00001111;

    // Match the per-header-type minimum-size guards already used by
    // packet_unpack / packet_parse_header. Without this a HEADER_2 packet
    // shorter than 18 bytes would slice raw.begin() + 18 — past raw.end()
    // — and feed an invalid range to insert(), which is UB.
    size_t min_size = (header_type == 1) ? (2 + DST_LEN + DST_LEN + 1)
                                         : (2 + DST_LEN + 1);
    if (raw.size() < min_size) {
        throw std::runtime_error("packet_hash: packet too short for header type");
    }

    bridge::Bytes hashable;
    hashable.push_back(masked);
    if (header_type == 1) {
        // Skip transport_id (16 bytes after hops)
        hashable.insert(hashable.end(), raw.begin() + 2 + DST_LEN, raw.end());
    } else {
        hashable.insert(hashable.end(), raw.begin() + 2, raw.end());
    }
    auto h = RNS::Cryptography::sha256(to_rns(hashable));
    bridge::Bytes truncated(h.data(), h.data() + 16);
    bridge::Bytes full(h.data(), h.data() + h.size());
    return bridge::json{
        {"hash", bridge::to_hex(full)},
        {"truncated_hash", bridge::to_hex(truncated)},
        {"hashable_part", bridge::to_hex(hashable)},
    };
})
