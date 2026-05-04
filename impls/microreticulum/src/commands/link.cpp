// Link-related commands. Stateless byte juggling — link state machine is
// Tier 2B and not addressed here.
//
// link_signalling_bytes: 3-byte field encoding (mode<<21) | mtu_low_21_bits.
// link_id_from_packet:  truncated SHA-256 of hashable part of LR packet.
// link_derive_key:      HKDF over (shared_key, salt=link_id) → 64 bytes.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/HKDF.h"

#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

constexpr size_t DST_LEN = 16;
constexpr size_t ECPUBSIZE = 64;
constexpr uint32_t MTU_BYTEMASK = 0x1FFFFF;
constexpr uint32_t MODE_BYTEMASK = 0xE0;

}  // namespace

REGISTER_COMMAND(link_signalling_bytes, {
    int mtu = bridge::int_param(p, "mtu");
    int mode = (p.contains("mode") && !p["mode"].is_null()) ? p["mode"].get<int>() : 1;

    uint32_t value = ((uint32_t)mtu & MTU_BYTEMASK)
                     + ((((uint32_t)(mode << 5)) & MODE_BYTEMASK) << 16);
    bridge::Bytes signalling = {
        (uint8_t)((value >> 16) & 0xFF),
        (uint8_t)((value >> 8) & 0xFF),
        (uint8_t)(value & 0xFF),
    };
    return bridge::json{
        {"signalling_bytes", bridge::to_hex(signalling)},
        {"decoded_mtu", (int)((uint32_t)mtu & MTU_BYTEMASK)},
        {"decoded_mode", mode},
    };
})

REGISTER_COMMAND(link_parse_signalling, {
    auto sig = bridge::hex_param(p, "signalling_bytes");
    if (sig.size() != 3) {
        throw std::runtime_error("link_parse_signalling: expected 3 bytes");
    }
    uint32_t value = ((uint32_t)sig[0] << 16) | ((uint32_t)sig[1] << 8) | (uint32_t)sig[2];
    int mtu = (int)(value & MTU_BYTEMASK);
    int mode = (int)((sig[0] & MODE_BYTEMASK) >> 5);
    return bridge::json{{"mtu", mtu}, {"mode", mode}};
})

REGISTER_COMMAND(link_id_from_packet, {
    auto raw = bridge::hex_param(p, "raw");
    if (raw.size() < 2) throw std::runtime_error("link_id_from_packet: too short");

    uint8_t flags = raw[0];
    int header_type = (flags & 0b01000000) >> 6;
    uint8_t masked = flags & 0b00001111;

    // HEADER_2 path slices raw.begin() + 2 + DST_LEN (offset 18) — without
    // a size guard, a 3..17-byte packet with the header-type-1 bit set
    // would form an iterator past raw.end() and feed it to insert(), which
    // is UB. packet_unpack and packet_parse_header check the same lower
    // bound — apply it here too.
    size_t min_size = (header_type == 1) ? (2 + DST_LEN + DST_LEN + 1)
                                         : (2 + DST_LEN + 1);
    if (raw.size() < min_size) {
        throw std::runtime_error("link_id_from_packet: packet too short for header type");
    }

    bridge::Bytes hashable;
    hashable.push_back(masked);
    size_t header_len;
    if (header_type == 1) {
        hashable.insert(hashable.end(), raw.begin() + 2 + DST_LEN, raw.end());
        header_len = 2 + DST_LEN + DST_LEN + 1;
    } else {
        hashable.insert(hashable.end(), raw.begin() + 2, raw.end());
        header_len = 2 + DST_LEN + 1;
    }

    // For LR packets: if data > ECPUBSIZE, truncate signalling tail off the hash input.
    size_t data_len = (raw.size() > header_len) ? (raw.size() - header_len) : 0;
    if (data_len > ECPUBSIZE) {
        size_t diff = data_len - ECPUBSIZE;
        if (hashable.size() >= diff) hashable.resize(hashable.size() - diff);
    }

    auto h = RNS::Cryptography::sha256(to_rns(hashable));
    bridge::Bytes link_id(h.data(), h.data() + 16);
    bridge::Bytes full(h.data(), h.data() + h.size());
    return bridge::json{
        {"link_id", bridge::to_hex(link_id)},
        {"full_hash", bridge::to_hex(full)},
    };
})

REGISTER_COMMAND(link_derive_key, {
    auto shared = bridge::hex_param(p, "shared_key");
    auto link_id = bridge::hex_param(p, "link_id");
    std::string mode = (p.contains("mode") && !p["mode"].is_null())
                          ? p["mode"].get<std::string>() : "AES_256_CBC";
    int length = (mode == "AES_256_CBC") ? 64 : 32;
    auto derived = RNS::Cryptography::hkdf((size_t)length, to_rns(shared),
                                            to_rns(link_id), RNS::Bytes());
    auto out = from_rns(derived);
    bridge::json j{{"derived_key", bridge::to_hex(out)}};
    if (length == 64) {
        bridge::Bytes enc(out.begin(), out.begin() + 32);
        bridge::Bytes sig(out.begin() + 32, out.end());
        j["encryption_key"] = bridge::to_hex(enc);
        j["signing_key"] = bridge::to_hex(sig);
    }
    return j;
})
