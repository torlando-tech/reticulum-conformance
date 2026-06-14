// Announce-related stateless commands.
//
// random_hash:    5 random bytes + 5-byte big-endian unix timestamp.
// announce_pack:  public_key(64) || name_hash(10) || random_hash(10)
//                 [|| ratchet(32)] || signature(64) [|| app_data]
// announce_sign:  Ed25519 over destination_hash || public_key || name_hash ||
//                 random_hash [|| ratchet] [|| app_data]
// announce_verify: Ed25519 verify + recompute expected destination hash.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/Ed25519.h"

#include <chrono>
#include <random>
#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

constexpr size_t KEYSIZE = 64;
constexpr size_t NAME_HASH_LEN = 10;
constexpr size_t RANDOM_HASH_LEN = 10;
constexpr size_t RATCHET_SIZE = 32;
constexpr size_t SIG_LEN = 64;

}  // namespace

REGISTER_COMMAND(random_hash, {
    bridge::Bytes random_bytes;
    if (p.contains("random_bytes") && !p["random_bytes"].is_null()) {
        random_bytes = bridge::from_hex(p["random_bytes"].get<std::string>());
        if (random_bytes.size() != 5) {
            throw std::runtime_error("random_hash: random_bytes must be 5 bytes");
        }
    } else {
        random_bytes.resize(5);
        std::random_device rd;
        for (auto& b : random_bytes) b = (uint8_t)(rd() & 0xFF);
    }

    int64_t timestamp;
    if (p.contains("timestamp") && !p["timestamp"].is_null()) {
        timestamp = p["timestamp"].get<int64_t>();
    } else {
        timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // 5-byte big-endian timestamp.
    bridge::Bytes ts_bytes(5);
    for (int i = 0; i < 5; ++i) {
        ts_bytes[4 - i] = (uint8_t)((timestamp >> (i * 8)) & 0xFF);
    }

    bridge::Bytes hash;
    hash.insert(hash.end(), random_bytes.begin(), random_bytes.end());
    hash.insert(hash.end(), ts_bytes.begin(), ts_bytes.end());

    return bridge::json{
        {"random_hash", bridge::to_hex(hash)},
        {"random_bytes", bridge::to_hex(random_bytes)},
        {"timestamp", timestamp},
        {"timestamp_bytes", bridge::to_hex(ts_bytes)},
    };
})

REGISTER_COMMAND(announce_pack, {
    auto public_key = bridge::hex_param(p, "public_key");
    auto name_hash = bridge::hex_param(p, "name_hash");
    auto random_hash = bridge::hex_param(p, "random_hash");
    auto ratchet = bridge::hex_param_or_empty(p, "ratchet");
    auto signature = bridge::hex_param(p, "signature");
    auto app_data = bridge::hex_param_or_empty(p, "app_data");

    if (public_key.size() != KEYSIZE)
        throw std::runtime_error("announce_pack: public_key must be 64 bytes");
    if (name_hash.size() != NAME_HASH_LEN)
        throw std::runtime_error("announce_pack: name_hash must be 10 bytes");
    if (random_hash.size() != RANDOM_HASH_LEN)
        throw std::runtime_error("announce_pack: random_hash must be 10 bytes");
    if (!ratchet.empty() && ratchet.size() != RATCHET_SIZE)
        throw std::runtime_error("announce_pack: ratchet must be 32 bytes");
    if (signature.size() != SIG_LEN)
        throw std::runtime_error("announce_pack: signature must be 64 bytes");

    bridge::Bytes out;
    out.insert(out.end(), public_key.begin(), public_key.end());
    out.insert(out.end(), name_hash.begin(), name_hash.end());
    out.insert(out.end(), random_hash.begin(), random_hash.end());
    out.insert(out.end(), ratchet.begin(), ratchet.end());
    out.insert(out.end(), signature.begin(), signature.end());
    out.insert(out.end(), app_data.begin(), app_data.end());

    return bridge::json{
        {"announce_data", bridge::to_hex(out)},
        {"size", (int)out.size()},
        {"has_ratchet", !ratchet.empty()},
    };
})

REGISTER_COMMAND(announce_unpack, {
    auto d = bridge::hex_param(p, "announce_data");
    bool has_ratchet = p.contains("has_ratchet") && !p["has_ratchet"].is_null()
                           ? p["has_ratchet"].get<bool>() : false;
    size_t rsz = has_ratchet ? RATCHET_SIZE : 0;
    size_t min = KEYSIZE + NAME_HASH_LEN + RANDOM_HASH_LEN + rsz + SIG_LEN;
    if (d.size() < min)
        throw std::runtime_error("announce_unpack: announce_data too short");

    size_t off = 0;
    bridge::Bytes public_key(d.begin() + off, d.begin() + off + KEYSIZE); off += KEYSIZE;
    bridge::Bytes name_hash(d.begin() + off, d.begin() + off + NAME_HASH_LEN); off += NAME_HASH_LEN;
    bridge::Bytes random_hash(d.begin() + off, d.begin() + off + RANDOM_HASH_LEN); off += RANDOM_HASH_LEN;
    bridge::Bytes ratchet;
    if (has_ratchet) { ratchet.assign(d.begin() + off, d.begin() + off + RATCHET_SIZE); off += RATCHET_SIZE; }
    bridge::Bytes signature(d.begin() + off, d.begin() + off + SIG_LEN); off += SIG_LEN;
    bridge::Bytes app_data(d.begin() + off, d.end());

    return bridge::json{
        {"public_key", bridge::to_hex(public_key)},
        {"name_hash", bridge::to_hex(name_hash)},
        {"random_hash", bridge::to_hex(random_hash)},
        {"ratchet", ratchet.empty() ? std::string() : bridge::to_hex(ratchet)},
        {"signature", bridge::to_hex(signature)},
        {"app_data", app_data.empty() ? std::string() : bridge::to_hex(app_data)},
        {"has_ratchet", !ratchet.empty()},
    };
})

REGISTER_COMMAND(announce_sign, {
    auto private_key = bridge::hex_param(p, "private_key");
    auto destination_hash = bridge::hex_param(p, "destination_hash");
    auto public_key = bridge::hex_param(p, "public_key");
    auto name_hash = bridge::hex_param(p, "name_hash");
    auto random_hash = bridge::hex_param(p, "random_hash");
    auto ratchet = bridge::hex_param_or_empty(p, "ratchet");
    auto app_data = bridge::hex_param_or_empty(p, "app_data");
    if (private_key.size() != KEYSIZE)
        throw std::runtime_error("announce_sign: private_key must be 64 bytes");

    // signed data = destination_hash || public_key || name_hash || random_hash
    //               [|| ratchet] [|| app_data]   (matches RNS Destination.announce)
    bridge::Bytes signed_data;
    signed_data.insert(signed_data.end(), destination_hash.begin(), destination_hash.end());
    signed_data.insert(signed_data.end(), public_key.begin(), public_key.end());
    signed_data.insert(signed_data.end(), name_hash.begin(), name_hash.end());
    signed_data.insert(signed_data.end(), random_hash.begin(), random_hash.end());
    signed_data.insert(signed_data.end(), ratchet.begin(), ratchet.end());
    signed_data.insert(signed_data.end(), app_data.begin(), app_data.end());

    // Sign with the Ed25519 half (second 32 bytes) of the identity private key.
    bridge::Bytes ed25519_priv(private_key.begin() + 32, private_key.end());
    auto sk = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed25519_priv));
    auto sig = sk->sign(to_rns(signed_data));

    return bridge::json{
        {"signature", bridge::to_hex(from_rns(sig))},
        {"signed_data", bridge::to_hex(signed_data)},
    };
})

REGISTER_COMMAND(announce_verify, {
    auto d = bridge::hex_param(p, "announce_data");
    auto destination_hash = bridge::hex_param(p, "destination_hash");
    bool has_ratchet = p.contains("has_ratchet") && !p["has_ratchet"].is_null()
                           ? p["has_ratchet"].get<bool>() : false;
    bool validate_dest_hash = p.contains("validate_dest_hash") && !p["validate_dest_hash"].is_null()
                                  ? p["validate_dest_hash"].get<bool>() : true;

    size_t rsz = has_ratchet ? RATCHET_SIZE : 0;
    if (d.size() < KEYSIZE + NAME_HASH_LEN + RANDOM_HASH_LEN + rsz + SIG_LEN)
        throw std::runtime_error("announce_verify: announce_data too short");

    size_t off = 0;
    bridge::Bytes public_key(d.begin() + off, d.begin() + off + KEYSIZE); off += KEYSIZE;
    bridge::Bytes name_hash(d.begin() + off, d.begin() + off + NAME_HASH_LEN); off += NAME_HASH_LEN;
    bridge::Bytes random_hash(d.begin() + off, d.begin() + off + RANDOM_HASH_LEN); off += RANDOM_HASH_LEN;
    bridge::Bytes ratchet;
    if (has_ratchet) { ratchet.assign(d.begin() + off, d.begin() + off + RATCHET_SIZE); off += RATCHET_SIZE; }
    bridge::Bytes signature(d.begin() + off, d.begin() + off + SIG_LEN); off += SIG_LEN;
    bridge::Bytes app_data(d.begin() + off, d.end());

    bridge::Bytes signed_data;
    signed_data.insert(signed_data.end(), destination_hash.begin(), destination_hash.end());
    signed_data.insert(signed_data.end(), public_key.begin(), public_key.end());
    signed_data.insert(signed_data.end(), name_hash.begin(), name_hash.end());
    signed_data.insert(signed_data.end(), random_hash.begin(), random_hash.end());
    signed_data.insert(signed_data.end(), ratchet.begin(), ratchet.end());
    signed_data.insert(signed_data.end(), app_data.begin(), app_data.end());

    bridge::Bytes ed25519_pub(public_key.begin() + 32, public_key.end());
    auto vk = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(to_rns(ed25519_pub));
    bool signature_valid = vk->verify(to_rns(signature), to_rns(signed_data));

    bool dest_hash_valid = true;
    bridge::Bytes expected_dest_hash;
    if (validate_dest_hash) {
        auto id_full = RNS::Cryptography::sha256(to_rns(public_key));
        bridge::Bytes identity_hash(id_full.data(), id_full.data() + 16);
        bridge::Bytes hash_material(name_hash);
        hash_material.insert(hash_material.end(), identity_hash.begin(), identity_hash.end());
        auto dh_full = RNS::Cryptography::sha256(to_rns(hash_material));
        expected_dest_hash.assign(dh_full.data(), dh_full.data() + 16);
        dest_hash_valid = (destination_hash == expected_dest_hash);
    }

    return bridge::json{
        {"valid", signature_valid && dest_hash_valid},
        {"signature_valid", signature_valid},
        {"dest_hash_valid", dest_hash_valid},
        {"expected_dest_hash", validate_dest_hash ? bridge::to_hex(expected_dest_hash) : std::string()},
    };
})
