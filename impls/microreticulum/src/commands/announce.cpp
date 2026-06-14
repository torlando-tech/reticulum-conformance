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
#include "Type.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/Ed25519.h"
#include "Cryptography/X25519.h"

#include <chrono>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

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

// ---------------------------------------------------------------------------
// Higher-level announce commands — the contract the reference bridge exposes
// (announce_build / announce_validate / announce_queue_constants /
// auto_discovery_token). These operate on the FULL RNS announce PACKET wire
// bytes (`raw`), not just the announce body, so a packet built by one impl can
// be validated by the other.
//
//   packet wire:  flags(1) || hops(1) || dest_hash(16) || context(1) || data
//                 flags = (header_type<<6)|(context_flag<<5)|(transport<<4)
//                         |(dest_type<<2)|packet_type
//                 announce: HEADER_1, BROADCAST, SINGLE, ANNOUNCE, context=NONE,
//                           context_flag set iff a ratchet is present.
//   data (body):  public_key(64) || name_hash(10) || random_hash(10)
//                 [|| ratchet(32)] || signature(64) [|| app_data]
//   signed_data:  dest_hash || public_key || name_hash || random_hash
//                 || ratchet || app_data            (Ed25519 over this blob)
//   dest_hash:    sha256(name_hash || sha256(public_key)[:16])[:16]
//
// The crypto is delegated to the fork's RNS::Cryptography (Ed25519 / X25519 /
// sha256); only the wire layout is reimplemented here — deliberately NOT going
// through Identity::validate_announce / Destination::announce (which require a
// Packet->msgpack round-trip the stateless bridge build excludes).
// ---------------------------------------------------------------------------

namespace {

bridge::Bytes trunc_sha256(const bridge::Bytes& data, size_t n) {
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + n);
}

bridge::Bytes full_sha256(const bridge::Bytes& data) {
    auto h = RNS::Cryptography::sha256(to_rns(data));
    return bridge::Bytes(h.data(), h.data() + h.size());
}

// name_hash = sha256(app_name[.aspect...])[:NAME_HASH_LEN], mirroring RNS
// Destination.expand_name(None, app_name, *aspects) -> full_hash -> truncate.
bridge::Bytes compute_name_hash(const std::string& app_name,
                                const std::vector<std::string>& aspects) {
    std::string full_name = app_name;
    for (const auto& a : aspects) { full_name += '.'; full_name += a; }
    bridge::Bytes nb(full_name.begin(), full_name.end());
    return trunc_sha256(nb, NAME_HASH_LEN);
}

// destination_hash = sha256(name_hash || sha256(public_key)[:16])[:16]
bridge::Bytes compute_dest_hash(const bridge::Bytes& name_hash,
                                const bridge::Bytes& public_key) {
    bridge::Bytes identity_hash = trunc_sha256(public_key, 16);
    bridge::Bytes material(name_hash);
    material.insert(material.end(), identity_hash.begin(), identity_hash.end());
    return trunc_sha256(material, 16);
}

// aspects: JSON array of strings, OR a comma-separated string, OR absent.
std::vector<std::string> parse_aspects(const bridge::json& p) {
    std::vector<std::string> aspects;
    if (p.contains("aspects") && !p["aspects"].is_null()) {
        const auto& a = p["aspects"];
        if (a.is_array()) {
            for (const auto& el : a) aspects.push_back(el.get<std::string>());
        } else if (a.is_string()) {
            std::string s = a.get<std::string>();
            if (!s.empty()) {
                size_t start = 0, pos;
                while ((pos = s.find(',', start)) != std::string::npos) {
                    aspects.push_back(s.substr(start, pos - start));
                    start = pos + 1;
                }
                aspects.push_back(s.substr(start));
            }
        }
    }
    return aspects;
}

constexpr int PACKET_TYPE_ANNOUNCE = 0x01;
constexpr int HEADER_TYPE_2 = 0x01;
constexpr int CONTEXT_NONE = 0x00;
constexpr size_t DST_HASH_LEN = 16;

}  // namespace

REGISTER_COMMAND(announce_build, {
    auto private_key = bridge::hex_param(p, "private_key");
    if (private_key.size() != KEYSIZE)
        throw std::runtime_error("announce_build: private_key must be 64 bytes");
    std::string app_name = bridge::str_param(p, "app_name");
    auto aspects = parse_aspects(p);
    auto app_data = bridge::hex_param_or_empty(p, "app_data");
    bool enable_ratchets = p.contains("enable_ratchets") && !p["enable_ratchets"].is_null()
                               ? p["enable_ratchets"].get<bool>() : false;

    // Identity private key is x25519_priv(32) || ed25519_priv(32); the public
    // key is the matching x25519_pub(32) || ed25519_pub(32).
    bridge::Bytes x_priv(private_key.begin(), private_key.begin() + 32);
    bridge::Bytes ed_priv(private_key.begin() + 32, private_key.end());
    auto x_pub = from_rns(RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(x_priv))
                              ->public_key()->public_bytes());
    auto sk = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(ed_priv));
    auto ed_pub = from_rns(sk->public_key()->public_bytes());
    bridge::Bytes public_key;
    public_key.insert(public_key.end(), x_pub.begin(), x_pub.end());
    public_key.insert(public_key.end(), ed_pub.begin(), ed_pub.end());

    bridge::Bytes name_hash = compute_name_hash(app_name, aspects);
    bridge::Bytes dest_hash = compute_dest_hash(name_hash, public_key);

    // random_hash = 5 random bytes || 5-byte big-endian unix timestamp
    // (emission_ts pins the wall-clock value, as RNS embeds int(time()).
    int64_t timestamp;
    if (p.contains("emission_ts") && !p["emission_ts"].is_null())
        timestamp = p["emission_ts"].get<int64_t>();
    else
        timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
    bridge::Bytes random_hash(10);
    {
        std::random_device rd;
        for (int i = 0; i < 5; ++i) random_hash[i] = (uint8_t)(rd() & 0xFF);
        for (int i = 0; i < 5; ++i) random_hash[9 - i] = (uint8_t)((timestamp >> (i * 8)) & 0xFF);
    }

    // Optional ratchet = a fresh X25519 public key (32 bytes), exactly what
    // RNS embeds via Identity._ratchet_public_bytes.
    bridge::Bytes ratchet;
    if (enable_ratchets) {
        bridge::Bytes r_priv = bridge::random_bytes(32);
        ratchet = from_rns(RNS::Cryptography::X25519PrivateKey::from_private_bytes(to_rns(r_priv))
                               ->public_key()->public_bytes());
    }
    bool has_ratchet = !ratchet.empty();

    bridge::Bytes signed_data;
    signed_data.insert(signed_data.end(), dest_hash.begin(), dest_hash.end());
    signed_data.insert(signed_data.end(), public_key.begin(), public_key.end());
    signed_data.insert(signed_data.end(), name_hash.begin(), name_hash.end());
    signed_data.insert(signed_data.end(), random_hash.begin(), random_hash.end());
    signed_data.insert(signed_data.end(), ratchet.begin(), ratchet.end());
    signed_data.insert(signed_data.end(), app_data.begin(), app_data.end());

    auto sig = from_rns(sk->sign(to_rns(signed_data)));

    bridge::Bytes announce_data;
    announce_data.insert(announce_data.end(), public_key.begin(), public_key.end());
    announce_data.insert(announce_data.end(), name_hash.begin(), name_hash.end());
    announce_data.insert(announce_data.end(), random_hash.begin(), random_hash.end());
    announce_data.insert(announce_data.end(), ratchet.begin(), ratchet.end());
    announce_data.insert(announce_data.end(), sig.begin(), sig.end());
    announce_data.insert(announce_data.end(), app_data.begin(), app_data.end());

    // Full packet header: HEADER_1, BROADCAST, SINGLE, ANNOUNCE, context=NONE.
    int flags = ((has_ratchet ? 1 : 0) << 5) | PACKET_TYPE_ANNOUNCE;
    bridge::Bytes raw;
    raw.push_back((uint8_t)flags);
    raw.push_back(0);  // hops
    raw.insert(raw.end(), dest_hash.begin(), dest_hash.end());
    raw.push_back((uint8_t)CONTEXT_NONE);
    raw.insert(raw.end(), announce_data.begin(), announce_data.end());

    return bridge::json{
        {"raw", bridge::to_hex(raw)},
        {"destination_hash", bridge::to_hex(dest_hash)},
        {"announce_data", bridge::to_hex(announce_data)},
        {"public_key", bridge::to_hex(public_key)},
        {"name_hash", bridge::to_hex(name_hash)},
        {"random_hash", bridge::to_hex(random_hash)},
        {"ratchet", has_ratchet ? bridge::to_hex(ratchet) : std::string()},
        {"signature", bridge::to_hex(sig)},
        {"app_data", app_data.empty() ? std::string() : bridge::to_hex(app_data)},
        {"has_ratchet", has_ratchet},
    };
})

REGISTER_COMMAND(announce_validate, {
    bridge::Bytes raw = bridge::hex_param(p, "raw");
    try {
        if (raw.size() < 2)
            return bridge::json{{"valid", false}, {"error", "unpack_failed"}};

        uint8_t flags = raw[0];
        int header_type = (flags >> 6) & 0x01;
        int context_flag = (flags >> 5) & 0x01;
        int packet_type = flags & 0x03;

        size_t hdr_len = (header_type == HEADER_TYPE_2)
                             ? (2 + 2 * DST_HASH_LEN + 1)
                             : (2 + DST_HASH_LEN + 1);
        if (raw.size() < hdr_len)
            return bridge::json{{"valid", false}, {"error", "unpack_failed"}};

        bridge::Bytes destination_hash;
        size_t data_off;
        if (header_type == HEADER_TYPE_2) {
            destination_hash.assign(raw.begin() + 2 + DST_HASH_LEN,
                                    raw.begin() + 2 + 2 * DST_HASH_LEN);
            data_off = 2 + 2 * DST_HASH_LEN + 1;
        } else {
            destination_hash.assign(raw.begin() + 2, raw.begin() + 2 + DST_HASH_LEN);
            data_off = 2 + DST_HASH_LEN + 1;
        }

        if (packet_type != PACKET_TYPE_ANNOUNCE)
            return bridge::json{{"valid", false}, {"error", "not_an_announce"},
                                {"destination_hash", bridge::to_hex(destination_hash)}};

        bool has_ratchet = context_flag == 1;
        bridge::Bytes data(raw.begin() + data_off, raw.end());

        size_t rsz = has_ratchet ? RATCHET_SIZE : 0;
        size_t need = KEYSIZE + NAME_HASH_LEN + RANDOM_HASH_LEN + rsz + SIG_LEN;
        if (data.size() < need)
            return bridge::json{{"valid", false}, {"error", "body_too_short"},
                                {"destination_hash", bridge::to_hex(destination_hash)},
                                {"has_ratchet", has_ratchet}};

        size_t off = 0;
        bridge::Bytes public_key(data.begin() + off, data.begin() + off + KEYSIZE); off += KEYSIZE;
        bridge::Bytes name_hash(data.begin() + off, data.begin() + off + NAME_HASH_LEN); off += NAME_HASH_LEN;
        bridge::Bytes random_hash(data.begin() + off, data.begin() + off + RANDOM_HASH_LEN); off += RANDOM_HASH_LEN;
        bridge::Bytes ratchet;
        if (has_ratchet) { ratchet.assign(data.begin() + off, data.begin() + off + RATCHET_SIZE); off += RATCHET_SIZE; }
        bridge::Bytes signature(data.begin() + off, data.begin() + off + SIG_LEN); off += SIG_LEN;
        bridge::Bytes app_data(data.begin() + off, data.end());

        // signed_data = dest_hash || pubkey || name_hash || random_hash
        //               || ratchet || app_data  (RNS.Identity.validate_announce)
        bridge::Bytes signed_data;
        signed_data.insert(signed_data.end(), destination_hash.begin(), destination_hash.end());
        signed_data.insert(signed_data.end(), public_key.begin(), public_key.end());
        signed_data.insert(signed_data.end(), name_hash.begin(), name_hash.end());
        signed_data.insert(signed_data.end(), random_hash.begin(), random_hash.end());
        signed_data.insert(signed_data.end(), ratchet.begin(), ratchet.end());
        signed_data.insert(signed_data.end(), app_data.begin(), app_data.end());

        // Signature is verified against the ANNOUNCED Ed25519 public key.
        bridge::Bytes ed_pub(public_key.begin() + 32, public_key.end());
        bool sig_valid = false;
        try {
            auto vk = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(to_rns(ed_pub));
            sig_valid = vk->verify(to_rns(signature), to_rns(signed_data));
        } catch (...) { sig_valid = false; }

        // Independent dest-hash recompute (the second rejection branch).
        bridge::Bytes expected = compute_dest_hash(name_hash, public_key);
        bool dest_valid = (destination_hash == expected);

        bridge::json result = {
            {"valid", sig_valid && dest_valid},
            {"destination_hash", bridge::to_hex(destination_hash)},
            {"has_ratchet", has_ratchet},
        };
        if (has_ratchet) result["ratchet"] = bridge::to_hex(ratchet);
        return result;
    } catch (...) {
        return bridge::json{{"valid", false}, {"error", "unpack_failed"}};
    }
})

REGISTER_COMMAND(announce_queue_constants, {
    (void)p;
    // Read straight off the fork's own Reticulum constants (Type.h) — the
    // per-interface announce egress-queue ceiling, the queued-announce
    // lifetime, and the default announce-bandwidth cap percentage.
    return bridge::json{
        {"announce_cap", (int)RNS::Type::Reticulum::ANNOUNCE_CAP},
        {"max_queued_announces", (int)RNS::Type::Reticulum::MAX_QUEUED_ANNOUNCES},
        {"queued_announce_life", (int64_t)RNS::Type::Reticulum::QUEUED_ANNOUNCE_LIFE},
    };
})

REGISTER_COMMAND(auto_discovery_token, {
    // AutoInterface peer-auth token = full_hash(group_id || addr.utf8), exactly
    // as AutoInterface.discovery_handler computes it (RNS.Identity.full_hash ==
    // sha256). The bridge does no hashing of its own beyond the delegated
    // sha256 primitive.
    auto group_id = bridge::hex_param(p, "group_id");
    std::string addr = bridge::str_param(p, "link_local_addr");
    bridge::Bytes material(group_id);
    material.insert(material.end(), addr.begin(), addr.end());
    return bridge::json{{"token", bridge::to_hex(full_sha256(material))}};
})
