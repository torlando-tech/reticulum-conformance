// IFAC (Interface Access Code) commands.
//
// IFAC_SALT is a fixed 32-byte constant from RNS. ifac_key = HKDF over
// (passphrase, salt=IFAC_SALT) → 64 bytes. ifac tag = last N bytes of
// Ed25519 signature of packet_data with the second half of ifac_key.

#include "../bridge.h"

#include "Bytes.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/Ed25519.h"

#include <cstring>
#include <stdexcept>

namespace {

inline RNS::Bytes to_rns(const bridge::Bytes& v) {
    return RNS::Bytes(v.data(), v.size());
}
inline bridge::Bytes from_rns(const RNS::Bytes& b) {
    return bridge::Bytes(b.data(), b.data() + b.size());
}

const bridge::Bytes IFAC_SALT = bridge::from_hex(
    "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
);

bridge::Bytes ed25519_sign(const bridge::Bytes& priv, const bridge::Bytes& message) {
    auto sk = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(to_rns(priv));
    return from_rns(sk->sign(to_rns(message)));
}

bridge::Bytes hkdf_expand(int length, const bridge::Bytes& ikm,
                          const bridge::Bytes& salt, const bridge::Bytes& info) {
    // Mirror the same guard the `hkdf` command handler applies: a negative
    // int silently wraps to a huge size_t when cast, asking HKDF to
    // allocate exabytes. Today's call sites pass result.size() / masked.size()
    // (always non-negative) but defending the helper costs nothing.
    if (length <= 0) {
        throw std::runtime_error("hkdf_expand: length must be positive");
    }
    return from_rns(RNS::Cryptography::hkdf(
        (size_t)length, to_rns(ikm), to_rns(salt), to_rns(info)));
}

}  // namespace

REGISTER_COMMAND(ifac_derive_key, {
    auto origin = bridge::hex_param(p, "ifac_origin");
    auto key = hkdf_expand(64, origin, IFAC_SALT, bridge::Bytes());
    return bridge::json{
        {"ifac_key", bridge::to_hex(key)},
        {"ifac_salt", bridge::to_hex(IFAC_SALT)},
    };
})

REGISTER_COMMAND(ifac_compute, {
    auto ifac_key = bridge::hex_param(p, "ifac_key");
    auto packet_data = bridge::hex_param(p, "packet_data");
    int ifac_size = (p.contains("ifac_size") && !p["ifac_size"].is_null())
                       ? p["ifac_size"].get<int>() : 16;
    if (ifac_key.size() != 64) {
        throw std::runtime_error("ifac_compute: ifac_key must be 64 bytes");
    }
    if (ifac_size <= 0) {
        throw std::runtime_error("ifac_compute: ifac_size must be positive");
    }
    bridge::Bytes ed_key(ifac_key.begin() + 32, ifac_key.end());
    auto sig = ed25519_sign(ed_key, packet_data);
    if ((int)sig.size() < ifac_size) {
        throw std::runtime_error("ifac_compute: signature shorter than ifac_size");
    }
    bridge::Bytes ifac(sig.end() - ifac_size, sig.end());
    return bridge::json{
        {"ifac", bridge::to_hex(ifac)},
        {"signature", bridge::to_hex(sig)},
    };
})

REGISTER_COMMAND(ifac_verify, {
    auto ifac_key = bridge::hex_param(p, "ifac_key");
    auto packet_data = bridge::hex_param(p, "packet_data");
    auto expected = bridge::hex_param(p, "expected_ifac");
    if (ifac_key.size() != 64) {
        throw std::runtime_error("ifac_verify: ifac_key must be 64 bytes");
    }
    bridge::Bytes ed_key(ifac_key.begin() + 32, ifac_key.end());
    auto sig = ed25519_sign(ed_key, packet_data);
    if (expected.size() > sig.size()) {
        // expected_ifac longer than the underlying Ed25519 signature (64
        // bytes) — pointer arithmetic below would underflow. Reject as
        // invalid IFAC rather than triggering UB.
        return bridge::json{{"valid", false}};
    }
    bridge::Bytes computed(sig.end() - (ptrdiff_t)expected.size(), sig.end());
    bool ok = computed.size() == expected.size()
              && bridge::consttime_memequal(computed.data(), expected.data(), expected.size());
    return bridge::json{{"valid", ok}};
})

// IFAC mask/unmask: apply a HKDF-derived XOR mask over packet bytes (header
// + payload, NOT the IFAC bytes themselves). Set/clear the IFAC flag (0x80
// on flags byte 0). On the wire: [flags|0x80][hops][ifac][rest...].
REGISTER_COMMAND(ifac_mask_packet, {
    auto ifac_key = bridge::hex_param(p, "ifac_key");
    auto raw = bridge::hex_param(p, "packet_data");
    int ifac_size = (p.contains("ifac_size") && !p["ifac_size"].is_null())
                       ? p["ifac_size"].get<int>() : 16;
    if (ifac_key.size() != 64) {
        throw std::runtime_error("ifac_mask_packet: ifac_key must be 64 bytes");
    }
    if (raw.size() < 2) {
        throw std::runtime_error("ifac_mask_packet: packet too short");
    }
    if (ifac_size <= 0) {
        throw std::runtime_error("ifac_mask_packet: ifac_size must be positive");
    }

    // Compute IFAC tag over original packet data.
    bridge::Bytes ed_key(ifac_key.begin() + 32, ifac_key.end());
    auto sig = ed25519_sign(ed_key, raw);
    if ((size_t)ifac_size > sig.size()) {
        // ifac_size larger than the underlying Ed25519 signature (64 bytes)
        // — guard against pointer underflow / UB.
        throw std::runtime_error("ifac_mask_packet: ifac_size exceeds signature length");
    }
    bridge::Bytes ifac(sig.end() - ifac_size, sig.end());

    // Build result: [flags|0x80][hops][ifac][rest...]
    bridge::Bytes result;
    result.push_back((uint8_t)(raw[0] | 0x80));
    result.push_back(raw[1]);
    result.insert(result.end(), ifac.begin(), ifac.end());
    result.insert(result.end(), raw.begin() + 2, raw.end());

    // Generate XOR mask via HKDF(ikm=ifac, salt=ifac_key) over result length.
    auto mask = hkdf_expand((int)result.size(), ifac, ifac_key, bridge::Bytes());

    // Apply mask EXCEPT to the IFAC bytes (which are at offset 2..2+ifac_size).
    for (size_t i = 0; i < result.size(); ++i) {
        bool in_ifac = (i >= 2 && i < (size_t)(2 + ifac_size));
        if (!in_ifac) result[i] ^= mask[i];
    }

    return bridge::json{
        {"masked_packet", bridge::to_hex(result)},
        {"ifac", bridge::to_hex(ifac)},
    };
})

REGISTER_COMMAND(ifac_unmask_packet, {
    auto ifac_key = bridge::hex_param(p, "ifac_key");
    auto masked = bridge::hex_param(p, "packet_data");
    int ifac_size = (p.contains("ifac_size") && !p["ifac_size"].is_null())
                       ? p["ifac_size"].get<int>() : 16;
    if (ifac_key.size() != 64) {
        throw std::runtime_error("ifac_unmask_packet: ifac_key must be 64 bytes");
    }
    if (ifac_size <= 0) {
        return bridge::json{{"valid", false}, {"unmasked", ""}};
    }
    if (masked.size() < (size_t)(2 + ifac_size)) {
        return bridge::json{{"valid", false}, {"unmasked", ""}};
    }
    if ((masked[0] & 0x80) == 0) {
        return bridge::json{{"valid", false}, {"unmasked", ""}};
    }

    bridge::Bytes ifac(masked.begin() + 2, masked.begin() + 2 + ifac_size);
    auto mask = hkdf_expand((int)masked.size(), ifac, ifac_key, bridge::Bytes());

    bridge::Bytes unmasked = masked;
    for (size_t i = 0; i < unmasked.size(); ++i) {
        bool in_ifac = (i >= 2 && i < (size_t)(2 + ifac_size));
        if (!in_ifac) unmasked[i] ^= mask[i];
    }

    // Strip IFAC from byte 2 onwards, clear the IFAC flag.
    bridge::Bytes original;
    original.push_back((uint8_t)(unmasked[0] & 0x7F));
    original.push_back(unmasked[1]);
    original.insert(original.end(), unmasked.begin() + 2 + ifac_size, unmasked.end());

    // Recompute expected IFAC over original packet data and compare.
    bridge::Bytes ed_key(ifac_key.begin() + 32, ifac_key.end());
    auto sig = ed25519_sign(ed_key, original);
    if ((size_t)ifac_size > sig.size()) {
        // ifac_size > Ed25519 signature length (64) — would underflow
        // the sig.end() - ifac_size arithmetic. Reject as invalid.
        return bridge::json{{"valid", false}, {"unmasked_packet", bridge::to_hex(original)}, {"ifac", bridge::to_hex(ifac)}};
    }
    bridge::Bytes expected(sig.end() - ifac_size, sig.end());
    bool ok = expected.size() == ifac.size()
              && bridge::consttime_memequal(expected.data(), ifac.data(), ifac_size);

    return bridge::json{
        {"valid", ok},
        {"unmasked_packet", bridge::to_hex(original)},
        {"ifac", bridge::to_hex(ifac)},
    };
})
