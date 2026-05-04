// Announce-related stateless commands.
//
// random_hash: 5 random bytes + 5-byte big-endian unix timestamp.

#include "../bridge.h"

#include <chrono>
#include <random>
#include <stdexcept>

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
