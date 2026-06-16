// Transport-layer stateless commands.
//
// path_request_pack/unpack: a path request body is a flat concatenation
//   destination_hash [|| transport_instance(16)] [|| tag(10)]
// (msgpack-based path table serialisation lives in Tier 2B and is not here).

#include "../bridge.h"

#include <stdexcept>

namespace {
constexpr size_t DST_LEN = 16;
constexpr size_t TAG_LEN = 10;
}  // namespace

REGISTER_COMMAND(path_request_pack, {
    auto destination_hash = bridge::hex_param(p, "destination_hash");
    auto transport_instance = bridge::hex_param_or_empty(p, "transport_instance");
    auto tag = bridge::hex_param_or_empty(p, "tag");

    bridge::Bytes data = destination_hash;
    if (!transport_instance.empty()) {
        data.insert(data.end(), transport_instance.begin(), transport_instance.end());
    }
    if (!tag.empty()) {
        data.insert(data.end(), tag.begin(), tag.end());
    }

    return bridge::json{
        {"data", bridge::to_hex(data)},
        {"has_transport_instance", !transport_instance.empty()},
        {"has_tag", !tag.empty()},
    };
})

REGISTER_COMMAND(path_request_unpack, {
    auto data = bridge::hex_param(p, "data");
    if (data.size() < DST_LEN) {
        throw std::runtime_error("path_request_unpack: data too short for destination hash");
    }
    bridge::Bytes destination_hash(data.begin(), data.begin() + DST_LEN);
    bridge::Bytes remaining(data.begin() + DST_LEN, data.end());

    bridge::json result = {{"destination_hash", bridge::to_hex(destination_hash)}};

    // Mirror reference heuristic: a 16-byte chunk is a transport instance,
    // then a trailing 10-byte chunk is the tag.
    if (remaining.size() >= DST_LEN) {
        bridge::Bytes transport_instance(remaining.begin(), remaining.begin() + DST_LEN);
        result["transport_instance"] = bridge::to_hex(transport_instance);
        bridge::Bytes rest(remaining.begin() + DST_LEN, remaining.end());
        if (rest.size() >= TAG_LEN) {
            result["tag"] = bridge::to_hex(bridge::Bytes(rest.begin(), rest.begin() + TAG_LEN));
        }
    } else if (remaining.size() >= TAG_LEN) {
        result["tag"] = bridge::to_hex(bridge::Bytes(remaining.begin(), remaining.begin() + TAG_LEN));
    }

    return result;
})
