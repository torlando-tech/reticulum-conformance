// Channel framing commands. Pure big-endian struct juggling — no msgpack.
//
// envelope:  [msgtype:2][sequence:2][length:2][data:N]   (all big-endian)
// stream msg: [header:2][data:N] where header =
//             (eof?0x8000) | (compressed?0x4000) | (stream_id & 0x3FFF)

#include "../bridge.h"

#include <stdexcept>

REGISTER_COMMAND(envelope_pack, {
    int msgtype = bridge::int_param(p, "msgtype");
    int sequence = bridge::int_param(p, "sequence");
    auto data = bridge::hex_param_or_empty(p, "data");
    int length = (int)data.size();

    bridge::Bytes env;
    env.push_back((uint8_t)((msgtype >> 8) & 0xFF));
    env.push_back((uint8_t)(msgtype & 0xFF));
    env.push_back((uint8_t)((sequence >> 8) & 0xFF));
    env.push_back((uint8_t)(sequence & 0xFF));
    env.push_back((uint8_t)((length >> 8) & 0xFF));
    env.push_back((uint8_t)(length & 0xFF));
    env.insert(env.end(), data.begin(), data.end());

    return bridge::json{
        {"envelope", bridge::to_hex(env)},
        {"msgtype", msgtype},
        {"sequence", sequence},
        {"length", length},
    };
})

REGISTER_COMMAND(envelope_unpack, {
    auto env = bridge::hex_param(p, "envelope");
    if (env.size() < 6) throw std::runtime_error("envelope_unpack: envelope too short");
    int msgtype = (env[0] << 8) | env[1];
    int sequence = (env[2] << 8) | env[3];
    int length = (env[4] << 8) | env[5];
    bridge::Bytes data(env.begin() + 6, env.end());
    return bridge::json{
        {"msgtype", msgtype},
        {"sequence", sequence},
        {"length", length},
        {"data", bridge::to_hex(data)},
    };
})

REGISTER_COMMAND(stream_msg_pack, {
    int stream_id = bridge::int_param(p, "stream_id");
    auto data = bridge::hex_param_or_empty(p, "data");
    bool eof = p.contains("eof") && !p["eof"].is_null() ? p["eof"].get<bool>() : false;
    bool compressed = p.contains("compressed") && !p["compressed"].is_null()
                          ? p["compressed"].get<bool>() : false;
    if (stream_id < 0 || stream_id > 0x3FFF) {
        throw std::runtime_error("stream_msg_pack: stream_id must be 0-16383");
    }

    int header_val = stream_id & 0x3FFF;
    if (eof) header_val |= 0x8000;
    if (compressed) header_val |= 0x4000;

    bridge::Bytes msg;
    msg.push_back((uint8_t)((header_val >> 8) & 0xFF));
    msg.push_back((uint8_t)(header_val & 0xFF));
    msg.insert(msg.end(), data.begin(), data.end());

    return bridge::json{
        {"message", bridge::to_hex(msg)},
        {"header_val", header_val},
        {"stream_id", stream_id},
        {"eof", eof},
        {"compressed", compressed},
    };
})

REGISTER_COMMAND(stream_msg_unpack, {
    auto msg = bridge::hex_param(p, "message");
    if (msg.size() < 2) throw std::runtime_error("stream_msg_unpack: message too short");
    int header_val = (msg[0] << 8) | msg[1];
    int stream_id = header_val & 0x3FFF;
    bool eof = (header_val & 0x8000) != 0;
    bool compressed = (header_val & 0x4000) != 0;
    bridge::Bytes data(msg.begin() + 2, msg.end());
    return bridge::json{
        {"stream_id", stream_id},
        {"eof", eof},
        {"compressed", compressed},
        {"data", bridge::to_hex(data)},
        {"header_val", header_val},
    };
})
