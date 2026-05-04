// HDLC + KISS framing commands.
//
// HDLC: FLAG=0x7E, ESC=0x7D, ESC_MASK=0x20.
//   0x7E -> 0x7D 0x5E
//   0x7D -> 0x7D 0x5D
// KISS: FEND=0xC0, FESC=0xDB, TFEND=0xDC, TFESC=0xDD.
//   0xC0 -> 0xDB 0xDC
//   0xDB -> 0xDB 0xDD
// Frame = FEND + command_byte + escaped + FEND.

#include "../bridge.h"

namespace {

constexpr uint8_t HDLC_FLAG = 0x7E;
constexpr uint8_t HDLC_ESC = 0x7D;
constexpr uint8_t HDLC_ESC_MASK = 0x20;

constexpr uint8_t KISS_FEND = 0xC0;
constexpr uint8_t KISS_FESC = 0xDB;
constexpr uint8_t KISS_TFEND = 0xDC;
constexpr uint8_t KISS_TFESC = 0xDD;
constexpr uint8_t KISS_CMD_DATA = 0x00;

bridge::Bytes hdlc_escape_bytes(const bridge::Bytes& data) {
    bridge::Bytes out;
    out.reserve(data.size());
    for (uint8_t b : data) {
        if (b == HDLC_ESC) {
            out.push_back(HDLC_ESC);
            out.push_back((uint8_t)(HDLC_ESC ^ HDLC_ESC_MASK));
        } else if (b == HDLC_FLAG) {
            out.push_back(HDLC_ESC);
            out.push_back((uint8_t)(HDLC_FLAG ^ HDLC_ESC_MASK));
        } else {
            out.push_back(b);
        }
    }
    return out;
}

bridge::Bytes kiss_escape_bytes(const bridge::Bytes& data) {
    bridge::Bytes out;
    out.reserve(data.size());
    for (uint8_t b : data) {
        if (b == KISS_FESC) {
            out.push_back(KISS_FESC);
            out.push_back(KISS_TFESC);
        } else if (b == KISS_FEND) {
            out.push_back(KISS_FESC);
            out.push_back(KISS_TFEND);
        } else {
            out.push_back(b);
        }
    }
    return out;
}

}  // namespace

REGISTER_COMMAND(hdlc_escape, {
    auto data = bridge::hex_param(p, "data");
    return bridge::json{{"escaped", bridge::to_hex(hdlc_escape_bytes(data))}};
})

REGISTER_COMMAND(hdlc_frame, {
    auto data = bridge::hex_param(p, "data");
    auto escaped = hdlc_escape_bytes(data);
    bridge::Bytes framed;
    framed.reserve(escaped.size() + 2);
    framed.push_back(HDLC_FLAG);
    framed.insert(framed.end(), escaped.begin(), escaped.end());
    framed.push_back(HDLC_FLAG);
    return bridge::json{
        {"framed", bridge::to_hex(framed)},
        {"escaped", bridge::to_hex(escaped)},
    };
})

REGISTER_COMMAND(kiss_escape, {
    auto data = bridge::hex_param(p, "data");
    return bridge::json{{"escaped", bridge::to_hex(kiss_escape_bytes(data))}};
})

REGISTER_COMMAND(kiss_frame, {
    auto data = bridge::hex_param(p, "data");
    int command = (p.contains("command") && !p["command"].is_null())
                      ? p["command"].get<int>()
                      : KISS_CMD_DATA;
    auto escaped = kiss_escape_bytes(data);
    bridge::Bytes framed;
    framed.reserve(escaped.size() + 3);
    framed.push_back(KISS_FEND);
    framed.push_back((uint8_t)command);
    framed.insert(framed.end(), escaped.begin(), escaped.end());
    framed.push_back(KISS_FEND);
    return bridge::json{
        {"framed", bridge::to_hex(framed)},
        {"escaped", bridge::to_hex(escaped)},
    };
})
