// HDLC + KISS framing commands.
//
// HDLC: FLAG=0x7E, ESC=0x7D, ESC_MASK=0x20.
//   0x7E -> 0x7D 0x5E
//   0x7D -> 0x7D 0x5D
// KISS: FEND=0xC0, FESC=0xDB, TFEND=0xDC, TFESC=0xDD.
//   0xC0 -> 0xDB 0xDC
//   0xDB -> 0xDB 0xDD
// Frame = FEND + command_byte + escaped + FEND.
//
// The *_deframe / *_deframe_stream commands are the exact inverse of the
// send-side codecs above. RNS exposes no standalone HDLC/KISS de-escape entry
// point — the receive logic is inlined in each interface's read loop — and the
// microReticulum fork ships no Interfaces/TCPInterface at all, so (matching the
// reference bridge, reference/bridge_server.py) there is nothing to delegate
// to: these mirror the precise byte replacements RNS performs.
//   - *_deframe       : single-frame un-stuffing between the first two delimiters
//                       (TCPInterface.py cmd_hdlc_deframe / cmd_kiss_deframe).
//   - *_deframe_stream : the full read_loop — FLAG/FEND scan with shared-delimiter
//                       buffer retention, the HDLC `len(frame) > HEADER_MINSIZE`
//                       (19) runt drop, the KISS leading port-nibble strip
//                       (command = byte & 0x0F), the KISS per-byte HW_MTU cap and
//                       the non-CMD_DATA ignore (TCPInterface.py read_loop).

#include "../bridge.h"

#include <cstddef>
#include <stdexcept>

namespace {

constexpr uint8_t HDLC_FLAG = 0x7E;
constexpr uint8_t HDLC_ESC = 0x7D;
constexpr uint8_t HDLC_ESC_MASK = 0x20;

constexpr uint8_t KISS_FEND = 0xC0;
constexpr uint8_t KISS_FESC = 0xDB;
constexpr uint8_t KISS_TFEND = 0xDC;
constexpr uint8_t KISS_TFESC = 0xDD;
constexpr uint8_t KISS_CMD_DATA = 0x00;
constexpr uint8_t KISS_CMD_UNKNOWN = 0xFE;

// RNS.Reticulum.HEADER_MINSIZE — the HDLC read loop drops any de-stuffed frame
// whose length is NOT > this value (frames of 0..19 bytes are runts).
constexpr size_t RNS_HEADER_MINSIZE = 19;

constexpr size_t SENTINEL = static_cast<size_t>(-1);

// Index of the first occurrence of `needle` in `data` at or after `from`, or
// SENTINEL if absent — mirrors Python bytes.find(byte, start).
size_t find_byte(const bridge::Bytes& data, uint8_t needle, size_t from = 0) {
    for (size_t i = from; i < data.size(); ++i) {
        if (data[i] == needle) return i;
    }
    return SENTINEL;
}

// Non-overlapping left-to-right replacement of the two-byte sequence {a, b} with
// the single byte `repl`, exactly like Python bytes.replace: each full .replace()
// is one independent pass and replacement output is NOT re-scanned within it.
bridge::Bytes replace_seq(const bridge::Bytes& in, uint8_t a, uint8_t b, uint8_t repl) {
    bridge::Bytes out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        if (i + 1 < in.size() && in[i] == a && in[i + 1] == b) {
            out.push_back(repl);
            i += 2;
        } else {
            out.push_back(in[i]);
            i += 1;
        }
    }
    return out;
}

// Reverse HDLC byte-stuffing: ESC+(FLAG^MASK) -> FLAG, then ESC+(ESC^MASK) -> ESC
// (the exact two replacements RNS's TCP read loop performs, in order).
bridge::Bytes hdlc_deescape(const bridge::Bytes& frame) {
    bridge::Bytes f =
        replace_seq(frame, HDLC_ESC, (uint8_t)(HDLC_FLAG ^ HDLC_ESC_MASK), HDLC_FLAG);
    return replace_seq(f, HDLC_ESC, (uint8_t)(HDLC_ESC ^ HDLC_ESC_MASK), HDLC_ESC);
}

// Reverse the KISS transpose: FESC+TFEND -> FEND, then FESC+TFESC -> FESC.
bridge::Bytes kiss_deescape(const bridge::Bytes& payload) {
    bridge::Bytes f = replace_seq(payload, KISS_FESC, KISS_TFEND, KISS_FEND);
    return replace_seq(f, KISS_FESC, KISS_TFESC, KISS_FESC);
}

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

// Strip HDLC framing (FLAG + HDLC.escape(data) + FLAG) and reverse the byte-
// stuffing. Extracts the bytes between the first two FLAG (0x7E) delimiters —
// leading non-FLAG garbage is skipped — then un-stuffs. Inverse of hdlc_frame.
REGISTER_COMMAND(hdlc_deframe, {
    auto framed = bridge::hex_param(p, "framed");
    size_t start = find_byte(framed, HDLC_FLAG);
    if (start == SENTINEL)
        throw std::runtime_error(
            "hdlc_deframe: no HDLC FLAG (0x7E) delimiter found in framed input");
    size_t end = find_byte(framed, HDLC_FLAG, start + 1);
    if (end == SENTINEL)
        throw std::runtime_error(
            "hdlc_deframe: unterminated HDLC frame: only one FLAG delimiter");
    bridge::Bytes frame(framed.begin() + start + 1, framed.begin() + end);
    return bridge::json{{"data", bridge::to_hex(hdlc_deescape(frame))}};
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

// Strip KISS framing (FEND + CMD_DATA + KISS.escape(data) + FEND) and reverse
// the transpose. Extracts the bytes between the first two FEND (0xC0) delimiters
// — leading non-FEND garbage is skipped — verifies the leading command byte is
// CMD_DATA (0x00), then un-transposes the payload. Inverse of kiss_frame.
REGISTER_COMMAND(kiss_deframe, {
    auto framed = bridge::hex_param(p, "framed");
    size_t start = find_byte(framed, KISS_FEND);
    if (start == SENTINEL)
        throw std::runtime_error(
            "kiss_deframe: no KISS FEND (0xC0) delimiter found in framed input");
    size_t end = find_byte(framed, KISS_FEND, start + 1);
    if (end == SENTINEL)
        throw std::runtime_error(
            "kiss_deframe: unterminated KISS frame: only one FEND delimiter");
    bridge::Bytes inner(framed.begin() + start + 1, framed.begin() + end);
    if (inner.empty())
        throw std::runtime_error("kiss_deframe: empty KISS frame: no command byte");
    if (inner[0] != KISS_CMD_DATA)
        throw std::runtime_error(
            "kiss_deframe: unexpected KISS command byte, expected CMD_DATA (0x00)");
    bridge::Bytes payload(inner.begin() + 1, inner.end());
    return bridge::json{{"data", bridge::to_hex(kiss_deescape(payload))}};
})

// Deframe a TCP/HDLC byte stream exactly as RNS's read_loop standard-HDLC path
// (TCPInterface.py:380-398): repeatedly slice between FLAG delimiters with the
// closing FLAG retained as the next frame's opener (shared-FLAG buffer
// retention), un-stuff, and drop any frame whose length is not > HEADER_MINSIZE
// (19). HW_MTU does not gate the HDLC path, so `hw_mtu` is accepted but unused.
REGISTER_COMMAND(hdlc_deframe_stream, {
    auto frame_buffer = bridge::hex_param(p, "stream");
    bridge::json frames = bridge::json::array();
    bool flags_remaining = true;
    while (flags_remaining) {
        size_t frame_start = find_byte(frame_buffer, HDLC_FLAG);
        if (frame_start != SENTINEL) {
            size_t frame_end = find_byte(frame_buffer, HDLC_FLAG, frame_start + 1);
            if (frame_end != SENTINEL) {
                bridge::Bytes frame(frame_buffer.begin() + frame_start + 1,
                                    frame_buffer.begin() + frame_end);
                frame = hdlc_deescape(frame);
                if (frame.size() > RNS_HEADER_MINSIZE)
                    frames.push_back(bridge::to_hex(frame));
                // Retain the closing FLAG as the next opener.
                frame_buffer = bridge::Bytes(frame_buffer.begin() + frame_end,
                                             frame_buffer.end());
            } else {
                flags_remaining = false;
            }
        } else {
            flags_remaining = false;
        }
    }
    return bridge::json{{"frames", frames}};
})

// Deframe a TCP/KISS byte stream exactly as RNS's read_loop kiss_framing path
// (TCPInterface.py:351-378): FEND opens/closes frames; the first in-frame byte's
// port nibble is stripped (command = byte & 0x0F) so 0x10/0x20 are accepted as
// CMD_DATA; frames whose command != CMD_DATA are silently ignored; in-frame
// bytes are appended only while len(data_buffer) < HW_MTU (per-byte cap), with
// FESC/TFEND/TFESC transpose reversed inline.
REGISTER_COMMAND(kiss_deframe_stream, {
    auto data_in = bridge::hex_param(p, "stream");
    size_t hw_mtu = (p.contains("hw_mtu") && !p["hw_mtu"].is_null())
                        ? p["hw_mtu"].get<size_t>()
                        : 262144;
    bridge::json frames = bridge::json::array();
    bool in_frame = false;
    bool escape = false;
    uint8_t command = KISS_CMD_UNKNOWN;
    bridge::Bytes data_buffer;
    for (size_t pointer = 0; pointer < data_in.size(); ++pointer) {
        uint8_t byte = data_in[pointer];
        if (in_frame && byte == KISS_FEND && command == KISS_CMD_DATA) {
            in_frame = false;
            frames.push_back(bridge::to_hex(data_buffer));
        } else if (byte == KISS_FEND) {
            in_frame = true;
            command = KISS_CMD_UNKNOWN;
            data_buffer.clear();
        } else if (in_frame && data_buffer.size() < hw_mtu) {
            if (data_buffer.empty() && command == KISS_CMD_UNKNOWN) {
                // One HDLC port only: strip the port nibble.
                byte = byte & 0x0F;
                command = byte;
            } else if (command == KISS_CMD_DATA) {
                if (byte == KISS_FESC) {
                    escape = true;
                } else {
                    if (escape) {
                        if (byte == KISS_TFEND) byte = KISS_FEND;
                        if (byte == KISS_TFESC) byte = KISS_FESC;
                        escape = false;
                    }
                    data_buffer.push_back(byte);
                }
            }
        }
    }
    return bridge::json{{"frames", frames}};
})
