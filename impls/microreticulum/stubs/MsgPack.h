// Minimal MsgPack stub for the conformance bridge.
//
// Bytes.h forward-declares `arduino::msgpack::Packer` and aliases it as
// `MsgPack`. Bytes.cpp's `to_msgpack(MsgPack::Packer&)` implementation calls
// `packer.pack(data(), size())`. We never invoke this from the bridge
// (Phase 2A is stateless primitives), so a stub Packer with no-op `pack()`
// is enough to make linking succeed.
//
// Tier 2B (transport-level conformance) will need the real MsgPack library.
#pragma once

#include <cstddef>
#include <cstdint>

namespace arduino {
namespace msgpack {

class Packer {
public:
    void pack(const uint8_t*, std::size_t) {}
    void pack(const void*, std::size_t) {}
};

}  // namespace msgpack
}  // namespace arduino
