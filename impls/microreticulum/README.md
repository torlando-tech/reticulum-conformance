# microReticulum conformance bridge

C++ bridge program that drives the [microReticulum](https://github.com/attermann/microReticulum) implementation through the reticulum-conformance JSON-RPC stdio protocol. Wraps microReticulum's `RNS::Cryptography::*` namespace plus hand-written wire-format codecs.

## Build

```bash
cmake -B build
cmake --build build --parallel
```

By default builds against `~/repos/pyxis/deps/microReticulum` (pyxis's pinned `feat/t-deck` fork). Override with `-DMICRORETICULUM_DIR=/path/to/microReticulum`.

The build vendors `attermann/Crypto` (rweather fork) and `bblanchon/ArduinoJson` via FetchContent, plus `nlohmann/json` (single-header in `src/json.hpp`).

## Run

```bash
CONFORMANCE_MICRORETICULUM_BRIDGE_CMD=$PWD/build/microReticulumBridge \
  pytest ~/repos/reticulum-conformance/tests/ --impl microreticulum -v
```

## Status (2026-05-03)

**53/85 top-level conformance tests pass** (62%). Skipping `tests/wire`, `tests/behavioral`, `tests/lxmf` — those need Tier 2B (transport layer) work.

| Category | Pass | Notes |
|---|---|---|
| Crypto (15) | 13 | hkdf_with_info, aes_encrypt_decrypt fail. PKCS7 + HMAC bugs in microReticulum surfaced. |
| Identity (4) | 3 | identity_encrypt_decrypt fails (downstream of PKCS7 bug). |
| Token (3) | 2 | token_cross_decrypt fails. |
| Destination (4) | 4 | All pass. |
| Packet (6) | 6 | All pass. |
| Framing (6) | 6 | All pass. |
| Announce (3) | 1 | random_hash passes; pack/unpack/verify need msgpack (Tier 2B). |
| Link (7) | 4 | derive_key, signalling, parse_signalling, id_from_packet pass. encrypt/decrypt + rtt + request need msgpack. |
| Resource (6) | 5 | hash, flags_encode/decode, map_hash, build_hashmap, proof — `resource_proof` fails. |
| Ratchet (4) | 0 | Not yet implemented. |
| Channel (2) | 0 | Need msgpack. |
| Transport (4+) | varies | path_request, packet_hashlist need msgpack; ifac_* now mostly working. |
| Compression (3) | 0 | bz2 not built into bridge. |
| LXMF (3) | 0 | Need full LXMF impl. |

## Bugs found in microReticulum (worked around in bridge)

1. **`Cryptography::PKCS7::pad`** — fills pad buffer with zeros and only sets last byte to padlen. Standard PKCS7 fills entire pad with the padlen value.
2. **`Cryptography::digest()` (HMAC.h:103)** — calls `update(msg)` after the `HMAC` constructor already consumed `msg`. Result: message HMAC'd twice.

Both have spec-correct workarounds in `src/bridge.cpp` (`pkcs7_pad`/`pkcs7_unpad`/`hmac_sha256` helpers). Upstream fix needed for code that uses `RNS::Cryptography::PKCS7::pad` or `digest()` directly.

## Phase boundaries

- **Tier 2A (this bridge)**: stateless primitives — pack/unpack, crypto, framing.
- **Tier 2B (deferred)**: TCP transport, link state machine, channel, resource transfer, msgpack-dependent commands.
- **Tier 3 (deferred)**: LXMF bridge for `lxmf-conformance`.

See `~/Documents/Obsidian/columba-vault/80 Assistant/Memory/pyxis/pyxis_microReticulum_testing_plan.md` for the full plan.
