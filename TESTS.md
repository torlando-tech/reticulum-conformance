# Conformance Test Cases

70 test cases across 14 categories. Each test compares the system under test (SUT) against the Python reference implementation (RNS/LXMF) to verify byte-level conformance.

All binary data is hex-encoded in the bridge protocol. Tests use randomized inputs on each run.

---

## 1. Cryptographic Primitives (15 tests)

**File:** `tests/test_crypto.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 1 | `test_sha256` | `sha256` | SHA-256 hash of 64 random bytes matches |
| 2 | `test_sha512` | `sha512` | SHA-512 hash of 64 random bytes matches |
| 3 | `test_hmac_sha256` | `hmac_sha256` | HMAC-SHA256 with 32-byte key and 48-byte message matches |
| 4 | `test_truncated_hash` | `truncated_hash` | Truncated hash (first 16 bytes of SHA-256) matches |
| 5 | `test_hkdf` | `hkdf` | HKDF with salt, 64-byte output matches |
| 6 | `test_hkdf_no_salt` | `hkdf` | HKDF without salt, 32-byte output matches |
| 7 | `test_hkdf_with_info` | `hkdf` | HKDF with salt and info context, 48-byte output matches |
| 8 | `test_aes_encrypt_decrypt` | `aes_encrypt`, `aes_decrypt` | AES-256-CBC encrypt produces identical ciphertext; decrypt recovers original plaintext |
| 9 | `test_pkcs7_pad_unpad` | `pkcs7_pad`, `pkcs7_unpad` | PKCS7 padding of non-aligned data matches; unpadding recovers original |
| 10 | `test_x25519_generate` | `x25519_generate` | X25519 keypair from deterministic seed produces same public key |
| 11 | `test_x25519_public_from_private` | `x25519_generate`, `x25519_public_from_private` | Deriving public key from private key matches |
| 12 | `test_x25519_exchange` | `x25519_generate`, `x25519_exchange` | ECDH shared secret between two keypairs matches |
| 13 | `test_ed25519_generate` | `ed25519_generate` | Ed25519 keypair from deterministic seed produces same public key |
| 14 | `test_ed25519_sign_verify` | `ed25519_generate`, `ed25519_sign`, `ed25519_verify` | Deterministic Ed25519 signature matches; both impls verify the signature as valid |
| 15 | `test_ed25519_verify_bad_sig` | `ed25519_generate`, `ed25519_verify` | Both impls reject a random (invalid) signature |

## 2. Identity (4 tests)

**File:** `tests/test_identity.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 16 | `test_identity_from_private_key` | `identity_from_private_key` | 64-byte private key (32B enc + 32B sig) produces same public key, hash, and hexhash |
| 17 | `test_identity_hash` | `identity_from_private_key`, `identity_hash` | Identity hash (truncated hash of public keys) matches |
| 18 | `test_identity_sign_verify` | `identity_sign`, `identity_from_private_key`, `identity_verify` | Identity signature matches; both impls verify as valid |
| 19 | `test_identity_encrypt_decrypt` | `identity_from_private_key`, `identity_encrypt`, `identity_decrypt` | Cross-implementation: encrypt with reference, decrypt with SUT; encrypt with SUT, decrypt with reference. Both recover original plaintext |

## 3. Token Encryption (3 tests)

**File:** `tests/test_token.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 20 | `test_token_encrypt_decrypt` | `token_encrypt`, `token_decrypt` | Token encryption (AES-256-CBC + HMAC-SHA256) with explicit IV produces identical token; both impls decrypt to original plaintext |
| 21 | `test_token_verify_hmac` | `token_encrypt`, `token_verify_hmac` | Both impls verify the HMAC on a token as valid |
| 22 | `test_token_cross_decrypt` | `token_encrypt`, `token_decrypt` | Cross-implementation: SUT-encrypted token decrypted by reference; reference-encrypted token decrypted by SUT |

## 4. Destination (4 tests)

**File:** `tests/test_destination.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 23 | `test_name_hash` | `name_hash` | Name hash of `"lxmf.delivery"` (10-byte truncated SHA-256 of full name) matches |
| 24 | `test_name_hash_single_aspect` | `name_hash` | Name hash of `"nomadnetwork.node"` matches |
| 25 | `test_destination_hash` | `identity_from_private_key`, `destination_hash` | Destination hash (truncated hash of name_hash + identity_hash) matches, including name_hash output |
| 26 | `test_packet_hash` | `packet_pack`, `packet_hash` | Full packet hash (SHA-256 of hashable part with masked flags) and hashable_part both match |

## 5. Packet (6 tests)

**File:** `tests/test_packet.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 27 | `test_packet_flags` | `packet_flags` | Flag byte encoding for a basic DATA packet (all zeros) matches |
| 28 | `test_packet_flags_announce` | `packet_flags` | Flag byte encoding for an ANNOUNCE packet (context_flag=1, packet_type=1) matches |
| 29 | `test_packet_parse_flags` | `packet_parse_flags` | Decoding 5 different flag bytes (0x00, 0x21, 0x41, 0x15, 0x7F) into header_type, context_flag, transport_type, destination_type, packet_type all match |
| 30 | `test_packet_pack_unpack_header1` | `packet_pack`, `packet_unpack` | HEADER_1 packet packing produces identical raw bytes; unpacking recovers hops, destination_hash, and data |
| 31 | `test_packet_pack_header2` | `packet_pack` | HEADER_2 packet (with transport_id) packing produces identical raw bytes |
| 32 | `test_packet_parse_header` | `packet_pack`, `packet_parse_header` | Header parsing extracts correct header_type, hops, destination_hash, and context |

## 6. Framing (6 tests)

**File:** `tests/test_framing.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 33 | `test_hdlc_escape` | `hdlc_escape` | HDLC byte-stuffing of random data matches (XOR mask 0x20 for FLAG/ESC bytes) |
| 34 | `test_hdlc_escape_special_bytes` | `hdlc_escape` | HDLC escaping of data containing FLAG (0x7E) and ESC (0x7D) bytes matches |
| 35 | `test_hdlc_frame` | `hdlc_frame` | Full HDLC framing (FLAG + escaped data + FLAG) matches |
| 36 | `test_kiss_escape` | `kiss_escape` | KISS byte-stuffing of random data matches (transposed values TFEND/TFESC) |
| 37 | `test_kiss_escape_special_bytes` | `kiss_escape` | KISS escaping of data containing FEND (0xC0) and FESC (0xDB) bytes matches |
| 38 | `test_kiss_frame` | `kiss_frame` | Full KISS framing (FEND + CMD_DATA + escaped data + FEND) matches |

## 7. Announce (3 tests)

**File:** `tests/test_announce.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 39 | `test_random_hash_with_params` | `random_hash` | Random hash generation with explicit random_bytes and timestamp produces identical 10-byte hash and timestamp_bytes |
| 40 | `test_announce_pack_unpack` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `announce_sign`, `announce_pack`, `announce_unpack` | Full announce lifecycle: signing produces identical signature; packing produces identical announce_data; unpacking recovers public_key, name_hash, random_hash, signature |
| 41 | `test_announce_verify` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `announce_sign`, `announce_pack`, `announce_verify` | Both impls verify a signed announce as valid (reconstructs signed_data from announce_data + destination_hash) |

## 8. Link (7 tests)

**File:** `tests/test_link.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 42 | `test_link_derive_key` | `link_derive_key` | Link key derivation (HKDF with shared_key as IKM, link_id as salt, 64-byte output) matches |
| 43 | `test_link_encrypt_decrypt` | `link_encrypt`, `link_decrypt` | Link-layer AES-256-CBC encryption with explicit IV produces identical ciphertext; decryption recovers original plaintext |
| 44 | `test_link_signalling_bytes` | `link_signalling_bytes` | 3-byte signalling encoding for 4 MTU values (500, 1196, 8192, 262144) matches, including decoded_mtu |
| 45 | `test_link_parse_signalling` | `link_parse_signalling` | Parsing signalling bytes `0x2001F4` recovers correct mtu and mode |
| 46 | `test_link_request_pack_unpack` | `link_request_pack`, `link_request_unpack` | Link request packing (msgpack array of timestamp, path_hash, data) matches; unpacking recovers timestamp and path_hash |
| 47 | `test_link_rtt_pack_unpack` | `link_rtt_pack`, `link_rtt_unpack` | RTT packing as msgpack float64 matches; unpacking recovers original RTT value |
| 48 | `test_link_id_from_packet` | `packet_pack`, `link_id_from_packet` | Link ID computed from a LINKREQUEST packet (truncated hash of hashable part) matches |

## 9. Resource (6 tests)

**File:** `tests/test_resource.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 49 | `test_resource_hash` | `resource_hash` | Resource hash (truncated SHA-256 of random_hash + data, 16 bytes) matches |
| 50 | `test_resource_flags_encode` | `resource_flags` | Resource flag byte encoding (encrypted, compressed, split, is_request, is_response, has_metadata) matches |
| 51 | `test_resource_flags_decode` | `resource_flags` | Resource flag byte decoding (0x11) into individual boolean fields matches |
| 52 | `test_resource_map_hash` | `resource_map_hash` | Part map hash (first 4 bytes of SHA-256(part_data + random_hash)) matches |
| 53 | `test_resource_build_hashmap` | `resource_build_hashmap` | Full hashmap built from 5 parts (concatenated 4-byte hashes) matches, including num_parts |
| 54 | `test_resource_proof` | `resource_proof` | Resource proof (truncated SHA-256(data + resource_hash), 16 bytes) matches |

## 10. Ratchet (4 tests)

**File:** `tests/test_ratchet.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 55 | `test_ratchet_id` | `ratchet_id` | Ratchet ID (first 10 bytes of SHA-256 of public key) matches |
| 56 | `test_ratchet_public_from_private` | `ratchet_public_from_private` | X25519 public key derivation from ratchet private key matches |
| 57 | `test_ratchet_derive_key` | `x25519_generate`, `ratchet_derive_key` | Ratchet key derivation (ECDH + HKDF with identity_hash as salt) produces matching shared_key and derived_key |
| 58 | `test_ratchet_encrypt_decrypt` | `ratchet_public_from_private`, `ratchet_encrypt`, `ratchet_decrypt` | Cross-implementation: encrypt with reference using ratchet public key, decrypt with SUT using ratchet private key. Recovers original plaintext |

## 11. Channel (2 tests)

**File:** `tests/test_channel.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 59 | `test_envelope_pack_unpack` | `envelope_pack`, `envelope_unpack` | Channel envelope packing ([MSGTYPE:2BE][SEQ:2BE][LEN:2BE][payload]) matches; unpacking recovers msgtype and data |
| 60 | `test_stream_msg_pack_unpack` | `stream_msg_pack`, `stream_msg_unpack` | Stream data message packing matches; unpacking recovers stream_id and data |

## 12. Transport (4 tests)

**File:** `tests/test_transport.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 61 | `test_path_request_pack_unpack` | `path_request_pack`, `path_request_unpack` | Path request packing (16-byte destination hash) matches; unpacking recovers destination_hash |
| 62 | `test_packet_hashlist_pack_unpack` | `packet_hashlist_pack`, `packet_hashlist_unpack` | Packet hashlist msgpack serialization of 5 hashes matches; unpacking recovers all hashes |
| 63 | `test_ifac_derive_key` | `ifac_derive_key` | IFAC key derivation from origin string (network_name + passphrase) matches |
| 64 | `test_ifac_compute_verify` | `ifac_derive_key`, `ifac_compute`, `ifac_verify` | IFAC tag computation (Ed25519 signature-based) matches; both impls verify the tag as valid |

## 13. Compression (3 tests)

**File:** `tests/test_compression.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 65 | `test_bz2_compress` | `bz2_compress` | BZ2 compression of 100 random bytes produces identical output |
| 66 | `test_bz2_decompress` | `bz2_compress`, `bz2_decompress` | Decompression of reference-compressed data recovers original bytes |
| 67 | `test_bz2_cross_decompress` | `bz2_compress`, `bz2_decompress` | Cross-implementation: SUT-compressed data decompressed by reference recovers original |

## 14. LXMF (3 tests)

**File:** `tests/test_lxmf.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 68 | `test_lxmf_pack_unpack` | `lxmf_pack`, `lxmf_unpack` | LXMF message packing (msgpack of [timestamp, title, content, fields]) produces identical packed_payload and message_hash; unpacking wire bytes recovers destination_hash and source_hash |
| 69 | `test_lxmf_hash` | `lxmf_hash` | LXMF message hash (SHA-256 of dest + src + packed_payload) matches |
| 70 | `test_lxmf_stamp_generate_validate` | `lxmf_stamp_workblock`, `lxmf_stamp_generate`, `lxmf_stamp_valid` | **(slow)** Stamp workblock generation (HKDF expansion) matches; stamp generated by reference validates with SUT; stamp generated by SUT validates with reference |

---

## Bridge Commands Required

Every implementation must handle 48 distinct bridge commands to pass all 70 tests. All binary parameters and return values are hex-encoded strings.

### Crypto (9 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `sha256` | `data` | `hash` |
| `sha512` | `data` | `hash` |
| `hmac_sha256` | `key`, `message` | `hmac` |
| `truncated_hash` | `data` | `hash` |
| `hkdf` | `length`, `ikm`, `salt`?, `info`? | `derived_key` |
| `aes_encrypt` | `plaintext`, `key`, `iv` | `ciphertext` |
| `aes_decrypt` | `ciphertext`, `key`, `iv` | `plaintext` |
| `pkcs7_pad` | `data` | `padded` |
| `pkcs7_unpad` | `data` | `unpadded` |

### Key Generation & Exchange (6 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `x25519_generate` | `seed` | `private_key`, `public_key` |
| `x25519_public_from_private` | `private_key` | `public_key` |
| `x25519_exchange` | `private_key`, `peer_public_key` | `shared_secret` |
| `ed25519_generate` | `seed` | `private_key`, `public_key` |
| `ed25519_sign` | `private_key`, `message` | `signature` |
| `ed25519_verify` | `public_key`, `message`, `signature` | `valid` |

### Identity (5 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `identity_from_private_key` | `private_key` (64B hex) | `public_key`, `hash`, `hexhash` |
| `identity_hash` | `public_key` | `hash` |
| `identity_sign` | `private_key`, `message` | `signature` |
| `identity_verify` | `public_key`, `message`, `signature` | `valid` |
| `identity_encrypt` | `public_key`, `plaintext`, `identity_hash` | `ciphertext` |
| `identity_decrypt` | `private_key`, `ciphertext`, `identity_hash` | `plaintext` |

### Token (3 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `token_encrypt` | `key` (64B hex), `plaintext`, `iv`? | `token` |
| `token_decrypt` | `key`, `token` | `plaintext` |
| `token_verify_hmac` | `key`, `token` | `valid` |

### Destination (3 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `name_hash` | `name` | `hash` |
| `destination_hash` | `identity_hash`, `app_name`, `aspects`? | `destination_hash`, `name_hash` |
| `packet_hash` | `raw` | `hash`, `truncated_hash`, `hashable_part` |

### Packet (4 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `packet_flags` | `header_type`, `context_flag`, `transport_type`, `destination_type`, `packet_type` | `flags` |
| `packet_parse_flags` | `flags` | `header_type`, `context_flag`, `transport_type`, `destination_type`, `packet_type` |
| `packet_pack` | `header_type`, `context_flag`, `transport_type`, `destination_type`, `packet_type`, `hops`, `destination_hash`, `transport_id`?, `context`, `data` | `raw` |
| `packet_unpack` | `raw` | `hops`, `destination_hash`, `data`, ... |
| `packet_parse_header` | `raw` | `header_type`, `hops`, `destination_hash`, `context` |

### Framing (4 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `hdlc_escape` | `data` | `escaped` |
| `hdlc_frame` | `data` | `framed` |
| `kiss_escape` | `data` | `escaped` |
| `kiss_frame` | `data` | `framed` |

### Announce (4 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `random_hash` | `random_bytes`?, `timestamp`? | `random_hash`, `timestamp_bytes` |
| `announce_sign` | `private_key`, `destination_hash`, `public_key`, `name_hash`, `random_hash` | `signature` |
| `announce_pack` | `public_key`, `name_hash`, `random_hash`, `signature` | `announce_data` |
| `announce_unpack` | `announce_data`, `has_ratchet` | `public_key`, `name_hash`, `random_hash`, `signature` |
| `announce_verify` | `public_key`, `announce_data`, `destination_hash`, `signature` | `valid` |

### Link (7 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `link_derive_key` | `shared_key`, `link_id` | `derived_key` |
| `link_encrypt` | `derived_key`, `plaintext`, `iv`? | `ciphertext` |
| `link_decrypt` | `derived_key`, `ciphertext` | `plaintext` |
| `link_signalling_bytes` | `mtu` | `signalling_bytes`, `decoded_mtu` |
| `link_parse_signalling` | `signalling_bytes` | `mtu`, `mode` |
| `link_request_pack` | `timestamp`, `path_hash`, `data`? | `packed` |
| `link_request_unpack` | `packed` | `timestamp`, `path_hash` |
| `link_rtt_pack` | `rtt` | `packed` |
| `link_rtt_unpack` | `packed` | `rtt` |
| `link_id_from_packet` | `raw` | `link_id` |

### Resource (5 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `resource_hash` | `data`, `random_hash` | `hash` |
| `resource_flags` | `mode`, + flag bools or `flags` int | `flags` or parsed bools |
| `resource_map_hash` | `part_data`, `random_hash` | `map_hash` |
| `resource_build_hashmap` | `parts` (list), `random_hash` | `hashmap`, `num_parts` |
| `resource_proof` | `data`, `resource_hash` | `proof` |

### Ratchet (4 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `ratchet_id` | `ratchet_public` | `ratchet_id` |
| `ratchet_public_from_private` | `ratchet_private` | `ratchet_public` |
| `ratchet_derive_key` | `ephemeral_private`, `ratchet_public`, `identity_hash` | `shared_key`, `derived_key` |
| `ratchet_encrypt` | `ratchet_public`, `identity_hash`, `plaintext` | `ciphertext` |
| `ratchet_decrypt` | `ratchet_private`, `identity_hash`, `ciphertext` | `plaintext` |

### Channel (2 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `envelope_pack` | `msgtype`, `sequence`, `data` | `envelope` |
| `envelope_unpack` | `envelope` | `msgtype`, `data` |
| `stream_msg_pack` | `stream_id`, `data`, `eof`, `compressed` | `message` |
| `stream_msg_unpack` | `message` | `stream_id`, `data` |

### Transport & IFAC (5 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `path_request_pack` | `destination_hash` | `data` |
| `path_request_unpack` | `data` | `destination_hash` |
| `packet_hashlist_pack` | `hashes` (list) | `serialized` |
| `packet_hashlist_unpack` | `serialized` | `hashes` (list) |
| `ifac_derive_key` | `ifac_origin` | `ifac_key` |
| `ifac_compute` | `ifac_key`, `packet_data` | `ifac` |
| `ifac_verify` | `ifac_key`, `packet_data`, `expected_ifac` | `valid` |

### Compression (2 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `bz2_compress` | `data` | `compressed` |
| `bz2_decompress` | `compressed` | `decompressed` |

### LXMF (5 commands)

| Command | Params | Returns |
|---------|--------|---------|
| `lxmf_pack` | `destination_hash`, `source_hash`, `timestamp`, `title`, `content` | `packed_payload`, `message_hash` |
| `lxmf_unpack` | `lxmf_bytes` | `destination_hash`, `source_hash`, ... |
| `lxmf_hash` | `destination_hash`, `source_hash`, `timestamp`, `title`, `content` | `message_hash` |
| `lxmf_stamp_workblock` | `message_id`, `expand_rounds`? | `workblock` |
| `lxmf_stamp_generate` | `message_id`, `stamp_cost`, `expand_rounds`? | `stamp`, `value` |
| `lxmf_stamp_valid` | `stamp`, `target_cost`, `workblock` | `valid` |

---

## Running the Tests

```bash
# Build Swift bridge
cd impls/swift && swift build -c release

# Run against Swift
python3 -m pytest tests/ --impl=swift -v

# Run against reference only (sanity check)
python3 -m pytest tests/ --reference-only -v

# Skip slow stamp test
python3 -m pytest tests/ --impl=swift -v -m "not slow"
```
