# Conformance Test Cases

## 1. Cryptographic Primitives (15 tests)

**File:** `tests/test_crypto.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 1.1 | `test_sha256` | `sha256` | SHA-256 of 64 random bytes is byte-identical across impls |
| 1.2 | `test_sha512` | `sha512` | SHA-512 of 64 random bytes is byte-identical across impls |
| 1.3 | `test_hmac_sha256` | `hmac_sha256` | HMAC-SHA256 of a random 32-byte key + 48-byte message is byte-identical |
| 1.4 | `test_truncated_hash` | `truncated_hash` | RNS's 16-byte `truncated_hash` (`SHA-256[:16]`) is byte-identical — the building block for destination, packet, and ratchet IDs |
| 1.5 | `test_hkdf` | `hkdf` | HKDF with a salt, 64-byte output is byte-identical |
| 1.6 | `test_hkdf_no_salt` | `hkdf` | HKDF with **no salt** (zero-salt path), 32-byte output is byte-identical |
| 1.7 | `test_hkdf_with_info` | `hkdf` | HKDF with salt **and an info-context label**, 48-byte output is byte-identical |
| 1.8 | `test_aes_encrypt_decrypt` | `aes_encrypt`, `aes_decrypt` | AES-256-CBC round-trip: with both impls given the same key, IV, and plaintext, encryption produces byte-identical ciphertext and decryption recovers the original |
| 1.9 | `test_pkcs7_pad_unpad` | `pkcs7_pad`, `pkcs7_unpad` | PKCS7 pad/unpad round-trip on non-aligned data: padding is byte-identical and unpadding recovers the original |
| 1.10 | `test_x25519_generate` | `x25519_generate` | X25519 keypair generation from a deterministic seed yields byte-identical public key |
| 1.11 | `test_x25519_public_from_private` | `x25519_generate`, `x25519_public_from_private` | Deriving an X25519 public key from a **raw private key** (no seed path) yields byte-identical output |
| 1.12 | `test_x25519_exchange` | `x25519_generate`, `x25519_exchange` | X25519 ECDH between two keypairs produces a byte-identical shared secret — the basis of link key derivation |
| 1.13 | `test_ed25519_generate` | `ed25519_generate` | Ed25519 keypair generation from a deterministic seed yields byte-identical public key |
| 1.14 | `test_ed25519_sign_verify` | `ed25519_generate`, `ed25519_sign`, `ed25519_verify` | Ed25519 sign+verify: signing is deterministic per RFC 8032 (same input → byte-identical signature) and both impls verify each other's signatures |
| 1.15 | `test_ed25519_verify_bad_sig` | `ed25519_generate`, `ed25519_verify` | Negative control: both impls reject a random (forged) Ed25519 signature |

## 2. Identity (4 tests)

**File:** `tests/test_identity.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 2.1 | `test_identity_from_private_key` | `identity_from_private_key` | Deriving an RNS Identity from its 64-byte private key (32-byte encryption + 32-byte signing halves) yields byte-identical public key, `identity_hash`, and `hexhash` string |
| 2.2 | `test_identity_hash` | `identity_from_private_key`, `identity_hash` | RNS's `identity_hash` (truncated SHA-256 of the concatenated encryption + signing public keys) is byte-identical |
| 2.3 | `test_identity_sign_verify` | `identity_sign`, `identity_from_private_key`, `identity_verify` | RNS Identity sign+verify: signatures are byte-identical and both impls verify each other's signatures |
| 2.4 | `test_identity_encrypt_decrypt` | `identity_from_private_key`, `identity_encrypt`, `identity_decrypt` | RNS Identity encrypt/decrypt cross-impl round-trip in both directions — exercises the X25519+HKDF+AES composition used for unicast encryption |

## 3. Token Encryption (3 tests)

**File:** `tests/test_token.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 3.1 | `test_token_encrypt_decrypt` | `token_encrypt`, `token_decrypt` | RNS Token encrypt/decrypt round-trip (Fernet-like AES-256-CBC + HMAC-SHA256): given the same key, IV, and plaintext, both impls produce byte-identical tokens and decrypt back to the original |
| 3.2 | `test_token_verify_hmac` | `token_encrypt`, `token_verify_hmac` | Both impls verify the HMAC tag on a well-formed RNS Token as valid — positive control on the verify path |
| 3.3 | `test_token_cross_decrypt` | `token_encrypt`, `token_decrypt` | RNS Token cross-impl interop: tokens produced by either impl decrypt to the original plaintext on the other |

## 4. Destination (3 tests)

**File:** `tests/test_destination.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 4.1 | `test_name_hash` | `name_hash` | RNS `name_hash` of `"lxmf.delivery"` (the canonical LXMF delivery destination) is byte-identical across impls |
| 4.2 | `test_destination_hash` | `identity_from_private_key`, `destination_hash` | RNS `destination_hash` composition: takes an `identity_hash` + `app_name` + `aspects`, computes the `name_hash`, then truncated-hashes `name_hash + identity_hash` into the 16-byte destination address — asserts both the intermediate `name_hash` and the final address |
| 4.3 | `test_packet_hash` | `packet_pack`, `packet_hash` | RNS `packet_hash` (SHA-256 of the "hashable part" of a packet — hops byte and HEADER_2 transport_id masked out): byte-identical hash and `hashable_part` slice. This is the dedup key in the packet hashlist, deliberately stable as packets propagate through transports |

## 5. Packet (8 tests)

**File:** `tests/test_packet.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 5.1 | `test_packet_flags` | `packet_flags` | RNS `packet_flags` byte encoding for a basic DATA packet (all bit-fields zero) is byte-identical |
| 5.2 | `test_packet_flags_announce` | `packet_flags` | RNS `packet_flags` byte encoding for an ANNOUNCE packet (`context_flag=1`, `packet_type=1` → byte `0x21`) is byte-identical |
| 5.3 | `test_packet_parse_flags` | `packet_parse_flags` | RNS `packet_parse_flags` decodes 6 distinct flag bytes (`0x00`, `0x21`, `0x41`, `0x15`, `0x0A`, `0x7F`) covering every value of every bit-field; all decoded fields (`header_type`, `context_flag`, `transport_type`, `destination_type`, `packet_type`) match the reference |
| 5.4 | `test_packet_parse_flags_ignores_ifac_bit` | `packet_parse_flags` | RNS `packet_parse_flags` ignores the IFAC flag (bit 7): for every curated flag byte, decoding `byte | 0x80` yields fields byte-identical to decoding `byte` on both impls — bit 7 is the masking layer's concern, not the packet decoder's. Catches bit-7 bleed even when both impls share the bug. |
| 5.5 | `test_packet_parse_flags_exhaustive` | `packet_parse_flags` | RNS `packet_parse_flags` exhaustive sweep: for every flag byte value `0x00`–`0x7F` (all 128 combinations of the 5 named fields, IFAC bit clear), SUT and reference decode byte-identically. Pairs with the curated `test_packet_parse_flags` (which documents WHICH byte covers what) — together they catch every per-byte miswiring SUT could possibly have. |
| 5.6 | `test_packet_pack_unpack_header1` | `packet_pack`, `packet_unpack` | RNS packet pack/unpack round-trip (HEADER_1 layout — no `transport_id`): packing is byte-identical and unpacking recovers `hops`, `destination_hash`, and data |
| 5.7 | `test_packet_pack_unpack_header2` | `packet_pack`, `packet_unpack` | RNS packet pack/unpack round-trip for HEADER_2 layout (includes `transport_id` for multi-hop routing): packing is byte-identical and unpacking recovers `hops`, `transport_id`, `destination_hash`, and data |
| 5.8 | `test_packet_parse_header` | `packet_pack`, `packet_parse_header` | RNS `packet_parse_header` extracts `header_type`, `hops`, `destination_hash`, and context byte-identically from a packed packet |

## 6. Framing (6 tests)

HDLC and KISS are byte-stuffing protocols for framing variable-length data on a serial link. Both pick two special bytes — a frame delimiter (FLAG=`0x7E` for HDLC, FEND=`0xC0` for KISS) and an escape byte (ESC=`0x7D`, FESC=`0xDB`). When the payload contains either special byte, it's escaped: HDLC writes ESC + (byte XOR `0x20`); KISS writes FESC + the byte's transposed value (TFEND=`0xDC` for FEND, TFESC=`0xDD` for FESC). RNS uses HDLC over direct serial interfaces and KISS to talk to TNCs.

**File:** `tests/test_framing.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 6.1 | `test_hdlc_escape` | `hdlc_escape` | HDLC byte-stuffing of random data (XOR-with-`0x20` escape for FLAG=`0x7E` and ESC=`0x7D`) is byte-identical |
| 6.2 | `test_hdlc_escape_special_bytes` | `hdlc_escape` | HDLC byte-stuffing of data that contains the special FLAG (`0x7E`) and ESC (`0x7D`) bytes — verifies the escape transform actually fires on the bytes it's designed to escape, not just random data that mostly doesn't trigger it |
| 6.3 | `test_hdlc_frame` | `hdlc_frame` | Full HDLC frame (FLAG sentinel + escaped payload + FLAG sentinel) is byte-identical |
| 6.4 | `test_kiss_escape` | `kiss_escape` | KISS byte-stuffing of random data (transposed-byte escape: FEND=`0xC0`→TFEND, FESC=`0xDB`→TFESC) is byte-identical |
| 6.5 | `test_kiss_escape_special_bytes` | `kiss_escape` | KISS byte-stuffing of data that contains the special FEND (`0xC0`) and FESC (`0xDB`) bytes — verifies the escape transform actually fires on the bytes it's designed to escape |
| 6.6 | `test_kiss_frame` | `kiss_frame` | Full KISS frame (FEND + CMD_DATA + escaped payload + FEND) is byte-identical |

## 7. Announce (6 tests)

An RNS announce is how a destination tells the network it exists. The packet bundles the destination's identity public keys (encryption + signing), a `name_hash`, a `random_hash` (freshness token from random bytes + timestamp), optionally a ratchet public key and `app_data`, plus an Ed25519 signature over the whole payload. These tests exercise the cryptographic primitives at the bytes level: sign, pack, unpack, verify. The wire-level propagation rules — transport nodes selectively forward subject to per-interface mode gating, bandwidth caps (default 2%), deduplication, and a 128-hop limit; this is *not* simple flooding — live in Wire Interop and Transport Behavior.

**File:** `tests/test_announce.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 7.1 | `test_random_hash_with_params` | `random_hash` | RNS `random_hash` generation with explicit `random_bytes` + timestamp inputs produces a byte-identical 10-byte hash and `timestamp_bytes` — exercising the deterministic path of the function (production uses random inputs each announce) |
| 7.2 | `test_announce_pack_unpack` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `announce_sign`, `announce_pack`, `announce_unpack` | RNS announce lifecycle round-trip: sign → pack → unpack. Signature is byte-identical, `announce_data` is byte-identical, and unpacking recovers `public_key`, `name_hash`, `random_hash`, and signature byte-for-byte across impls |
| 7.3 | `test_announce_with_app_data` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `announce_sign`, `announce_pack`, `announce_unpack` | RNS announce lifecycle round-trip with non-empty `app_data` (the trailing variable-length field, inside the signed payload). In LXMF a delivery destination's `app_data` is a msgpack `[display_name, stamp_cost]` pair — the user's nickname and the proof-of-work cost they require for inbound messages. Confirms `app_data` is signed, packs into the trailing bytes, unpacks back byte-identical, and the signature still verifies — closes the gap test_announce_pack_unpack leaves by always sending empty `app_data` |
| 7.4 | `test_announce_verify` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `announce_sign`, `announce_pack`, `announce_verify` | Both impls verify a signed announce as valid — `announce_verify` reconstructs the signed payload from `announce_data` + `destination_hash` and checks the Ed25519 signature; cross-impl verification confirms the signature is interoperable |
| 7.5 | `test_announce_verify_bad_sig` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `announce_pack`, `announce_verify` | Negative control: both impls reject an announce with a forged (random) Ed25519 signature — verify returns false. Mirrors test_ed25519_verify_bad_sig but at the announce composition layer |
| 7.6 | `test_announce_verify_dest_hash_mismatch` | `identity_from_private_key`, `name_hash`, `random_hash`, `announce_sign`, `announce_pack`, `announce_verify` | Negative control: an announce with a valid signature but a `destination_hash` that doesn't equal `truncated_hash(name_hash + identity_hash)` is rejected — exercises the dest-hash binding check that stops a node from claiming an unrelated destination's hash for an authentically-signed announce |

## 8. Link (10 tests)

An RNS Link is an encrypted, authenticated session between two destinations — established by a handshake (LINKREQUEST → link proof), then used for ongoing exchange with forward secrecy. These tests cover the cryptographic and wire-format primitives a link is built from: key derivation from the ECDH handshake, the AES link cipher, the signalling bytes that negotiate MTU, the link-request / response / RTT framing, and the link-proof signature. The full multi-hop establishment handshake is tested in Wire Interop.

**File:** `tests/test_link.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 8.1 | `test_link_derive_key` | `link_derive_key` | RNS link key derivation: HKDF over the ECDH shared secret (`shared_key` as input key material, `link_id` as salt) produces a byte-identical 64-byte derived key |
| 8.2 | `test_link_encrypt_decrypt` | `link_encrypt`, `link_decrypt` | RNS link-layer AES-256-CBC encrypt/decrypt round-trip: with both impls given the same derived key, IV, and plaintext, encryption produces byte-identical ciphertext and decryption recovers the original |
| 8.3 | `test_link_signalling_bytes` | `link_signalling_bytes` | RNS link signalling-byte encoding for 4 MTU values (500, 1196, 8192, 262144 bytes): the 3-byte signalling field is byte-identical and the round-tripped `decoded_mtu` matches — spans the small-frame to large-frame range |
| 8.4 | `test_link_parse_signalling` | `link_signalling_bytes`, `link_parse_signalling` | RNS link signalling-byte decoding: parses the fixed vector `0x2001F4` (mode 1, MTU 500) and round-trips all 4 MTU values from test_link_signalling_bytes — every parsed `mtu` + link `mode` matches the reference |
| 8.5 | `test_link_request_pack_unpack` | `link_request_pack`, `link_request_unpack` | RNS link-request pack/unpack round-trip: the msgpack array (`timestamp`, `path_hash`, `data`) packs byte-identically and unpacking recovers `timestamp` and `path_hash` |
| 8.6 | `test_link_response_pack_unpack` | `link_response_pack`, `link_response_unpack` | RNS link-response pack/unpack round-trip: the msgpack `[request_id, response_data]` array packs byte-identically and unpacking recovers both fields. Pairs with test_link_request_pack_unpack — request and response are the two halves of the link request/response exchange |
| 8.7 | `test_link_rtt_pack_unpack` | `link_rtt_pack`, `link_rtt_unpack` | RNS link RTT pack/unpack round-trip: the round-trip-time value packs as a msgpack float64 byte-identically and unpacks back to the original |
| 8.8 | `test_link_id_from_packet` | `packet_pack`, `link_id_from_packet` | RNS `link_id` derivation from a LINKREQUEST packet (truncated hash of the packet's hashable part) is byte-identical — this is the identifier both ends of a link must agree on |
| 8.9 | `test_link_prove_verify` | `identity_from_private_key`, `x25519_generate`, `ed25519_generate`, `link_signalling_bytes`, `link_prove`, `link_verify_proof` | RNS link proof (LRPROOF) round-trip: the destination signs `link_id + receiver_pub + receiver_sig_pub + signalling_bytes` with its Ed25519 key; the signature is byte-identical across impls and each impl verifies the other's proof — this is the handshake step that lets a link initiator confirm it's talking to the real destination |
| 8.10 | `test_link_prove_verify_bad_sig` | `identity_from_private_key`, `x25519_generate`, `ed25519_generate`, `link_verify_proof` | Negative control: both impls reject a link proof carrying a forged (random) Ed25519 signature — `link_verify_proof` returns false. Confirms the link handshake can't be spoofed by an attacker who doesn't hold the destination's signing key |

## 9. Ratchet (4 tests)

**File:** `tests/test_ratchet.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 9.1 | `test_ratchet_id` | `ratchet_id` | Ratchet ID (first 10 bytes of SHA-256 of public key) matches |
| 9.2 | `test_ratchet_public_from_private` | `ratchet_public_from_private` | X25519 public key derivation from ratchet private key matches |
| 9.3 | `test_ratchet_derive_key` | `x25519_generate`, `ratchet_derive_key` | Ratchet key derivation (ECDH + HKDF with identity_hash as salt) produces matching shared_key and derived_key |
| 9.4 | `test_ratchet_encrypt_decrypt` | `ratchet_public_from_private`, `ratchet_encrypt`, `ratchet_decrypt` | Cross-implementation: encrypt with reference using ratchet public key, decrypt with SUT using ratchet private key. Recovers original plaintext |

## 10. Ratchet Lifecycle (4 tests)

**File:** `tests/test_ratchet_lifecycle.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 10.1 | `test_announce_with_ratchet_pack_unpack` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `ratchet_public_from_private`, `announce_sign`, `announce_pack`, `announce_unpack` | An announce signed, packed, and unpacked with a ratchet public key round-trips byte-identically; ratchet field survives the wire |
| 10.2 | `test_ratchet_extract_from_announce` | `identity_from_private_key`, `name_hash`, `random_hash`, `destination_hash`, `ratchet_public_from_private`, `announce_sign`, `announce_pack`, `announce_unpack`, `ratchet_id` | Ratchet public key (and derived ratchet_id) extracted from a packed announce matches what was packed in |
| 10.3 | `test_ratchet_full_lifecycle_encrypt_decrypt` | `identity_from_private_key`, `ratchet_public_from_private`, `ratchet_encrypt`, `ratchet_decrypt` | Full ratchet flow (identity → ratchet keypair → encrypt → decrypt) round-trips a plaintext in both cross-impl directions; the path propagated LXMF delivery depends on |
| 10.4 | `test_ratchet_cross_encrypt_decrypt` | `ratchet_public_from_private`, `ratchet_encrypt`, `ratchet_decrypt` | Cross-impl ratchet encrypt/decrypt: SUT-encrypted ciphertext decrypts on the reference, and reference-encrypted ciphertext decrypts on the SUT |

## 11. Channel (2 tests)

**File:** `tests/test_channel.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.1 | `test_envelope_pack_unpack` | `envelope_pack`, `envelope_unpack` | Channel envelope packing ([MSGTYPE:2BE][SEQ:2BE][LEN:2BE][payload]) matches; unpacking recovers msgtype and data |
| 11.2 | `test_stream_msg_pack_unpack` | `stream_msg_pack`, `stream_msg_unpack` | Stream data message packing matches; unpacking recovers stream_id and data |

## 12. Transport (9 tests)

**File:** `tests/test_transport.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 12.1 | `test_path_request_pack_unpack` | `path_request_pack`, `path_request_unpack` | Path request packing (16-byte destination hash) matches; unpacking recovers destination_hash |
| 12.2 | `test_packet_hashlist_pack_unpack` | `packet_hashlist_pack`, `packet_hashlist_unpack` | Packet hashlist msgpack serialization of 5 hashes matches; unpacking recovers all hashes |
| 12.3 | `test_ifac_derive_key` | `ifac_derive_key` | IFAC key derivation from origin string (network_name + passphrase) matches |
| 12.4 | `test_ifac_compute_verify` | `ifac_derive_key`, `ifac_compute`, `ifac_verify` | IFAC tag computation (Ed25519 signature-based) matches; both impls verify the tag as valid |
| 12.5 | `test_ifac_mask_packet` | `ifac_derive_key`, `ifac_mask_packet` | IFAC masking transform produces byte-identical wire-format packets and sets the IFAC flag in byte 0 |
| 12.6 | `test_ifac_unmask_packet` | `ifac_derive_key`, `ifac_mask_packet`, `ifac_unmask_packet` | IFAC unmasking recovers the original packet bytes and validates the tag |
| 12.7 | `test_ifac_cross_mask_unmask` | `ifac_derive_key`, `ifac_mask_packet`, `ifac_unmask_packet` | Cross-impl: SUT-masked packets unmask correctly on the reference, and reference-masked packets unmask correctly on the SUT |
| 12.8 | `test_ifac_wrong_key_rejected` | `ifac_derive_key`, `ifac_mask_packet`, `ifac_unmask_packet` | A packet masked with one key is rejected when unmasked with a different key (negative control on IFAC enforcement) |
| 12.9 | `test_ifac_mask_small_ifac_size` | `ifac_derive_key`, `ifac_mask_packet`, `ifac_unmask_packet` | IFAC masking with the 8-byte radio-interface ifac_size produces matching wire bytes and round-trips correctly |

## 13. Compression (3 tests)

**File:** `tests/test_compression.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 13.1 | `test_bz2_compress` | `bz2_compress` | SUT bz2 output begins with the bz2 magic header and self-roundtrips (compress then decompress returns input) |
| 13.2 | `test_bz2_decompress` | `bz2_compress`, `bz2_decompress` | SUT decompression of reference-compressed bytes recovers the original input |
| 13.3 | `test_bz2_cross_decompress` | `bz2_compress`, `bz2_decompress` | Cross-impl: SUT-compressed bytes decompressed by reference recovers the original input |

## 14. LXMF (4 tests)

**File:** `tests/test_lxmf.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 14.1 | `test_lxmf_pack_unpack` | `lxmf_pack`, `lxmf_unpack` | LXMF message packing (msgpack of [timestamp, title, content, fields]) produces identical packed_payload and message_hash; unpacking wire bytes recovers destination_hash and source_hash |
| 14.2 | `test_lxmf_hash` | `lxmf_hash` | LXMF message hash (SHA-256 of dest + src + packed_payload) matches |
| 14.3 | `test_lxmf_stamp_replay_across_message_ids_rejected` | `lxmf_stamp_workblock`, `lxmf_stamp_generate`, `lxmf_stamp_valid` | (slow) A stamp generated for message_id A does NOT validate as proof for message_id B — per-message PoW binding (closes lxmf-conformance#11) |
| 14.4 | `test_lxmf_stamp_generate_validate` | `lxmf_stamp_workblock`, `lxmf_stamp_generate`, `lxmf_stamp_valid` | (slow) Stamp workblock generation (HKDF expansion) matches; stamp generated by reference validates with SUT; stamp generated by SUT validates with reference |

## 15. IFAC (6 tests)

**File:** `tests/test_ifac.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 15.1 | `test_ifac_derive_key` | `ifac_derive_key` | HKDF-derived 64-byte IFAC key and the IFAC_SALT constant match byte-for-byte across impls |
| 15.2 | `test_ifac_compute_issue_29_vector` | `ifac_derive_key`, `ifac_compute` | Fixed reticulum-kt#29 vector — packet=bytes(range(64)), network=testnet, pass=testpass — Ed25519 signature and IFAC tag match |
| 15.3 | `test_ifac_compute_random` | `ifac_compute` | Random key + random 48-byte packet — Ed25519 signature and IFAC tag match across impls |
| 15.4 | `test_ifac_compute_variable_size` | `ifac_compute` | IFAC tags match across impls for every ifac_size in {1, 8, 16, 32, 64} |
| 15.5 | `test_ifac_verify_cross_impl` | `ifac_compute`, `ifac_verify` | SUT-computed IFAC tag verifies on the reference, and reference-computed tag verifies on the SUT (end-to-end interop pair) |
| 15.6 | `test_ifac_mask_packet` | `ifac_mask_packet` | Full wire-format IFAC masking transform (Ed25519 sign + flag toggle + IFAC insert + HKDF mask + XOR) produces byte-identical masked packets and tags |

## 16. LXMF Delivery (5 tests)

### `tests/lxmf/test_direct.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 16.1 | `test_direct_text_round_trip` | `send_direct`, `wait_for_inbox_count` | A short text LXMessage delivered via DIRECT (single-packet, link-based) arrives at the receiver with exact content, title, and source |
| 16.2 | `test_direct_with_file_attachment_multipacket` | `send_direct`, `wait_for_inbox_count` | A DIRECT LXMessage carrying a 2 KiB FIELD_FILE_ATTACHMENTS payload (forces multi-packet Resource transfer) arrives intact with exact filename and bytes |

### `tests/lxmf/test_opportunistic.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 16.3 | `test_opportunistic_text_round_trip` | `send_opportunistic`, `wait_for_inbox_count` | A single-packet OPPORTUNISTIC LXMessage arrives at the receiver with exact content, title, source, and empty fields |
| 16.4 | `test_opportunistic_with_image_field` | `send_opportunistic`, `wait_for_inbox_count` | An OPPORTUNISTIC LXMessage carrying a FIELD_IMAGE payload (format + ~64-byte image bytes) arrives with exact field shape |

### `tests/lxmf/test_propagation.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 16.5 | `test_propagated_delivery_round_trip` | `send_propagated`, `wait_for_stored_message_count`, `sync_inbound`, `poll_inbox` | A PROPAGATED LXMessage is stored exactly once on the lxmd propagation node, sync_inbound pulls exactly one message, and the receiver's inbox holds the matching content/title/source |

## 17. Wire Interop (25 tests)

### `tests/wire/test_announce_burst_throttle.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.1 | `test_burst_throttle_holds_subsequent_announces` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | When 12 rapid announces exceed IC_BURST_FREQ_NEW on an ingress-controlled TCP server, at least one is held by burst-mode throttling rather than reaching the downstream local client |

### `tests/wire/test_announce_steady_state.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.2 | `test_steady_state_announce_three_in_a_row` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | Three distinct announces from a TCP remote spaced 10s apart each reach the local client via the shared-instance master — no fanout regression after the first announce |

### `tests/wire/test_announce_via_shared_master.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.3 | `test_announce_local_to_remote` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | A shared-instance local client's announce reaches a TCP-attached remote peer through the master (egress: LocalServerInterface → TCPInterface) |
| 17.4 | `test_announce_remote_to_local` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | A TCP remote's announce reaches a shared-instance local client through the master (ingress: TCPInterface → LocalServerInterface with master-as-transport_id spoof) |

### `tests/wire/test_ifac_interop.py` (3 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.5 | `test_announce_propagates_with_ifac` | `start_tcp_server`, `start_tcp_client`, `announce`, `poll_path` | An announce from a TCP client with matching IFAC credentials populates the server's path table (reticulum-kt#29 forward direction) |
| 17.6 | `test_announce_bidirectional` | `start_tcp_server`, `start_tcp_client`, `announce`, `poll_path` | Reverse-direction IFAC: server-initiated announce reaches the TCP client (exercises TCPServerInterface child-interface IFAC inheritance) |
| 17.7 | `test_mismatched_ifac_blocks_announce` | `start_tcp_server`, `start_tcp_client`, `announce`, `poll_path` | Negative control: when network_names match but passphrases differ, IFAC verification rejects the announce and no path is learned |

### `tests/wire/test_link_multihop.py` (3 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.8 | `test_link_establishes_multihop` | `start_tcp_server`, `start_tcp_client`, `listen`, `announce`, `link_open` | A 2-hop Link (sender → TCP transport → receiver) establishes with a 16-byte link_id within the establishment timeout |
| 17.9 | `test_link_data_reaches_receiver_multihop` | `link_open`, `link_send`, `link_poll` | Bytes sent over an established multi-hop Link arrive at the receiver intact — catches HEADER_2 transport_id mis-wrapping at the sender |
| 17.10 | `test_link_data_roundtrip_multiple_packets` | `link_open`, `link_send`, `link_poll` | Five back-to-back link DATA packets (16-48 bytes each) all arrive at the receiver as a multiset — catches 'only first packet routes' regressions |

### `tests/wire/test_link_via_shared_master.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.11 | `test_link_establishes_via_shared_master` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `listen`, `announce`, `poll_path`, `link_open` | A Link from a shared-instance local client to a TCP-attached destination establishes successfully via the master — catches the H1→H2 synthesis link_id-desynchronization bug |

### `tests/wire/test_path_discovery.py` (5 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.12 | `test_path_response_reuses_cached_announce` | `start_tcp_server`, `start_tcp_client`, `announce`, `request_path`, `poll_path`, `read_path_random_hash` | When B answers a path request for a destination it cached, the re-emitted announce's random_hash bytes are byte-identical to the cached announce's (no regeneration on re-emit) |
| 17.13 | `test_discover_paths_for_mode_gating` | `start_tcp_server`, `start_tcp_client`, `request_path`, `has_discovery_path_request` | B forwards path requests for unknown destinations only when its receiving interface's mode is in DISCOVER_PATHS_FOR={access_point, gateway, roaming}, gated correctly for every parametrized mode |
| 17.14 | `test_roaming_no_answer_when_next_hop_on_same_interface` | `start_tcp_server`, `start_tcp_client`, `announce`, `request_path`, `tx_bytes`, `read_path_entry` | Under ROAMING mode, B refuses to answer a path request when the cached path's next-hop is the same interface that received the PR (loop-prevention rule fires) |
| 17.15 | `test_roaming_loop_prevention_positive_companion` | `start_tcp_server`, `start_tcp_client`, `announce`, `request_path`, `tx_bytes`, `read_path_entry` | Under FULL mode (companion to the ROAMING test) B does answer the PR — proves the ROAMING test isn't vacuously passing because B never answers |
| 17.16 | `test_mode_specific_path_expiry_assignment` | `start_tcp_server`, `start_tcp_client`, `announce`, `read_path_entry` | Stored path-entry expiry equals timestamp + the per-mode constant (PATHFINDER_E for FULL, AP_PATH_TIME for ACCESS_POINT, ROAMING_PATH_TIME for ROAMING) within jitter |

### `tests/wire/test_resource_invariants.py` (5 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.17 | `test_resource_identity_is_fresh_per_construction` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: two Resources built from byte-identical payloads get different identities — RNS draws a fresh random_hash per construction (Resource.py:193), so the hash never leaks that two payloads were equal |
| 17.18 | `test_resource_encrypted_output_is_fresh_per_construction` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: two Resources built from byte-identical payloads produce entirely different encrypted parts — a fresh random prefix on the data stream (Resource.py:158/165) plus per-construction Link encryption keeps every chunk's ciphertext unique |
| 17.19 | `test_resource_truncated_hash_is_consistent_with_full_hash` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: a Resource's truncated_hash is its own full hash truncated to 16 bytes — not an independently derived value — catching an implementation that computes the two from different inputs |
| 17.20 | `test_resource_expected_proof_is_full_length` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: a Resource's expected_proof is a full-length 32-byte SHA-256 hash — directly catching the proof being truncated, which is the exact drift the deleted hand-rolled resource_proof command had |
| 17.21 | `test_resource_hashmap_has_one_entry_per_part` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: a Resource's hashmap carries exactly one 4-byte map hash per part — len(hashmap) == num_parts x MAPHASH_LEN — for a multi-part resource, catching a mis-sized or mis-counted hashmap |

### `tests/wire/test_resource_multihop.py` (4 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 17.22 | `test_small_resource_multihop` | `link_open`, `resource_send`, `resource_poll` | A sub-MDU 256-byte Resource transfer over a multi-hop Link round-trips exactly through RESOURCE_ADV → REQ → DATA → PROOF |
| 17.23 | `test_chunked_resource_multihop` | `link_open`, `resource_send`, `resource_poll` | A 16 KiB Resource (multi-packet chunking, mirroring Columba image-send size) round-trips intact over a multi-hop Link |
| 17.24 | `test_chunked_resource_with_ifac_multihop` | `link_open`, `resource_send`, `resource_poll` | A 16 KiB Resource round-trips intact over an IFAC-protected multi-hop Link — exercises per-packet IFAC masking on Resource chunks (Columba production config) |
| 17.25 | `test_large_resource_multihop` | `link_open`, `resource_send`, `resource_poll` | A 256 KiB Resource (~32 chunks) round-trips intact, stress-testing back-to-back link DATA transmission and reassembly |

## 18. Transport Behavior (3 tests)

### `tests/behavioral/test_hop_increment.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 18.1 | `test_hop_increment_on_receive` | `start`, `attach_mock_interface`, `inject`, `drain_tx` | An announce received with wire_hops=N is re-emitted on another interface with hops=N+1 (the per-hop +1 increment rule) |
| 18.2 | `test_hop_increment_when_transport_disabled` | `start`, `attach_mock_interface`, `inject`, `drain_tx` | With enable_transport=False and no local clients, received announces are NOT re-emitted on any other interface (the transport gate enforces) |

### `tests/behavioral/test_path_replacement.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 18.3 | `test_stale_path_response_does_not_overwrite_fresh_path` | `start`, `attach_mock_interface`, `inject`, `drain_tx` | A stale PATH_RESPONSE announce (older emission timestamp, novel random_blob, more hops) does NOT replace a fresh direct-path entry — observable via the retransmitted announce's hops value |

