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

## 2. Identity (5 tests)

**File:** `tests/test_identity.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 2.1 | `test_identity_from_private_key` | `identity_from_private_key` | Deriving an RNS Identity from its 64-byte private key (32-byte encryption + 32-byte signing halves) yields byte-identical public key, `identity_hash`, and `hexhash` string |
| 2.2 | `test_identity_hash` | `identity_from_private_key`, `identity_hash` | RNS's `identity_hash` (truncated SHA-256 of the concatenated encryption + signing public keys) is byte-identical |
| 2.3 | `test_identity_sign_verify` | `identity_sign`, `identity_from_private_key`, `identity_verify` | RNS Identity sign+verify: signatures are byte-identical and both impls verify each other's signatures |
| 2.4 | `test_identity_encrypt_decrypt` | `identity_from_private_key`, `identity_encrypt`, `identity_decrypt` | RNS Identity encrypt/decrypt cross-impl round-trip in both directions — exercises the X25519+HKDF+AES composition used for unicast encryption |
| 2.5 | `test_identity_encrypt_is_fresh_per_call` | `identity_from_private_key`, `identity_encrypt`, `identity_decrypt` | Invariant: two encryptions of byte-identical plaintext for the same Identity produce different ciphertext (RNS draws a fresh ephemeral X25519 key + AES IV per call), and both still decrypt back to the original |

## 3. Token Encryption (4 tests)

**File:** `tests/test_token.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 3.1 | `test_token_encrypt_decrypt` | `token_encrypt`, `token_decrypt` | RNS Token encrypt/decrypt round-trip (Fernet-like AES-256-CBC + HMAC-SHA256): a token encrypted by an impl decrypts back to the original plaintext on that same impl |
| 3.2 | `test_token_verify_hmac` | `token_encrypt`, `token_verify_hmac` | Both impls verify the HMAC tag on a well-formed RNS Token as valid — positive control on the verify path |
| 3.3 | `test_token_cross_decrypt` | `token_encrypt`, `token_decrypt` | RNS Token cross-impl interop: tokens produced by either impl decrypt to the original plaintext on the other |
| 3.4 | `test_token_encrypt_is_fresh_per_call` | `token_encrypt` | Invariant: two RNS Tokens encrypted from byte-identical key+plaintext differ (RNS draws a fresh AES IV per call) — a deterministic token would reuse the IV and leak plaintext equality |

## 4. Destination (2 tests)

**File:** `tests/test_destination.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 4.1 | `test_name_hash` | `name_hash` | RNS `name_hash` of `"lxmf.delivery"` (the canonical LXMF delivery destination) is byte-identical across impls |
| 4.2 | `test_destination_hash` | `identity_from_private_key`, `destination_hash` | RNS `destination_hash`: given an `identity_hash` + `app_name` + `aspects`, the 16-byte destination address (RNS.Destination.hash — expand_name -> name_hash -> truncated_hash(name_hash + identity_hash)) is byte-identical across impls |

## 5. Packet (5 tests)

**File:** `tests/test_packet.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 5.1 | `test_packet_plain_wire_format_roundtrip` | `packet_build`, `packet_unpack` | RNS packet wire-format cross-impl interop on a PLAIN destination: a packet built by either impl unpacks on the other to byte-identical hops/destination_hash/context/data, and the flags byte itself agrees — PLAIN carries the payload in the clear so the full wire bytes round-trip exactly |
| 5.2 | `test_packet_announce_wire_format_roundtrip` | `packet_build`, `packet_unpack` | RNS packet wire-format cross-impl interop on a SINGLE destination ANNOUNCE packet: announce payloads are not encrypted, so the full wire bytes round-trip; destination_type=SINGLE and packet_type=ANNOUNCE are recovered on the other impl |
| 5.3 | `test_packet_single_data_header_roundtrip` | `packet_build`, `packet_unpack` | RNS packet header round-trip on a SINGLE destination DATA packet: the header fields (flags, hops, destination_hash, context) parse identically across impls. Payload is encrypted-with-fresh-IV per call, so the wire bytes are non-deterministic and only the header is asserted |
| 5.4 | `test_packet_flags_byte_by_kind` | `packet_build`, `packet_unpack` | RNS flag byte composition for every packet kind buildable standalone (PLAIN/SINGLE × DATA/ANNOUNCE/LINKREQUEST/PROOF, both context_flag values): the flags byte raw[0] computed by RNS.Packet.pack composes to the same value both impls produce, and parse_flags decodes back to identical five-field tuples |
| 5.5 | `test_packet_hash_matches_across_impls` | `packet_build`, `packet_hash` | RNS packet hash (the transport-dedup key, computed over the hashable part with hops byte and HEADER_2 transport_id masked out) is byte-identical when both impls hash the same raw packet — the same call site impls hit for hashlist insertion |

## 6. Announce (5 tests)

**File:** `tests/test_announce.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 6.1 | `test_announce_build_validate_roundtrip` | `announce_build`, `announce_validate` | A well-formed RNS announce built by either impl validates as TRUE on the other — RNS.Identity.validate_announce accepts the cross-impl wire bytes including destination_hash, name_hash, random_hash and the Ed25519 signature over the (dest_hash + pubkey + name_hash + random_hash + ratchet + app_data) blob |
| 6.2 | `test_announce_with_app_data` | `announce_build`, `announce_validate` | An RNS announce carrying app_data round-trips cross-impl: app_data is part of what the signature covers, so a validator accepting the announce proves both impls agree on app_data inclusion in the signed scope |
| 6.3 | `test_announce_with_ratchet` | `announce_build`, `announce_validate` | An RNS announce carrying a ratchet round-trips cross-impl: context_flag=1, ratchet is 32 bytes inserted between random_hash and signature in the signed scope, and validate_announce accepts it as TRUE |
| 6.4 | `test_announce_validate_rejects_tampered_signature` | `announce_build`, `announce_validate` | Negative control: an announce whose Ed25519 signature byte is flipped is rejected by both impls (validate_announce returns False) — catches a validator that silently accepts a bad signature, which the propagation tests can't trigger |
| 6.5 | `test_announce_validate_rejects_tampered_destination_hash` | `announce_build`, `announce_validate` | Negative control: an announce whose destination_hash header byte is altered fails validation on both impls — validate_announce recomputes the expected destination_hash from the announce body and rejects the mismatch; catches a validator that trusts the header dest_hash without recomputing |

## 7. Ratchet (4 tests)

**File:** `tests/test_ratchet.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 7.1 | `test_ratchet_id` | `ratchet_id` | RNS ratchet ID (truncated_hash(ratchet_public)[:NAME_HASH_LENGTH//8] = 10 bytes) is byte-identical across impls |
| 7.2 | `test_ratchet_public_from_private` | `ratchet_public_from_private` | X25519 public key derivation from ratchet private key matches |
| 7.3 | `test_ratchet_encrypt_decrypt` | `identity_from_private_key`, `ratchet_public_from_private`, `ratchet_encrypt`, `ratchet_decrypt` | RNS ratchet encrypt/decrypt cross-impl round-trip: a message encrypted on either impl using RNS.Identity.encrypt(ratchet=...) decrypts to the original on the other via RNS.Identity.decrypt(ratchets=[...]) — the full ratcheted unicast path |
| 7.4 | `test_ratchet_encrypt_is_fresh_per_call` | `identity_from_private_key`, `ratchet_public_from_private`, `ratchet_encrypt` | Invariant: two ratchet encryptions of byte-identical plaintext for the same Identity + ratchet produce different ciphertext (RNS draws a fresh ephemeral X25519 key + AES IV per call) — deterministic ciphertext would leak plaintext equality |

## 8. Compression (3 tests)

**File:** `tests/test_compression.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 8.1 | `test_bz2_compress` | `bz2_compress` | SUT bz2 output begins with the bz2 magic header and self-roundtrips (compress then decompress returns input) |
| 8.2 | `test_bz2_decompress` | `bz2_compress`, `bz2_decompress` | SUT decompression of reference-compressed bytes recovers the original input |
| 8.3 | `test_bz2_cross_decompress` | `bz2_compress`, `bz2_decompress` | Cross-impl: SUT-compressed bytes decompressed by reference recovers the original input |

## 9. LXMF (2 tests)

**File:** `tests/test_lxmf.py`

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 9.1 | `test_lxmf_stamp_replay_across_message_ids_rejected` | `lxmf_stamp_workblock`, `lxmf_stamp_generate`, `lxmf_stamp_valid` | (slow) A stamp generated for message_id A does NOT validate as proof for message_id B — per-message PoW binding (closes lxmf-conformance#11) |
| 9.2 | `test_lxmf_stamp_generate_validate` | `lxmf_stamp_workblock`, `lxmf_stamp_generate`, `lxmf_stamp_valid` | (slow) Stamp workblock generation (HKDF expansion) matches; stamp generated by reference validates with SUT; stamp generated by SUT validates with reference |

## 10. LXMF Delivery (5 tests)

### `tests/lxmf/test_direct.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 10.1 | `test_direct_text_round_trip` | `send_direct`, `wait_for_inbox_count` | A short text LXMessage delivered via DIRECT (single-packet, link-based) arrives at the receiver with exact content, title, and source |
| 10.2 | `test_direct_with_file_attachment_multipacket` | `send_direct`, `wait_for_inbox_count` | A DIRECT LXMessage carrying a 2 KiB FIELD_FILE_ATTACHMENTS payload (forces multi-packet Resource transfer) arrives intact with exact filename and bytes |

### `tests/lxmf/test_opportunistic.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 10.3 | `test_opportunistic_text_round_trip` | `send_opportunistic`, `wait_for_inbox_count` | A single-packet OPPORTUNISTIC LXMessage arrives at the receiver with exact content, title, source, and empty fields |
| 10.4 | `test_opportunistic_with_image_field` | `send_opportunistic`, `wait_for_inbox_count` | An OPPORTUNISTIC LXMessage carrying a FIELD_IMAGE payload (format + ~64-byte image bytes) arrives with exact field shape |

### `tests/lxmf/test_propagation.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 10.5 | `test_propagated_delivery_round_trip` | `send_propagated`, `wait_for_stored_message_count`, `sync_inbound`, `poll_inbox` | A PROPAGATED LXMessage is stored exactly once on the lxmd propagation node, sync_inbound pulls exactly one message, and the receiver's inbox holds the matching content/title/source |

## 11. Wire Interop (25 tests)

### `tests/wire/test_announce_burst_throttle.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.1 | `test_burst_throttle_holds_subsequent_announces` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | When 12 rapid announces exceed IC_BURST_FREQ_NEW on an ingress-controlled TCP server, at least one is held by burst-mode throttling rather than reaching the downstream local client |

### `tests/wire/test_announce_steady_state.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.2 | `test_steady_state_announce_three_in_a_row` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | Three distinct announces from a TCP remote spaced 10s apart each reach the local client via the shared-instance master — no fanout regression after the first announce |

### `tests/wire/test_announce_via_shared_master.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.3 | `test_announce_local_to_remote` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | A shared-instance local client's announce reaches a TCP-attached remote peer through the master (egress: LocalServerInterface → TCPInterface) |
| 11.4 | `test_announce_remote_to_local` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `announce`, `poll_path` | A TCP remote's announce reaches a shared-instance local client through the master (ingress: TCPInterface → LocalServerInterface with master-as-transport_id spoof) |

### `tests/wire/test_ifac_interop.py` (3 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.5 | `test_announce_propagates_with_ifac` | `start_tcp_server`, `start_tcp_client`, `announce`, `poll_path` | An announce from a TCP client with matching IFAC credentials populates the server's path table (reticulum-kt#29 forward direction) |
| 11.6 | `test_announce_bidirectional` | `start_tcp_server`, `start_tcp_client`, `announce`, `poll_path` | Reverse-direction IFAC: server-initiated announce reaches the TCP client (exercises TCPServerInterface child-interface IFAC inheritance) |
| 11.7 | `test_mismatched_ifac_blocks_announce` | `start_tcp_server`, `start_tcp_client`, `announce`, `poll_path` | Negative control: when network_names match but passphrases differ, IFAC verification rejects the announce and no path is learned |

### `tests/wire/test_link_multihop.py` (3 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.8 | `test_link_establishes_multihop` | `start_tcp_server`, `start_tcp_client`, `listen`, `announce`, `link_open` | A 2-hop Link (sender → TCP transport → receiver) establishes with a 16-byte link_id within the establishment timeout |
| 11.9 | `test_link_data_reaches_receiver_multihop` | `link_open`, `link_send`, `link_poll` | Bytes sent over an established multi-hop Link arrive at the receiver intact — catches HEADER_2 transport_id mis-wrapping at the sender |
| 11.10 | `test_link_data_roundtrip_multiple_packets` | `link_open`, `link_send`, `link_poll` | Five back-to-back link DATA packets (16-48 bytes each) all arrive at the receiver as a multiset — catches 'only first packet routes' regressions |

### `tests/wire/test_link_via_shared_master.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.11 | `test_link_establishes_via_shared_master` | `start_tcp_server`, `start_tcp_client`, `start_local_client`, `listen`, `announce`, `poll_path`, `link_open` | A Link from a shared-instance local client to a TCP-attached destination establishes successfully via the master — catches the H1→H2 synthesis link_id-desynchronization bug |

### `tests/wire/test_path_discovery.py` (5 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.12 | `test_path_response_reuses_cached_announce` | `start_tcp_server`, `start_tcp_client`, `announce`, `request_path`, `poll_path`, `read_path_random_hash` | When B answers a path request for a destination it cached, the re-emitted announce's random_hash bytes are byte-identical to the cached announce's (no regeneration on re-emit) |
| 11.13 | `test_discover_paths_for_mode_gating` | `start_tcp_server`, `start_tcp_client`, `request_path`, `has_discovery_path_request` | B forwards path requests for unknown destinations only when its receiving interface's mode is in DISCOVER_PATHS_FOR={access_point, gateway, roaming}, gated correctly for every parametrized mode |
| 11.14 | `test_roaming_no_answer_when_next_hop_on_same_interface` | `start_tcp_server`, `start_tcp_client`, `announce`, `request_path`, `tx_bytes`, `read_path_entry` | Under ROAMING mode, B refuses to answer a path request when the cached path's next-hop is the same interface that received the PR (loop-prevention rule fires) |
| 11.15 | `test_roaming_loop_prevention_positive_companion` | `start_tcp_server`, `start_tcp_client`, `announce`, `request_path`, `tx_bytes`, `read_path_entry` | Under FULL mode (companion to the ROAMING test) B does answer the PR — proves the ROAMING test isn't vacuously passing because B never answers |
| 11.16 | `test_mode_specific_path_expiry_assignment` | `start_tcp_server`, `start_tcp_client`, `announce`, `read_path_entry` | Stored path-entry expiry equals timestamp + the per-mode constant (PATHFINDER_E for FULL, AP_PATH_TIME for ACCESS_POINT, ROAMING_PATH_TIME for ROAMING) within jitter |

### `tests/wire/test_resource_invariants.py` (5 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.17 | `test_resource_identity_is_fresh_per_construction` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: two Resources built from byte-identical payloads get different identities — RNS draws a fresh random_hash per construction (Resource.py:193), so the hash never leaks that two payloads were equal |
| 11.18 | `test_resource_encrypted_output_is_fresh_per_construction` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: two Resources built from byte-identical payloads produce entirely different encrypted parts — a fresh random prefix on the data stream (Resource.py:158/165) plus per-construction Link encryption keeps every chunk's ciphertext unique |
| 11.19 | `test_resource_truncated_hash_is_consistent_with_full_hash` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: a Resource's truncated_hash is its own full hash truncated to 16 bytes — not an independently derived value — catching an implementation that computes the two from different inputs |
| 11.20 | `test_resource_expected_proof_is_full_length` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: a Resource's expected_proof is a full-length 32-byte SHA-256 hash — directly catching the proof being truncated, which is the exact drift the deleted hand-rolled resource_proof command had |
| 11.21 | `test_resource_hashmap_has_one_entry_per_part` | `start_tcp_server`, `start_tcp_client`, `listen`, `link_open`, `resource_create` | Invariant: a Resource's hashmap carries exactly one 4-byte map hash per part — len(hashmap) == num_parts x MAPHASH_LEN — for a multi-part resource, catching a mis-sized or mis-counted hashmap |

### `tests/wire/test_resource_multihop.py` (4 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 11.22 | `test_small_resource_multihop` | `link_open`, `resource_send`, `resource_poll` | A sub-MDU 256-byte Resource transfer over a multi-hop Link round-trips exactly through RESOURCE_ADV → REQ → DATA → PROOF |
| 11.23 | `test_chunked_resource_multihop` | `link_open`, `resource_send`, `resource_poll` | A 16 KiB Resource (multi-packet chunking, mirroring Columba image-send size) round-trips intact over a multi-hop Link |
| 11.24 | `test_chunked_resource_with_ifac_multihop` | `link_open`, `resource_send`, `resource_poll` | A 16 KiB Resource round-trips intact over an IFAC-protected multi-hop Link — exercises per-packet IFAC masking on Resource chunks (Columba production config) |
| 11.25 | `test_large_resource_multihop` | `link_open`, `resource_send`, `resource_poll` | A 256 KiB Resource (~32 chunks) round-trips intact, stress-testing back-to-back link DATA transmission and reassembly |

## 12. Transport Behavior (3 tests)

### `tests/behavioral/test_hop_increment.py` (2 tests)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 12.1 | `test_hop_increment_on_receive` | `start`, `attach_mock_interface`, `inject`, `drain_tx` | An announce received with wire_hops=N is re-emitted on another interface with hops=N+1 (the per-hop +1 increment rule) |
| 12.2 | `test_hop_increment_when_transport_disabled` | `start`, `attach_mock_interface`, `inject`, `drain_tx` | With enable_transport=False and no local clients, received announces are NOT re-emitted on any other interface (the transport gate enforces) |

### `tests/behavioral/test_path_replacement.py` (1 test)

| # | Test | Commands Used | What It Verifies |
|---|------|--------------|-----------------|
| 12.3 | `test_stale_path_response_does_not_overwrite_fresh_path` | `start`, `attach_mock_interface`, `inject`, `drain_tx` | A stale PATH_RESPONSE announce (older emission timestamp, novel random_blob, more hops) does NOT replace a fresh direct-path entry — observable via the retransmitted announce's hops value |

