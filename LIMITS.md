# Scope Limits — what this conformance harness cannot certify

This suite verifies an implementation's **byte-level cryptography/encoding**
and its **wire-protocol interop as an endpoint and single-hop transport**
against real Python RNS 1.3.1 over loopback TCP. A green run is strong
evidence of correctness for everything it exercises — but the harness
architecture **cannot** observe the behaviors below. They are out of scope by
construction, not merely untested; an implementer must validate them by other
means. (Identified during the multi-agent completeness build; see
CONFORMANCE_COMPLETENESS.md §2 for the architectural analysis.)

## Architectural ceiling (cannot be observed in this harness)

- **Real-time timing**: retransmit/backoff intervals, RTT-derived timers,
  keepalive/stale watchdog cadence, announce-cap pacing, ingress/egress rate
  limiters, path/tunnel/record staleness culling. The harness uses backdating
  hooks for the *decision logic*, but the wall-clock schedule itself is unobserved.
- **Multi-hop (>1 transport hop)**: per-hop MTU signalling across heterogeneous
  next-hop interface types and recursive path discovery beyond one relay.
  Topologies max out at one transport hop. (The `remaining_hops > 1` mid-path
  HEADER_2-rewrite *decision* is KAT-tested at the rule level — only its actual
  execution on a >1-hop wire path is out of scope.)
- **Packet loss / reorder / duplication on the wire**: loopback TCP is lossless
  and ordered; re-request-after-loss and reorder tolerance are only inject-simulated.
- **Persistence across restart**: transport/known-destination/blackhole tables and
  transport-identity stability across process restarts. Every fixture spawns fresh.
- **Concurrency**: concurrent links/channels/resources/announce-under-load
  (`BridgeClient` is one-request-in-flight by design).
- **Non-TCP data planes**: AutoInterface multicast peering/data, UDPInterface,
  BackboneInterface, KISS/serial/RNode device I/O, TCP reconnect — all open real
  sockets/threads/devices the harness does not stand up.
- **SUT-bridge honesty**: the suite trusts that a SUT's bridge delegates to the
  SUT library; only assertions anchored on the *reference peer's* side of a
  heterogeneous exchange are structurally honest.

## Specific RNS 1.3.1 behaviors deferred as out-of-scope here

These were reached during the completeness build and confirmed to require one of
the ceilings above (sockets/threads, real timing, >1 hop, persistence, or a live
interface instance):

- **channel_buffer**: `receiver-proves-channel-packets`, `tx-window-enforcement`, `window-rate-upgrade-fast`
- **discovery_resolver**: `discovery-record-persistence-format`
- **identity**: `ratchet-expiry-30d` (the `RATCHET_EXPIRY` received+30d discard needs a
  back-dated received-ratchet file; RNS's only writer, `Identity._remember_ratchet`,
  stamps `received = time.time()` and exposes no clock-injection API — the real-timing
  ceiling). The *non-expiry* IDENTITY-side ratchet persistence (atomic temp-file write,
  cold-cache `get_ratchet` load round-trip, `_clean_ratchets` not-in-use cleanup) and the
  whole-table `known_destinations` save/recombine/load round-trip + 5-element record shape
  ARE covered (`test_identity_received_ratchet_persistence`,
  `test_known_destinations_save_reload_roundtrip`); only these load-time *rejection* sub-rules
  remain deferred for the same reason: `ratchet-persistence-format`'s expiry + malformed-size
  (`len != RATCHETSIZE//8`) branches and `known-destinations-persistence`'s 16-byte-key-skip /
  legacy 4->5-element upgrade branches each require a hand-built malformed on-disk file, which
  the delegation policy rejects. `known-destinations-pruning` is in-memory `_retain`/`_used`
  table hygiene — local-only, no wire-observable hook.
- **interfaces**: `announce-queue-ordering`, `auto-discovery-token-format-validation-reject`, `auto-mcast-group-derivation`, `backbone-wire-equivalence`, `ingress-limit-path-requests`, `local-client-ingress-exempt`, `local-origin-announce-bypass`, `spawned-announce-cap-default`
- **link**: `mtu-clamp-in-transport`, `proof-hops-check`, `rtt-packet-handling`, `transport-lrproof-relay-validation`
- **reticulum_config**: `announce-cap-default-and-queueing`, `announce-rate-limiting`, `hw-mtu-autoconfigure-tiers`, `ifac-recompute-per-hop`, `ingress-control-announce-hold`, `shared-instance-defaults`
- **transport_announce**: `announce-bandwidth-cap`, `announce-ingress-limiting`, `path-table-persistence-format`, `pr-ingress-egress-frequency-limits`, `tunnel-path-tracking-and-restore`

## microReticulum (torlando-tech fork) — certified surface and capability gaps

The microReticulum bridge (`impls/microreticulum/`, gated by
`.github/workflows/microreticulum.yml`) is built against the torlando-tech
**pyxis** pinned fork (`deps/microReticulum`). It compiles only the fork's
`Cryptography/*` sources plus `Bytes`/`Log`/`Crc` (CMakeLists), so it certifies
microReticulum's **stateless** surface: the RNS crypto primitives plus the
hand-assembled wire/identity/announce/ratchet/token/destination-hash/framing/IFAC
encoders that delegate to those primitives. The full Packet/Destination/Transport/
Identity/Channel/Resource classes (which pull in MsgPack and a live Transport
state machine) are **not compiled**.

Everything the suite drives outside the gaps below runs and passes against real
Python RNS 1.3.1. The gated run scopes out **only** the families the fork
genuinely cannot support (capability gaps — not hidden failures):

- **Discovery module** (`test_discovery_*`): the fork has no `RNS.Discovery`
  module, so the whole `discovery_*` surface (announce appdata, stamp,
  store/inject, address/name validation, stamp cost) is unrepresentable.
- **Config / interface layer** (`test_config_parse_hooks`, `test_reticulum_config_v2`,
  `test_interfaces_v2`, `test_interfaces_hooks::interface_hw_mtu_per_type`,
  and the `config_parse_interface`/`discovery_stamp`-backed `test_docs_normative_v2`
  literals): the fork has no config parser and no interface MTU+IFAC tier tables
  (`config_parse_interface`, `interface_optimise_mtu`, `interface_hw_mtu`,
  `interface_default_ifac_size`).
- **Packet / Destination object machine** (`test_packet`, `test_packet_completeness`,
  `test_packet_v2`, `test_reticulum_config_completeness`,
  `test_destination_completeness_more`, the packet-machine tests in
  `test_destination`/`test_packet_hooks`, and `test_destination_hooks`):
  `packet_build`/`packet_resend_observe`/`destination_*` drive the real
  `RNS::Packet` + `RNS::Destination` + Transport machine, which is MsgPack-backed
  and excluded from the crypto-only build. The stateless `packet_pack`/`unpack`,
  `packet_constants`, `packet_context_constants` and `destination_hash`
  primitives DO run and pass.
- **Channel/buffer wire framing** (`test_channel_buffer_hooks`):
  `wire_buffer_pack` / `wire_channel_envelope_pack` are MsgPack-framed (Tier 2B).
- **Stateful Identity machine** (`test_identity_hooks::remember_public_key_length_gate`,
  `::keyless_identity_ops_raise_keyerror`): `identity_remember` /
  `identity_keyless_op` need `RNS::Identity`'s known-destinations store and the
  `create_keys=False` runtime state — the same gap reticulum-kt documents as an
  xfail. The bridge derives identities from Cryptography primitives only.
- **Fork HKDF divergence** (`test_crypto::hkdf_with_info`,
  `::hkdf_rfc5869_test_case_1`, `test_crypto_v2::hkdf_accepts_empty_bytes_ikm`):
  microReticulum's HKDF **ignores the `info` parameter** and **rejects
  empty-bytes `ikm`**, diverging from RFC 5869 on those inputs. This is a
  correctness gap in the fork's standalone HKDF. (Identity/Token/ratchet all use
  empty-`info` HKDF and are byte-equivalent — see passing `test_token`,
  `test_ratchet`, `test_identity`.)

Plus the always-out Tier-2B networking surface shared with the architectural
ceiling above: `wire/`, `behavioral/`, `lxmf/`, `test_lxmf.py` (no networking /
LXMF router) and `test_compression.py` (libbz2 stripped from the build).
