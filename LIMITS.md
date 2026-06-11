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
- **interfaces**: `announce-queue-ordering`, `auto-discovery-token-format-validation-reject`, `auto-mcast-group-derivation`, `backbone-wire-equivalence`, `ingress-limit-path-requests`, `local-client-ingress-exempt`, `local-origin-announce-bypass`, `spawned-announce-cap-default`
- **link**: `mtu-clamp-in-transport`, `proof-hops-check`, `rtt-packet-handling`, `transport-lrproof-relay-validation`
- **reticulum_config**: `announce-cap-default-and-queueing`, `announce-rate-limiting`, `hw-mtu-autoconfigure-tiers`, `ifac-recompute-per-hop`, `ingress-control-announce-hold`, `shared-instance-defaults`
- **transport_announce**: `announce-bandwidth-cap`, `announce-ingress-limiting`, `path-table-persistence-format`, `pr-ingress-egress-frequency-limits`, `tunnel-path-tracking-and-restore`
