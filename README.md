# Reticulum Conformance Suite

A cross-implementation conformance test suite for [Reticulum](https://reticulum.network/).
It pins a new Reticulum implementation against the **RNS 1.3.1** reference,
byte-for-byte where the wire format demands it, by driving both the reference
and the system-under-test (SUT) through a uniform **bridge** protocol and
comparing their behavior on the same inputs.

> **Status:** experimental / WIP. Originally built to certify the Swift and
> Kotlin implementations. The reference legs are green; bringing a SUT bridge
> to the full command surface is the gating work (see
> `CONFORMANCE_COMPLETENESS_V3.md`).

---

## What a green run does — and does not — claim

A SUT that implements the full bridge command surface and passes
`pytest tests/ --impl=<name>` green supports exactly this claim, and no more:

> *Byte-accurate on RNS 1.3.1 cryptography, identity, wire formats, and the
> announce / path / link / channel / buffer / resource / IFAC protocol state
> machines, as an endpoint and one-hop transport over TCP.*

It does **not** claim "complete and accurate re-implementation of Reticulum."
By harness architecture (see `LIMITS.md`) the following are permanently **out
of scope** and are never asserted against a SUT:

- wall-clock timing schedules (announce pacing, ratchet 30-day expiry, …),
- execution beyond one transport hop (multi-hop forwarding/link reception),
- real packet loss / reordering / a lossy physical layer,
- persistence across process restart,
- concurrency / threading races,
- any non-TCP data plane (RNode/LoRa, I2P, UDP discovery frames, the
  shared-instance RPC wire plane).

Any certification language MUST carry the `LIMITS.md` disclaimer.

---

## Running the suite

```bash
# Against a specific implementation (a certification run):
python3 -m pytest tests/ --impl=kotlin

# Reference-as-SUT sanity run (reference vs reference — proves the suite,
# says nothing about any SUT):
python3 -m pytest tests/ --reference-only
```

**There is no silent fallback.** With neither `--impl` nor `--reference-only`,
the suite parametrizes in every registered impl whose bridge is *built on disk*;
if none is built, collection hard-fails rather than quietly self-certifying as
reference-vs-reference (V3 §7.4). `--reference-only` is the explicit escape for a
reference sanity run.

Most tests are parametrized cross-impl as `[<server>-to-<client>]` (e.g.
`reference-to-kotlin`, `kotlin-to-reference`, `kotlin-to-kotlin`) so both
directions of every wire interaction are exercised.

### Pointing the suite at your bridge

Each implementation has a default bridge command in `conftest.py`
(`BRIDGE_COMMANDS`) and a per-impl env-var override (`PER_IMPL_CMD_ENV`):

| impl | env var | default |
|---|---|---|
| reference | `CONFORMANCE_REFERENCE_BRIDGE_CMD` | `python3 reference/bridge_server.py` |
| kotlin | `CONFORMANCE_KOTLIN_BRIDGE_CMD` | `java -jar ../reticulum-kt/.../ConformanceBridge.jar` |
| swift | `CONFORMANCE_SWIFT_BRIDGE_CMD` | `../reticulum-swift-lib/.build/release/ConformanceBridge` |
| microreticulum | `CONFORMANCE_MICRORETICULUM_BRIDGE_CMD` | `impls/microreticulum/build/microReticulumBridge` |

(The legacy `CONFORMANCE_BRIDGE_CMD` applies to *every* peer and breaks
cross-impl parametrization; it is deprecated and emits a warning.)

---

## The implementer contract — what a bridge must do

A bridge is a long-lived subprocess speaking line-delimited JSON on stdin/stdout:
one request `{"id": "...", "command": "...", "params": {...}}` per line in, one
`{"id": "...", "success": true, ...}` (or `{"success": false, "error": "..."}`)
line out. See `reference/bridge_server.py`, `reference/behavioral_transport.py`,
and `reference/wire_tcp.py` for the canonical reference bridge.

1. **Implement the full command surface.** The authoritative list is every
   `.execute("<command>", ...)` literal the suite invokes. Measure your gap with:

   ```bash
   python3 tools/kotlin_gap.py            # exit 1 while any command is missing
   python3 tools/kotlin_gap.py --list     # the per-command breakdown
   ```

   (The tool is kotlin-pathed by default; point `--kt-dir` elsewhere or adapt
   for another impl.) The command families are: pure-crypto/identity/packet
   primitives, the `behavioral_*` MockInterface transport hooks, and the
   `wire_*` real-TCP-loopback layer (announce/path/link/channel/buffer/resource/
   IFAC). A missing command surfaces as a loud `BridgeError`, never a silent pass.

2. **Honor the delegation contract (trust boundary).** Every bridge command MUST
   drive your *real* library, not reconstruct the answer the test wants:
   - primitive commands are a thin wrapper over your real crypto/identity/packet
     code;
   - `behavioral_*` / `wire_*` commands drive your real Transport/Link/Resource/
     Channel state machines;
   - adversarial injectors MUST damage a *genuine* library-produced artifact, not
     hand-assemble protocol bytes.

   The suite verifies the *reference* bridge's delegation mechanically
   (`tools/audit_bridge_delegation.py`) but **cannot** see inside your bridge —
   SUT-side delegation honesty is a trust boundary, stated plainly in `LIMITS.md`.
   A bridge that fakes outputs passes while certifying nothing.

3. **Units & wire fidelity.** Timestamps/intervals cross the bridge boundary in
   **epoch seconds (float)**; convert at your boundary if you store millis. Hex
   strings carry raw bytes. Where a test pins a byte layout or an exact value
   (e.g. the AES-256 GROUP key is exactly 64 bytes, the default discovery stamp
   cost is 14), match it exactly.

4. **Keyed xfails for genuine, documented divergences only.** If a behavior is
   legitimately unimplemented, key the xfail to your impl (`sut_impl_name`
   fixture) AFTER asserting the reference arm, with an issue reference — never
   weaken the reference pinning.

---

## Repository layout

- `tests/` — the conformance tests (`tests/wire/`, `tests/behavioral/`, plus the
  primitive suites). `integration/` drives real in-process RNS (pipe / three-node
  sessions) and runs reference-only.
- `reference/` — the canonical reference bridge (RNS 1.3.1).
- `tools/` — `kotlin_gap.py` (command-surface gap), `audit_bridge_delegation.py`
  and `check_conformance_decorated.py` (honesty gates).
- `CONFORMANCE_COMPLETENESS_V3.md` — the current completeness evaluation and the
  scoped definition of "yes".
- `LIMITS.md` — the architectural ceiling and trust boundaries (normative for any
  certification claim).
