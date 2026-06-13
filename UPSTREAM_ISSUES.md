# Upstream issues to file

These are bugs that the Reticulum conformance suite has surfaced but **cannot fix
inside this repository** — they live in upstream RNS or in the systems-under-test
(SUTs). They are written here as ready-to-file issue drafts so the maintainer can
open them against the correct repositories (per the "file it the same day" rule).

Each entry: **affected repo/version**, **root cause (file:line)**, **repro**, and a
**suggested fix**. All facts below were validated against the installed ground-truth
stack: **RNS 1.3.1 + LXMF 0.9.9** at `~/.local/lib/python3.14/site-packages`.

---

## 1. `Reticulum._synthesize_interface` raises `KeyError('mode')` for `interface_mode = gateway`

- **Repo / version:** [markqvist/Reticulum](https://github.com/markqvist/Reticulum) —
  confirmed in **1.3.1** (`RNS/Reticulum.py`); per the conformance suite's working
  note this same defect is present in **1.1.3** as well.
- **Severity:** Medium — any config that sets `interface_mode = gateway` (or `gw`)
  on an interface, *without also* setting the legacy `mode` key, crashes Reticulum
  startup with an uncaught `KeyError`.

### Root cause

`RNS/Reticulum.py`, `_synthesize_interface`, the `interface_mode` branch
(lines **689–702**, gateway test at **line 701**):

```python
if "interface_mode" in c:
    c["interface_mode"] = str(c["interface_mode"]).lower()
    if c["interface_mode"] == "full":
        interface_mode = Interface.Interface.MODE_FULL
    elif c["interface_mode"] == "access_point" or c["interface_mode"] == "accesspoint" or c["interface_mode"] == "ap":
        interface_mode = Interface.Interface.MODE_ACCESS_POINT
    elif c["interface_mode"] == "pointtopoint" or c["interface_mode"] == "ptp":
        interface_mode = Interface.Interface.MODE_POINT_TO_POINT
    elif c["interface_mode"] == "roaming":
        interface_mode = Interface.Interface.MODE_ROAMING
    elif c["interface_mode"] == "boundary":
        interface_mode = Interface.Interface.MODE_BOUNDARY
    elif c["mode"] == "gateway" or c["mode"] == "gw":     # <-- BUG: reads c["mode"]
        interface_mode = Interface.Interface.MODE_GATEWAY
```

Inside the `if "interface_mode" in c:` block, the final `elif` for the gateway
mode dereferences `c["mode"]` instead of `c["interface_mode"]`. When a config
specifies only `interface_mode` (the documented, current key) and the value is
`gateway`/`gw`, none of the preceding `interface_mode` comparisons match, control
reaches line 701, and `c["mode"]` raises `KeyError` because that key is absent.

The parallel `elif "mode" in c:` fallback branch (lines **704–717**) is internally
consistent and correctly tests `c["mode"] == "gateway"` at line 716 — so the bug is
isolated to the copy/paste in the `interface_mode` branch only.

### Repro

```bash
python3 - <<'PY'
# Minimal reproduction of the buggy branch in Reticulum._synthesize_interface
c = {"interface_mode": "gateway"}          # only interface_mode set, no "mode"
c["interface_mode"] = str(c["interface_mode"]).lower()
if c["interface_mode"] == "full":          pass
elif c["interface_mode"] in ("access_point","accesspoint","ap"): pass
elif c["interface_mode"] in ("pointtopoint","ptp"): pass
elif c["interface_mode"] == "roaming":     pass
elif c["interface_mode"] == "boundary":    pass
elif c["mode"] == "gateway" or c["mode"] == "gw":  # KeyError('mode')
    pass
PY
# -> KeyError: 'mode'
```

End-to-end this manifests as a crash on `RNS.Reticulum()` startup with a config
file containing:

```ini
[[Some Interface]]
  type = TCPServerInterface
  listen_ip = 0.0.0.0
  listen_port = 4242
  interface_mode = gateway
```

### Suggested fix

Change line 701 to test the correct key:

```python
elif c["interface_mode"] == "gateway" or c["interface_mode"] == "gw":
    interface_mode = Interface.Interface.MODE_GATEWAY
```

### Conformance-suite workaround (so reviewers can see what we did)

`reference/wire_tcp.py` (`_write_ifac_ini`) deliberately writes `mode = <name>`
instead of `interface_mode = <name>` to route through the internally-consistent
`elif "mode" in c:` fallback and avoid the buggy code path entirely. The MODE_*
constant assigned is identical, so semantics are unchanged. Once upstream fixes
line 701, the suite can switch to the documented `interface_mode` key.

---

## 2. IFAC `ifac_key` derivation drops the final `full_hash` over the netname/netkey origin (SUT regression surface — issue #29)

- **Repos / versions:** the three SUTs validated by this suite —
  **reticulum-kt** (Kotlin), **reticulum-swift** (Swift), and
  **microReticulum** (C++). All three historically copied the same IFAC
  key-derivation mistake. Canonical correct behavior is **RNS 1.3.1**
  (`RNS/Reticulum.py`). Originally surfaced as **reticulum-kt issue #29**.
- **Severity:** High for interop — a wrong `ifac_key` produces wire bytes that a
  correct RNS peer's IFAC unmasker **silently rejects** (the packet is dropped, no
  error surfaced), so an IFAC-protected link between a buggy SUT and stock RNS
  simply never passes traffic, with no diagnostic.

### Root cause

The reference (correct) chain in `RNS/Reticulum.py`, `_synthesize_interface`
(lines **898–916**):

```python
ifac_origin = b""
if interface.ifac_netname != None:
    ifac_origin += RNS.Identity.full_hash(interface.ifac_netname.encode("utf-8"))
if interface.ifac_netkey != None:
    ifac_origin += RNS.Identity.full_hash(interface.ifac_netkey.encode("utf-8"))

ifac_origin_hash = RNS.Identity.full_hash(ifac_origin)        # <-- the final full_hash
interface.ifac_key = RNS.Cryptography.hkdf(
    length=64,
    derive_from=ifac_origin_hash,                             # <-- HKDF over the HASH of the origin
    salt=self.ifac_salt,                                      # Reticulum.IFAC_SALT
    context=None,
)
interface.ifac_identity  = RNS.Identity.from_bytes(interface.ifac_key)
interface.ifac_signature = interface.ifac_identity.sign(RNS.Identity.full_hash(interface.ifac_key))
```

The correct derivation is:

```
ifac_origin       = full_hash(netname) || full_hash(netkey)     # concatenation of the two SHA-256 digests
ifac_origin_hash  = full_hash(ifac_origin)                      # <-- the step that was dropped
ifac_key          = HKDF(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT)
```

The SUT bug was to feed the **concatenation `ifac_origin` directly** into HKDF's
`derive_from`, skipping the final `full_hash(ifac_origin)` wrapping. Because HKDF
is deterministic and the salt (`Reticulum.IFAC_SALT =
adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8`) is shared, the
two implementations agree on everything *except* this one hash step, yielding a
divergent 64-byte `ifac_key` → divergent `ifac_identity` → divergent IFAC
signature/mask. The receiving RNS recomputes the expected IFAC and the comparison
`ifac == expected_ifac` (`RNS/Transport.py:1432`) fails, so the de-masked packet is
discarded without error.

### Repro

```bash
python3 - <<'PY'
import RNS
from RNS.Cryptography import hkdf
IFAC_SALT = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
netname, netkey = "conformance-net", "test-pass"

origin      = RNS.Identity.full_hash(netname.encode()) + RNS.Identity.full_hash(netkey.encode())
origin_hash = RNS.Identity.full_hash(origin)

correct = hkdf(length=64, derive_from=origin_hash, salt=IFAC_SALT, context=None)  # RNS 1.3.1
buggy   = hkdf(length=64, derive_from=origin,      salt=IFAC_SALT, context=None)  # missing final full_hash
print("correct ifac_key[:8] =", correct[:8].hex())
print("buggy   ifac_key[:8] =", buggy[:8].hex())
print("keys differ          =", correct != buggy)
PY
# correct ifac_key[:8] = c008469aff09d54d
# buggy   ifac_key[:8] = b2be7d5183e94d52
# keys differ          = True
```

End-to-end: two RNS instances with matching `network_name`/`passphrase` exchange
IFAC-masked announces fine; swap one side for an SUT that omits the final hash and
the announce never crosses the boundary (silent drop).

### Suggested fix (each SUT)

Insert the missing `full_hash` over the concatenated origin before HKDF:

```
ifac_origin_hash = full_hash( full_hash(netname) || full_hash(netkey) )
ifac_key         = HKDF(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT)
```

Add a known-answer test pinning `(netname, passphrase) -> ifac_key` (and the
resulting Ed25519 IFAC signature) against stock RNS.

### Conformance-suite coverage note

The remediation re-pins the real `(netname, passphrase) -> ifac_key` chain (the
issue-#29 golden vector: HKDF + `Identity.from_bytes` + Ed25519 IFAC signature) so
a self-consistent-but-wrong derivation adopted by *both* test sides can no longer
hide behind a boolean "did the announce cross the boundary" check. Without this
byte-level pin, the regression is invisible to an end-to-end-only IFAC test.

---

## 3. reticulum-kt path-table replacement is missing the emission-time gate (stale path overwrites fresh)

- **Repo / version:** [reticulum-kt](https://github.com/) (Kotlin SUT). Tracked
  upstream in kt commit **`25ae62c`**. Canonical correct behavior is **RNS 1.3.1**
  `RNS/Transport.py` (announce-handling path-table update). The kt port mirrors the
  Python `Transport` region around **lines 1620–1681** of the version it was ported
  from.
- **Severity:** High — without the gate, a **stale** announce / PATH_RESPONSE (older
  emission timestamp) that arrives with an equal-or-lower hop count will overwrite a
  **fresh** path-table entry, corrupting the next-hop/hop-count for a destination and
  silently degrading or black-holing routing.

### Root cause

RNS gates every path-table replacement on the announce **emission timestamp**
(derived from the announce `random_blob`), not just hop count. The relevant logic in
**RNS 1.3.1 `RNS/Transport.py`** (the `should_add` computation, lines **1743–1823**):

- Equal-or-lower hop count (line **1762**): replace only if the announce is *not* a
  replay **and** `announce_emitted > path_timebase` (line **1769**) — i.e. the
  incoming announce was emitted *more recently* than the entry already held.
- Higher hop count (lines **1774–1823**): ignore the announce **unless** the existing
  path has expired (line **1790**) **or** the incoming emission is strictly more
  recent than the stored emission (`announce_emitted > path_announce_emitted`, line
  **1806**).

The reticulum-kt path-replacement code omitted this emission-time comparison, so it
would accept a stale path as long as the hop count was acceptable — exactly the
condition the gate exists to prevent.

### Repro (behavioral)

1. Inject announce **A** for destination `D` with hops=1 and a *recent* emission
   timestamp. Path table records `D -> hops 1`, fresh emission.
2. Inject announce **B** for the same `D` with hops=1 (or fewer) but an *older*
   emission timestamp (a replayed/stale path response).
3. Correct (RNS): `B` is rejected by the emission-time gate; `path_table[D]` still
   reflects `A` (fresh). Buggy (kt pre-`25ae62c`): `B` overwrites the entry.
4. Observe via a `path_request` answer for `D` and read the PATH_RESPONSE hop count /
   path-table emission — a correct impl reports the fresh path, a buggy one reports
   the stale one.

### Suggested fix

Port the RNS emission-time gate into the kt path-table update: before replacing an
existing entry, compare the incoming announce emission timestamp against the stored
path's timebase and only replace when the incoming announce is strictly more recent
(or the stored path has expired / been marked unresponsive), in addition to the
existing hop-count check. This is what kt commit `25ae62c` addresses.

### Conformance-suite coverage note

The behavioral path-replacement test (`tests/behavioral/test_path_replacement.py`)
is being corrected so that it actually observes the **path table** (via a
`path_request` answer asserting the fresh hop count) rather than the announce-table
retransmit it previously read. The previous observable passed even when cross-impl
path replacement was fully broken — i.e. it could not catch this exact reticulum-kt
divergence. See re-audit findings **N-H1 / N-H2 / H5**.

---

## 4. `Transport` blackhole check on path-table reload compares an `Identity` object against identity-hash bytes — blackholed paths always reload

- **Repo / version:** [markqvist/Reticulum](https://github.com/markqvist/Reticulum) —
  confirmed in **1.3.1** (`RNS/Transport.py`).
- **Severity:** Low/medium — the blackhole mechanism's path-table-reload guard is a
  no-op. Paths to blackholed identities survive a restart and are re-inserted into
  the path table; the runtime blackhole filters still apply to *new* traffic, so
  this is a persistence-path bypass of the reload skip only.

### Root cause

`RNS/Transport.py`, path-table load in `start()` (lines **313–315**):

```python
if len(Transport.blackholed_identities) > 0:
    path_identity = RNS.Identity.recall(destination_hash, _no_use=True)
    if path_identity in Transport.blackholed_identities: blackholed = True
```

`Identity.recall()` returns an `RNS.Identity` **object** (or `None`), but
`Transport.blackholed_identities` is a dict keyed by identity-hash **bytes**
(`blackhole_identity()`, lines 3417–3419, inserts `identity_hash` keys; the
type-correct membership idiom is used elsewhere, e.g. line 3497:
`associated_identity.hash in Transport.blackholed_identities`). `Identity`
defines no `__eq__`/`__hash__`, so default object identity applies and an
`Identity` instance can never equal a `bytes` dict key — the membership test is
always `False`, `blackholed` is never set, and the entry is loaded anyway.

### Repro

```bash
python3 - <<'PY'
import RNS
ident = RNS.Identity()
blackholed_identities = {ident.hash: {"until": None}}   # how Transport keys the table
recalled = ident                                         # stands in for Identity.recall(...)
print(recalled in blackholed_identities)                 # False — object vs bytes keys
print(recalled.hash in blackholed_identities)            # True  — the intended check
PY
```

On a live node: blackhole an identity (`Transport.blackhole_identity(h)`), let a
path to one of its destinations be saved to the path table, restart — the path
entry is reloaded despite the blackhole (the `blackholed == False` branch at
line 318 runs).

### Suggested fix

```python
if len(Transport.blackholed_identities) > 0:
    path_identity = RNS.Identity.recall(destination_hash, _no_use=True)
    if path_identity != None and path_identity.hash in Transport.blackholed_identities:
        blackholed = True
    del path_identity
```

(Also handles the `recall()`-returns-`None` case, which today only "works" by
accident of the same broken comparison.)

_Found 2026-06-10 during the conformance-suite completeness re-evaluation
(discovery/blackhole subsystem analysis); see CONFORMANCE_COMPLETENESS_V2.md §8._

---

_Validated against RNS 1.3.1 + LXMF 0.9.9 (`~/.local/lib/python3.14/site-packages`).
Line numbers refer to those installed sources; cross-check before filing if the
upstream HEAD has since shifted._
