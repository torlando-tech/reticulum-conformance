"""Resource construction invariants — properties every RNS.Resource must
hold, checked by building real Resource objects on a real Link and reading
back what the implementation computed.

These replace the deleted tests/test_resource.py, whose bridge commands
hand-rolled the hash compositions (sha256 over hand-assembled byte strings)
instead of delegating to RNS.Resource. Two of them had silently drifted
from upstream — wrong operand order, a truncated proof — and the suite
stayed green because it was testing the bridge's hand-rolled copy, not the
implementation. The honest replacement is the wire_resource_create command:
the bridge constructs a real RNS.Resource (real Link, full __init__,
advertise=False so nothing hits the wire) and reports the attributes the
object computed for itself. Nothing is recomputed in the bridge or here.

Two kinds of property are checked:

  * Freshness. RNS.Resource injects randomness at two independent points
    during construction — a fresh random_hash (Resource.py:440) and a fresh
    random prefix on the data stream (Resource.py:405/412). Two resources
    built from byte-identical payloads must therefore differ in both their
    identity (hash) and their encrypted output (parts). A resource that is
    reproducible from its payload is a conformance failure: identical
    payloads would produce identical hashes, leaking payload equality and
    undermining the truncated-hash collision-resistance assumption.

  * Internal consistency / structure. truncated_hash must be the resource's
    own full hash truncated — not an independently derived value;
    expected_proof must be a full-length 32-byte hash; the hashmap must
    carry exactly one fixed-width map hash per part. These directly catch
    the kind of drift the deleted hand-rolled commands had.

The peer that creates the resource (the client, which opens the outbound
Link) is the implementation under test for resource construction; the
wire_pair parametrization rotates each implementation through that role.
The server only anchors the Link — wire_resource_create neither advertises
nor sends, so nothing is transmitted and the server inspects nothing.
"""

import secrets
import time
# Aliased so the test's local SHA-256 recomputation (spec math, NOT a bridge
# call) is not mistaken for the bridge's `sha256` primitive by the
# conformance-decorator drift guard, which keys off attribute-call names.
from hashlib import sha256 as _sha256

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "resourceinv"
_ASPECTS = ["test"]

# Link establishment needs round-trips plus the RNS handshake grace timing;
# match the budgets the other wire tests use.
_SETTLE_SEC = 1.5
_LINK_TIMEOUT_MS = 15000
_PATH_POLL_TIMEOUT_MS = 10000

# A payload comfortably larger than one Resource part, so the resource
# splits into several parts (a multi-entry hashmap, num_parts >= 2) —
# exercises the real per-part packing path, not a degenerate single part.
# (The exact part count depends on the link's negotiated MDU; the tests
# below assert num_parts >= 2 rather than a fixed count.) Random bytes are
# incompressible, so this also pins the uncompressed construction path (bz2
# can't shrink it, so compressed=False, Resource.py:392/400/415).
_PAYLOAD_SIZE = 16384

# Structural constants from the RNS spec: RNS/Identity.py — full_hash is
# SHA-256 (32 bytes), truncated_hash is its first 16 bytes
# (TRUNCATED_HASHLENGTH = 128 bits); RNS/Resource.py — MAPHASH_LEN = 4.
# Hardcoded on purpose: the test encodes the spec, so an implementation —
# the reference included — that diverges from these is itself a finding.
_FULL_HASH_LEN = 32
_TRUNCATED_HASH_LEN = 16
_MAPHASH_LEN = 4

# Width of the per-resource random_hash RNS mixes into the identity hash:
# RANDOM_HASH_SIZE = 4 (Resource.py:104), taken as the first 4 bytes of a
# get_random_hash() at construction (Resource.py:440).
_RANDOM_HASH_LEN = 4


def _full_hash(data: bytes) -> bytes:
    """SHA-256 of ``data`` — the spec for RNS.Identity.full_hash
    (Identity.py:366-373, ``return RNS.Cryptography.sha256(data)``).

    Recomputed here straight from the spec (plain SHA-256) rather than read
    back off the RNS object, so the asserts below pin the *operand order* RNS
    feeds the hash — full_hash(data + random_hash), not full_hash(random_hash
    + data) — independent of the library under test. An implementation that
    reversed the operands (the exact drift the deleted hand-rolled
    cmd_resource_hash had) still produces a 32-byte digest, so a length-only
    check would miss it; recomputing the digest from the payload catches it.
    """
    return _sha256(data).digest()


def _establish_link(wire_peers):
    """Bring up a direct server<->client TCP pair and open one Link from the
    client to the server's IN destination. Returns (client, link_id).

    The client is the resource-creating peer — the implementation under
    test for resource construction. The server only anchors the Link.
    """
    server, client = wire_peers

    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="", target_host="127.0.0.1", target_port=port
    )
    time.sleep(_SETTLE_SEC)

    dest_hash = server.listen(app_name=_APP_NAME, aspects=_ASPECTS)
    assert client.poll_path(dest_hash, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — the Link could not be opened, so the resource "
        f"invariants below would be untestable."
    )
    link_id = client.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    return client, link_id


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="Invariant: two Resources built from byte-identical payloads get different identities — RNS draws a fresh random_hash per construction (Resource.py:440), so the hash never leaks that two payloads were equal",
)
def test_resource_identity_is_fresh_per_construction(wire_peers):
    """Construct two Resources from the *same* payload bytes on the same
    Link; their random_hash — and therefore their hash — must differ.

    Failure semantic: "<client_impl> produced a Resource hash that is a
    pure function of the payload." That means either random_hash was not
    regenerated per construction, or hash was not derived from it — either
    way the implementation has dropped RNS's per-resource identity
    randomisation.
    """
    client, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_PAYLOAD_SIZE)

    first = client.resource_create(link_id, payload)
    second = client.resource_create(link_id, payload)

    assert first["random_hash"] != second["random_hash"], (
        f"{client.role_label} reused random_hash {first['random_hash']} "
        f"across two Resources built from identical payloads — RNS draws a "
        f"fresh one per construction (Resource.py:440)."
    )
    assert first["hash"] != second["hash"], (
        f"{client.role_label} produced identical Resource hashes "
        f"({first['hash']}) for two constructions from byte-identical "
        f"payloads — the hash is leaking payload equality."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="Invariant: two Resources built from byte-identical payloads produce entirely different encrypted parts — a fresh random prefix on the data stream (Resource.py:405/412) plus per-construction Link encryption keeps every chunk's ciphertext unique",
)
def test_resource_encrypted_output_is_fresh_per_construction(wire_peers):
    """Construct two Resources from the *same* payload bytes; no encrypted
    part of one may be byte-identical to any part of the other.

    This is the headline freshness property: even with identical input,
    the on-wire bytes must be unique. RNS guarantees it by prepending a
    fresh random prefix to the data stream before encryption
    (Resource.py:405/412) and encrypting the whole stream through the Link.

    Failure semantic: "<client_impl> produced reproducible Resource
    ciphertext" — identical payloads yield identical wire bytes, which both
    leaks payload equality to an observer and means the random prefix was
    dropped.
    """
    client, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_PAYLOAD_SIZE)

    first = client.resource_create(link_id, payload)
    second = client.resource_create(link_id, payload)

    assert first["parts"] and second["parts"], (
        f"{client.role_label} returned a Resource with no parts — "
        f"a {_PAYLOAD_SIZE}-byte payload must chunk into at least one part."
    )
    overlap = set(first["parts"]) & set(second["parts"])
    assert not overlap, (
        f"{client.role_label} produced {len(overlap)} encrypted part(s) "
        f"that are byte-identical between two Resources built from the same "
        f"payload — the per-construction random prefix (Resource.py:405/412) "
        f"is not being applied."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="Invariant: a Resource's hash is exactly full_hash(payload + random_hash) (Resource.py:441) and truncated_hash is the first 16 bytes of that same digest (Resource.py:442) — pinning the SHA-256 operand ORDER (payload then random_hash), not just the 32/16-byte lengths",
)
def test_resource_hash_pins_operand_order_and_truncation(wire_peers):
    """A Resource's hash must be byte-for-byte SHA-256(payload + random_hash),
    and its truncated_hash the first 16 bytes of that same digest.

    RNS computes self.hash = full_hash(data + random_hash) (Resource.py:441)
    and self.truncated_hash = truncated_hash(data + random_hash)
    (Resource.py:442), where for a single-segment payload with no metadata
    `data` is the payload verbatim (Resource.py:320/333). Because we know the
    payload and read random_hash back off the object, we recompute the digest
    from the spec and assert equality — this pins the OPERAND ORDER (payload
    then random_hash). The deleted hand-rolled cmd_resource_hash had the
    operands reversed and a length-only check stayed green; recomputing the
    digest catches that drift. truncated_hash being the same digest's first
    16 bytes is asserted against the recomputed value too, so an
    implementation that derives the two from different inputs fails.
    """
    client, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_PAYLOAD_SIZE)

    resource = client.resource_create(link_id, payload)
    full = bytes.fromhex(resource["hash"])
    truncated = bytes.fromhex(resource["truncated_hash"])
    random_hash = bytes.fromhex(resource["random_hash"])

    assert len(random_hash) == _RANDOM_HASH_LEN, (
        f"{client.role_label} produced a {len(random_hash)}-byte random_hash; "
        f"RNS mixes a {_RANDOM_HASH_LEN}-byte random_hash into the resource "
        f"identity (RANDOM_HASH_SIZE = 4, Resource.py:104/440)."
    )
    assert len(full) == _FULL_HASH_LEN, (
        f"{client.role_label} produced a {len(full)}-byte Resource hash; "
        f"RNS full hashes are SHA-256 ({_FULL_HASH_LEN} bytes)."
    )
    assert len(truncated) == _TRUNCATED_HASH_LEN, (
        f"{client.role_label} produced a {len(truncated)}-byte "
        f"truncated_hash; RNS truncated hashes are {_TRUNCATED_HASH_LEN} "
        f"bytes (TRUNCATED_HASHLENGTH = 128 bits)."
    )

    # Operand-order pin: the digest must be over (payload + random_hash), in
    # that order. A reversed-operand implementation produces a 32-byte hash
    # that fails this exact-bytes comparison (the length checks above pass).
    expected_full = _full_hash(payload + random_hash)
    assert full == expected_full, (
        f"{client.role_label}'s Resource hash ({full.hex()}) is not "
        f"full_hash(payload + random_hash) ({expected_full.hex()}) — the hash "
        f"operands are reversed or the wrong bytes are being hashed "
        f"(Resource.py:441)."
    )
    assert truncated == expected_full[:_TRUNCATED_HASH_LEN], (
        f"{client.role_label}'s truncated_hash ({truncated.hex()}) is not the "
        f"first {_TRUNCATED_HASH_LEN} bytes of full_hash(payload + "
        f"random_hash) — the two are derived from different inputs "
        f"(Resource.py:442)."
    )
    # ...and internal consistency: truncated_hash is the resource's own full
    # hash truncated, not a value derived separately.
    assert truncated == full[:_TRUNCATED_HASH_LEN], (
        f"{client.role_label}'s truncated_hash ({truncated.hex()}) is not "
        f"the first {_TRUNCATED_HASH_LEN} bytes of its full hash "
        f"({full.hex()}) — the two are being derived from different inputs."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="Invariant: a Resource's expected_proof is exactly the 32-byte full_hash(payload + hash) (Resource.py:443) — pinning both the full SHA-256 length (catching the truncation the deleted resource_proof command had) and the operand composition (payload then the resource's own hash)",
)
def test_resource_expected_proof_is_full_hash_of_payload_and_hash(wire_peers):
    """A Resource's expected_proof must be byte-for-byte
    SHA-256(payload + hash), a full 32-byte digest.

    RNS computes self.expected_proof = full_hash(data + self.hash)
    (Resource.py:443) — the full SHA-256 over the payload followed by the
    resource's own hash, not a truncated value and not some other
    composition. The deleted hand-rolled resource_proof bridge command
    truncated it to 16 bytes and the suite never noticed, because the bridge
    was checked against its own copy of the logic. Recomputing the digest
    from the payload and the object's reported hash pins BOTH the length and
    the operand composition: a truncated proof fails the length check, a
    wrong-operand proof fails the exact-bytes check.
    """
    client, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_PAYLOAD_SIZE)

    resource = client.resource_create(link_id, payload)
    expected_proof = bytes.fromhex(resource["expected_proof"])
    full = bytes.fromhex(resource["hash"])

    assert len(expected_proof) == _FULL_HASH_LEN, (
        f"{client.role_label} produced a {len(expected_proof)}-byte "
        f"expected_proof; RNS expected proofs are full SHA-256 hashes "
        f"({_FULL_HASH_LEN} bytes) — a shorter value means the proof is "
        f"being truncated."
    )
    # Composition pin: full_hash(payload + hash), in that order.
    expected = _full_hash(payload + full)
    assert expected_proof == expected, (
        f"{client.role_label}'s expected_proof ({expected_proof.hex()}) is "
        f"not full_hash(payload + hash) ({expected.hex()}) — the proof is "
        f"composed from the wrong operands or wrong order (Resource.py:443)."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="Invariant: a Resource's hashmap carries exactly one 4-byte map hash per part — len(hashmap) == num_parts x MAPHASH_LEN — for a multi-part resource, catching a mis-sized or mis-counted hashmap",
)
def test_resource_hashmap_has_one_entry_per_part(wire_peers):
    """For a multi-part Resource, the hashmap must be exactly one
    MAPHASH_LEN-byte map hash per part.

    RNS appends part.map_hash (the first 4 bytes of full_hash(part_data +
    random_hash), get_map_hash at Resource.py:505-506) to the hashmap once
    per part as it packs them (Resource.py:471). The receiver walks the
    hashmap in fixed 4-byte strides to know which parts to expect, so a
    hashmap that is not num_parts x 4 bytes — or a num_parts that disagrees
    with it — desynchronises reassembly.
    """
    client, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_PAYLOAD_SIZE)

    resource = client.resource_create(link_id, payload)
    num_parts = resource["num_parts"]
    hashmap = bytes.fromhex(resource["hashmap"])

    assert num_parts >= 2, (
        f"a {_PAYLOAD_SIZE}-byte payload produced only {num_parts} "
        f"part(s) on {client.role_label} — expected a multi-part resource; "
        f"the single-part case does not exercise the hashmap stride."
    )
    assert len(hashmap) == num_parts * _MAPHASH_LEN, (
        f"{client.role_label} produced a {len(hashmap)}-byte hashmap for a "
        f"{num_parts}-part Resource — expected exactly "
        f"{num_parts} x {_MAPHASH_LEN} = {num_parts * _MAPHASH_LEN} bytes "
        f"(one map hash per part)."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="Invariant: the Resource auto-compression decision is data-driven — a highly-compressible payload sets compressed=True (bz2 shrank the stream, Resource.py:400/408) while an incompressible random payload of the same size sets compressed=False (Resource.py:415)",
)
def test_resource_compressed_flag_tracks_compressibility(wire_peers):
    """RNS attempts bz2 compression of the payload at construction and keeps
    it only if it actually shrank the data (Resource.py:392/400): a
    compressible payload yields compressed=True, an incompressible one
    compressed=False.

    The other invariant tests all use incompressible random payloads, so the
    compressed=True branch (Resource.py:404-408) was never exercised. This
    pins both branches on the same Link: a highly-compressible payload (a
    short repeated pattern bz2 collapses) must report compressed=True, and a
    same-size random payload — the positive control — must report
    compressed=False. An implementation that hard-wired the flag, or never
    compressed, fails one of the two.
    """
    client, link_id = _establish_link(wire_peers)

    # A short pattern repeated to _PAYLOAD_SIZE bytes: bz2 collapses it far
    # below its original size, so RNS keeps the compressed stream.
    compressible = (b"reticulum-conformance-" * (_PAYLOAD_SIZE // 22 + 1))[:_PAYLOAD_SIZE]
    incompressible = secrets.token_bytes(_PAYLOAD_SIZE)

    compressible_resource = client.resource_create(link_id, compressible)
    incompressible_resource = client.resource_create(link_id, incompressible)

    assert compressible_resource["compressed"] is True, (
        f"{client.role_label} did not set compressed=True for a "
        f"{_PAYLOAD_SIZE}-byte highly-compressible payload — bz2 shrinks it "
        f"dramatically, so RNS keeps the compressed stream "
        f"(Resource.py:400/408)."
    )
    assert incompressible_resource["compressed"] is False, (
        f"{client.role_label} set compressed=True for a {_PAYLOAD_SIZE}-byte "
        f"random (incompressible) payload — bz2 cannot shrink random bytes, "
        f"so RNS must send it uncompressed (Resource.py:415). A True here "
        f"means the flag is not tracking the actual compression result."
    )
