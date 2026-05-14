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
    during construction — a fresh random_hash (Resource.py:193) and a fresh
    random prefix on the data stream (Resource.py:158/165). Two resources
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

# A payload comfortably larger than one Resource part (link SDU is a few
# hundred bytes) so the resource splits into a many-entry hashmap —
# exercises the real per-part packing path, not a degenerate single part.
# Random bytes are incompressible, so this also pins the uncompressed
# construction path (bz2 can't shrink it, Resource.py:153).
_PAYLOAD_SIZE = 16384

# Structural constants from the RNS spec: RNS/Identity.py — full_hash is
# SHA-256 (32 bytes), truncated_hash is its first 16 bytes
# (TRUNCATED_HASHLENGTH = 128 bits); RNS/Resource.py — MAPHASH_LEN = 4.
# Hardcoded on purpose: the test encodes the spec, so an implementation —
# the reference included — that diverges from these is itself a finding.
_FULL_HASH_LEN = 32
_TRUNCATED_HASH_LEN = 16
_MAPHASH_LEN = 4


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
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "resource_create"],
    verifies="Invariant: two Resources built from byte-identical payloads get different identities — RNS draws a fresh random_hash per construction (Resource.py:193), so the hash never leaks that two payloads were equal",
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
        f"fresh one per construction (Resource.py:193)."
    )
    assert first["hash"] != second["hash"], (
        f"{client.role_label} produced identical Resource hashes "
        f"({first['hash']}) for two constructions from byte-identical "
        f"payloads — the hash is leaking payload equality."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "resource_create"],
    verifies="Invariant: two Resources built from byte-identical payloads produce entirely different encrypted parts — a fresh random prefix on the data stream (Resource.py:158/165) plus per-construction Link encryption keeps every chunk's ciphertext unique",
)
def test_resource_encrypted_output_is_fresh_per_construction(wire_peers):
    """Construct two Resources from the *same* payload bytes; no encrypted
    part of one may be byte-identical to any part of the other.

    This is the headline freshness property: even with identical input,
    the on-wire bytes must be unique. RNS guarantees it by prepending a
    fresh random prefix to the data stream before encryption
    (Resource.py:158/165) and encrypting the whole stream through the Link.

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
        f"payload — the per-construction random prefix (Resource.py:158/165) "
        f"is not being applied."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "resource_create"],
    verifies="Invariant: a Resource's truncated_hash is its own full hash truncated to 16 bytes — not an independently derived value — catching an implementation that computes the two from different inputs",
)
def test_resource_truncated_hash_is_consistent_with_full_hash(wire_peers):
    """A Resource's truncated_hash must equal the first 16 bytes of its
    full hash, and the two must have the spec lengths (32 and 16 bytes).

    RNS derives both from the same input (data + random_hash), with
    truncated_hash being literally full_hash(...)[:16]
    (Identity.truncated_hash). An implementation that derives them
    separately — or truncates to the wrong width — breaks the relationship
    receivers rely on to match a Resource by its truncated identity.
    """
    client, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_PAYLOAD_SIZE)

    resource = client.resource_create(link_id, payload)
    full = bytes.fromhex(resource["hash"])
    truncated = bytes.fromhex(resource["truncated_hash"])

    assert len(full) == _FULL_HASH_LEN, (
        f"{client.role_label} produced a {len(full)}-byte Resource hash; "
        f"RNS full hashes are SHA-256 ({_FULL_HASH_LEN} bytes)."
    )
    assert len(truncated) == _TRUNCATED_HASH_LEN, (
        f"{client.role_label} produced a {len(truncated)}-byte "
        f"truncated_hash; RNS truncated hashes are {_TRUNCATED_HASH_LEN} "
        f"bytes (TRUNCATED_HASHLENGTH = 128 bits)."
    )
    assert truncated == full[:_TRUNCATED_HASH_LEN], (
        f"{client.role_label}'s truncated_hash ({truncated.hex()}) is not "
        f"the first {_TRUNCATED_HASH_LEN} bytes of its full hash "
        f"({full.hex()}) — the two are being derived from different inputs."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "resource_create"],
    verifies="Invariant: a Resource's expected_proof is a full-length 32-byte SHA-256 hash — directly catching the proof being truncated, which is the exact drift the deleted hand-rolled resource_proof command had",
)
def test_resource_expected_proof_is_full_length(wire_peers):
    """A Resource's expected_proof must be a full-length 32-byte hash.

    RNS computes expected_proof as full_hash(data + hash) (Resource.py:196)
    — the full SHA-256, not a truncated one. The deleted hand-rolled
    resource_proof bridge command truncated it and the suite never noticed,
    because the bridge was checked against its own copy of the logic. This
    asserts the property against what the real RNS.Resource computed.
    """
    client, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_PAYLOAD_SIZE)

    resource = client.resource_create(link_id, payload)
    expected_proof = bytes.fromhex(resource["expected_proof"])

    assert len(expected_proof) == _FULL_HASH_LEN, (
        f"{client.role_label} produced a {len(expected_proof)}-byte "
        f"expected_proof; RNS expected proofs are full SHA-256 hashes "
        f"({_FULL_HASH_LEN} bytes) — a shorter value means the proof is "
        f"being truncated."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "resource_create"],
    verifies="Invariant: a Resource's hashmap carries exactly one 4-byte map hash per part — len(hashmap) == num_parts x MAPHASH_LEN — for a multi-part resource, catching a mis-sized or mis-counted hashmap",
)
def test_resource_hashmap_has_one_entry_per_part(wire_peers):
    """For a multi-part Resource, the hashmap must be exactly one
    MAPHASH_LEN-byte map hash per part.

    RNS appends part.map_hash (a 4-byte truncation of the part's hash) to
    the hashmap once per part as it packs them (Resource.py:224). The
    receiver walks the hashmap in fixed 4-byte strides to know which parts
    to expect, so a hashmap that is not num_parts x 4 bytes — or a
    num_parts that disagrees with it — desynchronises reassembly.
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
