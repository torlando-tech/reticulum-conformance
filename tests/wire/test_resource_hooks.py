"""Resource subsystem conformance: protocol constants, the sender-side
part-request / HMU-sequencing gate, the hashmap collision-guard remap, and the
one-outgoing-resource-at-a-time rule.

These pin Resource.py behaviours the ordinary (happy-path) Resource transfer
tests never reach, each against an EXTERNAL anchor — a RNS 1.3.1 spec literal or
a code-literal rule in Resource.py / Link.py — not impl-vs-itself:

  * window/hashmap/segmentation/retry CONSTANTS (Resource.WINDOW=4 ...,
    ResourceAdvertisement.HASHMAP_MAX_LEN=74, COLLISION_GUARD_SIZE=224);
  * the RESOURCE_REQ HMU sequencing gate — a hashmap-exhausted request whose
    resolved part index is NOT on a HASHMAP_MAX_LEN (74) boundary cancels the
    transfer (Resource.py:1040-1042); an aligned one does not;
  * the sender serving requested parts and reaching AWAITING_PROOF once every
    part is sent (Resource.py:1066), resending byte-identical bytes;
  * the hashmap collision-guard remap loop regenerating random_hash on a
    map-hash collision (Resource.py:436-472);
  * Link.ready_for_new_resource admitting only one outgoing resource at a time
    (Link.py:1328-1329) — a second advertised resource goes QUEUED
    (Resource.py:522-524).

Runs reference-vs-reference; no SUT binary required.
"""

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["resource-hooks"]


# RNS 1.3.1 spec literals — the EXTERNAL ground truth, NOT read from the impl.
_WINDOW = 4
_WINDOW_MIN = 2
_WINDOW_MAX = 75
_MAPHASH_LEN = 4
_RANDOM_HASH_SIZE = 4
_HASHMAP_MAX_LEN = 74
_COLLISION_GUARD_SIZE = 224
_MAX_EFFICIENT_SIZE = 1 * 1024 * 1024 - 1
_METADATA_MAX_SIZE = 16 * 1024 * 1024 - 1
_MAX_RETRIES = 16
_MAX_ADV_RETRIES = 4
_HASHMAP_IS_EXHAUSTED = 0xFF
_HASHMAP_IS_NOT_EXHAUSTED = 0x00


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "resource_constants",
    ],
    verifies=(
        "Resource/ResourceAdvertisement protocol constants match the RNS 1.3.1 "
        "spec literals exactly: WINDOW=4, WINDOW_MIN=2, WINDOW_MAX=75, "
        "MAPHASH_LEN=4, RANDOM_HASH_SIZE=4, HASHMAP_MAX_LEN=74, "
        "COLLISION_GUARD_SIZE=224, MAX_EFFICIENT_SIZE=1MiB-1, "
        "METADATA_MAX_SIZE=16MiB-1, MAX_RETRIES=16, MAX_ADV_RETRIES=4, "
        "HASHMAP_IS_EXHAUSTED=0xFF, HASHMAP_IS_NOT_EXHAUSTED=0x00 — plus their "
        "defining relationships (WINDOW_MIN < WINDOW < WINDOW_MAX, "
        "HASHMAP_MAX_LEN < COLLISION_GUARD_SIZE). An impl with any divergent "
        "value windows/chunks/segments differently and breaks interop"
    ),
)
def test_resource_constants_match_spec(wire_link_setup):
    server, client, _dest_hash, _link_id = wire_link_setup(_APP, _ASPECTS)
    c = client.resource_constants()
    assert c["WINDOW"] == _WINDOW, c
    assert c["WINDOW_MIN"] == _WINDOW_MIN, c
    assert c["WINDOW_MAX"] == _WINDOW_MAX, c
    assert c["MAPHASH_LEN"] == _MAPHASH_LEN, c
    assert c["RANDOM_HASH_SIZE"] == _RANDOM_HASH_SIZE, c
    assert c["HASHMAP_MAX_LEN"] == _HASHMAP_MAX_LEN, c
    assert c["COLLISION_GUARD_SIZE"] == _COLLISION_GUARD_SIZE, c
    assert c["MAX_EFFICIENT_SIZE"] == _MAX_EFFICIENT_SIZE, c
    assert c["METADATA_MAX_SIZE"] == _METADATA_MAX_SIZE, c
    assert c["MAX_RETRIES"] == _MAX_RETRIES, c
    assert c["MAX_ADV_RETRIES"] == _MAX_ADV_RETRIES, c
    assert c["HASHMAP_IS_EXHAUSTED"] == _HASHMAP_IS_EXHAUSTED, c
    assert c["HASHMAP_IS_NOT_EXHAUSTED"] == _HASHMAP_IS_NOT_EXHAUSTED, c
    # Defining relationships, not just the stored values.
    assert c["WINDOW_MIN"] < c["WINDOW"] < c["WINDOW_MAX"], c
    assert c["HASHMAP_MAX_LEN"] < c["COLLISION_GUARD_SIZE"], c
    assert c["HASHMAP_IS_EXHAUSTED"] != c["HASHMAP_IS_NOT_EXHAUSTED"], c


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_crafted_resource_request",
    ],
    verifies=(
        "A Resource SENDER enforces the HMU sequencing gate (Resource.py:"
        "1040-1042): a hashmap-exhausted RESOURCE_REQ whose last-known map hash "
        "resolves to an absolute part index that is NOT a multiple of "
        "HASHMAP_MAX_LEN (74) is a sequencing error and CANCELS the transfer "
        "(status FAILED); an exhausted request resolving to a 74-aligned index "
        "is accepted (the next hashmap segment is emitted, no cancel). An impl "
        "that skips the modulo check would serve a desynchronised hashmap segment"
    ),
)
def test_resource_request_hmu_sequencing_gate(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Negative: misaligned exhausted request (part_index 1, 1 % 74 != 0) cancels.
    bad = client.inject_crafted_resource_request(link_id, "misaligned_hmu")
    assert bad["cancelled"] is True, (
        f"a misaligned HMU request did NOT cancel the transfer: {bad!r}"
    )
    assert bad["status_name"] == "FAILED", bad

    # Positive control: aligned exhausted request (part_index 74, 74 % 74 == 0)
    # is accepted and does NOT cancel.
    good = client.inject_crafted_resource_request(link_id, "aligned")
    assert good["cancelled"] is False, (
        f"an aligned HMU request was wrongly treated as a sequencing error: {good!r}"
    )
    assert good["status_name"] != "FAILED", good


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_crafted_resource_request",
    ],
    verifies=(
        "A Resource SENDER serves exactly the parts a RESOURCE_REQ names (matched "
        "by map hash) and, once sent_parts == len(parts), transitions to "
        "AWAITING_PROOF (Resource.py:1066). Re-feeding the identical request "
        "resends byte-identical part bytes (part.resend, idempotent). An impl "
        "that served different bytes on resend or never reached AWAITING_PROOF "
        "would desynchronise or stall the transfer"
    ),
)
def test_resource_request_serves_all_then_awaits_proof(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.inject_crafted_resource_request(link_id, "serve_all")
    total = res["total_parts"]
    assert total >= 2, f"expected a multi-part sender: {res!r}"
    # Every part named in the request was served.
    assert res["served_indices"] == list(range(total)), res
    assert res["sent_parts"] == total, res
    # All parts sent -> AWAITING_PROOF.
    assert res["status_name"] == "AWAITING_PROOF", res
    # Idempotent resend: byte-identical part bytes.
    assert res["identical_on_resend"] is True, (
        f"resending the same request did not resend byte-identical parts: {res!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "resource_force_collision",
    ],
    verifies=(
        "The Resource hashmap collision-guard regenerates random_hash and "
        "rebuilds the whole hashmap when two parts share a map hash within "
        "COLLISION_GUARD_SIZE (Resource.py:436-472): forcing a map-hash "
        "collision on the first build pass yields a DIFFERENT random_hash on the "
        "rebuild pass (random_hash_before != random_hash_after) and the final "
        "object adopts the rebuilt random_hash. An impl without the guard would "
        "ship a hashmap with two indistinguishable entries"
    ),
)
def test_resource_hashmap_collision_guard_remaps(wire_link_setup, wire_pair):
    server_impl, client_impl = wire_pair
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.resource_force_collision(link_id)
    if client_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#resource-collision-guard: single-pass hashmap build "
            "with no collision-detect/rebuild loop (Resource.kt:430-443). "
            "Ref Resource.py:436-472."
        )
    assert res["remapped"] is True, (
        f"forced map-hash collision did not trigger a remap: {res!r}"
    )
    assert res["random_hash_before"] is not None, res
    assert res["random_hash_after"] is not None, res
    # A fresh random_hash is drawn on the rebuild — the two passes differ.
    assert res["random_hash_before"] != res["random_hash_after"], res
    # The rebuilt random_hash (not the collided one) is what the object adopted,
    # and it produced a valid multi-part hashmap.
    assert res["hashmap_changed"] is True, res
    assert res["num_parts"] >= 2, res


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "resource_outgoing_queue_state",
    ],
    verifies=(
        "A Link admits only ONE outgoing Resource at a time "
        "(Link.ready_for_new_resource, Link.py:1328-1329): with zero outgoing "
        "resources the link admits a new one (ready==True, positive control), "
        "with one registered it refuses (ready==False, negative control), and a "
        "SECOND advertised Resource spins in the QUEUED state "
        "(Resource.__advertise_job, Resource.py:522-524). An impl that admitted "
        "two would interleave two part streams on one link"
    ),
)
def test_resource_single_outgoing_at_a_time(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.resource_outgoing_queue_state(link_id)
    # Positive control: an idle link admits a new outgoing resource.
    assert res["ready_empty"] is True, (
        f"an idle link refused a new outgoing resource: {res!r}"
    )
    # Negative control: with one registered, the link refuses a second.
    assert res["ready_with_one"] is False, (
        f"a busy link wrongly admitted a second outgoing resource: {res!r}"
    )
    # The second advertised resource goes QUEUED.
    assert res["queued"] is True, (
        f"a second advertised resource did not queue behind the first: {res!r}"
    )
    assert res["second_status_name"] == "QUEUED", res
