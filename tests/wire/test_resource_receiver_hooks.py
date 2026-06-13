"""Resource RECEIVER-side conformance: the inbound-transfer state machine the
ordinary happy-path Resource tests never reach — assembly-time integrity, the
advertisement accept/de-dup/drop gates, the request/response advertisement flag
logic, inbound window / consecutive-height bookkeeping, hashmap-update (HMU)
idempotence, and per-part proof suppression.

Each case pins a Resource.py / Link.py rule against an EXTERNAL anchor — a RNS
1.3.1 code-literal rule or spec literal — never impl-vs-itself:

  * Resource.assemble marks a transfer CORRUPT and emits NO proof unless the
    reassembled stream passes its integrity check (Resource.py:694-721);
  * Resource.accept de-dups a re-delivered advertisement via
    Link.has_incoming_resource — no second receiver for the same hash
    (Resource.py:223 / Link.py:1308-1310);
  * Resource.accept silently drops an undecodable / missing-key advertisement
    without crashing (Resource.py:167-243);
  * Link.receive auto-accepts a REQUEST advertisement regardless of
    resource_strategy, accepts a RESPONSE advertisement only against a matching
    pending request, and gates a plain advertisement on resource_strategy
    (Link.py:1070-1098);
  * an inbound Resource starts window==WINDOW, consecutive_completed_height==-1,
    hashmap fully loaded for a single-segment transfer, and advances the
    consecutive pointer one slot per in-order part (Resource.py:828-926);
  * Resource.hashmap_update is idempotent on a duplicate segment but
    hashmap_update_packet always refreshes activity / retry budget
    (Resource.py:483-503);
  * a receiver emits exactly ONE RESOURCE_PRF after assembly, zero per-part
    (Resource.py:894-896 / 752-758).

Runs reference-vs-reference; no SUT binary required.
"""

import pytest

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["resource-receiver-hooks"]

# RNS 1.3.1 spec literals — EXTERNAL ground truth, NOT read from the impl.
_WINDOW = 4
_WINDOW_MIN = 2
_WINDOW_MAX_SLOW = 10  # Resource.WINDOW_MAX_SLOW — the initial inbound window cap
_HASHMAP_MAX_LEN = 74

# RNS.Link resource-strategy enum values (Link.py:120-122) — EXTERNAL literals.
_ACCEPT_NONE = 0x00
_ACCEPT_ALL = 0x02


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_corrupt_assembled_resource",
    ],
    verifies=(
        "A Resource receiver concludes a transfer COMPLETE and emits its single "
        "RESOURCE_PRF proof IFF the reassembled stream passes its integrity check "
        "(Resource.assemble, Resource.py:694-721): a buffer of the sender's own "
        "genuine parts assembles to the advertised hash -> COMPLETE with exactly "
        "one proof; corrupting a single part makes assembly fail its integrity "
        "check -> CORRUPT with ZERO proofs. An impl that proved regardless of the "
        "assembled hash would confirm corrupt deliveries"
    ),
)
def test_resource_assembly_hash_check(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Positive control: genuine parts assemble -> COMPLETE, exactly one proof.
    ok = client.inject_corrupt_assembled_resource(link_id, "valid")
    assert ok["status_name"] == "COMPLETE", ok
    assert ok["complete"] is True, ok
    assert ok["proof_sent"] is True, ok
    assert ok["proof_calls"] == 1, (
        f"a completed resource must send exactly one proof: {ok!r}"
    )

    # Negative: one corrupted part -> CORRUPT, no proof.
    bad = client.inject_corrupt_assembled_resource(link_id, "corrupt")
    assert bad["status_name"] == "CORRUPT", bad
    assert bad["corrupt"] is True, bad
    assert bad["proof_sent"] is False, (
        f"a corrupt resource must NOT send a proof: {bad!r}"
    )
    assert bad["proof_calls"] == 0, bad


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_duplicate_resource_adv",
    ],
    verifies=(
        "Resource.accept de-dups a re-delivered RESOURCE_ADV: the first "
        "advertisement registers one inbound Resource on the link, an IDENTICAL "
        "second advertisement is ignored (accept returns None) because "
        "Link.has_incoming_resource already maps the hash (Resource.py:223 / "
        "Link.py:1308-1310). Exactly one receiver exists for the hash. An impl "
        "that built a second receiver per advertisement would double-count parts "
        "and corrupt the transfer"
    ),
)
def test_resource_duplicate_adv_ignored(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.inject_duplicate_resource_adv(link_id)
    assert res["first_accepted"] is True, (
        f"the first advertisement was not accepted: {res!r}"
    )
    assert res["second_created"] is False, (
        f"a duplicate advertisement wrongly created a second receiver: {res!r}"
    )
    assert res["incoming_count"] == 1, (
        f"exactly one inbound Resource must exist for the hash: {res!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_malformed_resource_adv",
    ],
    verifies=(
        "Resource.accept silently drops a malformed RESOURCE_ADV without crashing "
        "(Resource.py:167-243, try/except around the unpack): an advertisement "
        "whose plaintext is undecodable msgpack ('garbage') or valid msgpack "
        "missing a required key ('missing_key') starts NO inbound Resource and "
        "raises nothing. An impl that threw on, or started a transfer from, a "
        "malformed advertisement would be trivially DoS-able"
    ),
)
def test_resource_malformed_adv_dropped(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    for variant in ("garbage", "missing_key"):
        res = client.inject_malformed_resource_adv(link_id, variant)
        assert res["inbound_started"] is False, (
            f"malformed advertisement ({variant}) wrongly started a transfer: {res!r}"
        )
        assert res["crashed"] is False, (
            f"malformed advertisement ({variant}) crashed the receiver: {res!r}"
        )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_resource_adv_flags",
    ],
    verifies=(
        "Link.receive resolves a RESOURCE_ADV by its q/u/p flags (Link.py:"
        "1070-1098): a REQUEST advertisement (q+u) is accepted UNCONDITIONALLY, "
        "even under resource_strategy ACCEPT_NONE (Link.py:1070-1071); a RESPONSE "
        "advertisement (q+p) with NO matching pending request is NOT accepted "
        "(Link.py:1072-1076); a plain advertisement is gated on resource_strategy "
        "(ACCEPT_NONE drops, ACCEPT_ALL accepts). An impl that gated requests on "
        "the strategy, or accepted unsolicited responses, would mis-handle the "
        "Link request/response protocol"
    ),
)
def test_resource_adv_request_response_flags(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Request advertisement bypasses ACCEPT_NONE.
    req = client.inject_resource_adv_flags(link_id, "request_autoaccept")
    assert req["strategy"] == _ACCEPT_NONE, req
    assert req["accepted"] is True, (
        f"a request advertisement was NOT auto-accepted under ACCEPT_NONE: {req!r}"
    )

    # Response advertisement with no pending request is rejected.
    resp = client.inject_resource_adv_flags(link_id, "response_no_pending_request")
    assert resp["accepted"] is False, (
        f"an unsolicited response advertisement was wrongly accepted: {resp!r}"
    )

    # Plain advertisement: gated by strategy (negative + positive control).
    none = client.inject_resource_adv_flags(link_id, "plain_accept_none")
    assert none["accepted"] is False, (
        f"a plain advertisement was accepted under ACCEPT_NONE: {none!r}"
    )
    allv = client.inject_resource_adv_flags(link_id, "plain_accept_all")
    assert allv["strategy"] == _ACCEPT_ALL, allv
    assert allv["accepted"] is True, (
        f"a plain advertisement was NOT accepted under ACCEPT_ALL: {allv!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "resource_receiver_request_state",
    ],
    verifies=(
        "An inbound Resource starts window==Resource.WINDOW (4), "
        "consecutive_completed_height==-1, and — for a single-segment transfer — "
        "its full hashmap loaded (hashmap_height==total_parts) (Resource.accept, "
        "Resource.py:191/214/233). Feeding parts strictly in order advances the "
        "consecutive completed-height pointer exactly one slot per part "
        "(Resource.py:876-882) while hashmap_height stays put. An impl whose "
        "pointer/window bookkeeping diverged would request the wrong missing parts"
    ),
)
def test_resource_inbound_window_semantics(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.resource_receiver_request_state(link_id, n=2)
    assert res["total_parts"] >= 3, f"expected a multi-part transfer: {res!r}"
    # Spec-literal initial window and pointer.
    assert res["window"] == _WINDOW, res
    assert res["window_min"] == _WINDOW_MIN, res
    assert res["window_max"] == _WINDOW_MAX_SLOW, res
    assert res["consecutive_height_initial"] == -1, res
    assert res["waiting_for_hmu_initial"] is False, res
    # Single-segment transfer: the whole hashmap arrives in the advertisement.
    assert res["total_parts"] <= _HASHMAP_MAX_LEN, res
    assert res["hashmap_height_initial"] == res["total_parts"], res
    # Two in-order parts -> pointer advances to index 1, height unchanged.
    assert res["fed"] == 2, res
    assert res["received_count"] == 2, res
    assert res["consecutive_height_after"] == 1, (
        f"the consecutive pointer must advance one slot per in-order part: {res!r}"
    )
    assert res["hashmap_height_after"] == res["hashmap_height_initial"], res


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_hashmap_update",
    ],
    verifies=(
        "Resource hashmap-update is idempotent on a duplicate segment "
        "(Resource.hashmap_update, Resource.py:492-503): hashmap_height only "
        "grows for slots that were still None, so applying the SAME later segment "
        "twice grows the height once (first delivery) and not at all on the "
        "duplicate. An impl that double-counted a duplicate segment would "
        "over-report progress and mis-drive the part-request window"
    ),
)
def test_resource_hashmap_update_idempotent(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.inject_hashmap_update(link_id)
    assert res["total_parts"] > _HASHMAP_MAX_LEN, (
        f"expected a multi-segment hashmap (>74 parts): {res!r}"
    )
    # Advertisement carried only segment 0 (first 74 entries).
    assert res["height_after_advert"] == _HASHMAP_MAX_LEN, res
    # First HMU for segment 1 grows the height.
    assert res["grew_on_first"] is True, (
        f"the first hashmap-update segment did not grow the height: {res!r}"
    )
    # Duplicate HMU is idempotent — no further growth.
    assert res["grew_on_duplicate"] is False, (
        f"a duplicate hashmap-update wrongly grew the height: {res!r}"
    )
    assert res["height_after_duplicate"] == res["height_after_first"], res


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "resource_receiver_proof_count",
    ],
    verifies=(
        "A Resource receiver sends ZERO proofs while parts arrive and exactly ONE "
        "RESOURCE_PRF after the payload assembles (Resource.receive_part spawns "
        "assemble only at received_count==total_parts, Resource.py:894-896; "
        "assemble calls prove once, Resource.py:713/752-758). An impl that proved "
        "per part would flood the link and break the sender's single completion "
        "signal"
    ),
)
def test_resource_no_per_part_proofs(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.resource_receiver_proof_count(link_id)
    assert res["total_parts"] >= 2, f"expected a multi-part transfer: {res!r}"
    # No proof emitted while parts (all but the last) arrived.
    assert res["proofs_before_final"] == 0, (
        f"per-part proofs were emitted before assembly: {res!r}"
    )
    # Exactly one proof after assembly, and the transfer completed.
    assert res["complete"] is True, res
    assert res["proofs_after_assembly"] == 1, (
        f"a completed resource must emit exactly one proof: {res!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_crafted_resource_request",
    ],
    verifies=(
        "A Link de-dups a re-delivered RESOURCE_REQ by packet hash "
        "(Link.py:1109-1115): the first request is served and its packet hash "
        "recorded in the outgoing Resource's req_hashlist; an IDENTICAL second "
        "request packet is silently ignored (no further parts served, the hash "
        "appears exactly once). An impl that re-served a duplicate request would "
        "re-send parts and risk a sequencing error"
    ),
)
def test_resource_duplicate_request_deduped(wire_link_setup, wire_pair):
    server_impl, client_impl = wire_pair
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.inject_crafted_resource_request(link_id, "duplicate")
    assert res["total_parts"] >= 2, f"expected a multi-part sender: {res!r}"
    # First request served every part.
    assert res["first_served"] == res["total_parts"], res
    # The sender (link initiator) records the served request's packet hash in
    # the outgoing Resource's req_hashlist; kotlin's Link has no per-resource
    # request-hash list, so this and the de-dup below are an architectural gap.
    if client_impl == "kotlin":
        pytest.xfail(
            "reticulum-kt#resource-req-hashlist: no req_hashlist packet-hash "
            "de-dup on RESOURCE_REQ (Link has no per-resource request-hash "
            "list). Ref Link.py:1109-1115."
        )
    assert res["first_in_hashlist"] is True, res
    # Duplicate served nothing more and the hash is recorded exactly once.
    assert res["second_served"] == res["first_served"], (
        f"a duplicate request wrongly served more parts: {res!r}"
    )
    assert res["req_hashlist_len"] == 1, res
    assert res["deduped"] is True, res
