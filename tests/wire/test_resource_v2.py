"""Resource subsystem conformance — V2 gap closure.

Extends the existing Resource hooks/receiver-hooks/tamper coverage with the
windowed-handshake and lifecycle rules the prior passes pinned only partially:

  * the window-adaptation PROFILE constants the rate logic promotes/demotes to
    (WINDOW_MAX_SLOW/VERY_SLOW/FAST, the rate thresholds and round budgets) and
    the decompression-bomb ceiling AUTO_COMPRESS_MAX_SIZE — pinned as RNS 1.3.1
    spec literals off the live classes/instances (Resource.py:64-130/364-365);
  * the part-acceptance WINDOW bound — a genuine part beyond hashmap[cch:cch+
    window] is ignored, and a duplicate into a filled slot is not re-counted
    (Resource.receive_part, Resource.py:863-873);
  * the RESOURCE_REQ CONTENT request_next emits — requested-hash count <= window,
    scan anchored at cch+1, stop + EXHAUSTED at the first un-arrived hashmap slot,
    and no further request while waiting_for_hmu (Resource.request_next,
    Resource.py:931-980);
  * a receiver DERIVES total_parts = ceil(t/sdu), ignoring the advertised n
    (Resource.accept, Resource.py:187);
  * a FAILED (cancelled) Resource ignores every late part/HMU/request/proof
    (Resource.py:492/783/857/984);
  * the sender scope-advance on an aligned HMU
    (receiver_min_consecutive_height = max(part_index-1-WINDOW_MAX, 0),
    Resource.py:1038).

Every assertion anchors on an EXTERNAL RNS 1.3.1 code-literal / spec literal /
independent derivation, never impl-vs-itself; each rule has a positive and a
negative case. Runs reference-vs-reference; no SUT binary required.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["resource-v2"]

# RNS 1.3.1 spec literals — EXTERNAL ground truth, NOT read from the impl.
_WINDOW = 4
_WINDOW_MIN = 2
_WINDOW_MAX_SLOW = 10
_WINDOW_MAX_VERY_SLOW = 4
_WINDOW_MAX_FAST = 75
_WINDOW_FLEXIBILITY = 4
_FAST_RATE_THRESHOLD = _WINDOW_MAX_SLOW - _WINDOW - 2  # = 4
_VERY_SLOW_RATE_THRESHOLD = 2
_RATE_FAST = (50 * 1000) / 8        # 6250.0 bytes/s
_RATE_VERY_SLOW = (2 * 1000) / 8    # 250.0 bytes/s
_AUTO_COMPRESS_MAX_SIZE = 64 * 1024 * 1024  # 67108864
_HASHMAP_MAX_LEN = 74

_SETUP = [
    "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
    "link_open",
]


@conformance_case(
    commands=_SETUP + ["resource_constants"],
    verifies=(
        "Resource window-adaptation PROFILE + decompression-bomb constants match "
        "the RNS 1.3.1 spec literals (Resource.py:64-130): WINDOW_MAX_SLOW=10 "
        "(inbound start cap), WINDOW_MAX_VERY_SLOW=4, WINDOW_MAX_FAST=75 "
        "(==WINDOW_MAX), WINDOW_FLEXIBILITY=4, FAST_RATE_THRESHOLD=4 "
        "(=WINDOW_MAX_SLOW-WINDOW-2), VERY_SLOW_RATE_THRESHOLD=2, "
        "RATE_FAST=6250.0 B/s, RATE_VERY_SLOW=250.0 B/s, "
        "AUTO_COMPRESS_MAX_SIZE=64 MiB — plus the defining orderings "
        "(VERY_SLOW<SLOW<FAST window caps, RATE_VERY_SLOW<RATE_FAST). An impl "
        "with any divergent value adapts the transfer window or bombs-out "
        "differently and breaks interop / DoS protection"
    ),
)
def test_resource_window_profile_and_bomb_constants(wire_link_setup):
    server, client, _dest_hash, _link_id = wire_link_setup(_APP, _ASPECTS)
    c = client.resource_constants()
    assert c["WINDOW_MAX_SLOW"] == _WINDOW_MAX_SLOW, c
    assert c["WINDOW_MAX_VERY_SLOW"] == _WINDOW_MAX_VERY_SLOW, c
    assert c["WINDOW_MAX_FAST"] == _WINDOW_MAX_FAST, c
    assert c["WINDOW_MAX_FAST"] == c["WINDOW_MAX"], c
    assert c["WINDOW_FLEXIBILITY"] == _WINDOW_FLEXIBILITY, c
    assert c["FAST_RATE_THRESHOLD"] == _FAST_RATE_THRESHOLD, c
    assert c["VERY_SLOW_RATE_THRESHOLD"] == _VERY_SLOW_RATE_THRESHOLD, c
    assert c["RATE_FAST"] == _RATE_FAST, c
    assert c["RATE_VERY_SLOW"] == _RATE_VERY_SLOW, c
    assert c["AUTO_COMPRESS_MAX_SIZE"] == _AUTO_COMPRESS_MAX_SIZE, c
    # Defining relationships, not just the stored values.
    assert (
        c["WINDOW_MAX_VERY_SLOW"] < c["WINDOW_MAX_SLOW"] < c["WINDOW_MAX_FAST"]
    ), c
    assert c["RATE_VERY_SLOW"] < c["RATE_FAST"], c
    assert c["FAST_RATE_THRESHOLD"] == (
        c["WINDOW_MAX_SLOW"] - c["WINDOW"] - 2
    ), c


@conformance_case(
    commands=_SETUP + ["resource_decompress_limit"],
    verifies=(
        "A live Resource wires its decompression-bomb ceiling to the spec "
        "default (Resource.__init__, Resource.py:364-365): max_decompressed_size "
        "== auto_compress_limit == Resource.AUTO_COMPRESS_MAX_SIZE == 64 MiB. "
        "This is the bound the receiver's bounded BZ2Decompressor.decompress "
        "stops at before declaring a CORRUPT bomb; an impl that left it unbounded "
        "(or set a different default) would be DoS-able by a crafted payload"
    ),
)
def test_resource_decompress_default_ceiling(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)
    dl = client.resource_decompress_limit(link_id)
    assert dl["constant"] == _AUTO_COMPRESS_MAX_SIZE, dl
    assert dl["max_decompressed_size"] == _AUTO_COMPRESS_MAX_SIZE, dl
    assert dl["auto_compress_limit"] == _AUTO_COMPRESS_MAX_SIZE, dl


@conformance_case(
    commands=_SETUP + ["inject_crafted_resource_part"],
    verifies=(
        "A Resource receiver only accepts a part whose map hash falls in the "
        "current request WINDOW hashmap[cch:cch+window] (Resource.receive_part "
        "scans exactly that slice, Resource.py:863-872) and only into an EMPTY "
        "slot (parts[i] == None, Resource.py:873). A GENUINE part whose index is "
        "PAST the window is dropped (received_count unchanged), and a duplicate "
        "of an already-stored part is not re-counted. A receiver that scanned the "
        "whole hashmap, or re-counted duplicates, would accept out-of-order parts "
        "or over-report progress"
    ),
)
def test_resource_part_acceptance_window_bound(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Positive control: the sender's own first (in-window) part is accepted.
    ok = client.inject_crafted_resource_part(link_id, "valid")
    assert ok["accepted"] is True, ok

    # Negative: a genuine part one index PAST the window is dropped.
    beyond = client.inject_crafted_resource_part(link_id, "beyond_window")
    assert beyond["accepted"] is False, (
        f"a genuine part beyond hashmap[cch:cch+window] was wrongly accepted: {beyond!r}"
    )
    assert beyond["parts_after"] == beyond["parts_before"], beyond
    assert beyond["received_count_after"] == 0, beyond

    # Negative: a duplicate into a filled slot is not re-counted.
    dup = client.inject_crafted_resource_part(link_id, "duplicate_filled")
    assert dup["accepted"] is False, (
        f"a duplicate part into a filled slot was wrongly re-inserted: {dup!r}"
    )
    assert dup["received_count_after"] == 1, (
        f"a duplicate part wrongly bumped received_count: {dup!r}"
    )
    assert dup["parts_after"] == dup["parts_before"], dup


@conformance_case(
    commands=_SETUP + ["resource_request_next_content"],
    verifies=(
        "The RESOURCE_REQ a receiver emits (Resource.request_next, Resource.py:"
        "931-980) requests EXACTLY the still-missing hashmap entries starting at "
        "consecutive_completed_height+1, at most `window` of them, NOT exhausted "
        "while the scanned slots are loaded. Feeding 2 in-order parts first moves "
        "the scan anchor to cch+1==2 (proving it tracks the consecutive pointer, "
        "not a fixed 0). An impl that requested the wrong hashes, more than "
        "window, or off the wrong index would desynchronise the handshake"
    ),
)
def test_resource_request_next_content(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    init = client.resource_request_next_content(link_id, "initial")
    assert init["consecutive_height"] == -1, init
    assert init["exhausted"] is False, init
    assert init["waiting_for_hmu"] is False, init
    # Requested count is window-bounded, and is exactly the first `window` hashes.
    assert len(init["requested"]) <= init["window"], init
    assert len(init["requested"]) == init["window"], init
    assert init["requested"] == init["expected"], (
        f"the initial request did not name hashmap[0:window]: {init!r}"
    )

    ap = client.resource_request_next_content(link_id, "after_parts")
    assert ap["consecutive_height"] == 1, (
        f"feeding 2 in-order parts must move the pointer to index 1: {ap!r}"
    )
    assert ap["exhausted"] is False, ap
    assert len(ap["requested"]) <= ap["window"], ap
    # Scan anchored at cch+1 == 2: the requested hashes are hashmap[2:2+window].
    assert ap["requested"] == ap["expected"], (
        f"the request after 2 parts did not anchor on cch+1: {ap!r}"
    )
    assert len(ap["requested"]) >= 1, ap


@conformance_case(
    commands=_SETUP + ["resource_request_next_content"],
    verifies=(
        "When request_next's window reaches an un-arrived hashmap slot (a "
        "multi-segment transfer whose later hashmap segment has not been "
        "delivered) it sets the EXHAUSTED flag + waiting_for_hmu and stops "
        "(Resource.py:955-963); while waiting_for_hmu a further request_next "
        "emits NOTHING (Resource.py:937). An impl that kept requesting past the "
        "loaded segment edge, or re-requested while awaiting the hashmap update, "
        "would spin or desynchronise"
    ),
)
def test_resource_request_next_exhausted_and_gated(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    ex = client.resource_request_next_content(link_id, "exhausted")
    assert ex["total_parts"] > _HASHMAP_MAX_LEN, ex
    # Only hashmap segment 0 was loaded by the advertisement.
    assert ex["hashmap_height"] == _HASHMAP_MAX_LEN, ex
    # Fed HASHMAP_MAX_LEN-1 in-order parts -> pointer at the segment edge.
    assert ex["consecutive_height"] == _HASHMAP_MAX_LEN - 2, ex
    # The request hit the first un-arrived slot -> EXHAUSTED + waiting_for_hmu.
    assert ex["exhausted"] is True, (
        f"a request reaching an un-arrived hashmap slot was not EXHAUSTED: {ex!r}"
    )
    assert ex["waiting_for_hmu"] is True, ex
    assert 1 <= len(ex["requested"]) <= ex["window"], ex
    assert ex["requested"] == ex["expected"], ex
    # No further request while waiting for the hashmap update.
    assert ex["second_request_emitted"] is False, (
        f"a receiver re-requested parts while waiting_for_hmu: {ex!r}"
    )


@conformance_case(
    commands=_SETUP + ["resource_part_count_derivation"],
    verifies=(
        "A receiver DERIVES total_parts = ceil(transfer_size / sdu) from the "
        "advertised transfer size and its OWN link SDU (Resource.accept, "
        "Resource.py:187), and IGNORES the advertised part-count field n. An "
        "advertisement whose n is tampered (n+5) still yields total_parts == "
        "ceil(t/sdu) == the sender's true part count. An impl that trusted n "
        "could be handed a wrong count and build a mis-sized parts list"
    ),
)
def test_resource_receiver_derives_part_count(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    d = client.resource_part_count_derivation(link_id)
    assert d["adv_n_genuine"] == d["sender_parts"], d
    assert d["adv_n_tampered"] == d["adv_n_genuine"] + 5, d
    # Derived from t and the receiver's sdu, equal to the true part count.
    assert d["receiver_total_parts"] == d["derived_expected"], (
        f"receiver did not derive ceil(t/sdu): {d!r}"
    )
    assert d["receiver_total_parts"] == d["sender_parts"], d
    # The bogus advertised n was ignored.
    assert d["receiver_total_parts"] != d["adv_n_tampered"], (
        f"receiver trusted the tampered advertised part count: {d!r}"
    )


@conformance_case(
    commands=_SETUP + ["resource_late_after_cancel"],
    verifies=(
        "A FAILED (cancelled) Resource ignores every late packet — each entry "
        "point is guarded by `if not self.status == Resource.FAILED` "
        "(Resource.py:492/783/857/984). A cancelled RECEIVER does not insert a "
        "late part (received_count unchanged) nor grow its hashmap on a late HMU; "
        "a cancelled SENDER does not serve parts on a late request nor conclude "
        "COMPLETE on a late valid proof. A fresh un-cancelled sender DOES conclude "
        "on the same proof shape (positive control). An impl missing those guards "
        "would mutate or conclude an abandoned transfer"
    ),
)
def test_resource_failed_ignores_late_packets(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    lc = client.resource_late_after_cancel(link_id)
    # Receiver side.
    assert lc["receiver_status"] == "FAILED", lc
    assert (
        lc["receiver_received_after_late_part"] == lc["receiver_received_before"]
    ), (f"a cancelled receiver inserted a late part: {lc!r}")
    assert (
        lc["receiver_height_after_late_hmu"] == lc["receiver_height_before"]
    ), (f"a cancelled receiver grew its hashmap on a late HMU: {lc!r}")
    # Sender side.
    assert lc["sender_status"] == "FAILED", lc
    assert (
        lc["sender_sent_after_late_request"] == lc["sender_sent_before"]
    ), (f"a cancelled sender served parts on a late request: {lc!r}")
    assert lc["sender_status_after_late_proof"] == "FAILED", (
        f"a cancelled sender concluded COMPLETE on a late proof: {lc!r}"
    )
    # Positive control: the proof shape WOULD conclude an un-cancelled sender.
    assert lc["control_status_after_proof"] == "COMPLETE", (
        f"positive control: a valid proof did not conclude a live sender: {lc!r}"
    )


@conformance_case(
    commands=_SETUP + ["inject_crafted_resource_request"],
    verifies=(
        "On an aligned hashmap-exhausted RESOURCE_REQ the sender advances its "
        "search scope: receiver_min_consecutive_height = "
        "max(part_index-1-WINDOW_MAX, 0) (Resource.py:1038). For an HMU resolving "
        "to the segment-2 boundary (part_index 148) that is "
        "max(148-1-75,0)==72 — a NON-zero advance, so very large (>scope-window) "
        "transfers keep resolving requests against a sliding scope. An impl that "
        "never advanced the scope (stuck at 0) passes every small-transfer test "
        "but stalls large transfers"
    ),
)
def test_resource_sender_scope_advance_on_hmu(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    sc = client.inject_crafted_resource_request(link_id, "aligned_scope")
    assert sc["cancelled"] is False, (
        f"an aligned HMU at the segment-2 boundary wrongly cancelled: {sc!r}"
    )
    assert sc["scope_before"] == 0, sc
    expected_scope = max(sc["part_index"] - 1 - sc["window_max"], 0)
    assert sc["scope_after"] == expected_scope, (
        f"scope advance != max(part_index-1-WINDOW_MAX, 0): {sc!r}"
    )
    assert sc["scope_after"] > 0, (
        f"the scope did not genuinely advance: {sc!r}"
    )


@conformance_case(
    commands=_SETUP + ["resource_window_inheritance"],
    verifies=(
        "A second inbound transfer on a link INHERITS the previous transfer's "
        "final window (Resource.accept reads link.get_last_resource_window(), "
        "Resource.py:216-219; Link.resource_concluded records "
        "last_resource_window = resource.window on conclusion, Link.py:1284). A "
        "first transfer driven to natural COMPLETE grows its window past the "
        "WINDOW=4 default as in-order parts drain successive request windows; the "
        "second Resource.accept then starts at that inherited window, NOT the "
        "default. An impl that always restarted at 4 would degrade multi-resource "
        "throughput"
    ),
)
def test_resource_incoming_window_inheritance(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.resource_window_inheritance(link_id)
    assert res["default_window"] == _WINDOW, res
    assert res["total_parts_1"] > _WINDOW + 1, res
    assert res["completed_1"] is True, (
        f"the first inbound transfer did not complete: {res!r}"
    )
    # The first transfer grew its window above the default before concluding.
    assert res["window_after_complete"] > _WINDOW, (
        f"the window did not grow during the first transfer: {res!r}"
    )
    # The link recorded that grown window on conclusion.
    assert res["link_last_window"] == res["window_after_complete"], res
    # The second receiver inherited it, rather than restarting at the default.
    assert res["window2_initial"] == res["window_after_complete"], (
        f"the second inbound transfer did not inherit the window: {res!r}"
    )
    assert res["window2_initial"] != _WINDOW, res


@conformance_case(
    commands=_SETUP + ["resource_progress"],
    verifies=(
        "A non-split receiver reports get_progress() == received_count / "
        "total_parts and fires its progress callback exactly once per accepted "
        "part (Resource.get_progress, Resource.py:1126-1180; receive_part "
        "progress callback, Resource.py:884-887). With nothing received progress "
        "is 0.0; after feeding `feed` of `total` parts it is feed/total with "
        "exactly `feed` callback invocations. An impl reporting arbitrary "
        "progress, or never firing the callback, breaks the user-visible transfer "
        "progress LXMF clients rely on"
    ),
)
def test_resource_progress_accounting(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    p = client.resource_progress(link_id)
    assert p["total_parts"] >= 4, p
    assert p["fed"] >= 1, p
    assert p["progress_initial"] == 0.0, (
        f"progress with nothing received must be 0.0: {p!r}"
    )
    assert p["received_count"] == p["fed"], p
    # The documented contract: progress == received_count / total_parts.
    expected = p["fed"] / p["total_parts"]
    assert abs(p["progress_mid"] - expected) < 1e-9, (
        f"progress != received_count/total_parts: {p!r} (expected {expected})"
    )
    # The progress callback fired exactly once per accepted part.
    assert p["progress_callback_calls"] == p["fed"], (
        f"progress callback did not fire once per accepted part: {p!r}"
    )
