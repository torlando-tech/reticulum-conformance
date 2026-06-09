"""Resource segmentation, multi-segment reassembly, and HMU coverage.

RNS bounds a single Resource transfer at MAX_EFFICIENT_SIZE (1 MiB - 1)
bytes per *segment* (Resource.py:116). A payload larger than that is split
into multiple segments, each sent and proven in turn, and appended on the
receiver into one reassembled stream (Resource.py:299/708/725/769). A
related limit governs the hashmap: a segment with more than
ResourceAdvertisement.HASHMAP_MAX_LEN (74) parts cannot fit its whole
hashmap in one advertisement, so RNS sends it across multiple hashmap
updates — the "HMU" regime (Resource.py:1040-1049).

Neither path was exercised anywhere in the suite (CONFORMANCE_REAUDIT.md §5
"Resource", CORE): the largest prior Resource test was 256 KiB, which is
both single-segment (well under 1 MiB) and — at the TCP interface's large
MDU — only ~32 parts, so it never crossed the 74-part HMU threshold. This
file adds the two CORE cases.

Three observables, all delegating to real RNS via the wire harness:

  * Segmentation boundary (construction). wire_resource_create builds a real
    RNS.Resource (advertise=False, nothing on the wire) and reports
    total_segments/segment_index/split. A payload of MAX_EFFICIENT_SIZE + 1
    must report total_segments == 2; a sub-threshold payload must report a
    single segment. This pins the boundary arithmetic without moving any
    data.

  * Multi-segment reassembly (transfer). A >1 MiB payload sent with
    wire_resource_send drives the full multi-segment send/append/proof loop
    (the sender's conclude callback fires only after the *last* segment's
    proof validates, Resource.py:788; the receiver appends each segment into
    one file and fires its callback once on the final segment with the whole
    payload, Resource.py:708/737). The receiver must hand back the exact
    original bytes.

  * HMU threshold (construction). On a Link whose per-part SDU is forced
    small, a modest payload chunks into more than 74 parts — the regime where
    the hashmap is advertised in multiple updates. The hashmap must remain
    exactly num_parts x MAPHASH_LEN bytes, and the same payload at the normal
    MDU must stay under the threshold (the positive control isolating the SDU
    as the cause).

The peer that creates/sends the resource (the client, which opens the
outbound Link) is the implementation under test; the wire_pair
parametrization rotates each implementation through that role. The server
anchors the Link and, for the transfer case, accepts and reassembles the
resource.
"""

import secrets
import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "resourceseg"
_ASPECTS = ["test"]

_SETTLE_SEC = 1.5
_LINK_TIMEOUT_MS = 15000
_PATH_POLL_TIMEOUT_MS = 10000
# A >1 MiB transfer drives two full segment send/prove cycles over a real
# TCP link; give it a generous budget so loopback windowing isn't the limit.
_RESOURCE_TIMEOUT_MS = 180000

# Per-segment ceiling: RNS splits a transfer once total_size exceeds this
# (Resource.py:116, MAX_EFFICIENT_SIZE = 1 MiB - 1). Hardcoded from the spec
# so an implementation that splits at the wrong boundary is itself a finding.
_MAX_EFFICIENT_SIZE = 1 * 1024 * 1024 - 1

# Above this many parts a segment's hashmap no longer fits in a single
# advertisement and RNS uses multi-advertisement hashmap updates (HMU):
# ResourceAdvertisement.HASHMAP_MAX_LEN = 74 (Resource.py:1236).
_HASHMAP_MAX_LEN = 74

# Bytes per map hash in the packed hashmap (Resource.py:102, MAPHASH_LEN).
_MAPHASH_LEN = 4

# A small forced per-part SDU: at 50 bytes/part even a few-KiB payload
# chunks into far more than 74 parts, putting the resource squarely in the
# HMU regime. The harness applies this only for the duration of the
# construction and restores the link's negotiated MTU afterward.
_FORCED_SDU = 50
_HMU_PAYLOAD_SIZE = 8192


def _establish_link(wire_peers):
    """Bring up a direct server<->client TCP pair and open one Link from the
    client to the server's IN destination.

    Returns (server, client, dest_hash, link_id). The client is the
    resource-creating/sending peer (the implementation under test); the
    server anchors the Link and, via wire_listen, is set up to accept and
    reassemble any inbound resource.
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
        f"destination — the Link could not be opened, so the segmentation "
        f"assertions below would be untestable."
    )
    link_id = client.link_open(
        dest_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    return server, client, dest_hash, link_id


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="A payload of MAX_EFFICIENT_SIZE + 1 (1 MiB) is split into exactly total_segments==2 (split=True, segment_index=1), while a sub-threshold payload stays single-segment (total_segments==1, split=False) — pinning the per-segment 1 MiB boundary (Resource.py:116/285/299)",
)
def test_payload_over_max_efficient_size_splits_into_two_segments(wire_peers):
    """Construction observable: a >1 MiB payload reports total_segments==2.

    RNS computes total_segments = ((total_size-1)//MAX_EFFICIENT_SIZE)+1 and
    sets split=True only once total_size exceeds MAX_EFFICIENT_SIZE
    (Resource.py:285/299). A payload one byte over the ceiling is the
    boundary case: it must report exactly two segments, this object being the
    first (segment_index==1). A small payload — the positive control — must
    report a single, unsplit segment, proving the split is driven by size and
    not always asserted.

    include_parts=False: the first segment of a 1 MiB payload is hundreds of
    parts at the real MDU, and the per-part bytes aren't needed here — only
    the segment counters are.
    """
    server, client, dest_hash, link_id = _establish_link(wire_peers)

    over_threshold = secrets.token_bytes(_MAX_EFFICIENT_SIZE + 1)
    multi = client.resource_create(link_id, over_threshold, include_parts=False)

    assert multi["total_segments"] == 2, (
        f"{client.role_label} reported total_segments={multi['total_segments']}"
        f" for a {_MAX_EFFICIENT_SIZE + 1}-byte payload (one byte over the "
        f"{_MAX_EFFICIENT_SIZE}-byte per-segment ceiling) — RNS splits this "
        f"into exactly 2 segments (Resource.py:299)."
    )
    assert multi["split"] is True, (
        f"{client.role_label} reported split=False for a payload exceeding "
        f"MAX_EFFICIENT_SIZE — the resource must be marked split "
        f"(Resource.py:301)."
    )
    assert multi["segment_index"] == 1, (
        f"{client.role_label} reported segment_index={multi['segment_index']}"
        f" for the first constructed segment — expected 1 (Resource.py:300)."
    )

    # Positive control: a payload below the ceiling is a single, unsplit
    # segment. Without this, an implementation that hardwired total_segments=2
    # would pass the assertions above.
    small = secrets.token_bytes(16384)
    single = client.resource_create(link_id, small, include_parts=False)
    assert single["total_segments"] == 1 and single["split"] is False, (
        f"{client.role_label} reported total_segments="
        f"{single['total_segments']} split={single['split']} for a "
        f"sub-threshold 16384-byte payload — expected a single unsplit "
        f"segment (Resource.py:285-288)."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_send", "resource_poll"],
    verifies="A >1 MiB Resource (2 segments) sent over a Link reassembles byte-exact at the receiver — the multi-segment send/append/proof loop (Resource.py:299/708/788) round-trips the entire payload, not just the first segment",
)
def test_multi_segment_transfer_reassembles_byte_exact(wire_peers):
    """Transfer observable: a >1 MiB payload survives the multi-segment path.

    A payload of MAX_EFFICIENT_SIZE + 64 KiB spans two segments with a
    non-trivial second segment. wire_resource_send blocks until the whole
    transfer concludes — the sender's callback fires only after the last
    segment's proof validates (Resource.py:788) — and the receiver appends
    each segment into one file, firing its conclude callback once, on the
    final segment, with the full reassembled payload (Resource.py:708/737).
    The receiver must hand back the exact original bytes; a sender that
    stopped after segment 1, or a receiver that dropped a segment, yields a
    short or mismatched payload.
    """
    server, client, dest_hash, link_id = _establish_link(wire_peers)

    payload = secrets.token_bytes(_MAX_EFFICIENT_SIZE + 64 * 1024)
    send_resp = client.resource_send(
        link_id, payload, timeout_ms=_RESOURCE_TIMEOUT_MS
    )
    assert send_resp["success"], (
        f"{client.role_label} multi-segment resource send of {len(payload)} "
        f"bytes did not complete: {send_resp!r}. The transfer spans 2 "
        f"segments; failure here points at segment sequencing on the send "
        f"side or proof handling between segments."
    )

    received = server.resource_poll(dest_hash, timeout_ms=_RESOURCE_TIMEOUT_MS)
    assert received == [payload], (
        f"{server.role_label} did not reassemble the {len(payload)}-byte "
        f"multi-segment resource from {client.role_label}. Got "
        f"{len(received)} resource(s) with sizes "
        f"{[len(r) for r in received]} — a size other than {len(payload)} "
        f"means a segment was lost or only the first segment arrived."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "listen", "link_open", "poll_path", "resource_create"],
    verifies="On a Link with a forced small per-part SDU a modest payload chunks into more than 74 parts (HASHMAP_MAX_LEN) — the HMU regime where the hashmap spans multiple advertisements — and the packed hashmap stays exactly num_parts x 4 bytes, while the same payload at the normal MDU stays under the threshold",
)
def test_small_mdu_resource_exceeds_hashmap_advertisement_limit(wire_peers):
    """Construction observable: a small SDU drives a resource over the 74-part
    HMU threshold.

    Above ResourceAdvertisement.HASHMAP_MAX_LEN (74) parts a segment's
    hashmap no longer fits in a single advertisement and RNS sends it across
    multiple hashmap updates (Resource.py:1040-1049). The harness forces the
    Link's per-part SDU down to a few dozen bytes for the duration of one
    construction, so an 8 KiB payload chunks into hundreds of parts — well
    past 74 — without moving a megabyte of data. The packed hashmap must
    still be exactly one MAPHASH_LEN-byte entry per part (Resource.py:471).

    Positive control: the SAME payload built at the link's normal (large) MDU
    stays well under 74 parts, isolating the small SDU — not the payload — as
    what pushes the resource into the HMU regime.
    """
    server, client, dest_hash, link_id = _establish_link(wire_peers)
    payload = secrets.token_bytes(_HMU_PAYLOAD_SIZE)

    hmu = client.resource_create(
        link_id, payload, force_sdu=_FORCED_SDU, include_parts=False
    )
    num_parts = hmu["num_parts"]
    hashmap = bytes.fromhex(hmu["hashmap"])

    assert num_parts > _HASHMAP_MAX_LEN, (
        f"{client.role_label} produced {num_parts} parts for an "
        f"{_HMU_PAYLOAD_SIZE}-byte payload at a forced {_FORCED_SDU}-byte SDU "
        f"— expected more than {_HASHMAP_MAX_LEN} (the HMU threshold) so the "
        f"multi-advertisement hashmap path is exercised."
    )
    assert len(hashmap) == num_parts * _MAPHASH_LEN, (
        f"{client.role_label} produced a {len(hashmap)}-byte hashmap for a "
        f"{num_parts}-part HMU resource — expected exactly "
        f"{num_parts} x {_MAPHASH_LEN} = {num_parts * _MAPHASH_LEN} bytes "
        f"(one map hash per part, Resource.py:471)."
    )

    # Positive control: the same payload at the link's real MDU stays under
    # the threshold, so the >74 result above is caused by the small SDU.
    normal = client.resource_create(link_id, payload, include_parts=False)
    assert normal["num_parts"] <= _HASHMAP_MAX_LEN, (
        f"{client.role_label} produced {normal['num_parts']} parts for the "
        f"same {_HMU_PAYLOAD_SIZE}-byte payload at the normal MDU — expected "
        f"at most {_HASHMAP_MAX_LEN}; if this already exceeds the threshold "
        f"the forced-SDU case is not isolating the HMU regime."
    )
