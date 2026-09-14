"""Remote DoS via the resource-proof path on a split in-memory transfer.

RNS bounds a single in-memory (byte-string) transfer to
``Resource.MAX_EFFICIENT_SIZE`` (``1*1024*1024 - 1``); anything larger is marked
``split`` and driven as a sequence of segments. When a segment's proof arrives,
the *sender's* ``Resource.validate_proof`` (``Resource.py:1088``) prepares and
advertises the next segment BEFORE concluding the transfer. For an in-memory
transfer the reference spills the payload to a temporary file at construction
(``Resource.py:274``) and keeps that handle as ``input_file``, so segment prep
can seek into it. A port that marks the transfer ``split`` from
``create(data=...)`` but never sets an input file for the in-memory path has no
file to seek: its segment preparer gives up and the proof validator waits for a
next segment that never materializes, spinning forever on the inbound thread
while holding the node-global jobs lock (``Transport.kt`` ``inbound`` wraps the
whole dispatch in ``jobsLock.withLock``). A peer reaches this by simply
completing one ordinary, valid in-memory transfer larger than the bound - no
malformed packets, no flood.

This is the DoS framing of a gap the suite already documents as a kotlin
*feature* xfail (test_resource_segmentation.py / test_resource_completeness.py:
"prepareNextSegment needs an inputFile byte-array sends never set"). Those
xfails treat multi-segment as an unimplemented feature; this test makes the
stronger claim that the reference's proof validator SPINS FOREVER (holding the
node-global jobs lock) rather than cleanly failing - a remote DoS reachable by
completing one valid transfer - and asserts it as a hard failure.

The stall is in the SENDER's proof path. In this harness the client is the link
initiator / resource sender, so the kotlin client is the DoS trigger: the test
fails on the kotlin-client pairs (the sender times out, the completion callback
never fires) and passes on the reference-client pairs. A 16 KiB single-segment
transfer first is the positive control, proving the Link moves resources at all
(so a timed-out split transfer is the input-file gap, not a broken link).

The sender-side completion is the discriminating observable. Receiver-side
byte reassembly of a split transfer is NOT asserted here: the kotlin receiver
has a separate, already-xfail'd "no segment-append" gap, so a reassembly
assertion would make the kotlin-receiver-only pair fail for the wrong reason.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["resource-dos"]

# RNS.Resource.MAX_EFFICIENT_SIZE on both implementations: 1*1024*1024 - 1.
# A payload strictly larger than this is split into >=2 segments. 1.5 MiB
# spans 2 segments (first = MAX_EFFICIENT_SIZE, second = the remainder) - the
# smallest shape that forces the sender's proof path to prepare a next segment.
_SPLIT_PAYLOAD = 1_572_864   # 1.5 MiB
_SINGLE_PAYLOAD = 16_384     # 16 KiB, single segment (positive control)
_SPLIT_TIMEOUT_MS = 60_000
_CONTROL_TIMEOUT_MS = 30_000
_POLL_TIMEOUT_MS = 30_000


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_send", "resource_poll",
    ],
    verifies=(
        "A split in-memory Resource transfer (payload > MAX_EFFICIENT_SIZE, "
        "1 MiB-1) sent by the link initiator CONCLUDES in bounded time. The "
        "reference spills an in-memory payload larger than the bound to a temp "
        "file (Resource.py:274) so the sender's validate_proof (Resource.py:"
        "1088) can prepare the next segment and the transfer completes. A port "
        "that marks the transfer split but never sets an input file for "
        "in-memory creation spins forever in validate_proof waiting for a next "
        "segment that never exists, holding the node-global jobs lock: the "
        "send times out (the completion callback never fires) even though the "
        "transfer is ordinary and valid - a remote DoS reachable by completing "
        "one valid transfer. A 16 KiB single-segment transfer is the positive "
        "control proving the Link moves resources at all"
    ),
)
def test_split_inmemory_resource_completes(wire_link_setup):
    # The client is the link initiator / resource sender - the peer whose proof
    # path is under test. The stall lives in the sender's validate_proof, so
    # this is the peer that must conclude the split transfer.
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Positive control: a single-segment in-memory transfer completes and
    # reassembles byte-exact, proving the Link moves resources at all (so a
    # timed-out split transfer is the input-file gap, not a broken link).
    # Reassembly is asserted here (single segment) because both reference and
    # kotlin reassemble a single segment cleanly; only the SPLIT reassembly
    # has the separate kotlin receiver-append gap, so it is not asserted below.
    control = secrets.token_bytes(_SINGLE_PAYLOAD)
    cresp = client.resource_send(link_id, control, timeout_ms=_CONTROL_TIMEOUT_MS)
    assert cresp["success"] is True, (
        f"{client.role_label} single-segment in-memory control transfer did "
        f"not complete - the Link is not moving resources at all, which "
        f"muddies the split-transfer repro: {cresp!r}"
    )
    got = server.resource_poll(dest_hash, timeout_ms=_POLL_TIMEOUT_MS)
    assert got == [control], (
        f"{server.role_label} did not reassemble the {len(control)}-byte "
        f"single-segment control resource byte-exact: "
        f"{[len(r) for r in got]}"
    )

    # The repro: a split in-memory transfer from the initiator. The reference
    # spills to a temp file and completes; a port missing the in-memory input
    # file times out (completion callback never fires) - the remote DoS.
    # Only SENDER-side completion is asserted (the DoS is in the sender's
    # proof path). Receiver reassembly of a split transfer is a separate,
    # already-xfail'd kotlin gap and is not asserted here.
    payload = secrets.token_bytes(_SPLIT_PAYLOAD)
    resp = client.resource_send(link_id, payload, timeout_ms=_SPLIT_TIMEOUT_MS)
    assert resp.get("total_segments", 0) >= 2, (
        f"the {len(payload)}-byte payload was not split into >=2 segments - "
        f"MAX_EFFICIENT_SIZE drifted and this test no longer exercises the "
        f"split path: {resp!r}"
    )
    assert resp["timed_out"] is False, (
        f"{client.role_label} split in-memory resource send (payload "
        f"{len(payload)} bytes, {resp.get('total_segments')} segments) TIMED "
        f"OUT - the transfer never reached its completion callback. A payload "
        f"larger than MAX_EFFICIENT_SIZE is split into segments, and the "
        f"sender's proof validator must prepare the next segment from the "
        f"transfer's input file; an in-memory transfer that never sets that "
        f"file leaves the validator waiting for a next segment that never "
        f"exists, spin-locked on the node's jobs lock - a remote DoS "
        f"triggered by completing one ordinary, valid transfer: {resp!r}"
    )
    assert resp["success"] is True, (
        f"{client.role_label} split in-memory resource send did not conclude "
        f"COMPLETE: {resp!r}"
    )
