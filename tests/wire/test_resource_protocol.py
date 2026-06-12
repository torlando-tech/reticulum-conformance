"""Resource protocol behaviors over a live Link — the on-wire paths that the
construction-only invariant/segmentation tests cannot reach.

Everything here drives a REAL transfer (or a real mid-transfer abort) over an
established Link and reads the receiver-side state back through the wire
harness, so each property is observed on the implementation under test rather
than recomputed in the bridge or the test. The peer that opens the Link (the
client) is the resource sender / implementation under test; the server anchors
the Link and, via wire_listen, accepts + reassembles inbound Resources and
exposes the receiver-side observables (wire_resource_receiver_status,
wire_resource_poll, wire_listener_link_status).

The gaps closed (CONFORMANCE_GAPS.md §4b Resource):

  * HMU wire handshake (CORE). On a Link pinned to a small fixed MTU, a modest
    payload chunks into >74 parts — the regime where a segment's hashmap no
    longer fits one advertisement and RNS drives the multi-advertisement
    hashmap-update (HMU) handshake (Resource.py:140/:483-495,
    Link.py:1100/:1122). Asserts byte-exact reassembly AND that the receiver
    issued >=1 HMU request and took in >=1 hashmap update.

  * Accept strategies (ACCEPT_NONE / ACCEPT_APP) and sender cancel
    (Link.py:1087-1098/:1131/:1140, Resource.py:155/:1075). ACCEPT_NONE drops
    the advertisement so no parts flow and the sender never completes;
    ACCEPT_APP accepts/rejects per a deterministic predicate (RESOURCE_RCL ->
    sender REJECTED); an initiator cancel mid-transfer drives RESOURCE_ICL so
    the receiver's inbound Resource concludes FAILED.

  * Metadata 'x' flag round-trip (Resource.py:260-268/:696-704/:207-208 +
    ResourceAdvertisement flag bit 5, Resource.py:1307). A Resource carrying
    metadata reports has_metadata=True with flag bit 5 set, and BOTH the
    payload and the metadata round-trip byte-exact at the receiver; a
    no-metadata send is the negative control.

  * bz2 decompression-bomb bound (Resource.py:686-689/:1075-1084). A crafted
    compressed Resource whose decompressed size exceeds the receiver's bound is
    marked CORRUPT and the receiver tears the Link down; a normal compressible
    transfer under the bound is the positive control.
"""

import secrets
import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "resourceproto"

# RNS.Resource status codes (Resource.py:143-152). REJECTED == NONE == 0.
_REJECTED = 0x00
_TRANSFERRING = 0x03
_COMPLETE = 0x06
_FAILED = 0x07
_CORRUPT = 0x08

# RNS.Link status (Link.py): ACTIVE / CLOSED — read back as status_name.
_LINK_ACTIVE = "ACTIVE"
_LINK_CLOSED = "CLOSED"

# Smallest link MTU RNS allows pinning a TCPInterface to (Reticulum.MTU=500).
# At this MTU the per-part SDU is ~464 bytes, so a few tens of KiB chunks into
# well over the 74-part HMU threshold (ResourceAdvertisement.HASHMAP_MAX_LEN).
_SMALL_MTU = 500

# ACCEPT_APP predicate boundary the wire_listen 'app' callback advertises:
# accept iff advertised uncompressed data size <= 4096 (wire_tcp.py
# _RESOURCE_APP_ACCEPT_MAX_SIZE). Test payloads sit on the two sides of it.
_APP_ACCEPT_MAX = 4096

# Receiver-side decompression bound wire_listen lowers every inbound Resource to
# (wire_tcp.py _WIRE_RX_MAX_DECOMPRESSED). A crafted payload decompressing past
# this trips the bomb guard; a control payload well under it transfers fine.
_RX_DECOMPRESS_BOUND = 256 * 1024


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_send", "resource_poll",
        "resource_receiver_status",
    ],
    verifies="Over a Link pinned to a small fixed MTU a ~48 KiB Resource chunks into >74 parts and drives the on-wire HMU handshake: the payload reassembles byte-exact at the receiver AND the receiver's hmu_requests_sent >= 1 and hashmap_updates_received >= 1 (Resource.py:140/:483-495, Link.py:1100/:1122)",
)
def test_hmu_handshake_over_small_mtu_link(wire_pair, wire_link_setup):
    """CORE: a >74-part transfer exercises the multi-advertisement hashmap
    update (HMU) path, not just byte reassembly.

    The prior largest Resource test (256 KiB at the TCP HW MTU) was only ~32
    parts — it never crossed the 74-part threshold, so the HMU request/response
    handshake was confirmed-untested. Pinning the link MTU to 500 forces the
    per-part SDU down to ~464 bytes on BOTH ends, so a 48 KiB payload becomes
    ~105 parts; the receiver cannot fit the whole hashmap from the first
    advertisement and must request the remainder via RESOURCE_HMU. The
    receiver-side counters are the discriminating observable: an implementation
    that reassembled the bytes some other way (e.g. carrying the full hashmap
    inline) would deliver the payload but leave hmu_requests_sent at 0.
    """
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP_NAME, aspects=("hmu",), fixed_mtu=_SMALL_MTU
    )

    payload = secrets.token_bytes(48 * 1024)
    send_resp = client.resource_send(link_id, payload, timeout_ms=120000)
    assert send_resp["success"], (
        f"{client.role_label} resource send over the {_SMALL_MTU}-MTU link did "
        f"not complete: {send_resp!r}. At this MTU the {len(payload)}-byte "
        f"payload spans >74 parts, so failure points at the HMU handshake or "
        f"windowed part delivery."
    )

    received = server.resource_poll(dest_hash, timeout_ms=120000)
    assert received == [payload], (
        f"{server.role_label} did not reassemble the {len(payload)}-byte "
        f">74-part resource byte-exact. Got {len(received)} resource(s) with "
        f"sizes {[len(r) for r in received]}."
    )

    status = server.resource_receiver_status(dest_hash, timeout_ms=5000)
    assert status["found"] and status["status"] == _COMPLETE, (
        f"{server.role_label} receiver status for the HMU transfer is "
        f"{status!r} — expected a COMPLETE inbound Resource."
    )
    assert status["hmu_requests_sent"] >= 1, (
        f"{server.role_label} reported hmu_requests_sent="
        f"{status['hmu_requests_sent']} for a {status.get('found') and 'multi'}"
        f"-part transfer that exceeds the 74-part HMU threshold — RNS must "
        f"request the rest of the hashmap via RESOURCE_HMU (Resource.py:483-495)."
    )
    assert status["hashmap_updates_received"] >= 1, (
        f"{server.role_label} reported hashmap_updates_received="
        f"{status['hashmap_updates_received']} — a >74-part transfer must take "
        f"in at least one hashmap-update packet (Resource.py:492-499)."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_send", "resource_poll",
    ],
    verifies="On an ACCEPT_APP link the per-Resource predicate (accept iff advertised data size <= 4096) is honored both ways: a 1 KiB Resource is accepted and reassembles byte-exact (status COMPLETE), while a 16 KiB Resource is rejected — RESOURCE_RCL drives the sender to status REJECTED(0) and nothing reassembles (Link.py:1088-1095/:1140)",
)
def test_accept_app_accepts_small_rejects_oversize(wire_pair, wire_link_setup):
    """IMPORTANT: ACCEPT_APP True-vs-False on the SAME link.

    The listener installs a deterministic resource_callback that accepts a
    Resource iff its advertised uncompressed data size is <= 4096. A small
    payload (the positive side) must transfer to COMPLETE and reassemble
    byte-exact; an oversize payload (the negative side) must be rejected, the
    RESOURCE_RCL landing the sender's outgoing Resource at status REJECTED(0)
    with nothing delivered. Random (incompressible) payloads keep the advertised
    data size equal to len(payload), so each sits cleanly on its side of 4096.
    """
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP_NAME, aspects=("app",), resource_strategy="app"
    )

    # Positive side: <= 4096 -> accepted -> COMPLETE, byte-exact.
    small = secrets.token_bytes(1024)
    assert len(small) <= _APP_ACCEPT_MAX
    accepted = client.resource_send(link_id, small, timeout_ms=30000)
    assert accepted["success"] and accepted["status"] == _COMPLETE, (
        f"{client.role_label} send of a {len(small)}-byte payload (under the "
        f"ACCEPT_APP {_APP_ACCEPT_MAX}-byte boundary) did not COMPLETE: "
        f"{accepted!r} — the accept callback should have admitted it."
    )
    assert server.resource_poll(dest_hash, timeout_ms=5000) == [small], (
        f"{server.role_label} did not reassemble the accepted {len(small)}-byte "
        f"resource byte-exact."
    )

    # Negative side: > 4096 -> rejected -> RESOURCE_RCL -> sender REJECTED(0).
    big = secrets.token_bytes(16 * 1024)
    assert len(big) > _APP_ACCEPT_MAX
    rejected = client.resource_send(link_id, big, timeout_ms=30000)
    assert not rejected["success"] and rejected["status"] == _REJECTED, (
        f"{client.role_label} send of a {len(big)}-byte payload (over the "
        f"ACCEPT_APP boundary) returned {rejected!r} — the reject callback "
        f"should have driven RESOURCE_RCL and left the sender at status "
        f"REJECTED({_REJECTED}), not COMPLETE."
    )
    assert server.resource_poll(dest_hash, timeout_ms=2000) == [], (
        f"{server.role_label} reassembled a resource that ACCEPT_APP should "
        f"have rejected — no parts must flow for a rejected advertisement."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_send", "resource_poll",
        "resource_receiver_status",
    ],
    verifies="An ACCEPT_NONE link drops the Resource advertisement: no parts flow, the receiver never starts an inbound Resource (found=False) and the sender cannot complete; a sibling ACCEPT_ALL destination on the same peers transfers the identical payload byte-exact as the positive control (Link.py:1087)",
)
def test_accept_none_blocks_transfer(wire_pair, wire_link_setup):
    """IMPORTANT: ACCEPT_NONE -> no parts, sender does not complete.

    Under ACCEPT_NONE the inbound Link simply ``pass``es on every RESOURCE_ADV
    (Link.py:1087), so the receiver never registers an incoming Resource and the
    sender's transfer can never conclude COMPLETE — it is bounded here by a
    short send timeout (the natural watchdog FAILED would take ~16 advertisement
    retries). The discriminator is that NO inbound Resource is ever created
    (found=False). A second listening destination on the SAME peer pair, set to
    ACCEPT_ALL, transfers the identical payload byte-exact — the positive
    control proving the failure is the strategy, not a broken link.
    """
    server, client, dest_none, link_none = wire_link_setup(
        app_name=_APP_NAME, aspects=("none",), resource_strategy="none"
    )

    # Positive control destination on the same pair, accepting everything.
    dest_all = server.listen(
        app_name=_APP_NAME, aspects=["allctrl"], resource_strategy="all"
    )
    assert client.poll_path(dest_all, timeout_ms=10000), (
        f"{client.role_label} never learned a path to the ACCEPT_ALL control "
        f"destination — the positive control could not be set up."
    )
    link_all = client.link_open(
        dest_all, app_name=_APP_NAME, aspects=["allctrl"], timeout_ms=15000
    )

    payload = secrets.token_bytes(2048)

    # Negative: ACCEPT_NONE link — bounded send cannot complete, no parts flow.
    neg = client.resource_send(link_none, payload, timeout_ms=6000)
    assert not neg["success"], (
        f"{client.role_label} reported success={neg['success']} sending over an "
        f"ACCEPT_NONE link — the receiver discards the advertisement, so the "
        f"transfer can never conclude COMPLETE: {neg!r}."
    )
    none_status = server.resource_receiver_status(dest_none, timeout_ms=0)
    assert none_status["found"] is False, (
        f"{server.role_label} created an inbound Resource on an ACCEPT_NONE "
        f"link ({none_status!r}) — ACCEPT_NONE must drop the advertisement "
        f"before any Resource is registered (no parts flow)."
    )
    assert server.resource_poll(dest_none, timeout_ms=1000) == [], (
        f"{server.role_label} reassembled a resource on an ACCEPT_NONE link."
    )

    # Positive control: identical payload over ACCEPT_ALL completes byte-exact.
    pos = client.resource_send(link_all, payload, timeout_ms=30000)
    assert pos["success"] and pos["status"] == _COMPLETE, (
        f"{client.role_label} could not transfer the identical {len(payload)}-"
        f"byte payload over the ACCEPT_ALL control destination: {pos!r} — if "
        f"this fails the ACCEPT_NONE assertion above is not isolating the "
        f"strategy."
    )
    assert server.resource_poll(dest_all, timeout_ms=10000) == [payload], (
        f"{server.role_label} did not reassemble the ACCEPT_ALL control "
        f"transfer byte-exact."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_send", "resource_poll", "resource_cancel",
        "resource_receiver_status",
    ],
    verifies="An initiator that cancels a Resource mid-transfer sends RESOURCE_ICL: the receiver's actively-TRANSFERRING inbound Resource transitions to FAILED (not CORRUPT) and the sender's Resource lands at status FAILED; a small uncancelled send over the same link completes byte-exact as the positive control (Resource.py:1075, Link.py:1131-1138)",
)
def test_sender_cancel_midtransfer_drives_receiver_icl(wire_pair, wire_link_setup):
    """IMPORTANT: initiator cancel -> RESOURCE_ICL -> receiver FAILED.

    The link is pinned small so a large single-segment payload spans ~2000
    parts and stays in flight long enough to be cancelled deterministically:
    the test starts a non-blocking send, waits until the receiver reports the
    inbound Resource is actively TRANSFERRING, then cancels. RNS.Resource.cancel
    on the initiator sends a RESOURCE_ICL whose receipt drives the receiver's
    incoming Resource to FAILED (Link.py:1136-1138) — distinct from the CORRUPT
    teardown the bomb test exercises. A small uncancelled send over the same
    link first proves the transfer machinery works (positive control), so the
    FAILED is attributable to the cancel.
    """
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP_NAME, aspects=("icl",), fixed_mtu=_SMALL_MTU
    )

    # Positive control: a small uncancelled transfer completes byte-exact.
    ctrl = secrets.token_bytes(1024)
    ctrl_resp = client.resource_send(link_id, ctrl, timeout_ms=30000)
    assert ctrl_resp["success"], (
        f"{client.role_label} control send failed: {ctrl_resp!r} — the link "
        f"itself is unhealthy, so the cancel assertion below would be moot."
    )
    assert server.resource_poll(dest_hash, timeout_ms=5000) == [ctrl], (
        f"{server.role_label} did not reassemble the control transfer."
    )
    baseline = server.resource_receiver_status(dest_hash, timeout_ms=0)
    baseline_count = baseline.get("resource_count", 0)

    # Large single-segment payload: ~2000 parts at the small MTU, so it stays
    # mid-transfer long enough to cancel.
    big = secrets.token_bytes(900 * 1024)
    started = client.resource_send(link_id, big, wait=False)
    resource_id = started["resource_id"]
    assert started.get("started"), f"non-blocking send did not start: {started!r}"

    # Wait until the receiver has registered the big inbound Resource AND it is
    # actively transferring (a NEW record beyond the control, status
    # TRANSFERRING) — proving real parts are flowing before we cancel.
    deadline = time.time() + 20.0
    rstat = None
    while time.time() < deadline:
        rstat = server.resource_receiver_status(dest_hash, timeout_ms=0)
        if (
            rstat.get("resource_count", 0) > baseline_count
            and rstat.get("status") == _TRANSFERRING
        ):
            break
        time.sleep(0.05)
    assert (
        rstat is not None
        and rstat.get("resource_count", 0) > baseline_count
        and rstat.get("status") == _TRANSFERRING
    ), (
        f"{server.role_label} never reported the large inbound Resource in "
        f"TRANSFERRING before the cancel window elapsed: {rstat!r} — cannot "
        f"prove the transfer was live when cancelled."
    )

    # Cancel mid-transfer: sender Resource -> FAILED, RESOURCE_ICL emitted.
    cancelled = client.resource_cancel(resource_id)
    assert cancelled["cancelled"] and cancelled["status"] == _FAILED, (
        f"{client.role_label} cancel of the in-flight Resource returned "
        f"{cancelled!r} — RNS.Resource.cancel must set the initiator's status "
        f"to FAILED({_FAILED})."
    )

    # Receiver observes the ICL and concludes its inbound Resource FAILED.
    final = server.resource_receiver_status(dest_hash, timeout_ms=15000)
    assert final["status"] == _FAILED, (
        f"{server.role_label} inbound Resource concluded at status "
        f"{final.get('status')} ({final.get('status_name')}), expected "
        f"FAILED({_FAILED}) after the initiator's RESOURCE_ICL: {final!r}."
    )
    assert final["corrupt"] is False, (
        f"{server.role_label} marked the cancelled Resource CORRUPT — an "
        f"initiator cancel is a clean FAILED, not a decompression/integrity "
        f"failure."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_create", "resource_send", "resource_poll",
        "resource_receiver_status",
    ],
    verifies="A Resource carrying metadata sets has_metadata=True with ResourceAdvertisement flag bit 5 set, and BOTH the payload and the metadata round-trip byte-exact at the receiver; a no-metadata Resource clears the flag and the receiver sees has_metadata=False / metadata=None (Resource.py:260-268/:696-704/:1307)",
)
def test_metadata_x_flag_round_trip(wire_pair, wire_link_setup):
    """IMPORTANT: the 'x' metadata field round-trips and sets flag bit 5.

    Construction observable (wire_resource_create, advertise=False): a metadata
    Resource reports has_metadata=True and ResourceAdvertisement.f bit 5 set
    (f = ... | x<<5 ...); a no-metadata Resource clears both — the negative
    control isolating the flag bit. Transfer observable: a real send with
    metadata reassembles the payload byte-exact AND surfaces the metadata bytes
    byte-exact at the receiver (umsgpack round-trip, Resource.py:696-704); a
    no-metadata send surfaces metadata=None.
    """
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP_NAME, aspects=("meta",)
    )

    payload = secrets.token_bytes(4096)
    metadata = b"conformance-x-flag:" + secrets.token_bytes(48)

    # --- Construction: flag bit 5 tracks has_metadata. ---
    with_md = client.resource_create(link_id, payload, metadata=metadata)
    assert with_md["has_metadata"] is True, (
        f"{client.role_label} built a Resource with metadata= but reported "
        f"has_metadata={with_md['has_metadata']}."
    )
    assert (with_md["flags"] >> 5) & 1 == 1, (
        f"{client.role_label} produced advertisement flags={with_md['flags']:#04x}"
        f" for a metadata Resource — bit 5 (the 'x' metadata flag, f|=x<<5, "
        f"Resource.py:1307) must be set."
    )

    without_md = client.resource_create(link_id, payload)
    assert without_md["has_metadata"] is False, (
        f"{client.role_label} reported has_metadata=True for a Resource built "
        f"with no metadata= argument."
    )
    assert (without_md["flags"] >> 5) & 1 == 0, (
        f"{client.role_label} set advertisement flag bit 5 "
        f"(flags={without_md['flags']:#04x}) for a Resource carrying no "
        f"metadata — the 'x' flag must be clear."
    )

    # --- Transfer: payload AND metadata round-trip byte-exact. ---
    sent = client.resource_send(
        link_id, payload, metadata=metadata, timeout_ms=30000
    )
    assert sent["success"] and sent["has_metadata"] is True, (
        f"{client.role_label} metadata send did not complete: {sent!r}."
    )
    rx = server.resource_receiver_status(dest_hash, timeout_ms=30000)
    assert rx["found"] and rx["status"] == _COMPLETE, (
        f"{server.role_label} inbound metadata Resource is {rx!r}, expected "
        f"COMPLETE."
    )
    assert rx["has_metadata"] is True, (
        f"{server.role_label} received the Resource without has_metadata set — "
        f"the 'x' flag did not survive the wire."
    )
    assert rx["metadata"] == metadata.hex(), (
        f"{server.role_label} surfaced metadata {rx['metadata']!r}, expected "
        f"{metadata.hex()!r} — the metadata field did not round-trip byte-exact."
    )
    assert rx["data"] == payload.hex(), (
        f"{server.role_label} reassembled payload that does not match the "
        f"sent bytes (metadata must be stripped from the payload, "
        f"Resource.py:696-704)."
    )
    assert server.resource_poll(dest_hash, timeout_ms=5000) == [payload], (
        f"{server.role_label} resource_poll did not yield the metadata-stripped "
        f"payload byte-exact."
    )

    # --- Negative round-trip: no metadata -> has_metadata False, metadata None. ---
    sent2 = client.resource_send(link_id, payload, timeout_ms=30000)
    assert sent2["success"] and sent2["has_metadata"] is False, (
        f"{client.role_label} no-metadata send reported {sent2!r}."
    )
    rx2 = server.resource_receiver_status(dest_hash, timeout_ms=30000)
    assert rx2["has_metadata"] is False and rx2["metadata"] is None, (
        f"{server.role_label} reported metadata on a no-metadata transfer: "
        f"{rx2!r}."
    )
    assert rx2["data"] == payload.hex(), (
        f"{server.role_label} did not reassemble the no-metadata payload "
        f"byte-exact."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_send", "resource_poll", "resource_send_bomb",
        "resource_receiver_status", "listener_link_status",
    ],
    verifies="A crafted compressed Resource whose decompressed size exceeds the receiver's bound is marked CORRUPT and the receiver tears the Link down (status CLOSED); a normal compressible transfer under the bound completes with the Link still ACTIVE as the positive control (Resource.py:686-689/:1075-1084)",
)
def test_bz2_decompression_bomb_marks_corrupt_and_tears_link(wire_pair, wire_link_setup):
    """IMPORTANT: the bz2 decompression-bomb bound -> CORRUPT + link teardown.

    The listener lowers every inbound Resource's max_decompressed_size to a
    small bound. A normal compressible payload that decompresses well under the
    bound transfers to COMPLETE and leaves the inbound Link ACTIVE (positive
    control). The crafted bomb (a payload that bz2-compresses tiny but inflates
    past the bound) makes the receiver's bounded decompressor stop short of EOF,
    so RNS marks the Resource CORRUPT and tears the Link down
    (Resource.py:686-689 -> cancel() -> link.teardown()). Observed via the
    receiver's CORRUPT verdict and the inbound link transitioning to CLOSED.
    """
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP_NAME, aspects=("bomb",)
    )

    # Positive control: a compressible payload under the bound completes and
    # leaves the link ACTIVE.
    control = (b"reticulum-bomb-control-" * 512)[: 8 * 1024]
    ctrl = client.resource_send(link_id, control, timeout_ms=30000)
    assert ctrl["success"], (
        f"{client.role_label} control compressible send failed: {ctrl!r}."
    )
    assert server.resource_poll(dest_hash, timeout_ms=5000) == [control], (
        f"{server.role_label} did not reassemble the control payload."
    )
    pre = server.listener_link_status(dest_hash, timeout_ms=5000)
    assert pre["found"] and pre["status_name"] == _LINK_ACTIVE, (
        f"{server.role_label} inbound link was {pre!r} before the bomb, "
        f"expected ACTIVE — the teardown assertion needs a healthy starting "
        f"point."
    )

    # The bomb: decompresses past the receiver's bound -> CORRUPT + teardown.
    bomb = client.resource_send_bomb(
        link_id, decompressed_size=2 * _RX_DECOMPRESS_BOUND, timeout_ms=30000
    )
    assert not bomb["success"], (
        f"{client.role_label} decompression-bomb send reported success — the "
        f"receiver must reject it: {bomb!r}."
    )
    # The CORRUPT path REJECTS the sender, not merely tears the link down: the
    # receiver's cancel() calls reject() -> sends a RESOURCE_RCL packet to the
    # sender (Resource.py:1083, 155-160) BEFORE link.teardown(), so the sender's
    # Resource lands in REJECTED (0), not FAILED (7). Pinning REJECTED here is
    # the on-wire-RCL observable a bare teardown could not produce.
    assert bomb["status"] == _REJECTED, (
        f"{client.role_label}'s bombed Resource ended in status {bomb['status']} "
        f"(expected REJECTED=={_REJECTED}); the receiver must send a RESOURCE_RCL "
        f"on the CORRUPT path, not merely tear the link down (which would leave "
        f"the sender FAILED=={_FAILED}): {bomb!r}."
    )

    rx = server.resource_receiver_status(dest_hash, timeout_ms=20000)
    assert rx["found"] and rx["corrupt"] is True and rx["status"] == _CORRUPT, (
        f"{server.role_label} did not mark the over-bound Resource CORRUPT: "
        f"{rx!r} — the bounded bz2 decompressor must stop short of EOF "
        f"(Resource.py:686-689)."
    )

    # The receiver tears the link down on a CORRUPT verdict (Resource.cancel ->
    # link.teardown()). Poll the inbound link until it reaches CLOSED.
    deadline = time.time() + 10.0
    ls = None
    while time.time() < deadline:
        ls = server.listener_link_status(dest_hash, timeout_ms=0)
        if ls.get("status_name") == _LINK_CLOSED:
            break
        time.sleep(0.1)
    assert ls is not None and ls["status_name"] == _LINK_CLOSED, (
        f"{server.role_label} did not tear the inbound link down after a "
        f"CORRUPT Resource: {ls!r} — Resource.cancel() on CORRUPT calls "
        f"link.teardown() (Resource.py:1081-1084)."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "resource_send", "resource_poll", "resource_receiver_status",
    ],
    verifies=(
        "The receiver's Resource lifecycle callbacks fire exactly as RNS "
        "specifies: the resource_started callback fires once when an inbound "
        "Resource begins (Resource.py:227-231) and the conclude callback fires "
        "once, only when the final segment assembles, carrying the whole "
        "reassembled payload (Resource.py:725-740). A single-segment transfer is "
        "pinned via the receiver's started-callback count (== 1) and a single "
        "full-data conclude (status COMPLETE, byte-exact payload). An impl that "
        "never fires resource_started, or concludes per-part instead of once at "
        "the end, diverges"
    ),
)
def test_receiver_resource_callbacks_lifecycle(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        app_name=_APP_NAME, aspects=("callbacks",)
    )

    # A small payload is a single Resource segment, so the started callback must
    # fire exactly once and the conclude exactly once with the full payload.
    payload = secrets.token_bytes(3 * 1024)
    send = client.resource_send(link_id, payload, timeout_ms=30000)
    assert send["success"], (
        f"{client.role_label} single-segment resource send failed: {send!r}"
    )
    assert send["total_segments"] == 1, (
        f"test precondition: payload must be a single segment, got "
        f"total_segments={send.get('total_segments')!r}: {send!r}"
    )

    rx = server.resource_receiver_status(dest_hash, timeout_ms=10000)
    assert rx["found"] and rx["status"] == _COMPLETE, (
        f"{server.role_label} inbound Resource did not conclude COMPLETE: {rx!r}"
    )
    # resource_started fired exactly once (one inbound-Resource record).
    assert rx["resource_count"] == 1, (
        f"the resource_started callback fired {rx['resource_count']} time(s), "
        f"expected exactly 1 for a single-segment transfer: {rx!r}"
    )
    # The single conclude carried the whole reassembled payload.
    assert rx["data"] == payload.hex(), (
        f"the conclude callback did not deliver the byte-exact payload "
        f"(a per-segment conclude would deliver a short chunk): {rx!r}"
    )
    # And exactly one conclude landed in the concluded buffer (not one per part).
    assert server.resource_poll(dest_hash, timeout_ms=2000) == [payload], (
        f"{server.role_label} concluded the Resource more than once, or not with "
        f"the full payload — the conclude must fire once at the final segment."
    )
