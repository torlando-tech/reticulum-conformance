"""RNS Link on-wire protocol conformance (CONFORMANCE_GAPS.md §4b Link).

The lifecycle suite (test_link_lifecycle.py) pins the watchdog timings and
teardown reasons; the request suite pins request/response RPC. This module
drives the *protocol behaviours that ride on an established Link* and were
previously only smoke-tested (or pinned at construction-time scalars) rather
than asserted on the wire, all validated against RNS 1.3.1:

  * Proof-strategy DATA behaviour (Link.py:999-1008): a link DATA packet is
    auto-proved under PROVE_ALL (the sender's PacketReceipt reaches DELIVERED),
    never under PROVE_NONE, and under PROVE_APP only when the destination's
    proof_requested callback returns True. Previously only the stored constant
    35/34/33 was asserted (test_link_lifecycle.py::test_proof_strategy_sets_
    destination_constant); the actual on-wire proof emission was never driven.

  * Keepalive byte values (Link.py:848-849/:974/:1149-1153): the keepalive
    protocol is a single byte — the initiator emits 0xFF and a NON-initiator
    answers with 0xFE, refreshing last_inbound but NOT last_data (keepalives are
    not payload data); the initiator drops its own 0xFF echo entirely (the
    receive guard at Link.py:974), so it never bumps last_inbound/last_data on
    its own keepalive. Previously only the keepalive *timing* was observed.

  * Link MTU/MDU/mode read-back (Link.py:609/:618/:636/:530): get_mtu()/
    get_mdu() return the negotiated values only while ACTIVE (None otherwise),
    get_mode() always returns the mode constant. mdu is the update_mdu floor
    (a 16-byte-aligned value below mtu). Previously no mtu/mdu/mode field
    existed on the link snapshot.

  * Remote-identity observation (Link.py:683-687/:1010-1028): the receiver-side
    link's get_remote_identity()/remote_identified only become populated once
    the initiator independently calls Link.identify — distinct from the
    request-handler remote_identity argument covered in test_link_identify.py.

  * STALE->ACTIVE watchdog recovery (Link.py:983-984): an inbound packet on a
    STALE link transitions it straight back to ACTIVE.

Everything drives REAL RNS.Link objects over a loopback TCP pair via the wire
bridge and reads back the live fields RNS computes. Every test passes
reference-vs-reference (the reference bridge plays both peers).
"""

import secrets
import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("link-protocol",)

# A fixed small link MTU so the negotiated SDU stays small: it pins an exact,
# assertable link.mtu (the negotiated value survives) and pushes a modest
# request/response over the link MDU so the >MDU resource path is exercised.
# Must be >= Reticulum.MTU (500); 500 is the floor.
_FIXED_MTU = 500

# RNS.Link.MODE_AES256_CBC (the only enabled link mode in RNS 1.3.1). Pinned as
# a known-answer; the wire harness deliberately does not import RNS.
_MODE_AES256_CBC = 1

# RNS.Link status ints (PENDING/HANDSHAKE/ACTIVE/STALE/CLOSED).
_STATUS_PENDING = 0
_STATUS_ACTIVE = 2
_STATUS_STALE = 3
_STATUS_CLOSED = 4


# --- Proof-strategy DATA behaviour (Link.py:999-1008) ----------------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "set_proof_strategy", "send_link_data",
        "packet_receipt_status",
    ],
    verifies="Proof-strategy governs auto-proof of inbound link DATA (Link.py:999-1008): with the destination set to PROVE_ALL a link DATA packet sent with a tracked PacketReceipt is auto-proved and the receipt reaches DELIVERED; with PROVE_NONE on the SAME link no proof is emitted and the receipt never DELIVERS (concludes FAILED). The PROVE_ALL delivery is the positive control for the PROVE_NONE negative.",
)
def test_link_data_proved_under_prove_all_not_under_prove_none(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        _APP, _ASPECTS, fixed_mtu=_FIXED_MTU,
    )

    # PROVE_ALL: the receiver auto-proves every inbound link DATA packet, so the
    # returning PROOF validates the sender's PacketReceipt to DELIVERED.
    server.set_proof_strategy(dest_hash, "all")
    sent = client.send_link_data(link_id, secrets.token_bytes(24), create_receipt=True)
    assert sent["sent"] and sent["receipt_id"], (
        f"send_link_data did not produce a tracked receipt: {sent!r}"
    )
    status = client.packet_receipt_status(sent["receipt_id"], timeout_ms=6000)
    assert status["delivered"] is True, (
        f"PROVE_ALL: the receiver must auto-prove inbound link DATA so the "
        f"sender's receipt reaches DELIVERED, got {status!r}"
    )

    # PROVE_NONE on the same link: no proof is emitted, so the receipt cannot
    # reach DELIVERED. (The PROVE_ALL delivery above proves the proof return
    # path works, so this non-delivery is meaningful, not a dead path.)
    server.set_proof_strategy(dest_hash, "none")
    sent2 = client.send_link_data(link_id, secrets.token_bytes(24), create_receipt=True)
    assert sent2["sent"] and sent2["receipt_id"], (
        f"send_link_data did not produce a tracked receipt: {sent2!r}"
    )
    status2 = client.packet_receipt_status(sent2["receipt_id"], timeout_ms=6000)
    assert status2["delivered"] is False, (
        f"PROVE_NONE: the receiver must NOT prove inbound link DATA, so the "
        f"sender's receipt must never reach DELIVERED, got {status2!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "set_proof_strategy", "send_link_data",
        "packet_receipt_status",
    ],
    verifies="PROVE_APP defers the proof decision to the destination's proof_requested callback (Link.py:1002-1008): the harness installs a callback that proves iff the decrypted payload begins with 0x01, so a link DATA packet whose payload starts 0x01 is proved (receipt DELIVERED) while one starting 0x02 is not (receipt never DELIVERS). The proved packet is the positive control for the declined one.",
)
def test_link_data_prove_app_follows_callback(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        _APP, _ASPECTS, fixed_mtu=_FIXED_MTU,
    )
    server.set_proof_strategy(dest_hash, "app")

    # Callback returns True for a payload beginning with 0x01 -> proved.
    proved = client.send_link_data(
        link_id, b"\x01" + secrets.token_bytes(23), create_receipt=True,
    )
    assert proved["sent"] and proved["receipt_id"], f"no receipt: {proved!r}"
    proved_status = client.packet_receipt_status(proved["receipt_id"], timeout_ms=6000)
    assert proved_status["delivered"] is True, (
        f"PROVE_APP: a payload the proof_requested callback approves (leading "
        f"0x01) must be proved so the receipt reaches DELIVERED, got "
        f"{proved_status!r}"
    )

    # Callback returns False for any other leading byte -> not proved.
    declined = client.send_link_data(
        link_id, b"\x02" + secrets.token_bytes(23), create_receipt=True,
    )
    assert declined["sent"] and declined["receipt_id"], f"no receipt: {declined!r}"
    declined_status = client.packet_receipt_status(declined["receipt_id"], timeout_ms=6000)
    assert declined_status["delivered"] is False, (
        f"PROVE_APP: a payload the proof_requested callback declines (leading "
        f"0x02) must NOT be proved, so the receipt must never reach DELIVERED, "
        f"got {declined_status!r}"
    )


# --- Keepalive byte values (Link.py:848-849/:974/:1149-1153) ----------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "listener_link_status", "send_keepalive_probe",
        "last_keepalive",
    ],
    verifies="Keepalive byte protocol (Link.py:1149-1153/:978-980): a NON-initiator that receives a 0xFF keepalive answers with exactly 0xFE and refreshes last_inbound but NOT last_data (keepalives are not payload data); last_keepalive read-back is 0xFE. The INITIATOR, by contrast, drops its own 0xFF echo entirely (the receive guard at Link.py:974) — no answer and neither last_inbound nor last_data advances.",
)
def test_keepalive_ff_answered_with_fe_initiator_ignores_own_echo(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Make sure the receiver-side inbound link has been accepted before probing.
    pre = server.listener_link_status(dest_hash, timeout_ms=5000)
    assert pre.get("found") and pre.get("link_count", 0) >= 1, (
        f"receiver never accepted the inbound link: {pre!r}"
    )

    # Non-initiator (the listener's inbound link): a 0xFF keepalive is answered
    # with 0xFE, last_inbound advances, last_data does not.
    answer = server.send_keepalive_probe(link_id)
    assert answer["initiator"] is False, (
        f"the listener's inbound link must be the NON-initiator: {answer!r}"
    )
    assert answer["answered"] is True and answer["response"] == "fe", (
        f"a non-initiator must answer a 0xFF keepalive with exactly 0xFE "
        f"(Link.py:1151), got {answer!r}"
    )
    assert answer["last_inbound_advanced"] is True, (
        f"receiving a keepalive must refresh last_inbound (Link.py:978): {answer!r}"
    )
    assert answer["last_data_advanced"] is False, (
        f"a keepalive must NOT bump last_data — it is not payload data "
        f"(Link.py:979-980): {answer!r}"
    )
    assert server.last_keepalive(link_id)["payload"] == "fe", (
        f"the last keepalive byte the non-initiator emitted must be 0xFE: "
        f"{server.last_keepalive(link_id)!r}"
    )

    # Initiator (the outbound link): its own 0xFF echo is dropped by the receive
    # guard (Link.py:974) — no 0xFE answer, and neither timestamp advances.
    echo = client.send_keepalive_probe(link_id)
    assert echo["initiator"] is True, (
        f"the outbound link must be the initiator: {echo!r}"
    )
    assert echo["answered"] is False and echo["response"] is None, (
        f"an initiator must drop its own 0xFF keepalive echo (Link.py:974) — "
        f"no answer, got {echo!r}"
    )
    assert echo["last_data_advanced"] is False, (
        f"an initiator must not bump last_data on its own 0xFF echo: {echo!r}"
    )
    assert echo["last_inbound_advanced"] is False, (
        f"an initiator's dropped 0xFF echo must not refresh last_inbound either "
        f"(the whole receive body is skipped): {echo!r}"
    )


# --- Link MTU / MDU / mode read-back (Link.py:609/:618/:636/:530) -----------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_status", "link_teardown",
    ],
    verifies="Negotiated link parameter read-back (Link.py:609/:618/:636/:530): an ACTIVE link pinned to a fixed MTU of 500 reports mtu==500, a positive mdu that is the update_mdu floor (0 < mdu < mtu and 16-byte aligned so (mdu+1) % 16 == 0), and mode==1 (MODE_AES256_CBC). After teardown the link is no longer ACTIVE so get_mtu()/get_mdu() return None, while get_mode() still returns the mode constant (it is not status-gated).",
)
def test_link_reports_negotiated_mtu_mdu_mode(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        _APP, _ASPECTS, fixed_mtu=_FIXED_MTU,
    )

    snap = client.link_status(link_id)
    assert snap["status_name"] == "ACTIVE", f"link not ACTIVE: {snap!r}"
    assert snap["mtu"] == _FIXED_MTU, (
        f"the fixed link MTU must be the negotiated mtu read back, expected "
        f"{_FIXED_MTU}, got {snap['mtu']!r}: {snap!r}"
    )
    mdu = snap["mdu"]
    assert isinstance(mdu, int) and 0 < mdu < snap["mtu"], (
        f"mdu must be a positive value below mtu (the update_mdu floor), got "
        f"{mdu!r}: {snap!r}"
    )
    # update_mdu computes floor((...)/AES128_BLOCKSIZE)*AES128_BLOCKSIZE - 1, so
    # mdu+1 is a multiple of the 16-byte AES block (Link.py:532).
    assert (mdu + 1) % 16 == 0, (
        f"mdu must be the 16-byte-aligned update_mdu floor (mdu+1 divisible by "
        f"16), got mdu={mdu!r}: {snap!r}"
    )
    assert snap["mode"] == _MODE_AES256_CBC, (
        f"link mode must be MODE_AES256_CBC ({_MODE_AES256_CBC}), got "
        f"{snap['mode']!r}: {snap!r}"
    )

    # After teardown the link leaves ACTIVE: get_mtu()/get_mdu() are status-gated
    # to None, but get_mode() is not — it still returns the negotiated mode.
    client.link_teardown(link_id)
    closed = client.link_status(link_id)
    assert closed["status_name"] == "CLOSED", f"link not CLOSED: {closed!r}"
    assert closed["mtu"] is None and closed["mdu"] is None, (
        f"get_mtu()/get_mdu() must return None once the link is no longer "
        f"ACTIVE (Link.py:613/:622), got mtu={closed['mtu']!r} mdu="
        f"{closed['mdu']!r}: {closed!r}"
    )
    assert closed["mode"] == _MODE_AES256_CBC, (
        f"get_mode() is not status-gated and must still return "
        f"MODE_AES256_CBC after teardown, got {closed['mode']!r}: {closed!r}"
    )


# --- Remote-identity observation (Link.py:683-687/:1010-1028) ---------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "listener_link_status", "link_identify",
    ],
    verifies="Link.get_remote_identity()/remote_identified on the receiver-side link (Link.py:683-687/:1010-1028) is None/False until the initiator independently calls Link.identify; after identify the receiver's inbound link reports remote_identified True with remote_identity_hash byte-equal to the identity the initiator presented. This is the link-object read-back, distinct from the request-handler remote_identity argument.",
)
def test_remote_identity_observable_after_initiator_identifies(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    pre = server.listener_link_status(dest_hash, timeout_ms=5000)
    assert pre.get("found"), f"receiver never accepted the inbound link: {pre!r}"
    assert pre.get("remote_identified") is False and pre.get("remote_identity_hash") is None, (
        f"before the initiator identifies, the receiver-side link must report "
        f"no remote identity (Link.get_remote_identity() is None), got {pre!r}"
    )

    identity_hash = client.link_identify(link_id, secrets.token_bytes(64))

    # identify is asynchronous (a LINKIDENTIFY packet must arrive and validate).
    observed = None
    snap = server.listener_link_status(dest_hash, timeout_ms=0)
    deadline = time.time() + 8.0
    while time.time() < deadline:
        if snap.get("remote_identified"):
            observed = snap
            break
        time.sleep(0.1)
        snap = server.listener_link_status(dest_hash, timeout_ms=0)
    assert observed is not None, (
        f"the receiver-side link never observed the initiator's identity after "
        f"Link.identify: {snap!r}"
    )
    assert observed["remote_identity_hash"] == identity_hash.hex(), (
        f"the receiver's link must surface the EXACT identity the initiator "
        f"presented, expected {identity_hash.hex()!r}, got "
        f"{observed['remote_identity_hash']!r}: {observed!r}"
    )


# --- STALE -> ACTIVE watchdog recovery (Link.py:983-984) --------------------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_set_watchdog", "listener_link_status",
        "send_keepalive_probe",
    ],
    verifies="STALE->ACTIVE watchdog recovery (Link.py:983-984): when the initiator stops sending keepalives the receiver-side link's watchdog drives it ACTIVE->STALE on inbound silence; a single inbound keepalive then transitions it straight back to ACTIVE. The recovery probe captures status_before==STALE(3) and status_after==ACTIVE(2) in one call, and the link answers the 0xFF with 0xFE.",
)
def test_stale_link_recovers_to_active_on_inbound(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    assert server.listener_link_status(dest_hash, timeout_ms=5000).get("found"), (
        "receiver never accepted the inbound link"
    )

    # Silence the initiator's keepalives (and keep its own link from timing out)
    # so the receiver-side link receives no inbound and its watchdog marks it
    # STALE after stale_time. This is the deterministic way to reach STALE
    # without killing the peer; the inbound-silence -> STALE path is the
    # precondition for the recovery the test actually pins.
    client.link_set_watchdog(link_id, keepalive_s=999.0, stale_time_s=999.0)

    # Poll (read-only — must not touch the link's receive path, or last_inbound
    # would refresh and STALE would never be reached) until STALE appears.
    deadline = time.time() + 25.0
    stale = False
    while time.time() < deadline:
        snap = server.listener_link_status(dest_hash, timeout_ms=0)
        name = snap.get("status_name")
        if name == "STALE":
            stale = True
            break
        if name == "CLOSED":
            break
        time.sleep(0.1)
    assert stale, (
        "receiver-side link never reached STALE on inbound silence — the "
        "ACTIVE->STALE watchdog leg is the precondition for recovery"
    )

    # One inbound keepalive on the STALE link must flip it back to ACTIVE.
    recovery = server.send_keepalive_probe(link_id)
    assert recovery["status_before"] == _STATUS_STALE, (
        f"the probe must observe the link STALE before the inbound packet "
        f"(raced past the ~5s STALE window if not): {recovery!r}"
    )
    assert recovery["status_after"] == _STATUS_ACTIVE, (
        f"an inbound packet on a STALE link must transition it back to ACTIVE "
        f"(Link.py:983-984), got status_after={recovery['status_after']!r}: "
        f"{recovery!r}"
    )
    assert recovery["answered"] is True and recovery["response"] == "fe", (
        f"the recovered non-initiator link must still answer the 0xFF keepalive "
        f"with 0xFE: {recovery!r}"
    )


# --- LINKCLOSE link_id forgery teardown rejection (Link.py:710-722) ---------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "send_forged_link_close", "link_status",
    ],
    verifies="LINKCLOSE teardown is gated on the embedded link_id (Link.teardown_packet, Link.py:710-722): injecting a LINKCLOSE whose decrypted payload is a WRONG 16-byte link id over an ACTIVE link does NOT tear it down — torn_down is False, status_before and status_after are both ACTIVE(2), and an independent link_status read still reports ACTIVE. The positive control is a genuine LINKCLOSE carrying the link's REAL link_id, which DOES tear the same link down (torn_down True, status_after CLOSED(4), link_status CLOSED) — so the survival above is a real id check, not a dead teardown path.",
)
def test_forged_link_close_with_wrong_link_id_is_ignored(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # A forged link id distinct from the real one (16-byte collision is
    # astronomically improbable, but assert it so the negative is meaningful).
    forged_id = secrets.token_bytes(len(link_id))
    while forged_id == link_id:
        forged_id = secrets.token_bytes(len(link_id))

    # Negative: a LINKCLOSE carrying the WRONG link_id must be ignored — the
    # established link stays ACTIVE (teardown_packet only acts when the decrypted
    # payload equals the link's own link_id, Link.py:711-714).
    forged = client.send_forged_link_close(link_id, forged_id)
    assert forged["real_link_id"] == link_id.hex() and forged["forged_id"] == forged_id.hex(), (
        f"forged-close did not target the right link / id: {forged!r}"
    )
    assert forged["status_before"] == _STATUS_ACTIVE, (
        f"the link must be ACTIVE before the forged close so the rejection is "
        f"meaningful, got status_before={forged['status_before']!r}: {forged!r}"
    )
    assert forged["torn_down"] is False, (
        f"a LINKCLOSE carrying a link_id that does not match the link's own id "
        f"must NOT tear the link down (Link.py:711-714), got {forged!r}"
    )
    assert forged["status_after"] == _STATUS_ACTIVE and forged["status_name_after"] == "ACTIVE", (
        f"after a forged (wrong-id) LINKCLOSE the link must remain ACTIVE, got "
        f"status_after={forged['status_after']!r}: {forged!r}"
    )
    # Independent confirmation via a second, separate read path: the live link
    # snapshot must still report ACTIVE (the forged close left it untouched).
    snap = client.link_status(link_id)
    assert snap["status_name"] == "ACTIVE", (
        f"an independent link_status read must confirm the link survived the "
        f"forged close, got {snap!r}"
    )

    # Positive control: a genuine LINKCLOSE carrying the link's REAL link_id
    # DOES tear the same link down — proving the survival above is a real id
    # check on a live teardown path, not a no-op detector.
    genuine = client.send_forged_link_close(link_id, link_id)
    assert genuine["status_before"] == _STATUS_ACTIVE, (
        f"the link must still have been ACTIVE going into the genuine close "
        f"(the forged close did not secretly damage it), got {genuine!r}"
    )
    assert genuine["torn_down"] is True, (
        f"a LINKCLOSE carrying the correct link_id MUST tear the link down "
        f"(Link.py:711-714), got {genuine!r}"
    )
    assert genuine["status_after"] == _STATUS_CLOSED and genuine["status_name_after"] == "CLOSED", (
        f"after a genuine LINKCLOSE the link must be CLOSED, got "
        f"status_after={genuine['status_after']!r}: {genuine!r}"
    )
    closed = client.link_status(link_id)
    assert closed["status_name"] == "CLOSED", (
        f"an independent link_status read must confirm the genuine close tore "
        f"the link down, got {closed!r}"
    )


# --- Link.identify on a PENDING link is a no-op (Link.py:459-475/:468) -------

@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_identify", "listener_link_status",
        "link_identify_pending",
    ],
    verifies="Link.identify is guarded by an ACTIVE-only check (Link.py:459-475/:468): calling identify on a PENDING (pre-ACTIVE) initiator link is a silent no-op — it does not raise (crashed False), emits no LINKIDENTIFY packet (identify_packet_sent False), leaves the link PENDING(0), and the link is an initiator. The positive control is Link.identify on the established ACTIVE link, which DOES propagate — the receiver-side inbound link reports remote_identified True with remote_identity_hash byte-equal to the identity presented — so the PENDING no-op is a real status gate, not a broken identify path.",
)
def test_link_identify_on_pending_link_is_noop(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Positive control: identify on the established ACTIVE link propagates to the
    # receiver-side link (the same Link.identify, taken with status==ACTIVE).
    active_identity = client.link_identify(link_id, secrets.token_bytes(64))
    observed = None
    deadline = time.time() + 8.0
    while time.time() < deadline:
        snap = server.listener_link_status(dest_hash, timeout_ms=0)
        if snap.get("remote_identified"):
            observed = snap
            break
        time.sleep(0.1)
    assert observed is not None, (
        "positive control failed: Link.identify on the ACTIVE link never "
        "propagated to the receiver — cannot conclude the PENDING case is a gate"
    )
    assert observed["remote_identity_hash"] == active_identity.hex(), (
        f"the receiver must surface the identity the ACTIVE-link initiator "
        f"presented, expected {active_identity.hex()!r}, got {observed!r}"
    )

    # Negative: the harness builds a fresh initiator link forced to PENDING and
    # calls identify on it. The ACTIVE-only guard (Link.py:468) must make this a
    # silent no-op: no exception, no LINKIDENTIFY packet, link still PENDING.
    pending = client.link_identify_pending(
        destination_hash=dest_hash,
        app_name=_APP,
        aspects=list(_ASPECTS),
        private_key=secrets.token_bytes(64),
    )
    assert pending["initiator"] is True, (
        f"the probed link must be an initiator link (identify only ever acts on "
        f"initiator links), got {pending!r}"
    )
    assert pending["crashed"] is False, (
        f"Link.identify on a PENDING link must not raise — it is guarded by the "
        f"ACTIVE-only check (Link.py:468), got {pending!r}"
    )
    assert pending["identify_packet_sent"] is False, (
        f"Link.identify on a PENDING link must emit NO LINKIDENTIFY packet "
        f"(the guard returns before send, Link.py:468), got {pending!r}"
    )
    assert pending["status"] == _STATUS_PENDING and pending["status_name"] == "PENDING", (
        f"the link must remain PENDING after the no-op identify, got "
        f"status={pending['status']!r}: {pending!r}"
    )

