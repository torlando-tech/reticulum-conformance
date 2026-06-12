"""
Behavioral conformance tests for Transport announce/path-response SCHEDULING
decision values and path-timestamp refresh.

Closes V2 gaps that previously had the state-machine pinned but never asserted
the scheduled VALUES (all readable via read_announce_table / read_path_table
WITHOUT any wall-clock waiting — the wall-clock schedule itself is out of scope
per the LIMITS timing ceiling, but the decision values are not):

  * announce-retransmit-scheduling — the initial retransmit_timeout window for a
    forwarded announce (now .. now+PATHFINDER_RW, retries=0), the local-client
    "retransmit now, retries preset to PATHFINDER_R" rule, and the
    PATHFINDER_G+PATHFINDER_RW retry window applied when a retransmit fires
    (Transport.py:1871/1889-1893/588).
  * path-response-grace-delays — the path-request answer's scheduled
    retransmit_timeout: now+PATH_REQUEST_GRACE (FULL), +PATH_REQUEST_RG extra on
    a roaming-mode arrival, and now (immediate) for a local-client requestor
    (Transport.py:2967-2987).
  * path-timestamp-refresh-on-use — forwarding traffic over a held path advances
    the path_table entry timestamp (Transport.py:1634).

Every test drives the REAL RNS.Transport.inbound / jobs path through the
behavioral bridge and asserts on observables; no transport logic is
reimplemented in the harness. Each value is anchored on a SPEC LITERAL read from
the RNS 1.3.1 source (positive AND negative / discriminating control).
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    CONTEXT_PATH_RESPONSE,
    HEADER_1_MIN_SIZE,
    HEADER_2,
    PATH_REQUEST_DESTINATION_NAME,
    TRUNCATED_HASH_BYTES,
    _plain_destination_hash,
    build_announce_from_destination,
    build_data_packet,
    build_path_request,
    parse_packet_header,
)


__category_title__ = "Transport Announce Scheduling"
__category_order__ = 23


# RNS spec literals, verified against the installed RNS 1.3.1 source:
_PATHFINDER_R = 1      # Transport.PATHFINDER_R   (Transport.py:68)
_PATHFINDER_G = 5      # Transport.PATHFINDER_G   (Transport.py:69)
_PATHFINDER_RW = 0.5   # Transport.PATHFINDER_RW  (Transport.py:70)
_PATH_REQUEST_GRACE = 0.4   # Transport.PATH_REQUEST_GRACE (Transport.py:81)
_PATH_REQUEST_RG = 1.5      # Transport.PATH_REQUEST_RG    (Transport.py:82)

_TOL = 0.01  # float tolerance for an exact same-`now`-derived delta


# ---------------------------------------------------------------------------
# announce-retransmit-scheduling: the initial retransmit_timeout differs for a
# forwarded (transport) announce vs a local-client announce.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_announce_table"],
    verifies=(
        "When Transport admits an announce into the retransmit table "
        "(Transport.py:1865-1906): a FORWARDED announce (received on an ordinary "
        "interface) is scheduled with retries=0 and an initial retransmit_timeout "
        "in the half-open window [timestamp, timestamp+PATHFINDER_RW] "
        "(=now+rand()*0.5), whereas a LOCAL-CLIENT announce is announced "
        "immediately exactly once: retransmit_timeout==timestamp (delay 0) and "
        "retries preset to PATHFINDER_R=1. The two cases are mutually "
        "discriminating — an impl that schedules the local-client announce with "
        "the random window (or the forwarded one immediately with retries=1) "
        "fails."
    ),
)
def test_forwarded_vs_local_client_retransmit_schedule(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        lc_iface = inst.attach_mock_interface("lc", mode="FULL", local_client=True)

        # Forwarded announce: retries=0, delay in [0, PATHFINDER_RW].
        fwd_raw, fwd_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=secrets.token_bytes(64),
            app_name="schedapp", aspects=["fwd"], emission_ts=1_000_000_000,
            wire_hops=0,
        )
        inst.inject(iface, fwd_raw)
        fwd = inst.read_announce_table(fwd_dest)
        assert fwd["found"], "forwarded announce not scheduled for retransmit"
        fwd_delay = fwd["retransmit_timeout"] - fwd["timestamp"]
        assert fwd["retries"] == 0, (
            f"forwarded announce must start at retries=0, got {fwd['retries']}"
        )
        assert -_TOL <= fwd_delay <= _PATHFINDER_RW + _TOL, (
            f"forwarded announce retransmit window {fwd_delay:.4f}s is outside "
            f"[0, PATHFINDER_RW={_PATHFINDER_RW}]"
        )

        # Local-client announce: retransmit_timeout==timestamp, retries==1.
        lc_raw, lc_dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=secrets.token_bytes(64),
            app_name="schedapp", aspects=["lc"], emission_ts=1_000_000_001,
            wire_hops=0,
        )
        inst.inject(lc_iface, lc_raw)
        lc = inst.read_announce_table(lc_dest)
        assert lc["found"], "local-client announce not scheduled"
        lc_delay = lc["retransmit_timeout"] - lc["timestamp"]
        assert abs(lc_delay) <= _TOL, (
            f"local-client announce must retransmit immediately "
            f"(retransmit_timeout==timestamp), got delay {lc_delay:.4f}s"
        )
        assert lc["retries"] == _PATHFINDER_R, (
            f"local-client announce retries must be preset to PATHFINDER_R="
            f"{_PATHFINDER_R}, got {lc['retries']}"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# announce-retransmit-scheduling: when a retransmit FIRES, the next
# retransmit_timeout is rescheduled to now + PATHFINDER_G + PATHFINDER_RW.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "read_announce_table", "set_announce_timestamp", "force_cull"],
    verifies=(
        "When the announce-retransmit job fires for a due entry "
        "(Transport.py:587-589), it increments retries by one and reschedules the "
        "next retransmit_timeout to now + PATHFINDER_G + PATHFINDER_RW (=5.5s). "
        "Driven deterministically by setting the entry due (retransmit_timeout=0) "
        "and running one jobs() pass; the rescheduled timeout is bounded by the "
        "wall clock captured immediately around the jobs() call, and retries goes "
        "0 -> 1."
    ),
)
def test_retransmit_retry_window_after_fire(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=secrets.token_bytes(64),
            app_name="schedapp", aspects=["retry"], emission_ts=1_000_000_010,
            wire_hops=2,
        )
        inst.inject(iface, raw)
        before = inst.read_announce_table(dest)
        assert before["found"] and before["retries"] == 0

        # Make the entry due, then fire exactly one retransmit pass.
        inst.set_announce_timestamp(dest, retransmit_timeout=0)
        t0 = time.time()
        inst.force_cull()
        t1 = time.time()

        after = inst.read_announce_table(dest)
        assert after["found"], "entry was completed/evicted on the first retransmit"
        assert after["retries"] == 1, (
            f"retransmit must increment retries 0->1, got {after['retries']}"
        )
        window = _PATHFINDER_G + _PATHFINDER_RW  # 5.5
        assert t0 + window - _TOL <= after["retransmit_timeout"] <= t1 + window + _TOL, (
            f"rescheduled retransmit_timeout {after['retransmit_timeout']:.3f} is "
            f"not now+PATHFINDER_G+PATHFINDER_RW (~{window}s) past the jobs() call "
            f"window [{t0:.3f}, {t1:.3f}]"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# path-response-grace-delays: a path-request answer is scheduled with
# now+PATH_REQUEST_GRACE, +PATH_REQUEST_RG extra on a roaming arrival, and now
# (immediate) for a local-client requestor.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "packet_build", "packet_unpack", "name_hash", "truncated_hash",
              "read_announce_table", "read_path_table"],
    verifies=(
        "The grace delay applied to a path-request answer (Transport.py:2973-2987) "
        "depends on the answering context: a FULL-mode arrival schedules the "
        "cached-announce rebroadcast at now+PATH_REQUEST_GRACE (0.4s); a "
        "ROAMING-mode arrival adds PATH_REQUEST_RG (total 1.9s) to let better-"
        "connected peers answer first; and a LOCAL-CLIENT requestor is answered "
        "immediately (delay 0). All three are read as retransmit_timeout-timestamp "
        "on the scheduled announce_table entry and anchored on the RNS spec "
        "literals; the three values are mutually discriminating."
    ),
)
def test_path_request_answer_grace_delays(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        # Each path is learned on its OWN dedicated FULL interface so the
        # per-interface announce ingress-burst control (Interface.should_ingress_
        # limit, which holds the 3rd+ rapid announce on a single interface) never
        # interferes; the path's received-on interface is always FULL, so the
        # roaming same-interface suppression (Transport.py:2949) never fires.
        full = inst.attach_mock_interface("full", mode="FULL")
        roam = inst.attach_mock_interface("roam", mode="ROAMING")
        lc = inst.attach_mock_interface("lc", mode="FULL", local_client=True)

        def seed_path(aspect, ts):
            # Seed via PATH_RESPONSE so the seeding announce does not itself
            # schedule a retransmit that would pollute the announce_table read.
            learn = inst.attach_mock_interface("learn-" + aspect, mode="FULL")
            raw, dest, _ = build_announce_from_destination(
                behavioral.bridge, identity_private_key=secrets.token_bytes(64),
                app_name="grace", aspects=[aspect], emission_ts=ts, wire_hops=0,
                context=CONTEXT_PATH_RESPONSE,
            )
            inst.inject(learn, raw)
            assert inst.read_path_table(dest)["found"], "seed path not created"
            assert inst.read_announce_table(dest)["found"] is False, (
                "seeding unexpectedly scheduled a retransmit"
            )
            return dest

        def answer_delay(dest, arrival_iface):
            pr = build_path_request(
                behavioral.bridge, dest,
                transport_id=secrets.token_bytes(TRUNCATED_HASH_BYTES),
                tag=secrets.token_bytes(TRUNCATED_HASH_BYTES),
            )
            inst.inject(arrival_iface, pr)
            ans = inst.read_announce_table(dest)
            assert ans["found"] and ans["block_rebroadcasts"] is True, (
                f"path request was not answered: {ans}"
            )
            return ans["retransmit_timeout"] - ans["timestamp"]

        # FULL arrival -> PATH_REQUEST_GRACE.
        d_full = seed_path("full", 1_000_000_020)
        full_delay = answer_delay(d_full, full)
        assert abs(full_delay - _PATH_REQUEST_GRACE) <= _TOL, (
            f"FULL path-request answer delay {full_delay:.4f}s != "
            f"PATH_REQUEST_GRACE={_PATH_REQUEST_GRACE}"
        )

        # ROAMING arrival -> PATH_REQUEST_GRACE + PATH_REQUEST_RG.
        d_roam = seed_path("roam", 1_000_000_021)
        roam_delay = answer_delay(d_roam, roam)
        assert abs(roam_delay - (_PATH_REQUEST_GRACE + _PATH_REQUEST_RG)) <= _TOL, (
            f"ROAMING path-request answer delay {roam_delay:.4f}s != "
            f"PATH_REQUEST_GRACE+PATH_REQUEST_RG="
            f"{_PATH_REQUEST_GRACE + _PATH_REQUEST_RG}"
        )

        # LOCAL-CLIENT requestor -> immediate.
        d_lc = seed_path("lc", 1_000_000_022)
        lc_delay = answer_delay(d_lc, lc)
        assert abs(lc_delay) <= _TOL, (
            f"local-client path-request answer must be immediate (delay 0), got "
            f"{lc_delay:.4f}s"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# path-timestamp-refresh-on-use: forwarding traffic over a held path advances
# the path_table entry timestamp.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "packet_build", "packet_unpack", "read_path_table",
              "set_path_timestamp"],
    verifies=(
        "When a transport node forwards a packet for which it is the designated "
        "next hop over a known path, it refreshes that path_table entry's "
        "timestamp to the current time (Transport.py:1634). Anchored on the "
        "system wall clock: after rewinding the entry's timestamp 1000s into the "
        "past, forwarding a HEADER_2 transport packet (transport_id == this node) "
        "addressed to the held destination advances the timestamp back to ~now. "
        "A discriminating negative — the same packet but with a FOREIGN "
        "transport_id (this node is NOT the next hop) — does not forward and "
        "leaves the rewound timestamp untouched, proving the refresh is the "
        "forward-over-path action rather than any inbound packet."
    ),
)
def test_path_timestamp_refreshed_on_forward(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        learn = inst.attach_mock_interface("learn", mode="FULL")
        ingress = inst.attach_mock_interface("ingress", mode="FULL")

        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=secrets.token_bytes(64),
            app_name="refresh", aspects=["d"], emission_ts=1_000_000_030,
            wire_hops=2,
        )
        inst.inject(learn, raw)
        pt = inst.read_path_table(dest)
        assert pt["found"], "path not learned"

        # Rewind the held entry's timestamp far into the past.
        rewound = pt["timestamp"] - 1000.0
        inst.set_path_timestamp(dest, rewound)
        assert abs(inst.read_path_table(dest)["timestamp"] - rewound) <= _TOL

        # Forward a transport packet for which WE are the next hop.
        fwd_pkt = build_data_packet(
            behavioral.bridge, dest, header_type=HEADER_2,
            transport_id=inst.identity_hash, destination_type="plain",
            payload=b"forward-me",
        )
        t0 = time.time()
        inst.inject(ingress, fwd_pkt)
        refreshed = inst.read_path_table(dest)["timestamp"]
        assert refreshed >= t0 - _TOL, (
            f"path timestamp {refreshed:.3f} was not advanced to ~now "
            f"({t0:.3f}) after forwarding over the held path"
        )
        assert refreshed > rewound + 500, (
            "path timestamp did not advance away from the rewound value on forward"
        )

        # Negative: rewind again and inject a packet whose transport_id is NOT
        # ours -> we are not the next hop -> no forward -> no refresh.
        rewound2 = refreshed - 1000.0
        inst.set_path_timestamp(dest, rewound2)
        foreign_pkt = build_data_packet(
            behavioral.bridge, dest, header_type=HEADER_2,
            transport_id=secrets.token_bytes(TRUNCATED_HASH_BYTES),
            destination_type="plain", payload=b"not-for-us",
        )
        inst.inject(ingress, foreign_pkt)
        unchanged = inst.read_path_table(dest)["timestamp"]
        assert abs(unchanged - rewound2) <= _TOL, (
            f"path timestamp changed ({unchanged:.3f} vs rewound {rewound2:.3f}) "
            f"for a packet this node is not the next hop for — the refresh is not "
            f"gated on the forward-over-path action"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# path-request-parse-and-tag-dedup (parse branches) + path-response-local-
# destination (answer context). The path_request_handler only answers when the
# payload carries a tag: a 16-byte (dest-only) payload leaves tag_bytes None and
# is ignored; a <16-byte payload fails the outer length guard and is ignored
# (Transport.py:2864-2895). When it DOES answer, the emitted cached-announce
# rebroadcast carries the PATH_RESPONSE context byte (0x0B).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "announce_build", "inject",
              "packet_build", "packet_unpack", "name_hash", "truncated_hash",
              "read_announce_table", "read_path_table", "drain_tx",
              "set_announce_timestamp", "force_cull"],
    verifies=(
        "Transport.path_request_handler answers a path request ONLY when its "
        "payload carries a tag, and the answer is a PATH_RESPONSE "
        "(Transport.py:2864-2895): a tagless 16-byte (destination-hash-only) "
        "request leaves tag_bytes None and schedules no answer; a sub-16-byte "
        "request fails the outer length guard and schedules no answer; a tagged "
        "request IS answered (cached-announce rebroadcast scheduled with "
        "block_rebroadcasts), and when that answer fires it is emitted with the "
        "PATH_RESPONSE context byte (0x0B). An impl that answers tagless/short "
        "requests, or emits the answer with a plain ANNOUNCE context, diverges"
    ),
)
def test_path_request_parse_branches_and_response_context(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface_a = inst.attach_mock_interface("a", mode="FULL")
        learn = inst.attach_mock_interface("learn", mode="FULL")

        # Seed a known path to D via PATH_RESPONSE (no forward retransmit, so the
        # announce_table stays empty until a path request schedules an answer).
        seed, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=secrets.token_bytes(64),
            app_name="prparse", aspects=["x"], emission_ts=1_000_000_030,
            wire_hops=0, context=CONTEXT_PATH_RESPONSE,
        )
        inst.inject(learn, seed)
        assert inst.read_path_table(dest)["found"], "seed path not created"
        assert inst.read_announce_table(dest)["found"] is False

        # Tagless (16-byte, destination-hash only) -> tag_bytes None -> no answer.
        tagless = build_path_request(behavioral.bridge, dest,
                                     transport_id=None, tag=None)
        inst.inject(iface_a, tagless)
        assert inst.read_announce_table(dest)["found"] is False, (
            "a tagless path request was answered — RNS only answers tagged "
            "requests (Transport.py:2884-2895)"
        )

        # Sub-16-byte payload -> outer length guard fails -> no answer.
        pr_ctrl = _plain_destination_hash(
            behavioral.bridge, PATH_REQUEST_DESTINATION_NAME
        )
        short = build_data_packet(
            behavioral.bridge, pr_ctrl, destination_type="plain",
            payload=b"\x00" * 8, hops=0,
        )
        inst.inject(iface_a, short)
        assert inst.read_announce_table(dest)["found"] is False, (
            "a sub-16-byte path request was answered — the outer length guard "
            "(len(data) >= 16) must drop it"
        )

        # Positive control: a TAGGED request is answered, and the emitted answer
        # carries the PATH_RESPONSE context byte.
        inst.drain_tx(iface_a)
        tagged = build_path_request(
            behavioral.bridge, dest,
            transport_id=secrets.token_bytes(TRUNCATED_HASH_BYTES),
            tag=secrets.token_bytes(TRUNCATED_HASH_BYTES),
        )
        inst.inject(iface_a, tagged)
        ans = inst.read_announce_table(dest)
        assert ans["found"] and ans["block_rebroadcasts"] is True, (
            f"a tagged path request was not answered (positive control): {ans}"
        )

        # Fire the scheduled answer and capture the emitted packet's context.
        guard = 0
        while inst.read_announce_table(dest)["found"]:
            guard += 1
            assert guard <= 6, "could not drain the scheduled answer"
            inst.set_announce_timestamp(dest, retransmit_timeout=0)
            inst.force_cull()
        emitted = inst.drain_tx(iface_a)
        contexts = [
            parse_packet_header(p)["context"]
            for p in emitted if len(p) >= HEADER_1_MIN_SIZE
        ]
        assert CONTEXT_PATH_RESPONSE in contexts, (
            f"the path-request answer was not emitted with the PATH_RESPONSE "
            f"context byte (0x0B); got contexts {[hex(c) for c in contexts]}"
        )
    finally:
        behavioral.cleanup()
