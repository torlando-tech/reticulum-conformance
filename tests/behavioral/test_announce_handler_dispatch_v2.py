"""
Behavioral conformance tests for Transport announce-handler DISPATCH.

Closes the V2 gap `announce-handler-dispatch` (core, previously uncovered): RNS
Transport.inbound dispatches every processed announce to the externally
registered announce handlers (Transport.py:2034-2087), and the dispatch rules
were not exercised anywhere in the suite.

The rules pinned here (each positive AND negative), read straight off the RNS
1.3.1 source:

  * `aspect_filter == None`  -> the callback fires for EVERY processed announce
    (Transport.py:2041-2044).
  * `aspect_filter` set      -> the callback fires ONLY when
    Destination.hash_from_name_and_identity(aspect_filter, announced_identity)
    equals the announce's destination_hash (Transport.py:2045-2047).
  * PATH_RESPONSE-context announces are delivered ONLY to handlers whose
    `receive_path_responses == True`; a handler without that attribute (the
    default) is skipped for path responses but still receives live announces
    (Transport.py:2049-2053).
  * the callback receives (destination_hash, announced_identity, app_data) for a
    3-parameter handler, and additionally announce_packet_hash for a
    4-parameter handler (Transport.py:2055-2069).
  * register_announce_handler only registers a handler that HAS an
    `aspect_filter` attribute (Transport.py:2476-2477).
  * a handler that raises is isolated: other handlers still fire
    (Transport.py:2083-2086).

The harness registers REAL handler objects via RNS.Transport.register_announce_
handler; the handler only records the arguments RNS dispatches to it. All
matching / gating / threaded dispatch is performed by real RNS — no transport
logic is reimplemented in the harness. Each assertion is anchored on an
independent value: the destination hash the test itself built, the announcer
identity hash derived a SECOND way (identity_from_private_key), the app_data the
test set, or the announce_table packet_hash observed through a different
RNS observable.
"""

import secrets
import time

from conformance import conformance_case
from tests.behavioral.packet_builders import (
    CONTEXT_PATH_RESPONSE,
    build_announce_from_destination,
)


__category_title__ = "Transport Announce Dispatch"
__category_order__ = 22


def _poll_calls(inst, handler_id, want=1, tries=40, delay=0.05):
    """Poll a recording handler until it has at least `want` calls or the
    budget is exhausted. The dispatch runs on a daemon thread spawned by
    Transport.inbound (Transport.py:2061), so a brief poll is required."""
    calls = []
    for _ in range(tries):
        calls = inst.read_announce_handler_calls(handler_id)["calls"]
        if len(calls) >= want:
            break
        time.sleep(delay)
    return calls


# ---------------------------------------------------------------------------
# aspect_filter==None fires for all; the callback args are exactly
# (destination_hash, announced_identity, app_data).
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "register_announce_handler",
              "read_announce_handler_calls", "announce_build", "inject",
              "identity_from_private_key"],
    verifies=(
        "An announce handler registered with aspect_filter=None receives EVERY "
        "processed announce (Transport.py:2041-2044), and its callback is invoked "
        "with the three documented arguments: destination_hash equal to the "
        "announced destination, announced_identity whose hash equals the "
        "announcer identity hash (derived independently from the same private key "
        "via identity_from_private_key), and app_data byte-equal to the app_data "
        "the announce carried. A control announce for a SECOND destination is "
        "also delivered, proving the None filter is not a one-shot."
    ),
)
def test_aspect_filter_none_matches_all(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        h_all = inst.register_announce_handler(aspect_filter=None, num_params=3)
        assert h_all["registered"] is True

        priv = secrets.token_bytes(64)
        ann_id_hash = behavioral.bridge.execute(
            "identity_from_private_key", private_key=priv.hex()
        )["hash"]
        app_data = b"\x01hello-world"
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="dispatchapp", aspects=["one"], app_data=app_data,
            emission_ts=1_000_000_000, wire_hops=0,
        )
        inst.inject(iface, raw)

        calls = _poll_calls(inst, h_all["handler_id"], want=1)
        assert len(calls) == 1, (
            f"aspect_filter=None handler did not receive the announce: {calls}"
        )
        c = calls[0]
        assert c["destination_hash"] == dest.hex(), (
            f"callback destination_hash {c['destination_hash']} != announced "
            f"destination {dest.hex()}"
        )
        assert c["announced_identity_hash"] == ann_id_hash, (
            f"callback announced_identity hash {c['announced_identity_hash']} != "
            f"independently-derived announcer identity hash {ann_id_hash}"
        )
        assert c["app_data"] == app_data.hex(), (
            f"callback app_data {c['app_data']} != announced app_data "
            f"{app_data.hex()}"
        )

        # Control: a second, different destination is ALSO delivered.
        priv2 = secrets.token_bytes(64)
        raw2, dest2, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv2,
            app_name="dispatchapp", aspects=["two"], app_data=b"\x02",
            emission_ts=1_000_000_001, wire_hops=0,
        )
        assert dest2 != dest
        inst.inject(iface, raw2)
        calls = _poll_calls(inst, h_all["handler_id"], want=2)
        seen = {c["destination_hash"] for c in calls}
        assert dest2.hex() in seen, (
            "aspect_filter=None handler only fired once — it is not matching "
            "every announce"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# aspect_filter matching: only the handler whose filter hashes (with the
# announced identity) to the destination fires.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "register_announce_handler",
              "read_announce_handler_calls", "announce_build", "inject",
              "hash_from_name_and_identity", "identity_from_private_key"],
    verifies=(
        "When an announce handler sets an aspect_filter, RNS fires its callback "
        "ONLY if Destination.hash_from_name_and_identity(aspect_filter, "
        "announced_identity) == the announce destination_hash "
        "(Transport.py:2045-2047). For an announce on 'dispatchapp.match', the "
        "handler filtered on 'dispatchapp.match' fires while a handler filtered "
        "on 'dispatchapp.other' does NOT — and an aspect_filter=None control "
        "handler fires for the same announce, proving the non-match is the filter "
        "at work rather than the announce never being processed. The matching "
        "filter's expected hash is cross-checked against the announce destination "
        "via the independent hash_from_name_and_identity oracle."
    ),
)
def test_aspect_filter_match_and_mismatch(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        h_match = inst.register_announce_handler(
            aspect_filter="dispatchapp.match", num_params=3)
        h_other = inst.register_announce_handler(
            aspect_filter="dispatchapp.other", num_params=3)
        h_all = inst.register_announce_handler(aspect_filter=None, num_params=3)
        assert h_match["registered"] and h_other["registered"] and h_all["registered"]

        priv = secrets.token_bytes(64)
        ann_id_hash = behavioral.bridge.execute(
            "identity_from_private_key", private_key=priv.hex()
        )["hash"]
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="dispatchapp", aspects=["match"], app_data=b"m",
            emission_ts=1_000_000_010, wire_hops=0,
        )
        # Independent oracle: the matching filter's name + this identity must
        # hash to exactly the announce destination (else the positive below is
        # vacuous), and the mismatching filter must NOT.
        expect_match = behavioral.bridge.execute(
            "hash_from_name_and_identity",
            full_name="dispatchapp.match", identity_hash=ann_id_hash,
        )["destination_hash"]
        expect_other = behavioral.bridge.execute(
            "hash_from_name_and_identity",
            full_name="dispatchapp.other", identity_hash=ann_id_hash,
        )["destination_hash"]
        assert expect_match == dest.hex(), (
            "test setup: matching aspect filter does not hash to the announce "
            "destination"
        )
        assert expect_other != dest.hex(), (
            "test setup: mismatching aspect filter unexpectedly hashes to the "
            "announce destination"
        )

        inst.inject(iface, raw)

        # Control fires first -> announce was processed and dispatched.
        all_calls = _poll_calls(inst, h_all["handler_id"], want=1)
        assert len(all_calls) == 1, "control (None-filter) handler never fired"

        match_calls = _poll_calls(inst, h_match["handler_id"], want=1)
        assert len(match_calls) == 1 and match_calls[0]["destination_hash"] == dest.hex(), (
            f"the matching-aspect handler did not fire: {match_calls}"
        )
        other_calls = inst.read_announce_handler_calls(h_other["handler_id"])["calls"]
        assert other_calls == [], (
            f"the mismatching-aspect handler fired for an announce its filter "
            f"does not match: {other_calls}"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# PATH_RESPONSE delivery gate: only receive_path_responses==True handlers see
# path-response announces.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "register_announce_handler",
              "read_announce_handler_calls", "announce_build", "inject"],
    verifies=(
        "A PATH_RESPONSE-context announce is dispatched ONLY to handlers whose "
        "receive_path_responses attribute is True; a handler without it (the "
        "default) is skipped for path responses (Transport.py:2049-2053). Both "
        "handlers (aspect_filter=None) receive an ordinary live announce, but "
        "only the receive_path_responses=True handler additionally receives a "
        "PATH_RESPONSE-context announce — so the default handler ends with one "
        "call and the path-response handler with two."
    ),
)
def test_path_response_delivery_gate(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        h_def = inst.register_announce_handler(aspect_filter=None, num_params=3)
        h_pr = inst.register_announce_handler(
            aspect_filter=None, num_params=3, receive_path_responses=True)
        assert h_def["registered"] and h_pr["registered"]

        # 1) A live (non-PATH_RESPONSE) announce -> BOTH handlers fire.
        priv_live = secrets.token_bytes(64)
        raw_live, dest_live, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_live,
            app_name="prapp", aspects=["live"], app_data=b"L",
            emission_ts=1_000_000_020, wire_hops=0,
        )
        inst.inject(iface, raw_live)
        assert len(_poll_calls(inst, h_def["handler_id"], want=1)) == 1, (
            "default handler missed a live announce"
        )
        assert len(_poll_calls(inst, h_pr["handler_id"], want=1)) == 1, (
            "path-response handler missed a live announce"
        )

        # 2) A PATH_RESPONSE-context announce -> ONLY the receive_path_responses
        #    handler fires.
        priv_pr = secrets.token_bytes(64)
        raw_pr, dest_pr, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv_pr,
            app_name="prapp", aspects=["resp"], app_data=b"R",
            emission_ts=1_000_000_021, wire_hops=0,
            context=CONTEXT_PATH_RESPONSE,
        )
        inst.inject(iface, raw_pr)
        pr_calls = _poll_calls(inst, h_pr["handler_id"], want=2)
        assert len(pr_calls) == 2 and any(
            c["destination_hash"] == dest_pr.hex() for c in pr_calls
        ), (
            f"receive_path_responses=True handler did not receive the path "
            f"response: {pr_calls}"
        )
        # Give the (suppressed) default handler the same wall-clock budget the
        # path-response handler needed, then assert it STILL has only its one
        # live-announce call.
        time.sleep(0.3)
        def_calls = inst.read_announce_handler_calls(h_def["handler_id"])["calls"]
        assert len(def_calls) == 1, (
            f"a handler without receive_path_responses received a PATH_RESPONSE "
            f"announce: {def_calls}"
        )
        assert def_calls[0]["destination_hash"] == dest_live.hex()
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# Callback arity: the 4-parameter handler additionally receives
# announce_packet_hash; the 3-parameter handler does not.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "register_announce_handler",
              "read_announce_handler_calls", "announce_build", "inject",
              "read_announce_table"],
    verifies=(
        "RNS selects the dispatch arm by the announce handler callback's "
        "parameter count (Transport.py:2055-2069): a 4-parameter handler also "
        "receives announce_packet_hash (the 32-byte packet hash), while a "
        "3-parameter handler does not. The 4-parameter handler's received "
        "announce_packet_hash is cross-checked against the same announce's "
        "packet_hash observed through the announce_table (an independent RNS "
        "observable), and the 3-parameter handler's recorded call carries no "
        "announce_packet_hash field at all."
    ),
)
def test_callback_arity_packet_hash(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")
        h3 = inst.register_announce_handler(aspect_filter=None, num_params=3)
        h4 = inst.register_announce_handler(aspect_filter=None, num_params=4)
        assert h3["registered"] and h4["registered"]

        priv = secrets.token_bytes(64)
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="arityapp", aspects=["x"], app_data=b"a",
            emission_ts=1_000_000_030, wire_hops=0,
        )
        inst.inject(iface, raw)

        # With transport enabled the announce also enters the announce_table,
        # whose stored packet IS the announce packet — an independent source of
        # the same packet hash the 4-param dispatch arm delivers.
        table_hash = None
        for _ in range(40):
            entry = inst.read_announce_table(dest)
            if entry.get("found") and entry.get("packet_hash"):
                table_hash = entry["packet_hash"]
                break
            time.sleep(0.05)
        assert table_hash is not None, "announce never entered the announce_table"

        c4 = _poll_calls(inst, h4["handler_id"], want=1)
        c3 = _poll_calls(inst, h3["handler_id"], want=1)
        assert len(c4) == 1 and len(c3) == 1

        assert "announce_packet_hash" in c4[0], (
            "4-parameter announce handler was not given announce_packet_hash"
        )
        assert c4[0]["announce_packet_hash"] == table_hash, (
            f"4-param announce_packet_hash {c4[0]['announce_packet_hash']} != "
            f"announce_table packet_hash {table_hash}"
        )
        assert len(bytes.fromhex(c4[0]["announce_packet_hash"])) == 32, (
            "announce_packet_hash is not a 32-byte packet hash"
        )
        assert "announce_packet_hash" not in c3[0], (
            "3-parameter announce handler was incorrectly given "
            "announce_packet_hash — the arity dispatch arms are conflated"
        )
    finally:
        behavioral.cleanup()


# ---------------------------------------------------------------------------
# Registration requires an aspect_filter attribute; per-handler exceptions are
# isolated.
# ---------------------------------------------------------------------------
@conformance_case(
    commands=["start", "attach_mock_interface", "register_announce_handler",
              "read_announce_handler_calls", "announce_build", "inject"],
    verifies=(
        "register_announce_handler only registers a handler that HAS an "
        "aspect_filter attribute (Transport.py:2476-2477): a handler lacking it "
        "is not added (registered=False) and never fires. And the dispatch loop "
        "isolates per-handler exceptions (Transport.py:2083-2086): a handler "
        "whose callback raises does not prevent a subsequently registered "
        "well-behaved handler from receiving the same announce."
    ),
)
def test_registration_guard_and_exception_isolation(behavioral):
    inst = behavioral.start(enable_transport=True)
    try:
        iface = inst.attach_mock_interface("a", mode="FULL")

        h_omit = inst.register_announce_handler(omit_aspect_filter=True)
        assert h_omit["registered"] is False, (
            "a handler with no aspect_filter attribute was registered — the "
            "register_announce_handler guard is absent"
        )

        h_raise = inst.register_announce_handler(
            aspect_filter=None, num_params=3, raise_on_call=True)
        h_good = inst.register_announce_handler(aspect_filter=None, num_params=3)
        assert h_raise["registered"] and h_good["registered"]

        priv = secrets.token_bytes(64)
        raw, dest, _ = build_announce_from_destination(
            behavioral.bridge, identity_private_key=priv,
            app_name="guardapp", aspects=["g"], app_data=b"g",
            emission_ts=1_000_000_040, wire_hops=0,
        )
        inst.inject(iface, raw)

        good_calls = _poll_calls(inst, h_good["handler_id"], want=1)
        assert len(good_calls) == 1 and good_calls[0]["destination_hash"] == dest.hex(), (
            f"a well-behaved handler registered after a raising handler did NOT "
            f"fire — exceptions are not isolated: {good_calls}"
        )
        # The non-registered (no aspect_filter) handler must have recorded nothing.
        omit_calls = inst.read_announce_handler_calls(h_omit["handler_id"])["calls"]
        assert omit_calls == [], (
            f"a handler that was never registered still received an announce: "
            f"{omit_calls}"
        )
    finally:
        behavioral.cleanup()
