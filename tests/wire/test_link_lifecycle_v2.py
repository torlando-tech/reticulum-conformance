"""Wire V2 link-lifecycle gaps (CONFORMANCE_COMPLETENESS_V2 link subsystem).

Four link rules that were entirely undriven before this file, each pinned
through the real RNS APIs (the oracle is RNS's own Link logic, never a
reimplementation):

  * link-init-single-only        — Link() raises TypeError for a non-SINGLE
                                    destination (Link.py:234).
  * link-track-phy-stats-gating  — get_rssi/get_snr/get_q return None unless
                                    track_phy_stats is enabled (Link.py:573-598).
  * teardown-no-packet-on-pending — teardown emits a LINKCLOSE only when the
                                    link is past PENDING (Link.py:699-704).
  * request-none-response-silent  — a request handler returning None sends no
                                    response; the requester only times out
                                    (Link.py:893).

Runs reference-vs-reference; no SUT binary required.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18

_APP = "conformance"
_ASPECTS = ["link-lifecycle"]


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "link_type_gate"],
    verifies=(
        "A Link can only be established to a SINGLE destination: constructing "
        "RNS.Link() against a PLAIN or GROUP destination raises TypeError before "
        "any handshake (Link.py:234), while a SINGLE destination constructs a "
        "real link (positive control). An impl that permits links to PLAIN/GROUP "
        "destinations diverges — link encryption is defined only for the SINGLE "
        "identity model"
    ),
)
def test_link_only_to_single_destination(wire_pair_started):
    _server, client = wire_pair_started

    res = client.link_type_gate()

    # Positive control: SINGLE constructs a real link, no TypeError.
    assert res["single"]["raised"] is False, (
        f"constructing a Link to a SINGLE destination raised TypeError "
        f"(positive control): {res['single']!r}"
    )
    assert res["single"]["link_created"] is True, (
        f"a SINGLE destination did not yield a link: {res['single']!r}"
    )

    # Negatives: PLAIN and GROUP each raise TypeError naming the single-only rule.
    for dtype in ("plain", "group"):
        arm = res[dtype]
        assert arm["raised"] is True, (
            f"constructing a Link to a {dtype.upper()} destination did NOT raise "
            f"TypeError — the single-only rule was not enforced: {arm!r}"
        )
        assert "single" in (arm["error"] or "").lower(), (
            f"the {dtype.upper()} TypeError did not name the single-only rule: {arm!r}"
        )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "link_phy_stats_gate",
    ],
    verifies=(
        "Link physical-layer statistics are gated on track_phy_stats: with "
        "tracking off (the default) get_rssi/get_snr/get_q each return None even "
        "when rssi/snr/q hold values; enabling track_phy_stats(True) makes the "
        "getters return the stored values; disabling it returns them to None "
        "(Link.py:573-598). An impl that leaks stale phy stats while tracking is "
        "off diverges from the documented API"
    ),
)
def test_phy_stats_gated_on_tracking(wire_link_setup):
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.link_phy_stats_gate(link_id)
    stored = res["stored"]

    # Tracking off (default): every getter gates to None despite stored values.
    assert res["off"] == {"rssi": None, "snr": None, "q": None}, (
        f"phy getters returned values while tracking was OFF — stale-stat leak: "
        f"{res['off']!r}"
    )
    # Tracking on: getters return the stored values.
    assert res["on"] == stored, (
        f"phy getters did not return the stored values while tracking was ON: "
        f"{res['on']!r} != {stored!r}"
    )
    # Tracking off again: gated back to None.
    assert res["off_again"] == {"rssi": None, "snr": None, "q": None}, (
        f"phy getters did not re-gate to None after tracking was disabled: "
        f"{res['off_again']!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "link_teardown_emission",
    ],
    verifies=(
        "Link.teardown emits an on-wire LINKCLOSE packet ONLY when the link is "
        "past PENDING (and not already CLOSED): tearing down a never-established "
        "PENDING link emits zero LINKCLOSE packets, while tearing down an "
        "established ACTIVE link emits exactly one (Link.py:699-704). An impl "
        "that sprays a close packet for an un-established link (or omits it for "
        "an active one) diverges observably on the wire"
    ),
)
def test_teardown_emits_linkclose_only_past_pending(wire_link_setup):
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    res = client.link_teardown_emission(link_id)

    assert res["active_status_before"] == "ACTIVE", (
        f"the established link was not ACTIVE before teardown (test precondition): "
        f"{res!r}"
    )
    assert res["pending_linkclose_emitted"] == 0, (
        f"tearing down a PENDING (never-established) link emitted a LINKCLOSE "
        f"packet — a non-initiated link must close silently: {res!r}"
    )
    assert res["active_linkclose_emitted"] == 1, (
        f"tearing down an ACTIVE link did not emit exactly one LINKCLOSE packet: "
        f"{res!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "register_request_handler", "link_request", "get_request_log",
    ],
    verifies=(
        "A request handler returning None produces NO response: the handler "
        "fires (the request is delivered and processed) but RNS sends no "
        "RESPONSE packet/resource, so the requester only ever times out "
        "(Link.py:893). A second handler returning bytes answers normally "
        "(positive control). An impl that sends an empty RESPONSE for a None "
        "return diverges — the requester would wrongly observe success"
    ),
)
def test_request_handler_none_sends_no_response(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    none_path = "/none"
    bytes_path = "/bytes"
    expected = secrets.token_bytes(24)
    server.register_request_handler(dest_hash, none_path, response_none=True)
    server.register_request_handler(dest_hash, bytes_path, response=expected)

    # Positive control: the bytes handler answers normally.
    good = client.link_request(link_id, bytes_path, timeout_ms=10000)
    assert good["status"] == "ready", (
        f"the bytes-returning handler did not answer (positive control): {good!r}"
    )
    assert good["response"] == expected.hex(), (
        f"the response did not round-trip byte-exact: {good!r}"
    )

    # Negative: the None handler sends nothing — the requester times out.
    none = client.link_request(link_id, none_path, timeout_ms=4000)
    assert none["status"] in ("timeout", "failed"), (
        f"a None-returning handler produced a response — RNS must send no "
        f"RESPONSE for a None return: {none!r}"
    )
    assert none["response"] is None, f"unexpected response for None handler: {none!r}"

    # But the handler DID fire — proving the request was delivered and processed,
    # so the silence is the None-response branch, not a dropped request.
    log = server.get_request_log(dest_hash, none_path)
    assert len(log) == 1, (
        f"the None handler did not fire exactly once (the request must still be "
        f"delivered and processed, just unanswered): {log!r}"
    )
