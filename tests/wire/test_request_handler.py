"""Destination request-handler authorization-policy conformance.

RNS Destination.register_request_handler takes an ``allow`` policy that
gates whether the linked requester's Link.request reaches the response
generator (Destination.py:370-401, enforced in Link.handle_request,
Link.py:853-904):

  - ``ALLOW_ALL``  — every request runs the generator (default).
  - ``ALLOW_LIST`` — only requesters whose identified Identity hash is on
    the allowed list run the generator (covered in test_link_identify.py).
  - ``ALLOW_NONE`` — every request is refused *before* the generator runs;
    the requester's RequestReceipt never gets a response.

Plus ``deregister_request_handler`` (Destination.py:389-401): removing a
handler makes a path that previously answered go silent.

These are the LXMF lxmd propagation-node auth surface (SYNC_REQUEST_PATH /
UNPEER_REQUEST_PATH use ALLOW_LIST; a node that wants to refuse a path
deregisters it). The discriminating property in every case is the SAME:
RNS decides admission before any user code runs, so a refused request
leaves the handler invocation log empty and the requester's receipt FAILED
— while a sibling/positive-control request on the same link succeeds,
isolating the refusal to the policy rather than a broken link.

Two tests:
  1. ALLOW_NONE default-deny — the ALLOW_NONE path is refused (receipt
     FAILED, log empty) while a sibling ALLOW_ALL path on the same link
     answers normally (positive control).
  2. deregister unhandles a path — a registered handler answers once
     (positive control), then after deregister_request_handler the same
     path goes unanswered with the generator never re-invoked; and
     deregistering a never-registered path returns False.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["request-handler-policy"]
_PATH = "/echo"
_REQUEST_TIMEOUT_MS = 15000
# A refused/unhandled request never gets a response, so its RequestReceipt only
# concludes (FAILED) when its own timeout expires. Keep that wait short — the
# request reaches the receiver instantly on loopback; the timeout is purely the
# no-response window — but long enough to outlast loopback jitter.
_DENY_TIMEOUT_MS = 6000


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "link_request",
        "get_request_log",
    ],
    verifies="ALLOW_NONE request-handler default-deny (Destination.py:370-401, Link.py:868): a request handler registered with allow=ALLOW_NONE refuses every Link.request before the response generator runs — the requester's RequestReceipt never reaches READY (status FAILED) and the handler invocation log stays empty; a sibling ALLOW_ALL handler on the same established link answers the same requester with its exact registered bytes (positive control isolating the refusal to the policy, not a broken link)",
)
def test_allow_none_default_deny(wire_allow_none_link):
    """ALLOW_NONE refuses; the ALLOW_ALL sibling on the same link answers."""
    (
        server, client, dest_hash, link_id, none_path, all_path, response,
    ) = wire_allow_none_link()

    # Negative: the ALLOW_NONE path is refused before the generator runs.
    deny = client.link_request(
        link_id, none_path, data=b"", timeout_ms=_DENY_TIMEOUT_MS,
    )
    assert deny["status"] in ("failed", "timeout"), (
        f"ALLOW_NONE handler answered a request that it must refuse: "
        f"status={deny['status']!r}, response={deny['response']!r}. RNS must "
        f"reject the request before sending any response."
    )
    none_entries = server.get_request_log(dest_hash, none_path)
    assert len(none_entries) == 0, (
        f"the ALLOW_NONE response generator ran {len(none_entries)} time(s) — "
        f"RNS must refuse the request before dispatching to the user generator "
        f"(Link.py:868). entries={none_entries!r}"
    )

    # Positive control: the ALLOW_ALL sibling on the SAME link answers, proving
    # the link works and the deny above is attributable to the policy alone.
    allow = client.link_request(
        link_id, all_path, data=b"", timeout_ms=_REQUEST_TIMEOUT_MS,
    )
    assert allow["status"] == "ready", (
        f"the ALLOW_ALL control did not complete READY: status="
        f"{allow['status']!r}, response={allow['response']!r}. The link itself "
        f"is broken, so the ALLOW_NONE refusal above is not discriminating."
    )
    assert bytes.fromhex(allow["response"]) == response, (
        f"the ALLOW_ALL control returned the wrong bytes: got "
        f"{allow['response']!r}, expected {response.hex()!r}."
    )
    allow_entries = server.get_request_log(dest_hash, all_path)
    assert len(allow_entries) == 1, (
        f"the ALLOW_ALL control handler ran {len(allow_entries)} time(s), "
        f"expected exactly 1. entries={allow_entries!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "link_request",
        "deregister_request_handler", "get_request_log",
    ],
    verifies="deregister_request_handler unhandles a path (Destination.py:389-401): a registered ALLOW_ALL handler answers a Link.request once with its exact bytes (positive control), then Destination.deregister_request_handler(path) returns True and a subsequent Link.request for the SAME path goes unanswered — the requester's RequestReceipt never reaches READY (status FAILED) and the generator is never re-invoked (the invocation log stays at its prior count); deregistering a path that was never registered returns False",
)
def test_deregister_request_handler_unhandles_path(wire_link_setup):
    """A registered handler answers once, then after deregister the path
    goes silent and the generator is not re-invoked.
    """
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)
    response = secrets.token_bytes(48)
    server.register_request_handler(dest_hash, _PATH, response, allow="all")

    # Positive control: the registered handler answers and runs exactly once.
    ok = client.link_request(
        link_id, _PATH, data=b"", timeout_ms=_REQUEST_TIMEOUT_MS,
    )
    assert ok["status"] == "ready", (
        f"the registered handler did not answer before deregister: "
        f"status={ok['status']!r}. Without a working positive control the "
        f"post-deregister silence is not discriminating."
    )
    assert bytes.fromhex(ok["response"]) == response, (
        f"the registered handler returned the wrong bytes: got "
        f"{ok['response']!r}, expected {response.hex()!r}."
    )
    assert len(server.get_request_log(dest_hash, _PATH)) == 1, (
        f"expected exactly 1 handler invocation before deregister, got "
        f"{len(server.get_request_log(dest_hash, _PATH))}."
    )

    # Deregister returns True for the registered path.
    assert server.deregister_request_handler(dest_hash, _PATH) is True, (
        f"deregister_request_handler({_PATH!r}) returned False for a "
        f"registered path — it failed to remove the handler."
    )
    # Negative control on the return value: deregistering a path that was never
    # registered returns False (RNS reports nothing was removed).
    assert server.deregister_request_handler(dest_hash, "/never-registered") is False, (
        f"deregister_request_handler('/never-registered') returned True for a "
        f"path that was never registered — it must report no handler removed."
    )

    # After deregister the path is unhandled: the same request goes unanswered.
    after = client.link_request(
        link_id, _PATH, data=b"", timeout_ms=_DENY_TIMEOUT_MS,
    )
    assert after["status"] in ("failed", "timeout"), (
        f"a request to the deregistered path {_PATH!r} still got a response: "
        f"status={after['status']!r}, response={after['response']!r}. The "
        f"handler was not actually deregistered."
    )
    # The generator must NOT have run again — the invocation count is unchanged
    # from the single pre-deregister call. An impl that ignores deregister would
    # show 2 invocations here.
    assert len(server.get_request_log(dest_hash, _PATH)) == 1, (
        f"the deregistered handler's generator ran again — invocation count is "
        f"{len(server.get_request_log(dest_hash, _PATH))}, expected to stay 1. "
        f"The handler was still dispatched after deregister."
    )
