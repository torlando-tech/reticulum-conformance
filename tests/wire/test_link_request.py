"""Link request / response handler conformance.

RNS Link supports a request/response RPC on top of an established Link:
the destination owner calls Destination.register_request_handler(path,
response_generator), and the client peer calls Link.request(path, data),
which delivers `data` to the registered handler and routes the handler's
return value back to the client via response_callback.

This is the path Columba's NomadNet browser uses (NativeNomadNetHandler
calls link.request to fetch a page) and the path LXMF's lxmd uses for
propagation-node sync (SYNC_REQUEST_PATH, UNPEER_REQUEST_PATH).

Honest test: peer A registers a fixed-response handler on a destination,
peer B opens a link and calls link.request(path, data). Real RNS routes
the request to A's handler, runs it, sends the response back over the
link, fires B's response_callback. We assert:
  - the response RNS delivered matches what A's handler returned, and
  - the handler was invoked exactly once with the exact request bytes B
    sent (this catches an impl that loses/duplicates request data on the
    wire).

The identity-gated path — where the handler observes the requester's
Identity after Link.identify — is NOT exercised here: this test leaves the
requester un-identified, so remote_identity is None by RNS default. That
path is covered separately in test_link_identify.py.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["request-handler"]
_PATH = "/echo"
_LINK_TIMEOUT_MS = 15000
_PATH_POLL_TIMEOUT_MS = 10000
_REQUEST_TIMEOUT_MS = 15000


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "link_request",
        "get_request_log",
    ],
    verifies="RNS Link request/response RPC: a Destination.register_request_handler-registered generator fires when the linked client calls Link.request(path, data); the handler's return bytes are delivered back via response_callback, and the handler observes the exact request data the client sent",
)
def test_link_request_round_trip(wire_peers):
    server, client = wire_peers
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )

    server_dest = server.listen(app_name=_APP, aspects=_ASPECTS)
    response_payload = secrets.token_bytes(64)
    server.register_request_handler(server_dest, _PATH, response_payload)

    assert client.poll_path(server_dest, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — request RPC needs the link first."
    )
    link_id = client.link_open(
        server_dest, app_name=_APP, aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )

    request_data = secrets.token_bytes(32)
    result = client.link_request(
        link_id, _PATH, data=request_data, timeout_ms=_REQUEST_TIMEOUT_MS,
    )
    assert result["status"] == "ready", (
        f"link.request did not complete READY: status={result['status']!r}, "
        f"response={result['response']!r}"
    )
    assert bytes.fromhex(result["response"]) == response_payload, (
        f"response payload did not match what the handler returned: "
        f"got {result['response']!r}, expected {response_payload.hex()!r}"
    )

    # Verify the handler observed exactly one invocation with the exact
    # request bytes. An impl that loses request data or fires the handler
    # zero/multiple times surfaces here, not transitively via response.
    entries = server.get_request_log(server_dest, _PATH)
    assert len(entries) == 1, (
        f"request handler was invoked {len(entries)} times for "
        f"{_PATH!r}, expected exactly 1. entries={entries!r}"
    )
    obs = entries[0]
    assert obs["data"] == request_data.hex(), (
        f"handler observed wrong request data: got {obs['data']!r}, "
        f"expected {request_data.hex()!r}"
    )
    # remote_identity_hash is None when the requester didn't call
    # link.identify(...) first — RNS's default. We don't exercise the
    # identified path here; ALLOW_LIST request handlers (LXMF lxmd's
    # SYNC_REQUEST_PATH, etc.) require an additional link.identify call
    # which belongs in a dedicated test that adds the identify bridge cmd.
