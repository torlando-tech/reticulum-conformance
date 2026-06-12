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

# A fixed small link MTU (>= Reticulum.MTU floor of 500) keeps the negotiated
# link MDU small (~431 B) so a modest request/response crosses it and RNS must
# deliver it as a Resource rather than a single RESPONSE packet — the only way
# to drive the >MDU resource-backed request/response path on a loopback link
# (a direct TCP link negotiates a ~256 KiB MDU that no realistic payload beats).
_FIXED_MTU = 500
_LARGE_RESPONSE_LEN = 50000   # ~50 KB handler response (>> MDU -> response Resource)
_LARGE_REQUEST_LEN = 2000     # ~2 KB request data (> MDU -> request Resource)
_LARGE_TIMEOUT_MS = 45000


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


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "link_request_large",
        "get_request_log",
    ],
    verifies="RequestReceipt over the >MDU resource path (Link.py:496-517/:898-901/:939-952): on a link pinned to a fixed 500-byte MTU (small MDU), a ~2 KB request and a ~50 KB handler response both exceed the link MDU, so RNS carries each as a Resource. The request data the handler observes is byte-exact, the handler-returned response round-trips byte-exact back to the requester, and the RequestReceipt reaches READY only once the response Resource fully transfers.",
)
def test_link_request_large_response_round_trips_as_resource(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(
        _APP, _ASPECTS, fixed_mtu=_FIXED_MTU,
    )

    # ~50 KB random response: incompressible and far above the ~431 B link MDU,
    # so handle_request delivers it as a response Resource (Link.py:901), not a
    # single RESPONSE packet.
    response_payload = secrets.token_bytes(_LARGE_RESPONSE_LEN)
    server.register_request_handler(dest_hash, _PATH, response_payload)

    # ~2 KB request data also exceeds the MDU, so the request itself is sent as
    # a Resource (Link.py:514-527) — exercising both >MDU directions.
    request_data = secrets.token_bytes(_LARGE_REQUEST_LEN)
    result = client.link_request_large(
        link_id, _PATH, data=request_data, timeout_ms=_LARGE_TIMEOUT_MS,
    )
    assert result["status"] == "ready", (
        f"a >MDU request/response did not reach RequestReceipt READY: "
        f"status={result['status']!r}. The RequestReceipt only goes READY once "
        f"the response Resource fully transfers (Link.py:939-952)."
    )
    assert bytes.fromhex(result["response"]) == response_payload, (
        f"the ~50 KB resource-backed response did not round-trip byte-exact: "
        f"got {len(bytes.fromhex(result['response']))} bytes, expected "
        f"{len(response_payload)}."
    )

    # The handler must have observed the exact >MDU request bytes (proves the
    # request Resource reassembled correctly on the receiver, not just that a
    # response came back).
    entries = server.get_request_log(dest_hash, _PATH)
    assert len(entries) == 1, (
        f"handler invoked {len(entries)} times, expected exactly 1: {entries!r}"
    )
    assert entries[0]["data"] == request_data.hex(), (
        f"the >MDU request data the handler observed did not match what the "
        f"client sent — the request Resource did not reassemble byte-exact."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "link_request", "get_request_log",
    ],
    verifies=(
        "A request handler returning a (file, metadata) tuple is answered as a "
        "metadata-bearing response Resource, NOT a RESPONSE packet "
        "(Link.py:884-895 / response_resource_concluded:939-945): the requester "
        "receives the file content byte-exact AND the separate metadata "
        "un-unpacked (the has_metadata branch), while a normal bytes handler "
        "answers with no metadata. An impl that umsgpack-wraps a file response, "
        "drops the metadata, or ships it as a RESPONSE packet diverges observably"
    ),
)
def test_file_response_carries_metadata_as_resource(wire_link_setup):
    server, client, dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    file_path = "/file"
    bytes_path = "/bytes"
    content = secrets.token_bytes(200)
    metadata = secrets.token_bytes(32)
    server.register_request_handler(
        dest_hash, file_path, response_file=content, response_metadata=metadata,
    )
    # Positive contrast: a normal bytes handler (umsgpack RESPONSE path).
    server.register_request_handler(dest_hash, bytes_path, response=secrets.token_bytes(48))

    # File response: delivered as a metadata-bearing Resource. Both the content
    # AND the metadata must round-trip — the metadata is the discriminator that
    # the file/Resource branch (not the umsgpack packet branch) was taken.
    fr = client.link_request(link_id, file_path, timeout_ms=15000)
    assert fr["status"] == "ready", (
        f"a file-response request did not reach READY: {fr!r}"
    )
    assert fr["response"] == content.hex(), (
        f"the file content did not round-trip byte-exact: {fr!r}"
    )
    assert fr["response_metadata"] == metadata.hex(), (
        f"the response metadata did not round-trip — the file/metadata Resource "
        f"branch was not taken (a RESPONSE packet or umsgpack wrap carries no "
        f"metadata): {fr!r}"
    )

    # Contrast: a normal bytes response carries NO metadata.
    br = client.link_request(link_id, bytes_path, timeout_ms=10000)
    assert br["status"] == "ready", f"the bytes-response request did not reach READY: {br!r}"
    assert br["response_metadata"] is None, (
        f"a normal bytes response must carry no metadata; metadata is the "
        f"file-Resource discriminator: {br!r}"
    )
