"""Link.identify + ALLOW_LIST request handler conformance.

RNS Link request handlers support an authentication policy:
``Destination.ALLOW_ALL`` (any requester, default) or
``Destination.ALLOW_LIST`` (only identities in a fixed allow-list). The
requester opts into being identified by calling ``Link.identify(identity)``
after the link is up — the remote then sees the requester's Identity on
the handler's ``remote_identity`` argument.

This is the path LXMF's lxmd uses for propagation-node sync:
SYNC_REQUEST_PATH and UNPEER_REQUEST_PATH register ALLOW_LIST handlers
(only peered propagation nodes are allowed), and the sync code calls
``link.identify(local_identity)`` before requesting. An impl that drops
``remote_identity`` from the handler signature, or that fails ALLOW_LIST
enforcement, silently breaks propagation auth.

Three tests:

  1. identified ALLOW_ALL — the handler observes a non-None
     remote_identity matching the requester's identity_hash.
  2. ALLOW_LIST positive — requester's identity_hash is on the list;
     the handler runs and the response comes back.
  3. ALLOW_LIST negative — requester not on the list; RNS rejects the
     request before the handler runs (request fails / times out), AND
     the invocation log shows zero entries.
"""

import secrets

from conformance import conformance_case
from conftest import random_hex


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["link-identify"]
_PATH = "/echo"
_LINK_TIMEOUT_MS = 15000
_PATH_POLL_TIMEOUT_MS = 10000
_REQUEST_TIMEOUT_MS = 15000


def _bring_up_link(server, client):
    """Wire the pair together and open a link from client to server's
    listening destination. Returns (server_dest, link_id).
    """
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )
    server_dest = server.listen(app_name=_APP, aspects=_ASPECTS)
    assert client.poll_path(server_dest, timeout_ms=_PATH_POLL_TIMEOUT_MS), (
        f"{client.role_label} never learned a path to {server.role_label}'s "
        f"destination — link-identify tests need the link first."
    )
    link_id = client.link_open(
        server_dest, app_name=_APP, aspects=_ASPECTS,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    return server_dest, link_id


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "link_identify",
        "link_request", "get_request_log",
    ],
    verifies="ALLOW_ALL request handler observes a non-None remote_identity when the requester called Link.identify first — the field handlers gate auth on. An impl that drops remote_identity through the request pipeline breaks every ALLOW_LIST handler (LXMF lxmd propagation sync etc.)",
)
def test_identified_request_surfaces_remote_identity(wire_peers):
    server, client = wire_peers
    server_dest, link_id = _bring_up_link(server, client)
    response_payload = secrets.token_bytes(32)
    server.register_request_handler(server_dest, _PATH, response_payload, allow="all")

    # Identify the link initiator BEFORE requesting. The handler's
    # remote_identity is None for an un-identified requester.
    client_priv = bytes.fromhex(random_hex(64))
    client_identity_hash = client.link_identify(link_id, client_priv)

    result = client.link_request(
        link_id, _PATH, data=b"", timeout_ms=_REQUEST_TIMEOUT_MS,
    )
    assert result["status"] == "ready", (
        f"identified link.request did not complete READY: status="
        f"{result['status']!r}, response={result['response']!r}"
    )
    entries = server.get_request_log(server_dest, _PATH)
    assert len(entries) == 1, (
        f"expected exactly 1 handler invocation, got {len(entries)}"
    )
    observed_hash = entries[0]["remote_identity_hash"]
    assert observed_hash == client_identity_hash.hex(), (
        f"handler observed remote_identity_hash={observed_hash!r}, "
        f"expected {client_identity_hash.hex()!r} (the requester's "
        f"identified identity). An impl that loses remote_identity "
        f"on identified requests breaks ALLOW_LIST auth."
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "identity_from_private_key",
        "link_identify", "link_request", "get_request_log",
    ],
    verifies="ALLOW_LIST request handler positive control: when the identified requester's identity_hash is in the destination's allowed_list, RNS runs the handler exactly once and routes the handler's exact registered response bytes back to the requester",
)
def test_allow_list_admits_listed_identity(wire_peers):
    server, client = wire_peers
    server_dest, link_id = _bring_up_link(server, client)
    response_payload = secrets.token_bytes(32)

    # Pre-compute the client's identity hash; only that identity is
    # allowed through the handler.
    client_priv = bytes.fromhex(random_hex(64))
    client_id_info = client.bridge.execute(
        "identity_from_private_key", private_key=client_priv.hex()
    )
    allowed_hash = bytes.fromhex(client_id_info["hash"])

    server.register_request_handler(
        server_dest, _PATH, response_payload,
        allow="list", allowed_identity_hashes=[allowed_hash],
    )
    client.link_identify(link_id, client_priv)

    result = client.link_request(
        link_id, _PATH, data=b"", timeout_ms=_REQUEST_TIMEOUT_MS,
    )
    assert result["status"] == "ready", (
        f"ALLOW_LIST request from listed identity did not complete READY: "
        f"status={result['status']!r}"
    )
    # The response RNS routed back must be exactly the handler's registered
    # payload (L11). status==ready alone does not prove the right bytes came
    # through — an impl that admits the request but returns the wrong/empty
    # response would otherwise pass.
    assert bytes.fromhex(result["response"]) == response_payload, (
        f"ALLOW_LIST handler ran but the routed response did not match the "
        f"registered payload: got {result['response']!r}, expected "
        f"{response_payload.hex()!r}"
    )
    entries = server.get_request_log(server_dest, _PATH)
    assert len(entries) == 1, (
        f"expected handler to run once for listed identity, got "
        f"{len(entries)} invocations"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "register_request_handler", "identity_from_private_key",
        "link_identify", "link_request", "get_request_log",
    ],
    verifies="ALLOW_LIST request handler negative control: when the identified requester's identity_hash is NOT in the destination's allowed_list, RNS rejects the request before the handler runs (request fails or times out) AND the handler's invocation log stays empty. An impl that runs the handler regardless of allow_list silently bypasses propagation-node auth.",
)
def test_allow_list_rejects_unlisted_identity(wire_peers):
    server, client = wire_peers
    server_dest, link_id = _bring_up_link(server, client)

    # Allowed list contains a *different* identity than the client's.
    different_priv = bytes.fromhex(random_hex(64))
    different_id = server.bridge.execute(
        "identity_from_private_key", private_key=different_priv.hex()
    )
    allowed_hash = bytes.fromhex(different_id["hash"])

    server.register_request_handler(
        server_dest, _PATH, secrets.token_bytes(32),
        allow="list", allowed_identity_hashes=[allowed_hash],
    )

    # Client identifies as its OWN identity — not the one on the list.
    client_priv = bytes.fromhex(random_hex(64))
    client.link_identify(link_id, client_priv)

    result = client.link_request(
        link_id, _PATH, data=b"", timeout_ms=5000,
    )
    # RNS rejects the request before the handler runs — the receipt
    # either times out or fails. The CRITICAL assertion is that the
    # handler's invocation log is EMPTY: ALLOW_LIST enforcement
    # happens in real RNS before any user code runs.
    assert result["status"] in ("failed", "timeout"), (
        f"ALLOW_LIST request from un-listed identity completed READY — "
        f"the destination accepted a request from an unauthorised "
        f"requester. status={result['status']!r}, response="
        f"{result['response']!r}"
    )
    entries = server.get_request_log(server_dest, _PATH)
    assert len(entries) == 0, (
        f"handler ran for an un-listed identity ({len(entries)} "
        f"invocations) — RNS did not enforce ALLOW_LIST before "
        f"dispatching to the user generator. entries={entries!r}"
    )
