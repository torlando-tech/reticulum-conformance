"""Wire V2 discovery gap: InterfaceDiscovery.autoconnect pre-connect decisions.

InterfaceDiscovery.autoconnect (Discovery.py:626-682) decides whether a
discovered-interface record should be auto-connected. The actual BackboneInterface
socket connect is out of scope (non-TCP-data-plane ceiling), but the pre-connect
GUARD logic is pure decision-making and must reject the records RNS does not
support auto-connecting — otherwise an impl could silently dial an unsupported or
Yggdrasil endpoint. This drives the real autoconnect for each record and asserts
no interface is added, plus the SHA-256 endpoint dedup key.

Runs reference-vs-reference; no SUT binary required.
"""

from hashlib import sha256

from conformance import conformance_case


__category_title__ = "Discovery & Resolver Completeness"
__category_order__ = 21


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "discovery_autoconnect_gate"],
    verifies=(
        "InterfaceDiscovery.autoconnect rejects every record it must not "
        "auto-connect, before opening any socket (Discovery.py:626-682): a "
        "non-AUTOCONNECT_TYPE (UDPInterface) makes no attempt; a TCPClientInterface "
        "and an I2PInterface each abort ('not yet implemented'); a BackboneInterface "
        "whose reachable_on is a Yggdrasil 200::/7 address is skipped — none add an "
        "interface to RNS.Transport.interfaces. The endpoint dedup key is pinned to "
        "SHA-256('reachable_on:port') (endpoint_hash, Discovery.py:601-606). An impl "
        "that auto-dials an unsupported/Yggdrasil endpoint, or mis-derives the dedup "
        "key, diverges"
    ),
)
def test_autoconnect_rejects_unsupported_records(wire_pair_started):
    server, _client = wire_pair_started

    res = server.discovery_autoconnect_gate()

    for case in ("wrong_type", "tcp_client", "i2p", "yggdrasil"):
        assert res[case]["interfaces_added"] == 0, (
            f"autoconnect added an interface for the {case!r} record — RNS must "
            f"not auto-connect this kind of discovered interface: {res!r}"
        )

    # The dedup key is SHA-256 of "reachable_on:port" (independent oracle).
    expected = sha256(res["endpoint_spec"].encode("utf-8")).hexdigest()
    assert res["endpoint_hash"] == expected, (
        f"InterfaceDiscovery.endpoint_hash != SHA-256('{res['endpoint_spec']}') — "
        f"the auto-connect dedup key is mis-derived: got {res['endpoint_hash']}, "
        f"expected {expected}"
    )
