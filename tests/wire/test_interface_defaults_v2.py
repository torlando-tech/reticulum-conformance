"""Wire V2 interface gap: transport-node interop default constants.

Two interface defaults a SUT must match for cross-implementation interop, read
straight off the live RNS instance / Interface class (the behaviours they govern
— the shared-instance frame plane and wall-clock announce pacing — are out of
scope under LIMITS, but the constants themselves are interop contract):

  * local-shared-instance-transport: the well-known shared-instance local
    interface port defaults to 37428 (Reticulum.local_interface_port).
  * announce-rate-enforcement: the transport-node announce-rate defaults are
    DEFAULT_AR_TARGET=3600 s, DEFAULT_AR_PENALTY=0, DEFAULT_AR_GRACE=5
    (Interface.py; the _default_ar_*() fallbacks, Reticulum.py:1083-1090).

Runs reference-vs-reference; no SUT binary required.
"""

from conformance import conformance_case


__category_title__ = "Interface Hooks"
__category_order__ = 17


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "interface_transport_defaults",
    ],
    verifies=(
        "The transport-node interface interop defaults match RNS exactly: the "
        "shared-instance local interface port defaults to 37428 "
        "(Reticulum.local_interface_port), and the announce-rate defaults a "
        "transport node applies when none are configured are "
        "DEFAULT_AR_TARGET=3600 s, DEFAULT_AR_PENALTY=0, DEFAULT_AR_GRACE=5 "
        "(Interface.DEFAULT_AR_*). A SUT that binds a different shared-instance "
        "port or applies different announce-rate defaults diverges on local "
        "connectivity and transport-node announce pacing"
    ),
)
def test_transport_node_interface_defaults(wire_pair_started):
    server, _client = wire_pair_started

    d = server.interface_transport_defaults()

    assert d["local_interface_port"] == 37428, (
        f"the shared-instance local interface port must default to 37428: {d!r}"
    )
    assert d["ar_target"] == 3600, (
        f"transport-node DEFAULT_AR_TARGET must be 3600 s: {d!r}"
    )
    assert d["ar_penalty"] == 0, (
        f"transport-node DEFAULT_AR_PENALTY must be 0: {d!r}"
    )
    assert d["ar_grace"] == 5, (
        f"transport-node DEFAULT_AR_GRACE must be 5: {d!r}"
    )
