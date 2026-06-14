"""In-transit link-MTU strip across a mixed interface-type relay.

Gap closed: CONFORMANCE_GAPS.md §2c "In-transit link-MTU strip to a
non-autoconfigure next-hop" (core) — RNS ref Transport.py:1593-1600.

Topology (provided by the `wire_mixed_relay_3peer` fixture):

    a_leaf (A, PipeInterface, hosts D, transport OFF)
             \\
              v   named-FIFO pair (loopback byte bridge)
    relay   (B, PipeInterface + TCPServerInterface, transport ON, hosts D2)
              ^
              |   TCP loopback
    c_tcp   (C, TCPClientInterface, initiator)

The protocol rule under test
----------------------------
When a transport node forwards a LINKREQUEST whose computed link MTU came
from the receiving interface, it re-clamps (or strips) the 3-byte
LINK_MTU signalling field according to the OUTBOUND (next-hop) interface
(Transport.py:1593-1600):

  * next-hop has no HW_MTU                              -> strip 3 bytes
  * next-hop is NOT AUTOCONFIGURE_MTU and NOT FIXED_MTU -> strip 3 bytes
  * otherwise                                           -> clamp to min()

PipeInterface inherits Interface's AUTOCONFIGURE_MTU=False / FIXED_MTU=False
(and has HW_MTU=1064), so it takes the strip branch. When C opens a Link to
D (hosted on A), B forwards the LINKREQUEST OUT the PipeInterface to A and
strips the 3 signalling bytes; A's responder-side `Link.validate_request`
then sees a bare ECPUBSIZE payload (no MTU field), never enters the
mtu-from-LR branch, and the inbound link keeps its constructor default
`Link.mtu = Reticulum.MTU` == 500 (Link.py:155-160, :194-198, :237).

The link_id is unaffected by the strip: `Link.link_id_from_lr_packet`
trims any trailing MTU bytes before hashing (Link.py:341-347), so the
link_id C computes equals the one A computes — that's why
`a_leaf.link_mtu(<C's link_id>)` resolves A's inbound link.

Discrimination + positive control
----------------------------------
The relayed link's inbound MTU must be EXACTLY 500. An implementation that
forgets the strip would hand A the MTU field that survived the TCP hop and
negotiate a larger value (the clamp branch would give 1064, the no-clamp
bug would give C's proposed HW_MTU) — in every non-conformant case the
inbound MTU is != 500, so the test fails.

The positive control is a SECOND link from the SAME initiator C straight to
a relay-hosted destination D2 over TCP only (no pipe hop). TCPInterface is
AUTOCONFIGURE_MTU=True, so that LINKREQUEST is NOT stripped and the inbound
link negotiates an MTU well above 500. Asserting `direct_mtu > 500` AND
`direct_mtu > relayed_mtu` proves the harness CAN produce a non-500 MTU on
this hardware — so the relayed link's 500 is genuinely the strip and not an
artifact of link-MTU discovery being globally inert.

Reference-only: PipeInterface FIFO bridging is a Python-RNS construct (the
fixture hardcodes reference bridges); a TCP-only relay cannot reproduce the
strip because TCP autoconfigures its MTU.
"""

import time

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP_NAME = "mtu_strip"
_ASPECTS_RELAYED = ["leaf"]    # D, hosted on A behind the pipe
_ASPECTS_DIRECT = ["relay"]    # D2, hosted on B (the relay) over TCP

# RNS.Reticulum.MTU — the value an inbound link falls back to when the
# forwarded LINKREQUEST arrived with its MTU signalling stripped.
_RETICULUM_MTU = 500

# Generous timings: pipe `cat` rendezvous + TCP connect + IFAC handshake,
# then announce propagation A -> B -> C (and B -> C), path discovery, and
# RTT-probe-laden link establishment across the relay.
_SETTLE_SEC = 3.0
_PATH_TIMEOUT_MS = 15000
_LINK_TIMEOUT_MS = 20000
_INBOUND_TIMEOUT_MS = 8000


def _bring_up_mixed_relay(a_leaf, relay, c_tcp):
    """Start the relay, leaf, and TCP client in the order the fixture
    documents, then settle until the byte bridges are live.

    Returns nothing; the peers are left configured for the caller to
    register listeners and open links.
    """
    # 1. Relay first: it owns the TCP listen port C connects to, and its
    #    pipe end must be present before the leaf's `cat` can rendezvous.
    port = relay.start_pipe_tcp_relay(relay.pipe_read_fifo, relay.pipe_write_fifo)
    assert port, f"{relay.role_label} did not return a TCP listen port"

    # 2. Leaf attaches its PipeInterface to the OTHER end of the FIFO pair.
    a_leaf.start_pipe_peer(a_leaf.pipe_read_fifo, a_leaf.pipe_write_fifo)

    # 3. TCP client connects to the relay's TCP server.
    c_tcp.start_tcp_client(
        network_name="",
        passphrase="",
        target_host="127.0.0.1",
        target_port=port,
    )

    # Let the pipe `cat` processes rendezvous and the TCP/IFAC handshake
    # complete before any destination announces — an announce emitted while
    # an interface is still offline is simply lost (no origin retransmit).
    time.sleep(_SETTLE_SEC)


@conformance_case(
    commands=[
        "start_pipe_tcp_relay",
        "start_pipe_peer",
        "start_tcp_client",
        "listen",
        "poll_path",
        "link_open",
        "listener_link_status",
        "link_mtu",
    ],
    verifies=(
        "Across a mixed PipeInterface<->TCPInterface relay, a LINKREQUEST "
        "forwarded by the transport node OUT the non-autoconfigure "
        "PipeInterface has its 3-byte LINK_MTU signalling field stripped, so "
        "the destination's inbound link.mtu falls back to Reticulum.MTU==500; "
        "a direct TCP link from the same initiator to a relay-hosted "
        "destination is NOT stripped and negotiates an MTU > 500 (positive "
        "control), and the relayed MTU is strictly smaller than the direct one."
    ),
)
def test_in_transit_link_mtu_strip_across_mixed_relay(wire_mixed_relay_3peer):
    """C opens two links from the same TCP interface:

      relayed: C -> [TCP] -> B -> [Pipe] -> A's destination D
      direct:  C -> [TCP] -> B's destination D2

    The relayed link's inbound MTU (read on A) must be exactly 500 — proof
    the 3 signalling bytes were stripped when B forwarded the LINKREQUEST out
    the PipeInterface. The direct link's inbound MTU (read on B) must be
    larger, proving link-MTU discovery is live and the 500 is the strip.
    """
    a_leaf, relay, c_tcp = wire_mixed_relay_3peer
    _bring_up_mixed_relay(a_leaf, relay, c_tcp)

    # A hosts D behind the pipe; B hosts D2 reachable directly over TCP.
    # wire_listen announces the destination as a side effect, so C can learn
    # a path to each.
    d_hash = a_leaf.listen(app_name=_APP_NAME, aspects=_ASPECTS_RELAYED)
    d2_hash = relay.listen(app_name=_APP_NAME, aspects=_ASPECTS_DIRECT)

    # C must learn both paths before opening links; failure here means the
    # topology didn't converge and the MTU assertions would be uninterpretable.
    assert c_tcp.poll_path(d_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{c_tcp.role_label} never learned a path to D on "
        f"{a_leaf.role_label} (relayed via {relay.role_label}'s pipe). The "
        f"mixed-relay topology did not converge."
    )
    assert c_tcp.poll_path(d2_hash, timeout_ms=_PATH_TIMEOUT_MS), (
        f"{c_tcp.role_label} never learned a path to D2 on "
        f"{relay.role_label} (direct TCP). The mixed-relay topology did not "
        f"converge."
    )

    # Open the relayed link (crosses the pipe) and the direct TCP link.
    relayed_link_id = c_tcp.link_open(
        d_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS_RELAYED,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    direct_link_id = c_tcp.link_open(
        d2_hash,
        app_name=_APP_NAME,
        aspects=_ASPECTS_DIRECT,
        timeout_ms=_LINK_TIMEOUT_MS,
    )
    assert len(relayed_link_id) == 16 and len(direct_link_id) == 16

    # Wait for the responder-side (inbound) links to be accepted. The strip
    # is observed on the DESTINATION's inbound link, not the initiator's.
    relayed_inbound = a_leaf.listener_link_status(
        d_hash, timeout_ms=_INBOUND_TIMEOUT_MS
    )
    assert relayed_inbound.get("found"), (
        f"{a_leaf.role_label} never accepted the inbound relayed link for D; "
        f"cannot read its negotiated MTU."
    )
    direct_inbound = relay.listener_link_status(
        d2_hash, timeout_ms=_INBOUND_TIMEOUT_MS
    )
    assert direct_inbound.get("found"), (
        f"{relay.role_label} never accepted the inbound direct link for D2."
    )

    # link_id is identical on both ends (the strip trims trailing MTU bytes
    # before hashing), so the initiator's link_id resolves the responder's
    # inbound link on each destination peer.
    relayed_mtu_info = a_leaf.link_mtu(relayed_link_id)
    direct_mtu_info = relay.link_mtu(direct_link_id)

    # Both inbound links must be ACTIVE so we read a fully-negotiated MTU.
    assert relayed_mtu_info["status_name"] == "ACTIVE", (
        f"relayed inbound link not ACTIVE: {relayed_mtu_info}"
    )
    assert direct_mtu_info["status_name"] == "ACTIVE", (
        f"direct inbound link not ACTIVE: {direct_mtu_info}"
    )

    relayed_mtu = relayed_mtu_info["mtu"]
    direct_mtu = direct_mtu_info["mtu"]

    # CORE assertion: the forwarded-out-the-pipe LINKREQUEST was stripped of
    # its 3 LINK_MTU bytes, so A's inbound link fell back to Reticulum.MTU.
    # An impl that fails to strip (or that clamps instead of stripping) lands
    # on a value != 500 (the pipe HW_MTU 1064, or C's proposed HW_MTU).
    assert relayed_mtu == _RETICULUM_MTU, (
        f"Expected the relayed inbound link.mtu to fall back to "
        f"Reticulum.MTU={_RETICULUM_MTU} after the in-transit LINK_MTU strip "
        f"out {relay.role_label}'s non-autoconfigure PipeInterface, but got "
        f"{relayed_mtu}. A non-500 value means the 3-byte LINK_MTU signalling "
        f"survived the pipe hop (strip not applied)."
    )

    # POSITIVE CONTROL: the direct TCP link from the same initiator is NOT
    # stripped (TCP autoconfigures its MTU) and negotiates a larger MTU.
    # This proves link-MTU discovery is live on this harness, so the relayed
    # 500 is the strip and not a globally-inert-discovery artifact.
    assert direct_mtu > _RETICULUM_MTU, (
        f"Expected the direct TCP link.mtu to exceed Reticulum.MTU="
        f"{_RETICULUM_MTU} (TCPInterface is AUTOCONFIGURE_MTU=True, no strip), "
        f"but got {direct_mtu}. If this equals 500, link-MTU discovery is "
        f"inert and the relayed assertion above is not discriminating."
    )
    assert direct_mtu > relayed_mtu, (
        f"The direct (non-stripped) link MTU {direct_mtu} should be strictly "
        f"larger than the relayed (stripped) link MTU {relayed_mtu}."
    )
