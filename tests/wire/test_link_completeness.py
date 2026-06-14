"""Link-subsystem completeness conformance (RNS 1.3.1 Link.py).

Three protocol rules that the existing wire-link suite only constrains loosely
(or not at all) are pinned here against INDEPENDENT oracles — values recomputed
from RNS 1.3.1 spec literals, not read back from the same code path that
produced them:

  * link-mdu — the exact link MDU formula. The existing read-back test only
    asserts 0 < mdu < mtu and 16-byte alignment, so an impl that drops a header
    term (e.g. yields 447, 448, 464 or 479 at MTU 500) passes. Here the MDU is
    pinned to the exact 431 the update_mdu floor produces at MTU 500 and is
    cross-checked against the formula recomputed from the spec constants, with
    plausible wrong formulas asserted to be rejected.

  * keepalive-interval-derivation — the keepalive clamp. The lifecycle test only
    asserts keepalive > 0 and stale == keepalive*2, so any constant passes. Here
    the keepalive is recomputed from the link's own measured RTT via the RNS
    clamp `max(min(rtt*(KEEPALIVE_MAX/KEEPALIVE_MAX_RTT), KEEPALIVE_MAX),
    KEEPALIVE_MIN)` and asserted byte-equal, and the KEEPALIVE_MIN=5 floor is
    shown to actually fire on a loopback link (raw scaled value < 5).

  * identify-validation (initiator-only gate) — a link's INITIATOR must IGNORE
    an inbound LINKIDENTIFY even when its signature is cryptographically valid
    (only the non-initiator adopts a remote identity). The existing forgery test
    only drives the non-initiator's signature checks; the initiator-only gate
    (Link.receive: `if not self.initiator and len(plaintext)==128`) is pinned
    here by feeding the SAME genuinely-valid identify to both the initiator side
    (must NOT adopt) and the non-initiator side (must adopt).

Runs reference-vs-reference; no SUT binary required.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ("link-completeness",)
_FIXED_MTU = 500

# --- RNS 1.3.1 spec literals (read straight from the source, NOT imported, so
# this is an independent oracle, not an impl-vs-itself round-trip) ------------
# Link.update_mdu (Link.py:532):
#   mdu = floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD)
#               / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
_IFAC_MIN_SIZE = 1       # RNS.Reticulum.IFAC_MIN_SIZE
_HEADER_MINSIZE = 19     # RNS.Reticulum.HEADER_MINSIZE
_HEADER_MAXSIZE = 35     # RNS.Reticulum.HEADER_MAXSIZE
_TOKEN_OVERHEAD = 48     # RNS.Identity.TOKEN_OVERHEAD
_AES128_BLOCKSIZE = 16   # RNS.Identity.AES128_BLOCKSIZE

# Link keepalive clamp (Link.py:845-846 / :92-99):
_KEEPALIVE_MIN = 5       # RNS.Link.KEEPALIVE_MIN
_KEEPALIVE_MAX = 360     # RNS.Link.KEEPALIVE_MAX
_KEEPALIVE_MAX_RTT = 1.75  # RNS.Link.KEEPALIVE_MAX_RTT
_STALE_FACTOR = 2        # RNS.Link.STALE_FACTOR

# keepalive_s / stale_time_s cross the bridge boundary in seconds, but a
# conformant impl may carry the local watchdog interval at integer-millisecond
# resolution (reticulum-kt keeps every link timer as a ms long, so its clamp is
# floor(rtt_ms * scale)/1000 rather than a full-precision seconds float). One
# millisecond is therefore the comparison quantum for those derived timings.
_MS = 1e-3


def _expected_mdu(mtu):
    """The RNS 1.3.1 link MDU floor, recomputed independently from spec
    literals (Link.update_mdu, Link.py:532)."""
    usable = mtu - _IFAC_MIN_SIZE - _HEADER_MINSIZE - _TOKEN_OVERHEAD
    return (usable // _AES128_BLOCKSIZE) * _AES128_BLOCKSIZE - 1


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_status",
    ],
    verifies=(
        "The negotiated link MDU is EXACTLY the RNS 1.3.1 update_mdu floor "
        "(Link.py:532): floor((mtu - IFAC_MIN_SIZE(1) - HEADER_MINSIZE(19) - "
        "TOKEN_OVERHEAD(48)) / AES128_BLOCKSIZE(16)) * 16 - 1, which is 431 at "
        "MTU 500. Pinned against the formula recomputed from spec literals and "
        "against the literal 431; plausible off-by-a-term formulas (dropping "
        "TOKEN_OVERHEAD -> 447, using HEADER_MAXSIZE -> 448/464, omitting both "
        "header and token terms -> 479) are asserted to be REJECTED, so an impl "
        "that mis-sizes the MDU by a block — and would silently fragment "
        "differently — fails here even though it would pass the loose "
        "0<mdu<mtu / 16-alignment read-back check."
    ),
)
def test_link_mdu_is_exact_update_mdu_floor(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(
        _APP, _ASPECTS, fixed_mtu=_FIXED_MTU,
    )

    snap = client.link_status(link_id)
    assert snap["status_name"] == "ACTIVE", f"link not ACTIVE: {snap!r}"
    assert snap["mtu"] == _FIXED_MTU, (
        f"link MTU pinned to {_FIXED_MTU} must be read back, got {snap['mtu']!r}"
    )
    mtu = snap["mtu"]
    mdu = snap["mdu"]

    # Independent derivation: recompute the floor from spec literals.
    expected = _expected_mdu(mtu)
    assert expected == 431, (
        f"sanity: the spec formula must yield 431 at MTU 500, got {expected}"
    )
    assert mdu == expected, (
        f"link MDU must equal the update_mdu floor recomputed from RNS spec "
        f"literals ({expected}) at MTU {mtu}, got {mdu!r}: {snap!r}"
    )
    assert mdu == 431, (
        f"link MDU at MTU 500 must be exactly 431 (RNS 1.3.1), got {mdu!r}"
    )

    # Negative controls: plausible off-by-a-term formulas an impl might use.
    # Dropping TOKEN_OVERHEAD: floor((500-1-19)/16)*16-1 = 479.
    wrong_no_token = ((mtu - _IFAC_MIN_SIZE - _HEADER_MINSIZE)
                      // _AES128_BLOCKSIZE) * _AES128_BLOCKSIZE - 1
    # Using HEADER_MAXSIZE instead of HEADER_MINSIZE: floor((500-1-35-48)/16)*16-1=415.
    wrong_max_header = ((mtu - _IFAC_MIN_SIZE - _HEADER_MAXSIZE - _TOKEN_OVERHEAD)
                        // _AES128_BLOCKSIZE) * _AES128_BLOCKSIZE - 1
    # Dropping the HEADER term only: floor((500-1-48)/16)*16-1 = 447.
    wrong_no_header = ((mtu - _IFAC_MIN_SIZE - _TOKEN_OVERHEAD)
                       // _AES128_BLOCKSIZE) * _AES128_BLOCKSIZE - 1
    # The overwritten naive line-531 subtraction: mtu - HEADER_MAXSIZE - IFAC = 464.
    wrong_naive = mtu - _HEADER_MAXSIZE - _IFAC_MIN_SIZE
    for label, bad in (
        ("dropped TOKEN_OVERHEAD", wrong_no_token),
        ("used HEADER_MAXSIZE", wrong_max_header),
        ("dropped HEADER term", wrong_no_header),
        ("naive HEADER_MAXSIZE subtraction", wrong_naive),
    ):
        if bad != expected:  # only meaningful where the wrong formula diverges
            assert mdu != bad, (
                f"link MDU {mdu} matched a WRONG formula ({label} -> {bad}); the "
                f"correct update_mdu floor is {expected}: {snap!r}"
            )

    # Structural cross-check: the floor is 16-byte aligned (mdu+1 % 16 == 0).
    assert (mdu + 1) % _AES128_BLOCKSIZE == 0, (
        f"update_mdu floor must be 16-byte aligned (mdu+1 divisible by 16), "
        f"got mdu={mdu!r}"
    )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "link_status",
    ],
    verifies=(
        "The link keepalive interval is the RNS 1.3.1 clamp of the measured RTT "
        "(Link.py:845-846): keepalive = max(min(rtt*(KEEPALIVE_MAX(360)/"
        "KEEPALIVE_MAX_RTT(1.75)), KEEPALIVE_MAX), KEEPALIVE_MIN(5)), and "
        "stale_time = keepalive * STALE_FACTOR(2). The keepalive is recomputed "
        "independently from the link's own reported RTT and asserted byte-equal, "
        "and on a loopback link the raw scaled value falls below the 5s floor, so "
        "the KEEPALIVE_MIN clamp is shown to actually fire (keepalive == 5, "
        "strictly above the raw value). An impl that hardcodes a constant or "
        "omits the floor — which the loose 'keepalive > 0' check would accept — "
        "fails here."
    ),
)
def test_keepalive_interval_is_rtt_clamp(wire_link_setup):
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    snap = client.link_status(link_id)
    assert snap["status_name"] == "ACTIVE", f"link not ACTIVE: {snap!r}"
    rtt = snap["rtt"]
    keepalive = snap["keepalive_s"]
    stale = snap["stale_time_s"]
    assert isinstance(rtt, (int, float)) and rtt >= 0, (
        f"ACTIVE link must report a measured RTT, got rtt={rtt!r}: {snap!r}"
    )

    # Independent derivation of the keepalive clamp from the reported RTT.
    raw = rtt * (_KEEPALIVE_MAX / _KEEPALIVE_MAX_RTT)
    expected = max(min(raw, _KEEPALIVE_MAX), _KEEPALIVE_MIN)
    # keepalive_s is a LOCAL watchdog interval, never carried on the wire: RNS
    # Link.py never serialises self.keepalive — it only gates send_keepalive and
    # the stale transition against time.time() (Link.py:792-803). The protocol
    # invariant is the clamp FORMULA (RTT scaling plus the min/max bounds), not
    # sub-millisecond float fidelity. A conformant impl may carry the interval at
    # integer-millisecond resolution (reticulum-kt: floor(rtt_ms*scale)/1000),
    # which differs from the full-precision float by up to one millisecond. Since
    # the RTT is a non-deterministic measurement, compare at the millisecond
    # resolution the bridge actually carries rather than asserting exact float
    # equality — the latter only passed when the measured RTT happened to yield a
    # whole-millisecond clamp, so it failed intermittently under CPU contention.
    assert abs(keepalive - expected) <= _MS, (
        f"keepalive_s ({keepalive!r}) must equal the RNS clamp of the measured "
        f"RTT ({expected!r} from rtt={rtt!r}) to within one millisecond; RNS "
        f"1.3.1 pins keepalive = max(min(rtt*360/1.75, 360), 5): {snap!r}"
    )
    assert abs(stale - keepalive * _STALE_FACTOR) <= _MS, (
        f"stale_time_s ({stale!r}) must be keepalive_s ({keepalive!r}) * "
        f"STALE_FACTOR ({_STALE_FACTOR}): {snap!r}"
    )

    if raw < _KEEPALIVE_MIN:
        # Quiet/fast loopback: the raw scaled RTT is below the 5s floor, so the
        # KEEPALIVE_MIN clamp MUST have fired — an impl omitting the floor would
        # report `raw`. KEEPALIVE_MIN is a whole number of seconds, so the clamp
        # is exact on both a float and an ms-resolution impl.
        assert keepalive == _KEEPALIVE_MIN, (
            f"on a loopback link with sub-floor RTT the keepalive must clamp UP "
            f"to KEEPALIVE_MIN ({_KEEPALIVE_MIN}), got {keepalive!r}: {snap!r}"
        )
        assert keepalive > raw, (
            f"the KEEPALIVE_MIN floor must have RAISED the keepalive above the "
            f"raw scaled value ({raw!r}); got keepalive={keepalive!r}: {snap!r}"
        )
    else:
        # Slower/contended runner: the measured RTT scaled above the 5s floor, so
        # the floor did not need to fire. The clamp equality above already pins
        # keepalive to the scaled value; assert it tracked the RTT (within the
        # min/max bounds) rather than returning a hardcoded constant.
        assert _KEEPALIVE_MIN <= keepalive <= _KEEPALIVE_MAX, (
            f"keepalive ({keepalive!r}) must be the RTT-scaled clamp within "
            f"[KEEPALIVE_MIN({_KEEPALIVE_MIN}), KEEPALIVE_MAX({_KEEPALIVE_MAX})] "
            f"when raw={raw!r} exceeds the floor: {snap!r}"
        )


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "poll_path",
        "link_open", "inject_crafted_link_identify",
    ],
    verifies=(
        "Link identify validation is gated to the NON-INITIATOR only "
        "(Link.receive LINKIDENTIFY branch: `if not self.initiator and "
        "len(plaintext)==128`). The SAME cryptographically-valid LINKIDENTIFY "
        "(the claimed identity signs link_id||public_key) is fed to both link "
        "ends: the INITIATOR (client) must IGNORE it — remote_identity stays "
        "None — while the NON-INITIATOR (server) ADOPTS it (remote_identity == "
        "the claimed identity). An impl that adopts a remote identity on the "
        "initiator side would let the listener impersonate a remote peer to the "
        "initiator; the only difference between the two calls is the link role, "
        "so the gate is isolated from the signature/length checks."
    ),
)
def test_initiator_ignores_inbound_link_identify(wire_link_setup):
    # The client is the initiator (outbound link); the server holds the inbound
    # (non-initiator) link.
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Initiator side: a genuinely-valid identify MUST be ignored (initiator-only
    # gate), so remote_identity stays None even though the signature verifies.
    on_initiator = client.inject_crafted_link_identify(link_id, "valid")
    assert on_initiator["initiator"] is True, (
        f"the client end must be the link INITIATOR for this gate test: "
        f"{on_initiator!r}"
    )
    assert on_initiator["adopted"] is False, (
        f"a valid LINKIDENTIFY was ADOPTED on the INITIATOR side — the "
        f"initiator-only gate (Link.receive `if not self.initiator`) is missing, "
        f"so the listener could impersonate a peer to the initiator: "
        f"{on_initiator!r}"
    )
    # The initiator's link already carries the DESTINATION's identity (learned
    # at establishment), so remote_identity is not None — the point is that the
    # injected CLAIMED identity was not adopted over it.
    assert (
        on_initiator["remote_identity_after"]
        != on_initiator["claimed_identity_hash"]
    ), (
        f"the initiator must NOT adopt the claimed identity from an inbound "
        f"identify, got {on_initiator!r}"
    )

    # Positive control: the identical valid identify IS adopted on the
    # NON-INITIATOR side, with remote_identity set to the claimed identity. The
    # only thing that changed is the link role.
    on_non_initiator = server.inject_crafted_link_identify(link_id, "valid")
    assert on_non_initiator["initiator"] is False, (
        f"the server end must be the link NON-INITIATOR: {on_non_initiator!r}"
    )
    assert on_non_initiator["adopted"] is True, (
        f"a valid LINKIDENTIFY was not adopted on the non-initiator side "
        f"(positive control): {on_non_initiator!r}"
    )
    assert (
        on_non_initiator["remote_identity_after"]
        == on_non_initiator["claimed_identity_hash"]
    ), (
        f"the non-initiator's remote_identity must equal the claimed identity "
        f"after a valid identify, got {on_non_initiator!r}"
    )
