"""Destination conformance tests.

Tests name hashing, destination hash computation, and packet hashing
by comparing SUT output against a reference implementation.
"""

import pytest

from bridge_client import BridgeError
from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Destination"
__category_order__ = 4


@conformance_case(
    commands=["name_hash"],
    verifies='RNS `name_hash` of `"lxmf.delivery"` (the canonical LXMF delivery destination) is byte-identical across impls',
)
def test_name_hash(sut, reference):
    ref = reference.execute("name_hash", name="lxmf.delivery")
    res = sut.execute("name_hash", name="lxmf.delivery")
    assert_hex_equal(res["hash"], ref["hash"])


@conformance_case(
    commands=["identity_from_private_key", "destination_hash"],
    verifies="RNS `destination_hash`: given an `identity_hash` + `app_name` + `aspects`, the 16-byte destination address (RNS.Destination.hash — expand_name -> name_hash -> truncated_hash(name_hash + identity_hash)) is byte-identical across impls",
)
def test_destination_hash(sut, reference):
    priv = random_hex(64)
    ref_id = reference.execute("identity_from_private_key", private_key=priv)
    ref = reference.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    res = sut.execute(
        "destination_hash",
        identity_hash=ref_id["hash"],
        app_name="lxmf",
        aspects=["delivery"],
    )
    assert_hex_equal(res["destination_hash"], ref["destination_hash"])


@conformance_case(
    commands=["identity_from_private_key", "destination_hash"],
    verifies="RNS forbids '.' in app_name and aspects (Destination.expand_name raises ValueError, because '.' is the reserved name-component separator): destination_hash on a dotted app_name OR a dotted aspect is rejected, while the dotless equivalent succeeds — so an impl that silently accepts dotted names (and would derive a different destination address) fails",
)
def test_destination_hash_rejects_dotted_names(sut):
    """A dot is the name-component separator in RNS destination names, so it is
    illegal inside an app_name or an aspect (Destination.expand_name). An impl
    that fails to reject it would hash a structurally different name and derive
    the wrong destination address, silently breaking interop. The positive
    control proves the rejection is specific to the dot, not a blanket failure.
    """
    priv = random_hex(64)
    ident = sut.execute("identity_from_private_key", private_key=priv)

    # Positive control: the dotless name builds a destination address.
    ok = sut.execute(
        "destination_hash",
        identity_hash=ident["hash"], app_name="lxmf", aspects=["delivery"],
    )
    assert len(bytes.fromhex(ok["destination_hash"])) == 16

    # Dotted app_name must be rejected.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_hash",
            identity_hash=ident["hash"], app_name="lx.mf", aspects=["delivery"],
        )

    # Dotted aspect must be rejected.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_hash",
            identity_hash=ident["hash"], app_name="lxmf", aspects=["de.livery"],
        )


# Note: packet_hash conformance lives in tests/test_packet.py
# (test_packet_hash_matches_across_impls). Removed from here when packet_pack
# was retired in favour of the honest packet_build command — the synthetic
# "pack arbitrary header fields + raw data" interface has no RNS entry point.


# ---------------------------------------------------------------------------
# Destination address derivation (Opus completeness gaps:
# dest-hash-derivation-no-identity, dest-expand-name-format, dest-type-bits-on-wire)
#
# These pin RNS.Destination.hash's composition by re-deriving the address an
# INDEPENDENT way (name_hash -> truncated_hash) and asserting it equals what RNS
# itself produced for a real Destination — two distinct code paths agreeing, not
# a field compared to itself.
# ---------------------------------------------------------------------------


@conformance_case(
    commands=["packet_build", "packet_unpack", "name_hash", "truncated_hash"],
    verifies="Identity-less (PLAIN) destination address = SHA-256(name_hash)[:16] with NO identity material mixed in (RNS.Destination.hash, identity=None): the 16-byte destination_hash RNS computed for a real PLAIN destination 'conformance.packet' equals truncated_hash(name_hash('conformance.packet')) re-derived independently — an impl that folds identity bytes (or a different digest) into a no-identity address diverges",
)
def test_dest_hash_no_identity_derivation(sut):
    # packet_build's PLAIN destination is RNS.Destination(None, OUT, PLAIN,
    # "conformance", "packet") -> expand_name == "conformance.packet".
    built = sut.execute(
        "packet_build", dest_type="plain", packet_type=0,
        context=0, context_flag=0, hops=0, data=random_hex(8),
    )
    rns_addr = built["destination_hash"]
    assert built["destination_type"] == 2, "PLAIN destination_type bits must be 2"

    # Independent derivation: name_hash of the dotted name, then truncated_hash.
    name_hash = sut.execute("name_hash", name="conformance.packet")["hash"]
    derived = sut.execute("truncated_hash", data=name_hash)["hash"]
    assert_hex_equal(rns_addr, derived,
                     "no-identity destination address != truncated_hash(name_hash)")
    assert len(bytes.fromhex(rns_addr)) == 16


@conformance_case(
    commands=["identity_from_private_key", "destination_hash", "name_hash", "truncated_hash"],
    verifies="Identity-bound destination address over a MULTI-aspect name = SHA-256(name_hash(app.a.b.c) || identity_hash)[:16]: RNS.Destination.hash for app_name='myapp', aspects=['alpha','beta','gamma'] equals the independently re-derived truncated_hash(name_hash('myapp.alpha.beta.gamma') || identity_hash), and reordering the aspects changes the address — pinning the dotted multi-aspect expansion AND the name_hash||identity_hash composition order",
)
def test_dest_hash_identity_bound_multiaspect_derivation(sut):
    idn = sut.execute("identity_from_private_key", private_key=random_hex(64))
    identity_hash = idn["hash"]
    app, aspects = "myapp", ["alpha", "beta", "gamma"]

    actual = sut.execute(
        "destination_hash", identity_hash=identity_hash, app_name=app, aspects=aspects,
    )["destination_hash"]

    name_hash = sut.execute("name_hash", name="myapp.alpha.beta.gamma")["hash"]
    material = name_hash + identity_hash  # hex concat == byte concat
    expected = sut.execute("truncated_hash", data=material)["hash"]
    assert_hex_equal(actual, expected,
                     "identity-bound multi-aspect address != truncated_hash(name_hash||identity_hash)")

    # Negative: aspect order is significant — the dotted name differs, so must the address.
    reordered = sut.execute(
        "destination_hash", identity_hash=identity_hash, app_name=app,
        aspects=list(reversed(aspects)),
    )["destination_hash"]
    assert reordered != actual, "reversing the aspects did not change the destination address"


@conformance_case(
    commands=["packet_build", "packet_unpack"],
    verifies="GROUP destination type encodes to flag bits 3-2 == 1 on the wire (SINGLE=0, GROUP=1, PLAIN=2, LINK=3): a real GROUP-destination packet built by RNS reports destination_type==1 and the other impl decodes raw[0] back to destination_type==1 — pins the GROUP wire code-point that the suite otherwise only used as an opaque hop-drop input",
)
def test_dest_type_bits_group_on_wire(sut, reference):
    for builder, unpacker, label in ((reference, sut, "ref->sut"), (sut, reference, "sut->ref")):
        built = builder.execute(
            "packet_build", dest_type="group", packet_type=0,
            context=0, context_flag=0, hops=0, data=random_hex(8),
        )
        assert built["destination_type"] == 1, f"{label}: builder GROUP bits != 1"
        # First-principles flags byte: (GROUP=1 << 2) | DATA=0, context_flag 0.
        assert built["flags"] == (1 << 2), f"{label}: GROUP DATA flags byte != 0x04"
        parsed = unpacker.execute("packet_unpack", raw=built["raw"])
        assert parsed["unpacked"] is True, f"{label}: GROUP packet unpack rejected"
        assert parsed["destination_type"] == 1, f"{label}: decoded GROUP bits != 1"
