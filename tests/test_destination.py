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
