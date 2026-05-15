"""Destination conformance tests.

Tests name hashing, destination hash computation, and packet hashing
by comparing SUT output against a reference implementation.
"""

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


# Note: packet_hash conformance lives in tests/test_packet.py
# (test_packet_hash_matches_across_impls). Removed from here when packet_pack
# was retired in favour of the honest packet_build command — the synthetic
# "pack arbitrary header fields + raw data" interface has no RNS entry point.
