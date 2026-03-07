"""LXMF conformance tests.

Tests LXMF message packing/unpacking, message hashing, and stamp
generation/validation by comparing SUT output against a reference
implementation.
"""

import pytest
from conftest import random_hex, assert_hex_equal


def test_lxmf_pack_unpack(sut, reference):
    dest = random_hex(16)
    src = random_hex(16)
    ts = 1700000000.0
    title = "48656c6c6f"  # "Hello" in hex
    content = "576f726c64"  # "World" in hex
    ref = reference.execute(
        "lxmf_pack",
        destination_hash=dest,
        source_hash=src,
        timestamp=ts,
        title=title,
        content=content,
    )
    res = sut.execute(
        "lxmf_pack",
        destination_hash=dest,
        source_hash=src,
        timestamp=ts,
        title=title,
        content=content,
    )
    assert_hex_equal(res["packed_payload"], ref["packed_payload"])
    assert_hex_equal(res["message_hash"], ref["message_hash"])
    # Unpack: construct full LXMF wire bytes = dest(16) + src(16) + sig(64) + packed_payload
    dummy_sig = "00" * 64  # 64 zero bytes for signature
    lxmf_bytes = dest + src + dummy_sig + ref["packed_payload"]
    ref_u = reference.execute("lxmf_unpack", lxmf_bytes=lxmf_bytes)
    res_u = sut.execute("lxmf_unpack", lxmf_bytes=lxmf_bytes)
    assert_hex_equal(res_u["destination_hash"], ref_u["destination_hash"])
    assert_hex_equal(res_u["source_hash"], ref_u["source_hash"])


def test_lxmf_hash(sut, reference):
    dest = random_hex(16)
    src = random_hex(16)
    ts = 1700000000.0
    title = random_hex(10)
    content = random_hex(20)
    ref = reference.execute(
        "lxmf_hash",
        destination_hash=dest,
        source_hash=src,
        timestamp=ts,
        title=title,
        content=content,
    )
    res = sut.execute(
        "lxmf_hash",
        destination_hash=dest,
        source_hash=src,
        timestamp=ts,
        title=title,
        content=content,
    )
    assert_hex_equal(res["message_hash"], ref["message_hash"])


@pytest.mark.slow
def test_lxmf_stamp_generate_validate(sut, reference):
    msg_id = random_hex(32)
    stamp_cost = 4  # Very low cost for speed in CI
    expand_rounds = 25  # Minimal rounds for fast workblock generation
    # First generate workblock from reference for validation
    ref_wb = reference.execute(
        "lxmf_stamp_workblock", message_id=msg_id,
        expand_rounds=expand_rounds,
    )
    workblock = ref_wb["workblock"]
    ref = reference.execute(
        "lxmf_stamp_generate", message_id=msg_id, stamp_cost=stamp_cost,
        expand_rounds=expand_rounds,
    )
    # Validate reference stamp with SUT
    res_v = sut.execute(
        "lxmf_stamp_valid",
        stamp=ref["stamp"],
        target_cost=stamp_cost,
        workblock=workblock,
    )
    assert res_v["valid"] is True
    # Generate with SUT and validate with reference
    res = sut.execute(
        "lxmf_stamp_generate", message_id=msg_id, stamp_cost=stamp_cost,
        expand_rounds=expand_rounds,
    )
    ref_v = reference.execute(
        "lxmf_stamp_valid",
        stamp=res["stamp"],
        target_cost=stamp_cost,
        workblock=workblock,
    )
    assert ref_v["valid"] is True
