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
def test_lxmf_stamp_replay_across_message_ids_rejected(sut, reference):
    """A stamp generated for message_id A MUST NOT validate as proof for message_id B.

    LXMF stamps are per-message proof-of-work — the workblock is derived
    from the message_id (LXStamper.stamp_workblock(message_id, ...)),
    so a stamp valid for one message MUST NOT be acceptable as proof
    for a different message. Without this rejection, an attacker
    generates one expensive stamp and replays it on N cheap messages,
    bypassing the receiver's cost gate entirely.

    Closes coverage gap from lxmf-conformance#11.

    Reference: LXMessage.py:282 (`if self.stamp == truncated_hash(ticket+self.message_id)`)
    pins message_id in the ticket path; the PoW path validates against
    the message-specific workblock derived in LXStamper.stamp_valid().
    """
    msg_id_a = random_hex(32)
    msg_id_b = random_hex(32)
    assert msg_id_a != msg_id_b, (
        "test sanity: random_hex collided — vanishingly unlikely but "
        "stop here so the rest of the test isn't testing identity"
    )

    stamp_cost = 4    # very low cost for CI speed
    expand_rounds = 25  # minimal rounds for fast workblock generation

    # Both workblocks derived via reference. We separately test
    # cross-impl workblock determinism in test_lxmf_hash / pack_unpack;
    # this test focuses only on the per-message-id binding of stamps.
    wb_a = reference.execute(
        "lxmf_stamp_workblock", message_id=msg_id_a,
        expand_rounds=expand_rounds,
    )["workblock"]
    wb_b = reference.execute(
        "lxmf_stamp_workblock", message_id=msg_id_b,
        expand_rounds=expand_rounds,
    )["workblock"]
    assert wb_a != wb_b, (
        "test sanity: distinct message_ids must produce distinct workblocks; "
        "otherwise stamp_workblock isn't actually mixing in the message_id "
        "and the rest of the test is meaningless"
    )

    # Generate stamp for msg_id_A on the SUT
    gen = sut.execute(
        "lxmf_stamp_generate", message_id=msg_id_a, stamp_cost=stamp_cost,
        expand_rounds=expand_rounds,
    )
    stamp_a = gen["stamp"]
    assert stamp_a is not None, (
        f"SUT failed to generate a stamp at cost={stamp_cost} after "
        f"expand_rounds={expand_rounds}. Cannot test replay rejection "
        f"without a valid stamp to attempt the replay with."
    )

    # Positive control: stamp_a validates against wb_a on the SUT.
    # If this fails, the SUT's generate/validate are inconsistent
    # internally and the replay assertion below isn't meaningful.
    self_check = sut.execute(
        "lxmf_stamp_valid",
        stamp=stamp_a, target_cost=stamp_cost, workblock=wb_a,
    )
    assert self_check["valid"] is True, (
        f"SUT-generated stamp does not validate against its own "
        f"message_id's workblock on the SUT. The SUT's generate/"
        f"validate code paths disagree internally — separate bug from "
        f"the replay invariant under test."
    )

    # The actual invariant: stamp_a MUST NOT validate against wb_b.
    replay_attempt = sut.execute(
        "lxmf_stamp_valid",
        stamp=stamp_a, target_cost=stamp_cost, workblock=wb_b,
    )
    assert replay_attempt["valid"] is False, (
        f"SUT validated a stamp generated for message_id_A as proof "
        f"for message_id_B. This means stamp validation does not pin "
        f"message_id properly — an attacker can generate one expensive "
        f"stamp and replay it across N cheap messages, bypassing the "
        f"receiver's cost gate.\n"
        f"  msg_id_A: {msg_id_a}\n"
        f"  msg_id_B: {msg_id_b}\n"
        f"  stamp_a:  {stamp_a}\n"
        f"  result:   valid={replay_attempt['valid']}, value={replay_attempt.get('value')}"
    )


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
