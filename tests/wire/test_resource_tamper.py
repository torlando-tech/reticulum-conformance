"""Adversarial resource-integrity conformance (RESOURCE_PRF + part acceptance).

A Resource transfer has two cryptographic gates a non-conformant implementation
can silently get wrong (and then accept forged data / forged delivery):

  * SENDER proof validation (Resource.validate_proof) — the receiver returns a
    RESOURCE_PRF of exactly hash(32)||proof(32) == 64 bytes, where the trailing
    32 bytes are full_hash(data||hash). The sender concludes the transfer
    COMPLETE only if the proof is exactly 64 bytes AND its trailing 32 bytes
    equal the expected proof; anything else is dropped. A sender that concludes
    on any 64-byte blob accepts a forged delivery confirmation.

  * RECEIVER part acceptance (Resource.receive_part) — each incoming part is
    accepted only if its map hash (a hash of the part's own bytes) matches an
    entry in the expected hashmap window; a part with any other map hash (a
    corrupted-in-flight or forged part) is silently dropped. A receiver that
    reassembles whatever arrives accepts forged content.

The completeness eval (CONFORMANCE_COMPLETENESS.md §4) flagged that "no test ever
corrupts a part in flight, forges a map hash, or sends a wrong RESOURCE_PRF" —
the rejection branches were untested (gaps proof-validation-rules /
part-acceptance-window). These drive the real RNS Resource.validate_proof /
receive_part with crafted inputs via the adversarial injectors, with the genuine
artifact as the positive control.

Runs reference-vs-reference; no SUT binary required.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["resource-tamper"]


_REJECTED_PROOF_VARIANTS = (
    ("wrong_proof", "64 bytes but trailing 32 != expected_proof"),
    ("wrong_length_short", "32-byte proof (!= 64) — length gate"),
    ("wrong_length_long", "96-byte proof (!= 64) — length gate"),
)


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_crafted_resource_proof",
    ],
    verifies=(
        "A Resource SENDER concludes a transfer only on a valid RESOURCE_PRF: a "
        "64-byte proof whose trailing 32 bytes != expected_proof, and any "
        "wrong-length proof (32 or 96 bytes), are all dropped (resource not "
        "COMPLETE), while the genuine proof (random(32)||expected_proof) "
        "concludes it (positive control). A sender that accepts any 64-byte blob "
        "would treat a forged proof as a delivery confirmation"
    ),
)
def test_resource_proof_validation_rejects_forgeries(wire_link_setup):
    _server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    for variant, why in _REJECTED_PROOF_VARIANTS:
        res = client.inject_crafted_resource_proof(link_id, variant)
        assert res["concluded"] is False, (
            f"a {variant} RESOURCE_PRF ({why}) CONCLUDED the resource — the "
            f"sender accepted an invalid proof: {res!r}"
        )

    # Positive control: a genuine proof concludes the resource.
    ok = client.inject_crafted_resource_proof(link_id, "valid")
    assert ok["concluded"] is True, (
        f"a valid RESOURCE_PRF did not conclude the resource (positive control): "
        f"{ok!r}"
    )
    assert ok["status_name"] == "COMPLETE", f"valid proof: resource not COMPLETE: {ok!r}"
    assert ok["proof_len"] == 64, f"valid proof length must be 64, got {ok!r}"
