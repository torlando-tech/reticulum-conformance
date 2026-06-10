"""Adversarial link-authentication forgery conformance (LINKIDENTIFY).

A link's INITIATOR may reveal its identity to the non-initiator with a
LINKIDENTIFY packet — `public_key(64) || signature(64)` over `link_id ||
public_key`, sent encrypted over the established link (Link.identify). The
NON-INITIATOR validates it (Link.receive's LINKIDENTIFY branch): it must be the
non-initiator, the decrypted plaintext must be exactly 128 bytes, and the
signature MUST verify against the claimed public key — otherwise the identity is
silently NOT adopted (remote_identity stays None). This is an authentication
primitive: apps use `link.get_remote_identity()` to decide who they are talking
to and gate access (request handlers, ALLOW_LIST).

The existing identify coverage only ever drives a *validly-signed* identify (the
ALLOW_LIST test rejects a valid identify from an *unlisted* identity — a policy
check, not a crypto check), so the signature-rejection branch was untested
(CONFORMANCE_COMPLETENESS.md §4 "forge a LINKIDENTIFY signature"; gap
identify-validation). The `wire_inject_crafted_link_identify` adversarial
injector crafts each forgery and runs it through the real link.receive, with a
genuinely-valid identify (adopted) as the positive control.

Runs reference-vs-reference; no SUT binary required.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["link-auth"]


# Each forgery and the validation branch it must trip on the non-initiator.
_REJECTED_VARIANTS = (
    ("forged_signature", "signature by the WRONG key — signature check"),
    ("wrong_signed_data", "valid key but signature over unrelated data — signature check"),
    ("wrong_length", "96-byte plaintext (!= 128) — length gate"),
)


@conformance_case(
    commands=[
        "start_tcp_server", "start_tcp_client", "listen", "announce", "poll_path",
        "link_open", "inject_crafted_link_identify",
    ],
    verifies=(
        "A link non-initiator REJECTS a forged LINKIDENTIFY and adopts only a "
        "cryptographically-valid one: a signature under the wrong key, a "
        "signature over unrelated data, and a wrong-length (96-byte, != 128) "
        "plaintext each leave remote_identity None (not adopted), while a genuine "
        "identify (claimed identity signs link_id||pubkey) is adopted "
        "(remote_identity == the claimed identity). An impl that sets "
        "remote_identity without verifying the signature is trivially "
        "impersonatable — any peer could claim any identity over an open link"
    ),
)
def test_link_identify_signature_validation(wire_link_setup):
    # The client is the initiator; the SERVER holds the inbound (non-initiator)
    # link whose LINKIDENTIFY validation is under test, so the injector runs on
    # the server.
    server, client, _dest_hash, link_id = wire_link_setup(_APP, _ASPECTS)

    # Negatives first (each leaves remote_identity None), so the positive control
    # adoption below can't be mistaken for leftover state.
    for variant, why in _REJECTED_VARIANTS:
        res = server.inject_crafted_link_identify(link_id, variant)
        assert res["initiator"] is False, (
            f"the link under test must be the non-initiator (server) side: {res!r}"
        )
        assert res["adopted"] is False, (
            f"a {variant} LINKIDENTIFY ({why}) was ADOPTED — the non-initiator "
            f"set remote_identity without verifying the signature: {res!r}"
        )
        assert res["remote_identity_after"] is None, (
            f"{variant}: remote_identity must stay None after a forged identify, "
            f"got {res!r}"
        )

    # Positive control: a genuine identify (claimed identity signs link_id||
    # public_key) is adopted, with remote_identity set to exactly that identity.
    ok = server.inject_crafted_link_identify(link_id, "valid")
    assert ok["adopted"] is True, (
        f"a valid LINKIDENTIFY was not adopted (positive control): {ok!r}"
    )
    assert ok["remote_identity_after"] == ok["claimed_identity_hash"], (
        f"remote_identity must equal the claimed identity after a valid "
        f"identify, got {ok!r}"
    )
