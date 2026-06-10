"""Destination constructor / lifecycle conformance (Opus, gap-closing).

These tests drive RNS.Destination's construction guards and lifecycle methods
through new bridge hooks (destination_construct, destination_announce_attempt,
app_and_aspects_from_name, hash_from_name_and_identity, destination_expand_name,
destination_set_proof_strategy_raw, destination_rotate_ratchets,
destination_group_encrypt, destination_register_request_handler_validate,
destination_path_response_cache). Each assertion anchors on an INDEPENDENT
value — an RNS spec literal restated here, an error mandated by the RNS source,
or a re-derivation through a DIFFERENT command — never an impl-vs-itself field
comparison.

RNS source of truth: RNS/Destination.py (1.3.1).
"""

import pytest

from bridge_client import BridgeError
from conftest import random_hex, assert_hex_equal
from conformance import conformance_case


__category_title__ = "Destination"
__category_order__ = 4


# RNS spec literals (RNS.Destination), independently restated here.
_PROVE_NONE = 0x21
_PROVE_APP = 0x22
_PROVE_ALL = 0x23
_SINGLE = 0x00
_GROUP = 0x01
_PLAIN = 0x02
_LINK = 0x03
_IN = 0x11
_OUT = 0x12
_PR_TAG_WINDOW = 30      # Destination.PR_TAG_WINDOW
_NAME_HASH_LEN = 10      # Identity.NAME_HASH_LENGTH // 8
_TRUNCATED_HASHLEN = 16  # Reticulum.TRUNCATED_HASHLENGTH // 8


def _rand_aspects(prefix="hooks"):
    # A fresh aspect per invocation keeps each constructed destination unique,
    # so the long-lived bridge never hands back a reused destination.
    return [prefix, random_hex(4)]


@conformance_case(
    commands=["destination_construct", "name_hash"],
    verifies="RNS.Destination.__init__ IN/non-PLAIN/no-identity branch (Destination.py:160): RNS auto-generates an Identity and appends its hexhash as an extra aspect BEFORE computing name_hash, so name_hash = full_hash(expand_name(None, app, *(aspects+[identity.hexhash])))[:10]. Re-deriving that preimage independently through the separate `name_hash` command reproduces the constructed name_hash, while the preimage WITHOUT the auto aspect does not.",
)
def test_ctor_in_auto_identity_appends_aspect(sut):
    aspects = _rand_aspects()
    res = sut.execute(
        "destination_construct",
        direction="in", type="single", app_name="lxmf", aspects=aspects,
    )
    auto = res.get("auto_identity_hexhash")
    assert auto, "IN non-PLAIN no-identity construction must auto-generate an identity"

    # Independent derivation of the rule: the auto aspect (identity.hexhash) is
    # folded into the name_hash preimage. Feed the spec-defined dotted name
    # through the SEPARATE name_hash command.
    name_with_auto = ".".join(["lxmf"] + aspects + [auto])
    derived = sut.execute("name_hash", name=name_with_auto)
    assert_hex_equal(res["name_hash"], derived["hash"])

    # Negative control: the preimage WITHOUT the auto aspect yields a different
    # name_hash — proving the auto aspect genuinely changed the preimage.
    name_without = ".".join(["lxmf"] + aspects)
    derived_without = sut.execute("name_hash", name=name_without)
    assert res["name_hash"] != derived_without["hash"]

    # expand_name appends the trailing identity suffix too, so the full name
    # ends with ".<hexhash>.<hexhash>" (auto aspect + identity suffix).
    assert res["name"].endswith("." + auto + "." + auto)
    assert len(bytes.fromhex(res["name_hash"])) == _NAME_HASH_LEN


@conformance_case(
    commands=["destination_construct", "identity_from_private_key", "destination_hash"],
    verifies="RNS.Destination.__init__ (Destination.py:163) raises ValueError('Can't create outbound SINGLE destination without an identity') for OUT + non-PLAIN + no identity. Positive control: OUT + identity succeeds, and the constructed destination_hash matches the address independently re-derived through the `destination_hash` command from the identity hash.",
)
def test_ctor_out_requires_identity(sut):
    aspects = _rand_aspects()

    # Negative: OUT SINGLE without an identity is rejected by RNS.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_construct",
            direction="out", type="single", app_name="lxmf", aspects=aspects,
        )

    # Positive control: OUT SINGLE WITH an identity constructs, and its address
    # equals the one re-derived independently from the identity hash.
    priv = random_hex(64)
    ident = sut.execute("identity_from_private_key", private_key=priv)
    res = sut.execute(
        "destination_construct",
        direction="out", type="single", app_name="lxmf", aspects=aspects,
        identity_private_key=priv,
    )
    assert res["direction"] == _OUT
    derived = sut.execute(
        "destination_hash",
        identity_hash=ident["hash"], app_name="lxmf", aspects=aspects,
    )
    assert_hex_equal(res["destination_hash"], derived["destination_hash"])


@conformance_case(
    commands=["destination_construct"],
    verifies="RNS.Destination.__init__ (Destination.py:166) raises TypeError('Selected destination type PLAIN cannot hold an identity') when a PLAIN destination is given an identity. Positive control: PLAIN with no identity constructs (type bits == 0x02).",
)
def test_plain_cannot_hold_identity(sut):
    aspects = _rand_aspects()

    # Negative: PLAIN + identity is rejected.
    priv = random_hex(64)
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_construct",
            direction="in", type="plain", app_name="lxmf", aspects=aspects,
            identity_private_key=priv,
        )

    # Positive control: PLAIN with no identity constructs.
    res = sut.execute(
        "destination_construct",
        direction="in", type="plain", app_name="lxmf", aspects=aspects,
    )
    assert res["type"] == _PLAIN
    assert "auto_identity_hexhash" not in res  # PLAIN never gets an auto identity


@conformance_case(
    commands=["destination_construct"],
    verifies="RNS.Destination.__init__ (Destination.py:148-149) guards type and direction against Destination.types == [0x00,0x01,0x02,0x03] and Destination.directions == [0x11,0x12], raising ValueError for an out-of-range value. Positive control: valid SINGLE/IN constructs.",
)
def test_ctor_type_direction_validation(sut):
    # Out-of-range type rejected.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_construct",
            direction="in", type=0x99, app_name="lxmf", aspects=_rand_aspects(),
        )
    # Out-of-range direction rejected.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_construct",
            direction=0x99, type="single", app_name="lxmf", aspects=_rand_aspects(),
        )
    # Positive control: valid SINGLE/IN constructs with the spec type/direction bits.
    res = sut.execute(
        "destination_construct",
        direction="in", type="single", app_name="lxmf", aspects=_rand_aspects(),
    )
    assert res["type"] == _SINGLE and res["direction"] == _IN


@conformance_case(
    commands=["destination_announce_attempt"],
    verifies="RNS.Destination.announce (Destination.py:251-256) raises TypeError('Only SINGLE destination types can be announced') for GROUP/PLAIN/LINK and TypeError('Only IN destination types can be announced') for OUT. Positive control: IN SINGLE announces (send=False) successfully.",
)
def test_announce_only_single_in(sut):
    # Positive: IN SINGLE announce succeeds.
    ok = sut.execute(
        "destination_announce_attempt",
        direction="in", type="single", app_name="lxmf", aspects=_rand_aspects(),
    )
    assert ok["ok"] is True

    # Negative: non-SINGLE types cannot be announced.
    for t in ("group", "plain", "link"):
        with pytest.raises(BridgeError):
            sut.execute(
                "destination_announce_attempt",
                direction="in", type=t, app_name="lxmf", aspects=_rand_aspects(),
            )

    # Negative: an OUT SINGLE (with identity) cannot be announced.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_announce_attempt",
            direction="out", type="single", app_name="lxmf",
            aspects=_rand_aspects(), identity_private_key=random_hex(64),
        )


@conformance_case(
    commands=["app_and_aspects_from_name", "hash_from_name_and_identity",
              "identity_from_private_key", "destination_hash"],
    verifies="RNS.Destination.app_and_aspects_from_name (Destination.py:131) splits a dotted full name into (first component = app_name, remaining components = aspects). hash_from_name_and_identity round-trips the name back to the same 16-byte address that `destination_hash` derives independently from the split app_name/aspects + identity hash.",
)
def test_name_split_and_hash_round_trip(sut):
    full = "lxmf.delivery.inbox"
    split = sut.execute("app_and_aspects_from_name", full_name=full)
    # Spec rule: first dotted component is the app name, the rest are aspects.
    assert split["app_name"] == "lxmf"
    assert split["aspects"] == ["delivery", "inbox"]

    priv = random_hex(64)
    ident = sut.execute("identity_from_private_key", private_key=priv)

    from_name = sut.execute(
        "hash_from_name_and_identity", full_name=full, identity_hash=ident["hash"],
    )
    # Independent derivation through the separate destination_hash command from
    # the split components — the full-name path must reach the same address.
    from_parts = sut.execute(
        "destination_hash",
        identity_hash=ident["hash"], app_name="lxmf", aspects=["delivery", "inbox"],
    )
    assert_hex_equal(from_name["destination_hash"], from_parts["destination_hash"])
    assert len(bytes.fromhex(from_name["destination_hash"])) == _TRUNCATED_HASHLEN


@conformance_case(
    commands=["destination_expand_name", "identity_from_private_key"],
    verifies="RNS.Destination.expand_name (Destination.py:96-110) appends '.' + identity.hexhash to the dotted app/aspects join when given an identity, and omits it when identity is None. identity.hexhash == identity.hash.hex(), so the suffix is independently pinned to the identity hash from `identity_from_private_key`.",
)
def test_expand_name_identity_suffix(sut):
    priv = random_hex(64)
    ident = sut.execute("identity_from_private_key", private_key=priv)

    with_id = sut.execute(
        "destination_expand_name",
        app_name="lxmf", aspects=["delivery"], identity_private_key=priv,
    )
    # The trailing suffix is exactly the identity hash hex (independent anchor).
    assert with_id["name"] == "lxmf.delivery." + ident["hash"]

    without_id = sut.execute(
        "destination_expand_name", app_name="lxmf", aspects=["delivery"],
    )
    # No identity -> bare dotted join, no suffix.
    assert without_id["name"] == "lxmf.delivery"


@conformance_case(
    commands=["destination_set_proof_strategy_raw"],
    verifies="RNS.Destination.set_proof_strategy (Destination.py:367) raises TypeError('Unsupported proof strategy') for any value not in Destination.proof_strategies == [0x21,0x22,0x23]. Positive controls: each of PROVE_NONE/PROVE_APP/PROVE_ALL is accepted and stored.",
)
def test_proof_strategy_validation(sut):
    # Positive controls: all three valid strategies accepted and reflected.
    for strat in (_PROVE_NONE, _PROVE_APP, _PROVE_ALL):
        res = sut.execute(
            "destination_set_proof_strategy_raw",
            direction="in", type="single", app_name="lxmf",
            aspects=_rand_aspects(), strategy_value=strat,
        )
        assert res["proof_strategy"] == strat

    # Negative: a value outside the proof_strategies set is rejected by RNS.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_set_proof_strategy_raw",
            direction="in", type="single", app_name="lxmf",
            aspects=_rand_aspects(), strategy_value=0x99,
        )


@conformance_case(
    commands=["destination_construct"],
    verifies="RNS.Destination.__init__ (Destination.py:144) sets self.proof_strategy = Destination.PROVE_NONE (0x21) on construction. A freshly constructed destination reports proof_strategy == 0x21.",
)
def test_proof_strategy_defaults_to_none(sut):
    res = sut.execute(
        "destination_construct",
        direction="in", type="single", app_name="lxmf", aspects=_rand_aspects(),
    )
    assert res["proof_strategy"] == _PROVE_NONE


@conformance_case(
    commands=["destination_rotate_ratchets"],
    verifies="RNS.Destination.rotate_ratchets (Destination.py:227-239) raises SystemError when self.ratchets is None — i.e. enable_ratchets was never called. Positive control: after enable_ratchets, self.ratchets is non-None and rotation succeeds.",
)
def test_rotate_ratchets_requires_enabled(sut):
    # Negative: rotating without enabling ratchets is rejected.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_rotate_ratchets",
            direction="in", type="single", app_name="lxmf", aspects=_rand_aspects(),
        )

    # Positive control: with ratchets enabled, rotation succeeds.
    res = sut.execute(
        "destination_rotate_ratchets",
        direction="in", type="single", app_name="lxmf",
        aspects=_rand_aspects(), enable=True,
    )
    assert res["rotated"] is True
    assert res["has_ratchets"] is True


@conformance_case(
    commands=["destination_group_encrypt"],
    verifies="RNS.Destination.encrypt GROUP path (Destination.py:608-612) raises ValueError('No private key held by GROUP destination') when no symmetric Token key was created/loaded. Positive control: after create_keys(), encryption succeeds and decrypt() recovers the plaintext (an external invertibility anchor), with ciphertext != plaintext.",
)
def test_group_destination_requires_key(sut):
    plaintext = b"group-secret-payload".hex()

    # Negative: GROUP encrypt with no key is rejected.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_group_encrypt",
            app_name="lxmf", aspects=_rand_aspects(), plaintext=plaintext,
        )

    # Positive control: with a created key, encrypt succeeds and round-trips.
    res = sut.execute(
        "destination_group_encrypt",
        app_name="lxmf", aspects=_rand_aspects(), plaintext=plaintext,
        create_keys=True,
    )
    assert res["has_key"] is True
    assert res["ciphertext"] != plaintext               # actually encrypted
    assert_hex_equal(res["roundtrip"], plaintext)        # invertible


@conformance_case(
    commands=["destination_register_request_handler_validate"],
    verifies="RNS.Destination.register_request_handler (Destination.py:384-386) raises ValueError for an empty path ('Invalid path specified'), a non-callable response_generator ('Invalid response generator specified'), and an allow policy outside request_policies == [0x00,0x01,0x02] ('Invalid request policy'). Positive control: a valid registration stores one handler.",
)
def test_request_handler_registration_validation(sut):
    # Positive control: a fully valid registration succeeds.
    ok = sut.execute(
        "destination_register_request_handler_validate",
        direction="in", type="single", app_name="lxmf", aspects=_rand_aspects(),
        path="/echo",
    )
    assert ok["registered"] is True
    assert ok["handler_count"] == 1

    # Negative: empty path.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_register_request_handler_validate",
            direction="in", type="single", app_name="lxmf",
            aspects=_rand_aspects(), path="",
        )
    # Negative: non-callable response generator.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_register_request_handler_validate",
            direction="in", type="single", app_name="lxmf",
            aspects=_rand_aspects(), generator_valid=False,
        )
    # Negative: allow policy outside the request_policies set.
    with pytest.raises(BridgeError):
        sut.execute(
            "destination_register_request_handler_validate",
            direction="in", type="single", app_name="lxmf",
            aspects=_rand_aspects(), allow=0x99,
        )


@conformance_case(
    commands=["destination_path_response_cache"],
    verifies="RNS.Destination.announce path-response caching (Destination.py:267-280): a second announce(path_response=True, tag=...) within PR_TAG_WINDOW (== 30s) reuses the cached announce_data (path_responses[tag]) verbatim, while an announce after the entry has aged past PR_TAG_WINDOW is evicted and rebuilt with fresh announce_data. The path_response context is RNS.Packet.PATH_RESPONSE.",
)
def test_path_response_announce_caching(sut):
    tag = random_hex(8)

    # Cache hit: zero time advance -> the second announce reuses cached data.
    hit = sut.execute(
        "destination_path_response_cache",
        direction="in", type="single", app_name="lxmf", aspects=_rand_aspects(),
        tag=tag, advance_seconds=0,
    )
    assert hit["pr_tag_window"] == _PR_TAG_WINDOW   # spec literal pin
    assert hit["first_is_path_response"] is True
    assert hit["reused"] is True
    assert hit["first_announce_data"] == hit["second_announce_data"]

    # Eviction: advancing past PR_TAG_WINDOW evicts the entry; the rebuilt
    # announce_data differs (fresh random_hash), so it is NOT reused.
    evict = sut.execute(
        "destination_path_response_cache",
        direction="in", type="single", app_name="lxmf", aspects=_rand_aspects(),
        tag=tag, advance_seconds=_PR_TAG_WINDOW + 1,
    )
    assert evict["reused"] is False
    assert evict["first_announce_data"] != evict["second_announce_data"]
