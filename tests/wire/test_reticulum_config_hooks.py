"""Reticulum instance/interface CONFIG conformance (the `reticulum_config`
subsystem).

These pin config-derived values RNS computes once, at `Reticulum.__init__` /
`__apply_config` / `_add_interface` time, that the ordinary wire harness never
surfaces. Each is read straight back off the live RNS objects (a static
accessor, or an attribute RNS set during config parse) and checked against an
EXTERNAL spec literal from the RNS source — never against the impl's own echo of
the config value.

Covered behaviours (with the RNS source the rule is anchored on):

  * ifac-signature-identifier — interface.ifac_signature is the Ed25519
    signature over full_hash(ifac_key) (Reticulum.py:916). Re-signing
    SHA-256(ifac_key) (full_hash IS SHA-256, Identity.py:366) via the existing
    ifac_compute reproduces it exactly; signing a DIFFERENT message does not.
  * ifac-size-defaults-and-config — TCP DEFAULT_IFAC_SIZE == 16
    (TCPInterface.py:77); a configured ifac_size (bits) divides by 8 when
    >= IFAC_MIN_SIZE*8 (==8), else floors back to DEFAULT_IFAC_SIZE
    (Reticulum.py:719-723, IFAC_MIN_SIZE=1).
  * const-minimum-bitrate — a configured bitrate below MINIMUM_BITRATE (==5)
    is ignored and the interface keeps its class BITRATE_GUESS
    (Reticulum.py:765-768; TCPInterface BITRATE_GUESS == 10_000_000).
  * rpc-auth-key — with no rpc_key configured, the RPC authkey is
    full_hash(transport_identity.private_key) == SHA-256(private_key)
    (Reticulum.py:347-348).
  * const-default-per-hop-timeout — Transport.first_hop_timeout with no known
    path returns exactly DEFAULT_PER_HOP_TIMEOUT (==6)
    (Transport.py:2697-2701, Reticulum.py:141).
  * probe-responder-config — respond_to_probes defaults OFF (Reticulum.py:257)
    and is flipped on by the config knob (:543-545).
  * implicit-proof-default — should_use_implicit_proof defaults ON
    (Reticulum.py:256) and is flipped off by use_implicit_proof=No (:555-558).
  * remote-management-acl — enable_remote_management toggles the flag
    (:528-530); remote_management_allowed hashes must be exactly
    TRUNCATED_HASHLENGTH//8 == 16 bytes (32 hex), else startup raises (:532-536).
  * shared-client-role-restrictions — a shared-instance local CLIENT forces
    transport / remote-management / probes all False regardless of intent
    (Reticulum.py:429-431).

Runs reference-vs-reference; the peers are independent bridge processes, so each
config value is the genuine result of RNS parsing that peer's config.
"""

import hashlib
import secrets

import pytest

from conformance import conformance_case
from bridge_client import BridgeError


__category_title__ = "Wire Interop"
__category_order__ = 18


# A well-formed remote-management ACL identity hash: exactly 16 bytes / 32 hex
# (RNS.Reticulum.TRUNCATED_HASHLENGTH//8 == 16).
_VALID_ACL_HASH = "00112233445566778899aabbccddeeff"
# 15 bytes / 30 hex — one byte short, must be rejected at startup.
_SHORT_ACL_HASH = "00112233445566778899aabbccddee"


@conformance_case(
    commands=["start_tcp_server", "ifac_signature", "ifac_compute", "sha256"],
    verifies=(
        "interface.ifac_signature is the Ed25519 signature over "
        "full_hash(ifac_key) (RNS.Reticulum.py:916, full_hash == SHA-256). "
        "Re-signing SHA-256(ifac_key) with the same live ifac_identity (via "
        "ifac_compute) reproduces ifac_signature byte-for-byte (positive); "
        "signing a DIFFERENT message — the raw ifac_key — does NOT match "
        "(negative), proving the signed payload is specifically full_hash("
        "ifac_key) and not arbitrary. A peer that signed the wrong material "
        "would publish an IFAC identifier no conformant peer could verify"
    ),
)
def test_ifac_signature_is_ed25519_over_full_hash_of_key(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="testnet", passphrase="testpass")

    sig = server.ifac_signature()
    ifac_key = sig["ifac_key"]

    # POSITIVE: full_hash IS SHA-256 (Identity.py:366); re-signing it with the
    # same live ifac_identity must reproduce the published ifac_signature.
    full_hash_of_key = hashlib.sha256(ifac_key).digest()
    resigned = server.ifac_compute(full_hash_of_key)
    assert resigned["signature"] == sig["ifac_signature"], (
        "ifac_signature is not the Ed25519 signature over full_hash(ifac_key): "
        f"got {sig['ifac_signature'].hex()}, re-signed {resigned['signature'].hex()}"
    )

    # NEGATIVE: signing a DIFFERENT message (the raw key, not its hash) must
    # NOT match — pins that the signed payload is specifically full_hash(key).
    wrong = server.ifac_compute(ifac_key)
    assert wrong["signature"] != sig["ifac_signature"], (
        "signing the raw ifac_key matched ifac_signature — the signature is "
        "not bound to full_hash(ifac_key) as RNS.Reticulum.py:916 requires"
    )


@conformance_case(
    commands=["start_tcp_server", "ifac_signature"],
    verifies=(
        "A TCPServerInterface's DEFAULT_IFAC_SIZE is 16 bytes "
        "(TCPInterface.py:77), so with no ifac_size config interface.ifac_size "
        "== 16 (positive). A configured ifac_size in BITS that is >= "
        "IFAC_MIN_SIZE*8 (==8) divides by 8: ifac_size=16 -> 2 "
        "(RNS.Reticulum.py:719-723). The two peers carry distinct ifac_size "
        "values, so neither is the other's echo"
    ),
)
def test_ifac_size_default_and_bit_divide(wire_peers):
    server, client = wire_peers
    server.start_tcp_server(network_name="neta", passphrase="pa")
    client.start_tcp_server(network_name="netb", passphrase="pb", ifac_size=16)

    s = server.ifac_signature()
    # POSITIVE: TCP default IFAC size is the spec literal 16.
    assert s["default_ifac_size"] == 16, (
        f"TCPInterface DEFAULT_IFAC_SIZE must be 16, got {s['default_ifac_size']}"
    )
    assert s["ifac_size"] == 16, (
        f"no-config ifac_size must default to DEFAULT_IFAC_SIZE (16), got {s['ifac_size']}"
    )

    c = client.ifac_signature()
    # POSITIVE: 16 bits / 8 == 2 (Reticulum.py:722). NEGATIVE relative to the
    # default: a configured value overrides the 16-byte default.
    assert c["ifac_size"] == 2, (
        f"ifac_size=16 (bits) must resolve to 2 bytes (//8), got {c['ifac_size']}"
    )
    assert c["ifac_size"] != s["ifac_size"], (
        "configured ifac_size did not override the per-type default"
    )


@conformance_case(
    commands=["start_tcp_server", "ifac_signature"],
    verifies=(
        "A configured ifac_size (bits) BELOW IFAC_MIN_SIZE*8 (==8) is rejected "
        "and floors back to DEFAULT_IFAC_SIZE: ifac_size=4 -> 16 "
        "(RNS.Reticulum.py:719-723, IFAC_MIN_SIZE==1). At the boundary "
        "ifac_size=8 -> 8//8 == 1 byte (positive). The sub-minimum value does "
        "NOT pass through as 0 (negative)"
    ),
)
def test_ifac_size_floor_and_minimum(wire_peers):
    server, client = wire_peers
    # 4 bits < IFAC_MIN_SIZE*8 (8) -> floored to DEFAULT_IFAC_SIZE (16).
    server.start_tcp_server(network_name="neta", passphrase="pa", ifac_size=4)
    # 8 bits == boundary -> 8//8 == 1 byte.
    client.start_tcp_server(network_name="netb", passphrase="pb", ifac_size=8)

    s = server.ifac_signature()
    assert s["ifac_size"] == s["default_ifac_size"] == 16, (
        f"sub-minimum ifac_size (4 bits) must floor to DEFAULT_IFAC_SIZE (16), "
        f"got {s['ifac_size']}"
    )
    assert s["ifac_size"] != 0, "sub-minimum ifac_size must NOT pass through as 0"

    c = client.ifac_signature()
    assert c["ifac_size"] == 1, (
        f"boundary ifac_size=8 bits must resolve to 1 byte (//8), got {c['ifac_size']}"
    )


@conformance_case(
    commands=["start_tcp_server", "interface_bitrate"],
    verifies=(
        "A configured bitrate below MINIMUM_BITRATE (==5 bps) is IGNORED and "
        "the interface keeps its class BITRATE_GUESS (TCPServerInterface "
        "BITRATE_GUESS == 10_000_000) (RNS.Reticulum.py:765-768): bitrate=3 -> "
        "10_000_000 (positive floor). A valid bitrate >= 5 IS applied: "
        "bitrate=1000 -> 1000 (negative control — the knob works when in range)"
    ),
)
def test_minimum_bitrate_floor(wire_peers):
    server, client = wire_peers
    server.start_tcp_server(network_name="", passphrase="", bitrate=3)
    client.start_tcp_server(network_name="", passphrase="", bitrate=1000)

    s = server.interface_bitrate()
    assert s["minimum_bitrate"] == 5, (
        f"MINIMUM_BITRATE must be 5, got {s['minimum_bitrate']}"
    )
    # POSITIVE: 3 < 5 so the config is rejected; interface keeps the guess.
    assert s["bitrate"] == s["bitrate_guess"] == 10_000_000, (
        f"sub-minimum bitrate (3) must be ignored, leaving BITRATE_GUESS "
        f"(10_000_000), got {s['bitrate']}"
    )

    c = client.interface_bitrate()
    # NEGATIVE control: a valid bitrate IS applied (so the floor above is a real
    # rejection, not the knob being a no-op).
    assert c["bitrate"] == 1000, (
        f"in-range bitrate (1000) must be applied, got {c['bitrate']}"
    )
    assert c["bitrate"] != c["bitrate_guess"], (
        "an applied in-range bitrate must differ from the class guess"
    )


@conformance_case(
    commands=["start_tcp_server", "rpc_authkey", "sha256"],
    verifies=(
        "With no rpc_key configured, the RPC control-channel authkey is derived "
        "as full_hash(transport_identity.private_key) == SHA-256(private_key), "
        "a 32-byte digest (RNS.Reticulum.py:347-348). Independently computing "
        "SHA-256 over the live private key reproduces rpc_key (positive); "
        "SHA-256 over a perturbed key, and the raw key itself, do NOT (negative)"
    ),
)
def test_default_rpc_authkey_is_sha256_of_private_key(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")

    rk = server.rpc_authkey()
    priv = rk["transport_private_key"]
    rpc_key = rk["rpc_key"]

    # POSITIVE: authkey == SHA-256(private_key) (full_hash is SHA-256).
    assert rpc_key == hashlib.sha256(priv).digest(), (
        "default rpc_key is not SHA-256(transport private key) as "
        "RNS.Reticulum.py:348 specifies"
    )
    assert len(rpc_key) == 32, f"SHA-256 digest must be 32 bytes, got {len(rpc_key)}"

    # NEGATIVE: a different input hashes differently, and the key is HASHED, not
    # the raw private material echoed back.
    assert rpc_key != hashlib.sha256(priv + b"\x00").digest(), (
        "rpc_key matched SHA-256 of a perturbed key — derivation is not "
        "over exactly the private key"
    )
    assert rpc_key != priv, "rpc_key must be a hash of the private key, not the key itself"


@conformance_case(
    commands=["start_tcp_server", "first_hop_timeout"],
    verifies=(
        "Transport.first_hop_timeout for a destination with NO known path "
        "returns exactly DEFAULT_PER_HOP_TIMEOUT (==6): no per-byte latency is "
        "known, so the latency term is absent (Transport.py:2697-2701, "
        "Reticulum.py:141). Two distinct unknown destinations both yield 6 "
        "(positive, spec literal); the value is the bare constant, not 0 and not "
        "a latency-augmented figure (negative)"
    ),
)
def test_default_per_hop_timeout_for_unknown_destination(wire_peers):
    server, _client = wire_peers
    server.start_tcp_server(network_name="", passphrase="")

    a = server.first_hop_timeout(secrets.token_bytes(16))
    b = server.first_hop_timeout(secrets.token_bytes(16))

    assert a["default_per_hop_timeout"] == 6, (
        f"DEFAULT_PER_HOP_TIMEOUT must be 6, got {a['default_per_hop_timeout']}"
    )
    # POSITIVE: unknown-path timeout is exactly the spec constant for both.
    assert a["timeout"] == 6 and b["timeout"] == 6, (
        f"unknown-destination first_hop_timeout must be DEFAULT_PER_HOP_TIMEOUT "
        f"(6), got {a['timeout']} / {b['timeout']}"
    )
    # NEGATIVE: it is the bare constant (no latency term added, not zeroed).
    assert a["timeout"] != 0, "first_hop_timeout must not be 0"
    assert a["timeout"] == a["default_per_hop_timeout"], (
        "with no known path the latency term must be absent, leaving exactly "
        "DEFAULT_PER_HOP_TIMEOUT"
    )


@conformance_case(
    commands=["start_tcp_server", "instance_posture"],
    verifies=(
        "respond_to_probes defaults OFF and use_implicit_proof defaults ON "
        "(RNS.Reticulum.py:256-257). A peer started with respond_to_probes=Yes "
        "and use_implicit_proof=No reports probe_destination_enabled()==True and "
        "should_use_implicit_proof()==False (positive, knobs applied at "
        ":543-558); a default peer reports probes False and implicit-proof True "
        "(negative control / default-on implicit proof)"
    ),
)
def test_probe_responder_and_implicit_proof_config(wire_peers):
    server, client = wire_peers
    server.start_tcp_server(
        network_name="", passphrase="",
        respond_to_probes=True, use_implicit_proof=False,
    )
    client.start_tcp_server(network_name="", passphrase="")

    s = server.instance_posture()
    c = client.instance_posture()

    # POSITIVE: knobs flip the process-wide statics.
    assert s["respond_to_probes"] is True, (
        "respond_to_probes=Yes must enable probe_destination_enabled()"
    )
    assert s["should_use_implicit_proof"] is False, (
        "use_implicit_proof=No must make should_use_implicit_proof() False"
    )
    # NEGATIVE/defaults: probes off, implicit proof on.
    assert c["respond_to_probes"] is False, (
        "respond_to_probes must default OFF (Reticulum.py:257)"
    )
    assert c["should_use_implicit_proof"] is True, (
        "should_use_implicit_proof must default ON (Reticulum.py:256)"
    )


@conformance_case(
    commands=["start_tcp_server", "instance_posture"],
    verifies=(
        "enable_remote_management toggles remote_management_enabled() and a "
        "well-formed (16-byte / 32-hex) ACL hash is admitted to "
        "Transport.remote_management_allowed (RNS.Reticulum.py:528-541); a "
        "default peer reports remote_management_enabled()==False with an empty "
        "ACL (negative). Remote management defaults OFF"
    ),
)
def test_remote_management_enable_and_acl(wire_peers):
    server, client = wire_peers
    server.start_tcp_server(
        network_name="", passphrase="",
        enable_remote_management=True,
        remote_management_allowed=[_VALID_ACL_HASH],
    )
    client.start_tcp_server(network_name="", passphrase="")

    s = server.instance_posture()
    c = client.instance_posture()

    # The ACL hash is exactly 16 bytes (TRUNCATED_HASHLENGTH//8).
    assert len(bytes.fromhex(_VALID_ACL_HASH)) == 16

    # POSITIVE: knob on, valid hash admitted.
    assert s["remote_management_enabled"] is True, (
        "enable_remote_management=Yes must enable remote_management_enabled()"
    )
    assert _VALID_ACL_HASH in s["remote_management_allowed"], (
        f"valid ACL hash not admitted: {s['remote_management_allowed']}"
    )
    # NEGATIVE/default: off, empty.
    assert c["remote_management_enabled"] is False, (
        "remote management must default OFF (Reticulum.py:255)"
    )
    assert c["remote_management_allowed"] == [], (
        "default ACL must be empty"
    )


@conformance_case(
    commands=["start_tcp_server", "instance_posture"],
    verifies=(
        "A remote_management_allowed identity hash that is NOT exactly "
        "TRUNCATED_HASHLENGTH//8 == 16 bytes (32 hex) is rejected at "
        "Reticulum startup with a ValueError (RNS.Reticulum.py:532-536): a "
        "30-hex (15-byte) hash fails the peer's start (negative). A 32-hex hash "
        "starts cleanly and is admitted to the ACL (positive control)"
    ),
)
def test_remote_management_acl_hash_length_validated(wire_peers):
    server, client = wire_peers

    # NEGATIVE: a short hash must abort RNS construction -> bridge error.
    with pytest.raises(BridgeError):
        server.start_tcp_server(
            network_name="", passphrase="",
            enable_remote_management=True,
            remote_management_allowed=[_SHORT_ACL_HASH],
        )

    # POSITIVE control: the correctly-sized hash starts cleanly and is admitted.
    client.start_tcp_server(
        network_name="", passphrase="",
        enable_remote_management=True,
        remote_management_allowed=[_VALID_ACL_HASH],
    )
    c = client.instance_posture()
    assert _VALID_ACL_HASH in c["remote_management_allowed"], (
        f"valid 16-byte ACL hash not admitted: {c['remote_management_allowed']}"
    )


@conformance_case(
    commands=["start_tcp_server", "start_local_client", "instance_posture"],
    verifies=(
        "A shared-instance local CLIENT forces transport_enabled, "
        "remote_management_enabled and probe_destination_enabled all False on "
        "attach, regardless of the master's posture (RNS.Reticulum.py:429-431). "
        "The master, started with transport on + respond_to_probes=Yes + "
        "enable_remote_management=Yes, reports all three True (positive); the "
        "attached client reports all three False and "
        "is_connected_to_shared_instance True (negative — the role override)"
    ),
)
def test_shared_local_client_forces_restricted_posture(wire_shared_3peer):
    local_client, master, _remote = wire_shared_3peer

    master.start_tcp_server(
        network_name="", passphrase="",
        share_instance=True, share_instance_type="tcp",
        respond_to_probes=True, enable_remote_management=True,
    )
    assert master.shared_instance_port is not None
    local_client.start_local_client(
        shared_instance_port=master.shared_instance_port,
        instance_control_port=master.instance_control_port,
        rpc_key=master.rpc_key,
    )

    m = master.instance_posture()
    c = local_client.instance_posture()

    # POSITIVE: the master's own knobs took effect.
    assert m["transport_enabled"] is True, "master should have transport enabled"
    assert m["respond_to_probes"] is True, "master respond_to_probes=Yes should apply"
    assert m["remote_management_enabled"] is True, (
        "master enable_remote_management=Yes should apply"
    )

    # NEGATIVE: the local client forces every privileged flag off on attach.
    assert c["is_connected_to_shared_instance"] is True, (
        "local client did not attach to the shared master"
    )
    assert c["transport_enabled"] is False, (
        "local client must force transport_enabled False (Reticulum.py:429)"
    )
    assert c["remote_management_enabled"] is False, (
        "local client must force remote_management_enabled False (Reticulum.py:430)"
    )
    assert c["respond_to_probes"] is False, (
        "local client must force probes off (Reticulum.py:431)"
    )
