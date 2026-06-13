"""Reticulum instance CONFIG conformance — V2 gap closure (reticulum_config).

These extend test_reticulum_config_hooks.py with config-derived rules the prior
passes left open. Every value is read straight back off the live RNS objects a
genuine `RNS.Reticulum(configdir=...)` start produced (static accessor, class
attribute, or the actual Destination objects RNS registered) and checked against
an EXTERNAL RNS 1.3.1 spec literal / independent derivation — never the impl's
own echo of the config value.

Covered V2 gaps (RNS source each rule anchors on):

  * config-enable-transport-gate — transport defaults OFF when the
    enable_transport option is ABSENT entirely (Reticulum.py:253 default False;
    :497-499 flips True only on an explicit Yes). The prior pass always wrote the
    option; an impl that defaulted transport ON would rebroadcast announces it
    must not, yet still parse an explicit No.
  * config-panic-on-interface-error — panic_on_interface_error defaults OFF
    (Reticulum.py:280) and the knob flips it (:551-553).
  * config-rpc-key-invalid-hex-fallback — a malformed (non-hex) rpc_key is
    rejected and falls back to the SHA-256(private-key) default
    (Reticulum.py:489-495, :347-348); a valid custom hex key is used verbatim.
  * config-blackhole-and-discovery-source-hash-validation — blackhole_sources and
    interface_discovery_sources entries must be exactly TRUNCATED_HASHLENGTH//8
    == 16 bytes (32 hex) and valid hex, else startup raises; valid entries are
    deduplicated into the source lists (Reticulum.py:575-591).
  * probe-responder-config (protocol consequence) — respond_to_probes=Yes
    registers Transport.probe_destination as an IN/SINGLE rnstransport.probe
    destination under the transport identity, with PROVE_ALL and
    accepts_links(False) (Transport.py:396-401); default OFF leaves it None.
  * remote-management-acl (protocol consequence) — enable_remote_management
    registers Transport.remote_management_destination
    (rnstransport.remote.management) with /status and /path request handlers
    bound to ALLOW_LIST + the remote_management_allowed ACL (Transport.py:252-258).

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


# --- EXTERNAL spec literals (RNS 1.3.1) ---
PROVE_ALL = 0x23        # Destination.PROVE_ALL
ALLOW_LIST = 0x02       # Destination.ALLOW_LIST
NAME_HASH_BYTES = 10    # Identity.NAME_HASH_LENGTH // 8  (80 bits)
TRUNC_HASH_BYTES = 16   # Reticulum.TRUNCATED_HASHLENGTH // 8  (128 bits)
APP_NAME = "rnstransport"

# A well-formed identity hash: exactly 16 bytes / 32 hex.
_VALID_HASH = "00112233445566778899aabbccddeeff"
_VALID_HASH2 = "ffeeddccbbaa99887766554433221100"
# 15 bytes / 30 hex — one byte short, must be rejected at startup.
_SHORT_HASH = "00112233445566778899aabbccddee"
# 16 bytes' worth of characters but NOT valid hex — must be rejected.
_NONHEX_HASH = "zz112233445566778899aabbccddeeff"


def _full_hash(data: bytes) -> bytes:
    """RNS Identity.full_hash == SHA-256 (Identity.py:366)."""
    return hashlib.sha256(data).digest()


def _destination_hash(full_name: str, identity_hash: bytes) -> bytes:
    """Independent re-derivation of Destination.hash (Destination.py:116-130):
    full_hash(full_hash(name)[:10] + identity_hash)[:16]."""
    name_hash = _full_hash(full_name.encode("utf-8"))[:NAME_HASH_BYTES]
    return _full_hash(name_hash + identity_hash)[:TRUNC_HASH_BYTES]


def _path_hash(path: str) -> bytes:
    """Independent re-derivation of Identity.truncated_hash(path)."""
    return _full_hash(path.encode("utf-8"))[:TRUNC_HASH_BYTES]


@conformance_case(
    commands=["wire_start_tcp_server", "wire_instance_posture"],
    verifies=(
        "transport_enabled() defaults FALSE when the enable_transport option is "
        "ABSENT from the config entirely (RNS.Reticulum.py:253 default False; "
        ":497-499 only sets it True on an explicit Yes). A peer started with NO "
        "enable_transport line reports transport_enabled()==False (positive — the "
        "option-absent default-off posture); a peer that DOES set "
        "enable_transport=Yes reports True (negative control — the knob still "
        "works). An impl defaulting transport ON would rebroadcast announces it "
        "must not while passing every test that always writes the option"
    ),
)
def test_enable_transport_default_off_when_absent(wire_peers):
    server, client = wire_peers
    # No enable_transport line at all (enable_transport=None omits it).
    server.start_tcp_server(network_name="", passphrase="", enable_transport=None)
    # Explicit Yes (the default) — positive control that the knob flips it on.
    client.start_tcp_server(network_name="", passphrase="", enable_transport=True)

    s = server.instance_posture()
    c = client.instance_posture()

    assert s["transport_enabled"] is False, (
        "with enable_transport absent, transport must default OFF "
        "(Reticulum.py:253)"
    )
    assert c["transport_enabled"] is True, (
        "enable_transport=Yes must enable transport (negative control)"
    )


@conformance_case(
    commands=["wire_start_tcp_server", "wire_instance_posture"],
    verifies=(
        "panic_on_interface_error defaults OFF (RNS.Reticulum.py:280) and is "
        "flipped on by the config knob (:551-553). A peer started with "
        "panic_on_interface_error=Yes reports it True (positive); a default peer "
        "reports it False (negative control). This is the documented crash-vs-"
        "continue contract interface drivers rely on"
    ),
)
def test_panic_on_interface_error_knob_and_default(wire_peers):
    server, client = wire_peers
    server.start_tcp_server(
        network_name="", passphrase="", panic_on_interface_error=True
    )
    client.start_tcp_server(network_name="", passphrase="")

    s = server.instance_posture()
    c = client.instance_posture()

    assert s["panic_on_interface_error"] is True, (
        "panic_on_interface_error=Yes must set the flag (Reticulum.py:551-553)"
    )
    assert c["panic_on_interface_error"] is False, (
        "panic_on_interface_error must default OFF (Reticulum.py:280)"
    )


@conformance_case(
    commands=["wire_start_tcp_server", "wire_rpc_authkey", "sha256"],
    verifies=(
        "A MALFORMED (non-hex) rpc_key is rejected and the node falls back to the "
        "default authkey full_hash(transport_private_key) == SHA-256(private_key) "
        "(RNS.Reticulum.py:489-495 catches the bytes.fromhex failure and sets "
        "rpc_key=None; :347-348 then derives the default). The node does NOT "
        "crash and does NOT use the malformed string verbatim (positive). A "
        "VALID custom hex key is accepted verbatim and is NOT the SHA-256 default "
        "(negative control — the parse path really does honour a good key)"
    ),
)
def test_rpc_key_invalid_hex_falls_back_to_default(wire_peers):
    server, client = wire_peers
    # Malformed rpc_key -> rejected -> default SHA-256(private-key).
    server.start_tcp_server(
        network_name="", passphrase="", rpc_key="nothexkey00zz"
    )
    # Valid custom 32-byte hex key -> used verbatim.
    custom = secrets.token_hex(32)
    client.start_tcp_server(network_name="", passphrase="", rpc_key=custom)

    s = server.rpc_authkey()
    expected_default = hashlib.sha256(s["transport_private_key"]).digest()
    # POSITIVE: malformed key fell back to SHA-256(private key).
    assert s["rpc_key"] == expected_default, (
        "a malformed rpc_key must fall back to SHA-256(private key), not crash "
        "or be used verbatim"
    )

    c = client.rpc_authkey()
    # NEGATIVE control: a valid custom key is used verbatim, distinct from the
    # SHA-256 default — proving the malformed case really was a rejection.
    assert c["rpc_key"] == bytes.fromhex(custom), (
        "a valid custom rpc_key must be applied verbatim (Reticulum.py:491-492)"
    )
    assert c["rpc_key"] != hashlib.sha256(c["transport_private_key"]).digest(), (
        "a valid custom rpc_key must override the SHA-256 default"
    )


@conformance_case(
    commands=["wire_start_tcp_server", "wire_instance_posture"],
    verifies=(
        "blackhole_sources identity hashes are validated at startup: a "
        "wrong-length entry (30 hex / 15 bytes) aborts the start with a "
        "ValueError (RNS.Reticulum.py:578-579) — exactly "
        "TRUNCATED_HASHLENGTH//8 == 16 bytes is required (negative). Valid "
        "16-byte entries are admitted to Reticulum.blackhole_sources() and "
        "DEDUPLICATED — the same hash twice yields a single entry (:582) "
        "(positive)"
    ),
)
def test_blackhole_source_hash_length_validated_and_dedup(wire_peers):
    server, client = wire_peers
    # NEGATIVE: a short hash must abort RNS construction -> bridge error.
    with pytest.raises(BridgeError):
        server.start_tcp_server(
            network_name="", passphrase="", blackhole_sources=[_SHORT_HASH]
        )
    # POSITIVE: a valid hash supplied twice is admitted once (dedup).
    client.start_tcp_server(
        network_name="", passphrase="",
        blackhole_sources=[_VALID_HASH, _VALID_HASH],
    )
    c = client.instance_posture()
    assert c["blackhole_sources"] == [_VALID_HASH], (
        f"valid blackhole source must be admitted exactly once (dedup), got "
        f"{c['blackhole_sources']}"
    )


@conformance_case(
    commands=["wire_start_tcp_server", "wire_instance_posture"],
    verifies=(
        "A blackhole_sources entry that is the right LENGTH (32 hex) but not "
        "valid hexadecimal is rejected at startup with a ValueError "
        "(RNS.Reticulum.py:580-581, the bytes.fromhex guard) (negative). A "
        "well-formed hex entry of the same length starts cleanly and is admitted "
        "(positive control)"
    ),
)
def test_blackhole_source_invalid_hex_rejected(wire_peers):
    server, client = wire_peers
    # NEGATIVE: correct length, invalid hex -> ValueError at start.
    assert len(_NONHEX_HASH) == 32
    with pytest.raises(BridgeError):
        server.start_tcp_server(
            network_name="", passphrase="", blackhole_sources=[_NONHEX_HASH]
        )
    # POSITIVE control: a valid hex hash of the same length is admitted.
    client.start_tcp_server(
        network_name="", passphrase="", blackhole_sources=[_VALID_HASH2]
    )
    c = client.instance_posture()
    assert _VALID_HASH2 in c["blackhole_sources"], (
        f"valid hex blackhole source not admitted: {c['blackhole_sources']}"
    )


@conformance_case(
    commands=["wire_start_tcp_server", "wire_instance_posture"],
    verifies=(
        "interface_discovery_sources identity hashes share the identical guard: "
        "a wrong-length entry (30 hex) aborts the start with a ValueError "
        "(RNS.Reticulum.py:587-588) (negative); a valid 16-byte hash is admitted "
        "to Reticulum.interface_discovery_sources() (positive). Pins that the "
        "discovery-source list enforces the same hash-length contract as the "
        "remote-management ACL and blackhole sources"
    ),
)
def test_interface_discovery_source_hash_length_validated(wire_peers):
    server, client = wire_peers
    # NEGATIVE: short hash aborts the start.
    with pytest.raises(BridgeError):
        server.start_tcp_server(
            network_name="", passphrase="",
            interface_discovery_sources=[_SHORT_HASH],
        )
    # POSITIVE: a valid hash is admitted to the discovery-source list.
    client.start_tcp_server(
        network_name="", passphrase="",
        interface_discovery_sources=[_VALID_HASH],
    )
    c = client.instance_posture()
    assert c["interface_discovery_sources"] == [_VALID_HASH], (
        f"valid interface discovery source not admitted: "
        f"{c['interface_discovery_sources']}"
    )


@conformance_case(
    commands=["wire_start_tcp_server", "wire_mgmt_destinations", "sha256"],
    verifies=(
        "respond_to_probes=Yes does not merely flip a flag — it registers "
        "Transport.probe_destination as an IN/SINGLE destination named "
        "rnstransport.probe under the transport identity, with proof strategy "
        "PROVE_ALL (0x23) and accepts_links(False) (Transport.py:396-401). The "
        "destination hash is INDEPENDENTLY re-derived as "
        "full_hash(full_hash('rnstransport.probe')[:10] + transport_identity_"
        "hash)[:16] and must match the live destination (positive). A peer with "
        "probes OFF (default) has probe_destination == None (negative — the "
        "registration is gated by the knob, Transport.py:403)"
    ),
)
def test_probe_responder_registers_probe_destination(wire_peers, wire_pair):
    server, client = wire_peers
    server_impl, client_impl = wire_pair
    server.start_tcp_server(network_name="", passphrase="", respond_to_probes=True)
    client.start_tcp_server(network_name="", passphrase="")  # probes OFF (default)

    # The reference-to-reference pair pins the probe-responder registration live
    # (it passes below). Any kotlin peer lacks the wire_mgmt_destinations command
    # and registers no probe-responder destination — an architectural gap.
    if "kotlin" in (server_impl, client_impl):
        pytest.xfail(
            "reticulum-kt#kotlin-no-probe-remote-mgmt: no wire_mgmt_destinations "
            "and no probe-responder / remote-management destination registration "
            "(Transport.py:252-258/396-403)."
        )

    s = server.mgmt_destinations()
    c = client.mgmt_destinations()

    assert s["app_name"] == APP_NAME, (
        f"transport APP_NAME must be {APP_NAME!r}, got {s['app_name']!r}"
    )

    probe = s["probe"]
    assert probe["present"] is True, (
        "respond_to_probes=Yes must register Transport.probe_destination"
    )
    # Independent external derivation of the probe destination hash.
    ident = bytes.fromhex(s["transport_identity_hash"])
    expected = _destination_hash("rnstransport.probe", ident)
    assert bytes.fromhex(probe["hash"]) == expected, (
        f"probe destination hash must be the rnstransport.probe address under "
        f"the transport identity; got {probe['hash']}, derived {expected.hex()}"
    )
    # Spec-literal proof strategy and link policy.
    assert probe["proof_strategy"] == PROVE_ALL, (
        f"probe destination must use PROVE_ALL ({PROVE_ALL:#x}), got "
        f"{probe['proof_strategy']:#x}"
    )
    assert probe["accepts_links"] is False, (
        "probe destination must NOT accept links (accepts_links(False))"
    )
    assert probe["in_mgmt_destinations"] is True, (
        "probe destination must be tracked in Transport.mgmt_destinations"
    )

    # NEGATIVE: a default peer registers no probe destination at all.
    assert c["probe"]["present"] is False, (
        "probe destination must be None when respond_to_probes is off "
        "(Transport.py:403)"
    )


@conformance_case(
    commands=["wire_start_tcp_server", "wire_mgmt_destinations", "sha256"],
    verifies=(
        "enable_remote_management registers Transport.remote_management_"
        "destination as an IN/SINGLE rnstransport.remote.management destination "
        "under the transport identity, with /status and /path request handlers "
        "each bound to ALLOW_LIST (0x02) and the remote_management_allowed ACL "
        "(Transport.py:252-258). The destination hash and each handler's "
        "path_hash are INDEPENDENTLY re-derived (positive). A default peer "
        "registers no such destination (negative). Pins the ACL enforcement "
        "surface beyond the generic app-destination ALLOW_LIST machinery"
    ),
)
def test_remote_management_registers_destination_and_handlers(wire_peers, wire_pair):
    server, client = wire_peers
    server_impl, client_impl = wire_pair
    server.start_tcp_server(
        network_name="", passphrase="",
        enable_remote_management=True,
        remote_management_allowed=[_VALID_HASH],
    )
    client.start_tcp_server(network_name="", passphrase="")  # remote mgmt OFF

    # The reference-to-reference pair pins the remote-management registration live
    # (it passes below). Any kotlin peer lacks the wire_mgmt_destinations command
    # and registers no remote-management destination — an architectural gap.
    if "kotlin" in (server_impl, client_impl):
        pytest.xfail(
            "reticulum-kt#kotlin-no-probe-remote-mgmt: no wire_mgmt_destinations "
            "and no probe-responder / remote-management destination registration "
            "(Transport.py:252-258/396-403)."
        )

    s = server.mgmt_destinations()
    c = client.mgmt_destinations()

    rm = s["remote_management"]
    assert rm["present"] is True, (
        "enable_remote_management must register the remote management destination"
    )
    ident = bytes.fromhex(s["transport_identity_hash"])
    expected = _destination_hash("rnstransport.remote.management", ident)
    assert bytes.fromhex(rm["hash"]) == expected, (
        f"remote management destination hash mismatch: got {rm['hash']}, "
        f"derived {expected.hex()}"
    )
    assert rm["in_mgmt_destinations"] is True and rm["in_mgmt_hashes"] is True, (
        "remote management destination must be tracked in mgmt_destinations and "
        "mgmt_hashes (Transport.py:256-257)"
    )

    handlers = {h["path"]: h for h in rm["request_handlers"]}
    for path in ("/status", "/path"):
        assert path in handlers, f"missing remote-management handler {path}"
        h = handlers[path]
        # Independent path-hash derivation.
        assert bytes.fromhex(h["path_hash"]) == _path_hash(path), (
            f"{path} handler path_hash mismatch: {h['path_hash']}"
        )
        # ALLOW_LIST policy bound to the live ACL containing our hash.
        assert h["allow"] == ALLOW_LIST, (
            f"{path} handler must use ALLOW_LIST ({ALLOW_LIST:#x}), got "
            f"{h['allow']:#x}"
        )
        assert h["allowed_list_is_acl"] is True, (
            f"{path} handler's allowed_list must be the Transport ACL object"
        )
        assert _VALID_HASH in h["allowed_hashes"], (
            f"{path} handler ACL must contain the configured allowed hash; got "
            f"{h['allowed_hashes']}"
        )

    # NEGATIVE: a default peer has no remote management destination.
    assert c["remote_management"]["present"] is False, (
        "remote management destination must be absent when the knob is off"
    )
