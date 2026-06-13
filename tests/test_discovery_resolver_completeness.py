"""Discovery / Resolver subsystem — destination-naming contracts.

The interface-discovery, blackhole-list, and management subsystems
(RNS Discovery.py, Transport.py) each publish to a *fixed, well-known*
RNS destination. A conformant implementation MUST address those control
destinations with byte-identical names, or its announces land on a
different 16-byte address and silently never reach a real RNS node:

  * interface discovery announces  -> rnstransport.discovery.interface
        (Discovery.APP_NAME="rnstransport" + aspects "discovery","interface";
         the receiver's InterfaceAnnounceHandler.aspect_filter is the same
         dotted string — Discovery.py:30,57-58,200)
  * blackhole list service          -> rnstransport.info.blackhole
        (Transport.blackhole_destination, Transport.py:261; the client
         recalls it via Destination.hash_from_name_and_identity, Discovery.py:751)
  * management / network instance    -> rnstransport.network
                                        rnstransport.network.instance.<hexhash>
        (Transport.network_destination / instance_destination, Transport.py:268-269)

These are the only black-box-observable parts of the discovery/blackhole/
mgmt contract reachable through the existing bridge surface: the
`destination_hash` command drives the real `RNS.Destination.hash`
(expand_name -> name_hash -> truncated_hash(name_hash+identity_hash)).
Everything else in the subsystem (msgpack info layout, LXStamper proof-of-work
stamps, receiver field validation, autoconnect, the /list request handler,
record persistence) needs a dedicated bridge command and is recorded as a
new-hook gap, not closed here.

ANCHOR (reference-vs-reference safe): the expected address is recomputed with
Python's stdlib `hashlib` SHA-256 — an INDEPENDENT path that never touches
RNS — over the literal dotted protocol name. RNS truncates the name hash to
`NAME_HASH_LENGTH = 80` bits (10 bytes) and the destination hash to
`TRUNCATED_HASHLENGTH = 128` bits (16 bytes); both are pinned here as spec
literals (Identity.py). A wrong app_name/aspect string, or a drift in the
truncation lengths or composition order, fails the assertion. Each rule also
carries a NEGATIVE control proving the address is specific to the exact name.
"""

import hashlib

from conformance import conformance_case


__category_title__ = "Discovery & Resolver Completeness"
__category_order__ = 33


# RNS spec literals (RNS.Identity, RNS 1.3.1).
_NAME_HASH_BYTES = 10   # NAME_HASH_LENGTH = 80 bits
_DEST_HASH_BYTES = 16   # TRUNCATED_HASHLENGTH = 128 bits

# A fixed, valid 64-byte Identity private key (32B X25519 || 32B Ed25519).
# Any concrete identity works; fixing it keeps the vectors reproducible.
_PRIV = (
    "856ae1d962caf4731dc9c9693719065ec01ea6a813de828ed12c889efd51374c"
    "75f6a90b1d711a4dbcd30a5f1d2109852ed69bde554118f3223331bfa1e07396"
)


def _expected_destination_hash(full_name, identity_hash_hex):
    """Independent (hashlib-only) re-derivation of RNS.Destination.hash.

    name_hash      = SHA256(full_name)[:10]
    destination    = SHA256(name_hash || identity_hash)[:16]

    This deliberately avoids every RNS code path so a reference that drifts
    from the documented composition is caught rather than confirmed.
    """
    # hashlib.new(...) (rather than hashlib.sha256(...)) keeps this an
    # independent stdlib digest without shadowing the bridge `sha256` command.
    name_hash = hashlib.new("sha256", full_name.encode("utf-8")).digest()[:_NAME_HASH_BYTES]
    identity_hash = bytes.fromhex(identity_hash_hex)
    return hashlib.new("sha256", name_hash + identity_hash).hexdigest()[: _DEST_HASH_BYTES * 2]


@conformance_case(
    commands=["identity_from_private_key", "destination_hash"],
    verifies=(
        "Interface-discovery announces address the control destination "
        "rnstransport.discovery.interface (Discovery.APP_NAME='rnstransport' + "
        "aspects 'discovery','interface'; InterfaceAnnounceHandler.aspect_filter "
        "is the same dotted name). RNS.Destination.hash for that identity + "
        "app_name + aspects equals an INDEPENDENT hashlib derivation "
        "SHA256(SHA256(name)[:10] || identity_hash)[:16]. A wrong aspect string "
        "('iface' instead of 'interface') or a wrong app_name yields a different "
        "16-byte address (negative control), so an impl that announces discovery "
        "to any other destination name fails."
    ),
)
def test_discovery_interface_destination_address(sut):
    ident = sut.execute("identity_from_private_key", private_key=_PRIV)
    idh = ident["hash"]

    expected = _expected_destination_hash("rnstransport.discovery.interface", idh)
    res = sut.execute(
        "destination_hash",
        identity_hash=idh,
        app_name="rnstransport",
        aspects=["discovery", "interface"],
    )
    assert res["destination_hash"] == expected, (
        f"discovery destination address {res['destination_hash']} != "
        f"independent SHA-256 derivation {expected}"
    )

    # Negative: a single-character aspect change must move the address.
    wrong_aspect = sut.execute(
        "destination_hash",
        identity_hash=idh,
        app_name="rnstransport",
        aspects=["discovery", "iface"],
    )
    assert wrong_aspect["destination_hash"] != expected

    # Negative: a wrong app_name must move the address.
    wrong_app = sut.execute(
        "destination_hash",
        identity_hash=idh,
        app_name="rnstransport2",
        aspects=["discovery", "interface"],
    )
    assert wrong_app["destination_hash"] != expected


@conformance_case(
    commands=["identity_from_private_key", "destination_hash"],
    verifies=(
        "The blackhole list service is published to rnstransport.info.blackhole "
        "(Transport.blackhole_destination = Destination(..., APP_NAME, 'info', "
        "'blackhole'); the client recalls it via "
        "Destination.hash_from_name_and_identity('rnstransport.info.blackhole', "
        "identity)). RNS.Destination.hash equals the INDEPENDENT hashlib "
        "derivation over that exact dotted name. A wrong aspect ('blackholes') "
        "yields a different address (negative control)."
    ),
)
def test_blackhole_publish_destination_address(sut):
    ident = sut.execute("identity_from_private_key", private_key=_PRIV)
    idh = ident["hash"]

    expected = _expected_destination_hash("rnstransport.info.blackhole", idh)
    res = sut.execute(
        "destination_hash",
        identity_hash=idh,
        app_name="rnstransport",
        aspects=["info", "blackhole"],
    )
    assert res["destination_hash"] == expected, (
        f"blackhole destination address {res['destination_hash']} != "
        f"independent SHA-256 derivation {expected}"
    )

    wrong = sut.execute(
        "destination_hash",
        identity_hash=idh,
        app_name="rnstransport",
        aspects=["info", "blackholes"],
    )
    assert wrong["destination_hash"] != expected


@conformance_case(
    commands=["identity_from_private_key", "destination_hash"],
    verifies=(
        "The management subsystem publishes two destinations under the network "
        "identity (Transport.py:268-269): the network destination "
        "rnstransport.network (aspects 'network') and the per-instance "
        "destination rnstransport.network.instance.<hexhash> (aspects 'network',"
        "'instance', hexrep(identity.hash, delimit=False)). Both RNS.Destination."
        "hash values match the INDEPENDENT hashlib derivation over the dotted "
        "name, and the instance address is distinct from the bare network "
        "address (negative control), pinning the lowercase-hex-suffix contract."
    ),
)
def test_mgmt_network_destination_addresses(sut):
    ident = sut.execute("identity_from_private_key", private_key=_PRIV)
    idh = ident["hash"]
    # hexrep(hash, delimit=False) is the lowercase, undelimited hex of the
    # 16-byte identity hash — exactly the identity_hash hex string here.
    hexhash = idh

    # Bare network destination.
    expected_net = _expected_destination_hash("rnstransport.network", idh)
    res_net = sut.execute(
        "destination_hash",
        identity_hash=idh,
        app_name="rnstransport",
        aspects=["network"],
    )
    assert res_net["destination_hash"] == expected_net, (
        f"network destination address {res_net['destination_hash']} != "
        f"independent SHA-256 derivation {expected_net}"
    )

    # Per-instance destination carries the hex identity hash as a 4th component.
    instance_name = f"rnstransport.network.instance.{hexhash}"
    expected_inst = _expected_destination_hash(instance_name, idh)
    res_inst = sut.execute(
        "destination_hash",
        identity_hash=idh,
        app_name="rnstransport",
        aspects=["network", "instance", hexhash],
    )
    assert res_inst["destination_hash"] == expected_inst, (
        f"instance destination address {res_inst['destination_hash']} != "
        f"independent SHA-256 derivation {expected_inst}"
    )

    # Negative: the instance destination must NOT collide with the bare
    # network destination — the hex suffix genuinely participates in the name.
    assert res_inst["destination_hash"] != res_net["destination_hash"]
