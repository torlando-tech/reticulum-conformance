"""Single source of truth for IFAC key derivation shared by the pipe peers.

`integration/pipe_session.py` (the Python-side host) and
`integration/pipe_peer_local.py` (the in-repo peer subprocess) must derive the
SAME ifac_key / ifac_identity / ifac_size from a given (passphrase, netname) so
the two ends authenticate over an IFAC-masked link. Previously each file carried
its own copy of the derivation; if one ever changed (salt, length, hashing
step) they would silently diverge and the IFAC integration tests would fail to
authenticate with no clear root cause. Keeping the derivation here makes any
future change atomic across both peers.

Mirrors Python Reticulum._add_interface's IFAC setup exactly.
"""

# Both peers pin the same masked-link IFAC tag length, in bytes.
IFAC_SIZE = 16


def configure_ifac(RNS, iface, passphrase, netname):
    """Derive the IFAC key from (passphrase, netname) and apply it to ``iface``.

    No-op when both ``passphrase`` and ``netname`` are None (IFAC disabled) or
    when ``iface`` is None. Mirrors RNS ``Reticulum._add_interface``::

        ifac_origin      = full_hash(netname) || full_hash(passphrase)
                           (each term appended only when that value is set)
        ifac_origin_hash = full_hash(ifac_origin)
        ifac_key         = hkdf(64, ifac_origin_hash, salt=IFAC_SALT)
        iface.ifac_identity = Identity.from_bytes(ifac_key)
        iface.ifac_size  = 16

    A non-matching passphrase/netname derives a different key, so the peer's
    packets are rejected — which is exactly what the IFAC negative tests assert.
    """
    if passphrase is None and netname is None:
        return
    if iface is None:
        return

    ifac_origin = b""
    if netname is not None:
        ifac_origin += RNS.Identity.full_hash(netname.encode("utf-8"))
    if passphrase is not None:
        ifac_origin += RNS.Identity.full_hash(passphrase.encode("utf-8"))

    ifac_origin_hash = RNS.Identity.full_hash(ifac_origin)
    ifac_key = RNS.Cryptography.hkdf(
        length=64,
        derive_from=ifac_origin_hash,
        salt=RNS.Reticulum.IFAC_SALT,
        context=None,
    )

    iface.ifac_key = ifac_key
    iface.ifac_identity = RNS.Identity.from_bytes(ifac_key)
    iface.ifac_size = IFAC_SIZE
