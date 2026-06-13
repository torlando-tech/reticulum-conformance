"""GROUP destination symmetric crypto conformance (Destination.py:533-653).

A Reticulum GROUP destination is symmetric: its "private key" is a single
shared Token key (Destination.create_keys -> Token.generate_key,
Destination.py:545-547) rather than an X25519/Ed25519 identity. Every member
that holds the same key can both encrypt (Destination.encrypt -> prv.encrypt,
:601-606) and decrypt (Destination.decrypt -> prv.decrypt, :645-651) for that
group. This is the primitive behind closed broadcast groups — the model
NomadNet/Sideband group conversations and any multi-reader feed build on.

Three protocol properties are asserted here, none of which a liveness smoke
test would catch:

  1. Cross-peer interop via the shared key. GROUP encryption is pure symmetric
     Token crypto — Destination.encrypt/decrypt operate ONLY on the shared key
     (prv.encrypt/prv.decrypt) and the destination hash is NOT part of the
     emitted Token. The hash is merely a local handle: in fact an inbound GROUP
     destination gets a fresh random identity aspect appended at construction
     (Destination.__init__:174-176), so two independent instances of the
     "same" group compute DIFFERENT addresses. Interop therefore rides entirely
     on the out-of-band-shared symmetric key: a member that loads the
     originator's key must decrypt the originator's ciphertext in either
     direction, regardless of each peer's local address. An impl that bound the
     ciphertext to the address (rather than the key alone) would diverge here.

  2. Fresh IV per encryption. Token.encrypt draws `iv = os.urandom(16)` every
     call (Token.py:89), so two encryptions of the SAME plaintext under the
     SAME key MUST differ. An impl that reused a static/zero IV (a real and
     catastrophic crypto bug) would emit identical ciphertext and fail here —
     while still round-tripping, so only this discriminating check catches it.

  3. Authenticated-failure, not garbage. Token.decrypt verifies the HMAC
     BEFORE decrypting (Token.py:102: `if not self.verify_hmac(token): raise`),
     and Destination.decrypt swallows that ValueError to return None
     (:647-651). So a member holding the WRONG key for the SAME group address
     must get None — never silently-wrong plaintext. The positive control
     (the originator decrypting the very same ciphertext -> exact plaintext)
     proves the ciphertext is well-formed; the ONLY variable between the two
     decrypts is the key. An impl that returned undecrypted/garbled bytes
     instead of authenticating would fail here.

The GROUP symmetric key is shared out-of-band (as RNS GROUP keys always are):
the tests carry it peer-to-peer in Python and NEVER send a packet over the
incidental TCP link. encrypt/decrypt are purely local Token operations on each
peer's real RNS.Destination.

Coverage note: group_create/group_encrypt/group_decrypt are fully wired in the
bridge (wire_tcp.py cmd_wire_group_*) and conftest (_WirePeer.group_*) but had
ZERO test callers prior to this file (CONFORMANCE_GAPS.md §4c, P1 #26).
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["group-destination"]
# Plaintext spanning the full byte range incl. NUL/0xFF, so PKCS7 padding and
# any byte-handling in the encrypt/decrypt path are exercised, not just ASCII.
_PLAINTEXT = b"group-shared-secret \x00\x01\xfe\xff payload \x00\x00 tail"


def _setup_independent_peers(server, client):
    """Bring up two independent RNS instances. The TCP link is incidental —
    GROUP crypto carries its key out-of-band and never sends a packet over it.
    """
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "group_create", "group_encrypt", "group_decrypt"],
    verifies="A real RNS GROUP destination is symmetric: peer A's group_create yields (destination_hash, key); peer B's group_create loading A's key reports the same key back byte-for-byte; ciphertext round-trips cross-peer in BOTH directions purely via the shared key (B.group_decrypt(A.group_encrypt(pt))==pt and A.group_decrypt(B.group_encrypt(pt))==pt, each peer using its own local destination handle), confirming the GROUP Token is bound to the key and not the address; and two encryptions of identical plaintext under the same key DIFFER (fresh per-message IV, Token.py os.urandom) yet each still decrypts to the exact plaintext on the peer",
)
def test_group_cross_peer_symmetric_roundtrip(wire_peers):
    """A creates a GROUP destination; B loads A's symmetric key and the two
    interoperate purely via that shared key: both-direction round-trip and
    non-deterministic (fresh-IV) ciphertext.
    """
    server, client = wire_peers
    _setup_independent_peers(server, client)

    # A originates the group and its symmetric key.
    a = server.group_create(app_name=_APP, aspects=_ASPECTS)
    a_hash, a_key = a["destination_hash"], a["key"]
    assert len(a_key) > 0, (
        f"{server.role_label}.group_create returned an empty symmetric key for "
        f"GROUP {a_hash.hex()}; a GROUP destination must hold a Token key."
    )

    # B builds its own group destination and loads A's key (shared out-of-band).
    # NOTE: a_hash != b_hash in general — an inbound GROUP destination appends a
    # fresh random identity aspect at construction (Destination.__init__:174),
    # so the address is per-peer. Interop rides on the shared KEY, not the hash;
    # each peer below uses its OWN hash purely as a local encrypt/decrypt handle.
    b = client.group_create(app_name=_APP, aspects=_ASPECTS, key=a_key)
    b_hash, b_key = b["destination_hash"], b["key"]

    # Loading A's key must report the same key back (no mangling on load).
    assert b_key == a_key, (
        f"{client.role_label} loaded A's GROUP key but reports a different "
        f"key back: loaded={a_key.hex()} reported={b_key.hex()}."
    )

    # A -> B: A encrypts, B (same key) decrypts to the exact plaintext.
    ct_ab = server.group_encrypt(a_hash, _PLAINTEXT)
    assert ct_ab != _PLAINTEXT, (
        f"{server.role_label}.group_encrypt returned the plaintext unchanged "
        f"for GROUP {a_hash.hex()} — GROUP encryption must produce a Token, "
        f"not a passthrough."
    )
    dec_b = client.group_decrypt(b_hash, ct_ab)
    assert dec_b == _PLAINTEXT, (
        f"{client.role_label} (holding A's GROUP key) failed to recover A's "
        f"plaintext: got {dec_b!r}, expected {_PLAINTEXT!r}. Cross-peer GROUP "
        f"decryption with the shared key must round-trip byte-exact."
    )

    # B -> A: symmetric the other way, proving the key works for both members.
    ct_ba = client.group_encrypt(b_hash, _PLAINTEXT)
    dec_a = server.group_decrypt(a_hash, ct_ba)
    assert dec_a == _PLAINTEXT, (
        f"{server.role_label} failed to recover B's plaintext: got {dec_a!r}, "
        f"expected {_PLAINTEXT!r}. GROUP crypto must be symmetric in both "
        f"directions for members sharing the key."
    )

    # Fresh IV: two encryptions of the SAME plaintext under the SAME key must
    # differ (Token.encrypt draws a random 16-byte IV each call). A static-IV
    # impl would still round-trip but emit identical ciphertext — caught here.
    ct1 = server.group_encrypt(a_hash, _PLAINTEXT)
    ct2 = server.group_encrypt(a_hash, _PLAINTEXT)
    assert ct1 != ct2, (
        f"Two GROUP encryptions of identical plaintext produced byte-identical "
        f"ciphertext on {server.role_label} ({ct1.hex()[:32]}...). Token "
        f"encryption must use a fresh random IV per message; a reused/static "
        f"IV is a forward-secrecy/replay-distinguishability break."
    )
    # ...yet both distinct ciphertexts must still decrypt to the same plaintext
    # on B — the difference is purely the IV, not the message.
    assert client.group_decrypt(b_hash, ct1) == _PLAINTEXT, (
        f"{client.role_label} could not decrypt the first IV-varied ciphertext."
    )
    assert client.group_decrypt(b_hash, ct2) == _PLAINTEXT, (
        f"{client.role_label} could not decrypt the second IV-varied ciphertext."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "group_create", "group_encrypt", "group_decrypt"],
    verifies="GROUP decryption with the WRONG key authenticates-and-fails rather than returning garbage: peer A encrypts plaintext under its GROUP key and A decrypting that SAME ciphertext recovers the exact plaintext (positive control proving the ciphertext is well-formed and key-decryptable); peer B generates a fresh, provably-different GROUP key, and B.group_decrypt of A's ciphertext returns None (Token HMAC verification fails before decryption -> Destination.decrypt returns None) — never silently-wrong bytes; the only variable between the succeeding and the None decrypt is the symmetric key",
)
def test_group_wrong_key_rejects_not_garbage(wire_peers):
    """A non-member (a different fresh key) must get None from group_decrypt of
    A's ciphertext — authenticated failure, not garbage.
    """
    server, client = wire_peers
    _setup_independent_peers(server, client)

    # A originates the group and encrypts a message under its key.
    a = server.group_create(app_name=_APP, aspects=_ASPECTS)
    a_hash, a_key = a["destination_hash"], a["key"]
    ct = server.group_encrypt(a_hash, _PLAINTEXT)

    # Positive control on the SAME ciphertext: the holder of the correct key
    # recovers the exact plaintext. This proves `ct` is a well-formed,
    # decryptable Token — so the None below is attributable solely to the key.
    assert server.group_decrypt(a_hash, ct) == _PLAINTEXT, (
        f"{server.role_label} could not decrypt its own GROUP ciphertext for "
        f"{a_hash.hex()}; the negative case below would be meaningless if the "
        f"ciphertext itself were malformed."
    )

    # B generates a FRESH, independent GROUP key (no load). The GROUP Token is
    # bound to the key, not any address, so the only thing distinguishing B from
    # a legitimate member is that its key differs from A's.
    b = client.group_create(app_name=_APP, aspects=_ASPECTS)
    b_hash, b_key = b["destination_hash"], b["key"]
    assert b_key != a_key, (
        f"Negative-case setup invalid: B's freshly generated GROUP key equals "
        f"A's ({a_key.hex()}); regenerate. The test requires a genuinely "
        f"different key to exercise the auth-failure path."
    )

    # The discriminating assertion: wrong key -> None (authenticated failure),
    # NOT garbage and NOT an exception leaking through. An impl that decrypted
    # without verifying the HMAC would hand back undecryptable/garbled bytes
    # here instead of None.
    dec = client.group_decrypt(b_hash, ct)
    assert dec is None, (
        f"{client.role_label}, holding the WRONG key for GROUP {b_hash.hex()}, "
        f"returned {dec!r} for A's ciphertext instead of None. GROUP decryption "
        f"must authenticate (Token HMAC) and fail closed; returning garbage "
        f"bytes for a wrong-key Token is a silent integrity break."
    )
