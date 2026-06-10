"""GROUP-destination symmetric-key completeness tests (gap-closing).

These close two `crypto` gaps that the existing wire GROUP coverage
(``tests/wire/test_group_destination.py``) leaves only loosely pinned. That
file asserts only ``len(key) > 0`` for a generated GROUP key and never pins the
Token wire overhead, so a SUT that emitted a 32-byte (AES-128) GROUP key or
mis-sized Token framing would still pass. Every rule here anchors on a SPEC
LITERAL read straight out of the installed RNS 1.3.1 source tree, never on an
impl-vs-itself comparison:

  * GROUP create_keys default key length -> RNS Cryptography/Token.py:53-56
        (``generate_key(mode=AES_256_CBC)``: the default mode is AES-256, whose
        key is ``os.urandom(64)`` — 64 bytes, NOT the 32-byte AES-128 key).
        Destination.create_keys for a GROUP calls Token.generate_key() with the
        default mode, so a conformant GROUP key is exactly 64 bytes.
  * Token wire overhead is a constant 48 bytes -> RNS Cryptography/Token.py:50
        (``TOKEN_OVERHEAD = 48``) = IV(16) + HMAC-SHA256(32). A GROUP token is
        a bare symmetric Token (no ephemeral key — that 32-byte prefix exists
        only in the Identity ECIES composite), so its ciphertext length is
        EXACTLY ``len(PKCS7-padded plaintext) + 48``, independent of message.

The PKCS7-padded length is derived independently here (the RFC 5652 block rule:
``n -> n + (16 - n % 16)``, always adding a full block when already aligned),
not read back from the impl, so the overhead assertion is a true external
anchor rather than a tautology. Positive controls (cross-key round-trip) keep
the negatives from passing vacuously.
"""

from conformance import conformance_case


__category_title__ = "Wire Interop"
__category_order__ = 18


_APP = "conformance"
_ASPECTS = ["group-crypto-completeness"]


def _pkcs7_padded_len(n: int, block: int = 16) -> int:
    """RFC 5652 PKCS7 padded length: always append 1..block bytes (a full
    block when already aligned). This is the EXTERNAL anchor — the expected
    ciphertext body length before Token overhead, derived without the impl.
    """
    return n + (block - (n % block))


def _setup_independent_peers(server, client):
    """Two independent RNS instances; the TCP link is incidental (GROUP crypto
    carries its key out-of-band and never sends a packet over the link)."""
    port = server.start_tcp_server(network_name="", passphrase="")
    client.start_tcp_client(
        network_name="", passphrase="",
        target_host="127.0.0.1", target_port=port,
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "group_create", "group_encrypt", "group_decrypt"],
    verifies="A GROUP destination's auto-generated symmetric key is EXACTLY 64 "
    "bytes — the AES-256 default of RNS Token.generate_key (Token.py:53-56, "
    "default mode AES_256_CBC -> os.urandom(64)), NOT the 32-byte AES-128 key. "
    "The 64-byte key is the positive-control proof of usability: it round-trips "
    "a message cross-peer (peer B loading the key decrypts A's ciphertext to the "
    "exact plaintext). A SUT that defaulted GROUP keys to 32-byte AES-128 keys "
    "(which the reference Token would still accept) is caught by the length pin",
)
def test_group_default_key_is_64_byte_aes256(wire_peers):
    server, client = wire_peers
    _setup_independent_peers(server, client)

    a = server.group_create(app_name=_APP, aspects=_ASPECTS)
    a_hash, a_key = a["destination_hash"], a["key"]
    # Spec-literal anchor: AES-256 Token key default is 64 bytes (Token.py:55).
    assert len(a_key) == 64, (
        f"{server.role_label}.group_create produced a {len(a_key)}-byte GROUP "
        f"key; RNS Token.generate_key defaults to AES-256 (os.urandom(64))."
    )
    # Positive control: the 64-byte key is a real, usable Token key — B loads it
    # and decrypts A's ciphertext, so the length pin is over a working key.
    b = client.group_create(app_name=_APP, aspects=_ASPECTS, key=a_key)
    assert b["key"] == a_key, "loading A's 64-byte key must echo it back verbatim"
    pt = b"group-aes256-default \x00\xff probe"
    ct = server.group_encrypt(a_hash, pt)
    assert client.group_decrypt(b["destination_hash"], ct) == pt, (
        f"{client.role_label} could not round-trip A's ciphertext under the "
        f"shared 64-byte key — the length pin must be over a usable key."
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "group_create", "group_encrypt", "group_decrypt"],
    verifies="A GROUP Token's wire overhead is a constant 48 bytes over the "
    "PKCS7-padded plaintext — IV(16) + HMAC-SHA256(32) per RNS Token.py:50 "
    "(TOKEN_OVERHEAD = 48), with NO ephemeral-key prefix (that 32-byte prefix "
    "exists only in the Identity ECIES composite, not in a bare symmetric "
    "Token). For plaintexts of 0/1/16/40 bytes the ciphertext length is exactly "
    "the independently-derived PKCS7-padded length + 48 (i.e. 64/64/80/96 "
    "bytes); each still decrypts cross-peer to the exact plaintext (positive "
    "control). A SUT whose Token framing were off by a block would fragment at "
    "different sizes than its peers and is caught here",
)
def test_group_token_overhead_is_constant_48(wire_peers):
    server, client = wire_peers
    _setup_independent_peers(server, client)

    a = server.group_create(app_name=_APP, aspects=_ASPECTS)
    a_hash, a_key = a["destination_hash"], a["key"]
    b = client.group_create(app_name=_APP, aspects=_ASPECTS, key=a_key)
    b_hash = b["destination_hash"]

    for n in (0, 1, 16, 40):
        pt = bytes((i * 7 + 3) & 0xFF for i in range(n))  # covers 0x00..0xff
        ct = server.group_encrypt(a_hash, pt)
        expected = _pkcs7_padded_len(n) + 48  # IV(16) + HMAC(32), Token.py:50
        assert len(ct) == expected, (
            f"GROUP token for a {n}-byte plaintext is {len(ct)} bytes; expected "
            f"PKCS7-padded({_pkcs7_padded_len(n)}) + 48 Token overhead = "
            f"{expected}. Overhead must be a constant 16-byte IV + 32-byte HMAC "
            f"with no extra prefix."
        )
        # Positive control: the framed token still decrypts cross-peer exactly.
        assert client.group_decrypt(b_hash, ct) == pt, (
            f"{client.role_label} failed to decrypt the {n}-byte-plaintext token "
            f"— the overhead pin must be over a well-formed, decryptable Token."
        )
