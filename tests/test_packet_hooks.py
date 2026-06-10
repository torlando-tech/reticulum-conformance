"""Packet pack/header/MDU/resend conformance (Opus, gap-closing).

These tests drive RNS.Packet construction and re-pack semantics through new
bridge hooks (packet_build_raw_header2, packet_resend_observe) plus the existing
packet_constants reader. Each assertion anchors on an INDEPENDENT value — an RNS
spec literal restated here, an error mandated by the RNS source, or an
independent arithmetic re-derivation — never an impl-vs-itself field comparison.

RNS source of truth: RNS/Packet.py + RNS/Reticulum.py + RNS/Identity.py (1.3.1).
"""

from conformance import conformance_case


__category_title__ = "Packet"
__category_order__ = 6


# RNS spec literals (Reticulum.py / Identity.py / Packet.py), independently
# restated here as the external ground truth — NOT read from the impl.
_MTU = 500
_HEADER_MINSIZE = 19          # 2 + 1 + TRUNCATED_HASHLENGTH//8(16)
_HEADER_MAXSIZE = 35          # 2 + 1 + (TRUNCATED_HASHLENGTH//8)*2(32)
_IFAC_MIN_SIZE = 1
_MDU = 464                    # MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
_ENCRYPTED_MDU = 383
_TOKEN_OVERHEAD = 48
_KEYSIZE = 512
_AES128_BLOCKSIZE = 16
_HEADER_2 = 1                 # RNS.Packet.HEADER_2 wire value
_SINGLE = 0x00               # RNS.Destination.SINGLE destination-type bits


# RNS.Packet.pack's own IOError text for a HEADER_2 with no transport id
# (Packet.py:228). Restated as the external literal a conformant impl must emit.
_HEADER2_NO_TID_MSG = "Packet with header type 2 must have a transport ID"


@conformance_case(
    commands=["packet_build_raw_header2", "packet_unpack", "identity_random_hash"],
    verifies=(
        "RNS.Packet.pack refuses a HEADER_2 packet with no transport id: packing "
        "an ANNOUNCE HEADER_2 with transport_id omitted raises RNS's own IOError "
        "'Packet with header type 2 must have a transport ID' (Packet.py:228) — "
        "surfaced by the hook WITHOUT a harness pre-check. Supplying a 16-byte "
        "transport id packs successfully and unpacks back to HEADER_2 with that "
        "exact transport id (positive control). An impl that forgets the "
        "transport-id requirement would emit an unaddressable transport frame"
    ),
)
def test_header2_requires_transport_id(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        # Negative: omit transport_id -> RNS's own IOError, surfaced as {error}.
        res = impl.execute(
            "packet_build_raw_header2", packet_type=1,  # 1 == RNS.Packet.ANNOUNCE
        )
        assert res.get("raw") is None, f"{label}: HEADER_2 w/o transport id must not pack: {res!r}"
        assert _HEADER2_NO_TID_MSG in (res.get("error") or ""), (
            f"{label}: expected RNS IOError text, got {res!r}"
        )

        # Positive control: a 16-byte transport id packs and round-trips.
        tid = impl.execute("identity_random_hash")["random_hash"]
        assert len(bytes.fromhex(tid)) == 16
        ok = impl.execute(
            "packet_build_raw_header2", packet_type=1, transport_id=tid,
        )
        assert ok.get("error") is None, f"{label}: HEADER_2 announce should pack: {ok!r}"
        parsed = impl.execute("packet_unpack", raw=ok["raw"])
        assert parsed["unpacked"] is True, f"{label}: announce frame must unpack: {parsed!r}"
        assert parsed["header_type"] == _HEADER_2, (
            f"{label}: packed frame must be HEADER_2, got {parsed['header_type']}"
        )
        assert parsed["transport_id"] == tid, (
            f"{label}: HEADER_2 transport id must round-trip: {parsed!r}"
        )


@conformance_case(
    commands=["packet_build_raw_header2"],
    verifies=(
        "RNS.Packet.pack only assembles a HEADER_2 header for ANNOUNCE packets "
        "(Packet.py:220-228): a HEADER_2 DATA packet — even WITH a valid 16-byte "
        "transport id — is never assigned ciphertext, so .raw assembly raises "
        "(AttributeError), refusing the origination. The hook surfaces RNS's own "
        "failure rather than a harness guard. An impl that lets a node ORIGINATE "
        "a HEADER_2 data packet (HEADER_2 is reserved for transport-relayed "
        "frames) would diverge"
    ),
)
def test_header2_non_announce_refused(sut, reference):
    # A definitely-16-byte transport id (so the ONLY reason to fail is the
    # non-announce branch, not a missing/short transport id).
    tid = "00112233445566778899aabbccddeeff"
    for impl, label in ((reference, "ref"), (sut, "sut")):
        res = impl.execute(
            "packet_build_raw_header2",
            packet_type=0,  # 0 == RNS.Packet.DATA
            transport_id=tid,
            data="abcdef",
        )
        assert res.get("raw") is None, (
            f"{label}: HEADER_2 DATA origination must be refused by RNS: {res!r}"
        )
        assert res.get("error"), f"{label}: expected an RNS error, got {res!r}"


@conformance_case(
    commands=["packet_constants"],
    verifies=(
        "RNS wire MDUs are exactly the values its own defining arithmetic yields: "
        "MDU == MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE == 464; PLAIN_MDU == MDU; "
        "ENCRYPTED_MDU == floor((MDU - TOKEN_OVERHEAD - KEYSIZE//16)/"
        "AES128_BLOCKSIZE)*AES128_BLOCKSIZE - 1 == 383; HEADER_MINSIZE == 19 and "
        "HEADER_MAXSIZE == 35. Re-derived independently from the live constants "
        "and cross-checked against the spec literals — an impl with a divergent "
        "MDU fragments/pads/addresses differently and breaks interop"
    ),
)
def test_mdu_constants_independent_derivation(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        c = impl.execute("packet_constants")
        # Each input pinned to its external spec literal first.
        assert c["mtu"] == _MTU, f"{label}: MTU"
        assert c["header_maxsize"] == _HEADER_MAXSIZE, f"{label}: HEADER_MAXSIZE"
        assert c["ifac_min_size"] == _IFAC_MIN_SIZE, f"{label}: IFAC_MIN_SIZE"
        assert c["token_overhead"] == _TOKEN_OVERHEAD, f"{label}: TOKEN_OVERHEAD"
        assert c["keysize"] == _KEYSIZE, f"{label}: KEYSIZE"
        assert c["aes128_blocksize"] == _AES128_BLOCKSIZE, f"{label}: AES128_BLOCKSIZE"

        # MDU and header sizes from their defining arithmetic.
        derived_mdu = c["mtu"] - c["header_maxsize"] - c["ifac_min_size"]
        assert derived_mdu == _MDU, f"{label}: derived MDU != 464 ({derived_mdu})"
        assert c["mdu"] == derived_mdu, f"{label}: stored MDU != derived"
        assert c["packet_plain_mdu"] == derived_mdu, f"{label}: PLAIN_MDU != MDU"
        assert c["header_minsize"] == 2 + 1 + 16, f"{label}: HEADER_MINSIZE arithmetic"
        assert c["header_maxsize"] == 2 + 1 + 32, f"{label}: HEADER_MAXSIZE arithmetic"

        # ENCRYPTED_MDU from RNS's documented formula (Packet.py:106).
        derived_enc = (
            ((derived_mdu - c["token_overhead"] - c["keysize"] // 16)
             // c["aes128_blocksize"]) * c["aes128_blocksize"] - 1
        )
        assert derived_enc == _ENCRYPTED_MDU, (
            f"{label}: derived ENCRYPTED_MDU != 383 ({derived_enc})"
        )
        assert c["packet_encrypted_mdu"] == derived_enc, (
            f"{label}: stored ENCRYPTED_MDU {c['packet_encrypted_mdu']} != derived {derived_enc}"
        )


@conformance_case(
    commands=["packet_resend_observe"],
    verifies=(
        "RNS.Packet.resend re-packs before re-transmitting so an ENCRYPTED "
        "destination gets fresh ephemeral key material every attempt "
        "(Packet.py:305-323): resending a SINGLE DATA packet yields different raw "
        "bytes AND a different packet hash than the first pack, while a PLAIN "
        "(unencrypted) packet resends to byte-identical raw and the same hash "
        "(contrast). An impl that re-uses the first ciphertext on resend would "
        "leak the static-IV/no-forward-secrecy property RNS deliberately avoids"
    ),
)
def test_resend_reencrypts_single_not_plain(sut, reference):
    for impl, label in ((reference, "ref"), (sut, "sut")):
        # Encrypted SINGLE destination: resend must produce fresh bytes + hash.
        single = impl.execute(
            "packet_resend_observe", dest_type="single", data="deadbeefcafe",
        )
        assert single["raw_2"] != single["raw_1"], (
            f"{label}: SINGLE resend did not re-encrypt (identical raw): {single!r}"
        )
        assert single["hash_2"] != single["hash_1"], (
            f"{label}: SINGLE resend produced same hash — no fresh material: {single!r}"
        )

        # PLAIN (unencrypted) destination: resend reproduces identical bytes.
        plain = impl.execute(
            "packet_resend_observe", dest_type="plain", data="deadbeefcafe",
        )
        assert plain["raw_2"] == plain["raw_1"], (
            f"{label}: PLAIN resend changed bytes — unexpected non-determinism: {plain!r}"
        )
        assert plain["hash_2"] == plain["hash_1"], (
            f"{label}: PLAIN resend changed hash: {plain!r}"
        )
