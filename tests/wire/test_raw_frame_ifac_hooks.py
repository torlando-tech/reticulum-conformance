"""Raw-frame injection against Transport.inbound's four pre-unpack drop guards.

These pin the silent-drop branches at the very top of RNS.Transport.inbound
(RNS 1.3.1, RNS/Transport.py:1387-1447) — the guards that run BEFORE a packet is
ever unpacked, on a LIVE interface:

  if len(raw) > 2:                                         # (4) minimum length
      if interface has ifac_identity:
          if raw[0] & 0x80 == 0x80:                        # IFAC flag set
              if len(raw) > 2+interface.ifac_size: ...      # (1) short-packet
              else: return                                  # (1) drop: too short
          else: return                                      # (2) flag missing
      else:
          if raw[0] & 0x80 == 0x80: return                  # (3) flag on open iface
  else: return                                              # (4) drop: <=2 bytes

Every injected frame is a GENUINE announce that real RNS produced
(Destination.announce(send=False) -> Packet.pack), optionally IFAC-masked by
real RNS (Transport.transmit) and/or trimmed. The drop is silent (inbound
returns None), so each test pairs a POSITIVE control — a genuine, well-formed
frame that the SAME interface DOES accept and learn a path from — with the
NEGATIVE rule-violating frame, so "no path learned" is attributable to the
specific guard and not to the injection being a no-op.

The anchor for every assertion is the RNS source rule above (an external spec
literal / independent length derivation), never impl-vs-itself.
"""

import secrets

from conformance import conformance_case


__category_title__ = "Raw Frame IFAC Drops"
__category_order__ = 19


def _creds() -> tuple[str, str]:
    """Fresh (network_name, passphrase) so IFAC keys never collide with a real
    Reticulum network on the test host."""
    return (f"rawframe-{secrets.token_hex(4)}", secrets.token_hex(16))


@conformance_case(
    commands=["start_tcp_server", "inject_raw_frame"],
    verifies="IFAC interface: a flag-set frame trimmed to exactly 2+ifac_size bytes is silently dropped by the short-packet IFAC guard (Transport.py:1402 `len(raw) > 2+interface.ifac_size` else return), while the full masked announce (len > 2+ifac_size) is accepted and learns a path",
)
def test_ifac_drops_short_packet(wire_peers):
    """ifac-drop-short-packet: on an IFAC-enabled interface, a frame whose
    length is <= 2+ifac_size (even with the IFAC flag correctly set) hits
    `else: return` at Transport.py:1435 and is dropped before any IFAC unmask.
    The full masked announce (len > 2+ifac_size) is the positive control."""
    server, _client = wire_peers
    network_name, passphrase = _creds()
    server.start_tcp_server(network_name, passphrase)

    full = server.inject_raw_frame("masked_full")
    ifac_size = int(full["ifac_size"])
    assert full["frame_len"] > 2 + ifac_size, (
        f"positive control frame_len={full['frame_len']} is not > 2+ifac_size="
        f"{2 + ifac_size}; cannot exercise the short-packet boundary"
    )
    assert full["learned"] is True, (
        "a full, valid IFAC-masked announce (len > 2+ifac_size) was NOT accepted "
        "on the IFAC interface — the inject path is broken, so the negative "
        "result below would be vacuous"
    )

    short = server.inject_raw_frame("masked_short")
    assert short["frame_len"] <= 2 + ifac_size, (
        f"short frame_len={short['frame_len']} must be <= 2+ifac_size="
        f"{2 + ifac_size} to land in the drop branch"
    )
    assert short["learned"] is False, (
        f"IFAC interface learned a path from a {short['frame_len']}-byte frame "
        f"(<= 2+ifac_size={2 + ifac_size}); RNS Transport.py:1402/:1435 require "
        f"such a frame to be dropped before the IFAC is even extracted"
    )


@conformance_case(
    commands=["start_tcp_server", "inject_raw_frame"],
    verifies="IFAC interface: an announce frame WITHOUT the 0x80 IFAC flag is silently dropped by the flag-missing guard (Transport.py:1437-1439 `else: return`), while the same announce IFAC-masked (flag set) is accepted",
)
def test_ifac_drops_flag_missing(wire_peers):
    """ifac-drop-flag-missing: an IFAC interface must reject a frame that lacks
    the IFAC flag — Transport.py:1439 `else: return`. The unmasked announce
    (flag clear) is dropped; the masked announce (flag set) is the positive
    control."""
    server, _client = wire_peers
    network_name, passphrase = _creds()
    server.start_tcp_server(network_name, passphrase)

    masked = server.inject_raw_frame("masked_full")
    assert masked["learned"] is True, (
        "a valid IFAC-masked announce (flag set) was NOT accepted on the IFAC "
        "interface — inject path broken; negative result would be vacuous"
    )

    plain = server.inject_raw_frame("plain_on_ifac")
    assert plain["learned"] is False, (
        "IFAC interface learned a path from an UNMASKED announce (0x80 flag "
        "clear); RNS Transport.py:1437-1439 require an IFAC interface to drop "
        "any frame whose IFAC flag is not set"
    )


@conformance_case(
    commands=["start_tcp_server", "start_tcp_client", "inject_raw_frame"],
    verifies="Open (non-IFAC) interface: a frame with the 0x80 IFAC flag SET is silently dropped (Transport.py:1442-1445 `if raw[0] & 0x80 == 0x80: return`), while a plain unflagged announce is accepted and learns a path",
)
def test_open_interface_drops_flag_set(wire_peers):
    """ifac-drop-flag-on-open-interface: an interface with NO IFAC configured
    must drop any frame that carries the IFAC flag — Transport.py:1445. The
    flag-set frame is a genuine IFAC-masked announce built by a separate
    IFAC-configured peer (real RNS masking); the plain announce built+injected
    on the open peer itself is the positive control."""
    server, client = wire_peers
    network_name, passphrase = _creds()
    # server = IFAC peer (only used to PRODUCE a genuine flag-set frame).
    port = server.start_tcp_server(network_name, passphrase)
    # client = OPEN peer (no IFAC) — the interface under test.
    client.start_tcp_client("", "", "127.0.0.1", port)

    # Positive control: an unflagged announce IS accepted by the open interface.
    plain = client.inject_raw_frame("plain_on_open")
    assert plain["learned"] is True, (
        "the OPEN interface did not learn a path from a plain unflagged "
        "announce — inject path broken; the negative below would be vacuous"
    )

    # Build a genuine IFAC-masked (flag-set) frame on the IFAC server, then
    # inject it onto the open client.
    built = server.inject_raw_frame("build_masked")
    masked_raw = bytes.fromhex(built["raw"])
    dest_hash = bytes.fromhex(built["dest_hash"])
    assert masked_raw[0] >= 0x80, (
        "build_masked did not set the 0x80 IFAC flag on byte 0 — RNS "
        "Transport.transmit (Transport.py:1062/:1072) must set it when masking"
    )

    dropped = client.inject_raw_frame(
        "inject_external", raw=masked_raw, dest_hash=dest_hash
    )
    assert dropped["learned"] is False, (
        "the OPEN (non-IFAC) interface learned a path from an IFAC-flagged "
        "frame; RNS Transport.py:1442-1445 require a non-IFAC interface to drop "
        "any frame whose 0x80 IFAC flag is set"
    )


@conformance_case(
    commands=["start_tcp_server", "inject_raw_frame"],
    verifies="A sub-3-byte frame is silently dropped by the minimum-length guard at the very top of Transport.inbound (Transport.py:1398 `if len(raw) > 2` else 1447 `return`), before any IFAC logic, while a full announce is accepted",
)
def test_drops_min_packet_length(wire_peers):
    """drop-min-packet-length: Transport.inbound drops any frame with
    len(raw) <= 2 (Transport.py:1398/:1447) before it ever reaches the IFAC or
    unpack stages. Verified on an open interface for 0-, 1- and 2-byte frames,
    with a full announce as the positive control."""
    server, _client = wire_peers
    # Open peer (no IFAC) so the only gate exercised is the length one.
    server.start_tcp_server("", "")

    full = server.inject_raw_frame("plain_on_open")
    assert full["learned"] is True, (
        "the open interface did not learn a path from a full announce — inject "
        "path broken; the negative results below would be vacuous"
    )

    for trim_to in (0, 1, 2):
        tiny = server.inject_raw_frame("min_short", trim_to=trim_to)
        assert tiny["frame_len"] == trim_to, (
            f"requested a {trim_to}-byte frame but got {tiny['frame_len']} bytes"
        )
        assert tiny["learned"] is False, (
            f"Transport learned a path from a {trim_to}-byte frame; RNS "
            f"Transport.py:1398/:1447 require any frame with len(raw) <= 2 to be "
            f"dropped at the top of inbound, before IFAC or unpack"
        )
