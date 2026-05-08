//! RFC 9000 §17 — Packet formats.
//!
//! These tests pin the *unprotected* wire format of every QUIC v1
//! packet shape: long-header common fields (§17.2), the four long
//! types (§17.2.2 Initial / §17.2.3 0-RTT / §17.2.4 Handshake /
//! §17.2.5 Retry), the short header (§17.3), and packet-number
//! truncation/expansion (§17.1). Header protection itself is RFC 9001
//! §5 and lives in `rfc9001_tls.zig`; here we only check the
//! plaintext wire layout that HP wraps.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9000 §17.1   MUST     PN encodes in 1..4 bytes
//!   RFC9000 §17.1   MUST     low 2 bits of first byte carry (PN_length - 1)
//!   RFC9000 §17.1   MUST     PN expansion uses largest_acked + 1 reference
//!   RFC9000 §17.1   MUST     PN expansion handles wrap forward across windows
//!   RFC9000 §17.1   MUST     PN expansion handles wrap backward across windows
//!   RFC9000 §17.1   MUST NOT accept fewer than 1 PN byte
//!   RFC9000 §17.1   MUST NOT accept more than 4 PN bytes
//!   RFC9000 §17.2   MUST     Header Form (bit 7) = 1 on every long header
//!   RFC9000 §17.2   MUST     Fixed Bit (bit 6) = 1 on every long header
//!   RFC9000 §17.2   MUST     Long Packet Type encoded in bits 5-4
//!                            (Initial=0, 0-RTT=1, Handshake=2, Retry=3)
//!   RFC9000 §17.2   MUST NOT accept v1 long header with DCID > 20 bytes
//!   RFC9000 §17.2   MUST NOT accept v1 long header with SCID > 20 bytes
//!   RFC9000 §17.2.1 MUST     Reserved Bits (bits 3-2) = 0 on transmit (Initial)
//!   RFC9000 §17.2.1 MUST     Reserved Bits (bits 3-2) = 0 on transmit (Handshake)
//!   RFC9000 §17.2.1 MUST     Reserved Bits (bits 3-2) = 0 on transmit (0-RTT)
//!   RFC9000 §17.2.1 MUST     non-zero long-header Reserved Bits on receive
//!                            close the connection with PROTOCOL_VIOLATION
//!   RFC9000 §17.2.2 MUST     Initial carries Token Length varint, then Token
//!   RFC9000 §17.2.2 MUST NOT accept Initial whose Token Length exceeds buffer
//!   RFC9000 §17.2.2 MUST     Initial carries Length varint framing PN+payload+tag
//!   RFC9000 §17.2.3 MUST     0-RTT shares Initial-shape minus Token field
//!   RFC9000 §17.2.4 MUST     Handshake shares 0-RTT shape exactly
//!   RFC9000 §17.2.5 MUST     Retry has no PN and no Length field
//!   RFC9000 §17.2.5 MUST     Retry's last 16 bytes are the integrity tag
//!   RFC9000 §17.2.5 MUST NOT accept Retry shorter than its 16-byte tag
//!   RFC9000 §17.3   MUST     Header Form (bit 7) = 0 on every short header
//!   RFC9000 §17.3   MUST     Fixed Bit (bit 6) = 1 on every short header
//!   RFC9000 §17.3   MUST     Spin Bit (bit 5) round-trips
//!   RFC9000 §17.3   MUST     Key Phase bit (bit 2) round-trips
//!   RFC9000 §17.3   MUST     Reserved Bits (bits 4-3) = 0 on transmit
//!   RFC9000 §17.3   MUST     PN Length (bits 1-0) encodes (length - 1)
//!   RFC9000 §17.3   MUST     non-zero short-header Reserved Bits on receive
//!                            close the connection with PROTOCOL_VIOLATION
//!
//! Visible debt:
//!   RFC9000 §17.2   ¶?   MUST NOT accept a long header whose Length field
//!                        exceeds the available buffer — `long_packet.zig`
//!                        already enforces this with
//!                        `Error.DeclaredLengthExceedsInput`, but the bare
//!                        `header.parse` (used by Retry and VN) doesn't
//!                        carry a Length field, and the Initial/Handshake/
//!                        0-RTT length-vs-buffer check happens in the open
//!                        path rather than on parse alone — captured here
//!                        as a header-level encode-side test only.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9000 §17.2.5 Retry integrity tag value     → rfc9001_tls.zig (RFC 9001 §5.8)
//!   RFC9000 §17     header-protection mask        → rfc9001_tls.zig (RFC 9001 §5.4)
//!   RFC9000 §17     coalesced packet walking      → rfc9000_packetization.zig (§12.2)
//!   RFC9000 §17.2.5 Retry handling state machine  → rfc9000_negotiation_validation.zig (§17.2.5)
//!   RFC8999 §4      generic long-header invariants (Form bit, Version field
//!                   width, DCID/SCID Length octets) → rfc8999_invariants.zig

const std = @import("std");
const quic_zig = @import("quic_zig");
const wire = quic_zig.wire;
const header = wire.header;
const packet_number = wire.packet_number;
const fixture = @import("_initial_fixture.zig");
const handshake_fixture = @import("_handshake_fixture.zig");

/// QUIC v1 wire-format version.
const QUIC_V1: u32 = 0x00000001;

// ---------------------------------------------------------------- §17.1 packet number encoding

test "MUST encode a 1-byte packet number when the unacked window allows it [RFC9000 §17.1 ¶1]" {
    // §17.1: "Packet numbers are limited to this range to ensure that they
    // can be encoded in 1, 2, 3, or 4 bytes." With a small unacked window,
    // 1 byte must suffice.
    const len = try packet_number.encodedLength(50, 0);
    try std.testing.expectEqual(@as(u8, 1), len);
}

test "MUST encode a 2-byte packet number when 1 byte would be ambiguous [RFC9000 §17.1 ¶3]" {
    // RFC 9000 §A.2 worked example: pn=0xac5c02 with largest=0xabe8b1
    // requires at least 2 bytes so the receiver can disambiguate.
    const len = try packet_number.encodedLength(0xac5c02, 0xabe8b1);
    try std.testing.expect(len >= 2);
}

test "MUST encode a 4-byte packet number when no PN has been ACKed yet [RFC9000 §17.1 ¶3]" {
    // Fresh PN space: §A.2 treats num_unacked = pn + 1. With a pn well
    // above 2^23, the §A.2 algorithm requires a 4-byte encoding so the
    // receiver can disambiguate against the entire pre-ack window.
    const len = try packet_number.encodedLength(10_000_000, null);
    try std.testing.expectEqual(@as(u8, 4), len);
}

test "MUST encode the (PN-length - 1) value in the low 2 bits of the first byte [RFC9000 §17.1 ¶4]" {
    // OneRtt with pn_length=.three should set bits 1-0 to 0b10 (= 3-1).
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.OneRtt{
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .pn_length = .three,
        .pn_truncated = 0x123456,
    };
    var buf: [16]u8 = undefined;
    _ = try header.encode(&buf, .{ .one_rtt = h });

    // First byte: form=0, fixed=1, spin=0, reserved=00, key_phase=0,
    //              pn_len bits = (3 - 1) = 0b10. So 0x40 | 0x02 = 0x42.
    try std.testing.expectEqual(@as(u8, 0x42), buf[0] & 0x43);
    try std.testing.expectEqual(@as(u2, 0b10), @as(u2, @intCast(buf[0] & 0x03)));
}

test "MUST decode the PN-length field as N-1 (so 0..3 maps to 1..4 bytes) [RFC9000 §17.1 ¶4]" {
    // PnLength.fromTwoBits is the receiver's mapping; verify all 4
    // values resolve to the lengths the spec lists.
    try std.testing.expectEqual(header.PnLength.one, header.PnLength.fromTwoBits(0));
    try std.testing.expectEqual(header.PnLength.two, header.PnLength.fromTwoBits(1));
    try std.testing.expectEqual(header.PnLength.three, header.PnLength.fromTwoBits(2));
    try std.testing.expectEqual(header.PnLength.four, header.PnLength.fromTwoBits(3));
}

test "MUST expand a truncated PN against largest_acked + 1 as the reference [RFC9000 §17.1 ¶6]" {
    // Canonical RFC 9000 §A.3 worked example: largest=0xa82f30ea,
    // truncated=0x9b32 across 2 bytes recovers to 0xa82f9b32.
    const recovered = try packet_number.decode(0x9b32, 2, 0xa82f30ea);
    try std.testing.expectEqual(@as(u64, 0xa82f9b32), recovered);
}

test "MUST snap a PN candidate forward by a window when too far behind expected [RFC9000 §17.1 ¶6]" {
    // largest=200, truncated=0x12 (1 byte) → expected=201, candidate=18.
    // |201 - 18| = 183 > 128 (half-window) → wrap forward to 18 + 256.
    const recovered = try packet_number.decode(0x12, 1, 200);
    try std.testing.expectEqual(@as(u64, 274), recovered);
}

test "MUST snap a PN candidate backward by a window when too far ahead of expected [RFC9000 §17.1 ¶6]" {
    // largest=1280, truncated=0xff → expected=1281, candidate=1535
    // (since 1281 & ~0xff = 1280; | 0xff = 1535). 1535 > 1281 + 128
    // (= 1409) → wrap backward to 1535 - 256 = 1279.
    const recovered = try packet_number.decode(0xff, 1, 1280);
    try std.testing.expectEqual(@as(u64, 1279), recovered);
}

test "MUST NOT accept fewer than 1 byte as a PN length [RFC9000 §17.1 ¶1]" {
    // Length 0 is outside the permitted 1..4 range.
    try std.testing.expectError(
        error.InvalidLength,
        packet_number.decode(0, 0, 0),
    );
}

test "MUST NOT accept more than 4 bytes as a PN length [RFC9000 §17.1 ¶1]" {
    // Length 5 is outside the permitted 1..4 range — the high-bits-of-PN
    // mapping in §17.1 only exposes a 2-bit field, so 5 should never reach
    // the wire, and explicit attempts must be rejected.
    try std.testing.expectError(
        error.InvalidLength,
        packet_number.decode(0, 5, 0),
    );
}

// ---------------------------------------------------------------- §17.2 long header common

test "MUST set the Header Form bit (bit 7) to 1 on an emitted Initial packet [RFC9000 §17.2 ¶2]" {
    const dcid_bytes = [_]u8{ 0xa1, 0xa2 };
    const scid_bytes = [_]u8{ 0xb1, 0xb2 };
    const h = header.Initial{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .token = "",
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .initial = h });

    try std.testing.expectEqual(@as(u8, 0x80), buf[0] & 0x80);
}

test "MUST set the Fixed Bit (bit 6) to 1 on an emitted Initial packet [RFC9000 §17.2 ¶3]" {
    const dcid_bytes = [_]u8{ 0xa1, 0xa2 };
    const scid_bytes = [_]u8{ 0xb1, 0xb2 };
    const h = header.Initial{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .token = "",
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .initial = h });

    try std.testing.expectEqual(@as(u8, 0x40), buf[0] & 0x40);
}

test "MUST encode Long Packet Type = 0 (Initial) in bits 5-4 of the first byte [RFC9000 §17.2 ¶4]" {
    const dcid_bytes = [_]u8{ 0xa1, 0xa2 };
    const h = header.Initial{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .token = "",
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .initial = h });

    // Bits 5-4 carry the type; for Initial the spec value is 0.
    try std.testing.expectEqual(@as(u2, 0), @as(u2, @intCast((buf[0] >> 4) & 0x03)));
}

test "MUST encode Long Packet Type = 1 (0-RTT) in bits 5-4 of the first byte [RFC9000 §17.2 ¶4]" {
    const dcid_bytes = [_]u8{ 0xa1, 0xa2 };
    const h = header.ZeroRtt{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .zero_rtt = h });

    try std.testing.expectEqual(@as(u2, 1), @as(u2, @intCast((buf[0] >> 4) & 0x03)));
}

test "MUST encode Long Packet Type = 2 (Handshake) in bits 5-4 of the first byte [RFC9000 §17.2 ¶4]" {
    const dcid_bytes = [_]u8{ 0xa1, 0xa2 };
    const h = header.Handshake{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .handshake = h });

    try std.testing.expectEqual(@as(u2, 2), @as(u2, @intCast((buf[0] >> 4) & 0x03)));
}

test "MUST encode Long Packet Type = 3 (Retry) in bits 5-4 of the first byte [RFC9000 §17.2 ¶4]" {
    const dcid_bytes = [_]u8{ 0xa1, 0xa2 };
    const tag: [16]u8 = @splat(0);
    const h = header.Retry{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .retry_token = "",
        .integrity_tag = tag,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .retry = h });

    try std.testing.expectEqual(@as(u2, 3), @as(u2, @intCast((buf[0] >> 4) & 0x03)));
}

test "MUST NOT accept a v1 long header whose DCID Length exceeds 20 [RFC9000 §17.2 ¶5]" {
    // RFC 9000 §17.2 narrows RFC 8999's 255-byte CID cap to 20 for v1.
    // Build a long header that claims DCIDLEN=21.
    var buf: [64]u8 = undefined;
    buf[0] = 0xc0;
    std.mem.writeInt(u32, buf[1..5], QUIC_V1, .big);
    buf[5] = 21; // > 20 — must be rejected
    // Filler so the parser doesn't trip on InsufficientBytes first.
    @memset(buf[6..32], 0);

    try std.testing.expectError(
        error.ConnIdTooLong,
        header.parse(buf[0..32], 0),
    );
}

test "MUST NOT accept a v1 long header whose SCID Length exceeds 20 [RFC9000 §17.2 ¶5]" {
    var buf: [64]u8 = undefined;
    buf[0] = 0xc0;
    std.mem.writeInt(u32, buf[1..5], QUIC_V1, .big);
    buf[5] = 0; // DCIDLEN = 0
    buf[6] = 21; // SCIDLEN > 20 — must be rejected
    @memset(buf[7..32], 0);

    try std.testing.expectError(
        error.ConnIdTooLong,
        header.parse(buf[0..32], 0),
    );
}

test "MUST NOT accept a long-header ConnId built from a slice longer than 20 bytes [RFC9000 §17.2 ¶5]" {
    // Encoder-side check: ConnId.fromSlice is the gate.
    var too_long: [21]u8 = @splat(0);
    try std.testing.expectError(
        error.ConnIdTooLong,
        header.ConnId.fromSlice(&too_long),
    );
}

// ---------------------------------------------------------------- §17.2.1 reserved bits

test "MUST set the Reserved Bits (bits 3-2) to 0 on an emitted Initial packet [RFC9000 §17.2.1 ¶17]" {
    // §17.2.1 "Reserved Bits": "The value included prior to protection
    // MUST be set to 0." Verify the encoder's default zero is honoured
    // even when the input struct had `reserved_bits = 0`.
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.Initial{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .token = "",
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
        .reserved_bits = 0,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .initial = h });

    // Bits 3-2 of the unprotected first byte must be zero.
    try std.testing.expectEqual(@as(u8, 0), buf[0] & 0x0c);
}

test "MUST set the Reserved Bits (bits 3-2) to 0 on an emitted Handshake packet [RFC9000 §17.2.1 ¶17]" {
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.Handshake{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
        .reserved_bits = 0,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .handshake = h });

    try std.testing.expectEqual(@as(u8, 0), buf[0] & 0x0c);
}

test "MUST set the Reserved Bits (bits 3-2) to 0 on an emitted 0-RTT packet [RFC9000 §17.2.1 ¶17]" {
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.ZeroRtt{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 20,
        .reserved_bits = 0,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .zero_rtt = h });

    try std.testing.expectEqual(@as(u8, 0), buf[0] & 0x0c);
}

test "MUST treat non-zero long-header Reserved Bits as PROTOCOL_VIOLATION on receive [RFC9000 §17.2.1 ¶17]" {
    // RFC 9000 §17.2.1 ¶17: "An endpoint MUST treat receipt of a
    // packet that has a non-zero value for these bits after removing
    // both packet and header protection as a connection error of
    // type PROTOCOL_VIOLATION."
    //
    // We seal an authentic Initial whose pre-HP first byte carries
    // reserved_bits=0b10. After AEAD passes on the receiver,
    // `Connection.handleInitial` reads bits 3-2 of the post-HP first
    // byte and observes the non-zero value — close fires before
    // dispatchFrames runs (so the payload itself doesn't matter; we
    // pass empty bytes).
    var srv = try fixture.buildServer();
    defer srv.deinit();

    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid = [_]u8{ 0xa0, 0xb0, 0xc0, 0xd0 };
    // Empty payload — the reserved-bits gate fires before any frame
    // is dispatched, so the payload contents are irrelevant.
    const close_event = try fixture.feedAndExpectClose(&srv, &dcid, &scid, 0b10, &.{});
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(quic_zig.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(quic_zig.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §17.2.2 Initial

test "MUST emit an Initial whose layout is Token Length varint, Token, Length varint, PN [RFC9000 §17.2.2 ¶1]" {
    // Construct a known-length packet and verify the byte offsets.
    const dcid_bytes = [_]u8{ 0xaa, 0xbb }; // 2-byte DCID
    const scid_bytes = [_]u8{0xcc}; // 1-byte SCID
    const token = [_]u8{ 0xde, 0xad }; // 2-byte token
    const h = header.Initial{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .token = &token,
        .pn_length = .one,
        .pn_truncated = 0x42,
        .payload_length = 20,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .initial = h });

    // Layout (offsets):
    //   0:    first byte
    //   1..5: version (4 bytes)
    //   5:    DCIDLEN (= 2)
    //   6..8: DCID
    //   8:    SCIDLEN (= 1)
    //   9:    SCID
    //   10:   Token Length varint = 2 (single byte 0x02)
    //   11:   Token byte 0 (0xde)
    //   12:   Token byte 1 (0xad)
    //   13:   Length varint = 20 (single-byte 0x14, since 20 < 64)
    //   14:   PN (1 byte)
    try std.testing.expectEqual(@as(u8, 0x02), buf[10]); // token-len varint
    try std.testing.expectEqual(@as(u8, 0xde), buf[11]); // token byte 0
    try std.testing.expectEqual(@as(u8, 0xad), buf[12]); // token byte 1
    try std.testing.expectEqual(@as(u8, 0x14), buf[13]); // length varint
    try std.testing.expectEqual(@as(u8, 0x42), buf[14]); // PN
}

test "MUST NOT accept an Initial whose Token Length exceeds the remaining buffer [RFC9000 §17.2.2 ¶6]" {
    // Hand-craft an Initial whose Token Length varint claims more bytes
    // than `src` provides — parser must refuse rather than read past
    // the slab.
    var buf: [16]u8 = undefined;
    buf[0] = 0xc0; // Initial first byte: long(1) fixed(1) type=00 reserved=00 pn_len=00
    std.mem.writeInt(u32, buf[1..5], QUIC_V1, .big);
    buf[5] = 0; // DCIDLEN = 0
    buf[6] = 0; // SCIDLEN = 0
    // Token length varint: claim 100 bytes (single-byte varint range
    // is 0..63; 100 needs the 2-byte form: 0x40 | high-byte, low-byte).
    // 100 = 0x64 → 2-byte varint: 0x40|0x00 = 0x40, 0x64.
    buf[7] = 0x40;
    buf[8] = 0x64;
    // No actual token bytes follow.

    try std.testing.expectError(
        error.InsufficientBytes,
        header.parse(buf[0..9], 0),
    );
}

test "MUST encode the Initial Length field as a varint covering PN + payload + tag [RFC9000 §17.2.2 ¶7]" {
    // §17.2.2 Length field "is the length of the remainder of the
    // packet (that is, the Packet Number and Payload fields)" — and
    // §17.2 says the Payload includes the AEAD tag. Round-trip through
    // parse and verify the field came back identical.
    const dcid_bytes = [_]u8{ 0xa1, 0xa2 };
    const h = header.Initial{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&[_]u8{}),
        .token = "",
        .pn_length = .two,
        .pn_truncated = 0xabcd,
        .payload_length = 1182, // RFC 9001 §A.2 Length
    };
    var buf: [64]u8 = undefined;
    const written = try header.encode(&buf, .{ .initial = h });

    const parsed = try header.parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqual(@as(u64, 1182), parsed.header.initial.payload_length);
}

// ---------------------------------------------------------------- §17.2.3 0-RTT

test "MUST emit a 0-RTT packet whose layout is Length varint then PN (no Token) [RFC9000 §17.2.3 ¶1]" {
    // Build a 0-RTT packet with known geometry; verify the Length
    // varint sits where Initial's Token Length would, and there's no
    // Token in between.
    const dcid_bytes = [_]u8{ 0x11, 0x22 }; // 2-byte DCID
    const scid_bytes = [_]u8{0x33}; // 1-byte SCID
    const h = header.ZeroRtt{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .pn_length = .one,
        .pn_truncated = 0x55,
        .payload_length = 30,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .zero_rtt = h });

    // Layout offsets:
    //   0: first byte
    //   1..5: version
    //   5: DCIDLEN (= 2)
    //   6..8: DCID
    //   8: SCIDLEN (= 1)
    //   9: SCID
    //   10: Length varint (30 → single-byte 0x1e)
    //   11: PN (= 0x55)
    try std.testing.expectEqual(@as(u8, 0x1e), buf[10]); // length varint
    try std.testing.expectEqual(@as(u8, 0x55), buf[11]); // PN
}

// ---------------------------------------------------------------- §17.2.4 Handshake

test "MUST emit a Handshake packet whose layout matches 0-RTT exactly (no Token) [RFC9000 §17.2.4 ¶1]" {
    const dcid_bytes = [_]u8{ 0x11, 0x22 };
    const scid_bytes = [_]u8{0x33};
    const h = header.Handshake{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .pn_length = .one,
        .pn_truncated = 0x55,
        .payload_length = 30,
    };
    var buf: [64]u8 = undefined;
    _ = try header.encode(&buf, .{ .handshake = h });

    // Same layout as the 0-RTT test above — only the type bits differ.
    try std.testing.expectEqual(@as(u8, 0x1e), buf[10]);
    try std.testing.expectEqual(@as(u8, 0x55), buf[11]);
}

// ---------------------------------------------------------------- §17.2.5 Retry

test "MUST place a 16-byte integrity tag at the end of an emitted Retry packet [RFC9000 §17.2.5 ¶2]" {
    // §17.2.5 Retry Integrity Tag: "Retry packets ... carry a Retry
    // Integrity Tag that provides ... [it] is computed over the Retry
    // Pseudo-Packet ... [the] last 128 bits of the packet."
    const dcid_bytes = [_]u8{ 0x11, 0x22 };
    const scid_bytes = [_]u8{0x33};
    const token = "abcd";
    const tag = [_]u8{
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const h = header.Retry{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .retry_token = token,
        .integrity_tag = tag,
    };
    var buf: [64]u8 = undefined;
    const written = try header.encode(&buf, .{ .retry = h });

    // Final 16 bytes must equal the integrity tag.
    try std.testing.expectEqualSlices(u8, &tag, buf[written - 16 .. written]);
}

test "MUST NOT include a Length field or Packet Number in an emitted Retry packet [RFC9000 §17.2.5 ¶1]" {
    // The Retry layout per §17.2.5 is: first byte | Version | DCIDLEN |
    // DCID | SCIDLEN | SCID | Retry Token | Retry Integrity Tag.
    // Verify total emitted size equals exactly that, with no slack.
    const dcid_bytes = [_]u8{ 0x11, 0x22 }; // 2 bytes
    const scid_bytes = [_]u8{ 0x33, 0x44, 0x55 }; // 3 bytes
    const token = "tok"; // 3 bytes
    const tag: [16]u8 = @splat(0);
    const h = header.Retry{
        .version = QUIC_V1,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .retry_token = token,
        .integrity_tag = tag,
    };
    var buf: [64]u8 = undefined;
    const written = try header.encode(&buf, .{ .retry = h });

    // Expected size: 1 (first) + 4 (version) + 1 (dcidlen) + 2 (dcid) +
    //                1 (scidlen) + 3 (scid) + 3 (token) + 16 (tag) = 31.
    try std.testing.expectEqual(@as(usize, 31), written);
}

test "MUST NOT accept a Retry packet shorter than its 16-byte integrity tag [RFC9000 §17.2.5 ¶2]" {
    // First byte 0xf0 = long(1), fixed(1), type=11 (Retry), unused=0000.
    // Version + 0-len CIDs + only 8 trailing bytes — less than the tag.
    var buf: [32]u8 = undefined;
    buf[0] = 0xf0;
    std.mem.writeInt(u32, buf[1..5], QUIC_V1, .big);
    buf[5] = 0; // DCIDLEN
    buf[6] = 0; // SCIDLEN
    @memset(buf[7..15], 0); // 8 bytes of "tail" — fewer than 16.

    try std.testing.expectError(
        error.InsufficientBytes,
        header.parse(buf[0..15], 0),
    );
}

// ---------------------------------------------------------------- §17.3 short header

test "MUST set the Header Form bit (bit 7) to 0 on an emitted 1-RTT packet [RFC9000 §17.3 ¶1]" {
    const dcid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const h = header.OneRtt{
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .pn_length = .one,
        .pn_truncated = 0,
    };
    var buf: [16]u8 = undefined;
    _ = try header.encode(&buf, .{ .one_rtt = h });

    try std.testing.expectEqual(@as(u8, 0), buf[0] & 0x80);
}

test "MUST set the Fixed Bit (bit 6) to 1 on an emitted 1-RTT packet [RFC9000 §17.3 ¶2]" {
    const dcid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const h = header.OneRtt{
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .pn_length = .one,
        .pn_truncated = 0,
    };
    var buf: [16]u8 = undefined;
    _ = try header.encode(&buf, .{ .one_rtt = h });

    try std.testing.expectEqual(@as(u8, 0x40), buf[0] & 0x40);
}

test "MUST round-trip the Spin Bit (bit 5) on a 1-RTT packet [RFC9000 §17.3.1 ¶2]" {
    // The Spin Bit is OPTIONAL (§17.4) but when implemented MUST be
    // bit 5. Verify the emitter places it there and the parser
    // recovers the same value.
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.OneRtt{
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .spin_bit = true,
        .pn_length = .one,
        .pn_truncated = 0,
    };
    var buf: [16]u8 = undefined;
    const written = try header.encode(&buf, .{ .one_rtt = h });
    try std.testing.expectEqual(@as(u8, 0x20), buf[0] & 0x20);

    const parsed = try header.parse(buf[0..written], @intCast(dcid_bytes.len));
    try std.testing.expect(parsed.header == .one_rtt);
    try std.testing.expectEqual(true, parsed.header.one_rtt.spin_bit);
}

test "MUST round-trip the Key Phase bit (bit 2) on a 1-RTT packet [RFC9000 §17.3 ¶?]" {
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.OneRtt{
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .key_phase = true,
        .pn_length = .one,
        .pn_truncated = 0,
    };
    var buf: [16]u8 = undefined;
    const written = try header.encode(&buf, .{ .one_rtt = h });
    try std.testing.expectEqual(@as(u8, 0x04), buf[0] & 0x04);

    const parsed = try header.parse(buf[0..written], @intCast(dcid_bytes.len));
    try std.testing.expect(parsed.header == .one_rtt);
    try std.testing.expectEqual(true, parsed.header.one_rtt.key_phase);
}

test "MUST set the Reserved Bits (bits 4-3) to 0 on an emitted 1-RTT packet [RFC9000 §17.3 ¶3]" {
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.OneRtt{
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .reserved_bits = 0,
        .pn_length = .one,
        .pn_truncated = 0,
    };
    var buf: [16]u8 = undefined;
    _ = try header.encode(&buf, .{ .one_rtt = h });

    // Bits 4-3 must be zero.
    try std.testing.expectEqual(@as(u8, 0), buf[0] & 0x18);
}

test "MUST encode the Short Header PN Length (bits 1-0) as (length - 1) [RFC9000 §17.3 ¶?]" {
    // PnLength.four → bits 1-0 = 0b11.
    const dcid_bytes = [_]u8{ 0x01, 0x02 };
    const h = header.OneRtt{
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .pn_length = .four,
        .pn_truncated = 0xdeadbeef,
    };
    var buf: [16]u8 = undefined;
    _ = try header.encode(&buf, .{ .one_rtt = h });

    try std.testing.expectEqual(@as(u2, 0b11), @as(u2, @intCast(buf[0] & 0x03)));
}

test "MUST treat non-zero short-header Reserved Bits as PROTOCOL_VIOLATION on receive [RFC9000 §17.3 ¶3]" {
    // RFC 9000 §17.3 ¶3: "The value included prior to protection MUST
    // be set to 0. An endpoint MUST treat receipt of a packet that has
    // a non-zero value for these bits, after removing both packet and
    // header protection, as a connection error of type
    // PROTOCOL_VIOLATION."
    //
    // Drive a real TLS handshake to handshake-confirmed, then have the
    // client seal an authentic 1-RTT packet whose pre-HP first byte
    // carries reserved_bits=0b10. After AEAD passes on the server,
    // `Connection.handleShort` reads bits 4-3 of the post-HP first
    // byte (surfaced via `Open1RttResult.reserved_bits`) and observes
    // the non-zero value — close fires before dispatchFrames runs (so
    // the PING payload is irrelevant; the gate fires before any frame
    // is processed).
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const ping_frame = [_]u8{0x01};
    const close_event = try pair.injectFrameAtServerWithReservedBits(&ping_frame, 0b10);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(quic_zig.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(quic_zig.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}
