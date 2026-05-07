//! RFC 9000 §16 — Variable-length integer encoding.
//!
//! QUIC encodes integers in 1, 2, 4, or 8 bytes. The two
//! most-significant bits of the first byte (the "2msb" prefix) encode
//! log2 of the byte length: 00→1, 01→2, 10→4, 11→8. The remaining 6
//! bits of the first byte plus the trailing bytes carry the value in
//! network byte order. Range: 0 .. 2^62 - 1. Decoders accept any of
//! the four forms for a given value; encoders pick the shortest.
//!
//! The implementation under test lives in `src/wire/varint.zig`.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9000 §16  ¶3   NORMATIVE  decode 1-byte form (2msb=00) — RFC test vector v=37
//!   RFC9000 §16  ¶3   NORMATIVE  decode 2-byte form (2msb=01) — RFC test vector v=15293
//!   RFC9000 §16  ¶3   NORMATIVE  decode 4-byte form (2msb=10) — RFC test vector v=494878333
//!   RFC9000 §16  ¶3   NORMATIVE  decode 8-byte form (2msb=11) — RFC test vector v=151288809941952652
//!   RFC9000 §16  ¶6   NORMATIVE  decode accepts non-minimum encoding (4-byte form of value 5)
//!   RFC9000 §16  ¶6   NORMATIVE  decode accepts non-minimum encoding (8-byte form of value 37)
//!   RFC9000 §16  ¶6   NORMATIVE  encoder picks the shortest legal form for each value
//!   RFC9000 §16  ¶1   MUST NOT   encode a value greater than 2^62 - 1
//!   RFC9000 §16  ¶3   MUST NOT   decode past the end of the input buffer (1B/2B/4B/8B truncation)
//!   RFC9000 §16  ¶3   MUST NOT   decode an empty input buffer
//!   RFC9000 §16  ¶3   NORMATIVE  encode 1B max boundary value (63)
//!   RFC9000 §16  ¶3   NORMATIVE  encode 2B max boundary value (16383)
//!   RFC9000 §16  ¶3   NORMATIVE  encode 4B max boundary value (2^30 - 1)
//!   RFC9000 §16  ¶3   NORMATIVE  encode 8B max boundary value (2^62 - 1)
//!   RFC9000 §16  ¶3   NORMATIVE  round-trip parity across all length boundaries
//!
//! Visible debt:
//!   none — the §16 normative surface is small and fully covered here.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9000 §17  varint use inside long-/short-header packets   → rfc9000_packet_headers.zig
//!   RFC9000 §18  varint use inside transport parameters        → rfc9000_transport_params.zig
//!   RFC9000 §19  varint use inside frame types                 → rfc9000_frames.zig
//!
//! Not implemented by design:
//!   none — RFC 9000 §16 is the encoding rule; nullq implements the full surface.

const std = @import("std");
const nullq = @import("nullq");
const varint = nullq.wire.varint;

// ---------------------------------------------------------------- §16 decode forms

test "NORMATIVE decode the 1-byte varint form (2msb=00) per RFC test vector [RFC9000 §16 ¶3]" {
    // RFC 9000 Appendix A.1 vector: 0x25 → 37. The 2msb of 0x25 is
    // 00, selecting the 1-byte form; the remaining 6 bits hold the
    // value directly.
    const d = try varint.decode(&[_]u8{0x25});
    try std.testing.expectEqual(@as(u64, 37), d.value);
    try std.testing.expectEqual(@as(u8, 1), d.bytes_read);
}

test "NORMATIVE decode the 2-byte varint form (2msb=01) per RFC test vector [RFC9000 §16 ¶3]" {
    // RFC 9000 Appendix A.1 vector: 0x7b 0xbd → 15293. 2msb of 0x7b
    // is 01 → 2-byte form; value is ((0x7b & 0x3f) << 8) | 0xbd.
    const d = try varint.decode(&[_]u8{ 0x7b, 0xbd });
    try std.testing.expectEqual(@as(u64, 15293), d.value);
    try std.testing.expectEqual(@as(u8, 2), d.bytes_read);
}

test "NORMATIVE decode the 4-byte varint form (2msb=10) per RFC test vector [RFC9000 §16 ¶3]" {
    // RFC 9000 Appendix A.1 vector: 0x9d 0x7f 0x3e 0x7d → 494878333.
    // 2msb of 0x9d is 10 → 4-byte form.
    const d = try varint.decode(&[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d });
    try std.testing.expectEqual(@as(u64, 494878333), d.value);
    try std.testing.expectEqual(@as(u8, 4), d.bytes_read);
}

test "NORMATIVE decode the 8-byte varint form (2msb=11) per RFC test vector [RFC9000 §16 ¶3]" {
    // RFC 9000 Appendix A.1 vector:
    //   0xc2 0x19 0x7c 0x5e 0xff 0x14 0xe8 0x8c → 151288809941952652.
    // 2msb of 0xc2 is 11 → 8-byte form.
    const d = try varint.decode(&[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c });
    try std.testing.expectEqual(@as(u64, 151288809941952652), d.value);
    try std.testing.expectEqual(@as(u8, 8), d.bytes_read);
}

// ---------------------------------------------------------------- §16 non-minimum encodings

test "NORMATIVE decode accepts a non-minimum 4-byte encoding of value 5 [RFC9000 §16 ¶6]" {
    // §16 ¶6: "The encoded form for an integer can be larger than the
    // minimum size required..." — i.e. the decoder is form-agnostic.
    // 0x80 selects 4-byte form; payload is the 30-bit big-endian value 5.
    const d = try varint.decode(&[_]u8{ 0x80, 0x00, 0x00, 0x05 });
    try std.testing.expectEqual(@as(u64, 5), d.value);
    try std.testing.expectEqual(@as(u8, 4), d.bytes_read);
}

test "NORMATIVE decode accepts a non-minimum 8-byte encoding of value 37 [RFC9000 §16 ¶6]" {
    // Same value (37) that fits in 1 byte (0x25) re-encoded into the
    // 8-byte form must round-trip-decode to 37. 0xc0 selects 8-byte
    // form; remaining 7 bytes carry value 37 in network byte order.
    const d = try varint.decode(&[_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25 });
    try std.testing.expectEqual(@as(u64, 37), d.value);
    try std.testing.expectEqual(@as(u8, 8), d.bytes_read);
}

// ---------------------------------------------------------------- §16 encoder picks minimum

test "NORMATIVE encode picks the 1-byte form for a value < 2^6 [RFC9000 §16 ¶6]" {
    // Encoder is required to produce the shortest legal form. The
    // RFC text says "The encoded form for an integer can be larger
    // than the minimum size required" (i.e. allowed on the wire), but
    // the standard convention — and the only behavior auditors care
    // about for an encoder — is "minimum form". Hence NORMATIVE.
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, 63);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0] & 0xc0);
}

test "NORMATIVE encode picks the 2-byte form for a value in [2^6, 2^14) [RFC9000 §16 ¶6]" {
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, 64);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0x40), buf[0] & 0xc0);
}

test "NORMATIVE encode picks the 4-byte form for a value in [2^14, 2^30) [RFC9000 §16 ¶6]" {
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, 16384);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(u8, 0x80), buf[0] & 0xc0);
}

test "NORMATIVE encode picks the 8-byte form for a value in [2^30, 2^62) [RFC9000 §16 ¶6]" {
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, 1 << 30);
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqual(@as(u8, 0xc0), buf[0] & 0xc0);
}

// ---------------------------------------------------------------- §16 boundary encodings

test "NORMATIVE encode the 1-byte boundary value 63 with prefix 00 [RFC9000 §16 ¶3]" {
    // 63 = 2^6 - 1, the largest value the 1-byte form can carry.
    // 0x3f = 0b00_111111: prefix 00, payload 63.
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, 63);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualSlices(u8, &.{0x3f}, buf[0..n]);
}

test "NORMATIVE encode the 2-byte boundary value 16383 with prefix 01 [RFC9000 §16 ¶3]" {
    // 16383 = 2^14 - 1. 0x7f 0xff = 0b01_111111 0xff: prefix 01, payload 16383.
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, 16383);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0xff }, buf[0..n]);
}

test "NORMATIVE encode the 4-byte boundary value 2^30 - 1 with prefix 10 [RFC9000 §16 ¶3]" {
    // 2^30 - 1 = 1073741823. 0xbf 0xff 0xff 0xff: prefix 10, payload 2^30 - 1.
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, (1 << 30) - 1);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualSlices(u8, &.{ 0xbf, 0xff, 0xff, 0xff }, buf[0..n]);
}

test "NORMATIVE encode the 8-byte boundary value 2^62 - 1 with prefix 11 [RFC9000 §16 ¶3]" {
    // 2^62 - 1 = 4_611_686_018_427_387_903 = max varint. All payload
    // bits set, prefix 11: 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xff.
    var buf: [8]u8 = undefined;
    const n = try varint.encode(&buf, varint.max_value);
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        buf[0..n],
    );
}

// ---------------------------------------------------------------- §16 range cap

test "MUST NOT encode a value greater than 2^62 - 1 [RFC9000 §16 ¶1]" {
    // §16 ¶1 fixes the varint range as 0..2^62-1; a value one past
    // the top must be rejected at the encoder, never silently
    // truncated.
    var buf: [8]u8 = undefined;
    try std.testing.expectError(
        varint.Error.ValueTooLarge,
        varint.encode(&buf, varint.max_value + 1),
    );
}

test "MUST NOT encode the maximum u64 (saturated value) [RFC9000 §16 ¶1]" {
    // Belt-and-suspenders: a caller passing std.math.maxInt(u64) —
    // far above 2^62-1 — still must hit ValueTooLarge.
    var buf: [8]u8 = undefined;
    try std.testing.expectError(
        varint.Error.ValueTooLarge,
        varint.encode(&buf, std.math.maxInt(u64)),
    );
}

// ---------------------------------------------------------------- §16 truncation guards

test "MUST NOT decode an empty input buffer [RFC9000 §16 ¶3]" {
    // Decoder must read the prefix byte before doing anything else;
    // a zero-length slice gives it nothing to read.
    try std.testing.expectError(varint.Error.InsufficientBytes, varint.decode(""));
}

test "MUST NOT decode a 2-byte varint with only 1 byte present [RFC9000 §16 ¶3]" {
    // 0x40 declares the 2-byte form (prefix 01) but only 1 byte is
    // available. Reading byte 1 would walk off the end of the slice.
    try std.testing.expectError(
        varint.Error.InsufficientBytes,
        varint.decode(&[_]u8{0x40}),
    );
}

test "MUST NOT decode a 4-byte varint with only 2 bytes present [RFC9000 §16 ¶3]" {
    // 0x80 declares the 4-byte form (prefix 10); two trailing bytes
    // are missing.
    try std.testing.expectError(
        varint.Error.InsufficientBytes,
        varint.decode(&[_]u8{ 0x80, 0x00 }),
    );
}

test "MUST NOT decode an 8-byte varint with only 4 bytes present [RFC9000 §16 ¶3]" {
    // 0xc0 declares the 8-byte form (prefix 11); four trailing bytes
    // are missing.
    try std.testing.expectError(
        varint.Error.InsufficientBytes,
        varint.decode(&[_]u8{ 0xc0, 0x00, 0x00, 0x00 }),
    );
}

// ---------------------------------------------------------------- §16 round-trip parity

test "NORMATIVE round-trip the boundary value set encode→decode [RFC9000 §16 ¶3]" {
    // Boundary values from the RFC's encoding table: each transition
    // between length classes (0/63, 64/16383, 16384/(2^30-1), 2^30,
    // 2^62-1) must survive a full encode→decode cycle without loss
    // of value. The encoder picks minimum form; the decoder must
    // reconstruct the original integer regardless.
    const cases = [_]u64{
        0,
        63,
        64,
        16383,
        16384,
        1073741823,
        1073741824,
        4611686018427387903,
    };
    for (cases) |v| {
        var buf: [varint.max_len]u8 = undefined;
        const w = try varint.encode(&buf, v);
        const d = try varint.decode(buf[0..w]);
        try std.testing.expectEqual(v, d.value);
        try std.testing.expectEqual(@as(u8, @intCast(w)), d.bytes_read);
    }
}
