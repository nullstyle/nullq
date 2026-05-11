//! QUIC variable-length integer encoding (RFC 9000 §16).
//!
//! The two most-significant bits of the first byte encode log2 of the
//! length in bytes (00=1, 01=2, 10=4, 11=8). The remaining bits hold
//! the integer value in network byte order. Range: 0 .. 2^62 - 1.
//!
//! Decoders accept any valid length encoding for a given value;
//! `encode` produces the minimum length, while `encodeFixed` lets the
//! caller pin a specific length (useful for fields that need a
//! reserved size for in-place rewriting).

const std = @import("std");

/// Maximum value representable by a QUIC varint: 2^62 - 1.
pub const max_value: u64 = (1 << 62) - 1;

/// Maximum bytes a varint can occupy.
pub const max_len: u8 = 8;

/// Errors returned by varint encode/decode operations.
pub const Error = error{
    BufferTooSmall,
    InsufficientBytes,
    ValueTooLarge,
    InvalidLength,
};

/// Number of bytes needed to encode `value` minimally. Returns 0 if
/// `value` exceeds `max_value`.
pub fn encodedLen(value: u64) u8 {
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    if (value <= max_value) return 8;
    return 0;
}

/// Encode `value` minimally into the start of `dst`. Returns bytes
/// written.
pub fn encode(dst: []u8, value: u64) Error!usize {
    const len = encodedLen(value);
    if (len == 0) return Error.ValueTooLarge;
    return encodeFixed(dst, value, len);
}

/// Encode `value` using exactly `length` bytes. Length must be 1, 2,
/// 4, or 8, and `value` must fit in that length.
pub fn encodeFixed(dst: []u8, value: u64, length: u8) Error!usize {
    const tag: u8 = switch (length) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        else => return Error.InvalidLength,
    };
    const max_for_length: u64 = switch (length) {
        1 => (1 << 6) - 1,
        2 => (1 << 14) - 1,
        4 => (1 << 30) - 1,
        8 => max_value,
        // invariant: the prior switch above returns InvalidLength
        // for any other value, so we never reach this arm. Not
        // peer-reachable; `length` is a local that the caller
        // already validated above.
        else => unreachable,
    };
    if (value > max_for_length) return Error.ValueTooLarge;
    if (dst.len < length) return Error.BufferTooSmall;

    var i: u8 = length;
    while (i > 0) : (i -= 1) {
        const shift: u6 = @intCast((length - i) * 8);
        dst[i - 1] = @truncate(value >> shift);
    }
    dst[0] |= tag;
    return length;
}

/// Result of a successful varint decode: the integer value and the
/// number of bytes consumed from the input.
pub const Decoded = struct {
    value: u64,
    bytes_read: u8,
};

/// Decode a varint at the start of `src`.
pub fn decode(src: []const u8) Error!Decoded {
    if (src.len == 0) return Error.InsufficientBytes;
    const first = src[0];
    const length: u8 = @as(u8, 1) << @intCast(first >> 6);
    if (src.len < length) return Error.InsufficientBytes;

    var value: u64 = first & 0x3f;
    var i: u8 = 1;
    while (i < length) : (i += 1) {
        value = (value << 8) | src[i];
    }
    return .{ .value = value, .bytes_read = length };
}

// -- tests ---------------------------------------------------------------

test "encode/decode 1-byte: 37 (RFC 9000 §16)" {
    var buf: [1]u8 = undefined;
    const written = try encode(&buf, 37);
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqualSlices(u8, &.{0x25}, &buf);

    const d = try decode(&buf);
    try std.testing.expectEqual(@as(u64, 37), d.value);
    try std.testing.expectEqual(@as(u8, 1), d.bytes_read);
}

test "encode/decode 2-byte: 15293 (RFC 9000 §16)" {
    var buf: [2]u8 = undefined;
    const written = try encode(&buf, 15293);
    try std.testing.expectEqual(@as(usize, 2), written);
    try std.testing.expectEqualSlices(u8, &.{ 0x7b, 0xbd }, &buf);

    const d = try decode(&buf);
    try std.testing.expectEqual(@as(u64, 15293), d.value);
    try std.testing.expectEqual(@as(u8, 2), d.bytes_read);
}

test "encode/decode 4-byte: 494878333 (RFC 9000 §16)" {
    var buf: [4]u8 = undefined;
    const written = try encode(&buf, 494878333);
    try std.testing.expectEqual(@as(usize, 4), written);
    try std.testing.expectEqualSlices(u8, &.{ 0x9d, 0x7f, 0x3e, 0x7d }, &buf);

    const d = try decode(&buf);
    try std.testing.expectEqual(@as(u64, 494878333), d.value);
    try std.testing.expectEqual(@as(u8, 4), d.bytes_read);
}

test "encode/decode 8-byte: 151288809941952652 (RFC 9000 §16)" {
    var buf: [8]u8 = undefined;
    const written = try encode(&buf, 151288809941952652);
    try std.testing.expectEqual(@as(usize, 8), written);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c },
        &buf,
    );

    const d = try decode(&buf);
    try std.testing.expectEqual(@as(u64, 151288809941952652), d.value);
    try std.testing.expectEqual(@as(u8, 8), d.bytes_read);
}

test "decode accepts non-minimum 2-byte encoding of 37 (RFC 9000 §16)" {
    const d = try decode(&[_]u8{ 0x40, 0x25 });
    try std.testing.expectEqual(@as(u64, 37), d.value);
    try std.testing.expectEqual(@as(u8, 2), d.bytes_read);
}

test "encodedLen at boundaries" {
    try std.testing.expectEqual(@as(u8, 1), encodedLen(0));
    try std.testing.expectEqual(@as(u8, 1), encodedLen(63));
    try std.testing.expectEqual(@as(u8, 2), encodedLen(64));
    try std.testing.expectEqual(@as(u8, 2), encodedLen(16383));
    try std.testing.expectEqual(@as(u8, 4), encodedLen(16384));
    try std.testing.expectEqual(@as(u8, 4), encodedLen((1 << 30) - 1));
    try std.testing.expectEqual(@as(u8, 8), encodedLen(1 << 30));
    try std.testing.expectEqual(@as(u8, 8), encodedLen(max_value));
    try std.testing.expectEqual(@as(u8, 0), encodedLen(max_value + 1));
}

test "encode rejects values exceeding max" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(Error.ValueTooLarge, encode(&buf, max_value + 1));
}

test "encode rejects buffer too small" {
    var small: [3]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, encode(&small, 1 << 30));
}

test "decode rejects empty input" {
    try std.testing.expectError(Error.InsufficientBytes, decode(""));
}

test "decode rejects truncated 4-byte varint" {
    try std.testing.expectError(Error.InsufficientBytes, decode(&[_]u8{ 0x80, 0x00 }));
}

test "decode rejects truncated 8-byte varint" {
    try std.testing.expectError(Error.InsufficientBytes, decode(&[_]u8{ 0xc0, 0x00, 0x00, 0x00 }));
}

test "encodeFixed in 8 bytes pads correctly" {
    var buf: [8]u8 = undefined;
    const written = try encodeFixed(&buf, 37, 8);
    try std.testing.expectEqual(@as(usize, 8), written);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25 },
        &buf,
    );
    const d = try decode(&buf);
    try std.testing.expectEqual(@as(u64, 37), d.value);
}

test "encodeFixed rejects invalid length" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(Error.InvalidLength, encodeFixed(&buf, 0, 3));
    try std.testing.expectError(Error.InvalidLength, encodeFixed(&buf, 0, 0));
}

test "encodeFixed rejects value too large for length" {
    var buf: [8]u8 = undefined;
    // 64 (= 2^6) doesn't fit in 1 byte.
    try std.testing.expectError(Error.ValueTooLarge, encodeFixed(&buf, 64, 1));
    // 16384 (= 2^14) doesn't fit in 2 bytes.
    try std.testing.expectError(Error.ValueTooLarge, encodeFixed(&buf, 1 << 14, 2));
    // 2^30 doesn't fit in 4 bytes.
    try std.testing.expectError(Error.ValueTooLarge, encodeFixed(&buf, 1 << 30, 4));
}

test "round-trip across length boundaries" {
    const cases = [_]u64{
        0,                 1,                 62,        63,
        64,                65,                16382,     16383,
        16384,             16385,             (1 << 30) - 1,
        1 << 30,           (1 << 30) + 1,     (1 << 62) - 2,
        max_value,
    };
    for (cases) |v| {
        var buf: [max_len]u8 = undefined;
        const w = try encode(&buf, v);
        const d = try decode(buf[0..w]);
        try std.testing.expectEqual(v, d.value);
        try std.testing.expectEqual(@as(u8, @intCast(w)), d.bytes_read);
    }
}

test "round-trip: deterministic random" {
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    const rng = prng.random();
    var buf: [max_len]u8 = undefined;
    var i: usize = 0;
    while (i < 4096) : (i += 1) {
        // Mask the top 2 bits to stay within varint range.
        const v = rng.int(u64) & max_value;
        const w = try encode(&buf, v);
        const d = try decode(buf[0..w]);
        try std.testing.expectEqual(v, d.value);
    }
}

// -- fuzz harness --------------------------------------------------------
//
// `zig build fuzz` invokes the test binary with libFuzzer-equivalent
// coverage feedback. The property: any byte slice fed to `decode`
// either errors cleanly or returns a `Decoded` whose `bytes_read` does
// not exceed the input, whose `value` fits in `max_value`, and whose
// payload re-encodes to a byte-equal prefix when run through
// `encodeFixed` at the same length. Crashes / panics / unreachable
// reaches abort the harness. Invariant violations from `expectEqual`
// are minimized + saved to the corpus.

// Seed corpus targets the four legal varint widths (RFC 9000 §16) and
// each width's min/max boundary. Smith.slice reads a 4-byte LE length
// prefix, so each entry begins with that prefix; the remaining bytes
// are what the harness's `decode(input)` actually sees.
test "fuzz: varint decode/encode round-trip" {
    try std.testing.fuzz({}, fuzzVarintRoundTrip, .{
        .corpus = &.{
            // length=0 → input = "" (empty, decode returns InsufficientBytes)
            "\x00\x00\x00\x00",
            // length=1, byte 0x00 → 1-byte varint = 0
            "\x01\x00\x00\x00\x00",
            // length=1, byte 0x3f → 1-byte varint = 63 (max for length 1)
            "\x01\x00\x00\x00\x3f",
            // length=2, bytes 0x40 0x00 → non-minimal 2-byte = 0
            "\x02\x00\x00\x00\x40\x00",
            // length=2, bytes 0x40 0x40 → 2-byte = 64 (min meaningful 2-byte)
            "\x02\x00\x00\x00\x40\x40",
            // length=2, bytes 0x7f 0xff → 2-byte = 16383 (max for length 2)
            "\x02\x00\x00\x00\x7f\xff",
            // length=4, bytes 0x80 0x00 0x40 0x00 → 4-byte = 16384 (min meaningful)
            "\x04\x00\x00\x00\x80\x00\x40\x00",
            // length=4, bytes 0xbf 0xff 0xff 0xff → 4-byte = 2^30 - 1 (max for length 4)
            "\x04\x00\x00\x00\xbf\xff\xff\xff",
            // length=8, bytes 0xc0..0x40.. → 8-byte = 2^30 (min meaningful 8-byte)
            "\x08\x00\x00\x00\xc0\x00\x00\x00\x40\x00\x00\x00",
            // length=8, all 0xff → 8-byte = 2^62 - 1 (max varint value)
            "\x08\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
            // RFC 9000 Appendix A.1 worked example: 151288809941952652
            "\x08\x00\x00\x00\xc2\x19\x7c\x5e\xff\x14\xe8\x8c",
            // Truncated 4-byte varint (only 2 bytes of payload follow header)
            "\x02\x00\x00\x00\x80\x00",
        },
    });
}

fn fuzzVarintRoundTrip(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    const d = decode(input) catch return;

    // The decoder must never report consuming bytes beyond the input.
    try std.testing.expect(d.bytes_read <= input.len);
    // Decoded value must always fit in the QUIC v1 varint range.
    try std.testing.expect(d.value <= max_value);
    // Re-encode at the original length: the bytes must match.
    var rt_buf: [max_len]u8 = undefined;
    const w = try encodeFixed(&rt_buf, d.value, d.bytes_read);
    try std.testing.expectEqual(@as(usize, d.bytes_read), w);
    try std.testing.expectEqualSlices(u8, input[0..d.bytes_read], rt_buf[0..w]);

    // Cross-length round-trip property: pick a fuzzer-supplied value
    // and a fuzzer-supplied legal length (1, 2, 4, 8). Any value in
    // that length's representable range MUST round-trip through
    // `encodeFixed` -> `decode` losslessly. This exercises the same
    // canonicalization the wire-builder relies on for fields it pads
    // out (e.g. the Initial / Handshake length field that is
    // rewritten in place once the encrypted payload size is known).
    const length_choice: u8 = switch (smith.valueRangeAtMost(u8, 0, 3)) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };
    const max_for_length: u64 = switch (length_choice) {
        1 => (1 << 6) - 1,
        2 => (1 << 14) - 1,
        4 => (1 << 30) - 1,
        8 => max_value,
        else => unreachable,
    };
    const raw_value = smith.value(u64);
    const value = if (max_for_length == max_value)
        raw_value & max_value
    else
        raw_value % (max_for_length + 1);

    var fixed_buf: [max_len]u8 = undefined;
    const written = try encodeFixed(&fixed_buf, value, length_choice);
    try std.testing.expectEqual(@as(usize, length_choice), written);
    const decoded = try decode(fixed_buf[0..written]);
    try std.testing.expectEqual(value, decoded.value);
    try std.testing.expectEqual(length_choice, decoded.bytes_read);
    // Truncation: dropping the last byte (when length > 1) must
    // surface as InsufficientBytes — never as a silent under-read.
    if (length_choice > 1) {
        try std.testing.expectError(
            Error.InsufficientBytes,
            decode(fixed_buf[0 .. written - 1]),
        );
    }
}
