//! QUIC packet number truncation and recovery.
//!
//! Packet numbers are 62-bit integers that increment monotonically per
//! packet number space (initial / handshake / application). On the
//! wire they're truncated to 1..4 bytes; the receiver reconstructs the
//! full PN using the largest already-received PN as a reference point.
//!
//! References:
//! - RFC 9000 §17.1 — packet number encoding (1..4 bytes).
//! - RFC 9000 §A.2 — sample packet number encoding.
//! - RFC 9000 §A.3 — sample packet number decoding (the recovery
//!   algorithm we implement here in `decode`).

const std = @import("std");

/// Maximum packet number value: 2^62 - 1 (per RFC 9000 §12.3).
pub const max_value: u64 = (1 << 62) - 1;

/// Errors returned by packet-number encode/decode operations.
pub const Error = error{
    BufferTooSmall,
    InsufficientBytes,
    InvalidLength,
    /// The gap between `pn_to_send` and `largest_acked` exceeds the
    /// 4-byte representable range (~2^31 unacked packets). In a
    /// healthy connection this never happens; if it does, the
    /// connection is dead anyway.
    UnacknowledgedTooFar,
};

/// Number of bytes needed to encode `pn_to_send` such that the
/// receiver — knowing `largest_acked` — can unambiguously recover it.
///
/// Per RFC 9000 §A.2: encode at least `1 + log2(2 * num_unacked)` bits.
/// Returns 1, 2, 3, or 4. Errors only if more than 4 bytes are needed,
/// which would require >2^31 unacked packets — pathological.
pub fn encodedLength(pn_to_send: u64, largest_acked: ?u64) Error!u8 {
    // RFC 9000 §A.2: the receiver treats a freshly-initialized PN
    // space as if a packet one less than the smallest possible PN had
    // been acked, so num_unacked = pn_to_send + 1 in that case.
    const num_unacked: u64 = if (largest_acked) |la| blk: {
        if (pn_to_send <= la) return Error.InvalidLength;
        break :blk pn_to_send - la;
    } else pn_to_send + 1;

    var bits: u8 = 1;
    var range: u64 = 2;
    while (range < 2 *| num_unacked) : (bits += 1) {
        if (bits >= 32) return Error.UnacknowledgedTooFar;
        range <<= 1;
    }
    if (bits <= 8) return 1;
    if (bits <= 16) return 2;
    if (bits <= 24) return 3;
    if (bits <= 32) return 4;
    return Error.UnacknowledgedTooFar;
}

/// Write the low `length` bytes of `pn` to `dst` in network byte
/// order. `length` must be 1..4.
pub fn encode(dst: []u8, pn: u64, length: u8) Error!void {
    if (length < 1 or length > 4) return Error.InvalidLength;
    if (dst.len < length) return Error.BufferTooSmall;

    var i: u8 = length;
    while (i > 0) : (i -= 1) {
        const shift: u6 = @intCast((length - i) * 8);
        dst[i - 1] = @truncate(pn >> shift);
    }
}

/// Read `length` bytes from `src` as a big-endian unsigned integer.
/// `length` must be 1..4.
pub fn readTruncated(src: []const u8, length: u8) Error!u64 {
    if (length < 1 or length > 4) return Error.InvalidLength;
    if (src.len < length) return Error.InsufficientBytes;
    var v: u64 = 0;
    var i: u8 = 0;
    while (i < length) : (i += 1) {
        v = (v << 8) | src[i];
    }
    return v;
}

/// Recover the full 62-bit packet number from a truncated value, the
/// number of bytes it was encoded in, and the largest PN already
/// successfully decrypted in this PN space.
///
/// Implements RFC 9000 §A.3 verbatim, with saturating arithmetic on
/// the boundary checks so 0-near and 2^62-near values don't underflow.
pub fn decode(truncated: u64, length: u8, largest_pn: u64) Error!u64 {
    if (length < 1 or length > 4) return Error.InvalidLength;

    const pn_nbits: u6 = @intCast(@as(u32, length) * 8);
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;

    // expected_pn = largest_pn + 1, but saturate at max_value so a
    // largest_pn at the top of the range doesn't wrap past 2^62.
    const expected_pn: u64 = if (largest_pn >= max_value) max_value else largest_pn + 1;

    const candidate: u64 = (expected_pn & ~pn_mask) | (truncated & pn_mask);

    // §A.3 wraparound rules. The lower-band check ("candidate is more
    // than pn_hwin behind expected, so it must have wrapped forward")
    // is only meaningful when there *is* a band that far behind —
    // i.e. expected_pn >= pn_hwin. Using saturating subtraction here
    // would spuriously fire when expected_pn is small, mapping
    // candidate=0 to candidate+pn_win.
    if (expected_pn >= pn_hwin and
        candidate <= expected_pn - pn_hwin and
        candidate < max_value + 1 - pn_win)
    {
        return candidate + pn_win;
    }
    // Upper-band: expected_pn + pn_hwin can't overflow u64 in practice
    // (max_value is 2^62 - 1; pn_hwin is at most 2^31). Saturating
    // addition is defense in depth.
    if (candidate > expected_pn +| pn_hwin and candidate >= pn_win) {
        return candidate - pn_win;
    }
    return candidate;
}

// -- tests ---------------------------------------------------------------

test "encode/decode: RFC 9000 §A.3 example (largest 0xa82f30ea, truncated 0x9b32)" {
    // The canonical §A.3 worked example.
    const recovered = try decode(0x9b32, 2, 0xa82f30ea);
    try std.testing.expectEqual(@as(u64, 0xa82f9b32), recovered);
}

test "encode: RFC 9000 §A.2 — 0xac5c02 with largest_acked 0xabe8b1 needs 2 bytes" {
    // The §A.2 worked example: 1 byte would be ambiguous.
    const len = try encodedLength(0xac5c02, 0xabe8b1);
    try std.testing.expect(len >= 2);
}

test "encode/decode round-trip via wire bytes" {
    var buf: [4]u8 = undefined;
    try encode(&buf, 0xa82f9b32, 2);
    try std.testing.expectEqualSlices(u8, &.{ 0x9b, 0x32 }, buf[0..2]);

    const t = try readTruncated(buf[0..2], 2);
    try std.testing.expectEqual(@as(u64, 0x9b32), t);
    const recovered = try decode(t, 2, 0xa82f30ea);
    try std.testing.expectEqual(@as(u64, 0xa82f9b32), recovered);
}

test "decode: reorder within window stays in window" {
    // largest = 100; truncated = 0x12 = 18 with 1 byte.
    // Expected = 101; candidate = 18; |candidate - expected| = 83 < 128.
    // Result: 18 (treated as a reordered older packet, dedup'd by caller).
    const recovered = try decode(0x12, 1, 100);
    try std.testing.expectEqual(@as(u64, 18), recovered);
}

test "decode: candidate snaps forward by a window when too far behind" {
    // largest = 200; truncated = 0x12 = 18 with 1 byte.
    // Expected = 201; candidate = 18; |201 - 18| = 183 > 128.
    // Result: 18 + 256 = 274.
    const recovered = try decode(0x12, 1, 200);
    try std.testing.expectEqual(@as(u64, 274), recovered);
}

test "decode: candidate snaps backward by a window when too far ahead" {
    // largest = 1023; truncated = 0xff with 1 byte.
    // Expected = 1024; candidate = (1024 & ~0xff) | 0xff = 1023.
    // Wait — 1023 isn't > expected + 128 (1152). Actually let's pick
    // a clearer case: largest = 1024, truncated = 0x00.
    // Expected = 1025; candidate = (1025 & ~0xff) | 0x00 = 1024.
    // 1024 isn't > 1025 + 128 = 1153 either. The "subtract pn_win"
    // branch only fires when the wrap would push candidate near the
    // top of a window above expected. Try largest = 1280, truncated = 0xff.
    // Expected = 1281; candidate = (1281 & ~0xff) | 0xff = 1280 | 0xff = wait,
    // 1281 = 0x501; 1281 & ~0xff = 0x500 = 1280; | 0xff = 1535.
    // Check: 1535 > 1281 + 128 = 1409? YES. And 1535 >= 256? YES. Result: 1535 - 256 = 1279.
    const recovered = try decode(0xff, 1, 1280);
    try std.testing.expectEqual(@as(u64, 1279), recovered);
}

test "decode: at PN 0, never underflows" {
    // First-ever packet: largest_pn = 0 is treated as "have not received any",
    // but the receiver still has to handle the boundary. Here we pretend
    // largest = 0 and a 1-byte truncated of 0x00 arrives.
    const recovered = try decode(0x00, 1, 0);
    try std.testing.expectEqual(@as(u64, 0), recovered);
}

test "decode: at top of PN range, never overflows" {
    // Near the 2^62 ceiling. largest = max_value - 5, truncated = max_value & 0xff.
    const recovered = try decode(max_value & 0xff, 1, max_value - 5);
    try std.testing.expectEqual(@as(u64, max_value), recovered);
}

test "decode rejects invalid length" {
    try std.testing.expectError(Error.InvalidLength, decode(0, 0, 0));
    try std.testing.expectError(Error.InvalidLength, decode(0, 5, 0));
}

test "encode rejects invalid length and short buffer" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(Error.InvalidLength, encode(&buf, 0, 0));
    try std.testing.expectError(Error.InvalidLength, encode(&buf, 0, 5));
    var small: [1]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, encode(&small, 0, 2));
}

test "readTruncated rejects invalid length and short input" {
    try std.testing.expectError(Error.InvalidLength, readTruncated(&[_]u8{}, 0));
    try std.testing.expectError(Error.InsufficientBytes, readTruncated(&[_]u8{0x12}, 2));
}

test "encodedLength baseline cases" {
    // Fresh PN space: largest_acked = null.
    try std.testing.expectEqual(@as(u8, 1), try encodedLength(0, null));
    try std.testing.expectEqual(@as(u8, 1), try encodedLength(127, null));
    try std.testing.expectEqual(@as(u8, 2), try encodedLength(128, null));

    // With acks: encoding shrinks as the gap shrinks.
    try std.testing.expectEqual(@as(u8, 1), try encodedLength(11, 10));
    try std.testing.expectEqual(@as(u8, 2), try encodedLength(1000, 800));
    try std.testing.expectEqual(@as(u8, 3), try encodedLength(0x123456, 0x100000));
}

test "encode then decode round-trip with realistic gaps" {
    var prng = std.Random.DefaultPrng.init(0xbeef);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 1024) : (i += 1) {
        const largest_pn = rng.int(u64) & max_value;
        // gap of 1..1024 packets ahead, well within the §A.2 window.
        const gap = (rng.int(u64) % 1024) + 1;
        const pn_to_send = if (largest_pn + gap <= max_value) largest_pn + gap else largest_pn;
        if (pn_to_send <= largest_pn) continue;

        const len = try encodedLength(pn_to_send, largest_pn);
        var buf: [4]u8 = undefined;
        try encode(&buf, pn_to_send, len);
        const t = try readTruncated(buf[0..len], len);
        const recovered = try decode(t, len, largest_pn);
        try std.testing.expectEqual(pn_to_send, recovered);
    }
}
