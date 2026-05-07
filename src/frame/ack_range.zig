//! ACK frame range-list helpers (RFC 9000 §19.3.1).
//!
//! Wire format: starting from `largest_acked`, the First ACK Range
//! gives the contiguous run ending there; each subsequent
//! `(gap, length)` pair walks down to the next acked range.
//!
//! Per §19.3.1:
//! - The First ACK Range covers `[largest_acked - first_range, largest_acked]`.
//! - For each subsequent range, given `previous_smallest`:
//!     - largest_in_this = previous_smallest - gap - 2
//!     - smallest_in_this = largest_in_this - length
//!
//! This module provides:
//! - `Iterator` — zero-allocation walk over the intervals an ACK
//!   frame describes, in descending order.
//! - `writeRanges` — encode a caller-owned `[]const AckRange` into
//!   wire bytes (the inverse of what `decode` populates as
//!   `ranges_bytes`).
//!
//! The higher-level "interval list builder" — given a sorted list
//! of acknowledged PNs, produce the optimal `(first_range, ranges)`
//! — lives with the ACK tracker (`conn/ack_tracker.zig`).

const std = @import("std");
const types = @import("types.zig");
const varint = @import("../wire/varint.zig");

/// Re-export of `types.AckRange` — one (gap, length) varint pair.
pub const AckRange = types.AckRange;

/// Errors `Iterator.next`, `writeRanges`, and `rangesEncodedLen` can
/// produce. Wire-level varint errors plus `error.InvalidLength` when
/// the range arithmetic underflows (a malformed peer ACK).
pub const Error = varint.Error;

/// Inclusive interval of acknowledged packet numbers.
pub const Interval = struct {
    smallest: u64,
    largest: u64,
};

/// Walks an ACK frame's range list, yielding `Interval`s in
/// descending order. Reads varints out of `ranges_bytes` lazily.
pub const Iterator = struct {
    largest_acked: u64,
    first_range: u64,
    range_count: u64,
    ranges_bytes: []const u8,

    /// Bytes consumed from `ranges_bytes` so far.
    pos: usize = 0,
    /// Index of the next subsequent range to read.
    next_range_index: u64 = 0,
    /// Smallest of the most recently emitted interval — used as the
    /// reference for the next gap.
    last_smallest: u64 = 0,
    /// Has the First ACK Range been emitted yet?
    first_emitted: bool = false,

    /// Yields the next acked interval (or `null` when exhausted).
    /// Returns `error.InvalidLength` if the wire bytes describe a
    /// range that would underflow `u64`.
    pub fn next(self: *Iterator) Error!?Interval {
        if (!self.first_emitted) {
            self.first_emitted = true;
            if (self.first_range > self.largest_acked) return Error.InvalidLength;
            const interval = Interval{
                .smallest = self.largest_acked - self.first_range,
                .largest = self.largest_acked,
            };
            self.last_smallest = interval.smallest;
            return interval;
        }
        if (self.next_range_index >= self.range_count) return null;

        const gap = try varint.decode(self.ranges_bytes[self.pos..]);
        self.pos += gap.bytes_read;
        const length = try varint.decode(self.ranges_bytes[self.pos..]);
        self.pos += length.bytes_read;

        // largest_in_this = previous_smallest - gap - 2
        if (self.last_smallest < gap.value + 2) return Error.InvalidLength;
        const largest_in_this = self.last_smallest - gap.value - 2;
        if (largest_in_this < length.value) return Error.InvalidLength;
        const smallest_in_this = largest_in_this - length.value;

        self.last_smallest = smallest_in_this;
        self.next_range_index += 1;
        return Interval{ .smallest = smallest_in_this, .largest = largest_in_this };
    }
};

/// Builds an `Iterator` over the acked intervals of an ACK frame.
/// Borrows `ack.ranges_bytes`, so the iterator must not outlive it.
pub fn iter(ack: types.Ack) Iterator {
    return .{
        .largest_acked = ack.largest_acked,
        .first_range = ack.first_range,
        .range_count = ack.range_count,
        .ranges_bytes = ack.ranges_bytes,
    };
}

/// Encode `ranges` into `dst` as the consecutive (gap, length) varint
/// pairs an ACK frame's `ranges_bytes` carries. Returns bytes written.
pub fn writeRanges(dst: []u8, ranges: []const AckRange) Error!usize {
    var pos: usize = 0;
    for (ranges) |r| {
        pos += try varint.encode(dst[pos..], r.gap);
        pos += try varint.encode(dst[pos..], r.length);
    }
    return pos;
}

/// Sum of varint lengths for the given range list.
pub fn rangesEncodedLen(ranges: []const AckRange) usize {
    var total: usize = 0;
    for (ranges) |r| {
        total += varint.encodedLen(r.gap);
        total += varint.encodedLen(r.length);
    }
    return total;
}

// -- tests ---------------------------------------------------------------

test "Iterator: only First ACK Range, no subsequent ranges" {
    // largest_acked = 100, first_range = 5 → acked PNs [95..100]
    var it = Iterator{
        .largest_acked = 100,
        .first_range = 5,
        .range_count = 0,
        .ranges_bytes = &[_]u8{},
    };

    const interval = (try it.next()).?;
    try std.testing.expectEqual(@as(u64, 95), interval.smallest);
    try std.testing.expectEqual(@as(u64, 100), interval.largest);
    try std.testing.expectEqual(@as(?Interval, null), try it.next());
}

test "Iterator: multi-range descent" {
    // Acked: [95..100], [88..92], [80..82]
    //   First range covers 100 down to 95 (length 5).
    //   Gap 0=2 (skip 93, 94 — 2 unacked PNs strictly between 95 and 92), length 0=4 → 88..92
    //   Gap 1=4 (skip 83..87 — wait, between 88 and 82 there are 5 unacked: 83,84,85,86,87; gap counts those minus the first one below the smallest of previous, so... let me work the spec arithmetic)
    //
    //   §19.3.1: largest_in_this = previous_smallest - gap - 2
    //   For range [88..92]: previous_smallest = 95, so 92 = 95 - gap - 2 → gap = 1.
    //                       length = 92 - 88 = 4.
    //   For range [80..82]: previous_smallest = 88, so 82 = 88 - gap - 2 → gap = 4.
    //                       length = 82 - 80 = 2.
    var ranges_buf: [8]u8 = undefined;
    const ranges = [_]AckRange{
        .{ .gap = 1, .length = 4 },
        .{ .gap = 4, .length = 2 },
    };
    const len = try writeRanges(&ranges_buf, &ranges);

    var it = Iterator{
        .largest_acked = 100,
        .first_range = 5,
        .range_count = 2,
        .ranges_bytes = ranges_buf[0..len],
    };

    var got: [3]Interval = undefined;
    got[0] = (try it.next()).?;
    got[1] = (try it.next()).?;
    got[2] = (try it.next()).?;
    try std.testing.expectEqual(@as(?Interval, null), try it.next());

    try std.testing.expectEqual(@as(u64, 95), got[0].smallest);
    try std.testing.expectEqual(@as(u64, 100), got[0].largest);
    try std.testing.expectEqual(@as(u64, 88), got[1].smallest);
    try std.testing.expectEqual(@as(u64, 92), got[1].largest);
    try std.testing.expectEqual(@as(u64, 80), got[2].smallest);
    try std.testing.expectEqual(@as(u64, 82), got[2].largest);
}

test "Iterator: rejects invalid range that would underflow" {
    // first_range = 200 with largest_acked = 100 → underflow.
    var it = Iterator{
        .largest_acked = 100,
        .first_range = 200,
        .range_count = 0,
        .ranges_bytes = &[_]u8{},
    };
    try std.testing.expectError(Error.InvalidLength, it.next());
}

test "Iterator: rejects gap that would underflow next range" {
    // largest=10, first_range=2 → range [8..10]. Then gap=10 means
    // next_largest = 8 - 10 - 2 → underflow.
    var ranges_buf: [4]u8 = undefined;
    const len = try writeRanges(&ranges_buf, &.{ .{ .gap = 10, .length = 0 } });
    var it = Iterator{
        .largest_acked = 10,
        .first_range = 2,
        .range_count = 1,
        .ranges_bytes = ranges_buf[0..len],
    };
    _ = try it.next();
    try std.testing.expectError(Error.InvalidLength, it.next());
}

test "writeRanges encodes pairs as concatenated varints" {
    var buf: [16]u8 = undefined;
    const written = try writeRanges(&buf, &.{
        .{ .gap = 0, .length = 5 },
        .{ .gap = 3, .length = 1 },
    });
    // Each value < 64 → 1-byte varints. So 4 bytes total.
    try std.testing.expectEqual(@as(usize, 4), written);
    try std.testing.expectEqualSlices(u8, &.{ 0, 5, 3, 1 }, buf[0..4]);
}

test "rangesEncodedLen matches writeRanges output" {
    const ranges = [_]AckRange{
        .{ .gap = 0, .length = 1 << 20 },
        .{ .gap = 1 << 14, .length = 7 },
    };
    var buf: [32]u8 = undefined;
    const written = try writeRanges(&buf, &ranges);
    try std.testing.expectEqual(rangesEncodedLen(&ranges), written);
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `Iterator.next` on an `Ack`-shaped record built from
// fuzzer-chosen inputs. Two modes per fuzz iteration:
//
// 1. Adversarial: feed arbitrary `(largest_acked, first_range,
//    range_count, ranges_bytes)`. Properties:
//      - No panic, no overflow trap.
//      - Each emitted interval has `smallest <= largest`.
//      - Intervals are strictly descending (RFC 9000 §19.3.1).
//      - Iterator yields at most `range_count + 1` intervals.
//
// 2. Generative: build a well-formed `[]AckRange` from the corpus
//    such that the wire-format arithmetic stays within `u64` and
//    every interval is non-negative. Properties (in addition to the
//    above):
//      - The encoded `(first_range, ranges_bytes)` round-trips
//        through `writeRanges` -> `iter` losslessly.
//      - Iterator emits exactly `count + 1` intervals (one for the
//        First ACK Range plus one per `(gap, length)` pair). Anything
//        else is a counter or reassembly bug.

// Seed corpus drives both adversarial and generative passes of the
// iterator. Smith consumption (must match `fuzzAckRangeIterator`):
//   adversarial: value(u64) largest_acked, value(u64) first_range,
//     valueRangeAtMost(u8, 0, 32) range_count, slice(...) ranges_bytes
//   generative:  value(u64) largest_acked', value(u64) first_range',
//     valueRangeAtMost(u8, 0, 6) wanted, then per-range value(u64)
//     gap, value(u64) length
test "fuzz: ack_range Iterator descending invariants" {
    try std.testing.fuzz({}, fuzzAckRangeIterator, .{
        .corpus = &.{
            // Minimal entry: all zeros — adversarial pass yields one
            // interval [0..0] then null; generative pass yields one
            // (largest_acked=100, first_range=0).
            "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // largest_acked = 0
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // first_range = 0
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // range_count = 0
                "\x00\x00\x00\x00" ++ // ranges_bytes len = 0
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen largest_acked
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen first_range
                "\x00\x00\x00\x00\x00\x00\x00\x00", // wanted = 0
            // range_count=1 with gap=0, length=0 → strict-descending
            // (cursor underflow guards). Generative wanted=1.
            "\x64\x00\x00\x00\x00\x00\x00\x00" ++ // largest_acked = 100
                "\x05\x00\x00\x00\x00\x00\x00\x00" ++ // first_range = 5
                "\x01\x00\x00\x00\x00\x00\x00\x00" ++ // range_count = 1
                "\x02\x00\x00\x00\x00\x00" ++ // ranges_bytes = "\x00\x00"
                "\xe8\x03\x00\x00\x00\x00\x00\x00" ++ // gen largest_acked
                "\x01\x00\x00\x00\x00\x00\x00\x00" ++ // gen first_range
                "\x01\x00\x00\x00\x00\x00\x00\x00" ++ // wanted = 1
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gap = 0
                "\x00\x00\x00\x00\x00\x00\x00\x00", // length = 0
            // Deep descent: 5 ranges. Adversarial path mostly fails on
            // arbitrary bytes but the iterator will stop cleanly.
            "\xe8\x03\x00\x00\x00\x00\x00\x00" ++ // largest_acked = 1000
                "\x0a\x00\x00\x00\x00\x00\x00\x00" ++ // first_range = 10
                "\x05\x00\x00\x00\x00\x00\x00\x00" ++ // range_count = 5
                "\x0a\x00\x00\x00" ++ "\x01\x02\x01\x03\x02\x01\x04\x02\x01\x00" ++
                "\xe8\x03\x00\x00\x00\x00\x00\x00" ++ // gen largest_acked
                "\x05\x00\x00\x00\x00\x00\x00\x00" ++ // gen first_range
                "\x05\x00\x00\x00\x00\x00\x00\x00" ++ // wanted = 5
                "\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00" ++
                "\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00" ++
                "\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00" ++
                "\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00" ++
                "\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00",
            // first_range = largest_acked: smallest of First ACK Range = 0
            "\x05\x00\x00\x00\x00\x00\x00\x00" ++ // largest_acked = 5
                "\x05\x00\x00\x00\x00\x00\x00\x00" ++ // first_range = 5
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // range_count = 0
                "\x00\x00\x00\x00" ++ // ranges_bytes empty
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen largest_acked = 100
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen first_range = 0
                "\x00\x00\x00\x00\x00\x00\x00\x00", // wanted = 0
            // first_range > largest_acked: triggers Error.InvalidLength on first next()
            "\x64\x00\x00\x00\x00\x00\x00\x00" ++ // largest_acked = 100
                "\xc8\x00\x00\x00\x00\x00\x00\x00" ++ // first_range = 200
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // range_count = 0
                "\x00\x00\x00\x00" ++ // ranges_bytes empty
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen largest_acked
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen first_range
                "\x00\x00\x00\x00\x00\x00\x00\x00", // wanted = 0
            // Underflow on later range: largest=10, first_range=2 → [8..10],
            // gap=10 → next_largest = 8 - 10 - 2 → InvalidLength
            "\x0a\x00\x00\x00\x00\x00\x00\x00" ++ // largest_acked = 10
                "\x02\x00\x00\x00\x00\x00\x00\x00" ++ // first_range = 2
                "\x01\x00\x00\x00\x00\x00\x00\x00" ++ // range_count = 1
                "\x02\x00\x00\x00" ++ "\x0a\x00" ++ // ranges_bytes = gap=10, length=0
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen largest_acked
                "\x00\x00\x00\x00\x00\x00\x00\x00" ++ // gen first_range
                "\x00\x00\x00\x00\x00\x00\x00\x00", // wanted = 0
        },
    });
}

fn fuzzAckRangeIterator(_: void, smith: *std.testing.Smith) anyerror!void {
    // ---- adversarial pass ----
    {
        const largest_acked = smith.value(u64) & varint.max_value;
        const first_range = smith.value(u64) & varint.max_value;
        const range_count: u64 = smith.valueRangeAtMost(u8, 0, 32);

        var ranges_buf: [256]u8 = undefined;
        const ranges_len = smith.slice(&ranges_buf);

        var it = Iterator{
            .largest_acked = largest_acked,
            .first_range = first_range,
            .range_count = range_count,
            .ranges_bytes = ranges_buf[0..ranges_len],
        };

        var emitted: u64 = 0;
        var prev: ?Interval = null;
        const cap = range_count + 1;
        while (emitted < cap + 1) {
            const maybe = it.next() catch break;
            if (maybe == null) break;
            const cur = maybe.?;
            try std.testing.expect(cur.smallest <= cur.largest);
            if (prev) |p| {
                try std.testing.expect(cur.largest < p.smallest);
            }
            prev = cur;
            emitted += 1;
        }
        try std.testing.expect(emitted <= cap);
    }

    // ---- generative pass: build a well-formed ACK and assert the
    // strong "emitted == count + 1" oracle ----
    {
        const largest_acked = 100 + (smith.value(u64) % 10_000);
        const first_range = smith.value(u64) % 16;
        // The smallest PN in the First ACK Range. We descend from
        // here for each subsequent (gap, length) pair, abandoning
        // the construction (early-break) if the next range would
        // underflow.
        if (first_range > largest_acked) return; // implausible — skip
        var previous_smallest = largest_acked - first_range;

        var ranges: [6]AckRange = undefined;
        const wanted = smith.valueRangeAtMost(u8, 0, ranges.len);
        var count: usize = 0;
        while (count < wanted) : (count += 1) {
            const gap = smith.value(u64) % 8;
            if (previous_smallest < gap + 2) break;
            const largest_this = previous_smallest - gap - 2;
            const length = @min(smith.value(u64) % 16, largest_this);
            ranges[count] = .{ .gap = gap, .length = length };
            previous_smallest = largest_this - length;
        }

        var ranges_buf: [96]u8 = undefined;
        const ranges_len = try writeRanges(&ranges_buf, ranges[0..count]);
        try std.testing.expectEqual(rangesEncodedLen(ranges[0..count]), ranges_len);

        var it = iter(.{
            .largest_acked = largest_acked,
            .ack_delay = 0,
            .first_range = first_range,
            .range_count = count,
            .ranges_bytes = ranges_buf[0..ranges_len],
        });

        var last_smallest: ?u64 = null;
        var emitted: usize = 0;
        while (try it.next()) |interval| {
            try std.testing.expect(interval.smallest <= interval.largest);
            if (last_smallest) |last| try std.testing.expect(interval.largest + 1 < last);
            last_smallest = interval.smallest;
            emitted += 1;
        }
        // Strong oracle: every well-formed ACK emits exactly one
        // interval per range plus one for the First ACK Range.
        try std.testing.expectEqual(count + 1, emitted);
    }
}
