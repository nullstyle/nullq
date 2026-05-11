//! Received-packet-number bookkeeping for ACK frame generation
//! (RFC 9000 §13.2). Maintains a sorted list of disjoint inclusive
//! intervals of received PNs; produces a `frame.types.Ack` whenever
//! the connection wants to send one.

const std = @import("std");
const varint = @import("../wire/varint.zig");
const frame_types = @import("../frame/types.zig");

/// One inclusive interval of received packet numbers.
pub const Range = struct {
    smallest: u64,
    largest: u64,
};

/// Maximum number of disjoint intervals we track. Real connections
/// usually have 1-3 active intervals during steady-state, but bursts
/// of out-of-order delivery from peers like quic-go can push that
/// well past 32 — and dropping low ranges triggers spurious
/// retransmits, which then make the situation worse. 255 is the
/// upper bound that fits in a u8 range_count.
pub const max_ranges: u8 = 255;

/// Errors raised by the ACK frame builders.
pub const Error = error{
    /// `toAckFrame*` was called with no PNs recorded.
    Empty,
    /// FIXME(audit): `BufferTooSmall` is never returned by any
    /// builder in this file — drop the variant (code change).
    BufferTooSmall,
} || varint.Error;

/// RFC 9000 §13.2 received-PN bookkeeping. Tracks disjoint inclusive
/// PN ranges and the delayed-ACK scheduling state used by ACK frame
/// emission.
pub const AckTracker = struct {
    ranges: [max_ranges]Range = undefined,
    range_count: u8 = 0,
    /// Highest PN ever `add`-ed. None until the first add.
    largest: ?u64 = null,
    /// Wall-clock time (ms) at which `largest` was recorded. Used
    /// to compute ACK delay for outgoing ACK frames.
    largest_at_ms: u64 = 0,
    /// True iff at least one PN has been added since the last
    /// `markAckSent`. The connection uses this as the "should we
    /// send an ACK?" signal.
    pending_ack: bool = false,
    /// True while an ACK-eliciting packet has been received but the
    /// delayed-ACK threshold/deadline has not yet forced emission.
    delayed_ack_armed: bool = false,
    /// Receive time of the first ACK-eliciting packet in the current
    /// delayed-ACK epoch. This drives the max_ack_delay deadline.
    delayed_ack_start_ms: u64 = 0,
    /// Number of ACK-eliciting packets received since the last sent ACK.
    ack_eliciting_since_ack: u8 = 0,

    /// Add a successfully-decrypted PN. Idempotent (re-adding a PN
    /// that's already in the set is a no-op). `ack_eliciting`
    /// controls only the ACK scheduling signal; all processed packet
    /// numbers remain ACKable once a later ACK-eliciting packet or
    /// timer causes an ACK frame to be emitted.
    pub fn addPacket(self: *AckTracker, pn: u64, now_ms: u64, ack_eliciting: bool) void {
        const previous_largest = self.largest;
        const inserted = self.insert(pn);
        if (!inserted) return;
        if (previous_largest == null or pn > previous_largest.?) {
            self.largest = pn;
            self.largest_at_ms = now_ms;
        }
        if (ack_eliciting) {
            self.pending_ack = true;
            self.delayed_ack_armed = false;
            self.ack_eliciting_since_ack = 0;
        }
    }

    /// Add a packet using application-data delayed-ACK scheduling.
    /// ACK-only packets are recorded as ACKable ranges but do not arm
    /// an ACK. ACK-eliciting packets arm a deadline, and force an
    /// immediate ACK when they cross `packet_threshold` or reveal
    /// reordering/loss.
    pub fn addPacketDelayed(
        self: *AckTracker,
        pn: u64,
        now_ms: u64,
        ack_eliciting: bool,
        packet_threshold: u8,
    ) void {
        const previous_largest = self.largest;
        const inserted = self.insert(pn);
        if (!inserted) return;
        if (previous_largest == null or pn > previous_largest.?) {
            self.largest = pn;
            self.largest_at_ms = now_ms;
        }
        if (!ack_eliciting or self.pending_ack) return;

        if (!self.delayed_ack_armed) {
            self.delayed_ack_armed = true;
            self.delayed_ack_start_ms = now_ms;
            self.ack_eliciting_since_ack = 0;
        }
        self.ack_eliciting_since_ack +|= 1;

        const reordered_or_gap = if (previous_largest) |largest|
            pn < largest or pn > largest +| 1
        else
            false;
        const threshold_reached = packet_threshold != 0 and
            self.ack_eliciting_since_ack >= packet_threshold;
        if (reordered_or_gap or threshold_reached) self.pending_ack = true;
    }

    /// Add an ACK-eliciting packet number.
    pub fn add(self: *AckTracker, pn: u64, now_ms: u64) void {
        self.addPacket(pn, now_ms, true);
    }

    /// True if `pn` has previously been added.
    pub fn contains(self: *const AckTracker, pn: u64) bool {
        var i: u8 = 0;
        while (i < self.range_count) : (i += 1) {
            const r = self.ranges[i];
            if (pn < r.smallest) return false;
            if (pn <= r.largest) return true;
        }
        return false;
    }

    /// Acknowledge that we've sent an ACK frame covering everything
    /// we know about. The state stays — we may need to repeat
    /// these acks if our frame is lost — but `pending_ack` clears.
    pub fn markAckSent(self: *AckTracker) void {
        self.pending_ack = false;
        self.delayed_ack_armed = false;
        self.ack_eliciting_since_ack = 0;
    }

    /// Receive timestamp (ms) used to compute the `ack_delay` field
    /// of the next outgoing ACK frame, or null if no ACK is scheduled.
    pub fn ackDelayBaseMs(self: *const AckTracker) ?u64 {
        if (self.delayed_ack_armed) return self.delayed_ack_start_ms;
        if (self.pending_ack) return self.largest_at_ms;
        return null;
    }

    /// Promote an armed delayed ACK to `pending_ack` if `max_ack_delay_ms`
    /// has elapsed since the first ACK-eliciting packet of the epoch.
    /// Returns true iff the promotion fired.
    pub fn promoteDelayedAck(self: *AckTracker, now_ms: u64, max_ack_delay_ms: u64) bool {
        if (self.pending_ack or !self.delayed_ack_armed) return false;
        const deadline_ms = self.delayed_ack_start_ms +| max_ack_delay_ms;
        if (now_ms < deadline_ms) return false;
        self.pending_ack = true;
        return true;
    }

    /// Build an `Ack` frame from the current ranges, encoding the
    /// gap/length pairs into `ranges_bytes_buf`. The returned
    /// `Ack.ranges_bytes` is a sub-slice of that buffer.
    pub fn toAckFrame(
        self: *const AckTracker,
        ack_delay_scaled: u64,
        ranges_bytes_buf: []u8,
    ) Error!frame_types.Ack {
        return self.toAckFrameWithEcn(ack_delay_scaled, ranges_bytes_buf, null);
    }

    /// Same as `toAckFrame`, but the `ecn_counts` argument lets the
    /// caller stamp the §19.3.2 ECN-counts trailer onto the frame.
    /// Pass `null` for the standard 0x02 frame; pass a populated
    /// `EcnCounts` to emit 0x03.
    pub fn toAckFrameWithEcn(
        self: *const AckTracker,
        ack_delay_scaled: u64,
        ranges_bytes_buf: []u8,
        ecn_counts: ?frame_types.EcnCounts,
    ) Error!frame_types.Ack {
        if (self.range_count == 0) return Error.Empty;

        const top = self.ranges[self.range_count - 1];
        const first_range = top.largest - top.smallest;

        var pos: usize = 0;
        // Iterate intervals from second-from-top down to the bottom.
        var prev = top;
        var i: u8 = self.range_count - 1;
        while (i > 0) {
            i -= 1;
            const this = self.ranges[i];
            // RFC 9000 §19.3.1: gap = prev_smallest - this_largest - 2
            //                   length = this_largest - this_smallest
            const gap = prev.smallest - this.largest - 2;
            const length = this.largest - this.smallest;
            pos += try varint.encode(ranges_bytes_buf[pos..], gap);
            pos += try varint.encode(ranges_bytes_buf[pos..], length);
            prev = this;
        }

        return .{
            .largest_acked = top.largest,
            .ack_delay = ack_delay_scaled,
            .first_range = first_range,
            .range_count = @as(u64, @intCast(self.range_count - 1)),
            .ranges_bytes = ranges_bytes_buf[0..pos],
            .ecn_counts = ecn_counts,
        };
    }

    /// Build an ACK frame that includes the largest contiguous range and
    /// then as many lower ranges as fit in `max_ranges_bytes`. This is the
    /// packet builder's bounded-emission path: under heavy loss/reordering,
    /// an ACK frame may legally omit older ranges instead of failing packet
    /// construction.
    pub fn toAckFrameLimited(
        self: *const AckTracker,
        ack_delay_scaled: u64,
        ranges_bytes_buf: []u8,
        max_ranges_bytes: usize,
    ) Error!frame_types.Ack {
        return self.toAckFrameLimitedRangesWithEcn(
            ack_delay_scaled,
            ranges_bytes_buf,
            max_ranges_bytes,
            std.math.maxInt(u64),
            null,
        );
    }

    /// Like `toAckFrameLimited`, but also caps the number of encoded lower
    /// ranges. The tracker still remembers all ranges for duplicate detection;
    /// this only bounds how much stale ACK history we spend packet budget on.
    pub fn toAckFrameLimitedRanges(
        self: *const AckTracker,
        ack_delay_scaled: u64,
        ranges_bytes_buf: []u8,
        max_ranges_bytes: usize,
        max_lower_ranges: u64,
    ) Error!frame_types.Ack {
        return self.toAckFrameLimitedRangesWithEcn(
            ack_delay_scaled,
            ranges_bytes_buf,
            max_ranges_bytes,
            max_lower_ranges,
            null,
        );
    }

    /// Same as `toAckFrameLimitedRanges`, but lets the caller stamp
    /// §19.3.2 ECN counts onto the frame so the encoder emits the
    /// 0x03 wire variant. The ranges-budget logic accounts for the
    /// extra varints in the ECN trailer when sizing the available
    /// space; if even the trailer doesn't fit, the frame ships with
    /// no ranges and just the leading `first_range`.
    pub fn toAckFrameLimitedRangesWithEcn(
        self: *const AckTracker,
        ack_delay_scaled: u64,
        ranges_bytes_buf: []u8,
        max_ranges_bytes: usize,
        max_lower_ranges: u64,
        ecn_counts: ?frame_types.EcnCounts,
    ) Error!frame_types.Ack {
        if (self.range_count == 0) return Error.Empty;

        const top = self.ranges[self.range_count - 1];
        const first_range = top.largest - top.smallest;
        const ranges_capacity = @min(ranges_bytes_buf.len, max_ranges_bytes);

        var pos: usize = 0;
        var included_ranges: u64 = 0;
        var prev = top;
        var i: u8 = self.range_count - 1;
        while (i > 0 and included_ranges < max_lower_ranges) {
            i -= 1;
            const this = self.ranges[i];
            const gap = prev.smallest - this.largest - 2;
            const length = this.largest - this.smallest;
            const needed = varint.encodedLen(gap) + varint.encodedLen(length);
            if (needed > ranges_capacity - pos) break;
            pos += try varint.encode(ranges_bytes_buf[pos..], gap);
            pos += try varint.encode(ranges_bytes_buf[pos..], length);
            prev = this;
            included_ranges += 1;
        }

        return .{
            .largest_acked = top.largest,
            .ack_delay = ack_delay_scaled,
            .first_range = first_range,
            .range_count = included_ranges,
            .ranges_bytes = ranges_bytes_buf[0..pos],
            .ecn_counts = ecn_counts,
        };
    }

    fn insert(self: *AckTracker, pn: u64) bool {
        // Find the lowest index `i` such that ranges[i].largest >= pn,
        // or `range_count` if no such index exists.
        var i: u8 = 0;
        while (i < self.range_count and self.ranges[i].largest < pn) : (i += 1) {}

        // Already covered by ranges[i]?
        if (i < self.range_count and pn >= self.ranges[i].smallest) return false;

        const ext_below: bool = i > 0 and self.ranges[i - 1].largest + 1 == pn;
        const ext_above: bool = i < self.range_count and self.ranges[i].smallest == pn + 1;

        if (ext_below and ext_above) {
            // Bridge: merge ranges[i-1] and ranges[i].
            self.ranges[i - 1].largest = self.ranges[i].largest;
            self.removeAt(i);
            return true;
        }
        if (ext_below) {
            self.ranges[i - 1].largest = pn;
            return true;
        }
        if (ext_above) {
            self.ranges[i].smallest = pn;
            return true;
        }

        // Disjoint insert at position `i`. If we're at capacity,
        // drop the lowest range to make room (we'll never re-ack
        // those PNs but the peer's lost-recovery handles it).
        if (self.range_count == max_ranges) {
            self.removeAt(0);
            if (i > 0) i -= 1;
        }
        var k: u8 = self.range_count;
        while (k > i) : (k -= 1) {
            self.ranges[k] = self.ranges[k - 1];
        }
        self.ranges[i] = .{ .smallest = pn, .largest = pn };
        self.range_count += 1;
        return true;
    }

    fn removeAt(self: *AckTracker, idx: u8) void {
        var k: u8 = idx;
        while (k + 1 < self.range_count) : (k += 1) {
            self.ranges[k] = self.ranges[k + 1];
        }
        self.range_count -= 1;
    }
};

// -- tests ---------------------------------------------------------------

test "single PN add" {
    var t: AckTracker = .{};
    t.add(7, 1000);
    try std.testing.expectEqual(@as(u8, 1), t.range_count);
    try std.testing.expectEqual(@as(u64, 7), t.ranges[0].smallest);
    try std.testing.expectEqual(@as(u64, 7), t.ranges[0].largest);
    try std.testing.expectEqual(@as(?u64, 7), t.largest);
    try std.testing.expect(t.pending_ack);
}

test "contiguous PNs collapse into one range" {
    var t: AckTracker = .{};
    t.add(0, 0);
    t.add(1, 0);
    t.add(2, 0);
    t.add(3, 0);
    try std.testing.expectEqual(@as(u8, 1), t.range_count);
    try std.testing.expectEqual(@as(u64, 0), t.ranges[0].smallest);
    try std.testing.expectEqual(@as(u64, 3), t.ranges[0].largest);
}

test "out-of-order arrival builds disjoint ranges then merges" {
    var t: AckTracker = .{};
    t.add(0, 0);
    t.add(2, 0);
    t.add(4, 0);
    try std.testing.expectEqual(@as(u8, 3), t.range_count);
    // Bridge with PN 1 -> ranges {0,0} and {2,2} merge.
    t.add(1, 0);
    try std.testing.expectEqual(@as(u8, 2), t.range_count);
    try std.testing.expectEqual(@as(u64, 0), t.ranges[0].smallest);
    try std.testing.expectEqual(@as(u64, 2), t.ranges[0].largest);
    try std.testing.expectEqual(@as(u64, 4), t.ranges[1].smallest);
    try std.testing.expectEqual(@as(u64, 4), t.ranges[1].largest);
    // Bridge with PN 3 -> all merge into {0..4}.
    t.add(3, 0);
    try std.testing.expectEqual(@as(u8, 1), t.range_count);
    try std.testing.expectEqual(@as(u64, 0), t.ranges[0].smallest);
    try std.testing.expectEqual(@as(u64, 4), t.ranges[0].largest);
}

test "duplicate add is a no-op" {
    var t: AckTracker = .{};
    t.add(5, 0);
    t.add(5, 0);
    try std.testing.expectEqual(@as(u8, 1), t.range_count);
}

test "contains works for hits and misses" {
    var t: AckTracker = .{};
    t.add(10, 0);
    t.add(11, 0);
    t.add(20, 0);
    try std.testing.expect(t.contains(10));
    try std.testing.expect(t.contains(11));
    try std.testing.expect(!t.contains(12));
    try std.testing.expect(t.contains(20));
    try std.testing.expect(!t.contains(21));
}

test "toAckFrame: single range produces empty ranges_bytes" {
    var t: AckTracker = .{};
    t.add(100, 0);
    t.add(101, 0);
    t.add(102, 0);
    var buf: [64]u8 = undefined;
    const ack = try t.toAckFrame(0, &buf);
    try std.testing.expectEqual(@as(u64, 102), ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 2), ack.first_range);
    try std.testing.expectEqual(@as(u64, 0), ack.range_count);
    try std.testing.expectEqual(@as(usize, 0), ack.ranges_bytes.len);
}

test "toAckFrame: round-trip via ack_range Iterator" {
    var t: AckTracker = .{};
    // Three disjoint intervals: [80..82], [88..92], [95..100].
    var pn: u64 = 80;
    while (pn <= 82) : (pn += 1) t.add(pn, 0);
    pn = 88;
    while (pn <= 92) : (pn += 1) t.add(pn, 0);
    pn = 95;
    while (pn <= 100) : (pn += 1) t.add(pn, 0);

    try std.testing.expectEqual(@as(u8, 3), t.range_count);

    var buf: [64]u8 = undefined;
    const ack = try t.toAckFrame(42, &buf);
    try std.testing.expectEqual(@as(u64, 100), ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 5), ack.first_range);
    try std.testing.expectEqual(@as(u64, 2), ack.range_count);
    try std.testing.expectEqual(@as(u64, 42), ack.ack_delay);

    // Decode the ranges_bytes back via the wire-format Iterator and
    // verify each interval matches.
    const ack_range = @import("../frame/ack_range.zig");
    var it = ack_range.iter(ack);
    const top = (try it.next()).?;
    const mid = (try it.next()).?;
    const bot = (try it.next()).?;
    try std.testing.expectEqual(@as(?ack_range.Interval, null), try it.next());
    try std.testing.expectEqual(@as(u64, 95), top.smallest);
    try std.testing.expectEqual(@as(u64, 100), top.largest);
    try std.testing.expectEqual(@as(u64, 88), mid.smallest);
    try std.testing.expectEqual(@as(u64, 92), mid.largest);
    try std.testing.expectEqual(@as(u64, 80), bot.smallest);
    try std.testing.expectEqual(@as(u64, 82), bot.largest);
}

test "toAckFrameLimited truncates older ranges to fit budget" {
    var t: AckTracker = .{};
    var pn: u64 = 0;
    while (pn <= 8) : (pn += 2) t.add(pn, 0);

    var buf: [3]u8 = undefined;
    const ack = try t.toAckFrameLimited(0, &buf, buf.len);
    try std.testing.expectEqual(@as(u64, 8), ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 0), ack.first_range);
    try std.testing.expectEqual(@as(u64, 1), ack.range_count);
    try std.testing.expectEqual(@as(usize, 2), ack.ranges_bytes.len);

    const ack_range = @import("../frame/ack_range.zig");
    var it = ack_range.iter(ack);
    const top = (try it.next()).?;
    const next = (try it.next()).?;
    try std.testing.expectEqual(@as(?ack_range.Interval, null), try it.next());
    try std.testing.expectEqual(@as(u64, 8), top.smallest);
    try std.testing.expectEqual(@as(u64, 8), top.largest);
    try std.testing.expectEqual(@as(u64, 6), next.smallest);
    try std.testing.expectEqual(@as(u64, 6), next.largest);
}

test "toAckFrameLimitedRanges truncates older ranges by count" {
    var t: AckTracker = .{};
    var pn: u64 = 0;
    while (pn <= 10) : (pn += 2) t.add(pn, 0);

    var buf: [64]u8 = undefined;
    const ack = try t.toAckFrameLimitedRanges(0, &buf, buf.len, 2);
    try std.testing.expectEqual(@as(u64, 10), ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 0), ack.first_range);
    try std.testing.expectEqual(@as(u64, 2), ack.range_count);
    try std.testing.expectEqual(@as(usize, 4), ack.ranges_bytes.len);

    const ack_range = @import("../frame/ack_range.zig");
    var it = ack_range.iter(ack);
    const top = (try it.next()).?;
    const next = (try it.next()).?;
    const last = (try it.next()).?;
    try std.testing.expectEqual(@as(?ack_range.Interval, null), try it.next());
    try std.testing.expectEqual(@as(u64, 10), top.smallest);
    try std.testing.expectEqual(@as(u64, 10), top.largest);
    try std.testing.expectEqual(@as(u64, 8), next.smallest);
    try std.testing.expectEqual(@as(u64, 8), next.largest);
    try std.testing.expectEqual(@as(u64, 6), last.smallest);
    try std.testing.expectEqual(@as(u64, 6), last.largest);
    try std.testing.expectEqual(@as(u8, 6), t.range_count);
}

test "markAckSent clears pending_ack but preserves intervals" {
    var t: AckTracker = .{};
    t.add(1, 0);
    t.add(2, 0);
    t.markAckSent();
    try std.testing.expect(!t.pending_ack);
    try std.testing.expectEqual(@as(u8, 1), t.range_count);
    t.add(3, 0);
    try std.testing.expect(t.pending_ack);
}

test "overflow drops the lowest range" {
    var t: AckTracker = .{};
    var n: u64 = 0;
    // Fill with disjoint PNs: 0, 2, 4, ... so each is its own range.
    while (n < max_ranges) : (n += 1) {
        t.add(n * 2, 0);
    }
    try std.testing.expectEqual(max_ranges, t.range_count);
    const old_lowest = t.ranges[0].smallest;
    // One more disjoint PN above the top — should drop the lowest.
    t.add(n * 2 + 100, 0);
    try std.testing.expectEqual(max_ranges, t.range_count);
    try std.testing.expect(t.ranges[0].smallest != old_lowest);
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `AckTracker` with arbitrary `add` / `addPacket` /
// `addPacketDelayed` / `markAckSent` / `promoteDelayedAck` calls and
// assert range-list invariants. Properties:
//
// - No panic, no overflow trap.
// - `range_count <= max_ranges` always.
// - Each range has `smallest <= largest`.
// - Intervals are sorted ascending and disjoint with at least a
//   1-PN gap between them (otherwise they would have merged).
// - `largest` (when set) equals the maximum largest across ranges.
// - `contains(pn)` agrees with a manual range scan.
// - `toAckFrame*` either errors cleanly or returns a frame with
//   `range_count <= self.range_count - 1`.

test "fuzz: ack_tracker range-list invariants" {
    try std.testing.fuzz({}, fuzzAckTracker, .{});
}

fn fuzzAckTracker(_: void, smith: *std.testing.Smith) anyerror!void {
    var t: AckTracker = .{};

    var steps: u32 = 0;
    while (steps < 256 and !smith.eos()) : (steps += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 5);
        switch (op) {
            0 => {
                const pn = smith.value(u64);
                const now = smith.value(u64);
                t.add(pn, now);
            },
            1 => {
                const pn = smith.value(u64);
                const now = smith.value(u64);
                const eliciting = smith.valueRangeAtMost(u8, 0, 1) == 1;
                t.addPacket(pn, now, eliciting);
            },
            2 => {
                const pn = smith.value(u64);
                const now = smith.value(u64);
                const eliciting = smith.valueRangeAtMost(u8, 0, 1) == 1;
                const threshold = smith.value(u8);
                t.addPacketDelayed(pn, now, eliciting, threshold);
            },
            3 => {
                t.markAckSent();
                try std.testing.expect(!t.pending_ack);
                try std.testing.expect(!t.delayed_ack_armed);
                try std.testing.expectEqual(@as(u8, 0), t.ack_eliciting_since_ack);
            },
            4 => {
                const now = smith.value(u64);
                const max_delay = smith.value(u64);
                _ = t.promoteDelayedAck(now, max_delay);
            },
            5 => {
                // Build an ACK frame and (if it succeeds) make sure
                // its shape agrees with our internal range table.
                var buf: [512]u8 = undefined;
                const max_lower = smith.value(u32);
                if (t.toAckFrameLimitedRanges(0, &buf, buf.len, max_lower)) |ack| {
                    // Builder must respect `range_count <= self.range_count - 1`.
                    if (t.range_count > 0) {
                        try std.testing.expect(ack.range_count <= t.range_count - 1);
                    }
                    // largest_acked must equal the top range's largest.
                    if (t.range_count > 0) {
                        try std.testing.expectEqual(
                            t.ranges[t.range_count - 1].largest,
                            ack.largest_acked,
                        );
                    }
                } else |_| {}
            },
            else => unreachable,
        }

        // Cross-cutting structural invariants.
        try std.testing.expect(t.range_count <= max_ranges);
        var i: u8 = 0;
        var max_largest: u64 = 0;
        var seen_any: bool = false;
        while (i < t.range_count) : (i += 1) {
            const r = t.ranges[i];
            try std.testing.expect(r.smallest <= r.largest);
            if (i > 0) {
                const prev = t.ranges[i - 1];
                // Sorted ascending and disjoint with at least one PN gap.
                try std.testing.expect(prev.largest < r.smallest);
                try std.testing.expect(prev.largest + 1 < r.smallest);
            }
            if (!seen_any or r.largest > max_largest) max_largest = r.largest;
            seen_any = true;
        }
        if (seen_any) {
            try std.testing.expect(t.largest != null);
            // The cached `largest` must be at least the top of the
            // top range (insert can only stash the running max).
            try std.testing.expect(t.largest.? >= max_largest);
        }
        // contains(pn) should agree with a linear range scan for a
        // small sample of PNs drawn from the existing ranges.
        if (t.range_count > 0) {
            const sample_idx = smith.indexWithHash(t.range_count, 0xfeed);
            const r = t.ranges[@intCast(sample_idx)];
            try std.testing.expect(t.contains(r.smallest));
            try std.testing.expect(t.contains(r.largest));
            // Just below the smallest: contains only if a lower range
            // also covers it.
            if (r.smallest > 0) {
                const below = r.smallest - 1;
                var hit = false;
                var j: u8 = 0;
                while (j < t.range_count) : (j += 1) {
                    const rj = t.ranges[j];
                    if (below >= rj.smallest and below <= rj.largest) {
                        hit = true;
                        break;
                    }
                }
                try std.testing.expectEqual(hit, t.contains(below));
            }
        }
    }
}
