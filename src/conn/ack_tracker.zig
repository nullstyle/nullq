//! Received-packet-number bookkeeping for ACK frame generation
//! (RFC 9000 §13.2). Maintains a sorted list of disjoint inclusive
//! intervals of received PNs; produces a `frame.types.Ack` whenever
//! the connection wants to send one.

const std = @import("std");
const varint = @import("../wire/varint.zig");
const frame_types = @import("../frame/types.zig");

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

pub const Error = error{
    Empty,
    BufferTooSmall,
} || varint.Error;

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

    pub fn ackDelayBaseMs(self: *const AckTracker) ?u64 {
        if (self.delayed_ack_armed) return self.delayed_ack_start_ms;
        if (self.pending_ack) return self.largest_at_ms;
        return null;
    }

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
            .ecn_counts = null,
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
        if (self.range_count == 0) return Error.Empty;

        const top = self.ranges[self.range_count - 1];
        const first_range = top.largest - top.smallest;
        const ranges_capacity = @min(ranges_bytes_buf.len, max_ranges_bytes);

        var pos: usize = 0;
        var included_ranges: u64 = 0;
        var prev = top;
        var i: u8 = self.range_count - 1;
        while (i > 0) {
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
            .ecn_counts = null,
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
