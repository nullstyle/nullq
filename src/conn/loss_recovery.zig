//! Loss recovery primitives — ACK processing and loss detection
//! per RFC 9002 §6 and Appendix A.
//!
//! Pure functions operating on caller-managed `SentPacketTracker`,
//! `PnSpace`, and `RttEstimator`. Connection (state.zig) owns the
//! state and ties these together via `onPacketSent` and
//! `onAckReceived` orchestration.

const std = @import("std");
const ack_range = @import("../frame/ack_range.zig");
const frame_types = @import("../frame/types.zig");

const PnSpace = @import("pn_space.zig").PnSpace;
const SentPacketTracker = @import("sent_packets.zig").SentPacketTracker;
const RttEstimator = @import("rtt.zig").RttEstimator;
const granularity_us = @import("rtt.zig").granularity_us;

/// kPacketThreshold from RFC 9002 §6.1.1: 3.
pub const packet_threshold: u64 = 3;
/// kTimeThreshold numerator from RFC 9002 §6.1.2.
pub const time_threshold_num: u64 = 9;
/// kTimeThreshold denominator from RFC 9002 §6.1.2 (threshold = 9/8 of the RTT).
pub const time_threshold_den: u64 = 8;

/// Outcome of `processAck`. The connection feeds the contained
/// metadata into the RTT estimator and congestion controller.
pub const AckProcessing = struct {
    /// Number of newly-acknowledged tracked packets removed.
    newly_acked_count: u32 = 0,
    /// Sum of `.bytes` for those packets.
    bytes_acked: u64 = 0,
    /// Sum of `.bytes` for the in-flight subset (CC update input).
    in_flight_bytes_acked: u64 = 0,
    /// Was `ack.largest_acked` newly acknowledged?
    largest_acked_newly_acked: bool = false,
    /// Send time of the largest-acked packet (microseconds), valid
    /// only when `largest_acked_newly_acked` is true.
    largest_acked_send_time_us: u64 = 0,
    /// Was that packet ack-eliciting? (RTT samples are taken only
    /// from ack-eliciting packets per RFC 9002 §5.1.)
    largest_acked_ack_eliciting: bool = false,
    /// Did the ACK include any ack-eliciting newly-acked packet?
    /// Caller uses this to decide whether to reset the PTO count.
    any_ack_eliciting_newly_acked: bool = false,
};

/// Walk the ACK frame and remove tracked packets that the ACK covers.
/// Returns metadata for downstream RTT and CC updates.
pub fn processAck(
    tracker: *SentPacketTracker,
    pn_space: *PnSpace,
    ack: frame_types.Ack,
) ack_range.Error!AckProcessing {
    pn_space.onAckReceived(ack.largest_acked);

    var result: AckProcessing = .{};

    var it = ack_range.iter(ack);
    while (try it.next()) |interval| {
        // Walk tracker entries whose PN ∈ [interval.smallest, interval.largest].
        // The tracker is sorted ascending; lowerBound finds the first
        // candidate; we then remove forward-walking, but since
        // `removeAt` shifts everything down, we don't increment `i`
        // when we remove.
        // `i` doesn't move forward in this loop: each iteration
        // either removes the packet at position `i` (which shifts
        // subsequent entries down so `i` now points at the next
        // candidate) or doesn't remove and breaks. So const works.
        const i = tracker.lowerBound(interval.smallest) orelse continue;
        while (i < tracker.count and tracker.packets[i].pn <= interval.largest) {
            const removed_pn = tracker.packets[i].pn;
            const removed = tracker.removeAt(i);
            result.newly_acked_count += 1;
            result.bytes_acked += removed.bytes;
            if (removed.in_flight) result.in_flight_bytes_acked += removed.bytes;
            if (removed.ack_eliciting) result.any_ack_eliciting_newly_acked = true;
            if (removed_pn == ack.largest_acked) {
                result.largest_acked_newly_acked = true;
                result.largest_acked_send_time_us = removed.sent_time_us;
                result.largest_acked_ack_eliciting = removed.ack_eliciting;
            }
        }
    }

    return result;
}

/// Outcome of `detectLosses`. Caller feeds the contained metadata
/// into the congestion controller's `onPacketLost` and into qlog/loss
/// observability counters.
pub const LossResult = struct {
    /// Sum of `.bytes` for declared-lost packets.
    bytes_lost: u64 = 0,
    /// Sum of `.bytes` for the in-flight subset.
    in_flight_bytes_lost: u64 = 0,
    /// Send time of the latest lost packet (microseconds). Drives the
    /// recovery-period start in `NewReno.onPacketLost`.
    largest_lost_send_time_us: u64 = 0,
    /// Number of packets declared lost.
    count: u32 = 0,
};

/// Detect and remove lost packets per RFC 9002 §6.1.
///
/// A packet is declared lost iff:
///   1. (packet-threshold) `largest_acked - packet.pn >= 3`, OR
///   2. (time-threshold)   `packet.send_time < now - max(9/8 * max(latest_rtt, smoothed_rtt), 1ms)`.
///
/// Only packets whose PN is below `pn_space.largest_acked_sent` are
/// candidates — we never declare unacked-but-newer packets lost.
pub fn detectLosses(
    tracker: *SentPacketTracker,
    pn_space: *const PnSpace,
    rtt_est: *const RttEstimator,
    now_us: u64,
) LossResult {
    const largest_acked_opt = pn_space.largest_acked_sent;
    if (largest_acked_opt == null) return .{};
    const largest_acked = largest_acked_opt.?;

    const reference_rtt = @max(rtt_est.latest_rtt_us, rtt_est.smoothed_rtt_us);
    const time_threshold = @max(
        reference_rtt * time_threshold_num / time_threshold_den,
        granularity_us,
    );
    const lost_send_time_cutoff: u64 = if (now_us > time_threshold)
        now_us - time_threshold
    else
        0;

    var result: LossResult = .{};

    // Scan in-flight tracked packets. We walk forward; when we
    // find a lost one we remove it (which shifts subsequent
    // entries down, so we don't advance `i`).
    var i: u32 = 0;
    while (i < tracker.count) {
        const p = tracker.packets[i];
        if (p.pn > largest_acked) {
            // Above largest_acked → not eligible for loss detection.
            i += 1;
            continue;
        }

        const packet_thresh_lost = (largest_acked - p.pn) >= packet_threshold;
        const time_thresh_lost = p.sent_time_us < lost_send_time_cutoff;

        if (packet_thresh_lost or time_thresh_lost) {
            const removed = tracker.removeAt(i);
            result.count += 1;
            result.bytes_lost += removed.bytes;
            if (removed.in_flight) result.in_flight_bytes_lost += removed.bytes;
            if (removed.sent_time_us > result.largest_lost_send_time_us) {
                result.largest_lost_send_time_us = removed.sent_time_us;
            }
            // Do not advance `i`: subsequent entries have shifted down.
            continue;
        }
        i += 1;
    }

    return result;
}

// -- tests ---------------------------------------------------------------

const ack_tracker_mod = @import("ack_tracker.zig");

fn buildAck(largest: u64, first_range: u64) frame_types.Ack {
    return .{
        .largest_acked = largest,
        .ack_delay = 0,
        .first_range = first_range,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    };
}

test "processAck removes a single contiguous range from the tracker" {
    var tr: SentPacketTracker = .{};
    var pn: u64 = 0;
    while (pn < 5) : (pn += 1) {
        try tr.record(.{ .pn = pn, .sent_time_us = pn * 10, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    }
    var space: PnSpace = .{};
    space.next_pn = 5;

    // ACK covers PN 2..4.
    const a = buildAck(4, 2);
    const result = try processAck(&tr, &space, a);
    try std.testing.expectEqual(@as(u32, 3), result.newly_acked_count);
    try std.testing.expectEqual(@as(u64, 3600), result.bytes_acked);
    try std.testing.expect(result.largest_acked_newly_acked);
    try std.testing.expectEqual(@as(u64, 40), result.largest_acked_send_time_us);
    try std.testing.expect(result.any_ack_eliciting_newly_acked);

    // Tracker still has PNs 0 and 1.
    try std.testing.expectEqual(@as(u32, 2), tr.count);
    try std.testing.expectEqual(@as(u64, 0), tr.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 1), tr.packets[1].pn);
    try std.testing.expectEqual(@as(?u64, 4), space.largest_acked_sent);
}

test "processAck handles an ACK with multiple ranges" {
    var tr: SentPacketTracker = .{};
    var pn: u64 = 0;
    while (pn < 11) : (pn += 1) {
        try tr.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    }
    var space: PnSpace = .{};
    space.next_pn = 11;

    // Build ACK covering [10..10] and [3..5] using a multi-range frame.
    var ranges_buf: [16]u8 = undefined;
    const ranges = [_]ack_tracker_mod.Range{}; // placeholder to silence import
    _ = ranges;

    // Wire ranges: largest = 10, first_range = 0 → [10..10].
    // Then: gap, length pair for [3..5]. previous_smallest = 10.
    //   largest_in_this = 10 - gap - 2; want 5. 10 - gap - 2 = 5 → gap = 3.
    //   length = 5 - 3 = 2.
    const ack_range_mod = @import("../frame/ack_range.zig");
    const wire_len = try ack_range_mod.writeRanges(&ranges_buf, &.{
        .{ .gap = 3, .length = 2 },
    });

    const a: frame_types.Ack = .{
        .largest_acked = 10,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 1,
        .ranges_bytes = ranges_buf[0..wire_len],
        .ecn_counts = null,
    };

    const result = try processAck(&tr, &space, a);
    // Acked: 10, 5, 4, 3 → 4 packets, 400 bytes.
    try std.testing.expectEqual(@as(u32, 4), result.newly_acked_count);
    try std.testing.expectEqual(@as(u64, 400), result.bytes_acked);
    try std.testing.expectEqual(@as(u32, 7), tr.count); // 11 - 4
    try std.testing.expect(result.largest_acked_newly_acked);
}

test "detectLosses by packet threshold" {
    var tr: SentPacketTracker = .{};
    var pn: u64 = 0;
    while (pn < 5) : (pn += 1) {
        try tr.record(.{ .pn = pn, .sent_time_us = 100, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    }

    var space: PnSpace = .{};
    var rtt_est: RttEstimator = .{};
    // largest_acked = 4 → packets 0 and 1 are lost (largest - pn >= 3).
    // Packet 2 is not (4 - 2 = 2 < 3).
    space.largest_acked_sent = 4;
    rtt_est.smoothed_rtt_us = 10_000; // 10ms
    rtt_est.latest_rtt_us = 10_000;
    rtt_est.first_sample_taken = true;

    // First, ack PN 4 to remove it from the tracker (this is what
    // would have happened in real life before detectLosses runs).
    const a = buildAck(4, 0);
    _ = try processAck(&tr, &space, a);
    // Tracker now has 0, 1, 2, 3.

    // Run loss detection at a `now` close enough to send time that
    // the time-threshold path doesn't fire (we want to isolate the
    // packet-threshold path).
    const result = detectLosses(&tr, &space, &rtt_est, 101);
    try std.testing.expectEqual(@as(u32, 2), result.count);
    try std.testing.expectEqual(@as(u64, 2400), result.bytes_lost);
    // Tracker now has only PN 2 and 3.
    try std.testing.expectEqual(@as(u32, 2), tr.count);
    try std.testing.expectEqual(@as(u64, 2), tr.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 3), tr.packets[1].pn);
}

test "detectLosses by time threshold" {
    var tr: SentPacketTracker = .{};
    // Two packets: PN 0 sent at t=0, PN 1 sent at t=100ms.
    try tr.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 1, .sent_time_us = 100_000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });

    var space: PnSpace = .{};
    space.largest_acked_sent = 1;
    var rtt_est: RttEstimator = .{};
    rtt_est.smoothed_rtt_us = 10_000; // 10ms
    rtt_est.latest_rtt_us = 10_000;
    rtt_est.first_sample_taken = true;

    // Time threshold = 9/8 * 10ms = 11.25ms. now=200ms.
    // Cutoff = 200ms - 11.25ms = 188.75ms.
    // PN 0 sent at 0 < 188.75ms → lost.
    // PN 1 sent at 100ms < 188.75ms → also lost.
    const result = detectLosses(&tr, &space, &rtt_est, 200_000);
    try std.testing.expectEqual(@as(u32, 2), result.count);
}

test "detectLosses skips packets above largest_acked" {
    var tr: SentPacketTracker = .{};
    // Packets 0, 1, 5, 6. largest_acked = 1.
    try tr.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 1, .sent_time_us = 1000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 5, .sent_time_us = 5000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 6, .sent_time_us = 6000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });

    var space: PnSpace = .{};
    space.largest_acked_sent = 1; // only PNs 0 and 1 are eligible
    var rtt_est: RttEstimator = .{};
    rtt_est.smoothed_rtt_us = 10_000;
    rtt_est.latest_rtt_us = 10_000;
    rtt_est.first_sample_taken = true;

    const result = detectLosses(&tr, &space, &rtt_est, 1_000_000_000);
    // Even though PNs 5 and 6 look "old" by time, they're above
    // largest_acked, so they're spared.
    try std.testing.expectEqual(@as(u32, 2), result.count);
    try std.testing.expectEqual(@as(u32, 2), tr.count);
    try std.testing.expectEqual(@as(u64, 5), tr.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 6), tr.packets[1].pn);
}

test "detectLosses with no largest_acked_sent is a no-op" {
    var tr: SentPacketTracker = .{};
    try tr.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    var space: PnSpace = .{};
    var rtt_est: RttEstimator = .{};
    const result = detectLosses(&tr, &space, &rtt_est, 1_000_000);
    try std.testing.expectEqual(@as(u32, 0), result.count);
    try std.testing.expectEqual(@as(u32, 1), tr.count);
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `processAck` against an arbitrary `SentPacketTracker` seeded
// with strictly-increasing PNs and an arbitrary `Ack` frame whose
// range bytes come from the corpus. Properties:
//
// - No panic, no overflow trap, no unreachable.
// - On success, `bytes_in_flight` and `ack_eliciting_in_flight` after
//   are ≤ before (ACK only frees, never adds).
// - `count` after ≤ before; `newly_acked_count` equals the delta.
// - The tracker remains sorted strictly ascending by PN.
// - `result.bytes_acked` ≥ `result.in_flight_bytes_acked`.
// - `space.largest_acked_sent` is monotonically non-decreasing across
//   the call (onAckReceived enforces this).

test "fuzz: loss_recovery processAck invariants" {
    try std.testing.fuzz({}, fuzzProcessAck, .{});
}

fn fuzzProcessAck(_: void, smith: *std.testing.Smith) anyerror!void {
    var tr: SentPacketTracker = .{};

    // Seed the tracker with up to 64 packets at strictly-increasing
    // PNs. Gap between PNs comes from the corpus so contiguous,
    // sparse, and large-gap layouts are all exercised.
    const seed_count = smith.valueRangeAtMost(u8, 0, 64);
    var pn: u64 = 0;
    var seeded: u8 = 0;
    while (seeded < seed_count and !smith.eos()) : (seeded += 1) {
        const gap = smith.valueRangeAtMost(u16, 1, 0xff);
        pn += gap;
        const bytes = smith.valueRangeAtMost(u16, 0, 1500);
        const sent_time_us = smith.value(u32);
        const eliciting = smith.valueRangeAtMost(u8, 0, 1) == 1;
        const in_flight = smith.valueRangeAtMost(u8, 0, 1) == 1;
        tr.record(.{
            .pn = pn,
            .sent_time_us = sent_time_us,
            .bytes = bytes,
            .ack_eliciting = eliciting,
            .in_flight = in_flight,
        }) catch break;
    }

    var space: PnSpace = .{};
    space.next_pn = pn + 1;
    if (smith.valueRangeAtMost(u8, 0, 1) == 1) {
        space.largest_acked_sent = smith.value(u64);
    }

    // Build an arbitrary ACK frame. Bias largest_acked into the
    // tracker's covered range half the time so we actually hit
    // packets; the other half exercises malformed/out-of-range cases.
    const largest_acked: u64 = if (smith.valueRangeAtMost(u8, 0, 1) == 1 and tr.count > 0)
        tr.packets[smith.indexWithHash(tr.count, 0xc0de)].pn
    else
        smith.value(u64);
    const first_range = smith.value(u64);

    var ranges_buf: [256]u8 = undefined;
    const ranges_len = smith.slice(&ranges_buf);
    const range_count = smith.valueRangeAtMost(u8, 0, 16);

    const ack: frame_types.Ack = .{
        .largest_acked = largest_acked,
        .ack_delay = 0,
        .first_range = first_range,
        .range_count = range_count,
        .ranges_bytes = ranges_buf[0..ranges_len],
        .ecn_counts = null,
    };

    const before_bytes_in_flight = tr.bytes_in_flight;
    const before_eliciting_in_flight = tr.ack_eliciting_in_flight;
    const before_count = tr.count;
    const before_largest_acked_sent = space.largest_acked_sent;

    if (processAck(&tr, &space, ack)) |result| {
        // bytes_in_flight monotonically decreases under processAck.
        try std.testing.expect(tr.bytes_in_flight <= before_bytes_in_flight);
        try std.testing.expect(tr.ack_eliciting_in_flight <= before_eliciting_in_flight);
        try std.testing.expect(tr.count <= before_count);
        try std.testing.expectEqual(before_count - tr.count, result.newly_acked_count);
        try std.testing.expect(result.in_flight_bytes_acked <= result.bytes_acked);
    } else |_| {
        // Errored ACK frames may leave the tracker partially modified;
        // we only check structural invariants below.
    }

    // largest_acked_sent is monotonically non-decreasing.
    if (before_largest_acked_sent) |old| {
        try std.testing.expect(space.largest_acked_sent != null);
        try std.testing.expect(space.largest_acked_sent.? >= old);
    }

    // Tracker remains strictly ascending by PN.
    if (tr.count > 1) {
        var i: u32 = 1;
        while (i < tr.count) : (i += 1) {
            try std.testing.expect(tr.packets[i - 1].pn < tr.packets[i].pn);
        }
    }
}
