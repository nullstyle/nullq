//! NewReno congestion control (RFC 9002 §7 + Appendix B).
//!
//! One controller per Path: the single-path connection has one,
//! multipath connections have one per active path. The controller
//! works in `bytes_in_flight` units the connection state machine
//! maintains externally (in `SentPacketTracker`), but the controller
//! itself tracks `cwnd` and `ssthresh` as authoritative per-path
//! limits.

const std = @import("std");

/// kPersistentCongestionThreshold from RFC 9002 §7.6.1: 3.
pub const persistent_congestion_threshold: u8 = 3;

/// kLossReductionFactor numerator from RFC 9002 §B.1.
pub const loss_reduction_factor_num: u64 = 1;
/// kLossReductionFactor denominator from RFC 9002 §B.1 (factor = 1/2).
pub const loss_reduction_factor_den: u64 = 2;

/// Tunables for the NewReno controller. Held by-value inside the
/// controller so each path has independent state.
pub const Config = struct {
    /// Maximum UDP datagram size we'll send. Conservatively 1200
    /// per the QUIC v1 minimum; raised by PMTU discovery later.
    max_datagram_size: u64 = 1200,

    /// Minimum congestion window: 2 * max_datagram_size.
    pub fn minWindow(self: Config) u64 {
        return 2 * self.max_datagram_size;
    }

    /// Initial congestion window: min(10 * max_datagram_size,
    /// max(2 * max_datagram_size, 14720)). RFC 9002 §7.2.
    pub fn initialWindow(self: Config) u64 {
        const ten = 10 * self.max_datagram_size;
        const fourteen720 = @max(self.minWindow(), 14720);
        return @min(ten, fourteen720);
    }
};

/// RFC 9002 NewReno congestion controller. One instance per QUIC
/// path. Tracks congestion window, slow-start threshold, and the
/// recovery period; exposes `sendAllowance` for the packet builder.
pub const NewReno = struct {
    cfg: Config,
    /// Current congestion window in bytes.
    cwnd: u64,
    /// Slow-start threshold. `null` means infinity (slow start
    /// continues until first loss).
    ssthresh: ?u64 = null,
    /// Recovery start time in microseconds, if currently in
    /// recovery. Set on loss; cleared once an ACK arrives for a
    /// packet sent after recovery_start_time.
    recovery_start_time_us: ?u64 = null,
    /// Bytes acknowledged since the last cwnd update during
    /// congestion avoidance. We compound increments per
    /// `bytes_acked / cwnd >= max_datagram_size`.
    bytes_acked_in_ca: u64 = 0,

    /// Build a fresh controller with `cfg` and `cwnd = initialWindow()`.
    pub fn init(cfg: Config) NewReno {
        return .{ .cfg = cfg, .cwnd = cfg.initialWindow() };
    }

    /// True iff the controller is currently in recovery and the
    /// packet sent at `sent_time_us` predates the recovery boundary
    /// (so its ACK should not grow `cwnd`).
    pub fn isInRecovery(self: *const NewReno, sent_time_us: u64) bool {
        return self.recovery_start_time_us != null and
            sent_time_us <= self.recovery_start_time_us.?;
    }

    /// True while we're in slow start (no `ssthresh` yet, or
    /// `cwnd < ssthresh`).
    pub fn isSlowStart(self: *const NewReno) bool {
        return self.ssthresh == null or self.cwnd < self.ssthresh.?;
    }

    /// Process an ACK for `bytes_acked` bytes whose newest packet
    /// was sent at `largest_acked_sent_time_us`. RFC 9002 §B.5.
    pub fn onPacketAcked(
        self: *NewReno,
        bytes_acked: u64,
        largest_acked_sent_time_us: u64,
    ) void {
        // Clear recovery if we've received an ACK for a packet sent
        // after recovery began.
        if (self.recovery_start_time_us) |rec_start| {
            if (largest_acked_sent_time_us > rec_start) {
                self.recovery_start_time_us = null;
            } else {
                // Still in recovery — don't grow cwnd.
                return;
            }
        }

        if (self.isSlowStart()) {
            self.cwnd += bytes_acked;
            return;
        }

        // Congestion avoidance: cwnd grows by ~max_datagram_size per RTT.
        // The standard accounting is to accumulate bytes_acked and
        // bump cwnd by max_datagram_size once we've accumulated enough.
        self.bytes_acked_in_ca += bytes_acked;
        if (self.bytes_acked_in_ca >= self.cwnd) {
            self.bytes_acked_in_ca -= self.cwnd;
            self.cwnd += self.cfg.max_datagram_size;
        }
    }

    /// Process a packet declared lost. RFC 9002 §B.6.
    /// `lost_largest_sent_time_us` is the send time of the latest
    /// lost packet; recovery period starts at that time.
    pub fn onPacketLost(
        self: *NewReno,
        bytes_lost: u64,
        lost_largest_sent_time_us: u64,
    ) void {
        _ = bytes_lost; // tracked externally; unused here

        // Don't re-enter recovery for losses that happened during
        // an existing recovery period.
        if (self.recovery_start_time_us) |rec_start| {
            if (lost_largest_sent_time_us <= rec_start) return;
        }

        self.recovery_start_time_us = lost_largest_sent_time_us;
        // ssthresh = cwnd * 0.5
        self.ssthresh = @max(
            self.cwnd * loss_reduction_factor_num / loss_reduction_factor_den,
            self.cfg.minWindow(),
        );
        self.cwnd = self.ssthresh.?;
        self.bytes_acked_in_ca = 0;
    }

    /// Sent during a "persistent congestion" period (RFC 9002 §7.6).
    /// Reset cwnd to the minimum window.
    pub fn onPersistentCongestion(self: *NewReno) void {
        self.cwnd = self.cfg.minWindow();
        self.recovery_start_time_us = null;
        self.bytes_acked_in_ca = 0;
    }

    /// Are we allowed to send `bytes_in_flight` worth of data right
    /// now? Returns the cwnd headroom (bytes that can still be sent
    /// before hitting the limit). 0 means "wait."
    pub fn sendAllowance(self: *const NewReno, bytes_in_flight: u64) u64 {
        if (bytes_in_flight >= self.cwnd) return 0;
        return self.cwnd - bytes_in_flight;
    }
};

// -- tests ---------------------------------------------------------------

test "initial window honors RFC 9002 §7.2 (max 10 MSS, min(2 MSS, 14720))" {
    const cfg: Config = .{ .max_datagram_size = 1200 };
    // 10 * 1200 = 12000; max(2400, 14720) = 14720; min = 12000.
    try std.testing.expectEqual(@as(u64, 12000), cfg.initialWindow());

    const big: Config = .{ .max_datagram_size = 1500 };
    // 10 * 1500 = 15000; max(3000, 14720) = 15000; min(15000, 15000) = 15000.
    // Wait — 14720 vs 3000: max is 14720. min(15000, 14720) = 14720.
    try std.testing.expectEqual(@as(u64, 14720), big.initialWindow());
}

test "slow start adds bytes_acked to cwnd" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    const initial = nr.cwnd;
    try std.testing.expect(nr.isSlowStart());
    nr.onPacketAcked(2400, 100);
    try std.testing.expectEqual(initial + 2400, nr.cwnd);
}

test "loss halves cwnd to ssthresh and enters recovery" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    nr.onPacketLost(1200, 1_000_000);
    try std.testing.expectEqual(@as(?u64, 6000), nr.ssthresh);
    try std.testing.expectEqual(@as(u64, 6000), nr.cwnd);
    try std.testing.expect(nr.recovery_start_time_us != null);
    try std.testing.expect(nr.isInRecovery(500_000));
    try std.testing.expect(!nr.isInRecovery(1_500_000));
}

test "loss can't shrink cwnd below min_window" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 2000; // already small
    nr.onPacketLost(1200, 1_000_000);
    try std.testing.expectEqual(nr.cfg.minWindow(), nr.cwnd);
}

test "recovery period prevents cwnd growth from in-recovery acks" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.onPacketLost(1200, 1_000_000);
    const cwnd_after_loss = nr.cwnd;
    // ACK for a packet sent before recovery → ignored for cwnd.
    nr.onPacketAcked(1200, 999_999);
    try std.testing.expectEqual(cwnd_after_loss, nr.cwnd);
    // ACK for a packet sent after recovery → recovery clears, but
    // cwnd is now in CA mode (cwnd == ssthresh after the loss).
    // Acking enough bytes to fill `bytes_acked_in_ca >= cwnd`
    // triggers one MSS bump.
    nr.onPacketAcked(cwnd_after_loss, 2_000_000);
    try std.testing.expectEqual(@as(?u64, null), nr.recovery_start_time_us);
    try std.testing.expectEqual(cwnd_after_loss + nr.cfg.max_datagram_size, nr.cwnd);
}

test "congestion avoidance grows cwnd by ~MSS per RTT" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    nr.ssthresh = 6000; // force CA mode
    try std.testing.expect(!nr.isSlowStart());

    // Accumulate cwnd worth of acks → one MSS bump.
    nr.onPacketAcked(12000, 100);
    try std.testing.expectEqual(@as(u64, 13200), nr.cwnd);
}

test "sendAllowance reports remaining cwnd" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    try std.testing.expectEqual(@as(u64, 12000), nr.sendAllowance(0));
    try std.testing.expectEqual(@as(u64, 4000), nr.sendAllowance(8000));
    try std.testing.expectEqual(@as(u64, 0), nr.sendAllowance(12000));
    try std.testing.expectEqual(@as(u64, 0), nr.sendAllowance(20000));
}

test "persistent congestion resets cwnd to min_window" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 30000;
    nr.onPersistentCongestion();
    try std.testing.expectEqual(nr.cfg.minWindow(), nr.cwnd);
}
