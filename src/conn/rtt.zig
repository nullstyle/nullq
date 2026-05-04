//! Round-trip-time estimator (RFC 9002 §5).
//!
//! Maintains `smoothed_rtt`, `rtt_var`, `min_rtt`, `latest_rtt` per
//! the RFC 9002 §5.3 update rules. Times are stored in microseconds
//! to give plenty of headroom for high-bandwidth sub-millisecond
//! networks while still fitting inside u64.

const std = @import("std");

pub const us: u64 = 1;
pub const ms: u64 = 1_000;
pub const sec: u64 = 1_000_000;

/// kInitialRtt from RFC 9002 §6.2.2: 333 ms.
pub const initial_rtt_us: u64 = 333 * ms;
/// kGranularity from RFC 9002 §6.1.2: 1 ms.
pub const granularity_us: u64 = 1 * ms;

pub const RttEstimator = struct {
    /// Most recently observed RTT sample (post ack-delay adjustment).
    /// Zero before the first sample.
    latest_rtt_us: u64 = 0,
    /// Smoothed RTT (RFC 9002 §5.3). Initialized to `initial_rtt_us`
    /// so PTO calculations work before the first ACK.
    smoothed_rtt_us: u64 = initial_rtt_us,
    /// RTT variance. Initialized to half of `initial_rtt_us`.
    rtt_var_us: u64 = initial_rtt_us / 2,
    /// Minimum RTT observed across the connection.
    /// Zero before the first sample.
    min_rtt_us: u64 = 0,
    /// Have we recorded at least one sample? Flips on the first call
    /// to `update`.
    first_sample_taken: bool = false,

    /// Update the RTT estimator with a new sample.
    ///
    /// `latest_rtt` is the wall-clock time between sending an
    /// ack-eliciting packet and receiving the ACK that covers it.
    /// `ack_delay` is the peer-reported `ack_delay` from the ACK
    /// frame (already scaled by `ack_delay_exponent` and converted
    /// to microseconds by the caller).
    /// `handshake_confirmed` toggles the §5.3 rule that clamps
    /// `ack_delay` to `max_ack_delay` once the handshake is done.
    /// `max_ack_delay_us` is the peer's `max_ack_delay` transport
    /// parameter (default 25 ms per RFC 9000 §18.2).
    pub fn update(
        self: *RttEstimator,
        latest_rtt_us_in: u64,
        ack_delay_us: u64,
        handshake_confirmed: bool,
        max_ack_delay_us: u64,
    ) void {
        self.latest_rtt_us = latest_rtt_us_in;

        if (!self.first_sample_taken) {
            self.first_sample_taken = true;
            self.min_rtt_us = latest_rtt_us_in;
            self.smoothed_rtt_us = latest_rtt_us_in;
            self.rtt_var_us = latest_rtt_us_in / 2;
            return;
        }

        if (latest_rtt_us_in < self.min_rtt_us) self.min_rtt_us = latest_rtt_us_in;

        // Clamp ack_delay once the handshake is confirmed.
        var ack_delay = ack_delay_us;
        if (handshake_confirmed and ack_delay > max_ack_delay_us) {
            ack_delay = max_ack_delay_us;
        }

        // Adjust the sample by ack_delay, but only if doing so
        // wouldn't make the result < min_rtt.
        var adjusted_rtt = latest_rtt_us_in;
        if (latest_rtt_us_in >= self.min_rtt_us + ack_delay) {
            adjusted_rtt = latest_rtt_us_in - ack_delay;
        }

        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        self.smoothed_rtt_us =
            (self.smoothed_rtt_us * 7 + adjusted_rtt) / 8;

        // rttvar_sample = |smoothed_rtt - adjusted_rtt|
        const rttvar_sample = if (self.smoothed_rtt_us > adjusted_rtt)
            self.smoothed_rtt_us - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt_us;
        // rtt_var = 3/4 * rtt_var + 1/4 * rttvar_sample
        self.rtt_var_us = (self.rtt_var_us * 3 + rttvar_sample) / 4;
    }

    /// Probe-timeout duration per RFC 9002 §6.2.1:
    ///   pto = smoothed_rtt + max(4 * rtt_var, kGranularity) + max_ack_delay
    /// Returns the duration in microseconds.
    pub fn pto(self: *const RttEstimator, max_ack_delay_us: u64) u64 {
        const variance_term = @max(self.rtt_var_us * 4, granularity_us);
        return self.smoothed_rtt_us + variance_term + max_ack_delay_us;
    }
};

// -- tests ---------------------------------------------------------------

test "initial state uses kInitialRtt and rtt_var = kInitialRtt/2" {
    const r: RttEstimator = .{};
    try std.testing.expectEqual(initial_rtt_us, r.smoothed_rtt_us);
    try std.testing.expectEqual(initial_rtt_us / 2, r.rtt_var_us);
    try std.testing.expectEqual(@as(u64, 0), r.min_rtt_us);
    try std.testing.expect(!r.first_sample_taken);
}

test "first sample sets smoothed_rtt = sample, rtt_var = sample/2, min_rtt = sample" {
    var r: RttEstimator = .{};
    r.update(50 * ms, 0, false, 25 * ms);
    try std.testing.expectEqual(@as(u64, 50 * ms), r.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 25 * ms), r.rtt_var_us);
    try std.testing.expectEqual(@as(u64, 50 * ms), r.min_rtt_us);
    try std.testing.expectEqual(@as(u64, 50 * ms), r.latest_rtt_us);
    try std.testing.expect(r.first_sample_taken);
}

test "subsequent samples use 7/8 + 1/8 EWMA" {
    var r: RttEstimator = .{};
    r.update(80 * ms, 0, false, 25 * ms); // first sample sets smoothed=80
    r.update(120 * ms, 0, false, 25 * ms);
    // expected smoothed = (80*7 + 120)/8 = (560 + 120)/8 = 85
    try std.testing.expectEqual(@as(u64, 85 * ms), r.smoothed_rtt_us);
}

test "min_rtt tracks the minimum across samples" {
    var r: RttEstimator = .{};
    r.update(100 * ms, 0, false, 25 * ms);
    r.update(60 * ms, 0, false, 25 * ms);
    r.update(75 * ms, 0, false, 25 * ms);
    try std.testing.expectEqual(@as(u64, 60 * ms), r.min_rtt_us);
}

test "ack_delay subtracts when sample >= min_rtt + ack_delay" {
    var r: RttEstimator = .{};
    r.update(100 * ms, 0, false, 25 * ms); // first sample, no adjustment
    // Now min_rtt = 100ms. Send a sample of 130ms with ack_delay=20ms.
    // Adjusted = 130 - 20 = 110, since 130 >= 100 + 20.
    r.update(130 * ms, 20 * ms, true, 25 * ms);
    // smoothed = (100*7 + 110)/8 = (700 + 110)/8 = 101.25 → 101.25ms
    // We're integer-truncating, so 810000us / 8 = 101250us = 101.25ms.
    try std.testing.expectEqual(@as(u64, 101_250), r.smoothed_rtt_us);
}

test "ack_delay clamped to max_ack_delay post-handshake" {
    var r: RttEstimator = .{};
    r.update(50 * ms, 0, false, 25 * ms);
    // Sample 100ms, ack_delay 100ms (peer lying), handshake confirmed.
    // Effective ack_delay clamped to 25ms.
    r.update(100 * ms, 100 * ms, true, 25 * ms);
    // adjusted = 100 - 25 = 75
    // smoothed = (50*7 + 75)/8 = (350 + 75)/8 = 53.125
    try std.testing.expectEqual(@as(u64, 53_125), r.smoothed_rtt_us);
}

test "PTO formula" {
    var r: RttEstimator = .{};
    r.smoothed_rtt_us = 100 * ms;
    r.rtt_var_us = 10 * ms;
    r.first_sample_taken = true;
    // pto = 100 + max(40, 1) + 25 = 165ms
    try std.testing.expectEqual(@as(u64, 165 * ms), r.pto(25 * ms));
}

test "PTO uses kGranularity when 4*rtt_var is tiny" {
    var r: RttEstimator = .{};
    r.smoothed_rtt_us = 1 * ms;
    r.rtt_var_us = 100; // 100us → 4*100 = 400us < 1ms granularity
    r.first_sample_taken = true;
    // pto = 1ms + 1ms (granularity) + 25ms = 27ms
    try std.testing.expectEqual(@as(u64, 27 * ms), r.pto(25 * ms));
}
