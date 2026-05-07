//! RFC 9002 — QUIC Loss Detection and Congestion Control.
//!
//! These tests pin the small RFC 9002 primitives that nullq exposes
//! under `nullq.conn`: the §5 RTT estimator (`rtt.RttEstimator`), the
//! §6 ACK processing and loss-detection helpers (`loss_recovery`),
//! and the §7 / Appendix B NewReno congestion controller
//! (`congestion.NewReno`). The connection-level orchestration that
//! wires these together — including PTO timer arming and the
//! §A.3 "ACK of unsent packet" PROTOCOL_VIOLATION — lives in
//! `src/conn/state.zig`; tests for those flows live with the
//! end-to-end connection corpus rather than here.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9002 §5.2 ¶2   MUST     first RTT sample initializes SRTT and RTTVar
//!   RFC9002 §5.3 ¶3   MUST     subsequent samples use 7/8 SRTT + 1/8 sample EWMA
//!   RFC9002 §5.3 ¶3   MUST     RTTVar uses 3/4 + 1/4 absolute-deviation EWMA
//!   RFC9002 §5.2 ¶3   MUST     min_rtt monotonically tracks the smallest sample
//!   RFC9002 §5.3 ¶6   MUST     post-handshake ack_delay clamped to max_ack_delay
//!   RFC9002 §5.3 ¶6   MUST NOT subtract ack_delay if it would push sample below min_rtt
//!   RFC9002 §6.1.1 ¶3 MUST     packet-threshold default = 3
//!   RFC9002 §6.1.1 ¶2 MUST     declare lost when ACK acks PN sent later AND gap >= threshold
//!   RFC9002 §6.1.1 ¶?  MUST NOT declare lost a packet above largest_acked
//!   RFC9002 §6.1.2 ¶2 MUST     time-threshold uses 9/8 of max(latest_rtt, smoothed_rtt)
//!   RFC9002 §6.1.2 ¶2 MUST     time-threshold floor = kGranularity (1ms)
//!   RFC9002 §6.2.1 ¶2 MUST     PTO = SRTT + max(4*RTTVar, kGranularity) + max_ack_delay
//!   RFC9002 §6.2.1 ¶3 MUST     PTO uses kGranularity (1ms) when 4*RTTVar is smaller
//!   RFC9002 §6.2.2 ¶1 MUST     kInitialRtt = 333 ms
//!   RFC9002 §A.7    MUST       AckProcessing flags `largest_acked_ack_eliciting`
//!                              so the connection can skip RTT updates from non-eliciting ACKs
//!   RFC9002 §A.7    MUST       AckProcessing flags `any_ack_eliciting_newly_acked`
//!                              so the connection can reset PTO count
//!   RFC9002 §7.2 ¶2 MUST       initial cwnd = min(10*MSS, max(2*MSS, 14720)) for MSS=1200
//!   RFC9002 §7.2 ¶2 MUST       initial cwnd capped at max(2*MSS, 14720) for large MSS
//!   RFC9002 §7.2 ¶2 MUST       min_window = 2 * max_datagram_size
//!   RFC9002 §7.3 ¶? MUST       slow start adds bytes_acked to cwnd
//!   RFC9002 §B.5 ¶? MUST       congestion-avoidance grows cwnd by ~MSS per RTT
//!   RFC9002 §B.6 ¶? MUST       loss halves cwnd to ssthresh and enters recovery
//!   RFC9002 §B.6 ¶? MUST NOT   shrink cwnd below min_window on loss
//!   RFC9002 §7.4 ¶3 MUST NOT   grow cwnd while in recovery
//!   RFC9002 §7.6 ¶2 MUST       persistent congestion resets cwnd to min_window
//!   RFC9002 §7.6.1 ¶? MUST     persistent_congestion_threshold = 3
//!   RFC9002 §A.3 ¶1   MUST     close the connection when an ACK acks an
//!                              unsent packet (PROTOCOL_VIOLATION) — same gate
//!                              as RFC 9000 §13.1, exercised against an authentic
//!                              Initial via the shared _initial_fixture
//!   RFC9002 §6.2.1 ¶? MUST     PTO doubles on each subsequent firing —
//!                              `Connection.ptoMicros()` returns
//!                              `base << pto_count`; driven through a real
//!                              handshake fixture with two ack-eliciting
//!                              client packets to fire two consecutive PTOs.
//!   RFC9002 §7.6.1 ¶? MUST     persistent congestion fires after 2+ ack-eliciting
//!                              losses spanning PC-duration — exercised via the
//!                              `loss_recovery.detectLosses` + `NewReno.onPersistentCongestion`
//!                              chain; connection-level orchestration that
//!                              measures the span lives in `state.zig` and is
//!                              tested in the integration corpus.
//!
//! Out of scope here:
//!   RFC9002 §7.7      Pacing — not implemented by design; nullq leaves
//!                     pacing to the embedder via `sendAllowance`.
//!   RFC9002 §6.3      Probe packets / PTO firing path — driven by
//!                     `state.zig`'s timer subsystem; tested at the
//!                     connection level.

const std = @import("std");
const nullq = @import("nullq");
const rtt = nullq.conn.rtt;
const loss_recovery = nullq.conn.loss_recovery;
const congestion = nullq.conn.congestion;
const sent_packets = nullq.conn.sent_packets;
const fixture = @import("_initial_fixture.zig");
const handshake_fixture = @import("_handshake_fixture.zig");

const RttEstimator = nullq.conn.RttEstimator;
const SentPacketTracker = nullq.conn.SentPacketTracker;
const PnSpace = nullq.conn.PnSpace;
const NewReno = nullq.conn.NewReno;
const ms = rtt.ms;

// Helper: build a minimal `frame.Ack` covering [largest - first_range, largest].
fn buildAck(largest: u64, first_range: u64) nullq.frame.types.Ack {
    return .{
        .largest_acked = largest,
        .ack_delay = 0,
        .first_range = first_range,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    };
}

// ---------------------------------------------------------------- §5 RTT estimation

test "MUST initialize SRTT and RTTVar from the first RTT sample [RFC9002 §5.2 ¶2]" {
    // §5.2 ¶2: "When the first RTT sample is generated, the
    // smoothed_rtt is set to the latest_rtt and rttvar is set to
    // half of the latest_rtt."
    var r: RttEstimator = .{};
    r.update(50 * ms, 0, false, 25 * ms);

    try std.testing.expectEqual(@as(u64, 50 * ms), r.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 25 * ms), r.rtt_var_us);
    try std.testing.expectEqual(@as(u64, 50 * ms), r.min_rtt_us);
    try std.testing.expect(r.first_sample_taken);
}

test "MUST update SRTT with a 7/8 + 1/8 EWMA on subsequent samples [RFC9002 §5.3 ¶3]" {
    // §5.3 ¶3: smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt.
    // First sample bootstraps to 80ms; second sample 120ms (no
    // ack_delay) → expected = (80*7 + 120)/8 = 85ms.
    var r: RttEstimator = .{};
    r.update(80 * ms, 0, false, 25 * ms);
    r.update(120 * ms, 0, false, 25 * ms);

    try std.testing.expectEqual(@as(u64, 85 * ms), r.smoothed_rtt_us);
}

test "MUST update RTTVar with a 3/4 + 1/4 absolute-deviation EWMA [RFC9002 §5.3 ¶3]" {
    // §5.3 ¶3: rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|.
    // First sample 100ms → rttvar = 50ms. Second sample 100ms (no
    // movement) → |sample - smoothed| = 0 → rttvar = 3/4 * 50 = 37.5ms.
    var r: RttEstimator = .{};
    r.update(100 * ms, 0, false, 25 * ms);
    r.update(100 * ms, 0, false, 25 * ms);

    try std.testing.expectEqual(@as(u64, 37_500), r.rtt_var_us);
}

test "MUST track min_rtt as the minimum sample observed [RFC9002 §5.2 ¶3]" {
    // §5.2 ¶3: "min_rtt is set to the latest_rtt on the first RTT
    // sample. min_rtt is set to the lesser of min_rtt and latest_rtt."
    var r: RttEstimator = .{};
    r.update(100 * ms, 0, false, 25 * ms);
    r.update(60 * ms, 0, false, 25 * ms);
    r.update(75 * ms, 0, false, 25 * ms);

    try std.testing.expectEqual(@as(u64, 60 * ms), r.min_rtt_us);
}

test "MUST clamp ack_delay to max_ack_delay once the handshake is confirmed [RFC9002 §5.3 ¶6]" {
    // §5.3 ¶6: "An endpoint can use the peer's max_ack_delay
    // ... if the handshake is confirmed." A peer reporting an
    // outsized ack_delay (e.g. 100ms) gets clamped to the
    // max_ack_delay (25ms here) before adjustment.
    var r: RttEstimator = .{};
    r.update(50 * ms, 0, false, 25 * ms);

    // Sample 100ms, peer-reported ack_delay 100ms, handshake confirmed.
    // Effective ack_delay = min(100, 25) = 25 → adjusted = 75.
    // smoothed = (50*7 + 75)/8 = 53.125ms = 53_125 µs.
    r.update(100 * ms, 100 * ms, true, 25 * ms);

    try std.testing.expectEqual(@as(u64, 53_125), r.smoothed_rtt_us);
}

test "MUST NOT subtract ack_delay if it would push the sample below min_rtt [RFC9002 §5.3 ¶?]" {
    // §5.3: "the RTT estimate ignores the contribution of an
    // ack_delay that would yield a sample less than min_rtt."
    var r: RttEstimator = .{};
    r.update(100 * ms, 0, false, 25 * ms);
    // Now min_rtt = 100ms. New sample 100ms with ack_delay 50ms.
    // 100 < 100 + 50, so ack_delay must NOT be subtracted —
    // adjusted == 100ms. smoothed = (100*7 + 100)/8 = 100ms.
    r.update(100 * ms, 50 * ms, true, 50 * ms);

    try std.testing.expectEqual(@as(u64, 100 * ms), r.smoothed_rtt_us);
}

test "MUST hold kInitialRtt at 333 ms [RFC9002 §6.2.2 ¶1]" {
    // §6.2.2 ¶1: "kInitialRtt: 333 milliseconds". Pre-sample state
    // must use this so PTO calculations work before the first ACK.
    try std.testing.expectEqual(@as(u64, 333 * ms), rtt.initial_rtt_us);

    const r: RttEstimator = .{};
    try std.testing.expectEqual(rtt.initial_rtt_us, r.smoothed_rtt_us);
    try std.testing.expectEqual(rtt.initial_rtt_us / 2, r.rtt_var_us);
}

// ---------------------------------------------------------------- §6.1 packet/time threshold loss

test "MUST set kPacketThreshold to 3 [RFC9002 §6.1.1 ¶3]" {
    // §6.1.1 ¶3: "kPacketThreshold = 3 ... is the RECOMMENDED initial
    // value." We pin nullq's compile-time constant to that value.
    try std.testing.expectEqual(@as(u64, 3), loss_recovery.packet_threshold);
}

test "MUST declare a packet lost when an ACK acks a packet >= 3 PNs higher [RFC9002 §6.1.1 ¶2]" {
    // §6.1.1 ¶2: "A packet is declared lost ... if a packet sent
    // kPacketThreshold packets after it has been acknowledged."
    // Send PN 0..4, ACK PN 4 → packets 0 and 1 satisfy
    // `4 - pn >= 3`; packets 2 and 3 do not.
    var tr: SentPacketTracker = .{};
    var pn: u64 = 0;
    while (pn < 5) : (pn += 1) {
        try tr.record(.{
            .pn = pn,
            .sent_time_us = 100,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    var space: PnSpace = .{};
    space.next_pn = 5;

    // ACK PN 4 first to remove it from the tracker, then run loss
    // detection at a `now` where time-threshold can't fire (so we
    // isolate the packet-threshold path).
    var rtt_est: RttEstimator = .{};
    rtt_est.smoothed_rtt_us = 10 * ms;
    rtt_est.latest_rtt_us = 10 * ms;
    rtt_est.first_sample_taken = true;

    _ = try loss_recovery.processAck(&tr, &space, buildAck(4, 0));
    const result = loss_recovery.detectLosses(&tr, &space, &rtt_est, 101);

    try std.testing.expectEqual(@as(u32, 2), result.count);
    try std.testing.expectEqual(@as(u64, 2400), result.bytes_lost);
    // Tracker now holds only PNs 2 and 3 (gap < kPacketThreshold).
    try std.testing.expectEqual(@as(u32, 2), tr.count);
    try std.testing.expectEqual(@as(u64, 2), tr.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 3), tr.packets[1].pn);
}

test "MUST NOT declare lost a packet whose PN exceeds largest_acked [RFC9002 §6.1.1 ¶?]" {
    // §6.1: only packets below the largest acknowledged PN are
    // candidates for loss detection. Higher PNs may simply not have
    // been ACKed yet and must remain in flight.
    var tr: SentPacketTracker = .{};
    try tr.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 1, .sent_time_us = 1000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 5, .sent_time_us = 5000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 6, .sent_time_us = 6000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });

    var space: PnSpace = .{};
    space.largest_acked_sent = 1; // only PNs 0 and 1 are below
    var rtt_est: RttEstimator = .{};
    rtt_est.smoothed_rtt_us = 10 * ms;
    rtt_est.latest_rtt_us = 10 * ms;
    rtt_est.first_sample_taken = true;

    // `now` is huge so even time-threshold could fire on PN 5/6 —
    // but they sit above largest_acked_sent and must be spared.
    const result = loss_recovery.detectLosses(&tr, &space, &rtt_est, 1_000_000_000);

    try std.testing.expectEqual(@as(u32, 2), result.count);
    try std.testing.expectEqual(@as(u32, 2), tr.count);
    try std.testing.expectEqual(@as(u64, 5), tr.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 6), tr.packets[1].pn);
}

test "MUST use 9/8 of max(latest_rtt, smoothed_rtt) as the time threshold [RFC9002 §6.1.2 ¶2]" {
    // §6.1.2 ¶2: "loss_delay = kTimeThreshold * max(smoothed_rtt,
    // latest_rtt)" with kTimeThreshold = 9/8. Pin both the numerator
    // and denominator the implementation declares.
    try std.testing.expectEqual(@as(u64, 9), loss_recovery.time_threshold_num);
    try std.testing.expectEqual(@as(u64, 8), loss_recovery.time_threshold_den);

    // Behavioural check: with smoothed=10ms and latest=10ms, time
    // threshold = 11.25ms. A packet sent at t=0, with now=200ms,
    // is older than the cutoff (200 - 11.25 = 188.75ms) and must
    // be declared lost; so is one sent at 100ms.
    var tr: SentPacketTracker = .{};
    try tr.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 1, .sent_time_us = 100_000, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    var space: PnSpace = .{};
    space.largest_acked_sent = 1;
    var rtt_est: RttEstimator = .{};
    rtt_est.smoothed_rtt_us = 10 * ms;
    rtt_est.latest_rtt_us = 10 * ms;
    rtt_est.first_sample_taken = true;

    const result = loss_recovery.detectLosses(&tr, &space, &rtt_est, 200_000);
    try std.testing.expectEqual(@as(u32, 2), result.count);
}

test "MUST floor the time threshold at kGranularity (1ms) [RFC9002 §6.1.2 ¶2]" {
    // §6.1.2 ¶2: "The RECOMMENDED ... loss_delay ... has a lower
    // bound of kGranularity." With near-zero smoothed/latest RTT,
    // the time threshold collapses to the granularity. A packet sent
    // 1ms ago at now=2ms should be lost (cutoff = 2ms - 1ms = 1ms,
    // packet sent at 0 < 1).
    try std.testing.expectEqual(@as(u64, 1 * ms), rtt.granularity_us);

    var tr: SentPacketTracker = .{};
    try tr.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    var space: PnSpace = .{};
    space.largest_acked_sent = 0;
    var rtt_est: RttEstimator = .{};
    // Tiny RTT — 4*0/8 = 0, so the granularity floor must apply.
    rtt_est.smoothed_rtt_us = 0;
    rtt_est.latest_rtt_us = 0;
    rtt_est.first_sample_taken = true;

    const result = loss_recovery.detectLosses(&tr, &space, &rtt_est, 2 * ms);
    try std.testing.expectEqual(@as(u32, 1), result.count);
}

// ---------------------------------------------------------------- §6.2 PTO

test "MUST compute PTO as SRTT + max(4*RTTVar, kGranularity) + max_ack_delay [RFC9002 §6.2.1 ¶2]" {
    // §6.2.1 ¶2: "PTO = smoothed_rtt + max(4*rttvar, kGranularity)
    // + max_ack_delay."
    // SRTT = 100ms, RTTVar = 10ms → 4*10 = 40ms > 1ms. max_ack_delay=25ms.
    // PTO = 100 + 40 + 25 = 165ms.
    var r: RttEstimator = .{};
    r.smoothed_rtt_us = 100 * ms;
    r.rtt_var_us = 10 * ms;
    r.first_sample_taken = true;

    try std.testing.expectEqual(@as(u64, 165 * ms), r.pto(25 * ms));
}

test "MUST use kGranularity as the variance term when 4*RTTVar is smaller [RFC9002 §6.2.1 ¶3]" {
    // §6.2.1 ¶3: variance term has a lower bound of kGranularity (1ms).
    // SRTT = 1ms, RTTVar = 100µs → 4*100µs = 400µs < 1ms. PTO must
    // use 1ms instead. PTO = 1 + 1 + 25 = 27ms.
    var r: RttEstimator = .{};
    r.smoothed_rtt_us = 1 * ms;
    r.rtt_var_us = 100;
    r.first_sample_taken = true;

    try std.testing.expectEqual(@as(u64, 27 * ms), r.pto(25 * ms));
}

test "MUST double the PTO on each subsequent firing [RFC9002 §6.2.1 ¶?]" {
    // §6.2.1: "When a PTO timer expires, the PTO timer MUST be set
    // to a value larger than its current value." nullq implements
    // this via `backoffDuration(base, count) = base << count` in
    // `state.zig`, observable through `Connection.ptoMicros()`
    // (returns base << pto_count) and `Connection.ptoCount()`. Drive
    // a real handshake to confirmed, put two ack-eliciting packets in
    // flight on the client, and verify two consecutive PTO firings
    // bump the count and double the duration each time.
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const client = pair.clientConn();

    // Snapshot the un-backed-off PTO value. After handshake-confirmed
    // the path's RTT estimator is populated from the handshake ACKs,
    // so `pto_base` is a stable post-handshake number, not the
    // pre-sample initial-RTT default.
    try std.testing.expectEqual(@as(u32, 0), client.ptoCount());
    const pto_base = client.ptoMicros();
    try std.testing.expect(pto_base > 0);

    // Open a client-initiated bidi stream and write enough data to
    // generate two separate ack-eliciting packets — one PTO fire
    // removes ONE ack-eliciting packet at a time, so we need two in
    // flight to drive two consecutive fires without polling between
    // them.
    const s = try client.openBidi(0);
    // Each datagram caps at MTU (~1200B). 4000B straddles two packets.
    const blob: [4000]u8 = @splat(0x42);
    _ = try client.streamWrite(s.id, &blob);

    var pkt_buf: [2048]u8 = undefined;
    var packets_sent: u32 = 0;
    while (try client.poll(&pkt_buf, pair.now_us)) |_| {
        packets_sent += 1;
        if (packets_sent >= 2) break;
    }
    try std.testing.expect(packets_sent >= 2);

    // Tick at base_pto past the most recent send time. The oldest
    // ack-eliciting packet is now older than base_pto → PTO fires
    // once. After firing: pto_count == 1, ptoMicros == base * 2.
    pair.now_us += pto_base + ms;
    try client.tick(pair.now_us);

    try std.testing.expectEqual(@as(u32, 1), client.ptoCount());
    try std.testing.expectEqual(pto_base * 2, client.ptoMicros());

    // Tick again past the new (doubled) deadline. The second
    // ack-eliciting packet is still in flight (the first fire
    // removes only one), so a second PTO fires and the count
    // doubles again.
    pair.now_us += pto_base * 2 + ms;
    try client.tick(pair.now_us);

    try std.testing.expectEqual(@as(u32, 2), client.ptoCount());
    try std.testing.expectEqual(pto_base * 4, client.ptoMicros());
}

// ---------------------------------------------------------------- §A — ACK processing

test "MUST report whether the largest acked packet was ack-eliciting [RFC9002 §A.7]" {
    // §A.7 / §5.1: "An endpoint generates an RTT sample on receiving
    // an ACK frame that meets the following two conditions: ... the
    // newly acknowledged packet was ack-eliciting." nullq exposes
    // this via `AckProcessing.largest_acked_ack_eliciting` so the
    // connection knows when to skip the RTT update.
    var tr: SentPacketTracker = .{};
    // Packet 0 is PADDING-only (not ack-eliciting); packet 1 carries
    // a STREAM frame (ack-eliciting).
    try tr.record(.{ .pn = 0, .sent_time_us = 100, .bytes = 1200, .ack_eliciting = false, .in_flight = false });
    try tr.record(.{ .pn = 1, .sent_time_us = 200, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    var space: PnSpace = .{};
    space.next_pn = 2;

    // ACK only PN 0. largest_acked_ack_eliciting must be false →
    // caller (state.zig) must NOT update the RTT estimator from
    // this ACK.
    const r0 = try loss_recovery.processAck(&tr, &space, buildAck(0, 0));
    try std.testing.expect(r0.largest_acked_newly_acked);
    try std.testing.expect(!r0.largest_acked_ack_eliciting);
    try std.testing.expect(!r0.any_ack_eliciting_newly_acked);

    // ACK PN 1. Now largest_acked_ack_eliciting must be true.
    const r1 = try loss_recovery.processAck(&tr, &space, buildAck(1, 0));
    try std.testing.expect(r1.largest_acked_newly_acked);
    try std.testing.expect(r1.largest_acked_ack_eliciting);
    try std.testing.expect(r1.any_ack_eliciting_newly_acked);
}

test "MUST flag any newly-acked ack-eliciting packet for PTO-count reset [RFC9002 §A.7]" {
    // §6.2.1: "An endpoint resets its PTO backoff factor on receiving
    // acknowledgments." nullq exposes this via
    // `AckProcessing.any_ack_eliciting_newly_acked` so the caller can
    // gate the reset on at least one ack-eliciting newly-acked packet.
    var tr: SentPacketTracker = .{};
    try tr.record(.{ .pn = 0, .sent_time_us = 100, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 1, .sent_time_us = 200, .bytes = 100, .ack_eliciting = false, .in_flight = false });
    var space: PnSpace = .{};
    space.next_pn = 2;

    // ACK [0..1]. PN 0 is ack-eliciting, PN 1 is not. The flag must
    // still report true because *some* ack-eliciting packet was
    // newly-acked.
    const result = try loss_recovery.processAck(&tr, &space, buildAck(1, 1));
    try std.testing.expect(result.any_ack_eliciting_newly_acked);
}

test "MUST close the connection when an ACK acks an unsent packet [RFC9002 §A.3 ¶1]" {
    // §A.3 ¶1: "If any computed packet number is unsent, the endpoint
    // MUST close the connection with the error code PROTOCOL_VIOLATION."
    // RFC 9000 §13.1 carries the same normative requirement worded
    // differently; both gates resolve to the same check in
    // `Connection.handleAckAtLevel` (state.zig). The duplicate citation
    // is intentional — auditors searching either RFC find the same
    // observable behaviour pinned. The §13.1 partner test in
    // rfc9000_frames.zig drives the same fixture.
    //
    // Seal an authentic Initial whose payload is an ACK with
    // largest_acked = 100. The server's Initial PN space is empty
    // (next_pn = 0), so the largest_acked >= next_pn check fires and
    // the connection closes with PROTOCOL_VIOLATION.
    var srv = try fixture.buildServer();
    defer srv.deinit();

    var payload_buf: [32]u8 = undefined;
    const payload_len = try nullq.frame.encode(&payload_buf, .{ .ack = .{
        .largest_acked = 100,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    } });

    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid = [_]u8{ 0xa0, 0xb0, 0xc0, 0xd0 };

    const close_event = try fixture.feedAndExpectClose(
        &srv,
        &dcid,
        &scid,
        0,
        payload_buf[0..payload_len],
    );
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §7.2 initial congestion window

test "MUST compute initial cwnd as 10*MSS for MSS=1200 (cap < 14720) [RFC9002 §7.2 ¶2]" {
    // §7.2 ¶2: "Endpoints SHOULD use an initial congestion window of
    // ten times the maximum datagram size (max_datagram_size), while
    // limiting the window to the larger of 14720 bytes or twice the
    // maximum datagram size." For MSS=1200: 10*1200=12000 ≤
    // max(2400, 14720)=14720 → cwnd = 12000.
    const cfg: congestion.Config = .{ .max_datagram_size = 1200 };
    try std.testing.expectEqual(@as(u64, 12000), cfg.initialWindow());
}

test "MUST cap initial cwnd at max(2*MSS, 14720) when 10*MSS exceeds it [RFC9002 §7.2 ¶2]" {
    // §7.2 ¶2: With MSS=1500, 10*1500=15000 > max(3000, 14720)=14720,
    // so cwnd = min(15000, 14720) = 14720.
    const cfg: congestion.Config = .{ .max_datagram_size = 1500 };
    try std.testing.expectEqual(@as(u64, 14720), cfg.initialWindow());
}

test "MUST set min_window to 2 * max_datagram_size [RFC9002 §7.2 ¶?]" {
    // §7.2: "kMinimumWindow: 2 * max_datagram_size". The smallest
    // window an endpoint may pick after loss reduction.
    const cfg: congestion.Config = .{ .max_datagram_size = 1200 };
    try std.testing.expectEqual(@as(u64, 2400), cfg.minWindow());
}

// ---------------------------------------------------------------- §7.3 / §7.4 NewReno mechanics

test "MUST grow cwnd by bytes_acked while in slow start [RFC9002 §7.3 ¶?]" {
    // §7.3 ¶1: "While in slow start, a NewReno sender increases the
    // congestion window by the number of bytes acknowledged when each
    // acknowledgment is processed."
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    const initial = nr.cwnd;
    try std.testing.expect(nr.isSlowStart());

    nr.onPacketAcked(2400, 100);

    try std.testing.expectEqual(initial + 2400, nr.cwnd);
}

test "MUST grow cwnd by ~MSS per RTT in congestion avoidance [RFC9002 §B.5 ¶?]" {
    // §B.5: in congestion avoidance NewReno accumulates `bytes_acked`
    // until it crosses `cwnd`, then bumps cwnd by max_datagram_size.
    // After acking exactly cwnd bytes, cwnd grows by one MSS.
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    nr.ssthresh = 6000; // force CA mode
    try std.testing.expect(!nr.isSlowStart());

    nr.onPacketAcked(12000, 100);

    try std.testing.expectEqual(@as(u64, 13200), nr.cwnd);
}

test "MUST halve cwnd to ssthresh and enter recovery on loss [RFC9002 §B.6 ¶?]" {
    // §B.6 / §7.3: ssthresh = cwnd/2 (kLossReductionFactor=1/2),
    // cwnd = ssthresh, recovery_start_time set to the latest lost
    // packet's send time.
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;

    nr.onPacketLost(1200, 1_000_000);

    try std.testing.expectEqual(@as(?u64, 6000), nr.ssthresh);
    try std.testing.expectEqual(@as(u64, 6000), nr.cwnd);
    try std.testing.expect(nr.recovery_start_time_us != null);
    try std.testing.expect(nr.isInRecovery(500_000));
    try std.testing.expect(!nr.isInRecovery(1_500_000));
}

test "MUST NOT shrink cwnd below min_window on loss [RFC9002 §B.6 ¶?]" {
    // §B.6: kLossReductionFactor halves cwnd, but with a floor at
    // kMinimumWindow (2 * max_datagram_size). A controller already
    // at or below min_window does not shrink further.
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 2000; // already below 2*MSS

    nr.onPacketLost(1200, 1_000_000);

    try std.testing.expectEqual(nr.cfg.minWindow(), nr.cwnd);
}

test "MUST NOT grow cwnd from ACKs of packets sent before recovery [RFC9002 §7.4 ¶3]" {
    // §7.4 ¶3: "A sender in a recovery period MUST NOT increase the
    // congestion window in response to an ACK." Recovery clears only
    // when an ACK arrives for a packet sent after recovery began.
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.onPacketLost(1200, 1_000_000);
    const cwnd_after_loss = nr.cwnd;

    // ACK for a packet sent at 999_999 — strictly before recovery_start.
    nr.onPacketAcked(1200, 999_999);

    try std.testing.expectEqual(cwnd_after_loss, nr.cwnd);
}

// ---------------------------------------------------------------- §7.6 persistent congestion

test "MUST set persistent_congestion_threshold to 3 [RFC9002 §7.6.1 ¶?]" {
    // §7.6.1: "kPersistentCongestionThreshold: 3 ... is the number of
    // PTOs that must elapse without any acknowledgment of an
    // ack-eliciting packet for persistent congestion to be declared."
    try std.testing.expectEqual(@as(u8, 3), congestion.persistent_congestion_threshold);
}

test "MUST reset cwnd to min_window on persistent congestion [RFC9002 §7.6 ¶2]" {
    // §7.6 ¶2: "When persistent congestion is declared, the sender's
    // congestion window MUST be reduced to the minimum congestion
    // window (kMinimumWindow)." Recovery state must also clear.
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 30000;
    nr.recovery_start_time_us = 5_000_000;

    nr.onPersistentCongestion();

    try std.testing.expectEqual(nr.cfg.minWindow(), nr.cwnd);
    try std.testing.expectEqual(@as(?u64, null), nr.recovery_start_time_us);
}

test "MUST detect persistent congestion across 2+ ack-eliciting losses spanning PC duration [RFC9002 §7.6.1 ¶?]" {
    // §7.6.1: "When a sender establishes loss of all in-flight
    // packets sent over a long enough duration, the network is
    // considered to be experiencing persistent congestion." The
    // duration is `kPersistentCongestionThreshold * (smoothed_rtt +
    // max(4*rttvar, kGranularity) + max_ack_delay)` — i.e. PC threshold
    // PTOs of the un-backed-off PTO. RFC requires that ≥ 2 ack-eliciting
    // packets sent that far apart, both declared lost without any
    // ack-eliciting packet between them being acknowledged, trigger
    // the cwnd reset.
    //
    // nullq splits this across primitives + the connection orchestrator:
    // `loss_recovery.detectLosses` declares the losses, `state.zig`
    // measures the span and decides whether persistent congestion
    // applies, and `congestion.NewReno.onPersistentCongestion` does the
    // actual cwnd reset. This test exercises the primitive chain:
    // hand-stuff a tracker with two ack-eliciting packets exactly
    // PC-duration apart, declare them lost via `detectLosses`, then
    // fire the controller-side reset and verify cwnd collapses to
    // min_window.
    const max_ack_delay_us: u64 = 25 * ms;

    // Build a deterministic RTT estimator whose un-backed-off PTO is
    // a round number, so the PC-duration math is auditable.
    var rtt_est: RttEstimator = .{};
    rtt_est.smoothed_rtt_us = 50 * ms;
    rtt_est.rtt_var_us = 10 * ms;
    rtt_est.latest_rtt_us = 50 * ms;
    rtt_est.first_sample_taken = true;
    const pto_us = rtt_est.pto(max_ack_delay_us);
    // pto = 50ms + max(4*10ms, 1ms) + 25ms = 50 + 40 + 25 = 115ms.
    try std.testing.expectEqual(@as(u64, 115 * ms), pto_us);
    const pc_duration_us =
        @as(u64, congestion.persistent_congestion_threshold) * pto_us;

    // Two ack-eliciting packets straddling exactly the PC duration.
    // PN 0 sent at t=0; PN 1 sent at t = PC duration. Both must
    // become loss candidates (PN > largest_acked is spared, so the
    // ACK that drives detection covers PN 2).
    var tr: SentPacketTracker = .{};
    try tr.record(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try tr.record(.{
        .pn = 1,
        .sent_time_us = pc_duration_us,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // PN 2 sent later; it's the one that gets ACKed and drives the
    // time-threshold loss detection of PN 0 and PN 1.
    try tr.record(.{
        .pn = 2,
        .sent_time_us = pc_duration_us + 10 * ms,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    var space: PnSpace = .{};
    space.next_pn = 3;
    _ = try loss_recovery.processAck(&tr, &space, buildAck(2, 0));

    // Now run loss detection at a `now` past PN 1's time-threshold
    // cutoff. With smoothed_rtt = 50ms, time-threshold = 9/8 * 50ms
    // = 56.25ms. PN 1 sent at PC_duration; cutoff at PN1_send +
    // 56.25ms means PN 0 (sent at 0) and PN 1 (sent at PC duration)
    // are both old enough to be declared lost.
    const now_us = pc_duration_us + 200 * ms;
    const result = loss_recovery.detectLosses(&tr, &space, &rtt_est, now_us);

    try std.testing.expectEqual(@as(u32, 2), result.count);
    // The latest lost send time is PN 1's send time (= PC duration).
    try std.testing.expectEqual(pc_duration_us, result.largest_lost_send_time_us);

    // Caller confirms persistent congestion: the gap between the
    // earliest and latest ack-eliciting lost packets (PN 0 → PN 1)
    // spans ≥ PC duration. The connection orchestrator then fires
    // the controller-side reset.
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 30000;
    nr.recovery_start_time_us = result.largest_lost_send_time_us;

    nr.onPersistentCongestion();

    // §7.6 ¶2: cwnd MUST collapse to kMinimumWindow (= 2 * MSS).
    try std.testing.expectEqual(nr.cfg.minWindow(), nr.cwnd);
    try std.testing.expectEqual(@as(?u64, null), nr.recovery_start_time_us);
}
