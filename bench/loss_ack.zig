//! Loss-recovery and ACK-range benchmark helpers.
//!
//! The fixtures are fixed-size and allocate nothing per iteration.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");

const ack_range = quic_zig.frame.ack_range;
const frame_types = quic_zig.frame.types;
const congestion = quic_zig.conn.congestion;
const Connection = quic_zig.Connection;
const loss_recovery = quic_zig.conn.loss_recovery;
const pn_space_mod = quic_zig.conn.pn_space;
const rtt_mod = quic_zig.conn.rtt;
const sent_packets = quic_zig.conn.sent_packets;

const PnSpace = pn_space_mod.PnSpace;
const RttEstimator = rtt_mod.RttEstimator;
const SentPacket = sent_packets.SentPacket;
const SentPacketTracker = sent_packets.SentPacketTracker;

pub const pn_space_record_ack_ranges_name = "pn_space_record_ack_ranges";
pub const loss_pto_tick_name = "loss_pto_tick";
pub const connection_ack_loss_dispatch_name = "connection_ack_loss_dispatch";

const ack_range_pn_count: usize = 24;
const default_ack_range_pns: [ack_range_pn_count]u64 = .{
    1008, 1009, 1012, 1020, 1021, 1022, 1023, 1024,
    1000, 1001, 1002, 995,  996,  998,  997,  990,
    991,  1006, 1007, 1010, 1011, 999,  1005, 1004,
};

/// Fixed fixture for received-PN range insertion and ACK frame
/// emission. The PN order intentionally mixes out-of-order inserts,
/// contiguous extension, and bridge inserts, ending with four ranges:
/// [990..991], [995..1002], [1004..1012], [1020..1024].
pub const PnSpaceRecordAckRangesCtx = struct {
    pns: [ack_range_pn_count]u64 = default_ack_range_pns,
    now_start_ms: u64 = 10_000,
    ack_delay_scaled: u64 = 37,
    delayed_ack_packet_threshold: u8 = 4,
    max_lower_ranges: u64 = 8,

    pub fn init() PnSpaceRecordAckRangesCtx {
        return .{};
    }

    pub fn deinit(_: *PnSpaceRecordAckRangesCtx) void {}
};

pub fn initPnSpaceRecordAckRangesCtx() PnSpaceRecordAckRangesCtx {
    return PnSpaceRecordAckRangesCtx.init();
}

/// One operation records the fixed received-PN fixture into a fresh
/// PN space, builds a bounded ACK frame, and walks the encoded ACK
/// ranges back through the wire-format iterator.
pub fn runPnSpaceRecordAckRanges(ctx: *const PnSpaceRecordAckRangesCtx, iters: u64) u64 {
    var space: PnSpace = undefined;
    var ranges_buf: [128]u8 = undefined;
    var sum: u64 = 0;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        space = .{};

        for (ctx.pns, 0..) |pn, idx| {
            const now_ms = ctx.now_start_ms + @as(u64, @intCast(idx));
            space.recordReceivedPacketDelayed(
                pn,
                now_ms,
                true,
                ctx.delayed_ack_packet_threshold,
            );
        }

        _ = space.received.promoteDelayedAck(ctx.now_start_ms + 50, 25);

        const ack = space.received.toAckFrameLimitedRanges(
            ctx.ack_delay_scaled,
            &ranges_buf,
            ranges_buf.len,
            ctx.max_lower_ranges,
        ) catch unreachable;

        sum +%= ack.largest_acked;
        sum +%= ack.first_range;
        sum +%= ack.range_count;
        sum +%= ack.ranges_bytes.len;
        sum +%= @intFromBool(space.received.pending_ack);
        sum +%= @as(u64, space.received.range_count);

        var it = ack_range.iter(ack);
        while ((it.next() catch unreachable)) |interval| {
            sum +%= interval.smallest;
            sum +%= interval.largest;
        }
    }

    return sum;
}

const loss_ranges_count: u64 = 3;

/// Fixed fixture for ACK processing, threshold loss detection, and a
/// PTO probe tick over caller-owned recovery state. The full
/// `Connection.tick` path also requeues stream/control frames, but
/// those side effects sit behind connection-private APIs and allocator
/// state; this context stays on the pure recovery surface.
pub const LossPtoTickCtx = struct {
    packet_count: u8 = 40,
    sent_start_us: u64 = 0,
    sent_spacing_us: u64 = 1_000,
    bytes: u64 = 1_200,
    now_us: u64 = 120_000,
    max_ack_delay_us: u64 = 25 * rtt_mod.ms,
    smoothed_rtt_us: u64 = 20 * rtt_mod.ms,
    latest_rtt_us: u64 = 20 * rtt_mod.ms,
    rtt_var_us: u64 = 5 * rtt_mod.ms,
    initial_pto_count: u32 = 0,
    ack_largest: u64 = 31,
    ack_first_range: u64 = 0,
    ack_delay_scaled: u64 = 0,
    ack_ranges_buf: [32]u8 = undefined,
    ack_ranges_len: usize = 0,

    pub fn init() LossPtoTickCtx {
        var ctx: LossPtoTickCtx = .{};
        ctx.ack_ranges_len = ack_range.writeRanges(&ctx.ack_ranges_buf, &.{
            // ACK [31], then [24..26], [16..18], [8..9].
            .{ .gap = 3, .length = 2 },
            .{ .gap = 4, .length = 2 },
            .{ .gap = 5, .length = 1 },
        }) catch unreachable;
        return ctx;
    }

    pub fn deinit(_: *LossPtoTickCtx) void {}

    fn ackFrame(self: *const LossPtoTickCtx) frame_types.Ack {
        return .{
            .largest_acked = self.ack_largest,
            .ack_delay = self.ack_delay_scaled,
            .first_range = self.ack_first_range,
            .range_count = loss_ranges_count,
            .ranges_bytes = self.ack_ranges_buf[0..self.ack_ranges_len],
            .ecn_counts = null,
        };
    }

    fn rtt(self: *const LossPtoTickCtx) RttEstimator {
        return .{
            .latest_rtt_us = self.latest_rtt_us,
            .smoothed_rtt_us = self.smoothed_rtt_us,
            .rtt_var_us = self.rtt_var_us,
            .min_rtt_us = self.smoothed_rtt_us,
            .first_sample_taken = true,
        };
    }
};

pub fn initLossPtoTickCtx() LossPtoTickCtx {
    return LossPtoTickCtx.init();
}

/// One operation seeds sent packets, processes a deterministic ACK
/// with multiple ranges, runs RFC 9002 threshold loss detection, then
/// fires one PTO probe candidate if the computed PTO deadline is due.
pub fn runLossPtoTick(ctx: *const LossPtoTickCtx, iters: u64) u64 {
    var tracker: SentPacketTracker = undefined;
    var space: PnSpace = undefined;
    var sum: u64 = 0;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        tracker = .{};
        space = .{};
        seedSentPackets(&tracker, ctx);

        const acked = loss_recovery.processAck(&tracker, &space, ctx.ackFrame()) catch unreachable;
        var rtt = ctx.rtt();
        const losses = loss_recovery.detectLosses(&tracker, &space, &rtt, ctx.now_us);

        var pto_count = ctx.initial_pto_count;
        const pto_us = ptoDuration(&rtt, ctx.max_ack_delay_us, pto_count);
        const fired = firePtoIfDue(&tracker, ctx.now_us, pto_us, &pto_count);

        sum +%= acked.newly_acked_count;
        sum +%= acked.bytes_acked;
        sum +%= acked.in_flight_bytes_acked;
        sum +%= @intFromBool(acked.largest_acked_newly_acked);
        sum +%= losses.count;
        sum +%= losses.bytes_lost;
        sum +%= losses.in_flight_bytes_lost;
        sum +%= pto_us;
        sum +%= pto_count;
        sum +%= tracker.count;
        if (fired) |packet| {
            sum +%= packet.pn;
            sum +%= packet.bytes;
        }
    }

    return sum;
}

fn seedSentPackets(tracker: *SentPacketTracker, ctx: *const LossPtoTickCtx) void {
    var pn: u64 = 0;
    while (pn < ctx.packet_count) : (pn += 1) {
        tracker.record(.{
            .pn = pn,
            .sent_time_us = ctx.sent_start_us + pn * ctx.sent_spacing_us,
            .bytes = ctx.bytes + (pn & 7) * 8,
            .ack_eliciting = true,
            .in_flight = true,
        }) catch unreachable;
    }
}

fn ptoDuration(rtt: *const RttEstimator, max_ack_delay_us: u64, pto_count: u32) u64 {
    const base = rtt.pto(max_ack_delay_us);
    const shift: u6 = @intCast(@min(pto_count, 16));
    const max_u64: u64 = std.math.maxInt(u64);
    if (base > (max_u64 >> shift)) return max_u64;
    return base << shift;
}

fn firePtoIfDue(
    tracker: *SentPacketTracker,
    now_us: u64,
    pto_us: u64,
    pto_count: *u32,
) ?SentPacket {
    var i: u32 = 0;
    while (i < tracker.count) : (i += 1) {
        const packet = tracker.packets[i];
        if (!packet.ack_eliciting) continue;
        if (now_us < packet.sent_time_us +| pto_us) return null;
        pto_count.* +|= 1;
        return tracker.removeAt(i);
    }
    return null;
}

const connection_ack_ranges_count: u64 = 3;

/// Real `Connection.handleAckAtLevel` fixture for ACK range walking,
/// per-packet dispatch hooks, and packet-threshold loss detection. It
/// intentionally carries no STREAM/control/DATAGRAM payload ownership;
/// this isolates the connection-level tracker and dispatch loop shape
/// from application-specific requeue work.
pub const ConnectionAckLossDispatchCtx = struct {
    allocator: std.mem.Allocator,
    tls_ctx: boringssl.tls.Context,
    conn: *Connection,
    packet_count: u8 = 64,
    sent_start_us: u64 = 0,
    sent_spacing_us: u64 = 1_000,
    bytes: u64 = 1_200,
    now_us: u64 = 120_000,
    ack_largest: u64 = 63,
    ack_first_range: u64 = 3,
    ack_delay_scaled: u64 = 0,
    ack_ranges_buf: [32]u8 = undefined,
    ack_ranges_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !ConnectionAckLossDispatchCtx {
        var tls_ctx = try boringssl.tls.Context.initClient(.{});
        errdefer tls_ctx.deinit();

        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);
        conn.* = try Connection.initClient(allocator, tls_ctx, "bench.invalid");
        errdefer conn.deinit();

        var ctx: ConnectionAckLossDispatchCtx = .{
            .allocator = allocator,
            .tls_ctx = tls_ctx,
            .conn = conn,
        };
        ctx.ack_ranges_len = ack_range.writeRanges(&ctx.ack_ranges_buf, &.{
            // ACK [60..63], then [48..51], [32..35], [16..18].
            .{ .gap = 7, .length = 3 },
            .{ .gap = 11, .length = 3 },
            .{ .gap = 12, .length = 2 },
        }) catch unreachable;
        return ctx;
    }

    pub fn deinit(self: *ConnectionAckLossDispatchCtx) void {
        self.conn.deinit();
        self.allocator.destroy(self.conn);
        self.tls_ctx.deinit();
        self.* = undefined;
    }

    fn ackFrame(self: *const ConnectionAckLossDispatchCtx) frame_types.Ack {
        return .{
            .largest_acked = self.ack_largest,
            .ack_delay = self.ack_delay_scaled,
            .first_range = self.ack_first_range,
            .range_count = connection_ack_ranges_count,
            .ranges_bytes = self.ack_ranges_buf[0..self.ack_ranges_len],
            .ecn_counts = null,
        };
    }
};

pub fn initConnectionAckLossDispatchCtx(
    allocator: std.mem.Allocator,
) !ConnectionAckLossDispatchCtx {
    return ConnectionAckLossDispatchCtx.init(allocator);
}

fn resetConnectionAckLossDispatch(ctx: *const ConnectionAckLossDispatchCtx) void {
    const path = ctx.conn.primaryPath();
    path.sent = .{};
    path.app_pn_space = .{};
    path.app_pn_space.next_pn = ctx.packet_count;
    path.path.rtt = .{
        .latest_rtt_us = 20 * rtt_mod.ms,
        .smoothed_rtt_us = 20 * rtt_mod.ms,
        .rtt_var_us = 5 * rtt_mod.ms,
        .min_rtt_us = 20 * rtt_mod.ms,
        .first_sample_taken = true,
    };
    path.path.cc = congestion.NewReno.init(.{});
    path.pto_count = 3;
    path.pending_ping = false;
    path.pmtu_probe_pn = null;
    path.pmtu_probes_in_flight = 0;
    ctx.conn.qlog_packets_lost = 0;
}

fn seedConnectionSentPackets(ctx: *const ConnectionAckLossDispatchCtx) void {
    const sent = ctx.conn.sentForLevel(.application);
    var pn: u64 = 0;
    while (pn < ctx.packet_count) : (pn += 1) {
        sent.record(.{
            .pn = pn,
            .sent_time_us = ctx.sent_start_us + pn * ctx.sent_spacing_us,
            .bytes = ctx.bytes + (pn & 7) * 8,
            .ack_eliciting = true,
            .in_flight = true,
        }) catch unreachable;
    }
}

/// One operation runs the production ACK handler over a fixture that
/// ACKs several ranges and declares the remaining lower packets lost.
pub fn runConnectionAckLossDispatch(
    ctx: *const ConnectionAckLossDispatchCtx,
    iters: u64,
) u64 {
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        resetConnectionAckLossDispatch(ctx);
        seedConnectionSentPackets(ctx);

        ctx.conn.handleAckAtLevel(.application, ctx.ackFrame(), ctx.now_us) catch unreachable;

        const path = ctx.conn.primaryPath();
        sum +%= path.app_pn_space.largest_acked_sent.?;
        sum +%= path.sent.count;
        sum +%= path.sent.bytes_in_flight;
        sum +%= path.pto_count;
        sum +%= path.path.cc.cwnd;
        sum +%= ctx.conn.qlog_packets_lost;
    }
    return sum;
}

test "pn_space_record_ack_ranges fixture emits the expected range shape" {
    const ctx = PnSpaceRecordAckRangesCtx.init();
    try std.testing.expect(runPnSpaceRecordAckRanges(&ctx, 1) != 0);

    var space: PnSpace = .{};
    for (ctx.pns, 0..) |pn, idx| {
        space.recordReceivedPacketDelayed(
            pn,
            ctx.now_start_ms + @as(u64, @intCast(idx)),
            true,
            ctx.delayed_ack_packet_threshold,
        );
    }
    try std.testing.expectEqual(@as(u8, 4), space.received.range_count);

    var buf: [128]u8 = undefined;
    const ack = try space.received.toAckFrameLimitedRanges(
        ctx.ack_delay_scaled,
        &buf,
        buf.len,
        ctx.max_lower_ranges,
    );
    try std.testing.expectEqual(@as(u64, 1024), ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 3), ack.range_count);
}

test "loss_pto_tick fixture reaches ack loss and pto paths" {
    const ctx = LossPtoTickCtx.init();
    try std.testing.expect(runLossPtoTick(&ctx, 1) != 0);

    var tracker: SentPacketTracker = .{};
    var space: PnSpace = .{};
    seedSentPackets(&tracker, &ctx);

    const acked = try loss_recovery.processAck(&tracker, &space, ctx.ackFrame());
    try std.testing.expect(acked.newly_acked_count > 0);

    var rtt = ctx.rtt();
    const losses = loss_recovery.detectLosses(&tracker, &space, &rtt, ctx.now_us);
    try std.testing.expect(losses.count > 0);

    var pto_count = ctx.initial_pto_count;
    const fired = firePtoIfDue(
        &tracker,
        ctx.now_us,
        ptoDuration(&rtt, ctx.max_ack_delay_us, pto_count),
        &pto_count,
    );
    try std.testing.expect(fired != null);
    try std.testing.expectEqual(@as(u32, 1), pto_count);
}

test "connection_ack_loss_dispatch fixture drains acked and lost packets" {
    var ctx = try ConnectionAckLossDispatchCtx.init(std.testing.allocator);
    defer ctx.deinit();

    try std.testing.expect(runConnectionAckLossDispatch(&ctx, 1) != 0);
    try std.testing.expectEqual(@as(u32, 0), ctx.conn.sentForLevel(.application).count);
    try std.testing.expectEqual(
        ctx.ack_largest,
        ctx.conn.pnSpaceForLevel(.application).largest_acked_sent.?,
    );
    try std.testing.expect(ctx.conn.qlog_packets_lost > 0);
}
