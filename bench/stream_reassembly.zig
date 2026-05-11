//! Deterministic stream microbenchmark helpers.

const std = @import("std");
const quic_zig = @import("quic_zig");

const send_stream = quic_zig.conn.send_stream;
const recv_stream = quic_zig.conn.recv_stream;

const SendStream = send_stream.SendStream;
const RecvStream = recv_stream.RecvStream;

pub const stream_send_ack_loss_requeue_name = "stream_send_ack_loss_requeue";
pub const stream_recv_reassembly_sparse_64k_name = "stream_recv_reassembly_sparse_64k";

pub const stream_bench_chunk_size: usize = 1024;
pub const stream_bench_total_bytes: usize = 64 * 1024;
pub const stream_bench_chunk_count: usize = stream_bench_total_bytes / stream_bench_chunk_size;
const stream_bench_pair_count: usize = stream_bench_chunk_count / 2;

comptime {
    std.debug.assert(stream_bench_total_bytes % stream_bench_chunk_size == 0);
    std.debug.assert(stream_bench_chunk_count % 2 == 0);
}

pub const StreamSendAckLossRequeueCtx = struct {
    allocator: std.mem.Allocator,
    stream: *SendStream,
    payload: []u8,

    pub fn init(allocator: std.mem.Allocator) !StreamSendAckLossRequeueCtx {
        const stream = try allocator.create(SendStream);
        errdefer allocator.destroy(stream);
        stream.* = SendStream.init(allocator);
        errdefer stream.deinit();

        const payload = try allocator.alloc(u8, stream_bench_total_bytes);
        errdefer allocator.free(payload);
        fillFixture(payload);

        var ctx: StreamSendAckLossRequeueCtx = .{
            .allocator = allocator,
            .stream = stream,
            .payload = payload,
        };
        try ctx.reserve();
        return ctx;
    }

    pub fn deinit(self: *StreamSendAckLossRequeueCtx) void {
        self.stream.deinit();
        self.allocator.destroy(self.stream);
        self.allocator.free(self.payload);
        self.* = undefined;
    }

    fn reserve(self: *StreamSendAckLossRequeueCtx) !void {
        try self.stream.bytes.ensureTotalCapacity(self.allocator, stream_bench_total_bytes);
        try self.stream.pending.ensureTotalCapacity(self.allocator, stream_bench_pair_count);
        try self.stream.acked_above.ensureTotalCapacity(self.allocator, stream_bench_pair_count);
        try self.stream.in_flight.ensureTotalCapacity(self.allocator, stream_bench_chunk_count);
    }
};

pub const StreamRecvReassemblySparse64kCtx = struct {
    allocator: std.mem.Allocator,
    stream: *RecvStream,
    payload: []u8,
    read_buf: []u8,
    order: [stream_bench_chunk_count]usize,

    pub fn init(allocator: std.mem.Allocator) !StreamRecvReassemblySparse64kCtx {
        const stream = try allocator.create(RecvStream);
        errdefer allocator.destroy(stream);
        stream.* = RecvStream.init(allocator);
        errdefer stream.deinit();

        const payload = try allocator.alloc(u8, stream_bench_total_bytes);
        errdefer allocator.free(payload);
        fillFixture(payload);

        const read_buf = try allocator.alloc(u8, stream_bench_total_bytes);
        errdefer allocator.free(read_buf);

        var ctx: StreamRecvReassemblySparse64kCtx = .{
            .allocator = allocator,
            .stream = stream,
            .payload = payload,
            .read_buf = read_buf,
            .order = undefined,
        };
        fillSparseOrder(&ctx.order);
        try ctx.reserve();
        return ctx;
    }

    pub fn deinit(self: *StreamRecvReassemblySparse64kCtx) void {
        self.stream.deinit();
        self.allocator.destroy(self.stream);
        self.allocator.free(self.read_buf);
        self.allocator.free(self.payload);
        self.* = undefined;
    }

    fn reserve(self: *StreamRecvReassemblySparse64kCtx) !void {
        try self.stream.bytes.ensureTotalCapacity(self.allocator, stream_bench_total_bytes);
        try self.stream.ranges.ensureTotalCapacity(self.allocator, stream_bench_chunk_count);
        self.stream.max_buffered_span = stream_bench_total_bytes;
    }
};

pub fn initStreamSendAckLossRequeueCtx(
    allocator: std.mem.Allocator,
) !StreamSendAckLossRequeueCtx {
    return StreamSendAckLossRequeueCtx.init(allocator);
}

pub fn initStreamRecvReassemblySparse64kCtx(
    allocator: std.mem.Allocator,
) !StreamRecvReassemblySparse64kCtx {
    return StreamRecvReassemblySparse64kCtx.init(allocator);
}

pub fn runStreamSendAckLossRequeue(
    ctx: *const StreamSendAckLossRequeueCtx,
    iters: u64,
) u64 {
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        resetSendStream(ctx.stream);

        const accepted = ctx.stream.write(ctx.payload) catch unreachable;
        std.debug.assert(accepted == stream_bench_total_bytes);
        sum +%= accepted;

        var chunk_idx: usize = 0;
        while (chunk_idx < stream_bench_chunk_count) : (chunk_idx += 1) {
            const chunk = ctx.stream.peekChunk(stream_bench_chunk_size).?;
            const bytes = ctx.stream.chunkBytes(chunk);
            sum +%= bytes[0];
            sum +%= bytes[bytes.len - 1];
            ctx.stream.recordSent(@intCast(chunk_idx), chunk) catch unreachable;
            sum +%= chunk.offset;
            sum +%= chunk.length;
        }

        var odd: usize = 1;
        while (odd < stream_bench_chunk_count) : (odd += 2) {
            ctx.stream.onPacketAcked(@intCast(odd)) catch unreachable;
            sum +%= ctx.stream.acked_above.items.len;
        }

        var even: usize = 0;
        while (even < stream_bench_chunk_count) : (even += 2) {
            ctx.stream.onPacketLost(@intCast(even)) catch unreachable;
            sum +%= ctx.stream.pending.items.len;
        }

        var retransmit_idx: usize = 0;
        while (retransmit_idx < stream_bench_pair_count) : (retransmit_idx += 1) {
            const pn: u64 = stream_bench_chunk_count + retransmit_idx;
            const chunk = ctx.stream.peekChunk(stream_bench_chunk_size).?;
            const bytes = ctx.stream.chunkBytes(chunk);
            sum +%= bytes[0];
            sum +%= bytes[bytes.len - 1];
            ctx.stream.recordSent(pn, chunk) catch unreachable;
            ctx.stream.onPacketAcked(pn) catch unreachable;
            sum +%= ctx.stream.ackedFloor();
        }

        std.debug.assert(ctx.stream.ackedFloor() == stream_bench_total_bytes);
        std.debug.assert(ctx.stream.bytes.items.len == 0);
        std.debug.assert(ctx.stream.pending.items.len == 0);
        std.debug.assert(ctx.stream.acked_above.items.len == 0);
        std.debug.assert(ctx.stream.in_flight.count() == 0);
    }
    return sum;
}

pub fn runStreamRecvReassemblySparse64k(
    ctx: *const StreamRecvReassemblySparse64kCtx,
    iters: u64,
) u64 {
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        resetRecvStream(ctx.stream);

        for (ctx.order) |chunk_idx| {
            const offset = chunk_idx * stream_bench_chunk_size;
            const data = ctx.payload[offset..][0..stream_bench_chunk_size];
            ctx.stream.recv(@intCast(offset), data, false) catch unreachable;
            sum +%= ctx.stream.peerHighestOffset();
            sum +%= ctx.stream.ranges.items.len;
        }

        const readable = ctx.stream.readableBytes();
        std.debug.assert(readable == stream_bench_total_bytes);
        sum +%= readable;

        const read_n = ctx.stream.read(ctx.read_buf);
        std.debug.assert(read_n == stream_bench_total_bytes);
        sum +%= read_n;
        sum +%= ctx.read_buf[0];
        sum +%= ctx.read_buf[stream_bench_total_bytes - 1];

        std.debug.assert(ctx.stream.read_offset == stream_bench_total_bytes);
        std.debug.assert(ctx.stream.bytes.items.len == 0);
        std.debug.assert(ctx.stream.ranges.items.len == 0);
    }
    return sum;
}

fn resetSendStream(stream: *SendStream) void {
    stream.bytes.clearRetainingCapacity();
    stream.pending.clearRetainingCapacity();
    stream.in_flight.clearRetainingCapacity();
    stream.acked_above.clearRetainingCapacity();

    stream.max_buffered = stream_bench_total_bytes;
    stream.base_offset = 0;
    stream.write_offset = 0;
    stream.fin_marked = false;
    stream.fin_in_flight = false;
    stream.fin_acked = false;
    stream.final_size = null;
    stream.reset = null;
    stream.state = .ready;
}

fn resetRecvStream(stream: *RecvStream) void {
    stream.bytes.clearRetainingCapacity();
    stream.ranges.clearRetainingCapacity();

    stream.read_offset = 0;
    stream.end_offset = 0;
    stream.final_size = null;
    stream.fin_seen = false;
    stream.reset = null;
    stream.max_buffered_span = stream_bench_total_bytes;
    stream.state = .recv;
}

fn fillFixture(buf: []u8) void {
    for (buf, 0..) |*b, idx| {
        b.* = @intCast((idx * 131 + 17) & 0xff);
    }
}

fn fillSparseOrder(order: *[stream_bench_chunk_count]usize) void {
    var out: usize = 0;

    var odd = stream_bench_chunk_count - 1;
    while (true) {
        order[out] = odd;
        out += 1;
        if (odd == 1) break;
        odd -= 2;
    }

    var even: usize = 0;
    while (even < stream_bench_chunk_count) : (even += 2) {
        order[out] = even;
        out += 1;
    }
}

test "send ack/loss/requeue helper drains all in-flight data" {
    var ctx = try StreamSendAckLossRequeueCtx.init(std.testing.allocator);
    defer ctx.deinit();

    const sum = runStreamSendAckLossRequeue(&ctx, 1);
    try std.testing.expect(sum != 0);
    try std.testing.expectEqual(@as(u64, stream_bench_total_bytes), ctx.stream.ackedFloor());
    try std.testing.expectEqual(@as(usize, 0), ctx.stream.bytes.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.stream.pending.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.stream.acked_above.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.stream.in_flight.count());
}

test "recv sparse 64k helper reassembles fixture" {
    var ctx = try StreamRecvReassemblySparse64kCtx.init(std.testing.allocator);
    defer ctx.deinit();

    const sum = runStreamRecvReassemblySparse64k(&ctx, 1);
    try std.testing.expect(sum != 0);
    try std.testing.expectEqualSlices(u8, ctx.payload, ctx.read_buf);
    try std.testing.expectEqual(@as(u64, stream_bench_total_bytes), ctx.stream.read_offset);
    try std.testing.expectEqual(@as(usize, 0), ctx.stream.bytes.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.stream.ranges.items.len);
}
