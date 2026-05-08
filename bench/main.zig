//! quic_zig microbenchmarks.
//!
//! Wire/frame-level only. We measure the hot codecs that every
//! sent or received packet exercises:
//!  - varint encode/decode (every length field)
//!  - frame encode/decode (STREAM, ACK)
//!  - short-header pure parse/serialize (no AEAD)
//!  - connection ID generation (BoringSSL CSPRNG)
//!
//! Each benchmark auto-tunes its iteration count to roughly
//! `target_ms` of wall time, then prints one line:
//!
//!     name: <ns/op> ns/op (<ops/sec> ops/sec, <iters> iterations)
//!
//! Run with: `zig build bench`. The build wires this binary at
//! ReleaseFast; Debug numbers are not useful.
//!
//! Out of scope (need fixtures + AEAD setup, deferred to a later
//! pass):
//!  - Initial / Handshake long-header packet build with AEAD
//!  - 1-RTT short-header packet protect / unprotect (header
//!    protection + AEAD seal/open)
//!  - Full Connection.handle / pollDatagram lifecycle
//!  - TLS handshake throughput

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");

const varint = quic_zig.wire.varint;
const header = quic_zig.wire.header;
const frame = quic_zig.frame;
const frame_types = frame.types;
const ack_range = frame.ack_range;

/// Approximate per-benchmark wall budget. We grow the iteration
/// count until elapsed >= this.
const target_ns: u64 = 100 * std.time.ns_per_ms;

/// Lower bound so very fast benchmarks (sub-ns/op) still produce
/// stable numbers.
const min_iters: u64 = 1_000;

/// Upper bound to keep one-shot runs from looping forever on a
/// dead-fast benchmark.
const max_iters: u64 = 200_000_000;

/// Read a monotonic clock in nanoseconds. We dodge `std.time` here
/// because Zig 0.16 moved time to the new I/O API, and these
/// benchmarks are deliberately Io-free — they exercise pure
/// codecs, not async machinery.
fn nowNanos() u64 {
    var ts: std.c.timespec = undefined;
    // POSIX MONOTONIC. macOS, Linux, BSDs all support this.
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec *% std.time.ns_per_s +% nsec;
}

const BenchResult = struct {
    name: []const u8,
    iters: u64,
    ns_per_op: f64,
    ops_per_sec: f64,
};

fn report(r: BenchResult) void {
    std.debug.print(
        "{s}: {d:.2} ns/op ({d:.2} ops/sec, {d} iterations)\n",
        .{ r.name, r.ns_per_op, r.ops_per_sec, r.iters },
    );
}

/// Run `runOnce` repeatedly with auto-tuned iteration count, then
/// time a final hot pass. `runOnce(iters)` must perform exactly
/// `iters` work units and return a value to feed `doNotOptimizeAway`.
fn benchmark(
    name: []const u8,
    comptime Ctx: type,
    ctx: Ctx,
    comptime runOnce: fn (Ctx, u64) u64,
) void {
    // Warmup + calibration: start small and double until we cross
    // ~10ms, then extrapolate to target_ns.
    var iters: u64 = min_iters;
    var elapsed_ns: u64 = 0;
    const calibration_floor: u64 = 10 * std.time.ns_per_ms;

    while (iters <= max_iters) {
        const start = nowNanos();
        const sink = runOnce(ctx, iters);
        const end = nowNanos();
        std.mem.doNotOptimizeAway(sink);
        elapsed_ns = end - start;
        if (elapsed_ns >= calibration_floor) break;
        iters *|= 2;
    }

    if (iters > max_iters) iters = max_iters;

    // Extrapolate to ~target_ns based on the calibration run.
    if (elapsed_ns > 0) {
        const scaled: u128 = @as(u128, iters) * @as(u128, target_ns) / @as(u128, elapsed_ns);
        var next: u64 = @intCast(@min(scaled, @as(u128, max_iters)));
        if (next < min_iters) next = min_iters;
        iters = next;
    }

    // Hot run.
    const start = nowNanos();
    const sink = runOnce(ctx, iters);
    const end = nowNanos();
    std.mem.doNotOptimizeAway(sink);
    const total_ns: u64 = end - start;

    const ns_per_op: f64 = @as(f64, @floatFromInt(total_ns)) /
        @as(f64, @floatFromInt(iters));
    const ops_per_sec: f64 = if (total_ns == 0)
        0
    else
        @as(f64, @floatFromInt(iters)) * 1e9 / @as(f64, @floatFromInt(total_ns));

    report(.{
        .name = name,
        .iters = iters,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_per_sec,
    });
}

// -- varint --------------------------------------------------------------

const VarintCtx = struct {
    inputs: [4]u64,
};

fn runVarintEncode(ctx: VarintCtx, iters: u64) u64 {
    var sink: [8]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const v = ctx.inputs[i & 3];
        const n = varint.encode(&sink, v) catch unreachable;
        sum +%= @intCast(n);
        sum +%= sink[0];
    }
    return sum;
}

fn runVarintDecode(ctx: VarintCtx, iters: u64) u64 {
    // Pre-encode the four canonical lengths.
    var encoded: [4][8]u8 = undefined;
    var lens: [4]u8 = undefined;
    for (ctx.inputs, 0..) |v, idx| {
        const n = varint.encode(&encoded[idx], v) catch unreachable;
        lens[idx] = @intCast(n);
    }
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const idx = i & 3;
        const slice = encoded[idx][0..lens[idx]];
        const d = varint.decode(slice) catch unreachable;
        sum +%= d.value;
        sum +%= d.bytes_read;
    }
    return sum;
}

// -- frames: STREAM ------------------------------------------------------

const StreamCtx = struct {
    payload: [100]u8,
};

fn streamFrame(ctx: *const StreamCtx) frame.Frame {
    return .{ .stream = .{
        .stream_id = 4,
        .offset = 1024,
        .data = &ctx.payload,
        .has_offset = true,
        .has_length = true,
        .fin = false,
    } };
}

fn runStreamEncode(ctx: *const StreamCtx, iters: u64) u64 {
    const f = streamFrame(ctx);
    var buf: [256]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = frame.encode(&buf, f) catch unreachable;
        sum +%= n;
        sum +%= buf[0];
    }
    return sum;
}

fn runStreamDecode(ctx: *const StreamCtx, iters: u64) u64 {
    const f = streamFrame(ctx);
    var encoded: [256]u8 = undefined;
    const enc_len = frame.encode(&encoded, f) catch unreachable;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const d = frame.decode(encoded[0..enc_len]) catch unreachable;
        sum +%= d.bytes_consumed;
        sum +%= d.frame.stream.stream_id;
    }
    return sum;
}

// -- frames: ACK ---------------------------------------------------------

const AckCtx = struct {
    /// Encoded gap/length pairs for 5 subsequent ranges. Built once
    /// in `init` so the encode/decode timing doesn't include
    /// writeRanges.
    ranges_bytes: []const u8,
    ranges_buf: [64]u8,
    ranges_len: usize,
};

fn ackFrame(ctx: *const AckCtx) frame.Frame {
    return .{ .ack = .{
        .largest_acked = 1_000,
        .ack_delay = 250,
        .first_range = 4,
        .range_count = 5,
        .ranges_bytes = ctx.ranges_bytes,
        .ecn_counts = null,
    } };
}

fn runAckEncode(ctx: *const AckCtx, iters: u64) u64 {
    const f = ackFrame(ctx);
    var buf: [128]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = frame.encode(&buf, f) catch unreachable;
        sum +%= n;
        sum +%= buf[0];
    }
    return sum;
}

fn runAckDecode(ctx: *const AckCtx, iters: u64) u64 {
    const f = ackFrame(ctx);
    var encoded: [128]u8 = undefined;
    const enc_len = frame.encode(&encoded, f) catch unreachable;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const d = frame.decode(encoded[0..enc_len]) catch unreachable;
        sum +%= d.bytes_consumed;
        sum +%= d.frame.ack.largest_acked;
    }
    return sum;
}

// -- short-header packet (1-RTT) ----------------------------------------

const ShortHdrCtx = struct {
    dcid: header.ConnId,
    pn_truncated: u64,
};

fn shortHeader(ctx: *const ShortHdrCtx) header.Header {
    return .{ .one_rtt = .{
        .dcid = ctx.dcid,
        .spin_bit = false,
        .reserved_bits = 0,
        .key_phase = false,
        .pn_length = .four,
        .pn_truncated = ctx.pn_truncated,
    } };
}

fn runShortEncode(ctx: *const ShortHdrCtx, iters: u64) u64 {
    const h = shortHeader(ctx);
    var buf: [64]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = header.encode(&buf, h) catch unreachable;
        sum +%= n;
        sum +%= buf[0];
    }
    return sum;
}

fn runShortDecode(ctx: *const ShortHdrCtx, iters: u64) u64 {
    const h = shortHeader(ctx);
    var encoded: [64]u8 = undefined;
    const enc_len = header.encode(&encoded, h) catch unreachable;
    const dcid_len = ctx.dcid.len;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const p = header.parse(encoded[0..enc_len], dcid_len) catch unreachable;
        sum +%= p.pn_offset;
        sum +%= p.header.one_rtt.pn_truncated;
    }
    return sum;
}

// -- connection ID generation -------------------------------------------

const CidCtx = struct {
    /// Match the QUIC v1 default DCID length most stacks pick (8).
    cid_len: u8,
};

fn runCidGenerate(ctx: CidCtx, iters: u64) u64 {
    var sum: u64 = 0;
    var bytes: [header.max_cid_len]u8 = undefined;
    const slice = bytes[0..ctx.cid_len];
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        boringssl.crypto.rand.fillBytes(slice) catch unreachable;
        // Fold all output into the sink so the optimizer can't
        // hoist the call.
        for (slice) |b| sum +%= b;
    }
    return sum;
}

// -- entry point ---------------------------------------------------------

pub fn main() !void {
    std.debug.print("quic_zig microbenchmarks (target ~{d}ms each, ReleaseFast)\n", .{
        target_ns / std.time.ns_per_ms,
    });
    std.debug.print("---------------------------------------------------------------\n", .{});

    // varint
    const varint_ctx: VarintCtx = .{ .inputs = .{
        0x3F,
        0x3FFF,
        0x3FFF_FFFF,
        0x3FFF_FFFF_FFFF_FFFF,
    } };
    benchmark("varint_encode", VarintCtx, varint_ctx, runVarintEncode);
    benchmark("varint_decode", VarintCtx, varint_ctx, runVarintDecode);

    // STREAM frame
    var stream_ctx: StreamCtx = .{ .payload = undefined };
    for (&stream_ctx.payload, 0..) |*b, idx| b.* = @intCast(idx & 0xff);
    benchmark("frame_stream_encode_100b", *const StreamCtx, &stream_ctx, runStreamEncode);
    benchmark("frame_stream_decode_100b", *const StreamCtx, &stream_ctx, runStreamDecode);

    // ACK frame with 5 ranges
    var ack_ctx: AckCtx = .{
        .ranges_bytes = undefined,
        .ranges_buf = undefined,
        .ranges_len = 0,
    };
    {
        const ranges = [_]frame_types.AckRange{
            .{ .gap = 1, .length = 3 },
            .{ .gap = 2, .length = 5 },
            .{ .gap = 1, .length = 2 },
            .{ .gap = 4, .length = 7 },
            .{ .gap = 0, .length = 1 },
        };
        ack_ctx.ranges_len = try ack_range.writeRanges(&ack_ctx.ranges_buf, &ranges);
        ack_ctx.ranges_bytes = ack_ctx.ranges_buf[0..ack_ctx.ranges_len];
    }
    benchmark("frame_ack_encode_5ranges", *const AckCtx, &ack_ctx, runAckEncode);
    benchmark("frame_ack_decode_5ranges", *const AckCtx, &ack_ctx, runAckDecode);

    // Short-header packet (no AEAD; pure header bytes)
    var short_ctx: ShortHdrCtx = .{
        .dcid = try header.ConnId.fromSlice(&[_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 }),
        .pn_truncated = 0x12345678,
    };
    _ = &short_ctx;
    benchmark("short_header_encode", *const ShortHdrCtx, &short_ctx, runShortEncode);
    benchmark("short_header_decode", *const ShortHdrCtx, &short_ctx, runShortDecode);

    // Connection ID generation (BoringSSL CSPRNG, 8-byte CID)
    benchmark("cid_generate_8bytes", CidCtx, .{ .cid_len = 8 }, runCidGenerate);

    std.debug.print("---------------------------------------------------------------\n", .{});
    std.debug.print("done. {d} benchmarks ran.\n", .{9});
}
