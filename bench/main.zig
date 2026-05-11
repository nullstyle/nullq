//! quic_zig microbenchmarks.
//!
//! Measures hot paths that every sent or received packet exercises:
//!  - varint encode/decode (every length field)
//!  - frame encode/decode (STREAM, ACK)
//!  - short-header pure parse/serialize (no AEAD)
//!  - connection ID generation (BoringSSL CSPRNG)
//!  - packet protection, AEAD, and header protection
//!  - stream send/receive state and reassembly
//!  - ACK range, loss recovery, PTO, and DATAGRAM event surfaces
//!
//! Each benchmark auto-tunes its iteration count to roughly
//! `target_ms` of wall time, then prints one line:
//!
//!     name: <ns/op> ns/op (<ops/sec> ops/sec, <iters> iterations)
//!
//! Run with: `zig build bench`, or `zig build bench -- --json path`
//! for a machine-readable report. The build wires this binary at
//! ReleaseSafe by default; use `-Dbench-unsafe-release-fast=true` for
//! unsafe ReleaseFast measurements.
//!
//! Out of scope:
//!  - Full Connection.handle / pollDatagram lifecycle
//!  - TLS handshake throughput

const std = @import("std");
const builtin = @import("builtin");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const connection_datagram_bench = @import("connection_datagram.zig");
const loss_ack_bench = @import("loss_ack.zig");
const packet_crypto_bench = @import("packet_crypto.zig");
const path_flow_bench = @import("path_flow.zig");
const stream_bench = @import("stream_reassembly.zig");
const tokens_lb_bench = @import("tokens_lb.zig");
const transport_params_bench = @import("transport_params.zig");

const varint = quic_zig.wire.varint;
const header = quic_zig.wire.header;
const frame = quic_zig.frame;
const frame_types = frame.types;
const ack_range = frame.ack_range;

/// Approximate per-benchmark wall budget. We grow the iteration
/// count until elapsed >= this.
const target_ns: u64 = 100 * std.time.ns_per_ms;
const max_bench_results: usize = 64;

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

fn unixNanos() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec *% std.time.ns_per_s +% nsec;
}

fn hostnameSlice(buf: *[std.posix.HOST_NAME_MAX]u8) ?[]const u8 {
    return std.posix.gethostname(buf) catch null;
}

fn shortSha(sha: ?[]const u8) ?[]const u8 {
    const s = sha orelse return null;
    return s[0..@min(s.len, 12)];
}

fn appendSanitizedToken(out: *std.ArrayList(u8), allocator: std.mem.Allocator, token: []const u8) !void {
    var wrote = false;
    for (token) |c| {
        const safe = switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => c,
            else => '-',
        };
        try out.append(allocator, safe);
        wrote = true;
    }
    if (!wrote) try out.appendSlice(allocator, "unknown");
}

fn buildReportPath(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    dir: []const u8,
    generated_unix_ns: u64,
    machine_id: []const u8,
    github_sha: ?[]const u8,
    github_run_id: ?[]const u8,
) ![]const u8 {
    out.clearRetainingCapacity();
    try out.appendSlice(allocator, dir);
    if (dir.len > 0 and dir[dir.len - 1] != std.fs.path.sep) {
        try out.append(allocator, std.fs.path.sep);
    }
    try out.appendSlice(allocator, "quic-zig-bench-");
    try out.print(allocator, "{d}-", .{generated_unix_ns});
    try appendSanitizedToken(out, allocator, machine_id);
    try out.append(allocator, '-');
    if (shortSha(github_sha)) |sha| {
        try appendSanitizedToken(out, allocator, sha);
    } else {
        try out.appendSlice(allocator, "local");
    }
    try out.append(allocator, '-');
    if (github_run_id) |run_id| {
        try appendSanitizedToken(out, allocator, run_id);
    } else {
        try out.appendSlice(allocator, "manual");
    }
    try out.appendSlice(allocator, ".json");
    return out.items;
}

const BenchResult = struct {
    name: []const u8,
    iters: u64,
    total_ns: u64,
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
) BenchResult {
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

    const result: BenchResult = .{
        .name = name,
        .iters = iters,
        .total_ns = total_ns,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_per_sec,
    };
    report(result);
    return result;
}

fn recordBenchmark(
    results: *[max_bench_results]BenchResult,
    result_count: *usize,
    name: []const u8,
    comptime Ctx: type,
    ctx: Ctx,
    comptime runOnce: fn (Ctx, u64) u64,
) void {
    results[result_count.*] = benchmark(name, Ctx, ctx, runOnce);
    result_count.* += 1;
}

fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(allocator, "\\\""),
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '\n' => try out.appendSlice(allocator, "\\n"),
        '\r' => try out.appendSlice(allocator, "\\r"),
        '\t' => try out.appendSlice(allocator, "\\t"),
        0x00...0x08, 0x0b...0x0c, 0x0e...0x1f => try out.print(
            allocator,
            "\\u{x:0>4}",
            .{c},
        ),
        else => try out.append(allocator, c),
    };
    try out.append(allocator, '"');
}

fn appendNullableJsonString(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    maybe: ?[]const u8,
) !void {
    if (maybe) |s| {
        try appendJsonString(out, allocator, s);
    } else {
        try out.appendSlice(allocator, "null");
    }
}

fn appendNullableU64(out: *std.ArrayList(u8), allocator: std.mem.Allocator, maybe: ?u64) !void {
    if (maybe) |value| {
        try out.print(allocator, "{d}", .{value});
    } else {
        try out.appendSlice(allocator, "null");
    }
}

fn ensureParentDir(io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    try std.Io.Dir.cwd().createDirPath(io, parent);
}

fn writeReportFile(io: std.Io, path: []const u8, data: []const u8) !void {
    try ensureParentDir(io, path);
    if (std.fs.path.isAbsolute(path)) {
        var file = try std.Io.Dir.createFileAbsolute(io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    } else {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
    }
}

fn writeJsonReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    generated_unix_ns: u64,
    machine_id: []const u8,
    hostname: ?[]const u8,
    results: []const BenchResult,
    github_sha: ?[]const u8,
    github_run_id: ?[]const u8,
    github_ref_name: ?[]const u8,
) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n");
    try out.print(allocator, "  \"schema_version\": 2,\n", .{});
    try out.appendSlice(allocator, "  \"suite\": \"quic_zig.microbench\",\n");
    try out.print(allocator, "  \"generated_unix_ns\": {d},\n", .{generated_unix_ns});
    try out.print(allocator, "  \"target_ns_per_benchmark\": {d},\n", .{target_ns});
    try out.print(allocator, "  \"min_iters\": {d},\n", .{min_iters});
    try out.print(allocator, "  \"max_iters\": {d},\n", .{max_iters});
    try out.appendSlice(allocator, "  \"optimize\": ");
    try appendJsonString(&out, allocator, @tagName(builtin.mode));
    try out.appendSlice(allocator, ",\n");
    try out.print(
        allocator,
        "  \"bench_unsafe_release_fast\": {},\n",
        .{builtin.mode == .ReleaseFast},
    );
    try out.appendSlice(allocator, "  \"report_path\": ");
    try appendJsonString(&out, allocator, path);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "  \"quic_zig_version\": ");
    try appendJsonString(&out, allocator, quic_zig.version());
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "  \"zig_version\": ");
    try appendJsonString(&out, allocator, builtin.zig_version_string);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "  \"target\": {\n");
    try out.appendSlice(allocator, "    \"arch\": ");
    try appendJsonString(&out, allocator, @tagName(builtin.target.cpu.arch));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"os\": ");
    try appendJsonString(&out, allocator, @tagName(builtin.target.os.tag));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"abi\": ");
    try appendJsonString(&out, allocator, @tagName(builtin.target.abi));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"cpu_model\": ");
    try appendJsonString(&out, allocator, builtin.target.cpu.model.name);
    try out.appendSlice(allocator, "\n  },\n");
    const logical_cpu_count: ?u64 = if (std.Thread.getCpuCount()) |n| @intCast(n) else |_| null;
    const total_memory_bytes: ?u64 = if (std.process.totalSystemMemory()) |n| n else |_| null;
    const uts = std.posix.uname();
    try out.appendSlice(allocator, "  \"system\": {\n");
    try out.appendSlice(allocator, "    \"machine_id\": ");
    try appendJsonString(&out, allocator, machine_id);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"hostname\": ");
    try appendNullableJsonString(&out, allocator, hostname);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"logical_cpu_count\": ");
    try appendNullableU64(&out, allocator, logical_cpu_count);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"total_memory_bytes\": ");
    try appendNullableU64(&out, allocator, total_memory_bytes);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"uname\": {\n");
    try out.appendSlice(allocator, "      \"sysname\": ");
    try appendJsonString(&out, allocator, std.mem.sliceTo(&uts.sysname, 0));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "      \"release\": ");
    try appendJsonString(&out, allocator, std.mem.sliceTo(&uts.release, 0));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "      \"version\": ");
    try appendJsonString(&out, allocator, std.mem.sliceTo(&uts.version, 0));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "      \"machine\": ");
    try appendJsonString(&out, allocator, std.mem.sliceTo(&uts.machine, 0));
    try out.appendSlice(allocator, "\n    }\n");
    try out.appendSlice(allocator, "  },\n");
    try out.appendSlice(allocator, "  \"github\": {\n");
    try out.appendSlice(allocator, "    \"sha\": ");
    try appendNullableJsonString(&out, allocator, github_sha);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"run_id\": ");
    try appendNullableJsonString(&out, allocator, github_run_id);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"ref_name\": ");
    try appendNullableJsonString(&out, allocator, github_ref_name);
    try out.appendSlice(allocator, "\n  },\n");
    try out.appendSlice(allocator, "  \"benchmarks\": [\n");
    for (results, 0..) |r, i| {
        try out.appendSlice(allocator, "    {\n");
        try out.appendSlice(allocator, "      \"name\": ");
        try appendJsonString(&out, allocator, r.name);
        try out.appendSlice(allocator, ",\n");
        try out.print(allocator, "      \"iterations\": {d},\n", .{r.iters});
        try out.print(allocator, "      \"total_ns\": {d},\n", .{r.total_ns});
        try out.print(allocator, "      \"ns_per_op\": {d:.6},\n", .{r.ns_per_op});
        try out.print(allocator, "      \"ops_per_sec\": {d:.6}\n", .{r.ops_per_sec});
        try out.appendSlice(allocator, if (i + 1 == results.len) "    }\n" else "    },\n");
    }
    try out.appendSlice(allocator, "  ]\n}\n");

    try writeReportFile(io, path, out.items);
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

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var json_path: ?[]const u8 = null;
    var json_dir: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--json")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonPath;
            if (json_dir != null) return error.DuplicateJsonTarget;
            json_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--json-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonDir;
            if (json_path != null) return error.DuplicateJsonTarget;
            json_dir = args[i];
        } else {
            std.debug.print("unknown benchmark argument: {s}\n", .{args[i]});
            return error.UnknownArgument;
        }
    }

    const generated_unix_ns = unixNanos();
    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = hostnameSlice(&hostname_buf);
    const machine_id = init.environ_map.get("BENCH_MACHINE_ID") orelse hostname orelse "unknown";
    const github_sha = init.environ_map.get("GITHUB_SHA");
    const github_run_id = init.environ_map.get("GITHUB_RUN_ID");
    const github_ref_name = init.environ_map.get("GITHUB_REF_NAME");
    var generated_report_path: std.ArrayList(u8) = .empty;
    defer generated_report_path.deinit(allocator);
    const report_path: ?[]const u8 = if (json_path) |path|
        path
    else if (json_dir) |dir|
        try buildReportPath(
            &generated_report_path,
            allocator,
            dir,
            generated_unix_ns,
            machine_id,
            github_sha,
            github_run_id,
        )
    else
        null;

    std.debug.print("quic_zig microbenchmarks (target ~{d}ms each, {s})\n", .{
        target_ns / std.time.ns_per_ms,
        @tagName(builtin.mode),
    });
    std.debug.print("---------------------------------------------------------------\n", .{});

    var results: [max_bench_results]BenchResult = undefined;
    var result_count: usize = 0;

    // varint
    const varint_ctx: VarintCtx = .{ .inputs = .{
        0x3F,
        0x3FFF,
        0x3FFF_FFFF,
        0x3FFF_FFFF_FFFF_FFFF,
    } };
    recordBenchmark(&results, &result_count, "varint_encode", VarintCtx, varint_ctx, runVarintEncode);
    recordBenchmark(&results, &result_count, "varint_decode", VarintCtx, varint_ctx, runVarintDecode);

    // STREAM frame
    var stream_ctx: StreamCtx = .{ .payload = undefined };
    for (&stream_ctx.payload, 0..) |*b, idx| b.* = @intCast(idx & 0xff);
    recordBenchmark(&results, &result_count, "frame_stream_encode_100b", *const StreamCtx, &stream_ctx, runStreamEncode);
    recordBenchmark(&results, &result_count, "frame_stream_decode_100b", *const StreamCtx, &stream_ctx, runStreamDecode);

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
    recordBenchmark(&results, &result_count, "frame_ack_encode_5ranges", *const AckCtx, &ack_ctx, runAckEncode);
    recordBenchmark(&results, &result_count, "frame_ack_decode_5ranges", *const AckCtx, &ack_ctx, runAckDecode);

    // Short-header packet (no AEAD; pure header bytes)
    var short_ctx: ShortHdrCtx = .{
        .dcid = try header.ConnId.fromSlice(&[_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 }),
        .pn_truncated = 0x12345678,
    };
    _ = &short_ctx;
    recordBenchmark(&results, &result_count, "short_header_encode", *const ShortHdrCtx, &short_ctx, runShortEncode);
    recordBenchmark(&results, &result_count, "short_header_decode", *const ShortHdrCtx, &short_ctx, runShortDecode);

    // Connection ID generation (BoringSSL CSPRNG, 8-byte CID)
    recordBenchmark(&results, &result_count, "cid_generate_8bytes", CidCtx, .{ .cid_len = 8 }, runCidGenerate);

    // Packet protection and AEAD paths
    const hp_ctx = try packet_crypto_bench.initHpMaskAes128CachedCtx();
    recordBenchmark(
        &results,
        &result_count,
        "hp_mask_aes128_cached",
        *const packet_crypto_bench.HpMaskAes128CachedCtx,
        &hp_ctx,
        packet_crypto_bench.runHpMaskAes128Cached,
    );
    var aead_seal_ctx = try packet_crypto_bench.initAeadAes128Seal1200bCtx();
    defer aead_seal_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        "aead_aes128_seal_1200b",
        *const packet_crypto_bench.AeadAes128Seal1200bCtx,
        &aead_seal_ctx,
        packet_crypto_bench.runAeadAes128Seal1200b,
    );
    var aead_open_ctx = try packet_crypto_bench.initAeadAes128Open1200bCtx();
    defer aead_open_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        "aead_aes128_open_1200b",
        *const packet_crypto_bench.AeadAes128Open1200bCtx,
        &aead_open_ctx,
        packet_crypto_bench.runAeadAes128Open1200b,
    );
    const packet_1rtt_seal_ctx = try packet_crypto_bench.initPacket1RttSeal100bAes128Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_1rtt_seal_100b_aes128",
        *const packet_crypto_bench.Packet1RttSeal100bAes128Ctx,
        &packet_1rtt_seal_ctx,
        packet_crypto_bench.runPacket1RttSeal100bAes128,
    );
    const packet_1rtt_open_ctx = try packet_crypto_bench.initPacket1RttOpen100bAes128Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_1rtt_open_100b_aes128",
        *const packet_crypto_bench.Packet1RttOpen100bAes128Ctx,
        &packet_1rtt_open_ctx,
        packet_crypto_bench.runPacket1RttOpen100bAes128,
    );
    const initial_seal_ctx = try packet_crypto_bench.initPacketInitialSeal1200bRfc9001Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_initial_seal_1200b_rfc9001",
        *const packet_crypto_bench.PacketInitialSeal1200bRfc9001Ctx,
        &initial_seal_ctx,
        packet_crypto_bench.runPacketInitialSeal1200bRfc9001,
    );
    var initial_open_ctx = try packet_crypto_bench.initPacketInitialOpen1200bRfc9001Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_initial_open_1200b_rfc9001",
        *packet_crypto_bench.PacketInitialOpen1200bRfc9001Ctx,
        &initial_open_ctx,
        packet_crypto_bench.runPacketInitialOpen1200bRfc9001,
    );

    // Stream send/receive state machines
    var stream_send_ctx = try stream_bench.initStreamSendAckLossRequeueCtx(allocator);
    defer stream_send_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        stream_bench.stream_send_ack_loss_requeue_name,
        *const stream_bench.StreamSendAckLossRequeueCtx,
        &stream_send_ctx,
        stream_bench.runStreamSendAckLossRequeue,
    );
    var stream_recv_ctx = try stream_bench.initStreamRecvReassemblySparse64kCtx(allocator);
    defer stream_recv_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        stream_bench.stream_recv_reassembly_sparse_64k_name,
        *const stream_bench.StreamRecvReassemblySparse64kCtx,
        &stream_recv_ctx,
        stream_bench.runStreamRecvReassemblySparse64k,
    );

    // ACK range and loss recovery primitives
    const pn_ack_ctx = loss_ack_bench.initPnSpaceRecordAckRangesCtx();
    recordBenchmark(
        &results,
        &result_count,
        loss_ack_bench.pn_space_record_ack_ranges_name,
        *const loss_ack_bench.PnSpaceRecordAckRangesCtx,
        &pn_ack_ctx,
        loss_ack_bench.runPnSpaceRecordAckRanges,
    );
    const loss_pto_ctx = loss_ack_bench.initLossPtoTickCtx();
    recordBenchmark(
        &results,
        &result_count,
        loss_ack_bench.loss_pto_tick_name,
        *const loss_ack_bench.LossPtoTickCtx,
        &loss_pto_ctx,
        loss_ack_bench.runLossPtoTick,
    );
    var connection_ack_loss_ctx = try loss_ack_bench.initConnectionAckLossDispatchCtx(allocator);
    defer connection_ack_loss_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        loss_ack_bench.connection_ack_loss_dispatch_name,
        *const loss_ack_bench.ConnectionAckLossDispatchCtx,
        &connection_ack_loss_ctx,
        loss_ack_bench.runConnectionAckLossDispatch,
    );

    // Connection-adjacent DATAGRAM ACK/loss event queue
    const datagram_event_ctx = connection_datagram_bench.initDatagramEventCtx();
    recordBenchmark(
        &results,
        &result_count,
        "conn_datagram_send_ack_loss_events",
        *const connection_datagram_bench.DatagramEventCtx,
        &datagram_event_ctx,
        connection_datagram_bench.runConnDatagramSendAckLossEvents,
    );

    // Transport-parameter codec paths
    var tp_encode_ctx = try transport_params_bench.initTransportParamsEncodeCommonCtx();
    defer tp_encode_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        transport_params_bench.transport_params_encode_common_name,
        *const transport_params_bench.TransportParamsEncodeCommonCtx,
        &tp_encode_ctx,
        transport_params_bench.runTransportParamsEncodeCommon,
    );
    var tp_decode_ctx = try transport_params_bench.initTransportParamsDecodeCommonCtx();
    defer tp_decode_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        transport_params_bench.transport_params_decode_common_name,
        *const transport_params_bench.TransportParamsDecodeCommonCtx,
        &tp_decode_ctx,
        transport_params_bench.runTransportParamsDecodeCommon,
    );
    var tp_extensions_ctx = try transport_params_bench.initTransportParamsDecodeExtensionsCtx();
    defer tp_extensions_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        transport_params_bench.transport_params_decode_extensions_name,
        *const transport_params_bench.TransportParamsDecodeExtensionsCtx,
        &tp_extensions_ctx,
        transport_params_bench.runTransportParamsDecodeExtensions,
    );

    // Token, stateless-reset, and QUIC-LB helpers
    var retry_token_ctx = tokens_lb_bench.initRetryTokenMintValidateCtx();
    defer retry_token_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.retry_token_mint_validate_name,
        *const tokens_lb_bench.RetryTokenMintValidateCtx,
        &retry_token_ctx,
        tokens_lb_bench.runRetryTokenMintValidate,
    );
    var new_token_ctx = tokens_lb_bench.initNewTokenMintValidateCtx();
    defer new_token_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.new_token_mint_validate_name,
        *const tokens_lb_bench.NewTokenMintValidateCtx,
        &new_token_ctx,
        tokens_lb_bench.runNewTokenMintValidate,
    );
    var reset_token_ctx = tokens_lb_bench.initStatelessResetTokenDeriveCtx();
    defer reset_token_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.stateless_reset_token_derive_name,
        *const tokens_lb_bench.StatelessResetTokenDeriveCtx,
        &reset_token_ctx,
        tokens_lb_bench.runStatelessResetTokenDerive,
    );
    var quic_lb_ctx = try tokens_lb_bench.initQuicLbCidGenerateCtx();
    defer quic_lb_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.quic_lb_cid_generate_name,
        *const tokens_lb_bench.QuicLbCidGenerateCtx,
        &quic_lb_ctx,
        tokens_lb_bench.runQuicLbCidGenerate,
    );

    // Flow-control, path-validation, and path scheduling helpers
    var flow_control_ctx = path_flow_bench.initFlowControlCreditUpdateCtx();
    defer flow_control_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        path_flow_bench.flow_control_credit_update_name,
        *const path_flow_bench.FlowControlCreditUpdateCtx,
        &flow_control_ctx,
        path_flow_bench.runFlowControlCreditUpdate,
    );
    var path_validator_ctx = path_flow_bench.initPathValidatorChallengeResponseCtx();
    defer path_validator_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        path_flow_bench.path_validator_challenge_response_name,
        *const path_flow_bench.PathValidatorChallengeResponseCtx,
        &path_validator_ctx,
        path_flow_bench.runPathValidatorChallengeResponse,
    );
    var path_set_ctx = try path_flow_bench.initPathSetScheduleRoundRobinCtx(allocator);
    defer path_set_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        path_flow_bench.path_set_schedule_round_robin_name,
        *const path_flow_bench.PathSetScheduleRoundRobinCtx,
        &path_set_ctx,
        path_flow_bench.runPathSetScheduleRoundRobin,
    );

    std.debug.print("---------------------------------------------------------------\n", .{});
    if (report_path) |path| {
        try writeJsonReport(
            allocator,
            io,
            path,
            generated_unix_ns,
            machine_id,
            hostname,
            results[0..result_count],
            github_sha,
            github_run_id,
            github_ref_name,
        );
        std.debug.print("wrote benchmark JSON report: {s}\n", .{path});
    }
    std.debug.print("done. {d} benchmarks ran.\n", .{result_count});
}
