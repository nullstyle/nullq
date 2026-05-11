//! Deterministic flow-control and path-validation benchmark helpers.
//!
//! Fixtures allocate only during context setup. Hot loops stay on the
//! public state-machine surfaces used by Connection.

const std = @import("std");
const quic_zig = @import("quic_zig");

const flow_control = quic_zig.conn.flow_control;
const path_mod = quic_zig.conn.path;
const path_validator_mod = quic_zig.conn.path_validator;

const ConnectionData = flow_control.ConnectionData;
const StreamCount = flow_control.StreamCount;
const StreamData = flow_control.StreamData;
const PathSet = path_mod.PathSet;
const PathValidator = path_validator_mod.PathValidator;

pub const flow_control_credit_update_name = "flow_control_credit_update";
pub const path_validator_challenge_response_name = "path_validator_challenge_response";
pub const path_set_schedule_round_robin_name = "path_set_schedule_round_robin";

pub const flow_control_step_count: usize = 8;
pub const path_validator_token_count: usize = 8;
pub const path_set_round_robin_path_count: usize = 5;

pub const FlowControlCreditUpdateCtx = struct {
    conn_local_initial: u64 = 64 * 1024,
    conn_peer_initial: u64 = 64 * 1024,
    stream_local_initial: u64 = 16 * 1024,
    stream_peer_initial: u64 = 16 * 1024,
    stream_count_local_initial: u64 = 32,
    stream_count_peer_initial: u64 = 32,

    conn_sent_chunks: [flow_control_step_count]u64 = .{
        211, 377, 89, 610, 144, 512, 233, 377,
    },
    conn_peer_chunks: [flow_control_step_count]u64 = .{
        313, 127, 449, 251, 337, 181, 397, 223,
    },
    conn_peer_max_updates: [flow_control_step_count]u64 = .{
        64 * 1024,
        66 * 1024,
        65 * 1024,
        70 * 1024,
        69 * 1024,
        72 * 1024,
        72 * 1024,
        80 * 1024,
    },
    conn_local_max_updates: [flow_control_step_count]u64 = .{
        65 * 1024,
        64 * 1024,
        68 * 1024,
        68 * 1024,
        73 * 1024,
        72 * 1024,
        76 * 1024,
        82 * 1024,
    },

    stream_sent_chunks: [flow_control_step_count]u64 = .{
        53, 97, 211, 31, 144, 89, 233, 55,
    },
    stream_peer_chunks: [flow_control_step_count]u64 = .{
        67, 131, 41, 173, 59, 199, 83, 157,
    },
    stream_peer_max_updates: [flow_control_step_count]u64 = .{
        16 * 1024,
        17 * 1024,
        17 * 1024 - 64,
        18 * 1024,
        19 * 1024,
        18 * 1024,
        20 * 1024,
        24 * 1024,
    },
    stream_local_max_updates: [flow_control_step_count]u64 = .{
        16 * 1024,
        16 * 1024 + 512,
        16 * 1024 + 128,
        17 * 1024,
        18 * 1024,
        18 * 1024 - 256,
        20 * 1024,
        23 * 1024,
    },

    peer_stream_indices: [flow_control_step_count]u64 = .{
        0, 2, 1, 4, 3, 7, 6, 5,
    },
    stream_count_updates: [flow_control_step_count]u64 = .{
        32, 34, 33, 40, 39, 48, 48, 64,
    },

    pub fn init() FlowControlCreditUpdateCtx {
        return .{};
    }

    pub fn deinit(_: *FlowControlCreditUpdateCtx) void {}
};

pub fn initFlowControlCreditUpdateCtx() FlowControlCreditUpdateCtx {
    return FlowControlCreditUpdateCtx.init();
}

pub fn deinitFlowControlCreditUpdateCtx(ctx: *FlowControlCreditUpdateCtx) void {
    ctx.deinit();
}

/// One operation rotates a fixed fixture through connection data,
/// stream data, and stream-count credit updates. The rotation prevents
/// the hot loop from being a single constant state transition while
/// keeping every operation under the advertised limits.
pub fn runFlowControlCreditUpdate(
    ctx: *const FlowControlCreditUpdateCtx,
    iters: u64,
) u64 {
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        sum +%= runFlowControlCreditUpdateOnce(ctx, @intCast(i & (flow_control_step_count - 1)));
    }
    return sum;
}

fn runFlowControlCreditUpdateOnce(
    ctx: *const FlowControlCreditUpdateCtx,
    rotate: usize,
) u64 {
    var conn = ConnectionData.init(ctx.conn_local_initial, ctx.conn_peer_initial);
    var stream = StreamData.init(ctx.stream_local_initial, ctx.stream_peer_initial);
    var stream_count = StreamCount.init(ctx.stream_count_local_initial, ctx.stream_count_peer_initial);
    var sum: u64 = 0;

    var step: usize = 0;
    while (step < flow_control_step_count) : (step += 1) {
        const idx = (rotate + step) & (flow_control_step_count - 1);

        conn.onMaxData(ctx.conn_peer_max_updates[idx]);
        tryOrUnreachable(conn.recordSent(ctx.conn_sent_chunks[idx]));
        conn.raiseLocalMax(ctx.conn_local_max_updates[idx]);
        tryOrUnreachable(conn.recordPeerSent(ctx.conn_peer_chunks[idx]));
        sum +%= conn.allowance();
        sum +%= conn.peer_max;
        sum +%= conn.local_max;
        sum +%= conn.we_sent;
        sum +%= conn.peer_sent;

        stream.onMaxStreamData(ctx.stream_peer_max_updates[idx]);
        tryOrUnreachable(stream.recordSent(ctx.stream_sent_chunks[idx]));
        stream.raiseLocalMax(ctx.stream_local_max_updates[idx]);
        tryOrUnreachable(stream.recordPeerSent(ctx.stream_peer_chunks[idx]));
        sum +%= stream.allowance();
        sum +%= stream.peer_max;
        sum +%= stream.local_max;
        sum +%= stream.we_sent;
        sum +%= stream.peer_sent;

        stream_count.onMaxStreams(ctx.stream_count_updates[idx]);
        tryOrUnreachable(stream_count.recordWeOpened());
        tryOrUnreachable(stream_count.recordPeerOpened(ctx.peer_stream_indices[idx]));
        sum +%= stream_count.peer_max;
        sum +%= stream_count.local_max;
        sum +%= stream_count.we_opened;
        sum +%= stream_count.peer_opened;
        sum +%= @intFromBool(stream_count.weCanOpen());
    }

    return sum;
}

pub const PathValidatorChallengeResponseCtx = struct {
    tokens: [path_validator_token_count][8]u8 = .{
        .{ 0x10, 0x22, 0x34, 0x46, 0x58, 0x6a, 0x7c, 0x8e },
        .{ 0x91, 0x83, 0x75, 0x67, 0x59, 0x4b, 0x3d, 0x2f },
        .{ 0x01, 0x21, 0x41, 0x61, 0x81, 0xa1, 0xc1, 0xe1 },
        .{ 0xf0, 0xd2, 0xb4, 0x96, 0x78, 0x5a, 0x3c, 0x1e },
        .{ 0x5a, 0x51, 0x48, 0x3f, 0x36, 0x2d, 0x24, 0x1b },
        .{ 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91 },
        .{ 0xc3, 0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf },
        .{ 0x04, 0x18, 0x2c, 0x40, 0x54, 0x68, 0x7c, 0x90 },
    },
    wrong_tokens: [path_validator_token_count][8]u8 = .{
        .{ 0x8e, 0x7c, 0x6a, 0x58, 0x46, 0x34, 0x22, 0x10 },
        .{ 0x2f, 0x3d, 0x4b, 0x59, 0x67, 0x75, 0x83, 0x91 },
        .{ 0xe1, 0xc1, 0xa1, 0x81, 0x61, 0x41, 0x21, 0x01 },
        .{ 0x1e, 0x3c, 0x5a, 0x78, 0x96, 0xb4, 0xd2, 0xf0 },
        .{ 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x51, 0x5a },
        .{ 0x91, 0x80, 0x7f, 0x6e, 0x5d, 0x4c, 0x3b, 0x2a },
        .{ 0xdf, 0xdb, 0xd7, 0xd3, 0xcf, 0xcb, 0xc7, 0xc3 },
        .{ 0x90, 0x7c, 0x68, 0x54, 0x40, 0x2c, 0x18, 0x04 },
    },
    now_start_us: u64 = 1_000_000,
    step_us: u64 = 37,
    timeout_us: u64 = 300_000,

    pub fn init() PathValidatorChallengeResponseCtx {
        return .{};
    }

    pub fn deinit(_: *PathValidatorChallengeResponseCtx) void {}
};

pub fn initPathValidatorChallengeResponseCtx() PathValidatorChallengeResponseCtx {
    return PathValidatorChallengeResponseCtx.init();
}

pub fn deinitPathValidatorChallengeResponseCtx(ctx: *PathValidatorChallengeResponseCtx) void {
    ctx.deinit();
}

/// One operation runs a PATH_CHALLENGE through stray response,
/// in-window tick, matching response, and timeout-after-rearm paths.
pub fn runPathValidatorChallengeResponse(
    ctx: *const PathValidatorChallengeResponseCtx,
    iters: u64,
) u64 {
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const idx: usize = @intCast(i & (path_validator_token_count - 1));
        const timeout_idx = (idx + 3) & (path_validator_token_count - 1);
        const now = ctx.now_start_us +% i *% ctx.step_us;

        var validator: PathValidator = .{};
        validator.beginChallenge(ctx.tokens[idx], now, ctx.timeout_us);
        const stray_matched = validator.recordResponse(ctx.wrong_tokens[idx]) catch unreachable;
        std.debug.assert(!stray_matched);
        validator.tick(now + ctx.timeout_us / 2);
        sum +%= statusInt(validator.status);
        sum +%= @intFromBool(validator.isValidated());

        const matched = validator.recordResponse(ctx.tokens[idx]) catch unreachable;
        std.debug.assert(matched);
        sum +%= statusInt(validator.status);
        sum +%= @intFromBool(validator.isValidated());

        const timeout_start = now +% 2 *% ctx.timeout_us;
        validator.beginChallenge(ctx.tokens[timeout_idx], timeout_start, ctx.timeout_us);
        validator.tick(timeout_start +% ctx.timeout_us +% 1);
        sum +%= statusInt(validator.status);
        sum +%= @intFromBool(validator.isValidated());
        sum +%= validator.pending_at_us;
        sum +%= validator.timeout_us;
        sum +%= foldToken(&validator.pending_token);
    }
    return sum;
}

pub const PathSetScheduleRoundRobinCtx = struct {
    allocator: std.mem.Allocator,
    set: *PathSet,
    path_ids: [path_set_round_robin_path_count]u32,

    pub fn init(allocator: std.mem.Allocator) !PathSetScheduleRoundRobinCtx {
        const set = try allocator.create(PathSet);
        errdefer allocator.destroy(set);
        set.* = .{};
        errdefer set.deinit(allocator);

        var path_ids: [path_set_round_robin_path_count]u32 = undefined;
        try set.ensurePrimary(allocator, .{ .max_datagram_size = 1200 });
        path_ids[0] = 0;
        set.primary().path.markValidated();
        set.primary().path.state = .active;

        var idx: usize = 1;
        while (idx < path_set_round_robin_path_count) : (idx += 1) {
            const cid_byte: u8 = @intCast(idx);
            const id = try set.openPath(
                allocator,
                testAddress(@intCast(idx)),
                testAddress(@intCast(0x40 + idx)),
                path_mod.ConnectionId.fromSlice(&.{ cid_byte, cid_byte +% 0x10 }),
                path_mod.ConnectionId.fromSlice(&.{cid_byte +% 0x80}),
                .{ .max_datagram_size = 1200 },
            );
            path_ids[idx] = id;
            const path = set.get(id).?;
            path.path.state = .active;
            path.path.markValidated();
        }

        // Keep two entries non-sendable so round-robin exercises the
        // skip loop while still returning stable sendable ids.
        set.get(path_ids[2]).?.path.retire();
        set.get(path_ids[4]).?.path.fail();
        set.setScheduler(.round_robin);

        return .{
            .allocator = allocator,
            .set = set,
            .path_ids = path_ids,
        };
    }

    pub fn deinit(self: *PathSetScheduleRoundRobinCtx) void {
        self.set.deinit(self.allocator);
        self.allocator.destroy(self.set);
        self.* = undefined;
    }
};

pub fn initPathSetScheduleRoundRobinCtx(
    allocator: std.mem.Allocator,
) !PathSetScheduleRoundRobinCtx {
    return PathSetScheduleRoundRobinCtx.init(allocator);
}

pub fn deinitPathSetScheduleRoundRobinCtx(ctx: *PathSetScheduleRoundRobinCtx) void {
    ctx.deinit();
}

/// One operation selects the next sendable path under public
/// round-robin scheduling. The context owns a primary path and four
/// opened paths, with two non-sendable entries to exercise skip logic.
pub fn runPathSetScheduleRoundRobin(
    ctx: *const PathSetScheduleRoundRobinCtx,
    iters: u64,
) u64 {
    var sum: u64 = 0;
    ctx.set.setScheduler(.round_robin);
    ctx.set.rr_cursor = 0;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const selected = ctx.set.selectForSending();
        sum +%= selected.id;
        sum +%= statusIntPath(selected.path.state);
        sum +%= @intFromBool(selected.path.isValidated());
        sum +%= selected.path.antiAmpAllowance() & 0xff;
        sum +%= @as(u64, @intCast(ctx.set.rr_cursor));
    }
    return sum;
}

fn tryOrUnreachable(result: flow_control.Error!void) void {
    result catch unreachable;
}

fn statusInt(status: path_validator_mod.Status) u64 {
    return @intFromEnum(status);
}

fn statusIntPath(state: path_mod.State) u64 {
    return @intFromEnum(state);
}

fn foldToken(token: *const [8]u8) u64 {
    var acc: u64 = 0;
    for (token) |b| {
        acc = (acc << 5) ^ (acc >> 2) ^ b;
    }
    return acc;
}

fn testAddress(seed: u8) path_mod.Address {
    var addr: path_mod.Address = .{};
    for (&addr.bytes, 0..) |*b, idx| {
        b.* = seed +% @as(u8, @intCast(idx));
    }
    return addr;
}

test "flow_control_credit_update helper preserves flow invariants" {
    var ctx = FlowControlCreditUpdateCtx.init();
    defer ctx.deinit();

    const sum = runFlowControlCreditUpdate(&ctx, 4);
    try std.testing.expect(sum != 0);

    var conn = ConnectionData.init(ctx.conn_local_initial, ctx.conn_peer_initial);
    var stream = StreamData.init(ctx.stream_local_initial, ctx.stream_peer_initial);
    var stream_count = StreamCount.init(ctx.stream_count_local_initial, ctx.stream_count_peer_initial);
    for (0..flow_control_step_count) |idx| {
        conn.onMaxData(ctx.conn_peer_max_updates[idx]);
        try conn.recordSent(ctx.conn_sent_chunks[idx]);
        conn.raiseLocalMax(ctx.conn_local_max_updates[idx]);
        try conn.recordPeerSent(ctx.conn_peer_chunks[idx]);
        try std.testing.expect(conn.we_sent <= conn.peer_max);
        try std.testing.expect(conn.peer_sent <= conn.local_max);

        stream.onMaxStreamData(ctx.stream_peer_max_updates[idx]);
        try stream.recordSent(ctx.stream_sent_chunks[idx]);
        stream.raiseLocalMax(ctx.stream_local_max_updates[idx]);
        try stream.recordPeerSent(ctx.stream_peer_chunks[idx]);
        try std.testing.expect(stream.we_sent <= stream.peer_max);
        try std.testing.expect(stream.peer_sent <= stream.local_max);

        stream_count.onMaxStreams(ctx.stream_count_updates[idx]);
        try stream_count.recordWeOpened();
        try stream_count.recordPeerOpened(ctx.peer_stream_indices[idx]);
        try std.testing.expect(stream_count.we_opened <= stream_count.peer_max);
        try std.testing.expect(stream_count.peer_opened <= stream_count.local_max);
    }
}

test "path_validator_challenge_response helper reaches matched and timeout paths" {
    var ctx = PathValidatorChallengeResponseCtx.init();
    defer ctx.deinit();

    const sum = runPathValidatorChallengeResponse(&ctx, 3);
    try std.testing.expect(sum != 0);

    var validator: PathValidator = .{};
    validator.beginChallenge(ctx.tokens[0], ctx.now_start_us, ctx.timeout_us);
    const stray = try validator.recordResponse(ctx.wrong_tokens[0]);
    try std.testing.expect(!stray);
    try std.testing.expectEqual(path_validator_mod.Status.pending, validator.status);
    const matched = try validator.recordResponse(ctx.tokens[0]);
    try std.testing.expect(matched);
    try std.testing.expectEqual(path_validator_mod.Status.validated, validator.status);

    validator.beginChallenge(ctx.tokens[1], ctx.now_start_us, ctx.timeout_us);
    validator.tick(ctx.now_start_us + ctx.timeout_us + 1);
    try std.testing.expectEqual(path_validator_mod.Status.failed, validator.status);
}

test "path_set_schedule_round_robin helper skips non-sendable paths" {
    var ctx = try PathSetScheduleRoundRobinCtx.init(std.testing.allocator);
    defer ctx.deinit();

    try std.testing.expectEqual(path_set_round_robin_path_count, ctx.set.paths.items.len);
    try std.testing.expectEqual(path_mod.State.retiring, ctx.set.get(ctx.path_ids[2]).?.path.state);
    try std.testing.expectEqual(path_mod.State.failed, ctx.set.get(ctx.path_ids[4]).?.path.state);

    ctx.set.rr_cursor = 0;
    const expected = [_]u32{ 0, 1, 3, 0, 1, 3 };
    for (expected) |id| {
        try std.testing.expectEqual(id, ctx.set.selectForSending().id);
    }

    const sum = runPathSetScheduleRoundRobin(&ctx, expected.len);
    try std.testing.expect(sum != 0);
}
