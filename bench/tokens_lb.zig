//! Token and QUIC-LB microbenchmark helpers.
//!
//! This module is intentionally standalone so another worker can wire
//! selected helpers into `bench/main.zig`. Fixtures are fixed and keep
//! allocation out of hot loops. Retry-token and NEW_TOKEN minting still
//! draw randomness internally because the public mint APIs intentionally
//! own their AES-GCM nonce generation.

const std = @import("std");
const quic_zig = @import("quic_zig");

const retry_token = quic_zig.conn.retry_token;
const new_token = quic_zig.conn.new_token;
const stateless_reset = quic_zig.conn.stateless_reset;
const lb = quic_zig.lb;

pub const retry_token_mint_validate_name = "retry_token_mint_validate";
pub const new_token_mint_validate_name = "new_token_mint_validate";
pub const stateless_reset_token_derive_name = "stateless_reset_token_derive";
pub const quic_lb_cid_generate_name = "quic_lb_cid_generate";

pub const quic_lb_mode_count: usize = 3;
pub const stateless_reset_cid_count: usize = 8;
pub const max_bench_cid_len: usize = 20;

const retry_key: retry_token.Key = fromHex(
    "8671150d9a2c5e0431a86af91844bd2b4dee903fa7610c55d628b47201c93f6a",
);
const new_token_key: new_token.Key = fromHex(
    "4f95d16b2a7c83ee1842903dfac46e7109b655a32cee1877d43f8821056ca933",
);
const reset_key: stateless_reset.Key = fromHex(
    "bb2f4d1a0662a83390c17945f72d6a0c1173ab598ed4c2069ff041d8a6126ce5",
);
const lb_single_pass_key: lb.Key = fromHex("8f95f09245765f80256934e50c66207f");
const lb_four_pass_key: lb.Key = fromHex("fdf726a9893ec05c0632d3956680baf0");

const client_address = "ip4:203.0.113.7:4433";
const retry_original_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const retry_scid: [8]u8 = .{ 0xc1, 0x5e, 0x71, 0x9d, 0x31, 0x41, 0x59, 0x26 };

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn fillPattern(dst: []u8, seed: u8) void {
    for (dst, 0..) |*b, i| {
        const lo: u8 = @intCast(i & 0xff);
        const hi: u8 = @intCast((i >> 8) & 0xff);
        b.* = seed +% (lo *% 29) +% (hi *% 17);
    }
}

fn foldBytes(bytes: []const u8) u64 {
    var acc: u64 = 0xcbf2_9ce4_8422_2325;
    for (bytes) |b| {
        acc ^= b;
        acc *%= 0x0000_0100_0000_01b3;
    }
    return acc;
}

pub const RetryTokenMintValidateCtx = struct {
    key: retry_token.Key = retry_key,
    issue_now_us: u64 = 1_000_000,
    validate_now_us: u64 = 2_000_000,
    lifetime_us: u64 = 10_000_000,
    client_address: []const u8 = client_address,
    original_dcid: [retry_original_dcid.len]u8 = retry_original_dcid,
    retry_scid: [retry_scid.len]u8 = retry_scid,
    quic_version: u32 = quic_zig.QUIC_VERSION_1,

    pub fn init() RetryTokenMintValidateCtx {
        return .{};
    }

    pub fn deinit(_: *RetryTokenMintValidateCtx) void {}

    fn mintOptions(self: *const RetryTokenMintValidateCtx) retry_token.MintOptions {
        return .{
            .key = &self.key,
            .now_us = self.issue_now_us,
            .lifetime_us = self.lifetime_us,
            .client_address = self.client_address,
            .original_dcid = &self.original_dcid,
            .retry_scid = &self.retry_scid,
            .quic_version = self.quic_version,
        };
    }

    fn validateOptions(self: *const RetryTokenMintValidateCtx) retry_token.ValidateOptions {
        return .{
            .key = &self.key,
            .now_us = self.validate_now_us,
            .client_address = self.client_address,
            .original_dcid = &self.original_dcid,
            .retry_scid = &self.retry_scid,
            .quic_version = self.quic_version,
        };
    }
};

pub fn initRetryTokenMintValidateCtx() RetryTokenMintValidateCtx {
    return RetryTokenMintValidateCtx.init();
}

pub fn deinitRetryTokenMintValidateCtx(ctx: *RetryTokenMintValidateCtx) void {
    ctx.deinit();
}

pub fn runRetryTokenMintValidate(ctx: *const RetryTokenMintValidateCtx, iters: u64) u64 {
    var token: retry_token.Token = undefined;
    var sum: u64 = 0;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = retry_token.mint(&token, ctx.mintOptions()) catch unreachable;
        const result = retry_token.validate(&token, ctx.validateOptions());
        std.debug.assert(result == .valid);

        sum +%= n;
        sum +%= @as(u64, @intFromEnum(result)) + 1;
        sum +%= token[@intCast(i % token.len)];
        sum +%= token[retry_token.nonce_len];
    }

    return sum;
}

pub const NewTokenMintValidateCtx = struct {
    key: new_token.Key = new_token_key,
    issue_now_us: u64 = 10_000_000,
    validate_now_us: u64 = 12_000_000,
    lifetime_us: u64 = 24 * 3600 * 1_000_000,
    client_address: []const u8 = client_address,
    quic_version: u32 = quic_zig.QUIC_VERSION_1,

    pub fn init() NewTokenMintValidateCtx {
        return .{};
    }

    pub fn deinit(_: *NewTokenMintValidateCtx) void {}

    fn mintOptions(self: *const NewTokenMintValidateCtx) new_token.MintOptions {
        return .{
            .key = &self.key,
            .now_us = self.issue_now_us,
            .lifetime_us = self.lifetime_us,
            .client_address = self.client_address,
            .quic_version = self.quic_version,
        };
    }

    fn validateOptions(self: *const NewTokenMintValidateCtx) new_token.ValidateOptions {
        return .{
            .key = &self.key,
            .now_us = self.validate_now_us,
            .client_address = self.client_address,
            .quic_version = self.quic_version,
        };
    }
};

pub fn initNewTokenMintValidateCtx() NewTokenMintValidateCtx {
    return NewTokenMintValidateCtx.init();
}

pub fn deinitNewTokenMintValidateCtx(ctx: *NewTokenMintValidateCtx) void {
    ctx.deinit();
}

pub fn runNewTokenMintValidate(ctx: *const NewTokenMintValidateCtx, iters: u64) u64 {
    var token: new_token.Token = undefined;
    var sum: u64 = 0;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = new_token.mint(&token, ctx.mintOptions()) catch unreachable;
        const result = new_token.validate(&token, ctx.validateOptions());
        std.debug.assert(result == .valid);

        sum +%= n;
        sum +%= @as(u64, @intFromEnum(result)) + 1;
        sum +%= token[@intCast(i % token.len)];
        sum +%= token[new_token.nonce_len];
    }

    return sum;
}

pub const StatelessResetTokenDeriveCtx = struct {
    key: stateless_reset.Key = reset_key,
    cid_lens: [stateless_reset_cid_count]u8 = .{ 0, 4, 7, 8, 12, 16, 18, 20 },
    cids: [stateless_reset_cid_count][max_bench_cid_len]u8 = undefined,

    pub fn init() StatelessResetTokenDeriveCtx {
        var ctx: StatelessResetTokenDeriveCtx = .{};
        for (&ctx.cids, 0..) |*cid, idx| {
            fillPattern(cid, @intCast(0x31 + idx * 7));
        }
        return ctx;
    }

    pub fn deinit(self: *StatelessResetTokenDeriveCtx) void {
        std.crypto.secureZero(u8, &self.key);
    }
};

pub fn initStatelessResetTokenDeriveCtx() StatelessResetTokenDeriveCtx {
    return StatelessResetTokenDeriveCtx.init();
}

pub fn deinitStatelessResetTokenDeriveCtx(ctx: *StatelessResetTokenDeriveCtx) void {
    ctx.deinit();
}

pub fn runStatelessResetTokenDerive(
    ctx: *const StatelessResetTokenDeriveCtx,
    iters: u64,
) u64 {
    var sum: u64 = 0;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const idx: usize = @intCast(i & (stateless_reset_cid_count - 1));
        const cid = ctx.cids[idx][0..ctx.cid_lens[idx]];
        const token = stateless_reset.derive(&ctx.key, cid) catch unreachable;
        sum +%= foldBytes(&token);
        sum +%= token[@intCast(i & (stateless_reset.token_len - 1))];
    }

    return sum;
}

pub const QuicLbCidGenerateCtx = struct {
    plaintext_factory: lb.Factory,
    single_pass_factory: lb.Factory,
    four_pass_factory: lb.Factory,
    plaintext_nonce: [6]u8 = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
    single_pass_nonce: [8]u8 = .{ 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5 },
    four_pass_nonce: [4]u8 = .{ 0x9c, 0x69, 0xc2, 0x75 },

    pub fn init() !QuicLbCidGenerateCtx {
        const plaintext_cfg: lb.LbConfig = .{
            .config_id = 4,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xde, 0xad, 0xbe, 0xef }),
            .nonce_len = 6,
        };
        const single_pass_cfg: lb.LbConfig = .{
            .config_id = 2,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f }),
            .nonce_len = 8,
            .key = lb_single_pass_key,
        };
        const four_pass_cfg: lb.LbConfig = .{
            .config_id = 0,
            .server_id = try lb.ServerId.fromSlice(&.{ 0x31, 0x44, 0x1a }),
            .nonce_len = 4,
            .key = lb_four_pass_key,
        };

        var plaintext_factory = try lb.Factory.init(plaintext_cfg);
        errdefer plaintext_factory.deinit();
        var single_pass_factory = try lb.Factory.init(single_pass_cfg);
        errdefer single_pass_factory.deinit();
        var four_pass_factory = try lb.Factory.init(four_pass_cfg);
        errdefer four_pass_factory.deinit();

        return .{
            .plaintext_factory = plaintext_factory,
            .single_pass_factory = single_pass_factory,
            .four_pass_factory = four_pass_factory,
        };
    }

    pub fn deinit(self: *QuicLbCidGenerateCtx) void {
        self.plaintext_factory.deinit();
        self.single_pass_factory.deinit();
        self.four_pass_factory.deinit();
        self.* = undefined;
    }
};

pub fn initQuicLbCidGenerateCtx() !QuicLbCidGenerateCtx {
    return QuicLbCidGenerateCtx.init();
}

pub fn deinitQuicLbCidGenerateCtx(ctx: *QuicLbCidGenerateCtx) void {
    ctx.deinit();
}

pub fn runQuicLbCidGenerate(ctx: *const QuicLbCidGenerateCtx, iters: u64) u64 {
    var plaintext_factory = ctx.plaintext_factory;
    var single_pass_factory = ctx.single_pass_factory;
    var four_pass_factory = ctx.four_pass_factory;
    defer plaintext_factory.deinit();
    defer single_pass_factory.deinit();
    defer four_pass_factory.deinit();

    var cid: [max_bench_cid_len]u8 = undefined;
    var sum: u64 = 0;

    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = switch (i % quic_lb_mode_count) {
            0 => plaintext_factory.mintWithNonce(&cid, &ctx.plaintext_nonce) catch unreachable,
            1 => single_pass_factory.mintWithNonce(&cid, &ctx.single_pass_nonce) catch unreachable,
            else => four_pass_factory.mintWithNonce(&cid, &ctx.four_pass_nonce) catch unreachable,
        };

        sum +%= n;
        sum +%= lb.cid.firstOctetConfigId(cid[0]);
        sum +%= lb.cid.firstOctetLengthBits(cid[0]);
        sum +%= foldBytes(cid[0..n]);
    }

    return sum;
}

test "retry_token_mint_validate helper mints usable tokens" {
    const ctx = RetryTokenMintValidateCtx.init();
    try std.testing.expect(runRetryTokenMintValidate(&ctx, 2) != 0);

    var token: retry_token.Token = undefined;
    _ = try retry_token.mint(&token, ctx.mintOptions());
    try std.testing.expectEqual(retry_token.ValidationResult.valid, retry_token.validate(&token, ctx.validateOptions()));
}

test "new_token_mint_validate helper mints usable tokens" {
    const ctx = NewTokenMintValidateCtx.init();
    try std.testing.expect(runNewTokenMintValidate(&ctx, 2) != 0);

    var token: new_token.Token = undefined;
    _ = try new_token.mint(&token, ctx.mintOptions());
    try std.testing.expectEqual(new_token.ValidationResult.valid, new_token.validate(&token, ctx.validateOptions()));
}

test "stateless_reset_token_derive helper is deterministic" {
    var ctx = StatelessResetTokenDeriveCtx.init();
    defer ctx.deinit();

    const a = runStatelessResetTokenDerive(&ctx, 16);
    const b = runStatelessResetTokenDerive(&ctx, 16);
    try std.testing.expectEqual(a, b);

    const cid = ctx.cids[3][0..ctx.cid_lens[3]];
    const token_a = try stateless_reset.derive(&ctx.key, cid);
    const token_b = try stateless_reset.derive(&ctx.key, cid);
    try std.testing.expect(stateless_reset.eql(token_a, token_b));
}

test "quic_lb_cid_generate helper uses fixed public nonce fixtures" {
    var ctx = try QuicLbCidGenerateCtx.init();
    defer ctx.deinit();

    const a = runQuicLbCidGenerate(&ctx, 9);
    const b = runQuicLbCidGenerate(&ctx, 9);
    try std.testing.expectEqual(a, b);

    var cid: [max_bench_cid_len]u8 = undefined;

    var plaintext_factory = ctx.plaintext_factory;
    defer plaintext_factory.deinit();
    const plaintext_len = try plaintext_factory.mintWithNonce(&cid, &ctx.plaintext_nonce);
    const plaintext_decoded = try lb.decode(cid[0..plaintext_len], plaintext_factory.cfg);
    try std.testing.expectEqualSlices(u8, plaintext_factory.cfg.server_id.slice(), plaintext_decoded.server_id.slice());
    try std.testing.expectEqualSlices(u8, &ctx.plaintext_nonce, plaintext_decoded.nonceSlice());

    var single_pass_factory = ctx.single_pass_factory;
    defer single_pass_factory.deinit();
    const single_pass_len = try single_pass_factory.mintWithNonce(&cid, &ctx.single_pass_nonce);
    const single_pass_decoded = try lb.decode(cid[0..single_pass_len], single_pass_factory.cfg);
    try std.testing.expectEqualSlices(u8, single_pass_factory.cfg.server_id.slice(), single_pass_decoded.server_id.slice());
    try std.testing.expectEqualSlices(u8, &ctx.single_pass_nonce, single_pass_decoded.nonceSlice());

    var four_pass_factory = ctx.four_pass_factory;
    defer four_pass_factory.deinit();
    const four_pass_len = try four_pass_factory.mintWithNonce(&cid, &ctx.four_pass_nonce);
    const four_pass_decoded = try lb.decode(cid[0..four_pass_len], four_pass_factory.cfg);
    try std.testing.expectEqualSlices(u8, four_pass_factory.cfg.server_id.slice(), four_pass_decoded.server_id.slice());
    try std.testing.expectEqualSlices(u8, &ctx.four_pass_nonce, four_pass_decoded.nonceSlice());
}
