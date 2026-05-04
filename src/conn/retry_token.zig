//! Stateless Retry-token helper for QUIC address validation.
//!
//! The transport stays I/O-agnostic: callers provide canonical client
//! address bytes. Tokens are HMAC-bound to those bytes, the Original
//! Destination CID, the Retry Source CID, the QUIC version, and an
//! expiry timestamp.

const std = @import("std");
const boringssl = @import("boringssl");

const path = @import("path.zig");

const HmacSha256 = boringssl.crypto.hmac.HmacSha256;

pub const token_format_version: u8 = 1;
pub const key_len: usize = 32;
pub const tag_len: usize = HmacSha256.digest_size;
pub const header_len: usize = 1 + 4 + 8 + 8;
pub const token_len: usize = header_len + tag_len;
pub const max_bound_value_len: usize = std.math.maxInt(u16);

pub const Key = [key_len]u8;
pub const Token = [token_len]u8;

const domain_separator = "nullq retry token v1";

pub const Error = error{
    OutputTooSmall,
    ContextTooLong,
    DcidTooLong,
};

pub const MintOptions = struct {
    key: *const Key,
    now_us: u64,
    lifetime_us: u64,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
    quic_version: u32 = 0x00000001,
};

pub const ValidateOptions = struct {
    key: *const Key,
    now_us: u64,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
    quic_version: u32 = 0x00000001,
    max_clock_skew_us: u64 = 0,
};

pub const ValidationResult = enum {
    valid,
    malformed,
    wrong_version,
    not_yet_valid,
    expired,
    invalid,
};

pub fn mint(dst: []u8, opts: MintOptions) Error!usize {
    if (dst.len < token_len) return Error.OutputTooSmall;
    try validateBoundInputs(opts.client_address, opts.original_dcid, opts.retry_scid);

    dst[0] = token_format_version;
    std.mem.writeInt(u32, dst[1..5], opts.quic_version, .big);
    std.mem.writeInt(u64, dst[5..13], opts.now_us, .big);
    std.mem.writeInt(u64, dst[13..21], addSat(opts.now_us, opts.lifetime_us), .big);
    const tag = authTag(opts.key, dst[0..header_len], opts.client_address, opts.original_dcid, opts.retry_scid) catch unreachable;
    @memcpy(dst[header_len..token_len], &tag);
    return token_len;
}

pub fn minted(opts: MintOptions) Error!Token {
    var token: Token = undefined;
    _ = try mint(&token, opts);
    return token;
}

pub fn validate(token: []const u8, opts: ValidateOptions) ValidationResult {
    if (token.len != token_len) return .malformed;
    if (token[0] != token_format_version) return .malformed;
    if (std.mem.readInt(u32, token[1..5], .big) != opts.quic_version) return .wrong_version;
    validateBoundInputs(opts.client_address, opts.original_dcid, opts.retry_scid) catch return .malformed;

    const issued_at_us = std.mem.readInt(u64, token[5..13], .big);
    const expires_at_us = std.mem.readInt(u64, token[13..21], .big);
    if (addSat(opts.now_us, opts.max_clock_skew_us) < issued_at_us) return .not_yet_valid;
    if (opts.now_us > addSat(expires_at_us, opts.max_clock_skew_us)) return .expired;

    const expected = authTag(opts.key, token[0..header_len], opts.client_address, opts.original_dcid, opts.retry_scid) catch return .malformed;
    var got: [tag_len]u8 = undefined;
    @memcpy(&got, token[header_len..token_len]);
    if (!std.crypto.timing_safe.eql([tag_len]u8, expected, got)) return .invalid;
    return .valid;
}

fn validateBoundInputs(client_address: []const u8, original_dcid: []const u8, retry_scid: []const u8) Error!void {
    if (client_address.len > max_bound_value_len) return Error.ContextTooLong;
    if (original_dcid.len > path.max_cid_len) return Error.DcidTooLong;
    if (retry_scid.len > path.max_cid_len) return Error.DcidTooLong;
}

fn authTag(
    key: *const Key,
    header: []const u8,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
) Error![tag_len]u8 {
    var h = HmacSha256.init(key);
    defer h.deinit();
    h.update(domain_separator);
    h.update(header);
    try updateBound(&h, client_address);
    try updateBound(&h, original_dcid);
    try updateBound(&h, retry_scid);
    return h.finalDigest();
}

fn updateBound(h: *HmacSha256, bytes: []const u8) Error!void {
    if (bytes.len > max_bound_value_len) return Error.ContextTooLong;
    var len: [2]u8 = undefined;
    std.mem.writeInt(u16, &len, @intCast(bytes.len), .big);
    h.update(&len);
    h.update(bytes);
}

fn addSat(a: u64, b: u64) u64 {
    return std.math.add(u64, a, b) catch std.math.maxInt(u64);
}

const testing_key: Key = .{
    0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
    0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
    0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
    0xd6, 0x28, 0xb4, 0x72, 0x01, 0xc9, 0x3f, 0x6a,
};

test "Retry token validates with matching address CIDs version and time" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
}

test "Retry token rejects replay with changed address or connection IDs" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4243",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 5 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9e },
    }));
}

test "Retry token rejects wrong version expired future and malformed tokens" {
    var token = try minted(.{
        .key = &testing_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
        .quic_version = 1,
    });

    const opts: ValidateOptions = .{
        .key = &testing_key,
        .now_us = 11_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    };
    var wrong_version = opts;
    wrong_version.quic_version = 0x6b3343cf;
    try std.testing.expectEqual(ValidationResult.wrong_version, validate(&token, wrong_version));

    var expired = opts;
    expired.now_us = 15_000_001;
    try std.testing.expectEqual(ValidationResult.expired, validate(&token, expired));

    var future = opts;
    future.now_us = 9_999_999;
    try std.testing.expectEqual(ValidationResult.not_yet_valid, validate(&token, future));

    try std.testing.expectEqual(ValidationResult.malformed, validate(token[0 .. token.len - 1], opts));
    token[token.len - 1] ^= 0x01;
    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, opts));
    token[0] = 0xff;
    try std.testing.expectEqual(ValidationResult.malformed, validate(&token, opts));
}
