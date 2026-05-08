//! NEW_TOKEN issuance helpers (RFC 9000 §8.1.3 / §19.7).
//!
//! A server hands the client a NEW_TOKEN frame after handshake
//! confirmation; the client may then echo that token in the long-header
//! Token field of an Initial belonging to a *future* connection. A
//! valid echoed token lets the server skip the Retry round-trip on
//! that next connection, treating the source as already address-validated.
//!
//! NEW_TOKEN is a sibling of `retry_token.zig` but binds different
//! material: it does NOT bind to ODCID or Retry SCID (those are
//! per-connection ephemera and would force the next connection's CIDs
//! to match the previous one's). It DOES bind the client address, the
//! QUIC version, and an issue/expiry window, all sealed inside an
//! AES-GCM-256 blob so peers and on-path observers see opaque random
//! bytes.
//!
//! Wire format (v1, fixed 96 bytes — matches the v2 Retry token shape
//! so both formats are uniformly opaque on the wire):
//!
//!     nonce (12)  |  ciphertext (68)  |  tag (16)
//!
//! Inner plaintext (zero-padded to 68 bytes before AEAD-seal):
//!
//!     version    (4 bytes,  big-endian)
//!     issued_at  (8 bytes,  big-endian, microseconds since epoch)
//!     expires_at (8 bytes,  big-endian, microseconds since epoch)
//!     addr_len   (1 byte)         | client_address (<= 22 bytes)
//!     <pad>      (zero bytes to reach 68)
//!
//! The address slot is the only variable-length bound material, so the
//! plaintext budget (68 - 21 fixed = 47 bytes) is far in excess of the
//! 22-byte `path.Address` shape — there is no `OutputTooSmall` rejection
//! path for normal addresses, but we keep one for forward-compatibility
//! if `path.Address` ever grows.
//!
//! Domain separator: `"quic_zig new_token v1"` — distinct from the
//! Retry-token domain separator so a Retry token presented in the
//! Initial-token field cannot be mistaken for a NEW_TOKEN (and vice
//! versa). The server's gate tries NEW_TOKEN.validate first; on
//! `.malformed` it falls through to Retry validation.

const std = @import("std");
const boringssl = @import("boringssl");

const path = @import("path.zig");

const AesGcm256 = boringssl.crypto.aead.AesGcm256;

/// AES-GCM-256 key length in bytes (also `Key`).
pub const key_len: usize = AesGcm256.key_len;
/// AEAD nonce length in bytes (12, GCM standard).
pub const nonce_len: usize = AesGcm256.nonce_len;
/// AEAD authentication tag length in bytes (16, GCM standard).
pub const tag_len: usize = AesGcm256.tag_len;

/// Maximum address length the format can carry. Matches
/// `path.Address.bytes`.
pub const max_address_len: usize = 22;

/// Plaintext layout overhead: 4 (version) + 8 (issued) + 8 (expires)
/// + 1 length prefix byte for the address slot.
const plaintext_fixed_overhead: usize = 4 + 8 + 8 + 1;

/// Total token length on the wire (and in `Token`). Fixed at 96 bytes
/// so NEW_TOKEN is bytewise indistinguishable from the v2 Retry token
/// shape on the wire.
pub const max_token_len: usize = 96;

/// Plaintext payload size: equal to `max_token_len - nonce_len - tag_len`.
/// Plaintext is zero-padded to this length before AEAD seal so every
/// minted token is a constant-length opaque blob.
const plaintext_len: usize = max_token_len - nonce_len - tag_len;

comptime {
    std.debug.assert(plaintext_len >= plaintext_fixed_overhead);
}

/// Maximum address-field length that fits the fixed plaintext budget.
/// Mint enforces this at runtime.
const max_bound_total: usize = plaintext_len - plaintext_fixed_overhead;

/// 32-byte AES-GCM-256 key. The server keeps this stable across every
/// outstanding token's lifetime so a client returning hours later can
/// still validate. **NEW_TOKENs typically outlive Retry tokens by
/// orders of magnitude**, so this key is intentionally separate from
/// `retry_token.Key`: rotating the Retry key (e.g. on every
/// shift) MUST NOT invalidate every NEW_TOKEN issued in the prior
/// shift.
pub const Key = [key_len]u8;

/// Fixed-size NEW_TOKEN. Always exactly `max_token_len` bytes.
pub const Token = [max_token_len]u8;

/// Domain separator. Mixed into the AEAD AAD; replaying a Retry token
/// blob through NEW_TOKEN.validate (or vice versa) returns `.malformed`.
const domain_separator = "quic_zig new_token v1";

/// Errors raised by `mint` (and surfaced as `.malformed` from
/// `validate`).
pub const Error = error{
    /// Output buffer was smaller than `max_token_len`, or the
    /// requested address length doesn't fit the fixed plaintext
    /// budget.
    OutputTooSmall,
    /// `client_address` exceeded `max_address_len`.
    ContextTooLong,
    /// AEAD seal/init failure (BoringSSL). Not peer-reachable in
    /// practice; surfaces only on out-of-memory or library misuse.
    AeadFailure,
    /// CSPRNG failure (BoringSSL). Same not-peer-reachable property.
    RandFailure,
};

/// Inputs to `mint`. The AEAD seal binds `client_address`,
/// `quic_version`, `now_us`, and the expiry derived from `lifetime_us`.
pub const MintOptions = struct {
    key: *const Key,
    now_us: u64,
    lifetime_us: u64,
    client_address: []const u8,
    quic_version: u32 = 0x00000001,
};

/// Inputs to `validate`. Must be byte-equal to the `MintOptions`
/// values used to issue the token (modulo `now_us`/`max_clock_skew_us`).
pub const ValidateOptions = struct {
    key: *const Key,
    now_us: u64,
    client_address: []const u8,
    quic_version: u32 = 0x00000001,
    max_clock_skew_us: u64 = 0,
};

/// Outcome of `validate`.
pub const ValidationResult = enum {
    /// AEAD opened cleanly, recovered fields match, and timestamps
    /// are within the allowed window.
    valid,
    /// Length, AEAD authentication, or recovered-field shape was
    /// wrong (also covers a Retry-token blob presented to NEW_TOKEN
    /// validate, since the domain separator differs). Treat as
    /// untrusted.
    malformed,
    /// The QUIC version field did not match.
    wrong_version,
    /// `issued_at_us` is in the future beyond `max_clock_skew_us`.
    not_yet_valid,
    /// `expires_at_us` is in the past beyond `max_clock_skew_us`.
    expired,
    /// AEAD opened cleanly but the recovered client address did not
    /// match the validator's expectation.
    invalid,
};

/// Mint a NEW_TOKEN into `dst`. Returns the number of bytes written
/// (always `max_token_len`).
pub fn mint(dst: []u8, opts: MintOptions) Error!usize {
    if (dst.len < max_token_len) return Error.OutputTooSmall;
    try validateBoundInputs(opts.client_address);
    if (opts.client_address.len > max_bound_total) return Error.OutputTooSmall;

    // Per-token random nonce. AES-GCM nonce reuse under a fixed key
    // breaks confidentiality and integrity, so the CSPRNG path is
    // load-bearing.
    var nonce: [nonce_len]u8 = undefined;
    boringssl.crypto.rand.fillBytes(&nonce) catch return Error.RandFailure;
    @memcpy(dst[0..nonce_len], &nonce);

    var pt_buf: [plaintext_len]u8 = @splat(0);
    writePlaintext(&pt_buf, opts);

    var aead = AesGcm256.init(opts.key) catch return Error.AeadFailure;
    defer aead.deinit();
    const ct_len = aead.seal(
        dst[nonce_len..max_token_len],
        &nonce,
        domain_separator,
        &pt_buf,
    ) catch return Error.AeadFailure;
    std.debug.assert(ct_len == plaintext_len + tag_len);
    return max_token_len;
}

/// Convenience wrapper around `mint` that returns a fresh `Token`
/// by-value.
pub fn minted(opts: MintOptions) Error!Token {
    var token: Token = undefined;
    _ = try mint(&token, opts);
    return token;
}

/// Validate a NEW_TOKEN. Returns `.valid` only if the AEAD opens
/// cleanly, the recovered address matches, and the token is within
/// its issue/expiry window (subject to `max_clock_skew_us`). All
/// failure modes are surfaced as enum variants — the function never
/// errors. Address comparison runs in constant time over the
/// recovered plaintext.
pub fn validate(token: []const u8, opts: ValidateOptions) ValidationResult {
    if (token.len != max_token_len) return .malformed;
    validateBoundInputs(opts.client_address) catch return .malformed;

    var nonce: [nonce_len]u8 = undefined;
    @memcpy(&nonce, token[0..nonce_len]);
    const ciphertext = token[nonce_len..max_token_len];

    var aead = AesGcm256.init(opts.key) catch return .malformed;
    defer aead.deinit();
    var pt_buf: [plaintext_len]u8 = undefined;
    const opened_len = aead.open(&pt_buf, &nonce, domain_separator, ciphertext) catch return .malformed;
    std.debug.assert(opened_len == plaintext_len);

    var fields: PlaintextFields = undefined;
    parsePlaintext(&pt_buf, &fields) catch return .malformed;

    if (fields.quic_version != opts.quic_version) return .wrong_version;
    if (addSat(opts.now_us, opts.max_clock_skew_us) < fields.issued_at_us) return .not_yet_valid;
    if (opts.now_us > addSat(fields.expires_at_us, opts.max_clock_skew_us)) return .expired;

    if (!equalCt(fields.client_address, opts.client_address)) return .invalid;
    return .valid;
}

fn validateBoundInputs(client_address: []const u8) Error!void {
    if (client_address.len > max_address_len) return Error.ContextTooLong;
}

/// Write the v1 plaintext layout into `dst`, which must be exactly
/// `plaintext_len` bytes (caller pre-zeros for trailing padding).
fn writePlaintext(dst: *[plaintext_len]u8, opts: MintOptions) void {
    var pos: usize = 0;
    std.mem.writeInt(u32, dst[pos..][0..4], opts.quic_version, .big);
    pos += 4;
    std.mem.writeInt(u64, dst[pos..][0..8], opts.now_us, .big);
    pos += 8;
    std.mem.writeInt(u64, dst[pos..][0..8], addSat(opts.now_us, opts.lifetime_us), .big);
    pos += 8;

    dst[pos] = @intCast(opts.client_address.len);
    pos += 1;
    @memcpy(dst[pos..][0..opts.client_address.len], opts.client_address);
    // Caller zero-initialised `dst`; trailing padding bytes are
    // well-defined zeros.
}

const PlaintextFields = struct {
    quic_version: u32,
    issued_at_us: u64,
    expires_at_us: u64,
    client_address: []const u8,
};

const ParseError = error{TruncatedField};

fn parsePlaintext(pt: *const [plaintext_len]u8, out: *PlaintextFields) ParseError!void {
    out.quic_version = std.mem.readInt(u32, pt[0..4], .big);
    out.issued_at_us = std.mem.readInt(u64, pt[4..12], .big);
    out.expires_at_us = std.mem.readInt(u64, pt[12..20], .big);

    var pos: usize = 20;
    out.client_address = try readLengthPrefixed(pt, &pos, max_address_len);
}

fn readLengthPrefixed(pt: *const [plaintext_len]u8, pos: *usize, cap: usize) ParseError![]const u8 {
    if (pos.* + 1 > pt.len) return ParseError.TruncatedField;
    const len: usize = pt[pos.*];
    pos.* += 1;
    if (len > cap) return ParseError.TruncatedField;
    if (pos.* + len > pt.len) return ParseError.TruncatedField;
    const slice = pt[pos.* .. pos.* + len];
    pos.* += len;
    return slice;
}

/// Length-aware constant-time byte slice equality. `timing_safe.eql`
/// requires fixed-size arrays, so we route through fixed-size scratch
/// buffers sized to fit any v1 bound field.
fn equalCt(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var sa: [plaintext_len]u8 = @splat(0);
    var sb: [plaintext_len]u8 = @splat(0);
    @memcpy(sa[0..a.len], a);
    @memcpy(sb[0..b.len], b);
    return std.crypto.timing_safe.eql([plaintext_len]u8, sa, sb);
}

fn addSat(a: u64, b: u64) u64 {
    return std.math.add(u64, a, b) catch std.math.maxInt(u64);
}

const testing_key: Key = .{
    0x4f, 0x95, 0xd1, 0x6b, 0x2a, 0x7c, 0x83, 0xee,
    0x18, 0x42, 0x90, 0x3d, 0xfa, 0xc4, 0x6e, 0x71,
    0x09, 0xb6, 0x55, 0xa3, 0x2c, 0xee, 0x18, 0x77,
    0xd4, 0x3f, 0x88, 0x21, 0x05, 0x6c, 0xa9, 0x33,
};

test "NEW_TOKEN validates with matching address version and time" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 24 * 3600 * 1_000_000,
        .client_address = "ip4:127.0.0.1:4242",
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
    }));
}

test "NEW_TOKEN validates under non-default QUIC version" {
    const v2: u32 = 0x6b3343cf;
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 60_000_000,
        .client_address = "addr",
        .quic_version = v2,
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 1_500_000,
        .client_address = "addr",
        .quic_version = v2,
    }));

    // Default version (0x00000001) is the wrong version here.
    try std.testing.expectEqual(ValidationResult.wrong_version, validate(&token, .{
        .key = &testing_key,
        .now_us = 1_500_000,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN rejects expired and not-yet-valid tokens" {
    var token = try minted(.{
        .key = &testing_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
    });

    const opts: ValidateOptions = .{
        .key = &testing_key,
        .now_us = 11_000_000,
        .client_address = "addr",
    };

    var expired = opts;
    expired.now_us = 15_000_001;
    try std.testing.expectEqual(ValidationResult.expired, validate(&token, expired));

    var future = opts;
    future.now_us = 9_999_999;
    try std.testing.expectEqual(ValidationResult.not_yet_valid, validate(&token, future));

    // Clock-skew tolerance moves both edges out.
    var skewed_expired = expired;
    skewed_expired.max_clock_skew_us = 2_000_000;
    try std.testing.expectEqual(ValidationResult.valid, validate(&token, skewed_expired));
    var skewed_future = future;
    skewed_future.max_clock_skew_us = 2_000_000;
    try std.testing.expectEqual(ValidationResult.valid, validate(&token, skewed_future));
}

test "NEW_TOKEN rejects malformed truncated and tampered tokens" {
    var token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000,
        .lifetime_us = 60_000,
        .client_address = "addr",
    });

    const opts: ValidateOptions = .{
        .key = &testing_key,
        .now_us = 5_000,
        .client_address = "addr",
    };

    // Truncating any byte makes the wire size != max_token_len, so
    // the length gate rejects before crypto state is touched.
    try std.testing.expectEqual(ValidationResult.malformed, validate(token[0 .. token.len - 1], opts));
    // Flipping the trailing tag byte breaks AEAD auth.
    token[token.len - 1] ^= 0x01;
    try std.testing.expectEqual(ValidationResult.malformed, validate(&token, opts));
    // Unflip and corrupt a nonce byte — also breaks auth.
    token[token.len - 1] ^= 0x01;
    token[0] ^= 0x01;
    try std.testing.expectEqual(ValidationResult.malformed, validate(&token, opts));
}

test "NEW_TOKEN rejects wrong key" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000,
        .lifetime_us = 60_000,
        .client_address = "addr",
    });
    const wrong_key: Key = @splat(0xff);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&token, .{
        .key = &wrong_key,
        .now_us = 5_000,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN rejects Retry-token-shaped bytes (wrong domain)" {
    // A token shaped at the wire level (96 bytes random) but minted
    // by some other AES-GCM construction, or with the wrong domain
    // separator, can never authenticate. Mint a Retry-token-style
    // blob as a stand-in: the AEAD AAD differs, so opening fails and
    // we return `.malformed`.
    var random_blob: [max_token_len]u8 = @splat(0xab);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&random_blob, .{
        .key = &testing_key,
        .now_us = 1_000,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN rejects address mismatch" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:127.0.0.1:4242",
    });

    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4243",
    }));
}

test "NEW_TOKEN mint rejects oversized address and undersized output" {
    var addr_buf: [max_address_len + 1]u8 = @splat(0);
    var dst: [max_token_len]u8 = undefined;
    try std.testing.expectError(Error.ContextTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = &addr_buf,
    }));

    var small: [4]u8 = undefined;
    try std.testing.expectError(Error.OutputTooSmall, mint(&small, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN mint produces fixed-length 96-byte tokens with random nonce" {
    var dst: [max_token_len]u8 = undefined;
    const n = try mint(&dst, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
    });
    try std.testing.expectEqual(@as(usize, max_token_len), n);

    var dst2: [max_token_len]u8 = undefined;
    _ = try mint(&dst2, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
    });
    // Two mints under the same key/inputs differ in the random
    // nonce, so the wire bytes diverge.
    try std.testing.expect(!std.mem.eql(u8, &dst, &dst2));
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `validate` with arbitrary bytes and a fuzzer-chosen address.
// Property: never panics or reaches `unreachable`, and never returns
// `.valid` for an input the fuzzer didn't mint with `testing_key` — a
// `.valid` answer would imply a forgery against AES-GCM-256.

test "fuzz: new_token validate never panics" {
    try std.testing.fuzz({}, fuzzValidate, .{});
}

fn fuzzValidate(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [max_token_len * 2]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    var addr_buf: [max_address_len]u8 = undefined;
    const addr_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_address_len));
    smith.bytes(addr_buf[0..addr_len]);

    const result = validate(input, .{
        .key = &testing_key,
        .now_us = smith.value(u64),
        .client_address = addr_buf[0..addr_len],
        .quic_version = smith.value(u32),
        .max_clock_skew_us = smith.value(u64),
    });
    if (result == .valid) return error.UnexpectedValid;
}
