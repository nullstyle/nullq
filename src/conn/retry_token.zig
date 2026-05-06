//! Stateless Retry-token helper for QUIC address validation.
//!
//! The transport stays I/O-agnostic: callers provide canonical client
//! address bytes. Tokens are AEAD-sealed with AES-GCM-256 and bind
//! the client address, the Original Destination CID, the Retry
//! Source CID, the QUIC version, and an issue/expiry window. The
//! previous v1 HMAC-only format leaked all bound fields in plaintext
//! (only the HMAC tag was opaque); v2 keeps the same authenticity
//! guarantee while making the token bytes a uniformly random opaque
//! blob to peers and on-path observers (hardening item B2).
//!
//! Wire format (v2, fixed 96 bytes):
//!
//!     nonce (12)  |  ciphertext (68)  |  tag (16)
//!
//! Mint always pads the inner plaintext to exactly 68 bytes before
//! AEAD-sealing, so on-wire tokens are constant-length and cannot
//! be distinguished by the layout of bound fields.
//!
//! Inner plaintext (68 bytes after zero-padding):
//!
//!     version    (4 bytes,  big-endian)
//!     issued_at  (8 bytes,  big-endian, microseconds since epoch)
//!     expires_at (8 bytes,  big-endian, microseconds since epoch)
//!     addr_len   (1 byte)         | client_address (<= 22 bytes)
//!     odcid_len  (1 byte)         | original_dcid  (<= 20 bytes)
//!     scid_len   (1 byte)         | retry_scid     (<= 20 bytes)
//!     <pad>      (zero bytes to reach 68)
//!
//! Mint enforces a per-call sum constraint so the bound material
//! fits the fixed plaintext budget:
//!
//!     addr_len + odcid_len + scid_len <= 45  bytes  (= 68 - 23)
//!
//! With server.zig's 22-byte address slot and the default 8-byte
//! server SCID that leaves up to 15 bytes for the peer's original
//! DCID — comfortably above the 8-byte typical and the 8-byte
//! interop convention. Peers presenting unusually long initial
//! DCIDs (>15 bytes when paired with the default SCID length) cause
//! `mint` to return `Error.OutputTooSmall`; the server then drops
//! the Initial rather than minting a Retry. Operators that want
//! full 20-byte CID coverage should bump `max_token_len`.

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

/// Maximum CID length the format can carry. Matches the QUIC v1
/// limit (`path.max_cid_len = 20`). Note the per-call sum cap
/// described in this module's preamble — both CIDs at full 20
/// bytes plus a 22-byte address overflows the fixed plaintext
/// budget and `mint` will return `Error.OutputTooSmall`.
pub const max_cid_len: usize = path.max_cid_len;

/// Plaintext layout overhead: 4 (version) + 8 (issued) + 8 (expires)
/// + 3 length prefix bytes (one per bound field).
const plaintext_fixed_overhead: usize = 4 + 8 + 8 + 3;

/// Total token length on the wire (and in `Token`). Fixed at 96
/// bytes: a 12-byte AEAD nonce, a 68-byte ciphertext (zero-padded
/// plaintext under fixed-size AEAD), and a 16-byte authentication
/// tag.
pub const max_token_len: usize = 96;

/// Plaintext payload size: equal to `max_token_len - nonce_len - tag_len`.
/// Plaintext is zero-padded to this length before AEAD seal so every
/// minted token is a constant-length opaque blob.
const plaintext_len: usize = max_token_len - nonce_len - tag_len;

comptime {
    // Guard against accidental misalignment of the tuned constants.
    std.debug.assert(plaintext_len >= plaintext_fixed_overhead);
}

/// Maximum sum of the three bound-field lengths that fits in the
/// fixed plaintext budget. Mint enforces this at runtime via
/// `Error.OutputTooSmall`.
const max_bound_total: usize = plaintext_len - plaintext_fixed_overhead;

/// 32-byte AES-GCM-256 key. The server must keep this stable across
/// the token's lifetime so it can validate after a Retry round-trip.
/// Rotate to invalidate every outstanding Retry token at once;
/// outstanding (already-minted) tokens cannot be migrated to a new
/// key, so rotate at session boundaries or via a brief two-key
/// overlap window.
pub const Key = [key_len]u8;

/// Fixed-size Retry token (RFC 9000 §8.1.2). Always exactly
/// `max_token_len` bytes — `mint` zero-pads its plaintext before
/// AEAD-sealing so the wire shape doesn't reveal which fields are
/// bound (or how long they were).
pub const Token = [max_token_len]u8;

/// Domain separator. Bumped from "...v1" because the format changed.
/// Mixed into AEAD AAD; replaying a v1 HMAC-tagged blob through v2
/// `validate` returns `.malformed`.
const domain_separator = "nullq retry token v2";

/// Errors raised by `mint` and (via `validate`) surfaced as `.malformed`.
pub const Error = error{
    /// Output buffer was smaller than `max_token_len`, or the
    /// requested bound-field combination doesn't fit the fixed
    /// plaintext budget.
    OutputTooSmall,
    /// `client_address` exceeded `max_address_len`.
    ContextTooLong,
    /// A Connection ID exceeded `max_cid_len`.
    DcidTooLong,
    /// AEAD seal/init failure (BoringSSL). Not peer-reachable in
    /// practice; surfaces only on out-of-memory or library misuse.
    AeadFailure,
    /// CSPRNG failure (BoringSSL). Same not-peer-reachable property.
    RandFailure,
};

/// Inputs to `mint`. The AEAD seal binds `client_address`,
/// `original_dcid`, `retry_scid`, `quic_version`, `now_us`, and the
/// expiry derived from `lifetime_us`.
pub const MintOptions = struct {
    key: *const Key,
    now_us: u64,
    lifetime_us: u64,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
    quic_version: u32 = 0x00000001,
};

/// Inputs to `validate`. Must be byte-equal to the `MintOptions`
/// values used to issue the token (modulo `now_us`/`max_clock_skew_us`).
pub const ValidateOptions = struct {
    key: *const Key,
    now_us: u64,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
    quic_version: u32 = 0x00000001,
    max_clock_skew_us: u64 = 0,
};

/// Outcome of `validate`.
pub const ValidationResult = enum {
    /// AEAD opened cleanly, recovered fields match, and timestamps
    /// are within the allowed window.
    valid,
    /// Length, AEAD authentication, or recovered-field shape was
    /// wrong (also covers the case where a v1 HMAC-format token is
    /// presented to v2). Treat as untrusted.
    malformed,
    /// The QUIC version field did not match.
    wrong_version,
    /// `issued_at_us` is in the future beyond `max_clock_skew_us`.
    not_yet_valid,
    /// `expires_at_us` is in the past beyond `max_clock_skew_us`.
    expired,
    /// AEAD opened cleanly but a recovered bound field (address,
    /// ODCID, retry SCID) did not match the validator's expectation.
    invalid,
};

/// Mint a Retry token into `dst`. Returns the number of bytes
/// written (always `max_token_len`). Errors come from oversized
/// bound fields, a bound-total that doesn't fit the fixed plaintext
/// budget, a short output buffer, or an underlying BoringSSL
/// failure.
pub fn mint(dst: []u8, opts: MintOptions) Error!usize {
    if (dst.len < max_token_len) return Error.OutputTooSmall;
    try validateBoundInputs(opts.client_address, opts.original_dcid, opts.retry_scid);
    if (opts.client_address.len + opts.original_dcid.len + opts.retry_scid.len > max_bound_total) {
        return Error.OutputTooSmall;
    }

    // Per-token random nonce. AES-GCM nonce reuse under a fixed key
    // breaks confidentiality and integrity, so the CSPRNG path is
    // load-bearing. boringssl-zig surfaces RAND failures as an
    // explicit error; bubble it up rather than silently zeroing.
    var nonce: [nonce_len]u8 = undefined;
    boringssl.crypto.rand.fillBytes(&nonce) catch return Error.RandFailure;
    @memcpy(dst[0..nonce_len], &nonce);

    // Plaintext is always exactly `plaintext_len` bytes; trailing
    // bytes are zero-padding so a length-prefix that consumes less
    // than the full budget recovers cleanly.
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

/// Validate a Retry token. Returns `.valid` only if the AEAD opens
/// cleanly, every bound field matches the validator's expectation,
/// and the token is within its issue/expiry window (subject to
/// `max_clock_skew_us`). All failure modes are surfaced as enum
/// variants — the function never errors. Bound-field comparisons
/// run in constant time over the recovered plaintext.
pub fn validate(token: []const u8, opts: ValidateOptions) ValidationResult {
    if (token.len != max_token_len) return .malformed;
    validateBoundInputs(opts.client_address, opts.original_dcid, opts.retry_scid) catch return .malformed;

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
    if (!equalCt(fields.original_dcid, opts.original_dcid)) return .invalid;
    if (!equalCt(fields.retry_scid, opts.retry_scid)) return .invalid;
    return .valid;
}

fn validateBoundInputs(client_address: []const u8, original_dcid: []const u8, retry_scid: []const u8) Error!void {
    if (client_address.len > max_address_len) return Error.ContextTooLong;
    if (original_dcid.len > max_cid_len) return Error.DcidTooLong;
    if (retry_scid.len > max_cid_len) return Error.DcidTooLong;
}

/// Write the v2 plaintext layout into `dst`, which must be exactly
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
    pos += opts.client_address.len;

    dst[pos] = @intCast(opts.original_dcid.len);
    pos += 1;
    @memcpy(dst[pos..][0..opts.original_dcid.len], opts.original_dcid);
    pos += opts.original_dcid.len;

    dst[pos] = @intCast(opts.retry_scid.len);
    pos += 1;
    @memcpy(dst[pos..][0..opts.retry_scid.len], opts.retry_scid);
    pos += opts.retry_scid.len;
    // Caller zero-initialised `dst`, so trailing padding bytes are
    // well-defined zeros.
}

const PlaintextFields = struct {
    quic_version: u32,
    issued_at_us: u64,
    expires_at_us: u64,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
};

const ParseError = error{TruncatedField};

/// Parse the v2 plaintext (length always `plaintext_len`). Trailing
/// bytes after the last length-prefixed field are treated as
/// padding — the AEAD already authenticated them, so we don't need
/// to validate the pad shape here.
fn parsePlaintext(pt: *const [plaintext_len]u8, out: *PlaintextFields) ParseError!void {
    out.quic_version = std.mem.readInt(u32, pt[0..4], .big);
    out.issued_at_us = std.mem.readInt(u64, pt[4..12], .big);
    out.expires_at_us = std.mem.readInt(u64, pt[12..20], .big);

    var pos: usize = 20;
    out.client_address = try readLengthPrefixed(pt, &pos, max_address_len);
    out.original_dcid = try readLengthPrefixed(pt, &pos, max_cid_len);
    out.retry_scid = try readLengthPrefixed(pt, &pos, max_cid_len);
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
/// requires fixed-size arrays, so we route through fixed-size
/// scratch buffers sized to fit any v2 bound field.
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

test "Retry token rejects v1 HMAC-format prefix as malformed under v2" {
    // Sanity: a token shaped like the legacy v1 wire format (53
    // bytes, no random nonce, HMAC tag at the tail) doesn't match
    // `max_token_len` and is rejected by the length gate. Operators
    // rotating from v1 to v2 see every outstanding token invalidate
    // cleanly.
    var legacy: [53]u8 = @splat(0xcd);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&legacy, .{
        .key = &testing_key,
        .now_us = 1_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
    // Even at the right wire size, random bytes don't AEAD-open.
    var random_blob: [max_token_len]u8 = @splat(0xab);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&random_blob, .{
        .key = &testing_key,
        .now_us = 1_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
}

test "Retry token mint rejects oversized bound fields" {
    var addr_buf: [max_address_len + 1]u8 = @splat(0);
    var dst: [max_token_len]u8 = undefined;
    try std.testing.expectError(Error.ContextTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = &addr_buf,
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));

    var cid_buf: [max_cid_len + 1]u8 = @splat(0);
    try std.testing.expectError(Error.DcidTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
        .original_dcid = &cid_buf,
        .retry_scid = &.{2},
    }));
    try std.testing.expectError(Error.DcidTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &cid_buf,
    }));
}

test "Retry token mint rejects bound-total over plaintext budget" {
    var dst: [max_token_len]u8 = undefined;
    var addr_full: [max_address_len]u8 = @splat(0);
    var cid_full: [max_cid_len]u8 = @splat(0);
    // 22 + 20 + 20 = 62 > 45, doesn't fit the 68-byte plaintext.
    try std.testing.expectError(Error.OutputTooSmall, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = &addr_full,
        .original_dcid = &cid_full,
        .retry_scid = &cid_full,
    }));
}

test "Retry token mint rejects undersized output buffer" {
    var dst: [4]u8 = undefined;
    try std.testing.expectError(Error.OutputTooSmall, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
}

test "Retry token mint produces fixed-length 96-byte tokens" {
    var dst: [max_token_len]u8 = undefined;
    const n = try mint(&dst, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });
    try std.testing.expectEqual(@as(usize, max_token_len), n);

    // Two mints under the same key/inputs differ in the random
    // nonce, so the wire bytes diverge. This is the ciphertext
    // indistinguishability property the v1 HMAC format lacked.
    var dst2: [max_token_len]u8 = undefined;
    _ = try mint(&dst2, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });
    try std.testing.expect(!std.mem.eql(u8, &dst, &dst2));
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `validate` with arbitrary bytes and a fuzzer-chosen set of
// expected bound fields. Property: the function never panics or
// reaches `unreachable`, and never returns `.valid` for an input the
// fuzzer didn't mint with the same key. (The fuzzer's bytes are
// untrusted relative to `testing_key`; any `.valid` answer would
// imply a forgery against AES-GCM-256.)

test "fuzz: retry_token validate never panics" {
    try std.testing.fuzz({}, fuzzValidate, .{});
}

fn fuzzValidate(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [max_token_len * 2]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    // Fuzzer-chosen expectations clamped to the format's caps so
    // `validate` itself drives any length-based rejection rather
    // than short-circuiting on `validateBoundInputs`.
    var addr_buf: [max_address_len]u8 = undefined;
    const addr_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_address_len));
    smith.bytes(addr_buf[0..addr_len]);

    var odcid_buf: [max_cid_len]u8 = undefined;
    const odcid_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_cid_len));
    smith.bytes(odcid_buf[0..odcid_len]);

    var scid_buf: [max_cid_len]u8 = undefined;
    const scid_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_cid_len));
    smith.bytes(scid_buf[0..scid_len]);

    const result = validate(input, .{
        .key = &testing_key,
        .now_us = smith.value(u64),
        .client_address = addr_buf[0..addr_len],
        .original_dcid = odcid_buf[0..odcid_len],
        .retry_scid = scid_buf[0..scid_len],
        .quic_version = smith.value(u32),
        .max_clock_skew_us = smith.value(u64),
    });
    // Every byte string the fuzzer hands us is unauthenticated
    // relative to `testing_key`. A `.valid` answer would imply a
    // forgery against AES-GCM-256 — fail loud so the fuzzer
    // minimizes and persists the witness.
    if (result == .valid) return error.UnexpectedValid;
}
