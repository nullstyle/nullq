//! Default-safe stateless-reset token derivation (RFC 9000 §10.3
//! and hardening guide §4.5).
//!
//! A QUIC stateless-reset token is a 16-byte value the server commits
//! to when issuing a connection ID; if the server later loses the
//! connection's keying material, it returns that same token in a
//! short-header packet to tell the peer "drop this connection". For
//! the mechanism to be safe:
//!
//!   - Tokens MUST be hard to guess from the outside (an attacker who
//!     can predict tokens can forge resets).
//!   - The same token MUST NOT be associated with more than one CID
//!     (RFC 9000 §10.3.1).
//!   - The same token MUST NOT be issued by more than one server
//!     (otherwise resets are linkable across servers).
//!
//! The recommended construction is HMAC over the CID with a
//! server-private key. This module ships that construction so an
//! embedder doesn't have to roll their own:
//!
//! ```zig
//! const key = try nullq.conn.stateless_reset.Key.generate();
//! const token = try nullq.conn.stateless_reset.derive(&key, cid_bytes);
//! try connection.provideConnectionId(.{
//!     .connection_id = cid_bytes,
//!     .stateless_reset_token = token,
//! });
//! ```
//!
//! Embedders that want a different scheme (e.g. encrypted tokens
//! that double as routing keys) keep ignoring this module and supply
//! their own bytes via `ConnectionIdProvision.stateless_reset_token`.

const std = @import("std");
const boringssl = @import("boringssl");

/// HMAC-SHA256 secret length. The key length matches the HMAC's
/// internal block size; `Key.generate` fills it from the CSPRNG.
pub const key_len: usize = 32;

/// Server-private HMAC key. **Per-server, never shared, never logged.**
/// `Server.deinit` (or whoever owns the embedded key) is responsible
/// for `std.crypto.secureZero`-ing the bytes when the key goes out of
/// scope. Rotation policy is up to the operator — the obvious
/// constraints are (a) rotating invalidates every issued token (peers
/// holding old reset tokens won't be able to use them), and (b) the
/// key must outlive the longest expected idle-timeout among live
/// connections so reset paths still work after a clean restart.
pub const Key = [key_len]u8;

/// Output token length per RFC 9000 §10.3 — fixed at 16 bytes.
pub const token_len: usize = 16;

/// Fixed-size stateless-reset token.
pub const Token = [token_len]u8;

/// Domain-separator label baked into the HMAC input. Prevents the
/// same `Key` from accidentally producing a colliding HMAC value if
/// the key is reused for an unrelated nullq HMAC primitive in the
/// future.
const domain_separator: []const u8 = "nullq stateless reset v1";

/// Errors that `derive` can surface. Currently the only failure mode
/// is an HMAC primitive failure from BoringSSL; nullq's own input
/// validation never rejects a CID here (any byte string is a valid
/// CID input — the standards-required CID-length cap is enforced by
/// the caller's `ConnectionId` type).
pub const Error = boringssl.crypto.hmac.Error;

/// Derive the 16-byte stateless-reset token for `connection_id` under
/// `key`. The token is the first 16 bytes of
/// `HMAC-SHA256(key, "nullq stateless reset v1" || connection_id)`.
///
/// Same `(key, connection_id)` pair always returns the same token
/// (deterministic — that's the point: the server can re-derive the
/// token if it loses local state, which is the whole reason
/// stateless-reset exists). Different CIDs under the same key
/// produce uncorrelated tokens (HMAC's collision-resistance).
pub fn derive(key: *const Key, connection_id: []const u8) Error!Token {
    var h = try boringssl.crypto.hmac.HmacSha256.init(key);
    defer h.deinit();
    try h.update(domain_separator);
    try h.update(connection_id);
    const digest = try h.finalDigest();
    var token: Token = undefined;
    @memcpy(&token, digest[0..token_len]);
    return token;
}

/// Generate a fresh random `Key` from the CSPRNG. Embedders that
/// want a deterministic key (test fixtures) construct one directly
/// from a `[32]u8` literal — there's no test-only init helper here
/// because the call shape would be identical.
pub fn generateKey() boringssl.crypto.rand.Error!Key {
    var key: Key = undefined;
    try boringssl.crypto.rand.fillBytes(&key);
    return key;
}

/// Constant-time equality for two stateless-reset tokens. RFC 9000
/// §10.3 ¶17 (last paragraph): "An endpoint MUST NOT … use any
/// non-constant-time comparison" when matching stateless-reset
/// tokens, because a timing oracle on a partially-matching prefix
/// would let an attacker incrementally guess the token.
///
/// `Connection` routes its receive-path token compare through this
/// helper (see `Connection.tokenEql`). Conformance tests verify the
/// observable property — equal tokens compare equal, and any
/// single-bit flip in any position compares not-equal.
pub fn eql(a: Token, b: Token) bool {
    return std.crypto.timing_safe.eql(Token, a, b);
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

test "derive is deterministic for a given (key, cid) pair" {
    const key: Key = @splat(0xab);
    const cid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const a = try derive(&key, &cid);
    const b = try derive(&key, &cid);

    try testing.expectEqualSlices(u8, &a, &b);
    try testing.expectEqual(@as(usize, token_len), a.len);
}

test "derive produces different tokens for different CIDs under the same key" {
    const key: Key = @splat(0x55);
    const cid_a: [4]u8 = .{ 1, 2, 3, 4 };
    const cid_b: [4]u8 = .{ 1, 2, 3, 5 };

    const ta = try derive(&key, &cid_a);
    const tb = try derive(&key, &cid_b);

    try testing.expect(!std.mem.eql(u8, &ta, &tb));
}

test "derive produces different tokens for the same CID under different keys" {
    const key_a: Key = @splat(0x01);
    const key_b: Key = @splat(0x02);
    const cid: [8]u8 = .{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11 };

    const ta = try derive(&key_a, &cid);
    const tb = try derive(&key_b, &cid);

    try testing.expect(!std.mem.eql(u8, &ta, &tb));
}

test "derive accepts a zero-length CID (some embedders use them for routing)" {
    const key: Key = @splat(0xff);
    const empty: []const u8 = &.{};

    const t = try derive(&key, empty);
    try testing.expectEqual(@as(usize, token_len), t.len);
}

test "generateKey produces non-zero, non-equal keys on successive calls" {
    const k1 = try generateKey();
    const k2 = try generateKey();

    // Zero-key is astronomically unlikely from a CSPRNG; treat it as
    // a regression in the wiring.
    var zero: Key = @splat(0);
    try testing.expect(!std.mem.eql(u8, &k1, &zero));
    try testing.expect(!std.mem.eql(u8, &k1, &k2));
}
