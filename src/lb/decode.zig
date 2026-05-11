//! LB-side connection-ID decoder
//! (draft-ietf-quic-load-balancers-21 §5.5).
//!
//! Reverses the server-side `lb.cid.Factory.mint` to recover the
//! routing identity (`server_id`, `nonce`, `config_id`) from a
//! minted CID. Used by:
//!
//!   * Round-trip property tests in the conformance suite.
//!   * Operations tooling that needs to inspect what a server
//!     would mint (e.g. the QNS harness, future LB tooling).
//!   * External load balancer tooling that needs the recovered
//!     routing identity.
//!
//! ## Coverage
//!
//! All three modes are implemented:
//!
//!   * **§5.5 plaintext** — direct extraction of `server_id || nonce`.
//!   * **§5.5.1 single-pass** — runs `AES-128-ECB decrypt` over the
//!     16-byte body to recover `server_id || nonce` via
//!     `Aes128.initDecrypt` / `decryptBlock`.
//!   * **§5.5.2 four-pass Feistel** — runs `feistel.decrypt`, which
//!     uses AES-128-ECB *encrypt* as the round function (Feistel only
//!     needs the round function to be deterministic, never invertible).

const std = @import("std");
const boringssl = @import("boringssl");

const config_mod = @import("config.zig");
const cid_mod = @import("cid.zig");
const feistel_mod = @import("feistel.zig");

pub const LbConfig = config_mod.LbConfig;
pub const ServerId = config_mod.ServerId;

const Aes128 = boringssl.crypto.aes.Aes128;

pub const Error = error{
    /// `cid` was shorter than `cfg.cidLength()`.
    CidTooShort,
    /// First octet's high 3 bits were `0b111`, signalling the
    /// unroutable fallback (§3.1). The LB has no routing identity to
    /// recover — these CIDs must be routed through a configured
    /// fallback path, not decoded.
    UnroutableCid,
    /// `cfg` was not internally consistent (`LbConfig.validate`
    /// rejected it).
    InvalidLbConfig,
    /// `cfg.key` was a 16-byte `[16]u8` BoringSSL refused.
    AesKeyInvalid,
};

/// Routing identity recovered from a minted CID. The byte slices in
/// `server_id` and `nonce` reference the bounded buffers held inline,
/// so they're stable for the value's lifetime.
pub const Decoded = struct {
    /// First-octet `config_id` (0..6 in valid CIDs). 7 surfaces as
    /// `Error.UnroutableCid`, never inside a `Decoded` value.
    config_id: u8,
    /// Decoded server identity. `len` matches `LbConfig.server_id.len`.
    server_id: ServerId,
    /// Decoded nonce. `len` matches `LbConfig.nonce_len`.
    nonce: BoundedNonce,

    /// Const slice of the live nonce bytes.
    pub fn nonceSlice(self: *const Decoded) []const u8 {
        return self.nonce.bytes[0..self.nonce.len];
    }
};

/// Bounded nonce buffer — the same shape as `lb.config.ServerId`,
/// sized for the `1..max_nonce_len` range.
pub const BoundedNonce = struct {
    len: u8 = 0,
    bytes: [config_mod.max_nonce_len]u8 = @splat(0),
};

/// Decode `cid` under `cfg`. Round-trip property: for any `mint(...)`
/// output `c` produced under the same `cfg`, `decode(c, cfg)` returns
/// `(server_id, nonce)` matching the inputs to `mint`.
///
/// Errors:
///   * `CidTooShort` — `cid.len < cfg.cidLength()`.
///   * `UnroutableCid` — first-octet config_id was 0b111.
///   * `InvalidLbConfig` — `cfg.validate()` failed.
///   * `AesKeyInvalid` — BoringSSL refused `cfg.key`.
pub fn decode(cid: []const u8, cfg: LbConfig) Error!Decoded {
    cfg.validate() catch return Error.InvalidLbConfig;
    if (cid.len < cfg.cidLength()) return Error.CidTooShort;

    const config_id_bits: u8 = cid_mod.firstOctetConfigId(cid[0]);
    if (config_id_bits == config_mod.unroutable_config_id) return Error.UnroutableCid;

    const sid_len: usize = cfg.server_id.len;
    const nonce_len: usize = cfg.nonce_len;
    const combined: usize = sid_len + nonce_len;

    var plaintext_buf: [config_mod.max_combined_len]u8 = undefined;

    if (cfg.key) |key| {
        if (combined == 16) {
            // §5.5.1 single-pass: invert the §5.4.1
            // AES-128-ECB(key, server_id || nonce) the server applied
            // when minting. Use `Aes128.initDecrypt` / `decryptBlock`;
            // the forward `init` would silently produce garbage because
            // AES uses different schedules for encrypt vs decrypt.
            const aes = Aes128.initDecrypt(&key) catch return Error.AesKeyInvalid;
            var pt_block: [16]u8 = undefined;
            const ct_ptr: *const [16]u8 = cid[1..17];
            aes.decryptBlock(ct_ptr, &pt_block);
            @memcpy(plaintext_buf[0..16], &pt_block);
        } else {
            const aes = Aes128.init(&key) catch return Error.AesKeyInvalid;
            feistel_mod.decrypt(&aes, cid[1 .. 1 + combined], plaintext_buf[0..combined]) catch |e| switch (e) {
                // `cfg.validate()` already enforced 5..19 with
                // combined != 16. Reaching this would mean the config
                // drifted from its validated state — surface as
                // InvalidLbConfig.
                error.InvalidPlaintextLen => return Error.InvalidLbConfig,
            };
        }
    } else {
        @memcpy(plaintext_buf[0..combined], cid[1 .. 1 + combined]);
    }

    var out: Decoded = .{
        .config_id = config_id_bits,
        .server_id = .{ .len = @intCast(sid_len) },
        .nonce = .{ .len = @intCast(nonce_len) },
    };
    @memcpy(out.server_id.bytes[0..sid_len], plaintext_buf[0..sid_len]);
    @memcpy(out.nonce.bytes[0..nonce_len], plaintext_buf[sid_len..combined]);
    return out;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

test "decode: plaintext round-trip recovers server_id and nonce" {
    const sid_bytes: []const u8 = &.{ 0xde, 0xad, 0xbe, 0xef };
    const nonce_bytes: []const u8 = &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const cfg: LbConfig = .{
        .config_id = 4,
        .server_id = try ServerId.fromSlice(sid_bytes),
        .nonce_len = @intCast(nonce_bytes.len),
    };
    var f = try cid_mod.Factory.init(cfg);
    defer f.deinit();

    var cid: [16]u8 = undefined;
    const n = try f.mintWithNonce(&cid, nonce_bytes);

    const decoded = try decode(cid[0..n], cfg);
    try testing.expectEqual(@as(u8, 4), decoded.config_id);
    try testing.expectEqualSlices(u8, sid_bytes, decoded.server_id.slice());
    try testing.expectEqualSlices(u8, nonce_bytes, decoded.nonceSlice());
}

test "decode: four-pass round-trip recovers server_id and nonce (odd combined)" {
    const sid_bytes: [3]u8 = .{ 0x31, 0x44, 0x1a };
    const nonce_bytes: [4]u8 = .{ 0x9c, 0x69, 0xc2, 0x75 };
    const key: [16]u8 = .{
        0xfd, 0xf7, 0x26, 0xa9, 0x89, 0x3e, 0xc0, 0x5c,
        0x06, 0x32, 0xd3, 0x95, 0x66, 0x80, 0xba, 0xf0,
    };
    const cfg: LbConfig = .{
        .config_id = 0,
        .server_id = try ServerId.fromSlice(&sid_bytes),
        .nonce_len = 4,
        .key = key,
    };
    var f = try cid_mod.Factory.init(cfg);
    defer f.deinit();

    var cid: [16]u8 = undefined;
    const n = try f.mintWithNonce(&cid, &nonce_bytes);

    const decoded = try decode(cid[0..n], cfg);
    try testing.expectEqualSlices(u8, &sid_bytes, decoded.server_id.slice());
    try testing.expectEqualSlices(u8, &nonce_bytes, decoded.nonceSlice());
}

test "decode: four-pass round-trip across every supported even/odd length" {
    const key: [16]u8 = @splat(0x55);
    const sid_full: [10]u8 = .{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa };
    const nonce_full: [18]u8 = @splat(0xbb);

    var combined: usize = 5;
    while (combined <= 19) : (combined += 1) {
        if (combined == 16) continue; // single-pass; deferred
        const sid_len: u8 = @intCast(@max(1, @min(combined - 4, sid_full.len)));
        const nonce_len: u8 = @intCast(combined - @as(usize, sid_len));

        const cfg: LbConfig = .{
            .config_id = 1,
            .server_id = try ServerId.fromSlice(sid_full[0..sid_len]),
            .nonce_len = nonce_len,
            .key = key,
        };
        var f = try cid_mod.Factory.init(cfg);
        defer f.deinit();

        var cid: [20]u8 = undefined;
        const n = try f.mintWithNonce(&cid, nonce_full[0..nonce_len]);
        const decoded = try decode(cid[0..n], cfg);
        try testing.expectEqualSlices(u8, sid_full[0..sid_len], decoded.server_id.slice());
        try testing.expectEqualSlices(u8, nonce_full[0..nonce_len], decoded.nonceSlice());
    }
}

test "decode: single-pass round-trip recovers server_id and nonce" {
    // §5.5.1 inverts §5.4.1: with the same key, AES-128-ECB-decrypt
    // the 16-byte body and read out `server_id || nonce`. Stable
    // across every (sid_len, nonce_len) split that sums to 16.
    const sid_bytes: []const u8 = &.{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const nonce_bytes: []const u8 = &.{ 9, 10, 11, 12, 13, 14, 15, 16 };
    const cfg: LbConfig = .{
        .config_id = 2,
        .server_id = try ServerId.fromSlice(sid_bytes),
        .nonce_len = @intCast(nonce_bytes.len),
        .key = @splat(0x42),
    };
    var f = try cid_mod.Factory.init(cfg);
    defer f.deinit();

    var cid: [17]u8 = undefined;
    const n = try f.mintWithNonce(&cid, nonce_bytes);
    const decoded = try decode(cid[0..n], cfg);
    try testing.expectEqualSlices(u8, sid_bytes, decoded.server_id.slice());
    try testing.expectEqualSlices(u8, nonce_bytes, decoded.nonceSlice());
}

test "decode: single-pass KAT against draft Appendix B.2 vector #2" {
    // Encode side already locks this in; here we verify the inverse
    // recovers the original server_id and nonce byte-for-byte from
    // the on-wire CID.
    const key: [16]u8 = .{
        0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
        0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
    };
    const sid_bytes: [8]u8 = .{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f };
    const nonce_bytes: [8]u8 = .{ 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5 };
    const on_wire: [17]u8 = .{
        0x50, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2,
        0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c, 0xc3,
    };

    const cfg: LbConfig = .{
        .config_id = 2,
        .server_id = try ServerId.fromSlice(&sid_bytes),
        .nonce_len = 8,
        .key = key,
    };
    const decoded = try decode(&on_wire, cfg);
    try testing.expectEqual(@as(u8, 2), decoded.config_id);
    try testing.expectEqualSlices(u8, &sid_bytes, decoded.server_id.slice());
    try testing.expectEqualSlices(u8, &nonce_bytes, decoded.nonceSlice());
}

test "decode: returns UnroutableCid for first-octet config_id 0b111" {
    var unroutable: [12]u8 = undefined;
    _ = try cid_mod.mintUnroutable(&unroutable, 12);

    // Use any plaintext config; the unroutable check fires before
    // the body is consulted.
    const cfg: LbConfig = .{
        .config_id = 0,
        .server_id = try ServerId.fromSlice(&.{ 1, 2, 3 }),
        .nonce_len = 8,
    };
    try testing.expectError(Error.UnroutableCid, decode(&unroutable, cfg));
}

test "decode: rejects too-short input" {
    const cfg: LbConfig = .{
        .config_id = 0,
        .server_id = try ServerId.fromSlice(&.{ 1, 2 }),
        .nonce_len = 6, // cidLength = 9
    };
    var short: [4]u8 = .{ 0, 0, 0, 0 };
    try testing.expectError(Error.CidTooShort, decode(&short, cfg));
}
