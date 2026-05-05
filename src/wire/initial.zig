//! QUIC Initial keys derivation (RFC 9001 §5.2).
//!
//! Initial packets are protected with keys deterministically derived
//! from the client's first Destination Connection ID and a
//! version-keyed salt. Both client and server can derive the same
//! keys without negotiation — that's how the very first ClientHello
//! gets encrypted.
//!
//! This is the first crypto-aware module in `wire/`; everything else
//! in this directory is pure-Zig wire-format code. We sit on top of
//! `boringssl.crypto.kdf.HkdfSha256`. The TLS 1.3 HKDF label helper
//! is also reused by Handshake/Application packet protection, where
//! the negotiated TLS cipher suite can select SHA-384.

const std = @import("std");
const boringssl = @import("boringssl");

const HkdfSha256 = boringssl.crypto.kdf.HkdfSha256;
const HkdfSha384 = boringssl.crypto.kdf.HkdfSha384;

/// HKDF hash function used by `hkdfExpandLabelWithHash`. Initial keys
/// always use SHA-256; negotiated TLS 1.3 cipher suites can require
/// SHA-384 for Handshake/Application key derivation.
pub const HkdfHash = enum {
    sha256,
    sha384,
};

/// QUIC v1 Initial Salt (RFC 9001 §5.2).
pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

/// Per-direction Initial keys.
pub const Keys = struct {
    /// {client,server}_initial_secret — the per-direction PRK from
    /// which key, iv, and hp are derived. Useful for debugging and
    /// for key updates (which Initial doesn't actually do, but the
    /// same struct shape will be reused for Handshake/Application).
    secret: [32]u8,
    /// AEAD key for AES-128-GCM packet protection.
    key: [16]u8,
    /// AEAD IV; the nonce per packet is iv XOR pn.
    iv: [12]u8,
    /// Header-protection key (AES-128 single-block input).
    hp: [16]u8,
};

/// Errors returned by HKDF-Expand-Label.
pub const Error = error{
    LabelTooLong,
    ContextTooLong,
    OutputTooLong,
};

/// HKDF-Expand-Label per RFC 8446 §7.1, with the TLS 1.3 prefix
/// `"tls13 "` baked in. Writes `dst.len` bytes into `dst`.
///
/// QUIC Initial uses this with `secret` of SHA-256 digest length,
/// `context` of zero length, and `dst.len` in {12, 16, 32}; negotiated
/// packet protection can also request 32-byte keys and 48-byte SHA-384
/// traffic secrets through `hkdfExpandLabelWithHash`.
pub fn hkdfExpandLabel(
    dst: []u8,
    secret: []const u8,
    label: []const u8,
    context: []const u8,
) Error!void {
    return hkdfExpandLabelWithHash(.sha256, dst, secret, label, context);
}

/// HKDF-Expand-Label with an explicit TLS 1.3 hash. QUIC Initial keys
/// always use SHA-256; Handshake/Application keys follow the negotiated
/// TLS cipher suite.
pub fn hkdfExpandLabelWithHash(
    hash: HkdfHash,
    dst: []u8,
    secret: []const u8,
    label: []const u8,
    context: []const u8,
) Error!void {
    const tls13_prefix = "tls13 ";
    const full_label_len = tls13_prefix.len + label.len;
    if (full_label_len > 255) return Error.LabelTooLong;
    if (context.len > 255) return Error.ContextTooLong;
    if (dst.len > std.math.maxInt(u16)) return Error.OutputTooLong;

    // HkdfLabel (RFC 8446 §7.1):
    //   uint16 length = Length;
    //   opaque label<7..255> = "tls13 " + Label;
    //   opaque context<0..255> = Context;
    //
    // Max info size: 2 + 1 + 255 + 1 + 255 = 514 bytes. Plenty of stack.
    var info_buf: [514]u8 = undefined;
    var pos: usize = 0;
    info_buf[pos] = @intCast(dst.len >> 8);
    pos += 1;
    info_buf[pos] = @intCast(dst.len & 0xff);
    pos += 1;
    info_buf[pos] = @intCast(full_label_len);
    pos += 1;
    @memcpy(info_buf[pos .. pos + tls13_prefix.len], tls13_prefix);
    pos += tls13_prefix.len;
    @memcpy(info_buf[pos .. pos + label.len], label);
    pos += label.len;
    info_buf[pos] = @intCast(context.len);
    pos += 1;
    @memcpy(info_buf[pos .. pos + context.len], context);
    pos += context.len;

    switch (hash) {
        .sha256 => HkdfSha256.expand(secret, info_buf[0..pos], dst),
        .sha384 => HkdfSha384.expand(secret, info_buf[0..pos], dst),
    }
}

/// Derive a full set of Initial keys for a given role.
///
/// `dcid` is the Destination Connection ID from the client's first
/// Initial packet — both endpoints use the same DCID as IKM (RFC 9001
/// §5.2). `is_server = false` produces client-side keys; `true`
/// produces server-side keys.
pub fn deriveInitialKeys(dcid: []const u8, is_server: bool) Error!Keys {
    const initial_secret = HkdfSha256.extract(&initial_salt_v1, dcid);

    var keys: Keys = undefined;
    const role_label: []const u8 = if (is_server) "server in" else "client in";
    try hkdfExpandLabel(&keys.secret, &initial_secret, role_label, "");
    try hkdfExpandLabel(&keys.key, &keys.secret, "quic key", "");
    try hkdfExpandLabel(&keys.iv, &keys.secret, "quic iv", "");
    try hkdfExpandLabel(&keys.hp, &keys.secret, "quic hp", "");
    return keys;
}

// -- tests ---------------------------------------------------------------

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 9001 §A.1 — client Initial keys" {
    // From RFC 9001 §A.1: the canonical example uses
    //   DCID = 0x8394c8f03e515708
    const dcid = fromHex("8394c8f03e515708");

    const got = try deriveInitialKeys(&dcid, false);

    try std.testing.expectEqualSlices(
        u8,
        &fromHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
        &got.secret,
    );
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("1f369613dd76d5467730efcbe3b1a22d"),
        &got.key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("fa044b2f42a3fd3b46fb255c"),
        &got.iv,
    );
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("9f50449e04a0e810283a1e9933adedd2"),
        &got.hp,
    );
}

test "RFC 9001 §A.1 — server Initial keys" {
    const dcid = fromHex("8394c8f03e515708");

    const got = try deriveInitialKeys(&dcid, true);

    try std.testing.expectEqualSlices(
        u8,
        &fromHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
        &got.secret,
    );
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("cf3a5331653c364c88f0f379b6067e37"),
        &got.key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("0ac1493ca1905853b0bba03e"),
        &got.iv,
    );
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("c206b8d9b9f0f37644430b490eeaa314"),
        &got.hp,
    );
}

test "hkdfExpandLabel matches the same shape boringssl-zig already KATs" {
    // Spot-check via the canonical client_initial_secret derivation
    // (boringssl-zig's QUIC v1 initial_secret KAT covers the extract
    // step; we cover the full chain in the §A.1 tests above).
    const dcid = fromHex("8394c8f03e515708");
    const initial_secret = HkdfSha256.extract(&initial_salt_v1, &dcid);

    var client_secret: [32]u8 = undefined;
    try hkdfExpandLabel(&client_secret, &initial_secret, "client in", "");
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
        &client_secret,
    );
}

test "hkdfExpandLabel rejects oversized label" {
    var dst: [16]u8 = undefined;
    const secret: [32]u8 = @splat(0);
    var huge_label: [250]u8 = @splat(0x41); // 250 + 6 ("tls13 ") > 255
    try std.testing.expectError(
        Error.LabelTooLong,
        hkdfExpandLabel(&dst, &secret, &huge_label, ""),
    );
}
