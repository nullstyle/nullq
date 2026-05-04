//! End-to-end seal/open for 1-RTT short-header packets
//! (RFC 9000 §17.3 + RFC 9001 §5).
//!
//! `seal1Rtt` takes a per-direction key set and a frame payload,
//! builds the short header, AEAD-encrypts the payload, applies
//! header protection, and writes the protected datagram into a
//! caller-provided buffer.
//!
//! `open1Rtt` is the receiver's reverse: remove header protection
//! into a small AAD copy, reconstruct the truncated packet number,
//! AEAD-decrypt the payload, and return the frame bytes, full PN,
//! and key phase.
//!
//! Cipher-suite coverage: TLS_AES_128_GCM_SHA256 only. AES-256
//! and ChaCha20-Poly1305 land alongside the matching boringssl
//! primitives (the 256-bit AES single-block isn't wrapped yet,
//! and `crypto.chacha20.quicHpMask` exists but the AEAD adapter
//! doesn't).

const std = @import("std");
const boringssl = @import("boringssl");

const header = @import("header.zig");
const packet_number_mod = @import("packet_number.zig");
const protection = @import("protection.zig");
const initial_mod = @import("initial.zig");

const AesGcm128 = boringssl.crypto.aead.AesGcm128;

/// TLS 1.3 cipher suite (the only suites legal in QUIC v1).
pub const Suite = enum {
    aes128_gcm_sha256,
    // future: aes256_gcm_sha384, chacha20_poly1305_sha256

    /// Protocol ID per IANA TLS Cipher Suite registry. Used to
    /// translate from BoringSSL's `SSL_CIPHER_get_protocol_id`.
    pub fn fromProtocolId(id: u16) ?Suite {
        return switch (id) {
            0x1301 => .aes128_gcm_sha256,
            else => null,
        };
    }

    pub fn keyLen(self: Suite) u8 {
        return switch (self) {
            .aes128_gcm_sha256 => 16,
        };
    }

    pub fn ivLen(self: Suite) u8 {
        _ = self;
        return 12;
    }

    pub fn hpLen(self: Suite) u8 {
        return switch (self) {
            .aes128_gcm_sha256 => 16,
        };
    }

    pub fn secretLen(self: Suite) u8 {
        return switch (self) {
            .aes128_gcm_sha256 => 32,
        };
    }
};

/// Per-direction packet protection keys — derived from a TLS
/// secret and a suite. The lengths used inside the fixed-size
/// arrays are bounded by `suite.{key,iv,hp}Len()`.
pub const PacketKeys = struct {
    suite: Suite,
    key: [32]u8 = @splat(0),
    iv: [12]u8 = @splat(0),
    hp: [32]u8 = @splat(0),

    pub fn keySlice(self: *const PacketKeys) []const u8 {
        return self.key[0..self.suite.keyLen()];
    }
    pub fn ivSlice(self: *const PacketKeys) *const [12]u8 {
        return &self.iv;
    }
    pub fn hpSlice(self: *const PacketKeys) []const u8 {
        return self.hp[0..self.suite.hpLen()];
    }
};

pub const Error = error{
    /// `secret.len` doesn't match `suite.secretLen()`.
    SecretWrongLength,
    /// Output buffer too small for the protected packet.
    OutputTooSmall,
    /// Input bytes can't be a 1-RTT packet — first bit set, or
    /// truncated.
    NotShortHeader,
    /// Caller passed a DCID length larger than QUIC v1 permits.
    DcidTooLong,
} || protection.Error || header.Error || packet_number_mod.Error || initial_mod.Error;

/// Derive AEAD/IV/HP material from a per-direction TLS secret.
/// QUIC v1 (RFC 9001 §5) uses HKDF-Expand-Label "quic key",
/// "quic iv", and "quic hp" with empty context.
pub fn derivePacketKeys(suite: Suite, secret: []const u8) Error!PacketKeys {
    if (secret.len != suite.secretLen()) return Error.SecretWrongLength;
    var keys: PacketKeys = .{ .suite = suite };
    try initial_mod.hkdfExpandLabel(
        keys.key[0..suite.keyLen()],
        secret,
        "quic key",
        "",
    );
    try initial_mod.hkdfExpandLabel(&keys.iv, secret, "quic iv", "");
    try initial_mod.hkdfExpandLabel(
        keys.hp[0..suite.hpLen()],
        secret,
        "quic hp",
        "",
    );
    return keys;
}

/// Derive the next 1-RTT application traffic secret for a QUIC key
/// update (RFC 9001 §6). Header-protection keys are intentionally
/// not updated; callers that turn the returned secret into
/// `PacketKeys` must retain the previous `hp` value.
pub fn deriveNextTrafficSecret(suite: Suite, secret: []const u8) Error![32]u8 {
    if (secret.len != suite.secretLen()) return Error.SecretWrongLength;
    var next: [32]u8 = @splat(0);
    try initial_mod.hkdfExpandLabel(next[0..suite.secretLen()], secret, "quic ku", "");
    return next;
}

/// Choose a packet-number length per RFC 9000 §17.1: enough bits to
/// carry `pn - largest_acked` unambiguously. With no prior ACK, use 4.
fn chooseShortPnLength(pn: u64, largest_acked: ?u64) u8 {
    const space: u64 = if (largest_acked) |la|
        (if (pn > la) pn - la else 1)
    else
        std.math.maxInt(u64);
    if (space < (1 << 7)) return 1;
    if (space < (1 << 15)) return 2;
    if (space < (1 << 23)) return 3;
    return 4;
}

pub const SealOptions = struct {
    /// Destination connection ID (the peer's CID — what they expect
    /// to see on the wire).
    dcid: []const u8,
    /// Full 64-bit packet number to encode.
    pn: u64,
    /// Largest PN we've seen ACKed in this PN space; used to choose
    /// PN truncation length. `null` means we have no prior ACK.
    largest_acked: ?u64 = null,
    /// Frame bytes to encrypt.
    payload: []const u8,
    keys: *const PacketKeys,
    /// Force a specific PN length (1..4). Must accommodate `pn`.
    pn_length_override: ?u8 = null,
    /// Spin / key_phase bits — Phase 5 always uses 0.
    spin_bit: bool = false,
    key_phase: bool = false,
    /// When set, use draft-ietf-quic-multipath-21 §2.4's
    /// path-ID-aware nonce for 1-RTT packet protection.
    multipath_path_id: ?u32 = null,
};

/// Build a fully-protected 1-RTT packet into `dst`. Returns the
/// total bytes written. RFC 9001 §5.4.2 requires the post-PN
/// ciphertext to be at least 4 bytes long so that the HP sample
/// always lies in the ciphertext; if the caller's payload is too
/// short to satisfy that, this routine appends PADDING frames
/// (0x00 bytes) inside the AEAD-protected payload.
pub fn seal1Rtt(dst: []u8, opts: SealOptions) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.keys.suite != .aes128_gcm_sha256) return error.UnsupportedSuite;
    const pn_len = opts.pn_length_override orelse chooseShortPnLength(opts.pn, opts.largest_acked);
    if (pn_len < 1 or pn_len > 4) return protection.Error.InvalidPnLength;

    // Minimum plaintext length so HP sample (16 bytes starting at
    // pn_offset + 4) lands in ciphertext.  pt_len + tag(16) must be
    // >= 4 + (4 - pn_len) = 8 - pn_len. So pt_len >= 4 - pn_len.
    const min_pt: usize = if (pn_len < 4) @as(usize, 4 - pn_len) else 0;
    const pt_len: usize = @max(opts.payload.len, min_pt);

    const total_required = 1 + opts.dcid.len + pn_len + pt_len + 16;
    if (dst.len < total_required) return Error.OutputTooSmall;

    // Encode unprotected header.
    const conn_id = try header.ConnId.fromSlice(opts.dcid);
    const pn_length: header.PnLength = switch (pn_len) {
        1 => .one,
        2 => .two,
        3 => .three,
        4 => .four,
        else => unreachable,
    };
    const truncated = packetNumberTruncated(opts.pn, pn_len);
    const hdr_len = try header.encode(dst, .{ .one_rtt = .{
        .dcid = conn_id,
        .spin_bit = opts.spin_bit,
        .reserved_bits = 0,
        .key_phase = opts.key_phase,
        .pn_length = pn_length,
        .pn_truncated = truncated,
    } });

    // AEAD-seal the payload immediately after the header.
    var aead = try AesGcm128.init(opts.keys.key[0..16]);
    defer aead.deinit();

    // Stage the plaintext if we need to pad. Common case (no padding)
    // hands the caller's slice straight through.
    var pad_buf: [4]u8 = @splat(0);
    var staged_buf: [4]u8 = undefined;
    const pt_slice: []const u8 = if (pt_len == opts.payload.len)
        opts.payload
    else blk: {
        std.debug.assert(pt_len <= staged_buf.len);
        @memcpy(staged_buf[0..opts.payload.len], opts.payload);
        const pad_n = pt_len - opts.payload.len;
        @memcpy(staged_buf[opts.payload.len..pt_len], pad_buf[0..pad_n]);
        break :blk staged_buf[0..pt_len];
    };

    const ct_len = if (opts.multipath_path_id) |path_id|
        try protection.aeadSealForPath(
            &aead,
            &opts.keys.iv,
            path_id,
            opts.pn,
            dst[0..hdr_len],
            pt_slice,
            dst[hdr_len..],
        )
    else
        try protection.aeadSeal(
            &aead,
            &opts.keys.iv,
            opts.pn,
            dst[0..hdr_len],
            pt_slice,
            dst[hdr_len..],
        );

    // Header-protect.
    const total_len = hdr_len + ct_len;
    const pn_offset = hdr_len - pn_len;
    const sample = try protection.sampleAt(dst[0..total_len], pn_offset);
    const hp_key: *const [16]u8 = @ptrCast(opts.keys.hp[0..16]);
    const mask = protection.aesHpMask(hp_key, &sample);
    try protection.applyHpMask(dst[0..total_len], .short, pn_offset, pn_len, mask);

    return total_len;
}

pub const Open1RttResult = struct {
    /// Reconstructed full 64-bit packet number.
    pn: u64,
    /// Unprotected short-header key phase bit.
    key_phase: bool,
    /// Slice of the receiver's plaintext output buffer holding the
    /// decrypted frames.
    payload: []u8,
};

/// Inputs to `open1Rtt`. The protected packet bytes in `src` are
/// left untouched; the unmasked short header is staged into a small
/// AAD buffer for AEAD open. Plaintext is written into `pt_dst`.
pub const OpenOptions = struct {
    /// Locally-issued DCID length — both endpoints know it because
    /// we issued the CID.
    dcid_len: u8,
    keys: *const PacketKeys,
    /// Highest PN we've ever decoded in this PN space (for
    /// truncated-PN reconstruction). 0 if none.
    largest_received: u64 = 0,
    /// When set, use draft-ietf-quic-multipath-21 §2.4's
    /// path-ID-aware nonce for 1-RTT packet protection.
    multipath_path_id: ?u32 = null,
};

pub fn open1Rtt(pt_dst: []u8, src: []u8, opts: OpenOptions) Error!Open1RttResult {
    if (src.len < 1) return Error.NotShortHeader;
    if (src[0] & 0x80 != 0) return Error.NotShortHeader;
    if (opts.dcid_len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.keys.suite != .aes128_gcm_sha256) return error.UnsupportedSuite;

    // The PN immediately follows the DCID. We don't yet know its
    // length — that's gated by HP. Use the worst-case PN-end (PN
    // offset + 4) for sample extraction per RFC 9001 §5.4.2.
    const pn_offset: usize = 1 + @as(usize, opts.dcid_len);
    if (src.len < pn_offset + 4 + protection.sample_len) return Error.InsufficientCiphertext;

    const sample = try protection.sampleAt(src, pn_offset);
    const hp_key: *const [16]u8 = @ptrCast(opts.keys.hp[0..16]);
    const mask = protection.aesHpMask(hp_key, &sample);

    // Strip HP into local copies. The source datagram stays intact
    // so callers can retry with updated packet-protection keys.
    const first = src[0] ^ (mask[0] & 0x1f);
    const key_phase = (first & 0x04) != 0;
    const pn_len: u8 = @intCast((first & 0x03) + 1);
    var pn_bytes: [4]u8 = undefined;
    var i: u8 = 0;
    while (i < pn_len) : (i += 1) {
        pn_bytes[i] = src[pn_offset + i] ^ mask[1 + i];
    }

    // Reconstruct PN from truncated bytes.
    const truncated = try packet_number_mod.readTruncated(&pn_bytes, pn_len);
    const full_pn = try packet_number_mod.decode(truncated, pn_len, opts.largest_received);

    // AEAD-open: AAD is now-unmasked header bytes [0, pn_offset+pn_len);
    // ciphertext is everything after.
    var aead = try AesGcm128.init(opts.keys.key[0..16]);
    defer aead.deinit();

    const hdr_len = pn_offset + pn_len;
    var aad_buf: [1 + header.max_cid_len + 4]u8 = undefined;
    aad_buf[0] = first;
    @memcpy(aad_buf[1..pn_offset], src[1..pn_offset]);
    @memcpy(aad_buf[pn_offset..hdr_len], pn_bytes[0..pn_len]);
    const pt_len = if (opts.multipath_path_id) |path_id|
        try protection.aeadOpenForPath(
            &aead,
            &opts.keys.iv,
            path_id,
            full_pn,
            aad_buf[0..hdr_len],
            src[hdr_len..],
            pt_dst,
        )
    else
        try protection.aeadOpen(
            &aead,
            &opts.keys.iv,
            full_pn,
            aad_buf[0..hdr_len],
            src[hdr_len..],
            pt_dst,
        );

    return .{ .pn = full_pn, .key_phase = key_phase, .payload = pt_dst[0..pt_len] };
}

fn packetNumberTruncated(pn: u64, pn_len: u8) u64 {
    if (pn_len >= 8) return pn;
    const shift: u6 = @intCast(@as(u32, pn_len) * 8);
    const mask: u64 = (@as(u64, 1) << shift) - 1;
    return pn & mask;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "derivePacketKeys: matches initial.zig output for AES-128-GCM-SHA256" {
    // Derive Initial keys via initial.zig, then derive packet keys
    // from the same secret via this module, and check that the
    // key/iv/hp triple matches.
    const dcid = fromHex("8394c8f03e515708");
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);

    const got = try derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    try testing.expectEqualSlices(u8, &init_keys.key, got.keySlice());
    try testing.expectEqualSlices(u8, &init_keys.iv, &got.iv);
    try testing.expectEqualSlices(u8, &init_keys.hp, got.hpSlice());
}

test "derivePacketKeys rejects mis-sized secrets" {
    const tiny = [_]u8{0} ** 16;
    try testing.expectError(
        Error.SecretWrongLength,
        derivePacketKeys(.aes128_gcm_sha256, &tiny),
    );
}

test "chooseShortPnLength: with no largest_acked, uses 4 bytes" {
    try testing.expectEqual(@as(u8, 4), chooseShortPnLength(0, null));
    try testing.expectEqual(@as(u8, 4), chooseShortPnLength(1_000_000, null));
}

test "chooseShortPnLength: scales with delta" {
    try testing.expectEqual(@as(u8, 1), chooseShortPnLength(50, 0));
    try testing.expectEqual(@as(u8, 1), chooseShortPnLength(127, 0));
    try testing.expectEqual(@as(u8, 2), chooseShortPnLength(128, 0));
    try testing.expectEqual(@as(u8, 2), chooseShortPnLength(32_767, 0));
    try testing.expectEqual(@as(u8, 3), chooseShortPnLength(32_768, 0));
    try testing.expectEqual(@as(u8, 4), chooseShortPnLength(8_388_608, 0));
}

test "seal1Rtt + open1Rtt round-trip" {
    const secret = fromHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    );
    const keys = try derivePacketKeys(.aes128_gcm_sha256, &secret);
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const payload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 52 bytes
    var packet: [256]u8 = undefined;

    const len = try seal1Rtt(&packet, .{
        .dcid = &dcid,
        .pn = 42,
        .largest_acked = 10,
        .payload = payload,
        .keys = &keys,
    });
    try testing.expect(len > 1 + 8 + payload.len);
    const protected = packet;

    var pt_buf: [256]u8 = undefined;
    const opened = try open1Rtt(&pt_buf, packet[0..len], .{
        .dcid_len = 8,
        .keys = &keys,
        .largest_received = 41,
    });
    try testing.expectEqual(@as(u64, 42), opened.pn);
    try testing.expectEqual(false, opened.key_phase);
    try testing.expectEqualSlices(u8, payload, opened.payload);
    try testing.expectEqualSlices(u8, protected[0..len], packet[0..len]);
}

test "seal1Rtt + open1Rtt use draft-21 path id in multipath nonce" {
    const secret = fromHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    );
    const keys = try derivePacketKeys(.aes128_gcm_sha256, &secret);
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const payload = "path-id-bound 1-RTT bytes";
    var packet: [256]u8 = undefined;

    const len = try seal1Rtt(&packet, .{
        .dcid = &dcid,
        .pn = 42,
        .largest_acked = 10,
        .payload = payload,
        .keys = &keys,
        .multipath_path_id = 3,
    });

    var pt_buf: [256]u8 = undefined;
    try testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        open1Rtt(&pt_buf, packet[0..len], .{
            .dcid_len = dcid.len,
            .keys = &keys,
            .largest_received = 41,
        }),
    );
    try testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        open1Rtt(&pt_buf, packet[0..len], .{
            .dcid_len = dcid.len,
            .keys = &keys,
            .largest_received = 41,
            .multipath_path_id = 4,
        }),
    );
    const opened = try open1Rtt(&pt_buf, packet[0..len], .{
        .dcid_len = dcid.len,
        .keys = &keys,
        .largest_received = 41,
        .multipath_path_id = 3,
    });
    try testing.expectEqual(@as(u64, 42), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload);
}

test "seal1Rtt: tampered ciphertext fails AEAD on open" {
    const secret = fromHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    );
    const keys = try derivePacketKeys(.aes128_gcm_sha256, &secret);
    const dcid: [4]u8 = .{ 9, 9, 9, 9 };
    const payload = "frame bytes here";
    var packet: [128]u8 = undefined;

    const len = try seal1Rtt(&packet, .{
        .dcid = &dcid,
        .pn = 7,
        .payload = payload,
        .keys = &keys,
    });
    // Flip a bit in the ciphertext (after the header).
    const ct_byte = 1 + dcid.len + 4; // first ct byte after worst-case PN
    packet[ct_byte] ^= 0x01;

    var pt: [128]u8 = undefined;
    try testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        open1Rtt(&pt, packet[0..len], .{
            .dcid_len = 4,
            .keys = &keys,
            .largest_received = 6,
        }),
    );
}

test "1-RTT key update opens with next traffic secret and stable HP" {
    const secret = fromHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    );
    const keys = try derivePacketKeys(.aes128_gcm_sha256, &secret);
    const next_secret = try deriveNextTrafficSecret(.aes128_gcm_sha256, &secret);
    var next_keys = try derivePacketKeys(.aes128_gcm_sha256, &next_secret);
    next_keys.hp = keys.hp;

    const dcid: [8]u8 = .{ 1, 3, 5, 7, 9, 11, 13, 15 };
    const payload = "post-update stream frame bytes";
    var packet: [256]u8 = undefined;
    const len = try seal1Rtt(&packet, .{
        .dcid = &dcid,
        .pn = 101,
        .largest_acked = 100,
        .payload = payload,
        .keys = &next_keys,
        .key_phase = true,
    });

    var pt: [256]u8 = undefined;
    try testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        open1Rtt(&pt, packet[0..len], .{
            .dcid_len = dcid.len,
            .keys = &keys,
            .largest_received = 100,
        }),
    );

    const opened = try open1Rtt(&pt, packet[0..len], .{
        .dcid_len = dcid.len,
        .keys = &next_keys,
        .largest_received = 100,
    });
    try testing.expectEqual(@as(u64, 101), opened.pn);
    try testing.expectEqual(true, opened.key_phase);
    try testing.expectEqualSlices(u8, payload, opened.payload);
}

test "seal1Rtt: PN length follows largest_acked" {
    const secret = fromHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    );
    const keys = try derivePacketKeys(.aes128_gcm_sha256, &secret);
    const dcid: [4]u8 = .{ 0, 0, 0, 0 };
    const payload = "x";
    var packet: [128]u8 = undefined;

    // PN 100 with largest_acked = 99 → 1-byte PN. RFC 9001 §5.4.2
    // requires a minimum of 4 - pn_len = 3 plaintext bytes so the
    // HP sample lands in ciphertext.
    const len1 = try seal1Rtt(&packet, .{
        .dcid = &dcid,
        .pn = 100,
        .largest_acked = 99,
        .payload = payload,
        .keys = &keys,
    });
    try testing.expectEqual(@as(usize, 1 + 4 + 1 + 3 + 16), len1);

    // PN 100 with no prior ACK → 4-byte PN; no padding needed.
    const len4 = try seal1Rtt(&packet, .{
        .dcid = &dcid,
        .pn = 100,
        .payload = payload,
        .keys = &keys,
    });
    try testing.expectEqual(@as(usize, 1 + 4 + 4 + 1 + 16), len4);
}

test "open1Rtt rejects long-header bytes" {
    const secret = fromHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    );
    const keys = try derivePacketKeys(.aes128_gcm_sha256, &secret);
    var bytes = [_]u8{0xc1} ++ [_]u8{0} ** 31; // first byte 0xc1 → long header
    var pt: [64]u8 = undefined;
    try testing.expectError(
        Error.NotShortHeader,
        open1Rtt(&pt, &bytes, .{
            .dcid_len = 0,
            .keys = &keys,
            .largest_received = 0,
        }),
    );
}

test "round-trip across many PNs and payload sizes" {
    const secret = fromHex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    );
    const keys = try derivePacketKeys(.aes128_gcm_sha256, &secret);
    const dcid: [12]u8 = .{ 0xa, 0xb, 0xc, 0xd, 1, 2, 3, 4, 5, 6, 7, 8 };

    var packet: [2048]u8 = undefined;
    var pt: [2048]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x12345678);

    var pn: u64 = 0;
    while (pn < 256) : (pn += 1) {
        var buf: [1500]u8 = undefined;
        const len: usize = @intCast(prng.random().intRangeAtMost(u32, 1, 1400));
        prng.random().bytes(buf[0..len]);

        const sealed = try seal1Rtt(&packet, .{
            .dcid = &dcid,
            .pn = pn,
            .largest_acked = if (pn == 0) null else pn - 1,
            .payload = buf[0..len],
            .keys = &keys,
        });
        const opened = try open1Rtt(&pt, packet[0..sealed], .{
            .dcid_len = 12,
            .keys = &keys,
            .largest_received = if (pn == 0) 0 else pn - 1,
        });
        try testing.expectEqual(pn, opened.pn);
        try testing.expectEqualSlices(u8, buf[0..len], opened.payload);
    }
}
