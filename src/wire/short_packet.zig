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
//! Cipher-suite coverage: the QUIC v1 TLS 1.3 suites
//! TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and
//! TLS_CHACHA20_POLY1305_SHA256.

const std = @import("std");
const boringssl = @import("boringssl");

const header = @import("header.zig");
const packet_number_mod = @import("packet_number.zig");
const protection = @import("protection.zig");
const initial_mod = @import("initial.zig");

const AesGcm128 = boringssl.crypto.aead.AesGcm128;
const AesGcm256 = boringssl.crypto.aead.AesGcm256;
const ChaCha20Poly1305 = boringssl.crypto.aead.ChaCha20Poly1305;

/// TLS 1.3 cipher suite (the only suites legal in QUIC v1).
pub const Suite = enum {
    aes128_gcm_sha256,
    aes256_gcm_sha384,
    chacha20_poly1305_sha256,

    /// Protocol ID per IANA TLS Cipher Suite registry. Used to
    /// translate from BoringSSL's `SSL_CIPHER_get_protocol_id`.
    pub fn fromProtocolId(id: u16) ?Suite {
        return switch (id) {
            0x1301 => .aes128_gcm_sha256,
            0x1302 => .aes256_gcm_sha384,
            0x1303 => .chacha20_poly1305_sha256,
            else => null,
        };
    }

    /// AEAD key length in bytes for this suite.
    pub fn keyLen(self: Suite) u8 {
        return switch (self) {
            .aes128_gcm_sha256 => 16,
            .aes256_gcm_sha384,
            .chacha20_poly1305_sha256,
            => 32,
        };
    }

    /// IV length in bytes for this suite. Always 12 in QUIC v1.
    pub fn ivLen(self: Suite) u8 {
        _ = self;
        return 12;
    }

    /// Header-protection key length in bytes for this suite.
    pub fn hpLen(self: Suite) u8 {
        return switch (self) {
            .aes128_gcm_sha256 => 16,
            .aes256_gcm_sha384,
            .chacha20_poly1305_sha256,
            => 32,
        };
    }

    /// TLS 1.3 traffic-secret length in bytes for this suite (matches
    /// the suite's HKDF hash digest length).
    pub fn secretLen(self: Suite) u8 {
        return switch (self) {
            .aes128_gcm_sha256 => 32,
            .aes256_gcm_sha384 => 48,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    /// HKDF hash function for this suite, suitable for
    /// `initial.hkdfExpandLabelWithHash`.
    pub fn hkdfHash(self: Suite) initial_mod.HkdfHash {
        return switch (self) {
            .aes128_gcm_sha256,
            .chacha20_poly1305_sha256,
            => .sha256,
            .aes256_gcm_sha384 => .sha384,
        };
    }
};

/// Largest traffic-secret length across QUIC v1 suites (SHA-384 = 48
/// bytes; rounded up to 64 to keep alignment-friendly).
pub const max_traffic_secret_len: usize = 64;
/// Fixed-size buffer big enough for any QUIC v1 traffic secret. The
/// active prefix length is `Suite.secretLen()`.
pub const TrafficSecret = [max_traffic_secret_len]u8;

/// Per-direction packet protection keys — derived from a TLS
/// secret and a suite. The lengths used inside the fixed-size
/// arrays are bounded by `suite.{key,iv,hp}Len()`.
pub const PacketKeys = struct {
    suite: Suite,
    key: [32]u8 = @splat(0),
    iv: [12]u8 = @splat(0),
    hp: [32]u8 = @splat(0),

    /// Borrow the AEAD key slice trimmed to the suite's `keyLen()`.
    pub fn keySlice(self: *const PacketKeys) []const u8 {
        return self.key[0..self.suite.keyLen()];
    }
    /// Borrow the 12-byte AEAD IV by pointer.
    pub fn ivSlice(self: *const PacketKeys) *const [12]u8 {
        return &self.iv;
    }
    /// Borrow the header-protection key slice trimmed to `hpLen()`.
    pub fn hpSlice(self: *const PacketKeys) []const u8 {
        return self.hp[0..self.suite.hpLen()];
    }
};

/// Errors returned by 1-RTT seal/open and key-derivation routines.
pub const Error = error{
    /// `secret.len` doesn't match `suite.secretLen()`.
    SecretWrongLength,
    UnsupportedSuite,
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
    try initial_mod.hkdfExpandLabelWithHash(
        suite.hkdfHash(),
        keys.key[0..suite.keyLen()],
        secret,
        "quic key",
        "",
    );
    try initial_mod.hkdfExpandLabelWithHash(suite.hkdfHash(), &keys.iv, secret, "quic iv", "");
    try initial_mod.hkdfExpandLabelWithHash(
        suite.hkdfHash(),
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
pub fn deriveNextTrafficSecret(suite: Suite, secret: []const u8) Error!TrafficSecret {
    if (secret.len != suite.secretLen()) return Error.SecretWrongLength;
    var next: TrafficSecret = @splat(0);
    try initial_mod.hkdfExpandLabelWithHash(
        suite.hkdfHash(),
        next[0..suite.secretLen()],
        secret,
        "quic ku",
        "",
    );
    return next;
}

/// Compute the 5-byte header-protection mask using the suite-specific
/// algorithm (RFC 9001 §5.4.3 / §5.4.4).
pub fn headerProtectionMask(keys: *const PacketKeys, sample: *const [protection.sample_len]u8) protection.Error![protection.mask_len]u8 {
    return switch (keys.suite) {
        .aes128_gcm_sha256 => try protection.aesHpMask(@ptrCast(keys.hp[0..16]), sample),
        .aes256_gcm_sha384 => try protection.aes256HpMask(@ptrCast(keys.hp[0..32]), sample),
        .chacha20_poly1305_sha256 => protection.chacha20HpMask(@ptrCast(keys.hp[0..32]), sample),
    };
}

/// AEAD-seal `plaintext` for a packet with `packet_header` as AAD.
/// Selects the AEAD primitive matching `keys.suite`. Writes
/// ciphertext+tag into `dst` and returns total bytes written. When
/// `multipath_path_id` is set, uses the draft-21 path-aware nonce.
pub fn sealPayloadWithKeys(
    keys: *const PacketKeys,
    multipath_path_id: ?u32,
    pn: u64,
    packet_header: []const u8,
    plaintext: []const u8,
    dst: []u8,
) protection.Error!usize {
    return switch (keys.suite) {
        .aes128_gcm_sha256 => blk: {
            var aead = try AesGcm128.init(@ptrCast(keys.key[0..16]));
            defer aead.deinit();
            break :blk try sealPayloadWithAead(&aead, keys, multipath_path_id, pn, packet_header, plaintext, dst);
        },
        .aes256_gcm_sha384 => blk: {
            var aead = try AesGcm256.init(@ptrCast(keys.key[0..32]));
            defer aead.deinit();
            break :blk try sealPayloadWithAead(&aead, keys, multipath_path_id, pn, packet_header, plaintext, dst);
        },
        .chacha20_poly1305_sha256 => blk: {
            var aead = try ChaCha20Poly1305.init(@ptrCast(keys.key[0..32]));
            defer aead.deinit();
            break :blk try sealPayloadWithAead(&aead, keys, multipath_path_id, pn, packet_header, plaintext, dst);
        },
    };
}

fn sealPayloadWithAead(
    aead: anytype,
    keys: *const PacketKeys,
    multipath_path_id: ?u32,
    pn: u64,
    packet_header: []const u8,
    plaintext: []const u8,
    dst: []u8,
) protection.Error!usize {
    return if (multipath_path_id) |path_id|
        try protection.aeadSealForPath(
            aead,
            &keys.iv,
            path_id,
            pn,
            packet_header,
            plaintext,
            dst,
        )
    else
        try protection.aeadSeal(
            aead,
            &keys.iv,
            pn,
            packet_header,
            plaintext,
            dst,
        );
}

/// AEAD-open `ciphertext` (which includes the 16-byte tag) for a
/// packet with `packet_header` as AAD. Reverse of
/// `sealPayloadWithKeys`. Returns plaintext bytes written into `dst`.
pub fn openPayloadWithKeys(
    keys: *const PacketKeys,
    multipath_path_id: ?u32,
    pn: u64,
    packet_header: []const u8,
    ciphertext: []const u8,
    dst: []u8,
) protection.Error!usize {
    return switch (keys.suite) {
        .aes128_gcm_sha256 => blk: {
            var aead = try AesGcm128.init(@ptrCast(keys.key[0..16]));
            defer aead.deinit();
            break :blk try openPayloadWithAead(&aead, keys, multipath_path_id, pn, packet_header, ciphertext, dst);
        },
        .aes256_gcm_sha384 => blk: {
            var aead = try AesGcm256.init(@ptrCast(keys.key[0..32]));
            defer aead.deinit();
            break :blk try openPayloadWithAead(&aead, keys, multipath_path_id, pn, packet_header, ciphertext, dst);
        },
        .chacha20_poly1305_sha256 => blk: {
            var aead = try ChaCha20Poly1305.init(@ptrCast(keys.key[0..32]));
            defer aead.deinit();
            break :blk try openPayloadWithAead(&aead, keys, multipath_path_id, pn, packet_header, ciphertext, dst);
        },
    };
}

fn openPayloadWithAead(
    aead: anytype,
    keys: *const PacketKeys,
    multipath_path_id: ?u32,
    pn: u64,
    packet_header: []const u8,
    ciphertext: []const u8,
    dst: []u8,
) protection.Error!usize {
    return if (multipath_path_id) |path_id|
        try protection.aeadOpenForPath(
            aead,
            &keys.iv,
            path_id,
            pn,
            packet_header,
            ciphertext,
            dst,
        )
    else
        try protection.aeadOpen(
            aead,
            &keys.iv,
            pn,
            packet_header,
            ciphertext,
            dst,
        );
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

/// Inputs to `seal1Rtt`. The DCID is what the peer expects on the
/// wire; the keys carry per-direction AEAD/HP material.
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
        // invariant: line 331 returns InvalidPnLength for any pn_len
        // outside [1, 4]. Not peer-reachable.
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

    const ct_len = try sealPayloadWithKeys(
        opts.keys,
        opts.multipath_path_id,
        opts.pn,
        dst[0..hdr_len],
        pt_slice,
        dst[hdr_len..],
    );

    // Header-protect.
    const total_len = hdr_len + ct_len;
    const pn_offset = hdr_len - pn_len;
    const sample = try protection.sampleAt(dst[0..total_len], pn_offset);
    const mask = try headerProtectionMask(opts.keys, &sample);
    try protection.applyHpMask(dst[0..total_len], .short, pn_offset, pn_len, mask);

    return total_len;
}

/// Result of a successful `open1Rtt`: reconstructed PN, key-phase
/// flag, and plaintext slice within the caller's output buffer.
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

/// Open a protected 1-RTT packet from `src`, writing plaintext into
/// `pt_dst`. `src` is read but not modified — header protection is
/// stripped into a small local AAD copy. Errors with `NotShortHeader`
/// if the first bit indicates a long header.
pub fn open1Rtt(pt_dst: []u8, src: []u8, opts: OpenOptions) Error!Open1RttResult {
    if (src.len < 1) return Error.NotShortHeader;
    if (src[0] & 0x80 != 0) return Error.NotShortHeader;
    if (opts.dcid_len > header.max_cid_len) return Error.DcidTooLong;

    // The PN immediately follows the DCID. We don't yet know its
    // length — that's gated by HP. Use the worst-case PN-end (PN
    // offset + 4) for sample extraction per RFC 9001 §5.4.2.
    const pn_offset: usize = 1 + @as(usize, opts.dcid_len);
    if (src.len < pn_offset + 4 + protection.sample_len) return Error.InsufficientCiphertext;

    const sample = try protection.sampleAt(src, pn_offset);
    const mask = try headerProtectionMask(opts.keys, &sample);

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
    const hdr_len = pn_offset + pn_len;
    var aad_buf: [1 + header.max_cid_len + 4]u8 = undefined;
    aad_buf[0] = first;
    @memcpy(aad_buf[1..pn_offset], src[1..pn_offset]);
    @memcpy(aad_buf[pn_offset..hdr_len], pn_bytes[0..pn_len]);
    const pt_len = try openPayloadWithKeys(
        opts.keys,
        opts.multipath_path_id,
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

fn fillSecret(dst: []u8, seed: u8) void {
    for (dst, 0..) |*b, i| {
        b.* = seed +% @as(u8, @truncate(i));
    }
}

test "Suite metadata covers the QUIC v1 TLS cipher suites" {
    try testing.expectEqual(Suite.aes128_gcm_sha256, Suite.fromProtocolId(0x1301).?);
    try testing.expectEqual(Suite.aes256_gcm_sha384, Suite.fromProtocolId(0x1302).?);
    try testing.expectEqual(Suite.chacha20_poly1305_sha256, Suite.fromProtocolId(0x1303).?);
    try testing.expectEqual(@as(?Suite, null), Suite.fromProtocolId(0x1304));

    try testing.expectEqual(@as(u8, 16), Suite.aes128_gcm_sha256.keyLen());
    try testing.expectEqual(@as(u8, 32), Suite.aes128_gcm_sha256.secretLen());
    try testing.expectEqual(@as(u8, 32), Suite.aes256_gcm_sha384.keyLen());
    try testing.expectEqual(@as(u8, 48), Suite.aes256_gcm_sha384.secretLen());
    try testing.expectEqual(@as(u8, 32), Suite.chacha20_poly1305_sha256.keyLen());
    try testing.expectEqual(@as(u8, 32), Suite.chacha20_poly1305_sha256.secretLen());
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

test "derivePacketKeys and key updates support every QUIC v1 suite" {
    const suites = [_]Suite{
        .aes128_gcm_sha256,
        .aes256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };

    for (suites, 0..) |suite, suite_idx| {
        var secret: TrafficSecret = @splat(0);
        fillSecret(secret[0..suite.secretLen()], @as(u8, @truncate(0x30 + suite_idx * 0x20)));

        const keys = try derivePacketKeys(suite, secret[0..suite.secretLen()]);
        try testing.expectEqual(@as(usize, suite.keyLen()), keys.keySlice().len);
        try testing.expectEqual(@as(usize, 12), keys.ivSlice().len);
        try testing.expectEqual(@as(usize, suite.hpLen()), keys.hpSlice().len);

        const next_secret = try deriveNextTrafficSecret(suite, secret[0..suite.secretLen()]);
        try testing.expect(!std.mem.eql(
            u8,
            secret[0..suite.secretLen()],
            next_secret[0..suite.secretLen()],
        ));
        for (next_secret[suite.secretLen()..]) |b| {
            try testing.expectEqual(@as(u8, 0), b);
        }
    }
}

test "derivePacketKeys rejects mis-sized secrets" {
    const tiny = @as([16]u8, @splat(0));
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

test "seal1Rtt + open1Rtt round-trip across all supported cipher suites" {
    const suites = [_]Suite{
        .aes128_gcm_sha256,
        .aes256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };
    const dcid: [8]u8 = .{ 1, 1, 2, 3, 5, 8, 13, 21 };
    const payload = "suite-flexible 1-RTT STREAM and DATAGRAM-ish frame bytes";

    for (suites, 0..) |suite, suite_idx| {
        var secret: TrafficSecret = @splat(0);
        fillSecret(secret[0..suite.secretLen()], @as(u8, @truncate(0x51 + suite_idx * 0x17)));
        const keys = try derivePacketKeys(suite, secret[0..suite.secretLen()]);

        var packet: [256]u8 = undefined;
        const len = try seal1Rtt(&packet, .{
            .dcid = &dcid,
            .pn = 77,
            .largest_acked = 76,
            .payload = payload,
            .keys = &keys,
        });

        var pt_buf: [256]u8 = undefined;
        const opened = try open1Rtt(&pt_buf, packet[0..len], .{
            .dcid_len = dcid.len,
            .keys = &keys,
            .largest_received = 76,
        });
        try testing.expectEqual(@as(u64, 77), opened.pn);
        try testing.expectEqualSlices(u8, payload, opened.payload);
    }
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
    var next_keys = try derivePacketKeys(.aes128_gcm_sha256, next_secret[0..Suite.aes128_gcm_sha256.secretLen()]);
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
    var bytes = [_]u8{0xc1} ++ @as([31]u8, @splat(0)); // first byte 0xc1 → long header
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
