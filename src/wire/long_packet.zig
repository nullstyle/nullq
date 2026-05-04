//! End-to-end seal/open for long-header QUIC packets — Initial
//! (RFC 9000 §17.2.2) and Handshake (§17.2.4).
//!
//! Long-header packets carry a varint Length field that frames
//! their PN+payload+tag region; this lets multiple long-header
//! packets coalesce into a single UDP datagram (§12.2). The
//! seal/open API here returns `bytes_consumed` so callers can
//! advance through a coalesced datagram one packet at a time.
//!
//! Protection mechanics are identical to short_packet:
//!   - AEAD nonce = static_iv XOR pn (RFC 9001 §5.3).
//!   - Header-protection mask is suite-specific (§5.4.3/§5.4.4),
//!     XORed into the low 4 bits of byte 0 + the PN bytes.
//!   - Sample begins at pn_offset + 4 regardless of pn_len (§5.4.2).

const std = @import("std");
const boringssl = @import("boringssl");

const header = @import("header.zig");
const packet_number_mod = @import("packet_number.zig");
const protection = @import("protection.zig");
const short_packet = @import("short_packet.zig");
const varint = @import("varint.zig");

const AesGcm128 = boringssl.crypto.aead.AesGcm128;

pub const PacketKeys = short_packet.PacketKeys;
pub const Suite = short_packet.Suite;

pub const Error = error{
    OutputTooSmall,
    NotInitialPacket,
    NotZeroRttPacket,
    NotHandshakePacket,
    DcidTooLong,
    ScidTooLong,
    UnsupportedSuite,
    /// The Length field claims more bytes than `src` provides.
    DeclaredLengthExceedsInput,
    /// The packet's payload is too short for the HP sample.
    PayloadTooShort,
} || protection.Error || header.Error || packet_number_mod.Error || varint.Error;

/// QUIC v1 Retry integrity key/nonce, RFC 9001 §5.8.
pub const retry_integrity_key_v1: [16]u8 = .{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

pub const retry_integrity_nonce_v1: [12]u8 = .{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
    0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

const retry_pseudo_packet_max: usize = 4096;

pub const RetrySealOptions = struct {
    version: u32 = 0x00000001,
    /// Original Destination Connection ID from the client's first Initial.
    original_dcid: []const u8,
    /// Destination CID for the Retry packet: the client's Initial SCID.
    dcid: []const u8,
    /// Server-chosen Retry Source CID.
    scid: []const u8,
    retry_token: []const u8,
    unused_bits: u4 = 0,
};

// -- Initial -------------------------------------------------------------

pub const InitialSealOptions = struct {
    /// QUIC version. Defaults to v1.
    version: u32 = 0x00000001,
    /// Destination Connection ID.
    dcid: []const u8,
    /// Source Connection ID (the CID we want the peer to send back to us).
    scid: []const u8,
    /// Address-validation token. Empty for client first-flight; set
    /// by the client when responding to a Retry.
    token: []const u8 = &.{},
    /// Full 64-bit packet number to encode.
    pn: u64,
    /// Largest PN we've seen ACKed in the Initial PN space; used to
    /// choose PN truncation length.
    largest_acked: ?u64 = null,
    /// Frame bytes to encrypt.
    payload: []const u8,
    /// Initial-level packet keys (derived per RFC 9001 §5.2).
    keys: *const PacketKeys,
    /// Pad the protected datagram to at least this many bytes by
    /// appending PADDING frames (0x00) inside the AEAD payload.
    /// RFC 9000 §14 requires the client's first-flight Initial UDP
    /// datagram to be ≥ 1200 bytes.
    pad_to: usize = 0,
    /// Force a specific PN length (1..4). Must accommodate `pn`.
    pn_length_override: ?u8 = null,
};

pub fn sealInitial(dst: []u8, opts: InitialSealOptions) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.scid.len > header.max_cid_len) return Error.ScidTooLong;
    if (opts.keys.suite != .aes128_gcm_sha256) return Error.UnsupportedSuite;

    const pn_len = opts.pn_length_override orelse chooseLongPnLength(opts.pn, opts.largest_acked);
    if (pn_len < 1 or pn_len > 4) return protection.Error.InvalidPnLength;

    // Plaintext padding to satisfy:
    //  (a) RFC 9001 §5.4.2: post-PN must be at least 4 bytes (so HP
    //      sample lies in ciphertext);
    //  (b) opts.pad_to: total datagram size floor.
    const min_pt_for_sample: usize = if (pn_len < 4) @as(usize, 4 - pn_len) else 0;

    const header_len_with_pn_no_length_field = blk: {
        // Pre-compute header length WITHOUT the Length varint so we
        // can iterate to the correct varint size below.
        var x: usize = 1 + 4; // first byte + version
        x += 1 + opts.dcid.len; // DCID len + bytes
        x += 1 + opts.scid.len; // SCID len + bytes
        x += varint.encodedLen(opts.token.len);
        x += opts.token.len;
        // Length varint goes here.
        x += pn_len; // PN bytes follow Length
        break :blk x;
    };

    // Find the smallest plaintext length that satisfies both the
    // sample-floor and pad_to (after accounting for the variable Length
    // varint).
    var pt_len: usize = @max(opts.payload.len, min_pt_for_sample);
    var length_varint_size: usize = varint.encodedLen(pt_len + 16 + pn_len);
    var total_size: usize = (header_len_with_pn_no_length_field - pn_len) + length_varint_size + pn_len + pt_len + 16;

    if (total_size < opts.pad_to) {
        const need = opts.pad_to - total_size;
        pt_len += need;
        // Recompute Length varint size (may have grown).
        const new_length_field_value = pt_len + 16 + pn_len;
        const new_length_varint_size = varint.encodedLen(new_length_field_value);
        if (new_length_varint_size != length_varint_size) {
            // Length varint grew — overshoot the floor by a few
            // bytes; padding is a floor, not a target.
            const delta = new_length_varint_size - length_varint_size;
            length_varint_size = new_length_varint_size;
            total_size += delta;
        } else {
            total_size += need;
        }
    }

    const length_field_value: u64 = @as(u64, pt_len) + 16 + pn_len;

    if (dst.len < total_size) return Error.OutputTooSmall;

    // Encode the unprotected header.
    const dcid_id = try header.ConnId.fromSlice(opts.dcid);
    const scid_id = try header.ConnId.fromSlice(opts.scid);
    const pn_length: header.PnLength = pnLengthFromInt(pn_len);
    const truncated = packetNumberTruncated(opts.pn, pn_len);

    const hdr_len = try header.encode(dst, .{ .initial = .{
        .version = opts.version,
        .dcid = dcid_id,
        .scid = scid_id,
        .token = opts.token,
        .pn_length = pn_length,
        .pn_truncated = truncated,
        .payload_length = length_field_value,
        .reserved_bits = 0,
    } });
    const pn_offset = hdr_len - pn_len;

    // Stage plaintext (with PADDING zero bytes if needed).
    var stage_buf: [2048]u8 = undefined;
    if (pt_len > stage_buf.len) return Error.OutputTooSmall;
    @memcpy(stage_buf[0..opts.payload.len], opts.payload);
    @memset(stage_buf[opts.payload.len..pt_len], 0);

    // AEAD seal.
    const ct_len = try short_packet.sealPayloadWithKeys(
        opts.keys,
        null,
        opts.pn,
        dst[0..hdr_len],
        stage_buf[0..pt_len],
        dst[hdr_len..],
    );
    const total_len = hdr_len + ct_len;

    // Header-protect.
    const sample = try protection.sampleAt(dst[0..total_len], pn_offset);
    const mask = short_packet.headerProtectionMask(opts.keys, &sample);
    try protection.applyHpMask(dst[0..total_len], .long, pn_offset, pn_len, mask);

    return total_len;
}

pub const LongOpenResult = struct {
    pn: u64,
    payload: []u8,
    /// Bytes consumed from the input slice. The caller can use
    /// `src[bytes_consumed..]` to access any coalesced packet that
    /// follows.
    bytes_consumed: usize,
    /// Source Connection ID echoed back from the peer (useful for
    /// the client's first parse — that's where the server tells us
    /// its CID).
    scid: header.ConnId,
    /// Destination Connection ID. The receiver uses this to verify
    /// that the packet is actually addressed to us.
    dcid: header.ConnId,
    /// Address-validation token, for Initial only. Empty for
    /// Handshake.
    token: []const u8,
};

pub const InitialOpenOptions = struct {
    keys: *const PacketKeys,
    largest_received: u64 = 0,
};

pub fn openInitial(pt_dst: []u8, src: []u8, opts: InitialOpenOptions) Error!LongOpenResult {
    return openLongHeader(pt_dst, src, opts.keys, opts.largest_received, .initial);
}

// -- 0-RTT ---------------------------------------------------------------

pub const ZeroRttSealOptions = struct {
    version: u32 = 0x00000001,
    dcid: []const u8,
    scid: []const u8,
    pn: u64,
    largest_acked: ?u64 = null,
    payload: []const u8,
    keys: *const PacketKeys,
    pn_length_override: ?u8 = null,
};

pub fn sealZeroRtt(dst: []u8, opts: ZeroRttSealOptions) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.scid.len > header.max_cid_len) return Error.ScidTooLong;

    const pn_len = opts.pn_length_override orelse chooseLongPnLength(opts.pn, opts.largest_acked);
    if (pn_len < 1 or pn_len > 4) return protection.Error.InvalidPnLength;

    const min_pt_for_sample: usize = if (pn_len < 4) @as(usize, 4 - pn_len) else 0;
    const pt_len: usize = @max(opts.payload.len, min_pt_for_sample);
    const length_field_value: u64 = @as(u64, pt_len) + 16 + pn_len;
    const length_varint_size = varint.encodedLen(length_field_value);

    const total_size: usize = 1 + 4 + 1 + opts.dcid.len + 1 + opts.scid.len +
        length_varint_size + pn_len + pt_len + 16;

    if (dst.len < total_size) return Error.OutputTooSmall;

    const dcid_id = try header.ConnId.fromSlice(opts.dcid);
    const scid_id = try header.ConnId.fromSlice(opts.scid);
    const pn_length: header.PnLength = pnLengthFromInt(pn_len);
    const truncated = packetNumberTruncated(opts.pn, pn_len);

    const hdr_len = try header.encode(dst, .{ .zero_rtt = .{
        .version = opts.version,
        .dcid = dcid_id,
        .scid = scid_id,
        .pn_length = pn_length,
        .pn_truncated = truncated,
        .payload_length = length_field_value,
        .reserved_bits = 0,
    } });
    const pn_offset = hdr_len - pn_len;

    var stage_buf: [2048]u8 = undefined;
    if (pt_len > stage_buf.len) return Error.OutputTooSmall;
    @memcpy(stage_buf[0..opts.payload.len], opts.payload);
    @memset(stage_buf[opts.payload.len..pt_len], 0);

    const ct_len = try short_packet.sealPayloadWithKeys(
        opts.keys,
        null,
        opts.pn,
        dst[0..hdr_len],
        stage_buf[0..pt_len],
        dst[hdr_len..],
    );
    const total_len = hdr_len + ct_len;

    const sample = try protection.sampleAt(dst[0..total_len], pn_offset);
    const mask = short_packet.headerProtectionMask(opts.keys, &sample);
    try protection.applyHpMask(dst[0..total_len], .long, pn_offset, pn_len, mask);

    return total_len;
}

pub fn openZeroRtt(pt_dst: []u8, src: []u8, opts: InitialOpenOptions) Error!LongOpenResult {
    return openLongHeader(pt_dst, src, opts.keys, opts.largest_received, .zero_rtt);
}

// -- Handshake -----------------------------------------------------------

pub const HandshakeSealOptions = struct {
    version: u32 = 0x00000001,
    dcid: []const u8,
    scid: []const u8,
    pn: u64,
    largest_acked: ?u64 = null,
    payload: []const u8,
    keys: *const PacketKeys,
    pn_length_override: ?u8 = null,
};

pub fn sealHandshake(dst: []u8, opts: HandshakeSealOptions) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.scid.len > header.max_cid_len) return Error.ScidTooLong;

    const pn_len = opts.pn_length_override orelse chooseLongPnLength(opts.pn, opts.largest_acked);
    if (pn_len < 1 or pn_len > 4) return protection.Error.InvalidPnLength;

    const min_pt_for_sample: usize = if (pn_len < 4) @as(usize, 4 - pn_len) else 0;
    const pt_len: usize = @max(opts.payload.len, min_pt_for_sample);
    const length_field_value: u64 = @as(u64, pt_len) + 16 + pn_len;
    const length_varint_size = varint.encodedLen(length_field_value);

    const total_size: usize = 1 + 4 + 1 + opts.dcid.len + 1 + opts.scid.len +
        length_varint_size + pn_len + pt_len + 16;

    if (dst.len < total_size) return Error.OutputTooSmall;

    const dcid_id = try header.ConnId.fromSlice(opts.dcid);
    const scid_id = try header.ConnId.fromSlice(opts.scid);
    const pn_length: header.PnLength = pnLengthFromInt(pn_len);
    const truncated = packetNumberTruncated(opts.pn, pn_len);

    const hdr_len = try header.encode(dst, .{ .handshake = .{
        .version = opts.version,
        .dcid = dcid_id,
        .scid = scid_id,
        .pn_length = pn_length,
        .pn_truncated = truncated,
        .payload_length = length_field_value,
        .reserved_bits = 0,
    } });
    const pn_offset = hdr_len - pn_len;

    var stage_buf: [2048]u8 = undefined;
    if (pt_len > stage_buf.len) return Error.OutputTooSmall;
    @memcpy(stage_buf[0..opts.payload.len], opts.payload);
    @memset(stage_buf[opts.payload.len..pt_len], 0);

    const ct_len = try short_packet.sealPayloadWithKeys(
        opts.keys,
        null,
        opts.pn,
        dst[0..hdr_len],
        stage_buf[0..pt_len],
        dst[hdr_len..],
    );
    const total_len = hdr_len + ct_len;

    const sample = try protection.sampleAt(dst[0..total_len], pn_offset);
    const mask = short_packet.headerProtectionMask(opts.keys, &sample);
    try protection.applyHpMask(dst[0..total_len], .long, pn_offset, pn_len, mask);

    return total_len;
}

pub fn openHandshake(pt_dst: []u8, src: []u8, opts: InitialOpenOptions) Error!LongOpenResult {
    return openLongHeader(pt_dst, src, opts.keys, opts.largest_received, .handshake);
}

// -- Retry ---------------------------------------------------------------

pub fn retryIntegrityTag(original_dcid: []const u8, retry_without_tag: []const u8) Error![16]u8 {
    if (original_dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (1 + original_dcid.len + retry_without_tag.len > retry_pseudo_packet_max) {
        return Error.OutputTooSmall;
    }

    var pseudo: [retry_pseudo_packet_max]u8 = undefined;
    var pos: usize = 0;
    pseudo[pos] = @intCast(original_dcid.len);
    pos += 1;
    @memcpy(pseudo[pos .. pos + original_dcid.len], original_dcid);
    pos += original_dcid.len;
    @memcpy(pseudo[pos .. pos + retry_without_tag.len], retry_without_tag);
    pos += retry_without_tag.len;

    var aead = try AesGcm128.init(&retry_integrity_key_v1);
    defer aead.deinit();
    var out: [16]u8 = undefined;
    const n = try aead.seal(&out, &retry_integrity_nonce_v1, pseudo[0..pos], "");
    std.debug.assert(n == out.len);
    return out;
}

pub fn sealRetry(dst: []u8, opts: RetrySealOptions) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.scid.len > header.max_cid_len) return Error.ScidTooLong;

    const dcid = try header.ConnId.fromSlice(opts.dcid);
    const scid = try header.ConnId.fromSlice(opts.scid);
    const zero_tag: [16]u8 = @splat(0);
    const len = try header.encode(dst, .{ .retry = .{
        .version = opts.version,
        .dcid = dcid,
        .scid = scid,
        .retry_token = opts.retry_token,
        .integrity_tag = zero_tag,
        .unused_bits = opts.unused_bits,
    } });
    const tag = try retryIntegrityTag(opts.original_dcid, dst[0 .. len - 16]);
    @memcpy(dst[len - 16 .. len], &tag);
    return len;
}

pub fn validateRetryIntegrity(original_dcid: []const u8, retry_packet: []const u8) Error!bool {
    if (retry_packet.len < 16) return Error.PayloadTooShort;
    const expected = try retryIntegrityTag(original_dcid, retry_packet[0 .. retry_packet.len - 16]);
    return std.mem.eql(u8, &expected, retry_packet[retry_packet.len - 16 ..]);
}

// -- shared open path ----------------------------------------------------

fn openLongHeader(
    pt_dst: []u8,
    src: []u8,
    keys: *const PacketKeys,
    largest_received: u64,
    expected_type: header.LongType,
) Error!LongOpenResult {
    if (src.len < 1) return Error.InsufficientBytes;
    if (src[0] & 0x80 == 0) {
        return unexpectedPacketType(expected_type);
    }
    // Long-type bits (5-4 of the first byte) are NOT covered by HP
    // (which masks only bits 3-0 for long headers, RFC 9001 §5.4.1),
    // so we can check the type before any decryption.
    const long_type_bits_pre: u2 = @intCast((src[0] >> 4) & 0x03);
    const pre_type: header.LongType = @enumFromInt(long_type_bits_pre);
    if (pre_type != expected_type) {
        return unexpectedPacketType(expected_type);
    }
    if (expected_type == .initial and keys.suite != .aes128_gcm_sha256) {
        return Error.UnsupportedSuite;
    }

    // Walk the unprotected header structure manually; the PN bytes
    // are still HP-masked, so we ignore the parser's pn_length /
    // pn_truncated for now and re-derive them after HP is removed.
    var pos: usize = 1;
    if (src.len < pos + 4) return Error.InsufficientBytes;
    pos += 4; // version

    if (src.len < pos + 1) return Error.InsufficientBytes;
    const dcid_len = src[pos];
    pos += 1;
    if (dcid_len > header.max_cid_len) return Error.ConnIdTooLong;
    if (src.len < pos + dcid_len) return Error.InsufficientBytes;
    const dcid = try header.ConnId.fromSlice(src[pos .. pos + dcid_len]);
    pos += dcid_len;

    if (src.len < pos + 1) return Error.InsufficientBytes;
    const scid_len = src[pos];
    pos += 1;
    if (scid_len > header.max_cid_len) return Error.ConnIdTooLong;
    if (src.len < pos + scid_len) return Error.InsufficientBytes;
    const scid = try header.ConnId.fromSlice(src[pos .. pos + scid_len]);
    pos += scid_len;

    var token: []const u8 = &.{};
    if (expected_type == .initial) {
        const tok_len = try varint.decode(src[pos..]);
        pos += tok_len.bytes_read;
        if (tok_len.value > src.len - pos) return Error.InsufficientBytes;
        const tlen: usize = @intCast(tok_len.value);
        token = src[pos .. pos + tlen];
        pos += tlen;
    }

    const len_varint = try varint.decode(src[pos..]);
    pos += len_varint.bytes_read;
    const length_value = len_varint.value;
    const pn_offset = pos;

    if (length_value > src.len - pn_offset) return Error.DeclaredLengthExceedsInput;
    if (length_value < 4 + 16) return Error.PayloadTooShort;

    // Sample for HP.
    if (src.len < pn_offset + 4 + protection.sample_len) return Error.InsufficientCiphertext;
    const sample = try protection.sampleAt(src, pn_offset);
    const mask = short_packet.headerProtectionMask(keys, &sample);

    // Strip HP from byte 0 (low 4 bits) and PN bytes.
    src[0] ^= mask[0] & 0x0f;
    const pn_len: u8 = @intCast((src[0] & 0x03) + 1);
    var i: u8 = 0;
    while (i < pn_len) : (i += 1) {
        src[pn_offset + i] ^= mask[1 + i];
    }

    // Now sanity-check actual_type. Bits 5-4 of the cleaned first byte.
    const long_type_bits: u2 = @intCast((src[0] >> 4) & 0x03);
    const actual_type: header.LongType = @enumFromInt(long_type_bits);
    if (actual_type != expected_type) {
        return unexpectedPacketType(expected_type);
    }

    // Reconstruct PN.
    const truncated = try packet_number_mod.readTruncated(src[pn_offset..], pn_len);
    const full_pn = try packet_number_mod.decode(truncated, pn_len, largest_received);

    // AEAD-open. AAD = src[0..pn_offset+pn_len]; ciphertext is the
    // remaining `length_value - pn_len` bytes.
    const aad_len = pn_offset + pn_len;
    const length_value_usize: usize = @intCast(length_value);
    const ct_len: usize = length_value_usize - pn_len;
    const pt_len = try short_packet.openPayloadWithKeys(
        keys,
        null,
        full_pn,
        src[0..aad_len],
        src[aad_len .. aad_len + ct_len],
        pt_dst,
    );

    return .{
        .pn = full_pn,
        .payload = pt_dst[0..pt_len],
        .bytes_consumed = pn_offset + @as(usize, @intCast(length_value)),
        .scid = scid,
        .dcid = dcid,
        .token = token,
    };
}

// -- helpers -------------------------------------------------------------

fn unexpectedPacketType(expected_type: header.LongType) Error {
    return switch (expected_type) {
        .initial => Error.NotInitialPacket,
        .zero_rtt => Error.NotZeroRttPacket,
        .handshake => Error.NotHandshakePacket,
        .retry => Error.NotInitialPacket,
    };
}

/// Choose a PN length for a long-header packet. Same shape as
/// short_packet.chooseShortPnLength but exposed locally to avoid
/// reaching into a private symbol of that module.
fn chooseLongPnLength(pn: u64, largest_acked: ?u64) u8 {
    const space: u64 = if (largest_acked) |la|
        (if (pn > la) pn - la else 1)
    else
        std.math.maxInt(u64);
    if (space < (1 << 7)) return 1;
    if (space < (1 << 15)) return 2;
    if (space < (1 << 23)) return 3;
    return 4;
}

fn pnLengthFromInt(pn_len: u8) header.PnLength {
    return switch (pn_len) {
        1 => .one,
        2 => .two,
        3 => .three,
        4 => .four,
        else => unreachable,
    };
}

fn packetNumberTruncated(pn: u64, pn_len: u8) u64 {
    if (pn_len >= 8) return pn;
    const shift: u6 = @intCast(@as(u32, pn_len) * 8);
    const mask: u64 = (@as(u64, 1) << shift) - 1;
    return pn & mask;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;
const initial_mod = @import("initial.zig");

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn fillSecret(dst: []u8, seed: u8) void {
    for (dst, 0..) |*b, i| {
        b.* = seed +% @as(u8, @truncate(i * 3));
    }
}

test "Initial seal/open round-trip with §A.1 client keys" {
    const dcid = fromHex("8394c8f03e515708");
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 1, 2, 3, 4 };
    const payload = "synthetic CRYPTO frame bytes go here";

    var packet: [2048]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 2,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [2048]u8 = undefined;
    const opened = try openInitial(&pt, packet[0..len], .{
        .keys = &keys,
        .largest_received = 1,
    });
    try testing.expectEqual(@as(u64, 2), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
    try testing.expectEqualSlices(u8, &dcid, opened.dcid.slice());
    try testing.expectEqualSlices(u8, &scid, opened.scid.slice());
    try testing.expectEqual(@as(usize, 0), opened.token.len);
    try testing.expectEqual(len, opened.bytes_consumed);
}

test "Initial seal pads to 1200 bytes when pad_to is set" {
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 9, 9, 9, 9 };
    const tiny_payload = "ch";

    var packet: [2048]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = tiny_payload,
        .keys = &keys,
        .pad_to = 1200,
    });
    try testing.expect(len >= 1200);
    try testing.expect(len <= 1208); // generous bound — varint reflow

    var pt: [2048]u8 = undefined;
    const opened = try openInitial(&pt, packet[0..len], .{ .keys = &keys });
    // The decrypted payload is the user payload + zero-byte PADDING
    // frames padded out to fit. Verify the prefix.
    try testing.expectEqualSlices(u8, tiny_payload, opened.payload[0..tiny_payload.len]);
    // The bytes after our payload are PADDING (RFC 9000 §19.1 = 0x00).
    for (opened.payload[tiny_payload.len..]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "Initial seal token round-trips through open" {
    const dcid: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 1, 2, 3, 4 };
    const payload = "frames";
    const token = [_]u8{ 0xa1, 0xb2, 0xc3 };

    var packet: [256]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .token = &token,
        .pn = 0,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    const opened = try openInitial(&pt, packet[0..len], .{ .keys = &keys });
    try testing.expectEqualSlices(u8, &token, opened.token);
}

test "Handshake seal/open round-trip" {
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    // Use synthetic 32-byte secret — Handshake keys don't have a
    // baked-in derivation; the connection layer derives them from
    // TLS handshake_traffic_secret.
    const secret = fromHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &secret);

    const scid: [4]u8 = .{ 9, 9, 9, 9 };
    const payload = "CRYPTO + ACK frames";

    var packet: [256]u8 = undefined;
    const len = try sealHandshake(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 5,
        .largest_acked = 4,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    const opened = try openHandshake(&pt, packet[0..len], .{
        .keys = &keys,
        .largest_received = 4,
    });
    try testing.expectEqual(@as(u64, 5), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
    try testing.expectEqualSlices(u8, &dcid, opened.dcid.slice());
    try testing.expectEqualSlices(u8, &scid, opened.scid.slice());
}

test "0-RTT seal/open round-trip" {
    const dcid: [8]u8 = .{ 4, 3, 2, 1, 8, 7, 6, 5 };
    const secret = fromHex("d00df151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &secret);

    const scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const payload = "early STREAM frames";

    var packet: [256]u8 = undefined;
    const len = try sealZeroRtt(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 9,
        .largest_acked = 8,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    const opened = try openZeroRtt(&pt, packet[0..len], .{
        .keys = &keys,
        .largest_received = 8,
    });
    try testing.expectEqual(@as(u64, 9), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
    try testing.expectEqualSlices(u8, &dcid, opened.dcid.slice());
    try testing.expectEqualSlices(u8, &scid, opened.scid.slice());
    try testing.expectEqual(len, opened.bytes_consumed);
}

test "Retry seal validates integrity tag" {
    const original_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const retry_scid: [8]u8 = .{ 1, 3, 3, 7, 5, 8, 13, 21 };
    const token = "retry-token";

    var packet: [256]u8 = undefined;
    const len = try sealRetry(&packet, .{
        .original_dcid = &original_dcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = token,
    });

    try testing.expect(try validateRetryIntegrity(&original_dcid, packet[0..len]));
    const parsed = try header.parse(packet[0..len], 0);
    try testing.expect(parsed.header == .retry);
    try testing.expectEqualSlices(u8, token, parsed.header.retry.retry_token);
    packet[len - 1] ^= 0x01;
    try testing.expect(!try validateRetryIntegrity(&original_dcid, packet[0..len]));
}

test "Handshake and 0-RTT support every negotiated QUIC v1 suite" {
    const suites = [_]Suite{
        .aes128_gcm_sha256,
        .aes256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };
    const dcid: [8]u8 = .{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid: [4]u8 = .{ 0xa0, 0xb0, 0xc0, 0xd0 };

    for (suites, 0..) |suite, suite_idx| {
        var secret: short_packet.TrafficSecret = @splat(0);
        fillSecret(secret[0..suite.secretLen()], @as(u8, @truncate(0x40 + suite_idx * 0x13)));
        const keys = try short_packet.derivePacketKeys(suite, secret[0..suite.secretLen()]);

        var handshake_packet: [256]u8 = undefined;
        const hs_payload = "suite-flexible HANDSHAKE CRYPTO frames";
        const hs_len = try sealHandshake(&handshake_packet, .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 11,
            .largest_acked = 10,
            .payload = hs_payload,
            .keys = &keys,
        });

        var pt: [256]u8 = undefined;
        const hs_opened = try openHandshake(&pt, handshake_packet[0..hs_len], .{
            .keys = &keys,
            .largest_received = 10,
        });
        try testing.expectEqual(@as(u64, 11), hs_opened.pn);
        try testing.expectEqualSlices(u8, hs_payload, hs_opened.payload[0..hs_payload.len]);

        var zero_rtt_packet: [256]u8 = undefined;
        const zr_payload = "suite-flexible 0-RTT STREAM frames";
        const zr_len = try sealZeroRtt(&zero_rtt_packet, .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 12,
            .largest_acked = 11,
            .payload = zr_payload,
            .keys = &keys,
        });

        const zr_opened = try openZeroRtt(&pt, zero_rtt_packet[0..zr_len], .{
            .keys = &keys,
            .largest_received = 11,
        });
        try testing.expectEqual(@as(u64, 12), zr_opened.pn);
        try testing.expectEqualSlices(u8, zr_payload, zr_opened.payload[0..zr_payload.len]);
    }
}

test "Initial rejects non-initial cipher suites" {
    var secret: short_packet.TrafficSecret = @splat(0);
    fillSecret(secret[0..Suite.aes256_gcm_sha384.secretLen()], 0x74);
    const keys = try short_packet.derivePacketKeys(
        .aes256_gcm_sha384,
        secret[0..Suite.aes256_gcm_sha384.secretLen()],
    );

    const dcid: [8]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const scid: [4]u8 = .{ 8, 9, 10, 11 };
    var packet: [256]u8 = undefined;
    try testing.expectError(
        Error.UnsupportedSuite,
        sealInitial(&packet, .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 0,
            .payload = "x",
            .keys = &keys,
        }),
    );
}

test "openInitial rejects bytes whose first bit indicates short header" {
    const secret = fromHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &secret);

    var bytes = [_]u8{0x40} ++ [_]u8{0} ** 31; // first byte 0x40 → short header
    var pt: [64]u8 = undefined;
    try testing.expectError(
        Error.NotInitialPacket,
        openInitial(&pt, &bytes, .{ .keys = &keys }),
    );
}

test "openHandshake rejects an Initial packet" {
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    const scid: [4]u8 = .{ 0, 0, 0, 0 };

    var packet: [256]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "x",
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    try testing.expectError(
        Error.NotHandshakePacket,
        openHandshake(&pt, packet[0..len], .{ .keys = &keys }),
    );
}

test "Initial coalesced with Handshake: bytes_consumed lets us advance" {
    // Build a 2-packet coalesced datagram: Initial then Handshake.
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, true); // server side
    const i_keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    const hs_secret = fromHex(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
    );
    const hs_keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &hs_secret);

    const scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    var dgram: [2048]u8 = undefined;
    const i_len = try sealInitial(&dgram, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "I0",
        .keys = &i_keys,
    });
    const h_len = try sealHandshake(dgram[i_len..], .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "H0",
        .keys = &hs_keys,
    });
    const total = i_len + h_len;

    var pt: [2048]u8 = undefined;
    const o1 = try openInitial(&pt, dgram[0..total], .{ .keys = &i_keys });
    try testing.expectEqualSlices(u8, "I0", o1.payload[0..2]);
    try testing.expectEqual(i_len, o1.bytes_consumed);

    const o2 = try openHandshake(&pt, dgram[o1.bytes_consumed..total], .{ .keys = &hs_keys });
    try testing.expectEqualSlices(u8, "H0", o2.payload[0..2]);
    try testing.expectEqual(h_len, o2.bytes_consumed);
}
