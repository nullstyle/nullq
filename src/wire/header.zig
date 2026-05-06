//! QUIC packet header parsing and serialization (RFC 9000 §17).
//!
//! This module deals with the *unprotected* wire format. RFC 9001 §5
//! header protection masks the low bits of the first byte and the
//! Packet Number bytes; that is the responsibility of
//! `wire/protection.zig`. Callers parsing live datagrams must remove
//! header protection before passing bytes here; the unit tests in
//! this file synthesize headers in their plaintext form for KAT
//! coverage.
//!
//! Connection IDs are capped at 20 bytes here (the QUIC v1 limit per
//! RFC 9000 §17.2). RFC 8999 invariants allow up to 255-byte CIDs in
//! version-negotiation contexts; nullq does not interop with such
//! peers in v0.1.

const std = @import("std");
const varint = @import("varint.zig");
const packet_number = @import("packet_number.zig");

/// Maximum Connection ID length permitted by QUIC v1.
pub const max_cid_len: u8 = 20;

/// Long Packet Type, encoded as a 2-bit field at positions 5-4 of the
/// first byte of a long-header packet (RFC 9000 §17.2).
pub const LongType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

/// Packet Number length in bytes. Encoded as N-1 in the low 2 bits of
/// the first byte after header protection is removed.
pub const PnLength = enum(u8) {
    one = 1,
    two = 2,
    three = 3,
    four = 4,

    /// Decode the raw 2-bit PN-length field (N-1 encoding) from a
    /// post-HP first byte.
    pub fn fromTwoBits(bits: u2) PnLength {
        return switch (bits) {
            0 => .one,
            1 => .two,
            2 => .three,
            3 => .four,
        };
    }

    /// Encode this length as the 2-bit (N-1) field for the first byte.
    pub fn toTwoBits(self: PnLength) u2 {
        return @intCast(@intFromEnum(self) - 1);
    }

    /// Length in bytes (1..4).
    pub fn bytes(self: PnLength) u8 {
        return @intFromEnum(self);
    }
};

/// A QUIC v1 Connection ID — up to 20 bytes.
pub const ConnId = struct {
    bytes: [max_cid_len]u8 = @splat(0),
    len: u8 = 0,

    /// Build a `ConnId` from a byte slice. Returns `ConnIdTooLong` if
    /// the slice exceeds the QUIC v1 maximum of 20 bytes.
    pub fn fromSlice(src: []const u8) Error!ConnId {
        if (src.len > max_cid_len) return Error.ConnIdTooLong;
        var c: ConnId = .{ .len = @intCast(src.len) };
        @memcpy(c.bytes[0..src.len], src);
        return c;
    }

    /// Borrow a view of the active CID bytes (length-bounded).
    pub fn slice(self: *const ConnId) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Initial long-header packet (RFC 9000 §17.2.2). Carries an
/// address-validation token in addition to the standard long-header
/// fields.
pub const Initial = struct {
    version: u32,
    dcid: ConnId,
    scid: ConnId,
    /// Borrowed from the input slice on parse; caller-owned on encode.
    token: []const u8,
    pn_length: PnLength,
    /// Truncated PN value (1..4 bytes worth, big-endian on the wire).
    pn_truncated: u64,
    /// The Length field's value: PN bytes + protected payload + AEAD
    /// tag. On parse, as decoded; on encode, written verbatim — the
    /// caller is responsible for it matching the actual emitted body.
    payload_length: u64,
    /// Bits 3-2 of the first byte. MUST be 0 in well-formed v1
    /// packets after header protection is removed; preserved here for
    /// round-trip tests.
    reserved_bits: u2 = 0,
};

/// 0-RTT long-header packet (RFC 9000 §17.2.3). Sent by clients to
/// resume early data after a prior session.
pub const ZeroRtt = struct {
    version: u32,
    dcid: ConnId,
    scid: ConnId,
    pn_length: PnLength,
    pn_truncated: u64,
    payload_length: u64,
    reserved_bits: u2 = 0,
};

/// Handshake long-header packet (RFC 9000 §17.2.4). Carries TLS
/// handshake CRYPTO frames after Initial keys are established.
pub const Handshake = struct {
    version: u32,
    dcid: ConnId,
    scid: ConnId,
    pn_length: PnLength,
    pn_truncated: u64,
    payload_length: u64,
    reserved_bits: u2 = 0,
};

/// Retry long-header packet (RFC 9000 §17.2.5). Server-issued
/// challenge that forces the client to re-send its first Initial
/// with an attached token.
pub const Retry = struct {
    version: u32,
    dcid: ConnId,
    scid: ConnId,
    /// Borrowed from input on parse; caller-owned on encode.
    retry_token: []const u8,
    integrity_tag: [16]u8,
    /// Bits 3-0 of the first byte; spec'd "Unused" — preserve as-is.
    unused_bits: u4 = 0,
};

/// 1-RTT short-header packet (RFC 9000 §17.3). Carries
/// application-data frames once the handshake completes.
pub const OneRtt = struct {
    /// For short headers the DCID length isn't carried on the wire;
    /// both endpoints know it from configuration. Caller-supplied at
    /// parse and encode.
    dcid: ConnId,
    spin_bit: bool = false,
    reserved_bits: u2 = 0,
    key_phase: bool = false,
    pn_length: PnLength,
    pn_truncated: u64,
};

/// Version Negotiation packet (RFC 8999 §6). Sent by a server that
/// does not support the version requested in the client's first
/// Initial, listing supported versions for the client to retry with.
pub const VersionNegotiation = struct {
    /// First-byte bits 6-0 are unspecified per RFC 8999 — preserve.
    unused_bits: u7 = 0,
    dcid: ConnId,
    scid: ConnId,
    /// Big-endian u32 list. Length must be a non-zero multiple of 4.
    /// Borrowed from the input slice on parse.
    versions_bytes: []const u8,

    /// Number of supported-version entries in `versions_bytes`.
    pub fn versionCount(self: VersionNegotiation) usize {
        return self.versions_bytes.len / 4;
    }

    /// Read the supported-version u32 at `index` from `versions_bytes`.
    pub fn version(self: VersionNegotiation, index: usize) u32 {
        const offset = index * 4;
        return std.mem.readInt(u32, self.versions_bytes[offset..][0..4], .big);
    }
};

/// Tagged union over every QUIC v1 header type. The active variant
/// determines which RFC 9000 §17 layout was parsed or will be encoded.
pub const Header = union(enum) {
    initial: Initial,
    zero_rtt: ZeroRtt,
    handshake: Handshake,
    retry: Retry,
    one_rtt: OneRtt,
    version_negotiation: VersionNegotiation,

    /// Return the Destination Connection ID carried by any header
    /// variant — useful for connection demultiplexing.
    pub fn dcid(self: Header) ConnId {
        return switch (self) {
            .initial => |h| h.dcid,
            .zero_rtt => |h| h.dcid,
            .handshake => |h| h.dcid,
            .retry => |h| h.dcid,
            .one_rtt => |h| h.dcid,
            .version_negotiation => |h| h.dcid,
        };
    }
};

/// Result of `parse`: the decoded header plus the offset of its PN
/// bytes (for header-protection sample extraction).
pub const Parsed = struct {
    header: Header,
    /// Byte offset within the input slice at which the (possibly
    /// still-encrypted) Packet Number bytes begin. For Retry and
    /// VersionNegotiation, zero — those have no PN.
    pn_offset: usize,
};

/// Errors returned by header parse/encode operations.
pub const Error = varint.Error || packet_number.Error || error{
    ConnIdTooLong,
    InvalidVersionNegotiation,
};

// -- parse ---------------------------------------------------------------

/// Parse the header at the start of `src`. For short-header packets
/// the receiver must supply `dcid_len_for_short` (its locally chosen
/// connection-ID length); this argument is ignored for long headers.
pub fn parse(src: []const u8, dcid_len_for_short: u8) Error!Parsed {
    if (src.len < 1) return Error.InsufficientBytes;
    const first = src[0];
    if ((first & 0x80) == 0) {
        return parseShort(src, first, dcid_len_for_short);
    }
    return parseLong(src, first);
}

fn parseShort(src: []const u8, first: u8, dcid_len: u8) Error!Parsed {
    if (dcid_len > max_cid_len) return Error.ConnIdTooLong;
    const spin = (first & 0x20) != 0;
    const reserved_bits: u2 = @intCast((first >> 3) & 0x03);
    const key_phase = (first & 0x04) != 0;
    const pn_bits: u2 = @intCast(first & 0x03);
    const pn_length = PnLength.fromTwoBits(pn_bits);

    var pos: usize = 1;
    if (src.len < pos + dcid_len) return Error.InsufficientBytes;
    const dcid = try ConnId.fromSlice(src[pos .. pos + dcid_len]);
    pos += dcid_len;

    const pn_offset = pos;
    if (src.len < pos + pn_length.bytes()) return Error.InsufficientBytes;
    const pn_truncated = try packet_number.readTruncated(src[pos..], pn_length.bytes());

    return Parsed{
        .header = .{ .one_rtt = .{
            .dcid = dcid,
            .spin_bit = spin,
            .reserved_bits = reserved_bits,
            .key_phase = key_phase,
            .pn_length = pn_length,
            .pn_truncated = pn_truncated,
        } },
        .pn_offset = pn_offset,
    };
}

const LongCommon = struct {
    version: u32,
    dcid: ConnId,
    scid: ConnId,
    /// Position of the first byte after SCID (where type-specific
    /// fields begin).
    end_pos: usize,
};

fn parseLongCommon(src: []const u8) Error!LongCommon {
    var pos: usize = 1;
    if (src.len < pos + 4) return Error.InsufficientBytes;
    const version = std.mem.readInt(u32, src[pos..][0..4], .big);
    pos += 4;

    if (src.len < pos + 1) return Error.InsufficientBytes;
    const dcid_len = src[pos];
    pos += 1;
    if (dcid_len > max_cid_len) return Error.ConnIdTooLong;
    if (src.len < pos + dcid_len) return Error.InsufficientBytes;
    const dcid = try ConnId.fromSlice(src[pos .. pos + dcid_len]);
    pos += dcid_len;

    if (src.len < pos + 1) return Error.InsufficientBytes;
    const scid_len = src[pos];
    pos += 1;
    if (scid_len > max_cid_len) return Error.ConnIdTooLong;
    if (src.len < pos + scid_len) return Error.InsufficientBytes;
    const scid = try ConnId.fromSlice(src[pos .. pos + scid_len]);
    pos += scid_len;

    return .{ .version = version, .dcid = dcid, .scid = scid, .end_pos = pos };
}

fn parseLong(src: []const u8, first: u8) Error!Parsed {
    const common = try parseLongCommon(src);

    if (common.version == 0) {
        // Version Negotiation: rest of packet is supported_versions.
        const versions_bytes = src[common.end_pos..];
        if (versions_bytes.len == 0 or versions_bytes.len % 4 != 0) {
            return Error.InvalidVersionNegotiation;
        }
        return Parsed{
            .header = .{ .version_negotiation = .{
                .unused_bits = @intCast(first & 0x7f),
                .dcid = common.dcid,
                .scid = common.scid,
                .versions_bytes = versions_bytes,
            } },
            .pn_offset = 0,
        };
    }

    const long_type: LongType = @enumFromInt(@as(u2, @intCast((first >> 4) & 0x03)));
    const reserved_bits: u2 = @intCast((first >> 2) & 0x03);
    const pn_bits: u2 = @intCast(first & 0x03);
    const pn_length = PnLength.fromTwoBits(pn_bits);

    return switch (long_type) {
        .initial => parseInitialTail(src, common, reserved_bits, pn_length),
        .zero_rtt => parseLongPnTail(src, common, reserved_bits, pn_length, .zero_rtt),
        .handshake => parseLongPnTail(src, common, reserved_bits, pn_length, .handshake),
        .retry => parseRetryTail(src, common, @intCast(first & 0x0f)),
    };
}

fn parseInitialTail(
    src: []const u8,
    common: LongCommon,
    reserved_bits: u2,
    pn_length: PnLength,
) Error!Parsed {
    var pos = common.end_pos;

    const tok_len = try varint.decode(src[pos..]);
    pos += tok_len.bytes_read;

    if (tok_len.value > src.len - pos) return Error.InsufficientBytes;
    const token_len: usize = @intCast(tok_len.value);
    const token = src[pos .. pos + token_len];
    pos += token_len;

    const length = try varint.decode(src[pos..]);
    pos += length.bytes_read;

    const pn_offset = pos;
    if (src.len < pos + pn_length.bytes()) return Error.InsufficientBytes;
    const pn_truncated = try packet_number.readTruncated(src[pos..], pn_length.bytes());

    return Parsed{
        .header = .{ .initial = .{
            .version = common.version,
            .dcid = common.dcid,
            .scid = common.scid,
            .token = token,
            .pn_length = pn_length,
            .pn_truncated = pn_truncated,
            .payload_length = length.value,
            .reserved_bits = reserved_bits,
        } },
        .pn_offset = pn_offset,
    };
}

const PnTailKind = enum { zero_rtt, handshake };

fn parseLongPnTail(
    src: []const u8,
    common: LongCommon,
    reserved_bits: u2,
    pn_length: PnLength,
    kind: PnTailKind,
) Error!Parsed {
    var pos = common.end_pos;

    const length = try varint.decode(src[pos..]);
    pos += length.bytes_read;

    const pn_offset = pos;
    if (src.len < pos + pn_length.bytes()) return Error.InsufficientBytes;
    const pn_truncated = try packet_number.readTruncated(src[pos..], pn_length.bytes());

    const header: Header = switch (kind) {
        .zero_rtt => .{ .zero_rtt = .{
            .version = common.version,
            .dcid = common.dcid,
            .scid = common.scid,
            .pn_length = pn_length,
            .pn_truncated = pn_truncated,
            .payload_length = length.value,
            .reserved_bits = reserved_bits,
        } },
        .handshake => .{ .handshake = .{
            .version = common.version,
            .dcid = common.dcid,
            .scid = common.scid,
            .pn_length = pn_length,
            .pn_truncated = pn_truncated,
            .payload_length = length.value,
            .reserved_bits = reserved_bits,
        } },
    };

    return Parsed{ .header = header, .pn_offset = pn_offset };
}

fn parseRetryTail(src: []const u8, common: LongCommon, unused_bits: u4) Error!Parsed {
    if (src.len < common.end_pos + 16) return Error.InsufficientBytes;
    const tag_start = src.len - 16;
    if (tag_start < common.end_pos) return Error.InsufficientBytes;
    const retry_token = src[common.end_pos..tag_start];
    var integrity_tag: [16]u8 = undefined;
    @memcpy(&integrity_tag, src[tag_start .. tag_start + 16]);

    return Parsed{
        .header = .{ .retry = .{
            .version = common.version,
            .dcid = common.dcid,
            .scid = common.scid,
            .retry_token = retry_token,
            .integrity_tag = integrity_tag,
            .unused_bits = unused_bits,
        } },
        .pn_offset = 0,
    };
}

// -- encode --------------------------------------------------------------

/// Serialize `header` into the start of `dst`. Returns bytes written.
/// Errors with `BufferTooSmall` if `dst` cannot hold the encoded form.
pub fn encode(dst: []u8, header: Header) Error!usize {
    return switch (header) {
        .initial => |h| encodeInitial(dst, h),
        .zero_rtt => |h| encodeLongPn(dst, h, .zero_rtt),
        .handshake => |h| encodeLongPn(dst, h, .handshake),
        .retry => |h| encodeRetry(dst, h),
        .one_rtt => |h| encodeOneRtt(dst, h),
        .version_negotiation => |h| encodeVersionNegotiation(dst, h),
    };
}

fn writeLongHeaderCommon(
    dst: []u8,
    first_byte: u8,
    version: u32,
    dcid: ConnId,
    scid: ConnId,
) Error!usize {
    const total: usize = 1 + 4 + 1 + dcid.len + 1 + scid.len;
    if (dst.len < total) return Error.BufferTooSmall;
    var pos: usize = 0;
    dst[pos] = first_byte;
    pos += 1;
    std.mem.writeInt(u32, dst[pos..][0..4], version, .big);
    pos += 4;
    dst[pos] = dcid.len;
    pos += 1;
    @memcpy(dst[pos .. pos + dcid.len], dcid.bytes[0..dcid.len]);
    pos += dcid.len;
    dst[pos] = scid.len;
    pos += 1;
    @memcpy(dst[pos .. pos + scid.len], scid.bytes[0..scid.len]);
    pos += scid.len;
    return pos;
}

fn encodeInitial(dst: []u8, h: Initial) Error!usize {
    const first_byte: u8 = 0xc0 |
        (@as(u8, @intFromEnum(LongType.initial)) << 4) |
        (@as(u8, h.reserved_bits) << 2) |
        h.pn_length.toTwoBits();
    var pos = try writeLongHeaderCommon(dst, first_byte, h.version, h.dcid, h.scid);

    pos += try varint.encode(dst[pos..], h.token.len);
    if (dst.len < pos + h.token.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + h.token.len], h.token);
    pos += h.token.len;

    pos += try varint.encode(dst[pos..], h.payload_length);

    if (dst.len < pos + h.pn_length.bytes()) return Error.BufferTooSmall;
    try packet_number.encode(dst[pos..], h.pn_truncated, h.pn_length.bytes());
    pos += h.pn_length.bytes();
    return pos;
}

fn encodeLongPn(dst: []u8, h: anytype, comptime kind: PnTailKind) Error!usize {
    const long_type: LongType = switch (kind) {
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
    };
    const first_byte: u8 = 0xc0 |
        (@as(u8, @intFromEnum(long_type)) << 4) |
        (@as(u8, h.reserved_bits) << 2) |
        h.pn_length.toTwoBits();
    var pos = try writeLongHeaderCommon(dst, first_byte, h.version, h.dcid, h.scid);

    pos += try varint.encode(dst[pos..], h.payload_length);

    if (dst.len < pos + h.pn_length.bytes()) return Error.BufferTooSmall;
    try packet_number.encode(dst[pos..], h.pn_truncated, h.pn_length.bytes());
    pos += h.pn_length.bytes();
    return pos;
}

fn encodeRetry(dst: []u8, h: Retry) Error!usize {
    const first_byte: u8 = 0xc0 |
        (@as(u8, @intFromEnum(LongType.retry)) << 4) |
        @as(u8, h.unused_bits);
    var pos = try writeLongHeaderCommon(dst, first_byte, h.version, h.dcid, h.scid);

    if (dst.len < pos + h.retry_token.len + 16) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + h.retry_token.len], h.retry_token);
    pos += h.retry_token.len;
    @memcpy(dst[pos .. pos + 16], &h.integrity_tag);
    pos += 16;
    return pos;
}

fn encodeOneRtt(dst: []u8, h: OneRtt) Error!usize {
    const total: usize = 1 + h.dcid.len + h.pn_length.bytes();
    if (dst.len < total) return Error.BufferTooSmall;
    // First byte: 0 1 S R R K LL  (form=0, fixed=1)
    var first: u8 = 0x40;
    if (h.spin_bit) first |= 0x20;
    first |= @as(u8, h.reserved_bits) << 3;
    if (h.key_phase) first |= 0x04;
    first |= h.pn_length.toTwoBits();

    var pos: usize = 0;
    dst[pos] = first;
    pos += 1;
    @memcpy(dst[pos .. pos + h.dcid.len], h.dcid.bytes[0..h.dcid.len]);
    pos += h.dcid.len;
    try packet_number.encode(dst[pos..], h.pn_truncated, h.pn_length.bytes());
    pos += h.pn_length.bytes();
    return pos;
}

fn encodeVersionNegotiation(dst: []u8, h: VersionNegotiation) Error!usize {
    if (h.versions_bytes.len == 0 or h.versions_bytes.len % 4 != 0) {
        return Error.InvalidVersionNegotiation;
    }
    const first_byte: u8 = 0x80 | @as(u8, h.unused_bits);
    var pos = try writeLongHeaderCommon(dst, first_byte, 0, h.dcid, h.scid);

    if (dst.len < pos + h.versions_bytes.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + h.versions_bytes.len], h.versions_bytes);
    pos += h.versions_bytes.len;
    return pos;
}

// -- tests ---------------------------------------------------------------

test "parse: RFC 9001 §A.2 unprotected client Initial header" {
    // From RFC 9001 §A.2:
    //   c300000001088394c8f03e5157080000449e00000002
    const bytes = [_]u8{
        0xc3, // long, fixed, type=Initial, reserved=0, pn_len=4
        0x00, 0x00, 0x00, 0x01, // version 1
        0x08, // dcid_len = 8
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, // dcid
        0x00, // scid_len = 0
        0x00, // token_len = 0
        0x44, 0x9e, // length varint = 1182
        0x00, 0x00, 0x00, 0x02, // packet number = 2
    };
    const parsed = try parse(&bytes, 0);
    try std.testing.expect(parsed.header == .initial);
    const i = parsed.header.initial;
    try std.testing.expectEqual(@as(u32, 1), i.version);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
        i.dcid.slice(),
    );
    try std.testing.expectEqual(@as(u8, 0), i.scid.len);
    try std.testing.expectEqual(@as(usize, 0), i.token.len);
    try std.testing.expectEqual(@as(u64, 1182), i.payload_length);
    try std.testing.expectEqual(PnLength.four, i.pn_length);
    try std.testing.expectEqual(@as(u64, 2), i.pn_truncated);
    try std.testing.expectEqual(@as(u2, 0), i.reserved_bits);
    try std.testing.expectEqual(@as(usize, 18), parsed.pn_offset);
}

test "encode/parse: round-trip RFC 9001 §A.2 client Initial header" {
    const original = [_]u8{
        0xc3, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x00,
        0x00,
        0x44, 0x9e,
        0x00, 0x00, 0x00, 0x02,
    };
    const parsed = try parse(&original, 0);

    var out: [128]u8 = undefined;
    const written = try encode(&out, parsed.header);
    try std.testing.expectEqualSlices(u8, &original, out[0..written]);
}

test "Initial: round-trip with non-empty token and reserved bits" {
    var token_storage: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    const dcid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const scid_bytes = [_]u8{ 0x10, 0x20, 0x30 };

    const h = Initial{
        .version = 0x00000001,
        .dcid = try ConnId.fromSlice(&dcid_bytes),
        .scid = try ConnId.fromSlice(&scid_bytes),
        .token = &token_storage,
        .pn_length = .two,
        .pn_truncated = 0xabcd,
        .payload_length = 100,
        .reserved_bits = 0,
    };
    var buf: [128]u8 = undefined;
    const written = try encode(&buf, .{ .initial = h });

    const parsed = try parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .initial);
    const got = parsed.header.initial;
    try std.testing.expectEqual(h.version, got.version);
    try std.testing.expectEqualSlices(u8, h.dcid.slice(), got.dcid.slice());
    try std.testing.expectEqualSlices(u8, h.scid.slice(), got.scid.slice());
    try std.testing.expectEqualSlices(u8, h.token, got.token);
    try std.testing.expectEqual(h.pn_length, got.pn_length);
    try std.testing.expectEqual(h.pn_truncated, got.pn_truncated);
    try std.testing.expectEqual(h.payload_length, got.payload_length);
}

test "Handshake: round-trip" {
    const dcid_bytes = [_]u8{ 0xaa, 0xbb, 0xcc };
    const h = Handshake{
        .version = 1,
        .dcid = try ConnId.fromSlice(&dcid_bytes),
        .scid = try ConnId.fromSlice(&[_]u8{}),
        .pn_length = .three,
        .pn_truncated = 0x123456,
        .payload_length = 256,
    };
    var buf: [64]u8 = undefined;
    const written = try encode(&buf, .{ .handshake = h });
    const parsed = try parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .handshake);
    const got = parsed.header.handshake;
    try std.testing.expectEqualSlices(u8, h.dcid.slice(), got.dcid.slice());
    try std.testing.expectEqual(h.pn_truncated, got.pn_truncated);
    try std.testing.expectEqual(h.payload_length, got.payload_length);
    try std.testing.expectEqual(h.pn_length, got.pn_length);
}

test "ZeroRtt: round-trip" {
    const dcid_bytes = [_]u8{ 0xaa, 0xbb, 0xcc };
    const h = ZeroRtt{
        .version = 1,
        .dcid = try ConnId.fromSlice(&dcid_bytes),
        .scid = try ConnId.fromSlice(&[_]u8{}),
        .pn_length = .one,
        .pn_truncated = 0x42,
        .payload_length = 50,
    };
    var buf: [64]u8 = undefined;
    const written = try encode(&buf, .{ .zero_rtt = h });
    const parsed = try parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .zero_rtt);
    const got = parsed.header.zero_rtt;
    try std.testing.expectEqual(h.pn_truncated, got.pn_truncated);
    try std.testing.expectEqual(h.payload_length, got.payload_length);
}

test "Retry: round-trip" {
    const dcid_bytes = [_]u8{ 0x11, 0x22 };
    const scid_bytes = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = "my-retry-token-here";
    const tag = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const h = Retry{
        .version = 1,
        .dcid = try ConnId.fromSlice(&dcid_bytes),
        .scid = try ConnId.fromSlice(&scid_bytes),
        .retry_token = token,
        .integrity_tag = tag,
        .unused_bits = 0,
    };
    var buf: [128]u8 = undefined;
    const written = try encode(&buf, .{ .retry = h });
    const parsed = try parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .retry);
    const got = parsed.header.retry;
    try std.testing.expectEqualSlices(u8, token, got.retry_token);
    try std.testing.expectEqualSlices(u8, &tag, &got.integrity_tag);
    try std.testing.expectEqualSlices(u8, h.dcid.slice(), got.dcid.slice());
    try std.testing.expectEqualSlices(u8, h.scid.slice(), got.scid.slice());
}

test "OneRtt: round-trip" {
    const dcid_bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33 };
    const h = OneRtt{
        .dcid = try ConnId.fromSlice(&dcid_bytes),
        .spin_bit = true,
        .reserved_bits = 0,
        .key_phase = true,
        .pn_length = .four,
        .pn_truncated = 0x12345678,
    };
    var buf: [32]u8 = undefined;
    const written = try encode(&buf, .{ .one_rtt = h });

    const parsed = try parse(buf[0..written], @intCast(dcid_bytes.len));
    try std.testing.expect(parsed.header == .one_rtt);
    const got = parsed.header.one_rtt;
    try std.testing.expectEqualSlices(u8, h.dcid.slice(), got.dcid.slice());
    try std.testing.expectEqual(true, got.spin_bit);
    try std.testing.expectEqual(true, got.key_phase);
    try std.testing.expectEqual(PnLength.four, got.pn_length);
    try std.testing.expectEqual(@as(u64, 0x12345678), got.pn_truncated);
}

test "VersionNegotiation: round-trip with three supported versions" {
    const dcid_bytes = [_]u8{ 0xaa, 0xbb };
    const scid_bytes = [_]u8{ 0xcc, 0xdd, 0xee };
    const versions = [_]u8{
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x6b, 0x33, 0x43, 0xcf, // grease (per RFC 9287)
        0xff, 0x00, 0x00, 0x20, // draft-32 (historical)
    };
    const h = VersionNegotiation{
        .unused_bits = 0x42,
        .dcid = try ConnId.fromSlice(&dcid_bytes),
        .scid = try ConnId.fromSlice(&scid_bytes),
        .versions_bytes = &versions,
    };
    var buf: [64]u8 = undefined;
    const written = try encode(&buf, .{ .version_negotiation = h });
    const parsed = try parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    const got = parsed.header.version_negotiation;
    try std.testing.expectEqualSlices(u8, &versions, got.versions_bytes);
    try std.testing.expectEqual(@as(usize, 3), got.versionCount());
    try std.testing.expectEqual(@as(u32, 0x00000001), got.version(0));
    try std.testing.expectEqual(@as(u32, 0x6b3343cf), got.version(1));
    try std.testing.expectEqual(@as(u32, 0xff000020), got.version(2));
    try std.testing.expectEqual(@as(u7, 0x42), got.unused_bits);
}

test "VersionNegotiation: rejects empty versions list" {
    const h = VersionNegotiation{
        .dcid = try ConnId.fromSlice(&[_]u8{}),
        .scid = try ConnId.fromSlice(&[_]u8{}),
        .versions_bytes = &[_]u8{},
    };
    var buf: [32]u8 = undefined;
    try std.testing.expectError(Error.InvalidVersionNegotiation, encode(&buf, .{ .version_negotiation = h }));
}

test "VersionNegotiation: rejects non-multiple-of-4 versions list" {
    const h = VersionNegotiation{
        .dcid = try ConnId.fromSlice(&[_]u8{}),
        .scid = try ConnId.fromSlice(&[_]u8{}),
        .versions_bytes = &[_]u8{ 0x00, 0x01, 0x02 },
    };
    var buf: [32]u8 = undefined;
    try std.testing.expectError(Error.InvalidVersionNegotiation, encode(&buf, .{ .version_negotiation = h }));
}

test "ConnId rejects oversize input" {
    var too_long: [21]u8 = @splat(0);
    try std.testing.expectError(Error.ConnIdTooLong, ConnId.fromSlice(&too_long));
}

test "parse rejects empty input" {
    try std.testing.expectError(Error.InsufficientBytes, parse("", 0));
}

test "parse rejects truncated long header" {
    // First byte says long, but no version follows.
    try std.testing.expectError(Error.InsufficientBytes, parse(&[_]u8{0xc0}, 0));
}

test "parse rejects DCID length > 20 in long header" {
    const bytes = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01, // first + version
        21, // dcid_len > max
    };
    try std.testing.expectError(Error.ConnIdTooLong, parse(&bytes, 0));
}

test "parse rejects truncated PN in short header" {
    const dcid: [4]u8 = @splat(0xaa);
    var bytes: [5]u8 = undefined;
    bytes[0] = 0x43; // short, fixed, pn_len=4 (low 2 bits = 0b11)
    @memcpy(bytes[1..5], &dcid);
    // Buffer has DCID but no PN bytes — error.
    try std.testing.expectError(Error.InsufficientBytes, parse(&bytes, 4));
}

test "Header.dcid accessor returns the right CID for each variant" {
    const cid1 = try ConnId.fromSlice(&[_]u8{ 0x01, 0x02 });
    const cid2 = try ConnId.fromSlice(&[_]u8{ 0x03, 0x04 });
    const cid3 = try ConnId.fromSlice(&[_]u8{ 0x05 });

    const i: Header = .{ .initial = .{
        .version = 1,
        .dcid = cid1,
        .scid = cid2,
        .token = "",
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 1,
    } };
    try std.testing.expectEqualSlices(u8, cid1.slice(), i.dcid().slice());

    const o: Header = .{ .one_rtt = .{
        .dcid = cid3,
        .pn_length = .one,
        .pn_truncated = 0,
    } };
    try std.testing.expectEqualSlices(u8, cid3.slice(), o.dcid().slice());
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `parse` with arbitrary bytes and a fuzzer-chosen short-header
// DCID length, then assert structural invariants on whatever it
// returned. Aborts on panic / unreachable. Invariant violations
// minimize and save to the corpus.

test "fuzz: header parse never panics and reports consistent offsets" {
    try std.testing.fuzz({}, fuzzHeaderParse, .{});
}

fn fuzzHeaderParse(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [2048]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    const dcid_len_for_short = smith.valueRangeAtMost(u8, 0, 20);

    const parsed = parse(input, dcid_len_for_short) catch return;

    // pn_offset is meaningful only for protected packets (Initial,
    // Handshake, ZeroRtt, OneRtt). For Retry / VersionNegotiation it
    // is documented as zero. Either way it must lie inside the input.
    try std.testing.expect(parsed.pn_offset <= input.len);

    // The parsed header's CIDs all came from inside `input`, so
    // accessing them must not access random memory.
    switch (parsed.header) {
        .initial => |h| {
            try std.testing.expect(h.dcid.len <= 20);
            try std.testing.expect(h.scid.len <= 20);
        },
        .zero_rtt => |h| {
            try std.testing.expect(h.dcid.len <= 20);
            try std.testing.expect(h.scid.len <= 20);
        },
        .handshake => |h| {
            try std.testing.expect(h.dcid.len <= 20);
            try std.testing.expect(h.scid.len <= 20);
        },
        .retry => |h| {
            try std.testing.expect(h.dcid.len <= 20);
            try std.testing.expect(h.scid.len <= 20);
        },
        .version_negotiation => |h| {
            try std.testing.expect(h.dcid.len <= 20);
            try std.testing.expect(h.scid.len <= 20);
            // VN versions list must be a multiple of 4 bytes.
            try std.testing.expectEqual(@as(usize, 0), h.versions_bytes.len % 4);
        },
        .one_rtt => |h| {
            try std.testing.expectEqual(dcid_len_for_short, h.dcid.len);
        },
    }
}
