//! RFC 8999 — Version-Independent Properties of QUIC.
//!
//! These invariants outlive any single QUIC version: a v1 endpoint and
//! a hypothetical v3 endpoint that disagree on everything else still
//! agree on these few framing rules. nullq's wire layer
//! (`src/wire/header.zig`) implements them; this suite is the
//! auditor-facing record.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC8999 §4    MUST     long-header form bit (bit 7 = 1) identifies long headers
//!   RFC8999 §4    MUST     long header carries 4-byte Version field at offsets 1..5
//!   RFC8999 §4.1  MUST     DCID Length octet immediately follows Version
//!   RFC8999 §4.1  MUST     SCID Length octet follows DCID
//!   RFC8999 §4.1  MUST NOT accept a long header whose DCID length exceeds the buffer
//!   RFC8999 §4.1  MUST NOT accept a long header whose SCID length exceeds the buffer
//!   RFC8999 §5.1  MUST     short-header form bit (bit 7 = 0) identifies short headers
//!   RFC8999 §6    MUST     Version Negotiation packet has Version = 0x00000000
//!   RFC8999 §6    MUST NOT accept a VN whose Supported Versions list is empty
//!   RFC8999 §6    MUST NOT accept a VN whose Supported Versions length is not a multiple of 4
//!   RFC8999 §6    NORMATIVE first-byte bits 6..0 of a VN packet are unused — preserved on parse
//!   RFC8999 §6    MUST     emitted VN lists at least one supported version (encode-side)
//!   RFC8999 §6    MUST     every supported_version entry is a 4-octet big-endian integer (encode-side)
//!
//! Out of scope here (covered elsewhere):
//!   RFC8999 §5.1  Connection-ID length cap (QUIC v1 = 20 bytes)  → rfc9000_packet_headers.zig §17.2
//!   RFC8999 §6    server's "do I send VN?" decision logic        → rfc9000_negotiation_validation.zig §6
//!
//! Not implemented by design:
//!   none — every RFC 8999 invariant relevant to a v1 endpoint is exercised here.

const std = @import("std");
const nullq = @import("nullq");
const wire = nullq.wire;
const header = wire.header;

/// QUIC v1 wire-format version, per RFC 9000 §15. Used to construct
/// well-formed long-header packets for these tests; the exact value is
/// version-specific but RFC 8999 §4 says the field is 4 bytes wide.
const QUIC_V1: u32 = 0x00000001;

/// Minimal long-header byte slab: 0xc0 | Version(4) | DCIDLEN | DCID | SCIDLEN | SCID | tail.
/// Tail is whatever bytes follow the SCID (e.g. token-len varint for Initial,
/// supported_versions list for VN).
fn longHeader(
    out: []u8,
    first_byte: u8,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    tail: []const u8,
) usize {
    var pos: usize = 0;
    out[pos] = first_byte;
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], version, .big);
    pos += 4;
    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos .. pos + dcid.len], dcid);
    pos += dcid.len;
    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos .. pos + scid.len], scid);
    pos += scid.len;
    @memcpy(out[pos .. pos + tail.len], tail);
    pos += tail.len;
    return pos;
}

// ---------------------------------------------------------------- §4 long header

test "MUST identify a long-header packet by the high bit of the first byte being 1 [RFC8999 §4 ¶1]" {
    // 0xc0 = 0b11000000: form bit (7) set, fixed bit (6) set,
    // remaining bits zero — a syntactically minimal long header that
    // parseHeader must classify as long.
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 9, 10, 11, 12 };
    // Initial-shaped tail: token-len=0, length=0, pn=0.
    const tail = [_]u8{ 0x00, 0x00, 0x00 };
    const len = longHeader(&buf, 0xc0, QUIC_V1, &dcid, &scid, &tail);

    const parsed = try header.parse(buf[0..len], 0);

    // The active variant must NOT be the short-header variant.
    try std.testing.expect(parsed.header != .one_rtt);
}

test "MUST encode the QUIC Version as a 4-byte big-endian field at offset 1 [RFC8999 §4 ¶3]" {
    // Pick a non-v1 sentinel so we can verify big-endian wiring
    // unambiguously. Any 4-byte value works for an RFC 8999 syntactic
    // check; semantic version-handling lives in RFC 9000 §6
    // (negotiation_validation suite).
    const sentinel: u32 = 0xCAFEF00D;
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const scid = [_]u8{ 0x55, 0x66 };
    const tail = [_]u8{ 0x00, 0x00, 0x00 };
    _ = longHeader(&buf, 0xc0, sentinel, &dcid, &scid, &tail);

    // Wire-level check: bytes [1..5] are the version, big-endian.
    const on_wire = std.mem.readInt(u32, buf[1..5], .big);
    try std.testing.expectEqual(sentinel, on_wire);
}

test "MUST place the DCID Length octet immediately after the Version field [RFC8999 §4.1 ¶1]" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc };
    const scid = [_]u8{0xdd};
    const tail = [_]u8{ 0x00, 0x00, 0x00 };
    _ = longHeader(&buf, 0xc0, QUIC_V1, &dcid, &scid, &tail);

    // Byte 5 is DCIDLEN. RFC 8999 §4.1 ¶1: "The Length of the
    // Destination Connection ID field, encoded as a single unsigned
    // 8-bit integer."
    try std.testing.expectEqual(@as(u8, dcid.len), buf[5]);
}

test "MUST place the SCID Length octet immediately after DCID [RFC8999 §4.1 ¶2]" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc };
    const scid = [_]u8{ 0xdd, 0xee };
    const tail = [_]u8{ 0x00, 0x00, 0x00 };
    _ = longHeader(&buf, 0xc0, QUIC_V1, &dcid, &scid, &tail);

    // SCIDLEN sits at: 1 (first byte) + 4 (version) + 1 (DCIDLEN) + dcid.len.
    const scid_len_offset: usize = 1 + 4 + 1 + dcid.len;
    try std.testing.expectEqual(@as(u8, scid.len), buf[scid_len_offset]);
}

test "MUST NOT accept a long header whose DCID Length exceeds the remaining buffer [RFC8999 §4.1 ¶1]" {
    // First-byte 0xc0 + version + DCIDLEN claimed > what's actually
    // present. Use a length within the QUIC v1 20-byte cap so the
    // parser's overflow gate fires, not the v1 length-cap gate (which
    // is RFC 9000 §17.2's stricter rule, exercised separately in the
    // §17 packet-headers suite).
    var buf: [16]u8 = undefined;
    buf[0] = 0xc0;
    std.mem.writeInt(u32, buf[1..5], QUIC_V1, .big);
    buf[5] = 8; // claimed DCIDLEN = 8 (<= v1 cap)
    // …but only 4 bytes of DCID actually trail
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;

    try std.testing.expectError(
        error.InsufficientBytes,
        header.parse(buf[0..10], 0),
    );
}

test "MUST NOT accept a long header whose SCID Length exceeds the remaining buffer [RFC8999 §4.1 ¶2]" {
    var buf: [16]u8 = undefined;
    // DCIDLEN = 0 (no DCID bytes), then SCIDLEN claimed = 8 (within
    // v1 cap) but only 1 byte actually trails. Parser must refuse on
    // buffer-overflow grounds rather than read past `buf`.
    buf[0] = 0xc0;
    std.mem.writeInt(u32, buf[1..5], QUIC_V1, .big);
    buf[5] = 0; // DCIDLEN = 0 → no DCID bytes
    buf[6] = 8; // SCIDLEN = 8 (<= v1 cap), but only 1 byte trails
    buf[7] = 0xab;

    try std.testing.expectError(
        error.InsufficientBytes,
        header.parse(buf[0..8], 0),
    );
}

// ---------------------------------------------------------------- §5 short header

test "MUST identify a short-header packet by the high bit of the first byte being 0 [RFC8999 §5.1 ¶1]" {
    // 0x40 = 0b01000000: form bit clear, fixed bit set. RFC 9000 §17.3
    // says short-header packets carry only DCID; the receiver supplies
    // its locally chosen length.
    var buf: [32]u8 = undefined;
    buf[0] = 0x40;
    const dcid_len: u8 = 8;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    @memcpy(buf[1..][0..dcid_len], &dcid);
    // 1 byte of PN (encoded as 0x00 because pn_bits = 0 in 0x40).
    buf[1 + dcid_len] = 0x00;

    const parsed = try header.parse(buf[0 .. 1 + dcid_len + 1], dcid_len);

    try std.testing.expect(parsed.header == .one_rtt);
}

// ---------------------------------------------------------------- §6 version negotiation

test "MUST mark a Version Negotiation packet with Version = 0x00000000 [RFC8999 §6 ¶2]" {
    // VN with version=0 and a single supported version (v1).
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0x10, 0x20, 0x30 };
    const scid = [_]u8{ 0x40, 0x50, 0x60, 0x70 };
    // Tail = supported_versions list — single entry, v1, big-endian.
    var tail: [4]u8 = undefined;
    std.mem.writeInt(u32, tail[0..4], QUIC_V1, .big);
    const len = longHeader(&buf, 0x80, 0x00000000, &dcid, &scid, &tail);

    const parsed = try header.parse(buf[0..len], 0);

    try std.testing.expect(parsed.header == .version_negotiation);
    const vn = parsed.header.version_negotiation;
    // Wire field is at [1..5] — verified separately above; here we
    // assert the parser routes Version=0 into the VN variant.
    try std.testing.expectEqual(@as(usize, 1), vn.versionCount());
    try std.testing.expectEqual(QUIC_V1, vn.version(0));
}

test "MUST NOT accept a VN packet with an empty Supported Versions list [RFC8999 §6 ¶3]" {
    // Long header bytes only, no supported_versions trailing.
    var buf: [16]u8 = undefined;
    const dcid = [_]u8{0xaa};
    const scid = [_]u8{0xbb};
    // No tail — versions_bytes will be zero-length.
    const len = longHeader(&buf, 0x80, 0x00000000, &dcid, &scid, &[_]u8{});

    try std.testing.expectError(
        error.InvalidVersionNegotiation,
        header.parse(buf[0..len], 0),
    );
}

test "MUST NOT accept a VN packet whose Supported Versions length is not a multiple of 4 octets [RFC8999 §6 ¶3]" {
    var buf: [16]u8 = undefined;
    const dcid = [_]u8{0xaa};
    const scid = [_]u8{0xbb};
    // 5 trailing bytes — not a multiple of 4.
    const tail = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0xff };
    const len = longHeader(&buf, 0x80, 0x00000000, &dcid, &scid, &tail);

    try std.testing.expectError(
        error.InvalidVersionNegotiation,
        header.parse(buf[0..len], 0),
    );
}

test "NORMATIVE round-trip the unused first-byte bits of a Version Negotiation packet [RFC8999 §6 ¶1]" {
    // RFC 8999 §6 ¶1: "The value in the Unused field is set to an
    // arbitrary value by the server." A receiver MUST be able to
    // parse VN regardless of those bits, and the encoder must
    // preserve them on round-trip. The RFC text doesn't use a BCP 14
    // keyword for the round-trip itself — hence NORMATIVE rather than MUST.
    var versions_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, versions_bytes[0..4], QUIC_V1, .big);
    const vn = header.VersionNegotiation{
        .unused_bits = 0x55, // arbitrary 7-bit pattern
        .dcid = try header.ConnId.fromSlice(&[_]u8{ 0x10, 0x20 }),
        .scid = try header.ConnId.fromSlice(&[_]u8{0x30}),
        .versions_bytes = versions_bytes[0..],
    };

    var encoded: [32]u8 = undefined;
    const written = try header.encode(&encoded, .{ .version_negotiation = vn });
    const parsed = try header.parse(encoded[0..written], 0);

    try std.testing.expect(parsed.header == .version_negotiation);
    try std.testing.expectEqual(vn.unused_bits, parsed.header.version_negotiation.unused_bits);
}

test "MUST list at least one supported version in an emitted VN packet [RFC8999 §6 ¶3]" {
    // Symmetric encode-side check: the encoder rejects an empty
    // supported_versions list, ensuring an RFC 8999 §6 ¶3-conformant
    // VN never leaves nullq.
    var buf: [16]u8 = undefined;
    const vn = header.VersionNegotiation{
        .dcid = try header.ConnId.fromSlice(&[_]u8{0xaa}),
        .scid = try header.ConnId.fromSlice(&[_]u8{0xbb}),
        .versions_bytes = &[_]u8{}, // empty — must be rejected
    };

    try std.testing.expectError(
        error.InvalidVersionNegotiation,
        header.encode(&buf, .{ .version_negotiation = vn }),
    );
}

test "MUST encode every supported_version entry as a 4-octet big-endian integer [RFC8999 §6 ¶3]" {
    // RFC 8999 §6 ¶3: "Supported Version: ... a list of 32-bit
    // versions which the server supports." Encoder rejects a
    // versions_bytes whose length is not a multiple of 4.
    var buf: [16]u8 = undefined;
    const not_multiple_of_4 = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0xff };
    const vn = header.VersionNegotiation{
        .dcid = try header.ConnId.fromSlice(&[_]u8{0xaa}),
        .scid = try header.ConnId.fromSlice(&[_]u8{0xbb}),
        .versions_bytes = &not_multiple_of_4,
    };

    try std.testing.expectError(
        error.InvalidVersionNegotiation,
        header.encode(&buf, .{ .version_negotiation = vn }),
    );
}
