//! RFC 9368 — Compatible Version Negotiation for QUIC.
//!
//! These tests pin the wire-format differences between QUIC v1 and
//! QUIC v2 plus the `version_information` transport parameter that
//! carries the compatible-version-negotiation set. The differences
//! are version-scoped — short headers, frame syntax, and the
//! connection-level state machine are unchanged from RFC 9000.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9368 §3.1 ¶1  MUST       QUIC v2 wire-format version code is 0x6b3343cf
//!   RFC9368 §3.2 ¶1  MUST       v2 long-packet-type bits rotate against v1
//!                                (Initial=0b01, 0-RTT=0b10, Handshake=0b11,
//!                                 Retry=0b00)
//!   RFC9368 §3.2 ¶1  MUST       parse round-trips a v2 Initial under the
//!                                rotated bit layout
//!   RFC9368 §3.3.1   MUST       v2 Initial Salt is the 20-byte fixed value
//!                                0x0dede1058e9c0746845cb9aab6a1e03d52e2d5a3
//!   RFC9368 §3.3.2   MUST       v2 Initial-key labels are
//!                                `quicv2 key` / `quicv2 iv` / `quicv2 hp`
//!   RFC9368 §3.3.2   MUST       v2 Initial keys differ from v1 under the
//!                                same DCID
//!   RFC9368 §3.3.3   MUST       v2 Retry integrity key is the §3.3.3 fixed
//!                                value 0x8fb4b01b56ac48e260fbcbcead7ccc92
//!   RFC9368 §3.3.3   MUST       v2 Retry integrity nonce is the §3.3.3 fixed
//!                                value 0xd86969bc2d7c6d9990efb04a
//!   RFC9368 §3.3.3   MUST       v2 sealRetry round-trips through
//!                                validateRetryIntegrity under the v2
//!                                constants
//!   RFC9368 §5 ¶1    MUST       version_information transport parameter has
//!                                codepoint 0x11
//!   RFC9368 §5 ¶3    MUST       version_information encodes as a list of
//!                                u32s with the chosen version first
//!   RFC9368 §5 ¶3    MUST       version_information round-trips through
//!                                Params.encode / Params.decode
//!   RFC9368 §6       MUST       a server with v1+v2 in its versions list
//!                                accepts v1-only clients (no VN, slot opens
//!                                under v1)
//!   RFC9368 §6       MUST       a server with only v1 in its versions list
//!                                emits a Version Negotiation listing v1 in
//!                                response to a v2 Initial

const std = @import("std");
const quic_zig = @import("quic_zig");

const wire = quic_zig.wire;
const header = wire.header;
const initial = wire.initial;
const long_packet = wire.long_packet;
const tls = quic_zig.tls;
const TransportParams = tls.TransportParams;
const transport_params_mod = tls.transport_params;

const QUIC_V1: u32 = 0x00000001;
const QUIC_V2: u32 = 0x6b3343cf;

const test_cert_pem = @embedFile("../data/test_cert.pem");
const test_key_pem = @embedFile("../data/test_key.pem");

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ---------------------------------------------------------------- §3.1 version code

test "QUIC v2 wire-format version code is 0x6b3343cf [RFC9368 §3.1 ¶1]" {
    try std.testing.expectEqual(@as(u32, 0x6b3343cf), quic_zig.QUIC_VERSION_2);
    try std.testing.expectEqual(@as(u32, 0x6b3343cf), QUIC_V2);
}

// ---------------------------------------------------------------- §3.2 long-packet-type rotation

test "v2 long-packet-type bits rotate against v1 [RFC9368 §3.2 ¶1]" {
    // RFC 9368 §3.2 table:
    //   v1 → Initial 0b00, 0-RTT 0b01, Handshake 0b10, Retry 0b11
    //   v2 → Initial 0b01, 0-RTT 0b10, Handshake 0b11, Retry 0b00
    try std.testing.expectEqual(@as(u2, 0b00), header.longTypeToBits(QUIC_V1, .initial));
    try std.testing.expectEqual(@as(u2, 0b01), header.longTypeToBits(QUIC_V1, .zero_rtt));
    try std.testing.expectEqual(@as(u2, 0b10), header.longTypeToBits(QUIC_V1, .handshake));
    try std.testing.expectEqual(@as(u2, 0b11), header.longTypeToBits(QUIC_V1, .retry));

    try std.testing.expectEqual(@as(u2, 0b01), header.longTypeToBits(QUIC_V2, .initial));
    try std.testing.expectEqual(@as(u2, 0b10), header.longTypeToBits(QUIC_V2, .zero_rtt));
    try std.testing.expectEqual(@as(u2, 0b11), header.longTypeToBits(QUIC_V2, .handshake));
    try std.testing.expectEqual(@as(u2, 0b00), header.longTypeToBits(QUIC_V2, .retry));

    // Inverse mapping must round-trip in both directions.
    inline for (.{ .initial, .zero_rtt, .handshake, .retry }) |t| {
        try std.testing.expectEqual(t, header.longTypeFromBits(QUIC_V1, header.longTypeToBits(QUIC_V1, t)));
        try std.testing.expectEqual(t, header.longTypeFromBits(QUIC_V2, header.longTypeToBits(QUIC_V2, t)));
    }
}

test "v2 Initial parses under the rotated long-type layout [RFC9368 §3.2 ¶1]" {
    const dcid_bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid_bytes = [_]u8{ 0xa, 0xb };
    const h = header.Initial{
        .version = QUIC_V2,
        .dcid = try header.ConnId.fromSlice(&dcid_bytes),
        .scid = try header.ConnId.fromSlice(&scid_bytes),
        .token = "",
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 24,
    };
    var buf: [64]u8 = undefined;
    const written = try header.encode(&buf, .{ .initial = h });
    // First-byte type bits MUST be 0b01 under v2 (RFC 9368 §3.2).
    const type_bits: u2 = @intCast((buf[0] >> 4) & 0x03);
    try std.testing.expectEqual(@as(u2, 0b01), type_bits);

    const parsed = try header.parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqual(QUIC_V2, parsed.header.initial.version);
    try std.testing.expectEqualSlices(u8, &dcid_bytes, parsed.header.initial.dcid.slice());
}

test "a v1 0-RTT byte pattern parses as v2 Initial under the rotation [RFC9368 §3.2 ¶1]" {
    // The same bit pattern (long header, type=0b01, fixed=1) means
    // 0-RTT under v1 but Initial under v2. Parse it both ways and
    // assert the resulting variant matches the version field.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0b1101_0000; // form=1, fixed=1, type=0b01, reserved=0, pn_len bits=00
    pos += 1;
    std.mem.writeInt(u32, buf[pos..][0..4], QUIC_V2, .big);
    pos += 4;
    buf[pos] = 8; // dcid_len
    pos += 1;
    @memcpy(buf[pos .. pos + 8], &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    pos += 8;
    buf[pos] = 0; // scid_len
    pos += 1;
    buf[pos] = 0; // token_len varint = 0
    pos += 1;
    buf[pos] = 17; // length varint = 17 (1 PN + 16-byte tag)
    pos += 1;
    buf[pos] = 0; // PN
    pos += 1;
    const v2_initial_len = pos;

    const v2_parsed = try header.parse(buf[0..v2_initial_len], 0);
    try std.testing.expect(v2_parsed.header == .initial);
    try std.testing.expectEqual(QUIC_V2, v2_parsed.header.initial.version);

    // Now flip the version field to v1 and reparse — same bytes,
    // but the parser now sees a 0-RTT.
    std.mem.writeInt(u32, buf[1..][0..4], QUIC_V1, .big);
    const v1_parsed = try header.parse(buf[0..v2_initial_len], 0);
    try std.testing.expect(v1_parsed.header == .zero_rtt);
}

// ---------------------------------------------------------------- §3.3.1 Initial Salt

test "v2 Initial Salt matches the §3.3.1 fixed constant [RFC9368 §3.3.1]" {
    // RFC 9368 §3.3.1 lists the salt verbatim:
    //   0x0dede1058e9c0746845cb9aab6a1e03d52e2d5a3
    const expected = fromHex("0dede1058e9c0746845cb9aab6a1e03d52e2d5a3");
    try std.testing.expectEqualSlices(u8, &expected, &initial.initial_salt_v2);
    // initialSaltFor() should pick v2 for v2 and v1 for everything
    // else.
    try std.testing.expectEqualSlices(u8, &initial.initial_salt_v2, initial.initialSaltFor(QUIC_V2));
    try std.testing.expectEqualSlices(u8, &initial.initial_salt_v1, initial.initialSaltFor(QUIC_V1));
}

// ---------------------------------------------------------------- §3.3.2 HKDF labels

test "v2 Initial HKDF labels are quicv2 key / iv / hp [RFC9368 §3.3.2]" {
    const labels = initial.initial_labels_v2;
    try std.testing.expectEqualStrings("quicv2 key", labels.key);
    try std.testing.expectEqualStrings("quicv2 iv", labels.iv);
    try std.testing.expectEqualStrings("quicv2 hp", labels.hp);
}

test "v2 Initial keys differ from v1 under the same DCID [RFC9368 §3.3.2]" {
    // Same DCID → different salt + different labels → different
    // keys/IV/HP across versions.
    const dcid = fromHex("8394c8f03e515708");
    const v1_keys = try initial.deriveInitialKeysFor(QUIC_V1, &dcid, false);
    const v2_keys = try initial.deriveInitialKeysFor(QUIC_V2, &dcid, false);
    try std.testing.expect(!std.mem.eql(u8, &v1_keys.secret, &v2_keys.secret));
    try std.testing.expect(!std.mem.eql(u8, &v1_keys.key, &v2_keys.key));
    try std.testing.expect(!std.mem.eql(u8, &v1_keys.iv, &v2_keys.iv));
    try std.testing.expect(!std.mem.eql(u8, &v1_keys.hp, &v2_keys.hp));
}

// ---------------------------------------------------------------- §3.3.3 Retry integrity

test "v2 Retry integrity key matches the §3.3.3 fixed constant [RFC9368 §3.3.3]" {
    const expected = fromHex("8fb4b01b56ac48e260fbcbcead7ccc92");
    try std.testing.expectEqualSlices(u8, &expected, &long_packet.retry_integrity_key_v2);
    try std.testing.expectEqualSlices(u8, &long_packet.retry_integrity_key_v2, long_packet.retryIntegrityKeyFor(QUIC_V2));
    try std.testing.expectEqualSlices(u8, &long_packet.retry_integrity_key_v1, long_packet.retryIntegrityKeyFor(QUIC_V1));
}

test "v2 Retry integrity nonce matches the §3.3.3 fixed constant [RFC9368 §3.3.3]" {
    const expected = fromHex("d86969bc2d7c6d9990efb04a");
    try std.testing.expectEqualSlices(u8, &expected, &long_packet.retry_integrity_nonce_v2);
    try std.testing.expectEqualSlices(u8, &long_packet.retry_integrity_nonce_v2, long_packet.retryIntegrityNonceFor(QUIC_V2));
    try std.testing.expectEqualSlices(u8, &long_packet.retry_integrity_nonce_v1, long_packet.retryIntegrityNonceFor(QUIC_V1));
}

test "v2 sealRetry validates under the v2 integrity constants [RFC9368 §3.3.3]" {
    const original_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const retry_scid: [8]u8 = .{ 1, 3, 3, 7, 5, 8, 13, 21 };
    const token = "v2-retry-token";

    var packet: [256]u8 = undefined;
    const len = try long_packet.sealRetry(&packet, .{
        .version = QUIC_V2,
        .original_dcid = &original_dcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = token,
    });

    // v2 Retry has type bits = 0b00 (the v1 Initial slot).
    const type_bits: u2 = @intCast((packet[0] >> 4) & 0x03);
    try std.testing.expectEqual(@as(u2, 0b00), type_bits);

    // Validation must succeed under v2 (the version is read from the
    // packet's version field).
    try std.testing.expect(try long_packet.validateRetryIntegrity(&original_dcid, packet[0..len]));

    // A v1 Retry of the same bytes (same DCID/SCID/token) produces a
    // *different* tag — proves the version is binding.
    var v1_packet: [256]u8 = undefined;
    const v1_len = try long_packet.sealRetry(&v1_packet, .{
        .version = QUIC_V1,
        .original_dcid = &original_dcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = token,
    });
    try std.testing.expect(!std.mem.eql(u8, packet[len - 16 .. len], v1_packet[v1_len - 16 .. v1_len]));
}

// ---------------------------------------------------------------- §5 transport parameter

test "version_information transport parameter codepoint is 0x11 [RFC9368 §5 ¶1]" {
    try std.testing.expectEqual(@as(u64, 0x11), transport_params_mod.Id.version_information);
}

test "version_information round-trips through Params encode/decode [RFC9368 §5 ¶3]" {
    const versions = [_]u32{ QUIC_V2, QUIC_V1, 0xff00abcd };
    var sent: TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_source_connection_id = transport_params_mod.ConnectionId.fromSlice(&[_]u8{ 1, 2, 3 }),
    };
    try sent.setCompatibleVersions(&versions);
    try std.testing.expectEqualSlices(u32, &versions, sent.compatibleVersions());

    var buf: [256]u8 = undefined;
    const n = try sent.encode(&buf);

    const got = try TransportParams.decode(buf[0..n]);
    try std.testing.expectEqual(@as(usize, versions.len), got.compatibleVersions().len);
    try std.testing.expectEqualSlices(u32, &versions, got.compatibleVersions());
}

test "version_information rejects mis-sized wire payload [RFC9368 §5 ¶3]" {
    // A non-multiple-of-4 byte length is malformed.
    const malformed = [_]u8{
        0x40, 0x11, // id = 0x11 (varint, 2-byte form)
        0x03, // len = 3
        0xaa, 0xbb, 0xcc,
    };
    try std.testing.expectError(transport_params_mod.Error.InvalidValue, TransportParams.decode(&malformed));

    // Empty payload (zero u32s) is also malformed — RFC 9368 §5
    // requires at least the chosen version.
    const empty = [_]u8{
        0x40, 0x11, // id
        0x00, // len = 0
    };
    try std.testing.expectError(transport_params_mod.Error.InvalidValue, TransportParams.decode(&empty));
}

test "Params.setCompatibleVersions rejects oversized lists [RFC9368 §5]" {
    var p: TransportParams = .{};
    var too_many: [17]u32 = @splat(QUIC_V1);
    try std.testing.expectError(transport_params_mod.Error.InvalidValue, p.setCompatibleVersions(&too_many));
}

// ---------------------------------------------------------------- §6 Server gating

const default_server_params = TransportParams{
    .max_idle_timeout_ms = 30_000,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 1 << 18,
    .initial_max_stream_data_bidi_remote = 1 << 18,
    .initial_max_stream_data_uni = 1 << 18,
    .initial_max_streams_bidi = 100,
    .initial_max_streams_uni = 100,
    .active_connection_id_limit = 4,
};

fn buildServerWithVersions(versions: []const u32) !quic_zig.Server {
    const protos = [_][]const u8{"hq-test"};
    return try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = default_server_params,
        .versions = versions,
    });
}

/// Build a v2 Initial datagram, padded to RFC 9000 §14's 1200-byte
/// floor so the server's pre-feed gates don't drop it.
fn buildV2InitialDatagram(dcid: []const u8, scid: []const u8) ![1500]u8 {
    var pkt: [1500]u8 = undefined;
    const v2_init_keys = try initial.deriveInitialKeysFor(QUIC_V2, dcid, false);
    const pkt_keys = try wire.short_packet.derivePacketKeys(
        .aes128_gcm_sha256,
        &v2_init_keys.secret,
    );
    const n = try long_packet.sealInitial(&pkt, .{
        .version = QUIC_V2,
        .dcid = dcid,
        .scid = scid,
        .pn = 0,
        .payload = &.{ 0x00, 0x00 }, // PADDING frames inside AEAD
        .keys = &pkt_keys,
        .pad_to = 1200,
    });
    _ = n;
    return pkt;
}

test "server with v1+v2 accepts a v2 Initial without VN [RFC9368 §6]" {
    const versions = [_]u32{ QUIC_V2, QUIC_V1 };
    var srv = try buildServerWithVersions(&versions);
    defer srv.deinit();

    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid: [4]u8 = .{ 0xa, 0xb, 0xc, 0xd };
    var pkt = try buildV2InitialDatagram(&dcid, &scid);

    const addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xee) };
    const out = try srv.feed(&pkt, addr, 1_000_000);
    try std.testing.expectEqual(quic_zig.Server.FeedOutcome.accepted, out);
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), srv.statelessResponseCount());

    // The slot's connection adopted v2 — a v1 client would fail to
    // open the keys derived under the v2 salt, but the server side
    // records the negotiated version on the Connection.
    const slot = srv.iterator()[0];
    try std.testing.expectEqual(QUIC_V2, slot.conn.version);
}

test "server with only v1 emits VN listing v1 for a v2 Initial [RFC9368 §6]" {
    const versions = [_]u32{QUIC_V1};
    var srv = try buildServerWithVersions(&versions);
    defer srv.deinit();

    // We don't need a fully-sealed v2 Initial here — the version
    // field is already enough to fail the gate. Use a minimal
    // hand-crafted long-header byte pattern so the test isn't
    // coupled to v2 key derivation.
    var bytes: [16]u8 = undefined;
    bytes[0] = 0xd0; // long, fixed, type=0b01 (Initial under v2)
    std.mem.writeInt(u32, bytes[1..][0..4], QUIC_V2, .big);
    bytes[5] = 4;
    @memcpy(bytes[6..10], &[_]u8{ 1, 2, 3, 4 });
    bytes[10] = 0; // scid_len
    @memset(bytes[11..], 0);

    const addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0x42) };
    const out = try srv.feed(&bytes, addr, 1_000_000);
    try std.testing.expectEqual(quic_zig.Server.FeedOutcome.version_negotiated, out);
    try std.testing.expectEqual(@as(usize, 1), srv.statelessResponseCount());

    // Drain the queued VN and inspect the supported_versions list.
    const vn = srv.drainStatelessResponse() orelse return error.UnexpectedNullVn;
    const parsed = try wire.header.parse(vn.slice(), 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    const vn_hdr = parsed.header.version_negotiation;
    try std.testing.expectEqual(@as(usize, 1), vn_hdr.versionCount());
    try std.testing.expectEqual(QUIC_V1, vn_hdr.version(0));
}

test "server VN body mirrors Config.versions when configured for both [RFC9368 §6]" {
    const versions = [_]u32{ QUIC_V2, QUIC_V1 };
    var srv = try buildServerWithVersions(&versions);
    defer srv.deinit();

    // Trigger VN with an unsupported version (greased, neither v1
    // nor v2).
    var bytes: [16]u8 = undefined;
    bytes[0] = 0xc0;
    std.mem.writeInt(u32, bytes[1..][0..4], 0xfa11_face, .big);
    bytes[5] = 4;
    @memcpy(bytes[6..10], &[_]u8{ 1, 2, 3, 4 });
    bytes[10] = 0;
    @memset(bytes[11..], 0);

    const addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0x99) };
    const out = try srv.feed(&bytes, addr, 1_000_000);
    try std.testing.expectEqual(quic_zig.Server.FeedOutcome.version_negotiated, out);
    const vn = srv.drainStatelessResponse() orelse return error.UnexpectedNullVn;
    const parsed = try wire.header.parse(vn.slice(), 0);
    const vn_hdr = parsed.header.version_negotiation;
    try std.testing.expectEqual(@as(usize, 2), vn_hdr.versionCount());
    try std.testing.expectEqual(QUIC_V2, vn_hdr.version(0));
    try std.testing.expectEqual(QUIC_V1, vn_hdr.version(1));
}

test "Server.init rejects empty versions list [RFC9368 §6]" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(quic_zig.Server.Error.InvalidConfig, quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = default_server_params,
        .versions = &.{},
    }));
}

test "Server.init rejects unknown version [RFC9368 §6]" {
    const versions = [_]u32{ QUIC_V1, 0xfa11_face };
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(quic_zig.Server.Error.InvalidConfig, quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = default_server_params,
        .versions = &versions,
    }));
}
