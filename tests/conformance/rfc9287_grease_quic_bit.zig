//! RFC 9287 — Greasing the QUIC Bit.
//!
//! RFC 9287 lets endpoints opt in to randomizing the second-most
//! significant bit of the first byte (the "QUIC Bit", mask 0x40) on
//! long- and short-header packets. Both peers signal tolerance with
//! the `grease_quic_bit` transport parameter (codepoint 0x2ab2,
//! zero-length value); once both sides advertised it, an endpoint
//! SHOULD set the bit to an unpredictable value per packet, and MUST
//! accept any value on receive.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9287 §3 ¶1   MUST       encoder may set QUIC Bit to 0 once peer
//!                              advertised support (round-trips through
//!                              encode/parse with bit cleared)
//!   RFC9287 §3 ¶1   MUST       decoder accepts a long-header packet
//!                              with QUIC Bit = 0
//!   RFC9287 §3 ¶1   MUST       decoder accepts a short-header packet
//!                              with QUIC Bit = 0
//!   RFC9287 §3 ¶1   MUST       decoder accepts QUIC Bit = 1 (the v1
//!                              wire-required default) without grease
//!                              negotiation
//!   RFC9287 §3 ¶3   MUST       endpoint that did NOT receive
//!                              `grease_quic_bit` from the peer keeps
//!                              the QUIC Bit set to 1
//!   RFC9287 §6.1    MUST       transport parameter codepoint = 0x2ab2
//!   RFC9287 §6.1    MUST       parameter is encoded as a zero-length flag
//!   RFC9287 §6.1    MUST       parameter omitted by default (false)
//!   RFC9287 §6.1    MUST       round-trips through encode → decode
//!   RFC9287 §6.1    NORMATIVE  either client or server may advertise
//!   RFC9287 §6.1    MUST NOT   accept a non-empty value (rejected as
//!                              TRANSPORT_PARAMETER_ERROR)
//!
//! Out of scope here (covered elsewhere):
//!   RFC9287 §3 ¶2   "unpredictable value" SHOULD — implementation
//!                   uses BoringSSL's CSPRNG (`RAND_bytes`) for the
//!                   per-packet draw; covered transitively by the
//!                   src/conn unit tests for `nextQuicBit()`.
//!   RFC9287 §3 ¶3   Stateless-reset packets are unlikely to grease
//!                   the bit — quic_zig's stateless-reset path uses
//!                   the spec-mandated 0x40 prefix already (RFC 9000
//!                   §10.3); not affected by RFC 9287.
//!   RFC9287 §3 ¶4   NEW_TOKEN-derived "early grease" optimization on
//!                   client first-flight Initials — an optional
//!                   future extension; v0.1 is conservative.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const wire = quic_zig.wire;
const header = wire.header;
const long_packet = wire.long_packet;
const short_packet = wire.short_packet;
const transport_params = quic_zig.tls.transport_params;
const initial_mod = wire.initial;
const Connection = quic_zig.conn.Connection;

// ---------------------------------------------------------------- §6.1 transport parameter

test "MUST register grease_quic_bit at IANA transport-parameter id 0x2ab2 [RFC9287 §6.1]" {
    // RFC 9287 §6.1 fixes the codepoint at 0x2ab2 (a 2-byte varint).
    // Both endpoints have to agree on this exact integer or the
    // negotiation never converges.
    try std.testing.expectEqual(@as(u64, 0x2ab2), transport_params.Id.grease_quic_bit);
}

test "MUST encode grease_quic_bit as a zero-length flag [RFC9287 §6.1]" {
    // RFC 9287 §6.1: "An endpoint that includes this transport
    // parameter MUST send it with an empty value." Our encoder
    // emits the parameter only when the flag is `true`, with a
    // zero-length value field.
    const sent: transport_params.Params = .{
        .grease_quic_bit = true,
        // initial_source_connection_id present so a future role-aware
        // decode would still pass §7.3 ¶1; not required for the wire
        // codec test itself.
    };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);

    // The blob is exactly two bytes: id varint (2-byte form, big-
    // endian: 0x6a 0xb2 — high two bits 01 mark a 2-byte varint
    // carrying value 0x2ab2) plus a 1-byte length varint of 0.
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 0x6a), buf[0]);
    try std.testing.expectEqual(@as(u8, 0xb2), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[2]);
}

test "MUST default grease_quic_bit to false (parameter absent) [RFC9287 §6.1]" {
    // The default-only `Params{}` encodes to an empty blob — confirms
    // the new flag respects the encoder-elides-defaults policy.
    const default_only: transport_params.Params = .{};
    try std.testing.expectEqual(false, default_only.grease_quic_bit);

    var buf: [16]u8 = undefined;
    const n = try default_only.encode(&buf);
    try std.testing.expectEqual(@as(usize, 0), n);

    const decoded = try transport_params.Params.decode(buf[0..n]);
    try std.testing.expectEqual(false, decoded.grease_quic_bit);
}

test "MUST round-trip grease_quic_bit through encode → decode [RFC9287 §6.1]" {
    const sent: transport_params.Params = .{ .grease_quic_bit = true };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    const got = try transport_params.Params.decode(buf[0..n]);
    try std.testing.expect(got.grease_quic_bit);
}

test "NORMATIVE either side may advertise grease_quic_bit [RFC9287 §6.1]" {
    // RFC 9287 §6.1 places no role restriction on the parameter.
    // Confirm that the role-aware `decodeAs` accepts a
    // grease-advertising blob from both a client and a server.
    const example_scid = transport_params.ConnectionId.fromSlice(&.{ 1, 2, 3, 4 });

    const client_sent: transport_params.Params = .{
        .initial_source_connection_id = example_scid,
        .grease_quic_bit = true,
    };
    var buf: [64]u8 = undefined;
    var n = try client_sent.encode(&buf);
    const got_client = try transport_params.decodeAs(buf[0..n], .{ .role = .client });
    try std.testing.expect(got_client.grease_quic_bit);

    const server_sent: transport_params.Params = .{
        .initial_source_connection_id = example_scid,
        .original_destination_connection_id = example_scid,
        .grease_quic_bit = true,
    };
    n = try server_sent.encode(&buf);
    const got_server = try transport_params.decodeAs(
        buf[0..n],
        .{ .role = .server, .server_sent_retry = false },
    );
    try std.testing.expect(got_server.grease_quic_bit);
}

test "MUST NOT accept grease_quic_bit with a non-empty value [RFC9287 §6.1]" {
    // RFC 9287 §6.1: a parameter with a non-empty value is treated
    // as TRANSPORT_PARAMETER_ERROR. We surface that as
    // `Error.InvalidValue` from the wire codec; the role-aware path
    // then maps any structural decode error to a connection close at
    // the connection layer.
    //
    // Wire: id varint(0x2ab2) | length varint(1) | value 0xff.
    const blob = [_]u8{ 0x6a, 0xb2, 0x01, 0xff };
    try std.testing.expectError(
        transport_params.Error.InvalidValue,
        transport_params.Params.decode(&blob),
    );
}

// ---------------------------------------------------------------- §3 wire format

test "MUST allow encoder to clear the QUIC Bit on a long-header packet [RFC9287 §3]" {
    // Build a synthetic Initial header with `quic_bit = 0`, encode
    // it, then parse it back and confirm bit 6 is preserved as 0.
    // The `quic_bit = 0` choice is what an encoder picks for a
    // grease-advertising peer; v1 receivers without grease support
    // would also have to drop it (which is exactly the negotiation
    // gate on the receive side, modeled at the conn layer).
    const dcid = try header.ConnId.fromSlice(&.{ 1, 2, 3, 4 });
    const scid = try header.ConnId.fromSlice(&.{ 5, 6, 7, 8 });
    const h: header.Header = .{ .initial = .{
        .version = 0x00000001,
        .dcid = dcid,
        .scid = scid,
        .token = &.{},
        .pn_length = .one,
        .pn_truncated = 0x00,
        .payload_length = 17, // 1 PN byte + 16 tag bytes
        .reserved_bits = 0,
        .quic_bit = 0,
    } };
    var buf: [64]u8 = undefined;
    const n = try header.encode(&buf, h);

    // First byte: form=1 (0x80), QUIC Bit=0 (0x00), Initial type=0,
    // reserved=0, pn_len-1=0 → exactly 0x80.
    try std.testing.expectEqual(@as(u8, 0x80), buf[0]);

    const parsed = try header.parse(buf[0..n], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqual(@as(u1, 0), parsed.header.initial.quic_bit);
}

test "MUST allow encoder to clear the QUIC Bit on a short-header packet [RFC9287 §3]" {
    // Same shape for short headers: bit 7 is the form bit (always 0
    // for short headers), bit 6 is the QUIC Bit.
    const dcid = try header.ConnId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    const h: header.Header = .{ .one_rtt = .{
        .dcid = dcid,
        .pn_length = .one,
        .pn_truncated = 0x42,
        .quic_bit = 0,
    } };
    var buf: [16]u8 = undefined;
    const n = try header.encode(&buf, h);

    // First byte: form=0, QUIC Bit=0, spin=0, reserved=0, key=0,
    // pn_len-1=0 → 0x00.
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);

    const parsed = try header.parse(buf[0..n], 4);
    try std.testing.expect(parsed.header == .one_rtt);
    try std.testing.expectEqual(@as(u1, 0), parsed.header.one_rtt.quic_bit);
}

test "MUST decode a long-header packet whose QUIC Bit is 0 [RFC9287 §3]" {
    // RFC 9287 §3: an endpoint that advertised grease_quic_bit MUST
    // accept a long-header packet whose QUIC Bit is 0. The wire
    // decoder is permissive (it never validates bit 6); confirm
    // an end-to-end seal/open round-trip accepts the cleared bit.
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 1, 2, 3, 4 };
    const payload = "synthetic CRYPTO frame bytes";

    var packet: [2048]u8 = undefined;
    const n = try long_packet.sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = payload,
        .keys = &keys,
        .quic_bit = 0,
    });
    // The header-protected bit 6 of the first byte may have been
    // toggled by HP; what matters for grease is that the receiver
    // doesn't reject the packet on its way through AEAD-open.
    var pt: [2048]u8 = undefined;
    const opened = try long_packet.openInitial(&pt, packet[0..n], .{ .keys = &keys });
    try std.testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
}

test "MUST decode a short-header packet whose QUIC Bit is 0 [RFC9287 §3]" {
    // Same property for the 1-RTT short header: a peer that has
    // negotiated grease MUST accept QUIC Bit = 0 on the wire.
    const secret: [32]u8 = @splat(0x42);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &secret);
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const payload = "frame-bytes";

    var packet: [256]u8 = undefined;
    const n = try short_packet.seal1Rtt(&packet, .{
        .dcid = &dcid,
        .pn = 1,
        .payload = payload,
        .keys = &keys,
        .quic_bit = 0,
    });

    var pt: [256]u8 = undefined;
    const opened = try short_packet.open1Rtt(&pt, packet[0..n], .{
        .dcid_len = dcid.len,
        .keys = &keys,
        .largest_received = 0,
    });
    try std.testing.expectEqualSlices(u8, payload, opened.payload);
}

test "MUST decode a packet whose QUIC Bit is 1 (default) [RFC9287 §3]" {
    // The default — and what every QUIC v1 peer without grease
    // support emits — is QUIC Bit = 1. Confirm parse round-trips.
    const dcid = try header.ConnId.fromSlice(&.{ 0xde, 0xad });
    const h: header.Header = .{ .initial = .{
        .version = 1,
        .dcid = dcid,
        .scid = dcid,
        .token = &.{},
        .pn_length = .one,
        .pn_truncated = 0,
        .payload_length = 17,
        .quic_bit = 1, // explicit
    } };
    var buf: [64]u8 = undefined;
    const n = try header.encode(&buf, h);
    // First byte: form=1, QUIC=1, type=Initial(0), reserved=0,
    // pn_len-1=0 → 0xc0.
    try std.testing.expectEqual(@as(u8, 0xc0), buf[0]);

    const parsed = try header.parse(buf[0..n], 0);
    try std.testing.expectEqual(@as(u1, 1), parsed.header.initial.quic_bit);
}

test "NORMATIVE peerSupportsGreaseQuicBit() requires both sides to advertise [RFC9287 §3]" {
    // The connection-level negotiation predicate is the gate that
    // controls whether `nextQuicBit()` draws random or always emits 1.
    // RFC 9287 §3: an endpoint MUST NOT clear the QUIC Bit unless it
    // has confirmed peer support — match that with a four-way truth
    // table (local x peer, both flags).
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Neither side advertised — predicate is false.
    conn.local_transport_params.grease_quic_bit = false;
    conn.cached_peer_transport_params = .{ .grease_quic_bit = false };
    try std.testing.expect(!conn.peerSupportsGreaseQuicBit());

    // Local-only — peer hasn't advertised, must NOT grease.
    conn.local_transport_params.grease_quic_bit = true;
    conn.cached_peer_transport_params = .{ .grease_quic_bit = false };
    try std.testing.expect(!conn.peerSupportsGreaseQuicBit());

    // Peer-only — we never told them we'd accept QUIC Bit = 0, so we
    // also can't grease (we don't know our wire would route).
    conn.local_transport_params.grease_quic_bit = false;
    conn.cached_peer_transport_params = .{ .grease_quic_bit = true };
    try std.testing.expect(!conn.peerSupportsGreaseQuicBit());

    // Both advertised — predicate flips on.
    conn.local_transport_params.grease_quic_bit = true;
    conn.cached_peer_transport_params = .{ .grease_quic_bit = true };
    try std.testing.expect(conn.peerSupportsGreaseQuicBit());

    // Pre-handshake state (no cached peer params) is also gated off,
    // matching RFC 9287 §3's "MUST NOT set the QUIC Bit to 0 without
    // knowing whether the peer supports the extension".
    conn.cached_peer_transport_params = null;
    try std.testing.expect(!conn.peerSupportsGreaseQuicBit());
}

test "MUST keep the QUIC Bit at 1 when the peer did not advertise grease [RFC9287 §3 ¶3]" {
    // The encoder's default `quic_bit = 1` is what a non-greasing
    // peer expects. Verify the seal options take this default and
    // the resulting first byte (after HP removal) carries bit 6.
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 1, 2, 3, 4 };
    var packet: [2048]u8 = undefined;
    const n = try long_packet.sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "x",
        .keys = &keys,
        // omit .quic_bit — defaults to 1
    });

    // Open the packet and inspect the post-HP first byte via the
    // parsed header. The seal/open path reconstructs the unprotected
    // first byte before AEAD validates the AAD, so this read is
    // authentic.
    var pt: [2048]u8 = undefined;
    const opened = try long_packet.openInitial(&pt, packet[0..n], .{ .keys = &keys });
    _ = opened;
    // After open, src[0] is the unprotected first byte. Bit 6 = 1.
    try std.testing.expect((packet[0] & 0x40) != 0);
}
