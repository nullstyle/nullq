//! Phase 5b acceptance: the QUIC handshake completes by exchanging
//! real Initial/Handshake/1-RTT datagrams between two
//! `nullq.Connection`s — no `peer.inbox` shortcut. CRYPTO frames
//! flow through `poll` (CRYPTO frame inside Initial/Handshake long-
//! header packets) and `handle` (decrypt → dispatch CRYPTO → feed
//! TLS via `provideQuicData`).
//!
//! Goal: once this test passes, a real Go QUIC peer can interop
//! with us over UDP — the in-process pipe is no longer load-bearing.

const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

const InitialDcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
const ClientScid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
const ServerScid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

test "client + server handshake via real datagram exchange" {
    const allocator = std.testing.allocator;

    // Use the QUIC interop ALPN that go-quic-peer expects.
    const protos = [_][]const u8{"quic-interop/1"};
    var server_tls = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    defer server_tls.deinit();
    try server_tls.loadCertChainAndKey(test_cert_pem, test_key_pem);

    var client_tls = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    // Crucially: NO `client.peer = &server` here. Bytes only move
    // through poll/handle.

    // Client picks an initial random DCID (used to derive Initial
    // keys) plus its own SCID. The peer_dcid for the very first
    // outbound packet is the same random DCID — the server will
    // tell us its real SCID in its first Initial response, and we'll
    // switch to that automatically inside handleInitial.
    try client.setLocalScid(&ClientScid);
    try client.setInitialDcid(&InitialDcid);
    try client.setPeerDcid(&InitialDcid);

    // Server only knows its own SCID up front; it discovers
    // peer_dcid + initial_dcid from the first incoming Initial.
    try server.setLocalScid(&ServerScid);

    const tp: nullq.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
        .max_datagram_frame_size = 1200,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    // Kick the client by stepping its handshake once — that fires
    // SSL_do_handshake → add_handshake_data → ClientHello bytes
    // accumulate in client.outbox[initial]. The next poll will
    // pack them into a properly-protected Initial packet.
    try client.advance();

    var buf_c2s: [2048]u8 = undefined;
    var buf_s2c: [2048]u8 = undefined;
    var iters: u32 = 0;
    var now_us: u64 = 1_000_000;

    while (iters < 100) : (iters += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        if (try client.poll(&buf_c2s, now_us)) |n| {
            try server.handle(buf_c2s[0..n], null, now_us);
        }
        if (try server.poll(&buf_s2c, now_us)) |n| {
            try client.handle(buf_s2c[0..n], null, now_us);
        }
        now_us += 10_000;
    }

    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
    try std.testing.expectEqualSlices(u8, &ServerScid, client.peer_dcid.slice());
    try std.testing.expectEqualSlices(u8, &ServerScid, client.paths.get(0).?.path.peer_cid.slice());

    // Application-level keys derived on both sides.
    try std.testing.expect(client.haveSecret(.application, .read));
    try std.testing.expect(client.haveSecret(.application, .write));
    try std.testing.expect(server.haveSecret(.application, .read));
    try std.testing.expect(server.haveSecret(.application, .write));

    // Each side now has the peer's transport parameters as a typed
    // value. Verifying decode against the values we sent confirms
    // the §18 codec made the round-trip cleanly through TLS.
    const client_view = (try server.peerTransportParams()).?;
    try std.testing.expectEqual(@as(u64, 30_000), client_view.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 1 << 20), client_view.initial_max_data);
    try std.testing.expectEqual(@as(u64, 1200), client_view.max_datagram_frame_size);
    try std.testing.expectEqual(@as(u64, 4), client_view.active_connection_id_limit);

    const server_view = (try client.peerTransportParams()).?;
    try std.testing.expectEqual(@as(u64, 30_000), server_view.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 100), server_view.initial_max_streams_bidi);

    // ALPN was negotiated to the QUIC interop protocol.
    try std.testing.expectEqualStrings("quic-interop/1", client.inner.alpnSelected().?);
    try std.testing.expectEqualStrings("quic-interop/1", server.inner.alpnSelected().?);

    // No alerts.
    try std.testing.expectEqual(@as(?u8, null), client.alert);
    try std.testing.expectEqual(@as(?u8, null), server.alert);
}
