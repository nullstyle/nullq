//! Phase 4 acceptance: two `quic_zig.Connection`s complete a TLS 1.3
//! handshake through a mock transport.
//!
//! No QUIC packet protection is involved — just CRYPTO bytes
//! shuttled through `tls.quic.Method` callbacks. Validates the
//! Connection ↔ BoringSSL bridge end-to-end.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

test "two quic_zig.Connections handshake to TLS 1.3 finished with application keys" {
    const allocator = std.testing.allocator;

    const protos = [_][]const u8{"hq-test"};

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

    var client = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try quic_zig.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    // Bind after the Connection values are at their final stack
    // address — bind() stashes &self in SSL ex-data, so it has to
    // happen post-move.
    try client.bind();
    try server.bind();

    client.peer = &server;
    server.peer = &client;

    // Both sides advertise typed transport parameters per RFC 9000 §18.
    const params: quic_zig.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
    try client.setTransportParams(params);
    try server.setTransportParams(params);

    // Both connections should be in QUIC mode immediately after init.
    try std.testing.expect(client.isQuic());
    try std.testing.expect(server.isQuic());

    // Drive the handshake.
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }

    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());

    // Both sides exported AEAD keys for the application encryption
    // level. (Phase 4 records that the secret was delivered; the
    // actual HKDF-Expand-Label key derivation lives in Phase 5's
    // packet-protection layer.)
    try std.testing.expect(client.haveSecret(.application, .read));
    try std.testing.expect(client.haveSecret(.application, .write));
    try std.testing.expect(server.haveSecret(.application, .read));
    try std.testing.expect(server.haveSecret(.application, .write));

    // No alerts.
    try std.testing.expectEqual(@as(?u8, null), client.alert);
    try std.testing.expectEqual(@as(?u8, null), server.alert);
}
