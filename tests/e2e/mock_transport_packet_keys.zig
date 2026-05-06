//! Phase 5 acceptance fragment: after the handshake, both sides
//! derive byte-equal application-level packet keys (client_write
//! == server_read and vice versa) and round-trip a 1-RTT
//! protected packet through `seal1Rtt` + `open1Rtt`.

const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

test "1-RTT keys derive cross-consistently and round-trip a packet" {
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

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const params: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(params);
    try server.setTransportParams(params);

    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());

    // Both sides derive 1-RTT keys for both directions.
    const c_write = (try client.packetKeys(.application, .write)).?;
    const c_read = (try client.packetKeys(.application, .read)).?;
    const s_write = (try server.packetKeys(.application, .write)).?;
    const s_read = (try server.packetKeys(.application, .read)).?;

    // TLS 1.3 makes the client's write secret == server's read secret.
    try std.testing.expectEqualSlices(u8, c_write.keySlice(), s_read.keySlice());
    try std.testing.expectEqualSlices(u8, &c_write.iv, &s_read.iv);
    try std.testing.expectEqualSlices(u8, c_write.hpSlice(), s_read.hpSlice());

    try std.testing.expectEqualSlices(u8, s_write.keySlice(), c_read.keySlice());
    try std.testing.expectEqualSlices(u8, &s_write.iv, &c_read.iv);
    try std.testing.expectEqualSlices(u8, s_write.hpSlice(), c_read.hpSlice());

    // Cipher-suite plumbing reports the same.
    try std.testing.expectEqual(
        nullq.conn.state.Suite.aes128_gcm_sha256,
        client.cipherSuite(.application, .write).?,
    );
    try std.testing.expectEqual(
        nullq.conn.state.Suite.aes128_gcm_sha256,
        server.cipherSuite(.application, .read).?,
    );

    // Round-trip a synthetic 1-RTT packet client→server.
    const dcid: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xfe, 0xed };
    const payload = "client says hello over 1-RTT — frames go here";

    var buf: [256]u8 = undefined;
    const n = try nullq.wire.short_packet.seal1Rtt(&buf, .{
        .dcid = &dcid,
        .pn = 1,
        .payload = payload,
        .keys = &c_write,
    });

    var pt: [256]u8 = undefined;
    const opened = try nullq.wire.short_packet.open1Rtt(&pt, buf[0..n], .{
        .dcid_len = dcid.len,
        .keys = &s_read,
        .largest_received = 0,
    });
    try std.testing.expectEqual(@as(u64, 1), opened.pn);
    try std.testing.expectEqualSlices(u8, payload, opened.payload);

    // And the reverse direction.
    const reply = "server replies on 1-RTT";
    const m = try nullq.wire.short_packet.seal1Rtt(&buf, .{
        .dcid = &dcid,
        .pn = 1,
        .payload = reply,
        .keys = &s_write,
    });
    const opened2 = try nullq.wire.short_packet.open1Rtt(&pt, buf[0..m], .{
        .dcid_len = dcid.len,
        .keys = &c_read,
        .largest_received = 0,
    });
    try std.testing.expectEqualSlices(u8, reply, opened2.payload);
}

test "frames round-trip end-to-end through 1-RTT seal/open" {
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

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }

    const c_write = (try client.packetKeys(.application, .write)).?;
    const s_read = (try server.packetKeys(.application, .read)).?;

    // Build a payload: PING, MAX_DATA, STREAM(stream_id=4, "hello", FIN).
    var fbuf: [128]u8 = undefined;
    var fpos: usize = 0;
    fpos += try nullq.frame.encode(fbuf[fpos..], .{ .ping = .{} });
    fpos += try nullq.frame.encode(fbuf[fpos..], .{ .max_data = .{ .maximum_data = 1 << 20 } });
    fpos += try nullq.frame.encode(fbuf[fpos..], .{ .stream = .{
        .stream_id = 4,
        .data = "hello",
        .has_offset = false,
        .has_length = true,
        .fin = true,
    } });

    const dcid: [4]u8 = .{ 1, 2, 3, 4 };
    var pkt: [256]u8 = undefined;
    const n = try nullq.wire.short_packet.seal1Rtt(&pkt, .{
        .dcid = &dcid,
        .pn = 7,
        .payload = fbuf[0..fpos],
        .keys = &c_write,
    });

    var pt: [256]u8 = undefined;
    const opened = try nullq.wire.short_packet.open1Rtt(&pt, pkt[0..n], .{
        .dcid_len = dcid.len,
        .keys = &s_read,
        .largest_received = 0,
    });
    try std.testing.expectEqual(@as(u64, 7), opened.pn);

    // Walk frames the receiver gets.
    var saw_ping = false;
    var saw_max_data: ?u64 = null;
    var stream_payload: ?[]const u8 = null;
    var stream_fin = false;

    var it = nullq.frame.iter(opened.payload);
    while (try it.next()) |f| switch (f) {
        .ping => saw_ping = true,
        .max_data => |md| saw_max_data = md.maximum_data,
        .stream => |s| {
            stream_payload = s.data;
            stream_fin = s.fin;
        },
        .padding => {},
        else => {},
    };

    try std.testing.expect(saw_ping);
    try std.testing.expectEqual(@as(?u64, 1 << 20), saw_max_data);
    try std.testing.expect(stream_payload != null);
    try std.testing.expectEqualStrings("hello", stream_payload.?);
    try std.testing.expect(stream_fin);
}
