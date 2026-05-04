//! Phase 5 acceptance: two `nullq.Connection`s open a stream
//! after the TLS handshake, the client streams bytes through
//! `Connection.poll`, the server consumes them via
//! `Connection.handle` + `streamRead`, and ACKs flow back to the
//! client so the send buffer drains.
//!
//! No simulated loss yet — that exercise lands when the
//! Connection wires `loss_recovery.detectLosses` into a tick
//! loop. This test is the integration "smoke": every primitive
//! (key derivation, packet protection, frame codec, send/recv
//! streams, ACK processing) cooperates over the same Connection.

const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");

const test_cert_pem = @embedFile("../data/test_cert.pem");
const test_key_pem = @embedFile("../data/test_key.pem");

const ClientCid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
const ServerCid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99 };

fn handshake(allocator: std.mem.Allocator, client: *nullq.Connection, server: *nullq.Connection) !void {
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    _ = allocator;
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
}

fn buildContexts(
    server_tls: *boringssl.tls.Context,
    client_tls: *boringssl.tls.Context,
) !void {
    const protos = [_][]const u8{"hq-test"};
    server_tls.* = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    try server_tls.loadCertChainAndKey(test_cert_pem, test_key_pem);
    client_tls.* = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
}

test "client streams 16 KiB to server through poll/handle" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
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
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    // Wire CIDs. Client writes packets with peer-DCID = ServerCid;
    // server expects to see ServerCid at the matching length on
    // incoming bytes (the local_dcid_len for the receiver). Same
    // logic in reverse.
    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // Client opens a bidi stream and writes 16 KiB of pseudo-random
    // data. The 16 KiB is far more than fits in one MTU, so this
    // exercises multi-packet send + ACK + buffer drain.
    const total: usize = 16 * 1024;
    var data: [total]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x42);
    prng.random().bytes(&data);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, &data);
    try client.streamFinish(0);

    // Drive the loop. Each iteration: client emits a packet (if it
    // can), server consumes it; server emits an ACK packet, client
    // consumes that. We bound iterations to avoid infinite loops on
    // bug.
    var pkt: [2048]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var consumed: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;

    while (consumed < total) : (iters += 1) {
        try std.testing.expect(iters < 200_000); // safety bound

        if (try client.poll(&pkt, now_us)) |n| {
            try server.handle(pkt[0..n], null, now_us);
        }
        if (try server.poll(&pkt, now_us)) |n| {
            try client.handle(pkt[0..n], null, now_us);
        }

        // Drain readable bytes out of the server's stream 0.
        while (true) {
            const got = try server.streamRead(0, &rbuf);
            if (got == 0) break;
            try std.testing.expectEqualSlices(
                u8,
                data[consumed .. consumed + got],
                rbuf[0..got],
            );
            consumed += got;
        }

        now_us += 1_000;
    }

    try std.testing.expectEqual(total, consumed);

    // The client's send-side buffer should now be drained: every
    // byte was acked.
    const cs = client.stream(0).?;
    try std.testing.expectEqual(@as(u64, total), cs.send.ackedFloor());
    try std.testing.expect(cs.send.fin_acked);

    // The server's receive-side saw the FIN.
    const ss = server.stream(0).?;
    try std.testing.expect(ss.recv.fin_seen);
}

test "DATAGRAM round-trips through the 1-RTT path" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
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
        .initial_max_streams_bidi = 16,
        .max_datagram_frame_size = 1200,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    try client.sendDatagram("hello-from-client");
    try server.sendDatagram("hello-from-server");

    var pkt: [2048]u8 = undefined;
    var rx_c: [256]u8 = undefined;
    var rx_s: [256]u8 = undefined;
    var iters: u32 = 0;
    var now_us: u64 = 1_000_000;

    while (iters < 10) : (iters += 1) {
        if (try client.poll(&pkt, now_us)) |n| try server.handle(pkt[0..n], null, now_us);
        if (try server.poll(&pkt, now_us)) |n| try client.handle(pkt[0..n], null, now_us);
        now_us += 1000;
    }

    const cn = client.receiveDatagram(&rx_c).?;
    try std.testing.expectEqualStrings("hello-from-server", rx_c[0..cn]);
    const sn = server.receiveDatagram(&rx_s).?;
    try std.testing.expectEqualStrings("hello-from-client", rx_s[0..sn]);
}

test "CONNECTION_CLOSE propagates from sender to receiver" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
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
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);
    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // Client closes with an application error.
    client.close(false, 0x42, "shutting down");
    try std.testing.expect(!client.isClosed());

    var pkt: [2048]u8 = undefined;
    var iters: u32 = 0;
    while (iters < 10 and !server.isClosed()) : (iters += 1) {
        if (try client.poll(&pkt, 1_000_000)) |n| {
            try server.handle(pkt[0..n], null, 1_000_000);
        }
        if (try server.poll(&pkt, 1_000_000)) |n| {
            try client.handle(pkt[0..n], null, 1_000_000);
        }
    }
    try std.testing.expect(client.isClosed());
    try std.testing.expect(server.isClosed());
}

test "STOP_SENDING propagates and resets the sender's stream" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
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
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);
    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, "data the server doesn't want");

    // Server tells client to stop sending stream 0.
    try server.streamStopSending(0, 0xff);

    var pkt: [2048]u8 = undefined;
    var iters: u32 = 0;
    while (iters < 8) : (iters += 1) {
        if (try server.poll(&pkt, 1_000_000)) |n| try client.handle(pkt[0..n], null, 1_000_000);
        if (try client.poll(&pkt, 1_000_000)) |n| try server.handle(pkt[0..n], null, 1_000_000);
    }

    // Client's send half should have sent RESET_STREAM and observed
    // the peer ACK it.
    const cs = client.stream(0).?;
    try std.testing.expectEqual(nullq.conn.send_stream.State.reset_recvd, cs.send.state);
    try std.testing.expect(cs.send.reset != null);
    try std.testing.expectEqual(@as(u64, 0xff), cs.send.reset.?.error_code);
}

test "client streams 512 KiB to server (regression for upload stall)" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    // Use the same TPs nullq-peer advertises so we exercise the same
    // flow-control limits the dev's go-quic-peer interop uses.
    const tp: nullq.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 8 * 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 8 * 1024 * 1024,
        .initial_max_stream_data_uni = 1024 * 1024,
        .initial_max_streams_bidi = 256,
        .initial_max_streams_uni = 256,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    const total: usize = 512 * 1024;
    var data = try allocator.alloc(u8, total);
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0xfeed);
    prng.random().bytes(data);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, data);
    try client.streamFinish(0);

    var pkt: [2048]u8 = undefined;
    var rbuf: [8192]u8 = undefined;
    var consumed: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;

    while (consumed < total) : (iters += 1) {
        try std.testing.expect(iters < 2_000_000);

        if (try client.poll(&pkt, now_us)) |n| try server.handle(pkt[0..n], null, now_us);
        if (try server.poll(&pkt, now_us)) |n| try client.handle(pkt[0..n], null, now_us);

        while (true) {
            const got = try server.streamRead(0, &rbuf);
            if (got == 0) break;
            try std.testing.expectEqualSlices(u8, data[consumed .. consumed + got], rbuf[0..got]);
            consumed += got;
        }
        now_us += 1_000;
    }

    try std.testing.expectEqual(total, consumed);
    const cs = client.stream(0).?;
    try std.testing.expectEqual(@as(u64, total), cs.send.ackedFloor());
}

test "PATH_CHALLENGE → PATH_RESPONSE validates the path round-trip" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
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
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // Client begins path validation with a known token.
    const token: [8]u8 = .{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 1, 2 };
    try client.probePath(token, 1_000_000, 100_000);
    try std.testing.expect(!client.isPathValidated());

    var pkt: [2048]u8 = undefined;
    var iters: u32 = 0;
    var now_us: u64 = 1_000_000;

    while (iters < 10 and !client.isPathValidated()) : (iters += 1) {
        if (try client.poll(&pkt, now_us)) |n| try server.handle(pkt[0..n], null, now_us);
        if (try server.poll(&pkt, now_us)) |n| try client.handle(pkt[0..n], null, now_us);
        now_us += 1000;
    }

    try std.testing.expect(client.isPathValidated());
}

test "client streams 16 KiB to server with 10% simulated loss" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
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
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    const total: usize = 16 * 1024;
    var data: [total]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc0d3);
    prng.random().bytes(&data);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, &data);
    try client.streamFinish(0);

    var pkt: [2048]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var consumed: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    const drop_pct: u32 = 10;

    while (consumed < total) : (iters += 1) {
        try std.testing.expect(iters < 500_000);

        try client.tick(now_us);
        try server.tick(now_us);

        if (try client.poll(&pkt, now_us)) |n| {
            const drop = prng.random().intRangeAtMost(u32, 0, 99) < drop_pct;
            if (!drop) try server.handle(pkt[0..n], null, now_us);
        }
        if (try server.poll(&pkt, now_us)) |n| {
            const drop = prng.random().intRangeAtMost(u32, 0, 99) < drop_pct;
            if (!drop) try client.handle(pkt[0..n], null, now_us);
        }

        // Drain readable bytes.
        while (true) {
            const got = try server.streamRead(0, &rbuf);
            if (got == 0) break;
            try std.testing.expectEqualSlices(
                u8,
                data[consumed .. consumed + got],
                rbuf[0..got],
            );
            consumed += got;
        }

        now_us += 1_000;
    }

    try std.testing.expectEqual(total, consumed);
    const cs = client.stream(0).?;
    try std.testing.expectEqual(@as(u64, total), cs.send.ackedFloor());
    try std.testing.expect(cs.send.fin_acked);
    const ss = server.stream(0).?;
    try std.testing.expect(ss.recv.fin_seen);
}
