//! Regression coverage for connection-close source attribution
//! across a real `nullq.Server` ↔ `nullq.Client` handshake.
//!
//! null3's integration suite caught a regression where the receiving
//! end of a CONNECTION_CLOSE was reporting `CloseSource.local` instead
//! of `.peer`. Bug should be reproducible inside nullq using the same
//! Server/Client pair driving used in `server_client_handshake.zig`.

const std = @import("std");
const nullq = @import("nullq");
const common = @import("common.zig");

fn pumpClientToServer(
    cli: *nullq.Client,
    srv: *nullq.Server,
    rx: []u8,
    addr: nullq.conn.path.Address,
    now_us: u64,
) !usize {
    var n: usize = 0;
    while (try cli.conn.poll(rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
        n += 1;
    }
    return n;
}

fn pumpServerToClient(
    srv: *nullq.Server,
    cli: *nullq.Client,
    rx: []u8,
    now_us: u64,
) !usize {
    var n: usize = 0;
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(rx, now_us)) |len| {
            try cli.conn.handle(rx[0..len], null, now_us);
            n += 1;
        }
    }
    return n;
}

test "peer-initiated CONNECTION_CLOSE attributes source=peer on receiver" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        // Keep the reason phrase on the wire so the receiver can
        // observe it (default redacts per hardening guide §9).
        .reveal_close_reason_on_wire = true,
    });
    defer srv.deinit();

    var cli = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xab) };

    try cli.conn.advance();

    var step: u32 = 0;
    const max_steps: u32 = 32;
    while (step < max_steps) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and srv.iterator()[0].conn.handshakeDone()) break;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());

    // Server-initiated application-space close.
    const slot = srv.iterator()[0];
    slot.conn.close(false, 0x100, "server shutdown");

    // Server's local view: source = local.
    {
        const ev = slot.conn.closeEvent().?;
        try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
        try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.application, ev.error_space);
        try std.testing.expectEqual(@as(u64, 0x100), ev.error_code);
    }

    // Pump until the client observes the close.
    var step2: u32 = step;
    while (step2 < step + max_steps) : (step2 += 1) {
        const now_us: u64 = @as(u64, step2) * 1_000;
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.closeEvent() != null) break;
    }

    const cli_ev = cli.conn.closeEvent() orelse return error.ClientNeverObservedClose;
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.peer, cli_ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.application, cli_ev.error_space);
    try std.testing.expectEqual(@as(u64, 0x100), cli_ev.error_code);
    try std.testing.expectEqualStrings("server shutdown", cli_ev.reason);
}
