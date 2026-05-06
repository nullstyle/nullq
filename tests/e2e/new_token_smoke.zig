//! End-to-end smoke for NEW_TOKEN issuance (RFC 9000 §8.1.3 /
//! hardening guide §4.3 follow-up B1).
//!
//! Three scenarios drive the full Server↔Client pump loop and assert
//! on the NEW_TOKEN lifecycle:
//!
//!   1. With `Server.Config.new_token_key` set, a successful handshake
//!      produces exactly one NEW_TOKEN frame on the wire and the
//!      embedder's client-side callback receives the bytes.
//!   2. A returning client that presents the captured NEW_TOKEN on its
//!      first Initial skips the Retry round-trip — `Server.feed`
//!      accepts the Initial directly without queuing a Retry.
//!   3. A returning client that presents an *expired* NEW_TOKEN falls
//!      through to the Retry gate; the server queues a Retry
//!      (when `retry_token_key` is configured) instead of accepting.

const std = @import("std");
const nullq = @import("nullq");
const common = @import("common.zig");

const new_token_key: nullq.conn.NewTokenKey = .{
    0xaa, 0x11, 0xbb, 0x22, 0xcc, 0x33, 0xdd, 0x44,
    0xee, 0x55, 0xff, 0x66, 0x10, 0x77, 0x21, 0x88,
    0x32, 0x99, 0x43, 0xa0, 0x54, 0xb1, 0x65, 0xc2,
    0x76, 0xd3, 0x87, 0xe4, 0x98, 0xf5, 0x09, 0x06,
};

const retry_key: nullq.RetryTokenKey = .{
    0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
    0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
    0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
    0xf2, 0x83, 0x1d, 0xb6, 0x95, 0x77, 0x40, 0x29,
};

/// Capture-on-callback singleton for the test. The callback runs
/// on the receive path, so we copy the bytes into a stable buffer.
const TokenCapture = struct {
    /// Up to one captured token per harness instance. The captured
    /// length is `len`; bytes past that are uninitialised.
    bytes: [256]u8 = @splat(0),
    len: usize = 0,
    fired: bool = false,

    fn callback(user_data: ?*anyopaque, token: []const u8) void {
        const self: *TokenCapture = @ptrCast(@alignCast(user_data.?));
        @memcpy(self.bytes[0..token.len], token);
        self.len = token.len;
        self.fired = true;
    }
};

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

test "Server emits NEW_TOKEN to handshake-confirmed client" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .new_token_key = new_token_key,
    });
    defer srv.deinit();

    var capture: TokenCapture = .{};
    var cli = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .new_token_callback = TokenCapture.callback,
        .new_token_user_data = &capture,
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xaa) };
    try cli.conn.advance();

    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (capture.fired) break;
    }

    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());
    try std.testing.expect(capture.fired);
    // The token must be exactly `new_token.max_token_len` (96) —
    // nullq mints fixed-shape tokens. A different length means the
    // server emitted from a different code path.
    try std.testing.expectEqual(@as(usize, nullq.conn.new_token.max_token_len), capture.len);
    // The slot's latch must be set so a second datagram doesn't
    // re-mint.
    try std.testing.expect(srv.iterator()[0].new_token_emitted);
}

test "Client with stored NEW_TOKEN skips Retry on next connection" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    // Phase 1 — first connection: capture the NEW_TOKEN.
    // No `retry_token_key` here so the first connection gets a
    // straight handshake without the Retry round-trip; we only care
    // about the NEW_TOKEN bytes the server emits after handshake
    // confirmation.
    var captured_token: [256]u8 = @splat(0);
    var captured_len: usize = 0;
    {
        var srv = try nullq.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = common.test_cert_pem,
            .tls_key_pem = common.test_key_pem,
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
            .new_token_key = new_token_key,
        });
        defer srv.deinit();

        var capture: TokenCapture = .{};
        var cli = try nullq.Client.connect(.{
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
            .new_token_callback = TokenCapture.callback,
            .new_token_user_data = &capture,
        });
        defer cli.deinit();

        var rx: [4096]u8 = undefined;
        const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xab) };
        try cli.conn.advance();

        var step: u32 = 0;
        while (step < 32) : (step += 1) {
            const now_us: u64 = @as(u64, step) * 1_000;
            _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
            while (srv.drainStatelessResponse()) |_| {}
            _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            if (capture.fired) break;
        }

        try std.testing.expect(capture.fired);
        @memcpy(captured_token[0..capture.len], capture.bytes[0..capture.len]);
        captured_len = capture.len;
    }

    // Phase 2 — fresh server (same key), fresh client presents the
    // stored NEW_TOKEN on its first Initial. Server's Retry gate
    // accepts directly: no `.retry_sent` outcome, no stateless
    // responses queued.
    var srv2 = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .new_token_key = new_token_key,
        .retry_token_key = retry_key,
    });
    defer srv2.deinit();

    var cli2 = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .new_token = captured_token[0..captured_len],
    });
    defer cli2.deinit();

    var rx: [4096]u8 = undefined;
    // SAME peer address as Phase 1 — NEW_TOKEN binds to the
    // address; a different `peer_addr` would invalidate the token.
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xab) };
    try cli2.conn.advance();

    // Pump exactly one client→server datagram (the first Initial)
    // and check the outcome. The server should NOT respond with a
    // Retry.
    const len = (try cli2.conn.poll(&rx, 1_000_000)).?;
    const outcome = try srv2.feed(rx[0..len], peer_addr, 1_000_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.accepted, outcome);
    try std.testing.expectEqual(@as(usize, 0), srv2.statelessResponseCount());

    // Drain the rest of the handshake to make sure NEW_TOKEN-skip
    // doesn't break later flights.
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, 2_000_000) + @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli2, &srv2, &rx, peer_addr, now_us);
        while (srv2.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv2, &cli2, &rx, now_us);
        try srv2.tick(now_us);
        try cli2.conn.tick(now_us);
        if (cli2.conn.handshakeDone() and srv2.iterator().len > 0) {
            if (srv2.iterator()[0].conn.handshakeDone()) break;
        }
    }
    try std.testing.expect(cli2.conn.handshakeDone());
    try std.testing.expect(srv2.iterator()[0].conn.handshakeDone());
}

test "Server rejects expired NEW_TOKEN and falls through to Retry" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    // Mint an obviously-expired NEW_TOKEN by setting the issue
    // timestamp far in the past with a tiny lifetime.
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xcd) };
    var addr_buf: [22]u8 = undefined;
    @memcpy(&addr_buf, &peer_addr.bytes);
    var token: nullq.conn.NewTokenBlob = undefined;
    _ = try nullq.conn.new_token.mint(&token, .{
        .key = &new_token_key,
        .now_us = 1_000_000,
        .lifetime_us = 1, // expires effectively immediately
        .client_address = &addr_buf,
    });

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .new_token_key = new_token_key,
        .retry_token_key = retry_key,
    });
    defer srv.deinit();

    var cli = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .new_token = &token,
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    try cli.conn.advance();

    // First Initial carries the expired token. Validation logic:
    // NEW_TOKEN.validate returns `.expired` (not `.malformed`), but
    // applyRetryGate treats every non-`.valid` NEW_TOKEN result as
    // "fall through to Retry". Because the Retry-state table has
    // no entry for this address yet (no prior round-trip), the
    // Retry path mints + queues a fresh Retry → outcome is
    // `.retry_sent`.
    const len = (try cli.conn.poll(&rx, 999_999_999)).?;
    const outcome = try srv.feed(rx[0..len], peer_addr, 999_999_999);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.retry_sent, outcome);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), srv.statelessResponseCount());
    // Drain so deinit doesn't trip the bounded-queue assertion.
    while (srv.drainStatelessResponse()) |_| {}
}
