//! Smoke tests for the high-level `nullq.Server` convenience type.
//!
//! These run from the integration-test module so they can
//! `@embedFile` the existing PEM fixtures under `tests/data/` —
//! anything in `src/server.zig` itself can't reach those because
//! they sit outside the published `nullq` package.

const std = @import("std");
const nullq = @import("nullq");

const test_cert_pem = @embedFile("../data/test_cert.pem");
const test_key_pem = @embedFile("../data/test_key.pem");

fn defaultParams() nullq.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
}

test "Server.init + deinit on a real cert/key pair" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

test "Server.feed drops non-Initial bytes silently" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Random bytes that don't parse as a long-header Initial.
    var junk = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd } ++ [_]u8{0} ** 32;
    const outcome = try srv.feed(&junk, null, 0);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // Empty datagrams are also a no-op.
    var empty: [0]u8 = .{};
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, try srv.feed(&empty, null, 1));

    // Calling shutdown / reap on an empty server is also a no-op.
    srv.shutdown(0, "");
    try std.testing.expectEqual(@as(usize, 0), srv.reap());
}

test "Server.feed rejects long-header packets when the table is full" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_concurrent_connections = 0,
    });
    defer srv.deinit();

    // A syntactically plausible long-header byte still gets
    // rejected because the cap is 0.
    var bytes = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 };
    const outcome = try srv.feed(&bytes, null, 0);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.table_full, outcome);
}

test "Server source rate limiter trips after the configured cap" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_initials_per_source_per_window = 3,
        .source_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    // A long-header byte sequence that passes `isInitialLongHeader`
    // (long header bit set, version 1, type=Initial) but fails
    // inside `openSlotFromInitial` because the declared DCID length
    // (21) exceeds the QUIC max of 20. The rate limiter still ticks
    // for each call.
    var initial = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 };
    const addr = nullq.conn.path.Address{ .bytes = @splat(0xab) };

    // First three from this source: each consumes a token, openSlot
    // fails internally, returns generic .dropped.
    for (0..3) |i| {
        const o = try srv.feed(&initial, addr, @intCast(i));
        try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, o);
    }

    // Fourth call from same source: rate limiter fires before
    // openSlot is even attempted.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.rate_limited,
        try srv.feed(&initial, addr, 4),
    );

    // Different source: still has its own budget.
    const other_addr = nullq.conn.path.Address{ .bytes = @splat(0xcd) };
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.dropped,
        try srv.feed(&initial, other_addr, 5),
    );

    // After the window elapses, the original source's budget resets.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.dropped,
        try srv.feed(&initial, addr, 1_500_000),
    );
}
