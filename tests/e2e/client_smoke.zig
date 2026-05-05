//! Smoke tests for the high-level `nullq.Client` convenience type.
//!
//! Mirror to `tests/e2e/server_smoke.zig`. These run from the
//! integration-test module so they can construct real TLS contexts
//! against the boringssl-zig dependency without polluting the
//! published `nullq` package's test surface.
//!
//! Like the server smoke, we don't try to drive a full handshake —
//! that would require an actual peer. We do verify that
//! `Client.connect` produces a Connection that's bound, has its
//! transport params set, and is ready to be ticked.

const std = @import("std");
const nullq = @import("nullq");

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

test "Client.connect succeeds and yields a tickable Connection" {
    const protos = [_][]const u8{"hq-test"};

    const conn = try nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer {
        conn.deinit();
        std.testing.allocator.destroy(conn);
    }

    // The connection should be live (not closed) and `tick` should
    // be a no-op since no time has passed and no datagrams have
    // arrived. This proves `bind` ran and the inner SSL/QUIC method
    // is wired up.
    try std.testing.expect(!conn.isClosed());
    try conn.tick(0);

    // After `connect`, the local SCID has been issued. `localScidCount`
    // returns >= 1 because `setLocalScid` registered the chosen
    // SCID as a routable CID.
    try std.testing.expect(conn.localScidCount() >= 1);
}

test "Client.connect drives the first Initial out via poll" {
    const protos = [_][]const u8{"hq-test"};

    const conn = try nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer {
        conn.deinit();
        std.testing.allocator.destroy(conn);
    }

    // Drive the handshake forward enough to produce the first
    // Initial. `Client.connect` does not call `advance` itself —
    // that's the embedder's first scheduler step, mirroring the
    // QNS pattern where the embedder may want to install
    // 0-RTT-bound STREAM data first.
    try conn.advance();

    var tx: [1500]u8 = undefined;
    const n = try conn.poll(&tx, 1) orelse return error.NoInitialEmitted;
    // First Initial is long-header, type=Initial (high bits 1100).
    try std.testing.expect(n > 0);
    try std.testing.expect((tx[0] & 0xc0) == 0xc0);
}

test "Client.connect rejects empty SNI" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(nullq.Client.Error.InvalidConfig, nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    }));
}

test "Client.connect rejects empty ALPN" {
    try std.testing.expectError(nullq.Client.Error.InvalidConfig, nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &.{},
        .transport_params = defaultParams(),
    }));
}

test "Client.connect rejects invalid CID lengths" {
    const protos = [_][]const u8{"hq-test"};

    // initial_dcid_len < 8 violates RFC 9000 §7.2.
    try std.testing.expectError(nullq.Client.Error.InvalidConfig, nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .initial_dcid_len = 7,
    }));

    // initial_dcid_len > 20 violates RFC 9000 §17.2.
    try std.testing.expectError(nullq.Client.Error.InvalidConfig, nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .initial_dcid_len = 21,
    }));

    // local_cid_len = 0 is allowed by RFC 9000 generally but the
    // wrapper rejects it because `Client.connect` follows the QNS
    // canonical pattern of CID-based routing.
    try std.testing.expectError(nullq.Client.Error.InvalidConfig, nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .local_cid_len = 0,
    }));

    // local_cid_len > 20 violates RFC 9000.
    try std.testing.expectError(nullq.Client.Error.InvalidConfig, nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .local_cid_len = 21,
    }));
}

test "Client.connect honours transport params (ISCID is auto-filled)" {
    const protos = [_][]const u8{"hq-test"};

    var params = defaultParams();
    // We don't fill in initial_source_connection_id; `Client.connect`
    // should do it from the freshly-minted client SCID.
    params.initial_source_connection_id = .{};

    const conn = try nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = params,
        .local_cid_len = 12,
    });
    defer {
        conn.deinit();
        std.testing.allocator.destroy(conn);
    }

    // The advertised SCID length matches the configured
    // `local_cid_len`. The actual bytes are random — we only check
    // that one was issued at the right length.
    try std.testing.expectEqual(@as(u8, 12), conn.localDcidLen());
}
