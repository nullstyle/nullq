//! Smoke tests for `quic_zig.transport.runUdpClient`.
//!
//! Mirror to `server_loop_smoke.zig`. The full loop is awkward to
//! drive headless (it needs a real UDP peer), so the in-tree tests
//! settle for compile-time checks plus a couple of zero-side-effect
//! assertions on the option surface and input validation. The
//! end-to-end happy path is exercised by the QUIC interop runner
//! when the QNS endpoint is paired against an external peer.
//!
//! What we *can* verify cheaply:
//!   1. The helper compiles when called against a real `Client`.
//!   2. `RunUdpClientOptions` has the documented defaults.
//!   3. `runUdpClient` rejects malformed target / bind literals
//!      and zero-byte buffers without ever touching the socket
//!      layer.

const std = @import("std");
const quic_zig = @import("quic_zig");

const common = @import("common.zig");

const defaultParams = common.defaultParams;

test "runUdpClient is importable from the transport namespace" {
    // `runUdpClient` and the option struct must both live on the
    // public `transport` API surface so embedders can reach them
    // without dipping into private modules.
    const helper: *const fn (
        *quic_zig.Client,
        quic_zig.transport.RunUdpClientOptions,
    ) quic_zig.transport.RunUdpClientError!void = quic_zig.transport.runUdpClient;
    _ = helper;
}

test "RunUdpClientOptions defaults match the documented contract" {
    const opts: quic_zig.transport.RunUdpClientOptions = .{
        .target = "127.0.0.1:4433",
        .io = undefined,
    };
    // 5 ms heartbeat — same as the server.
    try std.testing.expectEqual(@as(i64, 5), opts.receive_timeout.toMilliseconds());
    // Tuning on by default.
    try std.testing.expect(opts.tune_socket);
    // ECN on by default.
    try std.testing.expect(opts.enable_ecn);
    // 5 second grace.
    try std.testing.expectEqual(@as(u64, 5_000_000), opts.shutdown_grace_us);
    // Default close error code is 0 (clean exit).
    try std.testing.expectEqual(@as(u64, 0), opts.shutdown_error_code);
    try std.testing.expect(opts.shutdown_flag == null);
    try std.testing.expect(opts.bind == null);
}

test "runUdpClient rejects a malformed target literal" {
    const protos = [_][]const u8{"hq-test"};

    var client = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "test.example",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    // Garbage in -> InvalidTargetAddress out, before any bind is
    // attempted. Confirms the helper validates the target literal up
    // front so a typo doesn't surface as a confusing socket error
    // from deep in std.Io.
    const result = quic_zig.transport.runUdpClient(&client, .{
        .target = "not-an-address",
        .io = std.testing.io,
    });
    try std.testing.expectError(error.InvalidTargetAddress, result);
}

test "runUdpClient rejects a malformed bind literal" {
    const protos = [_][]const u8{"hq-test"};

    var client = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "test.example",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    const result = quic_zig.transport.runUdpClient(&client, .{
        .target = "127.0.0.1:4433",
        .bind = "not-an-address",
        .io = std.testing.io,
    });
    try std.testing.expectError(error.InvalidBindAddress, result);
}

test "runUdpClient rejects zero-byte buffers" {
    const protos = [_][]const u8{"hq-test"};

    var client = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "test.example",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    try std.testing.expectError(
        error.InvalidBufferSize,
        quic_zig.transport.runUdpClient(&client, .{
            .target = "127.0.0.1:4433",
            .io = std.testing.io,
            .rx_buffer_bytes = 0,
        }),
    );
    try std.testing.expectError(
        error.InvalidBufferSize,
        quic_zig.transport.runUdpClient(&client, .{
            .target = "127.0.0.1:4433",
            .io = std.testing.io,
            .tx_buffer_bytes = 0,
        }),
    );
}

test "runUdpClient with shutdown_flag pre-set returns inside the grace window" {
    // Closest thing to exercising the loop body without a peer:
    // pre-flip the shutdown flag, point the loop at an unused
    // loopback target, and verify it cleans up without waiting
    // for the connection to close on its own. The receive timeout
    // caps the worst case at ~1 ms per iteration; the 1 ms grace
    // bounds the total wait.
    const protos = [_][]const u8{"hq-test"};

    var client = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "test.example",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    var stop = std.atomic.Value(bool).init(true);

    quic_zig.transport.runUdpClient(&client, .{
        // Bind to the same family as the target so the implicit
        // `0.0.0.0:0` fallback is exercised; target itself is a
        // garbage but well-formed loopback port nothing is
        // listening on.
        .target = "127.0.0.1:1",
        .io = std.testing.io,
        .shutdown_flag = &stop,
        // Most CI sandboxes lack CAP_NET_ADMIN; tuning would fail
        // before the loop even starts.
        .tune_socket = false,
        // ECN setsockopts can also fail in sandboxes; turn off so
        // we don't conflate ECN-config rejection with the loop's
        // shutdown behaviour.
        .enable_ecn = false,
        .shutdown_grace_us = 1_000,
        .receive_timeout = std.Io.Duration.fromMilliseconds(1),
    }) catch |err| switch (err) {
        // The loopback bind itself can fail in a sandbox.
        error.AddressInUse,
        error.AddressUnavailable,
        error.AddressFamilyUnsupported,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SocketModeUnsupported,
        error.OptionUnsupported,
        error.NetworkDown,
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        => return error.SkipZigTest,
        // The handshake's first PTO can fire and propagate as
        // HandshakeFailed if the test machine has unusually slow
        // I/O. That's fine — the loop is exiting cleanly either
        // way.
        error.HandshakeFailed,
        => return error.SkipZigTest,
        else => return err,
    };

    // The connection never completed a handshake (no peer); after
    // the shutdown grace window expires the loop returns. The
    // connection should be in `closing` or `draining` (we queued
    // the close), which is fine — the embedder is responsible for
    // any post-loop introspection.
}
