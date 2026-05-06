//! Smoke tests for `nullq.transport.runUdpServer`.
//!
//! The full loop is awkward to drive headless: it needs a real UDP
//! peer to handshake against, a thread to run the loop, and a way to
//! signal shutdown. The QUIC interop runner already exercises the
//! end-to-end path when the QNS endpoint is rebuilt against this
//! helper, so here we settle for compile-time checks plus a couple
//! of zero-side-effect assertions on the option surface.
//!
//! What we *can* verify cheaply:
//!   1. The helper compiles when called against a real `Server`.
//!   2. `RunUdpOptions` has the documented defaults.
//!   3. `runUdpServer` rejects malformed listen addresses without
//!      ever touching the socket layer.
//!   4. The shutdown_flag plumbing accepts `*const std.atomic.Value(bool)`
//!      without the caller having to whisper-cast.
//!
//! What we can't easily verify here:
//!   - End-to-end handshake against a real peer. Driving that
//!     requires a second nullq client (or quic-go) on a known port,
//!     which is what `interop/qns_endpoint.zig` is for. The QNS
//!     interop matrix in `INTEROP_STATUS.md` is the canonical
//!     end-to-end gate.
//!   - Behavior under socket errors, signal-driven shutdown, or
//!     load. Those would need a fault-injection `std.Io` shim that
//!     is out of scope for this smoke test.

const std = @import("std");
const nullq = @import("nullq");

const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;
const defaultParams = common.defaultParams;

test "runUdpServer is importable from the transport namespace" {
    // `runUdpServer` and the option struct must both live on the
    // public `transport` API surface so embedders can reach them
    // without dipping into private modules.
    const helper: *const fn (
        *nullq.Server,
        nullq.transport.RunUdpOptions,
    ) nullq.transport.RunError!void = nullq.transport.runUdpServer;
    _ = helper;
}

test "RunUdpOptions defaults match the documented contract" {
    const opts: nullq.transport.RunUdpOptions = .{
        .listen = "127.0.0.1:0",
        .io = undefined, // not invoked
    };
    // 5 ms heartbeat — short enough for QUIC's PTO granularity,
    // long enough to avoid spinning on an idle network.
    try std.testing.expectEqual(@as(i64, 5), opts.receive_timeout.toMilliseconds());
    // Tuning on by default for production sanity.
    try std.testing.expect(opts.tune_socket);
    // 5 second grace — plenty for CONNECTION_CLOSE to flush even
    // through a single 200 ms RTT path with retransmits.
    try std.testing.expectEqual(@as(u64, 5_000_000), opts.shutdown_grace_us);
    // No shutdown flag by default; the loop runs forever until the
    // embedder either cancels the I/O or kills the process.
    try std.testing.expect(opts.shutdown_flag == null);
}

test "runUdpServer rejects a malformed listen literal" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Garbage in -> InvalidListenAddress out, before bind is ever
    // attempted. Important: this confirms the helper validates input
    // up front so a typo'd listen string doesn't surface as a
    // confusing socket error from deep in std.Io.
    const result = nullq.transport.runUdpServer(&srv, .{
        .listen = "not-an-address",
        .io = std.testing.io,
    });
    try std.testing.expectError(error.InvalidListenAddress, result);
}

test "runUdpServer rejects zero-byte buffers" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Bad rx buffer.
    try std.testing.expectError(error.InvalidBufferSize, nullq.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = std.testing.io,
        .rx_buffer_bytes = 0,
    }));

    // Bad tx buffer.
    try std.testing.expectError(error.InvalidBufferSize, nullq.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = std.testing.io,
        .tx_buffer_bytes = 0,
    }));
}

test "runUdpServer with shutdown_flag already set returns immediately" {
    // This is the closest we get to exercising the loop body
    // without a peer: pre-set the shutdown flag, point the loop at
    // a loopback ephemeral port, and verify it cleans up without
    // blocking. The receive timeout caps the worst case at ~5 ms.
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    var stop = std.atomic.Value(bool).init(true);

    // Skip if the test environment can't bind UDP at all (sandboxed
    // CI runners sometimes block this).
    nullq.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = std.testing.io,
        .shutdown_flag = &stop,
        // Don't try to tune buffers — most CI sandboxes lack
        // CAP_NET_ADMIN and we'd hit error.SocketTuningFailed.
        .tune_socket = false,
        // Tiny grace so the test doesn't sit on the loop.
        .shutdown_grace_us = 1_000,
        // Tiny receive timeout so the very first iteration sees the
        // flag and bails.
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
        else => return err,
    };

    // No live connections were ever fed in, so `connectionCount`
    // must be exactly 0 after the loop returns.
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}
