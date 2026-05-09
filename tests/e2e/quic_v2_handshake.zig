//! End-to-end QUIC v2 (RFC 9368) handshake.
//!
//! Mirrors `server_client_handshake.zig`, but both sides are
//! configured for QUIC v2. Drives the handshake through the full
//! `quic_zig.Server` / `quic_zig.Client` wrappers (slot table, CID
//! routing, the works) so a regression in the v2 long-header type
//! rotation, the v2 Initial salt + HKDF labels, or the v2 Retry
//! integrity tag would show up here as a hung handshake or an AEAD
//! authentication failure.
//!
//! Three scenarios:
//!
//!   1. v2-only on both sides: client picks v2, server accepts v2.
//!   2. v1-only on both sides (regression coverage): the
//!      version-aware refactor must not break the existing v1 path.
//!   3. Multi-version server (v1+v2) with a v1 client: the server's
//!      RFC 9368 §6 backwards-compat path. The client doesn't even
//!      know v2 exists; the server accepts v1 directly.

const std = @import("std");
const quic_zig = @import("quic_zig");
const common = @import("common.zig");

const QUIC_V1: u32 = quic_zig.QUIC_VERSION_1;
const QUIC_V2: u32 = quic_zig.QUIC_VERSION_2;

fn pumpClientToServer(
    cli: *quic_zig.Client,
    srv: *quic_zig.Server,
    rx: []u8,
    addr: quic_zig.conn.path.Address,
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
    srv: *quic_zig.Server,
    cli: *quic_zig.Client,
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

fn pumpStateless(srv: *quic_zig.Server) void {
    while (srv.drainStatelessResponse()) |_| {}
}

const HandshakeOutcome = struct {
    rounds: u32,
    completed: bool,
};

fn driveHandshake(
    cli: *quic_zig.Client,
    srv: *quic_zig.Server,
    peer_addr: quic_zig.conn.path.Address,
    max_rounds: u32,
) !HandshakeOutcome {
    var rx: [4096]u8 = undefined;
    var step: u32 = 0;
    try cli.conn.advance();
    while (step < max_rounds) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(cli, srv, &rx, peer_addr, now_us);
        pumpStateless(srv);
        _ = try pumpServerToClient(srv, cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0) {
            const slot = srv.iterator()[0];
            if (slot.conn.handshakeDone()) {
                return .{ .rounds = step + 1, .completed = true };
            }
        }
    }
    return .{ .rounds = max_rounds, .completed = false };
}

test "v2 handshake completes on both sides [RFC9368 §3]" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    const versions = [_]u32{QUIC_V2};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .versions = &versions,
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .preferred_version = QUIC_V2,
    });
    defer cli.deinit();

    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0x21) };
    const outcome = try driveHandshake(&cli, &srv, peer_addr, 32);
    try std.testing.expect(outcome.completed);
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());

    // Both sides settled on v2 — the connection's `version` field is
    // the post-Initial-derivation source of truth.
    try std.testing.expectEqual(QUIC_V2, cli.conn.version);
    try std.testing.expectEqual(QUIC_V2, srv.iterator()[0].conn.version);

    // ALPN survived the handshake.
    try std.testing.expectEqualStrings("hq-test", cli.conn.inner.alpnSelected().?);
    try std.testing.expectEqualStrings("hq-test", srv.iterator()[0].conn.inner.alpnSelected().?);
}

test "v1 handshake regression: still completes after v2 plumbing landed" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        // Default versions = v1 only. Explicit so the test reads as
        // intent rather than relying on the default.
        .versions = &.{QUIC_V1},
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .preferred_version = QUIC_V1,
    });
    defer cli.deinit();

    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0x42) };
    const outcome = try driveHandshake(&cli, &srv, peer_addr, 32);
    try std.testing.expect(outcome.completed);
    try std.testing.expectEqual(QUIC_V1, cli.conn.version);
    try std.testing.expectEqual(QUIC_V1, srv.iterator()[0].conn.version);
}

test "v1+v2 server with a v1 client: server accepts v1 directly [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    const versions = [_]u32{ QUIC_V1, QUIC_V2 };

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .versions = &versions,
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .preferred_version = QUIC_V1,
    });
    defer cli.deinit();

    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0x55) };
    const outcome = try driveHandshake(&cli, &srv, peer_addr, 32);
    try std.testing.expect(outcome.completed);
    try std.testing.expectEqual(QUIC_V1, srv.iterator()[0].conn.version);
}

test "v2-only server with a v1-only client emits a VN listing v2 [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    const versions = [_]u32{QUIC_V2};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .versions = &versions,
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        // Client is v1-only — no compatible_versions, no preferred
        // override. The server will reject this with a VN.
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0x77) };
    try cli.conn.advance();

    // Pump exactly one client→server datagram and inspect what the
    // server did. We expect a VN response queued on the stateless
    // queue and *no* slot in the connection table.
    var step: u32 = 0;
    while (step < 4) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        if (srv.statelessResponseCount() > 0) break;
    }

    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    try std.testing.expect(srv.statelessResponseCount() >= 1);
    const vn = srv.drainStatelessResponse() orelse return error.UnexpectedNullVn;
    const parsed = try quic_zig.wire.header.parse(vn.slice(), 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    const vn_hdr = parsed.header.version_negotiation;
    try std.testing.expectEqual(@as(usize, 1), vn_hdr.versionCount());
    try std.testing.expectEqual(QUIC_V2, vn_hdr.version(0));

    // The client never completes its handshake — the server's only
    // response was VN. We don't assert further state because the
    // client doesn't currently parse VN to discover v2 (that's the
    // compatible-version-negotiation upgrade path tracked as
    // `// TODO(B3-followup):`).
    try std.testing.expect(!cli.conn.handshakeDone());
}

test "v1+v2 client advertises version_information transport parameter [RFC9368 §5]" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    const versions = [_]u32{ QUIC_V1, QUIC_V2 };
    const cli_compat = [_]u32{QUIC_V2}; // chosen=v1, compatible=[v2]

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .versions = &versions,
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .preferred_version = QUIC_V1,
        .compatible_versions = &cli_compat,
    });
    defer cli.deinit();

    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0x88) };
    const outcome = try driveHandshake(&cli, &srv, peer_addr, 32);
    try std.testing.expect(outcome.completed);

    // After the handshake completes, both sides have the peer's
    // transport parameters resolved; the server should see the
    // client's `compatible_versions` advertising [v1, v2].
    const slot = srv.iterator()[0];
    const peer_params_opt = try slot.conn.peerTransportParams();
    const peer_params = peer_params_opt orelse return error.NoPeerParams;
    const got_versions = peer_params.compatibleVersions();
    try std.testing.expectEqual(@as(usize, 2), got_versions.len);
    try std.testing.expectEqual(QUIC_V1, got_versions[0]);
    try std.testing.expectEqual(QUIC_V2, got_versions[1]);

    // The server in turn advertises its full `Config.versions` set
    // back to the client. With chosen-version-first ordering, the
    // first entry matches the negotiated v1.
    const server_advertised_opt = try cli.conn.peerTransportParams();
    const server_advertised = (server_advertised_opt orelse return error.NoServerParams).compatibleVersions();
    try std.testing.expect(server_advertised.len >= 1);
    try std.testing.expectEqual(QUIC_V1, server_advertised[0]);
}

test "[v2,v1] server upgrades a v1-wire ClientHello that lists v2 [RFC9368 §6]" {
    // RFC 9368 §6 compatible-version-negotiation upgrade. The client
    // sends its ClientHello inside a wire-version-v1 Initial but
    // advertises `version_information = [v1, v2]` in its transport
    // parameters; the server is configured `versions = [v2, v1]`,
    // so the highest-priority overlap is v2 and the server upgrades.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    const srv_versions = [_]u32{ QUIC_V2, QUIC_V1 };
    const cli_compat = [_]u32{QUIC_V2}; // wire=v1, available=[v1, v2]

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .versions = &srv_versions,
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .preferred_version = QUIC_V1,
        .compatible_versions = &cli_compat,
    });
    defer cli.deinit();

    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xab) };
    // Drive at least one client→server pump so the server has
    // observed the v1-wire Initial and committed to its upgrade
    // decision. The full handshake won't finish here because the
    // client side doesn't yet respond to the server's upgrade signal
    // (that path is tracked on the client follow-up); the upgrade
    // assertion lives on the server side.
    var rx: [4096]u8 = undefined;
    try cli.conn.advance();
    _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, 0);

    // The server should now have a slot whose connection version is
    // the upgrade target (v2), and the outbound transport_params
    // should advertise chosen=v2 first.
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    const slot = srv.iterator()[0];
    try std.testing.expectEqual(QUIC_V2, slot.conn.version);
}

test "[v2,v1] server with v1-only client commits to v1, no upgrade [RFC9368 §6]" {
    // The mirror of the upgrade test: same server config, but the
    // client doesn't advertise version_information at all (it only
    // knows v1). The intersection between server's [v2, v1] and the
    // client's "implicit available = [wire]" is just v1, so the
    // chosen version is the wire version (v1) — no upgrade.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    const srv_versions = [_]u32{ QUIC_V2, QUIC_V1 };

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .versions = &srv_versions,
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .preferred_version = QUIC_V1,
        // No `compatible_versions` — the client behaves like a
        // legacy v1-only stack that never sends version_information.
    });
    defer cli.deinit();

    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xcd) };
    const outcome = try driveHandshake(&cli, &srv, peer_addr, 32);
    try std.testing.expect(outcome.completed);
    try std.testing.expectEqual(QUIC_V1, cli.conn.version);
    try std.testing.expectEqual(QUIC_V1, srv.iterator()[0].conn.version);
}
