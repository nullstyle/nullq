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
    // The client follows the upgrade signal in its first inbound
    // Initial via `Connection.clientAcceptCompatibleVersion`.
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
    const outcome = try driveHandshake(&cli, &srv, peer_addr, 32);
    try std.testing.expect(outcome.completed);

    // Both sides committed to the upgrade target (v2): the server's
    // first Initial response was sealed under v2 keys, and the client
    // followed that signal mid-flight before the AEAD open ran.
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    const slot = srv.iterator()[0];
    try std.testing.expectEqual(QUIC_V2, slot.conn.version);
    try std.testing.expectEqual(QUIC_V2, cli.conn.version);

    // ALPN survived the upgrade.
    try std.testing.expectEqualStrings("hq-test", cli.conn.inner.alpnSelected().?);
    try std.testing.expectEqualStrings("hq-test", slot.conn.inner.alpnSelected().?);
}

test "[v2,v1] server upgrades a multi-Initial fragmented ClientHello [RFC9368 §6]" {
    // RFC 9368 §6 multi-Initial fragmented ClientHello path. The
    // client's CH is split across two Initial packets:
    //   - Initial #1: CRYPTO offset=0 carrying the CH prefix.
    //   - Initial #2: CRYPTO offset=N carrying the CH tail.
    // Each Initial is independently AEAD-sealed under the wire-version
    // (v1) Initial keys derived from the client's chosen DCID. The
    // server is configured `versions=[v2,v1]`; the CH advertises
    // `version_information=[v1, v2]`, so the highest-priority overlap
    // is v2 and the server's pre-parse must drive the upgrade *only*
    // after both Initials have been fed.
    //
    // We construct the CH and the two Initial datagrams entirely from
    // wire-level helpers — feeding them into `Server.feed` exercises
    // the streaming `ChReassembler` that landed in this commit.
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

    // -- Build a synthetic but well-formed ClientHello. The pre-parse
    // doesn't run TLS validation; it walks the extension list looking
    // for `quic_transport_parameters` (codepoint 0x39). We construct
    // a 1280-byte CH so that even a single Initial wouldn't carry it
    // intact under a 1200-byte UDP datagram, and the only meaningful
    // extension is `quic_transport_parameters` advertising
    // version_information=[v1, v2].

    // First build the QUIC transport parameters blob with a
    // version_information that lists [v1, v2].
    var tp_buf: [256]u8 = undefined;
    var tp_params: quic_zig.tls.TransportParams = .{};
    try tp_params.setCompatibleVersions(&[_]u32{ QUIC_V1, QUIC_V2 });
    const tp_len = try tp_params.encode(&tp_buf);

    // Now build the ClientHello body. Layout (RFC 8446 §4.1.2):
    //   legacy_version (2) + random (32) + legacy_session_id (1+0) +
    //   cipher_suites (2 + 2) + legacy_compression_methods (1 + 1) +
    //   extensions (2 + ...).
    var ch_storage: [2048]u8 = undefined;
    var p: usize = 0;
    // Reserve outer Handshake header (4 bytes): type=0x01 + u24 length.
    ch_storage[p] = 0x01;
    p += 1;
    p += 3; // length placeholder
    const body_start = p;
    // legacy_version (TLS 1.2 placeholder).
    ch_storage[p] = 0x03;
    ch_storage[p + 1] = 0x03;
    p += 2;
    // random (32 bytes).
    @memset(ch_storage[p .. p + 32], 0xab);
    p += 32;
    // legacy_session_id (empty).
    ch_storage[p] = 0x00;
    p += 1;
    // cipher_suites: 1 entry = TLS_AES_128_GCM_SHA256 (0x1301).
    ch_storage[p] = 0x00;
    ch_storage[p + 1] = 0x02;
    ch_storage[p + 2] = 0x13;
    ch_storage[p + 3] = 0x01;
    p += 4;
    // legacy_compression_methods: 1 byte = null (0x00).
    ch_storage[p] = 0x01;
    ch_storage[p + 1] = 0x00;
    p += 2;
    // extensions block. We need:
    //   (a) quic_transport_parameters (codepoint 0x39, 4 bytes header
    //       + tp_len bytes payload),
    //   (b) padding (TLS 1.3 codepoint 0x0015) to inflate the CH past
    //       a single 1200-byte Initial.
    const ext_block_start = p;
    p += 2; // total ext-block length placeholder.

    // ext (a): quic_transport_parameters.
    ch_storage[p] = 0x00;
    ch_storage[p + 1] = 0x39;
    ch_storage[p + 2] = @intCast((tp_len >> 8) & 0xff);
    ch_storage[p + 3] = @intCast(tp_len & 0xff);
    p += 4;
    @memcpy(ch_storage[p .. p + tp_len], tp_buf[0..tp_len]);
    p += tp_len;

    // ext (b): padding to make the CH big enough that two Initials
    // are required. Initial overhead is roughly 50 bytes (long header
    // + length + PN + AEAD tag); a 1200-byte Initial holds ~1140
    // bytes of plaintext. Pad the CH to ~1500 bytes so the split is
    // forced.
    const padding_target_total: usize = 1500; // total CH including 4-byte header
    const cur_total = p;
    if (cur_total + 4 < padding_target_total) {
        const pad_payload_len = padding_target_total - cur_total - 4;
        ch_storage[p] = 0x00; // padding ext type 0x0015 high byte
        ch_storage[p + 1] = 0x15;
        ch_storage[p + 2] = @intCast((pad_payload_len >> 8) & 0xff);
        ch_storage[p + 3] = @intCast(pad_payload_len & 0xff);
        p += 4;
        @memset(ch_storage[p .. p + pad_payload_len], 0x00);
        p += pad_payload_len;
    }

    // Patch the extension block length and outer Handshake length.
    const ext_block_len = p - ext_block_start - 2;
    ch_storage[ext_block_start] = @intCast((ext_block_len >> 8) & 0xff);
    ch_storage[ext_block_start + 1] = @intCast(ext_block_len & 0xff);
    const ch_body_len = p - body_start;
    ch_storage[1] = @intCast((ch_body_len >> 16) & 0xff);
    ch_storage[2] = @intCast((ch_body_len >> 8) & 0xff);
    ch_storage[3] = @intCast(ch_body_len & 0xff);
    const ch = ch_storage[0..p];
    try std.testing.expect(ch.len > 1200);

    // -- Split the CH at byte 600 and build two Initial datagrams,
    // both AEAD-sealed under v1 Initial keys derived from the
    // client's chosen DCID.
    const split = 600;
    const dcid: [8]u8 = .{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const scid: [4]u8 = .{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const init_keys = try quic_zig.wire.initial.deriveInitialKeys(&dcid, false);
    const r_keys = try quic_zig.wire.short_packet.derivePacketKeys(
        .aes128_gcm_sha256,
        &init_keys.secret,
    );

    // Frame stream for Initial #1: CRYPTO offset=0 covering ch[0..split].
    var f1_buf: [2048]u8 = undefined;
    const f1_len = try quic_zig.frame.encode(&f1_buf, .{ .crypto = .{
        .offset = 0,
        .data = ch[0..split],
    } });

    // Frame stream for Initial #2: CRYPTO offset=split covering ch[split..].
    var f2_buf: [2048]u8 = undefined;
    const f2_len = try quic_zig.frame.encode(&f2_buf, .{ .crypto = .{
        .offset = split,
        .data = ch[split..],
    } });

    // Seal each Initial. RFC 9000 §14 requires the client's first-
    // flight Initial to pad to ≥ 1200 bytes; we pad both for safety.
    var pkt1: [2048]u8 = undefined;
    const len1 = try quic_zig.wire.long_packet.sealInitial(&pkt1, .{
        .version = QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = f1_buf[0..f1_len],
        .keys = &r_keys,
        .pad_to = 1200,
    });
    var pkt2: [2048]u8 = undefined;
    const len2 = try quic_zig.wire.long_packet.sealInitial(&pkt2, .{
        .version = QUIC_V1,
        .dcid = &dcid,
        .scid = &scid,
        .pn = 1,
        .payload = f2_buf[0..f2_len],
        .keys = &r_keys,
        .pad_to = 1200,
    });

    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xee) };

    // Feed Initial #1: the slot opens, but since the CH is fragmented
    // the single-shot pre-parse fails and a `pending_upgrade` is
    // attached. The connection still commits to v1 at this point.
    const out1 = try srv.feed(pkt1[0..len1], peer_addr, 0);
    try std.testing.expectEqual(@as(quic_zig.Server.FeedOutcome, .accepted), out1);
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    const slot = srv.iterator()[0];
    try std.testing.expectEqual(QUIC_V1, slot.conn.version);
    try std.testing.expect(slot.pending_upgrade != null);

    // Feed Initial #2: the streaming reassembler completes the CH,
    // the pre-parse picks the upgrade target, the server rebuilds
    // the local transport_params and sets the pending version flip.
    // After `dispatchToSlot.applyPendingVersionUpgrade` runs, the
    // connection's active version is v2.
    const out2 = try srv.feed(pkt2[0..len2], peer_addr, 0);
    try std.testing.expectEqual(@as(quic_zig.Server.FeedOutcome, .routed), out2);
    try std.testing.expectEqual(QUIC_V2, slot.conn.version);
    try std.testing.expect(slot.pending_upgrade == null);
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
