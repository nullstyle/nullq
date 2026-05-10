//! Hermetic in-process Server↔Client end-to-end QUIC handshake.
//!
//! `quic_zig.Server` and `quic_zig.Client` are both production-grade
//! convenience wrappers, but until now no test drove a real `Client`
//! through a real `Server` without sockets. The full handshake was
//! only exercised by the QNS Docker interop matrix, which means a
//! regression in `Server.feed` dispatch (CID routing, retry-token
//! gate, version-negotiation passthrough, etc.) only showed up as a
//! QNS CI failure rather than a unit-test failure.
//!
//! This file closes that gap. The pattern mirrors
//! `mock_transport_real_handshake.zig`'s "drive a real handshake
//! without a socket" loop, but the server side here is the full
//! `quic_zig.Server` wrapper — slot table, `feed` dispatch, stateless
//! response queue, CID-table resync, the works. Three scenarios:
//!
//!   1. Vanilla TLS-1.3 handshake completes via `Server.feed` and
//!      `Client.connect`, no DoS gates.
//!   2. After handshake completes, the server issues a
//!      NEW_CONNECTION_ID; the client switches to that DCID and the
//!      next 1-RTT packet routes correctly through `Server.feed`'s
//!      `cid_table` (regression coverage for the CID-rotation routing
//!      the architecture audit flagged as untested).
//!   3. With `Config.retry_token_key` set, the first Initial earns a
//!      Retry; the client validates and echoes the token, and the
//!      handshake completes through the post-Retry slot.

const std = @import("std");
const quic_zig = @import("quic_zig");
const common = @import("common.zig");

/// Drive an outbound packet from `src` straight into `dst.feed`.
/// Returns the number of times the loop body fired (i.e. how many
/// datagrams flowed). Wrapped in a helper so the three tests don't
/// repeat the same pump-loop boilerplate.
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

/// Drain every server slot's outbound packets into `cli`. Called
/// once per pump iteration. Each slot is polled until empty before
/// moving on so a slot that wants to emit Initial+Handshake on the
/// same wakeup gets fully drained.
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

test "Server <-> Client: full handshake completes through Server.feed" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xab) };

    // Kick the client so the very first Initial is in its outbox.
    // `Client.connect` deliberately leaves this to the embedder so
    // 0-RTT-bound STREAM data can be installed first.
    try cli.conn.advance();

    var step: u32 = 0;
    const max_steps: u32 = 32;
    var rounds_to_handshake: u32 = 0;
    while (step < max_steps) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;

        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);

        // Drain stateless responses (VN/Retry). On a vanilla v1
        // handshake with no retry_token_key this stays empty, but
        // the loop should be robust.
        while (srv.drainStatelessResponse()) |_| {}

        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);

        try srv.tick(now_us);
        try cli.conn.tick(now_us);

        if (cli.conn.handshakeDone() and srv.iterator().len > 0) {
            const slot = srv.iterator()[0];
            if (slot.conn.handshakeDone()) {
                rounds_to_handshake = step + 1;
                break;
            }
        }
    }

    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());

    // ALPN survived the codec round-trip on both sides.
    try std.testing.expectEqualStrings("hq-test", cli.conn.inner.alpnSelected().?);
    try std.testing.expectEqualStrings("hq-test", srv.iterator()[0].conn.inner.alpnSelected().?);

    // Sanity-cap the round-trip count so a future loop bug that
    // technically completes but takes 50 round-trips still fails.
    try std.testing.expect(rounds_to_handshake > 0);
    try std.testing.expect(rounds_to_handshake <= 12);
}

test "Server <-> Client: NEW_CONNECTION_ID rotates routing key in cid_table" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xcd) };
    try cli.conn.advance();

    // Phase 1: get the handshake done. Same loop as the first test.
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0) {
            if (srv.iterator()[0].conn.handshakeDone()) break;
        }
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());

    const slot = srv.iterator()[0];

    // Capture the original SCID the server is currently routing on.
    // After handshake the client's peer_dcid equals this SCID.
    const original_scid = slot.conn.local_scid;
    const routing_size_before = srv.routingTableSize();
    try std.testing.expect(routing_size_before >= 1);

    // Phase 2: server-side, queue a NEW_CONNECTION_ID with a fresh
    // CID that doesn't collide with the existing SCID.
    const new_cid_bytes = [_]u8{ 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    const reset_token: [16]u8 = @splat(0x42);
    const next_seq = slot.conn.nextLocalConnectionIdSequence(0);
    try slot.conn.queueNewConnectionId(next_seq, 0, &new_cid_bytes, reset_token);

    // Phase 3: pump server→client so the NEW_CONNECTION_ID frame
    // lands on the wire and the client stashes it in `peer_cids`.
    // The client will emit at least one ACK back; that ACK still
    // uses the OLD DCID, but it triggers `Server.feed` →
    // `resyncSlotCids`, which is what registers the new SCID in
    // `cid_table`. (queueNewConnectionId by itself only updates the
    // slot's `localScids`; the routing table catches up on the next
    // feed.)
    const peer_cids_before = cli.conn.peerCidsCount();
    var rotation_step: u32 = 0;
    while (rotation_step < 8) : (rotation_step += 1) {
        const now_us: u64 = @as(u64, 1000 + rotation_step) * 1_000;
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.peerCidsCount() > peer_cids_before and
            srv.routingTableSize() > routing_size_before) break;
    }
    try std.testing.expect(cli.conn.peerCidsCount() > peer_cids_before);
    try std.testing.expect(srv.routingTableSize() > routing_size_before);

    // Phase 4: switch the client's outgoing DCID to the new CID and
    // trigger an ack-eliciting 1-RTT packet (a RETIRE_CONNECTION_ID
    // for the *original* peer-issued CID). The packet's header now
    // carries `new_cid_bytes` as the DCID — `Server.feed` must look
    // it up in `cid_table` and route to the same slot.
    try cli.conn.setPeerDcid(&new_cid_bytes);
    try cli.conn.queueRetireConnectionId(0);

    const slot_count_before_routed = srv.connectionCount();
    var routed_packets: u32 = 0;
    var route_step: u32 = 0;
    while (route_step < 4) : (route_step += 1) {
        const now_us: u64 = @as(u64, 2000 + route_step) * 1_000;
        while (try cli.conn.poll(&rx, now_us)) |len| {
            // Sanity-check the wire-level DCID before feeding —
            // short-header packets place DCID at offset 1 and the
            // server's local_cid_len is 8. If this assertion fails,
            // the client is still using the old DCID and we'd be
            // accidentally exercising the legacy code path.
            try std.testing.expect(len >= 1 + new_cid_bytes.len);
            try std.testing.expect((rx[0] & 0x80) == 0); // short header
            try std.testing.expectEqualSlices(u8, &new_cid_bytes, rx[1 .. 1 + new_cid_bytes.len]);
            const outcome = try srv.feed(rx[0..len], peer_addr, now_us);
            try std.testing.expectEqual(quic_zig.Server.FeedOutcome.routed, outcome);
            routed_packets += 1;
        }
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
    }
    try std.testing.expect(routed_packets > 0);
    // Routing under the new CID must not have spawned a second slot.
    try std.testing.expectEqual(slot_count_before_routed, srv.connectionCount());
    // Defensive: connection isn't closed and the slot still owns
    // the new CID. The original SCID at sequence 0 is *expected* to
    // be retired by the time these assertions run — the client's
    // RETIRE_CONNECTION_ID(0) frame told the server to drop it, and
    // the resync loop has already pulled it out of `cid_table`.
    try std.testing.expect(!slot.conn.isClosed());
    try std.testing.expect(slot.conn.ownsLocalCid(&new_cid_bytes));
    // Keep `original_scid` referenced so the constant doesn't get
    // optimized out and reads as documentation.
    _ = original_scid;
}

test "Server <-> Client: handshake completes via Retry round-trip" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    // Stable HMAC key — any 32 bytes work, the value just has to be
    // consistent across mint/validate. Mirrors the value used in
    // `server_smoke.zig`'s Retry test.
    const retry_key: quic_zig.RetryTokenKey = .{
        0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
        0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
        0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
        0xf2, 0x83, 0x1d, 0xb6, 0x95, 0x77, 0x40, 0x29,
    };

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .retry_token_key = retry_key,
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xef) };
    try cli.conn.advance();

    // Phase 1: client emits Initial #1. Server queues a Retry.
    var saw_retry = false;
    {
        const now_us: u64 = 1_000;
        const len = (try cli.conn.poll(&rx, now_us)).?;
        const outcome = try srv.feed(rx[0..len], peer_addr, now_us);
        try std.testing.expectEqual(quic_zig.Server.FeedOutcome.retry_sent, outcome);
        try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
        try std.testing.expectEqual(@as(usize, 1), srv.statelessResponseCount());

        // Drain the Retry and feed it to the client. The client's
        // `handleRetry` captures the token + retry_scid and resets
        // its Initial-keys derivation.
        const retry_resp = srv.drainStatelessResponse() orelse return error.NoRetryQueued;
        // `StatelessResponse.bytes` is a fixed-size buffer; copy
        // into a mutable slice because `Connection.handle` takes
        // `[]u8` (decrypts in place — Retry is unencrypted but the
        // signature is still mutable).
        var retry_buf: [256]u8 = undefined;
        @memcpy(retry_buf[0..retry_resp.len], retry_resp.slice());
        try cli.conn.handle(retry_buf[0..retry_resp.len], null, now_us);
        saw_retry = true;
    }
    try std.testing.expect(saw_retry);

    // Phase 2: drive the rest of the handshake. The client's next
    // poll emits Initial #2 carrying the echoed token; server's
    // `feed` validates, opens a slot, and the handshake proceeds.
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, 2 + step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        // No Retry/VN should fire post-validation — but drain
        // anyway in case a regression sneaks in.
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0) {
            if (srv.iterator()[0].conn.handshakeDone()) break;
        }
    }

    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());

    // Client-side bookkeeping: `retry_accepted` flips to true inside
    // `Connection.handleRetry` once the integrity tag validates. If
    // it's still false here, the post-Retry handshake completed via
    // some unintended fallback path.
    try std.testing.expect(cli.conn.retry_accepted);

    // ALPN survived end-to-end — protects against a regression where
    // the post-Retry handshake completes but the second flight loses
    // the negotiated protocol.
    try std.testing.expectEqualStrings("hq-test", cli.conn.inner.alpnSelected().?);
    try std.testing.expectEqualStrings("hq-test", srv.iterator()[0].conn.inner.alpnSelected().?);
}

test "Server <-> Client: peer-side rebind after handshake arms PATH_CHALLENGE on existing slot" {
    // Regression coverage for `server × {ngtcp2, quic-go, quiche} × rebind-addr`
    // (the runner's mid-transfer source-address rewrite). Symmetric server-
    // role counterpart to the client-side `pollDatagram` migration test in
    // `_state_tests.zig`'s "client peer-address rebind" — that one pinned
    // the client's view of a server-tuple swap; this one pins the server's
    // view of a CLIENT-tuple swap routed through `Server.feed`.
    //
    // The runner's network simulator rewrites the client's source IP/port
    // mid-connection. Once the handshake is confirmed, the server's
    // existing-slot `feed` path:
    //
    //   1. Routes the post-rebind datagram via `findSlotForDatagram`
    //      (CID-keyed — the wire DCID is unchanged so the routing table
    //      hits the same slot), updates `slot.peer_addr` to the new tuple.
    //   2. Dispatches into `Connection.handleWithEcn`, which sees a
    //      different `from` than the active path's `peer_addr` and
    //      arms `peerAddressChangeCandidate`.
    //   3. Authenticated decrypt → `recordAuthenticatedDatagramAddress`
    //      → `handlePeerAddressChange` queues PATH_CHALLENGE on the
    //      primary path, snapshots rollback state, and (per the
    //      `fb267f6` fix) emits PATH_CHALLENGE as the FIRST frame on
    //      the next outbound datagram.
    //
    // Without this contract, peer-initiated NAT rebinding mid-transfer
    // looks like a fresh connection and the runner declares the test
    // failed because the server either drops the rebound datagram
    // (no migration arming) or burns through PTO retransmits to the
    // old (unreachable) tuple.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    // Pre-rebind peer address — the tuple the client appears to come
    // from before the simulator rewrites the source. The first byte
    // is a `path.Address` family tag (4 = IPv4); the actual layout
    // doesn't matter for `peerAddressChangeCandidate`'s `Address.eql`
    // check, only that old/new compare unequal byte-for-byte.
    const old_peer_addr: quic_zig.conn.path.Address = .{
        .bytes = .{ 4, 10, 0, 0, 1, 0x10, 0x00 } ++ @as([15]u8, @splat(0)),
    };
    try cli.conn.advance();

    // Phase 1: full handshake completes. We need handshakeDone() on
    // both sides because `recordAuthenticatedDatagramAddress` gates
    // peer-initiated migration on handshake confirmation (RFC 9000
    // §9.6 / hardening guide §4.8).
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, old_peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    const slot = srv.iterator()[0];
    try std.testing.expect(slot.conn.handshakeDone());

    // Drain any post-handshake outbound traffic (HANDSHAKE_DONE, ACKs,
    // NEW_CONNECTION_ID flights) so the slot starts the rebind window
    // with an empty outbox. Otherwise the per-slot poll below could
    // emit pre-migration packets first and mask the assertion that
    // PATH_CHALLENGE leads the FIRST outbound on the new tuple.
    var drain_step: u32 = 0;
    while (drain_step < 8) : (drain_step += 1) {
        const now_us: u64 = @as(u64, 100 + drain_step) * 1_000;
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        _ = try pumpClientToServer(&cli, &srv, &rx, old_peer_addr, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
    }

    // Capture pre-rebind path state for post-conditions.
    const path_before = slot.conn.primaryPathConst();
    try std.testing.expect(quic_zig.conn.path.Address.eql(path_before.path.peer_addr, old_peer_addr));
    try std.testing.expect(path_before.path.isValidated());
    try std.testing.expect(slot.conn.pending_frames.path_challenge == null);

    // Phase 2: simulate the runner's mid-transfer source-address
    // rewrite. Pump the client's next 1-RTT packet through `feed`
    // with a brand-new peer address. The packet bytes are unchanged
    // — only the `from` tuple rotates.
    const new_peer_addr: quic_zig.conn.path.Address = .{
        .bytes = .{ 4, 192, 0, 2, 99, 0xab, 0xcd } ++ @as([15]u8, @splat(0)),
    };
    try std.testing.expect(!quic_zig.conn.path.Address.eql(old_peer_addr, new_peer_addr));

    // Coax the client into emitting an ack-eliciting 1-RTT packet so
    // the server has something authenticated to record against the
    // new tuple. A queued PING via `pendingPing` is the minimum
    // authenticated-frame footprint.
    cli.conn.primaryPath().pending_ping = true;

    var rebound_inbound: u32 = 0;
    var path_challenge_observed = false;
    var migration_arm_step: u32 = 0;
    while (migration_arm_step < 4) : (migration_arm_step += 1) {
        const now_us: u64 = @as(u64, 200 + migration_arm_step) * 1_000;
        // Client→server through the NEW tuple. Per-iteration cap
        // matches `pumpClientToServer`'s shape but feeds with
        // `new_peer_addr`.
        while (try cli.conn.poll(&rx, now_us)) |len| {
            const outcome = try srv.feed(rx[0..len], new_peer_addr, now_us);
            try std.testing.expectEqual(quic_zig.Server.FeedOutcome.routed, outcome);
            rebound_inbound += 1;
            // First authenticated rebound datagram should arm the
            // migration: PATH_CHALLENGE queued on the active path
            // and the slot's `peer_addr` swung to the new tuple.
            if (slot.conn.pending_frames.path_challenge != null) {
                path_challenge_observed = true;
            }
        }
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (path_challenge_observed) break;
    }
    try std.testing.expect(rebound_inbound > 0);
    try std.testing.expect(path_challenge_observed);

    // Per-slot post-conditions: server saw the new tuple AND the
    // primary path is in the migration-pending window (anti-amp
    // counters reset, validator pending, rollback snapshotted).
    const path_after = slot.conn.primaryPathConst();
    try std.testing.expect(quic_zig.conn.path.Address.eql(path_after.path.peer_addr, new_peer_addr));
    try std.testing.expect(path_after.pending_migration_reset);
    try std.testing.expectEqual(@as(u32, 0), slot.conn.pending_frames.path_challenge_path_id);

    // Slot-level routing post-condition: the slot's `peer_addr` hint
    // (used by `runUdpServer`'s outbound drain to pick the receiving
    // socket) tracked the rebind. The connection itself doesn't
    // depend on this for correctness, but a divergence here would
    // mean outbound packets land on the wrong socket post-rebind.
    try std.testing.expect(slot.peer_addr != null);
    try std.testing.expect(quic_zig.conn.path.Address.eql(slot.peer_addr.?, new_peer_addr));

    // No second slot was opened — `findSlotForDatagram` matched the
    // existing one via the unchanged DCID. A fresh slot here would
    // mean `Server.feed` routed the post-rebind datagram into a new
    // connection, the failure mode the runner sees as "Expected
    // exactly 1 handshake. Got: 2".
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());

    // Outbound shape: the next datagram the slot emits must lead
    // with PATH_CHALLENGE per `fb267f6` (otherwise quiche / similar
    // implementations stall path validation and the rebind never
    // completes). Drive one poll under the post-rebind clock and
    // confirm a non-empty outbound was produced. We don't decrypt
    // here — the existing `_state_tests.zig` "peer-initiated
    // migration emits PATH_CHALLENGE as the first frame" pins the
    // frame ordering at the connection level; this test pins that
    // the server-wrapper end-to-end path actually reaches it.
    const post_rebind_now: u64 = @as(u64, 300) * 1_000;
    var post_rebind_outbound: u32 = 0;
    while (try slot.conn.poll(&rx, post_rebind_now)) |_| {
        post_rebind_outbound += 1;
    }
    try std.testing.expect(post_rebind_outbound > 0);
}
