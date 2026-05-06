//! Hermetic in-process Server↔Client end-to-end QUIC handshake.
//!
//! `nullq.Server` and `nullq.Client` are both production-grade
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
//! `nullq.Server` wrapper — slot table, `feed` dispatch, stateless
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
const nullq = @import("nullq");
const common = @import("common.zig");

/// Drive an outbound packet from `src` straight into `dst.feed`.
/// Returns the number of times the loop body fired (i.e. how many
/// datagrams flowed). Wrapped in a helper so the three tests don't
/// repeat the same pump-loop boilerplate.
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

/// Drain every server slot's outbound packets into `cli`. Called
/// once per pump iteration. Each slot is polled until empty before
/// moving on so a slot that wants to emit Initial+Handshake on the
/// same wakeup gets fully drained.
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

test "Server <-> Client: full handshake completes through Server.feed" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
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

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
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
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xcd) };
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
            try std.testing.expectEqual(nullq.Server.FeedOutcome.routed, outcome);
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
    const retry_key: nullq.RetryTokenKey = .{
        0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
        0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
        0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
        0xf2, 0x83, 0x1d, 0xb6, 0x95, 0x77, 0x40, 0x29,
    };

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .retry_token_key = retry_key,
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
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xef) };
    try cli.conn.advance();

    // Phase 1: client emits Initial #1. Server queues a Retry.
    var saw_retry = false;
    {
        const now_us: u64 = 1_000;
        const len = (try cli.conn.poll(&rx, now_us)).?;
        const outcome = try srv.feed(rx[0..len], peer_addr, now_us);
        try std.testing.expectEqual(nullq.Server.FeedOutcome.retry_sent, outcome);
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
