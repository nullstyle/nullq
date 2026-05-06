//! Hardening guide §5.2 / §11.2 regression: 0-RTT replay rejection.
//!
//! Embedders that opt in to 0-RTT (`Server.Config.enable_0rtt = true`)
//! are required to wire `nullq.tls.AntiReplayTracker` into their
//! server loop and reject any 0-RTT request whose ticket-derived
//! identity has already been seen — RFC 9001 §5.6 / RFC 8446 §8.
//! Without that check, an attacker who captures a 0-RTT request can
//! replay it for the lifetime of the resumed session ticket.
//!
//! BoringSSL's QUIC integration deliberately delegates the "has this
//! exact early-data already been seen?" check to the application —
//! the server-side session cache pins tickets, but the replay decision
//! lives at a layer that knows the ticket's identity. The
//! `AntiReplayTracker` is the data structure that check needs; this
//! test pins the embedder workflow:
//!
//!   1. Drive a real handshake to completion. The server issues a
//!      NewSessionTicket; the client captures it via
//!      `setNewSessionCallback` and serializes the bytes via
//!      `Session.toBytes`.
//!   2. First "0-RTT attempt" presenting those ticket bytes:
//!      compute a stable `[32]u8` identity from the bytes (SHA-256),
//!      call `tracker.consume(id, now_us)`, expect `.fresh`.
//!   3. Second "0-RTT attempt" presenting the same ticket bytes:
//!      same identity, `tracker.consume(id, now_us)`, expect `.replay`.
//!
//! The test demonstrates the full embedder workflow even though the
//! high-level `nullq.Server` wrapper does not yet auto-call
//! `setEarlyDataContext` on freshly-accepted slots — the replay-cache
//! data structure and the identity-construction recipe are what this
//! pins. When BoringSSL's 0-RTT acceptance is wired through the
//! Server wrapper end-to-end, this test will continue to work without
//! modification because the tracker is identity-based, not
//! BoringSSL-state-based.

const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");
const common = @import("common.zig");

/// SHA-256 of the resumed session's ticket bytes. Per §5.2 of the
/// hardening guide, this is option (1) in the "Identity choice"
/// section of `nullq.tls.anti_replay`'s module docstring: bound to
/// the ticket exactly, stable across replays of the same 0-RTT
/// message, differs across distinct legitimate 0-RTT attempts (a
/// peer-issued single-use ticket cannot be re-issued).
fn ticketIdentity(ticket_bytes: []const u8) nullq.tls.anti_replay.Id {
    var id: nullq.tls.anti_replay.Id = @splat(0);
    std.crypto.hash.sha2.Sha256.hash(ticket_bytes, &id, .{});
    return id;
}

/// Per-test session-ticket capture sink. The
/// `setNewSessionCallback` trampoline takes ownership of the
/// `Session`; we serialize it and stash the bytes so the test body
/// can later derive a stable identity from them.
const TicketSink = struct {
    allocator: std.mem.Allocator,
    captured: ?[]u8 = null,

    fn cb(user_data: ?*anyopaque, session_in: boringssl.tls.Session) void {
        const self: *TicketSink = @ptrCast(@alignCast(user_data.?));
        var s = session_in;
        defer s.deinit();
        // Ignore subsequent tickets — we only need one to pin the
        // workflow. The first one BoringSSL hands us is canonical.
        if (self.captured != null) return;
        self.captured = s.toBytes(self.allocator) catch null;
    }

    fn deinit(self: *TicketSink) void {
        if (self.captured) |bytes| self.allocator.free(bytes);
        self.* = undefined;
    }
};

/// Drain `cli`'s outbound packets and feed them to `srv`. Mirror of
/// the helper in `tests/e2e/server_client_handshake.zig` — kept
/// inline here so this file stays self-contained and the parallel
/// agents editing the existing e2e files don't collide on a shared
/// helper.
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

/// Drain every server slot's outbound packets into `cli`. Same shape
/// as the helper in `server_client_handshake.zig`.
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

test "0-RTT replay rejection: AntiReplayTracker marks first ticket fresh, second replay (§5.2 / §11.2)" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    // -- Step 1: build a Server with 0-RTT enabled, and a client TLS
    //   context that will capture the NewSessionTicket. --
    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .enable_0rtt = true,
    });
    defer srv.deinit();

    var sink: TicketSink = .{ .allocator = allocator };
    defer sink.deinit();

    var client_ctx = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    // The Client wrapper takes ownership of `client_ctx` because we
    // pass it via `tls_context_override`; do not deinit here.
    try client_ctx.setNewSessionCallback(TicketSink.cb, &sink);

    var cli = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .tls_context_override = client_ctx,
    });
    defer cli.deinit();

    // -- Step 2: drive the handshake to completion, then keep
    //   pumping until the post-handshake NST flight lands and the
    //   client has captured a ticket. --
    var rx: [4096]u8 = undefined;
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xab) };
    try cli.conn.advance();

    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        // Done when both sides handshake-completed AND the client
        // captured a ticket. The NST arrives in the application-PN
        // flight after `handshakeDone()` — keep pumping until the
        // sink has it.
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone() and sink.captured != null)
        {
            break;
        }
    }

    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());
    try std.testing.expect(sink.captured != null);

    const ticket_bytes = sink.captured.?;
    try std.testing.expect(ticket_bytes.len > 0);

    // -- Step 3: pin the embedder's anti-replay workflow. The tracker
    //   is the data structure §5.2 demands; identity = SHA-256 of the
    //   ticket bytes (option 1 in the anti_replay module docstring).
    //   First connection: `.fresh`. Second connection presenting the
    //   same ticket bytes: `.replay`. --
    var tracker = try nullq.tls.AntiReplayTracker.init(allocator, .{
        .max_entries = 64,
        .max_age_us = 10 * std.time.us_per_min,
    });
    defer tracker.deinit();

    const id = ticketIdentity(ticket_bytes);

    // First "0-RTT attempt" — the embedder calls `consume` after the
    // handshake reports `earlyDataStatus() == .accepted`. The tracker
    // reports `.fresh`, so the embedder MAY honor the early-data
    // request. The wall-clock time is microseconds since some
    // monotonic epoch; the tracker uses it for both insertion
    // bookkeeping and stale-entry pruning.
    try std.testing.expectEqual(
        nullq.tls.anti_replay.Verdict.fresh,
        try tracker.consume(id, 1_000_000),
    );
    try std.testing.expectEqual(@as(usize, 1), tracker.size());

    // Second "0-RTT attempt" with the SAME ticket bytes. SHA-256 is
    // deterministic, so the identity matches; the tracker reports
    // `.replay` and the embedder MUST reject the early-data bytes
    // (treat them as unauthenticated; serve any response only at
    // 1-RTT after handshake completion).
    try std.testing.expectEqual(
        nullq.tls.anti_replay.Verdict.replay,
        try tracker.consume(id, 1_500_000),
    );
    try std.testing.expectEqual(@as(usize, 1), tracker.size());

    // A different ticket (e.g. issued by a future legitimate
    // resumption) must produce a distinct identity. Sanity-check by
    // mutating one byte of the ticket — the SHA-256 avalanche
    // guarantees the new id collides with the old at a probability
    // far below the test's failure budget.
    const tampered = try allocator.dupe(u8, ticket_bytes);
    defer allocator.free(tampered);
    tampered[0] ^= 0x01;
    const id2 = ticketIdentity(tampered);
    try std.testing.expect(!std.mem.eql(u8, &id, &id2));
    try std.testing.expectEqual(
        nullq.tls.anti_replay.Verdict.fresh,
        try tracker.consume(id2, 2_000_000),
    );
    try std.testing.expectEqual(@as(usize, 2), tracker.size());

    // And the original id replayed *again* still trips. Re-insertion
    // semantics: the tracker is single-shot per identity within the
    // active window.
    try std.testing.expectEqual(
        nullq.tls.anti_replay.Verdict.replay,
        try tracker.consume(id, 2_500_000),
    );
}

test "0-RTT replay rejection: ticket bytes are stable across deserialization (§5.2)" {
    // Round-trip the captured ticket through `Session.fromBytes` /
    // `Session.toBytes` and verify the identity stays the same. This
    // matters because the embedder may stash the ticket bytes in a
    // session cache, retrieve them later, parse via `fromBytes`, and
    // re-serialize — the resulting bytes must produce the same
    // identity or the replay cache will silently fail to detect
    // round-tripped replays.
    //
    // (`boringssl-zig`'s `tls_session.zig` already covers byte-for-byte
    // round-trip; this test re-asserts it from the embedder's
    // identity-construction perspective, which is the load-bearing
    // property for the replay cache.)
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .enable_0rtt = true,
    });
    defer srv.deinit();

    var sink: TicketSink = .{ .allocator = allocator };
    defer sink.deinit();

    var client_ctx = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    try client_ctx.setNewSessionCallback(TicketSink.cb, &sink);

    var cli = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .tls_context_override = client_ctx,
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: nullq.conn.path.Address = .{ .bytes = @splat(0xab) };
    try cli.conn.advance();

    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (sink.captured != null) break;
    }

    try std.testing.expect(sink.captured != null);
    const original_bytes = sink.captured.?;
    const original_id = ticketIdentity(original_bytes);

    // Round-trip the ticket through fromBytes/toBytes. The resulting
    // bytes are byte-identical (per `boringssl-zig` §0.4.0 contract),
    // so SHA-256 is too.
    var session = try boringssl.tls.Session.fromBytes(cli.tls_ctx, original_bytes);
    defer session.deinit();
    const round_trip_bytes = try session.toBytes(allocator);
    defer allocator.free(round_trip_bytes);
    try std.testing.expectEqualSlices(u8, original_bytes, round_trip_bytes);
    const round_trip_id = ticketIdentity(round_trip_bytes);
    try std.testing.expectEqualSlices(u8, &original_id, &round_trip_id);
}
