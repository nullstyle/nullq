//! Smoke tests for the high-level `nullq.Server` convenience type.
//!
//! These run from the integration-test module so they can
//! `@embedFile` the existing PEM fixtures under `tests/data/` —
//! anything in `src/server.zig` itself can't reach those because
//! they sit outside the published `nullq` package.

const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;
const defaultParams = common.defaultParams;

/// Build a fresh server-mode TLS context wired identically to the
/// one `Server.init` constructs internally — TLS-1.3 only,
/// `verify=.none`, ALPN preloaded, early data enabled, and the test
/// cert/key loaded. Helper for the TLS-reload tests so each test
/// can hand the Server an `.override` and compare `inner` pointers.
fn buildOverrideTlsCtx(alpn: []const []const u8) !boringssl.tls.Context {
    var ctx = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = alpn,
        .early_data_enabled = true,
    });
    errdefer ctx.deinit();
    try ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
    return ctx;
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

test "Server.feed with unsupported version queues a Version Negotiation packet" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Long-header packet declaring version 0xdeadbeef, with 4-byte
    // DCID and 4-byte SCID. Anything past the SCID is unparsed
    // junk and irrelevant to VN — the server only needs the
    // version + CIDs to assemble the response.
    var bytes = [_]u8{
        0xc0, // long-header bit set, type=Initial-ish
        0xde, 0xad, 0xbe, 0xef, // unsupported version
        0x04, // DCID len
        0xa0, 0xa1, 0xa2, 0xa3, // DCID
        0x04, // SCID len
        0xb0, 0xb1, 0xb2, 0xb3, // SCID
        0x00, 0x00, 0x00, // padding
    };
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x77) };

    const outcome = try srv.feed(&bytes, addr, 1000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.version_negotiated, outcome);
    try std.testing.expectEqual(@as(usize, 1), srv.statelessResponseCount());
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    const drained = srv.drainStatelessResponse() orelse return error.NoStatelessResponse;
    try std.testing.expect(addr.eql(drained.dst));

    const wire_bytes = drained.slice();

    // Wire-level invariants (RFC 8999 §6 / RFC 9000 §6):
    //   - byte 0 has the long-header bit set;
    //   - version field (bytes 1..5) is zero — that's the VN sentinel.
    try std.testing.expect(wire_bytes.len >= 7);
    try std.testing.expect((wire_bytes[0] & 0x80) != 0);
    try std.testing.expectEqual(
        @as(u32, 0),
        std.mem.readInt(u32, wire_bytes[1..5], .big),
    );

    // Parse the queued bytes back as a VN packet and verify the
    // CIDs are swapped (RFC 8999 §6) and the supported_versions
    // list contains exactly QUIC_VERSION_1.
    const parsed = try nullq.wire.header.parse(wire_bytes, 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    const vn = parsed.header.version_negotiation;
    // The VN response sets DCID=client SCID and SCID=client DCID.
    try std.testing.expectEqualSlices(u8, &.{ 0xb0, 0xb1, 0xb2, 0xb3 }, vn.dcid.slice());
    try std.testing.expectEqualSlices(u8, &.{ 0xa0, 0xa1, 0xa2, 0xa3 }, vn.scid.slice());
    try std.testing.expectEqual(@as(usize, 1), vn.versionCount());
    try std.testing.expectEqual(nullq.QUIC_VERSION_1, vn.version(0));

    // Layout sanity: 1 (first byte) + 4 (version=0) + 1 (dcid_len) +
    // 4 (dcid) + 1 (scid_len) + 4 (scid) + 4 (one supported version)
    // = 19 bytes. No trailing junk: pn_offset is 0 for VN, and the
    // versions slice borrows from wire_bytes[end..].
    try std.testing.expectEqual(@as(usize, 19), wire_bytes.len);
    // The supported_versions slice the parser handed back must be
    // contained in (and end exactly at) the drained bytes — no extra
    // trailing data.
    const versions_end = @intFromPtr(vn.versions_bytes.ptr) +
        vn.versions_bytes.len;
    const wire_end = @intFromPtr(wire_bytes.ptr) + wire_bytes.len;
    try std.testing.expectEqual(wire_end, versions_end);

    // Drain returns null once the queue is empty.
    try std.testing.expectEqual(@as(?nullq.Server.StatelessResponse, null), srv.drainStatelessResponse());
}

test "Server.feed without `from` drops unsupported-version packets" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    var bytes = [_]u8{
        0xc0,
        0xde, 0xad, 0xbe, 0xef,
        0x04,
        0xa0, 0xa1, 0xa2, 0xa3,
        0x04,
        0xb0, 0xb1, 0xb2, 0xb3,
        0x00,
    };

    // Without a destination, the server can't queue a VN — drop
    // per the documented pass-through behavior.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.dropped,
        try srv.feed(&bytes, null, 0),
    );
    try std.testing.expectEqual(@as(usize, 0), srv.statelessResponseCount());
}

test "Server.feed with retry_token_key issues a Retry then drops a malformed echo" {
    const protos = [_][]const u8{"hq-test"};

    const retry_key: nullq.RetryTokenKey = .{
        0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
        0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
        0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
        0xf2, 0x83, 0x1d, 0xb6, 0x95, 0x77, 0x40, 0x29,
    };

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .retry_token_key = retry_key,
    });
    defer srv.deinit();

    // First Initial: no token. Build an Initial that parses
    // cleanly — the wire-format is Initial-shape with an explicit
    // token-length=0 varint, payload-length=0 varint, and PN
    // truncated 1-byte. That's enough for `peekInitialToken` to
    // surface "no token" and trigger Retry.
    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };

    // Hand-roll an Initial header (token-len=0, payload-len=1,
    // pn-bits=00 i.e. 1-byte PN). The cell after the PN doesn't
    // matter — Retry never inspects the payload.
    var initial: [256]u8 = @splat(0);
    initial[0] = 0xc0; // long header, type=Initial, PN-len bits=00
    std.mem.writeInt(u32, initial[1..5], nullq.QUIC_VERSION_1, .big);
    initial[5] = odcid.len;
    @memcpy(initial[6..][0..odcid.len], &odcid);
    var pos: usize = 6 + odcid.len;
    initial[pos] = client_scid.len;
    pos += 1;
    @memcpy(initial[pos..][0..client_scid.len], &client_scid);
    pos += client_scid.len;
    initial[pos] = 0x00; // token length: 0
    pos += 1;
    initial[pos] = 0x01; // payload length: 1
    pos += 1;
    initial[pos] = 0x00; // PN
    pos += 1;
    initial[pos] = 0xff; // payload byte (irrelevant)
    const initial_len = pos + 1;

    const addr = nullq.conn.path.Address{ .bytes = @splat(0x42) };
    const outcome1 = try srv.feed(initial[0..initial_len], addr, 1_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.retry_sent, outcome1);
    try std.testing.expectEqual(@as(usize, 1), srv.statelessResponseCount());
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    const retry_resp = srv.drainStatelessResponse() orelse return error.NoRetryQueued;
    try std.testing.expect(addr.eql(retry_resp.dst));
    const retry_parsed = try nullq.wire.header.parse(retry_resp.slice(), 0);
    try std.testing.expect(retry_parsed.header == .retry);
    try std.testing.expectEqualSlices(u8, &client_scid, retry_parsed.header.retry.dcid.slice());
    try std.testing.expectEqual(@as(usize, 53), retry_parsed.header.retry.retry_token.len);

    // Second Initial: malformed token (4 bytes of garbage instead
    // of the canonical 53-byte token). The peer is addressing the
    // retry SCID we just minted, but the token won't validate, so
    // the datagram drops and no Connection is created.
    const retry_scid_bytes = retry_parsed.header.retry.scid.slice();
    var bad_initial: [256]u8 = @splat(0);
    bad_initial[0] = 0xc0;
    std.mem.writeInt(u32, bad_initial[1..5], nullq.QUIC_VERSION_1, .big);
    bad_initial[5] = @intCast(retry_scid_bytes.len);
    @memcpy(bad_initial[6..][0..retry_scid_bytes.len], retry_scid_bytes);
    var bp: usize = 6 + retry_scid_bytes.len;
    bad_initial[bp] = client_scid.len;
    bp += 1;
    @memcpy(bad_initial[bp..][0..client_scid.len], &client_scid);
    bp += client_scid.len;
    bad_initial[bp] = 0x04; // token length: 4
    bp += 1;
    const garbage_token = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    @memcpy(bad_initial[bp..][0..4], &garbage_token);
    bp += 4;
    bad_initial[bp] = 0x01;
    bp += 1;
    bad_initial[bp] = 0x00;
    bp += 1;
    bad_initial[bp] = 0xff;
    const bad_len = bp + 1;

    const outcome2 = try srv.feed(bad_initial[0..bad_len], addr, 2_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome2);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    // Crucially: a malformed echo does NOT mint a fresh Retry
    // (per the documented behavior — would amplify probing).
    try std.testing.expectEqual(@as(usize, 0), srv.statelessResponseCount());
}

test "Server.feed Retry happy-path: client echoes a valid token and a slot opens" {
    // Drive a real `nullq.Client` through the Retry round trip:
    //   1. Client emits Initial #1 (no token).
    //   2. Server queues Retry, returns `.retry_sent`.
    //   3. We hand the Retry to the Client; it captures the token,
    //      switches its peer DCID to the Retry SCID, and re-arms the
    //      Initial PN space.
    //   4. Client emits Initial #2 with the captured token.
    //   5. Server validates the token and opens a slot — `.accepted`.
    //
    // Hand-rolling Initial #2 would mean reproducing the AEAD seal,
    // header protection, and the post-Retry CID/keys swap; the
    // canonical client already does that. The Client's TLS/QUIC
    // wiring is the load-bearing path we want to cover here anyway.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    const retry_key: nullq.RetryTokenKey = .{
        0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
        0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
        0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
        0xf2, 0x83, 0x1d, 0xb6, 0x95, 0x77, 0x40, 0x29,
    };

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .retry_token_key = retry_key,
    });
    defer srv.deinit();

    var client = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    // Step 1: drive the client's TLS state forward until the first
    // Initial is in its outbox, then poll it out.
    try client.conn.advance();

    var initial1: [2048]u8 = undefined;
    const n1 = (try client.conn.poll(&initial1, 1_000)) orelse
        return error.NoInitialEmitted;

    const addr = nullq.conn.path.Address{ .bytes = @splat(0x42) };

    // Step 2: feed Initial #1 to the server. Should trigger Retry.
    const outcome1 = try srv.feed(initial1[0..n1], addr, 1_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.retry_sent, outcome1);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), srv.statelessResponseCount());

    // Step 3: drain the Retry, parse it, sanity-check it.
    var retry_resp = srv.drainStatelessResponse() orelse
        return error.NoRetryQueued;
    try std.testing.expect(addr.eql(retry_resp.dst));

    const retry_parsed = try nullq.wire.header.parse(retry_resp.slice(), 0);
    try std.testing.expect(retry_parsed.header == .retry);
    const retry = retry_parsed.header.retry;
    try std.testing.expectEqual(nullq.QUIC_VERSION_1, retry.version);
    // RFC 9000 §17.2.5: token is 53 bytes (header 21 + HMAC tag 32).
    try std.testing.expectEqual(@as(usize, 53), retry.retry_token.len);

    // Step 4: hand the Retry to the client. `Connection.handle`
    // accepts the Retry, swaps its peer/initial DCID to the server's
    // retry SCID, and re-arms the Initial PN space with the token.
    // `handle` wants a mutable slice — copy out of the response.
    var retry_buf: [256]u8 = undefined;
    const retry_len = retry_resp.slice().len;
    @memcpy(retry_buf[0..retry_len], retry_resp.slice());
    try client.conn.handle(retry_buf[0..retry_len], null, 1_500);

    // Step 5: poll the next Initial. It carries the captured token
    // and addresses the server's retry SCID.
    var initial2: [2048]u8 = undefined;
    const n2 = (try client.conn.poll(&initial2, 2_000)) orelse
        return error.NoEchoedInitialEmitted;

    // Sanity-check the echoed Initial before feeding it: parse it as
    // a long header and confirm the token is present and matches.
    const echo_parsed = try nullq.wire.header.parse(initial2[0..n2], 0);
    try std.testing.expect(echo_parsed.header == .initial);
    try std.testing.expectEqualSlices(
        u8,
        retry.retry_token,
        echo_parsed.header.initial.token,
    );
    try std.testing.expectEqualSlices(
        u8,
        retry.scid.slice(),
        echo_parsed.header.initial.dcid.slice(),
    );

    // Step 6: feed the echoed Initial to the server. The token
    // validates, a slot is allocated, and the per-source Retry state
    // is cleared.
    const outcome2 = try srv.feed(initial2[0..n2], addr, 2_500);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.accepted, outcome2);
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    // No new stateless response: a successful echo proceeds to slot
    // creation, it does not mint another Retry.
    try std.testing.expectEqual(@as(usize, 0), srv.statelessResponseCount());

    // Closing the slot is the embedder's responsibility on shutdown;
    // `srv.deinit` cleans up regardless.
}

test "Server.feed Retry rejects an echoed token whose lifetime has elapsed" {
    // Variant of the happy-path test: configure a 1µs Retry token
    // lifetime so the second feed lands beyond `expires_at` and the
    // gate returns `.drop`. Confirms the expiry branch of
    // `applyRetryGate.validate`.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    const retry_key: nullq.RetryTokenKey = .{
        0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
        0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
        0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
        0xf2, 0x83, 0x1d, 0xb6, 0x95, 0x77, 0x40, 0x29,
    };

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .retry_token_key = retry_key,
        .retry_token_lifetime_us = 1,
    });
    defer srv.deinit();

    var client = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    try client.conn.advance();

    var initial1: [2048]u8 = undefined;
    const n1 = (try client.conn.poll(&initial1, 1_000)) orelse
        return error.NoInitialEmitted;

    const addr = nullq.conn.path.Address{ .bytes = @splat(0x42) };
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.retry_sent,
        try srv.feed(initial1[0..n1], addr, 1_000),
    );

    var retry_resp = srv.drainStatelessResponse() orelse
        return error.NoRetryQueued;

    var retry_buf: [256]u8 = undefined;
    const retry_len = retry_resp.slice().len;
    @memcpy(retry_buf[0..retry_len], retry_resp.slice());
    try client.conn.handle(retry_buf[0..retry_len], null, 1_500);

    var initial2: [2048]u8 = undefined;
    const n2 = (try client.conn.poll(&initial2, 2_000)) orelse
        return error.NoEchoedInitialEmitted;

    // Feed the echoed Initial well after the 1µs expiry window. The
    // token is structurally well-formed and HMAC-correct, but its
    // `expires_at_us` (= mint_now + 1) is far in the past relative
    // to this `now_us`, so `validate` returns `.expired` and the
    // gate drops the datagram without minting a fresh Retry.
    const outcome = try srv.feed(initial2[0..n2], addr, 1_000_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), srv.statelessResponseCount());
}

test "Server.replaceTlsContext on an empty server swaps the current context and tears down the old one" {
    // No live slots → the swap has no draining entry to record.
    // `current_generation` still bumps; the new context becomes
    // current; the previous Server-owned context is freed in place
    // (the leak detector catches the failure mode).
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    try std.testing.expectEqual(@as(u32, 0), srv.current_generation);
    try std.testing.expect(srv.owns_tls);
    const old_inner = srv.tls_ctx.inner;

    // Hand the Server a fresh override built outside its API so we
    // can compare `inner` pointers afterward.
    const new_ctx = try buildOverrideTlsCtx(&protos);
    const new_inner = new_ctx.inner;
    try srv.replaceTlsContext(.{ .override = new_ctx });

    // The current context now points at the new SSL_CTX, the old
    // one was torn down (no live slot to keep it draining), and the
    // generation rolled over to 1.
    try std.testing.expectEqual(new_inner, srv.tls_ctx.inner);
    try std.testing.expect(srv.owns_tls);
    try std.testing.expectEqual(@as(u32, 1), srv.current_generation);
    try std.testing.expectEqual(@as(usize, 0), srv.draining_tls_contexts.items.len);
    try std.testing.expect(old_inner != new_inner);

    // PEM-variant reload also works on an empty server.
    try srv.replaceTlsContext(.{ .pem = .{
        .cert_pem = test_cert_pem,
        .key_pem = test_key_pem,
    } });
    try std.testing.expectEqual(@as(u32, 2), srv.current_generation);
    try std.testing.expect(srv.tls_ctx.inner != new_inner);
    try std.testing.expectEqual(@as(usize, 0), srv.draining_tls_contexts.items.len);
}

test "Server.replaceTlsContext while a slot is live drains the old context and routes new connections through the new one" {
    // 1. Drive a real client to deposit an Initial → slot opens at
    //    generation 0, against the original Server-built context.
    // 2. Replace the TLS context with an `.override` whose `inner`
    //    we captured up-front. Verify the old context migrates into
    //    `draining_tls_contexts` with refcount=1, the new context
    //    becomes current, and `current_generation` bumps to 1.
    // 3. Drive a second client. Its Initial accepts into a fresh
    //    slot stamped with generation=1 (i.e. the new context).
    // 4. Close + reap each slot in turn, verifying the draining
    //    entry's refcount decrements when the gen-0 slot is reaped
    //    and the entry is removed entirely on the same reap.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    const old_inner = srv.tls_ctx.inner;

    // -- step 1: open slot #1 against the original context --
    var client1 = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client1.deinit();
    try client1.conn.advance();

    var initial_buf1: [2048]u8 = undefined;
    const n1 = (try client1.conn.poll(&initial_buf1, 1_000)) orelse
        return error.NoInitialEmitted;

    const addr1 = nullq.conn.path.Address{ .bytes = @splat(0x11) };
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.accepted,
        try srv.feed(initial_buf1[0..n1], addr1, 1_000),
    );
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expectEqual(@as(u32, 0), srv.slots.items[0].tls_generation);

    // -- step 2: hot-swap the context --
    const new_ctx = try buildOverrideTlsCtx(&protos);
    const new_inner = new_ctx.inner;
    try srv.replaceTlsContext(.{ .override = new_ctx });

    try std.testing.expectEqual(new_inner, srv.tls_ctx.inner);
    try std.testing.expectEqual(@as(u32, 1), srv.current_generation);
    try std.testing.expectEqual(@as(usize, 1), srv.draining_tls_contexts.items.len);
    try std.testing.expectEqual(old_inner, srv.draining_tls_contexts.items[0].ctx.inner);
    try std.testing.expectEqual(@as(u32, 0), srv.draining_tls_contexts.items[0].generation);
    try std.testing.expectEqual(@as(usize, 1), srv.draining_tls_contexts.items[0].refcount);
    // The original slot still talks to the old context — its
    // generation tag did not change.
    try std.testing.expectEqual(@as(u32, 0), srv.slots.items[0].tls_generation);

    // -- step 3: open slot #2 against the new context --
    var client2 = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client2.deinit();
    try client2.conn.advance();

    var initial_buf2: [2048]u8 = undefined;
    const n2 = (try client2.conn.poll(&initial_buf2, 2_000)) orelse
        return error.NoInitialEmitted;

    const addr2 = nullq.conn.path.Address{ .bytes = @splat(0x22) };
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.accepted,
        try srv.feed(initial_buf2[0..n2], addr2, 2_000),
    );
    try std.testing.expectEqual(@as(usize, 2), srv.connectionCount());

    // The new slot is at gen=1 (matches `current_generation`); the
    // old slot is still at gen=0. The draining refcount didn't
    // change — only reap touches it.
    var found_gen_0 = false;
    var found_gen_1 = false;
    for (srv.slots.items) |slot| {
        if (slot.tls_generation == 0) found_gen_0 = true;
        if (slot.tls_generation == 1) found_gen_1 = true;
    }
    try std.testing.expect(found_gen_0);
    try std.testing.expect(found_gen_1);
    try std.testing.expectEqual(@as(usize, 1), srv.draining_tls_contexts.items[0].refcount);

    // -- step 4: close both slots and reap --
    // Close the gen-1 slot first so we can confirm that reaping it
    // does NOT touch the draining entry (current generation).
    var gen_0_slot: *nullq.Server.Slot = undefined;
    var gen_1_slot: *nullq.Server.Slot = undefined;
    for (srv.slots.items) |slot| {
        if (slot.tls_generation == 0) gen_0_slot = slot;
        if (slot.tls_generation == 1) gen_1_slot = slot;
    }
    gen_1_slot.conn.close(true, 0x00, "test");
    // `close()` only sets pending_close; we have to drive a `poll`
    // for the CONNECTION_CLOSE frame to be emitted and the
    // connection to flip to `lifecycle.closed = true`. The poll
    // output goes nowhere — this is just a state-pumping call.
    var drain_buf: [2048]u8 = undefined;
    _ = try gen_1_slot.conn.poll(&drain_buf, 3_000);
    try std.testing.expect(gen_1_slot.conn.isClosed());
    try std.testing.expectEqual(@as(usize, 1), srv.reap());
    // Draining entry untouched — current-gen slot reaping is a no-op
    // for the refcount path.
    try std.testing.expectEqual(@as(usize, 1), srv.draining_tls_contexts.items.len);
    try std.testing.expectEqual(@as(usize, 1), srv.draining_tls_contexts.items[0].refcount);

    // Close the gen-0 slot. Reaping it should drop the refcount to
    // zero, deinit the draining context, and remove the entry.
    gen_0_slot.conn.close(true, 0x00, "test");
    _ = try gen_0_slot.conn.poll(&drain_buf, 4_000);
    try std.testing.expect(gen_0_slot.conn.isClosed());
    try std.testing.expectEqual(@as(usize, 1), srv.reap());
    try std.testing.expectEqual(@as(usize, 0), srv.draining_tls_contexts.items.len);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

test "Server.deinit after replaceTlsContext cleans up unreaped draining contexts" {
    // The leak detector is the actual oracle here: build a Server,
    // open a slot, swap the TLS context (so the old one moves into
    // `draining_tls_contexts` with refcount=1), then call
    // `srv.deinit` *without* reaping the gen-0 slot. The deinit
    // path must tear down both the current and the draining
    // context, plus the slot's Connection. Any leak fails the test.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });

    var client = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();
    try client.conn.advance();

    var initial_buf: [2048]u8 = undefined;
    const n = (try client.conn.poll(&initial_buf, 1_000)) orelse
        return error.NoInitialEmitted;
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x42) };
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.accepted,
        try srv.feed(initial_buf[0..n], addr, 1_000),
    );

    // Two swaps in a row → two draining entries (refcount=1 on the
    // first, refcount=0 path on the second since slot count at
    // gen=1 is zero, so the second pre-swap context is freed
    // in-place rather than draining).
    const new_ctx_a = try buildOverrideTlsCtx(&protos);
    try srv.replaceTlsContext(.{ .override = new_ctx_a });
    try std.testing.expectEqual(@as(usize, 1), srv.draining_tls_contexts.items.len);

    // Second swap: the post-swap-1 context has zero gen-1 slots, so
    // it is `deinit`-ed in place and never enters the draining list.
    try srv.replaceTlsContext(.{ .pem = .{
        .cert_pem = test_cert_pem,
        .key_pem = test_key_pem,
    } });
    try std.testing.expectEqual(@as(usize, 1), srv.draining_tls_contexts.items.len);
    try std.testing.expectEqual(@as(u32, 2), srv.current_generation);

    // No reap; jump straight to deinit. Leak detector validates.
    srv.deinit();
}
