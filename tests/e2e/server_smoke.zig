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

    // Parse the queued bytes back as a VN packet and verify the
    // CIDs are swapped (RFC 8999 §6) and the supported_versions
    // list contains exactly QUIC_VERSION_1.
    const parsed = try nullq.wire.header.parse(drained.slice(), 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    const vn = parsed.header.version_negotiation;
    // The VN response sets DCID=client SCID and SCID=client DCID.
    try std.testing.expectEqualSlices(u8, &.{ 0xb0, 0xb1, 0xb2, 0xb3 }, vn.dcid.slice());
    try std.testing.expectEqualSlices(u8, &.{ 0xa0, 0xa1, 0xa2, 0xa3 }, vn.scid.slice());
    try std.testing.expectEqual(@as(usize, 1), vn.versionCount());
    try std.testing.expectEqual(nullq.QUIC_VERSION_1, vn.version(0));

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
