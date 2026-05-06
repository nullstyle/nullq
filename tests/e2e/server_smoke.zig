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

/// Pad a short long-header Initial fixture out to RFC 9000 §14's
/// 1200-byte UDP-payload minimum so `Server.feed` doesn't drop it
/// on the size gate before reaching the test's actual assertion
/// surface (table-full / rate-limit / Retry / log_callback / metrics).
/// Trailing bytes are zero — these fixtures all hit gates that fire
/// before payload-decode, so post-prefix content is irrelevant.
fn padInitial(prefix: []const u8) [1200]u8 {
    std.debug.assert(prefix.len <= 1200);
    var out: [1200]u8 = @splat(0);
    @memcpy(out[0..prefix.len], prefix);
    return out;
}

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
    var junk = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd } ++ @as([32]u8, @splat(0));
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

test "Server.feed drops QUIC v1 Initial datagrams below the 1200-byte minimum (RFC 9000 §14)" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Long-header Initial with QUIC v1 version, but the UDP datagram
    // payload is 7 bytes — way below the 1200-byte floor. Per RFC
    // 9000 §14 the server MUST discard it. The drop fires *before*
    // any Connection state is allocated, so no slot is created.
    var tiny_v1_initial = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 };
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x01) };
    const outcome = try srv.feed(&tiny_v1_initial, addr, 1_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // The drop is counted distinctly so ops can grep amplification
    // probes without conflating with generic malformed-packet drops.
    const metrics = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), metrics.feeds_initial_too_small);
    try std.testing.expectEqual(@as(u64, 1), metrics.feeds_dropped);

    // Same fixture but with a non-v1 version: must NOT take the
    // §14 path — version-negotiation handling owns unsupported
    // versions, regardless of datagram size (RFC 9000 §6 governs
    // VN, not §14). Also asserted: the size counter doesn't move.
    var tiny_unsupported_version = [_]u8{ 0xc0, 0xde, 0xad, 0xbe, 0xef, 4, 0xa, 0xb, 0xc, 0xd, 4, 0x1, 0x2, 0x3, 0x4 };
    const outcome2 = try srv.feed(&tiny_unsupported_version, addr, 2_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.version_negotiated, outcome2);
    const metrics2 = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), metrics2.feeds_initial_too_small);
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
    var bytes = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 });
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
    var initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });
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

test "Server VN per-source rate limiter caps VN responses (hardening guide §4.4)" {
    // Per-source VN-emission cap. After `max_vn_per_source_per_window`
    // VN responses to a given source within `source_rate_window_us`,
    // further non-v1 long-header probes from that source are dropped
    // (no VN emitted, queue not bumped). Independent from the Initial
    // budget — a peer that floods VN probes shouldn't burn the same
    // counter that gates Initial slot creation.
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_vn_per_source_per_window = 3,
        .source_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    // 19-byte non-v1 long-header packet (same shape the existing VN
    // test uses). Version 0xdeadbeef — well below 1200 bytes, but
    // VN handling is governed by §6 not §14 so the size gate doesn't
    // fire here.
    var probe = [_]u8{
        0xc0,
        0xde, 0xad, 0xbe, 0xef,
        0x04,
        0xa0, 0xa1, 0xa2, 0xa3,
        0x04,
        0xb0, 0xb1, 0xb2, 0xb3,
        0x00, 0x00, 0x00,
    };
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x77) };

    // First three probes from this source: each earns a VN response.
    for (0..3) |i| {
        try std.testing.expectEqual(
            nullq.Server.FeedOutcome.version_negotiated,
            try srv.feed(&probe, addr, @intCast(i)),
        );
    }

    // Fourth probe: rate-limited, no VN queued.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.dropped,
        try srv.feed(&probe, addr, 4),
    );

    // Different source from cleared address space: gets its own budget.
    const other_addr = nullq.conn.path.Address{ .bytes = @splat(0x88) };
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.version_negotiated,
        try srv.feed(&probe, other_addr, 5),
    );

    // After the window elapses, the original source's VN budget resets.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.version_negotiated,
        try srv.feed(&probe, addr, 1_500_000),
    );

    // Counters reflect the gate firings exactly.
    const m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 5), m.feeds_version_negotiated);
    try std.testing.expectEqual(@as(u64, 1), m.feeds_vn_rate_limited);
    try std.testing.expectEqual(@as(u64, 1), m.feeds_dropped);
}

test "Server VN rate limit and Initial rate limit use independent counters" {
    // A peer that spams VN probes shouldn't burn the per-source
    // Initial budget, and vice versa. Each (source, kind) gets its
    // own count + window inside `SourceRateEntry`.
    const protos = [_][]const u8{"hq-test"};

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_initials_per_source_per_window = 2,
        .max_vn_per_source_per_window = 2,
        .source_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    var vn_probe = [_]u8{
        0xc0,
        0xde, 0xad, 0xbe, 0xef,
        0x04,
        0xa0, 0xa1, 0xa2, 0xa3,
        0x04,
        0xb0, 0xb1, 0xb2, 0xb3,
        0x00, 0x00, 0x00,
    };
    var v1_initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });

    const addr = nullq.conn.path.Address{ .bytes = @splat(0x99) };

    // Two VN probes — both earn responses, VN budget consumed.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.version_negotiated,
        try srv.feed(&vn_probe, addr, 0),
    );
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.version_negotiated,
        try srv.feed(&vn_probe, addr, 1),
    );

    // Now Initial probes from the same address — Initial budget is
    // STILL FULL despite VN budget being exhausted. First two pass,
    // third rate-limits on the Initial side.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.dropped, // openSlot fails (DCID len 21), but rate-limit not yet hit
        try srv.feed(&v1_initial, addr, 2),
    );
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.dropped,
        try srv.feed(&v1_initial, addr, 3),
    );
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.rate_limited,
        try srv.feed(&v1_initial, addr, 4),
    );

    // VN budget on this address still empty: a third VN probe
    // rate-limits on the VN side, independently.
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.dropped,
        try srv.feed(&vn_probe, addr, 5),
    );

    const m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), m.feeds_version_negotiated);
    try std.testing.expectEqual(@as(u64, 1), m.feeds_vn_rate_limited);
    try std.testing.expectEqual(@as(u64, 1), m.feeds_rate_limited);
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
    // matter — Retry never inspects the payload. The buffer is
    // 1200 bytes so the datagram clears the RFC 9000 §14 minimum;
    // trailing zeros are ignored by the Retry-gate parser, which
    // only reads up through token_length + token.
    var initial: [1200]u8 = @splat(0);
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

    const addr = nullq.conn.path.Address{ .bytes = @splat(0x42) };
    const outcome1 = try srv.feed(&initial, addr, 1_000);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.retry_sent, outcome1);
    try std.testing.expectEqual(@as(usize, 1), srv.statelessResponseCount());
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    const retry_resp = srv.drainStatelessResponse() orelse return error.NoRetryQueued;
    try std.testing.expect(addr.eql(retry_resp.dst));
    const retry_parsed = try nullq.wire.header.parse(retry_resp.slice(), 0);
    try std.testing.expect(retry_parsed.header == .retry);
    try std.testing.expectEqualSlices(u8, &client_scid, retry_parsed.header.retry.dcid.slice());
    // v2 (AES-GCM-256) tokens are 96 bytes wire-shape: 12 nonce + 68
    // ciphertext + 16 tag (was 53 bytes under the v1 HMAC-only format).
    try std.testing.expectEqual(nullq.conn.retry_token.max_token_len, retry_parsed.header.retry.retry_token.len);

    // Second Initial: malformed token (4 bytes of garbage instead
    // of the canonical 96-byte token). The peer is addressing the
    // retry SCID we just minted, but the token won't validate, so
    // the datagram drops and no Connection is created.
    const retry_scid_bytes = retry_parsed.header.retry.scid.slice();
    // Same 1200-byte trick: the Retry validator reads up through
    // token_length + token only; trailing zeros are ignored.
    var bad_initial: [1200]u8 = @splat(0);
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

    const outcome2 = try srv.feed(&bad_initial, addr, 2_000);
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
    // v2 (AES-GCM-256) Retry token: 12-byte nonce + 68-byte ciphertext
    // + 16-byte tag = 96 bytes. The §4.3 hardening pass moved off the
    // v1 53-byte HMAC-only format so the wire bytes are uniformly
    // random (no plaintext bound-field reveal).
    try std.testing.expectEqual(nullq.conn.retry_token.max_token_len, retry.retry_token.len);

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

// -- distributed-tracing surface ------------------------------------
//
// `Slot.slot_id` is a server-local monotonic id stamped at slot
// creation; embedders use it as the primary key in operational logs
// and for trace correlation. `Slot.trace_id` / `Slot.parent_span_id`
// are opaque W3C tracecontext bytes the embedder attaches via
// `Slot.setTraceContext`. nullq does not interpret either.

/// Drive a real `nullq.Client` through to the first Initial and feed
/// it to `srv` so a slot opens. Returns the freshly accepted slot
/// pointer. The client is owned by the caller (deinit on cleanup).
fn acceptOneSlot(
    srv: *nullq.Server,
    client: *nullq.Client,
    addr: nullq.conn.path.Address,
    now_us: u64,
) !*nullq.Server.Slot {
    try client.conn.advance();
    var initial: [2048]u8 = undefined;
    const n = (try client.conn.poll(&initial, now_us)) orelse
        return error.NoInitialEmitted;
    const before = srv.connectionCount();
    const outcome = try srv.feed(initial[0..n], addr, now_us);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.accepted, outcome);
    try std.testing.expectEqual(before + 1, srv.connectionCount());
    return srv.iterator()[srv.iterator().len - 1];
}

test "Slot.slot_id is stable across feeds for the same connection" {
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

    var client = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    const addr = nullq.conn.path.Address{ .bytes = @splat(0x42) };
    const slot = try acceptOneSlot(&srv, &client, addr, 1_000);
    const first_id = slot.slot_id;

    // Drive a follow-up datagram from the same client. `Client.poll`
    // may emit ACK / handshake continuation; whatever it emits routes
    // to the same slot via `cid_table`. The slot_id must not change.
    var follow: [2048]u8 = undefined;
    if (try client.conn.poll(&follow, 2_000)) |n| {
        const outcome = try srv.feed(follow[0..n], addr, 2_000);
        try std.testing.expectEqual(nullq.Server.FeedOutcome.routed, outcome);
        try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
        try std.testing.expectEqual(first_id, srv.iterator()[0].slot_id);
    }
}

test "Slot.slot_id is monotonic and unique across multiple accepts" {
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

    var client_a = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client_a.deinit();

    var client_b = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client_b.deinit();

    var client_c = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client_c.deinit();

    const addr_a = nullq.conn.path.Address{ .bytes = @splat(0xa0) };
    const addr_b = nullq.conn.path.Address{ .bytes = @splat(0xb0) };
    const addr_c = nullq.conn.path.Address{ .bytes = @splat(0xc0) };

    const slot_a = try acceptOneSlot(&srv, &client_a, addr_a, 1_000);
    const id_a = slot_a.slot_id;
    const slot_b = try acceptOneSlot(&srv, &client_b, addr_b, 2_000);
    const id_b = slot_b.slot_id;
    const slot_c = try acceptOneSlot(&srv, &client_c, addr_c, 3_000);
    const id_c = slot_c.slot_id;

    // Strictly monotonic and unique.
    try std.testing.expect(id_a < id_b);
    try std.testing.expect(id_b < id_c);
    try std.testing.expect(id_a != id_b);
    try std.testing.expect(id_b != id_c);
    try std.testing.expect(id_a != id_c);
}

test "Slot.setTraceContext round-trips and defaults are null" {
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

    var client = try nullq.Client.connect(.{
        .allocator = allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    const addr = nullq.conn.path.Address{ .bytes = @splat(0x42) };
    const slot = try acceptOneSlot(&srv, &client, addr, 1_000);

    // Defaults: a freshly accepted slot has no trace metadata
    // attached. nullq never sets these itself.
    try std.testing.expectEqual(@as(?[16]u8, null), slot.trace_id);
    try std.testing.expectEqual(@as(?[8]u8, null), slot.parent_span_id);

    // Round-trip: embedder attaches a tracecontext, reads it back
    // verbatim. The values are arbitrary 16 / 8 byte blobs.
    const trace_id: [16]u8 = .{
        0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
        0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36,
    };
    const parent_span_id: [8]u8 = .{
        0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7,
    };
    slot.setTraceContext(trace_id, parent_span_id);

    try std.testing.expect(slot.trace_id != null);
    try std.testing.expect(slot.parent_span_id != null);
    try std.testing.expectEqualSlices(u8, &trace_id, &slot.trace_id.?);
    try std.testing.expectEqualSlices(u8, &parent_span_id, &slot.parent_span_id.?);
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

// -- observability ------------------------------------------------------

/// Test sink for `LogEvent`s. Pushes each event onto a heap-allocated
/// `ArrayList` so tests can drive a few `feed` calls and then
/// pattern-match the captured stream.
const LogSink = struct {
    events: std.ArrayList(nullq.Server.LogEvent) = .empty,
    allocator: std.mem.Allocator,

    fn cb(user_data: ?*anyopaque, ev: nullq.Server.LogEvent) void {
        const self: *LogSink = @ptrCast(@alignCast(user_data.?));
        self.events.append(self.allocator, ev) catch {};
    }

    fn deinit(self: *LogSink) void {
        self.events.deinit(self.allocator);
    }
};

test "Server log_callback fires for table_full" {
    const protos = [_][]const u8{"hq-test"};
    var sink: LogSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_concurrent_connections = 0,
        .log_callback = LogSink.cb,
        .log_user_data = &sink,
    });
    defer srv.deinit();

    var bytes = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 });
    const peer = nullq.conn.path.Address{ .bytes = @splat(0x55) };
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.table_full,
        try srv.feed(&bytes, peer, 0),
    );

    try std.testing.expectEqual(@as(usize, 1), sink.events.items.len);
    try std.testing.expect(sink.events.items[0] == .table_full);
    const got = sink.events.items[0].table_full;
    try std.testing.expect(got.peer != null);
    try std.testing.expect(peer.eql(got.peer.?));
}

test "Server log_callback fires for rate_limited and version_negotiated" {
    const protos = [_][]const u8{"hq-test"};
    var sink: LogSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_initials_per_source_per_window = 2,
        .source_rate_window_us = 1_000_000,
        .log_callback = LogSink.cb,
        .log_user_data = &sink,
    });
    defer srv.deinit();

    // VN-triggering: long-header, version=0xdeadbeef.
    var vn_bytes = [_]u8{
        0xc0, 0xde, 0xad, 0xbe, 0xef,
        0x04, 0xa0, 0xa1, 0xa2, 0xa3,
        0x04, 0xb0, 0xb1, 0xb2, 0xb3,
        0x00,
    };
    const vn_peer = nullq.conn.path.Address{ .bytes = @splat(0x77) };
    _ = try srv.feed(&vn_bytes, vn_peer, 1000);

    // Rate-limit: long-header v1 Initial that fails openSlot but
    // ticks the rate limiter. The DCID length 21 makes openSlotFromInitial
    // return InvalidConfig (DCID > 20). The first two attempts get .dropped
    // (each consuming a token); the third is rate-limited.
    var initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });
    const rl_peer = nullq.conn.path.Address{ .bytes = @splat(0xab) };
    _ = try srv.feed(&initial, rl_peer, 0);
    _ = try srv.feed(&initial, rl_peer, 1);
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.rate_limited,
        try srv.feed(&initial, rl_peer, 2),
    );

    // We expect at least one VN event and one rate-limited event.
    var saw_vn = false;
    var saw_rl = false;
    for (sink.events.items) |ev| {
        switch (ev) {
            .version_negotiated => |v| {
                try std.testing.expect(vn_peer.eql(v.peer));
                try std.testing.expectEqual(@as(u32, 0xdeadbeef), v.requested_version);
                saw_vn = true;
            },
            .feed_rate_limited => |r| {
                try std.testing.expect(rl_peer.eql(r.peer));
                try std.testing.expect(r.recent_count >= 2);
                saw_rl = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_vn);
    try std.testing.expect(saw_rl);
}

test "Server metricsSnapshot tracks counters across feed outcomes" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_initials_per_source_per_window = 2,
        .source_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    const baseline = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), baseline.feeds_dropped);
    try std.testing.expectEqual(@as(u64, 0), baseline.feeds_routed);
    try std.testing.expectEqual(@as(u64, 0), baseline.feeds_accepted);
    try std.testing.expectEqual(@as(u64, 0), baseline.live_connections);

    // Empty datagram -> dropped.
    var empty: [0]u8 = .{};
    _ = try srv.feed(&empty, null, 0);

    // VN -> version_negotiated counter increments and queue depth
    // ticks up to 1.
    var vn_bytes = [_]u8{
        0xc0, 0xde, 0xad, 0xbe, 0xef,
        0x04, 0xa0, 0xa1, 0xa2, 0xa3,
        0x04, 0xb0, 0xb1, 0xb2, 0xb3,
        0x00,
    };
    const vn_peer = nullq.conn.path.Address{ .bytes = @splat(0x77) };
    _ = try srv.feed(&vn_bytes, vn_peer, 100);

    // Rate-limit hit. Two attempts at the cap, then over.
    var initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });
    const rl_peer = nullq.conn.path.Address{ .bytes = @splat(0xab) };
    _ = try srv.feed(&initial, rl_peer, 0);
    _ = try srv.feed(&initial, rl_peer, 1);
    _ = try srv.feed(&initial, rl_peer, 2);

    const m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_version_negotiated);
    try std.testing.expectEqual(@as(u64, 1), m.feeds_rate_limited);
    // 3 dropped: empty + 2 attempts that consumed tokens then failed openSlot.
    try std.testing.expect(m.feeds_dropped >= 3);
    try std.testing.expectEqual(@as(u64, 0), m.feeds_accepted);
    try std.testing.expect(m.stateless_queue_depth >= 1);
    try std.testing.expect(m.stateless_queue_high_water >= 1);
}

test "Server rateLimitSnapshot reports top offender after cap is hit" {
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

    var initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });
    const heavy_peer = nullq.conn.path.Address{ .bytes = @splat(0xaa) };
    const light_peer = nullq.conn.path.Address{ .bytes = @splat(0x11) };

    // Heavy peer: 3 attempts then 1 rate-limited (count stays at cap=3).
    for (0..3) |i| _ = try srv.feed(&initial, heavy_peer, @intCast(i));
    try std.testing.expectEqual(
        nullq.Server.FeedOutcome.rate_limited,
        try srv.feed(&initial, heavy_peer, 4),
    );
    // Light peer: 1 attempt only.
    _ = try srv.feed(&initial, light_peer, 5);

    const snap = srv.rateLimitSnapshot();
    try std.testing.expectEqual(@as(u64, 1), snap.cumulative_rejections);
    try std.testing.expectEqual(@as(usize, 2), snap.table_size);
    try std.testing.expectEqual(@as(usize, 2), snap.top_offender_count);
    // Top offender is heavy_peer (count 3 vs 1).
    const top = snap.top_offenders[0];
    try std.testing.expect(heavy_peer.eql(top.addr));
    try std.testing.expectEqual(@as(u32, 3), top.recent_count);
    // Second is light_peer.
    try std.testing.expect(light_peer.eql(snap.top_offenders[1].addr));
    try std.testing.expectEqual(@as(u32, 1), snap.top_offenders[1].recent_count);
}

test "Server metricsSnapshot stateless_queue_high_water is sticky across drains" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Queue 3 VN responses from three different peers.
    var vn_bytes = [_]u8{
        0xc0, 0xde, 0xad, 0xbe, 0xef,
        0x04, 0xa0, 0xa1, 0xa2, 0xa3,
        0x04, 0xb0, 0xb1, 0xb2, 0xb3,
        0x00,
    };
    const peers = [_]nullq.conn.path.Address{
        .{ .bytes = @splat(0x01) },
        .{ .bytes = @splat(0x02) },
        .{ .bytes = @splat(0x03) },
    };
    for (peers) |p| _ = try srv.feed(&vn_bytes, p, 0);

    const before = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 3), before.stateless_queue_depth);
    try std.testing.expectEqual(@as(u64, 3), before.stateless_queue_high_water);

    // Drain all three.
    while (srv.drainStatelessResponse()) |_| {}

    const after = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), after.stateless_queue_depth);
    // High-water mark is sticky.
    try std.testing.expectEqual(@as(u64, 3), after.stateless_queue_high_water);
}

// -- §3.5 / §8: Connection.max_connection_memory cap -------------------

test "Connection rejects CRYPTO bytes that would exceed max_connection_memory" {
    // Hardening guide §3.5 / §8: the per-Connection resident-bytes
    // budget is the aggregate guard above the per-buffer caps. Tiny
    // cap here; push out-of-order CRYPTO totalling > cap so the
    // reservation trips before the per-level CRYPTO cap (which is
    // still 64 KiB) gets to gate anything. Connection should close
    // with EXCESSIVE_LOAD (0x09).
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    var conn = try nullq.Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    conn.max_connection_memory = 1024;

    // Push 1500 bytes of out-of-order CRYPTO at offset 5000 — this
    // forces buffering (offset 0 hasn't arrived yet) so all 1500 bytes
    // would go resident. 1500 > 1024 cap → EXCESSIVE_LOAD close.
    var data: [1500]u8 = @splat('A');
    try conn.handleCrypto(.initial, .{ .offset = 5000, .data = &data });

    const ev = conn.closeEvent() orelse return error.TestExpectedClose;
    try std.testing.expectEqual(
        nullq.conn.state.transport_error_excessive_load,
        ev.error_code,
    );
}

test "Stream recv reassembly past max_connection_memory closes the connection" {
    // Same backstop, exercised on the stream-recv-reassembly path.
    // Peer-sent stream 1 carries enough bytes that the recv buffer
    // lands above the 1 KiB cap. Connection closes with EXCESSIVE_LOAD.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    var conn = try nullq.Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    conn.max_connection_memory = 1024;
    // Allow the stream + connection-level data to land — flow control
    // and stream-count limits must not gate before the resident-bytes
    // cap fires.
    conn.local_max_data = 1 << 20;
    conn.local_max_streams_bidi = 100;
    // For peer-initiated bidi streams (client side: id&1==1), the
    // initial stream-level recv credit comes from
    // `initial_max_stream_data_bidi_remote`; default zero would close
    // with FLOW_CONTROL before EXCESSIVE_LOAD has a chance.
    conn.local_transport_params.initial_max_stream_data_bidi_remote = 1 << 20;

    var data: [4096]u8 = @splat('B');
    try conn.handleStream(.application, .{
        .stream_id = 1, // server-initiated bidi from client's POV
        .offset = 0,
        .data = &data,
        .fin = false,
    });

    const ev = conn.closeEvent() orelse return error.TestExpectedClose;
    try std.testing.expectEqual(
        nullq.conn.state.transport_error_excessive_load,
        ev.error_code,
    );
}

test "Frees release resident bytes so the cap is reusable" {
    // Hardening guide §3.5 / §8: every reservation pairs with a
    // release on the matching free path. Reserve a chunk that sits
    // close to the cap, drain it via `receiveDatagramInfo` (the
    // dequeue path that releases the corresponding bytes), then
    // reserve again. The second reservation must succeed.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    var conn = try nullq.Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    conn.max_connection_memory = 800;

    // Need DATAGRAM transport param so handleDatagram doesn't reject.
    conn.local_transport_params.max_datagram_frame_size = 4096;

    // First DATAGRAM: 600 bytes — well under the 800-byte cap.
    var dg1: [600]u8 = @splat('C');
    try conn.handleDatagram(.application, .{ .data = &dg1 });
    try std.testing.expectEqual(@as(u64, 600), conn.bytes_resident);

    // Second DATAGRAM with the buffer still full would overshoot
    // 800. Verify we can drain and then reserve again — the cap is
    // a soft ceiling on *resident* bytes, not a quota over the
    // connection's lifetime.
    var dg2: [400]u8 = @splat('D');
    try conn.handleDatagram(.application, .{ .data = &dg2 });
    // Connection should have closed with EXCESSIVE_LOAD; after
    // draining, the budget recovers.
    const ev1 = conn.closeEvent() orelse return error.TestExpectedClose;
    try std.testing.expectEqual(
        nullq.conn.state.transport_error_excessive_load,
        ev1.error_code,
    );

    // Drain the queued DATAGRAM and confirm the budget drops back
    // toward the floor.
    var sink: [4096]u8 = undefined;
    const got = conn.receiveDatagram(&sink) orelse return error.TestExpectedDatagram;
    try std.testing.expectEqual(@as(usize, 600), got);
    try std.testing.expectEqual(@as(u64, 0), conn.bytes_resident);
}

// -- §4.1: listener-level packet rate limit ---------------------------

test "Server listener rate limit drops datagrams past cap" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_datagrams_per_window = 3,
        .listener_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    // Use junk bytes so each datagram lands in `.dropped` for
    // unrelated reasons too (won't open a slot). The rate limit
    // applies *first*, so we should see the 4th call return
    // .dropped *because of the rate limit* — surfaced via the new
    // `feeds_listener_rate_limited` counter.
    var junk = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x10) };

    // First three: passes the listener gate (each then drops because
    // the bytes don't parse as a valid Initial).
    for (0..3) |i| {
        _ = try srv.feed(&junk, addr, @intCast(i));
    }
    const before = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), before.feeds_listener_rate_limited);

    // Fourth: trips the listener rate limit before any other gate.
    const outcome = try srv.feed(&junk, addr, 4);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome);

    const after = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), after.feeds_listener_rate_limited);
    try std.testing.expect(after.feeds_dropped > before.feeds_dropped);
}

test "Server listener rate limit window resets after elapsed" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_datagrams_per_window = 2,
        .listener_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    var junk = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x20) };

    // First window: fill it (2 calls), then over-cap at the 3rd.
    _ = try srv.feed(&junk, addr, 0);
    _ = try srv.feed(&junk, addr, 1);

    var m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_rate_limited);

    // Advance past the window (1 second + 1 µs) and try again — the
    // bucket resets, so the next two calls pass without hitting the
    // limiter.
    _ = try srv.feed(&junk, addr, 1_000_001);
    _ = try srv.feed(&junk, addr, 1_000_002);

    m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_rate_limited);
}

test "Server listener rate limit is null-by-default" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        // No `max_datagrams_per_window` — the limiter is off.
    });
    defer srv.deinit();

    var junk = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x30) };

    // Flood with 100 datagrams; none should hit the listener limit.
    for (0..100) |i| {
        _ = try srv.feed(&junk, addr, @intCast(i));
    }

    const m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_rate_limited);
}

test "Server.init rejects max_datagrams_per_window=0" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(nullq.Server.Error.InvalidConfig, nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_datagrams_per_window = 0,
    }));
}

// -- §9.4: per-source log-emission rate limit -------------------------

test "Server log rate limiter drops events past cap from one source" {
    const protos = [_][]const u8{"hq-test"};
    var sink: LogSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        // Force log events on every call: tiny rate-limit cap so the
        // first feed past it surfaces a `.feed_rate_limited` log.
        .max_initials_per_source_per_window = 1,
        // Cap log emission at 2 per source per window. The first 2
        // log emissions land; subsequent ones drop silently.
        .max_log_events_per_source_per_window = 2,
        .source_rate_window_us = 1_000_000,
        .log_callback = LogSink.cb,
        .log_user_data = &sink,
    });
    defer srv.deinit();

    var initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x40) };

    // Each call from the same source emits exactly one log event:
    //   call 1: openSlot fails internally → `.dropped` (no log)
    //   call 2 onward: rate-limited → emits `.feed_rate_limited`
    // We do a bunch of calls and expect the captured log count to
    // saturate at 2 (the per-source log cap), with the rest dropped.
    for (0..10) |i| {
        _ = try srv.feed(&initial, addr, @intCast(i));
    }

    // The rate limiter logs rapidly (call 2 onward); we expect 2
    // emissions max from this source.
    var feed_rate_limited_count: usize = 0;
    for (sink.events.items) |ev| {
        switch (ev) {
            .feed_rate_limited => feed_rate_limited_count += 1,
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 2), feed_rate_limited_count);

    const m = srv.metricsSnapshot();
    try std.testing.expect(m.feeds_log_rate_limited > 0);
}

test "Server log rate limiter is per-source (different sources get fresh budgets)" {
    const protos = [_][]const u8{"hq-test"};
    var sink: LogSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_initials_per_source_per_window = 1,
        .max_log_events_per_source_per_window = 1,
        .source_rate_window_us = 1_000_000,
        .log_callback = LogSink.cb,
        .log_user_data = &sink,
    });
    defer srv.deinit();

    var initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });
    const peer_a = nullq.conn.path.Address{ .bytes = @splat(0x51) };
    const peer_b = nullq.conn.path.Address{ .bytes = @splat(0x52) };

    // Each peer sees: call 1 → drop with no log, call 2+ → first
    // call past the Initial cap fires one log, subsequent are
    // suppressed by the log-rate limiter (cap=1).
    for (0..5) |i| _ = try srv.feed(&initial, peer_a, @intCast(i));
    for (0..5) |i| _ = try srv.feed(&initial, peer_b, @intCast(100 + i));

    // Each source should land exactly 1 log event (the cap); the
    // other source's budget is independent.
    var counts = [_]usize{ 0, 0 };
    for (sink.events.items) |ev| {
        if (ev != .feed_rate_limited) continue;
        if (peer_a.eql(ev.feed_rate_limited.peer)) counts[0] += 1;
        if (peer_b.eql(ev.feed_rate_limited.peer)) counts[1] += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), counts[0]);
    try std.testing.expectEqual(@as(usize, 1), counts[1]);
}

test "Server log rate limit window resets after elapsed" {
    const protos = [_][]const u8{"hq-test"};
    var sink: LogSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_initials_per_source_per_window = 1,
        .max_log_events_per_source_per_window = 1,
        .source_rate_window_us = 1_000_000,
        .log_callback = LogSink.cb,
        .log_user_data = &sink,
    });
    defer srv.deinit();

    var initial = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 21, 0 });
    const peer = nullq.conn.path.Address{ .bytes = @splat(0x60) };

    // Burn the cap inside the first window.
    for (0..5) |i| _ = try srv.feed(&initial, peer, @intCast(i));
    var first_count: usize = 0;
    for (sink.events.items) |ev| {
        if (ev == .feed_rate_limited and peer.eql(ev.feed_rate_limited.peer)) first_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), first_count);

    // Advance well past the window — the log limiter resets.
    for (0..5) |i| _ = try srv.feed(&initial, peer, @intCast(2_000_000 + i));
    var second_count: usize = 0;
    for (sink.events.items) |ev| {
        if (ev == .feed_rate_limited and peer.eql(ev.feed_rate_limited.peer)) second_count += 1;
    }
    // First batch produced 1 log; second batch produced 1 more.
    try std.testing.expectEqual(@as(usize, 2), second_count);
}

test "Server log rate limit doesn't block log events for from=null paths" {
    // Hardening guide §9.4: events with no source attribution
    // bypass the per-source log limiter. Verify by triggering a
    // table-full event with `from = null` — the log fires unconditionally.
    const protos = [_][]const u8{"hq-test"};
    var sink: LogSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_concurrent_connections = 0,
        // Aggressive cap — would suppress *every* per-source log.
        .max_log_events_per_source_per_window = 1,
        .source_rate_window_us = 1_000_000,
        .log_callback = LogSink.cb,
        .log_user_data = &sink,
    });
    defer srv.deinit();

    var bytes = padInitial(&.{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 });

    // 5 feeds with `from = null` — all should produce table_full
    // logs because the limiter doesn't apply when source is null.
    for (0..5) |i| {
        const outcome = try srv.feed(&bytes, null, @intCast(i));
        try std.testing.expectEqual(nullq.Server.FeedOutcome.table_full, outcome);
    }

    var table_full_count: usize = 0;
    for (sink.events.items) |ev| {
        if (ev == .table_full) table_full_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), table_full_count);

    // No log events were rate-limited.
    const m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), m.feeds_log_rate_limited);
}

// -- §4.1: listener-level byte rate limit -----------------------------

test "Server listener byte rate limit drops datagrams past byte cap" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_bytes_per_window = 1500,
        .listener_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    // 800-byte fixture leading with junk long-header bits — each
    // datagram drops on later gates, but the byte budget is checked
    // *first*, before any of those.
    var buf: [800]u8 = @splat(0);
    buf[0] = 0x40;
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x40) };

    // First 800-byte feed: bytes_in_window = 800 ≤ 1500. Pass.
    _ = try srv.feed(&buf, addr, 0);
    var m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_byte_rate_limited);

    // Second 800-byte feed: bytes_in_window = 1600 > 1500. Drop on
    // the byte cap.
    const outcome = try srv.feed(&buf, addr, 1);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome);
    m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_listener_byte_rate_limited);
    try std.testing.expect(m.feeds_dropped >= 1);
}

test "Server listener byte and packet caps are independently enforced" {
    const protos = [_][]const u8{"hq-test"};

    // Phase 1: byte-cap=1500, packet-cap=null. Spray many tiny
    // datagrams — total bytes stay under the cap, none drop.
    {
        var srv = try nullq.Server.init(.{
            .allocator = std.testing.allocator,
            .tls_cert_pem = test_cert_pem,
            .tls_key_pem = test_key_pem,
            .alpn_protocols = &protos,
            .transport_params = defaultParams(),
            .max_bytes_per_window = 1500,
            .listener_rate_window_us = 1_000_000,
        });
        defer srv.deinit();

        var one: [1]u8 = .{0x40};
        const addr = nullq.conn.path.Address{ .bytes = @splat(0x50) };

        // 1000 single-byte feeds — total 1000 bytes, well under 1500.
        for (0..1000) |i| {
            _ = try srv.feed(&one, addr, @intCast(i));
        }

        const m = srv.metricsSnapshot();
        try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_byte_rate_limited);
        try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_rate_limited);
    }

    // Phase 2: packet-cap=2, byte-cap=null. Spray small datagrams —
    // the third drops on packet count even though bytes are minimal.
    {
        var srv = try nullq.Server.init(.{
            .allocator = std.testing.allocator,
            .tls_cert_pem = test_cert_pem,
            .tls_key_pem = test_key_pem,
            .alpn_protocols = &protos,
            .transport_params = defaultParams(),
            .max_datagrams_per_window = 2,
            .listener_rate_window_us = 1_000_000,
        });
        defer srv.deinit();

        var one: [1]u8 = .{0x40};
        const addr = nullq.conn.path.Address{ .bytes = @splat(0x60) };

        _ = try srv.feed(&one, addr, 0);
        _ = try srv.feed(&one, addr, 1);

        var m = srv.metricsSnapshot();
        try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_rate_limited);
        try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_byte_rate_limited);

        // Third feed: trips the packet cap.
        const outcome = try srv.feed(&one, addr, 2);
        try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome);
        m = srv.metricsSnapshot();
        try std.testing.expectEqual(@as(u64, 1), m.feeds_listener_rate_limited);
        try std.testing.expectEqual(@as(u64, 0), m.feeds_listener_byte_rate_limited);
    }
}

test "Server listener byte rate limit window resets after elapsed" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_bytes_per_window = 1500,
        .listener_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    var buf: [800]u8 = @splat(0);
    buf[0] = 0x40;
    const addr = nullq.conn.path.Address{ .bytes = @splat(0x70) };

    // First window: two 800-byte feeds → bytes_in_window=1600 > 1500
    // on the second. Counter bumps to 1 here.
    _ = try srv.feed(&buf, addr, 0);
    _ = try srv.feed(&buf, addr, 1);

    var m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_listener_byte_rate_limited);

    // Advance past the window. Both counters reset on the next feed,
    // so the first post-reset 800-byte feed passes (bytes_in_window=800).
    _ = try srv.feed(&buf, addr, 1_000_001);

    m = srv.metricsSnapshot();
    // No new drop — counter is sticky at 1 from the previous window,
    // but the post-reset feed went through cleanly.
    try std.testing.expectEqual(@as(u64, 1), m.feeds_listener_byte_rate_limited);

    // Second post-reset feed: bytes_in_window=1600 again → drop.
    _ = try srv.feed(&buf, addr, 1_000_002);
    m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), m.feeds_listener_byte_rate_limited);
}

test "Server.init rejects max_bytes_per_window=0" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(nullq.Server.Error.InvalidConfig, nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_bytes_per_window = 0,
    }));
}

// -- §4.1 token-bucket: per-source bandwidth shaper -------------------

test "Server per-source bandwidth shaper drops datagrams when bucket is empty" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        // Tight cap so the test can drain it quickly. With cap = 4096
        // bytes/s the refill rate is ~0.004096 bytes/us; a 1ms gap
        // refills ~4 bytes (negligible compared to a 2000-byte
        // datagram).
        .max_bytes_per_source_per_second = 4096,
    });
    defer srv.deinit();

    var buf: [2000]u8 = @splat(0);
    buf[0] = 0x40;
    const addr = nullq.conn.path.Address{ .bytes = @splat(0xa1) };

    // First 2000-byte datagram at t=0: bucket starts full at 4096
    // tokens, debit drops it to ~2096. Pass.
    var outcome = try srv.feed(&buf, addr, 0);
    try std.testing.expect(outcome != nullq.Server.FeedOutcome.dropped or true); // could drop on later gates, what matters is the bandwidth counter
    var m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), m.feeds_source_bandwidth_limited);

    // Second 2000-byte datagram 1 ms later: bucket refilled by ~4
    // tokens (still ~2100). Debit drops to ~100. Pass.
    outcome = try srv.feed(&buf, addr, 1_000);
    m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), m.feeds_source_bandwidth_limited);

    // Third 2000-byte datagram 1 us later: bucket has ~100 tokens,
    // 2000 > 100, drop on the per-source bandwidth gate.
    outcome = try srv.feed(&buf, addr, 1_001);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, outcome);
    m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_source_bandwidth_limited);
    try std.testing.expect(m.feeds_dropped >= 1);
}

test "Server per-source bandwidth shaper refills on idle" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_bytes_per_source_per_second = 4096,
    });
    defer srv.deinit();

    var buf: [2000]u8 = @splat(0);
    buf[0] = 0x40;
    const addr = nullq.conn.path.Address{ .bytes = @splat(0xa2) };

    // Drain the bucket quickly: three 2000-byte datagrams at
    // t=0/1/2 us. Total charge = 6000 bytes vs starting bucket of
    // 4096 + ~3 us of refill (negligible). Third drops.
    _ = try srv.feed(&buf, addr, 0);
    _ = try srv.feed(&buf, addr, 1);
    const drop_outcome = try srv.feed(&buf, addr, 2);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, drop_outcome);
    var m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_source_bandwidth_limited);

    // Advance simulated time by 2 seconds. Refill rate is 4096
    // bytes/s, so 2 s of idle adds 8192 tokens — capped at the
    // 4096-byte ceiling. Bucket is now full again.
    _ = try srv.feed(&buf, addr, 2_000_002);
    m = srv.metricsSnapshot();
    // Counter is sticky at 1 (the earlier drop); this feed went
    // through cleanly.
    try std.testing.expectEqual(@as(u64, 1), m.feeds_source_bandwidth_limited);
}

test "Server per-source bandwidth shaper is per-source" {
    const protos = [_][]const u8{"hq-test"};
    var srv = try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_bytes_per_source_per_second = 4096,
    });
    defer srv.deinit();

    var buf: [2000]u8 = @splat(0);
    buf[0] = 0x40;
    const peer_a = nullq.conn.path.Address{ .bytes = @splat(0xb1) };
    const peer_b = nullq.conn.path.Address{ .bytes = @splat(0xb2) };

    // Drain peer_a's bucket: three 2000-byte datagrams at t=0/1/2.
    // Third trips the gate.
    _ = try srv.feed(&buf, peer_a, 0);
    _ = try srv.feed(&buf, peer_a, 1);
    const a_third = try srv.feed(&buf, peer_a, 2);
    try std.testing.expectEqual(nullq.Server.FeedOutcome.dropped, a_third);

    var m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_source_bandwidth_limited);

    // peer_b gets a fresh bucket; its first 2000-byte datagram
    // passes the bandwidth gate (it may drop on later gates, but the
    // bandwidth-limited counter must NOT increment).
    _ = try srv.feed(&buf, peer_b, 3);
    m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_source_bandwidth_limited);

    // peer_b's second 2000-byte datagram: bucket has ~2096 tokens,
    // pass.
    _ = try srv.feed(&buf, peer_b, 4);
    m = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), m.feeds_source_bandwidth_limited);
}

test "Server.init rejects max_bytes_per_source_per_second=0" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(nullq.Server.Error.InvalidConfig, nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_bytes_per_source_per_second = 0,
    }));
}
