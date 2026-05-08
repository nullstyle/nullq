//! Hardening guide §4.4 / §11.2 regression: Version Negotiation flood
//! under spoofed-source mix.
//!
//! The hardening guide §4.4 calls for two separate VN protections:
//!
//!   1. Per-source VN rate limiter (`max_vn_per_source_per_window`).
//!      A single attacker address that sprays non-v1 long-header
//!      probes is throttled to the configured cap per window.
//!      Already pinned by `tests/e2e/server_smoke.zig` → "Server VN
//!      per-source rate limiter caps VN responses".
//!
//!   2. Bounded global stateless-response queue
//!      (`stateless_response_queue_capacity = 64`). Even when the
//!      attacker bypasses the per-source limiter by spoofing many
//!      distinct source addresses, the *total* outbound VN bytes are
//!      capped: the queue holds at most 64 entries; on overflow, the
//!      VN-eviction policy drops the oldest VN to keep Retry traffic
//!      to legitimate v1 peers flowing. (`feeds_dropped` /
//!      `stateless_responses_evicted` counters track the gating.)
//!
//! This file pins the second invariant — the part attackers actually
//! exploit when they spread the flood across spoofed source addresses
//! to defeat the per-source limiter. The cap is global, so no level
//! of source diversity bypasses it.
//!
//! What the test asserts:
//!
//!   - 200 distinct fake source addresses each send one VN-eligible
//!     probe (long-header packet with version != 0x00000001). Per
//!     source the recent_count stays at 1 — well under any reasonable
//!     `max_vn_per_source_per_window`. So the per-source limiter is
//!     NOT the gate that fires.
//!   - The per-source rate table tracks each address independently
//!     (`source_rate_table_size` reflects the number of distinct
//!     sources we fed, capped by `source_rate_table_capacity`).
//!   - The global stateless-response queue caps total outbound VN
//!     bytes at `stateless_response_queue_capacity * <max VN packet
//!     size>` — verified by checking
//!     `metrics.stateless_responses_evicted` once we exceed 64
//!     queued entries, and that `statelessResponseCount()` never
//!     exceeds 64.
//!
//! The combined effect is the §4.4 "VN responses are capped" defense:
//! per-source AND global. A spoofed-source flood cannot amplify the
//! server's outbound bytes beyond the global queue capacity, no matter
//! how many distinct addresses the attacker rotates through.

const std = @import("std");
const quic_zig = @import("quic_zig");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;
const defaultParams = common.defaultParams;

/// Build an 18-byte non-v1 long-header packet shaped exactly like the
/// fixture in `tests/e2e/server_smoke.zig`'s VN tests. Version
/// 0xdeadbeef triggers the §6 VN path; the DCID/SCID lengths are
/// minimal-but-valid. RFC 9000 §14's 1200-byte minimum does NOT apply
/// to non-v1 long-header packets — the §6 VN path is governed
/// independently of §14, so the fixture stays small. `Server.feed`
/// takes `[]u8` (mutable), so this returns the bytes by value and
/// callers stash them in a local `var` to obtain a mutable slice.
fn buildVnProbe() [18]u8 {
    return .{
        0xc0, // long-header bit set, type=Initial-shape (irrelevant for VN)
        0xde, 0xad, 0xbe, 0xef, // unsupported version → triggers VN
        0x04, 0xa0, 0xa1, 0xa2, 0xa3, // 4-byte DCID
        0x04, 0xb0, 0xb1, 0xb2, 0xb3, // 4-byte SCID
        0x00, 0x00, 0x00, // padding
    };
}

test "VN-flood across spoofed sources: per-source table tracks each address independently AND global queue caps total VN bytes (§4.4 / §11.2)" {
    // Configure the server with:
    //   - per-source VN cap = 8 (the default), and a 1-second window;
    //   - per-source table capacity 4096 (default) so all 200 fake
    //     sources fit.
    // Each fake source sends ONE probe — well under the per-source
    // cap of 8 — so the per-source limiter never fires for any
    // individual address. The defense that DOES fire is the global
    // 64-entry stateless-response queue, which evicts oldest VN
    // entries on overflow.
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        // Defaults are fine; spell out the relevant knobs for clarity.
        .max_vn_per_source_per_window = 8,
        .source_rate_window_us = 1_000_000,
        .source_rate_table_capacity = 4096,
    });
    defer srv.deinit();

    var probe = buildVnProbe();

    // 200 distinct spoofed source addresses, each sending a single
    // VN-eligible probe. 200 > 64 = queue capacity, so the global
    // cap MUST start evicting after the first 64 distinct sources.
    const source_count: usize = 200;
    var source_idx: usize = 0;
    while (source_idx < source_count) : (source_idx += 1) {
        // Address bytes: top byte rotates 0x00..0xFF, lower bytes
        // give a stable pattern so each address is distinct without
        // colliding under the underlying `Address.eql` rule (which
        // compares the full 22-byte buffer).
        var addr_bytes: [22]u8 = @splat(0);
        addr_bytes[0] = @intCast(source_idx & 0xff);
        addr_bytes[1] = @intCast((source_idx >> 8) & 0xff);
        addr_bytes[2] = 0x42;
        const addr: quic_zig.conn.path.Address = .{ .bytes = addr_bytes };
        // `now_us` ticks forward by 1 µs per probe. Far below the
        // 1-second window, so all 200 probes land in the same window
        // (and the per-source counter rolls forward without resetting).
        const outcome = try srv.feed(&probe, addr, @intCast(source_idx));

        // For the first 64 probes, outcome must be `.version_negotiated`
        // (queue has room, VN response gets queued).
        // After 64, the global queue has hit capacity and on each
        // overflow `queueStatelessResponse` evicts the oldest VN
        // entry. The outcome is still `.version_negotiated` from the
        // feed's perspective — the eviction is queue-internal, not
        // per-feed. (The eviction counter ticks instead.)
        try std.testing.expectEqual(
            quic_zig.Server.FeedOutcome.version_negotiated,
            outcome,
        );
    }

    // Per-source table: must hold 200 distinct entries (one per
    // unique source address). This is the property that breaks the
    // first part of the threat: each spoofed source has its own
    // bookkeeping; one source's count cannot pollute another's.
    const m = srv.metricsSnapshot();
    try std.testing.expectEqual(
        @as(u64, source_count),
        m.source_rate_table_size,
    );

    // Global queue cap held: the queue is at most 64 entries. The
    // queue depth right now is exactly 64 (every overflow evicted
    // one VN to make room for the next).
    try std.testing.expectEqual(
        @as(u64, 64),
        m.stateless_queue_depth,
    );
    try std.testing.expectEqual(@as(usize, 64), srv.statelessResponseCount());

    // Eviction counter: 200 probes − 64 queue-capacity = 136
    // evictions. This is the load-bearing assertion: a flood from
    // 200 spoofed addresses cannot blow up the queue past 64 entries
    // — every overflow drops an existing VN before queueing the new
    // one. Total outbound VN bytes are bounded by `64 * <max VN
    // packet size>`, regardless of source diversity.
    try std.testing.expectEqual(
        @as(u64, source_count - 64),
        m.stateless_responses_evicted,
    );

    // Per-source counters: every address has recent_count = 1 (one
    // probe each). The rate-limit snapshot's `top_offenders` ranks by
    // recent_count, but with everyone tied at 1 the ranking is
    // arbitrary — what we verify is that no single source breached
    // the per-source cap of 8.
    const snap = srv.rateLimitSnapshot();
    try std.testing.expectEqual(@as(usize, source_count), snap.table_size);
    for (snap.top_offenders[0..snap.top_offender_count]) |row| {
        // No single source crossed the per-source cap (=8). Each
        // source's recent_count is the Initial-driven count, which
        // stays 0 here because the probes are VN-only — a peer that
        // mixes VN and Initial probes from the same source would
        // accrete on both counters independently. The VN counter is
        // bookkept on the SourceRateEntry.vn_count field and is not
        // surfaced via `rateLimitSnapshot` (that snapshot is the
        // Initial-side view). Either way: every recent_count is well
        // under the per-source cap of 8 — the global queue is doing
        // the gating, not the per-source limiter.
        try std.testing.expect(row.recent_count <= 8);
    }

    // The total cumulative `feeds_version_negotiated` matches the
    // number of probes — every feed was classified as VN-eligible.
    try std.testing.expectEqual(
        @as(u64, source_count),
        m.feeds_version_negotiated,
    );

    // No probe was classified as `dropped` or `rate_limited`: the
    // per-source limiter never fired (each source had only 1 probe;
    // cap is 8), and the global queue overflow evicts INSIDE the VN
    // response path — it is not a `.dropped` outcome on the feed.
    try std.testing.expectEqual(@as(u64, 0), m.feeds_vn_rate_limited);
    try std.testing.expectEqual(@as(u64, 0), m.feeds_rate_limited);

    // -- Drain everything; verify no observable corruption. --
    var drained_count: usize = 0;
    while (srv.drainStatelessResponse()) |resp| {
        drained_count += 1;
        // Each entry carries a valid VN response shape (RFC 8999 §6):
        // first byte has the long-header bit set; the four version
        // bytes are zero (the VN sentinel).
        const bytes = resp.slice();
        try std.testing.expect(bytes.len >= 7);
        try std.testing.expect((bytes[0] & 0x80) != 0);
        try std.testing.expectEqual(
            @as(u32, 0),
            std.mem.readInt(u32, bytes[1..5], .big),
        );
        // The default-constructed `kind` is `.version_negotiation`;
        // every entry queued in this test came from a VN-eligible
        // probe, so they must all match.
        try std.testing.expect(resp.kind == .version_negotiation);
    }
    try std.testing.expectEqual(@as(usize, 64), drained_count);
}

test "VN-flood: 65th distinct source triggers the first global eviction (§4.4 / §11.2)" {
    // Boundary test: the first 64 distinct VN probes fit; the 65th
    // is the one that triggers the global eviction. Useful to make
    // sure the boundary at `stateless_response_queue_capacity` is
    // exact, not off by one. Companion to the bulk test above.
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .max_vn_per_source_per_window = 8,
        .source_rate_window_us = 1_000_000,
    });
    defer srv.deinit();

    var probe = buildVnProbe();

    // Probe from 64 distinct sources. Queue grows by 1 each time.
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var addr_bytes: [22]u8 = @splat(0);
        addr_bytes[0] = @intCast(i & 0xff);
        addr_bytes[1] = @intCast((i >> 8) & 0xff);
        addr_bytes[2] = 0x77;
        const addr: quic_zig.conn.path.Address = .{ .bytes = addr_bytes };
        try std.testing.expectEqual(
            quic_zig.Server.FeedOutcome.version_negotiated,
            try srv.feed(&probe, addr, @intCast(i)),
        );
    }

    // Right before the boundary: 64 entries queued, zero evictions.
    {
        const m = srv.metricsSnapshot();
        try std.testing.expectEqual(@as(u64, 64), m.stateless_queue_depth);
        try std.testing.expectEqual(@as(u64, 0), m.stateless_responses_evicted);
        try std.testing.expectEqual(@as(u64, 64), m.source_rate_table_size);
    }

    // 65th probe from a distinct address. Queue stays at 64 (one
    // VN evicted to make room). Eviction counter goes to 1.
    var addr_bytes_65: [22]u8 = @splat(0);
    addr_bytes_65[0] = 0x65;
    addr_bytes_65[1] = 0x65;
    addr_bytes_65[2] = 0x77;
    const addr_65: quic_zig.conn.path.Address = .{ .bytes = addr_bytes_65 };
    var probe_65 = buildVnProbe();
    try std.testing.expectEqual(
        quic_zig.Server.FeedOutcome.version_negotiated,
        try srv.feed(&probe_65, addr_65, 64),
    );

    {
        const m = srv.metricsSnapshot();
        try std.testing.expectEqual(@as(u64, 64), m.stateless_queue_depth);
        try std.testing.expectEqual(@as(u64, 1), m.stateless_responses_evicted);
        try std.testing.expectEqual(@as(u64, 65), m.source_rate_table_size);
        // High-water mark records the peak queue depth ever observed
        // — it's sticky at 64 (the queue never grew past that).
        try std.testing.expectEqual(@as(u64, 64), m.stateless_queue_high_water);
    }
}
