//! Shared "send a malicious-but-authentic Initial to a Server" fixture.
//!
//! Several conformance suites need to verify receiver-side gates that
//! fire after AEAD passes — RFC 9000 §17.2.1 (long-header Reserved
//! Bits), §12.4 (forbidden frames at Initial), and RFC 9221 §4 ¶3
//! (DATAGRAM at Initial). All three share the same shape: stand up a
//! real Server, derive client-side Initial keys from a chosen DCID,
//! seal a packet with a controlled Reserved-Bits or payload field,
//! feed it through `Server.feed`, and inspect the resulting close
//! event.
//!
//! This file ONLY exposes the fixture surface used by those tests; it
//! does not contain test blocks of its own. The leading underscore in
//! the filename keeps it lexically distinct from the per-RFC suite
//! files so it doesn't get confused for one.
//!
//! The package boundary is `tests/` (the conformance test root lives
//! at `tests/conformance.zig`), so `@embedFile("../data/...")` resolves
//! to `tests/data/` cleanly.

const std = @import("std");
const nullq = @import("nullq");
const wire = nullq.wire;
const long_packet = wire.long_packet;
const initial = wire.initial;

/// PROTOCOL_VIOLATION wire value (RFC 9000 §20.1). Asserted directly
/// against close events so a conformance test ties the observed error
/// code to the spec table, not to a private nullq constant.
pub const TRANSPORT_ERROR_PROTOCOL_VIOLATION: u64 = 0x0a;

/// Test cert/key — same fixture used by tests/e2e/. Embedded here so
/// the §17.2.1 / §12.4 / RFC9221 §4 ¶3 receiver-side gates can run a
/// real Server through `Server.feed`.
pub const test_cert_pem = @embedFile("../data/test_cert.pem");
pub const test_key_pem = @embedFile("../data/test_key.pem");

/// Server transport parameters used by every server-fixture test.
/// Mirrors `tests/e2e/common.defaultParams()`.
pub fn defaultParams() nullq.tls.TransportParams {
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

/// Build an authenticated Initial packet with caller-controlled
/// Reserved Bits and frame payload, feed it to a fresh server, and
/// return the resulting `CloseEvent` (or null if the server didn't
/// close).
///
/// The packet is sealed with the canonical Initial keys derived from
/// the supplied DCID (RFC 9001 §5.2) — the receiver re-derives the
/// same keys, so AEAD passes and the post-HP first byte is authentic.
/// `pad_to` is forced to 1200 to clear the §14 size gate.
pub fn feedAndExpectClose(
    server: *nullq.Server,
    dcid: []const u8,
    scid: []const u8,
    reserved_bits: u2,
    payload: []const u8,
) !?nullq.CloseEvent {
    // Derive the client-side Initial AEAD keys from the DCID.
    const client_secret = try initial.deriveInitialKeys(dcid, false);
    const pkt_keys = try wire.short_packet.derivePacketKeys(.aes128_gcm_sha256, &client_secret.secret);

    // Seal an Initial whose post-HP first byte carries the requested
    // Reserved Bits, padded to RFC 9000 §14's 1200-byte floor so the
    // server doesn't drop on the size gate.
    var pkt: [1500]u8 = undefined;
    const n = try long_packet.sealInitial(&pkt, .{
        .dcid = dcid,
        .scid = scid,
        .pn = 0,
        .payload = payload,
        .keys = &pkt_keys,
        .pad_to = 1200,
        .reserved_bits = reserved_bits,
    });

    // Feed it. Use a stable address so the source-rate-limit gate
    // doesn't fire across consecutive tests in the same suite.
    const addr = nullq.conn.path.Address{ .bytes = @splat(0xfe) };
    _ = try server.feed(pkt[0..n], addr, 1_000);

    // The reserved-bits / forbidden-frame / DATAGRAM gates fire inside
    // `Connection.handleInitial` → `dispatchFrames`. The slot is
    // already created (because `Server.feed` allocates a slot before
    // calling `handle`), so `iterator()` returns it and we can read
    // the sticky close event.
    const slots = server.iterator();
    if (slots.len == 0) return null;
    return slots[0].conn.closeEvent();
}

/// Build an authenticated Initial packet (1200-byte padded, sealed
/// with the canonical Initial keys derived from `dcid`) and feed it
/// to `server`. Unlike `feedAndExpectClose`, this helper does not
/// assert anything about the post-feed connection state — used by
/// tests that want a healthy-but-unvalidated server slot to inspect
/// (e.g. the §8.1 anti-amp wire-cap test).
pub fn feedInitial(
    server: *nullq.Server,
    dcid: []const u8,
    scid: []const u8,
    payload: []const u8,
) !void {
    const client_secret = try initial.deriveInitialKeys(dcid, false);
    const pkt_keys = try wire.short_packet.derivePacketKeys(.aes128_gcm_sha256, &client_secret.secret);

    var pkt: [1500]u8 = undefined;
    const n = try long_packet.sealInitial(&pkt, .{
        .dcid = dcid,
        .scid = scid,
        .pn = 0,
        .payload = payload,
        .keys = &pkt_keys,
        .pad_to = 1200,
        .reserved_bits = 0,
    });

    const addr = nullq.conn.path.Address{ .bytes = @splat(0xfe) };
    _ = try server.feed(pkt[0..n], addr, 1_000);
}

/// Construct a fresh `Server` ready to receive Initials. The caller
/// owns the returned value and `defer srv.deinit()`s it.
pub fn buildServer() !nullq.Server {
    const protos = [_][]const u8{"hq-test"};
    return try nullq.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
}
