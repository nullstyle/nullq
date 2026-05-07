//! Shared "drive a real handshake to handshake-confirmed, then inject
//! caller-controlled 1-RTT frames" fixture.
//!
//! Most of the remaining `skip_` tests in the conformance suite need
//! to hit receiver-side gates that fire only at .application
//! encryption level — frames that are forbidden mid-handshake but
//! legal once handshake confirms, FLOW_CONTROL_ERROR / STREAM_LIMIT_ERROR
//! gates that depend on negotiated transport-parameter values, etc.
//! The shared shape is: stand up a paired Server + Client, pump the
//! TLS handshake to completion through `Server.feed`, then seal a
//! caller-encoded frame with the live application keys and feed it
//! back into the receiver's `Connection.handle` (client side) or
//! `Server.feed` (server side). Inspect the resulting close event.
//!
//! This file ONLY exposes the fixture surface used by those tests
//! plus a handful of fixture-internal sanity tests; it doesn't add
//! RFC-traceable tests of its own — those live in the per-RFC suites.
//! The leading underscore in the filename keeps it lexically distinct
//! from the per-RFC suite files so it doesn't get confused for one.
//!
//! The package boundary is `tests/`, so `@embedFile("../data/...")`
//! resolves to `tests/data/` cleanly.
//!
//! IMPORTANT lifecycle: `HandshakePair` holds self-referential
//! pointers between its `server`/`client` and the per-connection
//! state. Callers MUST NOT copy the value after `init` — use
//! `var pair = try HandshakePair.init(...); defer pair.deinit();`
//! and pass `&pair` around.

const std = @import("std");
const nullq = @import("nullq");
const wire = nullq.wire;
const short_packet = wire.short_packet;
const long_packet = wire.long_packet;
const conn_state = nullq.conn.state;

/// Test cert/key — same fixture used by tests/e2e/. Embedded here so
/// the fixture can stand up a real Server alongside a real Client.
pub const test_cert_pem = @embedFile("../data/test_cert.pem");
pub const test_key_pem = @embedFile("../data/test_key.pem");

/// PROTOCOL_VIOLATION wire value (RFC 9000 §20.1). Asserted directly
/// against close events so a conformance test ties the observed error
/// code to the spec table, not to a private nullq constant.
pub const TRANSPORT_ERROR_PROTOCOL_VIOLATION: u64 = 0x0a;
/// FRAME_ENCODING_ERROR wire value (RFC 9000 §20.1).
pub const TRANSPORT_ERROR_FRAME_ENCODING_ERROR: u64 = 0x07;
/// FLOW_CONTROL_ERROR wire value (RFC 9000 §20.1).
pub const TRANSPORT_ERROR_FLOW_CONTROL_ERROR: u64 = 0x03;
/// STREAM_LIMIT_ERROR wire value (RFC 9000 §20.1).
pub const TRANSPORT_ERROR_STREAM_LIMIT_ERROR: u64 = 0x04;

/// Default transport parameters used by every handshake-fixture test.
/// Mirrors `tests/e2e/common.defaultParams()` so the shape stays in
/// lockstep with the e2e harness.
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

/// ALPN advertised by both sides.
const default_alpn: []const []const u8 = &.{"hq-test"};

/// Paired Client + Server harness driven through a real TLS
/// handshake to the handshake-confirmed state. Owns the server, the
/// client, a fixed peer Address, a monotonic clock, and a 4 KiB rx
/// scratch buffer used to pump packets between sides.
///
/// SELF-REFERENTIAL: `server` and `client` hold internal pointers
/// into themselves. Callers MUST treat the returned value as a fixed
/// location — no copying, no returning by value — and pair every
/// `init` with a `defer pair.deinit()`.
pub const HandshakePair = struct {
    server: nullq.Server,
    client: nullq.Client,
    peer_addr: nullq.conn.path.Address,
    now_us: u64,
    rx_buf: [4096]u8,

    /// Initialize a fresh paired Server + Client. The Server is built
    /// with `test_cert_pem` / `test_key_pem` and ALPN "hq-test"; the
    /// Client connects to "localhost" with the same ALPN. Both sides
    /// use `defaultParams()`.
    ///
    /// Caller owns the returned value. Pair it with `defer pair.deinit()`
    /// and never copy it — see the type docstring on lifecycle.
    pub fn init(allocator: std.mem.Allocator) !HandshakePair {
        return initWith(allocator, defaultParams(), defaultParams());
    }

    /// Initialize a fresh paired Server + Client with caller-supplied
    /// transport-parameter overrides. Used by §10.1 (asymmetric
    /// idle_timeout — verifies the effective value is min(local,peer))
    /// and the flow-control / stream-limit tests that need a smaller
    /// initial_max_data / initial_max_streams_bidi than the defaults
    /// to keep adversarial-frame fixtures small.
    pub fn initWith(
        allocator: std.mem.Allocator,
        server_params: nullq.tls.TransportParams,
        client_params: nullq.tls.TransportParams,
    ) !HandshakePair {
        var server = try nullq.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = test_cert_pem,
            .tls_key_pem = test_key_pem,
            .alpn_protocols = default_alpn,
            .transport_params = server_params,
        });
        errdefer server.deinit();

        var client = try nullq.Client.connect(.{
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = default_alpn,
            .transport_params = client_params,
        });
        errdefer client.deinit();

        return .{
            .server = server,
            .client = client,
            .peer_addr = .{ .bytes = @splat(0xab) },
            .now_us = 0,
            .rx_buf = undefined,
        };
    }

    pub fn deinit(self: *HandshakePair) void {
        self.client.deinit();
        self.server.deinit();
        self.* = undefined;
    }

    /// Pump packets back and forth until both sides report
    /// `handshakeDone()`. Mirrors the loop in
    /// `tests/e2e/server_client_handshake.zig`.
    /// Updates `self.now_us` as it advances and errors with
    /// `error.HandshakeStalled` if the cap is reached without
    /// completion.
    pub fn driveToHandshakeConfirmed(self: *HandshakePair) !void {
        // Kick the client so the very first Initial is in its outbox.
        // `Client.connect` deliberately leaves this to the embedder so
        // 0-RTT-bound STREAM data could be installed first.
        try self.client.conn.advance();

        const max_steps: u32 = 32;
        var iter: u32 = 0;
        while (iter < max_steps) : (iter += 1) {
            const now_us: u64 = @as(u64, iter) * 1_000;
            self.now_us = now_us;

            // Client → Server: drain every outbound Client packet.
            while (try self.client.conn.poll(&self.rx_buf, now_us)) |len| {
                _ = try self.server.feed(self.rx_buf[0..len], self.peer_addr, now_us);
            }

            // Drain stateless responses (VN/Retry) — empty on a vanilla
            // v1 handshake but the loop must be robust.
            while (self.server.drainStatelessResponse()) |_| {}

            // Server → Client: drain every slot's outbound packets.
            for (self.server.iterator()) |slot| {
                while (try slot.conn.poll(&self.rx_buf, now_us)) |len| {
                    try self.client.conn.handle(self.rx_buf[0..len], null, now_us);
                }
            }

            try self.server.tick(now_us);
            try self.client.conn.tick(now_us);

            if (self.client.conn.handshakeDone() and self.server.iterator().len > 0) {
                if (self.server.iterator()[0].conn.handshakeDone()) return;
            }
        }
        return error.HandshakeStalled;
    }

    /// Server-side connection corresponding to the client. Asserts
    /// the slot exists; errors with `error.NoServerSlot` otherwise.
    /// Callers should only invoke this after
    /// `driveToHandshakeConfirmed`.
    pub fn serverConn(self: *HandshakePair) !*nullq.conn.Connection {
        const slots = self.server.iterator();
        if (slots.len == 0) return error.NoServerSlot;
        return slots[0].conn;
    }

    /// Client-side connection. Always present — mostly a convenience
    /// to keep call sites symmetrical with `serverConn`. Note that
    /// `Client.conn` is itself a `*Connection`, so we just hand the
    /// pointer through.
    pub fn clientConn(self: *HandshakePair) *nullq.conn.Connection {
        return self.client.conn;
    }

    /// Build a 1-RTT packet on the CLIENT side carrying `frame_bytes`
    /// (caller-encoded), seal it with the live application write
    /// keys, and feed it into the Server. After feed, `step` once so
    /// any close pathway surfaces. Returns the server-side close
    /// event snapshot, or null if the server did not close.
    ///
    /// `frame_bytes` is the raw QUIC frame payload — encode via
    /// `nullq.frame.encode` (or hand-written bytes) before calling.
    pub fn injectFrameAtServer(
        self: *HandshakePair,
        frame_bytes: []const u8,
    ) !?nullq.CloseEvent {
        const cli_conn = self.clientConn();
        const keys = (try cli_conn.packetKeys(.application, .write)) orelse
            return error.NoApplicationWriteKeys;
        const dcid = cli_conn.peer_dcid.slice();
        // Allocate the PN from the client's own application PN
        // space so the server's reciprocal ACK doesn't trip the
        // §13.1 "ACK of unsent packet" gate on the client when it
        // arrives. The helper bumps `next_pn` for us.
        const pn = cli_conn.allocApplicationPacketNumberForTesting() orelse
            return error.PnSpaceExhausted;

        // Seal into a fresh local buffer (Server.feed wants a mutable
        // slice — it strips header protection in place during routing
        // / decryption attempts).
        var pkt: [2048]u8 = undefined;
        const n = try short_packet.seal1Rtt(&pkt, .{
            .dcid = dcid,
            .pn = pn,
            .payload = frame_bytes,
            .keys = &keys,
            .key_phase = false,
        });

        self.now_us +%= 1_000;
        _ = try self.server.feed(pkt[0..n], self.peer_addr, self.now_us);
        try self.step();

        const srv_conn = try self.serverConn();
        return srv_conn.closeEvent();
    }

    /// Variant of `injectFrameAtServer` that lets the caller force the
    /// short-header Reserved Bits (bits 4-3 of the unprotected first
    /// byte) to a specific value. Production callers must always pass
    /// 0 — RFC 9000 §17.3 ¶3 mandates that. This entry point exists
    /// SOLELY so conformance tests can build a
    /// malicious-but-AEAD-authentic 1-RTT packet to exercise the
    /// receiver-side reserved-bits gate in `Connection.handleShort`.
    pub fn injectFrameAtServerWithReservedBits(
        self: *HandshakePair,
        frame_bytes: []const u8,
        reserved_bits: u2,
    ) !?nullq.CloseEvent {
        const cli_conn = self.clientConn();
        const keys = (try cli_conn.packetKeys(.application, .write)) orelse
            return error.NoApplicationWriteKeys;
        const dcid = cli_conn.peer_dcid.slice();
        const pn = cli_conn.allocApplicationPacketNumberForTesting() orelse
            return error.PnSpaceExhausted;

        var pkt: [2048]u8 = undefined;
        const n = try short_packet.seal1Rtt(&pkt, .{
            .dcid = dcid,
            .pn = pn,
            .payload = frame_bytes,
            .keys = &keys,
            .key_phase = false,
            .reserved_bits = reserved_bits,
        });

        self.now_us +%= 1_000;
        _ = try self.server.feed(pkt[0..n], self.peer_addr, self.now_us);
        try self.step();

        const srv_conn = try self.serverConn();
        return srv_conn.closeEvent();
    }

    /// Mirror of `injectFrameAtServer` in the other direction. The
    /// SERVER seals (using the server-side application write keys)
    /// and the CLIENT receives via `Connection.handle`. Returns the
    /// client-side close event snapshot, or null if the client did
    /// not close.
    pub fn injectFrameAtClient(
        self: *HandshakePair,
        frame_bytes: []const u8,
    ) !?nullq.CloseEvent {
        const srv_conn = try self.serverConn();
        const keys = (try srv_conn.packetKeys(.application, .write)) orelse
            return error.NoApplicationWriteKeys;
        const dcid = srv_conn.peer_dcid.slice();
        // Allocate from the server's app PN space — see the symmetric
        // explanation in `injectFrameAtServer`.
        const pn = srv_conn.allocApplicationPacketNumberForTesting() orelse
            return error.PnSpaceExhausted;

        var pkt: [2048]u8 = undefined;
        const n = try short_packet.seal1Rtt(&pkt, .{
            .dcid = dcid,
            .pn = pn,
            .payload = frame_bytes,
            .keys = &keys,
            .key_phase = false,
        });

        self.now_us +%= 1_000;
        try self.client.conn.handle(pkt[0..n], null, self.now_us);
        try self.step();

        return self.clientConn().closeEvent();
    }

    /// Inject a 0-RTT-protected (long-header type=0x01) packet at the
    /// SERVER carrying `frame_bytes`. Used by the §12.4 conformance
    /// test that pins `frameAllowedInEarlyData` — the receiver-side
    /// gate in `Connection.dispatchFrames` that closes with
    /// PROTOCOL_VIOLATION when the peer sends ACK / NEW_TOKEN /
    /// HANDSHAKE_DONE in a 0-RTT packet.
    ///
    /// The high-level `nullq.Server` does NOT auto-wire
    /// `setEarlyDataContext` on freshly-accepted slots, so a real
    /// resumption flow at the public API would land BoringSSL on
    /// `earlyDataStatus() == .rejected` and the server would silently
    /// drop the 0-RTT packet at `keys_unavailable` BEFORE
    /// `dispatchFrames` runs. To reach the gate we want, this helper
    /// instead drives a normal handshake to completion, then forcibly
    /// installs a deterministic shared early-data secret on both the
    /// client (write side) and the server's slot (read side). A
    /// post-handshake server connection has `earlyDataStatus() ==
    /// .not_offered` (BoringSSL never advertised early data because
    /// no resumption was attempted), which is NOT `.rejected`, so the
    /// `handleZeroRtt` keys-available branch runs the AEAD-decrypt
    /// against our installed material and `dispatchFrames(.early_data,
    /// ...)` gets the parsed payload — exactly the path that
    /// `frameAllowedInEarlyData` guards.
    ///
    /// The trick is sound because the gate under test is structural
    /// (it inspects the parsed Frame tag, not any TLS state). The
    /// in-source test
    /// `"server rejects forbidden frames in 0-RTT"` in
    /// `src/conn/state.zig` uses the same secret-injection technique
    /// against a bare `Connection` to assert the same gate.
    pub fn injectFrameAtServer0Rtt(
        self: *HandshakePair,
        frame_bytes: []const u8,
    ) !?nullq.CloseEvent {
        // 32 zero bytes paired with `cipher_protocol_id = 0x1301`
        // (TLS_AES_128_GCM_SHA256) deterministically derives identical
        // PacketKeys on both sides — the in-source helpers
        // `installTestEarlyDataReadSecret` / `testEarlyDataPacketKeys`
        // use the same recipe. We're not asserting AEAD strength here;
        // we just need the packet to authenticate so the receiver
        // dispatches its frames.
        var material: conn_state.SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
        material.secret_len = 32;
        // Direct field write into `Connection.levels` mirrors the
        // existing in-source test pattern. The field has no
        // production-API setter for early-data secrets because
        // BoringSSL's `set_read_secret` / `set_write_secret`
        // trampolines are the only legitimate writers in production.
        const early_idx = conn_state.EncryptionLevel.early_data.idx();
        const cli_conn = self.clientConn();
        cli_conn.levels[early_idx].write = material;
        const srv_conn_ptr = try self.serverConn();
        srv_conn_ptr.levels[early_idx].read = material;

        // Derive matching PacketKeys for sealing on the client side.
        // The server independently re-derives the same keys via
        // `Connection.packetKeys(.early_data, .read)` at decrypt time.
        const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, material.secret[0..32]);

        const dcid = cli_conn.peer_dcid.slice();
        // Synthesize a stable SCID — only the wire shape matters here
        // (the server already routes by DCID for the existing slot).
        const scid: [4]u8 = .{ 0x01, 0x02, 0x03, 0x04 };
        // 0-RTT shares the Application PN space (RFC 9000 §12.3), so
        // `allocApplicationPacketNumberForTesting` is the right
        // allocator here too — it bumps `next_pn` so the connection's
        // own subsequent send doesn't reuse this PN.
        const pn = cli_conn.allocApplicationPacketNumberForTesting() orelse
            return error.PnSpaceExhausted;

        var pkt: [2048]u8 = undefined;
        const n = try long_packet.sealZeroRtt(&pkt, .{
            .dcid = dcid,
            .scid = &scid,
            .pn = pn,
            .payload = frame_bytes,
            .keys = &keys,
        });

        self.now_us +%= 1_000;
        _ = try self.server.feed(pkt[0..n], self.peer_addr, self.now_us);
        try self.step();

        return srv_conn_ptr.closeEvent();
    }

    /// Drain stateless responses, tick both sides, and advance time
    /// monotonically. Useful between an injection and an assertion
    /// when the close pathway needs the next tick to surface (e.g. the
    /// CONNECTION_CLOSE frame is queued but not yet emitted).
    pub fn step(self: *HandshakePair) !void {
        self.now_us +%= 1_000;
        // Drain any stateless responses the server queued in response.
        while (self.server.drainStatelessResponse()) |_| {}
        // Pump in both directions so a queued CONNECTION_CLOSE on
        // either side actually reaches the wire and gets delivered.
        for (self.server.iterator()) |slot| {
            while (try slot.conn.poll(&self.rx_buf, self.now_us)) |len| {
                try self.client.conn.handle(self.rx_buf[0..len], null, self.now_us);
            }
        }
        while (try self.client.conn.poll(&self.rx_buf, self.now_us)) |len| {
            _ = try self.server.feed(self.rx_buf[0..len], self.peer_addr, self.now_us);
        }
        try self.server.tick(self.now_us);
        try self.client.conn.tick(self.now_us);
    }
};

// ---------- fixture-internal sanity tests --------------------------
//
// These are NOT RFC-traceable conformance tests. The "FIXTURE_SANITY"
// prefix marks them as regression coverage for the helper itself so
// auditors don't mistake them for spec assertions. They live in the
// conformance binary because that's where the fixture lives and
// these are the cheapest possible smoke tests of its API surface.

test "FIXTURE_SANITY HandshakePair: handshake completes" {
    var pair = try HandshakePair.init(std.testing.allocator);
    defer pair.deinit();

    try pair.driveToHandshakeConfirmed();

    try std.testing.expect(pair.clientConn().handshakeDone());
    const srv_conn = try pair.serverConn();
    try std.testing.expect(srv_conn.handshakeDone());
}

test "FIXTURE_SANITY HandshakePair: injectFrameAtServer round-trips a PING (no close)" {
    var pair = try HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // PING is type 0x01 with no body — legal at 1-RTT in either
    // direction. Inject and confirm the server stays open.
    const ping_frame = [_]u8{0x01};
    const close_event = try pair.injectFrameAtServer(&ping_frame);
    try std.testing.expectEqual(@as(?nullq.CloseEvent, null), close_event);

    // Belt-and-suspenders: the client should still be open too.
    try std.testing.expectEqual(@as(?nullq.CloseEvent, null), pair.clientConn().closeEvent());
}

test "FIXTURE_SANITY HandshakePair: client-emitted HANDSHAKE_DONE closes the server with PROTOCOL_VIOLATION" {
    // RFC 9000 §19.20: "A server MUST treat receipt of a
    // HANDSHAKE_DONE frame as a connection error of type
    // PROTOCOL_VIOLATION." Use this as the canonical proof that the
    // 1-RTT injection path reaches `Connection.dispatchFrames` and
    // the server-side close machinery actually fires.
    var pair = try HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const handshake_done = [_]u8{0x1e};
    const close_event = try pair.injectFrameAtServer(&handshake_done);

    const ev = close_event orelse return error.TestExpectedClose;
    try std.testing.expectEqual(nullq.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}
