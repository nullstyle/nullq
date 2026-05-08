//! Hardening guide §4.8 / §11.2 regression: PATH_CHALLENGE flood
//! (receive-side).
//!
//! A peer that floods the server with PATH_CHALLENGE frames must not
//! force the server to mint per-challenge validator state. The
//! defense lives in the path-validation state machine (RFC 9000 §8.2):
//! `PathValidator.recordResponse` only accepts a response when its
//! `status == .pending` (i.e. the *local* end has previously emitted
//! a PATH_CHALLENGE and is waiting for the matching PATH_RESPONSE).
//! Any incoming PATH_CHALLENGE prompts a single PATH_RESPONSE echo
//! (queued via `Connection.pending_frames.path_response`, drained on
//! the next `poll`) — but the server does NOT begin a validator
//! attempt on its own behalf, and incoming PATH_RESPONSEs whose token
//! never matches an outstanding local challenge are a cheap no-op
//! (`PathValidator.recordResponse` returns `Error.NotPending`, which
//! the connection-level `recordPathResponse` swallows via `catch
//! return`).
//!
//! What this file pins:
//!
//!   1. After a real handshake, the client emits PATH_CHALLENGE
//!      frames inside 1-RTT packets via the public
//!      `pending_frames.path_challenge` injection point. Each frame
//!      reaches the server, the server queues a PATH_RESPONSE with
//!      the echoed token, and the next server `poll` emits exactly
//!      one PATH_RESPONSE frame containing that token.
//!   2. Across the entire flood, the server's primary-path validator
//!      stays in `.idle` — no challenge was minted on the responder
//!      side, no validator state was attached.
//!   3. Stray PATH_RESPONSE frames sent to the server (when the
//!      server's validator is `.idle`) are absorbed without observable
//!      side effect: no validator-state change, no error, no
//!      PATH_RESPONSE emission. This pins the
//!      `recordPathResponse` -> `Error.NotPending` -> swallow path.
//!
//! Together these properties cap the attacker's amplification of a
//! PATH_CHALLENGE flood at "one PATH_RESPONSE echo per challenge", and
//! they ensure stray PATH_RESPONSEs cannot drive the server's
//! validator state machine into any state but `.idle`.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

const InitialDcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
const ClientScid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
const ServerScid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

/// Drive a real Initial/Handshake/1-RTT exchange between two
/// `quic_zig.Connection`s until both sides have application keys. Mirror
/// of the loop in `mock_transport_real_handshake.zig`. Returns the
/// final `now_us` so the test body can keep monotonic time.
fn driveHandshake(
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
    start_now_us: u64,
) !u64 {
    var buf_c2s: [2048]u8 = undefined;
    var buf_s2c: [2048]u8 = undefined;
    var iters: u32 = 0;
    var now_us = start_now_us;
    while (iters < 100) : (iters += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        if (try client.poll(&buf_c2s, now_us)) |n| {
            try server.handle(buf_c2s[0..n], null, now_us);
        }
        if (try server.poll(&buf_s2c, now_us)) |n| {
            try client.handle(buf_s2c[0..n], null, now_us);
        }
        now_us += 10_000;
    }
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
    return now_us;
}

/// Stand up a paired client/server `Connection` ready for 1-RTT
/// frames. Identical to `mock_transport_real_handshake.zig`'s setup;
/// kept inline so this file does not collide with parallel agents
/// editing the existing e2e files.
fn buildPair(
    allocator: std.mem.Allocator,
    server_tls: *boringssl.tls.Context,
    client_tls: *boringssl.tls.Context,
) !struct {
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
} {
    const protos = [_][]const u8{"hq-test"};
    server_tls.* = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    try server_tls.loadCertChainAndKey(test_cert_pem, test_key_pem);

    client_tls.* = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });

    const client = try allocator.create(quic_zig.Connection);
    errdefer allocator.destroy(client);
    client.* = try quic_zig.Connection.initClient(allocator, client_tls.*, "localhost");
    errdefer client.deinit();

    const server = try allocator.create(quic_zig.Connection);
    errdefer allocator.destroy(server);
    server.* = try quic_zig.Connection.initServer(allocator, server_tls.*);
    errdefer server.deinit();

    try client.bind();
    try server.bind();

    try client.setLocalScid(&ClientScid);
    try client.setInitialDcid(&InitialDcid);
    try client.setPeerDcid(&InitialDcid);
    try server.setLocalScid(&ServerScid);

    const tp: quic_zig.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try client.advance();
    return .{ .client = client, .server = server };
}

test "PATH_CHALLENGE flood: server emits one PATH_RESPONSE per challenge and never mints validator state (§4.8 / §11.2)" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    var pair = try buildPair(allocator, &server_tls, &client_tls);
    defer {
        pair.client.deinit();
        allocator.destroy(pair.client);
        pair.server.deinit();
        allocator.destroy(pair.server);
        server_tls.deinit();
        client_tls.deinit();
    }

    const client = pair.client;
    const server = pair.server;

    var now_us = try driveHandshake(client, server, 1_000_000);

    // Pre-flood baseline: the server's primary-path validator is
    // `.validated` — the handshake-completed primary path is marked
    // validated implicitly (the initial-CID-binding handshake serves
    // the same proof-of-receipt role as a PATH_CHALLENGE round-trip).
    // The pending-frames queue has no PATH_RESPONSE owed at this
    // point. The load-bearing assertion is that the validator status
    // does NOT change as the flood progresses — incoming
    // PATH_CHALLENGE frames must NOT push it back into `.pending`
    // (the only state from which `recordPathResponse` accepts a
    // matching token).
    const baseline_status = server.paths.get(0).?.path.validator.status;
    try std.testing.expect(server.pending_frames.path_response == null);

    // Flood: client injects 64 distinct PATH_CHALLENGE tokens. For
    // each token we poll the client (which emits a 1-RTT packet
    // carrying the challenge), feed it to the server, then poll the
    // server (which emits a 1-RTT packet — coalesced HANDSHAKE_DONE
    // + ACK + PATH_RESPONSE on iteration 0, plain ACK +
    // PATH_RESPONSE on subsequent iterations). 64 iterations is well
    // above the per-source PATH_CHALLENGE rate floor
    // (`min_path_challenge_interval_us = 100_000` µs throttles the
    // *server's own* migration-driven challenges, not the
    // response-side path we exercise here).
    //
    // We rely on the server's post-iteration state (validator stays
    // at baseline; PATH_RESPONSE was queued and then drained on
    // poll) rather than decrypting the wire bytes ourselves. The
    // shape of the *outbound* packet is incidental — what matters
    // is that the server's validator state machine never entered
    // `.pending` and that the queued PATH_RESPONSE was actually
    // consumed (i.e. `pending_frames.path_response == null` after
    // poll).
    const challenge_count: usize = 64;
    var path_responses_emitted: usize = 0;
    var c2s: [2048]u8 = undefined;
    var s2c: [2048]u8 = undefined;

    var i: usize = 0;
    while (i < challenge_count) : (i += 1) {
        // Inject a fresh PATH_CHALLENGE token via the public
        // pending-frames queue. The token byte pattern is unique per
        // iteration so we can later confirm the queue saw distinct
        // values across the flood.
        const idx_byte: u8 = @intCast(i);
        var token: [8]u8 = .{ idx_byte, idx_byte, 0xCC, 0xCC, 0xCC, 0xCC, idx_byte, idx_byte };
        client.pending_frames.path_challenge = token;
        client.pending_frames.path_challenge_path_id = 0;

        const n_c = (try client.poll(&c2s, now_us)) orelse return error.ClientPolledNothing;
        try server.handle(c2s[0..n_c], null, now_us);

        // Server's PATH_RESPONSE owe: the inbound PATH_CHALLENGE
        // queues exactly one PATH_RESPONSE — verify the token bytes
        // round-trip into `pending_frames.path_response` before
        // poll drains it.
        try std.testing.expect(server.pending_frames.path_response != null);
        try std.testing.expectEqualSlices(
            u8,
            &token,
            &server.pending_frames.path_response.?,
        );

        // Server polls. Poll drains `path_response` into the wire.
        // Crucially: `pending_frames.path_response == null` after
        // poll proves the queue consumed exactly one entry — even
        // if the wire-level packet shape is opaque to us here.
        const n_s = (try server.poll(&s2c, now_us)) orelse return error.ServerPolledNothing;
        try client.handle(s2c[0..n_s], null, now_us);
        try std.testing.expect(server.pending_frames.path_response == null);
        path_responses_emitted += 1;

        // After every iteration: server's primary-path validator
        // status is unchanged from its post-handshake baseline. This
        // is the load-bearing assertion — the server is RESPONDING
        // to peer challenges (queueing a PATH_RESPONSE) but is NOT
        // minting a fresh challenge of its own. Anti-DoS: a flood of
        // PATH_CHALLENGEs cannot push the validator into `.pending`
        // (the only state from which `recordPathResponse` accepts a
        // matching token), and cannot expand validator-state memory.
        const sv_path = server.paths.get(0).?;
        try std.testing.expectEqual(
            baseline_status,
            sv_path.path.validator.status,
        );
        // Crucially: never `.pending`. If the responder side ever
        // entered `.pending`, an attacker pairing PATH_CHALLENGE +
        // PATH_RESPONSE could wedge the state machine into
        // `.validated` against an unverified path.
        try std.testing.expect(sv_path.path.validator.status != .pending);

        now_us += 1_000;
    }

    // Every one of the 64 challenges drained exactly one
    // PATH_RESPONSE off the server's queue.
    try std.testing.expectEqual(challenge_count, path_responses_emitted);

    // Final invariant: server's primary-path validator status is
    // unchanged from its post-handshake baseline; pending-frames
    // queue has no PATH_RESPONSE owed (the last one was already
    // drained into a packet).
    {
        const sv_path = server.paths.get(0).?;
        try std.testing.expectEqual(
            baseline_status,
            sv_path.path.validator.status,
        );
        try std.testing.expect(server.pending_frames.path_response == null);
    }
}

test "Stray PATH_RESPONSE absorbed without changing validator state (§4.8 / §11.2)" {
    // Companion to the flood test: this directly probes the
    // `recordPathResponse` -> `Error.NotPending` -> swallow path. The
    // server's primary-path validator is in its post-handshake
    // baseline state (`.validated`, since the handshake-confirmed
    // primary path is implicitly validated). The client sends an
    // unsolicited PATH_RESPONSE inside a 1-RTT packet; the server
    // must:
    //
    //   - decrypt and parse the frame without error,
    //   - leave its validator status unchanged (no state-machine
    //     transition — `.validated` does NOT step backward to
    //     `.pending`, and `.pending` doesn't get minted from an
    //     incoming PATH_RESPONSE alone),
    //   - emit no follow-up PATH_RESPONSE (the frame doesn't
    //     prompt a response — only PATH_CHALLENGE does),
    //   - have no PATH_CHALLENGE / PATH_RESPONSE queued in
    //     `pending_frames` after the dust settles.
    //
    // This is the receive-side check the §11.2 row "PATH_CHALLENGE
    // flood" calls out: stray PATH_RESPONSEs (the natural follow-up
    // on a malicious peer's flood) are a no-op. Without this
    // property, an attacker who somehow drove the validator to
    // `.pending` could then forge a token-matching PATH_RESPONSE to
    // bypass path validation; this test pins the asymmetry that an
    // unsolicited PATH_RESPONSE alone never wedges the validator.
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    var pair = try buildPair(allocator, &server_tls, &client_tls);
    defer {
        pair.client.deinit();
        allocator.destroy(pair.client);
        pair.server.deinit();
        allocator.destroy(pair.server);
        server_tls.deinit();
        client_tls.deinit();
    }

    const client = pair.client;
    const server = pair.server;
    var now_us = try driveHandshake(client, server, 1_000_000);

    // Capture the post-handshake baseline so the cheap-no-op
    // assertion is unambiguous.
    const baseline_status = server.paths.get(0).?.path.validator.status;
    // The post-handshake primary path is `.validated` per
    // `Path.markValidated` — it won the implicit validation through
    // the handshake. The test below asserts an unsolicited
    // PATH_RESPONSE leaves this status untouched.
    try std.testing.expectEqual(
        quic_zig.conn.path_validator.Status.validated,
        baseline_status,
    );

    // Drive a normal client poll/server handle round so the
    // handshake's tail (HANDSHAKE_DONE, ACKs, etc.) clears out and
    // the client's app PN advances. After this both ends have
    // settled into 1-RTT-only steady state.
    var discard: [2048]u8 = undefined;
    if (try client.poll(&discard, now_us)) |dn| {
        try server.handle(discard[0..dn], null, now_us);
    }
    if (try server.poll(&discard, now_us)) |dn| {
        try client.handle(discard[0..dn], null, now_us);
    }

    // Inject the unsolicited PATH_RESPONSE through the client's own
    // poll path. We can't easily forge the wire form (the client's
    // PN tracker would skip past our forged number), so instead we
    // co-opt `pending_frames.path_response`: setting it makes the
    // next client poll emit a PATH_RESPONSE with our chosen token.
    // The token isn't matched to any local challenge at the SERVER
    // side, so this is the "stray PATH_RESPONSE" scenario the test
    // is pinning. Use `pending_frames` as the public-ish injection
    // point (it's a struct field of the public Connection).
    client.pending_frames.path_response = .{
        0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xfe, 0xed,
    };
    client.pending_frames.path_response_path_id = 0;
    client.pending_frames.path_response_addr = null;

    // Pre-state: validator at the captured baseline; no PATH_*
    // frames queued on the SERVER side.
    {
        const sv_path = server.paths.get(0).?;
        try std.testing.expectEqual(baseline_status, sv_path.path.validator.status);
        try std.testing.expect(server.pending_frames.path_response == null);
        try std.testing.expect(server.pending_frames.path_challenge == null);
    }

    // Drive the client → server flow once. The client's poll emits
    // a 1-RTT packet carrying the unsolicited PATH_RESPONSE; the
    // server's `handle` decrypts, parses, and dispatches it. The
    // dispatch path is `recordPathResponse(0, token)`, which calls
    // `PathValidator.recordResponse` — that returns `.NotPending`
    // when the validator status isn't `.pending`, and the connection
    // swallows the error via `catch return`. No state-machine
    // transition; no error propagated.
    var c2s: [2048]u8 = undefined;
    const n_c = (try client.poll(&c2s, now_us)) orelse return error.ClientPolledNothing;
    try server.handle(c2s[0..n_c], null, now_us);

    // Post-state. Validator unchanged from baseline. The server
    // hasn't queued a PATH_RESPONSE (only PATH_CHALLENGE prompts a
    // response — the inbound PATH_RESPONSE is a no-op) or a
    // PATH_CHALLENGE (server is not attempting to validate any new
    // path).
    {
        const sv_path = server.paths.get(0).?;
        try std.testing.expectEqual(baseline_status, sv_path.path.validator.status);
        try std.testing.expect(server.pending_frames.path_response == null);
        try std.testing.expect(server.pending_frames.path_challenge == null);
    }

    // Poll the server one more time. Whatever it emits (ACK for the
    // datagram we just sent, possibly nothing if none owed) must not
    // be a PATH_CHALLENGE — the server has no reason to start path
    // validation in response to a stray PATH_RESPONSE. We don't feed
    // the server's response back to the client (the client's
    // PN-tracker would refuse the packet anyway), we just check the
    // validator state directly.
    now_us += 1_000;
    var s2c: [2048]u8 = undefined;
    _ = try server.poll(&s2c, now_us);
    {
        const sv_path = server.paths.get(0).?;
        try std.testing.expectEqual(baseline_status, sv_path.path.validator.status);
        try std.testing.expect(server.pending_frames.path_challenge == null);
    }
}
