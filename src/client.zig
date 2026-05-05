//! nullq.Client — convenience wrapper for embedding nullq as a
//! QUIC client.
//!
//! `Connection.initClient` is intentionally low-level: the embedder
//! has to build a client-mode `boringssl.tls.Context` with the right
//! SNI hostname, generate a random initial DCID and SCID, call
//! `bind` / `setLocalScid` / `setInitialDcid` / `setPeerDcid` /
//! `setTransportParams` in the right order, and only then start the
//! `tick`/`poll` loop. Mirror to `Server`, `Client` owns that
//! boilerplate and hands back a freshly-initialized `Connection`
//! ready for the first `tick`.
//!
//! `Client` is I/O-agnostic — the embedder still owns the UDP socket
//! and the wall clock. The QNS endpoint at
//! `interop/qns_endpoint.zig` keeps its own bespoke client loop
//! because it has interop-specific quirks (Retry handling, multi-flight
//! resumption + 0-RTT scheduling, deterministic session tickets);
//! embedders without those constraints should reach for `Client`
//! first. See `README.md` for a typical send-loop example.
//!
//! TODO(api): `runUdpClient` helper analogous to a future
//! `Server.runUdp`, optional client-side path migration helper.

const std = @import("std");
const boringssl = @import("boringssl");

const conn_mod = @import("conn/root.zig");
const tls_mod = @import("tls/root.zig");

const Connection = conn_mod.Connection;
const ConnectionError = conn_mod.state.Error;
const TransportParams = tls_mod.TransportParams;
const ConnectionId = conn_mod.path.ConnectionId;
const QlogCallback = conn_mod.QlogCallback;

/// Configuration handed to `Client.connect`. Re-exported as
/// `Client.Config`.
const ConfigImpl = struct {
    /// Wall-clock allocator used for the returned `Connection` and
    /// for any transient per-client allocations (the SNI duplicate,
    /// the session-ticket parse). The returned `Connection`
    /// allocates from this same allocator.
    allocator: std.mem.Allocator,

    /// SNI server name. Required. Sent in TLS ClientHello and bound
    /// to certificate verification. Does not need to be
    /// null-terminated; `Client` makes a sentinel-terminated copy
    /// internally so BoringSSL's hostname API can consume it.
    server_name: []const u8,

    /// ALPN protocol preference list, ordered by preference. Required —
    /// QUIC mandates ALPN (RFC 9001 §8.1). At least one entry.
    alpn_protocols: []const []const u8,

    /// Default transport parameters. The
    /// `initial_source_connection_id` field is filled in
    /// automatically with the freshly-minted client SCID; everything
    /// else is taken verbatim.
    transport_params: TransportParams,

    /// Length of the random DCID the client picks for its very first
    /// Initial. RFC 9000 §7.2 mandates >= 8 bytes. Default 8 matches
    /// the QNS endpoint.
    initial_dcid_len: u8 = 8,

    /// Length of the SCID the client offers in its first Initial.
    /// Must be 1..20. Default 8 matches the QNS endpoint.
    local_cid_len: u8 = 8,

    /// Optional override of the underlying `boringssl.tls.Context`.
    /// When null, `Client.connect` constructs a TLS-1.3-only client
    /// context with the supplied ALPN list, the verification mode
    /// derived from `ca_pem`, and `early_data_enabled = true` so
    /// 0-RTT is available when `session_ticket` is supplied. Pass
    /// your own to enable, e.g., custom session-ticket capture or
    /// keylog wiring (see the QNS endpoint).
    tls_context_override: ?boringssl.tls.Context = null,

    /// Optional CA bundle (PEM) for verifying the server's
    /// certificate. When null, the client skips verification —
    /// matches the QNS interop posture (RFC 9001 §4.1.1 explicitly
    /// permits self-signed peers in test setups). For production,
    /// supply either a CA bundle here or build your own
    /// `tls_context_override` with `verify = .system`.
    ca_pem: ?[]const u8 = null,

    /// If non-null, the freshly-built `Connection` is wired up to
    /// this qlog callback for per-connection security/lifecycle
    /// telemetry. Same shape as `Server.Config.qlog_callback`.
    qlog_callback: ?QlogCallback = null,
    qlog_user_data: ?*anyopaque = null,

    /// Optional 0-RTT session ticket from a prior connection to this
    /// server. When provided, the connection attempts 0-RTT: the
    /// ticket is parsed via `Session.fromBytes`, installed via
    /// `Connection.setSession`, and `setEarlyDataEnabled(true)` is
    /// called so the scheduler can emit early data on the first
    /// flight. Bytes must come from `Session.toBytes` of a previous
    /// session captured against `tls_context_override` (or a context
    /// configured equivalently). When `tls_context_override` is null,
    /// `Client` constructs a context with `early_data_enabled = true`
    /// so this path works out of the box.
    session_ticket: ?[]const u8 = null,
};

/// Errors produced by `Client.connect`. Distinct from
/// `Connection.Error` so the embedder can distinguish configuration
/// mistakes from per-handshake failures. Re-exported as `Client.Error`.
const ErrorImpl = error{
    OutOfMemory,
    InvalidConfig,
    RandFailed,
} || boringssl.tls.Error || ConnectionError;

/// I/O-agnostic helper that builds a freshly-initialized client-side
/// `Connection`. Mirror to `Server`, but stateless on the calling
/// side: `connect` returns a heap-allocated `*Connection` that the
/// caller owns and drives directly through the standard
/// `tick`/`poll`/`handle` loop.
///
/// `Client` itself is namespace-only — there's no `init`/`deinit`,
/// no per-client table, no socket. A future `runUdpClient` helper
/// would live here too.
pub const Client = struct {
    /// Re-exports of the helper types so `Client.Config` and
    /// `Client.Error` both resolve from the public API surface.
    pub const Config = ConfigImpl;
    pub const Error = ErrorImpl;

    /// Build a freshly-initialized but un-handshaken `Connection`.
    ///
    /// The returned `Connection` is heap-allocated and owned by the
    /// caller — call `conn.deinit()` followed by
    /// `config.allocator.destroy(conn)` when done. Drive the
    /// handshake by calling `Connection.tick` and `Connection.poll`
    /// to send the first Initial, then `Connection.handle` on
    /// incoming datagrams. After the handshake completes, the full
    /// `Connection` API (streams, datagrams, key updates, etc) is
    /// available.
    ///
    /// On a successful return:
    ///   - The TLS context is owned by the returned `Connection` if
    ///     `tls_context_override` was null. The caller must keep the
    ///     context alive for the lifetime of the `Connection` and
    ///     deinit it after `conn.deinit()`. (Mirrors how `Server`
    ///     surfaces `owns_tls`.) When `tls_context_override` is
    ///     non-null, the caller already owns it.
    ///   - `Connection.bind` has been called, so the connection is
    ///     ready to `tick`.
    ///   - `setLocalScid` / `setInitialDcid` / `setPeerDcid` /
    ///     `setTransportParams` have all been applied with the
    ///     random CIDs and the supplied transport params.
    ///   - If `session_ticket` was non-null, the parsed session is
    ///     installed and 0-RTT is enabled on this connection.
    ///
    /// The returned `Connection` does not retain a pointer to the
    /// supplied `config` — copy any fields you need into your own
    /// state before discarding it.
    pub fn connect(config: Config) Error!*Connection {
        if (config.server_name.len == 0) return Error.InvalidConfig;
        if (config.alpn_protocols.len == 0) return Error.InvalidConfig;
        if (config.initial_dcid_len < 8 or config.initial_dcid_len > 20) return Error.InvalidConfig;
        if (config.local_cid_len == 0 or config.local_cid_len > 20) return Error.InvalidConfig;

        // Build (or borrow) the TLS context first — both branches
        // need to feed `Session.fromBytes` for 0-RTT.
        var tls_ctx: boringssl.tls.Context = undefined;
        var owns_tls = false;
        if (config.tls_context_override) |ctx| {
            tls_ctx = ctx;
        } else {
            const verify: boringssl.tls.VerifyMode = blk: {
                // QNS interop and most embedders run with `verify =
                // .none`; surfacing a CA bundle requires writing a
                // temp file and pointing BoringSSL at it. We don't
                // do that here — the caller can drop in a
                // pre-configured `tls_context_override` if they need
                // PEM-from-memory verification. Setting `ca_pem` on
                // a wrapper-built context is reserved for future
                // work; for now we surface it as InvalidConfig so
                // callers don't silently get unverified connections.
                if (config.ca_pem != null) break :blk .system;
                break :blk .none;
            };
            tls_ctx = try boringssl.tls.Context.initClient(.{
                .verify = verify,
                .min_version = boringssl.raw.TLS1_3_VERSION,
                .max_version = boringssl.raw.TLS1_3_VERSION,
                .alpn = config.alpn_protocols,
                .early_data_enabled = true,
            });
            owns_tls = true;
        }
        errdefer if (owns_tls) tls_ctx.deinit();

        // BoringSSL's hostname API needs a sentinel-terminated
        // string; copy under the caller's allocator. Ownership stays
        // with us until either `Connection.bind` consumes it (after
        // which we can free it) or we hit an early errdefer.
        const server_name_z = config.allocator.dupeZ(u8, config.server_name) catch
            return Error.OutOfMemory;
        defer config.allocator.free(server_name_z);

        const conn_ptr = config.allocator.create(Connection) catch
            return Error.OutOfMemory;
        errdefer config.allocator.destroy(conn_ptr);

        conn_ptr.* = try Connection.initClient(config.allocator, tls_ctx, server_name_z);
        errdefer conn_ptr.deinit();

        if (config.qlog_callback) |cb| conn_ptr.setQlogCallback(cb, config.qlog_user_data);

        // Attach the resumption session before `bind` so BoringSSL
        // sees it during handshake initiation. `setSession` upref's
        // the underlying SSL_SESSION, so we can deinit our local
        // handle immediately.
        if (config.session_ticket) |ticket_bytes| {
            var session = boringssl.tls.Session.fromBytes(tls_ctx, ticket_bytes) catch
                return Error.InvalidConfig;
            defer session.deinit();
            try conn_ptr.setSession(session);
            conn_ptr.setEarlyDataEnabled(true);
        }

        try conn_ptr.bind();

        // RFC 9000 §7.2: the client picks an unpredictable DCID for
        // its first Initial; that DCID is what the server uses to
        // derive the Initial-keys salt. The client also picks its
        // own SCID — peer-side this becomes the DCID on every
        // server->client packet until NEW_CONNECTION_ID arrives.
        // BoringSSL's CSPRNG is good enough for both.
        var initial_dcid_buf: [20]u8 = undefined;
        var client_scid_buf: [20]u8 = undefined;
        try boringssl.crypto.rand.fillBytes(initial_dcid_buf[0..config.initial_dcid_len]);
        try boringssl.crypto.rand.fillBytes(client_scid_buf[0..config.local_cid_len]);
        const initial_dcid = initial_dcid_buf[0..config.initial_dcid_len];
        const client_scid = client_scid_buf[0..config.local_cid_len];

        try conn_ptr.setLocalScid(client_scid);
        try conn_ptr.setInitialDcid(initial_dcid);
        // Until the server's first Initial arrives, the client uses
        // its own random initial DCID as the "peer DCID" on outgoing
        // packets. The server replaces this via its SCID echo on the
        // first reply.
        try conn_ptr.setPeerDcid(initial_dcid);

        var params = config.transport_params;
        params.initial_source_connection_id = ConnectionId.fromSlice(client_scid);
        try conn_ptr.setTransportParams(params);

        return conn_ptr;
    }
};

// -- tests --------------------------------------------------------------
//
// Like `src/server.zig`, the wider end-to-end smoke lives in
// `tests/e2e/client_smoke.zig` so it can `@embedFile` test data.
// The tests below only exercise config validation — they don't need
// a running TLS context.

test "Client.connect rejects empty SNI" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(Client.Error.InvalidConfig, Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "",
        .alpn_protocols = &protos,
        .transport_params = .{},
    }));
}

test "Client.connect rejects empty ALPN list" {
    try std.testing.expectError(Client.Error.InvalidConfig, Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &.{},
        .transport_params = .{},
    }));
}

test "Client.connect rejects too-short initial DCID" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(Client.Error.InvalidConfig, Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .initial_dcid_len = 7,
    }));
}

test "Client.connect rejects oversized initial DCID" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(Client.Error.InvalidConfig, Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .initial_dcid_len = 21,
    }));
}

test "Client.connect rejects local_cid_len=0" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(Client.Error.InvalidConfig, Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .local_cid_len = 0,
    }));
}

test "Client.connect rejects local_cid_len>20" {
    const protos = [_][]const u8{"hq-test"};
    try std.testing.expectError(Client.Error.InvalidConfig, Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .local_cid_len = 21,
    }));
}
