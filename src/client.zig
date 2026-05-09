//! quic_zig.Client — convenience wrapper for embedding quic_zig as a
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
//! For embedders who don't want to hand-roll the bind/poll/recv/tick
//! loop, `quic_zig.transport.runUdpClient` is the opinionated
//! mirror to `runUdpServer`. It owns the UDP socket, drives the
//! state machine on a monotonic clock, and exits cleanly when the
//! connection closes (or an embedder-supplied shutdown flag
//! flips). See `src/transport/udp_client.zig` for the option
//! surface.

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
    /// context with the supplied ALPN list and the verification mode
    /// derived from `ca_pem`. The auto-built context's
    /// `early_data_enabled` flag follows whether `session_ticket` is
    /// non-null — 0-RTT is only enabled at the TLS layer when the
    /// embedder actually plans to use it (§5.2 / §12 hardening).
    /// Pass your own to enable, e.g., custom session-ticket capture
    /// or keylog wiring (see the QNS endpoint).
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
    /// the presence of this field also drives `early_data_enabled` on
    /// the auto-built TLS context so the path works out of the box;
    /// embedders without a ticket get `early_data_enabled = false`
    /// per the §5.2 / §12 hardening posture.
    session_ticket: ?[]const u8 = null,

    /// Whether to encode the locally-recorded close-reason string into
    /// outgoing CONNECTION_CLOSE frames. Default `false` (redact) per
    /// hardening guide §9 / §12 — internal parser-error strings reveal
    /// implementation detail to the peer. Local introspection via
    /// close events is unaffected.
    reveal_close_reason_on_wire: bool = false,

    /// Number of ack-eliciting application packets the client requires
    /// before forcing an immediate ACK (RFC 9000 §13.2.1 ¶2). Default
    /// matches `quic_zig.conn.state.application_ack_eliciting_threshold`.
    /// Lower this to 1 for low-RTT links where every packet should be
    /// ACKed; raise it to amortize ACK overhead at the cost of more
    /// peer PTOs.
    delayed_ack_packet_threshold: u8 = conn_mod.state.application_ack_eliciting_threshold,

    /// Enable IETF ECN signaling (RFC 9000 §13.4 / RFC 3168) on the
    /// underlying Connection. Default `true`. Flip to `false` only
    /// in environments known to bleach ECN bits (some legacy NATs /
    /// firewalls); see `Connection.ecn_enabled` for the per-connection
    /// kill-switch this maps onto.
    enable_ecn: bool = true,

    /// Optional NEW_TOKEN bytes from a prior connection to the same
    /// server (RFC 9000 §8.1.3). When set, the client embeds the
    /// token in its first Initial's long-header Token field so the
    /// server can skip its Retry round trip. Embedders typically
    /// capture the bytes from the previous connection's
    /// `new_token_callback` and persist them alongside the TLS
    /// session ticket.
    new_token: ?[]const u8 = null,
    /// Optional callback fired when this connection receives a
    /// NEW_TOKEN frame. Embedders capture the bytes (which are only
    /// borrowed for the duration of the call) for use as the
    /// `new_token` field on a future connection. See
    /// `Connection.setNewTokenCallback` for the lifetime contract.
    new_token_callback: ?conn_mod.NewTokenCallback = null,
    new_token_user_data: ?*anyopaque = null,

    /// QUIC wire-format version the client puts on its first
    /// Initial. RFC 9000 §15: defaults to v1
    /// (`quic_zig.QUIC_VERSION_1`). Embedders that want v2
    /// standalone set this to `quic_zig.QUIC_VERSION_2`; the
    /// client's Initial-key salt + HKDF labels (RFC 9368 §3.3.1 /
    /// §3.3.2), long-header type bits (§3.2), and Retry-tag
    /// constants (§3.3.3) follow.
    preferred_version: u32 = 0x00000001,

    /// Optional list of additional QUIC versions the client is
    /// willing to upgrade to via the RFC 9368 §5/§6 compatible-version
    /// negotiation mechanism. Empty (the default) suppresses the
    /// `version_information` (codepoint 0x11) transport parameter,
    /// keeping the on-wire posture indistinguishable from a v0.x
    /// client. When non-empty, the client advertises
    /// `[preferred_version, compatible_versions...]` so a server
    /// that supports a different overlapping version can opt in to
    /// a compatible upgrade.
    ///
    /// Upgrade consumption is implemented end-to-end: the first
    /// inbound Initial whose long-header version field differs from
    /// `preferred_version` triggers
    /// `Connection.clientAcceptCompatibleVersion` (in
    /// `conn/conn_recv_packet_handlers.handleInitial`), which
    /// validates the candidate against this list and re-derives
    /// Initial keys for the upgraded version before the AEAD open
    /// runs. Once the handshake produces the server's
    /// EncryptedExtensions, `validatePeerTransportRole` enforces the
    /// RFC 9368 §6 ¶6/¶7 downgrade guard (`chosen_version` MUST equal
    /// the wire version of the response carrying it).
    compatible_versions: []const u32 = &.{},

    /// RFC 8899 DPLPMTUD configuration applied to the underlying
    /// `Connection`. The default (1200 floor, 1452 ceiling, 64-byte
    /// step, 3-strike threshold, enabled) matches the QUIC v1
    /// minimum-MTU floor and the typical 1500-byte internet MTU.
    /// Set `enable = false` to keep the historical static-MTU
    /// behaviour.
    pmtud: conn_mod.PmtudConfig = .{},
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
/// `Connection` and owns the supporting TLS context. Mirror to
/// `Server`: returned by value from `connect`, owns its own
/// allocations (the heap `*Connection` plus the BoringSSL TLS
/// context when not overridden), torn down by `deinit`.
///
/// Lifecycle:
///   1. `connect(config)` builds the TLS context, mints random
///      DCID/SCID per RFC 9000 §7.2, calls `Connection.initClient`,
///      runs `bind` / `setLocalScid` / `setInitialDcid` /
///      `setPeerDcid` / `setTransportParams`, optionally installs a
///      0-RTT session ticket, and returns a ready-to-tick `Client`.
///   2. The embedder drives the handshake via `client.conn.advance` /
///      `client.conn.poll` to emit the first Initial, then
///      `client.conn.handle` on every received datagram.
///   3. `client.deinit()` frees the heap `Connection` and (when the
///      wrapper built one) the TLS context.
pub const Client = struct {
    /// Re-exports of the helper types so `Client.Config` and
    /// `Client.Error` both resolve from the public API surface.
    pub const Config = ConfigImpl;
    pub const Error = ErrorImpl;

    /// Allocator that backs the heap `Connection` and any per-client
    /// transient allocations.
    allocator: std.mem.Allocator,
    /// BoringSSL TLS context used by the connection. Whether `Client`
    /// owns it or it was passed in via `tls_context_override` is
    /// captured by `owns_tls`.
    tls_ctx: boringssl.tls.Context,
    /// True if the TLS context was built by `Client.connect` and
    /// must be torn down on `deinit`. False if the embedder supplied
    /// `tls_context_override`.
    owns_tls: bool,
    /// The owned, freshly-bound `Connection`. Embedders drive the
    /// handshake and per-stream I/O directly through this pointer
    /// (`client.conn.advance`, `client.conn.poll`, `client.conn.handle`,
    /// etc).
    conn: *Connection,

    /// Build the TLS context, mint the random DCID/SCID, and
    /// initialize the underlying `Connection`. See the type
    /// docstring for the post-condition shape. The returned `Client`
    /// owns its allocations until `deinit` is called.
    ///
    /// The returned `Client` does not retain a pointer to the
    /// supplied `config` — copy any fields you need into your own
    /// state before discarding it.
    pub fn connect(config: Config) Error!Client {
        if (config.server_name.len == 0) return Error.InvalidConfig;
        if (config.alpn_protocols.len == 0) return Error.InvalidConfig;
        if (config.initial_dcid_len < 8 or config.initial_dcid_len > 20) return Error.InvalidConfig;
        if (config.local_cid_len == 0 or config.local_cid_len > 20) return Error.InvalidConfig;
        // The version drives the Initial-key salt + HKDF labels
        // (RFC 9001 §5.2 v1 / RFC 9368 §3.3.1 v2) — only the wire
        // versions this implementation knows how to derive keys for
        // are accepted here.
        const wire_initial = @import("wire/initial.zig");
        if (!wire_initial.isSupportedVersion(config.preferred_version)) return Error.InvalidConfig;
        if (config.compatible_versions.len > 16) return Error.InvalidConfig;
        for (config.compatible_versions) |v| {
            if (!wire_initial.isSupportedVersion(v)) return Error.InvalidConfig;
        }

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
            // Only enable early-data on the auto-built TLS context
            // when the embedder actually plans to use it (i.e. they
            // supplied a 0-RTT session ticket). This is the §5.2 /
            // §12 secure-default posture: 0-RTT off unless
            // explicitly opted into. Embedders that want 0-RTT
            // capability without a ticket on this attempt can pass
            // their own `tls_context_override` with
            // `early_data_enabled = true`.
            tls_ctx = try boringssl.tls.Context.initClient(.{
                .verify = verify,
                .min_version = boringssl.raw.TLS1_3_VERSION,
                .max_version = boringssl.raw.TLS1_3_VERSION,
                .alpn = config.alpn_protocols,
                .early_data_enabled = config.session_ticket != null,
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
        conn_ptr.reveal_close_reason_on_wire = config.reveal_close_reason_on_wire;
        conn_ptr.delayed_ack_packet_threshold = config.delayed_ack_packet_threshold;
        // RFC 9368 §3 / §5: pick the wire-format version *before*
        // any Initial keys are derived. `setVersion` is a no-op when
        // the value is already current, so this works for the v1
        // default path too.
        conn_ptr.setVersion(config.preferred_version);
        conn_ptr.ecn_enabled = config.enable_ecn;
        // RFC 8899 DPLPMTUD: apply the embedder config and
        // re-initialise the per-path PMTUD state.
        conn_ptr.setPmtudConfig(config.pmtud);

        if (config.qlog_callback) |cb| conn_ptr.setQlogCallback(cb, config.qlog_user_data);

        // NEW_TOKEN receive callback — wire it before any frame
        // could be processed. Server-side connections never fire
        // this; the role check inside `setNewTokenCallback` would
        // accept it on a server connection too, but `Connection`
        // is in client mode here.
        if (config.new_token_callback) |cb| {
            conn_ptr.setNewTokenCallback(cb, config.new_token_user_data);
        }

        // NEW_TOKEN replay on the first Initial — RFC 9000 §8.1.3
        // lets a returning client present a previously-issued
        // token in the Initial's long-header Token field. quic_zig
        // reuses the `retry_token` storage on Connection because
        // the wire mechanism is identical (Token field on
        // long-header Initial). The Server's gate distinguishes
        // by trying NEW_TOKEN.validate first.
        if (config.new_token) |nt_bytes| {
            try conn_ptr.setInitialToken(nt_bytes);
        }

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
        // RFC 9368 §5: advertise the chosen version + compatible
        // versions so a server that supports a different version
        // can opt into a compatible upgrade. Empty
        // `compatible_versions` keeps the parameter absent, which
        // matches v0.x wire posture for embedders that don't opt in.
        if (config.compatible_versions.len > 0) {
            var ordered: [16]u32 = undefined;
            ordered[0] = config.preferred_version;
            const cv_count = @min(config.compatible_versions.len, ordered.len - 1);
            @memcpy(ordered[1..][0..cv_count], config.compatible_versions[0..cv_count]);
            try params.setCompatibleVersions(ordered[0 .. 1 + cv_count]);
        }
        try conn_ptr.setTransportParams(params);

        return .{
            .allocator = config.allocator,
            .tls_ctx = tls_ctx,
            .owns_tls = owns_tls,
            .conn = conn_ptr,
        };
    }

    /// Tear down the connection and (if owned) the TLS context.
    /// After this returns, `self` is invalid.
    pub fn deinit(self: *Client) void {
        self.conn.deinit();
        self.allocator.destroy(self.conn);
        if (self.owns_tls) self.tls_ctx.deinit();
        self.* = undefined;
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
