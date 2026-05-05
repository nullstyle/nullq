//! nullq.Server — high-level convenience wrapper for embedding nullq
//! as a QUIC server.
//!
//! nullq is intentionally I/O-agnostic at the protocol layer: a
//! `Connection` consumes incoming UDP datagrams via `handle()` and
//! produces outgoing ones via `poll()`. Wiring that to an actual UDP
//! socket, demultiplexing peers by connection ID, applying
//! transport-parameter templates, and stepping the per-connection
//! event loop is repetitive boilerplate that every embedder ends up
//! writing.
//!
//! `Server` provides that boilerplate as a reusable type. It is still
//! I/O-agnostic — the embedder owns the UDP socket and the wall clock
//! — but it owns the `boringssl.tls.Context`, the connection table
//! keyed by initial DCID, and the per-connection lifecycle bookkeeping
//! that the QNS interop endpoint open-codes.
//!
//! For an example loop, see the README. The QNS endpoint at
//! `interop/qns_endpoint.zig` keeps its own bespoke loop because it
//! has interop-specific quirks (Retry, version negotiation,
//! deterministic CID prefix); embedders without those constraints
//! should reach for `Server` first.
//!
//! TODO(api): client-side `Client.connect` helper, optional built-in
//! Retry token issuance & validation, optional version negotiation,
//! and optional `std.Io` socket loop helper. The current surface is
//! the minimum that compiles cleanly and makes the common server
//! pattern significantly less verbose.

const std = @import("std");
const boringssl = @import("boringssl");

const conn_mod = @import("conn/root.zig");
const tls_mod = @import("tls/root.zig");
const wire = @import("wire/root.zig");

const Connection = conn_mod.Connection;
const TransportParams = tls_mod.TransportParams;
const ConnectionId = conn_mod.path.ConnectionId;
const Address = conn_mod.path.Address;
const QlogCallback = conn_mod.QlogCallback;

/// Configuration handed to `Server.init`. Re-exported as
/// `Server.Config`.
const ConfigImpl = struct {
    /// Wall-clock allocator used for the connection table and any
    /// transient per-server allocations. Each `Connection` allocates
    /// from this allocator as well.
    allocator: std.mem.Allocator,

    /// Server certificate chain and private key, both PEM-encoded.
    /// The `Server` does not take ownership; the caller must keep
    /// these bytes alive for the lifetime of the server.
    tls_cert_pem: []const u8,
    tls_key_pem: []const u8,

    /// ALPN protocols the server is willing to negotiate, in
    /// preference order. Required — QUIC rejects connections that do
    /// not negotiate ALPN.
    alpn_protocols: []const []const u8,

    /// Default transport parameters applied to every accepted
    /// connection. The `original_destination_connection_id` and
    /// `initial_source_connection_id` fields are filled in
    /// automatically per connection; everything else is taken
    /// verbatim.
    transport_params: TransportParams,

    /// Maximum number of concurrent live connections. Excess Initial
    /// packets are dropped.
    max_concurrent_connections: u32 = 1000,

    /// Length of the locally-issued connection IDs (the SCIDs the
    /// server returns to clients). Must be 1..20. Default 8 matches
    /// the QNS endpoint.
    local_cid_len: u8 = 8,

    /// If non-null, every accepted `Connection` is wired up to this
    /// qlog callback for application-key-update telemetry.
    qlog_callback: ?QlogCallback = null,
    qlog_user_data: ?*anyopaque = null,

    /// Optional override of the underlying `boringssl.tls.Context`.
    /// When null, `Server.init` constructs a TLS-1.3-only server
    /// context with `verify=.none` and the supplied ALPN list. Pass
    /// your own to enable, e.g., 0-RTT or session-ticket callbacks.
    tls_context_override: ?boringssl.tls.Context = null,
};

/// One slot in the server's per-connection table. The `Connection`
/// is heap-allocated so the embedder can hold stable pointers to it
/// across `Server.feed` / `Server.poll` calls. Re-exported as
/// `Server.Slot`.
const SlotImpl = struct {
    /// The owned connection. Embedders may write to streams, call
    /// `sendDatagram`, or read events on this directly.
    conn: *Connection,
    /// The DCID the client picked on its very first Initial. Used as
    /// the table key until the server has issued its own CIDs.
    initial_dcid: ConnectionId,
    /// The SCID the server picked for this connection. Returned to
    /// the client in the server's first Initial.
    server_scid: [20]u8,
    server_scid_len: u8,
    /// Last time `feed` saw any datagram for this slot. Embedders can
    /// use this to enforce idle timeouts beyond what QUIC's own idle
    /// timer covers.
    last_activity_us: u64 = 0,
    /// Set once `transport_params` have been applied via
    /// `acceptInitial`. The first datagram triggers this.
    transport_params_set: bool = false,
};

/// Outcome of feeding a single datagram to the server. Re-exported
/// as `Server.FeedOutcome`.
const FeedOutcomeImpl = enum {
    /// The datagram was routed to an existing connection and
    /// processed.
    routed,
    /// The datagram opened a brand-new connection. The newly created
    /// `Slot` is at the back of `Server.slots`.
    accepted,
    /// The datagram was not for any known connection and did not
    /// look like a valid Initial — silently dropped per RFC 9000
    /// §10.3 stateless reset rules.
    dropped,
};

/// Errors produced by `Server.init` and `Server.feed`. `feed` only
/// returns `OutOfMemory` directly — per-connection errors are
/// suppressed so a malformed datagram from one peer cannot tear down
/// the server. Re-exported as `Server.Error`.
const ErrorImpl = error{
    OutOfMemory,
    InvalidConfig,
    RandFailed,
} || boringssl.tls.Error;

/// I/O-agnostic QUIC server. Owns the TLS context and a connection
/// table; the embedder owns the UDP socket and the clock.
///
/// Lifecycle:
///   1. `init` builds the TLS context and pre-allocates the slot
///      table.
///   2. The embedder repeatedly calls `feed(bytes, from, now_us)` on
///      every received datagram, then calls `poll(out_buf, now_us)`
///      in a loop on every live slot to drain queued packets.
///   3. `tick(now_us)` drives time-based recovery. Embedders should
///      call it on every loop iteration regardless of I/O.
///   4. `shutdown` queues `CONNECTION_CLOSE` on every live slot;
///      `deinit` reclaims memory.
pub const Server = struct {
    /// Re-exports of the helper types so `Server.Config`,
    /// `Server.Slot`, `Server.FeedOutcome`, and `Server.Error` all
    /// resolve from the public API surface. The top-level
    /// definitions remain authoritative.
    pub const Config = ConfigImpl;
    pub const Slot = SlotImpl;
    pub const FeedOutcome = FeedOutcomeImpl;
    pub const Error = ErrorImpl;

    allocator: std.mem.Allocator,
    tls_ctx: boringssl.tls.Context,
    /// True if the TLS context was built by `Server.init` and must
    /// be torn down on `deinit`. False if the embedder supplied
    /// `tls_context_override`.
    owns_tls: bool,
    transport_params: TransportParams,
    max_concurrent_connections: u32,
    local_cid_len: u8,
    qlog_callback: ?QlogCallback,
    qlog_user_data: ?*anyopaque,
    /// Live connection slots. Embedders may iterate this between
    /// `feed` / `poll` calls to inspect or mutate connections.
    slots: std.ArrayList(*Slot) = .empty,
    /// Random source used to mint server SCIDs. Embedders that need
    /// deterministic CIDs (interop fixtures, fuzzers) can swap this.
    random: std.Random,
    rng_state: std.Random.DefaultPrng,

    pub fn init(config: Config) Error!Server {
        if (config.alpn_protocols.len == 0) return Error.InvalidConfig;
        if (config.local_cid_len == 0 or config.local_cid_len > 20) return Error.InvalidConfig;
        if (config.tls_cert_pem.len == 0 or config.tls_key_pem.len == 0) return Error.InvalidConfig;

        var tls_ctx: boringssl.tls.Context = undefined;
        var owns_tls = false;
        if (config.tls_context_override) |ctx| {
            tls_ctx = ctx;
        } else {
            tls_ctx = try boringssl.tls.Context.initServer(.{
                .verify = .none,
                .min_version = boringssl.raw.TLS1_3_VERSION,
                .max_version = boringssl.raw.TLS1_3_VERSION,
                .alpn = config.alpn_protocols,
                .early_data_enabled = true,
            });
            errdefer tls_ctx.deinit();
            try tls_ctx.loadCertChainAndKey(config.tls_cert_pem, config.tls_key_pem);
            owns_tls = true;
        }

        // Cheap default RNG seed taken from BoringSSL's CSPRNG.
        // The PRNG itself is just `DefaultPrng` because all we need
        // is unique server SCIDs — embedders that want full crypto
        // randomness on every CID can post-init swap `Server.random`.
        var seed_bytes: [8]u8 = undefined;
        try boringssl.crypto.rand.fillBytes(&seed_bytes);
        const seed = std.mem.readInt(u64, &seed_bytes, .little);
        var prng = std.Random.DefaultPrng.init(seed);

        const slots_initial_capacity: usize = @min(config.max_concurrent_connections, 64);
        var slots: std.ArrayList(*Slot) = .empty;
        slots.ensureTotalCapacity(config.allocator, slots_initial_capacity) catch |e| switch (e) {
            error.OutOfMemory => {
                if (owns_tls) tls_ctx.deinit();
                return Error.OutOfMemory;
            },
        };

        return .{
            .allocator = config.allocator,
            .tls_ctx = tls_ctx,
            .owns_tls = owns_tls,
            .transport_params = config.transport_params,
            .max_concurrent_connections = config.max_concurrent_connections,
            .local_cid_len = config.local_cid_len,
            .qlog_callback = config.qlog_callback,
            .qlog_user_data = config.qlog_user_data,
            .slots = slots,
            .random = prng.random(),
            .rng_state = prng,
        };
    }

    pub fn deinit(self: *Server) void {
        for (self.slots.items) |slot| {
            slot.conn.deinit();
            self.allocator.destroy(slot.conn);
            self.allocator.destroy(slot);
        }
        self.slots.deinit(self.allocator);
        if (self.owns_tls) self.tls_ctx.deinit();
        self.* = undefined;
    }

    /// Number of live connections currently in the table.
    pub fn connectionCount(self: *const Server) usize {
        return self.slots.items.len;
    }

    /// Iterator over the live slots. Embedders can use this to push
    /// outgoing data, drain events, or call `Server.poll`.
    pub fn iterator(self: *Server) []*Slot {
        return self.slots.items;
    }

    /// Demultiplex `bytes` to the right connection, opening a new
    /// one for fresh long-header Initials. `now_us` is the monotonic
    /// clock in microseconds (any monotonic origin works as long as
    /// it's consistent across calls).
    pub fn feed(
        self: *Server,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!FeedOutcome {
        if (bytes.len == 0) return .dropped;

        // First try an existing connection by DCID.
        if (self.findSlotForDatagram(bytes)) |slot| {
            slot.last_activity_us = now_us;
            try self.dispatchToSlot(slot, bytes, from, now_us);
            return .routed;
        }

        // Otherwise, only Initial long-header packets can open a new
        // connection.
        if (!isInitialLongHeader(bytes)) return .dropped;
        if (self.slots.items.len >= self.max_concurrent_connections) return .dropped;

        const slot = self.openSlotFromInitial(bytes, from, now_us) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            // Anything else (TLS init, malformed Initial, Connection
            // setup) is a per-peer hiccup — drop the datagram and
            // keep the server alive.
            else => return .dropped,
        };
        try self.dispatchToSlot(slot, bytes, from, now_us);
        return .accepted;
    }

    /// Poll one outgoing datagram for `slot` into `dst`. Returns the
    /// number of bytes written, or null if nothing is queued. This
    /// is a thin wrapper around `Connection.poll` — embedders that
    /// need the full path-aware `OutgoingDatagram` should call
    /// `slot.conn.pollDatagram` directly.
    pub fn poll(
        self: *Server,
        slot: *Slot,
        dst: []u8,
        now_us: u64,
    ) Connection.Error!?usize {
        _ = self;
        return try slot.conn.poll(dst, now_us);
    }

    /// Drive time-based recovery on every live slot. Idempotent and
    /// cheap — call it on every loop iteration.
    pub fn tick(self: *Server, now_us: u64) Connection.Error!void {
        for (self.slots.items) |slot| {
            try slot.conn.tick(now_us);
        }
    }

    /// Reap any closed slots from the table. Returns the number of
    /// slots reclaimed.
    pub fn reap(self: *Server) usize {
        var i: usize = 0;
        var reaped: usize = 0;
        while (i < self.slots.items.len) {
            const slot = self.slots.items[i];
            if (slot.conn.isClosed()) {
                slot.conn.deinit();
                self.allocator.destroy(slot.conn);
                self.allocator.destroy(slot);
                _ = self.slots.orderedRemove(i);
                reaped += 1;
                continue;
            }
            i += 1;
        }
        return reaped;
    }

    /// Queue `CONNECTION_CLOSE` on every live slot. Embedders should
    /// keep polling and ticking until each slot becomes `.closed`.
    pub fn shutdown(self: *Server, error_code: u64, reason: []const u8) void {
        for (self.slots.items) |slot| {
            slot.conn.close(true, error_code, reason);
        }
    }

    // -- internals ------------------------------------------------------

    fn findSlotForDatagram(self: *Server, bytes: []const u8) ?*Slot {
        const dcid = peekDcidForServer(bytes, self.local_cid_len) orelse return null;
        for (self.slots.items) |slot| {
            // Match against initial DCID (pre-handshake) or the
            // server's own SCID (post-handshake).
            if (std.mem.eql(u8, dcid, slot.initial_dcid.slice())) return slot;
            if (slot.server_scid_len == dcid.len and
                std.mem.eql(u8, dcid, slot.server_scid[0..slot.server_scid_len]))
            {
                return slot;
            }
        }
        return null;
    }

    fn openSlotFromInitial(
        self: *Server,
        bytes: []const u8,
        from: ?Address,
        now_us: u64,
    ) !*Slot {
        _ = from;
        const ids = peekLongHeaderIds(bytes) orelse return error.InvalidInitial;

        const slot = try self.allocator.create(Slot);
        errdefer self.allocator.destroy(slot);

        const conn_ptr = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn_ptr);

        conn_ptr.* = try Connection.initServer(self.allocator, self.tls_ctx);
        errdefer conn_ptr.deinit();

        try conn_ptr.bind();
        if (self.qlog_callback) |cb| conn_ptr.setQlogCallback(cb, self.qlog_user_data);

        var server_scid: [20]u8 = undefined;
        self.random.bytes(server_scid[0..self.local_cid_len]);
        try conn_ptr.setLocalScid(server_scid[0..self.local_cid_len]);

        const original_dcid = ConnectionId.fromSlice(ids.dcid);

        var params = self.transport_params;
        params.original_destination_connection_id = original_dcid;
        params.initial_source_connection_id = ConnectionId.fromSlice(server_scid[0..self.local_cid_len]);
        try conn_ptr.acceptInitial(bytes, params);

        slot.* = .{
            .conn = conn_ptr,
            .initial_dcid = original_dcid,
            .server_scid = server_scid,
            .server_scid_len = self.local_cid_len,
            .last_activity_us = now_us,
            .transport_params_set = true,
        };
        try self.slots.append(self.allocator, slot);
        return slot;
    }

    fn dispatchToSlot(
        self: *Server,
        slot: *Slot,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!void {
        _ = self;
        slot.conn.handle(bytes, from, now_us) catch {
            // Per-connection error: don't tear down the server. The
            // connection itself transitions to .closed and the
            // embedder will reap it on the next `reap()` call.
        };
    }
};

// -- header-peek helpers ------------------------------------------------

const LongHeaderIds = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
};

fn peekLongHeaderIds(bytes: []const u8) ?LongHeaderIds {
    if (bytes.len < 6) return null;
    if ((bytes[0] & 0x80) == 0) return null;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    const dcid_len = bytes[5];
    if (dcid_len > 20) return null;
    var pos: usize = 6;
    if (bytes.len < pos + @as(usize, dcid_len) + 1) return null;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = bytes[pos];
    if (scid_len > 20) return null;
    pos += 1;
    if (bytes.len < pos + @as(usize, scid_len)) return null;
    const scid = bytes[pos .. pos + scid_len];

    return .{ .version = version, .dcid = dcid, .scid = scid };
}

fn isInitialLongHeader(bytes: []const u8) bool {
    if (bytes.len == 0 or (bytes[0] & 0x80) == 0) return false;
    if (bytes.len < 5) return false;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    if (version == 0) return false; // version negotiation
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    return long_type_bits == 0;
}

/// Peek the DCID from either header form. Long headers carry an
/// explicit length; short headers use the server's local-CID length.
fn peekDcidForServer(bytes: []const u8, local_cid_len: u8) ?[]const u8 {
    if (bytes.len == 0) return null;
    if ((bytes[0] & 0x80) != 0) {
        const ids = peekLongHeaderIds(bytes) orelse return null;
        return ids.dcid;
    }
    if (bytes.len < 1 + @as(usize, local_cid_len)) return null;
    return bytes[1 .. 1 + local_cid_len];
}

// -- tests --------------------------------------------------------------
//
// The init/feed end-to-end smoke test lives in
// `tests/e2e/server_smoke.zig` because it needs real cert/key PEMs
// from `tests/data`, which sit outside this package's import path.
// The tests below only exercise pure helpers and config validation —
// neither needs a TLS context.

test "Server.init validates configuration" {
    // Use empty PEMs that would otherwise reach BoringSSL — the
    // length check fires first so we never call into TLS here.
    const protos = [_][]const u8{"hq-test"};

    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "",
        .tls_key_pem = "",
        .alpn_protocols = &protos,
        .transport_params = .{},
    }));

    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &.{},
        .transport_params = .{},
    }));

    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .local_cid_len = 0,
        .transport_params = .{},
    }));

    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .local_cid_len = 21,
        .transport_params = .{},
    }));
}

test "peekLongHeaderIds rejects too-short" {
    try std.testing.expect(peekLongHeaderIds(&.{}) == null);
    try std.testing.expect(peekLongHeaderIds(&.{0xc0}) == null);
}

test "isInitialLongHeader recognizes Initial type bits" {
    // Long header, type=0 (Initial), version=1 (won't actually parse
    // payload — we only inspect the type bits and version field).
    const bytes = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&bytes));

    // Version negotiation (version=0) is *not* an Initial.
    const vn = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&vn));

    // Short header.
    const sh = [_]u8{ 0x40, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&sh));
}
