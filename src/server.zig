//! nullq.Server — production-grade convenience wrapper for embedding
//! nullq as a QUIC server.
//!
//! `Connection` is intentionally I/O-agnostic: it consumes incoming
//! UDP datagrams via `handle()` and produces outgoing ones via
//! `poll()`. Wiring that to a UDP socket, demultiplexing peers by
//! connection ID, applying transport-parameter templates, and
//! stepping the per-connection event loop is repetitive boilerplate
//! every embedder ends up writing.
//!
//! `Server` owns that boilerplate. It is still I/O-agnostic — the
//! embedder owns the UDP socket and the wall clock — but it owns the
//! `boringssl.tls.Context`, the per-connection lifecycle, and a
//! constant-time CID-to-slot routing table that follows
//! NEW_CONNECTION_ID issuance / RETIRE_CONNECTION_ID retirement
//! automatically.
//!
//! Routing
//! -------
//! After every successful `feed`, the slot's CID set is resynced
//! from `Connection.localScids` and the routing table is updated in
//! place — added SCIDs become routing keys immediately, retired
//! SCIDs stop accepting traffic. Lookup is `std.AutoHashMap`
//! O(1) on the length-prefixed CID bytes; reaping a slot drops
//! every CID it owned in one pass. RFC 9000 §5.1.1 lets peers pick
//! any issued CID at any time, and the router honors that without
//! the embedder writing CID-tracking glue.
//!
//! DoS posture
//! -----------
//! `Config.max_initials_per_source_per_window` (off by default)
//! enables a per-source-address token bucket on Initial-driven slot
//! creation. When the cap is exceeded, fresh Initials from that
//! source are dropped without state, so an attacker spraying
//! Initials from a single address cannot exhaust the slot table or
//! the TLS context. Set it for any deployment exposed to the open
//! internet.
//!
//! For a hand-rolled loop, see the README. Embedders that just want
//! "bind a socket and serve QUIC" should reach for
//! `nullq.transport.runUdpServer` instead — it owns the
//! `std.Io`-based bind / tune / receive / feed / poll / tick / reap
//! cadence. The QNS endpoint at `interop/qns_endpoint.zig` keeps its
//! own bespoke loop because it has interop-specific quirks (Retry,
//! version negotiation, deterministic CID prefix); embedders without
//! those constraints should reach for `Server` first.
//!
//! TODO(api): optional built-in Retry token issuance & validation,
//! optional version negotiation. (`nullq.Client` covers the
//! client-side connect helper; `nullq.transport.runUdpServer`
//! covers the std.Io socket loop.)

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

/// Maximum number of routing CIDs a slot tracks at once. Bounded
/// by the peer's `active_connection_id_limit` (default 8 in nullq);
/// 16 leaves headroom for in-flight retires and gives the router a
/// fixed, alloc-free slot footprint.
const max_tracked_cids_per_slot: usize = 16;

/// Length-prefixed packed CID key used as the `cid_table` HashMap
/// key. Byte 0 is the CID length (1..20); bytes 1..1+len are the
/// CID material; bytes past `len` are zeroed so the key compares
/// by value.
const CidKey = [21]u8;

fn cidKeyFromSlice(cid: []const u8) CidKey {
    std.debug.assert(cid.len <= 20);
    var k: CidKey = @splat(0);
    k[0] = @intCast(cid.len);
    @memcpy(k[1 .. 1 + cid.len], cid);
    return k;
}

fn cidKeyFromConnectionId(cid: ConnectionId) CidKey {
    return cidKeyFromSlice(cid.bytes[0..cid.len]);
}

/// Per-source rate-limit bookkeeping. One entry per active source
/// address; entries older than `source_rate_window_us` are pruned
/// lazily on each `feed`.
const SourceRateEntry = struct {
    /// Initial-driven slot creations attributed to this source
    /// within the current window.
    count: u32,
    /// Wall-clock microseconds when the current window started.
    window_start_us: u64,
};

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

    /// Per-source-address Initial-acceptance cap. Null disables the
    /// rate limiter; any other value enables it and rejects fresh
    /// Initials from a source whose recent count is at or above the
    /// cap within `source_rate_window_us`. Datagrams to existing
    /// slots are unaffected. Recommended: 32 for typical
    /// open-internet deployments.
    max_initials_per_source_per_window: ?u32 = null,

    /// Sliding-window size for `max_initials_per_source_per_window`,
    /// in microseconds. Default is one second.
    source_rate_window_us: u64 = 1_000_000,

    /// Maximum number of distinct source addresses the rate limiter
    /// tracks at once. Excess sources rotate out the oldest entry.
    /// Only consulted when the limiter is enabled.
    source_rate_table_capacity: u32 = 4096,
};

/// One slot in the server's per-connection table. The `Connection`
/// is heap-allocated so the embedder can hold stable pointers across
/// `Server.feed` / `Server.poll` calls. Re-exported as `Server.Slot`.
const SlotImpl = struct {
    /// The owned connection. Embedders may write to streams, call
    /// `sendDatagram`, or read events on this directly.
    conn: *Connection,
    /// The DCID the client picked on its very first Initial. Held
    /// in addition to `tracked_cids` because the peer may keep using
    /// it for several flights before switching to a server-issued
    /// SCID, and the router needs to recognize it from the very
    /// first datagram before `Connection.localScids` has populated.
    initial_dcid: ConnectionId,
    /// CIDs currently registered in `Server.cid_table` for this
    /// slot. Bounded — a slot's working set never exceeds the peer's
    /// `active_connection_id_limit` plus a small in-flight margin.
    /// Slots 0..tracked_cid_count are valid.
    tracked_cids: [max_tracked_cids_per_slot]ConnectionId = @splat(.{}),
    tracked_cid_count: u8 = 0,
    /// Source address most recently observed for this slot, or null
    /// if the embedder didn't pass one. Used as a routing hint for
    /// the rate limiter on connection close.
    peer_addr: ?Address = null,
    /// Last time `feed` saw any datagram for this slot. Embedders
    /// can use this to enforce idle timeouts beyond what QUIC's own
    /// idle timer covers.
    last_activity_us: u64 = 0,
};

/// Outcome of feeding a single datagram to the server. Re-exported
/// as `Server.FeedOutcome`. The variants distinguish reasons an
/// embedder might want to alert on (`rate_limited`, `table_full`)
/// from the generic drop bucket (`dropped`).
const FeedOutcomeImpl = enum {
    /// The datagram was routed to an existing connection and
    /// processed.
    routed,
    /// The datagram opened a brand-new connection. The newly created
    /// `Slot` is at the back of `Server.slots`.
    accepted,
    /// Generic drop — empty datagram, unroutable bytes that aren't
    /// an Initial, or `openSlotFromInitial` failed (malformed
    /// header, TLS hiccup). Silently dropped per RFC 9000 §10.3.
    dropped,
    /// Per-source rate limiter rejected this Initial; the source's
    /// recent budget is exhausted within the configured window.
    /// Embedders should treat a sustained stream of these from the
    /// same source as DoS-flood evidence.
    rate_limited,
    /// `max_concurrent_connections` reached. The slot table is
    /// full; new Initials are dropped until existing slots are
    /// reaped.
    table_full,
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

/// I/O-agnostic QUIC server. Owns the TLS context, the connection
/// table, and the CID-to-slot routing table. The embedder owns the
/// UDP socket and the clock.
///
/// Lifecycle:
///   1. `init` builds the TLS context and pre-allocates the slot +
///      routing tables.
///   2. The embedder repeatedly calls `feed(bytes, from, now_us)`
///      on every received datagram, then calls `poll(out_buf,
///      now_us)` in a loop on every live slot to drain queued
///      packets.
///   3. `tick(now_us)` drives time-based recovery. Embedders should
///      call it on every loop iteration regardless of I/O.
///   4. `reap()` reclaims closed slots periodically.
///   5. `shutdown` queues `CONNECTION_CLOSE` on every live slot;
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

    /// Routing table: every CID currently valid as a DCID for some
    /// slot maps to that slot. Updated on `openSlotFromInitial`,
    /// after every `feed` (resync), and on `reap`.
    cid_table: std.AutoHashMapUnmanaged(CidKey, *Slot) = .empty,

    /// Rate limiter state. Empty when the limiter is disabled.
    source_rate_table: std.AutoHashMapUnmanaged(Address, SourceRateEntry) = .empty,
    max_initials_per_source: ?u32,
    source_rate_window_us: u64,
    source_rate_table_capacity: u32,

    /// Random source used to mint server SCIDs. Embedders that need
    /// deterministic CIDs (interop fixtures, fuzzers) can swap this.
    random: std.Random,
    rng_state: std.Random.DefaultPrng,

    pub fn init(config: Config) Error!Server {
        if (config.alpn_protocols.len == 0) return Error.InvalidConfig;
        if (config.local_cid_len == 0 or config.local_cid_len > 20) return Error.InvalidConfig;
        if (config.tls_cert_pem.len == 0 or config.tls_key_pem.len == 0) return Error.InvalidConfig;
        if (config.max_initials_per_source_per_window) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_window_us == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }

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

        // Pre-size the CID table to roughly initial-slots * average
        // CIDs per slot; saves rehash churn on the first hundred
        // connections without committing pages we don't need.
        var cid_table: std.AutoHashMapUnmanaged(CidKey, *Slot) = .empty;
        cid_table.ensureTotalCapacity(config.allocator, @intCast(slots_initial_capacity * 2)) catch |e| switch (e) {
            error.OutOfMemory => {
                slots.deinit(config.allocator);
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
            .cid_table = cid_table,
            .source_rate_table = .empty,
            .max_initials_per_source = config.max_initials_per_source_per_window,
            .source_rate_window_us = config.source_rate_window_us,
            .source_rate_table_capacity = config.source_rate_table_capacity,
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
        self.cid_table.deinit(self.allocator);
        self.source_rate_table.deinit(self.allocator);
        if (self.owns_tls) self.tls_ctx.deinit();
        self.* = undefined;
    }

    /// Number of live connections currently in the table.
    pub fn connectionCount(self: *const Server) usize {
        return self.slots.items.len;
    }

    /// Number of CIDs currently registered as routing keys across
    /// all live slots. Useful for tests and metrics; production
    /// embedders rarely need this.
    pub fn routingTableSize(self: *const Server) usize {
        return self.cid_table.count();
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

        // Existing connection? Hash table lookup, O(1).
        if (self.findSlotForDatagram(bytes)) |slot| {
            slot.last_activity_us = now_us;
            if (from) |addr| slot.peer_addr = addr;
            self.dispatchToSlot(slot, bytes, from, now_us);
            try self.resyncSlotCids(slot);
            return .routed;
        }

        // New connection candidate: must be a long-header Initial.
        if (!isInitialLongHeader(bytes)) return .dropped;
        if (self.slots.items.len >= self.max_concurrent_connections) return .table_full;

        // Source-rate gate runs *before* TLS / Connection setup so
        // an attacker spraying Initials from one address can't burn
        // server CPU minting state we'll throw away.
        if (self.max_initials_per_source) |cap| {
            if (from) |addr| {
                if (!self.acceptSourceRate(addr, cap, now_us)) return .rate_limited;
            }
        }

        const slot = self.openSlotFromInitial(bytes, from, now_us) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            // Anything else (TLS init, malformed Initial, Connection
            // setup) is a per-peer hiccup — drop the datagram and
            // keep the server alive. The slot was never registered,
            // so cid_table stays clean.
            else => return .dropped,
        };
        self.dispatchToSlot(slot, bytes, from, now_us);
        try self.resyncSlotCids(slot);
        return .accepted;
    }

    /// Poll one outgoing datagram for `slot` into `dst`. Returns the
    /// number of bytes written, or null if nothing is queued. Thin
    /// wrapper around `Connection.poll` — embedders that need the
    /// full path-aware `OutgoingDatagram` should call
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
    /// cheap — call it on every loop iteration. Closed slots are
    /// skipped; call `reap` periodically to reclaim them.
    pub fn tick(self: *Server, now_us: u64) Connection.Error!void {
        for (self.slots.items) |slot| {
            if (slot.conn.isClosed()) continue;
            try slot.conn.tick(now_us);
        }
    }

    /// Reap any closed slots from the table. Returns the number of
    /// slots reclaimed. Iterates back-to-front and uses
    /// `swapRemove`, so reaping N closed slots is O(N), not O(N²).
    /// Each reaped slot drops every CID it owned from `cid_table`.
    pub fn reap(self: *Server) usize {
        var reaped: usize = 0;
        var i: usize = self.slots.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.slots.items[i];
            if (!slot.conn.isClosed()) continue;
            self.dropAllCidsFromTable(slot);
            slot.conn.deinit();
            self.allocator.destroy(slot.conn);
            self.allocator.destroy(slot);
            _ = self.slots.swapRemove(i);
            reaped += 1;
        }
        return reaped;
    }

    /// Queue `CONNECTION_CLOSE` on every live slot. Embedders should
    /// keep polling and ticking until each slot becomes `.closed`,
    /// then call `reap` to reclaim memory.
    pub fn shutdown(self: *Server, error_code: u64, reason: []const u8) void {
        for (self.slots.items) |slot| {
            slot.conn.close(true, error_code, reason);
        }
    }

    // -- internals ------------------------------------------------------

    fn findSlotForDatagram(self: *Server, bytes: []const u8) ?*Slot {
        const dcid = peekDcidForServer(bytes, self.local_cid_len) orelse return null;
        const key = cidKeyFromSlice(dcid);
        return self.cid_table.get(key);
    }

    fn openSlotFromInitial(
        self: *Server,
        bytes: []const u8,
        from: ?Address,
        now_us: u64,
    ) !*Slot {
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
            .peer_addr = from,
            .last_activity_us = now_us,
        };

        // Reserve a slot in the CID table for the initial DCID. If
        // this fails, the slot was never made visible to the router
        // and the deferred errdefer will tear down the Connection.
        try self.cid_table.put(self.allocator, cidKeyFromConnectionId(original_dcid), slot);
        errdefer _ = self.cid_table.remove(cidKeyFromConnectionId(original_dcid));

        try self.slots.append(self.allocator, slot);
        return slot;
    }

    fn dispatchToSlot(
        self: *Server,
        slot: *Slot,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) void {
        _ = self;
        slot.conn.handle(bytes, from, now_us) catch {
            // Per-connection error: don't tear down the server. The
            // connection itself transitions to .closed and the
            // embedder will reap it on the next `reap()` call.
        };
    }

    /// Diff the slot's currently-tracked CIDs against the
    /// connection's authoritative `localScids` list and patch
    /// `cid_table` accordingly. Called after every `feed` so that
    /// an SCID issued during this datagram (NEW_CONNECTION_ID) is
    /// routable from the *next* datagram on, and a retired SCID
    /// (RETIRE_CONNECTION_ID consumed during this datagram) stops
    /// accepting traffic.
    ///
    /// Algorithm: O(K + L) where K = current local SCID count and
    /// L = previously-tracked CID count. Both are bounded by
    /// `max_tracked_cids_per_slot`; in practice K ≈ L ≈ peer's
    /// `active_connection_id_limit` (default 8).
    fn resyncSlotCids(self: *Server, slot: *Slot) Error!void {
        var snapshot_buf: [max_tracked_cids_per_slot]ConnectionId = undefined;
        const total = slot.conn.localScidCount();
        // If the connection has issued more SCIDs than our slot's
        // bounded array can track, take the first `max` and call it
        // a TODO: nullq's default limits keep this well under 16,
        // and a runtime overflow would be a real configuration
        // problem worth surfacing.
        const n = slot.conn.localScids(snapshot_buf[0..@min(total, max_tracked_cids_per_slot)]);
        const snapshot = snapshot_buf[0..n];

        // Drop tracked CIDs that are no longer in the connection's
        // active set. `tracked_cids` is small and the inner loop is
        // a byte compare, so the nominal O(K*L) is fine.
        var i: usize = 0;
        while (i < slot.tracked_cid_count) {
            const tracked = slot.tracked_cids[i];
            if (!containsConnectionId(snapshot, tracked)) {
                _ = self.cid_table.remove(cidKeyFromConnectionId(tracked));
                // Swap-remove to keep the bookkeeping O(1).
                slot.tracked_cid_count -= 1;
                slot.tracked_cids[i] = slot.tracked_cids[slot.tracked_cid_count];
                continue;
            }
            i += 1;
        }

        // Add CIDs that the connection now owns but the table
        // doesn't yet route. Skip the initial DCID — that one is
        // peer-chosen, never returned by `localScids`, and it stays
        // pinned for the lifetime of the slot.
        for (snapshot) |cid| {
            if (containsConnectionId(slot.tracked_cids[0..slot.tracked_cid_count], cid)) continue;
            const gop = try self.cid_table.getOrPut(self.allocator, cidKeyFromConnectionId(cid));
            gop.value_ptr.* = slot;
            // invariant: snapshot ≤ max_tracked_cids_per_slot, so
            // we always have room.
            std.debug.assert(slot.tracked_cid_count < max_tracked_cids_per_slot);
            slot.tracked_cids[slot.tracked_cid_count] = cid;
            slot.tracked_cid_count += 1;
        }
    }

    /// Remove every routing entry owned by `slot` from `cid_table`.
    /// Called from `reap` after the slot is observed `.closed`.
    fn dropAllCidsFromTable(self: *Server, slot: *Slot) void {
        _ = self.cid_table.remove(cidKeyFromConnectionId(slot.initial_dcid));
        for (slot.tracked_cids[0..slot.tracked_cid_count]) |cid| {
            _ = self.cid_table.remove(cidKeyFromConnectionId(cid));
        }
        slot.tracked_cid_count = 0;
    }

    /// Token-bucket gate for per-source Initial acceptance. Returns
    /// true if `addr` is under its cap and the caller may proceed
    /// with slot creation; in that case, the source's count is
    /// incremented. Returns false if the cap is exceeded — caller
    /// should drop the datagram.
    ///
    /// The window is sliding-by-reset: when an entry's
    /// `window_start_us` is older than `source_rate_window_us`, the
    /// count resets. This is cheaper than a true sliding window and
    /// good enough for DoS-deflecting purposes; it allows up to 2x
    /// the cap across two adjacent windows in pathological timing.
    fn acceptSourceRate(
        self: *Server,
        addr: Address,
        cap: u32,
        now_us: u64,
    ) bool {
        // Lazy eviction when the table is at capacity. Pruning
        // every call is wasteful; only pay the O(table) cost when
        // we're about to add an entry that would overflow.
        if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
            self.pruneSourceRate(now_us);
            // If pruning didn't make room, drop the most stale
            // entry to guarantee progress.
            if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
                self.evictOldestSourceRate();
            }
        }

        const gop = self.source_rate_table.getOrPut(self.allocator, addr) catch {
            // OOM on the rate table is a cheap soft fail: deny the
            // accept rather than continue without protection.
            return false;
        };
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .count = 1, .window_start_us = now_us };
            return true;
        }

        const elapsed = now_us -% gop.value_ptr.window_start_us;
        if (elapsed >= self.source_rate_window_us) {
            gop.value_ptr.* = .{ .count = 1, .window_start_us = now_us };
            return true;
        }

        if (gop.value_ptr.count >= cap) return false;
        gop.value_ptr.count += 1;
        return true;
    }

    fn pruneSourceRate(self: *Server, now_us: u64) void {
        var it = self.source_rate_table.iterator();
        while (it.next()) |entry| {
            const elapsed = now_us -% entry.value_ptr.window_start_us;
            if (elapsed >= self.source_rate_window_us) {
                _ = self.source_rate_table.remove(entry.key_ptr.*);
            }
        }
    }

    fn evictOldestSourceRate(self: *Server) void {
        var it = self.source_rate_table.iterator();
        var oldest_addr: ?Address = null;
        var oldest_start: u64 = std.math.maxInt(u64);
        while (it.next()) |entry| {
            if (entry.value_ptr.window_start_us < oldest_start) {
                oldest_start = entry.value_ptr.window_start_us;
                oldest_addr = entry.key_ptr.*;
            }
        }
        if (oldest_addr) |addr| _ = self.source_rate_table.remove(addr);
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

fn containsConnectionId(haystack: []const ConnectionId, needle: ConnectionId) bool {
    for (haystack) |cid| {
        if (ConnectionId.eql(cid, needle)) return true;
    }
    return false;
}

// -- tests --------------------------------------------------------------
//
// The init/feed end-to-end smoke test lives in
// `tests/e2e/server_smoke.zig` because it needs real cert/key PEMs
// from `tests/data`, which sit outside this package's import path.
// The tests below only exercise pure helpers and config validation —
// neither needs a TLS context.

test "Server.init validates configuration" {
    const protos = [_][]const u8{"hq-test"};

    // Empty cert/key.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "",
        .tls_key_pem = "",
        .alpn_protocols = &protos,
        .transport_params = .{},
    }));

    // No ALPN.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &.{},
        .transport_params = .{},
    }));

    // local_cid_len=0.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .local_cid_len = 0,
        .transport_params = .{},
    }));

    // local_cid_len > 20.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .local_cid_len = 21,
        .transport_params = .{},
    }));

    // Source rate limiter enabled with cap=0.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .max_initials_per_source_per_window = 0,
        .transport_params = .{},
    }));

    // Source rate limiter enabled with window=0.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .max_initials_per_source_per_window = 32,
        .source_rate_window_us = 0,
        .transport_params = .{},
    }));
}

test "peekLongHeaderIds rejects too-short" {
    try std.testing.expect(peekLongHeaderIds(&.{}) == null);
    try std.testing.expect(peekLongHeaderIds(&.{0xc0}) == null);
}

test "isInitialLongHeader recognizes Initial type bits" {
    // Long header, type=0 (Initial), version=1.
    const bytes = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&bytes));

    // Version negotiation (version=0) is *not* an Initial.
    const vn = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&vn));

    // Short header.
    const sh = [_]u8{ 0x40, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&sh));
}

test "cidKey round-trips identical CIDs" {
    const a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const b = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const c = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 9 };
    const d = [_]u8{ 1, 2, 3, 4, 5, 6, 7 }; // different length

    try std.testing.expectEqual(cidKeyFromSlice(&a), cidKeyFromSlice(&b));
    try std.testing.expect(!std.mem.eql(u8, &cidKeyFromSlice(&a), &cidKeyFromSlice(&c)));
    try std.testing.expect(!std.mem.eql(u8, &cidKeyFromSlice(&a), &cidKeyFromSlice(&d)));
}
