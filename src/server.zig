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
//! Three opt-in gates harden Initial-driven slot creation; each is
//! null in `Config` by default and surfaces a distinct
//! `FeedOutcome` variant when it fires.
//!
//! 1. `Config.max_initials_per_source_per_window` enables a
//!    per-source-address token bucket. When the cap is exceeded,
//!    fresh Initials from that source are dropped without state, so
//!    an attacker spraying Initials from a single address cannot
//!    exhaust the slot table or the TLS context.
//! 2. `Config.retry_token_key` enables stateless Retry-based source
//!    validation (RFC 9000 §8.1.2). The first Initial from a peer
//!    earns a Retry packet bound to its address; until the peer
//!    echoes a valid token in a follow-up Initial, no `Connection`
//!    is allocated. Set this to gate the 3x amplification window
//!    behind a proof-of-address round trip.
//! 3. Long-header packets carrying any version other than
//!    `nullq.QUIC_VERSION_1` always trigger a Version Negotiation
//!    response (RFC 9000 §6 / RFC 8999 §6); this is unconditional
//!    and requires no `Config` opt-in.
//!
//! Stateless responses (Retry, Version Negotiation) are queued on
//! the `Server` and surfaced via `drainStatelessResponse`. The
//! embedder's I/O loop polls for these in addition to per-slot
//! `poll` output and forwards them on the same UDP socket. The
//! queue is bounded — when full, the oldest queued response is
//! dropped to keep ingest latency bounded.
//!
//! All three gates require an embedder-supplied `from` address
//! when calling `feed`. When `from` is null (the embedder didn't
//! capture the peer 4-tuple), the gates degrade to pass-through:
//! the rate limiter does not track the source, no Retry is
//! attempted, and a Version Negotiation response cannot be queued
//! because there is no destination to send it to (the datagram is
//! `dropped` instead). Passing `from` is strongly recommended for
//! any internet-facing deployment.
//!
//! For a hand-rolled loop, see the README. Embedders that just want
//! "bind a socket and serve QUIC" should reach for
//! `nullq.transport.runUdpServer` instead — it owns the
//! `std.Io`-based bind / tune / receive / feed / poll / tick / reap
//! cadence. The QNS endpoint at `interop/qns_endpoint.zig` keeps its
//! own bespoke loop because it has interop-specific quirks
//! (deterministic CID prefix, per-testcase wiring); general-purpose
//! embedders should reach for `Server` (server side) or
//! `nullq.Client` (client side) first.

const std = @import("std");
const boringssl = @import("boringssl");

const conn_mod = @import("conn/root.zig");
const tls_mod = @import("tls/root.zig");
const wire = @import("wire/root.zig");
const retry_token_mod = conn_mod.retry_token;
const lifecycle = conn_mod.lifecycle;

const Connection = conn_mod.Connection;
const ConnectionError = conn_mod.state.Error;
const TransportParams = tls_mod.TransportParams;
const ConnectionId = conn_mod.path.ConnectionId;
const Address = conn_mod.path.Address;
const QlogCallback = conn_mod.QlogCallback;
const RetryTokenKey = conn_mod.RetryTokenKey;
const QUIC_VERSION_1: u32 = 0x00000001;

/// Maximum byte size of a single queued stateless response (Version
/// Negotiation or Retry). Both packet types fit comfortably inside
/// this bound: VN is ~16 bytes plus 4 bytes per advertised version
/// (max 16), and Retry is ~32 bytes plus the token (53 bytes).
const max_stateless_response_bytes: usize = 256;

/// Bound on the stateless-response queue. Reached only when the
/// embedder is feeding faster than they drain; on overflow the
/// oldest VN entry is evicted in preference to any Retry entry, so
/// a flood of unsupported-version probes cannot crowd out Retry
/// responses to legitimate v1 peers. If the queue is full of
/// Retry entries (no VN to evict), the oldest Retry is dropped.
const stateless_response_queue_capacity: usize = 64;

/// What kind of stateless response this entry carries. Used by the
/// queue's overflow eviction policy to prefer dropping VN over
/// Retry when both are queued, since VN traffic is cheaper for
/// peers to retry than Retry round-trips.
pub const StatelessResponseKind = enum {
    version_negotiation,
    retry,
};

/// Structured observability events emitted by the `Server` at
/// well-defined choice points. Embedders install a `LogCallback` via
/// `Config.log_callback` to forward these to their logger of choice;
/// the server emits them synchronously and never holds any internal
/// lock while the callback runs. Re-exported as `Server.LogEvent`.
///
/// The variants are intentionally narrow — one struct per choice
/// point — so the embedder can pattern-match on the discriminator and
/// pick out only the fields they care about. Adding a new variant is
/// a non-breaking change at the source level (existing callers'
/// `else =>` arms still type-check) but is a wire/behavior change for
/// any embedder logging the variants verbatim, so each addition
/// should land in a CHANGELOG entry.
const LogEventImpl = union(enum) {
    /// A new connection slot was opened from an Initial datagram. The
    /// `slot_count` field is the live-slot count *after* this accept,
    /// which embedders can use to alert on saturation.
    connection_accepted: struct { peer: Address, slot_count: usize },
    /// A previously-live slot was reaped. `peer` is the last source
    /// address observed for that slot (or null if the embedder never
    /// passed `from` on `feed`); `source` is the close reason from
    /// the connection's sticky `closeEvent` (or null for slots torn
    /// down before they ever transitioned through the close pipeline).
    connection_closed: struct { peer: ?Address, source: ?lifecycle.CloseSource },
    /// The per-source rate limiter rejected an Initial. `recent_count`
    /// is the source's tally inside the current window at the moment
    /// of rejection, surfaced so embedders can tune
    /// `max_initials_per_source_per_window`.
    feed_rate_limited: struct { peer: Address, recent_count: u32 },
    /// A Retry packet was successfully minted and queued for `peer`.
    /// `scid_len` is the length of the server-issued SCID embedded in
    /// the Retry — currently always equal to `Config.local_cid_len`.
    retry_minted: struct { peer: Address, scid_len: u8 },
    /// A long-header packet declared an unsupported version and a
    /// Version Negotiation response was queued. `requested_version` is
    /// the version field the peer asked for; embedders can correlate
    /// this with their version-deployment posture.
    version_negotiated: struct { peer: Address, requested_version: u32 },
    /// The bounded stateless-response queue was full when a fresh
    /// response (VN or Retry) arrived; the indicated entry was
    /// evicted to make room. `kind` is the kind of the *evicted*
    /// entry, not the new one.
    stateless_queue_evicted: struct { kind: StatelessResponseKind },
    /// `feed` rejected an Initial because the slot table was at
    /// `max_concurrent_connections`. `peer` is the source address (or
    /// null when the embedder didn't pass `from`).
    table_full: struct { peer: ?Address },
};

/// Embedder-supplied logging hook. The `user_data` pointer is the
/// `Config.log_user_data` the server stashed at init time and is
/// passed back verbatim. Re-exported as `Server.LogCallback`.
///
/// The callback is invoked synchronously from inside `feed` / `reap` /
/// `queueStatelessResponse` and must not call back into the server it
/// was registered with (no `feed`, no `drainStatelessResponse`,
/// nothing else that mutates server state). Returning an error is not
/// supported — the callback's job is to push the event into a buffer,
/// log line, or counter and return.
const LogCallbackImpl = *const fn (user_data: ?*anyopaque, ev: LogEventImpl) void;

/// By-value snapshot of the server's instrumentation counters and
/// gauges. Returned from `Server.metricsSnapshot`; the snapshot is
/// taken atomically (no mutation between fields) because all reads
/// run on the embedder's thread. Re-exported as
/// `Server.MetricsSnapshot`.
///
/// Fields divide into two groups:
///   * Gauges describe *current* state — table sizes, queue depth,
///     the post-init high-water mark for the stateless queue.
///   * Counters monotonically increase from `init` to `deinit` and
///     cover every lifecycle event the embedder might want to chart.
///
/// Counters wrap at `u64` overflow, which is decades of traffic on
/// any realistic deployment. The embedder is responsible for
/// computing per-second rates if they want a flow chart.
const MetricsSnapshotImpl = struct {
    // Gauges (current state).
    /// Current number of live connection slots. Mirrors
    /// `Server.connectionCount`.
    live_connections: u64,
    /// Current number of routing CIDs across all live slots. Mirrors
    /// `Server.routingTableSize`.
    routing_table_size: u64,
    /// Number of distinct sources the rate limiter currently tracks.
    /// Zero when the limiter is disabled.
    source_rate_table_size: u64,
    /// Number of distinct peers with Retry-pending state. Zero when
    /// Retry is disabled.
    retry_state_table_size: u64,
    /// Current depth of the stateless-response (VN/Retry) queue.
    /// Mirrors `Server.statelessResponseCount`.
    stateless_queue_depth: u64,
    /// All-time maximum value of `stateless_queue_depth` since
    /// `init`. Sticky — it does not decrease when the queue drains.
    /// Useful for sizing the queue capacity for production load.
    stateless_queue_high_water: u64,

    // Counters (monotonic since init).
    /// Datagrams routed to an existing slot.
    feeds_routed: u64,
    /// Initials that opened a new slot (`.accepted`).
    feeds_accepted: u64,
    /// Datagrams rejected with `.dropped` for any reason — empty,
    /// malformed, slot creation failed, expired token, etc.
    feeds_dropped: u64,
    /// Initials rejected by the per-source rate limiter
    /// (`.rate_limited`).
    feeds_rate_limited: u64,
    /// Initials rejected because `max_concurrent_connections` was
    /// reached (`.table_full`).
    feeds_table_full: u64,
    /// Long-header packets that triggered a Version Negotiation
    /// response (`.version_negotiated`).
    feeds_version_negotiated: u64,
    /// Initials that triggered a Retry packet (`.retry_sent`).
    feeds_retry_sent: u64,
    /// Echoed Retry tokens that successfully validated and led to a
    /// post-Retry `.accepted`. Always less than or equal to
    /// `feeds_retry_sent`.
    retries_validated: u64,
    /// Stateless responses dropped on queue overflow.
    stateless_responses_evicted: u64,
    /// Slots reclaimed by `reap()` (one per closed connection).
    slots_reaped: u64,
};

/// By-value snapshot of the per-source rate limiter, ranked by
/// recent activity. Returned from `Server.rateLimitSnapshot`; the
/// top-N list is sorted in descending order by `recent_count`. When
/// the rate limiter is disabled, the snapshot is all-zero.
/// Re-exported as `Server.RateLimitSnapshot`.
const RateLimitSnapshotImpl = struct {
    /// One row in the top-N table.
    pub const SourceRow = struct {
        addr: Address,
        recent_count: u32,
        window_start_us: u64,
    };

    /// Maximum number of top-offender rows the snapshot returns.
    pub const top_n: usize = 16;

    /// Total number of distinct sources currently tracked. May be
    /// larger than `top_offender_count` when the table holds more
    /// than `top_n` sources.
    table_size: usize,
    /// Cumulative count of `.rate_limited` returns since `init`.
    /// Mirrors `MetricsSnapshot.feeds_rate_limited`.
    cumulative_rejections: u64,
    /// Top offenders, sorted descending by `recent_count`. Slots
    /// past `top_offender_count` are zero-initialized and should be
    /// ignored.
    top_offenders: [top_n]SourceRow,
    /// Number of valid rows in `top_offenders`.
    top_offender_count: usize,
};

/// One queued stateless server response (VN or Retry), held by
/// value so the embedder can drain across multiple `feed` calls.
/// Re-exported as `Server.StatelessResponse`.
const StatelessResponseImpl = struct {
    /// Where to send the response. Always set — `feed` only queues
    /// stateless responses when `from` is non-null because there is
    /// no destination to send to otherwise.
    dst: Address,
    /// Length of the valid bytes prefix in `bytes`.
    len: usize,
    /// Whether this is a Version Negotiation or Retry response.
    /// Drives queue-overflow eviction policy.
    kind: StatelessResponseKind = .version_negotiation,
    bytes: [max_stateless_response_bytes]u8 = @splat(0),

    /// Borrowed view of the encoded packet. Valid until the next
    /// `drainStatelessResponse` call returns this entry by value.
    pub fn slice(self: *const StatelessResponseImpl) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Per-source Retry bookkeeping. Created when the server queues a
/// Retry packet for a source; consulted on the next Initial from
/// that source to decide whether to validate the echoed token or
/// re-send Retry. Bound on the table size mirrors the rate-limit
/// table so a flood of distinct addresses cannot grow this
/// unbounded.
const RetryStateEntry = struct {
    /// Server-issued SCID embedded in the Retry packet — the peer
    /// must echo this DCID in subsequent Initials and the token
    /// HMAC binds it.
    retry_scid: [20]u8 = @splat(0),
    retry_scid_len: u8 = 0,
    /// The DCID from the client's first Initial — the
    /// `original_destination_connection_id` transport parameter
    /// must reflect this on the post-Retry connection.
    original_dcid: ConnectionId = .{},
    /// Wall-clock microseconds when the Retry was minted; used to
    /// evict stale entries on overflow.
    minted_at_us: u64 = 0,
};

/// Maximum number of routing CIDs a slot tracks at once. Bounded
/// by the peer's `active_connection_id_limit` (default 8 in nullq);
/// 32 leaves headroom for embedders that lift the limit and for
/// in-flight retires, while keeping the router a fixed, alloc-free
/// slot footprint. If a `Connection` ever issues more than this
/// many active SCIDs, `resyncSlotCids` asserts in debug builds and
/// truncates in release — bump this constant if you bump
/// `active_connection_id_limit` toward 32 or beyond.
const max_tracked_cids_per_slot: usize = 32;

/// Length-prefixed packed CID key used as the `cid_table` HashMap
/// key. Byte 0 is the CID length (1..20); bytes 1..1+len are the
/// CID material; bytes past `len` are zeroed so the key compares
/// by value.
const CidKey = [21]u8;

fn cidKeyFromSlice(cid: []const u8) CidKey {
    // Defensive: callers (peekDcidForServer, ConnectionId.slice, etc.)
    // already bound CID length to ≤ 20 via header parse and config
    // validation, but we clamp here so a future caller that forgets
    // can't reach a buffer overflow on a peer-controlled length.
    const n = @min(cid.len, 20);
    var k: CidKey = @splat(0);
    k[0] = @intCast(n);
    @memcpy(k[1 .. 1 + n], cid[0..n]);
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

    /// Optional structured-logging hook. When set, the server emits
    /// a `LogEvent` at every observable choice point (connection
    /// open / close / reaped, rate-limited Initial, Retry minted,
    /// VN response, queue eviction, table-full rejection). The
    /// callback runs synchronously on the embedder's thread inside
    /// `feed` / `reap` and must not call back into the server.
    log_callback: ?LogCallbackImpl = null,
    /// Opaque pointer passed back to `log_callback` on every event.
    log_user_data: ?*anyopaque = null,

    /// Optional override of the underlying `boringssl.tls.Context`.
    /// When null, `Server.init` constructs a TLS-1.3-only server
    /// context with `verify=.none` and the supplied ALPN list. The
    /// auto-built context's early-data posture is gated by
    /// `Config.enable_0rtt` (off by default; §5.2 / §12 hardening).
    /// Pass your own to enable session-ticket callbacks or any other
    /// TLS-context behavior the auto-built path doesn't expose.
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

    /// 32-byte HMAC key used to mint and validate stateless Retry
    /// tokens (RFC 9000 §8.1.2). When null, Retry is disabled and
    /// every well-formed Initial is accepted directly. When set,
    /// the first Initial from a peer is answered with a Retry
    /// packet; the connection is only allocated once the peer
    /// echoes back a valid token in a follow-up Initial.
    ///
    /// The key must be stable across the token lifetime so a Retry
    /// minted on one packet can be validated on the next. Embedders
    /// fronting multiple servers behind a load balancer should
    /// share one key across the pool.
    retry_token_key: ?RetryTokenKey = null,
    /// Lifetime of a minted Retry token in microseconds. Tokens
    /// older than this validate as `expired` and are dropped.
    /// Default is 10 seconds — the QNS-recommended ceiling, large
    /// enough to absorb a slow-handshake client and small enough
    /// that a stolen token expires before it can be replayed.
    retry_token_lifetime_us: u64 = 10_000_000,
    /// Maximum number of distinct source addresses for which the
    /// server holds Retry-pending state at once. Excess sources
    /// evict the oldest entry. Only consulted when
    /// `retry_token_key` is non-null.
    retry_state_table_capacity: u32 = 4096,

    /// Enable QUIC 0-RTT (early data) on the auto-built TLS context.
    /// Off by default to satisfy the §5.2 / §12 hardening posture:
    /// 0-RTT is replayable and unsuitable for state-changing requests
    /// without an application-level anti-replay mechanism (RFC 9001
    /// §5.6 / RFC 8446 §8). Embedders that want 0-RTT must opt in
    /// here AND set a per-connection allow via
    /// `Connection.setEarlyDataEnabled(true)` after installing the
    /// 0-RTT replay context.
    ///
    /// Only consulted when `tls_context_override` is null. Embedders
    /// supplying their own `boringssl.tls.Context` are responsible for
    /// configuring its early-data posture themselves.
    enable_0rtt: bool = false,
};

/// Argument to `Server.replaceTlsContext`. Either fresh PEM bytes
/// (the server rebuilds an internally-owned context with the same
/// shape `Server.init` produces) or a caller-built context the
/// embedder hands over wholesale. Re-exported as `Server.TlsReload`.
const TlsReloadImpl = union(enum) {
    /// Rebuild a fresh server context from PEM-encoded cert chain
    /// and private key. The new context is configured identically to
    /// `Server.init`'s default path: TLS-1.3 only, `verify=.none`,
    /// the server's currently-cached ALPN list, and the early-data
    /// posture the Server was originally initialized with via
    /// `Config.enable_0rtt`. The Server takes ownership of the
    /// resulting context and `deinit`s it (after refcounted draining)
    /// on `Server.deinit` or on a subsequent `replaceTlsContext`.
    pem: struct {
        /// PEM-encoded certificate chain (leaf first, then any
        /// intermediates). Must outlive only this call — the new
        /// `boringssl.tls.Context` parses the bytes during construction
        /// and copies what it needs.
        cert_pem: []const u8,
        /// PEM-encoded private key matching the leaf in `cert_pem`.
        /// Same lifetime constraint as `cert_pem`.
        key_pem: []const u8,
    },
    /// A caller-built context the Server should adopt as the new
    /// current context. Use this to wire up bespoke options the
    /// `pem` variant doesn't expose (custom verify modes, session
    /// ticket callbacks, ALPN protocols different from the
    /// init-time list, etc.). The Server takes ownership and will
    /// `deinit` the override when it eventually drains.
    override: boringssl.tls.Context,
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
    /// Server-local monotonic id assigned at slot creation. Stable
    /// for the slot's lifetime; embedders can use this as the
    /// primary key in operational logs and trace correlation
    /// without depending on peer-chosen CIDs.
    slot_id: u64,
    /// W3C traceparent trace-id (16 bytes), or null if the embedder
    /// has not associated a trace with this slot. Embedders set via
    /// `setTraceContext`; nullq itself never reads it.
    trace_id: ?[16]u8 = null,
    /// W3C traceparent parent-span-id (8 bytes), or null.
    parent_span_id: ?[8]u8 = null,
    /// TLS-context generation this slot was opened against. Set to
    /// `Server.current_generation` at `openSlotFromInitial` time and
    /// never mutated afterward. Drives draining-context refcount
    /// bookkeeping in `Server.reap`: when a slot is reaped, its
    /// generation tells us which draining context (if any) loses a
    /// reference.
    tls_generation: u32 = 0,

    /// Attach a W3C tracecontext to this slot. Embedders typically
    /// call this after `Server.feed` returns `.accepted` and the
    /// upstream service has assigned trace identifiers. nullq does
    /// not interpret these bytes — they are pure metadata for
    /// embedder-side correlation.
    pub fn setTraceContext(
        self: *SlotImpl,
        trace_id: [16]u8,
        parent_span_id: [8]u8,
    ) void {
        self.trace_id = trace_id;
        self.parent_span_id = parent_span_id;
    }
};

/// Bookkeeping for one TLS context that has been swapped out by
/// `Server.replaceTlsContext` but still has live slots referencing it
/// via per-connection SSL handles. The entry is `deinit`-ed and
/// dropped when `refcount` hits zero on reap.
const DrainingTlsEntry = struct {
    /// The swapped-out context. Owned — `refcount==0` deinit calls
    /// `Context.deinit` on this. Per-connection SSL handles created
    /// against this context already hold their own up-ref via
    /// `SSL_new`, so deiniting here only drops the Server's reference;
    /// the underlying SSL_CTX stays alive until every per-connection
    /// SSL handle is freed.
    ctx: boringssl.tls.Context,
    /// Generation tag. Slots opened against this context recorded the
    /// same value in their `tls_generation` field; reap matches on it.
    generation: u32,
    /// Number of live slots still associated with this context. Set
    /// at swap-time (= count of pre-swap slots whose generation was
    /// `current_generation`); decremented in `reap` when one of those
    /// slots is reclaimed.
    refcount: usize,
};

/// Outcome of feeding a single datagram to the server. Re-exported
/// as `Server.FeedOutcome`. The variants distinguish reasons an
/// embedder might want to alert on (`rate_limited`, `table_full`,
/// `version_negotiated`, `retry_sent`) from the generic drop bucket
/// (`dropped`).
const FeedOutcomeImpl = enum {
    /// The datagram was routed to an existing connection and
    /// processed.
    routed,
    /// The datagram opened a brand-new connection. The newly created
    /// `Slot` is at the back of `Server.slots`.
    accepted,
    /// Generic drop — empty datagram, unroutable bytes that aren't
    /// an Initial, malformed header, expired or invalid Retry token,
    /// or `openSlotFromInitial` failed (malformed header, TLS
    /// hiccup). Silently dropped per RFC 9000 §10.3.
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
    /// The datagram carried a long-header packet with a version
    /// other than `nullq.QUIC_VERSION_1`. A Version Negotiation
    /// response was queued for the embedder to drain via
    /// `drainStatelessResponse`. No `Connection` was created.
    /// RFC 9000 §6 / RFC 8999 §6.
    version_negotiated,
    /// `Config.retry_token_key` is set and this Initial either
    /// carried no token or carried one that is not the one we
    /// would have minted for this source. A fresh Retry packet was
    /// queued for the embedder to drain. RFC 9000 §8.1.2. No
    /// `Connection` was created — the peer must echo the Retry's
    /// SCID and token in a subsequent Initial to proceed.
    retry_sent,
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
    /// `Server.Slot`, `Server.FeedOutcome`, `Server.StatelessResponse`,
    /// `Server.TlsReload`, `Server.Error`, and the observability
    /// types all resolve from the public API surface. The top-level
    /// definitions remain authoritative.
    pub const Config = ConfigImpl;
    pub const Slot = SlotImpl;
    pub const FeedOutcome = FeedOutcomeImpl;
    pub const StatelessResponse = StatelessResponseImpl;
    pub const TlsReload = TlsReloadImpl;
    pub const Error = ErrorImpl;
    pub const LogEvent = LogEventImpl;
    pub const LogCallback = LogCallbackImpl;
    pub const MetricsSnapshot = MetricsSnapshotImpl;
    pub const RateLimitSnapshot = RateLimitSnapshotImpl;

    allocator: std.mem.Allocator,
    tls_ctx: boringssl.tls.Context,
    /// True if the TLS context was built by `Server.init` and must
    /// be torn down on `deinit`. False if the embedder supplied
    /// `tls_context_override`. `replaceTlsContext` updates this in
    /// step with the swap: a `.pem` reload produces an owned new
    /// context (`owns_tls = true`), an `.override` reload adopts the
    /// caller-supplied context as owned (`owns_tls = true`) — once
    /// the caller hands the context to the Server, the Server is
    /// responsible for the eventual `deinit`. The pre-swap context's
    /// owned/borrowed status is preserved by only moving it into
    /// `draining_tls_contexts` when it was previously owned.
    owns_tls: bool,
    /// Borrowed ALPN list captured from `Config.alpn_protocols` at
    /// `init` time. Used by `replaceTlsContext({.pem = ...})` to
    /// reconstruct the new context with the same ALPN preference
    /// order. Embedders that need to change the ALPN list across a
    /// reload must use the `.override` variant.
    alpn_protocols: []const []const u8,
    transport_params: TransportParams,
    max_concurrent_connections: u32,
    local_cid_len: u8,
    qlog_callback: ?QlogCallback,
    qlog_user_data: ?*anyopaque,
    log_callback: ?LogCallbackImpl,
    log_user_data: ?*anyopaque,

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

    /// Per-source Retry bookkeeping. Empty when Retry is disabled.
    /// One entry per peer that earned a Retry packet, dropped once
    /// the peer either successfully validates and a Slot opens
    /// (post-Retry SCID rotates into `cid_table`) or the entry is
    /// evicted on table overflow.
    retry_state_table: std.AutoHashMapUnmanaged(Address, RetryStateEntry) = .empty,
    retry_token_key: ?RetryTokenKey,
    retry_token_lifetime_us: u64,
    retry_state_table_capacity: u32,

    /// Captured `Config.enable_0rtt` from `init`. Drives the
    /// `early_data_enabled` knob on TLS contexts auto-built by
    /// `replaceTlsContext({.pem = ...})` so reloads preserve the
    /// original 0-RTT posture without forcing the embedder to pass
    /// it again.
    enable_0rtt: bool,

    /// Bounded FIFO of stateless responses (VN, Retry) queued for
    /// the embedder to drain via `drainStatelessResponse`. Bounded
    /// at `stateless_response_queue_capacity`; on overflow the
    /// oldest entry is evicted to keep ingest latency bounded.
    stateless_responses: std.ArrayList(StatelessResponse) = .empty,

    /// Random source used to mint server SCIDs. Embedders that need
    /// deterministic CIDs (interop fixtures, fuzzers) can swap this.
    random: std.Random,
    rng_state: std.Random.DefaultPrng,

    /// Monotonic, server-local slot id. Bumped on every accepted
    /// slot; stable for the slot's lifetime. NOT a CID — it's purely
    /// a routing key for embedder logs/tracing.
    next_slot_id: u64 = 0,
    /// Monotonic counter stamping every newly-opened slot's
    /// `tls_generation`. Starts at 0 and bumps on each
    /// `replaceTlsContext` call. Slots opened against `tls_ctx` carry
    /// this exact value; slots opened before a swap retain whatever
    /// generation was current when they were created.
    current_generation: u32 = 0,
    /// Pre-swap TLS contexts that were owned by the Server and still
    /// have at least one live slot referencing them via a
    /// per-connection SSL handle. Each entry is `deinit`-ed and
    /// removed in `reap` once its `refcount` reaches zero. Pre-swap
    /// contexts that the embedder originally supplied via
    /// `tls_context_override` are NOT inserted here — the embedder
    /// retains ownership of those.
    draining_tls_contexts: std.ArrayListUnmanaged(DrainingTlsEntry) = .empty,

    // -- observability counters ---------------------------------------
    //
    // All counters are monotonic since `init` and never reset; the
    // embedder takes deltas if they want a rate. They're plain `u64`
    // (not atomic) because `Server` is single-threaded — the embedder
    // serializes their loop on a single thread, so an atomic load is
    // strictly more expensive without buying anything.
    feeds_routed: u64 = 0,
    feeds_accepted: u64 = 0,
    feeds_dropped: u64 = 0,
    feeds_rate_limited: u64 = 0,
    feeds_table_full: u64 = 0,
    feeds_version_negotiated: u64 = 0,
    feeds_retry_sent: u64 = 0,
    retries_validated: u64 = 0,
    stateless_responses_evicted: u64 = 0,
    slots_reaped: u64 = 0,
    /// Sticky high-water mark of `stateless_responses.items.len`. Set
    /// in `queueStatelessResponse` *before* the new entry lands in
    /// the queue so it reflects the maximum depth ever observed,
    /// regardless of subsequent drains.
    stateless_queue_high_water: u64 = 0,

    pub fn init(config: Config) Error!Server {
        if (config.alpn_protocols.len == 0) return Error.InvalidConfig;
        if (config.local_cid_len == 0 or config.local_cid_len > 20) return Error.InvalidConfig;
        if (config.tls_cert_pem.len == 0 or config.tls_key_pem.len == 0) return Error.InvalidConfig;
        if (config.max_initials_per_source_per_window) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_window_us == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.retry_token_key != null) {
            if (config.retry_token_lifetime_us == 0) return Error.InvalidConfig;
            if (config.retry_state_table_capacity == 0) return Error.InvalidConfig;
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
                .early_data_enabled = config.enable_0rtt,
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
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
            .max_concurrent_connections = config.max_concurrent_connections,
            .local_cid_len = config.local_cid_len,
            .qlog_callback = config.qlog_callback,
            .qlog_user_data = config.qlog_user_data,
            .log_callback = config.log_callback,
            .log_user_data = config.log_user_data,
            .slots = slots,
            .cid_table = cid_table,
            .source_rate_table = .empty,
            .max_initials_per_source = config.max_initials_per_source_per_window,
            .source_rate_window_us = config.source_rate_window_us,
            .source_rate_table_capacity = config.source_rate_table_capacity,
            .retry_state_table = .empty,
            .retry_token_key = config.retry_token_key,
            .retry_token_lifetime_us = config.retry_token_lifetime_us,
            .retry_state_table_capacity = config.retry_state_table_capacity,
            .enable_0rtt = config.enable_0rtt,
            .stateless_responses = .empty,
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
        self.retry_state_table.deinit(self.allocator);
        self.stateless_responses.deinit(self.allocator);
        // Draining contexts always represent ownership the Server
        // took on at swap-time, so they're unconditionally deinit-ed
        // here regardless of `owns_tls` (which only describes the
        // *current* context).
        for (self.draining_tls_contexts.items) |*entry| entry.ctx.deinit();
        self.draining_tls_contexts.deinit(self.allocator);
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
    ///
    /// Stateless responses (Version Negotiation, Retry) are queued
    /// internally; the embedder must drain them via
    /// `drainStatelessResponse` and forward them on the same UDP
    /// socket the datagram came in on.
    pub fn feed(
        self: *Server,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!FeedOutcome {
        if (bytes.len == 0) {
            self.feeds_dropped += 1;
            return .dropped;
        }

        // Existing connection? Hash table lookup, O(1).
        if (self.findSlotForDatagram(bytes)) |slot| {
            slot.last_activity_us = now_us;
            if (from) |addr| slot.peer_addr = addr;
            try self.dispatchToSlot(slot, bytes, from, now_us);
            try self.resyncSlotCids(slot);
            self.feeds_routed += 1;
            return .routed;
        }

        // Long-header packets reach the version-negotiation gate
        // first: any long-header packet whose declared version is
        // not QUIC v1 earns a VN response, regardless of the
        // long-type bits. Per RFC 9000 §6 this catches non-Initial
        // long-header probes (0-RTT, Handshake) too.
        if (peekLongHeaderIds(bytes)) |ids| {
            if (ids.version != QUIC_VERSION_1) {
                if (from) |addr| {
                    self.queueVersionNegotiation(addr, bytes) catch {
                        self.feeds_dropped += 1;
                        return .dropped;
                    };
                    self.feeds_version_negotiated += 1;
                    self.emitLog(.{ .version_negotiated = .{
                        .peer = addr,
                        .requested_version = ids.version,
                    } });
                    return .version_negotiated;
                }
                // No destination address — we can't send a VN, so
                // the datagram is dropped per the documented
                // pass-through behavior.
                self.feeds_dropped += 1;
                return .dropped;
            }
        }

        // New connection candidate: must be a long-header Initial.
        if (!isInitialLongHeader(bytes)) {
            self.feeds_dropped += 1;
            return .dropped;
        }
        if (self.slots.items.len >= self.max_concurrent_connections) {
            self.feeds_table_full += 1;
            self.emitLog(.{ .table_full = .{ .peer = from } });
            return .table_full;
        }

        // Source-rate gate runs *before* Retry / TLS / Connection
        // setup so an attacker spraying Initials from one address
        // can't burn server CPU minting state we'll throw away.
        if (self.max_initials_per_source) |cap| {
            if (from) |addr| {
                if (!self.acceptSourceRate(addr, cap, now_us)) {
                    self.feeds_rate_limited += 1;
                    // Surface the bucket count *after* the rejection
                    // so the embedder sees the value the gate just
                    // tripped against.
                    const recent_count = if (self.source_rate_table.get(addr)) |e| e.count else cap;
                    self.emitLog(.{ .feed_rate_limited = .{
                        .peer = addr,
                        .recent_count = recent_count,
                    } });
                    return .rate_limited;
                }
            }
        }

        // Retry-token gate runs before the Connection is allocated.
        // Returns `.retry_sent` after queuing a Retry, `.dropped` for
        // an invalid echoed token, or null when validation passed
        // (i.e. proceed to slot creation with the post-Retry context).
        var retry_ctx: ?RetryEcho = null;
        if (self.retry_token_key) |_| {
            if (from) |addr| {
                switch (try self.applyRetryGate(addr, bytes, now_us)) {
                    .sent => {
                        self.feeds_retry_sent += 1;
                        // The Retry state table now holds the per-source
                        // entry just minted. Surface its SCID length.
                        const scid_len = if (self.retry_state_table.get(addr)) |e| e.retry_scid_len else self.local_cid_len;
                        self.emitLog(.{ .retry_minted = .{
                            .peer = addr,
                            .scid_len = scid_len,
                        } });
                        return .retry_sent;
                    },
                    .drop => {
                        self.feeds_dropped += 1;
                        return .dropped;
                    },
                    .none => {},
                    .echo => |echo| retry_ctx = echo,
                }
            }
            // No `from`: pass-through to the legacy accept path so
            // that null-address feed still works for in-process
            // tests; production embedders are expected to pass
            // `from` to engage Retry.
        }

        const slot = self.openSlotFromInitial(bytes, from, now_us, retry_ctx) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            // Anything else (TLS init, malformed Initial, Connection
            // setup) is a per-peer hiccup — drop the datagram and
            // keep the server alive. The slot was never registered,
            // so cid_table stays clean.
            else => {
                self.feeds_dropped += 1;
                return .dropped;
            },
        };
        // Successful Retry round-trip: clear the per-source bucket
        // so the next Initial from this address (e.g. a new
        // connection) starts fresh.
        if (retry_ctx != null) {
            if (from) |addr| _ = self.retry_state_table.remove(addr);
            self.retries_validated += 1;
        }
        try self.dispatchToSlot(slot, bytes, from, now_us);
        try self.resyncSlotCids(slot);
        self.feeds_accepted += 1;
        // Emit *after* slot is fully visible in the routing table so
        // the callback can index into `slots` if it wants to.
        if (from) |addr| {
            self.emitLog(.{ .connection_accepted = .{
                .peer = addr,
                .slot_count = self.slots.items.len,
            } });
        }
        return .accepted;
    }

    /// Drain the next stateless response the server has queued, if
    /// any. The returned `StatelessResponse` carries an owned copy
    /// of the encoded bytes plus the destination address — the
    /// embedder forwards it on the same UDP socket the source
    /// datagram came in on. Returns null when the queue is empty.
    pub fn drainStatelessResponse(self: *Server) ?StatelessResponse {
        if (self.stateless_responses.items.len == 0) return null;
        return self.stateless_responses.orderedRemove(0);
    }

    /// Number of stateless responses currently queued. Useful for
    /// tests and metrics.
    pub fn statelessResponseCount(self: *const Server) usize {
        return self.stateless_responses.items.len;
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
    ) ConnectionError!?usize {
        _ = self;
        return try slot.conn.poll(dst, now_us);
    }

    /// Drive time-based recovery on every live slot. Idempotent and
    /// cheap — call it on every loop iteration. Closed slots are
    /// skipped; call `reap` periodically to reclaim them.
    pub fn tick(self: *Server, now_us: u64) ConnectionError!void {
        for (self.slots.items) |slot| {
            if (slot.conn.isClosed()) continue;
            try slot.conn.tick(now_us);
        }
    }

    /// Reap any closed slots from the table. Returns the number of
    /// slots reclaimed. Iterates back-to-front and uses
    /// `swapRemove`, so reaping N closed slots is O(N), not O(N²).
    /// Each reaped slot drops every CID it owned from `cid_table`.
    /// If a reaped slot was opened against a draining TLS context,
    /// its draining-entry refcount is decremented; when the count
    /// reaches zero the draining context is `deinit`-ed and removed
    /// from `draining_tls_contexts`.
    pub fn reap(self: *Server) usize {
        var reaped: usize = 0;
        var i: usize = self.slots.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.slots.items[i];
            if (!slot.conn.isClosed()) continue;
            // Capture the close-event source and peer address before
            // we tear the connection down — once `slot.conn.deinit`
            // has run, both pointers are dead.
            const close_source: ?lifecycle.CloseSource =
                if (slot.conn.closeEvent()) |ev| ev.source else null;
            const close_peer: ?Address = slot.peer_addr;
            self.dropAllCidsFromTable(slot);
            const generation = slot.tls_generation;
            slot.conn.deinit();
            self.allocator.destroy(slot.conn);
            self.allocator.destroy(slot);
            _ = self.slots.swapRemove(i);
            reaped += 1;
            self.releaseGeneration(generation);
            self.emitLog(.{ .connection_closed = .{
                .peer = close_peer,
                .source = close_source,
            } });
        }
        self.slots_reaped += reaped;
        return reaped;
    }

    /// Decrement the refcount on the draining entry for `generation`,
    /// if any. When the refcount hits zero, the entry's context is
    /// torn down and the entry is dropped from
    /// `draining_tls_contexts`. A `generation` matching
    /// `current_generation` is a no-op (the current context isn't a
    /// draining entry until the next `replaceTlsContext`).
    fn releaseGeneration(self: *Server, generation: u32) void {
        if (generation == self.current_generation) return;
        var idx: usize = 0;
        while (idx < self.draining_tls_contexts.items.len) : (idx += 1) {
            const entry = &self.draining_tls_contexts.items[idx];
            if (entry.generation != generation) continue;
            // invariant: refcount > 0 — every live slot at this
            // generation contributed exactly one. Reaping a slot
            // can't drop to zero before all its refs are accounted.
            std.debug.assert(entry.refcount > 0);
            entry.refcount -= 1;
            if (entry.refcount == 0) {
                entry.ctx.deinit();
                _ = self.draining_tls_contexts.swapRemove(idx);
            }
            return;
        }
    }

    /// Queue `CONNECTION_CLOSE` on every live slot. Embedders should
    /// keep polling and ticking until each slot becomes `.closed`,
    /// then call `reap` to reclaim memory.
    pub fn shutdown(self: *Server, error_code: u64, reason: []const u8) void {
        for (self.slots.items) |slot| {
            slot.conn.close(true, error_code, reason);
        }
    }

    /// Hot-swap the TLS context used for new connections. Existing
    /// slots keep talking to their original context via the
    /// per-connection SSL handle (BoringSSL up-refs `SSL_CTX` on
    /// `SSL_new`, so the slot's TLS state survives the swap); only
    /// future `acceptInitial` calls — i.e. brand-new slots created
    /// after this returns — see the new context.
    ///
    /// The pre-swap context, if it was Server-owned, is moved into
    /// `draining_tls_contexts` with a refcount equal to the number of
    /// live slots that were opened against it. As those slots reach
    /// `.closed` and get reaped, the refcount decrements; the
    /// draining context is torn down on the reap that drops the last
    /// reference. If the pre-swap context was caller-supplied (via
    /// `Config.tls_context_override`), the embedder retains
    /// ownership: the swap simply forgets the borrowed pointer here
    /// and stops handing it to new slots. The draining list is
    /// always purely Server-owned.
    ///
    /// **Resumption note**: BoringSSL mints session tickets under
    /// the SSL_CTX's per-context ticket key, so a ticket issued
    /// before this swap cannot be decrypted under the new context
    /// (different key material). Embedders that need cross-reload
    /// resumption — for example to keep 0-RTT working across a hot
    /// cert rotation — must manage ticket key material themselves
    /// (`SSL_CTX_set_tlsext_ticket_keys` or its callback variants)
    /// and feed the rebuilt context in via the `.override` variant
    /// after configuring the keys explicitly. This call deliberately
    /// does not bridge ticket keys for you.
    ///
    /// Errors:
    ///   - `OutOfMemory`: appending to `draining_tls_contexts`.
    ///   - `boringssl.tls.Error.*` / `InvalidConfig`: only the
    ///     `.pem` variant — propagated from
    ///     `Context.initServer`/`loadCertChainAndKey`. The Server is
    ///     left untouched on error: the current context, slot table,
    ///     and draining list are all unchanged.
    pub fn replaceTlsContext(self: *Server, reload: TlsReload) Error!void {
        var new_ctx: boringssl.tls.Context = switch (reload) {
            .pem => |pem| blk: {
                if (pem.cert_pem.len == 0 or pem.key_pem.len == 0) return Error.InvalidConfig;
                var ctx = try boringssl.tls.Context.initServer(.{
                    .verify = .none,
                    .min_version = boringssl.raw.TLS1_3_VERSION,
                    .max_version = boringssl.raw.TLS1_3_VERSION,
                    .alpn = self.alpn_protocols,
                    .early_data_enabled = self.enable_0rtt,
                });
                errdefer ctx.deinit();
                try ctx.loadCertChainAndKey(pem.cert_pem, pem.key_pem);
                break :blk ctx;
            },
            .override => |ctx| ctx,
        };
        // From this point on the new context is logically the
        // Server's. If the bookkeeping below fails we have to deinit
        // it ourselves to avoid leaking — the caller already
        // surrendered ownership of an `.override`, and the `.pem`
        // branch built it locally.
        errdefer new_ctx.deinit();

        // Count live slots at the current generation so we know how
        // many references the about-to-drain context still holds.
        var refs: usize = 0;
        const gen_to_drain = self.current_generation;
        for (self.slots.items) |slot| {
            if (slot.tls_generation == gen_to_drain) refs += 1;
        }

        // Reserve a draining slot up-front when the pre-swap context
        // is owned and still referenced — `appendBounded`-style call
        // would also work, but doing it now means an OOM here leaves
        // both the old context and the slot table untouched.
        if (self.owns_tls and refs > 0) {
            try self.draining_tls_contexts.append(self.allocator, .{
                .ctx = self.tls_ctx,
                .generation = gen_to_drain,
                .refcount = refs,
            });
        } else if (self.owns_tls and refs == 0) {
            // Owned but no live slots reference it — drop immediately.
            self.tls_ctx.deinit();
        }
        // If !owns_tls, the embedder retains ownership of the
        // pre-swap context — we just forget the pointer.

        self.tls_ctx = new_ctx;
        self.owns_tls = true;
        self.current_generation +%= 1;
        // `errdefer new_ctx.deinit()` no longer applies after the
        // assignment above; everything that could fail has run.
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
        retry_ctx: ?RetryEcho,
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

        // Post-Retry connections use the SCID we minted in the Retry
        // packet — that SCID was bound into the token HMAC and is
        // the DCID the peer is actually addressing. Pre-Retry (or
        // Retry-disabled) connections use a fresh random SCID.
        var server_scid: [20]u8 = undefined;
        var local_scid: []const u8 = undefined;
        if (retry_ctx) |echo| {
            local_scid = echo.retry_scid[0..echo.retry_scid_len];
            @memcpy(server_scid[0..echo.retry_scid_len], local_scid);
            local_scid = server_scid[0..echo.retry_scid_len];
        } else {
            self.random.bytes(server_scid[0..self.local_cid_len]);
            local_scid = server_scid[0..self.local_cid_len];
        }
        try conn_ptr.setLocalScid(local_scid);

        // The original DCID for the transport-parameter binding is
        // the *first* Initial's DCID. Pre-Retry that's the DCID on
        // this datagram; post-Retry that was captured before we
        // emitted the Retry and the on-wire DCID here is our
        // server-issued retry_scid.
        const original_dcid = if (retry_ctx) |echo| echo.original_dcid else ConnectionId.fromSlice(ids.dcid);
        // The DCID the peer is addressing on the wire — which is
        // also the routing key — is what the Initial header
        // currently carries.
        const initial_dcid = ConnectionId.fromSlice(ids.dcid);

        var params = self.transport_params;
        params.original_destination_connection_id = original_dcid;
        params.initial_source_connection_id = ConnectionId.fromSlice(local_scid);
        if (retry_ctx) |_| {
            params.retry_source_connection_id = ConnectionId.fromSlice(local_scid);
        }
        try conn_ptr.acceptInitial(bytes, params);

        slot.* = .{
            .conn = conn_ptr,
            .initial_dcid = initial_dcid,
            .peer_addr = from,
            .last_activity_us = now_us,
            .slot_id = self.next_slot_id,
            .tls_generation = self.current_generation,
        };
        self.next_slot_id +%= 1;

        // Reserve a slot in the CID table for the initial DCID. If
        // this fails, the slot was never made visible to the router
        // and the deferred errdefer will tear down the Connection.
        try self.cid_table.put(self.allocator, cidKeyFromConnectionId(initial_dcid), slot);
        errdefer _ = self.cid_table.remove(cidKeyFromConnectionId(initial_dcid));

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
        slot.conn.handle(bytes, from, now_us) catch |err| switch (err) {
            // OOM is fatal for the whole server — propagate. The
            // surrounding `feed` will return `OutOfMemory` to the
            // embedder, who can decide whether to retry, scale, or
            // bail.
            error.OutOfMemory => return Error.OutOfMemory,
            // Per-connection error (peer protocol violation, TLS
            // hiccup, malformed input). Don't tear down the server.
            // If Connection.handle didn't already transition the
            // connection to `.closed`, force it so the slot gets
            // reaped on the next `reap` call. RFC 9000 §20.1
            // INTERNAL_ERROR (0x01) is the catch-all close code for
            // local-side failures.
            else => {
                if (!slot.conn.isClosed()) {
                    slot.conn.close(true, 0x01, "Server.handle failed");
                }
            },
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
        // Default `active_connection_id_limit=8` keeps `total` well
        // under the bound. If an embedder lifts the limit beyond
        // `max_tracked_cids_per_slot`, the router will silently miss
        // SCIDs past the cap and the peer could lose connectivity
        // after a CID rotation. Surface the misconfiguration loudly
        // in debug builds; release builds still truncate (no
        // panic), but the configuration is broken either way.
        std.debug.assert(total <= max_tracked_cids_per_slot);
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

    // -- Version Negotiation -------------------------------------------

    /// Encode a Version Negotiation packet into the response queue.
    /// Errors propagate from the encoder (`InsufficientBytes`) or
    /// the queue allocator (`OutOfMemory`); on either, `feed` falls
    /// back to `.dropped`. The encoder mirrors the QNS endpoint's
    /// `writeVersionNegotiation` (line 1149): supported_versions is
    /// the single-element list `{QUIC_VERSION_1}`, the response
    /// echoes the client's CIDs swapped, and the unused bits are
    /// left as the encoder default per RFC 8999 §6.
    fn queueVersionNegotiation(
        self: *Server,
        dst_addr: Address,
        client_packet: []const u8,
    ) !void {
        const ids = peekLongHeaderIds(client_packet) orelse return error.InvalidVersionNegotiation;
        var entry: StatelessResponse = .{ .dst = dst_addr, .len = 0, .kind = .version_negotiation };

        // Single supported version: QUIC v1. We encode through the
        // wire-level helper directly so we don't have to keep a
        // long-lived Connection just for this side-channel.
        var versions_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, versions_bytes[0..4], QUIC_VERSION_1, .big);

        const written = try wire.header.encode(&entry.bytes, .{ .version_negotiation = .{
            .dcid = try wire.header.ConnId.fromSlice(ids.scid),
            .scid = try wire.header.ConnId.fromSlice(ids.dcid),
            .versions_bytes = versions_bytes[0..],
        } });
        entry.len = written;
        try self.queueStatelessResponse(entry);
    }

    // -- Retry ----------------------------------------------------------

    /// What `applyRetryGate` decided. `none` means proceed with the
    /// normal accept path (this Initial carried no token and Retry
    /// is disabled, or the source already passed validation in a
    /// prior datagram). `sent` means we queued a Retry. `drop` means
    /// the echoed token was malformed/expired/wrong-source. `echo`
    /// means the token validated and the caller should accept this
    /// Initial as the post-Retry continuation.
    const RetryDecision = union(enum) {
        none,
        sent,
        drop,
        echo: RetryEcho,
    };

    /// Captured server-side context for an Initial that successfully
    /// echoed a Retry token. The slot opener uses these to set the
    /// post-Retry transport parameters.
    const RetryEcho = struct {
        retry_scid: [20]u8,
        retry_scid_len: u8,
        original_dcid: ConnectionId,
    };

    /// Run the Retry-token gate for an Initial from `addr`. Either
    /// queues a Retry (and returns `.sent`), validates an echoed
    /// token (and returns `.echo` with the per-source context), or
    /// returns `.drop` for a malformed/expired/wrong-source token.
    /// Returns `.none` only if Retry is disabled (caller checks
    /// before invoking).
    fn applyRetryGate(
        self: *Server,
        addr: Address,
        bytes: []const u8,
        now_us: u64,
    ) Error!RetryDecision {
        const key_ptr = if (self.retry_token_key) |*k| k else return .none;
        const ids = peekLongHeaderIds(bytes) orelse return .drop;

        const token = peekInitialToken(bytes);
        const existing = self.retry_state_table.get(addr);

        // No echoed token: the peer is on its first Initial. Mint a
        // Retry, queue it, and require the next Initial to echo.
        if (token == null or token.?.len == 0) {
            self.mintAndQueueRetry(addr, ids, now_us, key_ptr) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .drop,
            };
            return .sent;
        }

        // Echoed token but no per-source state: stale (we evicted on
        // overflow, restarted, etc.). Re-mint a fresh Retry; the peer
        // will retry with a new round-trip.
        const state = existing orelse {
            self.mintAndQueueRetry(addr, ids, now_us, key_ptr) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .drop,
            };
            return .sent;
        };

        // Echoed token: validate against the per-source retry_scid
        // we minted. The SCID binding ties the token to a specific
        // Retry round-trip — a token minted for some other peer
        // can't be replayed here even if the source IP collides.
        var addr_buf: [22]u8 = undefined;
        const ctx = addressContext(&addr_buf, addr);
        const result = retry_token_mod.validate(token.?, .{
            .key = key_ptr,
            .now_us = now_us,
            .client_address = ctx,
            .original_dcid = state.original_dcid.slice(),
            .retry_scid = state.retry_scid[0..state.retry_scid_len],
        });
        if (result != .valid) return .drop;

        // Validated: bubble up the per-source context so the slot
        // opener knows which SCID to bind and which odcid to set in
        // transport params.
        return .{ .echo = .{
            .retry_scid = state.retry_scid,
            .retry_scid_len = state.retry_scid_len,
            .original_dcid = state.original_dcid,
        } };
    }

    /// Sentinel returned from `mintAndQueueRetry` when token mint or
    /// Retry seal fails for a reason that isn't peer-induced (DCID
    /// length already bounded by `peekLongHeaderIds`, address ctx
    /// is fixed-size, dst buf is fixed-size). Any peer-reachable
    /// path that lands here means an invariant slipped, so the
    /// caller drops the datagram silently.
    const RetryMintError = Error || error{RetryEncodeFailed};

    fn mintAndQueueRetry(
        self: *Server,
        addr: Address,
        ids: LongHeaderIds,
        now_us: u64,
        key_ptr: *const RetryTokenKey,
    ) RetryMintError!void {
        // Bound the table without letting forged-source floods
        // evict legitimate-peer Retry round-trips. First sweep
        // anything older than the token lifetime — those entries
        // are already useless because their tokens won't validate.
        // Only fall back to oldest-eviction if the table is still
        // at capacity (i.e., every entry is within its lifetime).
        if (self.retry_state_table.count() >= self.retry_state_table_capacity) {
            self.pruneExpiredRetryState(now_us);
            if (self.retry_state_table.count() >= self.retry_state_table_capacity) {
                self.evictOldestRetryState();
            }
        }

        // Pick a fresh server-issued SCID for this Retry. The peer
        // will echo this DCID in its post-Retry Initial, and the
        // token HMAC binds to it so a replayed Retry can't authorize
        // a different connection.
        var retry_scid: [20]u8 = @splat(0);
        const retry_scid_len = self.local_cid_len;
        self.random.bytes(retry_scid[0..retry_scid_len]);

        var addr_buf: [22]u8 = undefined;
        const ctx = addressContext(&addr_buf, addr);
        var token: retry_token_mod.Token = undefined;
        _ = retry_token_mod.mint(&token, .{
            .key = key_ptr,
            .now_us = now_us,
            .lifetime_us = self.retry_token_lifetime_us,
            .client_address = ctx,
            .original_dcid = ids.dcid,
            .retry_scid = retry_scid[0..retry_scid_len],
        }) catch return error.RetryEncodeFailed;

        var entry: StatelessResponse = .{ .dst = addr, .len = 0, .kind = .retry };
        const written = wire.long_packet.sealRetry(&entry.bytes, .{
            .original_dcid = ids.dcid,
            .dcid = ids.scid,
            .scid = retry_scid[0..retry_scid_len],
            .retry_token = &token,
        }) catch return error.RetryEncodeFailed;
        entry.len = written;

        try self.queueStatelessResponse(entry);

        // Record the retry state so we can validate the echoed
        // token in the peer's next Initial.
        const gop = try self.retry_state_table.getOrPut(self.allocator, addr);
        gop.value_ptr.* = .{
            .retry_scid = retry_scid,
            .retry_scid_len = retry_scid_len,
            .original_dcid = ConnectionId.fromSlice(ids.dcid),
            .minted_at_us = now_us,
        };
    }

    fn evictOldestRetryState(self: *Server) void {
        var it = self.retry_state_table.iterator();
        var oldest_addr: ?Address = null;
        var oldest_us: u64 = std.math.maxInt(u64);
        while (it.next()) |entry| {
            if (entry.value_ptr.minted_at_us < oldest_us) {
                oldest_us = entry.value_ptr.minted_at_us;
                oldest_addr = entry.key_ptr.*;
            }
        }
        if (oldest_addr) |a| _ = self.retry_state_table.remove(a);
    }

    /// Drop every retry-state entry whose token has expired
    /// (`now_us - minted_at_us > retry_token_lifetime_us`).
    /// Expired entries can never validate a peer's echoed token,
    /// so freeing their slot is always safe and means the table
    /// fills with usable round-trips before any eviction policy
    /// has to fire.
    fn pruneExpiredRetryState(self: *Server, now_us: u64) void {
        const lifetime = self.retry_token_lifetime_us;
        var stale_buf: [32]Address = undefined;
        while (true) {
            var n: usize = 0;
            var it = self.retry_state_table.iterator();
            while (it.next()) |entry| {
                if (n >= stale_buf.len) break;
                const age = now_us -% entry.value_ptr.minted_at_us;
                if (age > lifetime) {
                    stale_buf[n] = entry.key_ptr.*;
                    n += 1;
                }
            }
            if (n == 0) return;
            for (stale_buf[0..n]) |addr| _ = self.retry_state_table.remove(addr);
            // If we evicted a full batch there may be more — loop
            // to keep sweeping. Bounded by the table size, so
            // this terminates.
            if (n < stale_buf.len) return;
        }
    }

    // -- stateless response queue --------------------------------------

    fn queueStatelessResponse(self: *Server, entry: StatelessResponse) Error!void {
        // Bound the queue: on overflow, prefer evicting the oldest
        // VN entry over any Retry. This stops a flood of
        // unsupported-version probes from starving Retry responses
        // to legitimate v1 peers. If no VN is queued (the queue is
        // all Retry), evict the oldest Retry — falling back to FIFO
        // is still better than refusing the new entry.
        if (self.stateless_responses.items.len >= stateless_response_queue_capacity) {
            const evict_idx: usize = blk: {
                for (self.stateless_responses.items, 0..) |*e, i| {
                    if (e.kind == .version_negotiation) break :blk i;
                }
                break :blk 0;
            };
            const evicted_kind = self.stateless_responses.items[evict_idx].kind;
            _ = self.stateless_responses.orderedRemove(evict_idx);
            self.stateless_responses_evicted += 1;
            self.emitLog(.{ .stateless_queue_evicted = .{ .kind = evicted_kind } });
        }
        try self.stateless_responses.append(self.allocator, entry);
        // Update the sticky high-water mark *after* append — it
        // captures the post-insert depth, which is the value the
        // queue actually held at this instant. The mark only ever
        // grows.
        const depth: u64 = @intCast(self.stateless_responses.items.len);
        if (depth > self.stateless_queue_high_water) {
            self.stateless_queue_high_water = depth;
        }
    }

    // -- observability -------------------------------------------------

    /// Internal helper: invoke `log_callback` if installed. Inlined
    /// at call sites so the no-callback path stays a single
    /// optional-null check.
    fn emitLog(self: *const Server, ev: LogEvent) void {
        if (self.log_callback) |cb| cb(self.log_user_data, ev);
    }

    /// Snapshot the server's instrumentation gauges and counters.
    /// The returned `MetricsSnapshot` is a flat by-value struct;
    /// reading it does not allocate, mutate the server, or invoke
    /// any user callback. Embedders typically call this on a fixed
    /// schedule and forward to their metrics pipeline (Prometheus,
    /// statsd, OpenTelemetry).
    pub fn metricsSnapshot(self: *const Server) MetricsSnapshot {
        return .{
            .live_connections = @intCast(self.slots.items.len),
            .routing_table_size = @intCast(self.cid_table.count()),
            .source_rate_table_size = @intCast(self.source_rate_table.count()),
            .retry_state_table_size = @intCast(self.retry_state_table.count()),
            .stateless_queue_depth = @intCast(self.stateless_responses.items.len),
            .stateless_queue_high_water = self.stateless_queue_high_water,
            .feeds_routed = self.feeds_routed,
            .feeds_accepted = self.feeds_accepted,
            .feeds_dropped = self.feeds_dropped,
            .feeds_rate_limited = self.feeds_rate_limited,
            .feeds_table_full = self.feeds_table_full,
            .feeds_version_negotiated = self.feeds_version_negotiated,
            .feeds_retry_sent = self.feeds_retry_sent,
            .retries_validated = self.retries_validated,
            .stateless_responses_evicted = self.stateless_responses_evicted,
            .slots_reaped = self.slots_reaped,
        };
    }

    /// Snapshot the rate-limiter table, returning the top
    /// `RateLimitSnapshot.top_n` (16) sources by `recent_count` in
    /// descending order. The unused tail of `top_offenders` is
    /// zero-initialized; embedders should iterate up to
    /// `top_offender_count`.
    ///
    /// The implementation is an O(N * top_n) insertion sort across
    /// the table (N = `source_rate_table` size, bounded by
    /// `Config.source_rate_table_capacity`). With the default
    /// capacity of 4096 entries and top_n=16 this is well under a
    /// millisecond on commodity hardware; the snapshot is meant for
    /// occasional polling (every few seconds), not the per-packet
    /// hot path.
    pub fn rateLimitSnapshot(self: *const Server) RateLimitSnapshot {
        var snap: RateLimitSnapshot = .{
            .table_size = self.source_rate_table.count(),
            .cumulative_rejections = self.feeds_rate_limited,
            .top_offenders = @splat(.{ .addr = .{}, .recent_count = 0, .window_start_us = 0 }),
            .top_offender_count = 0,
        };

        // Insertion-sort across the live table. For each entry, find
        // the first position whose count is below ours and shift
        // everything after it down by one. Bounded scan because the
        // top-N array is fixed at 16.
        var it = self.source_rate_table.iterator();
        while (it.next()) |entry| {
            const row: RateLimitSnapshot.SourceRow = .{
                .addr = entry.key_ptr.*,
                .recent_count = entry.value_ptr.count,
                .window_start_us = entry.value_ptr.window_start_us,
            };

            // Find insertion point in the descending-by-count list.
            var insert_idx: usize = snap.top_offender_count;
            for (0..snap.top_offender_count) |i| {
                if (row.recent_count > snap.top_offenders[i].recent_count) {
                    insert_idx = i;
                    break;
                }
            }
            if (insert_idx >= RateLimitSnapshot.top_n) continue;

            // Shift down to make room. If the array is already at
            // capacity, the last entry falls off the bottom.
            const last = @min(snap.top_offender_count, RateLimitSnapshot.top_n - 1);
            var j: usize = last;
            while (j > insert_idx) : (j -= 1) {
                snap.top_offenders[j] = snap.top_offenders[j - 1];
            }
            snap.top_offenders[insert_idx] = row;
            if (snap.top_offender_count < RateLimitSnapshot.top_n) {
                snap.top_offender_count += 1;
            }
        }
        return snap;
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

/// Extract the token slice from an Initial header, or null if the
/// packet didn't parse cleanly as one. The bytes returned are
/// borrowed from `bytes`.
fn peekInitialToken(bytes: []const u8) ?[]const u8 {
    const parsed = wire.header.parse(bytes, 0) catch return null;
    return switch (parsed.header) {
        .initial => |initial| initial.token,
        else => null,
    };
}

/// Canonicalize an `Address` into the byte string the Retry-token
/// HMAC binds against. The current `Address` type is a fixed 22-byte
/// blob, so the canonical form is just the full 22 bytes — both
/// peers are using the same in-memory shape, and any zero-padding is
/// part of the binding. This stays stable under future Address
/// extensions: as long as `Address.eql` is byte-equality on
/// `Address.bytes`, the HMAC binding remains tight.
fn addressContext(dst: []u8, addr: Address) []const u8 {
    std.debug.assert(dst.len >= addr.bytes.len);
    @memcpy(dst[0..addr.bytes.len], &addr.bytes);
    return dst[0..addr.bytes.len];
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

// -- fuzz harness --------------------------------------------------------
//
// `Server.feed` is the entry point an open-internet deployment exposes
// to arbitrary bytes; the header-peek helpers (`peekLongHeaderIds`,
// `isInitialLongHeader`, `peekDcidForServer`) gate it. None may panic
// on hostile input. We stop short of a full `Server` end-to-end fuzz
// (it would need a TLS context and an allocator-tracked
// `boringssl.tls.Context`) — the wire-level peek surface is the
// highest-yield target.

test "fuzz: peekLongHeaderIds never panics" {
    try std.testing.fuzz({}, fuzzPeekLongHeader, .{});
}

fn fuzzPeekLongHeader(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    const ids = peekLongHeaderIds(input) orelse return;
    // Returned CID slices must point into `input`.
    try std.testing.expect(ids.dcid.len <= 20);
    try std.testing.expect(ids.scid.len <= 20);
    try std.testing.expect(@intFromPtr(ids.dcid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(ids.dcid.ptr) + ids.dcid.len <= @intFromPtr(input.ptr) + input.len);
    try std.testing.expect(@intFromPtr(ids.scid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(ids.scid.ptr) + ids.scid.len <= @intFromPtr(input.ptr) + input.len);
}

test "fuzz: isInitialLongHeader never panics" {
    try std.testing.fuzz({}, fuzzIsInitialLongHeader, .{});
}

fn fuzzIsInitialLongHeader(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    _ = isInitialLongHeader(input);
}

test "fuzz: peekDcidForServer never panics across all CID lengths" {
    try std.testing.fuzz({}, fuzzPeekDcid, .{});
}

fn fuzzPeekDcid(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    const local_cid_len = smith.valueRangeAtMost(u8, 0, 20);

    const dcid = peekDcidForServer(input, local_cid_len) orelse return;
    // The returned slice must lie inside `input`.
    try std.testing.expect(@intFromPtr(dcid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(dcid.ptr) + dcid.len <= @intFromPtr(input.ptr) + input.len);
    try std.testing.expect(dcid.len <= 20);
}
