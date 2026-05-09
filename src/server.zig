//! quic_zig.Server — production-grade convenience wrapper for embedding
//! quic_zig as a QUIC server.
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
//! 3. Long-header packets carrying any version not in
//!    `Config.versions` (which defaults to QUIC v1 only) always
//!    trigger a Version Negotiation response (RFC 9000 §6 / RFC
//!    8999 §6 / RFC 9368 §6); this is unconditional and requires
//!    no further `Config` opt-in.
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
//! `quic_zig.transport.runUdpServer` instead — it owns the
//! `std.Io`-based bind / tune / receive / feed / poll / tick / reap
//! cadence. The QNS endpoint at `interop/qns_endpoint.zig` keeps its
//! own bespoke loop because it has interop-specific quirks
//! (deterministic CID prefix, per-testcase wiring); general-purpose
//! embedders should reach for `Server` (server side) or
//! `quic_zig.Client` (client side) first.

const std = @import("std");
const boringssl = @import("boringssl");

const conn_mod = @import("conn/root.zig");
const tls_mod = @import("tls/root.zig");
const wire = @import("wire/root.zig");
const lb_mod = @import("lb/root.zig");
const retry_token_mod = conn_mod.retry_token;
const new_token_mod = conn_mod.new_token;
const lifecycle = conn_mod.lifecycle;

const Connection = conn_mod.Connection;
const ConnectionError = conn_mod.state.Error;
const TransportParams = tls_mod.TransportParams;
const ConnectionId = conn_mod.path.ConnectionId;
const Address = conn_mod.path.Address;
const QlogCallback = conn_mod.QlogCallback;
const RetryTokenKey = conn_mod.RetryTokenKey;
const PreferredAddressTp = tls_mod.transport_params.PreferredAddress;

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
    /// Initial-bearing UDP datagrams discarded because the datagram
    /// payload was smaller than the RFC 9000 §14 minimum (1200
    /// bytes). A subset of `feeds_dropped` — incremented in addition
    /// to it. Spiking values point at amplification probes.
    feeds_initial_too_small: u64,
    /// Non-v1 long-header datagrams that would have triggered a
    /// Version Negotiation response but were dropped because the
    /// per-source VN rate limit (`max_vn_per_source_per_window`)
    /// fired. A subset of `feeds_dropped`. Spiking values point at
    /// VN-flood probes.
    feeds_vn_rate_limited: u64,
    /// Datagrams dropped at the listener-level packet rate limit
    /// (`Config.max_datagrams_per_window`). Subset of `feeds_dropped`.
    /// Hardening guide §4.1.
    feeds_listener_rate_limited: u64,
    /// Datagrams dropped at the listener-level byte rate limit
    /// (`Config.max_bytes_per_window`). Subset of `feeds_dropped`.
    /// Tracks bandwidth-flavored floods that the packet-count cap
    /// would let through (few-but-large datagrams). Hardening guide §4.1.
    feeds_listener_byte_rate_limited: u64,
    /// Datagrams dropped at the per-source bandwidth shaper
    /// (`Config.max_bytes_per_source_per_second`). Subset of
    /// `feeds_dropped`. Distinct from `feeds_listener_byte_rate_limited`:
    /// the listener cap protects the aggregate firehose, this protects
    /// against any single source consuming more than its fair share.
    /// Hardening guide §4.1 token-bucket.
    feeds_source_bandwidth_limited: u64,
    /// LogEvents the server dropped under the per-source log rate
    /// limit (`Config.max_log_events_per_source_per_window`).
    /// Distinct from `feeds_dropped` — feeding a datagram and emitting
    /// a log are separate side effects. Hardening guide §9.4.
    feeds_log_rate_limited: u64,
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
/// by the peer's `active_connection_id_limit` (default 8 in quic_zig);
/// 32 leaves headroom for embedders that lift the limit and for
/// in-flight retires, while keeping the router a fixed, alloc-free
/// slot footprint. If a `Connection` ever issues more than this
/// many active SCIDs, `resyncSlotCids` asserts in debug builds and
/// truncates in release — bump this constant if you bump
/// `active_connection_id_limit` toward 32 or beyond.
const max_tracked_cids_per_slot: usize = 32;

/// Idle threshold (microseconds) past which a `SourceRateEntry`
/// whose three counter windows have all elapsed is also considered
/// stale on the bandwidth-bucket axis and may be pruned. Five
/// seconds is comfortably longer than the default
/// `source_rate_window_us` (one second), so a source seen recently
/// enough to keep its bucket warm survives `pruneSourceRate` even
/// when its Initial / VN / log windows have aged out. Hardening
/// guide §4.1 token-bucket.
const bandwidth_idle_threshold_us: u64 = 5_000_000;

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
/// lazily on each `feed`. Three independent (count, window_start)
/// pairs track Initial-eligible, Version-Negotiation-eligible, and
/// LogEvent-eligible traffic separately — a peer that spams VN
/// probes shouldn't burn the per-source Initial budget, a peer that
/// gets rate-limited shouldn't free up its VN budget, and so on.
const SourceRateEntry = struct {
    /// Initial-driven slot creations attributed to this source
    /// within the current window.
    count: u32,
    /// Wall-clock microseconds when the current Initial window started.
    window_start_us: u64,
    /// Version-Negotiation responses attributed to this source within
    /// the current VN window. Gated by
    /// `Config.max_vn_per_source_per_window`.
    vn_count: u32 = 0,
    /// Wall-clock microseconds when the current VN window started.
    vn_window_start_us: u64 = 0,
    /// LogEvents emitted on behalf of this source within the current
    /// log window. Gated by `Config.max_log_events_per_source_per_window`.
    /// Hardening guide §9.4: a flood of feed-rate-limited /
    /// table-full / VN-rate-limited / etc. log events from one
    /// address would otherwise let the peer flood the embedder's
    /// log pipeline; this counter caps that.
    log_count: u32 = 0,
    /// Wall-clock microseconds when the current log window started.
    log_window_start_us: u64 = 0,
    /// Token-bucket level (in bytes) for per-source bandwidth shaping.
    /// Gated by `Config.max_bytes_per_source_per_second`. Refilled at
    /// the configured rate up to a one-second burst cap; each accepted
    /// datagram debits `bytes.len`. Hardening guide §4.1 token-bucket.
    bandwidth_tokens: u64 = 0,
    /// Wall-clock microseconds at the most recent token-bucket refill.
    /// Driven by the per-feed `now_us` so the shaper reads the
    /// embedder's monotonic clock rather than a separate timebase.
    bandwidth_last_refill_us: u64 = 0,
};

/// Configuration handed to `Server.init`. Re-exported as
/// `Server.Config`.
/// Server `preferred_address` (RFC 9000 §18.2 / §5.1.1) configuration.
/// When set on `Config.preferred_address`, the server advertises this
/// alternate IPv4/IPv6 address pair to clients during the handshake,
/// and (when used with `runUdpServer`) binds an additional listener
/// socket on each configured address. Clients that complete the
/// handshake migrate to the preferred address per RFC 9000 §5.1.1.
///
/// At least one of `ipv4` / `ipv6` must be non-null. When only one
/// family is set, the unused-family fields in the on-wire transport
/// parameter are left zero (the spec sentinel meaning "no preferred
/// address for this family"). The CID + stateless-reset token the
/// parameter advertises are derived per-connection at handshake time
/// using `Config.stateless_reset_key` and `Server.mintLocalScid`; the
/// embedder does not supply them.
///
/// **`Config.stateless_reset_key` is required** when this field is
/// set. The seq-1 stateless-reset token in the parameter must match
/// the token a future stateless-reset on the alt-CID would produce,
/// and the deterministic `conn.stateless_reset.derive` helper is the
/// only path quic_zig surfaces for that. Setting `preferred_address`
/// without a key fails `Server.init` with `InvalidConfig`.
pub const PreferredAddressConfig = struct {
    /// Alt IPv4 address + port to advertise + bind, or null. The
    /// 4-byte address bytes are advertised verbatim; an all-zero
    /// `ipv4` is interpreted by RFC 9000 §18.2 as "no IPv4
    /// preferred address" and `runUdpServer` will skip the v4 bind.
    ipv4: ?std.Io.net.Ip4Address = null,
    /// Alt IPv6 address + port to advertise + bind, or null.
    /// Same all-zero sentinel semantics as `ipv4`.
    ipv6: ?std.Io.net.Ip6Address = null,
};

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
    /// the QNS endpoint. **Ignored when `quic_lb` is set** — the
    /// QUIC-LB configuration determines the CID length
    /// (`1 + server_id_len + nonce_len`) and `Server.init` overrides
    /// this field with the resolved value.
    local_cid_len: u8 = 8,

    /// 32-byte HMAC key used to derive stateless-reset tokens
    /// (RFC 9000 §10.3) for CIDs the Server auto-issues on
    /// `installLbConfig` rotation. Off by default — leave null and
    /// drive replenishment manually via the `connection_ids_needed`
    /// event flow with embedder-supplied tokens.
    ///
    /// When set, `installLbConfig` automatically pushes a
    /// NEW_CONNECTION_ID frame to every live slot using the new LB
    /// factory; tokens are derived as
    /// `HMAC-SHA256(stateless_reset_key, "quic_zig stateless reset
    /// v1" || cid)` per `quic_zig.conn.stateless_reset.derive`.
    ///
    /// **Persist this key across server restarts.** A cold-start
    /// embedder that forgets the key invalidates every previously
    /// issued reset token: live connections through the restart will
    /// no longer drop on stateless reset. The same hardening note in
    /// the README §"Things you must wire yourself" applies.
    stateless_reset_key: ?conn_mod.stateless_reset.Key = null,

    /// QUIC-LB connection-ID generation
    /// (draft-ietf-quic-load-balancers-21). Off by default — leave
    /// null for pure-CSPRNG SCIDs. Set to opt every locally-issued
    /// SCID into the routing-encoded format an external layer-4 LB
    /// can decode.
    ///
    /// **Hardening note:** this deliberately inverts the
    /// "Server SCIDs are CSPRNG draws — no deployment metadata leaks
    /// on the wire" default (README §"On by default"). Treat the
    /// load balancer as the trust boundary; in plaintext mode (no
    /// `LbConfig.key`) any on-path observer between LB and peer can
    /// read `server_id` directly. Encrypted modes (LB-2, LB-3) raise
    /// the bar to "linkability without key" but do not protect
    /// against attackers between LB and server.
    ///
    /// LB-1 ships only the plaintext mode (`LbConfig.key == null`).
    /// Encrypted modes return `error.UnsupportedMode` from the
    /// minter until LB-2 / LB-3 land.
    ///
    /// When set in plaintext mode, `Server.init` also auto-enables
    /// `transport_params.disable_active_migration` per the draft
    /// §3 ¶3 SHOULD requirement, unless the embedder already set
    /// it true.
    quic_lb: ?lb_mod.LbConfig = null,

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
    /// in microseconds. Default is one second. Shared by the VN
    /// rate-limit window (`max_vn_per_source_per_window`).
    source_rate_window_us: u64 = 1_000_000,

    /// Maximum number of distinct source addresses the rate limiter
    /// tracks at once. Excess sources rotate out the oldest entry.
    /// Only consulted when the limiter is enabled.
    source_rate_table_capacity: u32 = 4096,

    /// Per-source-address Version-Negotiation-emission cap. Null
    /// disables the limiter (every non-v1 long-header packet earns a
    /// VN response, subject only to the bounded global stateless
    /// queue). Hardening guide §4.4: a peer flooding non-v1
    /// long-header probes from a single address can otherwise force
    /// up to `stateless_response_queue_capacity` outbound bytes per
    /// drain cycle. Recommended: 8 for open-internet deployments —
    /// legitimate clients fix their version after one VN response and
    /// retry with v1.
    max_vn_per_source_per_window: ?u32 = 8,

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

    /// AES-GCM-256 key used to mint and validate NEW_TOKEN frames
    /// (RFC 9000 §8.1.3). When null, NEW_TOKEN issuance is disabled
    /// and Initial-token validation falls through to the Retry
    /// token gate. When set, the server emits one NEW_TOKEN per
    /// successfully-handshake-confirmed connection, and accepts
    /// returning clients presenting a valid NEW_TOKEN as already
    /// address-validated (no Retry round-trip).
    ///
    /// This key is **distinct from `retry_token_key`** by design:
    /// NEW_TOKENs typically outlive Retry tokens by orders of
    /// magnitude (hours/days vs. seconds), so they need their own
    /// rotation policy. Sharing the key would force NEW_TOKEN
    /// rotation every time the operator rotated the Retry key.
    new_token_key: ?conn_mod.NewTokenKey = null,
    /// Lifetime of a minted NEW_TOKEN in microseconds. Returning
    /// clients presenting a token older than this fall through to
    /// the Retry gate (or the no-validation accept path, if Retry
    /// is also disabled). Default 24 hours — long enough that a
    /// returning user a day later still skips Retry, short enough
    /// that a stolen token's window of misuse is bounded.
    new_token_lifetime_us: u64 = 24 * 3600 * 1_000_000,

    /// Enable QUIC 0-RTT (early data) on the auto-built TLS context.
    /// Off by default to satisfy the §5.2 / §12 hardening posture:
    /// 0-RTT is replayable and unsuitable for state-changing requests
    /// without an application-level anti-replay mechanism (RFC 9001
    /// §5.6 / RFC 8446 §8). Embedders that want 0-RTT must opt in
    /// here AND wire a `quic_zig.tls.AntiReplayTracker` (or equivalent)
    /// into their server loop so duplicate early-data is rejected;
    /// see that type's module docstring for the recommended
    /// workflow. The transport ships the data structure but the
    /// "is this 0-RTT bytes a replay?" check fires at the embedder's
    /// application layer.
    ///
    /// Only consulted when `tls_context_override` is null. Embedders
    /// supplying their own `boringssl.tls.Context` are responsible for
    /// configuring its early-data posture themselves.
    enable_0rtt: bool = false,

    /// Anti-replay tracker for 0-RTT early-data (hardening §5.2 /
    /// RFC 9001 §5.6). When `enable_0rtt` is true and this is non-null,
    /// the Server installs a BoringSSL `allow_early_data` callback
    /// that hashes the resumed-session ticket bytes
    /// (`Conn.peerSessionId`) to the tracker's 32-byte `Id` and calls
    /// `tracker.consume(id, now)`. Verdict `.fresh` lets BoringSSL
    /// accept 0-RTT; `.replay` toggles `early_data_enabled` off for
    /// that handshake (the connection then completes as 1-RTT).
    ///
    /// The tracker is owned by the embedder and must outlive the
    /// `Server`. Only consulted when `tls_context_override` is null —
    /// override-mode embedders install their own callback via
    /// `boringssl.tls.Context.setAllowEarlyDataCallback`.
    early_data_anti_replay: ?*tls_mod.anti_replay.AntiReplayTracker = null,

    /// Whether to encode the locally-recorded close-reason string into
    /// outgoing CONNECTION_CLOSE frames. Default `false` (redact) per
    /// hardening guide §9 / §12: internal parser-error strings reveal
    /// implementation detail to the peer (parser fingerprinting,
    /// internal state names). Local introspection is unaffected; the
    /// embedder still sees the reason via close events.
    ///
    /// Threaded onto every Connection the Server creates. Embedders
    /// can also set `Connection.reveal_close_reason_on_wire` directly
    /// for finer-grained control (e.g. dev/debug builds).
    reveal_close_reason_on_wire: bool = false,

    /// Per-Connection cap on bytes resident in peer-controlled
    /// reassembly / queue buffers (CRYPTO, DATAGRAM, stream send /
    /// recv). See `conn.state.default_max_connection_memory` and
    /// `Connection.max_connection_memory` for the per-buffer
    /// rationale. Threaded onto every accepted slot at
    /// `openSlotFromInitial` time. 32 MiB by default — a healthy
    /// upper bound that still leaves headroom for the per-buffer
    /// caps to do their job before this aggregate cap fires.
    max_connection_memory: u64 = conn_mod.state.default_max_connection_memory,

    /// Number of ack-eliciting application packets the server requires
    /// before forcing an immediate ACK (RFC 9000 §13.2.1 ¶2). Default
    /// matches `quic_zig.conn.state.application_ack_eliciting_threshold`.
    /// Lower this to 1 for low-RTT links where every packet should be
    /// ACKed; raise it to amortize ACK overhead at the cost of more
    /// peer PTOs. Threaded onto every Connection at slot-open time.
    delayed_ack_packet_threshold: u8 = conn_mod.state.application_ack_eliciting_threshold,

    /// Enable IETF ECN signaling (RFC 9000 §13.4 / RFC 3168) on every
    /// Connection the Server creates. Default `true` — production
    /// QUIC reaps modest goodput wins by reacting to router-driven
    /// CE marks. Flip to `false` only in environments known to
    /// bleach ECN bits (some legacy NATs / firewalls). Threaded onto
    /// every Connection's `ecn_enabled` field at slot-open time.
    enable_ecn: bool = true,

    /// Listener-level packet rate limit (hardening guide §4.1):
    /// drop incoming UDP datagrams when the global per-window count
    /// exceeds this cap. Off by default (`null`) so embedders
    /// explicitly opt in for production. The window length is
    /// `listener_rate_window_us`; the bucket is single-global (no
    /// per-source bookkeeping) so it shares state with nothing and
    /// triggers cheaply on a flood from many spoofed sources.
    ///
    /// Recommended: scale to ~2x peak observed packets-per-window,
    /// then alert on `MetricsSnapshot.feeds_listener_rate_limited`
    /// growing. cap=0 fails `Server.init` with `InvalidConfig`.
    max_datagrams_per_window: ?u32 = null,

    /// Listener-level byte rate limit (hardening guide §4.1):
    /// drop incoming UDP datagrams when the global per-window byte
    /// total exceeds this cap. Off by default (`null`) so embedders
    /// explicitly opt in for production. Shares
    /// `listener_rate_window_us` with the packet-count cap; the
    /// bucket is single-global (no per-source bookkeeping) so a
    /// flood of few-but-large datagrams from any number of sources
    /// is gated even when the per-packet cap is generous.
    ///
    /// Recommended: scale to ~2x peak observed bytes-per-window,
    /// then alert on `MetricsSnapshot.feeds_listener_byte_rate_limited`
    /// growing. cap=0 fails `Server.init` with `InvalidConfig`.
    max_bytes_per_window: ?u64 = null,

    /// Window length for `max_datagrams_per_window` /
    /// `max_bytes_per_window` in microseconds. Default 1 second.
    /// Smaller windows make the caps more responsive at the cost of
    /// more reset jitter; larger windows smooth bursty traffic. Both
    /// listener-level caps share this single window.
    listener_rate_window_us: u64 = 1_000_000,

    /// Per-source bandwidth shaping (hardening §4.1 token-bucket).
    /// When non-null, every accepted datagram from a given source charges
    /// `bytes.len` against a token bucket that refills at
    /// `max_bytes_per_source_per_second` bytes per second up to the same
    /// value as a hard cap (one second's burst). When the bucket is empty
    /// the datagram is dropped and `feeds_source_bandwidth_limited` ticks.
    ///
    /// Null disables (default — production opts in). Distinct from the
    /// global sliding-window `max_bytes_per_window` cap: this gates per
    /// source, the global cap gates aggregate. Charging happens AFTER
    /// the global gates approve, so the global caps still bound aggregate
    /// bandwidth even when every individual source has full buckets.
    /// cap=0 fails `Server.init` with `InvalidConfig`.
    max_bytes_per_source_per_second: ?u64 = null,

    /// Per-source cap on `LogEvent` emissions per window (hardening
    /// guide §9.4). When the cap fires, the log is dropped silently —
    /// no nested log about the dropped log. Defaults to 16 events
    /// per window per source; null disables. Reuses
    /// `source_rate_window_us` (so the Initial / VN / log windows
    /// all share one knob).
    ///
    /// Log events with `from = null` (no source attribution) bypass
    /// the limiter — see `acceptLogRate`. Embedders that want a
    /// global ceiling on null-source events should put one in their
    /// own log_callback.
    max_log_events_per_source_per_window: ?u32 = 16,

    /// QUIC wire-format versions this server accepts on inbound
    /// Initials. RFC 9000 §6 / RFC 8999 §6: any long-header packet
    /// whose declared version isn't in this list earns a Version
    /// Negotiation response listing the configured set. Must be
    /// non-empty.
    ///
    /// Defaults to `&.{ 0x00000001 }` (QUIC v1 only) so v0.x embedders
    /// keep the same wire posture they had before RFC 9368 v2 support
    /// landed. Adding `0x6b3343cf` (`quic_zig.QUIC_VERSION_2`) opts
    /// the server into v2: incoming v2 Initials are accepted under
    /// the §3.3.1 salt + §3.3.2 labels, outgoing Retries / VN frames
    /// echo the negotiated version, and the optional
    /// `version_information` (codepoint 0x11) transport parameter
    /// advertises the full list to the peer for compatible-version
    /// upgrade.
    versions: []const u32 = &.{0x00000001},

    /// RFC 8899 DPLPMTUD configuration applied to every accepted
    /// connection. The default config (1200 floor, 1452 ceiling,
    /// 64-byte step, 3-strike threshold, enabled) matches the
    /// QUIC v1 minimum-MTU floor and the typical 1500-byte internet
    /// MTU. Set `enable = false` to keep the historical static-MTU
    /// behaviour (PMTU stays at `initial_mtu`).
    pmtud: conn_mod.PmtudConfig = .{},

    /// RFC 9000 §18.2 / §5.1.1 server preferred-address advertisement.
    /// Null disables the feature (default — no `preferred_address`
    /// transport parameter is sent and clients have no server-driven
    /// post-handshake migration target).
    ///
    /// When set, every accepted connection's outbound transport
    /// parameters carry a `preferred_address` value pointing at the
    /// configured IPv4 / IPv6 address pair. The seq-1 server CID +
    /// stateless reset token the parameter embeds is minted per-
    /// connection through `mintLocalScid` + `conn.stateless_reset.derive`,
    /// and queued on the connection as a NEW_CONNECTION_ID(seq=1)
    /// equivalent so post-migration packets the client addresses
    /// to the alt-CID authenticate. **Requires
    /// `Config.stateless_reset_key`**; without it `Server.init`
    /// returns `InvalidConfig` (the deterministic token derivation
    /// is the only path quic_zig surfaces for the seq-1 token).
    ///
    /// `runUdpServer` consults this field to also bind alt listener
    /// socket(s) on the configured port(s), poll all bound sockets
    /// per iteration, and route outbound replies through the socket
    /// the slot most recently received on. Embedders driving their
    /// own loop are responsible for the multi-socket plumbing —
    /// the codec auto-build still applies.
    preferred_address: ?PreferredAddressConfig = null,
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
    /// `setTraceContext`; quic_zig itself never reads it.
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
    /// True once this slot has queued its single NEW_TOKEN frame.
    /// `Server.feed` flips this on the first datagram routed to a
    /// slot whose connection has just confirmed the handshake (so
    /// every subsequent datagram skips the mint cost). Stays false
    /// for the slot's lifetime when `Server.new_token_key` is null.
    new_token_emitted: bool = false,

    /// RFC 9368 §6 multi-Initial pre-parse state. Non-null only while
    /// a multi-version server is still waiting for a fragmented
    /// ClientHello to complete so it can decide on a compatible-
    /// version upgrade. Allocated at slot-open time when
    /// `openSlotFromInitial`'s single-shot pre-parse reports the CH
    /// is incomplete; freed once the CH completes (decision applied)
    /// or the per-slot Initial budget is exhausted (fallback to wire
    /// version). Stays null for the rest of the slot's life — it is
    /// strictly a bootstrap construct.
    pending_upgrade: ?*PendingUpgradeState = null,

    /// Index into the `runUdpServer`-owned listener-socket array
    /// recording which socket most recently received an authenticated
    /// datagram for this slot. 0 = primary socket; 1+ = alt-listener
    /// sockets the loop bound from `Config.preferred_address`. The
    /// outbound drain consults this so replies follow the path the
    /// peer is currently sending on (RFC 9000 §5.1.1 server-initiated
    /// migration: pre-migration the client addresses the primary
    /// socket; post-migration it addresses the preferred-address
    /// alt-port). Embedders running their own loop ignore this
    /// field; nothing in the core transport reads it.
    last_recv_socket_idx: u8 = 0,

    /// Attach a W3C tracecontext to this slot. Embedders typically
    /// call this after `Server.feed` returns `.accepted` and the
    /// upstream service has assigned trace identifiers. quic_zig does
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

/// RFC 9368 §6 multi-Initial pre-parse buffer. Owned by the slot;
/// dropped once the CH completes or the Initial-packet budget runs
/// out. Sized to hold the largest CH the pre-parse will accept
/// (`vneg_preparse.max_client_hello_bytes`); together with the
/// reassembler's bookkeeping that is roughly 4 KiB per pending slot.
///
/// DoS posture: the reassembler is created lazily and destroyed
/// eagerly — a flood of new Initials still pays the global slot
/// quota and the per-source rate limiter, and each pending state
/// burns at most `max_initial_packets` packets of decryption work
/// before falling back to the wire version. There is no unbounded
/// per-CID accumulation.
const PendingUpgradeState = struct {
    /// Maximum number of client Initials we will decrypt to drive
    /// the upgrade decision before giving up and committing to the
    /// wire version. Real CHs split across at most 2-3 Initials in
    /// practice; 4 keeps a margin without letting a peer churn the
    /// pre-parse path indefinitely.
    pub const max_initial_packets: u8 = 4;

    /// Backing storage for the assembled CH. The reassembler borrows
    /// this slice via `init`.
    ch_buf: [wire.vneg_preparse.max_client_hello_bytes]u8 = undefined,
    /// Per-slot reassembler. Holds segment bookkeeping plus a
    /// pointer back into `ch_buf`.
    rc: wire.vneg_preparse.ChReassembler,
    /// Number of Initials we've already consumed for this slot's
    /// upgrade decision. Bumps on every routed datagram fed through
    /// `advancePendingUpgrade` and on the slot-creating Initial when
    /// `openPendingUpgrade` seeds the reassembler. Bounded by
    /// `max_initial_packets`.
    initials_seen: u8 = 0,
    /// The wire version the FIRST Initial arrived under. Subsequent
    /// Initials decrypted by the pre-parse use the same Initial-key
    /// derivation; if the peer flipped versions mid-flight (which
    /// would be a peer bug), `openInitial` will fail authentication
    /// and the pre-parse falls back gracefully.
    wire_version: u32,

    fn init(self: *PendingUpgradeState, wire_version: u32) void {
        self.* = .{
            .rc = wire.vneg_preparse.ChReassembler.init(&self.ch_buf),
            .wire_version = wire_version,
        };
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
    /// that is not in `Config.versions`. A Version Negotiation
    /// response was queued for the embedder to drain via
    /// `drainStatelessResponse`. No `Connection` was created.
    /// RFC 9000 §6 / RFC 8999 §6 / RFC 9368 §6.
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
    /// QUIC-LB factory built from `Config.quic_lb` at `init` time.
    /// Null when QUIC-LB is disabled; in that case all SCIDs are
    /// drawn directly from BoringSSL's CSPRNG (the secure-by-default
    /// path). When set, both initial-Slot SCIDs (in
    /// `openSlotFromInitial`) and Retry SCIDs (in
    /// `mintAndQueueRetry`) flow through `lb_factory.mint`.
    lb_factory: ?lb_mod.Factory,
    /// Stateless-reset HMAC key from `Config.stateless_reset_key`.
    /// `secureZero`-ed in `deinit`. When set, `installLbConfig`
    /// auto-pushes NEW_CONNECTION_ID frames to live slots; null
    /// means rotation is "lazy" (peers retain existing CIDs until
    /// they organically retire).
    stateless_reset_key: ?conn_mod.stateless_reset.Key,
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
    /// Captured `Config.max_vn_per_source_per_window`. Null disables
    /// the per-source VN rate limit; otherwise gates VN emission via
    /// the same `source_rate_table` (separate counter pair).
    max_vn_per_source: ?u32,

    /// Per-source Retry bookkeeping. Empty when Retry is disabled.
    /// One entry per peer that earned a Retry packet, dropped once
    /// the peer either successfully validates and a Slot opens
    /// (post-Retry SCID rotates into `cid_table`) or the entry is
    /// evicted on table overflow.
    retry_state_table: std.AutoHashMapUnmanaged(Address, RetryStateEntry) = .empty,
    retry_token_key: ?RetryTokenKey,
    retry_token_lifetime_us: u64,
    retry_state_table_capacity: u32,

    /// Captured `Config.new_token_key`. Null disables NEW_TOKEN
    /// issuance. Hardening guide §4.3 / RFC 9000 §8.1.3.
    new_token_key: ?conn_mod.NewTokenKey,
    /// Captured `Config.new_token_lifetime_us`. Only consulted when
    /// `new_token_key` is non-null.
    new_token_lifetime_us: u64,

    /// Captured `Config.enable_0rtt` from `init`. Drives the
    /// `early_data_enabled` knob on TLS contexts auto-built by
    /// `replaceTlsContext({.pem = ...})` so reloads preserve the
    /// original 0-RTT posture without forcing the embedder to pass
    /// it again.
    enable_0rtt: bool,

    /// Captured `Config.early_data_anti_replay`. Drives the
    /// `bumpClock` call in `feed` so the BoringSSL trampoline has
    /// the latest `now_us` to consult in its
    /// `consumeUsingInternalClock` call.
    early_data_anti_replay: ?*tls_mod.anti_replay.AntiReplayTracker,

    /// Captured `Config.reveal_close_reason_on_wire` — applied to
    /// every Connection the Server creates so the close-reason
    /// redaction posture matches the embedder's choice.
    reveal_close_reason_on_wire: bool,

    /// Captured `Config.max_connection_memory` — threaded onto every
    /// Connection at slot-open time so `tryReserveResidentBytes` has
    /// a per-connection cap. Hardening guide §3.5 / §8.
    max_connection_memory: u64,

    /// Captured `Config.delayed_ack_packet_threshold` — threaded onto
    /// every Connection at slot-open time. RFC 9000 §13.2.1.
    delayed_ack_packet_threshold: u8,

    /// Captured `Config.enable_ecn` — threaded onto every Connection
    /// at slot-open time. RFC 9000 §13.4 IETF ECN signaling. Default
    /// true; flip to false in environments known to bleach ECN bits.
    ecn_enabled: bool,
    /// Captured `Config.pmtud` — applied to every Connection at
    /// slot-open time. RFC 8899 DPLPMTUD.
    pmtud_config: conn_mod.PmtudConfig,

    /// Captured `Config.preferred_address` — used by `openSlotFromInitial`
    /// to auto-build the `preferred_address` transport parameter for
    /// every accepted connection (RFC 9000 §18.2 / §5.1.1) and by
    /// `runUdpServer` to bind alt listener sockets. Null when the
    /// feature is disabled (default).
    preferred_address: ?PreferredAddressConfig,

    /// Captured `Config.max_datagrams_per_window`. Null disables the
    /// listener-level packet rate limit; otherwise gates *every*
    /// inbound datagram (existing-slot routes included) at the very
    /// top of `feed`. Hardening guide §4.1.
    max_datagrams_per_window: ?u32,
    /// Captured `Config.max_bytes_per_window`. Null disables the
    /// listener-level byte rate limit; otherwise gates *every* inbound
    /// datagram by total bytes accumulated within the shared window.
    /// Runs after the packet-count gate at the top of `feed`.
    /// Hardening guide §4.1.
    max_bytes_per_window: ?u64,
    /// Captured `Config.listener_rate_window_us`. Window length shared
    /// by `max_datagrams_per_window` and `max_bytes_per_window`.
    listener_rate_window_us: u64,
    /// Sliding-window counters for the listener-level caps. Single
    /// global bucket per counter, sharing one window — no per-source
    /// bookkeeping, so they stay cheap even under floods from many
    /// sources.
    listener_rate_count: u32 = 0,
    bytes_in_window: u64 = 0,
    listener_rate_window_start_us: u64 = 0,
    /// Captured `Config.max_bytes_per_source_per_second`. Null disables
    /// the per-source bandwidth shaper; when set, every datagram that
    /// the global listener gates approve charges `bytes.len` against
    /// the source's token bucket (one second's burst capacity, refills
    /// at the configured rate). Hardening guide §4.1 token-bucket.
    max_bytes_per_source_per_second: ?u64,

    /// Captured `Config.max_log_events_per_source_per_window`. Null
    /// disables the per-source log rate limit. Hardening guide §9.4.
    max_log_events_per_source: ?u32,

    /// Captured `Config.versions`. Drives both the Version Negotiation
    /// gate (any inbound long-header packet whose declared version is
    /// not in this list earns a VN response listing the entries here)
    /// and the per-Initial version selection in `openSlotFromInitial`
    /// (the slot's connection adopts the matching incoming version).
    versions: []const u32,

    /// Snapshot of the most recent `feed`'s `now_us` argument. Threaded
    /// to `emitLog` so the per-source log rate limit fires its sliding
    /// window against in-feed time even though `emitLog` itself takes
    /// no clock argument. Set at the top of every `feed`; reads are
    /// only valid inside the feed's call frame.
    last_feed_now_us: u64 = 0,

    /// IP-layer ECN codepoint observed on the datagram currently being
    /// processed by `feedWithEcn`. Threaded to `dispatchToSlot` so the
    /// per-Connection `handleWithEcn` call gets the right marking.
    /// `not_ect` outside an active feed; mutating outside `feed*`
    /// (e.g. via test scaffolding) is undefined behavior.
    last_feed_ecn: conn_mod.state.socket_opts_mod.EcnCodepoint = .not_ect,

    /// Bounded FIFO of stateless responses (VN, Retry) queued for
    /// the embedder to drain via `drainStatelessResponse`. Bounded
    /// at `stateless_response_queue_capacity`; on overflow the
    /// oldest entry is evicted to keep ingest latency bounded.
    stateless_responses: std.ArrayList(StatelessResponse) = .empty,

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
    feeds_initial_too_small: u64 = 0,
    feeds_vn_rate_limited: u64 = 0,
    /// Datagrams dropped at the listener-level packet rate limit
    /// (`Config.max_datagrams_per_window`). Subset of `feeds_dropped`.
    /// Spiking values point at a flood-style attack.
    feeds_listener_rate_limited: u64 = 0,
    /// Datagrams dropped at the listener-level byte rate limit
    /// (`Config.max_bytes_per_window`). Subset of `feeds_dropped`.
    /// Spiking values point at a few-but-large bandwidth flood.
    feeds_listener_byte_rate_limited: u64 = 0,
    /// Datagrams dropped at the per-source bandwidth shaper
    /// (`Config.max_bytes_per_source_per_second`). Subset of
    /// `feeds_dropped`. Spiking values point at a single-source
    /// bandwidth abuser that the global listener cap is wide enough
    /// to let through. Hardening guide §4.1 token-bucket.
    feeds_source_bandwidth_limited: u64 = 0,
    /// LogEvents dropped by the per-source log rate limiter
    /// (`Config.max_log_events_per_source_per_window`). NOT a subset
    /// of `feeds_dropped` — log emission is a separate side effect
    /// from datagram disposition.
    feeds_log_rate_limited: u64 = 0,
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
        if (config.max_vn_per_source_per_window) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_window_us == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.retry_token_key != null) {
            if (config.retry_token_lifetime_us == 0) return Error.InvalidConfig;
            if (config.retry_state_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.new_token_key != null) {
            // NEW_TOKEN with a zero lifetime would expire on the next
            // microsecond — the feature degenerates into "always
            // invalid" but the embedder might never notice. Treat
            // that as misconfiguration.
            if (config.new_token_lifetime_us == 0) return Error.InvalidConfig;
        }
        // Hardening guide §4.1: cap=0 is meaningless for the listener
        // rate limits — it would drop every datagram. Surface it as
        // `InvalidConfig` instead of letting it silently DoS the
        // server itself.
        if (config.max_datagrams_per_window) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.listener_rate_window_us == 0) return Error.InvalidConfig;
        }
        if (config.max_bytes_per_window) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.listener_rate_window_us == 0) return Error.InvalidConfig;
        }
        // Hardening guide §4.1 token-bucket: cap=0 is meaningless —
        // it would drop every datagram. Surface it as `InvalidConfig`
        // instead of letting it silently DoS the server. The shaper
        // shares the `source_rate_table` with `acceptSourceRate` /
        // `acceptVnRate` / `acceptLogRate`, so the same capacity bound
        // applies; explicit checks here mirror those helpers' shape.
        if (config.max_bytes_per_source_per_second) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.max_log_events_per_source_per_window) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_window_us == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.quic_lb) |lb_cfg| {
            // Per-field and combined-length bounds from
            // draft-ietf-quic-load-balancers-21 §3 (server_id 1..15,
            // nonce 4..18, combined ≤ 19, config_id 0..6). Surface as
            // `InvalidConfig` so the failure mode matches every other
            // bad-Config case in `Server.init`. All three encoder
            // modes (§5.2 plaintext, §5.4.1 single-pass, §5.4.2
            // four-pass) are now wired — `Factory.mint` dispatches on
            // `(key, combined)` automatically.
            lb_cfg.validate() catch return Error.InvalidConfig;
        }
        // RFC 9000 §18.2 / §5.1.1: a `preferred_address` advertisement
        // requires a stateless-reset key so the seq-1 reset token in
        // the parameter matches the token a future stateless-reset on
        // the alt-CID would produce. The parameter must also point at
        // at least one address — both families null is a misconfiguration.
        if (config.preferred_address) |pa_cfg| {
            if (pa_cfg.ipv4 == null and pa_cfg.ipv6 == null) {
                return Error.InvalidConfig;
            }
            if (config.stateless_reset_key == null) {
                return Error.InvalidConfig;
            }
        }

        // Resolve the on-wire CID length and the transport parameters
        // we'll commit to. With QUIC-LB enabled, the CID length is
        // dictated by the LB configuration (1 + server_id_len +
        // nonce_len), and plaintext mode triggers the SHOULD from
        // draft §3 ¶3 to advertise `disable_active_migration` so peers
        // don't mint extra CIDs through this server (the unkeyed CIDs
        // would leak `server_id` directly on every NEW_CONNECTION_ID).
        var resolved_transport_params = config.transport_params;
        const resolved_local_cid_len: u8 = if (config.quic_lb) |lb_cfg| blk: {
            if (lb_cfg.isPlaintext() and !resolved_transport_params.disable_active_migration) {
                resolved_transport_params.disable_active_migration = true;
            }
            break :blk lb_cfg.cidLength();
        } else config.local_cid_len;

        // Build the LB factory before any allocation so an AES key
        // setup or CSPRNG-seeded nonce-counter failure short-circuits
        // before we own anything that needs cleanup. Errors are mapped
        // to existing Server-level codes — `AesKeyInvalid` to
        // `InvalidConfig` (the supplied `[16]u8` was somehow refused),
        // CSPRNG draws to `RandFailed`.
        const resolved_lb_factory: ?lb_mod.Factory = if (config.quic_lb) |lb_cfg| blk: {
            const f = lb_mod.Factory.initUnchecked(lb_cfg) catch |err| switch (err) {
                error.AesKeyInvalid => return Error.InvalidConfig,
                error.RandFailure => return Error.RandFailed,
                error.InvalidLbConfig => return Error.InvalidConfig,
                error.BufferTooSmall, error.NonceExhausted => unreachable,
            };
            break :blk f;
        } else null;

        // The version list drives the VN gate and per-slot version
        // adoption; an empty list would mean the server rejects every
        // inbound Initial, which is almost never what an embedder
        // wants. Every entry must be a wire-format version we know
        // how to derive Initial keys for (RFC 9001 §5.2 v1 / RFC
        // 9368 §3.3.1 v2). Reject `version == 0` outright because
        // the wire reserves it for Version Negotiation packets.
        if (config.versions.len == 0) return Error.InvalidConfig;
        for (config.versions) |v| {
            if (v == 0) return Error.InvalidConfig;
            if (!wire.initial.isSupportedVersion(v)) return Error.InvalidConfig;
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
            // Hardening §5.2 / RFC 9001 §5.6: when the embedder
            // installs an `AntiReplayTracker`, hook BoringSSL's
            // pre-resumption early-data callback so duplicate 0-RTT
            // attempts are rejected at the TLS layer (not just at
            // application post-handshake). Only fires on the
            // auto-built path; override-mode embedders own the hook
            // themselves.
            if (config.enable_0rtt and config.early_data_anti_replay != null) {
                try tls_ctx.setAllowEarlyDataCallback(
                    antiReplayEarlyDataTrampoline,
                    @ptrCast(config.early_data_anti_replay.?),
                );
            }
            owns_tls = true;
        }

        // SCIDs and Retry SCIDs are minted directly from BoringSSL's
        // CSPRNG — see `mintLocalCid` / `mintAndQueueRetry`. There is
        // no PRNG-from-seed cache: each ID is a fresh
        // `crypto.rand.fillBytes` call so an attacker observing
        // server-issued CIDs can't predict future ones from a finite
        // PRNG state. (Hardening guide §4.5.)

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
            .transport_params = resolved_transport_params,
            .max_concurrent_connections = config.max_concurrent_connections,
            .local_cid_len = resolved_local_cid_len,
            .lb_factory = resolved_lb_factory,
            .stateless_reset_key = config.stateless_reset_key,
            .qlog_callback = config.qlog_callback,
            .qlog_user_data = config.qlog_user_data,
            .log_callback = config.log_callback,
            .log_user_data = config.log_user_data,
            .slots = slots,
            .cid_table = cid_table,
            .source_rate_table = .empty,
            .max_initials_per_source = config.max_initials_per_source_per_window,
            .max_vn_per_source = config.max_vn_per_source_per_window,
            .source_rate_window_us = config.source_rate_window_us,
            .source_rate_table_capacity = config.source_rate_table_capacity,
            .retry_state_table = .empty,
            .retry_token_key = config.retry_token_key,
            .retry_token_lifetime_us = config.retry_token_lifetime_us,
            .retry_state_table_capacity = config.retry_state_table_capacity,
            .new_token_key = config.new_token_key,
            .new_token_lifetime_us = config.new_token_lifetime_us,
            .enable_0rtt = config.enable_0rtt,
            .early_data_anti_replay = config.early_data_anti_replay,
            .reveal_close_reason_on_wire = config.reveal_close_reason_on_wire,
            .max_connection_memory = config.max_connection_memory,
            .delayed_ack_packet_threshold = config.delayed_ack_packet_threshold,
            .ecn_enabled = config.enable_ecn,
            .max_datagrams_per_window = config.max_datagrams_per_window,
            .max_bytes_per_window = config.max_bytes_per_window,
            .listener_rate_window_us = config.listener_rate_window_us,
            .max_bytes_per_source_per_second = config.max_bytes_per_source_per_second,
            .max_log_events_per_source = config.max_log_events_per_source_per_window,
            .versions = config.versions,
            .pmtud_config = config.pmtud,
            .preferred_address = config.preferred_address,
            .stateless_responses = .empty,
        };
    }

    /// Install a new QUIC-LB configuration. Subsequent SCID mints
    /// (post-Initial Slot SCIDs and Retry SCIDs) use the new
    /// configuration; the previous factory's key bytes are
    /// `secureZero`-ed before the swap.
    ///
    /// **If `Config.stateless_reset_key` was provided**, this method
    /// ALSO pushes a NEW_CONNECTION_ID frame to every live slot via
    /// `rotateLiveSlotCids`, so peers retire their old CIDs and
    /// migrate to the new-config CIDs on their next datagram. Per-
    /// slot push failures are swallowed (best-effort) — the factory
    /// swap commits regardless.
    ///
    /// **Without `stateless_reset_key`**, the swap is point-in-time
    /// and peers continue using their existing CIDs until they
    /// organically retire them via the existing `connection_ids_needed`
    /// event flow.
    ///
    /// To keep the routing key shape stable for the slot table and
    /// `peekDcidForServer`, the new configuration MUST mint CIDs of
    /// the same length as the configuration the Server was built with
    /// (`Server.local_cid_len`). Mismatched lengths surface as
    /// `Error.InvalidConfig`. This restriction matches typical
    /// rotation flows (key rotation under a fixed deployment shape).
    ///
    /// Errors:
    ///   * `InvalidConfig` — `LbConfig.validate` failed, or the
    ///     resolved `cidLength` doesn't match the server's existing
    ///     `local_cid_len`, or the previous Server was built without
    ///     a `quic_lb` configuration (no factory to rotate).
    ///   * `RandFailed` — CSPRNG nonce-counter seed failed.
    pub fn installLbConfig(self: *Server, new_cfg: lb_mod.LbConfig) Error!void {
        new_cfg.validate() catch return Error.InvalidConfig;
        if (self.lb_factory == null) return Error.InvalidConfig;
        if (new_cfg.cidLength() != self.local_cid_len) return Error.InvalidConfig;

        const new_factory = lb_mod.Factory.initUnchecked(new_cfg) catch |err| switch (err) {
            error.AesKeyInvalid => return Error.InvalidConfig,
            error.RandFailure => return Error.RandFailed,
            error.InvalidLbConfig => return Error.InvalidConfig,
            error.BufferTooSmall, error.NonceExhausted => unreachable,
        };
        if (self.lb_factory) |*old| old.deinit();
        self.lb_factory = new_factory;

        // Auto-push to live peers. No-op without a stateless-reset
        // key (token derivation needs one); embedders running
        // without the key drive replenishment manually via
        // `connection_ids_needed`.
        if (self.stateless_reset_key != null) {
            _ = self.rotateLiveSlotCids();
        }
    }

    /// Push a fresh NEW_CONNECTION_ID frame to every live slot using
    /// the active LB factory and the configured stateless-reset key.
    /// Each pushed frame's `retire_prior_to` invalidates every
    /// previously-issued local CID on that slot, so the peer
    /// switches to the new CID on its next datagram.
    ///
    /// Returns the number of slots that successfully received a new
    /// CID. Per-slot failures (no LB factory, no stateless-reset
    /// key, CID-issue budget exhausted, factory mint failure,
    /// HMAC error, replenishment rejected) are swallowed so a single
    /// bad slot doesn't abort the rotation. Pre-handshake slots
    /// receive the queued frame but don't transmit it until they
    /// reach 1-RTT — NEW_CONNECTION_ID is a §12.4 / §17 1-RTT-only
    /// frame.
    ///
    /// `installLbConfig` calls this automatically when
    /// `Config.stateless_reset_key` is set; embedders typically
    /// reach for it directly only when proactively pushing CIDs
    /// without a config swap.
    pub fn rotateLiveSlotCids(self: *Server) usize {
        const factory_ptr = if (self.lb_factory) |*f| f else return 0;
        const key = self.stateless_reset_key orelse return 0;

        var rotated: usize = 0;
        for (self.slots.items) |slot| {
            if (slot.conn.isClosed()) continue;
            if (slot.conn.localConnectionIdIssueBudget(0) == 0) continue;

            var cid_buf: [20]u8 = undefined;
            const cid_slice = cid_buf[0..self.local_cid_len];
            _ = factory_ptr.mint(cid_slice) catch continue;

            const token = conn_mod.stateless_reset.derive(&key, cid_slice) catch continue;
            const next_seq = slot.conn.nextLocalConnectionIdSequence(0);
            const provision = conn_mod.ConnectionIdProvision{
                .connection_id = cid_slice,
                .stateless_reset_token = token,
                .retire_prior_to = next_seq,
            };
            _ = slot.conn.replenishConnectionIds(&[_]conn_mod.ConnectionIdProvision{provision}) catch continue;

            // Bring the routing table in line with the slot's new
            // active-CID set so the new CID becomes routable on
            // the next inbound datagram. Failures here leave the
            // CID in the connection but unreachable until the next
            // organic resync — log via the standard error path
            // by skipping the rotation count.
            self.resyncSlotCids(slot) catch continue;
            rotated += 1;
        }
        return rotated;
    }

    pub fn deinit(self: *Server) void {
        for (self.slots.items) |slot| {
            slot.conn.deinit();
            self.allocator.destroy(slot.conn);
            if (slot.pending_upgrade) |pu| self.allocator.destroy(pu);
            self.allocator.destroy(slot);
        }
        self.slots.deinit(self.allocator);
        self.cid_table.deinit(self.allocator);
        self.source_rate_table.deinit(self.allocator);
        self.retry_state_table.deinit(self.allocator);
        self.stateless_responses.deinit(self.allocator);
        // Hardening guide §3.5 / §9.4: zero the Retry-token HMAC key
        // before the `Server` struct is released. Even though the
        // memory is about to leave scope, the optimizer can't elide
        // a volatile-backed `secureZero`, so the key bytes don't
        // linger in a freed allocation that the host allocator might
        // reuse for unrelated data (or surface in a core dump).
        if (self.retry_token_key) |*key| {
            std.crypto.secureZero(u8, key[0..]);
        }
        // Same hardening rationale for the NEW_TOKEN AES-GCM-256
        // key — a peer-mintable token's worth of crypto state must
        // not linger after the Server struct is freed.
        if (self.new_token_key) |*key| {
            std.crypto.secureZero(u8, key[0..]);
        }
        // Same for the QUIC-LB encryption key — `Factory.deinit`
        // zeros the embedded `LbConfig.key` and the nonce counter
        // buffer. No-op for plaintext-mode factories (key was null).
        if (self.lb_factory) |*factory| {
            factory.deinit();
        }
        // And the stateless-reset HMAC key — same hardening
        // rationale as the other secret key fields.
        if (self.stateless_reset_key) |*key| {
            std.crypto.secureZero(u8, key[0..]);
        }
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
        return self.feedWithEcn(bytes, from, .not_ect, now_us);
    }

    /// Like `feed`, but also carries the IP-layer ECN codepoint the
    /// embedder peeled off the datagram's TOS byte. The codepoint
    /// flows down to `Connection.handleWithEcn` so per-PN-space ECN
    /// counters can be bumped on successful decrypt (RFC 9000
    /// §13.4.1). Embedders that aren't running cmsg parsing should
    /// keep using `feed` (which passes `not_ect`).
    pub fn feedWithEcn(
        self: *Server,
        bytes: []u8,
        from: ?Address,
        ecn: conn_mod.state.socket_opts_mod.EcnCodepoint,
        now_us: u64,
    ) Error!FeedOutcome {
        // Set the ingress ECN for any subsequent dispatch into a
        // slot's Connection. Stateless / pre-slot processing
        // (Version Negotiation, Retry minting, table_full) doesn't
        // care about the marking — only the per-Connection handlers
        // do. Cleared at function exit so a malformed/dropped feed
        // doesn't leave a stale codepoint visible to the next call.
        self.last_feed_ecn = ecn;
        defer self.last_feed_ecn = .not_ect;
        // Stamp the feed's `now_us` so `emitLog` can run its per-source
        // log rate limit against in-feed time without taking a separate
        // clock argument.
        self.last_feed_now_us = now_us;
        // Push the same `now_us` to the anti-replay tracker so its
        // BoringSSL `allow_early_data` trampoline (which has no other
        // path to a monotonic clock) ages entries against
        // Server-driven time. No-op when 0-RTT or anti-replay isn't
        // configured.
        if (self.early_data_anti_replay) |tracker| tracker.bumpClock(now_us);
        // Hardening guide §4.1: listener-level packet + byte rate
        // limits. Runs *before* the empty-bytes check, before the
        // 1200-byte Initial size gate, before slot lookup — every
        // datagram entering the server passes here so a flood from
        // many sources can't bleed through any of the per-source /
        // per-slot gates downstream. Single global bucket on a
        // sliding-by-reset window shared by both caps: cheap, and
        // good enough for DoS deflection (the per-source gates own
        // attribution; this owns the firehose).
        //
        // Order is packet-count first, byte-budget second so a
        // few-but-large flood that also exceeds the packet cap is
        // accounted to the packet counter (the cheaper signal to
        // alert on).
        if (self.max_datagrams_per_window != null or self.max_bytes_per_window != null) {
            const elapsed = now_us -% self.listener_rate_window_start_us;
            const window_reset =
                elapsed >= self.listener_rate_window_us or
                (self.listener_rate_count == 0 and self.bytes_in_window == 0);
            if (window_reset) {
                self.listener_rate_count = 0;
                self.bytes_in_window = 0;
                self.listener_rate_window_start_us = now_us;
            }
            if (self.max_datagrams_per_window) |cap| {
                if (self.listener_rate_count >= cap) {
                    self.feeds_listener_rate_limited += 1;
                    self.feeds_dropped += 1;
                    return .dropped;
                }
                self.listener_rate_count += 1;
            }
            if (self.max_bytes_per_window) |cap| {
                // Increment before the gate so the gate fires on the
                // byte that would push the budget over, not after.
                self.bytes_in_window += bytes.len;
                if (self.bytes_in_window > cap) {
                    self.feeds_listener_byte_rate_limited += 1;
                    self.feeds_dropped += 1;
                    return .dropped;
                }
            }
        }
        if (bytes.len == 0) {
            self.feeds_dropped += 1;
            return .dropped;
        }

        // Hardening guide §4.1 token-bucket: per-source bandwidth
        // shaper. Runs after the global listener gates (so the global
        // aggregate ceiling still bounds total bandwidth even when
        // every source has a full bucket) but before slot lookup (so
        // an in-flight handshake datagram from a misbehaving source
        // is gated too). Charge happens only when `from` is provided
        // — null-source feeds bypass the limiter for the same reason
        // as the per-source Initial / VN / log gates.
        if (self.max_bytes_per_source_per_second) |cap| {
            if (from) |addr| {
                if (!self.acceptSourceBandwidth(addr, bytes.len, cap, now_us)) {
                    self.feeds_source_bandwidth_limited += 1;
                    self.feeds_dropped += 1;
                    // Reuse `feed_rate_limited`: `recent_count` carries
                    // the dropped datagram's byte length so embedders
                    // can correlate the log with the bucket-empty
                    // condition without a new variant.
                    self.emitLog(.{ .feed_rate_limited = .{
                        .peer = addr,
                        .recent_count = std.math.lossyCast(u32, bytes.len),
                    } });
                    return .dropped;
                }
            }
        }

        // RFC 9000 §14: a server MUST discard a QUIC v1 Initial packet
        // carried in a UDP datagram with a payload smaller than 1200
        // bytes. Enforced *before* slot lookup so the rule applies
        // both to new-connection-creating Initials and to in-flight
        // handshake Initials that would otherwise route to an existing
        // slot.
        //
        // Gated on `Config.versions` membership so unsupported-version
        // probes still flow into the Version Negotiation path below
        // (whose response is governed by RFC 9000 §6, not §14). The
        // size check keys off the leading packet's long-header type
        // bits — coalesced datagrams whose first packet is Initial
        // are the typical adversarial pattern (single short Initial
        // used to mint server state cheaply); a pathological
        // inner-Initial would still ride a leading packet large
        // enough to push the datagram past 1200, so this covers the
        // practical attack surface.
        if (peekLongHeaderIds(bytes)) |ids| {
            if (isInitialLongHeader(bytes, ids.version) and
                bytes.len < conn_mod.state.min_quic_udp_payload_size and
                self.versionAccepted(ids.version))
            {
                self.feeds_initial_too_small += 1;
                self.feeds_dropped += 1;
                return .dropped;
            }
        }

        // Existing connection? Hash table lookup, O(1).
        if (self.findSlotForDatagram(bytes)) |slot| {
            slot.last_activity_us = now_us;
            if (from) |addr| slot.peer_addr = addr;
            // RFC 9368 §6: when a multi-Initial fragmented ClientHello
            // is in flight, the upgrade decision lands on a later
            // Initial than the slot-creating one. Try to advance the
            // pending reassembler before `dispatchToSlot` ingests this
            // datagram; if the CH completes here we update the
            // outbound transport_params (so the EE the server is about
            // to emit advertises chosen=upgrade) and stash the pending
            // version flip for `dispatchToSlot` to apply post-handle.
            //
            // Failure here is purely advisory — the pending state is
            // dropped and the connection continues under the wire
            // version, which is always spec-compliant.
            if (slot.pending_upgrade != null) {
                self.advancePendingUpgrade(slot, bytes);
            }
            try self.dispatchToSlot(slot, bytes, from, now_us);
            try self.resyncSlotCids(slot);
            // RFC 9000 §8.1.3: once the handshake is confirmed, the
            // server MAY issue NEW_TOKEN frames usable on the peer's
            // future first Initial. We emit exactly one per session
            // (the simplest policy that still removes the Retry
            // round-trip for returning clients); the slot's
            // `new_token_emitted` flag latches at first issuance.
            self.maybeIssueNewToken(slot, from, now_us);
            self.feeds_routed += 1;
            return .routed;
        }

        // Long-header packets reach the version-negotiation gate
        // first: any long-header packet whose declared version is
        // not in `Config.versions` earns a VN response, regardless
        // of the long-type bits. Per RFC 9000 §6 / RFC 9368 §6 this
        // catches non-Initial long-header probes (0-RTT, Handshake)
        // too.
        if (peekLongHeaderIds(bytes)) |ids| {
            if (!self.versionAccepted(ids.version)) {
                if (from) |addr| {
                    // Per-source VN-rate gate (hardening guide §4.4):
                    // legitimate clients fix their version and retry
                    // with one of our supported versions after one VN
                    // response, so even a small cap is non-disruptive.
                    // This blunts the VN-flood amplification surface
                    // where one source fills the global
                    // stateless-response queue.
                    if (self.max_vn_per_source) |cap| {
                        if (!self.acceptVnRate(addr, cap, now_us)) {
                            self.feeds_vn_rate_limited += 1;
                            self.feeds_dropped += 1;
                            self.emitLog(.{ .feed_rate_limited = .{
                                .peer = addr,
                                .recent_count = if (self.source_rate_table.get(addr)) |e| e.vn_count else cap,
                            } });
                            return .dropped;
                        }
                    }
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

        // New connection candidate: must be a long-header Initial
        // under one of our supported versions. The version-list gate
        // upstream already filtered unsupported versions to VN; here
        // we just translate the long-header type bits to an abstract
        // `LongType` and require Initial. We can't use `peekLongHeaderIds`
        // here because it rejects DCID-len > 20 — the source-rate
        // gate downstream wants to charge those datagrams too.
        if (bytes.len < 5 or (bytes[0] & 0x80) == 0) {
            self.feeds_dropped += 1;
            return .dropped;
        }
        const candidate_version = std.mem.readInt(u32, bytes[1..5], .big);
        if (!isInitialLongHeader(bytes, candidate_version)) {
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

        // Retry / NEW_TOKEN gate runs before the Connection is
        // allocated. `.sent` queues a Retry; `.drop` rejects a
        // wrong-source token; `.echo` accepts a Retry-validated
        // Initial; `.new_token_skip` accepts a NEW_TOKEN-validated
        // Initial directly (no Retry round-trip). `.none` is the
        // gate-disabled fall-through.
        var retry_ctx: ?RetryEcho = null;
        if (self.retry_token_key != null or self.new_token_key != null) {
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
                    .new_token_skip => {
                        // The peer presented a valid NEW_TOKEN; treat
                        // them as already address-validated and
                        // proceed to slot creation as if no Retry was
                        // ever required. No `retry_ctx` is set —
                        // there is no Retry SCID to bind to and the
                        // initial transport parameters skip the
                        // `retry_source_connection_id` echo.
                    },
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
        // Same NEW_TOKEN issuance check the routed path runs — a
        // pathological 0-RTT-only handshake might confirm in the
        // very first received datagram, in which case there is no
        // later "routed" feed to trip the issuance check.
        self.maybeIssueNewToken(slot, from, now_us);
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
    /// cheap — call it on every loop iteration. Terminal-closed slots
    /// are skipped (their deadlines have already fired and there's
    /// nothing more for `tick` to do); call `reap` periodically to
    /// reclaim them. RFC 9000 §10.2.1/§10.2.2 closing- and
    /// draining-state slots stay in the loop so their deadlines fire
    /// and the connection eventually transitions to terminal closed.
    pub fn tick(self: *Server, now_us: u64) ConnectionError!void {
        for (self.slots.items) |slot| {
            if (slot.conn.closeState() == .closed) continue;
            try slot.conn.tick(now_us);
        }
    }

    /// Reap any *terminally-closed* slots from the table. Returns the
    /// number of slots reclaimed. Iterates back-to-front and uses
    /// `swapRemove`, so reaping N closed slots is O(N), not O(N²).
    /// Each reaped slot drops every CID it owned from `cid_table`.
    /// If a reaped slot was opened against a draining TLS context,
    /// its draining-entry refcount is decremented; when the count
    /// reaches zero the draining context is `deinit`-ed and removed
    /// from `draining_tls_contexts`.
    ///
    /// RFC 9000 §10.2 ¶5 mandates that closing and draining states
    /// "SHOULD persist for at least three times the current PTO
    /// interval" — slots in those states are deliberately kept alive
    /// so a peer's late CC retransmit can still find the connection.
    pub fn reap(self: *Server) usize {
        var reaped: usize = 0;
        var i: usize = self.slots.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.slots.items[i];
            if (slot.conn.closeState() != .closed) continue;
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
            if (slot.pending_upgrade) |pu| self.allocator.destroy(pu);
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

    /// Fill `dst` (length `self.local_cid_len`) with a freshly-minted
    /// server-side SCID. With QUIC-LB enabled (`Config.quic_lb`), the
    /// bytes are produced by the configured `lb.Factory` so an
    /// external load balancer can decode the routing identity;
    /// otherwise the bytes come straight from BoringSSL's CSPRNG.
    /// Used by both `openSlotFromInitial` (initial Slot SCID) and
    /// `mintAndQueueRetry` (Retry SCID).
    /// Mint a fresh server SCID into `dst`. Three paths, in order of
    /// preference:
    ///
    ///   1. **No LB configured** — draw `dst.len` bytes from the
    ///      BoringSSL CSPRNG. Pure entropy on the wire; no metadata.
    ///   2. **LB configured, factory accepts** — defer to
    ///      `lb.Factory.mint`, which dispatches to plaintext,
    ///      single-pass AES, or four-pass Feistel based on
    ///      `(key, combined)`.
    ///   3. **LB configured, nonce counter exhausted** — fall back
    ///      to `lb.mintUnroutable` so the server keeps minting
    ///      well-formed CIDs (config_id `0b111`, length self-encoded)
    ///      until the operator rotates to a new configuration via
    ///      `installLbConfig`. The fallback requires
    ///      `local_cid_len >= lb.min_unroutable_cid_len` (8 octets);
    ///      configurations with shorter CIDs surface
    ///      `Error.RandFailed` instead.
    ///
    /// Public so the LB-5 conformance suite can exercise path (3)
    /// directly via white-box state manipulation. Embedders rarely
    /// need to call this — the Server's existing
    /// `openSlotFromInitial` and `mintAndQueueRetry` paths route
    /// through here automatically.
    pub fn mintLocalScid(self: *Server, dst: []u8) Error!void {
        if (self.lb_factory) |*factory| {
            const n = factory.mint(dst) catch |err| switch (err) {
                error.RandFailure => return Error.RandFailed,
                // Per draft §3 ¶3 / §3.1: when the active
                // configuration can no longer mint distinct CIDs the
                // server SHOULD switch to a new configuration or use
                // the unroutable fallback. Until the operator calls
                // `installLbConfig`, this branch keeps the server
                // alive by emitting unroutable CIDs that an LB can
                // route via its configured fallback path.
                error.NonceExhausted => {
                    if (dst.len < lb_mod.min_unroutable_cid_len) {
                        return Error.RandFailed;
                    }
                    _ = lb_mod.mintUnroutable(dst, @intCast(dst.len)) catch {
                        return Error.RandFailed;
                    };
                    return;
                },
                // `Server.init` already rejected ill-sized
                // configurations, and `local_cid_len` matches
                // `Factory.cidLength()` by construction. Reaching any
                // of these would mean an invariant upstream slipped —
                // surface as the generic SCID mint-failure code
                // rather than panicking, since the network-input path
                // must remain non-fatal.
                error.BufferTooSmall,
                error.InvalidLbConfig,
                error.AesKeyInvalid,
                => return Error.RandFailed,
            };
            std.debug.assert(n == dst.len);
            return;
        }
        try boringssl.crypto.rand.fillBytes(dst);
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
        conn_ptr.reveal_close_reason_on_wire = self.reveal_close_reason_on_wire;
        conn_ptr.max_connection_memory = self.max_connection_memory;
        conn_ptr.delayed_ack_packet_threshold = self.delayed_ack_packet_threshold;
        conn_ptr.ecn_enabled = self.ecn_enabled;
        // RFC 8899 DPLPMTUD: thread the embedder config to the
        // connection. setPmtudConfig also re-initialises every
        // existing path (only the primary at this point), so the
        // per-path pmtu / pmtu_state lands consistent with the config.
        conn_ptr.setPmtudConfig(self.pmtud_config);

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
            try self.mintLocalScid(server_scid[0..self.local_cid_len]);
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

        // RFC 9000 §18.2 / §5.1.1 `preferred_address` advertise. When
        // `Config.preferred_address` is set, mint a fresh seq-1 SCID
        // through the same `mintLocalScid` path as seq-0, derive the
        // accompanying stateless-reset token from the
        // `Config.stateless_reset_key` (Server.init's validation
        // guarantees the key is set whenever `preferred_address` is),
        // and stamp both into the outbound transport parameter so the
        // EE BoringSSL serializes carries the value verbatim. The
        // matching NEW_CONNECTION_ID(seq=1) is queued below, after
        // `acceptInitial` so the connection's local-CID table is
        // ready to register a sequence-1 entry.
        var pa_alt_cid_storage: [20]u8 = undefined;
        var pa_alt_cid_slice: ?[]u8 = null;
        var pa_alt_token: [16]u8 = @splat(0);
        if (self.preferred_address) |pa_cfg| {
            const slice = pa_alt_cid_storage[0..self.local_cid_len];
            try self.mintLocalScid(slice);
            const key = self.stateless_reset_key orelse unreachable;
            pa_alt_token = conn_mod.stateless_reset.derive(&key, slice) catch
                return Error.RandFailed;
            pa_alt_cid_slice = slice;
            params.preferred_address = buildPreferredAddressParam(pa_cfg, slice, pa_alt_token);
        }

        // RFC 9368 §5/§6: pre-parse the inbound Initial under wire-
        // version keys to extract the client's `version_information`
        // (codepoint 0x11) transport parameter, and intersect with
        // our configured `versions` list. The first server-preferred
        // version that also appears in the client's
        // `available_versions` is our `chosen_version`; if it differs
        // from the wire version, we upgrade.
        //
        // The pre-parse is purely advisory — any failure (auth fail,
        // fragmented ClientHello, missing extension, malformed
        // payload) returns `null` and we fall back to "use the wire
        // version", which is always spec-compliant. We never refuse a
        // connection because pre-parse failed.
        //
        // The decision MUST land BEFORE BoringSSL produces the EE
        // (which embeds our transport_parameters): RFC 9368 §5
        // requires `chosen_version` in the EE to match the version
        // of the server's first Initial response carrying it, so the
        // outbound transport_params must already say chosen=v_upgrade
        // when BoringSSL serializes the EE. We arrange that by:
        //   (a) running the pre-parse here, before `acceptInitial`,
        //   (b) building `params.compatibleVersions = [chosen, ...]`
        //       so the EE points at the upgrade target,
        //   (c) calling `acceptInitial`, which pushes those params to
        //       BoringSSL and (separately) sets `self.version` to the
        //       wire version so `handleInitial` opens this datagram
        //       under wire-version keys,
        //   (d) flipping `self.version` to `chosen` AFTER the first
        //       `handleWithEcn` returns (in `dispatchToSlot`), so
        //       outbound packets sealed by `poll` go out under the
        //       upgrade-target keys.
        var ch_complete: bool = false;
        const upgrade_target = self.preparseUpgradeTarget(bytes, ids.version, &ch_complete);
        const chosen_version: u32 = upgrade_target orelse ids.version;
        if (self.versions.len > 1) {
            var ordered: [16]u32 = undefined;
            ordered[0] = chosen_version;
            var n: usize = 1;
            for (self.versions) |v| {
                if (v == chosen_version) continue;
                if (n >= ordered.len) break;
                ordered[n] = v;
                n += 1;
            }
            try params.setCompatibleVersions(ordered[0..n]);
        }
        try conn_ptr.acceptInitial(bytes, params);
        // Stash the upgrade target so `dispatchToSlot` can flip
        // `self.version` after the first `handleWithEcn` consumes the
        // wire-version Initial under wire-version keys.
        if (upgrade_target) |upgraded| {
            if (upgraded != ids.version) {
                conn_ptr.setPendingVersionUpgrade(upgraded);
            }
        }

        // RFC 9368 §6 multi-Initial fallback: when the ClientHello
        // didn't fit in this single Initial and we're in multi-version
        // mode, attach a streaming reassembler so subsequent routed
        // Initials can drive the upgrade decision before BoringSSL
        // emits the EE. The reassembler is pre-seeded with this first
        // Initial's CRYPTO bytes so the next call to `feed` only has
        // to add what arrived later. Allocation or pre-seed failures
        // are non-fatal — the slot simply commits to the wire
        // version, which is always spec-compliant.
        const want_pending = !ch_complete and
            self.versions.len > 1 and
            wire.initial.isSupportedVersion(ids.version);
        var pending_upgrade: ?*PendingUpgradeState = null;
        if (want_pending) {
            pending_upgrade = self.openPendingUpgrade(bytes, ids.version);
        }
        errdefer if (pending_upgrade) |pu| self.allocator.destroy(pu);

        // Queue NEW_CONNECTION_ID(seq=1) carrying the alt-CID minted
        // for `preferred_address`. RFC 9000 §5.1.1 ¶6 says the client
        // treats the preferred-address `connection_id` as if it had
        // arrived in `NEW_CONNECTION_ID(seq=1)`; the server still
        // emits the matching frame on the wire, and the client's
        // `registerPeerCid` idempotently absorbs the duplicate. We
        // queue it AFTER `acceptInitial` so the connection's local-CID
        // table has its seq-0 entry already in place.
        if (pa_alt_cid_slice) |alt_cid| {
            const provision = conn_mod.ConnectionIdProvision{
                .connection_id = alt_cid,
                .stateless_reset_token = pa_alt_token,
            };
            // Propagate OOM (the broader feed loop expects to bubble
            // it). Any other failure (CID-issue budget saturated,
            // alt-CID collision with the seq-0 mint) silently skips
            // the queue: the transport parameter is still advertised,
            // and a post-migration packet bearing the unregistered
            // alt-CID will simply be dropped — pathological for the
            // server (a same-connection client whose
            // `active_connection_id_limit < 2` cannot follow the PA
            // anyway), no need to fail the handshake.
            _ = conn_ptr.replenishConnectionIds(&[_]conn_mod.ConnectionIdProvision{provision}) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            };
        }

        slot.* = .{
            .conn = conn_ptr,
            .initial_dcid = initial_dcid,
            .peer_addr = from,
            .last_activity_us = now_us,
            .slot_id = self.next_slot_id,
            .tls_generation = self.current_generation,
            .pending_upgrade = pending_upgrade,
            .last_recv_socket_idx = 0,
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
        // RFC 9000 §19.16 ¶3 plumbing: tell the connection which of
        // its locally-issued CIDs this datagram was addressed to,
        // so `handleRetireConnectionId` can reject a frame retiring
        // the in-use CID. `null` (no DCID match) leaves the gate
        // inert — that path is the pre-routing-table bootstrap case
        // for a brand-new Initial.
        const dcid_opt = peekDcidForServer(bytes, self.local_cid_len);
        const seq_opt: ?u64 = if (dcid_opt) |d| slot.conn.findLocalCidSequence(d) else null;
        slot.conn.setIncomingLocalCidSeq(seq_opt);
        defer slot.conn.setIncomingLocalCidSeq(null);
        slot.conn.handleWithEcn(bytes, from, self.last_feed_ecn, now_us) catch |err| switch (err) {
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
        // RFC 9368 §6 compatible-version-negotiation upgrade: the
        // wire-version Initial has now been opened under wire-version
        // keys and BoringSSL has consumed the ClientHello (producing
        // an EE that already embeds our chosen-version transport
        // params, since `openSlotFromInitial` set those before the
        // handshake advanced). Flip `self.version` to the upgrade
        // target so the next `poll` seals the response Initial under
        // the upgrade-target keys. Idempotent / no-op when no
        // upgrade was pending.
        _ = slot.conn.applyPendingVersionUpgrade();
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

    /// Per-source VN-emission rate gate. Mirrors `acceptSourceRate`
    /// but uses the entry's secondary `vn_count` / `vn_window_start_us`
    /// pair so VN floods don't burn the per-source Initial budget
    /// (and vice versa). Returns `true` when emission is permitted.
    fn acceptVnRate(
        self: *Server,
        addr: Address,
        cap: u32,
        now_us: u64,
    ) bool {
        // Lazy eviction shared with `acceptSourceRate`.
        if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
            self.pruneSourceRate(now_us);
            if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
                self.evictOldestSourceRate();
            }
        }

        const gop = self.source_rate_table.getOrPut(self.allocator, addr) catch {
            // OOM on the rate table: deny the VN rather than continue
            // unprotected. Mirrors `acceptSourceRate` policy.
            return false;
        };
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .count = 0,
                .window_start_us = 0,
                .vn_count = 1,
                .vn_window_start_us = now_us,
            };
            return true;
        }

        const elapsed = now_us -% gop.value_ptr.vn_window_start_us;
        if (elapsed >= self.source_rate_window_us) {
            gop.value_ptr.vn_count = 1;
            gop.value_ptr.vn_window_start_us = now_us;
            return true;
        }

        if (gop.value_ptr.vn_count >= cap) return false;
        gop.value_ptr.vn_count += 1;
        return true;
    }

    /// Per-source log-emission rate gate. Mirrors `acceptSourceRate`
    /// and `acceptVnRate` but uses the entry's tertiary
    /// `log_count` / `log_window_start_us` pair so log floods don't
    /// burn the Initial / VN budgets and vice versa. Returns `true`
    /// when emission is permitted.
    ///
    /// Hardening guide §9.4: a peer that triggers many feed-rate-limit
    /// or table-full or VN-rate-limit events from a single address
    /// would otherwise let the attacker flood the embedder's log
    /// pipeline (disk, stdout, structured-logging dependency, etc.).
    /// On a denial of `false`, the caller drops the LogEvent silently
    /// — there is no nested log about the dropped log.
    fn acceptLogRate(
        self: *Server,
        addr: Address,
        cap: u32,
        now_us: u64,
    ) bool {
        // Lazy eviction shared with `acceptSourceRate` / `acceptVnRate`.
        if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
            self.pruneSourceRate(now_us);
            if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
                self.evictOldestSourceRate();
            }
        }

        const gop = self.source_rate_table.getOrPut(self.allocator, addr) catch {
            // OOM on the rate table: deny the log rather than risk
            // unbounded emission. Mirrors `acceptSourceRate`.
            return false;
        };
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .count = 0,
                .window_start_us = 0,
                .log_count = 1,
                .log_window_start_us = now_us,
            };
            return true;
        }

        const elapsed = now_us -% gop.value_ptr.log_window_start_us;
        if (elapsed >= self.source_rate_window_us) {
            gop.value_ptr.log_count = 1;
            gop.value_ptr.log_window_start_us = now_us;
            return true;
        }

        if (gop.value_ptr.log_count >= cap) return false;
        gop.value_ptr.log_count += 1;
        return true;
    }

    /// Per-source bandwidth gate (token-bucket). Returns true when the
    /// `bytes_charged`-byte datagram is permitted; false when the
    /// bucket is empty. Mirrors `acceptSourceRate` / `acceptVnRate` /
    /// `acceptLogRate` in shape (lazy eviction, OOM-fail-closed) and
    /// shares the `source_rate_table`.
    ///
    /// The bucket is sized to one second of `cap_per_second`, refills
    /// at `cap_per_second` bytes/s up to that ceiling, and debits
    /// `bytes_charged` per accepted datagram. Hardening guide §4.1
    /// token-bucket: this is the per-source companion to the global
    /// sliding-window byte-rate cap. The shaper sits AFTER the global
    /// listener gates so the global aggregate ceiling still bounds
    /// total bandwidth even with every source's bucket full.
    fn acceptSourceBandwidth(
        self: *Server,
        addr: Address,
        bytes_charged: u64,
        cap_per_second: u64,
        now_us: u64,
    ) bool {
        // Lazy eviction shared with the rest of the per-source helpers.
        if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
            self.pruneSourceRate(now_us);
            if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
                self.evictOldestSourceRate();
            }
        }

        const gop = self.source_rate_table.getOrPut(self.allocator, addr) catch {
            // OOM on the rate table: deny the datagram rather than
            // continue unprotected. Mirrors `acceptSourceRate` policy.
            return false;
        };
        if (!gop.found_existing) {
            // Bootstrap: full bucket, charge immediately. A first
            // datagram larger than one full second's burst is dropped
            // here (the bucket starts at `cap_per_second`, not at
            // `cap_per_second + bytes_charged`).
            const tokens_after_charge: u64 = if (cap_per_second >= bytes_charged)
                cap_per_second - bytes_charged
            else
                0;
            gop.value_ptr.* = .{
                .count = 0,
                .window_start_us = 0,
                .vn_count = 0,
                .vn_window_start_us = 0,
                .log_count = 0,
                .log_window_start_us = 0,
                .bandwidth_tokens = tokens_after_charge,
                .bandwidth_last_refill_us = now_us,
            };
            return cap_per_second >= bytes_charged;
        }

        // Refill: tokens += elapsed_us * cap / 1_000_000, capped at cap.
        // `mulWide` keeps the intermediate product in u128 so a long
        // idle gap on a high cap can't overflow u64 mid-divide.
        const elapsed = now_us -% gop.value_ptr.bandwidth_last_refill_us;
        const refill: u64 = @intCast(std.math.mulWide(u64, elapsed, cap_per_second) / std.time.us_per_s);
        const refilled = std.math.add(u64, gop.value_ptr.bandwidth_tokens, refill) catch cap_per_second;
        gop.value_ptr.bandwidth_tokens = @min(refilled, cap_per_second);
        gop.value_ptr.bandwidth_last_refill_us = now_us;

        if (gop.value_ptr.bandwidth_tokens < bytes_charged) return false;
        gop.value_ptr.bandwidth_tokens -= bytes_charged;
        return true;
    }

    fn pruneSourceRate(self: *Server, now_us: u64) void {
        var it = self.source_rate_table.iterator();
        while (it.next()) |entry| {
            const init_elapsed = now_us -% entry.value_ptr.window_start_us;
            const vn_elapsed = now_us -% entry.value_ptr.vn_window_start_us;
            const log_elapsed = now_us -% entry.value_ptr.log_window_start_us;
            const bandwidth_elapsed = now_us -% entry.value_ptr.bandwidth_last_refill_us;
            // Only prune when *all four* per-counter / per-bucket axes
            // have gone idle — otherwise an entry that's only stale on
            // one axis would lose its still-active counters on the
            // others. The bandwidth-bucket survival threshold is held
            // separately so a long-idle source still pays the
            // refill-from-empty bootstrap rather than getting a free
            // full-bucket reset on its next packet.
            if (init_elapsed >= self.source_rate_window_us and
                vn_elapsed >= self.source_rate_window_us and
                log_elapsed >= self.source_rate_window_us and
                bandwidth_elapsed >= bandwidth_idle_threshold_us)
            {
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

    /// True if `version` is one of the wire-format versions this
    /// server is configured to accept. Drives the VN gate in `feed`.
    fn versionAccepted(self: *const Server, version: u32) bool {
        for (self.versions) |v| {
            if (v == version) return true;
        }
        return false;
    }

    /// RFC 9368 §5/§6 server-side pre-parse: decide whether to
    /// upgrade this incoming Initial from `wire_version` to a
    /// different chosen version.
    ///
    /// Decrypts a private copy of the Initial under wire-version
    /// keys, walks the resulting CRYPTO frames to assemble the
    /// ClientHello, looks for `quic_transport_parameters` and inside
    /// that for `version_information` (codepoint 0x11). Intersects
    /// the client's advertised `available_versions` with the server's
    /// configured `Config.versions` and returns the first server-
    /// preferred entry that also appears in the client's list.
    ///
    /// Returns:
    ///   - `null` when the pre-parse failed at any step (decrypt
    ///     auth, malformed/fragmented ClientHello, missing extension,
    ///     no overlap with the client's list). The caller falls back
    ///     to the wire version, which is always spec-compliant.
    ///   - `wire_version` when the decision is "no upgrade" (the
    ///     wire version is the highest-priority overlap). Cheap to
    ///     handle as a no-op upstream.
    ///   - The upgrade target version when the decision is to
    ///     upgrade. The caller MUST advertise this as `chosen_version`
    ///     in the outbound transport_params and (after the first
    ///     wire-version Initial is processed) flip the connection's
    ///     active version to it for outbound packet protection.
    ///
    /// Sets `*ch_complete` to false when the reassembled CH was
    /// incomplete on this Initial (i.e. the ClientHello is fragmented
    /// across multiple Initials). Callers that want to drive a
    /// streaming reassembler use that signal to attach a per-slot
    /// `PendingUpgradeState`.
    ///
    /// Defensive posture: any error path returns `null`. The pre-
    /// parse never closes the connection or surfaces an error to the
    /// caller — it is purely advisory.
    fn preparseUpgradeTarget(
        self: *const Server,
        bytes: []const u8,
        wire_version: u32,
        ch_complete: *bool,
    ) ?u32 {
        ch_complete.* = false;
        // Multi-version mode is the only case where an upgrade is
        // possible. With a single configured version there is nothing
        // to choose between.
        if (self.versions.len <= 1) return null;
        // Only Initial-key-derivable wire versions support compatible
        // version negotiation. Higher layers reject everything else
        // via `versionAccepted` upstream, but stay defensive.
        if (!wire.initial.isSupportedVersion(wire_version)) return null;

        var pt_buf: [conn_mod.state.max_recv_plaintext]u8 = undefined;
        const plaintext = decryptInitialPreparse(bytes, wire_version, &pt_buf) orelse return null;

        // Reassemble the ClientHello bytes from the decrypted payload's
        // CRYPTO frames. Single-Initial fast path; on fragmentation we
        // leave `ch_complete=false` and the caller falls into the
        // streaming `PendingUpgradeState` path.
        var ch_buf: [wire.vneg_preparse.max_client_hello_bytes]u8 = undefined;
        const ch = wire.vneg_preparse.reassembleClientHello(&ch_buf, plaintext) orelse return null;
        ch_complete.* = true;

        return self.upgradeTargetFromCh(ch);
    }

    /// Steps 3-5 of the §6 pre-parse: walk a contiguous ClientHello
    /// looking for `quic_transport_parameters` → `version_information`,
    /// then intersect the advertised `available_versions` with the
    /// server's configured preference list. Shared by the single-shot
    /// `preparseUpgradeTarget` and the streaming `advancePendingUpgrade`
    /// paths so both produce bit-identical decisions for any given CH.
    fn upgradeTargetFromCh(self: *const Server, ch: []const u8) ?u32 {
        const qtp = wire.vneg_preparse.findQuicTransportParamsExt(ch) orelse return null;
        const info = wire.vneg_preparse.findVersionInformation(qtp) orelse return null;
        return wire.vneg_preparse.chooseUpgradeVersion(self.versions, info.available());
    }

    /// Decrypt a single inbound Initial under the wire-version keys,
    /// returning a borrowed slice into `pt_buf` that holds the
    /// decrypted plaintext payload (frame stream). Stateless — the
    /// caller's normal `handleInitial` flow is the source of truth for
    /// `largest_received` etc.; the pre-parse just needs the
    /// frame-stream bytes once. Returns null on any decrypt failure
    /// (truncated header, key-derivation error, AEAD authentication
    /// failure, oversize buffer); callers treat null identically to
    /// "skip the upgrade".
    fn decryptInitialPreparse(
        bytes: []const u8,
        wire_version: u32,
        pt_buf: *[conn_mod.state.max_recv_plaintext]u8,
    ) ?[]const u8 {
        const ids = peekLongHeaderIds(bytes) orelse return null;

        // Make a private copy of the inbound bytes — `openInitial`
        // strips header protection in-place, and the caller will
        // re-decrypt the same buffer through the normal
        // `handleInitial` flow.
        var pkt_copy: [conn_mod.state.max_recv_plaintext]u8 = undefined;
        if (bytes.len > pkt_copy.len) return null;
        @memcpy(pkt_copy[0..bytes.len], bytes);

        const init_keys = wire.initial.deriveInitialKeysFor(wire_version, ids.dcid, false) catch return null;
        const r_keys = wire.short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret) catch return null;

        const opened = wire.long_packet.openInitial(pt_buf, pkt_copy[0..bytes.len], .{
            .keys = &r_keys,
            .largest_received = 0,
        }) catch return null;
        return opened.payload;
    }

    /// Allocate and seed a `PendingUpgradeState` for a freshly-opened
    /// slot whose first Initial carried only a CH prefix. Decrypts
    /// the first Initial again (the cost is one AEAD open per slot
    /// in the multi-Initial path; the single-Initial fast path
    /// doesn't enter here) and feeds its CRYPTO bytes through the
    /// reassembler so subsequent routed Initials can complete the
    /// CH. Returns null on allocation failure or a malformed first-
    /// Initial frame stream — in either case the slot commits to
    /// the wire version.
    fn openPendingUpgrade(
        self: *Server,
        bytes: []const u8,
        wire_version: u32,
    ) ?*PendingUpgradeState {
        const pu = self.allocator.create(PendingUpgradeState) catch return null;
        pu.init(wire_version);
        pu.initials_seen = 1;
        var pt_buf: [conn_mod.state.max_recv_plaintext]u8 = undefined;
        const plain = decryptInitialPreparse(bytes, wire_version, &pt_buf) orelse {
            self.allocator.destroy(pu);
            return null;
        };
        _ = pu.rc.feed(plain) catch {
            self.allocator.destroy(pu);
            return null;
        };
        return pu;
    }

    /// Apply a routed Initial datagram to the slot's pending §6
    /// upgrade reassembler. Decrypt under the cached wire version,
    /// feed the frame stream into the `ChReassembler`, and on a
    /// completed CH:
    ///   - run the same `upgradeTargetFromCh` decision the single-
    ///     shot path uses,
    ///   - if the chosen version differs from the wire version,
    ///     update the connection's outbound transport_params (so the
    ///     EE BoringSSL is about to write advertises the upgrade)
    ///     and stash a pending version flip for `dispatchToSlot` to
    ///     apply once `handleWithEcn` returns,
    ///   - drop the pending state so future routed datagrams don't
    ///     re-decrypt this Initial.
    ///
    /// Bounded by `PendingUpgradeState.max_initial_packets`: if the
    /// CH is still not complete after that many Initials, give up and
    /// commit to the wire version (same outcome as the
    /// `error.Invalid` / decrypt-failure paths). The CH is also never
    /// allowed to arrive on the upgrade target's keys — only the wire
    /// version's — and any frame the reassembler rejects (overflow,
    /// unexpected frame type, conflicting overlap) drops the pending
    /// state immediately.
    fn advancePendingUpgrade(self: *Server, slot: *Slot, bytes: []const u8) void {
        const pu = slot.pending_upgrade orelse return;

        // Only Initial-typed long-header datagrams advance the
        // reassembler. Routed Handshake / 1-RTT datagrams ride in via
        // the same path but are not part of CH reassembly. If we ever
        // see a non-Initial here it almost certainly means the peer
        // has already moved past Initial — drop pending state and
        // commit to the wire version.
        const ids = peekLongHeaderIds(bytes) orelse {
            self.dropPendingUpgrade(slot);
            return;
        };
        if (!isInitialLongHeader(bytes, ids.version) or ids.version != pu.wire_version) {
            self.dropPendingUpgrade(slot);
            return;
        }

        // Hard cap on pre-parse work per slot. A peer that keeps
        // sending fragmented Initials past this budget gets the wire-
        // version commitment (still spec-compliant) so we don't
        // accumulate unbounded decrypt CPU under their control.
        if (pu.initials_seen >= PendingUpgradeState.max_initial_packets) {
            self.dropPendingUpgrade(slot);
            return;
        }
        pu.initials_seen += 1;

        var pt_buf: [conn_mod.state.max_recv_plaintext]u8 = undefined;
        const plaintext = decryptInitialPreparse(bytes, pu.wire_version, &pt_buf) orelse {
            // Decrypt failure — likely a stale retransmit or a packet
            // the connection's normal flow will reject too. Don't
            // tear down pending state on a single failure; future
            // Initials may still drive the upgrade.
            return;
        };

        const got_or_err = pu.rc.feed(plaintext);
        const maybe_ch = got_or_err catch {
            // Malformed frame stream or oversize CH. Falls back to
            // wire version — drop pending state so we don't keep
            // re-evaluating broken inputs.
            self.dropPendingUpgrade(slot);
            return;
        };
        const ch = maybe_ch orelse return; // Still waiting for more bytes.

        // CH complete — make the §6 decision. Whether we upgrade or
        // commit to the wire version, the pending state can be
        // dropped: the decision is final.
        const upgrade_target = self.upgradeTargetFromCh(ch);
        const wire_version = pu.wire_version;
        self.dropPendingUpgrade(slot);

        const chosen = upgrade_target orelse wire_version;
        if (chosen == wire_version) return; // No upgrade.

        // Rebuild the local transport_params with the upgraded
        // chosen version listed first, then push them to BoringSSL.
        // BoringSSL serializes these only when it actually emits the
        // EE; that hasn't happened yet because the CH it has so far
        // is still fragmented (the very datagram we're about to feed
        // into `dispatchToSlot` carries the missing tail). The
        // `setTransportParams` call wins the race and the EE goes
        // out advertising chosen=upgrade.
        var params = slot.conn.localTransportParams();
        var ordered: [16]u32 = undefined;
        ordered[0] = chosen;
        var n: usize = 1;
        for (self.versions) |v| {
            if (v == chosen) continue;
            if (n >= ordered.len) break;
            ordered[n] = v;
            n += 1;
        }
        params.setCompatibleVersions(ordered[0..n]) catch return;
        slot.conn.setTransportParams(params) catch return;
        slot.conn.setPendingVersionUpgrade(chosen);
    }

    /// Free and unhook the per-slot multi-Initial pre-parse buffer.
    /// Idempotent. Called once the upgrade decision is final or when
    /// the per-slot Initial budget is exhausted.
    fn dropPendingUpgrade(self: *Server, slot: *Slot) void {
        const pu = slot.pending_upgrade orelse return;
        slot.pending_upgrade = null;
        self.allocator.destroy(pu);
    }

    /// Encode a Version Negotiation packet into the response queue.
    /// Errors propagate from the encoder (`InsufficientBytes`) or
    /// the queue allocator (`OutOfMemory`); on either, `feed` falls
    /// back to `.dropped`. The supported_versions list mirrors
    /// `Config.versions`; the response echoes the client's CIDs
    /// swapped (RFC 8999 §6) and the unused bits are left as the
    /// encoder default.
    fn queueVersionNegotiation(
        self: *Server,
        dst_addr: Address,
        client_packet: []const u8,
    ) !void {
        const ids = peekLongHeaderIds(client_packet) orelse return error.InvalidVersionNegotiation;
        var entry: StatelessResponse = .{ .dst = dst_addr, .len = 0, .kind = .version_negotiation };

        // Pack our configured versions into a u32-aligned buffer; the
        // wire-level VN encoder handles the rest. Capped at 16 entries
        // so we don't overflow the inline `entry.bytes` budget.
        var versions_bytes: [16 * 4]u8 = undefined;
        const count = @min(self.versions.len, 16);
        for (self.versions[0..count], 0..) |v, i| {
            std.mem.writeInt(u32, versions_bytes[i * 4 ..][0..4], v, .big);
        }

        const written = try wire.header.encode(&entry.bytes, .{ .version_negotiation = .{
            .dcid = try wire.header.ConnId.fromSlice(ids.scid),
            .scid = try wire.header.ConnId.fromSlice(ids.dcid),
            .versions_bytes = versions_bytes[0 .. count * 4],
        } });
        entry.len = written;
        try self.queueStatelessResponse(entry);
    }

    // -- NEW_TOKEN ------------------------------------------------------

    /// Mint and queue a single NEW_TOKEN on `slot`'s connection if all
    /// prerequisites are satisfied:
    ///  - `Server.new_token_key` is non-null (feature opt-in).
    ///  - The slot's connection has confirmed the handshake.
    ///  - This slot has not already emitted its NEW_TOKEN.
    ///  - We have a peer address to bind into the token (no `from`,
    ///    no NEW_TOKEN — the embedder is in a hermetic-test path).
    ///
    /// Called from the routed and accepted feed paths; idempotent
    /// across retries via the slot's `new_token_emitted` latch.
    fn maybeIssueNewToken(
        self: *Server,
        slot: *Slot,
        from: ?Address,
        now_us: u64,
    ) void {
        const key_ptr = if (self.new_token_key) |*k| k else return;
        if (slot.new_token_emitted) return;
        if (!slot.conn.handshakeDone()) return;
        const addr = from orelse return;

        var addr_buf: [22]u8 = undefined;
        const ctx = addressContext(&addr_buf, addr);
        var token: new_token_mod.Token = undefined;
        _ = new_token_mod.mint(&token, .{
            .key = key_ptr,
            .now_us = now_us,
            .lifetime_us = self.new_token_lifetime_us,
            .client_address = ctx,
        }) catch {
            // Mint failure is not peer-reachable in practice (output
            // buffer is fixed-size, address is fixed-size, the only
            // realistic failure is a BoringSSL CSPRNG hiccup). Skip
            // issuance for this slot; the slot stays usable, and
            // future Initials from the same address will fall
            // through to the Retry gate as if NEW_TOKEN was never
            // issued.
            return;
        };

        slot.conn.queueNewToken(&token) catch {
            // Same not-peer-reachable rationale; the queue holds at
            // most one entry, the bytes are fixed-size, and the
            // role check has already passed (we minted on a
            // server-role slot).
            return;
        };
        slot.new_token_emitted = true;
    }

    // -- Retry ----------------------------------------------------------

    /// What `applyRetryGate` decided. `none` means proceed with the
    /// normal accept path (this Initial carried no token and Retry
    /// is disabled, or the source already passed validation in a
    /// prior datagram). `sent` means we queued a Retry. `drop` means
    /// the echoed token was malformed/expired/wrong-source. `echo`
    /// means the Retry token validated and the caller should accept
    /// this Initial as the post-Retry continuation.
    /// `new_token_skip` means a valid NEW_TOKEN was presented, so
    /// the source is treated as already address-validated and the
    /// caller skips the Retry round-trip (RFC 9000 §8.1.3).
    const RetryDecision = union(enum) {
        none,
        sent,
        drop,
        echo: RetryEcho,
        new_token_skip,
    };

    /// Captured server-side context for an Initial that successfully
    /// echoed a Retry token. The slot opener uses these to set the
    /// post-Retry transport parameters.
    const RetryEcho = struct {
        retry_scid: [20]u8,
        retry_scid_len: u8,
        original_dcid: ConnectionId,
    };

    /// Run the Retry / NEW_TOKEN gate for an Initial from `addr`.
    /// Either queues a Retry (`.sent`), validates an echoed Retry
    /// token (`.echo`), validates an echoed NEW_TOKEN
    /// (`.new_token_skip`, accept directly), or returns `.drop` for
    /// a malformed/expired/wrong-source token. Returns `.none` only
    /// if both gates are disabled (caller checks before invoking).
    ///
    /// Token-disambiguation: if `new_token_key` is set, NEW_TOKEN
    /// validation runs first; on `.valid` we skip Retry. On
    /// `.malformed` (also covers a Retry-token blob in a fresh
    /// session — distinct domain separator), we fall through to
    /// Retry. Other NEW_TOKEN failures (`.expired`, `.invalid`,
    /// etc.) ALSO fall through so a stale stored token sends the
    /// peer through a fresh Retry round-trip rather than dropping
    /// the connection.
    fn applyRetryGate(
        self: *Server,
        addr: Address,
        bytes: []const u8,
        now_us: u64,
    ) Error!RetryDecision {
        const retry_key = if (self.retry_token_key) |*k| k else null;
        const new_token_key = if (self.new_token_key) |*k| k else null;
        if (retry_key == null and new_token_key == null) return .none;

        const ids = peekLongHeaderIds(bytes) orelse return .drop;
        const token = peekInitialToken(bytes);

        // NEW_TOKEN check first — if a returning client presents a
        // valid NEW_TOKEN, we want to accept it directly without
        // burning a Retry round-trip. On any failure we fall
        // through; a stale or wrong-address NEW_TOKEN should never
        // close the connection (the peer expected to be accepted
        // and would re-handshake gracefully on a Retry).
        if (token != null and token.?.len > 0) {
            if (new_token_key) |nt_key| {
                var addr_buf: [22]u8 = undefined;
                const ctx = addressContext(&addr_buf, addr);
                const result = new_token_mod.validate(token.?, .{
                    .key = nt_key,
                    .now_us = now_us,
                    .client_address = ctx,
                });
                if (result == .valid) return .new_token_skip;
                // Fall through to Retry validation on malformed,
                // expired, invalid, etc.
            }
        }

        // Retry-token path. If Retry is disabled, an Initial
        // carrying a non-NEW_TOKEN token is treated as if no token
        // were present (we can't validate it; falling back to
        // accept-without-validation is the only safe move when the
        // operator opted out of Retry).
        const key_ptr = retry_key orelse return .none;

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
        try self.mintLocalScid(retry_scid[0..retry_scid_len]);

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

    /// Internal helper: invoke `log_callback` if installed. Mediated
    /// by the per-source log rate limit (hardening guide §9.4) when
    /// the event carries a source address — events with `from = null`
    /// (or a variant that doesn't bind to a peer) bypass the gate.
    fn emitLog(self: *Server, ev: LogEvent) void {
        if (self.log_callback == null) return;
        if (self.max_log_events_per_source) |cap| {
            if (logEventSource(ev)) |addr| {
                // `acceptLogRate` allocates on first hit per source —
                // OOM there denies the log rather than crash. We pass
                // the most recent timestamp the caller surfaced via
                // the in-flight feed; emitLog doesn't take a clock so
                // we use the limiter's own `log_window_start_us`
                // semantics where the comparison is against `now_us`
                // captured at call time. Callers that want strict
                // timing pass `now_us` to whichever feed-side gate
                // upstream of this; here we use the source's most
                // recent log-window start as a stand-in for "now".
                //
                // The simplest correct implementation: hand
                // `acceptLogRate` an in-feed `now_us` via a ledger
                // captured at feed entry. We do that via
                // `last_feed_now_us`, set at the top of every `feed`.
                if (!self.acceptLogRate(addr, cap, self.last_feed_now_us)) {
                    self.feeds_log_rate_limited += 1;
                    return;
                }
            }
        }
        self.log_callback.?(self.log_user_data, ev);
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
            .feeds_initial_too_small = self.feeds_initial_too_small,
            .feeds_vn_rate_limited = self.feeds_vn_rate_limited,
            .feeds_listener_rate_limited = self.feeds_listener_rate_limited,
            .feeds_listener_byte_rate_limited = self.feeds_listener_byte_rate_limited,
            .feeds_source_bandwidth_limited = self.feeds_source_bandwidth_limited,
            .feeds_log_rate_limited = self.feeds_log_rate_limited,
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

/// Extract the source address from a `LogEvent` for the per-source log
/// rate limit. Returns null when the event has no source attribution
/// (e.g. `stateless_queue_evicted`) or the source is itself null
/// (`connection_closed` / `table_full` paths where the embedder
/// didn't pass `from`). Hardening guide §9.4: events with no source
/// bypass the limiter.
fn logEventSource(ev: LogEventImpl) ?Address {
    return switch (ev) {
        .connection_accepted => |e| e.peer,
        .connection_closed => |e| e.peer,
        .feed_rate_limited => |e| e.peer,
        .retry_minted => |e| e.peer,
        .version_negotiated => |e| e.peer,
        .stateless_queue_evicted => null,
        .table_full => |e| e.peer,
    };
}

/// Project a `PreferredAddressConfig` into the on-wire transport-
/// parameter struct. The seq-1 CID + token are minted by the caller
/// (`openSlotFromInitial`); this helper just packs the address pair
/// and identity bytes into the codec's six-field shape.
///
/// RFC 9000 §18.2 lets either family be all-zero as a sentinel for
/// "no preferred address for this family". When `cfg.ipv4` /
/// `cfg.ipv6` is null, the corresponding output bytes / port stay
/// zero — clients reading the parameter see no v4 / v6 address as
/// expected.
fn buildPreferredAddressParam(
    cfg: PreferredAddressConfig,
    cid: []const u8,
    stateless_reset_token: [16]u8,
) PreferredAddressTp {
    var out: PreferredAddressTp = .{
        .connection_id = ConnectionId.fromSlice(cid),
        .stateless_reset_token = stateless_reset_token,
    };
    if (cfg.ipv4) |v4| {
        out.ipv4_address = v4.bytes;
        out.ipv4_port = v4.port;
    }
    if (cfg.ipv6) |v6| {
        out.ipv6_address = v6.bytes;
        out.ipv6_port = v6.port;
    }
    return out;
}

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

/// True if `bytes` looks like a long-header Initial under the
/// supplied wire-format version. RFC 9368 §3.2 puts Initial at
/// 0b01 under v2 vs 0b00 under v1, so the caller has to pre-resolve
/// the version field — typically via `peekLongHeaderIds`.
fn isInitialLongHeader(bytes: []const u8, version: u32) bool {
    if (bytes.len == 0 or (bytes[0] & 0x80) == 0) return false;
    if (bytes.len < 5) return false;
    if (version == 0) return false; // version negotiation
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    return wire.header.longTypeFromBits(version, long_type_bits) == .initial;
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

/// BoringSSL `allow_early_data` callback installed by `Server.init`
/// when an `AntiReplayTracker` is supplied via Config. Hashes the
/// resumed-session ticket bytes (`Conn.peerSessionId`) to a 32-byte
/// tracker `Id` and consults `tracker.consume` for a verdict.
///
/// Return contract (mirrors `boringssl.tls.AllowEarlyDataCallback`):
///   - `true`  → BoringSSL proceeds with 0-RTT for this handshake.
///   - `false` → BoringSSL toggles `early_data_enabled = false` on
///               this `SSL` so the handshake completes as 1-RTT.
///
/// Defensive defaults: any plumbing failure (null user_data, hash
/// failure, OOM in the tracker) returns `false` — denying 0-RTT
/// rather than risking a replay window where the tracker can't see
/// the attempt. Hash failures are not peer-reachable in practice.
fn antiReplayEarlyDataTrampoline(
    user_data: ?*anyopaque,
    ssl: *boringssl.tls.Conn,
) bool {
    const raw_ptr = user_data orelse return false;
    const tracker: *tls_mod.anti_replay.AntiReplayTracker =
        @ptrCast(@alignCast(raw_ptr));

    // No resumed session attached → no replay risk to gate on. Return
    // true; BoringSSL will refuse 0-RTT anyway because there's no
    // ticket to bind it to.
    const ticket = ssl.peerSessionId() orelse return true;

    const id_full = boringssl.crypto.hash.Sha256.hash(ticket) catch return false;
    var id: tls_mod.anti_replay.Id = undefined;
    @memcpy(&id, id_full[0..tls_mod.anti_replay.id_len]);

    // The tracker exposes an internal-clock variant of `consume` so
    // this callback (which has no path to the Server's monotonic
    // clock) can defer to the most recent `now_us` that
    // `Server.feed` cached via `bumpClock`. The age-out window then
    // tracks Server-driven time exactly the way the application-
    // layer `consume(id, now_us)` callers see.
    const verdict = tracker.consumeUsingInternalClock(id) catch return false;
    return switch (verdict) {
        .fresh => true,
        .replay => false,
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

    // preferred_address with neither v4 nor v6 set.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .preferred_address = .{},
        .stateless_reset_key = @splat(0x42),
    }));

    // preferred_address without stateless_reset_key.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .preferred_address = .{
            .ipv6 = .{ .port = 444, .bytes = @splat(0), .flow = 0 },
        },
        // stateless_reset_key intentionally null.
    }));
}

test "buildPreferredAddressParam packs config + identity into transport-param shape" {
    // The codec auto-build path (used by `openSlotFromInitial`) projects
    // the embedder-supplied `PreferredAddressConfig` into the on-wire
    // `tls.transport_params.PreferredAddress` shape that the encoder
    // serializes. Pin the field-by-field mapping so future config
    // additions can't silently break the wire output.
    const cfg: PreferredAddressConfig = .{
        .ipv4 = .{ .bytes = .{ 193, 167, 100, 100 }, .port = 444 },
        .ipv6 = .{ .bytes = @splat(0), .port = 445, .flow = 0 },
    };
    var alt_cid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var token: [16]u8 = @splat(0xee);
    const got = buildPreferredAddressParam(cfg, &alt_cid, token);

    try std.testing.expectEqualSlices(u8, &cfg.ipv4.?.bytes, &got.ipv4_address);
    try std.testing.expectEqual(@as(u16, 444), got.ipv4_port);
    try std.testing.expectEqualSlices(u8, &cfg.ipv6.?.bytes, &got.ipv6_address);
    try std.testing.expectEqual(@as(u16, 445), got.ipv6_port);
    try std.testing.expectEqualSlices(u8, &alt_cid, got.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &token, &got.stateless_reset_token);
}

test "buildPreferredAddressParam leaves missing-family fields zero (RFC 9000 §18.2 sentinel)" {
    // §18.2 ¶2: the address pair fields are independently optional;
    // the all-zero address + zero port is the "no preferred address
    // for this family" sentinel. Verify the helper preserves that
    // when `ipv4` (or `ipv6`) is left null in the config.
    const cfg: PreferredAddressConfig = .{
        .ipv6 = .{ .bytes = .{
            0xfd, 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        }, .port = 444, .flow = 0 },
    };
    const cid: [8]u8 = .{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const tok: [16]u8 = @splat(0xab);
    const got = buildPreferredAddressParam(cfg, &cid, tok);

    // v4 stays at the all-zero / port-zero sentinel.
    const zero_v4: [4]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero_v4, &got.ipv4_address);
    try std.testing.expectEqual(@as(u16, 0), got.ipv4_port);
    // v6 is populated.
    try std.testing.expectEqualSlices(u8, &cfg.ipv6.?.bytes, &got.ipv6_address);
    try std.testing.expectEqual(@as(u16, 444), got.ipv6_port);
}

test "buildPreferredAddressParam round-trips through Params codec" {
    // End-to-end: pack a config into the transport-parameter struct,
    // encode through `Params.encode`, decode via `Params.decode`, and
    // confirm every field survives the wire format. The decoder is
    // role-aware (server-only acceptance) but `Params.decode` itself
    // is role-neutral; we use it for the codec round-trip without
    // engaging the role gate.
    const transport_params = @import("tls/root.zig").transport_params;

    const cfg: PreferredAddressConfig = .{
        .ipv4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 4433 },
        .ipv6 = .{ .bytes = .{
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        }, .port = 4434, .flow = 0 },
    };
    const cid: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    const token: [16]u8 = @splat(0x77);
    const pa = buildPreferredAddressParam(cfg, &cid, token);

    const params: transport_params.Params = .{ .preferred_address = pa };
    var buf: [256]u8 = undefined;
    const n = try params.encode(&buf);
    const decoded = try transport_params.Params.decode(buf[0..n]);
    const got = decoded.preferred_address orelse return error.MissingPreferredAddress;

    try std.testing.expectEqualSlices(u8, &pa.ipv4_address, &got.ipv4_address);
    try std.testing.expectEqual(pa.ipv4_port, got.ipv4_port);
    try std.testing.expectEqualSlices(u8, &pa.ipv6_address, &got.ipv6_address);
    try std.testing.expectEqual(pa.ipv6_port, got.ipv6_port);
    try std.testing.expectEqualSlices(u8, pa.connection_id.slice(), got.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &pa.stateless_reset_token, &got.stateless_reset_token);
}

test "peekLongHeaderIds rejects too-short" {
    try std.testing.expect(peekLongHeaderIds(&.{}) == null);
    try std.testing.expect(peekLongHeaderIds(&.{0xc0}) == null);
}

test "isInitialLongHeader recognizes Initial type bits" {
    // Long header, type=0b00 (Initial under v1), version=1.
    const v1_bytes = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&v1_bytes, 0x00000001));

    // Long header, type=0b01 (Initial under v2 per RFC 9368 §3.2),
    // version = 0x6b3343cf. The same bit pattern is 0-RTT under v1
    // and Initial under v2, so the helper has to consult `version`.
    const v2_bytes = [_]u8{ 0xd0, 0x6b, 0x33, 0x43, 0xcf, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&v2_bytes, 0x6b3343cf));
    try std.testing.expect(!isInitialLongHeader(&v2_bytes, 0x00000001));

    // Version negotiation (version=0) is *not* an Initial under
    // either version. The caller is expected to pass `version=0`
    // here (matching the bytes' version field); the helper rejects
    // outright.
    const vn = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&vn, 0));

    // Short header.
    const sh = [_]u8{ 0x40, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&sh, 0x00000001));
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
    // Drive the helper under both versions so the v1 and v2 long-type
    // rotations are both exercised on the same input bytes.
    _ = isInitialLongHeader(input, 0x00000001);
    _ = isInitialLongHeader(input, 0x6b3343cf);
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
