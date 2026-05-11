//! Path — a 4-tuple-bound bundle of QUIC connection state
//! (RFC 9000 §6, §8, §9). Each Connection holds a `PathSet` with
//! one or more Paths; migration switches the active path, multipath
//! widens the active set without restructuring the state machine.
//!
//! A Path owns:
//! - The peer + local address (the "4-tuple" minus the implicit
//!   transport protocol).
//! - The pair of Connection IDs in use on this path.
//! - Per-path anti-amplification credit (RFC 9000 §8.1).
//! - The path-validation state machine
//!   (`PathValidator`, RFC 9000 §8.2).
//! - The path's own RTT estimator and congestion controller.
//!
//! Address fields are placeholders sized for IPv6; the POSIX UDP
//! transport adapts these to `std.net.Address` at the boundary.

const std = @import("std");

const congestion_mod = @import("congestion.zig");
const pn_space_mod = @import("pn_space.zig");
const path_validator_mod = @import("path_validator.zig");
const rtt_mod = @import("rtt.zig");
const sent_packets_mod = @import("sent_packets.zig");

/// Re-export of the per-path NewReno congestion controller.
pub const NewReno = congestion_mod.NewReno;
/// Re-export of the QUIC packet number space type.
pub const PnSpace = pn_space_mod.PnSpace;
/// Re-export of the RFC 9000 §8.2 path validator.
pub const PathValidator = path_validator_mod.PathValidator;
/// Re-export of the RFC 9002 RTT estimator.
pub const RttEstimator = rtt_mod.RttEstimator;
/// Re-export of the per-path sent-packet tracker.
pub const SentPacketTracker = sent_packets_mod.SentPacketTracker;

/// QUIC connection IDs are between 0 and 20 bytes (RFC 9000 §17.2).
pub const max_cid_len: usize = 20;

/// Inline-storage QUIC connection ID. Holds 0..20 bytes of CID
/// material plus an explicit length, avoiding a heap allocation for
/// each path.
pub const ConnectionId = struct {
    bytes: [max_cid_len]u8 = @splat(0),
    len: u8 = 0,

    /// Build a ConnectionId from the given slice. Lengths above
    /// `max_cid_len` are clamped: every documented caller (header
    /// parser, transport-parameter decoder, frame decoder) already
    /// rejects oversized peer CIDs with a typed error, but the clamp
    /// keeps a hypothetical missed validation from indexing past the
    /// inline buffer on a peer-controlled length.
    pub fn fromSlice(s: []const u8) ConnectionId {
        const n = @min(s.len, max_cid_len);
        var cid: ConnectionId = .{};
        @memcpy(cid.bytes[0..n], s[0..n]);
        cid.len = @intCast(n);
        return cid;
    }

    /// View of the active CID bytes (length `len`).
    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    /// Byte-equality of two CIDs (length plus content).
    pub fn eql(a: ConnectionId, b: ConnectionId) bool {
        if (a.len != b.len) return false;
        return std.mem.eql(u8, a.slice(), b.slice());
    }
};

/// Path-tuple address. Holds enough bytes for an IPv6 sockaddr
/// (16-byte address + 2-byte port + 4-byte scope/flow). FIXME(audit):
/// migrate to `std.net.Address` once the transport layer is ready
/// to round-trip scope/flow through it.
pub const Address = struct {
    bytes: [22]u8 = @splat(0),

    /// Byte-wise equality (full 22-byte buffer, including padding).
    pub fn eql(a: Address, b: Address) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }
};

/// What does this Path's lifecycle look like, from the perspective
/// of the local endpoint?
pub const State = enum {
    /// Created but not yet used: no datagrams sent or received.
    fresh,
    /// Datagrams flow on this path; validation is either unnecessary
    /// (we initiated and the handshake completed here) or in
    /// progress (PATH_CHALLENGE pending).
    active,
    /// Validation failed (PATH_CHALLENGE timed out). The path is
    /// no longer usable.
    failed,
    /// We've decided to abandon this path (e.g. NAT rebinding moved
    /// us off it). Frames already in-flight may still be acked, but
    /// no new traffic will be scheduled here.
    retiring,
};

/// Application-data scheduling policy. `primary` preserves the
/// historical single-path behavior; the other policies are available
/// for embedders once multiple validated paths are registered.
pub const Scheduler = enum {
    /// Always send on the active (or primary) path.
    primary,
    /// Round-robin across sendable paths in registration order.
    round_robin,
    /// Pick the sendable path with the lowest RTT and free CWND.
    lowest_rtt_cwnd,
};

/// One QUIC path: a 4-tuple plus the per-path state (CIDs, anti-amp,
/// validator, RTT, congestion). Most connections have one Path;
/// migration and multipath (draft-ietf-quic-multipath-21) attach more.
pub const Path = struct {
    peer_addr: Address,
    local_addr: Address,
    local_cid: ConnectionId,
    peer_cid: ConnectionId,

    /// Bytes the peer has sent us on this path. The anti-amp budget
    /// is `3 * bytes_received` per RFC 9000 §8.1.
    bytes_received: u64 = 0,
    /// Bytes we've sent on this path. Counts against anti-amp until
    /// the path is validated.
    bytes_sent: u64 = 0,

    validator: PathValidator = .{},
    rtt: RttEstimator = .{},
    cc: NewReno,

    /// True once this path has been validated (or validation is
    /// implicit because we initiated it and completed the handshake
    /// here). Disables anti-amp gating.
    validated: bool = false,

    state: State = .fresh,

    /// Microseconds-clock when we most recently emitted a
    /// PATH_CHALLENGE for this path. Drives the rate-limit gate in
    /// `Connection.recordAuthenticatedDatagramAddress` (hardening
    /// guide §4.8: "rate-limit path probes"). Null until the first
    /// challenge.
    last_path_challenge_at_us: ?u64 = null,

    /// Construct a fresh `Path` with the given 4-tuple/CID pair and
    /// a NewReno controller seeded from `cc_cfg`. The path starts
    /// `fresh` and unvalidated.
    pub fn init(
        peer_addr: Address,
        local_addr: Address,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        cc_cfg: congestion_mod.Config,
    ) Path {
        return .{
            .peer_addr = peer_addr,
            .local_addr = local_addr,
            .local_cid = local_cid,
            .peer_cid = peer_cid,
            .cc = NewReno.init(cc_cfg),
        };
    }

    /// Mark this path as validated. Idempotent. Used for the
    /// initial path on a client connection where the handshake's
    /// completion implicitly validates it (RFC 9000 §8.1.4).
    pub fn markValidated(self: *Path) void {
        self.validated = true;
        self.validator.status = .validated;
    }

    /// True iff the path has been validated by any means.
    pub fn isValidated(self: *const Path) bool {
        return self.validated or self.validator.isValidated();
    }

    /// Record that we received a UDP datagram of `n` bytes. Lifts
    /// the anti-amp ceiling and keeps the path live (transitions
    /// `.fresh` → `.active`).
    pub fn onDatagramReceived(self: *Path, n: u64) void {
        self.bytes_received += n;
        if (self.state == .fresh) self.state = .active;
    }

    /// Anti-amplification headroom for the next outgoing datagram.
    /// Returns `maxInt(u64)` once the path is validated. Per
    /// RFC 9000 §8.1, the cap is `3 * bytes_received`.
    pub fn antiAmpAllowance(self: *const Path) u64 {
        if (self.isValidated()) return std.math.maxInt(u64);
        const cap = std.math.mul(u64, self.bytes_received, 3) catch std.math.maxInt(u64);
        if (self.bytes_sent >= cap) return 0;
        return cap - self.bytes_sent;
    }

    /// Record that we just shipped a UDP datagram of `n` bytes on
    /// this path. Counts against anti-amp.
    pub fn onDatagramSent(self: *Path, n: u64) void {
        self.bytes_sent += n;
        if (self.state == .fresh) self.state = .active;
    }

    /// Mark this path as retiring. New traffic should pick a
    /// different path; loss recovery on the old one continues.
    pub fn retire(self: *Path) void {
        self.state = .retiring;
    }

    /// Mark this path as failed (validator timeout). No further
    /// traffic.
    pub fn fail(self: *Path) void {
        self.state = .failed;
    }
};

/// RFC 8899 §5.2 DPLPMTUD configuration. Threaded onto every
/// `Connection` via `Server.Config.pmtud` / `Client.Config.pmtud`. The
/// transport applies these values at connection creation time and per
/// path; embedders can flip `enable=false` to opt back into the
/// static-MTU behaviour.
///
/// **Field semantics**:
/// - `initial_mtu`: the floor below which DPLPMTUD will never lower the
///   PMTU. Matches the RFC 9000 §14 / §14.3 minimum (1200 bytes).
/// - `max_mtu`: the ceiling. Search-mode probes never exceed this size.
/// - `probe_step`: how much the probed size grows above the current
///   PMTU on each search-mode probe.
/// - `probe_threshold`: RFC 8899 §5.1.4 / §5.1.5 fail counter. After
///   `probe_threshold` consecutive losses of the same probe size, the
///   probed size is recorded as the upper bound; after `probe_threshold`
///   consecutive REGULAR (non-probe) packet losses at the current PMTU,
///   the connection enters black-hole detection (§4.4) and halves the
///   PMTU back toward `initial_mtu`.
/// - `enable`: master switch. When false, no probes are scheduled and
///   the per-path PMTU stays at `initial_mtu`.
pub const PmtudConfig = struct {
    /// Floor PMTU. Matches RFC 9000 §14 MIN_MAX_DATAGRAM_SIZE (1200).
    initial_mtu: u16 = 1200,
    /// Ceiling PMTU. Search will not probe larger than this size.
    /// 1452 is the QUIC-friendly default for PMTU on most internet
    /// paths (1500 IPv4 MTU minus 20 IP + 8 UDP + 20 fudge).
    max_mtu: u16 = 1452,
    /// Probe size increment in bytes (RFC 8899 §5.3.1 "search step").
    probe_step: u16 = 64,
    /// Consecutive-loss threshold before a probe size is recorded as
    /// the upper bound, AND the consecutive-regular-loss threshold
    /// before black-hole detection halves the PMTU (RFC 8899 §4.4).
    probe_threshold: u16 = 3,
    /// Master switch. False disables probes and pins the PMTU at
    /// `initial_mtu` (static-MTU mode).
    enable: bool = true,
};

/// RFC 8899 §5.2 DPLPMTUD probe-state-machine phase. The connection
/// initialises every path in `disabled` (no probes); `Connection.init*`
/// flips the active path's state to `search` if the embedder set
/// `PmtudConfig.enable = true`.
///
/// State transitions:
///   disabled        — `enable=false` master switch.
///   search          — probe scheduler may build a PADDING+PING probe
///                     when no probe is in flight. Successful probe
///                     lifts `pmtu`; loss bumps `pmtu_fail_count`. Once
///                     `probe_step` past the upper bound, transitions
///                     to `search_complete`.
///   search_complete — at the ceiling (`max_mtu` or recorded upper
///                     bound). No further probes scheduled.
///   error_state     — every probe at `initial_mtu` failed. Disable
///                     further probes; PMTU stays at `initial_mtu`.
///                     Currently unused — reserved for future extensions
///                     where the embedder can re-enter search via a
///                     manual call.
pub const PmtudState = enum {
    disabled,
    search,
    search_complete,
    error_state,
};

/// Phase the per-path congestion controller is currently in. Surfaced
/// to qlog and `PathStats`.
pub const CongestionState = enum {
    /// Below `ssthresh` — `cwnd` grows by `bytes_acked` per ACK.
    slow_start,
    /// Currently in a recovery period after a loss event.
    recovery,
    /// `cwnd` has headroom but no data is queued to send.
    application_limited,
    /// Above `ssthresh` — `cwnd` grows by ~one MSS per RTT.
    congestion_avoidance,
};

/// Snapshot of one path's observability counters. Returned by
/// `PathState.stats` / `PathSet.stats`.
pub const PathStats = struct {
    path_id: u32,
    state: State,
    validated: bool,
    retire_deadline_us: ?u64,
    bytes_received: u64,
    bytes_sent: u64,
    bytes_in_flight: u64,
    ack_eliciting_in_flight: u64,
    cwnd: u64,
    smoothed_rtt_us: u64,
    latest_rtt_us: u64,
    pto_count: u32,
    pending_ping: bool,
    peer_prefers_backup: bool,
    peer_status_sequence_number: ?u64,

    // -- new observability fields --
    /// Total UDP payload bytes the connection has sent across this path.
    /// (`bytes_sent` above counts against anti-amp and resets on migration;
    /// this counter does not.)
    total_bytes_sent: u64 = 0,
    /// Total UDP payload bytes the connection has received across this path.
    /// (`bytes_received` resets on migration; this counter does not.)
    total_bytes_received: u64 = 0,
    /// Number of QUIC packets sent on the connection.
    packets_sent: u64 = 0,
    /// Number of QUIC packets received and authenticated on the connection.
    packets_received: u64 = 0,
    /// Number of QUIC packets declared lost on the connection.
    packets_lost: u64 = 0,
    /// RFC 9002 §5 RTT estimator snapshot (microseconds).
    srtt_us: u64 = 0,
    rttvar_us: u64 = 0,
    min_rtt_us: u64 = 0,
    /// Slow-start threshold in bytes; null = infinity (slow start active).
    ssthresh: ?u64 = null,
    /// Current congestion-control phase.
    congestion_window_state: CongestionState = .slow_start,

    // -- RFC 8899 DPLPMTUD observability ----------------------------
    /// Current path MTU floor in bytes — the maximum datagram size the
    /// transport will build outbound on this path.
    pmtu: usize = 0,
    /// Probe state-machine phase.
    pmtu_state: PmtudState = .disabled,
    /// Number of in-flight DPLPMTUD probes (0 or 1).
    pmtu_probes_in_flight: u16 = 0,
    /// Consecutive probe-loss counter at the current probe size.
    pmtu_fail_count: u16 = 0,
    /// Upper-bound size discovered via §5.1.5 probe-loss exhaustion.
    pmtu_upper_bound: ?u16 = null,
};

/// Snapshot of pre-migration path state, kept until the new 4-tuple
/// is validated. `rollbackFailedMigration` restores from this if
/// validation fails.
pub const MigrationRollback = struct {
    peer_addr: Address,
    peer_addr_set: bool,
    validated: bool,
    bytes_received: u64,
    bytes_sent: u64,
    state: State,
};

/// Per-path connection state that draft multipath requires to be
/// independent for Application packets. Initial and Handshake packet
/// number spaces stay connection-level.
pub const PathState = struct {
    id: u32,
    path: Path,
    app_pn_space: PnSpace = .{},
    sent: SentPacketTracker = .{},
    pto_count: u32 = 0,
    pending_ping: bool = false,
    pto_probe_count: u8 = 0,
    pmtu: usize = 1200,

    // -- RFC 8899 DPLPMTUD per-path state --------------------------
    //
    // The send path consults `pmtu_state` and `pmtu_probe_pn` on each
    // `pollLevelOnPath` call: when state is `search` and no probe is
    // in flight (probe_pn == null), it builds a PADDING+PING packet at
    // size `pmtu + probe_step` (capped at `pmtu_upper_bound` /
    // `max_mtu`) and stamps the resulting packet number in
    // `pmtu_probe_pn`. Probe ack / probe loss fire from
    // `Connection.onPacketAcked` / `requeueLostPacketOnPath` to clear
    // the in-flight slot and update `pmtu` (or `pmtu_fail_count`).
    //
    // **`pmtu_consecutive_regular_losses`** drives RFC 8899 §4.4
    // black-hole detection: every regular (non-probe) loss at the
    // current `pmtu` increments it; once it crosses `probe_threshold`,
    // the connection halves `pmtu` (down to `initial_mtu`) and
    // re-enters `search`.

    /// RFC 8899 probe-state-machine phase. Defaults to `disabled`;
    /// `Connection.init*` sets to `search` if PmtudConfig.enable.
    pmtu_state: PmtudState = .disabled,
    /// Packet number of the in-flight probe, or null if none. Only
    /// one probe is permitted in flight at a time per path (RFC 8899
    /// §5.3.2: the search algorithm runs probes serially).
    pmtu_probe_pn: ?u64 = null,
    /// Size in bytes the in-flight probe was padded to. Matches the
    /// resulting datagram size. Valid iff `pmtu_probe_pn != null`.
    pmtu_probed_size: u16 = 0,
    /// Consecutive-loss counter for the current probe size. Resets on
    /// any successful probe ack.
    pmtu_fail_count: u16 = 0,
    /// Recorded upper bound: the smallest probe size that has been
    /// declared lost `probe_threshold` times in a row. Probes never
    /// attempt sizes >= this value. Null = no upper bound discovered;
    /// search ceiling stays at `PmtudConfig.max_mtu`.
    pmtu_upper_bound: ?u16 = null,
    /// Number of in-flight probes ever transmitted on this path. The
    /// embedder reads this via `PathStats.pmtu_probes_in_flight` to
    /// confirm DPLPMTUD is active. Value reflects "currently in
    /// flight" (0 or 1) for symmetry with the existing PTO / PING
    /// counters.
    pmtu_probes_in_flight: u16 = 0,
    /// Consecutive regular-packet losses at the current PMTU for
    /// RFC 8899 §4.4 black-hole detection. Reset on any successful
    /// regular ack.
    pmtu_consecutive_regular_losses: u16 = 0,

    peer_addr_set: bool = false,
    local_addr_set: bool = false,
    retire_deadline_us: ?u64 = null,
    pending_migration_reset: bool = false,
    migration_rollback: ?MigrationRollback = null,
    peer_prefers_backup: bool = false,
    peer_status_sequence_number: ?u64 = null,
    local_status_sequence_number: u64 = 0,
    /// Highest sequence number we have ever assigned to a locally-issued
    /// connection ID on this path, plus one. Used to enforce
    /// RFC 9000 §19.16: a peer that sends RETIRE_CONNECTION_ID with a
    /// sequence number we never issued is committing a PROTOCOL_VIOLATION.
    /// Path 0 starts at 1 because sequence 0 is implicitly assigned to
    /// the long-header SCID; non-primary paths grow this when CIDs are
    /// issued via PATH_NEW_CONNECTION_ID.
    next_local_cid_seq: u64 = 0,

    /// Build a fresh `PathState` wrapping a `Path` initialized with
    /// the given 4-tuple, CIDs, and CC config.
    pub fn init(
        id: u32,
        peer_addr: Address,
        local_addr: Address,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        cc_cfg: congestion_mod.Config,
    ) PathState {
        return .{
            .id = id,
            .path = Path.init(peer_addr, local_addr, local_cid, peer_cid, cc_cfg),
        };
    }

    /// Free per-packet retransmit-frame and stream-key allocations.
    /// The `PathState` itself is not freed.
    pub fn deinit(self: *PathState, allocator: std.mem.Allocator) void {
        var i: u32 = 0;
        while (i < self.sent.count) : (i += 1) {
            self.sent.packets[i].deinit(allocator);
        }
    }

    /// Drop every tracked sent packet, clear the received-PN tracker,
    /// and zero PTO/ping state. Used on key-update boundaries and
    /// migration where in-flight bookkeeping is no longer meaningful.
    pub fn clearRecovery(self: *PathState, allocator: std.mem.Allocator) void {
        var i: u32 = 0;
        while (i < self.sent.count) : (i += 1) {
            self.sent.packets[i].deinit(allocator);
        }
        self.sent = .{};
        self.app_pn_space.received = .{};
        self.pending_ping = false;
        self.pto_probe_count = 0;
        self.pto_count = 0;
    }

    /// Reset RTT, congestion control, and PTO state after a successful
    /// migration. RFC 9000 §9.4 requires the sender to start over once
    /// the new 4-tuple is in use.
    pub fn resetRecoveryAfterMigration(
        self: *PathState,
        cc_cfg: congestion_mod.Config,
    ) void {
        self.path.rtt = .{};
        self.path.cc = NewReno.init(cc_cfg);
        self.pending_ping = false;
        self.pto_probe_count = 0;
        self.pto_count = 0;
        self.pending_migration_reset = false;
        self.migration_rollback = null;
    }

    /// Begin a migration to `peer_addr`. Snapshots current state into
    /// `migration_rollback` (if not already snapshotted), zeros the
    /// anti-amp counters, drops validation, and credits the triggering
    /// datagram against anti-amp.
    pub fn beginMigration(
        self: *PathState,
        peer_addr: Address,
        datagram_len: usize,
    ) void {
        if (self.migration_rollback == null) {
            self.migration_rollback = .{
                .peer_addr = self.path.peer_addr,
                .peer_addr_set = self.peer_addr_set,
                .validated = self.path.isValidated(),
                .bytes_received = self.path.bytes_received,
                .bytes_sent = self.path.bytes_sent,
                .state = self.path.state,
            };
        }
        self.setPeerAddress(peer_addr);
        self.path.validated = false;
        self.path.validator = .{};
        self.path.bytes_received = 0;
        self.path.bytes_sent = 0;
        self.path.onDatagramReceived(datagram_len);
        self.path.state = .active;
        self.pending_migration_reset = true;
    }

    /// Restore the snapshot saved by `beginMigration` after path
    /// validation fails. Returns true iff a rollback was applied.
    pub fn rollbackFailedMigration(self: *PathState) bool {
        const rollback = self.migration_rollback orelse return false;
        self.path.peer_addr = rollback.peer_addr;
        self.peer_addr_set = rollback.peer_addr_set;
        self.path.validated = rollback.validated;
        self.path.validator = .{};
        if (rollback.validated) self.path.validator.status = .validated;
        self.path.bytes_received = rollback.bytes_received;
        self.path.bytes_sent = rollback.bytes_sent;
        self.path.state = rollback.state;
        self.pending_migration_reset = false;
        self.migration_rollback = null;
        return true;
    }

    /// Current peer address, or null if it hasn't been observed yet.
    pub fn peerAddress(self: *const PathState) ?Address {
        if (!self.peer_addr_set) return null;
        return self.path.peer_addr;
    }

    /// True iff `addr` matches the live peer address or the
    /// pre-migration snapshot. Used to dispatch incoming datagrams
    /// during the validation window.
    pub fn matchesPeerAddress(self: *const PathState, addr: Address) bool {
        if (self.peer_addr_set and Address.eql(self.path.peer_addr, addr)) return true;
        return self.matchesMigrationRollbackAddress(addr);
    }

    /// True iff `addr` matches the pre-migration peer address kept
    /// in `migration_rollback`.
    pub fn matchesMigrationRollbackAddress(self: *const PathState, addr: Address) bool {
        const rollback = self.migration_rollback orelse return false;
        return rollback.peer_addr_set and Address.eql(rollback.peer_addr, addr);
    }

    /// Set or update the peer address for this path and mark it observed.
    pub fn setPeerAddress(self: *PathState, addr: Address) void {
        self.path.peer_addr = addr;
        self.peer_addr_set = true;
    }

    /// Set or update the local address for this path and mark it observed.
    pub fn setLocalAddress(self: *PathState, addr: Address) void {
        self.path.local_addr = addr;
        self.local_addr_set = true;
    }

    /// Build a `PathStats` snapshot of the current observability counters.
    pub fn stats(self: *const PathState) PathStats {
        const cc = &self.path.cc;
        const rtt = &self.path.rtt;
        const phase: CongestionState = blk: {
            if (cc.recovery_start_time_us != null) break :blk .recovery;
            if (cc.ssthresh == null or cc.cwnd < cc.ssthresh.?) break :blk .slow_start;
            break :blk .congestion_avoidance;
        };
        return .{
            .path_id = self.id,
            .state = self.path.state,
            .validated = self.path.isValidated(),
            .retire_deadline_us = self.retire_deadline_us,
            .bytes_received = self.path.bytes_received,
            .bytes_sent = self.path.bytes_sent,
            .bytes_in_flight = self.sent.bytes_in_flight,
            .ack_eliciting_in_flight = self.sent.ack_eliciting_in_flight,
            .cwnd = cc.cwnd,
            .smoothed_rtt_us = rtt.smoothed_rtt_us,
            .latest_rtt_us = rtt.latest_rtt_us,
            .pto_count = self.pto_count,
            .pending_ping = self.pending_ping,
            .peer_prefers_backup = self.peer_prefers_backup,
            .peer_status_sequence_number = self.peer_status_sequence_number,
            .srtt_us = rtt.smoothed_rtt_us,
            .rttvar_us = rtt.rtt_var_us,
            .min_rtt_us = rtt.min_rtt_us,
            .ssthresh = cc.ssthresh,
            .congestion_window_state = phase,
            .pmtu = self.pmtu,
            .pmtu_state = self.pmtu_state,
            .pmtu_probes_in_flight = self.pmtu_probes_in_flight,
            .pmtu_fail_count = self.pmtu_fail_count,
            .pmtu_upper_bound = self.pmtu_upper_bound,
        };
    }

    // -- RFC 8899 DPLPMTUD helpers ----------------------------------
    //
    // These are the small, unit-testable mutations the connection
    // calls from its send / ack / loss hot paths. Splitting them into
    // named methods keeps `state.zig` readable and lets the inline
    // tests below pin the state machine without standing up a full
    // Connection.

    /// True iff DPLPMTUD probing is enabled and the current state is
    /// `search`. `Connection.pollLevelOnPath` consults this to decide
    /// whether to emit a probe at the next opportunity.
    pub fn pmtudIsSearching(self: *const PathState) bool {
        return self.pmtu_state == .search and self.pmtu_probe_pn == null;
    }

    /// Return the next probe size in bytes given the embedder's
    /// configured `probe_step` and `max_mtu`, or null if no further
    /// probe is permitted (search complete / disabled / upper-bound
    /// reached). RFC 8899 §5.3.1 search algorithm.
    ///
    /// The upper bound is interpreted as a CLOSED ceiling — probes
    /// never re-try a size we already declared lost
    /// `probe_threshold` times. `max_mtu` is the OPEN ceiling: a
    /// probe at exactly `max_mtu` is allowed (e.g. to tighten on a
    /// 1500-byte ethernet path with 28 bytes of IPv4+UDP overhead
    /// already accounted for).
    pub fn pmtudNextProbeSize(
        self: *const PathState,
        probe_step: u16,
        max_mtu: u16,
    ) ?u16 {
        if (self.pmtu_state != .search) return null;
        if (self.pmtu_probe_pn != null) return null;
        const cur: u32 = @intCast(self.pmtu);
        const step: u32 = probe_step;
        const candidate: u32 = cur + step;
        if (self.pmtu_upper_bound) |ub| {
            if (candidate >= @as(u32, ub)) return null;
        }
        if (candidate > @as(u32, max_mtu)) return null;
        return @intCast(candidate);
    }

    /// Stamp a freshly-emitted probe's metadata. Called by the send
    /// path after the packet is sealed onto the wire. `pn` is the
    /// QUIC packet number the probe occupies; `size` is the resulting
    /// datagram size in bytes.
    pub fn pmtudOnProbeSent(self: *PathState, pn: u64, size: u16) void {
        self.pmtu_probe_pn = pn;
        self.pmtu_probed_size = size;
        self.pmtu_probes_in_flight = 1;
    }

    /// Probe ack: lift `pmtu` to the probed size and reset the fail
    /// counter. If the next probe step would exceed the ceiling,
    /// transition to `search_complete` (RFC 8899 §5.3.1 termination).
    /// Returns the new pmtu value.
    pub fn pmtudOnProbeAcked(
        self: *PathState,
        probe_step: u16,
        max_mtu: u16,
    ) usize {
        const probed = self.pmtu_probed_size;
        self.pmtu = probed;
        self.pmtu_probe_pn = null;
        self.pmtu_probes_in_flight = 0;
        self.pmtu_probed_size = 0;
        self.pmtu_fail_count = 0;
        self.pmtu_consecutive_regular_losses = 0;
        const next: u32 = @as(u32, probed) + probe_step;
        // Termination: stop searching when the next probe size
        // would land at or above a recorded upper bound, or strictly
        // above max_mtu (the OPEN ceiling).
        const upper_bound_blocks = if (self.pmtu_upper_bound) |ub|
            next >= @as(u32, ub)
        else
            false;
        if (upper_bound_blocks or next > @as(u32, max_mtu)) {
            self.pmtu_state = .search_complete;
        }
        return self.pmtu;
    }

    /// Probe loss: bump `pmtu_fail_count`. Once it reaches
    /// `probe_threshold`, record the probed size as the upper bound
    /// (no further probes at or above this value) and reset for the
    /// NEXT probe at the current `pmtu`. RFC 8899 §5.1.4 / §5.1.5.
    /// Returns true iff the upper bound was just recorded.
    pub fn pmtudOnProbeLost(self: *PathState, probe_threshold: u16) bool {
        const probed = self.pmtu_probed_size;
        self.pmtu_probe_pn = null;
        self.pmtu_probes_in_flight = 0;
        self.pmtu_probed_size = 0;
        self.pmtu_fail_count +|= 1;
        if (self.pmtu_fail_count >= probe_threshold) {
            // Record the upper bound and stay in search at current pmtu.
            // If a tighter bound was already known (e.g. peer
            // max_udp_payload_size), keep the smaller one.
            const new_ub: u16 = probed;
            self.pmtu_upper_bound = if (self.pmtu_upper_bound) |old|
                @min(old, new_ub)
            else
                new_ub;
            self.pmtu_fail_count = 0;
            // If the bound is at or below current pmtu the search
            // can never advance — transition to search_complete. The
            // upper bound is interpreted as a CLOSED ceiling
            // (matching `pmtudNextProbeSize`), so equality also
            // blocks further search.
            if (@as(u32, self.pmtu_upper_bound.?) <= @as(u32, @intCast(self.pmtu))) {
                self.pmtu_state = .search_complete;
            }
            return true;
        }
        return false;
    }

    /// Regular-packet (non-probe) ack: reset the consecutive
    /// regular-loss counter. Black-hole detection only fires on a
    /// SUSTAINED run of regular losses with no acks in between.
    pub fn pmtudOnRegularAcked(self: *PathState) void {
        self.pmtu_consecutive_regular_losses = 0;
    }

    /// Regular-packet loss at the current pmtu — increments the
    /// consecutive-loss counter and, once it reaches `probe_threshold`,
    /// halves the pmtu (down to `initial_mtu`) and re-enters `search`.
    /// RFC 8899 §4.4 black-hole detection. Returns true iff the
    /// black-hole branch fired.
    pub fn pmtudOnRegularLost(
        self: *PathState,
        probe_threshold: u16,
        initial_mtu: u16,
    ) bool {
        if (self.pmtu_state == .disabled) return false;
        self.pmtu_consecutive_regular_losses +|= 1;
        if (self.pmtu_consecutive_regular_losses < probe_threshold) return false;
        // Halve the PMTU but never go below the floor.
        const halved: usize = @max(self.pmtu / 2, @as(usize, initial_mtu));
        self.pmtu = halved;
        self.pmtu_consecutive_regular_losses = 0;
        self.pmtu_fail_count = 0;
        self.pmtu_upper_bound = null;
        self.pmtu_probe_pn = null;
        self.pmtu_probes_in_flight = 0;
        self.pmtu_probed_size = 0;
        self.pmtu_state = .search;
        return true;
    }

    /// Initialise the PMTUD state machine from the embedder's config.
    /// Called from `Connection.init*` once the primary path exists.
    pub fn pmtudInit(self: *PathState, cfg: PmtudConfig) void {
        self.pmtu = cfg.initial_mtu;
        self.pmtu_state = if (cfg.enable) .search else .disabled;
        self.pmtu_probe_pn = null;
        self.pmtu_probes_in_flight = 0;
        self.pmtu_probed_size = 0;
        self.pmtu_fail_count = 0;
        self.pmtu_consecutive_regular_losses = 0;
        self.pmtu_upper_bound = null;
    }

    /// Apply an incoming PATH_AVAILABLE / PATH_BACKUP frame
    /// (draft-ietf-quic-multipath-21). Stale sequence numbers are
    /// ignored; an `available` flag wakes a `fresh` path into `active`.
    pub fn recordPeerStatus(self: *PathState, available: bool, sequence_number: u64) void {
        if (self.peer_status_sequence_number) |old| {
            if (sequence_number <= old) return;
        }
        self.peer_status_sequence_number = sequence_number;
        self.peer_prefers_backup = !available;
        if (available and self.path.state == .fresh) self.path.state = .active;
    }
};

/// Collection of `PathState` entries belonging to one Connection.
/// Owns scheduling cursors and the primary/active ids that select
/// where each outgoing packet ships.
pub const PathSet = struct {
    paths: std.ArrayList(PathState) = .empty,
    primary_id: u32 = 0,
    active_id: u32 = 0,
    next_path_id: u32 = 1,
    scheduler: Scheduler = .primary,
    rr_cursor: usize = 0,

    /// Lazily install the primary path (id 0) on first use. No-op if
    /// the set already has paths.
    ///
    /// The primary starts in the **unvalidated** state. Each role decides
    /// when to flip it (`Path.markValidated`):
    ///
    /// - **Client**: validated immediately after `ensurePrimary` returns.
    ///   The client picked the destination address itself; there is no
    ///   spoofing risk for its own outbound, so the §8.1 3x cap doesn't
    ///   apply.
    /// - **Server**: validated when a Handshake-level packet from the
    ///   peer decrypts successfully (RFC 9000 §8.1). Only the genuine
    ///   peer holds Handshake keys, so a successful open proves the
    ///   source address. Until then the §8.1 anti-amplification cap
    ///   throttles outbound bytes to `3 * bytes_received`.
    pub fn ensurePrimary(
        self: *PathSet,
        allocator: std.mem.Allocator,
        cc_cfg: congestion_mod.Config,
    ) !void {
        if (self.paths.items.len != 0) return;
        var p = PathState.init(0, .{}, .{}, .{}, .{}, cc_cfg);
        p.path.state = .active;
        try self.paths.append(allocator, p);
    }

    /// Free every contained `PathState` and the path list itself.
    pub fn deinit(self: *PathSet, allocator: std.mem.Allocator) void {
        for (self.paths.items) |*p| p.deinit(allocator);
        self.paths.deinit(allocator);
        self.* = .{};
    }

    /// Look up a mutable path by id. Returns null if no path matches.
    pub fn get(self: *PathSet, id: u32) ?*PathState {
        for (self.paths.items) |*p| {
            if (p.id == id) return p;
        }
        return null;
    }

    /// Look up an immutable path by id. Returns null if no path matches.
    pub fn getConst(self: *const PathSet, id: u32) ?*const PathState {
        for (self.paths.items) |*p| {
            if (p.id == id) return p;
        }
        return null;
    }

    /// Mutable handle to the primary path (id `primary_id`). The
    /// primary path is guaranteed to exist after `ensurePrimary`.
    pub fn primary(self: *PathSet) *PathState {
        // invariant: primary_id is set in init() before any caller
        // can observe a PathSet, and openPath/abandon never remove
        // the primary entry. Not peer-reachable.
        return self.get(self.primary_id) orelse unreachable;
    }

    /// Immutable handle to the primary path.
    pub fn primaryConst(self: *const PathSet) *const PathState {
        // invariant: see primary(). Not peer-reachable.
        return self.getConst(self.primary_id) orelse unreachable;
    }

    /// Mutable handle to the active path (the one new application data
    /// goes on). Falls back to primary if `active_id` is stale.
    pub fn active(self: *PathSet) *PathState {
        return self.get(self.active_id) orelse self.primary();
    }

    /// Immutable handle to the active path.
    pub fn activeConst(self: *const PathSet) *const PathState {
        return self.getConst(self.active_id) orelse self.primaryConst();
    }

    /// Promote `id` to active. Returns false if no such path exists.
    pub fn setActive(self: *PathSet, id: u32) bool {
        if (self.get(id) == null) return false;
        self.active_id = id;
        return true;
    }

    /// Switch the multipath scheduler policy.
    pub fn setScheduler(self: *PathSet, scheduler: Scheduler) void {
        self.scheduler = scheduler;
    }

    /// Allocate a new path id and append a `PathState` for the given
    /// 4-tuple/CID pair. Returns the new id.
    pub fn openPath(
        self: *PathSet,
        allocator: std.mem.Allocator,
        peer_addr: Address,
        local_addr: Address,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        cc_cfg: congestion_mod.Config,
    ) !u32 {
        const id = self.next_path_id;
        self.next_path_id += 1;
        var p = PathState.init(id, peer_addr, local_addr, local_cid, peer_cid, cc_cfg);
        p.peer_addr_set = true;
        p.local_addr_set = true;
        try self.paths.append(allocator, p);
        return id;
    }

    /// Mark the given path as retiring and bounce active to primary
    /// if it was active. Returns false if the id is unknown or the
    /// path is already failed.
    pub fn abandon(self: *PathSet, id: u32) bool {
        const p = self.get(id) orelse return false;
        if (p.path.state == .failed) return false;
        p.path.retire();
        if (self.active_id == id) self.active_id = self.primary_id;
        return true;
    }

    /// Snapshot stats for the path with `id`, or null if unknown.
    pub fn stats(self: *const PathSet, id: u32) ?PathStats {
        const p = self.getConst(id) orelse return null;
        return p.stats();
    }

    /// Pick the next path to send on according to the active
    /// `Scheduler`. Returns the active/primary path as a fallback.
    pub fn selectForSending(self: *PathSet) *PathState {
        return switch (self.scheduler) {
            .primary => self.active(),
            .round_robin => self.selectRoundRobin(),
            .lowest_rtt_cwnd => self.selectLowestRttCwnd(),
        };
    }

    fn sendable(p: *const PathState) bool {
        return p.path.state != .failed and p.path.state != .retiring;
    }

    fn selectRoundRobin(self: *PathSet) *PathState {
        // invariant: callers only invoke this from selectForSending,
        // which is reachable only after openPath has been called at
        // least once (i.e. after a Connection is initialized). Not
        // peer-reachable.
        if (self.paths.items.len == 0) unreachable;
        var attempts: usize = 0;
        while (attempts < self.paths.items.len) : (attempts += 1) {
            const idx = self.rr_cursor % self.paths.items.len;
            self.rr_cursor = (idx + 1) % self.paths.items.len;
            if (sendable(&self.paths.items[idx])) return &self.paths.items[idx];
        }
        return self.active();
    }

    fn selectLowestRttCwnd(self: *PathSet) *PathState {
        var best: ?*PathState = null;
        for (self.paths.items) |*p| {
            if (!sendable(p)) continue;
            if (best == null) {
                best = p;
                continue;
            }
            const p_allowance = p.path.cc.sendAllowance(p.sent.bytes_in_flight);
            const best_allowance = best.?.path.cc.sendAllowance(best.?.sent.bytes_in_flight);
            if (p_allowance == 0 and best_allowance > 0) continue;
            if (p_allowance > 0 and best_allowance == 0) {
                best = p;
                continue;
            }
            const p_rtt = if (p.path.rtt.smoothed_rtt_us == 0)
                std.math.maxInt(u64)
            else
                p.path.rtt.smoothed_rtt_us;
            const best_rtt = if (best.?.path.rtt.smoothed_rtt_us == 0)
                std.math.maxInt(u64)
            else
                best.?.path.rtt.smoothed_rtt_us;
            if (p_rtt < best_rtt) best = p;
        }
        return best orelse self.active();
    }
};

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn testCid(s: []const u8) ConnectionId {
    return ConnectionId.fromSlice(s);
}

test "anti-amp: unvalidated server can send 3x what it received" {
    var p = Path.init(
        .{},
        .{},
        testCid(&.{ 1, 2, 3 }),
        testCid(&.{ 9, 9, 9 }),
        .{ .max_datagram_size = 1200 },
    );
    p.onDatagramReceived(1200); // peer's first Initial
    try testing.expectEqual(@as(u64, 3600), p.antiAmpAllowance());
    p.onDatagramSent(1200);
    try testing.expectEqual(@as(u64, 2400), p.antiAmpAllowance());
    p.onDatagramSent(1200);
    p.onDatagramSent(1200);
    try testing.expectEqual(@as(u64, 0), p.antiAmpAllowance());
}

test "anti-amp: validated path has unlimited allowance" {
    var p = Path.init(.{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    p.onDatagramReceived(100);
    p.onDatagramSent(1_000_000);
    try testing.expectEqual(@as(u64, 0), p.antiAmpAllowance());
    p.markValidated();
    try testing.expectEqual(std.math.maxInt(u64), p.antiAmpAllowance());
}

test "datagram lifecycle moves path from fresh -> active" {
    var p = Path.init(.{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    try testing.expectEqual(State.fresh, p.state);
    p.onDatagramReceived(800);
    try testing.expectEqual(State.active, p.state);
}

test "validator integration: PATH_CHALLENGE -> PATH_RESPONSE validates the path" {
    var p = Path.init(.{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    p.onDatagramReceived(1200); // some incoming
    try testing.expect(!p.isValidated());

    const token: [8]u8 = .{ 7, 7, 7, 7, 7, 7, 7, 7 };
    p.validator.beginChallenge(token, 1000, 100_000);
    _ = try p.validator.recordResponse(token);
    try testing.expect(p.isValidated());
    // Validated paths are free from anti-amp.
    try testing.expectEqual(std.math.maxInt(u64), p.antiAmpAllowance());
}

test "ConnectionId equality and slice" {
    const a = ConnectionId.fromSlice(&.{ 1, 2, 3, 4 });
    const b = ConnectionId.fromSlice(&.{ 1, 2, 3, 4 });
    const c = ConnectionId.fromSlice(&.{ 1, 2, 3, 5 });
    try testing.expect(ConnectionId.eql(a, b));
    try testing.expect(!ConnectionId.eql(a, c));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, a.slice());
}

test "retire and fail transitions" {
    var p = Path.init(.{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    p.onDatagramReceived(1);
    try testing.expectEqual(State.active, p.state);
    p.retire();
    try testing.expectEqual(State.retiring, p.state);
    p.fail();
    try testing.expectEqual(State.failed, p.state);
}

test "PathSet starts with active, unvalidated path 0" {
    var set: PathSet = .{};
    defer set.deinit(testing.allocator);
    try set.ensurePrimary(testing.allocator, .{ .max_datagram_size = 1200 });

    try testing.expectEqual(@as(usize, 1), set.paths.items.len);
    try testing.expectEqual(@as(u32, 0), set.primary().id);
    try testing.expectEqual(State.active, set.primary().path.state);
    // ensurePrimary leaves the path unvalidated; each role decides when to
    // flip it (see PathSet.ensurePrimary docs and Connection.initClient /
    // handleHandshake for the matching policies).
    try testing.expect(!set.primary().path.isValidated());
    try testing.expectEqual(@as(u32, 0), set.selectForSending().id);
}

test "PathSet opens and abandons additional paths" {
    var set: PathSet = .{};
    defer set.deinit(testing.allocator);
    try set.ensurePrimary(testing.allocator, .{ .max_datagram_size = 1200 });

    const id = try set.openPath(testing.allocator, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    try testing.expectEqual(@as(u32, 1), id);
    try testing.expect(set.setActive(id));
    try testing.expectEqual(id, set.active().id);
    try testing.expect(set.abandon(id));
    try testing.expectEqual(State.retiring, set.get(id).?.path.state);
    try testing.expectEqual(@as(u32, 0), set.active().id);
}

// -- RFC 8899 DPLPMTUD inline state-machine tests -----------------

test "DPLPMTUD: pmtudInit configures floor and search state" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{
        .initial_mtu = 1200,
        .max_mtu = 1452,
        .probe_step = 64,
        .probe_threshold = 3,
        .enable = true,
    });
    try testing.expectEqual(@as(usize, 1200), ps.pmtu);
    try testing.expectEqual(PmtudState.search, ps.pmtu_state);
    try testing.expectEqual(@as(?u64, null), ps.pmtu_probe_pn);
    try testing.expect(ps.pmtudIsSearching());
}

test "DPLPMTUD: enable=false leaves state disabled" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .enable = false });
    try testing.expectEqual(PmtudState.disabled, ps.pmtu_state);
    try testing.expect(!ps.pmtudIsSearching());
}

test "DPLPMTUD: pmtudNextProbeSize advances by probe_step until ceiling" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .initial_mtu = 1200, .max_mtu = 1280, .probe_step = 50 });
    try testing.expectEqual(@as(?u16, 1250), ps.pmtudNextProbeSize(50, 1280));
    ps.pmtu = 1250;
    try testing.expectEqual(@as(?u16, null), ps.pmtudNextProbeSize(50, 1280));
}

test "DPLPMTUD: probe ack lifts pmtu and resets fail counter" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .initial_mtu = 1200, .max_mtu = 1452, .probe_step = 64 });
    ps.pmtudOnProbeSent(7, 1264);
    ps.pmtu_fail_count = 2; // pretend we'd had earlier losses
    _ = ps.pmtudOnProbeAcked(64, 1452);
    try testing.expectEqual(@as(usize, 1264), ps.pmtu);
    try testing.expectEqual(@as(?u64, null), ps.pmtu_probe_pn);
    try testing.expectEqual(@as(u16, 0), ps.pmtu_fail_count);
    try testing.expectEqual(PmtudState.search, ps.pmtu_state);
}

test "DPLPMTUD: probe ack flips to search_complete at the ceiling" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .initial_mtu = 1200, .max_mtu = 1300, .probe_step = 64 });
    ps.pmtudOnProbeSent(11, 1264);
    _ = ps.pmtudOnProbeAcked(64, 1300);
    try testing.expectEqual(@as(usize, 1264), ps.pmtu);
    // 1264 + 64 = 1328 > 1300 ceiling → search_complete.
    try testing.expectEqual(PmtudState.search_complete, ps.pmtu_state);
}

test "DPLPMTUD: probe loss bumps fail_count, threshold records upper bound" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .initial_mtu = 1200, .max_mtu = 1500, .probe_step = 50, .probe_threshold = 3 });

    // Loss 1, 2: just bump counter.
    ps.pmtudOnProbeSent(1, 1300);
    try testing.expect(!ps.pmtudOnProbeLost(3));
    try testing.expectEqual(@as(u16, 1), ps.pmtu_fail_count);

    ps.pmtudOnProbeSent(2, 1300);
    try testing.expect(!ps.pmtudOnProbeLost(3));
    try testing.expectEqual(@as(u16, 2), ps.pmtu_fail_count);

    // Loss 3: record upper bound.
    ps.pmtudOnProbeSent(3, 1300);
    try testing.expect(ps.pmtudOnProbeLost(3));
    try testing.expectEqual(@as(?u16, 1300), ps.pmtu_upper_bound);
    // pmtu stays at floor (1200), state stays search but ceiling now 1300.
    try testing.expectEqual(@as(usize, 1200), ps.pmtu);
    try testing.expectEqual(PmtudState.search, ps.pmtu_state);
    // Next probe size is bounded by the new upper bound. Upper bound
    // is CLOSED — 1200+50=1250 < 1300, so 1250 is the next candidate.
    try testing.expectEqual(@as(?u16, 1250), ps.pmtudNextProbeSize(50, 1500));
}

test "DPLPMTUD: probe loss at floor with bound at floor → search_complete" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .initial_mtu = 1200, .max_mtu = 1500, .probe_step = 100, .probe_threshold = 1 });
    // First loss with threshold=1: record bound and check the
    // search_complete branch when bound <= pmtu. Probed size 1200 is
    // exactly the floor.
    ps.pmtudOnProbeSent(1, 1200);
    _ = ps.pmtudOnProbeLost(1);
    try testing.expectEqual(@as(?u16, 1200), ps.pmtu_upper_bound);
    try testing.expectEqual(PmtudState.search_complete, ps.pmtu_state);
}

test "DPLPMTUD: black-hole detection halves pmtu after probe_threshold regular losses" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .initial_mtu = 1200, .max_mtu = 1452, .probe_step = 64, .probe_threshold = 3 });
    // Pretend pmtu was lifted to 1400 via prior probes.
    ps.pmtu = 1400;
    ps.pmtu_state = .search_complete;
    try testing.expect(!ps.pmtudOnRegularLost(3, 1200));
    try testing.expectEqual(@as(u16, 1), ps.pmtu_consecutive_regular_losses);
    try testing.expect(!ps.pmtudOnRegularLost(3, 1200));
    try testing.expect(ps.pmtudOnRegularLost(3, 1200));
    // 1400 / 2 = 700, but never below floor 1200.
    try testing.expectEqual(@as(usize, 1200), ps.pmtu);
    try testing.expectEqual(PmtudState.search, ps.pmtu_state);
    try testing.expectEqual(@as(u16, 0), ps.pmtu_consecutive_regular_losses);
}

test "DPLPMTUD: a regular ack resets the consecutive-loss counter" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{});
    ps.pmtu = 1300;
    _ = ps.pmtudOnRegularLost(3, 1200);
    _ = ps.pmtudOnRegularLost(3, 1200);
    try testing.expectEqual(@as(u16, 2), ps.pmtu_consecutive_regular_losses);
    ps.pmtudOnRegularAcked();
    try testing.expectEqual(@as(u16, 0), ps.pmtu_consecutive_regular_losses);
    // Now another loss is below threshold → no halving.
    try testing.expect(!ps.pmtudOnRegularLost(3, 1200));
    try testing.expectEqual(@as(usize, 1300), ps.pmtu);
}

test "DPLPMTUD: disabled state never enters black-hole detection" {
    var ps = PathState.init(0, .{}, .{}, testCid(&.{1}), testCid(&.{2}), .{});
    ps.pmtudInit(.{ .enable = false });
    try testing.expect(!ps.pmtudOnRegularLost(1, 1200));
    try testing.expect(!ps.pmtudOnRegularLost(1, 1200));
    try testing.expect(!ps.pmtudOnRegularLost(1, 1200));
    try testing.expectEqual(PmtudState.disabled, ps.pmtu_state);
}
