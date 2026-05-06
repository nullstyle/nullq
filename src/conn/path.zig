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

/// Placeholder address. Holds enough bytes for an IPv6 sockaddr
/// (16-byte address + 2-byte port + 4-byte scope/flow). Phase 6
/// will replace this with `std.net.Address`.
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
/// validator, RTT, congestion). Most connections have one Path; phase
/// 9/10 add more for migration and multipath.
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
    /// the anti-amp ceiling and (Phase 5) keeps the path live.
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
        };
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
    pub fn ensurePrimary(
        self: *PathSet,
        allocator: std.mem.Allocator,
        cc_cfg: congestion_mod.Config,
    ) !void {
        if (self.paths.items.len != 0) return;
        var p = PathState.init(0, .{}, .{}, .{}, .{}, cc_cfg);
        p.path.markValidated();
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

test "PathSet starts with validated path 0" {
    var set: PathSet = .{};
    defer set.deinit(testing.allocator);
    try set.ensurePrimary(testing.allocator, .{ .max_datagram_size = 1200 });

    try testing.expectEqual(@as(usize, 1), set.paths.items.len);
    try testing.expectEqual(@as(u32, 0), set.primary().id);
    try testing.expect(set.primary().path.isValidated());
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
