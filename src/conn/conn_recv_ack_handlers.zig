// Inbound ACK frame processing: per-encryption-level ACKs, the
// multipath PATH_ACK twin, and the loss-recovery callback that
// re-queues control frames RFC 9002 has declared lost. Free-function
// siblings of `Connection`'s public method-style handlers; the
// methods on `Connection` are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const PathState = state_mod.PathState;
const frame_types = state_mod.frame_types;
const ack_range_mod = state_mod.ack_range_mod;
const sent_packets_mod = state_mod.sent_packets_mod;
const pn_space_mod = state_mod.pn_space_mod;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

/// Validate the ECN counts trailer of a peer ACK frame against the
/// rules in RFC 9000 §13.4.2:
///
///   * The ECT0 + ECT1 + CE total in the new ACK MUST be at least
///     as large as the previous ACK's total at this level (each
///     individual count MUST be monotonically non-decreasing as
///     well).
///   * The CE count's increase MAY trigger a congestion event;
///     ECT0 / ECT1 increases are informational.
///
/// Returns a `bool` indicating whether the frame was accepted. On
/// rejection, the caller flips the level's `validation` to `failed`
/// so subsequent ACKs at this level stop emitting our own ECN
/// counts and stop reacting to peer-reported CE bumps.
fn validateAndApplyAckEcn(
    pn_space: *pn_space_mod.PnSpace,
    ecn_counts: ?frame_types.EcnCounts,
) bool {
    const counts = ecn_counts orelse return true; // No ECN trailer → no validation.
    if (pn_space.validation == .failed) return false;

    if (pn_space.peer_ack_ecn_seen) {
        if (counts.ect0 < pn_space.peer_ack_ect0) return false;
        if (counts.ect1 < pn_space.peer_ack_ect1) return false;
        if (counts.ecn_ce < pn_space.peer_ack_ce) return false;
    }
    pn_space.peer_ack_ect0 = counts.ect0;
    pn_space.peer_ack_ect1 = counts.ect1;
    pn_space.peer_ack_ce = counts.ecn_ce;
    pn_space.peer_ack_ecn_seen = true;
    return true;
}

/// Compute the change in CE count between this ACK and the previous
/// one at the same level. Returns `null` when no prior ECN counts
/// were captured (the bump signal isn't meaningful in isolation —
/// the first count we see is the *running total*, not a delta).
fn ceDelta(
    prev_seen: bool,
    prev_ce: u64,
    new_counts: ?frame_types.EcnCounts,
) ?u64 {
    if (!prev_seen) return null;
    const c = new_counts orelse return null;
    if (c.ecn_ce <= prev_ce) return 0;
    return c.ecn_ce - prev_ce;
}

const LevelAckDispatchCtx = struct {
    self: *Connection,
    lvl: EncryptionLevel,
    ack: frame_types.Ack,
    now_us: u64,
    ack_path: *PathState,
    largest_acked_send_time_us: *?u64,
    largest_acked_ack_eliciting: *bool,
    any_ack_eliciting_newly_acked: *bool,
    in_flight_bytes_acked: *u64,
    newest_acked_sent_time_us: *u64,
    pmtud_probe_acked: *bool,
    any_regular_acked: *bool,
};

fn dispatchAckedAtLevel(
    ctx: *LevelAckDispatchCtx,
    acked: *sent_packets_mod.SentPacket,
) Error!void {
    defer acked.deinit(ctx.self.allocator);
    if (acked.pn == ctx.ack.largest_acked) {
        ctx.largest_acked_send_time_us.* = acked.sent_time_us;
        ctx.largest_acked_ack_eliciting.* = acked.ack_eliciting;
    }
    if (acked.ack_eliciting) ctx.any_ack_eliciting_newly_acked.* = true;
    if (acked.in_flight) {
        ctx.in_flight_bytes_acked.* += acked.bytes;
        if (acked.sent_time_us > ctx.newest_acked_sent_time_us.*) {
            ctx.newest_acked_sent_time_us.* = acked.sent_time_us;
        }
    }
    // RFC 8899 §5.1 probe-vs-regular ack classification —
    // 1-RTT only.
    if (ctx.lvl == .application) {
        if (ctx.ack_path.pmtu_probe_pn) |probe_pn| {
            if (probe_pn == acked.pn) {
                ctx.pmtud_probe_acked.* = true;
            } else {
                ctx.any_regular_acked.* = true;
            }
        } else {
            ctx.any_regular_acked.* = true;
        }
        ctx.self.onApplicationPacketAckedForKeys(acked, ctx.now_us);
        try ctx.self.dispatchAckedPacketToStreams(acked);
    }
    ctx.self.discardSentCryptoForPacket(ctx.lvl, acked.pn);
    ctx.self.dispatchAckedControlFrames(acked);
    ctx.self.recordDatagramAcked(acked);
}

const PathAckDispatchCtx = struct {
    self: *Connection,
    path: *PathState,
    ack: frame_types.Ack,
    now_us: u64,
    largest_acked_send_time_us: *?u64,
    largest_acked_ack_eliciting: *bool,
    any_ack_eliciting_newly_acked: *bool,
    in_flight_bytes_acked: *u64,
    newest_acked_sent_time_us: *u64,
    pmtud_probe_acked: *bool,
    any_regular_acked: *bool,
};

fn dispatchAckedOnPath(
    ctx: *PathAckDispatchCtx,
    acked: *sent_packets_mod.SentPacket,
) Error!void {
    defer acked.deinit(ctx.self.allocator);
    if (acked.pn == ctx.ack.largest_acked) {
        ctx.largest_acked_send_time_us.* = acked.sent_time_us;
        ctx.largest_acked_ack_eliciting.* = acked.ack_eliciting;
    }
    if (acked.ack_eliciting) ctx.any_ack_eliciting_newly_acked.* = true;
    if (acked.in_flight) {
        ctx.in_flight_bytes_acked.* += acked.bytes;
        if (acked.sent_time_us > ctx.newest_acked_sent_time_us.*) {
            ctx.newest_acked_sent_time_us.* = acked.sent_time_us;
        }
    }
    // RFC 8899 §5.1 probe-vs-regular ack classification.
    if (ctx.path.pmtu_probe_pn) |probe_pn| {
        if (probe_pn == acked.pn) {
            ctx.pmtud_probe_acked.* = true;
        } else {
            ctx.any_regular_acked.* = true;
        }
    } else {
        ctx.any_regular_acked.* = true;
    }
    try ctx.self.dispatchAckedPacketToStreams(acked);
    ctx.self.onApplicationPacketAckedForKeys(acked, ctx.now_us);
    ctx.self.discardSentCryptoForPacket(.application, acked.pn);
    ctx.self.dispatchAckedControlFrames(acked);
    ctx.self.recordDatagramAcked(acked);
}

pub fn handleAckAtLevel(
    self: *Connection,
    lvl: EncryptionLevel,
    a: frame_types.Ack,
    now_us: u64,
) Error!void {
    // Walk ACK ranges and notify each PN at this level to:
    //   1. every open SendStream (application level only),
    //   2. the per-level SentPacketTracker.
    //
    // FIXME(audit): O(streams × PNs) per ACK — a per-PN side-table
    // would make this O(1).
    const pn_space = self.pnSpaceForLevel(lvl);
    const sent = self.sentForLevel(lvl);
    // The path that owns 1-RTT in-flight bookkeeping. For Initial /
    // Handshake we still consult it (the primary) so RFC 8899
    // counters stay coherent, but no probes ride those levels.
    const ack_path: *PathState = self.primaryPath();
    // RFC 9000 §13.1 / RFC 9002 §A.3: an ACK that claims a packet
    // number we never sent (largest_acked >= next_pn) is a
    // PROTOCOL_VIOLATION. We must reject it before updating
    // largest_acked_sent — otherwise the bogus value would
    // poison packet-threshold loss detection on legitimate
    // in-flight packets.
    if (a.largest_acked >= pn_space.next_pn) {
        self.close(true, transport_error_protocol_violation, "ack of unsent packet");
        return;
    }
    // RFC 9000 §13.4.2: validate peer-reported ECN counts BEFORE
    // we walk the ACK ranges, so we can compute the CE delta
    // against the captured baseline rather than the just-mutated
    // baseline. Validation that fails here flips the level's
    // ECN state to `failed`; future outbound ACKs stop emitting
    // ECN counts at this level (`ecn_enabled` still says yes
    // overall, but this space is bleached).
    const prev_ecn_seen = pn_space.peer_ack_ecn_seen;
    const prev_ce = pn_space.peer_ack_ce;
    const ecn_ok = if (self.ecn_enabled) validateAndApplyAckEcn(pn_space, a.ecn_counts) else true;
    if (!ecn_ok) {
        pn_space.validation = .failed;
    }
    pn_space.onAckReceived(a.largest_acked);
    var largest_acked_send_time_us: ?u64 = null;
    var largest_acked_ack_eliciting = false;
    var any_ack_eliciting_newly_acked = false;
    var in_flight_bytes_acked: u64 = 0;
    var newest_acked_sent_time_us: u64 = 0;
    // RFC 8899 DPLPMTUD probe-ack vs regular-ack tracking.
    var pmtud_probe_acked = false;
    var any_regular_acked = false;
    var dispatch_ctx: LevelAckDispatchCtx = .{
        .self = self,
        .lvl = lvl,
        .ack = a,
        .now_us = now_us,
        .ack_path = ack_path,
        .largest_acked_send_time_us = &largest_acked_send_time_us,
        .largest_acked_ack_eliciting = &largest_acked_ack_eliciting,
        .any_ack_eliciting_newly_acked = &any_ack_eliciting_newly_acked,
        .in_flight_bytes_acked = &in_flight_bytes_acked,
        .newest_acked_sent_time_us = &newest_acked_sent_time_us,
        .pmtud_probe_acked = &pmtud_probe_acked,
        .any_regular_acked = &any_regular_acked,
    };

    var ack_it = ack_range_mod.iter(a);
    while (try ack_it.next()) |interval| {
        // Walk the (small, bounded) sent-packet tracker rather
        // than every PN in [smallest, largest]. A peer-chosen
        // first_range can stretch interval.smallest down to 0;
        // iterating the PN range directly would let a single
        // ACK force O(next_pn) work, which on a long-lived
        // connection is a real DoS surface (RFC 9000 §13.1
        // only constrains largest_acked < next_pn). Walking
        // the tracker is O(K log N) where K = packets matched
        // and N = tracker size, both bounded by our own send
        // rate × CWND.
        const start = sent.lowerBound(interval.smallest) orelse continue;
        var end = start;
        while (end < sent.count and sent.packets[end].pn <= interval.largest) : (end += 1) {}
        try sent.removeRangeWithError(start, end, &dispatch_ctx, dispatchAckedAtLevel);
    }
    // Fold PMTUD ack outcomes back into path state.
    if (lvl == .application) {
        if (pmtud_probe_acked) {
            _ = ack_path.pmtudOnProbeAcked(
                self.pmtud_config.probe_step,
                self.pmtud_config.max_mtu,
            );
        }
        if (any_regular_acked) ack_path.pmtudOnRegularAcked();
    }
    if (largest_acked_send_time_us) |sent_time_us| {
        if (largest_acked_ack_eliciting and now_us >= sent_time_us) {
            const ack_delay_us = a.ack_delay << self.peerAckDelayExponent();
            self.rttForLevel(lvl).update(
                now_us - sent_time_us,
                ack_delay_us,
                self.handshakeDone(),
                self.peerMaxAckDelayUs(),
            );
        }
    }
    if (any_ack_eliciting_newly_acked) self.ptoCountForLevel(lvl).* = 0;
    if (in_flight_bytes_acked > 0) {
        if (lvl == .application) {
            self.ccForApplication().onPacketAcked(in_flight_bytes_acked, newest_acked_sent_time_us);
        }
    }

    // RFC 9000 §13.4.2 / RFC 9002 §B.7: a peer-reported CE bump on
    // application packets is a congestion event; halve cwnd and
    // arm recovery. We only credit the event when the ACK passed
    // §13.4.2 validation AND we have a baseline to diff against
    // (`ceDelta` returns `null` for the very first ECN-bearing ACK
    // — no monotonicity to compute yet, so no congestion event is
    // implied either). The largest newly-acked sent time anchors
    // the recovery period boundary; if no in-flight packets were
    // matched (an empty-range ACK with bumped CE is technically
    // legal but never useful), we fall back to `now_us`.
    if (ecn_ok and lvl == .application) {
        if (ceDelta(prev_ecn_seen, prev_ce, a.ecn_counts)) |delta| {
            if (delta > 0) {
                const ce_anchor = if (newest_acked_sent_time_us != 0) newest_acked_sent_time_us else now_us;
                self.ccForApplication().onCongestionEvent(ce_anchor);
            }
        }
    }

    // Loss detection at the same level — packet-threshold only
    // (time-threshold lives in `tick`).
    try self.detectLossesByPacketThresholdAtLevel(lvl);

    // Snapshot metrics + congestion phase after a meaningful ACK.
    if (any_ack_eliciting_newly_acked or in_flight_bytes_acked > 0) {
        self.emitCongestionStateIfChanged(now_us);
        self.emitMetricsSnapshot(now_us);
    }
}

pub fn handleApplicationAckOnPath(
    self: *Connection,
    path: *PathState,
    a: frame_types.Ack,
    now_us: u64,
) Error!void {
    // RFC 9000 §13.1 / RFC 9002 §A.3: reject ACKs claiming PNs
    // we never sent on this path.
    if (a.largest_acked >= path.app_pn_space.next_pn) {
        self.close(true, transport_error_protocol_violation, "ack of unsent packet");
        return;
    }
    // §13.4.2 ECN validation, twin of `handleAckAtLevel`. Multipath
    // PATH_ACK frames carry the same ECN trailer; we run the same
    // monotonicity check against the path's app PN space. See the
    // single-path handler for the per-step rationale.
    const prev_ecn_seen = path.app_pn_space.peer_ack_ecn_seen;
    const prev_ce = path.app_pn_space.peer_ack_ce;
    const ecn_ok = if (self.ecn_enabled) validateAndApplyAckEcn(&path.app_pn_space, a.ecn_counts) else true;
    if (!ecn_ok) {
        path.app_pn_space.validation = .failed;
    }
    path.app_pn_space.onAckReceived(a.largest_acked);
    var largest_acked_send_time_us: ?u64 = null;
    var largest_acked_ack_eliciting = false;
    var any_ack_eliciting_newly_acked = false;
    var in_flight_bytes_acked: u64 = 0;
    var newest_acked_sent_time_us: u64 = 0;
    // RFC 8899 DPLPMTUD probe vs regular tracking — see
    // `handleAckAtLevel` for the matching code path on the primary.
    var pmtud_probe_acked = false;
    var any_regular_acked = false;
    var dispatch_ctx: PathAckDispatchCtx = .{
        .self = self,
        .path = path,
        .ack = a,
        .now_us = now_us,
        .largest_acked_send_time_us = &largest_acked_send_time_us,
        .largest_acked_ack_eliciting = &largest_acked_ack_eliciting,
        .any_ack_eliciting_newly_acked = &any_ack_eliciting_newly_acked,
        .in_flight_bytes_acked = &in_flight_bytes_acked,
        .newest_acked_sent_time_us = &newest_acked_sent_time_us,
        .pmtud_probe_acked = &pmtud_probe_acked,
        .any_regular_acked = &any_regular_acked,
    };

    var ack_it = ack_range_mod.iter(a);
    while (try ack_it.next()) |interval| {
        // See `handleAckAtLevel` above for the rationale; this
        // is the per-application-path twin walk and uses the
        // same tracker-bounded iteration.
        const start = path.sent.lowerBound(interval.smallest) orelse continue;
        var end = start;
        while (end < path.sent.count and path.sent.packets[end].pn <= interval.largest) : (end += 1) {}
        try path.sent.removeRangeWithError(start, end, &dispatch_ctx, dispatchAckedOnPath);
    }
    if (pmtud_probe_acked) {
        _ = path.pmtudOnProbeAcked(
            self.pmtud_config.probe_step,
            self.pmtud_config.max_mtu,
        );
    }
    if (any_regular_acked) path.pmtudOnRegularAcked();
    if (largest_acked_send_time_us) |sent_time_us| {
        if (largest_acked_ack_eliciting and now_us >= sent_time_us) {
            const ack_delay_us = a.ack_delay << self.peerAckDelayExponent();
            path.path.rtt.update(
                now_us - sent_time_us,
                ack_delay_us,
                self.handshakeDone(),
                self.peerMaxAckDelayUs(),
            );
        }
    }
    if (any_ack_eliciting_newly_acked) path.pto_count = 0;
    if (in_flight_bytes_acked > 0) {
        path.path.cc.onPacketAcked(in_flight_bytes_acked, newest_acked_sent_time_us);
    }

    // §13.4.2 ECN-CE → congestion event, twin of `handleAckAtLevel`.
    if (ecn_ok) {
        if (ceDelta(prev_ecn_seen, prev_ce, a.ecn_counts)) |delta| {
            if (delta > 0) {
                const ce_anchor = if (newest_acked_sent_time_us != 0) newest_acked_sent_time_us else now_us;
                path.path.cc.onCongestionEvent(ce_anchor);
            }
        }
    }

    try self.detectLossesByPacketThresholdOnApplicationPath(path);

    // Snapshot metrics + congestion phase after a meaningful ACK.
    if (any_ack_eliciting_newly_acked or in_flight_bytes_acked > 0) {
        self.emitCongestionStateIfChanged(now_us);
        self.emitMetricsSnapshot(now_us);
    }
}

pub fn dispatchLostControlFrames(
    self: *Connection,
    packet: *const sent_packets_mod.SentPacket,
) Error!bool {
    return self.dispatchLostControlFramesOnPath(packet, self.activePath().id);
}
