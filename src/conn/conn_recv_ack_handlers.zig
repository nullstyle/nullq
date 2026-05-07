// Inbound ACK frame processing: per-encryption-level ACKs, the
// multipath PATH_ACK twin, and the loss-recovery callback that
// re-queues control frames RFC 9002 has declared lost. Free-function
// siblings of `Connection`'s public method-style handlers; the
// methods on `Connection` are thin thunks that delegate here.
//
// Extracted from src/conn/state.zig to keep the connection state-
// machine monolith from growing further. No behavior change.

const std = @import("std");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const PathState = state_mod.PathState;
const frame_types = state_mod.frame_types;
const ack_range_mod = state_mod.ack_range_mod;
const sent_packets_mod = state_mod.sent_packets_mod;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

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
    // Phase 5b v1 walks streams brute-force per PN; a per-PN
    // side-table is the obvious next optimization.
    const pn_space = self.pnSpaceForLevel(lvl);
    const sent = self.sentForLevel(lvl);
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
    pn_space.onAckReceived(a.largest_acked);
    var largest_acked_send_time_us: ?u64 = null;
    var largest_acked_ack_eliciting = false;
    var any_ack_eliciting_newly_acked = false;
    var in_flight_bytes_acked: u64 = 0;
    var newest_acked_sent_time_us: u64 = 0;

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
        while (sent.lowerBound(interval.smallest)) |idx| {
            if (sent.packets[idx].pn > interval.largest) break;
            var acked = sent.removeAt(idx);
            defer acked.deinit(self.allocator);
            if (acked.pn == a.largest_acked) {
                largest_acked_send_time_us = acked.sent_time_us;
                largest_acked_ack_eliciting = acked.ack_eliciting;
            }
            if (acked.ack_eliciting) any_ack_eliciting_newly_acked = true;
            if (acked.in_flight) {
                in_flight_bytes_acked += acked.bytes;
                if (acked.sent_time_us > newest_acked_sent_time_us) {
                    newest_acked_sent_time_us = acked.sent_time_us;
                }
            }
            if (lvl == .application) {
                self.onApplicationPacketAckedForKeys(&acked, now_us);
                self.dispatchAckedPacketToStreams(&acked) catch |e| return e;
            }
            self.discardSentCryptoForPacket(lvl, acked.pn);
            self.dispatchAckedControlFrames(&acked);
            self.recordDatagramAcked(&acked);
        }
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
    path.app_pn_space.onAckReceived(a.largest_acked);
    var largest_acked_send_time_us: ?u64 = null;
    var largest_acked_ack_eliciting = false;
    var any_ack_eliciting_newly_acked = false;
    var in_flight_bytes_acked: u64 = 0;
    var newest_acked_sent_time_us: u64 = 0;

    var ack_it = ack_range_mod.iter(a);
    while (try ack_it.next()) |interval| {
        // See `handleAckAtLevel` above for the rationale; this
        // is the per-application-path twin walk and uses the
        // same tracker-bounded iteration.
        while (path.sent.lowerBound(interval.smallest)) |idx| {
            if (path.sent.packets[idx].pn > interval.largest) break;
            var acked = path.sent.removeAt(idx);
            defer acked.deinit(self.allocator);
            if (acked.pn == a.largest_acked) {
                largest_acked_send_time_us = acked.sent_time_us;
                largest_acked_ack_eliciting = acked.ack_eliciting;
            }
            if (acked.ack_eliciting) any_ack_eliciting_newly_acked = true;
            if (acked.in_flight) {
                in_flight_bytes_acked += acked.bytes;
                if (acked.sent_time_us > newest_acked_sent_time_us) {
                    newest_acked_sent_time_us = acked.sent_time_us;
                }
            }
            self.dispatchAckedPacketToStreams(&acked) catch |e| return e;
            self.onApplicationPacketAckedForKeys(&acked, now_us);
            self.discardSentCryptoForPacket(.application, acked.pn);
            self.dispatchAckedControlFrames(&acked);
            self.recordDatagramAcked(&acked);
        }
    }
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
