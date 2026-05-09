//! QUIC packet number space (RFC 9000 §12.3).
//!
//! Each connection has up to four PN-space kinds — initial,
//! handshake, application, and per-path application (multipath,
//! draft-ietf-quic-multipath-21) — each with its own
//! monotonically-increasing PN counter and its own ACK tracker for
//! received PNs.

const std = @import("std");
const ack_tracker_mod = @import("ack_tracker.zig");
const socket_opts = @import("../transport/socket_opts.zig");

/// Re-export of the underlying received-PN tracker.
pub const AckTracker = ack_tracker_mod.AckTracker;
/// Re-export of the IETF ECN codepoint enum (RFC 3168 §5).
pub const EcnCodepoint = socket_opts.EcnCodepoint;

/// Maximum PN value (RFC 9000 §12.3): 2^62 - 1.
pub const max_pn: u64 = (1 << 62) - 1;

/// Per-PN-space ECN validation state (RFC 9000 §13.4.2). The state
/// machine is tiny:
///   * `testing` (the default): we believe ECN works on this path.
///     We mark outgoing packets ECT(0) and emit ECN counts on
///     outgoing ACKs.
///   * `failed`: the §13.4.2 monotonicity check rejected one of the
///     peer's ECN reports. We stop emitting ECN counts on ACKs and
///     stop reacting to peer-reported CE for this space.
pub const EcnValidationState = enum { testing, failed };

/// One QUIC packet number space. Tracks the next outgoing PN, the
/// largest PN we've seen acknowledged, and the received-PN bookkeeping
/// for ACK generation.
pub const PnSpace = struct {
    /// Next packet number to assign on send.
    next_pn: u64 = 0,
    /// Largest PN we've sent that has been acknowledged. None
    /// until the first ACK arrives. Used by loss recovery to
    /// reason about in-flight packets.
    largest_acked_sent: ?u64 = null,
    /// Bookkeeping for received PNs. Populated whenever the
    /// receiver successfully decrypts a packet at this level.
    received: AckTracker = .{},

    /// Cumulative count of received packets with the named IP ECN
    /// codepoint (RFC 9000 §13.4.1). Emitted in our own outgoing ACK
    /// frames at type 0x03 / 0x03-PATH so the peer's congestion
    /// controller can react to CE marks observed on our path.
    recv_ect0: u64 = 0,
    recv_ect1: u64 = 0,
    recv_ce: u64 = 0,

    /// Latest peer-reported ECN counts seen in an ACK frame at this
    /// level. Used by §13.4.2 monotonicity validation: a fresh ACK
    /// whose ECT0/ECT1/CE total has gone backward (or whose CE
    /// dropped) indicates a peer or middlebox bug; we react by
    /// flipping `validation` to `failed`.
    peer_ack_ect0: u64 = 0,
    peer_ack_ect1: u64 = 0,
    peer_ack_ce: u64 = 0,
    /// True once the first ECN-bearing peer ACK has populated the
    /// `peer_ack_*` fields. Until then, monotonicity comparisons
    /// trivially pass.
    peer_ack_ecn_seen: bool = false,

    /// Per-space ECN validation state. Starts at `testing`; flips to
    /// `failed` on any §13.4.2 violation and never recovers (the
    /// path is presumed ECN-bleached for the remainder of the
    /// connection).
    validation: EcnValidationState = .testing,

    /// Allocate the next outgoing PN. Returns null if the space is
    /// exhausted (a connection-fatal condition per RFC 9000 §12.3).
    pub fn nextPn(self: *PnSpace) ?u64 {
        if (self.next_pn > max_pn) return null;
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }

    /// Record an ACK-eliciting received PN. Convenience wrapper that
    /// always treats the packet as ACK-eliciting.
    pub fn recordReceived(self: *PnSpace, pn: u64, now_ms: u64) void {
        self.received.add(pn, now_ms);
    }

    /// Record a received PN with explicit `ack_eliciting` flag. Used
    /// by Initial/Handshake spaces (no delayed-ACK), or by callers
    /// that have already promoted to `pending_ack`.
    pub fn recordReceivedPacket(self: *PnSpace, pn: u64, now_ms: u64, ack_eliciting: bool) void {
        self.received.addPacket(pn, now_ms, ack_eliciting);
    }

    /// Record a received PN under application-data delayed-ACK rules
    /// (RFC 9000 §13.2.1). `packet_threshold` is the count of
    /// ACK-eliciting packets that forces an immediate ACK (typically 2).
    pub fn recordReceivedPacketDelayed(
        self: *PnSpace,
        pn: u64,
        now_ms: u64,
        ack_eliciting: bool,
        packet_threshold: u8,
    ) void {
        self.received.addPacketDelayed(pn, now_ms, ack_eliciting, packet_threshold);
    }

    /// Update `largest_acked_sent` from an incoming ACK. Out-of-order
    /// ACKs (smaller `ack_largest_acked` than what we've already seen)
    /// are ignored.
    pub fn onAckReceived(self: *PnSpace, ack_largest_acked: u64) void {
        if (self.largest_acked_sent == null or ack_largest_acked > self.largest_acked_sent.?) {
            self.largest_acked_sent = ack_largest_acked;
        }
    }

    /// Increment the receive-side ECN counter for the named codepoint
    /// (RFC 9000 §13.4.1). `not_ect` is a no-op — only ECN-marked
    /// packets are counted. Saturates at u64.max so a pathological
    /// long-lived connection doesn't wrap.
    pub fn onPacketReceivedWithEcn(self: *PnSpace, codepoint: EcnCodepoint) void {
        switch (codepoint) {
            .not_ect => {},
            .ect0 => self.recv_ect0 +|= 1,
            .ect1 => self.recv_ect1 +|= 1,
            .ce => self.recv_ce +|= 1,
        }
    }

    /// True iff at least one received packet at this level carried a
    /// non-Not-ECT marking. Drives whether outgoing ACKs at this
    /// level emit type 0x03 (with ECN counts) or stay at 0x02.
    pub fn hasObservedEcn(self: *const PnSpace) bool {
        return self.recv_ect0 != 0 or self.recv_ect1 != 0 or self.recv_ce != 0;
    }
};

// -- tests ---------------------------------------------------------------

test "PnSpace.nextPn increments and exhausts at max_pn" {
    var s: PnSpace = .{};
    try std.testing.expectEqual(@as(?u64, 0), s.nextPn());
    try std.testing.expectEqual(@as(?u64, 1), s.nextPn());
    try std.testing.expectEqual(@as(?u64, 2), s.nextPn());
    try std.testing.expectEqual(@as(u64, 3), s.next_pn);

    s.next_pn = max_pn;
    try std.testing.expectEqual(@as(?u64, max_pn), s.nextPn());
    try std.testing.expectEqual(@as(?u64, null), s.nextPn());
}

test "recordReceived updates ack tracker" {
    var s: PnSpace = .{};
    s.recordReceived(0, 100);
    s.recordReceived(1, 105);
    s.recordReceived(3, 110);
    try std.testing.expectEqual(@as(u8, 2), s.received.range_count);
    try std.testing.expectEqual(@as(?u64, 3), s.received.largest);
    try std.testing.expectEqual(@as(u64, 110), s.received.largest_at_ms);
}

test "recordReceivedPacket can avoid arming an ACK" {
    var s: PnSpace = .{};
    s.recordReceivedPacket(0, 100, false);
    try std.testing.expectEqual(@as(u8, 1), s.received.range_count);
    try std.testing.expectEqual(@as(?u64, 0), s.received.largest);
    try std.testing.expect(!s.received.pending_ack);

    s.recordReceivedPacket(1, 101, true);
    try std.testing.expectEqual(@as(u8, 1), s.received.range_count);
    try std.testing.expectEqual(@as(?u64, 1), s.received.largest);
    try std.testing.expect(s.received.pending_ack);
}

test "recordReceivedPacketDelayed arms then promotes application ACKs" {
    var s: PnSpace = .{};
    s.recordReceivedPacketDelayed(0, 100, true, 2);
    try std.testing.expect(!s.received.pending_ack);
    try std.testing.expect(s.received.delayed_ack_armed);
    try std.testing.expectEqual(@as(?u64, 100), s.received.ackDelayBaseMs());

    s.recordReceivedPacketDelayed(1, 101, true, 2);
    try std.testing.expect(s.received.pending_ack);
    try std.testing.expect(s.received.delayed_ack_armed);

    s.received.markAckSent();
    try std.testing.expect(!s.received.pending_ack);
    try std.testing.expect(!s.received.delayed_ack_armed);
}

test "recordReceivedPacketDelayed promotes on gaps" {
    var s: PnSpace = .{};
    s.recordReceivedPacketDelayed(0, 100, true, 8);
    try std.testing.expect(!s.received.pending_ack);

    s.recordReceivedPacketDelayed(2, 101, true, 8);
    try std.testing.expect(s.received.pending_ack);
}

test "onAckReceived tracks the largest ack sent" {
    var s: PnSpace = .{};
    s.onAckReceived(5);
    try std.testing.expectEqual(@as(?u64, 5), s.largest_acked_sent);
    s.onAckReceived(3); // out-of-order ACK; ignored
    try std.testing.expectEqual(@as(?u64, 5), s.largest_acked_sent);
    s.onAckReceived(10);
    try std.testing.expectEqual(@as(?u64, 10), s.largest_acked_sent);
}

test "onPacketReceivedWithEcn bumps the counter for the codepoint" {
    var s: PnSpace = .{};
    try std.testing.expect(!s.hasObservedEcn());
    s.onPacketReceivedWithEcn(.not_ect);
    try std.testing.expect(!s.hasObservedEcn());
    try std.testing.expectEqual(@as(u64, 0), s.recv_ect0);

    s.onPacketReceivedWithEcn(.ect0);
    s.onPacketReceivedWithEcn(.ect0);
    try std.testing.expectEqual(@as(u64, 2), s.recv_ect0);
    try std.testing.expect(s.hasObservedEcn());

    s.onPacketReceivedWithEcn(.ect1);
    s.onPacketReceivedWithEcn(.ce);
    try std.testing.expectEqual(@as(u64, 1), s.recv_ect1);
    try std.testing.expectEqual(@as(u64, 1), s.recv_ce);
}

test "validation defaults to testing" {
    const s: PnSpace = .{};
    try std.testing.expectEqual(EcnValidationState.testing, s.validation);
    try std.testing.expect(!s.peer_ack_ecn_seen);
}
