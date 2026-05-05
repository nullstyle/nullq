//! QUIC packet number space (RFC 9000 §12.3).
//!
//! Each connection has up to four PN spaces — initial, handshake,
//! application, and (Phase 10) per-multipath-path application —
//! each with its own monotonically-increasing PN counter and its
//! own ACK tracker for received PNs.

const std = @import("std");
const ack_tracker_mod = @import("ack_tracker.zig");

pub const AckTracker = ack_tracker_mod.AckTracker;

/// Maximum PN value (RFC 9000 §12.3): 2^62 - 1.
pub const max_pn: u64 = (1 << 62) - 1;

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

    /// Allocate the next outgoing PN. Returns null if the space is
    /// exhausted (a connection-fatal condition per RFC 9000 §12.3).
    pub fn nextPn(self: *PnSpace) ?u64 {
        if (self.next_pn > max_pn) return null;
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }

    pub fn recordReceived(self: *PnSpace, pn: u64, now_ms: u64) void {
        self.received.add(pn, now_ms);
    }

    pub fn recordReceivedPacket(self: *PnSpace, pn: u64, now_ms: u64, ack_eliciting: bool) void {
        self.received.addPacket(pn, now_ms, ack_eliciting);
    }

    pub fn recordReceivedPacketDelayed(
        self: *PnSpace,
        pn: u64,
        now_ms: u64,
        ack_eliciting: bool,
        packet_threshold: u8,
    ) void {
        self.received.addPacketDelayed(pn, now_ms, ack_eliciting, packet_threshold);
    }

    pub fn onAckReceived(self: *PnSpace, ack_largest_acked: u64) void {
        if (self.largest_acked_sent == null or ack_largest_acked > self.largest_acked_sent.?) {
            self.largest_acked_sent = ack_largest_acked;
        }
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
