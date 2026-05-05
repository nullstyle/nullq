//! Sent-packet tracker (RFC 9002 §A.1).
//!
//! Per packet number space, records each sent packet's metadata
//! until it's acknowledged or declared lost. Loss recovery walks
//! this set when an ACK arrives to compute newly-acked PNs and
//! detect lost ones.

const std = @import("std");
const frame_types = @import("../frame/types.zig");

/// Maximum number of control frames a single tracked packet can carry
/// for retransmission bookkeeping.
pub const max_retransmit_frames: usize = 16;
/// Maximum number of STREAM keys a single tracked packet can reference
/// (one per coalesced STREAM frame inside the packet).
pub const max_stream_keys_per_packet: usize = 32;

/// Tagged union of control frames the connection may need to
/// retransmit when the carrying packet is lost.
pub const RetransmitFrame = union(enum) {
    max_data: frame_types.MaxData,
    max_stream_data: frame_types.MaxStreamData,
    max_streams: frame_types.MaxStreams,
    data_blocked: frame_types.DataBlocked,
    stream_data_blocked: frame_types.StreamDataBlocked,
    streams_blocked: frame_types.StreamsBlocked,
    new_connection_id: frame_types.NewConnectionId,
    retire_connection_id: frame_types.RetireConnectionId,
    handshake_done: frame_types.HandshakeDone,
    stop_sending: frame_types.StopSending,
    path_response: frame_types.PathResponse,
    path_challenge: frame_types.PathChallenge,
    reset_stream: frame_types.ResetStream,
    path_abandon: frame_types.PathAbandon,
    path_status_backup: frame_types.PathStatus,
    path_status_available: frame_types.PathStatus,
    path_new_connection_id: frame_types.PathNewConnectionId,
    path_retire_connection_id: frame_types.PathRetireConnectionId,
    max_path_id: frame_types.MaxPathId,
    paths_blocked: frame_types.PathsBlocked,
    path_cids_blocked: frame_types.PathCidsBlocked,
};

/// Reference to a DATAGRAM frame the application owns. Surfaces
/// ack/loss outcomes so the app can run its own retry policy
/// (RFC 9221 §3).
pub const SentDatagram = struct {
    id: u64,
    len: usize,
    path_id: u32 = 0,
};

/// Metadata for one packet the connection has put on the wire and
/// is awaiting an ACK or loss outcome for.
pub const SentPacket = struct {
    pn: u64,
    /// Send time in microseconds (monotonic clock the caller manages).
    sent_time_us: u64,
    /// Wire size of the encoded packet (header + ciphertext + tag).
    /// Used for in-flight bookkeeping and congestion-controller updates.
    bytes: u64,
    /// Did this packet contain at least one ack-eliciting frame?
    /// (Almost any frame except PADDING/ACK/CONNECTION_CLOSE.)
    ack_eliciting: bool,
    /// Did this packet contribute to bytes-in-flight? Most packets
    /// do; ACK-only packets and pure PADDING runs do not.
    in_flight: bool,
    /// Ack-eliciting control frames that need explicit ACK/loss
    /// handling. STREAM frames are tracked by SendStream; DATAGRAM,
    /// ACK, PADDING, and CONNECTION_CLOSE are intentionally absent.
    retransmit_frames: std.ArrayList(RetransmitFrame) = .empty,
    /// DATAGRAM frames are not retransmitted by QUIC, but apps need
    /// ack/loss visibility to implement their own retry policy.
    datagram: ?SentDatagram = null,
    /// Connection-local identifier used to route STREAM ACK/loss
    /// notifications. Application packet numbers are per-path when
    /// multipath is enabled, so a wire PN alone is not globally unique.
    stream_key: ?u64 = null,
    /// Additional STREAM keys when multiple STREAM frames are packed
    /// into one QUIC packet. Allocated only for coalesced STREAM
    /// packets; `stream_key` remains the first entry so the common
    /// single-frame case stays compact.
    extra_stream_keys: std.ArrayList(u64) = .empty,
    /// True when this Application-space packet was sent under 0-RTT
    /// keys. If TLS rejects early data, callers can requeue STREAM
    /// bytes without treating the packet as congestion loss.
    is_early_data: bool = false,
    /// 1-RTT application key epoch used to protect this packet.
    /// Null for Initial, Handshake, and 0-RTT packets.
    key_epoch: ?u64 = null,
    /// Key Phase bit used on the wire for a 1-RTT application packet.
    key_phase: ?bool = null,

    /// Append a control frame so loss recovery can re-queue it if the
    /// packet is declared lost. Errors with `TooManyRetransmittableFrames`
    /// when capacity is reached.
    pub fn addRetransmitFrame(
        self: *SentPacket,
        allocator: std.mem.Allocator,
        frame: RetransmitFrame,
    ) Error!void {
        if (self.retransmit_frames.items.len >= max_retransmit_frames) {
            return Error.TooManyRetransmittableFrames;
        }
        try self.retransmit_frames.append(allocator, frame);
    }

    /// Record a STREAM-frame routing key so ack/loss callbacks can
    /// reach the right `SendStream`. Sets `stream_key` on the first
    /// call, then appends to `extra_stream_keys`.
    pub fn addStreamKey(self: *SentPacket, allocator: std.mem.Allocator, key: u64) Error!void {
        if (self.stream_key == null) {
            self.stream_key = key;
            return;
        }
        if (self.extra_stream_keys.items.len >= max_stream_keys_per_packet - 1) {
            return Error.TooManyStreamFrames;
        }
        try self.extra_stream_keys.append(allocator, key);
    }

    /// Iterator over every STREAM key carried by a `SentPacket`
    /// (the primary `stream_key` first, then `extra_stream_keys`).
    pub const StreamKeyIterator = struct {
        packet: *const SentPacket,
        index: usize = 0,

        /// Yield the next STREAM key, or null when exhausted.
        pub fn next(self: *StreamKeyIterator) ?u64 {
            if (self.index == 0) {
                self.index = 1;
                if (self.packet.stream_key) |key| return key;
            }
            const extra_index = self.index - 1;
            if (extra_index >= self.packet.extra_stream_keys.items.len) return null;
            self.index += 1;
            return self.packet.extra_stream_keys.items[extra_index];
        }
    };

    /// Build an iterator over every STREAM key referenced by this packet.
    pub fn streamKeys(self: *const SentPacket) StreamKeyIterator {
        return .{ .packet = self };
    }

    /// Release the heap-backed retransmit-frame and stream-key arrays.
    pub fn deinit(self: *SentPacket, allocator: std.mem.Allocator) void {
        self.retransmit_frames.deinit(allocator);
        self.extra_stream_keys.deinit(allocator);
        self.* = undefined;
    }
};

/// Maximum tracked in-flight packets per PN space. Real connections
/// rarely exceed a few hundred; we cap at 4096 so fixed-size
/// arrays don't blow up the struct. When full, `record` returns
/// `Error.TooManyInFlight` — a connection-fatal condition the
/// caller should map to a CONNECTION_CLOSE.
pub const max_tracked: usize = 4096;

/// Errors raised by the sent-packet tracker.
pub const Error = error{
    /// `record` was called when the per-PN-space cap was reached.
    TooManyInFlight,
    /// `addRetransmitFrame` exceeded `max_retransmit_frames`.
    TooManyRetransmittableFrames,
    /// `addStreamKey` exceeded `max_stream_keys_per_packet`.
    TooManyStreamFrames,
} || std.mem.Allocator.Error;

/// RFC 9002 §A.1 sent-packet tracker. Indexed by PN, sorted ascending,
/// with running totals for in-flight bookkeeping.
pub const SentPacketTracker = struct {
    /// Sorted ascending by PN. Sent packets are appended at the
    /// high end; ACKs/loss removes from anywhere.
    packets: [max_tracked]SentPacket = undefined,
    count: u32 = 0,
    /// Sum of bytes for in-flight packets currently tracked.
    bytes_in_flight: u64 = 0,
    /// Sum of bytes for ack-eliciting packets currently tracked.
    /// Used for some loss-recovery state; tracked separately so
    /// we don't have to walk the array.
    ack_eliciting_in_flight: u64 = 0,

    /// Record a newly-sent packet. PNs must be strictly increasing.
    pub fn record(self: *SentPacketTracker, p: SentPacket) Error!void {
        if (self.count >= max_tracked) return Error.TooManyInFlight;
        if (self.count > 0) {
            std.debug.assert(p.pn > self.packets[self.count - 1].pn);
        }
        self.packets[self.count] = p;
        self.count += 1;
        if (p.in_flight) {
            self.bytes_in_flight += p.bytes;
            if (p.ack_eliciting) self.ack_eliciting_in_flight += p.bytes;
        }
    }

    /// Remove a tracked packet by index. Returns the removed entry.
    pub fn removeAt(self: *SentPacketTracker, idx: u32) SentPacket {
        std.debug.assert(idx < self.count);
        const p = self.packets[idx];
        var k: u32 = idx;
        while (k + 1 < self.count) : (k += 1) {
            self.packets[k] = self.packets[k + 1];
        }
        self.count -= 1;
        if (p.in_flight) {
            self.bytes_in_flight -= p.bytes;
            if (p.ack_eliciting) self.ack_eliciting_in_flight -= p.bytes;
        }
        return p;
    }

    /// Find the index of the tracked packet with the given PN.
    /// Returns null if no match. O(log N) binary search.
    pub fn indexOf(self: *const SentPacketTracker, pn: u64) ?u32 {
        var lo: u32 = 0;
        var hi: u32 = self.count;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const p = self.packets[mid];
            if (p.pn == pn) return mid;
            if (p.pn < pn) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return null;
    }

    /// Find the first tracked packet whose PN is >= `pn`.
    /// Returns null if all tracked PNs are smaller.
    pub fn lowerBound(self: *const SentPacketTracker, pn: u64) ?u32 {
        var lo: u32 = 0;
        var hi: u32 = self.count;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.packets[mid].pn < pn) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if (lo >= self.count) return null;
        return lo;
    }
};

// -- tests ---------------------------------------------------------------

test "record + remove + bytes_in_flight bookkeeping" {
    var t: SentPacketTracker = .{};
    try t.record(.{ .pn = 0, .sent_time_us = 100, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 1, .sent_time_us = 110, .bytes = 800, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 2, .sent_time_us = 120, .bytes = 60, .ack_eliciting = false, .in_flight = false });

    try std.testing.expectEqual(@as(u32, 3), t.count);
    try std.testing.expectEqual(@as(u64, 2000), t.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 2000), t.ack_eliciting_in_flight);

    const idx = t.indexOf(1) orelse unreachable;
    const removed = t.removeAt(idx);
    try std.testing.expectEqual(@as(u64, 1), removed.pn);
    try std.testing.expectEqual(@as(u32, 2), t.count);
    try std.testing.expectEqual(@as(u64, 1200), t.bytes_in_flight);
}

test "indexOf returns null for missing PNs" {
    var t: SentPacketTracker = .{};
    try t.record(.{ .pn = 5, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(?u32, 0), t.indexOf(5));
    try std.testing.expectEqual(@as(?u32, null), t.indexOf(4));
    try std.testing.expectEqual(@as(?u32, null), t.indexOf(6));
}

test "lowerBound finds the first PN >= target" {
    var t: SentPacketTracker = .{};
    try t.record(.{ .pn = 1, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 3, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 7, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(?u32, 0), t.lowerBound(0));
    try std.testing.expectEqual(@as(?u32, 0), t.lowerBound(1));
    try std.testing.expectEqual(@as(?u32, 1), t.lowerBound(2));
    try std.testing.expectEqual(@as(?u32, 1), t.lowerBound(3));
    try std.testing.expectEqual(@as(?u32, 2), t.lowerBound(4));
    try std.testing.expectEqual(@as(?u32, 2), t.lowerBound(7));
    try std.testing.expectEqual(@as(?u32, null), t.lowerBound(8));
}

test "non-in-flight packets don't update bytes_in_flight" {
    var t: SentPacketTracker = .{};
    try t.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 50, .ack_eliciting = false, .in_flight = false });
    try std.testing.expectEqual(@as(u64, 0), t.bytes_in_flight);
    _ = t.removeAt(0);
    try std.testing.expectEqual(@as(u64, 0), t.bytes_in_flight);
}

test "SentPacket stores retransmittable control frames" {
    var p: SentPacket = .{
        .pn = 1,
        .sent_time_us = 10,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer p.deinit(std.testing.allocator);
    try p.addRetransmitFrame(std.testing.allocator, .{ .max_data = .{ .maximum_data = 4096 } });
    try p.addRetransmitFrame(std.testing.allocator, .{ .path_challenge = .{ .data = .{ 1, 2, 3, 4, 5, 6, 7, 8 } } });

    try std.testing.expectEqual(@as(usize, 2), p.retransmit_frames.items.len);
    try std.testing.expect(p.retransmit_frames.items[0] == .max_data);
    try std.testing.expectEqual(@as(u64, 4096), p.retransmit_frames.items[0].max_data.maximum_data);
    try std.testing.expect(p.retransmit_frames.items[1] == .path_challenge);
}

test "SentPacket stores multiple STREAM keys" {
    var p: SentPacket = .{
        .pn = 1,
        .sent_time_us = 10,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer p.deinit(std.testing.allocator);

    try p.addStreamKey(std.testing.allocator, 11);
    try p.addStreamKey(std.testing.allocator, 12);
    try p.addStreamKey(std.testing.allocator, 13);

    var it = p.streamKeys();
    try std.testing.expectEqual(@as(?u64, 11), it.next());
    try std.testing.expectEqual(@as(?u64, 12), it.next());
    try std.testing.expectEqual(@as(?u64, 13), it.next());
    try std.testing.expectEqual(@as(?u64, null), it.next());
}
