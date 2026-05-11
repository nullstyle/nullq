//! Per-connection embedder-event surfacing buffers.
//!
//! `Connection.pollEvent` drains three FIFO ring-style buffers (in addition
//! to the sticky close event): flow-control blocks, CID-replenish requests,
//! and DATAGRAM ack/loss notifications. This module owns the event payload
//! types, capacity constants, and a small fixed-capacity `EventQueue(T, N)`
//! container that backs each buffer.
//!
//! The current container uses a fixed array plus `copyForwards` shift on
//! pop (O(n) per pop). FIXME(audit): switch to a true ring buffer; pop
//! is the hot path for embedder event drains.

const std = @import("std");

const sent_packets_mod = @import("sent_packets.zig");

/// Whether a flow-control block was hit on the local side or reported by the peer.
pub const FlowBlockedSource = enum {
    local,
    peer,
};

/// Which flow-control axis ran out of credit — connection data, per-stream data,
/// or stream-count (RFC 9000 §4 / §19.12-§19.14).
pub const FlowBlockedKind = enum {
    data,
    stream_data,
    streams,
};

/// One flow-control block event delivered to the embedder via `nextEvent`. Carries
/// the limit that was hit and (for stream-data) which stream tripped it.
pub const FlowBlockedInfo = struct {
    source: FlowBlockedSource,
    kind: FlowBlockedKind,
    limit: u64,
    stream_id: ?u64 = null,
    bidi: ?bool = null,
};

/// Maximum buffered FlowBlockedInfo events before older entries are dropped.
pub const max_flow_blocked_events: usize = 16;

/// Why the connection is asking the embedder to issue more local connection IDs.
pub const ConnectionIdReplenishReason = enum {
    retired,
    path_cids_blocked,
};

/// Embedder-visible snapshot of CID-issuance state when the active count drops
/// below the peer's `active_connection_id_limit` (RFC 9000 §5.1.1).
pub const ConnectionIdReplenishInfo = struct {
    path_id: u32,
    reason: ConnectionIdReplenishReason,
    active_count: usize,
    active_limit: usize,
    issue_budget: usize,
    next_sequence_number: u64,
    blocked_next_sequence_number: ?u64 = null,
};

/// Maximum buffered CID replenish events before older entries are dropped.
pub const max_connection_id_events: usize = 16;

/// One ACK or loss event for a previously-sent RFC 9221 DATAGRAM frame, returned
/// to the embedder so it can reconcile its outbound queue.
pub const DatagramSendEvent = struct {
    id: u64,
    len: usize,
    path_id: u32 = 0,
    packet_number: u64 = 0,
    sent_time_us: u64 = 0,
    arrived_in_early_data: bool = false,
};

/// Maximum buffered datagram ack/loss events before older entries are dropped.
pub const max_datagram_send_events: usize = 64;

/// One ALTERNATIVE_V4_ADDRESS event surfaced to the embedder.
pub const AlternativeServerAddressV4Event = struct {
    address: [4]u8,
    port: u16,
    /// `Status Sequence Number` from the on-wire frame
    /// (draft-munizaga-quic-alternative-server-address-00 §6 ¶5).
    status_sequence_number: u64,
    preferred: bool,
    retire: bool,
};

/// One ALTERNATIVE_V6_ADDRESS event surfaced to the embedder.
pub const AlternativeServerAddressV6Event = struct {
    address: [16]u8,
    port: u16,
    status_sequence_number: u64,
    preferred: bool,
    retire: bool,
};

/// Tagged union of received `ALTERNATIVE_V4/V6_ADDRESS` updates the
/// embedder pulls via `Connection.pollEvent`. The active tag mirrors
/// the on-wire frame type the peer emitted.
///
/// The receive path enforces §6 ¶5 monotonicity (Status Sequence
/// Number strictly increases) before queuing the event. Retransmits
/// (same sequence number, same content) are absorbed silently — the
/// receiver never sees a duplicate event for an already-emitted
/// sequence. Out-of-order older sequences are dropped: QUIC's app-PN
/// space allows packet reordering, so a strictly-lower sequence
/// number is treated as a stale state update from a sender that
/// honored §6 ¶5.
pub const AlternativeServerAddressEvent = union(enum) {
    v4: AlternativeServerAddressV4Event,
    v6: AlternativeServerAddressV6Event,

    /// `Status Sequence Number` shared by both variants — convenience
    /// accessor so embedders can sort received events without
    /// pattern-matching the union.
    pub fn statusSequenceNumber(self: AlternativeServerAddressEvent) u64 {
        return switch (self) {
            .v4 => |v| v.status_sequence_number,
            .v6 => |v| v.status_sequence_number,
        };
    }

    /// True if the peer set the `Preferred` flag bit on the frame.
    pub fn preferred(self: AlternativeServerAddressEvent) bool {
        return switch (self) {
            .v4 => |v| v.preferred,
            .v6 => |v| v.preferred,
        };
    }

    /// True if the peer set the `Retire` flag bit on the frame.
    pub fn retire(self: AlternativeServerAddressEvent) bool {
        return switch (self) {
            .v4 => |v| v.retire,
            .v6 => |v| v.retire,
        };
    }
};

/// Maximum buffered alternative-server-address events before older
/// entries are dropped. 16 mirrors the connection-id event cap; an
/// embedder that polls fast enough to act on `Preferred` migrations
/// won't see backlog, and a misbehaving peer that fires a thousand
/// updates can't pin proportional connection memory.
pub const max_alternative_address_events: usize = 16;

/// Internal storage form for datagram events, tagged by ack-vs-loss so the
/// queue can carry both kinds in one FIFO and `pollEvent` can re-tag them.
pub const StoredDatagramSendEvent = union(enum) {
    acked: DatagramSendEvent,
    lost: DatagramSendEvent,
};

/// Build a `DatagramSendEvent` snapshot from the metadata stashed on a sent
/// DATAGRAM packet at send time. Returns `null` when the packet did not
/// carry a DATAGRAM frame.
pub fn datagramEventFromPacket(packet: *const sent_packets_mod.SentPacket) ?DatagramSendEvent {
    const dg = packet.datagram orelse return null;
    return .{
        .id = dg.id,
        .len = dg.len,
        .path_id = dg.path_id,
        .packet_number = packet.pn,
        .sent_time_us = packet.sent_time_us,
        .arrived_in_early_data = packet.is_early_data,
    };
}

/// Fixed-capacity FIFO of `T` with drop-oldest-on-overflow semantics and
/// O(n) pop (`copyForwards` shift). Backs the per-connection event buffers
/// surfaced via `Connection.pollEvent`. See module-level `FIXME(audit)`
/// — pop should move to a true ring buffer.
pub fn EventQueue(comptime T: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();
        pub const Item = T;
        pub const cap: usize = capacity;

        items: [capacity]T = undefined,
        len: usize = 0,

        /// Append `value`, dropping the oldest entry first when the queue is full.
        pub fn push(self: *Self, value: T) void {
            if (self.len == capacity) {
                std.mem.copyForwards(
                    T,
                    self.items[0 .. capacity - 1],
                    self.items[1..capacity],
                );
                self.len -= 1;
            }
            self.items[self.len] = value;
            self.len += 1;
        }

        /// Remove and return the oldest entry, or `null` when empty.
        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            const out = self.items[0];
            if (self.len > 1) {
                std.mem.copyForwards(
                    T,
                    self.items[0 .. self.len - 1],
                    self.items[1..self.len],
                );
            }
            self.len -= 1;
            return out;
        }

        /// Remove the entry at `index`, sliding the tail forward. Caller
        /// must ensure `index < self.len`.
        pub fn removeAt(self: *Self, index: usize) void {
            std.debug.assert(index < self.len);
            if (index + 1 < self.len) {
                std.mem.copyForwards(
                    T,
                    self.items[index .. self.len - 1],
                    self.items[index + 1 .. self.len],
                );
            }
            self.len -= 1;
        }

        /// Slice view of the live items; valid until the next push/pop/removeAt.
        pub fn slice(self: *Self) []T {
            return self.items[0..self.len];
        }

        /// Const slice view of the live items.
        pub fn constSlice(self: *const Self) []const T {
            return self.items[0..self.len];
        }
    };
}

test "EventQueue push/pop FIFO order" {
    var q: EventQueue(u32, 4) = .{};
    try std.testing.expect(q.pop() == null);

    q.push(1);
    q.push(2);
    q.push(3);
    try std.testing.expectEqual(@as(usize, 3), q.len);
    try std.testing.expectEqual(@as(?u32, 1), q.pop());
    try std.testing.expectEqual(@as(?u32, 2), q.pop());
    try std.testing.expectEqual(@as(?u32, 3), q.pop());
    try std.testing.expectEqual(@as(?u32, null), q.pop());
}

test "EventQueue drops oldest when full" {
    var q: EventQueue(u32, 3) = .{};
    q.push(1);
    q.push(2);
    q.push(3);
    q.push(4);
    try std.testing.expectEqual(@as(usize, 3), q.len);
    try std.testing.expectEqual(@as(?u32, 2), q.pop());
    try std.testing.expectEqual(@as(?u32, 3), q.pop());
    try std.testing.expectEqual(@as(?u32, 4), q.pop());
}

test "EventQueue removeAt slides tail" {
    var q: EventQueue(u32, 8) = .{};
    q.push(10);
    q.push(20);
    q.push(30);
    q.push(40);
    q.removeAt(1);
    try std.testing.expectEqual(@as(usize, 3), q.len);
    try std.testing.expectEqual(@as(u32, 10), q.items[0]);
    try std.testing.expectEqual(@as(u32, 30), q.items[1]);
    try std.testing.expectEqual(@as(u32, 40), q.items[2]);
}
