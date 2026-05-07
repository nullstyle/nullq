//! Pending control-frame queues — the per-connection backlog of QUIC
//! control frames the sender owes the peer. Extracted from
//! `Connection` to keep the state machine focused on lifecycle and
//! routing while this module owns the FIFO/coalesced bookkeeping.
//!
//! Ownership model: every list is allocator-backed and stored
//! directly here. `Connection` calls `deinit(allocator)` when it
//! tears down. Methods that mutate the queues take an allocator
//! argument because the lists are unmanaged.
//!
//! This is a code-motion refactor — semantics are identical to the
//! pre-extraction inline fields in `state.zig`. The drain order in
//! `pollLevel` still walks each queue in the same sequence; this
//! module just provides typed homes for the fields.

const std = @import("std");

const frame_types = @import("../frame/types.zig");
const path_mod = @import("path.zig");

const Address = path_mod.Address;

/// One queued STOP_SENDING frame (RFC 9000 §19.5).
pub const StopSendingItem = struct {
    stream_id: u64,
    application_error_code: u64,
};

/// One queued MAX_STREAM_DATA frame (RFC 9000 §19.10) with the new credit value.
pub const MaxStreamDataItem = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

/// One queued NEW_TOKEN frame (RFC 9000 §19.7). The token payload is
/// stored inline as a fixed 96-byte buffer (matches
/// `conn.new_token.max_token_len`) plus a `len`. nullq mints a single
/// fixed-shape format so a heap allocation isn't needed.
pub const NewTokenItem = struct {
    /// Maximum supported NEW_TOKEN length on the wire. Matches
    /// `conn.new_token.max_token_len`. Tracked here to keep
    /// `pending_frames` self-contained.
    pub const max_len: usize = 96;
    bytes: [max_len]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const NewTokenItem) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// One queued NEW_CONNECTION_ID frame (RFC 9000 §19.15) the embedder has handed
/// to the connection and is awaiting transmission.
pub const PendingNewConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: frame_types.ConnId,
    stateless_reset_token: [16]u8,
};

/// One queued PATH_AVAILABLE / PATH_BACKUP frame from draft-ietf-quic-multipath-21.
pub const PendingPathStatus = struct {
    path_id: u32,
    sequence_number: u64,
    available: bool,
};

/// All control-frame backlogs the connection owes the peer at the
/// application encryption level. Drained in `pollLevel`; mutations
/// happen through helper methods on this struct or directly through
/// the field accesses preserved on the parent `Connection` (the
/// hot-path `canSend` and the per-frame drain blocks read these
/// fields directly).
pub const PendingFrameQueues = struct {
    // -- flow control window updates (RFC 9000 §19.9 / §19.10) --
    /// MAX_DATA value to advertise after application reads. Null
    /// means no connection-level window update is currently queued.
    max_data: ?u64 = null,
    /// Coalesced MAX_STREAM_DATA queue keyed by stream id.
    max_stream_data: std.ArrayList(MaxStreamDataItem) = .empty,
    /// MAX_STREAMS (bidi) limit pending advertisement.
    max_streams_bidi: ?u64 = null,
    /// MAX_STREAMS (uni) limit pending advertisement.
    max_streams_uni: ?u64 = null,
    /// DATA_BLOCKED that local-side flow control hit; null means we
    /// owe nothing.
    data_blocked: ?u64 = null,
    /// STREAM_DATA_BLOCKED queue (one entry per stream id).
    stream_data_blocked: std.ArrayList(frame_types.StreamDataBlocked) = .empty,
    /// STREAMS_BLOCKED (bidi) limit pending advertisement.
    streams_blocked_bidi: ?u64 = null,
    /// STREAMS_BLOCKED (uni) limit pending advertisement.
    streams_blocked_uni: ?u64 = null,

    // -- stop sending (RFC 9000 §19.5) --
    /// STOP_SENDING frames we owe the peer (one per stream id).
    stop_sending: std.ArrayList(StopSendingItem) = .empty,

    // -- NEW_TOKEN (RFC 9000 §19.7) --
    /// NEW_TOKEN payload the server has queued for emission. Single
    /// slot — nullq emits at most one NEW_TOKEN per session by
    /// default, so the queue is a fixed buffer holding the 96-byte
    /// AEAD-sealed token plus its length. `Connection.queueNewToken`
    /// stages bytes here; the application-level drain in
    /// `pollLevel` clears the slot once the frame is on the wire and
    /// pushes a retransmit copy onto the sent-packet bookkeeping
    /// instead of leaving the slot armed.
    new_token: ?NewTokenItem = null,

    // -- connection ID issuance/retirement (RFC 9000 §19.15 / §19.16) --
    new_connection_ids: std.ArrayList(PendingNewConnectionId) = .empty,
    retire_connection_ids: std.ArrayList(frame_types.RetireConnectionId) = .empty,

    // -- path challenge / response (RFC 9000 §19.17 / §19.18) --
    /// PATH_CHALLENGE token received from the peer that we still
    /// owe a PATH_RESPONSE for. The next outgoing 1-RTT packet
    /// will carry it.
    path_response: ?[8]u8 = null,
    path_response_path_id: u32 = 0,
    path_response_addr: ?Address = null,
    /// PATH_CHALLENGE token we've queued for transmission to start
    /// validating the current path.
    path_challenge: ?[8]u8 = null,
    path_challenge_path_id: u32 = 0,

    // -- multipath draft-21 control frames --
    path_abandons: std.ArrayList(frame_types.PathAbandon) = .empty,
    path_statuses: std.ArrayList(PendingPathStatus) = .empty,
    path_new_connection_ids: std.ArrayList(frame_types.PathNewConnectionId) = .empty,
    path_retire_connection_ids: std.ArrayList(frame_types.PathRetireConnectionId) = .empty,
    max_path_id: ?u32 = null,
    paths_blocked: ?u32 = null,
    path_cids_blocked: ?frame_types.PathCidsBlocked = null,

    // -- RFC 9221 datagram queues --
    /// Outbound DATAGRAM payloads waiting to be packed into 1-RTT
    /// packets. Each entry's `data` is allocator-owned by the
    /// connection; helpers on this struct hand it back so the
    /// connection can `free` after sending.
    send_datagrams: std.ArrayList(PendingSendDatagram) = .empty,
    send_datagram_bytes: usize = 0,
    /// Inbound DATAGRAMs received but not yet pulled by the app.
    /// Each entry's `data` is allocator-owned.
    recv_datagrams: std.ArrayList(PendingRecvDatagram) = .empty,
    recv_datagram_bytes: usize = 0,

    pub const empty: PendingFrameQueues = .{};

    /// Free all queue storage. Datagram payload bytes are also freed
    /// here; non-datagram frames are plain values with no nested
    /// allocations.
    pub fn deinit(self: *PendingFrameQueues, allocator: std.mem.Allocator) void {
        for (self.send_datagrams.items) |item| allocator.free(item.data);
        for (self.recv_datagrams.items) |item| allocator.free(item.data);
        self.send_datagrams.deinit(allocator);
        self.recv_datagrams.deinit(allocator);
        self.stop_sending.deinit(allocator);
        self.max_stream_data.deinit(allocator);
        self.stream_data_blocked.deinit(allocator);
        self.new_connection_ids.deinit(allocator);
        self.retire_connection_ids.deinit(allocator);
        self.path_abandons.deinit(allocator);
        self.path_statuses.deinit(allocator);
        self.path_new_connection_ids.deinit(allocator);
        self.path_retire_connection_ids.deinit(allocator);
    }

    // -- mutation helpers used by Connection --------------------------

    /// Drop any pending NEW_CONNECTION_ID with `sequence_number`.
    /// Used when the embedder retracts a CID before it's been sent.
    pub fn removeNewConnectionIdBySequence(
        self: *PendingFrameQueues,
        sequence_number: u64,
    ) void {
        var i: usize = 0;
        while (i < self.new_connection_ids.items.len) {
            if (self.new_connection_ids.items[i].sequence_number == sequence_number) {
                _ = self.new_connection_ids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    /// Drop any pending PATH_NEW_CONNECTION_ID for `(path_id, sequence_number)`.
    pub fn removePathNewConnectionIdBySequence(
        self: *PendingFrameQueues,
        path_id: u32,
        sequence_number: u64,
    ) void {
        var i: usize = 0;
        while (i < self.path_new_connection_ids.items.len) {
            const item = self.path_new_connection_ids.items[i];
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                _ = self.path_new_connection_ids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    /// Pop the head of `recv_datagrams`. Returns null when the queue is
    /// empty. The returned `data` is allocator-owned by the caller.
    pub fn popRecvDatagram(self: *PendingFrameQueues) ?PendingRecvDatagram {
        if (self.recv_datagrams.items.len == 0) return null;
        const item = self.recv_datagrams.orderedRemove(0);
        self.recv_datagram_bytes -= item.data.len;
        return item;
    }
};

/// One queued inbound DATAGRAM payload (RFC 9221 §4) — `data` is
/// allocator-owned and freed when the app drains it.
pub const PendingRecvDatagram = struct {
    data: []u8,
    arrived_in_early_data: bool = false,
};

/// One queued outbound DATAGRAM payload (RFC 9221 §4) — `data` is
/// allocator-owned and freed once it's been packed onto the wire.
pub const PendingSendDatagram = struct {
    id: u64,
    data: []u8,
};

// -- tests ---------------------------------------------------------------
//
// `PendingFrameQueues` is a plain typed home for control-frame backlogs:
// `Connection` mutates the optional fields directly and pushes/pops the
// `ArrayList` queues itself. The methods on the struct are limited to
// `deinit`, the two `remove*BySequence` helpers, and `popRecvDatagram`.
// These tests cover (a) the `empty` zero-state, (b) the documented
// direct-field semantics callers depend on, and (c) the helper methods
// end-to-end.

test "pending_frames: empty initial state has nothing pending" {
    var q: PendingFrameQueues = .empty;
    defer q.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?u64, null), q.max_data);
    try std.testing.expectEqual(@as(?u64, null), q.max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, null), q.max_streams_uni);
    try std.testing.expectEqual(@as(?u64, null), q.data_blocked);
    try std.testing.expectEqual(@as(?u64, null), q.streams_blocked_bidi);
    try std.testing.expectEqual(@as(?u64, null), q.streams_blocked_uni);
    try std.testing.expect(q.new_token == null);
    try std.testing.expect(q.path_response == null);
    try std.testing.expect(q.path_challenge == null);
    try std.testing.expect(q.path_response_addr == null);
    try std.testing.expectEqual(@as(?u32, null), q.max_path_id);
    try std.testing.expectEqual(@as(?u32, null), q.paths_blocked);
    try std.testing.expect(q.path_cids_blocked == null);

    try std.testing.expectEqual(@as(usize, 0), q.max_stream_data.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.stop_sending.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.new_connection_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.path_abandons.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.path_statuses.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.path_retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.send_datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.recv_datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), q.send_datagram_bytes);
    try std.testing.expectEqual(@as(usize, 0), q.recv_datagram_bytes);
}

test "pending_frames: set and clear MAX_DATA" {
    var q: PendingFrameQueues = .empty;
    defer q.deinit(std.testing.allocator);

    q.max_data = 16384;
    try std.testing.expectEqual(@as(?u64, 16384), q.max_data);

    // The drain path clears by assigning null after emitting the frame.
    q.max_data = null;
    try std.testing.expectEqual(@as(?u64, null), q.max_data);

    // Re-arming after a clear must work.
    q.max_data = 32768;
    try std.testing.expectEqual(@as(?u64, 32768), q.max_data);
}

test "pending_frames: MAX_STREAMS bidi vs uni do not alias" {
    var q: PendingFrameQueues = .empty;
    defer q.deinit(std.testing.allocator);

    q.max_streams_bidi = 100;
    try std.testing.expectEqual(@as(?u64, 100), q.max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, null), q.max_streams_uni);

    q.max_streams_uni = 50;
    try std.testing.expectEqual(@as(?u64, 100), q.max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, 50), q.max_streams_uni);

    q.max_streams_bidi = null;
    try std.testing.expectEqual(@as(?u64, null), q.max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, 50), q.max_streams_uni);
}

test "pending_frames: STREAMS_BLOCKED and STREAM_DATA_BLOCKED are independent slots" {
    var q: PendingFrameQueues = .empty;
    defer q.deinit(std.testing.allocator);

    q.streams_blocked_bidi = 7;
    q.streams_blocked_uni = 9;
    try q.stream_data_blocked.append(std.testing.allocator, .{
        .stream_id = 4,
        .maximum_stream_data = 1024,
    });

    // streams_blocked_* are connection-wide caps; stream_data_blocked is
    // a per-stream queue. They must not alias each other.
    try std.testing.expectEqual(@as(?u64, 7), q.streams_blocked_bidi);
    try std.testing.expectEqual(@as(?u64, 9), q.streams_blocked_uni);
    try std.testing.expectEqual(@as(usize, 1), q.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(u64, 4), q.stream_data_blocked.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 1024), q.stream_data_blocked.items[0].maximum_stream_data);

    // Clearing one of the optionals leaves the others (and the queue)
    // untouched.
    q.streams_blocked_bidi = null;
    try std.testing.expectEqual(@as(?u64, null), q.streams_blocked_bidi);
    try std.testing.expectEqual(@as(?u64, 9), q.streams_blocked_uni);
    try std.testing.expectEqual(@as(usize, 1), q.stream_data_blocked.items.len);
}

test "pending_frames: PATH_RESPONSE token round-trip" {
    var q: PendingFrameQueues = .empty;
    defer q.deinit(std.testing.allocator);

    const token: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    var addr: Address = .{};
    addr.bytes[0] = 0x7f; // 127.0.0.1 placeholder

    q.path_response = token;
    q.path_response_path_id = 3;
    q.path_response_addr = addr;

    try std.testing.expect(q.path_response != null);
    try std.testing.expectEqualSlices(u8, &token, &q.path_response.?);
    try std.testing.expectEqual(@as(u32, 3), q.path_response_path_id);
    try std.testing.expect(q.path_response_addr != null);
    try std.testing.expect(Address.eql(addr, q.path_response_addr.?));

    // The packetizer clears the slot once the frame is on the wire.
    q.path_response = null;
    q.path_response_addr = null;
    try std.testing.expect(q.path_response == null);
    try std.testing.expect(q.path_response_addr == null);
}

test "pending_frames: NEW_CONNECTION_ID and RETIRE_CONNECTION_ID lifecycle" {
    const allocator = std.testing.allocator;
    var q: PendingFrameQueues = .empty;
    defer q.deinit(allocator);

    const cid_bytes: [4]u8 = .{ 0x01, 0x02, 0x03, 0x04 };
    const cid = try frame_types.ConnId.fromSlice(&cid_bytes);

    try q.new_connection_ids.append(allocator, .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = cid,
        .stateless_reset_token = @splat(0xAA),
    });
    try q.new_connection_ids.append(allocator, .{
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = cid,
        .stateless_reset_token = @splat(0xBB),
    });
    try q.new_connection_ids.append(allocator, .{
        .sequence_number = 3,
        .retire_prior_to = 0,
        .connection_id = cid,
        .stateless_reset_token = @splat(0xCC),
    });

    try q.retire_connection_ids.append(allocator, .{ .sequence_number = 0 });

    try std.testing.expectEqual(@as(usize, 3), q.new_connection_ids.items.len);
    try std.testing.expectEqual(@as(usize, 1), q.retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 2), q.new_connection_ids.items[1].sequence_number);

    // `removeNewConnectionIdBySequence` drops the matching entry and
    // preserves order of the rest.
    q.removeNewConnectionIdBySequence(2);
    try std.testing.expectEqual(@as(usize, 2), q.new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 1), q.new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(u64, 3), q.new_connection_ids.items[1].sequence_number);

    // Removing a non-existent sequence number is a no-op.
    q.removeNewConnectionIdBySequence(99);
    try std.testing.expectEqual(@as(usize, 2), q.new_connection_ids.items.len);

    // Drain everything by removing the remaining sequence numbers.
    q.removeNewConnectionIdBySequence(1);
    q.removeNewConnectionIdBySequence(3);
    try std.testing.expectEqual(@as(usize, 0), q.new_connection_ids.items.len);
}

test "pending_frames: removePathNewConnectionIdBySequence keys on (path_id, sequence)" {
    const allocator = std.testing.allocator;
    var q: PendingFrameQueues = .empty;
    defer q.deinit(allocator);

    const cid = try frame_types.ConnId.fromSlice(&[_]u8{ 0xAA, 0xBB });
    try q.path_new_connection_ids.append(allocator, .{
        .path_id = 1,
        .sequence_number = 5,
        .retire_prior_to = 0,
        .connection_id = cid,
        .stateless_reset_token = @splat(0),
    });
    try q.path_new_connection_ids.append(allocator, .{
        .path_id = 2,
        .sequence_number = 5, // same seq, different path
        .retire_prior_to = 0,
        .connection_id = cid,
        .stateless_reset_token = @splat(0),
    });

    // Removing (path 1, seq 5) leaves (path 2, seq 5) intact.
    q.removePathNewConnectionIdBySequence(1, 5);
    try std.testing.expectEqual(@as(usize, 1), q.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u32, 2), q.path_new_connection_ids.items[0].path_id);
}

test "pending_frames: NEW_TOKEN slot stores bytes inline" {
    var q: PendingFrameQueues = .empty;
    defer q.deinit(std.testing.allocator);

    const token = "addr-validation-token-bytes";
    var item: NewTokenItem = .{};
    @memcpy(item.bytes[0..token.len], token);
    item.len = @intCast(token.len);
    q.new_token = item;

    try std.testing.expect(q.new_token != null);
    try std.testing.expectEqualSlices(u8, token, q.new_token.?.slice());

    // Drain.
    q.new_token = null;
    try std.testing.expect(q.new_token == null);
}

test "pending_frames: popRecvDatagram drains FIFO and tracks bytes" {
    const allocator = std.testing.allocator;
    var q: PendingFrameQueues = .empty;
    defer q.deinit(allocator);

    try std.testing.expect(q.popRecvDatagram() == null);

    const a = try allocator.dupe(u8, "alpha");
    const b = try allocator.dupe(u8, "br");
    try q.recv_datagrams.append(allocator, .{ .data = a });
    try q.recv_datagrams.append(allocator, .{ .data = b });
    q.recv_datagram_bytes = a.len + b.len;

    const first = q.popRecvDatagram() orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("alpha", first.data);
    try std.testing.expectEqual(@as(usize, 2), q.recv_datagram_bytes);
    allocator.free(first.data);

    const second = q.popRecvDatagram() orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings("br", second.data);
    try std.testing.expectEqual(@as(usize, 0), q.recv_datagram_bytes);
    allocator.free(second.data);

    try std.testing.expect(q.popRecvDatagram() == null);
}

test "pending_frames: deinit frees datagram payload bytes" {
    const allocator = std.testing.allocator;
    var q: PendingFrameQueues = .empty;

    // Populate both directions; deinit must free the payload buffers.
    const sd = try allocator.dupe(u8, "send-payload");
    try q.send_datagrams.append(allocator, .{ .id = 7, .data = sd });
    q.send_datagram_bytes = sd.len;

    const rd = try allocator.dupe(u8, "recv-payload");
    try q.recv_datagrams.append(allocator, .{ .data = rd });
    q.recv_datagram_bytes = rd.len;

    // Also stage a few non-datagram queue entries to confirm deinit
    // tears down every backing ArrayList. `std.testing.allocator` will
    // assert if any of these leak.
    try q.stop_sending.append(allocator, .{
        .stream_id = 1,
        .application_error_code = 0,
    });
    try q.max_stream_data.append(allocator, .{
        .stream_id = 1,
        .maximum_stream_data = 4096,
    });
    try q.retire_connection_ids.append(allocator, .{ .sequence_number = 0 });

    q.deinit(allocator);
}
