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
