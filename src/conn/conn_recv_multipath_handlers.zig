// Inbound frame handlers for QUIC multipath (draft-ietf-quic-multipath-21):
// PATH_ACK, PATH_ABANDON, PATH_STATUS, PATH_NEW_CONNECTION_ID,
// PATH_RETIRE_CONNECTION_ID, MAX_PATH_ID, PATHS_BLOCKED,
// PATH_CIDS_BLOCKED. Free-function siblings of `Connection`'s
// public method-style handlers; the methods on `Connection` are
// thin thunks that delegate here.
//
// These are the inbound counterparts of the queuePath* methods in
// `path_frame_queue.zig`. Extracted from src/conn/state.zig to keep
// the connection state-machine monolith from growing further.
// No behavior change.

const std = @import("std");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const frame_types = state_mod.frame_types;
const ConnectionId = state_mod.ConnectionId;
const _internal = state_mod._internal;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const max_supported_path_id = state_mod.max_supported_path_id;

fn pathAckToAck(pa: frame_types.PathAck) frame_types.Ack {
    return .{
        .largest_acked = pa.largest_acked,
        .ack_delay = pa.ack_delay,
        .first_range = pa.first_range,
        .range_count = pa.range_count,
        .ranges_bytes = pa.ranges_bytes,
        .ecn_counts = pa.ecn_counts,
    };
}

pub fn handlePathAck(
    self: *Connection,
    pa: frame_types.PathAck,
    now_us: u64,
) Error!void {
    if (pa.path_id == 0) {
        return self.handleAckAtLevel(.application, pathAckToAck(pa), now_us);
    }
    const path = self.paths.get(pa.path_id) orelse return;
    try self.handleApplicationAckOnPath(path, pathAckToAck(pa), now_us);
}

pub fn handlePathAbandon(
    self: *Connection,
    pa: frame_types.PathAbandon,
    now_us: u64,
) void {
    _ = self.retirePath(pa.path_id, pa.error_code, now_us, true);
}

pub fn handlePathStatus(
    self: *Connection,
    ps: frame_types.PathStatus,
    available: bool,
) void {
    const path = self.paths.get(ps.path_id) orelse return;
    path.recordPeerStatus(available, ps.sequence_number);
}

pub fn handlePathNewConnectionId(
    self: *Connection,
    nc: frame_types.PathNewConnectionId,
) Error!void {
    const cid = ConnectionId.fromSlice(nc.connection_id.slice());
    try self.registerPeerCid(nc.path_id, nc.sequence_number, nc.retire_prior_to, cid, nc.stateless_reset_token);
}

pub fn handlePathRetireConnectionId(
    self: *Connection,
    rc: frame_types.PathRetireConnectionId,
) void {
    // Multipath analogue of RFC 9000 §19.16. Same DoS surface — a
    // peer that walks ahead of the issued sequence forces us to do
    // a lookup-and-discard per frame.
    if (self.paths.getConst(rc.path_id)) |path| {
        if (rc.sequence_number >= path.next_local_cid_seq) {
            self.close(true, transport_error_protocol_violation, "path_retire_connection_id sequence not yet issued");
            return;
        }
    }
    self.retireLocalCidFromPeer(rc.path_id, rc.sequence_number);
    self.dropPendingLocalCidAdvertisement(rc.path_id, rc.sequence_number);
}

pub fn handleMaxPathId(self: *Connection, mp: frame_types.MaxPathId) void {
    if (self.cached_peer_transport_params) |params| {
        if (params.initial_max_path_id) |initial_max_path_id| {
            if (mp.maximum_path_id < initial_max_path_id) {
                self.close(true, transport_error_protocol_violation, "max path id below peer initial limit");
                return;
            }
        }
    }
    if (mp.maximum_path_id > self.peer_max_path_id) {
        self.peer_max_path_id = @min(mp.maximum_path_id, max_supported_path_id);
    }
}

pub fn handlePathsBlocked(self: *Connection, pb: frame_types.PathsBlocked) void {
    if (!self.pathIdAllowedByLocalLimit(pb.maximum_path_id)) return;
    if (pb.maximum_path_id < self.local_max_path_id) return;
    self.peer_paths_blocked_at = pb.maximum_path_id;
}

pub fn handlePathCidsBlocked(self: *Connection, pcb: frame_types.PathCidsBlocked) void {
    if (!self.pathIdAllowedByLocalLimit(pcb.path_id)) return;
    const next = _internal.nextLocalCidSequence(self,pcb.path_id);
    if (pcb.next_sequence_number > next) {
        self.close(true, transport_error_protocol_violation, "path cids blocked skips local cid sequence");
        return;
    }
    self.peer_path_cids_blocked_path_id = pcb.path_id;
    self.peer_path_cids_blocked_next_sequence = pcb.next_sequence_number;
    self.recordConnectionIdsNeeded(pcb.path_id, .path_cids_blocked, pcb.next_sequence_number);
}
