// Multipath path-scoped frame queueing — draft-ietf-quic-multipath-21
// §6. Free-function siblings of `Connection`'s `queuePath*` /
// `pendingPathCidsBlocked` / `clearPendingPathCidsBlocked` API; the
// methods on `Connection` are thin wrappers that delegate here.
//
// Extracted from `conn/state.zig` to keep the connection state-machine
// monolith from growing further. No behavior change.

const std = @import("std");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const PathCidsBlockedInfo = state_mod.PathCidsBlockedInfo;
const max_supported_path_id = state_mod.max_supported_path_id;
const path_mod = @import("path.zig");
const ConnectionId = path_mod.ConnectionId;
const frame_types = @import("../frame/types.zig");
const _internal = @import("_internal.zig");

/// Queue a PATH_ABANDON frame for the given multipath path. Coalesces
/// repeated calls for the same `path_id` (last `error_code` wins).
/// draft-ietf-quic-multipath-21 §6.1.
pub fn queuePathAbandon(
    self: *Connection,
    path_id: u32,
    error_code: u64,
) Error!void {
    for (self.pending_frames.path_abandons.items) |*item| {
        if (item.path_id == path_id) {
            item.error_code = error_code;
            return;
        }
    }
    try self.pending_frames.path_abandons.append(self.allocator, .{
        .path_id = path_id,
        .error_code = error_code,
    });
}

/// Queue a PATH_AVAILABLE / PATH_BACKUP frame announcing a status
/// change for `path_id`. Coalesces with any existing entry for the
/// same path, preferring the higher sequence number.
/// draft-ietf-quic-multipath-21 §6.2.
pub fn queuePathStatus(
    self: *Connection,
    path_id: u32,
    available: bool,
    sequence_number: u64,
) Error!void {
    for (self.pending_frames.path_statuses.items) |*item| {
        if (item.path_id == path_id) {
            if (sequence_number >= item.sequence_number) {
                item.sequence_number = sequence_number;
                item.available = available;
            }
            return;
        }
    }
    try self.pending_frames.path_statuses.append(self.allocator, .{
        .path_id = path_id,
        .sequence_number = sequence_number,
        .available = available,
    });
}

/// Queue a PATH_NEW_CONNECTION_ID frame for the multipath path-scoped
/// CID issuance flow. Validates `cid` length, issuance budget, and
/// uniqueness; remembers the local CID so packets bearing it can be
/// authenticated. draft-ietf-quic-multipath-21 §6.3.
pub fn queuePathNewConnectionId(
    self: *Connection,
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: []const u8,
    stateless_reset_token: [16]u8,
) Error!void {
    if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    try _internal.ensureCanIssueCidForPathId(self, path_id);
    try _internal.ensureCanIssueLocalCid(self, path_id, sequence_number, retire_prior_to, cid.len);
    const local_cid = ConnectionId.fromSlice(cid);
    try _internal.ensureLocalCidAvailable(self, path_id, sequence_number, local_cid);
    for (self.pending_frames.path_new_connection_ids.items) |item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            if (!std.mem.eql(u8, item.connection_id.slice(), cid)) return Error.ConnectionIdAlreadyInUse;
            return;
        }
    }
    var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
    @memcpy(connection_id.bytes[0..cid.len], cid);
    try _internal.rememberLocalCid(self, path_id, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
    try self.pending_frames.path_new_connection_ids.append(self.allocator, .{
        .path_id = path_id,
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .connection_id = connection_id,
        .stateless_reset_token = stateless_reset_token,
    });
    _internal.refreshConnectionIdEventsForPath(self, path_id);
}

/// Queue a PATH_RETIRE_CONNECTION_ID frame asking the peer to drop the
/// `(path_id, sequence_number)` CID. Idempotent — duplicate retires for
/// the same pair are coalesced. draft-ietf-quic-multipath-21 §6.4.
pub fn queuePathRetireConnectionId(
    self: *Connection,
    path_id: u32,
    sequence_number: u64,
) Error!void {
    for (self.pending_frames.path_retire_connection_ids.items) |item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) return;
    }
    try self.pending_frames.path_retire_connection_ids.append(self.allocator, .{
        .path_id = path_id,
        .sequence_number = sequence_number,
    });
}

/// Queue a MAX_PATH_ID frame raising our advertised path-id ceiling.
/// `maximum_path_id` is clamped to `max_supported_path_id`; lower values
/// than the current limit are ignored. draft-ietf-quic-multipath-21 §6.5.
pub fn queueMaxPathId(self: *Connection, maximum_path_id: u32) void {
    const bounded_maximum_path_id = @min(maximum_path_id, max_supported_path_id);
    if (bounded_maximum_path_id > self.local_max_path_id) {
        self.local_max_path_id = bounded_maximum_path_id;
    }
    if (self.pending_frames.max_path_id == null or bounded_maximum_path_id > self.pending_frames.max_path_id.?) {
        self.pending_frames.max_path_id = bounded_maximum_path_id;
    }
}

/// Queue a PATHS_BLOCKED frame telling the peer we have run out of
/// path-id headroom at `maximum_path_id`. Coalesces by keeping the
/// largest pending value. draft-ietf-quic-multipath-21 §6.6.
pub fn queuePathsBlocked(self: *Connection, maximum_path_id: u32) void {
    if (self.pending_frames.paths_blocked == null or maximum_path_id > self.pending_frames.paths_blocked.?) {
        self.pending_frames.paths_blocked = maximum_path_id;
    }
}

/// Queue a PATH_CIDS_BLOCKED frame on `path_id`. Sent when the peer's
/// CID issuance budget for this path is exhausted at
/// `next_sequence_number`. draft-ietf-quic-multipath-21 §6.7.
pub fn queuePathCidsBlocked(
    self: *Connection,
    path_id: u32,
    next_sequence_number: u64,
) void {
    self.pending_frames.path_cids_blocked = .{
        .path_id = path_id,
        .next_sequence_number = next_sequence_number,
    };
}

/// Returns the pending peer-side PATH_CIDS_BLOCKED report we have
/// received, or `null` if the peer is not currently blocked. Drives
/// proactive CID issuance via `provideConnectionId`.
pub fn pendingPathCidsBlocked(self: *const Connection) ?PathCidsBlockedInfo {
    const path_id = self.peer_path_cids_blocked_path_id orelse return null;
    return .{
        .path_id = path_id,
        .next_sequence_number = self.peer_path_cids_blocked_next_sequence,
    };
}

/// Clear a peer-side PATH_CIDS_BLOCKED report after the embedder has
/// issued enough fresh CIDs to satisfy it. The arguments must match the
/// `(path_id, next_sequence_number)` from `pendingPathCidsBlocked`;
/// mismatches are no-ops to avoid races with newer reports.
pub fn clearPendingPathCidsBlocked(
    self: *Connection,
    path_id: u32,
    next_sequence_number: u64,
) void {
    if (self.peer_path_cids_blocked_path_id == null) return;
    if (self.peer_path_cids_blocked_path_id.? != path_id) return;
    if (self.peer_path_cids_blocked_next_sequence != next_sequence_number) return;
    self.peer_path_cids_blocked_path_id = null;
    self.peer_path_cids_blocked_next_sequence = 0;
}

pub fn clearSatisfiedPathCidsBlocked(self: *Connection, path_id: u32) void {
    const pending = pendingPathCidsBlocked(self) orelse return;
    if (pending.path_id != path_id) return;
    if (_internal.nextLocalCidSequence(self, path_id) > pending.next_sequence_number) {
        clearPendingPathCidsBlocked(self, path_id, pending.next_sequence_number);
    }
}
