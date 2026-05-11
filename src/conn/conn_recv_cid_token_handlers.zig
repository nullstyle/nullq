// Inbound frame handlers for connection-id and token frames:
// NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, NEW_TOKEN. Free-function
// siblings of `Connection`'s public method-style handlers; the methods
// on `Connection` are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const frame_types = state_mod.frame_types;
const ConnectionId = state_mod.ConnectionId;
const incoming_retire_cid_cap = state_mod.incoming_retire_cid_cap;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const transport_error_frame_encoding = state_mod.transport_error_frame_encoding;

pub fn handleNewConnectionId(
    self: *Connection,
    nc: frame_types.NewConnectionId,
) Error!void {
    const cid = ConnectionId.fromSlice(nc.connection_id.slice());
    try self.registerPeerCid(0, nc.sequence_number, nc.retire_prior_to, cid, nc.stateless_reset_token);
}

pub fn handleRetireConnectionId(
    self: *Connection,
    rc: frame_types.RetireConnectionId,
) void {
    // Per-cycle flood gate (DoS hardening). A peer bursting
    // RETIRE_CONNECTION_ID frames forces O(N) walks of `local_cids`
    // per frame; once the count exceeds the cap there's no
    // legitimate flow that needs that many retires in one
    // datagram.
    self.incoming_retire_cid_count +|= 1;
    if (self.incoming_retire_cid_count > incoming_retire_cid_cap) {
        self.close(true, transport_error_protocol_violation, "retire_connection_id flood");
        return;
    }
    // RFC 9000 §19.16 ¶3: "The sequence number specified in a
    // RETIRE_CONNECTION_ID frame MUST NOT refer to the
    // Destination Connection ID field of the packet in which the
    // frame is contained. The peer MAY treat this as a
    // connection error of type PROTOCOL_VIOLATION." Server
    // routing has already populated `current_incoming_local_cid_seq`
    // with the seq of the CID this datagram was addressed to;
    // any retire-frame referencing that exact seq is a peer
    // protocol violation.
    if (self.current_incoming_local_cid_seq) |incoming_seq| {
        if (rc.sequence_number == incoming_seq) {
            self.close(true, transport_error_protocol_violation, "retire_connection_id refers to receiving CID");
            return;
        }
    }
    // RFC 9000 §19.16: a sequence number greater than any we ever
    // sent is a PROTOCOL_VIOLATION. Without this gate, an off-path
    // attacker (or a misbehaving peer) could spam RETIRE_CONNECTION_ID
    // for fabricated sequences and waste server processing per packet.
    if (self.paths.getConst(0)) |path| {
        if (rc.sequence_number >= path.next_local_cid_seq) {
            self.close(true, transport_error_protocol_violation, "retire_connection_id sequence not yet issued");
            return;
        }
    }
    // Fast-path skip: if this seq is below the smallest still-live
    // local CID seq for path 0, the retire is a no-op (the entry
    // is already gone or was never installed). Skipping spares the
    // O(N) walk through `local_cids` and `pending_frames`. Equality
    // with an existing entry still goes through the slow path so
    // promotion fires correctly.
    if (self.smallestLiveLocalCidSeq(0)) |smallest| {
        if (rc.sequence_number < smallest) return;
    }
    self.retireLocalCidFromPeer(0, rc.sequence_number);
    self.dropPendingLocalCidAdvertisement(0, rc.sequence_number);
}

/// RFC 9000 §19.7 — server-issued NEW_TOKEN. The frame is only
/// legal at application encryption level (filtered upstream by
/// the level-allowed-frames check). Servers MUST NOT receive
/// NEW_TOKEN; if a peer-acting-as-server sends it to us we
/// raise PROTOCOL_VIOLATION. Clients hand the borrowed slice
/// straight to the embedder callback if one is installed.
pub fn handleNewToken(self: *Connection, nt: frame_types.NewToken) void {
    if (self.role != .client) {
        // Per §19.7: receiving NEW_TOKEN with role=server is a
        // PROTOCOL_VIOLATION. The frame-level check is here so
        // we don't bake server-side state on a malicious peer
        // sending the wrong-direction frame.
        self.close(true, transport_error_protocol_violation, "new_token from peer to server");
        return;
    }
    if (nt.token.len == 0) {
        // Zero-length NEW_TOKEN is FRAME_ENCODING_ERROR per §19.7.
        self.close(true, transport_error_frame_encoding, "zero-length new_token");
        return;
    }
    if (self.new_token_callback) |cb| cb(self.new_token_user_data, nt.token);
}
