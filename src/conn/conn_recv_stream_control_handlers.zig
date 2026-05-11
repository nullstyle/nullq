// Inbound frame handlers for stream-control termination from the
// peer: STOP_SENDING (RFC 9000 §19.5) and RESET_STREAM (§19.4).
// Free-function siblings of `Connection`'s public method-style
// handlers; the methods on `Connection` are thin thunks that
// delegate here.

const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const Stream = state_mod.Stream;
const SendStream = state_mod.SendStream;
const RecvStream = state_mod.RecvStream;
const frame_types = state_mod.frame_types;
const transport_error_stream_state = state_mod.transport_error_stream_state;
const transport_error_flow_control = state_mod.transport_error_flow_control;
const transport_error_final_size = state_mod.transport_error_final_size;

pub fn handleStopSending(
    self: *Connection,
    ss: frame_types.StopSending,
) Error!void {
    const ptr = self.streams.get(ss.stream_id) orelse return;
    try ptr.send.resetStream(ss.application_error_code);
}

pub fn handleResetStream(self: *Connection, rs: frame_types.ResetStream) Error!void {
    if (!self.peerMaySendOnStream(rs.stream_id)) {
        self.close(true, transport_error_stream_state, "reset stream on receive-only stream");
        return;
    }
    const existing = self.streams.get(rs.stream_id);
    if (existing == null and self.streamInitiatedByLocal(rs.stream_id)) {
        self.close(true, transport_error_stream_state, "peer reset unopened local stream");
        return;
    }
    if (existing == null and !self.recordPeerStreamOpenOrClose(rs.stream_id)) return;
    const ptr = existing orelse blk: {
        const new_ptr = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(new_ptr);
        new_ptr.* = .{
            .id = rs.stream_id,
            .send = SendStream.init(self.allocator),
            .recv = RecvStream.init(self.allocator),
            .recv_max_data = self.initialRecvStreamLimit(rs.stream_id),
            .send_max_data = self.initialSendStreamLimit(rs.stream_id),
        };
        try self.streams.put(self.allocator, rs.stream_id, new_ptr);
        break :blk new_ptr;
    };
    const old_highest = ptr.recv.peerHighestOffset();
    const new_highest = @max(old_highest, rs.final_size);
    if (new_highest > ptr.recv_max_data) {
        self.close(true, transport_error_flow_control, "peer reset exceeds stream data limit");
        return;
    }
    const delta = new_highest - old_highest;
    if (delta > 0 and
        (delta > self.local_max_data or self.peer_sent_stream_data > self.local_max_data - delta))
    {
        self.close(true, transport_error_flow_control, "peer reset exceeds connection data limit");
        return;
    }
    // Hardening guide §3.5 / §8: snapshot the recv buffer length
    // before `resetStream`, which discards buffered-but-undelivered
    // bytes (no-longer-needed reassembly state) and shrinks the
    // backing allocation to zero. Reconcile the global
    // resident-bytes counter against that drop.
    const recv_before = ptr.recv.bytes.items.len;
    ptr.recv.resetStream(rs.application_error_code, rs.final_size) catch |err| switch (err) {
        error.BeyondFinalSize, error.FinalSizeChanged => {
            self.close(true, transport_error_final_size, "reset stream final size changed");
            return;
        },
        else => return err,
    };
    if (ptr.recv.bytes.items.len < recv_before) {
        self.releaseResidentBytes(recv_before - ptr.recv.bytes.items.len);
    }
    self.peer_sent_stream_data += delta;
    self.maybeReturnPeerStreamCredit(ptr);
}
