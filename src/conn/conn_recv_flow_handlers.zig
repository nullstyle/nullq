// Inbound frame handlers for connection-level + stream-level flow
// control: MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED,
// STREAM_DATA_BLOCKED, STREAMS_BLOCKED. Free-function siblings of
// `Connection`'s public method-style handlers; the methods on
// `Connection` are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const frame_types = state_mod.frame_types;
const transport_error_stream_state = state_mod.transport_error_stream_state;
const transport_error_frame_encoding = state_mod.transport_error_frame_encoding;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const max_stream_count_limit = state_mod.max_stream_count_limit;
const max_streams_per_connection = state_mod.max_streams_per_connection;
const upsertStreamBlocked = Connection.upsertStreamBlocked;

/// Handle a peer-sent MAX_DATA frame (RFC 9000 §19.9). Lifts our
/// connection-level send limit if the peer's value increases.
pub fn handleMaxData(self: *Connection, md: frame_types.MaxData) void {
    if (md.maximum_data > self.peer_max_data) {
        self.peer_max_data = md.maximum_data;
        self.clearLocalDataBlocked(md.maximum_data);
    }
}

/// Handle a peer-sent MAX_STREAM_DATA frame (RFC 9000 §19.10). Lifts
/// the per-stream send limit on `stream_id` if the peer's value
/// increases. PROTOCOL_VIOLATION if the stream is receive-only from
/// our perspective.
pub fn handleMaxStreamData(self: *Connection, msd: frame_types.MaxStreamData) void {
    if (!self.localMaySendOnStream(msd.stream_id)) {
        self.close(true, transport_error_stream_state, "max stream data for receive-only stream");
        return;
    }
    const s = self.streams.get(msd.stream_id) orelse return;
    if (msd.maximum_stream_data > s.send_max_data) {
        s.send_max_data = msd.maximum_stream_data;
        self.clearLocalStreamDataBlocked(msd.stream_id, msd.maximum_stream_data);
    }
}

/// Handle a peer-sent MAX_STREAMS frame (RFC 9000 §19.11). Lifts our
/// stream-count limit (bidi or uni) if the value increases. Caps at
/// `max_streams_per_connection`. FRAME_ENCODING_ERROR on out-of-range.
pub fn handleMaxStreams(self: *Connection, ms: frame_types.MaxStreams) void {
    if (ms.maximum_streams > max_stream_count_limit) {
        self.close(true, transport_error_frame_encoding, "max streams exceeds stream id space");
        return;
    }
    const bounded_maximum_streams = @min(ms.maximum_streams, max_streams_per_connection);
    if (ms.bidi) {
        if (bounded_maximum_streams > self.peer_max_streams_bidi) {
            self.peer_max_streams_bidi = bounded_maximum_streams;
            self.clearLocalStreamsBlocked(true, bounded_maximum_streams);
        }
    } else {
        if (bounded_maximum_streams > self.peer_max_streams_uni) {
            self.peer_max_streams_uni = bounded_maximum_streams;
            self.clearLocalStreamsBlocked(false, bounded_maximum_streams);
        }
    }
}

/// Handle a peer-sent DATA_BLOCKED frame (RFC 9000 §19.12). Records the
/// peer's advertised connection-level limit so the embedder can diagnose
/// flow-control deadlocks via `peerDataBlockedAt`.
pub fn handleDataBlocked(self: *Connection, db: frame_types.DataBlocked) void {
    self.peer_data_blocked_at = db.maximum_data;
    self.recordFlowBlockedEvent(.{
        .source = .peer,
        .kind = .data,
        .limit = db.maximum_data,
    });
}

/// Handle a peer-sent STREAM_DATA_BLOCKED frame (RFC 9000 §19.13).
/// Records the peer's stream-level limit. STREAM_STATE_ERROR if the
/// stream is receive-only from the peer's perspective.
pub fn handleStreamDataBlocked(self: *Connection, sdb: frame_types.StreamDataBlocked) Error!void {
    if (!self.peerMaySendOnStream(sdb.stream_id)) {
        self.close(true, transport_error_stream_state, "stream data blocked for receive-only stream");
        return;
    }
    const idx = Connection.streamIndex(sdb.stream_id);
    if (idx >= max_stream_count_limit) {
        self.close(true, transport_error_frame_encoding, "stream data blocked exceeds stream id space");
        return;
    }
    const existing = self.streams.get(sdb.stream_id);
    if (existing == null and self.streamInitiatedByLocal(sdb.stream_id)) return;
    if (existing == null and !self.peerStreamWithinLocalLimit(sdb.stream_id)) return;
    _ = upsertStreamBlocked(&self.peer_stream_data_blocked, self.allocator, sdb) catch |err| {
        if (err == Error.StreamLimitExceeded) {
            self.close(true, transport_error_protocol_violation, "stream data blocked tracking exhausted");
            return;
        }
        return err;
    };
    self.recordFlowBlockedEvent(.{
        .source = .peer,
        .kind = .stream_data,
        .limit = sdb.maximum_stream_data,
        .stream_id = sdb.stream_id,
    });
}

/// Handle a peer-sent STREAMS_BLOCKED frame (RFC 9000 §19.14). Records
/// the peer's advertised stream-count limit. FRAME_ENCODING_ERROR on
/// out-of-range value.
pub fn handleStreamsBlocked(self: *Connection, sb: frame_types.StreamsBlocked) void {
    if (sb.maximum_streams > max_stream_count_limit) {
        self.close(true, transport_error_frame_encoding, "streams blocked exceeds stream id space");
        return;
    }
    if (sb.bidi) {
        self.peer_streams_blocked_bidi = sb.maximum_streams;
    } else {
        self.peer_streams_blocked_uni = sb.maximum_streams;
    }
    self.recordFlowBlockedEvent(.{
        .source = .peer,
        .kind = .streams,
        .limit = sb.maximum_streams,
        .bidi = sb.bidi,
    });
}
