//! QUIC frame type definitions (RFC 9000 §19).
//!
//! Covers all 20 frame types in the v1 spec — 18 fixed-shape frames
//! plus ACK (with range encoding) and STREAM (with FIN/LEN/OFF flags
//! in the type byte).

const std = @import("std");
const wire_header = @import("../wire/header.zig");

/// Connection ID type, shared with `wire/header.zig`. NEW_CONNECTION_ID
/// frames carry these (RFC 9000 §19.15).
pub const ConnId = wire_header.ConnId;

pub const Padding = struct {
    /// Number of consecutive 0x00 bytes treated as one logical PADDING
    /// run. The decoder coalesces; the encoder writes `count` zero
    /// bytes. Spec-wise each byte is a separate PADDING frame, but
    /// every QUIC implementation models them as runs.
    count: u64,
};

pub const Ping = struct {};

pub const ResetStream = struct {
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
};

pub const StopSending = struct {
    stream_id: u64,
    application_error_code: u64,
};

pub const Crypto = struct {
    offset: u64,
    /// Borrowed from input on decode; caller-owned on encode.
    data: []const u8,
};

pub const NewToken = struct {
    token: []const u8,
};

pub const MaxData = struct {
    maximum_data: u64,
};

pub const MaxStreamData = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const MaxStreams = struct {
    /// True for bidirectional streams (type 0x12), false for
    /// unidirectional (0x13).
    bidi: bool,
    maximum_streams: u64,
};

pub const DataBlocked = struct {
    maximum_data: u64,
};

pub const StreamDataBlocked = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const StreamsBlocked = struct {
    bidi: bool,
    maximum_streams: u64,
};

pub const NewConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnId,
    stateless_reset_token: [16]u8,
};

pub const RetireConnectionId = struct {
    sequence_number: u64,
};

pub const PathChallenge = struct {
    data: [8]u8,
};

pub const PathResponse = struct {
    data: [8]u8,
};

pub const ConnectionClose = struct {
    /// True for transport-layer CONNECTION_CLOSE (frame type 0x1c) —
    /// includes a `frame_type` field naming the frame that triggered
    /// the close. False for application-layer (0x1d) — no frame_type.
    is_transport: bool,
    error_code: u64,
    /// Only meaningful when `is_transport`. 0 if unknown frame type.
    frame_type: u64 = 0,
    reason_phrase: []const u8,
};

pub const HandshakeDone = struct {};

/// One (gap, length) pair from an ACK frame's range list. Both
/// values are varint-encoded on the wire.
pub const AckRange = struct {
    gap: u64,
    length: u64,
};

/// Optional ECN counts present when ACK frame type is 0x03 (RFC
/// 9000 §13.4.2 / §19.3.2). All three are varints on the wire.
pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ecn_ce: u64,
};

pub const Ack = struct {
    largest_acked: u64,
    /// Encoded ack delay in microseconds, scaled by the peer's
    /// `ack_delay_exponent` transport parameter (RFC 9000 §13.2.5).
    /// nullq's wire layer doesn't apply the exponent — that's the
    /// state machine's job in Phase 5.
    ack_delay: u64,
    /// Length of the contiguous run [largest_acked - first_range,
    /// largest_acked]. So `first_range + 1` packets are acked at the top.
    first_range: u64,
    /// Number of (gap, length) pairs that follow. May be 0.
    range_count: u64,
    /// Borrowed wire bytes for the gap/length varints. Decode this
    /// with `ack_range.iter(...)`. On encode, the caller pre-builds
    /// these bytes (via `ack_range.writeRanges` or by hand).
    ranges_bytes: []const u8,
    /// Present when frame type is 0x03; `null` for type 0x02.
    ecn_counts: ?EcnCounts = null,
};

pub const PathAck = struct {
    path_id: u32,
    largest_acked: u64,
    ack_delay: u64,
    first_range: u64,
    range_count: u64,
    ranges_bytes: []const u8,
    ecn_counts: ?EcnCounts = null,
};

pub const PathAbandon = struct {
    path_id: u32,
    error_code: u64,
};

pub const PathStatus = struct {
    path_id: u32,
    sequence_number: u64,
};

pub const PathNewConnectionId = struct {
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnId,
    stateless_reset_token: [16]u8,
};

pub const PathRetireConnectionId = struct {
    path_id: u32,
    sequence_number: u64,
};

pub const MaxPathId = struct {
    maximum_path_id: u32,
};

pub const PathsBlocked = struct {
    maximum_path_id: u32,
};

pub const PathCidsBlocked = struct {
    path_id: u32,
    next_sequence_number: u64,
};

/// QUIC STREAM frame (RFC 9000 §19.8). The type byte has three flag
/// bits — OFF (0x04), LEN (0x02), FIN (0x01) — combined with the
/// base 0x08 to give the 8 wire types 0x08..0x0f.
pub const Stream = struct {
    stream_id: u64,
    offset: u64 = 0,
    /// Borrowed bytes on decode; caller-owned on encode.
    data: []const u8,
    /// True if the OFF flag is set on the type byte. When false, the
    /// offset on the wire is implicitly 0 (and `offset` MUST be 0 on
    /// encode).
    has_offset: bool = false,
    /// True if the LEN flag is set on the type byte. When false, the
    /// stream data extends to the end of the encoded `src` slice.
    /// (In a real packet that means STREAM must be the last frame.)
    has_length: bool = true,
    /// True if the FIN flag is set on the type byte.
    fin: bool = false,
};

/// QUIC DATAGRAM frame (RFC 9221 §4). The type byte is 0x30 for
/// the implicit-length variant (extends to end of packet) or 0x31
/// for the LEN-prefixed variant.
pub const Datagram = struct {
    /// Borrowed bytes on decode; caller-owned on encode.
    data: []const u8,
    /// True if the LEN flag is set on the type byte (0x31). When
    /// false, the data extends to the end of the encoded `src` slice
    /// (and so DATAGRAM must be the last frame in the packet).
    has_length: bool = true,
};

pub const Frame = union(enum) {
    padding: Padding,
    ping: Ping,
    ack: Ack,
    reset_stream: ResetStream,
    stop_sending: StopSending,
    crypto: Crypto,
    new_token: NewToken,
    stream: Stream,
    max_data: MaxData,
    max_stream_data: MaxStreamData,
    max_streams: MaxStreams,
    data_blocked: DataBlocked,
    stream_data_blocked: StreamDataBlocked,
    streams_blocked: StreamsBlocked,
    new_connection_id: NewConnectionId,
    retire_connection_id: RetireConnectionId,
    path_challenge: PathChallenge,
    path_response: PathResponse,
    connection_close: ConnectionClose,
    handshake_done: HandshakeDone,
    datagram: Datagram,
    path_ack: PathAck,
    path_abandon: PathAbandon,
    path_status_backup: PathStatus,
    path_status_available: PathStatus,
    path_new_connection_id: PathNewConnectionId,
    path_retire_connection_id: PathRetireConnectionId,
    max_path_id: MaxPathId,
    paths_blocked: PathsBlocked,
    path_cids_blocked: PathCidsBlocked,
};
