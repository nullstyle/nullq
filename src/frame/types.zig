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

/// PADDING frame (RFC 9000 §19.1). On the wire this is one or more
/// 0x00 bytes; this struct coalesces a contiguous run.
pub const Padding = struct {
    /// Number of consecutive 0x00 bytes treated as one logical PADDING
    /// run. The decoder coalesces; the encoder writes `count` zero
    /// bytes. Spec-wise each byte is a separate PADDING frame, but
    /// every QUIC implementation models them as runs.
    count: u64,
};

/// PING frame (RFC 9000 §19.2) — empty payload, used to elicit an ACK
/// and keep a path alive.
pub const Ping = struct {};

/// RESET_STREAM frame (RFC 9000 §19.4). Abruptly terminates the
/// sending part of a stream.
pub const ResetStream = struct {
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
};

/// STOP_SENDING frame (RFC 9000 §19.5). Asks the peer to stop sending
/// on a stream; the peer should respond with RESET_STREAM.
pub const StopSending = struct {
    stream_id: u64,
    application_error_code: u64,
};

/// CRYPTO frame (RFC 9000 §19.6) — carries a slice of the TLS handshake
/// stream at the given byte offset.
pub const Crypto = struct {
    offset: u64,
    /// Borrowed from input on decode; caller-owned on encode.
    data: []const u8,
};

/// NEW_TOKEN frame (RFC 9000 §19.7) — server gives the client a token
/// usable in a future Initial packet's Token field.
pub const NewToken = struct {
    token: []const u8,
};

/// MAX_DATA frame (RFC 9000 §19.9) — connection-level flow control limit.
pub const MaxData = struct {
    maximum_data: u64,
};

/// MAX_STREAM_DATA frame (RFC 9000 §19.10) — per-stream flow control limit.
pub const MaxStreamData = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

/// MAX_STREAMS frame (RFC 9000 §19.11). One frame type per direction;
/// the `bidi` flag selects which.
pub const MaxStreams = struct {
    /// True for bidirectional streams (type 0x12), false for
    /// unidirectional (0x13).
    bidi: bool,
    maximum_streams: u64,
};

/// DATA_BLOCKED frame (RFC 9000 §19.12) — sender hit the connection
/// flow control limit and is asking for credit.
pub const DataBlocked = struct {
    maximum_data: u64,
};

/// STREAM_DATA_BLOCKED frame (RFC 9000 §19.13) — sender hit a per-stream
/// flow control limit.
pub const StreamDataBlocked = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

/// STREAMS_BLOCKED frame (RFC 9000 §19.14). One frame type per direction;
/// the `bidi` flag selects which.
pub const StreamsBlocked = struct {
    /// True for bidirectional (type 0x16), false for unidirectional (0x17).
    bidi: bool,
    maximum_streams: u64,
};

/// NEW_CONNECTION_ID frame (RFC 9000 §19.15) — issues a fresh
/// connection ID with its stateless reset token.
pub const NewConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnId,
    stateless_reset_token: [16]u8,
};

/// RETIRE_CONNECTION_ID frame (RFC 9000 §19.16) — peer is done using
/// the connection ID at the given sequence number.
pub const RetireConnectionId = struct {
    sequence_number: u64,
};

/// PATH_CHALLENGE frame (RFC 9000 §19.17) — 8 random bytes the peer
/// must echo in PATH_RESPONSE to validate the path.
pub const PathChallenge = struct {
    data: [8]u8,
};

/// PATH_RESPONSE frame (RFC 9000 §19.18) — echo of a received
/// PATH_CHALLENGE's 8 bytes.
pub const PathResponse = struct {
    data: [8]u8,
};

/// CONNECTION_CLOSE frame (RFC 9000 §19.19). Two wire variants:
/// transport (0x1c) and application (0x1d), distinguished by `is_transport`.
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

/// HANDSHAKE_DONE frame (RFC 9000 §19.20) — server signals the
/// handshake is confirmed. Empty payload.
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

/// ACK frame (RFC 9000 §19.3). Two wire types: 0x02 (no ECN) and 0x03
/// (with ECN counts). The range list is a varint-pair stream stored
/// verbatim in `ranges_bytes`; decode with `ack_range.iter`.
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

/// PATH_ACK frame (draft-ietf-quic-multipath-21) — per-path ACK.
/// Same shape as `Ack` plus a `path_id` prefix. Wire types 0x3e/0x3f.
pub const PathAck = struct {
    path_id: u32,
    largest_acked: u64,
    ack_delay: u64,
    first_range: u64,
    range_count: u64,
    ranges_bytes: []const u8,
    ecn_counts: ?EcnCounts = null,
};

/// PATH_ABANDON frame (draft-ietf-quic-multipath-21) — peer is
/// abandoning the named path with an error code.
pub const PathAbandon = struct {
    path_id: u32,
    error_code: u64,
};

/// Body for PATH_STATUS_BACKUP / PATH_STATUS_AVAILABLE frames
/// (draft-ietf-quic-multipath-21). The variant is encoded by the
/// containing `Frame` tag, not by a field here.
pub const PathStatus = struct {
    path_id: u32,
    sequence_number: u64,
};

/// PATH_NEW_CONNECTION_ID frame (draft-ietf-quic-multipath-21) —
/// per-path equivalent of NEW_CONNECTION_ID.
pub const PathNewConnectionId = struct {
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnId,
    stateless_reset_token: [16]u8,
};

/// PATH_RETIRE_CONNECTION_ID frame (draft-ietf-quic-multipath-21) —
/// per-path equivalent of RETIRE_CONNECTION_ID.
pub const PathRetireConnectionId = struct {
    path_id: u32,
    sequence_number: u64,
};

/// MAX_PATH_ID frame (draft-ietf-quic-multipath-21) — raises the cap
/// on path IDs the peer may use.
pub const MaxPathId = struct {
    maximum_path_id: u32,
};

/// PATHS_BLOCKED frame (draft-ietf-quic-multipath-21) — sender wants
/// more paths than `maximum_path_id` currently allows.
pub const PathsBlocked = struct {
    maximum_path_id: u32,
};

/// PATH_CIDS_BLOCKED frame (draft-ietf-quic-multipath-21) — sender ran
/// out of usable connection IDs for the named path.
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

/// Tagged union of every QUIC frame nullq parses or emits. The active
/// tag tells you the frame type; the payload carries its fields. Use
/// `encode` / `decode` from this module to translate to and from wire
/// bytes.
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
