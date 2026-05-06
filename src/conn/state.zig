//! nullq.Connection — per-connection state machine root.
//!
//! The Connection wraps a `boringssl.tls.Conn` (the SSL object),
//! installs nullq's `tls.quic.Method` callbacks, and exposes a
//! deterministic `advance` driver that pulls peer-provided CRYPTO
//! bytes through `provideQuicData` + `SSL_do_handshake` until the
//! handshake completes. Once handshake is done it owns packet number
//! spaces, ACK tracking, congestion control, flow control, the
//! stream layer, the multipath `PathSet`, key updates, and the
//! close/draining lifecycle.

const std = @import("std");
const boringssl = @import("boringssl");
const c = boringssl.raw;

const level_mod = @import("../tls/level.zig");
const wire_header = @import("../wire/header.zig");
const short_packet_mod = @import("../wire/short_packet.zig");
const long_packet_mod = @import("../wire/long_packet.zig");
const initial_keys_mod = @import("../wire/initial.zig");
const transport_params_mod = @import("../tls/transport_params.zig");
const early_data_context_mod = @import("../tls/early_data_context.zig");
const varint = @import("../wire/varint.zig");
const frame_mod = @import("../frame/root.zig");
const frame_types = @import("../frame/types.zig");
const ack_range_mod = @import("../frame/ack_range.zig");
const ack_tracker_mod = @import("ack_tracker.zig");
const send_stream_mod = @import("send_stream.zig");
const recv_stream_mod = @import("recv_stream.zig");
const pn_space_mod = @import("pn_space.zig");
const sent_packets_mod = @import("sent_packets.zig");
const loss_recovery_mod = @import("loss_recovery.zig");
const path_mod = @import("path.zig");
const congestion_mod = @import("congestion.zig");
const rtt_mod = @import("rtt.zig");
const flow_control_mod = @import("flow_control.zig");
const event_queue_mod = @import("event_queue.zig");

/// Encryption level (Initial / Handshake / 0-RTT / 1-RTT) — RFC 9001 §2.1.
pub const EncryptionLevel = level_mod.EncryptionLevel;
/// Read or write half-direction selector for keying material.
pub const Direction = level_mod.Direction;
/// Derived AEAD packet protection keys for a single direction.
pub const PacketKeys = short_packet_mod.PacketKeys;
/// Negotiated TLS cipher suite mapped to QUIC AEAD parameters.
pub const Suite = short_packet_mod.Suite;
/// Send half of a QUIC stream (RFC 9000 §3) — owns offset, flow credit, retransmit queue.
pub const SendStream = send_stream_mod.SendStream;
/// Receive half of a QUIC stream — owns reassembly buffer and flow-control window.
pub const RecvStream = recv_stream_mod.RecvStream;
/// Per-encryption-level packet number space (RFC 9000 §12.3).
pub const PnSpace = pn_space_mod.PnSpace;
/// In-flight packet bookkeeping for ACK processing and loss recovery.
pub const SentPacketTracker = sent_packets_mod.SentPacketTracker;
/// One network path (4-tuple plus DCID/SCID) — RFC 9000 §9 / multipath draft-21.
pub const Path = path_mod.Path;
/// Container holding all paths a connection currently knows about.
pub const PathSet = path_mod.PathSet;
/// Per-path validation/availability state machine.
pub const PathState = path_mod.PathState;
/// Per-path counters (datagrams sent/received, loss, RTT inputs).
pub const PathStats = path_mod.PathStats;
/// Multipath scheduler that picks which path an outgoing datagram uses.
pub const Scheduler = path_mod.Scheduler;
/// QUIC connection ID — variable-length opaque identifier (RFC 9000 §5.1).
pub const ConnectionId = path_mod.ConnectionId;
/// IP address + port pair used as a path endpoint.
pub const Address = path_mod.Address;
/// PATH_CHALLENGE / PATH_RESPONSE state machine (RFC 9000 §8.2).
pub const PathValidator = path_mod.PathValidator;
/// Smoothed RTT / RTT-variance estimator (RFC 9002 §5).
pub const RttEstimator = rtt_mod.RttEstimator;
/// Decoded peer transport parameters from the TLS handshake (RFC 9000 §18).
pub const TransportParams = transport_params_mod.Params;
/// Default congestion controller — NewReno from RFC 9002 §7.
pub const NewReno = congestion_mod.NewReno;
/// BoringSSL TLS session ticket handle, used for 0-RTT resumption.
pub const Session = boringssl.tls.Session;
/// 0-RTT acceptance/rejection status reported by BoringSSL.
pub const EarlyDataStatus = boringssl.tls.Conn.EarlyDataStatus;

/// Whether this Connection is the QUIC client or server endpoint.
pub const Role = enum { client, server };

/// Wire version code for QUIC v1 (RFC 9000 §15).
pub const quic_version_1: u32 = 0x00000001;

/// Aggregate error set returned from any Connection operation.
pub const Error = error{
    OutOfMemory,
    HandshakeFailed,
    InboxOverflow,
    PeerAlerted,
    UnsupportedCipherSuite,
    StreamAlreadyOpen,
    StreamNotFound,
    PnSpaceExhausted,
    PeerDcidNotSet,
    PathNotFound,
    PathLimitExceeded,
    ConnectionIdLimitExceeded,
    ConnectionIdRequired,
    ConnectionIdAlreadyInUse,
    EmptyEarlyDataContext,
    KeyUpdateUnavailable,
    KeyUpdateBlocked,
    DatagramUnavailable,
    DatagramTooLarge,
    DatagramQueueFull,
    DatagramIdExhausted,
    InvalidStreamId,
    StreamLimitExceeded,
} || boringssl.tls.Error ||
    boringssl.crypto.rand.Error ||
    short_packet_mod.Error ||
    long_packet_mod.Error ||
    send_stream_mod.Error ||
    recv_stream_mod.Error ||
    sent_packets_mod.Error ||
    flow_control_mod.Error ||
    frame_mod.EncodeError ||
    frame_mod.DecodeError ||
    ack_range_mod.Error ||
    ack_tracker_mod.Error ||
    transport_params_mod.Error;

/// Per-level secret bookkeeping. The TLS bridge stores the BoringSSL
/// cipher protocol-id plus raw traffic secret; packet-protection keys
/// are derived on demand from the negotiated suite.
pub const SecretMaterial = struct {
    cipher_protocol_id: u16,
    secret: [64]u8 = @splat(0),
    secret_len: u8 = 0,
};

/// Read+write traffic-secret material for one TLS encryption level.
/// Either half can be `null` until BoringSSL installs that direction.
pub const PerLevelState = struct {
    read: ?SecretMaterial = null,
    write: ?SecretMaterial = null,
};

/// One QUIC stream — bundles the send and receive halves with a
/// stable `id`. Bidi or uni is a property of the id (RFC 9000 §2.1
/// stream IDs encode direction in the low two bits); for Phase 5
/// the Connection treats every stream as bidi.
pub const Stream = struct {
    id: u64,
    send: SendStream,
    recv: RecvStream,
    /// Current stream-level receive limit we have advertised for this
    /// stream via transport params / MAX_STREAM_DATA.
    recv_max_data: u64 = 0,
    /// Current stream-level send limit the peer has advertised via
    /// transport params / MAX_STREAM_DATA.
    send_max_data: u64 = std.math.maxInt(u64),
    /// One past the highest stream byte we have ever put on the wire.
    /// Retransmissions below this floor do not consume flow control.
    send_flow_highest: u64 = 0,
    /// True once any byte for this stream arrived in a 0-RTT packet.
    arrived_in_early_data: bool = false,
    /// True once this peer-initiated stream has returned one stream
    /// count credit through MAX_STREAMS.
    stream_count_credit_returned: bool = false,
};

/// Default datagram budget for outgoing 1-RTT packets. RFC 9000 §14
/// mandates at least 1200 bytes path MTU; PMTU discovery (Phase 11)
/// can lift this.
pub const default_mtu: usize = 1200;
const transport_error_protocol_violation: u64 = 0x0a;
const transport_error_flow_control: u64 = 0x03;
const transport_error_stream_limit: u64 = 0x04;
const transport_error_stream_state: u64 = 0x05;
const transport_error_final_size: u64 = 0x06;
const transport_error_frame_encoding: u64 = 0x07;
const transport_error_transport_parameter: u64 = 0x08;
const transport_error_aead_limit_reached: u64 = 0x0f;

/// Upper bound on AEAD plaintext for a single received packet. This
/// implementation deliberately advertises and enforces the same 4 KiB
/// UDP payload budget so packet protection can stay stack-backed.
pub const max_recv_plaintext: usize = 4096;
/// Largest UDP payload size we will advertise to the peer in transport params.
pub const max_supported_udp_payload_size: usize = max_recv_plaintext;
/// Wire-mandated minimum UDP payload size for Initial packets (RFC 9000 §14).
pub const min_quic_udp_payload_size: usize = default_mtu;

/// Bounded queue budgets for RFC 9221 DATAGRAM payloads.
pub const max_outbound_datagram_payload_size: usize = default_mtu - 9;
/// Maximum number of unsent outbound DATAGRAM frames buffered at once.
pub const max_pending_datagram_count: usize = 64;
/// Maximum total byte volume of unsent outbound DATAGRAM frames buffered at once.
pub const max_pending_datagram_bytes: usize = 64 * 1024;

/// Bounded reassembly budgets for peer-controlled CRYPTO gaps.
pub const max_pending_crypto_bytes_per_level: usize = 64 * 1024;
/// Largest gap (in bytes) we will tolerate between in-order CRYPTO data and a
/// future fragment before treating the peer's stream as malicious.
pub const max_crypto_reassembly_gap: u64 = 64 * 1024;
/// Number of ack-eliciting application packets we accept before forcing an
/// ACK frame (RFC 9000 §13.2.2).
pub const application_ack_eliciting_threshold: u8 = 1;
/// Hard cap on total bytes spent on ACK ranges in any single application packet.
pub const max_application_ack_ranges_bytes: usize = 128;
/// Hard cap on the number of additional (non-largest) ACK ranges per application packet.
pub const max_application_ack_lower_ranges: u64 = 16;

/// Default per-stream receive credit advertised in transport params.
pub const default_stream_receive_window: u64 = 1024 * 1024;
/// Default connection-level receive credit advertised in transport params.
pub const default_connection_receive_window: u64 = 16 * 1024 * 1024;
/// Hard ceiling on `initial_max_streams_*` we will ever advertise.
pub const max_stream_count_limit: u64 = @as(u64, 1) << 60;
/// Minimum number of stream credits to accumulate before sending MAX_STREAMS.
pub const min_stream_credit_return_batch: u64 = 16;
/// Divisor controlling the watermark at which MAX_STREAMS replenishment fires.
pub const stream_credit_return_divisor: u64 = 1;

/// Implementation allocation policy. QUIC's wire limits are intentionally
/// enormous; nullq caps the resources it advertises and tracks so peer input
/// cannot force unbounded stream/path/CID state.
pub const max_streams_per_connection: u64 = 4096;
/// Largest QUIC multipath path identifier we accept (draft-ietf-quic-multipath-21).
pub const max_supported_path_id: u32 = 255;
/// Hard cap on the `active_connection_id_limit` we honour from the peer.
pub const max_supported_active_connection_id_limit: u64 = 16;
/// Maximum unique (stream_id, offset) pairs we remember for STREAM_DATA_BLOCKED
/// dedupe before refusing to track more.
pub const max_tracked_stream_data_blocked: usize = 8192;
/// Upper bound on `initial_max_data` we accept from peer transport params.
pub const max_initial_connection_receive_window: u64 = default_connection_receive_window;
/// Upper bound on `initial_max_stream_data_*` we accept from peer transport params.
pub const max_initial_stream_receive_window: u64 = recv_stream_mod.default_max_buffered_span;

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
fn debugFrames() ?*const anyopaque {
    return getenv("NULLQ_DEBUG_FRAMES");
}

/// One out-of-order CRYPTO fragment held in `crypto_pending[lvl]`
/// until enough lower-offset bytes have arrived for it to be
/// delivered to TLS via `provideQuicData`.
pub const CryptoChunk = struct {
    offset: u64,
    /// Allocator-owned bytes. Freed when delivered or on `deinit`.
    data: []u8,
};

/// One CRYPTO fragment that has been written into a sent packet and is
/// awaiting acknowledgement. Tracks the packet number it rode in so the
/// ACK / loss path can match it back to a retransmission queue.
pub const SentCryptoChunk = struct {
    pn: u64,
    offset: u64,
    /// Allocator-owned bytes. Freed on ACK or moved back to
    /// `crypto_retx` on loss.
    data: []u8,
};

/// One peer-issued connection ID stashed from a NEW_CONNECTION_ID
/// frame (RFC 9000 §19.15).
pub const IssuedCid = struct {
    path_id: u32 = 0,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
};

/// Outgoing CONNECTION_CLOSE intent.
pub const ConnectionCloseInfo = struct {
    is_transport: bool,
    error_code: u64,
    frame_type: u64 = 0,
    reason: []const u8 = &.{},
};

/// Origin of a connection-close event surfaced through `nextEvent`.
pub const CloseSource = enum {
    local,
    peer,
    idle_timeout,
    stateless_reset,
    version_negotiation,
};

/// QUIC distinguishes transport-level (RFC 9000 §20.1) from application-level
/// (RFC 9000 §20.2) errors; this enum tags which space `error_code` lives in.
pub const CloseErrorSpace = enum {
    transport,
    application,
};

/// High-level connection lifecycle state — RFC 9000 §10 (closing/draining).
pub const CloseState = enum {
    open,
    closing,
    draining,
    closed,
};

/// Maximum length of a CONNECTION_CLOSE reason phrase we will record/emit.
pub const max_close_reason_len: usize = 256;

/// Snapshot of a close event delivered to the embedder via `nextEvent`.
/// Captures source, error space/code and (optionally) the wire-level frame
/// type that triggered the close. RFC 9000 §10.
pub const CloseEvent = struct {
    source: CloseSource,
    error_space: CloseErrorSpace,
    error_code: u64,
    frame_type: u64 = 0,
    reason: []const u8 = &.{},
    reason_truncated: bool = false,
    at_us: ?u64 = null,
    draining_deadline_us: ?u64 = null,
};

/// Tagged-union of all connection-level events the embedder polls via `nextEvent`.
/// Each variant carries enough context for the embedder to react without re-querying
/// Connection state.
pub const ConnectionEvent = union(enum) {
    close: CloseEvent,
    flow_blocked: FlowBlockedInfo,
    connection_ids_needed: ConnectionIdReplenishInfo,
    datagram_acked: DatagramSendEvent,
    datagram_lost: DatagramSendEvent,
};

/// Whether a flow-control block was hit on the local side or reported by the peer.
pub const FlowBlockedSource = event_queue_mod.FlowBlockedSource;
/// Which flow-control axis ran out of credit — connection data, per-stream data,
/// or stream-count (RFC 9000 §4 / §19.12-§19.14).
pub const FlowBlockedKind = event_queue_mod.FlowBlockedKind;
/// One flow-control block event delivered to the embedder via `nextEvent`. Carries
/// the limit that was hit and (for stream-data) which stream tripped it.
pub const FlowBlockedInfo = event_queue_mod.FlowBlockedInfo;
/// Maximum buffered FlowBlockedInfo events before older entries are dropped.
pub const max_flow_blocked_events: usize = event_queue_mod.max_flow_blocked_events;
/// Why the connection is asking the embedder to issue more local connection IDs.
pub const ConnectionIdReplenishReason = event_queue_mod.ConnectionIdReplenishReason;
/// Embedder-visible snapshot of CID-issuance state when the active count drops
/// below the peer's `active_connection_id_limit` (RFC 9000 §5.1.1).
pub const ConnectionIdReplenishInfo = event_queue_mod.ConnectionIdReplenishInfo;
/// Maximum buffered CID replenish events before older entries are dropped.
pub const max_connection_id_events: usize = event_queue_mod.max_connection_id_events;
/// One ACK or loss event for a previously-sent RFC 9221 DATAGRAM frame, returned
/// to the embedder so it can reconcile its outbound queue.
pub const DatagramSendEvent = event_queue_mod.DatagramSendEvent;
/// Maximum buffered datagram ack/loss events before older entries are dropped.
pub const max_datagram_send_events: usize = event_queue_mod.max_datagram_send_events;

const StoredDatagramSendEvent = event_queue_mod.StoredDatagramSendEvent;

const StoredCloseEvent = struct {
    source: CloseSource,
    error_space: CloseErrorSpace,
    error_code: u64,
    frame_type: u64 = 0,
    reason_len: usize = 0,
    reason_truncated: bool = false,
    at_us: ?u64 = null,
    draining_deadline_us: ?u64 = null,
    delivered: bool = false,
};

/// One queued STOP_SENDING frame (RFC 9000 §19.5) with its application error code.
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

/// Embedder-supplied bundle when calling `provideConnectionId`/`provisionPathConnectionId`
/// to install a fresh local CID and its stateless reset token.
pub const ConnectionIdProvision = struct {
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
    retire_prior_to: u64 = 0,
};

/// Snapshot reported when peer-issued CIDs for a path run dry — used to drive
/// PATH_CIDS_BLOCKED frames on the multipath extension.
pub const PathCidsBlockedInfo = struct {
    path_id: u32,
    next_sequence_number: u64,
};

/// One queued PATH_AVAILABLE / PATH_BACKUP frame from draft-ietf-quic-multipath-21.
pub const PendingPathStatus = struct {
    path_id: u32,
    sequence_number: u64,
    available: bool,
};

/// Header-only descriptor returned from `pollDatagram` — paired with the bytes
/// the caller wrote into the supplied buffer.
pub const OutgoingDatagram = struct {
    len: usize,
    to: ?Address = null,
    path_id: u32 = 0,
};

/// Embedder-visible descriptor for a peer datagram received via `handleDatagram`.
/// `arrived_in_early_data` propagates the 0-RTT-vs-1-RTT distinction up to the app.
pub const IncomingDatagram = struct {
    len: usize,
    arrived_in_early_data: bool = false,
};

const PendingRecvDatagram = struct {
    data: []u8,
    arrived_in_early_data: bool = false,
};

const PendingSendDatagram = struct {
    id: u64,
    data: []u8,
};

/// Distinct timers the Connection drives. The embedder only ever sees one at
/// a time via `nextTimer` — the earliest pending — but the kind disambiguates
/// what `tick` will do when it fires.
pub const TimerKind = enum {
    ack_delay,
    loss_detection,
    pto,
    idle,
    draining,
    path_retirement,
    key_discard,
};

/// One pending timer expiry returned from `nextTimer`. `level` and `path_id`
/// are populated for kinds that are scoped (e.g. key_discard / path_retirement);
/// the embedder treats them as opaque and just feeds `at_us` back into `tick`.
pub const TimerDeadline = struct {
    kind: TimerKind,
    at_us: u64,
    level: ?EncryptionLevel = null,
    path_id: u32 = 0,
};

const LossStats = struct {
    count: u32 = 0,
    bytes_lost: u64 = 0,
    in_flight_bytes_lost: u64 = 0,
    earliest_lost_sent_time_us: ?u64 = null,
    largest_lost_sent_time_us: u64 = 0,
    /// RFC 9002 §7.6.1 mandates that persistent congestion be
    /// determined only from ack-eliciting packets. We therefore
    /// track the time bounds of the *ack-eliciting* lost subset
    /// separately so the unfiltered counters above stay usable
    /// for cwnd reduction (which doesn't need the filter).
    ack_eliciting_count: u32 = 0,
    earliest_ack_eliciting_lost_sent_time_us: ?u64 = null,
    largest_ack_eliciting_lost_sent_time_us: u64 = 0,

    fn add(self: *LossStats, packet: sent_packets_mod.SentPacket) void {
        self.count += 1;
        self.bytes_lost += packet.bytes;
        if (packet.in_flight) self.in_flight_bytes_lost += packet.bytes;
        if (self.earliest_lost_sent_time_us == null or
            packet.sent_time_us < self.earliest_lost_sent_time_us.?)
        {
            self.earliest_lost_sent_time_us = packet.sent_time_us;
        }
        if (packet.sent_time_us > self.largest_lost_sent_time_us) {
            self.largest_lost_sent_time_us = packet.sent_time_us;
        }
        if (packet.ack_eliciting) {
            self.ack_eliciting_count += 1;
            if (self.earliest_ack_eliciting_lost_sent_time_us == null or
                packet.sent_time_us < self.earliest_ack_eliciting_lost_sent_time_us.?)
            {
                self.earliest_ack_eliciting_lost_sent_time_us = packet.sent_time_us;
            }
            if (packet.sent_time_us > self.largest_ack_eliciting_lost_sent_time_us) {
                self.largest_ack_eliciting_lost_sent_time_us = packet.sent_time_us;
            }
        }
    }
};

/// Tunables governing automatic 1-RTT key updates. Defaults follow the
/// RFC 9001 §6.6 confidentiality / integrity limits and an early proactive
/// rotation point so the connection never has to spend its last legal packet
/// on CONNECTION_CLOSE.
pub const ApplicationKeyUpdateLimits = struct {
    /// RFC 9001 §6.6 gives AES-GCM a 2^23 packet confidentiality limit.
    /// ChaCha20-Poly1305 does not force a lower update point, so the
    /// default uses the cross-suite conservative floor.
    confidentiality_limit: u64 = @as(u64, 1) << 23,
    /// Update slightly before the hard limit so we don't need to spend
    /// the last legal packet on CONNECTION_CLOSE.
    proactive_update_threshold: u64 = (@as(u64, 1) << 23) - 1024,
    /// RFC 9001 §6.6 gives ChaCha20-Poly1305 the strictest invalid-
    /// packet integrity limit among the supported QUIC v1 suites.
    integrity_limit: u64 = @as(u64, 1) << 36,
};

/// Read-only snapshot of 1-RTT key update bookkeeping returned from
/// `applicationKeyUpdateStatus()`. Useful for tests, qlog, and embedders
/// that want to surface key-rotation telemetry.
pub const ApplicationKeyUpdateStatus = struct {
    read_epoch: ?u64 = null,
    read_key_phase: bool = false,
    previous_read_discard_deadline_us: ?u64 = null,
    next_read_epoch_ready: bool = false,
    write_epoch: ?u64 = null,
    write_key_phase: bool = false,
    write_packets_protected: u64 = 0,
    write_update_pending_ack: bool = false,
    next_local_update_after_us: ?u64 = null,
    auth_failures: u64 = 0,
};

/// Tag identifying a qlog event (modeled on draft-ietf-quic-qlog-quic-events).
/// Used when the connection invokes its `qlog_callback` so consumers can route
/// the event without parsing arbitrary strings.
pub const QlogEventName = enum {
    application_read_key_installed,
    application_read_key_updated,
    application_read_key_discard_scheduled,
    application_read_key_discarded,
    application_write_key_installed,
    application_write_key_updated,
    application_write_update_acked,
    aead_confidentiality_limit_reached,
    aead_integrity_limit_reached,
    // -- new richer events (modeled after qlog draft-ietf-quic-qlog-quic-events) --
    /// One-shot event when the connection begins exchanging packets — emitted from
    /// the first call to `bind` for clients (or first authenticated packet for the
    /// server). Carries our role plus the SCID/DCID known at the time.
    connection_started,
    /// Emitted whenever `closeState()` transitions (open → closing → draining → closed).
    connection_state_updated,
    /// Emitted once when peer transport parameters are first decoded and
    /// validation passes.
    parameters_set,
    /// Opt-in (gated by `qlog_packet_events`): every outgoing packet.
    packet_sent,
    /// Opt-in (gated by `qlog_packet_events`): every incoming packet that
    /// we successfully authenticate.
    packet_received,
    /// A datagram or packet rejected before frame dispatch (header decode
    /// failure, AEAD failure, version mismatch, retired DCID, etc).
    packet_dropped,
    /// One or more packets declared lost via RFC 9002 logic.
    loss_detected,
    /// Opt-in (gated by `qlog_packet_events`): each individual lost packet.
    packet_lost,
    /// Congestion-controller phase transition (slow-start | recovery |
    /// application-limited). Emitted on transitions only, not periodically.
    congestion_state_updated,
    /// Snapshot of cwnd / RTT / bytes-in-flight after a meaningful update
    /// (currently emitted once per ack-eliciting ACK on the application
    /// path, which keeps volume bounded without per-packet overhead).
    metrics_updated,
    /// Path validation succeeded — PATH_RESPONSE matched a pending PATH_CHALLENGE.
    migration_path_validated,
    /// Path validation failed (timeout) or the peer abandoned the path.
    migration_path_failed,
    /// Stream lifecycle change (open / half-closed / closed).
    stream_state_updated,
    /// Generic key update notification — covers Initial, Handshake, 1-RTT
    /// installs and rotations beyond the more specific application_*
    /// variants above. Currently emitted from `installApplicationSecret`
    /// and `promoteApplicationReadKeys` callers as a duplicate of those
    /// finer-grained events to give a uniform "any key changed" stream.
    key_updated,
};

/// QUIC packet type as it appears in qlog `packet_sent` / `packet_received` /
/// `packet_lost` events.
pub const QlogPacketKind = enum {
    initial,
    handshake,
    zero_rtt,
    one_rtt,
    retry,
    version_negotiation,
};

/// Why a packet was dropped before frame dispatch — populates the qlog
/// `packet_dropped` event.
pub const QlogPacketDropReason = enum {
    /// Packet was too short or had a malformed header.
    header_decode_failure,
    /// AEAD authentication failed (key or content mismatch).
    decryption_failure,
    /// Long-header packet for an unsupported QUIC version.
    unsupported_version,
    /// Short-header DCID didn't map to any active local CID.
    unknown_connection_id,
    /// Packet payload exceeded the local `max_udp_payload_size`.
    payload_too_large,
    /// Stateless reset detected (the rest of the datagram is dropped).
    stateless_reset,
    /// Packet arrived after the keys for its level were dropped.
    keys_unavailable,
    /// Other / unspecified.
    other,
};

/// Packet number space tag carried in qlog packet/loss events.
pub const QlogPnSpace = enum {
    initial,
    handshake,
    application,
};

/// Stream lifecycle state reported via the qlog `stream_state_updated` event.
pub const QlogStreamState = enum {
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset,
};

/// Congestion-controller phase reported via qlog `congestion_state_updated`.
pub const QlogCongestionState = enum {
    slow_start,
    recovery,
    application_limited,
    congestion_avoidance,
};

/// Why a packet was declared lost — populates qlog `loss_detected` /
/// `packet_lost` events. Mirrors RFC 9002 §6 loss detection branches.
pub const QlogLossReason = enum {
    /// RFC 9002 §6.1.1 packet-threshold loss detection.
    packet_threshold,
    /// RFC 9002 §6.1.2 time-threshold loss detection.
    time_threshold,
    /// PTO probe — RFC 9002 §6.2 declared the leading ack-eliciting
    /// packet lost so a probe could go out.
    pto_probe,
};

/// Optional qlog event payload. Existing variants only populate the
/// previous fields; new variants additionally fill the per-event
/// fields below. Callers should branch on `name` and read only the
/// fields documented for that variant.
pub const QlogEvent = struct {
    name: QlogEventName,
    at_us: u64 = 0,
    level: EncryptionLevel = .application,
    key_epoch: ?u64 = null,
    key_phase: ?bool = null,
    packet_number: ?u64 = null,
    discard_deadline_us: ?u64 = null,
    details: []const u8 = &.{},

    // -- fields populated by new event variants ----------------------------
    /// Role and connection-id triple — populated by `connection_started`.
    role: ?Role = null,
    local_scid: ?ConnectionId = null,
    peer_scid: ?ConnectionId = null,
    /// Old/new state for `connection_state_updated`.
    old_state: ?CloseState = null,
    new_state: ?CloseState = null,
    /// Per-packet metadata used by packet_sent/packet_received/packet_lost.
    pn_space: ?QlogPnSpace = null,
    packet_kind: ?QlogPacketKind = null,
    packet_size: ?u32 = null,
    frames_summary: u32 = 0,
    drop_reason: ?QlogPacketDropReason = null,
    /// Loss-detection counts (loss_detected).
    lost_count: ?u32 = null,
    bytes_lost: ?u64 = null,
    loss_reason: ?QlogLossReason = null,
    /// Path-validation outcome (migration_path_*) and stream lifecycle.
    path_id: ?u32 = null,
    stream_id: ?u64 = null,
    stream_state: ?QlogStreamState = null,
    /// Congestion / RTT snapshot — congestion_state_updated + metrics_updated.
    cwnd: ?u64 = null,
    bytes_in_flight: ?u64 = null,
    ssthresh: ?u64 = null,
    smoothed_rtt_us: ?u64 = null,
    rtt_var_us: ?u64 = null,
    min_rtt_us: ?u64 = null,
    latest_rtt_us: ?u64 = null,
    pacing_rate: ?u64 = null,
    congestion_state: ?QlogCongestionState = null,
    /// Top-level numeric copy of the most relevant peer transport parameters.
    /// Filled only by `parameters_set`.
    peer_idle_timeout_ms: ?u64 = null,
    peer_max_udp_payload_size: ?u64 = null,
    peer_initial_max_data: ?u64 = null,
    peer_initial_max_streams_bidi: ?u64 = null,
    peer_initial_max_streams_uni: ?u64 = null,
    peer_active_connection_id_limit: ?u64 = null,
    peer_max_ack_delay_ms: ?u64 = null,
    peer_max_datagram_frame_size: ?u64 = null,
};

/// Embedder-supplied qlog sink. The Connection synchronously calls this with
/// each emitted `QlogEvent`; the callback must not call back into the same
/// Connection.
pub const QlogCallback = *const fn (user_data: ?*anyopaque, event: QlogEvent) void;

const ApplicationKeyEpoch = struct {
    material: SecretMaterial,
    keys: PacketKeys,
    key_phase: bool = false,
    epoch: u64 = 0,
    installed_at_us: u64 = 0,
    packets_protected: u64 = 0,
    discard_deadline_us: ?u64 = null,
    acked: bool = false,
};

const ApplicationReadKeySlot = enum {
    current,
    previous,
    next,
};

const ApplicationOpenResult = struct {
    opened: short_packet_mod.Open1RttResult,
    slot: ApplicationReadKeySlot,
};

/// Fixed-size CRYPTO frame buffer per encryption level. The
/// handshake fits comfortably in 16 KiB even for large cert chains;
/// we'll revisit (and bound via `SSL_quic_max_handshake_flight_len`)
/// in Phase 5.
pub const CryptoBuffer = struct {
    buf: [16384]u8 = undefined,
    len: usize = 0,

    /// Append bytes BoringSSL produced via `add_handshake_data`.
    /// Returns `error.InboxOverflow` if the fixed-size buffer is full.
    pub fn append(self: *CryptoBuffer, data: []const u8) !void {
        if (self.len + data.len > self.buf.len) return error.InboxOverflow;
        @memcpy(self.buf[self.len .. self.len + data.len], data);
        self.len += data.len;
    }

    /// Returns the buffered bytes and resets the buffer to empty. The
    /// returned slice aliases the internal storage and is valid only
    /// until the next `append`.
    pub fn drain(self: *CryptoBuffer) []const u8 {
        const out = self.buf[0..self.len];
        self.len = 0;
        return out;
    }
};

/// Per-QUIC-connection state machine and embedder-facing API.
///
/// The Connection owns the TLS handshake (`inner`), packet number spaces,
/// flow-control accounting, the stream table, path set, congestion controller,
/// loss detector, and timers. Embedders feed peer datagrams in through
/// `handleDatagram` / `handleClientInitial` / `handleStatelessReset`, drive
/// time forward with `tick`, pull outgoing datagrams via `pollDatagram`, and
/// observe lifecycle changes through `nextEvent` / `nextTimer`.
pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    /// Owned SSL handle from the caller-provided `boringssl.tls.Context`.
    /// The Context outlives the Connection (caller-managed).
    inner: boringssl.tls.Conn,

    /// Inbox of CRYPTO frame bytes received from the peer at each
    /// encryption level. The peer's `add_handshake_data` callback
    /// appends here; `advance` drains via `provideQuicData`.
    inbox: [4]CryptoBuffer = .{ .{}, .{}, .{}, .{} },

    /// Per-level secret bookkeeping. Updated by the
    /// `set_read_secret` / `set_write_secret` callbacks.
    levels: [4]PerLevelState = .{ .{}, .{}, .{}, .{} },

    /// Peer pointer for the in-process mock transport tests; real
    /// deployments don't set this (they ship CRYPTO bytes via QUIC
    /// packets through a `transport.Transport`, which lives in
    /// Phase 6).
    peer: ?*Connection = null,

    /// Last alert byte received via the `send_alert` callback, if
    /// any. Non-null = handshake should be torn down.
    alert: ?u8 = null,

    /// Pending hostname for client connections; applied during
    /// `bind` because we can't safely call `setHostname` before
    /// the Connection has a stable address.
    pending_hostname: ?[:0]const u8 = null,

    /// Connection-level packet-number bookkeeping for Initial and
    /// Handshake (RFC 9000 §12.3). Application PN spaces live in
    /// `paths` so multipath can allocate one space per active path.
    pn_spaces: [2]PnSpace = .{ .{}, .{} },
    /// Sent-packet tracker for connection-level PN spaces. Application
    /// packets live in `paths.primary().sent`; Initial/Handshake stay
    /// here because QUIC multipath only widens the Application space.
    sent: [2]SentPacketTracker = .{ .{}, .{} },
    /// Multipath-capable Application path set. Path id 0 is always the
    /// initial path and owns Application PN/ACK/sent/RTT/congestion.
    paths: PathSet = .{},
    multipath_enabled: bool = false,
    local_max_path_id: u32 = 0,
    peer_max_path_id: u32 = 0,
    peer_paths_blocked_at: ?u32 = null,
    peer_path_cids_blocked_path_id: ?u32 = null,
    peer_path_cids_blocked_next_sequence: u64 = 0,
    current_incoming_path_id: u32 = 0,
    current_incoming_addr: ?Address = null,
    last_authenticated_path_id: ?u32 = null,
    poll_addr_override: ?Address = null,
    /// PTO backoff count for Initial and Handshake. Application PTO
    /// backoff is per-path in `PathState.pto_count`. Reset when an
    /// ACK newly acknowledges ack-eliciting data in that space.
    pto_count: [2]u32 = .{ 0, 0 },
    /// PING probes requested by PTO for Initial and Handshake when no
    /// retransmittable data is immediately available.
    pending_ping: [2]bool = .{ false, false },

    /// Per-encryption-level outbox of CRYPTO bytes the TLS bridge
    /// has handed us via `add_handshake_data`. `poll` packs these
    /// into outgoing CRYPTO frames at the matching level. Replaces
    /// the Phase-4 in-process `peer.inbox` shortcut.
    outbox: [4]CryptoBuffer = .{ .{}, .{}, .{}, .{} },
    /// Highest CRYPTO offset we've handed to the peer at each level.
    /// Used to set the `offset` field on the next CRYPTO frame.
    crypto_send_offset: [4]u64 = .{ 0, 0, 0, 0 },
    /// Highest CRYPTO offset we've fed back to BoringSSL at each
    /// level (one past the last byte of in-order data delivered via
    /// `provideQuicData`).
    crypto_recv_offset: [4]u64 = .{ 0, 0, 0, 0 },
    /// Per-level reassembly queue for CRYPTO frames received out
    /// of order. Each entry holds bytes whose `offset` is strictly
    /// greater than `crypto_recv_offset[lvl]`. Drained whenever
    /// `crypto_recv_offset` catches up to the lowest entry.
    /// quic-go (and many real stacks) routinely fragment the
    /// ClientHello into out-of-order CRYPTO frames inside a single
    /// Initial; without reassembly the handshake stalls.
    crypto_pending: [4]std.ArrayList(CryptoChunk) = .{ .empty, .empty, .empty, .empty },
    crypto_pending_bytes: [4]usize = .{ 0, 0, 0, 0 },
    /// CRYPTO bytes that were sent in lost packets and need to be
    /// retransmitted at their original offsets.
    crypto_retx: [4]std.ArrayList(CryptoChunk) = .{ .empty, .empty, .empty, .empty },
    /// CRYPTO bytes currently in sent packets awaiting ACK/loss.
    sent_crypto: [4]std.ArrayList(SentCryptoChunk) = .{ .empty, .empty, .empty, .empty },

    /// Per-stream state, keyed by stream id.
    streams: std.AutoHashMapUnmanaged(u64, *Stream) = .empty,
    /// Monotonic connection-local key for STREAM send bookkeeping.
    /// Wire packet numbers are scoped by packet-number space/path;
    /// SendStream needs one global key to avoid multipath PN collisions.
    next_stream_packet_key: u64 = 0,

    /// Outbound RFC 9221 DATAGRAM payloads waiting to be packed
    /// into 1-RTT packets. Each entry is allocator-owned.
    pending_send_datagrams: std.ArrayList(PendingSendDatagram) = .empty,
    pending_send_datagram_bytes: usize = 0,
    next_datagram_id: u64 = 0,
    /// Inbound DATAGRAMs received but not yet pulled by the app.
    /// Each entry is allocator-owned.
    pending_recv_datagrams: std.ArrayList(PendingRecvDatagram) = .empty,
    pending_recv_datagram_bytes: usize = 0,

    /// DCID we put on outgoing packets (the peer chose this; client
    /// learns it from the server's first Initial SCID, or
    /// NEW_CONNECTION_ID). Zero-length CIDs are valid — `peer_dcid_set`
    /// distinguishes "explicitly empty" from "never set".
    peer_dcid: ConnectionId = .{},
    peer_dcid_set: bool = false,
    /// SCID we identify ourselves with — appears as SCID on outgoing
    /// long-header packets, and the peer puts it (or another CID we
    /// issued) as DCID on every incoming packet. Zero-length is valid.
    local_scid: ConnectionId = .{},
    local_scid_set: bool = false,
    /// Stable Source CID used on Initial, Handshake, and 0-RTT long
    /// headers. Peers can retire CID sequence 0 before the Initial or
    /// Handshake packet spaces are fully quiet, but the long-header SCID
    /// still has to remain the one advertised by the handshake transport
    /// parameter.
    initial_source_cid: ConnectionId = .{},
    initial_source_cid_set: bool = false,
    /// Original DCID used for Initial-key derivation (RFC 9001 §5.2).
    /// Client side: the random DCID it sent on the very first Initial.
    /// Server side: same value, recovered from that incoming Initial.
    initial_dcid: ConnectionId = .{},
    initial_dcid_set: bool = false,
    /// Stable copy of the client's first Initial DCID. If Retry is
    /// accepted, `initial_dcid` changes to the Retry SCID for key
    /// derivation, while this value remains the Original DCID used for
    /// Retry integrity and transport-parameter validation.
    original_initial_dcid: ConnectionId = .{},
    original_initial_dcid_set: bool = false,
    retry_source_cid: ConnectionId = .{},
    retry_source_cid_set: bool = false,
    retry_accepted: bool = false,
    retry_token: std.ArrayList(u8) = .empty,

    /// Cached Initial-level packet keys. Derived once `initial_dcid`
    /// is set; cleared if `initial_dcid` is rotated (e.g. after
    /// receiving a Retry, RFC 9001 §5.2). Direction-specific (server
    /// uses `is_server=true` derivation for write).
    initial_keys_read: ?short_packet_mod.PacketKeys = null,
    initial_keys_write: ?short_packet_mod.PacketKeys = null,

    /// Application key-update lifecycle. QUIC key updates derive new
    /// packet-protection key/IV from "quic ku" while retaining the
    /// original header-protection key. Read side keeps previous/current/next
    /// epochs so delayed old-phase packets survive until the 3x-PTO discard
    /// timer; write side tracks ACK-gating and AEAD packet limits.
    app_read_previous: ?ApplicationKeyEpoch = null,
    app_read_current: ?ApplicationKeyEpoch = null,
    app_read_next: ?ApplicationKeyEpoch = null,
    app_write_current: ?ApplicationKeyEpoch = null,
    app_write_update_pending_ack: bool = false,
    app_next_local_update_after_us: ?u64 = null,
    app_failed_auth_packets: u64 = 0,
    app_key_update_limits: ApplicationKeyUpdateLimits = .{},
    qlog_callback: ?QlogCallback = null,
    qlog_user_data: ?*anyopaque = null,
    /// Opt-in for high-volume per-packet qlog events
    /// (`packet_sent`, `packet_received`, `packet_lost`). Disabled by
    /// default so production callers don't pay for every packet
    /// crossing the boundary.
    qlog_packet_events: bool = false,
    /// Whether `connection_started` has fired yet. Single-shot.
    qlog_started: bool = false,
    /// Last close-state we emitted for `connection_state_updated`.
    qlog_last_state: CloseState = .open,
    /// Whether `parameters_set` fired.
    qlog_params_emitted: bool = false,
    /// Last congestion controller phase emitted (so we don't spam
    /// transitions). `null` means no snapshot has been taken yet.
    qlog_last_congestion_state: ?QlogCongestionState = null,

    // -- cheap aggregate counters used by PathStats --
    /// Total packets we've sent (across all paths/levels).
    qlog_packets_sent: u64 = 0,
    /// Total packets we've successfully received (post-AEAD).
    qlog_packets_received: u64 = 0,
    /// Total packets declared lost.
    qlog_packets_lost: u64 = 0,
    /// Total UDP payload bytes we've sent.
    qlog_bytes_sent: u64 = 0,
    /// Total UDP payload bytes the peer has sent us.
    qlog_bytes_received: u64 = 0,

    /// Local datagram budget for outgoing packets.
    mtu: usize = default_mtu,

    /// Local parameters handed to BoringSSL. Kept here too so ACK
    /// delay and idle timers can use the negotiated local values.
    local_transport_params: TransportParams = .{},
    /// Receive-side connection flow-control limit we have advertised
    /// through transport parameters / MAX_DATA.
    local_max_data: u64 = 0,
    /// Sum of per-stream receive high-water marks the peer has forced.
    peer_sent_stream_data: u64 = 0,
    /// Send-side connection flow-control limit advertised by the peer.
    peer_max_data: u64 = std.math.maxInt(u64),
    /// Sum of new stream bytes we have put on the wire.
    we_sent_stream_data: u64 = 0,
    /// Stream-count limits. `local_*` governs peer-created streams;
    /// `peer_*` governs streams opened through the public API. Unknown
    /// peer limits are permissive until peer transport params arrive.
    local_max_streams_bidi: u64 = 0,
    local_max_streams_uni: u64 = 0,
    peer_max_streams_bidi: u64 = std.math.maxInt(u64),
    peer_max_streams_uni: u64 = std.math.maxInt(u64),
    peer_opened_streams_bidi: u64 = 0,
    peer_opened_streams_uni: u64 = 0,
    local_opened_streams_bidi: u64 = 0,
    local_opened_streams_uni: u64 = 0,
    /// Decoded peer parameters once BoringSSL exposes them.
    cached_peer_transport_params: ?TransportParams = null,
    /// The peer's transport-parameter stateless reset token is bound
    /// to its initial source CID. Register it once; later peer DCID
    /// rotation is driven by NEW_CONNECTION_ID metadata.
    peer_transport_reset_token_installed: bool = false,
    /// Per-connection opt-in for sending queued application bytes in
    /// 0-RTT packets. Session resumption can still happen when this is
    /// false; nullq just waits for 1-RTT before emitting app data.
    early_data_send_enabled: bool = false,
    /// Once BoringSSL reports rejection, every tracked 0-RTT packet is
    /// removed from flight and its STREAM bytes are put back on the
    /// send queue exactly once.
    early_data_rejection_processed: bool = false,

    /// Last send/receive activity on this connection. Zero means no
    /// packet activity has been observed yet.
    last_activity_us: u64 = 0,
    /// Draining-state deadline. Until a richer close state lands, a
    /// non-null value means only the draining timer remains relevant.
    draining_deadline_us: ?u64 = null,

    /// PATH_CHALLENGE token received from the peer that we still
    /// owe a PATH_RESPONSE for. The next outgoing 1-RTT packet
    /// will carry it.
    pending_path_response: ?[8]u8 = null,
    pending_path_response_path_id: u32 = 0,
    pending_path_response_addr: ?Address = null,
    /// PATH_CHALLENGE token we've queued for transmission to start
    /// validating the current path.
    pending_path_challenge: ?[8]u8 = null,
    pending_path_challenge_path_id: u32 = 0,

    /// Peer-issued connection IDs we've stashed via NEW_CONNECTION_ID.
    /// Phase 9 (migration) will pull from this set; for now, the
    /// stash is just bookkeeping (and a place where a peer's
    /// `active_connection_id_limit` violation would surface).
    peer_cids: std.ArrayList(IssuedCid) = .empty,
    /// Locally-issued connection IDs, keyed by path, used to map
    /// incoming short-header DCIDs back to draft multipath path IDs.
    local_cids: std.ArrayList(IssuedCid) = .empty,
    /// CONNECTION_CLOSE we've queued (typically from `close()`); the
    /// next outgoing packet at the highest available encryption
    /// level emits it.
    pending_close: ?ConnectionCloseInfo = null,
    /// Server-only HANDSHAKE_DONE delivery. The frame is ack-eliciting
    /// and must be retransmitted on loss until the client confirms the
    /// handshake.
    pending_handshake_done: bool = false,
    handshake_done_queued_once: bool = false,
    /// True once we've sent or received a CONNECTION_CLOSE frame, or
    /// an idle timeout has entered draining.
    closed: bool = false,
    /// Sticky close/error status for embedders. The stored event keeps
    /// offsets into `close_reason_buf` so `Connection` can be moved before
    /// bind/init without leaving a self-referential slice behind.
    close_event: ?StoredCloseEvent = null,
    close_reason_buf: [max_close_reason_len]u8 = undefined,
    flow_blocked_events: event_queue_mod.EventQueue(FlowBlockedInfo, max_flow_blocked_events) = .{},
    connection_id_events: event_queue_mod.EventQueue(ConnectionIdReplenishInfo, max_connection_id_events) = .{},
    datagram_send_events: event_queue_mod.EventQueue(StoredDatagramSendEvent, max_datagram_send_events) = .{},
    /// STOP_SENDING frames we owe the peer (one per stream id).
    pending_stop_sending: std.ArrayList(StopSendingItem) = .empty,
    /// MAX_STREAM_DATA frames we owe after the application drains
    /// receive buffers. Coalesced by stream id.
    pending_max_stream_data: std.ArrayList(MaxStreamDataItem) = .empty,
    /// MAX_DATA value to advertise after application reads. Null
    /// means no connection-level window update is currently queued.
    pending_max_data: ?u64 = null,
    pending_max_streams_bidi: ?u64 = null,
    pending_max_streams_uni: ?u64 = null,
    pending_data_blocked: ?u64 = null,
    pending_stream_data_blocked: std.ArrayList(frame_types.StreamDataBlocked) = .empty,
    pending_streams_blocked_bidi: ?u64 = null,
    pending_streams_blocked_uni: ?u64 = null,
    local_data_blocked_at: ?u64 = null,
    local_stream_data_blocked: std.ArrayList(frame_types.StreamDataBlocked) = .empty,
    local_streams_blocked_bidi: ?u64 = null,
    local_streams_blocked_uni: ?u64 = null,
    peer_data_blocked_at: ?u64 = null,
    peer_stream_data_blocked: std.ArrayList(frame_types.StreamDataBlocked) = .empty,
    peer_streams_blocked_bidi: ?u64 = null,
    peer_streams_blocked_uni: ?u64 = null,
    /// Bytes the application has drained from all receive streams.
    recv_stream_bytes_read: u64 = 0,
    /// Server/client-issued CIDs to advertise to the peer. This is
    /// enough for migration and multipath probes to obtain spare CIDs.
    pending_new_connection_ids: std.ArrayList(PendingNewConnectionId) = .empty,
    pending_retire_connection_ids: std.ArrayList(frame_types.RetireConnectionId) = .empty,
    pending_path_abandons: std.ArrayList(frame_types.PathAbandon) = .empty,
    pending_path_statuses: std.ArrayList(PendingPathStatus) = .empty,
    pending_path_new_connection_ids: std.ArrayList(frame_types.PathNewConnectionId) = .empty,
    pending_path_retire_connection_ids: std.ArrayList(frame_types.PathRetireConnectionId) = .empty,
    pending_max_path_id: ?u32 = null,
    pending_paths_blocked: ?u32 = null,
    pending_path_cids_blocked: ?frame_types.PathCidsBlocked = null,

    /// Build a client-side `Connection`. `tls_ctx` must be a
    /// client-mode `boringssl.tls.Context` and stays caller-owned;
    /// `server_name` becomes the SNI hostname. The returned
    /// `Connection` must be `bind()`ed once it lives at its final
    /// memory address (`bind` stashes `&self` in SSL ex-data, so
    /// it has to happen post-move).
    pub fn initClient(
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
        server_name: [:0]const u8,
    ) !Connection {
        var conn: Connection = .{
            .allocator = allocator,
            .role = .client,
            .inner = try tls_ctx.newQuicClient(),
            .pending_hostname = server_name,
        };
        errdefer conn.inner.deinit();
        try conn.paths.ensurePrimary(allocator, .{ .max_datagram_size = default_mtu });
        return conn;
    }

    /// Build a server-side `Connection`. `tls_ctx` must be a
    /// server-mode `boringssl.tls.Context` and stays caller-owned.
    /// Like `initClient`, `bind()` must be called once the
    /// `Connection` lives at its final memory address.
    pub fn initServer(
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
    ) !Connection {
        var conn: Connection = .{
            .allocator = allocator,
            .role = .server,
            .inner = try tls_ctx.newQuicServer(),
        };
        errdefer conn.inner.deinit();
        try conn.paths.ensurePrimary(allocator, .{ .max_datagram_size = default_mtu });
        return conn;
    }

    /// Bind this Connection to its underlying SSL. Must be called
    /// once the Connection sits at its final stable address (after
    /// any `return` copies). Installs the `tls.quic.Method`
    /// callbacks and stashes `*Connection` in SSL ex-data so the
    /// callbacks can recover the right state.
    ///
    /// Calling `advance` before `bind` is undefined.
    pub fn bind(self: *Connection) !void {
        try self.inner.setUserData(self);
        try self.inner.setQuicMethod(&method);
        if (self.pending_hostname) |h| {
            try self.inner.setHostname(h);
            self.pending_hostname = null;
        }
        // For clients, `bind` is the moment we kick off the handshake;
        // emit `connection_started` here. Servers fire it from
        // `handleInitial` once they have a peer SCID.
        if (self.role == .client) self.emitConnectionStartedOnce();
    }

    /// Free all per-connection allocations, including stream
    /// buffers, queued frames, packet-number space state, and the
    /// underlying `boringssl.tls.Conn`. After this call the
    /// `Connection` is `undefined` and must not be reused.
    pub fn deinit(self: *Connection) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            s.send.deinit();
            s.recv.deinit();
            self.allocator.destroy(s);
        }
        self.streams.deinit(self.allocator);
        for (self.pending_send_datagrams.items) |item| self.allocator.free(item.data);
        for (self.pending_recv_datagrams.items) |item| self.allocator.free(item.data);
        self.pending_send_datagrams.deinit(self.allocator);
        self.pending_recv_datagrams.deinit(self.allocator);
        for (&self.sent) |*tracker| {
            var i: u32 = 0;
            while (i < tracker.count) : (i += 1) {
                tracker.packets[i].deinit(self.allocator);
            }
        }
        self.paths.deinit(self.allocator);
        for (&self.crypto_pending) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        for (&self.crypto_retx) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        for (&self.sent_crypto) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        self.peer_cids.deinit(self.allocator);
        self.local_cids.deinit(self.allocator);
        self.retry_token.deinit(self.allocator);
        self.pending_stop_sending.deinit(self.allocator);
        self.pending_max_stream_data.deinit(self.allocator);
        self.pending_stream_data_blocked.deinit(self.allocator);
        self.local_stream_data_blocked.deinit(self.allocator);
        self.peer_stream_data_blocked.deinit(self.allocator);
        self.pending_new_connection_ids.deinit(self.allocator);
        self.pending_retire_connection_ids.deinit(self.allocator);
        self.pending_path_abandons.deinit(self.allocator);
        self.pending_path_statuses.deinit(self.allocator);
        self.pending_path_new_connection_ids.deinit(self.allocator);
        self.pending_path_retire_connection_ids.deinit(self.allocator);
        self.inner.deinit();
        self.* = undefined;
    }

    /// Encode `params` (RFC 9000 §18 + RFC 9221) and hand the blob
    /// to BoringSSL for transmission inside CRYPTO frames during the
    /// handshake. Must be called before the first `advance`.
    pub fn setTransportParams(self: *Connection, params: TransportParams) !void {
        const local = try normalizeLocalTransportParams(params);
        var buf: [1024]u8 = undefined;
        const n = try local.encode(&buf);
        self.local_transport_params = local;
        self.applyLocalFlowTransportParams();
        if (local.initial_max_path_id) |max_path_id| {
            self.local_max_path_id = max_path_id;
            self.multipath_enabled = true;
        } else {
            self.local_max_path_id = 0;
        }
        try self.inner.setQuicTransportParams(buf[0..n]);
    }

    fn normalizeLocalTransportParams(params: TransportParams) transport_params_mod.Error!TransportParams {
        var local = params;
        if (local.max_udp_payload_size < min_quic_udp_payload_size) return error.InvalidValue;
        if (local.initial_max_streams_bidi > max_stream_count_limit or
            local.initial_max_streams_uni > max_stream_count_limit)
        {
            return error.InvalidValue;
        }
        if (local.initial_max_streams_bidi > max_streams_per_connection or
            local.initial_max_streams_uni > max_streams_per_connection)
        {
            return error.InvalidValue;
        }
        if (local.active_connection_id_limit > max_supported_active_connection_id_limit) {
            return error.InvalidValue;
        }
        if (local.initial_max_path_id) |max_path_id| {
            if (max_path_id > max_supported_path_id) return error.InvalidValue;
        }
        if (local.initial_max_data > max_initial_connection_receive_window) {
            return error.InvalidValue;
        }
        if (local.initial_max_stream_data_bidi_local > max_initial_stream_receive_window or
            local.initial_max_stream_data_bidi_remote > max_initial_stream_receive_window or
            local.initial_max_stream_data_uni > max_initial_stream_receive_window)
        {
            return error.InvalidValue;
        }
        if (local.max_udp_payload_size > max_supported_udp_payload_size) {
            local.max_udp_payload_size = max_supported_udp_payload_size;
        }
        if (local.max_datagram_frame_size > max_supported_udp_payload_size) {
            local.max_datagram_frame_size = max_supported_udp_payload_size;
        }
        return local;
    }

    fn applyLocalFlowTransportParams(self: *Connection) void {
        const params = self.local_transport_params;
        self.local_max_data = params.initial_max_data;
        self.local_max_streams_bidi = params.initial_max_streams_bidi;
        self.local_max_streams_uni = params.initial_max_streams_uni;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            s.recv_max_data = self.initialRecvStreamLimit(s.id);
        }
    }

    /// Escape hatch: set already-encoded transport-parameter bytes.
    /// Useful for testing the decoder against fixtures.
    pub fn setRawTransportParams(self: *Connection, params: []const u8) !void {
        try self.inner.setQuicTransportParams(params);
    }

    /// Decode the peer's transport parameters once the handshake has
    /// produced them (typically available right after Initial keys
    /// are derived on the peer's first flight). Returns null until
    /// the peer's blob is available.
    pub fn peerTransportParams(self: *Connection) !?TransportParams {
        const blob = self.inner.peerQuicTransportParams() orelse return null;
        const params = try transport_params_mod.Params.decode(blob);
        self.cached_peer_transport_params = params;
        if (params.initial_max_path_id) |max_path_id| {
            self.peer_max_path_id = @min(max_path_id, max_supported_path_id);
            self.multipath_enabled = true;
        }
        self.validatePeerTransportLimits();
        if (self.pending_close != null or self.closed) return params;
        self.validatePeerTransportRole();
        if (self.pending_close != null or self.closed) return params;
        try self.installPeerTransportStatelessResetToken();
        self.validatePeerTransportConnectionIds();
        return params;
    }

    /// Client-only: install a previously-captured TLS session before
    /// the first handshake step so BoringSSL can attempt resumption.
    pub fn setSession(self: *Connection, session: Session) !void {
        if (self.role != .client) return error.NotClientContext;
        try self.inner.setSession(session);
    }

    /// Per-connection 0-RTT toggle. This deliberately gates nullq's
    /// packet scheduler as well as BoringSSL, so early application data
    /// is only sent after the caller opts in for this connection.
    pub fn setEarlyDataEnabled(self: *Connection, enabled: bool) void {
        self.early_data_send_enabled = enabled;
        self.inner.setEarlyDataEnabled(enabled);
    }

    /// Snapshot of BoringSSL's 0-RTT state machine: whether early
    /// data was attempted, accepted, or rejected, plus the rejection
    /// reason if any. Useful after the handshake finishes for
    /// metrics and assertions.
    pub fn earlyDataStatus(self: *Connection) EarlyDataStatus {
        return self.inner.earlyDataStatus();
    }

    /// Free-form reason string from BoringSSL describing why 0-RTT
    /// was rejected. Empty when 0-RTT was accepted or not attempted.
    pub fn earlyDataReason(self: *Connection) []const u8 {
        return self.inner.earlyDataReason();
    }

    /// Server-only: install the QUIC 0-RTT replay context (RFC 9001
    /// §4.6.1). Required when 0-RTT is enabled on the server.
    pub fn setEarlyDataContext(self: *Connection, ctx: []const u8) !void {
        if (self.role != .server) return error.NotServerContext;
        if (ctx.len == 0) return Error.EmptyEarlyDataContext;
        try self.inner.setQuicEarlyDataContext(ctx);
    }

    /// Server convenience: build and install nullq's canonical replay
    /// context from current transport parameters plus app-owned bytes.
    /// The returned digest is what callers should remember beside the
    /// issued ticket if they keep their own ticket metadata.
    pub fn setEarlyDataContextForParams(
        self: *Connection,
        params: TransportParams,
        alpn: []const u8,
        application_context: []const u8,
    ) !early_data_context_mod.Digest {
        const digest = early_data_context_mod.build(.{
            .transport_params = params,
            .alpn = alpn,
            .application_context = application_context,
        });
        try self.setEarlyDataContext(&digest);
        return digest;
    }

    /// True once the TLS-1.3 handshake has emitted Finished and
    /// the server has issued HANDSHAKE_DONE. Streams and DATAGRAMs
    /// queued before this can still flow at 0-RTT level if early
    /// data was negotiated; everything else waits.
    pub fn handshakeDone(self: *Connection) bool {
        return self.inner.handshakeDone();
    }

    fn queueHandshakeDoneIfReady(self: *Connection) void {
        if (self.role != .server) return;
        if (!self.inner.handshakeDone()) return;
        if (self.handshake_done_queued_once) return;
        self.pending_handshake_done = true;
        self.handshake_done_queued_once = true;
    }

    /// True if BoringSSL is in QUIC mode (i.e. `tls.quic.Method`
    /// callbacks are wired up). Should always be true after `init*`.
    /// Useful as a sanity check during embedder bring-up.
    pub fn isQuic(self: *Connection) bool {
        return self.inner.isQuic();
    }

    /// Install an opt-in qlog-style callback for security/lifecycle
    /// diagnostics. nullq never writes logs on its own; embedders can
    /// translate these events into qlog JSON, metrics, or test probes.
    pub fn setQlogCallback(
        self: *Connection,
        callback: ?QlogCallback,
        user_data: ?*anyopaque,
    ) void {
        self.qlog_callback = callback;
        self.qlog_user_data = user_data;
    }

    /// Enable or disable per-packet qlog events
    /// (`packet_sent`, `packet_received`, `packet_lost`). High-volume —
    /// keep off in production unless actively debugging.
    pub fn setQlogPacketEvents(self: *Connection, enabled: bool) void {
        self.qlog_packet_events = enabled;
    }

    fn emitQlog(self: *Connection, event: QlogEvent) void {
        if (self.qlog_callback) |callback| callback(self.qlog_user_data, event);
    }

    fn qlogPnSpaceFromLevel(lvl: EncryptionLevel) QlogPnSpace {
        return switch (lvl) {
            .initial => .initial,
            .handshake => .handshake,
            .early_data, .application => .application,
        };
    }

    fn qlogPacketKindFromLevel(lvl: EncryptionLevel) QlogPacketKind {
        return switch (lvl) {
            .initial => .initial,
            .handshake => .handshake,
            .early_data => .zero_rtt,
            .application => .one_rtt,
        };
    }

    /// One-shot `connection_started` emitter. Called from `bind` for
    /// clients and from the handshake-progress callback for servers.
    fn emitConnectionStartedOnce(self: *Connection) void {
        if (self.qlog_callback == null or self.qlog_started) return;
        self.qlog_started = true;
        self.emitQlog(.{
            .name = .connection_started,
            .role = self.role,
            .local_scid = if (self.local_scid_set) self.local_scid else null,
            .peer_scid = if (self.peer_dcid_set) self.peer_dcid else null,
        });
    }

    /// Re-evaluate close state and emit a `connection_state_updated`
    /// if it changed since the last emit.
    fn emitConnectionStateIfChanged(self: *Connection) void {
        if (self.qlog_callback == null) return;
        const new_state = self.closeState();
        if (new_state == self.qlog_last_state) return;
        const old = self.qlog_last_state;
        self.qlog_last_state = new_state;
        self.emitQlog(.{
            .name = .connection_state_updated,
            .old_state = old,
            .new_state = new_state,
        });
    }

    /// Emit `parameters_set` when the peer's transport parameters are
    /// first decoded and accepted.
    fn emitPeerParametersSet(self: *Connection) void {
        if (self.qlog_callback == null or self.qlog_params_emitted) return;
        const params = self.cached_peer_transport_params orelse return;
        self.qlog_params_emitted = true;
        self.emitQlog(.{
            .name = .parameters_set,
            .peer_idle_timeout_ms = params.max_idle_timeout_ms,
            .peer_max_udp_payload_size = params.max_udp_payload_size,
            .peer_initial_max_data = params.initial_max_data,
            .peer_initial_max_streams_bidi = params.initial_max_streams_bidi,
            .peer_initial_max_streams_uni = params.initial_max_streams_uni,
            .peer_active_connection_id_limit = params.active_connection_id_limit,
            .peer_max_ack_delay_ms = params.max_ack_delay_ms,
            .peer_max_datagram_frame_size = params.max_datagram_frame_size,
        });
    }

    fn emitPacketSent(
        self: *Connection,
        lvl: EncryptionLevel,
        pn: u64,
        size: u32,
        frames_count: u32,
    ) void {
        if (!self.qlog_packet_events or self.qlog_callback == null) return;
        self.emitQlog(.{
            .name = .packet_sent,
            .level = lvl,
            .pn_space = qlogPnSpaceFromLevel(lvl),
            .packet_kind = qlogPacketKindFromLevel(lvl),
            .packet_number = pn,
            .packet_size = size,
            .frames_summary = frames_count,
        });
    }

    fn emitPacketReceived(
        self: *Connection,
        lvl: EncryptionLevel,
        pn: u64,
        size: u32,
        frames_count: u32,
    ) void {
        if (!self.qlog_packet_events or self.qlog_callback == null) return;
        self.emitQlog(.{
            .name = .packet_received,
            .level = lvl,
            .pn_space = qlogPnSpaceFromLevel(lvl),
            .packet_kind = qlogPacketKindFromLevel(lvl),
            .packet_number = pn,
            .packet_size = size,
            .frames_summary = frames_count,
        });
    }

    fn emitPacketDropped(
        self: *Connection,
        lvl: ?EncryptionLevel,
        size: u32,
        reason: QlogPacketDropReason,
    ) void {
        if (self.qlog_callback == null) return;
        self.emitQlog(.{
            .name = .packet_dropped,
            .level = lvl orelse .application,
            .pn_space = if (lvl) |l| qlogPnSpaceFromLevel(l) else null,
            .packet_kind = if (lvl) |l| qlogPacketKindFromLevel(l) else null,
            .packet_size = size,
            .drop_reason = reason,
        });
    }

    fn emitLossDetected(
        self: *Connection,
        lvl: EncryptionLevel,
        stats: LossStats,
        reason: QlogLossReason,
    ) void {
        if (self.qlog_callback == null or stats.count == 0) return;
        self.emitQlog(.{
            .name = .loss_detected,
            .level = lvl,
            .pn_space = qlogPnSpaceFromLevel(lvl),
            .lost_count = stats.count,
            .bytes_lost = stats.bytes_lost,
            .loss_reason = reason,
        });
    }

    fn emitPacketLost(
        self: *Connection,
        lvl: EncryptionLevel,
        pn: u64,
        bytes: u32,
        reason: QlogLossReason,
    ) void {
        if (!self.qlog_packet_events or self.qlog_callback == null) return;
        self.emitQlog(.{
            .name = .packet_lost,
            .level = lvl,
            .pn_space = qlogPnSpaceFromLevel(lvl),
            .packet_number = pn,
            .packet_size = bytes,
            .loss_reason = reason,
        });
    }

    /// Compute the current congestion phase for the primary application
    /// path and emit `congestion_state_updated` if it changed.
    fn emitCongestionStateIfChanged(self: *Connection, now_us: u64) void {
        if (self.qlog_callback == null) return;
        const path = self.primaryPath();
        const cc = &path.path.cc;
        const new_state: QlogCongestionState = blk: {
            if (cc.recovery_start_time_us != null and now_us <= cc.recovery_start_time_us.?) {
                break :blk .recovery;
            }
            if (cc.isSlowStart()) break :blk .slow_start;
            break :blk .congestion_avoidance;
        };
        if (self.qlog_last_congestion_state) |prev| {
            if (prev == new_state) return;
        }
        self.qlog_last_congestion_state = new_state;
        self.emitQlog(.{
            .name = .congestion_state_updated,
            .at_us = now_us,
            .congestion_state = new_state,
            .cwnd = cc.cwnd,
            .ssthresh = cc.ssthresh,
            .bytes_in_flight = path.sent.bytes_in_flight,
        });
    }

    /// Emit `metrics_updated` with a snapshot of the primary path's
    /// congestion / RTT counters.
    fn emitMetricsSnapshot(self: *Connection, now_us: u64) void {
        if (self.qlog_callback == null) return;
        const path = self.primaryPath();
        const cc = &path.path.cc;
        const rtt = &path.path.rtt;
        self.emitQlog(.{
            .name = .metrics_updated,
            .at_us = now_us,
            .cwnd = cc.cwnd,
            .ssthresh = cc.ssthresh,
            .bytes_in_flight = path.sent.bytes_in_flight,
            .smoothed_rtt_us = rtt.smoothed_rtt_us,
            .rtt_var_us = rtt.rtt_var_us,
            .min_rtt_us = rtt.min_rtt_us,
            .latest_rtt_us = rtt.latest_rtt_us,
        });
    }

    /// Are read/write secrets installed at the given encryption level?
    pub fn haveSecret(self: *const Connection, lvl: EncryptionLevel, dir: Direction) bool {
        const slot = self.levels[lvl.idx()];
        return switch (dir) {
            .read => slot.read != null,
            .write => slot.write != null,
        };
    }

    /// Cipher suite negotiated for the given encryption level, if
    /// the secret has been installed and the protocol-id is one we
    /// support. RFC 9001 only permits TLS 1.3 cipher suites; nullq
    /// understands the three QUIC v1 suites.
    pub fn cipherSuite(
        self: *const Connection,
        lvl: EncryptionLevel,
        dir: Direction,
    ) ?Suite {
        const slot = self.levels[lvl.idx()];
        const material_opt = switch (dir) {
            .read => slot.read,
            .write => slot.write,
        };
        const material = material_opt orelse return null;
        return Suite.fromProtocolId(material.cipher_protocol_id);
    }

    /// Derive AEAD/IV/HP keys for the given (level, direction). The
    /// secret was captured by the TLS bridge; HKDF-Expand-Label
    /// turns it into per-packet protection material.
    pub fn packetKeys(
        self: *const Connection,
        lvl: EncryptionLevel,
        dir: Direction,
    ) Error!?PacketKeys {
        if (lvl == .application) {
            switch (dir) {
                .read => if (self.app_read_current) |epoch| return epoch.keys,
                .write => if (self.app_write_current) |epoch| return epoch.keys,
            }
        }
        const slot = self.levels[lvl.idx()];
        const material_opt = switch (dir) {
            .read => slot.read,
            .write => slot.write,
        };
        const material = material_opt orelse return null;
        const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
            return Error.UnsupportedCipherSuite;
        const secret = material.secret[0..material.secret_len];
        return try short_packet_mod.derivePacketKeys(suite, secret);
    }

    fn applicationKeyEpochFromMaterial(
        material: SecretMaterial,
        key_phase: bool,
        epoch: u64,
        installed_at_us: u64,
    ) Error!ApplicationKeyEpoch {
        const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
            return Error.UnsupportedCipherSuite;
        const keys = try short_packet_mod.derivePacketKeys(
            suite,
            material.secret[0..material.secret_len],
        );
        return .{
            .material = material,
            .keys = keys,
            .key_phase = key_phase,
            .epoch = epoch,
            .installed_at_us = installed_at_us,
        };
    }

    fn nextApplicationKeyEpoch(
        current: ApplicationKeyEpoch,
        installed_at_us: u64,
    ) Error!ApplicationKeyEpoch {
        var material = current.material;
        const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
            return Error.UnsupportedCipherSuite;
        const next_secret = try short_packet_mod.deriveNextTrafficSecret(
            suite,
            material.secret[0..material.secret_len],
        );

        const secret_len: usize = suite.secretLen();
        @memcpy(material.secret[0..secret_len], next_secret[0..secret_len]);
        @memset(material.secret[secret_len..], 0);
        material.secret_len = @intCast(secret_len);

        var next_keys = try short_packet_mod.derivePacketKeys(
            suite,
            material.secret[0..material.secret_len],
        );
        next_keys.hp = current.keys.hp;
        return .{
            .material = material,
            .keys = next_keys,
            .key_phase = !current.key_phase,
            .epoch = current.epoch +| 1,
            .installed_at_us = installed_at_us,
        };
    }

    fn installApplicationSecret(
        self: *Connection,
        dir: Direction,
        material: SecretMaterial,
    ) Error!void {
        const app_idx = EncryptionLevel.application.idx();
        const epoch = try applicationKeyEpochFromMaterial(material, false, 0, 0);
        switch (dir) {
            .read => {
                self.levels[app_idx].read = material;
                self.app_read_previous = null;
                self.app_read_current = epoch;
                self.app_read_next = try nextApplicationKeyEpoch(epoch, 0);
                self.app_failed_auth_packets = 0;
                self.emitQlog(.{
                    .name = .application_read_key_installed,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                });
                self.emitQlog(.{
                    .name = .key_updated,
                    .level = .application,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                });
            },
            .write => {
                self.levels[app_idx].write = material;
                self.app_write_current = epoch;
                self.app_write_update_pending_ack = false;
                self.app_next_local_update_after_us = null;
                self.emitQlog(.{
                    .name = .application_write_key_installed,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                });
                self.emitQlog(.{
                    .name = .key_updated,
                    .level = .application,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                });
            },
        }
    }

    fn refreshNextApplicationReadKey(self: *Connection) Error!void {
        const current = self.app_read_current orelse {
            self.app_read_next = null;
            return;
        };
        self.app_read_next = try nextApplicationKeyEpoch(current, current.installed_at_us);
    }

    fn promoteApplicationReadKeys(self: *Connection, now_us: u64) Error!void {
        const current = self.app_read_current orelse return Error.KeyUpdateUnavailable;
        var previous = current;
        previous.discard_deadline_us = now_us +| self.retiredPathRetentionUs();
        self.app_read_previous = previous;
        self.app_read_current = self.app_read_next orelse
            try nextApplicationKeyEpoch(current, now_us);
        self.app_read_current.?.installed_at_us = now_us;
        self.app_read_current.?.discard_deadline_us = null;
        try self.refreshNextApplicationReadKey();
        self.emitQlog(.{
            .name = .application_read_key_discard_scheduled,
            .at_us = now_us,
            .key_epoch = previous.epoch,
            .key_phase = previous.key_phase,
            .discard_deadline_us = previous.discard_deadline_us,
        });
        self.emitQlog(.{
            .name = .application_read_key_updated,
            .at_us = now_us,
            .key_epoch = self.app_read_current.?.epoch,
            .key_phase = self.app_read_current.?.key_phase,
        });
        self.emitQlog(.{
            .name = .key_updated,
            .at_us = now_us,
            .level = .application,
            .key_epoch = self.app_read_current.?.epoch,
            .key_phase = self.app_read_current.?.key_phase,
        });
    }

    fn installNextApplicationWriteKeys(
        self: *Connection,
        now_us: u64,
        pending_ack: bool,
    ) Error!void {
        const current = self.app_write_current orelse return Error.KeyUpdateUnavailable;
        self.app_write_current = try nextApplicationKeyEpoch(current, now_us);
        self.app_write_current.?.installed_at_us = now_us;
        self.app_write_current.?.acked = false;
        self.app_write_update_pending_ack = pending_ack;
        self.emitQlog(.{
            .name = .application_write_key_updated,
            .at_us = now_us,
            .key_epoch = self.app_write_current.?.epoch,
            .key_phase = self.app_write_current.?.key_phase,
        });
        self.emitQlog(.{
            .name = .key_updated,
            .at_us = now_us,
            .level = .application,
            .key_epoch = self.app_write_current.?.epoch,
            .key_phase = self.app_write_current.?.key_phase,
        });
    }

    fn maybeRespondToPeerKeyUpdate(self: *Connection, now_us: u64) Error!void {
        const read = self.app_read_current orelse return;
        const write = self.app_write_current orelse return;
        if (write.key_phase == read.key_phase) return;
        try self.installNextApplicationWriteKeys(now_us, true);
    }

    /// True if the embedder may call `requestKeyUpdate` right now
    /// (RFC 9001 §6). Returns false while a previous update is still
    /// awaiting an ACK or while the cooldown deadline is in the future.
    pub fn canInitiateKeyUpdateAt(self: *const Connection, now_us: u64) bool {
        if (self.app_write_current == null) return false;
        if (self.app_write_update_pending_ack) return false;
        if (self.app_next_local_update_after_us) |deadline| {
            if (now_us < deadline) return false;
        }
        return true;
    }

    /// Initiate an application key update (RFC 9001 §6). Returns
    /// `error.KeyUpdateBlocked` if `canInitiateKeyUpdateAt` would
    /// have returned false.
    pub fn requestKeyUpdate(self: *Connection, now_us: u64) Error!void {
        if (!self.canInitiateKeyUpdateAt(now_us)) return Error.KeyUpdateBlocked;
        try self.installNextApplicationWriteKeys(now_us, true);
    }

    /// Snapshot of the current application key-update lifecycle —
    /// read/write epoch, key phase, packets protected with the
    /// current write key, and whether a discard deadline is set.
    pub fn keyUpdateStatus(self: *const Connection) ApplicationKeyUpdateStatus {
        var status: ApplicationKeyUpdateStatus = .{
            .write_update_pending_ack = self.app_write_update_pending_ack,
            .next_local_update_after_us = self.app_next_local_update_after_us,
            .auth_failures = self.app_failed_auth_packets,
            .next_read_epoch_ready = self.app_read_next != null,
        };
        if (self.app_read_current) |epoch| {
            status.read_epoch = epoch.epoch;
            status.read_key_phase = epoch.key_phase;
        }
        if (self.app_read_previous) |epoch| {
            status.previous_read_discard_deadline_us = epoch.discard_deadline_us;
        }
        if (self.app_write_current) |epoch| {
            status.write_epoch = epoch.epoch;
            status.write_key_phase = epoch.key_phase;
            status.write_packets_protected = epoch.packets_protected;
        }
        return status;
    }

    /// Override the AEAD confidentiality / integrity / proactive-update
    /// thresholds. Test-only — production embedders should accept the
    /// RFC 9001 §6.6 defaults.
    pub fn setApplicationKeyUpdateLimitsForTesting(
        self: *Connection,
        limits: ApplicationKeyUpdateLimits,
    ) void {
        self.app_key_update_limits = limits;
    }

    fn applicationWriteKeyPhase(self: *const Connection) bool {
        const current = self.app_write_current orelse return false;
        return current.key_phase;
    }

    fn prepareApplicationWriteKeys(self: *Connection, now_us: u64) Error!void {
        const current = self.app_write_current orelse return;
        if (current.packets_protected >= self.app_key_update_limits.proactive_update_threshold and
            self.canInitiateKeyUpdateAt(now_us))
        {
            try self.requestKeyUpdate(now_us);
            return;
        }
        if (current.packets_protected >= self.app_key_update_limits.confidentiality_limit) {
            self.emitQlog(.{
                .name = .aead_confidentiality_limit_reached,
                .at_us = now_us,
                .key_epoch = current.epoch,
                .key_phase = current.key_phase,
            });
            self.close(true, transport_error_aead_limit_reached, "AEAD confidentiality limit reached");
        }
    }

    fn recordApplicationPacketProtected(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
    ) void {
        if (self.app_write_current) |*epoch| {
            epoch.packets_protected +|= 1;
            sent_packet.key_epoch = epoch.epoch;
            sent_packet.key_phase = epoch.key_phase;
        }
    }

    fn onApplicationPacketAckedForKeys(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
        now_us: u64,
    ) void {
        const epoch_id = packet.key_epoch orelse return;
        if (self.app_write_current) |*epoch| {
            if (epoch.epoch == epoch_id) {
                epoch.acked = true;
                if (self.app_write_update_pending_ack) {
                    self.app_write_update_pending_ack = false;
                    self.app_next_local_update_after_us = now_us +| self.retiredPathRetentionUs();
                    self.emitQlog(.{
                        .name = .application_write_update_acked,
                        .at_us = now_us,
                        .key_epoch = epoch.epoch,
                        .key_phase = epoch.key_phase,
                        .packet_number = packet.pn,
                        .discard_deadline_us = self.app_next_local_update_after_us,
                    });
                }
            }
        }
    }

    fn noteApplicationAuthFailure(self: *Connection) void {
        self.app_failed_auth_packets +|= 1;
        if (self.app_failed_auth_packets >= self.app_key_update_limits.integrity_limit) {
            self.emitQlog(.{
                .name = .aead_integrity_limit_reached,
                .key_epoch = if (self.app_read_current) |epoch| epoch.epoch else null,
                .key_phase = if (self.app_read_current) |epoch| epoch.key_phase else null,
            });
            self.close(true, transport_error_aead_limit_reached, "AEAD integrity limit reached");
        }
    }

    fn discardExpiredApplicationReadKeys(self: *Connection, now_us: u64) void {
        if (self.app_read_previous) |epoch| {
            if (epoch.discard_deadline_us) |deadline| {
                if (now_us >= deadline) {
                    self.emitQlog(.{
                        .name = .application_read_key_discarded,
                        .at_us = now_us,
                        .key_epoch = epoch.epoch,
                        .key_phase = epoch.key_phase,
                        .discard_deadline_us = deadline,
                    });
                    self.app_read_previous = null;
                }
            }
        }
    }

    /// Set the DCID we put on outgoing 1-RTT packets. A zero-length
    /// CID is valid (RFC 9000 §5.1) and represents the case where
    /// the peer has chosen not to identify itself with a CID;
    /// `peer_dcid_set` flips to true regardless of length.
    pub fn setPeerDcid(self: *Connection, cid: []const u8) !void {
        if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        self.peer_dcid = ConnectionId.fromSlice(cid);
        self.primaryPath().path.peer_cid = self.peer_dcid;
        self.peer_dcid_set = true;
        try self.installPeerTransportStatelessResetToken();
    }

    /// Set the SCID this endpoint identifies with. A zero-length
    /// CID is permitted. Used as the SCID on outgoing long-header
    /// packets and as the expected DCID length on every incoming
    /// packet.
    pub fn setLocalScid(self: *Connection, cid: []const u8) Error!void {
        if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        self.local_scid = ConnectionId.fromSlice(cid);
        if (!self.initial_source_cid_set) {
            self.initial_source_cid = self.local_scid;
            self.initial_source_cid_set = true;
        }
        self.primaryPath().path.local_cid = self.local_scid;
        self.local_scid_set = true;
        try self.rememberLocalCid(0, 0, 0, self.local_scid, @splat(0));
    }

    /// Length of the local SCID — also the length of the DCID the
    /// peer puts on incoming short-header packets.
    pub fn localDcidLen(self: *const Connection) u8 {
        return self.local_scid.len;
    }

    fn longHeaderScid(self: *const Connection) ConnectionId {
        return if (self.initial_source_cid_set) self.initial_source_cid else self.local_scid;
    }

    fn rememberLocalCid(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [16]u8,
    ) Error!void {
        if (cid.len == 0) return;
        if (retire_prior_to > sequence_number) {
            self.close(true, transport_error_protocol_violation, "invalid retire_prior_to");
            return;
        }
        try self.ensureLocalCidAvailable(path_id, sequence_number, cid);
        for (self.local_cids.items) |*item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                item.retire_prior_to = retire_prior_to;
                item.cid = cid;
                item.stateless_reset_token = stateless_reset_token;
                return;
            }
        }
        self.retireLocalCidsPriorTo(path_id, retire_prior_to);
        try self.local_cids.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .cid = cid,
            .stateless_reset_token = stateless_reset_token,
        });
        if (self.paths.get(path_id)) |path| {
            if (path.path.local_cid.len == 0 or sequence_number == 0) {
                path.path.local_cid = cid;
                if (path_id == 0) self.local_scid = cid;
            }
            // Keep the per-path high watermark of issued CID sequences.
            // RFC 9000 §19.16 requires us to reject RETIRE_CONNECTION_ID
            // whose sequence is greater than any we ever assigned.
            if (sequence_number >= path.next_local_cid_seq) {
                path.next_local_cid_seq = sequence_number + 1;
            }
        }
    }

    fn retireLocalCidsPriorTo(
        self: *Connection,
        path_id: u32,
        retire_prior_to: u64,
    ) void {
        var i: usize = 0;
        while (i < self.local_cids.items.len) {
            const item = self.local_cids.items[i];
            if (item.path_id == path_id and item.sequence_number < retire_prior_to) {
                _ = self.local_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        self.promoteLocalCidForPath(path_id);
    }

    fn promoteLocalCidForPath(self: *Connection, path_id: u32) void {
        const path = self.paths.get(path_id) orelse return;
        path.path.local_cid = .{};
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id) {
                path.path.local_cid = item.cid;
                if (path_id == 0) self.local_scid = item.cid;
                return;
            }
        }
    }

    fn retireLocalCid(self: *Connection, path_id: u32, sequence_number: u64) void {
        var removed_cid: ?ConnectionId = null;
        var i: usize = 0;
        while (i < self.local_cids.items.len) {
            const item = self.local_cids.items[i];
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                removed_cid = item.cid;
                _ = self.local_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        const cid = removed_cid orelse return;
        const path = self.paths.get(path_id) orelse return;
        if (ConnectionId.eql(path.path.local_cid, cid)) {
            self.promoteLocalCidForPath(path_id);
        }
    }

    fn retireLocalCidFromPeer(self: *Connection, path_id: u32, sequence_number: u64) void {
        const before_budget = self.localConnectionIdIssueBudget(path_id);
        self.retireLocalCid(path_id, sequence_number);
        if (self.localConnectionIdIssueBudget(path_id) > before_budget) {
            self.recordConnectionIdsNeeded(path_id, .retired, null);
        }
    }

    fn dropPendingLocalCidAdvertisement(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
    ) void {
        if (path_id == 0) {
            var i: usize = 0;
            while (i < self.pending_new_connection_ids.items.len) {
                if (self.pending_new_connection_ids.items[i].sequence_number == sequence_number) {
                    _ = self.pending_new_connection_ids.orderedRemove(i);
                    continue;
                }
                i += 1;
            }
            return;
        }

        var i: usize = 0;
        while (i < self.pending_path_new_connection_ids.items.len) {
            const item = self.pending_path_new_connection_ids.items[i];
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                _ = self.pending_path_new_connection_ids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn nextLocalCidSequence(self: *const Connection, path_id: u32) u64 {
        var next: u64 = 0;
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id and item.sequence_number >= next) {
                next = item.sequence_number + 1;
            }
        }
        return next;
    }

    /// Sequence number to use for the next NEW_CONNECTION_ID
    /// the embedder issues on `path_id`. Useful when minting CIDs
    /// outside of `replenishConnectionIds`.
    pub fn nextLocalConnectionIdSequence(self: *const Connection, path_id: u32) u64 {
        return self.nextLocalCidSequence(path_id);
    }

    /// Number of currently-active local SCIDs across all paths
    /// (initial SCID plus every still-unretired SCID issued via
    /// NEW_CONNECTION_ID). Used by embedders that maintain a
    /// CID-to-connection routing table outside the connection
    /// (the canonical caller is `nullq.Server`).
    pub fn localScidCount(self: *const Connection) usize {
        return self.local_cids.items.len;
    }

    /// Snapshot the currently-active local SCIDs into `dst`.
    /// Returns the number of CIDs actually written (`min(dst.len,
    /// localScidCount())`). Caller is responsible for sizing `dst`
    /// large enough; oversize is fine, undersize silently truncates.
    /// CIDs are returned in arbitrary order.
    pub fn localScids(self: *const Connection, dst: []ConnectionId) usize {
        const n = @min(dst.len, self.local_cids.items.len);
        for (0..n) |i| dst[i] = self.local_cids.items[i].cid;
        return n;
    }

    /// Returns true if `dcid` matches one of this connection's
    /// currently-active local SCIDs. Per RFC 9000 §5.1, peers can
    /// migrate to any CID we have advertised via NEW_CONNECTION_ID
    /// at any time, so embedders that route by CID outside the
    /// connection MUST treat any of those SCIDs as valid routing
    /// keys, not just the initial one.
    pub fn ownsLocalCid(self: *const Connection, dcid: []const u8) bool {
        for (self.local_cids.items) |item| {
            if (item.cid.len != dcid.len) continue;
            if (std.mem.eql(u8, item.cid.bytes[0..item.cid.len], dcid)) return true;
        }
        return false;
    }

    fn localCidSequenceExists(
        self: *const Connection,
        path_id: u32,
        sequence_number: u64,
    ) bool {
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                return true;
            }
        }
        return false;
    }

    fn ensureLocalCidAvailable(
        self: *const Connection,
        path_id: u32,
        sequence_number: u64,
        cid: ConnectionId,
    ) Error!void {
        if (cid.len == 0) return;
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                if (!ConnectionId.eql(item.cid, cid)) return Error.ConnectionIdAlreadyInUse;
                continue;
            }
            if (ConnectionId.eql(item.cid, cid)) return Error.ConnectionIdAlreadyInUse;
        }
    }

    fn localCidForSequence(
        self: *const Connection,
        path_id: u32,
        sequence_number: u64,
    ) ?IssuedCid {
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                return item;
            }
        }
        return null;
    }

    fn localCidActiveCountForPath(self: *const Connection, path_id: u32) usize {
        var count: usize = 0;
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id) count += 1;
        }
        return count;
    }

    fn localCidActiveCountForPathAfterRetirePriorTo(
        self: *const Connection,
        path_id: u32,
        retire_prior_to: u64,
    ) usize {
        var count: usize = 0;
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id and item.sequence_number >= retire_prior_to) {
                count += 1;
            }
        }
        return count;
    }

    fn peerActiveConnectionIdLimit(self: *const Connection) u64 {
        const params = self.cached_peer_transport_params orelse return 2;
        return @min(params.active_connection_id_limit, max_supported_active_connection_id_limit);
    }

    fn peerActiveConnectionIdLimitUsize(self: *const Connection) usize {
        const limit = self.peerActiveConnectionIdLimit();
        const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
        if (limit > max_usize_as_u64) return std.math.maxInt(usize);
        return @intCast(limit);
    }

    /// Number of fresh NEW_CONNECTION_ID frames the embedder may
    /// queue on `path_id` without exceeding the peer's
    /// `active_connection_id_limit`.
    pub fn localConnectionIdIssueBudget(self: *const Connection, path_id: u32) usize {
        return self.localConnectionIdIssueBudgetAfterRetirePriorTo(path_id, 0);
    }

    fn localConnectionIdIssueBudgetAfterRetirePriorTo(
        self: *const Connection,
        path_id: u32,
        retire_prior_to: u64,
    ) usize {
        const limit = self.peerActiveConnectionIdLimit();
        const active: u64 = @intCast(
            self.localCidActiveCountForPathAfterRetirePriorTo(path_id, retire_prior_to),
        );
        if (active >= limit) return 0;
        const remaining = limit - active;
        const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
        if (remaining > max_usize_as_u64) return std.math.maxInt(usize);
        return @intCast(remaining);
    }

    fn ensureCanIssueLocalCid(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid_len: usize,
    ) Error!void {
        if (cid_len == 0) return;
        if (self.localCidSequenceExists(path_id, sequence_number)) return;
        if (self.localConnectionIdIssueBudgetAfterRetirePriorTo(path_id, retire_prior_to) == 0) {
            return Error.ConnectionIdLimitExceeded;
        }
    }

    /// Server-side helper: peek the unprotected DCID + SCID out of
    /// an incoming Initial datagram and install them along with the
    /// caller-supplied transport parameters. Idempotent — safe to
    /// call once before the first `handle`. Useful for plain UDP
    /// servers that need to seed CID/transport-parameter state
    /// from the very first datagram before TLS can advance.
    pub fn acceptInitial(
        self: *Connection,
        bytes: []const u8,
        params: TransportParams,
    ) Error!void {
        if (self.role != .server) return Error.NotServerContext;
        if (bytes.len < 6) return Error.InsufficientBytes;
        if ((bytes[0] & 0x80) == 0) return Error.NotShortHeader; // not a long header
        const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
        if (long_type_bits != 0) return Error.NotShortHeader;

        const dcid_len = bytes[5];
        if (dcid_len > path_mod.max_cid_len) return Error.DcidTooLong;
        var pos: usize = 6;
        if (bytes.len < pos + @as(usize, dcid_len) + 1) return Error.InsufficientBytes;
        const dcid = bytes[pos .. pos + dcid_len];
        pos += dcid_len;
        const scid_len = bytes[pos];
        if (scid_len > path_mod.max_cid_len) return Error.DcidTooLong;
        pos += 1;
        if (bytes.len < pos + @as(usize, scid_len)) return Error.InsufficientBytes;
        const scid = bytes[pos .. pos + scid_len];

        try self.setInitialDcid(dcid);
        try self.setPeerDcid(scid);
        try self.setTransportParams(params);
    }

    fn longHeaderCids(bytes: []const u8) Error!struct {
        version: u32,
        dcid: []const u8,
        scid: []const u8,
    } {
        if (bytes.len < 6) return Error.InsufficientBytes;
        if ((bytes[0] & 0x80) == 0) return Error.NotShortHeader;
        const version = std.mem.readInt(u32, bytes[1..5], .big);

        const dcid_len = bytes[5];
        if (dcid_len > path_mod.max_cid_len) return Error.DcidTooLong;
        var pos: usize = 6;
        if (bytes.len < pos + @as(usize, dcid_len) + 1) return Error.InsufficientBytes;
        const dcid = bytes[pos .. pos + dcid_len];
        pos += dcid_len;
        const scid_len = bytes[pos];
        if (scid_len > path_mod.max_cid_len) return Error.DcidTooLong;
        pos += 1;
        if (bytes.len < pos + @as(usize, scid_len)) return Error.InsufficientBytes;
        const scid = bytes[pos .. pos + scid_len];
        return .{ .version = version, .dcid = dcid, .scid = scid };
    }

    fn initialHeaderCids(bytes: []const u8) Error!struct {
        dcid: []const u8,
        scid: []const u8,
    } {
        const cids = try longHeaderCids(bytes);
        const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
        if (long_type_bits != @intFromEnum(wire_header.LongType.initial)) return Error.NotInitialPacket;
        return .{ .dcid = cids.dcid, .scid = cids.scid };
    }

    /// Server-side helper: write a Version Negotiation packet in
    /// response to a client's unsupported-version long-header packet.
    /// `supported_versions` is encoded in preference order.
    pub fn writeVersionNegotiation(
        self: *Connection,
        dst: []u8,
        client_packet: []const u8,
        supported_versions: []const u32,
    ) Error!usize {
        if (self.role != .server) return error.NotServerContext;
        if (supported_versions.len == 0) return error.InvalidVersionNegotiation;
        if (supported_versions.len > 16) return error.BufferTooSmall;
        const cids = try longHeaderCids(client_packet);

        var versions_bytes: [16 * 4]u8 = undefined;
        for (supported_versions, 0..) |version, i| {
            std.mem.writeInt(u32, versions_bytes[i * 4 ..][0..4], version, .big);
        }

        return try wire_header.encode(dst, .{ .version_negotiation = .{
            .dcid = try wire_header.ConnId.fromSlice(cids.scid),
            .scid = try wire_header.ConnId.fromSlice(cids.dcid),
            .versions_bytes = versions_bytes[0 .. supported_versions.len * 4],
        } });
    }

    /// Server-side helper: write a QUIC v1 Retry packet in response
    /// to `client_initial`. Token contents and validation remain
    /// embedder-owned; nullq handles the Retry header and RFC 9001
    /// integrity tag.
    pub fn writeRetry(
        self: *Connection,
        dst: []u8,
        client_initial: []const u8,
        retry_scid: []const u8,
        retry_token: []const u8,
    ) Error!usize {
        if (self.role != .server) return error.NotServerContext;
        const cids = try initialHeaderCids(client_initial);
        return try long_packet_mod.sealRetry(dst, .{
            .original_dcid = cids.dcid,
            .dcid = cids.scid,
            .scid = retry_scid,
            .retry_token = retry_token,
        });
    }

    /// Set the original DCID used for Initial-key derivation
    /// (RFC 9001 §5.2). On the client this is the random DCID it
    /// chose for its very first Initial. On the server, it's the
    /// DCID it received on the client's first Initial. Per RFC 9000
    /// the initial DCID is at least 8 bytes, so `len == 0` here is
    /// always "unset".
    pub fn setInitialDcid(self: *Connection, dcid: []const u8) Error!void {
        if (dcid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        if (!self.original_initial_dcid_set) {
            self.original_initial_dcid = ConnectionId.fromSlice(dcid);
            self.original_initial_dcid_set = true;
        }
        self.initial_dcid = ConnectionId.fromSlice(dcid);
        self.initial_dcid_set = true;
        self.initial_keys_read = null;
        self.initial_keys_write = null;
    }

    fn ensureInitialKeys(self: *Connection) Error!void {
        if (self.initial_keys_read != null and self.initial_keys_write != null) return;
        if (!self.initial_dcid_set) return;
        const dcid_slice = self.initial_dcid.slice();
        // RFC 9001 §5.2: client-direction secret comes from "client in",
        // server-direction from "server in". The Connection's role
        // determines which secret is the read-side and which is write.
        const client_keys_initial = try initial_keys_mod.deriveInitialKeys(dcid_slice, false);
        const server_keys_initial = try initial_keys_mod.deriveInitialKeys(dcid_slice, true);
        const client_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &client_keys_initial.secret);
        const server_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &server_keys_initial.secret);
        switch (self.role) {
            .client => {
                self.initial_keys_write = client_pkt;
                self.initial_keys_read = server_pkt;
            },
            .server => {
                self.initial_keys_write = server_pkt;
                self.initial_keys_read = client_pkt;
            },
        }
    }

    /// Open a new bidirectional stream with the given id. The id
    /// is caller-supplied. RFC 9000 §2.1 says the low two bits of
    /// a stream id encode (initiator, direction):
    ///   0 = client-initiated bidi, 1 = server-initiated bidi
    ///   2 = client-initiated uni,  3 = server-initiated uni
    pub fn openBidi(self: *Connection, id: u64) Error!*Stream {
        if (!streamIsBidi(id) or !self.streamInitiatedByLocal(id)) return Error.InvalidStreamId;
        if (self.streams.contains(id)) return Error.StreamAlreadyOpen;
        try self.recordLocalStreamOpen(id);
        return try self.openStream(id);
    }

    /// Open a new unidirectional stream. The caller is responsible
    /// for choosing an id with the right low bits per §2.1.
    pub fn openUni(self: *Connection, id: u64) Error!*Stream {
        if (!streamIsUni(id) or !self.streamInitiatedByLocal(id)) return Error.InvalidStreamId;
        if (self.streams.contains(id)) return Error.StreamAlreadyOpen;
        try self.recordLocalStreamOpen(id);
        return try self.openStream(id);
    }

    fn openStream(self: *Connection, id: u64) Error!*Stream {
        if (self.streams.contains(id)) return Error.StreamAlreadyOpen;
        const ptr = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(ptr);
        ptr.* = .{
            .id = id,
            .send = SendStream.init(self.allocator),
            .recv = RecvStream.init(self.allocator),
            .recv_max_data = self.initialRecvStreamLimit(id),
            .send_max_data = self.initialSendStreamLimit(id),
        };
        try self.streams.put(self.allocator, id, ptr);
        self.emitQlog(.{
            .name = .stream_state_updated,
            .stream_id = id,
            .stream_state = .open,
        });
        return ptr;
    }

    fn streamIsBidi(id: u64) bool {
        return (id & 0b10) == 0;
    }

    fn streamIsUni(id: u64) bool {
        return !streamIsBidi(id);
    }

    fn streamIndex(id: u64) u64 {
        return id >> 2;
    }

    fn streamInitiatedByClient(id: u64) bool {
        return (id & 0b01) == 0;
    }

    fn streamInitiatedByLocal(self: *const Connection, id: u64) bool {
        return streamInitiatedByClient(id) == (self.role == .client);
    }

    fn localMaySendOnStream(self: *const Connection, id: u64) bool {
        if (streamIsBidi(id)) return true;
        return self.streamInitiatedByLocal(id);
    }

    fn peerMaySendOnStream(self: *const Connection, id: u64) bool {
        if (streamIsBidi(id)) return true;
        return !self.streamInitiatedByLocal(id);
    }

    fn initialRecvStreamLimit(self: *const Connection, id: u64) u64 {
        const params = self.local_transport_params;
        if (streamIsUni(id)) {
            if (self.streamInitiatedByLocal(id)) return 0;
            return params.initial_max_stream_data_uni;
        }
        if (self.streamInitiatedByLocal(id)) {
            return params.initial_max_stream_data_bidi_local;
        }
        return params.initial_max_stream_data_bidi_remote;
    }

    fn initialSendStreamLimit(self: *const Connection, id: u64) u64 {
        const params = self.cached_peer_transport_params orelse return std.math.maxInt(u64);
        if (streamIsUni(id)) {
            if (!self.streamInitiatedByLocal(id)) return 0;
            return params.initial_max_stream_data_uni;
        }
        if (self.streamInitiatedByLocal(id)) {
            return params.initial_max_stream_data_bidi_remote;
        }
        return params.initial_max_stream_data_bidi_local;
    }

    fn recordLocalStreamOpen(self: *Connection, id: u64) Error!void {
        const idx = streamIndex(id);
        if (idx >= max_stream_count_limit) return Error.InvalidStreamId;
        const next = idx + 1;
        if (streamIsBidi(id)) {
            if (idx >= self.peer_max_streams_bidi) {
                self.noteStreamsBlocked(true, self.peer_max_streams_bidi);
                return Error.StreamLimitExceeded;
            }
            if (next > self.local_opened_streams_bidi) self.local_opened_streams_bidi = next;
        } else {
            if (idx >= self.peer_max_streams_uni) {
                self.noteStreamsBlocked(false, self.peer_max_streams_uni);
                return Error.StreamLimitExceeded;
            }
            if (next > self.local_opened_streams_uni) self.local_opened_streams_uni = next;
        }
    }

    fn recordPeerStreamOpenOrClose(self: *Connection, id: u64) bool {
        const idx = streamIndex(id);
        if (idx >= max_stream_count_limit) {
            self.close(true, transport_error_frame_encoding, "stream id exceeds stream count space");
            return false;
        }
        const next = idx + 1;
        if (streamIsBidi(id)) {
            if (idx >= self.local_max_streams_bidi) {
                self.close(true, transport_error_stream_limit, "peer exceeded bidirectional stream limit");
                return false;
            }
            if (next > self.peer_opened_streams_bidi) self.peer_opened_streams_bidi = next;
        } else {
            if (idx >= self.local_max_streams_uni) {
                self.close(true, transport_error_stream_limit, "peer exceeded unidirectional stream limit");
                return false;
            }
            if (next > self.peer_opened_streams_uni) self.peer_opened_streams_uni = next;
        }
        return true;
    }

    fn peerStreamWithinLocalLimit(self: *Connection, id: u64) bool {
        const idx = streamIndex(id);
        if (idx >= max_stream_count_limit) {
            self.close(true, transport_error_frame_encoding, "stream id exceeds stream count space");
            return false;
        }
        if (streamIsBidi(id)) {
            if (idx >= self.local_max_streams_bidi) {
                self.close(true, transport_error_stream_limit, "peer referenced bidirectional stream above limit");
                return false;
            }
        } else {
            if (idx >= self.local_max_streams_uni) {
                self.close(true, transport_error_stream_limit, "peer referenced unidirectional stream above limit");
                return false;
            }
        }
        return true;
    }

    fn limitChunkToSendFlow(
        self: *Connection,
        s: *const Stream,
        chunk: send_stream_mod.Chunk,
    ) Error!?send_stream_mod.Chunk {
        return self.limitChunkToSendFlowAfterPlanned(s, chunk, 0);
    }

    fn limitChunkToSendFlowAfterPlanned(
        self: *Connection,
        s: *const Stream,
        chunk: send_stream_mod.Chunk,
        planned_conn_new_bytes: u64,
    ) Error!?send_stream_mod.Chunk {
        if (!self.localMaySendOnStream(s.id)) return null;
        if (chunk.length == 0) return chunk;

        const chunk_end = std.math.add(u64, chunk.offset, chunk.length) catch return null;
        const wants_new_data = chunk_end > s.send_flow_highest;
        const stream_new_allowance = if (s.send_flow_highest >= s.send_max_data)
            0
        else
            s.send_max_data - s.send_flow_highest;
        const planned_conn_sent = self.we_sent_stream_data +| planned_conn_new_bytes;
        const conn_new_allowance = if (planned_conn_sent >= self.peer_max_data)
            0
        else
            self.peer_max_data - planned_conn_sent;
        if (wants_new_data and stream_new_allowance == 0) {
            try self.noteStreamDataBlocked(s.id, s.send_max_data);
        }
        if (wants_new_data and conn_new_allowance == 0) {
            self.noteDataBlocked(self.peer_max_data);
        }
        const new_allowance = @min(stream_new_allowance, conn_new_allowance);

        const retransmit_end = if (chunk.offset < s.send_flow_highest)
            @min(chunk_end, s.send_flow_highest)
        else
            chunk.offset;
        const allowed_end = retransmit_end +| new_allowance;
        const send_end = @min(chunk_end, allowed_end);
        if (send_end <= chunk.offset) return null;

        var limited = chunk;
        limited.length = send_end - chunk.offset;
        limited.fin = chunk.fin and send_end == chunk_end;
        return limited;
    }

    fn streamFlowNewBytes(s: *const Stream, chunk: send_stream_mod.Chunk) u64 {
        const end = std.math.add(u64, chunk.offset, chunk.length) catch return 0;
        if (end <= s.send_flow_highest) return 0;
        return end - s.send_flow_highest;
    }

    fn recordStreamFlowSent(self: *Connection, s: *Stream, chunk: send_stream_mod.Chunk) void {
        const end = std.math.add(u64, chunk.offset, chunk.length) catch return;
        if (end <= s.send_flow_highest) return;
        const delta = end - s.send_flow_highest;
        s.send_flow_highest = end;
        self.we_sent_stream_data += delta;
    }

    /// Iterate over every open stream. The yielded pointer is
    /// invalidated by `openBidi` / `openUni` (HashMap rehash) and
    /// by stream removal — finish iteration before mutating the
    /// stream set.
    pub fn streamIterator(self: *Connection) std.AutoHashMapUnmanaged(u64, *Stream).Iterator {
        return self.streams.iterator();
    }

    /// Number of currently-open streams.
    pub fn streamCount(self: *const Connection) usize {
        return self.streams.count();
    }

    /// Pick the next available server-initiated unidirectional
    /// stream id (low 2 bits = 0b11) starting from `start`. Skips
    /// ids that are already open.
    pub fn nextServerUniId(self: *const Connection, start: u64) u64 {
        var id = start | 0b11;
        while (self.streams.contains(id)) id += 4;
        return id;
    }

    /// Pick the next available server-initiated bidi stream id
    /// (low 2 bits = 0b01). Skips ids already open.
    pub fn nextServerBidiId(self: *const Connection, start: u64) u64 {
        var id = (start & ~@as(u64, 0b11)) | 0b01;
        while (self.streams.contains(id)) id += 4;
        return id;
    }

    /// Look up a stream by id. Returns null if no stream is open
    /// at that id.
    pub fn stream(self: *const Connection, id: u64) ?*Stream {
        return self.streams.get(id);
    }

    /// Convenience: write `data` to the send half of stream `id`.
    pub fn streamWrite(self: *Connection, id: u64, data: []const u8) Error!usize {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        return try s.send.write(data);
    }

    /// Convenience: read from the receive half of stream `id`.
    pub fn streamRead(self: *Connection, id: u64, dst: []u8) Error!usize {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        const n = s.recv.read(dst);
        if (n > 0) {
            self.recv_stream_bytes_read += n;
            if (shouldQueueReceiveCredit(
                s.recv.read_offset,
                s.recv_max_data,
                default_stream_receive_window,
            )) {
                try self.queueMaxStreamData(id, s.recv.read_offset +| default_stream_receive_window);
            }
            if (shouldQueueReceiveCredit(
                self.recv_stream_bytes_read,
                self.local_max_data,
                default_connection_receive_window,
            )) {
                self.queueMaxData(self.recv_stream_bytes_read +| default_connection_receive_window);
            }
        }
        self.maybeReturnPeerStreamCredit(s);
        return n;
    }

    /// Whether the receive side of `id` has seen any STREAM bytes in
    /// 0-RTT. Returns null for an unknown stream.
    pub fn streamArrivedInEarlyData(self: *const Connection, id: u64) ?bool {
        const s = self.streams.get(id) orelse return null;
        return s.arrived_in_early_data;
    }

    /// If the *local* sender ran out of connection-level send credit
    /// (RFC 9000 §4.1) and we therefore plan to emit a DATA_BLOCKED
    /// frame, this returns the limit we hit. Diagnostic only.
    pub fn localDataBlockedAt(self: *const Connection) ?u64 {
        return self.local_data_blocked_at;
    }

    /// As `localDataBlockedAt` but for one specific stream's
    /// stream-level send credit (would emit STREAM_DATA_BLOCKED).
    pub fn localStreamDataBlockedAt(self: *const Connection, stream_id: u64) ?u64 {
        const idx = findStreamBlocked(self.local_stream_data_blocked.items, stream_id) orelse return null;
        return self.local_stream_data_blocked.items[idx].maximum_stream_data;
    }

    /// As `localDataBlockedAt` but for stream-count limits (would
    /// emit STREAMS_BLOCKED). `bidi=true` checks bidi limits.
    pub fn localStreamsBlockedAt(self: *const Connection, bidi: bool) ?u64 {
        return if (bidi) self.local_streams_blocked_bidi else self.local_streams_blocked_uni;
    }

    /// If the *peer* told us they're stuck on connection-level send
    /// credit (received a DATA_BLOCKED frame), this is the limit
    /// they advertised. Useful for diagnosing flow-control deadlocks.
    pub fn peerDataBlockedAt(self: *const Connection) ?u64 {
        return self.peer_data_blocked_at;
    }

    /// As `peerDataBlockedAt` but for a single stream
    /// (received STREAM_DATA_BLOCKED).
    pub fn peerStreamDataBlockedAt(self: *const Connection, stream_id: u64) ?u64 {
        const idx = findStreamBlocked(self.peer_stream_data_blocked.items, stream_id) orelse return null;
        return self.peer_stream_data_blocked.items[idx].maximum_stream_data;
    }

    /// As `peerDataBlockedAt` but for stream-count limits
    /// (received STREAMS_BLOCKED).
    pub fn peerStreamsBlockedAt(self: *const Connection, bidi: bool) ?u64 {
        return if (bidi) self.peer_streams_blocked_bidi else self.peer_streams_blocked_uni;
    }

    fn queueMaxStreamData(
        self: *Connection,
        stream_id: u64,
        maximum_stream_data: u64,
    ) Error!void {
        if (self.streams.get(stream_id)) |stream_ptr| {
            stream_ptr.recv_max_data = @max(stream_ptr.recv_max_data, maximum_stream_data);
        }
        clearStreamBlocked(&self.peer_stream_data_blocked, stream_id, maximum_stream_data);
        for (self.pending_max_stream_data.items) |*item| {
            if (item.stream_id == stream_id) {
                if (maximum_stream_data > item.maximum_stream_data) {
                    item.maximum_stream_data = maximum_stream_data;
                }
                return;
            }
        }
        try self.pending_max_stream_data.append(self.allocator, .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        });
    }

    fn queueMaxData(self: *Connection, maximum_data: u64) void {
        if (maximum_data > self.local_max_data) self.local_max_data = maximum_data;
        if (self.peer_data_blocked_at) |limit| {
            if (maximum_data > limit) self.peer_data_blocked_at = null;
        }
        if (self.pending_max_data == null or maximum_data > self.pending_max_data.?) {
            self.pending_max_data = maximum_data;
        }
    }

    fn shouldQueueReceiveCredit(consumed: u64, advertised: u64, window: u64) bool {
        if (consumed == 0) return false;
        const target = consumed +| window;
        if (target <= advertised) return false;
        if (consumed >= advertised) return true;
        return advertised - consumed <= window / 2;
    }

    fn queueMaxStreams(self: *Connection, bidi: bool, maximum_streams: u64) void {
        if (maximum_streams > max_stream_count_limit) return;
        const bounded_maximum_streams = @min(maximum_streams, max_streams_per_connection);
        if (bidi) {
            if (bounded_maximum_streams > self.local_max_streams_bidi) self.local_max_streams_bidi = bounded_maximum_streams;
            if (self.peer_streams_blocked_bidi) |limit| {
                if (bounded_maximum_streams > limit) self.peer_streams_blocked_bidi = null;
            }
            if (self.pending_max_streams_bidi == null or bounded_maximum_streams > self.pending_max_streams_bidi.?) {
                self.pending_max_streams_bidi = bounded_maximum_streams;
            }
        } else {
            if (bounded_maximum_streams > self.local_max_streams_uni) self.local_max_streams_uni = bounded_maximum_streams;
            if (self.peer_streams_blocked_uni) |limit| {
                if (bounded_maximum_streams > limit) self.peer_streams_blocked_uni = null;
            }
            if (self.pending_max_streams_uni == null or bounded_maximum_streams > self.pending_max_streams_uni.?) {
                self.pending_max_streams_uni = bounded_maximum_streams;
            }
        }
    }

    fn maybeReturnPeerStreamCredit(self: *Connection, s: *Stream) void {
        if (self.streamInitiatedByLocal(s.id)) return;
        if (s.stream_count_credit_returned) return;
        if (!(s.recv.state == .data_recvd or
            s.recv.state == .data_read or
            s.recv.state == .reset_recvd or
            s.recv.state == .reset_read))
        {
            return;
        }
        s.stream_count_credit_returned = true;
        if (streamIsBidi(s.id)) {
            self.maybeQueueBatchedMaxStreams(true);
        } else {
            self.maybeQueueBatchedMaxStreams(false);
        }
    }

    fn maybeQueueBatchedMaxStreams(self: *Connection, bidi: bool) void {
        const current = if (bidi) self.local_max_streams_bidi else self.local_max_streams_uni;
        if (current >= max_streams_per_connection) return;

        const opened = if (bidi) self.peer_opened_streams_bidi else self.peer_opened_streams_uni;
        const remaining = current -| opened;
        const batch = streamCreditReturnBatch(current);
        if (remaining > batch / 2) return;

        const grant = @min(batch, max_streams_per_connection - current);
        self.queueMaxStreams(bidi, current + grant);
    }

    fn streamCreditReturnBatch(current_limit: u64) u64 {
        return @max(min_stream_credit_return_batch, current_limit / stream_credit_return_divisor);
    }

    fn recordFlowBlockedEvent(self: *Connection, info: FlowBlockedInfo) void {
        for (self.flow_blocked_events.constSlice()) |existing| {
            if (existing.source == info.source and
                existing.kind == info.kind and
                existing.limit == info.limit and
                existing.stream_id == info.stream_id and
                existing.bidi == info.bidi)
            {
                return;
            }
        }
        self.flow_blocked_events.push(info);
    }

    fn cidPathCanBeManaged(self: *const Connection, path_id: u32) bool {
        if (path_id == 0) return true;
        if (self.paths.getConst(path_id) != null) return true;
        return self.multipathNegotiated() and path_id <= self.local_max_path_id;
    }

    /// Snapshot of how many local CIDs are active on `path_id`, the peer's
    /// limit, and the embedder's remaining issuance budget. Returns `null`
    /// when `path_id` does not name a manageable path. Embedders use this to
    /// drive `provideConnectionId` proactively (RFC 9000 §5.1.1).
    pub fn connectionIdReplenishInfo(
        self: *const Connection,
        path_id: u32,
    ) ?ConnectionIdReplenishInfo {
        if (!self.cidPathCanBeManaged(path_id)) return null;
        return self.connectionIdReplenishInfoFor(path_id, .retired, null);
    }

    fn connectionIdReplenishInfoFor(
        self: *const Connection,
        path_id: u32,
        reason: ConnectionIdReplenishReason,
        blocked_next_sequence_number: ?u64,
    ) ConnectionIdReplenishInfo {
        return .{
            .path_id = path_id,
            .reason = reason,
            .active_count = self.localCidActiveCountForPath(path_id),
            .active_limit = self.peerActiveConnectionIdLimitUsize(),
            .issue_budget = self.localConnectionIdIssueBudget(path_id),
            .next_sequence_number = self.nextLocalCidSequence(path_id),
            .blocked_next_sequence_number = blocked_next_sequence_number,
        };
    }

    fn recordConnectionIdsNeeded(
        self: *Connection,
        path_id: u32,
        reason: ConnectionIdReplenishReason,
        blocked_next_sequence_number: ?u64,
    ) void {
        if (!self.cidPathCanBeManaged(path_id)) return;
        const info = self.connectionIdReplenishInfoFor(path_id, reason, blocked_next_sequence_number);
        if (info.issue_budget == 0 and info.blocked_next_sequence_number == null) return;
        for (self.connection_id_events.slice()) |*existing| {
            if (existing.path_id == path_id and existing.reason == reason) {
                existing.* = info;
                return;
            }
        }
        self.connection_id_events.push(info);
    }

    fn connectionIdEventStillNeeded(self: *const Connection, path_id: u32) bool {
        if (self.localConnectionIdIssueBudget(path_id) > 0) return true;
        if (self.pendingPathCidsBlocked()) |blocked| {
            if (blocked.path_id == path_id) return true;
        }
        return false;
    }

    fn refreshConnectionIdEventsForPath(self: *Connection, path_id: u32) void {
        var i: usize = 0;
        while (i < self.connection_id_events.len) {
            const slice = self.connection_id_events.slice();
            if (slice[i].path_id != path_id) {
                i += 1;
                continue;
            }
            if (!self.connectionIdEventStillNeeded(path_id)) {
                self.connection_id_events.removeAt(i);
                continue;
            }
            const event = slice[i];
            self.connection_id_events.slice()[i] = self.connectionIdReplenishInfoFor(
                path_id,
                event.reason,
                event.blocked_next_sequence_number,
            );
            i += 1;
        }
    }

    fn recordDatagramSendEvent(self: *Connection, event: StoredDatagramSendEvent) void {
        self.datagram_send_events.push(event);
    }

    fn recordDatagramAcked(self: *Connection, packet: *const sent_packets_mod.SentPacket) void {
        const event = event_queue_mod.datagramEventFromPacket(packet) orelse return;
        self.recordDatagramSendEvent(.{ .acked = event });
    }

    fn recordDatagramLost(self: *Connection, packet: *const sent_packets_mod.SentPacket) void {
        const event = event_queue_mod.datagramEventFromPacket(packet) orelse return;
        self.recordDatagramSendEvent(.{ .lost = event });
    }

    fn findStreamBlocked(
        list: []const frame_types.StreamDataBlocked,
        stream_id: u64,
    ) ?usize {
        for (list, 0..) |item, i| {
            if (item.stream_id == stream_id) return i;
        }
        return null;
    }

    fn upsertStreamBlocked(
        list: *std.ArrayList(frame_types.StreamDataBlocked),
        allocator: std.mem.Allocator,
        item: frame_types.StreamDataBlocked,
    ) Error!bool {
        if (findStreamBlocked(list.items, item.stream_id)) |idx| {
            if (list.items[idx].maximum_stream_data == item.maximum_stream_data) return false;
            list.items[idx].maximum_stream_data = item.maximum_stream_data;
            return true;
        }
        if (list.items.len >= max_tracked_stream_data_blocked) return Error.StreamLimitExceeded;
        try list.append(allocator, item);
        return true;
    }

    fn clearStreamBlocked(
        list: *std.ArrayList(frame_types.StreamDataBlocked),
        stream_id: u64,
        new_limit: u64,
    ) void {
        const idx = findStreamBlocked(list.items, stream_id) orelse return;
        if (new_limit > list.items[idx].maximum_stream_data) {
            _ = list.orderedRemove(idx);
        }
    }

    fn noteDataBlocked(self: *Connection, maximum_data: u64) void {
        const changed = self.local_data_blocked_at == null or self.local_data_blocked_at.? != maximum_data;
        self.local_data_blocked_at = maximum_data;
        if (changed) {
            self.pending_data_blocked = maximum_data;
            self.recordFlowBlockedEvent(.{
                .source = .local,
                .kind = .data,
                .limit = maximum_data,
            });
        }
    }

    fn requeueDataBlocked(self: *Connection, maximum_data: u64) bool {
        if (self.local_data_blocked_at == null or
            self.local_data_blocked_at.? != maximum_data)
        {
            return false;
        }
        self.pending_data_blocked = maximum_data;
        return true;
    }

    fn clearLocalDataBlocked(self: *Connection, new_limit: u64) void {
        if (self.local_data_blocked_at) |limit| {
            if (new_limit > limit) self.local_data_blocked_at = null;
        }
        if (self.pending_data_blocked) |limit| {
            if (new_limit > limit) self.pending_data_blocked = null;
        }
    }

    fn noteStreamDataBlocked(
        self: *Connection,
        stream_id: u64,
        maximum_stream_data: u64,
    ) Error!void {
        const item: frame_types.StreamDataBlocked = .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        };
        const changed = try upsertStreamBlocked(&self.local_stream_data_blocked, self.allocator, item);
        if (changed) {
            _ = try upsertStreamBlocked(&self.pending_stream_data_blocked, self.allocator, item);
            self.recordFlowBlockedEvent(.{
                .source = .local,
                .kind = .stream_data,
                .limit = maximum_stream_data,
                .stream_id = stream_id,
            });
        }
    }

    fn requeueStreamDataBlocked(
        self: *Connection,
        item: frame_types.StreamDataBlocked,
    ) Error!bool {
        const idx = findStreamBlocked(self.local_stream_data_blocked.items, item.stream_id) orelse return false;
        if (self.local_stream_data_blocked.items[idx].maximum_stream_data != item.maximum_stream_data) {
            return false;
        }
        _ = try upsertStreamBlocked(&self.pending_stream_data_blocked, self.allocator, item);
        return true;
    }

    fn clearLocalStreamDataBlocked(
        self: *Connection,
        stream_id: u64,
        new_limit: u64,
    ) void {
        clearStreamBlocked(&self.local_stream_data_blocked, stream_id, new_limit);
        clearStreamBlocked(&self.pending_stream_data_blocked, stream_id, new_limit);
    }

    fn noteStreamsBlocked(self: *Connection, bidi: bool, maximum_streams: u64) void {
        if (bidi) {
            const changed = self.local_streams_blocked_bidi == null or self.local_streams_blocked_bidi.? != maximum_streams;
            self.local_streams_blocked_bidi = maximum_streams;
            if (changed) {
                self.pending_streams_blocked_bidi = maximum_streams;
                self.recordFlowBlockedEvent(.{
                    .source = .local,
                    .kind = .streams,
                    .limit = maximum_streams,
                    .bidi = true,
                });
            }
        } else {
            const changed = self.local_streams_blocked_uni == null or self.local_streams_blocked_uni.? != maximum_streams;
            self.local_streams_blocked_uni = maximum_streams;
            if (changed) {
                self.pending_streams_blocked_uni = maximum_streams;
                self.recordFlowBlockedEvent(.{
                    .source = .local,
                    .kind = .streams,
                    .limit = maximum_streams,
                    .bidi = false,
                });
            }
        }
    }

    fn requeueStreamsBlocked(self: *Connection, item: frame_types.StreamsBlocked) bool {
        if (item.bidi) {
            if (self.local_streams_blocked_bidi == null or
                self.local_streams_blocked_bidi.? != item.maximum_streams)
            {
                return false;
            }
            self.pending_streams_blocked_bidi = item.maximum_streams;
        } else {
            if (self.local_streams_blocked_uni == null or
                self.local_streams_blocked_uni.? != item.maximum_streams)
            {
                return false;
            }
            self.pending_streams_blocked_uni = item.maximum_streams;
        }
        return true;
    }

    fn clearLocalStreamsBlocked(self: *Connection, bidi: bool, new_limit: u64) void {
        if (bidi) {
            if (self.local_streams_blocked_bidi) |limit| {
                if (new_limit > limit) self.local_streams_blocked_bidi = null;
            }
            if (self.pending_streams_blocked_bidi) |limit| {
                if (new_limit > limit) self.pending_streams_blocked_bidi = null;
            }
        } else {
            if (self.local_streams_blocked_uni) |limit| {
                if (new_limit > limit) self.local_streams_blocked_uni = null;
            }
            if (self.pending_streams_blocked_uni) |limit| {
                if (new_limit > limit) self.pending_streams_blocked_uni = null;
            }
        }
    }

    /// Convenience: close the send half of stream `id` (queues FIN).
    pub fn streamFinish(self: *Connection, id: u64) Error!void {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        try s.send.finish();
    }

    /// Convenience: abort the send half of stream `id` with
    /// RESET_STREAM (RFC 9000 §19.4). Any queued but unsent STREAM data
    /// is discarded; the final size is the number of bytes already
    /// accepted by `streamWrite`.
    pub fn streamReset(
        self: *Connection,
        id: u64,
        application_error_code: u64,
    ) Error!void {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        try s.send.resetStream(application_error_code);
    }

    /// Queue an RFC 9221 DATAGRAM payload for transmission. The next
    /// 1-RTT packet that fits the bytes ships them. Queueing is capped
    /// by the implementation's UDP packet budget and, once known, the
    /// peer's `max_datagram_frame_size` transport parameter.
    pub fn sendDatagram(self: *Connection, payload: []const u8) Error!void {
        _ = try self.sendDatagramTracked(payload);
    }

    /// Queue a DATAGRAM and return a connection-local id that will be
    /// echoed in `datagram_acked` / `datagram_lost` events. QUIC never
    /// retransmits DATAGRAM frames; this id is only for app retry policy.
    pub fn sendDatagramTracked(self: *Connection, payload: []const u8) Error!u64 {
        const max_payload = try self.maxOutboundDatagramPayload();
        if (payload.len > max_payload) return Error.DatagramTooLarge;
        if (self.pending_send_datagrams.items.len >= max_pending_datagram_count) {
            return Error.DatagramQueueFull;
        }
        if (payload.len > max_pending_datagram_bytes or
            self.pending_send_datagram_bytes > max_pending_datagram_bytes - payload.len)
        {
            return Error.DatagramQueueFull;
        }
        const copy = try self.allocator.alloc(u8, payload.len);
        errdefer self.allocator.free(copy);
        @memcpy(copy, payload);
        if (self.next_datagram_id == std.math.maxInt(u64)) return Error.DatagramIdExhausted;
        const id = self.next_datagram_id;
        self.next_datagram_id += 1;
        try self.pending_send_datagrams.append(self.allocator, .{
            .id = id,
            .data = copy,
        });
        self.pending_send_datagram_bytes += payload.len;
        return id;
    }

    fn maxOutboundDatagramPayload(self: *const Connection) Error!usize {
        var limit: usize = max_outbound_datagram_payload_size;
        if (self.cached_peer_transport_params) |params| {
            if (params.max_datagram_frame_size == 0) return Error.DatagramUnavailable;
            limit = @min(limit, @as(usize, @intCast(@min(params.max_datagram_frame_size, max_outbound_datagram_payload_size))));
        }
        return limit;
    }

    /// Queue a NEW_CONNECTION_ID frame. Sequence 0 is the Initial
    /// source CID; callers should normally start additional CIDs at
    /// sequence 1.
    pub fn queueNewConnectionId(
        self: *Connection,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: []const u8,
        stateless_reset_token: [16]u8,
    ) Error!void {
        if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        try self.ensureCanIssueLocalCid(0, sequence_number, retire_prior_to, cid.len);
        const local_cid = ConnectionId.fromSlice(cid);
        try self.ensureLocalCidAvailable(0, sequence_number, local_cid);
        for (self.pending_new_connection_ids.items) |item| {
            if (item.sequence_number == sequence_number) {
                if (!std.mem.eql(u8, item.connection_id.slice(), cid)) return Error.ConnectionIdAlreadyInUse;
                return;
            }
        }
        var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
        @memcpy(connection_id.bytes[0..cid.len], cid);
        try self.rememberLocalCid(0, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
        try self.pending_new_connection_ids.append(self.allocator, .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
        self.refreshConnectionIdEventsForPath(0);
    }

    /// Queue a RETIRE_CONNECTION_ID frame asking the peer to drop a
    /// previously-issued CID at `sequence_number`. Idempotent.
    pub fn queueRetireConnectionId(
        self: *Connection,
        sequence_number: u64,
    ) Error!void {
        for (self.pending_retire_connection_ids.items) |item| {
            if (item.sequence_number == sequence_number) return;
        }
        try self.pending_retire_connection_ids.append(self.allocator, .{
            .sequence_number = sequence_number,
        });
    }

    /// Pop the oldest received DATAGRAM into `dst`. Returns the
    /// number of bytes written, or null if none pending. The
    /// payload is dropped from the queue regardless of whether it
    /// fit — caller must size `dst` to the peer's advertised
    /// `max_datagram_frame_size`.
    pub fn receiveDatagram(self: *Connection, dst: []u8) ?usize {
        const item = self.receiveDatagramInfo(dst) orelse return null;
        return item.len;
    }

    /// Pop the oldest received DATAGRAM and include whether it arrived
    /// in 0-RTT. The payload is dropped from the queue regardless of
    /// whether it fit.
    pub fn receiveDatagramInfo(self: *Connection, dst: []u8) ?IncomingDatagram {
        if (self.pending_recv_datagrams.items.len == 0) return null;
        const item = self.pending_recv_datagrams.orderedRemove(0);
        defer self.allocator.free(item.data);
        self.pending_recv_datagram_bytes -= item.data.len;
        const n = @min(dst.len, item.data.len);
        @memcpy(dst[0..n], item.data[0..n]);
        return .{ .len = n, .arrived_in_early_data = item.arrived_in_early_data };
    }

    /// Number of inbound DATAGRAMs queued for the app to read.
    pub fn pendingDatagrams(self: *const Connection) usize {
        return self.pending_recv_datagrams.items.len;
    }

    /// Enable or disable the public multipath surface. The current
    /// implementation keeps existing single-path behavior unless callers
    /// explicitly open and schedule additional paths.
    pub fn enableMultipath(self: *Connection, enabled: bool) void {
        self.multipath_enabled = enabled;
    }

    /// True if `enableMultipath(true)` has been called locally.
    /// Doesn't imply the peer agreed — see `multipathNegotiated`.
    pub fn multipathEnabled(self: *const Connection) bool {
        return self.multipath_enabled;
    }

    /// True only when *both* sides advertised
    /// `initial_max_path_id` in transport parameters. Until this
    /// returns true, `openPath` for non-zero path ids will fail.
    pub fn multipathNegotiated(self: *const Connection) bool {
        if (!self.multipath_enabled) return false;
        if (self.local_transport_params.initial_max_path_id == null) return false;
        const peer_params = self.cached_peer_transport_params orelse return false;
        return peer_params.initial_max_path_id != null;
    }

    /// Register a new application path. Full draft-21 frame exchange is
    /// still staged behind this, but the path already owns independent
    /// Application PN, sent, RTT, congestion, validation, and PTO state.
    pub fn openPath(
        self: *Connection,
        peer_addr: Address,
        local_addr: Address,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
    ) Error!u32 {
        const path_id = self.paths.next_path_id;
        if (self.multipathNegotiated()) {
            if (path_id > self.peer_max_path_id) {
                self.queuePathsBlocked(self.peer_max_path_id);
                return Error.PathLimitExceeded;
            }
            if (path_id > self.local_max_path_id) return Error.PathLimitExceeded;
            if (local_cid.len == 0 or peer_cid.len == 0) return Error.ConnectionIdRequired;
            try self.ensureCanIssueLocalCid(path_id, 0, 0, local_cid.len);
            try self.ensureLocalCidAvailable(path_id, 0, local_cid);
        }
        const opened_path_id = try self.paths.openPath(
            self.allocator,
            peer_addr,
            local_addr,
            local_cid,
            peer_cid,
            .{ .max_datagram_size = self.mtu },
        );
        try self.rememberLocalCid(opened_path_id, 0, 0, local_cid, @splat(0));
        return opened_path_id;
    }

    /// Make `path_id` the primary path for new application data.
    /// Returns false if no such path exists.
    pub fn setActivePath(self: *Connection, path_id: u32) bool {
        return self.paths.setActive(path_id);
    }

    /// Mark `path_id` for retirement at the current activity time
    /// with error code 0. New traffic stops scheduling here; in-flight
    /// frames may still be acked.
    pub fn abandonPath(self: *Connection, path_id: u32) bool {
        return self.abandonPathAt(path_id, 0, self.last_activity_us);
    }

    /// As `abandonPath` but with an explicit timestamp and PATH_ABANDON
    /// error code (draft-21 §6.2). Useful when the embedder has a
    /// tighter clock than `last_activity_us`.
    pub fn abandonPathAt(
        self: *Connection,
        path_id: u32,
        error_code: u64,
        now_us: u64,
    ) bool {
        return self.retirePath(path_id, error_code, now_us, true);
    }

    /// Override the lifecycle state of `path_id` directly. Mainly
    /// useful for tests; production code should drive paths via
    /// `openPath`, `markPathValidated`, `abandonPath`.
    pub fn setPathStatus(self: *Connection, path_id: u32, state: path_mod.State) bool {
        const p = self.paths.get(path_id) orelse return false;
        p.path.state = state;
        return true;
    }

    /// Mark `path_id` available (`backup=false`) or backup
    /// (`backup=true`) and queue a PATH_STATUS_AVAILABLE /
    /// PATH_STATUS_BACKUP frame to inform the peer (draft-21 §6.4).
    pub fn setPathBackup(self: *Connection, path_id: u32, backup: bool) bool {
        const p = self.paths.get(path_id) orelse return false;
        p.local_status_sequence_number +|= 1;
        self.queuePathStatus(
            path_id,
            !backup,
            p.local_status_sequence_number,
        ) catch return false;
        return true;
    }

    /// Treat `path_id` as validated without running PATH_CHALLENGE.
    /// Useful when validation is provided out-of-band (e.g. tests
    /// that drive multipath through a mock transport). Returns false
    /// for unknown `path_id`.
    pub fn markPathValidated(self: *Connection, path_id: u32) bool {
        const p = self.paths.get(path_id) orelse return false;
        p.path.markValidated();
        if (p.pending_migration_reset) self.resetPathRecoveryAfterMigration(p);
        return true;
    }

    /// Choose how `poll` distributes application bytes across
    /// validated paths: `primary`, `round_robin`, or
    /// `lowest_rtt_cwnd`.
    pub fn setScheduler(self: *Connection, scheduler: Scheduler) void {
        self.paths.setScheduler(scheduler);
    }

    /// Path id currently used as the primary (active) path. Always 0
    /// for single-path connections.
    pub fn activePathId(self: *const Connection) u32 {
        return self.paths.activeConst().id;
    }

    /// Read-only snapshot of `path_id`'s RTT, congestion, and loss
    /// counters. Returns null for unknown `path_id`.
    pub fn pathStats(self: *const Connection, path_id: u32) ?PathStats {
        var st = self.paths.stats(path_id) orelse return null;
        // Connection-level counters live on Connection, not on PathState,
        // because they aggregate across all paths/levels (and across migrations).
        st.total_bytes_sent = self.qlog_bytes_sent;
        st.total_bytes_received = self.qlog_bytes_received;
        st.packets_sent = self.qlog_packets_sent;
        st.packets_received = self.qlog_packets_received;
        st.packets_lost = self.qlog_packets_lost;
        return st;
    }

    /// Queue a PATH_ABANDON frame for the given multipath path. Coalesces
    /// repeated calls for the same `path_id` (last `error_code` wins).
    /// draft-ietf-quic-multipath-21 §6.1.
    pub fn queuePathAbandon(
        self: *Connection,
        path_id: u32,
        error_code: u64,
    ) Error!void {
        for (self.pending_path_abandons.items) |*item| {
            if (item.path_id == path_id) {
                item.error_code = error_code;
                return;
            }
        }
        try self.pending_path_abandons.append(self.allocator, .{
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
        for (self.pending_path_statuses.items) |*item| {
            if (item.path_id == path_id) {
                if (sequence_number >= item.sequence_number) {
                    item.sequence_number = sequence_number;
                    item.available = available;
                }
                return;
            }
        }
        try self.pending_path_statuses.append(self.allocator, .{
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
        try self.ensureCanIssueCidForPathId(path_id);
        try self.ensureCanIssueLocalCid(path_id, sequence_number, retire_prior_to, cid.len);
        const local_cid = ConnectionId.fromSlice(cid);
        try self.ensureLocalCidAvailable(path_id, sequence_number, local_cid);
        for (self.pending_path_new_connection_ids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                if (!std.mem.eql(u8, item.connection_id.slice(), cid)) return Error.ConnectionIdAlreadyInUse;
                return;
            }
        }
        var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
        @memcpy(connection_id.bytes[0..cid.len], cid);
        try self.rememberLocalCid(path_id, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
        try self.pending_path_new_connection_ids.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
        self.refreshConnectionIdEventsForPath(path_id);
    }

    /// Queue a PATH_RETIRE_CONNECTION_ID frame asking the peer to drop the
    /// `(path_id, sequence_number)` CID. Idempotent — duplicate retires for
    /// the same pair are coalesced. draft-ietf-quic-multipath-21 §6.4.
    pub fn queuePathRetireConnectionId(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
    ) Error!void {
        for (self.pending_path_retire_connection_ids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) return;
        }
        try self.pending_path_retire_connection_ids.append(self.allocator, .{
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
        if (self.pending_max_path_id == null or bounded_maximum_path_id > self.pending_max_path_id.?) {
            self.pending_max_path_id = bounded_maximum_path_id;
        }
    }

    /// Queue a PATHS_BLOCKED frame telling the peer we have run out of
    /// path-id headroom at `maximum_path_id`. Coalesces by keeping the
    /// largest pending value. draft-ietf-quic-multipath-21 §6.6.
    pub fn queuePathsBlocked(self: *Connection, maximum_path_id: u32) void {
        if (self.pending_paths_blocked == null or maximum_path_id > self.pending_paths_blocked.?) {
            self.pending_paths_blocked = maximum_path_id;
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
        self.pending_path_cids_blocked = .{
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

    fn clearSatisfiedPathCidsBlocked(self: *Connection, path_id: u32) void {
        const pending = self.pendingPathCidsBlocked() orelse return;
        if (pending.path_id != path_id) return;
        if (self.nextLocalCidSequence(path_id) > pending.next_sequence_number) {
            self.clearPendingPathCidsBlocked(path_id, pending.next_sequence_number);
        }
    }

    /// Bulk-issue local CIDs on the default path (path_id 0) by emitting
    /// NEW_CONNECTION_ID frames for each `ConnectionIdProvision`. Returns
    /// the number of provisions actually accepted. RFC 9000 §19.15.
    pub fn replenishConnectionIds(
        self: *Connection,
        provisions: []const ConnectionIdProvision,
    ) Error!usize {
        return self.replenishLocalConnectionIds(0, provisions);
    }

    /// Multipath variant of `replenishConnectionIds` — bulk-issues local
    /// CIDs on `path_id` via PATH_NEW_CONNECTION_ID frames. Validates that
    /// the path-id is permitted before queuing any frames.
    /// draft-ietf-quic-multipath-21 §6.3.
    pub fn replenishPathConnectionIds(
        self: *Connection,
        path_id: u32,
        provisions: []const ConnectionIdProvision,
    ) Error!usize {
        try self.ensureCanIssueCidForPathId(path_id);
        return self.replenishLocalConnectionIds(path_id, provisions);
    }

    fn ensureCanIssueCidForPathId(self: *const Connection, path_id: u32) Error!void {
        if (path_id == 0) return;
        if (self.multipathNegotiated() and path_id > self.local_max_path_id) {
            return Error.PathLimitExceeded;
        }
        if (self.paths.getConst(path_id) != null) return;
        if (self.multipathNegotiated()) return;
        return Error.PathNotFound;
    }

    fn replenishLocalConnectionIds(
        self: *Connection,
        path_id: u32,
        provisions: []const ConnectionIdProvision,
    ) Error!usize {
        var queued: usize = 0;
        if (self.pendingPathCidsBlocked()) |blocked| {
            if (blocked.path_id == path_id) {
                var seq = blocked.next_sequence_number;
                const next = self.nextLocalCidSequence(path_id);
                while (seq < next) : (seq += 1) {
                    const issued = self.localCidForSequence(path_id, seq) orelse continue;
                    if (path_id == 0) {
                        try self.queueNewConnectionId(
                            issued.sequence_number,
                            issued.retire_prior_to,
                            issued.cid.slice(),
                            issued.stateless_reset_token,
                        );
                    } else {
                        try self.queuePathNewConnectionId(
                            path_id,
                            issued.sequence_number,
                            issued.retire_prior_to,
                            issued.cid.slice(),
                            issued.stateless_reset_token,
                        );
                    }
                    queued += 1;
                }
            }
        }

        for (provisions) |provision| {
            if (self.localConnectionIdIssueBudget(path_id) == 0) break;
            const sequence_number = self.nextLocalCidSequence(path_id);
            if (path_id == 0) {
                try self.queueNewConnectionId(
                    sequence_number,
                    provision.retire_prior_to,
                    provision.connection_id,
                    provision.stateless_reset_token,
                );
            } else {
                try self.queuePathNewConnectionId(
                    path_id,
                    sequence_number,
                    provision.retire_prior_to,
                    provision.connection_id,
                    provision.stateless_reset_token,
                );
            }
            queued += 1;
        }

        if (queued > 0) {
            self.clearSatisfiedPathCidsBlocked(path_id);
            self.refreshConnectionIdEventsForPath(path_id);
        }
        return queued;
    }

    fn cachePeerTransportParams(self: *Connection) Error!void {
        if (self.cached_peer_transport_params != null) return;
        const blob = self.inner.peerQuicTransportParams() orelse return;
        self.cached_peer_transport_params = try transport_params_mod.Params.decode(blob);
        if (self.cached_peer_transport_params.?.initial_max_path_id) |max_path_id| {
            self.peer_max_path_id = @min(max_path_id, max_supported_path_id);
            self.multipath_enabled = true;
        }
        self.validatePeerTransportLimits();
        if (self.pending_close != null or self.closed) {
            self.emitConnectionStateIfChanged();
            return;
        }
        self.validatePeerTransportRole();
        if (self.pending_close != null or self.closed) {
            self.emitConnectionStateIfChanged();
            return;
        }
        try self.installPeerTransportStatelessResetToken();
        self.validatePeerTransportConnectionIds();
        // Successfully accepted — fire `parameters_set` once.
        self.emitPeerParametersSet();
    }

    fn validatePeerTransportLimits(self: *Connection) void {
        const params = self.cached_peer_transport_params orelse return;
        if (params.max_udp_payload_size < min_quic_udp_payload_size) {
            self.close(true, transport_error_transport_parameter, "peer max udp payload below minimum");
            return;
        }
        if (params.initial_max_streams_bidi > max_stream_count_limit or
            params.initial_max_streams_uni > max_stream_count_limit)
        {
            self.close(true, transport_error_transport_parameter, "peer stream count exceeds maximum");
            return;
        }
        const peer_udp_limit: usize = @intCast(@min(params.max_udp_payload_size, max_supported_udp_payload_size));
        self.mtu = @min(self.mtu, peer_udp_limit);
        for (self.paths.paths.items) |*path| {
            path.pmtu = @min(path.pmtu, peer_udp_limit);
        }
        self.applyPeerFlowTransportParams(params);
    }

    fn validatePeerTransportRole(self: *Connection) void {
        if (self.role != .server) return;
        const params = self.cached_peer_transport_params orelse return;
        if (params.original_destination_connection_id != null) {
            self.close(true, transport_error_transport_parameter, "client sent original destination cid");
            return;
        }
        if (params.stateless_reset_token != null) {
            self.close(true, transport_error_transport_parameter, "client sent stateless reset token");
            return;
        }
        if (params.preferred_address != null) {
            self.close(true, transport_error_transport_parameter, "client sent preferred address");
            return;
        }
        if (params.retry_source_connection_id != null) {
            self.close(true, transport_error_transport_parameter, "client sent retry source cid");
            return;
        }
    }

    fn applyPeerFlowTransportParams(self: *Connection, params: TransportParams) void {
        self.peer_max_data = params.initial_max_data;
        self.peer_max_streams_bidi = @min(params.initial_max_streams_bidi, max_streams_per_connection);
        self.peer_max_streams_uni = @min(params.initial_max_streams_uni, max_streams_per_connection);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            const current = if (s.send_max_data == std.math.maxInt(u64)) 0 else s.send_max_data;
            s.send_max_data = @max(current, self.initialSendStreamLimit(s.id));
        }
    }

    fn peerAckDelayExponent(self: *const Connection) u6 {
        const params = self.cached_peer_transport_params orelse return 3;
        return @intCast(@min(params.ack_delay_exponent, 20));
    }

    fn peerMaxAckDelayUs(self: *const Connection) u64 {
        const params = self.cached_peer_transport_params orelse return 25 * rtt_mod.ms;
        return params.max_ack_delay_ms * rtt_mod.ms;
    }

    fn localMaxAckDelayUs(self: *const Connection) u64 {
        return self.local_transport_params.max_ack_delay_ms * rtt_mod.ms;
    }

    fn ackDelayScaled(
        self: *const Connection,
        tracker: *const ack_tracker_mod.AckTracker,
        now_us: u64,
    ) u64 {
        const largest_at_us = tracker.largest_at_ms * rtt_mod.ms;
        if (now_us <= largest_at_us) return 0;
        const shift: u6 = @intCast(@min(self.local_transport_params.ack_delay_exponent, 20));
        return (now_us - largest_at_us) >> shift;
    }

    fn ackDelayDeadlineUs(
        self: *const Connection,
        tracker: *const ack_tracker_mod.AckTracker,
    ) ?u64 {
        const base_ms = tracker.ackDelayBaseMs() orelse return null;
        return base_ms * rtt_mod.ms +| self.localMaxAckDelayUs();
    }

    fn promoteDueAckDelay(self: *Connection, tracker: *ack_tracker_mod.AckTracker, now_us: u64) void {
        _ = tracker.promoteDelayedAck(
            now_us / rtt_mod.ms,
            self.local_transport_params.max_ack_delay_ms,
        );
    }

    fn idleTimeoutUs(self: *const Connection) ?u64 {
        const local = self.local_transport_params.max_idle_timeout_ms * rtt_mod.ms;
        const peer = if (self.cached_peer_transport_params) |params|
            params.max_idle_timeout_ms * rtt_mod.ms
        else
            0;
        if (local == 0) return if (peer == 0) null else peer;
        if (peer == 0) return local;
        return @min(local, peer);
    }

    fn primaryPath(self: *Connection) *PathState {
        return self.paths.primary();
    }

    fn primaryPathConst(self: *const Connection) *const PathState {
        return self.paths.primaryConst();
    }

    fn activePath(self: *Connection) *PathState {
        return self.paths.active();
    }

    fn pathForId(self: *Connection, path_id: u32) *PathState {
        return self.paths.get(path_id) orelse self.primaryPath();
    }

    fn applicationPathForPoll(self: *Connection) *PathState {
        if (self.pending_path_response != null) {
            const p = self.pathForId(self.pending_path_response_path_id);
            if (p.path.state != .failed and p.path.state != .retiring) return p;
        }
        if (self.pending_path_challenge != null) {
            const p = self.pathForId(self.pending_path_challenge_path_id);
            if (p.path.state != .failed and p.path.state != .retiring) return p;
        }
        for (self.paths.paths.items) |*p| {
            if (p.path.state == .failed) continue;
            if (p.app_pn_space.received.pending_ack) return p;
        }
        for (self.paths.paths.items) |*p| {
            if (p.path.state == .failed) continue;
            if (p.pending_ping) return p;
        }
        return self.paths.selectForSending();
    }

    fn incomingPathId(self: *Connection, from: ?Address) u32 {
        if (from) |addr| {
            for (self.paths.paths.items) |*p| {
                if (p.matchesPeerAddress(addr)) return p.id;
            }
            return self.activePath().id;
        }
        return self.activePath().id;
    }

    fn peerAddressChangeCandidate(
        self: *Connection,
        path_id: u32,
        from: ?Address,
    ) ?Address {
        const addr = from orelse return null;
        const path = self.pathForId(path_id);
        if (!path.peer_addr_set) return null;
        if (path.matchesPeerAddress(addr)) return null;
        return addr;
    }

    fn clearQueuedPathChallengeForPath(self: *Connection, path_id: u32) void {
        if (self.pending_path_challenge != null and
            self.pending_path_challenge_path_id == path_id)
        {
            self.pending_path_challenge = null;
        }
    }

    fn queuePathResponseOnPath(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
        addr: ?Address,
    ) void {
        self.pending_path_response = token;
        self.pending_path_response_path_id = path_id;
        self.pending_path_response_addr = addr;
    }

    fn queuePathChallengeOnPath(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
    ) void {
        self.pending_path_challenge = token;
        self.pending_path_challenge_path_id = path_id;
    }

    fn newPathChallengeToken(self: *Connection) Error![8]u8 {
        _ = self;
        var token: [8]u8 = undefined;
        try boringssl.crypto.rand.fillBytes(&token);
        return token;
    }

    fn resetPathRecoveryAfterMigration(
        self: *Connection,
        path: *PathState,
    ) void {
        path.resetRecoveryAfterMigration(.{ .max_datagram_size = self.mtu });
    }

    fn handlePathValidationFailure(
        self: *Connection,
        path: *PathState,
    ) void {
        const path_id = path.id;
        if (path.pending_migration_reset and path.rollbackFailedMigration()) {
            self.clearQueuedPathChallengeForPath(path_id);
            self.emitQlog(.{ .name = .migration_path_failed, .path_id = path_id });
            return;
        }
        path.path.fail();
        path.pending_migration_reset = false;
        path.migration_rollback = null;
        self.clearQueuedPathChallengeForPath(path_id);
        self.emitQlog(.{ .name = .migration_path_failed, .path_id = path_id });
    }

    fn recordPathResponse(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
    ) void {
        const path = self.pathForId(path_id);
        const matched = path.path.validator.recordResponse(token) catch return;
        if (!matched) return;
        path.path.validated = true;
        self.clearQueuedPathChallengeForPath(path_id);
        if (path.pending_migration_reset) {
            self.resetPathRecoveryAfterMigration(path);
        }
        self.emitQlog(.{ .name = .migration_path_validated, .path_id = path_id });
    }

    fn shouldRequeuePathChallenge(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
    ) bool {
        const path = self.paths.get(path_id) orelse return false;
        if (path.path.validator.status != .pending) return false;
        return std.mem.eql(u8, &token, &path.path.validator.pending_token);
    }

    fn handlePeerAddressChange(
        self: *Connection,
        path: *PathState,
        addr: Address,
        datagram_len: usize,
        now_us: u64,
    ) Error!void {
        path.beginMigration(addr, datagram_len);

        const token = try self.newPathChallengeToken();
        const timeout_us = saturatingMul(self.ptoDurationForApplicationPath(path), 3);
        path.path.validator.beginChallenge(token, now_us, timeout_us);
        self.queuePathChallengeOnPath(path.id, token);
    }

    fn recordAuthenticatedDatagramAddress(
        self: *Connection,
        path_id: u32,
        addr: Address,
        datagram_len: usize,
        now_us: u64,
    ) Error!void {
        const path = self.pathForId(path_id);
        if (!path.peer_addr_set) {
            path.setPeerAddress(addr);
            path.path.onDatagramReceived(datagram_len);
            return;
        }
        if (Address.eql(path.path.peer_addr, addr)) {
            path.path.onDatagramReceived(datagram_len);
            return;
        }
        if (path.matchesMigrationRollbackAddress(addr)) return;
        try self.handlePeerAddressChange(path, addr, datagram_len, now_us);
    }

    fn incomingShortPath(self: *Connection, bytes: []const u8) ?*PathState {
        if (bytes.len < 1) return null;
        var best: ?*PathState = null;
        var best_len: u8 = 0;
        for (self.local_cids.items) |item| {
            const cid = item.cid.slice();
            if (cid.len == 0) continue;
            if (bytes.len < 1 + cid.len) continue;
            if (!std.mem.eql(u8, bytes[1 .. 1 + cid.len], cid)) continue;
            if (cid.len > best_len) {
                if (self.paths.get(item.path_id)) |path| {
                    best = path;
                    best_len = @intCast(cid.len);
                }
            }
        }
        if (best != null) return best;
        for (self.paths.paths.items) |*p| {
            const cid = p.path.local_cid.slice();
            if (cid.len == 0) continue;
            if (bytes.len < 1 + cid.len) continue;
            if (std.mem.eql(u8, bytes[1 .. 1 + cid.len], cid)) return p;
        }
        return best;
    }

    fn connPnIdx(lvl: EncryptionLevel) ?usize {
        return switch (lvl) {
            .initial => 0,
            .handshake => 1,
            .early_data, .application => null,
        };
    }

    fn pnSpaceForLevel(self: *Connection, lvl: EncryptionLevel) *PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &self.primaryPath().app_pn_space;
    }

    fn pnSpaceForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &self.primaryPathConst().app_pn_space;
    }

    fn pnSpaceForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &app_path.app_pn_space;
    }

    fn sentForLevel(self: *Connection, lvl: EncryptionLevel) *SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &self.primaryPath().sent;
    }

    fn sentForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &self.primaryPathConst().sent;
    }

    fn sentForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &app_path.sent;
    }

    fn rttForLevel(self: *Connection, lvl: EncryptionLevel) *RttEstimator {
        _ = lvl;
        return &self.primaryPath().path.rtt;
    }

    fn rttForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const RttEstimator {
        _ = lvl;
        return &self.primaryPathConst().path.rtt;
    }

    fn rttForLevelOnPathConst(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) *const RttEstimator {
        if (lvl == .application) return &app_path.path.rtt;
        return &self.primaryPathConst().path.rtt;
    }

    fn ccForApplication(self: *Connection) *NewReno {
        return &self.primaryPath().path.cc;
    }

    fn ccForApplicationConst(self: *const Connection) *const NewReno {
        return &self.primaryPathConst().path.cc;
    }

    fn ptoCountForLevel(self: *Connection, lvl: EncryptionLevel) *u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPath().pto_count;
    }

    fn ptoCountForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPathConst().pto_count;
    }

    fn pendingPingForLevel(self: *Connection, lvl: EncryptionLevel) *bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &self.primaryPath().pending_ping;
    }

    fn pendingPingForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &self.primaryPathConst().pending_ping;
    }

    fn pendingPingForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &app_path.pending_ping;
    }

    fn anyPendingPing(self: *const Connection) bool {
        for (self.pending_ping) |ping| {
            if (ping) return true;
        }
        for (self.paths.paths.items) |*p| {
            if (p.path.state == .failed) continue;
            if (p.pending_ping) return true;
        }
        return false;
    }

    fn clearPendingPings(self: *Connection) void {
        self.pending_ping = .{ false, false };
        for (self.paths.paths.items) |*p| {
            p.pending_ping = false;
            p.pto_probe_count = 0;
        }
    }

    fn clearSentTracker(self: *Connection, tracker: *SentPacketTracker) void {
        var i: u32 = 0;
        while (i < tracker.count) : (i += 1) {
            tracker.packets[i].deinit(self.allocator);
        }
        tracker.count = 0;
        tracker.bytes_in_flight = 0;
        tracker.ack_eliciting_in_flight = 0;
    }

    fn clearRecoveryState(self: *Connection) void {
        for (&self.sent) |*tracker| self.clearSentTracker(tracker);
        for (self.paths.paths.items) |*path| {
            self.clearSentTracker(&path.sent);
            path.pending_ping = false;
            path.pto_probe_count = 0;
            path.pto_count = 0;
        }
        self.clearPendingPings();
    }

    fn resetInitialRecoveryForRetry(self: *Connection) Error!void {
        const idx = EncryptionLevel.initial.idx();
        try self.crypto_retx[idx].ensureUnusedCapacity(
            self.allocator,
            self.sent_crypto[idx].items.len,
        );
        for (self.sent_crypto[idx].items) |chunk| {
            self.crypto_retx[idx].appendAssumeCapacity(.{
                .offset = chunk.offset,
                .data = chunk.data,
            });
        }
        self.sent_crypto[idx].clearRetainingCapacity();
        self.clearSentTracker(&self.sent[0]);
        self.pto_count[0] = 0;
        self.pending_ping[0] = false;
    }

    fn canSendEarlyData(self: *Connection) bool {
        if (self.role != .client) return false;
        if (!self.early_data_send_enabled) return false;
        if (self.inner.handshakeDone()) return false;
        if (self.inner.earlyDataStatus() == .rejected) return false;
        return self.haveSecret(.early_data, .write);
    }

    fn installPeerTransportStatelessResetToken(self: *Connection) Error!void {
        if (self.peer_transport_reset_token_installed) return;
        const params = self.cached_peer_transport_params orelse return;
        const token = params.stateless_reset_token orelse return;
        if (!self.peer_dcid_set or self.peer_dcid.len == 0) return;
        try self.registerPeerCid(0, 0, 0, self.peer_dcid, token);
        self.peer_transport_reset_token_installed = true;
    }

    fn validatePeerTransportConnectionIds(self: *Connection) void {
        const params = self.cached_peer_transport_params orelse return;
        if (params.original_destination_connection_id) |odcid| {
            if (self.original_initial_dcid_set and
                !ConnectionId.eql(odcid, self.original_initial_dcid))
            {
                self.close(true, transport_error_transport_parameter, "original destination cid mismatch");
                return;
            }
        }
        if (self.retry_accepted) {
            const retry_source = params.retry_source_connection_id orelse {
                self.close(true, transport_error_transport_parameter, "missing retry source cid");
                return;
            };
            if (!ConnectionId.eql(retry_source, self.retry_source_cid)) {
                self.close(true, transport_error_transport_parameter, "retry source cid mismatch");
                return;
            }
        } else if (params.retry_source_connection_id != null) {
            self.close(true, transport_error_transport_parameter, "unexpected retry source cid");
        }
    }

    fn refreshEarlyDataStatus(self: *Connection) Error!void {
        if (self.early_data_rejection_processed) return;
        if (self.inner.earlyDataStatus() != .rejected) return;
        try self.requeueRejectedEarlyData();
        self.early_data_rejection_processed = true;
    }

    fn requeueRejectedEarlyData(self: *Connection) Error!void {
        for (self.paths.paths.items) |*path| {
            var i: u32 = 0;
            while (i < path.sent.count) {
                const packet = path.sent.packets[i];
                if (!packet.is_early_data) {
                    i += 1;
                    continue;
                }

                var removed = path.sent.removeAt(i);
                defer removed.deinit(self.allocator);
                self.recordDatagramLost(&removed);
                _ = try self.dispatchLostPacketToStreams(&removed);
                _ = try self.dispatchLostControlFramesOnPath(&removed, path.id);
                self.discardSentCryptoForPacket(.early_data, removed.pn);
            }
        }
    }

    fn nextStreamPacketKey(self: *Connection) u64 {
        const key = self.next_stream_packet_key;
        self.next_stream_packet_key +|= 1;
        return key;
    }

    fn drainingDurationUs(self: *const Connection) u64 {
        return 3 * self.primaryPathConst().path.rtt.pto(self.peerMaxAckDelayUs());
    }

    fn saturatingMul(a: u64, b: u64) u64 {
        return std.math.mul(u64, a, b) catch std.math.maxInt(u64);
    }

    fn u64ToUsizeClamped(value: u64) usize {
        const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
        if (value > max_usize_as_u64) return std.math.maxInt(usize);
        return @intCast(value);
    }

    fn backoffDuration(base: u64, count: u32) u64 {
        const shift: u6 = @intCast(@min(count, 16));
        const max_u64: u64 = std.math.maxInt(u64);
        if (base > (max_u64 >> shift)) return max_u64;
        return base << shift;
    }

    fn basePtoDurationForLevel(self: *const Connection, lvl: EncryptionLevel) u64 {
        const max_ack_delay_us: u64 = switch (lvl) {
            .initial, .handshake => 0,
            .early_data, .application => self.peerMaxAckDelayUs(),
        };
        return self.rttForLevelConst(lvl).pto(max_ack_delay_us);
    }

    fn ptoDurationForLevel(self: *const Connection, lvl: EncryptionLevel) u64 {
        return backoffDuration(self.basePtoDurationForLevel(lvl), self.ptoCountForLevelConst(lvl).*);
    }

    fn basePtoDurationForApplicationPath(self: *const Connection, path: *const PathState) u64 {
        return path.path.rtt.pto(self.peerMaxAckDelayUs());
    }

    fn ptoDurationForApplicationPath(self: *const Connection, path: *const PathState) u64 {
        return backoffDuration(self.basePtoDurationForApplicationPath(path), path.pto_count);
    }

    fn largestApplicationPtoDurationUs(self: *const Connection) u64 {
        var largest: u64 = 0;
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            largest = @max(largest, self.ptoDurationForApplicationPath(path));
        }
        if (largest == 0) largest = self.ptoDurationForApplicationPath(self.primaryPathConst());
        return largest;
    }

    fn retiredPathRetentionUs(self: *const Connection) u64 {
        return saturatingMul(3, self.largestApplicationPtoDurationUs());
    }

    fn retirePath(
        self: *Connection,
        path_id: u32,
        error_code: u64,
        now_us: u64,
        queue_abandon: bool,
    ) bool {
        if (!self.paths.abandon(path_id)) return false;
        const path = self.paths.get(path_id) orelse return false;
        path.retire_deadline_us = now_us +| self.retiredPathRetentionUs();
        if (queue_abandon) {
            self.queuePathAbandon(path_id, error_code) catch return false;
        }
        return true;
    }

    fn expireRetiringPaths(self: *Connection, now_us: u64) void {
        for (self.paths.paths.items) |*path| {
            if (path.path.state != .retiring) continue;
            const deadline = path.retire_deadline_us orelse continue;
            if (now_us < deadline) continue;
            path.clearRecovery(self.allocator);
            self.retirePeerCidsForPath(path.id);
            path.path.fail();
            path.retire_deadline_us = null;
        }
    }

    fn considerDeadline(best: *?TimerDeadline, candidate: TimerDeadline) void {
        if (best.* == null or candidate.at_us < best.*.?.at_us) {
            best.* = candidate;
        }
    }

    fn lossDeadlineForLevel(self: *const Connection, lvl: EncryptionLevel) ?u64 {
        const pn_space = self.pnSpaceForLevelConst(lvl);
        const sent = self.sentForLevelConst(lvl);
        const rtt = self.rttForLevelConst(lvl);
        const largest_acked = pn_space.largest_acked_sent orelse return null;
        const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );

        var best: ?u64 = null;
        var i: u32 = 0;
        while (i < sent.count) : (i += 1) {
            const p = sent.packets[i];
            if (p.pn > largest_acked) continue;
            const at_us = p.sent_time_us +| time_threshold;
            if (best == null or at_us < best.?) best = at_us;
        }
        return best;
    }

    fn lossDeadlineForApplicationPath(self: *const Connection, path: *const PathState) ?u64 {
        _ = self;
        const largest_acked = path.app_pn_space.largest_acked_sent orelse return null;
        const reference_rtt = @max(path.path.rtt.latest_rtt_us, path.path.rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );

        var best: ?u64 = null;
        var i: u32 = 0;
        while (i < path.sent.count) : (i += 1) {
            const p = path.sent.packets[i];
            if (p.pn > largest_acked) continue;
            const at_us = p.sent_time_us +| time_threshold;
            if (best == null or at_us < best.?) best = at_us;
        }
        return best;
    }

    fn ptoDeadlineForLevel(self: *const Connection, lvl: EncryptionLevel) ?u64 {
        const sent = self.sentForLevelConst(lvl);
        var oldest: ?u64 = null;
        var i: u32 = 0;
        while (i < sent.count) : (i += 1) {
            const p = sent.packets[i];
            if (!p.ack_eliciting) continue;
            if (oldest == null or p.sent_time_us < oldest.?) oldest = p.sent_time_us;
        }
        const sent_at = oldest orelse return null;
        return sent_at +| self.ptoDurationForLevel(lvl);
    }

    fn ptoDeadlineForApplicationPath(self: *const Connection, path: *const PathState) ?u64 {
        var oldest: ?u64 = null;
        var i: u32 = 0;
        while (i < path.sent.count) : (i += 1) {
            const p = path.sent.packets[i];
            if (!p.ack_eliciting) continue;
            if (oldest == null or p.sent_time_us < oldest.?) oldest = p.sent_time_us;
        }
        const sent_at = oldest orelse return null;
        return sent_at +| self.ptoDurationForApplicationPath(path);
    }

    fn idleDeadline(self: *const Connection) ?u64 {
        if (self.last_activity_us == 0) return null;
        const timeout = self.idleTimeoutUs() orelse return null;
        return self.last_activity_us +| timeout;
    }

    fn bytesInFlight(self: *const Connection) u64 {
        var total: u64 = 0;
        for (&self.sent) |*tracker| total += tracker.bytes_in_flight;
        for (self.paths.paths.items) |*p| total += p.sent.bytes_in_flight;
        return total;
    }

    /// Current NewReno congestion window in bytes for the active
    /// application-data path. Diagnostic only; there is no setter.
    pub fn congestionWindow(self: *const Connection) u64 {
        return self.ccForApplicationConst().cwnd;
    }

    /// Total bytes currently in flight across all packet-number
    /// spaces and paths. Useful for back-pressure decisions.
    pub fn congestionBytesInFlight(self: *const Connection) u64 {
        return self.bytesInFlight();
    }

    fn congestionBlocked(self: *const Connection, lvl: EncryptionLevel) bool {
        if (lvl != .application and lvl != .early_data) return false;
        const path = self.primaryPathConst();
        if (path.pending_ping) return false;
        if (path.pto_probe_count > 0) return false;
        return path.path.cc.sendAllowance(path.sent.bytes_in_flight) == 0;
    }

    fn congestionBlockedOnPath(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) bool {
        _ = self;
        if (lvl != .application and lvl != .early_data) return false;
        if (app_path.pending_ping) return false;
        if (app_path.pto_probe_count > 0) return false;
        return app_path.path.cc.sendAllowance(app_path.sent.bytes_in_flight) == 0;
    }

    /// Soonest timer deadline among ack-delay, loss detection, PTO,
    /// idle, draining, path retirement, and key-discard. Embedders
    /// can park their event loop on this until `tick` should fire.
    /// Returns null when no timer is currently armed.
    pub fn nextTimerDeadline(self: *const Connection, now_us: u64) ?TimerDeadline {
        _ = now_us;
        var best: ?TimerDeadline = null;

        if (self.draining_deadline_us) |at_us| {
            considerDeadline(&best, .{ .kind = .draining, .at_us = at_us });
            return best;
        }
        if (self.closed) return null;

        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            const tracker = &self.pnSpaceForLevelConst(lvl).received;
            if (self.ackDelayDeadlineUs(tracker)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .ack_delay,
                    .at_us = at_us,
                    .level = lvl,
                });
            }
            if (self.lossDeadlineForLevel(lvl)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .loss_detection,
                    .at_us = at_us,
                    .level = lvl,
                });
            }
            if (self.ptoDeadlineForLevel(lvl)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .pto,
                    .at_us = at_us,
                    .level = lvl,
                });
            }
        }
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            if (path.path.state == .retiring) {
                if (path.retire_deadline_us) |at_us| {
                    considerDeadline(&best, .{
                        .kind = .path_retirement,
                        .at_us = at_us,
                        .level = .application,
                        .path_id = path.id,
                    });
                }
            }
            const tracker = &path.app_pn_space.received;
            if (self.ackDelayDeadlineUs(tracker)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .ack_delay,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
            if (self.lossDeadlineForApplicationPath(path)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .loss_detection,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
            if (self.ptoDeadlineForApplicationPath(path)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .pto,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
        }
        if (self.app_read_previous) |epoch| {
            if (epoch.discard_deadline_us) |at_us| {
                considerDeadline(&best, .{
                    .kind = .key_discard,
                    .at_us = at_us,
                    .level = .application,
                });
            }
        }

        if (self.idleDeadline()) |at_us| {
            considerDeadline(&best, .{ .kind = .idle, .at_us = at_us });
        }
        return best;
    }

    /// True if `poll` would produce an outgoing packet right now.
    pub fn canSend(self: *const Connection) bool {
        if (self.pending_close != null) return true;
        if (self.closed) return false;
        if (self.anyPendingPing()) return true;
        if (self.pending_handshake_done) return true;
        inline for (level_mod.all) |lvl| {
            const level_idx = lvl.idx();
            if (self.outbox[level_idx].len > 0) return true;
            if (self.crypto_retx[level_idx].items.len > 0) return true;
        }
        for (&self.pn_spaces) |*space| {
            if (space.received.pending_ack) return true;
        }
        if (self.pending_max_data != null) return true;
        if (self.pending_max_stream_data.items.len > 0) return true;
        if (self.pending_max_streams_bidi != null or self.pending_max_streams_uni != null) return true;
        if (self.pending_data_blocked != null) return true;
        if (self.pending_stream_data_blocked.items.len > 0) return true;
        if (self.pending_streams_blocked_bidi != null or self.pending_streams_blocked_uni != null) return true;
        if (self.pending_new_connection_ids.items.len > 0) return true;
        if (self.pending_retire_connection_ids.items.len > 0) return true;
        if (self.pending_stop_sending.items.len > 0) return true;
        if (self.pending_path_response != null) return true;
        if (self.pending_path_challenge != null) return true;
        if (self.pending_path_abandons.items.len > 0) return true;
        if (self.pending_path_statuses.items.len > 0) return true;
        if (self.pending_path_new_connection_ids.items.len > 0) return true;
        if (self.pending_path_retire_connection_ids.items.len > 0) return true;
        if (self.pending_max_path_id != null) return true;
        if (self.pending_paths_blocked != null) return true;
        if (self.pending_path_cids_blocked != null) return true;
        if (self.pending_send_datagrams.items.len > 0) return true;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.send.hasPendingChunk()) return true;
        }
        return false;
    }

    /// One outgoing-datagram step. Walks Initial → Handshake →
    /// Application encryption levels in order, packing whatever is
    /// pending at each (CRYPTO, ACK, STREAM) into a coalesced
    /// short/long-header datagram per RFC 9000 §12.2. Returns the
    /// total bytes written, or null if nothing was ready.
    pub fn poll(
        self: *Connection,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        const datagram = (try self.pollDatagram(dst, now_us)) orelse return null;
        return datagram.len;
    }

    /// Path-aware outgoing-datagram step. Single-path callers can
    /// keep using `poll`; multipath-aware embedders can inspect the
    /// destination address and path id once `PathSet` lands.
    pub fn pollDatagram(
        self: *Connection,
        dst: []u8,
        now_us: u64,
    ) Error!?OutgoingDatagram {
        if (self.closed) return null;
        self.queueHandshakeDoneIfReady();
        try self.refreshEarlyDataStatus();
        self.poll_addr_override = null;
        var pos: usize = 0;
        // Initial first (must lead a coalesced datagram).
        if (try self.pollLevel(.initial, dst[pos..], now_us)) |n| pos += n;
        // Client 0-RTT uses a long header but shares the Application
        // packet-number space. If the Initial padded this datagram to
        // the caller's MTU, this simply waits for the next poll.
        if (pos < dst.len) {
            if (try self.pollLevel(.early_data, dst[pos..], now_us)) |n| pos += n;
        }
        // Handshake next (after Initial keys are dropped post-handshake,
        // there's nothing here; otherwise it's CRYPTO + ACK).
        if (pos < dst.len) {
            if (try self.pollLevel(.handshake, dst[pos..], now_us)) |n| pos += n;
        }
        // Application last (the 1-RTT short header MUST be the last
        // packet in a coalesced datagram per §12.2). Only schedule a
        // non-zero path when there are no Initial/Handshake bytes already
        // in this datagram.
        const app_path_id = if (pos == 0)
            self.applicationPathForPoll().id
        else
            self.primaryPath().id;
        const app_start_pos = pos;
        if (pos < dst.len) {
            if (try self.pollLevelOnPath(.application, app_path_id, dst[pos..], now_us)) |n| pos += n;
        }
        if (pos == 0) return null;
        self.last_activity_us = now_us;
        const out_path = self.pathForId(app_path_id);
        const out_addr = if (pos > app_start_pos) self.poll_addr_override orelse out_path.peerAddress() else out_path.peerAddress();
        self.poll_addr_override = null;
        if (out_addr) |addr| {
            if (Address.eql(addr, out_path.path.peer_addr)) out_path.path.onDatagramSent(pos);
        } else {
            out_path.path.onDatagramSent(pos);
        }
        return .{
            .len = pos,
            .to = out_addr,
            .path_id = out_path.id,
        };
    }

    /// Emit one packet at the given level, if there's anything to
    /// send and we have keys. Internal helper of `poll` — exposed
    /// for tests that want fine-grained control.
    pub fn pollLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        return self.pollLevelOnPath(lvl, self.primaryPath().id, dst, now_us);
    }

    fn pollLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path_id: u32,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        // Determine keys for this level. Initial keys are derived
        // from `initial_dcid`; Handshake/Application keys come from
        // the TLS bridge.
        var keys: PacketKeys = undefined;
        var have_keys = false;
        switch (lvl) {
            .initial => {
                try self.ensureInitialKeys();
                if (self.initial_keys_write) |k| {
                    keys = k;
                    have_keys = true;
                }
            },
            .handshake, .application => {
                if (lvl == .application) try self.prepareApplicationWriteKeys(now_us);
                if (try self.packetKeys(lvl, .write)) |k| {
                    keys = k;
                    have_keys = true;
                }
            },
            .early_data => {
                if (!self.canSendEarlyData()) return null;
                if (try self.packetKeys(lvl, .write)) |k| {
                    keys = k;
                    have_keys = true;
                }
            },
        }
        if (!have_keys) return null;
        if (!self.peer_dcid_set) return Error.PeerDcidNotSet;

        // Build payload.
        const app_path = self.pathForId(app_path_id);
        const pn_space = self.pnSpaceForLevelOnPath(lvl, app_path);
        const sent_tracker = self.sentForLevelOnPath(lvl, app_path);
        const pending_ping = self.pendingPingForLevelOnPath(lvl, app_path);
        var pl_buf: [default_mtu]u8 = undefined;
        var pl_pos: usize = 0;
        var ack_eliciting = false;
        var sent_packet: sent_packets_mod.SentPacket = .{
            .pn = 0,
            .sent_time_us = now_us,
            .bytes = 0,
            .ack_eliciting = false,
            .in_flight = false,
        };
        var sent_packet_recorded = false;
        errdefer if (!sent_packet_recorded) sent_packet.deinit(self.allocator);
        var sent_crypto_chunk: ?struct {
            level_idx: usize,
            offset: u64,
            data: []u8,
        } = null;
        var sent_datagram: ?sent_packets_mod.SentDatagram = null;
        var crypto_copy: ?[]u8 = null;
        var retx_crypto_index: ?usize = null;
        errdefer if (crypto_copy) |bytes| self.allocator.free(bytes);

        // Header overhead (worst case) varies by long/short.
        const packet_dcid: *const ConnectionId = if (lvl == .application)
            &app_path.path.peer_cid
        else
            &self.peer_dcid;
        const packet_scid = self.longHeaderScid();
        const max_payload: usize = blk: {
            const dcid_len: usize = packet_dcid.len;
            const scid_len: usize = packet_scid.len;
            const long_overhead: usize = 1 + 4 + 1 + dcid_len + 1 + scid_len + 8 + 4 + 16 + 8; // ample
            const short_overhead: usize = 1 + dcid_len + 4 + 16;
            const overhead: usize = if (lvl == .application) short_overhead else long_overhead;
            var packet_capacity = @min(self.mtu, dst.len);
            // RFC 9000 §8.1: anti-amplification applies to ALL bytes the
            // endpoint sends on an unvalidated path, not just 1-RTT.
            // Initial and Handshake bytes count too — otherwise an off-path
            // attacker can spoof a small Initial and force us to emit a
            // full-MTU Initial+Handshake response (a >10x amplification
            // factor when the spoofed Initial is unpadded).
            if (!app_path.path.isValidated()) {
                const allowance = u64ToUsizeClamped(app_path.path.antiAmpAllowance());
                packet_capacity = @min(packet_capacity, allowance);
                if (packet_capacity <= overhead) return null;
            }
            if (packet_capacity <= overhead) break :blk 0;
            break :blk @min(default_mtu, packet_capacity - overhead);
        };
        if (max_payload == 0) return Error.OutputTooSmall;
        const congestion_blocked = self.congestionBlockedOnPath(lvl, app_path);
        const path_response_addr_overrides_current = blk: {
            if (lvl != .application) break :blk false;
            if (self.pending_path_response == null) break :blk false;
            if (self.pending_path_response_path_id != app_path.id) break :blk false;
            const addr = self.pending_path_response_addr orelse break :blk false;
            break :blk !Address.eql(addr, app_path.path.peer_addr);
        };
        const app_control_blocked = congestion_blocked or path_response_addr_overrides_current;

        // CONNECTION_CLOSE pre-empts everything: if pending, that's
        // the only frame we emit, and we mark the connection
        // closed once it goes on the wire.
        if (self.pending_close) |info| {
            const close_frame = frame_types.ConnectionClose{
                .is_transport = info.is_transport,
                .error_code = info.error_code,
                .frame_type = info.frame_type,
                .reason_phrase = info.reason,
            };
            const wrote = try frame_mod.encode(
                pl_buf[0..max_payload],
                .{ .connection_close = close_frame },
            );
            pl_pos += wrote;
            self.pending_close = null;
            self.closed = true;
            // No ack-eliciting flag — CONNECTION_CLOSE isn't
            // ack-eliciting per §13.2.1, but we do still want to
            // record it (it occupies a PN). Skip stream/CRYPTO/etc.
            const pn = pn_space.nextPn() orelse return Error.PnSpaceExhausted;
            const largest_acked_close = pn_space.largest_acked_sent;
            const n_close = switch (lvl) {
                .initial => try long_packet_mod.sealInitial(dst, .{
                    .dcid = packet_dcid.slice(),
                    .scid = packet_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                }),
                .handshake => try long_packet_mod.sealHandshake(dst, .{
                    .dcid = packet_dcid.slice(),
                    .scid = packet_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                }),
                .application => try short_packet_mod.seal1Rtt(dst, .{
                    .dcid = packet_dcid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                    .key_phase = self.applicationWriteKeyPhase(),
                    .multipath_path_id = if (self.multipathNegotiated()) app_path.id else null,
                }),
                .early_data => try long_packet_mod.sealZeroRtt(dst, .{
                    .dcid = packet_dcid.slice(),
                    .scid = packet_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                }),
            };
            var close_packet: sent_packets_mod.SentPacket = .{
                .pn = pn,
                .sent_time_us = now_us,
                .bytes = n_close,
                .ack_eliciting = false,
                .in_flight = false,
                .is_early_data = lvl == .early_data,
            };
            if (lvl == .application) self.recordApplicationPacketProtected(&close_packet);
            try sent_tracker.record(close_packet);
            const draining_deadline = now_us + self.drainingDurationUs();
            self.draining_deadline_us = draining_deadline;
            self.updateCloseEventDrainingDeadline(draining_deadline);
            self.qlog_packets_sent +|= 1;
            self.qlog_bytes_sent +|= n_close;
            self.emitPacketSent(lvl, pn, @intCast(n_close), 1);
            self.emitConnectionStateIfChanged();
            return n_close;
        }

        // 1) ACK frame (if pending in this level's space).
        const recv_tracker = &pn_space.received;
        if (lvl != .early_data and recv_tracker.pending_ack) {
            var ranges_buf: [default_mtu]u8 = undefined;
            const available = max_payload - pl_pos;
            var ranges_budget: usize = @min(ranges_buf.len, available);
            if (lvl == .application) {
                ranges_budget = @min(ranges_budget, max_application_ack_ranges_bytes);
            }
            while (true) {
                const max_lower_ranges = if (lvl == .application)
                    max_application_ack_lower_ranges
                else
                    std.math.maxInt(u64);
                const ack_frame = try recv_tracker.toAckFrameLimitedRanges(
                    self.ackDelayScaled(recv_tracker, now_us),
                    &ranges_buf,
                    ranges_budget,
                    max_lower_ranges,
                );
                const frame: frame_types.Frame = if (lvl == .application and app_path.id != 0)
                    .{ .path_ack = .{
                        .path_id = app_path.id,
                        .largest_acked = ack_frame.largest_acked,
                        .ack_delay = ack_frame.ack_delay,
                        .first_range = ack_frame.first_range,
                        .range_count = ack_frame.range_count,
                        .ranges_bytes = ack_frame.ranges_bytes,
                        .ecn_counts = ack_frame.ecn_counts,
                    } }
                else
                    .{ .ack = ack_frame };
                const needed = frame_mod.encodedLen(frame);
                if (needed <= available) {
                    const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], frame);
                    pl_pos += wrote;
                    recv_tracker.markAckSent();
                    break;
                }
                if (ranges_budget == 0 or ack_frame.ranges_bytes.len == 0) break;
                const overflow = needed - available;
                const reduced_budget = if (overflow >= ack_frame.ranges_bytes.len)
                    @as(usize, 0)
                else
                    ack_frame.ranges_bytes.len - overflow;
                ranges_budget = if (reduced_budget >= ack_frame.ranges_bytes.len)
                    ack_frame.ranges_bytes.len - 1
                else
                    reduced_budget;
            }
        }

        // 1a) PTO probe PING. A lost PING is not retransmitted as a
        // frame, but a later PTO will queue another probe.
        if (!path_response_addr_overrides_current and lvl != .early_data and pending_ping.* and pl_pos + 1 <= max_payload) {
            const ping_len = try frame_mod.encode(
                pl_buf[pl_pos..max_payload],
                .{ .ping = .{} },
            );
            pl_pos += ping_len;
            pending_ping.* = false;
            ack_eliciting = true;
        }

        // 1b) Server handshake confirmation. HANDSHAKE_DONE is
        // application-level, ack-eliciting, and retransmittable.
        if (!app_control_blocked and lvl == .application and self.pending_handshake_done and pl_pos + 1 <= max_payload) {
            const wrote = try frame_mod.encode(
                pl_buf[pl_pos..max_payload],
                .{ .handshake_done = .{} },
            );
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{ .handshake_done = .{} });
            self.pending_handshake_done = false;
            ack_eliciting = true;
        }

        // 2) CRYPTO frame: retransmit lost data first, then drain
        // fresh outbox bytes at this level into one frame.
        const out_idx = lvl.idx();
        if (lvl != .early_data and !congestion_blocked and self.crypto_retx[out_idx].items.len > 0 and pl_pos + 25 < max_payload) {
            const max_data = max_payload - pl_pos - 25;
            const chunk = self.crypto_retx[out_idx].items[0];
            if (chunk.data.len <= max_data) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .crypto = .{
                        .offset = chunk.offset,
                        .data = chunk.data,
                    },
                });
                pl_pos += wrote;
                const copy = try self.allocator.dupe(u8, chunk.data);
                crypto_copy = copy;
                sent_crypto_chunk = .{
                    .level_idx = out_idx,
                    .offset = chunk.offset,
                    .data = copy,
                };
                retx_crypto_index = 0;
                ack_eliciting = true;
            }
        } else if (lvl != .early_data and !congestion_blocked and self.outbox[out_idx].len > 0 and pl_pos + 25 < max_payload) {
            const max_data = max_payload - pl_pos - 25;
            const drain_len = @min(self.outbox[out_idx].len, max_data);
            const data_slice = self.outbox[out_idx].buf[0..drain_len];
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .crypto = .{
                    .offset = self.crypto_send_offset[out_idx],
                    .data = data_slice,
                },
            });
            pl_pos += wrote;
            const copy = try self.allocator.dupe(u8, data_slice);
            crypto_copy = copy;
            sent_crypto_chunk = .{
                .level_idx = out_idx,
                .offset = self.crypto_send_offset[out_idx],
                .data = copy,
            };
            self.crypto_send_offset[out_idx] += drain_len;
            // Shift the outbox left to drop what we just consumed.
            const remaining = self.outbox[out_idx].len - drain_len;
            std.mem.copyForwards(
                u8,
                self.outbox[out_idx].buf[0..remaining],
                self.outbox[out_idx].buf[drain_len..self.outbox[out_idx].len],
            );
            self.outbox[out_idx].len = remaining;
            ack_eliciting = true;
        }

        // 2a) MAX_DATA / MAX_STREAM_DATA (application only). We queue these
        // when the application drains receive buffers so peers can
        // continue uploads beyond their current stream window.
        if (!app_control_blocked and lvl == .application and self.pending_max_data != null) {
            const maximum_data = self.pending_max_data.?;
            const overhead_md: usize = 1 + varint.encodedLen(maximum_data);
            if (max_payload >= pl_pos + overhead_md) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .max_data = .{ .maximum_data = maximum_data },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .max_data = .{ .maximum_data = maximum_data },
                });
                self.pending_max_data = null;
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and self.pending_max_stream_data.items.len > 0) {
            const item = self.pending_max_stream_data.items[0];
            const overhead_msd: usize = 1 +
                varint.encodedLen(item.stream_id) +
                varint.encodedLen(item.maximum_stream_data);
            if (max_payload >= pl_pos + overhead_msd) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .max_stream_data = .{
                        .stream_id = item.stream_id,
                        .maximum_stream_data = item.maximum_stream_data,
                    },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .max_stream_data = .{
                        .stream_id = item.stream_id,
                        .maximum_stream_data = item.maximum_stream_data,
                    },
                });
                _ = self.pending_max_stream_data.orderedRemove(0);
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and (self.pending_max_streams_bidi != null or self.pending_max_streams_uni != null)) {
            const bidi = self.pending_max_streams_bidi != null;
            const maximum_streams = if (bidi) self.pending_max_streams_bidi.? else self.pending_max_streams_uni.?;
            const overhead_ms: usize = 1 + varint.encodedLen(maximum_streams);
            if (max_payload >= pl_pos + overhead_ms) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .max_streams = .{
                        .bidi = bidi,
                        .maximum_streams = maximum_streams,
                    },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .max_streams = .{
                        .bidi = bidi,
                        .maximum_streams = maximum_streams,
                    },
                });
                if (bidi) {
                    self.pending_max_streams_bidi = null;
                } else {
                    self.pending_max_streams_uni = null;
                }
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and self.pending_data_blocked != null) {
            const maximum_data = self.pending_data_blocked.?;
            const overhead_db: usize = 1 + varint.encodedLen(maximum_data);
            if (max_payload >= pl_pos + overhead_db) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .data_blocked = .{ .maximum_data = maximum_data },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .data_blocked = .{ .maximum_data = maximum_data },
                });
                self.pending_data_blocked = null;
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and self.pending_stream_data_blocked.items.len > 0) {
            const item = self.pending_stream_data_blocked.items[0];
            const overhead_sdb: usize = 1 +
                varint.encodedLen(item.stream_id) +
                varint.encodedLen(item.maximum_stream_data);
            if (max_payload >= pl_pos + overhead_sdb) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .stream_data_blocked = item,
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .stream_data_blocked = item,
                });
                _ = self.pending_stream_data_blocked.orderedRemove(0);
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and (self.pending_streams_blocked_bidi != null or self.pending_streams_blocked_uni != null)) {
            const bidi = self.pending_streams_blocked_bidi != null;
            const maximum_streams = if (bidi) self.pending_streams_blocked_bidi.? else self.pending_streams_blocked_uni.?;
            const overhead_sb: usize = 1 + varint.encodedLen(maximum_streams);
            if (max_payload >= pl_pos + overhead_sb) {
                const item: frame_types.StreamsBlocked = .{
                    .bidi = bidi,
                    .maximum_streams = maximum_streams,
                };
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .streams_blocked = item,
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{ .streams_blocked = item });
                if (bidi) {
                    self.pending_streams_blocked_bidi = null;
                } else {
                    self.pending_streams_blocked_uni = null;
                }
                ack_eliciting = true;
            }
        }

        // 2b) NEW_CONNECTION_ID (application only). Advertise spare
        // CIDs so peers can validate/migrate additional paths.
        if (!app_control_blocked and lvl == .application and self.pending_new_connection_ids.items.len > 0) {
            const item = self.pending_new_connection_ids.items[0];
            const overhead_ncid: usize = 1 +
                varint.encodedLen(item.sequence_number) +
                varint.encodedLen(item.retire_prior_to) +
                1 + item.connection_id.len + 16;
            if (max_payload >= pl_pos + overhead_ncid) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .new_connection_id = .{
                        .sequence_number = item.sequence_number,
                        .retire_prior_to = item.retire_prior_to,
                        .connection_id = item.connection_id,
                        .stateless_reset_token = item.stateless_reset_token,
                    },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .new_connection_id = .{
                        .sequence_number = item.sequence_number,
                        .retire_prior_to = item.retire_prior_to,
                        .connection_id = item.connection_id,
                        .stateless_reset_token = item.stateless_reset_token,
                    },
                });
                _ = self.pending_new_connection_ids.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        if (!app_control_blocked and lvl == .application and self.pending_retire_connection_ids.items.len > 0) {
            const item = self.pending_retire_connection_ids.items[0];
            const overhead_rcid: usize = 1 + varint.encodedLen(item.sequence_number);
            if (max_payload >= pl_pos + overhead_rcid) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .retire_connection_id = item,
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .retire_connection_id = item,
                });
                _ = self.pending_retire_connection_ids.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2c) STOP_SENDING (one per packet for now — application only).
        if (!app_control_blocked and lvl == .application and self.pending_stop_sending.items.len > 0) {
            const item = self.pending_stop_sending.items[0];
            const overhead_ss: usize = 1 + varint.encodedLen(item.stream_id) + varint.encodedLen(item.application_error_code);
            if (max_payload >= pl_pos + overhead_ss) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .stop_sending = .{
                        .stream_id = item.stream_id,
                        .application_error_code = item.application_error_code,
                    },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .stop_sending = .{
                        .stream_id = item.stream_id,
                        .application_error_code = item.application_error_code,
                    },
                });
                _ = self.pending_stop_sending.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2d) PATH_RESPONSE / PATH_CHALLENGE (application level only,
        //     RFC 9000 §19.17/19.18). PATH_RESPONSE has the highest
        //     priority on the application path so we don't make the
        //     peer wait through a stream-data backlog.
        var path_response_used_addr_override = false;
        if (!congestion_blocked and lvl == .application and self.pending_path_response != null and
            self.pending_path_response_path_id == app_path.id and pl_pos + 9 <= max_payload)
        {
            if (self.pending_path_response_addr) |addr| {
                path_response_used_addr_override = !Address.eql(addr, app_path.path.peer_addr);
            }
            const tok = self.pending_path_response.?;
            self.poll_addr_override = self.pending_path_response_addr;
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .path_response = .{ .data = tok },
            });
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{
                .path_response = .{ .data = tok },
            });
            self.pending_path_response = null;
            self.pending_path_response_addr = null;
            ack_eliciting = true;
        }
        if (!path_response_used_addr_override and
            !congestion_blocked and lvl == .application and self.pending_path_challenge != null and
            self.pending_path_challenge_path_id == app_path.id and pl_pos + 9 <= max_payload)
        {
            const tok = self.pending_path_challenge.?;
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .path_challenge = .{ .data = tok },
            });
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{
                .path_challenge = .{ .data = tok },
            });
            self.pending_path_challenge = null;
            ack_eliciting = true;
        }

        // 2e) Draft-21 multipath control frames. Coalesce as many as
        //     fit while preserving per-frame retransmit metadata.
        if (!path_response_used_addr_override and !congestion_blocked and lvl == .application) {
            if (try self.emitPendingMultipathFrames(&sent_packet, &pl_buf, &pl_pos, max_payload)) {
                ack_eliciting = true;
            }
        }

        // 2e) RESET_STREAM frames for streams in reset_sent state
        //     whose RESET hasn't been queued yet. Emit at most one
        //     per packet; the loop handles all eventually.
        if (!path_response_used_addr_override and !congestion_blocked and lvl == .application) {
            var rs_it = self.streams.iterator();
            while (rs_it.next()) |entry| {
                const s = entry.value_ptr.*;
                if (s.send.reset) |*ri| {
                    if (ri.queued) continue;
                    const overhead_rs: usize = 1 +
                        varint.encodedLen(s.id) +
                        varint.encodedLen(ri.error_code) +
                        varint.encodedLen(ri.final_size);
                    if (max_payload < pl_pos + overhead_rs) break;
                    const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                        .reset_stream = .{
                            .stream_id = s.id,
                            .application_error_code = ri.error_code,
                            .final_size = ri.final_size,
                        },
                    });
                    pl_pos += wrote;
                    try sent_packet.addRetransmitFrame(self.allocator, .{
                        .reset_stream = .{
                            .stream_id = s.id,
                            .application_error_code = ri.error_code,
                            .final_size = ri.final_size,
                        },
                    });
                    ri.queued = true;
                    ack_eliciting = true;
                    break;
                }
            }
        }

        // 3a) DATAGRAM frame (Application PN space). One queued
        //     payload per packet; LEN-prefixed so DATAGRAM doesn't
        //     have to be the last frame.
        if (!path_response_used_addr_override and !congestion_blocked and (lvl == .application or lvl == .early_data) and self.pending_send_datagrams.items.len > 0) {
            const dg = self.pending_send_datagrams.items[0];
            const dg_overhead: usize = 1 + varint.encodedLen(dg.data.len);
            if (max_payload >= pl_pos + dg_overhead + dg.data.len) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .datagram = .{ .data = dg.data, .has_length = true },
                });
                pl_pos += wrote;
                _ = self.pending_send_datagrams.orderedRemove(0);
                self.pending_send_datagram_bytes -= dg.data.len;
                sent_datagram = .{
                    .id = dg.id,
                    .len = dg.data.len,
                    .path_id = app_path.id,
                };
                self.allocator.free(dg.data);
                ack_eliciting = true;
            }
        }

        // 3b) STREAM frames (Application PN space). Pack as many
        // independent streams as fit; each chunk gets its own
        // connection-local key so ACK/loss can still route precisely.
        const SentStreamChunk = struct {
            stream: *Stream,
            chunk: send_stream_mod.Chunk,
            stream_key: u64,
        };
        var sent_chunks: [sent_packets_mod.max_stream_keys_per_packet]SentStreamChunk = undefined;
        var sent_chunk_count: usize = 0;
        var planned_conn_new_bytes: u64 = 0;
        if (!path_response_used_addr_override and !congestion_blocked and (lvl == .application or lvl == .early_data)) {
            var s_it = self.streams.iterator();
            while (s_it.next()) |entry| {
                if (sent_chunk_count >= sent_chunks.len) break;
                const s = entry.value_ptr.*;
                const stream_overhead: usize = 25;
                if (max_payload <= pl_pos + stream_overhead) break;
                const budget = max_payload - pl_pos - stream_overhead;
                const raw_chunk = s.send.peekChunk(budget) orelse continue;
                const chunk = (try self.limitChunkToSendFlowAfterPlanned(
                    s,
                    raw_chunk,
                    planned_conn_new_bytes,
                )) orelse continue;
                const data_slice = s.send.chunkBytes(chunk);
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .stream = .{
                        .stream_id = s.id,
                        .offset = chunk.offset,
                        .data = data_slice,
                        .has_offset = chunk.offset != 0,
                        .has_length = true,
                        .fin = chunk.fin,
                    },
                });
                pl_pos += wrote;
                sent_chunks[sent_chunk_count] = .{
                    .stream = s,
                    .chunk = chunk,
                    .stream_key = self.nextStreamPacketKey(),
                };
                sent_chunk_count += 1;
                planned_conn_new_bytes +|= streamFlowNewBytes(s, chunk);
                ack_eliciting = true;
            }
        }

        if (pl_pos == 0) return null;

        // 4) Allocate PN at this level, seal at the right header type.
        const pn = pn_space.nextPn() orelse return Error.PnSpaceExhausted;
        const largest_acked = pn_space.largest_acked_sent;
        const n = switch (lvl) {
            .initial => try long_packet_mod.sealInitial(dst, .{
                .dcid = packet_dcid.slice(),
                .scid = packet_scid.slice(),
                .token = if (self.role == .client) self.retry_token.items else &.{},
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
                // Pad client first-flight Initials to 1200 bytes
                // (RFC 9000 §14). We over-pad on every Initial here
                // for simplicity; tightening to "first flight only"
                // is a future scope.
                .pad_to = if (self.role == .client) 1200 else 0,
            }),
            .handshake => try long_packet_mod.sealHandshake(dst, .{
                .dcid = packet_dcid.slice(),
                .scid = packet_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
            }),
            .application => try short_packet_mod.seal1Rtt(dst, .{
                .dcid = packet_dcid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
                .key_phase = self.applicationWriteKeyPhase(),
                .multipath_path_id = if (self.multipathNegotiated()) app_path.id else null,
            }),
            .early_data => try long_packet_mod.sealZeroRtt(dst, .{
                .dcid = packet_dcid.slice(),
                .scid = packet_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
            }),
        };

        // 5) Commit.
        sent_packet.pn = pn;
        sent_packet.bytes = n;
        sent_packet.ack_eliciting = ack_eliciting;
        sent_packet.in_flight = ack_eliciting;
        sent_packet.is_early_data = lvl == .early_data;
        sent_packet.datagram = sent_datagram;
        if (lvl == .application) self.recordApplicationPacketProtected(&sent_packet);
        for (sent_chunks[0..sent_chunk_count]) |sc| {
            try sent_packet.addStreamKey(self.allocator, sc.stream_key);
        }
        if (sent_packet.ack_eliciting) {
            try sent_tracker.record(sent_packet);
            sent_packet_recorded = true;
        } else {
            sent_packet.deinit(self.allocator);
            sent_packet_recorded = true;
        }
        for (sent_chunks[0..sent_chunk_count]) |sc| {
            try sc.stream.send.recordSent(sc.stream_key, sc.chunk);
            self.recordStreamFlowSent(sc.stream, sc.chunk);
        }
        if (sent_crypto_chunk) |sc| {
            try self.sent_crypto[sc.level_idx].append(self.allocator, .{
                .pn = pn,
                .offset = sc.offset,
                .data = sc.data,
            });
            crypto_copy = null;
        }
        if (retx_crypto_index) |idx| {
            const old = self.crypto_retx[out_idx].orderedRemove(idx);
            self.allocator.free(old.data);
        }
        if ((lvl == .application or lvl == .early_data) and
            ack_eliciting and app_path.pto_probe_count > 0)
        {
            app_path.pto_probe_count -= 1;
        }

        // qlog hooks for the outgoing packet.
        self.qlog_packets_sent +|= 1;
        self.qlog_bytes_sent +|= n;
        self.emitPacketSent(lvl, pn, @intCast(n), countFrames(pl_buf[0..pl_pos]));

        return n;
    }

    fn encodeFrameIfFits(
        pl_buf: *[default_mtu]u8,
        pl_pos: *usize,
        max_payload: usize,
        frame: frame_types.Frame,
    ) Error!bool {
        const needed = frame_mod.encodedLen(frame);
        if (max_payload < pl_pos.* + needed) return false;
        const wrote = try frame_mod.encode(pl_buf[pl_pos.*..max_payload], frame);
        pl_pos.* += wrote;
        return true;
    }

    fn emitOnePendingMultipathFrame(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
        pl_buf: *[default_mtu]u8,
        pl_pos: *usize,
        max_payload: usize,
    ) Error!bool {
        if (self.pending_path_abandons.items.len > 0) {
            const item = self.pending_path_abandons.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_abandon = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_abandon = item });
                _ = self.pending_path_abandons.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_path_statuses.items.len > 0) {
            const item = self.pending_path_statuses.items[0];
            const status: frame_types.PathStatus = .{
                .path_id = item.path_id,
                .sequence_number = item.sequence_number,
            };
            const frame: frame_types.Frame = if (item.available)
                .{ .path_status_available = status }
            else
                .{ .path_status_backup = status };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, frame)) {
                try sent_packet.addRetransmitFrame(
                    self.allocator,
                    if (item.available)
                        .{ .path_status_available = status }
                    else
                        .{ .path_status_backup = status },
                );
                _ = self.pending_path_statuses.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_path_new_connection_ids.items.len > 0) {
            const item = self.pending_path_new_connection_ids.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_new_connection_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_new_connection_id = item });
                _ = self.pending_path_new_connection_ids.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_path_retire_connection_ids.items.len > 0) {
            const item = self.pending_path_retire_connection_ids.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_retire_connection_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_retire_connection_id = item });
                _ = self.pending_path_retire_connection_ids.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_max_path_id) |maximum_path_id| {
            const item: frame_types.MaxPathId = .{ .maximum_path_id = maximum_path_id };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .max_path_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .max_path_id = item });
                self.pending_max_path_id = null;
                return true;
            }
        }
        if (self.pending_paths_blocked) |maximum_path_id| {
            const item: frame_types.PathsBlocked = .{ .maximum_path_id = maximum_path_id };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .paths_blocked = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .paths_blocked = item });
                self.pending_paths_blocked = null;
                return true;
            }
        }
        if (self.pending_path_cids_blocked) |item| {
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_cids_blocked = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_cids_blocked = item });
                self.pending_path_cids_blocked = null;
                return true;
            }
        }
        return false;
    }

    fn emitPendingMultipathFrames(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
        pl_buf: *[default_mtu]u8,
        pl_pos: *usize,
        max_payload: usize,
    ) Error!bool {
        var emitted = false;
        const control_budget = sent_packets_mod.max_retransmit_frames - 1;
        while (sent_packet.retransmit_frames.items.len < control_budget) {
            const before = pl_pos.*;
            if (!try self.emitOnePendingMultipathFrame(sent_packet, pl_buf, pl_pos, max_payload)) break;
            emitted = true;
            if (pl_pos.* == before) break;
        }
        return emitted;
    }

    /// Process an incoming UDP datagram. Splits coalesced packets
    /// (RFC 9000 §12.2) and routes each through the matching
    /// per-level decrypt + frame-dispatch path.
    pub fn handle(
        self: *Connection,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!void {
        if (self.pending_close != null or self.closed) return;
        if (bytes.len > self.localUdpPayloadLimit()) {
            self.emitPacketDropped(null, @intCast(bytes.len), .payload_too_large);
            self.close(true, transport_error_protocol_violation, "udp payload exceeds local limit");
            self.emitConnectionStateIfChanged();
            return;
        }
        if (bytes.len > 0) {
            self.last_activity_us = now_us;
            self.qlog_bytes_received +|= bytes.len;
        }
        const incoming_path_id = self.incomingPathId(from);
        self.current_incoming_path_id = incoming_path_id;
        self.current_incoming_addr = from;
        const incoming_path = self.pathForId(incoming_path_id);
        const rebind_addr = self.peerAddressChangeCandidate(incoming_path_id, from);
        const from_migration_rollback_addr = if (from) |addr|
            incoming_path.matchesMigrationRollbackAddress(addr)
        else
            false;
        if (rebind_addr == null) {
            if (!from_migration_rollback_addr) {
                incoming_path.path.onDatagramReceived(bytes.len);
            }
            if (from) |addr| {
                if (!incoming_path.peer_addr_set) incoming_path.setPeerAddress(addr);
            }
        }
        var rebind_recorded = false;
        var pos: usize = 0;
        while (pos < bytes.len) {
            const drain_tls_after_packet = shouldDrainTlsAfterPacket(bytes[pos..]);
            self.last_authenticated_path_id = null;
            const consumed = try self.handleOnePacket(bytes[pos..], now_us);
            if (consumed == 0) break;
            pos += consumed;
            if (!rebind_recorded) {
                if (rebind_addr) |addr| {
                    if (self.last_authenticated_path_id) |path_id| {
                        try self.recordAuthenticatedDatagramAddress(path_id, addr, bytes.len, now_us);
                        rebind_recorded = true;
                    }
                }
            }
            if (self.pending_close != null or self.closed) break;
            if (!drain_tls_after_packet) break;
            // Drain CRYPTO into TLS BETWEEN packets, not just at
            // the end. A coalesced Initial+Handshake datagram
            // delivers the ServerHello at Initial level — we have
            // to feed it to TLS (deriving Handshake keys) before
            // we can decrypt the trailing Handshake packet.
            try self.drainInboxIntoTls();
        }
        if (self.cryptoInboxQueued()) try self.drainInboxIntoTls();

        // PATH_CHALLENGE → record-and-tick; the validator will
        // either succeed (echo arrived) or time out at PTO * 3.
        for (self.paths.paths.items) |*path| {
            path.path.validator.tick(now_us);
            if (path.path.validator.status == .failed) {
                self.handlePathValidationFailure(path);
            }
        }
        if (self.alert) |_| return error.PeerAlerted;
    }

    fn localUdpPayloadLimit(self: *const Connection) usize {
        return @intCast(@min(self.local_transport_params.max_udp_payload_size, max_supported_udp_payload_size));
    }

    fn shouldDrainTlsAfterPacket(bytes: []const u8) bool {
        if (bytes.len < 1) return false;
        if ((bytes[0] & 0x80) == 0) return false;
        if (bytes.len >= 5 and std.mem.readInt(u32, bytes[1..5], .big) == 0) return false;
        const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
        return long_type_bits != @intFromEnum(wire_header.LongType.retry);
    }

    /// Initiate path validation by queueing a PATH_CHALLENGE on
    /// the next outgoing 1-RTT packet. `timeout_us` is typically
    /// `3 * pto` per RFC 9000 §8.2.4. Returns the token.
    pub fn probePath(
        self: *Connection,
        token: [8]u8,
        now_us: u64,
        timeout_us: u64,
    ) Error!void {
        try self.probePathId(0, token, now_us, timeout_us);
    }

    /// As `probePath` but for an explicit `path_id`. Returns
    /// `error.PathNotFound` if the id is unknown.
    pub fn probePathId(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
        now_us: u64,
        timeout_us: u64,
    ) Error!void {
        const path = self.paths.get(path_id) orelse return Error.PathNotFound;
        path.path.validator.beginChallenge(token, now_us, timeout_us);
        self.queuePathChallengeOnPath(path_id, token);
    }

    /// Queue an application-level PING on the primary path. This is
    /// useful for embedders that need an explicit liveness probe even
    /// when they have no stream or datagram bytes to send.
    pub fn requestPing(self: *Connection) void {
        if (self.closeState() != .open) return;
        self.primaryPath().pending_ping = true;
    }

    /// Queue an application-level PING on a specific path.
    pub fn requestPathPing(self: *Connection, path_id: u32) Error!void {
        if (self.closeState() != .open) return;
        const path = self.paths.get(path_id) orelse return Error.PathNotFound;
        if (path.path.state == .failed or path.path.state == .retiring) return Error.PathNotFound;
        path.pending_ping = true;
    }

    /// True iff the active path has been validated (either via the
    /// validator's PATH_RESPONSE flow or by `markPathValidated`).
    pub fn isPathValidated(self: *const Connection) bool {
        return self.primaryPathConst().path.validator.isValidated();
    }

    /// Current public shutdown state.
    pub fn closeState(self: *const Connection) CloseState {
        if (self.draining_deadline_us != null) return .draining;
        if (self.pending_close != null) return .closing;
        if (self.closed) return .closed;
        return .open;
    }

    /// True after we've sent or received CONNECTION_CLOSE, received a
    /// stateless reset, or timed out. Use `closeState` to distinguish
    /// closing, draining, and terminal closed states.
    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    fn closeErrorSpace(is_transport: bool) CloseErrorSpace {
        return if (is_transport) .transport else .application;
    }

    fn recordCloseEvent(
        self: *Connection,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        at_us: ?u64,
        draining_deadline_us: ?u64,
    ) void {
        if (self.close_event != null) return;
        const reason_len = @min(reason.len, max_close_reason_len);
        if (reason_len > 0) {
            @memcpy(self.close_reason_buf[0..reason_len], reason[0..reason_len]);
        }
        self.close_event = .{
            .source = source,
            .error_space = error_space,
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_len = reason_len,
            .reason_truncated = reason.len > reason_len,
            .at_us = at_us,
            .draining_deadline_us = draining_deadline_us,
        };
    }

    fn updateCloseEventDrainingDeadline(self: *Connection, deadline_us: u64) void {
        if (self.close_event) |*event| {
            event.draining_deadline_us = deadline_us;
        }
    }

    fn enterDraining(
        self: *Connection,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_us: u64,
    ) void {
        const draining_deadline = now_us +| self.drainingDurationUs();
        self.recordCloseEvent(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
            draining_deadline,
        );
        self.pending_close = null;
        self.closed = true;
        self.draining_deadline_us = draining_deadline;
        self.clearPendingPings();
        self.emitConnectionStateIfChanged();
    }

    fn finishDraining(self: *Connection) void {
        self.pending_close = null;
        self.draining_deadline_us = null;
        self.closed = true;
        self.clearRecoveryState();
        self.emitConnectionStateIfChanged();
    }

    fn enterClosed(
        self: *Connection,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_us: u64,
    ) void {
        self.recordCloseEvent(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
            null,
        );
        self.pending_close = null;
        self.draining_deadline_us = null;
        self.closed = true;
        self.clearRecoveryState();
        self.emitConnectionStateIfChanged();
    }

    fn enterStatelessReset(self: *Connection, now_us: u64) void {
        self.enterDraining(
            .stateless_reset,
            .transport,
            0,
            0,
            "stateless reset",
            now_us,
        );
    }

    fn closeEventFromStored(self: *const Connection, event: StoredCloseEvent) CloseEvent {
        return .{
            .source = event.source,
            .error_space = event.error_space,
            .error_code = event.error_code,
            .frame_type = event.frame_type,
            .reason = self.close_reason_buf[0..event.reason_len],
            .reason_truncated = event.reason_truncated,
            .at_us = event.at_us,
            .draining_deadline_us = event.draining_deadline_us,
        };
    }

    /// Sticky close/error status for embedders. This remains available
    /// after `pollEvent` consumes the event notification.
    pub fn closeEvent(self: *const Connection) ?CloseEvent {
        const event = self.close_event orelse return null;
        return self.closeEventFromStored(event);
    }

    /// Poll the next connection-level event.
    pub fn pollEvent(self: *Connection) ?ConnectionEvent {
        if (self.close_event) |*event| {
            if (!event.delivered) {
                const out = self.closeEventFromStored(event.*);
                event.delivered = true;
                return .{ .close = out };
            }
        }
        if (self.flow_blocked_events.pop()) |out| {
            return .{ .flow_blocked = out };
        }
        if (self.connection_id_events.pop()) |out| {
            return .{ .connection_ids_needed = out };
        }
        if (self.datagram_send_events.pop()) |out| {
            return switch (out) {
                .acked => |event| .{ .datagram_acked = event },
                .lost => |event| .{ .datagram_lost = event },
            };
        }
        return null;
    }

    /// Queue a CONNECTION_CLOSE frame (RFC 9000 §19.19) for the
    /// next outgoing packet. `is_transport` selects between
    /// transport (0x1c) and application (0x1d) error spaces.
    pub fn close(
        self: *Connection,
        is_transport: bool,
        error_code: u64,
        reason: []const u8,
    ) void {
        if (self.pending_close != null or self.closed) return;
        self.recordCloseEvent(
            .local,
            closeErrorSpace(is_transport),
            error_code,
            0,
            reason,
            null,
            null,
        );
        self.pending_close = .{
            .is_transport = is_transport,
            .error_code = error_code,
            .reason = reason,
        };
        self.emitConnectionStateIfChanged();
    }

    /// Queue a STOP_SENDING for `stream_id` with the given app
    /// error code (RFC 9000 §19.5). Tells the peer to stop
    /// sending on the receiving half of the stream.
    pub fn streamStopSending(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.queueStopSending(.{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        });
    }

    fn queueStopSending(
        self: *Connection,
        item: StopSendingItem,
    ) Error!void {
        for (self.pending_stop_sending.items) |queued| {
            if (queued.stream_id == item.stream_id and
                queued.application_error_code == item.application_error_code)
            {
                return;
            }
        }
        try self.pending_stop_sending.append(self.allocator, .{
            .stream_id = item.stream_id,
            .application_error_code = item.application_error_code,
        });
    }

    /// Number of peer-issued connection IDs we currently have
    /// stashed via NEW_CONNECTION_ID frames.
    pub fn peerCidsCount(self: *const Connection) usize {
        return self.peer_cids.items.len;
    }

    fn handleOnePacket(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        if (bytes.len < 1) return 0;
        const first = bytes[0];

        if (first & 0x80 == 0) {
            // Short header → 1-RTT, last in datagram.
            return try self.handleShort(bytes, now_us);
        }

        if (bytes.len >= 5 and std.mem.readInt(u32, bytes[1..5], .big) == 0) {
            return self.handleVersionNegotiation(bytes, now_us);
        }

        const long_type_bits: u2 = @intCast((first >> 4) & 0x03);
        return switch (long_type_bits) {
            0 => try self.handleInitial(bytes, now_us),
            1 => try self.handleZeroRtt(bytes, now_us),
            2 => try self.handleHandshake(bytes, now_us),
            3 => try self.handleRetry(bytes, now_us),
        };
    }

    fn frameAckEliciting(f: frame_types.Frame) bool {
        return switch (f) {
            .padding,
            .ack,
            .path_ack,
            .connection_close,
            => false,
            else => true,
        };
    }

    fn packetPayloadAckEliciting(payload: []const u8) bool {
        var it = frame_mod.iter(payload);
        while (it.next() catch return true) |f| {
            if (frameAckEliciting(f)) return true;
        }
        return false;
    }

    fn packetPayloadNeedsImmediateAck(payload: []const u8) bool {
        var it = frame_mod.iter(payload);
        while (it.next() catch return true) |f| {
            switch (f) {
                .stream => |s| if (s.fin) return true,
                .reset_stream,
                .stop_sending,
                => return true,
                else => {},
            }
        }
        return false;
    }

    fn recordApplicationReceivedPacket(
        app_pn_space: *PnSpace,
        pn: u64,
        now_us: u64,
        payload: []const u8,
    ) void {
        const ack_eliciting = packetPayloadAckEliciting(payload);
        if (ack_eliciting and packetPayloadNeedsImmediateAck(payload)) {
            app_pn_space.recordReceivedPacket(pn, now_us / rtt_mod.ms, true);
            return;
        }
        app_pn_space.recordReceivedPacketDelayed(
            pn,
            now_us / rtt_mod.ms,
            ack_eliciting,
            application_ack_eliciting_threshold,
        );
    }

    fn versionListContains(vn: wire_header.VersionNegotiation, version: u32) bool {
        var i: usize = 0;
        while (i < vn.versionCount()) : (i += 1) {
            if (vn.version(i) == version) return true;
        }
        return false;
    }

    fn handleVersionNegotiation(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) usize {
        if (self.role != .client or self.inner.handshakeDone()) return bytes.len;
        const parsed = wire_header.parse(bytes, 0) catch return bytes.len;
        if (parsed.header != .version_negotiation) return bytes.len;
        const vn = parsed.header.version_negotiation;
        if (!self.local_scid_set or !self.initial_dcid_set) return bytes.len;
        if (!std.mem.eql(u8, vn.dcid.slice(), self.local_scid.slice())) return bytes.len;
        const odcid = if (self.original_initial_dcid_set)
            self.original_initial_dcid
        else
            self.initial_dcid;
        if (!std.mem.eql(u8, vn.scid.slice(), odcid.slice())) return bytes.len;
        if (versionListContains(vn, quic_version_1)) return bytes.len;

        self.enterClosed(
            .version_negotiation,
            .transport,
            0,
            0,
            "no compatible QUIC version",
            now_us,
        );
        return bytes.len;
    }

    fn handleShort(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        const app_path = self.incomingShortPath(bytes) orelse
            self.pathForId(self.current_incoming_path_id);
        self.current_incoming_path_id = app_path.id;
        const app_pn_space = &app_path.app_pn_space;
        const largest_received = if (app_pn_space.received.largest) |l| l else 0;
        const multipath_path_id: ?u32 = if (self.multipathNegotiated()) app_path.id else null;
        if (self.app_read_current == null) {
            if (self.isKnownStatelessReset(bytes)) {
                self.emitPacketDropped(.application, @intCast(bytes.len), .stateless_reset);
                self.enterStatelessReset(now_us);
            } else {
                self.emitPacketDropped(.application, @intCast(bytes.len), .keys_unavailable);
            }
            return bytes.len;
        }

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const open_result = (try self.openApplicationPacket(
            &pt_buf,
            bytes,
            app_path,
            largest_received,
            multipath_path_id,
        )) orelse {
            if (self.isKnownStatelessReset(bytes)) {
                self.emitPacketDropped(.application, @intCast(bytes.len), .stateless_reset);
                self.enterStatelessReset(now_us);
                return bytes.len;
            }
            self.emitPacketDropped(.application, @intCast(bytes.len), .decryption_failure);
            self.noteApplicationAuthFailure();
            return bytes.len;
        };
        if (open_result.slot == .next) {
            try self.promoteApplicationReadKeys(now_us);
            try self.maybeRespondToPeerKeyUpdate(now_us);
        }
        const opened = open_result.opened;

        self.last_authenticated_path_id = app_path.id;
        recordApplicationReceivedPacket(app_pn_space, opened.pn, now_us, opened.payload);
        self.qlog_packets_received +|= 1;
        self.emitPacketReceived(.application, opened.pn, @intCast(bytes.len), countFrames(opened.payload));
        try self.dispatchFrames(.application, opened.payload, now_us);
        return bytes.len;
    }

    fn countFrames(payload: []const u8) u32 {
        var count: u32 = 0;
        var it = frame_mod.iter(payload);
        while (it.next() catch return count) |_| {
            count += 1;
        }
        return count;
    }

    fn openApplicationPacket(
        self: *Connection,
        pt_buf: *[max_recv_plaintext]u8,
        bytes: []u8,
        app_path: *const PathState,
        largest_received: u64,
        multipath_path_id: ?u32,
    ) Error!?ApplicationOpenResult {
        if (try self.tryOpenApplicationPacketWithEpoch(
            pt_buf,
            bytes,
            app_path,
            largest_received,
            multipath_path_id,
            self.app_read_current,
            .current,
        )) |result| return result;
        if (try self.tryOpenApplicationPacketWithEpoch(
            pt_buf,
            bytes,
            app_path,
            largest_received,
            multipath_path_id,
            self.app_read_previous,
            .previous,
        )) |result| return result;
        if (self.app_read_next == null) try self.refreshNextApplicationReadKey();
        if (try self.tryOpenApplicationPacketWithEpoch(
            pt_buf,
            bytes,
            app_path,
            largest_received,
            multipath_path_id,
            self.app_read_next,
            .next,
        )) |result| return result;
        return null;
    }

    fn tryOpenApplicationPacketWithEpoch(
        self: *Connection,
        pt_buf: *[max_recv_plaintext]u8,
        bytes: []u8,
        app_path: *const PathState,
        largest_received: u64,
        multipath_path_id: ?u32,
        maybe_epoch: ?ApplicationKeyEpoch,
        slot: ApplicationReadKeySlot,
    ) Error!?ApplicationOpenResult {
        _ = self;
        const epoch = maybe_epoch orelse return null;
        const opened = short_packet_mod.open1Rtt(pt_buf, bytes, .{
            .dcid_len = app_path.path.local_cid.len,
            .keys = &epoch.keys,
            .largest_received = largest_received,
            .multipath_path_id = multipath_path_id,
        }) catch |e| switch (e) {
            boringssl.crypto.aead.Error.Auth => return null,
            else => return e,
        };
        if (opened.key_phase != epoch.key_phase) return null;
        return .{ .opened = opened, .slot = slot };
    }

    fn handleInitial(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        // Server-side bootstrap: discover `initial_dcid` from the
        // unprotected long-header bytes before any decryption can
        // happen. RFC 9001 §5.2 derives Initial keys from the DCID
        // the client put on its first Initial.
        if (self.role == .server and !self.initial_dcid_set) {
            if (bytes.len < 6) {
                self.emitPacketDropped(.initial, @intCast(bytes.len), .header_decode_failure);
                return bytes.len;
            }
            const dcid_len = bytes[5];
            if (dcid_len > path_mod.max_cid_len) {
                self.emitPacketDropped(.initial, @intCast(bytes.len), .header_decode_failure);
                return bytes.len;
            }
            if (bytes.len < @as(usize, 6) + dcid_len) {
                self.emitPacketDropped(.initial, @intCast(bytes.len), .header_decode_failure);
                return bytes.len;
            }
            try self.setInitialDcid(bytes[6 .. 6 + dcid_len]);
        }
        try self.ensureInitialKeys();
        const r_keys_opt = self.initial_keys_read;
        const r_keys = r_keys_opt orelse {
            self.emitPacketDropped(.initial, @intCast(bytes.len), .keys_unavailable);
            return bytes.len;
        };

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const opened = long_packet_mod.openInitial(&pt_buf, bytes, .{
            .keys = &r_keys,
            .largest_received = if (self.pnSpaceForLevel(.initial).received.largest) |l| l else 0,
        }) catch |e| switch (e) {
            boringssl.crypto.aead.Error.Auth => {
                self.emitPacketDropped(.initial, @intCast(bytes.len), .decryption_failure);
                return bytes.len;
            },
            else => return e,
        };

        // Server side: discover peer's CIDs from the very first Initial.
        if (self.role == .server) {
            if (!self.peer_dcid_set) {
                self.peer_dcid = ConnectionId.fromSlice(opened.scid.slice());
                self.peer_dcid_set = true;
            }
            if (!self.initial_dcid_set) {
                self.initial_dcid = ConnectionId.fromSlice(opened.dcid.slice());
                self.initial_dcid_set = true;
                try self.ensureInitialKeys();
            }
            self.emitConnectionStartedOnce();
        }
        if (self.role == .client) {
            const server_scid = ConnectionId.fromSlice(opened.scid.slice());
            if (!ConnectionId.eql(self.primaryPath().path.peer_cid, server_scid)) {
                try self.setPeerDcid(server_scid.slice());
            }
        }

        self.last_authenticated_path_id = self.current_incoming_path_id;
        self.pnSpaceForLevel(.initial).recordReceivedPacket(opened.pn, now_us / 1000, packetPayloadAckEliciting(opened.payload));
        self.qlog_packets_received +|= 1;
        self.emitPacketReceived(.initial, opened.pn, @intCast(opened.bytes_consumed), countFrames(opened.payload));
        try self.dispatchFrames(.initial, opened.payload, now_us);
        return opened.bytes_consumed;
    }

    fn handleRetry(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        _ = now_us;
        if (self.role != .client or self.retry_accepted or self.inner.handshakeDone()) {
            return bytes.len;
        }
        const parsed = wire_header.parse(bytes, 0) catch return bytes.len;
        if (parsed.header != .retry) return bytes.len;
        const retry = parsed.header.retry;
        if (retry.version != quic_version_1) return bytes.len;
        if (!self.local_scid_set or !self.initial_dcid_set) return bytes.len;
        if (!std.mem.eql(u8, retry.dcid.slice(), self.local_scid.slice())) return bytes.len;

        const odcid = if (self.original_initial_dcid_set)
            self.original_initial_dcid
        else
            self.initial_dcid;
        if (std.mem.eql(u8, retry.scid.slice(), odcid.slice())) {
            return bytes.len;
        }
        const retry_valid = long_packet_mod.validateRetryIntegrity(odcid.slice(), bytes) catch return bytes.len;
        if (!retry_valid) {
            return bytes.len;
        }

        try self.retry_token.resize(self.allocator, retry.retry_token.len);
        @memcpy(self.retry_token.items, retry.retry_token);
        self.retry_source_cid = ConnectionId.fromSlice(retry.scid.slice());
        self.retry_source_cid_set = true;
        self.retry_accepted = true;

        try self.setPeerDcid(retry.scid.slice());
        try self.setInitialDcid(retry.scid.slice());
        try self.resetInitialRecoveryForRetry();
        return bytes.len;
    }

    fn handleZeroRtt(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        if (self.role != .server) {
            self.emitPacketDropped(.early_data, @intCast(bytes.len), .other);
            return bytes.len;
        }
        if (self.inner.earlyDataStatus() == .rejected) {
            self.emitPacketDropped(.early_data, @intCast(bytes.len), .keys_unavailable);
            return bytes.len;
        }

        const r_keys_opt = try self.packetKeys(.early_data, .read);
        const r_keys = r_keys_opt orelse {
            self.emitPacketDropped(.early_data, @intCast(bytes.len), .keys_unavailable);
            return bytes.len;
        };
        const app_path = self.pathForId(self.current_incoming_path_id);
        const app_pn_space = &app_path.app_pn_space;
        const largest_received = if (app_pn_space.received.largest) |l| l else 0;

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const opened = long_packet_mod.openZeroRtt(&pt_buf, bytes, .{
            .keys = &r_keys,
            .largest_received = largest_received,
        }) catch |e| switch (e) {
            boringssl.crypto.aead.Error.Auth => {
                self.emitPacketDropped(.early_data, @intCast(bytes.len), .decryption_failure);
                return bytes.len;
            },
            else => return e,
        };

        self.last_authenticated_path_id = app_path.id;
        recordApplicationReceivedPacket(app_pn_space, opened.pn, now_us, opened.payload);
        self.qlog_packets_received +|= 1;
        self.emitPacketReceived(.early_data, opened.pn, @intCast(opened.bytes_consumed), countFrames(opened.payload));
        try self.dispatchFrames(.early_data, opened.payload, now_us);
        return opened.bytes_consumed;
    }

    fn handleHandshake(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        const r_keys_opt = try self.packetKeys(.handshake, .read);
        const r_keys = r_keys_opt orelse {
            self.emitPacketDropped(.handshake, @intCast(bytes.len), .keys_unavailable);
            return bytes.len;
        };

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const opened = long_packet_mod.openHandshake(&pt_buf, bytes, .{
            .keys = &r_keys,
            .largest_received = if (self.pnSpaceForLevel(.handshake).received.largest) |l| l else 0,
        }) catch |e| switch (e) {
            boringssl.crypto.aead.Error.Auth => {
                self.emitPacketDropped(.handshake, @intCast(bytes.len), .decryption_failure);
                return bytes.len;
            },
            else => return e,
        };

        self.last_authenticated_path_id = self.current_incoming_path_id;
        self.pnSpaceForLevel(.handshake).recordReceivedPacket(opened.pn, now_us / 1000, packetPayloadAckEliciting(opened.payload));
        self.qlog_packets_received +|= 1;
        self.emitPacketReceived(.handshake, opened.pn, @intCast(opened.bytes_consumed), countFrames(opened.payload));
        try self.dispatchFrames(.handshake, opened.payload, now_us);
        return opened.bytes_consumed;
    }

    fn dispatchFrames(
        self: *Connection,
        lvl: EncryptionLevel,
        payload: []const u8,
        now_us: u64,
    ) Error!void {
        if (debugFrames() != null) {
            std.debug.print("[frames lvl={s} payload_len={d}] ", .{ @tagName(lvl), payload.len });
        }
        var it = frame_mod.iter(payload);
        while (try it.next()) |f| {
            if (debugFrames() != null) {
                switch (f) {
                    .crypto => |cr| std.debug.print("CRYPTO(off={d},len={d}) ", .{ cr.offset, cr.data.len }),
                    .padding => |p| std.debug.print("PADDING(n={d}) ", .{p.count}),
                    .ack => |a| std.debug.print("ACK(la={d}) ", .{a.largest_acked}),
                    .path_ack => |a| std.debug.print("PATH_ACK(path={d},la={d}) ", .{ a.path_id, a.largest_acked }),
                    .stream => |s| std.debug.print("STREAM(id={d},off={d},len={d},fin={}) ", .{ s.stream_id, s.offset, s.data.len, s.fin }),
                    .datagram => |d| std.debug.print("DATAGRAM(len={d}) ", .{d.data.len}),
                    .reset_stream => |r| std.debug.print("RESET_STREAM(id={d},code={d},final={d}) ", .{ r.stream_id, r.application_error_code, r.final_size }),
                    .path_abandon => |pa| std.debug.print("PATH_ABANDON(path={d},code={d}) ", .{ pa.path_id, pa.error_code }),
                    .path_status_backup => |ps| std.debug.print("PATH_STATUS_BACKUP(path={d},seq={d}) ", .{ ps.path_id, ps.sequence_number }),
                    .path_status_available => |ps| std.debug.print("PATH_STATUS_AVAILABLE(path={d},seq={d}) ", .{ ps.path_id, ps.sequence_number }),
                    .path_new_connection_id => |nc| std.debug.print("PATH_NEW_CONNECTION_ID(path={d},seq={d}) ", .{ nc.path_id, nc.sequence_number }),
                    .path_retire_connection_id => |rc| std.debug.print("PATH_RETIRE_CONNECTION_ID(path={d},seq={d}) ", .{ rc.path_id, rc.sequence_number }),
                    .max_path_id => |mp| std.debug.print("MAX_PATH_ID(max={d}) ", .{mp.maximum_path_id}),
                    .paths_blocked => |pb| std.debug.print("PATHS_BLOCKED(max={d}) ", .{pb.maximum_path_id}),
                    .path_cids_blocked => |pcb| std.debug.print("PATH_CIDS_BLOCKED(path={d},next={d}) ", .{ pcb.path_id, pcb.next_sequence_number }),
                    .ping => std.debug.print("PING ", .{}),
                    else => |x| std.debug.print("{s} ", .{@tagName(x)}),
                }
            }
            if (lvl == .early_data and !frameAllowedInEarlyData(f)) {
                self.close(true, transport_error_protocol_violation, "forbidden frame in 0-RTT");
                return;
            }
            if (lvl != .application and isMultipathFrame(f)) {
                self.close(true, transport_error_protocol_violation, "multipath frame outside 1-RTT");
                return;
            }
            if (lvl == .application and isMultipathFrame(f) and !self.multipathNegotiated()) {
                self.close(true, transport_error_protocol_violation, "multipath frame without negotiation");
                return;
            }
            if (lvl == .application and isMultipathFrame(f) and
                !self.validateIncomingMultipathFrame(f))
            {
                return;
            }
            switch (f) {
                .padding, .ping, .handshake_done => {},
                .ack => |a| try self.handleAckAtLevel(lvl, a, now_us),
                .path_ack => |a| try self.handlePathAck(a, now_us),
                .crypto => |cr| try self.handleCrypto(lvl, cr),
                .stream => |s| try self.handleStream(lvl, s),
                .reset_stream => |rs| try self.handleResetStream(rs),
                .datagram => |dg| try self.handleDatagram(lvl, dg),
                .path_challenge => |pc| self.queuePathResponseOnPath(
                    self.current_incoming_path_id,
                    pc.data,
                    self.current_incoming_addr,
                ),
                .path_response => |pr| self.recordPathResponse(self.current_incoming_path_id, pr.data),
                .new_connection_id => |nc| try self.handleNewConnectionId(nc),
                .stop_sending => |ss| try self.handleStopSending(ss),
                .path_abandon => |pa| self.handlePathAbandon(pa, now_us),
                .path_status_backup => |ps| self.handlePathStatus(ps, false),
                .path_status_available => |ps| self.handlePathStatus(ps, true),
                .path_new_connection_id => |nc| try self.handlePathNewConnectionId(nc),
                .path_retire_connection_id => |rc| self.handlePathRetireConnectionId(rc),
                .max_path_id => |mp| self.handleMaxPathId(mp),
                .paths_blocked => |pb| self.handlePathsBlocked(pb),
                .path_cids_blocked => |pcb| self.handlePathCidsBlocked(pcb),
                .max_data => |md| self.handleMaxData(md),
                .max_stream_data => |msd| self.handleMaxStreamData(msd),
                .max_streams => |ms| self.handleMaxStreams(ms),
                .data_blocked => |db| self.handleDataBlocked(db),
                .stream_data_blocked => |sdb| try self.handleStreamDataBlocked(sdb),
                .streams_blocked => |sb| self.handleStreamsBlocked(sb),
                .connection_close => |cc| {
                    self.enterDraining(
                        .peer,
                        closeErrorSpace(cc.is_transport),
                        cc.error_code,
                        if (cc.is_transport) cc.frame_type else 0,
                        cc.reason_phrase,
                        now_us,
                    );
                },
                .retire_connection_id => |rc| self.handleRetireConnectionId(rc),
                .new_token => {},
            }
        }
        if (debugFrames() != null) {
            std.debug.print("\n", .{});
        }
    }

    fn isMultipathFrame(f: frame_types.Frame) bool {
        return switch (f) {
            .path_ack,
            .path_abandon,
            .path_status_backup,
            .path_status_available,
            .path_new_connection_id,
            .path_retire_connection_id,
            .max_path_id,
            .paths_blocked,
            .path_cids_blocked,
            => true,
            else => false,
        };
    }

    fn frameAllowedInEarlyData(f: frame_types.Frame) bool {
        return switch (f) {
            .ack,
            .crypto,
            .handshake_done,
            .new_token,
            .path_response,
            .retire_connection_id,
            => false,
            else => true,
        };
    }

    fn tokenEql(a: [16]u8, b: [16]u8) bool {
        // RFC 9000 §10.3 — stateless reset tokens MUST be compared in
        // constant time. A peer that observes timing differences across
        // mismatching prefixes can incrementally guess valid tokens.
        return std.crypto.timing_safe.eql([16]u8, a, b);
    }

    fn statelessResetTokenFromDatagram(bytes: []const u8) ?[16]u8 {
        if (bytes.len < 21) return null;
        if ((bytes[0] & 0x80) != 0) return null;
        var token: [16]u8 = undefined;
        @memcpy(&token, bytes[bytes.len - 16 ..]);
        return token;
    }

    fn isKnownStatelessReset(self: *const Connection, bytes: []const u8) bool {
        const token = statelessResetTokenFromDatagram(bytes) orelse return false;
        for (self.peer_cids.items) |item| {
            if (tokenEql(item.stateless_reset_token, token)) return true;
        }
        return false;
    }

    fn pathIdAllowedByLocalLimit(self: *Connection, path_id: u32) bool {
        if (path_id <= self.local_max_path_id) return true;
        self.close(true, transport_error_protocol_violation, "multipath path id exceeds local limit");
        return false;
    }

    fn validateIncomingMultipathFrame(self: *Connection, f: frame_types.Frame) bool {
        return switch (f) {
            .path_ack => |pa| self.pathIdAllowedByLocalLimit(pa.path_id),
            .path_abandon => |pa| self.pathIdAllowedByLocalLimit(pa.path_id),
            .path_status_backup => |ps| self.pathIdAllowedByLocalLimit(ps.path_id),
            .path_status_available => |ps| self.pathIdAllowedByLocalLimit(ps.path_id),
            .path_new_connection_id => |nc| self.pathIdAllowedByLocalLimit(nc.path_id),
            .path_retire_connection_id => |rc| self.pathIdAllowedByLocalLimit(rc.path_id),
            .paths_blocked => |pb| self.pathIdAllowedByLocalLimit(pb.maximum_path_id),
            .path_cids_blocked => |pcb| blk: {
                if (!self.pathIdAllowedByLocalLimit(pcb.path_id)) break :blk false;
                const next = self.nextLocalCidSequence(pcb.path_id);
                if (pcb.next_sequence_number > next) {
                    self.close(true, transport_error_protocol_violation, "path cids blocked skips local cid sequence");
                    break :blk false;
                }
                break :blk true;
            },
            .max_path_id => |mp| blk: {
                if (self.cached_peer_transport_params) |params| {
                    if (params.initial_max_path_id) |initial_max_path_id| {
                        if (mp.maximum_path_id < initial_max_path_id) {
                            self.close(true, transport_error_protocol_violation, "max path id below peer initial limit");
                            break :blk false;
                        }
                    }
                }
                break :blk true;
            },
            else => true,
        };
    }

    fn peerCidActiveCountForPath(self: *const Connection, path_id: u32) usize {
        var count: usize = 0;
        for (self.peer_cids.items) |item| {
            if (item.path_id == path_id) count += 1;
        }
        return count;
    }

    fn promotePeerCidForPath(self: *Connection, path_id: u32) void {
        const path = self.paths.get(path_id) orelse return;
        path.path.peer_cid = .{};
        for (self.peer_cids.items) |item| {
            if (item.path_id == path_id) {
                path.path.peer_cid = item.cid;
                break;
            }
        }
        if (path_id == 0) {
            self.peer_dcid = path.path.peer_cid;
            self.peer_dcid_set = self.peer_dcid.len != 0;
        }
    }

    fn retirePeerCidsPriorTo(
        self: *Connection,
        path_id: u32,
        retire_prior_to: u64,
    ) void {
        var i: usize = 0;
        var affected_current = false;
        const current = if (self.paths.get(path_id)) |path| path.path.peer_cid else ConnectionId{};
        while (i < self.peer_cids.items.len) {
            const item = self.peer_cids.items[i];
            if (item.path_id == path_id and item.sequence_number < retire_prior_to) {
                if (ConnectionId.eql(item.cid, current)) affected_current = true;
                _ = self.peer_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        if (affected_current) self.promotePeerCidForPath(path_id);
    }

    fn retirePeerCidsForPath(self: *Connection, path_id: u32) void {
        var i: usize = 0;
        while (i < self.peer_cids.items.len) {
            if (self.peer_cids.items[i].path_id == path_id) {
                _ = self.peer_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        self.promotePeerCidForPath(path_id);
    }

    fn registerPeerCid(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [16]u8,
    ) Error!void {
        if (retire_prior_to > sequence_number) {
            self.close(true, transport_error_protocol_violation, "invalid connection id retire_prior_to");
            return;
        }
        if (self.multipathNegotiated() and !self.pathIdAllowedByLocalLimit(path_id)) return;

        for (self.peer_cids.items) |*item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                if (!ConnectionId.eql(item.cid, cid) or
                    !tokenEql(item.stateless_reset_token, stateless_reset_token))
                {
                    self.close(true, transport_error_protocol_violation, "connection id sequence reused");
                    return;
                }
                if (retire_prior_to > item.retire_prior_to) {
                    item.retire_prior_to = retire_prior_to;
                    self.retirePeerCidsPriorTo(path_id, retire_prior_to);
                }
                return;
            }
            if (cid.len != 0 and ConnectionId.eql(item.cid, cid)) {
                self.close(true, transport_error_protocol_violation, "connection id reused across paths");
                return;
            }
        }

        self.retirePeerCidsPriorTo(path_id, retire_prior_to);
        const active_limit = self.local_transport_params.active_connection_id_limit;
        if (@as(u64, @intCast(self.peerCidActiveCountForPath(path_id))) >= active_limit) {
            self.close(true, transport_error_protocol_violation, "active connection id limit exceeded");
            return;
        }
        try self.peer_cids.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .cid = cid,
            .stateless_reset_token = stateless_reset_token,
        });
        if (self.paths.get(path_id)) |path| {
            if (path.path.peer_cid.len == 0 or sequence_number == 0) {
                path.path.peer_cid = cid;
            }
        }
        if (path_id == 0 and (self.peer_dcid.len == 0 or sequence_number == 0)) {
            self.peer_dcid = cid;
            self.peer_dcid_set = true;
        }
    }

    fn handleNewConnectionId(
        self: *Connection,
        nc: frame_types.NewConnectionId,
    ) Error!void {
        const cid = ConnectionId.fromSlice(nc.connection_id.slice());
        try self.registerPeerCid(0, nc.sequence_number, nc.retire_prior_to, cid, nc.stateless_reset_token);
    }

    fn handleRetireConnectionId(
        self: *Connection,
        rc: frame_types.RetireConnectionId,
    ) void {
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
        self.retireLocalCidFromPeer(0, rc.sequence_number);
        self.dropPendingLocalCidAdvertisement(0, rc.sequence_number);
    }

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

    fn handlePathAck(
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

    fn handlePathAbandon(
        self: *Connection,
        pa: frame_types.PathAbandon,
        now_us: u64,
    ) void {
        _ = self.retirePath(pa.path_id, pa.error_code, now_us, true);
    }

    fn handlePathStatus(
        self: *Connection,
        ps: frame_types.PathStatus,
        available: bool,
    ) void {
        const path = self.paths.get(ps.path_id) orelse return;
        path.recordPeerStatus(available, ps.sequence_number);
    }

    fn handlePathNewConnectionId(
        self: *Connection,
        nc: frame_types.PathNewConnectionId,
    ) Error!void {
        const cid = ConnectionId.fromSlice(nc.connection_id.slice());
        try self.registerPeerCid(nc.path_id, nc.sequence_number, nc.retire_prior_to, cid, nc.stateless_reset_token);
    }

    fn handlePathRetireConnectionId(
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

    fn handleMaxPathId(self: *Connection, mp: frame_types.MaxPathId) void {
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

    fn handlePathsBlocked(self: *Connection, pb: frame_types.PathsBlocked) void {
        if (!self.pathIdAllowedByLocalLimit(pb.maximum_path_id)) return;
        if (pb.maximum_path_id < self.local_max_path_id) return;
        self.peer_paths_blocked_at = pb.maximum_path_id;
    }

    fn handlePathCidsBlocked(self: *Connection, pcb: frame_types.PathCidsBlocked) void {
        if (!self.pathIdAllowedByLocalLimit(pcb.path_id)) return;
        const next = self.nextLocalCidSequence(pcb.path_id);
        if (pcb.next_sequence_number > next) {
            self.close(true, transport_error_protocol_violation, "path cids blocked skips local cid sequence");
            return;
        }
        self.peer_path_cids_blocked_path_id = pcb.path_id;
        self.peer_path_cids_blocked_next_sequence = pcb.next_sequence_number;
        self.recordConnectionIdsNeeded(pcb.path_id, .path_cids_blocked, pcb.next_sequence_number);
    }

    fn handleStopSending(
        self: *Connection,
        ss: frame_types.StopSending,
    ) Error!void {
        const ptr = self.streams.get(ss.stream_id) orelse return;
        try ptr.send.resetStream(ss.application_error_code);
    }

    fn handleMaxData(self: *Connection, md: frame_types.MaxData) void {
        if (md.maximum_data > self.peer_max_data) {
            self.peer_max_data = md.maximum_data;
            self.clearLocalDataBlocked(md.maximum_data);
        }
    }

    fn handleMaxStreamData(self: *Connection, msd: frame_types.MaxStreamData) void {
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

    fn handleMaxStreams(self: *Connection, ms: frame_types.MaxStreams) void {
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

    fn handleDataBlocked(self: *Connection, db: frame_types.DataBlocked) void {
        self.peer_data_blocked_at = db.maximum_data;
        self.recordFlowBlockedEvent(.{
            .source = .peer,
            .kind = .data,
            .limit = db.maximum_data,
        });
    }

    fn handleStreamDataBlocked(self: *Connection, sdb: frame_types.StreamDataBlocked) Error!void {
        if (!self.peerMaySendOnStream(sdb.stream_id)) {
            self.close(true, transport_error_stream_state, "stream data blocked for receive-only stream");
            return;
        }
        const idx = streamIndex(sdb.stream_id);
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

    fn handleStreamsBlocked(self: *Connection, sb: frame_types.StreamsBlocked) void {
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

    fn handleDatagram(
        self: *Connection,
        lvl: EncryptionLevel,
        dg: frame_types.Datagram,
    ) Error!void {
        const local_max = self.local_transport_params.max_datagram_frame_size;
        if (local_max == 0 or dg.data.len > local_max or dg.data.len > max_supported_udp_payload_size) {
            self.close(true, transport_error_protocol_violation, "datagram exceeds local limit");
            return;
        }
        if (self.pending_recv_datagrams.items.len >= max_pending_datagram_count) {
            self.close(true, transport_error_protocol_violation, "datagram receive queue exhausted");
            return;
        }
        if (dg.data.len > max_pending_datagram_bytes or
            self.pending_recv_datagram_bytes > max_pending_datagram_bytes - dg.data.len)
        {
            self.close(true, transport_error_protocol_violation, "datagram receive budget exhausted");
            return;
        }
        const copy = try self.allocator.alloc(u8, dg.data.len);
        errdefer self.allocator.free(copy);
        @memcpy(copy, dg.data);
        try self.pending_recv_datagrams.append(self.allocator, .{
            .data = copy,
            .arrived_in_early_data = lvl == .early_data,
        });
        self.pending_recv_datagram_bytes += dg.data.len;
    }

    fn handleCrypto(
        self: *Connection,
        lvl: EncryptionLevel,
        cr: frame_types.Crypto,
    ) Error!void {
        const idx = lvl.idx();
        if (cr.data.len == 0) return;

        const start = cr.offset;
        const data_len: u64 = @intCast(cr.data.len);
        const end = std.math.add(u64, cr.offset, data_len) catch {
            self.close(true, transport_error_protocol_violation, "crypto offset overflow");
            return;
        };
        const my_off = self.crypto_recv_offset[idx];

        // Already delivered → ignore (retransmit / overlap).
        if (end <= my_off) return;

        // Clip any prefix that was already delivered.
        const data_start: usize = if (start < my_off)
            @intCast(my_off - start)
        else
            0;
        const eff_offset: u64 = @max(start, my_off);
        const eff_data = cr.data[data_start..];

        if (eff_offset == my_off) {
            try self.inbox[idx].append(eff_data);
            self.crypto_recv_offset[idx] += eff_data.len;
            try self.drainPendingCrypto(idx);
        } else {
            // Out-of-order — buffer.
            if (eff_offset - my_off > max_crypto_reassembly_gap) {
                self.close(true, transport_error_protocol_violation, "crypto reassembly gap exceeds limit");
                return;
            }
            if (eff_data.len > max_pending_crypto_bytes_per_level or
                self.crypto_pending_bytes[idx] > max_pending_crypto_bytes_per_level - eff_data.len)
            {
                self.close(true, transport_error_protocol_violation, "crypto reassembly exceeds limit");
                return;
            }
            const copy = try self.allocator.alloc(u8, eff_data.len);
            errdefer self.allocator.free(copy);
            @memcpy(copy, eff_data);
            try self.crypto_pending[idx].append(self.allocator, .{
                .offset = eff_offset,
                .data = copy,
            });
            self.crypto_pending_bytes[idx] += eff_data.len;
        }
    }

    fn drainPendingCrypto(self: *Connection, idx: usize) Error!void {
        // Repeatedly find a pending chunk that starts at our floor
        // (or below it, in which case we clip), deliver it, and
        // bump the floor — until no chunk matches.
        outer: while (self.crypto_pending[idx].items.len > 0) {
            const my_off = self.crypto_recv_offset[idx];
            var i: usize = 0;
            while (i < self.crypto_pending[idx].items.len) : (i += 1) {
                const chunk = self.crypto_pending[idx].items[i];
                const c_end = std.math.add(u64, chunk.offset, @as(u64, @intCast(chunk.data.len))) catch {
                    self.close(true, transport_error_protocol_violation, "crypto pending offset overflow");
                    return;
                };
                if (c_end <= my_off) {
                    // Wholly below the floor — drop.
                    self.crypto_pending_bytes[idx] -= chunk.data.len;
                    self.allocator.free(chunk.data);
                    _ = self.crypto_pending[idx].orderedRemove(i);
                    continue :outer;
                }
                if (chunk.offset <= my_off) {
                    // Bridges the floor — deliver the new portion.
                    const skip: usize = @intCast(my_off - chunk.offset);
                    const tail = chunk.data[skip..];
                    try self.inbox[idx].append(tail);
                    self.crypto_recv_offset[idx] += tail.len;
                    self.crypto_pending_bytes[idx] -= chunk.data.len;
                    self.allocator.free(chunk.data);
                    _ = self.crypto_pending[idx].orderedRemove(i);
                    continue :outer;
                }
            }
            // No chunk reaches the floor → done.
            break;
        }
    }

    fn cryptoInboxQueued(self: *const Connection) bool {
        inline for (level_mod.all) |lvl| {
            if (self.inbox[lvl.idx()].len > 0) return true;
        }
        return false;
    }

    fn drainInboxIntoTls(self: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const idx = lvl.idx();
            if (self.inbox[idx].len > 0) {
                const bytes = self.inbox[idx].drain();
                try self.inner.provideQuicData(lvl.toBoringssl(), bytes);
                if (self.inner.handshakeDone()) {
                    try self.cachePeerTransportParams();
                    try self.inner.processQuicPostHandshake();
                } else {
                    try self.advanceHandshake();
                }
            }
        }
        if (!self.inner.handshakeDone()) try self.advanceHandshake();
        if (self.inner.handshakeDone()) try self.cachePeerTransportParams();
        self.queueHandshakeDoneIfReady();
        try self.refreshEarlyDataStatus();
    }

    fn handleStream(
        self: *Connection,
        lvl: EncryptionLevel,
        s: frame_types.Stream,
    ) Error!void {
        if (!self.peerMaySendOnStream(s.stream_id)) {
            self.close(true, transport_error_stream_state, "stream data on receive-only stream");
            return;
        }
        const frame_end = std.math.add(u64, s.offset, @as(u64, @intCast(s.data.len))) catch {
            self.close(true, transport_error_flow_control, "stream offset overflow");
            return;
        };
        const existing = self.streams.get(s.stream_id);
        if (existing == null and self.streamInitiatedByLocal(s.stream_id)) {
            self.close(true, transport_error_stream_state, "peer referenced unopened local stream");
            return;
        }
        if (existing == null and !self.recordPeerStreamOpenOrClose(s.stream_id)) return;

        const ptr = existing orelse blk: {
            const new_ptr = try self.allocator.create(Stream);
            errdefer self.allocator.destroy(new_ptr);
            new_ptr.* = .{
                .id = s.stream_id,
                .send = SendStream.init(self.allocator),
                .recv = RecvStream.init(self.allocator),
                .recv_max_data = self.initialRecvStreamLimit(s.stream_id),
                .send_max_data = self.initialSendStreamLimit(s.stream_id),
            };
            try self.streams.put(self.allocator, s.stream_id, new_ptr);
            break :blk new_ptr;
        };
        if (lvl == .early_data) ptr.arrived_in_early_data = true;
        const old_highest = ptr.recv.peerHighestOffset();
        const new_highest = @max(old_highest, frame_end);
        if (new_highest > ptr.recv_max_data) {
            self.close(true, transport_error_flow_control, "peer exceeded stream data limit");
            return;
        }
        const delta = new_highest - old_highest;
        if (delta > 0 and
            (delta > self.local_max_data or self.peer_sent_stream_data > self.local_max_data - delta))
        {
            self.close(true, transport_error_flow_control, "peer exceeded connection data limit");
            return;
        }
        ptr.recv.recv(s.offset, s.data, s.fin) catch |err| switch (err) {
            error.BufferLimitExceeded => {
                self.close(true, transport_error_protocol_violation, "stream reassembly exceeds allocation limit");
                return;
            },
            error.BeyondFinalSize, error.FinalSizeChanged => {
                self.close(true, transport_error_final_size, "stream final size changed");
                return;
            },
            else => return err,
        };
        self.peer_sent_stream_data += delta;
    }

    fn handleResetStream(self: *Connection, rs: frame_types.ResetStream) Error!void {
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
        ptr.recv.resetStream(rs.application_error_code, rs.final_size) catch |err| switch (err) {
            error.BeyondFinalSize, error.FinalSizeChanged => {
                self.close(true, transport_error_final_size, "reset stream final size changed");
                return;
            },
            else => return err,
        };
        self.peer_sent_stream_data += delta;
        self.maybeReturnPeerStreamCredit(ptr);
    }

    fn handleAckAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        a: frame_types.Ack,
        now_us: u64,
    ) Error!void {
        // Walk ACK ranges and notify each PN at this level to:
        //   1. every open SendStream (application level only),
        //   2. the per-level SentPacketTracker.
        //
        // Phase 5b v1 walks streams brute-force per PN; a per-PN
        // side-table is the obvious next optimization.
        const pn_space = self.pnSpaceForLevel(lvl);
        const sent = self.sentForLevel(lvl);
        // RFC 9000 §13.1 / RFC 9002 §A.3: an ACK that claims a packet
        // number we never sent (largest_acked >= next_pn) is a
        // PROTOCOL_VIOLATION. We must reject it before updating
        // largest_acked_sent — otherwise the bogus value would
        // poison packet-threshold loss detection on legitimate
        // in-flight packets.
        if (a.largest_acked >= pn_space.next_pn) {
            self.close(true, transport_error_protocol_violation, "ack of unsent packet");
            return;
        }
        pn_space.onAckReceived(a.largest_acked);
        var largest_acked_send_time_us: ?u64 = null;
        var largest_acked_ack_eliciting = false;
        var any_ack_eliciting_newly_acked = false;
        var in_flight_bytes_acked: u64 = 0;
        var newest_acked_sent_time_us: u64 = 0;

        var ack_it = ack_range_mod.iter(a);
        while (try ack_it.next()) |interval| {
            // Walk the (small, bounded) sent-packet tracker rather
            // than every PN in [smallest, largest]. A peer-chosen
            // first_range can stretch interval.smallest down to 0;
            // iterating the PN range directly would let a single
            // ACK force O(next_pn) work, which on a long-lived
            // connection is a real DoS surface (RFC 9000 §13.1
            // only constrains largest_acked < next_pn). Walking
            // the tracker is O(K log N) where K = packets matched
            // and N = tracker size, both bounded by our own send
            // rate × CWND.
            while (sent.lowerBound(interval.smallest)) |idx| {
                if (sent.packets[idx].pn > interval.largest) break;
                var acked = sent.removeAt(idx);
                defer acked.deinit(self.allocator);
                if (acked.pn == a.largest_acked) {
                    largest_acked_send_time_us = acked.sent_time_us;
                    largest_acked_ack_eliciting = acked.ack_eliciting;
                }
                if (acked.ack_eliciting) any_ack_eliciting_newly_acked = true;
                if (acked.in_flight) {
                    in_flight_bytes_acked += acked.bytes;
                    if (acked.sent_time_us > newest_acked_sent_time_us) {
                        newest_acked_sent_time_us = acked.sent_time_us;
                    }
                }
                if (lvl == .application) {
                    self.onApplicationPacketAckedForKeys(&acked, now_us);
                    self.dispatchAckedPacketToStreams(&acked) catch |e| return e;
                }
                self.discardSentCryptoForPacket(lvl, acked.pn);
                self.dispatchAckedControlFrames(&acked);
                self.recordDatagramAcked(&acked);
            }
        }
        if (largest_acked_send_time_us) |sent_time_us| {
            if (largest_acked_ack_eliciting and now_us >= sent_time_us) {
                const ack_delay_us = a.ack_delay << self.peerAckDelayExponent();
                self.rttForLevel(lvl).update(
                    now_us - sent_time_us,
                    ack_delay_us,
                    self.handshakeDone(),
                    self.peerMaxAckDelayUs(),
                );
            }
        }
        if (any_ack_eliciting_newly_acked) self.ptoCountForLevel(lvl).* = 0;
        if (in_flight_bytes_acked > 0) {
            if (lvl == .application) {
                self.ccForApplication().onPacketAcked(in_flight_bytes_acked, newest_acked_sent_time_us);
            }
        }

        // Loss detection at the same level — packet-threshold only
        // (time-threshold lives in `tick`).
        try self.detectLossesByPacketThresholdAtLevel(lvl);

        // Snapshot metrics + congestion phase after a meaningful ACK.
        if (any_ack_eliciting_newly_acked or in_flight_bytes_acked > 0) {
            self.emitCongestionStateIfChanged(now_us);
            self.emitMetricsSnapshot(now_us);
        }
    }

    fn handleApplicationAckOnPath(
        self: *Connection,
        path: *PathState,
        a: frame_types.Ack,
        now_us: u64,
    ) Error!void {
        // RFC 9000 §13.1 / RFC 9002 §A.3: reject ACKs claiming PNs
        // we never sent on this path.
        if (a.largest_acked >= path.app_pn_space.next_pn) {
            self.close(true, transport_error_protocol_violation, "ack of unsent packet");
            return;
        }
        path.app_pn_space.onAckReceived(a.largest_acked);
        var largest_acked_send_time_us: ?u64 = null;
        var largest_acked_ack_eliciting = false;
        var any_ack_eliciting_newly_acked = false;
        var in_flight_bytes_acked: u64 = 0;
        var newest_acked_sent_time_us: u64 = 0;

        var ack_it = ack_range_mod.iter(a);
        while (try ack_it.next()) |interval| {
            // See `handleAckAtLevel` above for the rationale; this
            // is the per-application-path twin walk and uses the
            // same tracker-bounded iteration.
            while (path.sent.lowerBound(interval.smallest)) |idx| {
                if (path.sent.packets[idx].pn > interval.largest) break;
                var acked = path.sent.removeAt(idx);
                defer acked.deinit(self.allocator);
                if (acked.pn == a.largest_acked) {
                    largest_acked_send_time_us = acked.sent_time_us;
                    largest_acked_ack_eliciting = acked.ack_eliciting;
                }
                if (acked.ack_eliciting) any_ack_eliciting_newly_acked = true;
                if (acked.in_flight) {
                    in_flight_bytes_acked += acked.bytes;
                    if (acked.sent_time_us > newest_acked_sent_time_us) {
                        newest_acked_sent_time_us = acked.sent_time_us;
                    }
                }
                self.dispatchAckedPacketToStreams(&acked) catch |e| return e;
                self.onApplicationPacketAckedForKeys(&acked, now_us);
                self.discardSentCryptoForPacket(.application, acked.pn);
                self.dispatchAckedControlFrames(&acked);
                self.recordDatagramAcked(&acked);
            }
        }
        if (largest_acked_send_time_us) |sent_time_us| {
            if (largest_acked_ack_eliciting and now_us >= sent_time_us) {
                const ack_delay_us = a.ack_delay << self.peerAckDelayExponent();
                path.path.rtt.update(
                    now_us - sent_time_us,
                    ack_delay_us,
                    self.handshakeDone(),
                    self.peerMaxAckDelayUs(),
                );
            }
        }
        if (any_ack_eliciting_newly_acked) path.pto_count = 0;
        if (in_flight_bytes_acked > 0) {
            path.path.cc.onPacketAcked(in_flight_bytes_acked, newest_acked_sent_time_us);
        }

        try self.detectLossesByPacketThresholdOnApplicationPath(path);

        // Snapshot metrics + congestion phase after a meaningful ACK.
        if (any_ack_eliciting_newly_acked or in_flight_bytes_acked > 0) {
            self.emitCongestionStateIfChanged(now_us);
            self.emitMetricsSnapshot(now_us);
        }
    }

    fn dispatchAckedToStreams(self: *Connection, pn: u64) Error!void {
        var s_it = self.streams.iterator();
        while (s_it.next()) |entry| {
            entry.value_ptr.*.send.onPacketAcked(pn) catch |e| switch (e) {
                send_stream_mod.Error.UnknownPacket => {},
                else => return e,
            };
        }
    }

    fn dispatchAckedPacketToStreams(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!void {
        var keys = packet.streamKeys();
        while (keys.next()) |stream_key| {
            try self.dispatchAckedToStreams(stream_key);
        }
    }

    fn dispatchLostToStreams(self: *Connection, pn: u64) Error!bool {
        var any = false;
        var s_it = self.streams.iterator();
        while (s_it.next()) |entry| {
            entry.value_ptr.*.send.onPacketLost(pn) catch |e| switch (e) {
                send_stream_mod.Error.UnknownPacket => continue,
                else => return e,
            };
            any = true;
        }
        return any;
    }

    fn dispatchLostPacketToStreams(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        var any = false;
        var keys = packet.streamKeys();
        while (keys.next()) |stream_key| {
            any = (try self.dispatchLostToStreams(stream_key)) or any;
        }
        return any;
    }

    fn discardSentCryptoForPacket(
        self: *Connection,
        lvl: EncryptionLevel,
        pn: u64,
    ) void {
        const idx = lvl.idx();
        var i: usize = 0;
        while (i < self.sent_crypto[idx].items.len) {
            const chunk = self.sent_crypto[idx].items[i];
            if (chunk.pn == pn) {
                const removed = self.sent_crypto[idx].orderedRemove(i);
                self.allocator.free(removed.data);
                continue;
            }
            i += 1;
        }
    }

    fn requeueSentCryptoForPacket(
        self: *Connection,
        lvl: EncryptionLevel,
        pn: u64,
    ) Error!bool {
        const idx = lvl.idx();
        var any = false;
        var i: usize = 0;
        while (i < self.sent_crypto[idx].items.len) {
            const chunk = self.sent_crypto[idx].items[i];
            if (chunk.pn == pn) {
                try self.crypto_retx[idx].ensureUnusedCapacity(self.allocator, 1);
                const removed = self.sent_crypto[idx].orderedRemove(i);
                self.crypto_retx[idx].appendAssumeCapacity(.{
                    .offset = removed.offset,
                    .data = removed.data,
                });
                any = true;
                continue;
            }
            i += 1;
        }
        return any;
    }

    fn dispatchAckedControlFrames(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) void {
        for (packet.retransmit_frames.items) |frame| {
            switch (frame) {
                .reset_stream => |rs| {
                    const s = self.streams.get(rs.stream_id) orelse continue;
                    if (s.send.reset) |r| {
                        if (r.error_code == rs.application_error_code and
                            r.final_size == rs.final_size)
                        {
                            s.send.onResetAcked();
                        }
                    }
                },
                else => {},
            }
        }
    }

    fn dispatchLostControlFrames(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        return self.dispatchLostControlFramesOnPath(packet, self.activePath().id);
    }

    fn dispatchLostControlFramesOnPath(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
        path_id: u32,
    ) Error!bool {
        var any = false;
        for (packet.retransmit_frames.items) |frame| {
            switch (frame) {
                .max_data => |md| {
                    self.queueMaxData(md.maximum_data);
                    any = true;
                },
                .max_stream_data => |msd| {
                    try self.queueMaxStreamData(
                        msd.stream_id,
                        msd.maximum_stream_data,
                    );
                    any = true;
                },
                .max_streams => |ms| {
                    self.queueMaxStreams(ms.bidi, ms.maximum_streams);
                    any = true;
                },
                .data_blocked => |db| {
                    any = self.requeueDataBlocked(db.maximum_data) or any;
                },
                .stream_data_blocked => |sdb| {
                    any = (try self.requeueStreamDataBlocked(sdb)) or any;
                },
                .streams_blocked => |sb| {
                    any = self.requeueStreamsBlocked(sb) or any;
                },
                .new_connection_id => |nc| {
                    try self.queueNewConnectionId(
                        nc.sequence_number,
                        nc.retire_prior_to,
                        nc.connection_id.slice(),
                        nc.stateless_reset_token,
                    );
                    any = true;
                },
                .retire_connection_id => |rc| {
                    try self.queueRetireConnectionId(rc.sequence_number);
                    any = true;
                },
                .handshake_done => {
                    self.pending_handshake_done = true;
                    any = true;
                },
                .stop_sending => |ss| {
                    try self.queueStopSending(.{
                        .stream_id = ss.stream_id,
                        .application_error_code = ss.application_error_code,
                    });
                    any = true;
                },
                .path_response => |pr| {
                    if (self.pending_path_response == null) {
                        self.queuePathResponseOnPath(path_id, pr.data, null);
                    }
                    any = true;
                },
                .path_challenge => |pc| {
                    if (self.pending_path_challenge == null and
                        self.shouldRequeuePathChallenge(path_id, pc.data))
                    {
                        self.queuePathChallengeOnPath(path_id, pc.data);
                        any = true;
                    }
                },
                .reset_stream => |rs| {
                    const s = self.streams.get(rs.stream_id) orelse continue;
                    if (s.send.reset) |r| {
                        if (r.error_code == rs.application_error_code and
                            r.final_size == rs.final_size)
                        {
                            s.send.onResetLost();
                        }
                    }
                    any = true;
                },
                .path_abandon => |pa| {
                    try self.queuePathAbandon(pa.path_id, pa.error_code);
                    any = true;
                },
                .path_status_backup => |ps| {
                    try self.queuePathStatus(ps.path_id, false, ps.sequence_number);
                    any = true;
                },
                .path_status_available => |ps| {
                    try self.queuePathStatus(ps.path_id, true, ps.sequence_number);
                    any = true;
                },
                .path_new_connection_id => |nc| {
                    try self.queuePathNewConnectionId(
                        nc.path_id,
                        nc.sequence_number,
                        nc.retire_prior_to,
                        nc.connection_id.slice(),
                        nc.stateless_reset_token,
                    );
                    any = true;
                },
                .path_retire_connection_id => |rc| {
                    try self.queuePathRetireConnectionId(rc.path_id, rc.sequence_number);
                    any = true;
                },
                .max_path_id => |mp| {
                    self.queueMaxPathId(mp.maximum_path_id);
                    any = true;
                },
                .paths_blocked => |pb| {
                    self.queuePathsBlocked(pb.maximum_path_id);
                    any = true;
                },
                .path_cids_blocked => |pcb| {
                    self.queuePathCidsBlocked(pcb.path_id, pcb.next_sequence_number);
                    any = true;
                },
            }
        }
        return any;
    }

    fn requeueLostPacket(
        self: *Connection,
        lvl: EncryptionLevel,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        return self.requeueLostPacketOnPath(lvl, packet, self.activePath().id);
    }

    fn requeueLostPacketOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        packet: *const sent_packets_mod.SentPacket,
        path_id: u32,
    ) Error!bool {
        var any = false;
        self.recordDatagramLost(packet);
        if (lvl == .application or lvl == .early_data or packet.is_early_data) {
            any = (try self.dispatchLostPacketToStreams(packet)) or any;
        }
        any = (try self.requeueSentCryptoForPacket(lvl, packet.pn)) or any;
        any = (try self.dispatchLostControlFramesOnPath(packet, path_id)) or any;
        return any;
    }

    fn isPersistentCongestionFromBasePto(base_pto_us: u64, stats: LossStats) bool {
        // RFC 9002 §7.6.1: persistent congestion is determined from
        // ack-eliciting packets only. Both the smallest and largest
        // lost packets in the persistent congestion window MUST be
        // ack-eliciting. A burst of lost PATH_RESPONSE-only or
        // PADDING-only packets, for example, is not enough on its
        // own to collapse cwnd to kMinimumWindow.
        const earliest = stats.earliest_ack_eliciting_lost_sent_time_us orelse return false;
        if (stats.ack_eliciting_count < 2 or
            stats.largest_ack_eliciting_lost_sent_time_us <= earliest)
        {
            return false;
        }
        const duration = stats.largest_ack_eliciting_lost_sent_time_us - earliest;
        const threshold = base_pto_us *
            congestion_mod.persistent_congestion_threshold;
        return duration >= threshold;
    }

    fn isPersistentCongestion(
        self: *const Connection,
        lvl: EncryptionLevel,
        stats: LossStats,
    ) bool {
        return isPersistentCongestionFromBasePto(
            self.basePtoDurationForLevel(lvl),
            stats,
        );
    }

    fn onPacketsLostAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        stats: LossStats,
    ) void {
        if (stats.in_flight_bytes_lost == 0) return;
        if (lvl == .application) {
            const cc = self.ccForApplication();
            cc.onPacketLost(
                stats.in_flight_bytes_lost,
                stats.largest_lost_sent_time_us,
            );
            if (self.isPersistentCongestion(lvl, stats)) {
                cc.onPersistentCongestion();
            }
        }
    }

    fn onApplicationPathPacketsLost(
        self: *Connection,
        path: *PathState,
        stats: LossStats,
    ) void {
        if (stats.in_flight_bytes_lost == 0) return;
        path.path.cc.onPacketLost(
            stats.in_flight_bytes_lost,
            stats.largest_lost_sent_time_us,
        );
        if (isPersistentCongestionFromBasePto(
            self.basePtoDurationForApplicationPath(path),
            stats,
        )) {
            path.path.cc.onPersistentCongestion();
        }
    }

    fn detectLossesByPacketThresholdAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
    ) Error!void {
        const pn_space = self.pnSpaceForLevel(lvl);
        const sent = self.sentForLevel(lvl);
        const largest_acked_opt = pn_space.largest_acked_sent;
        if (largest_acked_opt == null) return;
        const largest_acked = largest_acked_opt.?;
        const threshold: u64 = loss_recovery_mod.packet_threshold;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < sent.count) {
            const p = sent.packets[i];
            if (p.pn <= largest_acked and (largest_acked - p.pn) >= threshold) {
                var lost = sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                self.emitPacketLost(lvl, lost.pn, @intCast(lost.bytes), .packet_threshold);
                _ = try self.requeueLostPacket(lvl, &lost);
                continue;
            }
            i += 1;
        }
        self.qlog_packets_lost +|= stats.count;
        self.emitLossDetected(lvl, stats, .packet_threshold);
        self.onPacketsLostAtLevel(lvl, stats);
        self.emitCongestionStateIfChanged(0);
    }

    fn detectLossesByPacketThresholdOnApplicationPath(
        self: *Connection,
        path: *PathState,
    ) Error!void {
        const largest_acked_opt = path.app_pn_space.largest_acked_sent;
        if (largest_acked_opt == null) return;
        const largest_acked = largest_acked_opt.?;
        const threshold: u64 = loss_recovery_mod.packet_threshold;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < path.sent.count) {
            const p = path.sent.packets[i];
            if (p.pn <= largest_acked and (largest_acked - p.pn) >= threshold) {
                var lost = path.sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                self.emitPacketLost(.application, lost.pn, @intCast(lost.bytes), .packet_threshold);
                _ = try self.requeueLostPacketOnPath(.application, &lost, path.id);
                continue;
            }
            i += 1;
        }
        self.qlog_packets_lost +|= stats.count;
        self.emitLossDetected(.application, stats, .packet_threshold);
        self.onApplicationPathPacketsLost(path, stats);
        self.emitCongestionStateIfChanged(0);
    }

    fn detectLossesByTimeThresholdAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        now_us: u64,
    ) Error!void {
        const rtt = self.rttForLevelConst(lvl);
        const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );
        if (now_us <= time_threshold) return;
        const cutoff = now_us - time_threshold;
        const pn_space = self.pnSpaceForLevel(lvl);
        const sent = self.sentForLevel(lvl);
        const largest_acked_opt = pn_space.largest_acked_sent;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < sent.count) {
            const p = sent.packets[i];
            const eligible = if (largest_acked_opt) |la| p.pn <= la else false;
            if (eligible and p.sent_time_us < cutoff) {
                var lost = sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                self.emitPacketLost(lvl, lost.pn, @intCast(lost.bytes), .time_threshold);
                _ = try self.requeueLostPacket(lvl, &lost);
                continue;
            }
            i += 1;
        }
        self.qlog_packets_lost +|= stats.count;
        self.emitLossDetected(lvl, stats, .time_threshold);
        self.onPacketsLostAtLevel(lvl, stats);
        self.emitCongestionStateIfChanged(now_us);
    }

    fn detectLossesByTimeThresholdOnApplicationPath(
        self: *Connection,
        path: *PathState,
        now_us: u64,
    ) Error!void {
        const rtt = &path.path.rtt;
        const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );
        if (now_us <= time_threshold) return;
        const cutoff = now_us - time_threshold;
        const largest_acked_opt = path.app_pn_space.largest_acked_sent;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < path.sent.count) {
            const p = path.sent.packets[i];
            const eligible = if (largest_acked_opt) |la| p.pn <= la else false;
            if (eligible and p.sent_time_us < cutoff) {
                var lost = path.sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                self.emitPacketLost(.application, lost.pn, @intCast(lost.bytes), .time_threshold);
                _ = try self.requeueLostPacketOnPath(.application, &lost, path.id);
                continue;
            }
            i += 1;
        }
        self.qlog_packets_lost +|= stats.count;
        self.emitLossDetected(.application, stats, .time_threshold);
        self.onApplicationPathPacketsLost(path, stats);
        self.emitCongestionStateIfChanged(now_us);
    }

    fn firePtoAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
    ) Error!bool {
        const sent = self.sentForLevel(lvl);
        var i: u32 = 0;
        while (i < sent.count) : (i += 1) {
            const p = sent.packets[i];
            if (!p.ack_eliciting) continue;

            var lost = sent.removeAt(i);
            defer lost.deinit(self.allocator);
            var stats: LossStats = .{};
            stats.add(lost);
            self.emitPacketLost(lvl, lost.pn, @intCast(lost.bytes), .pto_probe);
            const requeued = try self.requeueLostPacket(lvl, &lost);
            self.qlog_packets_lost +|= stats.count;
            self.emitLossDetected(lvl, stats, .pto_probe);
            self.onPacketsLostAtLevel(lvl, stats);

            self.pendingPingForLevel(lvl).* = !requeued;
            self.ptoCountForLevel(lvl).* +|= 1;
            return true;
        }
        return false;
    }

    fn firePtoOnApplicationPath(
        self: *Connection,
        path: *PathState,
    ) Error!bool {
        var i: u32 = 0;
        while (i < path.sent.count) : (i += 1) {
            const p = path.sent.packets[i];
            if (!p.ack_eliciting) continue;

            var lost = path.sent.removeAt(i);
            defer lost.deinit(self.allocator);
            var stats: LossStats = .{};
            stats.add(lost);
            self.emitPacketLost(.application, lost.pn, @intCast(lost.bytes), .pto_probe);
            const requeued = try self.requeueLostPacketOnPath(.application, &lost, path.id);
            self.qlog_packets_lost +|= stats.count;
            self.emitLossDetected(.application, stats, .pto_probe);
            self.onApplicationPathPacketsLost(path, stats);

            path.pending_ping = !requeued;
            if (requeued and path.pto_probe_count < 2) path.pto_probe_count += 1;
            path.pto_count +|= 1;
            return true;
        }
        return false;
    }

    fn fireDuePtoAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        now_us: u64,
    ) Error!void {
        const deadline = self.ptoDeadlineForLevel(lvl) orelse return;
        if (now_us < deadline) return;
        _ = try self.firePtoAtLevel(lvl);
    }

    fn fireDuePtoOnApplicationPath(
        self: *Connection,
        path: *PathState,
        now_us: u64,
    ) Error!void {
        const deadline = self.ptoDeadlineForApplicationPath(path) orelse return;
        if (now_us < deadline) return;
        _ = try self.firePtoOnApplicationPath(path);
    }

    /// Periodic tick — drives time-based loss detection, PTO,
    /// idle timeout, and draining deadlines. The caller passes the
    /// current monotonic time in microseconds. Safe to call any time.
    pub fn tick(self: *Connection, now_us: u64) Error!void {
        for (self.paths.paths.items) |*p| {
            p.path.validator.tick(now_us);
            if (p.path.validator.status == .failed) {
                self.handlePathValidationFailure(p);
            }
        }
        self.expireRetiringPaths(now_us);
        self.discardExpiredApplicationReadKeys(now_us);

        if (self.draining_deadline_us) |deadline| {
            if (now_us >= deadline) {
                self.finishDraining();
            }
            return;
        }

        if (self.closed) return;

        if (!self.closed) {
            if (self.idleDeadline()) |deadline| {
                if (now_us >= deadline) {
                    self.enterDraining(
                        .idle_timeout,
                        .transport,
                        0,
                        0,
                        "idle timeout",
                        now_us,
                    );
                    return;
                }
            }
        }

        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            self.promoteDueAckDelay(&self.pnSpaceForLevel(lvl).received, now_us);
        }
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            self.promoteDueAckDelay(&path.app_pn_space.received, now_us);
        }

        try self.detectLossesByTimeThresholdAtLevel(.initial, now_us);
        try self.detectLossesByTimeThresholdAtLevel(.handshake, now_us);
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            try self.detectLossesByTimeThresholdOnApplicationPath(path, now_us);
        }

        try self.fireDuePtoAtLevel(.initial, now_us);
        try self.fireDuePtoAtLevel(.handshake, now_us);
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            try self.fireDuePtoOnApplicationPath(path, now_us);
        }
    }

    /// One handshake driver step:
    /// 1. For each encryption level (low → high), if there are
    ///    queued bytes from the peer, feed them in via
    ///    `provideQuicData` and advance the handshake. (Per-level
    ///    feeding is required because keys for level N+1 are
    ///    derived during processing of level N.)
    /// 2. After all queued levels are drained, make one more
    ///    handshake call in case there's outgoing-only progress
    ///    (e.g. the very first client step that emits ClientHello).
    /// 3. If the handshake is done and `application`-level bytes
    ///    are pending (post-handshake messages such as
    ///    NewSessionTicket), call `processQuicPostHandshake`.
    pub fn advance(self: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const idx = lvl.idx();
            if (self.inbox[idx].len > 0) {
                const bytes = self.inbox[idx].drain();
                try self.inner.provideQuicData(lvl.toBoringssl(), bytes);
                if (self.inner.handshakeDone()) {
                    try self.cachePeerTransportParams();
                    try self.inner.processQuicPostHandshake();
                } else {
                    try self.advanceHandshake();
                }
            }
        }
        if (!self.inner.handshakeDone()) try self.advanceHandshake();
        if (self.inner.handshakeDone()) try self.cachePeerTransportParams();
        self.queueHandshakeDoneIfReady();
        try self.refreshEarlyDataStatus();
        // Phase-4 in-process compatibility: shuttle outbox→peer.inbox
        // so the existing handshake test still works while the real
        // datagram-driven path is being built up.
        if (self.peer) |peer| try self.shuttleOutboxToPeer(peer);
        if (self.alert) |_| return error.PeerAlerted;
    }

    fn shuttleOutboxToPeer(self: *Connection, peer: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const i = lvl.idx();
            if (self.outbox[i].len > 0) {
                const bytes = self.outbox[i].drain();
                try peer.inbox[i].append(bytes);
                self.crypto_send_offset[i] += bytes.len;
            }
        }
    }

    fn advanceHandshake(self: *Connection) Error!void {
        self.inner.handshake() catch |e| switch (e) {
            error.WantRead, error.WantWrite => {},
            else => return e,
        };
    }
};

// -- tls.quic.Method bridge ---------------------------------------------
//
// Each callback recovers the *Connection from the SSL via ex-data,
// then writes into nullq state. The trampolines stay in this module
// because they reach into Connection's private fields directly.

fn setReadSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
) callconv(.c) c_int {
    return setSecret(ssl, level, cipher, secret, secret_len, .read);
}

fn setWriteSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
) callconv(.c) c_int {
    return setSecret(ssl, level, cipher, secret, secret_len, .write);
}

fn setSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
    dir: Direction,
) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    if (secret_len > 64) return 0;
    const cipher_id: u16 = blk: {
        if (cipher) |cph| {
            break :blk c.zbssl_SSL_CIPHER_get_protocol_id(cph);
        } else {
            break :blk 0;
        }
    };

    var material: SecretMaterial = .{ .cipher_protocol_id = cipher_id };
    @memcpy(material.secret[0..secret_len], secret[0..secret_len]);
    material.secret_len = @intCast(secret_len);

    const lvl = EncryptionLevel.fromBoringssl(@enumFromInt(level));
    if (lvl == .application) {
        conn.installApplicationSecret(dir, material) catch return 0;
    } else switch (dir) {
        .read => conn.levels[lvl.idx()].read = material,
        .write => conn.levels[lvl.idx()].write = material,
    }
    if (lvl != .application) {
        conn.emitQlog(.{ .name = .key_updated, .level = lvl });
    }
    return 1;
}

fn addHandshakeData(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    data: [*c]const u8,
    len: usize,
) callconv(.c) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    const lvl = EncryptionLevel.fromBoringssl(@enumFromInt(level));
    // Buffer outgoing CRYPTO bytes per level. `poll` packs them into
    // CRYPTO frames inside Initial/Handshake/1-RTT packets — that's
    // the wire-level handshake path. The legacy in-process Phase-4
    // test path additionally has `advance` shuttle outbox→peer.inbox
    // when `peer` is set.
    conn.outbox[lvl.idx()].append(data[0..len]) catch return 0;
    return 1;
}

fn flushFlight(_: ?*c.SSL) callconv(.c) c_int {
    return 1;
}

fn sendAlert(
    ssl: ?*c.SSL,
    _: c.ssl_encryption_level_t,
    alert: u8,
) callconv(.c) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    conn.alert = alert;
    return 1;
}

fn connFromSsl(ssl: ?*c.SSL) ?*Connection {
    const ssl_ptr = ssl orelse return null;
    const raw_ptr = boringssl.tls.Conn.userDataFromSsl(ssl_ptr) orelse return null;
    return @ptrCast(@alignCast(raw_ptr));
}

const method: boringssl.tls.quic.Method = .{
    .set_read_secret = setReadSecret,
    .set_write_secret = setWriteSecret,
    .add_handshake_data = addHandshakeData,
    .flush_flight = flushFlight,
    .send_alert = sendAlert,
};

// -- tests ---------------------------------------------------------------

test "streamReset publicly aborts the send half" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 5), try conn.streamWrite(0, "hello"));
    try conn.streamReset(0, 0xdead);

    const s = conn.stream(0).?;
    try std.testing.expectEqual(send_stream_mod.State.reset_sent, s.send.state);
    try std.testing.expect(s.send.reset != null);
    try std.testing.expectEqual(@as(u64, 0xdead), s.send.reset.?.error_code);
    try std.testing.expectEqual(@as(u64, 5), s.send.reset.?.final_size);
    try std.testing.expectError(send_stream_mod.Error.StreamClosed, conn.streamWrite(0, "late"));
    try std.testing.expectError(Error.StreamNotFound, conn.streamReset(4, 0));
}

test "local close is exposed as sticky and pollable event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.close(false, 0x42, "shutting down");
    try std.testing.expectEqual(CloseState.closing, conn.closeState());

    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.application, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x42), sticky.error_code);
    try std.testing.expectEqual(@as(u64, 0), sticky.frame_type);
    try std.testing.expectEqualStrings("shutting down", sticky.reason);
    try std.testing.expect(!sticky.reason_truncated);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .close);
    try std.testing.expectEqualStrings("shutting down", event.close.reason);
    try std.testing.expect(conn.pollEvent() == null);
    try std.testing.expect(conn.closeEvent() != null);
}

test "local close truncates long reason and keeps sticky event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var reason: [max_close_reason_len + 32]u8 = undefined;
    @memset(&reason, 'x');
    conn.close(true, 0x1337, reason[0..]);

    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x1337), sticky.error_code);
    try std.testing.expectEqual(max_close_reason_len, sticky.reason.len);
    try std.testing.expect(sticky.reason_truncated);
    for (sticky.reason) |byte| {
        try std.testing.expectEqual(@as(u8, 'x'), byte);
    }

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .close);
    try std.testing.expectEqual(max_close_reason_len, event.close.reason.len);
    try std.testing.expect(event.close.reason_truncated);
    try std.testing.expect(conn.pollEvent() == null);

    const after_poll = conn.closeEvent().?;
    try std.testing.expectEqual(max_close_reason_len, after_poll.reason.len);
    try std.testing.expect(after_poll.reason_truncated);
}

test "closing and draining ignore incoming datagrams" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.close(false, 0x42, "closing");
    var random_short = [_]u8{ 0x40, 0, 1, 2, 3, 4, 5 };
    try conn.handle(&random_short, null, 1_000_000);
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expectEqual(@as(u64, 0), conn.last_activity_us);
    try std.testing.expectEqual(@as(u64, 0), conn.primaryPathConst().path.bytes_received);

    var peer_ctx = try boringssl.tls.Context.initClient(.{});
    defer peer_ctx.deinit();
    var peer_closed = try Connection.initClient(allocator, peer_ctx, "x");
    defer peer_closed.deinit();
    var payload: [128]u8 = undefined;
    const n = try frame_mod.encode(&payload, .{
        .connection_close = .{
            .is_transport = false,
            .error_code = 0x7,
            .reason_phrase = "bye",
        },
    });
    try peer_closed.dispatchFrames(.application, payload[0..n], 2_000_000);
    try std.testing.expectEqual(CloseState.draining, peer_closed.closeState());
    const deadline = peer_closed.draining_deadline_us.?;
    try peer_closed.handle(&random_short, null, 2_000_001);
    try std.testing.expectEqual(@as(u64, 0), peer_closed.last_activity_us);
    try peer_closed.tick(deadline);
    try std.testing.expectEqual(CloseState.closed, peer_closed.closeState());
    try std.testing.expect(peer_closed.nextTimerDeadline(deadline) == null);
}

test "peer close records transport error details" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var payload: [128]u8 = undefined;
    const n = try frame_mod.encode(&payload, .{
        .connection_close = .{
            .is_transport = true,
            .error_code = 0x0a,
            .frame_type = 0x08,
            .reason_phrase = "bad stream frame",
        },
    });
    try conn.dispatchFrames(.application, payload[0..n], 1_000_000);

    const sticky = conn.closeEvent().?;
    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expectEqual(CloseSource.peer, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x0a), sticky.error_code);
    try std.testing.expectEqual(@as(u64, 0x08), sticky.frame_type);
    try std.testing.expectEqualStrings("bad stream frame", sticky.reason);
    try std.testing.expectEqual(@as(u64, 1_000_000), sticky.at_us.?);
    try std.testing.expect(sticky.draining_deadline_us != null);
}

test "stateless reset token closes without CONNECTION_CLOSE" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const token: [16]u8 = .{
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    };
    conn.cached_peer_transport_params = .{ .stateless_reset_token = token };
    try conn.setPeerDcid(&.{ 0xaa, 0xbb, 0xcc, 0xdd });

    var packet: [24]u8 = .{
        0x40, 0xaa, 0xbb, 0xcc,
        0xdd, 0x55, 0x66, 0x77,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
    };
    @memcpy(packet[packet.len - 16 ..], &token);

    try conn.handle(&packet, null, 3_000_000);

    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expect(conn.pending_close == null);
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.stateless_reset, close_event.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, close_event.error_space);
    try std.testing.expectEqualStrings("stateless reset", close_event.reason);
    try std.testing.expectEqual(@as(u64, 3_000_000), close_event.at_us.?);
}

test "stateless reset matcher requires short packet with known token" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const token: [16]u8 = .{
        0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f,
    };
    conn.cached_peer_transport_params = .{ .stateless_reset_token = token };
    try conn.setPeerDcid(&.{0xaa});

    var long_packet = [_]u8{0} ** 24;
    long_packet[0] = 0xc0;
    @memcpy(long_packet[long_packet.len - 16 ..], &token);
    try std.testing.expect(!conn.isKnownStatelessReset(long_packet[0..]));

    var unknown_short = [_]u8{0} ** 24;
    unknown_short[0] = 0x40;
    const unknown_token: [16]u8 = @splat(0xee);
    @memcpy(unknown_short[unknown_short.len - 16 ..], &unknown_token);
    try std.testing.expect(!conn.isKnownStatelessReset(unknown_short[0..]));

    var short_packet = [_]u8{0} ** 24;
    short_packet[0] = 0x40;
    @memcpy(short_packet[short_packet.len - 16 ..], &token);
    try std.testing.expect(conn.isKnownStatelessReset(short_packet[0..]));
}

test "tokenEql matches std.mem.eql across boundary cases" {
    // Constant-time compare must agree with std.mem.eql for the
    // ordinary (non-adversarial) cases: equal tokens, fully different
    // tokens, and tokens differing in only one byte at varying
    // positions. RFC 9000 §10.3 mandates CT compare; this test ensures
    // we did not accidentally weaken correctness while doing so.
    const a: [16]u8 = .{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };
    try std.testing.expectEqual(std.mem.eql(u8, &a, &a), Connection.tokenEql(a, a));

    const b: [16]u8 = @splat(0xff);
    try std.testing.expectEqual(std.mem.eql(u8, &a, &b), Connection.tokenEql(a, b));

    var differ: [16]u8 = a;
    inline for (.{ 0, 1, 7, 8, 14, 15 }) |i| {
        differ = a;
        differ[i] ^= 0x01;
        try std.testing.expectEqual(
            std.mem.eql(u8, &a, &differ),
            Connection.tokenEql(a, differ),
        );
    }

    // All-zero tokens must compare equal (the default-initialized
    // value of an unfilled cached entry — guard against accidentally
    // returning false for zero arrays).
    const zero: [16]u8 = @splat(0);
    try std.testing.expect(Connection.tokenEql(zero, zero));
}

test "Version Negotiation with no compatible version closes terminally" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const versions = [_]u8{
        0x6b, 0x33, 0x43, 0xcf,
        0xff, 0x00, 0x00, 0x20,
    };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &versions,
    } });

    try conn.handle(packet[0..n], null, 4_000_000);

    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.closed, conn.closeState());
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.version_negotiation, close_event.source);
    try std.testing.expectEqualStrings("no compatible QUIC version", close_event.reason);
}

test "Version Negotiation is ignored when it lists QUIC v1 or has wrong CID echo" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 8, 7, 6, 5 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const includes_v1 = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0xff, 0x00, 0x00, 0x20,
    };
    var packet: [128]u8 = undefined;
    var n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &includes_v1,
    } });
    try conn.handle(packet[0..n], null, 4_000_000);
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&.{ 0xde, 0xad }),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &other_versions,
    } });
    try conn.handle(packet[0..n], null, 4_000_001);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Version Negotiation is ignored with wrong SCID echo or malformed versions" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 8, 7, 6, 5 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&.{ 0xde, 0xad }),
        .versions_bytes = &other_versions,
    } });
    try conn.handle(packet[0..n], null, 4_000_002);
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    var malformed: [128]u8 = undefined;
    var pos: usize = 0;
    malformed[pos] = 0x80;
    pos += 1;
    std.mem.writeInt(u32, malformed[pos..][0..4], 0, .big);
    pos += 4;
    malformed[pos] = @intCast(client_scid.len);
    pos += 1;
    @memcpy(malformed[pos .. pos + client_scid.len], &client_scid);
    pos += client_scid.len;
    malformed[pos] = @intCast(odcid.len);
    pos += 1;
    @memcpy(malformed[pos .. pos + odcid.len], &odcid);
    pos += odcid.len;
    @memcpy(malformed[pos .. pos + 3], &[_]u8{ 0x6b, 0x33, 0x43 });
    pos += 3;

    try conn.handle(malformed[0..pos], null, 4_000_003);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Version Negotiation packets are ignored by servers" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&.{ 8, 7, 6, 5 }),
        .scid = try wire_header.ConnId.fromSlice(&.{ 1, 2, 3, 4 }),
        .versions_bytes = &other_versions,
    } });

    try conn.handle(packet[0..n], null, 4_000_004);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
    try std.testing.expect(conn.closeEvent() == null);
}

test "Retry is accepted once and re-arms Initial crypto with token" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const retry_token = "retry-token";
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    var packet: [256]u8 = undefined;
    const retry_len = try long_packet_mod.sealRetry(&packet, .{
        .original_dcid = &odcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = retry_token,
    });

    const sent_copy = try allocator.dupe(u8, "client hello");
    try conn.sent_crypto[EncryptionLevel.initial.idx()].append(allocator, .{
        .pn = 0,
        .offset = 0,
        .data = sent_copy,
    });
    try conn.sent[0].record(.{
        .pn = 0,
        .sent_time_us = 100,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pn_spaces[0].next_pn = 9;

    try conn.handle(packet[0..retry_len], null, 4_000_000);

    try std.testing.expect(conn.retry_accepted);
    try std.testing.expectEqualSlices(u8, retry_token, conn.retry_token.items);
    try std.testing.expectEqualSlices(u8, &retry_scid, conn.peer_dcid.slice());
    try std.testing.expectEqualSlices(u8, &retry_scid, conn.initial_dcid.slice());
    try std.testing.expectEqualSlices(u8, &odcid, conn.original_initial_dcid.slice());
    try std.testing.expectEqual(@as(u64, 9), conn.pn_spaces[0].next_pn);
    try std.testing.expectEqual(@as(u32, 0), conn.sent[0].count);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[EncryptionLevel.initial.idx()].items.len);

    var out: [1500]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &out, 4_000_001)).?;
    const parsed = try wire_header.parse(out[0..n], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqualSlices(u8, retry_token, parsed.header.initial.token);
}

test "Retry with invalid integrity tag is ignored" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    var packet: [256]u8 = undefined;
    const retry_len = try long_packet_mod.sealRetry(&packet, .{
        .original_dcid = &odcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = "retry-token",
    });
    packet[retry_len - 1] ^= 0x01;

    try conn.handle(packet[0..retry_len], null, 4_000_000);

    try std.testing.expect(!conn.retry_accepted);
    try std.testing.expectEqualSlices(u8, &odcid, conn.peer_dcid.slice());
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Retry source CID transport parameter is validated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 1, 2, 3, 5, 8, 13, 21 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    try conn.setInitialDcid(&odcid);
    conn.retry_accepted = true;
    conn.retry_source_cid = ConnectionId.fromSlice(&retry_scid);
    conn.retry_source_cid_set = true;

    conn.cached_peer_transport_params = .{
        .original_destination_connection_id = ConnectionId.fromSlice(&odcid),
        .retry_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb }),
    };
    conn.validatePeerTransportConnectionIds();

    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_transport_parameter, conn.pending_close.?.error_code);
    try std.testing.expectEqualStrings("retry source cid mismatch", conn.pending_close.?.reason);
}

fn expectServerOnlyPeerTransportParamRejected(params: TransportParams, reason: []const u8) !void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    conn.cached_peer_transport_params = params;
    conn.validatePeerTransportRole();

    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_transport_parameter, conn.pending_close.?.error_code);
    try std.testing.expectEqualStrings(reason, conn.pending_close.?.reason);
}

test "server rejects client-sent server-only transport parameters" {
    const reset_token: [16]u8 = .{
        0, 1, 2,  3,  4,  5,  6,  7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };

    try expectServerOnlyPeerTransportParamRejected(.{
        .original_destination_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb }),
    }, "client sent original destination cid");
    try expectServerOnlyPeerTransportParamRejected(.{
        .stateless_reset_token = reset_token,
    }, "client sent stateless reset token");
    try expectServerOnlyPeerTransportParamRejected(.{
        .preferred_address = .{
            .ipv4_address = .{ 192, 0, 2, 1 },
            .ipv4_port = 4433,
            .ipv6_address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .ipv6_port = 4433,
            .connection_id = ConnectionId.fromSlice(&.{ 0xc0, 0xc1 }),
            .stateless_reset_token = reset_token,
        },
    }, "client sent preferred address");
    try expectServerOnlyPeerTransportParamRejected(.{
        .retry_source_connection_id = ConnectionId.fromSlice(&.{ 0xcc, 0xdd }),
    }, "client sent retry source cid");
}

test "server writeRetry emits a Retry addressed to the client Initial SCID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const init_keys = try initial_keys_mod.deriveInitialKeys(&odcid, false);
    const keys = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    var initial: [256]u8 = undefined;
    const initial_len = try long_packet_mod.sealInitial(&initial, .{
        .dcid = &odcid,
        .scid = &client_scid,
        .pn = 0,
        .payload = "CRYPTO",
        .keys = &keys,
    });

    var retry: [256]u8 = undefined;
    const retry_len = try conn.writeRetry(
        &retry,
        initial[0..initial_len],
        &retry_scid,
        "server-token",
    );

    const parsed = try wire_header.parse(retry[0..retry_len], 0);
    try std.testing.expect(parsed.header == .retry);
    try std.testing.expectEqualSlices(u8, &client_scid, parsed.header.retry.dcid.slice());
    try std.testing.expectEqualSlices(u8, &retry_scid, parsed.header.retry.scid.slice());
    try std.testing.expectEqualSlices(u8, "server-token", parsed.header.retry.retry_token);
    try std.testing.expect(try long_packet_mod.validateRetryIntegrity(&odcid, retry[0..retry_len]));
}

test "server writeVersionNegotiation echoes client CIDs and versions" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const client_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
    const init_keys = try initial_keys_mod.deriveInitialKeys(&client_dcid, false);
    const keys = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    var initial: [256]u8 = undefined;
    const initial_len = try long_packet_mod.sealInitial(&initial, .{
        .version = 0x6b3343cf,
        .dcid = &client_dcid,
        .scid = &client_scid,
        .pn = 0,
        .payload = "CRYPTO",
        .keys = &keys,
    });

    var vn: [128]u8 = undefined;
    const vn_len = try conn.writeVersionNegotiation(
        &vn,
        initial[0..initial_len],
        &.{quic_version_1},
    );

    const parsed = try wire_header.parse(vn[0..vn_len], 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    try std.testing.expectEqualSlices(u8, &client_scid, parsed.header.version_negotiation.dcid.slice());
    try std.testing.expectEqualSlices(u8, &client_dcid, parsed.header.version_negotiation.scid.slice());
    try std.testing.expectEqual(@as(usize, 1), parsed.header.version_negotiation.versionCount());
    try std.testing.expectEqual(quic_version_1, parsed.header.version_negotiation.version(0));
}

test "EncryptionLevel idx round-trip" {
    inline for (level_mod.all) |lvl| {
        try std.testing.expectEqual(lvl.idx(), @intFromEnum(lvl));
    }
}

test "packetPayloadAckEliciting ignores ACK-only payloads" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    pos += try frame_mod.encode(buf[pos..], .{ .padding = .{ .count = 2 } });
    pos += try frame_mod.encode(buf[pos..], .{ .ack = .{
        .largest_acked = 9,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
    } });
    try std.testing.expect(!Connection.packetPayloadAckEliciting(buf[0..pos]));

    pos += try frame_mod.encode(buf[pos..], .{ .ping = .{} });
    try std.testing.expect(Connection.packetPayloadAckEliciting(buf[0..pos]));
}

test "packetPayloadNeedsImmediateAck flags stream finality and resets" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    pos += try frame_mod.encode(buf[pos..], .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_offset = false,
        .has_length = true,
        .fin = false,
    } });
    try std.testing.expect(!Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));

    pos = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .stream = .{
        .stream_id = 0,
        .offset = 1,
        .data = "",
        .has_offset = true,
        .has_length = true,
        .fin = true,
    } });
    try std.testing.expect(Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));

    pos = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 42,
        .final_size = 1,
    } });
    try std.testing.expect(Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));
}

test "CRYPTO reassembly: out-of-order fragments delivered in order" {
    // Tests the same shape quic-go sends on the wire: a high-offset
    // fragment first, then the low-offset fragment, then a tiny
    // bridge fragment, then the tail.
    const allocator = std.testing.allocator;

    // We don't need a real Connection for this — we exercise the
    // reassembly machinery via a bare struct that holds the same
    // fields. Cleaner: use a real Connection but skip TLS bring-up.
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();

    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    // Don't bind/handshake — we're only testing reassembly, which
    // doesn't need TLS.

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();

    // First fragment: out-of-order high range.
    try conn.handleCrypto(lvl, .{ .offset = 69, .data = "BBBBBBBB" });
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_pending[idx].items.len);

    // Second fragment: in-order low range — delivers immediately.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "AAAAAAAAAAA" }); // 11 bytes
    try std.testing.expectEqual(@as(u64, 11), conn.crypto_recv_offset[idx]);

    // Third fragment: bridges the gap [11, 69) — delivers, then
    // drains the pending [69, 77).
    var bridge: [58]u8 = @splat('M');
    try conn.handleCrypto(lvl, .{ .offset = 11, .data = &bridge });
    try std.testing.expectEqual(@as(u64, 77), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[idx].items.len);

    // Inbox should have all 77 bytes in the right order.
    try std.testing.expectEqual(@as(usize, 77), conn.inbox[idx].len);
    try std.testing.expectEqualSlices(u8, "AAAAAAAAAAA", conn.inbox[idx].buf[0..11]);
    for (conn.inbox[idx].buf[11..69]) |b| try std.testing.expectEqual(@as(u8, 'M'), b);
    try std.testing.expectEqualSlices(u8, "BBBBBBBB", conn.inbox[idx].buf[69..77]);
}

test "CRYPTO reassembly: duplicate fragment is silently ignored" {
    const allocator = std.testing.allocator;
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);

    // Retransmit of the same range — should be a no-op.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 6), conn.inbox[idx].len);

    // Partial overlap (offset=3 covers bytes already delivered + new).
    try conn.handleCrypto(lvl, .{ .offset = 3, .data = "defGHI" });
    try std.testing.expectEqual(@as(u64, 9), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqualSlices(u8, "abcdefGHI", conn.inbox[idx].buf[0..9]);
}

test "CRYPTO reassembly: deterministic shuffled fragment smoke" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();
    const total: usize = 4096;
    const chunk: usize = 64;
    const chunks = total / chunk;

    var data: [total]u8 = undefined;
    var indices: [chunks]usize = undefined;
    var prng = std.Random.DefaultPrng.init(0xc274_7074_6f66_757a);
    const rng = prng.random();
    rng.bytes(&data);
    for (&indices, 0..) |*slot, i| slot.* = i;
    rng.shuffle(usize, &indices);

    for (indices, 0..) |chunk_idx, order| {
        const off = chunk_idx * chunk;
        const bytes = data[off..][0..chunk];
        try conn.handleCrypto(lvl, .{ .offset = @intCast(off), .data = bytes });
        if ((order % 9) == 0) {
            try conn.handleCrypto(lvl, .{ .offset = @intCast(off), .data = bytes });
        }
    }

    try std.testing.expectEqual(@as(u64, total), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[idx].items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[idx]);
    try std.testing.expectEqual(total, conn.inbox[idx].len);
    try std.testing.expectEqualSlices(u8, &data, conn.inbox[idx].buf[0..total]);
}

test "timer deadline reports ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    conn.pnSpaceForLevel(.application).recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "application delayed ACK waits for configured threshold or timer" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    const tracker = &conn.primaryPath().app_pn_space.received;
    const delayed_ack_threshold = 2;
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(7, 1000, true, delayed_ack_threshold);

    try std.testing.expect(!tracker.pending_ack);
    try std.testing.expect(tracker.delayed_ack_armed);
    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);

    try conn.tick(1_009_000);
    try std.testing.expect(!tracker.pending_ack);
    try conn.tick(1_010_000);
    try std.testing.expect(tracker.pending_ack);

    tracker.markAckSent();
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(8, 1011, true, delayed_ack_threshold);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(9, 1012, true, delayed_ack_threshold);
    try std.testing.expect(tracker.pending_ack);
}

test "ACK-only application packets do not consume sent tracker slots" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    var packet_buf: [default_mtu]u8 = undefined;
    var pn: u64 = 0;
    while (pn < 32) : (pn += 1) {
        conn.pnSpaceForLevel(.application).recordReceived(pn, @intCast(1_000 + pn));
        _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000 + pn)).?;
    }

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).count);
    try std.testing.expectEqual(@as(u64, 0), conn.sentForLevel(.application).bytes_in_flight);
}

test "PTO requeues application stream data and arms a probe" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");
    const chunk = s.send.peekChunk(100).?;
    try s.send.recordSent(4, chunk);
    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 4,
        .sent_time_us = 0,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_key = 4,
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(u32, 0), app_sent.count);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u8, 1), conn.primaryPath().pto_probe_count);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
    const resent = s.send.peekChunk(100).?;
    try std.testing.expectEqual(@as(u64, 0), resent.offset);
    try std.testing.expectEqual(@as(u64, 5), resent.length);
}

test "PTO requeues retransmittable control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 8,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .max_data = .{ .maximum_data = 4096 } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(?u64, 4096), conn.pending_max_data);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "poll helper emits one draft multipath control frame with retransmit metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.queuePathStatus(2, false, 7);
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    defer packet.deinit(allocator);
    var payload: [default_mtu]u8 = undefined;
    var pos: usize = 0;

    try std.testing.expect(try conn.emitOnePendingMultipathFrame(&packet, &payload, &pos, default_mtu));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_statuses.items.len);
    try std.testing.expectEqual(@as(usize, 1), packet.retransmit_frames.items.len);
    try std.testing.expect(packet.retransmit_frames.items[0] == .path_status_backup);

    const decoded = try frame_mod.decode(payload[0..pos]);
    try std.testing.expect(decoded.frame == .path_status_backup);
    try std.testing.expectEqual(@as(u32, 2), decoded.frame.path_status_backup.path_id);
    try std.testing.expectEqual(@as(u64, 7), decoded.frame.path_status_backup.sequence_number);
}

test "poll helper coalesces draft multipath control frames with retransmit metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.queuePathStatus(2, true, 7);
    conn.queueMaxPathId(4);
    conn.queuePathsBlocked(3);

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    defer packet.deinit(allocator);
    var payload: [default_mtu]u8 = undefined;
    var pos: usize = 0;

    try std.testing.expect(try conn.emitPendingMultipathFrames(&packet, &payload, &pos, default_mtu));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_statuses.items.len);
    try std.testing.expectEqual(@as(?u32, null), conn.pending_max_path_id);
    try std.testing.expectEqual(@as(?u32, null), conn.pending_paths_blocked);
    try std.testing.expectEqual(@as(usize, 3), packet.retransmit_frames.items.len);
    try std.testing.expect(packet.retransmit_frames.items[0] == .path_status_available);
    try std.testing.expect(packet.retransmit_frames.items[1] == .max_path_id);
    try std.testing.expect(packet.retransmit_frames.items[2] == .paths_blocked);

    var it = frame_mod.iter(payload[0..pos]);
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    const third = (try it.next()).?;
    try std.testing.expect(first == .path_status_available);
    try std.testing.expect(second == .max_path_id);
    try std.testing.expect(third == .paths_blocked);
    try std.testing.expect((try it.next()) == null);
}

test "PTO requeues retransmittable draft multipath control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 11,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = 3,
        .error_code = 99,
    } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_abandons.items.len);
    try std.testing.expectEqual(@as(u32, 3), conn.pending_path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_path_abandons.items[0].error_code);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "PTO arms PING when no retransmittable data can be requeued" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 9,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expect(conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
}

test "requestPing queues application PING on primary path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    conn.requestPing();
    try std.testing.expect(conn.primaryPath().pending_ping);

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;

    try std.testing.expect(!conn.primaryPath().pending_ping);
    try std.testing.expectEqual(@as(u32, 1), conn.primaryPath().sent.count);
    try std.testing.expect(conn.primaryPath().sent.packets[0].ack_eliciting);
}

test "requestPathPing queues application PING on non-primary path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));

    try conn.requestPathPing(path_id);
    const path = conn.paths.get(path_id).?;
    try std.testing.expect(path.pending_ping);

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_000_000)).?;

    try std.testing.expect(!path.pending_ping);
    try std.testing.expectEqual(@as(u32, 1), path.sent.count);
    try std.testing.expect(path.sent.packets[0].ack_eliciting);
}

test "PTO requeues CRYPTO bytes at original offsets" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const level: EncryptionLevel = .initial;
    const level_idx = level.idx();
    const bytes = try allocator.dupe(u8, "crypto-fragment");
    var bytes_moved = false;
    errdefer if (!bytes_moved) allocator.free(bytes);
    try conn.sent_crypto[level_idx].append(allocator, .{
        .pn = 2,
        .offset = 123,
        .data = bytes,
    });
    bytes_moved = true;
    try conn.sentForLevel(level).record(.{
        .pn = 2,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(level));

    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[level_idx].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[level_idx].items.len);
    try std.testing.expectEqual(@as(u64, 123), conn.crypto_retx[level_idx].items[0].offset);
    try std.testing.expectEqualStrings("crypto-fragment", conn.crypto_retx[level_idx].items[0].data);
}

test "ACK of ack-eliciting packet resets PTO count and updates RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ptoCountForLevel(.application).* = 3;
    try conn.sentForLevel(.application).record(.{
        .pn = 11,
        .sent_time_us = 1_000_000,
        .bytes = 120,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 12;
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 11,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), conn.ptoCountForLevel(.application).*);
    try std.testing.expectEqual(@as(u64, 50_000), conn.rttForLevel(.application).latest_rtt_us);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).count);
}

test "ACK with largest_acked >= next_pn is a PROTOCOL_VIOLATION" {
    // RFC 9000 §13.1 / RFC 9002 §A.3: "Receipt of an acknowledgment
    // for a packet that was not sent ... MUST be treated as a
    // connection error of type PROTOCOL_VIOLATION." A peer that
    // claims to have acked a PN we never sent is either buggy or
    // hostile; we must close the connection rather than poison
    // packet-threshold loss detection on our legitimate in-flight
    // packets.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // We have two in-flight packets at PNs 0 and 1.
    try conn.sentForLevel(.application).record(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 1_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 2;

    // Peer claims an ACK for PN 7 — well beyond next_pn = 2.
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 7,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 100_000);

    // Connection must be closing with PROTOCOL_VIOLATION.
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(transport_error_protocol_violation, sticky.error_code);

    // Critically, our in-flight packets must NOT have been declared
    // lost or had their largest_acked_sent updated to the bogus 7.
    try std.testing.expectEqual(@as(u32, 2), conn.sentForLevel(.application).count);
    try std.testing.expectEqual(@as(?u64, null), conn.pnSpaceForLevel(.application).largest_acked_sent);
}

test "ACK with largest_acked == next_pn is a PROTOCOL_VIOLATION" {
    // Boundary case: next_pn is the *next* PN to assign on send,
    // so an ACK whose largest_acked equals next_pn is also illegal.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.sentForLevel(.application).record(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 1;

    // ACK claims PN 1, but next_pn is 1 (we've never sent PN 1).
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 100_000);

    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expectEqual(transport_error_protocol_violation, conn.closeEvent().?.error_code);
}

test "ACKed in-flight packets grow congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const initial_cwnd = conn.congestionWindow();
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 2;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_010_000);

    try std.testing.expect(conn.congestionWindow() > initial_cwnd);
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "packet-threshold loss reduces congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const initial_cwnd = conn.congestionWindow();
    var pn: u64 = 0;
    while (pn <= 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 1_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    conn.pnSpaceForLevel(.application).next_pn = 5;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 4,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 50_000);

    try std.testing.expect(conn.congestionWindow() < initial_cwnd);
    try std.testing.expect(conn.ccForApplication().ssthresh != null);
}

test "persistent congestion resets congestion window to minimum" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ccForApplication().cwnd = 30_000;
    conn.rttForLevel(.application).smoothed_rtt_us = 10_000;
    conn.rttForLevel(.application).latest_rtt_us = 10_000;
    conn.rttForLevel(.application).rtt_var_us = 1_000;
    conn.rttForLevel(.application).first_sample_taken = true;

    conn.pnSpaceForLevel(.application).largest_acked_sent = 10;
    var pn: u64 = 0;
    while (pn < 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 100_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    try conn.tick(1_000_000);

    try std.testing.expectEqual(conn.ccForApplication().cfg.minWindow(), conn.congestionWindow());
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "persistent congestion ignores non-ack-eliciting losses (RFC 9002 §7.6.1)" {
    // RFC 9002 §7.6.1: "Two ack-eliciting packets ... are declared
    // lost". A duration spanned only by non-ack-eliciting lost
    // packets must NOT establish persistent congestion.
    var stats: LossStats = .{};
    // Two non-ack-eliciting "lost" packets spanning a wide duration
    // (300ms). With pto = 30ms and threshold = 3, the unfiltered
    // earliest/largest range would easily satisfy the old check —
    // this regression-tests the ack-eliciting filter.
    stats.add(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    stats.add(.{
        .pn = 1,
        .sent_time_us = 300_000,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));

    // Adding a single ack-eliciting lost packet still doesn't
    // qualify — RFC requires *two* ack-eliciting losses bounding
    // the duration.
    stats.add(.{
        .pn = 2,
        .sent_time_us = 150_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));

    // Two ack-eliciting lost packets bounding the duration → fires.
    stats.add(.{
        .pn = 3,
        .sent_time_us = 400_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // duration (400ms − 150ms) = 250ms ≥ 3 × 30ms = 90ms → fires.
    try std.testing.expect(Connection.isPersistentCongestionFromBasePto(30_000, stats));
}

test "persistent congestion duration uses only ack-eliciting bounds" {
    // Mixed losses: a wide-spanning non-ack-eliciting lost packet
    // must NOT inflate the duration computed from the narrower
    // ack-eliciting subset.
    var stats: LossStats = .{};
    // Non-ack-eliciting at t=0 (would extend duration to 100ms).
    stats.add(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    // Two ack-eliciting losses inside a narrower window.
    stats.add(.{
        .pn = 1,
        .sent_time_us = 80_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    stats.add(.{
        .pn = 2,
        .sent_time_us = 100_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // base_pto = 30ms → threshold = 90ms. Ack-eliciting duration is
    // only 20ms (100ms − 80ms), so persistent congestion must NOT
    // fire even though the unfiltered duration (100ms) exceeds the
    // threshold.
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));
}

test "congestionBlocked gates application data but allows PTO probes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ccForApplication().cwnd = 1200;
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try std.testing.expect(conn.congestionBlocked(.application));
    try std.testing.expect(!conn.congestionBlocked(.initial));
    conn.pendingPingForLevel(.application).* = true;
    try std.testing.expect(!conn.congestionBlocked(.application));
    conn.pendingPingForLevel(.application).* = false;
    conn.primaryPath().pto_probe_count = 1;
    try std.testing.expect(!conn.congestionBlocked(.application));
}

test "PathSet API exposes path lifecycle and application recovery state" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.enableMultipath(true);
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
    const initial = conn.pathStats(0).?;
    try std.testing.expect(initial.validated);
    try std.testing.expectEqual(@as(u64, 0), initial.bytes_in_flight);

    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    const after_send = conn.pathStats(0).?;
    try std.testing.expectEqual(@as(u64, 1200), after_send.bytes_in_flight);

    const id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    try std.testing.expectEqual(@as(u32, 1), id);
    try std.testing.expect(conn.setActivePath(id));
    try std.testing.expectEqual(id, conn.activePathId());
    try std.testing.expect(conn.markPathValidated(id));
    try std.testing.expect(conn.pathStats(id).?.validated);
    try std.testing.expect(conn.setPathBackup(id, true));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_statuses.items.len);
    try std.testing.expect(!conn.pending_path_statuses.items[0].available);
    conn.setScheduler(.round_robin);
    try std.testing.expect(conn.abandonPath(id));
    try std.testing.expectEqual(path_mod.State.retiring, conn.pathStats(id).?.state);
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
}

test "abandoned paths keep recovery until three largest PTOs elapse" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    try path.sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000,
        .bytes = 64,
        .ack_eliciting = false,
        .in_flight = false,
    });

    conn.primaryPath().pto_count = 1;
    const now_us: u64 = 10_000;
    const expected_deadline = now_us +| 3 * conn.largestApplicationPtoDurationUs();
    try std.testing.expect(conn.abandonPathAt(path_id, 42, now_us));
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqual(expected_deadline, path.retire_deadline_us.?);
    try std.testing.expectEqual(expected_deadline, conn.pathStats(path_id).?.retire_deadline_us.?);

    const deadline = conn.nextTimerDeadline(now_us).?;
    try std.testing.expectEqual(TimerKind.path_retirement, deadline.kind);
    try std.testing.expectEqual(path_id, deadline.path_id);

    try conn.tick(expected_deadline - 1);
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqual(@as(u32, 1), path.sent.count);

    try conn.tick(expected_deadline);
    try std.testing.expectEqual(path_mod.State.failed, path.path.state);
    try std.testing.expectEqual(@as(?u64, null), path.retire_deadline_us);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
}

test "retiring paths retain peer CIDs and emit PATH_ACK during drain" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    const now_us: u64 = 10_000;
    const expected_deadline = now_us +| conn.retiredPathRetentionUs();
    try std.testing.expect(conn.abandonPathAt(path_id, 42, now_us));
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqualSlices(u8, &.{0xbb}, path.path.peer_cid.slice());

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, now_us + 1)).?;
    try std.testing.expectEqual(path_id, datagram.path_id);
    try std.testing.expect(!path.app_pn_space.received.pending_ack);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..datagram.len], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
        .multipath_path_id = path_id,
    });

    var saw_path_ack = false;
    var saw_path_abandon = false;
    var it = frame_mod.iter(opened.payload);
    while (try it.next()) |frame| switch (frame) {
        .path_ack => |ack| {
            saw_path_ack = true;
            try std.testing.expectEqual(path_id, ack.path_id);
            try std.testing.expectEqual(@as(u64, 9), ack.largest_acked);
        },
        .path_abandon => |abandon| {
            saw_path_abandon = true;
            try std.testing.expectEqual(path_id, abandon.path_id);
            try std.testing.expectEqual(@as(u64, 42), abandon.error_code);
        },
        else => {},
    };
    try std.testing.expect(saw_path_ack);
    try std.testing.expect(saw_path_abandon);

    try conn.tick(expected_deadline);
    try std.testing.expectEqual(path_mod.State.failed, path.path.state);
    try std.testing.expectEqual(@as(u8, 0), path.path.peer_cid.len);
}

test "PATH_ACK routes ACK processing to the indicated application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    const path = conn.paths.get(path_id).?;
    try path.sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    path.app_pn_space.next_pn = 1;

    try conn.handlePathAck(.{
        .path_id = path_id,
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expectEqual(@as(u64, 0), path.sent.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.largest_acked_sent);
    try std.testing.expectEqual(@as(u64, 50_000), path.path.rtt.latest_rtt_us);
}

fn installTestApplicationWriteSecret(conn: *Connection) !void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    try conn.installApplicationSecret(.write, material);
}

fn installTestApplicationReadSecret(conn: *Connection) !void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    try conn.installApplicationSecret(.read, material);
}

fn installTestEarlyDataWriteSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].write = material;
}

fn installTestEarlyDataReadSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].read = material;
}

test "peer key update promotes next read keys and keeps previous until discard deadline" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    const old_epoch = conn.app_read_current.?;
    const next_epoch = conn.app_read_next.?;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });

    var packet_buf: [default_mtu]u8 = undefined;
    const new_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 1,
        .largest_acked = 0,
        .payload = payload[0..payload_len],
        .keys = &next_epoch.keys,
        .key_phase = next_epoch.key_phase,
    });

    _ = try conn.handleShort(packet_buf[0..new_len], 1_000_000);
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.read_epoch);
    try std.testing.expect(status.read_key_phase);
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_key_phase);
    try std.testing.expect(status.write_update_pending_ack);
    const discard_deadline = status.previous_read_discard_deadline_us.?;

    const old_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .largest_acked = 0,
        .payload = payload[0..payload_len],
        .keys = &old_epoch.keys,
        .key_phase = old_epoch.key_phase,
    });
    _ = try conn.handleShort(packet_buf[0..old_len], 1_001_000);
    try std.testing.expectEqual(@as(u64, 0), conn.keyUpdateStatus().auth_failures);
    try std.testing.expect(conn.app_read_previous != null);

    try conn.tick(discard_deadline);
    try std.testing.expect(conn.app_read_previous == null);

    const late_old_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 2,
        .largest_acked = 1,
        .payload = payload[0..payload_len],
        .keys = &old_epoch.keys,
        .key_phase = old_epoch.key_phase,
    });
    _ = try conn.handleShort(packet_buf[0..late_old_len], discard_deadline + 1);
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(u64, 1), status.auth_failures);
}

test "local key update waits for ACK and three PTOs before the next update" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{});

    try conn.requestKeyUpdate(1_000_000);
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_key_phase);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectError(Error.KeyUpdateBlocked, conn.requestKeyUpdate(1_001_000));

    conn.primaryPath().pending_ping = true;
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_002_000)).?;
    try std.testing.expectEqual(@as(?u64, 1), conn.primaryPath().sent.packets[0].key_epoch);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);
    status = conn.keyUpdateStatus();
    try std.testing.expect(!status.write_update_pending_ack);
    const next_after = status.next_local_update_after_us.?;
    try std.testing.expect(!conn.canInitiateKeyUpdateAt(next_after - 1));
    try std.testing.expectError(Error.KeyUpdateBlocked, conn.requestKeyUpdate(next_after - 1));
    try conn.requestKeyUpdate(next_after);
    try std.testing.expectEqual(@as(?u64, 2), conn.keyUpdateStatus().write_epoch);
}

test "automatic write key update happens before configured packet limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 4,
        .proactive_update_threshold = 1,
        .integrity_limit = 4,
    });
    try conn.setPeerDcid(&.{});

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(?u64, 0), conn.keyUpdateStatus().write_epoch);
    try std.testing.expectEqual(@as(u64, 1), conn.keyUpdateStatus().write_packets_protected);

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    const status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);
}

test "application packet limit counts across paths before proactive key update" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 8,
        .proactive_update_threshold = 2,
        .integrity_limit = 8,
    });
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 0), status.write_epoch);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);

    const path = conn.paths.get(path_id).?;
    path.pending_ping = true;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 0), status.write_epoch);
    try std.testing.expectEqual(@as(u64, 2), status.write_packets_protected);

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_002_000)).?;
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);
}

test "non-zero path ACK clears local key update gate" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    try conn.requestKeyUpdate(1_000_000);

    const path = conn.paths.get(path_id).?;
    path.pending_ping = true;
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    try std.testing.expect(conn.keyUpdateStatus().write_update_pending_ack);

    try conn.handlePathAck(.{
        .path_id = path_id,
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);
    try std.testing.expect(!conn.keyUpdateStatus().write_update_pending_ack);
}

test "qlog callback records application key update lifecycle" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    try std.testing.expect(recorder.contains(.application_read_key_installed));
    try std.testing.expect(recorder.contains(.application_write_key_installed));

    try conn.promoteApplicationReadKeys(1_000_000);
    try std.testing.expect(recorder.contains(.application_read_key_discard_scheduled));
    try std.testing.expect(recorder.contains(.application_read_key_updated));

    try conn.requestKeyUpdate(1_100_000);
    const write_epoch = conn.app_write_current.?;
    try std.testing.expect(recorder.contains(.application_write_key_updated));
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 42,
        .sent_time_us = 1_100_000,
        .bytes = 64,
        .ack_eliciting = true,
        .in_flight = true,
        .key_epoch = write_epoch.epoch,
        .key_phase = write_epoch.key_phase,
    };
    conn.onApplicationPacketAckedForKeys(&packet, 1_150_000);
    try std.testing.expect(recorder.contains(.application_write_update_acked));

    const discard_deadline = conn.app_read_previous.?.discard_deadline_us.?;
    try conn.tick(discard_deadline);
    try std.testing.expect(recorder.contains(.application_read_key_discarded));
}

test "qlog records AEAD confidentiality-limit close" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 1,
        .proactive_update_threshold = 99,
        .integrity_limit = 99,
    });
    try conn.setPeerDcid(&.{});

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expect(!recorder.contains(.aead_confidentiality_limit_reached));

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    try std.testing.expect(recorder.contains(.aead_confidentiality_limit_reached));
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, close_event.source);
    try std.testing.expectEqual(transport_error_aead_limit_reached, close_event.error_code);
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
}

test "AEAD authentication failure limit closes the connection" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 4,
        .proactive_update_threshold = 3,
        .integrity_limit = 1,
    });
    const keys = conn.app_read_current.?.keys;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });
    packet_buf[n - 1] ^= 0x01;

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_aead_limit_reached, conn.pending_close.?.error_code);
}

fn testEarlyDataPacketKeys() !PacketKeys {
    const secret: [32]u8 = @splat(0);
    return try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &secret);
}

const TestQlogRecorder = struct {
    events: [128]QlogEvent = undefined,
    count: usize = 0,

    fn callback(user_data: ?*anyopaque, event: QlogEvent) void {
        const self: *TestQlogRecorder = @ptrCast(@alignCast(user_data.?));
        if (self.count >= self.events.len) return;
        self.events[self.count] = event;
        self.count += 1;
    }

    fn contains(self: *const TestQlogRecorder, name: QlogEventName) bool {
        for (self.events[0..self.count]) |event| {
            if (event.name == name) return true;
        }
        return false;
    }

    fn first(self: *const TestQlogRecorder, name: QlogEventName) ?QlogEvent {
        for (self.events[0..self.count]) |event| {
            if (event.name == name) return event;
        }
        return null;
    }

    fn countOf(self: *const TestQlogRecorder, name: QlogEventName) usize {
        var n: usize = 0;
        for (self.events[0..self.count]) |event| {
            if (event.name == name) n += 1;
        }
        return n;
    }
};

fn markTestMultipathNegotiated(conn: *Connection, max_path_id: u32) void {
    conn.enableMultipath(true);
    conn.local_transport_params.initial_max_path_id = max_path_id;
    conn.local_max_path_id = max_path_id;
    conn.cached_peer_transport_params = .{ .initial_max_path_id = max_path_id };
    conn.peer_max_path_id = max_path_id;
}

test "setTransportParams advertises bounded UDP payload limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_datagram_frame_size = 9000 });
    try std.testing.expectEqual(@as(u64, max_supported_udp_payload_size), conn.local_transport_params.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, max_supported_udp_payload_size), conn.local_transport_params.max_datagram_frame_size);

    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{ .max_udp_payload_size = default_mtu - 1 }));
}

test "peer transport parameter limit violations use transport parameter error" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initClient(allocator, ctx, "x");
        defer conn.deinit();
        conn.cached_peer_transport_params = .{ .max_udp_payload_size = min_quic_udp_payload_size - 1 };
        conn.validatePeerTransportLimits();
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_transport_parameter, conn.pending_close.?.error_code);
        try std.testing.expectEqualStrings("peer max udp payload below minimum", conn.pending_close.?.reason);
    }

    {
        var conn = try Connection.initClient(allocator, ctx, "x");
        defer conn.deinit();
        conn.cached_peer_transport_params = .{ .initial_max_streams_bidi = max_stream_count_limit + 1 };
        conn.validatePeerTransportLimits();
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_transport_parameter, conn.pending_close.?.error_code);
        try std.testing.expectEqualStrings("peer stream count exceeds maximum", conn.pending_close.?.reason);
    }
}

test "handle rejects UDP datagrams above local payload limit before path credit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_udp_payload_size = default_mtu });

    var bytes: [default_mtu + 1]u8 = @splat(0);
    try conn.handle(&bytes, null, 123);

    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
    try std.testing.expectEqual(@as(u64, 0), conn.primaryPath().path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), conn.last_activity_us);
}

test "sendDatagram enforces peer support and bounded queue" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 0 };
    try std.testing.expectError(Error.DatagramUnavailable, conn.sendDatagram("x"));

    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 4 };
    try std.testing.expectError(Error.DatagramTooLarge, conn.sendDatagram("12345"));
    try conn.sendDatagram("1234");
    try std.testing.expectEqual(@as(usize, 1), conn.pending_send_datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 4), conn.pending_send_datagram_bytes);

    while (conn.pending_send_datagrams.items.len < max_pending_datagram_count) {
        try conn.sendDatagram("x");
    }
    try std.testing.expectError(Error.DatagramQueueFull, conn.sendDatagram("x"));
}

test "tracked DATAGRAM emits ack event when packet is acknowledged" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    const id = try conn.sendDatagramTracked("ack-me");
    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;

    const sent = conn.primaryPath().sent.packets[0];
    try std.testing.expect(sent.datagram != null);
    try std.testing.expectEqual(id, sent.datagram.?.id);
    try std.testing.expectEqual(@as(usize, 6), sent.datagram.?.len);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = sent.pn,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(id, event.datagram_acked.id);
    try std.testing.expectEqual(@as(usize, 6), event.datagram_acked.len);
    try std.testing.expectEqual(sent.pn, event.datagram_acked.packet_number);
    try std.testing.expectEqual(@as(u32, 0), event.datagram_acked.path_id);
    try std.testing.expect(!event.datagram_acked.arrived_in_early_data);
    try std.testing.expect(conn.pollEvent() == null);
}

test "tracked DATAGRAM emits loss event without retransmission" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    const id = try conn.sendDatagramTracked("lost");
    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;

    var lost = conn.primaryPath().sent.removeAt(0);
    defer lost.deinit(conn.allocator);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_send_datagrams.items.len);
    try std.testing.expect(!(try conn.requeueLostPacket(.application, &lost)));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_send_datagrams.items.len);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(id, event.datagram_lost.id);
    try std.testing.expectEqual(@as(usize, 4), event.datagram_lost.len);
    try std.testing.expectEqual(lost.pn, event.datagram_lost.packet_number);
}

test "handleDatagram enforces local DATAGRAM limit and queue budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 0), conn.pending_recv_datagrams.items.len);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        conn.local_transport_params.max_datagram_frame_size = max_supported_udp_payload_size;
        while (conn.pending_recv_datagrams.items.len < max_pending_datagram_count) {
            try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        }
        try std.testing.expectEqual(max_pending_datagram_count, conn.pending_recv_datagrams.items.len);
        try std.testing.expectEqual(max_pending_datagram_count, conn.pending_recv_datagram_bytes);

        var buf: [1]u8 = undefined;
        const info = conn.receiveDatagramInfo(&buf).?;
        try std.testing.expectEqual(@as(usize, 1), info.len);
        try std.testing.expectEqual(max_pending_datagram_count - 1, conn.pending_recv_datagrams.items.len);
        try std.testing.expectEqual(max_pending_datagram_count - 1, conn.pending_recv_datagram_bytes);

        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
    }
}

test "handleCrypto bounds out-of-order reassembly" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.handleCrypto(.initial, .{ .offset = max_crypto_reassembly_gap + 1, .data = "x" });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[0]);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        var huge: [max_pending_crypto_bytes_per_level + 1]u8 = @splat(0);
        try conn.handleCrypto(.initial, .{ .offset = 1, .data = &huge });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[0]);
    }
}

test "peer-created streams respect advertised stream count" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = 1,
    });

    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "a",
        .has_length = true,
    });
    try std.testing.expectEqual(@as(u64, 1), conn.peer_opened_streams_bidi);
    try std.testing.expect(conn.pending_close == null);

    try conn.handleStream(.application, .{
        .stream_id = 4,
        .offset = 0,
        .data = "b",
        .has_length = true,
    });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_stream_limit, conn.pending_close.?.error_code);
}

test "local transport params reject allocation policy overflows" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_streams_bidi = max_streams_per_connection + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_streams_uni = max_streams_per_connection + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .active_connection_id_limit = max_supported_active_connection_id_limit + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_path_id = max_supported_path_id + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_data = max_initial_connection_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_bidi_local = max_initial_stream_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_bidi_remote = max_initial_stream_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_uni = max_initial_stream_receive_window + 1,
    }));
}

test "bounded policy clamps MAX_STREAMS MAX_PATH_ID and peer CID fanout" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_streams_bidi = 0;
    conn.peer_max_streams_uni = 0;
    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = max_streams_per_connection + 100 });
    conn.handleMaxStreams(.{ .bidi = false, .maximum_streams = max_streams_per_connection + 100 });
    try std.testing.expectEqual(max_streams_per_connection, conn.peer_max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.peer_max_streams_uni);

    conn.queueMaxStreams(true, max_streams_per_connection + 100);
    conn.queueMaxStreams(false, max_streams_per_connection + 100);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_uni);
    try std.testing.expectEqual(max_streams_per_connection, conn.pending_max_streams_bidi.?);
    try std.testing.expectEqual(max_streams_per_connection, conn.pending_max_streams_uni.?);

    conn.queueMaxPathId(max_supported_path_id + 100);
    try std.testing.expectEqual(max_supported_path_id, conn.local_max_path_id);
    try std.testing.expectEqual(max_supported_path_id, conn.pending_max_path_id.?);

    conn.cached_peer_transport_params = .{
        .active_connection_id_limit = max_supported_active_connection_id_limit + 100,
    };
    try std.testing.expectEqual(
        max_supported_active_connection_id_limit,
        conn.peerActiveConnectionIdLimit(),
    );
}

test "STREAM_DATA_BLOCKED tracking is bounded and validates stream space" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.setTransportParams(.{ .initial_max_streams_bidi = 1 });
        try conn.handleStreamDataBlocked(.{ .stream_id = 0, .maximum_stream_data = 7 });
        try std.testing.expect(conn.pending_close == null);
        try std.testing.expectEqual(@as(usize, 1), conn.peer_stream_data_blocked.items.len);

        try conn.handleStreamDataBlocked(.{ .stream_id = 4, .maximum_stream_data = 7 });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_stream_limit, conn.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 1), conn.peer_stream_data_blocked.items.len);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.handleStreamDataBlocked(.{ .stream_id = 3, .maximum_stream_data = 7 });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_stream_state, conn.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 0), conn.peer_stream_data_blocked.items.len);
    }

    {
        var list: std.ArrayList(frame_types.StreamDataBlocked) = .empty;
        defer list.deinit(allocator);
        var i: usize = 0;
        while (i < max_tracked_stream_data_blocked) : (i += 1) {
            try list.append(allocator, .{
                .stream_id = @as(u64, @intCast(i)) * 4,
                .maximum_stream_data = 1,
            });
        }
        try std.testing.expectError(Error.StreamLimitExceeded, Connection.upsertStreamBlocked(&list, allocator, .{
            .stream_id = @as(u64, @intCast(max_tracked_stream_data_blocked)) * 4,
            .maximum_stream_data = 1,
        }));
        try std.testing.expectEqual(max_tracked_stream_data_blocked, list.items.len);
    }
}

test "STREAM receive enforces stream and connection flow control" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.setTransportParams(.{
            .initial_max_data = 16,
            .initial_max_stream_data_bidi_remote = 3,
            .initial_max_streams_bidi = 1,
        });
        try conn.handleStream(.application, .{
            .stream_id = 0,
            .offset = 0,
            .data = "abcd",
            .has_length = true,
        });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_flow_control, conn.pending_close.?.error_code);
        try std.testing.expectEqual(@as(u64, 0), conn.peer_sent_stream_data);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.setTransportParams(.{
            .initial_max_data = 5,
            .initial_max_stream_data_bidi_remote = 8,
            .initial_max_streams_bidi = 2,
        });
        try conn.handleStream(.application, .{
            .stream_id = 0,
            .offset = 0,
            .data = "hello",
            .has_length = true,
        });
        try std.testing.expect(conn.pending_close == null);
        try std.testing.expectEqual(@as(u64, 5), conn.peer_sent_stream_data);
        try conn.handleStream(.application, .{
            .stream_id = 4,
            .offset = 0,
            .data = "!",
            .has_length = true,
        });
        try std.testing.expect(conn.pending_close != null);
        try std.testing.expectEqual(transport_error_flow_control, conn.pending_close.?.error_code);
        try std.testing.expectEqual(@as(u64, 5), conn.peer_sent_stream_data);
    }
}

test "MAX_DATA MAX_STREAM_DATA and MAX_STREAMS raise send-side limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_data = 4;
    conn.peer_max_streams_bidi = 1;
    const s0 = try conn.openBidi(0);
    s0.send_max_data = 4;

    try std.testing.expectError(Error.StreamLimitExceeded, conn.openBidi(4));
    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = 2 });
    _ = try conn.openBidi(4);

    conn.handleMaxData(.{ .maximum_data = 32 });
    conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 16 });
    try std.testing.expectEqual(@as(u64, 32), conn.peer_max_data);
    try std.testing.expectEqual(@as(u64, 16), conn.stream(0).?.send_max_data);
}

test "send-side STREAM emission is capped by flow-control allowance" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_data = 4;
    conn.peer_max_streams_bidi = 1;
    const s = try conn.openBidi(0);
    s.send_max_data = 8;
    _ = try s.send.write("abcdefgh");

    const raw = s.send.peekChunk(64).?;
    const limited = (try conn.limitChunkToSendFlow(s, raw)).?;
    try std.testing.expectEqual(@as(u64, 4), limited.length);
    try std.testing.expect(!limited.fin);

    conn.recordStreamFlowSent(s, limited);
    try std.testing.expectEqual(@as(u64, 4), conn.we_sent_stream_data);
    try std.testing.expectEqual(@as(u64, 4), s.send_flow_highest);
    const retransmit_only = (try conn.limitChunkToSendFlow(s, raw)).?;
    try std.testing.expectEqual(@as(u64, 4), retransmit_only.length);
    try std.testing.expect(!retransmit_only.fin);
    try std.testing.expectEqual(@as(?u64, 4), conn.localDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, 4), conn.pending_data_blocked);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.local, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(u64, 4), event.flow_blocked.limit);

    conn.handleMaxData(.{ .maximum_data = 16 });
    try std.testing.expectEqual(@as(?u64, null), conn.localDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, null), conn.pending_data_blocked);
}

test "receive flow-control MAX updates are paced by half-window" {
    try std.testing.expect(!Connection.shouldQueueReceiveCredit(
        1,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(!Connection.shouldQueueReceiveCredit(
        default_stream_receive_window / 2 - 1,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(Connection.shouldQueueReceiveCredit(
        default_stream_receive_window / 2,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(Connection.shouldQueueReceiveCredit(
        1,
        16,
        default_stream_receive_window,
    ));

    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = default_connection_receive_window,
        .initial_max_stream_data_bidi_remote = default_stream_receive_window,
        .initial_max_streams_bidi = 1,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_max_stream_data.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_max_data);
}

test "stream flow block queues STREAM_DATA_BLOCKED and clears on MAX_STREAM_DATA" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_data = 16;
    conn.peer_max_streams_bidi = 1;
    const s = try conn.openBidi(0);
    s.send_max_data = 4;
    _ = try s.send.write("abcdefgh");

    const raw = s.send.peekChunk(64).?;
    const limited = (try conn.limitChunkToSendFlow(s, raw)).?;
    conn.recordStreamFlowSent(s, limited);
    _ = (try conn.limitChunkToSendFlow(s, raw)).?;

    try std.testing.expectEqual(@as(?u64, 4), conn.localStreamDataBlockedAt(0));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_stream_data_blocked.items.len);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.stream_data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?u64, 0), event.flow_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 4), event.flow_blocked.limit);

    conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 8 });
    try std.testing.expectEqual(@as(?u64, null), conn.localStreamDataBlockedAt(0));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stream_data_blocked.items.len);
}

test "STREAMS_BLOCKED is queued when local stream opening hits peer limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_streams_bidi = 0;
    try std.testing.expectError(Error.StreamLimitExceeded, conn.openBidi(0));
    try std.testing.expectEqual(@as(?u64, 0), conn.localStreamsBlockedAt(true));
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_streams_blocked_bidi);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.local, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.streams, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?bool, true), event.flow_blocked.bidi);

    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = 1 });
    try std.testing.expectEqual(@as(?u64, null), conn.localStreamsBlockedAt(true));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_streams_blocked_bidi);
}

test "blocked frames emit with retransmit metadata and requeue on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    conn.noteDataBlocked(7);
    try conn.noteStreamDataBlocked(0, 11);
    conn.noteStreamsBlocked(true, 3);

    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;
    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 3), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .data_blocked);
    try std.testing.expect(sent.retransmit_frames.items[1] == .stream_data_blocked);
    try std.testing.expect(sent.retransmit_frames.items[2] == .streams_blocked);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_data_blocked);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_streams_blocked_bidi);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expectEqual(@as(?u64, 7), conn.pending_data_blocked);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, 3), conn.pending_streams_blocked_bidi);
}

test "stale blocked frames are not requeued after peer raises limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.noteDataBlocked(7);
    try conn.noteStreamDataBlocked(0, 11);
    conn.noteStreamsBlocked(true, 3);
    conn.clearLocalDataBlocked(8);
    conn.clearLocalStreamDataBlocked(0, 12);
    conn.clearLocalStreamsBlocked(true, 4);

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 9,
        .sent_time_us = 1_000,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer packet.deinit(allocator);
    try packet.addRetransmitFrame(allocator, .{ .data_blocked = .{ .maximum_data = 7 } });
    try packet.addRetransmitFrame(allocator, .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 11,
    } });
    try packet.addRetransmitFrame(allocator, .{ .streams_blocked = .{
        .bidi = true,
        .maximum_streams = 3,
    } });

    try std.testing.expect(!(try conn.dispatchLostControlFrames(&packet)));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_data_blocked);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_streams_blocked_bidi);
}

test "inbound blocked frames update peer state and pollable events" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{ .initial_max_streams_bidi = 2 });
    conn.handleDataBlocked(.{ .maximum_data = 10 });
    try conn.handleStreamDataBlocked(.{ .stream_id = 4, .maximum_stream_data = 20 });
    conn.handleStreamsBlocked(.{ .bidi = false, .maximum_streams = 2 });

    try std.testing.expectEqual(@as(?u64, 10), conn.peerDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, 20), conn.peerStreamDataBlockedAt(4));
    try std.testing.expectEqual(@as(?u64, 2), conn.peerStreamsBlockedAt(false));

    var event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.peer, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.data, event.flow_blocked.kind);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.stream_data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?u64, 4), event.flow_blocked.stream_id);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.streams, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?bool, false), event.flow_blocked.bidi);
}

test "draining a peer-initiated stream returns MAX_STREAMS credit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = 1,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
        .fin = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(?u64, 17), conn.pending_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 17), conn.local_max_streams_bidi);
}

test "draining at stream cap does not queue duplicate MAX_STREAMS" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = max_streams_per_connection,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
        .fin = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_bidi);
}

test "0-RTT send path requires explicit per-connection opt-in" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.pollLevel(.early_data, &out, 1_000));
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
}

test "0-RTT poll emits long-header packet in Application PN space" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    const n = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expect(n > 0);
    try std.testing.expect((out[0] & 0x80) != 0);
    try std.testing.expectEqual(@as(u2, 1), @as(u2, @intCast((out[0] >> 4) & 0x03)));
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);
    try std.testing.expect(conn.sentForLevel(.early_data).packets[0].is_early_data);
    try std.testing.expectEqual(@as(u64, 1), conn.pnSpaceForLevel(.early_data).next_pn);
}

test "0-RTT rejection requeues STREAM data but not DATAGRAM payloads" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const datagram_id = try conn.sendDatagramTracked("early-datagram");
    const s = try conn.openBidi(0);
    _ = try s.send.write("early-stream");

    var out: [512]u8 = undefined;
    const n = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expect(n > 0);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_send_datagrams.items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);

    try conn.requeueRejectedEarlyData();

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_send_datagrams.items.len);
    const chunk = s.send.peekChunk(64).?;
    try std.testing.expectEqual(@as(u64, 0), chunk.offset);
    try std.testing.expectEqual(@as(u64, 12), chunk.length);
    try std.testing.expectEqualSlices(u8, "early-stream", s.send.chunkBytes(chunk));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(datagram_id, event.datagram_lost.id);
    try std.testing.expect(event.datagram_lost.arrived_in_early_data);
}

test "0-RTT DATAGRAM ack event carries early-data metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const datagram_id = try conn.sendDatagramTracked("early-ack");
    var out: [256]u8 = undefined;
    _ = (try conn.pollLevel(.early_data, &out, 1_000)).?;

    const sent = conn.sentForLevel(.early_data).packets[0];
    try std.testing.expect(sent.is_early_data);
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = sent.pn,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(datagram_id, event.datagram_acked.id);
    try std.testing.expectEqual(@as(usize, 9), event.datagram_acked.len);
    try std.testing.expectEqual(sent.pn, event.datagram_acked.packet_number);
    try std.testing.expect(event.datagram_acked.arrived_in_early_data);
    try std.testing.expect(conn.pollEvent() == null);
}

test "0-RTT DATAGRAM packet-threshold loss carries early-data metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    var datagram_ids: [4]u64 = undefined;
    var out: [256]u8 = undefined;
    for (&datagram_ids, 0..) |*id, i| {
        id.* = try conn.sendDatagramTracked(if (i == 0) "lost" else "acked");
        _ = (try conn.pollLevel(.early_data, &out, 1_000 + @as(u64, @intCast(i)))).?;
    }
    try std.testing.expectEqual(@as(u32, 4), conn.sentForLevel(.early_data).count);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 3,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 2_000);

    var event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(datagram_ids[3], event.datagram_acked.id);
    try std.testing.expectEqual(@as(u64, 3), event.datagram_acked.packet_number);
    try std.testing.expect(event.datagram_acked.arrived_in_early_data);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(datagram_ids[0], event.datagram_lost.id);
    try std.testing.expectEqual(@as(u64, 0), event.datagram_lost.packet_number);
    try std.testing.expect(event.datagram_lost.arrived_in_early_data);
    try std.testing.expectEqual(@as(u32, 2), conn.sentForLevel(.early_data).count);
}

test "0-RTT STREAM packet-threshold loss requeues early bytes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const s = try conn.openBidi(0);
    _ = try s.send.write("early-loss");

    var out: [256]u8 = undefined;
    _ = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);
    try std.testing.expect(s.send.peekChunk(64) == null);
    // Pretend three more 1-RTT packets were sent at the application
    // layer so the ACK for PN 3 is legitimate (RFC 9000 §13.1).
    conn.pnSpaceForLevel(.application).next_pn = 4;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 3,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 2_000);

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
    const chunk = s.send.peekChunk(64).?;
    try std.testing.expectEqual(@as(u64, 0), chunk.offset);
    try std.testing.expectEqual(@as(u64, 10), chunk.length);
    try std.testing.expectEqualSlices(u8, "early-loss", s.send.chunkBytes(chunk));
    try std.testing.expect(conn.pollEvent() == null);
}

test "server handles accepted 0-RTT STREAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    try conn.setTransportParams(.{
        .initial_max_data = 1024,
        .initial_max_stream_data_bidi_remote = 1024,
        .initial_max_streams_bidi = 1,
    });
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "hello",
        .has_offset = false,
        .has_length = true,
        .fin = false,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);
    if (application_ack_eliciting_threshold == 1) {
        try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.pending_ack);
    } else {
        try std.testing.expect(!conn.pnSpaceForLevel(.early_data).received.pending_ack);
    }
    try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.delayed_ack_armed);

    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try conn.streamRead(0, &buf));
    try std.testing.expectEqualSlices(u8, "hello", buf[0..5]);
    try std.testing.expectEqual(true, conn.streamArrivedInEarlyData(0).?);
}

test "server marks accepted 0-RTT DATAGRAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    conn.local_transport_params.max_datagram_frame_size = max_supported_udp_payload_size;
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .datagram = .{
        .data = "early-dgram",
        .has_length = true,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);

    var buf: [32]u8 = undefined;
    const info = conn.receiveDatagramInfo(&buf).?;
    try std.testing.expectEqual(@as(usize, 11), info.len);
    try std.testing.expect(info.arrived_in_early_data);
    try std.testing.expectEqualSlices(u8, "early-dgram", buf[0..info.len]);
}

test "server rejects forbidden frames in 0-RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    const keys = try testEarlyDataPacketKeys();

    var payload: [32]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ack = .{
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    _ = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
    try std.testing.expectEqualStrings("forbidden frame in 0-RTT", conn.pending_close.?.reason);
}

test "pollLevel emits PATH_ACK for non-zero application path ACKs" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    try std.testing.expect(!path.app_pn_space.received.pending_ack);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
    try std.testing.expectEqual(@as(u64, 9), decoded.frame.path_ack.largest_acked);
}

test "pollLevel caps ACK ranges to packet budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const tracker = &conn.primaryPath().app_pn_space.received;
    var pn: u64 = 0;
    while (pn < 200) : (pn += 2) tracker.add(pn, 1_000);
    const tracked_lower_ranges = @as(u64, tracker.range_count - 1);

    var packet_buf: [128]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    try std.testing.expect(!tracker.pending_ack);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .ack);
    try std.testing.expectEqual(@as(u64, 198), decoded.frame.ack.largest_acked);
    try std.testing.expect(decoded.frame.ack.range_count < tracked_lower_ranges);
}

test "application ACK ranges use bounded emission budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const tracker = &conn.primaryPath().app_pn_space.received;
    var pn: u64 = 0;
    while (pn < 400) : (pn += 2) tracker.add(pn, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .ack);
    try std.testing.expect(decoded.frame.ack.ranges_bytes.len <= max_application_ack_ranges_bytes);
    try std.testing.expect(decoded.frame.ack.range_count <= max_application_ack_lower_ranges);
    try std.testing.expect(decoded.frame.ack.range_count < @as(u64, tracker.range_count - 1));
}

test "pollLevel coalesces multiple STREAM frames with distinct loss keys" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const s0 = try conn.openBidi(0);
    const s1 = try conn.openBidi(4);
    const s2 = try conn.openBidi(8);
    _ = try s0.send.write("alpha");
    _ = try s1.send.write("bravo");
    _ = try s2.send.write("charlie");

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000)).?;

    const sent = conn.sentForLevel(.application);
    try std.testing.expectEqual(@as(u32, 1), sent.count);
    var keys = sent.packets[0].streamKeys();
    var key_count: usize = 0;
    while (keys.next()) |_| key_count += 1;
    try std.testing.expectEqual(@as(usize, 3), key_count);
    try std.testing.expectEqual(@as(u32, 1), s0.send.in_flight.count());
    try std.testing.expectEqual(@as(u32, 1), s1.send.in_flight.count());
    try std.testing.expectEqual(@as(u32, 1), s2.send.in_flight.count());
}

test "pollDatagram can select a non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{ .bytes = .{ 1, 2, 3, 4 } ++ .{0} ** 18 }, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    try std.testing.expect(conn.setActivePath(path_id));
    try conn.queuePathStatus(path_id, true, 1);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(path_id, datagram.path_id);
    try std.testing.expect(datagram.to != null);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_statuses.items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.paths.get(path_id).?.sent.count);
}

test "multipath-negotiated non-zero path packets use draft-21 nonce" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    const keys = (try conn.packetKeys(.application, .write)).?;
    var plaintext: [max_recv_plaintext]u8 = undefined;

    try std.testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
            .dcid_len = 1,
            .keys = &keys,
            .largest_received = 0,
        }),
    );
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
        .multipath_path_id = path_id,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
}

test "incoming short packets are routed by local CID before multipath nonce open" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setLocalScid(&.{0xa0});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    const path = conn.paths.get(path_id).?;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = path.path.local_cid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
        .multipath_path_id = path_id,
    });

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expectEqual(path_id, conn.current_incoming_path_id);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.received.largest);
    try std.testing.expectEqual(@as(?u64, null), conn.primaryPath().app_pn_space.received.largest);
}

test "authenticated NAT rebinding starts validation and resets recovery after response" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try conn.setLocalScid(&.{0xa0});
    const old_addr = Address{ .bytes = .{ 1, 2, 3, 4 } ++ .{0} ** 18 };
    const new_addr = Address{ .bytes = .{ 5, 6, 7, 8 } ++ .{0} ** 18 };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.rtt.smoothed_rtt_us = 50_000;
    path.path.rtt.latest_rtt_us = 40_000;
    path.path.rtt.first_sample_taken = true;
    path.path.cc.cwnd = 30_000;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const packet_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = conn.local_scid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    try conn.handle(packet_buf[0..packet_len], new_addr, 1_000_000);

    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expectEqual(@as(u64, packet_len), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expectEqual(.pending, path.path.validator.status);
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback != null);
    try std.testing.expect(!conn.pathStats(0).?.validated);
    try std.testing.expect(conn.pending_path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_path_challenge_path_id);
    try std.testing.expectEqual(@as(u64, 50_000), path.path.rtt.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 30_000), path.path.cc.cwnd);

    conn.recordPathResponse(0, path.path.validator.pending_token);

    try std.testing.expect(conn.pathStats(0).?.validated);
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expectEqual(rtt_mod.initial_rtt_us, path.path.rtt.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 0), path.path.rtt.latest_rtt_us);
    const expected_cwnd = (congestion_mod.Config{ .max_datagram_size = default_mtu }).initialWindow();
    try std.testing.expectEqual(expected_cwnd, path.path.cc.cwnd);
    try std.testing.expect(conn.pending_path_challenge == null);
}

test "unvalidated rebound path obeys anti-amplification before polling" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const old_addr = Address{ .bytes = .{ 1, 1, 1, 1 } ++ .{0} ** 18 };
    const new_addr = Address{ .bytes = .{ 2, 2, 2, 2 } ++ .{0} ** 18 };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    try conn.handlePeerAddressChange(path, new_addr, 1, 1_000_000);
    path.pending_ping = true;

    var packet_buf: [default_mtu]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.pollLevel(.application, &packet_buf, 1_001_000));
    try std.testing.expect(path.pending_ping);
    try std.testing.expect(conn.pending_path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
}

test "unvalidated path enforces anti-amplification on Initial sends" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Force the primary path to be unvalidated and simulate the peer
    // having sent us only a small Initial. RFC 9000 §8.1 caps the
    // server's send budget at 3x bytes_received until validation
    // succeeds — and that applies to Initial and Handshake bytes too,
    // not just 1-RTT.
    const path = conn.primaryPath();
    path.path.validated = false;
    path.path.validator = .{};
    path.path.bytes_received = 100;
    path.path.bytes_sent = 0;

    // Plant retransmittable Initial CRYPTO bytes so pollLevel actually
    // wants to emit a packet. Without anti-amp, sealInitial would
    // happily fill an MTU-sized datagram.
    const odcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try conn.setInitialDcid(&odcid);
    try conn.setLocalScid(&.{0xc1});
    try conn.setPeerDcid(&odcid);

    const crypto_bytes = try allocator.dupe(u8, &([_]u8{0xab} ** 800));
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = crypto_bytes,
    });

    var packet_buf: [default_mtu]u8 = undefined;
    const result = try conn.pollLevel(.initial, &packet_buf, 1_000_000);

    if (result) |n| {
        // Anti-amp says we must not send more than 3 * 100 = 300 bytes.
        try std.testing.expect(n <= 300);
    }
    try std.testing.expect(path.path.antiAmpAllowance() <= 300);
}

test "validated path is not constrained by anti-amplification" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Default primary path is born validated, so even a tiny
    // bytes_received does not gate Initial sends — keep the existing
    // behavior intact for the validated case.
    const path = conn.primaryPath();
    try std.testing.expect(path.path.isValidated());
    path.path.bytes_received = 50;
    path.path.bytes_sent = 0;

    const odcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try conn.setInitialDcid(&odcid);
    try conn.setLocalScid(&.{0xc1});
    try conn.setPeerDcid(&odcid);

    const crypto_bytes = try allocator.dupe(u8, &([_]u8{0xab} ** 800));
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = crypto_bytes,
    });

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &packet_buf, 1_000_000)).?;
    // Allowance is unbounded for a validated path, so we should be
    // able to send well over 3 * 50 = 150 bytes.
    try std.testing.expect(n > 150);
}

test "failed NAT rebinding validation rolls back to the previous address" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const old_addr = Address{ .bytes = .{ 3, 3, 3, 3 } ++ .{0} ** 18 };
    const new_addr = Address{ .bytes = .{ 4, 4, 4, 4 } ++ .{0} ** 18 };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();
    path.path.bytes_received = 900;
    path.path.bytes_sent = 300;

    try conn.handlePeerAddressChange(path, new_addr, 40, 1_000_000);
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(@as(u64, 40), path.path.bytes_received);
    try std.testing.expect(conn.pending_path_challenge != null);
    const stale_token = path.path.validator.pending_token;

    try conn.tick(1_000_000 + path.path.validator.timeout_us + 1);

    try std.testing.expect(Address.eql(old_addr, path.path.peer_addr));
    try std.testing.expect(path.path.isValidated());
    try std.testing.expectEqual(.validated, path.path.validator.status);
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expectEqual(path_mod.State.active, path.path.state);
    try std.testing.expectEqual(@as(u64, 900), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 300), path.path.bytes_sent);
    try std.testing.expect(conn.pending_path_challenge == null);

    var stale_packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 1_000_000,
        .bytes = 64,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer stale_packet.deinit(allocator);
    try stale_packet.addRetransmitFrame(allocator, .{ .path_challenge = .{ .data = stale_token } });
    try std.testing.expect(!(try conn.dispatchLostControlFrames(&stale_packet)));
    try std.testing.expect(conn.pending_path_challenge == null);
}

test "old address packets during pending rebinding do not lift new path anti-amplification" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const old_addr = Address{ .bytes = .{ 7, 7, 7, 7 } ++ .{0} ** 18 };
    const new_addr = Address{ .bytes = .{ 8, 8, 8, 8 } ++ .{0} ** 18 };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.handlePeerAddressChange(path, new_addr, 10, 1_000_000);
    try std.testing.expectEqual(@as(u32, 0), conn.incomingPathId(old_addr));
    try std.testing.expect(conn.peerAddressChangeCandidate(0, old_addr) == null);

    try conn.recordAuthenticatedDatagramAddress(0, old_addr, 1200, 1_000_100);

    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(@as(u64, 10), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expectEqual(@as(u64, 30), path.path.antiAmpAllowance());
}

test "PATH_RESPONSE during pending rebinding is sent to the challenge address" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const old_addr = Address{ .bytes = .{ 9, 9, 9, 9 } ++ .{0} ** 18 };
    const new_addr = Address{ .bytes = .{ 1, 0, 1, 0 } ++ .{0} ** 18 };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.handlePeerAddressChange(path, new_addr, 1200, 1_000_000);
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    conn.queuePathResponseOnPath(0, token, old_addr);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_100)).?;
    try std.testing.expect(datagram.to != null);
    try std.testing.expect(Address.eql(old_addr, datagram.to.?));
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expect(conn.pending_path_response == null);
    try std.testing.expect(conn.pending_path_challenge != null);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..datagram.len], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_response);
    try std.testing.expectEqualSlices(u8, &token, &decoded.frame.path_response.data);

    const followup = (try conn.pollDatagram(&packet_buf, 1_000_200)).?;
    try std.testing.expect(followup.to != null);
    try std.testing.expect(Address.eql(new_addr, followup.to.?));
    try std.testing.expect(conn.pending_path_challenge == null);
    try std.testing.expect(path.path.bytes_sent > 0);
}

test "queued path CIDs participate in incoming short-header routing and retirement" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try conn.queuePathNewConnectionId(path_id, 1, 0, &.{0xc2}, @splat(0));

    const bytes = [_]u8{ 0x40, 0xc2, 0, 0, 0, 0 } ++ [_]u8{0} ** 16;
    try std.testing.expectEqual(path_id, conn.incomingShortPath(&bytes).?.id);

    conn.handlePathRetireConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
    });
    try std.testing.expect(conn.incomingShortPath(&bytes) == null);
}

test "multipath frames are rejected unless draft-21 was negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .max_path_id = .{ .maximum_path_id = 1 } });
    try conn.dispatchFrames(.application, payload[0..payload_len], 1_000_000);
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "setTransportParams advertises local multipath limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .initial_max_path_id = 2 });
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 2), conn.local_max_path_id);
}

test "openPath respects peer MAX_PATH_ID when multipath is negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    _ = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc2}), ConnectionId.fromSlice(&.{0xd2})),
    );
    try std.testing.expectEqual(@as(?u32, 1), conn.pending_paths_blocked);
}

test "openPath requires common path id capacity and CIDs when multipath is negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    try std.testing.expectError(
        Error.ConnectionIdRequired,
        conn.openPath(.{}, .{}, ConnectionId{}, ConnectionId.fromSlice(&.{0xd1})),
    );
    try std.testing.expectError(
        Error.ConnectionIdRequired,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId{}),
    );

    conn.peer_max_path_id = 2;
    _ = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc2}), ConnectionId.fromSlice(&.{0xd2})),
    );
}

test "local CID issuance rejects reuse across paths and sequences" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd2})),
    );
    try std.testing.expect(conn.paths.get(2) == null);
    try std.testing.expectEqual(@as(u32, 2), conn.paths.next_path_id);

    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.queuePathNewConnectionId(path_id, 1, 0, &.{0xc1}, @splat(0xc1)),
    );
    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.queueNewConnectionId(1, 0, &.{0xc1}, @splat(0xc1)),
    );
}

test "RETIRE_CONNECTION_ID surfaces replacement CID budget to embedders" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 3 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(0));

    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    const info = conn.connectionIdReplenishInfo(0).?;
    try std.testing.expectEqual(@as(u32, 0), info.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, info.reason);
    try std.testing.expectEqual(@as(usize, 2), info.active_count);
    try std.testing.expectEqual(@as(usize, 3), info.active_limit);
    try std.testing.expectEqual(@as(usize, 1), info.issue_budget);
    try std.testing.expectEqual(@as(u64, 3), info.next_sequence_number);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(@as(u32, 0), event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(usize, 1), event.connection_ids_needed.issue_budget);

    const queued = try conn.replenishConnectionIds(&.{
        .{ .connection_id = &.{0xa3}, .stateless_reset_token = @splat(0xa3) },
    });
    try std.testing.expectEqual(@as(usize, 1), queued);
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(0));
    try std.testing.expect(conn.pollEvent() == null);
}

test "RETIRE_CONNECTION_ID with sequence we never issued is a PROTOCOL_VIOLATION" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 4 };
    // We've issued sequences 0, 1, and 2 to the peer.
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));

    // A peer that retires a sequence we never assigned (RFC 9000 §19.16)
    // is committing a PROTOCOL_VIOLATION. Without this gate an attacker
    // could spam fabricated retire frames to force expensive list walks.
    conn.handleRetireConnectionId(.{ .sequence_number = 99 });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "RETIRE_CONNECTION_ID for an already-retired sequence is allowed" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 4 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));

    // First retire of seq 1: legitimate.
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    try std.testing.expect(conn.pending_close == null);
    // Second retire of seq 1 (could happen if we received a duplicate or
    // a delayed retransmission): still legitimate because seq 1 was issued
    // at some point. Only sequences strictly above the high watermark are
    // rejected.
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    try std.testing.expect(conn.pending_close == null);
}

test "retiring CID sequence 0 does not change long-header source CID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const initial_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const initial_scid = [_]u8{0xa0};
    const replacement_scid = [_]u8{0xa1};
    try conn.setInitialDcid(&initial_dcid);
    try conn.setPeerDcid(&.{});
    try conn.setLocalScid(&initial_scid);
    try conn.queueNewConnectionId(1, 0, &replacement_scid, @splat(0xa1));

    conn.handleRetireConnectionId(.{ .sequence_number = 0 });
    try std.testing.expectEqualSlices(u8, &replacement_scid, conn.local_scid.slice());
    try std.testing.expectEqualSlices(u8, &initial_scid, conn.longHeaderScid().slice());

    const bytes = try allocator.dupe(u8, "late-initial-ack");
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = bytes,
    });

    var out: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &out, 1_000_000)).?;
    const parsed = try wire_header.parse(out[0..n], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqualSlices(u8, &initial_scid, parsed.header.initial.scid.slice());
}

test "PATH_NEW_CONNECTION_ID rejects sequence reuse with different cid" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "PATH_NEW_CONNECTION_ID rejects path ids above local limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    try conn.handlePathNewConnectionId(.{
        .path_id = 2,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "MAX_PATH_ID cannot reduce the peer initial path limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    conn.handleMaxPathId(.{ .maximum_path_id = 1 });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "PATH_CIDS_BLOCKED cannot skip local cid sequence numbers" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    conn.handlePathCidsBlocked(.{ .path_id = path_id, .next_sequence_number = 2 });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "PATH_CIDS_BLOCKED can be surfaced and replenished within peer active cid limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 1,
        .active_connection_id_limit = 3,
    };
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));

    conn.handlePathCidsBlocked(.{ .path_id = path_id, .next_sequence_number = 1 });
    const blocked = conn.pendingPathCidsBlocked().?;
    try std.testing.expectEqual(path_id, blocked.path_id);
    try std.testing.expectEqual(@as(u64, 1), blocked.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 2), conn.localConnectionIdIssueBudget(path_id));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(path_id, event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.path_cids_blocked, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(?u64, 1), event.connection_ids_needed.blocked_next_sequence_number);
    try std.testing.expectEqual(@as(usize, 2), event.connection_ids_needed.issue_budget);

    const queued = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
        .{ .connection_id = &.{0xc4}, .stateless_reset_token = @splat(0xc4) },
    });
    try std.testing.expectEqual(@as(usize, 2), queued);
    try std.testing.expectEqual(@as(?PathCidsBlockedInfo, null), conn.pendingPathCidsBlocked());
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(path_id));
    try std.testing.expectEqual(@as(usize, 2), conn.pending_path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(u64, 2), conn.pending_path_new_connection_ids.items[1].sequence_number);
    try std.testing.expectEqual(@as(u64, 3), conn.nextLocalConnectionIdSequence(path_id));

    try std.testing.expectError(
        Error.ConnectionIdLimitExceeded,
        conn.queuePathNewConnectionId(path_id, 3, 0, &.{0xc5}, @splat(0xc5)),
    );
    try conn.queuePathNewConnectionId(path_id, 3, 1, &.{0xc5}, @splat(0xc5));
    try std.testing.expectEqual(@as(usize, 3), conn.pending_path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 4), conn.nextLocalConnectionIdSequence(path_id));
}

test "unused negotiated path ids can be pre-provisioned with PATH_NEW_CONNECTION_ID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 3);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 3,
        .active_connection_id_limit = 2,
    };

    const queued = try conn.replenishPathConnectionIds(2, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
    });
    try std.testing.expectEqual(@as(usize, 2), queued);
    try std.testing.expectEqual(@as(usize, 2), conn.pending_path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u32, 2), conn.pending_path_new_connection_ids.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 0), conn.pending_path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_path_new_connection_ids.items[1].sequence_number);
    try std.testing.expectEqual(@as(u64, 2), conn.nextLocalConnectionIdSequence(2));

    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.queuePathNewConnectionId(4, 0, 0, &.{0xc4}, @splat(0xc4)),
    );
}

test "PATH_RETIRE_CONNECTION_ID drops pending advertisements and allows replenishment" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 1,
        .active_connection_id_limit = 3,
    };
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    _ = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
    });
    try std.testing.expectEqual(@as(usize, 2), conn.pending_path_new_connection_ids.items.len);

    conn.handlePathRetireConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
    });
    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.pending_path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(usize, 1), conn.localConnectionIdIssueBudget(path_id));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(path_id, event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(usize, 1), event.connection_ids_needed.issue_budget);
    try std.testing.expectEqual(@as(u64, 3), event.connection_ids_needed.next_sequence_number);

    const queued = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc4}, .stateless_reset_token = @splat(0xc4) },
    });
    try std.testing.expectEqual(@as(usize, 1), queued);
    try std.testing.expectEqual(@as(usize, 2), conn.pending_path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 3), conn.pending_path_new_connection_ids.items[1].sequence_number);
}

test "RETIRE_CONNECTION_ID emits with retransmit metadata and requeues on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try conn.queueRetireConnectionId(7);
    try std.testing.expect(conn.canSend());

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pending_retire_connection_ids.items.len);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .retire_connection_id);
    try std.testing.expectEqual(@as(u64, 7), decoded.frame.retire_connection_id.sequence_number);

    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 1), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .retire_connection_id);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 7), conn.pending_retire_connection_ids.items[0].sequence_number);
}

test "server HANDSHAKE_DONE emits with retransmit metadata and requeues on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    conn.primaryPath().path.markValidated();
    conn.pending_handshake_done = true;
    try std.testing.expect(conn.canSend());

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expect(!conn.pending_handshake_done);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .handshake_done);

    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 1), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .handshake_done);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expect(conn.pending_handshake_done);
}

test "PATHS_BLOCKED below current local limit is ignored" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    conn.handlePathsBlocked(.{ .maximum_path_id = 1 });
    try std.testing.expectEqual(@as(?u32, null), conn.peer_paths_blocked_at);
    conn.handlePathsBlocked(.{ .maximum_path_id = 2 });
    try std.testing.expectEqual(@as(?u32, 2), conn.peer_paths_blocked_at);
}

test "peer cid registration enforces active cid limit per path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    conn.local_transport_params.active_connection_id_limit = 2;
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(1),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(2),
    });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "retire_prior_to retires peer cids only on the indicated path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handleNewConnectionId(.{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x20}),
        .stateless_reset_token = @splat(0x20),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0x10),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0x11),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 2,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(0x12),
    });

    try std.testing.expectEqual(@as(usize, 2), conn.peerCidsCount());
    try std.testing.expectEqualSlices(u8, &.{0x12}, conn.paths.get(path_id).?.path.peer_cid.slice());
    try std.testing.expectEqualSlices(u8, &.{0x20}, conn.primaryPath().path.peer_cid.slice());
}

test "STREAM send tracking survives duplicate application PNs across paths" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    const stream = try conn.openBidi(0);

    _ = try stream.send.write("hello");
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000)).?;

    _ = try stream.send.write("world");
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;

    try std.testing.expectEqual(@as(u64, 0), conn.primaryPath().sent.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 0), path.sent.packets[0].pn);
    const primary_stream_key = conn.primaryPath().sent.packets[0].stream_key orelse unreachable;
    const path_stream_key = path.sent.packets[0].stream_key orelse unreachable;
    try std.testing.expect(primary_stream_key != path_stream_key);
    try std.testing.expectEqual(@as(u32, 2), stream.send.in_flight.count());
}

test "timer deadline reports non-zero application path ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(path_id, deadline.path_id);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "PTO requeues retransmittable controls on non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = path_id,
        .error_code = 99,
    } });
    try path.sent.record(packet);

    try conn.tick(conn.ptoDurationForApplicationPath(path));

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expect(!path.pending_ping);
    try std.testing.expectEqual(@as(u8, 1), path.pto_probe_count);
    try std.testing.expectEqual(@as(u32, 1), path.pto_count);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_abandons.items.len);
    try std.testing.expectEqual(path_id, conn.pending_path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_path_abandons.items[0].error_code);
}

test "idle timer closes and enters draining" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_idle_timeout_ms = 5 });
    conn.last_activity_us = 1_000;
    const deadline = conn.nextTimerDeadline(1_000).?;
    try std.testing.expectEqual(TimerKind.idle, deadline.kind);
    try std.testing.expectEqual(@as(u64, 6_000), deadline.at_us);

    try conn.tick(6_000);
    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expect(conn.draining_deadline_us != null);
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.idle_timeout, close_event.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, close_event.error_space);
    try std.testing.expectEqual(@as(u64, 0), close_event.error_code);
    try std.testing.expectEqualStrings("idle timeout", close_event.reason);

    try conn.tick(conn.draining_deadline_us.?);
    try std.testing.expectEqual(CloseState.closed, conn.closeState());
    try std.testing.expect(conn.nextTimerDeadline(10_000) == null);
}

test "qlog: connection_started and connection_state_updated fire on bind+close" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    try conn.bind();
    // Client `bind` should have fired exactly one `connection_started`.
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.connection_started));
    const started = recorder.first(.connection_started).?;
    try std.testing.expectEqual(@as(?Role, .client), started.role);

    // Re-bind shouldn't double-fire.
    try conn.bind();
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.connection_started));

    // Closing transitions open → closing → draining → closed across the close pipeline.
    conn.close(true, transport_error_protocol_violation, "test close");
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expect(recorder.countOf(.connection_state_updated) >= 1);
    const closing_event = blk: {
        var i: usize = 0;
        while (i < recorder.count) : (i += 1) {
            const e = recorder.events[i];
            if (e.name == .connection_state_updated and e.new_state == .closing) break :blk e;
        }
        return error.TestExpectedClosingTransition;
    };
    try std.testing.expectEqual(@as(?CloseState, .open), closing_event.old_state);
}

test "qlog: parameters_set carries top-level peer transport-parameter fields" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Pretend the peer's params arrived and the connection accepted them.
    conn.cached_peer_transport_params = .{
        .max_idle_timeout_ms = 30_000,
        .max_udp_payload_size = 1452,
        .initial_max_data = 65536,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 50,
        .active_connection_id_limit = 4,
        .max_ack_delay_ms = 25,
        .max_datagram_frame_size = 1200,
    };
    conn.emitPeerParametersSet();

    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.parameters_set));
    const e = recorder.first(.parameters_set).?;
    try std.testing.expectEqual(@as(?u64, 30_000), e.peer_idle_timeout_ms);
    try std.testing.expectEqual(@as(?u64, 1452), e.peer_max_udp_payload_size);
    try std.testing.expectEqual(@as(?u64, 65536), e.peer_initial_max_data);
    try std.testing.expectEqual(@as(?u64, 100), e.peer_initial_max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, 50), e.peer_initial_max_streams_uni);
    try std.testing.expectEqual(@as(?u64, 4), e.peer_active_connection_id_limit);
    try std.testing.expectEqual(@as(?u64, 25), e.peer_max_ack_delay_ms);
    try std.testing.expectEqual(@as(?u64, 1200), e.peer_max_datagram_frame_size);

    // Idempotent — second call is a no-op.
    conn.emitPeerParametersSet();
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.parameters_set));
}

test "qlog: packet_sent / packet_received are gated by setQlogPacketEvents" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{});

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // With per-packet events disabled (the default), nothing should fire.
    var buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(usize, 0), recorder.countOf(.packet_sent));
    // But the cheap counter should have advanced.
    try std.testing.expect(conn.qlog_packets_sent >= 1);

    // Enable the opt-in flag and try again — now we should see the event.
    conn.setQlogPacketEvents(true);
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_001_000)).?;
    try std.testing.expect(recorder.countOf(.packet_sent) >= 1);
    const sent_event = recorder.first(.packet_sent).?;
    try std.testing.expectEqual(@as(?QlogPnSpace, .application), sent_event.pn_space);
    try std.testing.expectEqual(@as(?QlogPacketKind, .one_rtt), sent_event.packet_kind);
    try std.testing.expect(sent_event.packet_size != null);
    try std.testing.expect(sent_event.packet_size.? > 0);
}

test "qlog: packet_dropped fires on AEAD authentication failure" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Build a valid 1-RTT, then corrupt the tag so AEAD fails.
    const keys = conn.app_read_current.?.keys;
    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });
    packet_buf[n - 1] ^= 0x01;

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expect(recorder.contains(.packet_dropped));
    const dropped = recorder.first(.packet_dropped).?;
    try std.testing.expectEqual(@as(?QlogPacketDropReason, .decryption_failure), dropped.drop_reason);
}

test "qlog: loss_detected fires from packet-threshold loss detection" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    conn.setQlogPacketEvents(true);

    // Inject a few sent packets at Initial level, then ack a later PN to
    // force packet-threshold loss detection on the early ones.
    const initial_sent = self_blk: {
        break :self_blk &conn.sent[EncryptionLevel.initial.idx()];
    };
    for ([_]u64{ 0, 1, 2 }) |pn| {
        try initial_sent.record(.{
            .pn = pn,
            .sent_time_us = pn * 1000,
            .bytes = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    // Set largest_acked > packet_threshold so the early ones look lost.
    conn.pnSpaceForLevel(.initial).next_pn = 10;
    try conn.handleAckAtLevel(.initial, .{
        .largest_acked = 9,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 5_000);

    try std.testing.expect(recorder.countOf(.loss_detected) >= 1);
    const loss = recorder.first(.loss_detected).?;
    try std.testing.expectEqual(@as(?QlogLossReason, .packet_threshold), loss.loss_reason);
    try std.testing.expect(loss.lost_count != null);
    try std.testing.expect(loss.lost_count.? > 0);
    // packet_lost should fire too because we enabled per-packet events.
    try std.testing.expect(recorder.countOf(.packet_lost) >= 1);
    // The connection-level counter should also have moved.
    try std.testing.expect(conn.qlog_packets_lost >= 1);
}

test "qlog: pathStats exposes the new connection-level counters" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{});

    // Drive a single send to bump counters.
    var buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_000_000)).?;

    const stats = conn.pathStats(0).?;
    try std.testing.expect(stats.packets_sent >= 1);
    try std.testing.expect(stats.total_bytes_sent >= 1);
    // RTT estimator hasn't run yet — values are at their initial defaults.
    try std.testing.expect(stats.srtt_us > 0); // default kInitialRtt
    try std.testing.expectEqual(stats.srtt_us, stats.smoothed_rtt_us);
    try std.testing.expectEqual(stats.rttvar_us, stats.srtt_us / 2);
    // Slow start phase before any loss.
    try std.testing.expectEqual(path_mod.CongestionState.slow_start, stats.congestion_window_state);
}
