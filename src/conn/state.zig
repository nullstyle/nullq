//! quic_zig.Connection — per-connection state machine root.
//!
//! The Connection wraps a `boringssl.tls.Conn` (the SSL object),
//! installs quic_zig's `tls.quic.Method` callbacks, and exposes a
//! deterministic `advance` driver that pulls peer-provided CRYPTO
//! bytes through `provideQuicData` + `SSL_do_handshake` until the
//! handshake completes. Once handshake is done it owns packet number
//! spaces, ACK tracking, congestion control, flow control, the
//! stream layer, the multipath `PathSet`, key updates, and the
//! close/draining lifecycle.

const std = @import("std");
const boringssl = @import("boringssl");
const c = boringssl.raw;

pub const level_mod = @import("../tls/level.zig");
pub const wire_header = @import("../wire/header.zig");
pub const short_packet_mod = @import("../wire/short_packet.zig");
pub const long_packet_mod = @import("../wire/long_packet.zig");
pub const initial_keys_mod = @import("../wire/initial.zig");
pub const transport_params_mod = @import("../tls/transport_params.zig");
pub const early_data_context_mod = @import("../tls/early_data_context.zig");
pub const varint = @import("../wire/varint.zig");
pub const frame_mod = @import("../frame/root.zig");
pub const frame_types = @import("../frame/types.zig");
pub const ack_range_mod = @import("../frame/ack_range.zig");
pub const ack_tracker_mod = @import("ack_tracker.zig");
pub const send_stream_mod = @import("send_stream.zig");
pub const recv_stream_mod = @import("recv_stream.zig");
pub const pn_space_mod = @import("pn_space.zig");
pub const sent_packets_mod = @import("sent_packets.zig");
pub const loss_recovery_mod = @import("loss_recovery.zig");
pub const path_mod = @import("path.zig");
pub const congestion_mod = @import("congestion.zig");
pub const rtt_mod = @import("rtt.zig");
pub const flow_control_mod = @import("flow_control.zig");
pub const event_queue_mod = @import("event_queue.zig");
pub const pending_frames_mod = @import("pending_frames.zig");
pub const lifecycle_mod = @import("lifecycle.zig");
pub const stateless_reset_mod = @import("stateless_reset.zig");
pub const path_frame_queue = @import("path_frame_queue.zig");
pub const socket_opts_mod = @import("../transport/socket_opts.zig");
pub const _internal = @import("_internal.zig");
const conn_recv_flow_handlers = @import("conn_recv_flow_handlers.zig");
const conn_recv_cid_token_handlers = @import("conn_recv_cid_token_handlers.zig");
const conn_recv_multipath_handlers = @import("conn_recv_multipath_handlers.zig");
const conn_recv_stream_control_handlers = @import("conn_recv_stream_control_handlers.zig");
const conn_recv_packet_handlers = @import("conn_recv_packet_handlers.zig");
const conn_recv_ack_handlers = @import("conn_recv_ack_handlers.zig");

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
/// RFC 8899 DPLPMTUD probe-state-machine phase (re-export).
pub const PmtudState = path_mod.PmtudState;
/// RFC 8899 DPLPMTUD embedder configuration (re-export).
pub const PmtudConfig = path_mod.PmtudConfig;
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
    /// `tryReserveResidentBytes` would push the connection past
    /// `max_connection_memory`. Hardening guide §3.5 / §8: peer-driven
    /// allocations (CRYPTO reassembly, DATAGRAM queues, stream
    /// reassembly / send queues) collectively must not exceed the
    /// per-Connection budget. Returned from any handler that detects
    /// an over-cap reservation; callers close the connection with
    /// `transport_error_excessive_load` and a redacted reason before
    /// the over-cap allocation lands.
    ExcessiveLoad,
    /// `Connection.setNewTokenCallback` /
    /// `Connection.queueNewToken` / `Connection.setInitialToken` were
    /// called on a connection in the wrong role (e.g. queueing a
    /// NEW_TOKEN on a client). Embedder-side misuse — peer input
    /// can never produce this.
    NotServerContext,
    NotClientContext,
    /// `Connection.queueNewToken` was called with a zero-length
    /// token, which RFC 9000 §19.7 forbids.
    ZeroLengthNewToken,
    /// `Connection.queueNewToken` was called with a token longer
    /// than `pending_frames.NewTokenItem.max_len`. quic_zig mints
    /// fixed-shape 96-byte tokens via `conn.new_token.mint`; only
    /// custom embedder formats can hit this.
    NewTokenTooLong,
    /// `Connection.advertiseAlternativeV4Address` /
    /// `Connection.advertiseAlternativeV6Address` was called before
    /// the peer advertised support via the `alternative_address`
    /// transport parameter (draft-munizaga-quic-alternative-server-address-00 §4).
    /// Embedder-side misuse — advertising an alternative address to
    /// a peer that doesn't expect the frame would force a peer
    /// PROTOCOL_VIOLATION close.
    AlternativeAddressNotNegotiated,
    /// `Connection.advertiseAlternativeV4Address` /
    /// `Connection.advertiseAlternativeV6Address` ran out of fresh
    /// Status Sequence Numbers
    /// (draft-munizaga-quic-alternative-server-address-00 §6 ¶5).
    /// Saturating the counter and reusing the maximum value would
    /// silently violate the §6 ¶5 monotonically-increasing
    /// requirement — the receiver would dedupe the second emission
    /// as a retransmit and drop a real update on the floor.
    /// Embedders that hit this should restart the connection (or
    /// use a different connection for further advertisements);
    /// reaching 2^64 advertise calls on one connection without a
    /// teardown is functionally impossible, but failing closed is
    /// the right behavior at the boundary.
    AlternativeAddressSequenceExhausted,
    /// `Connection.noteServerLocalAddressChanged` was called on a
    /// connection whose `local_transport_params.preferred_address` is
    /// null. RFC 9000 §5.1.1 / §18.2: the server-initiated migration
    /// the API models is only meaningful when the server has advertised
    /// a `preferred_address` in its handshake transport parameters —
    /// without one, the client has no signal to migrate to and no
    /// remote 4-tuple can be authenticated against the advertised
    /// pair. Embedders hit this when wiring up the API on a server
    /// that never set `Server.Config.preferred_address`; the fix is
    /// either to configure a preferred address or to skip the call.
    PreferredAddressNotAdvertised,
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

    /// True if the recv side has reached one of the four "no further
    /// peer bytes will land" states. Mirrors `maybeReturnPeerStreamCredit`'s
    /// definition: FIN-with-bytes-drained (data_recvd / data_read) or
    /// peer RESET (reset_recvd / reset_read). Used by the connection-
    /// level stream GC to decide whether the receive half is structurally
    /// dead.
    pub fn recvFullyTerminated(self: *const Stream) bool {
        return self.recv.state == .data_recvd or
            self.recv.state == .data_read or
            self.recv.state == .reset_recvd or
            self.recv.state == .reset_read;
    }
};

/// Default datagram budget for outgoing 1-RTT packets. RFC 9000 §14
/// mandates at least 1200 bytes path MTU; PMTU discovery (Phase 11)
/// can lift this.
pub const default_mtu: usize = 1200;
pub const transport_error_protocol_violation: u64 = 0x0a;
pub const transport_error_flow_control: u64 = 0x03;
pub const transport_error_stream_limit: u64 = 0x04;
pub const transport_error_stream_state: u64 = 0x05;
pub const transport_error_final_size: u64 = 0x06;
pub const transport_error_frame_encoding: u64 = 0x07;
pub const transport_error_transport_parameter: u64 = 0x08;
/// RFC 9000 §20.1 / §3.5: a server that runs out of resource budget for
/// peer-controlled state (CRYPTO reassembly, DATAGRAM queues, stream
/// buffers) closes the connection with EXCESSIVE_LOAD (0x09) rather
/// than spilling unbounded peer input into the host allocator. The
/// hardening guide §8 calls this out as the "memory cap" backstop.
pub const transport_error_excessive_load: u64 = 0x09;
pub const transport_error_aead_limit_reached: u64 = 0x0f;
/// RFC 9000 §20.1 / §10.2.3: the generic transport-error code used when
/// converting an application-variant CONNECTION_CLOSE (0x1d) to the
/// transport variant (0x1c) for emission at Initial/Handshake levels —
/// "the application or application protocol caused the connection to
/// be closed."
pub const transport_error_application_error: u64 = 0x0c;

/// Default per-Connection cap on bytes resident in peer-controlled
/// reassembly buffers (CRYPTO, DATAGRAM, stream send/recv). Hits at
/// 32 MiB — comfortably above the per-stream / per-CRYPTO-level
/// budgets the per-buffer caps already enforce, so legitimate
/// traffic stays inside it, but well below the host RSS that a
/// flood of orthogonal buffers could otherwise push us into.
/// Tuneable per `Connection` via `max_connection_memory`; the
/// `Server.Config` default threads through to every accepted slot.
pub const default_max_connection_memory: u64 = 32 * 1024 * 1024;

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
/// Per-`handle`-cycle ceiling on cumulative ACK ranges drained from
/// inbound ACK / PATH_ACK frames. Sized at 4× the per-frame decoder
/// cap (`frame.decode.max_incoming_ack_ranges = 256`) so well-behaved
/// multipath peers can ACK across roughly 4 active paths in one
/// datagram before tripping the gate. Beyond that, additional frames
/// are skipped (see RFC 9000 §19.3 — ACK is not ack-eliciting and
/// dropping does not affect connection liveness).
pub const incoming_ack_range_cap: u64 = 4 * @import("../frame/decode.zig").max_incoming_ack_ranges;
/// Per-`handle`-cycle ceiling on RETIRE_CONNECTION_ID frames. The
/// `active_connection_id_limit` hard cap is 16 (transport_params.zig);
/// 4× that gives steady-state churn headroom for a legitimate peer
/// rotating CIDs aggressively without enabling a flood attack.
pub const incoming_retire_cid_cap: u64 = 64;

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

/// Minimum interval between path-validation probes (PATH_CHALLENGE
/// emissions) for the same path. Hardens against a peer that
/// repeatedly switches source addresses to force fresh validator
/// state and burn server CPU minting tokens. 100 ms is short enough
/// that a real NAT rebinding-then-immediate-keepalive sequence still
/// validates within one RTT, and long enough to stop any
/// adversarial probe-flood. Surfaced in qlog as
/// `migration_fail_reason = .rate_limited`.
pub const min_path_challenge_interval_us: u64 = 100_000;

/// Implementation allocation policy. QUIC's wire limits are intentionally
/// enormous; quic_zig caps the resources it advertises and tracks so peer input
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
    return getenv("QUIC_ZIG_DEBUG_FRAMES");
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
pub const ConnectionCloseInfo = lifecycle_mod.ConnectionCloseInfo;

/// Origin of a connection-close event surfaced through `nextEvent`.
pub const CloseSource = lifecycle_mod.CloseSource;

/// QUIC distinguishes transport-level (RFC 9000 §20.1) from application-level
/// (RFC 9000 §20.2) errors; this enum tags which space `error_code` lives in.
pub const CloseErrorSpace = lifecycle_mod.CloseErrorSpace;

/// High-level connection lifecycle state — RFC 9000 §10 (closing/draining).
pub const CloseState = lifecycle_mod.CloseState;

/// Maximum length of a CONNECTION_CLOSE reason phrase we will record/emit.
pub const max_close_reason_len: usize = lifecycle_mod.max_close_reason_len;

/// Snapshot of a close event delivered to the embedder via `nextEvent`.
/// Captures source, error space/code and (optionally) the wire-level frame
/// type that triggered the close. RFC 9000 §10.
pub const CloseEvent = lifecycle_mod.CloseEvent;

/// Pure close/draining state extracted from `Connection` — re-exported
/// for tests that want to assert on it directly.
pub const LifecycleState = lifecycle_mod.LifecycleState;

/// Tagged-union of all connection-level events the embedder polls via `nextEvent`.
/// Each variant carries enough context for the embedder to react without re-querying
/// Connection state.
pub const ConnectionEvent = union(enum) {
    close: CloseEvent,
    flow_blocked: FlowBlockedInfo,
    connection_ids_needed: ConnectionIdReplenishInfo,
    datagram_acked: DatagramSendEvent,
    datagram_lost: DatagramSendEvent,
    /// One ALTERNATIVE_V4/V6_ADDRESS update received from the peer
    /// (draft-munizaga-quic-alternative-server-address-00 §6). Only
    /// surfaced when the local endpoint advertised support via the
    /// §4 `alternative_address` transport parameter and the peer's
    /// Status Sequence Number is strictly greater than every previous
    /// update — see `AlternativeServerAddressEvent` for the dedup /
    /// reorder rules.
    alternative_server_address: AlternativeServerAddressEvent,
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
/// One §6 update surfaced via `Connection.pollEvent`.
pub const AlternativeServerAddressEvent = event_queue_mod.AlternativeServerAddressEvent;
/// One IPv4 update — payload of `AlternativeServerAddressEvent.v4`.
pub const AlternativeServerAddressV4Event = event_queue_mod.AlternativeServerAddressV4Event;
/// One IPv6 update — payload of `AlternativeServerAddressEvent.v6`.
pub const AlternativeServerAddressV6Event = event_queue_mod.AlternativeServerAddressV6Event;
/// Maximum buffered alt-address events before older entries are dropped.
pub const max_alternative_address_events: usize = event_queue_mod.max_alternative_address_events;

const StoredDatagramSendEvent = event_queue_mod.StoredDatagramSendEvent;

const StoredCloseEvent = lifecycle_mod.StoredCloseEvent;

/// One queued STOP_SENDING frame (RFC 9000 §19.5) with its application error code.
pub const StopSendingItem = pending_frames_mod.StopSendingItem;

/// One queued MAX_STREAM_DATA frame (RFC 9000 §19.10) with the new credit value.
pub const MaxStreamDataItem = pending_frames_mod.MaxStreamDataItem;

/// One queued NEW_CONNECTION_ID frame (RFC 9000 §19.15) the embedder has handed
/// to the connection and is awaiting transmission.
pub const PendingNewConnectionId = pending_frames_mod.PendingNewConnectionId;

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
pub const PendingPathStatus = pending_frames_mod.PendingPathStatus;

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

const PendingRecvDatagram = pending_frames_mod.PendingRecvDatagram;
const PendingSendDatagram = pending_frames_mod.PendingSendDatagram;

/// Distinct timers the Connection drives. The embedder only ever sees one at
/// a time via `nextTimer` — the earliest pending — but the kind disambiguates
/// what `tick` will do when it fires.
pub const TimerKind = enum {
    ack_delay,
    loss_detection,
    pto,
    idle,
    /// RFC 9000 §10.2.1 closing-state expiry. The connection has sent
    /// a CONNECTION_CLOSE; this timer fires at `now + 3 * PTO` after
    /// the first emit and transitions the connection to terminal
    /// closed (skipping draining if the peer's CC never arrives).
    closing,
    /// RFC 9000 §10.2.2 draining-state expiry. The connection has
    /// received the peer's CONNECTION_CLOSE (or hit idle timeout /
    /// stateless reset); this timer fires after the
    /// `lifecycle.draining_deadline_us` interval and transitions the
    /// connection to terminal closed.
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

// INTERNAL: pub for _state_tests.zig access; not part of embedder API.
pub const LossStats = struct {
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

    pub fn add(self: *LossStats, packet: sent_packets_mod.SentPacket) void {
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

/// Why a candidate path failed to validate — populates the qlog
/// `migration_path_failed` event. `timeout` is the RFC 9000 §8.2.4
/// 3 * PTO expiry; `policy_denied` is an embedder-installed
/// `MigrationCallback` returning `.deny` before validation began.
pub const QlogMigrationFailReason = enum {
    /// PATH_CHALLENGE went unanswered for 3 * PTO and the validator
    /// transitioned to `.failed`.
    timeout,
    /// A `MigrationCallback` returned `.deny`, so PATH_CHALLENGE was
    /// never queued and the candidate 4-tuple was abandoned.
    policy_denied,
    /// RFC 9000 §9.6 / hardening guide §4.8 — peer attempted to
    /// migrate before the handshake was confirmed. The triggering
    /// authenticated datagram is dropped (no anti-amp credit, no
    /// PATH_CHALLENGE emitted) so the connection state stays
    /// anchored to the original 4-tuple.
    pre_handshake,
    /// A new PATH_CHALLENGE for this path arrived too soon after the
    /// last one (per `min_path_challenge_interval_us`). Path probe
    /// rate-limit fired; the peer's address change was not honored.
    rate_limited,
    /// RFC 9000 §5.1.2 ¶1: migration would require us to use a fresh
    /// peer-issued CID, but the peer hasn't issued any beyond the one
    /// already in use on this path. The peer needs to send more
    /// NEW_CONNECTION_ID frames before the migration can proceed.
    no_fresh_peer_cid,
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
    /// Why a `migration_path_failed` event fired. `null` for the
    /// `migration_path_validated` variant or when the embedder hasn't
    /// observed the new field yet (existing emit sites set this).
    migration_fail_reason: ?QlogMigrationFailReason = null,
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

/// Allow / deny verdict returned by a `MigrationCallback`. The
/// callback is consulted before quic_zig starts path validation on a
/// candidate 4-tuple (RFC 9000 §9). `.allow` proceeds with
/// PATH_CHALLENGE; `.deny` skips validation entirely and keeps the
/// existing path live.
pub const MigrationDecision = enum {
    /// Proceed with path validation on the candidate addresss.
    allow,
    /// Refuse the migration. PATH_CHALLENGE is not queued, the
    /// peer's existing 4-tuple stays in use, and a
    /// `migration_path_failed` qlog event with reason
    /// `policy_denied` is emitted.
    deny,
};

/// Embedder policy hook consulted when quic_zig detects a peer migration
/// candidate (RFC 9000 §9). Fires synchronously, **before** the
/// PATH_CHALLENGE / PATH_RESPONSE round-trip — this lets the embedder
/// short-circuit purely-address-based allowlists ("only accept
/// migrations from corporate IPs") without paying for a probe. The
/// callback runs after the triggering datagram has decrypted cleanly
/// under the existing path's keys, so its frames are trustworthy.
///
/// Arguments:
/// - `user_data` — opaque pointer registered via
///   `Connection.setMigrationCallback`.
/// - `conn` — the live Connection, passed by const-pointer so the
///   callback can read state (e.g. role, peer SCID, scheduling
///   policy) but cannot mutate it. quic_zig is single-threaded
///   internally; the callback must not call back into this
///   Connection.
/// - `candidate_addr` — the new peer 4-tuple address the datagram
///   arrived on.
/// - `current_addr` — the existing peer address on the affected
///   path, or `null` if the path had no peer address recorded yet
///   (in which case the callback is not consulted).
///
/// Return `.allow` to start path validation as usual, or `.deny` to
/// drop the migration attempt while keeping the connection alive on
/// the existing path.
pub const MigrationCallback = *const fn (
    user_data: ?*anyopaque,
    conn: *const Connection,
    candidate_addr: Address,
    current_addr: ?Address,
) MigrationDecision;

/// Callback fired when a client connection receives a NEW_TOKEN frame
/// (RFC 9000 §8.1.3). The embedder typically stashes the bytes
/// alongside the server's session ticket; on the next attempt to the
/// same server, supplying these bytes back via
/// `Client.Config.new_token` lets the server skip the Retry round
/// trip. Tokens are opaque to the client — treat the slice as a
/// blob.
///
/// The slice is borrowed from the inbound packet's decoded frame; if
/// the embedder needs to keep it past the callback's return,
/// it MUST copy.
pub const NewTokenCallback = *const fn (user_data: ?*anyopaque, token: []const u8) void;

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

    /// **Test-only.** When set, the migration gate in
    /// `recordAuthenticatedDatagramAddress` bypasses its
    /// `handshakeDone()` check so peer-address-change tests can fire
    /// migration without driving a full TLS handshake. Production
    /// code MUST NOT set this — it disables RFC 9000 §9.6 / hardening
    /// guide §4.8 enforcement.
    test_only_force_handshake_for_migration: bool = false,

    /// Whether to encode the locally-recorded close-reason string into
    /// outgoing CONNECTION_CLOSE frames. Default `false` (redact) per
    /// hardening guide §9 / §12: internal parser-error strings like
    /// "ack of unsent packet" or "connection id reused across paths"
    /// are useful telemetry for the embedder but reveal implementation
    /// detail to the peer (parser fingerprinting, internal state
    /// names). Local introspection is unaffected — `lifecycle.record`
    /// always captures the reason for embedder-side observability,
    /// and `nextEvent` surfaces it via `CloseEvent.reason`.
    ///
    /// Embedders that want the reason on the wire (debug builds,
    /// internal load tests, etc.) can flip this to `true`.
    reveal_close_reason_on_wire: bool = false,

    /// Hard ceiling on `bytes_resident` (hardening guide §3.5 / §8).
    /// Sums every byte sitting in peer-controlled reassembly /
    /// queue buffers — CRYPTO `crypto_pending`, RFC 9221 inbound
    /// DATAGRAMs, and per-stream send/recv reassembly buffers. When
    /// a fresh allocation would push the running total past this
    /// cap, the handler closes the connection with
    /// `transport_error_excessive_load` instead of letting the
    /// allocation land. Defaults to `default_max_connection_memory`
    /// (32 MiB); `Server.Config.max_connection_memory` threads onto
    /// every accepted slot.
    ///
    /// Tuning note: per-buffer caps already exist
    /// (`max_pending_crypto_bytes_per_level = 64 KiB`,
    /// `max_pending_datagram_bytes = 64 KiB`,
    /// `max_initial_stream_receive_window = 16 MiB`,
    /// `default_max_buffered_send = 1 MiB`). This is the *aggregate*
    /// guard that prevents a peer from opening many streams at once
    /// and inflating the connection's host RSS even when each
    /// individual buffer stays under its own cap.
    max_connection_memory: u64 = default_max_connection_memory,

    /// Number of ack-eliciting application packets received before
    /// forcing an immediate ACK (RFC 9000 §13.2.1 ¶2: "An endpoint
    /// MUST acknowledge ack-eliciting packets within its advertised
    /// max_ack_delay, with the following exception: it MUST send an
    /// immediate ACK for ack-eliciting packets that are received after
    /// receiving at least 2 ack-eliciting packets without sending an
    /// ACK..."). RFC 9000 §13.2.2 lets implementations tune this
    /// threshold; 2 is the RFC-recommended starting point.
    /// Set lower (e.g. 1) to ACK every ack-eliciting packet
    /// immediately — useful in low-RTT environments where the
    /// `max_ack_delay` deadline rarely fires. Set higher to amortize
    /// ACK overhead at the cost of triggering more peer PTOs.
    /// `Server.Config` and `Client.Config` thread the chosen value
    /// onto every Connection at construction time.
    delayed_ack_packet_threshold: u8 = application_ack_eliciting_threshold,

    /// Enable IETF ECN signaling (RFC 9000 §13.4 / RFC 3168). When
    /// `true` (the default), quic_zig will:
    ///   * count incoming `EcnCodepoint` markings into per-PN-space
    ///     `recv_ect0` / `recv_ect1` / `recv_ce` counters,
    ///   * emit `0x03` ACK frames carrying those counts whenever any
    ///     received packet at that level was ECN-marked,
    ///   * validate peer-reported counts on incoming ACKs per
    ///     §13.4.2 and react to CE bumps via the NewReno
    ///     congestion controller.
    ///
    /// When `false`, the codec is otherwise unchanged but no marking
    /// signal is propagated either way; outgoing ACKs stay at type
    /// `0x02`. Embedders flip this off only on environments known to
    /// bleach ECN bits (some legacy NATs / firewalls), or when
    /// running tests that need a deterministic congestion control
    /// path.
    ecn_enabled: bool = true,
    /// IP-layer ECN codepoint observed on the most recently received
    /// (and decrypted) datagram. Set by `handle` from the cmsg the
    /// embedder plumbs in; consumed by the per-packet handlers when
    /// they record received PNs into the level's `PnSpace`.
    /// `not_ect` is the conservative default — the embedder
    /// hasn't surfaced any TOS byte for this datagram.
    last_recv_ecn: socket_opts_mod.EcnCodepoint = .not_ect,

    /// Running total of bytes currently resident in peer-controlled
    /// buffers — see `max_connection_memory`. Mutated by
    /// `tryReserveResidentBytes` / `releaseResidentBytes` at every
    /// allocation / free site that holds peer-supplied bytes.
    /// Monotonically non-negative — any release that would underflow
    /// the counter clamps at zero and asserts in debug builds.
    bytes_resident: u64 = 0,

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

    next_datagram_id: u64 = 0,

    /// Next Status Sequence Number to mint for an
    /// `ALTERNATIVE_V4/V6_ADDRESS` frame
    /// (draft-munizaga-quic-alternative-server-address-00 §6 ¶5).
    /// Both frame types share one monotonically-increasing space.
    next_alternative_address_sequence: u64 = 0,

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
    /// Active QUIC wire-format version for this connection. Drives
    /// the Initial-key salt + HKDF labels (RFC 9001 §5.2 / RFC 9368
    /// §3.3.1, §3.3.2), the long-header packet-type bit layout
    /// (RFC 9000 §17.2 / RFC 9368 §3.2), and the Retry integrity
    /// constants (RFC 9001 §5.8 / RFC 9368 §3.3.3). Defaults to
    /// QUIC v1; embedders that opt in to v2 set this via
    /// `setVersion` after `initClient` / `initServer`. Once an
    /// Initial is sealed or opened the value is effectively
    /// immutable (changing it would re-derive Initial keys against
    /// a different salt).
    version: u32 = quic_version_1,

    /// RFC 9368 §6 compatible-version-negotiation upgrade target,
    /// stashed by the server's `Server.preparseUpgradeTarget` and
    /// applied by the server's `dispatchToSlot` after the first
    /// `handleWithEcn` consumes the wire-version Initial under
    /// wire-version keys. `null` means no upgrade is pending.
    /// Server-side only; clients leave this null. See
    /// `setPendingVersionUpgrade` / `applyPendingVersionUpgrade`.
    pending_version_upgrade: ?u32 = null,

    /// RFC 9368 §6 ¶6/¶7 downgrade-attack guard: wire version on the
    /// FIRST Initial we observed. Captured BEFORE any compatible-
    /// version-negotiation upgrade flips `self.version`, so the
    /// server-side check in `validatePeerTransportRole` can compare
    /// the client's advertised `version_information.chosen_version`
    /// against the actual on-wire version of the client's Initial,
    /// even after `applyPendingVersionUpgrade` has retargeted
    /// `self.version` to the upgrade target. Set by `acceptInitial`
    /// on the server side; left `null` on the client side (the client
    /// only ever sends a single wire version on its first Initial,
    /// which equals `self.version` at the time the params are
    /// validated, so the simpler `advertised_versions[0] !=
    /// self.version` check in the client branch is sufficient).
    initial_wire_version: ?u32 = null,

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
    /// Latched true the first time `discardInitialKeys` fires (i.e.
    /// when Handshake or higher secrets are installed). Once set,
    /// `ensureInitialKeys` is a no-op — the discard is one-way and
    /// any subsequent Initial-level packet can't be sealed/opened
    /// with re-derived keys. RFC 9001 §5.7 ¶3.
    initial_keys_discarded: bool = false,
    /// Latched true when `discardHandshakeKeys` fires. RFC 9001 §4.9.2:
    /// "An endpoint MUST discard its handshake keys when the TLS
    /// handshake is confirmed (Section 4.1.2)." For the client, that
    /// confirmation event is receipt of HANDSHAKE_DONE (RFC 9001
    /// §4.1.2 ¶2); for the server, it is delivery of the client's
    /// Finished message (which equals `handshakeDone()` returning
    /// true). Once latched, `pnSpaceForLevel(.handshake)` and
    /// `sentForLevel(.handshake)` are dead — `tick` skips them and
    /// `packetKeys(.handshake, ...)` returns null because the
    /// per-level secret material has been zeroed.
    handshake_keys_discarded: bool = false,
    /// Latched true on the client when a HANDSHAKE_DONE frame is
    /// processed (RFC 9001 §4.1.2 ¶2). Drives `discardHandshakeKeys`
    /// in `applyPostFrameProcessing` and short-circuits any further
    /// Handshake-level activity (PTO, loss detection, retransmit).
    /// Server-side this stays false — the equivalent latch is
    /// `inner.handshakeDone()`, which already covers the §4.9.2
    /// "TLS handshake is confirmed" trigger for the server role.
    received_handshake_done: bool = false,
    /// Sequence number of the locally-issued CID the next-handled
    /// datagram was addressed to, or `null` when unknown. Set by
    /// `Server` from its routing table before each `Connection.handle`
    /// invocation; consumed by `handleRetireConnectionId` to enforce
    /// RFC 9000 §19.16 ¶3 (a peer MUST NOT retire the CID it just
    /// used to send to us — PROTOCOL_VIOLATION).
    current_incoming_local_cid_seq: ?u64 = null,

    /// Cumulative count of ACK ranges processed across every ACK /
    /// PATH_ACK frame in the current `handle` cycle. Reset on entry to
    /// `handle`. Incremented by `range_count + 1` per frame (the +1
    /// accounts for `first_range`, which is real but encoded out of
    /// the gap-list). The decoder already caps each individual frame
    /// at `frame.decode.max_incoming_ack_ranges = 256`; without a
    /// per-cycle ceiling, an attacker on N paths could submit
    /// N × 256 ranges per datagram and force unbounded
    /// loss-detection walks. We cap at `incoming_ack_range_cap` —
    /// enough headroom for legitimate multipath aggregation across
    /// ~4 active paths in one datagram, not enough to amplify.
    incoming_ack_range_count: u64 = 0,
    /// Cumulative count of RETIRE_CONNECTION_ID frames processed in
    /// the current `handle` cycle. Reset on entry to `handle`.
    /// Bounded at `incoming_retire_cid_cap` so a peer flooding
    /// retires inside one datagram is treated as adversarial and
    /// closed with PROTOCOL_VIOLATION rather than allowed to spend
    /// CPU walking `local_cids` once per frame.
    incoming_retire_cid_count: u64 = 0,

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
    /// Optional embedder policy that gates peer migrations to a new
    /// 4-tuple (RFC 9000 §9). When `null`, every authenticated
    /// migration candidate is accepted and validated. See
    /// `setMigrationCallback`.
    migration_callback: ?MigrationCallback = null,
    migration_user_data: ?*anyopaque = null,
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

    /// Local datagram budget for outgoing packets. Functions as the
    /// connection-wide ceiling: per-path PMTU values discovered via
    /// RFC 8899 DPLPMTUD must not exceed this. Negotiated peer
    /// `max_udp_payload_size` lowers this in `validatePeerTransportLimits`.
    mtu: usize = default_mtu,

    /// RFC 8899 DPLPMTUD configuration. Threaded onto every
    /// `PathState` at creation time. The Connection-level field
    /// defaults to `enable = false` so direct `Connection.initClient
    /// / initServer` callers (mainly internal test fixtures) keep
    /// the historical static-MTU behaviour. The public `Server.Config
    /// .pmtud` and `Client.Config.pmtud` wrappers default to enabled
    /// (`PmtudConfig{}` with `enable = true`) and call
    /// `setPmtudConfig` after `initClient` / `initServer`, so
    /// production embedders get DPLPMTUD without any extra wiring.
    pmtud_config: path_mod.PmtudConfig = .{ .enable = false },

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
    /// false; quic_zig just waits for 1-RTT before emitting app data.
    early_data_send_enabled: bool = false,
    /// Once BoringSSL reports rejection, every tracked 0-RTT packet is
    /// removed from flight and its STREAM bytes are put back on the
    /// send queue exactly once.
    early_data_rejection_processed: bool = false,

    /// Last send/receive activity on this connection. Zero means no
    /// packet activity has been observed yet.
    last_activity_us: u64 = 0,

    /// Close/draining lifecycle: pending CONNECTION_CLOSE, closing/
    /// draining deadlines, rate-limit bookkeeping, sticky close event,
    /// and the reason-phrase buffer. See `lifecycle.zig`.
    lifecycle: LifecycleState = .{},
    /// Set whenever an inbound packet authenticates under our keys
    /// while the connection is in RFC 9000 §10.2.1's closing state.
    /// `handle` consumes this flag after the per-datagram loop and
    /// re-arms `pending_close` if the §10.2.1 ¶3 rate-limit allows,
    /// so the peer gets a fresh CONNECTION_CLOSE. Cleared on every
    /// `handle` entry so the signal only reflects the current
    /// datagram.
    closing_state_attribution_observed: bool = false,

    /// Peer-issued connection IDs we've stashed via NEW_CONNECTION_ID.
    /// Phase 9 (migration) will pull from this set; for now, the
    /// stash is just bookkeeping (and a place where a peer's
    /// `active_connection_id_limit` violation would surface).
    peer_cids: std.ArrayList(IssuedCid) = .empty,
    /// Locally-issued connection IDs, keyed by path, used to map
    /// incoming short-header DCIDs back to draft multipath path IDs.
    local_cids: std.ArrayList(IssuedCid) = .empty,
    /// Server-only HANDSHAKE_DONE delivery. The frame is ack-eliciting
    /// and must be retransmitted on loss until the client confirms the
    /// handshake.
    pending_handshake_done: bool = false,
    handshake_done_queued_once: bool = false,
    flow_blocked_events: event_queue_mod.EventQueue(FlowBlockedInfo, max_flow_blocked_events) = .{},
    connection_id_events: event_queue_mod.EventQueue(ConnectionIdReplenishInfo, max_connection_id_events) = .{},
    datagram_send_events: event_queue_mod.EventQueue(StoredDatagramSendEvent, max_datagram_send_events) = .{},
    /// Received `ALTERNATIVE_V4/V6_ADDRESS` events
    /// (draft-munizaga-quic-alternative-server-address-00 §6) the
    /// embedder hasn't drained via `pollEvent` yet. Bounded at
    /// `max_alternative_address_events` (16) with drop-oldest
    /// eviction. Eviction is semantically safe under §6 ¶5
    /// monotonicity — the latest update always supersedes older
    /// ones — but a sluggish embedder polling on a chatty peer can
    /// miss intermediate state. The high-watermark is preserved on
    /// `highest_alternative_address_sequence_seen` so the embedder
    /// can detect that updates were dropped (sequence gap between
    /// the latest polled event and `highestAlternativeAddressSequenceSeen()`).
    alternative_server_address_events: event_queue_mod.EventQueue(AlternativeServerAddressEvent, max_alternative_address_events) = .{},
    /// Highest §6 ¶5 Status Sequence Number we've already observed.
    /// `null` until the first frame arrives. Drives the receive-side
    /// monotonicity gate: equal-or-lower numbers are absorbed silently
    /// (idempotent retransmit / out-of-order delivery).
    highest_alternative_address_sequence_seen: ?u64 = null,
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

    /// All control-frame backlog the connection owes the peer at the
    /// application encryption level — flow-control window updates,
    /// STOP_SENDING, NEW_CONNECTION_ID/RETIRE_CONNECTION_ID, the
    /// PATH_CHALLENGE/PATH_RESPONSE pair, multipath draft-21
    /// bookkeeping, and queued DATAGRAMs in both directions. The
    /// hot-path drain in `pollLevel` walks each subqueue in order.
    pending_frames: pending_frames_mod.PendingFrameQueues = .empty,

    /// Client-side callback fired when a NEW_TOKEN frame arrives at
    /// application encryption level (RFC 9000 §8.1.3). Embedders
    /// stash the bytes for use as the long-header Token on a future
    /// connection's first Initial. Server-side connections never
    /// fire this — peers MUST NOT send NEW_TOKEN to a server.
    new_token_callback: ?NewTokenCallback = null,
    new_token_user_data: ?*anyopaque = null,

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
        // Client picked the destination address itself, so the §8.1
        // anti-amplification cap doesn't apply on its outbound. Primary
        // path starts validated. (See `PathSet.ensurePrimary` for the
        // matching server policy: the server leaves it unvalidated and
        // flips it on the first authenticated Handshake from peer.)
        conn.primaryPath().path.markValidated();
        // RFC 8899 DPLPMTUD: install the default config on the primary
        // path. Embedders that supply a non-default config must call
        // `setPmtudConfig` after `init*` (the wrapper helpers
        // `Server.Config.pmtud` / `Client.Config.pmtud` thread it
        // automatically). `setPmtudConfig` does the matching lift on
        // `self.mtu` for us.
        conn.setPmtudConfig(conn.pmtud_config);
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
        // RFC 8899 DPLPMTUD on the primary path. See `initClient` for
        // the embedder-config plumbing path.
        conn.setPmtudConfig(conn.pmtud_config);
        return conn;
    }

    /// Replace the connection-wide `PmtudConfig` and re-initialise the
    /// PMTUD state on every existing path. Embedders pass a config via
    /// `Server.Config.pmtud` / `Client.Config.pmtud`; this entry point
    /// is reachable directly for tests and for embedders that want to
    /// retune at runtime.
    ///
    /// `Connection.mtu` is left untouched: it stays the connection-
    /// wide static ceiling (the QUIC v1 floor unless an embedder
    /// raised it explicitly, then potentially lowered by the peer's
    /// `max_udp_payload_size`). DPLPMTUD's own ceiling lives on
    /// `pmtud_config.max_mtu` and is consulted directly by the probe
    /// scheduler. Per-path `pmtu` floats inside that range as probes
    /// succeed or fail.
    pub fn setPmtudConfig(self: *Connection, cfg: path_mod.PmtudConfig) void {
        self.pmtud_config = cfg;
        for (self.paths.paths.items) |*p| {
            p.pmtudInit(cfg);
        }
    }

    /// RFC 8899 DPLPMTUD: current PMTU floor (in bytes) for the active
    /// application-data path. The send path consults this when sizing
    /// outbound 1-RTT packets; embedders surface it via observability.
    pub fn pmtu(self: *const Connection) usize {
        return self.paths.activeConst().pmtu;
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
        self.pending_frames.deinit(self.allocator);
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

        // Hardening guide §3.5 / §9.4: zero sensitive packet
        // protection material before the buffers go back to the
        // allocator. `secureZero` is volatile-backed so the optimizer
        // can't elide it on the dead-store path where the struct is
        // about to be `undefined`-poisoned. We zero in place — the
        // surrounding ArrayLists and structs will be deinit-ed below.
        for (&self.levels) |*level| {
            if (level.read) |*material| std.crypto.secureZero(u8, &material.secret);
            if (level.write) |*material| std.crypto.secureZero(u8, &material.secret);
        }
        zeroAppKeyEpoch(&self.app_read_previous);
        zeroAppKeyEpoch(&self.app_read_current);
        zeroAppKeyEpoch(&self.app_read_next);
        zeroAppKeyEpoch(&self.app_write_current);
        // Stateless-reset tokens — both directions. Peer-supplied
        // ones are the ones we'd compare incoming traffic against;
        // local ones are the ones we minted and may have shipped over
        // the wire. Either way they shouldn't linger in freed memory.
        for (self.peer_cids.items) |*item| std.crypto.secureZero(u8, &item.stateless_reset_token);
        for (self.local_cids.items) |*item| std.crypto.secureZero(u8, &item.stateless_reset_token);

        self.peer_cids.deinit(self.allocator);
        self.local_cids.deinit(self.allocator);
        self.retry_token.deinit(self.allocator);
        self.local_stream_data_blocked.deinit(self.allocator);
        self.peer_stream_data_blocked.deinit(self.allocator);
        self.inner.deinit();
        self.* = undefined;
    }

    /// Helper used by `deinit` to zero the secret + derived packet
    /// keys held inside an `ApplicationKeyEpoch` slot.
    fn zeroAppKeyEpoch(slot: *?ApplicationKeyEpoch) void {
        if (slot.*) |*epoch| {
            std.crypto.secureZero(u8, &epoch.material.secret);
            std.crypto.secureZero(u8, &epoch.keys.key);
            std.crypto.secureZero(u8, &epoch.keys.iv);
            std.crypto.secureZero(u8, &epoch.keys.hp);
            // The cached HP cipher holds an AES key schedule derived
            // from `hp`; zero its raw bytes too.
            std.crypto.secureZero(u8, std.mem.asBytes(&epoch.keys.hp_cipher));
        }
    }

    /// Snapshot of the parameters most recently passed to
    /// `setTransportParams`. Useful for callers (e.g. RFC 9368 §6
    /// multi-Initial pre-parse) that need to mutate one or two
    /// fields and re-push without rebuilding the full struct.
    pub fn localTransportParams(self: *const Connection) TransportParams {
        return self.local_transport_params;
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
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) return params;
        self.validatePeerTransportRole();
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) return params;
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

    /// Install a callback fired when the (client-side) connection
    /// receives a NEW_TOKEN frame (RFC 9000 §8.1.3). The embedder
    /// typically stashes the bytes alongside their session ticket so
    /// the next connection to the same server can present the token
    /// in its long-header Token field and skip the server's Retry
    /// round trip.
    ///
    /// `cb` may be null to clear an existing callback. Server-side
    /// connections never fire the callback (NEW_TOKEN from a peer is
    /// a client-only event).
    pub fn setNewTokenCallback(
        self: *Connection,
        cb: ?NewTokenCallback,
        user_data: ?*anyopaque,
    ) void {
        self.new_token_callback = cb;
        self.new_token_user_data = user_data;
    }

    /// Server-side helper: pre-load the client's first Initial Token
    /// field with `token` (a Retry token or a NEW_TOKEN from a prior
    /// connection). Idempotent. Used by `Client` to wire up
    /// `Client.Config.new_token` ahead of the first `advance`.
    pub fn setInitialToken(self: *Connection, token: []const u8) Error!void {
        if (self.role != .client) return Error.NotClientContext;
        try self.retry_token.resize(self.allocator, token.len);
        @memcpy(self.retry_token.items, token);
    }

    /// Server-side helper: queue a NEW_TOKEN frame for transmission at
    /// application encryption level (RFC 9000 §19.7). Idempotent — a
    /// second call before the first one drains overwrites the queued
    /// payload (we only ever owe one NEW_TOKEN per session by
    /// default). The bytes are copied into the per-connection
    /// pending-frames slot, so `token` does not need to outlive this
    /// call.
    pub fn queueNewToken(self: *Connection, token: []const u8) Error!void {
        if (self.role != .server) return Error.NotServerContext;
        // RFC 9000 §19.7: NEW_TOKEN MUST NOT carry a zero-length token
        // (a peer that received one would close with FRAME_ENCODING).
        // We also bound the upper end to the inline-buffer capacity;
        // server callers fed by `new_token.mint` always emit exactly
        // `new_token.max_token_len = 96`, which fits.
        if (token.len == 0) return Error.ZeroLengthNewToken;
        if (token.len > pending_frames_mod.NewTokenItem.max_len) return Error.NewTokenTooLong;
        var item: pending_frames_mod.NewTokenItem = .{};
        @memcpy(item.bytes[0..token.len], token);
        item.len = @intCast(token.len);
        self.pending_frames.new_token = item;
    }

    /// Per-connection 0-RTT toggle. This deliberately gates quic_zig's
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

    /// Server convenience: build and install quic_zig's canonical replay
    /// context from current transport parameters plus app-owned bytes.
    /// The returned digest is what callers should remember beside the
    /// issued ticket if they keep their own ticket metadata.
    pub fn setEarlyDataContextForParams(
        self: *Connection,
        params: TransportParams,
        alpn: []const u8,
        application_context: []const u8,
    ) !early_data_context_mod.Digest {
        const digest = try early_data_context_mod.build(.{
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
    /// diagnostics. quic_zig never writes logs on its own; embedders can
    /// translate these events into qlog JSON, metrics, or test probes.
    pub fn setQlogCallback(
        self: *Connection,
        callback: ?QlogCallback,
        user_data: ?*anyopaque,
    ) void {
        self.qlog_callback = callback;
        self.qlog_user_data = user_data;
    }

    /// Install an embedder-policy hook that gates peer migrations to
    /// a new 4-tuple (RFC 9000 §9). The callback fires synchronously
    /// **before** PATH_CHALLENGE / PATH_RESPONSE — i.e. as soon as the
    /// triggering datagram authenticates on the existing path's keys
    /// and we identify a different peer address. Most embedders only
    /// want an IP allowlist, which doesn't justify paying for a
    /// validation round-trip.
    ///
    /// Returning `.deny` from the callback drops the migration
    /// attempt: PATH_CHALLENGE is not queued, the existing path keeps
    /// its address (and its anti-amp credit grows from the triggering
    /// datagram), and the connection stays open. A
    /// `migration_path_failed` qlog event with reason `policy_denied`
    /// is emitted for observability.
    ///
    /// The callback receives `*const Connection` so it can read state
    /// but not mutate it. Pass `null` (with any user data) to remove
    /// a previously-installed callback.
    pub fn setMigrationCallback(
        self: *Connection,
        callback: ?MigrationCallback,
        user_data: ?*anyopaque,
    ) void {
        self.migration_callback = callback;
        self.migration_user_data = user_data;
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
    pub fn emitConnectionStartedOnce(self: *Connection) void {
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
    pub fn emitPeerParametersSet(self: *Connection) void {
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

    pub fn emitPacketReceived(
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

    pub fn emitPacketDropped(
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
    pub fn emitCongestionStateIfChanged(self: *Connection, now_us: u64) void {
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
    pub fn emitMetricsSnapshot(self: *Connection, now_us: u64) void {
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

    /// True if Initial-level packet protection keys are still installed
    /// for the given direction. RFC 9001 §5.7 ¶3 requires that an
    /// endpoint discard its Initial keys "when it first sends a
    /// Handshake packet" (write side) and after it "first successfully
    /// processes a Handshake packet" (read side); after that point
    /// inbound Initial packets must be dropped and outbound Initial
    /// packets cannot be sealed. Embedders shouldn't normally inspect
    /// this — it's exposed primarily for conformance assertions over
    /// the §5.7 lifecycle.
    pub fn initialKeysActive(self: *const Connection, dir: Direction) bool {
        return switch (dir) {
            .read => self.initial_keys_read != null,
            .write => self.initial_keys_write != null,
        };
    }

    /// Cipher suite negotiated for the given encryption level, if
    /// the secret has been installed and the protocol-id is one we
    /// support. RFC 9001 only permits TLS 1.3 cipher suites; quic_zig
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
        // RFC 9001 §6: HP keys don't rotate on a key update; only the
        // AEAD key/IV change. `setHp` keeps the cached HP cipher in
        // sync with the bytes — a bare `next_keys.hp = …` would leave
        // the cache pointing at the just-derived (but unused) HP key.
        try next_keys.setHp(current.keys.hp[0..suite.hpLen()]);
        return .{
            .material = material,
            .keys = next_keys,
            .key_phase = !current.key_phase,
            .epoch = current.epoch +| 1,
            .installed_at_us = installed_at_us,
        };
    }

    pub fn installApplicationSecret(
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

    pub fn promoteApplicationReadKeys(self: *Connection, now_us: u64) Error!void {
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

    pub fn maybeRespondToPeerKeyUpdate(self: *Connection, now_us: u64) Error!void {
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

    /// Test-only: allocate the next outgoing PN in the application
    /// (1-RTT) packet number space and bump `next_pn` so the
    /// connection's own send path will pick a strictly larger PN on
    /// its next outbound packet. Conformance fixtures use this to seal
    /// a synthetic 1-RTT packet with a PN consistent with the
    /// connection's bookkeeping — without this, an injected frame
    /// elicits an ACK whose `largest_acked` would exceed the live
    /// `next_pn`, which the connection (correctly) treats as an ACK
    /// of an unsent packet (RFC 9000 §13.1) and closes with
    /// PROTOCOL_VIOLATION. Only conformance fixtures should reach for
    /// this; production code drives PN allocation through the normal
    /// `pollLevel` path.
    pub fn allocApplicationPacketNumberForTesting(self: *Connection) ?u64 {
        return self.primaryPath().app_pn_space.nextPn();
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

    pub fn onApplicationPacketAckedForKeys(
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

    pub fn noteApplicationAuthFailure(self: *Connection) void {
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
        try _internal.rememberLocalCid(self,0, 0, 0, self.local_scid, @splat(0));
    }

    /// Length of the local SCID — also the length of the DCID the
    /// peer puts on incoming short-header packets.
    pub fn localDcidLen(self: *const Connection) u8 {
        return self.local_scid.len;
    }

    pub fn longHeaderScid(self: *const Connection) ConnectionId {
        return if (self.initial_source_cid_set) self.initial_source_cid else self.local_scid;
    }

    // INTERNAL: pub for refactor; not part of embedder API. Cascade
    // dependency of `_internal.rememberLocalCid`.
    pub fn retireLocalCidsPriorTo(
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

    pub fn retireLocalCidFromPeer(self: *Connection, path_id: u32, sequence_number: u64) void {
        const before_budget = self.localConnectionIdIssueBudget(path_id);
        self.retireLocalCid(path_id, sequence_number);
        if (self.localConnectionIdIssueBudget(path_id) > before_budget) {
            self.recordConnectionIdsNeeded(path_id, .retired, null);
        }
    }

    pub fn dropPendingLocalCidAdvertisement(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
    ) void {
        if (path_id == 0) {
            self.pending_frames.removeNewConnectionIdBySequence(sequence_number);
            return;
        }
        self.pending_frames.removePathNewConnectionIdBySequence(path_id, sequence_number);
    }

    /// Smallest sequence number still resident in `local_cids` for
    /// `path_id`, or null when the path has no local CIDs at all.
    /// Used by `handleRetireConnectionId` to short-circuit an
    /// O(N) walk when the peer retires a sequence already gone from
    /// the table.
    pub fn smallestLiveLocalCidSeq(self: *const Connection, path_id: u32) ?u64 {
        var smallest: ?u64 = null;
        for (self.local_cids.items) |item| {
            if (item.path_id != path_id) continue;
            if (smallest == null or item.sequence_number < smallest.?) {
                smallest = item.sequence_number;
            }
        }
        return smallest;
    }

    /// Sequence number to use for the next NEW_CONNECTION_ID
    /// the embedder issues on `path_id`. Useful when minting CIDs
    /// outside of `replenishConnectionIds`.
    pub fn nextLocalConnectionIdSequence(self: *const Connection, path_id: u32) u64 {
        return _internal.nextLocalCidSequence(self,path_id);
    }

    /// Number of currently-active local SCIDs across all paths
    /// (initial SCID plus every still-unretired SCID issued via
    /// NEW_CONNECTION_ID). Used by embedders that maintain a
    /// CID-to-connection routing table outside the connection
    /// (the canonical caller is `quic_zig.Server`).
    pub fn localScidCount(self: *const Connection) usize {
        return self.local_cids.items.len;
    }

    /// Snapshot the currently-active local SCIDs into `dst`.
    /// Returns the number of CIDs actually written (`min(dst.len,
    /// localScidCount())`). Caller is responsible for sizing `dst`
    /// large enough; oversize is fine, undersize silently truncates.
    /// CIDs are returned in insertion order — the initial SCID is
    /// at index 0, with subsequent NEW_CONNECTION_ID-issued CIDs
    /// following in the order they were minted, modulo retirements
    /// (which compact the list).
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

    /// Return the issuance sequence number of the locally-issued CID
    /// matching `dcid`, or `null` if `dcid` is not one of ours. The
    /// initial SCID is sequence 0; subsequent NEW_CONNECTION_ID-issued
    /// CIDs increment in mint order. Required by Server routing to
    /// inform `Connection.handle` which CID the inbound packet was
    /// addressed to so RFC 9000 §19.16 ¶3 (RETIRE_CONNECTION_ID for
    /// the receiving CID is PROTOCOL_VIOLATION) can fire.
    pub fn findLocalCidSequence(self: *const Connection, dcid: []const u8) ?u64 {
        for (self.local_cids.items) |item| {
            if (item.cid.len != dcid.len) continue;
            if (std.mem.eql(u8, item.cid.bytes[0..item.cid.len], dcid)) {
                return item.sequence_number;
            }
        }
        return null;
    }

    /// Tell the connection which locally-issued CID sequence the
    /// next-handled inbound datagram is addressed to. The Server's
    /// router calls this before `handle` based on the routing
    /// `cid_table` lookup so per-frame handlers (notably
    /// `handleRetireConnectionId`) can compare against it.
    /// `null` means "unknown" (e.g. an Initial packet on the
    /// pre-routing-table bootstrap path); the §19.16 ¶3 gate
    /// short-circuits in that case.
    pub fn setIncomingLocalCidSeq(self: *Connection, seq: ?u64) void {
        self.current_incoming_local_cid_seq = seq;
    }

    // INTERNAL: pub for refactor; not part of embedder API. Cascade
    // dependency of `_internal.ensureCanIssueLocalCid`.
    pub fn localCidSequenceExists(
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

    pub fn peerActiveConnectionIdLimit(self: *const Connection) u64 {
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

    // INTERNAL: pub for refactor; not part of embedder API. Cascade
    // dependency of `_internal.ensureCanIssueLocalCid`.
    pub fn localConnectionIdIssueBudgetAfterRetirePriorTo(
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
        if ((bytes[0] & 0x80) == 0) return Error.NotInitialPacket; // bit 7 clear → short header
        // RFC 9368 §3.2: the v2 long-header type rotation puts Initial
        // at 0b01 instead of 0b00. Resolve through `longTypeFromBits`
        // so a v2 ClientHello survives this gate.
        const version = std.mem.readInt(u32, bytes[1..5], .big);
        const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
        if (wire_header.longTypeFromBits(version, long_type_bits) != .initial) {
            return Error.NotInitialPacket;
        }
        // Adopt the peer's version so subsequent Initial-key
        // derivation (`ensureInitialKeys`), header encoding, and
        // Retry-tag construction all key off the right RFC 9001 §5
        // / RFC 9368 §3.3 constants. Invalidates any pre-existing
        // Initial keys via `setVersion`.
        if (version != self.version) self.setVersion(version);
        // RFC 9368 §6 ¶6/¶7 downgrade-attack guard: snapshot the wire
        // version of the FIRST Initial we accepted, BEFORE any
        // compatible-version upgrade flips `self.version`. The client's
        // `version_information.chosen_version` (parsed later from the
        // ClientHello transport params) MUST equal this — otherwise a
        // path attacker rewrote the wire version while leaving the
        // ClientHello intact. Latched once: subsequent `acceptInitial`
        // calls (e.g. retransmits) leave the snapshot alone.
        if (self.initial_wire_version == null) {
            self.initial_wire_version = version;
        }

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
        if ((bytes[0] & 0x80) == 0) return Error.NotInitialPacket;
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
        // RFC 9368 §3.2: the v2 long-header type rotation makes the
        // wire-bit value version-specific; resolve through
        // `longTypeFromBits` so v2 Initials don't get rejected here.
        const long_type = wire_header.longTypeFromBits(cids.version, long_type_bits);
        if (long_type != .initial) return Error.NotInitialPacket;
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

    /// Server-side helper: write a Retry packet in response to
    /// `client_initial`. Token contents and validation remain
    /// embedder-owned; quic_zig handles the Retry header and the
    /// version-keyed RFC 9001 §5.8 / RFC 9368 §3.3.3 integrity tag.
    /// The Retry's version field mirrors the client's Initial so the
    /// peer can validate under the matching constants.
    pub fn writeRetry(
        self: *Connection,
        dst: []u8,
        client_initial: []const u8,
        retry_scid: []const u8,
        retry_token: []const u8,
    ) Error!usize {
        if (self.role != .server) return error.NotServerContext;
        const cids = try longHeaderCids(client_initial);
        // Make sure the leading long-header packet really is an Initial
        // under the client's chosen version (RFC 9368 §3.2 v2 layout
        // moves the Retry slot, so a v1-only check would mis-classify
        // a v2 Retry as "not an Initial").
        const long_type_bits: u2 = @intCast((client_initial[0] >> 4) & 0x03);
        const long_type = wire_header.longTypeFromBits(cids.version, long_type_bits);
        if (long_type != .initial) return Error.NotInitialPacket;
        return try long_packet_mod.sealRetry(dst, .{
            .version = cids.version,
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

    /// RFC 9001 §5.7 ¶3: "Endpoints MUST discard their Initial keys
    /// when they first send a Handshake packet." quic_zig makes the call
    /// stricter: once Handshake-level secrets are installed (which
    /// means the TLS handshake has progressed past Initial) we drop
    /// Initial keys outright. Any further inbound Initial packet is
    /// rejected by `packetKeys` returning null, and the receiver
    /// drops it as `keys_unavailable`.
    ///
    /// Idempotent: safe to call multiple times. Securely zeroes the
    /// discarded key material so it can't be recovered from a memory
    /// dump after the discard point.
    fn discardInitialKeys(self: *Connection) void {
        if (self.initial_keys_read) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
        if (self.initial_keys_write) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
        self.initial_keys_read = null;
        self.initial_keys_write = null;
        self.initial_keys_discarded = true;
    }

    /// RFC 9001 §4.9.2: "An endpoint MUST discard its handshake keys
    /// when the TLS handshake is confirmed." Mirrors `discardInitialKeys`
    /// but operates on the Handshake-level slot in `levels` and the
    /// connection-level Handshake sent tracker (`sent[1]`).
    ///
    /// The trigger differs per role: clients latch on HANDSHAKE_DONE
    /// (RFC 9001 §4.1.2 ¶2), servers latch on `handshakeDone()`
    /// returning true (which equals "received client Finished" — the
    /// server's confirmation event). Both paths land here.
    ///
    /// Effect:
    ///   - Securely zeros the read+write traffic-secret material in
    ///     `levels[handshake.idx()]` and clears both slots, so
    ///     `packetKeys(.handshake, …)` returns null. Any subsequent
    ///     inbound Handshake-level packet is dropped at the receiver
    ///     as `keys_unavailable`; no further Handshake-level packet
    ///     can be sealed by the send path either.
    ///   - Clears the connection-level Handshake sent tracker. RFC
    ///     9002 §6.4 ¶1: "If a packet number space is discarded, then
    ///     all in-flight packets in that space MUST be removed from
    ///     bytes_in_flight." Without this, `firePtoAtLevel(.handshake)`
    ///     would keep retransmitting phantom Finished CRYPTO frames
    ///     forever — exactly the failure mode that quiche's strict
    ///     `dropped invalid packet` response made fatal in the
    ///     `rebind-addr` interop testcase (the post-rebind 1-RTT
    ///     stall left no fresh ACK source, so the only thing the
    ///     client kept emitting was useless Handshake-PTO probes).
    ///   - Resets the Handshake-level `pto_count` and `pending_ping`
    ///     so a stale latch can't immediately re-fire.
    ///
    /// Idempotent: the `handshake_keys_discarded` latch makes a
    /// second call a no-op.
    /// INTERNAL: pub for `_state_tests.zig` to drive the discard
    /// directly without the surrounding `handleWithEcn` /
    /// `drainInboxIntoTls` machinery. Embedders never need this —
    /// the gate is purely an internal RFC 9001 §4.9.2 invariant.
    pub fn discardHandshakeKeys(self: *Connection) void {
        if (self.handshake_keys_discarded) return;
        const hsk_lvl_idx = EncryptionLevel.handshake.idx();
        if (self.levels[hsk_lvl_idx].read) |*material| {
            std.crypto.secureZero(u8, &material.secret);
        }
        if (self.levels[hsk_lvl_idx].write) |*material| {
            std.crypto.secureZero(u8, &material.secret);
        }
        self.levels[hsk_lvl_idx].read = null;
        self.levels[hsk_lvl_idx].write = null;
        // Initial uses idx 0 in connPnIdx mapping; Handshake is idx 1.
        // See `connPnIdx` for the rationale (the array indices ride
        // the connection-level PN-space layout, not `EncryptionLevel.idx`).
        self.clearSentTracker(&self.sent[1]);
        self.pto_count[1] = 0;
        self.pending_ping[1] = false;
        self.handshake_keys_discarded = true;
    }

    pub fn ensureInitialKeys(self: *Connection) Error!void {
        // RFC 9001 §5.7 ¶3 — once the discard latch is set, never
        // re-derive. Any Initial-level packet from now on cannot be
        // sealed (poll path) or opened (handle path); the receiver
        // drops as `keys_unavailable`.
        if (self.initial_keys_discarded) return;
        if (self.initial_keys_read != null and self.initial_keys_write != null) return;
        if (!self.initial_dcid_set) return;
        const dcid_slice = self.initial_dcid.slice();
        // RFC 9001 §5.2 / RFC 9368 §3.3.1: client-direction secret
        // comes from "client in", server-direction from "server in";
        // the active version selects salt + HKDF labels.
        const client_keys_initial = try initial_keys_mod.deriveInitialKeysFor(self.version, dcid_slice, false);
        const server_keys_initial = try initial_keys_mod.deriveInitialKeysFor(self.version, dcid_slice, true);
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

    /// Set the active QUIC wire-format version. The Initial-keys
    /// derivation depends on it (RFC 9001 §5.2 v1 / RFC 9368 §3.3.1
    /// v2), so any cached Initial keys are dropped on change. Calling
    /// this after Initial-level traffic has been exchanged is a
    /// configuration error and bypasses the safety latch — embedders
    /// MUST switch versions only at construction time or via the
    /// compatible-version-negotiation upgrade path before either side
    /// has emitted an Initial under the previous version.
    pub fn setVersion(self: *Connection, version: u32) void {
        if (self.version == version) return;
        self.version = version;
        if (self.initial_keys_read) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
        if (self.initial_keys_write) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
        self.initial_keys_read = null;
        self.initial_keys_write = null;
    }

    /// RFC 9368 §6 server-side hook: stash an upgrade target so a
    /// later call to `applyPendingVersionUpgrade` can flip the active
    /// version after the first wire-version Initial has been consumed
    /// under its wire-version keys. The actual flip lives in the
    /// server's `dispatchToSlot`, just after `handleWithEcn` returns
    /// and before the embedder's `poll` would seal the EE-bearing
    /// response under what would otherwise still be the wire-version
    /// keys. Calling with `null` clears the pending upgrade. Idempotent.
    pub fn setPendingVersionUpgrade(self: *Connection, version: ?u32) void {
        self.pending_version_upgrade = version;
    }

    /// Returns the currently-pending upgrade target, or `null` if
    /// none was stashed via `setPendingVersionUpgrade`.
    pub fn pendingVersionUpgrade(self: *const Connection) ?u32 {
        return self.pending_version_upgrade;
    }

    /// Apply any RFC 9368 §6 pending version upgrade. The wire-
    /// version Initial keys are zeroed (via `setVersion`) so any
    /// retransmitted wire-version Initial that arrives after this
    /// point will be dropped at decrypt; the spec allows that —
    /// once the server has chosen to upgrade, the original wire-
    /// version stream is discarded. Returns `true` when a flip
    /// happened (so the caller can emit observability), `false`
    /// otherwise.
    pub fn applyPendingVersionUpgrade(self: *Connection) bool {
        const target = self.pending_version_upgrade orelse return false;
        self.pending_version_upgrade = null;
        if (target == self.version) return false;
        self.setVersion(target);
        return true;
    }

    /// RFC 9368 §6 client-side hook: accept a compatible-version
    /// upgrade signaled by the server's first Initial response carrying
    /// a wire version that differs from the one the client put on its
    /// outgoing Initial. The candidate `version` MUST appear in the
    /// client's locally-advertised `version_information.available_versions`
    /// (see `local_transport_params.compatibleVersions()` — entry 0 is
    /// the wire/preferred version, the remaining entries are the
    /// compatible set). Validates the candidate against the client's
    /// list and against `wire.initial.isSupportedVersion`, then flips
    /// `self.version` (which re-derives Initial keys via `setVersion`).
    ///
    /// Returns:
    ///  - `true` on a successful flip; the caller should re-derive
    ///    Initial keys (which `setVersion` zeroes) and retry decryption
    ///    of the inbound Initial.
    ///  - `false` when the upgrade is rejected (wrong role, no
    ///    advertised compatible-versions list, candidate not on the
    ///    client's list, candidate's keys aren't derivable, or the
    ///    state machine has already moved past the Initial-level
    ///    decision window). Caller treats this as "leave version
    ///    alone"; the inbound packet will then fail AEAD auth and be
    ///    dropped, which is the spec-compliant fallback.
    pub fn clientAcceptCompatibleVersion(self: *Connection, version: u32) bool {
        if (self.role != .client) return false;
        // Same-version is reported as "nothing to do" (false) so
        // callers can distinguish a real flip from a no-op.
        if (version == self.version) return false;
        // The decision window closes once Initial keys are dropped
        // (discardInitialKeys, post-handshake-confirm) — beyond that,
        // flipping `self.version` would desync the long-header type-bit
        // decoder against in-flight packets.
        if (self.initial_keys_discarded) return false;
        if (self.inner.handshakeDone()) return false;
        // Defensive: only accept versions whose Initial keys we can
        // derive. RFC 9368 §6 only defines v1↔v2; an unknown version
        // here would have been a configuration accident upstream.
        if (!initial_keys_mod.isSupportedVersion(version)) return false;
        // The candidate MUST appear in the locally-advertised
        // `available_versions` list (RFC 9368 §6 ¶6: "a server SHOULD
        // pick one of the versions" the client listed). The list
        // includes the wire version at index 0 plus every
        // compatible_version from `Client.Config`.
        const advertised = self.local_transport_params.compatibleVersions();
        if (std.mem.indexOfScalar(u32, advertised, version) == null) return false;
        self.setVersion(version);
        return true;
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

    pub fn streamIndex(id: u64) u64 {
        return id >> 2;
    }

    fn streamInitiatedByClient(id: u64) bool {
        return (id & 0b01) == 0;
    }

    pub fn streamInitiatedByLocal(self: *const Connection, id: u64) bool {
        return streamInitiatedByClient(id) == (self.role == .client);
    }

    pub fn localMaySendOnStream(self: *const Connection, id: u64) bool {
        if (streamIsBidi(id)) return true;
        return self.streamInitiatedByLocal(id);
    }

    pub fn peerMaySendOnStream(self: *const Connection, id: u64) bool {
        if (streamIsBidi(id)) return true;
        return !self.streamInitiatedByLocal(id);
    }

    pub fn initialRecvStreamLimit(self: *const Connection, id: u64) u64 {
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

    pub fn initialSendStreamLimit(self: *const Connection, id: u64) u64 {
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

    pub fn recordPeerStreamOpenOrClose(self: *Connection, id: u64) bool {
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

    pub fn peerStreamWithinLocalLimit(self: *Connection, id: u64) bool {
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

    pub fn limitChunkToSendFlow(
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

    pub fn recordStreamFlowSent(self: *Connection, s: *Stream, chunk: send_stream_mod.Chunk) void {
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
        // Hardening guide §3.5 / §8: pre-flight the resident-bytes
        // budget against the bytes we'd accept. The per-stream
        // `max_buffered` cap already gates a single stream; this
        // shares one budget with CRYPTO / DATAGRAM / recv reassembly
        // so opening many streams each near their per-stream cap
        // can't bypass the connection-wide ceiling.
        const before = s.send.bytes.items.len;
        const headroom = s.send.max_buffered -| before;
        const want = @min(data.len, headroom);
        if (want > 0) {
            try self.tryReserveResidentBytes(want);
        }
        const accepted = s.send.write(data) catch |err| {
            self.releaseResidentBytes(want);
            return err;
        };
        // `write` may accept fewer bytes than `want` if it short-writes
        // (e.g. on its own internal cap); reconcile so we only hold
        // budget for what actually landed in the buffer.
        if (accepted < want) {
            self.releaseResidentBytes(want - accepted);
        }
        return accepted;
    }

    /// Convenience: read from the receive half of stream `id`.
    pub fn streamRead(self: *Connection, id: u64, dst: []u8) Error!usize {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        const before = s.recv.bytes.items.len;
        const n = s.recv.read(dst);
        // Hardening guide §3.5 / §8: every byte the app drains is
        // bytes the connection no longer holds in its recv buffer.
        // `RecvStream.read` shifts the buffer down and shrinks it to
        // exactly the live tail, so the delta is the bytes actually
        // freed.
        if (s.recv.bytes.items.len < before) {
            self.releaseResidentBytes(before - s.recv.bytes.items.len);
        }
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
        for (self.pending_frames.max_stream_data.items) |*item| {
            if (item.stream_id == stream_id) {
                if (maximum_stream_data > item.maximum_stream_data) {
                    item.maximum_stream_data = maximum_stream_data;
                }
                return;
            }
        }
        try self.pending_frames.max_stream_data.append(self.allocator, .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        });
    }

    fn queueMaxData(self: *Connection, maximum_data: u64) void {
        if (maximum_data > self.local_max_data) self.local_max_data = maximum_data;
        if (self.peer_data_blocked_at) |limit| {
            if (maximum_data > limit) self.peer_data_blocked_at = null;
        }
        if (self.pending_frames.max_data == null or maximum_data > self.pending_frames.max_data.?) {
            self.pending_frames.max_data = maximum_data;
        }
    }

    pub fn shouldQueueReceiveCredit(consumed: u64, advertised: u64, window: u64) bool {
        if (consumed == 0) return false;
        const target = consumed +| window;
        if (target <= advertised) return false;
        if (consumed >= advertised) return true;
        return advertised - consumed <= window / 2;
    }

    pub fn queueMaxStreams(self: *Connection, bidi: bool, maximum_streams: u64) void {
        if (maximum_streams > max_stream_count_limit) return;
        const bounded_maximum_streams = @min(maximum_streams, max_streams_per_connection);
        // Early-out if the limit has not strictly advanced. RFC 9000
        // §19.11: a peer MUST ignore MAX_STREAMS that does not advance.
        // Locally we mirror that — no point clearing peer-blocked state
        // or re-queuing a frame that doesn't move the cursor.
        const current = if (bidi) self.local_max_streams_bidi else self.local_max_streams_uni;
        if (bounded_maximum_streams <= current) return;
        if (bidi) {
            self.local_max_streams_bidi = bounded_maximum_streams;
            if (self.peer_streams_blocked_bidi) |limit| {
                if (bounded_maximum_streams > limit) self.peer_streams_blocked_bidi = null;
            }
            if (self.pending_frames.max_streams_bidi == null or bounded_maximum_streams > self.pending_frames.max_streams_bidi.?) {
                self.pending_frames.max_streams_bidi = bounded_maximum_streams;
            }
        } else {
            self.local_max_streams_uni = bounded_maximum_streams;
            if (self.peer_streams_blocked_uni) |limit| {
                if (bounded_maximum_streams > limit) self.peer_streams_blocked_uni = null;
            }
            if (self.pending_frames.max_streams_uni == null or bounded_maximum_streams > self.pending_frames.max_streams_uni.?) {
                self.pending_frames.max_streams_uni = bounded_maximum_streams;
            }
        }
    }

    pub fn maybeReturnPeerStreamCredit(self: *Connection, s: *Stream) void {
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
        // Fire MAX_STREAMS once the peer has consumed at least a quarter of
        // the current limit (i.e. <= 3/4 of the cap remains). The previous
        // 1/2 watermark waited until the peer had drained 50% of the cap
        // before granting more, which left no room for an aggressively
        // pipelining peer (notably quiche) to keep going — by the time our
        // credit reached them they had already exhausted the 1000-stream
        // initial allotment the multiplexing interop testcase requires
        // (`initial_max_streams_bidi <= 1000`,
        // `quic-interop-runner/testcases_quic.py:286-288`). Dropping the
        // watermark to 1/4-consumed gives ~3 RTTs of headroom at typical
        // burst rates before the peer actually hits the cap, while still
        // batching enough closes per frame to keep MAX_STREAMS traffic low.
        const watermark = (current * 3) / 4;
        if (remaining > watermark) return;

        const batch = streamCreditReturnBatch(current);
        const grant = @min(batch, max_streams_per_connection - current);
        self.queueMaxStreams(bidi, current + grant);
    }

    fn streamCreditReturnBatch(current_limit: u64) u64 {
        return @max(min_stream_credit_return_batch, current_limit / stream_credit_return_divisor);
    }

    pub fn recordFlowBlockedEvent(self: *Connection, info: FlowBlockedInfo) void {
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

    // INTERNAL: pub for refactor; not part of embedder API. Cascade
    // dependency of `_internal.refreshConnectionIdEventsForPath`.
    pub fn connectionIdReplenishInfoFor(
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
            .next_sequence_number = _internal.nextLocalCidSequence(self,path_id),
            .blocked_next_sequence_number = blocked_next_sequence_number,
        };
    }

    pub fn recordConnectionIdsNeeded(
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

    // INTERNAL: pub for refactor; not part of embedder API. Cascade
    // dependency of `_internal.refreshConnectionIdEventsForPath`.
    pub fn connectionIdEventStillNeeded(self: *const Connection, path_id: u32) bool {
        if (self.localConnectionIdIssueBudget(path_id) > 0) return true;
        if (self.pendingPathCidsBlocked()) |blocked| {
            if (blocked.path_id == path_id) return true;
        }
        return false;
    }

    fn recordDatagramSendEvent(self: *Connection, event: StoredDatagramSendEvent) void {
        self.datagram_send_events.push(event);
    }

    pub fn recordDatagramAcked(self: *Connection, packet: *const sent_packets_mod.SentPacket) void {
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

    pub fn upsertStreamBlocked(
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

    pub fn noteDataBlocked(self: *Connection, maximum_data: u64) void {
        const changed = self.local_data_blocked_at == null or self.local_data_blocked_at.? != maximum_data;
        self.local_data_blocked_at = maximum_data;
        if (changed) {
            self.pending_frames.data_blocked = maximum_data;
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
        self.pending_frames.data_blocked = maximum_data;
        return true;
    }

    pub fn clearLocalDataBlocked(self: *Connection, new_limit: u64) void {
        if (self.local_data_blocked_at) |limit| {
            if (new_limit > limit) self.local_data_blocked_at = null;
        }
        if (self.pending_frames.data_blocked) |limit| {
            if (new_limit > limit) self.pending_frames.data_blocked = null;
        }
    }

    pub fn noteStreamDataBlocked(
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
            _ = try upsertStreamBlocked(&self.pending_frames.stream_data_blocked, self.allocator, item);
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
        _ = try upsertStreamBlocked(&self.pending_frames.stream_data_blocked, self.allocator, item);
        return true;
    }

    pub fn clearLocalStreamDataBlocked(
        self: *Connection,
        stream_id: u64,
        new_limit: u64,
    ) void {
        clearStreamBlocked(&self.local_stream_data_blocked, stream_id, new_limit);
        clearStreamBlocked(&self.pending_frames.stream_data_blocked, stream_id, new_limit);
    }

    pub fn noteStreamsBlocked(self: *Connection, bidi: bool, maximum_streams: u64) void {
        if (bidi) {
            const changed = self.local_streams_blocked_bidi == null or self.local_streams_blocked_bidi.? != maximum_streams;
            self.local_streams_blocked_bidi = maximum_streams;
            if (changed) {
                self.pending_frames.streams_blocked_bidi = maximum_streams;
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
                self.pending_frames.streams_blocked_uni = maximum_streams;
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
            self.pending_frames.streams_blocked_bidi = item.maximum_streams;
        } else {
            if (self.local_streams_blocked_uni == null or
                self.local_streams_blocked_uni.? != item.maximum_streams)
            {
                return false;
            }
            self.pending_frames.streams_blocked_uni = item.maximum_streams;
        }
        return true;
    }

    pub fn clearLocalStreamsBlocked(self: *Connection, bidi: bool, new_limit: u64) void {
        if (bidi) {
            if (self.local_streams_blocked_bidi) |limit| {
                if (new_limit > limit) self.local_streams_blocked_bidi = null;
            }
            if (self.pending_frames.streams_blocked_bidi) |limit| {
                if (new_limit > limit) self.pending_frames.streams_blocked_bidi = null;
            }
        } else {
            if (self.local_streams_blocked_uni) |limit| {
                if (new_limit > limit) self.local_streams_blocked_uni = null;
            }
            if (self.pending_frames.streams_blocked_uni) |limit| {
                if (new_limit > limit) self.pending_frames.streams_blocked_uni = null;
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
        if (self.pending_frames.send_datagrams.items.len >= max_pending_datagram_count) {
            return Error.DatagramQueueFull;
        }
        if (payload.len > max_pending_datagram_bytes or
            self.pending_frames.send_datagram_bytes > max_pending_datagram_bytes - payload.len)
        {
            return Error.DatagramQueueFull;
        }
        const copy = try self.allocator.alloc(u8, payload.len);
        errdefer self.allocator.free(copy);
        @memcpy(copy, payload);
        if (self.next_datagram_id == std.math.maxInt(u64)) return Error.DatagramIdExhausted;
        const id = self.next_datagram_id;
        self.next_datagram_id += 1;
        try self.pending_frames.send_datagrams.append(self.allocator, .{
            .id = id,
            .data = copy,
        });
        self.pending_frames.send_datagram_bytes += payload.len;
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
        try _internal.ensureCanIssueLocalCid(self,0, sequence_number, retire_prior_to, cid.len);
        const local_cid = ConnectionId.fromSlice(cid);
        try _internal.ensureLocalCidAvailable(self,0, sequence_number, local_cid);
        for (self.pending_frames.new_connection_ids.items) |item| {
            if (item.sequence_number == sequence_number) {
                if (!std.mem.eql(u8, item.connection_id.slice(), cid)) return Error.ConnectionIdAlreadyInUse;
                return;
            }
        }
        var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
        @memcpy(connection_id.bytes[0..cid.len], cid);
        try _internal.rememberLocalCid(self,0, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
        try self.pending_frames.new_connection_ids.append(self.allocator, .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
        _internal.refreshConnectionIdEventsForPath(self,0);
    }

    /// Queue a RETIRE_CONNECTION_ID frame asking the peer to drop a
    /// previously-issued CID at `sequence_number`. Idempotent.
    pub fn queueRetireConnectionId(
        self: *Connection,
        sequence_number: u64,
    ) Error!void {
        for (self.pending_frames.retire_connection_ids.items) |item| {
            if (item.sequence_number == sequence_number) return;
        }
        try self.pending_frames.retire_connection_ids.append(self.allocator, .{
            .sequence_number = sequence_number,
        });
    }

    // -- draft-munizaga-quic-alternative-server-address-00 ------------

    /// Optional flags for `Connection.advertiseAlternative*Address`.
    /// Both bits are off by default — embedders set them to drive the
    /// §6 Preferred / Retire semantics on the receiving client.
    pub const AdvertiseAlternativeAddressOptions = struct {
        /// §6: hint to the client that the path bound to this address
        /// SHOULD be migrated-to or otherwise prioritized.
        preferred: bool = false,
        /// §6: ask the client to close any path associated with this
        /// address (the SHOULD in §6 ¶3).
        retire: bool = false,
    };

    /// True if the peer advertised the §4 `alternative_address`
    /// transport parameter on its handshake. Returns false when peer
    /// transport parameters haven't been received yet, when the peer
    /// is a server (servers MUST NOT send the parameter), or when the
    /// peer simply omitted it. Drives the negotiation gate on
    /// `advertiseAlternative*Address`.
    pub fn peerSupportsAlternativeAddress(self: *const Connection) bool {
        const params = self.cached_peer_transport_params orelse return false;
        return params.alternative_address;
    }

    /// True if this endpoint advertised the §4 `alternative_address`
    /// transport parameter to its peer. Drives the receive-side gate
    /// in the frame dispatcher: a client that didn't advertise
    /// support is in a peer protocol-violation state on receipt of
    /// any ALT_*_ADDRESS frame.
    pub fn localAdvertisedAlternativeAddress(self: *const Connection) bool {
        return self.local_transport_params.alternative_address;
    }

    /// Queue an ALTERNATIVE_V4_ADDRESS frame
    /// (draft-munizaga-quic-alternative-server-address-00 §6) for
    /// emission at the application encryption level. Allocates a
    /// fresh, monotonically-increasing Status Sequence Number shared
    /// with the V6 sibling (§6 ¶5) and returns it.
    ///
    /// Server-only API: §4 ¶2 forbids clients from sending these
    /// frames. The peer MUST have advertised
    /// `alternative_address = true` in its transport parameters
    /// before this call — `Error.AlternativeAddressNotNegotiated` is
    /// returned otherwise so the embedder can't accidentally force a
    /// PROTOCOL_VIOLATION close on a non-supporting client. Returns
    /// `Error.AlternativeAddressSequenceExhausted` once the
    /// connection has emitted 2^64 advertisements, which is
    /// functionally unreachable but bounded explicitly so the wire
    /// contract can never silently break.
    pub fn advertiseAlternativeV4Address(
        self: *Connection,
        address: [4]u8,
        port: u16,
        opts: AdvertiseAlternativeAddressOptions,
    ) Error!u64 {
        if (self.role != .server) return Error.NotServerContext;
        if (!self.peerSupportsAlternativeAddress()) {
            return Error.AlternativeAddressNotNegotiated;
        }
        const seq = try self.allocAlternativeAddressSequence();
        try self.pending_frames.alternative_addresses.append(self.allocator, .{
            .v4 = .{
                .preferred = opts.preferred,
                .retire = opts.retire,
                .status_sequence_number = seq,
                .address = address,
                .port = port,
            },
        });
        return seq;
    }

    /// IPv6 sibling of `advertiseAlternativeV4Address`. Same semantics
    /// — same role gate, same shared sequence-number space, same
    /// `AlternativeAddressSequenceExhausted` boundary handling.
    pub fn advertiseAlternativeV6Address(
        self: *Connection,
        address: [16]u8,
        port: u16,
        opts: AdvertiseAlternativeAddressOptions,
    ) Error!u64 {
        if (self.role != .server) return Error.NotServerContext;
        if (!self.peerSupportsAlternativeAddress()) {
            return Error.AlternativeAddressNotNegotiated;
        }
        const seq = try self.allocAlternativeAddressSequence();
        try self.pending_frames.alternative_addresses.append(self.allocator, .{
            .v6 = .{
                .preferred = opts.preferred,
                .retire = opts.retire,
                .status_sequence_number = seq,
                .address = address,
                .port = port,
            },
        });
        return seq;
    }

    /// Allocate the next §6 ¶5 Status Sequence Number. Mirrors the
    /// `next_datagram_id` allocator pattern: returns
    /// `Error.AlternativeAddressSequenceExhausted` at the u64 cap
    /// rather than wrapping or saturating. Wrapping back to 0 would
    /// silently violate §6 ¶5 monotonicity; saturating would emit
    /// two distinct logical updates with the same sequence number,
    /// which the receiver would dedupe as a retransmit and drop the
    /// second update on the floor.
    fn allocAlternativeAddressSequence(self: *Connection) Error!u64 {
        const seq = self.next_alternative_address_sequence;
        if (seq == std.math.maxInt(u64)) {
            return Error.AlternativeAddressSequenceExhausted;
        }
        self.next_alternative_address_sequence = seq + 1;
        return seq;
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
        const item = self.pending_frames.popRecvDatagram() orelse return null;
        defer self.allocator.free(item.data);
        // Hardening guide §3.5 / §8: pair the resident-bytes release
        // with the queue dequeue. `popRecvDatagram` already decrements
        // `recv_datagram_bytes`; this drops the matching cents from
        // the global resident-bytes counter.
        defer self.releaseResidentBytes(item.data.len);
        const n = @min(dst.len, item.data.len);
        @memcpy(dst[0..n], item.data[0..n]);
        return .{ .len = n, .arrived_in_early_data = item.arrived_in_early_data };
    }

    /// Number of inbound DATAGRAMs queued for the app to read.
    pub fn pendingDatagrams(self: *const Connection) usize {
        return self.pending_frames.recv_datagrams.items.len;
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

    /// True only when *both* peers advertised the RFC 9287 §3
    /// `grease_quic_bit` transport parameter. While this returns
    /// true, every encoded long- or short-header packet draws bit 6
    /// of the first byte (the QUIC Bit) at random; the wire decoder
    /// has always accepted any value there.
    pub fn peerSupportsGreaseQuicBit(self: *const Connection) bool {
        if (!self.local_transport_params.grease_quic_bit) return false;
        const peer_params = self.cached_peer_transport_params orelse return false;
        return peer_params.grease_quic_bit;
    }

    /// Draw a fresh QUIC Bit value for the next outgoing packet.
    /// Returns 1 unless `peerSupportsGreaseQuicBit()` is true, in
    /// which case the bit is sampled uniformly at random per packet
    /// from BoringSSL's CSPRNG (RFC 9287 §3 SHOULDs an unpredictable
    /// value). Falls back to 1 if `RAND_bytes` errors so a transient
    /// CSPRNG failure can't drop us off the wire.
    fn nextQuicBit(self: *const Connection) u1 {
        if (!self.peerSupportsGreaseQuicBit()) return 1;
        var byte: [1]u8 = undefined;
        boringssl.crypto.rand.fillBytes(&byte) catch return 1;
        return @intCast(byte[0] & 0x01);
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
            try _internal.ensureCanIssueLocalCid(self,path_id, 0, 0, local_cid.len);
            try _internal.ensureLocalCidAvailable(self,path_id, 0, local_cid);
        }
        const opened_path_id = try self.paths.openPath(
            self.allocator,
            peer_addr,
            local_addr,
            local_cid,
            peer_cid,
            .{ .max_datagram_size = self.mtu },
        );
        // Seed RFC 8899 PMTUD state on the freshly-opened path.
        if (self.paths.get(opened_path_id)) |new_path| {
            new_path.pmtudInit(self.pmtud_config);
        }
        try _internal.rememberLocalCid(self,opened_path_id, 0, 0, local_cid, @splat(0));
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

    pub fn queuePathAbandon(self: *Connection, path_id: u32, error_code: u64) Error!void {
        return path_frame_queue.queuePathAbandon(self, path_id, error_code);
    }

    pub fn queuePathStatus(self: *Connection, path_id: u32, available: bool, sequence_number: u64) Error!void {
        return path_frame_queue.queuePathStatus(self, path_id, available, sequence_number);
    }

    pub fn queuePathNewConnectionId(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: []const u8,
        stateless_reset_token: [16]u8,
    ) Error!void {
        return path_frame_queue.queuePathNewConnectionId(self, path_id, sequence_number, retire_prior_to, cid, stateless_reset_token);
    }

    pub fn queuePathRetireConnectionId(self: *Connection, path_id: u32, sequence_number: u64) Error!void {
        return path_frame_queue.queuePathRetireConnectionId(self, path_id, sequence_number);
    }

    pub fn queueMaxPathId(self: *Connection, maximum_path_id: u32) void {
        return path_frame_queue.queueMaxPathId(self, maximum_path_id);
    }

    pub fn queuePathsBlocked(self: *Connection, maximum_path_id: u32) void {
        return path_frame_queue.queuePathsBlocked(self, maximum_path_id);
    }

    pub fn queuePathCidsBlocked(self: *Connection, path_id: u32, next_sequence_number: u64) void {
        return path_frame_queue.queuePathCidsBlocked(self, path_id, next_sequence_number);
    }

    pub fn pendingPathCidsBlocked(self: *const Connection) ?PathCidsBlockedInfo {
        return path_frame_queue.pendingPathCidsBlocked(self);
    }

    pub fn clearPendingPathCidsBlocked(self: *Connection, path_id: u32, next_sequence_number: u64) void {
        return path_frame_queue.clearPendingPathCidsBlocked(self, path_id, next_sequence_number);
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
        try _internal.ensureCanIssueCidForPathId(self,path_id);
        return self.replenishLocalConnectionIds(path_id, provisions);
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
                const next = _internal.nextLocalCidSequence(self,path_id);
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
            const sequence_number = _internal.nextLocalCidSequence(self,path_id);
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
            path_frame_queue.clearSatisfiedPathCidsBlocked(self, path_id);
            _internal.refreshConnectionIdEventsForPath(self,path_id);
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
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) {
            self.emitConnectionStateIfChanged();
            return;
        }
        self.validatePeerTransportRole();
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) {
            self.emitConnectionStateIfChanged();
            return;
        }
        try self.installPeerTransportStatelessResetToken();
        try self.installPreferredAddressConnectionId();
        self.validatePeerTransportConnectionIds();
        // Successfully accepted — fire `parameters_set` once.
        self.emitPeerParametersSet();
    }

    /// RFC 9000 §5.1.1 / §18.2: a server's `preferred_address` transport
    /// parameter carries a `connection_id` field that the client SHOULD
    /// register as if it had arrived in a NEW_CONNECTION_ID frame with
    /// sequence number 1. Some servers (notably ngtcp2) only ever
    /// advertise CIDs through this channel — they never proactively
    /// emit a NEW_CONNECTION_ID frame after the handshake, so missing
    /// this registration leaves the client with exactly one peer CID
    /// (the initial DCID) and a client-initiated active migration
    /// fails to satisfy the §5.1.2 ¶1 rotation requirement.
    ///
    /// Server-only operation: clients are forbidden from sending
    /// `preferred_address`; that's enforced upstream in
    /// `validatePeerTransportRole`.
    fn installPreferredAddressConnectionId(self: *Connection) Error!void {
        if (self.role != .client) return;
        const params = self.cached_peer_transport_params orelse return;
        const pref = params.preferred_address orelse return;
        if (pref.connection_id.len == 0) return;
        // Idempotent: skip if the CID is already registered (e.g. a
        // peer that also sends NEW_CONNECTION_ID for the same value).
        for (self.peer_cids.items) |item| {
            if (ConnectionId.eql(item.cid, pref.connection_id)) return;
        }
        try self.registerPeerCid(0, 1, 0, pref.connection_id, pref.stateless_reset_token);
    }

    pub fn validatePeerTransportLimits(self: *Connection) void {
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

    pub fn validatePeerTransportRole(self: *Connection) void {
        const params = self.cached_peer_transport_params orelse return;
        switch (self.role) {
            .server => {
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
                // RFC 9368 §6 ¶6/¶7 downgrade-attack guard (symmetric
                // server-side counterpart to the client-side check
                // below): the client's `version_information.chosen_version`
                // MUST equal the wire version of the FIRST Initial we
                // observed. We can't compare against `self.version`
                // directly because, when an RFC 9368 §6 compatible-
                // version upgrade has been applied, `self.version` has
                // already been flipped to the upgrade target by
                // `applyPendingVersionUpgrade` — the original wire
                // version was snapshotted into `initial_wire_version`
                // by `acceptInitial` before that flip. A mismatch
                // means a path attacker rewrote the wire version on
                // the client's Initial while leaving the encrypted
                // ClientHello intact (which would otherwise steer the
                // server onto a weaker version). Graceful fallback:
                // when `advertised_versions` is empty (a peer that
                // never sent `version_information`) or
                // `initial_wire_version` is null (handshake started
                // before this code was active), we ignore the check.
                const advertised_versions = params.compatibleVersions();
                if (advertised_versions.len > 0) {
                    if (self.initial_wire_version) |wire_version| {
                        if (advertised_versions[0] != wire_version) {
                            self.close(
                                true,
                                transport_error_transport_parameter,
                                "client chosen_version mismatches wire version",
                            );
                            return;
                        }
                    }
                }
            },
            .client => {
                // draft-munizaga-quic-alternative-server-address-00 §4 ¶2:
                // "Servers MUST NOT send this transport parameter. A
                // client that supports this extension and receives this
                // transport parameter MUST abort the connection with a
                // TRANSPORT_PARAMETER_ERROR."
                //
                // The MUST is explicitly conditioned on the client
                // supporting the extension; a non-supporting client
                // is technically free to ignore the parameter (RFC
                // 9000 §18 forward-compat would treat an unrecognized
                // parameter as a no-op). quic_zig deliberately picks
                // the strict close instead: a server that emits the
                // parameter is broken regardless of whether *this*
                // client happens to support the extension, and
                // surfacing the violation forces the operator to
                // notice and fix it rather than papering over the
                // bug. Both behaviors are spec-conformant; this is
                // the safer of the two.
                if (params.alternative_address) {
                    self.close(true, transport_error_transport_parameter, "server sent alternative_address");
                    return;
                }
                // RFC 9368 §6 ¶6/¶7 downgrade-attack guard: when the
                // server advertises `version_information`, the first
                // entry (the server's `chosen_version`) MUST equal
                // the wire version we currently see on the response
                // carrying it — otherwise a path attacker could
                // splice a v1 ClientHello into a v2 Initial response
                // and steer the client onto a weaker version. Since
                // these transport parameters are surfaced through TLS
                // EncryptedExtensions only after our active
                // `self.version` has been adopted (see the
                // compatible-version upgrade hook in
                // `handleInitial`), the check is just `chosen ==
                // self.version`.
                const advertised_versions = params.compatibleVersions();
                if (advertised_versions.len > 0 and advertised_versions[0] != self.version) {
                    self.close(
                        true,
                        transport_error_transport_parameter,
                        "server chosen_version mismatches wire version",
                    );
                    return;
                }
            },
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

    pub fn peerAckDelayExponent(self: *const Connection) u6 {
        const params = self.cached_peer_transport_params orelse return 3;
        return @intCast(@min(params.ack_delay_exponent, 20));
    }

    pub fn peerMaxAckDelayUs(self: *const Connection) u64 {
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
        // RFC 9000 §10.1 ¶2: "An idle timeout value of 0 is equivalent
        // to no timeout." The effective value is the minimum of local
        // and peer; if either is 0 the connection has no idle timeout.
        // We treat "peer params not yet cached" the same as "peer
        // advertised 0" — pre-handshake there is no negotiated value
        // so no idle deadline applies.
        const local = self.local_transport_params.max_idle_timeout_ms;
        if (local == 0) return null;
        const params = self.cached_peer_transport_params orelse return null;
        if (params.max_idle_timeout_ms == 0) return null;
        return @min(local, params.max_idle_timeout_ms) * rtt_mod.ms;
    }

    pub fn primaryPath(self: *Connection) *PathState {
        return self.paths.primary();
    }

    pub fn primaryPathConst(self: *const Connection) *const PathState {
        return self.paths.primaryConst();
    }

    pub fn activePath(self: *Connection) *PathState {
        return self.paths.active();
    }

    pub fn pathForId(self: *Connection, path_id: u32) *PathState {
        return self.paths.get(path_id) orelse self.primaryPath();
    }

    fn applicationPathForPoll(self: *Connection) *PathState {
        if (self.pending_frames.path_response != null) {
            const p = self.pathForId(self.pending_frames.path_response_path_id);
            if (p.path.state != .failed and p.path.state != .retiring) return p;
        }
        if (self.pending_frames.path_challenge != null) {
            const p = self.pathForId(self.pending_frames.path_challenge_path_id);
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

    pub fn incomingPathId(self: *Connection, from: ?Address) u32 {
        if (from) |addr| {
            for (self.paths.paths.items) |*p| {
                if (p.matchesPeerAddress(addr)) return p.id;
            }
            return self.activePath().id;
        }
        return self.activePath().id;
    }

    pub fn peerAddressChangeCandidate(
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
        if (self.pending_frames.path_challenge != null and
            self.pending_frames.path_challenge_path_id == path_id)
        {
            self.pending_frames.path_challenge = null;
        }
    }

    pub fn queuePathResponseOnPath(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
        addr: ?Address,
    ) void {
        self.pending_frames.path_response = token;
        self.pending_frames.path_response_path_id = path_id;
        self.pending_frames.path_response_addr = addr;
    }

    fn queuePathChallengeOnPath(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
    ) void {
        self.pending_frames.path_challenge = token;
        self.pending_frames.path_challenge_path_id = path_id;
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
            self.emitQlog(.{
                .name = .migration_path_failed,
                .path_id = path_id,
                .migration_fail_reason = .timeout,
            });
            return;
        }
        path.path.fail();
        path.pending_migration_reset = false;
        path.migration_rollback = null;
        self.clearQueuedPathChallengeForPath(path_id);
        self.emitQlog(.{
            .name = .migration_path_failed,
            .path_id = path_id,
            .migration_fail_reason = .timeout,
        });
    }

    pub fn recordPathResponse(
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

    pub fn handlePeerAddressChange(
        self: *Connection,
        path: *PathState,
        addr: Address,
        datagram_len: usize,
        now_us: u64,
    ) Error!void {
        // RFC 9000 §5.1.2 ¶1: "An endpoint MUST NOT use the same
        // connection ID on different paths." When a fresh peer-issued
        // CID is available (one we got via NEW_CONNECTION_ID that
        // isn't already in use on this path), rotate to it before
        // path validation begins. If no fresh CID is available
        // (peer hasn't issued more, or NAT rebinding without
        // deliberate CID issuance), quic_zig proceeds with the existing
        // CID — silently rather than refusing the migration outright,
        // because a strict refusal breaks NAT rebinding scenarios
        // where the peer never sent a NEW_CONNECTION_ID. The
        // conformance test for §5.1.2 ¶1 exercises the rotate-when-
        // available path explicitly.
        if (self.consumeFreshPeerCidForMigration(path)) |fresh_cid| {
            path.path.peer_cid = fresh_cid;
            if (path.id == 0) {
                self.peer_dcid = fresh_cid;
                self.peer_dcid_set = true;
            }
        }

        path.beginMigration(addr, datagram_len);

        const token = try self.newPathChallengeToken();
        const timeout_us = saturatingMul(self.ptoDurationForApplicationPath(path), 3);
        path.path.validator.beginChallenge(token, now_us, timeout_us);
        // Stamp the path's last-challenge clock so the rate limiter
        // in `recordAuthenticatedDatagramAddress` can throttle
        // subsequent peer-initiated migration attempts.
        path.path.last_path_challenge_at_us = now_us;
        self.queuePathChallengeOnPath(path.id, token);
    }

    /// RFC 9000 §5.1.2 ¶1 helper: pick a peer-issued CID for `path`
    /// that's NOT the one the path is currently using. Returns null if
    /// the only available CID is the current one (the migration must
    /// be refused — the peer needs to issue more CIDs via
    /// NEW_CONNECTION_ID first).
    ///
    /// Removes the chosen CID from `peer_cids` so a subsequent
    /// migration can't pick the same one again.
    fn consumeFreshPeerCidForMigration(
        self: *Connection,
        path: *PathState,
    ) ?ConnectionId {
        const current = path.path.peer_cid;
        var i: usize = 0;
        while (i < self.peer_cids.items.len) : (i += 1) {
            const item = self.peer_cids.items[i];
            if (item.path_id != path.id) continue;
            if (ConnectionId.eql(item.cid, current)) continue;
            const chosen = item.cid;
            _ = self.peer_cids.orderedRemove(i);
            return chosen;
        }
        return null;
    }

    /// Begin a client-initiated active connection migration to a new
    /// local 4-tuple (RFC 9000 §9.2). Composes the existing migration
    /// primitives — `consumeFreshPeerCidForMigration`,
    /// `PathState.beginMigration`, `queuePathChallengeOnPath` — but
    /// for the **client-side** case where the local endpoint chose
    /// to move rather than reacting to a peer-initiated address change.
    ///
    /// Preconditions:
    ///   - This is a client connection (`role == .client`).
    ///   - Handshake is complete (RFC 9000 §9.6: migration is forbidden
    ///     before handshake confirmation).
    ///   - No migration is currently pending (PATH_CHALLENGE outstanding
    ///     on the active path).
    ///   - At least one peer-issued CID is available beyond the current
    ///     one (so RFC 9000 §5.1.2 ¶1's CID-rotation requirement can
    ///     be satisfied).
    ///
    /// Effect:
    ///   - Snapshots current path state into `migration_rollback` so
    ///     the path can revert if PATH_CHALLENGE times out.
    ///   - Rotates the active path's `peer_cid` to a fresh peer-issued
    ///     CID; updates `peer_dcid` to match (long-header packets
    ///     during the validation window pick up the new SCID).
    ///   - Updates the active path's `local_addr` to `new_local_addr`
    ///     (informational on the embedder side; nothing in the core
    ///     routes by local_addr).
    ///   - Resets the path's anti-amp counters and validation state so
    ///     unvalidated bytes are re-budgeted against the 3x cap.
    ///   - Generates a fresh PATH_CHALLENGE token, arms the validator,
    ///     and queues PATH_CHALLENGE for the next `poll`.
    ///
    /// The embedder is responsible for binding a new local UDP socket
    /// (which provides `new_local_addr`) and routing all subsequent
    /// outbound datagrams through it. The new local SCID is **not**
    /// minted here — peers route inbound by DCID and the path's
    /// existing `local_cid` continues to work; embedders that want a
    /// fresh local SCID on the wire (RFC 9000 §5.1.2 ¶1 from our side)
    /// should call `queueNewConnectionId` ahead of this and then drive
    /// the peer through normal CID retirement/promotion.
    ///
    /// Returns `MigrationRefused` (encoded as `PathLimitExceeded` —
    /// the closest existing variant for "I would migrate but can't")
    /// when the precondition checks fail or no fresh peer CID is
    /// available. The caller can retry once the peer has issued more
    /// CIDs via NEW_CONNECTION_ID.
    pub fn beginClientActiveMigration(
        self: *Connection,
        new_local_addr: Address,
        now_us: u64,
    ) Error!void {
        if (self.role != .client) return Error.NotClientContext;
        const handshake_complete = self.handshakeDone() or self.test_only_force_handshake_for_migration;
        if (!handshake_complete) {
            // Mirror the diagnostic the peer-driven gate emits: §9.6
            // forbids migration before handshake confirmation. Even
            // though this is a local trigger rather than a peer event,
            // the wire effect is the same — we'd be sending PATH_CHALLENGE
            // off an unauthenticated path.
            self.emitQlog(.{
                .name = .migration_path_failed,
                .path_id = self.activePath().id,
                .migration_fail_reason = .pre_handshake,
            });
            return Error.PathLimitExceeded;
        }
        const path = self.activePath();
        if (path.path.validator.status == .pending) {
            return Error.PathLimitExceeded;
        }
        const fresh_cid = self.consumeFreshPeerCidForMigration(path) orelse {
            self.emitQlog(.{
                .name = .migration_path_failed,
                .path_id = path.id,
                .migration_fail_reason = .no_fresh_peer_cid,
            });
            return Error.PathLimitExceeded;
        };

        // Snapshot rollback state before any mutation so a
        // validation timeout can revert peer_cid / peer_dcid /
        // local_addr cleanly.
        if (path.migration_rollback == null) {
            path.migration_rollback = .{
                .peer_addr = path.path.peer_addr,
                .peer_addr_set = path.peer_addr_set,
                .validated = path.path.isValidated(),
                .bytes_received = path.path.bytes_received,
                .bytes_sent = path.path.bytes_sent,
                .state = path.path.state,
            };
        }

        // Rotate to the fresh peer CID per RFC 9000 §5.1.2 ¶1. The
        // first short header we emit after this call carries the new
        // DCID, which is exactly what the runner's connectionmigration
        // check looks for in the client pcap.
        path.path.peer_cid = fresh_cid;
        if (path.id == 0) {
            self.peer_dcid = fresh_cid;
            self.peer_dcid_set = true;
        }

        // Update local address bookkeeping. We deliberately do NOT
        // zero `bytes_received` / `bytes_sent` or flip `validated` to
        // false (the way `beginMigration` does for peer-initiated
        // migration). Rationale: §8.1 anti-amp protects an endpoint
        // from sending to an unverified peer. The client's peer (the
        // server) hasn't moved — only the client's own local address
        // changed — so anti-amp is irrelevant here. Resetting the
        // counters would clamp the next `poll`'s `max_payload` to 0
        // and stall the transfer until PATH_RESPONSE returned, which
        // is the wrong constraint to apply to client-initiated
        // migration.
        //
        // The path validator still tracks PATH_CHALLENGE in flight so
        // the embedder can observe migration progress; failure rolls
        // back peer_cid via the rollback snapshot above.
        path.setLocalAddress(new_local_addr);
        path.pending_migration_reset = true;

        const token = try self.newPathChallengeToken();
        const timeout_us = saturatingMul(self.ptoDurationForApplicationPath(path), 3);
        path.path.validator.beginChallenge(token, now_us, timeout_us);
        path.path.last_path_challenge_at_us = now_us;
        self.queuePathChallengeOnPath(path.id, token);
    }

    /// Server-side counterpart to `beginClientActiveMigration`: the
    /// embedder observed an authenticated datagram for this connection
    /// arrive on a NEW local address (typically because a peer that
    /// followed our advertised `preferred_address` flipped from the
    /// primary listening socket to the alt-port one). RFC 9000 §5.1.1
    /// requires the server to validate the new path before treating
    /// it as the active 4-tuple, so this call mirrors
    /// `handlePeerAddressChange` for the local-side flip — generates
    /// a fresh PATH_CHALLENGE token, arms the validator, queues
    /// PATH_CHALLENGE on the active path, and stamps the rate-limit
    /// clock. The `emit_path_challenge_first` machinery
    /// (`pending_migration_reset` + `validator.status == .pending`)
    /// then guarantees the next emitted packet on the new local
    /// address leads with PATH_CHALLENGE rather than burying it
    /// behind ACK / PATH_RESPONSE / STREAM frames.
    ///
    /// Preconditions:
    ///   - `role == .server` — clients drive their own migration via
    ///     `beginClientActiveMigration`.
    ///   - Handshake is complete (RFC 9000 §9.6: pre-handshake address
    ///     swaps are forbidden).
    ///   - `local_transport_params.preferred_address` is set — without
    ///     a server-advertised PA the embedder has no legitimate
    ///     trigger for this call. Returns
    ///     `PreferredAddressNotAdvertised` otherwise so embedder bugs
    ///     surface at the boundary.
    ///   - No migration is currently pending (PATH_CHALLENGE
    ///     outstanding on the active path) — re-firing for the same
    ///     local-addr on stale buffered datagrams is idempotent.
    ///
    /// Effect:
    ///   - Snapshots current path state into `migration_rollback` so
    ///     the path can revert if PATH_CHALLENGE times out.
    ///   - Updates the active path's `local_addr` to `new_local_addr`
    ///     (informational on the embedder side; nothing in the core
    ///     routes by local_addr — the embedder picks the outbound
    ///     socket via its own bookkeeping such as
    ///     `Server.Slot.last_recv_socket_idx` or the qns endpoint's
    ///     `last_recv_socket`).
    ///   - Generates a fresh PATH_CHALLENGE token, arms the validator
    ///     with a `3 * PTO` timeout (RFC 9000 §8.2.4), and queues
    ///     PATH_CHALLENGE for the next `poll`.
    ///   - Sets `pending_migration_reset = true` so a successful
    ///     PATH_RESPONSE drives `resetRecoveryAfterMigration` (RFC
    ///     9000 §9.4) and so the `emit_path_challenge_first` gate in
    ///     the send path fires for the next outbound packet.
    ///   - Does NOT zero `bytes_received` / `bytes_sent`: the peer
    ///     already authenticated the datagram on the existing path's
    ///     keys — the §8.1 anti-amp 3x cap is irrelevant to a
    ///     local-side address flip (the peer wasn't the entity that
    ///     moved). This matches the rationale in
    ///     `beginClientActiveMigration`.
    ///
    /// **Idempotence**: a no-op when the active path's `local_addr`
    /// already equals `new_local_addr` (idempotent under stale
    /// buffered datagrams that arrive shortly after the first
    /// post-migration packet) and when the validator is already
    /// `.pending` for this migration. Returns without error in both
    /// cases.
    ///
    /// Returns `PreferredAddressNotAdvertised` when no server
    /// `preferred_address` was advertised, `NotServerContext` when
    /// called on a client connection, and `PathLimitExceeded` when
    /// the handshake is incomplete or another migration is already
    /// pending (mirrors the diagnostic shape of
    /// `beginClientActiveMigration`).
    pub fn noteServerLocalAddressChanged(
        self: *Connection,
        new_local_addr: Address,
        now_us: u64,
    ) Error!void {
        if (self.role != .server) return Error.NotServerContext;
        // RFC 9000 §5.1.1 / §18.2: only meaningful when the server
        // has advertised a `preferred_address` to follow. Embedders
        // that have not configured one shouldn't be calling this API.
        if (self.local_transport_params.preferred_address == null) {
            return Error.PreferredAddressNotAdvertised;
        }
        const handshake_complete = self.handshakeDone() or self.test_only_force_handshake_for_migration;
        if (!handshake_complete) {
            self.emitQlog(.{
                .name = .migration_path_failed,
                .path_id = self.activePath().id,
                .migration_fail_reason = .pre_handshake,
            });
            return Error.PathLimitExceeded;
        }
        const path = self.activePath();

        // Idempotence: a follow-up datagram for the same migrated
        // local-addr (e.g. a duplicate or stale buffered packet) just
        // returns success. Two cases:
        //   1. The path's local_addr already matches — we already ran
        //      this body for an earlier call.
        //   2. The validator is .pending and pending_migration_reset
        //      is set — a migration is in flight; double-firing
        //      would mint a fresh token and lose the original
        //      challenge, breaking the in-flight validation.
        if (path.local_addr_set and Address.eql(path.path.local_addr, new_local_addr)) {
            return;
        }
        if (path.path.validator.status == .pending and path.pending_migration_reset) {
            return Error.PathLimitExceeded;
        }

        // Snapshot pre-migration state for rollback on validator
        // timeout. We capture the same fields
        // `beginClientActiveMigration` does so the rollback path is
        // shared. `peer_addr` doesn't change on a server-side
        // local-addr flip, but snapshotting it keeps the
        // `MigrationRollback` shape uniform across migration triggers.
        if (path.migration_rollback == null) {
            path.migration_rollback = .{
                .peer_addr = path.path.peer_addr,
                .peer_addr_set = path.peer_addr_set,
                .validated = path.path.isValidated(),
                .bytes_received = path.path.bytes_received,
                .bytes_sent = path.path.bytes_sent,
                .state = path.path.state,
            };
        }

        // Update local-address bookkeeping. Like the client-side
        // counterpart, we deliberately do NOT zero `bytes_received` /
        // `bytes_sent` — the peer hasn't moved (it just reached us
        // via a different local socket of ours), so RFC 9000 §8.1
        // anti-amp doesn't apply and the path stays validated for
        // outbound bytes. Resetting the counters would clamp the
        // first post-migration `poll`'s `max_payload` to 0, which is
        // exactly the bug we're fixing — the migrated path would
        // never send PATH_CHALLENGE because anti-amp would treat the
        // path as fresh.
        path.setLocalAddress(new_local_addr);
        path.pending_migration_reset = true;

        const token = try self.newPathChallengeToken();
        const timeout_us = saturatingMul(self.ptoDurationForApplicationPath(path), 3);
        path.path.validator.beginChallenge(token, now_us, timeout_us);
        path.path.last_path_challenge_at_us = now_us;
        self.queuePathChallengeOnPath(path.id, token);
    }

    pub fn recordAuthenticatedDatagramAddress(
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

        // RFC 9000 §9.6 / hardening guide §4.8: peer-initiated
        // migration is forbidden before the handshake is confirmed.
        // The triggering datagram authenticated under existing keys,
        // so we know the peer holds them — but pre-handshake an
        // address swap is more likely to be a probe than legitimate
        // NAT churn, and the cost of being wrong is allowing the
        // peer to anchor connection state to a half-handshaked
        // 4-tuple. Drop the datagram (no anti-amp credit, no
        // PATH_CHALLENGE) and surface the event in qlog.
        if (!self.handshakeDone() and !self.test_only_force_handshake_for_migration) {
            self.emitQlog(.{
                .name = .migration_path_failed,
                .path_id = path_id,
                .migration_fail_reason = .pre_handshake,
            });
            return;
        }

        // Per-path PATH_CHALLENGE rate limit (hardening guide §4.8:
        // "rate-limit path probes"). Caps how fast a peer can force
        // us to mint fresh challenge tokens and validator state. A
        // legitimate NAT rebinding + retry sequence completes inside
        // one RTT, so 100 ms between probes is well above the
        // legitimate floor; an adversarial probe flood is throttled
        // to one challenge per `min_path_challenge_interval_us`.
        if (path.path.last_path_challenge_at_us) |last_us| {
            if (now_us -| last_us < min_path_challenge_interval_us) {
                self.emitQlog(.{
                    .name = .migration_path_failed,
                    .path_id = path_id,
                    .migration_fail_reason = .rate_limited,
                });
                return;
            }
        }

        if (self.migration_callback) |callback| {
            const current = path.peerAddress();
            const verdict = callback(self.migration_user_data, self, addr, current);
            if (verdict == .deny) {
                // RFC 9000 §9 / design note: the triggering datagram
                // already decrypted cleanly under the existing path's
                // keys, so its frames are safe to credit against the
                // existing 4-tuple. Don't migrate; let the peer keep
                // using the old address.
                path.path.onDatagramReceived(datagram_len);
                self.emitQlog(.{
                    .name = .migration_path_failed,
                    .path_id = path_id,
                    .migration_fail_reason = .policy_denied,
                });
                return;
            }
        }
        try self.handlePeerAddressChange(path, addr, datagram_len, now_us);
    }

    pub fn incomingShortPath(self: *Connection, bytes: []const u8) ?*PathState {
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

    pub fn pnSpaceForLevel(self: *Connection, lvl: EncryptionLevel) *PnSpace {
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

    pub fn sentForLevel(self: *Connection, lvl: EncryptionLevel) *SentPacketTracker {
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

    pub fn rttForLevel(self: *Connection, lvl: EncryptionLevel) *RttEstimator {
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

    pub fn ccForApplication(self: *Connection) *NewReno {
        return &self.primaryPath().path.cc;
    }

    fn ccForApplicationConst(self: *const Connection) *const NewReno {
        return &self.primaryPathConst().path.cc;
    }

    pub fn ptoCountForLevel(self: *Connection, lvl: EncryptionLevel) *u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPath().pto_count;
    }

    fn ptoCountForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPathConst().pto_count;
    }

    pub fn pendingPingForLevel(self: *Connection, lvl: EncryptionLevel) *bool {
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

    pub fn resetInitialRecoveryForRetry(self: *Connection) Error!void {
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

    pub fn validatePeerTransportConnectionIds(self: *Connection) void {
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

    pub fn requeueRejectedEarlyData(self: *Connection) Error!void {
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

    pub fn ptoDurationForLevel(self: *const Connection, lvl: EncryptionLevel) u64 {
        return backoffDuration(self.basePtoDurationForLevel(lvl), self.ptoCountForLevelConst(lvl).*);
    }

    fn basePtoDurationForApplicationPath(self: *const Connection, path: *const PathState) u64 {
        return path.path.rtt.pto(self.peerMaxAckDelayUs());
    }

    pub fn ptoDurationForApplicationPath(self: *const Connection, path: *const PathState) u64 {
        return backoffDuration(self.basePtoDurationForApplicationPath(path), path.pto_count);
    }

    pub fn largestApplicationPtoDurationUs(self: *const Connection) u64 {
        var largest: u64 = 0;
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            largest = @max(largest, self.ptoDurationForApplicationPath(path));
        }
        if (largest == 0) largest = self.ptoDurationForApplicationPath(self.primaryPathConst());
        return largest;
    }

    pub fn retiredPathRetentionUs(self: *const Connection) u64 {
        return saturatingMul(3, self.largestApplicationPtoDurationUs());
    }

    pub fn retirePath(
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

    /// Current PTO duration in microseconds for the primary
    /// application path, with the §6.2.1 exponential backoff already
    /// applied (i.e. `base_pto << pto_count`). Test-only diagnostic so
    /// conformance tests can pin the §6.2.1 doubling invariant; there
    /// is no production reason an embedder would need this.
    pub fn ptoMicros(self: *const Connection) u64 {
        return self.ptoDurationForApplicationPath(self.primaryPathConst());
    }

    /// Current PTO backoff count for the primary application path.
    /// Reset to 0 by an ACK that newly acknowledges an ack-eliciting
    /// packet (§6.2.1). Test-only diagnostic — same justification as
    /// `ptoMicros`.
    pub fn ptoCount(self: *const Connection) u32 {
        return self.primaryPathConst().pto_count;
    }

    pub fn congestionBlocked(self: *const Connection, lvl: EncryptionLevel) bool {
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

        if (self.lifecycle.draining_deadline_us) |at_us| {
            considerDeadline(&best, .{ .kind = .draining, .at_us = at_us });
            return best;
        }
        // RFC 9000 §10.2.1 closing-state expiry: even though `closed`
        // is already latched, surface the deadline so embedders can
        // park their event loop on it.
        if (self.lifecycle.closing_deadline_us) |at_us| {
            considerDeadline(&best, .{ .kind = .closing, .at_us = at_us });
            return best;
        }
        if (self.lifecycle.closed) return null;

        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            // Twin of the `tick` gate: a discarded space contributes
            // no scheduling deadlines. Without this, `nextDeadline`
            // would surface a stale Handshake PTO timestamp from the
            // last unACKed Finished CRYPTO and an embedder polling
            // loop would wake repeatedly for a no-op `tick`.
            const space_active = switch (lvl) {
                .initial => !self.initial_keys_discarded,
                .handshake => !self.handshake_keys_discarded,
                else => false,
            };
            if (space_active) {
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
        if (self.lifecycle.pending_close != null) return true;
        if (self.lifecycle.closed) return false;
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
        if (self.pending_frames.max_data != null) return true;
        if (self.pending_frames.max_stream_data.items.len > 0) return true;
        if (self.pending_frames.max_streams_bidi != null or self.pending_frames.max_streams_uni != null) return true;
        if (self.pending_frames.data_blocked != null) return true;
        if (self.pending_frames.stream_data_blocked.items.len > 0) return true;
        if (self.pending_frames.streams_blocked_bidi != null or self.pending_frames.streams_blocked_uni != null) return true;
        if (self.pending_frames.new_connection_ids.items.len > 0) return true;
        if (self.pending_frames.retire_connection_ids.items.len > 0) return true;
        if (self.pending_frames.stop_sending.items.len > 0) return true;
        if (self.pending_frames.new_token != null) return true;
        if (self.pending_frames.path_response != null) return true;
        if (self.pending_frames.path_challenge != null) return true;
        if (self.pending_frames.path_abandons.items.len > 0) return true;
        if (self.pending_frames.path_statuses.items.len > 0) return true;
        if (self.pending_frames.path_new_connection_ids.items.len > 0) return true;
        if (self.pending_frames.path_retire_connection_ids.items.len > 0) return true;
        if (self.pending_frames.max_path_id != null) return true;
        if (self.pending_frames.paths_blocked != null) return true;
        if (self.pending_frames.path_cids_blocked != null) return true;
        if (self.pending_frames.alternative_addresses.items.len > 0) return true;
        if (self.pending_frames.send_datagrams.items.len > 0) return true;
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
        // Once `closed` is latched, the only legal outbound is a
        // CONNECTION_CLOSE frame queued by either the initial close or
        // a §10.2.1 ¶3 closing-state retransmit. Letting `pollLevel`
        // run handles both: its CC pre-empt path emits the queued
        // frame; otherwise nothing is emitted (no streams, no ACKs)
        // because every other branch is gated on stream/ACK state
        // that's empty in closing.
        if (self.lifecycle.closed and self.lifecycle.pending_close == null) return null;
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

    pub fn pollLevelOnPath(
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
        // RFC 8899 DPLPMTUD probes can grow the plaintext above 1200
        // bytes (up to `pmtud_config.max_mtu`). `max_recv_plaintext`
        // is the AEAD-supported ceiling on either direction; sizing
        // `pl_buf` to that gives headroom for any probe size we'd
        // accept on receive.
        var pl_buf: [max_recv_plaintext]u8 = undefined;
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

        // RFC 8899 DPLPMTUD probe scheduler: when the active path is in
        // `search` and no probe is in flight, build a PADDING+PING
        // packet sized to `pmtu + probe_step` (capped at the upper
        // bound or `pmtud_config.max_mtu`). The probe rides at
        // .application level only; Initial / Handshake follow their
        // own padding / size rules (§14 minimum-MTU 1200 floor on
        // first-flight Initials).
        //
        // The probe ceiling is `pmtud_config.max_mtu`, NOT
        // `Connection.mtu`. The static `mtu` field is the negotiated
        // peer ceiling and is advisory for application data; DPLPMTUD
        // explicitly probes ABOVE it on the assumption the path can
        // carry larger datagrams than the peer's handshake-time
        // advertised receive size. Embedders that want a tighter cap
        // can set `pmtud_config.max_mtu` accordingly.
        var probe_target_size: ?u16 = null;
        if (lvl == .application and
            self.pmtud_config.enable and
            app_path.pmtudIsSearching() and
            app_path.path.isValidated())
        {
            if (app_path.pmtudNextProbeSize(
                self.pmtud_config.probe_step,
                self.pmtud_config.max_mtu,
            )) |sz| {
                // Don't exceed the embedder's caller buffer.
                if (@as(usize, sz) <= dst.len) probe_target_size = sz;
            }
        }

        const max_payload: usize = blk: {
            const dcid_len: usize = packet_dcid.len;
            const scid_len: usize = packet_scid.len;
            const long_overhead: usize = 1 + 4 + 1 + dcid_len + 1 + scid_len + 8 + 4 + 16 + 8; // ample
            const short_overhead: usize = 1 + dcid_len + 4 + 16;
            const overhead: usize = if (lvl == .application) short_overhead else long_overhead;
            // The PMTU floor decides how big this packet may become.
            // For .application we read it off the chosen path
            // (DPLPMTUD updates this in step). For Initial/Handshake
            // we use self.mtu (the connection-wide ceiling — these
            // levels never change per-path). Both are independently
            // capped against the embedder's caller buffer.
            const level_mtu: usize = if (lvl == .application) app_path.pmtu else self.mtu;
            var packet_capacity = @min(level_mtu, dst.len);
            // When we've decided to emit a DPLPMTUD probe, the probe
            // size IS the packet capacity for this build (we want the
            // resulting datagram to be exactly that size). The probe
            // size is already capped at `pmtud_config.max_mtu` and
            // `dst.len` by the scheduler above.
            if (probe_target_size) |sz| packet_capacity = @min(@as(usize, sz), dst.len);
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
            // pl_buf is sized to `max_recv_plaintext` so we can
            // accommodate DPLPMTUD probes that grow above the
            // historical 1200-byte default. The plaintext budget
            // never needs more than that on either direction.
            break :blk @min(max_recv_plaintext, packet_capacity - overhead);
        };
        // `dst[pos..]` arrived too small to seal even an empty packet. This
        // is the routine "no room left in this datagram" outcome — the same
        // back-pressure signal the unvalidated branch above returns when its
        // anti-amp budget is spent. Caller (`pollDatagram` and the embedder
        // poll loop) treats `null` as "nothing to add at this level, move
        // on / try again next tick." Returning `Error.OutputTooSmall` here
        // would escape through `poll` and abort the entire endpoint —
        // particularly hot once the anti-amp fix forces real validation
        // and the validated path's first 1-RTT poll runs against a tiny
        // residual after Initial+Handshake have filled most of the MTU.
        if (max_payload == 0) return null;
        const congestion_blocked = self.congestionBlockedOnPath(lvl, app_path);
        const path_response_addr_overrides_current = blk: {
            if (lvl != .application) break :blk false;
            if (self.pending_frames.path_response == null) break :blk false;
            if (self.pending_frames.path_response_path_id != app_path.id) break :blk false;
            const addr = self.pending_frames.path_response_addr orelse break :blk false;
            break :blk !Address.eql(addr, app_path.path.peer_addr);
        };
        const app_control_blocked = congestion_blocked or path_response_addr_overrides_current;

        // Peer-initiated migration just queued a PATH_CHALLENGE on this
        // path: the receive side observed an authenticated datagram from
        // a fresh 4-tuple, `handlePeerAddressChange` snapshotted the old
        // state into `migration_rollback`, armed the validator, and
        // queued the challenge. RFC 9000 §8.2.1 ¶3 says probing-frame
        // datagrams MUST be padded to 1200 bytes (subject to anti-amp).
        //
        // Quiche's path-validation state machine is sensitive to where
        // PATH_CHALLENGE sits in the FIRST server datagram on the new
        // tuple: when ACK / MAX_DATA / MAX_STREAMS / NEW_CONNECTION_ID
        // precede it (the historical drain order), quiche occasionally
        // misroutes the packet's path-validation handling and stalls
        // the migration. Detect the freshly-migrated path here and emit
        // PATH_CHALLENGE FIRST on the next packet — before ACK and
        // every other queued control frame. This guarantees:
        //   1. PATH_CHALLENGE leads the packet (deterministic frame
        //      order across runs);
        //   2. PATH_CHALLENGE is in the FIRST emitted packet on the
        //      new path (no slot stolen by an earlier ACK-only packet
        //      because ACK is reordered behind us).
        //
        // The condition is intentionally narrow: the path must have a
        // queued PATH_CHALLENGE for THIS app_path AND the path must be
        // in the peer-migration validation window (`pending_migration_reset`
        // + `validator.status == .pending`). Client-initiated migration
        // hits the same condition (it also sets `pending_migration_reset`).
        // PATH_RESPONSE-only paths (peer probed us; we're echoing) and
        // ordinary CID-rotation paths don't trigger this fast path.
        const emit_path_challenge_first = blk: {
            if (lvl != .application) break :blk false;
            if (path_response_addr_overrides_current) break :blk false;
            if (self.pending_frames.path_challenge == null) break :blk false;
            if (self.pending_frames.path_challenge_path_id != app_path.id) break :blk false;
            if (!app_path.pending_migration_reset) break :blk false;
            if (app_path.path.validator.status != .pending) break :blk false;
            // PATH_CHALLENGE is 9 bytes (1 type + 8 token). Anti-amp
            // may have clamped `max_payload` below that; if so, we
            // can't emit a probing frame at all this poll. Skip the
            // fast path; the regular drain path will retry on the
            // next poll once anti-amp credit accrues.
            if (max_payload < 9) break :blk false;
            break :blk true;
        };

        // RFC 9000 §10.2.1 ¶2: "An endpoint MUST NOT send any frames
        // other than CONNECTION_CLOSE in the closing state." Once the
        // connection has flipped `closed` and there is no queued CC
        // (the pre-empt path below is the only escape hatch), every
        // other frame this function would emit — ACKs, CRYPTO retx,
        // streams, control frames — is illegal. Bail out before any
        // frame-builder runs. The first emit reaches this point with
        // `pending_close != null` and proceeds via the pre-empt path;
        // §10.2.1 ¶3 retransmits re-arm `pending_close` and re-enter
        // the same path on the next `poll`.
        if (self.lifecycle.closed and self.lifecycle.pending_close == null) return null;

        // CONNECTION_CLOSE pre-empts everything: if pending, that's
        // the only frame we emit, and we mark the connection
        // closed once it goes on the wire.
        if (self.lifecycle.pending_close) |info| {
            // RFC 9000 §10.2.3 ¶6: emit CONNECTION_CLOSE at the highest
            // available encryption level. When 1-RTT write keys are
            // installed, defer emission from Initial / Handshake / 0-RTT
            // to .application — this preserves the original CC variant
            // (transport vs. application) end-to-end. Without this, a
            // server that calls `close(false, ...)` post-handshake while
            // it still holds Handshake keys would emit the
            // application-variant CC at .handshake first (line 5159
            // clears `pending_close` after the first seal), forcing a
            // §10.2.3 ¶4 conversion to 0x1c on the wire and losing the
            // application error code on the receive side.
            if (lvl != .application and self.app_write_current != null) {
                return null;
            }
            // Hardening guide §9 / §12: redact the reason on the wire
            // by default. Embedders can opt in to wire-visible reasons
            // via `reveal_close_reason_on_wire = true`. Local sticky
            // reason (`lifecycle.record(...)` above the close path) is
            // always retained for embedder telemetry.
            const wire_reason: []const u8 = if (self.reveal_close_reason_on_wire)
                info.reason
            else
                &[_]u8{};
            // RFC 9000 §10.2.3 ¶4 (and Table 3 §12.4): the
            // application-variant CONNECTION_CLOSE (0x1d) MUST NOT be
            // emitted at Initial or Handshake encryption levels —
            // those levels predate application data, so an
            // application-error code there is meaningless. Convert to
            // the transport variant (0x1c) with a generic
            // APPLICATION_ERROR (0x0c) code; the embedder still sees
            // the original via the sticky `closeEvent()` (the
            // record(.local, ...) path above ran before queueing
            // pending_close). At 1-RTT (.application) and 0-RTT
            // (.early_data) — both of which carry application data —
            // the original variant goes on the wire unchanged.
            const force_transport_at_level = !info.is_transport and
                (lvl == .initial or lvl == .handshake);
            const wire_is_transport = info.is_transport or force_transport_at_level;
            const wire_error_code = if (force_transport_at_level)
                transport_error_application_error
            else
                info.error_code;
            const wire_frame_type = if (wire_is_transport) info.frame_type else 0;
            const close_frame = frame_types.ConnectionClose{
                .is_transport = wire_is_transport,
                .error_code = wire_error_code,
                .frame_type = wire_frame_type,
                .reason_phrase = wire_reason,
            };
            const wrote = try frame_mod.encode(
                pl_buf[0..max_payload],
                .{ .connection_close = close_frame },
            );
            pl_pos += wrote;
            // RFC 9000 §10.2 ¶2: "After sending a CONNECTION_CLOSE
            // frame, an endpoint immediately enters the closing
            // state." We arm the closing-state machinery via
            // `noteCloseEmit` further below (it needs the sealed-byte
            // count and the timer derived from PTO). Before the seal,
            // clear `pending_close` so a recursive `close()` from a
            // mid-emit error path doesn't double-queue the frame.
            self.lifecycle.pending_close = null;
            // No ack-eliciting flag — CONNECTION_CLOSE isn't
            // ack-eliciting per §13.2.1, but we do still want to
            // record it (it occupies a PN). Skip stream/CRYPTO/etc.
            const pn = pn_space.nextPn() orelse return Error.PnSpaceExhausted;
            const largest_acked_close = pn_space.largest_acked_sent;
            const close_quic_bit = self.nextQuicBit();
            const n_close = switch (lvl) {
                .initial => try long_packet_mod.sealInitial(dst, .{
                    .version = self.version,
                    .dcid = packet_dcid.slice(),
                    .scid = packet_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                    .quic_bit = close_quic_bit,
                }),
                .handshake => try long_packet_mod.sealHandshake(dst, .{
                    .version = self.version,
                    .dcid = packet_dcid.slice(),
                    .scid = packet_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                    .quic_bit = close_quic_bit,
                }),
                .application => try short_packet_mod.seal1Rtt(dst, .{
                    .dcid = packet_dcid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                    .key_phase = self.applicationWriteKeyPhase(),
                    .multipath_path_id = if (self.multipathNegotiated()) app_path.id else null,
                    .quic_bit = close_quic_bit,
                }),
                .early_data => try long_packet_mod.sealZeroRtt(dst, .{
                    .version = self.version,
                    .dcid = packet_dcid.slice(),
                    .scid = packet_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                    .quic_bit = close_quic_bit,
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
            // RFC 9000 §10.2.1 closing state. The first emit arms a
            // 3*PTO closing-state deadline; subsequent §10.2.1 ¶3
            // retransmits leave the deadline at its original value
            // (extending it would let a chatty peer keep the slot
            // alive past §10.2 ¶5's bound).
            const closing_deadline = now_us + self.drainingDurationUs();
            self.lifecycle.noteCloseEmit(now_us, closing_deadline);
            self.lifecycle.updateDrainingDeadline(closing_deadline);
            self.qlog_packets_sent +|= 1;
            self.qlog_bytes_sent +|= n_close;
            self.emitPacketSent(lvl, pn, @intCast(n_close), 1);
            self.emitConnectionStateIfChanged();
            return n_close;
        }

        // 0) PATH_CHALLENGE-first on a freshly-migrated path. RFC 9000
        // §8.2 / §9 — quiche's path-validation state machine expects
        // PATH_CHALLENGE to lead the first server datagram on the new
        // tuple; reordering it behind ACK / MAX_DATA / etc. (the
        // historical drain order, see section 2d below) loses
        // interop with quiche's `BA` (rebind-addr) test. The fast
        // path here writes the 9-byte frame BEFORE every other queued
        // frame so it's first on the wire AND so it can never be
        // pushed past the per-packet capacity by a fat ACK or a
        // freshly-queued NEW_CONNECTION_ID. Subsequent frames
        // (ACK, MAX_DATA, etc.) coalesce behind it as usual.
        if (emit_path_challenge_first) {
            const tok = self.pending_frames.path_challenge.?;
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .path_challenge = .{ .data = tok },
            });
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{
                .path_challenge = .{ .data = tok },
            });
            self.pending_frames.path_challenge = null;
            ack_eliciting = true;
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
            // RFC 9000 §13.4.1: outgoing ACK frames include ECN
            // counts when (a) we still believe ECN works on this
            // path (`validation == .testing`), AND (b) at least one
            // received packet at this level was ECN-marked. Otherwise
            // we stay at the no-ECN frame type so we don't mislead
            // the peer's monotonicity validation.
            const ack_ecn_counts: ?frame_types.EcnCounts = blk: {
                if (!self.ecn_enabled) break :blk null;
                if (pn_space.validation == .failed) break :blk null;
                if (!pn_space.hasObservedEcn()) break :blk null;
                break :blk frame_types.EcnCounts{
                    .ect0 = pn_space.recv_ect0,
                    .ect1 = pn_space.recv_ect1,
                    .ecn_ce = pn_space.recv_ce,
                };
            };
            while (true) {
                const max_lower_ranges = if (lvl == .application)
                    max_application_ack_lower_ranges
                else
                    std.math.maxInt(u64);
                const ack_frame = try recv_tracker.toAckFrameLimitedRangesWithEcn(
                    self.ackDelayScaled(recv_tracker, now_us),
                    &ranges_buf,
                    ranges_budget,
                    max_lower_ranges,
                    ack_ecn_counts,
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

        // 1a-pmtud) RFC 8899 DPLPMTUD probe PING. Always pairs with
        // PADDING below to inflate the datagram to `probe_target_size`.
        // The probe is structurally identical to a PTO PING (frame
        // type 0x01, 1 byte) but the in-flight bookkeeping is
        // DPLPMTUD-specific (recorded via `pmtudOnProbeSent` after the
        // seal so loss detection can route the loss outcome to
        // `pmtudOnProbeLost` instead of normal CC). The packet is
        // ack-eliciting per RFC 9000 §14.4 and §13.2.1.
        var pmtud_probe_emitted = false;
        if (probe_target_size != null and pl_pos + 1 <= max_payload) {
            const ping_len = try frame_mod.encode(
                pl_buf[pl_pos..max_payload],
                .{ .ping = .{} },
            );
            pl_pos += ping_len;
            ack_eliciting = true;
            pmtud_probe_emitted = true;
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

        // 1c) Server NEW_TOKEN issuance (RFC 9000 §19.7). The frame
        // is application-level, ack-eliciting, and retransmittable;
        // we emit at most one per session. Frame layout: type byte
        // (0x07) + varint(token.len) + token bytes.
        if (!app_control_blocked and lvl == .application) if (self.pending_frames.new_token) |item| {
            const overhead_nt: usize = 1 + varint.encodedLen(item.len) + item.len;
            if (max_payload >= pl_pos + overhead_nt) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .new_token = .{ .token = item.slice() },
                });
                pl_pos += wrote;
                // Stash a copy in the retransmit slot so loss
                // recovery can requeue from the captured bytes
                // (the pending-frames slot is about to be cleared).
                var retx_item: sent_packets_mod.NewTokenRetransmit = .{};
                @memcpy(retx_item.bytes[0..item.len], item.slice());
                retx_item.len = item.len;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .new_token = retx_item,
                });
                self.pending_frames.new_token = null;
                ack_eliciting = true;
            }
        };

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
        if (!app_control_blocked and lvl == .application and self.pending_frames.max_data != null) {
            const maximum_data = self.pending_frames.max_data.?;
            const overhead_md: usize = 1 + varint.encodedLen(maximum_data);
            if (max_payload >= pl_pos + overhead_md) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .max_data = .{ .maximum_data = maximum_data },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .max_data = .{ .maximum_data = maximum_data },
                });
                self.pending_frames.max_data = null;
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and self.pending_frames.max_stream_data.items.len > 0) {
            const item = self.pending_frames.max_stream_data.items[0];
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
                _ = self.pending_frames.max_stream_data.orderedRemove(0);
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and (self.pending_frames.max_streams_bidi != null or self.pending_frames.max_streams_uni != null)) {
            const bidi = self.pending_frames.max_streams_bidi != null;
            const maximum_streams = if (bidi) self.pending_frames.max_streams_bidi.? else self.pending_frames.max_streams_uni.?;
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
                    self.pending_frames.max_streams_bidi = null;
                } else {
                    self.pending_frames.max_streams_uni = null;
                }
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and self.pending_frames.data_blocked != null) {
            const maximum_data = self.pending_frames.data_blocked.?;
            const overhead_db: usize = 1 + varint.encodedLen(maximum_data);
            if (max_payload >= pl_pos + overhead_db) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .data_blocked = .{ .maximum_data = maximum_data },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .data_blocked = .{ .maximum_data = maximum_data },
                });
                self.pending_frames.data_blocked = null;
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and self.pending_frames.stream_data_blocked.items.len > 0) {
            const item = self.pending_frames.stream_data_blocked.items[0];
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
                _ = self.pending_frames.stream_data_blocked.orderedRemove(0);
                ack_eliciting = true;
            }
        }
        if (!app_control_blocked and lvl == .application and (self.pending_frames.streams_blocked_bidi != null or self.pending_frames.streams_blocked_uni != null)) {
            const bidi = self.pending_frames.streams_blocked_bidi != null;
            const maximum_streams = if (bidi) self.pending_frames.streams_blocked_bidi.? else self.pending_frames.streams_blocked_uni.?;
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
                    self.pending_frames.streams_blocked_bidi = null;
                } else {
                    self.pending_frames.streams_blocked_uni = null;
                }
                ack_eliciting = true;
            }
        }

        // 2b) NEW_CONNECTION_ID (application only). Advertise spare
        // CIDs so peers can validate/migrate additional paths.
        if (!app_control_blocked and lvl == .application and self.pending_frames.new_connection_ids.items.len > 0) {
            const item = self.pending_frames.new_connection_ids.items[0];
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
                _ = self.pending_frames.new_connection_ids.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        if (!app_control_blocked and lvl == .application and self.pending_frames.retire_connection_ids.items.len > 0) {
            const item = self.pending_frames.retire_connection_ids.items[0];
            const overhead_rcid: usize = 1 + varint.encodedLen(item.sequence_number);
            if (max_payload >= pl_pos + overhead_rcid) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .retire_connection_id = item,
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .retire_connection_id = item,
                });
                _ = self.pending_frames.retire_connection_ids.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2bx) ALTERNATIVE_V4/V6_ADDRESS (application only).
        // draft-munizaga-quic-alternative-server-address-00 §6 / §7:
        // application-data PN space, ack-eliciting. One frame per
        // packet keeps the size budgeting trivial and matches the
        // NEW_CONNECTION_ID drain pattern above; back-pressured advertise
        // calls accumulate in `pending_frames.alternative_addresses` and
        // drain across subsequent polls.
        if (!app_control_blocked and lvl == .application and self.pending_frames.alternative_addresses.items.len > 0) {
            const item = self.pending_frames.alternative_addresses.items[0];
            const candidate: frame_types.Frame = switch (item) {
                .v4 => |a| .{ .alternative_v4_address = a },
                .v6 => |a| .{ .alternative_v6_address = a },
            };
            const overhead_alt = frame_mod.encodedLen(candidate);
            if (max_payload >= pl_pos + overhead_alt) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], candidate);
                pl_pos += wrote;
                const retx: sent_packets_mod.RetransmitFrame = switch (item) {
                    .v4 => |a| .{ .alternative_v4_address = a },
                    .v6 => |a| .{ .alternative_v6_address = a },
                };
                try sent_packet.addRetransmitFrame(self.allocator, retx);
                _ = self.pending_frames.alternative_addresses.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2c) STOP_SENDING (one per packet for now — application only).
        if (!app_control_blocked and lvl == .application and self.pending_frames.stop_sending.items.len > 0) {
            const item = self.pending_frames.stop_sending.items[0];
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
                _ = self.pending_frames.stop_sending.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2d) PATH_RESPONSE / PATH_CHALLENGE (application level only,
        //     RFC 9000 §19.17/19.18). PATH_RESPONSE has the highest
        //     priority on the application path so we don't make the
        //     peer wait through a stream-data backlog.
        // RFC 9000 §8.2.1 + §9.4: PATH_CHALLENGE / PATH_RESPONSE are
        // probing frames that exist precisely to validate (or echo
        // validation on) a path whose congestion state we don't know
        // yet. Gating them on the *old* path's `congestion_blocked`
        // creates a deadlock at migration time: the file transfer
        // saturates the old cwnd, the address rebinds, the cwnd
        // (still old) rejects the PATH_CHALLENGE that's needed to
        // validate the new path, and the migration never completes.
        // The runner's rebind-addr verifier catches this directly:
        // it requires the FIRST server packet on a new client path to
        // contain a PATH_CHALLENGE frame. The 9-byte probe is small
        // enough that letting it past the CC limit is harmless; the
        // anti-amp `max_payload` clamp on unvalidated paths is the
        // real ceiling. A subsequent PATH_RESPONSE arrival resets the
        // path's CC to initial values via
        // `resetPathRecoveryAfterMigration`.
        var path_response_used_addr_override = false;
        if (lvl == .application and self.pending_frames.path_response != null and
            self.pending_frames.path_response_path_id == app_path.id and pl_pos + 9 <= max_payload)
        {
            if (self.pending_frames.path_response_addr) |addr| {
                path_response_used_addr_override = !Address.eql(addr, app_path.path.peer_addr);
            }
            const tok = self.pending_frames.path_response.?;
            self.poll_addr_override = self.pending_frames.path_response_addr;
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .path_response = .{ .data = tok },
            });
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{
                .path_response = .{ .data = tok },
            });
            self.pending_frames.path_response = null;
            self.pending_frames.path_response_addr = null;
            ack_eliciting = true;
        }
        if (!path_response_used_addr_override and
            lvl == .application and self.pending_frames.path_challenge != null and
            self.pending_frames.path_challenge_path_id == app_path.id and pl_pos + 9 <= max_payload)
        {
            const tok = self.pending_frames.path_challenge.?;
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .path_challenge = .{ .data = tok },
            });
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{
                .path_challenge = .{ .data = tok },
            });
            self.pending_frames.path_challenge = null;
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
        if (!path_response_used_addr_override and !congestion_blocked and (lvl == .application or lvl == .early_data) and self.pending_frames.send_datagrams.items.len > 0) {
            const dg = self.pending_frames.send_datagrams.items[0];
            const dg_overhead: usize = 1 + varint.encodedLen(dg.data.len);
            if (max_payload >= pl_pos + dg_overhead + dg.data.len) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .datagram = .{ .data = dg.data, .has_length = true },
                });
                pl_pos += wrote;
                _ = self.pending_frames.send_datagrams.orderedRemove(0);
                self.pending_frames.send_datagram_bytes -= dg.data.len;
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
        const quic_bit = self.nextQuicBit();
        const n = switch (lvl) {
            .initial => try long_packet_mod.sealInitial(dst, .{
                .version = self.version,
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
                .quic_bit = quic_bit,
            }),
            .handshake => try long_packet_mod.sealHandshake(dst, .{
                .version = self.version,
                .dcid = packet_dcid.slice(),
                .scid = packet_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
                .quic_bit = quic_bit,
            }),
            .application => try short_packet_mod.seal1Rtt(dst, .{
                .dcid = packet_dcid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
                .key_phase = self.applicationWriteKeyPhase(),
                .multipath_path_id = if (self.multipathNegotiated()) app_path.id else null,
                .quic_bit = quic_bit,
                // RFC 8899 DPLPMTUD: when a probe is in flight from
                // this poll, pad to the probed size so the resulting
                // datagram is exactly that big.
                //
                // RFC 9000 §8.2.1 ¶3: a datagram containing a
                // PATH_CHALLENGE MUST be padded to at least 1200 bytes,
                // unless anti-amplification on the path forbids it. The
                // anti-amp clamp on `max_payload` upstream already
                // gates that; when we emitted PATH_CHALLENGE first
                // (peer-initiated migration) honor the §8.2.1 floor.
                // The DPLPMTUD probe path takes precedence when both
                // are set — that path is gated on a validated path,
                // so the two conditions don't actually overlap, but we
                // pick the larger of the two for safety.
                .pad_to = if (probe_target_size) |sz|
                    @as(usize, sz)
                else if (emit_path_challenge_first)
                    @min(default_mtu, dst.len)
                else
                    0,
            }),
            .early_data => try long_packet_mod.sealZeroRtt(dst, .{
                .version = self.version,
                .dcid = packet_dcid.slice(),
                .scid = packet_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
                .quic_bit = quic_bit,
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

        // RFC 8899 DPLPMTUD: stamp the in-flight probe metadata. The
        // recorded `sent_packet` already carries `bytes = n`, but the
        // probe-size field is independent of the post-seal byte count
        // (n equals the probe size when `pad_to` is set, but on the
        // off-chance the path-specific overhead miscounted by a byte
        // we want the definitive value the probe scheduler asked for).
        if (lvl == .application) if (probe_target_size) |sz| {
            if (pmtud_probe_emitted) {
                app_path.pmtudOnProbeSent(pn, sz);
            }
        };

        // qlog hooks for the outgoing packet.
        self.qlog_packets_sent +|= 1;
        self.qlog_bytes_sent +|= n;
        self.emitPacketSent(lvl, pn, @intCast(n), countFrames(pl_buf[0..pl_pos]));

        return n;
    }

    fn encodeFrameIfFits(
        pl_buf: *[max_recv_plaintext]u8,
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

    pub fn emitOnePendingMultipathFrame(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
        pl_buf: *[max_recv_plaintext]u8,
        pl_pos: *usize,
        max_payload: usize,
    ) Error!bool {
        if (self.pending_frames.path_abandons.items.len > 0) {
            const item = self.pending_frames.path_abandons.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_abandon = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_abandon = item });
                _ = self.pending_frames.path_abandons.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_frames.path_statuses.items.len > 0) {
            const item = self.pending_frames.path_statuses.items[0];
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
                _ = self.pending_frames.path_statuses.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_frames.path_new_connection_ids.items.len > 0) {
            const item = self.pending_frames.path_new_connection_ids.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_new_connection_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_new_connection_id = item });
                _ = self.pending_frames.path_new_connection_ids.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_frames.path_retire_connection_ids.items.len > 0) {
            const item = self.pending_frames.path_retire_connection_ids.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_retire_connection_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_retire_connection_id = item });
                _ = self.pending_frames.path_retire_connection_ids.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_frames.max_path_id) |maximum_path_id| {
            const item: frame_types.MaxPathId = .{ .maximum_path_id = maximum_path_id };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .max_path_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .max_path_id = item });
                self.pending_frames.max_path_id = null;
                return true;
            }
        }
        if (self.pending_frames.paths_blocked) |maximum_path_id| {
            const item: frame_types.PathsBlocked = .{ .maximum_path_id = maximum_path_id };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .paths_blocked = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .paths_blocked = item });
                self.pending_frames.paths_blocked = null;
                return true;
            }
        }
        if (self.pending_frames.path_cids_blocked) |item| {
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_cids_blocked = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_cids_blocked = item });
                self.pending_frames.path_cids_blocked = null;
                return true;
            }
        }
        return false;
    }

    pub fn emitPendingMultipathFrames(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
        pl_buf: *[max_recv_plaintext]u8,
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
    ///
    /// Lifecycle gates per RFC 9000 §10.2:
    ///   - draining / closed (§10.2.2 ¶1): silently drop.
    ///   - pre-emit closing  (`pending_close != null`): drop here;
    ///     the next `poll` will emit the queued CC.
    ///   - post-emit closing (§10.2.1): keep processing the datagram
    ///     so we can attribute it (and re-arm a CC retransmit per
    ///     §10.2.1 ¶3) and so a peer's CC moves us to draining.
    ///     `dispatchFrames` is suppressed for non-CONNECTION_CLOSE
    ///     frames in this state via `closingAttributionOnly`.
    pub fn handle(
        self: *Connection,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!void {
        return self.handleWithEcn(bytes, from, .not_ect, now_us);
    }

    /// Same as `handle` but also accepts the IP-layer ECN codepoint
    /// the embedder peeled off the datagram's TOS byte (RFC 3168 §5).
    /// Plumbed through from `Server.feedWithEcn` /
    /// `runUdpServer`'s recvmsg cmsg parser; per-packet handlers read
    /// `last_recv_ecn` to bump the receiving PN-space's counters
    /// (RFC 9000 §13.4.1).
    pub fn handleWithEcn(
        self: *Connection,
        bytes: []u8,
        from: ?Address,
        ecn: socket_opts_mod.EcnCodepoint,
        now_us: u64,
    ) Error!void {
        // Stash the ECN marking for the per-packet handlers below; the
        // per-packet decryption tail consults it when crediting the
        // received PN in the level's `PnSpace`. Cleared at handle
        // exit so a subsequent test driver call can't accidentally
        // reuse stale state — the cmsg is per-datagram.
        self.last_recv_ecn = if (self.ecn_enabled) ecn else .not_ect;
        defer self.last_recv_ecn = .not_ect;
        const entry_state = self.lifecycle.state();
        if (entry_state == .draining or entry_state == .closed) return;
        if (entry_state == .closing and self.lifecycle.pending_close != null) return;
        // Closing-state attribution accumulator. Cleared on entry so
        // it reflects only this datagram's observations.
        self.closing_state_attribution_observed = false;
        // Per-handle-cycle DoS gates. See `incoming_ack_range_cap` /
        // `incoming_retire_cid_cap` for the rationale.
        self.incoming_ack_range_count = 0;
        self.incoming_retire_cid_count = 0;
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
            if (self.shouldStopDatagramLoop()) break;
            if (!drain_tls_after_packet) break;
            // Drain CRYPTO into TLS BETWEEN packets, not just at
            // the end. A coalesced Initial+Handshake datagram
            // delivers the ServerHello at Initial level — we have
            // to feed it to TLS (deriving Handshake keys) before
            // we can decrypt the trailing Handshake packet.
            try self.drainInboxIntoTls();
        }
        if (self.cryptoInboxQueued() and !self.closingAttributionOnly()) try self.drainInboxIntoTls();
        // RFC 9001 §4.1.2 ¶2 + §4.9.2: client confirms the handshake
        // when it processes a HANDSHAKE_DONE frame, and an endpoint
        // MUST discard its handshake keys at confirmation. We latch
        // the receipt in the frame switch above (so the `handshake_done`
        // arm stays a small enum-tag write); the actual discard runs
        // here, after the datagram's frames are dispatched, so a late
        // ACK in the same datagram still credits the Handshake-level
        // sent tracker before we tear it down. `discardHandshakeKeys`
        // is idempotent — the latch + the function-local guard makes
        // a re-entry on a second HANDSHAKE_DONE a no-op.
        if (self.received_handshake_done and !self.handshake_keys_discarded) {
            self.discardHandshakeKeys();
        }
        // RFC 9000 §10.2.1 ¶3: when in the closing state and an
        // attributed inbound packet arrived during this datagram,
        // re-arm a CONNECTION_CLOSE retransmit (subject to the SHOULD
        // rate-limit). The peer's CC, if any, would have transitioned
        // us to draining via `dispatchFrames` before we get here.
        self.maybeRearmClosingStateCloseRepeat(now_us);

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
        if (bytes.len < 5) return false;
        const version = std.mem.readInt(u32, bytes[1..5], .big);
        if (version == 0) return false;
        const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
        // RFC 9368 §3.2: Retry's wire bits depend on the version
        // (v1 = 0b11, v2 = 0b00). Resolve through `longTypeFromBits`
        // so the TLS drain skip on Retry packets covers both layouts.
        const long_type = wire_header.longTypeFromBits(version, long_type_bits);
        return long_type != .retry;
    }

    /// True when the connection is in RFC 9000 §10.2.1's closing state
    /// (the deadline-armed phase that follows the first
    /// CONNECTION_CLOSE seal) AND no follow-up CC is currently
    /// queued. The packet-decrypt tails consult this to decide whether
    /// to run the full record-and-dispatch pipeline or the
    /// closing-state-only "scan for peer CONNECTION_CLOSE, otherwise
    /// flag attribution" tail.
    pub fn closingAttributionOnly(self: *const Connection) bool {
        return self.lifecycle.closing_deadline_us != null
            and self.lifecycle.pending_close == null
            and self.lifecycle.draining_deadline_us == null;
    }

    /// Decide whether the per-datagram packet loop should bail out
    /// after the most recent packet. Terminal states (draining /
    /// closed) and a freshly-queued local close all force a break;
    /// closing-state attribution mode keeps iterating so a CC tucked
    /// into a later coalesced packet still transitions us to
    /// draining.
    fn shouldStopDatagramLoop(self: *const Connection) bool {
        const cs = self.lifecycle.state();
        if (cs == .draining or cs == .closed) return true;
        if (cs == .closing and self.lifecycle.pending_close != null) return true;
        return false;
    }

    /// Iterate `payload` looking for a peer CONNECTION_CLOSE frame.
    /// If found, transition the local lifecycle to draining (RFC 9000
    /// §10.2.2 ¶3 license: "An endpoint MAY enter the draining state
    /// from the closing state if it receives a CONNECTION_CLOSE
    /// frame"). Other frames are ignored — §10.2.1 ¶5: "An endpoint
    /// that is closing is not required to process any received
    /// frame."
    pub fn scanForPeerCloseFrame(
        self: *Connection,
        payload: []const u8,
        now_us: u64,
    ) void {
        var it = frame_mod.iter(payload);
        while (it.next() catch return) |f| {
            switch (f) {
                .connection_close => |cc| {
                    self.enterDraining(
                        .peer,
                        closeErrorSpace(cc.is_transport),
                        cc.error_code,
                        if (cc.is_transport) cc.frame_type else 0,
                        cc.reason_phrase,
                        now_us,
                    );
                    return;
                },
                else => {},
            }
        }
    }

    /// Re-arm `pending_close` so the next `poll` retransmits the
    /// CONNECTION_CLOSE, but only if (a) we're in the post-emit
    /// closing state, (b) at least one packet authenticated under our
    /// keys during the most recent `handle` call, and (c) the
    /// §10.2.1 ¶3 SHOULD-rate-limit allows another emission.
    ///
    /// The retransmit reuses the original close info captured on the
    /// sticky `lifecycle.close_event` — same error code, same reason
    /// phrase. Per §10.2.1 ¶2 ("An endpoint MAY send CONNECTION_CLOSE
    /// frames of different sizes or with different error codes, but
    /// the error code in all frames SHOULD be consistent"), keeping
    /// them identical satisfies the SHOULD-consistent guidance.
    fn maybeRearmClosingStateCloseRepeat(self: *Connection, now_us: u64) void {
        if (!self.closing_state_attribution_observed) return;
        self.closing_state_attribution_observed = false;
        if (self.lifecycle.state() != .closing) return;
        if (self.lifecycle.closing_deadline_us == null) return;
        if (self.lifecycle.pending_close != null) return;
        const base = self.basePtoDurationForLevel(.application);
        if (!self.lifecycle.shouldRearmCloseRepeat(now_us, base)) return;
        const stored = self.lifecycle.close_event orelse return;
        self.lifecycle.pending_close = .{
            .is_transport = stored.error_space == .transport,
            .error_code = stored.error_code,
            .frame_type = stored.frame_type,
            .reason = self.lifecycle.close_reason_buf[0..stored.reason_len],
        };
        self.emitConnectionStateIfChanged();
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
        return self.lifecycle.state();
    }

    /// True after we've sent or received CONNECTION_CLOSE, received a
    /// stateless reset, or timed out. Use `closeState` to distinguish
    /// closing, draining, and terminal closed states.
    pub fn isClosed(self: *const Connection) bool {
        return self.lifecycle.closed;
    }

    const closeErrorSpace = lifecycle_mod.closeErrorSpace;

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
        self.lifecycle.enterDraining(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
            draining_deadline,
        );
        self.clearPendingPings();
        self.emitConnectionStateIfChanged();
    }

    fn finishDraining(self: *Connection) void {
        self.lifecycle.finishDraining();
        self.clearRecoveryState();
        self.emitConnectionStateIfChanged();
    }

    pub fn enterClosed(
        self: *Connection,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_us: u64,
    ) void {
        self.lifecycle.enterClosed(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
        );
        self.clearRecoveryState();
        self.emitConnectionStateIfChanged();
    }

    pub fn enterStatelessReset(self: *Connection, now_us: u64) void {
        self.enterDraining(
            .stateless_reset,
            .transport,
            0,
            0,
            "stateless reset",
            now_us,
        );
    }

    /// Sticky close/error status for embedders. This remains available
    /// after `pollEvent` consumes the event notification.
    pub fn closeEvent(self: *const Connection) ?CloseEvent {
        return self.lifecycle.event();
    }

    /// Poll the next connection-level event.
    pub fn pollEvent(self: *Connection) ?ConnectionEvent {
        if (self.lifecycle.close_event) |*event| {
            if (!event.delivered) {
                const out = self.lifecycle.eventFromStored(event.*);
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
        if (self.alternative_server_address_events.pop()) |out| {
            return .{ .alternative_server_address = out };
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
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) return;
        self.lifecycle.record(
            .local,
            closeErrorSpace(is_transport),
            error_code,
            0,
            reason,
            null,
            null,
        );
        self.lifecycle.pending_close = .{
            .is_transport = is_transport,
            .error_code = error_code,
            .reason = reason,
        };
        self.emitConnectionStateIfChanged();
    }

    /// Try to reserve `n` bytes of resident-memory budget. Returns
    /// `error.ExcessiveLoad` when the reservation would push
    /// `bytes_resident` past `max_connection_memory` — callers should
    /// then `close(true, transport_error_excessive_load, "...")` and
    /// abandon the in-flight allocation rather than allow it to land.
    /// The reason string is the wire reason: keep it generic
    /// (`"excessive resource use"`) per hardening guide §9.1 / §14
    /// to avoid leaking which buffer tripped the cap.
    ///
    /// Pair every successful `tryReserveResidentBytes(n)` with a
    /// `releaseResidentBytes(n)` when the underlying bytes are freed.
    /// The helper has no awareness of which buffer the bytes live in —
    /// the call sites (handleCrypto / handleDatagram / handleStream /
    /// streamRead / dispatchAckedToStreams) own the pairing.
    pub fn tryReserveResidentBytes(self: *Connection, n: usize) Error!void {
        if (n == 0) return;
        const add: u64 = @intCast(n);
        const cap = self.max_connection_memory;
        // Saturating-add semantics: an attacker can't underflow the
        // budget by exceeding u64::MAX, but the cap check below still
        // fires once the running total overshoots `cap`.
        if (self.bytes_resident > cap or add > cap - self.bytes_resident) {
            return Error.ExcessiveLoad;
        }
        self.bytes_resident += add;
    }

    /// Release `n` bytes of resident-memory budget. Pairs with
    /// `tryReserveResidentBytes`. Underflow is clamped at zero in
    /// release builds (an unbalanced free is a bug, not a security
    /// issue — the cap stays honored), and asserts in debug.
    pub fn releaseResidentBytes(self: *Connection, n: usize) void {
        if (n == 0) return;
        const sub: u64 = @intCast(n);
        std.debug.assert(self.bytes_resident >= sub);
        self.bytes_resident -|= sub;
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
        for (self.pending_frames.stop_sending.items) |queued| {
            if (queued.stream_id == item.stream_id and
                queued.application_error_code == item.application_error_code)
            {
                return;
            }
        }
        try self.pending_frames.stop_sending.append(self.allocator, .{
            .stream_id = item.stream_id,
            .application_error_code = item.application_error_code,
        });
    }

    /// Number of peer-issued connection IDs we currently have
    /// stashed via NEW_CONNECTION_ID frames.
    pub fn peerCidsCount(self: *const Connection) usize {
        return self.peer_cids.items.len;
    }

    /// The Destination Connection ID we currently use to address the
    /// peer on the primary path. Migrates when the peer rotates CIDs
    /// (RFC 9000 §5.1.2). Test-facing — embedders normally don't need
    /// to inspect this.
    pub fn peerDcid(self: *const Connection) ConnectionId {
        return self.peer_dcid;
    }

    /// Test-only: register an extra peer-issued CID directly into the
    /// peer_cids pool, as if a peer NEW_CONNECTION_ID had arrived.
    /// Conformance tests that exercise §5.1.2 ¶1 (CID rotation on
    /// migration) use this to seed a fresh entry without driving a
    /// full wire round-trip. Production callers MUST NOT use this —
    /// the production path is a real `Connection.handleNewConnectionId`
    /// invocation through the frame dispatcher.
    pub fn registerPeerCidForTesting(
        self: *Connection,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [16]u8,
    ) Error!void {
        try self.registerPeerCid(0, sequence_number, retire_prior_to, cid, stateless_reset_token);
    }

    pub fn handleOnePacket(
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

        if (bytes.len < 5) return 0;
        const version = std.mem.readInt(u32, bytes[1..5], .big);
        if (version == 0) {
            return self.handleVersionNegotiation(bytes, now_us);
        }

        // RFC 9368 §3.2: long-header type bits rotate between v1 and
        // v2. Resolve through `longTypeFromBits` so a v2 packet with
        // wire bits 0b01 dispatches to `handleInitial`, not
        // `handleZeroRtt` (the v1 slot for that bit pattern). For
        // versions we don't recognize, the v1 mapping is the safest
        // default — those packets will fail downstream version /
        // AEAD gates anyway.
        const long_type_bits: u2 = @intCast((first >> 4) & 0x03);
        const long_type = wire_header.longTypeFromBits(version, long_type_bits);
        return switch (long_type) {
            .initial => try self.handleInitial(bytes, now_us),
            .zero_rtt => try self.handleZeroRtt(bytes, now_us),
            .handshake => try self.handleHandshake(bytes, now_us),
            .retry => try self.handleRetry(bytes, now_us),
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

    pub fn packetPayloadAckEliciting(payload: []const u8) bool {
        var it = frame_mod.iter(payload);
        while (it.next() catch return true) |f| {
            if (frameAckEliciting(f)) return true;
        }
        return false;
    }

    pub fn packetPayloadNeedsImmediateAck(payload: []const u8) bool {
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

    pub fn recordApplicationReceivedPacket(
        app_pn_space: *PnSpace,
        pn: u64,
        now_us: u64,
        payload: []const u8,
        delayed_ack_threshold: u8,
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
            delayed_ack_threshold,
        );
    }

    pub fn versionListContains(vn: wire_header.VersionNegotiation, version: u32) bool {
        var i: usize = 0;
        while (i < vn.versionCount()) : (i += 1) {
            if (vn.version(i) == version) return true;
        }
        return false;
    }

    pub fn handleVersionNegotiation( self: *Connection, bytes: []u8, now_us: u64, ) usize { return conn_recv_packet_handlers.handleVersionNegotiation(self, bytes, now_us); }

    pub fn handleShort( self: *Connection, bytes: []u8, now_us: u64, ) Error!usize { return conn_recv_packet_handlers.handleShort(self, bytes, now_us); }

    pub fn countFrames(payload: []const u8) u32 {
        var count: u32 = 0;
        var it = frame_mod.iter(payload);
        while (it.next() catch return count) |_| {
            count += 1;
        }
        return count;
    }

    pub fn openApplicationPacket(
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

    pub fn handleInitial( self: *Connection, bytes: []u8, now_us: u64, ) Error!usize { return conn_recv_packet_handlers.handleInitial(self, bytes, now_us); }

    pub fn handleRetry( self: *Connection, bytes: []u8, now_us: u64, ) Error!usize { return conn_recv_packet_handlers.handleRetry(self, bytes, now_us); }

    pub fn handleZeroRtt( self: *Connection, bytes: []u8, now_us: u64, ) Error!usize { return conn_recv_packet_handlers.handleZeroRtt(self, bytes, now_us); }

    pub fn handleHandshake( self: *Connection, bytes: []u8, now_us: u64, ) Error!usize { return conn_recv_packet_handlers.handleHandshake(self, bytes, now_us); }

    pub fn dispatchFrames(
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
            // RFC 9000 §12.4 / Table 3: at the Initial and Handshake
            // encryption levels the only legal frames are PADDING,
            // PING, ACK, CRYPTO, and CONNECTION_CLOSE of type 0x1c
            // (transport variant — application CONNECTION_CLOSE 0x1d
            // is application-data only, hence 1-RTT only). Any other
            // frame at those levels is a peer protocol violation.
            if ((lvl == .initial or lvl == .handshake) and
                !frameAllowedInInitialOrHandshake(f))
            {
                self.close(true, transport_error_protocol_violation, "forbidden frame at Initial/Handshake level");
                return;
            }
            if (lvl == .early_data and !frameAllowedInEarlyData(f)) {
                self.close(true, transport_error_protocol_violation, "forbidden frame in 0-RTT");
                return;
            }
            // RFC 9000 §19.20: HANDSHAKE_DONE is a server-only frame.
            // "A server MUST treat receipt of a HANDSHAKE_DONE frame as
            // a connection error of type PROTOCOL_VIOLATION."
            if (f == .handshake_done and self.role == .server) {
                self.close(true, transport_error_protocol_violation, "HANDSHAKE_DONE received by server");
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
                .padding, .ping => {},
                .handshake_done => {
                    // RFC 9001 §4.1.2 ¶2: client confirms the handshake
                    // on receipt of HANDSHAKE_DONE. The validity gate
                    // above already rejected this frame on the server
                    // role with PROTOCOL_VIOLATION, so we know we're
                    // the client. RFC 9001 §4.9.2 then mandates the
                    // Handshake-key discard. Latching the receipt here
                    // (rather than at end-of-datagram) keeps the gate
                    // and the discard atomic with respect to ACK
                    // processing — the ACK arm below uses
                    // `handshake_keys_discarded` to short-circuit a
                    // late peer ACK that arrives after we've cleaned
                    // the sent tracker.
                    self.received_handshake_done = true;
                },
                .ack => |a| {
                    if (self.exceedsIncomingAckRangeCap(a.range_count)) continue;
                    try self.handleAckAtLevel(lvl, a, now_us);
                },
                .path_ack => |a| {
                    if (self.exceedsIncomingAckRangeCap(a.range_count)) continue;
                    try self.handlePathAck(a, now_us);
                },
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
                .new_token => |nt| self.handleNewToken(nt),
                // draft-munizaga-quic-alternative-server-address-00 §6.
                // ALTERNATIVE_V4/V6_ADDRESS frames are gated by the
                // `alternative_address` transport parameter (§4) — only
                // a server may send them, and only after the client
                // advertised support. Receipt outside that envelope is
                // a peer protocol violation.
                .alternative_v4_address => |a| {
                    if (self.role != .client or
                        !self.localAdvertisedAlternativeAddress())
                    {
                        self.close(
                            true,
                            transport_error_protocol_violation,
                            "alternative_address frame without negotiation",
                        );
                        return;
                    }
                    self.handleAlternativeAddressV4(a);
                },
                .alternative_v6_address => |a| {
                    if (self.role != .client or
                        !self.localAdvertisedAlternativeAddress())
                    {
                        self.close(
                            true,
                            transport_error_protocol_violation,
                            "alternative_address frame without negotiation",
                        );
                        return;
                    }
                    self.handleAlternativeAddressV6(a);
                },
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
            // draft-munizaga-quic-alternative-server-address-00 §4 ¶3
            // forbids remembering the `alternative_address` parameter
            // for 0-RTT, so the negotiation cannot have happened by
            // the time a 0-RTT packet is processed. Reject the frames
            // outright at the early-data gate so the diagnostic close
            // reason is "forbidden frame in 0-RTT" rather than
            // "without negotiation" — clearer for operators and
            // closes the door even if a future role-gate change
            // accidentally weakens the inner check.
            .alternative_v4_address,
            .alternative_v6_address,
            => false,
            else => true,
        };
    }

    /// RFC 9000 §12.4 / Table 3: frames legal at the Initial or
    /// Handshake encryption level. Both levels share the same allowed
    /// list — PADDING, PING, ACK, CRYPTO, and the transport-variant
    /// CONNECTION_CLOSE (frame type 0x1c).
    ///
    /// CONNECTION_CLOSE 0x1d (the application-error variant) is
    /// 1-RTT-only because it carries an application-supplied error
    /// code; emitting it before the handshake completes would expose
    /// application semantics to an unauthenticated peer.
    fn frameAllowedInInitialOrHandshake(f: frame_types.Frame) bool {
        return switch (f) {
            .padding,
            .ping,
            .ack,
            .crypto,
            => true,
            .connection_close => |cc| cc.is_transport,
            else => false,
        };
    }

    pub fn tokenEql(a: [16]u8, b: [16]u8) bool {
        // RFC 9000 §10.3 — stateless reset tokens MUST be compared in
        // constant time. A peer that observes timing differences across
        // mismatching prefixes can incrementally guess valid tokens.
        // Routes through `stateless_reset.eql` so the conformance
        // suite can verify the property against the same code path
        // production callers exercise.
        return stateless_reset_mod.eql(a, b);
    }

    fn statelessResetTokenFromDatagram(bytes: []const u8) ?[16]u8 {
        if (bytes.len < 21) return null;
        if ((bytes[0] & 0x80) != 0) return null;
        var token: [16]u8 = undefined;
        @memcpy(&token, bytes[bytes.len - 16 ..]);
        return token;
    }

    pub fn isKnownStatelessReset(self: *const Connection, bytes: []const u8) bool {
        const token = statelessResetTokenFromDatagram(bytes) orelse return false;
        for (self.peer_cids.items) |item| {
            if (tokenEql(item.stateless_reset_token, token)) return true;
        }
        return false;
    }

    pub fn pathIdAllowedByLocalLimit(self: *Connection, path_id: u32) bool {
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
                const next = _internal.nextLocalCidSequence(self,pcb.path_id);
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

    pub fn peerCidActiveCountForPath(self: *const Connection, path_id: u32) usize {
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

    pub fn registerPeerCid(
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

    pub fn handleNewConnectionId( self: *Connection, nc: frame_types.NewConnectionId, ) Error!void { return conn_recv_cid_token_handlers.handleNewConnectionId(self, nc); }

    /// Returns true (and increments the per-cycle counter) when the
    /// cumulative ACK range count for this `handle` cycle would exceed
    /// `incoming_ack_range_cap`. Skipping rather than closing is RFC
    /// 9000 §19.3-aligned: ACK is not ack-eliciting, dropping it
    /// re-issues no liveness obligation, and the peer's loss-recovery
    /// will retransmit anything we miss.
    pub fn exceedsIncomingAckRangeCap(self: *Connection, range_count: u64) bool {
        const next = self.incoming_ack_range_count +| range_count +| 1;
        if (next > incoming_ack_range_cap) return true;
        self.incoming_ack_range_count = next;
        return false;
    }

    pub fn handleRetireConnectionId( self: *Connection, rc: frame_types.RetireConnectionId, ) void { return conn_recv_cid_token_handlers.handleRetireConnectionId(self, rc); }

    /// RFC 9000 §19.7 — server-issued NEW_TOKEN. The frame is only
    /// legal at application encryption level (filtered upstream by
    /// the level-allowed-frames check). Servers MUST NOT receive
    /// NEW_TOKEN; if a peer-acting-as-server sends it to us we
    /// silently drop the bytes. Clients hand the borrowed slice
    /// straight to the embedder callback if one is installed.
    pub fn handleNewToken(self: *Connection, nt: frame_types.NewToken) void { return conn_recv_cid_token_handlers.handleNewToken(self, nt); }

    pub fn pathAckToAck(pa: frame_types.PathAck) frame_types.Ack { return conn_recv_multipath_handlers.pathAckToAck(pa); }

    pub fn handlePathAck( self: *Connection, pa: frame_types.PathAck, now_us: u64, ) Error!void { return conn_recv_multipath_handlers.handlePathAck(self, pa, now_us); }

    pub fn handlePathAbandon( self: *Connection, pa: frame_types.PathAbandon, now_us: u64, ) void { return conn_recv_multipath_handlers.handlePathAbandon(self, pa, now_us); }

    pub fn handlePathStatus( self: *Connection, ps: frame_types.PathStatus, available: bool, ) void { return conn_recv_multipath_handlers.handlePathStatus(self, ps, available); }

    pub fn handlePathNewConnectionId( self: *Connection, nc: frame_types.PathNewConnectionId, ) Error!void { return conn_recv_multipath_handlers.handlePathNewConnectionId(self, nc); }

    pub fn handlePathRetireConnectionId( self: *Connection, rc: frame_types.PathRetireConnectionId, ) void { return conn_recv_multipath_handlers.handlePathRetireConnectionId(self, rc); }

    pub fn handleMaxPathId(self: *Connection, mp: frame_types.MaxPathId) void { return conn_recv_multipath_handlers.handleMaxPathId(self, mp); }

    pub fn handlePathsBlocked(self: *Connection, pb: frame_types.PathsBlocked) void { return conn_recv_multipath_handlers.handlePathsBlocked(self, pb); }

    pub fn handlePathCidsBlocked(self: *Connection, pcb: frame_types.PathCidsBlocked) void { return conn_recv_multipath_handlers.handlePathCidsBlocked(self, pcb); }

    /// Handle a received ALTERNATIVE_V4_ADDRESS frame
    /// (draft-munizaga-quic-alternative-server-address-00 §6).
    /// Caller has already validated the negotiation gate. Enforces
    /// §6 ¶5 monotonicity: a strictly-greater Status Sequence Number
    /// produces a fresh `ConnectionEvent.alternative_server_address`;
    /// equal-or-lower is dropped (idempotent retransmit / out-of-
    /// order delivery).
    pub fn handleAlternativeAddressV4(
        self: *Connection,
        a: frame_types.AlternativeV4Address,
    ) void {
        if (!self.acceptAltAddrSequence(a.status_sequence_number)) return;
        self.alternative_server_address_events.push(.{ .v4 = .{
            .address = a.address,
            .port = a.port,
            .status_sequence_number = a.status_sequence_number,
            .preferred = a.preferred,
            .retire = a.retire,
        } });
    }

    /// IPv6 sibling of `handleAlternativeAddressV4`. Same monotonicity
    /// rules — V4 and V6 share the §6 ¶5 sequence space.
    pub fn handleAlternativeAddressV6(
        self: *Connection,
        a: frame_types.AlternativeV6Address,
    ) void {
        if (!self.acceptAltAddrSequence(a.status_sequence_number)) return;
        self.alternative_server_address_events.push(.{ .v6 = .{
            .address = a.address,
            .port = a.port,
            .status_sequence_number = a.status_sequence_number,
            .preferred = a.preferred,
            .retire = a.retire,
        } });
    }

    /// True if `seq` is strictly greater than every previously-seen
    /// Status Sequence Number; updates `highest_alternative_address_sequence_seen`
    /// as a side-effect on accept. Older or equal numbers return
    /// false (idempotent retransmit / out-of-order delivery — §6 ¶5
    /// is sender-side).
    fn acceptAltAddrSequence(self: *Connection, seq: u64) bool {
        if (self.highest_alternative_address_sequence_seen) |highest| {
            if (seq <= highest) return false;
        }
        self.highest_alternative_address_sequence_seen = seq;
        return true;
    }

    /// Highest Status Sequence Number this connection has received
    /// across both ALT_*_ADDRESS frame types
    /// (draft-munizaga-quic-alternative-server-address-00 §6 ¶5), or
    /// `null` when no frame has arrived yet. Useful for tests and
    /// embedder-side debugging.
    pub fn highestAlternativeAddressSequenceSeen(self: *const Connection) ?u64 {
        return self.highest_alternative_address_sequence_seen;
    }

    pub fn handleStopSending( self: *Connection, ss: frame_types.StopSending, ) Error!void { return conn_recv_stream_control_handlers.handleStopSending(self, ss); }

    pub fn handleMaxData(self: *Connection, md: frame_types.MaxData) void {
        return conn_recv_flow_handlers.handleMaxData(self, md);
    }

    pub fn handleMaxStreamData(self: *Connection, msd: frame_types.MaxStreamData) void {
        return conn_recv_flow_handlers.handleMaxStreamData(self, msd);
    }

    pub fn handleMaxStreams(self: *Connection, ms: frame_types.MaxStreams) void {
        return conn_recv_flow_handlers.handleMaxStreams(self, ms);
    }

    pub fn handleDataBlocked(self: *Connection, db: frame_types.DataBlocked) void {
        return conn_recv_flow_handlers.handleDataBlocked(self, db);
    }

    pub fn handleStreamDataBlocked(self: *Connection, sdb: frame_types.StreamDataBlocked) Error!void {
        return conn_recv_flow_handlers.handleStreamDataBlocked(self, sdb);
    }

    pub fn handleStreamsBlocked(self: *Connection, sb: frame_types.StreamsBlocked) void {
        return conn_recv_flow_handlers.handleStreamsBlocked(self, sb);
    }

    /// Apply a peer-sent DATAGRAM frame (RFC 9221) to the inbound queue.
    /// Public so per-connection hardening tests can drive the
    /// resident-bytes accounting without crafting encrypted packets;
    /// the production path is `handleOnePacket` → `handleApplication`.
    pub fn handleDatagram(
        self: *Connection,
        lvl: EncryptionLevel,
        dg: frame_types.Datagram,
    ) Error!void {
        const local_max = self.local_transport_params.max_datagram_frame_size;
        if (local_max == 0 or dg.data.len > local_max or dg.data.len > max_supported_udp_payload_size) {
            self.close(true, transport_error_protocol_violation, "datagram exceeds local limit");
            return;
        }
        if (self.pending_frames.recv_datagrams.items.len >= max_pending_datagram_count) {
            self.close(true, transport_error_protocol_violation, "datagram receive queue exhausted");
            return;
        }
        if (dg.data.len > max_pending_datagram_bytes or
            self.pending_frames.recv_datagram_bytes > max_pending_datagram_bytes - dg.data.len)
        {
            self.close(true, transport_error_protocol_violation, "datagram receive budget exhausted");
            return;
        }
        // Hardening guide §3.5 / §8: the inbound DATAGRAM queue and
        // every other peer-controlled buffer share one resident-bytes
        // budget so a peer cannot bypass each per-buffer cap by
        // ballooning many of them at once.
        self.tryReserveResidentBytes(dg.data.len) catch {
            self.close(true, transport_error_excessive_load, "excessive resource use");
            return;
        };
        const copy = self.allocator.alloc(u8, dg.data.len) catch |err| {
            self.releaseResidentBytes(dg.data.len);
            return err;
        };
        errdefer {
            self.releaseResidentBytes(dg.data.len);
            self.allocator.free(copy);
        }
        @memcpy(copy, dg.data);
        try self.pending_frames.recv_datagrams.append(self.allocator, .{
            .data = copy,
            .arrived_in_early_data = lvl == .early_data,
        });
        self.pending_frames.recv_datagram_bytes += dg.data.len;
    }

    /// Apply a peer-sent CRYPTO frame's bytes at the given encryption
    /// level. Public so per-connection hardening tests can drive the
    /// reassembly path without crafting encrypted packets; the
    /// production path is `handleOnePacket` → `handleInitial` etc.
    pub fn handleCrypto(
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
            // Hardening guide §3.5 / §8: reserve from the global
            // resident-bytes budget *before* allocating. The per-level
            // crypto cap above gates a single level; this gates the
            // whole connection (CRYPTO + DATAGRAM + stream buffers
            // sharing one budget so a peer can't open many small
            // buffers and bypass each individual cap).
            self.tryReserveResidentBytes(eff_data.len) catch {
                self.close(true, transport_error_excessive_load, "excessive resource use");
                return;
            };
            const copy = self.allocator.alloc(u8, eff_data.len) catch |err| {
                self.releaseResidentBytes(eff_data.len);
                return err;
            };
            errdefer {
                self.releaseResidentBytes(eff_data.len);
                self.allocator.free(copy);
            }
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
                    self.releaseResidentBytes(chunk.data.len);
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
                    self.releaseResidentBytes(chunk.data.len);
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
        // RFC 9001 §5.7 ¶3 / ¶4: discard Initial keys once handshake
        // confirms. The strict spec timing is "first Handshake packet
        // sent" (client) / "first Handshake packet processed" (server),
        // but in quic_zig's flow the client's first Handshake send is
        // accompanied by an Initial-level ACK that's still needed by
        // the server, so we wait until handshake confirms — at which
        // point no further Initial activity is legitimate. Latched +
        // idempotent.
        if (self.inner.handshakeDone() and !self.initial_keys_discarded) {
            self.discardInitialKeys();
        }
        // RFC 9001 §4.1.2 ¶1 / §4.9.2: the server's "TLS handshake
        // confirmed" event coincides with TLS handshake completion
        // (i.e. processing the client's Finished). The matching key
        // discard runs immediately. The client takes the symmetrical
        // path on receipt of HANDSHAKE_DONE — see the
        // `received_handshake_done` arm in the frame switch above and
        // the `handleWithEcn` post-loop discard.
        if (self.role == .server and self.inner.handshakeDone() and !self.handshake_keys_discarded) {
            self.discardHandshakeKeys();
        }
        try self.refreshEarlyDataStatus();
    }

    /// Apply a peer-sent STREAM frame to the matching stream's recv
    /// reassembly buffer (creating the stream if it is peer-initiated
    /// and not yet seen). Public so per-connection hardening tests can
    /// drive the recv-reassembly path without crafting encrypted
    /// packets; the production path is `handleOnePacket` →
    /// `handleApplication`.
    pub fn handleStream(
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
        // Hardening guide §3.5 / §8: snapshot the recv-buffer length
        // around `recv()` and reconcile the global resident-bytes
        // budget. `RecvStream.recv` may grow its internal buffer to
        // cover [read_offset, frame_end) — the diff captures whatever
        // it actually allocated (overlapping ranges deduplicate, so
        // the diff can be 0 or smaller than `s.data.len`).
        const recv_before = ptr.recv.bytes.items.len;
        ptr.recv.recv(s.offset, s.data, s.fin) catch |err| switch (err) {
            error.BufferLimitExceeded => {
                self.reconcileRecvResidentBytes(ptr, recv_before);
                self.close(true, transport_error_protocol_violation, "stream reassembly exceeds allocation limit");
                return;
            },
            error.BeyondFinalSize, error.FinalSizeChanged => {
                self.reconcileRecvResidentBytes(ptr, recv_before);
                self.close(true, transport_error_final_size, "stream final size changed");
                return;
            },
            else => {
                self.reconcileRecvResidentBytes(ptr, recv_before);
                return err;
            },
        };
        if (ptr.recv.bytes.items.len > recv_before) {
            const grew = ptr.recv.bytes.items.len - recv_before;
            self.tryReserveResidentBytes(grew) catch {
                self.close(true, transport_error_excessive_load, "excessive resource use");
                return;
            };
        } else if (ptr.recv.bytes.items.len < recv_before) {
            self.releaseResidentBytes(recv_before - ptr.recv.bytes.items.len);
        }
        self.peer_sent_stream_data += delta;
    }

    /// Best-effort reconciliation of the resident-bytes counter when
    /// `RecvStream.recv` partially advanced its internal buffer before
    /// returning an error. Releases bytes the recv buffer dropped on
    /// the error path; if the buffer grew, the bytes are conceded to
    /// the running total but the connection is closing immediately so
    /// the over-count never leaks past `tick` / `reap`.
    fn reconcileRecvResidentBytes(self: *Connection, ptr: *Stream, recv_before: usize) void {
        const after = ptr.recv.bytes.items.len;
        if (after < recv_before) {
            self.releaseResidentBytes(recv_before - after);
        }
    }

    pub fn handleResetStream(self: *Connection, rs: frame_types.ResetStream) Error!void { return conn_recv_stream_control_handlers.handleResetStream(self, rs); }

    pub fn handleAckAtLevel( self: *Connection, lvl: EncryptionLevel, a: frame_types.Ack, now_us: u64, ) Error!void { return conn_recv_ack_handlers.handleAckAtLevel(self, lvl, a, now_us); }

    pub fn handleApplicationAckOnPath( self: *Connection, path: *PathState, a: frame_types.Ack, now_us: u64, ) Error!void { return conn_recv_ack_handlers.handleApplicationAckOnPath(self, path, a, now_us); }

    fn dispatchAckedToStreams(self: *Connection, pn: u64) Error!void {
        var s_it = self.streams.iterator();
        while (s_it.next()) |entry| {
            // Snapshot the send-buffer length so we can release the
            // matching budget when the ack advances the stream's
            // contiguous-acked floor (RFC 9000 §3.1: bytes ≤ floor are
            // dropped from the in-memory buffer).
            const before = entry.value_ptr.*.send.bytes.items.len;
            entry.value_ptr.*.send.onPacketAcked(pn) catch |e| switch (e) {
                send_stream_mod.Error.UnknownPacket => {},
                else => return e,
            };
            const after = entry.value_ptr.*.send.bytes.items.len;
            if (after < before) self.releaseResidentBytes(before - after);
        }
    }

    pub fn dispatchAckedPacketToStreams(
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

    pub fn discardSentCryptoForPacket(
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

    pub fn dispatchAckedControlFrames(
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

    pub fn dispatchLostControlFrames( self: *Connection, packet: *const sent_packets_mod.SentPacket, ) Error!bool { return conn_recv_ack_handlers.dispatchLostControlFrames(self, packet); }

    pub fn dispatchLostControlFramesOnPath(
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
                    if (self.pending_frames.path_response == null) {
                        self.queuePathResponseOnPath(path_id, pr.data, null);
                    }
                    any = true;
                },
                .path_challenge => |pc| {
                    if (self.pending_frames.path_challenge == null and
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
                .new_token => |item| {
                    // RFC 9000 §13.3 puts NEW_TOKEN on the
                    // retransmittable list; if the application
                    // hasn't already queued a fresh NEW_TOKEN over
                    // the top, restage the bytes from the lost copy.
                    if (self.pending_frames.new_token == null) {
                        var stage: pending_frames_mod.NewTokenItem = .{};
                        @memcpy(stage.bytes[0..item.len], item.slice());
                        stage.len = item.len;
                        self.pending_frames.new_token = stage;
                        any = true;
                    }
                },
                .alternative_v4_address => |a| {
                    // draft-munizaga-quic-alternative-server-address-00
                    // §6 ¶5: monotonically-increasing Status Sequence
                    // Numbers, but the spec is silent on retransmission.
                    // RFC 9000 §13.3 default applies — control frames
                    // that aren't redundant on receipt MUST be
                    // retransmitted on loss with the same content. The
                    // Status Sequence Number stays attached to the
                    // semantic update (which IPv4 address, what flags),
                    // so the requeued frame keeps its original
                    // sequence number.
                    try self.pending_frames.alternative_addresses.append(
                        self.allocator,
                        .{ .v4 = a },
                    );
                    any = true;
                },
                .alternative_v6_address => |a| {
                    try self.pending_frames.alternative_addresses.append(
                        self.allocator,
                        .{ .v6 = a },
                    );
                    any = true;
                },
            }
        }
        return any;
    }

    pub fn requeueLostPacket(
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

    pub fn isPersistentCongestionFromBasePto(base_pto_us: u64, stats: LossStats) bool {
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

    /// RFC 8899 DPLPMTUD probe-loss handler. If `lost.pn` matches the
    /// in-flight probe on `path`, account it as a probe loss (clears
    /// the probe slot, bumps `pmtu_fail_count`, possibly records the
    /// upper bound) and return true so the caller skips normal
    /// congestion-control processing. RFC 8899 §4.4 explicitly says
    /// probe loss MUST NOT trigger CC reactions.
    fn pmtudHandleProbeLossIfMatches(
        self: *Connection,
        path: *PathState,
        lost: *const sent_packets_mod.SentPacket,
    ) bool {
        const probe_pn = path.pmtu_probe_pn orelse return false;
        if (probe_pn != lost.pn) return false;
        _ = path.pmtudOnProbeLost(self.pmtud_config.probe_threshold);
        return true;
    }

    /// RFC 8899 §4.4 black-hole detection: invoke for every regular
    /// (non-probe) packet declared lost on this path. Increments the
    /// consecutive-regular-loss counter; at the threshold, halves
    /// `pmtu` (down to `initial_mtu`) and re-enters search.
    fn pmtudHandleRegularLoss(self: *Connection, path: *PathState) void {
        if (!self.pmtud_config.enable) return;
        if (path.pmtu_state == .disabled) return;
        _ = path.pmtudOnRegularLost(
            self.pmtud_config.probe_threshold,
            self.pmtud_config.initial_mtu,
        );
    }

    pub fn detectLossesByPacketThresholdAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
    ) Error!void {
        const pn_space = self.pnSpaceForLevel(lvl);
        const sent = self.sentForLevel(lvl);
        const largest_acked_opt = pn_space.largest_acked_sent;
        if (largest_acked_opt == null) return;
        const largest_acked = largest_acked_opt.?;
        const threshold: u64 = loss_recovery_mod.packet_threshold;
        // 1-RTT in-flight bookkeeping is owned by the primary path
        // until the multipath split (per `sentForLevel`). RFC 8899
        // probes only ride .application, so we only consult the
        // probe state when this is the application level.
        const path: *PathState = self.primaryPath();

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < sent.count) {
            const p = sent.packets[i];
            if (p.pn <= largest_acked and (largest_acked - p.pn) >= threshold) {
                var lost = sent.removeAt(i);
                defer lost.deinit(self.allocator);
                self.emitPacketLost(lvl, lost.pn, @intCast(lost.bytes), .packet_threshold);
                const is_probe = lvl == .application and
                    self.pmtudHandleProbeLossIfMatches(path, &lost);
                // Always requeue stream / control frames so a probe
                // that coalesced legitimate payload still progresses.
                _ = try self.requeueLostPacket(lvl, &lost);
                if (is_probe) {
                    // RFC 8899 §4.4: probe loss MUST NOT trigger CC
                    // reactions. Skip the LossStats add so neither
                    // cwnd nor persistent-congestion fires for the
                    // probe's bytes.
                    continue;
                }
                stats.add(lost);
                if (lvl == .application) self.pmtudHandleRegularLoss(path);
                continue;
            }
            i += 1;
        }
        self.qlog_packets_lost +|= stats.count;
        self.emitLossDetected(lvl, stats, .packet_threshold);
        self.onPacketsLostAtLevel(lvl, stats);
        self.emitCongestionStateIfChanged(0);
    }

    pub fn detectLossesByPacketThresholdOnApplicationPath(
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
                self.emitPacketLost(.application, lost.pn, @intCast(lost.bytes), .packet_threshold);
                const is_probe = self.pmtudHandleProbeLossIfMatches(path, &lost);
                _ = try self.requeueLostPacketOnPath(.application, &lost, path.id);
                if (is_probe) continue;
                stats.add(lost);
                self.pmtudHandleRegularLoss(path);
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
        const path: *PathState = self.primaryPath();

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < sent.count) {
            const p = sent.packets[i];
            const eligible = if (largest_acked_opt) |la| p.pn <= la else false;
            if (eligible and p.sent_time_us < cutoff) {
                var lost = sent.removeAt(i);
                defer lost.deinit(self.allocator);
                self.emitPacketLost(lvl, lost.pn, @intCast(lost.bytes), .time_threshold);
                const is_probe = lvl == .application and
                    self.pmtudHandleProbeLossIfMatches(path, &lost);
                _ = try self.requeueLostPacket(lvl, &lost);
                if (is_probe) continue;
                stats.add(lost);
                if (lvl == .application) self.pmtudHandleRegularLoss(path);
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
                self.emitPacketLost(.application, lost.pn, @intCast(lost.bytes), .time_threshold);
                const is_probe = self.pmtudHandleProbeLossIfMatches(path, &lost);
                _ = try self.requeueLostPacketOnPath(.application, &lost, path.id);
                if (is_probe) continue;
                stats.add(lost);
                self.pmtudHandleRegularLoss(path);
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
        const path: *PathState = self.primaryPath();
        var i: u32 = 0;
        while (i < sent.count) : (i += 1) {
            const p = sent.packets[i];
            if (!p.ack_eliciting) continue;

            var lost = sent.removeAt(i);
            defer lost.deinit(self.allocator);
            self.emitPacketLost(lvl, lost.pn, @intCast(lost.bytes), .pto_probe);
            // RFC 8899 §4.4: a probe expired by PTO counts as a probe
            // loss, NOT a regular loss; CC stays unaffected. The
            // requeue path still runs so coalesced control / stream
            // frames go back into the queue.
            const is_probe = lvl == .application and
                self.pmtudHandleProbeLossIfMatches(path, &lost);
            const requeued = try self.requeueLostPacket(lvl, &lost);
            if (is_probe) {
                self.pendingPingForLevel(lvl).* = false;
                self.ptoCountForLevel(lvl).* +|= 1;
                return true;
            }
            var stats: LossStats = .{};
            stats.add(lost);
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
            self.emitPacketLost(.application, lost.pn, @intCast(lost.bytes), .pto_probe);
            const is_probe = self.pmtudHandleProbeLossIfMatches(path, &lost);
            const requeued = try self.requeueLostPacketOnPath(.application, &lost, path.id);
            if (is_probe) {
                path.pending_ping = false;
                path.pto_count +|= 1;
                return true;
            }
            var stats: LossStats = .{};
            stats.add(lost);
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

        if (self.lifecycle.draining_deadline_us) |deadline| {
            if (now_us >= deadline) {
                self.finishDraining();
            }
            return;
        }
        // RFC 9000 §10.2.1 closing-state expiry. The deadline fires at
        // `first_close_emit + 3 * PTO`. If the peer's CC never came
        // back (otherwise we'd already be in draining), fall straight
        // to terminal closed — §10.2 ¶7: "Once its closing or
        // draining state ends, an endpoint SHOULD discard all
        // connection state."
        if (self.lifecycle.closing_deadline_us) |deadline| {
            if (now_us >= deadline) {
                self.finishDraining();
            }
            return;
        }

        if (self.lifecycle.closed) return;

        if (!self.lifecycle.closed) {
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
            // RFC 9001 §4.9.2: a discarded packet number space MUST
            // NOT continue to drive timers. The Initial latch lives
            // in `initial_keys_discarded`; the Handshake latch in
            // `handshake_keys_discarded`. Both are one-way, so the
            // gates below stay consistent with the corresponding
            // `levels[…]` and `sent[…]` shutdown.
            const space_active = switch (lvl) {
                .initial => !self.initial_keys_discarded,
                .handshake => !self.handshake_keys_discarded,
                else => false,
            };
            if (space_active) {
                self.promoteDueAckDelay(&self.pnSpaceForLevel(lvl).received, now_us);
            }
        }
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            self.promoteDueAckDelay(&path.app_pn_space.received, now_us);
        }

        if (!self.initial_keys_discarded) try self.detectLossesByTimeThresholdAtLevel(.initial, now_us);
        if (!self.handshake_keys_discarded) try self.detectLossesByTimeThresholdAtLevel(.handshake, now_us);
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            try self.detectLossesByTimeThresholdOnApplicationPath(path, now_us);
        }

        if (!self.initial_keys_discarded) try self.fireDuePtoAtLevel(.initial, now_us);
        if (!self.handshake_keys_discarded) try self.fireDuePtoAtLevel(.handshake, now_us);
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
// then writes into quic_zig state. The trampolines stay in this module
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
    // RFC 9001 §4.8: "A TLS alert is turned into a QUIC connection
    // error by converting the one-byte alert description into a QUIC
    // error code. The alert description is added to 0x0100 to produce
    // a QUIC error code from the range reserved for CRYPTO_ERROR."
    //
    // Examples: no_application_protocol (0x78) → 0x178,
    // bad_certificate (0x2a) → 0x12a, unknown_ca (0x30) → 0x130.
    //
    // Idempotent: if the connection has already started closing
    // (e.g. from another simultaneous error path), `close` no-ops.
    const quic_error_code: u64 = @as(u64, 0x100) + @as(u64, alert);
    conn.close(true, quic_error_code, "tls alert");
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
//
// All inline tests for state.zig live in src/conn/_state_tests.zig.
// The leading underscore signals "internal to conn/". Including the
// import here ensures the compiler walks the file for `test` blocks
// when this module is compiled in test mode.
comptime {
    _ = @import("_state_tests.zig");
}

