//! nullq.conn — per-connection state machine.
//!
//! The bulk of nullq lives here: the `Connection` type itself
//! (handshake driving, packet protection, streams, datagrams,
//! migration, multipath, key updates) and its supporting subsystems
//! split across submodules.
//!
//! Submodules:
//!  - `state` — the `Connection` state machine; ~106 public methods
//!    spanning bind/handshake, send/receive, stream open/close,
//!    multipath, close + draining, and event polling.
//!  - `ack_tracker` / `pn_space` / `sent_packets` — packet-number
//!    bookkeeping that drives ACK emission and loss detection.
//!  - `rtt` / `congestion` / `loss_recovery` — RFC 9002 recovery
//!    and NewReno congestion control.
//!  - `flow_control` — stream and connection MAX_DATA accounting.
//!  - `path` / `path_validator` — multipath, migration, and
//!    PATH_CHALLENGE/PATH_RESPONSE validation.
//!  - `send_stream` / `recv_stream` — half-stream send/receive
//!    state and reassembly.
//!  - `retry_token` — stateless Retry token HMAC helpers.
//!  - `pending_frames` — owns the pending control-frame queues
//!    (MAX_DATA, MAX_STREAM_DATA, STOP_SENDING, NEW_CONNECTION_ID,
//!    PATH_CHALLENGE/PATH_RESPONSE, multipath bookkeeping, DATAGRAMs)
//!    that `Connection` drains in `pollLevel`.

/// Connection state machine: handshake, send/receive, streams, migration, close.
pub const state = @import("state.zig");
/// Pending control-frame queues drained by `Connection.pollLevel`.
pub const pending_frames = @import("pending_frames.zig");
/// RFC 9000 §13.2 received-PN range bookkeeping for ACK frame generation.
pub const ack_tracker = @import("ack_tracker.zig");
/// QUIC packet number spaces (RFC 9000 §12.3): Initial / Handshake / Application.
pub const pn_space = @import("pn_space.zig");
/// RFC 9002 §5 round-trip-time estimator.
pub const rtt = @import("rtt.zig");
/// RFC 9002 §A.1 per-PN-space sent-packet tracker.
pub const sent_packets = @import("sent_packets.zig");
/// RFC 9002 §7 + Appendix B NewReno congestion control.
pub const congestion = @import("congestion.zig");
/// RFC 9002 §6 ACK processing and loss detection primitives.
pub const loss_recovery = @import("loss_recovery.zig");
/// RFC 9000 §4 connection-, stream-, and stream-count flow control.
pub const flow_control = @import("flow_control.zig");
/// RFC 9000 §8.2 PATH_CHALLENGE/PATH_RESPONSE state machine.
pub const path_validator = @import("path_validator.zig");
/// RFC 9000 §3.1 send-side stream buffer and FIN/RESET handling.
pub const send_stream = @import("send_stream.zig");
/// RFC 9000 §3.2 receive-side stream reassembly and RESET handling.
pub const recv_stream = @import("recv_stream.zig");
/// Per-path 4-tuple bundle: CIDs, anti-amp, validation, RTT, congestion.
pub const path = @import("path.zig");
/// RFC 9000 §8.1.2 stateless Retry token mint/validate.
pub const retry_token = @import("retry_token.zig");

/// Top-level QUIC connection state machine (RFC 9000).
pub const Connection = state.Connection;
/// One UDP datagram queued for transmission with destination metadata.
pub const OutgoingDatagram = state.OutgoingDatagram;
/// One UDP datagram delivered from the network with source metadata.
pub const IncomingDatagram = state.IncomingDatagram;
/// Which error namespace a CONNECTION_CLOSE belongs to (transport vs application).
pub const CloseErrorSpace = state.CloseErrorSpace;
/// Connection-close event surfaced to the application.
pub const CloseEvent = state.CloseEvent;
/// Origin of a CONNECTION_CLOSE (local, peer, or idle timeout).
pub const CloseSource = state.CloseSource;
/// Phase of the close handshake (closing, draining, etc.).
pub const CloseState = state.CloseState;
/// Tagged event surfaced from `Connection.poll`.
pub const ConnectionEvent = state.ConnectionEvent;
/// Outcome of a `sendDatagram` call (queued, blocked, lost).
pub const DatagramSendEvent = state.DatagramSendEvent;
/// Detail about why outgoing data is blocked on flow control.
pub const FlowBlockedInfo = state.FlowBlockedInfo;
/// Which kind of flow-control limit is blocking (data, stream-data, streams).
pub const FlowBlockedKind = state.FlowBlockedKind;
/// Whether the local or remote side is the limit holder.
pub const FlowBlockedSource = state.FlowBlockedSource;
/// Limits configuring the 1-RTT key-update policy.
pub const ApplicationKeyUpdateLimits = state.ApplicationKeyUpdateLimits;
/// Outcome of a key-update attempt (initiated, blocked, completed).
pub const ApplicationKeyUpdateStatus = state.ApplicationKeyUpdateStatus;
/// Optional callback for emitting qlog events (RFC 9001/draft-ietf-quic-qlog).
pub const QlogCallback = state.QlogCallback;
/// One qlog-formatted event payload.
pub const QlogEvent = state.QlogEvent;
/// qlog event name discriminator.
pub const QlogEventName = state.QlogEventName;
/// qlog packet number space tag.
pub const QlogPnSpace = state.QlogPnSpace;
/// qlog packet-kind tag (initial, handshake, 1-RTT, etc.).
pub const QlogPacketKind = state.QlogPacketKind;
/// qlog reason a packet was dropped at receive time.
pub const QlogPacketDropReason = state.QlogPacketDropReason;
/// qlog stream lifecycle state for stream events.
pub const QlogStreamState = state.QlogStreamState;
/// qlog congestion-control phase tag.
pub const QlogCongestionState = state.QlogCongestionState;
/// qlog reason a packet was declared lost.
pub const QlogLossReason = state.QlogLossReason;
/// Phase of the per-path congestion controller (slow-start, recovery, etc.).
pub const CongestionState = path.CongestionState;
/// How a new connection ID was provisioned (initial, server-assigned, user-assigned).
pub const ConnectionIdProvision = state.ConnectionIdProvision;
/// Detail about which path is blocked on CID supply.
pub const PathCidsBlockedInfo = state.PathCidsBlockedInfo;
/// Next firing of a connection timer (idle, PTO, key-update, etc.).
pub const TimerDeadline = state.TimerDeadline;
/// Discriminator for the kind of timer in a `TimerDeadline`.
pub const TimerKind = state.TimerKind;
/// Connection role: client or server.
pub const Role = state.Role;
/// TLS session handle wrapping the BoringSSL `SSL` object.
pub const Session = state.Session;
/// Outcome of 0-RTT early-data on this connection (accepted, rejected, none).
pub const EarlyDataStatus = state.EarlyDataStatus;
/// RFC 9000 §13.2 received-PN range bookkeeping (re-export).
pub const AckTracker = ack_tracker.AckTracker;
/// One QUIC packet number space (re-export).
pub const PnSpace = pn_space.PnSpace;
/// RFC 9002 §5 RTT estimator (re-export).
pub const RttEstimator = rtt.RttEstimator;
/// RFC 9002 §A.1 sent-packet tracker (re-export).
pub const SentPacketTracker = sent_packets.SentPacketTracker;
/// RFC 9002 NewReno congestion controller (re-export).
pub const NewReno = congestion.NewReno;
/// RFC 9000 §8.2 path-validation state machine (re-export).
pub const PathValidator = path_validator.PathValidator;
/// Send-side half-stream (re-export).
pub const SendStream = send_stream.SendStream;
/// Receive-side half-stream (re-export).
pub const RecvStream = recv_stream.RecvStream;
/// One QUIC path (4-tuple + CIDs + anti-amp + validator + CC).
pub const Path = path.Path;
/// Collection of paths per connection plus scheduling cursor.
pub const PathSet = path.PathSet;
/// Per-path connection state (multipath PN space, CIDs, recovery).
pub const PathState = path.PathState;
/// Snapshot of per-path observability counters.
pub const PathStats = path.PathStats;
/// Multipath scheduling policy (primary / round-robin / lowest-RTT-cwnd).
pub const Scheduler = path.Scheduler;
/// 32-byte stateless Retry token (re-export).
pub const RetryToken = retry_token.Token;
/// 32-byte HMAC-SHA256 key for Retry token mint/validate (re-export).
pub const RetryTokenKey = retry_token.Key;
/// Outcome of `retry_token.validate` (valid, expired, invalid, etc.).
pub const RetryTokenValidationResult = retry_token.ValidationResult;

test {
    _ = state;
    _ = ack_tracker;
    _ = pn_space;
    _ = rtt;
    _ = sent_packets;
    _ = congestion;
    _ = loss_recovery;
    _ = flow_control;
    _ = path_validator;
    _ = send_stream;
    _ = recv_stream;
    _ = path;
    _ = retry_token;
    _ = pending_frames;
}
