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

pub const state = @import("state.zig");
pub const ack_tracker = @import("ack_tracker.zig");
pub const pn_space = @import("pn_space.zig");
pub const rtt = @import("rtt.zig");
pub const sent_packets = @import("sent_packets.zig");
pub const congestion = @import("congestion.zig");
pub const loss_recovery = @import("loss_recovery.zig");
pub const flow_control = @import("flow_control.zig");
pub const path_validator = @import("path_validator.zig");
pub const send_stream = @import("send_stream.zig");
pub const recv_stream = @import("recv_stream.zig");
pub const path = @import("path.zig");
pub const retry_token = @import("retry_token.zig");

pub const Connection = state.Connection;
pub const OutgoingDatagram = state.OutgoingDatagram;
pub const IncomingDatagram = state.IncomingDatagram;
pub const CloseErrorSpace = state.CloseErrorSpace;
pub const CloseEvent = state.CloseEvent;
pub const CloseSource = state.CloseSource;
pub const CloseState = state.CloseState;
pub const ConnectionEvent = state.ConnectionEvent;
pub const DatagramSendEvent = state.DatagramSendEvent;
pub const FlowBlockedInfo = state.FlowBlockedInfo;
pub const FlowBlockedKind = state.FlowBlockedKind;
pub const FlowBlockedSource = state.FlowBlockedSource;
pub const ApplicationKeyUpdateLimits = state.ApplicationKeyUpdateLimits;
pub const ApplicationKeyUpdateStatus = state.ApplicationKeyUpdateStatus;
pub const QlogCallback = state.QlogCallback;
pub const QlogEvent = state.QlogEvent;
pub const QlogEventName = state.QlogEventName;
pub const ConnectionIdProvision = state.ConnectionIdProvision;
pub const PathCidsBlockedInfo = state.PathCidsBlockedInfo;
pub const TimerDeadline = state.TimerDeadline;
pub const TimerKind = state.TimerKind;
pub const Role = state.Role;
pub const Session = state.Session;
pub const EarlyDataStatus = state.EarlyDataStatus;
pub const AckTracker = ack_tracker.AckTracker;
pub const PnSpace = pn_space.PnSpace;
pub const RttEstimator = rtt.RttEstimator;
pub const SentPacketTracker = sent_packets.SentPacketTracker;
pub const NewReno = congestion.NewReno;
pub const PathValidator = path_validator.PathValidator;
pub const SendStream = send_stream.SendStream;
pub const RecvStream = recv_stream.RecvStream;
pub const Path = path.Path;
pub const PathSet = path.PathSet;
pub const PathState = path.PathState;
pub const PathStats = path.PathStats;
pub const Scheduler = path.Scheduler;
pub const RetryToken = retry_token.Token;
pub const RetryTokenKey = retry_token.Key;
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
}
