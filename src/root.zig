//! quic_zig — a Zig-first IETF QUIC v1 implementation.
//!
//! This module is the public API surface. It re-exports the namespace
//! modules (`wire`, `frame`, `tls`, `conn`, `transport`) plus the
//! commonly-used types and the high-level `Server` convenience
//! wrapper.
//!
//! See `README.md` at the project root for an embed-as-server
//! example and the high-level architecture overview.

const std = @import("std");
const boringssl = @import("boringssl");

/// QUIC v1 wire-format version, per RFC 9000 §15.
pub const QUIC_VERSION_1: u32 = 0x00000001;

/// QUIC v2 wire-format version, per RFC 9368 §3.1. The wire-format
/// differences against v1 are scoped to the Initial-key salt + HKDF
/// labels (§3.3.1 / §3.3.2), the long-header packet-type bit layout
/// (§3.2), and the Retry integrity constants (§3.3.3); short-header
/// packets, frame syntax, and connection-level state are identical.
/// Embedders opt in via `Server.Config.versions` (server) and
/// `Client.Config.preferred_version` (client).
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;

/// Public multipath target. Frame/transport behavior follows
/// draft-ietf-quic-multipath-21 until this extension is assigned
/// stable RFC values.
pub const multipath_draft_version: u32 = 21;

/// Pure-Zig wire-format encoders and decoders (varints, packet
/// numbers, headers). No BoringSSL dependency.
pub const wire = @import("wire/root.zig");

/// QUIC frame types and codecs (RFC 9000 §19). Pure Zig.
pub const frame = @import("frame/root.zig");

/// TLS handshake glue specific to QUIC: encryption levels,
/// transport-parameter codec, and the early-data context builder.
pub const tls = @import("tls/root.zig");

/// Per-connection state machine: streams, paths, congestion control,
/// loss recovery, key updates, multipath. The bulk of quic_zig lives
/// here.
pub const conn = @import("conn/root.zig");

/// Stateless Retry token HMAC helpers. Re-exported under
/// `quic_zig.retry_token` for embedders that want address-bound Retry
/// validation without writing the token format themselves.
pub const retry_token = conn.retry_token;

/// UDP transport plumbing — socket-option tuning today, batch
/// I/O and path-tracking helpers later.
pub const transport = @import("transport/root.zig");

/// High-level convenience wrapper for embedding quic_zig as a QUIC
/// server. Owns the TLS context and a connection table; the
/// embedder still owns the UDP socket and the clock.
pub const Server = @import("server.zig").Server;

/// High-level convenience wrapper for embedding quic_zig as a QUIC
/// client. Mirror to `Server` — owns the TLS context and per-Initial
/// random DCID/SCID generation; the embedder still owns the UDP
/// socket, the clock, and the returned `Connection` lifecycle.
pub const Client = @import("client.zig").Client;

/// The per-connection state machine. See `conn.Connection` for the
/// full method surface (~106 public methods).
pub const Connection = conn.Connection;

/// One emitted UDP datagram as produced by `Connection.pollDatagram`.
/// Carries the byte length, optional destination address (for
/// multipath / migration), and the originating path id.
pub const OutgoingDatagram = conn.OutgoingDatagram;

/// One received DATAGRAM (RFC 9221) the embedder pulled out via
/// `Connection.receiveDatagramInfo`. Carries the byte length and
/// whether it arrived in 0-RTT.
pub const IncomingDatagram = conn.IncomingDatagram;

/// Whether a `CloseEvent` came from a transport-level error or an
/// application-level error (`CONNECTION_CLOSE` frame type 0x1c vs.
/// 0x1d).
pub const CloseErrorSpace = conn.CloseErrorSpace;

/// Sticky descriptor of how a connection ended: source, error
/// space, error code, optional reason phrase, and timestamps.
pub const CloseEvent = conn.CloseEvent;

/// Why a connection closed: local intent, peer-initiated,
/// idle-timeout, stateless-reset, or version-negotiation forced
/// teardown.
pub const CloseSource = conn.CloseSource;

/// Lifecycle stage in the close machinery: open, closing, draining,
/// closed.
pub const CloseState = conn.CloseState;

/// Polled connection-level event: close, flow-blocked, CIDs needed,
/// or DATAGRAM ack/loss notifications.
pub const ConnectionEvent = conn.ConnectionEvent;

/// Embedder-tunable AEAD packet/integrity limits driving application
/// key updates (RFC 9001 §6.6).
pub const ApplicationKeyUpdateLimits = conn.ApplicationKeyUpdateLimits;

/// Snapshot of the current application key-update lifecycle: read
/// epoch, write epoch, packets protected, and discard deadline.
pub const ApplicationKeyUpdateStatus = conn.ApplicationKeyUpdateStatus;

/// Optional per-connection callback used to surface key-update and
/// AEAD-limit events for qlog-style logging or test assertions.
pub const QlogCallback = conn.QlogCallback;

/// One qlog-style observable event delivered through `QlogCallback`.
pub const QlogEvent = conn.QlogEvent;

/// The set of qlog event names quic_zig currently emits.
pub const QlogEventName = conn.QlogEventName;

/// Packet number space for qlog events.
pub const QlogPnSpace = conn.QlogPnSpace;
/// Packet kind classification (long-header type or short-header) for qlog.
pub const QlogPacketKind = conn.QlogPacketKind;
/// Reason a packet was dropped before processing.
pub const QlogPacketDropReason = conn.QlogPacketDropReason;
/// Stream lifecycle state for `stream_state_updated` qlog events.
pub const QlogStreamState = conn.QlogStreamState;
/// Congestion controller state for `congestion_state_updated` qlog events.
pub const QlogCongestionState = conn.QlogCongestionState;
/// Loss-detection reason classification for qlog `loss_detected` events.
pub const QlogLossReason = conn.QlogLossReason;
/// Why a candidate migration path failed (timeout, policy denial).
pub const QlogMigrationFailReason = conn.QlogMigrationFailReason;
/// Embedder policy hook gating peer migrations to a new 4-tuple
/// (RFC 9000 §9). Install via `Connection.setMigrationCallback`.
pub const MigrationCallback = conn.MigrationCallback;
/// Allow / deny verdict returned by a `MigrationCallback`.
pub const MigrationDecision = conn.MigrationDecision;
/// Per-path congestion controller state, exposed via `PathStats`.
pub const CongestionState = conn.CongestionState;

/// TLS keylog callback re-exported from boringssl-zig for SSLKEYLOGFILE
/// debugging.
pub const KeylogCallback = boringssl.tls.KeylogCallback;

/// Embedder-supplied connection ID + stateless-reset token batch
/// used to seed `NEW_CONNECTION_ID` issuance.
pub const ConnectionIdProvision = conn.ConnectionIdProvision;

/// Notification carrying the path id and CID-blocking sequence number
/// when a path runs out of usable peer-issued CIDs.
pub const PathCidsBlockedInfo = conn.PathCidsBlockedInfo;

/// Soonest deadline among all of a connection's timers. Embedders
/// can park their event loop on this until `tick` needs to fire.
pub const TimerDeadline = conn.TimerDeadline;

/// Which timer family produced a `TimerDeadline`.
pub const TimerKind = conn.TimerKind;

/// Read-only snapshot of one path's RTT, congestion, and loss
/// counters.
pub const PathStats = conn.PathStats;

/// Application-data scheduling policy across multiple validated
/// paths (primary, round-robin, lowest-RTT-cwnd).
pub const Scheduler = conn.Scheduler;

/// Captured TLS-1.3 session ticket. Re-export of
/// `boringssl.tls.Session` so embedders can persist tickets without
/// pulling in the BoringSSL namespace.
pub const Session = conn.Session;

/// Snapshot of the BoringSSL early-data status: whether 0-RTT was
/// attempted, accepted, or rejected, and the rejection reason if any.
pub const EarlyDataStatus = conn.EarlyDataStatus;

/// Stateless Retry token (RFC 9000 §17.2.5) produced by
/// `retry_token.create`.
pub const RetryToken = conn.RetryToken;

/// 32-byte HMAC key used to mint and validate stateless Retry tokens.
pub const RetryTokenKey = conn.RetryTokenKey;

/// Outcome of `retry_token.validate`: ok, expired, address mismatch,
/// or malformed.
pub const RetryTokenValidationResult = conn.RetryTokenValidationResult;

pub fn version() []const u8 {
    return "0.0.0";
}

test {
    _ = wire;
    _ = frame;
    _ = tls;
    _ = conn;
    _ = transport;
    _ = @import("server.zig");
    _ = @import("client.zig");
}

test "phase 0: builds and links against boringssl-zig" {
    // Touch boringssl so the link path is exercised.
    const digest = try boringssl.crypto.hash.Sha256.hash("quic_zig");
    try std.testing.expectEqual(@as(usize, 32), digest.len);

    try std.testing.expectEqualStrings("0.0.0", version());
    try std.testing.expectEqual(@as(u32, 1), QUIC_VERSION_1);
    try std.testing.expectEqual(@as(u32, 0x6b3343cf), QUIC_VERSION_2);
}
