//! nullq — a Zig-first IETF QUIC v1 implementation.
//!
//! See INITIAL_PROMPT.md at the project root for the architecture
//! and phased plan.

const std = @import("std");
const boringssl = @import("boringssl");

/// QUIC v1 wire-format version, per RFC 9000 §15.
pub const QUIC_VERSION_1: u32 = 0x00000001;

/// Public multipath target. Frame/transport behavior follows
/// draft-ietf-quic-multipath-21 until this extension is assigned
/// stable RFC values.
pub const multipath_draft_version: u32 = 21;

/// Pure-Zig wire-format encoders and decoders (varints, packet
/// numbers, headers). No BoringSSL dependency.
pub const wire = @import("wire/root.zig");

/// QUIC frame types and codecs (RFC 9000 §19). Pure Zig.
pub const frame = @import("frame/root.zig");

/// TLS handshake glue specific to QUIC.
pub const tls = @import("tls/root.zig");

/// Per-connection state machine (handshake; later: PN spaces,
/// streams, paths, congestion control).
pub const conn = @import("conn/root.zig");
pub const retry_token = conn.retry_token;

pub const Connection = conn.Connection;
pub const OutgoingDatagram = conn.OutgoingDatagram;
pub const IncomingDatagram = conn.IncomingDatagram;
pub const CloseErrorSpace = conn.CloseErrorSpace;
pub const CloseEvent = conn.CloseEvent;
pub const CloseSource = conn.CloseSource;
pub const CloseState = conn.CloseState;
pub const ConnectionEvent = conn.ConnectionEvent;
pub const ApplicationKeyUpdateLimits = conn.ApplicationKeyUpdateLimits;
pub const ApplicationKeyUpdateStatus = conn.ApplicationKeyUpdateStatus;
pub const QlogCallback = conn.QlogCallback;
pub const QlogEvent = conn.QlogEvent;
pub const QlogEventName = conn.QlogEventName;
pub const KeylogCallback = boringssl.tls.KeylogCallback;
pub const ConnectionIdProvision = conn.ConnectionIdProvision;
pub const PathCidsBlockedInfo = conn.PathCidsBlockedInfo;
pub const TimerDeadline = conn.TimerDeadline;
pub const TimerKind = conn.TimerKind;
pub const PathStats = conn.PathStats;
pub const Scheduler = conn.Scheduler;
pub const Session = conn.Session;
pub const EarlyDataStatus = conn.EarlyDataStatus;
pub const RetryToken = conn.RetryToken;
pub const RetryTokenKey = conn.RetryTokenKey;
pub const RetryTokenValidationResult = conn.RetryTokenValidationResult;

pub fn version() []const u8 {
    return "0.0.0";
}

test {
    _ = wire;
    _ = frame;
    _ = tls;
    _ = conn;
}

test "phase 0: builds and links against boringssl-zig" {
    // Touch boringssl so the link path is exercised.
    const digest = boringssl.crypto.hash.Sha256.hash("nullq");
    try std.testing.expectEqual(@as(usize, 32), digest.len);

    try std.testing.expectEqualStrings("0.0.0", version());
    try std.testing.expectEqual(@as(u32, 1), QUIC_VERSION_1);
}
