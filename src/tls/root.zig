//! nullq.tls — TLS handshake glue specific to QUIC.
//!
//! Thin layer over `boringssl.tls` plus the QUIC-specific bits that
//! don't belong in core TLS:
//!  - `EncryptionLevel` and `Direction` — the QUIC-side view of
//!    `tls.quic.Method` callbacks (Initial / Handshake / Application,
//!    read / write).
//!  - `transport_params` — RFC 9000 §18 + RFC 9221 + draft-21
//!    multipath transport parameter codec.
//!  - `early_data_context` — derived 0-RTT context digest builder
//!    binding ALPN, transport parameters, and an embedder-supplied
//!    application settings string per RFC 9001 §4.6.

/// QUIC encryption level submodule (RFC 9001 §2).
pub const level = @import("level.zig");
/// QUIC transport parameter codec (RFC 9000 §18, RFC 9221, draft-ietf-quic-multipath-21 §11).
pub const transport_params = @import("transport_params.zig");
/// 0-RTT early-data context digest builder (RFC 9001 §4.6.1).
pub const early_data_context = @import("early_data_context.zig");
/// Re-export of `level.EncryptionLevel` — Initial / 0-RTT / Handshake / 1-RTT.
pub const EncryptionLevel = level.EncryptionLevel;
/// Re-export of `level.Direction` — read vs. write side of a derived secret.
pub const Direction = level.Direction;
/// Re-export of `transport_params.Params`, the typed transport-parameter struct.
pub const TransportParams = transport_params.Params;
/// Re-export of `early_data_context.Options` for embedders building the 0-RTT digest.
pub const EarlyDataContextOptions = early_data_context.Options;
/// Re-export of `early_data_context.Digest` (the 32-byte SHA-256 output).
pub const EarlyDataContextDigest = early_data_context.Digest;

test {
    _ = level;
    _ = transport_params;
    _ = early_data_context;
}
