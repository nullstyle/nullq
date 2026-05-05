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

pub const level = @import("level.zig");
pub const transport_params = @import("transport_params.zig");
pub const early_data_context = @import("early_data_context.zig");
pub const EncryptionLevel = level.EncryptionLevel;
pub const Direction = level.Direction;
pub const TransportParams = transport_params.Params;
pub const EarlyDataContextOptions = early_data_context.Options;
pub const EarlyDataContextDigest = early_data_context.Digest;

test {
    _ = level;
    _ = transport_params;
    _ = early_data_context;
}
