//! nullq.tls — TLS handshake glue specific to QUIC.
//!
//! Mostly thin wrappers over `boringssl.tls`, plus types like
//! `EncryptionLevel` and (later) the transport_parameters codec
//! and the early_data_context builder.

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
