//! quic_zig.wire — pure-Zig encoders and decoders for the QUIC wire format.
//!
//! Everything here is byte-slice in / byte-slice out and free of
//! BoringSSL, I/O, or allocator dependencies. The few crypto-touching
//! pieces (header protection, AEAD packet protection, Initial-key
//! derivation) wrap BoringSSL primitives but stay confined to the
//! `protection`, `initial`, `short_packet`, and `long_packet`
//! submodules so the rest can be exercised in tight unit tests.
//!
//! Submodules:
//!  - `varint` — RFC 9000 §16 variable-length integers.
//!  - `packet_number` — RFC 9000 §17.1 truncation/expansion.
//!  - `header` — long/short-header parse/encode + variant types.
//!  - `initial`, `protection`, `short_packet`, `long_packet` —
//!    AEAD-aware packet protection, including Retry integrity.

/// RFC 9000 §16 variable-length integer encoding.
pub const varint = @import("varint.zig");
/// RFC 9000 §17.1 packet-number truncation and recovery.
pub const packet_number = @import("packet_number.zig");
/// QUIC v1 long- and short-header parse/encode plus variant types.
pub const header = @import("header.zig");
/// RFC 9001 §5.2 Initial-key derivation and HKDF-Expand-Label helper.
pub const initial = @import("initial.zig");
/// AEAD packet protection and header-protection masks (RFC 9001 §5).
pub const protection = @import("protection.zig");
/// 1-RTT short-header packet seal/open.
pub const short_packet = @import("short_packet.zig");
/// Initial / 0-RTT / Handshake / Retry long-header packet seal/open.
pub const long_packet = @import("long_packet.zig");

test {
    _ = varint;
    _ = packet_number;
    _ = header;
    _ = initial;
    _ = protection;
    _ = short_packet;
    _ = long_packet;
}
