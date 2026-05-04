//! nullq.wire — pure-Zig encoders and decoders for the QUIC wire format.
//!
//! Everything in this namespace operates on byte slices and is free of
//! BoringSSL or I/O dependencies. Crypto-aware layers (header
//! protection, AEAD packet protection) live in `wire/protection.zig`
//! and `wire/initial.zig` once those phases land.

pub const varint = @import("varint.zig");
pub const packet_number = @import("packet_number.zig");
pub const header = @import("header.zig");
pub const initial = @import("initial.zig");
pub const protection = @import("protection.zig");
pub const short_packet = @import("short_packet.zig");
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
