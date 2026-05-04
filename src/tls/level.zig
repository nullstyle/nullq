//! QUIC encryption level (RFC 9001 §5).
//!
//! Mirrors `boringssl.tls.quic.EncryptionLevel` 1:1 but lives at the
//! nullq abstraction so connection-state code doesn't have to import
//! the boringssl namespace just to refer to a level.

const boringssl = @import("boringssl");

pub const EncryptionLevel = enum(u8) {
    initial = 0,
    early_data = 1,
    handshake = 2,
    application = 3,

    pub fn fromBoringssl(lvl: boringssl.tls.quic.EncryptionLevel) EncryptionLevel {
        return @enumFromInt(@intFromEnum(lvl));
    }

    pub fn toBoringssl(self: EncryptionLevel) boringssl.tls.quic.EncryptionLevel {
        return @enumFromInt(@intFromEnum(self));
    }

    /// Index for slotted arrays keyed by level.
    pub fn idx(self: EncryptionLevel) usize {
        return @intFromEnum(self);
    }

    /// Map an encryption level to its packet number space (RFC 9000
    /// §12.3). Initial, Handshake, and Application get their own
    /// spaces; 0-RTT (early_data) shares the Application space.
    pub fn pnSpaceIdx(self: EncryptionLevel) usize {
        return switch (self) {
            .initial => 0,
            .handshake => 1,
            .early_data, .application => 2,
        };
    }
};

/// Number of packet number spaces (Initial, Handshake, Application).
pub const pn_space_count: usize = 3;

/// Direction of a derived secret.
pub const Direction = enum(u8) { read, write };

/// All four levels in canonical order. Useful for `inline for` over
/// per-level state.
pub const all = [_]EncryptionLevel{
    .initial,
    .early_data,
    .handshake,
    .application,
};

test "round-trip with boringssl level enum" {
    const std = @import("std");
    inline for (all) |lvl| {
        try std.testing.expectEqual(lvl, EncryptionLevel.fromBoringssl(lvl.toBoringssl()));
    }
}
