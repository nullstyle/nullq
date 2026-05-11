//! QUIC-LB configuration types (draft-ietf-quic-load-balancers-21).
//!
//! `LbConfig` describes one configuration the server-side stack will use
//! to mint connection IDs that an external layer-4 load balancer can
//! decode to recover the routing identity. It is the static slice of
//! state that lives on `Server.Config`; runtime mint state lives on the
//! `Factory` in `cid.zig`.
//!
//! Per the draft §3 ("Connection ID Format"):
//!   * `config_id` is 0..6 (3 bits). 7 is reserved for the unroutable
//!     fallback CID; embedders never set it directly — `Factory` mints
//!     unroutable CIDs through a separate path.
//!   * `server_id` is 1..15 octets, statically configured per server.
//!   * `nonce_len` is 4..18 octets and must satisfy
//!     `server_id_len + nonce_len <= 19` (leaves room for the leading
//!     first-octet inside QUIC v1's 20-octet CID limit).
//!   * `key` enables encryption: `null` selects the plaintext mode of
//!     §5.2; a 16-byte key selects single-pass AES-128-ECB if
//!     `server_id_len + nonce_len == 16` (§5.4.1) and four-pass Feistel
//!     otherwise (§5.4.2).
//!
//! Validation is centralised in `LbConfig.validate` so the same rule set
//! gates both `Server.init` and standalone `Factory.init` callers.

const std = @import("std");

/// 3-bit configuration rotation identifier. Values 0..6 select an
/// active configuration; value 7 (binary `111`) is reserved by the
/// draft for the unroutable fallback CID and is rejected by
/// `LbConfig.validate`.
pub const ConfigId = u3;

/// Reserved `config_id` value the LB recognises as "no active
/// configuration on this server" (draft §3.1). The LB MUST then route
/// the packet through a fallback path. Server code mints these only
/// through the unroutable helper, never via `LbConfig`.
pub const unroutable_config_id: u8 = 0b111;

/// Maximum permitted `server_id` length (draft §3, "1-15 octets").
pub const max_server_id_len: u8 = 15;

/// Maximum permitted `nonce` length (draft §3, "4-18 octets").
pub const max_nonce_len: u8 = 18;

/// Minimum permitted `nonce` length (draft §3, "4-18 octets").
pub const min_nonce_len: u8 = 4;

/// Combined server-id + nonce length must fit alongside the leading
/// first octet inside the 20-byte QUIC v1 CID limit (RFC 9000 §17.2):
/// `1 + server_id_len + nonce_len <= 20` ⇒ `server_id_len + nonce_len
/// <= 19`.
pub const max_combined_len: u8 = 19;

/// 16-byte AES-128 encryption key selecting an encrypted-mode
/// configuration. `null` on `LbConfig.key` selects plaintext mode.
pub const Key = [16]u8;

/// Errors `LbConfig.validate` can surface.
pub const Error = error{
    /// `config_id` outside the 0..6 active range, or any per-field
    /// length bound violated, or the combined-length cap exceeded.
    InvalidLbConfig,
    /// `server_id` slice was empty or too long for `max_server_id_len`.
    /// Surfaced from `ServerId.fromSlice`.
    InvalidServerId,
};

/// Bounded server identifier. The byte buffer is fixed-size so an
/// `LbConfig` is `Copy` and can live on `Server.Config` without
/// allocator coupling; `len` is the live byte count.
pub const ServerId = struct {
    /// Live byte count, 1..`max_server_id_len`.
    len: u8 = 0,
    /// Fixed-size storage. Bytes past `len` are ignored by the encoder.
    bytes: [max_server_id_len]u8 = @splat(0),

    /// Build a `ServerId` from a caller-owned slice. Rejects empty and
    /// too-long inputs.
    pub fn fromSlice(s: []const u8) Error!ServerId {
        if (s.len < 1 or s.len > max_server_id_len) return Error.InvalidServerId;
        var out: ServerId = .{ .len = @intCast(s.len) };
        @memcpy(out.bytes[0..s.len], s);
        return out;
    }

    /// Constant slice over the live bytes. Stable for the struct's
    /// lifetime.
    pub fn slice(self: *const ServerId) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// One QUIC-LB configuration the server uses to encode CIDs. This is
/// the immutable shape; runtime mint state (counters, draining
/// configurations) lives on the `Factory`.
pub const LbConfig = struct {
    /// Active configuration id, 0..6. `7` is rejected by `validate`.
    config_id: ConfigId,
    /// Routing identity the load balancer will recover from minted
    /// CIDs.
    server_id: ServerId,
    /// Number of nonce bytes, `min_nonce_len..max_nonce_len`.
    nonce_len: u8,
    /// AES-128 key that selects an encrypted mode, or null for the
    /// plaintext mode of draft §5.2. Single-pass and four-pass
    /// encrypted modes are both implemented.
    key: ?Key = null,
    /// When true, the low 5 bits of the first octet hold `cid_len - 1`
    /// so the LB can self-describe the CID length on short headers.
    /// When false, those bits are filled from the CSPRNG (draft §3).
    encode_length: bool = true,

    /// Validate every per-field bound and the cross-field combined
    /// length cap. Cheap; callers `try config.validate()` before doing
    /// anything else with the value.
    pub fn validate(self: *const LbConfig) Error!void {
        // u3 already enforces 0..7; reject only the reserved 7.
        if (@as(u8, self.config_id) > 6) return Error.InvalidLbConfig;
        if (self.server_id.len < 1 or self.server_id.len > max_server_id_len) {
            return Error.InvalidLbConfig;
        }
        if (self.nonce_len < min_nonce_len or self.nonce_len > max_nonce_len) {
            return Error.InvalidLbConfig;
        }
        const combined: usize = @as(usize, self.server_id.len) + @as(usize, self.nonce_len);
        if (combined > max_combined_len) return Error.InvalidLbConfig;
    }

    /// Total CID byte count this configuration mints: 1 first octet +
    /// `server_id_len` + `nonce_len`. Inside 1..20 by construction
    /// (`validate` enforces the per-field and combined bounds).
    pub fn cidLength(self: *const LbConfig) u8 {
        return 1 + self.server_id.len + self.nonce_len;
    }

    /// True iff `key` is null — selects the draft §5.2 plaintext mode,
    /// which writes `server_id || nonce` directly into the CID body.
    pub fn isPlaintext(self: *const LbConfig) bool {
        return self.key == null;
    }
};

// -- tests ---------------------------------------------------------------

const testing = std.testing;

test "ServerId.fromSlice rejects empty" {
    try testing.expectError(Error.InvalidServerId, ServerId.fromSlice(&.{}));
}

test "ServerId.fromSlice rejects oversize" {
    var oversize: [max_server_id_len + 1]u8 = @splat(0xaa);
    try testing.expectError(Error.InvalidServerId, ServerId.fromSlice(&oversize));
}

test "ServerId.fromSlice copies bytes and reports length" {
    const sid = try ServerId.fromSlice(&.{ 1, 2, 3 });
    try testing.expectEqual(@as(u8, 3), sid.len);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, sid.slice());
}

test "LbConfig.validate rejects reserved config_id 7" {
    const cfg: LbConfig = .{
        .config_id = 0b111,
        .server_id = try ServerId.fromSlice(&.{0xaa}),
        .nonce_len = 4,
    };
    try testing.expectError(Error.InvalidLbConfig, cfg.validate());
}

test "LbConfig.validate rejects nonce_len out of bounds" {
    const sid = try ServerId.fromSlice(&.{0xaa});
    var cfg: LbConfig = .{ .config_id = 0, .server_id = sid, .nonce_len = 3 };
    try testing.expectError(Error.InvalidLbConfig, cfg.validate());
    cfg.nonce_len = 19;
    try testing.expectError(Error.InvalidLbConfig, cfg.validate());
}

test "LbConfig.validate rejects combined > 19" {
    const sid_bytes: [15]u8 = @splat(0xaa);
    const sid = try ServerId.fromSlice(&sid_bytes);
    const cfg: LbConfig = .{ .config_id = 0, .server_id = sid, .nonce_len = 5 };
    try testing.expectError(Error.InvalidLbConfig, cfg.validate());
}

test "LbConfig.cidLength includes leading first octet" {
    const cfg: LbConfig = .{
        .config_id = 2,
        .server_id = try ServerId.fromSlice(&.{ 0xa, 0xb, 0xc, 0xd }),
        .nonce_len = 8,
    };
    try cfg.validate();
    try testing.expectEqual(@as(u8, 1 + 4 + 8), cfg.cidLength());
}

test "LbConfig.isPlaintext follows key presence" {
    const sid = try ServerId.fromSlice(&.{ 0xa, 0xb });
    const plain: LbConfig = .{ .config_id = 0, .server_id = sid, .nonce_len = 4 };
    try testing.expect(plain.isPlaintext());

    const keyed: LbConfig = .{
        .config_id = 0,
        .server_id = sid,
        .nonce_len = 4,
        .key = @splat(0x42),
    };
    try testing.expect(!keyed.isPlaintext());
}
