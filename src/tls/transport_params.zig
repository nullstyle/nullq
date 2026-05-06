//! QUIC transport parameters (RFC 9000 §18 + RFC 9221).
//!
//! Transport parameters are a sequence of `(id, length, value)`
//! triples where each component is a QUIC varint (the value is
//! itself either a varint, a fixed-size byte string, or a
//! zero-length flag depending on the parameter id).
//!
//! Both endpoints encode their parameters as one opaque blob and
//! ship it to BoringSSL via `Conn.setQuicTransportParams`. The peer
//! receives them via `Conn.peerQuicTransportParams`. This module
//! provides a typed `Params` struct plus `encode` / `decode` so
//! callers don't have to push raw bytes through.

const std = @import("std");
const varint = @import("../wire/varint.zig");
const path_mod = @import("../conn/path.zig");

/// QUIC connection ID type — re-exported from `conn/path` so
/// transport-parameter callers don't have to import the path module
/// just to construct a CID.
pub const ConnectionId = path_mod.ConnectionId;

/// Multipath QUIC draft version targeted by nullq's public API.
pub const multipath_draft_version: u32 = 21;

/// IANA Transport Parameter Registry — RFC 9000 §18.2 + RFC 9221.
pub const Id = struct {
    /// Per RFC 9000 §18.2 — `original_destination_connection_id` (server-only echo of client's first DCID).
    pub const original_destination_connection_id: u64 = 0x00;
    /// Per RFC 9000 §18.2 — `max_idle_timeout` (ms; 0 disables).
    pub const max_idle_timeout: u64 = 0x01;
    /// Per RFC 9000 §18.2 — `stateless_reset_token` (server-only, 16 bytes).
    pub const stateless_reset_token: u64 = 0x02;
    /// Per RFC 9000 §18.2 — `max_udp_payload_size`.
    pub const max_udp_payload_size: u64 = 0x03;
    /// Per RFC 9000 §18.2 — `initial_max_data` (connection-level flow control).
    pub const initial_max_data: u64 = 0x04;
    /// Per RFC 9000 §18.2 — `initial_max_stream_data_bidi_local`.
    pub const initial_max_stream_data_bidi_local: u64 = 0x05;
    /// Per RFC 9000 §18.2 — `initial_max_stream_data_bidi_remote`.
    pub const initial_max_stream_data_bidi_remote: u64 = 0x06;
    /// Per RFC 9000 §18.2 — `initial_max_stream_data_uni`.
    pub const initial_max_stream_data_uni: u64 = 0x07;
    /// Per RFC 9000 §18.2 — `initial_max_streams_bidi`.
    pub const initial_max_streams_bidi: u64 = 0x08;
    /// Per RFC 9000 §18.2 — `initial_max_streams_uni`.
    pub const initial_max_streams_uni: u64 = 0x09;
    /// Per RFC 9000 §18.2 — `ack_delay_exponent`.
    pub const ack_delay_exponent: u64 = 0x0a;
    /// Per RFC 9000 §18.2 — `max_ack_delay` (ms).
    pub const max_ack_delay: u64 = 0x0b;
    /// Per RFC 9000 §18.2 — `disable_active_migration` (zero-length flag).
    pub const disable_active_migration: u64 = 0x0c;
    /// Per RFC 9000 §18.2 — `preferred_address` (server-only).
    pub const preferred_address: u64 = 0x0d;
    /// Per RFC 9000 §18.2 — `active_connection_id_limit`.
    pub const active_connection_id_limit: u64 = 0x0e;
    /// Per RFC 9000 §18.2 — `initial_source_connection_id`.
    pub const initial_source_connection_id: u64 = 0x0f;
    /// Per RFC 9000 §18.2 — `retry_source_connection_id` (server-only).
    pub const retry_source_connection_id: u64 = 0x10;
    /// RFC 9221 §3
    pub const max_datagram_frame_size: u64 = 0x20;
    /// draft-ietf-quic-multipath-21 §2.1
    pub const initial_max_path_id: u64 = 0x3e;
};

/// Errors returned by `Params.encode` and `Params.decode`.
///
/// `BufferTooSmall` — encode buffer too short for the emitted blob.
/// `DuplicateParameter` — RFC 9000 §18 forbids repeating an id.
/// `UnknownLength` / `ValueTooLarge` — value field outside the
/// representable varint range.
/// `InvalidValue` — RFC-mandated bounds violated (e.g. `ack_delay_exponent > 20`,
/// `active_connection_id_limit < 2`, malformed `preferred_address`).
pub const Error = error{
    BufferTooSmall,
    DuplicateParameter,
    UnknownLength,
    ValueTooLarge,
    InvalidValue,
} || varint.Error;

/// Typed view of the QUIC transport parameters blob exchanged
/// during the handshake (RFC 9000 §18, RFC 9221, draft-ietf-quic-multipath-21).
/// Each field corresponds to one IANA-registered parameter id;
/// `encode` emits only non-default values and `decode` accepts an
/// arbitrary ordering with unknown ids skipped.
pub const Params = struct {
    /// 0x00 — server-only echo of the client's first-Initial DCID.
    /// Required on server transport params (RFC 9000 §7.3); the client
    /// validates the echo to detect off-path injection.
    original_destination_connection_id: ?ConnectionId = null,

    /// 0x01 — idle timeout in milliseconds. 0 disables the timer.
    max_idle_timeout_ms: u64 = 0,

    /// 0x02 — server-only 16-byte stateless reset token.
    stateless_reset_token: ?[16]u8 = null,

    /// 0x03 — max UDP payload the endpoint accepts. RFC default 65527
    /// (effectively unbounded). The wire codec only emits non-default
    /// values.
    max_udp_payload_size: u64 = 65527,

    /// 0x04 — connection-level flow-control limit on incoming bytes.
    initial_max_data: u64 = 0,

    /// 0x05 — initial max data for client-initiated bidi streams
    /// receive side at this endpoint.
    initial_max_stream_data_bidi_local: u64 = 0,
    /// 0x06 — initial max data for peer-initiated bidi streams
    /// receive side at this endpoint.
    initial_max_stream_data_bidi_remote: u64 = 0,
    /// 0x07 — initial max data for unidirectional streams.
    initial_max_stream_data_uni: u64 = 0,

    /// 0x08 — max number of bidi streams the peer may open.
    initial_max_streams_bidi: u64 = 0,
    /// 0x09 — max number of uni streams the peer may open.
    initial_max_streams_uni: u64 = 0,

    /// 0x0a — RFC 9000 §13.2.5: encodes ack_delay scaling. RFC default 3.
    ack_delay_exponent: u64 = 3,
    /// 0x0b — max time before peer must send ACK, in ms. RFC default 25.
    max_ack_delay_ms: u64 = 25,

    /// 0x0c — zero-length flag.
    disable_active_migration: bool = false,

    /// 0x0d — server-only preferred address for clients that support
    /// migration (RFC 9000 §18.2). The codec keeps the complete wire
    /// structure so embedders can advertise or inspect it without
    /// treating the parameter as an opaque extension.
    preferred_address: ?PreferredAddress = null,

    /// 0x0e — number of CIDs the peer is willing to store. Min 2; default 2.
    active_connection_id_limit: u64 = 2,
    /// 0x0f — SCID echoed by the endpoint on its first Initial.
    initial_source_connection_id: ?ConnectionId = null,
    /// 0x10 — server-only: SCID from the Retry packet, if Retry was sent.
    retry_source_connection_id: ?ConnectionId = null,

    /// 0x20 — RFC 9221: max datagram frame size accepted. 0 = no DATAGRAM support.
    max_datagram_frame_size: u64 = 0,

    /// 0x3e — draft-ietf-quic-multipath-21: maximum path ID this
    /// endpoint is willing to maintain at connection initiation.
    /// Null means multipath was not advertised; a value of 0 still
    /// advertises the extension but allows no extra paths yet.
    initial_max_path_id: ?u32 = null,

    /// Serialize `self` into `dst`. Only non-default fields are
    /// emitted; the resulting blob is the same shape regardless of
    /// whether the sender is client or server.
    pub fn encode(self: Params, dst: []u8) Error!usize {
        var pos: usize = 0;
        if (self.original_destination_connection_id) |cid| {
            pos += try writeBytes(dst, pos, Id.original_destination_connection_id, cid.slice());
        }
        if (self.max_idle_timeout_ms != 0) {
            pos += try writeVarint(dst, pos, Id.max_idle_timeout, self.max_idle_timeout_ms);
        }
        if (self.stateless_reset_token) |tok| {
            pos += try writeBytes(dst, pos, Id.stateless_reset_token, &tok);
        }
        if (self.max_udp_payload_size != 65527) {
            pos += try writeVarint(dst, pos, Id.max_udp_payload_size, self.max_udp_payload_size);
        }
        if (self.initial_max_data != 0) {
            pos += try writeVarint(dst, pos, Id.initial_max_data, self.initial_max_data);
        }
        if (self.initial_max_stream_data_bidi_local != 0) {
            pos += try writeVarint(dst, pos, Id.initial_max_stream_data_bidi_local, self.initial_max_stream_data_bidi_local);
        }
        if (self.initial_max_stream_data_bidi_remote != 0) {
            pos += try writeVarint(dst, pos, Id.initial_max_stream_data_bidi_remote, self.initial_max_stream_data_bidi_remote);
        }
        if (self.initial_max_stream_data_uni != 0) {
            pos += try writeVarint(dst, pos, Id.initial_max_stream_data_uni, self.initial_max_stream_data_uni);
        }
        if (self.initial_max_streams_bidi != 0) {
            pos += try writeVarint(dst, pos, Id.initial_max_streams_bidi, self.initial_max_streams_bidi);
        }
        if (self.initial_max_streams_uni != 0) {
            pos += try writeVarint(dst, pos, Id.initial_max_streams_uni, self.initial_max_streams_uni);
        }
        if (self.ack_delay_exponent != 3) {
            pos += try writeVarint(dst, pos, Id.ack_delay_exponent, self.ack_delay_exponent);
        }
        if (self.max_ack_delay_ms != 25) {
            pos += try writeVarint(dst, pos, Id.max_ack_delay, self.max_ack_delay_ms);
        }
        if (self.disable_active_migration) {
            pos += try writeFlag(dst, pos, Id.disable_active_migration);
        }
        if (self.preferred_address) |addr| {
            pos += try writePreferredAddress(dst, pos, addr);
        }
        if (self.active_connection_id_limit != 2) {
            pos += try writeVarint(dst, pos, Id.active_connection_id_limit, self.active_connection_id_limit);
        }
        if (self.initial_source_connection_id) |cid| {
            pos += try writeBytes(dst, pos, Id.initial_source_connection_id, cid.slice());
        }
        if (self.retry_source_connection_id) |cid| {
            pos += try writeBytes(dst, pos, Id.retry_source_connection_id, cid.slice());
        }
        if (self.max_datagram_frame_size != 0) {
            pos += try writeVarint(dst, pos, Id.max_datagram_frame_size, self.max_datagram_frame_size);
        }
        if (self.initial_max_path_id) |max_path_id| {
            pos += try writeVarint(dst, pos, Id.initial_max_path_id, max_path_id);
        }
        return pos;
    }

    /// Parse a transport-parameters blob. Unknown parameter ids are
    /// silently ignored per RFC 9000 §18 (allows forward extension
    /// without breaking interop).
    pub fn decode(src: []const u8) Error!Params {
        var p: Params = .{};
        var pos: usize = 0;
        while (pos < src.len) {
            const param_start = pos;
            const id_d = try varint.decode(src[pos..]);
            pos += id_d.bytes_read;
            const len_d = try varint.decode(src[pos..]);
            pos += len_d.bytes_read;
            if (len_d.value > src.len - pos) return Error.InvalidValue;
            const value_len: usize = @intCast(len_d.value);
            const value = src[pos .. pos + value_len];
            pos += value_len;
            if (try hasParameterId(src[0..param_start], id_d.value)) {
                return Error.DuplicateParameter;
            }
            try setOne(&p, id_d.value, value);
        }
        return p;
    }
};

/// Decoded `preferred_address` transport parameter (RFC 9000 §18.2).
/// All six wire fields are preserved so embedders can advertise or
/// inspect server-side migration hints without treating the value
/// as opaque.
pub const PreferredAddress = struct {
    ipv4_address: [4]u8 = @splat(0),
    ipv4_port: u16 = 0,
    ipv6_address: [16]u8 = @splat(0),
    ipv6_port: u16 = 0,
    connection_id: ConnectionId = .{},
    stateless_reset_token: [16]u8 = @splat(0),
};

fn writeVarint(dst: []u8, pos: usize, id: u64, value: u64) Error!usize {
    var written: usize = 0;
    if (dst.len < pos) return Error.BufferTooSmall;
    written += try varint.encode(dst[pos..], id);
    const value_len = varint.encodedLen(value);
    if (value_len == 0) return Error.ValueTooLarge;
    written += try varint.encode(dst[pos + written ..], value_len);
    written += try varint.encode(dst[pos + written ..], value);
    return written;
}

fn writeBytes(dst: []u8, pos: usize, id: u64, bytes: []const u8) Error!usize {
    var written: usize = 0;
    written += try varint.encode(dst[pos..], id);
    written += try varint.encode(dst[pos + written ..], bytes.len);
    if (dst.len < pos + written + bytes.len) return Error.BufferTooSmall;
    @memcpy(dst[pos + written .. pos + written + bytes.len], bytes);
    written += bytes.len;
    return written;
}

fn writeFlag(dst: []u8, pos: usize, id: u64) Error!usize {
    var written: usize = 0;
    written += try varint.encode(dst[pos..], id);
    written += try varint.encode(dst[pos + written ..], 0);
    return written;
}

fn writePreferredAddress(dst: []u8, pos: usize, addr: PreferredAddress) Error!usize {
    const cid_len = addr.connection_id.len;
    const value_len: usize = 4 + 2 + 16 + 2 + 1 + cid_len + 16;
    var written: usize = 0;
    written += try varint.encode(dst[pos..], Id.preferred_address);
    written += try varint.encode(dst[pos + written ..], value_len);
    if (dst.len < pos + written + value_len) return Error.BufferTooSmall;

    const value_start = pos + written;
    @memcpy(dst[value_start .. value_start + 4], &addr.ipv4_address);
    std.mem.writeInt(u16, dst[value_start + 4 ..][0..2], addr.ipv4_port, .big);
    @memcpy(dst[value_start + 6 .. value_start + 22], &addr.ipv6_address);
    std.mem.writeInt(u16, dst[value_start + 22 ..][0..2], addr.ipv6_port, .big);
    dst[value_start + 24] = cid_len;
    @memcpy(dst[value_start + 25 .. value_start + 25 + cid_len], addr.connection_id.slice());
    @memcpy(dst[value_start + 25 + cid_len .. value_start + 41 + cid_len], &addr.stateless_reset_token);
    written += value_len;
    return written;
}

fn hasParameterId(src: []const u8, needle: u64) Error!bool {
    var pos: usize = 0;
    while (pos < src.len) {
        const id_d = try varint.decode(src[pos..]);
        pos += id_d.bytes_read;
        const len_d = try varint.decode(src[pos..]);
        pos += len_d.bytes_read;
        if (len_d.value > src.len - pos) return Error.InvalidValue;
        if (id_d.value == needle) return true;
        pos += @intCast(len_d.value);
    }
    return false;
}

fn setOne(p: *Params, id: u64, value: []const u8) Error!void {
    switch (id) {
        Id.original_destination_connection_id => {
            if (value.len > path_mod.max_cid_len) return Error.InvalidValue;
            p.original_destination_connection_id = ConnectionId.fromSlice(value);
        },
        Id.max_idle_timeout => p.max_idle_timeout_ms = try decodeVarintValue(value),
        Id.stateless_reset_token => {
            if (value.len != 16) return Error.InvalidValue;
            var tok: [16]u8 = undefined;
            @memcpy(&tok, value);
            p.stateless_reset_token = tok;
        },
        Id.max_udp_payload_size => p.max_udp_payload_size = try decodeVarintValue(value),
        Id.initial_max_data => p.initial_max_data = try decodeVarintValue(value),
        Id.initial_max_stream_data_bidi_local => p.initial_max_stream_data_bidi_local = try decodeVarintValue(value),
        Id.initial_max_stream_data_bidi_remote => p.initial_max_stream_data_bidi_remote = try decodeVarintValue(value),
        Id.initial_max_stream_data_uni => p.initial_max_stream_data_uni = try decodeVarintValue(value),
        Id.initial_max_streams_bidi => p.initial_max_streams_bidi = try decodeVarintValue(value),
        Id.initial_max_streams_uni => p.initial_max_streams_uni = try decodeVarintValue(value),
        Id.ack_delay_exponent => {
            const v = try decodeVarintValue(value);
            if (v > 20) return Error.InvalidValue; // RFC 9000 §18.2
            p.ack_delay_exponent = v;
        },
        Id.max_ack_delay => {
            const v = try decodeVarintValue(value);
            if (v >= (@as(u64, 1) << 14)) return Error.InvalidValue;
            p.max_ack_delay_ms = v;
        },
        Id.disable_active_migration => {
            if (value.len != 0) return Error.InvalidValue;
            p.disable_active_migration = true;
        },
        Id.preferred_address => p.preferred_address = try decodePreferredAddress(value),
        Id.active_connection_id_limit => {
            const v = try decodeVarintValue(value);
            if (v < 2) return Error.InvalidValue;
            p.active_connection_id_limit = v;
        },
        Id.initial_source_connection_id => {
            if (value.len > path_mod.max_cid_len) return Error.InvalidValue;
            p.initial_source_connection_id = ConnectionId.fromSlice(value);
        },
        Id.retry_source_connection_id => {
            if (value.len > path_mod.max_cid_len) return Error.InvalidValue;
            p.retry_source_connection_id = ConnectionId.fromSlice(value);
        },
        Id.max_datagram_frame_size => p.max_datagram_frame_size = try decodeVarintValue(value),
        Id.initial_max_path_id => {
            const v = try decodeVarintValue(value);
            if (v > std.math.maxInt(u32)) return Error.InvalidValue;
            p.initial_max_path_id = @intCast(v);
        },
        else => {}, // unknown ids are ignored per §18
    }
}

fn decodePreferredAddress(value: []const u8) Error!PreferredAddress {
    if (value.len < 41) return Error.InvalidValue;
    const cid_len = value[24];
    if (cid_len > path_mod.max_cid_len) return Error.InvalidValue;
    const expected_len: usize = 41 + @as(usize, cid_len);
    if (value.len != expected_len) return Error.InvalidValue;

    var addr: PreferredAddress = .{
        .ipv4_port = std.mem.readInt(u16, value[4..][0..2], .big),
        .ipv6_port = std.mem.readInt(u16, value[22..][0..2], .big),
        .connection_id = ConnectionId.fromSlice(value[25 .. 25 + cid_len]),
    };
    @memcpy(&addr.ipv4_address, value[0..4]);
    @memcpy(&addr.ipv6_address, value[6..22]);
    @memcpy(&addr.stateless_reset_token, value[25 + cid_len .. expected_len]);
    return addr;
}

fn decodeVarintValue(value: []const u8) Error!u64 {
    const d = try varint.decode(value);
    if (d.bytes_read != value.len) return Error.InvalidValue;
    return d.value;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

test "round-trip with the parameters a typical client advertises" {
    const scid = ConnectionId.fromSlice(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const sent: Params = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .max_udp_payload_size = 1452,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = scid,
        .max_datagram_frame_size = 1200,
        .initial_max_path_id = 2,
    };

    var buf: [256]u8 = undefined;
    const n = try sent.encode(&buf);

    const got = try Params.decode(buf[0..n]);
    try testing.expectEqual(sent.max_idle_timeout_ms, got.max_idle_timeout_ms);
    try testing.expectEqual(sent.initial_max_data, got.initial_max_data);
    try testing.expectEqual(sent.initial_max_stream_data_bidi_local, got.initial_max_stream_data_bidi_local);
    try testing.expectEqual(sent.initial_max_stream_data_bidi_remote, got.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(sent.initial_max_stream_data_uni, got.initial_max_stream_data_uni);
    try testing.expectEqual(sent.initial_max_streams_bidi, got.initial_max_streams_bidi);
    try testing.expectEqual(sent.initial_max_streams_uni, got.initial_max_streams_uni);
    try testing.expectEqual(sent.max_udp_payload_size, got.max_udp_payload_size);
    try testing.expectEqual(sent.active_connection_id_limit, got.active_connection_id_limit);
    try testing.expectEqual(sent.max_datagram_frame_size, got.max_datagram_frame_size);
    try testing.expectEqual(sent.initial_max_path_id, got.initial_max_path_id);
    try testing.expectEqualSlices(u8, scid.slice(), got.initial_source_connection_id.?.slice());
}

test "server-only fields round-trip" {
    const dcid = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc });
    const scid = ConnectionId.fromSlice(&.{ 0xdd, 0xee });
    const reset_tok: [16]u8 = .{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    const sent: Params = .{
        .original_destination_connection_id = dcid,
        .initial_source_connection_id = scid,
        .stateless_reset_token = reset_tok,
        .retry_source_connection_id = scid,
        .disable_active_migration = true,
    };
    var buf: [256]u8 = undefined;
    const n = try sent.encode(&buf);
    const got = try Params.decode(buf[0..n]);
    try testing.expectEqualSlices(u8, dcid.slice(), got.original_destination_connection_id.?.slice());
    try testing.expectEqualSlices(u8, scid.slice(), got.initial_source_connection_id.?.slice());
    try testing.expectEqualSlices(u8, scid.slice(), got.retry_source_connection_id.?.slice());
    try testing.expectEqualSlices(u8, &reset_tok, &got.stateless_reset_token.?);
    try testing.expect(got.disable_active_migration);
}

test "preferred_address round-trips" {
    const cid = ConnectionId.fromSlice(&.{ 0xca, 0xfe, 0xba, 0xbe });
    const reset_tok: [16]u8 = .{
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    const preferred: PreferredAddress = .{
        .ipv4_address = .{ 192, 0, 2, 1 },
        .ipv4_port = 4433,
        .ipv6_address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .ipv6_port = 8443,
        .connection_id = cid,
        .stateless_reset_token = reset_tok,
    };
    const sent: Params = .{ .preferred_address = preferred };

    var buf: [128]u8 = undefined;
    const n = try sent.encode(&buf);
    const got = (try Params.decode(buf[0..n])).preferred_address.?;

    try testing.expectEqualSlices(u8, &preferred.ipv4_address, &got.ipv4_address);
    try testing.expectEqual(preferred.ipv4_port, got.ipv4_port);
    try testing.expectEqualSlices(u8, &preferred.ipv6_address, &got.ipv6_address);
    try testing.expectEqual(preferred.ipv6_port, got.ipv6_port);
    try testing.expectEqualSlices(u8, preferred.connection_id.slice(), got.connection_id.slice());
    try testing.expectEqualSlices(u8, &preferred.stateless_reset_token, &got.stateless_reset_token);
}

test "decode rejects malformed preferred_address" {
    var short_buf: [64]u8 = @splat(0);
    var pos: usize = 0;
    pos += try varint.encode(short_buf[pos..], Id.preferred_address);
    pos += try varint.encode(short_buf[pos..], 40);
    pos += 40;
    try testing.expectError(Error.InvalidValue, Params.decode(short_buf[0..pos]));

    var long_cid_buf: [96]u8 = @splat(0);
    pos = 0;
    pos += try varint.encode(long_cid_buf[pos..], Id.preferred_address);
    pos += try varint.encode(long_cid_buf[pos..], 62);
    long_cid_buf[pos + 24] = path_mod.max_cid_len + 1;
    pos += 62;
    try testing.expectError(Error.InvalidValue, Params.decode(long_cid_buf[0..pos]));

    var trailing_buf: [64]u8 = @splat(0);
    pos = 0;
    pos += try varint.encode(trailing_buf[pos..], Id.preferred_address);
    pos += try varint.encode(trailing_buf[pos..], 42);
    trailing_buf[pos + 24] = 0;
    pos += 42;
    try testing.expectError(Error.InvalidValue, Params.decode(trailing_buf[0..pos]));
}

test "decode rejects oversized stateless_reset_token" {
    // id=0x02 (stateless_reset_token), len=8 (must be 16) — invalid.
    const blob = [_]u8{ 0x02, 0x08, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(Error.InvalidValue, Params.decode(&blob));
}

test "decode rejects duplicate transport parameters" {
    const known = [_]u8{
        0x04, 0x01, 0x05,
        0x04, 0x01, 0x06,
    };
    try testing.expectError(Error.DuplicateParameter, Params.decode(&known));

    var unknown: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(unknown[pos..], 0x1234);
    pos += try varint.encode(unknown[pos..], 0);
    pos += try varint.encode(unknown[pos..], 0x1234);
    pos += try varint.encode(unknown[pos..], 0);
    try testing.expectError(Error.DuplicateParameter, Params.decode(unknown[0..pos]));
}

test "decode rejects active_connection_id_limit < 2" {
    // id=0x0e, len=1, value=varint(1) = 0x01.
    const blob = [_]u8{ 0x0e, 0x01, 0x01 };
    try testing.expectError(Error.InvalidValue, Params.decode(&blob));
}

test "decode rejects initial_max_path_id above u32 max" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], Id.initial_max_path_id);
    pos += try varint.encode(buf[pos..], 8);
    pos += try varint.encode(buf[pos..], @as(u64, std.math.maxInt(u32)) + 1);
    try testing.expectError(Error.InvalidValue, Params.decode(buf[0..pos]));
}

test "decode rejects disable_active_migration with non-zero length" {
    const blob = [_]u8{ 0x0c, 0x01, 0x00 };
    try testing.expectError(Error.InvalidValue, Params.decode(&blob));
}

test "decode rejects ack_delay_exponent > 20" {
    // id=0x0a, len=1, value=varint(21).
    const blob = [_]u8{ 0x0a, 0x01, 21 };
    try testing.expectError(Error.InvalidValue, Params.decode(&blob));
}

test "decode skips unknown ids" {
    // id=0xfe (reserved/unknown), len=2, then a normal known id.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0xfe);
    pos += try varint.encode(buf[pos..], 2);
    buf[pos] = 0xaa;
    buf[pos + 1] = 0xbb;
    pos += 2;
    pos += try varint.encode(buf[pos..], Id.initial_max_data);
    pos += try varint.encode(buf[pos..], 1);
    buf[pos] = 0x05;
    pos += 1;

    const got = try Params.decode(buf[0..pos]);
    try testing.expectEqual(@as(u64, 5), got.initial_max_data);
}

test "default-only Params encodes to empty blob" {
    const empty: Params = .{};
    var buf: [16]u8 = undefined;
    const n = try empty.encode(&buf);
    try testing.expectEqual(@as(usize, 0), n);
    const decoded = try Params.decode(buf[0..n]);
    try testing.expectEqual(empty.max_idle_timeout_ms, decoded.max_idle_timeout_ms);
    try testing.expectEqual(empty.initial_max_data, decoded.initial_max_data);
}

test "unknown-but-large id round-trips through varint" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], 0x1234); // 2-byte varint id
    pos += try varint.encode(buf[pos..], 0);
    const got = try Params.decode(buf[0..pos]);
    _ = got;
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `Params.decode` with arbitrary bytes. Properties:
//
// - No panic, no overflow trap.
// - On success, every bound-checked field obeys its RFC 9000 §18.2 cap:
//   - `ack_delay_exponent <= 20`
//   - `max_ack_delay_ms < 2^14`
//   - `active_connection_id_limit >= 2`
//   - `max_udp_payload_size >= 1200` is NOT enforced by decode (the
//     decoder accepts any varint), so we don't assert it.
//   - When the multipath max-path-id is set, it fits in u32.
// - CID-shaped fields (original/initial/retry SCID/DCID) have len ≤
//   `path_mod.max_cid_len`.
// - PreferredAddress (when present) has a CID len ≤ `max_cid_len`.
// - Decoding rejects duplicate ids — re-decoding the encode of a
//   successful decode is also successful (no field accidentally
//   round-trips into a value that fails its own bound).

test "fuzz: transport_params decode never panics and respects RFC bounds" {
    try std.testing.fuzz({}, fuzzTransportParams, .{});
}

fn fuzzTransportParams(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [1024]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    const p = Params.decode(input) catch return;

    // RFC 9000 §18.2 bounds the decoder enforces on success.
    try testing.expect(p.ack_delay_exponent <= 20);
    try testing.expect(p.max_ack_delay_ms < (@as(u64, 1) << 14));
    try testing.expect(p.active_connection_id_limit >= 2);

    // CID lengths fit in the wire-format cap.
    if (p.original_destination_connection_id) |cid| {
        try testing.expect(cid.len <= path_mod.max_cid_len);
    }
    if (p.initial_source_connection_id) |cid| {
        try testing.expect(cid.len <= path_mod.max_cid_len);
    }
    if (p.retry_source_connection_id) |cid| {
        try testing.expect(cid.len <= path_mod.max_cid_len);
    }
    if (p.stateless_reset_token) |tok| {
        try testing.expectEqual(@as(usize, 16), tok.len);
    }
    if (p.preferred_address) |addr| {
        try testing.expect(addr.connection_id.len <= path_mod.max_cid_len);
    }

    // Re-encode + re-decode round-trip: a value the decoder accepted
    // must also be encodable back into a blob that the decoder
    // accepts. This catches asymmetric bound errors (e.g. a field that
    // decodes from a varint outside the encode-side range).
    var encoded: [2048]u8 = undefined;
    const n = p.encode(&encoded) catch return;
    const p2 = Params.decode(encoded[0..n]) catch |e| {
        // If a successful decode produces a struct that cannot be
        // round-tripped, that's a parser asymmetry worth flagging.
        // Allow `BufferTooSmall` (the encode buffer was sized to
        // 2 KiB; pathological values could need more) but not the
        // structural-error variants.
        if (e == Error.BufferTooSmall) return;
        return e;
    };
    // The two decodes agree on the bound-checked scalar fields.
    try testing.expectEqual(p.max_idle_timeout_ms, p2.max_idle_timeout_ms);
    try testing.expectEqual(p.initial_max_data, p2.initial_max_data);
    try testing.expectEqual(p.ack_delay_exponent, p2.ack_delay_exponent);
    try testing.expectEqual(p.max_ack_delay_ms, p2.max_ack_delay_ms);
    try testing.expectEqual(p.active_connection_id_limit, p2.active_connection_id_limit);
    try testing.expectEqual(p.disable_active_migration, p2.disable_active_migration);
    try testing.expectEqual(p.initial_max_path_id, p2.initial_max_path_id);
}
