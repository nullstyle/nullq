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

/// Multipath QUIC draft version targeted by quic_zig's public API.
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
/// `TransportParameterError` — RFC 9000 §7.3 / §18.2 role-aware or
/// universal-bound rejection raised by `decodeAs` (a peer's blob is
/// well-formed on the wire but violates a presence / forbidden /
/// bound rule that the role-agnostic `decode` cannot enforce on its
/// own). Maps to QUIC transport error code TRANSPORT_PARAMETER_ERROR
/// (0x08) when surfaced to a connection close.
pub const Error = error{
    BufferTooSmall,
    DuplicateParameter,
    UnknownLength,
    ValueTooLarge,
    InvalidValue,
    TransportParameterError,
} || varint.Error;

/// Identifies which side of the handshake authored a transport-
/// parameter blob. Drives the §7.3 / §18.2 role gates in `decodeAs`:
/// the *sender's* role determines which parameters are required,
/// allowed, or forbidden. When a server parses the blob it received
/// from the client, it parses with `Role.client` because the client
/// authored those bytes.
pub const Role = enum { client, server };

/// Inputs to `decodeAs`. `role` selects the §7.3 / §18.2 gate set;
/// `server_sent_retry` is consulted only when `role == .server` and
/// drives the §7.3 ¶3 retry_source_connection_id presence check
/// (server MUST include the parameter iff a Retry was sent).
pub const DecodeOptions = struct {
    role: Role,
    /// Required only when `role == .server`: did this server send a
    /// Retry to the client during the handshake? Drives the §7.3 ¶3
    /// presence/absence check for retry_source_connection_id. Ignored
    /// when `role == .client` (a client never sets this parameter).
    server_sent_retry: bool = false,
};

/// RFC 9000 §18.2 ¶9: max_udp_payload_size values below 1200 are
/// invalid. The minimum is universal (both peers must respect the
/// floor); enforced inside `decodeAs` rather than `decode` because
/// `decode` is the wire-shape primitive used by hand-built fixtures
/// that intentionally drive the codec near its bounds.
const min_max_udp_payload_size: u64 = 1200;

/// RFC 9000 §18.2 ¶19 / ¶21: initial_max_streams_{bidi,uni} values
/// above 2^60 would allow a stream id that cannot be expressed as a
/// QUIC varint. Universal (role-independent) bound.
const max_initial_max_streams: u64 = 1 << 60;

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

/// Role-aware decode. Calls `Params.decode` to parse the wire format,
/// then applies the universal bound checks (RFC 9000 §18.2 ¶9, ¶19,
/// ¶21) and the role-specific gates (RFC 9000 §7.3 + §18.2 ¶29 / ¶35
/// + the server-only parameters listed in §18.2). Any role / bound
/// violation is reported as `Error.TransportParameterError` so callers
/// can map a single error variant to a TRANSPORT_PARAMETER_ERROR
/// connection close.
///
/// The role argument identifies *the side that authored the bytes*.
/// A server reading the client's blob calls this with `role = .client`
/// because the client wrote the parameters; a client reading the
/// server's blob calls with `role = .server`.
///
/// `opts.server_sent_retry` is consulted only for `role == .server`
/// and drives the §7.3 ¶3 presence rule for `retry_source_connection_id`:
///   * Retry was sent → the parameter MUST be present.
///   * Retry was not sent → the parameter MUST be absent.
pub fn decodeAs(blob: []const u8, opts: DecodeOptions) Error!Params {
    const params = try Params.decode(blob);

    // -- universal bound checks (role-independent §18.2 caps) --

    // §18.2 ¶9: max_udp_payload_size values below 1200 are invalid.
    // The wire codec accepts any varint here because it doesn't know
    // whether the blob describes the local or peer endpoint; the role-
    // aware path always rejects the under-floor case.
    if (params.max_udp_payload_size < min_max_udp_payload_size) {
        return Error.TransportParameterError;
    }

    // §18.2 ¶19 / ¶21: a max_streams value above 2^60 would name a
    // stream id outside the QUIC varint range (62 bits). Both bidi
    // and uni share the same cap.
    if (params.initial_max_streams_bidi > max_initial_max_streams) {
        return Error.TransportParameterError;
    }
    if (params.initial_max_streams_uni > max_initial_max_streams) {
        return Error.TransportParameterError;
    }

    // -- role-specific gates --

    // Both sides MUST advertise initial_source_connection_id (§7.3 ¶1)
    // so the peer can detect off-path injection of the first Initial.
    if (params.initial_source_connection_id == null) {
        return Error.TransportParameterError;
    }

    switch (opts.role) {
        .client => {
            // §18.2 ¶29: preferred_address is server-only — a client
            // MUST NOT send it; the receiving server treats receipt
            // as TRANSPORT_PARAMETER_ERROR.
            if (params.preferred_address != null) {
                return Error.TransportParameterError;
            }
            // §18.2 ¶35: retry_source_connection_id is server-only.
            if (params.retry_source_connection_id != null) {
                return Error.TransportParameterError;
            }
            // original_destination_connection_id is the server's
            // echo of the client's first DCID (§18.2 ¶3); a client-
            // authored blob MUST NOT contain it.
            if (params.original_destination_connection_id != null) {
                return Error.TransportParameterError;
            }
            // stateless_reset_token is server-only (§18.2 ¶7); a
            // client MUST NOT send one.
            if (params.stateless_reset_token != null) {
                return Error.TransportParameterError;
            }
        },
        .server => {
            // §7.3 ¶3: the server MUST include retry_source_connection_id
            // iff it sent a Retry packet during the handshake.
            const has_retry_scid = params.retry_source_connection_id != null;
            if (opts.server_sent_retry and !has_retry_scid) {
                return Error.TransportParameterError;
            }
            if (!opts.server_sent_retry and has_retry_scid) {
                return Error.TransportParameterError;
            }
        },
    }

    return params;
}

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

// -- decodeAs role gates -------------------------------------------------
//
// `decodeAs` layers RFC 9000 §7.3 / §18.2 role and bound rejections on
// top of the wire codec. The cases below exercise each gate one at a
// time; the conformance suite repeats the same shapes with their RFC
// citations attached.

const example_scid: ConnectionId = .{
    .bytes = .{ 0xb0, 0xb1, 0xb2, 0xb3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .len = 4,
};

test "decodeAs rejects max_udp_payload_size below 1200 (universal §18.2 ¶9)" {
    const sent: Params = .{
        .max_udp_payload_size = 1199,
        .initial_source_connection_id = example_scid,
    };
    var buf: [32]u8 = undefined;
    const n = try sent.encode(&buf);
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..n], .{ .role = .client }),
    );
}

test "decodeAs rejects initial_max_streams_bidi above 2^60 (universal §18.2 ¶19)" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try writeVarint(&buf, pos, Id.initial_max_streams_bidi, (1 << 60) + 1);
    pos += try writeBytes(&buf, pos, Id.initial_source_connection_id, example_scid.slice());
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..pos], .{ .role = .client }),
    );
}

test "decodeAs rejects missing initial_source_connection_id on either side (§7.3 ¶1)" {
    // Empty blob has every default and no initial_source_connection_id.
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(&.{}, .{ .role = .client }),
    );
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(&.{}, .{ .role = .server }),
    );
}

test "decodeAs rejects preferred_address authored by a client (§18.2 ¶29)" {
    const sent: Params = .{
        .initial_source_connection_id = example_scid,
        .preferred_address = .{},
    };
    var buf: [128]u8 = undefined;
    const n = try sent.encode(&buf);
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..n], .{ .role = .client }),
    );
}

test "decodeAs rejects retry_source_connection_id authored by a client (§18.2 ¶35)" {
    const sent: Params = .{
        .initial_source_connection_id = example_scid,
        .retry_source_connection_id = example_scid,
    };
    var buf: [64]u8 = undefined;
    const n = try sent.encode(&buf);
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..n], .{ .role = .client }),
    );
}

test "decodeAs rejects original_destination_connection_id and stateless_reset_token from a client" {
    const odcid_sent: Params = .{
        .initial_source_connection_id = example_scid,
        .original_destination_connection_id = example_scid,
    };
    var buf: [64]u8 = undefined;
    var n = try odcid_sent.encode(&buf);
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..n], .{ .role = .client }),
    );

    const reset_tok: [16]u8 = @splat(0xaa);
    const reset_sent: Params = .{
        .initial_source_connection_id = example_scid,
        .stateless_reset_token = reset_tok,
    };
    n = try reset_sent.encode(&buf);
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..n], .{ .role = .client }),
    );
}

test "decodeAs enforces server's retry_source_connection_id presence rule (§7.3 ¶3)" {
    // Server sent Retry but blob is missing retry_source_connection_id.
    const without_rscid: Params = .{
        .initial_source_connection_id = example_scid,
    };
    var buf: [64]u8 = undefined;
    var n = try without_rscid.encode(&buf);
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..n], .{ .role = .server, .server_sent_retry = true }),
    );

    // Server did NOT send Retry but blob includes retry_source_connection_id.
    const with_rscid: Params = .{
        .initial_source_connection_id = example_scid,
        .retry_source_connection_id = example_scid,
    };
    n = try with_rscid.encode(&buf);
    try testing.expectError(
        Error.TransportParameterError,
        decodeAs(buf[0..n], .{ .role = .server, .server_sent_retry = false }),
    );

    // Matching presence: both Retry-sent + parameter present is accepted.
    const ok = try decodeAs(buf[0..n], .{ .role = .server, .server_sent_retry = true });
    try testing.expect(ok.retry_source_connection_id != null);
}

test "decodeAs accepts a typical client blob and a typical server blob" {
    // Client side: ISCID present, server-only fields absent.
    const client_sent: Params = .{
        .initial_source_connection_id = example_scid,
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
    };
    var buf: [128]u8 = undefined;
    var n = try client_sent.encode(&buf);
    const got_client = try decodeAs(buf[0..n], .{ .role = .client });
    try testing.expectEqual(@as(u64, 30_000), got_client.max_idle_timeout_ms);

    // Server side without Retry: no retry_source_connection_id allowed.
    const server_no_retry: Params = .{
        .initial_source_connection_id = example_scid,
        .original_destination_connection_id = example_scid,
    };
    n = try server_no_retry.encode(&buf);
    const got_server = try decodeAs(buf[0..n], .{ .role = .server, .server_sent_retry = false });
    try testing.expect(got_server.original_destination_connection_id != null);
    try testing.expect(got_server.retry_source_connection_id == null);
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

// Build a `Params` struct with every field populated from corpus
// bytes, using value ranges that fit each parameter's RFC bounds, and
// then assert encode → decode → encode is canonical (the second
// encode must match the first byte-for-byte). This is the
// generative-input counterpart to `fuzzTransportParams` above (which
// only feeds malformed bytes into `decode`).
//
// Properties:
//   - `encode` accepts every well-formed `Params` we construct.
//   - `decode` recovers the same structurally-bound fields.
//   - The encode is canonical: re-encoding the decoded value yields
//     identical bytes.
test "fuzz: transport_params canonical round-trip" {
    try std.testing.fuzz({}, fuzzTransportParamsRoundTrip, .{});
}

fn fuzzTransportParamsRoundTrip(_: void, smith: *std.testing.Smith) anyerror!void {
    var token: [16]u8 = undefined;
    smith.bytes(&token);

    var cid_a_buf: [path_mod.max_cid_len]u8 = undefined;
    smith.bytes(&cid_a_buf);
    const cid_a_len = smith.valueRangeAtMost(u8, 0, @intCast(path_mod.max_cid_len));
    const cid_a = ConnectionId.fromSlice(cid_a_buf[0..cid_a_len]);

    var cid_b_buf: [path_mod.max_cid_len]u8 = undefined;
    smith.bytes(&cid_b_buf);
    const cid_b_len = smith.valueRangeAtMost(u8, 0, @intCast(path_mod.max_cid_len));
    const cid_b = ConnectionId.fromSlice(cid_b_buf[0..cid_b_len]);

    var cid_c_buf: [path_mod.max_cid_len]u8 = undefined;
    smith.bytes(&cid_c_buf);
    const cid_c_len = smith.valueRangeAtMost(u8, 0, @intCast(path_mod.max_cid_len));
    const cid_c = ConnectionId.fromSlice(cid_c_buf[0..cid_c_len]);

    const have_preferred = smith.valueRangeAtMost(u8, 0, 1) == 0;
    const preferred_address: ?PreferredAddress = if (!have_preferred) null else blk: {
        var ipv4: [4]u8 = undefined;
        smith.bytes(&ipv4);
        var ipv6: [16]u8 = undefined;
        smith.bytes(&ipv6);
        var preferred_token: [16]u8 = undefined;
        smith.bytes(&preferred_token);
        var pa_cid_buf: [path_mod.max_cid_len]u8 = undefined;
        smith.bytes(&pa_cid_buf);
        const pa_cid_len = smith.valueRangeAtMost(u8, 0, @intCast(path_mod.max_cid_len));
        const pa_cid = ConnectionId.fromSlice(pa_cid_buf[0..pa_cid_len]);
        break :blk .{
            .ipv4_address = ipv4,
            .ipv4_port = smith.value(u16),
            .ipv6_address = ipv6,
            .ipv6_port = smith.value(u16),
            .connection_id = pa_cid,
            .stateless_reset_token = preferred_token,
        };
    };

    const params: Params = .{
        .original_destination_connection_id = if (smith.valueRangeAtMost(u8, 0, 1) == 0) null else cid_a,
        .max_idle_timeout_ms = smith.valueRangeAtMost(u64, 0, 60_000),
        .stateless_reset_token = if (smith.valueRangeAtMost(u8, 0, 1) == 0) null else token,
        .max_udp_payload_size = 1200 + smith.valueRangeAtMost(u64, 0, 2895),
        .initial_max_data = smith.valueRangeAtMost(u64, 0, 16 * 1024 * 1024 - 1),
        .initial_max_stream_data_bidi_local = smith.valueRangeAtMost(u64, 0, 1024 * 1024 - 1),
        .initial_max_stream_data_bidi_remote = smith.valueRangeAtMost(u64, 0, 1024 * 1024 - 1),
        .initial_max_stream_data_uni = smith.valueRangeAtMost(u64, 0, 1024 * 1024 - 1),
        .initial_max_streams_bidi = smith.valueRangeAtMost(u64, 0, 255),
        .initial_max_streams_uni = smith.valueRangeAtMost(u64, 0, 255),
        .ack_delay_exponent = smith.valueRangeAtMost(u64, 0, 20),
        .max_ack_delay_ms = smith.valueRangeAtMost(u64, 0, (@as(u64, 1) << 14) - 1),
        .disable_active_migration = smith.valueRangeAtMost(u8, 0, 1) == 0,
        .preferred_address = preferred_address,
        .active_connection_id_limit = 2 + smith.valueRangeAtMost(u64, 0, 14),
        .initial_source_connection_id = if (smith.valueRangeAtMost(u8, 0, 1) == 0) null else cid_b,
        .retry_source_connection_id = if (smith.valueRangeAtMost(u8, 0, 1) == 0) null else cid_c,
        .max_datagram_frame_size = smith.valueRangeAtMost(u64, 0, 4095),
        .initial_max_path_id = if (smith.valueRangeAtMost(u8, 0, 1) == 0) null else smith.valueRangeAtMost(u32, 0, 255),
    };

    var encoded: [1024]u8 = undefined;
    const encoded_len = try params.encode(&encoded);
    const decoded = try Params.decode(encoded[0..encoded_len]);
    var reencoded: [1024]u8 = undefined;
    const reencoded_len = try decoded.encode(&reencoded);
    try testing.expectEqualSlices(u8, encoded[0..encoded_len], reencoded[0..reencoded_len]);
}
