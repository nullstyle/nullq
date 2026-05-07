//! Frame encoder for the 18 fixed-shape QUIC frame types (RFC 9000 §19).
//!
//! `encode(dst, frame)` writes the wire bytes for a `Frame` and
//! returns the number of bytes written. `encodedLen(frame)` returns
//! the byte count without writing anywhere — useful for sizing
//! buffers and for the packet builder's PMTU budget.

const std = @import("std");
const types = @import("types.zig");
const varint = @import("../wire/varint.zig");
const wire_header = @import("../wire/header.zig");

const Frame = types.Frame;

/// Errors that `encode` can return — `BufferTooSmall` if `dst` doesn't
/// fit the frame, plus any wire-level varint/CID errors.
pub const Error = varint.Error || wire_header.Error;

/// Frame type for PATH_ACK without ECN (draft-ietf-quic-multipath-21).
pub const frame_type_path_ack: u64 = 0x3e;
/// Frame type for PATH_ACK with ECN counts.
pub const frame_type_path_ack_ecn: u64 = 0x3f;
/// Frame type for PATH_ABANDON.
pub const frame_type_path_abandon: u64 = 0x3e75;
/// Frame type for PATH_STATUS_BACKUP.
pub const frame_type_path_status_backup: u64 = 0x3e76;
/// Frame type for PATH_STATUS_AVAILABLE.
pub const frame_type_path_status_available: u64 = 0x3e77;
/// Frame type for PATH_NEW_CONNECTION_ID.
pub const frame_type_path_new_connection_id: u64 = 0x3e78;
/// Frame type for PATH_RETIRE_CONNECTION_ID.
pub const frame_type_path_retire_connection_id: u64 = 0x3e79;
/// Frame type for MAX_PATH_ID.
pub const frame_type_max_path_id: u64 = 0x3e7a;
/// Frame type for PATHS_BLOCKED.
pub const frame_type_paths_blocked: u64 = 0x3e7b;
/// Frame type for PATH_CIDS_BLOCKED.
pub const frame_type_path_cids_blocked: u64 = 0x3e7c;

/// Writes `frame` to the start of `dst` and returns the number of
/// bytes written. Returns `error.BufferTooSmall` if `dst` doesn't have
/// room for the full frame.
pub fn encode(dst: []u8, frame: Frame) Error!usize {
    return switch (frame) {
        .padding => |f| encodePadding(dst, f),
        .ping => writeTypeOnly(dst, 0x01),
        .ack => |f| encodeAck(dst, f),
        .reset_stream => |f| encodeResetStream(dst, f),
        .stop_sending => |f| encodeStopSending(dst, f),
        .crypto => |f| encodeCrypto(dst, f),
        .new_token => |f| encodeNewToken(dst, f),
        .stream => |f| encodeStream(dst, f),
        .max_data => |f| encodeSingleVarint(dst, 0x10, f.maximum_data),
        .max_stream_data => |f| encodeMaxStreamData(dst, f),
        .max_streams => |f| encodeSingleVarint(dst, if (f.bidi) 0x12 else 0x13, f.maximum_streams),
        .data_blocked => |f| encodeSingleVarint(dst, 0x14, f.maximum_data),
        .stream_data_blocked => |f| encodeStreamDataBlocked(dst, f),
        .streams_blocked => |f| encodeSingleVarint(dst, if (f.bidi) 0x16 else 0x17, f.maximum_streams),
        .new_connection_id => |f| encodeNewConnectionId(dst, f),
        .retire_connection_id => |f| encodeSingleVarint(dst, 0x19, f.sequence_number),
        .path_challenge => |f| encodeFixed8(dst, 0x1a, f.data),
        .path_response => |f| encodeFixed8(dst, 0x1b, f.data),
        .connection_close => |f| encodeConnectionClose(dst, f),
        .handshake_done => writeTypeOnly(dst, 0x1e),
        .datagram => |f| encodeDatagram(dst, f),
        .path_ack => |f| encodePathAck(dst, f),
        .path_abandon => |f| encodePathAbandon(dst, f),
        .path_status_backup => |f| encodePathStatus(dst, frame_type_path_status_backup, f),
        .path_status_available => |f| encodePathStatus(dst, frame_type_path_status_available, f),
        .path_new_connection_id => |f| encodePathNewConnectionId(dst, f),
        .path_retire_connection_id => |f| encodePathRetireConnectionId(dst, f),
        .max_path_id => |f| encodePathIdOnly(dst, frame_type_max_path_id, f.maximum_path_id),
        .paths_blocked => |f| encodePathIdOnly(dst, frame_type_paths_blocked, f.maximum_path_id),
        .path_cids_blocked => |f| encodePathCidsBlocked(dst, f),
    };
}

/// Number of bytes `encode(dst, frame)` would write, without touching
/// any buffer. Useful for the packet builder's PMTU budget.
pub fn encodedLen(frame: Frame) usize {
    return switch (frame) {
        .padding => |f| @intCast(f.count),
        .ping => 1,
        .ack => |f| blk: {
            var len: usize = 1 +
                varint.encodedLen(f.largest_acked) +
                varint.encodedLen(f.ack_delay) +
                varint.encodedLen(f.range_count) +
                varint.encodedLen(f.first_range) +
                f.ranges_bytes.len;
            if (f.ecn_counts) |e| {
                len += varint.encodedLen(e.ect0);
                len += varint.encodedLen(e.ect1);
                len += varint.encodedLen(e.ecn_ce);
            }
            break :blk len;
        },
        .reset_stream => |f| 1 +
            varint.encodedLen(f.stream_id) +
            varint.encodedLen(f.application_error_code) +
            varint.encodedLen(f.final_size),
        .stop_sending => |f| 1 +
            varint.encodedLen(f.stream_id) +
            varint.encodedLen(f.application_error_code),
        .crypto => |f| 1 +
            varint.encodedLen(f.offset) +
            varint.encodedLen(f.data.len) +
            f.data.len,
        .new_token => |f| 1 + varint.encodedLen(f.token.len) + f.token.len,
        .stream => |f| blk: {
            var len: usize = 1 + varint.encodedLen(f.stream_id);
            if (f.has_offset) len += varint.encodedLen(f.offset);
            if (f.has_length) len += varint.encodedLen(f.data.len);
            len += f.data.len;
            break :blk len;
        },
        .max_data => |f| 1 + varint.encodedLen(f.maximum_data),
        .max_stream_data => |f| 1 +
            varint.encodedLen(f.stream_id) +
            varint.encodedLen(f.maximum_stream_data),
        .max_streams => |f| 1 + varint.encodedLen(f.maximum_streams),
        .data_blocked => |f| 1 + varint.encodedLen(f.maximum_data),
        .stream_data_blocked => |f| 1 +
            varint.encodedLen(f.stream_id) +
            varint.encodedLen(f.maximum_stream_data),
        .streams_blocked => |f| 1 + varint.encodedLen(f.maximum_streams),
        .new_connection_id => |f| 1 +
            varint.encodedLen(f.sequence_number) +
            varint.encodedLen(f.retire_prior_to) +
            1 +
            f.connection_id.len +
            16,
        .retire_connection_id => |f| 1 + varint.encodedLen(f.sequence_number),
        .path_challenge => 1 + 8,
        .path_response => 1 + 8,
        .connection_close => |f| blk: {
            var len: usize = 1 + varint.encodedLen(f.error_code);
            if (f.is_transport) len += varint.encodedLen(f.frame_type);
            len += varint.encodedLen(f.reason_phrase.len);
            len += f.reason_phrase.len;
            break :blk len;
        },
        .handshake_done => 1,
        .datagram => |f| blk: {
            var len: usize = 1;
            if (f.has_length) len += varint.encodedLen(f.data.len);
            len += f.data.len;
            break :blk len;
        },
        .path_ack => |f| blk: {
            var len: usize = varint.encodedLen(if (f.ecn_counts == null) frame_type_path_ack else frame_type_path_ack_ecn) +
                varint.encodedLen(f.path_id) +
                varint.encodedLen(f.largest_acked) +
                varint.encodedLen(f.ack_delay) +
                varint.encodedLen(f.range_count) +
                varint.encodedLen(f.first_range) +
                f.ranges_bytes.len;
            if (f.ecn_counts) |e| {
                len += varint.encodedLen(e.ect0);
                len += varint.encodedLen(e.ect1);
                len += varint.encodedLen(e.ecn_ce);
            }
            break :blk len;
        },
        .path_abandon => |f| varint.encodedLen(frame_type_path_abandon) +
            varint.encodedLen(f.path_id) +
            varint.encodedLen(f.error_code),
        .path_status_backup => |f| encodedPathStatusLen(frame_type_path_status_backup, f),
        .path_status_available => |f| encodedPathStatusLen(frame_type_path_status_available, f),
        .path_new_connection_id => |f| varint.encodedLen(frame_type_path_new_connection_id) +
            varint.encodedLen(f.path_id) +
            varint.encodedLen(f.sequence_number) +
            varint.encodedLen(f.retire_prior_to) +
            1 +
            f.connection_id.len +
            16,
        .path_retire_connection_id => |f| varint.encodedLen(frame_type_path_retire_connection_id) +
            varint.encodedLen(f.path_id) +
            varint.encodedLen(f.sequence_number),
        .max_path_id => |f| varint.encodedLen(frame_type_max_path_id) + varint.encodedLen(f.maximum_path_id),
        .paths_blocked => |f| varint.encodedLen(frame_type_paths_blocked) + varint.encodedLen(f.maximum_path_id),
        .path_cids_blocked => |f| varint.encodedLen(frame_type_path_cids_blocked) +
            varint.encodedLen(f.path_id) +
            varint.encodedLen(f.next_sequence_number),
    };
}

fn writeTypeOnly(dst: []u8, type_byte: u8) Error!usize {
    if (dst.len < 1) return Error.BufferTooSmall;
    dst[0] = type_byte;
    return 1;
}

fn writeFrameType(dst: []u8, frame_type: u64) Error!usize {
    return try varint.encode(dst, frame_type);
}

fn encodedPathStatusLen(frame_type: u64, f: types.PathStatus) usize {
    return varint.encodedLen(frame_type) +
        varint.encodedLen(f.path_id) +
        varint.encodedLen(f.sequence_number);
}

fn encodePadding(dst: []u8, p: types.Padding) Error!usize {
    const n: usize = @intCast(p.count);
    if (dst.len < n) return Error.BufferTooSmall;
    @memset(dst[0..n], 0);
    return n;
}

fn encodeSingleVarint(dst: []u8, type_byte: u8, value: u64) Error!usize {
    var pos = try writeTypeOnly(dst, type_byte);
    pos += try varint.encode(dst[pos..], value);
    return pos;
}

fn encodeResetStream(dst: []u8, f: types.ResetStream) Error!usize {
    var pos = try writeTypeOnly(dst, 0x04);
    pos += try varint.encode(dst[pos..], f.stream_id);
    pos += try varint.encode(dst[pos..], f.application_error_code);
    pos += try varint.encode(dst[pos..], f.final_size);
    return pos;
}

fn encodeStopSending(dst: []u8, f: types.StopSending) Error!usize {
    var pos = try writeTypeOnly(dst, 0x05);
    pos += try varint.encode(dst[pos..], f.stream_id);
    pos += try varint.encode(dst[pos..], f.application_error_code);
    return pos;
}

fn encodeCrypto(dst: []u8, f: types.Crypto) Error!usize {
    var pos = try writeTypeOnly(dst, 0x06);
    pos += try varint.encode(dst[pos..], f.offset);
    pos += try varint.encode(dst[pos..], f.data.len);
    if (dst.len < pos + f.data.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.data.len], f.data);
    pos += f.data.len;
    return pos;
}

fn encodeNewToken(dst: []u8, f: types.NewToken) Error!usize {
    var pos = try writeTypeOnly(dst, 0x07);
    pos += try varint.encode(dst[pos..], f.token.len);
    if (dst.len < pos + f.token.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.token.len], f.token);
    pos += f.token.len;
    return pos;
}

fn encodeMaxStreamData(dst: []u8, f: types.MaxStreamData) Error!usize {
    var pos = try writeTypeOnly(dst, 0x11);
    pos += try varint.encode(dst[pos..], f.stream_id);
    pos += try varint.encode(dst[pos..], f.maximum_stream_data);
    return pos;
}

fn encodeStreamDataBlocked(dst: []u8, f: types.StreamDataBlocked) Error!usize {
    var pos = try writeTypeOnly(dst, 0x15);
    pos += try varint.encode(dst[pos..], f.stream_id);
    pos += try varint.encode(dst[pos..], f.maximum_stream_data);
    return pos;
}

fn encodeNewConnectionId(dst: []u8, f: types.NewConnectionId) Error!usize {
    var pos = try writeTypeOnly(dst, 0x18);
    pos += try varint.encode(dst[pos..], f.sequence_number);
    pos += try varint.encode(dst[pos..], f.retire_prior_to);
    if (dst.len < pos + 1) return Error.BufferTooSmall;
    dst[pos] = f.connection_id.len;
    pos += 1;
    if (dst.len < pos + f.connection_id.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.connection_id.len], f.connection_id.bytes[0..f.connection_id.len]);
    pos += f.connection_id.len;
    if (dst.len < pos + 16) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + 16], &f.stateless_reset_token);
    pos += 16;
    return pos;
}

fn encodeFixed8(dst: []u8, type_byte: u8, data: [8]u8) Error!usize {
    if (dst.len < 9) return Error.BufferTooSmall;
    dst[0] = type_byte;
    @memcpy(dst[1..9], &data);
    return 9;
}

fn encodeAck(dst: []u8, f: types.Ack) Error!usize {
    const type_byte: u8 = if (f.ecn_counts == null) 0x02 else 0x03;
    var pos = try writeTypeOnly(dst, type_byte);
    pos += try varint.encode(dst[pos..], f.largest_acked);
    pos += try varint.encode(dst[pos..], f.ack_delay);
    pos += try varint.encode(dst[pos..], f.range_count);
    pos += try varint.encode(dst[pos..], f.first_range);
    if (dst.len < pos + f.ranges_bytes.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.ranges_bytes.len], f.ranges_bytes);
    pos += f.ranges_bytes.len;
    if (f.ecn_counts) |e| {
        pos += try varint.encode(dst[pos..], e.ect0);
        pos += try varint.encode(dst[pos..], e.ect1);
        pos += try varint.encode(dst[pos..], e.ecn_ce);
    }
    return pos;
}

fn encodeStream(dst: []u8, f: types.Stream) Error!usize {
    var type_byte: u8 = 0x08;
    if (f.has_offset) type_byte |= 0x04;
    if (f.has_length) type_byte |= 0x02;
    if (f.fin) type_byte |= 0x01;

    var pos = try writeTypeOnly(dst, type_byte);
    pos += try varint.encode(dst[pos..], f.stream_id);
    if (f.has_offset) pos += try varint.encode(dst[pos..], f.offset);
    if (f.has_length) pos += try varint.encode(dst[pos..], f.data.len);
    if (dst.len < pos + f.data.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.data.len], f.data);
    pos += f.data.len;
    return pos;
}

fn encodeDatagram(dst: []u8, f: types.Datagram) Error!usize {
    const type_byte: u8 = if (f.has_length) 0x31 else 0x30;
    var pos = try writeTypeOnly(dst, type_byte);
    if (f.has_length) pos += try varint.encode(dst[pos..], f.data.len);
    if (dst.len < pos + f.data.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.data.len], f.data);
    pos += f.data.len;
    return pos;
}

fn encodeConnectionClose(dst: []u8, f: types.ConnectionClose) Error!usize {
    var pos = try writeTypeOnly(dst, if (f.is_transport) @as(u8, 0x1c) else 0x1d);
    pos += try varint.encode(dst[pos..], f.error_code);
    if (f.is_transport) {
        pos += try varint.encode(dst[pos..], f.frame_type);
    }
    pos += try varint.encode(dst[pos..], f.reason_phrase.len);
    if (dst.len < pos + f.reason_phrase.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.reason_phrase.len], f.reason_phrase);
    pos += f.reason_phrase.len;
    return pos;
}

fn encodePathAck(dst: []u8, f: types.PathAck) Error!usize {
    const frame_type = if (f.ecn_counts == null) frame_type_path_ack else frame_type_path_ack_ecn;
    var pos = try writeFrameType(dst, frame_type);
    pos += try varint.encode(dst[pos..], f.path_id);
    pos += try varint.encode(dst[pos..], f.largest_acked);
    pos += try varint.encode(dst[pos..], f.ack_delay);
    pos += try varint.encode(dst[pos..], f.range_count);
    pos += try varint.encode(dst[pos..], f.first_range);
    if (dst.len < pos + f.ranges_bytes.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.ranges_bytes.len], f.ranges_bytes);
    pos += f.ranges_bytes.len;
    if (f.ecn_counts) |e| {
        pos += try varint.encode(dst[pos..], e.ect0);
        pos += try varint.encode(dst[pos..], e.ect1);
        pos += try varint.encode(dst[pos..], e.ecn_ce);
    }
    return pos;
}

fn encodePathAbandon(dst: []u8, f: types.PathAbandon) Error!usize {
    var pos = try writeFrameType(dst, frame_type_path_abandon);
    pos += try varint.encode(dst[pos..], f.path_id);
    pos += try varint.encode(dst[pos..], f.error_code);
    return pos;
}

fn encodePathStatus(dst: []u8, frame_type: u64, f: types.PathStatus) Error!usize {
    var pos = try writeFrameType(dst, frame_type);
    pos += try varint.encode(dst[pos..], f.path_id);
    pos += try varint.encode(dst[pos..], f.sequence_number);
    return pos;
}

fn encodePathNewConnectionId(dst: []u8, f: types.PathNewConnectionId) Error!usize {
    var pos = try writeFrameType(dst, frame_type_path_new_connection_id);
    pos += try varint.encode(dst[pos..], f.path_id);
    pos += try varint.encode(dst[pos..], f.sequence_number);
    pos += try varint.encode(dst[pos..], f.retire_prior_to);
    if (dst.len < pos + 1) return Error.BufferTooSmall;
    dst[pos] = f.connection_id.len;
    pos += 1;
    if (dst.len < pos + f.connection_id.len) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + f.connection_id.len], f.connection_id.bytes[0..f.connection_id.len]);
    pos += f.connection_id.len;
    if (dst.len < pos + 16) return Error.BufferTooSmall;
    @memcpy(dst[pos .. pos + 16], &f.stateless_reset_token);
    pos += 16;
    return pos;
}

fn encodePathRetireConnectionId(dst: []u8, f: types.PathRetireConnectionId) Error!usize {
    var pos = try writeFrameType(dst, frame_type_path_retire_connection_id);
    pos += try varint.encode(dst[pos..], f.path_id);
    pos += try varint.encode(dst[pos..], f.sequence_number);
    return pos;
}

fn encodePathIdOnly(dst: []u8, frame_type: u64, path_id: u32) Error!usize {
    var pos = try writeFrameType(dst, frame_type);
    pos += try varint.encode(dst[pos..], path_id);
    return pos;
}

fn encodePathCidsBlocked(dst: []u8, f: types.PathCidsBlocked) Error!usize {
    var pos = try writeFrameType(dst, frame_type_path_cids_blocked);
    pos += try varint.encode(dst[pos..], f.path_id);
    pos += try varint.encode(dst[pos..], f.next_sequence_number);
    return pos;
}

// -- tests ---------------------------------------------------------------

test "encode PING produces 0x01" {
    var buf: [4]u8 = undefined;
    const written = try encode(&buf, .{ .ping = .{} });
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "encode PADDING writes count zero bytes" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0xff);
    const written = try encode(&buf, .{ .padding = .{ .count = 5 } });
    try std.testing.expectEqual(@as(usize, 5), written);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0 }, buf[0..5]);
    try std.testing.expectEqual(@as(u8, 0xff), buf[5]); // untouched
}

test "encodedLen agrees with bytes written for several frames" {
    const cases = [_]Frame{
        .{ .ping = .{} },
        .{ .padding = .{ .count = 7 } },
        .{ .max_data = .{ .maximum_data = 1 << 30 } },
        .{ .reset_stream = .{
            .stream_id = 4,
            .application_error_code = 0xab,
            .final_size = 4096,
        } },
        .{ .crypto = .{ .offset = 0, .data = "hello world" } },
        .{ .handshake_done = .{} },
    };
    for (cases) |f| {
        var buf: [256]u8 = undefined;
        const written = try encode(&buf, f);
        try std.testing.expectEqual(encodedLen(f), written);
    }
}

test "encode rejects buffer too small" {
    var tiny: [0]u8 = .{};
    try std.testing.expectError(Error.BufferTooSmall, encode(&tiny, .{ .ping = .{} }));
    var small: [1]u8 = undefined;
    try std.testing.expectError(
        Error.BufferTooSmall,
        encode(&small, .{ .reset_stream = .{
            .stream_id = 100,
            .application_error_code = 0,
            .final_size = 0,
        } }),
    );
}

// -- fuzz harness --------------------------------------------------------
//
// Build a `Frame` from corpus bytes (covering all 33 wire-shape
// variants nullq parses or emits: PADDING, PING, HANDSHAKE_DONE,
// RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, two STREAM shapes
// (LEN-prefixed and implicit-tail), two ACK shapes (with/without
// ECN), MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED,
// STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID,
// RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, two
// CONNECTION_CLOSE shapes (transport vs. application), DATAGRAM,
// PATH_ACK, PATH_ABANDON, PATH_STATUS_BACKUP/AVAILABLE,
// PATH_NEW_CONNECTION_ID, PATH_RETIRE_CONNECTION_ID, MAX_PATH_ID,
// PATHS_BLOCKED, PATH_CIDS_BLOCKED), then drive the encode → decode →
// re-encode pipeline. Properties:
//
// - No panic during encode or decode.
// - `decode` consumes exactly `bytes_consumed == encoded_len`.
// - The decoded frame re-encodes byte-for-byte to the original bytes
//   (canonical round-trip — varint length agreement plus payload
//   preservation).

test "fuzz: frame encode/decode canonical round-trip" {
    try std.testing.fuzz({}, fuzzFrameRoundTrip, .{});
}

fn fuzzFrameRoundTrip(_: void, smith: *std.testing.Smith) anyerror!void {
    const decode_mod = @import("decode.zig");
    const ack_range_mod = @import("ack_range.zig");

    var payload_buf: [96]u8 = undefined;
    smith.bytes(&payload_buf);
    const payload_len = smith.valueRangeAtMost(u8, 0, payload_buf.len);
    const payload = payload_buf[0..payload_len];

    var ranges_buf: [16]u8 = undefined;
    const range_count: u64 = if (smith.valueRangeAtMost(u8, 0, 1) == 0) 0 else 1;
    const ranges_len = if (range_count == 0) 0 else try ack_range_mod.writeRanges(
        &ranges_buf,
        &.{.{ .gap = 1, .length = 0 }},
    );

    var cid_buf: [20]u8 = undefined;
    smith.bytes(&cid_buf);
    const cid_len = smith.valueRangeAtMost(u8, 0, 20);
    const cid = wire_header.ConnId.fromSlice(cid_buf[0..cid_len]) catch return;

    var reset_token: [16]u8 = undefined;
    smith.bytes(&reset_token);

    const value: u64 = smith.value(u64) & varint.max_value;
    const path_id: u32 = smith.valueRangeAtMost(u8, 0, 255);

    // PATH_CHALLENGE / PATH_RESPONSE carry an 8-byte fixed payload.
    // Carve two non-overlapping windows out of `reset_token` so a
    // single corpus draw covers both.
    const challenge_data: [8]u8 = reset_token[0..8].*;
    const response_data: [8]u8 = reset_token[8..16].*;

    const frame: Frame = switch (smith.valueRangeAtMost(u8, 0, 32)) {
        0 => .{ .padding = .{ .count = smith.valueRangeAtMost(u8, 1, 16) } },
        1 => .{ .ping = .{} },
        2 => .{ .handshake_done = .{} },
        3 => .{ .reset_stream = .{
            .stream_id = value,
            .application_error_code = value >> 2,
            .final_size = value >> 3,
        } },
        4 => .{ .stop_sending = .{
            .stream_id = value,
            .application_error_code = value >> 4,
        } },
        5 => .{ .crypto = .{ .offset = value % 4096, .data = payload } },
        6 => .{ .new_token = .{ .token = payload } },
        7 => .{ .stream = .{
            .stream_id = value,
            .offset = if (smith.valueRangeAtMost(u8, 0, 1) == 0) 0 else value % 4096,
            .data = payload,
            .has_offset = smith.valueRangeAtMost(u8, 0, 1) == 1,
            .has_length = true,
            .fin = smith.valueRangeAtMost(u8, 0, 1) == 1,
        } },
        8 => .{ .stream = .{
            .stream_id = value,
            .data = payload,
            .has_length = false,
        } },
        9 => .{ .ack = .{
            .largest_acked = 32 + (value % 2048),
            .ack_delay = value % 1024,
            .first_range = value % 16,
            .range_count = range_count,
            .ranges_bytes = ranges_buf[0..ranges_len],
            .ecn_counts = null,
        } },
        10 => .{ .ack = .{
            .largest_acked = 32 + (value % 2048),
            .ack_delay = value % 1024,
            .first_range = value % 16,
            .range_count = range_count,
            .ranges_bytes = ranges_buf[0..ranges_len],
            .ecn_counts = .{ .ect0 = value % 17, .ect1 = value % 19, .ecn_ce = value % 23 },
        } },
        11 => .{ .max_data = .{ .maximum_data = value } },
        12 => .{ .max_stream_data = .{
            .stream_id = value >> 1,
            .maximum_stream_data = value,
        } },
        13 => .{ .max_streams = .{
            .bidi = smith.valueRangeAtMost(u8, 0, 1) == 0,
            .maximum_streams = value,
        } },
        14 => .{ .data_blocked = .{ .maximum_data = value } },
        15 => .{ .stream_data_blocked = .{
            .stream_id = value >> 1,
            .maximum_stream_data = value,
        } },
        16 => .{ .streams_blocked = .{
            .bidi = smith.valueRangeAtMost(u8, 0, 1) == 0,
            .maximum_streams = value,
        } },
        17 => .{ .new_connection_id = .{
            .sequence_number = value % 64,
            .retire_prior_to = value % 8,
            .connection_id = cid,
            .stateless_reset_token = reset_token,
        } },
        18 => .{ .retire_connection_id = .{ .sequence_number = value } },
        19 => .{ .path_challenge = .{ .data = challenge_data } },
        20 => .{ .path_response = .{ .data = response_data } },
        21 => .{ .connection_close = .{
            .is_transport = true,
            .error_code = value % 256,
            .frame_type = 0x06,
            .reason_phrase = payload,
        } },
        22 => .{ .connection_close = .{
            .is_transport = false,
            .error_code = value % 256,
            .reason_phrase = payload,
        } },
        23 => .{ .datagram = .{
            .data = payload,
            .has_length = smith.valueRangeAtMost(u8, 0, 1) == 0,
        } },
        24 => .{ .path_ack = .{
            .path_id = path_id,
            .largest_acked = 32 + (value % 2048),
            .ack_delay = value % 1024,
            .first_range = value % 16,
            .range_count = range_count,
            .ranges_bytes = ranges_buf[0..ranges_len],
            .ecn_counts = if (smith.valueRangeAtMost(u8, 0, 1) == 0)
                null
            else
                .{ .ect0 = 1, .ect1 = 2, .ecn_ce = 3 },
        } },
        25 => .{ .path_abandon = .{
            .path_id = path_id,
            .error_code = value,
        } },
        26 => .{ .path_status_backup = .{
            .path_id = path_id,
            .sequence_number = value,
        } },
        27 => .{ .path_status_available = .{
            .path_id = path_id,
            .sequence_number = value,
        } },
        28 => .{ .path_new_connection_id = .{
            .path_id = path_id,
            .sequence_number = value % 64,
            .retire_prior_to = value % 8,
            .connection_id = cid,
            .stateless_reset_token = reset_token,
        } },
        29 => .{ .path_retire_connection_id = .{
            .path_id = path_id,
            .sequence_number = value,
        } },
        30 => .{ .max_path_id = .{ .maximum_path_id = path_id } },
        31 => .{ .paths_blocked = .{ .maximum_path_id = path_id } },
        else => .{ .path_cids_blocked = .{
            .path_id = path_id,
            .next_sequence_number = value,
        } },
    };

    // The DATAGRAM/STREAM implicit-length variants extend to the end
    // of the encoded buffer when decoded — so the canonical re-encode
    // is byte-equal only when the original encoding's tail is exactly
    // the payload. That is true here because we encode each frame
    // alone (no trailing padding).
    var enc1: [1024]u8 = undefined;
    const len1 = encode(&enc1, frame) catch return;
    // encodedLen agrees with what we just wrote.
    try std.testing.expectEqual(encodedLen(frame), len1);

    const d = try decode_mod.decode(enc1[0..len1]);
    try std.testing.expectEqual(len1, d.bytes_consumed);

    var enc2: [1024]u8 = undefined;
    const len2 = try encode(&enc2, d.frame);
    try std.testing.expectEqual(encodedLen(d.frame), len2);
    try std.testing.expectEqualSlices(u8, enc1[0..len1], enc2[0..len2]);
}
