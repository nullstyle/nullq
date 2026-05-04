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

pub const Error = varint.Error || wire_header.Error;

pub const frame_type_path_ack: u64 = 0x3e;
pub const frame_type_path_ack_ecn: u64 = 0x3f;
pub const frame_type_path_abandon: u64 = 0x3e75;
pub const frame_type_path_status_backup: u64 = 0x3e76;
pub const frame_type_path_status_available: u64 = 0x3e77;
pub const frame_type_path_new_connection_id: u64 = 0x3e78;
pub const frame_type_path_retire_connection_id: u64 = 0x3e79;
pub const frame_type_max_path_id: u64 = 0x3e7a;
pub const frame_type_paths_blocked: u64 = 0x3e7b;
pub const frame_type_path_cids_blocked: u64 = 0x3e7c;

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
