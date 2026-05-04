//! nullq.frame — QUIC frame encoders, decoders, and types (RFC 9000 §19).
//!
//! All 20 frame types are implemented: 18 fixed-shape frames plus
//! ACK (range-encoded) and STREAM (FIN/LEN/OFF flag bits).

const std = @import("std");

pub const types = @import("types.zig");
pub const ack_range = @import("ack_range.zig");
pub const decode = @import("decode.zig").decode;
pub const encode = @import("encode.zig").encode;
pub const encodedLen = @import("encode.zig").encodedLen;

/// Walk every frame in a packet payload. Frames borrow slices from
/// `src`, so the iterator must outlive the bytes it scans.
pub fn iter(src: []const u8) Iterator {
    return .{ .rest = src };
}

pub const Iterator = struct {
    rest: []const u8,

    pub fn next(self: *Iterator) DecodeError!?Frame {
        if (self.rest.len == 0) return null;
        const d = try decode(self.rest);
        self.rest = self.rest[d.bytes_consumed..];
        return d.frame;
    }
};

pub const Frame = types.Frame;
pub const DecodeError = @import("decode.zig").Error;
pub const EncodeError = @import("encode.zig").Error;

test {
    _ = types;
    _ = ack_range;
    _ = @import("decode.zig");
    _ = @import("encode.zig");
}

// -- round-trip tests ----------------------------------------------------

fn roundTrip(frame: Frame) !@import("decode.zig").Decoded {
    var buf: [512]u8 = undefined;
    const written = try encode(&buf, frame);
    try std.testing.expectEqual(encodedLen(frame), written);
    const d = try decode(buf[0..written]);
    try std.testing.expectEqual(written, d.bytes_consumed);
    return d;
}

test "round-trip: PADDING with count" {
    const f: Frame = .{ .padding = .{ .count = 12 } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .padding);
    try std.testing.expectEqual(@as(u64, 12), d.frame.padding.count);
}

test "round-trip: PING" {
    const f: Frame = .{ .ping = .{} };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .ping);
}

test "round-trip: HANDSHAKE_DONE" {
    const f: Frame = .{ .handshake_done = .{} };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .handshake_done);
}

test "round-trip: RESET_STREAM" {
    const f: Frame = .{ .reset_stream = .{
        .stream_id = 4,
        .application_error_code = 0xff,
        .final_size = 1024,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .reset_stream);
    try std.testing.expectEqual(@as(u64, 4), d.frame.reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 0xff), d.frame.reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 1024), d.frame.reset_stream.final_size);
}

test "round-trip: STOP_SENDING" {
    const f: Frame = .{ .stop_sending = .{
        .stream_id = 8,
        .application_error_code = 42,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .stop_sending);
    try std.testing.expectEqual(@as(u64, 8), d.frame.stop_sending.stream_id);
    try std.testing.expectEqual(@as(u64, 42), d.frame.stop_sending.application_error_code);
}

test "round-trip: CRYPTO" {
    const data = "ClientHello bytes go here";
    const f: Frame = .{ .crypto = .{ .offset = 1234, .data = data } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .crypto);
    try std.testing.expectEqual(@as(u64, 1234), d.frame.crypto.offset);
    try std.testing.expectEqualSlices(u8, data, d.frame.crypto.data);
}

test "round-trip: CRYPTO with empty payload" {
    const f: Frame = .{ .crypto = .{ .offset = 0, .data = "" } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .crypto);
    try std.testing.expectEqual(@as(usize, 0), d.frame.crypto.data.len);
}

test "round-trip: NEW_TOKEN" {
    const tok = "an-issued-retry-token";
    const f: Frame = .{ .new_token = .{ .token = tok } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .new_token);
    try std.testing.expectEqualSlices(u8, tok, d.frame.new_token.token);
}

test "round-trip: MAX_DATA" {
    const f: Frame = .{ .max_data = .{ .maximum_data = 1 << 28 } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .max_data);
    try std.testing.expectEqual(@as(u64, 1 << 28), d.frame.max_data.maximum_data);
}

test "round-trip: MAX_STREAM_DATA" {
    const f: Frame = .{ .max_stream_data = .{
        .stream_id = 16,
        .maximum_stream_data = 65536,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .max_stream_data);
    try std.testing.expectEqual(@as(u64, 16), d.frame.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 65536), d.frame.max_stream_data.maximum_stream_data);
}

test "round-trip: MAX_STREAMS bidi and uni" {
    {
        const f: Frame = .{ .max_streams = .{ .bidi = true, .maximum_streams = 100 } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .max_streams);
        try std.testing.expectEqual(true, d.frame.max_streams.bidi);
        try std.testing.expectEqual(@as(u64, 100), d.frame.max_streams.maximum_streams);
    }
    {
        const f: Frame = .{ .max_streams = .{ .bidi = false, .maximum_streams = 50 } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .max_streams);
        try std.testing.expectEqual(false, d.frame.max_streams.bidi);
        try std.testing.expectEqual(@as(u64, 50), d.frame.max_streams.maximum_streams);
    }
}

test "round-trip: DATA_BLOCKED" {
    const f: Frame = .{ .data_blocked = .{ .maximum_data = 4096 } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .data_blocked);
    try std.testing.expectEqual(@as(u64, 4096), d.frame.data_blocked.maximum_data);
}

test "round-trip: STREAM_DATA_BLOCKED" {
    const f: Frame = .{ .stream_data_blocked = .{
        .stream_id = 4,
        .maximum_stream_data = 8192,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .stream_data_blocked);
}

test "round-trip: STREAMS_BLOCKED bidi and uni" {
    {
        const f: Frame = .{ .streams_blocked = .{ .bidi = true, .maximum_streams = 8 } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .streams_blocked);
        try std.testing.expectEqual(true, d.frame.streams_blocked.bidi);
    }
    {
        const f: Frame = .{ .streams_blocked = .{ .bidi = false, .maximum_streams = 4 } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .streams_blocked);
        try std.testing.expectEqual(false, d.frame.streams_blocked.bidi);
    }
}

test "round-trip: NEW_CONNECTION_ID with stateless reset token" {
    const cid_bytes = [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4 };
    const reset: [16]u8 = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const f: Frame = .{ .new_connection_id = .{
        .sequence_number = 7,
        .retire_prior_to = 3,
        .connection_id = try types.ConnId.fromSlice(&cid_bytes),
        .stateless_reset_token = reset,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .new_connection_id);
    const got = d.frame.new_connection_id;
    try std.testing.expectEqual(@as(u64, 7), got.sequence_number);
    try std.testing.expectEqual(@as(u64, 3), got.retire_prior_to);
    try std.testing.expectEqualSlices(u8, &cid_bytes, got.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &reset, &got.stateless_reset_token);
}

test "round-trip: RETIRE_CONNECTION_ID" {
    const f: Frame = .{ .retire_connection_id = .{ .sequence_number = 12 } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .retire_connection_id);
    try std.testing.expectEqual(@as(u64, 12), d.frame.retire_connection_id.sequence_number);
}

test "round-trip: PATH_CHALLENGE / PATH_RESPONSE" {
    const data: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    {
        const f: Frame = .{ .path_challenge = .{ .data = data } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .path_challenge);
        try std.testing.expectEqualSlices(u8, &data, &d.frame.path_challenge.data);
    }
    {
        const f: Frame = .{ .path_response = .{ .data = data } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .path_response);
        try std.testing.expectEqualSlices(u8, &data, &d.frame.path_response.data);
    }
}

test "round-trip: PATH_ACK without and with ECN" {
    var ranges_buf: [16]u8 = undefined;
    const ranges_in = [_]types.AckRange{.{ .gap = 1, .length = 2 }};
    const ranges_len = try ack_range.writeRanges(&ranges_buf, &ranges_in);
    {
        const f: Frame = .{ .path_ack = .{
            .path_id = 2,
            .largest_acked = 100,
            .ack_delay = 7,
            .first_range = 4,
            .range_count = 1,
            .ranges_bytes = ranges_buf[0..ranges_len],
            .ecn_counts = null,
        } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .path_ack);
        const got = d.frame.path_ack;
        try std.testing.expectEqual(@as(u32, 2), got.path_id);
        try std.testing.expectEqual(@as(u64, 100), got.largest_acked);
        try std.testing.expectEqual(@as(u64, 1), got.range_count);
    }
    {
        const f: Frame = .{ .path_ack = .{
            .path_id = 3,
            .largest_acked = 44,
            .ack_delay = 1,
            .first_range = 0,
            .range_count = 0,
            .ranges_bytes = &.{},
            .ecn_counts = .{ .ect0 = 5, .ect1 = 6, .ecn_ce = 7 },
        } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .path_ack);
        try std.testing.expectEqual(@as(u32, 3), d.frame.path_ack.path_id);
        try std.testing.expect(d.frame.path_ack.ecn_counts != null);
        try std.testing.expectEqual(@as(u64, 7), d.frame.path_ack.ecn_counts.?.ecn_ce);
    }
}

test "round-trip: draft-21 multipath control frames" {
    const cid_bytes = [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4 };
    const reset: [16]u8 = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    {
        const d = try roundTrip(.{ .path_abandon = .{ .path_id = 4, .error_code = 0x3e } });
        try std.testing.expect(d.frame == .path_abandon);
        try std.testing.expectEqual(@as(u32, 4), d.frame.path_abandon.path_id);
    }
    {
        const d = try roundTrip(.{ .path_status_backup = .{ .path_id = 1, .sequence_number = 9 } });
        try std.testing.expect(d.frame == .path_status_backup);
        try std.testing.expectEqual(@as(u64, 9), d.frame.path_status_backup.sequence_number);
    }
    {
        const d = try roundTrip(.{ .path_status_available = .{ .path_id = 1, .sequence_number = 10 } });
        try std.testing.expect(d.frame == .path_status_available);
        try std.testing.expectEqual(@as(u64, 10), d.frame.path_status_available.sequence_number);
    }
    {
        const d = try roundTrip(.{ .path_new_connection_id = .{
            .path_id = 2,
            .sequence_number = 7,
            .retire_prior_to = 3,
            .connection_id = try types.ConnId.fromSlice(&cid_bytes),
            .stateless_reset_token = reset,
        } });
        try std.testing.expect(d.frame == .path_new_connection_id);
        const got = d.frame.path_new_connection_id;
        try std.testing.expectEqual(@as(u32, 2), got.path_id);
        try std.testing.expectEqualSlices(u8, &cid_bytes, got.connection_id.slice());
        try std.testing.expectEqualSlices(u8, &reset, &got.stateless_reset_token);
    }
    {
        const d = try roundTrip(.{ .path_retire_connection_id = .{ .path_id = 2, .sequence_number = 7 } });
        try std.testing.expect(d.frame == .path_retire_connection_id);
        try std.testing.expectEqual(@as(u64, 7), d.frame.path_retire_connection_id.sequence_number);
    }
    {
        const d = try roundTrip(.{ .max_path_id = .{ .maximum_path_id = 32 } });
        try std.testing.expect(d.frame == .max_path_id);
        try std.testing.expectEqual(@as(u32, 32), d.frame.max_path_id.maximum_path_id);
    }
    {
        const d = try roundTrip(.{ .paths_blocked = .{ .maximum_path_id = 3 } });
        try std.testing.expect(d.frame == .paths_blocked);
        try std.testing.expectEqual(@as(u32, 3), d.frame.paths_blocked.maximum_path_id);
    }
    {
        const d = try roundTrip(.{ .path_cids_blocked = .{ .path_id = 2, .next_sequence_number = 5 } });
        try std.testing.expect(d.frame == .path_cids_blocked);
        try std.testing.expectEqual(@as(u64, 5), d.frame.path_cids_blocked.next_sequence_number);
    }
}

test "draft-21 multipath extended frame types use varint encodings" {
    var buf: [32]u8 = undefined;
    const n = try encode(&buf, .{ .path_abandon = .{ .path_id = 1, .error_code = 0 } });
    try std.testing.expect(n >= 2);
    try std.testing.expectEqualSlices(u8, &.{ 0x7e, 0x75 }, buf[0..2]);
}

test "round-trip: CONNECTION_CLOSE transport with frame_type and reason" {
    const f: Frame = .{
        .connection_close = .{
            .is_transport = true,
            .error_code = 0x01, // INTERNAL_ERROR
            .frame_type = 0x06, // CRYPTO
            .reason_phrase = "TLS handshake failed",
        },
    };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .connection_close);
    const got = d.frame.connection_close;
    try std.testing.expectEqual(true, got.is_transport);
    try std.testing.expectEqual(@as(u64, 0x01), got.error_code);
    try std.testing.expectEqual(@as(u64, 0x06), got.frame_type);
    try std.testing.expectEqualSlices(u8, "TLS handshake failed", got.reason_phrase);
}

test "round-trip: CONNECTION_CLOSE application without frame_type" {
    const f: Frame = .{ .connection_close = .{
        .is_transport = false,
        .error_code = 42,
        .reason_phrase = "",
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .connection_close);
    const got = d.frame.connection_close;
    try std.testing.expectEqual(false, got.is_transport);
    try std.testing.expectEqual(@as(u64, 42), got.error_code);
    try std.testing.expectEqual(@as(usize, 0), got.reason_phrase.len);
}

test "round-trip: ACK with no subsequent ranges" {
    const f: Frame = .{ .ack = .{
        .largest_acked = 100,
        .ack_delay = 50,
        .first_range = 5,
        .range_count = 0,
        .ranges_bytes = &[_]u8{},
        .ecn_counts = null,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .ack);
    const got = d.frame.ack;
    try std.testing.expectEqual(@as(u64, 100), got.largest_acked);
    try std.testing.expectEqual(@as(u64, 50), got.ack_delay);
    try std.testing.expectEqual(@as(u64, 5), got.first_range);
    try std.testing.expectEqual(@as(u64, 0), got.range_count);
    try std.testing.expectEqual(@as(?types.EcnCounts, null), got.ecn_counts);
}

test "round-trip: ACK with multi-range descent and Iterator agreement" {
    var ranges_buf: [16]u8 = undefined;
    const ranges_in = [_]types.AckRange{
        .{ .gap = 1, .length = 4 },
        .{ .gap = 4, .length = 2 },
    };
    const ranges_len = try ack_range.writeRanges(&ranges_buf, &ranges_in);

    const f: Frame = .{ .ack = .{
        .largest_acked = 100,
        .ack_delay = 0,
        .first_range = 5,
        .range_count = 2,
        .ranges_bytes = ranges_buf[0..ranges_len],
        .ecn_counts = null,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .ack);

    var it = ack_range.iter(d.frame.ack);
    const a = (try it.next()).?;
    const b = (try it.next()).?;
    const c = (try it.next()).?;
    try std.testing.expectEqual(@as(?ack_range.Interval, null), try it.next());

    try std.testing.expectEqual(@as(u64, 95), a.smallest);
    try std.testing.expectEqual(@as(u64, 100), a.largest);
    try std.testing.expectEqual(@as(u64, 88), b.smallest);
    try std.testing.expectEqual(@as(u64, 92), b.largest);
    try std.testing.expectEqual(@as(u64, 80), c.smallest);
    try std.testing.expectEqual(@as(u64, 82), c.largest);
}

test "round-trip: ACK with ECN counts (type 0x03)" {
    const f: Frame = .{ .ack = .{
        .largest_acked = 50,
        .ack_delay = 1,
        .first_range = 10,
        .range_count = 0,
        .ranges_bytes = &[_]u8{},
        .ecn_counts = .{ .ect0 = 100, .ect1 = 200, .ecn_ce = 3 },
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .ack);
    const got = d.frame.ack;
    try std.testing.expect(got.ecn_counts != null);
    try std.testing.expectEqual(@as(u64, 100), got.ecn_counts.?.ect0);
    try std.testing.expectEqual(@as(u64, 200), got.ecn_counts.?.ect1);
    try std.testing.expectEqual(@as(u64, 3), got.ecn_counts.?.ecn_ce);
}

test "round-trip: STREAM all 8 type-byte combinations" {
    const data = "stream-payload";
    var combos: usize = 0;
    while (combos < 8) : (combos += 1) {
        const has_offset = (combos & 0b100) != 0;
        const has_length = (combos & 0b010) != 0;
        const fin = (combos & 0b001) != 0;
        const f: Frame = .{ .stream = .{
            .stream_id = 4,
            .offset = if (has_offset) 1024 else 0,
            .data = data,
            .has_offset = has_offset,
            .has_length = has_length,
            .fin = fin,
        } };
        const d = try roundTrip(f);
        try std.testing.expect(d.frame == .stream);
        const got = d.frame.stream;
        try std.testing.expectEqual(@as(u64, 4), got.stream_id);
        try std.testing.expectEqual(if (has_offset) @as(u64, 1024) else 0, got.offset);
        try std.testing.expectEqual(has_offset, got.has_offset);
        try std.testing.expectEqual(has_length, got.has_length);
        try std.testing.expectEqual(fin, got.fin);
        try std.testing.expectEqualSlices(u8, data, got.data);
    }
}

test "round-trip: STREAM with FIN and empty payload" {
    const f: Frame = .{ .stream = .{
        .stream_id = 8,
        .data = "",
        .has_offset = false,
        .has_length = true,
        .fin = true,
    } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .stream);
    try std.testing.expectEqual(true, d.frame.stream.fin);
    try std.testing.expectEqual(@as(usize, 0), d.frame.stream.data.len);
}

test "round-trip: DATAGRAM with LEN flag" {
    const f: Frame = .{ .datagram = .{ .data = "hello-dgram", .has_length = true } };
    const d = try roundTrip(f);
    try std.testing.expect(d.frame == .datagram);
    try std.testing.expectEqualStrings("hello-dgram", d.frame.datagram.data);
    try std.testing.expect(d.frame.datagram.has_length);
}

test "round-trip: DATAGRAM without LEN runs to end of buffer" {
    var buf: [64]u8 = undefined;
    const written = try encode(&buf, .{ .datagram = .{ .data = "tail-only", .has_length = false } });
    try std.testing.expectEqual(@as(usize, 1 + 9), written);
    const d = try decode(buf[0..written]);
    try std.testing.expect(d.frame == .datagram);
    try std.testing.expectEqualStrings("tail-only", d.frame.datagram.data);
    try std.testing.expect(!d.frame.datagram.has_length);
    try std.testing.expectEqual(written, d.bytes_consumed);
}

test "iter walks multiple frames in a payload" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += try encode(buf[pos..], .{ .ping = .{} });
    pos += try encode(buf[pos..], .{ .max_data = .{ .maximum_data = 1 << 20 } });
    pos += try encode(buf[pos..], .{ .padding = .{ .count = 5 } });
    pos += try encode(buf[pos..], .{ .stream = .{
        .stream_id = 4,
        .data = "abc",
        .has_offset = false,
        .has_length = true,
        .fin = true,
    } });

    var it = iter(buf[0..pos]);
    const f0 = (try it.next()).?;
    try std.testing.expect(f0 == .ping);
    const f1 = (try it.next()).?;
    try std.testing.expect(f1 == .max_data);
    try std.testing.expectEqual(@as(u64, 1 << 20), f1.max_data.maximum_data);
    const f2 = (try it.next()).?;
    try std.testing.expect(f2 == .padding);
    try std.testing.expectEqual(@as(u64, 5), f2.padding.count);
    const f3 = (try it.next()).?;
    try std.testing.expect(f3 == .stream);
    try std.testing.expectEqualStrings("abc", f3.stream.data);
    try std.testing.expectEqual(true, f3.stream.fin);
    try std.testing.expectEqual(@as(?Frame, null), try it.next());
}

test "iter on empty input yields null" {
    var it = iter(&[_]u8{});
    try std.testing.expectEqual(@as(?Frame, null), try it.next());
}

test "STREAM without LEN: data spans the rest of the input" {
    // Manually construct: type=0x08 (no flags) | stream_id=4 | data
    const wire = [_]u8{
        0x08, // STREAM, no OFF, no LEN, no FIN
        0x04, // stream_id varint = 4
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
    };
    const d = try decode(&wire);
    try std.testing.expect(d.frame == .stream);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee }, d.frame.stream.data);
    try std.testing.expectEqual(@as(usize, wire.len), d.bytes_consumed);
    try std.testing.expectEqual(false, d.frame.stream.has_length);
}
