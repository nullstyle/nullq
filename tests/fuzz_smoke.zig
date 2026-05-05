const std = @import("std");
const nullq = @import("nullq");

const frame = nullq.frame;
const frame_types = frame.types;
const ack_range = frame.ack_range;
const varint = nullq.wire.varint;
const header = nullq.wire.header;
const transport_params = nullq.tls.transport_params;

fn randomVarint(rng: std.Random) u64 {
    return rng.int(u64) & varint.max_value;
}

fn randomBytes(rng: std.Random, buf: []u8) []const u8 {
    rng.bytes(buf);
    const len = @as(usize, rng.int(u8)) % (buf.len + 1);
    return buf[0..len];
}

fn expectFrameCanonicalRoundTrip(f: frame.Frame) !void {
    var encoded: [512]u8 = undefined;
    const encoded_len = try frame.encode(&encoded, f);
    try std.testing.expectEqual(frame.encodedLen(f), encoded_len);

    const decoded = try frame.decode(encoded[0..encoded_len]);
    try std.testing.expectEqual(encoded_len, decoded.bytes_consumed);

    var reencoded: [512]u8 = undefined;
    const reencoded_len = try frame.encode(&reencoded, decoded.frame);
    try std.testing.expectEqual(frame.encodedLen(decoded.frame), reencoded_len);
    try std.testing.expectEqualSlices(u8, encoded[0..encoded_len], reencoded[0..reencoded_len]);
}

fn makeRandomCid(rng: std.Random, storage: *[header.max_cid_len]u8) !header.ConnId {
    rng.bytes(storage);
    const len = @as(usize, rng.int(u8)) % (storage.len + 1);
    return header.ConnId.fromSlice(storage[0..len]);
}

fn makeRandomTransportCid(rng: std.Random, storage: *[nullq.conn.path.max_cid_len]u8) transport_params.ConnectionId {
    rng.bytes(storage);
    const len = @as(usize, rng.int(u8)) % (storage.len + 1);
    return transport_params.ConnectionId.fromSlice(storage[0..len]);
}

fn expectHeaderCanonicalRoundTrip(h: header.Header) !void {
    var encoded: [256]u8 = undefined;
    const encoded_len = try header.encode(&encoded, h);

    const short_dcid_len: u8 = switch (h) {
        .one_rtt => |one| one.dcid.len,
        else => 0,
    };
    const parsed = try header.parse(encoded[0..encoded_len], short_dcid_len);
    try std.testing.expect(parsed.pn_offset <= encoded_len);

    var reencoded: [256]u8 = undefined;
    const reencoded_len = try header.encode(&reencoded, parsed.header);
    try std.testing.expectEqualSlices(u8, encoded[0..encoded_len], reencoded[0..reencoded_len]);
}

test "fuzz smoke: varint fixed-width and malformed slices" {
    var prng = std.Random.DefaultPrng.init(0x7163_7661_7269_6e74);
    const rng = prng.random();

    const lengths = [_]u8{ 1, 2, 4, 8 };
    for (lengths) |len| {
        var i: usize = 0;
        while (i < 512) : (i += 1) {
            const max_for_len: u64 = switch (len) {
                1 => (1 << 6) - 1,
                2 => (1 << 14) - 1,
                4 => (1 << 30) - 1,
                8 => varint.max_value,
                else => unreachable,
            };
            const value = randomVarint(rng) % (max_for_len + 1);
            var encoded: [varint.max_len]u8 = undefined;
            const written = try varint.encodeFixed(&encoded, value, len);
            try std.testing.expectEqual(@as(usize, len), written);
            const decoded = try varint.decode(encoded[0..written]);
            try std.testing.expectEqual(value, decoded.value);
            try std.testing.expectEqual(len, decoded.bytes_read);
            if (len > 1) {
                try std.testing.expectError(
                    varint.Error.InsufficientBytes,
                    varint.decode(encoded[0 .. written - 1]),
                );
            }
        }
    }

    var raw: [varint.max_len]u8 = undefined;
    var i: usize = 0;
    while (i < 2048) : (i += 1) {
        rng.bytes(&raw);
        const len = @as(usize, rng.int(u8)) % (raw.len + 1);
        if (varint.decode(raw[0..len])) |decoded| {
            try std.testing.expect(decoded.bytes_read <= len);
            try std.testing.expect(decoded.value <= varint.max_value);
        } else |_| {}
    }
}

test "fuzz smoke: generated frame corpus round-trips canonically" {
    var prng = std.Random.DefaultPrng.init(0x7163_6672_616d_6573);
    const rng = prng.random();

    var payload: [96]u8 = undefined;
    var cid_storage: [header.max_cid_len]u8 = undefined;
    var ranges_buf: [32]u8 = undefined;
    var reset_token: [16]u8 = undefined;

    var i: usize = 0;
    while (i < 768) : (i += 1) {
        const data = randomBytes(rng, &payload);
        rng.bytes(&reset_token);
        rng.bytes(&cid_storage);
        const cid_len = @as(usize, rng.int(u8)) % (cid_storage.len + 1);
        const cid = try frame_types.ConnId.fromSlice(cid_storage[0..cid_len]);
        const path_id = @as(u32, rng.int(u8));
        const value = randomVarint(rng);

        const ranges_len = if ((rng.int(u8) & 1) == 0) blk: {
            const ranges = [_]frame_types.AckRange{.{ .gap = 1, .length = 0 }};
            break :blk try ack_range.writeRanges(&ranges_buf, &ranges);
        } else 0;
        const range_count: u64 = if (ranges_len == 0) 0 else 1;
        const ranges = ranges_buf[0..ranges_len];

        const f: frame.Frame = switch (i % 33) {
            0 => .{ .padding = .{ .count = 1 + @as(u64, rng.int(u3)) } },
            1 => .{ .ping = .{} },
            2 => .{ .handshake_done = .{} },
            3 => .{ .reset_stream = .{ .stream_id = value, .application_error_code = value >> 2, .final_size = value >> 3 } },
            4 => .{ .stop_sending = .{ .stream_id = value, .application_error_code = value >> 4 } },
            5 => .{ .crypto = .{ .offset = value % 4096, .data = data } },
            6 => .{ .new_token = .{ .token = data } },
            7 => .{ .stream = .{
                .stream_id = value,
                .offset = if ((rng.int(u8) & 1) == 0) value % 4096 else 0,
                .data = data,
                .has_offset = (rng.int(u8) & 1) == 0,
                .has_length = true,
                .fin = (rng.int(u8) & 1) == 0,
            } },
            8 => .{ .stream = .{ .stream_id = value, .data = data, .has_length = false } },
            9 => .{ .ack = .{
                .largest_acked = 32 + (value % 2048),
                .ack_delay = value % 1024,
                .first_range = value % 16,
                .range_count = range_count,
                .ranges_bytes = ranges,
                .ecn_counts = null,
            } },
            10 => .{ .ack = .{
                .largest_acked = 32 + (value % 2048),
                .ack_delay = value % 1024,
                .first_range = value % 16,
                .range_count = range_count,
                .ranges_bytes = ranges,
                .ecn_counts = .{ .ect0 = value % 17, .ect1 = value % 19, .ecn_ce = value % 23 },
            } },
            11 => .{ .max_data = .{ .maximum_data = value } },
            12 => .{ .max_stream_data = .{ .stream_id = value >> 1, .maximum_stream_data = value } },
            13 => .{ .max_streams = .{ .bidi = (rng.int(u8) & 1) == 0, .maximum_streams = value } },
            14 => .{ .data_blocked = .{ .maximum_data = value } },
            15 => .{ .stream_data_blocked = .{ .stream_id = value >> 1, .maximum_stream_data = value } },
            16 => .{ .streams_blocked = .{ .bidi = (rng.int(u8) & 1) == 0, .maximum_streams = value } },
            17 => .{ .new_connection_id = .{ .sequence_number = value % 64, .retire_prior_to = value % 8, .connection_id = cid, .stateless_reset_token = reset_token } },
            18 => .{ .retire_connection_id = .{ .sequence_number = value } },
            19 => .{ .path_challenge = .{ .data = reset_token[0..8].* } },
            20 => .{ .path_response = .{ .data = reset_token[8..16].* } },
            21 => .{ .connection_close = .{ .is_transport = true, .error_code = value % 256, .frame_type = 0x06, .reason_phrase = data } },
            22 => .{ .connection_close = .{ .is_transport = false, .error_code = value % 256, .reason_phrase = data } },
            23 => .{ .datagram = .{ .data = data, .has_length = (rng.int(u8) & 1) == 0 } },
            24 => .{ .path_ack = .{
                .path_id = path_id,
                .largest_acked = 32 + (value % 2048),
                .ack_delay = value % 1024,
                .first_range = value % 16,
                .range_count = range_count,
                .ranges_bytes = ranges,
                .ecn_counts = if ((rng.int(u8) & 1) == 0) null else .{ .ect0 = 1, .ect1 = 2, .ecn_ce = 3 },
            } },
            25 => .{ .path_abandon = .{ .path_id = path_id, .error_code = value } },
            26 => .{ .path_status_backup = .{ .path_id = path_id, .sequence_number = value } },
            27 => .{ .path_status_available = .{ .path_id = path_id, .sequence_number = value } },
            28 => .{ .path_new_connection_id = .{ .path_id = path_id, .sequence_number = value % 64, .retire_prior_to = value % 8, .connection_id = cid, .stateless_reset_token = reset_token } },
            29 => .{ .path_retire_connection_id = .{ .path_id = path_id, .sequence_number = value } },
            30 => .{ .max_path_id = .{ .maximum_path_id = path_id } },
            31 => .{ .paths_blocked = .{ .maximum_path_id = path_id } },
            else => .{ .path_cids_blocked = .{ .path_id = path_id, .next_sequence_number = value } },
        };

        try expectFrameCanonicalRoundTrip(f);
    }
}

test "fuzz smoke: malformed frame buffers terminate safely" {
    var prng = std.Random.DefaultPrng.init(0x7163_6261_6466_726d);
    const rng = prng.random();
    var raw: [128]u8 = undefined;

    var i: usize = 0;
    while (i < 2048) : (i += 1) {
        rng.bytes(&raw);
        const len = @as(usize, rng.int(u8)) % (raw.len + 1);
        if (frame.decode(raw[0..len])) |decoded| {
            try std.testing.expect(decoded.bytes_consumed > 0);
            try std.testing.expect(decoded.bytes_consumed <= len);
        } else |_| {}
    }
}

test "fuzz smoke: transport parameter codec canonicalizes generated params" {
    var prng = std.Random.DefaultPrng.init(0x7163_7470_6172_616d);
    const rng = prng.random();
    var cid_a: [nullq.conn.path.max_cid_len]u8 = undefined;
    var cid_b: [nullq.conn.path.max_cid_len]u8 = undefined;
    var cid_c: [nullq.conn.path.max_cid_len]u8 = undefined;

    var i: usize = 0;
    while (i < 512) : (i += 1) {
        var token: [16]u8 = undefined;
        rng.bytes(&token);
        const params: transport_params.Params = .{
            .original_destination_connection_id = if ((rng.int(u8) & 1) == 0) null else makeRandomTransportCid(rng, &cid_a),
            .max_idle_timeout_ms = randomVarint(rng) % 60_000,
            .stateless_reset_token = if ((rng.int(u8) & 1) == 0) null else token,
            .max_udp_payload_size = 1200 + (randomVarint(rng) % 2896),
            .initial_max_data = randomVarint(rng) % (16 * 1024 * 1024),
            .initial_max_stream_data_bidi_local = randomVarint(rng) % (1024 * 1024),
            .initial_max_stream_data_bidi_remote = randomVarint(rng) % (1024 * 1024),
            .initial_max_stream_data_uni = randomVarint(rng) % (1024 * 1024),
            .initial_max_streams_bidi = randomVarint(rng) % 256,
            .initial_max_streams_uni = randomVarint(rng) % 256,
            .ack_delay_exponent = randomVarint(rng) % 21,
            .max_ack_delay_ms = randomVarint(rng) % ((@as(u64, 1) << 14) - 1),
            .disable_active_migration = (rng.int(u8) & 1) == 0,
            .active_connection_id_limit = 2 + (randomVarint(rng) % 15),
            .initial_source_connection_id = if ((rng.int(u8) & 1) == 0) null else makeRandomTransportCid(rng, &cid_b),
            .retry_source_connection_id = if ((rng.int(u8) & 1) == 0) null else makeRandomTransportCid(rng, &cid_c),
            .max_datagram_frame_size = randomVarint(rng) % 4096,
            .initial_max_path_id = if ((rng.int(u8) & 1) == 0) null else @as(u32, rng.int(u8)),
        };

        var encoded: [512]u8 = undefined;
        const encoded_len = try params.encode(&encoded);
        const decoded = try transport_params.Params.decode(encoded[0..encoded_len]);
        var reencoded: [512]u8 = undefined;
        const reencoded_len = try decoded.encode(&reencoded);
        try std.testing.expectEqualSlices(u8, encoded[0..encoded_len], reencoded[0..reencoded_len]);
    }
}

test "fuzz smoke: malformed transport parameter buffers terminate safely" {
    var prng = std.Random.DefaultPrng.init(0x7163_6261_6474_7061);
    const rng = prng.random();
    var raw: [128]u8 = undefined;

    var i: usize = 0;
    while (i < 2048) : (i += 1) {
        rng.bytes(&raw);
        const len = @as(usize, rng.int(u8)) % (raw.len + 1);
        if (transport_params.Params.decode(raw[0..len])) |decoded| {
            try std.testing.expect(decoded.ack_delay_exponent <= 20);
            try std.testing.expect(decoded.active_connection_id_limit >= 2);
            if (decoded.initial_max_path_id) |path_id| {
                try std.testing.expect(path_id <= std.math.maxInt(u32));
            }
        } else |_| {}
    }
}

test "fuzz smoke: packet headers round-trip generated variants" {
    var prng = std.Random.DefaultPrng.init(0x7163_6865_6164_6572);
    const rng = prng.random();
    var dcid_buf: [header.max_cid_len]u8 = undefined;
    var scid_buf: [header.max_cid_len]u8 = undefined;
    var token_buf: [48]u8 = undefined;
    var versions_buf: [12]u8 = undefined;
    var tag: [16]u8 = undefined;

    var i: usize = 0;
    while (i < 384) : (i += 1) {
        const dcid = try makeRandomCid(rng, &dcid_buf);
        const scid = try makeRandomCid(rng, &scid_buf);
        const token = randomBytes(rng, &token_buf);
        rng.bytes(&tag);
        std.mem.writeInt(u32, versions_buf[0..4], 0x00000001, .big);
        std.mem.writeInt(u32, versions_buf[4..8], 0x6b3343cf, .big);
        std.mem.writeInt(u32, versions_buf[8..12], 0xff000020, .big);

        const pn_length = header.PnLength.fromTwoBits(@intCast(rng.int(u8) & 0x03));
        const pn_mask = (@as(u64, 1) << @intCast(pn_length.bytes() * 8)) - 1;
        const pn = randomVarint(rng) & pn_mask;
        const h: header.Header = switch (i % 6) {
            0 => .{ .initial = .{
                .version = 1,
                .dcid = dcid,
                .scid = scid,
                .token = token,
                .pn_length = pn_length,
                .pn_truncated = pn,
                .payload_length = 16 + pn_length.bytes(),
                .reserved_bits = @intCast(rng.int(u8) & 0x03),
            } },
            1 => .{ .zero_rtt = .{
                .version = 1,
                .dcid = dcid,
                .scid = scid,
                .pn_length = pn_length,
                .pn_truncated = pn,
                .payload_length = 32 + pn_length.bytes(),
                .reserved_bits = @intCast(rng.int(u8) & 0x03),
            } },
            2 => .{ .handshake = .{
                .version = 1,
                .dcid = dcid,
                .scid = scid,
                .pn_length = pn_length,
                .pn_truncated = pn,
                .payload_length = 24 + pn_length.bytes(),
                .reserved_bits = @intCast(rng.int(u8) & 0x03),
            } },
            3 => .{ .retry = .{
                .version = 1,
                .dcid = dcid,
                .scid = scid,
                .retry_token = token,
                .integrity_tag = tag,
                .unused_bits = @intCast(rng.int(u8) & 0x0f),
            } },
            4 => .{ .one_rtt = .{
                .dcid = dcid,
                .spin_bit = (rng.int(u8) & 1) == 0,
                .reserved_bits = @intCast(rng.int(u8) & 0x03),
                .key_phase = (rng.int(u8) & 1) == 0,
                .pn_length = pn_length,
                .pn_truncated = pn,
            } },
            else => .{ .version_negotiation = .{
                .unused_bits = @intCast(rng.int(u8) & 0x7f),
                .dcid = dcid,
                .scid = scid,
                .versions_bytes = &versions_buf,
            } },
        };
        try expectHeaderCanonicalRoundTrip(h);
    }
}

test "fuzz smoke: malformed packet headers terminate safely" {
    var prng = std.Random.DefaultPrng.init(0x7163_6261_6468_6472);
    const rng = prng.random();
    var raw: [160]u8 = undefined;

    var i: usize = 0;
    while (i < 2048) : (i += 1) {
        rng.bytes(&raw);
        const len = @as(usize, rng.int(u8)) % (raw.len + 1);
        const short_dcid_len: u8 = @intCast(@as(usize, rng.int(u8)) % (header.max_cid_len + 1));
        if (header.parse(raw[0..len], short_dcid_len)) |parsed| {
            try std.testing.expect(parsed.pn_offset <= len);
            try std.testing.expect(parsed.header.dcid().len <= header.max_cid_len);
        } else |_| {}
    }
}

test "fuzz smoke: ACK range iterator preserves descending intervals" {
    var prng = std.Random.DefaultPrng.init(0x7163_6163_6b72_6e67);
    const rng = prng.random();
    var ranges: [6]frame_types.AckRange = undefined;
    var ranges_buf: [96]u8 = undefined;

    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const largest = 100 + (randomVarint(rng) % 10_000);
        const first_range = randomVarint(rng) % 16;
        var previous_smallest = largest - first_range;
        const wanted = @as(usize, rng.int(u8)) % (ranges.len + 1);
        var count: usize = 0;
        while (count < wanted) : (count += 1) {
            const gap = randomVarint(rng) % 8;
            if (previous_smallest < gap + 2) break;
            const largest_this = previous_smallest - gap - 2;
            const length = @min(randomVarint(rng) % 16, largest_this);
            ranges[count] = .{ .gap = gap, .length = length };
            previous_smallest = largest_this - length;
        }

        const ranges_len = try ack_range.writeRanges(&ranges_buf, ranges[0..count]);
        try std.testing.expectEqual(ack_range.rangesEncodedLen(ranges[0..count]), ranges_len);

        var it = ack_range.iter(.{
            .largest_acked = largest,
            .ack_delay = 0,
            .first_range = first_range,
            .range_count = count,
            .ranges_bytes = ranges_buf[0..ranges_len],
        });

        var last_smallest: ?u64 = null;
        var emitted: usize = 0;
        while (try it.next()) |interval| {
            try std.testing.expect(interval.smallest <= interval.largest);
            if (last_smallest) |last| try std.testing.expect(interval.largest + 1 < last);
            last_smallest = interval.smallest;
            emitted += 1;
        }
        try std.testing.expectEqual(count + 1, emitted);
    }
}

test "fuzz smoke: STREAM receive reassembly handles shuffled duplicates" {
    var prng = std.Random.DefaultPrng.init(0x7163_7374_7265_616d);
    const rng = prng.random();
    const allocator = std.testing.allocator;

    const total: usize = 4096;
    const chunk: usize = 64;
    const chunks = total / chunk;

    var data: [total]u8 = undefined;
    var indices: [chunks]usize = undefined;
    var read_buf: [257]u8 = undefined;

    var run: usize = 0;
    while (run < 24) : (run += 1) {
        rng.bytes(&data);
        for (&indices, 0..) |*slot, idx| slot.* = idx;
        rng.shuffle(usize, &indices);

        var stream = nullq.conn.RecvStream.init(allocator);
        defer stream.deinit();

        for (indices, 0..) |idx, order| {
            const off = idx * chunk;
            try stream.recv(@intCast(off), data[off..][0..chunk], false);
            if ((order % 7) == 0) {
                const overlap_off = if (off == 0) off else off - @min(off, chunk / 2);
                const overlap_len = @min(chunk, total - overlap_off);
                try stream.recv(@intCast(overlap_off), data[overlap_off..][0..overlap_len], false);
            }
        }
        try stream.recv(@intCast(total), "", true);

        var consumed: usize = 0;
        while (consumed < total) {
            const n = stream.read(&read_buf);
            try std.testing.expect(n > 0);
            try std.testing.expectEqualSlices(u8, data[consumed..][0..n], read_buf[0..n]);
            consumed += n;
        }
        try std.testing.expectEqual(total, consumed);
        try std.testing.expectEqual(nullq.conn.recv_stream.State.data_recvd, stream.state);
    }
}
