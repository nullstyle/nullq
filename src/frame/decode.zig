//! Frame decoder for the 18 fixed-shape QUIC frame types (RFC 9000 §19).
//!
//! `decode(src)` reads one frame from the start of `src` and returns
//! the typed value plus the number of bytes consumed. Callers
//! typically iterate by feeding `src[bytes_consumed..]` back in until
//! `src` is exhausted or an error fires.
//!
//! All slice-typed fields in the returned `Frame` (Crypto.data,
//! NewToken.token, ConnectionClose.reason_phrase) point into the
//! input slice — they are *not* copied.

const std = @import("std");
const types = @import("types.zig");
const varint = @import("../wire/varint.zig");
const wire_header = @import("../wire/header.zig");

const Frame = types.Frame;

const frame_type_path_ack: u64 = 0x3e;
const frame_type_path_ack_ecn: u64 = 0x3f;
const frame_type_path_abandon: u64 = 0x3e75;
const frame_type_path_status_backup: u64 = 0x3e76;
const frame_type_path_status_available: u64 = 0x3e77;
const frame_type_path_new_connection_id: u64 = 0x3e78;
const frame_type_path_retire_connection_id: u64 = 0x3e79;
const frame_type_max_path_id: u64 = 0x3e7a;
const frame_type_paths_blocked: u64 = 0x3e7b;
const frame_type_path_cids_blocked: u64 = 0x3e7c;
const frame_type_alternative_v4_address: u64 = 0x1d5845e2;
const frame_type_alternative_v6_address: u64 = 0x1d5845e3;

/// Errors `decode` can return. Wire-level varint/CID errors plus:
/// - `UnknownFrameType` — frame type byte/varint is not a recognized v1
///   or supported draft-21 multipath type.
/// - `PathIdTooLarge` — multipath frame's path_id exceeds `u32` range.
/// - `AckRangeCountTooLarge` — incoming ACK / PATH_ACK frame declares
///   more ranges than `max_incoming_ack_ranges` (RFC 9000 §13.1
///   recommends bounding ACK range processing; the hardening guide §4.7
///   classes unbounded ACK-range loops as a DoS surface).
/// - `OverlappingAckRanges` — incoming ACK / PATH_ACK frame's range
///   list contains ranges that overlap or whose gap+length arithmetic
///   underflows the descending PN cursor. Per RFC 9000 §19.3.1, ranges
///   are encoded strictly descending from `largest_acked`; any
///   redundancy is malformed and a peer that emits it is wasting
///   decoder cycles. Hardening guide §4.7 calls for fail-fast at
///   decode rather than letting downstream loss-detection see ranges
///   that overlap each other.
pub const Error = varint.Error || wire_header.Error || error{
    UnknownFrameType,
    PathIdTooLarge,
    AckRangeCountTooLarge,
    OverlappingAckRanges,
};

/// Upper bound on the number of additional gap+length range pairs an
/// incoming ACK or PATH_ACK frame may declare. Mirrors the local emit
/// cap (`conn.ack_tracker.max_ranges = 255`) with one slot of margin
/// so well-behaved peers never trip the cap. Caps both the per-frame
/// CPU cost of the decoder loop and the downstream loss-detection
/// walk that has to validate every range against sent-PN history.
///
/// The actual byte-budget cap is implicit (a 4 KiB plaintext budget
/// limits how many varint pairs fit anyway) but we cap explicitly so
/// the loop can't be amplified by varint lengths shorter than the
/// 1-byte minimum we assume.
pub const max_incoming_ack_ranges: u64 = 256;

/// Result of `decode`: the parsed frame and how many input bytes it
/// consumed. Slice fields inside `frame` borrow from the input.
pub const Decoded = struct {
    frame: Frame,
    bytes_consumed: usize,
};

/// Reads one frame from the start of `src`. Slice fields in the
/// returned `Frame` borrow from `src`, so `src` must outlive the
/// returned value. Returns `error.InsufficientBytes` on truncation,
/// `error.UnknownFrameType` on unknown type bytes.
pub fn decode(src: []const u8) Error!Decoded {
    if (src.len == 0) return Error.InsufficientBytes;

    // PADDING (0x00): coalesce a run of zero bytes into one Padding{count}.
    if (src[0] == 0x00) {
        var n: usize = 0;
        while (n < src.len and src[n] == 0x00) : (n += 1) {}
        return .{
            .frame = .{ .padding = .{ .count = n } },
            .bytes_consumed = n,
        };
    }

    const t = try varint.decode(src);
    const start = t.bytes_read;
    const frame_type = t.value;

    return switch (frame_type) {
        0x01 => .{ .frame = .{ .ping = .{} }, .bytes_consumed = start },
        0x02 => decodeAck(src, start, false),
        0x03 => decodeAck(src, start, true),
        0x04 => decodeResetStream(src, start),
        0x05 => decodeStopSending(src, start),
        0x06 => decodeCrypto(src, start),
        0x07 => decodeNewToken(src, start),
        0x08...0x0f => decodeStream(src, start, @intCast(frame_type)),
        0x10 => decodeMaxData(src, start),
        0x11 => decodeMaxStreamData(src, start),
        0x12 => decodeMaxStreams(src, start, true),
        0x13 => decodeMaxStreams(src, start, false),
        0x14 => decodeDataBlocked(src, start),
        0x15 => decodeStreamDataBlocked(src, start),
        0x16 => decodeStreamsBlocked(src, start, true),
        0x17 => decodeStreamsBlocked(src, start, false),
        0x18 => decodeNewConnectionId(src, start),
        0x19 => decodeRetireConnectionId(src, start),
        0x1a => decodePathChallenge(src, start),
        0x1b => decodePathResponse(src, start),
        0x1c => decodeConnectionClose(src, start, true),
        0x1d => decodeConnectionClose(src, start, false),
        0x1e => .{ .frame = .{ .handshake_done = .{} }, .bytes_consumed = start },
        0x30 => decodeDatagram(src, start, false), // no LEN: rest of packet
        0x31 => decodeDatagram(src, start, true), // LEN-prefixed
        frame_type_path_ack => decodePathAck(src, start, false),
        frame_type_path_ack_ecn => decodePathAck(src, start, true),
        frame_type_path_abandon => decodePathAbandon(src, start),
        frame_type_path_status_backup => decodePathStatus(src, start, false),
        frame_type_path_status_available => decodePathStatus(src, start, true),
        frame_type_path_new_connection_id => decodePathNewConnectionId(src, start),
        frame_type_path_retire_connection_id => decodePathRetireConnectionId(src, start),
        frame_type_max_path_id => decodeMaxPathId(src, start),
        frame_type_paths_blocked => decodePathsBlocked(src, start),
        frame_type_path_cids_blocked => decodePathCidsBlocked(src, start),
        frame_type_alternative_v4_address => decodeAlternativeV4Address(src, start),
        frame_type_alternative_v6_address => decodeAlternativeV6Address(src, start),
        else => Error.UnknownFrameType,
    };
}

fn decodeAck(src: []const u8, start: usize, with_ecn: bool) Error!Decoded {
    var pos = start;
    const largest = try varint.decode(src[pos..]);
    pos += largest.bytes_read;
    const ack_delay = try varint.decode(src[pos..]);
    pos += ack_delay.bytes_read;
    const range_count = try varint.decode(src[pos..]);
    pos += range_count.bytes_read;
    if (range_count.value > max_incoming_ack_ranges) return Error.AckRangeCountTooLarge;
    const first_range = try varint.decode(src[pos..]);
    pos += first_range.bytes_read;

    const ranges_start = pos;
    var i: u64 = 0;
    while (i < range_count.value) : (i += 1) {
        const gap = try varint.decode(src[pos..]);
        pos += gap.bytes_read;
        const length = try varint.decode(src[pos..]);
        pos += length.bytes_read;
    }
    const ranges_bytes = src[ranges_start..pos];

    try validateAckRanges(largest.value, first_range.value, range_count.value, ranges_bytes);

    var ecn: ?types.EcnCounts = null;
    if (with_ecn) {
        const ect0 = try varint.decode(src[pos..]);
        pos += ect0.bytes_read;
        const ect1 = try varint.decode(src[pos..]);
        pos += ect1.bytes_read;
        const ce = try varint.decode(src[pos..]);
        pos += ce.bytes_read;
        ecn = .{ .ect0 = ect0.value, .ect1 = ect1.value, .ecn_ce = ce.value };
    }

    return .{
        .frame = .{ .ack = .{
            .largest_acked = largest.value,
            .ack_delay = ack_delay.value,
            .first_range = first_range.value,
            .range_count = range_count.value,
            .ranges_bytes = ranges_bytes,
            .ecn_counts = ecn,
        } },
        .bytes_consumed = pos,
    };
}

const DecodedPathId = struct {
    value: u32,
    bytes_read: u8,
};

fn decodePathId(src: []const u8) Error!DecodedPathId {
    const d = try varint.decode(src);
    if (d.value > std.math.maxInt(u32)) return Error.PathIdTooLarge;
    return .{ .value = @intCast(d.value), .bytes_read = d.bytes_read };
}

fn decodePathAck(src: []const u8, start: usize, with_ecn: bool) Error!Decoded {
    var pos = start;
    const path_id = try decodePathId(src[pos..]);
    pos += path_id.bytes_read;
    const largest = try varint.decode(src[pos..]);
    pos += largest.bytes_read;
    const ack_delay = try varint.decode(src[pos..]);
    pos += ack_delay.bytes_read;
    const range_count = try varint.decode(src[pos..]);
    pos += range_count.bytes_read;
    if (range_count.value > max_incoming_ack_ranges) return Error.AckRangeCountTooLarge;
    const first_range = try varint.decode(src[pos..]);
    pos += first_range.bytes_read;

    const ranges_start = pos;
    var i: u64 = 0;
    while (i < range_count.value) : (i += 1) {
        const gap = try varint.decode(src[pos..]);
        pos += gap.bytes_read;
        const length = try varint.decode(src[pos..]);
        pos += length.bytes_read;
    }
    const ranges_bytes = src[ranges_start..pos];

    try validateAckRanges(largest.value, first_range.value, range_count.value, ranges_bytes);

    var ecn: ?types.EcnCounts = null;
    if (with_ecn) {
        const ect0 = try varint.decode(src[pos..]);
        pos += ect0.bytes_read;
        const ect1 = try varint.decode(src[pos..]);
        pos += ect1.bytes_read;
        const ce = try varint.decode(src[pos..]);
        pos += ce.bytes_read;
        ecn = .{ .ect0 = ect0.value, .ect1 = ect1.value, .ecn_ce = ce.value };
    }

    return .{
        .frame = .{ .path_ack = .{
            .path_id = path_id.value,
            .largest_acked = largest.value,
            .ack_delay = ack_delay.value,
            .first_range = first_range.value,
            .range_count = range_count.value,
            .ranges_bytes = ranges_bytes,
            .ecn_counts = ecn,
        } },
        .bytes_consumed = pos,
    };
}

/// Walk an ACK / PATH_ACK frame's range list and reject any list where
/// the gap+length arithmetic underflows the descending PN cursor.
///
/// Wire format (RFC 9000 §19.3.1): the First ACK Range covers
/// `[largest_acked - first_range, largest_acked]`. Each subsequent
/// `(gap, length)` pair walks down strictly:
///
///     new_largest  = prev_smallest - gap - 2
///     new_smallest = new_largest - length
///
/// A peer that violates the descent — either by encoding a first_range
/// larger than `largest_acked`, or by emitting a gap+length pair whose
/// subtraction would dip below zero — is malformed. There is no valid
/// way for two ranges in a single ACK frame to overlap or duplicate
/// each other; an "overlapping" encoding manifests as one of these
/// underflows because PN-space is unsigned. Hardening guide §4.7.
///
/// `ranges_bytes` is the slice the decode loop above already
/// successfully parsed, so varint.decode here cannot fail
/// (InsufficientBytes was rejected in the parse loop). We re-decode
/// rather than threading the parsed values through the parse loop so
/// the parse loop stays a single pass with no allocation.
fn validateAckRanges(
    largest_acked: u64,
    first_range: u64,
    range_count: u64,
    ranges_bytes: []const u8,
) Error!void {
    if (first_range > largest_acked) return Error.OverlappingAckRanges;
    var cursor: u64 = largest_acked - first_range; // smallest of the prior range
    var pos: usize = 0;
    var i: u64 = 0;
    while (i < range_count) : (i += 1) {
        const gap = try varint.decode(ranges_bytes[pos..]);
        pos += gap.bytes_read;
        const length = try varint.decode(ranges_bytes[pos..]);
        pos += length.bytes_read;

        // new_largest = cursor - gap - 2; underflow ⇒ overlap/malformed.
        if (cursor < gap.value + 2) return Error.OverlappingAckRanges;
        const new_largest = cursor - gap.value - 2;
        if (new_largest < length.value) return Error.OverlappingAckRanges;
        cursor = new_largest - length.value; // smallest of the new range
    }
}

fn decodeStream(src: []const u8, start: usize, type_byte: u8) Error!Decoded {
    const has_offset = (type_byte & 0x04) != 0;
    const has_length = (type_byte & 0x02) != 0;
    const fin = (type_byte & 0x01) != 0;

    var pos = start;
    const sid = try varint.decode(src[pos..]);
    pos += sid.bytes_read;

    var offset: u64 = 0;
    if (has_offset) {
        const off = try varint.decode(src[pos..]);
        pos += off.bytes_read;
        offset = off.value;
    }

    var data: []const u8 = undefined;
    if (has_length) {
        const len = try varint.decode(src[pos..]);
        pos += len.bytes_read;
        data = try readBorrowed(src, pos, len.value);
        pos += data.len;
    } else {
        // STREAM-without-LEN runs to the end of `src`. The caller is
        // responsible for slicing src to exactly this frame's bytes.
        data = src[pos..];
        pos = src.len;
    }

    return .{
        .frame = .{ .stream = .{
            .stream_id = sid.value,
            .offset = offset,
            .data = data,
            .has_offset = has_offset,
            .has_length = has_length,
            .fin = fin,
        } },
        .bytes_consumed = pos,
    };
}

fn readBorrowed(src: []const u8, pos: usize, len_value: u64) Error![]const u8 {
    if (len_value > src.len - pos) return Error.InsufficientBytes;
    const len_usize: usize = @intCast(len_value);
    return src[pos .. pos + len_usize];
}

fn decodeResetStream(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const sid = try varint.decode(src[pos..]);
    pos += sid.bytes_read;
    const ec = try varint.decode(src[pos..]);
    pos += ec.bytes_read;
    const sz = try varint.decode(src[pos..]);
    pos += sz.bytes_read;
    return .{
        .frame = .{ .reset_stream = .{
            .stream_id = sid.value,
            .application_error_code = ec.value,
            .final_size = sz.value,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeStopSending(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const sid = try varint.decode(src[pos..]);
    pos += sid.bytes_read;
    const ec = try varint.decode(src[pos..]);
    pos += ec.bytes_read;
    return .{
        .frame = .{ .stop_sending = .{
            .stream_id = sid.value,
            .application_error_code = ec.value,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeCrypto(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const off = try varint.decode(src[pos..]);
    pos += off.bytes_read;
    const len = try varint.decode(src[pos..]);
    pos += len.bytes_read;
    const data = try readBorrowed(src, pos, len.value);
    pos += data.len;
    return .{
        .frame = .{ .crypto = .{
            .offset = off.value,
            .data = data,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeNewToken(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const len = try varint.decode(src[pos..]);
    pos += len.bytes_read;
    const token = try readBorrowed(src, pos, len.value);
    pos += token.len;
    return .{
        .frame = .{ .new_token = .{ .token = token } },
        .bytes_consumed = pos,
    };
}

fn decodeMaxData(src: []const u8, start: usize) Error!Decoded {
    const v = try varint.decode(src[start..]);
    return .{
        .frame = .{ .max_data = .{ .maximum_data = v.value } },
        .bytes_consumed = start + v.bytes_read,
    };
}

fn decodeMaxStreamData(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const sid = try varint.decode(src[pos..]);
    pos += sid.bytes_read;
    const m = try varint.decode(src[pos..]);
    pos += m.bytes_read;
    return .{
        .frame = .{ .max_stream_data = .{
            .stream_id = sid.value,
            .maximum_stream_data = m.value,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeMaxStreams(src: []const u8, start: usize, bidi: bool) Error!Decoded {
    const v = try varint.decode(src[start..]);
    return .{
        .frame = .{ .max_streams = .{ .bidi = bidi, .maximum_streams = v.value } },
        .bytes_consumed = start + v.bytes_read,
    };
}

fn decodeDataBlocked(src: []const u8, start: usize) Error!Decoded {
    const v = try varint.decode(src[start..]);
    return .{
        .frame = .{ .data_blocked = .{ .maximum_data = v.value } },
        .bytes_consumed = start + v.bytes_read,
    };
}

fn decodeStreamDataBlocked(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const sid = try varint.decode(src[pos..]);
    pos += sid.bytes_read;
    const m = try varint.decode(src[pos..]);
    pos += m.bytes_read;
    return .{
        .frame = .{ .stream_data_blocked = .{
            .stream_id = sid.value,
            .maximum_stream_data = m.value,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeStreamsBlocked(src: []const u8, start: usize, bidi: bool) Error!Decoded {
    const v = try varint.decode(src[start..]);
    return .{
        .frame = .{ .streams_blocked = .{ .bidi = bidi, .maximum_streams = v.value } },
        .bytes_consumed = start + v.bytes_read,
    };
}

fn decodeNewConnectionId(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const seq = try varint.decode(src[pos..]);
    pos += seq.bytes_read;
    const ret = try varint.decode(src[pos..]);
    pos += ret.bytes_read;
    if (src.len < pos + 1) return Error.InsufficientBytes;
    const cid_len = src[pos];
    pos += 1;
    if (cid_len > wire_header.max_cid_len) return Error.ConnIdTooLong;
    if (src.len < pos + cid_len) return Error.InsufficientBytes;
    const cid = try types.ConnId.fromSlice(src[pos .. pos + cid_len]);
    pos += cid_len;
    if (src.len < pos + 16) return Error.InsufficientBytes;
    var token: [16]u8 = undefined;
    @memcpy(&token, src[pos .. pos + 16]);
    pos += 16;
    return .{
        .frame = .{ .new_connection_id = .{
            .sequence_number = seq.value,
            .retire_prior_to = ret.value,
            .connection_id = cid,
            .stateless_reset_token = token,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeRetireConnectionId(src: []const u8, start: usize) Error!Decoded {
    const v = try varint.decode(src[start..]);
    return .{
        .frame = .{ .retire_connection_id = .{ .sequence_number = v.value } },
        .bytes_consumed = start + v.bytes_read,
    };
}

fn decodePathChallenge(src: []const u8, start: usize) Error!Decoded {
    if (src.len < start + 8) return Error.InsufficientBytes;
    var data: [8]u8 = undefined;
    @memcpy(&data, src[start .. start + 8]);
    return .{
        .frame = .{ .path_challenge = .{ .data = data } },
        .bytes_consumed = start + 8,
    };
}

fn decodePathResponse(src: []const u8, start: usize) Error!Decoded {
    if (src.len < start + 8) return Error.InsufficientBytes;
    var data: [8]u8 = undefined;
    @memcpy(&data, src[start .. start + 8]);
    return .{
        .frame = .{ .path_response = .{ .data = data } },
        .bytes_consumed = start + 8,
    };
}

fn decodeConnectionClose(src: []const u8, start: usize, is_transport: bool) Error!Decoded {
    var pos = start;
    const ec = try varint.decode(src[pos..]);
    pos += ec.bytes_read;
    var frame_type: u64 = 0;
    if (is_transport) {
        const ft = try varint.decode(src[pos..]);
        pos += ft.bytes_read;
        frame_type = ft.value;
    }
    const rl = try varint.decode(src[pos..]);
    pos += rl.bytes_read;
    const reason = try readBorrowed(src, pos, rl.value);
    pos += reason.len;
    return .{
        .frame = .{ .connection_close = .{
            .is_transport = is_transport,
            .error_code = ec.value,
            .frame_type = frame_type,
            .reason_phrase = reason,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeDatagram(src: []const u8, start: usize, has_length: bool) Error!Decoded {
    var pos = start;
    var data: []const u8 = undefined;
    if (has_length) {
        const len = try varint.decode(src[pos..]);
        pos += len.bytes_read;
        data = try readBorrowed(src, pos, len.value);
        pos += data.len;
    } else {
        // DATAGRAM-without-LEN runs to the end of `src` (RFC 9221 §4).
        data = src[pos..];
        pos = src.len;
    }
    return .{
        .frame = .{ .datagram = .{ .data = data, .has_length = has_length } },
        .bytes_consumed = pos,
    };
}

fn decodePathAbandon(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const path_id = try decodePathId(src[pos..]);
    pos += path_id.bytes_read;
    const error_code = try varint.decode(src[pos..]);
    pos += error_code.bytes_read;
    return .{
        .frame = .{ .path_abandon = .{
            .path_id = path_id.value,
            .error_code = error_code.value,
        } },
        .bytes_consumed = pos,
    };
}

fn decodePathStatus(src: []const u8, start: usize, available: bool) Error!Decoded {
    var pos = start;
    const path_id = try decodePathId(src[pos..]);
    pos += path_id.bytes_read;
    const seq = try varint.decode(src[pos..]);
    pos += seq.bytes_read;
    const status: types.PathStatus = .{
        .path_id = path_id.value,
        .sequence_number = seq.value,
    };
    return .{
        .frame = if (available)
            .{ .path_status_available = status }
        else
            .{ .path_status_backup = status },
        .bytes_consumed = pos,
    };
}

fn decodePathNewConnectionId(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const path_id = try decodePathId(src[pos..]);
    pos += path_id.bytes_read;
    const seq = try varint.decode(src[pos..]);
    pos += seq.bytes_read;
    const ret = try varint.decode(src[pos..]);
    pos += ret.bytes_read;
    if (src.len < pos + 1) return Error.InsufficientBytes;
    const cid_len = src[pos];
    pos += 1;
    if (cid_len > wire_header.max_cid_len) return Error.ConnIdTooLong;
    if (src.len < pos + cid_len) return Error.InsufficientBytes;
    const cid = try types.ConnId.fromSlice(src[pos .. pos + cid_len]);
    pos += cid_len;
    if (src.len < pos + 16) return Error.InsufficientBytes;
    var token: [16]u8 = undefined;
    @memcpy(&token, src[pos .. pos + 16]);
    pos += 16;
    return .{
        .frame = .{ .path_new_connection_id = .{
            .path_id = path_id.value,
            .sequence_number = seq.value,
            .retire_prior_to = ret.value,
            .connection_id = cid,
            .stateless_reset_token = token,
        } },
        .bytes_consumed = pos,
    };
}

fn decodePathRetireConnectionId(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const path_id = try decodePathId(src[pos..]);
    pos += path_id.bytes_read;
    const seq = try varint.decode(src[pos..]);
    pos += seq.bytes_read;
    return .{
        .frame = .{ .path_retire_connection_id = .{
            .path_id = path_id.value,
            .sequence_number = seq.value,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeMaxPathId(src: []const u8, start: usize) Error!Decoded {
    const path_id = try decodePathId(src[start..]);
    return .{
        .frame = .{ .max_path_id = .{ .maximum_path_id = path_id.value } },
        .bytes_consumed = start + path_id.bytes_read,
    };
}

fn decodePathsBlocked(src: []const u8, start: usize) Error!Decoded {
    const path_id = try decodePathId(src[start..]);
    return .{
        .frame = .{ .paths_blocked = .{ .maximum_path_id = path_id.value } },
        .bytes_consumed = start + path_id.bytes_read,
    };
}

fn decodePathCidsBlocked(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    const path_id = try decodePathId(src[pos..]);
    pos += path_id.bytes_read;
    const next_seq = try varint.decode(src[pos..]);
    pos += next_seq.bytes_read;
    return .{
        .frame = .{ .path_cids_blocked = .{
            .path_id = path_id.value,
            .next_sequence_number = next_seq.value,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeAlternativeV4Address(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    if (src.len < pos + 1) return Error.InsufficientBytes;
    const flags = src[pos];
    pos += 1;
    const preferred = (flags & 0b1000_0000) != 0;
    const retire = (flags & 0b0100_0000) != 0;
    const seq = try varint.decode(src[pos..]);
    pos += seq.bytes_read;
    if (src.len < pos + 4) return Error.InsufficientBytes;
    var address: [4]u8 = undefined;
    @memcpy(&address, src[pos .. pos + 4]);
    pos += 4;
    if (src.len < pos + 2) return Error.InsufficientBytes;
    const port = std.mem.readInt(u16, src[pos..][0..2], .big);
    pos += 2;
    return .{
        .frame = .{ .alternative_v4_address = .{
            .preferred = preferred,
            .retire = retire,
            .status_sequence_number = seq.value,
            .address = address,
            .port = port,
        } },
        .bytes_consumed = pos,
    };
}

fn decodeAlternativeV6Address(src: []const u8, start: usize) Error!Decoded {
    var pos = start;
    if (src.len < pos + 1) return Error.InsufficientBytes;
    const flags = src[pos];
    pos += 1;
    const preferred = (flags & 0b1000_0000) != 0;
    const retire = (flags & 0b0100_0000) != 0;
    const seq = try varint.decode(src[pos..]);
    pos += seq.bytes_read;
    if (src.len < pos + 16) return Error.InsufficientBytes;
    var address: [16]u8 = undefined;
    @memcpy(&address, src[pos .. pos + 16]);
    pos += 16;
    if (src.len < pos + 2) return Error.InsufficientBytes;
    const port = std.mem.readInt(u16, src[pos..][0..2], .big);
    pos += 2;
    return .{
        .frame = .{ .alternative_v6_address = .{
            .preferred = preferred,
            .retire = retire,
            .status_sequence_number = seq.value,
            .address = address,
            .port = port,
        } },
        .bytes_consumed = pos,
    };
}

// -- tests ---------------------------------------------------------------

test "decode rejects empty input" {
    try std.testing.expectError(Error.InsufficientBytes, decode(""));
}

test "decode rejects unknown frame type" {
    try std.testing.expectError(Error.UnknownFrameType, decode(&[_]u8{ 0x40, 0x40 }));
}

test "decode coalesces PADDING run" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }; // 5 PADDING then PING
    const d = try decode(&bytes);
    try std.testing.expect(d.frame == .padding);
    try std.testing.expectEqual(@as(u64, 5), d.frame.padding.count);
    try std.testing.expectEqual(@as(usize, 5), d.bytes_consumed);
}

test "decode PING (single byte 0x01)" {
    const d = try decode(&[_]u8{0x01});
    try std.testing.expect(d.frame == .ping);
    try std.testing.expectEqual(@as(usize, 1), d.bytes_consumed);
}

test "decode HANDSHAKE_DONE (single byte 0x1e)" {
    const d = try decode(&[_]u8{0x1e});
    try std.testing.expect(d.frame == .handshake_done);
    try std.testing.expectEqual(@as(usize, 1), d.bytes_consumed);
}

test "decode rejects ACK frames whose range_count exceeds max_incoming_ack_ranges" {
    // range_count varint value = 1000 (well above the 256 cap). The
    // hardening test: a peer-spammed ACK with a huge range count must
    // be rejected *before* the decoder enters the gap+length loop, so
    // the reject is constant-cost regardless of how many varint pairs
    // the peer claims to be sending.
    const bytes = [_]u8{
        0x02, // ACK type (no ECN)
        0x00, // largest_acked = 0
        0x00, // ack_delay = 0
        0x43, 0xe8, // range_count = 1000 (2-byte varint)
        0x00, // first_range = 0
    };
    try std.testing.expectError(Error.AckRangeCountTooLarge, decode(&bytes));
}

test "decode accepts ACK frames whose range_count is exactly max_incoming_ack_ranges" {
    // range_count = 256, but we don't supply 256 valid ranges — the
    // body will fail with InsufficientBytes once the loop starts.
    // What we're locking in: the *cap check itself* lets 256 through.
    // Anything past the cap is AckRangeCountTooLarge; up to and
    // including the cap goes on to consume range bytes.
    const bytes = [_]u8{
        0x02, // ACK type (no ECN)
        0x00, // largest_acked = 0
        0x00, // ack_delay = 0
        0x41, 0x00, // range_count = 256 (2-byte varint)
        0x00, // first_range = 0
    };
    // We expect InsufficientBytes (loop tries to read 256 pairs but
    // input is exhausted), NOT AckRangeCountTooLarge.
    try std.testing.expectError(Error.InsufficientBytes, decode(&bytes));
}

test "decode rejects PATH_ACK frames whose range_count exceeds max_incoming_ack_ranges" {
    // PATH_ACK without ECN = 0x3e. Same shape as ACK plus a leading
    // path_id varint.
    const bytes = [_]u8{
        0x3e, // PATH_ACK type (no ECN)
        0x00, // path_id = 0
        0x00, // largest_acked = 0
        0x00, // ack_delay = 0
        0x43, 0xe8, // range_count = 1000
        0x00, // first_range = 0
    };
    try std.testing.expectError(Error.AckRangeCountTooLarge, decode(&bytes));
}

test "decode rejects ACK with overlapping ranges" {
    // largest_acked = 100, first_range = 5 → first interval [95..100].
    // A well-formed second range with gap=0 would land at
    // new_largest = 95 - 0 - 2 = 93 → interval [93 - length .. 93].
    // To force overlap into the *first* range we'd need new_largest
    // ≥ 95, i.e. cursor=95, gap=0 and 95 - 0 - 2 = 93 — never reaches
    // back into the prior interval.
    //
    // Overlap in PN-space is therefore expressible only by
    // arithmetic underflow: e.g. cursor = 95, but gap is encoded so
    // that gap + 2 > 95. With first_range = 5 and largest_acked = 5
    // the first interval is [0..5], and a gap=10 makes
    // new_largest = 0 - 10 - 2 → underflow. That underflow IS the
    // overlap signature for a peer that tried to claim a range
    // already covered by the descending walk.
    const bytes = [_]u8{
        0x02, // ACK (no ECN)
        0x05, // largest_acked = 5
        0x00, // ack_delay = 0
        0x01, // range_count = 1
        0x05, // first_range = 5 → covers [0..5]
        0x0a, // gap = 10 → would underflow
        0x00, // length = 0
    };
    try std.testing.expectError(Error.OverlappingAckRanges, decode(&bytes));
}

test "decode rejects ACK with underflowing range arithmetic" {
    // first_range = 200 with largest_acked = 100 → the first interval
    // would span [-100..100], i.e. underflow. Reject before any
    // subsequent range is even consulted.
    const bytes = [_]u8{
        0x02, // ACK (no ECN)
        0x40, 0x64, // largest_acked = 100 (2-byte varint)
        0x00, // ack_delay = 0
        0x00, // range_count = 0
        0x40, 0xc8, // first_range = 200 (2-byte varint)
    };
    try std.testing.expectError(Error.OverlappingAckRanges, decode(&bytes));
}

test "decode accepts ACK with adjacent ranges (gap=0)" {
    // gap=0 in the QUIC encoding does NOT mean ranges share a PN —
    // §19.3.1 makes new_largest = prev_smallest - 2. So with cursor=20
    // (smallest of [20..30]) the next range's largest = 18. Adjacent
    // here means "minimum legal gap"; the single PN 19 is unacked.
    //
    // Acked: [20..30], [10..18]. Encoded:
    //   largest_acked = 30, first_range = 10 (covers 20..30)
    //   gap = 0 → new_largest = 20 - 0 - 2 = 18
    //   length = 8 → new_smallest = 18 - 8 = 10
    const bytes = [_]u8{
        0x02, // ACK (no ECN)
        0x1e, // largest_acked = 30
        0x00, // ack_delay = 0
        0x01, // range_count = 1
        0x0a, // first_range = 10
        0x00, // gap = 0
        0x08, // length = 8
    };
    const d = try decode(&bytes);
    try std.testing.expect(d.frame == .ack);
    try std.testing.expectEqual(@as(u64, 30), d.frame.ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 10), d.frame.ack.first_range);
    try std.testing.expectEqual(@as(u64, 1), d.frame.ack.range_count);
}

test "decode accepts ACK with ranges at the boundary" {
    // Boundary: descending walk reaches PN 0 with no slack, but does
    // not underflow. Setup: largest_acked = 5, first_range = 3 →
    // first interval [2..5] (smallest = 2). Then gap=0, length=0:
    //   new_largest = 2 - 0 - 2 = 0
    //   new_smallest = 0 - 0     = 0
    // Second interval is exactly [0..0]. Anything tighter (gap=1, or
    // length=1) would underflow and trip OverlappingAckRanges.
    const bytes = [_]u8{
        0x02, // ACK (no ECN)
        0x05, // largest_acked = 5
        0x00, // ack_delay = 0
        0x01, // range_count = 1
        0x03, // first_range = 3 → [2..5]
        0x00, // gap = 0
        0x00, // length = 0 → [0..0]
    };
    const d = try decode(&bytes);
    try std.testing.expect(d.frame == .ack);
    try std.testing.expectEqual(@as(u64, 5), d.frame.ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 1), d.frame.ack.range_count);

    // Sanity: nudge length up by 1, the same descent now underflows.
    const bytes_bad = [_]u8{
        0x02,
        0x05,
        0x00,
        0x01,
        0x03,
        0x00,
        0x01, // length = 1 → new_smallest = 0 - 1 → underflow
    };
    try std.testing.expectError(Error.OverlappingAckRanges, decode(&bytes_bad));
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `decode` (single-frame) with arbitrary bytes. Property: the
// decoder must never panic, and on success it must report a
// `bytes_consumed` that lies inside the input. The decoded frame's
// type tag must match the QUIC v1 frame catalog. Crashes / panics
// abort. Invariant violations save to corpus.

// Seed corpus targets each frame type's minimal byte form (RFC 9000 §19).
// Smith consumes a single slice — entries are `<u32 LE len><payload>`.
test "fuzz: frame decode single-frame property" {
    try std.testing.fuzz({}, fuzzFrameDecode, .{
        .corpus = &.{
            // Empty input
            "\x00\x00\x00\x00",
            // PADDING (single 0x00)
            "\x01\x00\x00\x00\x00",
            // PING (0x01)
            "\x01\x00\x00\x00\x01",
            // ACK (no ECN): largest=0, ack_delay=0, range_count=0, first_range=0
            "\x05\x00\x00\x00\x02\x00\x00\x00\x00",
            // ACK_ECN: same fields plus ect0/ect1/ce
            "\x08\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00",
            // RESET_STREAM: stream_id=0, app_err=0, final_size=0
            "\x04\x00\x00\x00\x04\x00\x00\x00",
            // STOP_SENDING: stream_id=0, app_err=0
            "\x03\x00\x00\x00\x05\x00\x00",
            // CRYPTO: offset=0, len=0, no data
            "\x03\x00\x00\x00\x06\x00\x00",
            // NEW_TOKEN: len=0
            "\x02\x00\x00\x00\x07\x00",
            // STREAM (0x08, no offset, no length, no fin): stream_id=0
            "\x02\x00\x00\x00\x08\x00",
            // MAX_DATA: maximum=0
            "\x02\x00\x00\x00\x10\x00",
            // MAX_STREAM_DATA: stream_id=0, maximum=0
            "\x03\x00\x00\x00\x11\x00\x00",
            // MAX_STREAMS bidi: maximum=0
            "\x02\x00\x00\x00\x12\x00",
            // DATA_BLOCKED: maximum=0
            "\x02\x00\x00\x00\x14\x00",
            // NEW_CONNECTION_ID: seq=1, retire=0, len=0x10, 16 CID bytes, 16 token bytes
            "\x24\x00\x00\x00" ++
                "\x18\x01\x00\x10" ++
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" ++
                "\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99",
            // RETIRE_CONNECTION_ID: seq=0
            "\x02\x00\x00\x00\x19\x00",
            // PATH_CHALLENGE: 8 random bytes
            "\x09\x00\x00\x00\x1a\x01\x02\x03\x04\x05\x06\x07\x08",
            // PATH_RESPONSE: 8 random bytes
            "\x09\x00\x00\x00\x1b\x01\x02\x03\x04\x05\x06\x07\x08",
            // CONNECTION_CLOSE transport: error=0, frame_type=0, reason_len=0
            "\x04\x00\x00\x00\x1c\x00\x00\x00",
            // CONNECTION_CLOSE application: error=0, reason_len=0
            "\x03\x00\x00\x00\x1d\x00\x00",
            // HANDSHAKE_DONE
            "\x01\x00\x00\x00\x1e",
            // DATAGRAM (no LEN, runs to end)
            "\x05\x00\x00\x00\x30\xde\xad\xbe\xef",
            // DATAGRAM (LEN-prefixed): len=4 + 4 bytes
            "\x06\x00\x00\x00\x31\x04\xde\xad\xbe\xef",
            // PATH_ACK (multipath, 2-byte varint type 0x3e): path_id=0,
            // largest=0, ack_delay=0, range_count=0, first_range=0
            "\x06\x00\x00\x00\x40\x3e\x00\x00\x00\x00",
            // ALTERNATIVE_V4_ADDRESS: 4-byte type varint(0x1d5845e2),
            // flags=0x80 (Preferred), seq=0, addr=192.0.2.1, port=4433.
            // Total payload = 4 + 1 + 1 + 4 + 2 = 12 bytes.
            "\x0c\x00\x00\x00\x9d\x58\x45\xe2\x80\x00\xc0\x00\x02\x01\x11\x51",
            // ALTERNATIVE_V6_ADDRESS: 4-byte type varint(0x1d5845e3),
            // flags=0x40 (Retire), seq=2, addr=2001:db8::1, port=8443.
            // Total payload = 4 + 1 + 1 + 16 + 2 = 24 bytes.
            "\x18\x00\x00\x00\x9d\x58\x45\xe3\x40\x02" ++
                "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" ++
                "\x20\xfb",
            // Adjacent ACK ranges (gap=0): largest=30, first_range=10, gap=0, length=8
            "\x07\x00\x00\x00\x02\x1e\x00\x01\x0a\x00\x08",
            // ACK with overflowing range_count (rejected by AckRangeCountTooLarge)
            "\x07\x00\x00\x00\x02\x00\x00\x43\xe8\x00",
            // Unknown frame type 0x40 0x40 = varint = 64 (not in catalog)
            "\x02\x00\x00\x00\x40\x40",
        },
    });
}

fn fuzzFrameDecode(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [4096]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    const d = decode(input) catch return;

    // The decoder must not over-read.
    try std.testing.expect(d.bytes_consumed <= input.len);
    // bytes_consumed of 0 is meaningless — at minimum the type byte
    // costs 1.
    try std.testing.expect(d.bytes_consumed >= 1);
}

// Drive `decode` repeatedly until input is exhausted or the parser
// errors. Mirrors how `Connection.handle` walks the frames inside one
// decrypted packet payload. Property: no panic; cumulative
// `bytes_consumed` stays inside the input.

test "fuzz: frame decode loop until exhausted" {
    try std.testing.fuzz({}, fuzzFrameDecodeLoop, .{});
}

fn fuzzFrameDecodeLoop(_: void, smith: *std.testing.Smith) anyerror!void {
    const encode_mod = @import("encode.zig");
    var input_buf: [4096]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    var pos: usize = 0;
    var iters: usize = 0;
    while (pos < input.len) {
        const d = decode(input[pos..]) catch return;
        try std.testing.expect(d.bytes_consumed >= 1);
        try std.testing.expect(d.bytes_consumed <= input.len - pos);
        // The encoder produces minimum-length varints; the decoder
        // accepts any valid length encoding (RFC 9000 §16 doesn't
        // mandate minimal encoding on incoming values). So
        // `encodedLen` is a lower bound on what `bytes_consumed`
        // can be: the decoder may have consumed extra bytes for
        // non-minimal varint forms, but never fewer than the
        // canonical re-encoding would produce.
        try std.testing.expect(encode_mod.encodedLen(d.frame) <= d.bytes_consumed);
        pos += d.bytes_consumed;
        // Cap loop iterations as a defense against an O(1)-per-frame
        // payload like all-PADDING (one byte per frame). 16k frames
        // is far more than any real packet would carry.
        iters += 1;
        if (iters >= 16_384) break;
    }
}
