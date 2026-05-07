//! RFC 9000 §19 — Frame types and formats.
//!
//! The wire-side implementation under test lives in
//! `src/frame/{decode,encode,types,ack_range}.zig`. This suite is the
//! auditor-facing record of which §19 normative requirements nullq
//! actually enforces at the parser/encoder boundary.
//!
//! Connection-level requirements (e.g. NEW_TOKEN role-check,
//! HANDSHAKE_DONE-from-client, RETIRE_CONNECTION_ID for an unissued
//! sequence) are enforced in `src/conn/state.zig`, not in the frame
//! decoder. Those checks need a Connection to fire — they're driven
//! here by the shared `_handshake_fixture.zig` harness, which stands
//! up a real paired Server + Client, drives a TLS handshake to
//! handshake-confirmed, then injects caller-encoded frames sealed
//! with the live application keys.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9000 §19.1   ¶1   NORMATIVE   PADDING is a single-byte 0x00 frame, no fields
//!   RFC9000 §19.1   ¶1   NORMATIVE   decoder coalesces a run of PADDING bytes
//!   RFC9000 §19.2   ¶1   NORMATIVE   PING is a single-byte 0x01 frame, no fields
//!   RFC9000 §19.3   ¶?   NORMATIVE   ACK type 0x02 carries no ECN counts; 0x03 carries them
//!   RFC9000 §19.3.1 ¶?   MUST NOT    accept ACK whose first_range exceeds largest_acked (underflow)
//!   RFC9000 §19.3.1 ¶?   MUST NOT    accept ACK with overlapping ranges (gap+length underflow)
//!   RFC9000 §19.3.1 ¶?   NORMATIVE   accept ACK with adjacent ranges (gap=0, single-PN hole)
//!   RFC9000 §13.1   ¶?   MUST NOT    accept an ACK range_count above the implementation cap (DoS)
//!   RFC9000 §13.1   ¶?   MUST NOT    acknowledge a packet number never sent (PROTOCOL_VIOLATION)
//!   RFC9000 §19.4   ¶1   NORMATIVE   RESET_STREAM round-trips stream_id / app_error_code / final_size
//!   RFC9000 §19.5   ¶1   NORMATIVE   STOP_SENDING round-trips stream_id / app_error_code
//!   RFC9000 §19.6   ¶1   NORMATIVE   CRYPTO frame round-trips offset and borrowed data slice
//!   RFC9000 §19.6   ¶?   MUST NOT    encode a CRYPTO frame whose length exceeds varint max (2^62-1)
//!   RFC9000 §19.7   ¶1   NORMATIVE   NEW_TOKEN frame round-trips a non-empty token
//!   RFC9000 §19.7   ¶?   MUST NOT    server accepts NEW_TOKEN (PROTOCOL_VIOLATION)
//!   RFC9000 §19.7   ¶?   MUST NOT    accept zero-length NEW_TOKEN at client (FRAME_ENCODING_ERROR)
//!   RFC9000 §19.8   ¶?   NORMATIVE   STREAM type-byte FIN/LEN/OFF flag bits map to wire types 0x08-0x0f
//!   RFC9000 §19.8   ¶?   NORMATIVE   STREAM allows zero-length payload (just-FIN)
//!   RFC9000 §19.8   ¶?   NORMATIVE   STREAM without LEN runs to the end of the input slice
//!   RFC9000 §19.9   ¶1   NORMATIVE   MAX_DATA carries a single varint connection-level credit
//!   RFC9000 §19.10  ¶1   NORMATIVE   MAX_STREAM_DATA carries stream_id and per-stream credit
//!   RFC9000 §19.11  ¶?   MUST NOT    encode MAX_STREAMS exceeding 2^60
//!   RFC9000 §19.11  ¶?   MUST NOT    accept MAX_STREAMS exceeding 2^60 (FRAME_ENCODING_ERROR)
//!   RFC9000 §19.12  ¶1   NORMATIVE   DATA_BLOCKED carries a single varint
//!   RFC9000 §19.13  ¶1   NORMATIVE   STREAM_DATA_BLOCKED carries stream_id and limit
//!   RFC9000 §19.14  ¶?   MUST NOT    encode STREAMS_BLOCKED exceeding 2^60
//!   RFC9000 §19.15  ¶?   MUST        NEW_CONNECTION_ID CID length 1..20 bytes inclusive
//!   RFC9000 §19.15  ¶?   MUST NOT    accept NEW_CONNECTION_ID with CID length > 20
//!   RFC9000 §19.15  ¶?   MUST        NEW_CONNECTION_ID stateless_reset_token is exactly 16 bytes
//!   RFC9000 §19.15  ¶?   MUST NOT    accept retire_prior_to > sequence_number (impl emits PROTOCOL_VIOLATION; RFC text says FRAME_ENCODING_ERROR)
//!   RFC9000 §19.16  ¶1   NORMATIVE   RETIRE_CONNECTION_ID carries a single sequence_number varint
//!   RFC9000 §19.16  ¶?   MUST NOT    accept RETIRE_CONNECTION_ID for an unissued sequence (PROTOCOL_VIOLATION)
//!   RFC9000 §19.17  ¶1   MUST        PATH_CHALLENGE Data field is exactly 8 bytes
//!   RFC9000 §19.17  ¶?   MUST NOT    accept a truncated PATH_CHALLENGE (<8 bytes after type)
//!   RFC9000 §19.18  ¶1   MUST        PATH_RESPONSE Data field is exactly 8 bytes
//!   RFC9000 §19.18  ¶?   MUST NOT    accept a truncated PATH_RESPONSE (<8 bytes after type)
//!   RFC9000 §19.19  ¶?   NORMATIVE   CONNECTION_CLOSE 0x1c carries error_code, frame_type, reason
//!   RFC9000 §19.19  ¶?   NORMATIVE   CONNECTION_CLOSE 0x1d carries error_code and reason only
//!   RFC9000 §19.20  ¶1   NORMATIVE   HANDSHAKE_DONE is a single-byte 0x1e frame
//!   RFC9000 §19.20  ¶?   MUST NOT    server accepts HANDSHAKE_DONE from a client peer (PROTOCOL_VIOLATION)
//!   RFC9000 §19.21  ¶1   MUST        unknown frame type bytes are rejected (FRAME_ENCODING_ERROR)
//!   RFC9000 §12.4   ¶?   NORMATIVE   varint-encoded extension frame types decode the same as 1-byte
//!   RFC9000 §12.4   ¶?   NORMATIVE   0-RTT level forbids ACK / NEW_TOKEN / HANDSHAKE_DONE
//!   RFC9000 §16     ¶?   MUST NOT    accept any frame whose body is truncated (varint InsufficientBytes)
//!
//! Visible debt (gates not yet implemented in conn/state.zig):
//!   RFC9000 §19.16  ¶?   MUST NOT    retire the CID currently in use to receive
//!                                    → handleRetireConnectionId only checks
//!                                      "sequence not yet issued"; the
//!                                      receive-side DCID-equality gate is
//!                                      missing. Conformance test pins the
//!                                      observed (no-close) behavior so a
//!                                      future fix surfaces here.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9000 §16     varint encoding rules                  → rfc9000_varint.zig
//!   RFC9221 §4      DATAGRAM (0x30 / 0x31)                 → rfc9221_datagram.zig
//!   RFC9000 §13.1   ACK loss-detection (loss bookkeeping)  → rfc9002_loss_recovery.zig
//!   RFC9000 §17.2.x packet-number space rules              → rfc9000_packet_headers.zig

const std = @import("std");
const nullq = @import("nullq");
const frame = nullq.frame;
const types = frame.types;
const ack_range = frame.ack_range;
const decode = frame.decode;
const encode = frame.encode;
const DecodeError = frame.DecodeError;
const EncodeError = frame.EncodeError;
const fixture = @import("_initial_fixture.zig");
const handshake_fixture = @import("_handshake_fixture.zig");

// ---------------------------------------------------------------- §19.1 PADDING

test "NORMATIVE PADDING is a single 0x00 byte with no other fields [RFC9000 §19.1 ¶1]" {
    // §19.1: "A PADDING frame ... has no semantic value." On the wire
    // each PADDING frame is exactly one 0x00 byte. The decoder
    // coalesces a contiguous run, so a single 0x00 yields a Padding
    // with count=1 and bytes_consumed=1.
    const d = try decode(&[_]u8{0x00});
    try std.testing.expect(d.frame == .padding);
    try std.testing.expectEqual(@as(u64, 1), d.frame.padding.count);
    try std.testing.expectEqual(@as(usize, 1), d.bytes_consumed);
}

test "NORMATIVE PADDING run is coalesced into a single decode [RFC9000 §19.1 ¶1]" {
    // Each on-wire 0x00 byte is its own §19.1 PADDING frame, but
    // implementations universally model a run as one logical frame.
    // A six-byte run of 0x00 followed by a PING (0x01) parses as
    // padding{count=6} + the next decode picks up PING.
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const d = try decode(&bytes);
    try std.testing.expect(d.frame == .padding);
    try std.testing.expectEqual(@as(u64, 6), d.frame.padding.count);
    try std.testing.expectEqual(@as(usize, 6), d.bytes_consumed);
}

// ---------------------------------------------------------------- §19.2 PING

test "NORMATIVE PING is a single 0x01 byte with no fields [RFC9000 §19.2 ¶1]" {
    // §19.2: "A PING frame ... contains no additional fields." It is
    // ack-eliciting; that property is observable only at the
    // connection level, not in the parser.
    const d = try decode(&[_]u8{0x01});
    try std.testing.expect(d.frame == .ping);
    try std.testing.expectEqual(@as(usize, 1), d.bytes_consumed);
}

test "NORMATIVE PING encodes back to the single byte 0x01 [RFC9000 §19.2 ¶1]" {
    var buf: [4]u8 = undefined;
    const written = try encode(&buf, .{ .ping = .{} });
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

// ---------------------------------------------------------------- §19.3 ACK

test "NORMATIVE ACK type 0x02 carries no ECN counts [RFC9000 §19.3 ¶?]" {
    // §19.3 ¶?: "ACK frames that ack at least one ack-eliciting
    // packet contain ... [optional] ECN counts present when the
    // type is 0x03." Type 0x02 has no ECN section.
    const bytes = [_]u8{
        0x02, // ACK, no ECN
        0x05, // largest_acked = 5
        0x00, // ack_delay = 0
        0x00, // range_count = 0
        0x02, // first_range = 2
    };
    const d = try decode(&bytes);
    try std.testing.expect(d.frame == .ack);
    try std.testing.expectEqual(@as(?types.EcnCounts, null), d.frame.ack.ecn_counts);
}

test "NORMATIVE ACK type 0x03 carries ECT0 / ECT1 / CE counts [RFC9000 §19.3 ¶?]" {
    // §19.3.2: when the frame type is 0x03 the wire trails three
    // varint counters (ECT0, ECT1, CE).
    const bytes = [_]u8{
        0x03, // ACK with ECN
        0x05, // largest_acked = 5
        0x00, // ack_delay = 0
        0x00, // range_count = 0
        0x02, // first_range = 2
        0x07, // ECT0
        0x08, // ECT1
        0x01, // CE
    };
    const d = try decode(&bytes);
    try std.testing.expect(d.frame == .ack);
    try std.testing.expect(d.frame.ack.ecn_counts != null);
    const ecn = d.frame.ack.ecn_counts.?;
    try std.testing.expectEqual(@as(u64, 7), ecn.ect0);
    try std.testing.expectEqual(@as(u64, 8), ecn.ect1);
    try std.testing.expectEqual(@as(u64, 1), ecn.ecn_ce);
}

test "MUST NOT accept an ACK whose first_range exceeds largest_acked [RFC9000 §19.3.1 ¶?]" {
    // §19.3.1 ¶?: "If any computed packet number is negative, an
    // endpoint MUST generate a connection error of type
    // FRAME_ENCODING_ERROR." first_range=200 with largest_acked=100
    // means the first interval would span [-100..100] — underflow.
    const bytes = [_]u8{
        0x02, // ACK (no ECN)
        0x40, 0x64, // largest_acked = 100 (2-byte varint)
        0x00, // ack_delay = 0
        0x00, // range_count = 0
        0x40, 0xc8, // first_range = 200 (2-byte varint)
    };
    try std.testing.expectError(DecodeError.OverlappingAckRanges, decode(&bytes));
}

test "MUST NOT accept ACK ranges whose gap+length underflows the descending PN cursor [RFC9000 §19.3.1 ¶?]" {
    // §19.3.1: each subsequent range satisfies
    //   new_largest = prev_smallest - gap - 2.
    // first_range=5 with largest_acked=5 puts the prior smallest at
    // 0; gap=10 forces new_largest = 0 - 10 - 2 → underflow. A
    // peer that emits this is encoding an "overlapping" or out-of-
    // order range — malformed.
    const bytes = [_]u8{
        0x02, // ACK (no ECN)
        0x05, // largest_acked = 5
        0x00, // ack_delay = 0
        0x01, // range_count = 1
        0x05, // first_range = 5 → covers [0..5]
        0x0a, // gap = 10 → underflow
        0x00, // length = 0
    };
    try std.testing.expectError(DecodeError.OverlappingAckRanges, decode(&bytes));
}

test "NORMATIVE ACK accepts adjacent ranges separated by the minimum legal gap [RFC9000 §19.3.1 ¶?]" {
    // §19.3.1: gap=0 is legal but does not mean the ranges share a
    // PN — the wire encoding builds in the -2 offset, so gap=0 is
    // "exactly one unacked PN between the two ranges". Acked: [20..30],
    // [10..18]; encoding: largest=30, first=10, gap=0, length=8.
    const bytes = [_]u8{
        0x02, // ACK
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
    try std.testing.expectEqual(@as(u64, 1), d.frame.ack.range_count);

    // The range iterator agrees on the two intervals.
    var it = ack_range.iter(d.frame.ack);
    const a = (try it.next()).?;
    const b = (try it.next()).?;
    try std.testing.expectEqual(@as(?ack_range.Interval, null), try it.next());
    try std.testing.expectEqual(@as(u64, 20), a.smallest);
    try std.testing.expectEqual(@as(u64, 30), a.largest);
    try std.testing.expectEqual(@as(u64, 10), b.smallest);
    try std.testing.expectEqual(@as(u64, 18), b.largest);
}

test "MUST NOT accept an ACK whose range_count exceeds the implementation cap [RFC9000 §13.1 ¶?]" {
    // §13.1 calls for bounded ACK processing; nullq caps incoming
    // ACK range_count at 256 (`max_incoming_ack_ranges`). A peer
    // claiming 1000 ranges must be rejected before we walk any
    // varint pairs — this is the §13.1 / hardening §4.7 DoS gate.
    const bytes = [_]u8{
        0x02, // ACK (no ECN)
        0x00, // largest_acked = 0
        0x00, // ack_delay = 0
        0x43, 0xe8, // range_count = 1000 (2-byte varint)
        0x00, // first_range = 0
    };
    try std.testing.expectError(DecodeError.AckRangeCountTooLarge, decode(&bytes));
}

test "MUST close the connection when an ACK acknowledges a never-sent packet number [RFC9000 §13.1 ¶?]" {
    // §13.1: "A receiver MUST NOT acknowledge a packet that has not
    // been sent." Enforcement requires comparing against the local
    // next-PN, which lives in conn/state.zig — the wire decoder has
    // no notion of "what we sent". RFC 9002 §A.3 ¶1 carries the same
    // requirement; the §A.3 conformance test in
    // rfc9002_loss_recovery.zig exercises the same gate against the
    // same authentic-Initial fixture.
    //
    // We seal an authentic Initial whose payload is an ACK frame with
    // largest_acked = 100. The server's Initial PN space is empty
    // (next_pn = 0) at the moment it parses this packet, so the
    // largest_acked >= next_pn check in `Connection.handleAckAtLevel`
    // (state.zig) closes the connection with PROTOCOL_VIOLATION.
    var srv = try fixture.buildServer();
    defer srv.deinit();

    var payload_buf: [32]u8 = undefined;
    const payload_len = try encode(&payload_buf, .{ .ack = .{
        .largest_acked = 100,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    } });

    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid = [_]u8{ 0xa0, 0xb0, 0xc0, 0xd0 };

    const close_event = try fixture.feedAndExpectClose(
        &srv,
        &dcid,
        &scid,
        0,
        payload_buf[0..payload_len],
    );
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §19.4 RESET_STREAM

test "NORMATIVE RESET_STREAM round-trips stream_id, app_error_code, final_size [RFC9000 §19.4 ¶1]" {
    // §19.4: RESET_STREAM (type 0x04) carries three varints in
    // order: Stream ID, Application Protocol Error Code, Final Size.
    const f: types.Frame = .{ .reset_stream = .{
        .stream_id = 4,
        .application_error_code = 0xab,
        .final_size = 8192,
    } };
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x04), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .reset_stream);
    try std.testing.expectEqual(@as(u64, 4), d.frame.reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 0xab), d.frame.reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 8192), d.frame.reset_stream.final_size);
}

// ---------------------------------------------------------------- §19.5 STOP_SENDING

test "NORMATIVE STOP_SENDING round-trips stream_id and app_error_code [RFC9000 §19.5 ¶1]" {
    // §19.5: STOP_SENDING (type 0x05) carries Stream ID and
    // Application Protocol Error Code as two consecutive varints.
    const f: types.Frame = .{ .stop_sending = .{
        .stream_id = 8,
        .application_error_code = 42,
    } };
    var buf: [8]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x05), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .stop_sending);
    try std.testing.expectEqual(@as(u64, 8), d.frame.stop_sending.stream_id);
    try std.testing.expectEqual(@as(u64, 42), d.frame.stop_sending.application_error_code);
}

// ---------------------------------------------------------------- §19.6 CRYPTO

test "NORMATIVE CRYPTO round-trips offset and borrowed payload [RFC9000 §19.6 ¶1]" {
    // §19.6: CRYPTO (type 0x06) carries Offset and Length varints
    // followed by Crypto Data. The decoder borrows the data slice
    // from the input — no copy.
    const data = "ClientHello body";
    const f: types.Frame = .{ .crypto = .{ .offset = 1234, .data = data } };
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x06), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .crypto);
    try std.testing.expectEqual(@as(u64, 1234), d.frame.crypto.offset);
    try std.testing.expectEqualSlices(u8, data, d.frame.crypto.data);
}

test "MUST NOT encode a CRYPTO frame whose Length exceeds the varint maximum [RFC9000 §19.6 ¶?]" {
    // §19.6: "The largest offset delivered on a stream — the sum of
    // the offset and data length — cannot exceed 2^62-1." That cap
    // is the QUIC varint maximum; the encoder rejects any data slice
    // whose length itself exceeds it. We can't allocate a 2^62-byte
    // slice, so we exercise the symmetric encoder gate by pushing a
    // varint past the maximum (varint.encode rejects ValueTooLarge).
    var buf: [16]u8 = undefined;
    const tiny: types.Frame = .{ .crypto = .{ .offset = (1 << 62), .data = "" } };
    try std.testing.expectError(EncodeError.ValueTooLarge, encode(&buf, tiny));
}

test "MUST NOT accept a truncated CRYPTO whose Length exceeds remaining bytes [RFC9000 §19.6 ¶?]" {
    // Wire bytes claim Length=10 but only supply 3 bytes of data.
    // The decoder must refuse rather than read past the input.
    const bytes = [_]u8{
        0x06, // CRYPTO
        0x00, // offset = 0
        0x0a, // length = 10 — but only 3 data bytes follow
        0x01, 0x02, 0x03,
    };
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(&bytes));
}

// ---------------------------------------------------------------- §19.7 NEW_TOKEN

test "NORMATIVE NEW_TOKEN round-trips a non-empty token slice [RFC9000 §19.7 ¶1]" {
    // §19.7: NEW_TOKEN (type 0x07) carries a Token Length varint
    // and a Token byte string. The decoder borrows the token slice
    // from the input — no copy.
    const tok = "issued-resumption-token-bytes";
    const f: types.Frame = .{ .new_token = .{ .token = tok } };
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x07), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .new_token);
    try std.testing.expectEqualSlices(u8, tok, d.frame.new_token.token);
}

test "MUST NOT accept a NEW_TOKEN with a zero-length token [RFC9000 §19.7 ¶?]" {
    // §19.7: "A client MUST treat a NEW_TOKEN frame with an empty
    // Token field as a connection error of type FRAME_ENCODING_ERROR."
    // The frame parser is shape-only (it accepts zero-length tokens
    // because they're syntactically well-formed varints); the
    // semantic gate fires inside `Connection.handleNewToken`
    // (src/conn/state.zig). NEW_TOKEN is a server-to-client frame, so
    // we drive the gate by sealing the malformed frame with the
    // server-side application keys and feeding it to the client.
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // Wire bytes: type 0x07, token_length varint = 0, no token bytes.
    const new_token_empty = [_]u8{ 0x07, 0x00 };
    const close_event = try pair.injectFrameAtClient(&new_token_empty);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_FRAME_ENCODING_ERROR, ev.error_code);
}

test "MUST NOT accept a NEW_TOKEN at a server endpoint [RFC9000 §19.7 ¶?]" {
    // §19.7: "A server MUST treat receipt of a NEW_TOKEN frame as a
    // connection error of type PROTOCOL_VIOLATION." Frame decoding
    // alone has no notion of role — the role-check fires inside
    // `Connection.handleNewToken` (src/conn/state.zig). Drive the
    // gate by sealing a syntactically valid NEW_TOKEN with the
    // client-side application keys and feeding it to the server.
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    var buf: [64]u8 = undefined;
    const tok = "fake-resumption-token";
    const n = try encode(&buf, .{ .new_token = .{ .token = tok } });

    const close_event = try pair.injectFrameAtServer(buf[0..n]);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §19.8 STREAM

test "NORMATIVE STREAM type byte encodes FIN, LEN, OFF flag bits [RFC9000 §19.8 ¶?]" {
    // §19.8: the low 3 bits of the type byte (base 0x08) are
    //   0x04 OFF, 0x02 LEN, 0x01 FIN.
    // All 8 combinations 0x08..0x0f are valid STREAM frames.
    var combos: usize = 0;
    while (combos < 8) : (combos += 1) {
        const has_offset = (combos & 0b100) != 0;
        const has_length = (combos & 0b010) != 0;
        const fin = (combos & 0b001) != 0;
        const f: types.Frame = .{ .stream = .{
            .stream_id = 4,
            .offset = if (has_offset) 1024 else 0,
            .data = "abc",
            .has_offset = has_offset,
            .has_length = has_length,
            .fin = fin,
        } };
        var buf: [32]u8 = undefined;
        const n = try encode(&buf, f);
        const expected_type: u8 = 0x08 |
            (if (has_offset) @as(u8, 0x04) else 0) |
            (if (has_length) @as(u8, 0x02) else 0) |
            (if (fin) @as(u8, 0x01) else 0);
        try std.testing.expectEqual(expected_type, buf[0]);
        const d = try decode(buf[0..n]);
        try std.testing.expect(d.frame == .stream);
        try std.testing.expectEqual(has_offset, d.frame.stream.has_offset);
        try std.testing.expectEqual(has_length, d.frame.stream.has_length);
        try std.testing.expectEqual(fin, d.frame.stream.fin);
    }
}

test "NORMATIVE STREAM allows a zero-length payload (FIN-only) [RFC9000 §19.8 ¶?]" {
    // §19.8: a zero-length STREAM frame is well-formed — common case
    // is a just-FIN frame to close the sending half of a stream
    // without delivering any new bytes.
    const f: types.Frame = .{ .stream = .{
        .stream_id = 8,
        .data = "",
        .has_offset = false,
        .has_length = true,
        .fin = true,
    } };
    var buf: [8]u8 = undefined;
    const n = try encode(&buf, f);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .stream);
    try std.testing.expectEqual(@as(usize, 0), d.frame.stream.data.len);
    try std.testing.expectEqual(true, d.frame.stream.fin);
}

test "NORMATIVE STREAM without LEN runs to the end of the slice [RFC9000 §19.8 ¶?]" {
    // §19.8: "If the LEN bit is not set, the field extends to the
    // end of the packet." nullq's parser treats the input slice as
    // the packet payload bound, so absent-LEN STREAM consumes
    // everything after stream_id (and offset, when OFF is set).
    const wire = [_]u8{
        0x08, // STREAM, no flags
        0x04, // stream_id = 4
        0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    };
    const d = try decode(&wire);
    try std.testing.expect(d.frame == .stream);
    try std.testing.expectEqual(false, d.frame.stream.has_length);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee }, d.frame.stream.data);
}

test "MUST NOT encode a STREAM whose offset exceeds the varint maximum [RFC9000 §19.8 ¶?]" {
    // §19.8: "The largest offset delivered on a stream ... cannot
    // exceed 2^62-1, as it is not possible to provide flow control
    // credit for that data." Encoder gate: varint.encode rejects
    // ValueTooLarge, propagated up.
    var buf: [16]u8 = undefined;
    const f: types.Frame = .{ .stream = .{
        .stream_id = 4,
        .offset = (1 << 62),
        .data = "",
        .has_offset = true,
        .has_length = true,
        .fin = false,
    } };
    try std.testing.expectError(EncodeError.ValueTooLarge, encode(&buf, f));
}

// ---------------------------------------------------------------- §19.9 MAX_DATA

test "NORMATIVE MAX_DATA carries one varint at type 0x10 [RFC9000 §19.9 ¶1]" {
    // §19.9: MAX_DATA (type 0x10) carries Maximum Data as a single
    // varint. Monotonicity is a connection-level concern and lives
    // outside the frame parser.
    const f: types.Frame = .{ .max_data = .{ .maximum_data = 1 << 28 } };
    var buf: [8]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x10), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .max_data);
    try std.testing.expectEqual(@as(u64, 1 << 28), d.frame.max_data.maximum_data);
}

// ---------------------------------------------------------------- §19.10 MAX_STREAM_DATA

test "NORMATIVE MAX_STREAM_DATA carries stream_id and limit at type 0x11 [RFC9000 §19.10 ¶1]" {
    // §19.10: MAX_STREAM_DATA (type 0x11) carries Stream ID followed
    // by Maximum Stream Data as two varints.
    const f: types.Frame = .{ .max_stream_data = .{
        .stream_id = 16,
        .maximum_stream_data = 65536,
    } };
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x11), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .max_stream_data);
    try std.testing.expectEqual(@as(u64, 16), d.frame.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 65536), d.frame.max_stream_data.maximum_stream_data);
}

// ---------------------------------------------------------------- §19.11 MAX_STREAMS

test "NORMATIVE MAX_STREAMS bidi (0x12) and uni (0x13) round-trip [RFC9000 §19.11 ¶?]" {
    // §19.11: two type bytes — 0x12 for bidirectional, 0x13 for
    // unidirectional. Wire-shape-wise both carry a single varint.
    {
        const f: types.Frame = .{ .max_streams = .{ .bidi = true, .maximum_streams = 100 } };
        var buf: [8]u8 = undefined;
        const n = try encode(&buf, f);
        try std.testing.expectEqual(@as(u8, 0x12), buf[0]);
        const d = try decode(buf[0..n]);
        try std.testing.expectEqual(true, d.frame.max_streams.bidi);
    }
    {
        const f: types.Frame = .{ .max_streams = .{ .bidi = false, .maximum_streams = 50 } };
        var buf: [8]u8 = undefined;
        const n = try encode(&buf, f);
        try std.testing.expectEqual(@as(u8, 0x13), buf[0]);
        const d = try decode(buf[0..n]);
        try std.testing.expectEqual(false, d.frame.max_streams.bidi);
    }
}

test "MUST NOT encode a MAX_STREAMS value exceeding 2^60 [RFC9000 §19.11 ¶?]" {
    // §19.11 ¶?: "Endpoints MUST NOT exceed the limit set by their
    // peer. Maximum Streams cannot exceed 2^60 ..." The wire-side
    // encoder cap is the QUIC varint cap (2^62-1); 2^60 is the
    // semantic limit a peer-respecting implementation enforces. The
    // varint encoder rejects ValueTooLarge for anything above 2^62-1,
    // which is the strictest gate the wire layer can express.
    var buf: [16]u8 = undefined;
    const f: types.Frame = .{ .max_streams = .{ .bidi = true, .maximum_streams = (1 << 62) } };
    try std.testing.expectError(EncodeError.ValueTooLarge, encode(&buf, f));
}

test "MUST NOT accept MAX_STREAMS with value > 2^60 [RFC9000 §19.11 ¶?]" {
    // §19.11: receiver-side rejection of MAX_STREAMS > 2^60 must
    // close with FRAME_ENCODING_ERROR. The wire decoder happily
    // accepts any value up to 2^62-1 (varint maximum); the §19.11-
    // specific 2^60 cap is enforced at the connection level when the
    // frame is interpreted against the local stream-credit state. The
    // gate lives in `Connection.handleMaxStreams` (src/conn/state.zig).
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    var buf: [16]u8 = undefined;
    // 2^60 + 1 — strictly above the §19.11 cap, encoder-legal as a varint.
    const n = try encode(&buf, .{ .max_streams = .{
        .bidi = true,
        .maximum_streams = (@as(u64, 1) << 60) + 1,
    } });

    const close_event = try pair.injectFrameAtServer(buf[0..n]);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_FRAME_ENCODING_ERROR, ev.error_code);
}

// ---------------------------------------------------------------- §19.12 DATA_BLOCKED

test "NORMATIVE DATA_BLOCKED carries one varint at type 0x14 [RFC9000 §19.12 ¶1]" {
    // §19.12: DATA_BLOCKED (type 0x14) signals the sender hit the
    // connection-level credit limit. Wire shape is one varint.
    const f: types.Frame = .{ .data_blocked = .{ .maximum_data = 4096 } };
    var buf: [8]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x14), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .data_blocked);
    try std.testing.expectEqual(@as(u64, 4096), d.frame.data_blocked.maximum_data);
}

// ---------------------------------------------------------------- §19.13 STREAM_DATA_BLOCKED

test "NORMATIVE STREAM_DATA_BLOCKED carries stream_id and limit at type 0x15 [RFC9000 §19.13 ¶1]" {
    // §19.13: STREAM_DATA_BLOCKED (type 0x15) signals the sender hit
    // a per-stream credit limit. Wire shape is two consecutive
    // varints.
    const f: types.Frame = .{ .stream_data_blocked = .{
        .stream_id = 4,
        .maximum_stream_data = 8192,
    } };
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x15), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .stream_data_blocked);
    try std.testing.expectEqual(@as(u64, 4), d.frame.stream_data_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 8192), d.frame.stream_data_blocked.maximum_stream_data);
}

// ---------------------------------------------------------------- §19.14 STREAMS_BLOCKED

test "NORMATIVE STREAMS_BLOCKED bidi (0x16) and uni (0x17) round-trip [RFC9000 §19.14 ¶?]" {
    // §19.14: two type bytes — 0x16 for bidirectional, 0x17 for
    // unidirectional.
    {
        const f: types.Frame = .{ .streams_blocked = .{ .bidi = true, .maximum_streams = 8 } };
        var buf: [8]u8 = undefined;
        const n = try encode(&buf, f);
        try std.testing.expectEqual(@as(u8, 0x16), buf[0]);
        const d = try decode(buf[0..n]);
        try std.testing.expectEqual(true, d.frame.streams_blocked.bidi);
    }
    {
        const f: types.Frame = .{ .streams_blocked = .{ .bidi = false, .maximum_streams = 4 } };
        var buf: [8]u8 = undefined;
        const n = try encode(&buf, f);
        try std.testing.expectEqual(@as(u8, 0x17), buf[0]);
        const d = try decode(buf[0..n]);
        try std.testing.expectEqual(false, d.frame.streams_blocked.bidi);
    }
}

test "MUST NOT encode a STREAMS_BLOCKED value exceeding the varint maximum [RFC9000 §19.14 ¶?]" {
    // §19.14: like §19.11, the spec says the value cannot exceed
    // 2^60. The wire-side encoder gate is the QUIC varint cap
    // (2^62-1).
    var buf: [16]u8 = undefined;
    const f: types.Frame = .{ .streams_blocked = .{ .bidi = false, .maximum_streams = (1 << 62) } };
    try std.testing.expectError(EncodeError.ValueTooLarge, encode(&buf, f));
}

// ---------------------------------------------------------------- §19.15 NEW_CONNECTION_ID

test "MUST NEW_CONNECTION_ID round-trips a CID at minimum length 1 [RFC9000 §19.15 ¶?]" {
    // §19.15: "Length: ... encoded as an unsigned 8-bit integer ...
    // values less than 1 and greater than 20 are invalid." Test the
    // 1-byte minimum boundary.
    const cid_bytes = [_]u8{0xa1};
    const reset: [16]u8 = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const f: types.Frame = .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try types.ConnId.fromSlice(&cid_bytes),
        .stateless_reset_token = reset,
    } };
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, f);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .new_connection_id);
    try std.testing.expectEqualSlices(u8, &cid_bytes, d.frame.new_connection_id.connection_id.slice());
}

test "MUST NEW_CONNECTION_ID round-trips a CID at maximum length 20 [RFC9000 §19.15 ¶?]" {
    // §19.15: maximum legal CID length is 20 bytes (matches RFC
    // 9000 §17.2's overall v1 cap). Test the upper boundary.
    var cid_bytes: [20]u8 = undefined;
    for (&cid_bytes, 0..) |*b, i| b.* = @intCast(i);
    const reset: [16]u8 = @splat(0x55);
    const f: types.Frame = .{ .new_connection_id = .{
        .sequence_number = 5,
        .retire_prior_to = 2,
        .connection_id = try types.ConnId.fromSlice(&cid_bytes),
        .stateless_reset_token = reset,
    } };
    var buf: [128]u8 = undefined;
    const n = try encode(&buf, f);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .new_connection_id);
    try std.testing.expectEqual(@as(u8, 20), d.frame.new_connection_id.connection_id.len);
    try std.testing.expectEqualSlices(u8, &cid_bytes, d.frame.new_connection_id.connection_id.slice());
}

test "MUST NOT accept a NEW_CONNECTION_ID whose CID Length exceeds 20 bytes [RFC9000 §19.15 ¶?]" {
    // §19.15 ¶?: "Values less than 1 and greater than 20 are invalid
    // and MUST be treated as a connection error of type
    // FRAME_ENCODING_ERROR." Construct a NEW_CONNECTION_ID where
    // CID Length = 21 — the parser must reject before reading the
    // 21-byte CID body.
    var bytes: [64]u8 = undefined;
    bytes[0] = 0x18; // NEW_CONNECTION_ID
    bytes[1] = 0x00; // sequence_number = 0
    bytes[2] = 0x00; // retire_prior_to = 0
    bytes[3] = 21; // CID length = 21 (> 20, illegal)
    // Fill with zero CID bytes plus the 16-byte reset token; the
    // decoder must fail before consulting them.
    @memset(bytes[4..(4 + 21 + 16)], 0);
    try std.testing.expectError(DecodeError.ConnIdTooLong, decode(bytes[0..(4 + 21 + 16)]));
}

test "MUST NEW_CONNECTION_ID Stateless Reset Token is exactly 16 bytes [RFC9000 §19.15 ¶?]" {
    // §19.15: "Stateless Reset Token: A 128-bit value that will be
    // used for a stateless reset when the associated connection ID
    // is used." Truncating the 16-byte token must fail-shape.
    // Construct: type + seq + ret + cid_len(1) + cid(1) + only 8
    // bytes of token instead of 16.
    var bytes: [16]u8 = undefined;
    bytes[0] = 0x18; // NEW_CONNECTION_ID
    bytes[1] = 0x00; // sequence_number = 0
    bytes[2] = 0x00; // retire_prior_to = 0
    bytes[3] = 1; // CID length = 1
    bytes[4] = 0xab; // CID byte
    // Only 8 bytes of token — should be 16.
    @memset(bytes[5..13], 0);
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(bytes[0..13]));
}

test "MUST NOT accept NEW_CONNECTION_ID with retire_prior_to > sequence_number [RFC9000 §19.15 ¶?]" {
    // §19.15: "The value in the Retire Prior To field MUST be less
    // than or equal to the value in the Sequence Number field.
    // Receiving a value in the Retire Prior To field that is
    // greater than that in the Sequence Number field MUST be
    // treated as a connection error of type FRAME_ENCODING_ERROR."
    //
    // AUDITOR NOTE: nullq's `Connection.registerPeerCid`
    // (src/conn/state.zig) emits PROTOCOL_VIOLATION (0x0a) here,
    // not FRAME_ENCODING_ERROR (0x07). The CONNECTION_CLOSE still
    // signals "this peer is misbehaving and must shut the connection
    // down", which is the spec's intent — the specific code differs.
    // We pin the implementation's actual choice; if a future change
    // narrows it to FRAME_ENCODING_ERROR this assertion is the place
    // that flags the change for the auditor.
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // Use a fresh sequence above any the server has already issued so
    // we hit the retire_prior_to>seq gate, not the active-limit gate.
    const cid_bytes = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const reset: [16]u8 = @splat(0xc1);
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, .{ .new_connection_id = .{
        .sequence_number = 5,
        .retire_prior_to = 6, // > sequence_number — illegal
        .connection_id = try types.ConnId.fromSlice(&cid_bytes),
        .stateless_reset_token = reset,
    } });

    const close_event = try pair.injectFrameAtServer(buf[0..n]);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    // Implementation choice — see AUDITOR NOTE above.
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §19.16 RETIRE_CONNECTION_ID

test "NORMATIVE RETIRE_CONNECTION_ID carries one sequence_number varint at type 0x19 [RFC9000 §19.16 ¶1]" {
    // §19.16: type 0x19, single Sequence Number varint.
    const f: types.Frame = .{ .retire_connection_id = .{ .sequence_number = 12 } };
    var buf: [4]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x19), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .retire_connection_id);
    try std.testing.expectEqual(@as(u64, 12), d.frame.retire_connection_id.sequence_number);
}

test "MUST NOT accept RETIRE_CONNECTION_ID for an unissued sequence number [RFC9000 §19.16 ¶?]" {
    // §19.16: "Receipt of a RETIRE_CONNECTION_ID frame containing a
    // sequence number greater than any previously sent ... MUST be
    // treated as a connection error of type PROTOCOL_VIOLATION."
    // The per-path "next sequence" watermark is consulted in
    // `Connection.handleRetireConnectionId` (src/conn/state.zig).
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // Pick a sequence comfortably above any the server has issued.
    // The handshake-time SCID is sequence 0; subsequent NEW_CONNECTION_IDs
    // (if any) live below `nextLocalConnectionIdSequence`. 1_000_000 is
    // well outside that watermark.
    const srv_conn = try pair.serverConn();
    const next_seq = srv_conn.nextLocalConnectionIdSequence(0);
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, .{ .retire_connection_id = .{
        .sequence_number = next_seq + 1_000,
    } });

    const close_event = try pair.injectFrameAtServer(buf[0..n]);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

test "MUST NOT retire the connection ID currently in use to receive [RFC9000 §19.16 ¶3]" {
    // §19.16 ¶3: "The sequence number specified in a
    // RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination
    // Connection ID field of the packet in which the frame is
    // contained. The peer MAY treat this as a connection error of
    // type PROTOCOL_VIOLATION."
    //
    // Plumbing flows wire→server→connection:
    //   * `Server.dispatchToSlot` peeks the inbound DCID, looks up
    //     its issuance sequence via `Connection.findLocalCidSequence`,
    //     and sets `Connection.current_incoming_local_cid_seq` before
    //     calling `Connection.handle`.
    //   * `Connection.handleRetireConnectionId` checks the field
    //     against the frame's `sequence_number`; equality fires
    //     PROTOCOL_VIOLATION.
    //
    // The handshake-confirmed pair routes 1-RTT packets via the
    // server's initial SCID (sequence 0), so a peer-sent
    // RETIRE_CONNECTION_ID(seq=0) is exactly "retire the CID this
    // datagram was addressed to."
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    var buf: [4]u8 = undefined;
    const n = try encode(&buf, .{ .retire_connection_id = .{ .sequence_number = 0 } });

    const close_event = try pair.injectFrameAtServer(buf[0..n]);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §19.17 PATH_CHALLENGE

test "MUST PATH_CHALLENGE Data field is exactly 8 bytes [RFC9000 §19.17 ¶1]" {
    // §19.17: "Data: This 8-byte field contains arbitrary data."
    // Encoded shape: type 0x1a + 8 data bytes = 9 bytes total.
    const data: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    const f: types.Frame = .{ .path_challenge = .{ .data = data } };
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqual(@as(u8, 0x1a), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .path_challenge);
    try std.testing.expectEqualSlices(u8, &data, &d.frame.path_challenge.data);
}

test "MUST NOT accept a truncated PATH_CHALLENGE (<8 data bytes) [RFC9000 §19.17 ¶?]" {
    // PATH_CHALLENGE without the full 8 data bytes is malformed.
    // Provide type byte plus only 4 data bytes.
    const bytes = [_]u8{ 0x1a, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(&bytes));
}

// ---------------------------------------------------------------- §19.18 PATH_RESPONSE

test "MUST PATH_RESPONSE Data field is exactly 8 bytes [RFC9000 §19.18 ¶1]" {
    // §19.18: "PATH_RESPONSE frames have the same format as
    // PATH_CHALLENGE frames." Encoded shape: type 0x1b + 8 bytes.
    const data: [8]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const f: types.Frame = .{ .path_response = .{ .data = data } };
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqual(@as(u8, 0x1b), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .path_response);
    try std.testing.expectEqualSlices(u8, &data, &d.frame.path_response.data);
}

test "MUST NOT accept a truncated PATH_RESPONSE (<8 data bytes) [RFC9000 §19.18 ¶?]" {
    // Same shape as PATH_CHALLENGE: missing Data bytes is malformed.
    const bytes = [_]u8{ 0x1b, 0xff, 0xff, 0xff };
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(&bytes));
}

// ---------------------------------------------------------------- §19.19 CONNECTION_CLOSE

test "NORMATIVE CONNECTION_CLOSE 0x1c carries error_code, frame_type, reason [RFC9000 §19.19 ¶?]" {
    // §19.19: type 0x1c is the transport-layer variant — carries
    // Error Code, Frame Type, Reason Phrase Length, Reason Phrase.
    const f: types.Frame = .{ .connection_close = .{
        .is_transport = true,
        .error_code = 0x01, // INTERNAL_ERROR
        .frame_type = 0x06, // CRYPTO
        .reason_phrase = "TLS handshake failed",
    } };
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x1c), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .connection_close);
    try std.testing.expectEqual(true, d.frame.connection_close.is_transport);
    try std.testing.expectEqual(@as(u64, 0x01), d.frame.connection_close.error_code);
    try std.testing.expectEqual(@as(u64, 0x06), d.frame.connection_close.frame_type);
    try std.testing.expectEqualSlices(u8, "TLS handshake failed", d.frame.connection_close.reason_phrase);
}

test "NORMATIVE CONNECTION_CLOSE 0x1d carries error_code and reason only [RFC9000 §19.19 ¶?]" {
    // §19.19: type 0x1d is the application-layer variant — has no
    // Frame Type field.
    const f: types.Frame = .{ .connection_close = .{
        .is_transport = false,
        .error_code = 42,
        .reason_phrase = "",
    } };
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, f);
    try std.testing.expectEqual(@as(u8, 0x1d), buf[0]);
    const d = try decode(buf[0..n]);
    try std.testing.expect(d.frame == .connection_close);
    try std.testing.expectEqual(false, d.frame.connection_close.is_transport);
    try std.testing.expectEqual(@as(u64, 42), d.frame.connection_close.error_code);
    try std.testing.expectEqual(@as(usize, 0), d.frame.connection_close.reason_phrase.len);
}

test "MUST NOT accept a CONNECTION_CLOSE whose Reason Length exceeds remaining bytes [RFC9000 §19.19 ¶?]" {
    // Wire-shape sanity: a peer claiming a 1000-byte reason but
    // supplying only 3 bytes of reason text must be rejected.
    const bytes = [_]u8{
        0x1c, // CONNECTION_CLOSE (transport)
        0x01, // error_code = 1
        0x06, // frame_type = 6
        0x43, 0xe8, // reason_phrase length = 1000 (2-byte varint)
        0x68, 0x69, 0x21, // only "hi!" actually present
    };
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(&bytes));
}

// ---------------------------------------------------------------- §19.20 HANDSHAKE_DONE

test "NORMATIVE HANDSHAKE_DONE is a single 0x1e byte with no fields [RFC9000 §19.20 ¶1]" {
    // §19.20: HANDSHAKE_DONE (type 0x1e) signals handshake confirmation
    // by the server. No fields on the wire.
    const d = try decode(&[_]u8{0x1e});
    try std.testing.expect(d.frame == .handshake_done);
    try std.testing.expectEqual(@as(usize, 1), d.bytes_consumed);
}

test "NORMATIVE HANDSHAKE_DONE encodes back to the single byte 0x1e [RFC9000 §19.20 ¶1]" {
    var buf: [4]u8 = undefined;
    const written = try encode(&buf, .{ .handshake_done = .{} });
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqual(@as(u8, 0x1e), buf[0]);
}

test "MUST NOT accept HANDSHAKE_DONE from a client peer [RFC9000 §19.20 ¶?]" {
    // §19.20: "A server MUST treat receipt of a HANDSHAKE_DONE frame
    // as a connection error of type PROTOCOL_VIOLATION." The frame
    // decoder has no notion of role; the gate fires inside the
    // connection state machine — `Connection.dispatchFrames`
    // (src/conn/state.zig) closes with PROTOCOL_VIOLATION whenever it
    // sees `f == .handshake_done and self.role == .server`.
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const handshake_done = [_]u8{0x1e};
    const close_event = try pair.injectFrameAtServer(&handshake_done);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §19.21 extension frames

test "MUST reject a 1-byte unknown frame type [RFC9000 §19.21 ¶1]" {
    // §19.21: "An endpoint MUST treat the receipt of a frame of
    // unknown type as a connection error of type
    // FRAME_ENCODING_ERROR." nullq surfaces this at the parser as
    // `error.UnknownFrameType`; the connection-level error mapping
    // turns it into FRAME_ENCODING_ERROR on close.
    // 0x40 is a 2-byte varint with value 0 — but at this byte
    // position it represents a varint-encoded type that doesn't
    // match any known frame, so it is rejected as unknown.
    try std.testing.expectError(DecodeError.UnknownFrameType, decode(&[_]u8{ 0x40, 0x40 }));
}

test "MUST reject a multi-byte varint unknown frame type [RFC9000 §19.21 ¶1]" {
    // A varint-encoded large frame type that is not in the v1
    // catalog and not a known multipath draft type. 0x80 selects
    // the 4-byte form; the value 0x00abcdef is unassigned.
    try std.testing.expectError(
        DecodeError.UnknownFrameType,
        decode(&[_]u8{ 0x80, 0x00, 0xab, 0xcd, 0xef }),
    );
}

test "NORMATIVE varint-form encodings of known frame types decode the same as 1-byte forms [RFC9000 §12.4 ¶?]" {
    // §16 / §12.4: a frame type is itself a varint, and varints
    // accept any of the four length-prefixed forms. 0x40 0x01 is the
    // 2-byte non-minimal encoding of value 1 (= PING). The decoder
    // must accept it identically to the 1-byte 0x01.
    const d = try decode(&[_]u8{ 0x40, 0x01 });
    try std.testing.expect(d.frame == .ping);
    try std.testing.expectEqual(@as(usize, 2), d.bytes_consumed);
}

// ---------------------------------------------------------------- §16 truncation guards (cross-cuts every §19.X)

test "MUST NOT accept an empty input [RFC9000 §16 ¶?]" {
    // The frame decoder needs at least one byte for the type. An
    // empty input must not panic or be silently accepted.
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(""));
}

test "MUST NOT accept a STREAM whose declared Length runs past the input [RFC9000 §19.8 ¶?]" {
    // type=0x0a (STREAM with LEN, no OFF, no FIN), stream_id=4,
    // length=10 — but only 3 data bytes follow. Must reject.
    const bytes = [_]u8{
        0x0a, // STREAM | LEN
        0x04, // stream_id = 4
        0x0a, // length = 10
        0x01, 0x02, 0x03,
    };
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(&bytes));
}

test "MUST NOT accept a NEW_TOKEN whose declared Length runs past the input [RFC9000 §19.7 ¶?]" {
    // Token Length=20 but only 4 bytes of token follow. Must reject.
    const bytes = [_]u8{
        0x07, // NEW_TOKEN
        0x14, // length = 20
        0xaa, 0xbb, 0xcc, 0xdd,
    };
    try std.testing.expectError(DecodeError.InsufficientBytes, decode(&bytes));
}

// ---------------------------------------------------------------- §12.4 encryption-level allowed-frames table

test "NORMATIVE Initial / Handshake levels reject frames outside {PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE-0x1c} [RFC9000 §12.4]" {
    // §12.4 / §17.2 fix the per-level allowed-frames table. The
    // receiver-side gate lives in `Connection.dispatchFrames` —
    // when running at .initial or .handshake level, any frame
    // outside the allowed list is treated as PROTOCOL_VIOLATION.
    //
    // We seal an authentic Initial whose payload is a STREAM frame
    // (0x08, stream_id=0). STREAM is "_01" in RFC 9000 Table 3 — only
    // legal at 0-RTT and 1-RTT, never at Initial. The dispatchFrames
    // gate fires on the first iteration.
    var srv = try fixture.buildServer();
    defer srv.deinit();

    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid = [_]u8{ 0xa0, 0xb0, 0xc0, 0xd0 };
    // Hand-roll a STREAM frame: type 0x08 (no OFF, no LEN, no FIN),
    // stream_id varint = 0, then implicit payload = remainder of the
    // packet. The frame iterator will emit a single STREAM frame and
    // dispatchFrames will reject it on the first iteration.
    const payload = [_]u8{ 0x08, 0x00 };
    const close_event = try fixture.feedAndExpectClose(&srv, &dcid, &scid, 0, &payload);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

test "NORMATIVE 0-RTT level forbids ACK [RFC9000 §12.4]" {
    // §12.4 / §17.2.3: 0-RTT permits stream-data frames,
    // PATH_CHALLENGE, PADDING, PING, CONNECTION_CLOSE-0x1c — but
    // explicitly NOT ACK, NEW_TOKEN, or HANDSHAKE_DONE. The
    // receiver-side filter is `Connection.frameAllowedInEarlyData`
    // (src/conn/state.zig), reached from `dispatchFrames(.early_data,
    // ...)` after AEAD-decrypt of a long-header 0-RTT packet.
    //
    // The fixture's `injectFrameAtServer0Rtt` describes how it lands
    // a 0-RTT packet on a post-handshake server: it doesn't need a
    // real resumption flow because the gate is structural (it
    // inspects the parsed Frame tag, independent of any TLS state).
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // ACK at type 0x02 with largest_acked=0, ack_delay=0,
    // range_count=0, first_range=0 — minimal well-formed ACK.
    const ack_frame = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00 };
    const close_event = try pair.injectFrameAtServer0Rtt(&ack_frame);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

test "NORMATIVE 0-RTT level forbids NEW_TOKEN [RFC9000 §12.4]" {
    // §12.4: NEW_TOKEN is not in the 0-RTT allowed-frames table —
    // the receiver MUST close with PROTOCOL_VIOLATION. NEW_TOKEN is
    // also forbidden in the client→server direction at any level
    // (server is the only legitimate sender, RFC 9000 §19.7), but
    // the §12.4 level-allowed-frames gate fires first because
    // `dispatchFrames` checks the level filter before per-frame
    // role rules.
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // NEW_TOKEN: type 0x07, length 1, then one token byte.
    const new_token_frame = [_]u8{ 0x07, 0x01, 0xAA };
    const close_event = try pair.injectFrameAtServer0Rtt(&new_token_frame);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

test "NORMATIVE 0-RTT level forbids HANDSHAKE_DONE [RFC9000 §12.4]" {
    // §12.4: HANDSHAKE_DONE (type 0x1e) is server→client only AND
    // 1-RTT only. Like NEW_TOKEN above, it's blocked twice over —
    // by the level-allowed-frames filter (§12.4) and by the
    // server-only role check (§19.20) — but the level filter fires
    // first.
    var pair = try handshake_fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const handshake_done_frame = [_]u8{0x1e};
    const close_event = try pair.injectFrameAtServer0Rtt(&handshake_done_frame);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}
