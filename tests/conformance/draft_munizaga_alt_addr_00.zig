//! draft-munizaga-quic-alternative-server-address-00 conformance.
//!
//! Locks down the wire format and transport-parameter rules quic_zig
//! observes for the QUIC Alternative Server Address frames extension.
//! Pinned to draft revision 00 — bumping
//! `quic_zig.alt_server_address_draft_version` is a deliberate scoped
//! change.
//!
//! ## Coverage (codec scope)
//!
//!   §4        MUST       transport parameter id is 0xff0969d85c
//!                        (8-byte varint encoding)
//!   §4        MUST       client advertises with an empty (zero-length) value
//!   §4        MUST       non-zero value rejected as malformed
//!   §4 ¶2     MUST NOT   server must not send the parameter; receipt is
//!                        TRANSPORT_PARAMETER_ERROR
//!   §4 ¶3     MUST NOT   parameter must not be remembered for 0-RTT
//!                        (asserted as a Params field default)
//!   §6        MUST       ALTERNATIVE_V4_ADDRESS type byte sequence is the
//!                        4-byte varint of 0x1d5845e2
//!   §6        MUST       ALTERNATIVE_V6_ADDRESS type byte sequence is the
//!                        4-byte varint of 0x1d5845e3
//!   §6        NORMATIVE  flag byte: bit 7 = Preferred, bit 6 = Retire,
//!                        bits 5..0 = unused (zero on encode; preserved
//!                        on decode-then-encode)
//!   §6        NORMATIVE  Status Sequence Number is QUIC varint
//!   §6        NORMATIVE  IPv4 (4 bytes) / IPv6 (16 bytes) address payloads
//!                        are preserved byte-for-byte
//!   §6        NORMATIVE  port is 16-bit big-endian
//!   §6 ¶5     NORMATIVE  sender encodes monotonically-increasing
//!                        Status Sequence Numbers across both frame
//!                        types (codec preserves whatever the sender
//!                        supplies; this test demonstrates correct
//!                        framing of an increasing run)
//!   §7        NORMATIVE  frames are ack-eliciting under quic_zig's
//!                        classifier (drives loss-recovery / ACK
//!                        scheduling correctly)
//!   §7        NORMATIVE  receiving the frame without the extension
//!                        being negotiated is a peer protocol
//!                        violation
//!   §6        NORMATIVE  Connection.advertiseAlternative*Address
//!                        rejects calls from a client connection
//!                        (server-only API)
//!   §4        NORMATIVE  Connection.advertiseAlternative*Address
//!                        rejects when the peer hasn't advertised
//!                        `alternative_address` (avoids forcing a
//!                        peer PROTOCOL_VIOLATION close)
//!   §6 ¶5     MUST       advertise calls allocate monotonically-
//!                        increasing Status Sequence Numbers shared
//!                        between V4 and V6
//!   §6        NORMATIVE  end-to-end: when the client advertises
//!                        support, a server-emitted ALTERNATIVE_*_ADDRESS
//!                        frame round-trips through the handshake
//!                        fixture without closing either side
//!   §4 ¶2     MUST       client closes with TRANSPORT_PARAMETER_ERROR
//!                        when the server's transport-parameter blob
//!                        carries `alternative_address`
//!   §6        NORMATIVE  receiver surfaces a typed
//!                        `ConnectionEvent.alternative_server_address`
//!                        carrying the parsed address / port / flags
//!                        when negotiated
//!   §6 ¶5     MUST       receiver enforces monotonically-increasing
//!                        Status Sequence Number — duplicate /
//!                        out-of-order frames are absorbed silently
//!                        without re-emitting an event
//!
//!   §8        NORMATIVE  end-to-end ALT_*_ADDRESS receipt under a
//!                        multipath-negotiated handshake — the
//!                        receive arm doesn't conflict with the
//!                        multipath dispatch and the surfaced event
//!                        carries the same payload as in the non-
//!                        multipath case
//!   §9        SHOULD     `alt_addr.recommendedMigrationDelayMs`
//!                        returns a value inside the embedder's
//!                        configured range (smearing the migration
//!                        across N concurrently-notified clients
//!                        per the thundering-herd mitigation)
//!
//! ## Out of scope here
//!
//!   * Driver-level auto-migration on receipt of a Preferred
//!     update — embedder policy. The connection surfaces the event;
//!     the embedder decides when (and whether) to validate and
//!     adopt the new path.

const std = @import("std");
const quic_zig = @import("quic_zig");
const handshake_fixture = @import("_handshake_fixture.zig");

const frame = quic_zig.frame;
const tls = quic_zig.tls;
const transport_params = tls.transport_params;
const varint = quic_zig.wire.varint;
const Frame = frame.types.Frame;

// ---------------------------------------------------------------- §4 transport parameter

test "MUST encode alternative_address transport parameter id as 8-byte varint of 0xff0969d85c [draft-munizaga-quic-alternative-server-address-00 §4]" {
    const sent: transport_params.Params = .{ .alternative_address = true };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    // 8-byte id varint + 1-byte length varint = 9 bytes total.
    try std.testing.expectEqual(@as(usize, 9), n);
    // Top two bits 0b11 → 8-byte varint length encoding; remaining 62
    // bits hold 0xff0969d85c zero-padded big-endian. Pinning the
    // prefix shape so a future encoder change can't silently shorten
    // the form.
    const expected: [9]u8 = .{
        0xc0, 0x00, 0x00, 0xff, 0x09, 0x69, 0xd8, 0x5c, // id (8-byte varint)
        0x00, // length varint (zero-length value)
    };
    try std.testing.expectEqualSlices(u8, &expected, buf[0..n]);
}

test "MUST decode the alternative_address transport parameter back to a true flag [draft-munizaga-quic-alternative-server-address-00 §4]" {
    const blob: [9]u8 = .{
        0xc0, 0x00, 0x00, 0xff, 0x09, 0x69, 0xd8, 0x5c, // id (8-byte varint)
        0x00, // zero-length value
    };
    const decoded = try transport_params.Params.decode(&blob);
    try std.testing.expect(decoded.alternative_address);
}

test "MUST reject alternative_address parameter with a non-empty value [draft-munizaga-quic-alternative-server-address-00 §4]" {
    // 8-byte id varint + length=1 + 1 body byte.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], transport_params.Id.alternative_address);
    pos += try varint.encode(buf[pos..], 1);
    buf[pos] = 0x00;
    pos += 1;
    try std.testing.expectError(
        transport_params.Error.InvalidValue,
        transport_params.Params.decode(buf[0..pos]),
    );
}

test "MUST NOT accept a server-authored alternative_address — TRANSPORT_PARAMETER_ERROR [draft-munizaga-quic-alternative-server-address-00 §4 ¶2]" {
    const example_scid = transport_params.ConnectionId.fromSlice(&.{ 0xb0, 0xb1, 0xb2, 0xb3 });
    const sent: transport_params.Params = .{
        .initial_source_connection_id = example_scid,
        // §7.3 ¶3 requires the OD-CID on a server blob without Retry,
        // so the server-shape is otherwise valid; the only nominal
        // violation is `alternative_address` itself.
        .original_destination_connection_id = example_scid,
        .alternative_address = true,
    };
    var buf: [128]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectError(
        transport_params.Error.TransportParameterError,
        transport_params.decodeAs(buf[0..n], .{
            .role = .server,
            .server_sent_retry = false,
        }),
    );
}

test "MAY accept a client-authored alternative_address [draft-munizaga-quic-alternative-server-address-00 §4]" {
    const example_scid = transport_params.ConnectionId.fromSlice(&.{ 0xb0, 0xb1, 0xb2, 0xb3 });
    const sent: transport_params.Params = .{
        .initial_source_connection_id = example_scid,
        .alternative_address = true,
    };
    var buf: [64]u8 = undefined;
    const n = try sent.encode(&buf);
    const got = try transport_params.decodeAs(buf[0..n], .{ .role = .client });
    try std.testing.expect(got.alternative_address);
}

test "MUST NOT remember alternative_address for 0-RTT [draft-munizaga-quic-alternative-server-address-00 §4 ¶3]" {
    // The receiving endpoint's stored `Params` defaults the field to
    // false. An embedder building a 0-RTT context from cached peer
    // parameters MUST NOT carry this field over; the default value
    // anchors the §4 ¶3 prohibition at the type level.
    const fresh: transport_params.Params = .{};
    try std.testing.expectEqual(false, fresh.alternative_address);
}

// ---------------------------------------------------------------- §6 frame format

test "MUST encode ALTERNATIVE_V4_ADDRESS type byte sequence as 4-byte varint of 0x1d5845e2 [draft-munizaga-quic-alternative-server-address-00 §6]" {
    var buf: [32]u8 = undefined;
    const n = try frame.encode(&buf, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 0,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    } });
    try std.testing.expectEqual(@as(usize, 4 + 1 + 1 + 4 + 2), n);
    // 4-byte varint of 0x1d5845e2 encodes to 0x9d, 0x58, 0x45, 0xe2.
    try std.testing.expectEqualSlices(u8, &.{ 0x9d, 0x58, 0x45, 0xe2 }, buf[0..4]);
}

test "MUST encode ALTERNATIVE_V6_ADDRESS type byte sequence as 4-byte varint of 0x1d5845e3 [draft-munizaga-quic-alternative-server-address-00 §6]" {
    var buf: [64]u8 = undefined;
    const n = try frame.encode(&buf, .{ .alternative_v6_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 0,
        .address = @splat(0),
        .port = 0,
    } });
    try std.testing.expectEqual(@as(usize, 4 + 1 + 1 + 16 + 2), n);
    try std.testing.expectEqualSlices(u8, &.{ 0x9d, 0x58, 0x45, 0xe3 }, buf[0..4]);
}

test "NORMATIVE Preferred is the high (first) flag bit; Retire is the next bit [draft-munizaga-quic-alternative-server-address-00 §6]" {
    // Preferred-only.
    var buf_pref: [32]u8 = undefined;
    const n_pref = try frame.encode(&buf_pref, .{ .alternative_v4_address = .{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 0,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    } });
    try std.testing.expectEqual(@as(u8, 0b1000_0000), buf_pref[4]);
    _ = n_pref;

    // Retire-only.
    var buf_ret: [32]u8 = undefined;
    const n_ret = try frame.encode(&buf_ret, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = true,
        .status_sequence_number = 0,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    } });
    try std.testing.expectEqual(@as(u8, 0b0100_0000), buf_ret[4]);
    _ = n_ret;

    // Both flags.
    var buf_both: [32]u8 = undefined;
    _ = try frame.encode(&buf_both, .{ .alternative_v4_address = .{
        .preferred = true,
        .retire = true,
        .status_sequence_number = 0,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    } });
    try std.testing.expectEqual(@as(u8, 0b1100_0000), buf_both[4]);
}

test "NORMATIVE flag byte's low 6 bits are unused (encoder zeroes them; decoder ignores them) [draft-munizaga-quic-alternative-server-address-00 §6]" {
    // Encode round-trip: encoder MUST zero the 6 unused bits.
    var enc: [32]u8 = undefined;
    _ = try frame.encode(&enc, .{ .alternative_v4_address = .{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 0,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    } });
    try std.testing.expectEqual(@as(u8, 0b1000_0000), enc[4]);
    try std.testing.expectEqual(@as(u8, 0), enc[4] & 0b0011_1111);

    // Decoder ignores the unused bits — flip them all and the decoded
    // flags read back unchanged.
    var dec_input: [12]u8 = .{
        0x9d, 0x58, 0x45, 0xe2, // type varint
        0b1000_1010, // Preferred=1, Retire=0, junk in unused
        0x00, // status seq = 0
        192, 0,    2, 1, 0x11, 0x51, // ipv4 + port
    };
    const d = try frame.decode(&dec_input);
    try std.testing.expect(d.frame == .alternative_v4_address);
    try std.testing.expectEqual(true, d.frame.alternative_v4_address.preferred);
    try std.testing.expectEqual(false, d.frame.alternative_v4_address.retire);
}

test "NORMATIVE Status Sequence Number round-trips across single- and multi-byte varints [draft-munizaga-quic-alternative-server-address-00 §6]" {
    const seqs = [_]u64{ 0, 1, 63, 64, 16383, 16384, 1_073_741_823 };
    for (seqs) |seq| {
        var buf: [64]u8 = undefined;
        const n = try frame.encode(&buf, .{ .alternative_v6_address = .{
            .preferred = false,
            .retire = false,
            .status_sequence_number = seq,
            .address = @splat(0),
            .port = 0,
        } });
        const d = try frame.decode(buf[0..n]);
        try std.testing.expect(d.frame == .alternative_v6_address);
        try std.testing.expectEqual(seq, d.frame.alternative_v6_address.status_sequence_number);
    }
}

test "NORMATIVE IPv4 address payload preserved byte-for-byte [draft-munizaga-quic-alternative-server-address-00 §6]" {
    const addr: [4]u8 = .{ 198, 51, 100, 7 };
    var buf: [32]u8 = undefined;
    const n = try frame.encode(&buf, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 5,
        .address = addr,
        .port = 4433,
    } });
    // Address bytes sit at offset 4 (type) + 1 (flags) + 1 (seq=5 single-byte) = 6.
    try std.testing.expectEqualSlices(u8, &addr, buf[6..10]);
    const d = try frame.decode(buf[0..n]);
    try std.testing.expectEqualSlices(u8, &addr, &d.frame.alternative_v4_address.address);
}

test "NORMATIVE IPv6 address payload preserved byte-for-byte [draft-munizaga-quic-alternative-server-address-00 §6]" {
    const addr: [16]u8 = .{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
    };
    var buf: [64]u8 = undefined;
    const n = try frame.encode(&buf, .{ .alternative_v6_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 0,
        .address = addr,
        .port = 8443,
    } });
    // 4 (type) + 1 (flags) + 1 (seq=0 single-byte) = 6, address spans 6..22.
    try std.testing.expectEqualSlices(u8, &addr, buf[6..22]);
    const d = try frame.decode(buf[0..n]);
    try std.testing.expectEqualSlices(u8, &addr, &d.frame.alternative_v6_address.address);
}

test "NORMATIVE port is encoded big-endian (network byte order) [draft-munizaga-quic-alternative-server-address-00 §6]" {
    var buf: [32]u8 = undefined;
    const n = try frame.encode(&buf, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 0,
        .address = .{ 0, 0, 0, 0 },
        .port = 0x1234,
    } });
    // Port at the tail: high byte before low byte.
    try std.testing.expectEqual(@as(u8, 0x12), buf[n - 2]);
    try std.testing.expectEqual(@as(u8, 0x34), buf[n - 1]);
    const d = try frame.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u16, 0x1234), d.frame.alternative_v4_address.port);
}

test "NORMATIVE sender can issue increasing Status Sequence Numbers across both frame types [draft-munizaga-quic-alternative-server-address-00 §6 ¶5]" {
    // §6 ¶5: "monotonically increasing values MUST be used when sending
    // updates." The codec preserves whatever sequence the sender
    // supplies — this test demonstrates correct framing of an
    // increasing run that mixes V4 and V6.
    const frames = [_]Frame{
        .{ .alternative_v4_address = .{
            .preferred = false,
            .retire = false,
            .status_sequence_number = 1,
            .address = .{ 192, 0, 2, 1 },
            .port = 4433,
        } },
        .{ .alternative_v6_address = .{
            .preferred = false,
            .retire = false,
            .status_sequence_number = 2,
            .address = @splat(0),
            .port = 4433,
        } },
        .{ .alternative_v4_address = .{
            .preferred = true,
            .retire = false,
            .status_sequence_number = 3,
            .address = .{ 198, 51, 100, 7 },
            .port = 4433,
        } },
    };

    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    for (frames) |f| {
        pos += try frame.encode(buf[pos..], f);
    }

    var it = frame.iter(buf[0..pos]);
    var expected_seq: u64 = 1;
    while (try it.next()) |f| {
        const seq = switch (f) {
            .alternative_v4_address => |a| a.status_sequence_number,
            .alternative_v6_address => |a| a.status_sequence_number,
            else => unreachable,
        };
        try std.testing.expectEqual(expected_seq, seq);
        expected_seq += 1;
    }
}

// ---------------------------------------------------------------- §7 frame properties

test "NORMATIVE receiver closes with PROTOCOL_VIOLATION on receipt without negotiation [draft-munizaga-quic-alternative-server-address-00 §7]" {
    // The default handshake-fixture client doesn't advertise
    // `alternative_address`, so per §7 (frames are gated on the
    // transport parameter) the receive arm of the frame dispatcher
    // closes with PROTOCOL_VIOLATION. ALT-3 paired this gate with a
    // negotiated-acceptance branch in the next test below.
    const allocator = std.testing.allocator;
    var pair = try handshake_fixture.HandshakePair.init(allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    var frame_buf: [32]u8 = undefined;
    const n = try frame.encode(&frame_buf, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    } });

    const close_event = try pair.injectFrameAtClient(frame_buf[0..n]);
    try std.testing.expect(close_event != null);
    try std.testing.expectEqual(
        handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION,
        close_event.?.error_code,
    );
}

test "NORMATIVE receiver surfaces a typed ALTERNATIVE_V4_ADDRESS event when client advertised support [draft-munizaga-quic-alternative-server-address-00 §6]" {
    // End-to-end: client advertises `alternative_address = true` in
    // its transport parameters during the handshake, server emits an
    // ALTERNATIVE_V4_ADDRESS frame, client accepts and surfaces a
    // typed `ConnectionEvent.alternative_server_address` carrying the
    // parsed address, port, sequence number, and flag bits.
    const allocator = std.testing.allocator;
    var client_params = handshake_fixture.defaultParams();
    client_params.alternative_address = true;
    var pair = try handshake_fixture.HandshakePair.initWith(
        allocator,
        handshake_fixture.defaultParams(),
        client_params,
    );
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // Inject the frame at the client side; the helper seals it with
    // the server's app-write keys (matching what a real
    // server.poll() emission looks like on the wire).
    var frame_buf: [32]u8 = undefined;
    const n = try frame.encode(&frame_buf, .{ .alternative_v4_address = .{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    } });

    const close_event = try pair.injectFrameAtClient(frame_buf[0..n]);
    try std.testing.expect(close_event == null);

    // Drain non-alt-addr events first (handshake completion, etc.),
    // then assert exactly one §6 event with the expected payload.
    var saw_alt: ?quic_zig.AlternativeServerAddressEvent = null;
    while (pair.clientConn().pollEvent()) |event| {
        if (event == .alternative_server_address) {
            saw_alt = event.alternative_server_address;
        }
    }
    const got = saw_alt orelse return error.TestUnexpectedNull;
    try std.testing.expect(got == .v4);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &got.v4.address);
    try std.testing.expectEqual(@as(u16, 4433), got.v4.port);
    try std.testing.expectEqual(@as(u64, 1), got.v4.status_sequence_number);
    try std.testing.expect(got.v4.preferred);
    try std.testing.expect(!got.v4.retire);
    try std.testing.expectEqual(
        @as(?u64, 1),
        pair.clientConn().highestAlternativeAddressSequenceSeen(),
    );
}

test "MUST absorb a duplicate Status Sequence Number without re-emitting the event [draft-munizaga-quic-alternative-server-address-00 §6 ¶5]" {
    // §6 ¶5: senders MUST use monotonically-increasing values. The
    // receiver's job under that contract is to dedupe retransmits and
    // tolerate out-of-order delivery without re-firing the event.
    const allocator = std.testing.allocator;
    var client_params = handshake_fixture.defaultParams();
    client_params.alternative_address = true;
    var pair = try handshake_fixture.HandshakePair.initWith(
        allocator,
        handshake_fixture.defaultParams(),
        client_params,
    );
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    var frame_buf: [32]u8 = undefined;
    const same: Frame = .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 7,
        .address = .{ 198, 51, 100, 7 },
        .port = 4433,
    } };
    const n = try frame.encode(&frame_buf, same);

    // Two identical frames carrying the same sequence number — the
    // second imitates a §13.3 retransmit.
    _ = try pair.injectFrameAtClient(frame_buf[0..n]);
    _ = try pair.injectFrameAtClient(frame_buf[0..n]);

    var alt_count: usize = 0;
    while (pair.clientConn().pollEvent()) |event| {
        if (event == .alternative_server_address) alt_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), alt_count);
}

test "MUST drop a stale (lower) Status Sequence Number as out-of-order delivery [draft-munizaga-quic-alternative-server-address-00 §6 ¶5]" {
    const allocator = std.testing.allocator;
    var client_params = handshake_fixture.defaultParams();
    client_params.alternative_address = true;
    var pair = try handshake_fixture.HandshakePair.initWith(
        allocator,
        handshake_fixture.defaultParams(),
        client_params,
    );
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    var buf_high: [32]u8 = undefined;
    const high_n = try frame.encode(&buf_high, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 10,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    } });
    var buf_low: [32]u8 = undefined;
    const low_n = try frame.encode(&buf_low, .{ .alternative_v4_address = .{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 3,
        .address = .{ 198, 51, 100, 7 },
        .port = 4433,
    } });

    // Receive seq=10 first — the receiver remembers 10 as the high
    // watermark. Then a delayed packet with seq=3 arrives; the
    // receiver MUST NOT close (no protocol violation) but MUST NOT
    // re-emit the event for the stale update.
    _ = try pair.injectFrameAtClient(buf_high[0..high_n]);
    _ = try pair.injectFrameAtClient(buf_low[0..low_n]);
    try std.testing.expect(pair.clientConn().closeEvent() == null);

    var seqs: [4]u64 = undefined;
    var len: usize = 0;
    while (pair.clientConn().pollEvent()) |event| {
        if (event == .alternative_server_address) {
            if (len < seqs.len) {
                seqs[len] = event.alternative_server_address.statusSequenceNumber();
                len += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u64, 10), seqs[0]);
    try std.testing.expectEqual(
        @as(?u64, 10),
        pair.clientConn().highestAlternativeAddressSequenceSeen(),
    );
}

test "NORMATIVE Connection.advertiseAlternativeV4Address emits a well-formed §6 frame end-to-end [draft-munizaga-quic-alternative-server-address-00 §6]" {
    const allocator = std.testing.allocator;
    var client_params = handshake_fixture.defaultParams();
    client_params.alternative_address = true;
    var pair = try handshake_fixture.HandshakePair.initWith(
        allocator,
        handshake_fixture.defaultParams(),
        client_params,
    );
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const srv_conn = try pair.serverConn();
    const seq = try srv_conn.advertiseAlternativeV4Address(
        .{ 198, 51, 100, 7 },
        4433,
        .{ .preferred = true },
    );
    try std.testing.expectEqual(@as(u64, 0), seq);
    try std.testing.expectEqual(
        @as(usize, 1),
        srv_conn.pending_frames.alternative_addresses.items.len,
    );

    // Pump packets — the server.poll() in `step` should drain the
    // queued frame onto the wire, the client.handle() runs the
    // receive arm, and neither side closes.
    try pair.step();
    try std.testing.expectEqual(
        @as(usize, 0),
        srv_conn.pending_frames.alternative_addresses.items.len,
    );
    try std.testing.expect(pair.clientConn().closeEvent() == null);
    try std.testing.expect(srv_conn.closeEvent() == null);
}

test "MUST close with TRANSPORT_PARAMETER_ERROR when server's transport params carry alternative_address [draft-munizaga-quic-alternative-server-address-00 §4 ¶2]" {
    // §4 ¶2: the server MUST NOT send the `alternative_address`
    // transport parameter; a supporting client that observes it MUST
    // abort with TRANSPORT_PARAMETER_ERROR. The handshake fixture's
    // server defaults don't set the flag, so we reach into the
    // fixture's params and toggle it before initWith. The client side
    // detects the violation in `validatePeerTransportRole` once
    // BoringSSL hands the decoded blob over after handshake.
    const allocator = std.testing.allocator;
    var server_params = handshake_fixture.defaultParams();
    server_params.alternative_address = true;
    var client_params = handshake_fixture.defaultParams();
    client_params.alternative_address = true;
    var pair = try handshake_fixture.HandshakePair.initWith(
        allocator,
        server_params,
        client_params,
    );
    defer pair.deinit();
    // Drive the handshake. Once the client decodes the server's
    // transport-parameter blob, `validatePeerTransportRole` closes
    // with TRANSPORT_PARAMETER_ERROR (wire code 0x08). `driveToHandshakeConfirmed`
    // will fail because the close prevents handshake completion, so
    // we don't `try` it — we just let it iterate, then inspect close.
    pair.driveToHandshakeConfirmed() catch {};

    const close_event = pair.clientConn().closeEvent();
    try std.testing.expect(close_event != null);
    try std.testing.expectEqual(
        @as(u64, 0x08), // TRANSPORT_PARAMETER_ERROR
        close_event.?.error_code,
    );
}

test "NORMATIVE advertiseAlternativeV4Address rejects calls from a client role [draft-munizaga-quic-alternative-server-address-00 §6]" {
    const allocator = std.testing.allocator;
    var pair = try handshake_fixture.HandshakePair.init(allocator);
    defer pair.deinit();

    const cli = pair.clientConn();
    try std.testing.expectError(
        // Connection.Error.NotServerContext via state.zig — surfaced
        // as the embedder-misuse signal "you're calling a server-only
        // API on a client connection".
        error.NotServerContext,
        cli.advertiseAlternativeV4Address(.{ 192, 0, 2, 1 }, 4433, .{}),
    );
    try std.testing.expectError(
        error.NotServerContext,
        cli.advertiseAlternativeV6Address(@splat(0), 4433, .{}),
    );
}

test "NORMATIVE advertiseAlternativeV4Address rejects calls before client advertised support [draft-munizaga-quic-alternative-server-address-00 §4]" {
    // Without the client advertising `alternative_address = true`,
    // `peerSupportsAlternativeAddress()` returns false and the API
    // refuses to queue the frame — calling it anyway would force the
    // (non-supporting) client into a PROTOCOL_VIOLATION close.
    const allocator = std.testing.allocator;
    var pair = try handshake_fixture.HandshakePair.init(allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const srv_conn = try pair.serverConn();
    try std.testing.expect(!srv_conn.peerSupportsAlternativeAddress());
    try std.testing.expectError(
        error.AlternativeAddressNotNegotiated,
        srv_conn.advertiseAlternativeV4Address(.{ 192, 0, 2, 1 }, 4433, .{}),
    );
}

test "NORMATIVE ALTERNATIVE_*_ADDRESS frames are ack-eliciting in a 1-RTT payload [draft-munizaga-quic-alternative-server-address-00 §7]" {
    // §7: "all frames are ack-eliciting, and MUST only be sent in the
    // application data packet number space." The codec doesn't track
    // packet-number-space gating (that's the connection state machine's
    // job — see the protocol-violation test below); but the
    // ack-eliciting classifier in `Connection` MUST agree.
    var buf: [32]u8 = undefined;
    const n = try frame.encode(&buf, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    } });
    try std.testing.expect(quic_zig.Connection.packetPayloadAckEliciting(buf[0..n]));

    var buf6: [64]u8 = undefined;
    const n6 = try frame.encode(&buf6, .{ .alternative_v6_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 2,
        .address = @splat(0),
        .port = 4433,
    } });
    try std.testing.expect(quic_zig.Connection.packetPayloadAckEliciting(buf6[0..n6]));
}

// ---------------------------------------------------------------- §8 multipath interaction (ALT-5)

test "NORMATIVE ALTERNATIVE_*_ADDRESS receipt under a multipath-negotiated handshake [draft-munizaga-quic-alternative-server-address-00 §8]" {
    // §8: "The Alternative Server Address frame extension can be
    // combined with the multipath extension." Smoke test that the
    // receive arm + event surfacing behaves identically when
    // multipath is also negotiated (`initial_max_path_id` on both
    // sides). Driver-level path-opening on the parsed address is an
    // embedder concern and stays out of scope here.
    const allocator = std.testing.allocator;
    var server_params = handshake_fixture.defaultParams();
    server_params.initial_max_path_id = 1;
    var client_params = handshake_fixture.defaultParams();
    client_params.alternative_address = true;
    client_params.initial_max_path_id = 1;
    var pair = try handshake_fixture.HandshakePair.initWith(
        allocator,
        server_params,
        client_params,
    );
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // Pre-condition: multipath is negotiated. The §8 statement is
    // about composability — the test only proves something useful if
    // both extensions are simultaneously live.
    try std.testing.expect(pair.clientConn().multipathNegotiated());
    const srv_conn_pre = try pair.serverConn();
    try std.testing.expect(srv_conn_pre.multipathNegotiated());

    var frame_buf: [32]u8 = undefined;
    const n = try frame.encode(&frame_buf, .{ .alternative_v4_address = .{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    } });
    const close_event = try pair.injectFrameAtClient(frame_buf[0..n]);
    try std.testing.expect(close_event == null);

    var saw: ?quic_zig.AlternativeServerAddressEvent = null;
    while (pair.clientConn().pollEvent()) |event| {
        if (event == .alternative_server_address) saw = event.alternative_server_address;
    }
    const got = saw orelse return error.TestUnexpectedNull;
    try std.testing.expect(got == .v4);
    try std.testing.expectEqual(@as(u64, 1), got.v4.status_sequence_number);
    try std.testing.expectEqual(@as(u16, 4433), got.v4.port);
}

// ---------------------------------------------------------------- §9 thundering-herd mitigation

test "SHOULD recommendedMigrationDelayMs returns a value within the requested range [draft-munizaga-quic-alternative-server-address-00 §9]" {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const v = try quic_zig.alt_addr.recommendedMigrationDelayMs(50, 500);
        try std.testing.expect(v >= 50);
        try std.testing.expect(v <= 500);
    }
}

test "MUST close with PROTOCOL_VIOLATION on receipt of an ALTERNATIVE_*_ADDRESS frame at the 0-RTT level [draft-munizaga-quic-alternative-server-address-00 §4 ¶3]" {
    // §4 ¶3 forbids remembering the `alternative_address` transport
    // parameter for 0-RTT, so a peer cannot have completed the §4
    // negotiation by the time a 0-RTT packet is processed. The
    // receive path rejects the frame at the early-data gate
    // (`frameAllowedInEarlyData`) rather than at the per-frame
    // negotiation check, giving operators a clear diagnostic.
    const allocator = std.testing.allocator;
    var pair = try handshake_fixture.HandshakePair.init(allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    var frame_buf: [32]u8 = undefined;
    const n = try frame.encode(&frame_buf, .{ .alternative_v4_address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    } });

    const close_event = try pair.injectFrameAtServer0Rtt(frame_buf[0..n]);
    try std.testing.expect(close_event != null);
    try std.testing.expectEqual(
        handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION,
        close_event.?.error_code,
    );
}

test "SHOULD recommendedMigrationDelayMs returns the lower bound when the range collapses [draft-munizaga-quic-alternative-server-address-00 §9]" {
    // A degenerate range is plausible (e.g. an embedder that always
    // wants a fixed 25 ms delay). The helper preserves that contract
    // rather than panicking so config files can express it.
    try std.testing.expectEqual(
        @as(u64, 25),
        try quic_zig.alt_addr.recommendedMigrationDelayMs(25, 25),
    );
}
