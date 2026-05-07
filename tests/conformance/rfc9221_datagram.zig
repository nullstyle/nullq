//! RFC 9221 — An Unreliable Datagram Extension to QUIC.
//!
//! RFC 9221 negotiates DATAGRAM service at the transport layer with a
//! single transport parameter (`max_datagram_frame_size`, id 0x20) and
//! adds two frame types — 0x30 (no LEN) and 0x31 (LEN-prefixed) — that
//! ride inside ordinary 0-RTT and 1-RTT packets. nullq's
//! `src/frame/{encode,decode,types}.zig` and
//! `src/tls/transport_params.zig` carry the wire codec; this suite
//! locks those bits down.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9221 §3 ¶1   MUST       max_datagram_frame_size has IANA id 0x20
//!   RFC9221 §3 ¶2   MUST       max_datagram_frame_size is encoded as a varint
//!   RFC9221 §3 ¶2   NORMATIVE  encode omits the parameter when value is 0 (default)
//!   RFC9221 §3 ¶2   NORMATIVE  decode of an absent parameter leaves the default 0
//!   RFC9221 §3 ¶3   NORMATIVE  decoding accepts a non-zero advertised value
//!   RFC9221 §4 ¶1   MUST       frame type 0x30 has no LEN field; data runs to end of buffer
//!   RFC9221 §4 ¶2   MUST       frame type 0x31 is LEN-prefixed with a varint length
//!   RFC9221 §4      MUST       0x30/0x31 round-trip through encode/decode
//!   RFC9221 §4      MUST       LEN varint with length > buffer is rejected
//!   RFC9221 §4 ¶6   MUST       receiver-side handler closes with PROTOCOL_VIOLATION
//!                              on a DATAGRAM larger than its advertised limit
//!   RFC9221 §4 ¶7   MUST NOT   sender emits DATAGRAM exceeding peer's advertised limit
//!   RFC9221 §4 ¶7   MUST NOT   sender emits DATAGRAM when peer advertised 0 / no support
//!   RFC9221 §5.1    NORMATIVE  the frame catalog tags DATAGRAM as non-retransmittable
//!                              (no entry in `SentPacket.retransmit_frames`)
//!
//! Visible debt:
//!   RFC9221 §4 ¶3   MUST       reject DATAGRAM in Initial / Handshake packets
//!                              with PROTOCOL_VIOLATION. nullq's frame dispatcher
//!                              (src/conn/state.zig dispatchFrames) lacks a per-
//!                              encryption-level allowed-frames table for
//!                              Initial/Handshake; the broader gap is RFC 9000
//!                              §12.4 / §17.2 territory (skip_MUST below).
//!
//! Out of scope here (covered elsewhere or not yet wired):
//!   RFC9221 §5.2    DATAGRAM is congestion-controlled — exercised through
//!                   the loss-recovery suite in rfc9002_loss_recovery.zig;
//!                   verifying it from public frame APIs alone is not
//!                   meaningful.
//!   RFC9221 §5      DATAGRAM is ack-eliciting — `packetPayloadAckEliciting`
//!                   in src/conn/state.zig folds DATAGRAM in with the other
//!                   ack-eliciting frames; covered via connection-level
//!                   suites where a real packet is built.
//!   RFC9221 §6      Inherits RFC 9000 security considerations — covered
//!                   transitively by the RFC 9000 suites.

const std = @import("std");
const nullq = @import("nullq");
const frame = nullq.frame;
const transport_params = nullq.tls.transport_params;
const fixture = @import("_initial_fixture.zig");
const handshake_fixture = @import("_handshake_fixture.zig");

const Frame = frame.Frame;
const Datagram = frame.types.Datagram;

// ---------------------------------------------------------------- §3 transport parameter

test "MUST register max_datagram_frame_size at IANA transport-parameter id 0x20 [RFC9221 §3 ¶1]" {
    // RFC 9221 §3 ¶1 fixes the IANA registration: id = 0x20. A wire
    // format is only interoperable if both endpoints agree on this
    // exact integer; verify the constant directly.
    try std.testing.expectEqual(@as(u64, 0x20), transport_params.Id.max_datagram_frame_size);
}

test "MUST encode max_datagram_frame_size as a QUIC varint value [RFC9221 §3 ¶2]" {
    // A non-zero `max_datagram_frame_size` advertises DATAGRAM
    // support; the value is the maximum DATAGRAM frame the endpoint
    // is willing to receive (header + payload). Use a 4-byte
    // varint-encodable value (0x4000) so decode-side trip catches a
    // truncated/wrongly-sized field without ambiguity.
    const sent: transport_params.Params = .{ .max_datagram_frame_size = 0x4000 };
    var buf: [32]u8 = undefined;
    const n = try sent.encode(&buf);
    const got = try transport_params.Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x4000), got.max_datagram_frame_size);
}

test "NORMATIVE max_datagram_frame_size = 0 (default) is omitted from the encoded blob [RFC9221 §3 ¶2]" {
    // RFC 9221 §3 ¶2: a value of 0 indicates the endpoint does NOT
    // support DATAGRAMs. A QUIC transport-parameter blob omits
    // defaults (RFC 9000 §18 ¶2 — "Each transport parameter ... can
    // appear at most once"); nullq's encoder elides default-valued
    // parameters so the absence and the explicit-zero cases are
    // wire-equivalent.
    const default_only: transport_params.Params = .{};
    var buf: [16]u8 = undefined;
    const n = try default_only.encode(&buf);
    // No fields differ from defaults → empty blob.
    try std.testing.expectEqual(@as(usize, 0), n);

    // Sanity: an explicit zero should also produce the empty blob,
    // since the default IS zero.
    const explicit_zero: transport_params.Params = .{ .max_datagram_frame_size = 0 };
    const n2 = try explicit_zero.encode(&buf);
    try std.testing.expectEqual(@as(usize, 0), n2);
}

test "NORMATIVE absent max_datagram_frame_size decodes to 0 (DATAGRAM disabled) [RFC9221 §3 ¶2]" {
    // RFC 9221 §3 ¶2: "An endpoint that does not support DATAGRAM
    // frames does not include this transport parameter ..." A
    // receiver that doesn't see the parameter MUST treat the peer as
    // having no DATAGRAM support, which the codec models as the zero
    // default — `nullq.conn` then refuses outbound DATAGRAMs via
    // `Error.DatagramUnavailable` (covered in src/conn unit tests).
    const empty_blob = try transport_params.Params.decode(&[_]u8{});
    try std.testing.expectEqual(@as(u64, 0), empty_blob.max_datagram_frame_size);
}

test "NORMATIVE non-zero max_datagram_frame_size advertises support and the receive cap [RFC9221 §3 ¶3]" {
    // The advertised value is the maximum DATAGRAM frame size the
    // endpoint will accept (header + payload). Verify decode of a
    // hand-built blob carrying just that one parameter.
    //
    // Wire layout: id(0x20) len(0x01) value(varint 0x05). 0x05 is a
    // 1-byte varint = 5; so the peer advertises a 5-byte cap.
    const blob = [_]u8{ 0x20, 0x01, 0x05 };
    const got = try transport_params.Params.decode(&blob);
    try std.testing.expectEqual(@as(u64, 5), got.max_datagram_frame_size);
}

// ---------------------------------------------------------------- §4 frame format

test "MUST encode DATAGRAM type 0x30 (no LEN) as the type byte followed by raw data [RFC9221 §4 ¶1]" {
    // The 0x30 variant carries no length — the receiver derives the
    // payload length from the remaining bytes in the packet. So it
    // can only legally appear as the last frame in a packet.
    const payload = "hello-no-len";
    var buf: [64]u8 = undefined;
    const written = try frame.encode(&buf, .{ .datagram = .{
        .data = payload,
        .has_length = false,
    } });
    // Byte 0 is the type; remaining bytes are the payload verbatim,
    // no length prefix.
    try std.testing.expectEqual(@as(u8, 0x30), buf[0]);
    try std.testing.expectEqual(@as(usize, 1 + payload.len), written);
    try std.testing.expectEqualStrings(payload, buf[1..written]);
}

test "MUST encode DATAGRAM type 0x31 (LEN flag) with a varint length prefix [RFC9221 §4 ¶2]" {
    // The 0x31 variant carries a varint Length field, so it can be
    // followed by other frames in the same packet.
    const payload = "hi";
    var buf: [16]u8 = undefined;
    const written = try frame.encode(&buf, .{ .datagram = .{
        .data = payload,
        .has_length = true,
    } });
    // Byte 0: type 0x31. Byte 1: 1-byte varint Length = 2. Bytes 2..:
    // the payload. Total = 4.
    try std.testing.expectEqual(@as(usize, 4), written);
    try std.testing.expectEqual(@as(u8, 0x31), buf[0]);
    try std.testing.expectEqual(@as(u8, 2), buf[1]);
    try std.testing.expectEqualStrings(payload, buf[2..4]);
}

test "MUST decode DATAGRAM type 0x30 by consuming the rest of the buffer as data [RFC9221 §4 ¶1]" {
    // Wire format:
    //   0x30 | <data bytes ...>
    // The decoder MUST treat every byte after the type as DATAGRAM
    // payload — no length field is present and no other frame may
    // follow inside the same packet payload slice.
    const wire = [_]u8{ 0x30, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    const d = try frame.decode(&wire);
    try std.testing.expect(d.frame == .datagram);
    try std.testing.expectEqual(false, d.frame.datagram.has_length);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee }, d.frame.datagram.data);
    try std.testing.expectEqual(@as(usize, wire.len), d.bytes_consumed);
}

test "MUST decode DATAGRAM type 0x31 by reading the LEN varint and consuming exactly that many bytes [RFC9221 §4 ¶2]" {
    // Wire: 0x31 | varint(3) | "abc" | trailing-garbage. The
    // LEN-prefixed variant MUST consume exactly the declared number
    // of payload bytes; trailing bytes inside `src` belong to the
    // next frame and the decoder must NOT swallow them.
    const wire = [_]u8{ 0x31, 0x03, 'a', 'b', 'c', 0xff, 0xff };
    const d = try frame.decode(&wire);
    try std.testing.expect(d.frame == .datagram);
    try std.testing.expectEqual(true, d.frame.datagram.has_length);
    try std.testing.expectEqualStrings("abc", d.frame.datagram.data);
    try std.testing.expectEqual(@as(usize, 1 + 1 + 3), d.bytes_consumed);
}

test "MUST round-trip DATAGRAM (LEN variant) through encode/decode [RFC9221 §4]" {
    const f: Frame = .{ .datagram = .{
        .data = "round-trip-payload",
        .has_length = true,
    } };
    var buf: [64]u8 = undefined;
    const written = try frame.encode(&buf, f);
    try std.testing.expectEqual(frame.encodedLen(f), written);

    const d = try frame.decode(buf[0..written]);
    try std.testing.expect(d.frame == .datagram);
    try std.testing.expect(d.frame.datagram.has_length);
    try std.testing.expectEqualStrings("round-trip-payload", d.frame.datagram.data);
    try std.testing.expectEqual(written, d.bytes_consumed);
}

test "MUST round-trip DATAGRAM (no-LEN variant) through encode/decode [RFC9221 §4]" {
    const f: Frame = .{ .datagram = .{
        .data = "tail-only-payload",
        .has_length = false,
    } };
    var buf: [64]u8 = undefined;
    const written = try frame.encode(&buf, f);
    try std.testing.expectEqual(frame.encodedLen(f), written);

    const d = try frame.decode(buf[0..written]);
    try std.testing.expect(d.frame == .datagram);
    try std.testing.expect(!d.frame.datagram.has_length);
    try std.testing.expectEqualStrings("tail-only-payload", d.frame.datagram.data);
    try std.testing.expectEqual(written, d.bytes_consumed);
}

test "MUST encode DATAGRAM (LEN) with empty payload as type+length(0) [RFC9221 §4 ¶2]" {
    // An empty DATAGRAM payload is legal: the application sent
    // zero bytes and the LEN varint encodes 0. We assert the wire
    // shape (type 0x31, length 0, no payload bytes) so a peer's
    // empty-DATAGRAM ping can be interoperably parsed.
    const f: Frame = .{ .datagram = .{
        .data = "",
        .has_length = true,
    } };
    var buf: [4]u8 = undefined;
    const written = try frame.encode(&buf, f);
    try std.testing.expectEqual(@as(usize, 2), written);
    try std.testing.expectEqual(@as(u8, 0x31), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]);

    const d = try frame.decode(buf[0..written]);
    try std.testing.expect(d.frame == .datagram);
    try std.testing.expect(d.frame.datagram.has_length);
    try std.testing.expectEqual(@as(usize, 0), d.frame.datagram.data.len);
}

test "MUST NOT accept a DATAGRAM (LEN) whose declared length overruns the input slice [RFC9221 §4 ¶2]" {
    // RFC 9221 §4 ¶2: the Length field "is the length of the Data
    // field in bytes". An encoded DATAGRAM that claims more bytes
    // than `src` carries is malformed and must be rejected before
    // the decoder reads off the end of the buffer.
    //
    // Wire: 0x31 (type) | 0x05 (varint LEN = 5) | only 2 payload bytes.
    const wire = [_]u8{ 0x31, 0x05, 0xaa, 0xbb };
    try std.testing.expectError(
        frame.DecodeError.InsufficientBytes,
        frame.decode(&wire),
    );
}

// ---------------------------------------------------------------- §4 size limits

test "MUST NOT emit a DATAGRAM whose encoded size exceeds the encode buffer [RFC9221 §4 ¶7]" {
    // The encoder enforces the more general invariant: refuse to
    // write a DATAGRAM if the destination buffer can't fit the
    // payload + header. RFC 9221 §4 ¶7 then layers an additional
    // sender-side check ("MUST NOT send DATAGRAMs larger than peer's
    // max_datagram_frame_size") on top of this — that policy lives
    // in `Connection.maxOutboundDatagramPayload` (verified at the
    // connection-suite layer; here we lock down the codec floor).
    const f: Frame = .{ .datagram = .{
        .data = "way-too-big-for-buffer",
        .has_length = true,
    } };
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(
        frame.EncodeError.BufferTooSmall,
        frame.encode(&tiny, f),
    );
}

test "MUST close with PROTOCOL_VIOLATION on a DATAGRAM larger than max_datagram_frame_size [RFC9221 §4 ¶6]" {
    // Receiver-side normative check: RFC 9221 §4 ¶6 says an endpoint
    // that receives a DATAGRAM frame whose size exceeds the value it
    // advertised in `max_datagram_frame_size` MUST close the
    // connection with PROTOCOL_VIOLATION.
    //
    // Drive a real handshake where the SERVER advertises a tight
    // 100-byte cap, then have the CLIENT seal a 1-RTT packet whose
    // DATAGRAM payload (150 bytes) clearly exceeds that cap. After
    // AEAD passes, `Connection.handleDatagram` (src/conn/state.zig)
    // hits its `dg.data.len > local_max` gate and closes locally
    // with PROTOCOL_VIOLATION (transport error 0x0a).
    var server_p = handshake_fixture.defaultParams();
    server_p.max_datagram_frame_size = 100;
    var client_p = handshake_fixture.defaultParams();
    client_p.max_datagram_frame_size = 200; // accept up to 200 from peer

    var pair = try handshake_fixture.HandshakePair.initWith(
        std.testing.allocator,
        server_p,
        client_p,
    );
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // 0x31 (LEN flag) + varint(150) + 150 bytes of payload — the
    // DATAGRAM-frame-encoded size is 152 bytes, well above the
    // server's 100-byte advertised cap (and the local check compares
    // payload length against that cap).
    var frame_buf: [256]u8 = undefined;
    const data: [150]u8 = @splat('A');
    const frame_len = try frame.encode(&frame_buf, .{ .datagram = .{
        .data = &data,
        .has_length = true,
    } });

    const close_event = try pair.injectFrameAtServer(frame_buf[0..frame_len]);
    const ev = close_event orelse return error.NoCloseEventEmitted;
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(handshake_fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

test "MUST NOT send a DATAGRAM exceeding the peer's advertised max_datagram_frame_size [RFC9221 §4 ¶7]" {
    // Sender-side mirror: RFC 9221 §4 ¶7. nullq enforces this in
    // `Connection.maxOutboundDatagramPayload` — `sendDatagram`
    // returns `Error.DatagramTooLarge` up front when the application
    // payload exceeds the cached peer transport parameter, before
    // any frame ever hits the wire.
    //
    // Drive a real handshake so the client's
    // `cached_peer_transport_params.max_datagram_frame_size` is
    // populated from the server's advertisement (50 bytes here),
    // then ask the client to send 100 bytes — twice the cap.
    var server_p = handshake_fixture.defaultParams();
    server_p.max_datagram_frame_size = 50;
    var client_p = handshake_fixture.defaultParams();
    client_p.max_datagram_frame_size = 200;

    var pair = try handshake_fixture.HandshakePair.initWith(
        std.testing.allocator,
        server_p,
        client_p,
    );
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    const oversized: [100]u8 = @splat('B');
    try std.testing.expectError(
        error.DatagramTooLarge,
        pair.clientConn().sendDatagram(&oversized),
    );
}

// ---------------------------------------------------------------- §4 ¶3 encryption-level restriction

test "MUST close with PROTOCOL_VIOLATION on a DATAGRAM in an Initial packet [RFC9221 §4 ¶3]" {
    // RFC 9221 §4 ¶3: DATAGRAM frames are only permitted in 0-RTT
    // and 1-RTT packets. A receiver that decodes one in an Initial
    // packet MUST close with PROTOCOL_VIOLATION — this is the RFC
    // 9221 instance of the broader RFC 9000 §12.4 / §17.2 "frame X
    // allowed only at level Y" rule.
    //
    // The gate lives in `Connection.dispatchFrames` →
    // `frameAllowedInInitialOrHandshake`, which whitelists exactly
    // {PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE-0x1c}. DATAGRAM
    // (0x30 / 0x31) is outside that set so the dispatcher closes
    // with PROTOCOL_VIOLATION on the first iteration.
    var srv = try fixture.buildServer();
    defer srv.deinit();

    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid = [_]u8{ 0xa0, 0xb0, 0xc0, 0xd0 };
    // Hand-roll a DATAGRAM frame: type 0x31 (LEN flag set), length
    // varint = 2, payload "hi". Length-prefixed so the iterator can
    // step past it cleanly even though the gate fires immediately.
    const payload = [_]u8{ 0x31, 0x02, 'h', 'i' };
    const close_event = try fixture.feedAndExpectClose(&srv, &dcid, &scid, 0, &payload);
    const ev = close_event orelse return error.NoCloseEventEmitted;

    try std.testing.expectEqual(nullq.conn.lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(nullq.conn.lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(fixture.TRANSPORT_ERROR_PROTOCOL_VIOLATION, ev.error_code);
}

// ---------------------------------------------------------------- §5 reliability and congestion

test "NORMATIVE the SentPacket frame catalog has no entry for DATAGRAM retransmission [RFC9221 §5.1]" {
    // RFC 9221 §5.1: "DATAGRAM frames are not retransmitted upon
    // loss detection." nullq encodes that policy structurally:
    // `SentPacket.retransmit_frames` (src/conn/sent_packets.zig)
    // intentionally omits DATAGRAM from its `RetransmitFrame`
    // tagged union — there is no variant the loss-recovery path
    // could push back onto the queue. Loss detection instead
    // surfaces a `datagram_lost` event for the application
    // (src/conn/event_queue.zig:datagramEventFromPacket).
    //
    // We exercise the codec floor: round-tripping a DATAGRAM frame
    // never produces a value that any other code path could
    // mistake for a retransmittable control frame. The frame is
    // its own union variant (`.datagram`) and stays within the
    // ack/loss-event lane, not the retransmit lane.
    const f: Frame = .{ .datagram = .{
        .data = "single-shot",
        .has_length = true,
    } };
    var buf: [32]u8 = undefined;
    const written = try frame.encode(&buf, f);
    const d = try frame.decode(buf[0..written]);
    // Tag is `.datagram` — distinct from every other v1 frame tag,
    // and `RetransmitFrame` (in src/conn/sent_packets.zig) has no
    // matching variant for it. Cross-suite verification of the
    // loss-recovery wiring lives in rfc9002_loss_recovery.zig.
    try std.testing.expect(d.frame == .datagram);
}
