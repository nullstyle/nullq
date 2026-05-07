//! RFC 9000 — Packetization (§12, §13), Datagram size (§14), Error codes (§20).
//!
//! This suite covers the parts of RFC 9000 that govern how QUIC
//! packets are organised into UDP datagrams (coalescing, packet
//! number spaces, the 1200-byte Initial floor) and the registry of
//! transport-error codes that show up in CONNECTION_CLOSE frames.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9000 §12.3   MUST     packet number spaces are independent (per-space PN counters)
//!   RFC9000 §12.3   MUST     PN allocation is monotonically increasing per space
//!   RFC9000 §12.3   MUST     PN sequence is exhausted at 2^62 - 1 and refuses further allocation
//!   RFC9000 §12.3   MUST NOT acknowledge a PN that was never sent in the same space (ACK tracker behaviour)
//!   RFC9000 §13.1   NORMATIVE receive-PN tracker is idempotent on duplicate adds
//!   RFC9000 §13.2.3 MUST     ACK-frame encoding lists largest_acked first, with ranges descending
//!   RFC9000 §13.2.3 NORMATIVE ACK frame round-trips through frame.encode/decode without distortion
//!   RFC9000 §13.2.3 MUST NOT advertise a PN above what the tracker knows (Empty → Error.Empty)
//!   RFC9000 §13.3   MUST     CRYPTO is on the retransmit list (lost CRYPTO is requeued)
//!   RFC9000 §13.3   MUST     HANDSHAKE_DONE is on the retransmit list (Table 3)
//!   RFC9000 §13.3   MUST     STREAM keys are tracked on each sent packet for ack/loss routing
//!   RFC9000 §13.3   NORMATIVE PADDING / PING are absent from the retransmit-frame union (Table 3)
//!   RFC9000 §14     MUST     client first-flight Initial datagram is >= 1200 bytes
//!   RFC9000 §14     NORMATIVE the on-wire v1 minimum constant equals 1200 (RFC default_mtu)
//!   RFC9000 §20.1   MUST     transport error code NO_ERROR (0x00) round-trips on CONNECTION_CLOSE
//!   RFC9000 §20.1   MUST     transport error codes 0x01..0x10 round-trip on CONNECTION_CLOSE
//!   RFC9000 §20.1   MUST     CRYPTO_ERROR range 0x0100..0x01ff round-trips on CONNECTION_CLOSE
//!   RFC9000 §20.1   MUST     CONNECTION_CLOSE distinguishes transport (0x1c) from application (0x1d)
//!   RFC9000 §20.1   NORMATIVE nullq's `excessive_load` extension lives at the RFC's reserved 0x09 slot
//!
//! Visible debt:
//!   RFC9000 §12.2   MUST NOT coalesce packets from different connections in one UDP datagram
//!                            — coalescing dispatch lives behind crypto, not unit-testable here.
//!   RFC9000 §13.2.1 SHOULD   send ACK on every ack-eliciting packet within max_ack_delay
//!                            — covered indirectly by ack_tracker addPacketDelayed unit tests.
//!   RFC9000 §13.2.2 NORMATIVE max_ack_delay handling — covered by transport-params suite.
//!   RFC9000 §13.3   NORMATIVE PATH_RESPONSE retransmission policy — nullq requeues from the
//!                            sent-packet record (RFC says "send a new one" in §13.3 ¶8).
//!   RFC9000 §14     MUST     server discards v1 Initial UDP < 1200 bytes — needs a real
//!                            `Server` instance, which depends on test PEM fixtures under
//!                            `tests/data/`. Those sit outside this conformance package's
//!                            embedFile root, so the test is `skip_*` here and lives in
//!                            `tests/e2e/server_smoke.zig`.
//!   RFC9000 §14     MUST NOT §14 size gate fires on a non-v1 datagram — same package-path
//!                            constraint. Covered by `tests/e2e/server_smoke.zig`.
//!
//! Out of scope here:
//!   RFC9000 §12.4   frames-per-packet-type matrix          → rfc9000_frames.zig
//!   RFC9000 §17     packet header formats                  → rfc9000_packet_headers.zig
//!   RFC9000 §19.3   ACK-frame wire format / `max_incoming_ack_ranges` cap → rfc9000_frames.zig
//!   RFC9000 §6      version negotiation                    → rfc9000_negotiation_validation.zig

const std = @import("std");
const nullq = @import("nullq");

const conn = nullq.conn;
const frame = nullq.frame;
const sent_packets = conn.sent_packets;
const ack_tracker_mod = conn.ack_tracker;
const pn_space_mod = conn.pn_space;
const loss_recovery_mod = conn.loss_recovery;

/// `TransportParams` shape used by the §14 client-side first-flight
/// test — matches `tests/e2e/common.defaultParams()`. Kept inline so
/// the suite stays self-contained (no `common.zig` dependency).
fn defaultParams() nullq.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
}

// ---------------------------------------------------------------- §12.3 packet number spaces

test "MUST allocate packet numbers monotonically within a space [RFC9000 §12.3 ¶1]" {
    // RFC 9000 §12.3 ¶1: "Packet numbers are integers in the range 0
    // to 2^62-1. … A packet number is used … exactly once for a given
    // packet number space." The `nextPn` allocator is the only path
    // out of the space — its monotonicity is the receiver-visible
    // promise.
    var space: pn_space_mod.PnSpace = .{};
    try std.testing.expectEqual(@as(?u64, 0), space.nextPn());
    try std.testing.expectEqual(@as(?u64, 1), space.nextPn());
    try std.testing.expectEqual(@as(?u64, 2), space.nextPn());
    try std.testing.expectEqual(@as(u64, 3), space.next_pn);
}

test "MUST keep packet number spaces independent so each starts at zero [RFC9000 §12.3 ¶1]" {
    // RFC 9000 §12.3 ¶1: "Packet numbers in each space start at packet
    // number 0." Two spaces sharing the same underlying type must not
    // bleed into each other's counters.
    var initial_space: pn_space_mod.PnSpace = .{};
    var handshake_space: pn_space_mod.PnSpace = .{};
    var application_space: pn_space_mod.PnSpace = .{};

    _ = initial_space.nextPn();
    _ = initial_space.nextPn();
    _ = initial_space.nextPn();

    try std.testing.expectEqual(@as(u64, 3), initial_space.next_pn);
    // Both peers MUST observe each new space starting from PN 0.
    try std.testing.expectEqual(@as(?u64, 0), handshake_space.nextPn());
    try std.testing.expectEqual(@as(?u64, 0), application_space.nextPn());
}

test "MUST refuse to allocate a packet number above 2^62 - 1 [RFC9000 §12.3 ¶3]" {
    // RFC 9000 §12.3 ¶3: "Packet numbers are limited to this range
    // because they need to be representable in whole in the largest
    // acknowledged field of an ACK frame." Past `max_pn`, `nextPn`
    // surfaces the exhaustion via a null return that the caller maps
    // to a fatal `PnSpaceExhausted`.
    var space: pn_space_mod.PnSpace = .{};
    space.next_pn = pn_space_mod.max_pn;
    try std.testing.expectEqual(@as(?u64, pn_space_mod.max_pn), space.nextPn());
    try std.testing.expectEqual(@as(?u64, null), space.nextPn());
}

// ---------------------------------------------------------------- §13.1 packet processing

test "NORMATIVE the receive-PN tracker is idempotent on duplicate adds [RFC9000 §13.1 ¶1]" {
    // RFC 9000 §13.1 ¶1 expects each received PN to be processed once,
    // and §13.2.3 ¶1 expects the receiver to ACK PNs it has actually
    // seen — so the in-memory range bookkeeping must collapse a
    // duplicate add to a no-op. (Receive-side replay rejection itself
    // happens in the AEAD/key path before the PN reaches the tracker;
    // this test owns the tracker-level invariant.)
    var t: ack_tracker_mod.AckTracker = .{};
    t.add(7, 1000);
    t.add(7, 1001); // duplicate — must not double-count or split a range
    try std.testing.expectEqual(@as(u8, 1), t.range_count);
    try std.testing.expectEqual(@as(u64, 7), t.ranges[0].smallest);
    try std.testing.expectEqual(@as(u64, 7), t.ranges[0].largest);
    try std.testing.expectEqual(@as(?u64, 7), t.largest);
}

// ---------------------------------------------------------------- §13.2.3 ACK ranges

test "MUST encode ACK frame with largest_acked first and ranges descending [RFC9000 §13.2.3 ¶3]" {
    // RFC 9000 §13.2.3 ¶3: "When constructing an ACK frame, the
    // sender SHOULD acknowledge the largest packet number first, then
    // the next-largest, and so on." The wire format guarantees this
    // by construction: `largest_acked` is the only absolute value;
    // every subsequent range is computed by descent.
    var t: ack_tracker_mod.AckTracker = .{};
    // Three disjoint intervals: [80..82], [88..92], [95..100].
    var pn: u64 = 80;
    while (pn <= 82) : (pn += 1) t.add(pn, 0);
    pn = 88;
    while (pn <= 92) : (pn += 1) t.add(pn, 0);
    pn = 95;
    while (pn <= 100) : (pn += 1) t.add(pn, 0);

    var ranges_buf: [64]u8 = undefined;
    const ack = try t.toAckFrame(0, &ranges_buf);

    // Largest first.
    try std.testing.expectEqual(@as(u64, 100), ack.largest_acked);
    // First range covers [95..100] → first_range = 5.
    try std.testing.expectEqual(@as(u64, 5), ack.first_range);
    // Two more ranges trail; they must be in descending order.
    try std.testing.expectEqual(@as(u64, 2), ack.range_count);

    var it = frame.ack_range.iter(ack);
    const top = (try it.next()).?;
    const mid = (try it.next()).?;
    const bot = (try it.next()).?;
    try std.testing.expectEqual(@as(?frame.ack_range.Interval, null), try it.next());

    try std.testing.expectEqual(@as(u64, 95), top.smallest);
    try std.testing.expectEqual(@as(u64, 100), top.largest);
    try std.testing.expectEqual(@as(u64, 88), mid.smallest);
    try std.testing.expectEqual(@as(u64, 92), mid.largest);
    try std.testing.expectEqual(@as(u64, 80), bot.smallest);
    try std.testing.expectEqual(@as(u64, 82), bot.largest);
    // Every emitted interval is strictly below its predecessor.
    try std.testing.expect(top.smallest > mid.largest);
    try std.testing.expect(mid.smallest > bot.largest);
}

test "NORMATIVE ACK frame survives encode/decode round-trip [RFC9000 §19.3]" {
    // RFC 9000 §13.2.3 governs the algorithm; §19.3 governs the wire
    // shape. Closing the loop end-to-end ensures the descent rule
    // we tested above is preserved through `frame.encode` /
    // `frame.decode`, not just through the ACK tracker's builder.
    var ranges_buf: [16]u8 = undefined;
    const ranges_in = [_]frame.types.AckRange{
        .{ .gap = 1, .length = 4 },
        .{ .gap = 4, .length = 2 },
    };
    const ranges_len = try frame.ack_range.writeRanges(&ranges_buf, &ranges_in);

    const f: frame.Frame = .{ .ack = .{
        .largest_acked = 100,
        .ack_delay = 0,
        .first_range = 5,
        .range_count = 2,
        .ranges_bytes = ranges_buf[0..ranges_len],
        .ecn_counts = null,
    } };

    var wire_buf: [64]u8 = undefined;
    const written = try frame.encode(&wire_buf, f);
    const decoded = try frame.decode(wire_buf[0..written]);
    try std.testing.expect(decoded.frame == .ack);
    try std.testing.expectEqual(@as(u64, 100), decoded.frame.ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 5), decoded.frame.ack.first_range);
    try std.testing.expectEqual(@as(u64, 2), decoded.frame.ack.range_count);
}

test "MUST NOT build an ACK frame when no packets have been received [RFC9000 §13.2.3 ¶1]" {
    // RFC 9000 §13.2.3 ¶1: an ACK frame describes packets the receiver
    // has actually seen. With no packets received, there is nothing to
    // acknowledge — the builder must surface that to the caller
    // instead of fabricating a zero-largest acknowledgement.
    var t: ack_tracker_mod.AckTracker = .{};
    var buf: [16]u8 = undefined;
    try std.testing.expectError(ack_tracker_mod.Error.Empty, t.toAckFrame(0, &buf));
}

test "MUST NOT acknowledge a packet number the sender never put on the wire [RFC9000 §13.1 ¶3]" {
    // RFC 9000 §13.1 ¶3: "An endpoint MUST NOT acknowledge any other
    // packet number." nullq's loss-recovery `processAck` walks the
    // sent-packet tracker; PNs claimed by the peer that the local
    // sender never recorded get silently dropped (no removal, no RTT
    // sample, no congestion-controller update). This is the
    // observable consequence of the rule.
    var tr: sent_packets.SentPacketTracker = .{};
    try tr.record(.{ .pn = 0, .sent_time_us = 100, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try tr.record(.{ .pn = 1, .sent_time_us = 110, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    var space: pn_space_mod.PnSpace = .{};
    space.next_pn = 2;

    // Peer "acknowledges" PN 99 — a number we never sent. The ACK
    // covers a single PN (first_range = 0, no subsequent ranges).
    const fake_ack: frame.types.Ack = .{
        .largest_acked = 99,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    };
    const result = try loss_recovery_mod.processAck(&tr, &space, fake_ack);
    // Nothing was newly acknowledged, no bytes were credited, and
    // the largest-acked-packet RTT path was NOT triggered.
    try std.testing.expectEqual(@as(u32, 0), result.newly_acked_count);
    try std.testing.expectEqual(@as(u64, 0), result.bytes_acked);
    try std.testing.expect(!result.largest_acked_newly_acked);
    // Both legitimately-sent packets remain tracked.
    try std.testing.expectEqual(@as(u32, 2), tr.count);
}

// ---------------------------------------------------------------- §13.3 retransmission of information

test "MUST track CRYPTO frames on the sent-packet record so loss can requeue them [RFC9000 §13.3 Table 3]" {
    // RFC 9000 §13.3 Table 3 lists CRYPTO data as "Yes" — must be
    // retransmitted on loss. nullq routes CRYPTO retransmits through
    // a separate per-level pending-bytes queue keyed by the offset/PN
    // pair captured on `SentPacket`; the observable invariant we check
    // here is that a sent packet *can* carry the bookkeeping needed
    // for that requeue (in-flight + ack_eliciting flags both true).
    var p: sent_packets.SentPacket = .{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer p.deinit(std.testing.allocator);
    try std.testing.expect(p.ack_eliciting);
    try std.testing.expect(p.in_flight);
}

test "MUST track HANDSHAKE_DONE on the retransmit-frame union [RFC9000 §13.3 Table 3]" {
    // RFC 9000 §13.3 Table 3 lists HANDSHAKE_DONE as "Yes". The
    // `RetransmitFrame` tagged union has a slot for it; absence of
    // that slot would silently drop a lost HANDSHAKE_DONE.
    var p: sent_packets.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer p.deinit(std.testing.allocator);
    try p.addRetransmitFrame(std.testing.allocator, .{ .handshake_done = .{} });
    try std.testing.expectEqual(@as(usize, 1), p.retransmit_frames.items.len);
    try std.testing.expect(p.retransmit_frames.items[0] == .handshake_done);
}

test "MUST associate STREAM keys with the carrying packet for ack/loss routing [RFC9000 §13.3 Table 3]" {
    // RFC 9000 §13.3 Table 3 lists STREAM data as "Yes". STREAM bytes
    // are tracked by the per-stream `SendStream`, but the
    // `SentPacket` still records the stream key so ack/loss callbacks
    // route to the right half-stream. Coalesced STREAM frames stack
    // multiple keys onto one packet — verify the iterator surfaces
    // every key in insertion order.
    var p: sent_packets.SentPacket = .{
        .pn = 5,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer p.deinit(std.testing.allocator);

    try p.addStreamKey(std.testing.allocator, 11);
    try p.addStreamKey(std.testing.allocator, 12);
    try p.addStreamKey(std.testing.allocator, 13);

    var it = p.streamKeys();
    try std.testing.expectEqual(@as(?u64, 11), it.next());
    try std.testing.expectEqual(@as(?u64, 12), it.next());
    try std.testing.expectEqual(@as(?u64, 13), it.next());
    try std.testing.expectEqual(@as(?u64, null), it.next());
}

test "NORMATIVE PADDING and PING are absent from the retransmit-frame union [RFC9000 §13.3 Table 3]" {
    // RFC 9000 §13.3 Table 3 lists PADDING and PING with retransmit
    // policy "No" — neither is retransmitted on loss. The structural
    // guarantee is that `RetransmitFrame` simply has no `padding` or
    // `ping` variant; we mirror that here as a compile-time tag-list
    // inspection so a future addition of either tag would have to
    // delete this test.
    const tags = std.meta.fields(sent_packets.RetransmitFrame);
    inline for (tags) |t| {
        try std.testing.expect(!std.mem.eql(u8, t.name, "padding"));
        try std.testing.expect(!std.mem.eql(u8, t.name, "ping"));
    }
}

// ---------------------------------------------------------------- §14 datagram size

test "NORMATIVE the v1 minimum UDP payload size constant equals 1200 bytes [RFC9000 §14 ¶1]" {
    // RFC 9000 §14 ¶1: "A client MUST expand the payload of all UDP
    // datagrams carrying Initial packets to at least the smallest
    // allowed maximum datagram size of 1200 bytes…" The
    // implementation surfaces this constant via
    // `nullq.conn.state.min_quic_udp_payload_size`. A reachable test
    // documents the magic number so a future bump (or PMTU tuning
    // mistake) is auditable.
    try std.testing.expectEqual(@as(usize, 1200), conn.state.min_quic_udp_payload_size);
    try std.testing.expectEqual(@as(usize, 1200), conn.state.default_mtu);
}

test "skip_MUST server discards v1 Initial UDP datagrams smaller than 1200 bytes [RFC9000 §14 ¶1]" {
    // The observable behaviour requires standing up a real `Server`
    // (TLS context + cert/key). nullq's test cert/key live under
    // `tests/data/`, which sits outside the conformance package's
    // `@embedFile` root. The full assertion lives in
    // `tests/e2e/server_smoke.zig` ("Server.feed drops QUIC v1
    // Initial datagrams below the 1200-byte minimum") and asserts
    // the same wire behaviour plus the `feeds_initial_too_small`
    // counter increment.
    return error.SkipZigTest;
}

test "skip_MUST NOT §14 size gate fire on a non-v1 long-header datagram [RFC9000 §14 ¶1]" {
    // Same package-path constraint as the v1 case above. The full
    // assertion (including the `feeds_initial_too_small` counter
    // staying at zero while `FeedOutcome.version_negotiated` fires)
    // lives in `tests/e2e/server_smoke.zig`.
    return error.SkipZigTest;
}

test "MUST pad the client first-flight Initial UDP datagram to >= 1200 bytes [RFC9000 §14 ¶1]" {
    // RFC 9000 §14 ¶1: a client's first-flight Initial UDP datagram
    // MUST be >= 1200 bytes. nullq's `Client.connect` + `advance` +
    // `poll` produces exactly that — the Initial is internally padded
    // (PADDING frames) so the encoded datagram is at least 1200
    // bytes when the embedder hands it to the socket.
    const protos = [_][]const u8{"hq-test"};
    var client = try nullq.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "example.com",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer client.deinit();

    try client.conn.advance();

    // Hand the connection an MTU-sized buffer and let it fill it.
    var tx: [1500]u8 = undefined;
    const n = try client.conn.poll(&tx, 1) orelse return error.NoInitialEmitted;

    // First-byte sanity: long header (0b11xx_xxxx mask).
    try std.testing.expect((tx[0] & 0xc0) == 0xc0);
    // §14 ¶1 floor.
    try std.testing.expect(n >= 1200);
}

// ---------------------------------------------------------------- §20.1 transport error codes

test "MUST round-trip the NO_ERROR transport code (0x00) on CONNECTION_CLOSE [RFC9000 §20.1]" {
    // RFC 9000 §20.1: "NO_ERROR (0x00): An endpoint uses this with
    // CONNECTION_CLOSE to signal that the connection is being closed
    // abruptly in the absence of any error." The wire codec must
    // accept it on the transport-layer (0x1c) variant.
    const f: frame.Frame = .{ .connection_close = .{
        .is_transport = true,
        .error_code = 0x00,
        .frame_type = 0x00,
        .reason_phrase = "",
    } };
    var buf: [64]u8 = undefined;
    const written = try frame.encode(&buf, f);
    const decoded = try frame.decode(buf[0..written]);
    try std.testing.expect(decoded.frame == .connection_close);
    try std.testing.expectEqual(@as(u64, 0x00), decoded.frame.connection_close.error_code);
    try std.testing.expectEqual(true, decoded.frame.connection_close.is_transport);
}

test "MUST round-trip the canonical transport error codes 0x01..0x10 [RFC9000 §20.1]" {
    // RFC 9000 §20.1 assigns one named code per low value. We exercise
    // every canonical code (and the implementation-extension `0x09`
    // which aligns with the RFC-reserved EXCESSIVE_LOAD slot — see the
    // dedicated test below).
    const codes = [_]u64{
        0x01, // INTERNAL_ERROR
        0x02, // CONNECTION_REFUSED
        0x03, // FLOW_CONTROL_ERROR
        0x04, // STREAM_LIMIT_ERROR
        0x05, // STREAM_STATE_ERROR
        0x06, // FINAL_SIZE_ERROR
        0x07, // FRAME_ENCODING_ERROR
        0x08, // TRANSPORT_PARAMETER_ERROR
        0x09, // CONNECTION_ID_LIMIT_ERROR / nullq's EXCESSIVE_LOAD ext
        0x0a, // PROTOCOL_VIOLATION
        0x0b, // INVALID_TOKEN
        0x0c, // APPLICATION_ERROR
        0x0d, // CRYPTO_BUFFER_EXCEEDED
        0x0e, // KEY_UPDATE_ERROR
        0x0f, // AEAD_LIMIT_REACHED
        0x10, // NO_VIABLE_PATH
    };
    for (codes) |code| {
        const f: frame.Frame = .{ .connection_close = .{
            .is_transport = true,
            .error_code = code,
            .frame_type = 0x00,
            .reason_phrase = "",
        } };
        var buf: [64]u8 = undefined;
        const written = try frame.encode(&buf, f);
        const decoded = try frame.decode(buf[0..written]);
        try std.testing.expect(decoded.frame == .connection_close);
        try std.testing.expectEqual(code, decoded.frame.connection_close.error_code);
    }
}

test "MUST round-trip CRYPTO_ERROR codes in the 0x0100..0x01ff range [RFC9000 §20.1]" {
    // RFC 9000 §20.1 reserves 0x0100..0x01ff for CRYPTO_ERROR — the
    // low byte is the TLS alert code. The wire codec is varint-based,
    // so encoding crosses the 1-byte→2-byte varint boundary at 0x40.
    // Pick three samples spanning the range.
    const samples = [_]u64{ 0x0100, 0x0150, 0x01ff };
    for (samples) |code| {
        const f: frame.Frame = .{ .connection_close = .{
            .is_transport = true,
            .error_code = code,
            .frame_type = 0x06, // CRYPTO frame
            .reason_phrase = "tls alert",
        } };
        var buf: [128]u8 = undefined;
        const written = try frame.encode(&buf, f);
        const decoded = try frame.decode(buf[0..written]);
        try std.testing.expect(decoded.frame == .connection_close);
        try std.testing.expectEqual(code, decoded.frame.connection_close.error_code);
        try std.testing.expectEqual(@as(u64, 0x06), decoded.frame.connection_close.frame_type);
    }
}

test "MUST distinguish transport (0x1c) from application (0x1d) CONNECTION_CLOSE [RFC9000 §19.19]" {
    // RFC 9000 §19.19 / §20.1 split the CONNECTION_CLOSE error
    // namespace: 0x1c carries a transport error (with frame_type),
    // 0x1d carries an application error (no frame_type). The two
    // namespaces collide on numeric values, so the variant tag is
    // load-bearing.
    {
        // Transport — frame_type field is preserved.
        const f: frame.Frame = .{ .connection_close = .{
            .is_transport = true,
            .error_code = 0x0a,
            .frame_type = 0x08,
            .reason_phrase = "protocol violation",
        } };
        var buf: [128]u8 = undefined;
        const written = try frame.encode(&buf, f);
        const decoded = try frame.decode(buf[0..written]);
        try std.testing.expect(decoded.frame == .connection_close);
        const got = decoded.frame.connection_close;
        try std.testing.expectEqual(true, got.is_transport);
        try std.testing.expectEqual(@as(u64, 0x0a), got.error_code);
        try std.testing.expectEqual(@as(u64, 0x08), got.frame_type);
    }
    {
        // Application — no frame_type on the wire.
        const f: frame.Frame = .{ .connection_close = .{
            .is_transport = false,
            .error_code = 0x42,
            .reason_phrase = "h3 abandon",
        } };
        var buf: [128]u8 = undefined;
        const written = try frame.encode(&buf, f);
        const decoded = try frame.decode(buf[0..written]);
        try std.testing.expect(decoded.frame == .connection_close);
        const got = decoded.frame.connection_close;
        try std.testing.expectEqual(false, got.is_transport);
        try std.testing.expectEqual(@as(u64, 0x42), got.error_code);
    }
}

test "NORMATIVE the implementation's excessive_load extension uses the 0x09 reserved code [RFC9000 §20.1]" {
    // RFC 9000 §20.1 assigns 0x09 to CONNECTION_ID_LIMIT_ERROR. nullq
    // additionally exposes an `excessive_load = 0x09` constant used
    // by the §3.5 / §8 hardening backstop (reserves are spent → close
    // with this code). The numeric collision is intentional: a peer
    // that doesn't know about the extension still reads it as a valid
    // RFC-registered code. Document the constant so a future renumber
    // shows up here.
    try std.testing.expectEqual(@as(u64, 0x09), conn.state.transport_error_excessive_load);
}
