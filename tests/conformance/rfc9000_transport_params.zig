//! RFC 9000 §18 — Transport Parameter Encoding (and the role-specific
//! constraints in §7.3 that bind on top of the wire format).
//!
//! Transport parameters are exchanged inside the TLS handshake as a
//! single opaque blob: a sequence of `(id, length, value)` triples,
//! where each component is itself a QUIC varint and the value bytes
//! have a per-id schema (varint, fixed-width byte string, or
//! zero-length flag). RFC 9000 §18.1 reserves the IDs `31 * N + 27`
//! for GREASE and requires receivers to ignore unknown IDs so the
//! ecosystem can introduce new parameters without breaking interop.
//!
//! The implementation under test lives in `src/tls/transport_params.zig`,
//! exposed publicly as `nullq.tls.transport_params`.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9000 §7.3   ¶1   MUST     reject blob lacking initial_source_connection_id (both sides)
//!   RFC9000 §7.3   ¶3   MUST     server includes retry_source_connection_id iff Retry was sent
//!   RFC9000 §18    ¶3   MUST     emit each TP as id(varint)|len(varint)|value
//!   RFC9000 §18    ¶3   MUST NOT include a duplicate parameter id
//!   RFC9000 §18    ¶3   MUST NOT accept a value field longer than the buffer
//!   RFC9000 §18    ¶3   MUST     silently ignore unknown TP ids (forward extensibility)
//!   RFC9000 §18.1  ¶1   MUST     ignore reserved/GREASE TP ids of form 31*N+27
//!   RFC9000 §18.2  0x00 MUST     round-trip original_destination_connection_id (server-only)
//!   RFC9000 §18.2  0x00 MUST NOT accept original_destination_connection_id > 20 bytes
//!   RFC9000 §18.2  0x01 MUST     round-trip max_idle_timeout
//!   RFC9000 §18.2  0x02 MUST     stateless_reset_token is exactly 16 bytes
//!   RFC9000 §18.2  0x03 MUST     round-trip max_udp_payload_size
//!   RFC9000 §18.2  0x03 ¶9 MUST     reject max_udp_payload_size < 1200 (universal floor)
//!   RFC9000 §18.2  0x04 MUST     round-trip initial_max_data
//!   RFC9000 §18.2  0x05 MUST     round-trip initial_max_stream_data_bidi_local
//!   RFC9000 §18.2  0x08 ¶1 MUST NOT accept initial_max_streams_bidi > 2^60
//!   RFC9000 §18.2  0x09 ¶1 MUST NOT accept initial_max_streams_uni > 2^60
//!   RFC9000 §18.2  0x0a ¶1 MUST NOT accept ack_delay_exponent > 20
//!   RFC9000 §18.2  0x0a ¶1 MUST     accept ack_delay_exponent boundary value 20
//!   RFC9000 §18.2  0x0b ¶1 MUST NOT accept max_ack_delay >= 2^14
//!   RFC9000 §18.2  0x0b ¶1 MUST     accept max_ack_delay boundary value 2^14 - 1
//!   RFC9000 §18.2  0x0c ¶1 MUST NOT accept disable_active_migration with non-zero length
//!   RFC9000 §18.2  0x0c ¶1 MUST     accept disable_active_migration as a zero-length flag
//!   RFC9000 §18.2  0x0d ¶29 MUST    treat preferred_address authored by a client as TRANSPORT_PARAMETER_ERROR
//!   RFC9000 §18.2  0x0e ¶1 MUST NOT accept active_connection_id_limit < 2
//!   RFC9000 §18.2  0x0e ¶1 MUST     accept active_connection_id_limit boundary value 2
//!   RFC9000 §18.2  0x0f    MUST     round-trip initial_source_connection_id (both endpoints)
//!   RFC9000 §18.2  0x10    MUST     round-trip retry_source_connection_id (server-only)
//!   RFC9000 §18.2  0x10 ¶35 MUST NOT accept retry_source_connection_id authored by a client
//!
//! Visible debt:
//!   RFC9000 §7.3   MUST     server MUST send original_destination_connection_id matching client's first DCID
//!   RFC9000 §7.3   MUST     server MUST send initial_source_connection_id matching its own SCID (value match, not just presence)
//!   RFC9000 §7.3   MUST     client MUST send initial_source_connection_id matching its own SCID (value match, not just presence)
//!   These remaining gaps need cross-layer state (the actual SCID a
//!   peer used in its first Initial) that the transport-params codec
//!   does not have access to; they live in the connection state
//!   machine integration tests rather than the codec conformance
//!   suite. The role-aware presence/absence and universal-bound
//!   checks above are now enforced inside `decodeAs`.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9000 §16    varint encoding rules                      → rfc9000_varint.zig
//!   RFC9221  §3   max_datagram_frame_size (id 0x20)           → rfc9221_datagram.zig
//!
//! Not implemented by design:
//!   none — every parameter id in the RFC 9000 §18.2 table is exercised
//!   here, either as a positive round-trip or as a bound-rejection test.

const std = @import("std");
const nullq = @import("nullq");
const transport_params = nullq.tls.transport_params;
const varint = nullq.wire.varint;

const Params = transport_params.Params;
const Id = transport_params.Id;
const Error = transport_params.Error;
const ConnectionId = transport_params.ConnectionId;

/// Helper: build a single-parameter blob of the form
/// `id(varint) | len(varint) | <value bytes>` into `out` and return
/// the byte count written. Used to feed the decoder hand-crafted wire
/// shapes without going through the encoder, so we can exercise the
/// wire-level validation surface even for values the typed encoder
/// would refuse to emit.
fn writeTriple(out: []u8, id: u64, value: []const u8) !usize {
    var pos: usize = 0;
    pos += try varint.encode(out[pos..], id);
    pos += try varint.encode(out[pos..], value.len);
    @memcpy(out[pos .. pos + value.len], value);
    pos += value.len;
    return pos;
}

/// Helper: write `id(varint) | len(varint) | value(varint)` — the
/// shape the typed encoder uses for varint-valued parameters. We
/// hand-roll it so a test can put an out-of-range value on the wire
/// (the typed `encode` rejects bad values up front).
fn writeVarintParam(out: []u8, id: u64, value: u64) !usize {
    var pos: usize = 0;
    pos += try varint.encode(out[pos..], id);
    const value_len = varint.encodedLen(value);
    pos += try varint.encode(out[pos..], value_len);
    pos += try varint.encode(out[pos..], value);
    return pos;
}

// ---------------------------------------------------------------- §18 wire shape

test "MUST encode each transport parameter as an id|length|value triple [RFC9000 §18 ¶3]" {
    // §18 ¶3: "Each transport parameter is encoded as an (identifier,
    // length, value) tuple". Pick a single, simple parameter and
    // verify the three components are present in order.
    const sent: Params = .{ .initial_max_data = 1234 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);

    // The blob is one triple. Decode it as raw varints and check that
    // (id, len, value) match what we set.
    const id = try varint.decode(buf[0..n]);
    try std.testing.expectEqual(Id.initial_max_data, id.value);

    const after_id = id.bytes_read;
    const len = try varint.decode(buf[after_id..n]);
    // 1234 fits in 2 bytes of varint.
    try std.testing.expectEqual(@as(u64, 2), len.value);

    const value_start = after_id + len.bytes_read;
    const value = try varint.decode(buf[value_start..n]);
    try std.testing.expectEqual(@as(u64, 1234), value.value);

    // Whole blob consumed.
    try std.testing.expectEqual(@as(usize, value_start + value.bytes_read), n);
}

test "MUST round-trip an emitted blob through the decoder [RFC9000 §18 ¶3]" {
    // The shape contract is symmetric: anything `encode` produces,
    // `decode` must accept and reconstruct the field-equivalent value.
    const sent: Params = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_streams_bidi = 100,
        .ack_delay_exponent = 5,
    };
    var buf: [64]u8 = undefined;
    const n = try sent.encode(&buf);

    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(sent.max_idle_timeout_ms, got.max_idle_timeout_ms);
    try std.testing.expectEqual(sent.initial_max_data, got.initial_max_data);
    try std.testing.expectEqual(sent.initial_max_streams_bidi, got.initial_max_streams_bidi);
    try std.testing.expectEqual(sent.ack_delay_exponent, got.ack_delay_exponent);
}

test "MUST NOT accept a parameter whose declared length runs past the buffer [RFC9000 §18 ¶3]" {
    // id=0x04 (initial_max_data), declared length=0x05, but only 1
    // value byte trails. The decoder must refuse rather than read
    // past the end.
    const blob = [_]u8{ 0x04, 0x05, 0x00 };
    try std.testing.expectError(Error.InvalidValue, Params.decode(&blob));
}

// ---------------------------------------------------------------- §18 forward extensibility

test "MUST silently ignore an unknown transport parameter id [RFC9000 §18 ¶5]" {
    // §18 ¶5: "An endpoint MUST ignore transport parameters that it
    // does not support." We pick id=0xfe (unassigned in the §18.2
    // registry) and pair it with a known parameter so we can verify
    // the known one still decodes.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += try writeTriple(buf[pos..], 0xfe, &.{ 0xaa, 0xbb });
    pos += try writeVarintParam(buf[pos..], Id.initial_max_data, 7);

    const got = try Params.decode(buf[0..pos]);
    try std.testing.expectEqual(@as(u64, 7), got.initial_max_data);
}

test "MUST silently ignore an unknown transport parameter id with a multi-byte varint id [RFC9000 §18 ¶5]" {
    // Forward extensibility for the high end of the IANA registry: an
    // id that requires a 2-byte varint encoding (e.g. 0x1234) must
    // not wedge the decoder.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try writeTriple(buf[pos..], 0x1234, &.{ 0xaa, 0xbb, 0xcc });

    const got = try Params.decode(buf[0..pos]);
    // No fields touched — defaults preserved.
    try std.testing.expectEqual(@as(u64, 0), got.initial_max_data);
    try std.testing.expectEqual(@as(u64, 3), got.ack_delay_exponent);
}

// ---------------------------------------------------------------- §18.1 GREASE / reserved ids

test "MUST ignore reserved transport parameters whose id has the form 31*N+27 [RFC9000 §18.1 ¶1]" {
    // §18.1 ¶1: "Transport parameters with an identifier of the form
    // 31 * N + 27 for integer values of N are reserved... These
    // reserved transport parameters have no semantics and can carry
    // arbitrary values." The receiver MUST treat them like any other
    // unknown id and continue parsing.
    //
    // 31*1+27 = 58, 31*2+27 = 89, 31*0+27 = 27 — three distinct
    // reserved ids interleaved with a real parameter so we can also
    // verify the real one survived.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try writeTriple(buf[pos..], 27, &.{0x01});
    pos += try writeVarintParam(buf[pos..], Id.initial_max_data, 9);
    pos += try writeTriple(buf[pos..], 58, &.{ 0x02, 0x03 });
    pos += try writeTriple(buf[pos..], 89, &.{});

    const got = try Params.decode(buf[0..pos]);
    try std.testing.expectEqual(@as(u64, 9), got.initial_max_data);
}

// ---------------------------------------------------------------- §18.2 0x00 original_destination_connection_id

test "MUST round-trip original_destination_connection_id (id 0x00) [RFC9000 §18.2 ¶3]" {
    const dcid = ConnectionId.fromSlice(&.{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4 });
    const sent: Params = .{ .original_destination_connection_id = dcid };

    var buf: [32]u8 = undefined;
    const n = try sent.encode(&buf);

    // First byte on the wire is the varint-encoded id 0x00.
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);

    const got = try Params.decode(buf[0..n]);
    try std.testing.expect(got.original_destination_connection_id != null);
    try std.testing.expectEqualSlices(
        u8,
        dcid.slice(),
        got.original_destination_connection_id.?.slice(),
    );
}

test "MUST NOT accept original_destination_connection_id longer than 20 bytes [RFC9000 §18.2 ¶3]" {
    // Connection IDs in QUIC v1 are bounded at 20 octets (RFC 9000
    // §17.2). A transport parameter that smuggles a 21-byte CID must
    // be refused.
    var buf: [32]u8 = undefined;
    const overlong: [21]u8 = @splat(0xab);
    const n = try writeTriple(&buf, Id.original_destination_connection_id, &overlong);
    try std.testing.expectError(Error.InvalidValue, Params.decode(buf[0..n]));
}

// ---------------------------------------------------------------- §18.2 0x01 max_idle_timeout

test "MUST round-trip max_idle_timeout (id 0x01) [RFC9000 §18.2 ¶5]" {
    const sent: Params = .{ .max_idle_timeout_ms = 30_000 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 30_000), got.max_idle_timeout_ms);
}

// ---------------------------------------------------------------- §18.2 0x02 stateless_reset_token

test "MUST accept stateless_reset_token only when its value is exactly 16 bytes [RFC9000 §18.2 ¶7]" {
    // §18.2 ¶7: "A stateless reset token... is a 16-byte value". The
    // decoder must reject any other length.
    var buf: [32]u8 = undefined;

    // 8 bytes — too short.
    const short_value: [8]u8 = @splat(0);
    var n = try writeTriple(&buf, Id.stateless_reset_token, &short_value);
    try std.testing.expectError(Error.InvalidValue, Params.decode(buf[0..n]));

    // 17 bytes — too long.
    const long_value: [17]u8 = @splat(0);
    n = try writeTriple(&buf, Id.stateless_reset_token, &long_value);
    try std.testing.expectError(Error.InvalidValue, Params.decode(buf[0..n]));

    // 16 bytes — accepted; round-trip the exact value.
    const ok_value: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    n = try writeTriple(&buf, Id.stateless_reset_token, &ok_value);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expect(got.stateless_reset_token != null);
    try std.testing.expectEqualSlices(u8, &ok_value, &got.stateless_reset_token.?);
}

// ---------------------------------------------------------------- §18.2 0x03 max_udp_payload_size

test "MUST round-trip max_udp_payload_size (id 0x03) [RFC9000 §18.2 ¶9]" {
    const sent: Params = .{ .max_udp_payload_size = 1452 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x03), buf[0]);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 1452), got.max_udp_payload_size);
}

test "MUST reject max_udp_payload_size below the 1200-byte minimum [RFC9000 §18.2 ¶9]" {
    // RFC 9000 §18.2 ¶9: "Values below 1200 are invalid." The bound
    // is universal (binds both peers, regardless of role); the
    // role-aware `decodeAs` rejects any blob whose value falls below
    // the floor. 1199 is the smallest violation; 0 is also below the
    // floor and must likewise be refused.
    const cid = ConnectionId.fromSlice(&.{ 0xa0, 0xa1 });
    const just_below: Params = .{
        .max_udp_payload_size = 1199,
        .initial_source_connection_id = cid,
    };
    var buf: [32]u8 = undefined;
    var n = try just_below.encode(&buf);
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(buf[0..n], .{ .role = .client }),
    );

    // Boundary: exactly 1200 is the smallest legal value.
    const at_floor: Params = .{
        .max_udp_payload_size = 1200,
        .initial_source_connection_id = cid,
    };
    n = try at_floor.encode(&buf);
    const got = try transport_params.decodeAs(buf[0..n], .{ .role = .client });
    try std.testing.expectEqual(@as(u64, 1200), got.max_udp_payload_size);
}

// ---------------------------------------------------------------- §18.2 0x04 initial_max_data

test "MUST round-trip initial_max_data (id 0x04) [RFC9000 §18.2 ¶11]" {
    const sent: Params = .{ .initial_max_data = 1 << 20 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x04), buf[0]);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 1 << 20), got.initial_max_data);
}

// ---------------------------------------------------------------- §18.2 0x05..0x07 initial_max_stream_data_*

test "MUST round-trip initial_max_stream_data_bidi_local (id 0x05) [RFC9000 §18.2 ¶13]" {
    const sent: Params = .{ .initial_max_stream_data_bidi_local = 65_536 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x05), buf[0]);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 65_536), got.initial_max_stream_data_bidi_local);
}

test "MUST round-trip initial_max_stream_data_bidi_remote (id 0x06) [RFC9000 §18.2 ¶15]" {
    const sent: Params = .{ .initial_max_stream_data_bidi_remote = 65_536 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x06), buf[0]);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 65_536), got.initial_max_stream_data_bidi_remote);
}

test "MUST round-trip initial_max_stream_data_uni (id 0x07) [RFC9000 §18.2 ¶17]" {
    const sent: Params = .{ .initial_max_stream_data_uni = 32_768 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x07), buf[0]);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 32_768), got.initial_max_stream_data_uni);
}

// ---------------------------------------------------------------- §18.2 0x08..0x09 initial_max_streams_*

test "MUST round-trip initial_max_streams_bidi (id 0x08) [RFC9000 §18.2 ¶19]" {
    const sent: Params = .{ .initial_max_streams_bidi = 100 };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x08), buf[0]);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 100), got.initial_max_streams_bidi);
}

test "MUST NOT accept initial_max_streams_bidi greater than 2^60 [RFC9000 §18.2 ¶19]" {
    // §18.2 ¶19: "If a max_streams transport parameter or a
    // MAX_STREAMS frame is received with a value greater than 2^60,
    // this would allow a maximum stream ID that cannot be expressed
    // as a variable-length integer." The role-aware decoder rejects
    // the over-cap blob with TRANSPORT_PARAMETER_ERROR.
    const cid = ConnectionId.fromSlice(&.{ 0xa0, 0xa1 });
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try writeVarintParam(buf[pos..], Id.initial_max_streams_bidi, (1 << 60) + 1);
    pos += try writeTriple(buf[pos..], Id.initial_source_connection_id, cid.slice());
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(buf[0..pos], .{ .role = .client }),
    );

    // Boundary: exactly 2^60 is legal.
    pos = 0;
    pos += try writeVarintParam(buf[pos..], Id.initial_max_streams_bidi, 1 << 60);
    pos += try writeTriple(buf[pos..], Id.initial_source_connection_id, cid.slice());
    const got = try transport_params.decodeAs(buf[0..pos], .{ .role = .client });
    try std.testing.expectEqual(@as(u64, 1 << 60), got.initial_max_streams_bidi);
}

test "MUST NOT accept initial_max_streams_uni greater than 2^60 [RFC9000 §18.2 ¶21]" {
    // Companion to the bidi cap above: the same 2^60 limit binds the
    // unidirectional stream count.
    const cid = ConnectionId.fromSlice(&.{ 0xa0, 0xa1 });
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try writeVarintParam(buf[pos..], Id.initial_max_streams_uni, (1 << 60) + 1);
    pos += try writeTriple(buf[pos..], Id.initial_source_connection_id, cid.slice());
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(buf[0..pos], .{ .role = .client }),
    );
}

// ---------------------------------------------------------------- §18.2 0x0a ack_delay_exponent

test "MUST NOT accept ack_delay_exponent greater than 20 [RFC9000 §18.2 ¶23]" {
    // §18.2 ¶23: "Values above 20 are invalid." 21 is the smallest
    // value that must be rejected.
    var buf: [16]u8 = undefined;
    const n = try writeVarintParam(&buf, Id.ack_delay_exponent, 21);
    try std.testing.expectError(Error.InvalidValue, Params.decode(buf[0..n]));
}

test "MUST accept ack_delay_exponent at the boundary value 20 [RFC9000 §18.2 ¶23]" {
    // Boundary check: 20 is the largest legal value. A correct
    // off-by-one in the bound check is the difference between
    // accepting 20 and rejecting it.
    var buf: [16]u8 = undefined;
    const n = try writeVarintParam(&buf, Id.ack_delay_exponent, 20);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 20), got.ack_delay_exponent);
}

// ---------------------------------------------------------------- §18.2 0x0b max_ack_delay

test "MUST NOT accept max_ack_delay greater than or equal to 2^14 [RFC9000 §18.2 ¶25]" {
    // §18.2 ¶25: "Values of 2^14 or greater are invalid." The codec
    // emits InvalidValue rather than silently truncating.
    var buf: [16]u8 = undefined;
    const n = try writeVarintParam(&buf, Id.max_ack_delay, 1 << 14);
    try std.testing.expectError(Error.InvalidValue, Params.decode(buf[0..n]));
}

test "MUST accept max_ack_delay at the boundary value 2^14 - 1 [RFC9000 §18.2 ¶25]" {
    // The largest legal value: 2^14 - 1 = 16383.
    var buf: [16]u8 = undefined;
    const n = try writeVarintParam(&buf, Id.max_ack_delay, (1 << 14) - 1);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, (1 << 14) - 1), got.max_ack_delay_ms);
}

// ---------------------------------------------------------------- §18.2 0x0c disable_active_migration

test "MUST encode disable_active_migration as a zero-length flag [RFC9000 §18.2 ¶27]" {
    // §18.2 ¶27 / §18.1: zero-length parameter signals presence; the
    // encoded triple is id=0x0c, length=0x00, no value bytes.
    const sent: Params = .{ .disable_active_migration = true };
    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);

    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0x0c), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]);

    const got = try Params.decode(buf[0..n]);
    try std.testing.expect(got.disable_active_migration);
}

test "MUST NOT accept disable_active_migration with a non-zero length [RFC9000 §18.2 ¶27]" {
    // The flag is zero-length by definition; a value byte is a wire
    // violation and must be refused.
    var buf: [8]u8 = undefined;
    const n = try writeTriple(&buf, Id.disable_active_migration, &.{0x00});
    try std.testing.expectError(Error.InvalidValue, Params.decode(buf[0..n]));
}

// ---------------------------------------------------------------- §18.2 0x0d preferred_address

test "MUST treat preferred_address received by a client-side peer as TRANSPORT_PARAMETER_ERROR [RFC9000 §18.2 ¶29]" {
    // §18.2 ¶29: preferred_address is server-only; "A client MUST
    // NOT send a preferred_address transport parameter. A server MUST
    // treat the receipt of a preferred_address transport parameter as
    // a connection error of type TRANSPORT_PARAMETER_ERROR." The
    // server invokes `decodeAs(.. .role = .client)` because the bytes
    // were authored by the client side.
    const cid = ConnectionId.fromSlice(&.{ 0xa0, 0xa1 });
    const sent: Params = .{
        .initial_source_connection_id = cid,
        .preferred_address = .{},
    };
    var buf: [128]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(buf[0..n], .{ .role = .client }),
    );

    // Authored by the server, the same bytes are valid.
    const ok = try transport_params.decodeAs(
        buf[0..n],
        .{ .role = .server, .server_sent_retry = false },
    );
    try std.testing.expect(ok.preferred_address != null);
}

// ---------------------------------------------------------------- §18.2 0x0e active_connection_id_limit

test "MUST NOT accept active_connection_id_limit less than 2 [RFC9000 §18.2 ¶31]" {
    // §18.2 ¶31: "Values less than 2 are invalid." 1 is the smallest
    // value that must be rejected; 0 follows trivially.
    var buf: [16]u8 = undefined;
    const n = try writeVarintParam(&buf, Id.active_connection_id_limit, 1);
    try std.testing.expectError(Error.InvalidValue, Params.decode(buf[0..n]));
}

test "MUST accept active_connection_id_limit at the boundary value 2 [RFC9000 §18.2 ¶31]" {
    // The smallest legal value (and the RFC default).
    var buf: [16]u8 = undefined;
    const n = try writeVarintParam(&buf, Id.active_connection_id_limit, 2);
    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 2), got.active_connection_id_limit);
}

// ---------------------------------------------------------------- §18.2 0x0f initial_source_connection_id

test "MUST round-trip initial_source_connection_id (id 0x0f) [RFC9000 §18.2 ¶33]" {
    // §18.2 ¶33 / §7.3: "Each endpoint includes the value of the
    // Source Connection ID field from the first Initial packet it
    // sent" — required on both sides of the handshake.
    const scid = ConnectionId.fromSlice(&.{ 0xb0, 0xb1, 0xb2, 0xb3 });
    const sent: Params = .{ .initial_source_connection_id = scid };

    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x0f), buf[0]);

    const got = try Params.decode(buf[0..n]);
    try std.testing.expect(got.initial_source_connection_id != null);
    try std.testing.expectEqualSlices(
        u8,
        scid.slice(),
        got.initial_source_connection_id.?.slice(),
    );
}

test "MUST require initial_source_connection_id on every endpoint's transport params [RFC9000 §7.3 ¶1]" {
    // §7.3 ¶1: "Each endpoint includes the value of the Source
    // Connection ID field from the first Initial packet it sent in
    // the initial_source_connection_id transport parameter". A blob
    // missing this parameter is a TRANSPORT_PARAMETER_ERROR no matter
    // which side authored it.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try writeVarintParam(buf[pos..], Id.initial_max_data, 1234);

    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(buf[0..pos], .{ .role = .client }),
    );
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(buf[0..pos], .{ .role = .server }),
    );

    // Once initial_source_connection_id is present, the same blob
    // shape decodes successfully.
    const cid = ConnectionId.fromSlice(&.{ 0xa0, 0xa1 });
    pos += try writeTriple(buf[pos..], Id.initial_source_connection_id, cid.slice());
    const got = try transport_params.decodeAs(buf[0..pos], .{ .role = .client });
    try std.testing.expectEqual(@as(u64, 1234), got.initial_max_data);
}

// ---------------------------------------------------------------- §18.2 0x10 retry_source_connection_id

test "MUST round-trip retry_source_connection_id (id 0x10) [RFC9000 §18.2 ¶35]" {
    // §18.2 ¶35 / §7.3: server-only parameter, included only when
    // the server sent a Retry packet.
    const rscid = ConnectionId.fromSlice(&.{ 0xc0, 0xc1, 0xc2 });
    const sent: Params = .{ .retry_source_connection_id = rscid };

    var buf: [16]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x10), buf[0]);

    const got = try Params.decode(buf[0..n]);
    try std.testing.expect(got.retry_source_connection_id != null);
    try std.testing.expectEqualSlices(
        u8,
        rscid.slice(),
        got.retry_source_connection_id.?.slice(),
    );
}

test "MUST send retry_source_connection_id when (and only when) the server sent Retry [RFC9000 §7.3 ¶3]" {
    // §7.3 ¶3: "If the server sent a Retry packet, but the client
    // did not present a valid token... the server MUST include the
    // retry_source_connection_id transport parameter". The codec
    // takes the Retry context as `server_sent_retry` and enforces
    // both directions of the iff: present-with-retry-not-sent is
    // rejected, absent-with-retry-sent is rejected.
    const cid = ConnectionId.fromSlice(&.{ 0xb0, 0xb1, 0xb2 });

    // Case A: server sent Retry but blob lacks retry_source_connection_id.
    const without_rscid: Params = .{ .initial_source_connection_id = cid };
    var buf: [64]u8 = undefined;
    var n = try without_rscid.encode(&buf);
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(
            buf[0..n],
            .{ .role = .server, .server_sent_retry = true },
        ),
    );

    // Case B: server did NOT send Retry but blob carries retry_source_connection_id.
    const with_rscid: Params = .{
        .initial_source_connection_id = cid,
        .retry_source_connection_id = cid,
    };
    n = try with_rscid.encode(&buf);
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(
            buf[0..n],
            .{ .role = .server, .server_sent_retry = false },
        ),
    );

    // Case C: matched presence (Retry sent + parameter present) is accepted.
    const ok = try transport_params.decodeAs(
        buf[0..n],
        .{ .role = .server, .server_sent_retry = true },
    );
    try std.testing.expectEqualSlices(u8, cid.slice(), ok.retry_source_connection_id.?.slice());
}

test "MUST NOT send retry_source_connection_id from a client [RFC9000 §18.2 ¶35]" {
    // §18.2 ¶35: retry_source_connection_id is a server-only
    // parameter; a client receiving one (or a server receiving one
    // from a client) MUST treat it as TRANSPORT_PARAMETER_ERROR.
    const cid = ConnectionId.fromSlice(&.{ 0xc0, 0xc1 });
    const sent: Params = .{
        .initial_source_connection_id = cid,
        .retry_source_connection_id = cid,
    };
    var buf: [64]u8 = undefined;
    const n = try sent.encode(&buf);
    try std.testing.expectError(
        Error.TransportParameterError,
        transport_params.decodeAs(buf[0..n], .{ .role = .client }),
    );
}

// ---------------------------------------------------------------- §18 once-only rule

test "MUST NOT accept a duplicate transport parameter id [RFC9000 §18 ¶3]" {
    // §18 ¶3: "An endpoint SHOULD treat receipt of duplicate
    // transport parameters as a connection error of type
    // TRANSPORT_PARAMETER_ERROR." nullq elevates this to a hard
    // reject in the codec. Two id=0x04 (initial_max_data) entries
    // back-to-back must be rejected.
    const blob = [_]u8{
        0x04, 0x01, 0x05,
        0x04, 0x01, 0x06,
    };
    try std.testing.expectError(Error.DuplicateParameter, Params.decode(&blob));
}

test "MUST NOT accept a duplicate unknown transport parameter id [RFC9000 §18 ¶3]" {
    // The duplicate-id check applies to every parameter, not just
    // the ones the codec recognizes. Two copies of id=0x1234 must
    // also be rejected.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try writeTriple(buf[pos..], 0x1234, &.{});
    pos += try writeTriple(buf[pos..], 0x1234, &.{});
    try std.testing.expectError(Error.DuplicateParameter, Params.decode(buf[0..pos]));
}

// ---------------------------------------------------------------- §18 default-only blob

test "NORMATIVE encode emits an empty blob when every field holds its RFC default [RFC9000 §18 ¶3]" {
    // §18 ¶3 doesn't use a BCP 14 keyword for "omit defaults" — it
    // is the implementation's responsibility to keep the blob small
    // — but the round-trip property is normative: a peer that
    // receives an empty blob recovers the RFC default for every field.
    const empty: Params = .{};
    var buf: [16]u8 = undefined;
    const n = try empty.encode(&buf);
    try std.testing.expectEqual(@as(usize, 0), n);

    const got = try Params.decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 3), got.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 25), got.max_ack_delay_ms);
    try std.testing.expectEqual(@as(u64, 65527), got.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 2), got.active_connection_id_limit);
}
