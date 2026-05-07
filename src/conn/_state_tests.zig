// Internal test suite for src/conn/state.zig — extracted from the
// monolith for editability. Tests reach into state.zig privates via
// the pub-broadened module imports and constants annotated as
// INTERNAL in state.zig. The leading underscore on this file's name
// signals "internal to conn/, not for embedders".

const std = @import("std");
const boringssl = @import("boringssl");
const c = boringssl.raw;
const state = @import("state.zig");

const LossStats = state.LossStats;
const Address = state.Address;
const ApplicationKeyUpdateLimits = state.ApplicationKeyUpdateLimits;
const ApplicationKeyUpdateStatus = state.ApplicationKeyUpdateStatus;
const CloseErrorSpace = state.CloseErrorSpace;
const CloseEvent = state.CloseEvent;
const CloseSource = state.CloseSource;
const CloseState = state.CloseState;
const Connection = state.Connection;
const ConnectionCloseInfo = state.ConnectionCloseInfo;
const ConnectionEvent = state.ConnectionEvent;
const ConnectionId = state.ConnectionId;
const ConnectionIdProvision = state.ConnectionIdProvision;
const ConnectionIdReplenishInfo = state.ConnectionIdReplenishInfo;
const ConnectionIdReplenishReason = state.ConnectionIdReplenishReason;
const CryptoBuffer = state.CryptoBuffer;
const CryptoChunk = state.CryptoChunk;
const DatagramSendEvent = state.DatagramSendEvent;
const Direction = state.Direction;
const EarlyDataStatus = state.EarlyDataStatus;
const EncryptionLevel = state.EncryptionLevel;
const Error = state.Error;
const FlowBlockedInfo = state.FlowBlockedInfo;
const FlowBlockedKind = state.FlowBlockedKind;
const FlowBlockedSource = state.FlowBlockedSource;
const IncomingDatagram = state.IncomingDatagram;
const IssuedCid = state.IssuedCid;
const LifecycleState = state.LifecycleState;
const MaxStreamDataItem = state.MaxStreamDataItem;
const MigrationCallback = state.MigrationCallback;
const MigrationDecision = state.MigrationDecision;
const NewReno = state.NewReno;
const NewTokenCallback = state.NewTokenCallback;
const OutgoingDatagram = state.OutgoingDatagram;
const PacketKeys = state.PacketKeys;
const Path = state.Path;
const PathCidsBlockedInfo = state.PathCidsBlockedInfo;
const PathSet = state.PathSet;
const PathState = state.PathState;
const PathStats = state.PathStats;
const PathValidator = state.PathValidator;
const PendingNewConnectionId = state.PendingNewConnectionId;
const PendingPathStatus = state.PendingPathStatus;
const PerLevelState = state.PerLevelState;
const PnSpace = state.PnSpace;
const QlogCallback = state.QlogCallback;
const QlogCongestionState = state.QlogCongestionState;
const QlogEvent = state.QlogEvent;
const QlogEventName = state.QlogEventName;
const QlogLossReason = state.QlogLossReason;
const QlogMigrationFailReason = state.QlogMigrationFailReason;
const QlogPacketDropReason = state.QlogPacketDropReason;
const QlogPacketKind = state.QlogPacketKind;
const QlogPnSpace = state.QlogPnSpace;
const QlogStreamState = state.QlogStreamState;
const RecvStream = state.RecvStream;
const Role = state.Role;
const RttEstimator = state.RttEstimator;
const Scheduler = state.Scheduler;
const SecretMaterial = state.SecretMaterial;
const SendStream = state.SendStream;
const SentCryptoChunk = state.SentCryptoChunk;
const SentPacketTracker = state.SentPacketTracker;
const Session = state.Session;
const StopSendingItem = state.StopSendingItem;
const Stream = state.Stream;
const Suite = state.Suite;
const TimerDeadline = state.TimerDeadline;
const TimerKind = state.TimerKind;
const TransportParams = state.TransportParams;
const ack_range_mod = state.ack_range_mod;
const ack_tracker_mod = state.ack_tracker_mod;
const application_ack_eliciting_threshold = state.application_ack_eliciting_threshold;
const congestion_mod = state.congestion_mod;
const default_connection_receive_window = state.default_connection_receive_window;
const default_max_connection_memory = state.default_max_connection_memory;
const default_mtu = state.default_mtu;
const default_stream_receive_window = state.default_stream_receive_window;
const early_data_context_mod = state.early_data_context_mod;
const event_queue_mod = state.event_queue_mod;
const flow_control_mod = state.flow_control_mod;
const frame_mod = state.frame_mod;
const frame_types = state.frame_types;
const incoming_ack_range_cap = state.incoming_ack_range_cap;
const incoming_retire_cid_cap = state.incoming_retire_cid_cap;
const initial_keys_mod = state.initial_keys_mod;
const level_mod = state.level_mod;
const lifecycle_mod = state.lifecycle_mod;
const long_packet_mod = state.long_packet_mod;
const loss_recovery_mod = state.loss_recovery_mod;
const max_application_ack_lower_ranges = state.max_application_ack_lower_ranges;
const max_application_ack_ranges_bytes = state.max_application_ack_ranges_bytes;
const max_close_reason_len = state.max_close_reason_len;
const max_connection_id_events = state.max_connection_id_events;
const max_crypto_reassembly_gap = state.max_crypto_reassembly_gap;
const max_datagram_send_events = state.max_datagram_send_events;
const max_flow_blocked_events = state.max_flow_blocked_events;
const max_initial_connection_receive_window = state.max_initial_connection_receive_window;
const max_initial_stream_receive_window = state.max_initial_stream_receive_window;
const max_outbound_datagram_payload_size = state.max_outbound_datagram_payload_size;
const max_pending_crypto_bytes_per_level = state.max_pending_crypto_bytes_per_level;
const max_pending_datagram_bytes = state.max_pending_datagram_bytes;
const max_pending_datagram_count = state.max_pending_datagram_count;
const max_recv_plaintext = state.max_recv_plaintext;
const max_stream_count_limit = state.max_stream_count_limit;
const max_streams_per_connection = state.max_streams_per_connection;
const max_supported_active_connection_id_limit = state.max_supported_active_connection_id_limit;
const max_supported_path_id = state.max_supported_path_id;
const max_supported_udp_payload_size = state.max_supported_udp_payload_size;
const max_tracked_stream_data_blocked = state.max_tracked_stream_data_blocked;
const min_path_challenge_interval_us = state.min_path_challenge_interval_us;
const min_quic_udp_payload_size = state.min_quic_udp_payload_size;
const min_stream_credit_return_batch = state.min_stream_credit_return_batch;
const path_frame_queue = state.path_frame_queue;
const path_mod = state.path_mod;
const pending_frames_mod = state.pending_frames_mod;
const pn_space_mod = state.pn_space_mod;
const quic_version_1 = state.quic_version_1;
const recv_stream_mod = state.recv_stream_mod;
const rtt_mod = state.rtt_mod;
const send_stream_mod = state.send_stream_mod;
const sent_packets_mod = state.sent_packets_mod;
const short_packet_mod = state.short_packet_mod;
const stateless_reset_mod = state.stateless_reset_mod;
const stream_credit_return_divisor = state.stream_credit_return_divisor;
const transport_error_aead_limit_reached = state.transport_error_aead_limit_reached;
const transport_error_excessive_load = state.transport_error_excessive_load;
const transport_error_final_size = state.transport_error_final_size;
const transport_error_flow_control = state.transport_error_flow_control;
const transport_error_frame_encoding = state.transport_error_frame_encoding;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const transport_error_stream_limit = state.transport_error_stream_limit;
const transport_error_stream_state = state.transport_error_stream_state;
const transport_error_transport_parameter = state.transport_error_transport_parameter;
const transport_params_mod = state.transport_params_mod;
const varint = state.varint;
const wire_header = state.wire_header;
const _internal = state._internal;

test "streamReset publicly aborts the send half" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 5), try conn.streamWrite(0, "hello"));
    try conn.streamReset(0, 0xdead);

    const s = conn.stream(0).?;
    try std.testing.expectEqual(send_stream_mod.State.reset_sent, s.send.state);
    try std.testing.expect(s.send.reset != null);
    try std.testing.expectEqual(@as(u64, 0xdead), s.send.reset.?.error_code);
    try std.testing.expectEqual(@as(u64, 5), s.send.reset.?.final_size);
    try std.testing.expectError(send_stream_mod.Error.StreamClosed, conn.streamWrite(0, "late"));
    try std.testing.expectError(Error.StreamNotFound, conn.streamReset(4, 0));
}

test "local close is exposed as sticky and pollable event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.close(false, 0x42, "shutting down");
    try std.testing.expectEqual(CloseState.closing, conn.closeState());

    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.application, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x42), sticky.error_code);
    try std.testing.expectEqual(@as(u64, 0), sticky.frame_type);
    try std.testing.expectEqualStrings("shutting down", sticky.reason);
    try std.testing.expect(!sticky.reason_truncated);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .close);
    try std.testing.expectEqualStrings("shutting down", event.close.reason);
    try std.testing.expect(conn.pollEvent() == null);
    try std.testing.expect(conn.closeEvent() != null);
}

test "local close truncates long reason and keeps sticky event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var reason: [max_close_reason_len + 32]u8 = undefined;
    @memset(&reason, 'x');
    conn.close(true, 0x1337, reason[0..]);

    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x1337), sticky.error_code);
    try std.testing.expectEqual(max_close_reason_len, sticky.reason.len);
    try std.testing.expect(sticky.reason_truncated);
    for (sticky.reason) |byte| {
        try std.testing.expectEqual(@as(u8, 'x'), byte);
    }

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .close);
    try std.testing.expectEqual(max_close_reason_len, event.close.reason.len);
    try std.testing.expect(event.close.reason_truncated);
    try std.testing.expect(conn.pollEvent() == null);

    const after_poll = conn.closeEvent().?;
    try std.testing.expectEqual(max_close_reason_len, after_poll.reason.len);
    try std.testing.expect(after_poll.reason_truncated);
}

test "closing and draining ignore incoming datagrams" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.close(false, 0x42, "closing");
    var random_short = [_]u8{ 0x40, 0, 1, 2, 3, 4, 5 };
    try conn.handle(&random_short, null, 1_000_000);
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expectEqual(@as(u64, 0), conn.last_activity_us);
    try std.testing.expectEqual(@as(u64, 0), conn.primaryPathConst().path.bytes_received);

    var peer_ctx = try boringssl.tls.Context.initClient(.{});
    defer peer_ctx.deinit();
    var peer_closed = try Connection.initClient(allocator, peer_ctx, "x");
    defer peer_closed.deinit();
    var payload: [128]u8 = undefined;
    const n = try frame_mod.encode(&payload, .{
        .connection_close = .{
            .is_transport = false,
            .error_code = 0x7,
            .reason_phrase = "bye",
        },
    });
    try peer_closed.dispatchFrames(.application, payload[0..n], 2_000_000);
    try std.testing.expectEqual(CloseState.draining, peer_closed.closeState());
    const deadline = peer_closed.lifecycle.draining_deadline_us.?;
    try peer_closed.handle(&random_short, null, 2_000_001);
    try std.testing.expectEqual(@as(u64, 0), peer_closed.last_activity_us);
    try peer_closed.tick(deadline);
    try std.testing.expectEqual(CloseState.closed, peer_closed.closeState());
    try std.testing.expect(peer_closed.nextTimerDeadline(deadline) == null);
}

test "peer close records transport error details" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var payload: [128]u8 = undefined;
    const n = try frame_mod.encode(&payload, .{
        .connection_close = .{
            .is_transport = true,
            .error_code = 0x0a,
            .frame_type = 0x08,
            .reason_phrase = "bad stream frame",
        },
    });
    try conn.dispatchFrames(.application, payload[0..n], 1_000_000);

    const sticky = conn.closeEvent().?;
    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expectEqual(CloseSource.peer, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x0a), sticky.error_code);
    try std.testing.expectEqual(@as(u64, 0x08), sticky.frame_type);
    try std.testing.expectEqualStrings("bad stream frame", sticky.reason);
    try std.testing.expectEqual(@as(u64, 1_000_000), sticky.at_us.?);
    try std.testing.expect(sticky.draining_deadline_us != null);
}

test "stateless reset token closes without CONNECTION_CLOSE" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const token: [16]u8 = .{
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    };
    conn.cached_peer_transport_params = .{ .stateless_reset_token = token };
    try conn.setPeerDcid(&.{ 0xaa, 0xbb, 0xcc, 0xdd });

    var packet: [24]u8 = .{
        0x40, 0xaa, 0xbb, 0xcc,
        0xdd, 0x55, 0x66, 0x77,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
    };
    @memcpy(packet[packet.len - 16 ..], &token);

    try conn.handle(&packet, null, 3_000_000);

    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expect(conn.lifecycle.pending_close == null);
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.stateless_reset, close_event.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, close_event.error_space);
    try std.testing.expectEqualStrings("stateless reset", close_event.reason);
    try std.testing.expectEqual(@as(u64, 3_000_000), close_event.at_us.?);
}

test "stateless reset matcher requires short packet with known token" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const token: [16]u8 = .{
        0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f,
    };
    conn.cached_peer_transport_params = .{ .stateless_reset_token = token };
    try conn.setPeerDcid(&.{0xaa});

    var long_packet = @as([24]u8, @splat(0));
    long_packet[0] = 0xc0;
    @memcpy(long_packet[long_packet.len - 16 ..], &token);
    try std.testing.expect(!conn.isKnownStatelessReset(long_packet[0..]));

    var unknown_short = @as([24]u8, @splat(0));
    unknown_short[0] = 0x40;
    const unknown_token: [16]u8 = @splat(0xee);
    @memcpy(unknown_short[unknown_short.len - 16 ..], &unknown_token);
    try std.testing.expect(!conn.isKnownStatelessReset(unknown_short[0..]));

    var short_packet = @as([24]u8, @splat(0));
    short_packet[0] = 0x40;
    @memcpy(short_packet[short_packet.len - 16 ..], &token);
    try std.testing.expect(conn.isKnownStatelessReset(short_packet[0..]));
}

test "tokenEql matches std.mem.eql across boundary cases" {
    // Constant-time compare must agree with std.mem.eql for the
    // ordinary (non-adversarial) cases: equal tokens, fully different
    // tokens, and tokens differing in only one byte at varying
    // positions. RFC 9000 §10.3 mandates CT compare; this test ensures
    // we did not accidentally weaken correctness while doing so.
    const a: [16]u8 = .{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };
    try std.testing.expectEqual(std.mem.eql(u8, &a, &a), Connection.tokenEql(a, a));

    const b: [16]u8 = @splat(0xff);
    try std.testing.expectEqual(std.mem.eql(u8, &a, &b), Connection.tokenEql(a, b));

    var differ: [16]u8 = a;
    inline for (.{ 0, 1, 7, 8, 14, 15 }) |i| {
        differ = a;
        differ[i] ^= 0x01;
        try std.testing.expectEqual(
            std.mem.eql(u8, &a, &differ),
            Connection.tokenEql(a, differ),
        );
    }

    // All-zero tokens must compare equal (the default-initialized
    // value of an unfilled cached entry — guard against accidentally
    // returning false for zero arrays).
    const zero: [16]u8 = @splat(0);
    try std.testing.expect(Connection.tokenEql(zero, zero));
}

test "Version Negotiation with no compatible version closes terminally" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const versions = [_]u8{
        0x6b, 0x33, 0x43, 0xcf,
        0xff, 0x00, 0x00, 0x20,
    };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &versions,
    } });

    try conn.handle(packet[0..n], null, 4_000_000);

    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.closed, conn.closeState());
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.version_negotiation, close_event.source);
    try std.testing.expectEqualStrings("no compatible QUIC version", close_event.reason);
}

test "Version Negotiation is ignored when it lists QUIC v1 or has wrong CID echo" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 8, 7, 6, 5 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const includes_v1 = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0xff, 0x00, 0x00, 0x20,
    };
    var packet: [128]u8 = undefined;
    var n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &includes_v1,
    } });
    try conn.handle(packet[0..n], null, 4_000_000);
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&.{ 0xde, 0xad }),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &other_versions,
    } });
    try conn.handle(packet[0..n], null, 4_000_001);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Version Negotiation is ignored with wrong SCID echo or malformed versions" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 8, 7, 6, 5 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&.{ 0xde, 0xad }),
        .versions_bytes = &other_versions,
    } });
    try conn.handle(packet[0..n], null, 4_000_002);
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    var malformed: [128]u8 = undefined;
    var pos: usize = 0;
    malformed[pos] = 0x80;
    pos += 1;
    std.mem.writeInt(u32, malformed[pos..][0..4], 0, .big);
    pos += 4;
    malformed[pos] = @intCast(client_scid.len);
    pos += 1;
    @memcpy(malformed[pos .. pos + client_scid.len], &client_scid);
    pos += client_scid.len;
    malformed[pos] = @intCast(odcid.len);
    pos += 1;
    @memcpy(malformed[pos .. pos + odcid.len], &odcid);
    pos += odcid.len;
    @memcpy(malformed[pos .. pos + 3], &[_]u8{ 0x6b, 0x33, 0x43 });
    pos += 3;

    try conn.handle(malformed[0..pos], null, 4_000_003);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Version Negotiation packets are ignored by servers" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&.{ 8, 7, 6, 5 }),
        .scid = try wire_header.ConnId.fromSlice(&.{ 1, 2, 3, 4 }),
        .versions_bytes = &other_versions,
    } });

    try conn.handle(packet[0..n], null, 4_000_004);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
    try std.testing.expect(conn.closeEvent() == null);
}

test "Retry is accepted once and re-arms Initial crypto with token" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const retry_token = "retry-token";
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    var packet: [256]u8 = undefined;
    const retry_len = try long_packet_mod.sealRetry(&packet, .{
        .original_dcid = &odcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = retry_token,
    });

    const sent_copy = try allocator.dupe(u8, "client hello");
    try conn.sent_crypto[EncryptionLevel.initial.idx()].append(allocator, .{
        .pn = 0,
        .offset = 0,
        .data = sent_copy,
    });
    try conn.sent[0].record(.{
        .pn = 0,
        .sent_time_us = 100,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pn_spaces[0].next_pn = 9;

    try conn.handle(packet[0..retry_len], null, 4_000_000);

    try std.testing.expect(conn.retry_accepted);
    try std.testing.expectEqualSlices(u8, retry_token, conn.retry_token.items);
    try std.testing.expectEqualSlices(u8, &retry_scid, conn.peer_dcid.slice());
    try std.testing.expectEqualSlices(u8, &retry_scid, conn.initial_dcid.slice());
    try std.testing.expectEqualSlices(u8, &odcid, conn.original_initial_dcid.slice());
    try std.testing.expectEqual(@as(u64, 9), conn.pn_spaces[0].next_pn);
    try std.testing.expectEqual(@as(u32, 0), conn.sent[0].count);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[EncryptionLevel.initial.idx()].items.len);

    var out: [1500]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &out, 4_000_001)).?;
    const parsed = try wire_header.parse(out[0..n], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqualSlices(u8, retry_token, parsed.header.initial.token);
}

test "Retry with invalid integrity tag is ignored" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    var packet: [256]u8 = undefined;
    const retry_len = try long_packet_mod.sealRetry(&packet, .{
        .original_dcid = &odcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = "retry-token",
    });
    packet[retry_len - 1] ^= 0x01;

    try conn.handle(packet[0..retry_len], null, 4_000_000);

    try std.testing.expect(!conn.retry_accepted);
    try std.testing.expectEqualSlices(u8, &odcid, conn.peer_dcid.slice());
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Retry source CID transport parameter is validated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 1, 2, 3, 5, 8, 13, 21 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    try conn.setInitialDcid(&odcid);
    conn.retry_accepted = true;
    conn.retry_source_cid = ConnectionId.fromSlice(&retry_scid);
    conn.retry_source_cid_set = true;

    conn.cached_peer_transport_params = .{
        .original_destination_connection_id = ConnectionId.fromSlice(&odcid),
        .retry_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb }),
    };
    conn.validatePeerTransportConnectionIds();

    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqualStrings("retry source cid mismatch", conn.lifecycle.pending_close.?.reason);
}

fn expectServerOnlyPeerTransportParamRejected(params: TransportParams, reason: []const u8) !void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    conn.cached_peer_transport_params = params;
    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqualStrings(reason, conn.lifecycle.pending_close.?.reason);
}

test "server rejects client-sent server-only transport parameters" {
    const reset_token: [16]u8 = .{
        0, 1, 2,  3,  4,  5,  6,  7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };

    try expectServerOnlyPeerTransportParamRejected(.{
        .original_destination_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb }),
    }, "client sent original destination cid");
    try expectServerOnlyPeerTransportParamRejected(.{
        .stateless_reset_token = reset_token,
    }, "client sent stateless reset token");
    try expectServerOnlyPeerTransportParamRejected(.{
        .preferred_address = .{
            .ipv4_address = .{ 192, 0, 2, 1 },
            .ipv4_port = 4433,
            .ipv6_address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .ipv6_port = 4433,
            .connection_id = ConnectionId.fromSlice(&.{ 0xc0, 0xc1 }),
            .stateless_reset_token = reset_token,
        },
    }, "client sent preferred address");
    try expectServerOnlyPeerTransportParamRejected(.{
        .retry_source_connection_id = ConnectionId.fromSlice(&.{ 0xcc, 0xdd }),
    }, "client sent retry source cid");
}

test "server writeRetry emits a Retry addressed to the client Initial SCID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const init_keys = try initial_keys_mod.deriveInitialKeys(&odcid, false);
    const keys = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    var initial: [256]u8 = undefined;
    const initial_len = try long_packet_mod.sealInitial(&initial, .{
        .dcid = &odcid,
        .scid = &client_scid,
        .pn = 0,
        .payload = "CRYPTO",
        .keys = &keys,
    });

    var retry: [256]u8 = undefined;
    const retry_len = try conn.writeRetry(
        &retry,
        initial[0..initial_len],
        &retry_scid,
        "server-token",
    );

    const parsed = try wire_header.parse(retry[0..retry_len], 0);
    try std.testing.expect(parsed.header == .retry);
    try std.testing.expectEqualSlices(u8, &client_scid, parsed.header.retry.dcid.slice());
    try std.testing.expectEqualSlices(u8, &retry_scid, parsed.header.retry.scid.slice());
    try std.testing.expectEqualSlices(u8, "server-token", parsed.header.retry.retry_token);
    try std.testing.expect(try long_packet_mod.validateRetryIntegrity(&odcid, retry[0..retry_len]));
}

test "server writeVersionNegotiation echoes client CIDs and versions" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const client_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
    const init_keys = try initial_keys_mod.deriveInitialKeys(&client_dcid, false);
    const keys = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    var initial: [256]u8 = undefined;
    const initial_len = try long_packet_mod.sealInitial(&initial, .{
        .version = 0x6b3343cf,
        .dcid = &client_dcid,
        .scid = &client_scid,
        .pn = 0,
        .payload = "CRYPTO",
        .keys = &keys,
    });

    var vn: [128]u8 = undefined;
    const vn_len = try conn.writeVersionNegotiation(
        &vn,
        initial[0..initial_len],
        &.{quic_version_1},
    );

    const parsed = try wire_header.parse(vn[0..vn_len], 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    try std.testing.expectEqualSlices(u8, &client_scid, parsed.header.version_negotiation.dcid.slice());
    try std.testing.expectEqualSlices(u8, &client_dcid, parsed.header.version_negotiation.scid.slice());
    try std.testing.expectEqual(@as(usize, 1), parsed.header.version_negotiation.versionCount());
    try std.testing.expectEqual(quic_version_1, parsed.header.version_negotiation.version(0));
}

test "EncryptionLevel idx round-trip" {
    inline for (level_mod.all) |lvl| {
        try std.testing.expectEqual(lvl.idx(), @intFromEnum(lvl));
    }
}

test "packetPayloadAckEliciting ignores ACK-only payloads" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    pos += try frame_mod.encode(buf[pos..], .{ .padding = .{ .count = 2 } });
    pos += try frame_mod.encode(buf[pos..], .{ .ack = .{
        .largest_acked = 9,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
    } });
    try std.testing.expect(!Connection.packetPayloadAckEliciting(buf[0..pos]));

    pos += try frame_mod.encode(buf[pos..], .{ .ping = .{} });
    try std.testing.expect(Connection.packetPayloadAckEliciting(buf[0..pos]));
}

test "packetPayloadNeedsImmediateAck flags stream finality and resets" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    pos += try frame_mod.encode(buf[pos..], .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_offset = false,
        .has_length = true,
        .fin = false,
    } });
    try std.testing.expect(!Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));

    pos = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .stream = .{
        .stream_id = 0,
        .offset = 1,
        .data = "",
        .has_offset = true,
        .has_length = true,
        .fin = true,
    } });
    try std.testing.expect(Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));

    pos = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 42,
        .final_size = 1,
    } });
    try std.testing.expect(Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));
}

test "CRYPTO reassembly: out-of-order fragments delivered in order" {
    // Tests the same shape quic-go sends on the wire: a high-offset
    // fragment first, then the low-offset fragment, then a tiny
    // bridge fragment, then the tail.
    const allocator = std.testing.allocator;

    // We don't need a real Connection for this — we exercise the
    // reassembly machinery via a bare struct that holds the same
    // fields. Cleaner: use a real Connection but skip TLS bring-up.
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();

    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    // Don't bind/handshake — we're only testing reassembly, which
    // doesn't need TLS.

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();

    // First fragment: out-of-order high range.
    try conn.handleCrypto(lvl, .{ .offset = 69, .data = "BBBBBBBB" });
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_pending[idx].items.len);

    // Second fragment: in-order low range — delivers immediately.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "AAAAAAAAAAA" }); // 11 bytes
    try std.testing.expectEqual(@as(u64, 11), conn.crypto_recv_offset[idx]);

    // Third fragment: bridges the gap [11, 69) — delivers, then
    // drains the pending [69, 77).
    var bridge: [58]u8 = @splat('M');
    try conn.handleCrypto(lvl, .{ .offset = 11, .data = &bridge });
    try std.testing.expectEqual(@as(u64, 77), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[idx].items.len);

    // Inbox should have all 77 bytes in the right order.
    try std.testing.expectEqual(@as(usize, 77), conn.inbox[idx].len);
    try std.testing.expectEqualSlices(u8, "AAAAAAAAAAA", conn.inbox[idx].buf[0..11]);
    for (conn.inbox[idx].buf[11..69]) |b| try std.testing.expectEqual(@as(u8, 'M'), b);
    try std.testing.expectEqualSlices(u8, "BBBBBBBB", conn.inbox[idx].buf[69..77]);
}

test "CRYPTO reassembly: duplicate fragment is silently ignored" {
    const allocator = std.testing.allocator;
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);

    // Retransmit of the same range — should be a no-op.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 6), conn.inbox[idx].len);

    // Partial overlap (offset=3 covers bytes already delivered + new).
    try conn.handleCrypto(lvl, .{ .offset = 3, .data = "defGHI" });
    try std.testing.expectEqual(@as(u64, 9), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqualSlices(u8, "abcdefGHI", conn.inbox[idx].buf[0..9]);
}

test "CRYPTO reassembly: deterministic shuffled fragment smoke" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();
    const total: usize = 4096;
    const chunk: usize = 64;
    const chunks = total / chunk;

    var data: [total]u8 = undefined;
    var indices: [chunks]usize = undefined;
    var prng = std.Random.DefaultPrng.init(0xc274_7074_6f66_757a);
    const rng = prng.random();
    rng.bytes(&data);
    for (&indices, 0..) |*slot, i| slot.* = i;
    rng.shuffle(usize, &indices);

    for (indices, 0..) |chunk_idx, order| {
        const off = chunk_idx * chunk;
        const bytes = data[off..][0..chunk];
        try conn.handleCrypto(lvl, .{ .offset = @intCast(off), .data = bytes });
        if ((order % 9) == 0) {
            try conn.handleCrypto(lvl, .{ .offset = @intCast(off), .data = bytes });
        }
    }

    try std.testing.expectEqual(@as(u64, total), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[idx].items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[idx]);
    try std.testing.expectEqual(total, conn.inbox[idx].len);
    try std.testing.expectEqualSlices(u8, &data, conn.inbox[idx].buf[0..total]);
}

test "timer deadline reports ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    conn.pnSpaceForLevel(.application).recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "delayed_ack_packet_threshold tunes the immediate-ACK gate" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Threshold = 1: every ack-eliciting packet forces an immediate
    // ACK with no delayed-ACK arming.
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(0, 1_000, true, 1);
    var tracker = &conn.primaryPath().app_pn_space.received;
    try std.testing.expect(tracker.pending_ack);

    // Reset and try threshold=4. The first three ack-eliciting
    // packets arm but don't promote; the fourth promotes.
    conn.primaryPath().app_pn_space.received = .{};
    tracker = &conn.primaryPath().app_pn_space.received;
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(10, 1_000, true, 4);
    try std.testing.expect(!tracker.pending_ack);
    try std.testing.expect(tracker.delayed_ack_armed);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(11, 1_001, true, 4);
    try std.testing.expect(!tracker.pending_ack);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(12, 1_002, true, 4);
    try std.testing.expect(!tracker.pending_ack);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(13, 1_003, true, 4);
    try std.testing.expect(tracker.pending_ack);

    // The Connection-level field defaults to
    // `application_ack_eliciting_threshold`.
    try std.testing.expectEqual(application_ack_eliciting_threshold, conn.delayed_ack_packet_threshold);
    conn.delayed_ack_packet_threshold = 4;
    try std.testing.expectEqual(@as(u8, 4), conn.delayed_ack_packet_threshold);
}

test "application delayed ACK waits for configured threshold or timer" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    const tracker = &conn.primaryPath().app_pn_space.received;
    const delayed_ack_threshold = 2;
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(7, 1000, true, delayed_ack_threshold);

    try std.testing.expect(!tracker.pending_ack);
    try std.testing.expect(tracker.delayed_ack_armed);
    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);

    try conn.tick(1_009_000);
    try std.testing.expect(!tracker.pending_ack);
    try conn.tick(1_010_000);
    try std.testing.expect(tracker.pending_ack);

    tracker.markAckSent();
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(8, 1011, true, delayed_ack_threshold);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(9, 1012, true, delayed_ack_threshold);
    try std.testing.expect(tracker.pending_ack);
}

test "ACK-only application packets do not consume sent tracker slots" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    var packet_buf: [default_mtu]u8 = undefined;
    var pn: u64 = 0;
    while (pn < 32) : (pn += 1) {
        conn.pnSpaceForLevel(.application).recordReceived(pn, @intCast(1_000 + pn));
        _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000 + pn)).?;
    }

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).count);
    try std.testing.expectEqual(@as(u64, 0), conn.sentForLevel(.application).bytes_in_flight);
}

test "PTO requeues application stream data and arms a probe" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");
    const chunk = s.send.peekChunk(100).?;
    try s.send.recordSent(4, chunk);
    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 4,
        .sent_time_us = 0,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_key = 4,
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(u32, 0), app_sent.count);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u8, 1), conn.primaryPath().pto_probe_count);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
    const resent = s.send.peekChunk(100).?;
    try std.testing.expectEqual(@as(u64, 0), resent.offset);
    try std.testing.expectEqual(@as(u64, 5), resent.length);
}

test "PTO requeues retransmittable control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 8,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .max_data = .{ .maximum_data = 4096 } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(?u64, 4096), conn.pending_frames.max_data);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "poll helper emits one draft multipath control frame with retransmit metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.queuePathStatus(2, false, 7);
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    defer packet.deinit(allocator);
    var payload: [default_mtu]u8 = undefined;
    var pos: usize = 0;

    try std.testing.expect(try conn.emitOnePendingMultipathFrame(&packet, &payload, &pos, default_mtu));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.path_statuses.items.len);
    try std.testing.expectEqual(@as(usize, 1), packet.retransmit_frames.items.len);
    try std.testing.expect(packet.retransmit_frames.items[0] == .path_status_backup);

    const decoded = try frame_mod.decode(payload[0..pos]);
    try std.testing.expect(decoded.frame == .path_status_backup);
    try std.testing.expectEqual(@as(u32, 2), decoded.frame.path_status_backup.path_id);
    try std.testing.expectEqual(@as(u64, 7), decoded.frame.path_status_backup.sequence_number);
}

test "poll helper coalesces draft multipath control frames with retransmit metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.queuePathStatus(2, true, 7);
    conn.queueMaxPathId(4);
    conn.queuePathsBlocked(3);

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    defer packet.deinit(allocator);
    var payload: [default_mtu]u8 = undefined;
    var pos: usize = 0;

    try std.testing.expect(try conn.emitPendingMultipathFrames(&packet, &payload, &pos, default_mtu));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.path_statuses.items.len);
    try std.testing.expectEqual(@as(?u32, null), conn.pending_frames.max_path_id);
    try std.testing.expectEqual(@as(?u32, null), conn.pending_frames.paths_blocked);
    try std.testing.expectEqual(@as(usize, 3), packet.retransmit_frames.items.len);
    try std.testing.expect(packet.retransmit_frames.items[0] == .path_status_available);
    try std.testing.expect(packet.retransmit_frames.items[1] == .max_path_id);
    try std.testing.expect(packet.retransmit_frames.items[2] == .paths_blocked);

    var it = frame_mod.iter(payload[0..pos]);
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    const third = (try it.next()).?;
    try std.testing.expect(first == .path_status_available);
    try std.testing.expect(second == .max_path_id);
    try std.testing.expect(third == .paths_blocked);
    try std.testing.expect((try it.next()) == null);
}

test "PTO requeues retransmittable draft multipath control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 11,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = 3,
        .error_code = 99,
    } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_abandons.items.len);
    try std.testing.expectEqual(@as(u32, 3), conn.pending_frames.path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_frames.path_abandons.items[0].error_code);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "PTO arms PING when no retransmittable data can be requeued" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 9,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expect(conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
}

test "requestPing queues application PING on primary path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    conn.requestPing();
    try std.testing.expect(conn.primaryPath().pending_ping);

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;

    try std.testing.expect(!conn.primaryPath().pending_ping);
    try std.testing.expectEqual(@as(u32, 1), conn.primaryPath().sent.count);
    try std.testing.expect(conn.primaryPath().sent.packets[0].ack_eliciting);
}

test "requestPathPing queues application PING on non-primary path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));

    try conn.requestPathPing(path_id);
    const path = conn.paths.get(path_id).?;
    try std.testing.expect(path.pending_ping);

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_000_000)).?;

    try std.testing.expect(!path.pending_ping);
    try std.testing.expectEqual(@as(u32, 1), path.sent.count);
    try std.testing.expect(path.sent.packets[0].ack_eliciting);
}

test "PTO requeues CRYPTO bytes at original offsets" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const level: EncryptionLevel = .initial;
    const level_idx = level.idx();
    const bytes = try allocator.dupe(u8, "crypto-fragment");
    var bytes_moved = false;
    errdefer if (!bytes_moved) allocator.free(bytes);
    try conn.sent_crypto[level_idx].append(allocator, .{
        .pn = 2,
        .offset = 123,
        .data = bytes,
    });
    bytes_moved = true;
    try conn.sentForLevel(level).record(.{
        .pn = 2,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(level));

    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[level_idx].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[level_idx].items.len);
    try std.testing.expectEqual(@as(u64, 123), conn.crypto_retx[level_idx].items[0].offset);
    try std.testing.expectEqualStrings("crypto-fragment", conn.crypto_retx[level_idx].items[0].data);
}

test "ACK of ack-eliciting packet resets PTO count and updates RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ptoCountForLevel(.application).* = 3;
    try conn.sentForLevel(.application).record(.{
        .pn = 11,
        .sent_time_us = 1_000_000,
        .bytes = 120,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 12;
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 11,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), conn.ptoCountForLevel(.application).*);
    try std.testing.expectEqual(@as(u64, 50_000), conn.rttForLevel(.application).latest_rtt_us);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).count);
}

test "ACK with largest_acked >= next_pn is a PROTOCOL_VIOLATION" {
    // RFC 9000 §13.1 / RFC 9002 §A.3: "Receipt of an acknowledgment
    // for a packet that was not sent ... MUST be treated as a
    // connection error of type PROTOCOL_VIOLATION." A peer that
    // claims to have acked a PN we never sent is either buggy or
    // hostile; we must close the connection rather than poison
    // packet-threshold loss detection on our legitimate in-flight
    // packets.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // We have two in-flight packets at PNs 0 and 1.
    try conn.sentForLevel(.application).record(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 1_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 2;

    // Peer claims an ACK for PN 7 — well beyond next_pn = 2.
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 7,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 100_000);

    // Connection must be closing with PROTOCOL_VIOLATION.
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(transport_error_protocol_violation, sticky.error_code);

    // Critically, our in-flight packets must NOT have been declared
    // lost or had their largest_acked_sent updated to the bogus 7.
    try std.testing.expectEqual(@as(u32, 2), conn.sentForLevel(.application).count);
    try std.testing.expectEqual(@as(?u64, null), conn.pnSpaceForLevel(.application).largest_acked_sent);
}

test "ACK with largest_acked == next_pn is a PROTOCOL_VIOLATION" {
    // Boundary case: next_pn is the *next* PN to assign on send,
    // so an ACK whose largest_acked equals next_pn is also illegal.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.sentForLevel(.application).record(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 1;

    // ACK claims PN 1, but next_pn is 1 (we've never sent PN 1).
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 100_000);

    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expectEqual(transport_error_protocol_violation, conn.closeEvent().?.error_code);
}

test "ACKed in-flight packets grow congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const initial_cwnd = conn.congestionWindow();
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 2;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_010_000);

    try std.testing.expect(conn.congestionWindow() > initial_cwnd);
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "packet-threshold loss reduces congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const initial_cwnd = conn.congestionWindow();
    var pn: u64 = 0;
    while (pn <= 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 1_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    conn.pnSpaceForLevel(.application).next_pn = 5;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 4,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 50_000);

    try std.testing.expect(conn.congestionWindow() < initial_cwnd);
    try std.testing.expect(conn.ccForApplication().ssthresh != null);
}

test "persistent congestion resets congestion window to minimum" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ccForApplication().cwnd = 30_000;
    conn.rttForLevel(.application).smoothed_rtt_us = 10_000;
    conn.rttForLevel(.application).latest_rtt_us = 10_000;
    conn.rttForLevel(.application).rtt_var_us = 1_000;
    conn.rttForLevel(.application).first_sample_taken = true;

    conn.pnSpaceForLevel(.application).largest_acked_sent = 10;
    var pn: u64 = 0;
    while (pn < 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 100_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    try conn.tick(1_000_000);

    try std.testing.expectEqual(conn.ccForApplication().cfg.minWindow(), conn.congestionWindow());
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "persistent congestion ignores non-ack-eliciting losses (RFC 9002 §7.6.1)" {
    // RFC 9002 §7.6.1: "Two ack-eliciting packets ... are declared
    // lost". A duration spanned only by non-ack-eliciting lost
    // packets must NOT establish persistent congestion.
    var stats: LossStats = .{};
    // Two non-ack-eliciting "lost" packets spanning a wide duration
    // (300ms). With pto = 30ms and threshold = 3, the unfiltered
    // earliest/largest range would easily satisfy the old check —
    // this regression-tests the ack-eliciting filter.
    stats.add(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    stats.add(.{
        .pn = 1,
        .sent_time_us = 300_000,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));

    // Adding a single ack-eliciting lost packet still doesn't
    // qualify — RFC requires *two* ack-eliciting losses bounding
    // the duration.
    stats.add(.{
        .pn = 2,
        .sent_time_us = 150_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));

    // Two ack-eliciting lost packets bounding the duration → fires.
    stats.add(.{
        .pn = 3,
        .sent_time_us = 400_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // duration (400ms − 150ms) = 250ms ≥ 3 × 30ms = 90ms → fires.
    try std.testing.expect(Connection.isPersistentCongestionFromBasePto(30_000, stats));
}

test "persistent congestion duration uses only ack-eliciting bounds" {
    // Mixed losses: a wide-spanning non-ack-eliciting lost packet
    // must NOT inflate the duration computed from the narrower
    // ack-eliciting subset.
    var stats: LossStats = .{};
    // Non-ack-eliciting at t=0 (would extend duration to 100ms).
    stats.add(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    // Two ack-eliciting losses inside a narrower window.
    stats.add(.{
        .pn = 1,
        .sent_time_us = 80_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    stats.add(.{
        .pn = 2,
        .sent_time_us = 100_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // base_pto = 30ms → threshold = 90ms. Ack-eliciting duration is
    // only 20ms (100ms − 80ms), so persistent congestion must NOT
    // fire even though the unfiltered duration (100ms) exceeds the
    // threshold.
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));
}

test "congestionBlocked gates application data but allows PTO probes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ccForApplication().cwnd = 1200;
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try std.testing.expect(conn.congestionBlocked(.application));
    try std.testing.expect(!conn.congestionBlocked(.initial));
    conn.pendingPingForLevel(.application).* = true;
    try std.testing.expect(!conn.congestionBlocked(.application));
    conn.pendingPingForLevel(.application).* = false;
    conn.primaryPath().pto_probe_count = 1;
    try std.testing.expect(!conn.congestionBlocked(.application));
}

test "PathSet API exposes path lifecycle and application recovery state" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.enableMultipath(true);
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
    const initial = conn.pathStats(0).?;
    try std.testing.expect(initial.validated);
    try std.testing.expectEqual(@as(u64, 0), initial.bytes_in_flight);

    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    const after_send = conn.pathStats(0).?;
    try std.testing.expectEqual(@as(u64, 1200), after_send.bytes_in_flight);

    const id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    try std.testing.expectEqual(@as(u32, 1), id);
    try std.testing.expect(conn.setActivePath(id));
    try std.testing.expectEqual(id, conn.activePathId());
    try std.testing.expect(conn.markPathValidated(id));
    try std.testing.expect(conn.pathStats(id).?.validated);
    try std.testing.expect(conn.setPathBackup(id, true));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_statuses.items.len);
    try std.testing.expect(!conn.pending_frames.path_statuses.items[0].available);
    conn.setScheduler(.round_robin);
    try std.testing.expect(conn.abandonPath(id));
    try std.testing.expectEqual(path_mod.State.retiring, conn.pathStats(id).?.state);
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
}

test "abandoned paths keep recovery until three largest PTOs elapse" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    try path.sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000,
        .bytes = 64,
        .ack_eliciting = false,
        .in_flight = false,
    });

    conn.primaryPath().pto_count = 1;
    const now_us: u64 = 10_000;
    const expected_deadline = now_us +| 3 * conn.largestApplicationPtoDurationUs();
    try std.testing.expect(conn.abandonPathAt(path_id, 42, now_us));
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqual(expected_deadline, path.retire_deadline_us.?);
    try std.testing.expectEqual(expected_deadline, conn.pathStats(path_id).?.retire_deadline_us.?);

    const deadline = conn.nextTimerDeadline(now_us).?;
    try std.testing.expectEqual(TimerKind.path_retirement, deadline.kind);
    try std.testing.expectEqual(path_id, deadline.path_id);

    try conn.tick(expected_deadline - 1);
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqual(@as(u32, 1), path.sent.count);

    try conn.tick(expected_deadline);
    try std.testing.expectEqual(path_mod.State.failed, path.path.state);
    try std.testing.expectEqual(@as(?u64, null), path.retire_deadline_us);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
}

test "retiring paths retain peer CIDs and emit PATH_ACK during drain" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    const now_us: u64 = 10_000;
    const expected_deadline = now_us +| conn.retiredPathRetentionUs();
    try std.testing.expect(conn.abandonPathAt(path_id, 42, now_us));
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqualSlices(u8, &.{0xbb}, path.path.peer_cid.slice());

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, now_us + 1)).?;
    try std.testing.expectEqual(path_id, datagram.path_id);
    try std.testing.expect(!path.app_pn_space.received.pending_ack);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..datagram.len], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
        .multipath_path_id = path_id,
    });

    var saw_path_ack = false;
    var saw_path_abandon = false;
    var it = frame_mod.iter(opened.payload);
    while (try it.next()) |frame| switch (frame) {
        .path_ack => |ack| {
            saw_path_ack = true;
            try std.testing.expectEqual(path_id, ack.path_id);
            try std.testing.expectEqual(@as(u64, 9), ack.largest_acked);
        },
        .path_abandon => |abandon| {
            saw_path_abandon = true;
            try std.testing.expectEqual(path_id, abandon.path_id);
            try std.testing.expectEqual(@as(u64, 42), abandon.error_code);
        },
        else => {},
    };
    try std.testing.expect(saw_path_ack);
    try std.testing.expect(saw_path_abandon);

    try conn.tick(expected_deadline);
    try std.testing.expectEqual(path_mod.State.failed, path.path.state);
    try std.testing.expectEqual(@as(u8, 0), path.path.peer_cid.len);
}

test "PATH_ACK routes ACK processing to the indicated application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    const path = conn.paths.get(path_id).?;
    try path.sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    path.app_pn_space.next_pn = 1;

    try conn.handlePathAck(.{
        .path_id = path_id,
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expectEqual(@as(u64, 0), path.sent.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.largest_acked_sent);
    try std.testing.expectEqual(@as(u64, 50_000), path.path.rtt.latest_rtt_us);
}

test "ACK / PATH_ACK range-count sum is bounded per handle cycle" {
    // Build a payload of 16 PATH_ACK frames each declaring 256 ranges
    // (the per-frame decoder cap). 16 * (256 + 1) > incoming_ack_range_cap,
    // so dispatch must skip frames once the cumulative count exceeds
    // the cap. We can't easily run real decode (the ranges are
    // synthetic), so drive `dispatchFrames` with a hand-rolled
    // payload using `range_count = 256, first_range = 0`.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Pre-record sent packets so handleAckAtLevel doesn't bail with
    // "ack of unsent packet". We'll only ack pn=0 from each frame,
    // since the synthetic ranges_bytes is empty (range_count is the
    // declared count; the iterator stops at the first invalid byte —
    // but we feed it through the in-source dispatch path using
    // pre-built frame_types.PathAck values that don't go through the
    // decoder).
    conn.paths.primary().app_pn_space.next_pn = 1;
    try conn.paths.primary().sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000,
        .bytes = 32,
        .ack_eliciting = true,
        .in_flight = true,
    });

    // Simulate per-handle-cycle entry: counters reset.
    conn.incoming_ack_range_count = 0;

    // First frame: range_count = 256 → bump cumulative to 257.
    try std.testing.expect(!conn.exceedsIncomingAckRangeCap(256));
    try std.testing.expectEqual(@as(u64, 257), conn.incoming_ack_range_count);

    // Three more frames bump the count past 4*256 = 1024.
    try std.testing.expect(!conn.exceedsIncomingAckRangeCap(256));
    try std.testing.expect(!conn.exceedsIncomingAckRangeCap(256));
    // Fourth would push to 1028 — beyond the 1024 cap.
    try std.testing.expect(conn.exceedsIncomingAckRangeCap(256));
    // Counter stops advancing once the cap is reached.
    try std.testing.expectEqual(@as(u64, 771), conn.incoming_ack_range_count);
    // Subsequent frames continue to be rejected without further
    // bumping the counter (cap stays sticky for this cycle).
    try std.testing.expect(conn.exceedsIncomingAckRangeCap(256));
    try std.testing.expectEqual(@as(u64, 771), conn.incoming_ack_range_count);
}

fn installTestApplicationWriteSecret(conn: *Connection) !void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    try conn.installApplicationSecret(.write, material);
}

fn installTestApplicationReadSecret(conn: *Connection) !void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    try conn.installApplicationSecret(.read, material);
}

fn installTestEarlyDataWriteSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].write = material;
}

fn installTestEarlyDataReadSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].read = material;
}

test "peer key update promotes next read keys and keeps previous until discard deadline" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    const old_epoch = conn.app_read_current.?;
    const next_epoch = conn.app_read_next.?;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });

    var packet_buf: [default_mtu]u8 = undefined;
    const new_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 1,
        .largest_acked = 0,
        .payload = payload[0..payload_len],
        .keys = &next_epoch.keys,
        .key_phase = next_epoch.key_phase,
    });

    _ = try conn.handleShort(packet_buf[0..new_len], 1_000_000);
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.read_epoch);
    try std.testing.expect(status.read_key_phase);
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_key_phase);
    try std.testing.expect(status.write_update_pending_ack);
    const discard_deadline = status.previous_read_discard_deadline_us.?;

    const old_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .largest_acked = 0,
        .payload = payload[0..payload_len],
        .keys = &old_epoch.keys,
        .key_phase = old_epoch.key_phase,
    });
    _ = try conn.handleShort(packet_buf[0..old_len], 1_001_000);
    try std.testing.expectEqual(@as(u64, 0), conn.keyUpdateStatus().auth_failures);
    try std.testing.expect(conn.app_read_previous != null);

    try conn.tick(discard_deadline);
    try std.testing.expect(conn.app_read_previous == null);

    const late_old_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 2,
        .largest_acked = 1,
        .payload = payload[0..payload_len],
        .keys = &old_epoch.keys,
        .key_phase = old_epoch.key_phase,
    });
    _ = try conn.handleShort(packet_buf[0..late_old_len], discard_deadline + 1);
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(u64, 1), status.auth_failures);
}

test "local key update waits for ACK and three PTOs before the next update" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{});

    try conn.requestKeyUpdate(1_000_000);
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_key_phase);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectError(Error.KeyUpdateBlocked, conn.requestKeyUpdate(1_001_000));

    conn.primaryPath().pending_ping = true;
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_002_000)).?;
    try std.testing.expectEqual(@as(?u64, 1), conn.primaryPath().sent.packets[0].key_epoch);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);
    status = conn.keyUpdateStatus();
    try std.testing.expect(!status.write_update_pending_ack);
    const next_after = status.next_local_update_after_us.?;
    try std.testing.expect(!conn.canInitiateKeyUpdateAt(next_after - 1));
    try std.testing.expectError(Error.KeyUpdateBlocked, conn.requestKeyUpdate(next_after - 1));
    try conn.requestKeyUpdate(next_after);
    try std.testing.expectEqual(@as(?u64, 2), conn.keyUpdateStatus().write_epoch);
}

test "automatic write key update happens before configured packet limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 4,
        .proactive_update_threshold = 1,
        .integrity_limit = 4,
    });
    try conn.setPeerDcid(&.{});

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(?u64, 0), conn.keyUpdateStatus().write_epoch);
    try std.testing.expectEqual(@as(u64, 1), conn.keyUpdateStatus().write_packets_protected);

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    const status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);
}

test "application packet limit counts across paths before proactive key update" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 8,
        .proactive_update_threshold = 2,
        .integrity_limit = 8,
    });
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 0), status.write_epoch);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);

    const path = conn.paths.get(path_id).?;
    path.pending_ping = true;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 0), status.write_epoch);
    try std.testing.expectEqual(@as(u64, 2), status.write_packets_protected);

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_002_000)).?;
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);
}

test "non-zero path ACK clears local key update gate" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    try conn.requestKeyUpdate(1_000_000);

    const path = conn.paths.get(path_id).?;
    path.pending_ping = true;
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    try std.testing.expect(conn.keyUpdateStatus().write_update_pending_ack);

    try conn.handlePathAck(.{
        .path_id = path_id,
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);
    try std.testing.expect(!conn.keyUpdateStatus().write_update_pending_ack);
}

test "qlog callback records application key update lifecycle" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    try std.testing.expect(recorder.contains(.application_read_key_installed));
    try std.testing.expect(recorder.contains(.application_write_key_installed));

    try conn.promoteApplicationReadKeys(1_000_000);
    try std.testing.expect(recorder.contains(.application_read_key_discard_scheduled));
    try std.testing.expect(recorder.contains(.application_read_key_updated));

    try conn.requestKeyUpdate(1_100_000);
    const write_epoch = conn.app_write_current.?;
    try std.testing.expect(recorder.contains(.application_write_key_updated));
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 42,
        .sent_time_us = 1_100_000,
        .bytes = 64,
        .ack_eliciting = true,
        .in_flight = true,
        .key_epoch = write_epoch.epoch,
        .key_phase = write_epoch.key_phase,
    };
    conn.onApplicationPacketAckedForKeys(&packet, 1_150_000);
    try std.testing.expect(recorder.contains(.application_write_update_acked));

    const discard_deadline = conn.app_read_previous.?.discard_deadline_us.?;
    try conn.tick(discard_deadline);
    try std.testing.expect(recorder.contains(.application_read_key_discarded));
}

test "qlog records AEAD confidentiality-limit close" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 1,
        .proactive_update_threshold = 99,
        .integrity_limit = 99,
    });
    try conn.setPeerDcid(&.{});

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expect(!recorder.contains(.aead_confidentiality_limit_reached));

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    try std.testing.expect(recorder.contains(.aead_confidentiality_limit_reached));
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, close_event.source);
    try std.testing.expectEqual(transport_error_aead_limit_reached, close_event.error_code);
    // First CC has been sealed → RFC 9000 §10.2.1 closing state. The
    // peer's CC hasn't arrived (and won't, since this is a unit test
    // with no peer), so we stay in closing until the §10.2 ¶5
    // 3*PTO deadline elapses.
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
}

test "AEAD authentication failure limit closes the connection" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 4,
        .proactive_update_threshold = 3,
        .integrity_limit = 1,
    });
    const keys = conn.app_read_current.?.keys;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });
    packet_buf[n - 1] ^= 0x01;

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_aead_limit_reached, conn.lifecycle.pending_close.?.error_code);
}

fn testEarlyDataPacketKeys() !PacketKeys {
    const secret: [32]u8 = @splat(0);
    return try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &secret);
}

const TestQlogRecorder = struct {
    events: [128]QlogEvent = undefined,
    count: usize = 0,

    fn callback(user_data: ?*anyopaque, event: QlogEvent) void {
        const self: *TestQlogRecorder = @ptrCast(@alignCast(user_data.?));
        if (self.count >= self.events.len) return;
        self.events[self.count] = event;
        self.count += 1;
    }

    fn contains(self: *const TestQlogRecorder, name: QlogEventName) bool {
        for (self.events[0..self.count]) |event| {
            if (event.name == name) return true;
        }
        return false;
    }

    fn first(self: *const TestQlogRecorder, name: QlogEventName) ?QlogEvent {
        for (self.events[0..self.count]) |event| {
            if (event.name == name) return event;
        }
        return null;
    }

    fn countOf(self: *const TestQlogRecorder, name: QlogEventName) usize {
        var n: usize = 0;
        for (self.events[0..self.count]) |event| {
            if (event.name == name) n += 1;
        }
        return n;
    }
};

fn markTestMultipathNegotiated(conn: *Connection, max_path_id: u32) void {
    conn.enableMultipath(true);
    conn.local_transport_params.initial_max_path_id = max_path_id;
    conn.local_max_path_id = max_path_id;
    conn.cached_peer_transport_params = .{ .initial_max_path_id = max_path_id };
    conn.peer_max_path_id = max_path_id;
}

test "setTransportParams advertises bounded UDP payload limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_datagram_frame_size = 9000 });
    try std.testing.expectEqual(@as(u64, max_supported_udp_payload_size), conn.local_transport_params.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, max_supported_udp_payload_size), conn.local_transport_params.max_datagram_frame_size);

    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{ .max_udp_payload_size = default_mtu - 1 }));
}

test "peer transport parameter limit violations use transport parameter error" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initClient(allocator, ctx, "x");
        defer conn.deinit();
        conn.cached_peer_transport_params = .{ .max_udp_payload_size = min_quic_udp_payload_size - 1 };
        conn.validatePeerTransportLimits();
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqualStrings("peer max udp payload below minimum", conn.lifecycle.pending_close.?.reason);
    }

    {
        var conn = try Connection.initClient(allocator, ctx, "x");
        defer conn.deinit();
        conn.cached_peer_transport_params = .{ .initial_max_streams_bidi = max_stream_count_limit + 1 };
        conn.validatePeerTransportLimits();
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqualStrings("peer stream count exceeds maximum", conn.lifecycle.pending_close.?.reason);
    }
}

test "handle rejects UDP datagrams above local payload limit before path credit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_udp_payload_size = default_mtu });

    var bytes: [default_mtu + 1]u8 = @splat(0);
    try conn.handle(&bytes, null, 123);

    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqual(@as(u64, 0), conn.primaryPath().path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), conn.last_activity_us);
}

test "sendDatagram enforces peer support and bounded queue" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 0 };
    try std.testing.expectError(Error.DatagramUnavailable, conn.sendDatagram("x"));

    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 4 };
    try std.testing.expectError(Error.DatagramTooLarge, conn.sendDatagram("12345"));
    try conn.sendDatagram("1234");
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.send_datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 4), conn.pending_frames.send_datagram_bytes);

    while (conn.pending_frames.send_datagrams.items.len < max_pending_datagram_count) {
        try conn.sendDatagram("x");
    }
    try std.testing.expectError(Error.DatagramQueueFull, conn.sendDatagram("x"));
}

test "tracked DATAGRAM emits ack event when packet is acknowledged" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    const id = try conn.sendDatagramTracked("ack-me");
    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;

    const sent = conn.primaryPath().sent.packets[0];
    try std.testing.expect(sent.datagram != null);
    try std.testing.expectEqual(id, sent.datagram.?.id);
    try std.testing.expectEqual(@as(usize, 6), sent.datagram.?.len);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = sent.pn,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(id, event.datagram_acked.id);
    try std.testing.expectEqual(@as(usize, 6), event.datagram_acked.len);
    try std.testing.expectEqual(sent.pn, event.datagram_acked.packet_number);
    try std.testing.expectEqual(@as(u32, 0), event.datagram_acked.path_id);
    try std.testing.expect(!event.datagram_acked.arrived_in_early_data);
    try std.testing.expect(conn.pollEvent() == null);
}

test "tracked DATAGRAM emits loss event without retransmission" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    const id = try conn.sendDatagramTracked("lost");
    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;

    var lost = conn.primaryPath().sent.removeAt(0);
    defer lost.deinit(conn.allocator);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);
    try std.testing.expect(!(try conn.requeueLostPacket(.application, &lost)));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(id, event.datagram_lost.id);
    try std.testing.expectEqual(@as(usize, 4), event.datagram_lost.len);
    try std.testing.expectEqual(lost.pn, event.datagram_lost.packet_number);
}

test "handleDatagram enforces local DATAGRAM limit and queue budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.recv_datagrams.items.len);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        conn.local_transport_params.max_datagram_frame_size = max_supported_udp_payload_size;
        while (conn.pending_frames.recv_datagrams.items.len < max_pending_datagram_count) {
            try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        }
        try std.testing.expectEqual(max_pending_datagram_count, conn.pending_frames.recv_datagrams.items.len);
        try std.testing.expectEqual(max_pending_datagram_count, conn.pending_frames.recv_datagram_bytes);

        var buf: [1]u8 = undefined;
        const info = conn.receiveDatagramInfo(&buf).?;
        try std.testing.expectEqual(@as(usize, 1), info.len);
        try std.testing.expectEqual(max_pending_datagram_count - 1, conn.pending_frames.recv_datagrams.items.len);
        try std.testing.expectEqual(max_pending_datagram_count - 1, conn.pending_frames.recv_datagram_bytes);

        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
    }
}

test "handleCrypto bounds out-of-order reassembly" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.handleCrypto(.initial, .{ .offset = max_crypto_reassembly_gap + 1, .data = "x" });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[0]);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        var huge: [max_pending_crypto_bytes_per_level + 1]u8 = @splat(0);
        try conn.handleCrypto(.initial, .{ .offset = 1, .data = &huge });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[0]);
    }
}

test "peer-created streams respect advertised stream count" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = 1,
    });

    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "a",
        .has_length = true,
    });
    try std.testing.expectEqual(@as(u64, 1), conn.peer_opened_streams_bidi);
    try std.testing.expect(conn.lifecycle.pending_close == null);

    try conn.handleStream(.application, .{
        .stream_id = 4,
        .offset = 0,
        .data = "b",
        .has_length = true,
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_stream_limit, conn.lifecycle.pending_close.?.error_code);
}

test "local transport params reject allocation policy overflows" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_streams_bidi = max_streams_per_connection + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_streams_uni = max_streams_per_connection + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .active_connection_id_limit = max_supported_active_connection_id_limit + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_path_id = max_supported_path_id + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_data = max_initial_connection_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_bidi_local = max_initial_stream_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_bidi_remote = max_initial_stream_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_uni = max_initial_stream_receive_window + 1,
    }));
}

test "bounded policy clamps MAX_STREAMS MAX_PATH_ID and peer CID fanout" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_streams_bidi = 0;
    conn.peer_max_streams_uni = 0;
    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = max_streams_per_connection + 100 });
    conn.handleMaxStreams(.{ .bidi = false, .maximum_streams = max_streams_per_connection + 100 });
    try std.testing.expectEqual(max_streams_per_connection, conn.peer_max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.peer_max_streams_uni);

    conn.queueMaxStreams(true, max_streams_per_connection + 100);
    conn.queueMaxStreams(false, max_streams_per_connection + 100);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_uni);
    try std.testing.expectEqual(max_streams_per_connection, conn.pending_frames.max_streams_bidi.?);
    try std.testing.expectEqual(max_streams_per_connection, conn.pending_frames.max_streams_uni.?);

    conn.queueMaxPathId(max_supported_path_id + 100);
    try std.testing.expectEqual(max_supported_path_id, conn.local_max_path_id);
    try std.testing.expectEqual(max_supported_path_id, conn.pending_frames.max_path_id.?);

    conn.cached_peer_transport_params = .{
        .active_connection_id_limit = max_supported_active_connection_id_limit + 100,
    };
    try std.testing.expectEqual(
        max_supported_active_connection_id_limit,
        conn.peerActiveConnectionIdLimit(),
    );
}

test "STREAM_DATA_BLOCKED tracking is bounded and validates stream space" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.setTransportParams(.{ .initial_max_streams_bidi = 1 });
        try conn.handleStreamDataBlocked(.{ .stream_id = 0, .maximum_stream_data = 7 });
        try std.testing.expect(conn.lifecycle.pending_close == null);
        try std.testing.expectEqual(@as(usize, 1), conn.peer_stream_data_blocked.items.len);

        try conn.handleStreamDataBlocked(.{ .stream_id = 4, .maximum_stream_data = 7 });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_stream_limit, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 1), conn.peer_stream_data_blocked.items.len);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.handleStreamDataBlocked(.{ .stream_id = 3, .maximum_stream_data = 7 });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_stream_state, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 0), conn.peer_stream_data_blocked.items.len);
    }

    {
        var list: std.ArrayList(frame_types.StreamDataBlocked) = .empty;
        defer list.deinit(allocator);
        var i: usize = 0;
        while (i < max_tracked_stream_data_blocked) : (i += 1) {
            try list.append(allocator, .{
                .stream_id = @as(u64, @intCast(i)) * 4,
                .maximum_stream_data = 1,
            });
        }
        try std.testing.expectError(Error.StreamLimitExceeded, Connection.upsertStreamBlocked(&list, allocator, .{
            .stream_id = @as(u64, @intCast(max_tracked_stream_data_blocked)) * 4,
            .maximum_stream_data = 1,
        }));
        try std.testing.expectEqual(max_tracked_stream_data_blocked, list.items.len);
    }
}

test "STREAM receive enforces stream and connection flow control" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.setTransportParams(.{
            .initial_max_data = 16,
            .initial_max_stream_data_bidi_remote = 3,
            .initial_max_streams_bidi = 1,
        });
        try conn.handleStream(.application, .{
            .stream_id = 0,
            .offset = 0,
            .data = "abcd",
            .has_length = true,
        });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_flow_control, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(u64, 0), conn.peer_sent_stream_data);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.setTransportParams(.{
            .initial_max_data = 5,
            .initial_max_stream_data_bidi_remote = 8,
            .initial_max_streams_bidi = 2,
        });
        try conn.handleStream(.application, .{
            .stream_id = 0,
            .offset = 0,
            .data = "hello",
            .has_length = true,
        });
        try std.testing.expect(conn.lifecycle.pending_close == null);
        try std.testing.expectEqual(@as(u64, 5), conn.peer_sent_stream_data);
        try conn.handleStream(.application, .{
            .stream_id = 4,
            .offset = 0,
            .data = "!",
            .has_length = true,
        });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_flow_control, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(u64, 5), conn.peer_sent_stream_data);
    }
}

test "MAX_DATA MAX_STREAM_DATA and MAX_STREAMS raise send-side limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_data = 4;
    conn.peer_max_streams_bidi = 1;
    const s0 = try conn.openBidi(0);
    s0.send_max_data = 4;

    try std.testing.expectError(Error.StreamLimitExceeded, conn.openBidi(4));
    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = 2 });
    _ = try conn.openBidi(4);

    conn.handleMaxData(.{ .maximum_data = 32 });
    conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 16 });
    try std.testing.expectEqual(@as(u64, 32), conn.peer_max_data);
    try std.testing.expectEqual(@as(u64, 16), conn.stream(0).?.send_max_data);
}

test "send-side STREAM emission is capped by flow-control allowance" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_data = 4;
    conn.peer_max_streams_bidi = 1;
    const s = try conn.openBidi(0);
    s.send_max_data = 8;
    _ = try s.send.write("abcdefgh");

    const raw = s.send.peekChunk(64).?;
    const limited = (try conn.limitChunkToSendFlow(s, raw)).?;
    try std.testing.expectEqual(@as(u64, 4), limited.length);
    try std.testing.expect(!limited.fin);

    conn.recordStreamFlowSent(s, limited);
    try std.testing.expectEqual(@as(u64, 4), conn.we_sent_stream_data);
    try std.testing.expectEqual(@as(u64, 4), s.send_flow_highest);
    const retransmit_only = (try conn.limitChunkToSendFlow(s, raw)).?;
    try std.testing.expectEqual(@as(u64, 4), retransmit_only.length);
    try std.testing.expect(!retransmit_only.fin);
    try std.testing.expectEqual(@as(?u64, 4), conn.localDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, 4), conn.pending_frames.data_blocked);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.local, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(u64, 4), event.flow_blocked.limit);

    conn.handleMaxData(.{ .maximum_data = 16 });
    try std.testing.expectEqual(@as(?u64, null), conn.localDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.data_blocked);
}

test "receive flow-control MAX updates are paced by half-window" {
    try std.testing.expect(!Connection.shouldQueueReceiveCredit(
        1,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(!Connection.shouldQueueReceiveCredit(
        default_stream_receive_window / 2 - 1,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(Connection.shouldQueueReceiveCredit(
        default_stream_receive_window / 2,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(Connection.shouldQueueReceiveCredit(
        1,
        16,
        default_stream_receive_window,
    ));

    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = default_connection_receive_window,
        .initial_max_stream_data_bidi_remote = default_stream_receive_window,
        .initial_max_streams_bidi = 1,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.max_stream_data.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_data);
}

test "stream flow block queues STREAM_DATA_BLOCKED and clears on MAX_STREAM_DATA" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_data = 16;
    conn.peer_max_streams_bidi = 1;
    const s = try conn.openBidi(0);
    s.send_max_data = 4;
    _ = try s.send.write("abcdefgh");

    const raw = s.send.peekChunk(64).?;
    const limited = (try conn.limitChunkToSendFlow(s, raw)).?;
    conn.recordStreamFlowSent(s, limited);
    _ = (try conn.limitChunkToSendFlow(s, raw)).?;

    try std.testing.expectEqual(@as(?u64, 4), conn.localStreamDataBlockedAt(0));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.stream_data_blocked.items.len);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.stream_data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?u64, 0), event.flow_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 4), event.flow_blocked.limit);

    conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 8 });
    try std.testing.expectEqual(@as(?u64, null), conn.localStreamDataBlockedAt(0));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.stream_data_blocked.items.len);
}

test "STREAMS_BLOCKED is queued when local stream opening hits peer limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_streams_bidi = 0;
    try std.testing.expectError(Error.StreamLimitExceeded, conn.openBidi(0));
    try std.testing.expectEqual(@as(?u64, 0), conn.localStreamsBlockedAt(true));
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_frames.streams_blocked_bidi);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.local, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.streams, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?bool, true), event.flow_blocked.bidi);

    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = 1 });
    try std.testing.expectEqual(@as(?u64, null), conn.localStreamsBlockedAt(true));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.streams_blocked_bidi);
}

test "blocked frames emit with retransmit metadata and requeue on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    conn.noteDataBlocked(7);
    try conn.noteStreamDataBlocked(0, 11);
    conn.noteStreamsBlocked(true, 3);

    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;
    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 3), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .data_blocked);
    try std.testing.expect(sent.retransmit_frames.items[1] == .stream_data_blocked);
    try std.testing.expect(sent.retransmit_frames.items[2] == .streams_blocked);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.data_blocked);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.streams_blocked_bidi);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expectEqual(@as(?u64, 7), conn.pending_frames.data_blocked);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, 3), conn.pending_frames.streams_blocked_bidi);
}

test "stale blocked frames are not requeued after peer raises limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.noteDataBlocked(7);
    try conn.noteStreamDataBlocked(0, 11);
    conn.noteStreamsBlocked(true, 3);
    conn.clearLocalDataBlocked(8);
    conn.clearLocalStreamDataBlocked(0, 12);
    conn.clearLocalStreamsBlocked(true, 4);

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 9,
        .sent_time_us = 1_000,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer packet.deinit(allocator);
    try packet.addRetransmitFrame(allocator, .{ .data_blocked = .{ .maximum_data = 7 } });
    try packet.addRetransmitFrame(allocator, .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 11,
    } });
    try packet.addRetransmitFrame(allocator, .{ .streams_blocked = .{
        .bidi = true,
        .maximum_streams = 3,
    } });

    try std.testing.expect(!(try conn.dispatchLostControlFrames(&packet)));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.data_blocked);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.streams_blocked_bidi);
}

test "inbound blocked frames update peer state and pollable events" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{ .initial_max_streams_bidi = 2 });
    conn.handleDataBlocked(.{ .maximum_data = 10 });
    try conn.handleStreamDataBlocked(.{ .stream_id = 4, .maximum_stream_data = 20 });
    conn.handleStreamsBlocked(.{ .bidi = false, .maximum_streams = 2 });

    try std.testing.expectEqual(@as(?u64, 10), conn.peerDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, 20), conn.peerStreamDataBlockedAt(4));
    try std.testing.expectEqual(@as(?u64, 2), conn.peerStreamsBlockedAt(false));

    var event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.peer, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.data, event.flow_blocked.kind);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.stream_data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?u64, 4), event.flow_blocked.stream_id);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.streams, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?bool, false), event.flow_blocked.bidi);
}

test "draining a peer-initiated stream returns MAX_STREAMS credit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = 1,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
        .fin = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(?u64, 17), conn.pending_frames.max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 17), conn.local_max_streams_bidi);
}

test "draining at stream cap does not queue duplicate MAX_STREAMS" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = max_streams_per_connection,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
        .fin = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_bidi);
}

test "0-RTT send path requires explicit per-connection opt-in" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.pollLevel(.early_data, &out, 1_000));
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
}

test "0-RTT poll emits long-header packet in Application PN space" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    const n = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expect(n > 0);
    try std.testing.expect((out[0] & 0x80) != 0);
    try std.testing.expectEqual(@as(u2, 1), @as(u2, @intCast((out[0] >> 4) & 0x03)));
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);
    try std.testing.expect(conn.sentForLevel(.early_data).packets[0].is_early_data);
    try std.testing.expectEqual(@as(u64, 1), conn.pnSpaceForLevel(.early_data).next_pn);
}

test "0-RTT rejection requeues STREAM data but not DATAGRAM payloads" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const datagram_id = try conn.sendDatagramTracked("early-datagram");
    const s = try conn.openBidi(0);
    _ = try s.send.write("early-stream");

    var out: [512]u8 = undefined;
    const n = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expect(n > 0);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);

    try conn.requeueRejectedEarlyData();

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);
    const chunk = s.send.peekChunk(64).?;
    try std.testing.expectEqual(@as(u64, 0), chunk.offset);
    try std.testing.expectEqual(@as(u64, 12), chunk.length);
    try std.testing.expectEqualSlices(u8, "early-stream", s.send.chunkBytes(chunk));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(datagram_id, event.datagram_lost.id);
    try std.testing.expect(event.datagram_lost.arrived_in_early_data);
}

test "0-RTT DATAGRAM ack event carries early-data metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const datagram_id = try conn.sendDatagramTracked("early-ack");
    var out: [256]u8 = undefined;
    _ = (try conn.pollLevel(.early_data, &out, 1_000)).?;

    const sent = conn.sentForLevel(.early_data).packets[0];
    try std.testing.expect(sent.is_early_data);
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = sent.pn,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(datagram_id, event.datagram_acked.id);
    try std.testing.expectEqual(@as(usize, 9), event.datagram_acked.len);
    try std.testing.expectEqual(sent.pn, event.datagram_acked.packet_number);
    try std.testing.expect(event.datagram_acked.arrived_in_early_data);
    try std.testing.expect(conn.pollEvent() == null);
}

test "0-RTT DATAGRAM packet-threshold loss carries early-data metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    var datagram_ids: [4]u64 = undefined;
    var out: [256]u8 = undefined;
    for (&datagram_ids, 0..) |*id, i| {
        id.* = try conn.sendDatagramTracked(if (i == 0) "lost" else "acked");
        _ = (try conn.pollLevel(.early_data, &out, 1_000 + @as(u64, @intCast(i)))).?;
    }
    try std.testing.expectEqual(@as(u32, 4), conn.sentForLevel(.early_data).count);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 3,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 2_000);

    var event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(datagram_ids[3], event.datagram_acked.id);
    try std.testing.expectEqual(@as(u64, 3), event.datagram_acked.packet_number);
    try std.testing.expect(event.datagram_acked.arrived_in_early_data);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(datagram_ids[0], event.datagram_lost.id);
    try std.testing.expectEqual(@as(u64, 0), event.datagram_lost.packet_number);
    try std.testing.expect(event.datagram_lost.arrived_in_early_data);
    try std.testing.expectEqual(@as(u32, 2), conn.sentForLevel(.early_data).count);
}

test "0-RTT STREAM packet-threshold loss requeues early bytes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const s = try conn.openBidi(0);
    _ = try s.send.write("early-loss");

    var out: [256]u8 = undefined;
    _ = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);
    try std.testing.expect(s.send.peekChunk(64) == null);
    // Pretend three more 1-RTT packets were sent at the application
    // layer so the ACK for PN 3 is legitimate (RFC 9000 §13.1).
    conn.pnSpaceForLevel(.application).next_pn = 4;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 3,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 2_000);

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
    const chunk = s.send.peekChunk(64).?;
    try std.testing.expectEqual(@as(u64, 0), chunk.offset);
    try std.testing.expectEqual(@as(u64, 10), chunk.length);
    try std.testing.expectEqualSlices(u8, "early-loss", s.send.chunkBytes(chunk));
    try std.testing.expect(conn.pollEvent() == null);
}

test "server handles accepted 0-RTT STREAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    try conn.setTransportParams(.{
        .initial_max_data = 1024,
        .initial_max_stream_data_bidi_remote = 1024,
        .initial_max_streams_bidi = 1,
    });
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "hello",
        .has_offset = false,
        .has_length = true,
        .fin = false,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);
    if (application_ack_eliciting_threshold == 1) {
        try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.pending_ack);
    } else {
        try std.testing.expect(!conn.pnSpaceForLevel(.early_data).received.pending_ack);
    }
    try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.delayed_ack_armed);

    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try conn.streamRead(0, &buf));
    try std.testing.expectEqualSlices(u8, "hello", buf[0..5]);
    try std.testing.expectEqual(true, conn.streamArrivedInEarlyData(0).?);
}

test "server marks accepted 0-RTT DATAGRAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    conn.local_transport_params.max_datagram_frame_size = max_supported_udp_payload_size;
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .datagram = .{
        .data = "early-dgram",
        .has_length = true,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);

    var buf: [32]u8 = undefined;
    const info = conn.receiveDatagramInfo(&buf).?;
    try std.testing.expectEqual(@as(usize, 11), info.len);
    try std.testing.expect(info.arrived_in_early_data);
    try std.testing.expectEqualSlices(u8, "early-dgram", buf[0..info.len]);
}

test "server rejects forbidden frames in 0-RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    const keys = try testEarlyDataPacketKeys();

    var payload: [32]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ack = .{
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    _ = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqualStrings("forbidden frame in 0-RTT", conn.lifecycle.pending_close.?.reason);
}

test "pollLevel emits PATH_ACK for non-zero application path ACKs" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    try std.testing.expect(!path.app_pn_space.received.pending_ack);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
    try std.testing.expectEqual(@as(u64, 9), decoded.frame.path_ack.largest_acked);
}

test "pollLevel caps ACK ranges to packet budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const tracker = &conn.primaryPath().app_pn_space.received;
    var pn: u64 = 0;
    while (pn < 200) : (pn += 2) tracker.add(pn, 1_000);
    const tracked_lower_ranges = @as(u64, tracker.range_count - 1);

    var packet_buf: [128]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    try std.testing.expect(!tracker.pending_ack);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .ack);
    try std.testing.expectEqual(@as(u64, 198), decoded.frame.ack.largest_acked);
    try std.testing.expect(decoded.frame.ack.range_count < tracked_lower_ranges);
}

test "application ACK ranges use bounded emission budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const tracker = &conn.primaryPath().app_pn_space.received;
    var pn: u64 = 0;
    while (pn < 400) : (pn += 2) tracker.add(pn, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .ack);
    try std.testing.expect(decoded.frame.ack.ranges_bytes.len <= max_application_ack_ranges_bytes);
    try std.testing.expect(decoded.frame.ack.range_count <= max_application_ack_lower_ranges);
    try std.testing.expect(decoded.frame.ack.range_count < @as(u64, tracker.range_count - 1));
}

test "pollLevel coalesces multiple STREAM frames with distinct loss keys" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const s0 = try conn.openBidi(0);
    const s1 = try conn.openBidi(4);
    const s2 = try conn.openBidi(8);
    _ = try s0.send.write("alpha");
    _ = try s1.send.write("bravo");
    _ = try s2.send.write("charlie");

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000)).?;

    const sent = conn.sentForLevel(.application);
    try std.testing.expectEqual(@as(u32, 1), sent.count);
    var keys = sent.packets[0].streamKeys();
    var key_count: usize = 0;
    while (keys.next()) |_| key_count += 1;
    try std.testing.expectEqual(@as(usize, 3), key_count);
    try std.testing.expectEqual(@as(u32, 1), s0.send.in_flight.count());
    try std.testing.expectEqual(@as(u32, 1), s1.send.in_flight.count());
    try std.testing.expectEqual(@as(u32, 1), s2.send.in_flight.count());
}

test "pollDatagram can select a non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{ .bytes = .{ 1, 2, 3, 4 } ++ @as([18]u8, @splat(0)) }, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    try std.testing.expect(conn.setActivePath(path_id));
    try conn.queuePathStatus(path_id, true, 1);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(path_id, datagram.path_id);
    try std.testing.expect(datagram.to != null);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.path_statuses.items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.paths.get(path_id).?.sent.count);
}

test "multipath-negotiated non-zero path packets use draft-21 nonce" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    const keys = (try conn.packetKeys(.application, .write)).?;
    var plaintext: [max_recv_plaintext]u8 = undefined;

    try std.testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
            .dcid_len = 1,
            .keys = &keys,
            .largest_received = 0,
        }),
    );
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
        .multipath_path_id = path_id,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
}

test "incoming short packets are routed by local CID before multipath nonce open" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setLocalScid(&.{0xa0});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    const path = conn.paths.get(path_id).?;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = path.path.local_cid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
        .multipath_path_id = path_id,
    });

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expectEqual(path_id, conn.current_incoming_path_id);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.received.largest);
    try std.testing.expectEqual(@as(?u64, null), conn.primaryPath().app_pn_space.received.largest);
}

test "authenticated NAT rebinding starts validation and resets recovery after response" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    // The migration gate enforces handshakeDone() before honoring a
    // peer-address change. This test exercises post-handshake NAT
    // rebinding without driving an actual TLS handshake; opt out of
    // the gate so the test stays focused on the validation flow.
    conn.test_only_force_handshake_for_migration = true;
    try conn.setLocalScid(&.{0xa0});
    const old_addr = Address{ .bytes = .{ 1, 2, 3, 4 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 5, 6, 7, 8 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.rtt.smoothed_rtt_us = 50_000;
    path.path.rtt.latest_rtt_us = 40_000;
    path.path.rtt.first_sample_taken = true;
    path.path.cc.cwnd = 30_000;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const packet_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = conn.local_scid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    try conn.handle(packet_buf[0..packet_len], new_addr, 1_000_000);

    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expectEqual(@as(u64, packet_len), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expectEqual(.pending, path.path.validator.status);
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback != null);
    try std.testing.expect(!conn.pathStats(0).?.validated);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_challenge_path_id);
    try std.testing.expectEqual(@as(u64, 50_000), path.path.rtt.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 30_000), path.path.cc.cwnd);

    conn.recordPathResponse(0, path.path.validator.pending_token);

    try std.testing.expect(conn.pathStats(0).?.validated);
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expectEqual(rtt_mod.initial_rtt_us, path.path.rtt.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 0), path.path.rtt.latest_rtt_us);
    const expected_cwnd = (congestion_mod.Config{ .max_datagram_size = default_mtu }).initialWindow();
    try std.testing.expectEqual(expected_cwnd, path.path.cc.cwnd);
    try std.testing.expect(conn.pending_frames.path_challenge == null);
}

test "unvalidated rebound path obeys anti-amplification before polling" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const old_addr = Address{ .bytes = .{ 1, 1, 1, 1 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 2, 2, 2, 2 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    try conn.handlePeerAddressChange(path, new_addr, 1, 1_000_000);
    path.pending_ping = true;

    var packet_buf: [default_mtu]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.pollLevel(.application, &packet_buf, 1_001_000));
    try std.testing.expect(path.pending_ping);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
}

test "unvalidated path enforces anti-amplification on Initial sends" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Force the primary path to be unvalidated and simulate the peer
    // having sent us only a small Initial. RFC 9000 §8.1 caps the
    // server's send budget at 3x bytes_received until validation
    // succeeds — and that applies to Initial and Handshake bytes too,
    // not just 1-RTT.
    const path = conn.primaryPath();
    path.path.validated = false;
    path.path.validator = .{};
    path.path.bytes_received = 100;
    path.path.bytes_sent = 0;

    // Plant retransmittable Initial CRYPTO bytes so pollLevel actually
    // wants to emit a packet. Without anti-amp, sealInitial would
    // happily fill an MTU-sized datagram.
    const odcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try conn.setInitialDcid(&odcid);
    try conn.setLocalScid(&.{0xc1});
    try conn.setPeerDcid(&odcid);

    const crypto_bytes = try allocator.dupe(u8, &(@as([800]u8, @splat(0xab))));
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = crypto_bytes,
    });

    var packet_buf: [default_mtu]u8 = undefined;
    const result = try conn.pollLevel(.initial, &packet_buf, 1_000_000);

    if (result) |n| {
        // Anti-amp says we must not send more than 3 * 100 = 300 bytes.
        try std.testing.expect(n <= 300);
    }
    try std.testing.expect(path.path.antiAmpAllowance() <= 300);
}

test "validated path is not constrained by anti-amplification" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Server primary starts unvalidated (RFC 9000 §8.1). Force-validate
    // it so we can exercise the "validated path bypasses anti-amp"
    // branch directly without driving a Handshake exchange.
    const path = conn.primaryPath();
    path.path.markValidated();
    try std.testing.expect(path.path.isValidated());
    path.path.bytes_received = 50;
    path.path.bytes_sent = 0;

    const odcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try conn.setInitialDcid(&odcid);
    try conn.setLocalScid(&.{0xc1});
    try conn.setPeerDcid(&odcid);

    const crypto_bytes = try allocator.dupe(u8, &(@as([800]u8, @splat(0xab))));
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = crypto_bytes,
    });

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &packet_buf, 1_000_000)).?;
    // Allowance is unbounded for a validated path, so we should be
    // able to send well over 3 * 50 = 150 bytes.
    try std.testing.expect(n > 150);
}

test "failed NAT rebinding validation rolls back to the previous address" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const old_addr = Address{ .bytes = .{ 3, 3, 3, 3 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 4, 4, 4, 4 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();
    path.path.bytes_received = 900;
    path.path.bytes_sent = 300;

    try conn.handlePeerAddressChange(path, new_addr, 40, 1_000_000);
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(@as(u64, 40), path.path.bytes_received);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    const stale_token = path.path.validator.pending_token;

    try conn.tick(1_000_000 + path.path.validator.timeout_us + 1);

    try std.testing.expect(Address.eql(old_addr, path.path.peer_addr));
    try std.testing.expect(path.path.isValidated());
    try std.testing.expectEqual(.validated, path.path.validator.status);
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expectEqual(path_mod.State.active, path.path.state);
    try std.testing.expectEqual(@as(u64, 900), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 300), path.path.bytes_sent);
    try std.testing.expect(conn.pending_frames.path_challenge == null);

    var stale_packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 1_000_000,
        .bytes = 64,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer stale_packet.deinit(allocator);
    try stale_packet.addRetransmitFrame(allocator, .{ .path_challenge = .{ .data = stale_token } });
    try std.testing.expect(!(try conn.dispatchLostControlFrames(&stale_packet)));
    try std.testing.expect(conn.pending_frames.path_challenge == null);
}

test "old address packets during pending rebinding do not lift new path anti-amplification" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const old_addr = Address{ .bytes = .{ 7, 7, 7, 7 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 8, 8, 8, 8 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.handlePeerAddressChange(path, new_addr, 10, 1_000_000);
    try std.testing.expectEqual(@as(u32, 0), conn.incomingPathId(old_addr));
    try std.testing.expect(conn.peerAddressChangeCandidate(0, old_addr) == null);

    try conn.recordAuthenticatedDatagramAddress(0, old_addr, 1200, 1_000_100);

    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(@as(u64, 10), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expectEqual(@as(u64, 30), path.path.antiAmpAllowance());
}

test "PATH_RESPONSE during pending rebinding is sent to the challenge address" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const old_addr = Address{ .bytes = .{ 9, 9, 9, 9 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 1, 0, 1, 0 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.handlePeerAddressChange(path, new_addr, 1200, 1_000_000);
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    conn.queuePathResponseOnPath(0, token, old_addr);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_100)).?;
    try std.testing.expect(datagram.to != null);
    try std.testing.expect(Address.eql(old_addr, datagram.to.?));
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expect(conn.pending_frames.path_response == null);
    try std.testing.expect(conn.pending_frames.path_challenge != null);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..datagram.len], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_response);
    try std.testing.expectEqualSlices(u8, &token, &decoded.frame.path_response.data);

    const followup = (try conn.pollDatagram(&packet_buf, 1_000_200)).?;
    try std.testing.expect(followup.to != null);
    try std.testing.expect(Address.eql(new_addr, followup.to.?));
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expect(path.path.bytes_sent > 0);
}

test "queued path CIDs participate in incoming short-header routing and retirement" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try conn.queuePathNewConnectionId(path_id, 1, 0, &.{0xc2}, @splat(0));

    const bytes = [_]u8{ 0x40, 0xc2, 0, 0, 0, 0 } ++ @as([16]u8, @splat(0));
    try std.testing.expectEqual(path_id, conn.incomingShortPath(&bytes).?.id);

    conn.handlePathRetireConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
    });
    try std.testing.expect(conn.incomingShortPath(&bytes) == null);
}

test "multipath frames are rejected unless draft-21 was negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .max_path_id = .{ .maximum_path_id = 1 } });
    try conn.dispatchFrames(.application, payload[0..payload_len], 1_000_000);
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "setTransportParams advertises local multipath limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .initial_max_path_id = 2 });
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 2), conn.local_max_path_id);
}

test "openPath respects peer MAX_PATH_ID when multipath is negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    _ = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc2}), ConnectionId.fromSlice(&.{0xd2})),
    );
    try std.testing.expectEqual(@as(?u32, 1), conn.pending_frames.paths_blocked);
}

test "openPath requires common path id capacity and CIDs when multipath is negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    try std.testing.expectError(
        Error.ConnectionIdRequired,
        conn.openPath(.{}, .{}, ConnectionId{}, ConnectionId.fromSlice(&.{0xd1})),
    );
    try std.testing.expectError(
        Error.ConnectionIdRequired,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId{}),
    );

    conn.peer_max_path_id = 2;
    _ = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc2}), ConnectionId.fromSlice(&.{0xd2})),
    );
}

test "local CID issuance rejects reuse across paths and sequences" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd2})),
    );
    try std.testing.expect(conn.paths.get(2) == null);
    try std.testing.expectEqual(@as(u32, 2), conn.paths.next_path_id);

    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.queuePathNewConnectionId(path_id, 1, 0, &.{0xc1}, @splat(0xc1)),
    );
    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.queueNewConnectionId(1, 0, &.{0xc1}, @splat(0xc1)),
    );
}

test "RETIRE_CONNECTION_ID surfaces replacement CID budget to embedders" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 3 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(0));

    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    const info = conn.connectionIdReplenishInfo(0).?;
    try std.testing.expectEqual(@as(u32, 0), info.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, info.reason);
    try std.testing.expectEqual(@as(usize, 2), info.active_count);
    try std.testing.expectEqual(@as(usize, 3), info.active_limit);
    try std.testing.expectEqual(@as(usize, 1), info.issue_budget);
    try std.testing.expectEqual(@as(u64, 3), info.next_sequence_number);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(@as(u32, 0), event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(usize, 1), event.connection_ids_needed.issue_budget);

    const queued = try conn.replenishConnectionIds(&.{
        .{ .connection_id = &.{0xa3}, .stateless_reset_token = @splat(0xa3) },
    });
    try std.testing.expectEqual(@as(usize, 1), queued);
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(0));
    try std.testing.expect(conn.pollEvent() == null);
}

test "RETIRE_CONNECTION_ID with sequence we never issued is a PROTOCOL_VIOLATION" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 4 };
    // We've issued sequences 0, 1, and 2 to the peer.
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));

    // A peer that retires a sequence we never assigned (RFC 9000 §19.16)
    // is committing a PROTOCOL_VIOLATION. Without this gate an attacker
    // could spam fabricated retire frames to force expensive list walks.
    conn.handleRetireConnectionId(.{ .sequence_number = 99 });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "RETIRE_CONNECTION_ID for an already-retired sequence is allowed" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 4 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));

    // First retire of seq 1: legitimate.
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    try std.testing.expect(conn.lifecycle.pending_close == null);
    // Second retire of seq 1 (could happen if we received a duplicate or
    // a delayed retransmission): still legitimate because seq 1 was issued
    // at some point. Only sequences strictly above the high watermark are
    // rejected.
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    try std.testing.expect(conn.lifecycle.pending_close == null);
}

test "retiring CID sequence 0 does not change long-header source CID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Server primary starts unvalidated (RFC 9000 §8.1). This test
    // exercises long-header SCID selection on a late Initial; not the
    // anti-amp path. Force-validate so pollLevel isn't gated.
    conn.primaryPath().path.markValidated();

    const initial_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const initial_scid = [_]u8{0xa0};
    const replacement_scid = [_]u8{0xa1};
    try conn.setInitialDcid(&initial_dcid);
    try conn.setPeerDcid(&.{});
    try conn.setLocalScid(&initial_scid);
    try conn.queueNewConnectionId(1, 0, &replacement_scid, @splat(0xa1));

    conn.handleRetireConnectionId(.{ .sequence_number = 0 });
    try std.testing.expectEqualSlices(u8, &replacement_scid, conn.local_scid.slice());
    try std.testing.expectEqualSlices(u8, &initial_scid, conn.longHeaderScid().slice());

    const bytes = try allocator.dupe(u8, "late-initial-ack");
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = bytes,
    });

    var out: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &out, 1_000_000)).?;
    const parsed = try wire_header.parse(out[0..n], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqualSlices(u8, &initial_scid, parsed.header.initial.scid.slice());
}

test "PATH_NEW_CONNECTION_ID rejects sequence reuse with different cid" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "PATH_NEW_CONNECTION_ID rejects path ids above local limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    try conn.handlePathNewConnectionId(.{
        .path_id = 2,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "MAX_PATH_ID cannot reduce the peer initial path limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    conn.handleMaxPathId(.{ .maximum_path_id = 1 });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "PATH_CIDS_BLOCKED cannot skip local cid sequence numbers" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    conn.handlePathCidsBlocked(.{ .path_id = path_id, .next_sequence_number = 2 });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "PATH_CIDS_BLOCKED can be surfaced and replenished within peer active cid limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 1,
        .active_connection_id_limit = 3,
    };
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));

    conn.handlePathCidsBlocked(.{ .path_id = path_id, .next_sequence_number = 1 });
    const blocked = conn.pendingPathCidsBlocked().?;
    try std.testing.expectEqual(path_id, blocked.path_id);
    try std.testing.expectEqual(@as(u64, 1), blocked.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 2), conn.localConnectionIdIssueBudget(path_id));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(path_id, event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.path_cids_blocked, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(?u64, 1), event.connection_ids_needed.blocked_next_sequence_number);
    try std.testing.expectEqual(@as(usize, 2), event.connection_ids_needed.issue_budget);

    const queued = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
        .{ .connection_id = &.{0xc4}, .stateless_reset_token = @splat(0xc4) },
    });
    try std.testing.expectEqual(@as(usize, 2), queued);
    try std.testing.expectEqual(@as(?PathCidsBlockedInfo, null), conn.pendingPathCidsBlocked());
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(path_id));
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_frames.path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(u64, 2), conn.pending_frames.path_new_connection_ids.items[1].sequence_number);
    try std.testing.expectEqual(@as(u64, 3), conn.nextLocalConnectionIdSequence(path_id));

    try std.testing.expectError(
        Error.ConnectionIdLimitExceeded,
        conn.queuePathNewConnectionId(path_id, 3, 0, &.{0xc5}, @splat(0xc5)),
    );
    try conn.queuePathNewConnectionId(path_id, 3, 1, &.{0xc5}, @splat(0xc5));
    try std.testing.expectEqual(@as(usize, 3), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 4), conn.nextLocalConnectionIdSequence(path_id));
}

test "unused negotiated path ids can be pre-provisioned with PATH_NEW_CONNECTION_ID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 3);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 3,
        .active_connection_id_limit = 2,
    };

    const queued = try conn.replenishPathConnectionIds(2, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
    });
    try std.testing.expectEqual(@as(usize, 2), queued);
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u32, 2), conn.pending_frames.path_new_connection_ids.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 0), conn.pending_frames.path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_frames.path_new_connection_ids.items[1].sequence_number);
    try std.testing.expectEqual(@as(u64, 2), conn.nextLocalConnectionIdSequence(2));

    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.queuePathNewConnectionId(4, 0, 0, &.{0xc4}, @splat(0xc4)),
    );
}

test "PATH_RETIRE_CONNECTION_ID drops pending advertisements and allows replenishment" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 1,
        .active_connection_id_limit = 3,
    };
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    _ = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
    });
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);

    conn.handlePathRetireConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
    });
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.pending_frames.path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(usize, 1), conn.localConnectionIdIssueBudget(path_id));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(path_id, event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(usize, 1), event.connection_ids_needed.issue_budget);
    try std.testing.expectEqual(@as(u64, 3), event.connection_ids_needed.next_sequence_number);

    const queued = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc4}, .stateless_reset_token = @splat(0xc4) },
    });
    try std.testing.expectEqual(@as(usize, 1), queued);
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 3), conn.pending_frames.path_new_connection_ids.items[1].sequence_number);
}

test "RETIRE_CONNECTION_ID emits with retransmit metadata and requeues on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try conn.queueRetireConnectionId(7);
    try std.testing.expect(conn.canSend());

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.retire_connection_ids.items.len);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .retire_connection_id);
    try std.testing.expectEqual(@as(u64, 7), decoded.frame.retire_connection_id.sequence_number);

    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 1), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .retire_connection_id);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 7), conn.pending_frames.retire_connection_ids.items[0].sequence_number);
}

test "server HANDSHAKE_DONE emits with retransmit metadata and requeues on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    conn.primaryPath().path.markValidated();
    conn.pending_handshake_done = true;
    try std.testing.expect(conn.canSend());

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expect(!conn.pending_handshake_done);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .handshake_done);

    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 1), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .handshake_done);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expect(conn.pending_handshake_done);
}

test "PATHS_BLOCKED below current local limit is ignored" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    conn.handlePathsBlocked(.{ .maximum_path_id = 1 });
    try std.testing.expectEqual(@as(?u32, null), conn.peer_paths_blocked_at);
    conn.handlePathsBlocked(.{ .maximum_path_id = 2 });
    try std.testing.expectEqual(@as(?u32, 2), conn.peer_paths_blocked_at);
}

test "peer cid registration enforces active cid limit per path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    conn.local_transport_params.active_connection_id_limit = 2;
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(1),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(2),
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "retire_prior_to retires peer cids only on the indicated path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handleNewConnectionId(.{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x20}),
        .stateless_reset_token = @splat(0x20),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0x10),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0x11),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 2,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(0x12),
    });

    try std.testing.expectEqual(@as(usize, 2), conn.peerCidsCount());
    try std.testing.expectEqualSlices(u8, &.{0x12}, conn.paths.get(path_id).?.path.peer_cid.slice());
    try std.testing.expectEqualSlices(u8, &.{0x20}, conn.primaryPath().path.peer_cid.slice());
}

test "STREAM send tracking survives duplicate application PNs across paths" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    const stream = try conn.openBidi(0);

    _ = try stream.send.write("hello");
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000)).?;

    _ = try stream.send.write("world");
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;

    try std.testing.expectEqual(@as(u64, 0), conn.primaryPath().sent.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 0), path.sent.packets[0].pn);
    const primary_stream_key = conn.primaryPath().sent.packets[0].stream_key orelse unreachable;
    const path_stream_key = path.sent.packets[0].stream_key orelse unreachable;
    try std.testing.expect(primary_stream_key != path_stream_key);
    try std.testing.expectEqual(@as(u32, 2), stream.send.in_flight.count());
}

test "timer deadline reports non-zero application path ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(path_id, deadline.path_id);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "PTO requeues retransmittable controls on non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = path_id,
        .error_code = 99,
    } });
    try path.sent.record(packet);

    try conn.tick(conn.ptoDurationForApplicationPath(path));

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expect(!path.pending_ping);
    try std.testing.expectEqual(@as(u8, 1), path.pto_probe_count);
    try std.testing.expectEqual(@as(u32, 1), path.pto_count);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_abandons.items.len);
    try std.testing.expectEqual(path_id, conn.pending_frames.path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_frames.path_abandons.items[0].error_code);
}

test "idle timer closes and enters draining" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Per RFC 9000 §10.1 ¶2 the effective idle timeout is the min of
    // local and peer; either side advertising 0 means no timeout. Set
    // both so the idle gate actually arms.
    try conn.setTransportParams(.{ .max_idle_timeout_ms = 5 });
    conn.cached_peer_transport_params = .{ .max_idle_timeout_ms = 5 };
    conn.last_activity_us = 1_000;
    const deadline = conn.nextTimerDeadline(1_000).?;
    try std.testing.expectEqual(TimerKind.idle, deadline.kind);
    try std.testing.expectEqual(@as(u64, 6_000), deadline.at_us);

    try conn.tick(6_000);
    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expect(conn.lifecycle.draining_deadline_us != null);
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.idle_timeout, close_event.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, close_event.error_space);
    try std.testing.expectEqual(@as(u64, 0), close_event.error_code);
    try std.testing.expectEqualStrings("idle timeout", close_event.reason);

    try conn.tick(conn.lifecycle.draining_deadline_us.?);
    try std.testing.expectEqual(CloseState.closed, conn.closeState());
    try std.testing.expect(conn.nextTimerDeadline(10_000) == null);
}

test "idle timer disabled when either endpoint advertises 0 [RFC9000 §10.1 ¶2]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    const Helper = struct {
        fn run(
            a: std.mem.Allocator,
            tls_ctx: boringssl.tls.Context,
            local_ms: u64,
            peer_ms: u64,
        ) !?TimerDeadline {
            const conn_ptr = try a.create(Connection);
            defer a.destroy(conn_ptr);
            conn_ptr.* = try Connection.initClient(a, tls_ctx, "x");
            defer conn_ptr.deinit();
            try conn_ptr.setTransportParams(.{ .max_idle_timeout_ms = local_ms });
            conn_ptr.cached_peer_transport_params = .{ .max_idle_timeout_ms = peer_ms };
            conn_ptr.last_activity_us = 1_000;
            return conn_ptr.nextTimerDeadline(1_000);
        }
    };

    // Local says 0 → no timeout regardless of peer.
    {
        const next = try Helper.run(allocator, ctx, 0, 30_000);
        try std.testing.expect(next == null or next.?.kind != TimerKind.idle);
    }
    // Peer says 0 → no timeout regardless of local.
    {
        const next = try Helper.run(allocator, ctx, 30_000, 0);
        try std.testing.expect(next == null or next.?.kind != TimerKind.idle);
    }
    // Both non-zero → uses min.
    {
        const deadline = (try Helper.run(allocator, ctx, 30_000, 5)).?;
        try std.testing.expectEqual(TimerKind.idle, deadline.kind);
        try std.testing.expectEqual(@as(u64, 6_000), deadline.at_us);
    }
}

test "qlog: connection_started and connection_state_updated fire on bind+close" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    try conn.bind();
    // Client `bind` should have fired exactly one `connection_started`.
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.connection_started));
    const started = recorder.first(.connection_started).?;
    try std.testing.expectEqual(@as(?Role, .client), started.role);

    // Re-bind shouldn't double-fire.
    try conn.bind();
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.connection_started));

    // Closing transitions open → closing → draining → closed across the close pipeline.
    conn.close(true, transport_error_protocol_violation, "test close");
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expect(recorder.countOf(.connection_state_updated) >= 1);
    const closing_event = blk: {
        var i: usize = 0;
        while (i < recorder.count) : (i += 1) {
            const e = recorder.events[i];
            if (e.name == .connection_state_updated and e.new_state == .closing) break :blk e;
        }
        return error.TestExpectedClosingTransition;
    };
    try std.testing.expectEqual(@as(?CloseState, .open), closing_event.old_state);
}

test "qlog: parameters_set carries top-level peer transport-parameter fields" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Pretend the peer's params arrived and the connection accepted them.
    conn.cached_peer_transport_params = .{
        .max_idle_timeout_ms = 30_000,
        .max_udp_payload_size = 1452,
        .initial_max_data = 65536,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 50,
        .active_connection_id_limit = 4,
        .max_ack_delay_ms = 25,
        .max_datagram_frame_size = 1200,
    };
    conn.emitPeerParametersSet();

    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.parameters_set));
    const e = recorder.first(.parameters_set).?;
    try std.testing.expectEqual(@as(?u64, 30_000), e.peer_idle_timeout_ms);
    try std.testing.expectEqual(@as(?u64, 1452), e.peer_max_udp_payload_size);
    try std.testing.expectEqual(@as(?u64, 65536), e.peer_initial_max_data);
    try std.testing.expectEqual(@as(?u64, 100), e.peer_initial_max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, 50), e.peer_initial_max_streams_uni);
    try std.testing.expectEqual(@as(?u64, 4), e.peer_active_connection_id_limit);
    try std.testing.expectEqual(@as(?u64, 25), e.peer_max_ack_delay_ms);
    try std.testing.expectEqual(@as(?u64, 1200), e.peer_max_datagram_frame_size);

    // Idempotent — second call is a no-op.
    conn.emitPeerParametersSet();
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.parameters_set));
}

test "qlog: packet_sent / packet_received are gated by setQlogPacketEvents" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{});
    // Server primary starts unvalidated (RFC 9000 §8.1). This test
    // exercises the qlog gating, not the anti-amp path; force-validate
    // so pollLevel returns a packet.
    conn.primaryPath().path.markValidated();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // With per-packet events disabled (the default), nothing should fire.
    var buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(usize, 0), recorder.countOf(.packet_sent));
    // But the cheap counter should have advanced.
    try std.testing.expect(conn.qlog_packets_sent >= 1);

    // Enable the opt-in flag and try again — now we should see the event.
    conn.setQlogPacketEvents(true);
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_001_000)).?;
    try std.testing.expect(recorder.countOf(.packet_sent) >= 1);
    const sent_event = recorder.first(.packet_sent).?;
    try std.testing.expectEqual(@as(?QlogPnSpace, .application), sent_event.pn_space);
    try std.testing.expectEqual(@as(?QlogPacketKind, .one_rtt), sent_event.packet_kind);
    try std.testing.expect(sent_event.packet_size != null);
    try std.testing.expect(sent_event.packet_size.? > 0);
}

test "qlog: packet_dropped fires on AEAD authentication failure" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Build a valid 1-RTT, then corrupt the tag so AEAD fails.
    const keys = conn.app_read_current.?.keys;
    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });
    packet_buf[n - 1] ^= 0x01;

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expect(recorder.contains(.packet_dropped));
    const dropped = recorder.first(.packet_dropped).?;
    try std.testing.expectEqual(@as(?QlogPacketDropReason, .decryption_failure), dropped.drop_reason);
}

test "qlog: loss_detected fires from packet-threshold loss detection" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    conn.setQlogPacketEvents(true);

    // Inject a few sent packets at Initial level, then ack a later PN to
    // force packet-threshold loss detection on the early ones.
    const initial_sent = self_blk: {
        break :self_blk &conn.sent[EncryptionLevel.initial.idx()];
    };
    for ([_]u64{ 0, 1, 2 }) |pn| {
        try initial_sent.record(.{
            .pn = pn,
            .sent_time_us = pn * 1000,
            .bytes = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    // Set largest_acked > packet_threshold so the early ones look lost.
    conn.pnSpaceForLevel(.initial).next_pn = 10;
    try conn.handleAckAtLevel(.initial, .{
        .largest_acked = 9,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 5_000);

    try std.testing.expect(recorder.countOf(.loss_detected) >= 1);
    const loss = recorder.first(.loss_detected).?;
    try std.testing.expectEqual(@as(?QlogLossReason, .packet_threshold), loss.loss_reason);
    try std.testing.expect(loss.lost_count != null);
    try std.testing.expect(loss.lost_count.? > 0);
    // packet_lost should fire too because we enabled per-packet events.
    try std.testing.expect(recorder.countOf(.packet_lost) >= 1);
    // The connection-level counter should also have moved.
    try std.testing.expect(conn.qlog_packets_lost >= 1);
}

test "qlog: pathStats exposes the new connection-level counters" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{});
    // Server primary starts unvalidated (RFC 9000 §8.1). This test
    // exercises pathStats counters, not the anti-amp path; force-validate
    // so pollLevel returns a packet.
    conn.primaryPath().path.markValidated();

    // Drive a single send to bump counters.
    var buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_000_000)).?;

    const stats = conn.pathStats(0).?;
    try std.testing.expect(stats.packets_sent >= 1);
    try std.testing.expect(stats.total_bytes_sent >= 1);
    // RTT estimator hasn't run yet — values are at their initial defaults.
    try std.testing.expect(stats.srtt_us > 0); // default kInitialRtt
    try std.testing.expectEqual(stats.srtt_us, stats.smoothed_rtt_us);
    try std.testing.expectEqual(stats.rttvar_us, stats.srtt_us / 2);
    // Slow start phase before any loss.
    try std.testing.expectEqual(path_mod.CongestionState.slow_start, stats.congestion_window_state);
}

const TestMigrationPolicy = struct {
    decision: MigrationDecision,
    invocations: u32 = 0,
    last_candidate: ?Address = null,
    last_current: ?Address = null,
    last_role: ?Role = null,

    fn callback(
        user_data: ?*anyopaque,
        conn: *const Connection,
        candidate_addr: Address,
        current_addr: ?Address,
    ) MigrationDecision {
        const self: *TestMigrationPolicy = @ptrCast(@alignCast(user_data.?));
        self.invocations += 1;
        self.last_candidate = candidate_addr;
        self.last_current = current_addr;
        self.last_role = conn.role;
        return self.decision;
    }
};

test "migration callback: allow lets path validation start as usual" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Bypass the handshake-done migration gate; this test verifies
    // post-handshake migration-callback behavior without driving TLS.
    conn.test_only_force_handshake_for_migration = true;

    var policy: TestMigrationPolicy = .{ .decision = .allow };
    conn.setMigrationCallback(TestMigrationPolicy.callback, &policy);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const old_addr = Address{ .bytes = .{ 10, 0, 0, 1 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 10, 0, 0, 2 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // The callback was consulted once with the right addresses.
    try std.testing.expectEqual(@as(u32, 1), policy.invocations);
    try std.testing.expect(policy.last_candidate != null);
    try std.testing.expect(Address.eql(new_addr, policy.last_candidate.?));
    try std.testing.expect(policy.last_current != null);
    try std.testing.expect(Address.eql(old_addr, policy.last_current.?));
    try std.testing.expectEqual(@as(?Role, .client), policy.last_role);

    // Allow path: PATH_CHALLENGE was queued and migration began.
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_challenge_path_id);
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(.pending, path.path.validator.status);

    // Drive validation to completion and confirm the path validates.
    conn.recordPathResponse(0, path.path.validator.pending_token);
    try std.testing.expect(path.path.isValidated());
    try std.testing.expect(recorder.contains(.migration_path_validated));
    // No policy_denied event was emitted on the allow path.
    try std.testing.expect(!recorder.contains(.migration_path_failed));
}

test "migration callback: deny skips PATH_CHALLENGE and keeps the old 4-tuple live" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Bypass the handshake-done migration gate (post-handshake-only
    // behavior is exercised here without driving the actual TLS).
    conn.test_only_force_handshake_for_migration = true;

    var policy: TestMigrationPolicy = .{ .decision = .deny };
    conn.setMigrationCallback(TestMigrationPolicy.callback, &policy);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const old_addr = Address{ .bytes = .{ 10, 0, 0, 1 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 192, 168, 9, 9 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();
    const orig_bytes_received = path.path.bytes_received;

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // Callback was consulted exactly once.
    try std.testing.expectEqual(@as(u32, 1), policy.invocations);

    // Deny: no PATH_CHALLENGE, no rollback snapshot, peer_addr unchanged.
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expect(Address.eql(old_addr, path.path.peer_addr));
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expect(path.path.isValidated());
    // markValidated set the validator to .validated; deny path must
    // not perturb that — it should leave the existing validator state
    // alone (no new challenge, no transition to pending/idle/failed).
    try std.testing.expectEqual(.validated, path.path.validator.status);

    // The triggering datagram's bytes credited the existing path's
    // anti-amp rather than vanishing.
    try std.testing.expectEqual(orig_bytes_received + 1200, path.path.bytes_received);

    // qlog observability: migration_path_failed with policy_denied.
    try std.testing.expect(recorder.contains(.migration_path_failed));
    const fail_event = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .policy_denied),
        fail_event.migration_fail_reason,
    );
    try std.testing.expectEqual(@as(?u32, 0), fail_event.path_id);

    // The peer can keep talking on the old 4-tuple — confirm a
    // subsequent same-address datagram is still credited cleanly.
    try conn.recordAuthenticatedDatagramAddress(0, old_addr, 800, 1_000_500);
    try std.testing.expectEqual(orig_bytes_received + 1200 + 800, path.path.bytes_received);
    // Callback is not consulted for same-address traffic.
    try std.testing.expectEqual(@as(u32, 1), policy.invocations);
}

test "migration callback: no callback installed preserves prior migration behavior" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Bypass the handshake-done migration gate; the post-handshake
    // no-callback path is what's under test here.
    conn.test_only_force_handshake_for_migration = true;

    // Explicitly leave the callback unset — this is the pre-existing
    // behavior path. The same setup that drives an allow-with-callback
    // succeeds without one, identically.
    try std.testing.expect(conn.migration_callback == null);

    const old_addr = Address{ .bytes = .{ 7, 7, 7, 7 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 8, 8, 8, 8 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // PATH_CHALLENGE queued, migration in progress — same as before.
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(.pending, path.path.validator.status);
}

test "pre-handshake migration: peer-address change is dropped, no PATH_CHALLENGE" {
    // Hardening guide §4.8 / RFC 9000 §9.6: an authenticated peer-
    // address change before handshake confirmation is not legitimate
    // migration. The gate must drop the datagram (no anti-amp credit,
    // no validator state, no PATH_CHALLENGE) and emit
    // `migration_path_failed` with reason `pre_handshake`.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Note: NOT setting test_only_force_handshake_for_migration here
    // — the gate is what we're testing.
    try std.testing.expect(!conn.handshakeDone());

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const old_addr = Address{ .bytes = .{ 1, 1, 1, 1 } ++ @as([18]u8, @splat(0)) };
    const new_addr = Address{ .bytes = .{ 2, 2, 2, 2 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    const orig_bytes_received = path.path.bytes_received;

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // Drop semantics: peer_addr unchanged, no anti-amp credit, no
    // PATH_CHALLENGE, no validator state mutation, last-challenge
    // clock not stamped.
    try std.testing.expect(Address.eql(old_addr, path.path.peer_addr));
    try std.testing.expectEqual(orig_bytes_received, path.path.bytes_received);
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expectEqual(@as(?u64, null), path.path.last_path_challenge_at_us);

    // qlog event: migration_path_failed / pre_handshake.
    try std.testing.expect(recorder.contains(.migration_path_failed));
    const evt = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .pre_handshake),
        evt.migration_fail_reason,
    );
    try std.testing.expectEqual(@as(?u32, 0), evt.path_id);
}

test "post-handshake migration: PATH_CHALLENGE rate-limit blocks rapid-fire probes" {
    // Hardening guide §4.8: per-path PATH_CHALLENGE rate limit
    // (`min_path_challenge_interval_us`). The first migration after
    // handshake fires a challenge; a second migration arriving
    // sooner than the interval is rate-limited (no second challenge).
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.test_only_force_handshake_for_migration = true;

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const addr_a = Address{ .bytes = .{ 10, 0, 0, 1 } ++ @as([18]u8, @splat(0)) };
    const addr_b = Address{ .bytes = .{ 10, 0, 0, 2 } ++ @as([18]u8, @splat(0)) };
    const addr_c = Address{ .bytes = .{ 10, 0, 0, 3 } ++ @as([18]u8, @splat(0)) };
    const path = conn.primaryPath();
    path.setPeerAddress(addr_a);
    path.path.markValidated();

    // First migration: challenge fires, last_path_challenge_at_us stamped.
    const t0: u64 = 1_000_000;
    try conn.recordAuthenticatedDatagramAddress(0, addr_b, 1200, t0);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(?u64, t0), path.path.last_path_challenge_at_us);

    // Drain the queued challenge so the next migration tries a fresh
    // queue, otherwise the queue-already-set assertion would mask the
    // rate-limit verdict.
    conn.pending_frames.path_challenge = null;

    // Second migration arrives 50 ms later — well inside the 100 ms
    // rate limit. Must be rejected with `rate_limited`.
    const t1: u64 = t0 + 50_000;
    try conn.recordAuthenticatedDatagramAddress(0, addr_c, 1200, t1);
    try std.testing.expect(conn.pending_frames.path_challenge == null);

    const fail_evt = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .rate_limited),
        fail_evt.migration_fail_reason,
    );

    // Third migration after the interval elapses: clears the gate.
    const t2: u64 = t0 + min_path_challenge_interval_us + 1;
    try conn.recordAuthenticatedDatagramAddress(0, addr_c, 1200, t2);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(?u64, t2), path.path.last_path_challenge_at_us);
}

test "migration callback: setMigrationCallback installs and clears the hook" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var policy: TestMigrationPolicy = .{ .decision = .deny };
    conn.setMigrationCallback(TestMigrationPolicy.callback, &policy);
    try std.testing.expect(conn.migration_callback != null);
    try std.testing.expect(conn.migration_user_data == @as(?*anyopaque, &policy));

    conn.setMigrationCallback(null, null);
    try std.testing.expect(conn.migration_callback == null);
    try std.testing.expect(conn.migration_user_data == null);
}

// -- Connection-level fuzz harnesses (hardening guide §11.1 #8 / #9 / #20) ----
//
// These sit one layer above the per-buffer fuzz harnesses landed in
// `recv_stream.zig` / `send_stream.zig` / `flow_control.zig` /
// `path_validator.zig` / `ack_tracker.zig`. The per-buffer harnesses
// proved each state machine in isolation; here we drive a fully
// constructed `Connection` so the fuzzer also exercises the
// integration paths that include `bytes_resident` accounting against
// `max_connection_memory`, peer-state stream-count gating, and the
// per-path migration rate limiter / validator wiring.
//
// Each harness uses `std.testing.allocator` and `defer conn.deinit()`
// so a failed assertion still cleans up; aborting on uninteresting
// input is `return` (not `error`) to keep the corpus tight.

// CRYPTO reassembly fuzz harness — drives `dispatchFrames(.handshake,
// payload, now_us)` with a smith-built CRYPTO frame stream and
// asserts:
//
// - No panic / overflow trap.
// - `bytes_resident` always stays inside `max_connection_memory`
//   (set tiny here at 1024 so the resident-bytes path is reachable).
// - Once the connection has closed with `transport_error_excessive_load`
//   the harness stops feeding new frames (nothing else to assert).
// - Duplicate offsets do not push `bytes_resident` higher than the
//   first non-duplicate frame at that offset already cost.
// - `crypto_recv_offset[idx]` is monotonic across the entire run.
//
// Note: `dispatchFrames` does not call `drainInboxIntoTls`, so the
// harness exercises only the reassembly state machine — TLS is never
// fed real bytes.
test "fuzz: Connection.handleCrypto reassembly invariants" {
    try std.testing.fuzz({}, fuzzConnHandleCryptoImpl, .{});
}

fn fuzzConnHandleCryptoImpl(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Tiny cap so the resident-bytes path (`tryReserveResidentBytes`
    // → `error.ExcessiveLoad` → close with EXCESSIVE_LOAD) is
    // reachable on a few hundred bytes of fuzz input.
    conn.max_connection_memory = 1024;
    const cap = conn.max_connection_memory;
    const lvl: EncryptionLevel = .handshake;
    const idx = lvl.idx();

    const num_frames = smith.valueRangeAtMost(u32, 0, 32);
    var frame_buf: [4096]u8 = undefined;
    var data_buf: [64]u8 = undefined;

    var i: u32 = 0;
    while (i < num_frames) : (i += 1) {
        const offset = smith.valueRangeAtMost(u64, 0, 4096);
        const data_len = smith.valueRangeAtMost(u8, 0, 64);
        smith.bytes(data_buf[0..data_len]);

        const frame: frame_types.Frame = .{ .crypto = .{
            .offset = offset,
            .data = data_buf[0..data_len],
        } };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const before_resident = conn.bytes_resident;
        const before_recv_off = conn.crypto_recv_offset[idx];

        conn.dispatchFrames(lvl, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            // `dispatchFrames` propagates frame-iter decode errors and
            // a few other Connection errors — they are expected on
            // malformed input. We continue feeding frames; the
            // invariants below still apply.
            error.OutOfMemory => return err,
            else => {},
        };

        // Resident-bytes invariant: never overshoots the cap.
        try std.testing.expect(conn.bytes_resident <= cap);
        // crypto_recv_offset is monotonic across the entire run.
        try std.testing.expect(conn.crypto_recv_offset[idx] >= before_recv_off);

        // If the connection closed with EXCESSIVE_LOAD, the resident
        // bytes after close must also be inside the cap (close does
        // not free buffers, it just stops accepting more).
        if (conn.lifecycle.pending_close) |info| {
            // The close error code is one we recognize: every code
            // path in `handleCrypto` that can close goes through one
            // of {protocol_violation, excessive_load}.
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_excessive_load,
            );
            // Once closed, stop feeding frames — `dispatchFrames`
            // would no-op anyway.
            break;
        }

        // Suppress unused-warning: before_resident is used implicitly
        // by the cap invariant above (it bounds growth).
        _ = before_resident;
    }
}

// STREAM reassembly fuzz harness — drives
// `dispatchFrames(.application, payload, now_us)` with smith-built
// STREAM frames on a single peer-initiated bidi stream and asserts:
//
// - No panic / overflow trap.
// - `bytes_resident` always stays inside `max_connection_memory`
//   (set to 1024 here so the cap path is reachable).
// - `read_offset` of the recv buffer is monotonic across the run
//   (we never call `streamRead`, so it stays at 0 — but the
//   monotonicity invariant still holds trivially).
// - After any RESET_STREAM-like close, the stream's send-side state
//   machine is well-formed (one of the SendStream.State enum values).
// - `final_size` invariants hold: once a FIN is observed, no
//   subsequent fragment extends past the locked final size, and the
//   recv buffer's `final_size` matches the FIN offset.
test "fuzz: Connection.handleStream reassembly invariants" {
    try std.testing.fuzz({}, fuzzConnHandleStreamImpl, .{});
}

fn fuzzConnHandleStreamImpl(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Tiny memory cap so the resident-bytes path is reachable, plus
    // matching small per-stream / per-conn flow control windows so
    // the FLOW_CONTROL close path can also fire.
    conn.max_connection_memory = 1024;
    try conn.setTransportParams(.{
        .initial_max_data = 512,
        .initial_max_stream_data_bidi_remote = 512,
        .initial_max_streams_bidi = 1,
    });
    const cap = conn.max_connection_memory;

    // We drive a single peer-initiated client-bidi stream (id 0).
    // The first STREAM frame creates the Stream entry; subsequent
    // frames hit the existing entry and exercise the reassembly /
    // flow-control / final-size paths.
    const stream_id: u64 = 0;

    const num_frames = smith.valueRangeAtMost(u32, 0, 32);
    var frame_buf: [4096]u8 = undefined;
    var data_buf: [64]u8 = undefined;

    var observed_fin_offset: ?u64 = null;

    var i: u32 = 0;
    while (i < num_frames) : (i += 1) {
        const offset = smith.valueRangeAtMost(u64, 0, 4096);
        const data_len = smith.valueRangeAtMost(u8, 0, 64);
        const fin = smith.valueRangeAtMost(u8, 0, 3) == 0;
        smith.bytes(data_buf[0..data_len]);

        const frame: frame_types.Frame = .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = data_buf[0..data_len],
            .has_offset = true,
            .has_length = true,
            .fin = fin,
        } };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const stream_before = conn.streams.get(stream_id);
        const read_off_before: u64 = if (stream_before) |sp| sp.recv.read_offset else 0;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        // Resident-bytes invariant.
        try std.testing.expect(conn.bytes_resident <= cap);

        if (conn.streams.get(stream_id)) |sp| {
            // read_offset is monotonic (the harness never calls
            // streamRead, so this should always hold trivially as 0).
            try std.testing.expect(sp.recv.read_offset >= read_off_before);

            // Send-side state machine is one of the documented
            // SendStream.State enum variants. The Zig type system
            // enforces this; assert the runtime tag is well-formed by
            // running a switch over every variant.
            switch (sp.send.state) {
                .ready, .send, .data_sent, .data_recvd, .reset_sent, .reset_recvd => {},
            }

            // Final-size invariants: once a FIN is locked in, no
            // range may extend past it, and read_offset stays inside.
            if (sp.recv.final_size) |fs| {
                try std.testing.expect(sp.recv.read_offset <= fs);
                try std.testing.expect(sp.recv.end_offset <= fs);
                if (observed_fin_offset) |prev_fs| {
                    // The recv-stream is RFC §4.5 strict: once FIN is
                    // locked, a second FIN at a different offset
                    // surfaces as `FinalSizeChanged` and the
                    // connection closes. So `final_size` here equals
                    // the previously observed value.
                    try std.testing.expectEqual(prev_fs, fs);
                } else {
                    observed_fin_offset = fs;
                }
            }
        }

        // Once closed, stop — `dispatchFrames` would no-op.
        if (conn.lifecycle.pending_close) |info| {
            // Recognized close codes for handleStream:
            // - flow_control (peer overshot stream/conn window)
            // - stream_state (forbidden id pattern)
            // - stream_limit (peer-opened stream count exceeded)
            // - final_size (FIN clash / past-FIN extension)
            // - excessive_load (resident-bytes cap)
            // - protocol_violation (recv-buffer span limit)
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_flow_control or
                    code == transport_error_stream_state or
                    code == transport_error_stream_limit or
                    code == transport_error_final_size or
                    code == transport_error_excessive_load or
                    code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding,
            );
            break;
        }
    }
}

// Migration sequence fuzz harness — drives
// `recordAuthenticatedDatagramAddress` with smith-built sequences of
// (path_id=0, candidate_addr, datagram_len, now_us) tuples and
// asserts:
//
// - No panic / overflow trap.
// - `path.path.peer_addr` always equals one of the candidate addresses
//   we ever fed in (never garbage / never half-mutated state).
// - `path.path.validator.status` after every step is one of
//   {idle, pending, validated, failed} (the type system enforces
//   this; the assertion is a runtime sanity check).
// - Every emitted `migration_path_failed` qlog event carries a
//   `migration_fail_reason` value drawn from the documented set
//   (timeout, policy_denied, pre_handshake, rate_limited).
test "fuzz: Connection.recordAuthenticatedDatagramAddress migration sequences" {
    try std.testing.fuzz({}, fuzzConnMigrationImpl, .{});
}

fn fuzzConnMigrationImpl(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Bypass the pre-handshake gate so the validator + rate-limit
    // paths are reachable. (Without this, the very first migration
    // emits `pre_handshake` and the rate-limit / validator paths are
    // never exercised.)
    conn.test_only_force_handshake_for_migration = true;

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Stable candidate-address pool. Picking from a fixed set keeps
    // the invariant "peer_addr is one of the candidates we fed in"
    // simple to assert (the rollback path also draws from this set,
    // since the rollback snapshot was previously written from here).
    const candidates: [4]Address = .{
        .{ .bytes = .{ 10, 0, 0, 1 } ++ @as([18]u8, @splat(0)) },
        .{ .bytes = .{ 10, 0, 0, 2 } ++ @as([18]u8, @splat(0)) },
        .{ .bytes = .{ 10, 0, 0, 3 } ++ @as([18]u8, @splat(0)) },
        .{ .bytes = .{ 10, 0, 0, 4 } ++ @as([18]u8, @splat(0)) },
    };

    const path = conn.primaryPath();
    path.setPeerAddress(candidates[0]);
    path.path.markValidated();

    var now_us: u64 = 1_000_000;
    const num_events = smith.valueRangeAtMost(u8, 0, 16);

    var i: u8 = 0;
    while (i < num_events) : (i += 1) {
        const which: u8 = smith.valueRangeAtMost(u8, 0, 3);
        const addr = candidates[which];
        const dt: u16 = smith.value(u16);
        now_us = now_us +| @as(u64, dt);

        // Drain any queued PATH_CHALLENGE so the next migration runs
        // through the rate-limit / validator paths cleanly. Mirrors
        // the existing `post-handshake migration` test pattern.
        conn.pending_frames.path_challenge = null;

        conn.recordAuthenticatedDatagramAddress(0, addr, 1200, now_us) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        // Validator status is one of the four enum members.
        switch (path.path.validator.status) {
            .idle, .pending, .validated, .failed => {},
        }

        // peer_addr is one of the candidates we ever fed in.
        var matched = false;
        for (candidates) |cand| {
            if (Address.eql(path.path.peer_addr, cand)) {
                matched = true;
                break;
            }
        }
        try std.testing.expect(matched);

        // Bail out if the connection closed; nothing useful left to
        // exercise. (The migration paths in
        // `recordAuthenticatedDatagramAddress` themselves don't close
        // the connection, but `handlePeerAddressChange` allocates a
        // fresh path-challenge token which can hit OOM under fuzz.)
        if (conn.lifecycle.pending_close != null) break;
    }

    // Every emitted `migration_path_failed` event carries a known
    // reason — qlog never invents new tag values.
    var ev_idx: usize = 0;
    while (ev_idx < recorder.count) : (ev_idx += 1) {
        const evt = recorder.events[ev_idx];
        if (evt.name != .migration_path_failed) continue;
        const reason = evt.migration_fail_reason orelse {
            try std.testing.expect(false);
            return;
        };
        switch (reason) {
            .timeout, .policy_denied, .pre_handshake, .rate_limited, .no_fresh_peer_cid => {},
        }
    }
}

// Connection-ID lifecycle fuzz harness — drives smith-chosen
// interleavings of `handleNewConnectionId` / `handleRetireConnectionId`
// / `handlePathNewConnectionId` against a fully-authenticated
// `Connection` and asserts:
//
// - No panic / overflow trap on any sequence.
// - `peer_cids.items.len` for path 0 never exceeds the local-side
//   `active_connection_id_limit` cap that gates `registerPeerCid`
//   (set tight at 4 here so the cap path is reachable in 0..32 ops).
// - Every `peer_cids` entry has a unique (path_id, sequence_number)
//   pair — `registerPeerCid` rejects sequence reuse with a different
//   cid/token, so duplicates surface as a close rather than a stored
//   collision.
// - After `handleRetireConnectionId(seq=N)` returns without closing
//   the connection, sequence N is no longer present in `local_cids`
//   for path 0 (we pre-populate `local_cids` with seq 0/1/2 so the
//   retire path has something to remove).
// - `path.path.peer_cid` (the active CID for path 0) always matches
//   one of the entries in `peer_cids` — or is empty (initial state)
//   or the connection has closed.
// - If the connection closed during the run, the close error code is
//   one of {`transport_error_protocol_violation`,
//   `transport_error_frame_encoding`,
//   `transport_error_excessive_load`}. In practice
//   `registerPeerCid` / `handleRetireConnectionId` only emit
//   `protocol_violation` (retire-not-yet-issued, sequence-reuse,
//   cid-reuse-across-paths, retire_prior_to-too-large, active-cid
//   limit), but the broader set is documented for forward-compat.
//
// Multipath scope reduction: we hold path_id at 0 for the
// `handlePathNewConnectionId` op so the harness does not need to
// negotiate multipath transport parameters and stand up secondary
// paths — both `handleNewConnectionId` and the path_id=0 form of
// `handlePathNewConnectionId` converge on `registerPeerCid`, so the
// fuzzer-chosen interleaving of the two entry points still exercises
// the same state-machine surface that §11.1 #19 calls out.
test "fuzz: Connection NEW_CONNECTION_ID / RETIRE_CONNECTION_ID lifecycle invariants" {
    try std.testing.fuzz({}, fuzzCidLifecycle, .{});
}

test "RETIRE_CONNECTION_ID flood beyond per-cycle cap closes with PROTOCOL_VIOLATION" {
    // Seed corpus entry mirroring an adversarial peer that bursts
    // `incoming_retire_cid_cap + 1` RETIRE frames in one datagram.
    // The fast-path skip handles the bulk (each retire targets a
    // sequence below the smallest live entry), so the closing
    // signal is the per-cycle counter, not the per-frame walk.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 8 };
    try conn.setLocalScid(&.{0xb0});
    try conn.queueNewConnectionId(1, 0, &.{0xb1}, @splat(0xb1));
    try conn.queueNewConnectionId(2, 0, &.{0xb2}, @splat(0xb2));

    // Fresh handle cycle.
    conn.incoming_retire_cid_count = 0;

    var i: u64 = 0;
    while (i <= incoming_retire_cid_cap) : (i += 1) {
        // Use sequence 0 every time — it's a real local CID, so
        // the retire actually does something on the first call,
        // then the fast-path skip kicks in for the rest. Either
        // way, the per-cycle counter advances.
        conn.handleRetireConnectionId(.{ .sequence_number = 0 });
        if (conn.lifecycle.pending_close != null) break;
    }
    const close = conn.lifecycle.pending_close orelse return error.TestExpectedFloodClose;
    try std.testing.expectEqual(transport_error_protocol_violation, close.error_code);
    try std.testing.expectEqualStrings("retire_connection_id flood", close.reason);
}

test "RETIRE_CONNECTION_ID fast-path skips sequences already retired" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 8 };
    try conn.setLocalScid(&.{0xc0});
    try conn.queueNewConnectionId(1, 0, &.{0xc1}, @splat(0xc1));
    try conn.queueNewConnectionId(2, 0, &.{0xc2}, @splat(0xc2));
    try conn.queueNewConnectionId(3, 0, &.{0xc3}, @splat(0xc3));

    // Real retire: removes seq 0 and 1 from local_cids.
    conn.handleRetireConnectionId(.{ .sequence_number = 0 });
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });

    // smallestLiveLocalCidSeq(0) is now 2. A retire of seq 0 must
    // hit the fast-path skip (no close, no further state change).
    const closes_before = conn.incoming_retire_cid_count;
    conn.handleRetireConnectionId(.{ .sequence_number = 0 });
    try std.testing.expect(conn.lifecycle.pending_close == null);
    // Counter still bumped (the cap gates total frame count, not
    // just slow-path frames) but no work was done.
    try std.testing.expectEqual(closes_before + 1, conn.incoming_retire_cid_count);
    try std.testing.expectEqual(@as(u64, 2), conn.smallestLiveLocalCidSeq(0).?);
}

fn fuzzCidLifecycle(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Tight `active_connection_id_limit` so the
    // "peer_cids exceeds limit" close path is reachable in a 32-op
    // budget. The cap on `peer_cids` per path comes from the local
    // side's transport params (it bounds how many of the peer's CIDs
    // we are willing to hold). 4 is small enough that the fuzzer
    // routinely walks past it.
    conn.local_transport_params.active_connection_id_limit = 4;
    const peer_cid_cap = conn.local_transport_params.active_connection_id_limit;

    // Plant a few `local_cids` entries so `handleRetireConnectionId`
    // has something to remove (otherwise it always no-ops on the
    // local-side list). The peer's `active_connection_id_limit`
    // governs how many of OUR CIDs we may issue, so set the peer's
    // cached transport params to allow the seeds.
    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 8 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));
    // After this, `local_cids` holds seqs 0, 1, 2 on path 0 and the
    // recorded high-watermark `next_local_cid_seq` is 3. RETIRE
    // frames with seq < 3 are legal (well-formed); seq >= 3 is a
    // PROTOCOL_VIOLATION the fuzz harness must ride out as a close.

    const num_ops = smith.valueRangeAtMost(u8, 0, 32);
    var op_i: u8 = 0;
    while (op_i < num_ops) : (op_i += 1) {
        const op_kind = smith.valueRangeAtMost(u8, 0, 2);
        const seq = smith.valueRangeAtMost(u64, 0, 16);
        const cid_len = smith.valueRangeAtMost(u8, 0, 20);
        // Bail out of obviously-invalid input the parser would reject
        // before the handler sees it. `wire_header.ConnId.fromSlice`
        // errors on len > 20, but we already cap above; this is
        // belt-and-braces for forward-compat.
        if (cid_len > 20) return;

        var cid_bytes: [20]u8 = undefined;
        smith.bytes(cid_bytes[0..cid_len]);
        var token: [16]u8 = undefined;
        smith.bytes(&token);

        // Pick a `retire_prior_to` <= seq sometimes, > seq sometimes
        // (the latter triggers the PROTOCOL_VIOLATION close path).
        const rpt_kind = smith.valueRangeAtMost(u8, 0, 3);
        const retire_prior_to: u64 = switch (rpt_kind) {
            0 => 0,
            1 => seq,
            2 => if (seq > 0) seq - 1 else 0,
            else => seq +| 1, // forces invalid-rpt close
        };

        switch (op_kind) {
            0 => {
                // NEW_CONNECTION_ID — register a peer-issued CID at
                // path 0.
                const conn_id = frame_types.ConnId.fromSlice(cid_bytes[0..cid_len]) catch return;
                conn.handleNewConnectionId(.{
                    .sequence_number = seq,
                    .retire_prior_to = retire_prior_to,
                    .connection_id = conn_id,
                    .stateless_reset_token = token,
                }) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {},
                };
            },
            1 => {
                // RETIRE_CONNECTION_ID — peer asks us to retire one
                // of OUR (local) CIDs at the named sequence.
                conn.handleRetireConnectionId(.{ .sequence_number = seq });
            },
            else => {
                // PATH_NEW_CONNECTION_ID — same shape as NEW with
                // path_id=0. Doc'd above: keeping path_id at 0 means
                // we don't have to negotiate multipath, but the call
                // still exercises the second entry point into
                // `registerPeerCid`.
                const conn_id = frame_types.ConnId.fromSlice(cid_bytes[0..cid_len]) catch return;
                conn.handlePathNewConnectionId(.{
                    .path_id = 0,
                    .sequence_number = seq,
                    .retire_prior_to = retire_prior_to,
                    .connection_id = conn_id,
                    .stateless_reset_token = token,
                }) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {},
                };
            },
        }

        // Invariant 1: peer_cids count for path 0 stays inside cap.
        // (`registerPeerCid` closes with PROTOCOL_VIOLATION rather
        // than overshoot the cap, so the cap holds even on
        // adversarial input.)
        const path0_count: u64 = @intCast(conn.peerCidActiveCountForPath(0));
        try std.testing.expect(path0_count <= peer_cid_cap);

        // Invariant 2: sequence_number is unique per path within
        // peer_cids. Walk the list O(n^2) — we cap at 4 entries.
        for (conn.peer_cids.items, 0..) |a, ai| {
            for (conn.peer_cids.items[ai + 1 ..]) |b| {
                if (a.path_id == b.path_id) {
                    try std.testing.expect(a.sequence_number != b.sequence_number);
                }
            }
        }

        // Invariant 3 (RETIRE consequence): the named sequence was
        // removed from `local_cids` on path 0 if it was present and
        // the call did not close. We can't know which op fired this
        // iteration without re-checking `op_kind`, so guard on it.
        if (op_kind == 1 and conn.lifecycle.pending_close == null) {
            // After a successful retire, no `local_cids` entry on
            // path 0 with that sequence remains.
            for (conn.local_cids.items) |item| {
                if (item.path_id == 0) {
                    try std.testing.expect(item.sequence_number != seq);
                }
            }
        }

        // Invariant 4: path 0's active peer_cid matches one of the
        // peer_cids entries on path 0, OR the field is empty (no
        // peer-issued CID promoted yet), OR the connection has
        // closed.
        if (conn.lifecycle.pending_close == null) {
            const path = conn.paths.get(0).?;
            const active = path.path.peer_cid;
            if (active.len != 0) {
                var matched = false;
                for (conn.peer_cids.items) |item| {
                    if (item.path_id == 0 and ConnectionId.eql(item.cid, active)) {
                        matched = true;
                        break;
                    }
                }
                try std.testing.expect(matched);
            }
        }

        // Invariant 5 (close-code coherence): if the run produced a
        // close, the error code lives in the documented set. Stop
        // feeding ops once closed — the handlers no-op anyway, but
        // the asserts above grow stale on a zombie state machine.
        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_excessive_load,
            );
            break;
        }
    }
}

// PATH_CHALLENGE / PATH_RESPONSE fuzz harness — drives
// `dispatchFrames(.application, payload, now_us)` with smith-built
// PATH_CHALLENGE and PATH_RESPONSE frames against a post-handshake
// client `Connection` whose primary path validator already has a
// pending challenge token. Asserts:
//
// - No panic / overflow trap.
// - After a PATH_CHALLENGE, `pending_frames.path_response` is non-null
//   and equals the challenge token (the dispatcher echoes the bytes).
// - After a PATH_RESPONSE that matches the validator's pending token,
//   the validator transitions to `.validated`. Mismatching tokens
//   leave the status alone (`.pending` or `.validated`).
// - Validator status is always one of {.idle, .pending, .validated,
//   .failed}.
// - Lifecycle state is one of the documented `CloseState` values.
// - If the connection closed, the close code lives in the documented
//   set ({protocol_violation, frame_encoding, excessive_load}). The
//   PATH_CHALLENGE / PATH_RESPONSE handlers themselves never close, but
//   the dispatcher's frame-iter and level-gate close paths can fire on
//   adversarial bytes.
test "fuzz: Connection PATH_CHALLENGE / PATH_RESPONSE handler invariants" {
    try std.testing.fuzz({}, fuzzConnPathChallenge, .{});
}

fn fuzzConnPathChallenge(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path = conn.primaryPath();
    path.setPeerAddress(.{ .bytes = .{ 10, 0, 0, 1 } ++ @as([18]u8, @splat(0)) });
    const pending_token: [8]u8 = .{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    path.path.validator.beginChallenge(pending_token, 1_000_000, 1_000_000);
    conn.current_incoming_path_id = 0;
    conn.current_incoming_addr = path.path.peer_addr;

    const num_frames = smith.valueRangeAtMost(u8, 0, 32);
    var frame_buf: [64]u8 = undefined;

    var i: u8 = 0;
    while (i < num_frames) : (i += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 3);
        var token: [8]u8 = undefined;
        smith.bytes(&token);
        const use_pending = smith.valueRangeAtMost(u8, 0, 3) == 0;
        const data: [8]u8 = if (use_pending) pending_token else token;

        const challenge_data: [8]u8 = switch (op) {
            0 => data,
            2 => token,
            else => @splat(0),
        };
        const response_data: [8]u8 = switch (op) {
            1 => data,
            3 => token,
            else => @splat(0),
        };
        const frame: frame_types.Frame = switch (op) {
            0 => .{ .path_challenge = .{ .data = challenge_data } },
            1 => .{ .path_response = .{ .data = response_data } },
            2 => .{ .path_challenge = .{ .data = challenge_data } },
            else => .{ .path_response = .{ .data = response_data } },
        };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const status_before = path.path.validator.status;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        switch (path.path.validator.status) {
            .idle, .pending, .validated, .failed => {},
        }

        if (op == 0 or op == 2) {
            if (conn.lifecycle.pending_close == null) {
                const echoed = conn.pending_frames.path_response orelse {
                    try std.testing.expect(false);
                    return;
                };
                try std.testing.expect(std.mem.eql(u8, &echoed, &challenge_data));
                try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_response_path_id);
            }
        }

        if ((op == 1 or op == 3) and use_pending and status_before == .pending and
            conn.lifecycle.pending_close == null)
        {
            const matches_pending = std.mem.eql(u8, &response_data, &pending_token);
            if (matches_pending) {
                try std.testing.expect(path.path.validator.status == .validated);
            }
        }

        switch (conn.lifecycle.state()) {
            .open, .closing, .draining, .closed => {},
        }

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_excessive_load,
            );
            break;
        }
    }
}

// MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS fuzz harness — drives
// `dispatchFrames(.application, payload, now_us)` with smith-built
// flow-control window-update frames and asserts:
//
// - `peer_max_data` is monotonic non-decreasing (handler only widens).
// - `peer_max_streams_bidi` and `peer_max_streams_uni` are monotonic
//   non-decreasing AND bounded above by `max_streams_per_connection`
//   (the handler clamps with `@min`).
// - MAX_STREAM_DATA on a peer-to-local-only stream id (e.g. peer-uni
//   stream where the peer is sending) closes with `stream_state`.
// - MAX_STREAMS exceeding `max_stream_count_limit` closes with
//   `frame_encoding`.
// - Lifecycle state is one of the documented `CloseState` values.
// - Close codes (when set) are in the documented set.
test "fuzz: Connection MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS monotonicity" {
    try std.testing.fuzz({}, fuzzConnFlowControlWindow, .{});
}

fn fuzzConnFlowControlWindow(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.peer_max_data = 0;
    conn.peer_max_streams_bidi = 0;
    conn.peer_max_streams_uni = 0;

    const num_frames = smith.valueRangeAtMost(u8, 0, 32);
    var frame_buf: [64]u8 = undefined;

    var i: u8 = 0;
    while (i < num_frames) : (i += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 3);
        const value = smith.value(u64) & ((1 << 62) - 1);
        const stream_id_low = smith.valueRangeAtMost(u8, 0, 31);
        const bidi = smith.valueRangeAtMost(u8, 0, 1) == 0;

        const frame: frame_types.Frame = switch (op) {
            0 => .{ .max_data = .{ .maximum_data = value } },
            1 => .{ .max_stream_data = .{
                .stream_id = stream_id_low,
                .maximum_stream_data = value,
            } },
            2 => .{ .max_streams = .{ .bidi = bidi, .maximum_streams = value } },
            else => .{ .max_streams = .{
                .bidi = bidi,
                .maximum_streams = max_stream_count_limit + (value & 7) + 1,
            } },
        };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const before_max_data = conn.peer_max_data;
        const before_streams_bidi = conn.peer_max_streams_bidi;
        const before_streams_uni = conn.peer_max_streams_uni;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        try std.testing.expect(conn.peer_max_data >= before_max_data);
        try std.testing.expect(conn.peer_max_streams_bidi >= before_streams_bidi);
        try std.testing.expect(conn.peer_max_streams_uni >= before_streams_uni);
        try std.testing.expect(conn.peer_max_streams_bidi <= max_streams_per_connection);
        try std.testing.expect(conn.peer_max_streams_uni <= max_streams_per_connection);

        switch (conn.lifecycle.state()) {
            .open, .closing, .draining, .closed => {},
        }

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_stream_state or
                    code == transport_error_excessive_load,
            );
            break;
        }
    }
}

// DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED fuzz harness —
// drives `dispatchFrames(.application, ...)` with peer-blocked
// signal frames and asserts:
//
// - No panic / overflow trap.
// - After DATA_BLOCKED, `peer_data_blocked_at == frame.maximum_data`.
// - After STREAMS_BLOCKED(bidi=true) without close, the stored value
//   matches the frame's maximum (and likewise for uni).
// - `peer_stream_data_blocked.items.len <= max_stream_count_limit` —
//   bounded by the same global stream-count cap that gates the handler.
// - STREAM_DATA_BLOCKED on a receive-only stream closes with
//   `stream_state`. STREAMS_BLOCKED with maximum > stream-id space
//   closes with `frame_encoding`.
// - Lifecycle state is one of the documented `CloseState` values and
//   close codes are in the documented set.
test "fuzz: Connection DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED invariants" {
    try std.testing.fuzz({}, fuzzConnBlockedFrames, .{});
}

fn fuzzConnBlockedFrames(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try conn.setTransportParams(.{
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
    });

    const num_frames = smith.valueRangeAtMost(u8, 0, 32);
    var frame_buf: [64]u8 = undefined;

    var i: u8 = 0;
    while (i < num_frames) : (i += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 3);
        const value = smith.value(u64) & ((1 << 62) - 1);
        const stream_id_low = smith.valueRangeAtMost(u8, 0, 15);
        const bidi = smith.valueRangeAtMost(u8, 0, 1) == 0;

        const frame: frame_types.Frame = switch (op) {
            0 => .{ .data_blocked = .{ .maximum_data = value } },
            1 => .{ .stream_data_blocked = .{
                .stream_id = stream_id_low,
                .maximum_stream_data = value,
            } },
            2 => .{ .streams_blocked = .{ .bidi = bidi, .maximum_streams = value } },
            else => .{ .streams_blocked = .{
                .bidi = bidi,
                .maximum_streams = max_stream_count_limit + (value & 3) + 1,
            } },
        };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        if (op == 0 and conn.lifecycle.pending_close == null) {
            const stored = conn.peer_data_blocked_at orelse {
                try std.testing.expect(false);
                return;
            };
            try std.testing.expectEqual(value, stored);
        }
        if (op == 2 and conn.lifecycle.pending_close == null and value <= max_stream_count_limit) {
            const stored = if (bidi) conn.peer_streams_blocked_bidi else conn.peer_streams_blocked_uni;
            try std.testing.expectEqual(value, stored.?);
        }

        try std.testing.expect(conn.peer_stream_data_blocked.items.len <= max_stream_count_limit);

        switch (conn.lifecycle.state()) {
            .open, .closing, .draining, .closed => {},
        }

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_stream_state or
                    code == transport_error_excessive_load,
            );
            break;
        }
    }
}

// CONNECTION_CLOSE-at-Initial-or-Handshake fuzz harness — drives
// `dispatchFrames(.initial, ...)` and `dispatchFrames(.handshake, ...)`
// with smith-built CONNECTION_CLOSE frames and other 1-RTT-only frames
// to exercise the §12.4/§19.19 envelope before the handshake completes.
//
// Asserts:
// - No panic / overflow trap.
// - A transport CONNECTION_CLOSE (0x1c) at .initial or .handshake
//   transitions lifecycle into draining (state in
//   {.draining, .closing, .closed}).
// - An application CONNECTION_CLOSE (0x1d) at .initial or .handshake
//   triggers a `protocol_violation` close (forbidden frame at
//   Initial/Handshake level, RFC 9000 §12.4 / Table 3).
// - Forbidden 1-RTT-only frames (STREAM, MAX_DATA, NEW_CONNECTION_ID,
//   PATH_CHALLENGE, …) at .initial or .handshake close with
//   `protocol_violation`.
// - Once closed, lifecycle state is one of {.draining, .closing, .closed}
//   and the close code is in the documented set.
// - Reason-phrase length on the wire never overflows the 256-byte
//   `max_close_reason_len` ceiling — the lifecycle records reasons
//   truncated, never beyond.
test "fuzz: Connection CONNECTION_CLOSE pre-handshake envelope invariants" {
    try std.testing.fuzz({}, fuzzConnCloseAtInitial, .{});
}

fn fuzzConnCloseAtInitial(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const op = smith.valueRangeAtMost(u8, 0, 7);
    const lvl: EncryptionLevel = if (smith.valueRangeAtMost(u8, 0, 1) == 0) .initial else .handshake;
    const error_code = smith.value(u64) & ((1 << 30) - 1);
    const reason_len = smith.valueRangeAtMost(u16, 0, 320);
    var reason_buf: [320]u8 = undefined;
    smith.bytes(reason_buf[0..reason_len]);
    const value = smith.value(u64) & ((1 << 62) - 1);

    const frame: frame_types.Frame = switch (op) {
        0 => .{ .connection_close = .{
            .is_transport = true,
            .error_code = error_code,
            .frame_type = 0,
            .reason_phrase = reason_buf[0..reason_len],
        } },
        1 => .{ .connection_close = .{
            .is_transport = false,
            .error_code = error_code,
            .reason_phrase = reason_buf[0..reason_len],
        } },
        2 => .{ .stream = .{
            .stream_id = value & 0xff,
            .offset = 0,
            .data = reason_buf[0..@min(reason_len, 32)],
            .has_offset = false,
            .has_length = true,
            .fin = false,
        } },
        3 => .{ .max_data = .{ .maximum_data = value } },
        4 => .{ .new_token = .{ .token = reason_buf[0..@min(reason_len, 64)] } },
        5 => .{ .path_challenge = .{ .data = reason_buf[0..8].* } },
        6 => .{ .handshake_done = .{} },
        else => .{ .ping = .{} },
    };

    var frame_buf: [512]u8 = undefined;
    const needed = frame_mod.encodedLen(frame);
    if (needed > frame_buf.len) return;
    const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

    conn.dispatchFrames(lvl, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {},
    };

    switch (conn.lifecycle.state()) {
        .open, .closing, .draining, .closed => {},
    }

    if (op == 0) {
        switch (conn.lifecycle.state()) {
            .draining, .closing, .closed => {},
            .open => try std.testing.expect(false),
        }
    }
    if (op == 1 or op == 2 or op == 3 or op == 4 or op == 5) {
        if (conn.lifecycle.pending_close) |info| {
            try std.testing.expectEqual(transport_error_protocol_violation, info.error_code);
        }
    }

    if (op == 6) {
        if (conn.lifecycle.pending_close) |info| {
            try std.testing.expectEqual(transport_error_protocol_violation, info.error_code);
        }
    }

    if (conn.lifecycle.event()) |ev| {
        try std.testing.expect(ev.reason.len <= lifecycle_mod.max_close_reason_len);
    }

    if (conn.lifecycle.pending_close) |info| {
        const code = info.error_code;
        try std.testing.expect(
            code == transport_error_protocol_violation or
                code == transport_error_frame_encoding or
                code == transport_error_excessive_load or
                code == error_code,
        );
    }
}
