//! QUIC 0-RTT replay-context builder (RFC 9001 §4.6.1).
//!
//! BoringSSL stores the server's `quic_early_data_context` in session
//! tickets and compares it on resumption before accepting early data.
//! The context must cover every transport or application setting that
//! changes how 0-RTT bytes are interpreted. This module builds a stable
//! SHA-256 digest from nullq's remembered transport parameters plus an
//! opaque application context (for example HTTP/3 SETTINGS).

const std = @import("std");
const boringssl = @import("boringssl");
const Params = @import("transport_params.zig").Params;

pub const digest_len: usize = 32;
pub const Digest = [digest_len]u8;

pub const Options = struct {
    /// QUIC wire version whose transport rules the ticket is bound to.
    quic_version: u32 = 0x00000001,
    /// Negotiated ALPN wire identifier, e.g. "h3" or "hq-interop".
    alpn: []const u8 = &.{},
    /// Local transport parameters that affect what 0-RTT is allowed
    /// to send. The builder records defaults as well as explicit fields.
    transport_params: Params = .{},
    /// Application-owned compatibility bytes. HTTP/3 should include a
    /// canonicalized SETTINGS/QPACK policy digest here.
    application_context: []const u8 = &.{},
};

pub fn build(opts: Options) Digest {
    var h = boringssl.crypto.hash.Sha256.init();
    h.update("nullq quic 0-rtt context v1");
    updateU32(&h, opts.quic_version);
    updateBytes(&h, opts.alpn);
    updateTransportParams(&h, opts.transport_params);
    updateBytes(&h, opts.application_context);
    return h.finalDigest();
}

pub fn buildForTransportParams(
    transport_params: Params,
    alpn: []const u8,
    application_context: []const u8,
) Digest {
    return build(.{
        .transport_params = transport_params,
        .alpn = alpn,
        .application_context = application_context,
    });
}

fn updateTransportParams(h: *boringssl.crypto.hash.Sha256, p: Params) void {
    // Deliberately exclude connection-instance identifiers and tokens
    // such as original_destination_connection_id, stateless_reset_token,
    // preferred_address, initial_source_connection_id, and
    // retry_source_connection_id. Those vary by connection attempt or
    // migration hint and would make otherwise valid resumption reject
    // 0-RTT. The context below covers the transport and application
    // settings that constrain early bytes.
    updateU64(h, p.max_idle_timeout_ms);
    updateU64(h, p.max_udp_payload_size);
    updateU64(h, p.initial_max_data);
    updateU64(h, p.initial_max_stream_data_bidi_local);
    updateU64(h, p.initial_max_stream_data_bidi_remote);
    updateU64(h, p.initial_max_stream_data_uni);
    updateU64(h, p.initial_max_streams_bidi);
    updateU64(h, p.initial_max_streams_uni);
    updateU64(h, p.ack_delay_exponent);
    updateU64(h, p.max_ack_delay_ms);
    updateBool(h, p.disable_active_migration);
    updateU64(h, p.active_connection_id_limit);
    updateU64(h, p.max_datagram_frame_size);
    if (p.initial_max_path_id) |max_path_id| {
        h.update(&.{1});
        updateU32(h, max_path_id);
    } else {
        h.update(&.{0});
    }
}

fn updateBytes(h: *boringssl.crypto.hash.Sha256, bytes: []const u8) void {
    updateU64(h, bytes.len);
    h.update(bytes);
}

fn updateBool(h: *boringssl.crypto.hash.Sha256, value: bool) void {
    h.update(if (value) &.{1} else &.{0});
}

fn updateU32(h: *boringssl.crypto.hash.Sha256, value: u32) void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], value, .big);
    h.update(&buf);
}

fn updateU64(h: *boringssl.crypto.hash.Sha256, value: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], value, .big);
    h.update(&buf);
}

fn expectContextDiffers(base: Options, changed: Options) !void {
    const base_digest = build(base);
    const changed_digest = build(changed);
    try std.testing.expect(!std.mem.eql(u8, &base_digest, &changed_digest));
}

test "context is stable and sensitive to transport and app settings" {
    const base = build(.{
        .alpn = "h3",
        .transport_params = .{
            .initial_max_data = 1024,
            .initial_max_streams_bidi = 8,
        },
        .application_context = "settings-v1",
    });
    const same = build(.{
        .alpn = "h3",
        .transport_params = .{
            .initial_max_data = 1024,
            .initial_max_streams_bidi = 8,
        },
        .application_context = "settings-v1",
    });
    const changed_tp = build(.{
        .alpn = "h3",
        .transport_params = .{
            .initial_max_data = 2048,
            .initial_max_streams_bidi = 8,
        },
        .application_context = "settings-v1",
    });
    const changed_app = build(.{
        .alpn = "h3",
        .transport_params = .{
            .initial_max_data = 1024,
            .initial_max_streams_bidi = 8,
        },
        .application_context = "settings-v2",
    });

    try std.testing.expectEqualSlices(u8, &base, &same);
    try std.testing.expect(!std.mem.eql(u8, &base, &changed_tp));
    try std.testing.expect(!std.mem.eql(u8, &base, &changed_app));
}

test "context changes for every 0-RTT replay-relevant transport parameter" {
    const base: Options = .{
        .quic_version = 0x00000001,
        .alpn = "h3",
        .transport_params = .{
            .max_idle_timeout_ms = 30_000,
            .max_udp_payload_size = 1400,
            .initial_max_data = 64 * 1024,
            .initial_max_stream_data_bidi_local = 8 * 1024,
            .initial_max_stream_data_bidi_remote = 9 * 1024,
            .initial_max_stream_data_uni = 10 * 1024,
            .initial_max_streams_bidi = 16,
            .initial_max_streams_uni = 8,
            .ack_delay_exponent = 4,
            .max_ack_delay_ms = 15,
            .disable_active_migration = false,
            .active_connection_id_limit = 4,
            .max_datagram_frame_size = 1200,
            .initial_max_path_id = 2,
        },
        .application_context = "settings-v1",
    };

    var changed = base;
    changed.quic_version = 0x6b3343cf;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.alpn = "hq-interop";
    try expectContextDiffers(base, changed);

    changed = base;
    changed.application_context = "settings-v2";
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.max_idle_timeout_ms += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.max_udp_payload_size -= 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_data += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_stream_data_bidi_local += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_stream_data_bidi_remote += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_stream_data_uni += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_streams_bidi += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_streams_uni += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.ack_delay_exponent += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.max_ack_delay_ms += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.disable_active_migration = true;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.active_connection_id_limit += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.max_datagram_frame_size += 1;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_path_id = 3;
    try expectContextDiffers(base, changed);

    changed = base;
    changed.transport_params.initial_max_path_id = null;
    try expectContextDiffers(base, changed);
}

test "context ignores connection-instance identifiers" {
    const path = @import("../conn/path.zig");
    const base = build(.{
        .transport_params = .{
            .original_destination_connection_id = path.ConnectionId.fromSlice(&.{ 1, 2, 3, 4 }),
            .initial_source_connection_id = path.ConnectionId.fromSlice(&.{ 5, 6, 7, 8 }),
            .retry_source_connection_id = path.ConnectionId.fromSlice(&.{ 9, 10, 11, 12 }),
            .stateless_reset_token = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            .preferred_address = .{
                .ipv4_address = .{ 192, 0, 2, 1 },
                .ipv4_port = 4433,
                .ipv6_address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
                .ipv6_port = 4433,
                .connection_id = path.ConnectionId.fromSlice(&.{ 0xa0, 0xa1 }),
                .stateless_reset_token = .{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf },
            },
            .initial_max_data = 1024,
        },
    });
    const changed_ids = build(.{
        .transport_params = .{
            .original_destination_connection_id = path.ConnectionId.fromSlice(&.{ 0xaa, 0xbb }),
            .initial_source_connection_id = path.ConnectionId.fromSlice(&.{ 0xcc, 0xdd }),
            .retry_source_connection_id = path.ConnectionId.fromSlice(&.{ 0xee, 0xff }),
            .stateless_reset_token = .{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
            .preferred_address = .{
                .ipv4_address = .{ 198, 51, 100, 9 },
                .ipv4_port = 8443,
                .ipv6_address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 },
                .ipv6_port = 8443,
                .connection_id = path.ConnectionId.fromSlice(&.{ 0xb0, 0xb1, 0xb2 }),
                .stateless_reset_token = .{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf },
            },
            .initial_max_data = 1024,
        },
    });
    const changed_limit = build(.{
        .transport_params = .{
            .original_destination_connection_id = path.ConnectionId.fromSlice(&.{ 1, 2, 3, 4 }),
            .initial_source_connection_id = path.ConnectionId.fromSlice(&.{ 5, 6, 7, 8 }),
            .retry_source_connection_id = path.ConnectionId.fromSlice(&.{ 9, 10, 11, 12 }),
            .stateless_reset_token = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            .initial_max_data = 2048,
        },
    });

    try std.testing.expectEqualSlices(u8, &base, &changed_ids);
    try std.testing.expect(!std.mem.eql(u8, &base, &changed_limit));
}
