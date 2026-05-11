//! TLS transport-parameter microbenchmark helpers.
//!
//! Fixtures are deterministic and allocation-free in the hot loops.
//! `bench/main.zig` can import this module and register whichever
//! helpers it wants without needing to construct transport-parameter
//! blobs itself.

const std = @import("std");
const quic_zig = @import("quic_zig");

const transport_params = quic_zig.tls.transport_params;

const Params = transport_params.Params;
const PreferredAddress = transport_params.PreferredAddress;
const ConnectionId = transport_params.ConnectionId;

pub const transport_params_encode_common_name = "transport_params_encode_common";
pub const transport_params_decode_common_name = "transport_params_decode_common";
pub const transport_params_decode_extensions_name = "transport_params_decode_extensions";

pub const transport_params_bench_capacity: usize = 256;

const common_scid_bytes: [8]u8 = .{ 0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f };
const client_ext_scid_bytes: [8]u8 = .{ 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98 };
const server_ext_scid_bytes: [8]u8 = .{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 };
const server_ext_odcid_bytes: [8]u8 = .{ 0x90, 0x81, 0x72, 0x63, 0x54, 0x45, 0x36, 0x27 };
const preferred_cid_bytes: [8]u8 = .{ 0xca, 0xfe, 0xba, 0xbe, 0x09, 0x19, 0x29, 0x39 };
const reset_token: [16]u8 = .{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
const preferred_reset_token: [16]u8 = .{
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
};
const versions: [3]u32 = .{ 0x0000_0001, 0x6b33_43cf, 0xff00_abcd };

pub const TransportParamsEncodeCommonCtx = struct {
    params: Params,

    pub fn deinit(self: *TransportParamsEncodeCommonCtx) void {
        deinitTransportParamsEncodeCommonCtx(self);
    }
};

pub const TransportParamsDecodeCommonCtx = struct {
    blob: [transport_params_bench_capacity]u8,
    blob_len: usize,

    pub fn deinit(self: *TransportParamsDecodeCommonCtx) void {
        deinitTransportParamsDecodeCommonCtx(self);
    }

    pub fn bytes(self: *const TransportParamsDecodeCommonCtx) []const u8 {
        return self.blob[0..self.blob_len];
    }
};

pub const TransportParamsDecodeExtensionsCtx = struct {
    client_blob: [transport_params_bench_capacity]u8,
    client_blob_len: usize,
    server_blob: [transport_params_bench_capacity]u8,
    server_blob_len: usize,

    pub fn deinit(self: *TransportParamsDecodeExtensionsCtx) void {
        deinitTransportParamsDecodeExtensionsCtx(self);
    }

    pub fn clientBytes(self: *const TransportParamsDecodeExtensionsCtx) []const u8 {
        return self.client_blob[0..self.client_blob_len];
    }

    pub fn serverBytes(self: *const TransportParamsDecodeExtensionsCtx) []const u8 {
        return self.server_blob[0..self.server_blob_len];
    }
};

pub fn initTransportParamsEncodeCommonCtx() !TransportParamsEncodeCommonCtx {
    return .{ .params = commonParams() };
}

pub fn deinitTransportParamsEncodeCommonCtx(_: *TransportParamsEncodeCommonCtx) void {}

pub fn initTransportParamsDecodeCommonCtx() !TransportParamsDecodeCommonCtx {
    var ctx: TransportParamsDecodeCommonCtx = .{
        .blob = undefined,
        .blob_len = 0,
    };
    ctx.blob_len = try commonParams().encode(&ctx.blob);
    return ctx;
}

pub fn deinitTransportParamsDecodeCommonCtx(_: *TransportParamsDecodeCommonCtx) void {}

pub fn initTransportParamsDecodeExtensionsCtx() !TransportParamsDecodeExtensionsCtx {
    var ctx: TransportParamsDecodeExtensionsCtx = .{
        .client_blob = undefined,
        .client_blob_len = 0,
        .server_blob = undefined,
        .server_blob_len = 0,
    };
    ctx.client_blob_len = try extensionClientParams().encode(&ctx.client_blob);
    ctx.server_blob_len = try extensionServerParams().encode(&ctx.server_blob);
    return ctx;
}

pub fn deinitTransportParamsDecodeExtensionsCtx(_: *TransportParamsDecodeExtensionsCtx) void {}

pub fn runTransportParamsEncodeCommon(ctx: *const TransportParamsEncodeCommonCtx, iters: u64) u64 {
    var buf: [transport_params_bench_capacity]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = ctx.params.encode(&buf) catch unreachable;
        sum +%= n;
        sum +%= foldEncodedSample(buf[0..n]);
    }
    return sum;
}

pub fn runTransportParamsDecodeCommon(ctx: *const TransportParamsDecodeCommonCtx, iters: u64) u64 {
    const blob = ctx.bytes();
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const decoded = Params.decode(blob) catch unreachable;
        sum +%= foldCommonParams(&decoded);
    }
    return sum;
}

pub fn runTransportParamsDecodeExtensions(ctx: *const TransportParamsDecodeExtensionsCtx, iters: u64) u64 {
    const client_blob = ctx.clientBytes();
    const server_blob = ctx.serverBytes();
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        if ((i & 1) == 0) {
            const decoded = transport_params.decodeAs(client_blob, .{ .role = .client }) catch unreachable;
            sum +%= foldExtensionParams(&decoded);
        } else {
            const decoded = transport_params.decodeAs(server_blob, .{
                .role = .server,
                .server_sent_retry = false,
            }) catch unreachable;
            sum +%= foldExtensionParams(&decoded);
        }
    }
    return sum;
}

fn commonParams() Params {
    return .{
        .max_idle_timeout_ms = 30_000,
        .max_udp_payload_size = 1452,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 17,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 32,
        .ack_delay_exponent = 5,
        .max_ack_delay_ms = 20,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = ConnectionId.fromSlice(&common_scid_bytes),
    };
}

fn extensionClientParams() Params {
    var p: Params = .{
        .max_idle_timeout_ms = 45_000,
        .max_udp_payload_size = 1452,
        .initial_max_data = 2 << 20,
        .initial_max_stream_data_bidi_local = 512 * 1024,
        .initial_max_stream_data_bidi_remote = 512 * 1024,
        .initial_max_stream_data_uni = 256 * 1024,
        .initial_max_streams_bidi = 128,
        .initial_max_streams_uni = 64,
        .active_connection_id_limit = 6,
        .initial_source_connection_id = ConnectionId.fromSlice(&client_ext_scid_bytes),
        .max_datagram_frame_size = 1200,
        .grease_quic_bit = true,
        .initial_max_path_id = 3,
        .alternative_address = true,
    };
    p.setCompatibleVersions(&versions) catch unreachable;
    return p;
}

fn extensionServerParams() Params {
    var p: Params = .{
        .original_destination_connection_id = ConnectionId.fromSlice(&server_ext_odcid_bytes),
        .max_idle_timeout_ms = 45_000,
        .stateless_reset_token = reset_token,
        .max_udp_payload_size = 1452,
        .initial_max_data = 2 << 20,
        .initial_max_stream_data_bidi_local = 512 * 1024,
        .initial_max_stream_data_bidi_remote = 512 * 1024,
        .initial_max_stream_data_uni = 256 * 1024,
        .initial_max_streams_bidi = 128,
        .initial_max_streams_uni = 64,
        .disable_active_migration = true,
        .preferred_address = preferredAddress(),
        .active_connection_id_limit = 6,
        .initial_source_connection_id = ConnectionId.fromSlice(&server_ext_scid_bytes),
        .max_datagram_frame_size = 1200,
        .grease_quic_bit = true,
        .initial_max_path_id = 3,
    };
    p.setCompatibleVersions(&versions) catch unreachable;
    return p;
}

fn preferredAddress() PreferredAddress {
    return .{
        .ipv4_address = .{ 192, 0, 2, 9 },
        .ipv4_port = 4433,
        .ipv6_address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 },
        .ipv6_port = 8443,
        .connection_id = ConnectionId.fromSlice(&preferred_cid_bytes),
        .stateless_reset_token = preferred_reset_token,
    };
}

fn foldEncodedSample(bytes: []const u8) u64 {
    if (bytes.len == 0) return 0;
    var sum: u64 = bytes.len;
    sum +%= bytes[0];
    sum +%= bytes[bytes.len / 3];
    sum +%= bytes[(bytes.len * 2) / 3];
    sum +%= bytes[bytes.len - 1];
    return sum;
}

fn foldCommonParams(p: *const Params) u64 {
    var sum: u64 = p.max_idle_timeout_ms;
    sum +%= p.max_udp_payload_size;
    sum +%= p.initial_max_data;
    sum +%= p.initial_max_stream_data_bidi_local;
    sum +%= p.initial_max_stream_data_bidi_remote;
    sum +%= p.initial_max_stream_data_uni;
    sum +%= p.initial_max_streams_bidi;
    sum +%= p.initial_max_streams_uni;
    sum +%= p.ack_delay_exponent;
    sum +%= p.max_ack_delay_ms;
    sum +%= p.active_connection_id_limit;
    sum +%= foldMaybeCid(p.initial_source_connection_id);
    return sum;
}

fn foldExtensionParams(p: *const Params) u64 {
    var sum = foldCommonParams(p);
    sum +%= foldMaybeCid(p.original_destination_connection_id);
    sum +%= foldMaybeCid(p.retry_source_connection_id);
    if (p.stateless_reset_token) |token| sum +%= foldBytes(&token);
    sum +%= @intFromBool(p.disable_active_migration);
    if (p.preferred_address) |addr| sum +%= foldPreferredAddress(&addr);
    sum +%= p.max_datagram_frame_size;
    sum +%= @intFromBool(p.grease_quic_bit);
    sum +%= if (p.initial_max_path_id) |path_id| path_id else 0;
    sum +%= @intFromBool(p.alternative_address);
    for (p.compatibleVersions()) |version| sum +%= version;
    return sum;
}

fn foldPreferredAddress(addr: *const PreferredAddress) u64 {
    var sum = foldBytes(&addr.ipv4_address);
    sum +%= addr.ipv4_port;
    sum +%= foldBytes(&addr.ipv6_address);
    sum +%= addr.ipv6_port;
    sum +%= foldMaybeCid(addr.connection_id);
    sum +%= foldBytes(&addr.stateless_reset_token);
    return sum;
}

fn foldMaybeCid(maybe: ?ConnectionId) u64 {
    const cid = maybe orelse return 0;
    return cid.len +% foldBytes(cid.slice());
}

fn foldBytes(bytes: []const u8) u64 {
    var sum: u64 = 0;
    for (bytes) |b| {
        sum = (sum << 5) ^ (sum >> 2) ^ b;
    }
    return sum;
}

test "transport_params_encode_common fixture is canonical" {
    const ctx = try initTransportParamsEncodeCommonCtx();
    try std.testing.expect(runTransportParamsEncodeCommon(&ctx, 1) != 0);

    var buf: [transport_params_bench_capacity]u8 = undefined;
    const n = try ctx.params.encode(&buf);
    const decoded = try Params.decode(buf[0..n]);

    try std.testing.expectEqual(@as(u64, 30_000), decoded.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 1 << 20), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_bidi);
    try std.testing.expect(decoded.initial_source_connection_id != null);
    try std.testing.expectEqualSlices(
        u8,
        &common_scid_bytes,
        decoded.initial_source_connection_id.?.slice(),
    );
}

test "transport_params_decode_common fixture decodes" {
    const ctx = try initTransportParamsDecodeCommonCtx();
    try std.testing.expect(ctx.blob_len > 0);
    try std.testing.expect(runTransportParamsDecodeCommon(&ctx, 2) != 0);

    const decoded = try Params.decode(ctx.bytes());
    try std.testing.expectEqual(@as(u64, 1452), decoded.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 4), decoded.active_connection_id_limit);
    try std.testing.expectEqual(@as(u64, 5), decoded.ack_delay_exponent);
}

test "transport_params_decode_extensions fixture exercises extension fields" {
    const ctx = try initTransportParamsDecodeExtensionsCtx();
    try std.testing.expect(ctx.client_blob_len > 0);
    try std.testing.expect(ctx.server_blob_len > 0);
    try std.testing.expect(runTransportParamsDecodeExtensions(&ctx, 2) != 0);

    const client = try transport_params.decodeAs(ctx.clientBytes(), .{ .role = .client });
    try std.testing.expect(client.alternative_address);
    try std.testing.expect(client.grease_quic_bit);
    try std.testing.expectEqual(@as(u32, 3), client.initial_max_path_id.?);
    try std.testing.expectEqual(@as(u64, 1200), client.max_datagram_frame_size);
    try std.testing.expectEqualSlices(u32, &versions, client.compatibleVersions());

    const server = try transport_params.decodeAs(ctx.serverBytes(), .{
        .role = .server,
        .server_sent_retry = false,
    });
    try std.testing.expect(server.preferred_address != null);
    try std.testing.expect(server.grease_quic_bit);
    try std.testing.expectEqual(@as(u32, 3), server.initial_max_path_id.?);
    try std.testing.expectEqualSlices(u32, &versions, server.compatibleVersions());
}
