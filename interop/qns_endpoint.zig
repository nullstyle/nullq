const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");

const Net = std.Io.net;

const hq_alpn = "hq-interop";
const server_cid = [_]u8{ 0x51, 0x4e, 0x53, 0x2d, 0x6e, 0x75, 0x6c, 0x6c };
const retry_token_key = [_]u8{
    0x4e, 0x55, 0x4c, 0x4c, 0x51, 0x2d, 0x51, 0x4e,
    0x53, 0x2d, 0x52, 0x45, 0x54, 0x52, 0x59, 0x21,
    0x90, 0x51, 0x43, 0x7b, 0x2d, 0xa4, 0x17, 0x66,
    0x10, 0xe1, 0x44, 0x58, 0x73, 0x88, 0x2b, 0x31,
};
const retry_token_lifetime_us: u64 = 30_000_000;

const ServerOptions = struct {
    listen: []const u8 = "0.0.0.0:443",
    www: []const u8 = "/www",
    cert: []const u8 = "/certs/cert.pem",
    key: []const u8 = "/certs/priv.key",
    retry: bool = false,
};

const StreamState = struct {
    buf: std.ArrayList(u8) = .empty,
    responded: bool = false,

    fn deinit(self: *StreamState, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
        self.* = undefined;
    }
};

const Http09App = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    www_dir: std.Io.Dir,
    streams: std.AutoHashMap(u64, StreamState),

    fn init(allocator: std.mem.Allocator, io: std.Io, www_dir: std.Io.Dir) Http09App {
        return .{
            .allocator = allocator,
            .io = io,
            .www_dir = www_dir,
            .streams = std.AutoHashMap(u64, StreamState).init(allocator),
        };
    }

    fn deinit(self: *Http09App) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.streams.deinit();
        self.www_dir.close(self.io);
    }

    fn process(self: *Http09App, conn: *nullq.Connection) !void {
        var it = conn.streamIterator();
        while (it.next()) |entry| {
            try self.processStream(conn, entry.key_ptr.*);
        }
    }

    fn stateFor(self: *Http09App, stream_id: u64) !*StreamState {
        const gop = try self.streams.getOrPut(stream_id);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        return gop.value_ptr;
    }

    fn processStream(self: *Http09App, conn: *nullq.Connection, stream_id: u64) !void {
        const state = try self.stateFor(stream_id);
        if (state.responded) return;

        var tmp: [4096]u8 = undefined;
        while (true) {
            const n = try conn.streamRead(stream_id, &tmp);
            if (n == 0) break;
            try state.buf.appendSlice(self.allocator, tmp[0..n]);
        }

        const stream = conn.stream(stream_id) orelse return;
        if (!(stream.recv.state == .data_recvd or stream.recv.state == .data_read)) return;

        const rel = parseGetPath(state.buf.items) orelse {
            _ = try conn.streamWrite(stream_id, "400");
            try conn.streamFinish(stream_id);
            state.responded = true;
            return;
        };

        const contents = self.readFile(rel) catch |err| switch (err) {
            error.FileNotFound => blk: {
                _ = try conn.streamWrite(stream_id, "404");
                break :blk null;
            },
            else => return err,
        };
        if (contents) |bytes| {
            defer self.allocator.free(bytes);
            _ = try conn.streamWrite(stream_id, bytes);
        }
        try conn.streamFinish(stream_id);
        state.responded = true;
    }

    fn readFile(self: *Http09App, rel: []const u8) ![]u8 {
        return try self.www_dir.readFileAlloc(self.io, rel, self.allocator, .limited(64 * 1024 * 1024));
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();

    _ = args.next();
    const command = args.next() orelse {
        usage();
        return;
    };

    if (std.mem.eql(u8, command, "server")) {
        var opts: ServerOptions = .{};
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "-listen")) {
                opts.listen = args.next() orelse return error.MissingListenAddress;
            } else if (std.mem.eql(u8, arg, "-www")) {
                opts.www = args.next() orelse return error.MissingWwwDirectory;
            } else if (std.mem.eql(u8, arg, "-cert")) {
                opts.cert = args.next() orelse return error.MissingCertificatePath;
            } else if (std.mem.eql(u8, arg, "-key")) {
                opts.key = args.next() orelse return error.MissingKeyPath;
            } else if (std.mem.eql(u8, arg, "-retry")) {
                opts.retry = true;
            } else {
                usage();
                return error.UnknownArgument;
            }
        }
        try runServer(allocator, io, opts);
        return;
    }

    if (std.mem.eql(u8, command, "client")) {
        std.debug.print("nullq qns client endpoint is not implemented yet\n", .{});
        std.process.exit(127);
    }

    usage();
    return error.UnknownCommand;
}

fn usage() void {
    std.debug.print(
        \\usage:
        \\  qns-endpoint server [-listen 0.0.0.0:443] [-www /www] [-cert /certs/cert.pem] [-key /certs/priv.key] [-retry]
        \\  qns-endpoint client
        \\
    , .{});
}

fn runServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    opts: ServerOptions,
) !void {
    const bind_addr = try Net.IpAddress.parseLiteral(opts.listen);
    const sock = try Net.IpAddress.bind(&bind_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    const cert_pem = try readWholeFile(io, allocator, opts.cert, 1024 * 1024);
    defer allocator.free(cert_pem);
    const key_pem = try readWholeFile(io, allocator, opts.key, 1024 * 1024);
    defer allocator.free(key_pem);

    const protos = [_][]const u8{hq_alpn};
    var server_tls = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    defer server_tls.deinit();
    try server_tls.loadCertChainAndKey(cert_pem, key_pem);

    std.debug.print("nullq qns endpoint listening on {f} www={s} retry={}\n", .{ bind_addr, opts.www, opts.retry });

    while (true) {
        var conn = try nullq.Connection.initServer(allocator, server_tls);
        defer conn.deinit();
        try conn.bind();
        try conn.setLocalScid(&server_cid);

        var next_cid_seq: u8 = 1;
        try queueServerConnectionIds(&conn, &next_cid_seq, 4);

        var app = Http09App.init(allocator, io, try openDir(io, opts.www));
        defer app.deinit();

        var peer: ?Net.IpAddress = null;
        var transport_params_set = false;
        var retry_sent = false;
        var retry_original_dcid: nullq.conn.path.ConnectionId = .{};
        var retry_source_cid = retrySourceCid();
        var now_us: u64 = 1_000_000;
        var rx: [64 * 1024]u8 = undefined;
        var tx: [4096]u8 = undefined;

        while (!conn.isClosed()) {
            const maybe_msg = sock.receiveTimeout(io, &rx, .{
                .duration = .{
                    .raw = std.Io.Duration.fromMilliseconds(5),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => null,
                else => return err,
            };

            if (maybe_msg) |msg| {
                peer = msg.from;
                if (!transport_params_set) {
                    const ids = peekLongHeaderIds(msg.data) orelse continue;
                    if (ids.version != nullq.QUIC_VERSION_1) {
                        const n = try conn.writeVersionNegotiation(&tx, msg.data, &.{nullq.QUIC_VERSION_1});
                        try sock.send(io, &msg.from, tx[0..n]);
                        continue;
                    }

                    if (opts.retry and !retry_sent) {
                        retry_original_dcid = nullq.conn.path.ConnectionId.fromSlice(ids.dcid);
                        const token = try retryToken(msg.from, now_us, ids.dcid, &retry_source_cid);
                        const n = try conn.writeRetry(&tx, msg.data, &retry_source_cid, &token);
                        try sock.send(io, &msg.from, tx[0..n]);
                        retry_sent = true;
                        continue;
                    }

                    const original_dcid = if (retry_sent) retry_original_dcid else nullq.conn.path.ConnectionId.fromSlice(ids.dcid);
                    const retry_source: ?nullq.conn.path.ConnectionId = if (retry_sent)
                        nullq.conn.path.ConnectionId.fromSlice(&retry_source_cid)
                    else
                        null;
                    if (retry_sent) {
                        const token = peekInitialToken(msg.data) orelse continue;
                        if (!validRetryToken(msg.from, now_us, original_dcid.slice(), &retry_source_cid, token)) continue;
                    }

                    const params: nullq.tls.TransportParams = .{
                        .original_destination_connection_id = original_dcid,
                        .initial_source_connection_id = nullq.conn.path.ConnectionId.fromSlice(&server_cid),
                        .retry_source_connection_id = retry_source,
                        .max_idle_timeout_ms = 30_000,
                        .initial_max_data = 64 * 1024 * 1024,
                        .initial_max_stream_data_bidi_local = 16 * 1024 * 1024,
                        .initial_max_stream_data_bidi_remote = 16 * 1024 * 1024,
                        .initial_max_stream_data_uni = 1024 * 1024,
                        .initial_max_streams_bidi = 128,
                        .initial_max_streams_uni = 16,
                        .max_udp_payload_size = 1200,
                        .active_connection_id_limit = 8,
                    };
                    try conn.acceptInitial(msg.data, params);
                    _ = try conn.setEarlyDataContextForParams(params, hq_alpn, "nullq qns endpoint v1");
                    transport_params_set = true;
                }
                try conn.handle(msg.data, null, now_us);
            }

            if (conn.handshakeDone()) try queueServerConnectionIds(&conn, &next_cid_seq, 8);
            try app.process(&conn);
            while (try conn.poll(&tx, now_us)) |n| {
                if (peer) |p| try sock.send(io, &p, tx[0..n]) else break;
            }
            try conn.tick(now_us);
            now_us += 1_000;
        }
    }
}

fn parseGetPath(request: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimEnd(u8, request, " \r\n");
    if (!std.mem.startsWith(u8, trimmed, "GET ")) return null;
    var path = trimmed[4..];
    if (std.mem.indexOfAny(u8, path, " \t")) |end| path = path[0..end];
    while (std.mem.startsWith(u8, path, "/")) path = path[1..];
    if (path.len == 0) return null;
    if (std.mem.indexOf(u8, path, "..") != null) return null;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return null;
    return path;
}

fn openDir(io: std.Io, path: []const u8) !std.Io.Dir {
    if (std.fs.path.isAbsolute(path)) return try std.Io.Dir.openDirAbsolute(io, path, .{});
    return try std.Io.Dir.cwd().openDir(io, path, .{});
}

fn readWholeFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_bytes));
}

fn queueServerConnectionIds(conn: *nullq.Connection, next_seq: *u8, desired_last_seq: u8) !void {
    const budget = conn.localConnectionIdIssueBudget(0);
    if (budget == 0 or next_seq.* > desired_last_seq) return;

    var cid_storage: [8][server_cid.len]u8 = undefined;
    var provisions: [8]nullq.ConnectionIdProvision = undefined;
    var count: usize = 0;
    var seq = next_seq.*;
    while (seq <= desired_last_seq and count < provisions.len and count < budget) {
        cid_storage[count] = server_cid;
        cid_storage[count][7] +%= seq;
        provisions[count] = .{
            .connection_id = cid_storage[count][0..],
            .stateless_reset_token = statelessResetToken(seq),
        };
        count += 1;
        seq += 1;
    }
    if (count == 0) return;

    const queued = try conn.replenishConnectionIds(provisions[0..count]);
    next_seq.* += @as(u8, @intCast(queued));
}

fn statelessResetToken(seq: u8) [16]u8 {
    var token: [16]u8 = undefined;
    for (&token, 0..) |*b, i| b.* = seq ^ @as(u8, @truncate(i * 17));
    return token;
}

fn retrySourceCid() [server_cid.len]u8 {
    var cid = server_cid;
    cid[7] +%= 0x80;
    return cid;
}

fn retryToken(
    peer: Net.IpAddress,
    now_us: u64,
    original_dcid: []const u8,
    retry_scid: []const u8,
) !nullq.RetryToken {
    var addr_buf: [32]u8 = undefined;
    const client_address = retryAddressContext(&addr_buf, peer);
    return try nullq.retry_token.minted(.{
        .key = &retry_token_key,
        .now_us = now_us,
        .lifetime_us = retry_token_lifetime_us,
        .client_address = client_address,
        .original_dcid = original_dcid,
        .retry_scid = retry_scid,
    });
}

fn validRetryToken(
    peer: Net.IpAddress,
    now_us: u64,
    original_dcid: []const u8,
    retry_scid: []const u8,
    token: []const u8,
) bool {
    var addr_buf: [32]u8 = undefined;
    const client_address = retryAddressContext(&addr_buf, peer);
    return nullq.retry_token.validate(token, .{
        .key = &retry_token_key,
        .now_us = now_us,
        .client_address = client_address,
        .original_dcid = original_dcid,
        .retry_scid = retry_scid,
    }) == .valid;
}

fn retryAddressContext(dst: []u8, peer: Net.IpAddress) []const u8 {
    var pos: usize = 0;
    switch (peer) {
        .ip4 => |ip4| {
            dst[pos] = 4;
            pos += 1;
            @memcpy(dst[pos .. pos + ip4.bytes.len], &ip4.bytes);
            pos += ip4.bytes.len;
            std.mem.writeInt(u16, dst[pos..][0..2], ip4.port, .big);
            pos += 2;
        },
        .ip6 => |ip6| {
            dst[pos] = 6;
            pos += 1;
            @memcpy(dst[pos .. pos + ip6.bytes.len], &ip6.bytes);
            pos += ip6.bytes.len;
            std.mem.writeInt(u16, dst[pos..][0..2], ip6.port, .big);
            pos += 2;
            std.mem.writeInt(u32, dst[pos..][0..4], ip6.flow, .big);
            pos += 4;
        },
    }
    return dst[0..pos];
}

fn peekInitialToken(bytes: []const u8) ?[]const u8 {
    const parsed = nullq.wire.header.parse(bytes, 0) catch return null;
    return switch (parsed.header) {
        .initial => |initial| initial.token,
        else => null,
    };
}

const LongHeaderIds = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
};

fn peekLongHeaderIds(bytes: []const u8) ?LongHeaderIds {
    if (bytes.len < 6) return null;
    if ((bytes[0] & 0x80) == 0) return null;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    const dcid_len = bytes[5];
    if (dcid_len > 20) return null;
    var pos: usize = 6;
    if (bytes.len < pos + @as(usize, dcid_len) + 1) return null;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = bytes[pos];
    if (scid_len > 20) return null;
    pos += 1;
    if (bytes.len < pos + @as(usize, scid_len)) return null;
    const scid = bytes[pos .. pos + scid_len];

    return .{ .version = version, .dcid = dcid, .scid = scid };
}

test "parse HTTP/0.9 GET path" {
    try std.testing.expectEqualStrings("file", parseGetPath("GET /file\r\n").?);
    try std.testing.expect(parseGetPath("POST /file\r\n") == null);
    try std.testing.expect(parseGetPath("GET /../secret\r\n") == null);
}
