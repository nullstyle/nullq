const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");

const Net = std.Io.net;

const hq_alpn = "hq-interop";
const server_cid_len = 8;
const server_cid_prefix = [_]u8{ 0x51, 0x4e, 0x53, 0x2d }; // "QNS-"
const retry_token_key = [_]u8{
    0x4e, 0x55, 0x4c, 0x4c, 0x51, 0x2d, 0x51, 0x4e,
    0x53, 0x2d, 0x52, 0x45, 0x54, 0x52, 0x59, 0x21,
    0x90, 0x51, 0x43, 0x7b, 0x2d, 0xa4, 0x17, 0x66,
    0x10, 0xe1, 0x44, 0x58, 0x73, 0x88, 0x2b, 0x31,
};
const retry_token_lifetime_us: u64 = 30_000_000;
const endpoint_udp_payload_size = 1350;
const endpoint_connection_receive_window: u64 = 16 * 1024 * 1024;
const endpoint_stream_receive_window: u64 = 16 * 1024 * 1024;
const endpoint_uni_stream_receive_window: u64 = 1024 * 1024;

const ServerOptions = struct {
    listen: []const u8 = "0.0.0.0:443",
    www: []const u8 = "/www",
    cert: []const u8 = "/certs/cert.pem",
    key: []const u8 = "/certs/priv.key",
    keylog_file: ?[]const u8 = null,
    qlog_dir: ?[]const u8 = null,
    retry: bool = false,
};

const ClientOptions = struct {
    server: []const u8 = "server4:443",
    server_name: []const u8 = "server4",
    downloads: []const u8 = "/downloads",
    requests: []const u8 = "",
    testcase: []const u8 = "",
    keylog_file: ?[]const u8 = null,
    qlog_dir: ?[]const u8 = null,
};

const ClientMode = enum {
    normal,
    resumption,
    zerortt,
};

const ClientConnectionOptions = struct {
    session: ?boringssl.tls.Session = null,
    early_data: bool = false,
    wait_for_ticket: ?*TicketStore = null,
    qlog_sink: ?*QlogSink = null,
};

var keylog_io: ?std.Io = null;
var keylog_file: ?std.Io.File = null;

const QlogSink = struct {
    io: std.Io,
    file: std.Io.File,

    fn init(io: std.Io, dir: []const u8, role: []const u8) !QlogSink {
        try std.Io.Dir.cwd().createDirPath(io, dir);
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/nullq-{s}.jsonl", .{ dir, role });
        const file = try createTraceFile(io, path, true);
        return .{ .io = io, .file = file };
    }

    fn deinit(self: *QlogSink) void {
        self.file.close(self.io);
        self.* = undefined;
    }

    fn callback(user_data: ?*anyopaque, event: nullq.QlogEvent) void {
        const self: *QlogSink = @ptrCast(@alignCast(user_data.?));
        self.write(event) catch {};
    }

    fn write(self: *QlogSink, event: nullq.QlogEvent) !void {
        const key_epoch: i128 = if (event.key_epoch) |v| @intCast(v) else -1;
        const key_phase: i8 = if (event.key_phase) |v| if (v) 1 else 0 else -1;
        const packet_number: i128 = if (event.packet_number) |v| @intCast(v) else -1;
        const discard_deadline: i128 = if (event.discard_deadline_us) |v| @intCast(v) else -1;
        var buf: [512]u8 = undefined;
        const line = try std.fmt.bufPrint(
            &buf,
            "{{\"name\":\"{s}\",\"at_us\":{},\"level\":\"{s}\",\"key_epoch\":{},\"key_phase\":{},\"packet_number\":{},\"discard_deadline_us\":{}}}",
            .{
                @tagName(event.name),
                event.at_us,
                @tagName(event.level),
                key_epoch,
                key_phase,
                packet_number,
                discard_deadline,
            },
        );
        try self.file.writeStreamingAll(self.io, line);
        try self.file.writeStreamingAll(self.io, "\n");
    }
};

const TicketStore = struct {
    allocator: std.mem.Allocator,
    latest: ?[]u8 = null,
    failed: bool = false,

    fn init(allocator: std.mem.Allocator) TicketStore {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *TicketStore) void {
        if (self.latest) |bytes| self.allocator.free(bytes);
        self.* = undefined;
    }

    fn capture(self: *TicketStore, ticket: boringssl.tls.Session) void {
        var owned = ticket;
        defer owned.deinit();
        const bytes = owned.toBytes(self.allocator) catch {
            self.failed = true;
            return;
        };
        if (self.latest) |old| self.allocator.free(old);
        self.latest = bytes;
    }

    fn session(self: *TicketStore, ctx: boringssl.tls.Context) !boringssl.tls.Session {
        if (self.failed) return error.SessionTicketCaptureFailed;
        const bytes = self.latest orelse return error.NoSessionTicket;
        return try boringssl.tls.Session.fromBytes(ctx, bytes);
    }
};

const StreamState = struct {
    buf: std.ArrayList(u8) = .empty,
    responded: bool = false,

    fn deinit(self: *StreamState, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
        self.* = undefined;
    }
};

const ClientDownload = struct {
    url: []const u8,
    rel_path: []const u8,
    stream_id: u64,
    response: std.ArrayList(u8) = .empty,
    started: bool = false,
    complete: bool = false,
    written: bool = false,

    fn deinit(self: *ClientDownload, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
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
        if (init.environ_map.get("SSLKEYLOGFILE")) |path| opts.keylog_file = path;
        if (init.environ_map.get("QLOGDIR")) |path| opts.qlog_dir = path;
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "-listen")) {
                opts.listen = args.next() orelse return error.MissingListenAddress;
            } else if (std.mem.eql(u8, arg, "-www")) {
                opts.www = args.next() orelse return error.MissingWwwDirectory;
            } else if (std.mem.eql(u8, arg, "-cert")) {
                opts.cert = args.next() orelse return error.MissingCertificatePath;
            } else if (std.mem.eql(u8, arg, "-key")) {
                opts.key = args.next() orelse return error.MissingKeyPath;
            } else if (std.mem.eql(u8, arg, "-keylog-file")) {
                opts.keylog_file = args.next() orelse return error.MissingKeylogPath;
            } else if (std.mem.eql(u8, arg, "-qlog-dir")) {
                opts.qlog_dir = args.next() orelse return error.MissingQlogDirectory;
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
        var opts: ClientOptions = .{};
        if (init.environ_map.get("REQUESTS")) |requests| opts.requests = requests;
        if (init.environ_map.get("TESTCASE")) |testcase| opts.testcase = testcase;
        if (init.environ_map.get("SSLKEYLOGFILE")) |path| opts.keylog_file = path;
        if (init.environ_map.get("QLOGDIR")) |path| opts.qlog_dir = path;
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "-server")) {
                opts.server = args.next() orelse return error.MissingServerAddress;
            } else if (std.mem.eql(u8, arg, "-server-name")) {
                opts.server_name = args.next() orelse return error.MissingServerName;
            } else if (std.mem.eql(u8, arg, "-downloads")) {
                opts.downloads = args.next() orelse return error.MissingDownloadsDirectory;
            } else if (std.mem.eql(u8, arg, "-requests")) {
                opts.requests = args.next() orelse return error.MissingRequests;
            } else if (std.mem.eql(u8, arg, "-testcase")) {
                opts.testcase = args.next() orelse return error.MissingTestcase;
            } else if (std.mem.eql(u8, arg, "-keylog-file")) {
                opts.keylog_file = args.next() orelse return error.MissingKeylogPath;
            } else if (std.mem.eql(u8, arg, "-qlog-dir")) {
                opts.qlog_dir = args.next() orelse return error.MissingQlogDirectory;
            } else {
                usage();
                return error.UnknownArgument;
            }
        }
        try runClient(allocator, io, opts);
        return;
    }

    usage();
    return error.UnknownCommand;
}

fn usage() void {
    std.debug.print(
        \\usage:
        \\  qns-endpoint server [-listen 0.0.0.0:443] [-www /www] [-cert /certs/cert.pem] [-key /certs/priv.key] [-keylog-file path] [-qlog-dir dir] [-retry]
        \\  qns-endpoint client [-server server:443] [-server-name server] [-downloads /downloads] [-requests "$REQUESTS"] [-testcase "$TESTCASE"] [-keylog-file path] [-qlog-dir dir]
        \\
    , .{});
}

fn createTraceFile(io: std.Io, path: []const u8, truncate: bool) !std.Io.File {
    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0) try std.Io.Dir.cwd().createDirPath(io, parent);
    }
    const flags: std.Io.Dir.CreateFileOptions = .{ .truncate = truncate };
    return if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.createFileAbsolute(io, path, flags)
    else
        try std.Io.Dir.cwd().createFile(io, path, flags);
}

fn enableKeylog(io: std.Io, ctx: *boringssl.tls.Context, path: []const u8) !void {
    closeKeylog(io);
    keylog_file = try createTraceFile(io, path, false);
    keylog_io = io;
    try ctx.setKeylogCallback(writeKeylogLine);
}

fn closeKeylog(io: std.Io) void {
    if (keylog_file) |file| file.close(io);
    keylog_file = null;
    keylog_io = null;
}

fn writeKeylogLine(line: []const u8) void {
    const file = keylog_file orelse return;
    const io = keylog_io orelse return;
    file.writeStreamingAll(io, line) catch return;
    file.writeStreamingAll(io, "\n") catch return;
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
    if (opts.keylog_file) |path| try enableKeylog(io, &server_tls, path);
    defer closeKeylog(io);

    var qlog_sink: ?QlogSink = null;
    if (opts.qlog_dir) |dir| qlog_sink = try QlogSink.init(io, dir, "server");
    defer if (qlog_sink) |*sink| sink.deinit();

    std.debug.print("nullq qns endpoint listening on {f} www={s} retry={}\n", .{ bind_addr, opts.www, opts.retry });

    while (true) {
        var conn = try nullq.Connection.initServer(allocator, server_tls);
        defer conn.deinit();
        if (qlog_sink) |*sink| conn.setQlogCallback(QlogSink.callback, sink);
        try conn.bind();
        const initial_server_cid = randomServerCid(io);
        try conn.setLocalScid(&initial_server_cid);

        var next_cid_seq: u8 = 1;
        try queueServerConnectionIds(&conn, &next_cid_seq, 4, &initial_server_cid);

        var app = Http09App.init(allocator, io, try openDir(io, opts.www));
        defer app.deinit();

        var peer: ?Net.IpAddress = null;
        var transport_params_set = false;
        var retry_sent = false;
        var retry_original_dcid: nullq.conn.path.ConnectionId = .{};
        var retry_source_cid = retrySourceCid(&initial_server_cid);
        var now_us: u64 = 1_000_000;
        var rx: [64 * 1024]u8 = undefined;
        var tx: [endpoint_udp_payload_size]u8 = undefined;

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
                        .initial_source_connection_id = nullq.conn.path.ConnectionId.fromSlice(&initial_server_cid),
                        .retry_source_connection_id = retry_source,
                        .max_idle_timeout_ms = 30_000,
                        .initial_max_data = endpoint_connection_receive_window,
                        .initial_max_stream_data_bidi_local = endpoint_stream_receive_window,
                        .initial_max_stream_data_bidi_remote = endpoint_stream_receive_window,
                        .initial_max_stream_data_uni = endpoint_uni_stream_receive_window,
                        .initial_max_streams_bidi = 128,
                        .initial_max_streams_uni = 16,
                        .max_udp_payload_size = endpoint_udp_payload_size,
                        .active_connection_id_limit = 8,
                    };
                    try conn.acceptInitial(msg.data, params);
                    _ = try conn.setEarlyDataContextForParams(params, hq_alpn, "nullq qns endpoint v1");
                    transport_params_set = true;
                }
                try conn.handle(msg.data, null, now_us);
            }

            if (conn.handshakeDone()) try queueServerConnectionIds(&conn, &next_cid_seq, 8, &initial_server_cid);
            try app.process(&conn);
            while (try conn.poll(&tx, now_us)) |n| {
                if (peer) |p| try sock.send(io, &p, tx[0..n]) else break;
            }
            try conn.tick(now_us);
            now_us += 1_000;
        }
    }
}

fn runClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    opts: ClientOptions,
) !void {
    const downloads = try parseRequestList(allocator, opts.requests);
    defer {
        for (downloads) |*download| download.deinit(allocator);
        allocator.free(downloads);
    }
    if (downloads.len == 0) return error.NoRequests;

    const server_addr = try resolveEndpoint(io, opts.server);
    const protos = [_][]const u8{hq_alpn};
    var client_tls = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    defer client_tls.deinit();
    if (opts.keylog_file) |path| try enableKeylog(io, &client_tls, path);
    defer closeKeylog(io);

    var tickets = TicketStore.init(allocator);
    defer tickets.deinit();
    try client_tls.setNewSessionCallback(captureSessionTicket, &tickets);

    const server_name_z = try allocator.dupeZ(u8, opts.server_name);
    defer allocator.free(server_name_z);

    const mode = clientMode(opts.testcase);
    std.debug.print("nullq qns client connecting to {f} testcase={s} requests={d}\n", .{
        server_addr,
        if (opts.testcase.len == 0) "default" else opts.testcase,
        downloads.len,
    });

    try std.Io.Dir.cwd().createDirPath(io, opts.downloads);
    var downloads_dir = try openDir(io, opts.downloads);
    defer downloads_dir.close(io);

    var qlog_sink: ?QlogSink = null;
    if (opts.qlog_dir) |dir| qlog_sink = try QlogSink.init(io, dir, "client");
    defer if (qlog_sink) |*sink| sink.deinit();

    switch (mode) {
        .normal => try runClientConnection(
            allocator,
            io,
            client_tls,
            server_name_z,
            server_addr,
            downloads_dir,
            downloads,
            .{ .qlog_sink = if (qlog_sink) |*sink| sink else null },
        ),
        .resumption, .zerortt => {
            if (downloads.len < 2) return error.ResumptionRequiresMultipleRequests;
            try runClientConnection(
                allocator,
                io,
                client_tls,
                server_name_z,
                server_addr,
                downloads_dir,
                downloads[0..1],
                .{
                    .wait_for_ticket = &tickets,
                    .qlog_sink = if (qlog_sink) |*sink| sink else null,
                },
            );
            var session = try tickets.session(client_tls);
            defer session.deinit();
            try runClientConnection(
                allocator,
                io,
                client_tls,
                server_name_z,
                server_addr,
                downloads_dir,
                downloads[1..],
                .{
                    .session = session,
                    .early_data = mode == .zerortt,
                    .qlog_sink = if (qlog_sink) |*sink| sink else null,
                },
            );
        },
    }
}

fn captureSessionTicket(user_data: ?*anyopaque, session: boringssl.tls.Session) void {
    const store: *TicketStore = @ptrCast(@alignCast(user_data.?));
    store.capture(session);
}

fn clientMode(testcase: []const u8) ClientMode {
    if (std.mem.eql(u8, testcase, "resumption")) return .resumption;
    if (std.mem.eql(u8, testcase, "zerortt")) return .zerortt;
    return .normal;
}

fn runClientConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    client_tls: boringssl.tls.Context,
    server_name_z: [:0]const u8,
    server_addr: Net.IpAddress,
    downloads_dir: std.Io.Dir,
    downloads: []ClientDownload,
    conn_opts: ClientConnectionOptions,
) !void {
    const bind_addr: Net.IpAddress = switch (server_addr) {
        .ip4 => .{ .ip4 = Net.Ip4Address.unspecified(0) },
        .ip6 => .{ .ip6 = Net.Ip6Address.unspecified(0) },
    };
    const sock = try Net.IpAddress.bind(&bind_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    var conn = try nullq.Connection.initClient(allocator, client_tls, server_name_z);
    defer conn.deinit();
    if (conn_opts.qlog_sink) |sink| conn.setQlogCallback(QlogSink.callback, sink);
    if (conn_opts.session) |session| try conn.setSession(session);
    if (conn_opts.early_data) conn.setEarlyDataEnabled(true);
    try conn.bind();

    var initial_dcid: [8]u8 = undefined;
    var client_scid: [8]u8 = undefined;
    io.random(&initial_dcid);
    io.random(&client_scid);
    try conn.setLocalScid(&client_scid);
    try conn.setInitialDcid(&initial_dcid);
    try conn.setPeerDcid(&initial_dcid);

    const params: nullq.tls.TransportParams = .{
        .initial_source_connection_id = nullq.conn.path.ConnectionId.fromSlice(&client_scid),
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = endpoint_connection_receive_window,
        .initial_max_stream_data_bidi_local = endpoint_stream_receive_window,
        .initial_max_stream_data_bidi_remote = endpoint_uni_stream_receive_window,
        .initial_max_stream_data_uni = endpoint_uni_stream_receive_window,
        .initial_max_streams_bidi = 256,
        .initial_max_streams_uni = 16,
        .max_udp_payload_size = endpoint_udp_payload_size,
        .active_connection_id_limit = 8,
    };
    try conn.setTransportParams(params);

    var requests_enabled = false;
    if (conn_opts.early_data) {
        _ = try startClientRequests(allocator, &conn, downloads);
        requests_enabled = true;
    }
    try conn.advance();

    var now_us: u64 = 1_000_000;
    var idle_us: u64 = 0;
    var rx: [64 * 1024]u8 = undefined;
    var tx: [endpoint_udp_payload_size]u8 = undefined;

    while ((!allDownloadsComplete(downloads) or !ticketRequirementMet(conn_opts.wait_for_ticket)) and !conn.isClosed()) {
        var progressed = false;
        const had_ticket = ticketRequirementMet(conn_opts.wait_for_ticket);

        const maybe_msg = sock.receiveTimeout(io, &rx, .{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(1),
                .clock = .awake,
            },
        }) catch |err| switch (err) {
            error.Timeout => null,
            else => return err,
        };
        if (maybe_msg) |msg| {
            try conn.handle(msg.data, null, now_us);
            progressed = true;
        }

        if (conn.handshakeDone() and !requests_enabled) {
            requests_enabled = true;
        }

        if (requests_enabled) {
            if (try startClientRequests(allocator, &conn, downloads)) progressed = true;
            if (try drainClientResponses(allocator, &conn, downloads)) progressed = true;
            try writeCompletedDownloads(io, downloads_dir, downloads);
        }
        if (!had_ticket and ticketRequirementMet(conn_opts.wait_for_ticket)) {
            std.debug.print("captured session ticket\n", .{});
            progressed = true;
        }

        while (try conn.poll(&tx, now_us)) |n| {
            try sock.send(io, &server_addr, tx[0..n]);
            progressed = true;
        }
        try conn.tick(now_us);

        if (progressed) {
            idle_us = 0;
        } else {
            idle_us += 1_000;
            if (idle_us > 120_000_000) return error.ClientTimeout;
        }
        now_us += 1_000;
    }

    if (!allDownloadsComplete(downloads)) {
        if (conn.closeEvent()) |event| {
            std.debug.print("connection closed before downloads completed: source={s} code={d} reason={s}\n", .{
                @tagName(event.source),
                event.error_code,
                event.reason,
            });
        }
        return error.ConnectionClosedBeforeDownloadsCompleted;
    }
    if (!ticketRequirementMet(conn_opts.wait_for_ticket)) return error.NoSessionTicket;
    if (conn_opts.early_data) {
        std.debug.print("0-RTT status: {s} ({s})\n", .{
            @tagName(conn.earlyDataStatus()),
            conn.earlyDataReason(),
        });
    }

    conn.close(false, 0, "qns downloads complete");
    var flushes: u8 = 0;
    while (flushes < 8) : (flushes += 1) {
        while (try conn.poll(&tx, now_us)) |n| try sock.send(io, &server_addr, tx[0..n]);
        try conn.tick(now_us);
        now_us += 1_000;
    }
}

fn ticketRequirementMet(ticket_store: ?*TicketStore) bool {
    const store = ticket_store orelse return true;
    return store.latest != null;
}

fn parseRequestList(allocator: std.mem.Allocator, requests: []const u8) ![]ClientDownload {
    var list: std.ArrayList(ClientDownload) = .empty;
    errdefer {
        for (list.items) |*download| download.deinit(allocator);
        list.deinit(allocator);
    }

    var it = std.mem.tokenizeAny(u8, requests, " \t\r\n");
    var stream_id: u64 = 0;
    while (it.next()) |url| {
        const rel_path = try requestPathFromUrl(url);
        try list.append(allocator, .{
            .url = url,
            .rel_path = rel_path,
            .stream_id = stream_id,
        });
        stream_id += 4;
    }
    return try list.toOwnedSlice(allocator);
}

fn requestPathFromUrl(url: []const u8) ![]const u8 {
    var path = url;
    if (std.mem.startsWith(u8, path, "https://")) {
        const rest = path["https://".len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.InvalidRequestUrl;
        path = rest[slash + 1 ..];
    } else if (std.mem.startsWith(u8, path, "http://")) {
        const rest = path["http://".len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.InvalidRequestUrl;
        path = rest[slash + 1 ..];
    }

    while (std.mem.startsWith(u8, path, "/")) path = path[1..];
    if (std.mem.indexOfAny(u8, path, "?#")) |end| path = path[0..end];
    if (path.len == 0) return error.InvalidRequestUrl;
    if (std.mem.indexOf(u8, path, "..") != null) return error.InvalidRequestUrl;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.InvalidRequestUrl;
    return path;
}

fn resolveEndpoint(io: std.Io, endpoint: []const u8) !Net.IpAddress {
    if (Net.IpAddress.parseLiteral(endpoint)) |addr| return addr else |_| {}

    const parsed = try splitHostPort(endpoint);
    if (Net.IpAddress.parse(parsed.host, parsed.port)) |addr| return addr else |_| {}

    const host_name = try Net.HostName.init(parsed.host);
    var result_buffer: [32]Net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(Net.HostName.LookupResult) = .init(&result_buffer);
    try Net.HostName.lookup(host_name, io, &results, .{
        .port = parsed.port,
        .family = .ip4,
    });

    while (results.getOne(io)) |result| {
        switch (result) {
            .address => |address| return address,
            .canonical_name => continue,
        }
    } else |err| {
        switch (err) {
            error.Closed => {},
            error.Canceled => |e| return e,
        }
    }
    return error.NoAddressReturned;
}

const HostPort = struct {
    host: []const u8,
    port: u16,
};

fn splitHostPort(endpoint: []const u8) !HostPort {
    if (endpoint.len == 0) return error.InvalidServerAddress;
    if (endpoint[0] == '[') {
        const close = std.mem.indexOfScalar(u8, endpoint, ']') orelse return error.InvalidServerAddress;
        const host = endpoint[1..close];
        if (endpoint.len == close + 1) return .{ .host = host, .port = 443 };
        if (endpoint.len <= close + 2 or endpoint[close + 1] != ':') return error.InvalidServerAddress;
        return .{ .host = host, .port = try parsePort(endpoint[close + 2 ..]) };
    }
    if (std.mem.lastIndexOfScalar(u8, endpoint, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, endpoint[0..colon], ':') != null) return error.InvalidServerAddress;
        return .{ .host = endpoint[0..colon], .port = try parsePort(endpoint[colon + 1 ..]) };
    }
    return .{ .host = endpoint, .port = 443 };
}

fn parsePort(bytes: []const u8) !u16 {
    if (bytes.len == 0) return error.InvalidServerAddress;
    return std.fmt.parseInt(u16, bytes, 10) catch return error.InvalidServerAddress;
}

fn startClientRequests(
    allocator: std.mem.Allocator,
    conn: *nullq.Connection,
    downloads: []ClientDownload,
) !bool {
    var progressed = false;
    for (downloads) |*download| {
        if (download.started) continue;
        _ = conn.openBidi(download.stream_id) catch |err| {
            if (err == error.StreamLimitExceeded) return progressed;
            return err;
        };
        const request = try std.fmt.allocPrint(allocator, "GET /{s}\r\n", .{download.rel_path});
        defer allocator.free(request);
        const written = try conn.streamWrite(download.stream_id, request);
        if (written != request.len) return error.ShortStreamWrite;
        try conn.streamFinish(download.stream_id);
        download.started = true;
        progressed = true;
    }
    return progressed;
}

fn drainClientResponses(
    allocator: std.mem.Allocator,
    conn: *nullq.Connection,
    downloads: []ClientDownload,
) !bool {
    var progressed = false;
    var tmp: [8192]u8 = undefined;
    for (downloads) |*download| {
        if (!download.started or download.complete) continue;

        while (true) {
            const n = try conn.streamRead(download.stream_id, &tmp);
            if (n == 0) break;
            if (download.response.items.len + n > 128 * 1024 * 1024) return error.ResponseTooLarge;
            try download.response.appendSlice(allocator, tmp[0..n]);
            progressed = true;
        }

        const stream = conn.stream(download.stream_id) orelse continue;
        switch (stream.recv.state) {
            .data_recvd, .data_read => {
                download.complete = true;
                progressed = true;
            },
            .reset_recvd, .reset_read => return error.StreamResetByPeer,
            else => {},
        }
    }
    return progressed;
}

fn writeCompletedDownloads(
    io: std.Io,
    downloads_dir: std.Io.Dir,
    downloads: []ClientDownload,
) !void {
    for (downloads) |*download| {
        if (!download.complete or download.written) continue;
        if (std.fs.path.dirname(download.rel_path)) |parent| {
            if (parent.len > 0) try downloads_dir.createDirPath(io, parent);
        }
        try downloads_dir.writeFile(io, .{
            .sub_path = download.rel_path,
            .data = download.response.items,
        });
        std.debug.print("downloaded {s} -> {s} ({d} bytes)\n", .{
            download.url,
            download.rel_path,
            download.response.items.len,
        });
        download.written = true;
    }
}

fn allDownloadsComplete(downloads: []const ClientDownload) bool {
    for (downloads) |download| {
        if (!download.complete or !download.written) return false;
    }
    return true;
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

fn randomServerCid(io: std.Io) [server_cid_len]u8 {
    var cid: [server_cid_len]u8 = undefined;
    @memcpy(cid[0..server_cid_prefix.len], &server_cid_prefix);
    io.random(cid[server_cid_prefix.len..]);
    return cid;
}

fn queueServerConnectionIds(
    conn: *nullq.Connection,
    next_seq: *u8,
    desired_last_seq: u8,
    base_cid: *const [server_cid_len]u8,
) !void {
    const budget = conn.localConnectionIdIssueBudget(0);
    if (budget == 0 or next_seq.* > desired_last_seq) return;

    var cid_storage: [8][server_cid_len]u8 = undefined;
    var provisions: [8]nullq.ConnectionIdProvision = undefined;
    var count: usize = 0;
    var seq = next_seq.*;
    while (seq <= desired_last_seq and count < provisions.len and count < budget) {
        cid_storage[count] = base_cid.*;
        cid_storage[count][7] +%= seq;
        provisions[count] = .{
            .connection_id = cid_storage[count][0..],
            .stateless_reset_token = statelessResetToken(&cid_storage[count], seq),
        };
        count += 1;
        seq += 1;
    }
    if (count == 0) return;

    const queued = try conn.replenishConnectionIds(provisions[0..count]);
    next_seq.* += @as(u8, @intCast(queued));
}

fn statelessResetToken(cid: []const u8, seq: u8) [16]u8 {
    var token: [16]u8 = undefined;
    for (&token, 0..) |*b, i| b.* = seq ^ @as(u8, @truncate(i * 17)) ^ cid[i % cid.len];
    return token;
}

fn retrySourceCid(base_cid: *const [server_cid_len]u8) [server_cid_len]u8 {
    var cid = base_cid.*;
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
    return retryTokenValidationResult(
        peer,
        now_us,
        original_dcid,
        retry_scid,
        token,
    ) == .valid;
}

fn retryTokenValidationResult(
    peer: Net.IpAddress,
    now_us: u64,
    original_dcid: []const u8,
    retry_scid: []const u8,
    token: []const u8,
) nullq.RetryTokenValidationResult {
    var addr_buf: [32]u8 = undefined;
    const client_address = retryAddressContext(&addr_buf, peer);
    return nullq.retry_token.validate(token, .{
        .key = &retry_token_key,
        .now_us = now_us,
        .client_address = client_address,
        .original_dcid = original_dcid,
        .retry_scid = retry_scid,
    });
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

test "Retry-token endpoint validation rejects malformed and replayed probes" {
    const peer = try Net.IpAddress.parseLiteral("127.0.0.1:4444");
    const replay_peer = try Net.IpAddress.parseLiteral("127.0.0.1:4445");
    const original_dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const retry_scid = [_]u8{ 0x52, 0x45, 0x54, 0x52, 0x59, 0x21 };
    var token = try retryToken(peer, 1_000_000, &original_dcid, &retry_scid);

    try std.testing.expect(validRetryToken(
        peer,
        2_000_000,
        &original_dcid,
        &retry_scid,
        &token,
    ));
    try std.testing.expectEqual(nullq.RetryTokenValidationResult.malformed, retryTokenValidationResult(
        peer,
        2_000_000,
        &original_dcid,
        &retry_scid,
        token[0 .. token.len - 1],
    ));
    try std.testing.expectEqual(nullq.RetryTokenValidationResult.invalid, retryTokenValidationResult(
        replay_peer,
        2_000_000,
        &original_dcid,
        &retry_scid,
        &token,
    ));
    try std.testing.expectEqual(nullq.RetryTokenValidationResult.invalid, retryTokenValidationResult(
        peer,
        2_000_000,
        &.{ 1, 2, 3, 4, 5, 6, 7, 9 },
        &retry_scid,
        &token,
    ));
    try std.testing.expectEqual(nullq.RetryTokenValidationResult.expired, retryTokenValidationResult(
        peer,
        1_000_000 + retry_token_lifetime_us + 1,
        &original_dcid,
        &retry_scid,
        &token,
    ));

    std.mem.writeInt(u32, token[1..5], 0x6b3343cf, .big);
    try std.testing.expectEqual(nullq.RetryTokenValidationResult.wrong_version, retryTokenValidationResult(
        peer,
        2_000_000,
        &original_dcid,
        &retry_scid,
        &token,
    ));
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

test "parse QNS request URL paths" {
    try std.testing.expectEqualStrings("index.html", try requestPathFromUrl("https://server:443/index.html"));
    try std.testing.expectEqualStrings("dir/file", try requestPathFromUrl("/dir/file?ignored=yes"));
    try std.testing.expectError(error.InvalidRequestUrl, requestPathFromUrl("https://server:443/../secret"));
}

test "split endpoint host and port" {
    const hp = try splitHostPort("server:443");
    try std.testing.expectEqualStrings("server", hp.host);
    try std.testing.expectEqual(@as(u16, 443), hp.port);

    const default_port = try splitHostPort("server");
    try std.testing.expectEqualStrings("server", default_port.host);
    try std.testing.expectEqual(@as(u16, 443), default_port.port);

    const ip6 = try splitHostPort("[::1]:8443");
    try std.testing.expectEqualStrings("::1", ip6.host);
    try std.testing.expectEqual(@as(u16, 8443), ip6.port);
}

test "QNS client mode follows TESTCASE" {
    try std.testing.expectEqual(ClientMode.normal, clientMode(""));
    try std.testing.expectEqual(ClientMode.normal, clientMode("transfer"));
    try std.testing.expectEqual(ClientMode.resumption, clientMode("resumption"));
    try std.testing.expectEqual(ClientMode.zerortt, clientMode("zerortt"));
}
