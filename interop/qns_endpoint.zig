const std = @import("std");
const quic_zig = @import("quic_zig");
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

// NEW_TOKEN issuance configuration (RFC 9000 §8.1.3 / hardening A.5).
//
// The QNS endpoint emits one NEW_TOKEN per server-side session as soon
// as the handshake is confirmed; returning interop clients echo the
// token in a future Initial's long-header Token field so the server
// can skip the Retry round-trip on that next connection. Validation
// runs before the Retry gate in the QNS Initial-handling loop so a
// valid NEW_TOKEN bypasses Retry entirely; on any failure
// (.malformed, .expired, .invalid) we fall through to Retry exactly
// the way `Server.applyRetryGate` does, so a stale or wrong-source
// token never closes the connection — it simply pays a fresh Retry
// round-trip.
//
// The key below is a deterministic 32-byte constant chosen to match
// the interop reproducibility posture of `retry_token_key`: the
// official QUIC interop runner spawns a fresh server process per
// scenario, so per-process random keys would break cross-test reuse
// of NEW_TOKENs even within a single run. Operators deploying quic_zig
// outside the interop runner should generate a key with
// `boringssl.crypto.rand.fillBytes` and persist it across restarts —
// the per-process choice here is interop-test territory only.
//
// Token persistence policy (caveat for the interop runner):
//   * Lifetime: 1 hour. The interop runner's longest sequence (e.g.
//     handshake + transfer + resumption) finishes well within this
//     window, so a token minted on the first connection of a test
//     remains valid for every subsequent connection.
//   * Rotation: keys never rotate within a process. The interop
//     runner expects deterministic behaviour across the `server`
//     and follow-up `client` invocations; rotation would force a
//     Retry round-trip that the runner doesn't budget for.
//   * Distinct from `retry_token_key`: NEW_TOKEN typically outlives
//     a Retry token by orders of magnitude, and operators rotate the
//     two on different cadences (see `src/conn/new_token.zig`).
const new_token_key = [_]u8{
    0x4e, 0x55, 0x4c, 0x4c, 0x51, 0x2d, 0x51, 0x4e,
    0x53, 0x2d, 0x4e, 0x45, 0x57, 0x54, 0x4b, 0x21,
    0xc1, 0x09, 0x66, 0xb4, 0x7e, 0x53, 0x82, 0x90,
    0x4d, 0x21, 0x9a, 0x6f, 0xee, 0x71, 0x18, 0x42,
};
const new_token_lifetime_us: u64 = 3600 * 1_000_000;
const endpoint_udp_payload_size = 1350;
const endpoint_connection_receive_window: u64 = 16 * 1024 * 1024;
const endpoint_stream_receive_window: u64 = 16 * 1024 * 1024;
const endpoint_uni_stream_receive_window: u64 = 1024 * 1024;
// Capped at 1000 because the quic-interop-runner's `multiplexing`
// testcase asserts `initial_max_streams_bidi <= 1000`
// (`testcases_quic.py:286-288`: "Server set a stream limit > 1000.").
// Raising the initial cap to absorb quiche's 2000-stream pipelined
// burst was tried briefly (commit 77e6bed) and reverted after the
// 2026-05-09 verification matrix showed it broke server ×
// multiplexing × {quic-go, ngtcp2} — the runner deliberately
// validates that servers issue `MAX_STREAMS` dynamically rather
// than statically advertising a huge floor. The actual fix lives
// in `maybeQueueBatchedMaxStreams` in `src/conn/state.zig`, which
// now lowers the credit-return watermark from "1/2 consumed" to
// "1/4 consumed" so MAX_STREAMS reaches the peer before quiche's
// pipelined burst exhausts the initial allotment.
const endpoint_bidi_stream_limit: u64 = 1000;
const endpoint_uni_stream_limit: u64 = 64;
const endpoint_active_connection_id_limit: u64 = 2;
const endpoint_server_cid_desired_last_seq: u8 = 1;
const max_qns_server_connections = 128;
const qns_time_base_us: u64 = 1_000_000;

const ServerOptions = struct {
    // Dual-stack: an IPv6 wildcard socket on Linux (the deployment OS for
    // the official quic-interop-runner) also accepts IPv4 traffic via
    // mapped addresses, since `/proc/sys/net/ipv6/bindv6only` is `0` by
    // default. The runner's `ipv6` testcase needs this — `0.0.0.0:443`
    // wouldn't see a single v6 datagram.
    listen: []const u8 = "[::]:443",
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
    /// Capture inbound NEW_TOKEN frames for replay on a follow-up
    /// connection within the same test run.
    new_token_store: ?*NewTokenStore = null,
    /// Optional pre-captured NEW_TOKEN bytes to embed in the first
    /// Initial's long-header Token field. Lets a follow-up connection
    /// in `resumption` / `zerortt` testcases skip the server's Retry
    /// round-trip when the peer issues NEW_TOKENs.
    initial_token: ?[]const u8 = null,
    /// Drive a single application-key update mid-connection (RFC 9001
    /// §6). The runner's `keyupdate` testcase observes the wire and
    /// expects both endpoints to send packets at `key_phase=1`; the
    /// embedder needs to *initiate* the update — there's no peer-side
    /// signal that triggers one. Set true for `TESTCASE=keyupdate`.
    request_key_update: bool = false,
    /// Trigger one client-initiated active connection migration
    /// (RFC 9000 §9.2) mid-transfer. The runner's `connectionmigration`
    /// testcase tells the client `TESTCASE=transfer` (the migration
    /// is meant to be transparent to the application) and discriminates
    /// the test by its server hostname `server46`. The embedder
    /// detects that hostname and sets this flag; `runClientConnection`
    /// binds a fresh local UDP socket on a kernel-chosen ephemeral
    /// port and calls `Connection.beginClientActiveMigration` once
    /// the handshake has completed and at least one 1-RTT datagram
    /// has flowed. Subsequent `poll` output and inbound recvs are
    /// routed via the new socket.
    request_active_migration: bool = false,
    /// Sleep 750ms before binding the client socket to dodge the
    /// quic-network-simulator's bridge / ns-3-boot packet-drop race.
    /// Only useful for `TESTCASE=longrtt` where the runner's harness
    /// asserts ≥2 ClientHellos on the wire and the dropped PTO retx
    /// causes a false negative. Harmful for `rebind-addr` (the warmup
    /// pushes the first CH into the rebind window so the handshake
    /// CRYPTO bytes get stranded on the pre-rebind 4-tuple). Default
    /// false; the embedder flips it on for longrtt only.
    apply_simulator_warmup: bool = false,
};

var keylog_io: ?std.Io = null;
var keylog_file: ?std.Io.File = null;

const QlogSink = struct {
    io: std.Io,
    file: std.Io.File,

    fn init(io: std.Io, dir: []const u8, role: []const u8) !QlogSink {
        try std.Io.Dir.cwd().createDirPath(io, dir);
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/quic-zig-{s}.jsonl", .{ dir, role });
        const file = try createTraceFile(io, path, true);
        return .{ .io = io, .file = file };
    }

    fn deinit(self: *QlogSink) void {
        self.file.close(self.io);
        self.* = undefined;
    }

    fn callback(user_data: ?*anyopaque, event: quic_zig.QlogEvent) void {
        const self: *QlogSink = @ptrCast(@alignCast(user_data.?));
        self.write(event) catch {};
    }

    fn write(self: *QlogSink, event: quic_zig.QlogEvent) !void {
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

/// Process-local capture store for NEW_TOKEN bytes received on a
/// client-mode connection. The `resumption` and `zerortt` interop
/// scenarios open two back-to-back connections to the same server;
/// when quic_zig pairs with itself or with a peer that issues NEW_TOKEN,
/// we capture the token on the first connection and replay it on
/// the second via `Connection.setInitialToken`. The bytes are
/// borrowed-only inside the callback (per
/// `Connection.setNewTokenCallback`'s contract), so we copy them.
const NewTokenStore = struct {
    allocator: std.mem.Allocator,
    latest: ?[]u8 = null,
    failed: bool = false,

    fn init(allocator: std.mem.Allocator) NewTokenStore {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *NewTokenStore) void {
        if (self.latest) |bytes| self.allocator.free(bytes);
        self.* = undefined;
    }

    fn capture(self: *NewTokenStore, token: []const u8) void {
        const owned = self.allocator.dupe(u8, token) catch {
            self.failed = true;
            return;
        };
        if (self.latest) |old| self.allocator.free(old);
        self.latest = owned;
    }

    fn callback(user_data: ?*anyopaque, token: []const u8) void {
        const self: *NewTokenStore = @ptrCast(@alignCast(user_data.?));
        self.capture(token);
    }
};

const StreamState = struct {
    buf: std.ArrayList(u8) = .empty,
    /// Allocator-owned response bytes that still need to be written to the
    /// send half. Populated once we've parsed the request; flushed across
    /// however many `processStream` calls it takes for `streamWrite` to
    /// accept all of them (the connection short-writes when the per-stream
    /// send queue is full — hardening §8 / `default_max_buffered_send`).
    /// `null` until the response is decided; non-null thereafter.
    response: ?[]u8 = null,
    response_offset: usize = 0,
    responded: bool = false,

    fn deinit(self: *StreamState, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
        if (self.response) |bytes| allocator.free(bytes);
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

    fn process(self: *Http09App, conn: *quic_zig.Connection) !void {
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

    fn processStream(self: *Http09App, conn: *quic_zig.Connection, stream_id: u64) !void {
        const state = try self.stateFor(stream_id);
        if (state.responded) return;

        // Decide the response once, the first time we see the full request.
        // After that, `state.response` carries the bytes we still owe the
        // peer and `processStream` is re-entered each event-loop tick by
        // `Http09App.process` until everything has been accepted by
        // `streamWrite`.
        if (state.response == null) {
            var tmp: [4096]u8 = undefined;
            while (true) {
                const n = try conn.streamRead(stream_id, &tmp);
                if (n == 0) break;
                try state.buf.appendSlice(self.allocator, tmp[0..n]);
            }

            const stream = conn.stream(stream_id) orelse return;
            if (!(stream.recv.state == .data_recvd or stream.recv.state == .data_read)) return;

            if (parseGetPath(state.buf.items)) |rel| {
                state.response = self.readFile(rel) catch |err| switch (err) {
                    error.FileNotFound => try self.allocator.dupe(u8, "404"),
                    else => return err,
                };
            } else {
                state.response = try self.allocator.dupe(u8, "400");
            }
        }

        // Drain whatever the send queue can take this tick. `streamWrite`
        // is allowed to short-write (returns `accepted < data.len`) when
        // the per-stream send buffer is full; we just resume from the
        // updated offset on the next call.
        const buf = state.response.?;
        while (state.response_offset < buf.len) {
            const accepted = try conn.streamWrite(stream_id, buf[state.response_offset..]);
            if (accepted == 0) return;
            state.response_offset += accepted;
        }

        try conn.streamFinish(stream_id);
        state.responded = true;
    }

    fn readFile(self: *Http09App, rel: []const u8) ![]u8 {
        return try self.www_dir.readFileAlloc(self.io, rel, self.allocator, .limited(64 * 1024 * 1024));
    }
};

const ServerConn = struct {
    conn: quic_zig.Connection,
    app: Http09App,
    peer: Net.IpAddress,
    transport_params_set: bool = false,
    retry_sent: bool = false,
    retry_original_dcid: quic_zig.conn.path.ConnectionId = .{},
    retry_source_cid: [server_cid_len]u8,
    initial_server_cid: [server_cid_len]u8,
    /// DCID the peer put on the first Initial we accepted on this
    /// connection. We use it as a routing key in `ownsServerCid` so
    /// that an Initial retransmit from the same peer (e.g. after a
    /// NAT rebinding mid-handshake — see the rebind-addr test) can be
    /// dispatched to this `ServerConn` instead of being misidentified
    /// as a brand-new connection just because the source 4-tuple
    /// changed and the wire DCID is still the peer-chosen pre-handshake
    /// one rather than `initial_server_cid`.
    client_initial_dcid: quic_zig.conn.path.ConnectionId = .{},
    next_cid_seq: u8 = 1,
    last_activity_us: u64,
    /// Latches once we've minted and queued a NEW_TOKEN on this
    /// session. Mirrors `Server.Slot.new_token_emitted` so we issue
    /// at most one NEW_TOKEN per server-side connection (the simplest
    /// policy that still removes the Retry round-trip for returning
    /// clients).
    new_token_emitted: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        server_tls: boringssl.tls.Context,
        www: []const u8,
        qlog_sink: ?*QlogSink,
        peer: Net.IpAddress,
        now_us: u64,
    ) !*ServerConn {
        const self = try allocator.create(ServerConn);
        errdefer allocator.destroy(self);
        self.* = undefined;

        self.conn = try quic_zig.Connection.initServer(allocator, server_tls);
        errdefer self.conn.deinit();

        self.app = Http09App.init(allocator, io, try openDir(io, www));
        errdefer self.app.deinit();

        self.peer = peer;
        self.transport_params_set = false;
        self.retry_sent = false;
        self.retry_original_dcid = .{};
        self.client_initial_dcid = .{};
        self.initial_server_cid = randomServerCid(io);
        self.retry_source_cid = retrySourceCid(&self.initial_server_cid);
        self.next_cid_seq = 1;
        self.last_activity_us = now_us;
        self.new_token_emitted = false;

        if (qlog_sink) |sink| self.conn.setQlogCallback(QlogSink.callback, sink);
        try self.conn.bind();
        try self.conn.setLocalScid(&self.initial_server_cid);
        try queueServerConnectionIds(&self.conn, &self.next_cid_seq, endpoint_server_cid_desired_last_seq, &self.initial_server_cid);
        return self;
    }

    fn destroy(self: *ServerConn, allocator: std.mem.Allocator) void {
        self.app.deinit();
        self.conn.deinit();
        allocator.destroy(self);
    }

    fn ownsServerCid(self: *const ServerConn, cid: []const u8) bool {
        if (std.mem.eql(u8, cid, &self.initial_server_cid)) return true;
        if (self.retry_sent and std.mem.eql(u8, cid, &self.retry_source_cid)) return true;
        // Match Initial-flight retransmits whose wire DCID is still the
        // peer-chosen one (pre-handshake the client hasn't yet switched
        // to using `initial_server_cid`). Without this, a rebind during
        // handshake — same DCID, new 4-tuple — falls through to
        // `findServerConn`'s peer-addr fallback, doesn't match anyone,
        // and spawns a duplicate `ServerConn` that completes a second
        // handshake on top of the first.
        if (self.client_initial_dcid.len > 0 and std.mem.eql(u8, cid, self.client_initial_dcid.slice())) return true;

        var seq: u8 = 1;
        while (seq < self.next_cid_seq) : (seq += 1) {
            var issued = self.initial_server_cid;
            issued[7] +%= seq;
            if (std.mem.eql(u8, cid, &issued)) return true;
        }
        return false;
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
        \\  qns-endpoint server [-listen [::]:443] [-www /www] [-cert /certs/cert.pem] [-key /certs/priv.key] [-keylog-file path] [-qlog-dir dir] [-retry]
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

    // Grow the kernel UDP buffers so a single connection can
    // absorb a burst of ~3000 1350-byte datagrams (a multiplexing
    // stream open or a flight of stream data) without dropping
    // packets at the OS layer. The default of ~200 KiB on Linux
    // and ~9 KiB on macOS holds far fewer than that, and any
    // packet the kernel discards looks like ordinary loss to
    // QUIC — triggering retransmits and obscuring real congestion
    // signals.
    tuneServerSocket(sock.handle);

    // Enable RFC 9000 §13.4 / RFC 3168 IP ECN signaling so the
    // runner's `E` testcase exercises the end-to-end ECN path.
    // Both setsockopts are best-effort; in a sandbox without
    // CAP_NET_ADMIN we silently degrade to the Not-ECT path.
    const ecn_active = enableServerEcn(sock.handle);

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

    std.debug.print("quic_zig qns endpoint listening on {f} www={s} retry={}\n", .{ bind_addr, opts.www, opts.retry });

    var conns: std.ArrayList(*ServerConn) = .empty;
    defer {
        for (conns.items) |server_conn| server_conn.destroy(allocator);
        conns.deinit(allocator);
    }

    const start = std.Io.Timestamp.now(io, .awake);
    var rx: [64 * 1024]u8 = undefined;
    var tx: [endpoint_udp_payload_size]u8 = undefined;
    var cmsg_buf: [quic_zig.transport.default_cmsg_buffer_bytes]u8 = undefined;

    while (true) {
        var now_us = qnsNowUs(io, start);
        // Two recv shapes: when ECN is active we go through
        // `receiveManyTimeout` so the kernel populates the cmsg
        // control buffer with IP_TOS / IPV6_TCLASS bytes. Otherwise
        // the cheaper `receiveTimeout` shape (no control buffer,
        // no cmsg parse).
        var maybe_msg: ?Net.IncomingMessage = null;
        var ecn: quic_zig.transport.EcnCodepoint = .not_ect;
        if (ecn_active) {
            var recv_msg: Net.IncomingMessage = .init;
            recv_msg.control = &cmsg_buf;
            const buf_slice = (&recv_msg)[0..1];
            const ret = sock.receiveManyTimeout(io, buf_slice, &rx, .{}, .{
                .duration = .{
                    .raw = std.Io.Duration.fromMilliseconds(5),
                    .clock = .awake,
                },
            });
            if (ret[0]) |err| switch (err) {
                error.Timeout => {},
                else => return err,
            } else if (ret[1] == 1) {
                ecn = quic_zig.transport.parseEcnFromControl(recv_msg.control);
                maybe_msg = recv_msg;
            }
        } else {
            maybe_msg = sock.receiveTimeout(io, &rx, .{
                .duration = .{
                    .raw = std.Io.Duration.fromMilliseconds(5),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => null,
                else => return err,
            };
        }
        now_us = qnsNowUs(io, start);

        if (maybe_msg) |msg| {
            var server_conn = findServerConn(conns.items, msg.data, msg.from);
            if (server_conn == null) {
                const ids = peekLongHeaderIds(msg.data) orelse {
                    continue;
                };
                if (ids.version != quic_zig.QUIC_VERSION_1) {
                    const n = try writeVersionNegotiation(&tx, msg.data, &.{quic_zig.QUIC_VERSION_1});
                    try sock.send(io, &msg.from, tx[0..n]);
                    continue;
                }
                if (!isInitialLongHeader(msg.data)) {
                    continue;
                }
                if (conns.items.len >= max_qns_server_connections) {
                    std.debug.print("dropping new QNS server connection from {f}: active limit reached\n", .{msg.from});
                    continue;
                }
                const new_conn = try ServerConn.init(
                    allocator,
                    io,
                    server_tls,
                    opts.www,
                    if (qlog_sink) |*sink| sink else null,
                    msg.from,
                    now_us,
                );
                try conns.append(allocator, new_conn);
                server_conn = new_conn;
            }

            const sc = server_conn.?;
            sc.peer = msg.from;
            sc.last_activity_us = now_us;
            if (!sc.transport_params_set) {
                const ids = peekLongHeaderIds(msg.data) orelse {
                    continue;
                };
                if (ids.version != quic_zig.QUIC_VERSION_1) {
                    const n = try writeVersionNegotiation(&tx, msg.data, &.{quic_zig.QUIC_VERSION_1});
                    try sock.send(io, &msg.from, tx[0..n]);
                    continue;
                }

                // NEW_TOKEN check first: a returning interop client
                // that captured a NEW_TOKEN on a prior connection echoes
                // it in this Initial's long-header Token field. A valid
                // NEW_TOKEN means the source is already address-validated
                // and we skip the Retry round-trip even when `-retry` is
                // on. On any failure (.malformed/.expired/.invalid) we
                // fall through to the Retry gate, mirroring
                // `Server.applyRetryGate` so a stale stored token
                // gracefully degrades to a fresh Retry rather than
                // dropping the connection.
                const presented_token = peekInitialToken(msg.data);
                const new_token_validated = blk: {
                    const t = presented_token orelse break :blk false;
                    if (t.len == 0) break :blk false;
                    break :blk validNewToken(msg.from, now_us, t);
                };

                if (opts.retry and !sc.retry_sent and !new_token_validated) {
                    sc.retry_original_dcid = quic_zig.conn.path.ConnectionId.fromSlice(ids.dcid);
                    const token = try retryToken(msg.from, now_us, ids.dcid, &sc.retry_source_cid);
                    const n = try sc.conn.writeRetry(&tx, msg.data, &sc.retry_source_cid, &token);
                    try sock.send(io, &msg.from, tx[0..n]);
                    sc.retry_sent = true;
                    continue;
                }

                const original_dcid = if (sc.retry_sent) sc.retry_original_dcid else quic_zig.conn.path.ConnectionId.fromSlice(ids.dcid);
                // Pin the wire DCID we're about to accept so future
                // Initial retransmits from any peer 4-tuple route here.
                // Pre-Retry: peer-chosen random. Post-Retry:
                // `retry_source_cid` (already covered by `ownsServerCid`,
                // but storing it is harmless and keeps the field
                // semantically meaningful: "the DCID the peer is
                // currently addressing on the Initial wire").
                sc.client_initial_dcid = quic_zig.conn.path.ConnectionId.fromSlice(ids.dcid);
                const retry_source: ?quic_zig.conn.path.ConnectionId = if (sc.retry_sent)
                    quic_zig.conn.path.ConnectionId.fromSlice(&sc.retry_source_cid)
                else
                    null;
                if (sc.retry_sent) {
                    const token = peekInitialToken(msg.data) orelse {
                        continue;
                    };
                    if (!validRetryToken(msg.from, now_us, original_dcid.slice(), &sc.retry_source_cid, token)) {
                        continue;
                    }
                }

                const params: quic_zig.tls.TransportParams = .{
                    .original_destination_connection_id = original_dcid,
                    .initial_source_connection_id = quic_zig.conn.path.ConnectionId.fromSlice(&sc.initial_server_cid),
                    .retry_source_connection_id = retry_source,
                    .max_idle_timeout_ms = 30_000,
                    .initial_max_data = endpoint_connection_receive_window,
                    .initial_max_stream_data_bidi_local = endpoint_stream_receive_window,
                    .initial_max_stream_data_bidi_remote = endpoint_stream_receive_window,
                    .initial_max_stream_data_uni = endpoint_uni_stream_receive_window,
                    .initial_max_streams_bidi = endpoint_bidi_stream_limit,
                    .initial_max_streams_uni = endpoint_uni_stream_limit,
                    .max_udp_payload_size = endpoint_udp_payload_size,
                    .active_connection_id_limit = endpoint_active_connection_id_limit,
                };
                try sc.conn.acceptInitial(msg.data, params);
                _ = try sc.conn.setEarlyDataContextForParams(params, hq_alpn, "quic_zig qns endpoint v1");
                sc.transport_params_set = true;
            }
            try sc.conn.handleWithEcn(msg.data, netAddressToPathAddress(msg.from), ecn, now_us);
        }

        var i: usize = 0;
        while (i < conns.items.len) {
            const sc = conns.items[i];
            if (sc.conn.handshakeDone()) {
                try queueServerConnectionIds(&sc.conn, &sc.next_cid_seq, endpoint_server_cid_desired_last_seq, &sc.initial_server_cid);
                maybeIssueNewToken(sc, now_us);
            }
            try sc.app.process(&sc.conn);
            while (try sc.conn.poll(&tx, now_us)) |n| {
                try sock.send(io, &sc.peer, tx[0..n]);
            }
            try sc.conn.tick(now_us);
            if (sc.conn.isClosed()) {
                sc.destroy(allocator);
                _ = conns.orderedRemove(i);
                continue;
            }
            i += 1;
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
    const aes_hw_override_for_testing: ?bool =
        if (std.mem.eql(u8, opts.testcase, "chacha20")) false else null;
    var client_tls = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
        .aes_hw_override_for_testing = aes_hw_override_for_testing,
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
    std.debug.print("quic_zig qns client connecting to {f} testcase={s} requests={d}\n", .{
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

    // NEW_TOKEN capture (RFC 9000 §8.1.3): inbound NEW_TOKEN frames
    // land here and are replayed on the second connection of
    // resumption / zerortt scenarios. The store outlives both
    // connection invocations.
    var new_tokens = NewTokenStore.init(allocator);
    defer new_tokens.deinit();

    const request_key_update = std.mem.eql(u8, opts.testcase, "keyupdate");
    // The runner's `connectionmigration` testcase doesn't surface as
    // a TESTCASE value on the client side (it sets `TESTCASE=transfer`).
    // Instead the runner discriminates by giving the client a
    // dual-stack hostname `server46:443`; transparent transfer tests
    // use `server4` or `server6`. When we see `server46` in either
    // the SERVER address or the SERVER_NAME env var, we know the
    // client is expected to perform an active migration mid-transfer.
    const request_active_migration = clientShouldActivelyMigrate(opts);
    // Apply the qns simulator-bridge warmup only on `longrtt`; the
    // 2026-05-09 matrix run showed it actively breaks `rebind-addr`
    // (handshake collapses inside the rebind window). See
    // `ClientConnectionOptions.apply_simulator_warmup` for the full
    // rationale.
    const apply_simulator_warmup = std.mem.eql(u8, opts.testcase, "longrtt");

    switch (mode) {
        .normal => try runClientConnection(
            allocator,
            io,
            client_tls,
            server_name_z,
            server_addr,
            downloads_dir,
            downloads,
            .{
                .qlog_sink = if (qlog_sink) |*sink| sink else null,
                .new_token_store = &new_tokens,
                .request_key_update = request_key_update,
                .request_active_migration = request_active_migration,
                .apply_simulator_warmup = apply_simulator_warmup,
            },
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
                    .new_token_store = &new_tokens,
                    .apply_simulator_warmup = apply_simulator_warmup,
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
                    .new_token_store = &new_tokens,
                    .initial_token = new_tokens.latest,
                    .apply_simulator_warmup = apply_simulator_warmup,
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

/// Decide whether this client run should perform a client-initiated
/// active migration. The runner identifies the connectionmigration
/// testcase by its dual-stack server hostname `server46`; we check
/// either field in case the runner ever passes the hostname through
/// just one of them. The TESTCASE env var is unreliable here because
/// `TestCaseConnectionMigration.testname(CLIENT)` returns "transfer".
fn clientShouldActivelyMigrate(opts: ClientOptions) bool {
    if (std.mem.indexOf(u8, opts.server, "server46") != null) return true;
    if (std.mem.indexOf(u8, opts.server_name, "server46") != null) return true;
    return false;
}

fn qnsNowUs(io: std.Io, start: std.Io.Timestamp) u64 {
    const now = std.Io.Timestamp.now(io, .awake);
    const delta = start.durationTo(now).toMicroseconds();
    if (delta <= 0) return qns_time_base_us;
    const delta_us: u64 = @intCast(delta);
    return qns_time_base_us +| delta_us;
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
    var sock = try Net.IpAddress.bind(&bind_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    var sock_owned = true;
    defer if (sock_owned) sock.close(io);

    // Same rationale as runServer: grow OS buffers so bursty
    // server responses (e.g. the multiplexing test's 1999
    // concurrent streams) do not get dropped before we can read
    // them.
    tuneServerSocket(sock.handle);

    // Workaround for a quic-interop-runner harness flakiness, not a
    // QUIC- or transport-layer issue. The runner places client / sim
    // / server in three Docker containers wired through ns-3
    // (`martenseemann/quic-network-simulator`). The sim's `eth0` is
    // put in promiscuous mode and ns-3's `EmuFdNetDeviceHelper`
    // grabs the interface; while ns-3 is still finishing its boot
    // (gratuitous-ARP storm visible at sim_t≈1.4-1.5s in
    // `trace_node_left.pcap`), packets arriving from the client veth
    // get silently dropped by the host bridge before reaching sim's
    // `eth0`. tcpdump inside the client container confirms the
    // kernel did transmit; dumpcap on sim's `eth0` shows nothing
    // arrived. No counter increments anywhere — purely a
    // bridge-layer race.
    //
    // quic_zig is unusual in starting the handshake within microseconds
    // of process start, so its first PTO retransmit (RFC 9002 default
    // PTO = 333+4*166.5 = 999ms) lands smack in the bad window. The
    // longrtt testcase asserts ≥2 ClientHellos on the wire; when the
    // PTO retx is the dropped packet, only one shows up and the test
    // fails. Other implementations have enough socket-setup latency
    // that their retx misses the window.
    //
    // 750ms of warmup is enough to push the first CH (and therefore
    // the +999ms PTO retx) past the bad window in every run we
    // tested. 100ms is not enough; we did not narrow the lower bound
    // beyond that. The warmup is gated on `apply_simulator_warmup`
    // (set only for `TESTCASE=longrtt`): we previously applied it
    // unconditionally on the assumption it was harmless. The
    // 2026-05-09 interop matrix run proved that wrong for
    // `rebind-addr` — the runner's `--first-rebind=1s` lands exactly
    // when the warmup-delayed CH hits the wire, the handshake CRYPTO
    // bytes get stranded on the pre-rebind 4-tuple, and the
    // handshake collapses into bare retransmits. Other testcases
    // either don't rebind (so the warmup is a free 750ms idle) or
    // already have RTTs / timeouts that absorb the sleep without
    // affecting outcomes; either way, only `longrtt` *needs* the
    // workaround.
    //
    // If/when the simulator harness is fixed (see
    // https://github.com/marten-seemann/quic-network-simulator), this
    // sleep can be deleted.
    if (conn_opts.apply_simulator_warmup) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(750), .awake) catch {};
    }

    var conn = try quic_zig.Connection.initClient(allocator, client_tls, server_name_z);
    defer conn.deinit();
    if (conn_opts.qlog_sink) |sink| conn.setQlogCallback(QlogSink.callback, sink);
    if (conn_opts.session) |session| try conn.setSession(session);
    if (conn_opts.early_data) conn.setEarlyDataEnabled(true);
    if (conn_opts.new_token_store) |store| {
        conn.setNewTokenCallback(NewTokenStore.callback, store);
    }
    if (conn_opts.initial_token) |token_bytes| {
        try conn.setInitialToken(token_bytes);
    }
    try conn.bind();

    var initial_dcid: [8]u8 = undefined;
    var client_scid: [8]u8 = undefined;
    io.random(&initial_dcid);
    io.random(&client_scid);
    try conn.setLocalScid(&client_scid);
    try conn.setInitialDcid(&initial_dcid);
    try conn.setPeerDcid(&initial_dcid);

    const params: quic_zig.tls.TransportParams = .{
        .initial_source_connection_id = quic_zig.conn.path.ConnectionId.fromSlice(&client_scid),
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = endpoint_connection_receive_window,
        .initial_max_stream_data_bidi_local = endpoint_stream_receive_window,
        .initial_max_stream_data_bidi_remote = endpoint_uni_stream_receive_window,
        .initial_max_stream_data_uni = endpoint_uni_stream_receive_window,
        .initial_max_streams_bidi = endpoint_bidi_stream_limit,
        .initial_max_streams_uni = endpoint_uni_stream_limit,
        .max_udp_payload_size = endpoint_udp_payload_size,
        .active_connection_id_limit = endpoint_active_connection_id_limit,
    };
    try conn.setTransportParams(params);

    var requests_enabled = false;
    if (conn_opts.early_data) {
        _ = try startClientRequests(allocator, &conn, downloads);
        requests_enabled = true;
    }
    try conn.advance();

    // Enable RFC 9000 §13.4 / RFC 3168 IP ECN signaling on the
    // client socket so the runner's `E` testcase exercises the
    // end-to-end ECN path. Both setsockopts are best-effort; we
    // silently degrade to the Not-ECT path when the kernel rejects
    // (typical on sandboxed CI).
    const ecn_active = enableServerEcn(sock.handle);

    const start = std.Io.Timestamp.now(io, .awake);
    var last_progress_us = qnsNowUs(io, start);
    var rx: [64 * 1024]u8 = undefined;
    var tx: [endpoint_udp_payload_size]u8 = undefined;
    var cmsg_buf: [quic_zig.transport.default_cmsg_buffer_bytes]u8 = undefined;
    var old_cmsg_buf: [quic_zig.transport.default_cmsg_buffer_bytes]u8 = undefined;
    var key_update_done = !conn_opts.request_key_update;

    // Active migration plumbing: when `request_active_migration` is
    // set, the loop binds a fresh local socket once a few 1-RTT
    // datagrams have flowed and calls `Connection.beginClientActiveMigration`.
    // Outbound is then routed via the new socket. The old socket is
    // kept readable for an extra grace window so in-flight server
    // datagrams already addressed to the old port aren't lost while
    // the server's own migration handler swings to our new tuple.
    var migration_pending = conn_opts.request_active_migration;
    var datagrams_sent_since_handshake: u32 = 0;
    var old_sock: ?Net.Socket = null;
    var old_sock_close_deadline_us: ?u64 = null;
    defer if (old_sock) |*s| s.close(io);

    while ((!allDownloadsComplete(downloads) or !ticketRequirementMet(conn_opts.wait_for_ticket)) and !conn.isClosed()) {
        var now_us = qnsNowUs(io, start);
        var progressed = false;
        const had_ticket = ticketRequirementMet(conn_opts.wait_for_ticket);

        var maybe_msg: ?Net.IncomingMessage = null;
        var ecn: quic_zig.transport.EcnCodepoint = .not_ect;
        if (ecn_active) {
            var recv_msg: Net.IncomingMessage = .init;
            recv_msg.control = &cmsg_buf;
            const buf_slice = (&recv_msg)[0..1];
            const ret = sock.receiveManyTimeout(io, buf_slice, &rx, .{}, .{
                .duration = .{
                    .raw = std.Io.Duration.fromMilliseconds(1),
                    .clock = .awake,
                },
            });
            if (ret[0]) |err| switch (err) {
                error.Timeout => {},
                else => return err,
            } else if (ret[1] == 1) {
                ecn = quic_zig.transport.parseEcnFromControl(recv_msg.control);
                maybe_msg = recv_msg;
            }
        } else {
            maybe_msg = sock.receiveTimeout(io, &rx, .{
                .duration = .{
                    .raw = std.Io.Duration.fromMilliseconds(1),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => null,
                else => return err,
            };
        }
        now_us = qnsNowUs(io, start);
        if (maybe_msg) |msg| {
            try conn.handleWithEcn(msg.data, null, ecn, now_us);
            progressed = true;
        }

        // Drain any in-flight datagrams the server already addressed
        // to our pre-migration socket. Closed below once the grace
        // window passes.
        if (old_sock) |*old| {
            var old_maybe_msg: ?Net.IncomingMessage = null;
            var old_ecn: quic_zig.transport.EcnCodepoint = .not_ect;
            if (ecn_active) {
                var recv_msg: Net.IncomingMessage = .init;
                recv_msg.control = &old_cmsg_buf;
                const buf_slice = (&recv_msg)[0..1];
                const ret = old.receiveManyTimeout(io, buf_slice, &rx, .{}, .{
                    .duration = .{
                        .raw = std.Io.Duration.fromMilliseconds(0),
                        .clock = .awake,
                    },
                });
                if (ret[0]) |_| {
                    // Timeout / unknown — treat as "no message."
                } else if (ret[1] == 1) {
                    old_ecn = quic_zig.transport.parseEcnFromControl(recv_msg.control);
                    old_maybe_msg = recv_msg;
                }
            } else {
                old_maybe_msg = old.receiveTimeout(io, &rx, .{
                    .duration = .{
                        .raw = std.Io.Duration.fromMilliseconds(0),
                        .clock = .awake,
                    },
                }) catch |err| switch (err) {
                    error.Timeout => null,
                    else => null,
                };
            }
            if (old_maybe_msg) |msg| {
                try conn.handleWithEcn(msg.data, null, old_ecn, qnsNowUs(io, start));
                progressed = true;
            }
            if (old_sock_close_deadline_us) |deadline| {
                if (now_us >= deadline) {
                    old.close(io);
                    old_sock = null;
                    old_sock_close_deadline_us = null;
                }
            }
        }

        if (conn.handshakeDone() and !requests_enabled) {
            requests_enabled = true;
        }

        if (requests_enabled) {
            if (try startClientRequests(allocator, &conn, downloads)) progressed = true;
            if (try drainClientResponses(allocator, &conn, downloads)) progressed = true;
            try writeCompletedDownloads(io, downloads_dir, downloads);
        }

        // RFC 9001 §6 application key update for the `keyupdate` testcase.
        // Fire as soon as the handshake completes so all subsequent stream
        // traffic rides key_phase=1 — the runner counts packets per phase
        // and needs many on phase=1 from both sides to pass.
        // `requestKeyUpdate` returns `KeyUpdateBlocked` if the prior update
        // is still pending ack or the cooldown hasn't elapsed; treat that
        // as "try again next tick" rather than fatal.
        if (!key_update_done and conn.handshakeDone()) {
            conn.requestKeyUpdate(now_us) catch |err| switch (err) {
                error.KeyUpdateBlocked => {},
                else => return err,
            };
            if (conn.keyUpdateStatus().write_key_phase) {
                key_update_done = true;
                std.debug.print("quic_zig qns client initiated key update\n", .{});
                progressed = true;
            }
        }
        if (!had_ticket and ticketRequirementMet(conn_opts.wait_for_ticket)) {
            std.debug.print("captured session ticket\n", .{});
            progressed = true;
        }

        // RFC 9000 §9.2 client-initiated active migration. Trigger
        // exactly once after the handshake is confirmed and a few
        // 1-RTT datagrams have flowed (i.e. there's an actual transfer
        // in progress for the runner's pcap to capture). We bind a
        // fresh socket on a kernel-chosen ephemeral port; quic_zig core
        // rotates the peer DCID and queues a PATH_CHALLENGE on the
        // active path. Subsequent `poll` output and inbound recvs
        // route through the new socket.
        if (migration_pending and conn.handshakeDone() and datagrams_sent_since_handshake >= 8) migrate: {
            const new_sock = Net.IpAddress.bind(&bind_addr, io, .{
                .mode = .dgram,
                .protocol = .udp,
            }) catch |err| {
                std.debug.print("active migration: bind failed ({s}); skipping\n", .{@errorName(err)});
                migration_pending = false;
                break :migrate;
            };
            tuneServerSocket(new_sock.handle);
            const new_local_addr = sockaddrFromHandle(new_sock.handle);
            conn.beginClientActiveMigration(new_local_addr, now_us) catch |err| {
                std.debug.print("active migration: core refused ({s}); keeping original socket\n", .{@errorName(err)});
                new_sock.close(io);
                migration_pending = false;
                break :migrate;
            };
            std.debug.print("quic_zig qns client active migration to fresh local socket\n", .{});
            old_sock = sock;
            // Hold the old socket readable for ~500 ms so server
            // packets already in-flight to the old port still feed
            // back into Connection.handle. Beyond that, the server's
            // own migration handler will be sending exclusively to
            // the new tuple.
            old_sock_close_deadline_us = now_us +| 500_000;
            sock = new_sock;
            sock_owned = true;
            migration_pending = false;
            progressed = true;
        }

        while (try conn.poll(&tx, now_us)) |n| {
            const first_byte: u8 = if (n > 0) tx[0] else 0;
            const long = (first_byte & 0x80) != 0;
            const long_type: u2 = @intCast((first_byte >> 4) & 0x03);
            const tag: []const u8 = if (!long) "1RTT" else switch (long_type) {
                0 => "Init",
                1 => "0RTT",
                2 => "Hsk ",
                3 => "Retr",
            };
            std.debug.print(
                "[diag-send] t={d}us len={d} {s} b0=0x{x:0>2}\n",
                .{ now_us, n, tag, first_byte },
            );
            sock.send(io, &server_addr, tx[0..n]) catch |err| {
                std.debug.print("[diag-send] FAILED err={s}\n", .{@errorName(err)});
                return err;
            };
            if (conn.handshakeDone()) datagrams_sent_since_handshake +|= 1;
            progressed = true;
        }
        try conn.tick(now_us);

        if (progressed) {
            last_progress_us = now_us;
        } else {
            if (now_us -| last_progress_us > 120_000_000) return error.ClientTimeout;
        }
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
        const now_us = qnsNowUs(io, start);
        while (try conn.poll(&tx, now_us)) |n| try sock.send(io, &server_addr, tx[0..n]);
        try conn.tick(now_us);
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
    conn: *quic_zig.Connection,
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
    conn: *quic_zig.Connection,
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

/// Apply quic_zig's recommended UDP buffer tuning to a freshly bound
/// socket. Errors are reported but not fatal — a tiny CI box that
/// rejects 4 MiB buffers can still run the QNS endpoint, just with
/// the OS-default risk of receive-buffer overflow during bursts.
fn tuneServerSocket(handle: std.posix.socket_t) void {
    quic_zig.transport.applyServerTuning(handle, .{}) catch |err| {
        std.debug.print(
            "warning: could not tune QNS UDP socket buffers ({s}); falling back to OS defaults\n",
            .{@errorName(err)},
        );
        return;
    };
    if (quic_zig.transport.getRecvBufferSize(handle)) |rcv| {
        if (quic_zig.transport.getSendBufferSize(handle)) |snd| {
            std.debug.print(
                "tuned QNS UDP socket: SO_RCVBUF={} bytes, SO_SNDBUF={} bytes\n",
                .{ rcv, snd },
            );
        } else |_| {}
    } else |_| {}
}

/// Set the IP TOS / IPV6 TCLASS sockopt to ECT(0) on outbound and
/// IP_RECVTOS / IPV6_RECVTCLASS on inbound so the kernel surfaces
/// the per-datagram TOS byte via cmsg. Both are best-effort: a
/// kernel that rejects (sandbox without CAP_NET_ADMIN, non-IP
/// socket, IPV6_TCLASS on a strict-IPv4 socket) makes us fall
/// through to the Not-ECT path. RFC 9000 §13.4 calls for ECT(0) by
/// default for QUIC; the runner's `E` testcase observes the
/// resulting CE marks and ACK ECN counts to verify the path.
fn enableServerEcn(handle: std.posix.socket_t) bool {
    quic_zig.transport.setEcnSendMarking(handle, .ect0) catch return false;
    quic_zig.transport.setEcnRecvEnabled(handle, true) catch return false;
    return true;
}

fn findServerConn(conns: []const *ServerConn, bytes: []const u8, from: Net.IpAddress) ?*ServerConn {
    if (peekPacketDcid(bytes)) |dcid| {
        for (conns) |server_conn| {
            if (server_conn.ownsServerCid(dcid)) return server_conn;
        }
    }

    const initial = isInitialLongHeader(bytes);
    for (conns) |server_conn| {
        if (!netAddressEql(server_conn.peer, from)) continue;
        if (!initial) return server_conn;
        if (!server_conn.transport_params_set or !server_conn.conn.handshakeDone()) return server_conn;
    }
    return null;
}

fn peekPacketDcid(bytes: []const u8) ?[]const u8 {
    if (bytes.len == 0) return null;
    if ((bytes[0] & 0x80) != 0) {
        const ids = peekLongHeaderIds(bytes) orelse return null;
        return ids.dcid;
    }
    if (bytes.len < 1 + server_cid_len) return null;
    return bytes[1 .. 1 + server_cid_len];
}

fn isInitialLongHeader(bytes: []const u8) bool {
    if (bytes.len == 0 or (bytes[0] & 0x80) == 0) return false;
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    return long_type_bits == 0;
}

fn netAddressEql(a: Net.IpAddress, b: Net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| a4.port == b4.port and std.mem.eql(u8, &a4.bytes, &b4.bytes),
            else => false,
        },
        .ip6 => |a6| switch (b) {
            .ip6 => |b6| a6.port == b6.port and a6.flow == b6.flow and std.mem.eql(u8, &a6.bytes, &b6.bytes),
            else => false,
        },
    };
}

fn sockaddrFromHandle(handle: std.posix.socket_t) quic_zig.conn.path.Address {
    var sa: std.posix.sockaddr.storage = undefined;
    var sa_len: std.posix.socklen_t = @sizeOf(@TypeOf(sa));
    if (std.c.getsockname(handle, @ptrCast(&sa), &sa_len) != 0) return .{};
    var out: quic_zig.conn.path.Address = .{};
    if (sa.family == std.posix.AF.INET) {
        const v4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&sa));
        out.bytes[0] = 4;
        const ip_bytes: [4]u8 = @bitCast(v4.addr);
        @memcpy(out.bytes[1..5], &ip_bytes);
        std.mem.writeInt(u16, out.bytes[5..7], std.mem.bigToNative(u16, v4.port), .big);
    } else if (sa.family == std.posix.AF.INET6) {
        const v6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(&sa));
        out.bytes[0] = 6;
        @memcpy(out.bytes[1..17], &v6.addr);
        std.mem.writeInt(u16, out.bytes[17..19], std.mem.bigToNative(u16, v6.port), .big);
    }
    return out;
}

fn netAddressToPathAddress(addr: Net.IpAddress) quic_zig.conn.path.Address {
    var out: quic_zig.conn.path.Address = .{};
    switch (addr) {
        .ip4 => |ip4| {
            out.bytes[0] = 4;
            @memcpy(out.bytes[1..5], &ip4.bytes);
            std.mem.writeInt(u16, out.bytes[5..7], ip4.port, .big);
        },
        .ip6 => |ip6| {
            out.bytes[0] = 6;
            @memcpy(out.bytes[1..17], &ip6.bytes);
            std.mem.writeInt(u16, out.bytes[17..19], ip6.port, .big);
            out.bytes[19] = @truncate(ip6.flow >> 16);
            out.bytes[20] = @truncate(ip6.flow >> 8);
            out.bytes[21] = @truncate(ip6.flow);
        },
    }
    return out;
}

fn writeVersionNegotiation(
    dst: []u8,
    client_packet: []const u8,
    supported_versions: []const u32,
) !usize {
    if (supported_versions.len == 0 or supported_versions.len > 16) return error.InvalidVersionNegotiation;
    const ids = peekLongHeaderIds(client_packet) orelse return error.InvalidVersionNegotiation;

    var versions_bytes: [16 * 4]u8 = undefined;
    for (supported_versions, 0..) |version, i| {
        std.mem.writeInt(u32, versions_bytes[i * 4 ..][0..4], version, .big);
    }

    return try quic_zig.wire.header.encode(dst, .{ .version_negotiation = .{
        .dcid = try quic_zig.wire.header.ConnId.fromSlice(ids.scid),
        .scid = try quic_zig.wire.header.ConnId.fromSlice(ids.dcid),
        .versions_bytes = versions_bytes[0 .. supported_versions.len * 4],
    } });
}

fn randomServerCid(io: std.Io) [server_cid_len]u8 {
    var cid: [server_cid_len]u8 = undefined;
    @memcpy(cid[0..server_cid_prefix.len], &server_cid_prefix);
    io.random(cid[server_cid_prefix.len..]);
    return cid;
}

fn queueServerConnectionIds(
    conn: *quic_zig.Connection,
    next_seq: *u8,
    desired_last_seq: u8,
    base_cid: *const [server_cid_len]u8,
) !void {
    const budget = conn.localConnectionIdIssueBudget(0);
    if (budget == 0 or next_seq.* > desired_last_seq) return;

    var cid_storage: [8][server_cid_len]u8 = undefined;
    var provisions: [8]quic_zig.ConnectionIdProvision = undefined;
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
) !quic_zig.RetryToken {
    var addr_buf: [32]u8 = undefined;
    const client_address = retryAddressContext(&addr_buf, peer);
    return try quic_zig.retry_token.minted(.{
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
) quic_zig.RetryTokenValidationResult {
    var addr_buf: [32]u8 = undefined;
    const client_address = retryAddressContext(&addr_buf, peer);
    return quic_zig.retry_token.validate(token, .{
        .key = &retry_token_key,
        .now_us = now_us,
        .client_address = client_address,
        .original_dcid = original_dcid,
        .retry_scid = retry_scid,
    });
}

fn retryAddressContext(dst: []u8, peer: Net.IpAddress) []const u8 {
    // The bound context fits inside `retry_token.max_address_len`
    // (22 bytes, mirroring `path.Address.bytes`). The v6 form is
    // 1 (family) + 16 (addr) + 2 (port) = 19 bytes; we deliberately
    // omit the 4-byte IPv6 flow label so the budget is met. Including
    // the flow label was the original shape but pushed the v6 form to
    // 23 bytes — `validateBoundInputs` (`src/conn/retry_token.zig`)
    // returns `Error.ContextTooLong`, and the qns server crashed on
    // every IPv4-mapped-IPv6 client (every quic-interop-runner peer
    // since the wrapper started inheriting the binary's `[::]:443`
    // dual-stack default). The flow label adds no useful binding —
    // it's a hint for ECMP routing, not part of peer identity.
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
        },
    }
    return dst[0..pos];
}

/// Mint a NEW_TOKEN bound to `peer`. The address-binding shape mirrors
/// `quic_zig.Server.addressContext` (the full 22-byte `path.Address`
/// buffer) so a NEW_TOKEN minted by the QNS endpoint round-trips
/// identically through `Server.applyRetryGate`'s NEW_TOKEN path on a
/// follow-up connection — useful when the interop runner pairs a
/// quic_zig server with a third-party client that simply echoes the
/// token bytes verbatim.
fn newToken(peer: Net.IpAddress, now_us: u64) !quic_zig.conn.NewTokenBlob {
    const addr = netAddressToPathAddress(peer);
    var token: quic_zig.conn.NewTokenBlob = undefined;
    _ = try quic_zig.conn.new_token.mint(&token, .{
        .key = &new_token_key,
        .now_us = now_us,
        .lifetime_us = new_token_lifetime_us,
        .client_address = &addr.bytes,
    });
    return token;
}

fn validNewToken(peer: Net.IpAddress, now_us: u64, token: []const u8) bool {
    return newTokenValidationResult(peer, now_us, token) == .valid;
}

fn newTokenValidationResult(
    peer: Net.IpAddress,
    now_us: u64,
    token: []const u8,
) quic_zig.conn.NewTokenValidationResult {
    const addr = netAddressToPathAddress(peer);
    return quic_zig.conn.new_token.validate(token, .{
        .key = &new_token_key,
        .now_us = now_us,
        .client_address = &addr.bytes,
    });
}

/// Mint a single NEW_TOKEN once the handshake is confirmed and queue
/// it for transmission on `sc.conn`. Idempotent: the
/// `new_token_emitted` latch ensures we issue at most one per session.
/// Mirror to `Server.maybeIssueNewToken`. All failure modes here are
/// not peer-reachable (BoringSSL CSPRNG + AEAD seal under fixed-size
/// inputs); we silently skip issuance and the source pays a fresh
/// Retry round-trip on its next connection — exactly the gracefully-
/// degrades posture documented at the NEW_TOKEN config block above.
fn maybeIssueNewToken(sc: *ServerConn, now_us: u64) void {
    if (sc.new_token_emitted) return;
    if (!sc.conn.handshakeDone()) return;

    var token = newToken(sc.peer, now_us) catch return;
    sc.conn.queueNewToken(&token) catch return;
    sc.new_token_emitted = true;
}

fn peekInitialToken(bytes: []const u8) ?[]const u8 {
    const parsed = quic_zig.wire.header.parse(bytes, 0) catch return null;
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
    try std.testing.expectEqual(quic_zig.RetryTokenValidationResult.malformed, retryTokenValidationResult(
        peer,
        2_000_000,
        &original_dcid,
        &retry_scid,
        token[0 .. token.len - 1],
    ));
    try std.testing.expectEqual(quic_zig.RetryTokenValidationResult.invalid, retryTokenValidationResult(
        replay_peer,
        2_000_000,
        &original_dcid,
        &retry_scid,
        &token,
    ));
    try std.testing.expectEqual(quic_zig.RetryTokenValidationResult.invalid, retryTokenValidationResult(
        peer,
        2_000_000,
        &.{ 1, 2, 3, 4, 5, 6, 7, 9 },
        &retry_scid,
        &token,
    ));
    try std.testing.expectEqual(quic_zig.RetryTokenValidationResult.expired, retryTokenValidationResult(
        peer,
        1_000_000 + retry_token_lifetime_us + 1,
        &original_dcid,
        &retry_scid,
        &token,
    ));

    // §4.3 hardening (B2): Retry tokens are now AES-GCM-256-sealed,
    // so the v1 trick of corrupting bytes[1..5] (the cleartext version
    // field) doesn't hit the `.wrong_version` path under v2 — those
    // bytes are AEAD nonce now, and corrupting them yields
    // `.malformed` (auth fail). To drive `.wrong_version` properly
    // under v2 we mint with one version and validate against another:
    // the AEAD opens cleanly, the recovered plaintext version doesn't
    // match `opts.quic_version`, so the validator returns
    // `.wrong_version` exactly as the §4.3 path is documented to.
    var addr_buf2: [32]u8 = undefined;
    const wrong_version_token = try quic_zig.retry_token.minted(.{
        .key = &retry_token_key,
        .now_us = 1_000_000,
        .lifetime_us = retry_token_lifetime_us,
        .client_address = retryAddressContext(&addr_buf2, peer),
        .original_dcid = &original_dcid,
        .retry_scid = &retry_scid,
        .quic_version = 0x6b3343cf,
    });
    try std.testing.expectEqual(quic_zig.RetryTokenValidationResult.wrong_version, retryTokenValidationResult(
        peer,
        2_000_000,
        &original_dcid,
        &retry_scid,
        &wrong_version_token,
    ));
}

test "NEW_TOKEN endpoint validation accepts a fresh token, rejects expired, rejects address mismatch" {
    const peer = try Net.IpAddress.parseLiteral("127.0.0.1:4444");
    const wrong_peer = try Net.IpAddress.parseLiteral("127.0.0.1:4445");

    // Fresh mint at t=1_000_000 with the QNS endpoint's lifetime.
    const token = try newToken(peer, 1_000_000);

    // Same peer, well within the lifetime window: .valid.
    try std.testing.expect(validNewToken(peer, 2_000_000, &token));
    try std.testing.expectEqual(
        quic_zig.conn.NewTokenValidationResult.valid,
        newTokenValidationResult(peer, 2_000_000, &token),
    );

    // Different source address (different port — `path.Address.bytes`
    // includes the port at offset 5..7 for IPv4) -> .invalid.
    try std.testing.expectEqual(
        quic_zig.conn.NewTokenValidationResult.invalid,
        newTokenValidationResult(wrong_peer, 2_000_000, &token),
    );

    // Past the issuance lifetime -> .expired.
    try std.testing.expectEqual(
        quic_zig.conn.NewTokenValidationResult.expired,
        newTokenValidationResult(peer, 1_000_000 + new_token_lifetime_us + 1, &token),
    );

    // Truncating the wire blob breaks the fixed-length gate -> .malformed.
    try std.testing.expectEqual(
        quic_zig.conn.NewTokenValidationResult.malformed,
        newTokenValidationResult(peer, 2_000_000, token[0 .. token.len - 1]),
    );

    // Sanity: the gate-side `validNewToken` helper used by the
    // Initial-handling loop returns false for every non-`.valid`
    // outcome (matches `Server.applyRetryGate`'s NEW_TOKEN
    // fall-through posture).
    try std.testing.expect(!validNewToken(wrong_peer, 2_000_000, &token));
    try std.testing.expect(!validNewToken(peer, 1_000_000 + new_token_lifetime_us + 1, &token));
    try std.testing.expect(!validNewToken(peer, 2_000_000, token[0 .. token.len - 1]));

    // §4.3-style cross-version mismatch: a token minted under QUIC v2
    // wire-shape must not authenticate against the QNS endpoint's
    // v1-only validator (NEW_TOKEN binds the version inside the AEAD
    // plaintext, not the on-wire format).
    const addr = netAddressToPathAddress(peer);
    var v2_token: quic_zig.conn.NewTokenBlob = undefined;
    _ = try quic_zig.conn.new_token.mint(&v2_token, .{
        .key = &new_token_key,
        .now_us = 1_000_000,
        .lifetime_us = new_token_lifetime_us,
        .client_address = &addr.bytes,
        .quic_version = 0x6b3343cf,
    });
    try std.testing.expectEqual(
        quic_zig.conn.NewTokenValidationResult.wrong_version,
        newTokenValidationResult(peer, 2_000_000, &v2_token),
    );
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
