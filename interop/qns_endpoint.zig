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
// Symmetric to `endpoint_server_cid_desired_last_seq`: the client
// also issues one extra SCID (sequence 1) once the handshake
// completes so the server has a fresh DCID available for path
// rotation under RFC 9000 §5.1.2 ¶1 / §9.5. Without this, the
// `rebind-addr` testcase fails on the server side (e.g. quic-go
// logs `skipping validation of new path … since no connection ID
// is available`) because the only client-issued CID is the initial
// one and the server cannot reuse it on a new path.
const endpoint_client_cid_desired_last_seq: u8 = 1;
const max_qns_server_connections = 128;
const qns_time_base_us: u64 = 1_000_000;

// IPv4 + IPv6 addresses the runner statically assigns to the SERVER
// container on the rightnet bridge (per `docker-compose.yml`). The
// `connectionmigration` testcase needs the server's `preferred_address`
// transport parameter to advertise reachable IPs, and the runner does
// not surface its own assignment as an env var — every published QNS
// endpoint either hardcodes these or peeks at the local interfaces.
// Hardcoding is the simpler path for the interop fixture: the runner
// is the only environment that actually exercises this binary, and
// the addresses are stable across runs (changing them would force
// every interop endpoint in the matrix to drop).
const interop_runner_server_ipv4: [4]u8 = .{ 193, 167, 100, 100 };
const interop_runner_server_ipv6: [16]u8 = .{
    0xfd, 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
};

// 32-byte HMAC key used to derive stateless-reset tokens for the qns
// server (RFC 9000 §10.3). Mirrors `retry_token_key` and `new_token_key`
// in posture: a deterministic constant chosen so that the interop
// runner — which spawns a fresh server process per scenario — keeps
// reset tokens stable across the run, including for the seq-1 alt-CID
// the `preferred_address` transport parameter advertises (RFC 9000
// §18.2 / §5.1.1). Operators deploying quic_zig outside the interop
// runner should generate a key with `quic_zig.conn.stateless_reset.generateKey`
// and persist it across restarts so a cold-start doesn't invalidate
// every previously-issued reset token. The qns is interop-test
// territory; reproducibility wins over per-process randomness.
const stateless_reset_key: quic_zig.conn.stateless_reset.Key = .{
    0x4e, 0x55, 0x4c, 0x4c, 0x51, 0x2d, 0x51, 0x4e,
    0x53, 0x2d, 0x53, 0x52, 0x2d, 0x4b, 0x45, 0x59,
    0xa0, 0x18, 0x6b, 0x52, 0xc4, 0xd1, 0x33, 0x7e,
    0x29, 0x4f, 0xb6, 0x71, 0xe2, 0x88, 0x95, 0x6a,
};

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
    /// Optional alt-port literal (e.g. `"[::]:444"`) — only the
    /// PORT is consumed. When set, the server builds a
    /// `quic_zig.PreferredAddressConfig` whose v4/v6 addresses come
    /// from the runner-bridge `interop_runner_server_ipv4` /
    /// `_ipv6` constants and whose port comes from this literal.
    /// Mirroring the public-API `runUdpServer`'s pattern, the loop
    /// then binds one alt-listener per configured family (v4 first,
    /// then v6) and polls every bound socket per iteration. The
    /// `preferred_address` transport parameter (RFC 9000 §18.2) the
    /// server advertises points at the same address pair, with the
    /// seq-1 alt-CID + matching stateless-reset token minted per-
    /// connection through the public
    /// `quic_zig.conn.stateless_reset.derive` helper. The runner's
    /// `connectionmigration` testcase relies on this server-
    /// initiated migration: the client receives the parameter,
    /// registers the alt-CID at sequence 1, and migrates to the
    /// alt-address mid-transfer. Wired in via `-pref-addr [::]:444`
    /// from `interop/qns/run_endpoint.sh` only when
    /// `TESTCASE=connectionmigration`.
    pref_addr: ?[]const u8 = null,
    /// QUIC wire-format versions this server accepts. The first
    /// entry is the server's preferred wire version; remaining
    /// entries are alternates the server is willing to advertise via
    /// the `version_information` (codepoint 0x11) transport parameter
    /// for RFC 9368 §6 compatible-version-negotiation upgrade. Defaults
    /// to v1-only so legacy interop testcases keep their historical
    /// posture; `TESTCASE=versionnegotiation` or `TESTCASE=v2` flips
    /// this to `[QUIC_V2, QUIC_V1]` so the server advertises v2 as
    /// preferred and upgrades any v1-wire ClientHello whose
    /// `version_information` includes v2. The runner's actual testcase
    /// name for compatible-version-negotiation is `v2` (per
    /// `quic-interop-runner/testcases_quic.py:TestCaseV2`); the
    /// `versionnegotiation` value is kept for parity with internal
    /// scripts that pre-date the runner's renaming.
    versions: []const u32 = &.{quic_zig.QUIC_VERSION_1},
};

const ClientOptions = struct {
    server: []const u8 = "server4:443",
    server_name: []const u8 = "server4",
    downloads: []const u8 = "/downloads",
    requests: []const u8 = "",
    testcase: []const u8 = "",
    keylog_file: ?[]const u8 = null,
    qlog_dir: ?[]const u8 = null,
    /// QUIC wire-format versions this client offers. The first entry
    /// is the wire version of the outbound Initial; remaining entries
    /// are alternates emitted in the `version_information` (codepoint
    /// 0x11) transport parameter (RFC 9368 §5) so a multi-version
    /// server can pick the highest-priority overlap and upgrade.
    /// Defaults to v1-only; `TESTCASE=versionnegotiation` or
    /// `TESTCASE=v2` flips this to `[QUIC_V1, QUIC_V2]` so the client
    /// sends a v1 wire Initial while advertising v2 as a compatible
    /// upgrade target. The runner's actual testcase name for the
    /// compatible-version-negotiation cell is `v2`.
    versions: []const u32 = &.{quic_zig.QUIC_VERSION_1},
};

/// Pick the QUIC wire-format version list for the server role given a
/// runner-supplied `TESTCASE` value. Returns `[QUIC_V2, QUIC_V1]` for
/// `versionnegotiation` and `v2` (server prefers v2; if the client
/// offers v2 in `version_information`, the server upgrades), and the
/// v1-only default otherwise. The caller is expected to pass the
/// env-var contents verbatim — empty string maps to "default".
///
/// The runner's compatible-version-negotiation testcase name is `v2`
/// (`quic-interop-runner/testcases_quic.py:TestCaseV2`); the
/// `versionnegotiation` alias is preserved because it pre-dates the
/// runner rename and is still referenced by internal scripts.
fn serverVersionsForTestcase(testcase: []const u8) []const u32 {
    if (isVersionNegotiationTestcase(testcase)) {
        return &qns_versions_v2_first;
    }
    return &.{quic_zig.QUIC_VERSION_1};
}

/// Pick the QUIC wire-format version list for the client role given a
/// runner-supplied `TESTCASE` value. Returns `[QUIC_V1, QUIC_V2]` for
/// `versionnegotiation` and `v2` (client sends a v1 wire Initial but
/// advertises v2 as a compatible target via `version_information`),
/// and the v1-only default otherwise. Note the inverse ordering vs.
/// `serverVersionsForTestcase`: the first entry is the wire version,
/// not the preferred version, so `[v1, v2]` keeps the wire compatible
/// with v1-only servers while letting a multi-version server upgrade.
///
/// See `serverVersionsForTestcase` for the rationale on why both
/// `versionnegotiation` and `v2` are accepted.
fn clientVersionsForTestcase(testcase: []const u8) []const u32 {
    if (isVersionNegotiationTestcase(testcase)) {
        return &qns_versions_v1_first;
    }
    return &.{quic_zig.QUIC_VERSION_1};
}

/// Is this `TESTCASE` value the runner's compatible-version-negotiation
/// cell? The runner ships it as `v2` (per
/// `quic-interop-runner/testcases_quic.py:TestCaseV2`); the historical
/// `versionnegotiation` alias is also accepted so this binary keeps
/// working with internal harnesses that pre-date the runner's name.
inline fn isVersionNegotiationTestcase(testcase: []const u8) bool {
    return std.mem.eql(u8, testcase, "v2") or
        std.mem.eql(u8, testcase, "versionnegotiation");
}

/// Module-level constant slices so the `versionsForTestcase` helpers
/// can return a stable `[]const u32` view rather than constructing a
/// fresh array each call.
const qns_versions_v2_first = [_]u32{ quic_zig.QUIC_VERSION_2, quic_zig.QUIC_VERSION_1 };
const qns_versions_v1_first = [_]u32{ quic_zig.QUIC_VERSION_1, quic_zig.QUIC_VERSION_2 };

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
    /// QUIC wire-format versions this client offers. The first entry
    /// drives the wire version of the outbound Initial; remaining
    /// entries flow into `params.compatibleVersions` (the
    /// `version_information` codepoint 0x11 transport parameter, RFC
    /// 9368 §5) so a multi-version server can pick the highest-
    /// priority overlap and upgrade. Defaults to v1-only;
    /// `TESTCASE=versionnegotiation` flips this to `[QUIC_V1, QUIC_V2]`.
    versions: []const u32 = &.{quic_zig.QUIC_VERSION_1},
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

    /// Which of the bound listening sockets received the most recent
    /// authenticated datagram for this connection. 0 = main port,
    /// 1+ = preferred-address alt-listener(s) (one per family, in the
    /// order `runUdpServer`-style alt binds: v4 first if present,
    /// then v6). The qns server uses this to pick the outbound
    /// socket: once a peer has migrated to the preferred address
    /// (RFC 9000 §5.1.1, §18.2), all subsequent inbound datagrams
    /// arrive on the alt-listener and outbound replies must follow.
    ///
    /// We track this on the embedder (this struct) rather than the
    /// `Connection` because per-path `local_addr` bookkeeping in the
    /// core is informational only — the routing decision lives
    /// entirely above the public API. A naive alternative would be
    /// to inspect `OutgoingDatagram.to.port`, but that's the *peer's*
    /// destination, not our local socket; the local-port is a
    /// property of which UDP socket we received on, and the simplest
    /// way to surface it to the send side is the latch below.
    last_recv_socket: u8 = 0,

    /// Pre-minted seq-1 server CID for the `preferred_address`
    /// (RFC 9000 §18.2 / §5.1.1) advertisement, when one is configured
    /// at runtime. Drawn from the CSPRNG at `ServerConn.init` (mirrors
    /// what `Server.openSlotFromInitial` does in the public API path)
    /// so the alt-CID lives in the same routing-encoded space as the
    /// seq-0 SCID rather than in the older deterministic
    /// `cid[7] +%= 1` derivation. Both `buildPreferredAddress` (which
    /// stamps the CID + matching stateless-reset token into the
    /// transport-parameter blob) and `queueServerConnectionIds` (which
    /// emits the matching NEW_CONNECTION_ID(seq=1) frame) read from
    /// this single source of truth so the two on-wire surfaces describe
    /// the same CID.
    ///
    /// Zero-initialized when no `preferred_address` is configured;
    /// `pa_alt_cid_set` discriminates.
    pa_alt_cid: [server_cid_len]u8 = @splat(0),
    /// Matching stateless-reset token for `pa_alt_cid` derived via
    /// `quic_zig.conn.stateless_reset.derive(stateless_reset_key,
    /// pa_alt_cid)` at `ServerConn.init`. Cached so the per-Initial
    /// hot path doesn't re-run the HMAC, and so the seq-1
    /// NEW_CONNECTION_ID emitted by `queueServerConnectionIds` carries
    /// the same token bytes the transport-parameter advertise pinned.
    pa_alt_token: quic_zig.conn.stateless_reset.Token = @splat(0),
    /// Latches when the preferred-address alt-CID + token have been
    /// minted on this connection. Stays false when no
    /// `preferred_address` is configured; `dispatchInbound` and
    /// `queueServerConnectionIds` consult this to decide whether to
    /// advertise the parameter and queue the seq-1 frame.
    pa_alt_cid_set: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        server_tls: boringssl.tls.Context,
        www: []const u8,
        qlog_sink: ?*QlogSink,
        peer: Net.IpAddress,
        now_us: u64,
        /// True when the runtime configuration has a `preferred_address`
        /// to advertise (`runServer` set up at least one alt listener);
        /// drives the seq-1 alt-CID mint below. When false, the seq-1
        /// CID is still derived deterministically from the seq-0 SCID
        /// the way `queueServerConnectionIds` always has — no behavior
        /// change for the non-PA scenarios that interop runs.
        pa_advertise: bool,
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
        self.last_recv_socket = 0;
        self.pa_alt_cid = @splat(0);
        self.pa_alt_token = @splat(0);
        self.pa_alt_cid_set = false;

        // Mint the seq-1 preferred-address alt-CID via the CSPRNG and
        // derive its matching stateless-reset token via the public
        // `quic_zig.conn.stateless_reset.derive` helper. Mirrors what
        // `Server.openSlotFromInitial` does for `Config.preferred_address`
        // so the qns becomes a clean reference embedder of the public
        // API rather than a parallel deterministic implementation.
        // Failure to mint the token is non-fatal for the rest of the
        // connection: we leave `pa_alt_cid_set = false` and the
        // dispatch path simply does not advertise the parameter for
        // this connection — the rest of the handshake proceeds as if
        // no preferred-address were configured. The HMAC failure mode
        // is not peer-reachable (BoringSSL HMAC over fixed-size inputs)
        // but the silent-degrade matches the qns's existing posture
        // for `maybeIssueNewToken` and similar best-effort hardening.
        if (pa_advertise) {
            const cid_slice = self.pa_alt_cid[0..];
            io.random(cid_slice);
            // Steer clear of accidentally aliasing the seq-0 SCID — a
            // 64-bit collision is astronomically unlikely but the
            // `cid_table` upstream rejects duplicate registrations and
            // we don't want a single coincidence to take out a
            // connection. Cheap to re-roll one byte in the rare case.
            if (std.mem.eql(u8, cid_slice, &self.initial_server_cid)) {
                cid_slice[0] +%= 1;
            }
            const token = quic_zig.conn.stateless_reset.derive(&stateless_reset_key, cid_slice) catch null;
            if (token) |t| {
                self.pa_alt_token = t;
                self.pa_alt_cid_set = true;
            }
        }

        if (qlog_sink) |sink| self.conn.setQlogCallback(QlogSink.callback, sink);
        try self.conn.bind();
        try self.conn.setLocalScid(&self.initial_server_cid);
        try queueServerConnectionIds(&self.conn, &self.next_cid_seq, endpoint_server_cid_desired_last_seq, self);
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

        // Match the seq-1 preferred-address alt-CID when one was minted.
        // The alt-CID is no longer derivable from `initial_server_cid +
        // seq`, so the routing table looks it up via the stored bytes.
        // Without this branch, a post-migration packet addressed to the
        // alt-CID would fall through to `findServerConn`'s peer-addr
        // fallback and only match because the source 4-tuple still
        // points at the same peer — but the runner's connectionmigration
        // testcase sends from the same client address through the
        // simulator, so the fallback would normally kick in. We still
        // want CID-keyed matching to be the primary path because (a)
        // `findServerConn`'s peer-addr branch refuses Initials for
        // already-handshaken connections (so a stray Initial bearing
        // the alt-CID would be dropped silently) and (b) an upcoming
        // multi-server-per-process embedder would not have the 4-tuple
        // disambiguator we currently lean on.
        if (self.pa_alt_cid_set and std.mem.eql(u8, cid, &self.pa_alt_cid)) return true;

        // Match the deterministic seq-1..N CIDs the non-PA path emits
        // (`cid[7] +%= seq`). The PA-path seq-1 alt-CID is matched
        // above and skipped here so we don't double-reject an
        // accidental collision that lands in the deterministic
        // walk-window.
        var seq: u8 = 1;
        while (seq < self.next_cid_seq) : (seq += 1) {
            if (seq == 1 and self.pa_alt_cid_set) continue;
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
        // RFC 9368 §6 opt-in for the runner's compatible-version-
        // negotiation cell (`TESTCASE=v2`; `versionnegotiation` also
        // accepted for backwards compat with internal scripts). The
        // runner doesn't pass `-testcase` to the server side via
        // `interop/qns/run_endpoint.sh`, so we read the env var
        // directly. Any unrelated value (or unset) leaves
        // `opts.versions` at its v1-only default.
        if (init.environ_map.get("TESTCASE")) |testcase| {
            opts.versions = serverVersionsForTestcase(testcase);
        }
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
            } else if (std.mem.eql(u8, arg, "-pref-addr")) {
                opts.pref_addr = args.next() orelse return error.MissingPreferredAddress;
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
        if (init.environ_map.get("TESTCASE")) |testcase| {
            opts.testcase = testcase;
            // RFC 9368 §5 opt-in for the runner's compatible-version-
            // negotiation cell (`TESTCASE=v2`; `versionnegotiation`
            // also accepted for backwards compat). The env-var value
            // flows through both the existing `opts.testcase` (which
            // still drives 0-RTT / resumption / keyupdate / chacha20
            // mode selection elsewhere) and the new `opts.versions`
            // slot consulted by `runClientConnection` when building
            // the transport parameters.
            opts.versions = clientVersionsForTestcase(testcase);
        }
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
        \\  qns-endpoint server [-listen [::]:443] [-www /www] [-cert /certs/cert.pem] [-key /certs/priv.key] [-keylog-file path] [-qlog-dir dir] [-retry] [-pref-addr [::]:444]
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

/// One bound listening socket plus its log-friendly metadata.
const ServerSocket = struct {
    handle: Net.Socket,
    /// Local bind address (informational; printed at startup so the
    /// runner's keylog tooling can correlate ports). Borrows the
    /// caller's literal so no allocation is needed.
    bind_addr: Net.IpAddress,
    /// Per-socket ECN active flag. Best-effort: a kernel that rejects
    /// the IPV6_TCLASS / IP_TOS sockopts on this socket leaves us in
    /// the not-ECT path for that socket while another socket may
    /// still carry ECN. Tracked per-socket because `ecn_active` is a
    /// property of the file descriptor, not the loop.
    ecn_active: bool,
};

fn runServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    opts: ServerOptions,
) !void {
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

    // Bind the main listening socket, plus optional alt-listener
    // socket(s) for `preferred_address` advertise. The
    // `preferred_address` (RFC 9000 §18.2) transport parameter
    // advertises a different local address pair the client SHOULD
    // migrate to once the handshake completes — the runner's
    // `connectionmigration` testcase exercises exactly this server-
    // initiated migration. We mirror the public-API
    // `quic_zig.transport.runUdpServer` shape: when `preferred_address`
    // is configured, bind one alt-listener per configured family (v4
    // first if present, then v6). The qns advertises both families on
    // the same port for the runner; the dispatch loop polls every
    // bound socket per iteration and routes outbound replies through
    // the listener the slot most recently received on.
    //
    // The CLI flag `-pref-addr LITERAL` keeps its historical shape:
    // the LITERAL's port is consumed as the qns alt-port; the v4/v6
    // address bytes come from the runner-bridge constants because the
    // runner is the only environment that exercises this binary, and
    // its bridge IPs are stable. Embedders bringing their own runner
    // would patch those constants.
    const main_addr = try Net.IpAddress.parseLiteral(opts.listen);
    const main_handle = try Net.IpAddress.bind(&main_addr, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    // sockets[0] = primary; sockets[1..] = alt-listeners (v4, v6) in
    // the same order the on-wire transport-parameter blob lists them.
    // Three slots covers main + v4 + v6 simultaneously; bumping the
    // capacity is a one-line change if a future scenario needs more.
    var sockets_storage: [3]ServerSocket = undefined;
    sockets_storage[0] = .{
        .handle = main_handle,
        .bind_addr = main_addr,
        .ecn_active = false,
    };
    var sockets_len: usize = 1;

    // Build the runtime `quic_zig.PreferredAddressConfig` once, so the
    // bind logic and the per-Initial transport-parameter advertise
    // both read from a single source of truth. `null` when the CLI
    // flag wasn't supplied (every testcase except `connectionmigration`).
    var pa_config: ?quic_zig.PreferredAddressConfig = null;
    if (opts.pref_addr) |pref_addr_str| {
        const alt_literal = try Net.IpAddress.parseLiteral(pref_addr_str);
        const alt_port: u16 = switch (alt_literal) {
            .ip4 => |ip4| ip4.port,
            .ip6 => |ip6| ip6.port,
        };
        pa_config = .{
            .ipv4 = .{ .bytes = interop_runner_server_ipv4, .port = alt_port },
            .ipv6 = .{ .bytes = interop_runner_server_ipv6, .port = alt_port, .flow = 0 },
        };
    }

    // Bind alt-listeners eagerly (before the recv loop) so a bind
    // failure surfaces immediately; the runner's `connectionmigration`
    // testcase would otherwise time out without an actionable error.
    // Mirrors what `runUdpServer` does in `src/transport/udp_server.zig`.
    if (pa_config) |pa| {
        if (pa.ipv4) |v4| {
            var bind_v4: Net.IpAddress = .{ .ip4 = v4 };
            const sock = try Net.IpAddress.bind(&bind_v4, io, .{
                .mode = .dgram,
                .protocol = .udp,
            });
            sockets_storage[sockets_len] = .{
                .handle = sock,
                .bind_addr = bind_v4,
                .ecn_active = false,
            };
            sockets_len += 1;
        }
        if (pa.ipv6) |v6| {
            var bind_v6: Net.IpAddress = .{ .ip6 = v6 };
            const sock = try Net.IpAddress.bind(&bind_v6, io, .{
                .mode = .dgram,
                .protocol = .udp,
            });
            sockets_storage[sockets_len] = .{
                .handle = sock,
                .bind_addr = bind_v6,
                .ecn_active = false,
            };
            sockets_len += 1;
        }
    }

    const sockets = sockets_storage[0..sockets_len];
    defer for (sockets) |s| s.handle.close(io);

    // Tune all sockets identically. We grow the kernel UDP buffers
    // so a single connection can absorb a burst of ~3000 1350-byte
    // datagrams (a multiplexing stream open or a flight of stream
    // data) without dropping packets at the OS layer.
    for (sockets) |*s| {
        tuneServerSocket(s.handle.handle);
        s.ecn_active = enableServerEcn(s.handle.handle);
    }

    if (pa_config) |pa| {
        const alt_port: u16 = if (pa.ipv4) |v4| v4.port else if (pa.ipv6) |v6| v6.port else 0;
        std.debug.print(
            "quic_zig qns endpoint listening on {f} (main) + {d} alt-listener(s) on port {d} for preferred_address; www={s} retry={}\n",
            .{ sockets[0].bind_addr, sockets.len - 1, alt_port, opts.www, opts.retry },
        );
    } else {
        std.debug.print(
            "quic_zig qns endpoint listening on {f} www={s} retry={}\n",
            .{ sockets[0].bind_addr, opts.www, opts.retry },
        );
    }

    var conns: std.ArrayList(*ServerConn) = .empty;
    defer {
        for (conns.items) |server_conn| server_conn.destroy(allocator);
        conns.deinit(allocator);
    }

    const start = std.Io.Timestamp.now(io, .awake);
    var rx: [64 * 1024]u8 = undefined;
    var tx: [endpoint_udp_payload_size]u8 = undefined;
    var cmsg_buf: [quic_zig.transport.default_cmsg_buffer_bytes]u8 = undefined;

    // When polling multiple sockets we split the per-iteration idle
    // wait across them so the worst-case loop latency stays close to
    // the original 5ms heartbeat. Each socket waiting 5ms would
    // multiply the PTO-tick latency at idle by `sockets_len`; floor at
    // 1ms so we never spin. Mirrors the `runUdpServer` per-listener
    // timeout split.
    const recv_timeout_ms: i64 = blk: {
        if (sockets_len <= 1) break :blk 5;
        const split: i64 = @divFloor(5, @as(i64, @intCast(sockets_len)));
        break :blk if (split < 1) 1 else split;
    };

    while (true) {
        var now_us = qnsNowUs(io, start);
        // Drain each bound socket once per iteration. Most loops
        // see traffic on the main socket; the alt-port socket only
        // carries traffic after the client migrates following a
        // `preferred_address` advertise. We deliberately do NOT
        // break on the first socket that returns a datagram — both
        // sockets share the same connection table and processing a
        // stale alt-port datagram before the next main-port one is
        // semantically equivalent to processing them in network
        // arrival order at the granularity QUIC cares about.
        for (sockets, 0..) |s, sock_idx| {
            // Two recv shapes: when ECN is active we go through
            // `receiveManyTimeout` so the kernel populates the cmsg
            // control buffer with IP_TOS / IPV6_TCLASS bytes. Otherwise
            // the cheaper `receiveTimeout` shape (no control buffer,
            // no cmsg parse).
            var maybe_msg: ?Net.IncomingMessage = null;
            var ecn: quic_zig.transport.EcnCodepoint = .not_ect;
            if (s.ecn_active) {
                var recv_msg: Net.IncomingMessage = .init;
                recv_msg.control = &cmsg_buf;
                const buf_slice = (&recv_msg)[0..1];
                const ret = s.handle.receiveManyTimeout(io, buf_slice, &rx, .{}, .{
                    .duration = .{
                        .raw = std.Io.Duration.fromMilliseconds(recv_timeout_ms),
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
                maybe_msg = s.handle.receiveTimeout(io, &rx, .{
                    .duration = .{
                        .raw = std.Io.Duration.fromMilliseconds(recv_timeout_ms),
                        .clock = .awake,
                    },
                }) catch |err| switch (err) {
                    error.Timeout => null,
                    else => return err,
                };
            }
            now_us = qnsNowUs(io, start);

            const msg = maybe_msg orelse continue;
            try dispatchInbound(.{
                .allocator = allocator,
                .io = io,
                .server_tls = server_tls,
                .opts = opts,
                .qlog_sink = if (qlog_sink) |*sink| sink else null,
                .conns = &conns,
                .sockets = sockets,
                .sock_idx = sock_idx,
                .msg = msg,
                .ecn = ecn,
                .tx = &tx,
                .now_us = now_us,
                .pa_config = pa_config,
            });
        }

        var i: usize = 0;
        while (i < conns.items.len) {
            const sc = conns.items[i];
            if (sc.conn.handshakeDone()) {
                try queueServerConnectionIds(&sc.conn, &sc.next_cid_seq, endpoint_server_cid_desired_last_seq, sc);
                maybeIssueNewToken(sc, now_us);
            }
            try sc.app.process(&sc.conn);
            // Outbound on the socket the connection most recently
            // received from. Pre-migration that's the main socket
            // (last_recv_socket = 0); once the client follows the
            // `preferred_address` advertise, it flips to whichever
            // alt-listener (v4 or v6) the migrated path arrives on.
            // This is the simplest routing rule that doesn't require
            // multiplexing the outbound across all sockets per packet.
            const out_sock = sockets[sc.last_recv_socket].handle;
            while (try sc.conn.poll(&tx, now_us)) |n| {
                try out_sock.send(io, &sc.peer, tx[0..n]);
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

/// Per-iteration dispatch parameters for `dispatchInbound`. Bundled
/// into a struct so the call site stays readable when the loop polls
/// every bound socket.
const DispatchInboundCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server_tls: boringssl.tls.Context,
    opts: ServerOptions,
    qlog_sink: ?*QlogSink,
    conns: *std.ArrayList(*ServerConn),
    sockets: []const ServerSocket,
    sock_idx: usize,
    msg: Net.IncomingMessage,
    ecn: quic_zig.transport.EcnCodepoint,
    tx: *[endpoint_udp_payload_size]u8,
    now_us: u64,
    /// Runtime preferred-address configuration mirrored from
    /// `runServer`. Non-null when the qns advertises a
    /// `preferred_address` transport parameter (the runner's
    /// `connectionmigration` testcase); the per-connection
    /// `acceptInitial` call reads the v4/v6 address pair off this
    /// value to build the on-wire `PreferredAddress`. Null disables
    /// the advertise — the dispatch path just skips the parameter and
    /// `ServerConn.init` doesn't mint a seq-1 alt-CID.
    pa_config: ?quic_zig.PreferredAddressConfig,
};

/// Dispatch one inbound datagram pulled off `ctx.sockets[ctx.sock_idx]`.
/// Mirrors what the loop body did inline before alt-listener support
/// landed; factored out so every bound socket shares the same
/// per-datagram lookup / handshake-bootstrap / `handle` path. The
/// only socket-aware bit is `ServerConn.last_recv_socket`, which the
/// outbound drain consults to route replies to the alt-listener once
/// the client has migrated to the preferred-address.
fn dispatchInbound(ctx: DispatchInboundCtx) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const opts = ctx.opts;
    const conns = ctx.conns;
    const sockets = ctx.sockets;
    const msg = ctx.msg;
    const ecn = ctx.ecn;
    const tx = ctx.tx;
    const now_us = ctx.now_us;
    const sock = sockets[ctx.sock_idx].handle;

    var server_conn = findServerConn(conns.items, msg.data, msg.from);
    if (server_conn == null) {
        const ids = peekLongHeaderIds(msg.data) orelse return;
        if (!isVersionSupported(opts.versions, ids.version)) {
            const n = try writeVersionNegotiation(tx, msg.data, opts.versions);
            try sock.send(io, &msg.from, tx[0..n]);
            return;
        }
        if (!isInitialLongHeader(msg.data)) return;
        if (conns.items.len >= max_qns_server_connections) {
            std.debug.print("dropping new QNS server connection from {f}: active limit reached\n", .{msg.from});
            return;
        }
        // Brand-new connections always begin on the main socket
        // (the runner only advertises `[::]:443` to the client by
        // default; the alt-port is reachable only after the
        // `preferred_address` migration). If a peer happens to
        // address an Initial directly to the alt-port we still
        // accept it — the post-handshake migration just becomes a
        // no-op for that connection — but bookkeeping below treats
        // the receiving socket index uniformly.
        const new_conn = try ServerConn.init(
            allocator,
            io,
            ctx.server_tls,
            opts.www,
            ctx.qlog_sink,
            msg.from,
            now_us,
            ctx.pa_config != null,
        );
        try conns.append(allocator, new_conn);
        server_conn = new_conn;
    }

    const sc = server_conn.?;
    sc.peer = msg.from;
    sc.last_activity_us = now_us;
    sc.last_recv_socket = @intCast(ctx.sock_idx);
    if (!sc.transport_params_set) {
        const ids = peekLongHeaderIds(msg.data) orelse return;
        if (!isVersionSupported(opts.versions, ids.version)) {
            const n = try writeVersionNegotiation(tx, msg.data, opts.versions);
            try sock.send(io, &msg.from, tx[0..n]);
            return;
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
            const n = try sc.conn.writeRetry(tx, msg.data, &sc.retry_source_cid, &token);
            try sock.send(io, &msg.from, tx[0..n]);
            sc.retry_sent = true;
            return;
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
            const token = peekInitialToken(msg.data) orelse return;
            if (!validRetryToken(msg.from, now_us, original_dcid.slice(), &sc.retry_source_cid, token)) {
                return;
            }
        }

        // Advertise `preferred_address` only when (a) the runtime
        // config supplied one (`ctx.pa_config`), AND (b) the
        // per-connection alt-CID + token mint succeeded in
        // `ServerConn.init` (`sc.pa_alt_cid_set`). The parameter is
        // server-only (RFC 9000 §18.2 ¶29); pointing at an unbound
        // port would teach the client to migrate into a black hole.
        // The CID + token are pre-minted on `sc` so this code path
        // and `queueServerConnectionIds`'s seq-1 frame describe the
        // same on-wire bytes.
        const preferred_address: ?quic_zig.tls.transport_params.PreferredAddress = blk: {
            const pa = ctx.pa_config orelse break :blk null;
            if (!sc.pa_alt_cid_set) break :blk null;
            break :blk buildPreferredAddress(pa, sc);
        };

        var params: quic_zig.tls.TransportParams = .{
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
            .preferred_address = preferred_address,
        };

        // RFC 9368 §5/§6 compatible-version-negotiation upgrade. When
        // the server is configured with multiple versions, pre-parse
        // the inbound Initial under wire-version keys to extract the
        // client's `version_information` (codepoint 0x11) transport
        // parameter, intersect with `opts.versions`, and pick the
        // first server-preferred version that also appears in the
        // client's `available_versions`. If that differs from the
        // wire version, advertise the upgrade target as
        // `chosen_version` (so the EE BoringSSL produces matches §5)
        // and stash the target via `setPendingVersionUpgrade` so the
        // post-`handleWithEcn` flip seals the response Initial under
        // the upgrade-target keys (mirrors `Server.dispatchToSlot`).
        //
        // Pre-parse failures (decrypt auth, fragmented ClientHello,
        // missing extension) fall back to the wire version, which is
        // always spec-compliant.
        const upgrade_target = preparseUpgradeTarget(opts.versions, msg.data, ids.version);
        const chosen_version: u32 = upgrade_target orelse ids.version;
        if (opts.versions.len > 1) {
            var ordered: [16]u32 = undefined;
            ordered[0] = chosen_version;
            var n_versions: usize = 1;
            for (opts.versions) |v| {
                if (v == chosen_version) continue;
                if (n_versions >= ordered.len) break;
                ordered[n_versions] = v;
                n_versions += 1;
            }
            try params.setCompatibleVersions(ordered[0..n_versions]);
        }
        try sc.conn.acceptInitial(msg.data, params);
        if (upgrade_target) |upgraded| {
            if (upgraded != ids.version) sc.conn.setPendingVersionUpgrade(upgraded);
        }
        _ = try sc.conn.setEarlyDataContextForParams(params, hq_alpn, "quic_zig qns endpoint v1");
        sc.transport_params_set = true;
    }
    try sc.conn.handleWithEcn(msg.data, netAddressToPathAddress(msg.from), ecn, now_us);
    // Apply any pending RFC 9368 §6 version upgrade now that the
    // wire-version Initial has been opened under wire-version keys.
    // The next outbound `poll` will seal the response under the
    // chosen-version keys. Idempotent / no-op when nothing pending.
    _ = sc.conn.applyPendingVersionUpgrade();
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
                .versions = opts.versions,
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
                    .versions = opts.versions,
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
                    .versions = opts.versions,
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

    var params: quic_zig.tls.TransportParams = .{
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
    // RFC 9368 §5: when the client offers more than one wire-format
    // version, advertise the full list (chosen first, alternates
    // following) via the `version_information` (codepoint 0x11)
    // transport parameter so a multi-version server can pick the
    // highest-priority overlap and drive a §6 compatible-version
    // upgrade. The first entry is treated as `chosen_version` —
    // matching the wire version of the outbound Initial — by RFC
    // 9368 §5.
    if (conn_opts.versions.len > 1) {
        try params.setCompatibleVersions(conn_opts.versions);
    }
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

    // Track whether we've issued the spare client SCIDs the server
    // needs for path rotation. Bumped from 1 to whatever
    // `queueClientConnectionIds` queues once the handshake completes.
    var next_client_cid_seq: u8 = 1;

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
            // RFC 9000 §9: forward the inbound source address into the
            // connection so it can detect a peer-side address rebind.
            // The runner's `rebind-addr` testcase rewrites source IPs
            // transparently in the ns-3 simulator; from the client's
            // POV the server's source tuple changes mid-connection.
            // Without the `from` argument, `Connection.handleWithEcn`
            // receives `null`, `peerAddressChangeCandidate` short-
            // circuits, and the migration / PATH_CHALLENGE flow never
            // arms — the client keeps sending to the original
            // `server_addr` and the runner declares the test failed.
            try conn.handleWithEcn(msg.data, netAddressToPathAddress(msg.from), ecn, now_us);
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
                // Same source-address forwarding rationale as the
                // primary recv branch above. Datagrams the server
                // addressed to our pre-migration socket carry the
                // peer's then-current source tuple; let the connection
                // observe it.
                try conn.handleWithEcn(msg.data, netAddressToPathAddress(msg.from), old_ecn, qnsNowUs(io, start));
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

        // RFC 9000 §5.1.2 ¶1 / §9.5 client CID issuance: once the
        // handshake completes, hand the server a spare DCID so it can
        // rotate when a new client path appears (e.g. the runner's
        // `rebind-addr` testcase rewriting our source address in the
        // sim layer). Idempotent — once `next_client_cid_seq` passes
        // the desired-last-seq cursor, subsequent calls no-op.
        if (conn.handshakeDone() and next_client_cid_seq <= endpoint_client_cid_desired_last_seq) {
            try queueClientConnectionIds(
                &conn,
                &next_client_cid_seq,
                endpoint_client_cid_desired_last_seq,
                &client_scid,
            );
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

        while (try conn.pollDatagram(&tx, now_us)) |out| {
            const first_byte: u8 = if (out.len > 0) tx[0] else 0;
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
                .{ now_us, out.len, tag, first_byte },
            );
            // Honor the per-datagram destination produced by the core.
            // After a peer-initiated rebind (`rebind-addr` testcase),
            // the active path's `peer_addr` swings to the new server
            // tuple; `pollDatagram.to` reflects that. Falling back to
            // `server_addr` covers the early handshake before the path
            // address is set and any internal callsite that emits
            // without an explicit destination.
            const dest = pathAddressToNetAddress(out.to) orelse server_addr;
            sock.send(io, &dest, tx[0..out.len]) catch |err| {
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
        while (try conn.pollDatagram(&tx, now_us)) |out| {
            const dest = pathAddressToNetAddress(out.to) orelse server_addr;
            try sock.send(io, &dest, tx[0..out.len]);
        }
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

/// Inverse of `netAddressToPathAddress`. Returns `null` for the
/// zero-tag default (a `path.Address` that the core never set), so
/// callers can fall back to a default destination — typically the
/// connection's original target address. Mirrors the helper that
/// lives in `src/transport/udp_server.zig` for `runUdpClient`.
fn pathAddressToNetAddress(addr: ?quic_zig.conn.path.Address) ?Net.IpAddress {
    const a = addr orelse return null;
    switch (a.bytes[0]) {
        4 => {
            var ip4_bytes: [4]u8 = undefined;
            @memcpy(&ip4_bytes, a.bytes[1..5]);
            const port = std.mem.readInt(u16, a.bytes[5..7], .big);
            return .{ .ip4 = .{ .bytes = ip4_bytes, .port = port } };
        },
        6 => {
            var ip6_bytes: [16]u8 = undefined;
            @memcpy(&ip6_bytes, a.bytes[1..17]);
            const port = std.mem.readInt(u16, a.bytes[17..19], .big);
            const flow: u32 = (@as(u32, a.bytes[19]) << 16) |
                (@as(u32, a.bytes[20]) << 8) |
                @as(u32, a.bytes[21]);
            return .{ .ip6 = .{ .bytes = ip6_bytes, .port = port, .flow = flow } };
        },
        else => return null,
    }
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

/// Returns true when `version` is one of the wire-format versions in
/// `supported`. Linear scan; `supported` is bounded at 16 entries by
/// `writeVersionNegotiation` and the broader RFC 9368 §5
/// `version_information` cap.
fn isVersionSupported(supported: []const u32, version: u32) bool {
    for (supported) |v| {
        if (v == version) return true;
    }
    return false;
}

/// RFC 9368 §6 server-side compatible-version-negotiation pre-parse.
/// Mirrors `Server.preparseUpgradeTarget` in `src/server.zig` but uses
/// only the public `quic_zig.wire.vneg_preparse` helpers so the qns
/// endpoint stays a pure embedder of the library API.
///
/// Returns `null` when:
///   * The configured `supported` list has 0 or 1 entries (no upgrade
///     is possible with a single version).
///   * The wire `version` is not Initial-key derivable (RFC 9001 §5.2 /
///     RFC 9368 §3.3.1 — only v1 and v2 are pre-parseable today).
///   * Any pre-parse step fails (decrypt auth, fragmented ClientHello,
///     missing `quic_transport_parameters` extension, missing
///     `version_information` parameter, no overlap with `supported`).
///
/// Returns the upgrade target version when the highest-priority overlap
/// between the server's `supported` list and the client's
/// `available_versions` differs from the wire version. The caller MUST
/// then advertise the target as the leading entry of
/// `params.compatibleVersions` (so the EE BoringSSL produces matches §5)
/// and stash it via `Connection.setPendingVersionUpgrade` so the next
/// outbound `poll` seals under the upgrade-target keys.
///
/// Defensive throughout: any error path returns `null` and the caller
/// falls back to "use the wire version", which is always spec-compliant
/// per §6's graceful-degradation clause.
fn preparseUpgradeTarget(
    supported: []const u32,
    bytes: []const u8,
    wire_version: u32,
) ?u32 {
    if (supported.len <= 1) return null;
    if (!quic_zig.wire.initial.isSupportedVersion(wire_version)) return null;

    const ids = peekLongHeaderIds(bytes) orelse return null;

    // Make a private copy of the inbound bytes so `openInitial`'s
    // in-place header-protection strip doesn't disturb the caller's
    // buffer — `Connection.handleWithEcn` will re-process the same
    // bytes through its normal Initial-handling flow.
    var pkt_copy: [quic_zig.conn.state.max_recv_plaintext]u8 = undefined;
    if (bytes.len > pkt_copy.len) return null;
    @memcpy(pkt_copy[0..bytes.len], bytes);

    // Derive client-direction Initial keys for the wire version.
    const init_keys = quic_zig.wire.initial.deriveInitialKeysFor(wire_version, ids.dcid, false) catch return null;
    const r_keys = quic_zig.wire.short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret) catch return null;

    var pt_buf: [quic_zig.conn.state.max_recv_plaintext]u8 = undefined;
    const opened = quic_zig.wire.long_packet.openInitial(&pt_buf, pkt_copy[0..bytes.len], .{
        .keys = &r_keys,
        .largest_received = 0,
    }) catch return null;

    var ch_buf: [quic_zig.wire.vneg_preparse.max_client_hello_bytes]u8 = undefined;
    const ch = quic_zig.wire.vneg_preparse.reassembleClientHello(&ch_buf, opened.payload) orelse return null;
    const qtp = quic_zig.wire.vneg_preparse.findQuicTransportParamsExt(ch) orelse return null;
    const info = quic_zig.wire.vneg_preparse.findVersionInformation(qtp) orelse return null;

    return quic_zig.wire.vneg_preparse.chooseUpgradeVersion(supported, info.available());
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
    sc: *ServerConn,
) !void {
    const budget = conn.localConnectionIdIssueBudget(0);
    if (budget == 0 or next_seq.* > desired_last_seq) return;

    var cid_storage: [8][server_cid_len]u8 = undefined;
    var provisions: [8]quic_zig.ConnectionIdProvision = undefined;
    var count: usize = 0;
    var seq = next_seq.*;
    while (seq <= desired_last_seq and count < provisions.len and count < budget) {
        // Two seq-1 CID-mint paths share this loop. Both produce a
        // CID + matching stateless-reset token, but they describe the
        // same on-wire bytes through different routes:
        //
        //   * `pa_alt_cid_set`: the connection has a preferred-address
        //     advertise pinned, so seq-1 MUST reuse `sc.pa_alt_cid` /
        //     `sc.pa_alt_token`. Anything else and the post-migration
        //     packets the client addresses to the PA's CID would not
        //     authenticate (the local CID table doesn't recognize the
        //     PA's bytes). RFC 9000 §5.1.1 ¶6 says the client treats
        //     the PA's `connection_id` as if it had arrived in
        //     NEW_CONNECTION_ID(seq=1); we still emit the matching
        //     frame on the wire and the client's `registerPeerCid`
        //     idempotently absorbs the duplicate.
        //
        //   * Otherwise (no PA configured, or PA mint failed at
        //     `ServerConn.init`): the historical deterministic
        //     `cid[7] +%= seq` derivation, paired with a token
        //     derived via `quic_zig.conn.stateless_reset.derive` from
        //     the qns-wide `stateless_reset_key`. The wider refactor
        //     replaced an XOR-shaped stand-in token with the public-
        //     API HMAC; the seq-1..N CID derivation stays
        //     deterministic so the rest of the runner's (non-PA)
        //     testcase matrix sees no on-wire bookkeeping change.
        //     `connectionmigration` is the only testcase that
        //     exercises the seq-1 CID, and it always configures a PA
        //     so it goes through the branch above.
        if (seq == 1 and sc.pa_alt_cid_set) {
            cid_storage[count] = sc.pa_alt_cid;
            provisions[count] = .{
                .connection_id = cid_storage[count][0..],
                .stateless_reset_token = sc.pa_alt_token,
            };
        } else {
            cid_storage[count] = sc.initial_server_cid;
            cid_storage[count][7] +%= seq;
            const tok = quic_zig.conn.stateless_reset.derive(&stateless_reset_key, &cid_storage[count]) catch
                return error.RandFailure;
            provisions[count] = .{
                .connection_id = cid_storage[count][0..],
                .stateless_reset_token = tok,
            };
        }
        count += 1;
        seq += 1;
    }
    if (count == 0) return;

    const queued = try conn.replenishConnectionIds(provisions[0..count]);
    next_seq.* += @as(u8, @intCast(queued));
}

/// Build the `preferred_address` transport-parameter value the server
/// advertises for the runner's `connectionmigration` testcase. Reads
/// the alt-address pair from `pa_cfg` (the runtime
/// `quic_zig.PreferredAddressConfig` the qns endpoint constructed at
/// `runServer`) and pulls the per-connection seq-1 CID + stateless-
/// reset token off `sc` — both pre-minted in `ServerConn.init` so the
/// seq-1 NEW_CONNECTION_ID emitted by `queueServerConnectionIds`
/// describes the same on-wire CID this transport-parameter
/// advertises. RFC 9000 §5.1.1 ¶6 says the client treats the PA's
/// `connection_id` as if it had arrived in NEW_CONNECTION_ID(seq=1);
/// the matching frame the server still emits is then idempotently
/// absorbed by the client's peer-CID table.
///
/// Mirrors what the public-API `Server` does internally
/// (`src/server.zig`'s `buildPreferredAddressParam`): the qns just
/// runs the same projection from `PreferredAddressConfig` shape into
/// the on-wire `tls.transport_params.PreferredAddress` shape, with
/// the missing-family fields zeroed per the §18.2 sentinel.
fn buildPreferredAddress(
    pa_cfg: quic_zig.PreferredAddressConfig,
    sc: *const ServerConn,
) quic_zig.tls.transport_params.PreferredAddress {
    var out: quic_zig.tls.transport_params.PreferredAddress = .{
        .connection_id = quic_zig.conn.path.ConnectionId.fromSlice(&sc.pa_alt_cid),
        .stateless_reset_token = sc.pa_alt_token,
    };
    if (pa_cfg.ipv4) |v4| {
        out.ipv4_address = v4.bytes;
        out.ipv4_port = v4.port;
    }
    if (pa_cfg.ipv6) |v6| {
        out.ipv6_address = v6.bytes;
        out.ipv6_port = v6.port;
    }
    return out;
}

/// Client-side mirror of `queueServerConnectionIds`. Once the
/// handshake completes, queue extra NEW_CONNECTION_ID frames so the
/// peer (server) has a fresh DCID available when it needs to rotate
/// per RFC 9000 §5.1.2 ¶1 / §9.5. The runner's `rebind-addr` testcase
/// stresses this: the network simulator rewrites the client's source
/// address mid-transfer, the server detects the new path and would
/// validate it, but if quic-zig only ever issued the initial SCID
/// (sequence 0) the server has no CID to rotate to and the
/// validation is skipped (e.g. quic-go's `skipping validation of new
/// path … since no connection ID is available`).
///
/// `next_seq` is the next-sequence cursor — after the first call it
/// advances by however many provisions were accepted. Idempotent
/// across retries: when the issue budget is exhausted (the peer's
/// `active_connection_id_limit` is already saturated), the call is a
/// no-op and `next_seq` is unchanged.
///
/// The client's initial SCID is at sequence 0 (`setLocalScid` registers
/// it implicitly). We start issuing at `next_seq.*` and stop at
/// `desired_last_seq` inclusive. CIDs are derived deterministically
/// from the seq-0 base; stateless reset tokens go through
/// `quic_zig.conn.stateless_reset.derive` with the qns-wide
/// `stateless_reset_key`, matching the public-API path the
/// server side now uses for seq-1 alt-CIDs.
fn queueClientConnectionIds(
    conn: *quic_zig.Connection,
    next_seq: *u8,
    desired_last_seq: u8,
    base_cid: *const [8]u8,
) !void {
    const budget = conn.localConnectionIdIssueBudget(0);
    if (budget == 0 or next_seq.* > desired_last_seq) return;

    var cid_storage: [8][8]u8 = undefined;
    var provisions: [8]quic_zig.ConnectionIdProvision = undefined;
    var count: usize = 0;
    var seq = next_seq.*;
    while (seq <= desired_last_seq and count < provisions.len and count < budget) {
        cid_storage[count] = base_cid.*;
        cid_storage[count][7] +%= seq;
        const tok = quic_zig.conn.stateless_reset.derive(&stateless_reset_key, &cid_storage[count]) catch
            return error.RandFailure;
        provisions[count] = .{
            .connection_id = cid_storage[count][0..],
            .stateless_reset_token = tok,
        };
        count += 1;
        seq += 1;
    }
    if (count == 0) return;

    const queued = try conn.replenishConnectionIds(provisions[0..count]);
    next_seq.* += @as(u8, @intCast(queued));
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

test "QNS server/client versions follow TESTCASE=versionnegotiation" {
    // Default (TESTCASE unset or any non-`versionnegotiation`/`v2`
    // value): both roles fall back to v1-only so legacy interop
    // testcases keep their historical wire posture.
    const default_server = serverVersionsForTestcase("");
    try std.testing.expectEqual(@as(usize, 1), default_server.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, default_server[0]);

    const default_client = clientVersionsForTestcase("");
    try std.testing.expectEqual(@as(usize, 1), default_client.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, default_client[0]);

    // Sanity-check a couple of unrelated TESTCASE values to make sure
    // they don't accidentally trip the v2 opt-in. `transfer` is the
    // generic "happy path" testcase; `connectionmigration` already
    // overloads other env handling and we want to confirm the
    // version-selection path stays orthogonal to it.
    const transfer_server = serverVersionsForTestcase("transfer");
    try std.testing.expectEqual(@as(usize, 1), transfer_server.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, transfer_server[0]);

    const cm_client = clientVersionsForTestcase("connectionmigration");
    try std.testing.expectEqual(@as(usize, 1), cm_client.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, cm_client[0]);

    // `versionnegotiation`: server prefers v2 first so it advertises
    // v2 as `chosen_version` to a v1-wire client whose
    // `version_information` includes v2; the v1 entry remains in the
    // list as a fallback for legacy clients with no `version_information`.
    const vn_server = serverVersionsForTestcase("versionnegotiation");
    try std.testing.expectEqual(@as(usize, 2), vn_server.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_2, vn_server[0]);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, vn_server[1]);

    // `versionnegotiation`: client puts v1 first because that's the
    // wire version of its outbound Initial; v2 is the upgrade target
    // it offers via `version_information`. The asymmetry vs. the
    // server (v2-first) is intentional — see the helper docstrings.
    const vn_client = clientVersionsForTestcase("versionnegotiation");
    try std.testing.expectEqual(@as(usize, 2), vn_client.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, vn_client[0]);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_2, vn_client[1]);

    // `v2`: this is the runner's actual testcase name for the
    // compatible-version-negotiation cell
    // (`quic-interop-runner/testcases_quic.py:TestCaseV2`). Both roles
    // must pick the multi-version posture identical to
    // `versionnegotiation` so the runner's wire-trace check sees the
    // server emit a v2 Initial and the post-handshake versions
    // converge on v2. Earlier qns endpoints fired only on
    // `versionnegotiation`, which left the server replying with a v1
    // Initial — the runner then logged "Wrong version in server
    // Initial. Expected 0x6b3343cf, got {'0x1'}" and failed the cell.
    const v2_server = serverVersionsForTestcase("v2");
    try std.testing.expectEqual(@as(usize, 2), v2_server.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_2, v2_server[0]);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, v2_server[1]);

    const v2_client = clientVersionsForTestcase("v2");
    try std.testing.expectEqual(@as(usize, 2), v2_client.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, v2_client[0]);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_2, v2_client[1]);

    // Defensive: a value that *contains* `v2` as a substring but isn't
    // exactly `v2` (e.g. a hypothetical future `v2+something` testcase)
    // must NOT trip the multi-version posture, since
    // `isVersionNegotiationTestcase` uses exact-equality matching.
    const not_v2_server = serverVersionsForTestcase("v22");
    try std.testing.expectEqual(@as(usize, 1), not_v2_server.len);
    try std.testing.expectEqual(quic_zig.QUIC_VERSION_1, not_v2_server[0]);
}

test "isVersionSupported scans the configured list" {
    // Single-version (v1-only default): only v1 hits.
    try std.testing.expect(isVersionSupported(&.{quic_zig.QUIC_VERSION_1}, quic_zig.QUIC_VERSION_1));
    try std.testing.expect(!isVersionSupported(&.{quic_zig.QUIC_VERSION_1}, quic_zig.QUIC_VERSION_2));
    try std.testing.expect(!isVersionSupported(&.{quic_zig.QUIC_VERSION_1}, 0xdeadbeef));

    // Multi-version (`TESTCASE=versionnegotiation` posture): both v1
    // and v2 hit; an unknown version misses so the dispatch path
    // sends a Version Negotiation rather than passing the bytes
    // through to `Connection.acceptInitial`.
    const both = serverVersionsForTestcase("versionnegotiation");
    try std.testing.expect(isVersionSupported(both, quic_zig.QUIC_VERSION_1));
    try std.testing.expect(isVersionSupported(both, quic_zig.QUIC_VERSION_2));
    try std.testing.expect(!isVersionSupported(both, 0xdeadbeef));
    // Empty list: nothing matches (defensive — production code never
    // hits this since the env-derived defaults guarantee >= 1 entry).
    try std.testing.expect(!isVersionSupported(&.{}, quic_zig.QUIC_VERSION_1));
}

test "queueClientConnectionIds issues a fresh CID once handshake completes" {
    // RFC 9000 §5.1.2 ¶1 / §9.5: a client must hand the server at
    // least one extra CID via NEW_CONNECTION_ID so the server has a
    // fresh DCID to use when the client's path appears at a new
    // tuple. Without this, the runner's `rebind-addr` testcase trips
    // the server-side "skipping validation of new path … since no
    // connection ID is available" path (verified against quic-go on
    // 2026-05-09).
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try quic_zig.Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // The peer's `active_connection_id_limit` governs how many of
    // OUR CIDs we may issue. The qns endpoint advertises 2, matching
    // the floor we receive from quic-go / quiche / ngtcp2 in interop.
    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 2 };

    const base_cid = [_]u8{ 0xc1, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    try conn.setLocalScid(&base_cid);

    // Sequence 0 is the initial SCID we just registered. The helper
    // should issue sequence 1 (and stop there because
    // `endpoint_client_cid_desired_last_seq = 1`).
    var next_seq: u8 = 1;
    try queueClientConnectionIds(&conn, &next_seq, endpoint_client_cid_desired_last_seq, &base_cid);
    try std.testing.expectEqual(@as(u8, 2), next_seq);

    // One NEW_CONNECTION_ID frame queued for emission.
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.new_connection_ids.items.len);
    const queued = conn.pending_frames.new_connection_ids.items[0];
    try std.testing.expectEqual(@as(u64, 1), queued.sequence_number);
    try std.testing.expectEqual(@as(u64, 0), queued.retire_prior_to);
    try std.testing.expectEqual(@as(u8, base_cid.len), queued.connection_id.len);

    // Idempotent on second call: cursor doesn't advance, queue
    // doesn't grow.
    try queueClientConnectionIds(&conn, &next_seq, endpoint_client_cid_desired_last_seq, &base_cid);
    try std.testing.expectEqual(@as(u8, 2), next_seq);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.new_connection_ids.items.len);
}

test "queueClientConnectionIds no-ops when peer's CID limit is saturated" {
    // The helper consults `localConnectionIdIssueBudget`; if the peer
    // hasn't budgeted room for an extra SCID, the helper must be
    // silent rather than sending a frame the peer would treat as a
    // CONNECTION_ID_LIMIT_ERROR.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try quic_zig.Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Peer permits exactly one active CID at a time — the initial
    // one. Any call to issue a sequence >0 is over-budget.
    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 1 };

    const base_cid = [_]u8{ 0xc2, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    try conn.setLocalScid(&base_cid);

    var next_seq: u8 = 1;
    try queueClientConnectionIds(&conn, &next_seq, endpoint_client_cid_desired_last_seq, &base_cid);

    // No frame queued; cursor unchanged.
    try std.testing.expectEqual(@as(u8, 1), next_seq);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.new_connection_ids.items.len);
}

test "buildPreferredAddress packs config + identity into transport-param shape" {
    // The preferred_address transport parameter (RFC 9000 §18.2)
    // carries a CID + stateless reset token the client treats as if
    // it had arrived in a NEW_CONNECTION_ID frame at sequence 1
    // (§5.1.1 ¶3). The qns server pre-mints those bytes in
    // `ServerConn.init` and `buildPreferredAddress` simply projects
    // them — together with the v4/v6 address pair from
    // `quic_zig.PreferredAddressConfig` — into the on-wire shape.
    // This test pins that projection: any divergence between the
    // pre-minted bytes on `sc` and the encoded transport-parameter
    // would either (a) leave the post-migration packets that bear
    // the PA's CID unauthenticated server-side, or (b) make the
    // client migrate to the wrong family / port and silently
    // black-hole.
    var sc: ServerConn = .{
        .conn = undefined,
        .app = undefined,
        .peer = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .retry_source_cid = @splat(0),
        .initial_server_cid = .{ 'Q', 'N', 'S', '-', 0x11, 0x22, 0x33, 0x44 },
        .last_activity_us = 0,
    };
    sc.pa_alt_cid = .{ 'Q', 'N', 'S', '-', 0xaa, 0xbb, 0xcc, 0xdd };
    sc.pa_alt_token = .{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    sc.pa_alt_cid_set = true;

    const cfg: quic_zig.PreferredAddressConfig = .{
        .ipv4 = .{ .bytes = interop_runner_server_ipv4, .port = 444 },
        .ipv6 = .{ .bytes = interop_runner_server_ipv6, .port = 444, .flow = 0 },
    };
    const pa = buildPreferredAddress(cfg, &sc);

    // CID + token: must come from `sc.pa_alt_cid` / `sc.pa_alt_token`
    // verbatim (the same bytes `queueServerConnectionIds` uses for
    // the matching seq-1 NEW_CONNECTION_ID frame).
    try std.testing.expectEqual(@as(u8, server_cid_len), pa.connection_id.len);
    try std.testing.expectEqualSlices(u8, &sc.pa_alt_cid, pa.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &sc.pa_alt_token, &pa.stateless_reset_token);

    // Ports + addresses come from the runtime config. A test failure
    // here would mean the client migrates to either an unbound IP
    // family or to the wrong port — both silent black-holes that are
    // hard to diagnose from the runner's pcap alone.
    try std.testing.expectEqual(@as(u16, 444), pa.ipv4_port);
    try std.testing.expectEqual(@as(u16, 444), pa.ipv6_port);
    try std.testing.expectEqualSlices(u8, &interop_runner_server_ipv4, &pa.ipv4_address);
    try std.testing.expectEqualSlices(u8, &interop_runner_server_ipv6, &pa.ipv6_address);
}

test "buildPreferredAddress encodes into the transport-params blob" {
    // End-to-end check that a server-authored TransportParams blob
    // carrying `preferred_address` round-trips through `Params.encode`
    // and `Params.decode`. The qns endpoint passes the value through
    // `Connection.acceptInitial`, which calls
    // `setTransportParams`, which calls `Params.encode`. This test
    // shortcuts to the codec because we don't want to spin up a TLS
    // handshake just to assert the PA fields make it onto the wire.
    var sc: ServerConn = .{
        .conn = undefined,
        .app = undefined,
        .peer = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .retry_source_cid = @splat(0),
        .initial_server_cid = .{ 'Q', 'N', 'S', '-', 0xa1, 0xa2, 0xa3, 0xa4 },
        .last_activity_us = 0,
    };
    sc.pa_alt_cid = .{ 'Q', 'N', 'S', '-', 0xb1, 0xb2, 0xb3, 0xb4 };
    sc.pa_alt_token = try quic_zig.conn.stateless_reset.derive(&stateless_reset_key, &sc.pa_alt_cid);
    sc.pa_alt_cid_set = true;

    const cfg: quic_zig.PreferredAddressConfig = .{
        .ipv4 = .{ .bytes = interop_runner_server_ipv4, .port = 444 },
        .ipv6 = .{ .bytes = interop_runner_server_ipv6, .port = 444, .flow = 0 },
    };
    const pa = buildPreferredAddress(cfg, &sc);

    const params: quic_zig.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 1 * 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 1 * 1024 * 1024,
        .initial_max_stream_data_uni = 1 * 1024 * 1024,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 16,
        .max_udp_payload_size = endpoint_udp_payload_size,
        .active_connection_id_limit = 2,
        .preferred_address = pa,
    };

    var buf: [512]u8 = undefined;
    const n = try params.encode(&buf);
    const decoded = try quic_zig.tls.transport_params.Params.decode(buf[0..n]);

    const got = decoded.preferred_address orelse return error.MissingPreferredAddress;
    try std.testing.expectEqualSlices(u8, pa.connection_id.slice(), got.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &pa.stateless_reset_token, &got.stateless_reset_token);
    try std.testing.expectEqual(pa.ipv4_port, got.ipv4_port);
    try std.testing.expectEqual(pa.ipv6_port, got.ipv6_port);
    try std.testing.expectEqualSlices(u8, &pa.ipv4_address, &got.ipv4_address);
    try std.testing.expectEqualSlices(u8, &pa.ipv6_address, &got.ipv6_address);
}

test "buildPreferredAddress projects v4-only / v6-only configs into RFC 9000 §18.2 sentinels" {
    // RFC 9000 §18.2 lets either family be all-zero as a sentinel for
    // "no preferred address for this family". When the runtime
    // `PreferredAddressConfig` only sets one family, the other should
    // come out zero-valued — no spurious hostname leak across families.
    var sc: ServerConn = .{
        .conn = undefined,
        .app = undefined,
        .peer = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .retry_source_cid = @splat(0),
        .initial_server_cid = .{ 'Q', 'N', 'S', '-', 0xc1, 0xc2, 0xc3, 0xc4 },
        .last_activity_us = 0,
    };
    sc.pa_alt_cid = .{ 'Q', 'N', 'S', '-', 0xd1, 0xd2, 0xd3, 0xd4 };
    sc.pa_alt_token = @splat(0xab);
    sc.pa_alt_cid_set = true;

    const v4_only_cfg: quic_zig.PreferredAddressConfig = .{
        .ipv4 = .{ .bytes = interop_runner_server_ipv4, .port = 444 },
        .ipv6 = null,
    };
    const v4_only = buildPreferredAddress(v4_only_cfg, &sc);
    try std.testing.expectEqualSlices(u8, &interop_runner_server_ipv4, &v4_only.ipv4_address);
    try std.testing.expectEqual(@as(u16, 444), v4_only.ipv4_port);
    const zero16: [16]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero16, &v4_only.ipv6_address);
    try std.testing.expectEqual(@as(u16, 0), v4_only.ipv6_port);

    const v6_only_cfg: quic_zig.PreferredAddressConfig = .{
        .ipv4 = null,
        .ipv6 = .{ .bytes = interop_runner_server_ipv6, .port = 444, .flow = 0 },
    };
    const v6_only = buildPreferredAddress(v6_only_cfg, &sc);
    const zero4: [4]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero4, &v6_only.ipv4_address);
    try std.testing.expectEqual(@as(u16, 0), v6_only.ipv4_port);
    try std.testing.expectEqualSlices(u8, &interop_runner_server_ipv6, &v6_only.ipv6_address);
    try std.testing.expectEqual(@as(u16, 444), v6_only.ipv6_port);
}

test "ServerConn.last_recv_socket defaults to main on init" {
    // Pre-migration the qns server's outbound drain assumes
    // `last_recv_socket == 0` (the main listening socket). A regression
    // that left it as garbage / non-zero would make every reply on a
    // brand-new connection go through the alt-port socket, breaking
    // the handshake before any peer ever observes the
    // `preferred_address` advertise. We can't run `ServerConn.init`
    // without a real `/www` and an `std.Io` but the field's
    // default-zero invariant is enough — `ServerConn.init` doesn't
    // override it (only the recv-side `dispatchInbound` flips it),
    // so as long as the struct literal and the in-place assignment
    // in `ServerConn.init` agree, this latch holds.
    const sc: ServerConn = .{
        .conn = undefined,
        .app = undefined,
        .peer = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .retry_source_cid = @splat(0),
        .initial_server_cid = @splat(0),
        .last_activity_us = 0,
    };
    try std.testing.expectEqual(@as(u8, 0), sc.last_recv_socket);
}
