//! Opinionated `std.Io`-based UDP server loop for `quic_zig.Server`.
//!
//! `quic_zig.Server` is intentionally I/O-agnostic: the embedder owns the
//! UDP socket and the wall clock. That keeps the library minimal but
//! means every embedder spelling out their first server reaches for the
//! same boilerplate — bind a UDP socket, tune `SO_RCVBUF` /
//! `SO_SNDBUF`, drive a `receiveTimeout` -> `feed` -> `poll-each-slot`
//! -> `tick` -> `reap` loop on a monotonic clock.
//!
//! `runUdpServer` is that boilerplate, distilled. It is opt-in: pass
//! a `*Server` and a `RunUdpOptions` and the function takes over the
//! socket. Embedders who need full control (Retry token issuance,
//! version negotiation, deterministic CIDs, batched I/O via `recvmmsg`,
//! qlog file rotation) keep using `Server.feed` / `Server.poll`
//! directly.
//!
//! Time
//! ----
//! The loop uses `std.Io.Timestamp.now(io, .awake)` (a monotonic clock)
//! and converts to microseconds since the loop start, then feeds that
//! into `Server.feed` / `Server.tick`. Wall-clock skew on the host
//! cannot drag QUIC's recovery timers backwards; `now_us` is strictly
//! monotonically non-decreasing for the lifetime of the server.
//!
//! Shutdown
//! --------
//! If `RunUdpOptions.shutdown_flag` is set, the loop checks the flag
//! on every iteration. Once flipped, it calls `Server.shutdown` to
//! queue `CONNECTION_CLOSE` on every live slot, then continues
//! polling for up to `shutdown_grace_us` so those CONNECTION_CLOSEs
//! actually reach the wire. After the grace period (or once every
//! slot is reaped, whichever comes first), it returns cleanly.
//!
//! See `README.md` for an end-to-end embedder example.

const std = @import("std");

const Server = @import("../server.zig").Server;
const path_mod = @import("../conn/path.zig");
const socket_opts = @import("socket_opts.zig");

const Net = std.Io.net;
const Address = path_mod.Address;

/// Default size of the receive buffer scratch space used by the loop.
/// 64 KiB is the maximum a single UDP datagram can be, and matches
/// the QNS endpoint's `rx` buffer.
pub const default_rx_buffer_bytes: usize = 64 * 1024;

/// Hardening guide §8 `max_datagrams_per_event_loop_tick`: the loop
/// processes exactly one inbound datagram per iteration. After ingest
/// it drains every slot's outbox before looping back to `recv`. The
/// 1-per-tick cap is a structural property of `runUdpServer`, not a
/// configurable knob — it exists primarily so PTO / loss-detection
/// tick-driven work can't be starved by a hot ingress queue. Embedders
/// that need batched ingress (e.g. via `recvmmsg`) bypass this loop
/// and call `Server.feed` directly, taking responsibility for their
/// own per-tick budget.
pub const max_datagrams_per_loop_iteration: u32 = 1;

/// Default size of the send buffer scratch space used by the loop.
/// 1500 bytes covers the default QUIC `max_udp_payload_size` plus a
/// small margin; embedders that raise the transport parameter cap
/// will need to override.
pub const default_tx_buffer_bytes: usize = 1500;

/// How the loop is configured. The defaults are tuned for a small
/// open-internet QUIC server; tweak as needed for embedded targets,
/// load testers, or fixtures.
pub const RunUdpOptions = struct {
    /// IPv4 or IPv6 listen address as a literal — `"0.0.0.0:443"`,
    /// `"127.0.0.1:4433"`, `"[::]:443"`, etc. Parsed by
    /// `std.Io.net.IpAddress.parseLiteral`.
    listen: []const u8,
    /// Caller-provided `std.Io` instance. quic_zig does not pick its
    /// own I/O backend — pass whatever you're already using
    /// (typically `std.Io.threaded` or a single-threaded harness).
    io: std.Io,
    /// How long to block in `Socket.receiveTimeout` between
    /// feed/tick iterations. The default of 5 ms keeps
    /// `Connection.tick` responsive (QUIC's PTO timer fires on
    /// millisecond-ish granularity) without busy-spinning when the
    /// network is idle. Match what the QNS endpoint uses.
    receive_timeout: std.Io.Duration = std.Io.Duration.fromMilliseconds(5),
    /// Apply quic_zig's recommended `SO_RCVBUF` / `SO_SNDBUF` tuning to
    /// the bound socket via `transport.applyServerTuning`. On by
    /// default — production QUIC servers want big OS buffers to
    /// absorb open-internet bursts. Turn off only for tiny fixtures
    /// where the 4 MiB default is wasteful.
    tune_socket: bool = true,
    /// Tuning applied when `tune_socket` is true. Overriding lets
    /// embedders pick smaller (embedded targets) or larger (10G NIC)
    /// buffers without disabling tuning altogether.
    tuning: socket_opts.ServerTuning = .{},

    /// Enable IETF ECN signaling (RFC 9000 §13.4). When `true`, the
    /// loop sets `IP_TOS` / `IPV6_TCLASS` to ECT(0) on the bound
    /// socket and `IP_RECVTOS` / `IPV6_RECVTCLASS` so the kernel
    /// surfaces the per-datagram TOS byte via cmsg. The parsed
    /// codepoint is plumbed into `Server.feedWithEcn`. On by default
    /// — production QUIC reaps modest goodput wins by reacting to
    /// router-driven CE marks. Embedders on environments that bleach
    /// ECN can flip this off and the loop falls through to the plain
    /// `Server.feed` (Not-ECT) path.
    enable_ecn: bool = true,
    /// Send-side ECN codepoint applied to the bound socket when
    /// `enable_ecn = true`. Defaults to ECT(0) (RFC 9000 §13.4
    /// recommends ECT(0) for QUIC). `not_ect` disables marking;
    /// `ect1` and `ce` are reserved.
    ecn_send_codepoint: socket_opts.EcnCodepoint = .ect0,
    /// Per-recv cmsg control buffer size. Each iteration allocates a
    /// stack-local buffer of this many bytes for the kernel to
    /// populate with TOS / TCLASS cmsgs. 64 bytes is comfortably
    /// large enough for both `IP_TOS` and `IPV6_TCLASS` cmsgs in
    /// the same datagram with alignment slack. Bump only if
    /// pipelining other ancillary data (PKTINFO, etc.) onto the same
    /// socket is in scope.
    cmsg_buffer_bytes: usize = socket_opts.default_cmsg_buffer_bytes,
    /// Optional shutdown signal. The loop calls `flag.load(.acquire)`
    /// at the top of every iteration; once it observes `true`, it
    /// calls `Server.shutdown(0, "")`, drains outgoing CONNECTION_CLOSE
    /// for up to `shutdown_grace_us`, and returns cleanly. Embedders
    /// typically wire this to a `SIGINT` handler.
    shutdown_flag: ?*const std.atomic.Value(bool) = null,
    /// Maximum microseconds to keep the loop running after
    /// `shutdown_flag` is observed true. The grace window lets
    /// CONNECTION_CLOSE frames reach peers; without it, the server
    /// would just stop sending and peers would idle out.
    shutdown_grace_us: u64 = 5_000_000,
    /// Receive scratch buffer size. The loop allocates this on its
    /// own stack; embedders cannot pass external memory because
    /// `std.Io` does not surface any zero-copy receive hooks today.
    rx_buffer_bytes: usize = default_rx_buffer_bytes,
    /// Send scratch buffer size. Should be at least the connection's
    /// negotiated `max_udp_payload_size` (default 1200 in quic_zig, plus
    /// header overhead — 1500 is safe; bump for jumbo-frame paths).
    tx_buffer_bytes: usize = default_tx_buffer_bytes,
    /// How often (in iterations) to call `Server.reap`. Reaping is
    /// cheap, but doing it every iteration when the typical loop is
    /// already a few hundred microseconds is pure overhead. The
    /// default of 64 means the slot table is reclaimed every few
    /// hundred milliseconds at idle.
    reap_every_n_iterations: u32 = 64,
};

/// Errors `runUdpServer` can return. Most are propagated from
/// `std.Io.net.IpAddress.bind`, `Socket.send`, or `Server.feed` —
/// the helper itself does not introduce new error categories.
pub const RunError = error{
    /// `RunUdpOptions.listen` did not parse as an IPv4/IPv6 literal.
    InvalidListenAddress,
    /// `tune_socket = true` but the kernel refused both the privileged
    /// (`*BUFFORCE`) and cap-respecting `setsockopt` calls. Production
    /// servers without `CAP_NET_ADMIN` rarely hit this — the
    /// cap-respecting fallback usually returns OK with a smaller
    /// buffer. Embedders that want best-effort tuning should clear
    /// `tune_socket` and call `transport.setRecvBufferSize` /
    /// `transport.setSendBufferSize` directly.
    SocketTuningFailed,
    /// `RunUdpOptions.rx_buffer_bytes` or `tx_buffer_bytes` was set
    /// to 0. Both must be > 0 for the loop to make progress.
    InvalidBufferSize,
    OutOfMemory,
} || Net.IpAddress.BindError ||
    Net.Socket.SendError ||
    Net.Socket.ReceiveTimeoutError ||
    Server.Error;

/// Run a UDP server loop driven by `server`. Blocks until either
/// `RunUdpOptions.shutdown_flag` is observed true or an unrecoverable
/// I/O error occurs.
///
/// The loop owns the socket: it is bound, tuned, used, and closed
/// inside this function. The `server` is used non-owning — its
/// `Config` and lifecycle are still entirely the caller's.
pub fn runUdpServer(server: *Server, options: RunUdpOptions) RunError!void {
    if (options.rx_buffer_bytes == 0 or options.tx_buffer_bytes == 0) {
        return error.InvalidBufferSize;
    }

    const bind_addr = Net.IpAddress.parseLiteral(options.listen) catch {
        return error.InvalidListenAddress;
    };
    const sock = try Net.IpAddress.bind(&bind_addr, options.io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(options.io);

    if (options.tune_socket) {
        socket_opts.applyServerTuning(sock.handle, options.tuning) catch {
            // Permission and resource caps are common in container
            // sandboxes; surface them as a single soft error so the
            // embedder can decide whether to retry without tuning.
            // We collapse every `setsockopt` failure mode (permission,
            // resource, unsupported, invalid, unexpected) into one
            // signal because none of them are individually
            // actionable from the loop's perspective.
            return error.SocketTuningFailed;
        };
    }

    // Enable IP-layer ECN if the embedder asked for it. Both setters
    // are best-effort: if the kernel rejects (e.g. a sandbox without
    // CAP_NET_RAW for some platforms, or a non-IP socket), we fall
    // through to the no-ECN path silently rather than aborting the
    // whole server. The Connection-side ECN counters degrade
    // gracefully when no codepoint ever arrives.
    var ecn_active = options.enable_ecn;
    if (ecn_active) {
        socket_opts.setEcnSendMarking(sock.handle, options.ecn_send_codepoint) catch {
            ecn_active = false;
        };
        if (ecn_active) {
            socket_opts.setEcnRecvEnabled(sock.handle, true) catch {
                ecn_active = false;
            };
        }
    }

    const allocator = server.allocator;
    const rx = try allocator.alloc(u8, options.rx_buffer_bytes);
    defer allocator.free(rx);
    const tx = try allocator.alloc(u8, options.tx_buffer_bytes);
    defer allocator.free(tx);
    const cmsg_buf_len: usize = if (ecn_active) options.cmsg_buffer_bytes else 0;
    var empty_cmsg_buf: [0]u8 = undefined;
    const cmsg_buf: []u8 = if (cmsg_buf_len > 0)
        try allocator.alloc(u8, cmsg_buf_len)
    else
        empty_cmsg_buf[0..0];
    defer if (cmsg_buf_len > 0) allocator.free(cmsg_buf);

    const start = std.Io.Timestamp.now(options.io, .awake);
    var iteration_count: u32 = 0;
    var shutdown_started: bool = false;
    var shutdown_deadline_us: u64 = 0;

    while (true) {
        var now_us = monotonicNowUs(options.io, start);

        // Shutdown gate: once the flag flips, queue CONNECTION_CLOSE
        // on every slot and start a grace window. We keep polling
        // and ticking inside the window so the queued
        // CONNECTION_CLOSE actually reaches the wire.
        if (!shutdown_started) {
            if (options.shutdown_flag) |flag| {
                if (flag.load(.acquire)) {
                    server.shutdown(0, "");
                    shutdown_started = true;
                    shutdown_deadline_us = now_us +| options.shutdown_grace_us;
                }
            }
        } else {
            // Either the deadline expired or every slot has drained.
            if (now_us >= shutdown_deadline_us or server.connectionCount() == 0) {
                _ = server.reap();
                return;
            }
        }

        // Receive (or timeout). Timeout is the loop's heartbeat —
        // it bounds the latency between datagram arrival and the
        // next `tick` call, which is what drives QUIC PTO. Exactly
        // one datagram per iteration per
        // `max_datagrams_per_loop_iteration` (hardening §8).
        //
        // Two paths: when ECN is active we go through
        // `receiveManyTimeout` so we can hand the kernel a control
        // buffer for IP_TOS / IPV6_TCLASS cmsgs. Otherwise we keep
        // the cheaper `receiveTimeout` shape (no control buffer
        // alloc, no cmsg parse).
        var maybe_msg: ?Net.IncomingMessage = null;
        var ecn: socket_opts.EcnCodepoint = .not_ect;
        if (ecn_active) {
            var msg: Net.IncomingMessage = .init;
            msg.control = cmsg_buf;
            const buf_slice = (&msg)[0..1];
            const ret = sock.receiveManyTimeout(options.io, buf_slice, rx, .{}, .{
                .duration = .{
                    .raw = options.receive_timeout,
                    .clock = .awake,
                },
            });
            if (ret[0]) |err| switch (err) {
                error.Timeout => {},
                else => return err,
            } else if (ret[1] == 1) {
                ecn = socket_opts.parseEcnFromControl(msg.control);
                maybe_msg = msg;
            }
        } else {
            maybe_msg = sock.receiveTimeout(options.io, rx, .{
                .duration = .{
                    .raw = options.receive_timeout,
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Timeout => null,
                else => return err,
            };
        }

        // Refresh time after the (possibly-blocking) receive call.
        // Don't reuse the pre-receive timestamp: tick / poll need to
        // see the actual now_us so PTO timers fire on schedule.
        now_us = monotonicNowUs(options.io, start);

        if (maybe_msg) |msg| {
            const from_addr = ipAddressToPathAddress(msg.from);
            // `feed` swallows per-connection errors internally; only
            // OutOfMemory propagates out, and that's already a hard
            // failure for the loop. The FeedOutcome is informational —
            // production embedders may want to plumb it into a metrics
            // counter, but the default loop just lets it ride.
            _ = try server.feedWithEcn(msg.data, from_addr, ecn, now_us);

            // Drain any Version Negotiation / Retry packets that
            // `feed` queued. Sending these via the same socket the
            // datagram arrived on is part of the Server contract:
            // they are stateless responses with no associated slot,
            // so the per-slot poll loop below would never reach
            // them.
            while (server.drainStatelessResponse()) |response| {
                const dest = pathAddressToIpAddress(response.dst) orelse continue;
                sock.send(options.io, &dest, response.slice()) catch {
                    // Send-side failures here are not fatal: VN/Retry
                    // is best-effort. The peer will retry on its next
                    // Initial. A persistent failure becomes visible
                    // through the per-slot poll path soon enough.
                };
            }
        }

        // Drain every slot's outbox and tick its recovery clock in
        // one pass. We use `Connection.pollDatagram` (path-aware)
        // rather than `Server.poll` so VN/Retry peers, migration,
        // and multipath all see the right destination address.
        // Slots without a current peer address (synthetic fixtures,
        // disconnected peers) are skipped silently.
        //
        // Per-connection errors are swallowed: a malformed peer must
        // not tear down the whole server. The connection itself
        // transitions to `.closed` and gets reaped on the next pass.
        for (server.iterator()) |slot| {
            // Terminal closed → nothing to do. Closing/draining slots
            // stay in the loop so their deadlines fire and the
            // closing-state CC retransmits can still emit (RFC 9000
            // §10.2.1 ¶3). `drainSlot`/`tick` are both idempotent on
            // those states.
            if (slot.conn.closeState() == .closed) continue;
            drainSlot(slot, tx, now_us, sock, options.io) catch {};
            slot.conn.tick(now_us) catch {};
        }

        iteration_count +%= 1;
        if (iteration_count % options.reap_every_n_iterations == 0) {
            _ = server.reap();
        }
    }
}

/// Drain every queued outgoing datagram for one slot. Caller wraps
/// the call in a `catch {}` so a per-connection failure (TLS hiccup,
/// CID exhaustion) doesn't abort the whole server loop. Errors only
/// propagate when `sock.send` itself fails — that's a real I/O
/// failure the embedder needs to know about.
fn drainSlot(
    slot: *Server.Slot,
    tx: []u8,
    now_us: u64,
    sock: Net.Socket,
    io: std.Io,
) !void {
    while (try slot.conn.pollDatagram(tx, now_us)) |out| {
        const target = out.to orelse slot.peer_addr orelse continue;
        const dest = pathAddressToIpAddress(target) orelse continue;
        try sock.send(io, &dest, tx[0..out.len]);
    }
}

/// Convert the loop's monotonic-clock origin into a microsecond
/// offset suitable for `Server.feed` / `Server.tick`. Mirrors the
/// QNS endpoint's `qnsNowUs` so the two stay numerically consistent
/// when both are running.
fn monotonicNowUs(io: std.Io, start: std.Io.Timestamp) u64 {
    const now = std.Io.Timestamp.now(io, .awake);
    const delta = start.durationTo(now).toMicroseconds();
    if (delta <= 0) return 0;
    return @intCast(delta);
}

/// Project a `std.Io.net.IpAddress` into quic_zig's bag-of-bytes
/// `path.Address`. Mirrors the QNS endpoint's `netAddressToPathAddress`
/// — kept private here because the only consumer is the loop itself.
fn ipAddressToPathAddress(addr: Net.IpAddress) Address {
    var out: Address = .{};
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

/// Inverse projection: turn a quic_zig `path.Address` back into a
/// `std.Io.net.IpAddress` for the outgoing `Socket.send` call.
/// Returns `null` for a zero-initialized / unrecognized tag — the
/// loop treats that as "no usable destination" and skips the send.
fn pathAddressToIpAddress(addr: Address) ?Net.IpAddress {
    switch (addr.bytes[0]) {
        4 => {
            var ip4_bytes: [4]u8 = undefined;
            @memcpy(&ip4_bytes, addr.bytes[1..5]);
            const port = std.mem.readInt(u16, addr.bytes[5..7], .big);
            return .{ .ip4 = .{ .bytes = ip4_bytes, .port = port } };
        },
        6 => {
            var ip6_bytes: [16]u8 = undefined;
            @memcpy(&ip6_bytes, addr.bytes[1..17]);
            const port = std.mem.readInt(u16, addr.bytes[17..19], .big);
            const flow: u32 = (@as(u32, addr.bytes[19]) << 16) |
                (@as(u32, addr.bytes[20]) << 8) |
                @as(u32, addr.bytes[21]);
            return .{ .ip6 = .{ .bytes = ip6_bytes, .port = port, .flow = flow } };
        },
        else => return null,
    }
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;

test "RunUdpOptions: defaults are sensible" {
    const opts: RunUdpOptions = .{
        .listen = "127.0.0.1:0",
        .io = undefined, // not invoked in this test
    };
    try testing.expectEqualStrings("127.0.0.1:0", opts.listen);
    try testing.expectEqual(@as(i64, 5), opts.receive_timeout.toMilliseconds());
    try testing.expect(opts.tune_socket);
    try testing.expectEqual(@as(u64, 5_000_000), opts.shutdown_grace_us);
    try testing.expectEqual(default_rx_buffer_bytes, opts.rx_buffer_bytes);
    try testing.expectEqual(default_tx_buffer_bytes, opts.tx_buffer_bytes);
    try testing.expect(opts.shutdown_flag == null);
}

test "ipAddressToPathAddress / pathAddressToIpAddress round-trip IPv4" {
    const v4: Net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 192, 168, 1, 7 },
        .port = 4433,
    } };
    const pa = ipAddressToPathAddress(v4);
    try testing.expectEqual(@as(u8, 4), pa.bytes[0]);

    const back = pathAddressToIpAddress(pa).?;
    try testing.expect(back == .ip4);
    try testing.expectEqual(v4.ip4.port, back.ip4.port);
    try testing.expectEqualSlices(u8, &v4.ip4.bytes, &back.ip4.bytes);
}

test "ipAddressToPathAddress / pathAddressToIpAddress round-trip IPv6" {
    const v6: Net.IpAddress = .{ .ip6 = .{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 4433,
        .flow = 0xabcdef,
    } };
    const pa = ipAddressToPathAddress(v6);
    try testing.expectEqual(@as(u8, 6), pa.bytes[0]);

    const back = pathAddressToIpAddress(pa).?;
    try testing.expect(back == .ip6);
    try testing.expectEqual(v6.ip6.port, back.ip6.port);
    try testing.expectEqual(v6.ip6.flow, back.ip6.flow);
    try testing.expectEqualSlices(u8, &v6.ip6.bytes, &back.ip6.bytes);
}

test "pathAddressToIpAddress returns null for empty address" {
    const empty: Address = .{};
    try testing.expect(pathAddressToIpAddress(empty) == null);
}

test "monotonicNowUs is non-negative" {
    const io = std.testing.io;
    const start = std.Io.Timestamp.now(io, .awake);
    const elapsed = monotonicNowUs(io, start);
    // Right after start the elapsed time is small (likely 0) but
    // never wraps to a giant u64.
    try testing.expect(elapsed < 1_000_000); // < 1 second
}
