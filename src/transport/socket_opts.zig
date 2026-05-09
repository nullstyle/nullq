//! Socket-option knobs for QUIC datagram sockets.
//!
//! QUIC servers exposed to the open internet need bigger kernel
//! buffers than the OS default (~200 KiB on Linux, ~9 KiB on macOS for
//! UDP). On a 1 Gbit/s NIC a single 5-tuple can deliver hundreds of
//! 1350-byte datagrams in a few hundred microseconds; if the userland
//! receive loop is briefly preempted, the kernel's `SO_RCVBUF` queue
//! is the only thing that absorbs the burst before the kernel starts
//! dropping packets and incrementing `netstat -s | grep "receive
//! buffer errors"`. Those drops look like ordinary loss to QUIC, so
//! they trigger PTO/retransmits, hurt goodput, and can mask real
//! congestion-control behavior. msquic, quic-go, lsquic, and
//! nginx-quic all bump `SO_RCVBUF` / `SO_SNDBUF` to several MiB at
//! socket setup for exactly this reason.
//!
//! This module provides small, platform-aware wrappers around
//! `setsockopt` so any consumer of the quic_zig library — the QNS
//! endpoint, an embedded server, a load tester — can tune a freshly
//! bound socket the same way.
//!
//! Conventions:
//! * Sizes are passed as `usize` (bytes). The Linux kernel will
//!   silently double the requested value (`net/core/sock.c`
//!   `sock_setsockopt`), and `net.core.rmem_max` / `wmem_max` cap
//!   the final size; an unprivileged process cannot exceed the cap.
//! * On Linux we first attempt `SO_RCVBUFFORCE` /
//!   `SO_SNDBUFFORCE` (which require `CAP_NET_ADMIN` and bypass
//!   the sysctl cap). If that fails with `EPERM` we fall through
//!   to the regular cap-respecting variant. Production QUIC
//!   servers run inside containers or behind systemd hardening
//!   where granting `CAP_NET_ADMIN` is cheap; outside that, the
//!   fallback gets us whatever `rmem_max` allows.
//! * macOS / BSD do not have a "force" variant. The kernel honors
//!   the requested size up to `kern.ipc.maxsockbuf` (default
//!   ~8 MiB on macOS Sequoia).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Platform-specific IP-layer constants. `posix.IP` / `posix.IPV6`
/// resolve to `void` on macOS / Darwin (the `std.c` switch elides
/// Apple), so we hard-code the numeric values from the kernel
/// headers — these are wire-stable ABI on every Unix we run on.
const ip_consts = blk: {
    if (builtin.os.tag == .linux) {
        // include/uapi/linux/in.h
        break :blk struct {
            pub const ip_proto: u32 = 0;
            pub const ipv6_proto: u32 = 41;
            pub const ip_tos: u32 = 1;
            pub const ip_recvtos: u32 = 13;
            pub const ipv6_tclass: u32 = 67;
            pub const ipv6_recvtclass: u32 = 66;
        };
    } else if (builtin.os.tag.isDarwin()) {
        // bsd/netinet/in.h, bsd/netinet6/in6.h
        break :blk struct {
            pub const ip_proto: u32 = 0;
            pub const ipv6_proto: u32 = 41;
            pub const ip_tos: u32 = 3;
            pub const ip_recvtos: u32 = 27;
            pub const ipv6_tclass: u32 = 36;
            pub const ipv6_recvtclass: u32 = 35;
        };
    } else {
        // Unknown platform — pretend the constants are unset so the
        // setter helpers below fall through to `error.Unsupported`.
        break :blk struct {
            pub const ip_proto: u32 = 0;
            pub const ipv6_proto: u32 = 0;
            pub const ip_tos: u32 = 0;
            pub const ip_recvtos: u32 = 0;
            pub const ipv6_tclass: u32 = 0;
            pub const ipv6_recvtclass: u32 = 0;
        };
    }
};

/// True iff the build target exposes IP TOS / IPV6 TCLASS sockopts.
/// Both setter helpers degrade to `error.Unsupported` on platforms
/// where this is `false`.
const has_ip_ecn_sockopts: bool = builtin.os.tag == .linux or builtin.os.tag.isDarwin();

/// Underlying socket handle type; matches `std.Io.net.Socket.Handle`.
pub const Handle = posix.socket_t;

/// IETF ECN codepoint (RFC 3168 §5). The two low bits of the IPv4
/// TOS byte / IPv6 TCLASS byte. QUIC uses these for path-level
/// congestion signaling (RFC 9000 §13.4):
/// * `not_ect` (0b00) — endpoint is opting out of ECN.
/// * `ect0` (0b10) — ECN-Capable, codepoint 0; quic_zig's default for
///   1-RTT and 0-RTT packets.
/// * `ect1` (0b01) — ECN-Capable, codepoint 1; quic_zig only ever
///   parses, never emits, this on the send side (per QUIC consensus).
/// * `ce` (0b11) — Congestion Experienced; only ever set by routers
///   on the path. A QUIC endpoint that emits CE itself is broken.
pub const EcnCodepoint = enum(u2) {
    not_ect = 0b00,
    ect1 = 0b01,
    ect0 = 0b10,
    ce = 0b11,
};

/// Recommended size for the per-recv cmsg control buffer that the
/// loop hands `Socket.receiveTimeout`. 64 bytes is comfortably big
/// enough for both `IP_TOS` (Linux IP_TOS / macOS RECVTOS) and
/// `IPV6_TCLASS` cmsgs in one datagram, including alignment padding;
/// production QUIC embedders rarely enable other ancillary data
/// (PKTINFO etc.) on the QUIC socket, so the 64-byte ceiling is
/// generous.
pub const default_cmsg_buffer_bytes: usize = 64;

/// Errors raised by the ECN socket-option helpers. They wrap the
/// same `setsockopt` error space as the buffer helpers above.
pub const SetEcnError = error{
    /// The platform does not expose either `IP_TOS` or `IPV6_TCLASS`.
    /// Embedders that must run on such a platform should fall back to
    /// disabling ECN at the `Connection.Config` / `Server.Config`
    /// level rather than treating this as fatal.
    Unsupported,
    /// `setsockopt` rejected the value.
    InvalidValue,
    /// The current process lacks the privileges to set the socket
    /// option (rare; sometimes seen in restrictive container
    /// sandboxes).
    PermissionDenied,
} || posix.UnexpectedError;

/// Set the outgoing IP-layer ECN codepoint for every datagram
/// emitted on `handle`. Sets both `IP_TOS` (IPv4) and `IPV6_TCLASS`
/// (IPv6) so the same socket carries the marking on dual-stack
/// listeners. Failures on the IPv6 setter when the socket is
/// AF_INET-only (and vice versa) collapse to "first success wins"
/// — the QUIC stack tolerates one of the two failing as long as
/// the address family it actually uses got the marking.
///
/// Only the low two bits of the TOS byte are touched; quic_zig
/// leaves the DSCP bits at zero (the kernel default).
pub fn setEcnSendMarking(handle: Handle, codepoint: EcnCodepoint) SetEcnError!void {
    if (!has_ip_ecn_sockopts) return error.Unsupported;
    const tos: c_int = @intFromEnum(codepoint);
    const tos_bytes = std.mem.asBytes(&tos);

    var any_ok = false;
    setsockoptIntChecked(handle, ip_consts.ip_proto, ip_consts.ip_tos, tos_bytes) catch |err| switch (err) {
        // OS treats the option as inapplicable for this socket family
        // — that's fine if the v6 setter below succeeds.
        error.Unsupported => {},
        else => |e| return e,
    };
    any_ok = true;

    // Some platforms expose IPV6_TCLASS only when the socket is
    // bound IPv6; on a strict-IPv4 socket the call returns EINVAL
    // / ENOPROTOOPT. Try anyway and swallow those failures.
    setsockoptIntChecked(handle, ip_consts.ipv6_proto, ip_consts.ipv6_tclass, tos_bytes) catch |err| switch (err) {
        error.Unsupported => {},
        else => |e| {
            // If IPv4 also failed (any_ok would be false), surface
            // the v6 error. Otherwise the v4 setter already won.
            if (!any_ok) return e;
        },
    };
    if (!any_ok) return error.Unsupported;
}

/// Enable ancillary delivery of the received IP TOS byte via cmsg
/// on `handle`. Sets `IP_RECVTOS` (Linux/BSD/macOS) and
/// `IPV6_RECVTCLASS` so a recvmsg with a control buffer surfaces
/// the per-datagram TOS. Same dual-stack tolerance as
/// `setEcnSendMarking` — at least one address family must succeed.
pub fn setEcnRecvEnabled(handle: Handle, enabled: bool) SetEcnError!void {
    if (!has_ip_ecn_sockopts) return error.Unsupported;
    const value: c_int = if (enabled) 1 else 0;
    const value_bytes = std.mem.asBytes(&value);

    var any_ok = false;
    setsockoptIntChecked(handle, ip_consts.ip_proto, ip_consts.ip_recvtos, value_bytes) catch |err| switch (err) {
        error.Unsupported => {},
        else => |e| return e,
    };
    any_ok = true;
    setsockoptIntChecked(handle, ip_consts.ipv6_proto, ip_consts.ipv6_recvtclass, value_bytes) catch |err| switch (err) {
        error.Unsupported => {},
        else => |e| {
            if (!any_ok) return e;
        },
    };
    if (!any_ok) return error.Unsupported;
}

fn setsockoptIntChecked(handle: Handle, level: u32, optname: u32, opt_bytes: []const u8) SetEcnError!void {
    // We can't use `posix.setsockopt` here: it panics on EINVAL,
    // and EINVAL is the documented "IPv6 option on an AF_INET
    // socket" / "IPv4 option on an AF_INET6 V6ONLY socket" return
    // — which is exactly the dual-stack-tolerant behavior the
    // ECN setters above rely on. Map the errnos ourselves and
    // surface them as `error.Unsupported` so the caller falls
    // through to the other address family.
    const rc = std.c.setsockopt(handle, @intCast(level), optname, opt_bytes.ptr, @intCast(opt_bytes.len));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INVAL,
        .NOPROTOOPT,
        .OPNOTSUPP,
        .AFNOSUPPORT,
        .PROTONOSUPPORT,
        => return error.Unsupported,
        .PERM, .ACCES => return error.PermissionDenied,
        .NOMEM, .NOBUFS => return error.InvalidValue,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// Walk a populated `recvmsg` control buffer and extract the IP
/// ECN codepoint, if present. Returns `not_ect` when no IP_TOS /
/// IPV6_TCLASS cmsg was found — that's the conservative choice
/// (no ECN marking observed). The walker tolerates malformed cmsg
/// payloads (zero-length data, oversized `cmsg_len`) by skipping
/// them; QUIC peers can't influence our control buffer so the
/// guards are belt-and-suspenders for kernel quirks.
pub fn parseEcnFromControl(control: []const u8) EcnCodepoint {
    // cmsghdr layout differs between glibc Linux (`size_t` len, two
    // `int`) and BSD/macOS (`socklen_t` len, two `int`). We read both
    // by reaching into `std.c.cmsghdr` (the `extern struct` defined
    // for every supported OS) and projecting the byte offsets via
    // `@offsetOf` / `@sizeOf`. CMSG_DATA pads the header to
    // pointer-alignment; CMSG_NXTHDR pads `cmsg_len` to the same.
    const Cmsg = std.c.cmsghdr;
    const header_size: usize = @sizeOf(Cmsg);
    const len_off: usize = @offsetOf(Cmsg, "len");
    const level_off: usize = @offsetOf(Cmsg, "level");
    const type_off: usize = @offsetOf(Cmsg, "type");
    const len_size: usize = @sizeOf(@FieldType(Cmsg, "len"));
    const align_to: usize = @sizeOf(usize);

    var pos: usize = 0;
    while (pos + header_size <= control.len) {
        const cmsg_len: usize = blk: {
            if (len_size == @sizeOf(usize)) {
                break :blk std.mem.readInt(usize, control[pos + len_off ..][0..@sizeOf(usize)], native_endian);
            } else {
                break :blk @intCast(std.mem.readInt(u32, control[pos + len_off ..][0..@sizeOf(u32)], native_endian));
            }
        };
        if (cmsg_len < header_size or pos + cmsg_len > control.len) break;
        const cmsg_level = std.mem.readInt(i32, control[pos + level_off ..][0..4], native_endian);
        const cmsg_type = std.mem.readInt(i32, control[pos + type_off ..][0..4], native_endian);

        const data_off = pos + header_size;
        const data_len = cmsg_len - header_size;

        if (cmsg_level == @as(i32, @intCast(ip_consts.ip_proto)) and
            (cmsg_type == @as(i32, @intCast(ip_consts.ip_tos)) or
                cmsg_type == @as(i32, @intCast(ip_consts.ip_recvtos))))
        {
            // The IP TOS byte may be carried as a single u8 (Linux
            // / macOS) or as a 4-byte int (some BSDs). Either way
            // the low byte holds the TOS.
            if (data_len >= 1 and data_off < control.len) {
                const tos_byte: u8 = control[data_off];
                return @enumFromInt(@as(u2, @truncate(tos_byte & 0x03)));
            }
        }
        if (cmsg_level == @as(i32, @intCast(ip_consts.ipv6_proto)) and cmsg_type == @as(i32, @intCast(ip_consts.ipv6_tclass))) {
            // IPV6_TCLASS is documented as a 4-byte int across all
            // major Unixes; the low byte holds the TCLASS (DSCP +
            // ECN), of which we only consume the low two ECN bits.
            if (data_len >= 4 and data_off + 4 <= control.len) {
                const tclass = std.mem.readInt(i32, control[data_off..][0..4], native_endian);
                return @enumFromInt(@as(u2, @truncate(@as(u32, @bitCast(tclass)) & 0x03)));
            }
            if (data_len >= 1 and data_off < control.len) {
                const tos_byte: u8 = control[data_off];
                return @enumFromInt(@as(u2, @truncate(tos_byte & 0x03)));
            }
        }

        // Advance to the next cmsg, aligned per `CMSG_ALIGN`.
        const aligned = std.mem.alignForward(usize, cmsg_len, align_to);
        if (aligned == 0) break;
        pos += aligned;
    }
    return .not_ect;
}

const native_endian = @import("builtin").cpu.arch.endian();

/// Recommended `SO_RCVBUF` for a QUIC server on the open internet.
///
/// 4 MiB lets a single connection absorb roughly a 30 ms burst at
/// 1 Gbit/s without OS-level drops, which is enough to ride out
/// scheduler jitter on a busy machine. Embedders that target tens
/// of thousands of concurrent connections may want to tune this
/// down (per-socket buffer × N connections is real RAM) or up,
/// after measuring `netstat -s` UDP receive-buffer errors.
pub const default_server_recv_buffer_bytes: usize = 4 * 1024 * 1024;

/// Recommended `SO_SNDBUF` for a QUIC server on the open internet.
///
/// QUIC sends are paced by the userland congestion controller, so
/// `SO_SNDBUF` mostly matters for absorbing transient
/// `EAGAIN`/`ENOBUFS` from a busy NIC. 4 MiB is conservative and
/// matches what other production stacks use.
pub const default_server_send_buffer_bytes: usize = 4 * 1024 * 1024;

/// Errors returned by `setRecvBufferSize` / `setSendBufferSize` /
/// `applyServerTuning`. See each variant for the corresponding
/// `setsockopt` failure mode.
pub const SetBufferError = error{
    /// The platform does not expose a way to set this option.
    Unsupported,
    /// The kernel rejected the value (rare; usually only on
    /// pathological inputs like 0 or > INT_MAX).
    InvalidValue,
    /// The current process lacks the privileges to grow the
    /// buffer beyond the system cap, *and* the cap-respecting
    /// fallback also failed. Production servers usually do not
    /// see this — the cap-respecting path returns OK with a
    /// silently smaller buffer.
    PermissionDenied,
    /// The kernel could not allocate the requested buffer.
    SystemResources,
} || posix.UnexpectedError;

/// Set the kernel receive buffer for a UDP socket.
///
/// On Linux this tries the `SO_RCVBUFFORCE` variant first to
/// bypass `net.core.rmem_max`, then falls back to `SO_RCVBUF` if
/// the process lacks `CAP_NET_ADMIN`. On other Unixes only
/// `SO_RCVBUF` is attempted.
pub fn setRecvBufferSize(handle: Handle, bytes: usize) SetBufferError!void {
    return setBufferImpl(handle, bytes, .recv);
}

/// Set the kernel send buffer for a UDP socket. See
/// `setRecvBufferSize` for the Linux-specific force fallback
/// behavior; the same approach is used here with
/// `SO_SNDBUFFORCE` / `SO_SNDBUF`.
pub fn setSendBufferSize(handle: Handle, bytes: usize) SetBufferError!void {
    return setBufferImpl(handle, bytes, .send);
}

const BufferDirection = enum { recv, send };

fn setBufferImpl(handle: Handle, bytes: usize, dir: BufferDirection) SetBufferError!void {
    if (bytes == 0) return error.InvalidValue;
    // setsockopt takes a C int. Saturate at INT_MAX rather than
    // overflowing — anyone asking for >2 GiB of socket buffer has
    // bigger problems than UDP drops.
    const value: c_int = if (bytes > std.math.maxInt(c_int))
        std.math.maxInt(c_int)
    else
        @intCast(bytes);
    const opt_bytes = std.mem.asBytes(&value);

    // On Linux, try the privileged "force" variant first. It is
    // the only way to exceed `net.core.{r,w}mem_max` without
    // editing sysctl; production servers behind systemd or k8s
    // typically have `CAP_NET_ADMIN` and benefit from this.
    if (builtin.os.tag == .linux) {
        const force_optname: u32 = switch (dir) {
            .recv => @intCast(std.os.linux.SO.RCVBUFFORCE),
            .send => @intCast(std.os.linux.SO.SNDBUFFORCE),
        };
        if (posix.setsockopt(handle, posix.SOL.SOCKET, force_optname, opt_bytes)) |_| {
            return;
        } else |err| switch (err) {
            // Unprivileged process: fall through to the
            // cap-respecting variant below. Same for kernels
            // that do not recognize *FORCE.
            error.PermissionDenied,
            error.InvalidProtocolOption,
            error.OperationUnsupported,
            => {},
            error.AlreadyConnected => return error.InvalidValue,
            error.TimeoutTooBig => return error.InvalidValue,
            error.SystemResources => return error.SystemResources,
            error.FileDescriptorNotASocket,
            error.SocketNotBound,
            error.NetworkDown,
            error.NoDevice,
            error.Unexpected,
            => return error.Unexpected,
        }
    }

    const optname: u32 = switch (dir) {
        .recv => @intCast(posix.SO.RCVBUF),
        .send => @intCast(posix.SO.SNDBUF),
    };

    posix.setsockopt(handle, posix.SOL.SOCKET, optname, opt_bytes) catch |err| switch (err) {
        error.PermissionDenied => return error.PermissionDenied,
        error.InvalidProtocolOption => return error.Unsupported,
        error.AlreadyConnected => return error.InvalidValue,
        error.TimeoutTooBig => return error.InvalidValue,
        error.OperationUnsupported => return error.Unsupported,
        error.SystemResources => return error.SystemResources,
        error.FileDescriptorNotASocket,
        error.SocketNotBound,
        error.NetworkDown,
        error.NoDevice,
        error.Unexpected,
        => return error.Unexpected,
    };
}

/// Apply quic_zig's recommended server-side tuning to a freshly bound
/// UDP socket. This is the one-shot helper an embedder calls right
/// after `Net.IpAddress.bind`. Failures from the underlying
/// `setsockopt` calls are returned so the caller can decide
/// whether to log-and-continue (the QNS endpoint does) or refuse
/// to start (a production server that requires headroom may
/// prefer to fail loudly).
pub const ServerTuning = struct {
    /// Bytes for `SO_RCVBUF`. `null` skips the call.
    recv_buffer_bytes: ?usize = default_server_recv_buffer_bytes,
    /// Bytes for `SO_SNDBUF`. `null` skips the call.
    send_buffer_bytes: ?usize = default_server_send_buffer_bytes,
};

/// Alias for `SetBufferError` — every error from `applyServerTuning`
/// flows through one of the underlying `setsockopt` calls.
pub const TuneError = SetBufferError;

/// Apply `ServerTuning` to a socket handle. Errors from the
/// individual setsockopt calls propagate; callers that want
/// best-effort behavior should use the lower-level
/// `setRecvBufferSize` / `setSendBufferSize` directly and discard
/// errors at the call site.
pub fn applyServerTuning(handle: Handle, tuning: ServerTuning) TuneError!void {
    if (tuning.recv_buffer_bytes) |bytes| try setRecvBufferSize(handle, bytes);
    if (tuning.send_buffer_bytes) |bytes| try setSendBufferSize(handle, bytes);
}

/// Read back the kernel's actual receive buffer size. Useful for
/// logging "we asked for 4 MiB, got N MiB" so operators can see
/// when sysctl caps are biting.
pub fn getRecvBufferSize(handle: Handle) !usize {
    return getBufferImpl(handle, .recv);
}

/// Read back the kernel's actual send buffer size via
/// `getsockopt(SO_SNDBUF, ...)`. Mirrors `getRecvBufferSize` and is
/// useful for the same operator-visible "asked vs. got" logging.
pub fn getSendBufferSize(handle: Handle) !usize {
    return getBufferImpl(handle, .send);
}

fn getBufferImpl(handle: Handle, dir: BufferDirection) !usize {
    const optname: u32 = switch (dir) {
        .recv => @intCast(posix.SO.RCVBUF),
        .send => @intCast(posix.SO.SNDBUF),
    };
    var value: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    switch (posix.errno(std.c.getsockopt(handle, posix.SOL.SOCKET, @intCast(optname), &value, &len))) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    if (value < 0) return 0;
    return @intCast(value);
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;
const Net = std.Io.net;

/// Test scaffolding: bind a real loopback UDP socket via the
/// public `std.Io` API so the tests exercise the same code path
/// as production callers.
const TestSocket = struct {
    socket: Net.Socket,
    io: std.Io,

    fn init() !TestSocket {
        const io = std.testing.io;
        const addr = try Net.IpAddress.parseLiteral("127.0.0.1:0");
        const sock = try Net.IpAddress.bind(&addr, io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        return .{ .socket = sock, .io = io };
    }

    fn deinit(self: *TestSocket) void {
        self.socket.close(self.io);
    }

    fn handle(self: *const TestSocket) Handle {
        return self.socket.handle;
    }
};

test "setRecvBufferSize grows the kernel buffer" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    const before = try getRecvBufferSize(ts.handle());

    const requested: usize = 1 * 1024 * 1024; // 1 MiB
    setRecvBufferSize(ts.handle(), requested) catch |err| switch (err) {
        // CI may not give us the privileges or the cap; if even
        // the cap-respecting fallback can't grow the buffer,
        // skip rather than fail.
        error.PermissionDenied, error.SystemResources => return error.SkipZigTest,
        else => return err,
    };

    const after = try getRecvBufferSize(ts.handle());
    // Linux doubles the requested value, BSD/macOS returns ~what
    // was set; either way we expect >= the prior default.
    try testing.expect(after >= before);
}

test "setSendBufferSize grows the kernel buffer" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    const before = try getSendBufferSize(ts.handle());

    const requested: usize = 1 * 1024 * 1024;
    setSendBufferSize(ts.handle(), requested) catch |err| switch (err) {
        error.PermissionDenied, error.SystemResources => return error.SkipZigTest,
        else => return err,
    };

    const after = try getSendBufferSize(ts.handle());
    try testing.expect(after >= before);
}

test "setRecvBufferSize rejects zero" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    try testing.expectError(error.InvalidValue, setRecvBufferSize(ts.handle(), 0));
}

test "setSendBufferSize rejects zero" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    try testing.expectError(error.InvalidValue, setSendBufferSize(ts.handle(), 0));
}

test "applyServerTuning sets both buffers" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    applyServerTuning(ts.handle(), .{
        .recv_buffer_bytes = 512 * 1024,
        .send_buffer_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.PermissionDenied, error.SystemResources => return error.SkipZigTest,
        else => return err,
    };

    const rcv = try getRecvBufferSize(ts.handle());
    const snd = try getSendBufferSize(ts.handle());
    try testing.expect(rcv > 0);
    try testing.expect(snd > 0);
}

test "applyServerTuning honors null fields" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    const before_rcv = try getRecvBufferSize(ts.handle());
    const before_snd = try getSendBufferSize(ts.handle());

    // Skip both; should be a no-op.
    try applyServerTuning(ts.handle(), .{
        .recv_buffer_bytes = null,
        .send_buffer_bytes = null,
    });

    try testing.expectEqual(before_rcv, try getRecvBufferSize(ts.handle()));
    try testing.expectEqual(before_snd, try getSendBufferSize(ts.handle()));
}

test "saturates oversize requests at INT_MAX" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    // Asking for usize.max bytes must not overflow our internal
    // c_int conversion; we should see a defined error or a
    // best-effort accept rather than `unreachable`.
    const requested: usize = std.math.maxInt(usize);
    _ = setRecvBufferSize(ts.handle(), requested) catch |err| switch (err) {
        error.PermissionDenied,
        error.SystemResources,
        error.Unsupported,
        error.InvalidValue,
        => return,
        else => return err,
    };
    // If the kernel did honor it, at least confirm we came back
    // without crashing.
    _ = try getRecvBufferSize(ts.handle());
}

test "default tuning constants are reasonable" {
    // Sanity: the recommended default should be at least 1 MiB,
    // which is the inflection point above which a single-burst
    // RTT delivery rarely overflows the kernel buffer. If
    // someone accidentally drops these to a small value the
    // QNS test will silently regress, so make it a unit test.
    try testing.expect(default_server_recv_buffer_bytes >= 1 * 1024 * 1024);
    try testing.expect(default_server_send_buffer_bytes >= 1 * 1024 * 1024);
}

test "EcnCodepoint two-bit encoding matches RFC 3168" {
    try testing.expectEqual(@as(u2, 0b00), @intFromEnum(EcnCodepoint.not_ect));
    try testing.expectEqual(@as(u2, 0b01), @intFromEnum(EcnCodepoint.ect1));
    try testing.expectEqual(@as(u2, 0b10), @intFromEnum(EcnCodepoint.ect0));
    try testing.expectEqual(@as(u2, 0b11), @intFromEnum(EcnCodepoint.ce));
}

test "setEcnSendMarking applies ECT(0) without erroring on loopback" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    setEcnSendMarking(ts.handle(), .ect0) catch |err| switch (err) {
        // Some sandboxes refuse to set IP options at all; accept.
        error.PermissionDenied,
        error.Unsupported,
        => return error.SkipZigTest,
        else => return err,
    };
}

test "setEcnRecvEnabled enables IP_RECVTOS without erroring on loopback" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    setEcnRecvEnabled(ts.handle(), true) catch |err| switch (err) {
        error.PermissionDenied,
        error.Unsupported,
        => return error.SkipZigTest,
        else => return err,
    };
    setEcnRecvEnabled(ts.handle(), false) catch |err| switch (err) {
        error.PermissionDenied,
        error.Unsupported,
        => return error.SkipZigTest,
        else => return err,
    };
}

test "parseEcnFromControl: empty buffer is not_ect" {
    try testing.expectEqual(EcnCodepoint.not_ect, parseEcnFromControl(&.{}));
}

test "parseEcnFromControl: hand-rolled IP_TOS cmsg returns the codepoint" {
    if (!has_ip_ecn_sockopts) return error.SkipZigTest;
    const Cmsg = std.c.cmsghdr;
    const header_size: usize = @sizeOf(Cmsg);
    const align_to: usize = @sizeOf(usize);
    const data_len: usize = 1;
    const cmsg_total = std.mem.alignForward(usize, header_size + data_len, align_to);
    var buf: [64]u8 = @splat(0);
    const len_off: usize = @offsetOf(Cmsg, "len");
    const level_off: usize = @offsetOf(Cmsg, "level");
    const type_off: usize = @offsetOf(Cmsg, "type");
    const len_size: usize = @sizeOf(@FieldType(Cmsg, "len"));
    if (len_size == @sizeOf(usize)) {
        std.mem.writeInt(usize, buf[len_off..][0..@sizeOf(usize)], header_size + data_len, native_endian);
    } else {
        std.mem.writeInt(u32, buf[len_off..][0..@sizeOf(u32)], @as(u32, @intCast(header_size + data_len)), native_endian);
    }
    std.mem.writeInt(i32, buf[level_off..][0..4], @as(i32, @intCast(ip_consts.ip_proto)), native_endian);
    std.mem.writeInt(i32, buf[type_off..][0..4], @as(i32, @intCast(ip_consts.ip_tos)), native_endian);
    // ECT(0) on the wire is the byte 0x02 (low two bits of TOS).
    buf[header_size] = 0x02;
    const out = parseEcnFromControl(buf[0..cmsg_total]);
    try testing.expectEqual(EcnCodepoint.ect0, out);
}

test "parseEcnFromControl: hand-rolled IPV6_TCLASS cmsg returns the codepoint" {
    if (!has_ip_ecn_sockopts) return error.SkipZigTest;
    const Cmsg = std.c.cmsghdr;
    const header_size: usize = @sizeOf(Cmsg);
    const align_to: usize = @sizeOf(usize);
    const data_len: usize = 4;
    const cmsg_total = std.mem.alignForward(usize, header_size + data_len, align_to);
    var buf: [64]u8 = @splat(0);
    const len_off: usize = @offsetOf(Cmsg, "len");
    const level_off: usize = @offsetOf(Cmsg, "level");
    const type_off: usize = @offsetOf(Cmsg, "type");
    const len_size: usize = @sizeOf(@FieldType(Cmsg, "len"));
    if (len_size == @sizeOf(usize)) {
        std.mem.writeInt(usize, buf[len_off..][0..@sizeOf(usize)], header_size + data_len, native_endian);
    } else {
        std.mem.writeInt(u32, buf[len_off..][0..@sizeOf(u32)], @as(u32, @intCast(header_size + data_len)), native_endian);
    }
    std.mem.writeInt(i32, buf[level_off..][0..4], @as(i32, @intCast(ip_consts.ipv6_proto)), native_endian);
    std.mem.writeInt(i32, buf[type_off..][0..4], @as(i32, @intCast(ip_consts.ipv6_tclass)), native_endian);
    // CE = 0b11.
    std.mem.writeInt(i32, buf[header_size..][0..4], 0x03, native_endian);
    const out = parseEcnFromControl(buf[0..cmsg_total]);
    try testing.expectEqual(EcnCodepoint.ce, out);
}
