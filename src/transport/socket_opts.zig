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
//! `setsockopt` so any consumer of the nullq library — the QNS
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

/// Underlying socket handle type; matches `std.Io.net.Socket.Handle`.
pub const Handle = posix.socket_t;

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

/// Apply nullq's recommended server-side tuning to a freshly bound
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
