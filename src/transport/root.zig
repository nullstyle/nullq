//! quic_zig.transport — UDP socket plumbing.
//!
//! quic_zig is transport-agnostic at the protocol layer: connections
//! consume and produce datagrams, and *something* shuttles those
//! datagrams to a UDP socket. This module collects helpers for
//! that "something" — for now, just socket-option tuning that any
//! production server (the QNS endpoint or otherwise) will want.
//!
//! Future additions: `recvmmsg` / `sendmmsg` / GSO wrappers,
//! `IP_PKTINFO` / `IPV6_RECVPKTINFO` for path tracking, ECN
//! marking helpers.

/// Submodule of UDP socket-option helpers (`SO_RCVBUF`, `SO_SNDBUF`).
pub const socket_opts = @import("socket_opts.zig");
/// Submodule of the opinionated `std.Io`-based UDP server loop.
pub const udp_server = @import("udp_server.zig");

/// Re-export of `socket_opts.ServerTuning`, the buffer-size knob struct.
pub const ServerTuning = socket_opts.ServerTuning;
/// Re-export of `socket_opts.setRecvBufferSize` — sets `SO_RCVBUF`
/// (with Linux `SO_RCVBUFFORCE` fallback).
pub const setRecvBufferSize = socket_opts.setRecvBufferSize;
/// Re-export of `socket_opts.setSendBufferSize` — sets `SO_SNDBUF`
/// (with Linux `SO_SNDBUFFORCE` fallback).
pub const setSendBufferSize = socket_opts.setSendBufferSize;
/// Re-export of `socket_opts.getRecvBufferSize`.
pub const getRecvBufferSize = socket_opts.getRecvBufferSize;
/// Re-export of `socket_opts.getSendBufferSize`.
pub const getSendBufferSize = socket_opts.getSendBufferSize;
/// Re-export of `socket_opts.applyServerTuning` — applies a
/// `ServerTuning` to a freshly bound UDP socket.
pub const applyServerTuning = socket_opts.applyServerTuning;
/// Re-export of `socket_opts.default_server_recv_buffer_bytes` (4 MiB).
pub const default_server_recv_buffer_bytes = socket_opts.default_server_recv_buffer_bytes;
/// Re-export of `socket_opts.default_server_send_buffer_bytes` (4 MiB).
pub const default_server_send_buffer_bytes = socket_opts.default_server_send_buffer_bytes;

/// Re-export of `udp_server.runUdpServer` — the opinionated
/// `std.Io`-based UDP server loop. See `udp_server.zig` for the full
/// option surface.
pub const runUdpServer = udp_server.runUdpServer;
/// Re-export of `udp_server.RunUdpOptions`.
pub const RunUdpOptions = udp_server.RunUdpOptions;
/// Re-export of `udp_server.RunError`.
pub const RunError = udp_server.RunError;

test {
    _ = socket_opts;
    _ = udp_server;
}
