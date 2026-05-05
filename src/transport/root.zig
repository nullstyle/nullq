//! nullq.transport — UDP socket plumbing.
//!
//! nullq is transport-agnostic at the protocol layer: connections
//! consume and produce datagrams, and *something* shuttles those
//! datagrams to a UDP socket. This module collects helpers for
//! that "something" — for now, just socket-option tuning that any
//! production server (the QNS endpoint or otherwise) will want.
//!
//! Future additions: `recvmmsg` / `sendmmsg` / GSO wrappers,
//! `IP_PKTINFO` / `IPV6_RECVPKTINFO` for path tracking, ECN
//! marking helpers.

pub const socket_opts = @import("socket_opts.zig");

pub const ServerTuning = socket_opts.ServerTuning;
pub const setRecvBufferSize = socket_opts.setRecvBufferSize;
pub const setSendBufferSize = socket_opts.setSendBufferSize;
pub const getRecvBufferSize = socket_opts.getRecvBufferSize;
pub const getSendBufferSize = socket_opts.getSendBufferSize;
pub const applyServerTuning = socket_opts.applyServerTuning;
pub const default_server_recv_buffer_bytes = socket_opts.default_server_recv_buffer_bytes;
pub const default_server_send_buffer_bytes = socket_opts.default_server_send_buffer_bytes;

test {
    _ = socket_opts;
}
