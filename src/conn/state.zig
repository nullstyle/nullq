//! nullq.Connection — per-connection state machine root.
//!
//! Phase 4 scope: TLS handshake glue. The Connection wraps a
//! `boringssl.tls.Conn` (the SSL object), installs nullq's
//! `tls.quic.Method` callbacks, and exposes a deterministic
//! `advance` driver that pulls peer-provided CRYPTO bytes through
//! `provideQuicData` + `SSL_do_handshake` until the handshake
//! completes.
//!
//! The packet number space, ACK tracker, congestion controller,
//! flow control, and stream layer all land in Phase 5; their
//! placeholders are noted here.

const std = @import("std");
const boringssl = @import("boringssl");
const c = boringssl.raw;

const level_mod = @import("../tls/level.zig");
const short_packet_mod = @import("../wire/short_packet.zig");
const long_packet_mod = @import("../wire/long_packet.zig");
const initial_keys_mod = @import("../wire/initial.zig");
const transport_params_mod = @import("../tls/transport_params.zig");
const early_data_context_mod = @import("../tls/early_data_context.zig");
const varint = @import("../wire/varint.zig");
const frame_mod = @import("../frame/root.zig");
const frame_types = @import("../frame/types.zig");
const ack_range_mod = @import("../frame/ack_range.zig");
const ack_tracker_mod = @import("ack_tracker.zig");
const send_stream_mod = @import("send_stream.zig");
const recv_stream_mod = @import("recv_stream.zig");
const pn_space_mod = @import("pn_space.zig");
const sent_packets_mod = @import("sent_packets.zig");
const loss_recovery_mod = @import("loss_recovery.zig");
const path_mod = @import("path.zig");
const congestion_mod = @import("congestion.zig");
const rtt_mod = @import("rtt.zig");

pub const EncryptionLevel = level_mod.EncryptionLevel;
pub const Direction = level_mod.Direction;
pub const PacketKeys = short_packet_mod.PacketKeys;
pub const Suite = short_packet_mod.Suite;
pub const SendStream = send_stream_mod.SendStream;
pub const RecvStream = recv_stream_mod.RecvStream;
pub const PnSpace = pn_space_mod.PnSpace;
pub const SentPacketTracker = sent_packets_mod.SentPacketTracker;
pub const Path = path_mod.Path;
pub const PathSet = path_mod.PathSet;
pub const PathState = path_mod.PathState;
pub const PathStats = path_mod.PathStats;
pub const Scheduler = path_mod.Scheduler;
pub const ConnectionId = path_mod.ConnectionId;
pub const Address = path_mod.Address;
pub const PathValidator = path_mod.PathValidator;
pub const RttEstimator = rtt_mod.RttEstimator;
pub const TransportParams = transport_params_mod.Params;
pub const NewReno = congestion_mod.NewReno;
pub const Session = boringssl.tls.Session;
pub const EarlyDataStatus = boringssl.tls.Conn.EarlyDataStatus;

pub const Role = enum { client, server };

pub const Error = error{
    OutOfMemory,
    HandshakeFailed,
    InboxOverflow,
    PeerAlerted,
    UnsupportedCipherSuite,
    StreamAlreadyOpen,
    StreamNotFound,
    PnSpaceExhausted,
    PeerDcidNotSet,
    PathLimitExceeded,
    EmptyEarlyDataContext,
} || boringssl.tls.Error ||
    short_packet_mod.Error ||
    long_packet_mod.Error ||
    send_stream_mod.Error ||
    recv_stream_mod.Error ||
    sent_packets_mod.Error ||
    frame_mod.EncodeError ||
    frame_mod.DecodeError ||
    ack_range_mod.Error ||
    ack_tracker_mod.Error ||
    transport_params_mod.Error;

/// Per-level secret bookkeeping. We don't actually derive AEAD keys
/// in Phase 4 — that's Phase 5's packet-protection wiring. For now,
/// a flag plus the cipher protocol-id + secret bytes is enough to
/// validate that BoringSSL handed us material at the right point.
pub const SecretMaterial = struct {
    cipher_protocol_id: u16,
    secret: [64]u8 = @splat(0),
    secret_len: u8 = 0,
};

pub const PerLevelState = struct {
    read: ?SecretMaterial = null,
    write: ?SecretMaterial = null,
};

/// One QUIC stream — bundles the send and receive halves with a
/// stable `id`. Bidi or uni is a property of the id (RFC 9000 §2.1
/// stream IDs encode direction in the low two bits); for Phase 5
/// the Connection treats every stream as bidi.
pub const Stream = struct {
    id: u64,
    send: SendStream,
    recv: RecvStream,
    /// True once any byte for this stream arrived in a 0-RTT packet.
    arrived_in_early_data: bool = false,
};

/// Default datagram budget for outgoing 1-RTT packets. RFC 9000 §14
/// mandates at least 1200 bytes path MTU; PMTU discovery (Phase 11)
/// can lift this.
pub const default_mtu: usize = 1200;
const transport_error_protocol_violation: u64 = 0x0a;

/// Upper bound on AEAD plaintext for a single received packet.
/// Sized to comfortably hold any UDP datagram a peer is likely to
/// send: 65507-byte IPv4 max minus a token sliver of headers, but
/// in practice peers stay under ~1500 bytes per Ethernet MTU. We
/// pick 4 KiB as a safe headroom that still fits on the stack.
pub const max_recv_plaintext: usize = 4096;

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
fn debugFrames() ?*const anyopaque {
    return getenv("NULLQ_DEBUG_FRAMES");
}

/// One out-of-order CRYPTO fragment held in `crypto_pending[lvl]`
/// until enough lower-offset bytes have arrived for it to be
/// delivered to TLS via `provideQuicData`.
pub const CryptoChunk = struct {
    offset: u64,
    /// Allocator-owned bytes. Freed when delivered or on `deinit`.
    data: []u8,
};

pub const SentCryptoChunk = struct {
    pn: u64,
    offset: u64,
    /// Allocator-owned bytes. Freed on ACK or moved back to
    /// `crypto_retx` on loss.
    data: []u8,
};

/// One peer-issued connection ID stashed from a NEW_CONNECTION_ID
/// frame (RFC 9000 §19.15).
pub const IssuedCid = struct {
    path_id: u32 = 0,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
};

/// Outgoing CONNECTION_CLOSE intent.
pub const ConnectionCloseInfo = struct {
    is_transport: bool,
    error_code: u64,
    frame_type: u64 = 0,
    reason: []const u8 = &.{},
};

pub const StopSendingItem = struct {
    stream_id: u64,
    application_error_code: u64,
};

pub const MaxStreamDataItem = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const PendingNewConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: frame_types.ConnId,
    stateless_reset_token: [16]u8,
};

pub const PendingPathStatus = struct {
    path_id: u32,
    sequence_number: u64,
    available: bool,
};

pub const OutgoingDatagram = struct {
    len: usize,
    to: ?Address = null,
    path_id: u32 = 0,
};

pub const IncomingDatagram = struct {
    len: usize,
    arrived_in_early_data: bool = false,
};

const PendingRecvDatagram = struct {
    data: []u8,
    arrived_in_early_data: bool = false,
};

pub const TimerKind = enum {
    ack_delay,
    loss_detection,
    pto,
    idle,
    draining,
};

pub const TimerDeadline = struct {
    kind: TimerKind,
    at_us: u64,
    level: ?EncryptionLevel = null,
    path_id: u32 = 0,
};

const LossStats = struct {
    count: u32 = 0,
    bytes_lost: u64 = 0,
    in_flight_bytes_lost: u64 = 0,
    earliest_lost_sent_time_us: ?u64 = null,
    largest_lost_sent_time_us: u64 = 0,

    fn add(self: *LossStats, packet: sent_packets_mod.SentPacket) void {
        self.count += 1;
        self.bytes_lost += packet.bytes;
        if (packet.in_flight) self.in_flight_bytes_lost += packet.bytes;
        if (self.earliest_lost_sent_time_us == null or
            packet.sent_time_us < self.earliest_lost_sent_time_us.?)
        {
            self.earliest_lost_sent_time_us = packet.sent_time_us;
        }
        if (packet.sent_time_us > self.largest_lost_sent_time_us) {
            self.largest_lost_sent_time_us = packet.sent_time_us;
        }
    }
};

/// Fixed-size CRYPTO frame buffer per encryption level. The
/// handshake fits comfortably in 16 KiB even for large cert chains;
/// we'll revisit (and bound via `SSL_quic_max_handshake_flight_len`)
/// in Phase 5.
pub const CryptoBuffer = struct {
    buf: [16384]u8 = undefined,
    len: usize = 0,

    pub fn append(self: *CryptoBuffer, data: []const u8) !void {
        if (self.len + data.len > self.buf.len) return error.InboxOverflow;
        @memcpy(self.buf[self.len .. self.len + data.len], data);
        self.len += data.len;
    }

    pub fn drain(self: *CryptoBuffer) []const u8 {
        const out = self.buf[0..self.len];
        self.len = 0;
        return out;
    }
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    /// Owned SSL handle from the caller-provided `boringssl.tls.Context`.
    /// The Context outlives the Connection (caller-managed).
    inner: boringssl.tls.Conn,

    /// Inbox of CRYPTO frame bytes received from the peer at each
    /// encryption level. The peer's `add_handshake_data` callback
    /// appends here; `advance` drains via `provideQuicData`.
    inbox: [4]CryptoBuffer = .{ .{}, .{}, .{}, .{} },

    /// Per-level secret bookkeeping. Updated by the
    /// `set_read_secret` / `set_write_secret` callbacks.
    levels: [4]PerLevelState = .{ .{}, .{}, .{}, .{} },

    /// Peer pointer for the in-process mock transport tests; real
    /// deployments don't set this (they ship CRYPTO bytes via QUIC
    /// packets through a `transport.Transport`, which lives in
    /// Phase 6).
    peer: ?*Connection = null,

    /// Last alert byte received via the `send_alert` callback, if
    /// any. Non-null = handshake should be torn down.
    alert: ?u8 = null,

    /// Pending hostname for client connections; applied during
    /// `bind` because we can't safely call `setHostname` before
    /// the Connection has a stable address.
    pending_hostname: ?[:0]const u8 = null,

    /// Connection-level packet-number bookkeeping for Initial and
    /// Handshake (RFC 9000 §12.3). Application PN spaces live in
    /// `paths` so multipath can allocate one space per active path.
    pn_spaces: [2]PnSpace = .{ .{}, .{} },
    /// Sent-packet tracker for connection-level PN spaces. Application
    /// packets live in `paths.primary().sent`; Initial/Handshake stay
    /// here because QUIC multipath only widens the Application space.
    sent: [2]SentPacketTracker = .{ .{}, .{} },
    /// Multipath-capable Application path set. Path id 0 is always the
    /// initial path and owns Application PN/ACK/sent/RTT/congestion.
    paths: PathSet = .{},
    multipath_enabled: bool = false,
    local_max_path_id: u32 = 0,
    peer_max_path_id: u32 = 0,
    peer_paths_blocked_at: ?u32 = null,
    peer_path_cids_blocked_path_id: ?u32 = null,
    peer_path_cids_blocked_next_sequence: u64 = 0,
    current_incoming_path_id: u32 = 0,
    /// PTO backoff count for Initial and Handshake. Application PTO
    /// backoff is per-path in `PathState.pto_count`. Reset when an
    /// ACK newly acknowledges ack-eliciting data in that space.
    pto_count: [2]u32 = .{ 0, 0 },
    /// PING probes requested by PTO for Initial and Handshake when no
    /// retransmittable data is immediately available.
    pending_ping: [2]bool = .{ false, false },

    /// Per-encryption-level outbox of CRYPTO bytes the TLS bridge
    /// has handed us via `add_handshake_data`. `poll` packs these
    /// into outgoing CRYPTO frames at the matching level. Replaces
    /// the Phase-4 in-process `peer.inbox` shortcut.
    outbox: [4]CryptoBuffer = .{ .{}, .{}, .{}, .{} },
    /// Highest CRYPTO offset we've handed to the peer at each level.
    /// Used to set the `offset` field on the next CRYPTO frame.
    crypto_send_offset: [4]u64 = .{ 0, 0, 0, 0 },
    /// Highest CRYPTO offset we've fed back to BoringSSL at each
    /// level (one past the last byte of in-order data delivered via
    /// `provideQuicData`).
    crypto_recv_offset: [4]u64 = .{ 0, 0, 0, 0 },
    /// Per-level reassembly queue for CRYPTO frames received out
    /// of order. Each entry holds bytes whose `offset` is strictly
    /// greater than `crypto_recv_offset[lvl]`. Drained whenever
    /// `crypto_recv_offset` catches up to the lowest entry.
    /// quic-go (and many real stacks) routinely fragment the
    /// ClientHello into out-of-order CRYPTO frames inside a single
    /// Initial; without reassembly the handshake stalls.
    crypto_pending: [4]std.ArrayList(CryptoChunk) = .{ .empty, .empty, .empty, .empty },
    /// CRYPTO bytes that were sent in lost packets and need to be
    /// retransmitted at their original offsets.
    crypto_retx: [4]std.ArrayList(CryptoChunk) = .{ .empty, .empty, .empty, .empty },
    /// CRYPTO bytes currently in sent packets awaiting ACK/loss.
    sent_crypto: [4]std.ArrayList(SentCryptoChunk) = .{ .empty, .empty, .empty, .empty },

    /// Per-stream state, keyed by stream id.
    streams: std.AutoHashMapUnmanaged(u64, *Stream) = .empty,
    /// Monotonic connection-local key for STREAM send bookkeeping.
    /// Wire packet numbers are scoped by packet-number space/path;
    /// SendStream needs one global key to avoid multipath PN collisions.
    next_stream_packet_key: u64 = 0,

    /// Outbound RFC 9221 DATAGRAM payloads waiting to be packed
    /// into 1-RTT packets. Each entry is allocator-owned.
    pending_send_datagrams: std.ArrayList([]u8) = .empty,
    /// Inbound DATAGRAMs received but not yet pulled by the app.
    /// Each entry is allocator-owned.
    pending_recv_datagrams: std.ArrayList(PendingRecvDatagram) = .empty,

    /// DCID we put on outgoing packets (the peer chose this; client
    /// learns it from the server's first Initial SCID, or
    /// NEW_CONNECTION_ID). Zero-length CIDs are valid — `peer_dcid_set`
    /// distinguishes "explicitly empty" from "never set".
    peer_dcid: ConnectionId = .{},
    peer_dcid_set: bool = false,
    /// SCID we identify ourselves with — appears as SCID on outgoing
    /// long-header packets, and the peer puts it (or another CID we
    /// issued) as DCID on every incoming packet. Zero-length is valid.
    local_scid: ConnectionId = .{},
    local_scid_set: bool = false,
    /// Original DCID used for Initial-key derivation (RFC 9001 §5.2).
    /// Client side: the random DCID it sent on the very first Initial.
    /// Server side: same value, recovered from that incoming Initial.
    initial_dcid: ConnectionId = .{},
    initial_dcid_set: bool = false,

    /// Cached Initial-level packet keys. Derived once `initial_dcid`
    /// is set; cleared if `initial_dcid` is rotated (e.g. after
    /// receiving a Retry, RFC 9001 §5.2). Direction-specific (server
    /// uses `is_server=true` derivation for write).
    initial_keys_read: ?short_packet_mod.PacketKeys = null,
    initial_keys_write: ?short_packet_mod.PacketKeys = null,

    /// Application key-phase state. QUIC key updates derive new
    /// packet-protection key/IV from "quic ku" while retaining the
    /// original header-protection key.
    app_read_key_phase: bool = false,
    app_write_key_phase: bool = false,
    app_read_hp: ?[32]u8 = null,
    app_write_hp: ?[32]u8 = null,

    /// Local datagram budget for outgoing packets.
    mtu: usize = default_mtu,

    /// Local parameters handed to BoringSSL. Kept here too so ACK
    /// delay and idle timers can use the negotiated local values.
    local_transport_params: TransportParams = .{},
    /// Decoded peer parameters once BoringSSL exposes them.
    cached_peer_transport_params: ?TransportParams = null,
    /// Per-connection opt-in for sending queued application bytes in
    /// 0-RTT packets. Session resumption can still happen when this is
    /// false; nullq just waits for 1-RTT before emitting app data.
    early_data_send_enabled: bool = false,
    /// Once BoringSSL reports rejection, every tracked 0-RTT packet is
    /// removed from flight and its STREAM bytes are put back on the
    /// send queue exactly once.
    early_data_rejection_processed: bool = false,

    /// Last send/receive activity on this connection. Zero means no
    /// packet activity has been observed yet.
    last_activity_us: u64 = 0,
    /// Draining-state deadline. Until a richer close state lands, a
    /// non-null value means only the draining timer remains relevant.
    draining_deadline_us: ?u64 = null,

    /// PATH_CHALLENGE token received from the peer that we still
    /// owe a PATH_RESPONSE for. The next outgoing 1-RTT packet
    /// will carry it.
    pending_path_response: ?[8]u8 = null,
    /// PATH_CHALLENGE token we've queued for transmission to start
    /// validating the current path.
    pending_path_challenge: ?[8]u8 = null,

    /// Peer-issued connection IDs we've stashed via NEW_CONNECTION_ID.
    /// Phase 9 (migration) will pull from this set; for now, the
    /// stash is just bookkeeping (and a place where a peer's
    /// `active_connection_id_limit` violation would surface).
    peer_cids: std.ArrayList(IssuedCid) = .empty,
    /// Locally-issued connection IDs, keyed by path, used to map
    /// incoming short-header DCIDs back to draft multipath path IDs.
    local_cids: std.ArrayList(IssuedCid) = .empty,
    /// CONNECTION_CLOSE we've queued (typically from `close()`); the
    /// next outgoing packet at the highest available encryption
    /// level emits it.
    pending_close: ?ConnectionCloseInfo = null,
    /// True once we've sent or received a CONNECTION_CLOSE frame.
    /// `poll` returns null and `handle` ignores frames after this.
    closed: bool = false,
    /// STOP_SENDING frames we owe the peer (one per stream id).
    pending_stop_sending: std.ArrayList(StopSendingItem) = .empty,
    /// MAX_STREAM_DATA frames we owe after the application drains
    /// receive buffers. Coalesced by stream id.
    pending_max_stream_data: std.ArrayList(MaxStreamDataItem) = .empty,
    /// MAX_DATA value to advertise after application reads. Null
    /// means no connection-level window update is currently queued.
    pending_max_data: ?u64 = null,
    /// Bytes the application has drained from all receive streams.
    recv_stream_bytes_read: u64 = 0,
    /// Server/client-issued CIDs to advertise to the peer. This is
    /// enough for migration and multipath probes to obtain spare CIDs.
    pending_new_connection_ids: std.ArrayList(PendingNewConnectionId) = .empty,
    pending_path_abandons: std.ArrayList(frame_types.PathAbandon) = .empty,
    pending_path_statuses: std.ArrayList(PendingPathStatus) = .empty,
    pending_path_new_connection_ids: std.ArrayList(frame_types.PathNewConnectionId) = .empty,
    pending_path_retire_connection_ids: std.ArrayList(frame_types.PathRetireConnectionId) = .empty,
    pending_max_path_id: ?u32 = null,
    pending_paths_blocked: ?u32 = null,
    pending_path_cids_blocked: ?frame_types.PathCidsBlocked = null,

    pub fn initClient(
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
        server_name: [:0]const u8,
    ) !Connection {
        var conn: Connection = .{
            .allocator = allocator,
            .role = .client,
            .inner = try tls_ctx.newQuicClient(),
            .pending_hostname = server_name,
        };
        errdefer conn.inner.deinit();
        try conn.paths.ensurePrimary(allocator, .{ .max_datagram_size = default_mtu });
        return conn;
    }

    pub fn initServer(
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
    ) !Connection {
        var conn: Connection = .{
            .allocator = allocator,
            .role = .server,
            .inner = try tls_ctx.newQuicServer(),
        };
        errdefer conn.inner.deinit();
        try conn.paths.ensurePrimary(allocator, .{ .max_datagram_size = default_mtu });
        return conn;
    }

    /// Bind this Connection to its underlying SSL. Must be called
    /// once the Connection sits at its final stable address (after
    /// any `return` copies). Installs the `tls.quic.Method`
    /// callbacks and stashes `*Connection` in SSL ex-data so the
    /// callbacks can recover the right state.
    ///
    /// Calling `advance` before `bind` is undefined.
    pub fn bind(self: *Connection) !void {
        try self.inner.setUserData(self);
        try self.inner.setQuicMethod(&method);
        if (self.pending_hostname) |h| {
            try self.inner.setHostname(h);
            self.pending_hostname = null;
        }
    }

    pub fn deinit(self: *Connection) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            s.send.deinit();
            s.recv.deinit();
            self.allocator.destroy(s);
        }
        self.streams.deinit(self.allocator);
        for (self.pending_send_datagrams.items) |bytes| self.allocator.free(bytes);
        for (self.pending_recv_datagrams.items) |item| self.allocator.free(item.data);
        self.pending_send_datagrams.deinit(self.allocator);
        self.pending_recv_datagrams.deinit(self.allocator);
        for (&self.sent) |*tracker| {
            var i: u32 = 0;
            while (i < tracker.count) : (i += 1) {
                tracker.packets[i].deinit(self.allocator);
            }
        }
        self.paths.deinit(self.allocator);
        for (&self.crypto_pending) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        for (&self.crypto_retx) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        for (&self.sent_crypto) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        self.peer_cids.deinit(self.allocator);
        self.local_cids.deinit(self.allocator);
        self.pending_stop_sending.deinit(self.allocator);
        self.pending_max_stream_data.deinit(self.allocator);
        self.pending_new_connection_ids.deinit(self.allocator);
        self.pending_path_abandons.deinit(self.allocator);
        self.pending_path_statuses.deinit(self.allocator);
        self.pending_path_new_connection_ids.deinit(self.allocator);
        self.pending_path_retire_connection_ids.deinit(self.allocator);
        self.inner.deinit();
        self.* = undefined;
    }

    /// Encode `params` (RFC 9000 §18 + RFC 9221) and hand the blob
    /// to BoringSSL for transmission inside CRYPTO frames during the
    /// handshake. Must be called before the first `advance`.
    pub fn setTransportParams(self: *Connection, params: TransportParams) !void {
        var buf: [1024]u8 = undefined;
        const n = try params.encode(&buf);
        self.local_transport_params = params;
        if (params.initial_max_path_id) |max_path_id| {
            self.local_max_path_id = max_path_id;
            self.multipath_enabled = true;
        } else {
            self.local_max_path_id = 0;
        }
        try self.inner.setQuicTransportParams(buf[0..n]);
    }

    /// Escape hatch: set already-encoded transport-parameter bytes.
    /// Useful for testing the decoder against fixtures.
    pub fn setRawTransportParams(self: *Connection, params: []const u8) !void {
        try self.inner.setQuicTransportParams(params);
    }

    /// Decode the peer's transport parameters once the handshake has
    /// produced them (typically available right after Initial keys
    /// are derived on the peer's first flight). Returns null until
    /// the peer's blob is available.
    pub fn peerTransportParams(self: *Connection) !?TransportParams {
        const blob = self.inner.peerQuicTransportParams() orelse return null;
        const params = try transport_params_mod.Params.decode(blob);
        self.cached_peer_transport_params = params;
        if (params.initial_max_path_id) |max_path_id| {
            self.peer_max_path_id = max_path_id;
            self.multipath_enabled = true;
        }
        return params;
    }

    /// Client-only: install a previously-captured TLS session before
    /// the first handshake step so BoringSSL can attempt resumption.
    pub fn setSession(self: *Connection, session: Session) !void {
        if (self.role != .client) return error.NotClientContext;
        try self.inner.setSession(session);
    }

    /// Per-connection 0-RTT toggle. This deliberately gates nullq's
    /// packet scheduler as well as BoringSSL, so early application data
    /// is only sent after the caller opts in for this connection.
    pub fn setEarlyDataEnabled(self: *Connection, enabled: bool) void {
        self.early_data_send_enabled = enabled;
        self.inner.setEarlyDataEnabled(enabled);
    }

    pub fn earlyDataStatus(self: *Connection) EarlyDataStatus {
        return self.inner.earlyDataStatus();
    }

    pub fn earlyDataReason(self: *Connection) []const u8 {
        return self.inner.earlyDataReason();
    }

    /// Server-only: install the QUIC 0-RTT replay context (RFC 9001
    /// §4.6.1). Required when 0-RTT is enabled on the server.
    pub fn setEarlyDataContext(self: *Connection, ctx: []const u8) !void {
        if (self.role != .server) return error.NotServerContext;
        if (ctx.len == 0) return Error.EmptyEarlyDataContext;
        try self.inner.setQuicEarlyDataContext(ctx);
    }

    /// Server convenience: build and install nullq's canonical replay
    /// context from current transport parameters plus app-owned bytes.
    /// The returned digest is what callers should remember beside the
    /// issued ticket if they keep their own ticket metadata.
    pub fn setEarlyDataContextForParams(
        self: *Connection,
        params: TransportParams,
        alpn: []const u8,
        application_context: []const u8,
    ) !early_data_context_mod.Digest {
        const digest = early_data_context_mod.build(.{
            .transport_params = params,
            .alpn = alpn,
            .application_context = application_context,
        });
        try self.setEarlyDataContext(&digest);
        return digest;
    }

    pub fn handshakeDone(self: *Connection) bool {
        return self.inner.handshakeDone();
    }

    pub fn isQuic(self: *Connection) bool {
        return self.inner.isQuic();
    }

    /// Are read/write secrets installed at the given encryption level?
    pub fn haveSecret(self: *const Connection, lvl: EncryptionLevel, dir: Direction) bool {
        const slot = self.levels[lvl.idx()];
        return switch (dir) {
            .read => slot.read != null,
            .write => slot.write != null,
        };
    }

    /// Cipher suite negotiated for the given encryption level, if
    /// the secret has been installed and the protocol-id is one we
    /// support. RFC 9001 only permits TLS 1.3 cipher suites; nullq
    /// currently understands `TLS_AES_128_GCM_SHA256` only.
    pub fn cipherSuite(
        self: *const Connection,
        lvl: EncryptionLevel,
        dir: Direction,
    ) ?Suite {
        const slot = self.levels[lvl.idx()];
        const material_opt = switch (dir) {
            .read => slot.read,
            .write => slot.write,
        };
        const material = material_opt orelse return null;
        return Suite.fromProtocolId(material.cipher_protocol_id);
    }

    /// Derive AEAD/IV/HP keys for the given (level, direction). The
    /// secret was captured by the TLS bridge; HKDF-Expand-Label
    /// turns it into per-packet protection material.
    pub fn packetKeys(
        self: *const Connection,
        lvl: EncryptionLevel,
        dir: Direction,
    ) Error!?PacketKeys {
        const slot = self.levels[lvl.idx()];
        const material_opt = switch (dir) {
            .read => slot.read,
            .write => slot.write,
        };
        const material = material_opt orelse return null;
        const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
            return Error.UnsupportedCipherSuite;
        const secret = material.secret[0..material.secret_len];
        var keys = try short_packet_mod.derivePacketKeys(suite, secret);
        if (lvl == .application) {
            switch (dir) {
                .read => if (self.app_read_hp) |hp| {
                    keys.hp = hp;
                },
                .write => if (self.app_write_hp) |hp| {
                    keys.hp = hp;
                },
            }
        }
        return keys;
    }

    const ApplicationKeyUpdate = struct {
        material: SecretMaterial,
        keys: PacketKeys,
        hp: [32]u8,
    };

    fn nextApplicationKeyUpdate(
        self: *const Connection,
        dir: Direction,
    ) Error!?ApplicationKeyUpdate {
        const app_idx = EncryptionLevel.application.idx();
        var material = switch (dir) {
            .read => self.levels[app_idx].read,
            .write => self.levels[app_idx].write,
        } orelse return null;
        const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
            return Error.UnsupportedCipherSuite;

        const current_keys = (try self.packetKeys(.application, dir)) orelse return null;
        const hp = switch (dir) {
            .read => self.app_read_hp,
            .write => self.app_write_hp,
        } orelse current_keys.hp;
        const next_secret = try short_packet_mod.deriveNextTrafficSecret(
            suite,
            material.secret[0..material.secret_len],
        );

        const secret_len: usize = suite.secretLen();
        @memcpy(material.secret[0..secret_len], next_secret[0..secret_len]);
        @memset(material.secret[secret_len..], 0);
        material.secret_len = @intCast(secret_len);

        var next_keys = try short_packet_mod.derivePacketKeys(
            suite,
            material.secret[0..material.secret_len],
        );
        next_keys.hp = hp;
        return .{ .material = material, .keys = next_keys, .hp = hp };
    }

    fn installApplicationKeyUpdate(
        self: *Connection,
        dir: Direction,
        update: ApplicationKeyUpdate,
    ) void {
        const app_idx = EncryptionLevel.application.idx();
        switch (dir) {
            .read => {
                self.levels[app_idx].read = update.material;
                self.app_read_hp = update.hp;
                self.app_read_key_phase = !self.app_read_key_phase;
            },
            .write => {
                self.levels[app_idx].write = update.material;
                self.app_write_hp = update.hp;
                self.app_write_key_phase = !self.app_write_key_phase;
            },
        }
    }

    fn updateApplicationWriteKeys(self: *Connection) Error!void {
        const update = (try self.nextApplicationKeyUpdate(.write)) orelse return;
        self.installApplicationKeyUpdate(.write, update);
    }

    /// Set the DCID we put on outgoing 1-RTT packets. A zero-length
    /// CID is valid (RFC 9000 §5.1) and represents the case where
    /// the peer has chosen not to identify itself with a CID;
    /// `peer_dcid_set` flips to true regardless of length.
    pub fn setPeerDcid(self: *Connection, cid: []const u8) !void {
        if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        self.peer_dcid = ConnectionId.fromSlice(cid);
        self.primaryPath().path.peer_cid = self.peer_dcid;
        self.peer_dcid_set = true;
    }

    /// Set the SCID this endpoint identifies with. A zero-length
    /// CID is permitted. Used as the SCID on outgoing long-header
    /// packets and as the expected DCID length on every incoming
    /// packet.
    pub fn setLocalScid(self: *Connection, cid: []const u8) Error!void {
        if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        self.local_scid = ConnectionId.fromSlice(cid);
        self.primaryPath().path.local_cid = self.local_scid;
        self.local_scid_set = true;
        try self.rememberLocalCid(0, 0, 0, self.local_scid, @splat(0));
    }

    /// Length of the local SCID — also the length of the DCID the
    /// peer puts on incoming short-header packets.
    pub fn localDcidLen(self: *const Connection) u8 {
        return self.local_scid.len;
    }

    fn rememberLocalCid(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [16]u8,
    ) Error!void {
        if (cid.len == 0) return;
        if (retire_prior_to > sequence_number) {
            self.close(true, transport_error_protocol_violation, "invalid retire_prior_to");
            return;
        }
        for (self.local_cids.items) |*item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                item.retire_prior_to = retire_prior_to;
                item.cid = cid;
                item.stateless_reset_token = stateless_reset_token;
                return;
            }
        }
        self.retireLocalCidsPriorTo(path_id, retire_prior_to);
        try self.local_cids.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .cid = cid,
            .stateless_reset_token = stateless_reset_token,
        });
        if (self.paths.get(path_id)) |path| {
            if (path.path.local_cid.len == 0 or sequence_number == 0) {
                path.path.local_cid = cid;
                if (path_id == 0) self.local_scid = cid;
            }
        }
    }

    fn retireLocalCidsPriorTo(
        self: *Connection,
        path_id: u32,
        retire_prior_to: u64,
    ) void {
        var i: usize = 0;
        while (i < self.local_cids.items.len) {
            const item = self.local_cids.items[i];
            if (item.path_id == path_id and item.sequence_number < retire_prior_to) {
                _ = self.local_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        self.promoteLocalCidForPath(path_id);
    }

    fn promoteLocalCidForPath(self: *Connection, path_id: u32) void {
        const path = self.paths.get(path_id) orelse return;
        path.path.local_cid = .{};
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id) {
                path.path.local_cid = item.cid;
                if (path_id == 0) self.local_scid = item.cid;
                return;
            }
        }
    }

    fn retireLocalCid(self: *Connection, path_id: u32, sequence_number: u64) void {
        var removed_cid: ?ConnectionId = null;
        var i: usize = 0;
        while (i < self.local_cids.items.len) {
            const item = self.local_cids.items[i];
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                removed_cid = item.cid;
                _ = self.local_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        const cid = removed_cid orelse return;
        const path = self.paths.get(path_id) orelse return;
        if (ConnectionId.eql(path.path.local_cid, cid)) {
            self.promoteLocalCidForPath(path_id);
        }
    }

    fn nextLocalCidSequence(self: *const Connection, path_id: u32) u64 {
        var next: u64 = 0;
        for (self.local_cids.items) |item| {
            if (item.path_id == path_id and item.sequence_number >= next) {
                next = item.sequence_number + 1;
            }
        }
        return next;
    }

    /// Server-side helper: peek the unprotected DCID + SCID out of
    /// an incoming Initial datagram and install them along with the
    /// caller-supplied transport parameters. Idempotent — safe to
    /// call once before the first `handle`. Useful for plain UDP
    /// servers that need to seed CID/transport-parameter state
    /// from the very first datagram before TLS can advance.
    pub fn acceptInitial(
        self: *Connection,
        bytes: []const u8,
        params: TransportParams,
    ) Error!void {
        if (self.role != .server) return Error.NotServerContext;
        if (bytes.len < 6) return Error.InsufficientBytes;
        if ((bytes[0] & 0x80) == 0) return Error.NotShortHeader; // not a long header
        const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
        if (long_type_bits != 0) return Error.NotShortHeader;

        const dcid_len = bytes[5];
        if (dcid_len > path_mod.max_cid_len) return Error.DcidTooLong;
        var pos: usize = 6;
        if (bytes.len < pos + @as(usize, dcid_len) + 1) return Error.InsufficientBytes;
        const dcid = bytes[pos .. pos + dcid_len];
        pos += dcid_len;
        const scid_len = bytes[pos];
        if (scid_len > path_mod.max_cid_len) return Error.DcidTooLong;
        pos += 1;
        if (bytes.len < pos + @as(usize, scid_len)) return Error.InsufficientBytes;
        const scid = bytes[pos .. pos + scid_len];

        try self.setInitialDcid(dcid);
        try self.setPeerDcid(scid);
        try self.setTransportParams(params);
    }

    /// Set the original DCID used for Initial-key derivation
    /// (RFC 9001 §5.2). On the client this is the random DCID it
    /// chose for its very first Initial. On the server, it's the
    /// DCID it received on the client's first Initial. Per RFC 9000
    /// the initial DCID is at least 8 bytes, so `len == 0` here is
    /// always "unset".
    pub fn setInitialDcid(self: *Connection, dcid: []const u8) Error!void {
        if (dcid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        self.initial_dcid = ConnectionId.fromSlice(dcid);
        self.initial_dcid_set = true;
        self.initial_keys_read = null;
        self.initial_keys_write = null;
    }

    fn ensureInitialKeys(self: *Connection) Error!void {
        if (self.initial_keys_read != null and self.initial_keys_write != null) return;
        if (!self.initial_dcid_set) return;
        const dcid_slice = self.initial_dcid.slice();
        // RFC 9001 §5.2: client-direction secret comes from "client in",
        // server-direction from "server in". The Connection's role
        // determines which secret is the read-side and which is write.
        const client_keys_initial = try initial_keys_mod.deriveInitialKeys(dcid_slice, false);
        const server_keys_initial = try initial_keys_mod.deriveInitialKeys(dcid_slice, true);
        const client_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &client_keys_initial.secret);
        const server_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &server_keys_initial.secret);
        switch (self.role) {
            .client => {
                self.initial_keys_write = client_pkt;
                self.initial_keys_read = server_pkt;
            },
            .server => {
                self.initial_keys_write = server_pkt;
                self.initial_keys_read = client_pkt;
            },
        }
    }

    /// Open a new bidirectional stream with the given id. The id
    /// is caller-supplied. RFC 9000 §2.1 says the low two bits of
    /// a stream id encode (initiator, direction):
    ///   0 = client-initiated bidi, 1 = server-initiated bidi
    ///   2 = client-initiated uni,  3 = server-initiated uni
    pub fn openBidi(self: *Connection, id: u64) Error!*Stream {
        return try self.openStream(id);
    }

    /// Open a new unidirectional stream. The caller is responsible
    /// for choosing an id with the right low bits per §2.1.
    pub fn openUni(self: *Connection, id: u64) Error!*Stream {
        return try self.openStream(id);
    }

    fn openStream(self: *Connection, id: u64) Error!*Stream {
        if (self.streams.contains(id)) return Error.StreamAlreadyOpen;
        const ptr = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(ptr);
        ptr.* = .{
            .id = id,
            .send = SendStream.init(self.allocator),
            .recv = RecvStream.init(self.allocator),
        };
        try self.streams.put(self.allocator, id, ptr);
        return ptr;
    }

    /// Iterate over every open stream. The yielded pointer is
    /// invalidated by `openBidi` / `openUni` (HashMap rehash) and
    /// by stream removal — finish iteration before mutating the
    /// stream set.
    pub fn streamIterator(self: *Connection) std.AutoHashMapUnmanaged(u64, *Stream).Iterator {
        return self.streams.iterator();
    }

    /// Number of currently-open streams.
    pub fn streamCount(self: *const Connection) usize {
        return self.streams.count();
    }

    /// Pick the next available server-initiated unidirectional
    /// stream id (low 2 bits = 0b11) starting from `start`. Skips
    /// ids that are already open.
    pub fn nextServerUniId(self: *const Connection, start: u64) u64 {
        var id = start | 0b11;
        while (self.streams.contains(id)) id += 4;
        return id;
    }

    /// Pick the next available server-initiated bidi stream id
    /// (low 2 bits = 0b01). Skips ids already open.
    pub fn nextServerBidiId(self: *const Connection, start: u64) u64 {
        var id = (start & ~@as(u64, 0b11)) | 0b01;
        while (self.streams.contains(id)) id += 4;
        return id;
    }

    /// Look up a stream by id. Returns null if no stream is open
    /// at that id.
    pub fn stream(self: *const Connection, id: u64) ?*Stream {
        return self.streams.get(id);
    }

    /// Convenience: write `data` to the send half of stream `id`.
    pub fn streamWrite(self: *Connection, id: u64, data: []const u8) Error!usize {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        return try s.send.write(data);
    }

    /// Convenience: read from the receive half of stream `id`.
    pub fn streamRead(self: *Connection, id: u64, dst: []u8) Error!usize {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        const n = s.recv.read(dst);
        if (n > 0) {
            self.recv_stream_bytes_read += n;
            // Keep a generous receive window open. Full RFC 9000 flow-control
            // accounting will use peer transport params and autotuning; this
            // minimal update is enough for external peers that otherwise stall
            // after the first receive window.
            try self.queueMaxStreamData(id, s.recv.read_offset + 1024 * 1024);
            self.queueMaxData(self.recv_stream_bytes_read + 16 * 1024 * 1024);
        }
        return n;
    }

    /// Whether the receive side of `id` has seen any STREAM bytes in
    /// 0-RTT. Returns null for an unknown stream.
    pub fn streamArrivedInEarlyData(self: *const Connection, id: u64) ?bool {
        const s = self.streams.get(id) orelse return null;
        return s.arrived_in_early_data;
    }

    fn queueMaxStreamData(
        self: *Connection,
        stream_id: u64,
        maximum_stream_data: u64,
    ) Error!void {
        for (self.pending_max_stream_data.items) |*item| {
            if (item.stream_id == stream_id) {
                if (maximum_stream_data > item.maximum_stream_data) {
                    item.maximum_stream_data = maximum_stream_data;
                }
                return;
            }
        }
        try self.pending_max_stream_data.append(self.allocator, .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        });
    }

    fn queueMaxData(self: *Connection, maximum_data: u64) void {
        if (self.pending_max_data == null or maximum_data > self.pending_max_data.?) {
            self.pending_max_data = maximum_data;
        }
    }

    /// Convenience: close the send half of stream `id` (queues FIN).
    pub fn streamFinish(self: *Connection, id: u64) Error!void {
        const s = self.streams.get(id) orelse return Error.StreamNotFound;
        try s.send.finish();
    }

    /// Queue an RFC 9221 DATAGRAM payload for transmission. The
    /// next 1-RTT packet that fits the bytes ships them. The peer
    /// must have advertised a non-zero `max_datagram_frame_size`
    /// transport parameter for them to be received — that policy
    /// check is the caller's; here we just queue and emit.
    pub fn sendDatagram(self: *Connection, payload: []const u8) Error!void {
        const copy = try self.allocator.alloc(u8, payload.len);
        errdefer self.allocator.free(copy);
        @memcpy(copy, payload);
        try self.pending_send_datagrams.append(self.allocator, copy);
    }

    /// Queue a NEW_CONNECTION_ID frame. Sequence 0 is the Initial
    /// source CID; callers should normally start additional CIDs at
    /// sequence 1.
    pub fn queueNewConnectionId(
        self: *Connection,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: []const u8,
        stateless_reset_token: [16]u8,
    ) Error!void {
        if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        const local_cid = ConnectionId.fromSlice(cid);
        for (self.pending_new_connection_ids.items) |item| {
            if (item.sequence_number == sequence_number) return;
        }
        var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
        @memcpy(connection_id.bytes[0..cid.len], cid);
        try self.rememberLocalCid(0, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
        try self.pending_new_connection_ids.append(self.allocator, .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
    }

    /// Pop the oldest received DATAGRAM into `dst`. Returns the
    /// number of bytes written, or null if none pending. The
    /// payload is dropped from the queue regardless of whether it
    /// fit — caller must size `dst` to the peer's advertised
    /// `max_datagram_frame_size`.
    pub fn receiveDatagram(self: *Connection, dst: []u8) ?usize {
        const item = self.receiveDatagramInfo(dst) orelse return null;
        return item.len;
    }

    /// Pop the oldest received DATAGRAM and include whether it arrived
    /// in 0-RTT. The payload is dropped from the queue regardless of
    /// whether it fit.
    pub fn receiveDatagramInfo(self: *Connection, dst: []u8) ?IncomingDatagram {
        if (self.pending_recv_datagrams.items.len == 0) return null;
        const item = self.pending_recv_datagrams.orderedRemove(0);
        defer self.allocator.free(item.data);
        const n = @min(dst.len, item.data.len);
        @memcpy(dst[0..n], item.data[0..n]);
        return .{ .len = n, .arrived_in_early_data = item.arrived_in_early_data };
    }

    /// Number of inbound DATAGRAMs queued for the app to read.
    pub fn pendingDatagrams(self: *const Connection) usize {
        return self.pending_recv_datagrams.items.len;
    }

    /// Enable or disable the public multipath surface. The current
    /// implementation keeps existing single-path behavior unless callers
    /// explicitly open and schedule additional paths.
    pub fn enableMultipath(self: *Connection, enabled: bool) void {
        self.multipath_enabled = enabled;
    }

    pub fn multipathEnabled(self: *const Connection) bool {
        return self.multipath_enabled;
    }

    pub fn multipathNegotiated(self: *const Connection) bool {
        if (!self.multipath_enabled) return false;
        if (self.local_transport_params.initial_max_path_id == null) return false;
        const peer_params = self.cached_peer_transport_params orelse return false;
        return peer_params.initial_max_path_id != null;
    }

    /// Register a new application path. Full draft-21 frame exchange is
    /// still staged behind this, but the path already owns independent
    /// Application PN, sent, RTT, congestion, validation, and PTO state.
    pub fn openPath(
        self: *Connection,
        peer_addr: Address,
        local_addr: Address,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
    ) Error!u32 {
        if (self.multipathNegotiated() and self.paths.next_path_id > self.peer_max_path_id) {
            self.queuePathsBlocked(self.peer_max_path_id);
            return Error.PathLimitExceeded;
        }
        const path_id = try self.paths.openPath(
            self.allocator,
            peer_addr,
            local_addr,
            local_cid,
            peer_cid,
            .{ .max_datagram_size = self.mtu },
        );
        try self.rememberLocalCid(path_id, 0, 0, local_cid, @splat(0));
        return path_id;
    }

    pub fn setActivePath(self: *Connection, path_id: u32) bool {
        return self.paths.setActive(path_id);
    }

    pub fn abandonPath(self: *Connection, path_id: u32) bool {
        if (!self.paths.abandon(path_id)) return false;
        self.retirePeerCidsForPath(path_id);
        self.queuePathAbandon(path_id, 0) catch return false;
        return true;
    }

    pub fn setPathStatus(self: *Connection, path_id: u32, state: path_mod.State) bool {
        const p = self.paths.get(path_id) orelse return false;
        p.path.state = state;
        return true;
    }

    pub fn setPathBackup(self: *Connection, path_id: u32, backup: bool) bool {
        const p = self.paths.get(path_id) orelse return false;
        p.local_status_sequence_number +|= 1;
        self.queuePathStatus(
            path_id,
            !backup,
            p.local_status_sequence_number,
        ) catch return false;
        return true;
    }

    pub fn markPathValidated(self: *Connection, path_id: u32) bool {
        const p = self.paths.get(path_id) orelse return false;
        p.path.markValidated();
        return true;
    }

    pub fn setScheduler(self: *Connection, scheduler: Scheduler) void {
        self.paths.setScheduler(scheduler);
    }

    pub fn activePathId(self: *const Connection) u32 {
        return self.paths.activeConst().id;
    }

    pub fn pathStats(self: *const Connection, path_id: u32) ?PathStats {
        return self.paths.stats(path_id);
    }

    pub fn queuePathAbandon(
        self: *Connection,
        path_id: u32,
        error_code: u64,
    ) Error!void {
        for (self.pending_path_abandons.items) |*item| {
            if (item.path_id == path_id) {
                item.error_code = error_code;
                return;
            }
        }
        try self.pending_path_abandons.append(self.allocator, .{
            .path_id = path_id,
            .error_code = error_code,
        });
    }

    pub fn queuePathStatus(
        self: *Connection,
        path_id: u32,
        available: bool,
        sequence_number: u64,
    ) Error!void {
        for (self.pending_path_statuses.items) |*item| {
            if (item.path_id == path_id) {
                if (sequence_number >= item.sequence_number) {
                    item.sequence_number = sequence_number;
                    item.available = available;
                }
                return;
            }
        }
        try self.pending_path_statuses.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .available = available,
        });
    }

    pub fn queuePathNewConnectionId(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: []const u8,
        stateless_reset_token: [16]u8,
    ) Error!void {
        if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
        const local_cid = ConnectionId.fromSlice(cid);
        for (self.pending_path_new_connection_ids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) return;
        }
        var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
        @memcpy(connection_id.bytes[0..cid.len], cid);
        try self.rememberLocalCid(path_id, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
        try self.pending_path_new_connection_ids.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
    }

    pub fn queuePathRetireConnectionId(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
    ) Error!void {
        for (self.pending_path_retire_connection_ids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) return;
        }
        try self.pending_path_retire_connection_ids.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
        });
    }

    pub fn queueMaxPathId(self: *Connection, maximum_path_id: u32) void {
        if (maximum_path_id > self.local_max_path_id) {
            self.local_max_path_id = maximum_path_id;
        }
        if (self.pending_max_path_id == null or maximum_path_id > self.pending_max_path_id.?) {
            self.pending_max_path_id = maximum_path_id;
        }
    }

    pub fn queuePathsBlocked(self: *Connection, maximum_path_id: u32) void {
        if (self.pending_paths_blocked == null or maximum_path_id > self.pending_paths_blocked.?) {
            self.pending_paths_blocked = maximum_path_id;
        }
    }

    pub fn queuePathCidsBlocked(
        self: *Connection,
        path_id: u32,
        next_sequence_number: u64,
    ) void {
        self.pending_path_cids_blocked = .{
            .path_id = path_id,
            .next_sequence_number = next_sequence_number,
        };
    }

    fn cachePeerTransportParams(self: *Connection) Error!void {
        if (self.cached_peer_transport_params != null) return;
        const blob = self.inner.peerQuicTransportParams() orelse return;
        self.cached_peer_transport_params = try transport_params_mod.Params.decode(blob);
        if (self.cached_peer_transport_params.?.initial_max_path_id) |max_path_id| {
            self.peer_max_path_id = max_path_id;
            self.multipath_enabled = true;
        }
    }

    fn peerAckDelayExponent(self: *const Connection) u6 {
        const params = self.cached_peer_transport_params orelse return 3;
        return @intCast(@min(params.ack_delay_exponent, 20));
    }

    fn peerMaxAckDelayUs(self: *const Connection) u64 {
        const params = self.cached_peer_transport_params orelse return 25 * rtt_mod.ms;
        return params.max_ack_delay_ms * rtt_mod.ms;
    }

    fn localMaxAckDelayUs(self: *const Connection) u64 {
        return self.local_transport_params.max_ack_delay_ms * rtt_mod.ms;
    }

    fn ackDelayScaled(
        self: *const Connection,
        tracker: *const ack_tracker_mod.AckTracker,
        now_us: u64,
    ) u64 {
        const largest_at_us = tracker.largest_at_ms * rtt_mod.ms;
        if (now_us <= largest_at_us) return 0;
        const shift: u6 = @intCast(@min(self.local_transport_params.ack_delay_exponent, 20));
        return (now_us - largest_at_us) >> shift;
    }

    fn idleTimeoutUs(self: *const Connection) ?u64 {
        const local = self.local_transport_params.max_idle_timeout_ms * rtt_mod.ms;
        const peer = if (self.cached_peer_transport_params) |params|
            params.max_idle_timeout_ms * rtt_mod.ms
        else
            0;
        if (local == 0) return if (peer == 0) null else peer;
        if (peer == 0) return local;
        return @min(local, peer);
    }

    fn primaryPath(self: *Connection) *PathState {
        return self.paths.primary();
    }

    fn primaryPathConst(self: *const Connection) *const PathState {
        return self.paths.primaryConst();
    }

    fn activePath(self: *Connection) *PathState {
        return self.paths.active();
    }

    fn activePathConst(self: *const Connection) *const PathState {
        return self.paths.activeConst();
    }

    fn pathForId(self: *Connection, path_id: u32) *PathState {
        return self.paths.get(path_id) orelse self.primaryPath();
    }

    fn pathForIdConst(self: *const Connection, path_id: u32) *const PathState {
        return self.paths.getConst(path_id) orelse self.primaryPathConst();
    }

    fn applicationPathForPoll(self: *Connection) *PathState {
        for (self.paths.paths.items) |*p| {
            if (p.app_pn_space.received.pending_ack) return p;
        }
        for (self.paths.paths.items) |*p| {
            if (p.pending_ping) return p;
        }
        return self.paths.selectForSending();
    }

    fn incomingPathId(self: *Connection, from: ?Address) u32 {
        if (from) |addr| {
            for (self.paths.paths.items) |*p| {
                if (p.peer_addr_set and Address.eql(p.path.peer_addr, addr)) return p.id;
            }
            return self.activePath().id;
        }
        return self.activePath().id;
    }

    fn incomingShortPath(self: *Connection, bytes: []const u8) ?*PathState {
        if (bytes.len < 1) return null;
        var best: ?*PathState = null;
        var best_len: u8 = 0;
        for (self.local_cids.items) |item| {
            const cid = item.cid.slice();
            if (cid.len == 0) continue;
            if (bytes.len < 1 + cid.len) continue;
            if (!std.mem.eql(u8, bytes[1 .. 1 + cid.len], cid)) continue;
            if (cid.len > best_len) {
                if (self.paths.get(item.path_id)) |path| {
                    best = path;
                    best_len = @intCast(cid.len);
                }
            }
        }
        if (best != null) return best;
        for (self.paths.paths.items) |*p| {
            const cid = p.path.local_cid.slice();
            if (cid.len == 0) continue;
            if (bytes.len < 1 + cid.len) continue;
            if (std.mem.eql(u8, bytes[1 .. 1 + cid.len], cid)) return p;
        }
        return best;
    }

    fn connPnIdx(lvl: EncryptionLevel) ?usize {
        return switch (lvl) {
            .initial => 0,
            .handshake => 1,
            .early_data, .application => null,
        };
    }

    fn pnSpaceForLevel(self: *Connection, lvl: EncryptionLevel) *PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &self.primaryPath().app_pn_space;
    }

    fn pnSpaceForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &self.primaryPathConst().app_pn_space;
    }

    fn pnSpaceForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &app_path.app_pn_space;
    }

    fn pnSpaceForLevelOnPathConst(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) *const PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &app_path.app_pn_space;
    }

    fn sentForLevel(self: *Connection, lvl: EncryptionLevel) *SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &self.primaryPath().sent;
    }

    fn sentForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &self.primaryPathConst().sent;
    }

    fn sentForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &app_path.sent;
    }

    fn sentForLevelOnPathConst(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) *const SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &app_path.sent;
    }

    fn rttForLevel(self: *Connection, lvl: EncryptionLevel) *RttEstimator {
        _ = lvl;
        return &self.primaryPath().path.rtt;
    }

    fn rttForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const RttEstimator {
        _ = lvl;
        return &self.primaryPathConst().path.rtt;
    }

    fn rttForLevelOnPathConst(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) *const RttEstimator {
        if (lvl == .application) return &app_path.path.rtt;
        return &self.primaryPathConst().path.rtt;
    }

    fn ccForApplication(self: *Connection) *NewReno {
        return &self.primaryPath().path.cc;
    }

    fn ccForApplicationConst(self: *const Connection) *const NewReno {
        return &self.primaryPathConst().path.cc;
    }

    fn ptoCountForLevel(self: *Connection, lvl: EncryptionLevel) *u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPath().pto_count;
    }

    fn ptoCountForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPathConst().pto_count;
    }

    fn pendingPingForLevel(self: *Connection, lvl: EncryptionLevel) *bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &self.primaryPath().pending_ping;
    }

    fn pendingPingForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &self.primaryPathConst().pending_ping;
    }

    fn pendingPingForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &app_path.pending_ping;
    }

    fn anyPendingPing(self: *const Connection) bool {
        for (self.pending_ping) |ping| {
            if (ping) return true;
        }
        for (self.paths.paths.items) |*p| {
            if (p.pending_ping) return true;
        }
        return false;
    }

    fn clearPendingPings(self: *Connection) void {
        self.pending_ping = .{ false, false };
        for (self.paths.paths.items) |*p| p.pending_ping = false;
    }

    fn canSendEarlyData(self: *Connection) bool {
        if (self.role != .client) return false;
        if (!self.early_data_send_enabled) return false;
        if (self.inner.handshakeDone()) return false;
        if (self.inner.earlyDataStatus() == .rejected) return false;
        return self.haveSecret(.early_data, .write);
    }

    fn refreshEarlyDataStatus(self: *Connection) Error!void {
        if (self.early_data_rejection_processed) return;
        if (self.inner.earlyDataStatus() != .rejected) return;
        try self.requeueRejectedEarlyData();
        self.early_data_rejection_processed = true;
    }

    fn requeueRejectedEarlyData(self: *Connection) Error!void {
        for (self.paths.paths.items) |*path| {
            var i: u32 = 0;
            while (i < path.sent.count) {
                const packet = path.sent.packets[i];
                if (!packet.is_early_data) {
                    i += 1;
                    continue;
                }

                var removed = path.sent.removeAt(i);
                defer removed.deinit(self.allocator);
                if (removed.stream_key) |stream_key| {
                    _ = try self.dispatchLostToStreams(stream_key);
                }
                _ = try self.dispatchLostControlFrames(&removed);
                self.discardSentCryptoForPacket(.early_data, removed.pn);
            }
        }
    }

    fn nextStreamPacketKey(self: *Connection) u64 {
        const key = self.next_stream_packet_key;
        self.next_stream_packet_key +|= 1;
        return key;
    }

    fn drainingDurationUs(self: *const Connection) u64 {
        return 3 * self.primaryPathConst().path.rtt.pto(self.peerMaxAckDelayUs());
    }

    fn backoffDuration(base: u64, count: u32) u64 {
        const shift: u6 = @intCast(@min(count, 16));
        const max_u64: u64 = std.math.maxInt(u64);
        if (base > (max_u64 >> shift)) return max_u64;
        return base << shift;
    }

    fn basePtoDurationForLevel(self: *const Connection, lvl: EncryptionLevel) u64 {
        const max_ack_delay_us: u64 = switch (lvl) {
            .initial, .handshake => 0,
            .early_data, .application => self.peerMaxAckDelayUs(),
        };
        return self.rttForLevelConst(lvl).pto(max_ack_delay_us);
    }

    fn ptoDurationForLevel(self: *const Connection, lvl: EncryptionLevel) u64 {
        return backoffDuration(self.basePtoDurationForLevel(lvl), self.ptoCountForLevelConst(lvl).*);
    }

    fn basePtoDurationForApplicationPath(self: *const Connection, path: *const PathState) u64 {
        return path.path.rtt.pto(self.peerMaxAckDelayUs());
    }

    fn ptoDurationForApplicationPath(self: *const Connection, path: *const PathState) u64 {
        return backoffDuration(self.basePtoDurationForApplicationPath(path), path.pto_count);
    }

    fn considerDeadline(best: *?TimerDeadline, candidate: TimerDeadline) void {
        if (best.* == null or candidate.at_us < best.*.?.at_us) {
            best.* = candidate;
        }
    }

    fn lossDeadlineForLevel(self: *const Connection, lvl: EncryptionLevel) ?u64 {
        const pn_space = self.pnSpaceForLevelConst(lvl);
        const sent = self.sentForLevelConst(lvl);
        const rtt = self.rttForLevelConst(lvl);
        const largest_acked = pn_space.largest_acked_sent orelse return null;
        const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );

        var best: ?u64 = null;
        var i: u32 = 0;
        while (i < sent.count) : (i += 1) {
            const p = sent.packets[i];
            if (p.pn > largest_acked) continue;
            const at_us = p.sent_time_us +| time_threshold;
            if (best == null or at_us < best.?) best = at_us;
        }
        return best;
    }

    fn lossDeadlineForApplicationPath(self: *const Connection, path: *const PathState) ?u64 {
        _ = self;
        const largest_acked = path.app_pn_space.largest_acked_sent orelse return null;
        const reference_rtt = @max(path.path.rtt.latest_rtt_us, path.path.rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );

        var best: ?u64 = null;
        var i: u32 = 0;
        while (i < path.sent.count) : (i += 1) {
            const p = path.sent.packets[i];
            if (p.pn > largest_acked) continue;
            const at_us = p.sent_time_us +| time_threshold;
            if (best == null or at_us < best.?) best = at_us;
        }
        return best;
    }

    fn ptoDeadlineForLevel(self: *const Connection, lvl: EncryptionLevel) ?u64 {
        const sent = self.sentForLevelConst(lvl);
        var oldest: ?u64 = null;
        var i: u32 = 0;
        while (i < sent.count) : (i += 1) {
            const p = sent.packets[i];
            if (!p.ack_eliciting) continue;
            if (oldest == null or p.sent_time_us < oldest.?) oldest = p.sent_time_us;
        }
        const sent_at = oldest orelse return null;
        return sent_at +| self.ptoDurationForLevel(lvl);
    }

    fn ptoDeadlineForApplicationPath(self: *const Connection, path: *const PathState) ?u64 {
        var oldest: ?u64 = null;
        var i: u32 = 0;
        while (i < path.sent.count) : (i += 1) {
            const p = path.sent.packets[i];
            if (!p.ack_eliciting) continue;
            if (oldest == null or p.sent_time_us < oldest.?) oldest = p.sent_time_us;
        }
        const sent_at = oldest orelse return null;
        return sent_at +| self.ptoDurationForApplicationPath(path);
    }

    fn idleDeadline(self: *const Connection) ?u64 {
        if (self.last_activity_us == 0) return null;
        const timeout = self.idleTimeoutUs() orelse return null;
        return self.last_activity_us +| timeout;
    }

    fn bytesInFlight(self: *const Connection) u64 {
        var total: u64 = 0;
        for (&self.sent) |*tracker| total += tracker.bytes_in_flight;
        for (self.paths.paths.items) |*p| total += p.sent.bytes_in_flight;
        return total;
    }

    pub fn congestionWindow(self: *const Connection) u64 {
        return self.ccForApplicationConst().cwnd;
    }

    pub fn congestionBytesInFlight(self: *const Connection) u64 {
        return self.bytesInFlight();
    }

    fn congestionBlocked(self: *const Connection, lvl: EncryptionLevel) bool {
        if (lvl != .application and lvl != .early_data) return false;
        const path = self.primaryPathConst();
        if (path.pending_ping) return false;
        return path.path.cc.sendAllowance(path.sent.bytes_in_flight) == 0;
    }

    fn congestionBlockedOnPath(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) bool {
        _ = self;
        if (lvl != .application and lvl != .early_data) return false;
        if (app_path.pending_ping) return false;
        return app_path.path.cc.sendAllowance(app_path.sent.bytes_in_flight) == 0;
    }

    pub fn nextTimerDeadline(self: *const Connection, now_us: u64) ?TimerDeadline {
        _ = now_us;
        var best: ?TimerDeadline = null;

        if (self.draining_deadline_us) |at_us| {
            considerDeadline(&best, .{ .kind = .draining, .at_us = at_us });
            return best;
        }

        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            const tracker = &self.pnSpaceForLevelConst(lvl).received;
            if (tracker.pending_ack) {
                considerDeadline(&best, .{
                    .kind = .ack_delay,
                    .at_us = tracker.largest_at_ms * rtt_mod.ms +| self.localMaxAckDelayUs(),
                    .level = lvl,
                });
            }
            if (self.lossDeadlineForLevel(lvl)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .loss_detection,
                    .at_us = at_us,
                    .level = lvl,
                });
            }
            if (self.ptoDeadlineForLevel(lvl)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .pto,
                    .at_us = at_us,
                    .level = lvl,
                });
            }
        }
        for (self.paths.paths.items) |*path| {
            const tracker = &path.app_pn_space.received;
            if (tracker.pending_ack) {
                considerDeadline(&best, .{
                    .kind = .ack_delay,
                    .at_us = tracker.largest_at_ms * rtt_mod.ms +| self.localMaxAckDelayUs(),
                    .level = .application,
                    .path_id = path.id,
                });
            }
            if (self.lossDeadlineForApplicationPath(path)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .loss_detection,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
            if (self.ptoDeadlineForApplicationPath(path)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .pto,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
        }

        if (self.idleDeadline()) |at_us| {
            considerDeadline(&best, .{ .kind = .idle, .at_us = at_us });
        }
        return best;
    }

    /// True if `poll` would produce an outgoing packet right now.
    pub fn canSend(self: *const Connection) bool {
        if (self.pending_close != null) return true;
        if (self.anyPendingPing()) return true;
        inline for (level_mod.all) |lvl| {
            const level_idx = lvl.idx();
            if (self.outbox[level_idx].len > 0) return true;
            if (self.crypto_retx[level_idx].items.len > 0) return true;
        }
        for (&self.pn_spaces) |*space| {
            if (space.received.pending_ack) return true;
        }
        if (self.pending_max_data != null) return true;
        if (self.pending_max_stream_data.items.len > 0) return true;
        if (self.pending_new_connection_ids.items.len > 0) return true;
        if (self.pending_stop_sending.items.len > 0) return true;
        if (self.pending_path_response != null) return true;
        if (self.pending_path_challenge != null) return true;
        if (self.pending_path_abandons.items.len > 0) return true;
        if (self.pending_path_statuses.items.len > 0) return true;
        if (self.pending_path_new_connection_ids.items.len > 0) return true;
        if (self.pending_path_retire_connection_ids.items.len > 0) return true;
        if (self.pending_max_path_id != null) return true;
        if (self.pending_paths_blocked != null) return true;
        if (self.pending_path_cids_blocked != null) return true;
        if (self.pending_send_datagrams.items.len > 0) return true;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.send.hasPendingChunk()) return true;
        }
        return false;
    }

    /// One outgoing-datagram step. Walks Initial → Handshake →
    /// Application encryption levels in order, packing whatever is
    /// pending at each (CRYPTO, ACK, STREAM) into a coalesced
    /// short/long-header datagram per RFC 9000 §12.2. Returns the
    /// total bytes written, or null if nothing was ready.
    pub fn poll(
        self: *Connection,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        const datagram = (try self.pollDatagram(dst, now_us)) orelse return null;
        return datagram.len;
    }

    /// Path-aware outgoing-datagram step. Single-path callers can
    /// keep using `poll`; multipath-aware embedders can inspect the
    /// destination address and path id once `PathSet` lands.
    pub fn pollDatagram(
        self: *Connection,
        dst: []u8,
        now_us: u64,
    ) Error!?OutgoingDatagram {
        if (self.closed and self.pending_close == null) return null;
        try self.refreshEarlyDataStatus();
        var pos: usize = 0;
        // Initial first (must lead a coalesced datagram).
        if (try self.pollLevel(.initial, dst[pos..], now_us)) |n| pos += n;
        // Client 0-RTT uses a long header but shares the Application
        // packet-number space. If the Initial padded this datagram to
        // the caller's MTU, this simply waits for the next poll.
        if (pos < dst.len) {
            if (try self.pollLevel(.early_data, dst[pos..], now_us)) |n| pos += n;
        }
        // Handshake next (after Initial keys are dropped post-handshake,
        // there's nothing here; otherwise it's CRYPTO + ACK).
        if (pos < dst.len) {
            if (try self.pollLevel(.handshake, dst[pos..], now_us)) |n| pos += n;
        }
        // Application last (the 1-RTT short header MUST be the last
        // packet in a coalesced datagram per §12.2). Only schedule a
        // non-zero path when there are no Initial/Handshake bytes already
        // in this datagram.
        const app_path_id = if (pos == 0)
            self.applicationPathForPoll().id
        else
            self.primaryPath().id;
        if (pos < dst.len) {
            if (try self.pollLevelOnPath(.application, app_path_id, dst[pos..], now_us)) |n| pos += n;
        }
        if (pos == 0) return null;
        self.last_activity_us = now_us;
        const out_path = self.pathForId(app_path_id);
        out_path.path.onDatagramSent(pos);
        return .{
            .len = pos,
            .to = out_path.peerAddress(),
            .path_id = out_path.id,
        };
    }

    /// Emit one packet at the given level, if there's anything to
    /// send and we have keys. Internal helper of `poll` — exposed
    /// for tests that want fine-grained control.
    pub fn pollLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        return self.pollLevelOnPath(lvl, self.primaryPath().id, dst, now_us);
    }

    fn pollLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path_id: u32,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        // Determine keys for this level. Initial keys are derived
        // from `initial_dcid`; Handshake/Application keys come from
        // the TLS bridge.
        var keys: PacketKeys = undefined;
        var have_keys = false;
        switch (lvl) {
            .initial => {
                try self.ensureInitialKeys();
                if (self.initial_keys_write) |k| {
                    keys = k;
                    have_keys = true;
                }
            },
            .handshake, .application => {
                if (try self.packetKeys(lvl, .write)) |k| {
                    keys = k;
                    have_keys = true;
                }
            },
            .early_data => {
                if (!self.canSendEarlyData()) return null;
                if (try self.packetKeys(lvl, .write)) |k| {
                    keys = k;
                    have_keys = true;
                }
            },
        }
        if (!have_keys) return null;
        if (!self.peer_dcid_set) return Error.PeerDcidNotSet;

        // Build payload.
        const app_path = self.pathForId(app_path_id);
        const pn_space = self.pnSpaceForLevelOnPath(lvl, app_path);
        const sent_tracker = self.sentForLevelOnPath(lvl, app_path);
        const pending_ping = self.pendingPingForLevelOnPath(lvl, app_path);
        var pl_buf: [default_mtu]u8 = undefined;
        var pl_pos: usize = 0;
        var ack_eliciting = false;
        var sent_packet: sent_packets_mod.SentPacket = .{
            .pn = 0,
            .sent_time_us = now_us,
            .bytes = 0,
            .ack_eliciting = false,
            .in_flight = false,
        };
        var sent_packet_recorded = false;
        errdefer if (!sent_packet_recorded) sent_packet.deinit(self.allocator);
        var sent_crypto_chunk: ?struct {
            level_idx: usize,
            offset: u64,
            data: []u8,
        } = null;
        var crypto_copy: ?[]u8 = null;
        var retx_crypto_index: ?usize = null;
        errdefer if (crypto_copy) |bytes| self.allocator.free(bytes);

        // Header overhead (worst case) varies by long/short.
        const packet_dcid: *const ConnectionId = if (lvl == .application)
            &app_path.path.peer_cid
        else
            &self.peer_dcid;
        const max_payload: usize = blk: {
            const dcid_len: usize = packet_dcid.len;
            const scid_len: usize = self.local_scid.len;
            const long_overhead: usize = 1 + 4 + 1 + dcid_len + 1 + scid_len + 8 + 4 + 16 + 8; // ample
            const short_overhead: usize = 1 + dcid_len + 4 + 16;
            const overhead: usize = if (lvl == .application) short_overhead else long_overhead;
            if (self.mtu <= overhead) break :blk 0;
            break :blk @min(default_mtu, self.mtu - overhead);
        };
        if (max_payload == 0) return Error.OutputTooSmall;
        const congestion_blocked = self.congestionBlockedOnPath(lvl, app_path);

        // CONNECTION_CLOSE pre-empts everything: if pending, that's
        // the only frame we emit, and we mark the connection
        // closed once it goes on the wire.
        if (self.pending_close) |info| {
            const close_frame = frame_types.ConnectionClose{
                .is_transport = info.is_transport,
                .error_code = info.error_code,
                .frame_type = info.frame_type,
                .reason_phrase = info.reason,
            };
            const wrote = try frame_mod.encode(
                pl_buf[0..max_payload],
                .{ .connection_close = close_frame },
            );
            pl_pos += wrote;
            self.pending_close = null;
            self.closed = true;
            // No ack-eliciting flag — CONNECTION_CLOSE isn't
            // ack-eliciting per §13.2.1, but we do still want to
            // record it (it occupies a PN). Skip stream/CRYPTO/etc.
            const pn = pn_space.nextPn() orelse return Error.PnSpaceExhausted;
            const largest_acked_close = pn_space.largest_acked_sent;
            const n_close = switch (lvl) {
                .initial => try long_packet_mod.sealInitial(dst, .{
                    .dcid = packet_dcid.slice(),
                    .scid = self.local_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                }),
                .handshake => try long_packet_mod.sealHandshake(dst, .{
                    .dcid = packet_dcid.slice(),
                    .scid = self.local_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                }),
                .application => try short_packet_mod.seal1Rtt(dst, .{
                    .dcid = packet_dcid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                    .key_phase = self.app_write_key_phase,
                    .multipath_path_id = if (self.multipathNegotiated()) app_path.id else null,
                }),
                .early_data => try long_packet_mod.sealZeroRtt(dst, .{
                    .dcid = packet_dcid.slice(),
                    .scid = self.local_scid.slice(),
                    .pn = pn,
                    .largest_acked = largest_acked_close,
                    .payload = pl_buf[0..pl_pos],
                    .keys = &keys,
                }),
            };
            try sent_tracker.record(.{
                .pn = pn,
                .sent_time_us = now_us,
                .bytes = n_close,
                .ack_eliciting = false,
                .in_flight = false,
                .is_early_data = lvl == .early_data,
            });
            self.draining_deadline_us = now_us + self.drainingDurationUs();
            return n_close;
        }

        // 1) ACK frame (if pending in this level's space).
        const recv_tracker = &pn_space.received;
        if (lvl != .early_data and recv_tracker.pending_ack) {
            var ranges_buf: [128]u8 = undefined;
            const ack_frame = try recv_tracker.toAckFrame(
                self.ackDelayScaled(recv_tracker, now_us),
                &ranges_buf,
            );
            const ack_len = if (lvl == .application and app_path.id != 0)
                try frame_mod.encode(
                    pl_buf[pl_pos..max_payload],
                    .{ .path_ack = .{
                        .path_id = app_path.id,
                        .largest_acked = ack_frame.largest_acked,
                        .ack_delay = ack_frame.ack_delay,
                        .first_range = ack_frame.first_range,
                        .range_count = ack_frame.range_count,
                        .ranges_bytes = ack_frame.ranges_bytes,
                        .ecn_counts = ack_frame.ecn_counts,
                    } },
                )
            else
                try frame_mod.encode(
                    pl_buf[pl_pos..max_payload],
                    .{ .ack = ack_frame },
                );
            pl_pos += ack_len;
            recv_tracker.markAckSent();
        }

        // 1a) PTO probe PING. A lost PING is not retransmitted as a
        // frame, but a later PTO will queue another probe.
        if (lvl != .early_data and pending_ping.* and pl_pos + 1 <= max_payload) {
            const ping_len = try frame_mod.encode(
                pl_buf[pl_pos..max_payload],
                .{ .ping = .{} },
            );
            pl_pos += ping_len;
            pending_ping.* = false;
            ack_eliciting = true;
        }

        // 2) CRYPTO frame: retransmit lost data first, then drain
        // fresh outbox bytes at this level into one frame.
        const out_idx = lvl.idx();
        if (lvl != .early_data and !congestion_blocked and self.crypto_retx[out_idx].items.len > 0 and pl_pos + 25 < max_payload) {
            const max_data = max_payload - pl_pos - 25;
            const chunk = self.crypto_retx[out_idx].items[0];
            if (chunk.data.len <= max_data) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .crypto = .{
                        .offset = chunk.offset,
                        .data = chunk.data,
                    },
                });
                pl_pos += wrote;
                const copy = try self.allocator.dupe(u8, chunk.data);
                crypto_copy = copy;
                sent_crypto_chunk = .{
                    .level_idx = out_idx,
                    .offset = chunk.offset,
                    .data = copy,
                };
                retx_crypto_index = 0;
                ack_eliciting = true;
            }
        } else if (lvl != .early_data and !congestion_blocked and self.outbox[out_idx].len > 0 and pl_pos + 25 < max_payload) {
            const max_data = max_payload - pl_pos - 25;
            const drain_len = @min(self.outbox[out_idx].len, max_data);
            const data_slice = self.outbox[out_idx].buf[0..drain_len];
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .crypto = .{
                    .offset = self.crypto_send_offset[out_idx],
                    .data = data_slice,
                },
            });
            pl_pos += wrote;
            const copy = try self.allocator.dupe(u8, data_slice);
            crypto_copy = copy;
            sent_crypto_chunk = .{
                .level_idx = out_idx,
                .offset = self.crypto_send_offset[out_idx],
                .data = copy,
            };
            self.crypto_send_offset[out_idx] += drain_len;
            // Shift the outbox left to drop what we just consumed.
            const remaining = self.outbox[out_idx].len - drain_len;
            std.mem.copyForwards(
                u8,
                self.outbox[out_idx].buf[0..remaining],
                self.outbox[out_idx].buf[drain_len..self.outbox[out_idx].len],
            );
            self.outbox[out_idx].len = remaining;
            ack_eliciting = true;
        }

        // 2a) MAX_DATA / MAX_STREAM_DATA (application only). We queue these
        // when the application drains receive buffers so peers can
        // continue uploads beyond their current stream window.
        if (!congestion_blocked and lvl == .application and self.pending_max_data != null) {
            const maximum_data = self.pending_max_data.?;
            const overhead_md: usize = 1 + varint.encodedLen(maximum_data);
            if (max_payload >= pl_pos + overhead_md) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .max_data = .{ .maximum_data = maximum_data },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .max_data = .{ .maximum_data = maximum_data },
                });
                self.pending_max_data = null;
                ack_eliciting = true;
            }
        }
        if (!congestion_blocked and lvl == .application and self.pending_max_stream_data.items.len > 0) {
            const item = self.pending_max_stream_data.items[0];
            const overhead_msd: usize = 1 +
                varint.encodedLen(item.stream_id) +
                varint.encodedLen(item.maximum_stream_data);
            if (max_payload >= pl_pos + overhead_msd) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .max_stream_data = .{
                        .stream_id = item.stream_id,
                        .maximum_stream_data = item.maximum_stream_data,
                    },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .max_stream_data = .{
                        .stream_id = item.stream_id,
                        .maximum_stream_data = item.maximum_stream_data,
                    },
                });
                _ = self.pending_max_stream_data.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2b) NEW_CONNECTION_ID (application only). Advertise spare
        // CIDs so peers can validate/migrate additional paths.
        if (!congestion_blocked and lvl == .application and self.pending_new_connection_ids.items.len > 0) {
            const item = self.pending_new_connection_ids.items[0];
            const overhead_ncid: usize = 1 +
                varint.encodedLen(item.sequence_number) +
                varint.encodedLen(item.retire_prior_to) +
                1 + item.connection_id.len + 16;
            if (max_payload >= pl_pos + overhead_ncid) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .new_connection_id = .{
                        .sequence_number = item.sequence_number,
                        .retire_prior_to = item.retire_prior_to,
                        .connection_id = item.connection_id,
                        .stateless_reset_token = item.stateless_reset_token,
                    },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .new_connection_id = .{
                        .sequence_number = item.sequence_number,
                        .retire_prior_to = item.retire_prior_to,
                        .connection_id = item.connection_id,
                        .stateless_reset_token = item.stateless_reset_token,
                    },
                });
                _ = self.pending_new_connection_ids.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2c) STOP_SENDING (one per packet for now — application only).
        if (!congestion_blocked and lvl == .application and self.pending_stop_sending.items.len > 0) {
            const item = self.pending_stop_sending.items[0];
            const overhead_ss: usize = 1 + varint.encodedLen(item.stream_id) + varint.encodedLen(item.application_error_code);
            if (max_payload >= pl_pos + overhead_ss) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .stop_sending = .{
                        .stream_id = item.stream_id,
                        .application_error_code = item.application_error_code,
                    },
                });
                pl_pos += wrote;
                try sent_packet.addRetransmitFrame(self.allocator, .{
                    .stop_sending = .{
                        .stream_id = item.stream_id,
                        .application_error_code = item.application_error_code,
                    },
                });
                _ = self.pending_stop_sending.orderedRemove(0);
                ack_eliciting = true;
            }
        }

        // 2d) PATH_RESPONSE / PATH_CHALLENGE (application level only,
        //     RFC 9000 §19.17/19.18). PATH_RESPONSE has the highest
        //     priority on the application path so we don't make the
        //     peer wait through a stream-data backlog.
        if (!congestion_blocked and lvl == .application and self.pending_path_response != null and pl_pos + 9 <= max_payload) {
            const tok = self.pending_path_response.?;
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .path_response = .{ .data = tok },
            });
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{
                .path_response = .{ .data = tok },
            });
            self.pending_path_response = null;
            ack_eliciting = true;
        }
        if (!congestion_blocked and lvl == .application and self.pending_path_challenge != null and pl_pos + 9 <= max_payload) {
            const tok = self.pending_path_challenge.?;
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .path_challenge = .{ .data = tok },
            });
            pl_pos += wrote;
            try sent_packet.addRetransmitFrame(self.allocator, .{
                .path_challenge = .{ .data = tok },
            });
            self.pending_path_challenge = null;
            ack_eliciting = true;
        }

        // 2e) Draft-21 multipath control frames. Emit at most one per
        //     packet so the fixed sent-packet retransmit metadata budget
        //     stays predictable while the full scheduler is still landing.
        if (!congestion_blocked and lvl == .application) {
            if (try self.emitOnePendingMultipathFrame(&sent_packet, &pl_buf, &pl_pos, max_payload)) {
                ack_eliciting = true;
            }
        }

        // 2e) RESET_STREAM frames for streams in reset_sent state
        //     whose RESET hasn't been queued yet. Emit at most one
        //     per packet; the loop handles all eventually.
        if (!congestion_blocked and lvl == .application) {
            var rs_it = self.streams.iterator();
            while (rs_it.next()) |entry| {
                const s = entry.value_ptr.*;
                if (s.send.reset) |*ri| {
                    if (ri.queued) continue;
                    const overhead_rs: usize = 1 +
                        varint.encodedLen(s.id) +
                        varint.encodedLen(ri.error_code) +
                        varint.encodedLen(ri.final_size);
                    if (max_payload < pl_pos + overhead_rs) break;
                    const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                        .reset_stream = .{
                            .stream_id = s.id,
                            .application_error_code = ri.error_code,
                            .final_size = ri.final_size,
                        },
                    });
                    pl_pos += wrote;
                    try sent_packet.addRetransmitFrame(self.allocator, .{
                        .reset_stream = .{
                            .stream_id = s.id,
                            .application_error_code = ri.error_code,
                            .final_size = ri.final_size,
                        },
                    });
                    ri.queued = true;
                    ack_eliciting = true;
                    break;
                }
            }
        }

        // 3a) DATAGRAM frame (Application PN space). One queued
        //     payload per packet; LEN-prefixed so DATAGRAM doesn't
        //     have to be the last frame.
        if (!congestion_blocked and (lvl == .application or lvl == .early_data) and self.pending_send_datagrams.items.len > 0) {
            const dg = self.pending_send_datagrams.items[0];
            const dg_overhead: usize = 1 + varint.encodedLen(dg.len);
            if (max_payload >= pl_pos + dg_overhead + dg.len) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .datagram = .{ .data = dg, .has_length = true },
                });
                pl_pos += wrote;
                _ = self.pending_send_datagrams.orderedRemove(0);
                self.allocator.free(dg);
                ack_eliciting = true;
            }
        }

        // 3b) STREAM frame (Application PN space).
        var sent_chunk: ?struct { stream: *Stream, chunk: send_stream_mod.Chunk } = null;
        if (!congestion_blocked and (lvl == .application or lvl == .early_data)) {
            var s_it = self.streams.iterator();
            while (s_it.next()) |entry| {
                const s = entry.value_ptr.*;
                const stream_overhead: usize = 25;
                if (max_payload <= pl_pos + stream_overhead) break;
                const budget = max_payload - pl_pos - stream_overhead;
                const chunk = s.send.peekChunk(budget) orelse continue;
                const data_slice = s.send.chunkBytes(chunk);
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                    .stream = .{
                        .stream_id = s.id,
                        .offset = chunk.offset,
                        .data = data_slice,
                        .has_offset = chunk.offset != 0,
                        .has_length = true,
                        .fin = chunk.fin,
                    },
                });
                pl_pos += wrote;
                sent_chunk = .{ .stream = s, .chunk = chunk };
                ack_eliciting = true;
                break;
            }
        }

        if (pl_pos == 0) return null;

        // 4) Allocate PN at this level, seal at the right header type.
        const pn = pn_space.nextPn() orelse return Error.PnSpaceExhausted;
        const largest_acked = pn_space.largest_acked_sent;
        const n = switch (lvl) {
            .initial => try long_packet_mod.sealInitial(dst, .{
                .dcid = packet_dcid.slice(),
                .scid = self.local_scid.slice(),
                .token = &.{},
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
                // Pad client first-flight Initials to 1200 bytes
                // (RFC 9000 §14). We over-pad on every Initial here
                // for simplicity; tightening to "first flight only"
                // is a future scope.
                .pad_to = if (self.role == .client) 1200 else 0,
            }),
            .handshake => try long_packet_mod.sealHandshake(dst, .{
                .dcid = packet_dcid.slice(),
                .scid = self.local_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
            }),
            .application => try short_packet_mod.seal1Rtt(dst, .{
                .dcid = packet_dcid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
                .key_phase = self.app_write_key_phase,
                .multipath_path_id = if (self.multipathNegotiated()) app_path.id else null,
            }),
            .early_data => try long_packet_mod.sealZeroRtt(dst, .{
                .dcid = packet_dcid.slice(),
                .scid = self.local_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked,
                .payload = pl_buf[0..pl_pos],
                .keys = &keys,
            }),
        };

        // 5) Commit.
        sent_packet.pn = pn;
        sent_packet.bytes = n;
        sent_packet.ack_eliciting = ack_eliciting;
        sent_packet.in_flight = ack_eliciting;
        sent_packet.is_early_data = lvl == .early_data;
        const sent_stream_key = if (sent_chunk != null) self.nextStreamPacketKey() else null;
        sent_packet.stream_key = sent_stream_key;
        try sent_tracker.record(sent_packet);
        sent_packet_recorded = true;
        if (sent_chunk) |sc| {
            try sc.stream.send.recordSent(sent_stream_key.?, sc.chunk);
        }
        if (sent_crypto_chunk) |sc| {
            try self.sent_crypto[sc.level_idx].append(self.allocator, .{
                .pn = pn,
                .offset = sc.offset,
                .data = sc.data,
            });
            crypto_copy = null;
        }
        if (retx_crypto_index) |idx| {
            const old = self.crypto_retx[out_idx].orderedRemove(idx);
            self.allocator.free(old.data);
        }

        return n;
    }

    fn encodeFrameIfFits(
        pl_buf: *[default_mtu]u8,
        pl_pos: *usize,
        max_payload: usize,
        frame: frame_types.Frame,
    ) Error!bool {
        const needed = frame_mod.encodedLen(frame);
        if (max_payload < pl_pos.* + needed) return false;
        const wrote = try frame_mod.encode(pl_buf[pl_pos.*..max_payload], frame);
        pl_pos.* += wrote;
        return true;
    }

    fn emitOnePendingMultipathFrame(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
        pl_buf: *[default_mtu]u8,
        pl_pos: *usize,
        max_payload: usize,
    ) Error!bool {
        if (self.pending_path_abandons.items.len > 0) {
            const item = self.pending_path_abandons.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_abandon = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_abandon = item });
                _ = self.pending_path_abandons.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_path_statuses.items.len > 0) {
            const item = self.pending_path_statuses.items[0];
            const status: frame_types.PathStatus = .{
                .path_id = item.path_id,
                .sequence_number = item.sequence_number,
            };
            const frame: frame_types.Frame = if (item.available)
                .{ .path_status_available = status }
            else
                .{ .path_status_backup = status };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, frame)) {
                try sent_packet.addRetransmitFrame(
                    self.allocator,
                    if (item.available)
                        .{ .path_status_available = status }
                    else
                        .{ .path_status_backup = status },
                );
                _ = self.pending_path_statuses.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_path_new_connection_ids.items.len > 0) {
            const item = self.pending_path_new_connection_ids.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_new_connection_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_new_connection_id = item });
                _ = self.pending_path_new_connection_ids.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_path_retire_connection_ids.items.len > 0) {
            const item = self.pending_path_retire_connection_ids.items[0];
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_retire_connection_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_retire_connection_id = item });
                _ = self.pending_path_retire_connection_ids.orderedRemove(0);
                return true;
            }
        }
        if (self.pending_max_path_id) |maximum_path_id| {
            const item: frame_types.MaxPathId = .{ .maximum_path_id = maximum_path_id };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .max_path_id = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .max_path_id = item });
                self.pending_max_path_id = null;
                return true;
            }
        }
        if (self.pending_paths_blocked) |maximum_path_id| {
            const item: frame_types.PathsBlocked = .{ .maximum_path_id = maximum_path_id };
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .paths_blocked = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .paths_blocked = item });
                self.pending_paths_blocked = null;
                return true;
            }
        }
        if (self.pending_path_cids_blocked) |item| {
            if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_cids_blocked = item })) {
                try sent_packet.addRetransmitFrame(self.allocator, .{ .path_cids_blocked = item });
                self.pending_path_cids_blocked = null;
                return true;
            }
        }
        return false;
    }

    /// Process an incoming UDP datagram. Splits coalesced packets
    /// (RFC 9000 §12.2) and routes each through the matching
    /// per-level decrypt + frame-dispatch path.
    pub fn handle(
        self: *Connection,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!void {
        if (bytes.len > 0) self.last_activity_us = now_us;
        const incoming_path_id = self.incomingPathId(from);
        self.current_incoming_path_id = incoming_path_id;
        const incoming_path = self.pathForId(incoming_path_id);
        incoming_path.path.onDatagramReceived(bytes.len);
        if (from) |addr| incoming_path.setPeerAddress(addr);
        var pos: usize = 0;
        while (pos < bytes.len) {
            const consumed = try self.handleOnePacket(bytes[pos..], now_us);
            if (consumed == 0) break;
            pos += consumed;
            // Drain CRYPTO into TLS BETWEEN packets, not just at
            // the end. A coalesced Initial+Handshake datagram
            // delivers the ServerHello at Initial level — we have
            // to feed it to TLS (deriving Handshake keys) before
            // we can decrypt the trailing Handshake packet.
            try self.drainInboxIntoTls();
        }
        // PATH_CHALLENGE → record-and-tick; the validator will
        // either succeed (echo arrived) or time out at PTO * 3.
        self.primaryPath().path.validator.tick(now_us);
        if (self.alert) |_| return error.PeerAlerted;
    }

    /// Initiate path validation by queueing a PATH_CHALLENGE on
    /// the next outgoing 1-RTT packet. `timeout_us` is typically
    /// `3 * pto` per RFC 9000 §8.2.4. Returns the token.
    pub fn probePath(
        self: *Connection,
        token: [8]u8,
        now_us: u64,
        timeout_us: u64,
    ) Error!void {
        self.primaryPath().path.validator.beginChallenge(token, now_us, timeout_us);
        self.pending_path_challenge = token;
    }

    /// True iff the active path has been validated (either via the
    /// validator's PATH_RESPONSE flow or by `markPathValidated`).
    pub fn isPathValidated(self: *const Connection) bool {
        return self.primaryPathConst().path.validator.isValidated();
    }

    /// True after we've sent or received a CONNECTION_CLOSE frame.
    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    /// Queue a CONNECTION_CLOSE frame (RFC 9000 §19.19) for the
    /// next outgoing packet. `is_transport` selects between
    /// transport (0x1c) and application (0x1d) error spaces.
    pub fn close(
        self: *Connection,
        is_transport: bool,
        error_code: u64,
        reason: []const u8,
    ) void {
        if (self.pending_close != null) return;
        self.pending_close = .{
            .is_transport = is_transport,
            .error_code = error_code,
            .reason = reason,
        };
    }

    /// Queue a STOP_SENDING for `stream_id` with the given app
    /// error code (RFC 9000 §19.5). Tells the peer to stop
    /// sending on the receiving half of the stream.
    pub fn streamStopSending(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.queueStopSending(.{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        });
    }

    fn queueStopSending(
        self: *Connection,
        item: StopSendingItem,
    ) Error!void {
        for (self.pending_stop_sending.items) |queued| {
            if (queued.stream_id == item.stream_id and
                queued.application_error_code == item.application_error_code)
            {
                return;
            }
        }
        try self.pending_stop_sending.append(self.allocator, .{
            .stream_id = item.stream_id,
            .application_error_code = item.application_error_code,
        });
    }

    /// Number of peer-issued connection IDs we currently have
    /// stashed via NEW_CONNECTION_ID frames.
    pub fn peerCidsCount(self: *const Connection) usize {
        return self.peer_cids.items.len;
    }

    fn handleOnePacket(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        if (bytes.len < 1) return 0;
        const first = bytes[0];

        if (first & 0x80 == 0) {
            // Short header → 1-RTT, last in datagram.
            return try self.handleShort(bytes, now_us);
        }

        const long_type_bits: u2 = @intCast((first >> 4) & 0x03);
        return switch (long_type_bits) {
            0 => try self.handleInitial(bytes, now_us),
            1 => try self.handleZeroRtt(bytes, now_us),
            2 => try self.handleHandshake(bytes, now_us),
            // 3 = Retry
            else => bytes.len,
        };
    }

    fn handleShort(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        const r_keys_opt = try self.packetKeys(.application, .read);
        const r_keys = r_keys_opt orelse return bytes.len;
        const app_path = self.incomingShortPath(bytes) orelse
            self.pathForId(self.current_incoming_path_id);
        self.current_incoming_path_id = app_path.id;
        const app_pn_space = &app_path.app_pn_space;
        const largest_received = if (app_pn_space.received.largest) |l| l else 0;
        const multipath_path_id: ?u32 = if (self.multipathNegotiated()) app_path.id else null;

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const opened = short_packet_mod.open1Rtt(&pt_buf, bytes, .{
            .dcid_len = app_path.path.local_cid.len,
            .keys = &r_keys,
            .largest_received = largest_received,
            .multipath_path_id = multipath_path_id,
        }) catch |e| switch (e) {
            // RFC 9000 §5.2: a packet that fails authentication is
            // silently dropped without affecting the rest of the
            // connection. First try the next application read keys:
            // quic-go initiates its first key update after about 100
            // packets, which large uploads hit quickly.
            boringssl.crypto.aead.Error.Auth => blk: {
                const update = (try self.nextApplicationKeyUpdate(.read)) orelse
                    return bytes.len;
                const retried = short_packet_mod.open1Rtt(&pt_buf, bytes, .{
                    .dcid_len = app_path.path.local_cid.len,
                    .keys = &update.keys,
                    .largest_received = largest_received,
                    .multipath_path_id = multipath_path_id,
                }) catch |retry_e| switch (retry_e) {
                    boringssl.crypto.aead.Error.Auth => return bytes.len,
                    else => return retry_e,
                };
                if (retried.key_phase == self.app_read_key_phase) return bytes.len;
                self.installApplicationKeyUpdate(.read, update);
                try self.updateApplicationWriteKeys();
                break :blk retried;
            },
            else => return e,
        };
        if (opened.key_phase != self.app_read_key_phase) return bytes.len;

        app_pn_space.recordReceived(opened.pn, now_us / 1000);
        try self.dispatchFrames(.application, opened.payload, now_us);
        return bytes.len;
    }

    fn handleInitial(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        // Server-side bootstrap: discover `initial_dcid` from the
        // unprotected long-header bytes before any decryption can
        // happen. RFC 9001 §5.2 derives Initial keys from the DCID
        // the client put on its first Initial.
        if (self.role == .server and !self.initial_dcid_set) {
            if (bytes.len < 6) return bytes.len;
            const dcid_len = bytes[5];
            if (dcid_len > path_mod.max_cid_len) return bytes.len;
            if (bytes.len < @as(usize, 6) + dcid_len) return bytes.len;
            try self.setInitialDcid(bytes[6 .. 6 + dcid_len]);
        }
        try self.ensureInitialKeys();
        const r_keys_opt = self.initial_keys_read;
        const r_keys = r_keys_opt orelse return bytes.len;

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const opened = long_packet_mod.openInitial(&pt_buf, bytes, .{
            .keys = &r_keys,
            .largest_received = if (self.pnSpaceForLevel(.initial).received.largest) |l| l else 0,
        }) catch |e| switch (e) {
            boringssl.crypto.aead.Error.Auth => return bytes.len,
            else => return e,
        };

        // Server side: discover peer's CIDs from the very first Initial.
        if (self.role == .server) {
            if (!self.peer_dcid_set) {
                self.peer_dcid = ConnectionId.fromSlice(opened.scid.slice());
                self.peer_dcid_set = true;
            }
            if (!self.initial_dcid_set) {
                self.initial_dcid = ConnectionId.fromSlice(opened.dcid.slice());
                self.initial_dcid_set = true;
                try self.ensureInitialKeys();
            }
        }

        self.pnSpaceForLevel(.initial).recordReceived(opened.pn, now_us / 1000);
        try self.dispatchFrames(.initial, opened.payload, now_us);
        return opened.bytes_consumed;
    }

    fn handleZeroRtt(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        if (self.role != .server) return bytes.len;
        if (self.inner.earlyDataStatus() == .rejected) return bytes.len;

        const r_keys_opt = try self.packetKeys(.early_data, .read);
        const r_keys = r_keys_opt orelse return bytes.len;
        const app_path = self.pathForId(self.current_incoming_path_id);
        const app_pn_space = &app_path.app_pn_space;
        const largest_received = if (app_pn_space.received.largest) |l| l else 0;

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const opened = long_packet_mod.openZeroRtt(&pt_buf, bytes, .{
            .keys = &r_keys,
            .largest_received = largest_received,
        }) catch |e| switch (e) {
            boringssl.crypto.aead.Error.Auth => return bytes.len,
            else => return e,
        };

        app_pn_space.recordReceived(opened.pn, now_us / 1000);
        try self.dispatchFrames(.early_data, opened.payload, now_us);
        return opened.bytes_consumed;
    }

    fn handleHandshake(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        const r_keys_opt = try self.packetKeys(.handshake, .read);
        const r_keys = r_keys_opt orelse return bytes.len;

        var pt_buf: [max_recv_plaintext]u8 = undefined;
        const opened = long_packet_mod.openHandshake(&pt_buf, bytes, .{
            .keys = &r_keys,
            .largest_received = if (self.pnSpaceForLevel(.handshake).received.largest) |l| l else 0,
        }) catch |e| switch (e) {
            boringssl.crypto.aead.Error.Auth => return bytes.len,
            else => return e,
        };

        self.pnSpaceForLevel(.handshake).recordReceived(opened.pn, now_us / 1000);
        try self.dispatchFrames(.handshake, opened.payload, now_us);
        return opened.bytes_consumed;
    }

    fn dispatchFrames(
        self: *Connection,
        lvl: EncryptionLevel,
        payload: []const u8,
        now_us: u64,
    ) Error!void {
        if (debugFrames() != null) {
            std.debug.print("[frames lvl={s} payload_len={d}] ", .{ @tagName(lvl), payload.len });
        }
        var it = frame_mod.iter(payload);
        while (try it.next()) |f| {
            if (debugFrames() != null) {
                switch (f) {
                    .crypto => |cr| std.debug.print("CRYPTO(off={d},len={d}) ", .{ cr.offset, cr.data.len }),
                    .padding => |p| std.debug.print("PADDING(n={d}) ", .{p.count}),
                    .ack => |a| std.debug.print("ACK(la={d}) ", .{a.largest_acked}),
                    .path_ack => |a| std.debug.print("PATH_ACK(path={d},la={d}) ", .{ a.path_id, a.largest_acked }),
                    .stream => |s| std.debug.print("STREAM(id={d},off={d},len={d},fin={}) ", .{ s.stream_id, s.offset, s.data.len, s.fin }),
                    .datagram => |d| std.debug.print("DATAGRAM(len={d}) ", .{d.data.len}),
                    .reset_stream => |r| std.debug.print("RESET_STREAM(id={d},code={d},final={d}) ", .{ r.stream_id, r.application_error_code, r.final_size }),
                    .path_abandon => |pa| std.debug.print("PATH_ABANDON(path={d},code={d}) ", .{ pa.path_id, pa.error_code }),
                    .path_status_backup => |ps| std.debug.print("PATH_STATUS_BACKUP(path={d},seq={d}) ", .{ ps.path_id, ps.sequence_number }),
                    .path_status_available => |ps| std.debug.print("PATH_STATUS_AVAILABLE(path={d},seq={d}) ", .{ ps.path_id, ps.sequence_number }),
                    .path_new_connection_id => |nc| std.debug.print("PATH_NEW_CONNECTION_ID(path={d},seq={d}) ", .{ nc.path_id, nc.sequence_number }),
                    .path_retire_connection_id => |rc| std.debug.print("PATH_RETIRE_CONNECTION_ID(path={d},seq={d}) ", .{ rc.path_id, rc.sequence_number }),
                    .max_path_id => |mp| std.debug.print("MAX_PATH_ID(max={d}) ", .{mp.maximum_path_id}),
                    .paths_blocked => |pb| std.debug.print("PATHS_BLOCKED(max={d}) ", .{pb.maximum_path_id}),
                    .path_cids_blocked => |pcb| std.debug.print("PATH_CIDS_BLOCKED(path={d},next={d}) ", .{ pcb.path_id, pcb.next_sequence_number }),
                    .ping => std.debug.print("PING ", .{}),
                    else => |x| std.debug.print("{s} ", .{@tagName(x)}),
                }
            }
            if (lvl == .early_data and !frameAllowedInEarlyData(f)) {
                self.close(true, transport_error_protocol_violation, "forbidden frame in 0-RTT");
                return;
            }
            if (lvl != .application and isMultipathFrame(f)) {
                self.close(true, transport_error_protocol_violation, "multipath frame outside 1-RTT");
                return;
            }
            if (lvl == .application and isMultipathFrame(f) and !self.multipathNegotiated()) {
                self.close(true, transport_error_protocol_violation, "multipath frame without negotiation");
                return;
            }
            if (lvl == .application and isMultipathFrame(f) and
                !self.validateIncomingMultipathFrame(f))
            {
                return;
            }
            switch (f) {
                .padding, .ping, .handshake_done => {},
                .ack => |a| try self.handleAckAtLevel(lvl, a, now_us),
                .path_ack => |a| try self.handlePathAck(a, now_us),
                .crypto => |cr| try self.handleCrypto(lvl, cr),
                .stream => |s| try self.handleStream(lvl, s),
                .reset_stream => |rs| try self.handleResetStream(rs),
                .datagram => |dg| try self.handleDatagram(lvl, dg),
                .path_challenge => |pc| self.pending_path_response = pc.data,
                .path_response => |pr| {
                    _ = self.pathForId(self.current_incoming_path_id).path.validator.recordResponse(pr.data) catch {};
                },
                .new_connection_id => |nc| try self.handleNewConnectionId(nc),
                .stop_sending => |ss| try self.handleStopSending(ss),
                .path_abandon => |pa| self.handlePathAbandon(pa),
                .path_status_backup => |ps| self.handlePathStatus(ps, false),
                .path_status_available => |ps| self.handlePathStatus(ps, true),
                .path_new_connection_id => |nc| try self.handlePathNewConnectionId(nc),
                .path_retire_connection_id => |rc| self.handlePathRetireConnectionId(rc),
                .max_path_id => |mp| self.handleMaxPathId(mp),
                .paths_blocked => |pb| self.handlePathsBlocked(pb),
                .path_cids_blocked => |pcb| self.handlePathCidsBlocked(pcb),
                .connection_close => {
                    self.closed = true;
                    self.draining_deadline_us = now_us + self.drainingDurationUs();
                },
                .retire_connection_id => |rc| self.handleRetireConnectionId(rc),
                .max_data, .max_stream_data, .max_streams, .data_blocked, .stream_data_blocked, .streams_blocked, .new_token => {},
            }
        }
        if (debugFrames() != null) {
            std.debug.print("\n", .{});
        }
    }

    fn isMultipathFrame(f: frame_types.Frame) bool {
        return switch (f) {
            .path_ack,
            .path_abandon,
            .path_status_backup,
            .path_status_available,
            .path_new_connection_id,
            .path_retire_connection_id,
            .max_path_id,
            .paths_blocked,
            .path_cids_blocked,
            => true,
            else => false,
        };
    }

    fn frameAllowedInEarlyData(f: frame_types.Frame) bool {
        return switch (f) {
            .ack,
            .crypto,
            .handshake_done,
            .new_token,
            .path_response,
            .retire_connection_id,
            => false,
            else => true,
        };
    }

    fn tokenEql(a: [16]u8, b: [16]u8) bool {
        return std.mem.eql(u8, a[0..], b[0..]);
    }

    fn pathIdAllowedByLocalLimit(self: *Connection, path_id: u32) bool {
        if (path_id <= self.local_max_path_id) return true;
        self.close(true, transport_error_protocol_violation, "multipath path id exceeds local limit");
        return false;
    }

    fn validateIncomingMultipathFrame(self: *Connection, f: frame_types.Frame) bool {
        return switch (f) {
            .path_ack => |pa| self.pathIdAllowedByLocalLimit(pa.path_id),
            .path_abandon => |pa| self.pathIdAllowedByLocalLimit(pa.path_id),
            .path_status_backup => |ps| self.pathIdAllowedByLocalLimit(ps.path_id),
            .path_status_available => |ps| self.pathIdAllowedByLocalLimit(ps.path_id),
            .path_new_connection_id => |nc| self.pathIdAllowedByLocalLimit(nc.path_id),
            .path_retire_connection_id => |rc| self.pathIdAllowedByLocalLimit(rc.path_id),
            .paths_blocked => |pb| self.pathIdAllowedByLocalLimit(pb.maximum_path_id),
            .path_cids_blocked => |pcb| blk: {
                if (!self.pathIdAllowedByLocalLimit(pcb.path_id)) break :blk false;
                const next = self.nextLocalCidSequence(pcb.path_id);
                if (pcb.next_sequence_number > next) {
                    self.close(true, transport_error_protocol_violation, "path cids blocked skips local cid sequence");
                    break :blk false;
                }
                break :blk true;
            },
            .max_path_id => |mp| blk: {
                if (self.cached_peer_transport_params) |params| {
                    if (params.initial_max_path_id) |initial_max_path_id| {
                        if (mp.maximum_path_id < initial_max_path_id) {
                            self.close(true, transport_error_protocol_violation, "max path id below peer initial limit");
                            break :blk false;
                        }
                    }
                }
                break :blk true;
            },
            else => true,
        };
    }

    fn peerCidActiveCountForPath(self: *const Connection, path_id: u32) usize {
        var count: usize = 0;
        for (self.peer_cids.items) |item| {
            if (item.path_id == path_id) count += 1;
        }
        return count;
    }

    fn promotePeerCidForPath(self: *Connection, path_id: u32) void {
        const path = self.paths.get(path_id) orelse return;
        path.path.peer_cid = .{};
        for (self.peer_cids.items) |item| {
            if (item.path_id == path_id) {
                path.path.peer_cid = item.cid;
                break;
            }
        }
        if (path_id == 0) {
            self.peer_dcid = path.path.peer_cid;
            self.peer_dcid_set = self.peer_dcid.len != 0;
        }
    }

    fn retirePeerCidsPriorTo(
        self: *Connection,
        path_id: u32,
        retire_prior_to: u64,
    ) void {
        var i: usize = 0;
        var affected_current = false;
        const current = if (self.paths.get(path_id)) |path| path.path.peer_cid else ConnectionId{};
        while (i < self.peer_cids.items.len) {
            const item = self.peer_cids.items[i];
            if (item.path_id == path_id and item.sequence_number < retire_prior_to) {
                if (ConnectionId.eql(item.cid, current)) affected_current = true;
                _ = self.peer_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        if (affected_current) self.promotePeerCidForPath(path_id);
    }

    fn retirePeerCidsForPath(self: *Connection, path_id: u32) void {
        var i: usize = 0;
        while (i < self.peer_cids.items.len) {
            if (self.peer_cids.items[i].path_id == path_id) {
                _ = self.peer_cids.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        self.promotePeerCidForPath(path_id);
    }

    fn registerPeerCid(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [16]u8,
    ) Error!void {
        if (retire_prior_to > sequence_number) {
            self.close(true, transport_error_protocol_violation, "invalid connection id retire_prior_to");
            return;
        }
        if (self.multipathNegotiated() and !self.pathIdAllowedByLocalLimit(path_id)) return;

        for (self.peer_cids.items) |*item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                if (!ConnectionId.eql(item.cid, cid) or
                    !tokenEql(item.stateless_reset_token, stateless_reset_token))
                {
                    self.close(true, transport_error_protocol_violation, "connection id sequence reused");
                    return;
                }
                if (retire_prior_to > item.retire_prior_to) {
                    item.retire_prior_to = retire_prior_to;
                    self.retirePeerCidsPriorTo(path_id, retire_prior_to);
                }
                return;
            }
            if (cid.len != 0 and ConnectionId.eql(item.cid, cid)) {
                self.close(true, transport_error_protocol_violation, "connection id reused across paths");
                return;
            }
        }

        self.retirePeerCidsPriorTo(path_id, retire_prior_to);
        const active_limit = self.local_transport_params.active_connection_id_limit;
        if (@as(u64, @intCast(self.peerCidActiveCountForPath(path_id))) >= active_limit) {
            self.close(true, transport_error_protocol_violation, "active connection id limit exceeded");
            return;
        }
        try self.peer_cids.append(self.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .cid = cid,
            .stateless_reset_token = stateless_reset_token,
        });
        if (self.paths.get(path_id)) |path| {
            if (path.path.peer_cid.len == 0 or sequence_number == 0) {
                path.path.peer_cid = cid;
            }
        }
        if (path_id == 0 and (self.peer_dcid.len == 0 or sequence_number == 0)) {
            self.peer_dcid = cid;
            self.peer_dcid_set = true;
        }
    }

    fn handleNewConnectionId(
        self: *Connection,
        nc: frame_types.NewConnectionId,
    ) Error!void {
        const cid = ConnectionId.fromSlice(nc.connection_id.slice());
        try self.registerPeerCid(0, nc.sequence_number, nc.retire_prior_to, cid, nc.stateless_reset_token);
    }

    fn handleRetireConnectionId(
        self: *Connection,
        rc: frame_types.RetireConnectionId,
    ) void {
        self.retireLocalCid(0, rc.sequence_number);
    }

    fn pathAckToAck(pa: frame_types.PathAck) frame_types.Ack {
        return .{
            .largest_acked = pa.largest_acked,
            .ack_delay = pa.ack_delay,
            .first_range = pa.first_range,
            .range_count = pa.range_count,
            .ranges_bytes = pa.ranges_bytes,
            .ecn_counts = pa.ecn_counts,
        };
    }

    fn handlePathAck(
        self: *Connection,
        pa: frame_types.PathAck,
        now_us: u64,
    ) Error!void {
        if (pa.path_id == 0) {
            return self.handleAckAtLevel(.application, pathAckToAck(pa), now_us);
        }
        const path = self.paths.get(pa.path_id) orelse return;
        try self.handleApplicationAckOnPath(path, pathAckToAck(pa), now_us);
    }

    fn handlePathAbandon(self: *Connection, pa: frame_types.PathAbandon) void {
        _ = pa.error_code;
        _ = self.paths.abandon(pa.path_id);
        self.retirePeerCidsForPath(pa.path_id);
        self.queuePathAbandon(pa.path_id, pa.error_code) catch {};
    }

    fn handlePathStatus(
        self: *Connection,
        ps: frame_types.PathStatus,
        available: bool,
    ) void {
        const path = self.paths.get(ps.path_id) orelse return;
        path.recordPeerStatus(available, ps.sequence_number);
    }

    fn handlePathNewConnectionId(
        self: *Connection,
        nc: frame_types.PathNewConnectionId,
    ) Error!void {
        const cid = ConnectionId.fromSlice(nc.connection_id.slice());
        try self.registerPeerCid(nc.path_id, nc.sequence_number, nc.retire_prior_to, cid, nc.stateless_reset_token);
    }

    fn handlePathRetireConnectionId(
        self: *Connection,
        rc: frame_types.PathRetireConnectionId,
    ) void {
        self.retireLocalCid(rc.path_id, rc.sequence_number);
    }

    fn handleMaxPathId(self: *Connection, mp: frame_types.MaxPathId) void {
        if (self.cached_peer_transport_params) |params| {
            if (params.initial_max_path_id) |initial_max_path_id| {
                if (mp.maximum_path_id < initial_max_path_id) {
                    self.close(true, transport_error_protocol_violation, "max path id below peer initial limit");
                    return;
                }
            }
        }
        if (mp.maximum_path_id > self.peer_max_path_id) {
            self.peer_max_path_id = mp.maximum_path_id;
        }
    }

    fn handlePathsBlocked(self: *Connection, pb: frame_types.PathsBlocked) void {
        if (!self.pathIdAllowedByLocalLimit(pb.maximum_path_id)) return;
        if (pb.maximum_path_id < self.local_max_path_id) return;
        self.peer_paths_blocked_at = pb.maximum_path_id;
    }

    fn handlePathCidsBlocked(self: *Connection, pcb: frame_types.PathCidsBlocked) void {
        if (!self.pathIdAllowedByLocalLimit(pcb.path_id)) return;
        const next = self.nextLocalCidSequence(pcb.path_id);
        if (pcb.next_sequence_number > next) {
            self.close(true, transport_error_protocol_violation, "path cids blocked skips local cid sequence");
            return;
        }
        self.peer_path_cids_blocked_path_id = pcb.path_id;
        self.peer_path_cids_blocked_next_sequence = pcb.next_sequence_number;
    }

    fn handleStopSending(
        self: *Connection,
        ss: frame_types.StopSending,
    ) Error!void {
        const ptr = self.streams.get(ss.stream_id) orelse return;
        try ptr.send.resetStream(ss.application_error_code);
    }

    fn handleDatagram(
        self: *Connection,
        lvl: EncryptionLevel,
        dg: frame_types.Datagram,
    ) Error!void {
        const copy = try self.allocator.alloc(u8, dg.data.len);
        errdefer self.allocator.free(copy);
        @memcpy(copy, dg.data);
        try self.pending_recv_datagrams.append(self.allocator, .{
            .data = copy,
            .arrived_in_early_data = lvl == .early_data,
        });
    }

    fn handleCrypto(
        self: *Connection,
        lvl: EncryptionLevel,
        cr: frame_types.Crypto,
    ) Error!void {
        const idx = lvl.idx();
        if (cr.data.len == 0) return;

        const start = cr.offset;
        const end = cr.offset + cr.data.len;
        const my_off = self.crypto_recv_offset[idx];

        // Already delivered → ignore (retransmit / overlap).
        if (end <= my_off) return;

        // Clip any prefix that was already delivered.
        const data_start: usize = if (start < my_off)
            @intCast(my_off - start)
        else
            0;
        const eff_offset: u64 = @max(start, my_off);
        const eff_data = cr.data[data_start..];

        if (eff_offset == my_off) {
            try self.inbox[idx].append(eff_data);
            self.crypto_recv_offset[idx] += eff_data.len;
            try self.drainPendingCrypto(idx);
        } else {
            // Out-of-order — buffer.
            const copy = try self.allocator.alloc(u8, eff_data.len);
            errdefer self.allocator.free(copy);
            @memcpy(copy, eff_data);
            try self.crypto_pending[idx].append(self.allocator, .{
                .offset = eff_offset,
                .data = copy,
            });
        }
    }

    fn drainPendingCrypto(self: *Connection, idx: usize) Error!void {
        // Repeatedly find a pending chunk that starts at our floor
        // (or below it, in which case we clip), deliver it, and
        // bump the floor — until no chunk matches.
        outer: while (self.crypto_pending[idx].items.len > 0) {
            const my_off = self.crypto_recv_offset[idx];
            var i: usize = 0;
            while (i < self.crypto_pending[idx].items.len) : (i += 1) {
                const chunk = self.crypto_pending[idx].items[i];
                const c_end = chunk.offset + chunk.data.len;
                if (c_end <= my_off) {
                    // Wholly below the floor — drop.
                    self.allocator.free(chunk.data);
                    _ = self.crypto_pending[idx].orderedRemove(i);
                    continue :outer;
                }
                if (chunk.offset <= my_off) {
                    // Bridges the floor — deliver the new portion.
                    const skip: usize = @intCast(my_off - chunk.offset);
                    const tail = chunk.data[skip..];
                    try self.inbox[idx].append(tail);
                    self.crypto_recv_offset[idx] += tail.len;
                    self.allocator.free(chunk.data);
                    _ = self.crypto_pending[idx].orderedRemove(i);
                    continue :outer;
                }
            }
            // No chunk reaches the floor → done.
            break;
        }
    }

    fn drainInboxIntoTls(self: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const idx = lvl.idx();
            if (self.inbox[idx].len > 0) {
                const bytes = self.inbox[idx].drain();
                try self.inner.provideQuicData(lvl.toBoringssl(), bytes);
                if (self.inner.handshakeDone()) {
                    try self.cachePeerTransportParams();
                    try self.inner.processQuicPostHandshake();
                } else {
                    try self.advanceHandshake();
                }
            }
        }
        if (!self.inner.handshakeDone()) try self.advanceHandshake();
        if (self.inner.handshakeDone()) try self.cachePeerTransportParams();
        try self.refreshEarlyDataStatus();
    }

    fn handleStream(
        self: *Connection,
        lvl: EncryptionLevel,
        s: frame_types.Stream,
    ) Error!void {
        const ptr = self.streams.get(s.stream_id) orelse blk: {
            const new_ptr = try self.allocator.create(Stream);
            errdefer self.allocator.destroy(new_ptr);
            new_ptr.* = .{
                .id = s.stream_id,
                .send = SendStream.init(self.allocator),
                .recv = RecvStream.init(self.allocator),
            };
            try self.streams.put(self.allocator, s.stream_id, new_ptr);
            break :blk new_ptr;
        };
        if (lvl == .early_data) ptr.arrived_in_early_data = true;
        try ptr.recv.recv(s.offset, s.data, s.fin);
    }

    fn handleResetStream(self: *Connection, rs: frame_types.ResetStream) Error!void {
        const ptr = self.streams.get(rs.stream_id) orelse return;
        try ptr.recv.resetStream(rs.application_error_code, rs.final_size);
    }

    fn handleAckAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        a: frame_types.Ack,
        now_us: u64,
    ) Error!void {
        // Walk ACK ranges and notify each PN at this level to:
        //   1. every open SendStream (application level only),
        //   2. the per-level SentPacketTracker.
        //
        // Phase 5b v1 walks streams brute-force per PN; a per-PN
        // side-table is the obvious next optimization.
        const pn_space = self.pnSpaceForLevel(lvl);
        const sent = self.sentForLevel(lvl);
        pn_space.onAckReceived(a.largest_acked);
        var largest_acked_send_time_us: ?u64 = null;
        var largest_acked_ack_eliciting = false;
        var any_ack_eliciting_newly_acked = false;
        var in_flight_bytes_acked: u64 = 0;
        var newest_acked_sent_time_us: u64 = 0;

        var ack_it = ack_range_mod.iter(a);
        while (try ack_it.next()) |interval| {
            var pn = interval.smallest;
            while (true) {
                if (sent.indexOf(pn)) |idx| {
                    var acked = sent.removeAt(idx);
                    defer acked.deinit(self.allocator);
                    if (acked.pn == a.largest_acked) {
                        largest_acked_send_time_us = acked.sent_time_us;
                        largest_acked_ack_eliciting = acked.ack_eliciting;
                    }
                    if (acked.ack_eliciting) any_ack_eliciting_newly_acked = true;
                    if (acked.in_flight) {
                        in_flight_bytes_acked += acked.bytes;
                        if (acked.sent_time_us > newest_acked_sent_time_us) {
                            newest_acked_sent_time_us = acked.sent_time_us;
                        }
                    }
                    if (lvl == .application) {
                        if (acked.stream_key) |stream_key| {
                            self.dispatchAckedToStreams(stream_key) catch |e| return e;
                        }
                    }
                    self.discardSentCryptoForPacket(lvl, acked.pn);
                    self.dispatchAckedControlFrames(&acked);
                }
                if (pn == interval.largest) break;
                pn += 1;
            }
        }
        if (largest_acked_send_time_us) |sent_time_us| {
            if (largest_acked_ack_eliciting and now_us >= sent_time_us) {
                const ack_delay_us = a.ack_delay << self.peerAckDelayExponent();
                self.rttForLevel(lvl).update(
                    now_us - sent_time_us,
                    ack_delay_us,
                    self.handshakeDone(),
                    self.peerMaxAckDelayUs(),
                );
            }
        }
        if (any_ack_eliciting_newly_acked) self.ptoCountForLevel(lvl).* = 0;
        if (in_flight_bytes_acked > 0) {
            if (lvl == .application) {
                self.ccForApplication().onPacketAcked(in_flight_bytes_acked, newest_acked_sent_time_us);
            }
        }

        // Loss detection at the same level — packet-threshold only
        // (time-threshold lives in `tick`).
        try self.detectLossesByPacketThresholdAtLevel(lvl);
    }

    fn handleApplicationAckOnPath(
        self: *Connection,
        path: *PathState,
        a: frame_types.Ack,
        now_us: u64,
    ) Error!void {
        path.app_pn_space.onAckReceived(a.largest_acked);
        var largest_acked_send_time_us: ?u64 = null;
        var largest_acked_ack_eliciting = false;
        var any_ack_eliciting_newly_acked = false;
        var in_flight_bytes_acked: u64 = 0;
        var newest_acked_sent_time_us: u64 = 0;

        var ack_it = ack_range_mod.iter(a);
        while (try ack_it.next()) |interval| {
            var pn = interval.smallest;
            while (true) {
                if (path.sent.indexOf(pn)) |idx| {
                    var acked = path.sent.removeAt(idx);
                    defer acked.deinit(self.allocator);
                    if (acked.pn == a.largest_acked) {
                        largest_acked_send_time_us = acked.sent_time_us;
                        largest_acked_ack_eliciting = acked.ack_eliciting;
                    }
                    if (acked.ack_eliciting) any_ack_eliciting_newly_acked = true;
                    if (acked.in_flight) {
                        in_flight_bytes_acked += acked.bytes;
                        if (acked.sent_time_us > newest_acked_sent_time_us) {
                            newest_acked_sent_time_us = acked.sent_time_us;
                        }
                    }
                    if (acked.stream_key) |stream_key| {
                        self.dispatchAckedToStreams(stream_key) catch |e| return e;
                    }
                    self.discardSentCryptoForPacket(.application, acked.pn);
                    self.dispatchAckedControlFrames(&acked);
                }
                if (pn == interval.largest) break;
                pn += 1;
            }
        }
        if (largest_acked_send_time_us) |sent_time_us| {
            if (largest_acked_ack_eliciting and now_us >= sent_time_us) {
                const ack_delay_us = a.ack_delay << self.peerAckDelayExponent();
                path.path.rtt.update(
                    now_us - sent_time_us,
                    ack_delay_us,
                    self.handshakeDone(),
                    self.peerMaxAckDelayUs(),
                );
            }
        }
        if (any_ack_eliciting_newly_acked) path.pto_count = 0;
        if (in_flight_bytes_acked > 0) {
            path.path.cc.onPacketAcked(in_flight_bytes_acked, newest_acked_sent_time_us);
        }

        try self.detectLossesByPacketThresholdOnApplicationPath(path);
    }

    fn dispatchAckedToStreams(self: *Connection, pn: u64) Error!void {
        var s_it = self.streams.iterator();
        while (s_it.next()) |entry| {
            entry.value_ptr.*.send.onPacketAcked(pn) catch |e| switch (e) {
                send_stream_mod.Error.UnknownPacket => {},
                else => return e,
            };
        }
    }

    fn dispatchLostToStreams(self: *Connection, pn: u64) Error!bool {
        var any = false;
        var s_it = self.streams.iterator();
        while (s_it.next()) |entry| {
            entry.value_ptr.*.send.onPacketLost(pn) catch |e| switch (e) {
                send_stream_mod.Error.UnknownPacket => continue,
                else => return e,
            };
            any = true;
        }
        return any;
    }

    fn discardSentCryptoForPacket(
        self: *Connection,
        lvl: EncryptionLevel,
        pn: u64,
    ) void {
        const idx = lvl.idx();
        var i: usize = 0;
        while (i < self.sent_crypto[idx].items.len) {
            const chunk = self.sent_crypto[idx].items[i];
            if (chunk.pn == pn) {
                const removed = self.sent_crypto[idx].orderedRemove(i);
                self.allocator.free(removed.data);
                continue;
            }
            i += 1;
        }
    }

    fn requeueSentCryptoForPacket(
        self: *Connection,
        lvl: EncryptionLevel,
        pn: u64,
    ) Error!bool {
        const idx = lvl.idx();
        var any = false;
        var i: usize = 0;
        while (i < self.sent_crypto[idx].items.len) {
            const chunk = self.sent_crypto[idx].items[i];
            if (chunk.pn == pn) {
                try self.crypto_retx[idx].ensureUnusedCapacity(self.allocator, 1);
                const removed = self.sent_crypto[idx].orderedRemove(i);
                self.crypto_retx[idx].appendAssumeCapacity(.{
                    .offset = removed.offset,
                    .data = removed.data,
                });
                any = true;
                continue;
            }
            i += 1;
        }
        return any;
    }

    fn dispatchAckedControlFrames(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) void {
        for (packet.retransmit_frames.items) |frame| {
            switch (frame) {
                .reset_stream => |rs| {
                    const s = self.streams.get(rs.stream_id) orelse continue;
                    if (s.send.reset) |r| {
                        if (r.error_code == rs.application_error_code and
                            r.final_size == rs.final_size)
                        {
                            s.send.onResetAcked();
                        }
                    }
                },
                else => {},
            }
        }
    }

    fn dispatchLostControlFrames(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        var any = false;
        for (packet.retransmit_frames.items) |frame| {
            switch (frame) {
                .max_data => |md| {
                    self.queueMaxData(md.maximum_data);
                    any = true;
                },
                .max_stream_data => |msd| {
                    try self.queueMaxStreamData(
                        msd.stream_id,
                        msd.maximum_stream_data,
                    );
                    any = true;
                },
                .new_connection_id => |nc| {
                    try self.queueNewConnectionId(
                        nc.sequence_number,
                        nc.retire_prior_to,
                        nc.connection_id.slice(),
                        nc.stateless_reset_token,
                    );
                    any = true;
                },
                .stop_sending => |ss| {
                    try self.queueStopSending(.{
                        .stream_id = ss.stream_id,
                        .application_error_code = ss.application_error_code,
                    });
                    any = true;
                },
                .path_response => |pr| {
                    if (self.pending_path_response == null) {
                        self.pending_path_response = pr.data;
                    }
                    any = true;
                },
                .path_challenge => |pc| {
                    if (self.pending_path_challenge == null) {
                        self.pending_path_challenge = pc.data;
                    }
                    any = true;
                },
                .reset_stream => |rs| {
                    const s = self.streams.get(rs.stream_id) orelse continue;
                    if (s.send.reset) |r| {
                        if (r.error_code == rs.application_error_code and
                            r.final_size == rs.final_size)
                        {
                            s.send.onResetLost();
                        }
                    }
                    any = true;
                },
                .path_abandon => |pa| {
                    try self.queuePathAbandon(pa.path_id, pa.error_code);
                    any = true;
                },
                .path_status_backup => |ps| {
                    try self.queuePathStatus(ps.path_id, false, ps.sequence_number);
                    any = true;
                },
                .path_status_available => |ps| {
                    try self.queuePathStatus(ps.path_id, true, ps.sequence_number);
                    any = true;
                },
                .path_new_connection_id => |nc| {
                    try self.queuePathNewConnectionId(
                        nc.path_id,
                        nc.sequence_number,
                        nc.retire_prior_to,
                        nc.connection_id.slice(),
                        nc.stateless_reset_token,
                    );
                    any = true;
                },
                .path_retire_connection_id => |rc| {
                    try self.queuePathRetireConnectionId(rc.path_id, rc.sequence_number);
                    any = true;
                },
                .max_path_id => |mp| {
                    self.queueMaxPathId(mp.maximum_path_id);
                    any = true;
                },
                .paths_blocked => |pb| {
                    self.queuePathsBlocked(pb.maximum_path_id);
                    any = true;
                },
                .path_cids_blocked => |pcb| {
                    self.queuePathCidsBlocked(pcb.path_id, pcb.next_sequence_number);
                    any = true;
                },
            }
        }
        return any;
    }

    fn requeueLostPacket(
        self: *Connection,
        lvl: EncryptionLevel,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        var any = false;
        if (lvl == .application) {
            if (packet.stream_key) |stream_key| {
                any = (try self.dispatchLostToStreams(stream_key)) or any;
            }
        }
        any = (try self.requeueSentCryptoForPacket(lvl, packet.pn)) or any;
        any = (try self.dispatchLostControlFrames(packet)) or any;
        return any;
    }

    fn isPersistentCongestionFromBasePto(base_pto_us: u64, stats: LossStats) bool {
        const earliest = stats.earliest_lost_sent_time_us orelse return false;
        if (stats.count < 2 or stats.largest_lost_sent_time_us <= earliest) return false;
        const duration = stats.largest_lost_sent_time_us - earliest;
        const threshold = base_pto_us *
            congestion_mod.persistent_congestion_threshold;
        return duration >= threshold;
    }

    fn isPersistentCongestion(
        self: *const Connection,
        lvl: EncryptionLevel,
        stats: LossStats,
    ) bool {
        return isPersistentCongestionFromBasePto(
            self.basePtoDurationForLevel(lvl),
            stats,
        );
    }

    fn onPacketsLostAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        stats: LossStats,
    ) void {
        if (stats.in_flight_bytes_lost == 0) return;
        if (lvl == .application) {
            const cc = self.ccForApplication();
            cc.onPacketLost(
                stats.in_flight_bytes_lost,
                stats.largest_lost_sent_time_us,
            );
            if (self.isPersistentCongestion(lvl, stats)) {
                cc.onPersistentCongestion();
            }
        }
    }

    fn onApplicationPathPacketsLost(
        self: *Connection,
        path: *PathState,
        stats: LossStats,
    ) void {
        if (stats.in_flight_bytes_lost == 0) return;
        path.path.cc.onPacketLost(
            stats.in_flight_bytes_lost,
            stats.largest_lost_sent_time_us,
        );
        if (isPersistentCongestionFromBasePto(
            self.basePtoDurationForApplicationPath(path),
            stats,
        )) {
            path.path.cc.onPersistentCongestion();
        }
    }

    fn detectLossesByPacketThresholdAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
    ) Error!void {
        const pn_space = self.pnSpaceForLevel(lvl);
        const sent = self.sentForLevel(lvl);
        const largest_acked_opt = pn_space.largest_acked_sent;
        if (largest_acked_opt == null) return;
        const largest_acked = largest_acked_opt.?;
        const threshold: u64 = loss_recovery_mod.packet_threshold;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < sent.count) {
            const p = sent.packets[i];
            if (p.pn <= largest_acked and (largest_acked - p.pn) >= threshold) {
                var lost = sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                _ = try self.requeueLostPacket(lvl, &lost);
                continue;
            }
            i += 1;
        }
        self.onPacketsLostAtLevel(lvl, stats);
    }

    fn detectLossesByPacketThresholdOnApplicationPath(
        self: *Connection,
        path: *PathState,
    ) Error!void {
        const largest_acked_opt = path.app_pn_space.largest_acked_sent;
        if (largest_acked_opt == null) return;
        const largest_acked = largest_acked_opt.?;
        const threshold: u64 = loss_recovery_mod.packet_threshold;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < path.sent.count) {
            const p = path.sent.packets[i];
            if (p.pn <= largest_acked and (largest_acked - p.pn) >= threshold) {
                var lost = path.sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                _ = try self.requeueLostPacket(.application, &lost);
                continue;
            }
            i += 1;
        }
        self.onApplicationPathPacketsLost(path, stats);
    }

    fn detectLossesByTimeThresholdAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        now_us: u64,
    ) Error!void {
        const rtt = self.rttForLevelConst(lvl);
        const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );
        if (now_us <= time_threshold) return;
        const cutoff = now_us - time_threshold;
        const pn_space = self.pnSpaceForLevel(lvl);
        const sent = self.sentForLevel(lvl);
        const largest_acked_opt = pn_space.largest_acked_sent;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < sent.count) {
            const p = sent.packets[i];
            const eligible = if (largest_acked_opt) |la| p.pn <= la else false;
            if (eligible and p.sent_time_us < cutoff) {
                var lost = sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                _ = try self.requeueLostPacket(lvl, &lost);
                continue;
            }
            i += 1;
        }
        self.onPacketsLostAtLevel(lvl, stats);
    }

    fn detectLossesByTimeThresholdOnApplicationPath(
        self: *Connection,
        path: *PathState,
        now_us: u64,
    ) Error!void {
        const rtt = &path.path.rtt;
        const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
        const time_threshold = @max(
            reference_rtt * loss_recovery_mod.time_threshold_num /
                loss_recovery_mod.time_threshold_den,
            rtt_mod.granularity_us,
        );
        if (now_us <= time_threshold) return;
        const cutoff = now_us - time_threshold;
        const largest_acked_opt = path.app_pn_space.largest_acked_sent;

        var i: u32 = 0;
        var stats: LossStats = .{};
        while (i < path.sent.count) {
            const p = path.sent.packets[i];
            const eligible = if (largest_acked_opt) |la| p.pn <= la else false;
            if (eligible and p.sent_time_us < cutoff) {
                var lost = path.sent.removeAt(i);
                defer lost.deinit(self.allocator);
                stats.add(lost);
                _ = try self.requeueLostPacket(.application, &lost);
                continue;
            }
            i += 1;
        }
        self.onApplicationPathPacketsLost(path, stats);
    }

    fn firePtoAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
    ) Error!bool {
        const sent = self.sentForLevel(lvl);
        var i: u32 = 0;
        while (i < sent.count) : (i += 1) {
            const p = sent.packets[i];
            if (!p.ack_eliciting) continue;

            var lost = sent.removeAt(i);
            defer lost.deinit(self.allocator);
            var stats: LossStats = .{};
            stats.add(lost);
            const requeued = try self.requeueLostPacket(lvl, &lost);
            self.onPacketsLostAtLevel(lvl, stats);

            self.pendingPingForLevel(lvl).* = !requeued;
            self.ptoCountForLevel(lvl).* +|= 1;
            return true;
        }
        return false;
    }

    fn firePtoOnApplicationPath(
        self: *Connection,
        path: *PathState,
    ) Error!bool {
        var i: u32 = 0;
        while (i < path.sent.count) : (i += 1) {
            const p = path.sent.packets[i];
            if (!p.ack_eliciting) continue;

            var lost = path.sent.removeAt(i);
            defer lost.deinit(self.allocator);
            var stats: LossStats = .{};
            stats.add(lost);
            const requeued = try self.requeueLostPacket(.application, &lost);
            self.onApplicationPathPacketsLost(path, stats);

            path.pending_ping = !requeued;
            path.pto_count +|= 1;
            return true;
        }
        return false;
    }

    fn fireDuePtoAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        now_us: u64,
    ) Error!void {
        const deadline = self.ptoDeadlineForLevel(lvl) orelse return;
        if (now_us < deadline) return;
        _ = try self.firePtoAtLevel(lvl);
    }

    fn fireDuePtoOnApplicationPath(
        self: *Connection,
        path: *PathState,
        now_us: u64,
    ) Error!void {
        const deadline = self.ptoDeadlineForApplicationPath(path) orelse return;
        if (now_us < deadline) return;
        _ = try self.firePtoOnApplicationPath(path);
    }

    /// Periodic tick — drives time-based loss detection, PTO,
    /// idle timeout, and draining deadlines. The caller passes the
    /// current monotonic time in microseconds. Safe to call any time.
    pub fn tick(self: *Connection, now_us: u64) Error!void {
        for (self.paths.paths.items) |*p| p.path.validator.tick(now_us);

        if (self.draining_deadline_us) |deadline| {
            if (now_us >= deadline) {
                self.pending_close = null;
                self.clearPendingPings();
            }
            return;
        }

        if (!self.closed) {
            if (self.idleDeadline()) |deadline| {
                if (now_us >= deadline) {
                    self.closed = true;
                    self.draining_deadline_us = now_us +| self.drainingDurationUs();
                    return;
                }
            }
        }

        try self.detectLossesByTimeThresholdAtLevel(.initial, now_us);
        try self.detectLossesByTimeThresholdAtLevel(.handshake, now_us);
        for (self.paths.paths.items) |*path| {
            try self.detectLossesByTimeThresholdOnApplicationPath(path, now_us);
        }

        try self.fireDuePtoAtLevel(.initial, now_us);
        try self.fireDuePtoAtLevel(.handshake, now_us);
        for (self.paths.paths.items) |*path| {
            try self.fireDuePtoOnApplicationPath(path, now_us);
        }
    }

    /// One handshake driver step:
    /// 1. For each encryption level (low → high), if there are
    ///    queued bytes from the peer, feed them in via
    ///    `provideQuicData` and advance the handshake. (Per-level
    ///    feeding is required because keys for level N+1 are
    ///    derived during processing of level N.)
    /// 2. After all queued levels are drained, make one more
    ///    handshake call in case there's outgoing-only progress
    ///    (e.g. the very first client step that emits ClientHello).
    /// 3. If the handshake is done and `application`-level bytes
    ///    are pending (post-handshake messages such as
    ///    NewSessionTicket), call `processQuicPostHandshake`.
    pub fn advance(self: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const idx = lvl.idx();
            if (self.inbox[idx].len > 0) {
                const bytes = self.inbox[idx].drain();
                try self.inner.provideQuicData(lvl.toBoringssl(), bytes);
                if (self.inner.handshakeDone()) {
                    try self.cachePeerTransportParams();
                    try self.inner.processQuicPostHandshake();
                } else {
                    try self.advanceHandshake();
                }
            }
        }
        if (!self.inner.handshakeDone()) try self.advanceHandshake();
        if (self.inner.handshakeDone()) try self.cachePeerTransportParams();
        try self.refreshEarlyDataStatus();
        // Phase-4 in-process compatibility: shuttle outbox→peer.inbox
        // so the existing handshake test still works while the real
        // datagram-driven path is being built up.
        if (self.peer) |peer| try self.shuttleOutboxToPeer(peer);
        if (self.alert) |_| return error.PeerAlerted;
    }

    fn shuttleOutboxToPeer(self: *Connection, peer: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const i = lvl.idx();
            if (self.outbox[i].len > 0) {
                const bytes = self.outbox[i].drain();
                try peer.inbox[i].append(bytes);
                self.crypto_send_offset[i] += bytes.len;
            }
        }
    }

    fn advanceHandshake(self: *Connection) Error!void {
        self.inner.handshake() catch |e| switch (e) {
            error.WantRead, error.WantWrite => {},
            else => return e,
        };
    }
};

// -- tls.quic.Method bridge ---------------------------------------------
//
// Each callback recovers the *Connection from the SSL via ex-data,
// then writes into nullq state. The trampolines stay in this module
// because they reach into Connection's private fields directly.

fn setReadSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
) callconv(.c) c_int {
    return setSecret(ssl, level, cipher, secret, secret_len, .read);
}

fn setWriteSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
) callconv(.c) c_int {
    return setSecret(ssl, level, cipher, secret, secret_len, .write);
}

fn setSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
    dir: Direction,
) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    if (secret_len > 64) return 0;
    const cipher_id: u16 = blk: {
        if (cipher) |cph| {
            break :blk c.zbssl_SSL_CIPHER_get_protocol_id(cph);
        } else {
            break :blk 0;
        }
    };

    var material: SecretMaterial = .{ .cipher_protocol_id = cipher_id };
    @memcpy(material.secret[0..secret_len], secret[0..secret_len]);
    material.secret_len = @intCast(secret_len);

    const lvl = EncryptionLevel.fromBoringssl(@enumFromInt(level));
    switch (dir) {
        .read => {
            conn.levels[lvl.idx()].read = material;
            if (lvl == .application) {
                conn.app_read_key_phase = false;
                conn.app_read_hp = null;
            }
        },
        .write => {
            conn.levels[lvl.idx()].write = material;
            if (lvl == .application) {
                conn.app_write_key_phase = false;
                conn.app_write_hp = null;
            }
        },
    }
    return 1;
}

fn addHandshakeData(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    data: [*c]const u8,
    len: usize,
) callconv(.c) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    const lvl = EncryptionLevel.fromBoringssl(@enumFromInt(level));
    // Buffer outgoing CRYPTO bytes per level. `poll` packs them into
    // CRYPTO frames inside Initial/Handshake/1-RTT packets — that's
    // the wire-level handshake path. The legacy in-process Phase-4
    // test path additionally has `advance` shuttle outbox→peer.inbox
    // when `peer` is set.
    conn.outbox[lvl.idx()].append(data[0..len]) catch return 0;
    return 1;
}

fn flushFlight(_: ?*c.SSL) callconv(.c) c_int {
    return 1;
}

fn sendAlert(
    ssl: ?*c.SSL,
    _: c.ssl_encryption_level_t,
    alert: u8,
) callconv(.c) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    conn.alert = alert;
    return 1;
}

fn connFromSsl(ssl: ?*c.SSL) ?*Connection {
    const ssl_ptr = ssl orelse return null;
    const raw_ptr = boringssl.tls.Conn.userDataFromSsl(ssl_ptr) orelse return null;
    return @ptrCast(@alignCast(raw_ptr));
}

const method: boringssl.tls.quic.Method = .{
    .set_read_secret = setReadSecret,
    .set_write_secret = setWriteSecret,
    .add_handshake_data = addHandshakeData,
    .flush_flight = flushFlight,
    .send_alert = sendAlert,
};

fn installMethod(conn: *Connection) !void {
    try conn.inner.setUserData(conn);
    try conn.inner.setQuicMethod(&method);
}

// -- tests ---------------------------------------------------------------

test "EncryptionLevel idx round-trip" {
    inline for (level_mod.all) |lvl| {
        try std.testing.expectEqual(lvl.idx(), @intFromEnum(lvl));
    }
}

test "CRYPTO reassembly: out-of-order fragments delivered in order" {
    // Tests the same shape quic-go sends on the wire: a high-offset
    // fragment first, then the low-offset fragment, then a tiny
    // bridge fragment, then the tail.
    const allocator = std.testing.allocator;

    // We don't need a real Connection for this — we exercise the
    // reassembly machinery via a bare struct that holds the same
    // fields. Cleaner: use a real Connection but skip TLS bring-up.
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();

    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    // Don't bind/handshake — we're only testing reassembly, which
    // doesn't need TLS.

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();

    // First fragment: out-of-order high range.
    try conn.handleCrypto(lvl, .{ .offset = 69, .data = "BBBBBBBB" });
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_pending[idx].items.len);

    // Second fragment: in-order low range — delivers immediately.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "AAAAAAAAAAA" }); // 11 bytes
    try std.testing.expectEqual(@as(u64, 11), conn.crypto_recv_offset[idx]);

    // Third fragment: bridges the gap [11, 69) — delivers, then
    // drains the pending [69, 77).
    var bridge: [58]u8 = @splat('M');
    try conn.handleCrypto(lvl, .{ .offset = 11, .data = &bridge });
    try std.testing.expectEqual(@as(u64, 77), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[idx].items.len);

    // Inbox should have all 77 bytes in the right order.
    try std.testing.expectEqual(@as(usize, 77), conn.inbox[idx].len);
    try std.testing.expectEqualSlices(u8, "AAAAAAAAAAA", conn.inbox[idx].buf[0..11]);
    for (conn.inbox[idx].buf[11..69]) |b| try std.testing.expectEqual(@as(u8, 'M'), b);
    try std.testing.expectEqualSlices(u8, "BBBBBBBB", conn.inbox[idx].buf[69..77]);
}

test "CRYPTO reassembly: duplicate fragment is silently ignored" {
    const allocator = std.testing.allocator;
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);

    // Retransmit of the same range — should be a no-op.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 6), conn.inbox[idx].len);

    // Partial overlap (offset=3 covers bytes already delivered + new).
    try conn.handleCrypto(lvl, .{ .offset = 3, .data = "defGHI" });
    try std.testing.expectEqual(@as(u64, 9), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqualSlices(u8, "abcdefGHI", conn.inbox[idx].buf[0..9]);
}

test "timer deadline reports ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    conn.pnSpaceForLevel(.application).recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "PTO requeues application stream data and arms a probe" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");
    const chunk = s.send.peekChunk(100).?;
    try s.send.recordSent(4, chunk);
    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 4,
        .sent_time_us = 0,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_key = 4,
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(u32, 0), app_sent.count);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
    const resent = s.send.peekChunk(100).?;
    try std.testing.expectEqual(@as(u64, 0), resent.offset);
    try std.testing.expectEqual(@as(u64, 5), resent.length);
}

test "PTO requeues retransmittable control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 8,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .max_data = .{ .maximum_data = 4096 } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(?u64, 4096), conn.pending_max_data);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "poll helper emits one draft multipath control frame with retransmit metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.queuePathStatus(2, false, 7);
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    defer packet.deinit(allocator);
    var payload: [default_mtu]u8 = undefined;
    var pos: usize = 0;

    try std.testing.expect(try conn.emitOnePendingMultipathFrame(&packet, &payload, &pos, default_mtu));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_statuses.items.len);
    try std.testing.expectEqual(@as(usize, 1), packet.retransmit_frames.items.len);
    try std.testing.expect(packet.retransmit_frames.items[0] == .path_status_backup);

    const decoded = try frame_mod.decode(payload[0..pos]);
    try std.testing.expect(decoded.frame == .path_status_backup);
    try std.testing.expectEqual(@as(u32, 2), decoded.frame.path_status_backup.path_id);
    try std.testing.expectEqual(@as(u64, 7), decoded.frame.path_status_backup.sequence_number);
}

test "PTO requeues retransmittable draft multipath control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 11,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = 3,
        .error_code = 99,
    } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_abandons.items.len);
    try std.testing.expectEqual(@as(u32, 3), conn.pending_path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_path_abandons.items[0].error_code);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "PTO arms PING when no retransmittable data can be requeued" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 9,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expect(conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
}

test "PTO requeues CRYPTO bytes at original offsets" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const level: EncryptionLevel = .initial;
    const level_idx = level.idx();
    const bytes = try allocator.dupe(u8, "crypto-fragment");
    var bytes_moved = false;
    errdefer if (!bytes_moved) allocator.free(bytes);
    try conn.sent_crypto[level_idx].append(allocator, .{
        .pn = 2,
        .offset = 123,
        .data = bytes,
    });
    bytes_moved = true;
    try conn.sentForLevel(level).record(.{
        .pn = 2,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(level));

    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[level_idx].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[level_idx].items.len);
    try std.testing.expectEqual(@as(u64, 123), conn.crypto_retx[level_idx].items[0].offset);
    try std.testing.expectEqualStrings("crypto-fragment", conn.crypto_retx[level_idx].items[0].data);
}

test "ACK of ack-eliciting packet resets PTO count and updates RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ptoCountForLevel(.application).* = 3;
    try conn.sentForLevel(.application).record(.{
        .pn = 11,
        .sent_time_us = 1_000_000,
        .bytes = 120,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 11,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), conn.ptoCountForLevel(.application).*);
    try std.testing.expectEqual(@as(u64, 50_000), conn.rttForLevel(.application).latest_rtt_us);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).count);
}

test "ACKed in-flight packets grow congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const initial_cwnd = conn.congestionWindow();
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_010_000);

    try std.testing.expect(conn.congestionWindow() > initial_cwnd);
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "packet-threshold loss reduces congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const initial_cwnd = conn.congestionWindow();
    var pn: u64 = 0;
    while (pn <= 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 1_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 4,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 50_000);

    try std.testing.expect(conn.congestionWindow() < initial_cwnd);
    try std.testing.expect(conn.ccForApplication().ssthresh != null);
}

test "persistent congestion resets congestion window to minimum" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ccForApplication().cwnd = 30_000;
    conn.rttForLevel(.application).smoothed_rtt_us = 10_000;
    conn.rttForLevel(.application).latest_rtt_us = 10_000;
    conn.rttForLevel(.application).rtt_var_us = 1_000;
    conn.rttForLevel(.application).first_sample_taken = true;

    conn.pnSpaceForLevel(.application).largest_acked_sent = 10;
    var pn: u64 = 0;
    while (pn < 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 100_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    try conn.tick(1_000_000);

    try std.testing.expectEqual(conn.ccForApplication().cfg.minWindow(), conn.congestionWindow());
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "congestionBlocked gates application data but allows PTO probes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.ccForApplication().cwnd = 1200;
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try std.testing.expect(conn.congestionBlocked(.application));
    try std.testing.expect(!conn.congestionBlocked(.initial));
    conn.pendingPingForLevel(.application).* = true;
    try std.testing.expect(!conn.congestionBlocked(.application));
}

test "PathSet API exposes path lifecycle and application recovery state" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.enableMultipath(true);
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
    const initial = conn.pathStats(0).?;
    try std.testing.expect(initial.validated);
    try std.testing.expectEqual(@as(u64, 0), initial.bytes_in_flight);

    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    const after_send = conn.pathStats(0).?;
    try std.testing.expectEqual(@as(u64, 1200), after_send.bytes_in_flight);

    const id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    try std.testing.expectEqual(@as(u32, 1), id);
    try std.testing.expect(conn.setActivePath(id));
    try std.testing.expectEqual(id, conn.activePathId());
    try std.testing.expect(conn.markPathValidated(id));
    try std.testing.expect(conn.pathStats(id).?.validated);
    try std.testing.expect(conn.setPathBackup(id, true));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_statuses.items.len);
    try std.testing.expect(!conn.pending_path_statuses.items[0].available);
    conn.setScheduler(.round_robin);
    try std.testing.expect(conn.abandonPath(id));
    try std.testing.expectEqual(path_mod.State.retiring, conn.pathStats(id).?.state);
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
}

test "PATH_ACK routes ACK processing to the indicated application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    const path = conn.paths.get(path_id).?;
    try path.sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.handlePathAck(.{
        .path_id = path_id,
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expectEqual(@as(u64, 0), path.sent.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.largest_acked_sent);
    try std.testing.expectEqual(@as(u64, 50_000), path.path.rtt.latest_rtt_us);
}

fn installTestApplicationWriteSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.application.idx()].write = material;
}

fn installTestApplicationReadSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.application.idx()].read = material;
}

fn installTestEarlyDataWriteSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].write = material;
}

fn installTestEarlyDataReadSecret(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.early_data.idx()].read = material;
}

fn testEarlyDataPacketKeys() !PacketKeys {
    const secret: [32]u8 = @splat(0);
    return try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &secret);
}

fn markTestMultipathNegotiated(conn: *Connection, max_path_id: u32) void {
    conn.enableMultipath(true);
    conn.local_transport_params.initial_max_path_id = max_path_id;
    conn.local_max_path_id = max_path_id;
    conn.cached_peer_transport_params = .{ .initial_max_path_id = max_path_id };
    conn.peer_max_path_id = max_path_id;
}

test "0-RTT send path requires explicit per-connection opt-in" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.pollLevel(.early_data, &out, 1_000));
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
}

test "0-RTT poll emits long-header packet in Application PN space" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    const n = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expect(n > 0);
    try std.testing.expect((out[0] & 0x80) != 0);
    try std.testing.expectEqual(@as(u2, 1), @as(u2, @intCast((out[0] >> 4) & 0x03)));
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);
    try std.testing.expect(conn.sentForLevel(.early_data).packets[0].is_early_data);
    try std.testing.expectEqual(@as(u64, 1), conn.pnSpaceForLevel(.early_data).next_pn);
}

test "server handles accepted 0-RTT STREAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "hello",
        .has_offset = false,
        .has_length = true,
        .fin = false,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);
    try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.pending_ack);

    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try conn.streamRead(0, &buf));
    try std.testing.expectEqualSlices(u8, "hello", buf[0..5]);
    try std.testing.expectEqual(true, conn.streamArrivedInEarlyData(0).?);
}

test "server marks accepted 0-RTT DATAGRAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .datagram = .{
        .data = "early-dgram",
        .has_length = true,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);

    var buf: [32]u8 = undefined;
    const info = conn.receiveDatagramInfo(&buf).?;
    try std.testing.expectEqual(@as(usize, 11), info.len);
    try std.testing.expect(info.arrived_in_early_data);
    try std.testing.expectEqualSlices(u8, "early-dgram", buf[0..info.len]);
}

test "server rejects forbidden frames in 0-RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    const keys = try testEarlyDataPacketKeys();

    var payload: [32]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ack = .{
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    _ = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
    try std.testing.expectEqualStrings("forbidden frame in 0-RTT", conn.pending_close.?.reason);
}

test "pollLevel emits PATH_ACK for non-zero application path ACKs" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    try std.testing.expect(!path.app_pn_space.received.pending_ack);
    try std.testing.expectEqual(@as(u32, 1), path.sent.count);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
    try std.testing.expectEqual(@as(u64, 9), decoded.frame.path_ack.largest_acked);
}

test "pollDatagram can select a non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{ .bytes = .{ 1, 2, 3, 4 } ++ .{0} ** 18 }, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.setActivePath(path_id));
    try conn.queuePathStatus(path_id, true, 1);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(path_id, datagram.path_id);
    try std.testing.expect(datagram.to != null);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_statuses.items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.paths.get(path_id).?.sent.count);
}

test "multipath-negotiated non-zero path packets use draft-21 nonce" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    const keys = (try conn.packetKeys(.application, .write)).?;
    var plaintext: [max_recv_plaintext]u8 = undefined;

    try std.testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
            .dcid_len = 1,
            .keys = &keys,
            .largest_received = 0,
        }),
    );
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
        .multipath_path_id = path_id,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
}

test "incoming short packets are routed by local CID before multipath nonce open" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    installTestApplicationReadSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setLocalScid(&.{0xa0});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    const path = conn.paths.get(path_id).?;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = path.path.local_cid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
        .multipath_path_id = path_id,
    });

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expectEqual(path_id, conn.current_incoming_path_id);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.received.largest);
    try std.testing.expectEqual(@as(?u64, null), conn.primaryPath().app_pn_space.received.largest);
}

test "queued path CIDs participate in incoming short-header routing and retirement" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try conn.queuePathNewConnectionId(path_id, 1, 0, &.{0xc2}, @splat(0));

    const bytes = [_]u8{ 0x40, 0xc2, 0, 0, 0, 0 } ++ [_]u8{0} ** 16;
    try std.testing.expectEqual(path_id, conn.incomingShortPath(&bytes).?.id);

    conn.handlePathRetireConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
    });
    try std.testing.expect(conn.incomingShortPath(&bytes) == null);
}

test "multipath frames are rejected unless draft-21 was negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .max_path_id = .{ .maximum_path_id = 1 } });
    try conn.dispatchFrames(.application, payload[0..payload_len], 1_000_000);
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "setTransportParams advertises local multipath limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .initial_max_path_id = 2 });
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 2), conn.local_max_path_id);
}

test "openPath respects peer MAX_PATH_ID when multipath is negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    _ = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc2}), ConnectionId.fromSlice(&.{0xd2})),
    );
    try std.testing.expectEqual(@as(?u32, 1), conn.pending_paths_blocked);
}

test "PATH_NEW_CONNECTION_ID rejects sequence reuse with different cid" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "PATH_NEW_CONNECTION_ID rejects path ids above local limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    try conn.handlePathNewConnectionId(.{
        .path_id = 2,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "MAX_PATH_ID cannot reduce the peer initial path limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    conn.handleMaxPathId(.{ .maximum_path_id = 1 });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "PATH_CIDS_BLOCKED cannot skip local cid sequence numbers" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    conn.handlePathCidsBlocked(.{ .path_id = path_id, .next_sequence_number = 2 });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "PATHS_BLOCKED below current local limit is ignored" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    conn.handlePathsBlocked(.{ .maximum_path_id = 1 });
    try std.testing.expectEqual(@as(?u32, null), conn.peer_paths_blocked_at);
    conn.handlePathsBlocked(.{ .maximum_path_id = 2 });
    try std.testing.expectEqual(@as(?u32, 2), conn.peer_paths_blocked_at);
}

test "peer cid registration enforces active cid limit per path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    conn.local_transport_params.active_connection_id_limit = 2;
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(1),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(2),
    });
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.pending_close.?.error_code);
}

test "retire_prior_to retires peer cids only on the indicated path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handleNewConnectionId(.{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x20}),
        .stateless_reset_token = @splat(0x20),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0x10),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0x11),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 2,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(0x12),
    });

    try std.testing.expectEqual(@as(usize, 2), conn.peerCidsCount());
    try std.testing.expectEqualSlices(u8, &.{0x12}, conn.paths.get(path_id).?.path.peer_cid.slice());
    try std.testing.expectEqualSlices(u8, &.{0x20}, conn.primaryPath().path.peer_cid.slice());
}

test "STREAM send tracking survives duplicate application PNs across paths" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    const path = conn.paths.get(path_id).?;
    const stream = try conn.openBidi(0);

    _ = try stream.send.write("hello");
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000)).?;

    _ = try stream.send.write("world");
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;

    try std.testing.expectEqual(@as(u64, 0), conn.primaryPath().sent.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 0), path.sent.packets[0].pn);
    const primary_stream_key = conn.primaryPath().sent.packets[0].stream_key orelse unreachable;
    const path_stream_key = path.sent.packets[0].stream_key orelse unreachable;
    try std.testing.expect(primary_stream_key != path_stream_key);
    try std.testing.expectEqual(@as(u32, 2), stream.send.in_flight.count());
}

test "timer deadline reports non-zero application path ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(path_id, deadline.path_id);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "PTO requeues retransmittable controls on non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.{}, .{}, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = path_id,
        .error_code = 99,
    } });
    try path.sent.record(packet);

    try conn.tick(conn.ptoDurationForApplicationPath(path));

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expect(!path.pending_ping);
    try std.testing.expectEqual(@as(u32, 1), path.pto_count);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_abandons.items.len);
    try std.testing.expectEqual(path_id, conn.pending_path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_path_abandons.items[0].error_code);
}

test "idle timer closes and enters draining" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_idle_timeout_ms = 5 });
    conn.last_activity_us = 1_000;
    const deadline = conn.nextTimerDeadline(1_000).?;
    try std.testing.expectEqual(TimerKind.idle, deadline.kind);
    try std.testing.expectEqual(@as(u64, 6_000), deadline.at_us);

    try conn.tick(6_000);
    try std.testing.expect(conn.isClosed());
    try std.testing.expect(conn.draining_deadline_us != null);
}
