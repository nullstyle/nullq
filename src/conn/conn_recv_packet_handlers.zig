// Inbound packet handlers for the six per-encryption-level packet
// dispatch paths a `Connection` exposes: Version Negotiation, Initial,
// Retry, 0-RTT (early data), Handshake, and 1-RTT (short header).
// Each handler is responsible for header parse / AEAD open / reserved-
// bits gate / per-level state updates and then defers frame-level
// processing to `Connection.dispatchFrames`. Free-function siblings of
// `Connection`'s public method-style handlers; the methods on
// `Connection` are thin thunks that delegate here.
//
// Extracted from src/conn/state.zig to keep the connection state-
// machine monolith from growing further. No behavior change.
//
// `Connection.handleOnePacket` (the long-header type dispatcher) stays
// in state.zig — it's the orchestrator that picks which of these six
// handlers to invoke based on the first byte / version field.

const std = @import("std");
const boringssl = @import("boringssl");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const ConnectionId = state_mod.ConnectionId;
const wire_header = state_mod.wire_header;
const long_packet_mod = state_mod.long_packet_mod;
const path_mod = state_mod.path_mod;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const quic_version_1 = state_mod.quic_version_1;
const max_recv_plaintext = state_mod.max_recv_plaintext;

/// Handle a Version Negotiation packet (RFC 8999 §6 / RFC 9000 §6).
/// Client-only entrypoint: validate that the VN is bound to our
/// outstanding Initial (matches our SCID and the original DCID), then
/// either ignore it (if the peer still lists v1) or terminate the
/// connection if no compatible version is offered.
pub fn handleVersionNegotiation(
    self: *Connection,
    bytes: []u8,
    now_us: u64,
) usize {
    if (self.role != .client or self.inner.handshakeDone()) return bytes.len;
    const parsed = wire_header.parse(bytes, 0) catch return bytes.len;
    if (parsed.header != .version_negotiation) return bytes.len;
    const vn = parsed.header.version_negotiation;
    if (!self.local_scid_set or !self.initial_dcid_set) return bytes.len;
    if (!std.mem.eql(u8, vn.dcid.slice(), self.local_scid.slice())) return bytes.len;
    const odcid = if (self.original_initial_dcid_set)
        self.original_initial_dcid
    else
        self.initial_dcid;
    if (!std.mem.eql(u8, vn.scid.slice(), odcid.slice())) return bytes.len;
    if (Connection.versionListContains(vn, quic_version_1)) return bytes.len;

    self.enterClosed(
        .version_negotiation,
        .transport,
        0,
        0,
        "no compatible QUIC version",
        now_us,
    );
    return bytes.len;
}

/// Handle a 1-RTT (short-header) packet (RFC 9000 §17.3 / RFC 9001 §5).
/// Resolves the receiving path, opens the packet under one of the
/// current/previous/next application read-key epochs, applies key
/// updates, and dispatches frames. Stateless-reset detection is folded
/// into both the no-keys and decryption-failure branches.
pub fn handleShort(
    self: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    const app_path = self.incomingShortPath(bytes) orelse
        self.pathForId(self.current_incoming_path_id);
    self.current_incoming_path_id = app_path.id;
    const app_pn_space = &app_path.app_pn_space;
    const largest_received = if (app_pn_space.received.largest) |l| l else 0;
    const multipath_path_id: ?u32 = if (self.multipathNegotiated()) app_path.id else null;
    if (self.app_read_current == null) {
        if (self.isKnownStatelessReset(bytes)) {
            self.emitPacketDropped(.application, @intCast(bytes.len), .stateless_reset);
            self.enterStatelessReset(now_us);
        } else {
            self.emitPacketDropped(.application, @intCast(bytes.len), .keys_unavailable);
        }
        return bytes.len;
    }

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const open_result = (try self.openApplicationPacket(
        &pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
    )) orelse {
        if (self.isKnownStatelessReset(bytes)) {
            self.emitPacketDropped(.application, @intCast(bytes.len), .stateless_reset);
            self.enterStatelessReset(now_us);
            return bytes.len;
        }
        self.emitPacketDropped(.application, @intCast(bytes.len), .decryption_failure);
        self.noteApplicationAuthFailure();
        return bytes.len;
    };
    if (open_result.slot == .next) {
        try self.promoteApplicationReadKeys(now_us);
        try self.maybeRespondToPeerKeyUpdate(now_us);
    }
    const opened = open_result.opened;

    // RFC 9000 §17.3 ¶3: short-header Reserved Bits MUST be 0 after
    // header protection is removed. AEAD just authenticated the
    // post-HP first byte (it's mixed into the AAD), so a non-zero
    // value is a peer protocol violation.
    if (opened.reserved_bits != 0) {
        self.close(true, transport_error_protocol_violation, "non-zero short-header reserved bits");
        return bytes.len;
    }

    self.last_authenticated_path_id = app_path.id;
    if (self.closingAttributionOnly()) {
        // RFC 9000 §10.2.1 ¶3 attribution path. Decrypt has
        // succeeded; mark the observation, scan for a peer CC,
        // and skip everything else (no ACK tracker update, no
        // dispatchFrames). The outer `handle` re-arms a CC
        // retransmit subject to the SHOULD-rate-limit.
        self.closing_state_attribution_observed = true;
        self.scanForPeerCloseFrame(opened.payload, now_us);
        return bytes.len;
    }
    Connection.recordApplicationReceivedPacket(app_pn_space, opened.pn, now_us, opened.payload, self.delayed_ack_packet_threshold);
    self.qlog_packets_received +|= 1;
    self.emitPacketReceived(.application, opened.pn, @intCast(bytes.len), Connection.countFrames(opened.payload));
    try self.dispatchFrames(.application, opened.payload, now_us);
    return bytes.len;
}

/// Handle an Initial packet (RFC 9000 §17.2.2 / RFC 9001 §5.2). Server
/// side bootstraps `initial_dcid` from the unprotected long-header
/// bytes before any key derivation. Both roles validate the long-header
/// reserved-bits gate, then dispatch frames at the .initial level.
pub fn handleInitial(
    self: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    // Server-side bootstrap: discover `initial_dcid` from the
    // unprotected long-header bytes before any decryption can
    // happen. RFC 9001 §5.2 derives Initial keys from the DCID
    // the client put on its first Initial.
    if (self.role == .server and !self.initial_dcid_set) {
        if (bytes.len < 6) {
            self.emitPacketDropped(.initial, @intCast(bytes.len), .header_decode_failure);
            return bytes.len;
        }
        const dcid_len = bytes[5];
        if (dcid_len > path_mod.max_cid_len) {
            self.emitPacketDropped(.initial, @intCast(bytes.len), .header_decode_failure);
            return bytes.len;
        }
        if (bytes.len < @as(usize, 6) + dcid_len) {
            self.emitPacketDropped(.initial, @intCast(bytes.len), .header_decode_failure);
            return bytes.len;
        }
        try self.setInitialDcid(bytes[6 .. 6 + dcid_len]);
    }
    try self.ensureInitialKeys();
    const r_keys_opt = self.initial_keys_read;
    const r_keys = r_keys_opt orelse {
        self.emitPacketDropped(.initial, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    };

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const opened = long_packet_mod.openInitial(&pt_buf, bytes, .{
        .keys = &r_keys,
        .largest_received = if (self.pnSpaceForLevel(.initial).received.largest) |l| l else 0,
    }) catch |e| switch (e) {
        boringssl.crypto.aead.Error.Auth => {
            self.emitPacketDropped(.initial, @intCast(bytes.len), .decryption_failure);
            return bytes.len;
        },
        else => return e,
    };

    // RFC 9000 §17.2.1 ¶17: long-header Reserved Bits MUST be 0
    // after header protection is removed. AEAD has authenticated
    // the post-HP first byte by now, so a non-zero value is a
    // peer protocol violation.
    if (opened.reserved_bits != 0) {
        self.close(true, transport_error_protocol_violation, "non-zero long-header reserved bits");
        return bytes.len;
    }

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
        self.emitConnectionStartedOnce();
    }
    if (self.role == .client) {
        const server_scid = ConnectionId.fromSlice(opened.scid.slice());
        if (!ConnectionId.eql(self.primaryPath().path.peer_cid, server_scid)) {
            try self.setPeerDcid(server_scid.slice());
        }
    }

    self.last_authenticated_path_id = self.current_incoming_path_id;
    if (self.closingAttributionOnly()) {
        // RFC 9000 §10.2.1 ¶3 attribution path. See `handleShort`.
        self.closing_state_attribution_observed = true;
        self.scanForPeerCloseFrame(opened.payload, now_us);
        return opened.bytes_consumed;
    }
    self.pnSpaceForLevel(.initial).recordReceivedPacket(opened.pn, now_us / 1000, Connection.packetPayloadAckEliciting(opened.payload));
    self.qlog_packets_received +|= 1;
    self.emitPacketReceived(.initial, opened.pn, @intCast(opened.bytes_consumed), Connection.countFrames(opened.payload));
    try self.dispatchFrames(.initial, opened.payload, now_us);
    return opened.bytes_consumed;
}

/// Handle a Retry packet (RFC 9000 §17.2.5). Client-only: validates
/// the Retry Integrity Tag against the original DCID, stashes the
/// retry token + new SCID, then resets the Initial recovery state so
/// the next Initial flight goes out under the server-supplied DCID
/// and carries the token.
pub fn handleRetry(
    self: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    _ = now_us;
    if (self.role != .client or self.retry_accepted or self.inner.handshakeDone()) {
        return bytes.len;
    }
    const parsed = wire_header.parse(bytes, 0) catch return bytes.len;
    if (parsed.header != .retry) return bytes.len;
    const retry = parsed.header.retry;
    if (retry.version != quic_version_1) return bytes.len;
    if (!self.local_scid_set or !self.initial_dcid_set) return bytes.len;
    if (!std.mem.eql(u8, retry.dcid.slice(), self.local_scid.slice())) return bytes.len;

    const odcid = if (self.original_initial_dcid_set)
        self.original_initial_dcid
    else
        self.initial_dcid;
    if (std.mem.eql(u8, retry.scid.slice(), odcid.slice())) {
        return bytes.len;
    }
    const retry_valid = long_packet_mod.validateRetryIntegrity(odcid.slice(), bytes) catch return bytes.len;
    if (!retry_valid) {
        return bytes.len;
    }

    try self.retry_token.resize(self.allocator, retry.retry_token.len);
    @memcpy(self.retry_token.items, retry.retry_token);
    self.retry_source_cid = ConnectionId.fromSlice(retry.scid.slice());
    self.retry_source_cid_set = true;
    self.retry_accepted = true;

    try self.setPeerDcid(retry.scid.slice());
    try self.setInitialDcid(retry.scid.slice());
    try self.resetInitialRecoveryForRetry();
    return bytes.len;
}

/// Handle a 0-RTT (early data) packet (RFC 9001 §4.6). Server-only:
/// drop if 0-RTT was rejected or keys are unavailable. Otherwise open
/// under the early-data read keys, gate on the long-header reserved
/// bits, and dispatch frames at the .early_data level.
pub fn handleZeroRtt(
    self: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    if (self.role != .server) {
        self.emitPacketDropped(.early_data, @intCast(bytes.len), .other);
        return bytes.len;
    }
    if (self.inner.earlyDataStatus() == .rejected) {
        self.emitPacketDropped(.early_data, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    }

    const r_keys_opt = try self.packetKeys(.early_data, .read);
    const r_keys = r_keys_opt orelse {
        self.emitPacketDropped(.early_data, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    };
    const app_path = self.pathForId(self.current_incoming_path_id);
    const app_pn_space = &app_path.app_pn_space;
    const largest_received = if (app_pn_space.received.largest) |l| l else 0;

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const opened = long_packet_mod.openZeroRtt(&pt_buf, bytes, .{
        .keys = &r_keys,
        .largest_received = largest_received,
    }) catch |e| switch (e) {
        boringssl.crypto.aead.Error.Auth => {
            self.emitPacketDropped(.early_data, @intCast(bytes.len), .decryption_failure);
            return bytes.len;
        },
        else => return e,
    };

    // RFC 9000 §17.2.1 ¶17 long-header Reserved Bits gate.
    if (opened.reserved_bits != 0) {
        self.close(true, transport_error_protocol_violation, "non-zero long-header reserved bits");
        return bytes.len;
    }

    self.last_authenticated_path_id = app_path.id;
    if (self.closingAttributionOnly()) {
        // RFC 9000 §10.2.1 ¶3 attribution path. See `handleShort`.
        self.closing_state_attribution_observed = true;
        self.scanForPeerCloseFrame(opened.payload, now_us);
        return opened.bytes_consumed;
    }
    Connection.recordApplicationReceivedPacket(app_pn_space, opened.pn, now_us, opened.payload, self.delayed_ack_packet_threshold);
    self.qlog_packets_received +|= 1;
    self.emitPacketReceived(.early_data, opened.pn, @intCast(opened.bytes_consumed), Connection.countFrames(opened.payload));
    try self.dispatchFrames(.early_data, opened.payload, now_us);
    return opened.bytes_consumed;
}

/// Handle a Handshake packet (RFC 9000 §17.2.4 / RFC 9001 §5.2).
/// Decrypt under the Handshake read keys, gate on long-header reserved
/// bits, then dispatch frames at the .handshake level.
pub fn handleHandshake(
    self: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    const r_keys_opt = try self.packetKeys(.handshake, .read);
    const r_keys = r_keys_opt orelse {
        self.emitPacketDropped(.handshake, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    };

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const opened = long_packet_mod.openHandshake(&pt_buf, bytes, .{
        .keys = &r_keys,
        .largest_received = if (self.pnSpaceForLevel(.handshake).received.largest) |l| l else 0,
    }) catch |e| switch (e) {
        boringssl.crypto.aead.Error.Auth => {
            self.emitPacketDropped(.handshake, @intCast(bytes.len), .decryption_failure);
            return bytes.len;
        },
        else => return e,
    };

    // RFC 9000 §17.2.1 ¶17 long-header Reserved Bits gate.
    if (opened.reserved_bits != 0) {
        self.close(true, transport_error_protocol_violation, "non-zero long-header reserved bits");
        return bytes.len;
    }

    self.last_authenticated_path_id = self.current_incoming_path_id;
    if (self.closingAttributionOnly()) {
        // RFC 9000 §10.2.1 ¶3 attribution path. See `handleShort`.
        self.closing_state_attribution_observed = true;
        self.scanForPeerCloseFrame(opened.payload, now_us);
        return opened.bytes_consumed;
    }
    self.pnSpaceForLevel(.handshake).recordReceivedPacket(opened.pn, now_us / 1000, Connection.packetPayloadAckEliciting(opened.payload));
    self.qlog_packets_received +|= 1;
    self.emitPacketReceived(.handshake, opened.pn, @intCast(opened.bytes_consumed), Connection.countFrames(opened.payload));
    try self.dispatchFrames(.handshake, opened.payload, now_us);
    return opened.bytes_consumed;
}
