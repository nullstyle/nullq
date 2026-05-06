//! Phase 5 acceptance: two `nullq.Connection`s open a stream
//! after the TLS handshake, the client streams bytes through
//! `Connection.poll`, the server consumes them via
//! `Connection.handle` + `streamRead`, and ACKs flow back to the
//! client so the send buffer drains.
//!
//! The later scenarios add deterministic loss, reordering, and
//! multipath path abandonment. This file is the integration
//! "smoke": every primitive (key derivation, packet protection,
//! frame codec, send/recv streams, ACK processing) cooperates over
//! the same Connection.

const std = @import("std");
const nullq = @import("nullq");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

const ClientCid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
const ServerCid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99 };
const ClientPath1Cid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
const ServerPath1Cid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xb0, 0xb1 };
const Address = nullq.conn.path.Address;

fn handshake(allocator: std.mem.Allocator, client: *nullq.Connection, server: *nullq.Connection) !void {
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    _ = allocator;
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
}

fn buildContexts(
    server_tls: *boringssl.tls.Context,
    client_tls: *boringssl.tls.Context,
) !void {
    const protos = [_][]const u8{"hq-test"};
    server_tls.* = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    try server_tls.loadCertChainAndKey(test_cert_pem, test_key_pem);
    client_tls.* = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
}

const SimPacket = struct {
    bytes: []u8,
    from_client: bool,
    path_id: u32,
    release_us: u64,
};

const AddressedPacket = struct {
    bytes: []u8,
    from_client: bool,
    source: Address,
    release_us: u64,
};

const MultipathNet = struct {
    allocator: std.mem.Allocator,
    queue: std.ArrayList(SimPacket) = .empty,
    c2s_seq: [2]u32 = .{ 0, 0 },
    s2c_seq: [2]u32 = .{ 0, 0 },
    c2s_path_seen: [2]bool = .{ false, false },
    s2c_path_seen: [2]bool = .{ false, false },
    drop_enabled: bool = false,
    dropped_c2s_path1: bool = false,
    dropped_s2c_path0: bool = false,

    fn init(allocator: std.mem.Allocator) MultipathNet {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *MultipathNet) void {
        for (self.queue.items) |pkt| self.allocator.free(pkt.bytes);
        self.queue.deinit(self.allocator);
        self.* = undefined;
    }

    fn pathIndex(path_id: u32) usize {
        return if (path_id == 0) 0 else 1;
    }

    fn delayUs(from_client: bool, path_id: u32, seq: u32) u64 {
        if (path_id == 0) return if (from_client) 1_000 else 2_000;
        return if (seq % 2 == 0) 8_000 else 1_000;
    }

    fn shouldDrop(self: *MultipathNet, from_client: bool, path_id: u32, seq: u32) bool {
        if (!self.drop_enabled) return false;
        if (from_client and path_id == 1 and !self.dropped_c2s_path1 and seq >= 1) {
            self.dropped_c2s_path1 = true;
            return true;
        }
        if (!from_client and path_id == 0 and !self.dropped_s2c_path0 and seq >= 1) {
            self.dropped_s2c_path0 = true;
            return true;
        }
        return false;
    }

    fn enqueue(
        self: *MultipathNet,
        from_client: bool,
        datagram: nullq.OutgoingDatagram,
        bytes: []const u8,
        now_us: u64,
    ) !void {
        const idx = pathIndex(datagram.path_id);
        const seq = if (from_client) self.c2s_seq[idx] else self.s2c_seq[idx];
        if (from_client) {
            self.c2s_seq[idx] += 1;
            self.c2s_path_seen[idx] = true;
        } else {
            self.s2c_seq[idx] += 1;
            self.s2c_path_seen[idx] = true;
        }
        if (self.shouldDrop(from_client, datagram.path_id, seq)) return;

        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.queue.append(self.allocator, .{
            .bytes = copy,
            .from_client = from_client,
            .path_id = datagram.path_id,
            .release_us = now_us + delayUs(from_client, datagram.path_id, seq),
        });
    }

    fn pollEndpoint(
        self: *MultipathNet,
        from_client: bool,
        conn: *nullq.Connection,
        now_us: u64,
    ) !void {
        var pkt: [2048]u8 = undefined;
        if (try conn.pollDatagram(&pkt, now_us)) |datagram| {
            try self.enqueue(from_client, datagram, pkt[0..datagram.len], now_us);
        }
    }

    fn deliverDue(
        self: *MultipathNet,
        client: *nullq.Connection,
        server: *nullq.Connection,
        now_us: u64,
    ) !void {
        var delivered = true;
        while (delivered) {
            delivered = false;
            var i: usize = 0;
            while (i < self.queue.items.len) {
                if (self.queue.items[i].release_us > now_us) {
                    i += 1;
                    continue;
                }
                const pkt = self.queue.orderedRemove(i);
                defer self.allocator.free(pkt.bytes);
                if (pkt.from_client) {
                    try server.handle(pkt.bytes, null, now_us);
                } else {
                    try client.handle(pkt.bytes, null, now_us);
                }
                delivered = true;
                break;
            }
        }
    }
};

const RebindingNet = struct {
    allocator: std.mem.Allocator,
    queue: std.ArrayList(AddressedPacket) = .empty,
    client_addr: Address,
    client_rebound_addr: Address,
    server_addr: Address,
    client_rebound: bool = false,
    c2s_seq: u32 = 0,
    s2c_seq: u32 = 0,
    dropped_first_rebound_c2s: bool = false,
    delivered_rebound_c2s: bool = false,
    server_sent_to_rebound: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        client_addr: Address,
        client_rebound_addr: Address,
        server_addr: Address,
    ) RebindingNet {
        return .{
            .allocator = allocator,
            .client_addr = client_addr,
            .client_rebound_addr = client_rebound_addr,
            .server_addr = server_addr,
        };
    }

    fn deinit(self: *RebindingNet) void {
        for (self.queue.items) |pkt| self.allocator.free(pkt.bytes);
        self.queue.deinit(self.allocator);
        self.* = undefined;
    }

    fn clientSource(self: *const RebindingNet) Address {
        return if (self.client_rebound) self.client_rebound_addr else self.client_addr;
    }

    fn delayUs(from_client: bool, seq: u32) u64 {
        if (from_client) return if (seq % 4 == 1) 7_000 else 1_000;
        return if (seq % 3 == 2) 6_000 else 1_000;
    }

    fn enqueue(
        self: *RebindingNet,
        from_client: bool,
        datagram: nullq.OutgoingDatagram,
        bytes: []const u8,
        now_us: u64,
    ) !void {
        const seq = if (from_client) self.c2s_seq else self.s2c_seq;
        if (from_client) {
            self.c2s_seq += 1;
        } else {
            self.s2c_seq += 1;
            if (datagram.to) |addr| {
                if (Address.eql(addr, self.client_rebound_addr)) self.server_sent_to_rebound = true;
            }
        }

        const source = if (from_client) self.clientSource() else self.server_addr;
        if (from_client and
            self.client_rebound and
            !self.dropped_first_rebound_c2s)
        {
            self.dropped_first_rebound_c2s = true;
            return;
        }

        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.queue.append(self.allocator, .{
            .bytes = copy,
            .from_client = from_client,
            .source = source,
            .release_us = now_us + delayUs(from_client, seq),
        });
    }

    fn pollEndpoint(
        self: *RebindingNet,
        from_client: bool,
        conn: *nullq.Connection,
        now_us: u64,
    ) !void {
        var pkt: [2048]u8 = undefined;
        if (try conn.pollDatagram(&pkt, now_us)) |datagram| {
            try self.enqueue(from_client, datagram, pkt[0..datagram.len], now_us);
        }
    }

    fn deliverDue(
        self: *RebindingNet,
        client: *nullq.Connection,
        server: *nullq.Connection,
        now_us: u64,
    ) !void {
        var delivered = true;
        while (delivered) {
            delivered = false;
            var i: usize = 0;
            while (i < self.queue.items.len) {
                if (self.queue.items[i].release_us > now_us) {
                    i += 1;
                    continue;
                }
                const pkt = self.queue.orderedRemove(i);
                defer self.allocator.free(pkt.bytes);
                if (pkt.from_client) {
                    if (Address.eql(pkt.source, self.client_rebound_addr)) {
                        self.delivered_rebound_c2s = true;
                    }
                    try server.handle(pkt.bytes, pkt.source, now_us);
                } else {
                    try client.handle(pkt.bytes, pkt.source, now_us);
                }
                delivered = true;
                break;
            }
        }
    }
};

fn configurePrimaryCids(client: *nullq.Connection, server: *nullq.Connection) !void {
    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);
}

fn openSecondPath(client: *nullq.Connection, server: *nullq.Connection) !u32 {
    const Cid = nullq.conn.path.ConnectionId;
    const client_path_id = try client.openPath(
        .{},
        .{},
        Cid.fromSlice(&ClientPath1Cid),
        Cid.fromSlice(&ServerPath1Cid),
    );
    const server_path_id = try server.openPath(
        .{},
        .{},
        Cid.fromSlice(&ServerPath1Cid),
        Cid.fromSlice(&ClientPath1Cid),
    );
    try std.testing.expectEqual(client_path_id, server_path_id);
    try std.testing.expect(client.markPathValidated(client_path_id));
    try std.testing.expect(server.markPathValidated(server_path_id));
    return client_path_id;
}

fn noteDatagram(payload: []const u8, seen_p0: *bool, seen_p1: *bool) void {
    if (std.mem.endsWith(u8, payload, "-p0")) seen_p0.* = true;
    if (std.mem.endsWith(u8, payload, "-p1")) seen_p1.* = true;
}

fn drainExpectedStream(
    conn: *nullq.Connection,
    stream_id: u64,
    expected: []const u8,
    consumed: *usize,
    scratch: []u8,
) !void {
    if (conn.stream(stream_id) == null) return;
    while (true) {
        const got = try conn.streamRead(stream_id, scratch);
        if (got == 0) break;
        try std.testing.expectEqualSlices(
            u8,
            expected[consumed.* .. consumed.* + got],
            scratch[0..got],
        );
        consumed.* += got;
    }
}

test "client streams 16 KiB to server through poll/handle" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    // Wire CIDs. Client writes packets with peer-DCID = ServerCid;
    // server expects to see ServerCid at the matching length on
    // incoming bytes (the local_dcid_len for the receiver). Same
    // logic in reverse.
    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // Client opens a bidi stream and writes 16 KiB of pseudo-random
    // data. The 16 KiB is far more than fits in one MTU, so this
    // exercises multi-packet send + ACK + buffer drain.
    const total: usize = 16 * 1024;
    var data: [total]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x42);
    prng.random().bytes(&data);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, &data);
    try client.streamFinish(0);

    // Drive the loop. Each iteration: client emits a packet (if it
    // can), server consumes it; server emits an ACK packet, client
    // consumes that. We bound iterations to avoid infinite loops on
    // bug.
    var pkt: [2048]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var consumed: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;

    while (consumed < total) : (iters += 1) {
        try std.testing.expect(iters < 200_000); // safety bound

        if (try client.poll(&pkt, now_us)) |n| {
            try server.handle(pkt[0..n], null, now_us);
        }
        if (try server.poll(&pkt, now_us)) |n| {
            try client.handle(pkt[0..n], null, now_us);
        }

        // Drain readable bytes out of the server's stream 0.
        while (true) {
            const got = try server.streamRead(0, &rbuf);
            if (got == 0) break;
            try std.testing.expectEqualSlices(
                u8,
                data[consumed .. consumed + got],
                rbuf[0..got],
            );
            consumed += got;
        }

        now_us += 1_000;
    }

    try std.testing.expectEqual(total, consumed);

    // The client's send-side buffer should now be drained: every
    // byte was acked.
    const cs = client.stream(0).?;
    try std.testing.expectEqual(@as(u64, total), cs.send.ackedFloor());
    try std.testing.expect(cs.send.fin_acked);

    // The server's receive-side saw the FIN.
    const ss = server.stream(0).?;
    try std.testing.expect(ss.recv.fin_seen);
}

test "DATAGRAM round-trips through the 1-RTT path" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
        .max_datagram_frame_size = 1200,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    try client.sendDatagram("hello-from-client");
    try server.sendDatagram("hello-from-server");

    var pkt: [2048]u8 = undefined;
    var rx_c: [256]u8 = undefined;
    var rx_s: [256]u8 = undefined;
    var iters: u32 = 0;
    var now_us: u64 = 1_000_000;

    while (iters < 10) : (iters += 1) {
        if (try client.poll(&pkt, now_us)) |n| try server.handle(pkt[0..n], null, now_us);
        if (try server.poll(&pkt, now_us)) |n| try client.handle(pkt[0..n], null, now_us);
        now_us += 1000;
    }

    const cn = client.receiveDatagram(&rx_c).?;
    try std.testing.expectEqualStrings("hello-from-server", rx_c[0..cn]);
    const sn = server.receiveDatagram(&rx_s).?;
    try std.testing.expectEqualStrings("hello-from-client", rx_s[0..sn]);
}

test "CONNECTION_CLOSE propagates from sender to receiver" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);
    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // Client closes with an application error.
    client.close(false, 0x42, "shutting down");
    try std.testing.expect(!client.isClosed());

    var pkt: [2048]u8 = undefined;
    var iters: u32 = 0;
    while (iters < 10 and !server.isClosed()) : (iters += 1) {
        if (try client.poll(&pkt, 1_000_000)) |n| {
            try server.handle(pkt[0..n], null, 1_000_000);
        }
        if (try server.poll(&pkt, 1_000_000)) |n| {
            try client.handle(pkt[0..n], null, 1_000_000);
        }
    }
    try std.testing.expect(client.isClosed());
    try std.testing.expect(server.isClosed());
}

test "STOP_SENDING propagates and resets the sender's stream" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);
    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, "data the server doesn't want");

    // Server tells client to stop sending stream 0.
    try server.streamStopSending(0, 0xff);

    var pkt: [2048]u8 = undefined;
    var iters: u32 = 0;
    while (iters < 8) : (iters += 1) {
        if (try server.poll(&pkt, 1_000_000)) |n| try client.handle(pkt[0..n], null, 1_000_000);
        if (try client.poll(&pkt, 1_000_000)) |n| try server.handle(pkt[0..n], null, 1_000_000);
    }

    // Client's send half should have sent RESET_STREAM and observed
    // the peer ACK it.
    const cs = client.stream(0).?;
    try std.testing.expectEqual(nullq.conn.send_stream.State.reset_recvd, cs.send.state);
    try std.testing.expect(cs.send.reset != null);
    try std.testing.expectEqual(@as(u64, 0xff), cs.send.reset.?.error_code);
}

test "client streams 512 KiB to server (regression for upload stall)" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    // Use the same TPs nullq-peer advertises so we exercise the same
    // flow-control limits the dev's go-quic-peer interop uses.
    const tp: nullq.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 16 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 8 * 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 8 * 1024 * 1024,
        .initial_max_stream_data_uni = 1024 * 1024,
        .initial_max_streams_bidi = 256,
        .initial_max_streams_uni = 256,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    const total: usize = 512 * 1024;
    var data = try allocator.alloc(u8, total);
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0xfeed);
    prng.random().bytes(data);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, data);
    try client.streamFinish(0);

    var pkt: [2048]u8 = undefined;
    var rbuf: [8192]u8 = undefined;
    var consumed: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;

    while (consumed < total) : (iters += 1) {
        try std.testing.expect(iters < 2_000_000);

        if (try client.poll(&pkt, now_us)) |n| try server.handle(pkt[0..n], null, now_us);
        if (try server.poll(&pkt, now_us)) |n| try client.handle(pkt[0..n], null, now_us);

        while (true) {
            const got = try server.streamRead(0, &rbuf);
            if (got == 0) break;
            try std.testing.expectEqualSlices(u8, data[consumed .. consumed + got], rbuf[0..got]);
            consumed += got;
        }
        now_us += 1_000;
    }

    try std.testing.expectEqual(total, consumed);
    const cs = client.stream(0).?;
    try std.testing.expectEqual(@as(u64, total), cs.send.ackedFloor());
}

test "PATH_CHALLENGE → PATH_RESPONSE validates the path round-trip" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    // Client begins path validation with a known token.
    const token: [8]u8 = .{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 1, 2 };
    try client.probePath(token, 1_000_000, 100_000);
    try std.testing.expect(!client.isPathValidated());

    var pkt: [2048]u8 = undefined;
    var iters: u32 = 0;
    var now_us: u64 = 1_000_000;

    while (iters < 10 and !client.isPathValidated()) : (iters += 1) {
        if (try client.poll(&pkt, now_us)) |n| try server.handle(pkt[0..n], null, now_us);
        if (try server.poll(&pkt, now_us)) |n| try client.handle(pkt[0..n], null, now_us);
        now_us += 1000;
    }

    try std.testing.expect(client.isPathValidated());
}

test "client streams 16 KiB to server with 10% simulated loss" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);

    try client.setPeerDcid(&ServerCid);
    try client.setLocalScid(&ClientCid);
    try server.setPeerDcid(&ClientCid);
    try server.setLocalScid(&ServerCid);

    const total: usize = 16 * 1024;
    var data: [total]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc0d3);
    prng.random().bytes(&data);

    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, &data);
    try client.streamFinish(0);

    var pkt: [2048]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var consumed: usize = 0;
    var now_us: u64 = 1_000_000;
    var iters: u32 = 0;
    const drop_pct: u32 = 10;

    while (consumed < total) : (iters += 1) {
        try std.testing.expect(iters < 500_000);

        try client.tick(now_us);
        try server.tick(now_us);

        if (try client.poll(&pkt, now_us)) |n| {
            const drop = prng.random().intRangeAtMost(u32, 0, 99) < drop_pct;
            if (!drop) try server.handle(pkt[0..n], null, now_us);
        }
        if (try server.poll(&pkt, now_us)) |n| {
            const drop = prng.random().intRangeAtMost(u32, 0, 99) < drop_pct;
            if (!drop) try client.handle(pkt[0..n], null, now_us);
        }

        // Drain readable bytes.
        while (true) {
            const got = try server.streamRead(0, &rbuf);
            if (got == 0) break;
            try std.testing.expectEqualSlices(
                u8,
                data[consumed .. consumed + got],
                rbuf[0..got],
            );
            consumed += got;
        }

        now_us += 1_000;
    }

    try std.testing.expectEqual(total, consumed);
    const cs = client.stream(0).?;
    try std.testing.expectEqual(@as(u64, total), cs.send.ackedFloor());
    try std.testing.expect(cs.send.fin_acked);
    const ss = server.stream(0).?;
    try std.testing.expect(ss.recv.fin_seen);
}

test "single-path NAT rebinding survives loss and reordering" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);
    try configurePrimaryCids(&client, &server);

    var net = RebindingNet.init(
        allocator,
        .{ .bytes = .{ 10, 0, 0, 1 } ++ @as([18]u8, @splat(0)) },
        .{ .bytes = .{ 10, 0, 0, 2 } ++ @as([18]u8, @splat(0)) },
        .{ .bytes = .{ 10, 0, 0, 99 } ++ @as([18]u8, @splat(0)) },
    );
    defer net.deinit();

    const total: usize = 32 * 1024;
    const client_data = try allocator.alloc(u8, total);
    defer allocator.free(client_data);
    const server_data = try allocator.alloc(u8, total);
    defer allocator.free(server_data);
    var prng = std.Random.DefaultPrng.init(0x9a7_91);
    prng.random().bytes(client_data);
    prng.random().bytes(server_data);

    _ = try client.openBidi(0);
    _ = try server.openBidi(1);
    _ = try client.streamWrite(0, client_data);
    _ = try server.streamWrite(1, server_data);
    try client.streamFinish(0);
    try server.streamFinish(1);

    var now_us: u64 = 1_000_000;
    var client_consumed: usize = 0;
    var server_consumed: usize = 0;
    var cbuf: [4096]u8 = undefined;
    var sbuf: [4096]u8 = undefined;
    var rebound_started = false;
    var iters: u32 = 0;

    while (iters < 700_000) : (iters += 1) {
        try client.tick(now_us);
        try server.tick(now_us);
        try net.deliverDue(&client, &server, now_us);
        try net.pollEndpoint(true, &client, now_us);
        try net.pollEndpoint(false, &server, now_us);

        try drainExpectedStream(&server, 0, client_data, &server_consumed, &sbuf);
        try drainExpectedStream(&client, 1, server_data, &client_consumed, &cbuf);

        if (!rebound_started and server_consumed >= total / 4 and client_consumed >= total / 4) {
            net.client_rebound = true;
            rebound_started = true;
        }

        const cstream = client.stream(0).?;
        const sstream = server.stream(1).?;
        const done =
            client_consumed == total and
            server_consumed == total and
            cstream.send.ackedFloor() == @as(u64, @intCast(total)) and
            sstream.send.ackedFloor() == @as(u64, @intCast(total)) and
            cstream.send.fin_acked and
            sstream.send.fin_acked and
            server.pathStats(0).?.validated and
            net.server_sent_to_rebound;
        if (done) break;

        now_us += 1_000;
    }

    try std.testing.expect(iters < 700_000);
    try std.testing.expect(rebound_started);
    try std.testing.expect(net.dropped_first_rebound_c2s);
    try std.testing.expect(net.delivered_rebound_c2s);
    try std.testing.expect(net.server_sent_to_rebound);
    try std.testing.expect(server.pathStats(0).?.validated);
    try std.testing.expectEqual(total, server_consumed);
    try std.testing.expectEqual(total, client_consumed);
}

test "multipath concurrent transfer survives reordering loss and path abandon" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var client = try nullq.Connection.initClient(allocator, client_tls, "localhost");
    defer client.deinit();
    var server = try nullq.Connection.initServer(allocator, server_tls);
    defer server.deinit();

    try client.bind();
    try server.bind();
    client.peer = &server;
    server.peer = &client;

    const tp: nullq.tls.TransportParams = .{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
        .active_connection_id_limit = 4,
        .max_datagram_frame_size = 1200,
        .initial_max_path_id = 1,
    };
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try handshake(allocator, &client, &server);
    try std.testing.expect(client.multipathNegotiated());
    try std.testing.expect(server.multipathNegotiated());

    try configurePrimaryCids(&client, &server);
    const path1 = try openSecondPath(&client, &server);
    try std.testing.expectEqual(@as(u32, 1), path1);

    var net = MultipathNet.init(allocator);
    defer net.deinit();
    var now_us: u64 = 1_000_000;

    client.setScheduler(.primary);
    server.setScheduler(.primary);

    try std.testing.expect(client.setActivePath(0));
    try client.sendDatagram("client-dg-p0");
    try net.pollEndpoint(true, &client, now_us);
    try std.testing.expect(client.setActivePath(path1));
    try client.sendDatagram("client-dg-p1");
    try net.pollEndpoint(true, &client, now_us);

    try std.testing.expect(server.setActivePath(0));
    try server.sendDatagram("server-dg-p0");
    try net.pollEndpoint(false, &server, now_us);
    try std.testing.expect(server.setActivePath(path1));
    try server.sendDatagram("server-dg-p1");
    try net.pollEndpoint(false, &server, now_us);

    var client_dg_p0 = false;
    var client_dg_p1 = false;
    var server_dg_p0 = false;
    var server_dg_p1 = false;
    var dg_buf: [256]u8 = undefined;
    var dg_iters: u32 = 0;
    while (!(client_dg_p0 and client_dg_p1 and server_dg_p0 and server_dg_p1)) : (dg_iters += 1) {
        try std.testing.expect(dg_iters < 200);
        try net.deliverDue(&client, &server, now_us);
        try net.pollEndpoint(true, &client, now_us);
        try net.pollEndpoint(false, &server, now_us);

        while (client.receiveDatagram(&dg_buf)) |n| {
            noteDatagram(dg_buf[0..n], &client_dg_p0, &client_dg_p1);
        }
        while (server.receiveDatagram(&dg_buf)) |n| {
            noteDatagram(dg_buf[0..n], &server_dg_p0, &server_dg_p1);
        }
        now_us += 1_000;
    }

    client.setScheduler(.round_robin);
    server.setScheduler(.round_robin);
    try std.testing.expect(client.setActivePath(0));
    try std.testing.expect(server.setActivePath(0));

    const total: usize = 24 * 1024;
    const client_data = try allocator.alloc(u8, total);
    defer allocator.free(client_data);
    const server_data = try allocator.alloc(u8, total);
    defer allocator.free(server_data);
    var prng = std.Random.DefaultPrng.init(0x5eed_21);
    prng.random().bytes(client_data);
    prng.random().bytes(server_data);

    _ = try client.openBidi(0);
    _ = try server.openBidi(1);
    _ = try client.streamWrite(0, client_data);
    _ = try server.streamWrite(1, server_data);
    try client.streamFinish(0);
    try server.streamFinish(1);

    net.drop_enabled = true;
    var client_consumed: usize = 0;
    var server_consumed: usize = 0;
    var cbuf: [4096]u8 = undefined;
    var sbuf: [4096]u8 = undefined;
    var abandoned = false;
    var iters: u32 = 0;

    while (iters < 700_000) : (iters += 1) {
        try client.tick(now_us);
        try server.tick(now_us);
        try net.deliverDue(&client, &server, now_us);
        try net.pollEndpoint(true, &client, now_us);
        try net.pollEndpoint(false, &server, now_us);

        try drainExpectedStream(&server, 0, client_data, &server_consumed, &sbuf);
        try drainExpectedStream(&client, 1, server_data, &client_consumed, &cbuf);

        if (!abandoned and server_consumed >= total / 3 and client_consumed >= total / 3) {
            try std.testing.expect(client.abandonPathAt(path1, 0x51, now_us));
            try std.testing.expect(server.abandonPathAt(path1, 0x51, now_us));
            try std.testing.expect(client.setActivePath(0));
            try std.testing.expect(server.setActivePath(0));
            abandoned = true;
        }

        const cstream = client.stream(0).?;
        const sstream = server.stream(1).?;
        const done =
            client_consumed == total and
            server_consumed == total and
            cstream.send.ackedFloor() == @as(u64, @intCast(total)) and
            sstream.send.ackedFloor() == @as(u64, @intCast(total)) and
            cstream.send.fin_acked and
            sstream.send.fin_acked;
        if (done) break;

        now_us += 1_000;
    }

    try std.testing.expect(iters < 700_000);
    try std.testing.expect(abandoned);
    try std.testing.expect(net.dropped_c2s_path1);
    try std.testing.expect(net.dropped_s2c_path0);
    try std.testing.expect(net.c2s_path_seen[0]);
    try std.testing.expect(net.c2s_path_seen[1]);
    try std.testing.expect(net.s2c_path_seen[0]);
    try std.testing.expect(net.s2c_path_seen[1]);

    try std.testing.expectEqual(total, server_consumed);
    try std.testing.expectEqual(total, client_consumed);
    try std.testing.expectEqual(nullq.conn.path.State.retiring, client.pathStats(path1).?.state);
    try std.testing.expectEqual(nullq.conn.path.State.retiring, server.pathStats(path1).?.state);

    const retire_at = @max(
        client.pathStats(path1).?.retire_deadline_us.?,
        server.pathStats(path1).?.retire_deadline_us.?,
    );
    now_us = @max(now_us, retire_at);
    try client.tick(now_us);
    try server.tick(now_us);
    try std.testing.expectEqual(nullq.conn.path.State.failed, client.pathStats(path1).?.state);
    try std.testing.expectEqual(nullq.conn.path.State.failed, server.pathStats(path1).?.state);
}
