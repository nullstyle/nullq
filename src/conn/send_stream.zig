//! Send-side stream buffer (RFC 9000 §3.1, §19.8).
//!
//! Owns the bytes the application has handed us for a single
//! stream and tracks which absolute byte ranges:
//!
//! - have been queued by the app but not yet sent (`pending`),
//! - have been sent in some packet and are awaiting ACK
//!   (`in_flight`, keyed by packet number),
//! - are above `base_offset` and have been ACKed but cannot yet be
//!   collapsed into the floor because of a gap (`acked_above`).
//!
//! Bytes whose absolute offset is < `base_offset` have been ACKed
//! contiguously from offset 0 and dropped from the buffer.
//!
//! The connection asks for a chunk to ship in the next outgoing
//! packet via `nextChunk`, calls `recordSent` once the packet is
//! framed, and feeds back ACK/loss outcomes via `onPacketAcked`
//! and `onPacketLost`.
//!
//! FIN and RESET_STREAM are tracked per RFC 9000 §3.1's stream
//! state machine. The application calls `finish` to mark the FIN
//! intent and `resetStream` to abandon. `nextChunk` emits a FIN
//! flag on the chunk that carries the last byte (or a 0-length FIN
//! chunk if `finish` was called with no remaining bytes).

const std = @import("std");

pub const Error = error{
    /// `write` was called after `finish` or `resetStream`.
    StreamClosed,
    /// `recordSent` was called with a chunk that doesn't sit inside
    /// the current pending range, or the in-flight map already has
    /// an entry for this PN.
    InvalidChunk,
    /// Unknown PN handed to `onPacketAcked` / `onPacketLost`.
    UnknownPacket,
} || std.mem.Allocator.Error;

/// State of a stream's send half (RFC 9000 §3.1):
/// ready → send → data_sent → data_recvd
///                    ↘ reset_sent → reset_recvd
pub const State = enum {
    /// No bytes written yet (app has the stream open but is silent).
    ready,
    /// Bytes have been written and are pending or in-flight.
    send,
    /// FIN has been queued; some bytes may still be in-flight.
    data_sent,
    /// Every byte and the FIN have been ACKed.
    data_recvd,
    /// `resetStream` was called; we'll emit a RESET_STREAM frame.
    reset_sent,
    /// The peer ACKed our RESET_STREAM.
    reset_recvd,
};

pub const Range = struct {
    offset: u64,
    /// Inclusive end. A 0-length range cannot be represented; use
    /// the `pending` list's `count == 0` instead.
    end: u64,

    pub fn len(self: Range) u64 {
        return self.end - self.offset;
    }
};

/// One in-flight chunk: bytes [offset, offset+length) and a
/// possible trailing FIN. Length 0 is permitted only when `fin`
/// is true (a pure FIN chunk).
pub const Chunk = struct {
    offset: u64,
    length: u64,
    fin: bool,
};

pub const ResetInfo = struct {
    /// Application-supplied error code (RFC 9000 §19.4).
    error_code: u64,
    /// Final size at the moment of reset.
    final_size: u64,
    /// Has the RESET_STREAM frame been queued for send?
    queued: bool = false,
    /// Has the peer ACKed our RESET_STREAM?
    acked: bool = false,
};

pub const SendStream = struct {
    allocator: std.mem.Allocator,

    /// Bytes the app has written but not yet had fully-prefix-acked.
    /// `bytes.items[0]` is at absolute offset `base_offset`.
    bytes: std.ArrayList(u8) = .empty,
    /// Absolute offset of the first byte still in `bytes`.
    base_offset: u64 = 0,
    /// One past the highest absolute offset the app has written.
    /// Invariant: `write_offset == base_offset + bytes.items.len`.
    write_offset: u64 = 0,

    /// Sorted disjoint ranges (subset of [base_offset, write_offset))
    /// that need to be sent or retransmitted.
    pending: std.ArrayList(Range) = .empty,
    /// In-flight chunks per packet number.
    in_flight: std.AutoHashMapUnmanaged(u64, Chunk) = .empty,
    /// Sorted disjoint ranges above `base_offset` that have been
    /// ACKed but can't yet be folded into the floor.
    acked_above: std.ArrayList(Range) = .empty,

    /// FIN intent set via `finish`.
    fin_marked: bool = false,
    /// FIN has been packed into an in-flight chunk.
    fin_in_flight: bool = false,
    /// FIN chunk has been ACKed.
    fin_acked: bool = false,
    /// Final stream size; set once `finish` is called.
    final_size: ?u64 = null,

    /// Reset state. `null` until `resetStream` is called.
    reset: ?ResetInfo = null,

    state: State = .ready,

    pub fn init(allocator: std.mem.Allocator) SendStream {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SendStream) void {
        self.bytes.deinit(self.allocator);
        self.pending.deinit(self.allocator);
        self.acked_above.deinit(self.allocator);
        self.in_flight.deinit(self.allocator);
        self.* = undefined;
    }

    /// Append `data` to the stream. Returns the number of bytes
    /// accepted (always `data.len` for now; future flow-control
    /// gates may shorten it).
    pub fn write(self: *SendStream, data: []const u8) Error!usize {
        if (self.fin_marked or self.reset != null) return Error.StreamClosed;
        if (data.len == 0) return 0;

        try self.bytes.appendSlice(self.allocator, data);
        const start = self.write_offset;
        self.write_offset += data.len;
        try self.addPending(.{ .offset = start, .end = self.write_offset });
        if (self.state == .ready) self.state = .send;
        return data.len;
    }

    /// Mark the send side closed. The current `write_offset` becomes
    /// the final size and a FIN flag will be emitted on the next
    /// chunk that covers it (or a pure-FIN chunk if no bytes remain).
    pub fn finish(self: *SendStream) Error!void {
        if (self.reset != null) return Error.StreamClosed;
        if (self.fin_marked) return;
        self.fin_marked = true;
        self.final_size = self.write_offset;
        if (self.state == .send or self.state == .ready) self.state = .data_sent;
    }

    /// Abandon the stream. Equivalent to RESET_STREAM (§19.4).
    pub fn resetStream(
        self: *SendStream,
        error_code: u64,
    ) Error!void {
        if (self.reset != null) return;
        self.reset = .{ .error_code = error_code, .final_size = self.write_offset };
        self.state = .reset_sent;
        // Drop any pending data; we'll never send it.
        self.pending.clearRetainingCapacity();
        // In-flight bytes stay tracked so we can correctly handle
        // their ACK/loss outcomes (and not re-pend them on loss).
    }

    /// True if the stream is fully terminated (data_recvd or reset_recvd).
    pub fn isTerminal(self: *const SendStream) bool {
        return self.state == .data_recvd or self.state == .reset_recvd;
    }

    /// Total bytes ever queued by the app.
    pub fn writtenBytes(self: *const SendStream) u64 {
        return self.write_offset;
    }

    /// Bytes contiguously ACKed from offset 0.
    pub fn ackedFloor(self: *const SendStream) u64 {
        return self.base_offset;
    }

    /// Are there bytes (or a FIN) ready to send right now?
    pub fn hasPendingChunk(self: *const SendStream) bool {
        if (self.reset) |r| return !r.queued;
        if (self.pending.items.len > 0) return true;
        if (self.fin_marked and !self.fin_in_flight and !self.fin_acked) return true;
        return false;
    }

    /// Peek the next chunk we'd ship without consuming it. The
    /// chunk is bounded by `max_bytes`. Returns null if there's
    /// nothing to send.
    pub fn peekChunk(self: *const SendStream, max_bytes: usize) ?Chunk {
        if (self.reset != null) return null;
        if (self.pending.items.len == 0) {
            if (self.fin_marked and !self.fin_in_flight and !self.fin_acked) {
                // Pure FIN chunk at final_size.
                return .{ .offset = self.final_size.?, .length = 0, .fin = true };
            }
            return null;
        }
        const r = self.pending.items[0];
        const take: u64 = @min(@as(u64, max_bytes), r.end - r.offset);
        const fin = self.fin_marked and !self.fin_in_flight and !self.fin_acked and
            r.offset + take == self.final_size.?;
        return .{ .offset = r.offset, .length = take, .fin = fin };
    }

    /// Borrow the bytes for a chunk so the caller can copy them
    /// into a STREAM frame. The slice is valid until the next
    /// mutation of the buffer (write, ACK floor advance, or
    /// resetStream). 0-length chunks (pure FIN) return an empty
    /// slice.
    pub fn chunkBytes(self: *const SendStream, c: Chunk) []const u8 {
        if (c.length == 0) return &.{};
        const start: usize = @intCast(c.offset - self.base_offset);
        const end: usize = start + @as(usize, @intCast(c.length));
        return self.bytes.items[start..end];
    }

    /// Record that the given chunk has been packed into a packet
    /// with packet number `pn` and is now in-flight. Removes the
    /// covered offsets from `pending` and stores the chunk under `pn`.
    pub fn recordSent(self: *SendStream, pn: u64, c: Chunk) Error!void {
        if (self.in_flight.contains(pn)) return Error.InvalidChunk;

        if (c.length > 0) {
            // The chunk must be a prefix of the first pending range.
            if (self.pending.items.len == 0) return Error.InvalidChunk;
            const r = self.pending.items[0];
            if (c.offset != r.offset) return Error.InvalidChunk;
            if (c.offset + c.length > r.end) return Error.InvalidChunk;

            if (c.offset + c.length == r.end) {
                _ = self.pending.orderedRemove(0);
            } else {
                self.pending.items[0].offset = c.offset + c.length;
            }
        } else if (!c.fin) {
            return Error.InvalidChunk;
        }

        if (c.fin) {
            if (self.fin_in_flight or self.fin_acked) return Error.InvalidChunk;
            if (self.final_size == null or
                c.offset + c.length != self.final_size.?)
            {
                return Error.InvalidChunk;
            }
            self.fin_in_flight = true;
        }

        try self.in_flight.put(self.allocator, pn, c);
    }

    /// Process an ACK for the packet identified by `pn`. Returns
    /// `Error.UnknownPacket` if the PN doesn't have an in-flight
    /// chunk for this stream (the caller should treat that as a
    /// no-op since not every ACKed packet carries this stream).
    pub fn onPacketAcked(self: *SendStream, pn: u64) Error!void {
        const entry = self.in_flight.fetchRemove(pn) orelse return Error.UnknownPacket;
        const c = entry.value;
        if (c.fin) self.fin_acked = true;
        if (c.length > 0) try self.markAcked(.{ .offset = c.offset, .end = c.offset + c.length });
        self.maybeAdvanceState();
    }

    /// Process a loss for the packet identified by `pn`. The chunk
    /// re-enters the pending queue (unless we're in `reset_sent`,
    /// in which case losses are silently dropped).
    pub fn onPacketLost(self: *SendStream, pn: u64) Error!void {
        const entry = self.in_flight.fetchRemove(pn) orelse return Error.UnknownPacket;
        const c = entry.value;

        if (self.reset != null) return; // RESET_STREAM supersedes data losses

        if (c.length > 0) {
            try self.addPending(.{ .offset = c.offset, .end = c.offset + c.length });
        }
        if (c.fin) {
            self.fin_in_flight = false;
        }
    }

    /// Process ACK/loss for a RESET_STREAM frame carried by a packet.
    pub fn onResetAcked(self: *SendStream) void {
        if (self.reset) |*r| {
            r.acked = true;
            self.maybeAdvanceState();
        }
    }

    pub fn onResetLost(self: *SendStream) void {
        if (self.reset) |*r| {
            if (!r.acked) r.queued = false;
        }
    }

    /// Queue `r` into `pending`, merging with adjacent existing
    /// ranges where possible.
    fn addPending(self: *SendStream, r: Range) Error!void {
        try insertMerge(&self.pending, self.allocator, r);
    }

    /// Mark `r` as acked. Either advance `base_offset` and drop
    /// covered bytes from `bytes`, or stash into `acked_above`.
    fn markAcked(self: *SendStream, r: Range) Error!void {
        if (r.offset != self.base_offset) {
            try insertMerge(&self.acked_above, self.allocator, r);
            return;
        }
        // Contiguous with the floor: advance, then absorb anything
        // in `acked_above` that's now contiguous.
        self.advanceFloor(r.end);
        while (self.acked_above.items.len > 0 and
            self.acked_above.items[0].offset == self.base_offset)
        {
            const first = self.acked_above.orderedRemove(0);
            self.advanceFloor(first.end);
        }
    }

    fn advanceFloor(self: *SendStream, new_floor: u64) void {
        std.debug.assert(new_floor >= self.base_offset);
        std.debug.assert(new_floor <= self.write_offset);
        const drop_n: usize = @intCast(new_floor - self.base_offset);
        if (drop_n == 0) return;
        // Shift the live tail down. For a v1 implementation this is
        // O(N) per advance; a ring buffer is a future optimization.
        const live_len = self.bytes.items.len - drop_n;
        std.mem.copyForwards(
            u8,
            self.bytes.items[0..live_len],
            self.bytes.items[drop_n..],
        );
        self.bytes.shrinkRetainingCapacity(live_len);
        self.base_offset = new_floor;
    }

    fn maybeAdvanceState(self: *SendStream) void {
        if (self.state == .reset_sent) {
            if (self.reset.?.acked) self.state = .reset_recvd;
            return;
        }
        if (self.fin_acked and self.fin_marked and
            self.base_offset == self.final_size.?)
        {
            self.state = .data_recvd;
        }
    }
};

/// Insert `new` into a sorted-disjoint range list, merging with any
/// adjacent or overlapping existing range. The list grows by at
/// most one slot.
fn insertMerge(
    list: *std.ArrayList(Range),
    allocator: std.mem.Allocator,
    new: Range,
) std.mem.Allocator.Error!void {
    if (new.offset >= new.end) return;

    // Find the first range whose end >= new.offset (i.e., the first
    // range that could overlap or touch `new` from below or itself).
    var i: usize = 0;
    while (i < list.items.len and list.items[i].end < new.offset) : (i += 1) {}

    // No overlap on either side: pure insert.
    if (i == list.items.len or list.items[i].offset > new.end) {
        try list.insert(allocator, i, new);
        return;
    }

    // Merge with list.items[i] and any further ranges it now connects to.
    var merged: Range = .{
        .offset = @min(list.items[i].offset, new.offset),
        .end = @max(list.items[i].end, new.end),
    };
    var j: usize = i + 1;
    while (j < list.items.len and list.items[j].offset <= merged.end) : (j += 1) {
        merged.end = @max(merged.end, list.items[j].end);
    }
    // Replace [i, j) with the single merged range.
    list.replaceRangeAssumeCapacity(i, j - i, &.{merged});
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;
const test_alloc = std.testing.allocator;

test "write then peekChunk yields the queued bytes" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();

    const n = try s.write("hello");
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqual(@as(u64, 5), s.writtenBytes());
    try testing.expectEqual(State.send, s.state);

    const c = s.peekChunk(10).?;
    try testing.expectEqual(@as(u64, 0), c.offset);
    try testing.expectEqual(@as(u64, 5), c.length);
    try testing.expect(!c.fin);
    try testing.expectEqualStrings("hello", s.chunkBytes(c));
}

test "peek bounded by max_bytes" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("0123456789");

    const c = s.peekChunk(3).?;
    try testing.expectEqual(@as(u64, 3), c.length);
    try testing.expectEqualStrings("012", s.chunkBytes(c));
}

test "recordSent removes the prefix from pending" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("0123456789");

    try s.recordSent(0, .{ .offset = 0, .length = 4, .fin = false });
    const c = s.peekChunk(100).?;
    try testing.expectEqual(@as(u64, 4), c.offset);
    try testing.expectEqual(@as(u64, 6), c.length);
}

test "ack of in-order chunk advances base_offset and drops bytes" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("0123456789");

    try s.recordSent(0, .{ .offset = 0, .length = 5, .fin = false });
    try testing.expectEqual(@as(u64, 0), s.ackedFloor());

    try s.onPacketAcked(0);
    try testing.expectEqual(@as(u64, 5), s.ackedFloor());
    try testing.expectEqual(@as(usize, 5), s.bytes.items.len);
    try testing.expectEqualStrings("56789", s.bytes.items);
}

test "out-of-order ACK is held until the gap closes" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("aaaabbbbcccc"); // 12 bytes

    try s.recordSent(0, .{ .offset = 0, .length = 4, .fin = false });
    try s.recordSent(1, .{ .offset = 4, .length = 4, .fin = false });
    try s.recordSent(2, .{ .offset = 8, .length = 4, .fin = false });

    // ACK only the middle chunk.
    try s.onPacketAcked(1);
    try testing.expectEqual(@as(u64, 0), s.ackedFloor());
    try testing.expectEqual(@as(usize, 1), s.acked_above.items.len);

    // Now ACK the first chunk → floor jumps to 8 by absorbing the
    // pending-acked middle range.
    try s.onPacketAcked(0);
    try testing.expectEqual(@as(u64, 8), s.ackedFloor());
    try testing.expectEqual(@as(usize, 0), s.acked_above.items.len);
    try testing.expectEqualStrings("cccc", s.bytes.items);

    // Final ACK collapses everything.
    try s.onPacketAcked(2);
    try testing.expectEqual(@as(u64, 12), s.ackedFloor());
    try testing.expectEqual(@as(usize, 0), s.bytes.items.len);
}

test "loss re-pends the chunk's bytes" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("0123456789");

    try s.recordSent(0, .{ .offset = 0, .length = 5, .fin = false });
    try s.recordSent(1, .{ .offset = 5, .length = 5, .fin = false });

    try s.onPacketLost(0);
    // Pending now has [0..5) at the head again. peekChunk should
    // give us 0..5.
    const c = s.peekChunk(100).?;
    try testing.expectEqual(@as(u64, 0), c.offset);
    try testing.expectEqual(@as(u64, 5), c.length);
}

test "loss merges with adjacent pending ranges" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("0123456789");

    try s.recordSent(0, .{ .offset = 0, .length = 5, .fin = false });
    // Bytes [5..10) still pending; lose [0..5) → it should merge.
    try s.onPacketLost(0);
    try testing.expectEqual(@as(usize, 1), s.pending.items.len);
    try testing.expectEqual(@as(u64, 0), s.pending.items[0].offset);
    try testing.expectEqual(@as(u64, 10), s.pending.items[0].end);
}

test "FIN appears on the chunk that covers final_size" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("hello");
    try s.finish();

    const c = s.peekChunk(100).?;
    try testing.expectEqual(@as(u64, 0), c.offset);
    try testing.expectEqual(@as(u64, 5), c.length);
    try testing.expect(c.fin);
}

test "FIN deferred when chunk is short of final_size" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("hello");
    try s.finish();

    const c = s.peekChunk(3).?;
    try testing.expectEqual(@as(u64, 3), c.length);
    try testing.expect(!c.fin);
}

test "pure FIN chunk emitted when finish() called with no bytes left to send" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("ok");
    try s.recordSent(0, .{ .offset = 0, .length = 2, .fin = false });
    try s.finish();

    const c = s.peekChunk(100).?;
    try testing.expectEqual(@as(u64, 2), c.offset);
    try testing.expectEqual(@as(u64, 0), c.length);
    try testing.expect(c.fin);
}

test "FIN+data chunk: ACK transitions to data_recvd" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("hi");
    try s.finish();

    const c = s.peekChunk(100).?;
    try s.recordSent(0, c);
    try testing.expectEqual(State.data_sent, s.state);

    try s.onPacketAcked(0);
    try testing.expectEqual(State.data_recvd, s.state);
    try testing.expect(s.fin_acked);
    try testing.expect(s.isTerminal());
}

test "loss of FIN un-flags fin_in_flight so it gets re-sent" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("a");
    try s.finish();

    const c = s.peekChunk(100).?;
    try s.recordSent(0, c);
    try testing.expect(s.fin_in_flight);

    try s.onPacketLost(0);
    try testing.expect(!s.fin_in_flight);

    const c2 = s.peekChunk(100).?;
    try testing.expectEqual(@as(u64, 0), c2.offset);
    try testing.expectEqual(@as(u64, 1), c2.length);
    try testing.expect(c2.fin);
}

test "resetStream drops pending data and stops further writes" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("hello");

    try s.resetStream(42);
    try testing.expectEqual(State.reset_sent, s.state);
    try testing.expectEqual(@as(usize, 0), s.pending.items.len);

    try testing.expectError(Error.StreamClosed, s.write("more"));
}

test "write after finish errors with StreamClosed" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    try s.finish();
    try testing.expectError(Error.StreamClosed, s.write("late"));
}

test "recordSent rejects chunk that doesn't match pending head" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("0123456789");

    // Wrong offset.
    try testing.expectError(Error.InvalidChunk, s.recordSent(0, .{ .offset = 5, .length = 3, .fin = false }));
    // Past the end of pending.
    try testing.expectError(Error.InvalidChunk, s.recordSent(0, .{ .offset = 0, .length = 11, .fin = false }));
}

test "recordSent rejects duplicate PN" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("hello");

    try s.recordSent(7, .{ .offset = 0, .length = 2, .fin = false });
    try testing.expectError(Error.InvalidChunk, s.recordSent(7, .{ .offset = 2, .length = 1, .fin = false }));
}

test "onPacketAcked for unknown PN returns UnknownPacket" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    try testing.expectError(Error.UnknownPacket, s.onPacketAcked(99));
}

test "loss after reset is a no-op (chunk dropped silently)" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("hello");
    try s.recordSent(0, .{ .offset = 0, .length = 5, .fin = false });
    try s.resetStream(7);

    try s.onPacketLost(0);
    try testing.expectEqual(@as(usize, 0), s.pending.items.len);
}

test "RESET_STREAM ack/loss updates queued state" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();

    _ = try s.write("hello");
    try s.resetStream(77);
    try testing.expect(s.reset != null);
    s.reset.?.queued = true;

    s.onResetLost();
    try testing.expect(!s.reset.?.queued);

    s.reset.?.queued = true;
    s.onResetAcked();
    try testing.expect(s.reset.?.acked);
    try testing.expectEqual(State.reset_recvd, s.state);

    s.onResetLost();
    try testing.expect(s.reset.?.queued);
}

test "stress: 256 KiB through a tiny chunk size with random ACK order" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();

    const total: usize = 256 * 1024;
    var data: [total]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    prng.random().bytes(&data);
    _ = try s.write(&data);
    try s.finish();

    // Send in 1024-byte chunks.
    var pn: u64 = 0;
    var sent_pns: std.ArrayList(u64) = .empty;
    defer sent_pns.deinit(test_alloc);

    while (s.peekChunk(1024)) |c| {
        try s.recordSent(pn, c);
        try sent_pns.append(test_alloc, pn);
        pn += 1;
    }

    // Shuffle and ACK every PN.
    prng.random().shuffle(u64, sent_pns.items);
    for (sent_pns.items) |p| try s.onPacketAcked(p);

    try testing.expect(s.isTerminal());
    try testing.expectEqual(@as(u64, total), s.ackedFloor());
    try testing.expectEqual(@as(usize, 0), s.bytes.items.len);
}

test "stress with simulated 10% loss until convergence" {
    var s = SendStream.init(test_alloc);
    defer s.deinit();

    const total: usize = 64 * 1024;
    var data: [total]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    prng.random().bytes(&data);
    _ = try s.write(&data);
    try s.finish();

    var pn: u64 = 0;
    var attempts: usize = 0;
    const max_attempts: usize = 10_000;

    while (!s.isTerminal() and attempts < max_attempts) : (attempts += 1) {
        const c = s.peekChunk(1024) orelse break;
        try s.recordSent(pn, c);

        // 10% loss, otherwise ACK.
        if (prng.random().intRangeAtMost(u32, 0, 99) < 10) {
            try s.onPacketLost(pn);
        } else {
            try s.onPacketAcked(pn);
        }
        pn += 1;
    }

    try testing.expect(s.isTerminal());
    try testing.expectEqual(@as(u64, total), s.ackedFloor());
}
