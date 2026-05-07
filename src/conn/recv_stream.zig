//! Receive-side stream buffer (RFC 9000 §3.2, §19.8).
//!
//! Accepts STREAM frames at arbitrary offsets, performs gap
//! reassembly, and hands the application in-order bytes via
//! `read`. Tracks RESET_STREAM and FIN; enforces the §4.5 invariant
//! that a stream's final size is consistent across all frames.
//!
//! Storage is a single contiguous buffer indexed by absolute
//! offset minus `read_offset`. The set of valid byte ranges is
//! tracked in `ranges` (sorted, disjoint); bytes outside any range
//! are allocated but undefined. As the app consumes bytes via
//! `read`, the prefix is dropped and the buffer shrinks.
//!
//! Stream-level flow control (§4) is enforced *outside* this
//! module by `flow_control.StreamData`; the recv buffer surfaces
//! `bufferedBytes` and `peerHighestOffset` so the caller can feed
//! them in.

const std = @import("std");

/// Errors raised by `recv` and `resetStream`.
pub const Error = error{
    /// Peer sent bytes past a previously-locked final size
    /// (RFC 9000 §4.5 / FINAL_SIZE_ERROR).
    BeyondFinalSize,
    /// FIN or RESET_STREAM tries to set a final size that conflicts
    /// with the size already locked by an earlier FIN/RESET, or that
    /// is below the highest offset we've already received bytes for
    /// (RFC 9000 §4.5 / FINAL_SIZE_ERROR).
    FinalSizeChanged,
    /// The frame would force the reassembly buffer to cover an
    /// implementation-defined, peer-controlled span.
    BufferLimitExceeded,
} || std.mem.Allocator.Error;

/// Default cap for the contiguous receive reassembly span of one
/// stream. This is intentionally independent from QUIC flow control:
/// flow control is a protocol limit, while this is an allocation
/// guard against sparse offsets before fuller stream windows land.
pub const default_max_buffered_span: u64 = 16 * 1024 * 1024;

/// State of the receive half (RFC 9000 §3.2):
/// recv → size_known → data_recvd → data_read
///                          ↘ reset_recvd → reset_read
pub const State = enum {
    recv,
    size_known,
    data_recvd,
    data_read,
    reset_recvd,
    reset_read,
};

/// Half-open interval `[offset, end)` of received stream bytes.
pub const Range = struct {
    offset: u64,
    end: u64,

    /// Length of the range in bytes.
    pub fn len(self: Range) u64 {
        return self.end - self.offset;
    }
};

/// State recorded when the peer sends RESET_STREAM (RFC 9000 §19.4).
pub const ResetInfo = struct {
    error_code: u64,
    final_size: u64,
};

/// One stream's receive half: STREAM-frame buffering, in-order
/// reassembly, RESET_STREAM and FIN handling.
pub const RecvStream = struct {
    allocator: std.mem.Allocator,

    /// Backing storage indexed by `offset - read_offset`.
    bytes: std.ArrayList(u8) = .empty,
    /// Absolute offset of the first byte in `bytes`. Bytes
    /// < read_offset have been read by the app and dropped.
    read_offset: u64 = 0,
    /// One past the highest absolute offset anything has touched.
    end_offset: u64 = 0,

    /// Sorted disjoint ranges of received bytes, in absolute
    /// offsets. All ranges have offset >= read_offset and end <=
    /// end_offset.
    ranges: std.ArrayList(Range) = .empty,

    /// Final stream size, set when FIN or RESET_STREAM arrives.
    final_size: ?u64 = null,
    /// True iff a STREAM frame with the FIN bit was accepted.
    fin_seen: bool = false,
    /// Non-null when RESET_STREAM has been processed.
    reset: ?ResetInfo = null,

    /// Maximum contiguous span `bytes` may cover from `read_offset`.
    max_buffered_span: u64 = default_max_buffered_span,

    state: State = .recv,

    /// Construct an empty receive buffer that owns its allocations.
    pub fn init(allocator: std.mem.Allocator) RecvStream {
        return .{ .allocator = allocator };
    }

    /// Free the reassembly buffer and range list.
    pub fn deinit(self: *RecvStream) void {
        self.bytes.deinit(self.allocator);
        self.ranges.deinit(self.allocator);
        self.* = undefined;
    }

    /// Highest absolute offset the peer has touched (for connection
    /// flow-control accounting).
    pub fn peerHighestOffset(self: *const RecvStream) u64 {
        return self.end_offset;
    }

    /// Bytes currently buffered (not yet read by the app). Sum of
    /// all `ranges` — useful as a stream-level flow-control hint
    /// alongside `peerHighestOffset`.
    pub fn bufferedBytes(self: *const RecvStream) u64 {
        var sum: u64 = 0;
        for (self.ranges.items) |r| sum += r.end - r.offset;
        return sum;
    }

    /// In-order bytes ready to be read by the app: the size of the
    /// lowest range if it starts at `read_offset`, else 0.
    pub fn readableBytes(self: *const RecvStream) u64 {
        if (self.ranges.items.len == 0) return 0;
        const r = self.ranges.items[0];
        if (r.offset != self.read_offset) return 0;
        return r.end - r.offset;
    }

    /// Has the app read every byte and seen the FIN?
    pub fn isClosed(self: *const RecvStream) bool {
        return self.state == .data_read or self.state == .reset_read;
    }

    /// Process a STREAM frame from the peer. `data` covers absolute
    /// offsets [offset, offset+data.len). Duplicates and overlaps
    /// are accepted (only the new bytes are buffered).
    pub fn recv(
        self: *RecvStream,
        offset: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.reset != null) return; // RESET_STREAM ignores subsequent data
        if (self.state == .data_recvd or self.state == .data_read) return;

        const data_len: u64 = @intCast(data.len);
        const new_end = std.math.add(u64, offset, data_len) catch return Error.BufferLimitExceeded;

        // §4.5: data can never extend past a locked final_size.
        if (self.final_size) |fs| {
            if (new_end > fs) return Error.BeyondFinalSize;
        }

        // FIN tries to lock final_size = new_end.
        if (fin) {
            if (self.final_size) |fs| {
                if (fs != new_end) return Error.FinalSizeChanged;
            } else {
                // Make sure existing high-water mark fits inside the
                // newly-locked size.
                if (self.end_offset > new_end) return Error.FinalSizeChanged;
                self.final_size = new_end;
            }
            self.fin_seen = true;
            if (self.state == .recv) self.state = .size_known;
        }

        // Bytes below read_offset are already-consumed duplicates.
        var clip_offset = offset;
        var clip_data = data;
        if (clip_offset < self.read_offset) {
            const skip = self.read_offset - clip_offset;
            if (skip >= clip_data.len) {
                // Entirely below the floor.
                self.maybeAdvanceState();
                return;
            }
            clip_offset = self.read_offset;
            clip_data = clip_data[@intCast(skip)..];
        }
        if (clip_data.len == 0) {
            // Track the high water-mark after the frame has passed
            // overflow checks, even when it only carried duplicates.
            if (new_end > self.end_offset) self.end_offset = new_end;
            self.maybeAdvanceState();
            return;
        }

        // Make sure the buffer covers up to clip_offset+clip_data.len.
        const clip_data_len: u64 = @intCast(clip_data.len);
        const clip_end = std.math.add(u64, clip_offset, clip_data_len) catch return Error.BufferLimitExceeded;
        const span = clip_end - self.read_offset;
        if (span > self.max_buffered_span) return Error.BufferLimitExceeded;
        const buf_required: usize = @intCast(span);
        if (self.bytes.items.len < buf_required) {
            const grow_by = buf_required - self.bytes.items.len;
            const slack = try self.bytes.addManyAsSlice(self.allocator, grow_by);
            @memset(slack, 0);
        }

        // Track the high water-mark only after sparse-offset allocation
        // limits have accepted the frame.
        if (new_end > self.end_offset) self.end_offset = new_end;

        // Walk over `clip_data`, writing only the bytes that fall
        // into gaps (no overlap with an existing range).
        var pos = clip_offset;
        var idx_in: usize = 0;
        var i: usize = 0;
        // Find the first range whose end > pos.
        while (i < self.ranges.items.len and self.ranges.items[i].end <= pos) : (i += 1) {}

        while (idx_in < clip_data.len) {
            const remaining = clip_data.len - idx_in;
            const seg_end = pos + remaining;

            // Determine the next "covered" range that intersects [pos, seg_end).
            var covered_start: u64 = seg_end;
            var covered_end: u64 = seg_end;
            if (i < self.ranges.items.len) {
                const r = self.ranges.items[i];
                if (r.offset < seg_end) {
                    covered_start = @max(r.offset, pos);
                    covered_end = @min(r.end, seg_end);
                }
            }

            // Bytes in [pos, covered_start) are new — write them.
            const new_end_pos: u64 = covered_start;
            if (new_end_pos > pos) {
                const buf_pos: usize = @intCast(pos - self.read_offset);
                const buf_len: usize = @intCast(new_end_pos - pos);
                @memcpy(
                    self.bytes.items[buf_pos .. buf_pos + buf_len],
                    clip_data[idx_in .. idx_in + buf_len],
                );
                idx_in += buf_len;
                pos = new_end_pos;
            }

            // Bytes in [covered_start, covered_end) overlap an
            // existing range — skip.
            if (covered_end > pos) {
                const skip_len: usize = @intCast(covered_end - pos);
                idx_in += skip_len;
                pos = covered_end;
                i += 1;
            }
        }

        // Now insert the original [clip_offset, new_end) into the
        // range list, merging neighbors.
        try insertMerge(&self.ranges, self.allocator, .{
            .offset = clip_offset,
            .end = clip_end,
        });

        self.maybeAdvanceState();
    }

    /// Read up to `dst.len` in-order bytes into `dst`. Returns the
    /// number of bytes actually written. Returns 0 when no bytes
    /// are available — call `readableBytes` first if you want to
    /// distinguish "would block" from "stream done".
    pub fn read(self: *RecvStream, dst: []u8) usize {
        if (self.ranges.items.len == 0) {
            self.maybeAdvanceState();
            return 0;
        }
        const r = self.ranges.items[0];
        if (r.offset != self.read_offset) return 0;

        const avail: usize = @intCast(r.end - r.offset);
        const take: usize = @min(dst.len, avail);
        @memcpy(dst[0..take], self.bytes.items[0..take]);

        // Shift the buffer down.
        const live_len = self.bytes.items.len - take;
        std.mem.copyForwards(u8, self.bytes.items[0..live_len], self.bytes.items[take..]);
        self.bytes.shrinkRetainingCapacity(live_len);
        self.read_offset += take;

        // Update range head.
        if (take == avail) {
            _ = self.ranges.orderedRemove(0);
        } else {
            self.ranges.items[0].offset += take;
        }

        self.maybeAdvanceState();

        // Once the stream is fully drained and FIN has been seen,
        // the buffer will never grow again — release the backing
        // capacity so a long-lived connection doesn't accumulate
        // peak-sized allocations across short streams. The connection
        // budget is keyed on `bytes.items.len`, which is already 0
        // here, so this is purely a physical-allocator return; no
        // additional budget bookkeeping is required.
        if (self.state == .data_recvd and self.bytes.items.len == 0) {
            self.compact();
        }

        return take;
    }

    /// Process a RESET_STREAM frame from the peer. Subsequent data
    /// is ignored.
    pub fn resetStream(
        self: *RecvStream,
        error_code: u64,
        final_size_in: u64,
    ) Error!void {
        if (self.reset != null) return; // duplicate; already handled
        if (self.fin_seen and self.final_size != null and self.final_size.? != final_size_in) {
            return Error.FinalSizeChanged;
        }
        if (self.end_offset > final_size_in) {
            return Error.FinalSizeChanged;
        }
        self.reset = .{ .error_code = error_code, .final_size = final_size_in };
        self.final_size = final_size_in;
        self.state = .reset_recvd;
        // Any buffered bytes are now dead — the application will never
        // see them. Drop the live items and release the backing
        // capacity. The caller (Connection.handleResetStream) is
        // responsible for releasing the connection-wide budget for the
        // bytes that just disappeared from `bytes.items.len`.
        self.compact();
    }

    /// Drop any buffered bytes and reassembly metadata, returning
    /// backing capacity to the allocator. Safe to call any time the
    /// caller has decided no further bytes will be delivered to the
    /// app — i.e. after RESET_STREAM, or after FIN-and-fully-drained
    /// (state == .data_recvd or .data_read).
    ///
    /// Idempotent. Does not touch `read_offset`, `end_offset`,
    /// `final_size`, `fin_seen`, `reset`, or `state`.
    ///
    /// The connection-wide resident-bytes budget is keyed on
    /// `bytes.items.len`, so a caller that snapshots `items.len`
    /// before invoking `compact` (directly or via `read` / `resetStream`
    /// /`recv` after final-size lock) and releases the difference will
    /// keep the budget honest. This method does NOT call back into the
    /// connection — `RecvStream` has no knowledge of it.
    pub fn compact(self: *RecvStream) void {
        if (self.bytes.items.len > 0) {
            self.bytes.clearRetainingCapacity();
        }
        if (self.bytes.capacity > 0) {
            self.bytes.shrinkAndFree(self.allocator, 0);
        }
        if (self.ranges.items.len > 0) {
            self.ranges.clearRetainingCapacity();
        }
        if (self.ranges.capacity > 0) {
            self.ranges.shrinkAndFree(self.allocator, 0);
        }
    }

    /// Mark the stream as fully read by the app — only meaningful
    /// after every byte has been delivered. Idempotent.
    pub fn markRead(self: *RecvStream) void {
        if (self.state == .data_recvd) self.state = .data_read;
        if (self.state == .reset_recvd) self.state = .reset_read;
    }

    fn maybeAdvanceState(self: *RecvStream) void {
        if (self.reset != null) return;
        if (!self.fin_seen) return;
        // FIN seen + every byte delivered => data_recvd.
        if (self.read_offset == self.final_size.? and self.ranges.items.len == 0) {
            if (self.state != .data_read) self.state = .data_recvd;
        } else if (self.ranges.items.len == 1 and
            self.ranges.items[0].offset == self.read_offset and
            self.ranges.items[0].end == self.final_size.?)
        {
            // All bytes received, just not yet read.
            if (self.state == .recv or self.state == .size_known) {
                // stay in size_known until read drains; data_recvd
                // is reserved for the post-read terminal.
                self.state = .size_known;
            }
        }
    }
};

fn insertMerge(
    list: *std.ArrayList(Range),
    allocator: std.mem.Allocator,
    new: Range,
) std.mem.Allocator.Error!void {
    if (new.offset >= new.end) return;

    var i: usize = 0;
    while (i < list.items.len and list.items[i].end < new.offset) : (i += 1) {}

    if (i == list.items.len or list.items[i].offset > new.end) {
        try list.insert(allocator, i, new);
        return;
    }

    var merged: Range = .{
        .offset = @min(list.items[i].offset, new.offset),
        .end = @max(list.items[i].end, new.end),
    };
    var j: usize = i + 1;
    while (j < list.items.len and list.items[j].offset <= merged.end) : (j += 1) {
        merged.end = @max(merged.end, list.items[j].end);
    }
    list.replaceRangeAssumeCapacity(i, j - i, &.{merged});
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;
const test_alloc = std.testing.allocator;

test "in-order recv + read" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "hello", false);
    try testing.expectEqual(@as(u64, 5), s.readableBytes());

    var out: [10]u8 = undefined;
    const n = s.read(&out);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualStrings("hello", out[0..5]);
    try testing.expectEqual(@as(u64, 5), s.read_offset);
    try testing.expectEqual(@as(u64, 0), s.readableBytes());
}

test "out-of-order recv buffers until gap closes" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(5, "world", false);
    try testing.expectEqual(@as(u64, 0), s.readableBytes()); // gap
    try testing.expectEqual(@as(u64, 5), s.bufferedBytes());

    try s.recv(0, "hello", false);
    try testing.expectEqual(@as(u64, 10), s.readableBytes());

    var out: [16]u8 = undefined;
    const n = s.read(&out);
    try testing.expectEqual(@as(usize, 10), n);
    try testing.expectEqualStrings("helloworld", out[0..10]);
}

test "duplicate recv is accepted; old bytes win" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abcdef", false);
    // Resend an overlapping prefix — should be a no-op.
    try s.recv(0, "ZZZdef", false);

    var out: [16]u8 = undefined;
    const n = s.read(&out);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualStrings("abcdef", out[0..6]);
}

test "FIN locks final_size and transitions to size_known then data_recvd after read" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", true);
    try testing.expectEqual(@as(?u64, 3), s.final_size);
    try testing.expect(s.fin_seen);
    try testing.expectEqual(State.size_known, s.state);

    var out: [10]u8 = undefined;
    _ = s.read(&out);
    try testing.expectEqual(State.data_recvd, s.state);
    s.markRead();
    try testing.expectEqual(State.data_read, s.state);
    try testing.expect(s.isClosed());
}

test "reject bytes past locked final_size" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", true);
    try testing.expectError(Error.BeyondFinalSize, s.recv(3, "more", false));
}

test "reject FIN with mismatched final_size" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", true);
    // Resend bytes within the locked size — fine.
    try s.recv(0, "abc", false);
    // FIN with a different end — error.
    try testing.expectError(Error.FinalSizeChanged, s.recv(0, "ab", true));
}

test "RESET_STREAM transitions to reset_recvd; further bytes ignored" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", false);
    try s.resetStream(7, 3);
    try testing.expectEqual(State.reset_recvd, s.state);

    // After reset, recv is silently ignored.
    try s.recv(3, "x", false);
    try testing.expectEqual(@as(u64, 3), s.end_offset);

    s.markRead();
    try testing.expectEqual(State.reset_read, s.state);
}

test "RESET_STREAM with final_size below already-received offset is an error" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abcdef", false);
    try testing.expectError(Error.FinalSizeChanged, s.resetStream(7, 3));
}

test "interleaved out-of-order chunks reassemble correctly" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    // Insert in scrambled order: [4..6), [0..2), [2..4), [6..10) with FIN.
    try s.recv(4, "ef", false);
    try s.recv(0, "ab", false);
    try s.recv(2, "cd", false);
    try s.recv(6, "ghij", true);

    try testing.expectEqual(@as(u64, 10), s.readableBytes());
    var out: [16]u8 = undefined;
    const n = s.read(&out);
    try testing.expectEqual(@as(usize, 10), n);
    try testing.expectEqualStrings("abcdefghij", out[0..n]);
}

test "FIN that would shrink the stream below already-received bytes is an error" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(10, "kl", false); // end_offset = 12
    try testing.expectError(Error.FinalSizeChanged, s.recv(0, "abcdef", true));
}

test "partial read advances head; second read drains the rest" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();
    try s.recv(0, "abcdef", false);

    var out: [4]u8 = undefined;
    var n = s.read(&out);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualStrings("abcd", &out);

    var out2: [10]u8 = undefined;
    n = s.read(&out2);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("ef", out2[0..2]);
}

test "duplicate-after-read bytes are skipped" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abcdef", false);
    var out: [3]u8 = undefined;
    _ = s.read(&out);
    try testing.expectEqualStrings("abc", &out);

    // Resend bytes 0..6 — only 6.. would be new, and that range
    // doesn't extend the stream, so the call is essentially a no-op.
    try s.recv(0, "abcdef", false);

    try testing.expectEqual(@as(u64, 3), s.readableBytes());
}

test "sparse STREAM offsets are bounded before allocation" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();
    s.max_buffered_span = 16;

    try testing.expectError(Error.BufferLimitExceeded, s.recv(1024, "x", false));
    try testing.expectEqual(@as(usize, 0), s.bytes.items.len);
    try testing.expectEqual(@as(u64, 0), s.end_offset);
}

test "STREAM offset overflow is rejected before mutation" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try testing.expectError(Error.BufferLimitExceeded, s.recv(std.math.maxInt(u64), "x", false));
    try testing.expectEqual(@as(usize, 0), s.bytes.items.len);
    try testing.expectEqual(@as(u64, 0), s.end_offset);
}

test "stress: 64 KiB random shuffle reassembles in order with FIN" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    const total: usize = 64 * 1024;
    var data: [total]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xa11ce);
    prng.random().bytes(&data);

    const chunk: usize = 1024;
    const chunks = total / chunk;
    var indices: [chunks]usize = undefined;
    for (&indices, 0..) |*x, i| x.* = i;
    prng.random().shuffle(usize, &indices);

    for (indices, 0..) |idx, k| {
        const off: u64 = @intCast(idx * chunk);
        const slice = data[off..][0..chunk];
        const fin = (k == chunks - 1) and idx == chunks - 1;
        try s.recv(off, slice, fin);
    }

    // The last shuffled chunk may not be the "logical last" — make
    // sure FIN was set on the final-offset chunk specifically.
    if (s.final_size == null) {
        try s.recv(@intCast((chunks - 1) * chunk), data[(chunks - 1) * chunk ..], true);
    }

    var consumed: usize = 0;
    var rbuf: [4096]u8 = undefined;
    while (consumed < total) {
        const n = s.read(&rbuf);
        if (n == 0) break;
        try testing.expectEqualSlices(u8, data[consumed .. consumed + n], rbuf[0..n]);
        consumed += n;
    }
    try testing.expectEqual(total, consumed);
    try testing.expectEqual(State.data_recvd, s.state);
}

test "compact: peak buffer capacity is released after fully draining a 1 MiB stream" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();
    s.max_buffered_span = 4 * 1024 * 1024;

    const total: usize = 1024 * 1024;
    const payload = try test_alloc.alloc(u8, total);
    defer test_alloc.free(payload);
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    prng.random().bytes(payload);

    try s.recv(0, payload, true);
    try testing.expectEqual(State.size_known, s.state);
    try testing.expect(s.bytes.capacity >= total);

    var rbuf: [4096]u8 = undefined;
    var consumed: usize = 0;
    while (consumed < total) {
        const n = s.read(&rbuf);
        try testing.expect(n > 0);
        try testing.expectEqualSlices(u8, payload[consumed..][0..n], rbuf[0..n]);
        consumed += n;
    }

    try testing.expectEqual(State.data_recvd, s.state);
    // Capacity must be released to the allocator: the prior peak of
    // ~1 MiB is unrecoverable until close without compact().
    try testing.expectEqual(@as(usize, 0), s.bytes.items.len);
    try testing.expectEqual(@as(usize, 0), s.bytes.capacity);
    try testing.expectEqual(@as(usize, 0), s.ranges.items.len);
}

test "compact: RESET_STREAM after buffered data drops the backing capacity" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    // Drive the buffer to a non-trivial peak and confirm it grew.
    var chunk: [1024]u8 = undefined;
    @memset(&chunk, 0xab);
    var off: u64 = 0;
    while (off < 64 * 1024) : (off += chunk.len) {
        try s.recv(off, &chunk, false);
    }
    try testing.expect(s.bytes.capacity >= 64 * 1024);
    try testing.expect(s.ranges.capacity >= 1);

    // RESET at the current high-water mark must drop the buffer.
    try s.resetStream(7, off);
    try testing.expectEqual(State.reset_recvd, s.state);
    try testing.expectEqual(@as(usize, 0), s.bytes.items.len);
    try testing.expectEqual(@as(usize, 0), s.bytes.capacity);
    try testing.expectEqual(@as(usize, 0), s.ranges.items.len);
    try testing.expectEqual(@as(usize, 0), s.ranges.capacity);
}

test "compact is idempotent and safe when called twice" {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "hello", true);
    var out: [16]u8 = undefined;
    _ = s.read(&out);
    // First compact triggered inside read(); a manual second call must
    // be a no-op rather than a panic.
    s.compact();
    s.compact();
    try testing.expectEqual(@as(usize, 0), s.bytes.capacity);
    try testing.expectEqual(@as(usize, 0), s.ranges.capacity);
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `RecvStream` with arbitrary `recv` / `read` / `resetStream`
// operations and assert reassembly invariants. Properties:
//
// - No panic, no overflow trap.
// - `read_offset` is monotonic (only ever advances).
// - `read_offset <= end_offset` always.
// - When `final_size` is set, no range extends beyond it.
// - `bytes.items.len` matches the buffered span (a function of
//   `read_offset` and the highest range end).
// - Range list stays sorted, disjoint, non-empty.
//
// Offsets and lengths are kept small enough to actually exercise
// reassembly without hitting `BufferLimitExceeded` on every call.

test "fuzz: recv_stream reassembly invariants" {
    try std.testing.fuzz({}, fuzzRecvStream, .{});
}

fn fuzzRecvStream(_: void, smith: *std.testing.Smith) anyerror!void {
    var s = RecvStream.init(test_alloc);
    defer s.deinit();
    s.max_buffered_span = 1024;

    var steps: u32 = 0;
    while (steps < 64 and !smith.eos()) : (steps += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 3);
        switch (op) {
            0 => {
                // recv: pick offset within plausible bounds, fuzzer-chosen
                // length and FIN flag.
                const offset = smith.valueRangeAtMost(u64, 0, 512);
                var data: [64]u8 = undefined;
                const data_len = smith.slice(&data);
                const fin = smith.valueRangeAtMost(u8, 0, 1) == 1;
                const before_read_offset = s.read_offset;
                _ = s.recv(offset, data[0..data_len], fin) catch {};
                // read_offset never moves on recv.
                try testing.expectEqual(before_read_offset, s.read_offset);
            },
            1 => {
                var dst: [64]u8 = undefined;
                const dst_len = smith.valueRangeAtMost(u32, 0, 64);
                const before_read_offset = s.read_offset;
                const n = s.read(dst[0..dst_len]);
                try testing.expect(n <= dst_len);
                // Monotonic read_offset advance.
                try testing.expect(s.read_offset >= before_read_offset);
                try testing.expectEqual(before_read_offset + @as(u64, @intCast(n)), s.read_offset);
            },
            2 => {
                const code = smith.value(u64);
                const final_size_in = smith.valueRangeAtMost(u64, 0, 1024);
                _ = s.resetStream(code, final_size_in) catch {};
            },
            3 => {
                // Pure offset-overflow probe — must not panic.
                const offset = smith.value(u64);
                var data: [4]u8 = undefined;
                const data_len = smith.valueRangeAtMost(u32, 0, 4);
                _ = s.recv(offset, data[0..data_len], false) catch {};
            },
            else => unreachable,
        }

        // Cross-cutting invariants.
        try testing.expect(s.read_offset <= s.end_offset);
        // Buffered span equals end-of-highest-range minus read_offset
        // (or 0 if there are no ranges).
        if (s.ranges.items.len == 0) {
            try testing.expectEqual(@as(usize, 0), s.bytes.items.len);
        } else {
            const top = s.ranges.items[s.ranges.items.len - 1].end;
            try testing.expect(top >= s.read_offset);
            const expected_buf: u64 = top - s.read_offset;
            try testing.expectEqual(@as(usize, @intCast(expected_buf)), s.bytes.items.len);
        }
        // Range list invariants: sorted, disjoint, non-empty intervals,
        // bounded by [read_offset, final_size or end_offset].
        if (s.ranges.items.len > 0) {
            var prev_end: u64 = 0;
            for (s.ranges.items, 0..) |r, i| {
                try testing.expect(r.offset < r.end);
                try testing.expect(r.offset >= s.read_offset);
                if (i > 0) try testing.expect(r.offset > prev_end); // disjoint, sorted
                if (s.final_size) |fs| try testing.expect(r.end <= fs);
                try testing.expect(r.end <= s.end_offset);
                prev_end = r.end;
            }
        }
        if (s.final_size) |fs| {
            try testing.expect(s.end_offset <= fs);
            try testing.expect(s.read_offset <= fs);
        }
    }
}

// Generative reassembly: lock down the strong oracle that the
// adversarial harness above can't carry — that the bytes the app
// reads back equal the bytes the peer wrote, regardless of how the
// chunks were split, shuffled, or duplicated. Build a known
// `[total]u8` payload from corpus bytes, then deliver it as `chunks`
// fixed-size pieces in a fuzzer-driven order (with occasional
// overlapping retransmits). After a final FIN, drain via `read` and
// compare byte-for-byte.

test "fuzz: recv_stream shuffled-delivery byte-equal reassembly" {
    try std.testing.fuzz({}, fuzzRecvStreamShuffled, .{});
}

fn fuzzRecvStreamShuffled(_: void, smith: *std.testing.Smith) anyerror!void {
    const total: usize = 256;
    const chunk: usize = 16;
    const chunks = total / chunk;

    var data: [total]u8 = undefined;
    smith.bytes(&data);

    // Build a permutation of [0, chunks) using a corpus-driven
    // Fisher-Yates shuffle: at each step pick the next chunk to
    // deliver from the unfilled tail of the array. The fuzzer's
    // index choices steer which order chunks land in.
    var indices: [chunks]u16 = undefined;
    for (&indices, 0..) |*slot, i| slot.* = @intCast(i);
    var i: u16 = chunks;
    while (i > 1) : (i -= 1) {
        const j = smith.valueRangeAtMost(u16, 0, i - 1);
        const tmp = indices[i - 1];
        indices[i - 1] = indices[j];
        indices[j] = tmp;
    }

    var stream = RecvStream.init(test_alloc);
    defer stream.deinit();

    for (indices, 0..) |idx, order| {
        const off = idx * chunk;
        try stream.recv(@intCast(off), data[off..][0..chunk], false);
        // Periodically retransmit a partially-overlapping window to
        // exercise duplicate-handling paths.
        if (smith.valueRangeAtMost(u8, 0, 7) == 0 and !smith.eos()) {
            const overlap_off = if (off == 0) off else off - @min(off, chunk / 2);
            const overlap_len = @min(chunk, total - overlap_off);
            try stream.recv(@intCast(overlap_off), data[overlap_off..][0..overlap_len], false);
        }
        _ = order;
    }
    try stream.recv(@intCast(total), "", true);

    var read_buf: [33]u8 = undefined;
    var consumed: usize = 0;
    while (consumed < total) {
        const n = stream.read(&read_buf);
        try testing.expect(n > 0);
        try testing.expectEqualSlices(u8, data[consumed..][0..n], read_buf[0..n]);
        consumed += n;
    }
    try testing.expectEqual(total, consumed);
    try testing.expectEqual(State.data_recvd, stream.state);
}
