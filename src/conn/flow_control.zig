//! Flow control bookkeeping (RFC 9000 §4).
//!
//! Three layers:
//! - Connection-level data: total bytes the peer will accept across
//!   all streams (`MAX_DATA`, RFC 9000 §19.9).
//! - Stream-level data: per-stream limit (`MAX_STREAM_DATA`,
//!   §19.10).
//! - Stream-count: how many streams we may open of each direction
//!   (`MAX_STREAMS`, §19.11).
//!
//! This module is pure bookkeeping. It does not advance state on
//! its own; the connection feeds it events (sent N bytes, received
//! a MAX_DATA frame, etc.).

const std = @import("std");

/// Errors raised by the flow-control bookkeeping helpers.
pub const Error = error{
    /// We tried to send beyond the peer's flow-control limit.
    FlowControlExceeded,
    /// Peer tried to send beyond our advertised limit. RFC 9000 §4.1
    /// says to close with FLOW_CONTROL_ERROR.
    PeerExceededLimit,
};

/// Connection-level data flow control. One per Connection.
pub const ConnectionData = struct {
    /// Maximum bytes we have advertised the peer can send to us.
    /// Bumped via outgoing MAX_DATA frames as we consume incoming
    /// stream bytes.
    local_max: u64 = 0,
    /// Bytes the peer has actually sent to us (sum of new bytes
    /// across all streams).
    peer_sent: u64 = 0,

    /// Maximum bytes the peer has advertised we can send to them.
    /// Bumped on incoming MAX_DATA frames.
    peer_max: u64 = 0,
    /// Bytes we have sent to the peer.
    we_sent: u64 = 0,

    /// Construct with the local- and peer-advertised initial limits
    /// (typically the `initial_max_data` transport parameters).
    pub fn init(local_initial: u64, peer_initial: u64) ConnectionData {
        return .{ .local_max = local_initial, .peer_max = peer_initial };
    }

    /// True iff sending `n` more bytes would still fit under `peer_max`.
    pub fn weCanSend(self: *const ConnectionData, n: u64) bool {
        const total = std.math.add(u64, self.we_sent, n) catch return false;
        return total <= self.peer_max;
    }

    /// Remaining bytes we may send before hitting the peer's limit.
    pub fn allowance(self: *const ConnectionData) u64 {
        if (self.we_sent >= self.peer_max) return 0;
        return self.peer_max - self.we_sent;
    }

    /// Record `n` bytes shipped on the wire. Errors with
    /// `FlowControlExceeded` if it would overshoot `peer_max`.
    pub fn recordSent(self: *ConnectionData, n: u64) Error!void {
        if (!self.weCanSend(n)) return Error.FlowControlExceeded;
        self.we_sent += n;
    }

    /// Apply an incoming MAX_DATA frame (RFC 9000 §19.9). Monotonic:
    /// stale/retransmitted MAX_DATA values are ignored.
    pub fn onMaxData(self: *ConnectionData, new_max: u64) void {
        if (new_max > self.peer_max) self.peer_max = new_max;
    }

    /// Charge `n` bytes from the peer against our advertised limit.
    /// Errors with `PeerExceededLimit` if the peer overran our cap
    /// (FLOW_CONTROL_ERROR per §4.1).
    pub fn recordPeerSent(self: *ConnectionData, n: u64) Error!void {
        const total = std.math.add(u64, self.peer_sent, n) catch
            return Error.PeerExceededLimit;
        if (total > self.local_max) return Error.PeerExceededLimit;
        self.peer_sent = total;
    }

    /// Lift the local advertised limit, e.g. before sending a new
    /// MAX_DATA frame. Monotonic.
    pub fn raiseLocalMax(self: *ConnectionData, new_max: u64) void {
        if (new_max > self.local_max) self.local_max = new_max;
    }
};

/// Per-stream data flow control. One per send-or-receive direction.
pub const StreamData = struct {
    /// What we've advertised — peer can send up to this.
    local_max: u64 = 0,
    /// What the peer has sent.
    peer_sent: u64 = 0,
    /// What the peer has advertised — we can send up to this.
    peer_max: u64 = 0,
    /// What we have sent.
    we_sent: u64 = 0,

    /// Construct with the advertised initial limits for this stream
    /// (`initial_max_stream_data_*` transport parameters).
    pub fn init(local_initial: u64, peer_initial: u64) StreamData {
        return .{ .local_max = local_initial, .peer_max = peer_initial };
    }

    /// Remaining bytes we may send on this stream before hitting the
    /// peer's limit.
    pub fn allowance(self: *const StreamData) u64 {
        if (self.we_sent >= self.peer_max) return 0;
        return self.peer_max - self.we_sent;
    }

    /// Charge `n` bytes against the peer's stream limit. Errors with
    /// `FlowControlExceeded` on overrun.
    pub fn recordSent(self: *StreamData, n: u64) Error!void {
        const total = std.math.add(u64, self.we_sent, n) catch
            return Error.FlowControlExceeded;
        if (total > self.peer_max) return Error.FlowControlExceeded;
        self.we_sent = total;
    }

    /// Apply an incoming MAX_STREAM_DATA frame (RFC 9000 §19.10).
    /// Monotonic.
    pub fn onMaxStreamData(self: *StreamData, new_max: u64) void {
        if (new_max > self.peer_max) self.peer_max = new_max;
    }

    /// Charge `n` bytes from the peer against our advertised stream
    /// limit. Errors with `PeerExceededLimit` on overrun.
    pub fn recordPeerSent(self: *StreamData, n: u64) Error!void {
        const total = std.math.add(u64, self.peer_sent, n) catch
            return Error.PeerExceededLimit;
        if (total > self.local_max) return Error.PeerExceededLimit;
        self.peer_sent = total;
    }

    /// Lift our advertised stream limit. Monotonic.
    pub fn raiseLocalMax(self: *StreamData, new_max: u64) void {
        if (new_max > self.local_max) self.local_max = new_max;
    }
};

/// Stream-count flow control. One per (bidi, uni) × (we-init, peer-init).
pub const StreamCount = struct {
    /// Highest stream number the peer has advertised we may open
    /// (exclusive). E.g. `peer_max = 10` permits streams 0..9.
    peer_max: u64 = 0,
    /// Highest stream number we've opened (inclusive index).
    we_opened: u64 = 0,
    /// Highest stream number we've advertised the peer may open
    /// (exclusive).
    local_max: u64 = 0,
    /// Highest stream number the peer has opened (inclusive index).
    peer_opened: u64 = 0,

    /// Construct with the local- and peer-advertised initial maxima
    /// (the `initial_max_streams_*` transport parameters).
    pub fn init(local_initial: u64, peer_initial: u64) StreamCount {
        return .{ .local_max = local_initial, .peer_max = peer_initial };
    }

    /// True iff the local endpoint may open one more stream of this
    /// (direction, initiator) pair.
    pub fn weCanOpen(self: *const StreamCount) bool {
        return self.we_opened < self.peer_max;
    }

    /// Account for opening one more stream. Errors with
    /// `FlowControlExceeded` if `peer_max` is already reached.
    pub fn recordWeOpened(self: *StreamCount) Error!void {
        if (!self.weCanOpen()) return Error.FlowControlExceeded;
        self.we_opened += 1;
    }

    /// Apply an incoming MAX_STREAMS frame (RFC 9000 §19.11). Monotonic.
    pub fn onMaxStreams(self: *StreamCount, new_max: u64) void {
        if (new_max > self.peer_max) self.peer_max = new_max;
    }

    /// Record that the peer opened the given peer-initiated stream
    /// index. Errors with `PeerExceededLimit` if the peer's stream
    /// number is at or past our advertised cap (STREAM_LIMIT_ERROR).
    pub fn recordPeerOpened(self: *StreamCount, stream_index: u64) Error!void {
        if (stream_index >= self.local_max) return Error.PeerExceededLimit;
        if (stream_index >= self.peer_opened) {
            // local_max is bounded well below 2^64, so the increment
            // never overflows in practice. Use checked add anyway so
            // a future loosening of local_max can't reach UB.
            self.peer_opened = std.math.add(u64, stream_index, 1) catch
                return Error.PeerExceededLimit;
        }
    }
};

// -- tests ---------------------------------------------------------------

test "ConnectionData: send up to peer_max then refuse" {
    var c = ConnectionData.init(0, 1000);
    try c.recordSent(400);
    try std.testing.expectEqual(@as(u64, 600), c.allowance());
    try c.recordSent(600);
    try std.testing.expectEqual(@as(u64, 0), c.allowance());
    try std.testing.expectError(Error.FlowControlExceeded, c.recordSent(1));
}

test "ConnectionData: onMaxData lifts the cap monotonically" {
    var c = ConnectionData.init(0, 100);
    c.onMaxData(200);
    try std.testing.expectEqual(@as(u64, 200), c.peer_max);
    c.onMaxData(150); // out-of-order MAX_DATA; ignored
    try std.testing.expectEqual(@as(u64, 200), c.peer_max);
}

test "ConnectionData: peer-side enforcement" {
    var c = ConnectionData.init(1000, 0);
    try c.recordPeerSent(900);
    try std.testing.expectError(Error.PeerExceededLimit, c.recordPeerSent(101));
    c.raiseLocalMax(2000);
    try c.recordPeerSent(101); // now legal
}

test "StreamData allowance and limit" {
    var s = StreamData.init(0, 256);
    try s.recordSent(100);
    try s.recordSent(156);
    try std.testing.expectError(Error.FlowControlExceeded, s.recordSent(1));
    s.onMaxStreamData(512);
    try s.recordSent(256);
}

test "StreamCount: open up to peer_max then refuse" {
    var sc = StreamCount.init(0, 3);
    try sc.recordWeOpened();
    try sc.recordWeOpened();
    try sc.recordWeOpened();
    try std.testing.expectError(Error.FlowControlExceeded, sc.recordWeOpened());
    sc.onMaxStreams(5);
    try sc.recordWeOpened();
}

test "StreamCount: peer opening enforces local_max" {
    var sc = StreamCount.init(2, 0);
    try sc.recordPeerOpened(0);
    try sc.recordPeerOpened(1);
    try std.testing.expectError(Error.PeerExceededLimit, sc.recordPeerOpened(2));
}
