//! Connection close/draining lifecycle state.
//!
//! Owns the close-related fields and pure transitions extracted from
//! `Connection`. The Connection still wraps these calls to layer in
//! side effects (clearing recovery state, emitting qlog state-change
//! events) that aren't pure lifecycle concerns.
//!
//! RFC 9000 §10 defines the lifecycle: open → closing → draining → closed.

const std = @import("std");

/// Public CONNECTION_CLOSE descriptor passed to `Connection.close` and
/// queued until the next outgoing packet emits the frame (RFC 9000 §19.19).
pub const ConnectionCloseInfo = struct {
    is_transport: bool,
    error_code: u64,
    frame_type: u64 = 0,
    reason: []const u8 = &.{},
};

/// Origin of a connection-close event surfaced through `nextEvent`.
pub const CloseSource = enum {
    local,
    peer,
    idle_timeout,
    stateless_reset,
    version_negotiation,
};

/// QUIC distinguishes transport-level (RFC 9000 §20.1) from application-level
/// (RFC 9000 §20.2) errors; this enum tags which space `error_code` lives in.
pub const CloseErrorSpace = enum {
    transport,
    application,
};

/// High-level connection lifecycle state — RFC 9000 §10 (closing/draining).
pub const CloseState = enum {
    open,
    closing,
    draining,
    closed,
};

/// Maximum length of a CONNECTION_CLOSE reason phrase we will record/emit.
pub const max_close_reason_len: usize = 256;

/// Snapshot of a close event delivered to the embedder via `nextEvent`.
/// Captures source, error space/code and (optionally) the wire-level frame
/// type that triggered the close. RFC 9000 §10.
pub const CloseEvent = struct {
    source: CloseSource,
    error_space: CloseErrorSpace,
    error_code: u64,
    frame_type: u64 = 0,
    reason: []const u8 = &.{},
    reason_truncated: bool = false,
    at_us: ?u64 = null,
    draining_deadline_us: ?u64 = null,
};

/// Internal sticky-state copy of the close event. Stores the reason phrase
/// as offsets into `LifecycleState.close_reason_buf` so the Connection can
/// be moved before bind/init without leaving a self-referential slice.
pub const StoredCloseEvent = struct {
    source: CloseSource,
    error_space: CloseErrorSpace,
    error_code: u64,
    frame_type: u64 = 0,
    reason_len: usize = 0,
    reason_truncated: bool = false,
    at_us: ?u64 = null,
    draining_deadline_us: ?u64 = null,
    delivered: bool = false,
};

/// Map a transport/application boolean onto a `CloseErrorSpace` enum.
pub fn closeErrorSpace(is_transport: bool) CloseErrorSpace {
    return if (is_transport) .transport else .application;
}

/// Pure close/draining state for a Connection. Owns the queued
/// CONNECTION_CLOSE info, the closed flag, the closing/draining
/// deadlines, the close-emit rate-limit bookkeeping, and the sticky
/// close event with its reason buffer.
///
/// All methods are pure with respect to the rest of Connection — the
/// caller layers in side effects (clearing recovery state, emitting
/// qlog state transitions) at the call sites.
///
/// Lifecycle, mapped to RFC 9000 §10.2:
///   - open       → no fields set
///   - closing    → either `pending_close` (CC queued, not yet sealed)
///                  or `closing_deadline_us` (first CC sealed, awaiting
///                  closing-state expiry per §10.2.1)
///   - draining   → `draining_deadline_us` set (entered after peer's
///                  CC arrives, idle timeout, or stateless reset path)
///   - closed     → `closed = true` with both deadlines null
pub const LifecycleState = struct {
    /// CONNECTION_CLOSE we've queued (typically from `close()`); the
    /// next outgoing packet at the highest available encryption
    /// level emits it.
    pending_close: ?ConnectionCloseInfo = null,
    /// True once we've sent or received a CONNECTION_CLOSE frame, or
    /// an idle timeout has entered draining.
    closed: bool = false,
    /// Closing-state deadline. Set once the first locally-originated
    /// CONNECTION_CLOSE goes on the wire and we transition to RFC 9000
    /// §10.2.1's closing state. While in this state, attributed
    /// incoming packets re-arm `pending_close` (rate-limited per
    /// §10.2.1 ¶3) so the peer can re-observe the close if the first
    /// CC was lost. Cleared when the connection moves on to draining
    /// or terminal closed.
    closing_deadline_us: ?u64 = null,
    /// Draining-state deadline. A non-null value means only the
    /// draining timer remains relevant.
    draining_deadline_us: ?u64 = null,
    /// Wall-clock of the most recent CONNECTION_CLOSE emission. Used
    /// by `shouldRearmCloseRepeat` to enforce the §10.2.1 ¶3
    /// rate-limit.
    last_close_emit_us: ?u64 = null,
    /// Number of times we've sealed a CONNECTION_CLOSE (initial emit
    /// + repeats). Used as the exponent for the §10.2.1 ¶3
    /// "progressively increasing … amount of time" backoff. Saturates
    /// at the upper bound of `shift` inside the rate-limit math.
    close_emit_count: u32 = 0,
    /// Sticky close/error status for embedders. The stored event keeps
    /// offsets into `close_reason_buf` so `Connection` can be moved
    /// before bind/init without leaving a self-referential slice
    /// behind.
    close_event: ?StoredCloseEvent = null,
    close_reason_buf: [max_close_reason_len]u8 = undefined,

    /// Current public shutdown state derived from the stored fields.
    pub fn state(self: *const LifecycleState) CloseState {
        if (self.draining_deadline_us != null) return .draining;
        if (self.closing_deadline_us != null) return .closing;
        if (self.pending_close != null) return .closing;
        if (self.closed) return .closed;
        return .open;
    }

    /// Sticky close event, projected back into the public `CloseEvent`
    /// shape (with the reason phrase resolved against the buffer).
    pub fn event(self: *const LifecycleState) ?CloseEvent {
        const stored = self.close_event orelse return null;
        return self.eventFromStored(stored);
    }

    /// Project a `StoredCloseEvent` into the public `CloseEvent`. The
    /// resulting reason slice borrows from `self.close_reason_buf`.
    pub fn eventFromStored(self: *const LifecycleState, stored: StoredCloseEvent) CloseEvent {
        return .{
            .source = stored.source,
            .error_space = stored.error_space,
            .error_code = stored.error_code,
            .frame_type = stored.frame_type,
            .reason = self.close_reason_buf[0..stored.reason_len],
            .reason_truncated = stored.reason_truncated,
            .at_us = stored.at_us,
            .draining_deadline_us = stored.draining_deadline_us,
        };
    }

    /// Record the sticky close event the first time something
    /// terminates the connection. Subsequent calls are no-ops so
    /// the originating cause "wins."
    pub fn record(
        self: *LifecycleState,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        at_us: ?u64,
        draining_deadline_us: ?u64,
    ) void {
        if (self.close_event != null) return;
        const reason_len = @min(reason.len, max_close_reason_len);
        if (reason_len > 0) {
            @memcpy(self.close_reason_buf[0..reason_len], reason[0..reason_len]);
        }
        self.close_event = .{
            .source = source,
            .error_space = error_space,
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_len = reason_len,
            .reason_truncated = reason.len > reason_len,
            .at_us = at_us,
            .draining_deadline_us = draining_deadline_us,
        };
    }

    /// Patch the draining deadline on the sticky event after the
    /// outgoing CONNECTION_CLOSE goes on the wire and we transition
    /// to draining.
    pub fn updateDrainingDeadline(self: *LifecycleState, deadline_us: u64) void {
        if (self.close_event) |*ev| {
            ev.draining_deadline_us = deadline_us;
        }
    }

    /// Transition into the draining state with a precomputed deadline.
    /// The caller is responsible for sourcing `draining_deadline` (it
    /// derives from the path's PTO and isn't a pure lifecycle concern).
    pub fn enterDraining(
        self: *LifecycleState,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_us: u64,
        draining_deadline: u64,
    ) void {
        self.record(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
            draining_deadline,
        );
        self.pending_close = null;
        self.closing_deadline_us = null;
        self.closed = true;
        self.draining_deadline_us = draining_deadline;
    }

    /// Drop any queued CONNECTION_CLOSE / closing/draining timer and
    /// mark the connection terminally closed. Caller clears recovery
    /// state separately.
    pub fn finishDraining(self: *LifecycleState) void {
        self.pending_close = null;
        self.closing_deadline_us = null;
        self.draining_deadline_us = null;
        self.closed = true;
    }

    /// Skip the draining stopwatch and go straight to closed (used
    /// for stateless reset, version negotiation forced teardown, etc.).
    pub fn enterClosed(
        self: *LifecycleState,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_us: u64,
    ) void {
        self.record(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
            null,
        );
        self.pending_close = null;
        self.closing_deadline_us = null;
        self.draining_deadline_us = null;
        self.closed = true;
    }

    /// Unconditionally drop to draining once now_us has crossed the
    /// stored deadline. Returns true if the transition fired so the
    /// caller can emit the corresponding side effects.
    pub fn finishDrainingIfElapsed(self: *LifecycleState, now_us: u64) bool {
        const deadline = self.draining_deadline_us orelse return false;
        if (now_us < deadline) return false;
        self.finishDraining();
        return true;
    }

    /// Bookkeeping the caller invokes immediately after the seal-and-
    /// send path emits a CONNECTION_CLOSE. Clears `pending_close`,
    /// flips the terminal `closed` flag, arms the closing-state
    /// deadline, and bumps the rate-limit counters that gate further
    /// CC retransmissions per RFC 9000 §10.2.1 ¶3. The caller passes a
    /// precomputed `closing_deadline` (typically `now_us + 3 * PTO`,
    /// matching §10.2 ¶5's "These states SHOULD persist for at least
    /// three times the current PTO interval").
    pub fn noteCloseEmit(
        self: *LifecycleState,
        now_us: u64,
        closing_deadline: u64,
    ) void {
        self.pending_close = null;
        self.closed = true;
        // Only arm the closing-state deadline on the FIRST emit. A
        // §10.2.1 ¶3 retransmit doesn't extend the timer (otherwise
        // a chatty peer could keep the slot alive forever — that's
        // the exact amplification angle the ¶3 SHOULD-rate-limit and
        // §10.2 ¶5 fixed deadline guard against).
        if (self.draining_deadline_us == null and self.closing_deadline_us == null) {
            self.closing_deadline_us = closing_deadline;
        }
        self.last_close_emit_us = now_us;
        self.close_emit_count +|= 1;
    }

    /// Whether enough time has elapsed since the last CONNECTION_CLOSE
    /// emission to re-arm `pending_close` for another retransmit. RFC
    /// 9000 §10.2.1 ¶3 SHOULD: "limit the rate at which it generates
    /// packets in the closing state. For instance, an endpoint could
    /// wait for a progressively increasing number of received packets
    /// or amount of time before responding to received packets."
    ///
    /// quic_zig's policy: exponential time backoff. Wait at least
    /// `base_interval_us << close_emit_count` before re-arming. The
    /// shift saturates at 16 (matching the loss-recovery PTO backoff
    /// cap) so the interval can't run away into u64 overflow.
    pub fn shouldRearmCloseRepeat(
        self: *const LifecycleState,
        now_us: u64,
        base_interval_us: u64,
    ) bool {
        if (self.pending_close != null) return false;
        if (self.closing_deadline_us == null) return false;
        const last = self.last_close_emit_us orelse return true;
        const shift: u6 = @intCast(@min(self.close_emit_count, 16));
        const max_u64: u64 = std.math.maxInt(u64);
        const interval = if (base_interval_us > (max_u64 >> shift))
            max_u64
        else
            base_interval_us << shift;
        return now_us >= last +| interval;
    }

    /// Drop to terminal-closed once `now_us` crosses the stored
    /// closing-state deadline. Returns true if the transition fired so
    /// the caller can emit the corresponding side effects. The closing
    /// state ends without ever entering draining when the peer never
    /// returns a CONNECTION_CLOSE — per §10.2 ¶5 the state SHOULD have
    /// persisted at least 3*PTO, which is what the caller arms.
    pub fn finishClosingIfElapsed(self: *LifecycleState, now_us: u64) bool {
        const deadline = self.closing_deadline_us orelse return false;
        if (now_us < deadline) return false;
        self.finishDraining();
        return true;
    }
};

// -- tests ---------------------------------------------------------------

test "lifecycle: default-initialized state is open" {
    const ls: LifecycleState = .{};
    try std.testing.expectEqual(CloseState.open, ls.state());
    try std.testing.expectEqual(@as(?StoredCloseEvent, null), ls.close_event);
    try std.testing.expectEqual(@as(u32, 0), ls.close_emit_count);
    try std.testing.expectEqual(@as(?u64, null), ls.last_close_emit_us);
    try std.testing.expectEqual(@as(?u64, null), ls.closing_deadline_us);
}

test "lifecycle: noteCloseEmit arms closing deadline and bumps counter" {
    var ls: LifecycleState = .{};
    const pto_us: u64 = 100_000; // 100 ms
    const now_us: u64 = 1_000_000;
    const deadline = now_us + 3 * pto_us;

    ls.noteCloseEmit(now_us, deadline);

    try std.testing.expectEqual(CloseState.closing, ls.state());
    try std.testing.expectEqual(@as(?u64, deadline), ls.closing_deadline_us);
    try std.testing.expectEqual(@as(?u64, now_us), ls.last_close_emit_us);
    try std.testing.expectEqual(@as(u32, 1), ls.close_emit_count);
    try std.testing.expect(ls.closed);
    try std.testing.expectEqual(@as(?ConnectionCloseInfo, null), ls.pending_close);
}

test "lifecycle: noteCloseEmit retransmit doesn't extend the closing deadline" {
    var ls: LifecycleState = .{};
    const first_now: u64 = 1_000_000;
    const first_deadline: u64 = first_now + 300_000;
    ls.noteCloseEmit(first_now, first_deadline);

    // Second emit at a later time: deadline must NOT be moved (§10.2.1 ¶3
    // amplification guard) but the counter and last-emit must update.
    const second_now: u64 = first_now + 50_000;
    const stale_deadline: u64 = second_now + 999_999_999;
    ls.noteCloseEmit(second_now, stale_deadline);

    try std.testing.expectEqual(@as(?u64, first_deadline), ls.closing_deadline_us);
    try std.testing.expectEqual(@as(?u64, second_now), ls.last_close_emit_us);
    try std.testing.expectEqual(@as(u32, 2), ls.close_emit_count);
}

test "lifecycle: shouldRearmCloseRepeat applies exponential backoff per emit count" {
    var ls: LifecycleState = .{};
    const base: u64 = 1_000; // 1 ms base interval
    const t0: u64 = 10_000;

    // Pre-arm: the closing-state deadline must be set for rearm to fire.
    ls.noteCloseEmit(t0, t0 + 300_000);
    // After first emit, count==1, shift=1, interval = base << 1 = 2*base.
    try std.testing.expect(!ls.shouldRearmCloseRepeat(t0 + (2 * base) - 1, base));
    try std.testing.expect(ls.shouldRearmCloseRepeat(t0 + 2 * base, base));

    // Second emit: count==2 → interval = base << 2 = 4*base.
    const t1 = t0 + 2 * base;
    ls.noteCloseEmit(t1, t0 + 300_000); // deadline ignored (already armed).
    try std.testing.expect(!ls.shouldRearmCloseRepeat(t1 + (4 * base) - 1, base));
    try std.testing.expect(ls.shouldRearmCloseRepeat(t1 + 4 * base, base));

    // Third emit: count==3 → interval = 8*base.
    const t2 = t1 + 4 * base;
    ls.noteCloseEmit(t2, t0 + 300_000);
    try std.testing.expect(!ls.shouldRearmCloseRepeat(t2 + (8 * base) - 1, base));
    try std.testing.expect(ls.shouldRearmCloseRepeat(t2 + 8 * base, base));
}

test "lifecycle: shouldRearmCloseRepeat is false while pending_close is queued" {
    var ls: LifecycleState = .{};
    ls.noteCloseEmit(0, 300_000);
    ls.pending_close = .{ .is_transport = true, .error_code = 0 };
    // Even past the backoff window the rearm path must short-circuit on
    // pending_close — we already have a CC queued for the next packet.
    try std.testing.expect(!ls.shouldRearmCloseRepeat(1_000_000_000, 1));
}

test "lifecycle: finishClosingIfElapsed is no-op before the deadline" {
    var ls: LifecycleState = .{};
    const t0: u64 = 0;
    const pto: u64 = 100_000;
    ls.noteCloseEmit(t0, t0 + 3 * pto);

    try std.testing.expect(!ls.finishClosingIfElapsed(t0 + pto));
    try std.testing.expectEqual(CloseState.closing, ls.state());
    try std.testing.expectEqual(@as(?u64, t0 + 3 * pto), ls.closing_deadline_us);
}

test "lifecycle: finishClosingIfElapsed transitions to closed past the deadline" {
    var ls: LifecycleState = .{};
    const t0: u64 = 0;
    const pto: u64 = 100_000;
    const deadline = t0 + 3 * pto;
    ls.noteCloseEmit(t0, deadline);

    try std.testing.expect(ls.finishClosingIfElapsed(deadline + 1));
    try std.testing.expectEqual(CloseState.closed, ls.state());
    try std.testing.expectEqual(@as(?u64, null), ls.closing_deadline_us);
    try std.testing.expectEqual(@as(?u64, null), ls.draining_deadline_us);
    try std.testing.expect(ls.closed);
}

test "lifecycle: record truncates reason phrases longer than max_close_reason_len" {
    var ls: LifecycleState = .{};
    var long_reason: [max_close_reason_len + 32]u8 = undefined;
    @memset(&long_reason, 'x');

    ls.record(.local, .application, 0x42, 0, &long_reason, 100, null);
    const ev = ls.event() orelse return error.MissingEvent;
    try std.testing.expectEqual(max_close_reason_len, ev.reason.len);
    try std.testing.expect(ev.reason_truncated);
    for (ev.reason) |b| try std.testing.expectEqual(@as(u8, 'x'), b);
}

test "lifecycle: record is sticky — first close wins" {
    var ls: LifecycleState = .{};
    ls.record(.local, .application, 1, 0, "first", 10, null);
    ls.record(.peer, .transport, 2, 7, "second", 20, 50);

    const ev = ls.event() orelse return error.MissingEvent;
    try std.testing.expectEqual(CloseSource.local, ev.source);
    try std.testing.expectEqual(CloseErrorSpace.application, ev.error_space);
    try std.testing.expectEqual(@as(u64, 1), ev.error_code);
    try std.testing.expectEqual(@as(u64, 0), ev.frame_type);
    try std.testing.expectEqualStrings("first", ev.reason);
    try std.testing.expectEqual(@as(?u64, 10), ev.at_us);
    try std.testing.expect(!ev.reason_truncated);
}

test "lifecycle: enterDraining transitions and arms the draining deadline" {
    var ls: LifecycleState = .{};
    // Simulate that we'd already sent our own CC and were in closing.
    ls.noteCloseEmit(0, 300_000);
    try std.testing.expectEqual(CloseState.closing, ls.state());

    const draining_deadline: u64 = 600_000;
    ls.enterDraining(.peer, .transport, 0x0a, 0, "peer-cc", 100, draining_deadline);

    try std.testing.expectEqual(CloseState.draining, ls.state());
    try std.testing.expectEqual(@as(?u64, draining_deadline), ls.draining_deadline_us);
    try std.testing.expectEqual(@as(?u64, null), ls.closing_deadline_us);
    try std.testing.expect(ls.closed);

    const ev = ls.event() orelse return error.MissingEvent;
    try std.testing.expectEqual(CloseSource.peer, ev.source);
    try std.testing.expectEqual(@as(?u64, draining_deadline), ev.draining_deadline_us);

    // Past the draining deadline, finishDrainingIfElapsed transitions to closed.
    try std.testing.expect(ls.finishDrainingIfElapsed(draining_deadline + 1));
    try std.testing.expectEqual(CloseState.closed, ls.state());
}
