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
/// CONNECTION_CLOSE info, the closed flag, the draining deadline,
/// and the sticky close event with its reason buffer.
///
/// All methods are pure with respect to the rest of Connection — the
/// caller layers in side effects (clearing recovery state, emitting
/// qlog state transitions) at the call sites.
pub const LifecycleState = struct {
    /// CONNECTION_CLOSE we've queued (typically from `close()`); the
    /// next outgoing packet at the highest available encryption
    /// level emits it.
    pending_close: ?ConnectionCloseInfo = null,
    /// True once we've sent or received a CONNECTION_CLOSE frame, or
    /// an idle timeout has entered draining.
    closed: bool = false,
    /// Draining-state deadline. A non-null value means only the
    /// draining timer remains relevant.
    draining_deadline_us: ?u64 = null,
    /// Sticky close/error status for embedders. The stored event keeps
    /// offsets into `close_reason_buf` so `Connection` can be moved
    /// before bind/init without leaving a self-referential slice
    /// behind.
    close_event: ?StoredCloseEvent = null,
    close_reason_buf: [max_close_reason_len]u8 = undefined,

    /// Current public shutdown state derived from the stored fields.
    pub fn state(self: *const LifecycleState) CloseState {
        if (self.draining_deadline_us != null) return .draining;
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
        self.closed = true;
        self.draining_deadline_us = draining_deadline;
    }

    /// Drop any queued CONNECTION_CLOSE / draining timer and mark the
    /// connection terminally closed. Caller clears recovery state
    /// separately.
    pub fn finishDraining(self: *LifecycleState) void {
        self.pending_close = null;
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
};
