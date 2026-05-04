//! Path validation state machine (RFC 9000 §8.2).
//!
//! On wishing to use a new path (or in response to peer activity on
//! an unvalidated path), an endpoint sends `PATH_CHALLENGE` with an
//! 8-byte random token. The peer echoes the token in `PATH_RESPONSE`.
//! Receipt of the matching token within 3 * PTO validates the path;
//! a timeout marks it failed.
//!
//! The validator here is *just* the state machine — the connection
//! is responsible for sending the challenge frame, receiving the
//! response frame, and ticking the timeout.

const std = @import("std");

pub const Status = enum {
    /// No challenge in flight, no validation outcome yet.
    idle,
    /// Challenge sent; awaiting matching response.
    pending,
    /// Response received and matched. Path is usable.
    validated,
    /// Timeout fired before a matching response arrived.
    failed,
};

pub const Error = error{
    /// `recordResponse` was called when no challenge was pending.
    NotPending,
};

pub const PathValidator = struct {
    status: Status = .idle,
    /// Token from the most recent challenge sent. Valid only when
    /// status == .pending.
    pending_token: [8]u8 = @splat(0),
    /// Wall-clock time (µs) at which the current challenge was
    /// sent. Used by `tick` to compute timeout.
    pending_at_us: u64 = 0,
    /// Per-validator timeout duration in µs. Caller computes
    /// `3 * pto` (RFC 9000 §8.2.4) and sets this each time a new
    /// challenge starts.
    timeout_us: u64 = 0,

    /// Begin a new challenge with the given random token. Resets
    /// state from any prior outcome.
    pub fn beginChallenge(
        self: *PathValidator,
        token: [8]u8,
        now_us: u64,
        timeout_us_in: u64,
    ) void {
        self.status = .pending;
        self.pending_token = token;
        self.pending_at_us = now_us;
        self.timeout_us = timeout_us_in;
    }

    /// Process a received PATH_RESPONSE. Returns true if the token
    /// matched the pending challenge. A non-match leaves the state
    /// pending (per §8.2.2: a stray PATH_RESPONSE is ignored, not
    /// fatal).
    pub fn recordResponse(self: *PathValidator, token: [8]u8) Error!bool {
        if (self.status != .pending) return Error.NotPending;
        if (std.mem.eql(u8, &token, &self.pending_token)) {
            self.status = .validated;
            return true;
        }
        return false;
    }

    /// Tick the timeout. If `now_us - pending_at_us > timeout_us`,
    /// transitions the status from `.pending` → `.failed`.
    pub fn tick(self: *PathValidator, now_us: u64) void {
        if (self.status != .pending) return;
        if (now_us > self.pending_at_us and now_us - self.pending_at_us > self.timeout_us) {
            self.status = .failed;
        }
    }

    pub fn isValidated(self: *const PathValidator) bool {
        return self.status == .validated;
    }
};

// -- tests ---------------------------------------------------------------

test "matched response transitions to validated" {
    var v: PathValidator = .{};
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    v.beginChallenge(token, 100, 1000);
    try std.testing.expectEqual(Status.pending, v.status);

    const matched = try v.recordResponse(token);
    try std.testing.expect(matched);
    try std.testing.expectEqual(Status.validated, v.status);
    try std.testing.expect(v.isValidated());
}

test "mismatched response leaves status pending" {
    var v: PathValidator = .{};
    const correct: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const wrong: [8]u8 = .{ 9, 9, 9, 9, 9, 9, 9, 9 };
    v.beginChallenge(correct, 0, 1000);

    const matched = try v.recordResponse(wrong);
    try std.testing.expect(!matched);
    try std.testing.expectEqual(Status.pending, v.status);

    // Subsequent matching response still works.
    const matched2 = try v.recordResponse(correct);
    try std.testing.expect(matched2);
    try std.testing.expectEqual(Status.validated, v.status);
}

test "recordResponse on idle state returns NotPending" {
    var v: PathValidator = .{};
    try std.testing.expectError(Error.NotPending, v.recordResponse(@splat(0)));
}

test "tick fails the validator when timeout exceeds" {
    var v: PathValidator = .{};
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    v.beginChallenge(token, 100, 1000);

    v.tick(500); // within timeout
    try std.testing.expectEqual(Status.pending, v.status);

    v.tick(2000); // past timeout
    try std.testing.expectEqual(Status.failed, v.status);
    try std.testing.expect(!v.isValidated());
}

test "tick on validated state is a no-op" {
    var v: PathValidator = .{};
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    v.beginChallenge(token, 0, 100);
    _ = try v.recordResponse(token);
    v.tick(1_000_000_000);
    try std.testing.expectEqual(Status.validated, v.status);
}

test "beginChallenge resets after a prior outcome" {
    var v: PathValidator = .{};
    const token1: [8]u8 = .{ 1, 1, 1, 1, 1, 1, 1, 1 };
    v.beginChallenge(token1, 0, 100);
    v.tick(1_000_000); // failed
    try std.testing.expectEqual(Status.failed, v.status);

    const token2: [8]u8 = .{ 2, 2, 2, 2, 2, 2, 2, 2 };
    v.beginChallenge(token2, 2_000_000, 100_000);
    try std.testing.expectEqual(Status.pending, v.status);
    const matched = try v.recordResponse(token2);
    try std.testing.expect(matched);
}
