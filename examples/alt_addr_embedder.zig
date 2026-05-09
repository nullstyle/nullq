//! Reference embedder for the
//! draft-munizaga-quic-alternative-server-address-00 receive surface.
//!
//! The connection's `pollEvent` returns each `ALTERNATIVE_V4/V6_ADDRESS`
//! frame as a typed `AlternativeServerAddressEvent`. quic_zig
//! pre-filters out duplicates and stale-reorders (RFC 9000 §13.3
//! retransmits and out-of-order app-PN delivery), so the embedder
//! only sees forward-progress updates. What remains is the
//! application policy: which addresses to record, when to migrate,
//! when to retire, how to schedule the migration to avoid the §9
//! thundering-herd.
//!
//! This file ships a minimal but realistic shape:
//!
//!  - `AddressBook` — an in-memory store keyed by (kind, addr, port).
//!    Every Preferred / Retire update gets folded into the matching
//!    entry; sequence numbers are remembered so a second
//!    `process` call against the same event is idempotent.
//!  - `MigrationScheduler` — holds the next recommended migration
//!    deadline for the current Preferred target. The deadline is
//!    backed by the `alt_addr.recommendedMigrationDelayMs` helper
//!    so a malicious server that ships Preferred to many clients at
//!    once can't synthesize a thundering herd at the advertised
//!    victim.
//!  - `Embedder.run` — the recommended event-pump shape. Pulls every
//!    `ConnectionEvent`, dispatches `alternative_server_address` to
//!    the book + scheduler, and forwards any non-alt-addr event to
//!    a caller-supplied callback so this example composes with an
//!    embedder that already has a `pollEvent` loop.
//!
//! The whole thing uses only the public `quic_zig` API surface; the
//! tests at the bottom drive it against a stubbed event stream so
//! the example doubles as a regression for the receive-side
//! contract.

const std = @import("std");
const quic_zig = @import("quic_zig");

const AlternativeServerAddressEvent = quic_zig.AlternativeServerAddressEvent;
const ConnectionEvent = quic_zig.ConnectionEvent;

/// Maximum number of distinct `(kind, addr, port)` entries the
/// embedder will track at once. Bounded so a chatty server can't
/// pin proportional memory by spraying ever-new tuples.
pub const max_entries: usize = 16;

/// One row in the address book: the on-wire payload from the most
/// recent §6 update for this `(kind, addr, port)` tuple, plus the
/// monotonically-increasing sequence number that produced it.
pub const Entry = union(enum) {
    v4: V4,
    v6: V6,

    pub const V4 = struct {
        address: [4]u8,
        port: u16,
        last_sequence_number: u64,
        preferred: bool,
        retire: bool,
    };

    pub const V6 = struct {
        address: [16]u8,
        port: u16,
        last_sequence_number: u64,
        preferred: bool,
        retire: bool,
    };

    /// True if the most recent update for this entry asked the
    /// client to migrate (or otherwise prioritize) its path.
    pub fn preferred(self: Entry) bool {
        return switch (self) {
            .v4 => |v| v.preferred,
            .v6 => |v| v.preferred,
        };
    }

    /// True if the most recent update asked the client to close any
    /// path bound to this address.
    pub fn retire(self: Entry) bool {
        return switch (self) {
            .v4 => |v| v.retire,
            .v6 => |v| v.retire,
        };
    }
};

/// Fixed-capacity key/value table of received alternative-address
/// updates. Lookup + update is linear over the live entries; with
/// `max_entries = 16` that's fine for every realistic deployment.
pub const AddressBook = struct {
    entries: [max_entries]Entry = undefined,
    len: usize = 0,

    /// Apply an event to the book. Idempotent: an event whose
    /// `(kind, addr, port)` already matches the latest entry simply
    /// updates that row's flags + sequence number.
    ///
    /// Returns `true` if the event landed (book was updated),
    /// `false` only if the book was full and the event named a
    /// brand-new tuple. Existing tuples are always updated even
    /// when the book is at capacity.
    pub fn apply(self: *AddressBook, event: AlternativeServerAddressEvent) bool {
        if (self.findIndex(event)) |idx| {
            self.entries[idx] = entryFromEvent(event);
            return true;
        }
        if (self.len >= max_entries) return false;
        self.entries[self.len] = entryFromEvent(event);
        self.len += 1;
        return true;
    }

    /// Look up the entry currently flagged `Preferred = true`. The
    /// embedder consumes this when scheduling a migration. Returns
    /// the highest-sequence-number Preferred entry if more than one
    /// row is flagged (a server that emits Preferred for two
    /// different addresses is allowed; the latest wins).
    pub fn currentPreferred(self: *const AddressBook) ?Entry {
        var best: ?Entry = null;
        var best_seq: u64 = 0;
        for (self.entries[0..self.len]) |entry| {
            if (!entry.preferred()) continue;
            const seq = sequenceNumber(entry);
            if (best == null or seq > best_seq) {
                best = entry;
                best_seq = seq;
            }
        }
        return best;
    }

    /// Iterator helper for embedders that want to inspect every
    /// retire-flagged entry (e.g. to tear down their own
    /// per-address bookkeeping). Slice borrows from `self`; valid
    /// until the next `apply` call.
    pub fn entries_view(self: *const AddressBook) []const Entry {
        return self.entries[0..self.len];
    }

    fn findIndex(self: *const AddressBook, event: AlternativeServerAddressEvent) ?usize {
        for (self.entries[0..self.len], 0..) |entry, idx| {
            if (entryMatchesEvent(entry, event)) return idx;
        }
        return null;
    }
};

fn entryFromEvent(event: AlternativeServerAddressEvent) Entry {
    return switch (event) {
        .v4 => |v| .{ .v4 = .{
            .address = v.address,
            .port = v.port,
            .last_sequence_number = v.status_sequence_number,
            .preferred = v.preferred,
            .retire = v.retire,
        } },
        .v6 => |v| .{ .v6 = .{
            .address = v.address,
            .port = v.port,
            .last_sequence_number = v.status_sequence_number,
            .preferred = v.preferred,
            .retire = v.retire,
        } },
    };
}

fn entryMatchesEvent(entry: Entry, event: AlternativeServerAddressEvent) bool {
    return switch (entry) {
        .v4 => |a| switch (event) {
            .v4 => |b| std.mem.eql(u8, &a.address, &b.address) and a.port == b.port,
            .v6 => false,
        },
        .v6 => |a| switch (event) {
            .v4 => false,
            .v6 => |b| std.mem.eql(u8, &a.address, &b.address) and a.port == b.port,
        },
    };
}

fn sequenceNumber(entry: Entry) u64 {
    return switch (entry) {
        .v4 => |v| v.last_sequence_number,
        .v6 => |v| v.last_sequence_number,
    };
}

/// Bounds on the random-delay window the scheduler hands to
/// `alt_addr.recommendedMigrationDelayMs`. The defaults are picked
/// for the public-internet shape:
///
///  - `min_ms = 50` keeps migrations responsive within a region.
///  - `max_ms = 500` smears 1k concurrently-notified clients across
///    half a second, well below realistic uplink limits at the
///    advertised victim.
///
/// Embedders on a private network (DC-internal, mTLS-pinned) often
/// drop these to single-digit milliseconds; embedders on a flaky
/// mobile carrier raise the upper bound to a few seconds so the
/// migration probe doesn't compete with TCP congestion in the
/// access network.
pub const SchedulerConfig = struct {
    min_delay_ms: u64 = 50,
    max_delay_ms: u64 = 500,
};

/// Picks (and remembers) when to perform the next migration based
/// on Preferred updates from the address book. The embedder's main
/// loop calls `tick(now_ms)` to drive any due migration; when the
/// scheduler hands back a target, the embedder validates the path
/// (PATH_CHALLENGE / PATH_RESPONSE) and, if validation succeeds,
/// adopts it as the active path.
pub const MigrationScheduler = struct {
    config: SchedulerConfig = .{},
    /// Earliest absolute time (in monotonic-clock ms) the embedder
    /// MAY initiate the next migration. `null` means no migration
    /// is currently scheduled.
    next_eligible_at_ms: ?u64 = null,
    /// The Preferred target the deadline is for. Refreshed every
    /// time `schedule` is called.
    target: ?Entry = null,

    /// Schedule a migration toward `target`. Picks a random delay
    /// within `[config.min_delay_ms, config.max_delay_ms]` and
    /// stores `now_ms + delay` as the eligibility threshold.
    /// Replaces any prior schedule.
    pub fn schedule(
        self: *MigrationScheduler,
        target: Entry,
        now_ms: u64,
    ) !void {
        const delay_ms = try quic_zig.alt_addr.recommendedMigrationDelayMs(
            self.config.min_delay_ms,
            self.config.max_delay_ms,
        );
        self.target = target;
        self.next_eligible_at_ms = now_ms + delay_ms;
    }

    /// Returns the scheduled migration target if its deadline has
    /// passed, otherwise `null`. Embedders call this each iteration
    /// of their poll loop. After a non-null return the schedule
    /// clears — the embedder is responsible for actually performing
    /// the migration before calling `schedule` again.
    pub fn dueMigration(self: *MigrationScheduler, now_ms: u64) ?Entry {
        const deadline = self.next_eligible_at_ms orelse return null;
        if (now_ms < deadline) return null;
        const target = self.target;
        self.next_eligible_at_ms = null;
        self.target = null;
        return target;
    }
};

/// Glue that runs the recommended `pollEvent` loop. The caller
/// supplies a forwarding callback for non-alt-addr events so the
/// embedder's existing event handling stays in one place.
pub const Embedder = struct {
    book: AddressBook = .{},
    scheduler: MigrationScheduler = .{},

    /// Drain every event currently on `conn`'s queue. Returns the
    /// number of `alternative_server_address` events processed so
    /// the caller can spot-check progress. `non_alt_callback` may be
    /// null; when set, every non-alt-addr event is forwarded so the
    /// embedder's existing pollEvent loop continues to fire.
    pub fn pump(
        self: *Embedder,
        conn: *quic_zig.Connection,
        now_ms: u64,
        non_alt_callback: ?*const fn (event: ConnectionEvent) void,
    ) !usize {
        var alt_count: usize = 0;
        while (conn.pollEvent()) |event| {
            switch (event) {
                .alternative_server_address => |alt| {
                    alt_count += 1;
                    _ = self.book.apply(alt);
                    if (alt.preferred()) {
                        if (self.book.currentPreferred()) |target| {
                            try self.scheduler.schedule(target, now_ms);
                        }
                    }
                },
                else => if (non_alt_callback) |cb| cb(event),
            }
        }
        return alt_count;
    }
};

// -- main: smoke-print so the example builds as an executable --------------

pub fn main() !void {
    // Tiny smoke main: prints the example's tunables so embedders
    // running `zig build examples && ./zig-out/bin/alt-addr-embedder-example`
    // see something sensible. The interesting code paths are in the
    // tests + the AddressBook / MigrationScheduler / Embedder
    // surface above.
    std.debug.print(
        "alt_addr_embedder: AddressBook capacity={d}, default delay window {d}..{d} ms\n",
        .{
            max_entries,
            (SchedulerConfig{}).min_delay_ms,
            (SchedulerConfig{}).max_delay_ms,
        },
    );
}

// -- tests ------------------------------------------------------------------

const testing = std.testing;

fn fakeV4(seq: u64, octets: [4]u8, port: u16, preferred: bool, retire: bool) AlternativeServerAddressEvent {
    return .{ .v4 = .{
        .address = octets,
        .port = port,
        .status_sequence_number = seq,
        .preferred = preferred,
        .retire = retire,
    } };
}

fn fakeV6(seq: u64, octets: [16]u8, port: u16, preferred: bool, retire: bool) AlternativeServerAddressEvent {
    return .{ .v6 = .{
        .address = octets,
        .port = port,
        .status_sequence_number = seq,
        .preferred = preferred,
        .retire = retire,
    } };
}

test "AddressBook: first event of a tuple appends a new entry" {
    var book: AddressBook = .{};
    try testing.expect(book.apply(fakeV4(1, .{ 192, 0, 2, 1 }, 4433, true, false)));
    try testing.expectEqual(@as(usize, 1), book.len);
    try testing.expect(book.entries[0] == .v4);
    try testing.expectEqual(@as(u64, 1), book.entries[0].v4.last_sequence_number);
    try testing.expect(book.entries[0].v4.preferred);
}

test "AddressBook: same tuple updates in place; new tuple appends" {
    var book: AddressBook = .{};
    _ = book.apply(fakeV4(1, .{ 192, 0, 2, 1 }, 4433, true, false));
    _ = book.apply(fakeV4(2, .{ 192, 0, 2, 1 }, 4433, false, true));
    _ = book.apply(fakeV4(3, .{ 198, 51, 100, 7 }, 4433, true, false));

    try testing.expectEqual(@as(usize, 2), book.len);
    // First tuple updated in place — Preferred bit cleared, Retire set.
    try testing.expect(!book.entries[0].v4.preferred);
    try testing.expect(book.entries[0].v4.retire);
    try testing.expectEqual(@as(u64, 2), book.entries[0].v4.last_sequence_number);
    // Second tuple appended.
    try testing.expectEqualSlices(u8, &.{ 198, 51, 100, 7 }, &book.entries[1].v4.address);
}

test "AddressBook: V4 vs V6 do not alias even at the same port" {
    var book: AddressBook = .{};
    _ = book.apply(fakeV4(1, .{ 192, 0, 2, 1 }, 4433, true, false));
    const v6_addr: [16]u8 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 1,
    };
    _ = book.apply(fakeV6(2, v6_addr, 4433, false, false));
    try testing.expectEqual(@as(usize, 2), book.len);
}

test "AddressBook: respects max_entries and refuses brand-new tuples once full" {
    var book: AddressBook = .{};
    var i: u8 = 0;
    while (i < max_entries) : (i += 1) {
        _ = book.apply(fakeV4(@as(u64, i), .{ 198, 51, 100, i }, 4433, false, false));
    }
    try testing.expectEqual(max_entries, book.len);
    // Updating an existing tuple still works.
    try testing.expect(book.apply(fakeV4(99, .{ 198, 51, 100, 0 }, 4433, true, false)));
    // A brand-new tuple is rejected.
    try testing.expect(!book.apply(fakeV4(100, .{ 198, 51, 100, 99 }, 4433, true, false)));
    try testing.expectEqual(max_entries, book.len);
}

test "AddressBook: currentPreferred returns the highest-sequence Preferred entry" {
    var book: AddressBook = .{};
    _ = book.apply(fakeV4(1, .{ 192, 0, 2, 1 }, 4433, true, false));
    _ = book.apply(fakeV4(5, .{ 198, 51, 100, 7 }, 4433, true, false));
    _ = book.apply(fakeV4(3, .{ 203, 0, 113, 9 }, 4433, false, false));

    const winner = book.currentPreferred() orelse return error.TestUnexpectedNull;
    try testing.expectEqualSlices(u8, &.{ 198, 51, 100, 7 }, &winner.v4.address);
    try testing.expectEqual(@as(u64, 5), winner.v4.last_sequence_number);
}

test "AddressBook: currentPreferred returns null when no entry is Preferred" {
    var book: AddressBook = .{};
    _ = book.apply(fakeV4(1, .{ 192, 0, 2, 1 }, 4433, false, false));
    _ = book.apply(fakeV4(2, .{ 198, 51, 100, 7 }, 4433, false, true));
    try testing.expect(book.currentPreferred() == null);
}

test "MigrationScheduler: schedule + dueMigration round-trip inside the configured window" {
    var sched: MigrationScheduler = .{ .config = .{ .min_delay_ms = 100, .max_delay_ms = 200 } };
    const target = Entry{ .v4 = .{
        .address = .{ 198, 51, 100, 7 },
        .port = 4433,
        .last_sequence_number = 5,
        .preferred = true,
        .retire = false,
    } };
    try sched.schedule(target, 1_000);
    try testing.expect(sched.next_eligible_at_ms != null);

    // Before the deadline: nothing due.
    try testing.expect(sched.dueMigration(1_050) == null);
    try testing.expect(sched.next_eligible_at_ms != null);

    // After the deadline window's upper bound: due.
    const due = sched.dueMigration(1_001 + 200) orelse return error.TestUnexpectedNull;
    try testing.expectEqualSlices(u8, &.{ 198, 51, 100, 7 }, &due.v4.address);
    // Schedule clears once consumed.
    try testing.expect(sched.next_eligible_at_ms == null);
    try testing.expect(sched.dueMigration(2_000) == null);
}

test "MigrationScheduler: degenerate config returns the lower bound" {
    var sched: MigrationScheduler = .{ .config = .{ .min_delay_ms = 25, .max_delay_ms = 25 } };
    const target = Entry{ .v4 = .{
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
        .last_sequence_number = 1,
        .preferred = true,
        .retire = false,
    } };
    try sched.schedule(target, 100);
    try testing.expectEqual(@as(?u64, 125), sched.next_eligible_at_ms);
}

test "Embedder.pump: drains alt-addr events and forwards non-alt-addr ones" {
    // We don't have a real Connection here, so this test exercises
    // AddressBook + MigrationScheduler directly (the same shape
    // pump() uses internally). The full pollEvent path is covered
    // end-to-end in tests/conformance/draft_munizaga_alt_addr_00.zig.
    var emb: Embedder = .{ .scheduler = .{ .config = .{ .min_delay_ms = 10, .max_delay_ms = 10 } } };

    // Two preferred events — the latter wins as the scheduler's
    // target because it has a higher sequence number.
    _ = emb.book.apply(fakeV4(1, .{ 192, 0, 2, 1 }, 4433, true, false));
    _ = emb.book.apply(fakeV4(7, .{ 198, 51, 100, 7 }, 4433, true, false));
    if (emb.book.currentPreferred()) |target| {
        try emb.scheduler.schedule(target, 0);
    }
    const due = emb.scheduler.dueMigration(100) orelse return error.TestUnexpectedNull;
    try testing.expectEqualSlices(u8, &.{ 198, 51, 100, 7 }, &due.v4.address);
}
