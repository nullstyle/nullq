//! quic_zig.alt_addr — embedder helpers for the
//! draft-munizaga-quic-alternative-server-address-00 extension.
//!
//! The extension's frame codec, transport-parameter negotiation,
//! server-emit API, and receive-side event surface live in
//! `frame.types`, `tls.transport_params`, `Connection.advertiseAlternative*Address`,
//! and `ConnectionEvent.alternative_server_address` respectively.
//! This module collects the small embedder-facing helpers that don't
//! belong on the Connection itself — today, the §9 thundering-herd
//! migration-delay helper.
//!
//! ## Embedder integration pattern
//!
//! The connection surfaces the §6 frames as a stream of typed
//! events. Acting on them — opening a path, migrating to it, tearing
//! down a Retire-marked path — is embedder policy per §6 / §9. A
//! reasonable shape:
//!
//! ```zig
//! while (conn.pollEvent()) |event| {
//!     switch (event) {
//!         .alternative_server_address => |alt| {
//!             // Track or update the address book the embedder owns.
//!             // The event stream is sequence-numbered (§6 ¶5) and
//!             // duplicates / out-of-order frames are pre-filtered
//!             // by the receive arm; the latest event for a given
//!             // sequence wins.
//!             try address_book.apply(alt);
//!
//!             if (alt.preferred()) {
//!                 // Smear the migration window per §9 to avoid a
//!                 // thundering-herd toward the advertised victim.
//!                 const delay = try alt_addr.recommendedMigrationDelayMs(50, 500);
//!                 try scheduler.scheduleMigration(alt, delay);
//!             } else if (alt.retire()) {
//!                 try paths.retireBoundTo(alt);
//!             }
//!         },
//!         else => { /* handle other event variants */ },
//!     }
//! }
//! ```
//!
//! ## Receive-event queue saturation
//!
//! `ConnectionEvent.alternative_server_address` events buffer in a
//! bounded `EventQueue` (capacity `max_alternative_address_events`
//! = 16). A peer that fires more than 16 updates between
//! `pollEvent` calls will see the oldest events evicted — but per
//! §6 ¶5 monotonicity the latest update always supersedes older
//! ones, so dropping older events is semantically safe. The
//! high-watermark is preserved on
//! `Connection.highestAlternativeAddressSequenceSeen()` even if the
//! event itself was evicted before the embedder polled.
//!
//! ## §4 ¶3 0-RTT contract
//!
//! "Endpoints MUST NOT remember the value of this extension for
//! 0-RTT." quic_zig satisfies this by construction: server emit
//! gates on the live handshake's transport parameters and the
//! `local_transport_params` is whatever the embedder configured for
//! *this* connection. Embedders that persist transport-parameter
//! blobs across sessions (e.g. for telemetry or for handing back to
//! the application layer) MUST clear `Params.alternative_address`
//! before re-installing such a blob into a fresh connection's
//! 0-RTT context.

const std = @import("std");
const boringssl = @import("boringssl");

/// Sample a cryptographically-random delay (in milliseconds) from a
/// uniform distribution over the closed range `[min_ms, max_ms]`.
/// Backs the §9 "Clients may mitigate this by randomly delaying the
/// migration" recommendation
/// (draft-munizaga-quic-alternative-server-address-00 §9):
/// a malicious server that ships `Preferred = true` updates to many
/// clients simultaneously can synthesize a thundering herd at the
/// advertised victim address. Embedders that auto-migrate on receipt
/// of a Preferred update SHOULD wait `recommendedMigrationDelayMs`
/// before initiating path validation, so concurrently-notified
/// clients smear their probes over the configured window.
///
/// Sizing guidance:
/// - `min_ms` keeps the migration responsive — 10..50 ms is typical
///   for round-trips within a single geographic region.
/// - `max_ms` controls the spread. With `max_ms = 500` a bursty
///   notification of 1k clients converts to about 2 PATH_CHALLENGE
///   probes per millisecond at the victim — well below any realistic
///   bandwidth cap.
///
/// Edge cases:
/// - Returns `min_ms` exactly when `min_ms == max_ms`.
/// - Returns `min_ms` when `max_ms < min_ms` (treat as a degenerate
///   no-spread window). The function does NOT panic on a misordered
///   range so embedders can pass user-supplied config through
///   without an extra clamp.
/// - Errors with `error.RandFailed` only if BoringSSL's CSPRNG draw
///   fails. Practically that never happens on modern OSes — the
///   error variant is plumbed through so embedders can surface a
///   diagnostic without auto-migrating on a degraded RNG.
pub fn recommendedMigrationDelayMs(
    min_ms: u64,
    max_ms: u64,
) boringssl.crypto.rand.Error!u64 {
    if (max_ms <= min_ms) return min_ms;
    const range = max_ms - min_ms + 1;
    var draw: [8]u8 = undefined;
    try boringssl.crypto.rand.fillBytes(&draw);
    const r = std.mem.readInt(u64, &draw, .little);
    return min_ms + (r % range);
}

test "recommendedMigrationDelayMs returns min_ms when range collapses" {
    try std.testing.expectEqual(@as(u64, 25), try recommendedMigrationDelayMs(25, 25));
    // Misordered range: prefer fail-soft over panic so embedders can
    // pass user-supplied configuration through without a clamp.
    try std.testing.expectEqual(@as(u64, 50), try recommendedMigrationDelayMs(50, 10));
}

test "recommendedMigrationDelayMs returns a value inside the requested range" {
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const v = try recommendedMigrationDelayMs(10, 500);
        try std.testing.expect(v >= 10);
        try std.testing.expect(v <= 500);
    }
}

test "recommendedMigrationDelayMs spreads across the requested range" {
    // Smoke test for the CSPRNG path: 256 draws across [0, 1000]
    // should hit at least 32 distinct values. The threshold is
    // generous — the test isn't a uniformity proof, it's a "did we
    // forget to actually draw randomness" canary.
    var seen: [1001]bool = @splat(false);
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        const v = try recommendedMigrationDelayMs(0, 1000);
        std.debug.assert(v <= 1000);
        seen[@intCast(v)] = true;
    }
    var distinct: usize = 0;
    for (seen) |hit| {
        if (hit) distinct += 1;
    }
    try std.testing.expect(distinct >= 32);
}
