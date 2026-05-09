//! RFC 8899 — Datagram Packetization Layer Path MTU Discovery
//! (DPLPMTUD), QUIC profile.
//!
//! RFC 8899 specifies a generic active PMTU-discovery protocol. The
//! QUIC-specific application is documented under §6 (also leaning on
//! RFC 9000 §14.3 for the QUIC v1 minimum-MTU floor of 1200 bytes and
//! §14.4 for the PADDING+PING probe shape). quic_zig implements this
//! per-`PathState` so each application-data path probes / discovers
//! its own MTU independently — see `src/conn/path.zig` for the
//! state-machine primitives and `src/conn/state.zig` for the send /
//! ack / loss wiring.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC 8899 §4.4   MUST       black-hole detection: a sustained run
//!                              of regular-packet losses at the current
//!                              PMTU lowers it back toward
//!                              `initial_mtu` (the RFC 9000 §14
//!                              floor) and re-enters search.
//!   RFC 8899 §5.1.4 MUST       probe loss bumps a fail counter; once
//!                              the counter reaches `probe_threshold`,
//!                              the probed size is recorded as the
//!                              upper bound and search continues at
//!                              the current pmtu.
//!   RFC 8899 §5.1.5 MUST NOT   probe loss MUST NOT trigger congestion-
//!                              control reactions (cwnd, ssthresh,
//!                              recovery period).
//!   RFC 8899 §5.3.1 MUST       successful probe ack lifts pmtu to the
//!                              probed size; once the next probe step
//!                              would exceed the ceiling, transition
//!                              to search-complete.
//!   RFC 8899 §6     MUST       QUIC probe shape: PADDING+PING
//!                              ack-eliciting datagram padded to the
//!                              probed size (RFC 9000 §14.4).
//!   RFC 8899 §5.2   NORMATIVE  embedder configuration: the floor /
//!                              ceiling / step / threshold knobs and
//!                              the master enable switch.
//!
//! Out of scope here (covered elsewhere or not yet wired):
//!   RFC 8899 §3     QUIC-Initial padding (§14 minimum-MTU floor) is
//!                   pinned by the existing rfc9000_packetization /
//!                   rfc8999_invariants suites.
//!   RFC 8899 §5.5   Multipath: when the connection has more than one
//!                   active path, every path runs its own DPLPMTUD
//!                   state machine. The per-path state machine is
//!                   exercised by the inline `_state_tests` in
//!                   `src/conn/path.zig`; e2e multipath probing is a
//!                   future scope.

const std = @import("std");
const quic_zig = @import("quic_zig");
const conn_mod = quic_zig.conn;
const path_mod = conn_mod.path;
const wire = quic_zig.wire;
const short_packet = wire.short_packet;
const frame_mod = quic_zig.frame;

const testing = std.testing;
const handshake_fixture = @import("_handshake_fixture.zig");

// ---------------------------------------------------------------- §5.2 config

test "NORMATIVE PmtudConfig defaults match the QUIC v1 floor / 1500-friendly ceiling [RFC8899 §5.2]" {
    // Fresh-default config must hand out values that satisfy the
    // QUIC v1 minimum-MTU rule: initial_mtu = 1200 (the §14
    // floor), max_mtu high enough to actually reach a 1500-byte
    // ethernet MTU after 28 bytes of IPv4 + UDP, probe_step = 64
    // bytes (a common DPLPMTUD search step), probe_threshold = 3
    // (matches the RFC 9002 §6.1.1 packet-threshold so probe loss
    // gates align with regular loss timing), enabled.
    const cfg: path_mod.PmtudConfig = .{};
    try testing.expectEqual(@as(u16, 1200), cfg.initial_mtu);
    try testing.expectEqual(@as(u16, 1452), cfg.max_mtu);
    try testing.expectEqual(@as(u16, 64), cfg.probe_step);
    try testing.expectEqual(@as(u16, 3), cfg.probe_threshold);
    try testing.expect(cfg.enable);
}

test "NORMATIVE Connection.pmtu reports the active path's PMTU floor [RFC8899 §5.2]" {
    // Embedder-visible getter: hand out the active path's pmtu so
    // application telemetry (and DATAGRAM-frame sizing) reads a
    // single source of truth that DPLPMTUD updates as it learns.
    //
    // The fixture handshake also runs DPLPMTUD with the default
    // config so the value can be at or above the 1200-byte floor
    // (the in-band PADDING+PING probes successfully ack each round
    // trip on the loopback fixture). The contract here is "pmtu()
    // returns the active path's pmtu in usize bytes, never below
    // the configured initial_mtu".
    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();
    try testing.expect(pair.clientConn().pmtu() >= 1200);
    try testing.expectEqual(
        pair.clientConn().primaryPath().pmtu,
        pair.clientConn().pmtu(),
    );
    const srv = try pair.serverConn();
    try testing.expect(srv.pmtu() >= 1200);
}

test "NORMATIVE setPmtudConfig reseeds every existing path [RFC8899 §5.2]" {
    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // Tighten to a strict 1300-byte ceiling so we can verify the
    // ceiling propagates per-path (the search step would otherwise
    // race with the test ack/loss helpers below).
    pair.clientConn().setPmtudConfig(.{
        .initial_mtu = 1200,
        .max_mtu = 1300,
        .probe_step = 64,
        .probe_threshold = 3,
        .enable = true,
    });
    const path = pair.clientConn().primaryPath();
    try testing.expectEqual(@as(usize, 1200), path.pmtu);
    try testing.expectEqual(path_mod.PmtudState.search, path.pmtu_state);
    // Next probe size honors the embedder-supplied ceiling.
    try testing.expectEqual(
        @as(?u16, 1264),
        path.pmtudNextProbeSize(64, 1300),
    );
}

test "NORMATIVE enable=false leaves every path in disabled state [RFC8899 §5.2]" {
    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();
    pair.clientConn().setPmtudConfig(.{ .enable = false });
    const path = pair.clientConn().primaryPath();
    try testing.expectEqual(path_mod.PmtudState.disabled, path.pmtu_state);
    // No probe ever scheduled.
    try testing.expect(!path.pmtudIsSearching());
}

// ---------------------------------------------------------------- §6 probe shape

/// Helper: drain client → server and server → client until both
/// pipes are empty so the next `client.poll()` returns whatever the
/// scheduler picks first under controlled inputs.
///
/// Two passes: the first drains both directions repeatedly until
/// idle. The second flips PMTUD off on the client (to suppress
/// probes that would otherwise fire on each idle poll) and drains
/// again so the post-handshake control traffic (HANDSHAKE_DONE ack,
/// pending ACKs) all settles. The caller then re-enables PMTUD
/// with the desired config — `setPmtudConfig` reseeds the per-path
/// search state — and the next poll emits the very first probe.
fn drainAndSettle(pair: *handshake_fixture.HandshakePair) !void {
    // Suppress probes during the drain so the loop doesn't run the
    // entire DPLPMTUD search algorithm to completion.
    pair.clientConn().setPmtudConfig(.{ .enable = false });
    const srv = try pair.serverConn();
    srv.setPmtudConfig(.{ .enable = false });

    var pumped: u8 = 0;
    while (pumped < 16) : (pumped += 1) {
        var any = false;
        while (try pair.clientConn().poll(&pair.rx_buf, pair.now_us)) |len| {
            _ = try pair.server.feed(pair.rx_buf[0..len], pair.peer_addr, pair.now_us);
            any = true;
        }
        for (pair.server.iterator()) |slot| {
            while (try slot.conn.poll(&pair.rx_buf, pair.now_us)) |len| {
                try pair.clientConn().handle(pair.rx_buf[0..len], null, pair.now_us);
                any = true;
            }
        }
        if (!any) break;
    }
}

test "MUST emit PADDING+PING probe at pmtu+probe_step and exact datagram size [RFC8899 §6, RFC9000 §14.4]" {
    // The DPLPMTUD probe scheduler builds a 1-RTT packet sized to
    // `pmtu + probe_step`. The plaintext must contain exactly one
    // PING frame (0x01) plus PADDING (0x00) bytes — RFC 9000 §14.4
    // explicitly names PADDING+PING as the QUIC PMTU probe shape
    // (the PING makes the packet ack-eliciting, the PADDING inflates
    // the datagram to the probed size).

    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    // Drain post-handshake control traffic (HANDSHAKE_DONE ack,
    // any pending ACKs) with PMTUD suppressed so the search loop
    // doesn't pre-empt the test. Then enable the desired config —
    // `setPmtudConfig` reseeds search state on every path.
    try drainAndSettle(&pair);

    const client = pair.clientConn();
    // Pin the search step to a small known value so the probe size
    // is testable in isolation. probe_step=64 → first probe is at
    // 1264 bytes.
    client.setPmtudConfig(.{
        .initial_mtu = 1200,
        .max_mtu = 1452,
        .probe_step = 64,
        .probe_threshold = 3,
        .enable = true,
    });

    // Snapshot path probe state pre-poll.
    const path = client.primaryPath();
    try testing.expectEqual(path_mod.PmtudState.search, path.pmtu_state);
    try testing.expectEqual(@as(?u64, null), path.pmtu_probe_pn);

    pair.now_us +%= 1_000;
    var rx: [4096]u8 = undefined;
    const n_opt = try client.poll(&rx, pair.now_us);
    const n = n_opt orelse return error.TestExpectedProbe;
    // The probe size MUST equal pmtu + probe_step = 1264 bytes.
    try testing.expectEqual(@as(usize, 1264), n);
    // The path now reports an in-flight probe.
    try testing.expect(path.pmtu_probe_pn != null);
    try testing.expectEqual(@as(u16, 1264), path.pmtu_probed_size);
    try testing.expectEqual(@as(u16, 1), path.pmtu_probes_in_flight);
}

test "MUST mark probe packet as ack-eliciting and in-flight [RFC8899 §6, RFC9000 §13.2.1]" {
    // RFC 9000 §13.2.1: a packet is ack-eliciting iff it contains
    // any frame other than PADDING / ACK / CONNECTION_CLOSE. A
    // PADDING+PING bundle qualifies on the strength of the PING.
    // The wire-level packet is also "in-flight" (it counts toward
    // congestion control until ack/loss); RFC 8899 §4.4 says CC
    // reactions are skipped specifically when the loss outcome
    // fires, NOT when the packet is recorded.

    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    try drainAndSettle(&pair);

    const client = pair.clientConn();
    client.setPmtudConfig(.{ .initial_mtu = 1200, .max_mtu = 1452, .probe_step = 64 });

    var rx: [4096]u8 = undefined;
    pair.now_us +%= 1_000;
    _ = try client.poll(&rx, pair.now_us);

    const path = client.primaryPath();
    const probe_pn = path.pmtu_probe_pn orelse return error.TestExpectedProbe;
    // The sent-packet tracker carries the probe with ack_eliciting
    // = true and in_flight = true. Locate it by PN.
    const idx = path.sent.indexOf(probe_pn) orelse return error.TestProbeNotTracked;
    const sp = path.sent.packets[idx];
    try testing.expect(sp.ack_eliciting);
    try testing.expect(sp.in_flight);
    try testing.expectEqual(@as(u64, 1264), sp.bytes);
}

// ---------------------------------------------------------------- §5.3.1 probe ack

test "MUST lift pmtu to probed size on probe ack [RFC8899 §5.3.1]" {
    // RFC 8899 §5.3.1 search algorithm: when the peer ACKs a probe,
    // the PL Path MTU is updated to the probed size and the next
    // step is scheduled (or, if step would exceed the ceiling, the
    // state transitions to search-complete).

    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    try drainAndSettle(&pair);

    const client = pair.clientConn();
    client.setPmtudConfig(.{ .initial_mtu = 1200, .max_mtu = 1452, .probe_step = 64 });

    // Drive the probe out, then deliver it to the server, then drain
    // the server's ACK back to the client. After the ACK is
    // processed, the client's pmtu should rise to 1264.
    var rx: [4096]u8 = undefined;
    pair.now_us +%= 1_000;
    const n = (try client.poll(&rx, pair.now_us)) orelse return error.TestExpectedProbe;
    _ = try pair.server.feed(rx[0..n], pair.peer_addr, pair.now_us);

    // Pump server → client to deliver the ACK.
    pair.now_us +%= 1_000;
    for (pair.server.iterator()) |slot| {
        while (try slot.conn.poll(&rx, pair.now_us)) |len| {
            try client.handle(rx[0..len], null, pair.now_us);
        }
    }

    const path = client.primaryPath();
    try testing.expectEqual(@as(usize, 1264), path.pmtu);
    try testing.expectEqual(@as(?u64, null), path.pmtu_probe_pn);
    try testing.expectEqual(@as(u16, 0), path.pmtu_probes_in_flight);
}

// ---------------------------------------------------------------- §5.1.5 probe loss vs CC

test "MUST NOT trigger CC reaction when a probe is declared lost [RFC8899 §4.4 §5.1.5]" {
    // RFC 8899 §4.4 / §5.1.5: probe-packet loss is a discovery
    // signal, NOT a congestion signal. The implementation MUST NOT
    // shrink cwnd, bump ssthresh, or enter the recovery period
    // because of a probe loss. quic_zig's loss-detection path
    // routes a probe-PN-matched loss through `pmtudOnProbeLost`
    // and skips the LossStats add — which is what every CC update
    // function consumes. We assert the cwnd snapshot is unchanged
    // across the synthetic probe-loss event.

    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    try drainAndSettle(&pair);

    const client = pair.clientConn();
    client.setPmtudConfig(.{ .initial_mtu = 1200, .max_mtu = 1452, .probe_step = 64, .probe_threshold = 1 });

    // Send the probe but DON'T deliver it (simulate a black-hole
    // path that drops oversized datagrams). Then synthesize an ACK
    // that covers a NEWER non-probe packet so loss detection at
    // packet-threshold (default 3) declares the older probe lost.

    var rx: [4096]u8 = undefined;
    pair.now_us +%= 1_000;
    const probe_n = (try client.poll(&rx, pair.now_us)) orelse return error.TestExpectedProbe;
    _ = probe_n; // probe is not delivered.
    const path = client.primaryPath();
    const probe_pn = path.pmtu_probe_pn orelse return error.TestProbeNotRecorded;

    // Snapshot cwnd before any loss event.
    const cwnd_before = path.path.cc.cwnd;
    const ssthresh_before = path.path.cc.ssthresh;

    // Now build 3 PINGs from the client to bump app PNs forward,
    // then deliver them to the server. The server's ACK will cover
    // PNs >= probe_pn + 3, which packet-threshold (default 3)
    // treats as a loss declaration for the older probe PN.
    //
    // Simpler and more deterministic: directly fake the loss by
    // calling the connection's loss-detection helper with a
    // largest_acked that's >= probe_pn + 3. We achieve that by
    // bumping the path's `largest_acked_sent` directly.
    path.app_pn_space.largest_acked_sent = probe_pn + 4;
    try client.detectLossesByPacketThresholdOnApplicationPath(path);

    // Probe-loss accounting fired: probe PN slot is cleared, fail
    // counter incremented (or — at threshold=1 — the upper bound
    // is recorded immediately).
    try testing.expectEqual(@as(?u64, null), path.pmtu_probe_pn);
    try testing.expectEqual(@as(u16, 0), path.pmtu_probes_in_flight);
    try testing.expectEqual(@as(?u16, 1264), path.pmtu_upper_bound);

    // Most importantly: cwnd and ssthresh did NOT shrink. The
    // probe loss carried no LossStats so `onApplicationPathPacketsLost`
    // saw `in_flight_bytes_lost = 0` and skipped both the
    // `onPacketLost` cwnd cut and the persistent-congestion check.
    try testing.expectEqual(cwnd_before, path.path.cc.cwnd);
    try testing.expectEqual(ssthresh_before, path.path.cc.ssthresh);
}

test "MUST record upper bound after probe_threshold consecutive probe losses [RFC8899 §5.1.4]" {
    // RFC 8899 §5.1.4: `MAX_PROBES` (== `probe_threshold` here) is
    // the number of consecutive probe losses at the same probed
    // size before the implementation gives up on that size and
    // records it as the upper bound. Subsequent search-mode probes
    // must avoid sizes >= that bound.

    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    try drainAndSettle(&pair);

    const client = pair.clientConn();
    client.setPmtudConfig(.{
        .initial_mtu = 1200,
        .max_mtu = 1452,
        .probe_step = 64,
        .probe_threshold = 3,
    });

    const path = client.primaryPath();

    // Three consecutive probe losses at 1264 bytes.
    var rx: [4096]u8 = undefined;
    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        pair.now_us +%= 1_000;
        _ = (try client.poll(&rx, pair.now_us)) orelse return error.TestExpectedProbe;
        const probe_pn = path.pmtu_probe_pn orelse return error.TestProbeNotRecorded;
        // Force loss: bump largest_acked above the probe PN by 4.
        path.app_pn_space.largest_acked_sent = probe_pn + 4;
        try client.detectLossesByPacketThresholdOnApplicationPath(path);
    }
    try testing.expectEqual(@as(?u16, 1264), path.pmtu_upper_bound);
    // Search continues at the floor (1200) but never probes >= 1264.
    try testing.expectEqual(@as(usize, 1200), path.pmtu);
    // No further probe size lands at >= 1264 (next probe at 1200+64=1264 = upper bound,
    // which is treated as the closed boundary → search_complete).
    // (The boundary semantics live in `pmtudNextProbeSize`: a probe
    // size strictly less than the bound is fine, equal is not.)
    const next_size = path.pmtudNextProbeSize(64, 1452);
    if (next_size) |sz| try testing.expect(sz < 1264);
}

// ---------------------------------------------------------------- §4.4 black-hole

test "MUST halve pmtu after probe_threshold consecutive REGULAR losses [RFC8899 §4.4]" {
    // RFC 8899 §4.4: when the path-MTU drops while DPLPMTUD has
    // already lifted the local PMTU to a higher value, regular
    // packets at the higher value start blackholing. Once the
    // implementation observes `probe_threshold` consecutive regular
    // losses it MUST lower the PMTU back toward the floor and
    // re-enter the search state machine.

    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();
    const client = pair.clientConn();
    client.setPmtudConfig(.{
        .initial_mtu = 1200,
        .max_mtu = 1452,
        .probe_step = 64,
        .probe_threshold = 3,
    });
    const path = client.primaryPath();
    // Pretend earlier probes lifted pmtu to 1400 and search has
    // settled.
    path.pmtu = 1400;
    path.pmtu_state = .search_complete;

    // Three consecutive regular losses at the elevated pmtu →
    // halve down to 1200 (never below initial_mtu) and re-enter
    // search.
    try testing.expect(!path.pmtudOnRegularLost(3, 1200));
    try testing.expect(!path.pmtudOnRegularLost(3, 1200));
    try testing.expect(path.pmtudOnRegularLost(3, 1200));
    try testing.expectEqual(@as(usize, 1200), path.pmtu);
    try testing.expectEqual(path_mod.PmtudState.search, path.pmtu_state);
}

// ---------------------------------------------------------------- §5.3.1 termination

test "MUST transition to search_complete once pmtu+step exceeds max_mtu [RFC8899 §5.3.1]" {
    // RFC 8899 §5.3.1 termination condition: when a probe ack lifts
    // pmtu to a value such that pmtu + probe_step would exceed the
    // ceiling (max_mtu, or a smaller upper-bound recorded earlier),
    // the search algorithm transitions to search-complete and stops
    // scheduling probes.

    var pair = try handshake_fixture.HandshakePair.init(testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    try drainAndSettle(&pair);

    const client = pair.clientConn();
    // Tight ceiling: max_mtu = 1300, step = 64. The first probe at
    // 1264 acks → next would be 1328 > 1300 → search_complete.
    client.setPmtudConfig(.{
        .initial_mtu = 1200,
        .max_mtu = 1300,
        .probe_step = 64,
        .probe_threshold = 3,
    });

    const path = client.primaryPath();
    var rx: [4096]u8 = undefined;
    pair.now_us +%= 1_000;
    const n = (try client.poll(&rx, pair.now_us)) orelse return error.TestExpectedProbe;
    _ = try pair.server.feed(rx[0..n], pair.peer_addr, pair.now_us);
    pair.now_us +%= 1_000;
    for (pair.server.iterator()) |slot| {
        while (try slot.conn.poll(&rx, pair.now_us)) |len| {
            try client.handle(rx[0..len], null, pair.now_us);
        }
    }
    try testing.expectEqual(@as(usize, 1264), path.pmtu);
    try testing.expectEqual(path_mod.PmtudState.search_complete, path.pmtu_state);
    // No further probe scheduled — pollLevel returns null instead.
    try testing.expectEqual(@as(?u16, null), path.pmtudNextProbeSize(64, 1300));
}
