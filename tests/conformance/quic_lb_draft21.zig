//! draft-ietf-quic-load-balancers-21 — server-side QUIC-LB
//! connection-ID generation conformance.
//!
//! This suite locks down the on-wire and config-validation rules a
//! quic_zig server-side stack honours when an embedder opts into
//! `Server.Config.quic_lb`. Pinned to draft revision 21 — bumping
//! `quic_zig.quic_lb_draft_version` is a deliberate scoped change.
//!
//! ## Coverage (LB-1 through LB-6)
//!
//!   §3        MUST       first-octet bits 0-2 carry config_id (0..6)
//!   §3        MUST       first-octet bits 3-7 carry (cid_len - 1) when encoding
//!   §3        MUST       reject config_id == 0b111 (reserved unroutable)
//!   §3        MUST       reject server_id length 0
//!   §3        MUST       reject server_id length > 15
//!   §3        MUST       reject nonce length < 4
//!   §3        MUST       reject nonce length > 18
//!   §3        MUST       reject server_id + nonce > 19
//!   §3 ¶3     SHOULD     plaintext mode auto-sets disable_active_migration
//!                        unless the embedder already enabled it
//!   §3.1      MUST       unroutable CID encodes config_id 0b111 + length
//!   §3.1      SHOULD     unroutable CID is at least 8 octets (1 + 7 entropy)
//!   §3 ¶3     MUST       Server falls back to unroutable on nonce exhaustion
//!                        when local_cid_len ≥ 8 (otherwise surfaces RandFailed)
//!   §5.2      NORMATIVE  plaintext CID body equals server_id || nonce
//!   §5.2      NORMATIVE  fresh nonce on every mint (CSPRNG draw)
//!   §5.4.1    MUST       single-pass mode selected when combined == 16
//!   §5.4.1    MUST       single-pass body is AES-128-ECB(key, server_id||nonce)
//!   §5.4.1    MUST       first octet is written in the clear, never encrypted
//!   §5.4 ¶3   MUST NOT   reuse a nonce under the same key
//!                        (NonceCounter advances per mint, errors on wrap)
//!   §5.4.2    MUST       four-pass Feistel selected when combined != 16 (with key)
//!   §5.4.2    MUST       four-pass output is length-preserving
//!   §5.4.2.4  KAT        worked example (3+4 odd plaintext) round-trips byte-exact
//!   §5.5      NORMATIVE  decode round-trips plaintext mints (LB-side)
//!   §5.5.1    NORMATIVE  decode round-trips single-pass mints (LB-side)
//!   §5.5.1    KAT        Appendix B.2 #2 decoded byte-exact (LB-side)
//!   §5.5.2    NORMATIVE  decode round-trips four-pass mints (LB-side)
//!   §B.2 #2   KAT        single-pass vector for config_id=2 round-trips (encode)
//!   server    NORMATIVE  installLbConfig swaps the active factory
//!                        (rotation; CIDs minted afterward use the new config)
//!
//! ## Out of scope here
//!
//!   * Load-balancer-side decoding — quic_zig ships server-side only.
//!     A future stretch goal may add a decode helper for ops tooling.
//!   * Retry Service — per draft-21 change log, the Retry Service was
//!     split into a separate document. Not part of this draft.

const std = @import("std");
const quic_zig = @import("quic_zig");
const handshake_fixture = @import("_handshake_fixture.zig");
const initial_fixture = @import("_initial_fixture.zig");

const lb = quic_zig.lb;

// ---------------------------------------------------------------- §3 first-octet layout

test "MUST encode config_id in the high 3 bits of the first octet [draft-ietf-quic-load-balancers-21 §3]" {
    // Draft §3: "The first three bits of the connection ID encode a
    // 'config rotation' identifier with values 0–6." Each minted CID
    // must read back the configured `config_id` via the high 3 bits.
    var i: u8 = 0;
    while (i <= 6) : (i += 1) {
        const cfg: lb.LbConfig = .{
            .config_id = @intCast(i),
            .server_id = try lb.ServerId.fromSlice(&.{ 0xa, 0xb }),
            .nonce_len = 4,
        };
        var f = try lb.Factory.init(cfg);
        var cid: [32]u8 = undefined;
        const n = try f.mint(&cid);
        try std.testing.expectEqual(@as(u8, i), lb.cid.firstOctetConfigId(cid[0]));
        // Length-encoding mode is on by default — the low 5 bits hold
        // (cid_len - 1) so peers / LBs can self-describe the CID
        // length on short headers (next test asserts this directly).
        try std.testing.expectEqual(@as(u8, @intCast(n - 1)), lb.cid.firstOctetLengthBits(cid[0]));
    }
}

test "MUST encode (cid_len - 1) in the low 5 bits when encode_length is true [draft-ietf-quic-load-balancers-21 §3]" {
    // Draft §3 covers two options for the low 5 bits — self-describe
    // length, or fill with random. quic_zig defaults `encode_length` to
    // true; the wire result is exactly the CID length minus one (so
    // values fit in 5 bits up to the 20-octet QUIC v1 cap).
    const cfg: lb.LbConfig = .{
        .config_id = 3,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3, 4, 5 }),
        .nonce_len = 8,
    };
    var f = try lb.Factory.init(cfg);
    var cid: [32]u8 = undefined;
    const n = try f.mint(&cid);
    try std.testing.expectEqual(@as(usize, 1 + 5 + 8), n);
    try std.testing.expectEqual(@as(u8, @intCast(n - 1)), lb.cid.firstOctetLengthBits(cid[0]));
}

// ---------------------------------------------------------------- §3 length bounds

test "MUST reject config_id 0b111 in active configurations [draft-ietf-quic-load-balancers-21 §3.1]" {
    // §3.1 reserves 0b111 for the unroutable fallback CID, which an
    // embedder never sets via `LbConfig` directly — it's minted
    // through a separate path (LB-5).
    const cfg: lb.LbConfig = .{
        .config_id = 0b111,
        .server_id = try lb.ServerId.fromSlice(&.{0xaa}),
        .nonce_len = 4,
    };
    try std.testing.expectError(lb.config.Error.InvalidLbConfig, cfg.validate());
}

test "MUST reject empty server_id [draft-ietf-quic-load-balancers-21 §3]" {
    try std.testing.expectError(lb.config.Error.InvalidServerId, lb.ServerId.fromSlice(&.{}));
}

test "MUST reject server_id longer than 15 octets [draft-ietf-quic-load-balancers-21 §3]" {
    var oversize: [16]u8 = @splat(0xaa);
    try std.testing.expectError(lb.config.Error.InvalidServerId, lb.ServerId.fromSlice(&oversize));
}

test "MUST reject nonce_len below 4 octets [draft-ietf-quic-load-balancers-21 §3]" {
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{0xaa}),
        .nonce_len = 3,
    };
    try std.testing.expectError(lb.config.Error.InvalidLbConfig, cfg.validate());
}

test "MUST reject nonce_len above 18 octets [draft-ietf-quic-load-balancers-21 §3]" {
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{0xaa}),
        .nonce_len = 19,
    };
    try std.testing.expectError(lb.config.Error.InvalidLbConfig, cfg.validate());
}

test "MUST reject server_id + nonce combined length above 19 octets [draft-ietf-quic-load-balancers-21 §3]" {
    const sid_bytes: [15]u8 = @splat(0xaa);
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&sid_bytes),
        .nonce_len = 5, // 15 + 5 = 20 > 19
    };
    try std.testing.expectError(lb.config.Error.InvalidLbConfig, cfg.validate());
}

// ---------------------------------------------------------------- §5.2 plaintext mode

test "NORMATIVE plaintext CID body is server_id || nonce [draft-ietf-quic-load-balancers-21 §5.2]" {
    // §5.2: "The Server ID is in the most significant bytes of the
    // plaintext block, followed by the Nonce." With no key configured,
    // those bytes appear directly in the CID after the first octet.
    const sid_bytes: []const u8 = &.{ 0xde, 0xad, 0xbe, 0xef };
    const cfg: lb.LbConfig = .{
        .config_id = 1,
        .server_id = try lb.ServerId.fromSlice(sid_bytes),
        .nonce_len = 6,
    };
    var f = try lb.Factory.init(cfg);
    var cid: [32]u8 = undefined;
    const n = try f.mint(&cid);
    try std.testing.expectEqual(@as(usize, 1 + 4 + 6), n);
    try std.testing.expectEqualSlices(u8, sid_bytes, cid[1 .. 1 + sid_bytes.len]);
}

test "NORMATIVE plaintext mint draws a fresh nonce on every call [draft-ietf-quic-load-balancers-21 §5.2]" {
    // §5.2: "A server SHOULD fill the Nonce field with bytes that have
    // no observable correlation to those of any previous Nonce."
    // The CSPRNG draw satisfies the SHOULD trivially; the property
    // here is that the same `Factory` produces nonces that compare
    // unequal across calls.
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{ 0xab, 0xcd }),
        .nonce_len = 8, // 8 random bytes — collision odds 2^-64 per pair.
    };
    var f = try lb.Factory.init(cfg);
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    _ = try f.mint(&a);
    _ = try f.mint(&b);
    const a_nonce = a[1 + 2 .. 1 + 2 + 8];
    const b_nonce = b[1 + 2 .. 1 + 2 + 8];
    try std.testing.expect(!std.mem.eql(u8, a_nonce, b_nonce));
}

// ---------------------------------------------------------------- §3 ¶3 plaintext-mode SHOULD

test "SHOULD auto-set disable_active_migration when QUIC-LB is plaintext [draft-ietf-quic-load-balancers-21 §3 ¶3]" {
    // §3 ¶3: "Servers that are encoding their server ID without a key
    // algorithm … SHOULD send the disable_active_migration transport
    // parameter." The Server in plaintext mode SHOULD NOT issue extra
    // CIDs via NEW_CONNECTION_ID, and disabling active migration
    // signals that intent to peers. quic_zig auto-flips this when the
    // embedder hasn't already.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var transport_params = handshake_fixture.defaultParams();
    transport_params.disable_active_migration = false;

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = transport_params,
        .quic_lb = .{
            .config_id = 0,
            .server_id = try lb.ServerId.fromSlice(&.{ 0x01, 0x02, 0x03 }),
            .nonce_len = 6,
        },
    });
    defer srv.deinit();

    try std.testing.expect(srv.transport_params.disable_active_migration);
}

test "NORMATIVE Server.init resolves local_cid_len from the QUIC-LB config [draft-ietf-quic-load-balancers-21 §3]" {
    // §3 fixes the CID length at `1 + server_id_len + nonce_len`. The
    // Server overrides the user-supplied `local_cid_len` so the wire
    // shape and the routing-key length agree on the lb-derived value.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        .local_cid_len = 8, // intentionally different from the LB-derived value
        .quic_lb = .{
            .config_id = 2,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd }),
            .nonce_len = 7, // 1 + 4 + 7 = 12
        },
    });
    defer srv.deinit();

    try std.testing.expectEqual(@as(u8, 12), srv.local_cid_len);
}

test "NORMATIVE Server.init leaves local_cid_len untouched without QUIC-LB config [draft-ietf-quic-load-balancers-21 §3]" {
    // Regression for the "off by default" hardening guarantee: when
    // `quic_lb` is null, the embedder's `local_cid_len` is honoured
    // verbatim and SCIDs are pure CSPRNG draws (covered indirectly —
    // any deviation would surface here as a wrong length).
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        .local_cid_len = 14,
    });
    defer srv.deinit();

    try std.testing.expectEqual(@as(u8, 14), srv.local_cid_len);
}

// ---------------------------------------------------------------- §5.4.1 single-pass AES-128-ECB

test "MUST select single-pass mode when server_id + nonce sum to 16 octets [draft-ietf-quic-load-balancers-21 §5.4.1]" {
    // §5.4.1: "When the nonce length and server ID length sum to
    // exactly 16 octets, the server MUST use a single-pass encryption
    // algorithm." `Factory.mode()` reads back the dispatch decision.
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }),
        .nonce_len = 8,
        .key = @splat(0x42),
    };
    var f = try lb.Factory.init(cfg);
    defer f.deinit();
    try std.testing.expectEqual(lb.Mode.aes_single_pass, f.mode());
}

test "MUST encrypt the body with AES-128-ECB(key, server_id||nonce) [draft-ietf-quic-load-balancers-21 §B.2]" {
    // Appendix B.2 vector #2 (config_id = 2):
    //   key       = 8f95f09245765f80256934e50c66207f
    //   server_id = ed793a51d49b8f5f
    //   nonce     = ee080dbf48c0d1e5
    //   on-wire   = 504dd2d05a7b0de9b2b9907afb5ecf8cc3
    //
    // The first octet 0x50 = (config_id << 5) | (cid_len - 1) =
    // (2 << 5) | 16 = 0x50, with the LB self-encoding the CID
    // length on the wire so a peer or LB seeing a short header
    // can recover the routing key without other context.
    const key = hexToBytes16("8f95f09245765f80256934e50c66207f");
    const sid_bytes = hexToBytes8("ed793a51d49b8f5f");
    const nonce_bytes = hexToBytes8("ee080dbf48c0d1e5");
    const expected_cid = hexToBytes17("504dd2d05a7b0de9b2b9907afb5ecf8cc3");

    var f = try lb.Factory.init(.{
        .config_id = 2,
        .server_id = try lb.ServerId.fromSlice(&sid_bytes),
        .nonce_len = 8,
        .key = key,
    });
    defer f.deinit();

    var cid: [17]u8 = undefined;
    const n = try f.mintWithNonce(&cid, &nonce_bytes);
    try std.testing.expectEqual(@as(usize, 17), n);
    try std.testing.expectEqualSlices(u8, &expected_cid, &cid);
}

test "MUST keep the first octet unencrypted in single-pass mode [draft-ietf-quic-load-balancers-21 §5.4.1]" {
    // §5.4.1: "All connection ID octets except the first form an
    // AES-ECB block." The first octet is composed plaintext-style and
    // never fed to AES, so its config_id readout is identical to the
    // plaintext-mode case.
    const key: [16]u8 = @splat(0xab);
    const sid_bytes: [8]u8 = .{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f };
    const nonce_bytes: [8]u8 = .{ 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5 };

    var f = try lb.Factory.init(.{
        .config_id = 5,
        .server_id = try lb.ServerId.fromSlice(&sid_bytes),
        .nonce_len = 8,
        .key = key,
    });
    defer f.deinit();

    var cid: [17]u8 = undefined;
    _ = try f.mintWithNonce(&cid, &nonce_bytes);
    try std.testing.expectEqual(@as(u8, 5), lb.cid.firstOctetConfigId(cid[0]));
    try std.testing.expectEqual(@as(u8, 16), lb.cid.firstOctetLengthBits(cid[0]));
}

test "MUST advance nonce per mint so the same nonce is never reused [draft-ietf-quic-load-balancers-21 §5.4 ¶3]" {
    // §5.4 ¶3: "If servers simply increment the nonce by one with each
    // generated connection ID, then it is safe to use the existing
    // keys until any server's nonce counter exhausts the allocated
    // space and rolls over." The factory's NonceCounter does exactly
    // that — observable as two consecutive mints producing distinct
    // ciphertext blocks under the same key.
    const cfg: lb.LbConfig = .{
        .config_id = 1,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }),
        .nonce_len = 8,
        .key = @splat(0x33),
    };
    var f = try lb.Factory.init(cfg);
    defer f.deinit();

    var a: [17]u8 = undefined;
    var b: [17]u8 = undefined;
    _ = try f.mint(&a);
    _ = try f.mint(&b);
    // First octet may differ if encode_length is false; the body
    // (16 ciphertext bytes) must differ because the nonce advanced.
    try std.testing.expect(!std.mem.eql(u8, a[1..17], b[1..17]));
}

test "MUST refuse to mint when the nonce counter wraps [draft-ietf-quic-load-balancers-21 §5.4 ¶3]" {
    // §5.4 ¶3 requires "either switch to a new configuration or use
    // [the unroutable] config_id" once the nonce space exhausts. LB-1
    // through LB-2 surface the rotation point as `error.NonceExhausted`
    // from `Factory.mint`; LB-4 will turn it into a recoverable
    // rotation event, and LB-5 will mint an unroutable CID.
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }),
        .nonce_len = 8,
        .key = @splat(0x33),
    };
    var f = try lb.Factory.init(cfg);
    defer f.deinit();

    // Force the counter to its maximum so the next mint marks it
    // exhausted; the *following* mint refuses.
    if (f.nonce_counter) |*nc| {
        @memset(nc.bytes[0..nc.nonce_len], 0xff);
    } else return error.UnexpectedlyMissingNonceCounter;

    var dst: [17]u8 = undefined;
    _ = try f.mint(&dst); // succeeds, counter wraps after.
    try std.testing.expectError(lb.Error.NonceExhausted, f.mint(&dst));
}

// ---------------------------------------------------------------- §5.4.2 four-pass Feistel

test "MUST select four-pass mode when combined != 16 with a key configured [draft-ietf-quic-load-balancers-21 §5.4.2]" {
    // §5.4.2: "When configured with both a key, and a nonce length and
    // server ID length that sum to any number other than 16, the
    // server MUST follow the [four-pass] algorithm." Mode dispatch is
    // pure on `(key, server_id_len + nonce_len)`.
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3, 4 }),
        .nonce_len = 8, // combined = 12, even, != 16
        .key = @splat(0x42),
    };
    var f = try lb.Factory.init(cfg);
    defer f.deinit();
    try std.testing.expectEqual(lb.Mode.aes_four_pass, f.mode());
}

test "KAT §5.4.2.4 worked example: 3-byte server_id, 4-byte nonce, odd combined [draft-ietf-quic-load-balancers-21 §5.4.2.4]" {
    // The draft's narrative example wires every dial that matters
    // (odd plaintext length, the boundary-nibble clearing, the four
    // distinct AES inputs through `expand`). Byte-exact match is the
    // gating property — any encoder bug shows up here.
    //
    //   server_id = 31441a
    //   nonce     = 9c69c275
    //   key       = fdf726a9893ec05c0632d3956680baf0
    //   on-wire   = 0767947d29be054a (8 bytes; first octet 0x07)
    const key = hexToBytes16("fdf726a9893ec05c0632d3956680baf0");
    const sid_bytes: [3]u8 = .{ 0x31, 0x44, 0x1a };
    const nonce_bytes: [4]u8 = .{ 0x9c, 0x69, 0xc2, 0x75 };
    const expected_cid: [8]u8 = .{ 0x07, 0x67, 0x94, 0x7d, 0x29, 0xbe, 0x05, 0x4a };

    var f = try lb.Factory.init(.{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&sid_bytes),
        .nonce_len = 4,
        .key = key,
    });
    defer f.deinit();

    var cid: [8]u8 = undefined;
    const n = try f.mintWithNonce(&cid, &nonce_bytes);
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualSlices(u8, &expected_cid, &cid);
}

test "MUST keep four-pass output length identical to plaintext block [draft-ietf-quic-load-balancers-21 §5.4.2]" {
    // The Feistel network is length-preserving by construction: the
    // body of the CID has exactly `combined` bytes regardless of mode
    // choice. Iterate every supported `combined` from 5..15 and 17..19
    // (skipping 16, which is single-pass territory) under the same key.
    const key: [16]u8 = @splat(0xab);
    const sid_full: [10]u8 = .{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13 };
    var combined: usize = 5;
    while (combined <= 19) : (combined += 1) {
        if (combined == 16) continue;
        // Choose any sid_len in 1..combined-4 (so nonce_len >= 4).
        const sid_len: u8 = @intCast(@max(1, @min(combined - 4, sid_full.len)));
        const nonce_len: u8 = @intCast(combined - @as(usize, sid_len));
        var f = try lb.Factory.init(.{
            .config_id = 1,
            .server_id = try lb.ServerId.fromSlice(sid_full[0..sid_len]),
            .nonce_len = nonce_len,
            .key = key,
        });
        defer f.deinit();
        var cid: [20]u8 = undefined;
        const n = try f.mint(&cid);
        try std.testing.expectEqual(@as(usize, 1 + combined), n);
    }
}

test "MUST round-trip four-pass encrypt/decrypt for every supported length [draft-ietf-quic-load-balancers-21 §5.4.2 / §5.5.2]" {
    // Pure-Feistel round-trip: encrypt then decrypt under the same
    // key recovers the plaintext exactly. This is independent of the
    // CID assembly and pins down the inverse-function property.
    const key: [16]u8 = @splat(0x77);
    const aes = try @import("boringssl").crypto.aes.Aes128.init(&key);

    var combined: usize = 5;
    while (combined <= 19) : (combined += 1) {
        if (combined == 16) continue;
        var pt_buf: [19]u8 = undefined;
        for (pt_buf[0..combined], 0..) |*b, i| b.* = @intCast((i * 13 + 1) & 0xff);
        const pt = pt_buf[0..combined];

        var ct_buf: [19]u8 = undefined;
        const ct = ct_buf[0..combined];
        try lb.feistel.encrypt(&aes, pt, ct);

        var pt2_buf: [19]u8 = undefined;
        const pt2 = pt2_buf[0..combined];
        try lb.feistel.decrypt(&aes, ct, pt2);
        try std.testing.expectEqualSlices(u8, pt, pt2);
    }
}

// ---------------------------------------------------------------- §3.1 auto-fallback (Server-level)

test "MUST fall back to unroutable CIDs once the active nonce counter exhausts [draft-ietf-quic-load-balancers-21 §3 ¶3]" {
    // §3 ¶3: "When the nonce counter exhausts, the server MUST
    // either switch to a new configuration or use the [unroutable]
    // 0b111 config_id." quic_zig's Server-level `mintLocalScid`
    // implements the latter automatically: forced exhaustion plus a
    // mint produces a `0b111` first octet so the LB can route via
    // its fallback path while the operator pushes a fresh
    // configuration via `installLbConfig`.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        .quic_lb = .{
            .config_id = 1,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xaa, 0xbb }),
            .nonce_len = 6, // cidLength = 9 ≥ 8 (unroutable minimum)
            .key = @splat(0xab), // encrypted mode — has a nonce counter
        },
    });
    defer srv.deinit();

    // Pre-exhaust: a normal mint emits config_id = 1 in the high 3
    // bits.
    var pre: [9]u8 = undefined;
    try srv.mintLocalScid(&pre);
    try std.testing.expectEqual(@as(u8, 1), lb.cid.firstOctetConfigId(pre[0]));

    // Force the nonce counter to wrap on the next `next` call by
    // setting every byte of the counter buffer to 0xff and minting
    // once (which advances and trips the exhaustion flag).
    if (srv.lb_factory.?.nonce_counter) |*nc| {
        @memset(nc.bytes[0..nc.nonce_len], 0xff);
    }
    try srv.mintLocalScid(&pre); // succeeds, counter wraps after.

    // Subsequent mints take the unroutable fallback: first octet
    // high 3 bits = 0b111 with the low 5 bits self-encoding length.
    var post: [9]u8 = undefined;
    try srv.mintLocalScid(&post);
    try std.testing.expectEqual(@as(u8, 0b111), lb.cid.firstOctetConfigId(post[0]));
    try std.testing.expectEqual(@as(u8, 8), lb.cid.firstOctetLengthBits(post[0]));
}

test "MUST surface RandFailed on auto-fallback when local_cid_len < 8 [draft-ietf-quic-load-balancers-21 §3.1]" {
    // §3.1 SHOULD: unroutable CIDs are at least 8 octets. If the
    // active LB config produces shorter CIDs, the auto-fallback
    // can't honour the floor and surfaces `RandFailed` so the
    // surrounding feed/poll loop bails on this Initial. Operators
    // detect via the standard error path and rotate to a longer
    // configuration.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        .quic_lb = .{
            .config_id = 0,
            .server_id = try lb.ServerId.fromSlice(&.{0xaa}),
            .nonce_len = 4, // cidLength = 6 < 8
            .key = @splat(0x33),
        },
    });
    defer srv.deinit();

    // Force exhaustion same way as above.
    if (srv.lb_factory.?.nonce_counter) |*nc| {
        @memset(nc.bytes[0..nc.nonce_len], 0xff);
    }
    var burn: [6]u8 = undefined;
    try srv.mintLocalScid(&burn); // wrap

    var dst: [6]u8 = undefined;
    try std.testing.expectError(quic_zig.Server.Error.RandFailed, srv.mintLocalScid(&dst));
}

// ---------------------------------------------------------------- §3.1 unroutable fallback

test "MUST set first-octet config_id to 0b111 for unroutable CIDs [draft-ietf-quic-load-balancers-21 §3.1]" {
    // §3.1: "Servers ... MUST issue connection IDs with the first
    // three bits set to 0b111." The unroutable mint path writes that
    // pattern unconditionally so an LB short-circuits routing for
    // these CIDs (no `server_id` to recover).
    var cid: [16]u8 = undefined;
    const n = try lb.mintUnroutable(&cid, 12);
    try std.testing.expectEqual(@as(usize, 12), n);
    try std.testing.expectEqual(@as(u8, 0b111), lb.cid.firstOctetConfigId(cid[0]));
}

test "MUST self-encode CID length in unroutable first octet [draft-ietf-quic-load-balancers-21 §3.1]" {
    // §3.1: unroutable CIDs MUST self-encode length so the LB can
    // peek the length on a short header without configuration.
    var cid: [16]u8 = undefined;
    _ = try lb.mintUnroutable(&cid, 11);
    try std.testing.expectEqual(@as(u8, 10), lb.cid.firstOctetLengthBits(cid[0]));
}

test "SHOULD make unroutable CIDs at least 8 octets total [draft-ietf-quic-load-balancers-21 §3.1]" {
    // §3.1: 1 first octet + at least 7 octets of entropy = 8 octets
    // minimum. Smaller requests fail.
    var cid: [16]u8 = undefined;
    try std.testing.expectError(lb.Error.InvalidLbConfig, lb.mintUnroutable(&cid, 7));
    // 8 is the minimum acceptable.
    const n = try lb.mintUnroutable(&cid, 8);
    try std.testing.expectEqual(@as(usize, 8), n);
}

// ---------------------------------------------------------------- §5.5 LB-side decode

test "NORMATIVE decode round-trips plaintext mints [draft-ietf-quic-load-balancers-21 §5.5]" {
    // §5.5: "The load balancer ... extracts the server ID from the
    // most significant bytes of the resulting plaintext." For
    // plaintext mode that's a direct extraction; round-trip must
    // recover the byte-exact server_id and nonce we minted with.
    const sid_bytes: []const u8 = &.{ 0xde, 0xad, 0xbe, 0xef };
    const nonce_bytes: []const u8 = &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const cfg: lb.LbConfig = .{
        .config_id = 4,
        .server_id = try lb.ServerId.fromSlice(sid_bytes),
        .nonce_len = @intCast(nonce_bytes.len),
    };
    var f = try lb.Factory.init(cfg);
    defer f.deinit();
    var cid: [16]u8 = undefined;
    const n = try f.mintWithNonce(&cid, nonce_bytes);

    const decoded = try lb.decode(cid[0..n], cfg);
    try std.testing.expectEqual(@as(u8, 4), decoded.config_id);
    try std.testing.expectEqualSlices(u8, sid_bytes, decoded.server_id.slice());
    try std.testing.expectEqualSlices(u8, nonce_bytes, decoded.nonceSlice());
}

test "NORMATIVE decode round-trips four-pass mints across odd/even lengths [draft-ietf-quic-load-balancers-21 §5.5.2]" {
    const key: [16]u8 = @splat(0x55);
    const sid_full: [10]u8 = .{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa };
    const nonce_full: [18]u8 = @splat(0xbb);

    var combined: usize = 5;
    while (combined <= 19) : (combined += 1) {
        if (combined == 16) continue; // single-pass; deferred decode
        const sid_len: u8 = @intCast(@max(1, @min(combined - 4, sid_full.len)));
        const nonce_len: u8 = @intCast(combined - @as(usize, sid_len));

        const cfg: lb.LbConfig = .{
            .config_id = 1,
            .server_id = try lb.ServerId.fromSlice(sid_full[0..sid_len]),
            .nonce_len = nonce_len,
            .key = key,
        };
        var f = try lb.Factory.init(cfg);
        defer f.deinit();

        var cid: [20]u8 = undefined;
        const n = try f.mintWithNonce(&cid, nonce_full[0..nonce_len]);
        const decoded = try lb.decode(cid[0..n], cfg);
        try std.testing.expectEqualSlices(u8, sid_full[0..sid_len], decoded.server_id.slice());
        try std.testing.expectEqualSlices(u8, nonce_full[0..nonce_len], decoded.nonceSlice());
    }
}

test "decode: returns UnroutableCid when peek sees config_id 0b111 [draft-ietf-quic-load-balancers-21 §3.1]" {
    var unroutable: [12]u8 = undefined;
    _ = try lb.mintUnroutable(&unroutable, 12);
    const cfg: lb.LbConfig = .{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3 }),
        .nonce_len = 8,
    };
    try std.testing.expectError(lb.DecodeError.UnroutableCid, lb.decode(&unroutable, cfg));
}

// ---------------------------------------------------------------- Server-level rotation (LB-4)

test "NORMATIVE installLbConfig swaps the active factory and subsequent mints use new config_id [server rotation]" {
    // The Server-level public surface for QUIC-LB rotation. Calling
    // `installLbConfig` replaces the active factory in place; the old
    // factory's key bytes are zeroed by `Factory.deinit`. Subsequent
    // mints (post-Initial Slot SCIDs, Retry SCIDs) use the new
    // config_id; existing CIDs in the routing table remain valid
    // until the peer retires them organically.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        .quic_lb = .{
            .config_id = 1,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xaa, 0xbb }),
            .nonce_len = 6, // cidLength = 9
        },
    });
    defer srv.deinit();

    // Mint a CID under the old config and confirm config_id = 1.
    var pre: [9]u8 = undefined;
    _ = try srv.lb_factory.?.mint(&pre);
    try std.testing.expectEqual(@as(u8, 1), lb.cid.firstOctetConfigId(pre[0]));

    // Rotate: new config_id, same cidLength.
    try srv.installLbConfig(.{
        .config_id = 5,
        .server_id = try lb.ServerId.fromSlice(&.{ 0xcc, 0xdd }),
        .nonce_len = 6,
    });

    var post: [9]u8 = undefined;
    _ = try srv.lb_factory.?.mint(&post);
    try std.testing.expectEqual(@as(u8, 5), lb.cid.firstOctetConfigId(post[0]));
}

test "MUST reject installLbConfig with mismatched cidLength [server rotation]" {
    // Same-length restriction: rotating to a config that mints
    // different-sized CIDs would break short-header routing
    // (`peekDcidForServer` peeks `local_cid_len` bytes after the
    // first byte). LB-4 minimum rejects mismatched lengths.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        .quic_lb = .{
            .config_id = 0,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xaa }),
            .nonce_len = 6, // cidLength = 8
        },
    });
    defer srv.deinit();

    // New config has cidLength = 12 (1 + 4 + 7); mismatch.
    try std.testing.expectError(quic_zig.Server.Error.InvalidConfig, srv.installLbConfig(.{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3, 4 }),
        .nonce_len = 7,
    }));
}

test "MUST push NEW_CONNECTION_ID to live slots on installLbConfig with stateless_reset_key set [server rotation]" {
    // With `stateless_reset_key` provided, `installLbConfig` doesn't
    // just swap the factory — it walks every live slot and queues a
    // NEW_CONNECTION_ID frame using the new factory's CID and the
    // configured key's HMAC-derived reset token. `retire_prior_to`
    // is set to the next-issued sequence so the peer drops every
    // pre-rotation CID on its next datagram.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    const stateless_key: quic_zig.conn.stateless_reset.Key = @splat(0x42);

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        .stateless_reset_key = stateless_key,
        .quic_lb = .{
            .config_id = 1,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xaa, 0xbb }),
            .nonce_len = 6, // cidLength = 9
        },
    });
    defer srv.deinit();

    // Open a slot via a healthy 1200-byte authenticated Initial.
    // PING-only payload — the AEAD passes and the server allocates a
    // slot without invoking the TLS state machine, which is plenty
    // for inspecting the post-rotation NEW_CONNECTION_ID queue.
    const dcid: [9]u8 = .{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90 };
    const scid: [4]u8 = .{ 0xa0, 0xb0, 0xc0, 0xd0 };
    try initial_fixture.feedInitial(&srv, &dcid, &scid, &.{0x01});

    const slots = srv.iterator();
    try std.testing.expect(slots.len > 0);
    const slot = slots[0];
    const pre_count = slot.conn.pending_frames.new_connection_ids.items.len;

    // Rotate to a new config. The factory swap commits and
    // `rotateLiveSlotCids` runs automatically — verifiable by the
    // queued frame count growing and the latest queued CID's first
    // octet carrying the new `config_id` (5).
    try srv.installLbConfig(.{
        .config_id = 5,
        .server_id = try lb.ServerId.fromSlice(&.{ 0xcc, 0xdd }),
        .nonce_len = 6,
    });

    const post_items = slot.conn.pending_frames.new_connection_ids.items;
    try std.testing.expect(post_items.len > pre_count);
    const last = post_items[post_items.len - 1];
    try std.testing.expectEqual(@as(u8, 5), lb.cid.firstOctetConfigId(last.connection_id.bytes[0]));
    // `retire_prior_to` should equal the new CID's sequence number
    // so the peer drops every prior CID on its next datagram.
    try std.testing.expectEqual(last.sequence_number, last.retire_prior_to);
}

test "NORMATIVE installLbConfig is lazy without stateless_reset_key [server rotation]" {
    // Without a key, the Server can't derive stateless-reset tokens
    // for new CIDs, so it leaves rotation to the embedder. The
    // factory swap still commits but the live slots' NEW_CONNECTION_ID
    // queues stay untouched.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
        // No stateless_reset_key — auto-push disabled.
        .quic_lb = .{
            .config_id = 1,
            .server_id = try lb.ServerId.fromSlice(&.{ 0xaa, 0xbb }),
            .nonce_len = 6,
        },
    });
    defer srv.deinit();

    const dcid: [9]u8 = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    const scid: [4]u8 = .{ 0xa1, 0xb1, 0xc1, 0xd1 };
    try initial_fixture.feedInitial(&srv, &dcid, &scid, &.{0x01});

    const slot = srv.iterator()[0];
    const pre_count = slot.conn.pending_frames.new_connection_ids.items.len;

    try srv.installLbConfig(.{
        .config_id = 5,
        .server_id = try lb.ServerId.fromSlice(&.{ 0xcc, 0xdd }),
        .nonce_len = 6,
    });

    // Auto-push didn't fire — queue length unchanged.
    try std.testing.expectEqual(pre_count, slot.conn.pending_frames.new_connection_ids.items.len);
}

test "MUST reject installLbConfig when Server was built without QUIC-LB [server rotation]" {
    // Rotation isn't a fresh-install path. If the server wasn't
    // configured with QUIC-LB at init, `installLbConfig` returns
    // InvalidConfig — embedders should re-init the server instead.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = handshake_fixture.test_cert_pem,
        .tls_key_pem = handshake_fixture.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = handshake_fixture.defaultParams(),
    });
    defer srv.deinit();

    try std.testing.expectError(quic_zig.Server.Error.InvalidConfig, srv.installLbConfig(.{
        .config_id = 0,
        .server_id = try lb.ServerId.fromSlice(&.{ 1, 2, 3 }),
        .nonce_len = 5,
    }));
}

// ---------------------------------------------------------------- §5.5.1 LB-side single-pass decode

test "NORMATIVE decode round-trips single-pass mints across every (sid, nonce) split [draft-ietf-quic-load-balancers-21 §5.5.1]" {
    // §5.5.1: "If server ID length and nonce length sum to exactly 16
    // octets, they form a ciphertext block. The load balancer
    // decrypts the block using the AES-ECB key and extracts the
    // server ID from the most significant bytes of the resulting
    // plaintext." Verify the round-trip property across every
    // permitted single-pass split (sid_len 1..15 with nonce_len =
    // 16 - sid_len, clamped to nonce ≥ 4).
    const key: [16]u8 = @splat(0x77);
    const sid_full: [15]u8 = .{
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const nonce_full: [15]u8 = @splat(0xbb);

    var sid_len: u8 = 1;
    while (sid_len <= 12) : (sid_len += 1) { // nonce_len = 16-sid_len in 4..15
        const nonce_len: u8 = 16 - sid_len;
        const cfg: lb.LbConfig = .{
            .config_id = 3,
            .server_id = try lb.ServerId.fromSlice(sid_full[0..sid_len]),
            .nonce_len = nonce_len,
            .key = key,
        };
        var f = try lb.Factory.init(cfg);
        defer f.deinit();

        var cid: [17]u8 = undefined;
        const n = try f.mintWithNonce(&cid, nonce_full[0..nonce_len]);
        const decoded = try lb.decode(cid[0..n], cfg);
        try std.testing.expectEqualSlices(u8, sid_full[0..sid_len], decoded.server_id.slice());
        try std.testing.expectEqualSlices(u8, nonce_full[0..nonce_len], decoded.nonceSlice());
    }
}

test "KAT §5.5.1 decode of Appendix B.2 vector #2 recovers the inputs byte-exact [draft-ietf-quic-load-balancers-21 §B.2]" {
    // The encode-side KAT (above, §5.4.1) is byte-exact; this is the
    // matching decode side: feed the on-wire CID into `lb.decode` and
    // recover the original `server_id` and `nonce`.
    const key: [16]u8 = .{
        0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
        0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
    };
    const sid_bytes: [8]u8 = .{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f };
    const nonce_bytes: [8]u8 = .{ 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5 };
    const on_wire: [17]u8 = .{
        0x50, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2,
        0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c, 0xc3,
    };
    const cfg: lb.LbConfig = .{
        .config_id = 2,
        .server_id = try lb.ServerId.fromSlice(&sid_bytes),
        .nonce_len = 8,
        .key = key,
    };
    const decoded = try lb.decode(&on_wire, cfg);
    try std.testing.expectEqual(@as(u8, 2), decoded.config_id);
    try std.testing.expectEqualSlices(u8, &sid_bytes, decoded.server_id.slice());
    try std.testing.expectEqualSlices(u8, &nonce_bytes, decoded.nonceSlice());
}

// ---------------------------------------------------------------- helpers

fn hexToBytes16(comptime hex: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn hexToBytes8(comptime hex: []const u8) [8]u8 {
    var out: [8]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn hexToBytes17(comptime hex: []const u8) [17]u8 {
    var out: [17]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
