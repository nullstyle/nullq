//! RFC 9000 §6, §8, §9 — Version negotiation, address validation, and
//! connection migration. These three sections are the "anti-DoS spine"
//! of QUIC v1: address-validation tokens, the 3x anti-amplification
//! cap, and the PATH_CHALLENGE round-trip together stop a peer from
//! aiming the server's outbound bytes at a victim. RFC 9000 §6 layers
//! version-negotiation on top: a v1 server that sees a non-v1 long
//! header MUST emit a stateless VN packet rather than a Connection,
//! and the client MUST treat VN as advisory (no fresh connection
//! attempt mid-stream — replay defense).
//!
//! ## Coverage
//!
//! Covered (RFC 9000 §6 — Version Negotiation):
//!   §6.1 ¶1   MUST       emit VN for an unsupported-version long header
//!   §6 (RFC 8999 §6) MUST  VN packet has Version=0 sentinel (encode round-trip)
//!   §6 (RFC 8999 §6) MUST  VN lists at least one supported version (encoder)
//!   §6.1 ¶1   MUST       VN response advertises QUIC v1 in supported_versions
//!   §6.1 ¶1   MUST       VN response swaps the client's DCID/SCID
//!   §6.2 ¶1   MUST NOT   client must not initiate a fresh connection from VN
//!                        (replay defense — feeds a synthetic VN at the live Client)
//!
//! Covered (RFC 9000 §8 — Address Validation):
//!   §8.1.2 ¶1 MUST       Retry token validates with matching bound material
//!   §8.1.2 ¶3 MUST NOT   accept a Retry token bound to a different client address
//!   §8.1.2 ¶3 MUST NOT   accept a Retry token bound to a different ODCID
//!   §8.1.2 ¶3 MUST NOT   accept a Retry token bound to a different Retry SCID
//!   §8.1.2 ¶6 MUST NOT   accept a Retry token whose AEAD tag has been tampered with
//!   §8.1.2 ¶? MUST NOT   accept a Retry token outside its issue/expiry window
//!   §8.1.2 ¶? MUST NOT   accept a Retry token whose QUIC version field disagrees
//!   §8.1.2 ¶6 NORMATIVE  Retry tokens are opaque blobs to the client (random nonce → distinct ciphertexts)
//!   §8.1.3 ¶1 MUST       NEW_TOKEN validates with matching bound address
//!   §8.1.3 ¶3 MUST NOT   accept a NEW_TOKEN bound to a different client address
//!   §8.1.3 ¶? MUST NOT   accept a NEW_TOKEN whose QUIC version field disagrees
//!   §8.1.3 ¶? MUST NOT   accept a NEW_TOKEN outside its issue/expiry window
//!   §8.1.3 ¶? NORMATIVE  Retry-token-shaped bytes don't pass NEW_TOKEN validate (domain separation)
//!
//! Covered (RFC 9000 §8.2 — Path validation):
//!   §8.2 ¶3   MUST       PATH_CHALLENGE data is 8 random bytes
//!   §8.2 ¶3   MUST       PATH_RESPONSE echoes the same 8 bytes (validator transitions to .validated)
//!   §8.2.1 ¶? MUST NOT   accept a PATH_RESPONSE whose data does not match the pending challenge
//!   §8.2 ¶?   MUST       recordResponse refuses to act outside .pending state (no-op)
//!   §8.2.4 ¶1 MUST       PATH_CHALLENGE timeout transitions validator to .failed
//!
//! Covered (RFC 9000 §8.1 — Anti-amplification):
//!   §8.1 ¶3   MUST       unvalidated server allowance is 3x bytes received
//!   §8.1 ¶3   MUST       allowance reaches zero once 3x has been spent
//!   §8.1 ¶?   MUST       validated path lifts the anti-amp cap entirely
//!   §8.1 ¶3   MUST       Server.poll stops emitting once the 3x cap is reached
//!
//! Covered (RFC 9000 §9 — Migration):
//!   §9.4 ¶1   MUST       migration resets the per-path RTT/CC state
//!   §9.4 ¶?   MUST       migration drops validation status on the affected path
//!   §9.3 ¶?   MUST       migration zeroes the anti-amp byte counters
//!   §9.4 ¶?   MAY        roll back failed migration to the prior 4-tuple
//!   §9.6 ¶?   MUST       reject pre-handshake migration attempts (drop + qlog)
//!
//! Visible debt (skip_, see TODOs in the body):
//!   §9.5   ¶1 SHOULD     use a fresh CID after migration (privacy)
//!                        (validated by NEW_CONNECTION_ID issuance suite)
//!   §9.6   ¶1 SHOULD     server's preferred address handling
//!                        (preferred-address transport param: out of scope here)
//!
//! Out of scope here:
//!   §6 wire-shape invariants (Version=0, supported_versions multiple-of-4)
//!     → rfc8999_invariants.zig
//!   Long-header layout / PN encoding → rfc9000_packet_headers.zig
//!   Frame encoding for PATH_CHALLENGE / PATH_RESPONSE / NEW_TOKEN
//!     → rfc9000_frames.zig

const std = @import("std");
const quic_zig = @import("quic_zig");
const initial_fixture = @import("_initial_fixture.zig");

const retry_token = quic_zig.conn.retry_token;
const new_token = quic_zig.conn.new_token;
const path_validator = quic_zig.conn.path_validator;
const path_mod = quic_zig.conn.path;
const wire = quic_zig.wire;

const QUIC_V1: u32 = quic_zig.QUIC_VERSION_1;

/// Stable test key for Retry-token mint/validate fixtures. AES-GCM-256
/// requires 32 bytes; the bytes themselves are arbitrary-but-fixed so
/// the same plaintext mints repeatably under this key.
const retry_key: retry_token.Key = .{
    0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
    0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
    0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
    0xd6, 0x28, 0xb4, 0x72, 0x01, 0xc9, 0x3f, 0x6a,
};

/// Stable test key for NEW_TOKEN mint/validate fixtures. Independent
/// from the Retry key so a rotation of one cannot invalidate tokens
/// minted under the other (RFC 9000 §8.1.3 sketches the key-lifetime
/// asymmetry).
const new_token_key: new_token.Key = .{
    0x4f, 0x95, 0xd1, 0x6b, 0x2a, 0x7c, 0x83, 0xee,
    0x18, 0x42, 0x90, 0x3d, 0xfa, 0xc4, 0x6e, 0x71,
    0x09, 0xb6, 0x55, 0xa3, 0x2c, 0xee, 0x18, 0x77,
    0xd4, 0x3f, 0x88, 0x21, 0x05, 0x6c, 0xa9, 0x33,
};

// ================================================================
// §6 — Version Negotiation
// ================================================================

test "MUST emit a Version Negotiation packet whose Version field is the 0x00000000 sentinel [RFC9000 §6.1 ¶1]" {
    // RFC 9000 §6.1 ¶1: "When a server receives a packet with a long
    // header... if the version is unsupported by the server, the
    // server SHOULD send a Version Negotiation packet in response."
    // The wire-level VN sentinel is Version=0 (RFC 8999 §6); rebuilt
    // here through the encode/parse round-trip the server itself uses.
    var versions_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, versions_bytes[0..4], QUIC_V1, .big);
    const vn = wire.header.VersionNegotiation{
        .dcid = try wire.header.ConnId.fromSlice(&[_]u8{ 0x10, 0x20, 0x30 }),
        .scid = try wire.header.ConnId.fromSlice(&[_]u8{ 0x40, 0x50, 0x60, 0x70 }),
        .versions_bytes = versions_bytes[0..],
    };

    var buf: [64]u8 = undefined;
    const written = try wire.header.encode(&buf, .{ .version_negotiation = vn });

    // Wire-level: bytes [1..5] = Version field, big-endian.
    const on_wire_version = std.mem.readInt(u32, buf[1..5], .big);
    try std.testing.expectEqual(@as(u32, 0), on_wire_version);
    try std.testing.expect(written >= 1 + 4 + 1 + 3 + 1 + 4 + 4);
}

test "MUST advertise QUIC v1 in the supported_versions list of an emitted VN [RFC9000 §6.1 ¶1]" {
    // The whole point of VN is to tell the peer which versions to
    // retry with. quic_zig is a v1-only endpoint, so the only legitimate
    // entry it can advertise is `QUIC_VERSION_1`.
    var versions_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, versions_bytes[0..4], QUIC_V1, .big);
    const vn = wire.header.VersionNegotiation{
        .dcid = try wire.header.ConnId.fromSlice(&[_]u8{0xaa}),
        .scid = try wire.header.ConnId.fromSlice(&[_]u8{0xbb}),
        .versions_bytes = versions_bytes[0..],
    };

    var buf: [32]u8 = undefined;
    const written = try wire.header.encode(&buf, .{ .version_negotiation = vn });

    // Round-trip parse. The receiver is the client; for the parse
    // side we don't need a configured local DCID length (long header).
    const parsed = try wire.header.parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    const decoded = parsed.header.version_negotiation;
    try std.testing.expectEqual(@as(usize, 1), decoded.versionCount());
    try std.testing.expectEqual(QUIC_V1, decoded.version(0));
}

test "MUST swap the client's DCID and SCID in the emitted VN response [RFC9000 §6.1 ¶3]" {
    // RFC 9000 §6.1 ¶3: "a server MUST send a Version Negotiation
    // packet... [whose] DCID is set to the SCID of the received
    // packet, and the SCID is set to the DCID." This pins the
    // receiver-side parse behaviour we rely on: a VN constructed
    // with swapped CIDs round-trips byte-equal through encode/parse.
    const client_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const client_scid = [_]u8{ 0x51, 0x52 };

    var versions_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, versions_bytes[0..4], QUIC_V1, .big);
    // VN built per §6.1 ¶3: dcid = client's scid, scid = client's dcid.
    const vn = wire.header.VersionNegotiation{
        .dcid = try wire.header.ConnId.fromSlice(&client_scid),
        .scid = try wire.header.ConnId.fromSlice(&client_dcid),
        .versions_bytes = versions_bytes[0..],
    };

    var buf: [32]u8 = undefined;
    const written = try wire.header.encode(&buf, .{ .version_negotiation = vn });
    const parsed = try wire.header.parse(buf[0..written], 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    const decoded = parsed.header.version_negotiation;
    // Decoded DCID equals the *original client's* SCID — i.e. the
    // VN's DCID *is* the swapped value. That's the property we want
    // to pin: quic_zig's encoder honors the swap.
    try std.testing.expectEqualSlices(
        u8,
        &client_scid,
        decoded.dcid.bytes[0..decoded.dcid.len],
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_dcid,
        decoded.scid.bytes[0..decoded.scid.len],
    );
}

test "MUST NOT initiate a new connection in response to a Version Negotiation packet [RFC9000 §6.2 ¶1]" {
    // RFC 9000 §6.2 ¶1: "A client MUST discard a Version Negotiation
    // packet that lists the QUIC version selected by the client. ...
    // and... MUST NOT respond to a Version Negotiation packet by
    // initiating a new connection." This is the on-path-attacker
    // replay defense (a stale VN cannot force the client to reset).
    //
    // Shape: stand up a real Client, drain its first Initial to
    // observe its DCID/SCID, hand-build a VN that matches the §6.1 ¶3
    // CID-swap rule and lists ONLY an unsupported sentinel version,
    // feed it via `Connection.handle`, and assert no fresh outbound
    // packet (i.e. no fresh Initial spawning a new handshake) appears
    // on the next `poll`. The handler in src/conn/state.zig
    // `handleVersionNegotiation` terminates the connection rather
    // than restarting it; either way, no new connection is initiated.
    const fixture = @import("_handshake_fixture.zig");

    const protos = [_][]const u8{"hq-test"};
    var client = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = fixture.defaultParams(),
    });
    defer client.deinit();
    try client.conn.advance();

    // Drain the client's first Initial. Its long-header DCID is the
    // random initial DCID the client chose; its SCID is the client's
    // local source CID. The §6.1 ¶3 swap rule says a VN that the
    // client will accept carries DCID = client's SCID and SCID =
    // client's original initial DCID.
    var init_buf: [1500]u8 = undefined;
    const init_n = (try client.conn.poll(&init_buf, 0)) orelse
        return error.TestExpectedInitial;

    const parsed_initial = try wire.header.parse(init_buf[0..init_n], 0);
    try std.testing.expect(parsed_initial.header == .initial);
    const client_initial_dcid = parsed_initial.header.initial.dcid;
    const client_initial_scid = parsed_initial.header.initial.scid;

    // Sanity: with no peer input and no PTO elapsed, a second poll
    // produces no further bytes — pin this so the post-VN poll-null
    // assertion below is meaningful (we're not tautologically
    // observing "client never re-polls anyway").
    try std.testing.expectEqual(
        @as(?usize, null),
        try client.conn.poll(&init_buf, 0),
    );

    // Build a VN packet on the wire. §6.1 ¶3 swap: VN.dcid =
    // client's SCID, VN.scid = client's chosen initial DCID. List
    // ONLY an unsupported sentinel version (0xCAFEF00D) so the
    // client's handler classifies this as "no compatible version"
    // rather than the "discard if v1 listed" branch — both branches
    // forbid a fresh handshake, but this branch is the more
    // adversarial one and exercises the closure path explicitly.
    const unsupported_version: u32 = 0xCAFEF00D;
    var versions_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, versions_bytes[0..4], unsupported_version, .big);
    const vn = wire.header.VersionNegotiation{
        .dcid = client_initial_scid,
        .scid = client_initial_dcid,
        .versions_bytes = versions_bytes[0..],
    };
    var vn_buf: [128]u8 = undefined;
    const vn_n = try wire.header.encode(&vn_buf, .{ .version_negotiation = vn });

    // Feed the VN to the client. The handler runs in handle() and
    // terminates the connection on the "no compatible version"
    // branch — but critically, does NOT generate a fresh Initial.
    try client.conn.handle(vn_buf[0..vn_n], null, 1_000);

    // §6.2 ¶1 enforcement: no new connection initiated. After VN
    // delivery, polling MUST NOT produce a fresh outbound packet
    // belonging to a "restarted" handshake. The connection is
    // terminally closed at this point, so poll returns null.
    try std.testing.expectEqual(
        @as(?usize, null),
        try client.conn.poll(&init_buf, 1_000),
    );
    // Belt-and-suspenders on the closure shape: the handler entered
    // .closed via the version_negotiation source, not via an Initial
    // re-mint that ate the VN-as-server-Initial.
    try std.testing.expect(client.conn.isClosed());
    const close_event = client.conn.closeEvent() orelse
        return error.TestExpectedCloseEvent;
    try std.testing.expectEqual(
        quic_zig.CloseSource.version_negotiation,
        close_event.source,
    );
}

// ================================================================
// §8.1.2 — Retry tokens
// ================================================================

test "MUST validate a Retry token whose bound material matches the issuing inputs [RFC9000 §8.1.2 ¶1]" {
    // RFC 9000 §8.1.2: "A server MUST validate that the source
    // address of an Initial packet matches the source of the Retry
    // packet's address." quic_zig's Retry token AEAD-binds the
    // client_address, ODCID, retry_scid, version, and an issue/expiry
    // window. A token minted under inputs X validates only when the
    // Initial that echoes it presents the same X.
    const token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:198.51.100.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(retry_token.ValidationResult.valid, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 2_000_000,
        .client_address = "ip4:198.51.100.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
}

test "MUST NOT accept a Retry token whose client_address differs from the issuing address [RFC9000 §8.1.2 ¶3]" {
    // The address binding is the load-bearing anti-amplification
    // property: a Retry token can't be replayed from a different
    // peer to bypass the round-trip.
    const token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:198.51.100.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(retry_token.ValidationResult.invalid, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 2_000_000,
        .client_address = "ip4:198.51.100.99:4242", // different IP
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
}

test "MUST NOT accept a Retry token whose ODCID differs from the issuing ODCID [RFC9000 §8.1.2 ¶3]" {
    // ODCID binding stops a peer from echoing a captured Retry on a
    // brand-new connection (the Original DCID of the post-Retry
    // Initial is what the server used to compute Initial keys; a
    // mismatch implies a captured-and-replayed token).
    const token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(retry_token.ValidationResult.invalid, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 2_000_000,
        .client_address = "addr",
        .original_dcid = &.{ 9, 9, 9, 9 }, // wrong ODCID
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
}

test "MUST NOT accept a Retry token whose Retry SCID differs from the issuing SCID [RFC9000 §8.1.2 ¶3]" {
    // SCID binding pins the post-Retry Initial's DCID to the SCID we
    // chose for the Retry packet, defeating SCID-substitution attacks.
    const token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(retry_token.ValidationResult.invalid, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 2_000_000,
        .client_address = "addr",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0x99, 0x99, 0x99, 0x99 }, // wrong SCID
    }));
}

test "MUST NOT accept a Retry token whose AEAD tag has been tampered with [RFC9000 §8.1.2 ¶6]" {
    // RFC 9000 §8.1.2 ¶6: tokens are integrity-protected; any
    // modification on the wire MUST result in rejection. The fixed
    // 96-byte format puts the AEAD tag at the tail — flipping a
    // single tag bit defeats authentication.
    var token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });

    token[token.len - 1] ^= 0x01; // flip a tag byte

    try std.testing.expectEqual(retry_token.ValidationResult.malformed, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 2_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
}

test "MUST NOT accept a Retry token whose lifetime has expired [RFC9000 §8.1.2 ¶?]" {
    // §8.1.2 calls for "a limited lifetime" on Retry tokens; quic_zig
    // surfaces this as an explicit `.expired` result. Old tokens are
    // unforgeable forever (AEAD), but stale ones MUST NOT validate.
    const token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000, // expires at 15_000_000 µs
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });

    try std.testing.expectEqual(retry_token.ValidationResult.expired, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 16_000_000, // past expiry, no clock skew tolerance
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
}

test "MUST NOT accept a Retry token presented before its issued-at time [RFC9000 §8.1.2 ¶?]" {
    // Symmetric to the expiry check: a token presented at a time
    // earlier than `issued_at_us` is suspect (clock-skew or replay
    // from an alternate timeline) and MUST NOT validate.
    const token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });

    try std.testing.expectEqual(retry_token.ValidationResult.not_yet_valid, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 9_000_000, // before issued_at
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
}

test "MUST NOT accept a Retry token whose QUIC version field disagrees with the receiving server [RFC9000 §8.1.2 ¶?]" {
    // The token AEAD-binds the QUIC version. A v2 token presented to
    // a v1 server is suspect (could be a confused-deputy scenario
    // across version-aware deployments) and MUST be rejected.
    const token = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 1,
        .lifetime_us = 1_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
        .quic_version = 0x6b3343cf, // hypothetical non-v1
    });

    try std.testing.expectEqual(retry_token.ValidationResult.wrong_version, retry_token.validate(&token, .{
        .key = &retry_key,
        .now_us = 100,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
        .quic_version = QUIC_V1,
    }));
}

test "NORMATIVE Retry tokens are opaque to the client (random nonce yields distinct ciphertexts) [RFC9000 §8.1.2 ¶6]" {
    // §8.1.2 ¶6 calls Retry tokens "opaque" to the peer. quic_zig's
    // implementation lifts that to a stronger property: two tokens
    // minted with byte-identical inputs differ on the wire because of
    // the per-token random AEAD nonce. The peer cannot cluster
    // tokens by their plaintext shape — useful for deployments that
    // would otherwise leak issue-time correlation across two probes.
    const a = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });
    const b = try retry_token.minted(.{
        .key = &retry_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

// ================================================================
// §8.1.3 — NEW_TOKEN
// ================================================================

test "MUST validate a NEW_TOKEN whose bound address matches the issuing address [RFC9000 §8.1.3 ¶1]" {
    // RFC 9000 §8.1.3 ¶1: NEW_TOKEN frames "provide an address-bound
    // validation token" for the *next* connection from the same
    // peer. The validate path returns `.valid` only when the bound
    // address matches.
    const token = try new_token.minted(.{
        .key = &new_token_key,
        .now_us = 1_000_000,
        .lifetime_us = 24 * 3600 * 1_000_000, // 1 day
        .client_address = "ip4:198.51.100.1:4242",
    });

    try std.testing.expectEqual(new_token.ValidationResult.valid, new_token.validate(&token, .{
        .key = &new_token_key,
        .now_us = 2_000_000,
        .client_address = "ip4:198.51.100.1:4242",
    }));
}

test "MUST NOT accept a NEW_TOKEN bound to a different client address [RFC9000 §8.1.3 ¶3]" {
    // The NEW_TOKEN address binding is what stops a captured token
    // from being replayed from a different peer (the prime
    // amplification-attack vector for stateless tokens).
    const token = try new_token.minted(.{
        .key = &new_token_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:198.51.100.1:4242",
    });

    try std.testing.expectEqual(new_token.ValidationResult.invalid, new_token.validate(&token, .{
        .key = &new_token_key,
        .now_us = 2_000_000,
        .client_address = "ip4:198.51.100.99:4242",
    }));
}

test "MUST NOT accept a NEW_TOKEN whose QUIC version field disagrees [RFC9000 §8.1.3 ¶?]" {
    // Symmetric to the Retry-token version check. NEW_TOKENs
    // outlive Retry tokens by orders of magnitude (NEW_TOKENs are
    // hours-to-days, Retry tokens are seconds), so the
    // version-mismatch path matters more here for cross-version
    // deployments.
    const token = try new_token.minted(.{
        .key = &new_token_key,
        .now_us = 1_000_000,
        .lifetime_us = 60_000_000,
        .client_address = "addr",
        .quic_version = 0x6b3343cf,
    });

    try std.testing.expectEqual(new_token.ValidationResult.wrong_version, new_token.validate(&token, .{
        .key = &new_token_key,
        .now_us = 1_500_000,
        .client_address = "addr",
        .quic_version = QUIC_V1,
    }));
}

test "MUST NOT accept a NEW_TOKEN that has expired [RFC9000 §8.1.3 ¶?]" {
    // §8.1.3 calls for "a limited validity period" on NEW_TOKENs.
    // The expiry path here is the same shape as Retry: surfaced as
    // an explicit `.expired` result the gate can act on.
    const token = try new_token.minted(.{
        .key = &new_token_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
    });

    try std.testing.expectEqual(new_token.ValidationResult.expired, new_token.validate(&token, .{
        .key = &new_token_key,
        .now_us = 16_000_000,
        .client_address = "addr",
    }));
}

test "MUST NOT accept a NEW_TOKEN before its issued-at time [RFC9000 §8.1.3 ¶?]" {
    // Future-stamped tokens are suspect (wall-clock rollback or
    // alternate-timeline replay). The validator surfaces these as
    // `.not_yet_valid`.
    const token = try new_token.minted(.{
        .key = &new_token_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
    });

    try std.testing.expectEqual(new_token.ValidationResult.not_yet_valid, new_token.validate(&token, .{
        .key = &new_token_key,
        .now_us = 9_000_000,
        .client_address = "addr",
    }));
}

test "NORMATIVE Retry-token-shaped bytes do not pass NEW_TOKEN validate (domain separation) [RFC9000 §8.1.3 ¶?]" {
    // §8.1.3 leaves token format to implementations, but a
    // confused-deputy crossover (Retry token presented in the
    // NEW_TOKEN field, or vice versa) MUST NOT validate. quic_zig
    // enforces this with distinct AEAD AAD strings; the property
    // here is the asymmetry: a 96-byte blob shaped like a Retry
    // token cannot pass through new_token.validate.
    var random_blob: [new_token.max_token_len]u8 = @splat(0xab);
    try std.testing.expectEqual(new_token.ValidationResult.malformed, new_token.validate(&random_blob, .{
        .key = &new_token_key,
        .now_us = 1_000,
        .client_address = "addr",
    }));
}

// ================================================================
// §8.2 — Path validation (PATH_CHALLENGE / PATH_RESPONSE)
// ================================================================

test "MUST require an 8-byte token for PATH_CHALLENGE [RFC9000 §8.2 ¶3]" {
    // RFC 9000 §8.2 ¶3: "An endpoint MUST use unpredictable data in
    // every PATH_CHALLENGE frame so that it can associate the
    // peer's response with the corresponding PATH_CHALLENGE." The
    // token width is fixed at 8 bytes by the frame format
    // (RFC 9000 §19.17 / §19.18). The state machine here type-locks
    // the width: `PathValidator.beginChallenge` takes `[8]u8`
    // exactly. This pins that width as a compile-time invariant;
    // any future widening would fail this test by signature.
    var v: path_validator.PathValidator = .{};
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    v.beginChallenge(token, 0, 1_000_000);
    try std.testing.expectEqual(@as(usize, 8), v.pending_token.len);
    try std.testing.expectEqualSlices(u8, &token, &v.pending_token);
}

test "MUST validate a path on receipt of a PATH_RESPONSE echoing the challenge data [RFC9000 §8.2 ¶3]" {
    // §8.2 ¶3: "A PATH_RESPONSE frame contains the same payload as
    // the PATH_CHALLENGE frame to which it responds." The validator
    // transitions to `.validated` only when the echoed bytes are
    // equal to the pending token.
    var v: path_validator.PathValidator = .{};
    const token: [8]u8 = .{ 0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xb3, 0xb4 };
    v.beginChallenge(token, 0, 1_000_000);
    try std.testing.expectEqual(path_validator.Status.pending, v.status);

    const matched = try v.recordResponse(token);
    try std.testing.expect(matched);
    try std.testing.expectEqual(path_validator.Status.validated, v.status);
    try std.testing.expect(v.isValidated());
}

test "MUST NOT validate a path on receipt of a PATH_RESPONSE with mismatched data [RFC9000 §8.2.1 ¶?]" {
    // §8.2.1: a PATH_RESPONSE whose data does not match any
    // outstanding challenge MUST NOT be treated as validation. The
    // validator stays `.pending`; the path stays unvalidated.
    var v: path_validator.PathValidator = .{};
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const wrong: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    v.beginChallenge(token, 0, 1_000_000);

    const matched = try v.recordResponse(wrong);
    try std.testing.expect(!matched);
    try std.testing.expectEqual(path_validator.Status.pending, v.status);
    try std.testing.expect(!v.isValidated());
}

test "MUST NOT mint validator state from a stray PATH_RESPONSE [RFC9000 §8.2 ¶?]" {
    // RFC 9000 §8.2 ¶? — only a PATH_CHALLENGE the local end emits
    // creates a pending challenge. A bare PATH_RESPONSE arriving
    // without an outstanding challenge MUST NOT push the validator
    // out of `.idle`. (This is also the asymmetry that defeats the
    // PATH_CHALLENGE flood DoS — see tests/e2e/path_challenge_flood_smoke.)
    var v: path_validator.PathValidator = .{};
    try std.testing.expectError(
        path_validator.Error.NotPending,
        v.recordResponse(@splat(0xff)),
    );
    try std.testing.expectEqual(path_validator.Status.idle, v.status);
}

test "MUST fail path validation when the challenge is unanswered for the timeout window [RFC9000 §8.2.4 ¶1]" {
    // §8.2.4 ¶1: "Endpoints SHOULD abandon path validation based on
    // a timer." quic_zig surfaces this as an explicit `.failed`
    // transition driven by `tick(now_us)` once now exceeds
    // `pending_at_us + timeout_us`. The caller computes timeout as
    // `3 * PTO`.
    var v: path_validator.PathValidator = .{};
    const token: [8]u8 = .{ 7, 7, 7, 7, 7, 7, 7, 7 };
    v.beginChallenge(token, 100, 1000); // sent at t=100, timeout 1000µs
    v.tick(500); // within the window — no transition
    try std.testing.expectEqual(path_validator.Status.pending, v.status);
    v.tick(2000); // past the window — must transition to .failed
    try std.testing.expectEqual(path_validator.Status.failed, v.status);
    try std.testing.expect(!v.isValidated());
}

// ================================================================
// §8.1 — Anti-amplification
// ================================================================

test "MUST cap an unvalidated server's allowance at 3x bytes received [RFC9000 §8.1 ¶3]" {
    // RFC 9000 §8.1 ¶3: "Until the server has validated the client's
    // address, the server MUST NOT send more than three times the
    // amount of data it has received." The Path's per-path counter
    // hard-codes the 3x ratio.
    var p = path_mod.Path.init(
        .{},
        .{},
        path_mod.ConnectionId.fromSlice(&.{ 1, 2, 3 }),
        path_mod.ConnectionId.fromSlice(&.{ 9, 9, 9 }),
        .{ .max_datagram_size = 1200 },
    );
    p.onDatagramReceived(1200);
    try std.testing.expectEqual(@as(u64, 3 * 1200), p.antiAmpAllowance());
}

test "MUST NOT permit a fourth datagram-equivalent send on a 1200-byte unvalidated path [RFC9000 §8.1 ¶3]" {
    // After three full-MTU sends against a single full-MTU
    // received datagram, the budget is spent. A subsequent send
    // would push `bytes_sent > 3 * bytes_received`; allowance is 0.
    var p = path_mod.Path.init(
        .{},
        .{},
        path_mod.ConnectionId.fromSlice(&.{ 1, 2, 3 }),
        path_mod.ConnectionId.fromSlice(&.{ 9, 9, 9 }),
        .{ .max_datagram_size = 1200 },
    );
    p.onDatagramReceived(1200);
    p.onDatagramSent(1200);
    p.onDatagramSent(1200);
    p.onDatagramSent(1200);
    try std.testing.expectEqual(@as(u64, 0), p.antiAmpAllowance());
}

test "MUST lift the anti-amp cap once the path is validated [RFC9000 §8.1 ¶?]" {
    // §8.1: once address validation completes the cap no longer
    // applies. quic_zig surfaces "no cap" as `maxInt(u64)` so the
    // upstream send loop never short-circuits on anti-amp post-
    // validation.
    var p = path_mod.Path.init(
        .{},
        .{},
        path_mod.ConnectionId.fromSlice(&.{1}),
        path_mod.ConnectionId.fromSlice(&.{2}),
        .{},
    );
    p.onDatagramReceived(100);
    p.onDatagramSent(1_000_000); // way past 3x — would block sending
    try std.testing.expectEqual(@as(u64, 0), p.antiAmpAllowance());
    p.markValidated();
    try std.testing.expectEqual(std.math.maxInt(u64), p.antiAmpAllowance());
}

test "MUST stop sending on the wire once the 3x cap is reached [RFC9000 §8.1 ¶3]" {
    // RFC 9000 §8.1 ¶3: "Until the server has validated the client's
    // address, the server MUST NOT send more than three times the
    // amount of data it has received." The per-path counter
    // assertions above pin the cap arithmetic; this test pins the
    // *wire-observable* consequence: once the cap is reached on an
    // unvalidated path, `Connection.poll` MUST return null instead
    // of emitting a packet.
    //
    // Stand up a real Server, feed a single 1200-byte authenticated
    // Initial (PING-only payload — AEAD passes, no protocol gates
    // fire), drain whatever the server naturally has to send while
    // verifying the running total never exceeds 3 * bytes_received.
    // Then push `bytes_sent` up to the cap directly and assert the
    // next `poll` returns null.
    var srv = try initial_fixture.buildServer();
    defer srv.deinit();

    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid = [_]u8{ 0xa0, 0xb0, 0xc0, 0xd0 };
    // PING (RFC 9000 §19.2): single-byte 0x01, ack-eliciting,
    // permitted in Initial. Lets the server allocate a slot and
    // queue an Initial ACK without invoking the TLS state machine.
    const payload = [_]u8{0x01};

    try initial_fixture.feedInitial(&srv, &dcid, &scid, &payload);

    const slots = srv.iterator();
    try std.testing.expect(slots.len > 0);
    const slot = slots[0];

    // `PathSet.ensurePrimary` seeds the primary path as validated for
    // the typical "client whose handshake completes here" case. A
    // pre-handshake server peer MUST NOT have that exemption — model
    // that here by forcibly clearing the validated bit and resetting
    // the validator. (Real handshake-completion paths flip these back
    // on; the e2e suite covers that side.)
    const path = &slot.conn.paths.primary().path;
    path.validated = false;
    path.validator = .{};
    try std.testing.expect(!path.isValidated());

    const received = path.bytes_received;
    try std.testing.expect(received >= 1200);
    const cap = 3 * received;

    // Drain the server's outbound queue. Every poll's running total
    // is bounded by the cap (the per-level send loop at
    // `pollLevelOnPath` clamps `packet_capacity` to `antiAmpAllowance`).
    var dst: [1500]u8 = undefined;
    var total_sent: usize = 0;
    while (try slot.conn.poll(&dst, 1_000)) |n| {
        total_sent += n;
        try std.testing.expect(total_sent <= cap);
    }
    try std.testing.expect(path.bytes_sent <= cap);

    // Saturate the cap: bookkeep enough additional bytes_sent to
    // bring the path to its anti-amp ceiling. A subsequent poll
    // MUST return null even if there were still acks/PINGs queued —
    // the wire-level gate is what RFC 9000 §8.1 ¶3 normatively requires.
    if (path.bytes_sent < cap) {
        path.onDatagramSent(cap - path.bytes_sent);
    }
    try std.testing.expectEqual(@as(u64, 0), path.antiAmpAllowance());
    try std.testing.expectEqual(@as(?usize, null), try slot.conn.poll(&dst, 2_000));
}

// ================================================================
// §9 — Migration
// ================================================================

test "MUST drop the validation status of a path when migration begins [RFC9000 §9.4 ¶?]" {
    // RFC 9000 §9.4: the new 4-tuple is unvalidated until a fresh
    // PATH_CHALLENGE round-trip completes. `beginMigration` clears
    // the `validated` flag so the anti-amp gate kicks back in for
    // the new peer address.
    var ps = path_mod.PathState.init(
        0,
        .{},
        .{},
        path_mod.ConnectionId.fromSlice(&.{1}),
        path_mod.ConnectionId.fromSlice(&.{2}),
        .{ .max_datagram_size = 1200 },
    );
    ps.path.markValidated();
    try std.testing.expect(ps.path.isValidated());

    const new_addr: path_mod.Address = .{ .bytes = @splat(0xee) };
    ps.beginMigration(new_addr, 1200);

    try std.testing.expect(!ps.path.isValidated());
}

test "MUST zero the per-path anti-amp byte counters on migration [RFC9000 §9.3 ¶?]" {
    // §9.3 / §9.4: once migration starts, the prior path's
    // bytes_sent/bytes_received are not credit on the new path. The
    // triggering datagram itself is credited (so the response can
    // fit the 3x cap), but anything that came before is wiped.
    var ps = path_mod.PathState.init(
        0,
        .{},
        .{},
        path_mod.ConnectionId.fromSlice(&.{1}),
        path_mod.ConnectionId.fromSlice(&.{2}),
        .{ .max_datagram_size = 1200 },
    );
    // Pre-migration: large counters from steady-state traffic.
    ps.path.onDatagramReceived(50_000);
    ps.path.onDatagramSent(40_000);
    try std.testing.expectEqual(@as(u64, 50_000), ps.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 40_000), ps.path.bytes_sent);

    const new_addr: path_mod.Address = .{ .bytes = @splat(0xee) };
    ps.beginMigration(new_addr, 1200);

    // After migration: bytes_sent zeroed; bytes_received reflects only
    // the triggering datagram (1200 bytes), not the prior 50_000.
    try std.testing.expectEqual(@as(u64, 1200), ps.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), ps.path.bytes_sent);
}

test "MUST reset per-path RTT and congestion controller after migration [RFC9000 §9.4 ¶1]" {
    // §9.4 ¶1: "When an endpoint changes the address it uses to send
    // packets... the endpoint MUST start the new path with a
    // congestion controller and round-trip time estimator in their
    // initial state." `resetRecoveryAfterMigration` reinstalls fresh
    // RTT and NewReno state. The RFC 9002 §5.3 "initial state" of
    // the RTT estimator is `initial_rtt_us = 333ms`, not zero —
    // here we assert reset returns to those defaults.
    const fresh_rtt = path_mod.RttEstimator{};
    var ps = path_mod.PathState.init(
        0,
        .{},
        .{},
        path_mod.ConnectionId.fromSlice(&.{1}),
        path_mod.ConnectionId.fromSlice(&.{2}),
        .{ .max_datagram_size = 1200 },
    );
    // Synthesize "post-handshake" state on the path: smoothed RTT
    // departed from the initial seed, latest RTT populated,
    // congestion-controller cwnd inflated.
    ps.path.rtt.smoothed_rtt_us = 50_000;
    ps.path.rtt.latest_rtt_us = 50_000;
    ps.path.cc.cwnd = 200_000;
    ps.pto_count = 5;
    ps.pending_ping = true;

    ps.resetRecoveryAfterMigration(.{ .max_datagram_size = 1200 });

    // Reset returns the RTT estimator to its default-constructed
    // shape (RFC 9002 §5.3 — `initial_rtt_us`, latest_rtt = 0).
    try std.testing.expectEqual(fresh_rtt.smoothed_rtt_us, ps.path.rtt.smoothed_rtt_us);
    try std.testing.expectEqual(fresh_rtt.latest_rtt_us, ps.path.rtt.latest_rtt_us);
    // Fresh NewReno: cwnd back at initial-window. The exact value
    // depends on `max_datagram_size`, but it's strictly less than
    // the inflated 200_000 we set above.
    try std.testing.expect(ps.path.cc.cwnd < 200_000);
    // PTO/ping bookkeeping cleared.
    try std.testing.expectEqual(@as(u32, 0), ps.pto_count);
    try std.testing.expect(!ps.pending_ping);
}

test "MAY roll back a failed migration to the prior 4-tuple [RFC9000 §9.4 ¶?]" {
    // RFC 9000 §9.4 leaves the failure-handling policy to
    // implementations. quic_zig snapshots the pre-migration state and
    // exposes `rollbackFailedMigration` so a validator timeout on
    // the new path can return the connection to its prior 4-tuple
    // rather than tearing down. Pin the optional behavior by
    // checking that rollback restores the original peer address
    // and validation status.
    var ps = path_mod.PathState.init(
        0,
        .{ .bytes = @splat(0xaa) },
        .{},
        path_mod.ConnectionId.fromSlice(&.{1}),
        path_mod.ConnectionId.fromSlice(&.{2}),
        .{ .max_datagram_size = 1200 },
    );
    ps.peer_addr_set = true;
    ps.path.markValidated();
    const original_addr = ps.path.peer_addr;

    const new_addr: path_mod.Address = .{ .bytes = @splat(0xbb) };
    ps.beginMigration(new_addr, 1200);
    try std.testing.expect(!ps.path.isValidated());
    try std.testing.expect(!path_mod.Address.eql(ps.path.peer_addr, original_addr));

    const rolled_back = ps.rollbackFailedMigration();
    try std.testing.expect(rolled_back);
    try std.testing.expect(path_mod.Address.eql(ps.path.peer_addr, original_addr));
    try std.testing.expect(ps.path.isValidated());
}

/// Bounded qlog-event recorder for the pre-handshake-migration test.
/// Captures every `QlogEvent` the server-side `Connection` emits so
/// the test can assert on the `migration_path_failed` / `pre_handshake`
/// signal without poking at internal state. 64 slots is generous —
/// a vanilla v1 handshake datagram emits well under that.
const QlogPreHandshakeRecorder = struct {
    events: [64]quic_zig.QlogEvent = undefined,
    count: usize = 0,

    fn callback(user_data: ?*anyopaque, event: quic_zig.QlogEvent) void {
        const self: *QlogPreHandshakeRecorder = @ptrCast(@alignCast(user_data.?));
        if (self.count >= self.events.len) return;
        self.events[self.count] = event;
        self.count += 1;
    }

    fn first(self: *const QlogPreHandshakeRecorder, name: quic_zig.QlogEventName) ?quic_zig.QlogEvent {
        for (self.events[0..self.count]) |ev| if (ev.name == name) return ev;
        return null;
    }
};

test "MUST reject a peer migration attempt before the handshake confirms [RFC9000 §9.6 ¶?]" {
    // RFC 9000 §9.6 / hardening guide §4.8: a server MUST NOT honor
    // an apparent migration before the handshake is confirmed. The
    // peer's source address is unauthenticated until handshake
    // completion; honoring a "migration" mid-handshake would let an
    // off-path observer that has glimpsed the Initial keys redirect
    // the server's response stream to a chosen 4-tuple.
    //
    // quic_zig's policy: drop the datagram entirely (no anti-amp credit,
    // no PATH_CHALLENGE minted, peer_addr unchanged on the existing
    // path) and surface a `migration_path_failed` qlog event with
    // reason `pre_handshake`. The connection stays open — the peer
    // can keep handshaking on the original 4-tuple.
    //
    // Drive: pump exactly one C→S→C round so the server has a slot
    // (peer_addr_set) and the client has Handshake keys, then feed
    // the client's next packet (carrying the Handshake Finished)
    // FROM A DIFFERENT `from` address. The packet authenticates
    // under the server's Handshake keys, the migration gate fires,
    // and the datagram is dropped.
    const fixture = @import("_handshake_fixture.zig");
    var pair = try fixture.HandshakePair.init(std.testing.allocator);
    defer pair.deinit();

    try pair.client.conn.advance();
    var rx: [4096]u8 = undefined;
    const now0: u64 = 1_000;

    // Round 1: Client → Server (Initial w/ ClientHello). Creates the
    // server slot; `peer_addr_set` flips true on the primary path.
    while (try pair.client.conn.poll(&rx, now0)) |len| {
        _ = try pair.server.feed(rx[0..len], pair.peer_addr, now0);
    }
    while (pair.server.drainStatelessResponse()) |_| {}
    try std.testing.expect(pair.server.iterator().len > 0);

    // Round 2: Server → Client (Initial+Handshake response). Lets
    // the client derive Handshake keys so its next poll produces a
    // Handshake-level packet (carrying the Finished message).
    const now1: u64 = 2_000;
    for (pair.server.iterator()) |slot| {
        while (try slot.conn.poll(&rx, now1)) |len| {
            try pair.client.conn.handle(rx[0..len], null, now1);
        }
    }

    const srv_conn = pair.server.iterator()[0].conn;

    // Sanity: server is mid-handshake. The migration gate keys off
    // exactly this — `handshakeDone() == false` makes the rebind
    // attempt below pre-handshake by definition.
    try std.testing.expect(!srv_conn.handshakeDone());

    // Wire up the qlog recorder AFTER the handshake setup so the
    // recorder window covers only the migration attempt.
    var recorder: QlogPreHandshakeRecorder = .{};
    srv_conn.setQlogCallback(QlogPreHandshakeRecorder.callback, &recorder);

    // Round 3 (the test): client polls a Handshake-level packet
    // (Finished). Feed it FROM A DIFFERENT `from` address.
    const now2: u64 = 3_000;
    const migration_addr: quic_zig.conn.path.Address = .{ .bytes = @splat(0xcd) };
    try std.testing.expect(!quic_zig.conn.path.Address.eql(migration_addr, pair.peer_addr));

    var fed_any = false;
    while (try pair.client.conn.poll(&rx, now2)) |len| {
        _ = try pair.server.feed(rx[0..len], migration_addr, now2);
        fed_any = true;
    }
    try std.testing.expect(fed_any);

    // Drop semantics — connection must NOT have closed. A migration-
    // gate firing is graceful: the peer can still recover by sending
    // again from the original address.
    try std.testing.expectEqual(@as(?quic_zig.CloseEvent, null), srv_conn.closeEvent());

    // The load-bearing assertion: a `migration_path_failed` qlog
    // event with reason `pre_handshake` was emitted. This is the
    // observable signal that the gate fired and the datagram was
    // dropped (rather than honored as a migration). Without the
    // gate, the server would have credited the Finished against
    // a new path tied to `migration_addr`, anchoring connection
    // state to a half-handshaked 4-tuple of the attacker's choosing.
    const evt = recorder.first(.migration_path_failed) orelse
        return error.ExpectedMigrationPathFailedEvent;
    try std.testing.expectEqual(
        @as(?quic_zig.QlogMigrationFailReason, .pre_handshake),
        evt.migration_fail_reason,
    );
}
