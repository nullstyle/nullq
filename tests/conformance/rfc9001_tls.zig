//! RFC 9001 — Using TLS to Secure QUIC.
//!
//! These suites pin the cryptographic interface QUIC v1 layers on top
//! of TLS 1.3: Initial-key derivation from the original DCID
//! (§5.2), AEAD nonce / AAD construction (§5.3), header protection
//! (§5.4), the Retry integrity tag (§5.8), the 0-RTT replay window
//! (§5.6), the AEAD invocation limit constants (§6.6), and the
//! mandatory ALPN / cipher-suite constraints (§4.1.1, §8.1, §8.2).
//!
//! Implementations under test:
//!   src/wire/initial.zig            — §5.2 Initial keys + HKDF-Expand-Label
//!   src/wire/protection.zig         — §5.3 AEAD nonce, §5.4 HP mask, §5.4.2 sample offset
//!   src/wire/short_packet.zig       — §5.4.1 short-header HP first-byte mask
//!   src/wire/long_packet.zig        — §5.8 Retry integrity, long-header HP mask
//!   src/tls/anti_replay.zig         — §5.6 anti-replay tracker
//!   src/tls/early_data_context.zig  — §4.6.1 0-RTT context digest
//!   src/tls/level.zig               — §5 encryption levels
//!
//! Most §A KAT vectors are cross-referenced from in-file unit tests
//! in `src/wire/initial.zig` and `src/wire/protection.zig`; this file
//! re-asserts them against the RFC text rather than against the unit-
//! test labels so an auditor can match each test back to a paragraph.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9001 §5.2 ¶2  MUST       client_initial_secret = HKDF-Expand-Label("client in", initial_secret) [KAT]
//!   RFC9001 §5.2 ¶2  MUST       server_initial_secret = HKDF-Expand-Label("server in", initial_secret) [KAT]
//!   RFC9001 §5.2 ¶2  MUST       Initial AEAD key derived with label "quic key" [KAT]
//!   RFC9001 §5.2 ¶2  MUST       Initial AEAD IV derived with label "quic iv" [KAT]
//!   RFC9001 §5.2 ¶2  MUST       Initial header-protection key derived with label "quic hp" [KAT]
//!   RFC9001 §5.2 ¶1  MUST       Initial keys use the v1 fixed salt 38762cf7…cad ccbb7f0a
//!   RFC9001 §5.3 ¶3  MUST       AEAD nonce = static_iv XOR PN (PN packed into low bytes)
//!   RFC9001 §5.3 ¶3  MUST       PN=0 leaves the static IV unchanged in the nonce
//!   RFC9001 §5.3 ¶2  MUST       AEAD opens reject ciphertext with a tampered tag
//!   RFC9001 §5.4.1 ¶3 MUST      HP masks low 4 bits of long-header first byte
//!   RFC9001 §5.4.1 ¶4 MUST      HP masks low 5 bits of short-header first byte
//!   RFC9001 §5.4.2 ¶1 MUST      HP sample is 16 bytes starting at PN_offset + 4 regardless of PN length
//!   RFC9001 §5.4.2 ¶1 MUST NOT  extract a sample when fewer than PN_offset + 20 bytes are available
//!   RFC9001 §5.4.3 ¶3 MUST      AES HP mask = first 5 bytes of AES_ECB(hp_key, sample) [§A.2 KAT]
//!   RFC9001 §5.4.4   MUST       HP mask is involutive (apply twice = no change)
//!   RFC9001 §5.6 ¶3  MUST       0-RTT replay tracker rejects a duplicate within the active window
//!   RFC9001 §5.6 ¶3  SHOULD     0-RTT replay tracker uses a single bounded-duration mechanism
//!   RFC9001 §5.7 ¶1  MUST       initial / handshake / 0-RTT / 1-RTT levels are distinct
//!   RFC9001 §5.8 ¶3  MUST       v1 Retry integrity key matches the §5.8 fixed constant
//!   RFC9001 §5.8 ¶3  MUST       v1 Retry integrity nonce matches the §5.8 fixed constant
//!   RFC9001 §5.8 ¶6  MUST       Retry integrity tag is 16 bytes appended to the packet
//!   RFC9001 §5.8 ¶6  MUST       sealRetry round-trips through validateRetryIntegrity
//!   RFC9001 §5.8 ¶6  MUST NOT   accept a Retry whose integrity tag was tampered
//!   RFC9001 §5.8 ¶6  MUST NOT   accept a Retry whose Original DCID was tampered
//!   RFC9001 §6.6 ¶3  MUST       AES-GCM confidentiality limit floor = 2^23 packets
//!   RFC9001 §6.6 ¶6  MUST       Integrity limit floor (ChaCha20-Poly1305 = 2^36)
//!   RFC9001 §8.2 ¶1  MUST       only TLS_AES_128/256_GCM_*, TLS_CHACHA20_POLY1305_SHA256 are negotiated
//!   RFC9001 §4.6.1 ¶3 MUST      0-RTT context digest changes when transport parameters change
//!   RFC9001 §4.6.1 ¶3 SHOULD    session-ticket context binds ALPN, transport params, and app context
//!
//! Visible debt:
//!   RFC9001 §4.1.1 ¶3 MUST     server closes with crypto_error 120 when peer omits ALPN
//!                              — needs Server fixture + handshake driver; skip_ below.
//!   RFC9001 §4.6 ¶1   MUST     0-RTT remains opt-in
//!                              — exercised by Server.Config.enable_0rtt default; skip_ here.
//!   RFC9001 §4.7 ¶1   MUST     server certificate validates against client trust store
//!                              — outside the wire/tls scope of this file; skip_.
//!   RFC9001 §4.8 ¶2   SHOULD   session ticket includes transport-parameter context
//!                              — covered structurally below; full ticket round-trip is skip_.
//!   RFC9001 §5.5 ¶2   MUST     enforce per-key AEAD invocation limits at runtime
//!                              — behavior lives in Connection; skip_ with TODO.
//!   RFC9001 §5.7 ¶3   MUST     discard Initial keys once Handshake keys are available
//!                              — needs full Connection fixture; skip_ with TODO.
//!   RFC9001 §6.1 ¶2   MUST     refuse first key update before handshake confirmation
//!                              — Connection-driven; skip_ with TODO.
//!   RFC9001 §6.5 ¶1   MUST     refuse second key update until peer ACKs the new keys
//!                              — Connection-driven; skip_ with TODO.
//!
//! Out of scope here (covered elsewhere):
//!   RFC9001 §17.2.5 (Retry framing, packet bytes)            → rfc9000_packet_headers.zig
//!   RFC9001 transport parameter codec                        → rfc9000_transport_params.zig
//!   RFC9001 PN truncation/recovery                           → rfc9000_packetization.zig

const std = @import("std");
const nullq = @import("nullq");

const initial = nullq.wire.initial;
const protection = nullq.wire.protection;
const long_packet = nullq.wire.long_packet;
const anti_replay = nullq.tls.anti_replay;
const early_data_context = nullq.tls.early_data_context;
const level = nullq.tls.level;

/// Comptime hex literal → fixed-size byte array. The standard fixture
/// helper used elsewhere in the conformance suites.
fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// RFC 9001 §A.1 fixture: the canonical worked-example Initial DCID.
const appendix_a_dcid = fromHex("8394c8f03e515708");

// ---------------------------------------------------------------- §5.2 initial keys

test "MUST derive client_initial_secret with label \"client in\" from the §A.1 DCID [RFC9001 §5.2 ¶2]" {
    // RFC 9001 §A.1 spells out the SHA-256 output for the canonical
    // DCID 8394c8f03e515708. A single byte difference in the salt or
    // the label would change every byte of this digest.
    const got = try initial.deriveInitialKeys(&appendix_a_dcid, false);
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
        &got.secret,
    );
}

test "MUST derive server_initial_secret with label \"server in\" from the §A.1 DCID [RFC9001 §5.2 ¶2]" {
    // §A.1 gives the server-side counterpart. The two role labels
    // ("client in" / "server in") are the only thing distinguishing
    // the secrets — a swap would deadlock the handshake.
    const got = try initial.deriveInitialKeys(&appendix_a_dcid, true);
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
        &got.secret,
    );
}

test "MUST derive Initial AEAD key with HKDF-Expand-Label \"quic key\" [RFC9001 §5.2 ¶2]" {
    // §A.1 KAT for the client-side AEAD key. AES-128-GCM uses 16
    // bytes of key material; SHA-384 suites would use 32 bytes but
    // Initial is locked to AES-128-GCM-SHA256 by §5.2.
    const got = try initial.deriveInitialKeys(&appendix_a_dcid, false);
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("1f369613dd76d5467730efcbe3b1a22d"),
        &got.key,
    );
}

test "MUST derive Initial AEAD IV with HKDF-Expand-Label \"quic iv\" [RFC9001 §5.2 ¶2]" {
    // §A.1 KAT for the client-side static IV. The IV is XORed with
    // the PN to form the per-packet nonce (§5.3), so the entire
    // packet stream's authenticity hinges on this 12-byte value.
    const got = try initial.deriveInitialKeys(&appendix_a_dcid, false);
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("fa044b2f42a3fd3b46fb255c"),
        &got.iv,
    );
}

test "MUST derive Initial header-protection key with HKDF-Expand-Label \"quic hp\" [RFC9001 §5.2 ¶2]" {
    // §A.1 KAT for the client-side header-protection key. Used as
    // the AES-128 key in §5.4.3's mask = AES_ECB(hp_key, sample).
    const got = try initial.deriveInitialKeys(&appendix_a_dcid, false);
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("9f50449e04a0e810283a1e9933adedd2"),
        &got.hp,
    );
}

test "MUST use the QUIC v1 Initial salt 38762cf7…cad ccbb7f0a [RFC9001 §5.2 ¶1]" {
    // §5.2 fixes the v1 salt as "38762cf7f55934b34d179ae6a4c80cad ccbb7f0a"
    // (20 bytes — SHA-256 block size). A fork to a different salt is
    // exactly how a hypothetical QUIC v2 would reuse this code path.
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        &initial.initial_salt_v1,
    );
}

// ---------------------------------------------------------------- §5.3 AEAD usage

test "MUST construct AEAD nonce as static_iv XOR PN with PN in the low bytes [RFC9001 §5.3 ¶3]" {
    // §5.3: "The exact output of the AEAD function is dependent on
    // the cipher suite negotiated. … The nonce, N, is formed by
    // combining the packet protection IV with the packet number."
    // Low-byte placement: PN=2 must flip bit 1 of nonce[11].
    const iv = fromHex("fa044b2f42a3fd3b46fb255c");
    const nonce = protection.aeadNonce(&iv, 2);

    var expected = iv;
    expected[11] ^= 0x02;
    try std.testing.expectEqualSlices(u8, &expected, &nonce);
}

test "MUST keep AEAD nonce equal to static_iv when PN is zero [RFC9001 §5.3 ¶3]" {
    // The XOR construction: PN=0 contributes no bits, so the very
    // first packet in a PN space uses nonce = iv verbatim.
    const iv = fromHex("fa044b2f42a3fd3b46fb255c");
    try std.testing.expectEqualSlices(u8, &iv, &protection.aeadNonce(&iv, 0));
}

test "MUST NOT accept a packet whose AEAD tag has been tampered [RFC9001 §5.3 ¶2]" {
    // §5.3: AEAD authenticates header (AAD) + payload. Mutating any
    // ciphertext byte or any header byte must produce
    // boringssl.crypto.aead.Error.Auth.
    const boringssl = @import("boringssl");
    const AesGcm128 = boringssl.crypto.aead.AesGcm128;

    const keys = try initial.deriveInitialKeys(&appendix_a_dcid, false);
    var aead = try AesGcm128.init(&keys.key);
    defer aead.deinit();

    const header_bytes = fromHex("c300000001088394c8f03e5157080000449e00000002");
    var ct: [128]u8 = undefined;
    const ct_len = try protection.aeadSeal(&aead, &keys.iv, 2, &header_bytes, "x", &ct);

    ct[0] ^= 0x01; // flip a single bit anywhere in ciphertext+tag
    var pt: [64]u8 = undefined;
    try std.testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        protection.aeadOpen(&aead, &keys.iv, 2, &header_bytes, ct[0..ct_len], &pt),
    );
}

// ---------------------------------------------------------------- §5.4 header protection

test "MUST mask only the low 4 bits of the first byte for long-header packets [RFC9001 §5.4.1 ¶3]" {
    // §5.4.1: "The least significant four bits of the first byte
    // (...) Protected Bits ... long header." The high 4 bits (form,
    // fixed, type-bits) are NOT touched by HP — that's why the
    // receiver can determine packet type before having keys.
    var packet = [_]u8{ 0xc0, 0xff };
    const all_ones_mask: [protection.mask_len]u8 = .{ 0xff, 0, 0, 0, 0 };
    try protection.applyHpMask(&packet, .long, 1, 1, all_ones_mask);
    // Only low 4 bits flipped: 0xc0 ^ 0x0f = 0xcf.
    try std.testing.expectEqual(@as(u8, 0xcf), packet[0]);
}

test "MUST mask the low 5 bits of the first byte for short-header packets [RFC9001 §5.4.1 ¶4]" {
    // §5.4.1: short-header Protected Bits include reserved (2),
    // key_phase (1), and PN length (2) — five bits in total. The
    // form bit and fixed bit (bits 7-6) are still untouched.
    var packet = [_]u8{ 0x40, 0xff };
    const all_ones_mask: [protection.mask_len]u8 = .{ 0xff, 0, 0, 0, 0 };
    try protection.applyHpMask(&packet, .short, 1, 1, all_ones_mask);
    // Only low 5 bits flipped: 0x40 ^ 0x1f = 0x5f.
    try std.testing.expectEqual(@as(u8, 0x5f), packet[0]);
}

test "MUST sample 16 ciphertext bytes starting at PN_offset + 4 [RFC9001 §5.4.2 ¶1]" {
    // §5.4.2: "the sampled ciphertext is taken starting from an
    // offset of 4 bytes after the start of the Packet Number field"
    // — i.e. always 4 bytes past `pn_offset`, regardless of the
    // actual PN length (1..4). This is what lets the receiver
    // sample BEFORE knowing the true PN length.
    var packet: [40]u8 = undefined;
    var i: u8 = 0;
    while (i < packet.len) : (i += 1) packet[i] = i;

    const pn_offset: usize = 18;
    const got = try protection.sampleAt(&packet, pn_offset);

    // Expected sample = packet[22..38] = 22, 23, …, 37.
    var expected: [16]u8 = undefined;
    var j: u8 = 0;
    while (j < expected.len) : (j += 1) expected[j] = @intCast(22 + j);
    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "MUST NOT extract a sample when fewer than 20 bytes follow PN_offset [RFC9001 §5.4.2 ¶1]" {
    // §5.4.2 implicitly requires 4 + 16 = 20 bytes of post-PN
    // ciphertext. nullq surfaces this as
    // protection.Error.InsufficientCiphertext rather than reading
    // past the buffer.
    var packet: [22]u8 = undefined;
    @memset(&packet, 0);
    // pn_offset=4 → sample would need bytes 8..24 but only 22 exist.
    try std.testing.expectError(
        protection.Error.InsufficientCiphertext,
        protection.sampleAt(&packet, 4),
    );
}

test "MUST derive AES HP mask as the first 5 bytes of AES_ECB(hp_key, sample) [RFC9001 §5.4.3 ¶3]" {
    // §A.2 worked example: with the §A.1 client hp key and the spec's
    // sample d1b1c98dd7689fb8ec11d242b123dc9b, the mask is exactly
    // 437b9aec36. Any silently-wrong endianness or AES variant would
    // not produce this 40-bit value.
    const keys = try initial.deriveInitialKeys(&appendix_a_dcid, false);
    const sample = fromHex("d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = try protection.aesHpMask(&keys.hp, &sample);
    try std.testing.expectEqualSlices(u8, &fromHex("437b9aec36"), &mask);
}

test "MUST be involutive: apply HP twice and the bytes are unchanged [RFC9001 §5.4 ¶1]" {
    // HP is XOR — sender and receiver use the exact same mask. If
    // applying twice didn't restore the input, encrypt/decrypt
    // wouldn't be symmetric.
    var packet = [_]u8{ 0xc3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const original = packet;
    const mask: [protection.mask_len]u8 = .{ 0xa3, 0x5b, 0xc1, 0x77, 0x9d };
    try protection.applyHpMask(&packet, .long, 1, 4, mask);
    try std.testing.expect(!std.mem.eql(u8, &original, &packet));
    try protection.applyHpMask(&packet, .long, 1, 4, mask);
    try std.testing.expectEqualSlices(u8, &original, &packet);
}

// ---------------------------------------------------------------- §5.6 anti-replay

test "MUST reject a 0-RTT identity replayed within the active window [RFC9001 §5.6 ¶3]" {
    // §5.6: "an endpoint that accepts 0-RTT MUST implement an anti-
    // replay mechanism." The tracker treats first sight as `.fresh`
    // and any sight within `max_age_us` as `.replay` — the embedder
    // must drop the replay.
    var tracker = try anti_replay.AntiReplayTracker.init(std.testing.allocator, .{});
    defer tracker.deinit();

    const id: anti_replay.Id = @splat(0x42);
    try std.testing.expectEqual(anti_replay.Verdict.fresh, try tracker.consume(id, 1_000));
    try std.testing.expectEqual(anti_replay.Verdict.replay, try tracker.consume(id, 1_500));
}

test "SHOULD age out replay-window entries past max_age_us [RFC9001 §5.6 ¶3]" {
    // §5.6: "such mechanisms tend to be limited in either capacity
    // or duration." The tracker enforces a bounded duration; once
    // past `max_age_us` the identity becomes legally fresh again.
    var tracker = try anti_replay.AntiReplayTracker.init(
        std.testing.allocator,
        .{ .max_age_us = 1_000 },
    );
    defer tracker.deinit();

    const id: anti_replay.Id = @splat(0xab);
    try std.testing.expectEqual(anti_replay.Verdict.fresh, try tracker.consume(id, 1_000));
    try std.testing.expectEqual(anti_replay.Verdict.replay, try tracker.consume(id, 1_500));
    // 1000 us past insertion: aged out — back to `.fresh`.
    try std.testing.expectEqual(anti_replay.Verdict.fresh, try tracker.consume(id, 2_000));
}

// ---------------------------------------------------------------- §5.7 keys per level

test "MUST keep Initial / 0-RTT / Handshake / 1-RTT as distinct encryption levels [RFC9001 §5.7 ¶1]" {
    // §5: four levels with different secrets and (for Initial /
    // Handshake / Application) different PN spaces. The level enum
    // is the dispatch key for which keys to use; the contract is
    // that the four discriminants are unique and that 0-RTT shares
    // the application PN space.
    try std.testing.expect(level.EncryptionLevel.initial != level.EncryptionLevel.handshake);
    try std.testing.expect(level.EncryptionLevel.initial != level.EncryptionLevel.early_data);
    try std.testing.expect(level.EncryptionLevel.initial != level.EncryptionLevel.application);
    try std.testing.expect(level.EncryptionLevel.early_data != level.EncryptionLevel.handshake);
    try std.testing.expect(level.EncryptionLevel.handshake != level.EncryptionLevel.application);
    // 0-RTT shares the application PN space (RFC 9000 §12.3).
    try std.testing.expectEqual(
        level.EncryptionLevel.application.pnSpaceIdx(),
        level.EncryptionLevel.early_data.pnSpaceIdx(),
    );
    // The other three spaces are distinct.
    try std.testing.expect(
        level.EncryptionLevel.initial.pnSpaceIdx() != level.EncryptionLevel.handshake.pnSpaceIdx(),
    );
    try std.testing.expect(
        level.EncryptionLevel.handshake.pnSpaceIdx() != level.EncryptionLevel.application.pnSpaceIdx(),
    );
}

// ---------------------------------------------------------------- §5.8 Retry integrity

test "MUST use the v1 Retry integrity key be0c690b9f66575a1d766b54e368c84e [RFC9001 §5.8 ¶3]" {
    // §5.8: "The secret key is be0c690b9f66575a1d766b54e368c84e."
    // This is a fixed value for QUIC v1. A v2 would publish its own.
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("be0c690b9f66575a1d766b54e368c84e"),
        &long_packet.retry_integrity_key_v1,
    );
}

test "MUST use the v1 Retry integrity nonce 461599d35d632bf2239825bb [RFC9001 §5.8 ¶3]" {
    // §5.8: companion nonce. AES-128-GCM with this fixed (key,
    // nonce) on a per-Retry-pseudo-packet AAD effectively turns
    // the AEAD into a keyed MAC for the Retry packet.
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("461599d35d632bf2239825bb"),
        &long_packet.retry_integrity_nonce_v1,
    );
}

test "MUST append a 16-byte Retry integrity tag to every emitted Retry [RFC9001 §5.8 ¶6]" {
    // §17.2.5 + §5.8: the Retry packet ends with a 128-bit AEAD tag.
    // The tag length is structural — it lets the receiver split
    // token bytes from tag bytes without a Length field.
    const original_dcid = fromHex("8394c8f03e515708");
    const dcid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const scid: [8]u8 = .{ 1, 3, 3, 7, 5, 8, 13, 21 };
    const token = "retry-token";

    var packet: [128]u8 = undefined;
    const len = try long_packet.sealRetry(&packet, .{
        .original_dcid = &original_dcid,
        .dcid = &dcid,
        .scid = &scid,
        .retry_token = token,
    });
    // The encoded packet must be at least 16 bytes long; we
    // separately validate that the trailing 16 bytes are the
    // computed AEAD tag (validateRetryIntegrity is a true round-
    // trip check).
    try std.testing.expect(len >= 16);
    try std.testing.expect(try long_packet.validateRetryIntegrity(&original_dcid, packet[0..len]));
}

test "MUST NOT validate a Retry whose integrity tag was modified [RFC9001 §5.8 ¶6]" {
    // §5.8: "The Retry Integrity Tag is a 128-bit field that is
    // computed as the output of AEAD_AES_128_GCM …" — flipping any
    // bit must fail the AEAD check.
    const original_dcid = fromHex("8394c8f03e515708");
    const dcid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const scid: [8]u8 = .{ 1, 3, 3, 7, 5, 8, 13, 21 };
    const token = "retry-token";

    var packet: [128]u8 = undefined;
    const len = try long_packet.sealRetry(&packet, .{
        .original_dcid = &original_dcid,
        .dcid = &dcid,
        .scid = &scid,
        .retry_token = token,
    });
    packet[len - 1] ^= 0x01; // flip a bit of the trailing tag
    try std.testing.expect(!try long_packet.validateRetryIntegrity(&original_dcid, packet[0..len]));
}

test "MUST NOT validate a Retry against a different Original DCID [RFC9001 §5.8 ¶6]" {
    // §5.8: the Retry pseudo-packet that the AEAD authenticates
    // begins with `ODCID Length || Original DCID`. A peer that
    // observes a Retry can't replay it to a different original
    // connection — the ODCID is part of the AAD.
    const original_dcid = fromHex("8394c8f03e515708");
    const dcid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const scid: [8]u8 = .{ 1, 3, 3, 7, 5, 8, 13, 21 };
    const token = "retry-token";

    var packet: [128]u8 = undefined;
    const len = try long_packet.sealRetry(&packet, .{
        .original_dcid = &original_dcid,
        .dcid = &dcid,
        .scid = &scid,
        .retry_token = token,
    });

    const wrong_dcid = fromHex("0000000000000000");
    try std.testing.expect(!try long_packet.validateRetryIntegrity(&wrong_dcid, packet[0..len]));
}

// ---------------------------------------------------------------- §6.6 invocation limits

test "MUST keep AES-GCM confidentiality limit at or below 2^23 packets [RFC9001 §6.6 ¶3]" {
    // §6.6: "For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the
    // confidentiality limit is 2^23 encrypted packets." nullq's
    // default `confidentiality_limit` must not exceed that floor.
    const defaults: nullq.ApplicationKeyUpdateLimits = .{};
    try std.testing.expect(defaults.confidentiality_limit <= (@as(u64, 1) << 23));
    try std.testing.expectEqual(@as(u64, 8388608), @as(u64, 1) << 23);
}

test "MUST keep proactive update threshold strictly below the hard confidentiality limit [RFC9001 §6.6 ¶3]" {
    // §6: an endpoint MUST NOT send more than the limit. nullq
    // updates keys *before* the hard limit so the last legal packet
    // can carry CONNECTION_CLOSE if needed.
    const defaults: nullq.ApplicationKeyUpdateLimits = .{};
    try std.testing.expect(defaults.proactive_update_threshold < defaults.confidentiality_limit);
}

test "MUST cap the integrity limit at the cross-suite floor of 2^36 [RFC9001 §6.6 ¶6]" {
    // §6.6: "For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the integrity
    // limit is 2^52 invocations. … For AEAD_CHACHA20_POLY1305, the
    // integrity limit is 2^36 invocations." The cross-suite floor
    // (and nullq's chosen default) is 2^36.
    const defaults: nullq.ApplicationKeyUpdateLimits = .{};
    try std.testing.expect(defaults.integrity_limit <= (@as(u64, 1) << 36));
}

// ---------------------------------------------------------------- §8.2 cipher suite

test "MUST recognize exactly the three QUIC v1 TLS 1.3 cipher suites [RFC9001 §8.2 ¶1]" {
    // §8.2: "An implementation of QUIC v1 MUST support … the AEAD
    // and hash functions for these cipher suites: TLS_AES_128_GCM_
    // SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256."
    // IANA TLS Cipher Suite codes 0x1301..0x1303.
    const Suite = nullq.wire.short_packet.Suite;
    try std.testing.expectEqual(Suite.aes128_gcm_sha256, Suite.fromProtocolId(0x1301).?);
    try std.testing.expectEqual(Suite.aes256_gcm_sha384, Suite.fromProtocolId(0x1302).?);
    try std.testing.expectEqual(Suite.chacha20_poly1305_sha256, Suite.fromProtocolId(0x1303).?);
    // Anything outside that set must NOT be accepted (e.g. a TLS 1.2-
    // only suite, or a future TLS 1.3 suite that isn't QUIC-blessed).
    try std.testing.expectEqual(@as(?Suite, null), Suite.fromProtocolId(0x009c));
    try std.testing.expectEqual(@as(?Suite, null), Suite.fromProtocolId(0x1304));
}

// ---------------------------------------------------------------- §4.6.1 / §4.8 0-RTT context

test "MUST bind the 0-RTT context digest to the transport parameters [RFC9001 §4.6.1 ¶3]" {
    // §4.6.1 ¶3: "The server MUST NOT … accept 0-RTT data that …
    // would result in different protocol behavior than the data
    // being sent in 1-RTT." nullq enforces this by hashing every
    // replay-relevant transport parameter into a single digest that
    // the BoringSSL session compares on resumption.
    const base = try early_data_context.build(.{
        .alpn = "h3",
        .transport_params = .{ .initial_max_data = 1024 },
    });
    const changed = try early_data_context.build(.{
        .alpn = "h3",
        .transport_params = .{ .initial_max_data = 2048 },
    });
    try std.testing.expect(!std.mem.eql(u8, &base, &changed));
}

test "SHOULD bind the session-ticket context to ALPN as well as transport parameters [RFC9001 §4.8 ¶2]" {
    // §4.8 (and §4.6.1): the resumption context "SHOULD" cover ALPN
    // so a client that resumed under a different application
    // protocol can't replay 0-RTT bytes meant for the original
    // protocol.
    const base = try early_data_context.build(.{
        .alpn = "h3",
        .transport_params = .{ .initial_max_data = 1024 },
    });
    const alpn_changed = try early_data_context.build(.{
        .alpn = "hq-interop",
        .transport_params = .{ .initial_max_data = 1024 },
    });
    try std.testing.expect(!std.mem.eql(u8, &base, &alpn_changed));
}

// ---------------------------------------------------------------- visible debt

test "skip_MUST close with crypto_error 120 when the peer's ClientHello omits ALPN [RFC9001 §4.1.1 ¶3]" {
    // §4.1.1: "endpoints MUST send the no_application_protocol TLS
    // alert (QUIC error code 0x0178) when ALPN is absent."
    // TODO: needs a Server fixture driving a synthetic ClientHello
    // through `Server.feed`; not exercisable from the wire/tls layer
    // alone. Tracked alongside the rest of the §4 surface.
    return error.SkipZigTest;
}

test "skip_MUST keep 0-RTT opt-in (default disabled) [RFC9001 §4.6 ¶1]" {
    // §4.6: "The server MUST … disable early data by default."
    // nullq's `Server.Config.enable_0rtt` defaults to false; a
    // proper conformance test would instantiate two `Config`
    // values and assert the default. Skipping until the auditor-
    // facing Config API is reachable through `nullq.*` re-exports
    // without pulling the full Server fixture.
    return error.SkipZigTest;
}

test "skip_MUST validate the server certificate chain at the client [RFC9001 §4.7 ¶1]" {
    // §4.7: "The TLS handshake provides authentication … the client
    // MUST verify the server's certificate chain." Validation lives
    // inside BoringSSL plus our `verify=...` plumbing; auditing it
    // against §4.7 would require a TLS fixture that's outside the
    // wire/tls scope of this file.
    return error.SkipZigTest;
}

test "skip_MUST enforce per-key AEAD invocation limits at runtime [RFC9001 §5.5 ¶2]" {
    // §5.5: "An endpoint MUST NOT … exceed the confidentiality limit
    // for an AEAD algorithm." nullq's enforcement lives in
    // `Connection`'s send path (see ApplicationKeyUpdateLimits +
    // setApplicationKeyUpdateLimitsForTesting). A full conformance
    // test would drive a Connection up to the threshold and observe
    // the close event — outside the wire/tls scope.
    return error.SkipZigTest;
}

test "skip_MUST discard Initial keys once Handshake keys are available [RFC9001 §5.7 ¶3]" {
    // §5.7: "Endpoints MUST … discard Initial keys when they first
    // send a Handshake packet." Driven by the connection state
    // machine; a proper conformance test would step through a real
    // handshake and observe that subsequent inbound Initial packets
    // are dropped.
    return error.SkipZigTest;
}

test "skip_MUST refuse the first key update before handshake confirmation [RFC9001 §6.1 ¶2]" {
    // §6.1: "An endpoint MUST NOT initiate a key update prior to
    // having confirmed the handshake." Connection-driven; out of
    // scope for the §5 wire-protection layer this file covers.
    return error.SkipZigTest;
}

test "skip_MUST refuse a second key update until the first is acknowledged [RFC9001 §6.5 ¶1]" {
    // §6.5: "An endpoint MUST NOT initiate a subsequent key update
    // unless it has received an acknowledgment for a packet that was
    // sent protected with keys from the current key phase." Driven
    // by the Connection ack path; needs a state-machine fixture.
    return error.SkipZigTest;
}
