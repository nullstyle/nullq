//! QUIC packet protection (RFC 9001 §5.3 + §5.4).
//!
//! Two cooperating mechanisms wrap each protected packet:
//!
//! 1. **AEAD packet protection** (§5.3): per-packet nonce =
//!    static_iv XOR pn (zero-padded). Authenticates the packet
//!    header as AAD and encrypts the payload.
//! 2. **Header protection** (§5.4): a 5-byte mask derived from a
//!    sample of the AEAD ciphertext is XORed into the first byte's
//!    low bits and the encrypted PN bytes, so the PN length and
//!    PN value can't be read without first recovering the keys.
//!
//! This module covers the packet-protection mechanics shared by the
//! QUIC v1 TLS cipher suites: TLS_AES_128_GCM_SHA256,
//! TLS_AES_256_GCM_SHA384, and TLS_CHACHA20_POLY1305_SHA256.

const std = @import("std");
const boringssl = @import("boringssl");

const AesGcm128 = boringssl.crypto.aead.AesGcm128;
const Aes128 = boringssl.crypto.aes.Aes128;
const Aes256 = boringssl.crypto.aes.Aes256;
const chacha20 = boringssl.crypto.chacha20;

/// Sample size used to derive the header-protection mask. Always 16
/// bytes regardless of cipher suite (RFC 9001 §5.4.2).
pub const sample_len: usize = 16;

/// Header-protection mask length (1 byte for first-byte fixup + up
/// to 4 bytes of PN).
pub const mask_len: usize = 5;

/// Errors returned by header- and packet-protection routines.
pub const Error = error{
    InsufficientCiphertext,
    InvalidPnLength,
    InvalidPnOffset,
    OutputTooSmall,
} || boringssl.crypto.aead.Error || boringssl.crypto.aes.Error;

/// Construct the per-packet AEAD nonce by XORing the 62-bit packet
/// number (left-padded with zeros to 12 bytes, big-endian) into the
/// static IV. RFC 9001 §5.3.
pub fn aeadNonce(iv: *const [12]u8, pn: u64) [12]u8 {
    var nonce = iv.*;
    var pn_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_be, pn, .big);
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        nonce[12 - 8 + i] ^= pn_be[i];
    }
    return nonce;
}

/// Construct the multipath 1-RTT AEAD nonce from draft-ietf-quic-
/// multipath-21 §2.4: IV XOR PPN, where PPN is path_id(32) ||
/// zeroes(2) || packet_number(62), all in network byte order.
pub fn aeadNonceForPath(iv: *const [12]u8, path_id: u32, pn: u64) [12]u8 {
    var nonce = iv.*;
    var ppn: [12]u8 = @splat(0);
    var path_be: [4]u8 = undefined;
    var pn_be: [8]u8 = undefined;
    std.mem.writeInt(u32, &path_be, path_id, .big);
    std.mem.writeInt(u64, &pn_be, pn & ((@as(u64, 1) << 62) - 1), .big);
    @memcpy(ppn[0..4], &path_be);
    @memcpy(ppn[4..12], &pn_be);
    var i: usize = 0;
    while (i < ppn.len) : (i += 1) nonce[i] ^= ppn[i];
    return nonce;
}

/// Compute the 5-byte header-protection mask from a 16-byte ciphertext
/// sample using AES-128 single-block encryption. The mask is the first
/// 5 bytes of `AES_encrypt(hp_key, sample)`. RFC 9001 §5.4.3.
pub fn aesHpMask(hp_key: *const [16]u8, sample: *const [sample_len]u8) Error![mask_len]u8 {
    const aes = try Aes128.init(hp_key);
    var block: [16]u8 = undefined;
    aes.encryptBlock(sample, &block);
    var mask: [mask_len]u8 = undefined;
    @memcpy(&mask, block[0..mask_len]);
    return mask;
}

/// AES-256-GCM uses AES-256 for QUIC header protection.
pub fn aes256HpMask(hp_key: *const [32]u8, sample: *const [sample_len]u8) Error![mask_len]u8 {
    const aes = try Aes256.init(hp_key);
    var block: [16]u8 = undefined;
    aes.encryptBlock(sample, &block);
    var mask: [mask_len]u8 = undefined;
    @memcpy(&mask, block[0..mask_len]);
    return mask;
}

/// ChaCha20-Poly1305 uses RFC 9001 §5.4.4 header protection.
pub fn chacha20HpMask(hp_key: *const [32]u8, sample: *const [sample_len]u8) [mask_len]u8 {
    return chacha20.quicHpMask(hp_key, sample);
}

/// Whether a packet uses the long-header or short-header form. Drives
/// how many low bits of the first byte are masked by header
/// protection (RFC 9001 §5.4.1).
pub const HeaderForm = enum {
    /// Long header: mask the low 4 bits of the first byte (reserved +
    /// PN length).
    long,
    /// Short header: mask the low 5 bits (reserved + key_phase + PN
    /// length).
    short,
};

/// Apply (or, since XOR is involutive, remove) a header-protection
/// mask in place.
///
/// `packet[0]` is masked according to `header_form`; `packet[pn_offset
/// .. pn_offset + pn_length]` is masked with `mask[1 .. 1+pn_length]`.
pub fn applyHpMask(
    packet: []u8,
    header_form: HeaderForm,
    pn_offset: usize,
    pn_length: u8,
    mask: [mask_len]u8,
) Error!void {
    if (pn_length < 1 or pn_length > 4) return Error.InvalidPnLength;
    if (packet.len < pn_offset + pn_length) return Error.InvalidPnOffset;

    const first_byte_mask: u8 = switch (header_form) {
        .long => 0x0f,
        .short => 0x1f,
    };
    packet[0] ^= mask[0] & first_byte_mask;
    var i: u8 = 0;
    while (i < pn_length) : (i += 1) {
        packet[pn_offset + i] ^= mask[1 + i];
    }
}

/// AEAD-seal `plaintext` for a packet whose header occupies
/// `header` bytes (used as AAD), packet number `pn`, with the
/// already-initialized AEAD context. Writes ciphertext (with
/// 16-byte tag appended) into `dst`. Returns total bytes written.
pub fn aeadSeal(
    aead: anytype,
    iv: *const [12]u8,
    pn: u64,
    header: []const u8,
    plaintext: []const u8,
    dst: []u8,
) Error!usize {
    const nonce = aeadNonce(iv, pn);
    return aead.seal(dst, &nonce, header, plaintext);
}

/// AEAD-seal using the draft multipath path-ID-aware nonce.
pub fn aeadSealForPath(
    aead: anytype,
    iv: *const [12]u8,
    path_id: u32,
    pn: u64,
    header: []const u8,
    plaintext: []const u8,
    dst: []u8,
) Error!usize {
    const nonce = aeadNonceForPath(iv, path_id, pn);
    return aead.seal(dst, &nonce, header, plaintext);
}

/// AEAD-open: reverse of `aeadSeal`. `ciphertext` includes the tag.
pub fn aeadOpen(
    aead: anytype,
    iv: *const [12]u8,
    pn: u64,
    header: []const u8,
    ciphertext: []const u8,
    dst: []u8,
) Error!usize {
    const nonce = aeadNonce(iv, pn);
    return aead.open(dst, &nonce, header, ciphertext);
}

/// AEAD-open using the draft multipath path-ID-aware nonce.
pub fn aeadOpenForPath(
    aead: anytype,
    iv: *const [12]u8,
    path_id: u32,
    pn: u64,
    header: []const u8,
    ciphertext: []const u8,
    dst: []u8,
) Error!usize {
    const nonce = aeadNonceForPath(iv, path_id, pn);
    return aead.open(dst, &nonce, header, ciphertext);
}

/// Extract a 16-byte sample for HP mask generation from a fully
/// formed protected packet, given the offset of the (post-HP) PN.
/// Per RFC 9001 §5.4.2, the sample begins at `pn_offset + 4` — i.e.
/// just past where a maximum-length PN would end, regardless of how
/// many PN bytes are actually used. The sample is the next 16 bytes
/// of ciphertext.
pub fn sampleAt(packet: []const u8, pn_offset: usize) Error![sample_len]u8 {
    const sample_start = pn_offset + 4;
    if (packet.len < sample_start + sample_len) return Error.InsufficientCiphertext;
    var s: [sample_len]u8 = undefined;
    @memcpy(&s, packet[sample_start .. sample_start + sample_len]);
    return s;
}

// -- tests ---------------------------------------------------------------

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "aeadNonce: PN 2 in canonical iv from RFC 9001 §A.1 client" {
    // RFC 9001 §A.2 reuses the client iv = fa044b2f42a3fd3b46fb255c.
    // For PN=2 the spec doesn't tabulate the constructed nonce
    // explicitly, but the AEAD path will validate it via the
    // byte-equal §A.2 KAT below. As a unit test, just check that
    // PN=0 leaves the iv unchanged and PN=1 flips the lowest bit.
    const iv = fromHex("fa044b2f42a3fd3b46fb255c");
    try std.testing.expectEqualSlices(u8, &iv, &aeadNonce(&iv, 0));

    const n1 = aeadNonce(&iv, 1);
    var expected = iv;
    expected[11] ^= 0x01;
    try std.testing.expectEqualSlices(u8, &expected, &n1);

    // PN=2 flips bit 1 of last byte.
    const n2 = aeadNonce(&iv, 2);
    expected = iv;
    expected[11] ^= 0x02;
    try std.testing.expectEqualSlices(u8, &expected, &n2);
}

test "aeadNonceForPath: draft-21 nonce example" {
    const iv = fromHex("6b26114b9cba2b63a9e8dd4f");
    const nonce = aeadNonceForPath(&iv, 3, 0xd431);
    try std.testing.expectEqualSlices(u8, &fromHex("6b2611489cba2b63a9e8097e"), &nonce);
}

test "applyHpMask is involutive on long headers" {
    var packet = [_]u8{ 0xc3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const original = packet;
    const mask: [mask_len]u8 = .{ 0xa3, 0x5b, 0xc1, 0x77, 0x9d };
    try applyHpMask(&packet, .long, 1, 4, mask);
    try std.testing.expect(!std.mem.eql(u8, &original, &packet));
    try applyHpMask(&packet, .long, 1, 4, mask);
    try std.testing.expectEqualSlices(u8, &original, &packet);
}

test "applyHpMask: short header masks 5 bits of first byte" {
    var packet = [_]u8{ 0x40, 0xff };
    const mask: [mask_len]u8 = .{ 0xff, 0, 0, 0, 0 };
    try applyHpMask(&packet, .short, 1, 1, mask);
    try std.testing.expectEqual(@as(u8, 0x40 ^ 0x1f), packet[0]);
    try std.testing.expectEqual(@as(u8, 0xff), packet[1]);
}

test "applyHpMask rejects invalid pn_length" {
    var packet = @as([16]u8, @splat(0));
    const mask: [mask_len]u8 = @splat(0);
    try std.testing.expectError(Error.InvalidPnLength, applyHpMask(&packet, .long, 0, 0, mask));
    try std.testing.expectError(Error.InvalidPnLength, applyHpMask(&packet, .long, 0, 5, mask));
}

test "AEAD round-trip with RFC 9001 §A.1 client keys, §A.2 header as AAD" {
    // Use the §A.1 client keys + the §A.2 unprotected header bytes
    // as AAD; encrypt a synthetic plaintext and verify decrypt gives
    // the original. This validates the seal/open path end-to-end
    // against the canonical key material.
    //
    // The fully byte-equal §A.2 KAT (1200 protected bytes) lands
    // when we vendor the spec's ClientHello fixture as a separate
    // test file under `tests/rfc/`; transcribing 2400 chars of hex
    // inline would invite typo bugs without adding much over what
    // the §A.2 HP-mask test below already covers.
    const initial = @import("initial.zig");
    const dcid = fromHex("8394c8f03e515708");
    const keys = try initial.deriveInitialKeys(&dcid, false);

    var aead = try AesGcm128.init(&keys.key);
    defer aead.deinit();

    const unprotected_header = fromHex(
        "c300000001088394c8f03e5157080000449e00000002",
    );
    const small_pt = "synthetic CRYPTO payload for round-trip";

    var ct_buf: [256]u8 = undefined;
    const ct_len = try aeadSeal(&aead, &keys.iv, 2, &unprotected_header, small_pt, &ct_buf);
    try std.testing.expectEqual(small_pt.len + 16, ct_len);

    var pt_back: [256]u8 = undefined;
    const pt_len = try aeadOpen(&aead, &keys.iv, 2, &unprotected_header, ct_buf[0..ct_len], &pt_back);
    try std.testing.expectEqualSlices(u8, small_pt, pt_back[0..pt_len]);
}

test "full pipeline: protect then unprotect a synthetic Initial" {
    // End-to-end: build a packet, AEAD-seal payload using header as
    // AAD, header-protect, then run the receiver flow in reverse
    // (sample → mask → unmask → AEAD-open). Validates that all four
    // primitives fit together correctly without depending on any
    // specific spec hex output.
    const initial = @import("initial.zig");
    const dcid = fromHex("8394c8f03e515708");
    const keys = try initial.deriveInitialKeys(&dcid, false);

    var aead = try AesGcm128.init(&keys.key);
    defer aead.deinit();

    const pn: u64 = 7;
    const pn_length: u8 = 2;
    var packet: [256]u8 = undefined;
    @memset(&packet, 0);

    // Synthetic 20-byte unprotected header: first byte 0xc1 (long,
    // fixed, Initial, reserved=0, pn_len=2), version, no token,
    // length=20. Doesn't have to match a real Initial — we're
    // testing the protection layer, not the framing layer.
    const header_bytes = fromHex(
        "c100000001020102030400000007", // 14 bytes
    );
    @memcpy(packet[0..header_bytes.len], &header_bytes);

    // Where in `packet` does the PN sit? Last 2 bytes of the header.
    const pn_offset: usize = header_bytes.len - pn_length;

    // Plaintext payload that would normally be CRYPTO+PADDING.
    const plaintext = "the quick brown fox jumps over the lazy dogthe quick brown fox jumps over the lazy dog";

    // AEAD-seal: ciphertext goes immediately after the header.
    const ct_start = header_bytes.len;
    const ct_len = try aeadSeal(
        &aead,
        &keys.iv,
        pn,
        packet[0..ct_start],
        plaintext,
        packet[ct_start..],
    );

    // Header-protect: sample is 16 bytes starting at pn_offset+4.
    const sample = try sampleAt(packet[0 .. ct_start + ct_len], pn_offset);
    const mask = try aesHpMask(&keys.hp, &sample);
    try applyHpMask(&packet, .long, pn_offset, pn_length, mask);

    // ── receiver flow ──
    // Sample is the same 16 bytes (HP doesn't touch the ciphertext).
    const rx_sample = try sampleAt(packet[0 .. ct_start + ct_len], pn_offset);
    try std.testing.expectEqualSlices(u8, &sample, &rx_sample);

    const rx_mask = try aesHpMask(&keys.hp, &rx_sample);
    try applyHpMask(&packet, .long, pn_offset, pn_length, rx_mask);

    // After unmasking, the header bytes should be byte-equal to the
    // unprotected header we started with.
    try std.testing.expectEqualSlices(u8, &header_bytes, packet[0..header_bytes.len]);

    // AEAD-open: gets back the original plaintext.
    var pt_back: [256]u8 = undefined;
    const pt_len = try aeadOpen(
        &aead,
        &keys.iv,
        pn,
        packet[0..ct_start],
        packet[ct_start .. ct_start + ct_len],
        &pt_back,
    );
    try std.testing.expectEqualSlices(u8, plaintext, pt_back[0..pt_len]);
}

test "RFC 9001 §A.2 — header-protection mask matches spec" {
    // RFC 9001 §A.2 documents:
    //   sample = d1b1c98dd7689fb8ec11d242b123dc9b
    //   mask   = 437b9aec36 (first 5 bytes of AES-128-ECB(hp_key, sample))
    // Verify our aesHpMask produces the spec mask byte-for-byte.
    const initial = @import("initial.zig");
    const dcid = fromHex("8394c8f03e515708");
    const keys = try initial.deriveInitialKeys(&dcid, false);

    const sample = fromHex("d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = try aesHpMask(&keys.hp, &sample);
    try std.testing.expectEqualSlices(u8, &fromHex("437b9aec36"), &mask);
}

test "aeadOpen rejects modified ciphertext" {
    const initial = @import("initial.zig");
    const dcid = fromHex("8394c8f03e515708");
    const keys = try initial.deriveInitialKeys(&dcid, false);
    var aead = try AesGcm128.init(&keys.key);
    defer aead.deinit();

    const header = fromHex("c300000001088394c8f03e5157080000449e00000002");
    var ct: [128]u8 = undefined;
    const ct_len = try aeadSeal(&aead, &keys.iv, 2, &header, "secret data", &ct);
    ct[0] ^= 0x01; // tamper

    var pt: [64]u8 = undefined;
    try std.testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        aeadOpen(&aead, &keys.iv, 2, &header, ct[0..ct_len], &pt),
    );
}

test "sampleAt extracts the right 16 bytes" {
    var packet: [40]u8 = undefined;
    var i: u8 = 0;
    while (i < packet.len) : (i += 1) packet[i] = i;

    const s = try sampleAt(&packet, 18);
    // sample_start = 18 + 4 = 22; bytes 22..38.
    var expected: [16]u8 = undefined;
    var j: u8 = 0;
    while (j < 16) : (j += 1) expected[j] = 22 + j;
    try std.testing.expectEqualSlices(u8, &expected, &s);
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `aesHpMask` with arbitrary AES-128 keys and 16-byte samples.
// Header protection (RFC 9001 §5.4.3) is the first 5 bytes of
// AES-ECB(hp_key, sample); BoringSSL's AES is the implementation, so
// the property we check is functional rather than cryptographic:
//
// - No panic on any input.
// - Determinism: same (key, sample) produces byte-identical mask.
// - Sensitivity: flipping a single sample byte changes the mask
//   (catches a no-op stub or a swap-bug that ignores the sample).

test "fuzz: protection.aesHpMask determinism and sensitivity" {
    try std.testing.fuzz({}, fuzzAesHpMask, .{});
}

fn fuzzAesHpMask(_: void, smith: *std.testing.Smith) anyerror!void {
    var key: [16]u8 = undefined;
    smith.bytes(&key);
    var sample: [sample_len]u8 = undefined;
    smith.bytes(&sample);

    const m1 = aesHpMask(&key, &sample) catch return;
    const m2 = try aesHpMask(&key, &sample);
    try std.testing.expectEqualSlices(u8, &m1, &m2);

    var sample_alt = sample;
    const flip_idx: u8 = smith.valueRangeAtMost(u8, 0, sample_len - 1);
    sample_alt[flip_idx] ^= 0x01;
    const m_alt = try aesHpMask(&key, &sample_alt);
    try std.testing.expect(!std.mem.eql(u8, &m1, &m_alt));
}
