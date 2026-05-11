//! Four-pass Feistel network operating over a `combined`-byte plaintext
//! block (draft-ietf-quic-load-balancers-21 §5.4.2).
//!
//! The Feistel structure is a length-preserving, round-keyed permutation:
//! plaintext and ciphertext are the same byte count (5..15 or 17..19 in
//! QUIC-LB; combined == 16 takes the §5.4.1 single-pass shortcut and is
//! NOT this module's territory). The round function is `AES-128-ECB`
//! over an `expand`-padded 16-byte block whose final two bytes carry the
//! plaintext length and the pass index, so each pass uses a structurally
//! distinct input even though the cipher key is identical.
//!
//! ## Algorithm (server-side encrypt)
//!
//! Per draft §5.4.2.3:
//!
//! 1. Concatenate `server_id || nonce` → `plaintext` (length
//!    `combined`). If `combined` is odd, clear the lower 4 bits of the
//!    last byte of `left_0` and the upper 4 bits of the first byte of
//!    `right_0` so the half-byte at the split boundary doesn't appear
//!    in both halves.
//! 2. Split into `left_0` and `right_0` of length `half_len = ceil(combined / 2)`.
//!    On odd lengths the two halves overlap by one byte at the split,
//!    with each half keeping only its own nibble of that byte.
//! 3-11. Four Feistel rounds:
//!      * Pass `n`: encrypt `expand(combined, n, side_(n-1))` with
//!        AES-128-ECB, XOR the first `half_len` bytes of the result
//!        into the *other* half. Re-clear the boundary nibble after
//!        every XOR for odd lengths.
//! 12. Concatenate `left_2 || right_2`; for odd lengths, fuse the
//!     boundary byte (left_2's high nibble + right_2's low nibble)
//!     so the final output is exactly `combined` bytes.
//!
//! ## Decrypt
//!
//! Decrypt runs the same four passes in reverse order, also using
//! AES-128-*encrypt* (Feistel only needs the round function to be
//! deterministic, never invertible). The embedder-facing server path
//! uses `encrypt`; `decrypt` is public so round-trip property tests and
//! operations tooling can recover the plaintext.

const std = @import("std");
const boringssl = @import("boringssl");

pub const Aes128 = boringssl.crypto.aes.Aes128;

pub const aes_block_size: usize = 16;
/// Maximum plaintext length the Feistel processes. Set by the QUIC-LB
/// combined-length cap (`server_id_len + nonce_len <= 19`).
pub const max_plaintext_len: usize = 19;
/// Maximum half length: `ceil(19 / 2) == 10`.
pub const max_half_len: usize = 10;

pub const Error = error{
    /// Plaintext length is outside the 5..19 range or equals 16
    /// (which is the single-pass §5.4.1 territory, not this module).
    /// `Factory` never feeds us those sizes — surfaces only when the
    /// module is called directly.
    InvalidPlaintextLen,
};

/// `expand(combined, pass, half) → 16 bytes`.
///
/// Layout per §5.4.2.2:
///
/// ```text
/// bytes 0..N        : input_bytes (the half just produced)
/// bytes N..14       : zero pad
/// byte  14          : combined plaintext length (5..19)
/// byte  15          : pass index (1..4)
/// ```
///
/// where `N = ceil(combined / 2) = half_len`. The length+pass tail
/// makes every pass's AES input distinct even under a fixed key.
pub fn expand(out: *[aes_block_size]u8, combined: u8, pass: u8, half: []const u8) void {
    @memset(out, 0);
    @memcpy(out[0..half.len], half);
    out[14] = combined;
    out[15] = pass;
}

/// Server-side four-pass Feistel encrypt. `plaintext.len ==
/// ciphertext.len == combined`, where `combined` is the configured
/// `server_id_len + nonce_len` and is NOT 16 (combined==16 selects
/// the §5.4.1 single-pass code path elsewhere).
pub fn encrypt(aes: *const Aes128, plaintext: []const u8, ciphertext: []u8) Error!void {
    try validateLen(plaintext.len);
    std.debug.assert(ciphertext.len == plaintext.len);

    const combined: u8 = @intCast(plaintext.len);
    const half_len: usize = (plaintext.len + 1) / 2;
    const odd: bool = (plaintext.len & 1) == 1;

    // `left_0` and `right_0` overlap by one byte when `combined` is
    // odd (the split byte). The clears restrict each half to its own
    // nibble of that byte so the Feistel round XORs don't recombine
    // them through the boundary.
    var left_0: [max_half_len]u8 = undefined;
    var right_0: [max_half_len]u8 = undefined;
    @memcpy(left_0[0..half_len], plaintext[0..half_len]);
    @memcpy(right_0[0..half_len], plaintext[plaintext.len - half_len ..]);
    if (odd) {
        left_0[half_len - 1] &= 0xf0;
        right_0[0] &= 0x0f;
    }

    var ex: [aes_block_size]u8 = undefined;
    var aes_out: [aes_block_size]u8 = undefined;

    // Pass 1: right_1 = right_0 XOR truncate(AES(expand(combined, 1, left_0)))
    expand(&ex, combined, 1, left_0[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var right_1: [max_half_len]u8 = undefined;
    xorInto(right_1[0..half_len], right_0[0..half_len], aes_out[0..half_len]);
    if (odd) right_1[0] &= 0x0f;

    // Pass 2: left_1 = left_0 XOR truncate(AES(expand(combined, 2, right_1)))
    expand(&ex, combined, 2, right_1[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var left_1: [max_half_len]u8 = undefined;
    xorInto(left_1[0..half_len], left_0[0..half_len], aes_out[0..half_len]);
    if (odd) left_1[half_len - 1] &= 0xf0;

    // Pass 3: right_2 = right_1 XOR truncate(AES(expand(combined, 3, left_1)))
    expand(&ex, combined, 3, left_1[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var right_2: [max_half_len]u8 = undefined;
    xorInto(right_2[0..half_len], right_1[0..half_len], aes_out[0..half_len]);
    if (odd) right_2[0] &= 0x0f;

    // Pass 4: left_2 = left_1 XOR truncate(AES(expand(combined, 4, right_2)))
    expand(&ex, combined, 4, right_2[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var left_2: [max_half_len]u8 = undefined;
    xorInto(left_2[0..half_len], left_1[0..half_len], aes_out[0..half_len]);
    if (odd) left_2[half_len - 1] &= 0xf0;

    // Step 12: assemble final ciphertext.
    // Even: simple concatenation.
    // Odd:  the last byte of `left_2` holds the high nibble (low
    //       nibble cleared); the first byte of `right_2` holds the low
    //       nibble (high nibble cleared); merge them via `or` into a
    //       single shared byte.
    if (odd) {
        @memcpy(ciphertext[0 .. half_len - 1], left_2[0 .. half_len - 1]);
        ciphertext[half_len - 1] = left_2[half_len - 1] | right_2[0];
        @memcpy(ciphertext[half_len..plaintext.len], right_2[1..half_len]);
    } else {
        @memcpy(ciphertext[0..half_len], left_2[0..half_len]);
        @memcpy(ciphertext[half_len..plaintext.len], right_2[0..half_len]);
    }
}

/// Inverse of `encrypt`. Same constraints on lengths. Test/ops
/// tooling — production server code never decrypts.
pub fn decrypt(aes: *const Aes128, ciphertext: []const u8, plaintext: []u8) Error!void {
    try validateLen(ciphertext.len);
    std.debug.assert(plaintext.len == ciphertext.len);

    const combined: u8 = @intCast(ciphertext.len);
    const half_len: usize = (ciphertext.len + 1) / 2;
    const odd: bool = (ciphertext.len & 1) == 1;

    // Recover (left_2, right_2) from the on-wire ciphertext, undoing
    // the boundary fusion if needed. The cleared nibbles re-appear as
    // zeros so the Feistel rounds see the same inputs as encrypt did
    // immediately after step 11.
    var left_2: [max_half_len]u8 = undefined;
    var right_2: [max_half_len]u8 = undefined;
    @memcpy(left_2[0..half_len], ciphertext[0..half_len]);
    @memcpy(right_2[0..half_len], ciphertext[ciphertext.len - half_len ..]);
    if (odd) {
        left_2[half_len - 1] &= 0xf0;
        right_2[0] &= 0x0f;
    }

    var ex: [aes_block_size]u8 = undefined;
    var aes_out: [aes_block_size]u8 = undefined;

    // Reverse pass 4: left_1 = left_2 XOR truncate(AES(expand(combined, 4, right_2)))
    expand(&ex, combined, 4, right_2[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var left_1: [max_half_len]u8 = undefined;
    xorInto(left_1[0..half_len], left_2[0..half_len], aes_out[0..half_len]);
    if (odd) left_1[half_len - 1] &= 0xf0;

    // Reverse pass 3: right_1 = right_2 XOR truncate(AES(expand(combined, 3, left_1)))
    expand(&ex, combined, 3, left_1[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var right_1: [max_half_len]u8 = undefined;
    xorInto(right_1[0..half_len], right_2[0..half_len], aes_out[0..half_len]);
    if (odd) right_1[0] &= 0x0f;

    // Reverse pass 2: left_0 = left_1 XOR truncate(AES(expand(combined, 2, right_1)))
    expand(&ex, combined, 2, right_1[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var left_0: [max_half_len]u8 = undefined;
    xorInto(left_0[0..half_len], left_1[0..half_len], aes_out[0..half_len]);
    if (odd) left_0[half_len - 1] &= 0xf0;

    // Reverse pass 1: right_0 = right_1 XOR truncate(AES(expand(combined, 1, left_0)))
    expand(&ex, combined, 1, left_0[0..half_len]);
    aes.encryptBlock(&ex, &aes_out);
    var right_0: [max_half_len]u8 = undefined;
    xorInto(right_0[0..half_len], right_1[0..half_len], aes_out[0..half_len]);
    if (odd) right_0[0] &= 0x0f;

    if (odd) {
        @memcpy(plaintext[0 .. half_len - 1], left_0[0 .. half_len - 1]);
        plaintext[half_len - 1] = left_0[half_len - 1] | right_0[0];
        @memcpy(plaintext[half_len..ciphertext.len], right_0[1..half_len]);
    } else {
        @memcpy(plaintext[0..half_len], left_0[0..half_len]);
        @memcpy(plaintext[half_len..ciphertext.len], right_0[0..half_len]);
    }
}

fn validateLen(len: usize) Error!void {
    if (len < 5 or len > max_plaintext_len or len == 16) return Error.InvalidPlaintextLen;
}

fn xorInto(dst: []u8, a: []const u8, b: []const u8) void {
    std.debug.assert(dst.len == a.len);
    std.debug.assert(dst.len == b.len);
    for (dst, a, b) |*d, av, bv| d.* = av ^ bv;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "expand: example from draft §5.4.2.2" {
    // Spec example: expand(0x06, 0x02, 0xaaba3c) =
    //   aaba3c00000000000000000000000602
    var out: [aes_block_size]u8 = undefined;
    const input = [_]u8{ 0xaa, 0xba, 0x3c };
    expand(&out, 0x06, 0x02, &input);
    const expected = fromHex("aaba3c00000000000000000000000602");
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "expand: ten-byte input fills 0..10, then 4 zeros, then length+pass" {
    var out: [aes_block_size]u8 = undefined;
    const input: [10]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    expand(&out, 19, 4, &input);
    var expected: [16]u8 = undefined;
    @memcpy(expected[0..10], &input);
    @memset(expected[10..14], 0);
    expected[14] = 19;
    expected[15] = 4;
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "encrypt: §5.4.2.4 worked example (3+4 server_id || nonce)" {
    // Per the draft's narrative example (combined=7, odd):
    //   server_id = 31441a
    //   nonce     = 9c69c275
    //   key       = fdf726a9893ec05c0632d3956680baf0
    //   on-wire   = 0767947d29be054a (8 bytes; first octet 0x07)
    // The ciphertext body is therefore 67947d29be054a (7 bytes).
    const key = fromHex("fdf726a9893ec05c0632d3956680baf0");
    const plaintext = fromHex("31441a9c69c275");
    const expected_ct = fromHex("67947d29be054a");

    const aes = try Aes128.init(&key);
    var ct: [7]u8 = undefined;
    try encrypt(&aes, &plaintext, &ct);
    try testing.expectEqualSlices(u8, &expected_ct, &ct);
}

test "decrypt: round-trips the §5.4.2.4 worked example" {
    const key = fromHex("fdf726a9893ec05c0632d3956680baf0");
    const plaintext = fromHex("31441a9c69c275");
    const aes = try Aes128.init(&key);

    var ct: [7]u8 = undefined;
    try encrypt(&aes, &plaintext, &ct);

    var pt2: [7]u8 = undefined;
    try decrypt(&aes, &ct, &pt2);
    try testing.expectEqualSlices(u8, &plaintext, &pt2);
}

test "encrypt + decrypt round-trip: every supported even length" {
    const key: [16]u8 = @splat(0x42);
    const aes = try Aes128.init(&key);

    var combined: usize = 6;
    while (combined <= 18) : (combined += 2) {
        if (combined == 16) continue; // single-pass territory
        var plaintext_buf: [max_plaintext_len]u8 = undefined;
        for (plaintext_buf[0..combined], 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xff);
        const plaintext = plaintext_buf[0..combined];

        var ct_buf: [max_plaintext_len]u8 = undefined;
        const ct = ct_buf[0..combined];
        try encrypt(&aes, plaintext, ct);
        try testing.expect(!std.mem.eql(u8, plaintext, ct));

        var pt_buf: [max_plaintext_len]u8 = undefined;
        const pt = pt_buf[0..combined];
        try decrypt(&aes, ct, pt);
        try testing.expectEqualSlices(u8, plaintext, pt);
    }
}

test "encrypt + decrypt round-trip: every supported odd length" {
    const key: [16]u8 = @splat(0x99);
    const aes = try Aes128.init(&key);

    var combined: usize = 5;
    while (combined <= 19) : (combined += 2) {
        var plaintext_buf: [max_plaintext_len]u8 = undefined;
        for (plaintext_buf[0..combined], 0..) |*b, i| b.* = @intCast((i * 11 + 5) & 0xff);
        const plaintext = plaintext_buf[0..combined];

        var ct_buf: [max_plaintext_len]u8 = undefined;
        const ct = ct_buf[0..combined];
        try encrypt(&aes, plaintext, ct);

        var pt_buf: [max_plaintext_len]u8 = undefined;
        const pt = pt_buf[0..combined];
        try decrypt(&aes, ct, pt);
        try testing.expectEqualSlices(u8, plaintext, pt);
    }
}

test "encrypt: rejects combined == 16 (single-pass territory)" {
    const key: [16]u8 = @splat(0xab);
    const aes = try Aes128.init(&key);
    const plaintext: [16]u8 = @splat(0);
    var ct: [16]u8 = undefined;
    try testing.expectError(Error.InvalidPlaintextLen, encrypt(&aes, &plaintext, &ct));
}

test "encrypt: rejects combined < 5 and > 19" {
    const key: [16]u8 = @splat(0xab);
    const aes = try Aes128.init(&key);
    var pt_short: [4]u8 = @splat(0);
    var ct_short: [4]u8 = undefined;
    try testing.expectError(Error.InvalidPlaintextLen, encrypt(&aes, &pt_short, &ct_short));
    var pt_long: [20]u8 = @splat(0);
    var ct_long: [20]u8 = undefined;
    try testing.expectError(Error.InvalidPlaintextLen, encrypt(&aes, &pt_long, &ct_long));
}
