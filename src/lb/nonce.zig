//! QUIC-LB nonce counter (draft-ietf-quic-load-balancers-21 §5.4 ¶3).
//!
//! Encrypted-mode QUIC-LB CIDs MUST never reuse a nonce under the same
//! key — the nonce is the only varying input to the ECB block, so a
//! repeat would produce a colliding CID and leak information across
//! peers. The recommended construction (§5.4 ¶3) is to start with a
//! random nonce and increment by one per mint:
//!
//!   > "If servers simply increment the nonce by one with each
//!   > generated connection ID, then it is safe to use the existing
//!   > keys until any server's nonce counter exhausts the allocated
//!   > space and rolls over."
//!
//! `NonceCounter` implements that exactly: `initRandom` seeds the
//! counter from BoringSSL's CSPRNG, `next` copies the current value
//! into the caller's buffer and increments. On wrap-around the
//! counter is marked exhausted; further `next` calls return
//! `error.NonceExhausted`. The embedder is then expected either to
//! rotate to a new configuration (LB-4) or to fall back to the
//! unroutable `0b111` CID (LB-5).
//!
//! The plaintext mode of §5.2 does **not** use this counter — that
//! mode draws every nonce directly from the CSPRNG so consecutive
//! nonces have "no observable correlation" (the draft's normative
//! requirement when no key is configured).

const std = @import("std");
const boringssl = @import("boringssl");

const config_mod = @import("config.zig");

pub const Error = error{
    /// Counter has wrapped past the maximum value representable in
    /// `nonce_len` octets. Reusing a nonce under the same key would
    /// break the encryption guarantees, so further `next` calls
    /// refuse to produce output.
    NonceExhausted,
    /// BoringSSL CSPRNG draw failed in `initRandom`.
    RandFailure,
};

/// Big-endian counter occupying the high `nonce_len` bytes of an
/// internal 18-byte buffer (the maximum permitted nonce length per
/// draft §3). Not internally synchronised — concurrent callers must
/// serialise externally, the same as `lb.Factory`.
pub const NonceCounter = struct {
    /// Live nonce length in octets (`min_nonce_len..max_nonce_len`).
    nonce_len: u8,
    /// Counter storage. Bytes `0..nonce_len` hold the current
    /// big-endian counter value; bytes past that are unused but kept
    /// in the struct so the caller can pass `bytes[0..nonce_len]` to
    /// `@memcpy`.
    bytes: [config_mod.max_nonce_len]u8 = @splat(0),
    /// Sticky exhaustion flag. Set the first time `next` increments
    /// the counter past its maximum representable value. Once true,
    /// every subsequent `next` returns `error.NonceExhausted`.
    exhausted: bool = false,

    /// Build a counter with a CSPRNG-drawn starting value. Per the
    /// draft "Servers SHOULD start with a random nonce to maximize
    /// entropy before exhaustion" — a counter that always started at
    /// zero would correlate the first CIDs minted across server
    /// restarts.
    pub fn initRandom(nonce_len: u8) Error!NonceCounter {
        var nc: NonceCounter = .{ .nonce_len = nonce_len };
        boringssl.crypto.rand.fillBytes(nc.bytes[0..nonce_len]) catch return Error.RandFailure;
        return nc;
    }

    /// Build a counter with a caller-supplied starting value. **Test
    /// fixtures and KATs only** — production code uses `initRandom`.
    /// Reusing a starting value across server restarts under the same
    /// key reuses nonces and breaks the encryption guarantees.
    pub fn initFromBytes(start: []const u8) NonceCounter {
        std.debug.assert(start.len >= config_mod.min_nonce_len);
        std.debug.assert(start.len <= config_mod.max_nonce_len);
        var nc: NonceCounter = .{ .nonce_len = @intCast(start.len) };
        @memcpy(nc.bytes[0..start.len], start);
        return nc;
    }

    /// Copy the current counter value into `out` (which must be
    /// exactly `nonce_len` bytes), then increment. Marks the counter
    /// `exhausted` if the increment wraps the top byte. Returns
    /// `error.NonceExhausted` if the counter was already exhausted
    /// going in.
    pub fn next(self: *NonceCounter, out: []u8) Error!void {
        if (self.exhausted) return Error.NonceExhausted;
        std.debug.assert(out.len == self.nonce_len);
        @memcpy(out, self.bytes[0..self.nonce_len]);

        // Big-endian counter increment with carry. Iterate from the
        // least-significant byte (last in the slice) to the most
        // significant; the first non-0xff byte stops the propagation.
        var carry: u1 = 1;
        var i: usize = self.nonce_len;
        while (i > 0 and carry == 1) {
            i -= 1;
            const sum: u9 = @as(u9, self.bytes[i]) + @as(u9, carry);
            self.bytes[i] = @truncate(sum);
            carry = if (sum > 0xff) 1 else 0;
        }
        if (carry == 1) self.exhausted = true;
    }

    /// Has the counter wrapped past its maximum representable value?
    /// Once true, never resets — the embedder must construct a fresh
    /// `NonceCounter` (typically as part of a configuration rotation
    /// in LB-4) to keep minting.
    pub fn isExhausted(self: *const NonceCounter) bool {
        return self.exhausted;
    }
};

// -- tests ---------------------------------------------------------------

const testing = std.testing;

test "initFromBytes seeds counter and reports the supplied length" {
    var nc = NonceCounter.initFromBytes(&.{ 0x00, 0x00, 0x00, 0x01 });
    try testing.expectEqual(@as(u8, 4), nc.nonce_len);
    try testing.expect(!nc.isExhausted());
}

test "next produces the seed value, then increments by one" {
    var nc = NonceCounter.initFromBytes(&.{ 0x00, 0x00, 0x00, 0x05 });
    var out: [4]u8 = undefined;
    try nc.next(&out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x05 }, &out);
    try nc.next(&out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x06 }, &out);
}

test "next propagates carry across bytes" {
    var nc = NonceCounter.initFromBytes(&.{ 0x00, 0x00, 0x00, 0xff });
    var out: [4]u8 = undefined;
    try nc.next(&out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0xff }, &out);
    try nc.next(&out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x01, 0x00 }, &out);
}

test "next marks exhausted on counter wrap" {
    var nc = NonceCounter.initFromBytes(&.{ 0xff, 0xff, 0xff, 0xff });
    var out: [4]u8 = undefined;
    try nc.next(&out);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff }, &out);
    try testing.expect(nc.isExhausted());
    try testing.expectError(Error.NonceExhausted, nc.next(&out));
}

test "initRandom seeds independent counters with high probability" {
    // Two CSPRNG-seeded counters of length 8 collide with probability
    // 2^-64; an empirical inequality is overwhelmingly likely.
    var a = try NonceCounter.initRandom(8);
    var b = try NonceCounter.initRandom(8);
    try testing.expect(!std.mem.eql(u8, a.bytes[0..8], b.bytes[0..8]));
}

test "initRandom output is the right length and not exhausted" {
    var nc = try NonceCounter.initRandom(12);
    try testing.expectEqual(@as(u8, 12), nc.nonce_len);
    try testing.expect(!nc.isExhausted());
    var out: [12]u8 = undefined;
    try nc.next(&out);
    // Counter advanced by one — the seed differs from the post-next
    // state with overwhelming probability over 12 random bytes.
    try testing.expect(!nc.isExhausted());
}
