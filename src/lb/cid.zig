//! QUIC-LB connection-ID minter (draft-ietf-quic-load-balancers-21 §5).
//!
//! `Factory` owns the runtime state needed to mint CIDs that an external
//! layer-4 load balancer can decode to recover the routing identity. The
//! immutable shape of one configuration lives in `config.zig`; this
//! module wires the configuration to the encoder dispatch and the
//! per-mint nonce path.
//!
//! ## Modes
//!
//! All three modes the draft defines are implemented:
//!
//!   * **§5.2 plaintext** (no key configured). `CID = first_octet ||
//!     server_id || nonce`, with the nonce drawn from the CSPRNG on
//!     every mint so consecutive CIDs have "no observable
//!     correlation".
//!   * **§5.4.1 single-pass AES-128-ECB** (key configured,
//!     `server_id_len + nonce_len == 16`). `CID = first_octet ||
//!     AES-ECB(key, server_id || nonce)`. Counter-based nonce, seeded
//!     from CSPRNG.
//!   * **§5.4.2 four-pass Feistel** (key configured, combined != 16).
//!     `CID = first_octet || feistel.encrypt(aes, server_id || nonce)`,
//!     where the Feistel network preserves length so the body has
//!     exactly the same byte count as the plaintext. Same nonce
//!     counter as single-pass.
//!
//! In every encrypted mode `Factory.deinit` `secureZero`s the
//! embedded key bytes and the nonce counter.
//!
//! ## First-octet layout (draft §3)
//!
//! ```text
//! bit  0  1  2  3  4  5  6  7
//!     [config_id ][   length-or-random   ]
//! ```
//!
//! The high 3 bits hold the active `config_id` (0..6; 7 is reserved
//! for the unroutable fallback). The low 5 bits either self-describe
//! the CID length as `cid_len - 1` (for short-header routing) or are
//! filled from the CSPRNG. The choice is per-configuration and
//! controlled by `LbConfig.encode_length`. The first octet is **never
//! encrypted** (§5.4.1) — encryption only covers the body.

const std = @import("std");
const boringssl = @import("boringssl");

const config_mod = @import("config.zig");
const nonce_mod = @import("nonce.zig");
const feistel_mod = @import("feistel.zig");

pub const LbConfig = config_mod.LbConfig;
pub const ServerId = config_mod.ServerId;
pub const ConfigId = config_mod.ConfigId;
pub const NonceCounter = nonce_mod.NonceCounter;

const Aes128 = boringssl.crypto.aes.Aes128;
const aes_block_size: usize = 16;

/// Errors `Factory.init` and `Factory.mint` can surface.
pub const Error = error{
    /// `LbConfig.validate` rejected the supplied configuration.
    InvalidLbConfig,
    /// `dst` slice was shorter than `cidLength()`.
    BufferTooSmall,
    /// BoringSSL CSPRNG draw failed. Surfaces the underlying
    /// `boringssl.crypto.rand.Error` so embedders can map it to their
    /// own logging.
    RandFailure,
    /// BoringSSL refused the AES-128 key during `Factory.init`.
    /// Surfaces `boringssl.crypto.aes.Error.AesKeyInvalid` — should
    /// never fire for a well-formed `[16]u8` but we propagate the
    /// failure rather than panic.
    AesKeyInvalid,
    /// The nonce counter has wrapped and would reuse a value if `mint`
    /// drew another nonce under the same key. The embedder must
    /// rotate to a new configuration (LB-4) or fall back to the
    /// unroutable `0b111` CID (LB-5). Encrypted modes only —
    /// plaintext mode never exhausts (every nonce comes from the
    /// CSPRNG, with no counter).
    NonceExhausted,
};

/// CID-generation algorithm selected by an `LbConfig`. The draft maps
/// key presence and combined server-id/nonce length to plaintext,
/// single-pass AES, or four-pass Feistel mode.
pub const Mode = enum {
    /// Draft §5.2: write `server_id || nonce` directly. Selected when
    /// `LbConfig.key` is null.
    plaintext,
    /// Draft §5.3: AES-128-ECB over the full plaintext block. Selected
    /// when `key != null` and `server_id_len + nonce_len == 16`.
    aes_single_pass,
    /// Draft §5.4: 4-round Feistel network with AES-128-ECB as the
    /// round function. Selected when `key != null` and
    /// `server_id_len + nonce_len != 16`.
    aes_four_pass,
};

/// Pick the encoding mode for `cfg`. Pure function of the configuration —
/// equivalent inputs always pick the same mode.
pub fn modeForConfig(cfg: *const LbConfig) Mode {
    if (cfg.key == null) return .plaintext;
    const combined: usize = @as(usize, cfg.server_id.len) + @as(usize, cfg.nonce_len);
    if (combined == 16) return .aes_single_pass;
    return .aes_four_pass;
}

/// Runtime CID minter for one `LbConfig`. The factory is owned by the
/// embedder (typically held inside `Server`). It is not internally
/// synchronised — concurrent callers must serialise externally.
///
/// Hold the factory by pointer (`*Factory`) so future LB-4 rotation
/// state (a draining configuration, a nonce counter) can mutate
/// in-place without breaking call sites. Encrypted-mode factories
/// hold key material — call `deinit` before letting the struct go
/// out of scope so the key bytes are zeroed.
pub const Factory = struct {
    cfg: LbConfig,
    /// AES-128 cipher state, populated only for keyed configurations.
    /// Held by value so the BoringSSL key schedule travels with the
    /// factory; no allocation involved.
    aes: ?Aes128 = null,
    /// Nonce counter, populated only for keyed configurations. Seeded
    /// from the CSPRNG at `init` time; advanced by one per mint.
    /// Plaintext mode draws nonces directly from the CSPRNG and never
    /// touches this counter.
    nonce_counter: ?NonceCounter = null,

    /// Build a factory after running `LbConfig.validate`. For keyed
    /// configurations the AES context and nonce counter are
    /// initialised here; on success the resulting `Factory` is ready
    /// for `mint`. Callers that already validated and want to skip the
    /// re-validation cost can call `initUnchecked`.
    pub fn init(cfg: LbConfig) Error!Factory {
        cfg.validate() catch return Error.InvalidLbConfig;
        return initUnchecked(cfg);
    }

    /// Trust-the-caller variant — the config field is copied verbatim
    /// without running `validate`. Used inside `Server.init` after the
    /// surrounding configuration sweep has already validated the field.
    /// Still initialises AES + nonce state for keyed configurations.
    pub fn initUnchecked(cfg: LbConfig) Error!Factory {
        var f: Factory = .{ .cfg = cfg };
        if (cfg.key) |key| {
            f.aes = Aes128.init(&key) catch return Error.AesKeyInvalid;
            errdefer if (f.aes) |*a| {
                _ = a;
                // BoringSSL's AES_KEY is opaque key-schedule state.
                // We can't `secureZero` through the wrapper, but on
                // this errdefer path we're about to drop the whole
                // `Factory` — the key bytes never escape.
            };
            f.nonce_counter = NonceCounter.initRandom(cfg.nonce_len) catch return Error.RandFailure;
        }
        return f;
    }

    /// Zero out key-derived state. Always safe to call; idempotent.
    /// `Server.deinit` chains into this before reclaiming the slot.
    pub fn deinit(self: *Factory) void {
        if (self.cfg.key) |*key| std.crypto.secureZero(u8, key[0..]);
        // Wipe the nonce counter buffer too so the high-water mark
        // doesn't linger in freed memory. Plaintext factories left
        // `nonce_counter` null; nothing to wipe.
        if (self.nonce_counter) |*nc| std.crypto.secureZero(u8, &nc.bytes);
        self.aes = null;
        self.nonce_counter = null;
    }

    /// Total CID byte count `mint` will write. Stable for the
    /// factory's lifetime; embedders use it to size their CID buffers.
    pub fn cidLength(self: *const Factory) u8 {
        return self.cfg.cidLength();
    }

    /// Encoding mode this factory dispatches to.
    pub fn mode(self: *const Factory) Mode {
        return modeForConfig(&self.cfg);
    }

    /// Mint a fresh CID into the front of `dst`. Returns the number of
    /// bytes written (always `cidLength()`). `dst` must have room.
    ///
    /// In plaintext mode, every nonce is drawn from the BoringSSL
    /// CSPRNG to honour the §5.2 "no observable correlation"
    /// requirement. In encrypted modes, the nonce comes from a counter
    /// (random start, increment by one) so the same nonce is never
    /// reused under the same key.
    pub fn mint(self: *Factory, dst: []u8) Error!usize {
        return switch (modeForConfig(&self.cfg)) {
            .plaintext => self.mintPlaintext(dst),
            .aes_single_pass => self.mintSinglePass(dst),
            .aes_four_pass => self.mintFourPass(dst),
        };
    }

    /// Mint a fresh CID using a caller-supplied nonce. **Test
    /// fixtures and KATs only** — production code uses `mint`, which
    /// pulls nonces from the CSPRNG (plaintext) or a unique-per-key
    /// counter (encrypted). Reusing a nonce under the same key
    /// breaks the encrypted-mode guarantees.
    ///
    /// `nonce.len` MUST equal `LbConfig.nonce_len`; the caller takes
    /// responsibility for that invariant. Returns `BufferTooSmall` if
    /// `dst` cannot fit `cidLength()` bytes.
    pub fn mintWithNonce(self: *Factory, dst: []u8, nonce: []const u8) Error!usize {
        std.debug.assert(nonce.len == self.cfg.nonce_len);
        return switch (modeForConfig(&self.cfg)) {
            .plaintext => self.assemblePlaintext(dst, nonce),
            .aes_single_pass => self.assembleSinglePass(dst, nonce),
            .aes_four_pass => self.assembleFourPass(dst, nonce),
        };
    }

    fn mintPlaintext(self: *Factory, dst: []u8) Error!usize {
        var nonce_buf: [config_mod.max_nonce_len]u8 = undefined;
        const nonce = nonce_buf[0..self.cfg.nonce_len];
        boringssl.crypto.rand.fillBytes(nonce) catch return Error.RandFailure;
        return self.assemblePlaintext(dst, nonce);
    }

    fn mintSinglePass(self: *Factory, dst: []u8) Error!usize {
        var nonce_buf: [config_mod.max_nonce_len]u8 = undefined;
        const nonce = nonce_buf[0..self.cfg.nonce_len];
        // `nonce_counter` is non-null whenever `aes` is — both are
        // populated together in `initUnchecked` for keyed configs.
        try self.nonce_counter.?.next(nonce);
        return self.assembleSinglePass(dst, nonce);
    }

    fn mintFourPass(self: *Factory, dst: []u8) Error!usize {
        var nonce_buf: [config_mod.max_nonce_len]u8 = undefined;
        const nonce = nonce_buf[0..self.cfg.nonce_len];
        try self.nonce_counter.?.next(nonce);
        return self.assembleFourPass(dst, nonce);
    }

    fn assemblePlaintext(self: *Factory, dst: []u8, nonce: []const u8) Error!usize {
        const len: usize = self.cfg.cidLength();
        if (dst.len < len) return Error.BufferTooSmall;

        dst[0] = try self.composeFirstOctet();
        const sid = self.cfg.server_id.slice();
        @memcpy(dst[1 .. 1 + sid.len], sid);
        @memcpy(dst[1 + sid.len .. 1 + sid.len + nonce.len], nonce);
        return len;
    }

    fn assembleSinglePass(self: *Factory, dst: []u8, nonce: []const u8) Error!usize {
        const len: usize = self.cfg.cidLength();
        if (dst.len < len) return Error.BufferTooSmall;
        std.debug.assert(len == 1 + aes_block_size);

        // First octet: written in the clear, never encrypted (§5.4.1).
        dst[0] = try self.composeFirstOctet();

        // Plaintext block: server_id || nonce (combined == 16 octets
        // by the §5.4.1 selector).
        var plaintext: [aes_block_size]u8 = undefined;
        const sid = self.cfg.server_id.slice();
        @memcpy(plaintext[0..sid.len], sid);
        @memcpy(plaintext[sid.len .. sid.len + nonce.len], nonce);

        // Single-block AES-128-ECB. Result lands directly in the CID
        // body — no further mixing.
        var ciphertext: [aes_block_size]u8 = undefined;
        self.aes.?.encryptBlock(&plaintext, &ciphertext);
        @memcpy(dst[1 .. 1 + aes_block_size], &ciphertext);
        return len;
    }

    fn assembleFourPass(self: *Factory, dst: []u8, nonce: []const u8) Error!usize {
        const len: usize = self.cfg.cidLength();
        if (dst.len < len) return Error.BufferTooSmall;

        // First octet: identical handling to plaintext / single-pass.
        // §5.4.2 keeps the first octet outside the Feistel input.
        dst[0] = try self.composeFirstOctet();

        // Build plaintext = server_id || nonce (length-preserving
        // through the Feistel; ciphertext sits in the body slot).
        var plaintext: [config_mod.max_combined_len]u8 = undefined;
        const sid = self.cfg.server_id.slice();
        const combined: usize = sid.len + nonce.len;
        @memcpy(plaintext[0..sid.len], sid);
        @memcpy(plaintext[sid.len..combined], nonce);

        // The Feistel preserves length, so `dst[1..len]` is exactly
        // `combined` bytes. `feistel.encrypt` requires `combined` to
        // be 5..19 with `combined != 16`; `LbConfig.validate` plus the
        // `modeForConfig` dispatch already guarantee that.
        feistel_mod.encrypt(
            &self.aes.?,
            plaintext[0..combined],
            dst[1..len],
        ) catch |err| switch (err) {
            error.InvalidPlaintextLen => unreachable,
        };
        return len;
    }

    /// Build the first octet: config_id in the high 3 bits, then
    /// either `cid_len - 1` or random in the low 5 bits. Shared
    /// between plaintext and encrypted modes — §5.4.1 explicitly
    /// keeps the first octet unencrypted, so the same composition
    /// applies to both.
    fn composeFirstOctet(self: *Factory) Error!u8 {
        const len: usize = self.cfg.cidLength();
        const config_bits: u8 = (@as(u8, self.cfg.config_id) & 0x07) << 5;
        const length_bits: u8 = blk: {
            if (self.cfg.encode_length) {
                break :blk @as(u8, @intCast(len - 1)) & 0x1F;
            } else {
                var rb: [1]u8 = undefined;
                boringssl.crypto.rand.fillBytes(&rb) catch return Error.RandFailure;
                break :blk rb[0] & 0x1F;
            }
        };
        return config_bits | length_bits;
    }
};

// -- helpers (used by tests + future LB phases) --------------------------

/// Extract the `config_id` (high 3 bits) of a minted CID's first
/// octet. Useful for both round-trip tests and LB-side decode helpers.
pub fn firstOctetConfigId(first_octet: u8) u8 {
    return (first_octet >> 5) & 0x07;
}

/// Extract the low 5 bits of a minted CID's first octet. When the
/// configuration encodes length, this is `cid_len - 1`; otherwise
/// it's pseudo-random.
pub fn firstOctetLengthBits(first_octet: u8) u8 {
    return first_octet & 0x1F;
}

/// Minimum total CID length for an unroutable CID per draft §3.1:
/// "Servers SHOULD ... [have] at least seven octets of randomness …
/// [in addition to] the first octet". 1 first octet + 7 entropy = 8.
pub const min_unroutable_cid_len: u8 = 8;

/// Mint an unroutable CID per draft §3.1. Used when no QUIC-LB
/// configuration is currently active (e.g. during a configuration
/// rotation gap, or after the active config's nonce counter
/// exhausts). The first octet's high 3 bits are
/// `config_mod.unroutable_config_id` (0b111), the low 5 bits hold
/// `cid_len - 1` so peers and LBs see a self-described length, and
/// the body is filled from the CSPRNG so different connections never
/// collide.
///
/// `len` is the total CID byte count, 8..20 inclusive. Smaller
/// rejects with `InvalidLbConfig`; larger rejects too because QUIC v1
/// caps CIDs at 20 octets.
///
/// This is a free function on purpose — no `Factory` state is read,
/// so embedders can mint unroutable CIDs without holding an active
/// `LbConfig`.
pub fn mintUnroutable(dst: []u8, len: u8) Error!usize {
    if (len < min_unroutable_cid_len or len > 20) return Error.InvalidLbConfig;
    if (dst.len < len) return Error.BufferTooSmall;

    // First octet: config_id = 0b111, length self-encoded into the
    // low 5 bits. `len - 1` is at most 19; fits.
    const config_bits: u8 = (config_mod.unroutable_config_id & 0x07) << 5;
    const length_bits: u8 = @as(u8, @intCast(len - 1)) & 0x1F;
    dst[0] = config_bits | length_bits;

    // Remaining bytes: pure CSPRNG. The first octet already
    // signals "unroutable" so there's no further structure for
    // the LB to recover.
    boringssl.crypto.rand.fillBytes(dst[1..len]) catch return Error.RandFailure;
    return len;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn buildPlaintextConfig(config_id: ConfigId, server_id: []const u8, nonce_len: u8) !LbConfig {
    return .{
        .config_id = config_id,
        .server_id = try ServerId.fromSlice(server_id),
        .nonce_len = nonce_len,
    };
}

test "modeForConfig: null key selects plaintext" {
    const cfg = try buildPlaintextConfig(0, &.{ 1, 2, 3 }, 5);
    try testing.expectEqual(Mode.plaintext, modeForConfig(&cfg));
}

test "modeForConfig: keyed config with combined==16 selects single-pass" {
    var cfg = try buildPlaintextConfig(0, &.{ 1, 2, 3, 4 }, 12);
    cfg.key = @splat(0x42);
    try testing.expectEqual(Mode.aes_single_pass, modeForConfig(&cfg));
}

test "modeForConfig: keyed config with combined!=16 selects four-pass" {
    var cfg = try buildPlaintextConfig(0, &.{ 1, 2, 3, 4 }, 8);
    cfg.key = @splat(0x42);
    try testing.expectEqual(Mode.aes_four_pass, modeForConfig(&cfg));
}

test "Factory.init runs LbConfig.validate" {
    var bad = try buildPlaintextConfig(0, &.{0xaa}, 4);
    bad.config_id = 0b111;
    try testing.expectError(Error.InvalidLbConfig, Factory.init(bad));
}

test "plaintext mint: first octet encodes config_id and length" {
    var f = try Factory.init(try buildPlaintextConfig(5, &.{ 0xa, 0xb, 0xc }, 6));
    var cid: [32]u8 = undefined;
    const n = try f.mint(&cid);
    try testing.expectEqual(@as(usize, 1 + 3 + 6), n);

    // High 3 bits = config_id (5 = 0b101).
    try testing.expectEqual(@as(u8, 5), firstOctetConfigId(cid[0]));
    // Low 5 bits = cid_len - 1 = 9 (because encode_length defaults true).
    try testing.expectEqual(@as(u8, 9), firstOctetLengthBits(cid[0]));
}

test "plaintext mint: server_id is copied verbatim into body" {
    const sid_bytes: []const u8 = &.{ 0xde, 0xad, 0xbe, 0xef };
    var f = try Factory.init(try buildPlaintextConfig(2, sid_bytes, 5));
    var cid: [32]u8 = undefined;
    _ = try f.mint(&cid);
    try testing.expectEqualSlices(u8, sid_bytes, cid[1 .. 1 + sid_bytes.len]);
}

test "plaintext mint: each call draws a fresh nonce" {
    var f = try Factory.init(try buildPlaintextConfig(1, &.{ 0xab, 0xcd }, 8));
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    const an = try f.mint(&a);
    const bn = try f.mint(&b);
    try testing.expectEqual(an, bn);
    // Server-id portion is identical; nonce portion must differ with
    // overwhelming probability (8 random bytes — collision odds 2^-64).
    try testing.expectEqualSlices(u8, a[1..3], b[1..3]);
    try testing.expect(!std.mem.eql(u8, a[3..an], b[3..bn]));
}

test "plaintext mint: encode_length=false fills low 5 bits without (len-1)" {
    var cfg = try buildPlaintextConfig(0, &.{0xaa}, 4);
    cfg.encode_length = false;
    var f = try Factory.init(cfg);

    // Draw enough samples that "always equals (len-1)" would be a
    // statistical near-certainty (32^32 ≈ 2^160). Even 16 samples
    // diverging from a single fixed value is overwhelmingly likely
    // when the source is a CSPRNG.
    var saw_non_len_minus_one = false;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var cid: [32]u8 = undefined;
        _ = try f.mint(&cid);
        // Config id must always be 0.
        try testing.expectEqual(@as(u8, 0), firstOctetConfigId(cid[0]));
        if (firstOctetLengthBits(cid[0]) != f.cidLength() - 1) {
            saw_non_len_minus_one = true;
        }
    }
    try testing.expect(saw_non_len_minus_one);
}

test "mint: four-pass (encrypted, combined != 16) succeeds and produces a length-preserving body" {
    var cfg = try buildPlaintextConfig(0, &.{ 1, 2, 3, 4 }, 8);
    cfg.key = @splat(0x42);
    var f = try Factory.init(cfg);
    defer f.deinit();
    try testing.expectEqual(Mode.aes_four_pass, f.mode());

    var cid: [32]u8 = undefined;
    const n = try f.mint(&cid);
    // Combined = 4 + 8 = 12; CID length = 1 + 12 = 13.
    try testing.expectEqual(@as(usize, 13), n);
}

test "mint: single-pass (encrypted, combined == 16) succeeds and produces 17-byte CID" {
    var cfg = try buildPlaintextConfig(0, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, 8);
    cfg.key = @splat(0x42);
    var f = try Factory.init(cfg);
    defer f.deinit();
    try testing.expectEqual(Mode.aes_single_pass, f.mode());

    var cid: [32]u8 = undefined;
    const n = try f.mint(&cid);
    try testing.expectEqual(@as(usize, 17), n);
}

test "mint: BufferTooSmall when dst is shorter than cidLength()" {
    var f = try Factory.init(try buildPlaintextConfig(0, &.{ 1, 2 }, 6));
    var dst: [3]u8 = undefined;
    try testing.expectError(Error.BufferTooSmall, f.mint(&dst));
}

test "mintUnroutable: first octet has config_id 0b111 and length self-encoded" {
    var dst: [16]u8 = undefined;
    const n = try mintUnroutable(&dst, 12);
    try testing.expectEqual(@as(usize, 12), n);
    try testing.expectEqual(@as(u8, 0b111), firstOctetConfigId(dst[0]));
    try testing.expectEqual(@as(u8, 11), firstOctetLengthBits(dst[0]));
}

test "mintUnroutable: rejects len < 8 and len > 20" {
    var dst: [32]u8 = undefined;
    try testing.expectError(Error.InvalidLbConfig, mintUnroutable(&dst, 7));
    try testing.expectError(Error.InvalidLbConfig, mintUnroutable(&dst, 21));
}

test "mintUnroutable: rejects too-small dst" {
    var dst: [4]u8 = undefined;
    try testing.expectError(Error.BufferTooSmall, mintUnroutable(&dst, 8));
}

test "mintUnroutable: two consecutive mints produce uncorrelated bodies" {
    var a: [12]u8 = undefined;
    var b: [12]u8 = undefined;
    _ = try mintUnroutable(&a, 12);
    _ = try mintUnroutable(&b, 12);
    // First octets identical (both encode same config_id + length).
    try testing.expectEqual(a[0], b[0]);
    // Bodies differ with overwhelming probability over 11 random bytes.
    try testing.expect(!std.mem.eql(u8, a[1..], b[1..]));
}

test "first-octet KAT: config_id 0..6 with encode_length=true" {
    // For each valid config_id, the high 3 bits of the first octet
    // must read back unchanged via firstOctetConfigId.
    var i: u8 = 0;
    while (i <= 6) : (i += 1) {
        const cfg: LbConfig = .{
            .config_id = @intCast(i),
            .server_id = try ServerId.fromSlice(&.{ 0xaa, 0xbb }),
            .nonce_len = 4,
        };
        var f = try Factory.init(cfg);
        var cid: [32]u8 = undefined;
        const n = try f.mint(&cid);
        try testing.expectEqual(@as(u8, i), firstOctetConfigId(cid[0]));
        // Length encoding round-trips: low 5 bits = n - 1.
        try testing.expectEqual(@as(u8, @intCast(n - 1)), firstOctetLengthBits(cid[0]));
    }
}
