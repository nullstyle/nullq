//! Packet-protection microbenchmark helpers.
//!
//! This module is intentionally standalone: bench/main.zig can import it
//! and choose which helpers to register. Fixtures are deterministic and
//! contexts own all reusable crypto/key state needed by hot loops.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");

const protection = quic_zig.wire.protection;
const initial = quic_zig.wire.initial;
const short_packet = quic_zig.wire.short_packet;
const long_packet = quic_zig.wire.long_packet;

const Aes128 = boringssl.crypto.aes.Aes128;
const AesGcm128 = boringssl.crypto.aead.AesGcm128;

pub const aead_plaintext_len: usize = 1200;
pub const aead_ciphertext_len: usize = aead_plaintext_len + AesGcm128.tag_len;
pub const packet_1rtt_payload_len: usize = 100;
pub const packet_1rtt_capacity: usize = 256;
pub const packet_initial_target_len: usize = 1200;
pub const packet_initial_capacity: usize = 2048;

const hp_sample_count: usize = 8;
const aead_pn_base: u64 = 0x1020_3040;
const packet_1rtt_pn_base: u64 = 0x2040_6080;
const packet_initial_pn_base: u64 = 0x3040_5060;

const rfc9001_dcid = fromHex("8394c8f03e515708");
const rfc9001_client_secret = fromHex(
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
);
const rfc9001_client_key = fromHex("1f369613dd76d5467730efcbe3b1a22d");
const rfc9001_client_iv = fromHex("fa044b2f42a3fd3b46fb255c");
const rfc9001_client_hp = fromHex("9f50449e04a0e810283a1e9933adedd2");
const aead_header = fromHex("c300000001088394c8f03e5157080000449e00000002");
const packet_dcid: [8]u8 = .{ 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22 };
const packet_scid: [4]u8 = .{ 0x34, 0x55, 0x89, 0xe5 };

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn fillPattern(dst: []u8, seed: u8) void {
    for (dst, 0..) |*b, i| {
        const lo: u8 = @intCast(i & 0xff);
        const hi: u8 = @intCast((i >> 8) & 0xff);
        b.* = seed +% (lo *% 31) +% (hi *% 17);
    }
}

fn foldBytes(bytes: []const u8) u64 {
    var acc: u64 = 0;
    for (bytes) |b| {
        acc = (acc << 5) ^ (acc >> 2) ^ b;
    }
    return acc;
}

fn packetKeysFromClientSecret() !short_packet.PacketKeys {
    return try short_packet.derivePacketKeys(.aes128_gcm_sha256, &rfc9001_client_secret);
}

fn initialPacketKeys() !short_packet.PacketKeys {
    const init_keys = try initial.deriveInitialKeys(&rfc9001_dcid, false);
    return try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
}

pub const HpMaskAes128CachedCtx = struct {
    aes: Aes128,
    samples: [hp_sample_count][protection.sample_len]u8,
};

pub fn initHpMaskAes128CachedCtx() !HpMaskAes128CachedCtx {
    var samples: [hp_sample_count][protection.sample_len]u8 = undefined;
    for (&samples, 0..) |*sample, i| {
        fillPattern(sample, @intCast(0x31 + i));
    }
    return .{
        .aes = try Aes128.init(&rfc9001_client_hp),
        .samples = samples,
    };
}

pub fn runHpMaskAes128Cached(ctx: *const HpMaskAes128CachedCtx, iters: u64) u64 {
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const sample_index: usize = @intCast(i & (hp_sample_count - 1));
        const mask = protection.aesHpMaskWithCtx(&ctx.aes, &ctx.samples[sample_index]);
        acc +%= foldBytes(&mask);
    }
    return acc;
}

pub const AeadAes128Seal1200bCtx = struct {
    aead: AesGcm128,
    iv: [12]u8,
    header: [aead_header.len]u8,
    plaintext: [aead_plaintext_len]u8,

    pub fn deinit(self: *AeadAes128Seal1200bCtx) void {
        self.aead.deinit();
    }
};

pub fn initAeadAes128Seal1200bCtx() !AeadAes128Seal1200bCtx {
    var plaintext: [aead_plaintext_len]u8 = undefined;
    fillPattern(&plaintext, 0x42);
    return .{
        .aead = try AesGcm128.init(&rfc9001_client_key),
        .iv = rfc9001_client_iv,
        .header = aead_header,
        .plaintext = plaintext,
    };
}

pub fn runAeadAes128Seal1200b(ctx: *const AeadAes128Seal1200bCtx, iters: u64) u64 {
    var ciphertext: [aead_ciphertext_len]u8 = undefined;
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const pn = aead_pn_base +% i;
        const len = protection.aeadSeal(
            &ctx.aead,
            &ctx.iv,
            pn,
            &ctx.header,
            &ctx.plaintext,
            &ciphertext,
        ) catch unreachable;
        acc +%= len;
        acc +%= ciphertext[@intCast(i & 0x0f)];
    }
    return acc;
}

pub const AeadAes128Open1200bCtx = struct {
    aead: AesGcm128,
    iv: [12]u8,
    pn: u64,
    header: [aead_header.len]u8,
    ciphertext: [aead_ciphertext_len]u8,

    pub fn deinit(self: *AeadAes128Open1200bCtx) void {
        self.aead.deinit();
    }
};

pub fn initAeadAes128Open1200bCtx() !AeadAes128Open1200bCtx {
    var plaintext: [aead_plaintext_len]u8 = undefined;
    fillPattern(&plaintext, 0x42);

    var aead = try AesGcm128.init(&rfc9001_client_key);
    errdefer aead.deinit();

    var ciphertext: [aead_ciphertext_len]u8 = undefined;
    const pn = aead_pn_base;
    const len = try protection.aeadSeal(
        &aead,
        &rfc9001_client_iv,
        pn,
        &aead_header,
        &plaintext,
        &ciphertext,
    );
    std.debug.assert(len == ciphertext.len);

    return .{
        .aead = aead,
        .iv = rfc9001_client_iv,
        .pn = pn,
        .header = aead_header,
        .ciphertext = ciphertext,
    };
}

pub fn runAeadAes128Open1200b(ctx: *const AeadAes128Open1200bCtx, iters: u64) u64 {
    var plaintext: [aead_plaintext_len]u8 = undefined;
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const len = protection.aeadOpen(
            &ctx.aead,
            &ctx.iv,
            ctx.pn,
            &ctx.header,
            &ctx.ciphertext,
            &plaintext,
        ) catch unreachable;
        acc +%= len;
        acc +%= plaintext[@intCast(i & 0x0f)];
    }
    return acc;
}

pub const Packet1RttSeal100bAes128Ctx = struct {
    keys: short_packet.PacketKeys,
    dcid: [packet_dcid.len]u8,
    payload: [packet_1rtt_payload_len]u8,
};

pub fn initPacket1RttSeal100bAes128Ctx() !Packet1RttSeal100bAes128Ctx {
    var payload: [packet_1rtt_payload_len]u8 = undefined;
    fillPattern(&payload, 0x53);
    return .{
        .keys = try packetKeysFromClientSecret(),
        .dcid = packet_dcid,
        .payload = payload,
    };
}

pub fn runPacket1RttSeal100bAes128(ctx: *const Packet1RttSeal100bAes128Ctx, iters: u64) u64 {
    var packet: [packet_1rtt_capacity]u8 = undefined;
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const len = short_packet.seal1Rtt(&packet, .{
            .dcid = &ctx.dcid,
            .pn = packet_1rtt_pn_base +% i,
            .largest_acked = null,
            .payload = &ctx.payload,
            .keys = &ctx.keys,
            .pn_length_override = 4,
        }) catch unreachable;
        acc +%= len;
        acc +%= packet[@intCast(i & 0x0f)];
    }
    return acc;
}

pub const Packet1RttOpen100bAes128Ctx = struct {
    keys: short_packet.PacketKeys,
    dcid_len: u8,
    pn: u64,
    packet: [packet_1rtt_capacity]u8,
    packet_len: usize,
};

pub fn initPacket1RttOpen100bAes128Ctx() !Packet1RttOpen100bAes128Ctx {
    const keys = try packetKeysFromClientSecret();
    var payload: [packet_1rtt_payload_len]u8 = undefined;
    fillPattern(&payload, 0x53);

    var packet: [packet_1rtt_capacity]u8 = undefined;
    const pn = packet_1rtt_pn_base;
    const packet_len = try short_packet.seal1Rtt(&packet, .{
        .dcid = &packet_dcid,
        .pn = pn,
        .largest_acked = null,
        .payload = &payload,
        .keys = &keys,
        .pn_length_override = 4,
    });

    return .{
        .keys = keys,
        .dcid_len = packet_dcid.len,
        .pn = pn,
        .packet = packet,
        .packet_len = packet_len,
    };
}

pub fn runPacket1RttOpen100bAes128(ctx: *const Packet1RttOpen100bAes128Ctx, iters: u64) u64 {
    var plaintext: [packet_1rtt_capacity]u8 = undefined;
    var packet = ctx.packet;
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const opened = short_packet.open1Rtt(&plaintext, packet[0..ctx.packet_len], .{
            .dcid_len = ctx.dcid_len,
            .keys = &ctx.keys,
            .largest_received = ctx.pn - 1,
        }) catch unreachable;
        acc +%= opened.pn;
        acc +%= opened.payload[@intCast(i % opened.payload.len)];
    }
    return acc;
}

pub const PacketInitialSeal1200bRfc9001Ctx = struct {
    keys: short_packet.PacketKeys,
    dcid: [rfc9001_dcid.len]u8,
    scid: [packet_scid.len]u8,
    payload: [packet_1rtt_payload_len]u8,
};

pub fn initPacketInitialSeal1200bRfc9001Ctx() !PacketInitialSeal1200bRfc9001Ctx {
    var payload: [packet_1rtt_payload_len]u8 = undefined;
    fillPattern(&payload, 0x64);
    return .{
        .keys = try initialPacketKeys(),
        .dcid = rfc9001_dcid,
        .scid = packet_scid,
        .payload = payload,
    };
}

pub fn runPacketInitialSeal1200bRfc9001(
    ctx: *const PacketInitialSeal1200bRfc9001Ctx,
    iters: u64,
) u64 {
    var packet: [packet_initial_capacity]u8 = undefined;
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const len = long_packet.sealInitial(&packet, .{
            .dcid = &ctx.dcid,
            .scid = &ctx.scid,
            .pn = packet_initial_pn_base +% i,
            .payload = &ctx.payload,
            .keys = &ctx.keys,
            .pad_to = packet_initial_target_len,
            .pn_length_override = 4,
        }) catch unreachable;
        acc +%= len;
        acc +%= packet[@intCast(i & 0x0f)];
    }
    return acc;
}

pub const PacketInitialOpen1200bRfc9001Ctx = struct {
    keys: short_packet.PacketKeys,
    pn: u64,
    pn_offset: usize,
    pn_len: u8,
    protected_first: u8,
    protected_pn: [4]u8,
    packet: [packet_initial_capacity]u8,
    packet_len: usize,

    fn restoreProtectedHeader(self: *PacketInitialOpen1200bRfc9001Ctx) void {
        self.packet[0] = self.protected_first;
        @memcpy(
            self.packet[self.pn_offset .. self.pn_offset + self.pn_len],
            self.protected_pn[0..self.pn_len],
        );
    }
};

pub fn initPacketInitialOpen1200bRfc9001Ctx() !PacketInitialOpen1200bRfc9001Ctx {
    const keys = try initialPacketKeys();
    var payload: [packet_1rtt_payload_len]u8 = undefined;
    fillPattern(&payload, 0x64);

    var packet: [packet_initial_capacity]u8 = undefined;
    const pn = packet_initial_pn_base;
    const packet_len = try long_packet.sealInitial(&packet, .{
        .dcid = &rfc9001_dcid,
        .scid = &packet_scid,
        .pn = pn,
        .payload = &payload,
        .keys = &keys,
        .pad_to = packet_initial_target_len,
        .pn_length_override = 4,
    });
    std.debug.assert(packet_len == packet_initial_target_len);

    const pn_len: u8 = 4;
    const pn_offset: usize = 1 + 4 + 1 + rfc9001_dcid.len + 1 + packet_scid.len + 1 + 2;
    var protected_pn: [4]u8 = @splat(0);
    @memcpy(protected_pn[0..pn_len], packet[pn_offset .. pn_offset + pn_len]);

    return .{
        .keys = keys,
        .pn = pn,
        .pn_offset = pn_offset,
        .pn_len = pn_len,
        .protected_first = packet[0],
        .protected_pn = protected_pn,
        .packet = packet,
        .packet_len = packet_len,
    };
}

/// `long_packet.openInitial` removes header protection in place. To avoid
/// copying 1200 bytes per iteration, this benchmark owns a mutable packet
/// buffer and restores the touched first byte plus PN bytes after each open.
pub fn runPacketInitialOpen1200bRfc9001(
    ctx: *PacketInitialOpen1200bRfc9001Ctx,
    iters: u64,
) u64 {
    var plaintext: [packet_initial_capacity]u8 = undefined;
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const opened = long_packet.openInitial(&plaintext, ctx.packet[0..ctx.packet_len], .{
            .keys = &ctx.keys,
            .largest_received = ctx.pn - 1,
        }) catch unreachable;
        acc +%= opened.pn;
        acc +%= opened.payload[@intCast(i % opened.payload.len)];
        ctx.restoreProtectedHeader();
    }
    return acc;
}

test "packet crypto benchmark fixtures run" {
    const hp = try initHpMaskAes128CachedCtx();
    try std.testing.expect(runHpMaskAes128Cached(&hp, 3) != 0);

    var seal_aead = try initAeadAes128Seal1200bCtx();
    defer seal_aead.deinit();
    try std.testing.expect(runAeadAes128Seal1200b(&seal_aead, 2) != 0);

    var open_aead = try initAeadAes128Open1200bCtx();
    defer open_aead.deinit();
    try std.testing.expect(runAeadAes128Open1200b(&open_aead, 2) != 0);

    const seal_1rtt = try initPacket1RttSeal100bAes128Ctx();
    try std.testing.expect(runPacket1RttSeal100bAes128(&seal_1rtt, 2) != 0);

    const open_1rtt = try initPacket1RttOpen100bAes128Ctx();
    try std.testing.expect(runPacket1RttOpen100bAes128(&open_1rtt, 2) != 0);

    const seal_initial = try initPacketInitialSeal1200bRfc9001Ctx();
    try std.testing.expect(runPacketInitialSeal1200bRfc9001(&seal_initial, 2) != 0);

    var open_initial = try initPacketInitialOpen1200bRfc9001Ctx();
    try std.testing.expect(runPacketInitialOpen1200bRfc9001(&open_initial, 2) != 0);
}
