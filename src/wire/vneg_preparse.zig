//! RFC 9368 §5/§6 server-side pre-parse helpers for compatible-version
//! negotiation upgrade.
//!
//! When a server is configured with multiple wire versions (e.g.
//! `versions = [v2, v1]`), it can choose to upgrade an incoming wire-
//! version-v1 ClientHello to v2 if the client advertises v2 in its
//! `version_information` transport parameter (RFC 9368 §5). The
//! decision MUST be made before BoringSSL produces the EE message,
//! because §5 requires the EE's `chosen_version` to match the version
//! of the packet carrying it (and the EE's transport_parameters embed
//! the server's chosen_version).
//!
//! That means the server has to:
//!   1. Decrypt the client's Initial under wire-version keys.
//!   2. Reassemble the ClientHello from the decrypted CRYPTO frames
//!      (single-Initial only; fragmented ClientHellos fall back to
//!      "no upgrade" — spec-compliant via §6 graceful degradation).
//!   3. Walk the ClientHello extensions to find
//!      `quic_transport_parameters` (codepoint 0x39).
//!   4. Decode the `version_information` (codepoint 0x11) entry from
//!      that blob and intersect with the server's preference list.
//!
//! This module owns steps 2-4. Step 1 stays in the server (it already
//! decrypts the Initial via `long_packet.openInitial`); step 5 — the
//! actual `setVersion` + outbound transport-params rebuild — happens
//! in `Server.openSlotFromInitial` because it has the Connection
//! handle and the configured `Server.versions` list.
//!
//! Defensive posture: every parser here returns `null` on malformed or
//! unexpected input rather than erroring. The server treats a `null`
//! result as "no upgrade — use the wire version", which is always
//! spec-compliant. We never reject a connection because pre-parse
//! failed.

const std = @import("std");
const varint = @import("varint.zig");
const frame_decode = @import("../frame/decode.zig");
const transport_params = @import("../tls/transport_params.zig");

/// TLS Handshake message type for ClientHello (RFC 8446 §4).
const tls_msg_type_client_hello: u8 = 0x01;

/// TLS extension codepoint for `quic_transport_parameters`
/// (RFC 9001 §8.2). Both endpoints use this on wire under the modern
/// codepoint; some legacy stacks used `0xffa5` — accept both for the
/// pre-parse since this is purely advisory and the upgrade-decision
/// path falls back gracefully on failure.
const tls_ext_quic_transport_params: u16 = 0x0039;
const tls_ext_quic_transport_params_legacy: u16 = 0xffa5;

/// Maximum cumulative ClientHello bytes we are willing to assemble
/// from CRYPTO frames in a single Initial. The pre-parse only needs
/// to look at the first ClientHello bytes; this cap keeps the
/// reassembly fixed-stack with no allocator.
pub const max_client_hello_bytes: usize = 4096;

/// Maximum number of versions we extract from the client's
/// `version_information` transport parameter. Mirrors
/// `transport_params.max_compatible_versions`.
pub const max_versions: usize = 16;

/// Result of a successful version_information decode.
pub const ClientVersionInfo = struct {
    /// Number of valid entries in `buf`. The first entry is the
    /// client's chosen version (the one its outer Initial is sent
    /// under); the remainder are the compatibility set in client
    /// preference order.
    count: u8,
    buf: [max_versions]u32,

    /// Borrowed view of the active entries.
    pub fn slice(self: *const ClientVersionInfo) []const u32 {
        return self.buf[0..self.count];
    }

    /// The client's `available_versions` per RFC 9368 §5: every
    /// entry from the wire blob (chosen + remaining), since the
    /// client implicitly considers its own chosen version available.
    /// This is what the server's intersection logic walks.
    pub fn available(self: *const ClientVersionInfo) []const u32 {
        return self.buf[0..self.count];
    }
};

/// Reassemble the ClientHello bytes from a decrypted Initial payload.
/// Walks the frame stream looking for CRYPTO frames; collects them by
/// offset; returns the contiguous slice covering `[0, total_len)`.
///
/// Single-Initial ClientHellos are the overwhelming common case (and
/// the hard requirement here). When the ClientHello is fragmented
/// across multiple Initials — or when the frame stream is malformed,
/// has overlapping fragments, or starts with a gap at offset > 0 —
/// the function returns `null`. The caller treats `null` as "skip the
/// upgrade and continue with the wire version", which is spec-
/// compliant via §6's graceful-fallback clause.
///
/// `dst` must be at least `max_client_hello_bytes` long. The returned
/// slice borrows into `dst`.
pub fn reassembleClientHello(dst: []u8, payload: []const u8) ?[]const u8 {
    if (dst.len < max_client_hello_bytes) return null;

    // Track which bytes of the prefix have been written. We only care
    // about the contiguous prefix starting at offset 0; once the
    // contiguous frontier covers enough bytes to hold the declared
    // ClientHello length, we return that prefix.
    var contig_end: usize = 0;
    var have_first_frame = false;
    var declared_len: ?usize = null;

    var pos: usize = 0;
    while (pos < payload.len) {
        const decoded = frame_decode.decode(payload[pos..]) catch return null;
        pos += decoded.bytes_consumed;
        switch (decoded.frame) {
            .crypto => |cr| {
                const off: u64 = cr.offset;
                const data = cr.data;
                if (data.len == 0) continue;
                // Bound check: refuse to grow beyond `dst`.
                const end_off = std.math.add(u64, off, @intCast(data.len)) catch return null;
                if (end_off > @as(u64, dst.len)) return null;
                const off_usize: usize = @intCast(off);
                @memcpy(dst[off_usize .. off_usize + data.len], data);
                if (off == 0) have_first_frame = true;
                // Advance the contiguous frontier.
                if (off <= contig_end and end_off > contig_end) {
                    contig_end = @intCast(end_off);
                }
                // Once we have enough bytes to read the TLS Handshake
                // length prefix, lock in the declared length.
                if (declared_len == null and have_first_frame and contig_end >= 4) {
                    if (dst[0] != tls_msg_type_client_hello) return null;
                    const u24_len = (@as(usize, dst[1]) << 16) |
                        (@as(usize, dst[2]) << 8) |
                        @as(usize, dst[3]);
                    const total = u24_len + 4;
                    if (total > dst.len) return null;
                    declared_len = total;
                }
            },
            // Initials carry CRYPTO + ACK + PING + PADDING. Any of
            // those are fine to skip.
            .padding, .ping, .ack, .path_ack => {},
            // Any other frame type in an Initial is a peer protocol
            // violation; the proper handler will catch it. We just
            // bail out of the pre-parse so the upgrade falls back.
            else => return null,
        }
    }

    if (!have_first_frame) return null;
    const want = declared_len orelse return null;
    if (contig_end < want) return null;
    return dst[0..want];
}

/// Streaming offset-based ClientHello reassembler.
///
/// Multi-Initial fragmented ClientHellos (RFC 9000 §17.2.2 / TLS 1.3
/// CH up to 16 KiB-ish) are split across two or more client Initial
/// packets, each carrying its own slice of CRYPTO frames at distinct
/// offsets. The single-shot `reassembleClientHello` only sees one
/// Initial at a time and bails when offset 0 is missing or the
/// declared CH length isn't covered. To still drive the RFC 9368 §6
/// upgrade decision under that pattern, the server feeds each
/// Initial's decrypted plaintext through a `ChReassembler`; once the
/// CH is contiguous from offset 0 to its declared length the
/// reassembler returns the assembled slice.
///
/// Defensive posture: any malformed input (oversize CH, unexpected
/// non-CRYPTO frame, conflicting overlapping data) returns
/// `error.Invalid` from `feed`, and the caller treats it the same as
/// "skip the upgrade and use the wire version". The reassembler
/// itself never panics and never allocates.
///
/// Capacity:
///   - `dst` is the caller-owned backing storage for the assembled
///     CH. Must be at least `max_client_hello_bytes` long. The
///     returned slice on `feed` borrows into `dst` and is valid until
///     the next `reset` or until `dst` itself is reused.
///   - At most `max_segments` non-contiguous segments are tracked in
///     parallel. Real CHs hardly ever fragment beyond two segments;
///     16 is a generous cap that still bounds the memory footprint.
pub const ChReassembler = struct {
    /// Maximum number of non-contiguous segments retained while
    /// waiting for the gaps to fill. A typical 2-Initial CH produces
    /// 1–2 segments; the cap is per-CID so a cap of 16 absorbs
    /// pathological reordering without unbounded growth.
    pub const max_segments: usize = 16;

    const Segment = struct {
        offset: usize,
        end: usize, // exclusive
    };

    pub const Error = error{
        /// Caller-supplied buffer is too small or the CH overflows it.
        Overflow,
        /// Frame stream is malformed, conflicts with previously-seen
        /// bytes, or contains a frame type that doesn't belong in an
        /// Initial (RFC 9000 §17.2.2).
        Invalid,
    };

    dst: []u8,
    /// Highest contiguous offset reached starting from 0. The CH is
    /// complete when `contig_end >= declared_len`.
    contig_end: usize = 0,
    /// Declared CH length (TLS Handshake header value + 4 prefix
    /// bytes), or null until at least the first 4 bytes have arrived.
    declared_len: ?usize = null,
    /// Sorted, disjoint list of byte ranges already received. Always
    /// merged on insert so that consecutive entries have a gap
    /// between them (i.e. `segs[i].end < segs[i+1].offset`). The
    /// segment that includes offset 0 always sits at index 0 if any
    /// range starting at 0 has been seen.
    segs: [max_segments]Segment = @splat(.{ .offset = 0, .end = 0 }),
    seg_count: u8 = 0,

    /// Construct an empty reassembler that writes into the
    /// caller-owned `dst`. `dst.len >= max_client_hello_bytes` is
    /// required; smaller buffers degrade to `error.Overflow` on the
    /// first frame.
    pub fn init(dst: []u8) ChReassembler {
        return .{ .dst = dst };
    }

    /// Reset to the empty state. The backing buffer is *not* zeroed —
    /// every byte returned by `feed` corresponds to a CRYPTO offset
    /// the caller observed, so leftover bytes from a prior
    /// reassembly that the new CH does not overwrite stay invisible
    /// behind `contig_end`.
    pub fn reset(self: *ChReassembler) void {
        self.contig_end = 0;
        self.declared_len = null;
        self.seg_count = 0;
    }

    /// True once the assembled CH covers `[0, declared_len)`.
    /// Idempotent — additional `feed` calls after completion are
    /// allowed (e.g. retransmitted CRYPTO frames) and continue to
    /// return the same slice.
    pub fn isComplete(self: *const ChReassembler) bool {
        const want = self.declared_len orelse return false;
        return self.contig_end >= want;
    }

    /// Feed one Initial's decrypted plaintext. Walks the frame stream
    /// for CRYPTO frames, records each fragment in the reassembler's
    /// segment list, and returns the assembled CH the moment the
    /// contiguous prefix covers the declared length.
    ///
    /// Returns:
    ///   - `null` while waiting for more bytes (gap not yet filled,
    ///     or declared length not yet covered).
    ///   - `error.Overflow` when a CRYPTO offset/length would write
    ///     past `dst`.
    ///   - `error.Invalid` for a malformed frame stream, an overlap
    ///     that conflicts with previously-seen bytes, or a non-PADDING
    ///     non-PING non-ACK frame other than CRYPTO. Callers should
    ///     treat this identically to `null` for upgrade purposes —
    ///     fall back to the wire version — but propagate distinctly so
    ///     the caller can stop feeding (the stream is broken).
    pub fn feed(self: *ChReassembler, payload: []const u8) Error!?[]const u8 {
        if (self.dst.len < max_client_hello_bytes) return Error.Overflow;
        var pos: usize = 0;
        while (pos < payload.len) {
            const decoded = frame_decode.decode(payload[pos..]) catch return Error.Invalid;
            pos += decoded.bytes_consumed;
            switch (decoded.frame) {
                .crypto => |cr| {
                    if (cr.data.len == 0) continue;
                    const off64: u64 = cr.offset;
                    const end64 = std.math.add(u64, off64, @intCast(cr.data.len)) catch return Error.Overflow;
                    if (end64 > @as(u64, self.dst.len)) return Error.Overflow;
                    const off: usize = @intCast(off64);
                    const end: usize = @intCast(end64);

                    // Conflict check on any overlap with already-stored
                    // bytes — segments hold the bytes we're confident
                    // about, and a CRYPTO retransmission should match
                    // the original. A peer that contradicts itself is
                    // either malicious or buggy; either way we skip the
                    // upgrade.
                    if (overlapsAndDiffers(self.segs[0..self.seg_count], self.dst, off, cr.data)) {
                        return Error.Invalid;
                    }

                    @memcpy(self.dst[off..end], cr.data);
                    try self.insertSegment(off, end);
                    self.advanceContig();

                    // Lock in the declared length once the first 4
                    // bytes are contiguous.
                    if (self.declared_len == null and self.contig_end >= 4) {
                        if (self.dst[0] != tls_msg_type_client_hello) return Error.Invalid;
                        const u24_len = (@as(usize, self.dst[1]) << 16) |
                            (@as(usize, self.dst[2]) << 8) |
                            @as(usize, self.dst[3]);
                        const total = u24_len + 4;
                        if (total > self.dst.len) return Error.Overflow;
                        self.declared_len = total;
                    }
                },
                // CRYPTO + ACK + PING + PADDING are the only frame
                // types legitimate inside an Initial (RFC 9000 §17.2.2).
                .padding, .ping, .ack, .path_ack => {},
                else => return Error.Invalid,
            }
        }

        if (self.isComplete()) {
            return self.dst[0..self.declared_len.?];
        }
        return null;
    }

    /// Returns true when `[off, off+data.len)` intersects an existing
    /// segment but the byte values differ from what's already stored
    /// at that offset.
    fn overlapsAndDiffers(segs: []const Segment, dst: []const u8, off: usize, data: []const u8) bool {
        const end = off + data.len;
        for (segs) |s| {
            if (s.offset >= end or s.end <= off) continue;
            const ov_start = @max(s.offset, off);
            const ov_end = @min(s.end, end);
            if (!std.mem.eql(u8, dst[ov_start..ov_end], data[ov_start - off .. ov_end - off])) {
                return true;
            }
        }
        return false;
    }

    /// Insert `[off, end)` into the sorted segment list, merging with
    /// any neighbours it overlaps or abuts. Returns `error.Invalid`
    /// if the merge would exceed `max_segments` (deeply pathological
    /// reordering — fall back to no upgrade).
    fn insertSegment(self: *ChReassembler, off: usize, end: usize) Error!void {
        // Find the first segment whose end >= off (potential merge
        // candidate); everything strictly to its left stays untouched.
        var i: usize = 0;
        while (i < self.seg_count and self.segs[i].end < off) : (i += 1) {}

        // Greedy merge: while the next segment overlaps or abuts the
        // new range, swallow it.
        var new_off = off;
        var new_end = end;
        var j = i;
        while (j < self.seg_count and self.segs[j].offset <= new_end) : (j += 1) {
            if (self.segs[j].offset < new_off) new_off = self.segs[j].offset;
            if (self.segs[j].end > new_end) new_end = self.segs[j].end;
        }

        // Rewrite [i..j) with the merged range, shifting the tail.
        const removed = j - i;
        if (removed == 0) {
            if (self.seg_count >= self.segs.len) return Error.Invalid;
            // Shift right to make room.
            var k: usize = self.seg_count;
            while (k > i) : (k -= 1) self.segs[k] = self.segs[k - 1];
            self.segs[i] = .{ .offset = new_off, .end = new_end };
            self.seg_count += 1;
        } else {
            // Replace the merged span and shift the tail left.
            self.segs[i] = .{ .offset = new_off, .end = new_end };
            const drop = removed - 1;
            if (drop > 0) {
                var k: usize = i + 1;
                while (k + drop < self.seg_count) : (k += 1) {
                    self.segs[k] = self.segs[k + drop];
                }
                self.seg_count -= @intCast(drop);
            }
        }
    }

    /// Re-evaluate the contiguous-from-zero frontier after an insert.
    /// The first segment, if it starts at 0, defines the reachable
    /// prefix; everything else stays buffered until the gap fills.
    fn advanceContig(self: *ChReassembler) void {
        if (self.seg_count == 0) return;
        if (self.segs[0].offset != 0) return;
        if (self.segs[0].end > self.contig_end) self.contig_end = self.segs[0].end;
    }
};

/// Walk a TLS ClientHello (including the outer Handshake header) and
/// return the bytes of the `quic_transport_parameters` extension
/// value. Returns `null` on any malformation or if the extension is
/// absent.
///
/// `client_hello` is the full TLS Handshake record:
///   { type=1, length:u24, ClientHello body }
pub fn findQuicTransportParamsExt(client_hello: []const u8) ?[]const u8 {
    var pos: usize = 0;
    if (pos + 4 > client_hello.len) return null;
    if (client_hello[pos] != tls_msg_type_client_hello) return null;
    const body_len = (@as(usize, client_hello[pos + 1]) << 16) |
        (@as(usize, client_hello[pos + 2]) << 8) |
        @as(usize, client_hello[pos + 3]);
    pos += 4;
    if (pos + body_len > client_hello.len) return null;
    const body_end = pos + body_len;

    // legacy_version: 2 bytes; random: 32 bytes
    if (pos + 2 + 32 > body_end) return null;
    pos += 2 + 32;

    // legacy_session_id: u8-len-prefix
    if (pos + 1 > body_end) return null;
    const sid_len: usize = client_hello[pos];
    pos += 1;
    if (pos + sid_len > body_end) return null;
    pos += sid_len;

    // cipher_suites: u16-len-prefix
    if (pos + 2 > body_end) return null;
    const cs_len = (@as(usize, client_hello[pos]) << 8) | @as(usize, client_hello[pos + 1]);
    pos += 2;
    if (pos + cs_len > body_end) return null;
    pos += cs_len;

    // legacy_compression_methods: u8-len-prefix
    if (pos + 1 > body_end) return null;
    const cm_len: usize = client_hello[pos];
    pos += 1;
    if (pos + cm_len > body_end) return null;
    pos += cm_len;

    // extensions: u16-len-prefix
    if (pos + 2 > body_end) return null;
    const exts_len = (@as(usize, client_hello[pos]) << 8) | @as(usize, client_hello[pos + 1]);
    pos += 2;
    if (pos + exts_len > body_end) return null;
    const exts_end = pos + exts_len;

    while (pos < exts_end) {
        if (pos + 4 > exts_end) return null;
        const ext_type = (@as(u16, client_hello[pos]) << 8) | @as(u16, client_hello[pos + 1]);
        const ext_len = (@as(usize, client_hello[pos + 2]) << 8) | @as(usize, client_hello[pos + 3]);
        pos += 4;
        if (pos + ext_len > exts_end) return null;
        if (ext_type == tls_ext_quic_transport_params or
            ext_type == tls_ext_quic_transport_params_legacy)
        {
            return client_hello[pos .. pos + ext_len];
        }
        pos += ext_len;
    }
    return null;
}

/// Find the `version_information` (codepoint 0x11) parameter inside a
/// QUIC transport-parameters blob and decode it into a
/// `ClientVersionInfo`. Returns `null` if the parameter is absent or
/// the blob is malformed.
///
/// We deliberately do NOT call `transport_params.Params.decode`: that
/// path enforces invariants (e.g. role-aware checks via `decodeAs`)
/// that don't all apply to a pre-handshake sniff. Walking the blob
/// directly keeps the pre-parse defensive — anything other than a
/// well-formed `version_information` parameter falls through to
/// `null` and the upgrade is skipped.
pub fn findVersionInformation(tp_blob: []const u8) ?ClientVersionInfo {
    var pos: usize = 0;
    while (pos < tp_blob.len) {
        const id_d = varint.decode(tp_blob[pos..]) catch return null;
        pos += id_d.bytes_read;
        const len_d = varint.decode(tp_blob[pos..]) catch return null;
        pos += len_d.bytes_read;
        const value_len: usize = std.math.cast(usize, len_d.value) orelse return null;
        if (pos + value_len > tp_blob.len) return null;
        if (id_d.value == transport_params.Id.version_information) {
            // Value: N x 4 bytes, big-endian. First entry is chosen
            // version; remainder is the compatibility set.
            if (value_len == 0 or value_len % 4 != 0) return null;
            const count = value_len / 4;
            if (count > max_versions) return null;
            var info: ClientVersionInfo = .{ .count = @intCast(count), .buf = @splat(0) };
            var i: usize = 0;
            while (i < count) : (i += 1) {
                info.buf[i] = std.mem.readInt(u32, tp_blob[pos + i * 4 ..][0..4], .big);
            }
            return info;
        }
        pos += value_len;
    }
    return null;
}

/// RFC 9368 §5 upgrade decision: pick the first server-preferred
/// version that ALSO appears in the client's `available_versions`.
/// Returns `null` if there is no overlap (the server should keep the
/// wire version and continue the handshake under it; if neither side
/// can agree, the connection fails normally).
pub fn chooseUpgradeVersion(
    server_versions: []const u32,
    client_available: []const u32,
) ?u32 {
    for (server_versions) |sv| {
        for (client_available) |cv| {
            if (sv == cv) return sv;
        }
    }
    return null;
}

// -- tests ---------------------------------------------------------------

test "chooseUpgradeVersion picks highest-priority overlap" {
    const v1: u32 = 0x00000001;
    const v2: u32 = 0x6b3343cf;

    // Server prefers v2; client offers [v1, v2] → upgrade to v2.
    try std.testing.expectEqual(
        @as(?u32, v2),
        chooseUpgradeVersion(&.{ v2, v1 }, &.{ v1, v2 }),
    );

    // Server prefers v2; client offers only [v1] → fall back to v1.
    try std.testing.expectEqual(
        @as(?u32, v1),
        chooseUpgradeVersion(&.{ v2, v1 }, &.{v1}),
    );

    // No overlap.
    try std.testing.expectEqual(
        @as(?u32, null),
        chooseUpgradeVersion(&.{0xdeadbeef}, &.{ v1, v2 }),
    );

    // Empty client list (parameter absent or malformed) → no choice.
    try std.testing.expectEqual(
        @as(?u32, null),
        chooseUpgradeVersion(&.{ v2, v1 }, &.{}),
    );
}

test "findVersionInformation extracts a 2-version blob" {
    var buf: [256]u8 = undefined;
    var params: transport_params.Params = .{};
    const v1: u32 = 0x00000001;
    const v2: u32 = 0x6b3343cf;
    try params.setCompatibleVersions(&.{ v1, v2 });
    const n = try params.encode(&buf);

    const info = findVersionInformation(buf[0..n]) orelse return error.TestExpectedSome;
    try std.testing.expectEqual(@as(u8, 2), info.count);
    try std.testing.expectEqual(v1, info.buf[0]);
    try std.testing.expectEqual(v2, info.buf[1]);
}

test "findVersionInformation returns null when parameter absent" {
    var buf: [256]u8 = undefined;
    const params: transport_params.Params = .{
        .max_idle_timeout_ms = 30_000,
        .initial_source_connection_id = transport_params.ConnectionId.fromSlice(&[_]u8{ 1, 2, 3, 4 }),
    };
    const n = try params.encode(&buf);
    try std.testing.expectEqual(@as(?ClientVersionInfo, null), findVersionInformation(buf[0..n]));
}

test "findVersionInformation rejects malformed payload" {
    // Codepoint 0x11 with length 3 (not multiple of 4).
    const blob = [_]u8{ 0x11, 0x03, 0x00, 0x00, 0x01 };
    try std.testing.expectEqual(@as(?ClientVersionInfo, null), findVersionInformation(&blob));
}

test "findQuicTransportParamsExt extracts the QTP payload" {
    // Build a minimal but valid TLS ClientHello with a single
    // `quic_transport_parameters` (codepoint 0x39) extension whose
    // value is `payload`. We only need the structural shape — the
    // pre-parse never inspects ciphersuites, session id, etc.
    var buf: [256]u8 = undefined;
    const payload = [_]u8{ 0xab, 0xcd, 0xef };
    var pos: usize = 0;

    // Handshake type + length placeholder.
    buf[pos] = 0x01;
    pos += 1;
    pos += 3; // u24 length, fill later

    const body_start = pos;
    // legacy_version
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;
    // random (32 zero bytes)
    @memset(buf[pos .. pos + 32], 0);
    pos += 32;
    // legacy_session_id (empty)
    buf[pos] = 0x00;
    pos += 1;
    // cipher_suites: 2 bytes len + 1 suite TLS_AES_128_GCM_SHA256 (0x1301)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x02;
    buf[pos + 2] = 0x13;
    buf[pos + 3] = 0x01;
    pos += 4;
    // legacy_compression_methods: 1 byte len + 1 byte null compression
    buf[pos] = 0x01;
    buf[pos + 1] = 0x00;
    pos += 2;
    // extensions: u16 length + one extension.
    const ext_len_pos = pos;
    pos += 2;
    const ext_start = pos;
    // ext type 0x0039
    buf[pos] = 0x00;
    buf[pos + 1] = 0x39;
    pos += 2;
    // ext data length
    buf[pos] = 0x00;
    buf[pos + 1] = @intCast(payload.len);
    pos += 2;
    // ext data
    @memcpy(buf[pos .. pos + payload.len], &payload);
    pos += payload.len;
    const exts_total = pos - ext_start;
    buf[ext_len_pos] = @intCast((exts_total >> 8) & 0xff);
    buf[ext_len_pos + 1] = @intCast(exts_total & 0xff);
    const body_total = pos - body_start;
    buf[1] = @intCast((body_total >> 16) & 0xff);
    buf[2] = @intCast((body_total >> 8) & 0xff);
    buf[3] = @intCast(body_total & 0xff);

    const got = findQuicTransportParamsExt(buf[0..pos]) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, &payload, got);
}

test "findQuicTransportParamsExt returns null on truncated header" {
    const buf = [_]u8{ 0x01, 0x00, 0x00 }; // missing length octet
    try std.testing.expectEqual(@as(?[]const u8, null), findQuicTransportParamsExt(&buf));
}

test "findQuicTransportParamsExt rejects non-ClientHello message type" {
    const buf = [_]u8{ 0x02, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(@as(?[]const u8, null), findQuicTransportParamsExt(&buf));
}

test "reassembleClientHello: single-frame at offset 0" {
    // Build a minimal ClientHello (8 bytes of body content, body_len = 8).
    // Outer header: 4 bytes (type + u24 len). Total = 12 bytes.
    const body_len: u8 = 8;
    var ch: [12]u8 = .{ 0x01, 0x00, 0x00, body_len, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };

    // Frame: type=0x06 (CRYPTO), offset=0, length=12, data=ch.
    var payload_buf: [32]u8 = undefined;
    var p: usize = 0;
    payload_buf[p] = 0x06; // varint 0x06
    p += 1;
    payload_buf[p] = 0x00; // varint offset = 0
    p += 1;
    payload_buf[p] = ch.len; // varint length = 12 (single-byte varint)
    p += 1;
    @memcpy(payload_buf[p .. p + ch.len], &ch);
    p += ch.len;

    var dst: [max_client_hello_bytes]u8 = undefined;
    const got = reassembleClientHello(&dst, payload_buf[0..p]) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, &ch, got);
}

test "reassembleClientHello: returns null when first byte is wrong" {
    // CRYPTO frame whose data starts with 0x02 (ServerHello tag).
    const body: [4]u8 = .{ 0x02, 0x00, 0x00, 0x00 };
    var payload_buf: [16]u8 = undefined;
    payload_buf[0] = 0x06;
    payload_buf[1] = 0x00;
    payload_buf[2] = body.len;
    @memcpy(payload_buf[3 .. 3 + body.len], &body);

    var dst: [max_client_hello_bytes]u8 = undefined;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        reassembleClientHello(&dst, payload_buf[0 .. 3 + body.len]),
    );
}

test "reassembleClientHello: tolerates leading PADDING and trailing PADDING" {
    const body_len: u8 = 4;
    const ch: [8]u8 = .{ 0x01, 0x00, 0x00, body_len, 0xaa, 0xbb, 0xcc, 0xdd };

    // [PADDING][CRYPTO offset=0 data=ch][PADDING]
    var payload_buf: [64]u8 = undefined;
    var p: usize = 0;
    @memset(payload_buf[p .. p + 4], 0); // 4 bytes of PADDING
    p += 4;
    payload_buf[p] = 0x06;
    p += 1;
    payload_buf[p] = 0x00; // offset = 0
    p += 1;
    payload_buf[p] = ch.len;
    p += 1;
    @memcpy(payload_buf[p .. p + ch.len], &ch);
    p += ch.len;
    @memset(payload_buf[p .. p + 8], 0); // trailing PADDING
    p += 8;

    var dst: [max_client_hello_bytes]u8 = undefined;
    const got = reassembleClientHello(&dst, payload_buf[0..p]) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, &ch, got);
}

test "reassembleClientHello: bails on missing offset 0 frame (fragmented)" {
    // Single CRYPTO frame at offset 100 — looks like a fragmented
    // ClientHello where the prefix ended up in a different Initial.
    const body: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    var payload_buf: [16]u8 = undefined;
    payload_buf[0] = 0x06; // type
    payload_buf[1] = 0x40; // varint two-byte prefix: 0x4064 = 100
    payload_buf[2] = 0x64;
    payload_buf[3] = body.len; // length
    @memcpy(payload_buf[4 .. 4 + body.len], &body);

    var dst: [max_client_hello_bytes]u8 = undefined;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        reassembleClientHello(&dst, payload_buf[0 .. 4 + body.len]),
    );
}

// -- ChReassembler test helpers ----------------------------------------

const frame_encode = @import("../frame/encode.zig");
const frame_types = @import("../frame/types.zig");

/// Build an Initial-style payload containing a single CRYPTO frame at
/// `offset` carrying `data`. Returns the bytes written into `out`.
fn buildCryptoPayload(out: []u8, offset: u64, data: []const u8) []u8 {
    const n = frame_encode.encode(out, .{ .crypto = .{
        .offset = offset,
        .data = data,
    } }) catch unreachable;
    return out[0..n];
}

/// Construct a synthetic ClientHello with `total` total bytes (header
/// + body). Bytes 4..total are an arbitrary deterministic pattern so
/// equality assertions can verify the reassembler reproduced exactly
/// what was fed in.
fn buildSyntheticCh(buf: []u8, total: usize) []u8 {
    std.debug.assert(total >= 4 and total <= buf.len);
    const body_len = total - 4;
    buf[0] = tls_msg_type_client_hello;
    buf[1] = @intCast((body_len >> 16) & 0xff);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);
    var i: usize = 4;
    while (i < total) : (i += 1) buf[i] = @as(u8, @intCast(i & 0xff)) ^ 0x5a;
    return buf[0..total];
}

test "ChReassembler: single-feed CH completes in one shot" {
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 64);
    var payload: [128]u8 = undefined;
    const pkt = buildCryptoPayload(&payload, 0, ch);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    const got = (try rc.feed(pkt)) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, got);
    try std.testing.expect(rc.isComplete());
}

test "ChReassembler: two-Initial CH fed in order" {
    // CH split across two CRYPTO frames at offset 0 and offset 32.
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 80);
    var p1: [128]u8 = undefined;
    var p2: [128]u8 = undefined;
    const pkt1 = buildCryptoPayload(&p1, 0, ch[0..32]);
    const pkt2 = buildCryptoPayload(&p2, 32, ch[32..]);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try rc.feed(pkt1),
    );
    const got = (try rc.feed(pkt2)) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, got);
    try std.testing.expect(rc.isComplete());
}

test "ChReassembler: two-Initial CH fed out of order" {
    // Tail arrives first, then the head — a plausible reordering on a
    // congested path. The reassembler must hold the tail until offset
    // 0 fills.
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 80);
    var p1: [128]u8 = undefined;
    var p2: [128]u8 = undefined;
    const pkt_head = buildCryptoPayload(&p1, 0, ch[0..32]);
    const pkt_tail = buildCryptoPayload(&p2, 32, ch[32..]);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    // Tail first: declared length isn't observable yet (we haven't
    // seen byte 0..3 contiguously) so feed must report null.
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try rc.feed(pkt_tail),
    );
    const got = (try rc.feed(pkt_head)) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, got);
}

test "ChReassembler: duplicate / retransmitted CRYPTO frames are idempotent" {
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 64);
    var p1: [128]u8 = undefined;
    const pkt = buildCryptoPayload(&p1, 0, ch);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    const first = (try rc.feed(pkt)) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, first);

    // Re-feed the same frame; isComplete stays true and the slice is
    // unchanged.
    const again = (try rc.feed(pkt)) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, again);
    try std.testing.expect(rc.isComplete());
}

test "ChReassembler: oversize CH is rejected with Overflow" {
    // Forge a CH header advertising 5000 bytes — far past
    // `max_client_hello_bytes` (4096) — and feed it.
    var hdr: [4]u8 = .{ 0x01, 0x00, 0x13, 0x84 };
    _ = &hdr;
    var p1: [16]u8 = undefined;
    const pkt = buildCryptoPayload(&p1, 0, &hdr);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    try std.testing.expectError(ChReassembler.Error.Overflow, rc.feed(pkt));
}

test "ChReassembler: hole in offsets keeps result null" {
    // Feed only the first 16 bytes of a 64-byte CH and one trailing
    // chunk past a hole. Until the gap fills, feed() returns null.
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 64);
    var p1: [128]u8 = undefined;
    var p2: [128]u8 = undefined;
    const head = buildCryptoPayload(&p1, 0, ch[0..16]);
    const tail = buildCryptoPayload(&p2, 32, ch[32..]); // gap [16..32)

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    try std.testing.expectEqual(@as(?[]const u8, null), try rc.feed(head));
    try std.testing.expectEqual(@as(?[]const u8, null), try rc.feed(tail));
    try std.testing.expect(!rc.isComplete());

    // Now patch the gap and we should complete.
    var p3: [128]u8 = undefined;
    const fill = buildCryptoPayload(&p3, 16, ch[16..32]);
    const got = (try rc.feed(fill)) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, got);
}

test "ChReassembler: reset clears state for reuse" {
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 32);
    var p1: [128]u8 = undefined;
    const pkt = buildCryptoPayload(&p1, 0, ch);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    _ = try rc.feed(pkt);
    try std.testing.expect(rc.isComplete());
    rc.reset();
    try std.testing.expect(!rc.isComplete());
    try std.testing.expectEqual(@as(?[]const u8, null), try rc.feed(p1[0..0]));
}

test "ChReassembler: out-of-order three-fragment CH" {
    // Fragments [0..16), [16..32), [32..64) fed in order [16..32),
    // [32..64), [0..16). The reassembler must merge segments and
    // resolve the contiguous frontier only on the last feed.
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 64);
    var p1: [128]u8 = undefined;
    var p2: [128]u8 = undefined;
    var p3: [128]u8 = undefined;
    const a = buildCryptoPayload(&p1, 16, ch[16..32]);
    const b = buildCryptoPayload(&p2, 32, ch[32..]);
    const c = buildCryptoPayload(&p3, 0, ch[0..16]);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    try std.testing.expectEqual(@as(?[]const u8, null), try rc.feed(a));
    try std.testing.expectEqual(@as(?[]const u8, null), try rc.feed(b));
    const got = (try rc.feed(c)) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, got);
}

test "ChReassembler: conflicting overlap returns Invalid" {
    // First feed lays down bytes [0..32) of one synthetic CH; second
    // feed claims to deliver [16..48) but with mismatched overlap
    // bytes. The reassembler should reject as Invalid.
    var ch1_storage: [128]u8 = undefined;
    const ch1 = buildSyntheticCh(&ch1_storage, 64);
    var p1: [128]u8 = undefined;
    const pkt1 = buildCryptoPayload(&p1, 0, ch1[0..32]);

    // Build a "conflicting" second buffer: same offsets but bytes
    // bit-flipped in the overlap region.
    var bad: [32]u8 = undefined;
    @memcpy(bad[0..16], ch1[16..32]);
    for (bad[0..16]) |*b| b.* ^= 0xff;
    @memcpy(bad[16..], ch1[32..48]);
    var p2: [128]u8 = undefined;
    const pkt2 = buildCryptoPayload(&p2, 16, &bad);

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    _ = try rc.feed(pkt1);
    try std.testing.expectError(ChReassembler.Error.Invalid, rc.feed(pkt2));
}

test "ChReassembler: rejects unexpected frame type" {
    // STREAM frame in an Initial is a protocol violation; we don't
    // try to interpret it — fall back to no upgrade.
    var pkt: [16]u8 = undefined;
    // STREAM with type=0x08 (no OFF/LEN/FIN bits), id=0, no data.
    pkt[0] = 0x08;
    pkt[1] = 0x00;

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    try std.testing.expectError(ChReassembler.Error.Invalid, rc.feed(pkt[0..2]));
}

test "ChReassembler: tolerates leading PADDING/PING/ACK in the payload" {
    var ch_storage: [128]u8 = undefined;
    const ch = buildSyntheticCh(&ch_storage, 32);

    // [PADDING 4][PING][CRYPTO offset=0 data=ch][PADDING 8]
    var payload: [128]u8 = undefined;
    var p: usize = 0;
    @memset(payload[p .. p + 4], 0); // 4 PADDING bytes (frame type 0x00)
    p += 4;
    payload[p] = 0x01; // PING
    p += 1;
    const wrote = frame_encode.encode(payload[p..], .{ .crypto = .{
        .offset = 0,
        .data = ch,
    } }) catch unreachable;
    p += wrote;
    @memset(payload[p .. p + 8], 0);
    p += 8;

    var dst: [max_client_hello_bytes]u8 = undefined;
    var rc = ChReassembler.init(&dst);
    const got = (try rc.feed(payload[0..p])) orelse return error.TestExpectedSome;
    try std.testing.expectEqualSlices(u8, ch, got);
}
