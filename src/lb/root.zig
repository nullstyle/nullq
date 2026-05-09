//! `quic_zig.lb` — server-side QUIC-LB connection-ID generation.
//!
//! Implements the server-side surface of
//! [draft-ietf-quic-load-balancers-21][draft]: encoding routing
//! identity into connection IDs that an external layer-4 load balancer
//! can decode. The LB-side decode path is intentionally out of scope
//! for now (an LB is not a server); a future stretch goal may ship one
//! for ops tooling and round-trip tests.
//!
//! [draft]: https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/
//!
//! ## Pinned to draft revision 21
//!
//! Like `multipath_draft_version`, the QUIC-LB draft revision quic_zig
//! tracks is pinned in `quic_zig.quic_lb_draft_version`. Bumping it is
//! a deliberate scoped change — the wire format is unstable until the
//! draft is published as an RFC.
//!
//! ## Hardening note
//!
//! quic_zig's default posture is "server SCIDs are CSPRNG draws — no
//! deployment metadata leaks on the wire" (see README §"On by default").
//! Configuring `Server.Config.quic_lb` deliberately inverts that: every
//! minted CID encodes the configured `server_id`, and in plaintext mode
//! anyone observing the network can read it. Treat the load balancer as
//! the trust boundary.

const std = @import("std");

pub const config = @import("config.zig");
pub const cid = @import("cid.zig");
pub const nonce = @import("nonce.zig");
pub const feistel = @import("feistel.zig");
pub const decode_mod = @import("decode.zig");

pub const ConfigId = config.ConfigId;
pub const ServerId = config.ServerId;
pub const LbConfig = config.LbConfig;
pub const Key = config.Key;

pub const Factory = cid.Factory;
pub const Mode = cid.Mode;
pub const Error = cid.Error;
pub const NonceCounter = nonce.NonceCounter;

/// Mint an unroutable (`config_id = 0b111`) CID per draft §3.1.
/// Used when the active LB configuration is unavailable (rotation
/// gap, nonce exhaustion). See `cid.mintUnroutable` for the byte-
/// layout contract.
pub const mintUnroutable = cid.mintUnroutable;
pub const min_unroutable_cid_len = cid.min_unroutable_cid_len;

/// LB-side decoder. Recovers `(config_id, server_id, nonce)` from a
/// minted CID. Plaintext (§5.5) and four-pass Feistel (§5.5.2) are
/// implemented; single-pass §5.5.1 returns
/// `Decoded.Error.SinglePassDecodeNotImplemented` until a
/// `boringssl-zig` AES-128-ECB-decrypt wrapper lands.
pub const decode = decode_mod.decode;
pub const Decoded = decode_mod.Decoded;
pub const DecodeError = decode_mod.Error;

pub const max_server_id_len = config.max_server_id_len;
pub const max_nonce_len = config.max_nonce_len;
pub const min_nonce_len = config.min_nonce_len;
pub const max_combined_len = config.max_combined_len;
pub const unroutable_config_id = config.unroutable_config_id;

test {
    _ = config;
    _ = cid;
    _ = nonce;
    _ = feistel;
    _ = decode_mod;
}
