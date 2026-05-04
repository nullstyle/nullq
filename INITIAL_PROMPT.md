# nullq — a Zig-first QUIC implementation, built from the RFCs

A from-the-RFC-up implementation of IETF QUIC v1 in Zig 0.16, using
[`boringssl-zig`](../boringssl-zig) for crypto and TLS 1.3. nullq is the
QUIC *transport*: it carries reliable streams, unreliable datagrams,
and TLS-secured packets over UDP. HTTP/3 is out of scope; nullq is
what HTTP/3 (or any other QUIC consumer) sits on top of.

This document is a Codex-ready brief: it captures the intent, the
analysis of the dependency, the architecture, the phase plan, and the
acceptance criteria. It is the load-bearing source of truth — the code
follows from it, not the reverse.

## Goal

Produce a Zig package, `nullq`, that:

1. Implements QUIC v1 from RFC 8999 (invariants), RFC 9000 (transport),
   RFC 9001 (TLS), and RFC 9002 (loss detection + congestion control).
2. Uses `boringssl-zig` for TLS 1.3 handshake and AEAD/HKDF crypto. No
   pure-Zig `std.crypto` for the hot path; BoringSSL is the spec's
   expected, audited, side-channel-resistant implementation.
3. Treats every other layer (varints, frames, packet numbers, ACK
   ranges, RTT, NewReno, flow control, stream reassembly) as **pure
   Zig** with no BoringSSL dependency. These are byte-pushing and
   bookkeeping; they get tested against RFC vectors and don't need C.
4. Is **I/O-decoupled**: the connection state machine is a synchronous
   datagram-in / datagram-out function. The user owns the socket, the
   clock, and the event loop. We ship a blocking POSIX UDP adapter and
   an in-memory mock transport for tests, but the library itself
   doesn't care.
5. Passes the IETF QUIC interop runner's `H` (handshake), `D` (data
   transfer), `C` (close), `R` (retry), `Z` (0-RTT), and `M`
   (migration) test cases against ngtcp2 and quiche.
6. Supports **0-RTT data** (RFC 9001 §4.5/4.6) — session ticket
   export/import, early-data send/receive, rejection-recovery, and a
   replay-safety contract the embedder can enforce.
7. Supports **connection migration** (RFC 9000 §9) — peer-initiated
   address change and client-initiated migration, with PATH_CHALLENGE/
   PATH_RESPONSE validation, per-path anti-amplification credit, and
   congestion-controller reset on path switch.
8. Supports **Multipath QUIC** (draft-ietf-quic-multipath) — multiple
   active paths with per-path packet number spaces, per-path loss
   recovery, and a pluggable scheduler. Tracks the current stable
   draft; expect API churn confined to this layer until the spec is
   published as an RFC.

## Non-goals

Do not attempt, in the MVP:

- HTTP/3 (RFC 9114) or QPACK (RFC 9204) — separate library, separate repo.
- Windows.
- FIPS mode.
- Hardware offload, GSO/GRO, kTLS, recvmmsg batching — performance
  optimizations come after correctness.
- A built-in async runtime. nullq is sync state machine + transport.

## Why Zig-first

QUIC implementations in Zig that already exist (e.g. `zig-quic`,
hobbyist forks) are mostly thin wrappers over C libraries (ngtcp2,
quiche, picoquic). nullq is the opposite: we ship the protocol logic
in Zig and treat BoringSSL as a black box for primitives we don't want
to write ourselves.

Reasons to write QUIC's protocol logic in Zig rather than wrap a C
library:

1. **Clarity of ownership.** Frame parsing, flow control, ACK ranges,
   loss detection — these are exactly the modules where memory safety
   bugs and integer overflows have caused CVEs in the C ecosystem
   (CVE-2022-30580, etc.). Zig's bounds checks, slice arithmetic, and
   typed varints catch a class of errors at compile time.
2. **Testability.** A pure-Zig state machine driven by an in-memory
   transport runs deterministically under any clock; we can replay
   captured PCAPs against it without spinning up sockets.
3. **No FFI tax on the hot path.** AEAD seal/open is the only per-packet
   call into C. Frame parsing, packet number reconstruction, ACK
   processing — all stay in Zig.
4. **Spec literacy.** Implementing from the RFCs forces a thorough
   understanding of the protocol that wrapping a library never gives
   you. This is also why we treat the RFCs as the source of truth and
   cite section numbers in module headers.

## Analysis: what does `boringssl-zig` give us?

The dependency is published as
[`nullstyle/boringssl-zig`](https://github.com/nullstyle/boringssl-zig)
on GitHub. It builds BoringSSL natively from `build.zig`, fetches the
BoringSSL source via tarball URL+hash through `build.zig.zon` (no
submodule), is symbol-prefixed (`BORINGSSL_PREFIX=zbssl`), and
cross-compiles to all four target triples we care about
(aarch64/x86_64 × {macos, linux-musl}).

Five releases relevant to nullq:

- **v0.1.0** — TLS 1.3 client, hash, hmac, rand.
- **v0.2.0** (2026-05-03) — QUIC-ready crypto primitives. AEAD, HKDF,
  AES single-block. Cross-cutting RFC 9001 §A.1 initial-secret KAT
  upstream. Unblocks nullq Phase 2.
- **v0.3.0** (2026-05-03) — TLS 1.3 server + ALPN + QUIC TLS bridge.
  The QUIC-specific TLS surface (SSL_QUIC_METHOD wrapping, transport
  params, provide_quic_data, encryption-level accessors) is now
  ergonomically available. Unblocks nullq Phase 4.
- **v0.4.0** (2026-05-03) — TLS 1.3 session resumption + QUIC 0-RTT.
  `tls.Session` with toBytes/fromBytes/upRef/deinit; client-side
  `setSession` and server/client `setEarlyDataEnabled`;
  `setNewSessionCallback` for asynchronous NST capture;
  `earlyDataStatus` / `earlyDataReason` for outcome introspection.
  Unblocks nullq Phase 8 (0-RTT) end-to-end through the bridge.
- **v0.5.0** (2026-05-03) — production polish. `crypto.chacha20.xor`
  + `quicHpMask` (header protection for the ChaCha cipher suite —
  RFC 9001 §5.4.4); `errors.popErrorString` + `popErrorStringInto`
  for diagnostic logging; `Context.setKeylogCallback` for
  SSLKEYLOGFILE-style debugging.

What the public API exposes as of v0.3.0 (`boringssl.crypto.*` /
`boringssl.tls.*`):

| Surface                                                   | Since   | Used by nullq for                                    |
| --------------------------------------------------------- | ------- | ---------------------------------------------------- |
| `crypto.hash.Sha256/384/512`                              | v0.1.0  | TLS handshake transcript                             |
| `crypto.hmac.HmacSha256/384/512`                          | v0.1.0  | (indirectly, via HKDF)                               |
| `crypto.rand.fillBytes`                                   | v0.1.0  | CIDs, PNs, path-validation tokens                    |
| `crypto.aead.{AesGcm128, AesGcm256, ChaCha20Poly1305}`    | v0.2.0  | Per-packet AEAD seal/open (RFC 9001 §5.3)            |
| `crypto.kdf.{HkdfSha256/384/512}`                         | v0.2.0  | QUIC key schedule (§5.2)                             |
| `crypto.aes.{Aes128, Aes256}` single-block                | v0.2.0  | Header-protection mask (§5.4.3)                      |
| `tls.Context.initClient` / `initServer`                   | v0.3.0  | Both ends of the QUIC TLS handshake                  |
| `tls.Context.loadCertChainAndKey(chain_pem, key_pem)`     | v0.3.0  | Server certificate provisioning                      |
| `ContextOptions.alpn: []const []const u8`                 | v0.3.0  | ALPN advertisement / selection                       |
| `Conn.alpnSelected()`, `setHostname()`, `handshakeDone()` | v0.3.0  | Negotiation introspection                            |
| `Context.newQuicClient` / `newQuicServer`                 | v0.3.0  | fd-less SSL for QUIC                                 |
| `tls.quic.{Method, EncryptionLevel}`                      | v0.3.0  | Callback ABI bridge into TLS 1.3                     |
| `Conn.setQuicMethod`, `setUserData` / `userData` / `userDataFromSsl` | v0.3.0 | Install bridge + recover `*Connection` in callbacks |
| `Conn.setQuicTransportParams` / `peerQuicTransportParams` | v0.3.0  | RFC 9000 §18 transport parameters                    |
| `Conn.provideQuicData` / `processQuicPostHandshake`       | v0.3.0  | Drive handshake from peer CRYPTO bytes               |
| `Conn.quicReadLevel` / `quicWriteLevel` / `isQuic`        | v0.3.0  | Encryption-level introspection                       |
| `Conn.setQuicEarlyDataContext`                            | v0.3.0  | Server-side 0-RTT replay context                     |
| `tls.Session.{toBytes, fromBytes, upRef, deinit}`         | v0.4.0  | Capture / restore session for 0-RTT (Phase 8)        |
| `Conn.setSession`, `setEarlyDataEnabled`                  | v0.4.0  | Client-side resumption + 0-RTT enable                |
| `Context.setNewSessionCallback`                           | v0.4.0  | Capture NewSessionTicket on the client               |
| `Conn.earlyDataStatus()` / `earlyDataReason()`            | v0.4.0  | Was 0-RTT accepted? + textual reason                 |
| `ContextOptions.early_data_enabled`                       | v0.4.0  | One-shot 0-RTT enable on a Context                   |
| `crypto.chacha20.{xor, quicHpMask}`                       | v0.5.0  | HP mask for `TLS_CHACHA20_POLY1305_SHA256` (§5.4.4)  |
| `errors.popErrorString` / `popErrorStringInto`            | v0.5.0  | Diagnostic logging from BoringSSL's error queue      |
| `Context.setKeylogCallback`                               | v0.5.0  | SSLKEYLOGFILE-style debug output                     |
| `errors`                                                  | v0.1.0  | Error mapping                                        |
| `raw.zbssl_*` (translate-c)                               | v0.1.0  | Bridge to anything not yet in the high-level API     |

What is **still not wrapped** in the public API: nothing nullq needs
through Phase 10. Future upstream candidates (HPKE, custom verify
callbacks, AES-GCM-SIV) are nice-to-haves but not on the critical
path.

### Where the new wrappers live

Two categories. Decide based on whether the wrapper is generally
useful to *any* boringssl-zig consumer:

**Upstream into boringssl-zig** (general-purpose primitives):

- ✅ **Shipped in v0.2.0**: AEAD (`crypto.aead`), HKDF (`crypto.kdf`),
  AES single-block (`crypto.aes`). Phase 2's PR-back-upstream task
  is complete.
- ✅ **Shipped in v0.3.0**: TLS 1.3 server (`Context.initServer` +
  `loadCertChainAndKey`), ALPN, QUIC bridge (`tls.quic.Method`, all
  the SSL_*_quic_* setters/getters, `provideQuicData`,
  `processQuicPostHandshake`, level accessors, ex-data helpers).
  Phase 4's required surface is upstream.
- ✅ **Shipped in v0.4.0**: TLS 1.3 session-ticket plumbing
  (`Session.toBytes` / `fromBytes`, `setSession`,
  `setNewSessionCallback`, `setEarlyDataEnabled`,
  `earlyDataStatus` / `earlyDataReason`). End-to-end QUIC 0-RTT
  acceptance test passes upstream. Phase 8's required surface is
  upstream.
- ✅ **Shipped in v0.5.0**: ChaCha20 stream primitive
  (`crypto.chacha20.xor` + `quicHpMask` for the ChaCha cipher
  suite's header protection), `errors.popErrorString` for
  diagnostic logging, `Context.setKeylogCallback` for
  SSLKEYLOGFILE-style debugging. Phase 11 polish surface ready.

**Local to nullq** (QUIC-specific glue layered on top of v0.3.0):

- `nullq.tls.handshake` — concrete `tls.quic.Method` implementation
  whose callbacks know how to wire BoringSSL's encryption-level
  events into nullq's packet number spaces. The callback ABI is
  generic (lives upstream); the implementation that maps to
  nullq's Connection state is local.
- `nullq.tls.transport_params` — RFC 9000 §18 codec. Encodes nullq's
  `Params` struct to bytes and hands those to
  `Conn.setQuicTransportParams`; decodes peer bytes from
  `Conn.peerQuicTransportParams` into a typed `Params`.
- `nullq.tls.early_data_context` — builder that fills the blob
  `Conn.setQuicEarlyDataContext` requires, parameterised by which
  transport params and application settings cover 0-RTT replay.

This split keeps boringssl-zig general and publishable while letting
nullq own the QUIC-specific semantics on top.

### Consuming boringssl-zig from nullq

Two valid `build.zig.zon` shapes:

```zig
// (a) Local-development path dep — what nullq uses today while both
//     repos iterate together. Changes in ../boringssl-zig flow through
//     immediately.
.boringssl_zig = .{ .path = "../boringssl-zig" },

// (b) Pinned URL+hash — what published nullq tags will use. The hash
//     is computed once via `zig fetch --save=boringssl_zig <url>`.
.boringssl_zig = .{
    .url  = "https://github.com/nullstyle/boringssl-zig/archive/refs/tags/v0.2.0.tar.gz",
    .hash = "<computed by zig fetch>",
},
```

Default for the working tree is (a). Switch to (b) when nullq cuts
its first tagged release, or when boringssl-zig stops moving. Bumping
boringssl-zig becomes an intentional `zig fetch --save` PR rather
than an invisible ride-along.

## RFC scope

### Mandatory for v0.1

- **RFC 8999** — QUIC version-independent invariants. Long header
  layout, version field, connection ID encoding. ~10 pages.
- **RFC 9000** — Core protocol. ~250 pages. The bulk of nullq.
  - §12: Packet structure, packet number spaces.
  - §13: Reliable transmission semantics.
  - §14: Datagram size, PMTU baseline (1200-byte minimum).
  - §17: Packet formats (Initial, Handshake, 0-RTT, 1-RTT, Retry, VN).
  - §18: Transport parameters.
  - §19: Frame types and encoding (incl. PATH_CHALLENGE / PATH_RESPONSE).
  - §10: Connection close, idle timeout, stateless reset.
  - §8: Address validation, anti-amplification (per-path).
  - **§9: Connection migration** — peer/client address change, path
    validation, congestion-controller reset, NAT rebinding handling.
- **RFC 9001** — Using TLS to Secure QUIC. ~30 pages.
  - §5: Packet protection (header + AEAD).
  - §5.2: Initial keys derivation (the version-keyed `initial_salt`).
  - §6: Key updates.
  - §4: Carrying TLS messages in CRYPTO frames; handshake confirmed.
  - **§4.5–4.6: 0-RTT data** — early-data encryption level on
    client and server, ticket-based resumption, replay-safety
    contract, `quic_early_data_context` enforcement on the server,
    rejection recovery on the client.
- **RFC 9002** — Loss Detection and Congestion Control. ~40 pages.
  - §6: Loss detection (PTO, time-threshold, packet-threshold).
  - §7: NewReno congestion control. Pluggable trait for future BBR/Cubic.
  - §A,B: Pseudocode appendices — implement these almost verbatim.

### Multipath QUIC (goal, draft-tracked)

- **draft-ietf-quic-multipath** — active path set, per-path packet
  number spaces, path identifiers, per-path loss recovery and
  congestion control, multipath transport parameter, ADD/REMOVE/ABANDON
  PATH frames (exact frame types per the latest stable draft), and a
  pluggable path scheduler. The spec is still in IETF process, so:
  - We track the latest stable draft revision and pin it explicitly
    in `tls/transport_params.zig` and `frame/types.zig`.
  - All multipath surface is behind an opt-in `enable_multipath`
    transport parameter; default behavior is single-path.
  - Single-path nullq remains the supported base; multipath is a
    superset whose API churn is *expected* and acceptable until the
    spec is published as an RFC.

### Stretch (post-v0.1)

These are nice-to-haves. None of them block 1.0; they're separate
roadmap items.

- **RFC 9221** — Unreliable Datagram extension. Cheap, useful for testing
  the transport layer without stream complexity.
- **RFC 9287** — Greasing the QUIC Bit. One-line interop niceness.
- **RFC 9368** — QUIC version 2 negotiation.
- **ECN** (RFC 9000 §13.4).
- **DPLPMTUD** (RFC 8899) — beyond the 1200-byte baseline.

## Architecture

### Principles

1. **Pure Zig where it's pure Zig.** Anything that's bytes-and-math
   has zero BoringSSL imports. This makes ~80% of the code testable
   without crypto setup.
2. **BoringSSL only for crypto.** AEAD seal/open, HKDF, AES block,
   TLS handshake. That's it.
3. **I/O is the embedder's problem.** The connection is a state machine:
   ```
   ConnState.handleDatagram(buf, now)  →  []OutgoingDatagram
   ConnState.poll(now)                 →  ?OutgoingDatagram
   ConnState.timeout()                 →  ?Instant   // when to next call poll
   ```
   This shape is what msquic, ngtcp2, quiche, picoquic, neqo, and
   s2n-quic all converge on. It's the right shape.
4. **Time is injected.** A `Clock` interface; tests pass a fake clock
   that advances explicitly. No `std.time.nanoTimestamp` calls inside
   the state machine.
5. **No allocations on the hot path.** Per-packet processing uses
   pre-allocated buffers. Allocator passed in at connection
   construction for slow-path state (CID lists, TLS buffers,
   recv-stream gap maps).
6. **One connection per state machine instance.** Multi-connection
   concurrency is the embedder's job.
7. **Paths are first-class from Phase 5.** Even single-path
   connections route every send/receive through a `Path` value
   (anti-amplification credit, RTT, CC state, PATH_CHALLENGE token,
   peer address, local CID, peer CID). Phase 9 (migration) adds path
   *switching*; Phase 10 (multipath) adds path *concurrency*. Neither
   should require restructuring the state machine — only widening
   the active-path set from one to many.
8. **Encryption levels include `early_data` from Phase 4.** Even
   though 0-RTT semantics don't land until Phase 8, the level enum
   and packet-protection table reserve a slot for `early_data` from
   the moment the TLS bridge exists. Adding 0-RTT later is then a
   matter of installing keys into an existing slot, not introducing
   a new one.
9. **Replay-safety is the embedder's policy, with our help.** nullq
   labels every received stream/datagram with whether it arrived in
   `early_data`. The library does not invent a list of "safe verbs";
   that's an application concern (HTTP/3 has its own rules). What we
   guarantee is that the embedder always knows which bytes might
   have been replayed.

### Module layout

```
nullq/
  build.zig
  build.zig.zon
  mise.toml
  justfile
  README.md
  INITIAL_PROMPT.md          # this document
  .gitignore

  src/
    root.zig                 # public API surface
    version.zig              # nullq.version, RFC version constants

    wire/
      varint.zig             # RFC 9000 §16 variable-length integer
      packet_number.zig      # truncated PN encode/decode (§17.1, §A.2/A.3)
      header.zig             # long/short header parse + serialize
      initial.zig            # RFC 9001 §5.2 initial salt → keys
      protection.zig         # header protection + AEAD packet protection

    frame/
      types.zig              # registry, type → variant tag
      decode.zig             # decoder for all 30+ frame types
      encode.zig             # encoder + size estimation for budgeted PMTU
      ack_range.zig          # gap/range encoding for ACK frames

    conn/
      state.zig              # per-connection state machine root
      role.zig               # client vs server divergent behaviors
      ids.zig                # connection ID issuance, retirement, stash
      pn_space.zig           # initial / handshake / application[/path] PN spaces
      ack_tracker.zig        # received-PN ranges, ACK frame generation
      flow_control.zig       # stream + connection limits, MAX_*_DATA pacing
      loss_recovery.zig      # RFC 9002 §A pseudocode (per-path-aware)
      congestion.zig         # RFC 9002 §B NewReno; trait for swappable CC
      send_pacer.zig         # cwnd / smoothed_rtt → emission pacing
      path.zig               # Path value: addr pair, CIDs, anti-amp,
                             #   validation state, RTT, CC instance
      path_validator.zig     # PATH_CHALLENGE / PATH_RESPONSE driver
      path_scheduler.zig     # which path to send on (single-path = trivial;
                             #   multipath = pluggable strategy)
      early_data.zig         # 0-RTT state: attempting/accepted/rejected,
                             #   pending early-data buffer, replay flagging
      timer.zig              # ack_delay, PTO, idle_timeout, draining timers
      multipath/
        capability.zig       # negotiation, transport-parameter handling
        path_id.zig          # path identifier per draft-ietf-quic-multipath
        coordinator.zig      # cross-path CC coordination policies (sum/indep)

    stream/
      send_buffer.zig        # offset-ranged tx buffer, retransmit-aware
      recv_buffer.zig        # in-order reassembly from STREAM frames
      stream.zig             # bidi/uni state, FIN, RESET, STOP_SENDING

    tls/
      handshake.zig          # SSL_QUIC_METHOD callback bridge
      transport_params.zig   # encode/decode/apply (RFC 9000 §18 + multipath)
      crypto_buffer.zig      # ordered handshake byte buffer (CRYPTO frames)
      level.zig              # ssl_encryption_level_t ↔ pn_space mapping;
                             #   includes early_data slot from Phase 4
      session_ticket.zig     # NewSessionTicket export/import, resumption
      early_data_context.zig # SSL_set_quic_early_data_context (server side)

    transport/
      udp.zig                # blocking POSIX UDP adapter (CLI use)
      mock.zig               # in-memory pair, deterministic, for tests
      iface.zig              # Transport trait

    util/
      buffer.zig             # zero-copy slice helpers, BoundedArrayList
      time.zig               # Clock interface, monotonic Instant
      rand.zig               # thin wrapper over boringssl.crypto.rand
      bigendian.zig          # u16/u24/u32 BE codec helpers

  tests/
    rfc/
      rfc9000_appendix_A.zig    # PN truncation/recovery test vectors
      rfc9001_appendix_A.zig    # Initial keys, sample protected packet
      rfc9001_appendix_B.zig    # ChaCha20-Poly1305 short-header sample
      rfc9001_appendix_C.zig    # Retry integrity tag
    unit/
      varint_test.zig
      frame_roundtrip_test.zig
      ack_range_test.zig
      flow_control_test.zig
      loss_recovery_test.zig
      newreno_test.zig
      path_validator_test.zig
      early_data_state_test.zig
    e2e/
      mock_transport_handshake.zig
      mock_transport_streams.zig
      mock_transport_close.zig
      mock_transport_loss.zig
      mock_transport_0rtt.zig          # Phase 8
      mock_transport_migration.zig     # Phase 9: NAT rebinding + active migration
      mock_transport_multipath.zig     # Phase 10: 2-path with asymmetric RTT/loss

  cli/
    qclient.zig              # quic-only HTTP/0.9-ish client for smoke
    qserver.zig              # echo server for interop

  fuzz/
    frame_decode_fuzz.zig    # libFuzzer-style entry, runnable via std.testing.fuzz
    varint_fuzz.zig
    packet_parse_fuzz.zig
```

### Key types (sketch)

```zig
// src/root.zig public surface
pub const Endpoint     = @import("conn/state.zig").Endpoint;     // client/server factory
pub const Connection   = @import("conn/state.zig").Connection;
pub const Datagram     = @import("conn/state.zig").Datagram;
pub const TransportParams = @import("tls/transport_params.zig").Params;
pub const Clock        = @import("util/time.zig").Clock;
pub const Stream       = @import("stream/stream.zig").Stream;

// pure-Zig sub-namespaces, available for users building on top
pub const wire  = @import("wire/root.zig");
pub const frame = @import("frame/root.zig");
```

The connection lifecycle (client side):

```zig
const nullq = @import("nullq");
const boringssl = @import("boringssl");

var ssl_ctx = try boringssl.tls.Context.initClient(.{ .verify = .system });
defer ssl_ctx.deinit();

var endpoint = try nullq.Endpoint.initClient(allocator, .{
    .ssl_ctx = &ssl_ctx,
    .clock   = nullq.Clock.realtime(),
});
defer endpoint.deinit();

var conn = try endpoint.connect(.{
    .server_name        = "cloudflare-quic.com",
    .alpn               = &.{ "hq-interop" },
    .transport_params   = .{ .initial_max_data = 1 << 20, .{...} },
    .peer_address       = peer_sockaddr,
});
defer conn.deinit();

// Drive the state machine
var udp = try nullq.transport.udp.open(.{ .bind = "0.0.0.0:0" });
defer udp.close();

while (!conn.isClosed()) {
    if (conn.pollOutgoing()) |dg| try udp.send(dg);
    if (try udp.recv(buf, conn.timeout())) |dg| {
        try conn.handleIncoming(dg.payload, dg.from, endpoint.clock.now());
    }
}
```

### Why this shape

- `Endpoint` owns the SSL_CTX and provides connection factories. One
  `Endpoint` per process is the common case but multiple is fine.
- `Connection` is a single state machine. `pollOutgoing()`, `handleIncoming()`,
  `timeout()` is the entire driving surface — the same three calls that
  ngtcp2's API exposes.
- The blocking UDP adapter in `transport/udp.zig` is a thin wrapper for
  CLI / smoke tests. Real apps will plug into their own event loop and
  call `Connection.handleIncoming` / `pollOutgoing` directly.
- `Clock` injection lets unit tests run a 60-second handshake retry
  in a microsecond.

## Phasing

Each phase ends with a hard acceptance criterion that's executable
(`zig build test` passes specific tests). No phase says "design is
complete"; everything is verified by code.

### Phase 0 — Scaffold ✓ (this commit)

- Project layout, `build.zig.zon` declares dep on
  `../boringssl-zig`, `build.zig` produces an empty static library,
  `zig build test` runs and passes (no tests yet, but the harness
  wires correctly).
- mise pin: zig 0.16.0, just 1.49.0 (matches boringssl-zig).
- A `nullq.version()` function returns `"0.0.0"` and a constant
  `nullq.QUIC_VERSION = 0x00000001` for QUIC v1.

**Acceptance:** `just test` from a clean checkout passes.

### Phase 1 — Pure-Zig wire format ✓ (2026-05-03)

- ✅ RFC 9000 §16 varints in [`wire/varint.zig`](src/wire/varint.zig) —
  encode/encodeFixed/decode/encodedLen, all four §16 worked vectors
  (37, 15293, 494,878,333, 151,288,809,941,952,652) as byte-for-byte
  KATs, non-minimum decoding, boundary tests, 4096-iter PRNG round-trip.
- ✅ Packet number truncation/recovery in
  [`wire/packet_number.zig`](src/wire/packet_number.zig) —
  encode/readTruncated/decode + encodedLength sizing. §A.3 worked
  example as KAT (largest 0xa82f30ea, truncated 0x9b32 → 0xa82f9b32).
  Snap-forward, snap-backward, PN-0 and PN-near-2^62 boundary cases.
- ✅ Long + short header parse/serialize in
  [`wire/header.zig`](src/wire/header.zig) — Initial, 0-RTT,
  Handshake, Retry, 1-RTT, Version Negotiation. RFC 9001 §A.2
  unprotected client Initial header as KAT.
- ✅ Frame decode/encode for all 20 v1 frame types in
  [`frame/decode.zig`](src/frame/decode.zig),
  [`frame/encode.zig`](src/frame/encode.zig),
  [`frame/types.zig`](src/frame/types.zig). Round-trip tests for each
  type, including STREAM's 8 type-byte combinations.
- ✅ ACK range encoding in
  [`frame/ack_range.zig`](src/frame/ack_range.zig) — `Iterator` walks
  `Interval`s in descending order without allocation; `writeRanges`
  encodes a caller-owned slice; multi-range descent KAT.

**Acceptance met:** 89/89 tests pass. The PN §A.3 vector, RFC 9001
§A.2 Initial, and full-coverage frame round-trips form the canonical
KAT set for the wire layer. The "tests/rfc/" directory mentioned in
the plan hasn't been split out yet — Phase-1 KATs live alongside the
modules they exercise (matching boringssl-zig's pattern); we'll move
them into `tests/rfc/` if/when separate cross-module tests start
needing them.

### Phase 2 — Initial-keys derivation ✓ (2026-05-03)

Implemented in [`wire/initial.zig`](src/wire/initial.zig). Both
client and server initial keys derive byte-for-byte against
RFC 9001 §A.1 vectors:
- `initial_secret = HKDF_extract(initial_salt_v1, dcid)` — via
  `boringssl.crypto.kdf.HkdfSha256.extract`.
- HKDF-Expand-Label per RFC 8446 §7.1 — built locally on top of
  `HkdfSha256.expand`, with the `tls13 ` prefix baked in.
- Client `secret` / `key` / `iv` / `hp` and server `secret` / `key` /
  `iv` / `hp` all match their §A.1 hex.

**Acceptance met:** §A.1 client + server keys verified by KAT.

#### Original plan

The crypto primitives this phase originally needed —
`crypto.aead.{AesGcm128, AesGcm256, ChaCha20Poly1305}`,
`crypto.kdf.HkdfSha256/384/512`, `crypto.aes.{Aes128, Aes256}` — all
shipped in boringssl-zig v0.2.0. Phase 2 collapses to *consume them*
and implement the QUIC-specific derivation on top.

- Implement RFC 9001 §5.2 initial-keys derivation in `wire/initial.zig`,
  using `boringssl.crypto.kdf.HkdfSha256.{extract, expand}`:
  - `initial_secret = HKDF_extract(initial_salt_v1, dcid)`
  - `{client,server}_initial_secret = HKDF_Expand_Label(initial_secret, "client in" / "server in", "", 32)`
  - `key = HKDF_Expand_Label(secret, "quic key", "", 16)`
  - `iv  = HKDF_Expand_Label(secret, "quic iv",  "", 12)`
  - `hp  = HKDF_Expand_Label(secret, "quic hp",  "", 16)`
- HKDF-Expand-Label (TLS 1.3 RFC 8446 §7.1) is a thin construction
  over HKDF-Expand: build the labeled `info` blob (length-prefixed
  "tls13 " + label + length-prefixed context) and call `expand`.
  This lives in `wire/initial.zig` as a private helper; if a second
  caller materializes (e.g. RFC 9001 §6 key updates), promote it.
- `boringssl-zig` v0.2.0 already KATs the QUIC v1 `initial_secret`
  derivation against §A.1; nullq re-runs it against the full
  initial-keys output for both client and server sides. Treat the
  upstream KAT as a smoke test, not as our acceptance.

**Acceptance:** RFC 9001 Appendix A vectors derive the exact
client/server `key`, `iv`, and `hp` listed in the RFC. KAT
comparison, byte-for-byte.

### Phase 3 — Packet protection (header + AEAD) ✓ (2026-05-03)

Implemented in [`wire/protection.zig`](src/wire/protection.zig).
- ✅ **AEAD nonce construction** (RFC 9001 §5.3) — left-pad PN to 12
  bytes big-endian, XOR with static IV.
- ✅ **AEAD seal/open** — `aeadSeal` / `aeadOpen` wrap
  `boringssl.crypto.aead.AesGcm128` with the constructed nonce;
  packet header is the AAD.
- ✅ **AES-128-ECB header-protection mask** (§5.4.3) — `aesHpMask`
  takes the 16-byte sample and returns the 5-byte mask via
  `boringssl.crypto.aes.Aes128.encryptBlock`.
- ✅ **HP application** — `applyHpMask` masks low 4 bits (long) or
  low 5 bits (short) of byte 0, plus 1..4 PN bytes; involutive XOR
  serves both protect and unprotect.
- ✅ **§A.2 HP mask KAT** — `aesHpMask(client_hp, sample=d1b1...dc9b)`
  produces the spec mask `437b9aec36` byte-for-byte. This is the
  load-bearing crypto verification: if HP key derivation, ECB
  encryption, or sample alignment were off, this test would fail.
- ✅ **Full pipeline end-to-end test** — synthesized packet → seal →
  HP-protect → sample → HP-unprotect → open round-trips correctly,
  exercising every primitive in sequence.

**Acceptance met (with one caveat):** the §A.2 HP mask KAT confirms
the HP path matches the spec exactly. The full 1200-byte byte-equal
protected-packet KAT is deferred until we vendor the spec's
ClientHello fixture into a separate `tests/rfc/rfc9001_appendix_A.zig`
file; transcribing 2400 hex chars inline invites typo bugs without
adding much over the HP-mask KAT plus the synthetic full-pipeline
test.

Cipher-suite coverage: AES-128-GCM only for now. AES-256-GCM follows
the same shape with `Aes256` (already in boringssl-zig v0.2.0);
ChaCha20-Poly1305 needs a single-block ChaCha20 primitive that's not
yet wrapped — both are bookmarked as future upstream PRs that fall
out naturally when the connection state machine selects a non-default
suite.

#### Original plan

### Phase 4 — TLS handshake glue ✓ (2026-05-03)

Two `nullq.Connection`s complete a TLS 1.3 handshake through an
in-memory mock transport
([tests/e2e/mock_transport_handshake.zig](tests/e2e/mock_transport_handshake.zig));
both reach the `application` encryption level for read and write
secrets, with ALPN selected and no alerts. 108/108 tests green.

Wired:
- [src/conn/state.zig](src/conn/state.zig) — `Connection` type with
  `initClient`/`initServer`, `bind` (separate from `init` because
  ex-data must be installed once the value sits at its stable
  address; otherwise the `&local` stashed in ex-data dangles after
  the return-by-value copy), `deinit`, `advance`, `handshakeDone`,
  `isQuic`, `haveSecret(level, dir)`, `setTransportParams`,
  `setEarlyDataContext`.
- [src/tls/level.zig](src/tls/level.zig) — `EncryptionLevel` enum
  with `fromBoringssl`/`toBoringssl` round-trip plus `Direction`
  (`read`/`write`) for indexing per-level state.
- `tls.quic.Method` static value + the five nullq callbacks
  (set_{read,write}_secret, add_handshake_data, flush_flight,
  send_alert), each recovering `*Connection` via
  `boringssl.tls.Conn.userDataFromSsl(ssl)`.
- Per-level inbox (16 KiB fixed) for CRYPTO bytes from the peer;
  drained one level at a time in `advance` since keys for level
  N+1 derive during processing of level N.
- Per-level `SecretMaterial` slots holding the cipher protocol-id
  and the secret bytes (Phase 5 will run HKDF-Expand-Label on them
  to derive packet-protection keys).

#### Original plan

- Implement nullq's concrete `tls.quic.Method` callbacks in
  `tls/handshake.zig`:
  - `set_read_secret` / `set_write_secret` → derive the
    AEAD/HP/IV keys for the given encryption level (using
    `boringssl.crypto.kdf.HkdfSha*` + nullq's HKDF-Expand-Label
    helper) and install them into the connection's protection
    table.
  - `add_handshake_data` → push outgoing CRYPTO bytes into the
    nullq packet number space's pending-CRYPTO-frame queue at
    the matching PN space.
  - `flush_flight` → mark the matched PN space's flight ready to
    coalesce into datagrams.
  - `send_alert` → translate to CONNECTION_CLOSE with TLS alert
    mapped to error code `0x100 + alert_value` (RFC 9001 §4.8).
- Recover the `*Connection` from the `*SSL` callback parameter via
  `tls.Conn.userDataFromSsl(ssl)` — the bridge's
  `setUserData`/`userData` infrastructure already covers this.
- Implement transport_parameters encoder/decoder in
  `tls/transport_params.zig` per RFC 9000 §18. Reserve registry
  slots for the multipath transport parameter (filled in Phase 10).
  Use `Conn.setQuicTransportParams` / `peerQuicTransportParams` to
  shuttle the encoded blob.
- Bake the **`early_data` encryption level** into `tls/level.zig`
  from day one — keys are not yet installed (that's Phase 8) but
  the level slot, the PN space mapping, and the read/write callback
  dispatch all handle the level. This avoids a refactor when 0-RTT
  lands.
- In-memory loopback test: two `nullq.Connection`s on a mock
  transport complete a TLS 1.3 handshake.

**Acceptance:** `tests/e2e/mock_transport_handshake.zig` — two nullq
connections handshake to TLS 1.3 finished, both export AEAD keys for
the application encryption level, and `Conn.isQuic()` returns true.
The `early_data` level exists in the level enum and a defensive
assert fires if any code tries to seal a packet at that level (since
no keys are installed yet). The `boringssl-zig` v0.3.0
`tests/quic_bridge.zig` test already validates the bridge ABI works;
this Phase 4 test is the higher-level "nullq drives the bridge
correctly through its own state machine" check.

### Phase 5 — Connection state machine

- Implement packet number spaces (`conn/pn_space.zig`).
- Implement ACK tracking and ACK frame generation
  (`conn/ack_tracker.zig`) per RFC 9000 §13.2.
- Implement loss recovery (`conn/loss_recovery.zig`) following
  RFC 9002 Appendix A pseudocode literally.
- Implement NewReno congestion control (`conn/congestion.zig`)
  following RFC 9002 §7 / Appendix B literally. Trait-based so BBR
  can drop in later.
- Implement flow control (`conn/flow_control.zig`) per RFC 9000 §4.
- Implement send/recv stream buffers and `Stream` API.
- **Path is a first-class value** (`conn/path.zig`): every packet is
  sent on a `*Path` and every received datagram resolves to one.
  The state machine holds an active-path *set* internally, but
  Phase 5 keeps that set at exactly one element. Per-path state:
  remote+local addr, peer+local CID, anti-amplification credit,
  validation status, RTT estimator, CC instance, PTO timer.
- **PATH_CHALLENGE / PATH_RESPONSE driver** (`conn/path_validator.zig`):
  full encode/decode + the validation state machine (issue a 64-bit
  random challenge, accept matching response, time out at 3× current
  PTO). Phase 5 doesn't *trigger* migration, but Phase 9 plugs into
  this driver without changes.
- Mock-transport e2e: two endpoints exchange streams, simulate loss,
  verify retransmission + ACK frequency match RFC 9002 expectations.

**Acceptance:**
- `tests/e2e/mock_transport_streams.zig` — open a bidirectional
  stream, write 16 MiB through one side, verify it arrives intact on
  the other side, with simulated 1% packet loss.
- `tests/e2e/mock_transport_loss.zig` — assert PTO triggers
  retransmission within 1 RTT + 4*rttvar of the loss.
- `tests/unit/path_validator_test.zig` — a path is brought from
  unvalidated → validated by exchanging matched challenge/response;
  mismatched response leaves it unvalidated; timeout marks failure.

### Phase 6 — POSIX UDP transport

- `transport/udp.zig` blocking adapter on top of `std.posix` socket
  syscalls. Non-blocking is a Phase-7 nicety; blocking is enough for
  the smoke client.
- CLI: `cli/qclient.zig` does HTTP/0.9 GET over hq-interop ALPN against
  cloudflare-quic.com or quic.nginx.org.

**Acceptance:** `just qclient https://cloudflare-quic.com/` returns a
non-empty response body. TLS verification on; certificate validates.

### Phase 7 — Server mode + interop

- Implement server-side: address validation token, Retry packet,
  version negotiation packet (RFC 9000 §17.2.5).
- `cli/qserver.zig` echo server.
- Wire up the [QUIC interop runner](https://github.com/marten-seemann/quic-interop-runner)
  test harness (Docker pull). Run `H`, `D`, `C`, `R`, `S`, `V`
  scenarios against ngtcp2, quiche, picoquic, msquic.

**Acceptance:** Pass `H` (handshake), `D` (transfer), `C` (close),
`R` (retry) against ngtcp2 *and* quiche.

### Phase 8 — 0-RTT (RFC 9001 §4.5/4.6)

Phase 4 already reserved the `early_data` encryption level. Phase 8
turns it on and wires the resumption flow.

- **Session ticket plumbing in boringssl-zig.** Add wrappers for
  `SSL_CTX_sess_set_new_cb` (or an equivalent capture API),
  `SSL_SESSION_to_bytes`, `SSL_SESSION_from_bytes`, `SSL_set_session`.
  These are general TLS 1.3 resumption — not QUIC-specific — so they
  belong upstream alongside the v0.2.0 AEAD/HKDF/AES wrappers. Plan:
  1. Land a `boringssl.tls.Session` API upstream that exports
     `Session.toBytes(allocator) []u8` and
     `Session.fromBytes(allocator, []const u8) !Session`, plus a way
     to register a "session received" callback on the client side.
  2. Tag a `boringssl-zig` v0.3.0 with the session API.
  3. nullq Phase 8 starts work behind a thin local
     `nullq/src/_bsslext/session_ticket.zig` shim against
     `boringssl.raw.zbssl_*` so we're not blocked on the upstream
     tag, then deletes the shim once v0.3.0 is consumable.
- **Server side** (`tls/early_data_context.zig`): call
  `SSL_set_quic_early_data_context` with a context blob covering
  every transport parameter that affects 0-RTT semantics (per
  RFC 9001 §4.6.1). Without a non-empty context, the server must
  refuse 0-RTT — encode that as a hard assertion.
- **Client side** (`conn/early_data.zig`): expose
  `Endpoint.connectWithSession(session_blob, ...)`. State machine:
  `attempting` → `accepted` (peer signaled accept_early_data) or
  `rejected`. On rejection, all early-data stream bytes are
  re-queued at the application encryption level — the embedder
  doesn't see a stream "rewind"; it sees the same bytes delivered
  reliably, just later.
- **Replay-safety contract.** Every received `Stream` and (Phase
  11 if we ever do datagrams) every Datagram carries an
  `arrived_in_early_data: bool` flag. nullq does not invent a
  policy; the embedder decides what's idempotent.
- **Anti-replay via early-data context.** Document the contract
  loudly in `tls/early_data_context.zig`: the server's context blob
  must include any application-layer settings that change
  semantics, or the client's 0-RTT bytes can be replayed against a
  divergent server config.

**Acceptance:**
- `tests/e2e/mock_transport_0rtt.zig` — three-step test:
  1. Client connects, server issues a NewSessionTicket, client
     exports a session blob, server tears down.
  2. Client reconnects with the blob, sends 4 KiB of stream data
     before handshake completes, server accepts 0-RTT, the bytes
     arrive on a stream marked `arrived_in_early_data = true`.
  3. Same blob but the server's early-data context has changed →
     server rejects 0-RTT → client's queued bytes are delivered at
     1-RTT, semantics preserved, no data loss, no duplicate delivery.
- Interop runner `Z` (zero-RTT) test passes against ngtcp2 and quiche.

### Phase 9 — Connection migration (RFC 9000 §9)

The `Path` type and validator from Phase 5 are real. Phase 9 turns
on path *switching*.

- **Active-path set widens to two during validation.** Both old and
  new paths can carry traffic; only the validated one carries
  *new* application data. PATH_CHALLENGE on the new path; ACKs and
  retransmits continue on the old path until the new one is
  validated.
- **Server-side detection** (`conn/state.zig`): when a packet
  arrives on a 4-tuple that doesn't match any known path *but*
  uses an active DCID we've issued, treat it as a peer-initiated
  migration. Issue PATH_CHALLENGE on the new path; obey
  per-path anti-amplification (3× received) until validated.
- **Client-side initiation:** add `Connection.migrate(local_addr,
  peer_addr)` API. Issues a fresh local CID via NEW_CONNECTION_ID,
  binds the new socket, validates, switches.
- **Congestion controller reset on switch** per RFC 9000 §9.4 —
  new `Path` gets a fresh `Congestion` instance; the old one is
  dropped (or kept frozen for a draining period).
- **Connection ID dynamics:** ensure NEW_CONNECTION_ID and
  RETIRE_CONNECTION_ID frame logic in `conn/ids.zig` honors the
  `active_connection_id_limit` transport parameter. Migration
  costs CIDs; retire them on the path that's gone away.
- **NAT rebinding** is the same code path as peer-initiated
  migration with a slightly different trigger (peer's source
  address changed, but their DCID didn't). Test it explicitly.

**Acceptance:**
- `tests/e2e/mock_transport_migration.zig` — three sub-cases:
  1. Mid-flight NAT rebind: peer's UDP source port changes; data
     transfer continues without loss.
  2. Active client migration: client API call relocates to a new
     local socket; server validates path; new data flows on new
     path, old path drains.
  3. Failed validation: peer responds incorrectly to PATH_CHALLENGE;
     state remains on old path; idle timeout cleans up.
- Interop runner `M` (migration) passes against ngtcp2 and quiche.

### Phase 10 — Multipath QUIC (draft-ietf-quic-multipath)

Major architectural step. The single-path code from Phases 5–9 was
written with `Path` already first-class; Phase 10 widens the active
set, splits PN spaces, and adds a scheduler.

- **Capability negotiation** (`conn/multipath/capability.zig`): the
  multipath transport parameter (exact codepoint per current draft).
  Both endpoints must advertise; otherwise behavior stays single-path.
- **Per-path application PN spaces** (`conn/pn_space.zig` widens):
  initial and handshake PN spaces stay singular; the application PN
  space splits into one per active path. Each path tracks its own
  largest received PN, ack delays, and retransmission queue.
- **Path identifiers** (`conn/multipath/path_id.zig`): per the draft,
  paths are named via a path-id varint. Map path-id ↔ `*Path`.
- **Multipath frames** (`frame/types.zig`, `frame/decode.zig`,
  `frame/encode.zig`): ADD_ADDRESS, REMOVE_ADDRESS, PATH_ABANDON,
  multipath-aware ACK_MP — exact set per the latest stable draft.
  Pin the draft revision in a comment at the top of the file.
- **Per-path loss recovery and CC** (`conn/loss_recovery.zig` and
  `conn/congestion.zig` already key off `*Path`): no change to their
  internal pseudocode, just allocated once per active path.
- **Cross-path coordination policy**
  (`conn/multipath/coordinator.zig`): the draft leaves CC
  coordination implementation-defined. Implement two policies as a
  trait: `independent` (each path has its own NewReno; default) and
  `sum` (cwnd shared across paths via a coupled controller). Default
  is `independent`; `sum` is opt-in.
- **Path scheduler** (`conn/path_scheduler.zig` becomes real):
  default strategy is "lowest-latency available with cwnd". Pluggable
  via a trait so apps can use round-robin, redundant, or app-specific.
- **Frame routing:** stream frames can go on any validated path;
  ACK_MP frames travel on the path whose PN they cover (or anywhere,
  per draft). Path-bound frames (PATH_CHALLENGE, etc.) go on their path.

**Acceptance:**
- `tests/e2e/mock_transport_multipath.zig`:
  1. Two paths come up with asymmetric RTT (10 ms / 50 ms) and 0% loss;
     a stream's bytes arrive in order; total throughput exceeds
     single-path-fast within a smoothed-RTT envelope.
  2. The 10 ms path drops at midflight; data continues on the 50 ms
     path; loss recovery does not stall.
  3. `enable_multipath` is *not* advertised by the peer → connection
     stays single-path, no multipath frames are sent.

### Phase 11 — Stretch / nice-to-haves

Not blockers for v0.1. Pick based on demand:

- **RFC 9221 DATAGRAM frames** — useful for transport-only tests and
  certain real-time apps.
- **RFC 9287 bit-greasing** — one-line interop niceness.
- **RFC 9368 v2 negotiation** — when other implementations start
  rolling out QUIC v2.
- **ECN** (RFC 9000 §13.4) — congestion signaling.
- **DPLPMTUD** (RFC 8899) — beyond the 1200-byte baseline.
- **BBRv2 / CUBIC** congestion control behind the existing trait.
- **Performance:** GSO/GRO, recvmmsg, kTLS, zero-copy AEAD nonce.

## Testing strategy

Three kinds of tests, each with explicit purposes:

### 1. RFC vector KATs

For every RFC appendix that has test vectors, write a test that
produces them byte-for-byte. These are the gold standard for
correctness because any deviation is unambiguously a bug.

- RFC 9000 Appendix A — packet number recovery.
- RFC 9001 Appendix A — Initial keys + protected Initial.
- RFC 9001 Appendix B — ChaCha20-Poly1305 short header.
- RFC 9001 Appendix C — Retry integrity tag.

### 2. Mock-transport e2e

Two `nullq.Connection`s connected by an in-memory `Transport` that
delivers datagrams in order, with optional loss/reorder/delay
injection. Run by a deterministic clock. This gives us bug-isolating
e2e coverage with no network.

The mock transport extends through every phase:

- **Phase 5:** single-path, loss/reorder/delay injection.
- **Phase 8:** ticket capture/replay across two distinct connections;
  controlled mismatched-context to force 0-RTT rejection.
- **Phase 9:** address-rewriting (rebind) and dual-socket (migration)
  scenarios; per-path delay/loss for asymmetric path tests.
- **Phase 10:** N-path topology with per-path delay/loss, hot
  un-plugging of paths, capability advertisement on/off.

Keeping every regression in this hermetic harness is what makes the
project tractable as it grows; a bug found by interop should always
be reproducible here too.

### 3. Interop runner

The IETF interop runner runs scenario tests across all major QUIC
implementations. Phase 7 acceptance gates on `H/D/C/R`; Phase 8 adds
`Z` (zero-RTT); Phase 9 adds `M` (migration); Phase 10 doesn't have a
runner test of its own (multipath is not yet a runner scenario), so
its acceptance is the mock-transport tests plus interop with quiche
or msquic's experimental multipath mode where available.

### Property tests (where applicable)

Zig has no QuickCheck, but we can write generators for varints,
packet numbers, and frame sequences and assert round-trip invariants.
`std.testing.fuzz` (Zig 0.16) covers byte-input fuzzing; for
structured generation we hand-roll generators using `std.Random`.

## Toolchain

Mirror boringssl-zig's `mise.toml` so the same `mise install` works
in either repo:

```toml
[tools]
zig  = "0.16.0"
just = "1.49.0"
```

(BoringSSL toolchain — cmake/ninja/go — is *not* needed in nullq;
the dependency is a build artifact that boringssl-zig produces.)

## Risks & open questions

1. **boringssl-zig wrapper coverage.** Phase 4's QUIC bridge
   (boringssl-zig v0.3.0) and Phase 8's session ticket plumbing
   (v0.4.0) and Phase 11's ChaCha20 / keylog (v0.5.0) are all
   upstream as of 2026-05-03. No `_bsslext/` shim is required.
   Future risk: any unwrapped surface that turns up later (e.g.
   custom verify callbacks for mTLS interop) goes through the same
   path — vendor a thin shim, then PR upstream.

2. **`SSL_QUIC_METHOD` callback shape.** BoringSSL's callbacks pass
   a `void*` user data via the SSL ex-data slot. We'll need to
   round-trip a `*Connection` through that slot safely. Standard
   pattern but worth a small spike before Phase 4.

3. **`std.Io` Writer shape in 0.16.** The non-blocking writer pattern
   used elsewhere in the std library evolved between 0.14 and 0.16.
   The connection's `pollOutgoing` is a value-returning API rather
   than a Writer-into, which sidesteps this — but if we want to
   stream into a user-provided buffer we'll need to pick a Writer
   shape that matches 0.16 idioms. Decide in Phase 5.

4. **PMTU & 1200-byte minimum.** RFC 9000 mandates the path can
   carry 1200-byte UDP datagrams. We'll hard-code that for v0.1
   (no PMTU discovery). Defer DPLPMTUD to Phase 11.

5. **Anti-amplification.** Server-side rule (RFC 9000 §8.1) — the
   server cannot send more than 3× what it has received from an
   un-validated client. Easy to forget. Bake it into the send pacer
   from the start.

6. **Test data sources for RFC appendix vectors.** Some appendices
   have copy-paste-friendly hex; some have descriptive prose. We may
   need to cross-check against ngtcp2's test fixtures to disambiguate
   in a couple of places. Note this when writing the KAT file.

7. **Time source.** Zig 0.16's `std.time.Instant` is acceptable for
   the realtime clock; the abstraction layer (`util/time.zig`) keeps
   us insulated if it changes.

8. **Multipath draft volatility.** draft-ietf-quic-multipath has
   gone through several non-backward-compatible revisions (PN-space
   model, frame layout, transport parameter codepoint). Phase 10
   pins a specific revision in source; bumping it is a deliberate
   PR. We do not pretend the multipath surface is stable until the
   IETF publishes an RFC.

9. **0-RTT replay-safety contract.** nullq exposes
   `arrived_in_early_data` per stream/datagram and stops there.
   What's idempotent is application policy. Document this loudly in
   `early_data.zig`'s module header — failure to read it is how
   embedders get themselves into trouble.

10. **Server `quic_early_data_context` discipline.** Forgetting to
    call `SSL_set_quic_early_data_context` on the server quietly
    disables 0-RTT. Even worse, calling it with a *too-narrow*
    context allows replay attacks against application-layer state
    that should have been covered. Encode as a hard assertion: if
    the server enables `accept_early_data` without setting a
    non-empty context, refuse to start.

11. **Per-path anti-amplification accounting.** Server-side
    anti-amplification (RFC 9000 §8.1) applies *per path*, not per
    connection. A migrating peer resets the credit. Easy to leak.
    The `Path` value owns its own credit counter from Phase 5 —
    don't aggregate at the connection level.

12. **NEW_CONNECTION_ID supply during migration.** Migration
    consumes CIDs. If `active_connection_id_limit` is too low or
    we issue too slowly, the peer can't migrate. Phase 9 should
    issue CIDs eagerly up to the limit and re-fill on retirement.

13. **Path scheduler behavior under partial failure.** When a path
    silently dies (no PATH_RESPONSE within PTO budget), the
    scheduler must stop sending on it before loss recovery
    declares all in-flight packets lost — otherwise the CC dump
    on the dead path triggers spurious retransmissions on the
    survivor. Bake into the scheduler trait that "path is dead"
    is a separate signal from "path is congested".

14. **Multipath CC coordination.** The default of independent
    per-path NewReno is safe but suboptimal — flows can race each
    other on shared bottlenecks. The `sum` policy is closer to
    what production deployments want but requires care around
    fairness with non-multipath flows. Default to `independent`,
    let users opt in.

15. **Pinning boringssl-zig at a tag vs. tracking the path dep.**
    During Phases 1–4 we move in lockstep with boringssl-zig (we
    needed v0.2.0; we'll need v0.3.0 for session tickets). A path
    dep is right for that period. After Phase 5 the contact patch
    with boringssl-zig stabilizes and pinning to a tag (URL+hash)
    avoids surprise breakage from upstream refactors. Switch
    deliberately, not by drift.

## Out-of-scope discipline

The biggest risk to a multi-month QUIC project is scope creep into
HTTP/3, QPACK, or "just one more" RFC. nullq is the transport. If
something is in the "Mandatory for v0.1" or the explicit Multipath
goal section above, it's in scope; everything else (HTTP/3, QPACK,
DPLPMTUD, ECN, BBR, perf optimizations) is Phase 11 or a sibling
repo. Period.

When in doubt, write the question down here and keep going.

## What this document is not

This document is a **plan**. It is not:

- A line-by-line spec for every API (those land in module headers).
- A schedule (each phase takes as long as it takes).
- A guarantee about decisions for unwritten phases (Phase 8 may
  reorder; Phase 5's CC trait shape may change once we feel the
  contact patch with NewReno).

When the plan and the code disagree, the code wins — but update the
plan in the same PR.

[1]: https://www.rfc-editor.org/rfc/rfc8999  "RFC 8999 - QUIC: Version-Independent Properties"
[2]: https://www.rfc-editor.org/rfc/rfc9000  "RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport"
[3]: https://www.rfc-editor.org/rfc/rfc9001  "RFC 9001 - Using TLS to Secure QUIC"
[4]: https://www.rfc-editor.org/rfc/rfc9002  "RFC 9002 - QUIC Loss Detection and Congestion Control"
[5]: https://www.rfc-editor.org/rfc/rfc9221  "RFC 9221 - An Unreliable Datagram Extension to QUIC"
[6]: https://www.rfc-editor.org/rfc/rfc9287  "RFC 9287 - Greasing the QUIC Bit"
[7]: https://github.com/marten-seemann/quic-interop-runner
