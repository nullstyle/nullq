# Changelog

All notable changes to nullq are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. Until then, any release in the `0.x` line may include
breaking changes; see notes per release.

## [Unreleased]

### Added
- `Connection.setMigrationCallback` and the `MigrationCallback` /
  `MigrationDecision` types — an embedder policy hook gating peer
  migrations to a new 4-tuple (RFC 9000 §9). The callback fires
  synchronously on the existing path's auth context **before**
  PATH_CHALLENGE / PATH_RESPONSE so that pure address-allowlist
  policies don't pay for a validation round-trip. Returning `.deny`
  drops the migration attempt, credits the triggering datagram
  against the existing path's anti-amp, and emits a
  `migration_path_failed` qlog event with reason `policy_denied`;
  the connection stays open on the original 4-tuple. Re-exported as
  `nullq.MigrationCallback` / `nullq.MigrationDecision`.
- `QlogMigrationFailReason` enum (`timeout`, `policy_denied`) and
  matching optional `migration_fail_reason` field on `QlogEvent`.
  Existing `migration_path_failed` emit sites now populate
  `.timeout`; the new `policy_denied` value comes from the
  migration-callback deny path.
- `nullq.Server.Slot` distributed-tracing surface for embedders
  building W3C tracecontext / OpenTelemetry pipelines. Each slot now
  carries a server-local monotonic `slot_id: u64` stamped at accept
  time (stable for the slot's lifetime, suitable as the primary key
  in operational logs without depending on peer-chosen CIDs), plus
  optional `trace_id: ?[16]u8` and `parent_span_id: ?[8]u8` fields
  the embedder attaches via the new `Slot.setTraceContext(trace_id,
  parent_span_id)` method. nullq treats both as opaque metadata —
  they are never read or forwarded into qlog or onto the wire.
- `nullq.Server.replaceTlsContext` — graceful, hot-swappable TLS
  context reload. Accepts either fresh PEM bytes (rebuilt with the
  Server's existing ALPN preference list and TLS-1.3 defaults) or a
  caller-built `boringssl.tls.Context` via the new `Server.TlsReload`
  union. The pre-swap context is moved into a draining list with a
  refcount equal to the live slots that opened against it; existing
  slots keep their per-connection SSL handle (BoringSSL's `SSL_new`
  up-ref keeps the underlying `SSL_CTX` alive across the swap). On
  each successful `Server.reap`, draining contexts whose refcount
  hits zero are torn down. `Server.deinit` cleans up any still-live
  draining entries. Resumption note: tickets minted under the old
  context cannot decrypt under the new one (different key material);
  embedders that need cross-reload resumption must manage ticket
  keys themselves and pass the rebuilt context via the `.override`
  variant. See `src/server.zig` and the tests in
  `tests/e2e/server_smoke.zig`.

## [0.1.0-pre.1] - 2026-05-05

First tagged pre-release. The transport passes the full quic-go
interop matrix (`H, DC, C20, S, R, Z, M`); public Zig API is still
expected to churn before `0.1.0` final.

### Added
- `nullq.Server` production-grade convenience wrapper for embedding
  nullq as a UDP server. Owns the TLS context and a CID-to-slot
  routing table; the embedder owns the socket and clock. Config /
  Slot / feed / poll / tick / reap / iterator. The router resyncs
  each slot's CID set from `Connection.localScids` after every
  `feed`, so NEW_CONNECTION_ID-issued SCIDs route from the next
  datagram on (RFC 9000 §5.1.1). Lookup is `std.AutoHashMap` O(1).
  Per-source-address Initial-acceptance rate limiter is opt-in via
  `Config.max_initials_per_source_per_window` and surfaces a
  distinct `FeedOutcome.rate_limited` variant. See `src/server.zig`
  and the `README.md` "Embed nullq as a server" section.
- `nullq.Server` Version Negotiation and stateless Retry gates,
  surfaced through new `FeedOutcome.version_negotiated` /
  `FeedOutcome.retry_sent` variants and a new
  `Server.drainStatelessResponse` method. Version Negotiation is
  unconditional (RFC 9000 §6 / RFC 8999 §6) — any long-header
  packet with version != `nullq.QUIC_VERSION_1` queues a VN
  response listing QUIC v1. Retry is opt-in via
  `Config.retry_token_key` (32-byte HMAC-SHA256 key); when set,
  the first Initial from a peer earns a stateless Retry packet
  bound to (peer_addr, original_dcid, retry_scid, mint_time) per
  RFC 9000 §8.1.2, and no `Connection` is allocated until the
  peer echoes back a valid token. `Config.retry_token_lifetime_us`
  defaults to 10 s. Stateless responses queue on the `Server` and
  the embedder drains them via `drainStatelessResponse`; the queue
  is bounded at 64 entries with oldest-evicted-on-overflow. The
  legacy QNS endpoint loop at `interop/qns_endpoint.zig` retains
  its bespoke version of these flows for interop fixtures, but new
  embedders can rely on `Server` for both.
- `nullq.Client` convenience wrapper for embedding nullq as a QUIC
  client. Mirror to `nullq.Server`: builds a client-mode TLS
  context, generates the per-connection random initial DCID and
  SCID (RFC 9000 §7.2), and runs `bind` / `setLocalScid` /
  `setInitialDcid` / `setPeerDcid` / `setTransportParams` in the
  right order, returning a heap-allocated `*Connection` ready for
  the first `advance` / `poll`. Optional `Config.session_ticket`
  wires up resumption + 0-RTT in one step. See `src/client.zig` and
  the `README.md` "Embed nullq as a client" section.
- `nullq.transport.runUdpServer` — opinionated `std.Io`-based UDP
  server loop that binds the socket, applies `SO_RCVBUF` / `SO_SNDBUF`
  tuning, drives the `feed` / `pollDatagram` / `tick` / `reap`
  cadence on a 5 ms heartbeat, and shuts down cleanly when a
  caller-supplied `std.atomic.Value(bool)` flag flips. Intended as
  the fastest path from `nullq.Server.init` to a working QUIC
  endpoint. The QNS endpoint and other embedders that need full
  control (Retry, version negotiation, deterministic CIDs) keep
  driving the I/O-agnostic Server interface directly. See
  `src/transport/udp_server.zig` and the README "Embed nullq as a
  server" section.
- `Connection.localScidCount`, `Connection.localScids`, and
  `Connection.ownsLocalCid` for embedders that maintain a
  CID-to-connection routing table outside the connection
  (`nullq.Server` is the canonical caller).
- Public-API documentation pass: every `pub fn` / `pub const` /
  `pub var` in `src/conn/`, `src/frame/`, `src/tls/`, `src/transport/`,
  and `src/wire/` (713 declarations) now carries a 1-3 line `///`
  doc comment, with RFC section references where the declaration
  implements a specific protocol requirement (RFC 9000, 9001, 9002,
  9221, draft-ietf-quic-multipath-21).
- 14 new qlog event variants (`packet_sent` / `packet_received` /
  `packet_dropped` / `packet_lost`, `loss_detected`,
  `congestion_state_updated`, `metrics_updated`, `parameters_set`,
  `migration_path_validated` / `migration_path_failed`,
  `connection_started` / `connection_state_updated`,
  `stream_state_updated`, `key_updated`). Per-packet events are
  opt-in via `Connection.setQlogPacketEvents(true)` to keep the
  default cost off the hot path.
- `PathStats` now surfaces `total_bytes_sent`, `total_bytes_received`,
  `packets_sent`, `packets_received`, `packets_lost`, `srtt_us`,
  `rttvar_us`, `min_rtt_us`, `ssthresh`, and `congestion_window_state`.
- `zig build bench` step with 9 ReleaseFast wire/frame microbenchmarks
  (varint enc/dec, STREAM enc/dec, ACK enc/dec, short-header enc/dec,
  CID generation). See `bench/main.zig` and `bench/README.md`.
- `.github/workflows/test.yml`: matrix build/test on ubuntu-latest and
  macos-latest with Zig 0.16.0.
- `.github/workflows/interop.yml`: weekly QNS interop run against the
  official `quic-interop/quic-interop-runner` (server role, `H,DC,M`
  against quic-go, quiche, ngtcp2). Marked `continue-on-error` since
  interop is environment-sensitive and not a hard merge gate.

### Changed
- `boringssl-zig` is now a URL+hash dep pinned to a specific upstream
  commit (currently `8c47b6e`, post-v0.5.0). External consumers can
  build nullq without a sibling boringssl-zig checkout. Bumping the
  pin is a `zig fetch <url>` + commit.
- Stateless reset token comparison uses
  `std.crypto.timing_safe.eql` instead of `std.mem.eql`, closing
  the timing side-channel called out in RFC 9000 §10.3.
- All 15 `unreachable` / `@panic` sites in `src/` were audited; the
  9 reachable-from-input arms in `src/wire`, `src/conn/path`, and
  `src/conn/retry_token` are now annotated with `// invariant:`
  comments documenting why each is unreachable from peer input.
  None are peer-reachable.

### Notes
- nullq remains pre-1.0 (`0.0.0` in `build.zig.zon`). The transport is
  feature-rich and passes a substantial QNS interop matrix (see
  `INTEROP_STATUS.md`), but the public Zig API is still expected to
  churn before the first tagged release.

## [0.0.0] - pre-release development

This section summarizes the work that has shipped on `main` to date,
prior to any tagged release. It is grouped by theme rather than by
commit. See `git log` for the full history.

### Added
- **IETF QUIC v1 transport.** Implementation of RFCs 8999, 9000, 9001,
  and 9002: long/short-header packet protection, all v1 cipher suites
  (`AES_128_GCM_SHA256`, `AES_256_GCM_SHA384`,
  `CHACHA20_POLY1305_SHA256`), packet number encoding, ACK frames with
  bounded range emission, NewReno congestion control, RTT estimation,
  and PTO-driven loss recovery.
- **QUIC interop-runner endpoint (`qns-endpoint`).** Server-side
  HTTP/0.9 `hq-interop` endpoint plus driver tooling for running the
  official `quic-interop/quic-interop-runner` matrix
  (`zig build external-interop -- runner ...`). The server endpoint
  passes `H` (handshake), `DC` (transfer/chacha), `C20`, `S` (retry),
  `R` (resumption), `Z` (0-RTT), and `M` (multiplexing) against
  `quic-go`. See `INTEROP_STATUS.md` for the full matrix.
- **0-RTT (RFC 9001 §4.5/4.6).** Early STREAM/DATAGRAM transport
  plumbing, accepted/rejected resumption smokes, replay context
  binding to transport+application params, and rejection requeue
  coverage. QNS client supports resumption and 0-RTT against quic-go.
- **Connection migration.** PATH_CHALLENGE/PATH_RESPONSE,
  path-validator state machine, NAT rebinding hardening, migration
  rollback, CID retirement on path change, and stateless reset token
  handling.
- **Multipath QUIC (draft-ietf-quic-multipath-21, partial).**
  `initial_max_path_id`, `multipath_draft_version = 21`, draft-21
  nonce/CID routing checks, embedder-driven CID replenishment,
  abandoned-path 3x-PTO retention, and a deterministic two-path
  transfer stress test. Expect API churn here until the draft
  becomes an RFC.
- **HyStart++ slow-start exit (RFC 9406).** Adds an exit signal to
  NewReno slow start to avoid overshoot at the start of a connection.
- **Retry and Version Negotiation.** Stateless `retry_token` HMAC
  helper, `writeRetry` / `writeVersionNegotiation` for server
  embedders, client-side validation of CID echoes, retry integrity
  tags, and retry transport parameters with Initial CRYPTO re-arm.
  Live quic-go Retry and v2-to-v1 VN scenarios are exercised.
- **Application key updates.** Previous/current/next read epoch
  retention, 3x-PTO discard, locally-initiated rotation, and
  cross-suite AEAD packet/auth-limit enforcement on all Application
  paths.
- **Close lifecycle.** `closeState()`, sticky `closeEvent()` status,
  `pollEvent()` notifications, draining suppression of incoming
  packets, and clean stateless-reset shutdown.
- **DATAGRAM extension.** Send/receive plumbing with ack and loss
  events exposed to embedders.
- **Diagnostics.** TLS keylog re-export
  (`nullq.KeylogCallback`) and qlog-style application key-update
  callbacks.
- **Deterministic fuzz smokes.** `zig build test` now runs property
  smokes for varints, frames, transport parameters, packet headers,
  ACK ranges, and CRYPTO/STREAM reassembly.

### Hardening (production sweep)
The "production hardening" line of work tightens the transport against
adversarial peers and lossy paths. Notable items:
- **Anti-amplification.** The 3x cap is enforced on every send from an
  unvalidated path, not only the initial flight.
- **RETIRE_CONNECTION_ID validation.** Frames referencing
  unassigned sequence numbers are now rejected
  (PROTOCOL_VIOLATION).
- **ACK validation.** ACK frames claiming packet numbers we never sent
  are rejected.
- **Persistent congestion filter.** Persistent-congestion detection
  only considers ack-eliciting losses, matching RFC 9002.
- **Socket buffer tuning.** QNS endpoint raises SO_RCVBUF/SO_SNDBUF
  to absorb open-internet bursts under interop runner load.
- **Bounded allocation policy.** Explicit caps on receive windows,
  stream counts, path IDs, CID fanout, DATAGRAM queues, CRYPTO gaps,
  and advisory `*_BLOCKED` tracking. UDP payload bounds are
  enforced.
- **Transport-parameter parsing.** Stricter handling: rejects
  client-sent server-only parameters, duplicate parameters, and
  invalid `preferred_address` payloads. Close errors use transport
  parameter codes.
- **Flow-control hardening.** Receive flow-control updates are paced;
  blocked-frame backpressure plumbed through the embedder API.
- **Stream credit batching.** MAX_STREAMS issuance batched and
  duplicate-at-cap suppressed.
- **Migration / CID hardening.** CID replenishment and rebinding drain
  ordering now correct under abandoned paths and post-migration loss.

### Known gaps
- HTTP/3, QPACK, Windows targets, FIPS mode, ECN, DPLPMTUD, and BBR
  are explicitly out of scope for v0.1.
- Multipath tracks an in-flight draft and will need updates as the
  draft converges with the RFC.
- 0-RTT mismatch/loss hardening still has open work.

[Unreleased]: https://github.com/nullstyle/nullq/compare/v0.0.0...HEAD
[0.0.0]: https://github.com/nullstyle/nullq
