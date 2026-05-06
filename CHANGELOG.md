# Changelog

All notable changes to nullq are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. Until then, any release in the `0.x` line may include
breaking changes; see notes per release.

## [Unreleased]

(no changes since v0.2.0)

## [0.2.0] - 2026-05-06

A production-posture release. Substantial pass against
`hardening-guide.md` §3 (Zig safety), §4 (QUIC transport), §5 (TLS /
0-RTT), §8 (resource exhaustion), §9 (info disclosure), §11 (fuzz
coverage), §12 (defaults). Twenty-plus commits closed the bulk of
the original audit's open items; defaults are now secure-out-of-box;
opt-in production knobs are documented in `README.md`'s "Production
posture" section.

See also `docs/hardening-status.md` for the per-§ COMPLETE / PARTIAL /
DEFERRED scorecard, and `docs/fuzz-coverage.md` for the fuzz-target
inventory (now 19 coverage-guided harnesses).

### Hardening (security-relevant)

- §3.1 — Build-mode policy as a top-of-file comment block in
  `build.zig`: `-Doptimize=ReleaseSafe` mandatory for production /
  internet-facing builds; `ReleaseFast` / `ReleaseSmall` forbidden
  for the network-input parser surface (residual `unreachable`
  invariants would stop being trapped). Commit `1a7ec80`.
- §3.2 / §3.3 — Safety-wrapper sweep: `retryIntegrityTag` AEAD ABI
  drift converted from `assert` to typed `Error.OutputTooSmall`;
  oversized-CID inline-buffer paths in `path.zig` and `server.zig`
  clamped via `@min`; flow-control `+` on peer-controlled values
  switched to `std.math.add`. Commit `0457262`.
- §3.5 / §9.4 — `secureZero` Retry-token HMAC key, NEW_TOKEN AEAD
  key, TLS traffic secrets, packet protection keys, and
  stateless-reset tokens at Connection / Server `deinit`. Commit
  `a167068`.
- §3.5 / §8 — `Server.Config.max_connection_memory`
  (default 32 MiB) caps peer-driven CRYPTO / STREAM / DATAGRAM /
  pending-frame / ack-tracker resident memory per Connection;
  `bytes_resident` accounting gates every reassembly write. Commit
  `426a222`.
- §4.1 — RFC 9000 §14 1200-byte minimum on Initial-bearing UDP
  datagrams, with `feeds_initial_too_small` MetricsSnapshot counter.
  Commit `e5ce8d0`.
- §4.1 — Listener-level packet-rate limit
  (`Server.Config.max_datagrams_per_window`) plus
  `feeds_listener_rate_limited` counter. Commit `426a222`.
- §4.1 — Listener-level byte-rate limit
  (`Server.Config.max_bytes_per_window`) plus
  `feeds_listener_byte_rate_limited` counter. Commit `1dceea5`.
- §4.1 — Per-source bandwidth shaping via token-bucket. New
  `Server.Config.max_bytes_per_source_per_second` (null-default)
  with one-second burst capacity; drops surface in
  `feeds_source_bandwidth_limited`. Charged AFTER the global
  listener gates so the aggregate ceiling still bounds total
  bandwidth even when every source has a full bucket. Commit
  `0b12ad7`.
- §4.3 — Retry token format encrypt-then-authenticate with
  AES-GCM-256: 96-byte fixed wire size (12-byte nonce + 68-byte
  ciphertext + 16-byte tag); plaintext zero-padded so every minted
  token is a uniformly random opaque blob. Domain separator bumped
  to `"nullq retry token v2"`. Plus `fuzz: retry_token validate
  never panics`. Commit `474a71b`.
- §4.4 — Per-source Version Negotiation rate limit
  (`vn_count` / `vn_window_start_us`, default 8/window) on
  `SourceRateEntry` with independent counter axis from Initial rate
  limit. New `feeds_vn_rate_limited` MetricsSnapshot counter. Commit
  `b22ebee`.
- §4.5 — Server / Retry SCIDs minted directly from BoringSSL CSPRNG
  (`boringssl.crypto.rand.fillBytes`); the seed-once
  `std.Random.DefaultPrng` ceremony is gone. Commit `2137f77`.
- §4.5 — `nullq.conn.stateless_reset` default-safe HMAC-SHA256
  derivation helper for stateless-reset tokens (Key /
  derive(key, cid) / generateKey()) with domain separator
  `"nullq stateless reset v1"`. Commit `030b9fe`.
- §4.7 — Cap incoming ACK / PATH_ACK `range_count` at 256
  (`max_incoming_ack_ranges`) before iteration; new
  `Error.AckRangeCountTooLarge`. Commit `3a64820`.
- §4.7 — Reject overlapping ranges inside ACK / PATH_ACK frames at
  decode time. Commit `0baa170`.
- §4.8 — Pre-handshake migration drop in
  `recordAuthenticatedDatagramAddress` plus per-path PATH_CHALLENGE
  rate limit (`min_path_challenge_interval_us = 100 ms`). New
  `QlogMigrationFailReason` variants `.pre_handshake` and
  `.rate_limited`. Commit `a4b2a3b`.
- §5.2 — 0-RTT default-off:
  `Server.Config.enable_0rtt: bool = false`; client-side
  `early_data_enabled` follows `config.session_ticket != null`
  rather than always-on. Commit `0457262`.
- §5.2 / RFC 9001 §5.6 — `nullq.tls.AntiReplayTracker` primitive:
  bounded LRU with time window (default 4096 entries / 10 minutes),
  `consume(id, now_us) → .fresh | .replay`, opaque
  `Id = [32]u8`. Commit `108180a`.
- §5.2 — TLS-pre-accept BoringSSL trampoline wires
  `AntiReplayTracker` through `Server.Config.early_data_anti_replay`
  via `SSL_CTX_set_allow_early_data_cb`. Replay verdict denies
  early data at the TLS layer rather than post-handshake.
  `AntiReplayTracker.bumpClock(now_us)` /
  `consumeUsingInternalClock(id)` give the trampoline a path to
  monotonic time. Commit `7fc58b6`.
- §8 — Per-stream send-queue cap
  (`SendStream.max_buffered`, default 1 MiB,
  `default_max_buffered_send`); `write` short-writes to apply
  back-pressure when the cap is hit. Commit `23c925f`.
- §8 — Cite `max_datagrams_per_event_loop_tick = 1` policy
  explicitly via the `max_datagrams_per_loop_iteration` constant in
  `src/transport/udp_server.zig`. Commit `bb68404`.
- §9 / §12 — CONNECTION_CLOSE `reason_phrase` redacted on the wire
  by default (`reveal_close_reason_on_wire: bool = false` on
  Connection / `Server.Config` / `Client.Config`). Local introspection
  unaffected — sticky `lifecycle.record(...)` and `closeEvent` still
  carry the full reason. Commit `adfbba2`.
- §9.4 — Per-source log-event rate limit
  (`Server.Config.max_log_events_per_source_per_window`, default
  16/window). New `feeds_log_rate_limited` MetricsSnapshot counter.
  Commit `426a222`.

### Features

- §4.3 — NEW_TOKEN issuance pipeline (RFC 9000 §8.1.3):
  `Server.Config.new_token_key` / `Server.Config.new_token_lifetime_us`
  (default 24h), `Client.Config.new_token` /
  `Client.Config.new_token_callback` / `new_token_user_data`,
  `nullq.conn.new_token` module with AES-GCM-256-sealed token
  format (96-byte wire shape mirroring v2 Retry tokens with a
  distinct domain separator and address-only binding so tokens
  travel across connections). Server-side mints one NEW_TOKEN per
  session at handshake-confirmed via a `Server.Slot.new_token_emitted`
  latch; Initial-token validate path runs before the Retry gate so
  returning clients with a valid NEW_TOKEN skip the Retry round-trip.
  Commit `04d762e`.
- Interop — QNS endpoint exercises the NEW_TOKEN pipeline end-to-end
  so external interop runners can validate the wire format. Commit
  `1300334`.
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
- `nullq.Server` operability surface: a structured logging hook
  (`Config.log_callback` / `Config.log_user_data` plus `Server.LogEvent`
  / `Server.LogCallback`) emits one event per observable choice point
  (`connection_accepted`, `connection_closed`, `feed_rate_limited`,
  `retry_minted`, `version_negotiated`, `stateless_queue_evicted`,
  `table_full`); `Server.metricsSnapshot()` returns a flat by-value
  `MetricsSnapshot` covering live-connection / routing-table /
  source-rate-table / retry-state-table / stateless-queue gauges, the
  sticky `stateless_queue_high_water` mark, and ten cumulative
  counters since `init` (`feeds_routed`, `feeds_accepted`,
  `feeds_dropped`, `feeds_rate_limited`, `feeds_table_full`,
  `feeds_version_negotiated`, `feeds_retry_sent`, `retries_validated`,
  `stateless_responses_evicted`, `slots_reaped`); and
  `Server.rateLimitSnapshot()` returns the top 16 most-active sources
  by recent count (`RateLimitSnapshot.SourceRow`). The log callback
  runs synchronously and never holds an internal lock; counters are
  plain `u64` fields with no allocator-using state. See `src/server.zig`.

### Tests / fuzz coverage

- §11.1 — `std.testing.fuzz` harness coverage for the highest-yield
  parser surfaces: `wire/varint.zig`, `wire/header.zig`,
  `frame/decode.zig` (single + drain-loop), `server.zig` peek
  helpers (`peekLongHeaderIds` / `isInitialLongHeader` /
  `peekDcidForServer`). Each callback runs once per `zig build test`
  against an empty input. Coverage-guided fuzzing via
  `zig build test --fuzz=100K` (bounded) or `zig build test --fuzz`
  (forever, web UI). Validated on Zig 0.17-dev master with ~1.8M
  iterations against `peekLongHeaderIds` finding zero crashes.
- §11.1.4 — `fuzz: coalesced long-header walker terminates with
  bounded advance` at `src/wire/long_packet.zig:973`. Commit
  `935928d`.
- §11.1.5 / .7 / .17 / .18 / .20 — Six state-machine fuzz harnesses
  for flow-control (`ConnectionData`), send_stream lifecycle,
  recv_stream reassembly, path_validator, ack_tracker range list,
  and transport_params decode. Commit `0f2ea74`.
- §11.1.8 / .9 / .20 — Three Connection-level fuzz harnesses:
  `Connection.handleCrypto` reassembly, `Connection.handleStream`
  reassembly, `Connection.recordAuthenticatedDatagramAddress`
  migration sequences (`src/conn/state.zig:13193,13285,13418`).
  Commit `9fb1142`.
- §11.2 — Three regression-class smoke tests in `tests/e2e/`:
  `zero_rtt_replay_smoke.zig` (AntiReplayTracker `.fresh` /
  `.replay` workflow over a real handshake-captured ticket),
  `path_challenge_flood_smoke.zig` (64-frame flood; one
  PATH_RESPONSE per challenge; validator state never churns; stray
  PATH_RESPONSE swallow path), `vn_spoofed_source_smoke.zig` (200
  distinct fake source addresses; per-source rate table tracks
  each independently; global stateless-response queue caps at 64;
  65th source triggers first eviction). Commit `512d1c3`.
- Adapt v1-byte-shape assertions to the new v2 (96-byte) AES-GCM-256
  Retry-token format. Commit `c2c0c90`.
- §11.1 #19 — `fuzz: Connection NEW_CONNECTION_ID /
  RETIRE_CONNECTION_ID lifecycle invariants` at
  `src/conn/state.zig:13548`. Drives smith-chosen interleavings of
  `handleNewConnectionId` / `handleRetireConnectionId` /
  `handlePathNewConnectionId`; asserts `peer_cids` count ≤
  `active_connection_id_limit`, sequence numbers unique, retired
  sequences gone, active path CID always one of the live entries.
  Commit `889b70b`.
- §11.2 #14 — `tests/e2e/unknown_frames_smoke.zig` regression test
  pumping a 1000-byte all-unknown-frame-type payload through a
  fully-authenticated 1-RTT packet; asserts `Connection.handle`
  surfaces `error.UnknownFrameType` without auto-closing or
  spinning. Commit `889b70b`.

### Docs

- §3.1 ReleaseSafe build-mode policy comment block at the top of
  `build.zig`. Commit `1a7ec80`.
- §4.3 NEW_TOKEN deferral scope spelled out (later closed by
  `04d762e`). Commit `5c93cdd`.
- `docs/hardening-status.md` rewritten as the post-hardening status
  doc; the original 2026-05-06 audit body archived at
  `docs/archive/hardening-audit-2026-05-06.md`.
- `docs/fuzz-coverage.md` refreshed to reflect the 19 fuzz harness
  sites now in tree; all in-scope §11.1 / §11.2 rows COVERED after
  the §4.1 bandwidth shaper, the CID-lifecycle harness, and the
  all-unknown-frames regression landed.
- `README.md` — new "Production posture" section listing
  default-safe knobs, opt-in production caps, build-mode policy,
  and the embedder-must-wire-yourself items (`MigrationCallback`,
  `AntiReplayTracker`, custom `tls.Context`). Commit `054c668`.

### Build / dependencies

- Bumped boringssl-zig pin to `c2218dd`
  (`SSL_CTX_set_allow_early_data_cb` exposed). Commit `7fc58b6`.

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
