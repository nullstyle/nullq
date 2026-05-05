# Changelog

All notable changes to nullq are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. Until then, any release in the `0.x` line may include
breaking changes; see notes per release.

## [Unreleased]

### Added
- `.github/workflows/test.yml`: matrix build/test on ubuntu-latest and
  macos-latest with Zig 0.16.0.
- `.github/workflows/interop.yml`: weekly QNS interop run against the
  official `quic-interop/quic-interop-runner` (server role, `H,DC,M`
  against quic-go, quiche, ngtcp2). Marked `continue-on-error` since
  interop is environment-sensitive and not a hard merge gate.
- This `CHANGELOG.md`.

### Notes
- nullq remains pre-1.0 (`0.0.0` in `build.zig.zon`). The transport is
  feature-rich and passes a substantial QNS interop matrix, but the
  public Zig API is still expected to churn before the first tagged
  release. See the "decisions" section of the agent CI/release report
  for why no version bump was applied.
- The `boringssl-zig` dependency is currently a path dep
  (`../boringssl-zig`). The upstream repo is published at
  `github.com/nullstyle/boringssl-zig` with tagged releases, so a
  follow-up will migrate this to a URL+hash dep once we settle on a
  release tag (`v0.5.0` is the current candidate). Until then, CI
  checks out the dependency repo as a sibling.

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
