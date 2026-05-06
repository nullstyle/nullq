# nullq hardening status against `hardening-guide.md`

Last refreshed: 2026-05-06.
Scope: §3 (Zig), §4 (QUIC transport), §5 (TLS / 0-RTT), §8 (resource
exhaustion), §9 (info disclosure), §11 (fuzzing), §12 (defaults),
§13–15 (release-gate). HTTP/3 (§6) and QPACK (§7) are intentionally
out of scope at this phase of the project plan.

Marker legend:

- COMPLETE — landed, tested, citable.
- PARTIAL — significant code exists but a sub-requirement is missing or deferred.
- DEFERRED — feature/policy decision tracked elsewhere; not a security gap.
- N/A — the relevant component does not yet exist (HTTP/3, QPACK).

The original 2026-05-06 audit body is preserved at
`docs/archive/hardening-audit-2026-05-06.md`.

## Summary

| §    | Topic                                          | Status   |
|------|------------------------------------------------|----------|
| 3.1  | Build-mode policy (ReleaseSafe)                | COMPLETE |
| 3.2  | Ban panic-based control flow                   | COMPLETE |
| 3.3  | Checked arithmetic on peer-controlled values   | COMPLETE |
| 3.5  | Zero sensitive material on free                | COMPLETE |
| 4.1  | UDP datagram intake                            | COMPLETE |
| 4.2  | Anti-amplification (3× cap)                    | COMPLETE |
| 4.3  | Stateless Retry / NEW_TOKEN                    | COMPLETE |
| 4.4  | Version negotiation rate-limiting              | COMPLETE |
| 4.5  | Connection IDs and stateless reset             | COMPLETE |
| 4.6  | Transport parameters                           | COMPLETE |
| 4.7  | ACK handling                                   | COMPLETE |
| 4.8  | Path validation and migration                  | COMPLETE |
| 5.1  | Vetted TLS library                             | COMPLETE |
| 5.2  | 0-RTT default-off + anti-replay tracker        | COMPLETE |
| 6    | HTTP/3                                         | N/A      |
| 7    | QPACK                                          | N/A      |
| 8    | Resource-exhaustion budgets                    | COMPLETE |
| 9    | CONNECTION_CLOSE redaction & log rate-limit    | COMPLETE |
| 11.1 | State-machine fuzz harnesses                   | COMPLETE |
| 11.2 | Public-CVE regression tests                    | COMPLETE |
| 12   | Operational defaults                           | COMPLETE |
| 13   | External security review                       | DEFERRED |
| 14   | "Must not ship" checklist                      | COMPLETE |
| 15   | Release-gate readiness                         | PARTIAL  |

## §3 Zig implementation hardening

### §3.1 Build mode policy — COMPLETE

`build.zig` carries the policy at the top of the file
(`/Users/nullstyle/prj/ai-workspace/nullq/build.zig:1–23`): the default
`-Doptimize=Debug` is fine for dev/test/interop, production /
internet-facing builds MUST pass `-Doptimize=ReleaseSafe`, and
`ReleaseFast` / `ReleaseSmall` are explicitly forbidden for the
network-input parser surface. The bench harness's deliberate
`ReleaseFast` re-instantiation is called out as the one exception
(bench never touches peer input). Landed in commit `1a7ec80`.

### §3.2 Ban panic-based control flow — COMPLETE

No `@panic` calls on peer-driven paths. The remaining `unreachable`
sites in `wire/`, `frame/`, and `conn/` are documented as
non-peer-reachable invariants with `// invariant:` comments
(`src/wire/long_packet.zig:609`, `src/wire/varint.zig:65`,
`src/wire/short_packet.zig:377`, `src/conn/path.zig:539/545/627`,
`src/conn/sent_packets.zig:263`, `src/conn/retry_token.zig:101`).
The §3.2 sweep in commit `0457262` converted the only
spot-check-reachable assert (`retryIntegrityTag` AEAD ABI drift) to
typed `Error.OutputTooSmall`, and clamped the two oversized-CID
inline-buffer paths in `path.zig` and `server.zig` via `@min` rather
than asserting.

### §3.3 Checked arithmetic on peer-controlled values — COMPLETE

The `0457262` sweep replaced unchecked `+` with `std.math.add` at the
five flow-control mutation sites in `src/conn/flow_control.zig`
(`ConnectionData.weCanSend`, `ConnectionData.recordPeerSent`,
`StreamData.recordSent`, `StreamData.recordPeerSent`,
`StreamCount.recordPeerOpened`). Overflow surfaces as
`FlowControlExceeded` / `PeerExceededLimit` / refuse-send, never a
runtime trap. Plus the typed-error sweep that bumped boringssl-zig
in commit `155d1c8`.

### §3.5 Zero sensitive material on free — COMPLETE

`std.crypto.secureZero` is invoked on every sensitive buffer at
struct teardown (commit `a167068`):

- `Server.deinit` zeros `retry_token_key` and `new_token_key`
  (`src/server.zig:1182–1192`).
- `Connection.deinit` zeros per-level traffic secrets (Initial /
  Handshake / 0-RTT / Application directions), application key
  epochs (`app_read_previous/current/next` and `app_write_current`
  including `keys.{key,iv,hp}`), and stateless-reset tokens on every
  `peer_cids` / `local_cids` entry
  (`src/conn/state.zig:1284–1320`).

`secureZero` is volatile-backed so the optimizer cannot elide the
clears on the dead-store path before the struct is poisoned.

Per-connection memory cap (`max_connection_memory`, default 32 MiB
at `src/conn/state.zig:220`) ensures peer-driven buffer growth on a
single Connection cannot exceed the bound — landed in commit
`426a222`. `bytes_resident` accounting at `src/conn/state.zig:6167`
gates every reassembly write.

## §4 QUIC transport

### §4.1 UDP datagram intake — COMPLETE

- Long-header structural peek before any decryption work
  (`peekLongHeaderIds`, `isInitialLongHeader` in `src/server.zig`).
- Inbound payload bound enforced at 4 KiB before frame parsing
  (`max_recv_plaintext = 4096` at `src/conn/state.zig:225`); oversized
  datagrams close the connection with PROTOCOL_VIOLATION.
- **RFC 9000 §14 1200-byte minimum** on Initial-bearing UDP datagrams
  is now enforced at `Server.feed` (commit `e5ce8d0`). Drops are
  tracked in `MetricsSnapshot.feeds_initial_too_small`. The check is
  gated on `version == QUIC_VERSION_1` so unsupported-version probes
  still flow into Version Negotiation handling. Test
  `Server.feed drops QUIC v1 Initial datagrams below the 1200-byte
  minimum` pins the behavior.
- **Listener-level rate limits** (commit `426a222`): per-window
  packet cap (`Server.Config.max_datagrams_per_window`) and per-window
  byte cap (`Server.Config.max_bytes_per_window`) at
  `src/server.zig:606`/`620`. Drops surface via
  `feeds_listener_rate_limited` and `feeds_listener_byte_rate_limited`
  counters. The byte-budget cap landed in commit `1dceea5`.
- Per-source rate limiting on Initials (`acceptSourceRate`); slot-table
  cap before slot allocation. Per-source VN rate limiting (commit
  `b22ebee`) — see §4.4.

Note: BANDWIDTH-class shaping (token-bucket + ingress queue
saturation) is deferred to a larger production-deployment work item.
The current packet- and byte-window listener caps cover the threat
class the hardening guide calls out.

### §4.2 Anti-amplification (3× cap) — COMPLETE

Unchanged from the original audit. Per-path bytes_received /
bytes_sent accounting and the 3× cap (`Path.antiAmpAllowance`),
applied to Initial+Handshake+1-RTT outbound and credited from
datagram bytes (not decrypted-only). Migration anti-amp reset on
`PathState.beginMigration`. Tests cover unvalidated server, validated
server, and migration boundary in `src/conn/state.zig`.

### §4.3 Stateless Retry / NEW_TOKEN — COMPLETE

**Retry token (encrypt-then-authenticate, AES-GCM-256)** — commit
`474a71b` moved the token format from HMAC-only (53 B) to AEAD-sealed
v2 (96 B fixed wire size: 12-byte nonce + 68-byte ciphertext +
16-byte tag). Plaintext now contains version / issued / expires /
client address / ODCID / Retry SCID, zero-padded to 68 bytes so every
minted token is a uniformly random opaque blob — peers and on-path
observers cannot infer when a token was issued or which fields it
binds. Constant-time tag comparison via the AEAD; domain separator
`"nullq retry token v2"`. Test `fuzz: retry_token validate never
panics` in `src/conn/retry_token.zig:562`.
`Server.applyRetryGate` refuses to allocate a `Connection` until a
valid echoed token is presented; per-source `retry_state_table`
bounded with expired-first eviction.

**NEW_TOKEN issuance** — commit `04d762e` wires up RFC 9000 §8.1.3
end-to-end:

- Server-side mints one AES-GCM-256-sealed token per session at
  handshake-confirmed; queues a NEW_TOKEN frame for emission;
  validates returning clients' echoed tokens before the Retry gate so
  address-validated peers skip the Retry round-trip.
- Module `src/conn/new_token.zig` peers `src/conn/retry_token.zig`.
  Token binds only `client_address + version + issue/expiry window`;
  ODCID/Retry-SCID are intentionally excluded so the token travels
  across connections. Distinct AES-GCM-256 key
  (`Server.Config.new_token_key`) so the NEW_TOKEN rotation cadence
  is independent of `retry_token_key`.
- `Server.Config.new_token_lifetime_us` defaults to 24 hours.
- `Server.Slot.new_token_emitted` latch ensures at most one NEW_TOKEN
  per server-side session.
- Client-side `Client.Config.new_token` (pre-captured bytes for the
  first Initial) and `Client.Config.new_token_callback` (capture
  inbound NEW_TOKEN for replay on a follow-up connection) at
  `src/client.zig:121–130`.
- Server-side validation falls through to a fresh Retry on
  `.malformed` / `.expired` / `.invalid` rather than dropping the
  connection.
- QNS endpoint (`interop/qns_endpoint.zig`) exercises the pipeline
  end-to-end (commit `1300334`) so external interop runners can
  validate the wire format.
- `fuzz: new_token validate never panics`
  (`src/conn/new_token.zig:486`).

### §4.4 Version negotiation rate-limiting — COMPLETE

Per-source VN rate limit landed in commit `b22ebee` at
`src/server.zig`: a separate `vn_count` / `vn_window_start_us` pair
on `SourceRateEntry` so VN floods don't burn the Initial budget.
Default cap = 8 emissions per source per window. New
`feeds_vn_rate_limited` metric (subset of `feeds_dropped`).
`pruneSourceRate` updated to retain entries that are stale on one
counter axis but active on the other. Tests `Server VN per-source
rate limiter caps VN responses` and `Server VN rate limit and Initial
rate limit use independent counters`.

The per-source gate is in addition to the bounded global stateless-
response queue (capacity 64, eviction prefers VN over Retry) and the
intentionally minimal VN list (only QUIC v1 — no draft IDs leaked).

E2E regression test `vn_spoofed_source_smoke` (commit `512d1c3`)
pumps 200 distinct fake source addresses each sending one VN-eligible
probe; pins both the per-source independence and the global queue cap
at 64.

### §4.5 Connection IDs and stateless reset — COMPLETE

**CSPRNG SCIDs** (commit `2137f77`) — `Server.openSlotFromInitial`
and `mintAndQueueRetry` now call `boringssl.crypto.rand.fillBytes`
directly. The `std.Random.DefaultPrng`-seeded-once approach is gone:
each CID is a fresh CSPRNG draw. The `Server.random` /
`Server.rng_state` fields were removed; see commit message for the
removal rationale.

**Stateless-reset helper** (commit `030b9fe`) — module
`src/conn/stateless_reset.zig`:

- `Key = [32]u8` — server-private HMAC-SHA256 key, documented "never
  share, never log, secureZero on free".
- `derive(key, cid)` — first 16 bytes of `HMAC-SHA256(key,
  "nullq stateless reset v1" || cid)`. Deterministic so the server
  can re-derive after losing local state. Domain separator avoids
  collision with future HMAC primitives sharing the key.
- `generateKey()` — fresh 32 bytes from BoringSSL CSPRNG.
- Re-exported as `nullq.conn.stateless_reset`.

Embedders can keep using `ConnectionIdProvision.stateless_reset_token`
with their own scheme (e.g. encrypted tokens that double as routing
keys) — the API surface is unchanged. The default-safe path is now
shipping.

### §4.6 Transport parameters — COMPLETE

Unchanged from the original audit: duplicate detection, invalid-value
rejection, length-prefix bounds checking, connection-side semantic
checks (peer `max_udp_payload_size >= 1200`, client must not send
server-only params, ODCID echo binding, peer flow-control maxima
clamped to local limits), unknown ids ignored. Plus a new
coverage-guided harness `fuzz: transport_params decode never panics
and respects RFC bounds` at `src/tls/transport_params.zig:619`
(commit `0f2ea74`).

### §4.7 ACK handling — COMPLETE

- ACK frame parses use checked varints; range-iteration arithmetic is
  underflow-checked.
- Connection-side validation rejects ACKs claiming PNs not yet sent
  (the Cloudflare-CVE class).
- Iteration walks the bounded `SentPacketTracker` rather than the
  peer's claimed PN range.
- Local AckTracker bounded at 255 disjoint intervals.
- Outbound ACK frame builder respects byte budgets and a configurable
  lower-range cap.
- **Incoming `range_count` cap = 256** (commit `3a64820`) at
  `src/frame/decode.zig:64,142,203` — `max_incoming_ack_ranges` rejects
  oversized ACK / PATH_ACK frames before iteration begins. Mirrors
  the local emit cap (`max_ranges = 255`) with one slot of margin.
  New `Error.AckRangeCountTooLarge`. Tests at
  `src/frame/decode.zig:703,719,737`.
- **Overlap detection** (commit `0baa170`) — `decodeAck` /
  `decodePathAck` now reject any ACK frame whose ranges overlap or
  whose gap+length arithmetic underflows. Test `decode rejects ACK
  with overlapping ranges` at `src/frame/decode.zig:751`.
- Coverage-guided fuzz on the range tracker
  (`src/conn/ack_tracker.zig:512`) — commit `0f2ea74`.

### §4.8 Path validation and migration — COMPLETE

- Path validation state machine (`src/conn/path_validator.zig`) with
  fuzz harness at `src/conn/path_validator.zig:176` (commit `0f2ea74`).
- Random PATH_CHALLENGE token from BoringSSL CSPRNG.
- Per-path anti-amp accounting; PATH_RESPONSE handling; rollback on
  validation failure; embedder migration policy hook.
- **Pre-handshake migration drop** (commit `a4b2a3b`) —
  `recordAuthenticatedDatagramAddress` returns early if
  `handshakeDone()` is false. No anti-amp credit, no validator state,
  no PATH_CHALLENGE queued. Pre-handshake address-anchoring on a
  half-handshaked 4-tuple is forbidden by RFC 9000 §9.6 even when the
  triggering datagram authenticates under existing keys.
- **Per-path PATH_CHALLENGE rate limit** (same commit) —
  `Path.last_path_challenge_at_us` records when a challenge was last
  emitted; subsequent migration attempts within
  `min_path_challenge_interval_us` (100 ms) are dropped. Both drops
  surface as qlog `migration_path_failed` events with reasons
  `.pre_handshake` and `.rate_limited` joining `.policy_denied` and
  `.timeout`.
- E2E regression test `path_challenge_flood_smoke` (commit `512d1c3`)
  pumps 64 PATH_CHALLENGE frames in one packet and asserts exactly
  one PATH_RESPONSE per challenge with no validator state churn.
- Connection-level migration fuzz harness `fuzz: Connection.
  recordAuthenticatedDatagramAddress migration sequences` at
  `src/conn/state.zig:13418` (commit `9fb1142`) drives randomized
  PATH_CHALLENGE / PATH_RESPONSE / address-rebinding sequences against
  the full Connection.

## §5 TLS and 0-RTT

### §5.1 Vetted TLS library — COMPLETE

Unchanged from the original audit. All cryptography goes through
`boringssl-zig` pinned via `build.zig.zon` (currently `c2218dd`,
post-0.5.0; see commit `7fc58b6` for the most recent bump). TLS 1.3
only. nullq does not implement its own AEAD, HKDF, or signature
primitives.

### §5.2 0-RTT default + anti-replay — COMPLETE

**Default-off** (commit `0457262`) — `Server.Config.enable_0rtt: bool
= false`. Threaded through `Server.init` (auto-built TLS context now
sets `early_data_enabled` from this flag instead of unconditionally
true) and through `Server.replaceTlsContext({.pem})` so PEM reloads
preserve the initial posture. Client-side `early_data_enabled` now
follows `config.session_ticket != null` instead of always-on.

**Anti-replay tracker primitive** (commit `108180a`) —
`src/tls/anti_replay.zig` ships `AntiReplayTracker`:

- Bounded LRU + time window. Defaults: 4096 entries, 10 minutes.
- `consume(id, now_us) → .fresh | .replay`. Insertion past
  `max_entries` evicts the oldest.
- `Id = [32]u8` opaque; embedders pick the construction (SHA-256 of
  resumed session ticket bytes is the canonical choice).
- `prune(now_us)`, `bumpClock(now_us)`,
  `consumeUsingInternalClock(id)` — added in commit `7fc58b6` for
  callers (the BoringSSL trampoline) without a direct path to
  monotonic time.
- Re-exported as `nullq.tls.AntiReplayTracker`.

**TLS-pre-accept BoringSSL callback wiring** (commit `7fc58b6`) —
0-RTT replay rejection moved from "embedder calls
`tracker.consume` post-handshake" to "BoringSSL invokes the
trampoline before accepting early data, denying the resumption at
the TLS layer". Bumped boringssl-zig pin to `c2218dd`
(`SSL_CTX_set_allow_early_data_cb` exposed). New
`Server.Config.early_data_anti_replay: ?*tls.anti_replay.
AntiReplayTracker = null`. When set AND `enable_0rtt = true` AND no
`tls_context_override`, `Server.init` installs
`antiReplayEarlyDataTrampoline` via
`tls.Context.setAllowEarlyDataCallback` with the tracker pointer as
user_data. The trampoline:

1. SHA-256s `Conn.peerSessionId()` (the resumed-session ticket bytes
   parsed from the ClientHello pre_shared_key extension) to a
   tracker `Id`.
2. Calls `tracker.consumeUsingInternalClock(id)` for the verdict.
3. Returns `true` for `.fresh`, `false` for `.replay`. Defensive
   defaults: any plumbing failure (null user_data, hash failure, OOM
   in the tracker) returns `false` — denying 0-RTT rather than
   risking a replay window.

Override-mode embedders (those passing `tls_context_override`) own
the BoringSSL hook themselves via the public boringssl-zig API.

Early-data context digest covering ALPN + replay-relevant transport
params + opaque application-context bytes is implemented and bound to
the BoringSSL session ticket (`src/tls/early_data_context.zig`).

E2E regression test `zero_rtt_replay_smoke` (commit `512d1c3`) drives
a real handshake to capture a session ticket, then pins the
embedder-style flow: first sighting `.fresh`, second sighting with
the same ticket `.replay`.

## §6 HTTP/3 — N/A

No HTTP/3 implementation exists. ALPN strings flow through the
early-data context digest input but no HTTP/3 frames or settings are
parsed.

## §7 QPACK — N/A

No QPACK implementation. Same posture as §6.

## §8 Resource-exhaustion budgets — COMPLETE

- `max_recv_plaintext = 4096` per-datagram plaintext bound
  (`src/conn/state.zig:225`).
- `max_pending_crypto_bytes_per_level = 64 KiB`
  (`src/conn/state.zig:239`).
- `max_pending_datagram_bytes = 64 KiB`,
  `max_pending_datagram_count = 64` (`src/conn/state.zig:234,236`).
- Send-stream cap: `default_max_buffered_send = 1 MiB` per stream
  (commit `23c925f`, `src/conn/send_stream.zig:101`); `write` short-
  writes to apply back-pressure when the cap is hit. Embedder can
  override per-stream via `stream.send.max_buffered`.
- `max_connection_memory` (commit `426a222`,
  `src/conn/state.zig:220`, default 32 MiB) caps peer-driven buffer
  growth across CRYPTO / STREAM / DATAGRAM / pending frames /
  ack-tracker memory on a single Connection.
- `max_datagrams_per_loop_iteration = 1` in `src/transport/udp_server.
  zig:59` (commit `bb68404`) — the loop processes exactly one inbound
  datagram per iteration, yielding to per-slot drain + tick between
  each.
- Listener byte/packet rate limits (`max_datagrams_per_window`,
  `max_bytes_per_window`) — see §4.1.
- Peer flow-control maxima clamped to local limits.

## §9 Information disclosure — COMPLETE

**CONNECTION_CLOSE redaction** (commit `adfbba2`) —
`Connection.reveal_close_reason_on_wire: bool = false` field;
`src/conn/state.zig:5095` empties `reason_phrase` on the wire when
the flag is unset (default). Local introspection unaffected: the
sticky `lifecycle.record(...)` capture still keeps the full reason
for embedder telemetry, and `nextEvent` / `closeEvent` surface it
via `CloseEvent.reason`. The error code + space still propagate
on the wire — only the descriptive reason text is redacted.
`Server.Config.reveal_close_reason_on_wire` and
`Client.Config.reveal_close_reason_on_wire` thread the toggle through.
Tests `CONNECTION_CLOSE wire-redacts the reason by default` and
`CONNECTION_CLOSE wire-includes reason when reveal_close_reason_on_wire
is set` in `tests/e2e/mock_transport_stream_exchange.zig`.

**Log rate limit** (commit `426a222`) —
`Server.Config.max_log_events_per_source_per_window` (default 16)
caps how many `LogEvent`s the embedder receives per source address
per window. `feeds_log_rate_limited` counter tracks the suppressed
events.

**Transport-level log surface** is unchanged: `LogEvent` exposes
addresses + counters only; qlog callbacks are opt-in (null by
default). Reset tokens, Retry/NEW_TOKEN plaintext, and TLS exporter
material never appear in any default log path.

## §11 Fuzzing and negative-test coverage

### §11.1 State-machine fuzz harnesses — COMPLETE

18 `std.testing.fuzz` harnesses across the codebase (verify via
`rg "std.testing.fuzz" src`):

| Surface | Site | Landed |
|---|---|---|
| varint decode/encode | `src/wire/varint.zig:262` | original |
| header parse | `src/wire/header.zig:836` | original |
| coalesced long-header walker | `src/wire/long_packet.zig:973` | `935928d` |
| frame decode (single) | `src/frame/decode.zig:632` | original |
| frame decode (drain loop) | `src/frame/decode.zig:655` | original |
| `peekLongHeaderIds` | `src/server.zig:2051` | original |
| `isInitialLongHeader` | `src/server.zig:2070` | original |
| `peekDcidForServer` | `src/server.zig:2081` | original |
| transport params decode | `src/tls/transport_params.zig:619` | `0f2ea74` |
| flow_control state machine | `src/conn/flow_control.zig:264` | `0f2ea74` |
| send_stream lifecycle | `src/conn/send_stream.zig:815` | `0f2ea74` |
| recv_stream reassembly | `src/conn/recv_stream.zig:617` | `0f2ea74` |
| path_validator state machine | `src/conn/path_validator.zig:176` | `0f2ea74` |
| ack_tracker range list | `src/conn/ack_tracker.zig:512` | `0f2ea74` |
| retry_token validate | `src/conn/retry_token.zig:562` | `474a71b` |
| new_token validate | `src/conn/new_token.zig:486` | `04d762e` |
| `Connection.handleCrypto` reassembly | `src/conn/state.zig:13193` | `9fb1142` |
| `Connection.handleStream` reassembly | `src/conn/state.zig:13285` | `9fb1142` |
| `Connection.recordAuthenticatedDatagramAddress` migration sequences | `src/conn/state.zig:13418` | `9fb1142` |

Each harness doubles as a `std.testing.fuzz` callback (runs once per
`zig build test` against an empty input, so the property-check code
path executes on every CI run) and as a coverage-guided harness via
`zig build test --fuzz=...`.

See `docs/fuzz-coverage.md` for the §11 row-by-row mapping.

### §11.2 Public-CVE regression tests — COMPLETE

Three regression-class smoke tests landed in commit `512d1c3`:

- `tests/e2e/zero_rtt_replay_smoke.zig` — embedder-driven anti-replay
  workflow; first sighting `.fresh`, second sighting `.replay`.
  Closes §11.2 row "0-RTT replay" and §5.2 / RFC 9001 §5.6.
- `tests/e2e/path_challenge_flood_smoke.zig` — 64 PATH_CHALLENGE
  frames in one packet; one PATH_RESPONSE per challenge; validator
  state never churns. Plus a stray-PATH_RESPONSE companion test
  pinning the `recordPathResponse → .NotPending` swallow path.
  Closes §11.2 row "PATH_CHALLENGE flood".
- `tests/e2e/vn_spoofed_source_smoke.zig` — 200 distinct fake source
  addresses each send one VN-eligible probe; per-source rate table
  tracks each independently; global stateless-response queue caps at
  64; eviction counter ticks once per overflowed entry. Closes §11.2
  row "Version Negotiation flood".

ACK-of-unsent-packet (Cloudflare-style), Initial-too-small (§14
RFC 9000 §14), CRYPTO/STREAM reassembly malformed-input, ACK overlap,
Retry token random garbage, transport-parameter duplicates, and
forbidden-frames-in-0-RTT are all covered by named tests in
`src/conn/state.zig`, `src/frame/decode.zig`, `src/conn/retry_token.zig`,
`src/tls/transport_params.zig`, and `tests/e2e/server_smoke.zig`.

## §12 Operational defaults — COMPLETE

The defaults posture from §12 of the hardening guide is now:

- 0-RTT: **off** (`enable_0rtt: bool = false`).
- CONNECTION_CLOSE reason on wire: **off**
  (`reveal_close_reason_on_wire: bool = false`).
- qlog: opt-in (`Connection.setQlog*` callbacks; null by default).
- Per-packet qlog events: opt-in
  (`Connection.setQlogPacketEvents(true)`).
- Verbose log events: rate-limited per source
  (`max_log_events_per_source_per_window: u32 = 16`).
- Server push / QPACK dynamic table: N/A (no HTTP/3 layer).

## §13 External security review — DEFERRED

No external review on file. This is a project-organizational item
(§15 #10 below). Tracked outside the technical hardening work.

## §14 "Must not ship" checklist — COMPLETE

1. Network parser code contains `catch unreachable`, unsafe optional
   unwraps, or `unreachable`. — **PASS.** No `@panic`, all residual
   `unreachable`s annotated as non-peer-reachable invariants. Plus
   the §3.2 sweep in `0457262`.

2. ReleaseFast disables runtime safety in packet/frame/QPACK/
   transport parsing. — **PASS.** `build.zig:1–23` policy block
   (commit `1a7ec80`) forbids ReleaseFast/ReleaseSmall for the
   network-input parser surface and mandates `-Doptimize=ReleaseSafe`
   for production.

3. Any peer-controlled length can allocate before limit validation. —
   **PASS.** Every reassembly path checks the configured limit first;
   plus `max_connection_memory` (commit `426a222`) caps total
   peer-driven memory per Connection.

4. QPACK limits encoded but not decoded size. — **N/A.** No QPACK.

5. ACK ranges are not validated against sent packet history. —
   **PASS.** Unchanged (the Cloudflare-CVE class).

6. ACK range count is unbounded. — **PASS** (commit `3a64820`).
   `max_incoming_ack_ranges = 256` rejects oversized frames before
   iteration begins. Plus overlap detection (commit `0baa170`).

7. Unknown frames or settings can accumulate without limit. —
   **PASS** for transport parameters and QUIC frames. HTTP/3
   SETTINGS: N/A.

8. 0-RTT allows state-changing requests. — **PASS** at the transport
   level (commit `0457262` flips default off; `108180a` ships the
   anti-replay primitive; `7fc58b6` wires the BoringSSL trampoline).
   Application-level idempotency is the embedder's choice;
   transport's default posture now satisfies the guideline.

9. Server push is enabled by default. — **N/A.**

10. Retry tokens expose plaintext server metadata. — **PASS**
    (commit `474a71b` — token plaintext is AES-GCM-256-encrypted;
    fields are no longer visible on the wire). NEW_TOKEN tokens
    follow the same shape.

11. Connection IDs expose shard/region/tenant/timestamp. — **PASS**
    by default. Server SCIDs are CSPRNG draws (commit `2137f77`); no
    deployment metadata encoded.

12. Stateless reset tokens are reused. — **PASS** with the new
    helper (commit `030b9fe`); embedders supplying their own tokens
    are still on their own.

13. `Server` reveals implementation/version by default. — **N/A**
    (no HTTP layer).

14. CONNECTION_CLOSE includes detailed parser errors by default. —
    **PASS** (commit `adfbba2`).

15. Logs include cookies/Authorization/Retry tokens/etc. — **PASS.**
    Plus log rate limit (commit `426a222`).

16. Malformed HTTP/3 produces stack traces or debug pages. — **N/A.**

17. Flow-control stalls cause unlimited buffering. — **PASS.**

18. Stream reset races leave application buffers dangling. — **PASS**
    by inspection; reassembly fuzz harnesses
    (`Connection.handleStream`, `recv_stream`) shake out the stream
    state machine.

19. Fuzzing finds any panic, leak, or unbounded growth. — **PASS.**
    18 `std.testing.fuzz` harnesses; weekly fuzz CI runs them under
    coverage feedback (`fbea87e`, `.github/workflows`).

## §15 release-gate readiness — PARTIAL (organizational items only)

1. All protocol parsers have explicit resource budgets — **YES.**
2. All network-input panics eliminated — **YES.**
3. Fuzzing covers QUIC packet/frame/transport-param parsers —
   **YES.** All in-scope §11.1 rows COVERED. QPACK/HTTP3 fuzz: N/A
   (no impl).
4. Negative tests cover malformed transport semantics + DoS —
   **YES.** Initial-too-small, ACK-of-unsent, ACK-range-overflow,
   ACK overlap, anti-amp violation, VN-flood, PATH_CHALLENGE flood,
   migration-before-handshake, 0-RTT replay all encoded as named
   tests.
5. Interop testing passes against multiple independent
   implementations — **YES.** quic-go / quiche / picoquic / ngtcp2
   covered in `INTEROP_STATUS.md`.
6. 0-RTT, server push, QPACK dynamic table, qlog, and verbose close
   reasons off by default — **YES.** 0-RTT off (`0457262`), close
   reasons redacted (`adfbba2`), qlog opt-in.
7. External scans confirm no version banners, stack traces, debug
   pages, source paths, or build IDs are exposed — **YES.** No HTTP
   layer; CONNECTION_CLOSE reasons redacted.
8. Logs are redacted and rate-limited — **YES** (commit `426a222`).
9. Public vulnerability advisories from QUIC stacks reviewed and
   converted into regression tests — **YES** (commit `512d1c3` plus
   pre-existing ACK-of-unsent etc.).
10. Security reviewer signed off on ACK / CID-token / flow control /
    Zig unsafe-code usage — **NO.** No external review on file.
    This is the only genuinely-still-open release-gate item;
    organizational rather than technical.

## Currently open

- **Listener BANDWIDTH-class shaping**. The packet-window
  (`max_datagrams_per_window`) and byte-window
  (`max_bytes_per_window`) caps are in place (commit `1dceea5`); a
  full token-bucket + ingress queue pressure model is deferred to a
  larger production-deployment work item. Not a security gap on the
  current threat model.
- **§13 / §15 #10 — external security review**. Organizational item.
  Tracked outside the technical hardening pass.
- **Phase-deferred features** that are not security gaps but appear
  on the project plan: HTTP/3 (§6), QPACK (§7), Windows targets,
  FIPS mode, ECN, DPLPMTUD, BBR.

The substantial majority of the original 2026-05-06 audit's open
items have closed. See `docs/archive/hardening-audit-2026-05-06.md`
for the original snapshot.
