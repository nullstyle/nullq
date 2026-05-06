# nullq hardening status against `hardening-guide.md`

Audit date: 2026-05-06.
Scope: §4 (QUIC transport), §5 (TLS / 0-RTT), §6/§7 existence checks, plus
§13–15 release-gate items. nullq is a Zig-first IETF QUIC v1 transport built
on `boringssl-zig`; HTTP/3 and QPACK are intentionally out of scope at this
point in the project plan.

Marker legend:

- IMPLEMENTED — the requirement is met by code.
- PARTIAL — significant code exists but key sub-requirements are missing or
  delegated to the embedder without a vetted default.
- NOT IMPLEMENTED — code does not satisfy the requirement.
- N/A — the relevant component is not yet present (HTTP/3, QPACK).
- PASS / FAIL / N/A used in the §14 checklist below.

All citations are absolute paths plus line numbers.

---

## §4. QUIC transport

### §4.1 UDP datagram intake — PARTIAL

What's there:

- Long-header structural peek before any decryption work:
  `peekLongHeaderIds`, `isInitialLongHeader` —
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:1868–1895`.
- Inbound payload bound enforced at 4 KiB before frame parsing:
  `max_recv_plaintext = 4096` and `max_supported_udp_payload_size = 4096`
  used on every receive path
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:185–187`,
  `5995`, `6131`); `Connection.handle` rejects oversized datagrams with
  PROTOCOL_VIOLATION
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:5565–5570`).
- Per-source rate limiting on Initials, gated before any TLS or Connection
  allocation:
  `Server.acceptSourceRate`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:958–973`,
  config flag `max_initials_per_source_per_window`).
- Slot-table cap before slot allocation:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:949–953`.

What's missing (the headline gap):

- **No 1200-byte minimum check on Initial-bearing UDP datagrams.**
  RFC 9000 §14 requires servers to discard Initial packets carried in
  datagrams smaller than 1200 bytes; nullq's Server.feed accepts any
  long-header datagram of size ≥ 6 bytes and the per-Connection
  `handleInitial` only checks DCID-extraction lengths
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:6109–6122`).
  The constant `min_quic_udp_payload_size` exists at line 189 but is only
  consulted to validate transport parameters, never actual datagram size.
- No listener-level packet/byte rate limit; rate limiting is per-source
  Initial-only and does nothing for short-header floods.

### §4.2 Anti-amplification (3× cap) — IMPLEMENTED

- Per-path bytes_received / bytes_sent accounting and the 3× cap:
  `Path.antiAmpAllowance`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/path.zig:121–185`).
- Anti-amp gating applied to Initial+Handshake+1-RTT outbound, not just
  1-RTT, and credited from datagram bytes (not decrypted-only):
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:4770–4783`,
  `5586`. Comment at 4770–4775 calls out the >10× amplification risk if
  this were limited to 1-RTT.
- Per-path migration anti-amp reset (zeroes counters, re-credits triggering
  datagram): `PathState.beginMigration`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/path.zig:364–388`).
- Tests cover unvalidated server, validated server, migration boundary:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:11270`,
  `11294`, `11336`, `11416`.

### §4.3 Stateless Retry / NEW_TOKEN — PARTIAL

What's there (Retry token):

- HMAC-SHA256 over QUIC version + issued/expires timestamps + length-prefixed
  client address + ODCID + Retry SCID:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/retry_token.zig:1–166`.
- Constant-time tag comparison (`std.crypto.timing_safe.eql`) at line 132.
- Domain separator string `"nullq retry token v1"` at line 34.
- Issued/expires window plus optional clock skew, rotation supported by
  swapping `RetryTokenKey` (the embedder owns key rotation policy).
- No deployment metadata (region/shard/node/process) is encoded; tokens are
  pure HMAC over the fields above.
- Server-side Retry gate (`Server.applyRetryGate`,
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:1563–1619`) refuses
  to allocate a `Connection` until a valid echoed token is presented;
  per-source `retry_state_table` bounded with expired-first eviction.

What's missing:

- **No NEW_TOKEN issuance.** The frame is parsed but the server side never
  emits NEW_TOKEN, so subsequent connections from the same client always
  pay a Retry round-trip. Search `/Users/nullstyle/prj/ai-workspace/nullq/src/`
  for `new_token` shows the frame type only;
  `/Users/nullstyle/prj/ai-workspace/nullq/src/frame/types.zig` has the
  decoder but no emitter or token policy. This is missing-feature, not
  insecure, but means zero-RTT-reconnection guidance from §4.3 (lifetime,
  uniqueness, no plaintext metadata) doesn't yet apply.
- The Retry token format does not include encryption — only authentication.
  The hardening guide says encryption is required only if the token carries
  address/timestamp/routing/deployment metadata; nullq's token does carry
  client address bytes and timestamps. These are bound-fields under the
  HMAC and thus authenticated, but they are NOT confidential. Whether this
  is acceptable depends on operator policy on revealing the address binding
  in the token bytes; downgrade to PARTIAL for that reason.

### §4.4 Version negotiation rate-limiting — NOT IMPLEMENTED

What's there:

- VN encoding and queueing on any non-v1 long-header packet:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:922–942`,
  `1509–1530`.
- Bounded stateless-response queue (capacity 64) with eviction policy that
  preferentially drops VN over Retry:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:1735–1763`.
- VN list intentionally minimal (only QUIC v1) — no draft IDs leaked
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:1521`).

What's missing:

- **No per-source rate limiting on VN responses.** The per-source token
  bucket gates only Initials of the matching version
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:958–973`); a
  flood of long-header packets carrying `version != 0x00000001` always
  triggers a VN response (subject only to the 64-entry global queue cap).
  An attacker with a single source address can still trigger 64 outbound
  VN responses per drain cycle, and from many addresses, more.
- No allocation gate on unsupported versions before queueing. The current
  flow doesn't allocate a `Connection`, but each VN entry consumes 256
  bytes of fixed buffer, and a flood from spoofed addresses would burn
  drain cycles even if the queue cap holds.

### §4.5 Connection IDs and stateless reset — PARTIAL

Connection IDs:

- Server-issued SCIDs are random and CSPRNG-sourced (`Server.random`
  drains BoringSSL's CSPRNG seed at init then uses `DefaultPrng`):
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:794–797`,
  `1278–1287`. Length is configurable (`local_cid_len`, default 8).
- No deployment metadata (shard/region/process/timestamp) is encoded —
  CIDs are pure random bytes by default. The embedder can swap
  `Server.random` to inject deterministic CIDs (tests, fuzzers); a
  production embedder swapping in a router-encoding scheme would have to
  evaluate that themselves, but the default is safe.
- CIDs are issued and retired through `provideConnectionId` /
  `provisionPathConnectionId` (`conn/state.zig:3212`, `3474`); the slot
  router (`Server.resyncSlotCids`,
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:1370–1414`) keeps
  routing table aligned with active SCIDs.
- The default RNG (`std.Random.DefaultPrng`) is seeded once from a CSPRNG;
  it is *not* a CSPRNG itself. For typical CID lengths (8 bytes) the
  birthday-bound is fine for unique routing, but an attacker who can
  observe enough server-issued CIDs could in principle predict future
  ones. That is operator-tunable (swap `Server.random`) but should be
  flagged.

Stateless reset:

- Tokens are 16 bytes per RFC, supplied by the embedder via
  `ConnectionIdProvision`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:348–352`);
  nullq does **not** mint them.
- **No HMAC-from-secret derivation helper.** The hardening guide requires
  reset tokens be derived from a secret HMAC over the CID and never
  reused; nullq accepts whatever the embedder supplies and has no policy
  enforcement that prevents reuse across CIDs/connections. An embedder
  can comply, but the default-safe path is missing.
- Inbound stateless-reset detection is implemented and matches against
  every peer-issued reset token:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:6427–6433`.

### §4.6 Transport parameters — IMPLEMENTED

- Duplicate detection (linear scan) before storing each parameter:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/tls/transport_params.zig:233–237`,
  `304–316`. Test for duplicates at line 521.
- Invalid-value rejection: `ack_delay_exponent > 20`
  (`tls/transport_params.zig:340`), `max_ack_delay >= 2^14` (`345`),
  `active_connection_id_limit < 2` (`355`), oversized `stateless_reset_token`
  (`326`), oversized CIDs (`321`/`360`/`364`),
  `disable_active_migration` zero-length flag check (`349`),
  malformed `preferred_address` (`376–392`).
- Length-prefix bounds checked against remaining buffer (`230`, `311`).
- Connection-side validation also enforces:
  - peer `max_udp_payload_size >= 1200`
    (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3709–3712`),
  - client must not send server-only params
    (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3731–3744`),
  - `original_destination_connection_id` echo binding
    (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:4225–4239`),
  - peer flow-control maxima clamped to local limits
    (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3713–3717`).
- Local params self-check: `max_udp_payload_size >= 1200`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:1178`).
- Unknown ids ignored after their length is validated
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/tls/transport_params.zig:372`).

Minor note: duplicate detection is O(n²) over the parameter blob; n is
small for legitimate inputs, and the blob length is implicitly bounded by
TLS extension limits (≤ 64 KiB) but no explicit cap enforced inside this
parser. Acceptable.

### §4.7 ACK handling — PARTIAL

What's there:

- ACK frame parses use checked varints
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/frame/decode.zig:107–150`).
- Range-iteration arithmetic is underflow-checked
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/frame/ack_range.zig:63–90`).
- Connection-side validation rejects ACKs claiming PNs not yet sent — this
  is the Cloudflare-CVE class:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:7088–7091`
  (per-level) and `7172–7175` (per-application-path), both close the
  connection with PROTOCOL_VIOLATION before updating loss-detection state.
- Iteration walks the bounded `SentPacketTracker` rather than the peer's
  claimed PN range — comment at
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:7100–7110`
  explicitly calls out the DoS risk of iterating
  `[interval.smallest, interval.largest]` directly. Good.
- Local AckTracker bounded at 255 disjoint intervals
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/ack_tracker.zig:22`).
- Outbound ACK frame builder respects byte budgets and a configurable
  lower-range cap (`max_application_ack_lower_ranges` /
  `toAckFrameLimitedRanges`,
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/ack_tracker.zig:218–256`).

What's missing:

- **No explicit cap on incoming `range_count`.** The decoder loops
  `while (i < range_count.value)`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/frame/decode.zig:120`,
  `178` for PATH_ACK) and only fails when the underlying buffer is
  exhausted. Because we cap `max_recv_plaintext = 4096` and each varint
  pair is ≥ 2 bytes, the worst case is ~2K range pairs per ACK frame —
  still O(n) downstream, but unbounded by an explicit guideline-style
  cap. The hardening guide calls for an explicit cap; downgrade to
  PARTIAL.
- No detection of duplicate or overlapping ranges *within* the ACK
  frame. Each range is processed against the tracker, and ranges that
  overlap waste cycles but do not cause incorrect state.

### §4.8 Path validation and migration — PARTIAL

- Path validation state machine (RFC 9000 §8.2):
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/path_validator.zig`.
- Random PATH_CHALLENGE token from BoringSSL CSPRNG:
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3897–3902`.
- Per-path anti-amp accounting (see §4.2).
- Per-path PATH_RESPONSE handling: `recordPathResponse` clears queued
  challenge and validates the matching path
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3936–3950`).
- Migration rollback on validation failure:
  `PathState.rollbackFailedMigration`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/path.zig:391–404`).
- Embedder migration policy hook (`migration_callback`,
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:1366`).

What's missing or weak:

- **No explicit `handshakeDone()` gate before accepting a peer-driven
  migration.** `recordAuthenticatedDatagramAddress`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3977–4014`)
  triggers `handlePeerAddressChange` purely on address mismatch. Frames
  authenticated under Initial/Handshake keys arrive there and could
  begin a "migration" before the handshake confirms — the hardening
  guide explicitly forbids this.
- No rate-limiting on PATH_CHALLENGE / PATH_RESPONSE emission. A peer
  that flips addresses repeatedly forces the server to emit a fresh
  challenge per flip; nothing throttles that.
- One `PATH_RESPONSE` per challenge is enforced by the validator state
  machine (only `.pending` accepts a response,
  `path_validator.zig:67`), so the §4.8 "at most one PATH_RESPONSE per
  PATH_CHALLENGE" point is effectively covered.

---

## §5. TLS and 0-RTT

### §5.1 Vetted TLS library — IMPLEMENTED

- All cryptography goes through `boringssl-zig` 0.5.0 pinned via
  `build.zig.zon`
  (`/Users/nullstyle/prj/ai-workspace/nullq/build.zig.zon:7–9`,
  `/Users/nullstyle/prj/ai-workspace/nullq/build.zig:7–18`).
- AEAD, HMAC, hash, RNG all wrap BoringSSL primitives (see imports in
  `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/retry_token.zig:9`,
  `/Users/nullstyle/prj/ai-workspace/nullq/src/wire/protection.zig`,
  `/Users/nullstyle/prj/ai-workspace/nullq/src/wire/long_packet.zig`).
- TLS 1.3 only (`min_version` and `max_version` both
  `boringssl.raw.TLS1_3_VERSION`):
  `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:780–781`.
- nullq does not implement its own AEAD, HKDF, or signature primitives.

### §5.2 0-RTT default — NOT IMPLEMENTED

- **`Server.init` enables 0-RTT by default**: `early_data_enabled = true`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:783`,
  `1198`). Same for the convenience `Client`
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/client.zig:194`,
  `226`).
- No anti-replay tracker. Searching the codebase for "anti-replay",
  "replay", "0rtt-replay" returns no hits inside `src/`.
- The early-data context digest covering ALPN + replay-relevant transport
  params + opaque application-context bytes is implemented and bound to
  the BoringSSL session ticket
  (`/Users/nullstyle/prj/ai-workspace/nullq/src/tls/early_data_context.zig`).
  This is the right primitive to make resumption strict, and tests verify
  every replay-relevant transport parameter changes the digest.
- No application-side gate constraining early-data requests to "idempotent
  only"; nullq surfaces `EarlyDataStatus` so the embedder can decide, but
  the default posture is "0-RTT enabled, no idempotency check, no replay
  cache."

This is the highest-severity finding in this audit. The hardening guide
states 0-RTT "must be disabled by default" and a vetted server "must
maintain an anti-replay mechanism" if it ever ships 0-RTT.

---

## §6. HTTP/3 — N/A

No HTTP/3 implementation exists. Searches for `http3`, `h3`,
`HTTP/3 frame`, `H3_FRAME`, `:method`, etc. across `src/` return only
the early-data context's `"h3"` ALPN sample input
(`/Users/nullstyle/prj/ai-workspace/nullq/src/tls/early_data_context.zig:126`)
and ALPN string-handling docs. The README and CHANGELOG describe nullq as
the QUIC transport only; HTTP/3 is explicitly out of scope at this phase.

## §7. QPACK — N/A

No QPACK implementation. Searches for `qpack`, `QPACK`, `dynamic_table`,
`encoder_stream`, `decoder_stream`, etc., find only documentation
mentioning QPACK as application context input to the early-data digest
(`/Users/nullstyle/prj/ai-workspace/nullq/src/tls/early_data_context.zig:34`).

---

## §14 "Must not ship" checklist

Each item: PASS / FAIL / N/A with citation.

1. Network parser code contains `catch unreachable`, unsafe optional
   unwraps, or `unreachable`. — **PASS (with caveat).** The remaining
   `unreachable`s are documented as non-peer-reachable invariants
   (`/Users/nullstyle/prj/ai-workspace/nullq/src/wire/varint.zig:65`,
   `/Users/nullstyle/prj/ai-workspace/nullq/src/wire/short_packet.zig:377`,
   `/Users/nullstyle/prj/ai-workspace/nullq/src/wire/long_packet.zig:609`,
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/path.zig:539`,
   `545`, `627`,
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/sent_packets.zig:263`,
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/retry_token.zig:101`).
   No `@panic` calls. `.?` patterns are guarded by a preceding null check
   in every spot-checked case. Each invariant deserves a ReleaseSafe
   build-mode policy, but none looks reachable from the network on the
   current paths.

2. ReleaseFast disables runtime safety in packet/frame/QPACK/transport
   parsing. — **PASS.** `build.zig` does not pin any module to
   ReleaseFast (the bench harness explicitly re-instantiates the tree
   under ReleaseFast for meaningful numbers but bench never touches
   peer input). Default `b.standardOptimizeOption` is Debug; the
   build-mode policy comment block at the top of `build.zig` spells
   out that production / internet-facing builds MUST pass
   `-Doptimize=ReleaseSafe` and that ReleaseFast/ReleaseSmall are
   forbidden for the network-input parser surface (residual
   `unreachable` invariants stop being trapped under no-safety
   modes). No internal `@setRuntimeSafety(false)`.

3. Any peer-controlled length can allocate before limit validation. —
   **PASS.** Every reassembly path checks the configured limit before
   accepting bytes:
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:6878–6879`
   (CRYPTO),
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:6821–6826`
   (DATAGRAM),
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3173–3177`
   (outbound DATAGRAM queue). Stream receive uses bounded windows.

4. QPACK limits encoded but not decoded size. — **N/A.** No QPACK.

5. ACK ranges are not validated against sent packet history. — **PASS.**
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:7088–7091`,
   `7172–7175` close the connection with PROTOCOL_VIOLATION before
   updating loss-detection state.

6. ACK range count is unbounded. — **PARTIAL FAIL.** No explicit cap on
   incoming `range_count`; bounded only by the 4 KiB plaintext budget
   (`/Users/nullstyle/prj/ai-workspace/nullq/src/frame/decode.zig:120`).

7. Unknown frames or settings can accumulate without limit. — **PASS for
   transport parameters** (unknown ids are skipped, blob length is
   implicitly bounded by the TLS extension envelope). HTTP/3 SETTINGS:
   N/A. Unknown QUIC frame types currently cause `error.UnknownFrameType`
   and packet rejection
   (`/Users/nullstyle/prj/ai-workspace/nullq/src/frame/decode.zig:103`),
   so they cannot accumulate. PASS.

8. 0-RTT allows state-changing requests. — **FAIL** at the transport
   level: 0-RTT is enabled by default with no anti-replay tracker
   (`/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:783`,
   `1198`). Whether the *application* serves state-changing requests is
   the embedder's choice, but the transport's default posture violates
   the guideline.

9. Server push is enabled by default. — **N/A** (no HTTP/3).

10. Retry tokens expose plaintext server metadata. — **PASS.** Retry
    token format
    (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/retry_token.zig:90–104`)
    contains version/issued/expires + HMAC tag — no shard/region/process
    bytes. The token is authenticated, not encrypted; the bound fields
    (client address, ODCID, Retry SCID) are NOT present in plaintext —
    only their HMAC contribution is, so this is fine.

11. Connection IDs expose shard/region/tenant/timestamp. — **PASS** by
    default (random bytes,
    `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:1285`). An
    embedder swapping in router-encoded CIDs is on their own.

12. Stateless reset tokens are reused. — **N/A**: nullq does not mint
    reset tokens (the embedder supplies them via
    `ConnectionIdProvision`,
    `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:348–352`).
    No nullq-side default-safe HMAC helper; flag this as a reasonable
    next addition.

13. `Server` reveals implementation/version by default. — **N/A** (no
    HTTP layer).

14. CONNECTION_CLOSE includes detailed parser errors by default. —
    **FAIL.** Internal reason strings are sent on the wire as-is; e.g.
    `"peer max udp payload below minimum"`,
    `"original destination cid mismatch"`,
    `"connection id reused across paths"`,
    `"ack of unsent packet"`. See ~80 sites in
    `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig` and the
    encoder at
    `/Users/nullstyle/prj/ai-workspace/nullq/src/frame/encode.zig:338–341`.
    The framework needs a "scrub reason in production" toggle (or use
    empty strings by default).

15. Logs include cookies/Authorization/Retry tokens/etc. — **PASS** at
    the transport level: nullq has no HTTP layer, the `LogEvent` enum
    in `server.zig` exposes only addresses and counters, and qlog
    callbacks are opt-in (null by default,
    `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:936`).
    Reset tokens, Retry token plaintext, and TLS exporter material
    never appear in any default log path.

16. Malformed HTTP/3 produces stack traces or debug pages. — **N/A.**

17. Flow-control stalls cause unlimited buffering. — **PASS.** Bounded
    pending-data caps:
    `max_pending_crypto_bytes_per_level = 64 KiB`
    (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:199`),
    `max_pending_datagram_bytes = 64 KiB` (line 196), peer flow-control
    limits clamped to local maxima
    (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3713–3717`).

18. Stream reset races leave application buffers dangling. — **PASS by
    inspection.** Stream lifecycle and send/recv stream state machines
    are typed and ack-driven; no spot check found dangling-buffer paths
    on reset (`recv_stream.zig`, `send_stream.zig`, `state.zig` reset
    handling). Not exhaustively fuzzed.

19. Fuzzing finds any panic, leak, or unbounded growth. — **N/A**.
    Fuzz-smoke tests at
    `/Users/nullstyle/prj/ai-workspace/nullq/tests/fuzz_smoke.zig` are
    canonical-roundtrip / malformed-input smoke tests, not extended
    fuzz harnesses. No coverage-guided fuzzing has run.

---

## §15 release-gate readiness summary

1. All protocol parsers have explicit resource budgets — **mostly yes.**
   Exception: incoming ACK frame `range_count` cap is implicit (bounded
   only by the 4 KiB plaintext budget).
2. All network-input panics eliminated — **likely yes.** No `@panic`,
   remaining `unreachable`s are documented invariants on non-peer paths,
   `.?` unwraps are guarded.
3. Fuzzing covers QUIC packet/frame/transport-param parsers — **partial.**
   Smoke-only roundtrip + malformed-input fuzz; no coverage-guided fuzz
   harness, no QPACK/HTTP3 fuzz (those don't exist yet).
4. Negative tests cover malformed transport semantics + DoS — **partial.**
   Transport param malformed cases, stream-state cases, multipath cases
   exist; ACK-range-explosion, anti-amp violation, VN-flood,
   migration-before-handshake, and 0-RTT-replay tests are missing.
5. Interop testing passes against multiple independent implementations —
   **yes.** `INTEROP_STATUS.md` documents quic-go / quiche / picoquic /
   ngtcp2 interop runs; the QNS endpoint at
   `/Users/nullstyle/prj/ai-workspace/nullq/interop/` exists.
6. 0-RTT, server push, QPACK dynamic table, qlog, and verbose close
   reasons off by default — **NO.** 0-RTT is on; verbose close reasons
   are sent as-is. (Server push / QPACK / qlog are correctly off or
   opt-in.)
7. External scans confirm no version banners, stack traces, debug pages,
   source paths, or build IDs are exposed — **partial.** No `Server:`
   header (no HTTP), but transport CONNECTION_CLOSE leaks parser
   strings. No build IDs in any external response that I can see.
8. Logs are redacted and rate-limited — **partial.** No structured
   redaction layer, but no sensitive data is emitted by default
   (callbacks are opt-in). Per-source feed-rate-limited LogEvents fire
   freely; no per-source rate limit on log emission.
9. Public vulnerability advisories from QUIC stacks reviewed and
   converted into regression tests — **partial.** ACK-of-unsent-packet
   (Cloudflare-style) is covered; other classes (QPACK expansion,
   anti-amp bypass, VN flood, PATH_CHALLENGE flood, Initial-too-small)
   are not encoded as named regression tests.
10. Security reviewer signed off on ACK / CID-token / flow control / Zig
    unsafe-code usage — **NO.** No external review on file. CHANGELOG
    references "phase 5b" interop work, not a security review.

---

## Top 5 highest-priority gaps (exploit risk × ease of fix)

1. **0-RTT is enabled by default with no anti-replay** — §5.2.
   Risk: replayable side-effect requests if the embedder ever serves
   non-idempotent traffic over 0-RTT.
   Fix: flip `early_data_enabled = false` at
   `/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:783` and
   `1198`; expose a config flag the embedder must explicitly enable,
   and add a TODO/asserted requirement that an anti-replay tracker (or
   strict idempotent-only ACL) accompanies any opt-in. Also flip the
   client-side default at
   `/Users/nullstyle/prj/ai-workspace/nullq/src/client.zig:194`,
   `226`.

2. **No 1200-byte minimum on Initial-bearing UDP datagrams** — §4.1.
   Risk: lets attackers spray small Initials below the QUIC minimum
   (RFC 9000 §14) which we must discard. Today they reach
   `Connection.handle` and burn TLS/Connection setup before being
   detected as malformed (or worse, succeed).
   Fix: at `Server.feed`
   (`/Users/nullstyle/prj/ai-workspace/nullq/src/server.zig:944–948`),
   reject `isInitialLongHeader(bytes)` paths where
   `bytes.len < min_quic_udp_payload_size`. The constant already
   exists at
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:189`.

3. **CONNECTION_CLOSE leaks internal parser reason strings** — §9.1
   / §14 #14. Risk: fingerprinting + verbose error oracle for
   adversarial peers.
   Fix: introduce a build-time or `Config.production_mode` flag that
   replaces every `self.close(true, code, "literal")` reason with `""`
   (or a generic class), and assert that any inbound CONNECTION_CLOSE
   reason is dropped from logs except via the qlog hook. Touch:
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:close()`
   call sites (~80) plus the encoder
   (`/Users/nullstyle/prj/ai-workspace/nullq/src/frame/encode.zig:338`).

4. **Migration accepted on authenticated Initial/Handshake datagrams,
   not gated on handshake completion** — §4.8. Risk: peer can drive a
   premature migration or path-validation churn before the handshake
   finishes; couples with the missing rate limit on PATH_CHALLENGE.
   Fix: add a `if (!self.handshakeDone()) return; // queue address
   re-anchor for post-handshake` guard at the top of
   `Connection.recordAuthenticatedDatagramAddress`
   (`/Users/nullstyle/prj/ai-workspace/nullq/src/conn/state.zig:3977`),
   and rate-limit PATH_CHALLENGE emission at
   `Connection.handlePeerAddressChange` (line 3962).

5. **No explicit cap on ACK frame `range_count`** — §4.7. Risk: bounded
   only by the 4 KiB plaintext budget, allowing ~2K range pairs per
   ACK; CPU work scales with ranges × tracked-packets even though no
   memory blows up.
   Fix: at
   `/Users/nullstyle/prj/ai-workspace/nullq/src/frame/decode.zig:113–125`
   (and `171–183` for PATH_ACK), reject `range_count.value > 256`
   (or a configurable per-peer maximum) with `error.MalformedFrame`
   before iterating. Mirror the local emit cap (`max_ranges = 255`,
   `/Users/nullstyle/prj/ai-workspace/nullq/src/conn/ack_tracker.zig:22`).

Honourable mentions that didn't crack the top 5 but should be tracked:

- VN responses are not per-source rate-limited (§4.4); the bounded
  global queue is necessary but not sufficient.
- No nullq-side helper for HMAC-derived stateless-reset tokens (§4.5)
  — embedders are on their own to comply with no-reuse policy.
- Default RNG for server SCIDs is a CSPRNG-seeded `DefaultPrng`, not a
  CSPRNG itself; document that production embedders should swap
  `Server.random` for a CSPRNG.
- Sensitive buffers (Retry key, TLS exporter material, reset tokens)
  are not zeroed on free; add `std.crypto.utils.secureZero` on the
  relevant deinit paths.
