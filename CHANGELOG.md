# Changelog

All notable changes to quic-zig are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. Until then, any release in the `0.x` line may include
breaking changes; see notes per release.

## [Unreleased]

### Tests

- **`v2` testcase-name coverage in the qns version-selection unit test**
  — the existing test "QNS server/client versions follow
  `TESTCASE=versionnegotiation`" in `interop/qns_endpoint.zig` now
  also asserts that `serverVersionsForTestcase("v2")` and
  `clientVersionsForTestcase("v2")` return the same multi-version
  postures as the `versionnegotiation` legacy alias, plus a
  defensive `v22` case to lock the exact-equality matching of the
  shared `isVersionNegotiationTestcase` helper. Pins the
  testcase-name gating fix so a future rename of the gate cannot
  regress the runner's `v2` cell silently.

- **Regression pin: server-wrapper end-to-end peer-side rebind-addr
  arms PATH_CHALLENGE on the existing slot** — a new e2e test in
  `tests/e2e/server_client_handshake.zig` ("Server <-> Client:
  peer-side rebind after handshake arms PATH_CHALLENGE on existing
  slot") drives a full Server.feed-routed handshake to completion,
  drains post-handshake outbound, then injects the client's next
  ack-eliciting 1-RTT datagram through `Server.feed` with a
  brand-new `from` tuple to simulate the runner's mid-transfer
  source-address rewrite. Pins (a) `Server.feed` returns
  `FeedOutcome.routed` (the new tuple's datagram still routes via
  CID match to the same slot, no second slot opens), (b)
  `slot.conn.pending_frames.path_challenge != null` on the active
  app path, (c) `path.path.peer_addr` swung to the new tuple, (d)
  `path.pending_migration_reset` latched, and (e) the slot's
  `peer_addr` routing hint (consulted by `runUdpServer`'s outbound
  drain) tracks the rebind. Symmetric server-role counterpart to
  the client-side `_state_tests.zig` "client peer-address rebind:
  pollDatagram exposes the new server tuple after migration" pin
  shipped in `f596d80`. Investigation of the matrix-run report
  showing `server × ngtcp2 × rebind-addr` regressed between
  `8e65ef2` and `d2c6b6b` could not narrow the regression to a
  single in-tree commit — the test passes at both endpoints — so
  the test is documented as defensive coverage rather than a
  fix-pinning regression.

- **Regression pin: qns `Connection.acceptInitial` code path preserves
  `preferred_address` end-to-end** — a new e2e test in
  `tests/e2e/server_smoke.zig` ("Connection.acceptInitial: qns code path
  preserves preferred_address through to client") mirrors the
  `interop/qns_endpoint.zig` sequencing precisely (`Connection.initServer`
  → `bind` → `setLocalScid` → `replenishConnectionIds(seq=1 alt-CID)`
  → `acceptInitial` with PA-bearing params, then `setEarlyDataContextForParams`)
  and drives a full mock-transport handshake to completion. Pins that
  the client's `peerTransportParams()` contains the configured
  `preferred_address` value (IPv4/IPv6 addr+port, alt-CID, stateless
  reset token) byte-for-byte. Investigation of the
  `server × {quic-go, ngtcp2, quiche} × connectionmigration` matrix
  cell (FAIL on 2026-05-09) confirmed via tshark+keylog that the
  server's EncryptedExtensions blob already carries the
  `preferred_address` parameter (codepoint 0x0d, length 49) with the
  expected fields, so the qns encode path is correct; the matrix cell
  failures have separate root causes (quiche has a TODO to decode PA;
  quic-go's connection.go explicitly states "We don't support
  connection migration yet … no use for the preferred_address";
  ngtcp2's failure is a missing server-issued `PATH_CHALLENGE` on the
  alt-port path, separate from PA encoding). The new test prevents
  future regressions in the qns code path even though no PA-encoding
  bug was found.

### Added

- **Server-side preferred-address migration detection
  (`Connection.noteServerLocalAddressChanged`)** — embedders observing
  an authenticated datagram for a server-role connection arrive on a
  new local address (typically a peer that followed the
  `preferred_address` advertise from the primary listener to the
  alt-port one) call this API to start RFC 9000 §5.1.1 path
  validation symmetrically with the existing peer-driven
  `handlePeerAddressChange` path. The new method snapshots
  pre-migration state, updates the active path's `local_addr`,
  generates a fresh PATH_CHALLENGE token, arms the validator with a
  `3 * PTO` timeout, and queues PATH_CHALLENGE for the next `poll`
  via the existing `emit_path_challenge_first` machinery so the
  first emitted packet on the new path leads with PATH_CHALLENGE
  rather than burying it behind ACK/PATH_RESPONSE/STREAM frames.
  Returns `PreferredAddressNotAdvertised` (new error variant) when
  no `preferred_address` is configured locally; idempotent on a
  duplicate call for the same `new_local_addr`. Wired into
  `transport.runUdpServer` (the public-API runtime helper) and into
  `interop/qns_endpoint.zig` so any embedder that uses
  `Server.Config.preferred_address` gets automatic migration
  detection. Fixes the
  `server × ngtcp2 × connectionmigration` interop cell where the
  server's first post-migration packet on the alt-port carried
  `ACK + PATH_RESPONSE + STREAM` but no `PATH_CHALLENGE`, leaving
  ngtcp2's path-validation state machine permanently waiting.

- **External-interop wrapper testcase aliases** — `tools/external_interop.zig`
  now recognizes the short forms `BA`, `CM`, `V2`, `V`, `LR`, `IPV6`/`6`, `E`,
  and `A` for the runner's `rebind-addr`, `connectionmigration`, `v2`,
  `longrtt`, `ipv6`, `ecn`, and `amplificationlimit` testcases. (`V` aliases
  to `v2` because the runner has no separate `versionnegotiation` testcase.)
  Existing aliases are unchanged.

- **Server-side RFC 9368 §6 ¶6/¶7 downgrade-attack guard** — symmetric
  counterpart to the client-side guard. New `Connection.initial_wire_version`
  snapshots the wire version of the first Initial in `acceptInitial` (before
  any compatible-version upgrade flip), and `validatePeerTransportRole`'s
  server branch closes with TRANSPORT_PARAMETER_ERROR (0x08) when the client's
  `version_information.chosen_version` doesn't match it.

- **Client-side RFC 9368 §6 compatible-version-negotiation consumption** —
  a multi-version `Client.Config.compatible_versions` (e.g.
  `preferred_version = QUIC_VERSION_1, compatible_versions =
  [QUIC_VERSION_2]`) now follows a server-driven upgrade signal
  carried on the first inbound Initial. New
  `Connection.clientAcceptCompatibleVersion` (in
  `src/conn/state.zig`), wired into
  `conn_recv_packet_handlers.handleInitial`, detects a long-header
  version mismatch on the very first Initial response, validates the
  candidate against the client's locally-advertised
  `version_information.available_versions`, and flips
  `Connection.version` (re-deriving Initial keys via `setVersion`)
  before the AEAD open runs. The hook is gated on the receive-side
  Initial space being empty so a stale on-wire-version Initial can't
  flip the version back; rejection is silent (the inbound packet then
  fails AEAD auth, which is the spec-compliant fallback). Once the
  handshake produces the server's EncryptedExtensions, a new RFC 9368
  §6 ¶6/¶7 downgrade-attack guard in `validatePeerTransportRole`
  closes the connection with TRANSPORT_PARAMETER_ERROR (0x08) when
  the server's `chosen_version` (the first entry of the peer
  `version_information` parameter) does not match the wire version
  of the response carrying it. Replaces the prior `//
  TODO(B3-followup):` placeholder on
  `Client.Config.compatible_versions`. New unit tests in
  `src/conn/_state_tests.zig` cover the upgrade-accept / -reject /
  no-op paths and the chosen_version guard; the existing `[v2,v1]
  server upgrades a v1-wire ClientHello that lists v2` e2e test in
  `tests/e2e/quic_v2_handshake.zig` now drives the full handshake to
  completion (it previously stopped after the server's commit
  because the client side was still v1-only on the receive path).

- **Public-API `Server.Config.preferred_address` (RFC 9000 §18.2 / §5.1.1)** —
  arbitrary `quic_zig.Server` embedders can now advertise a server-
  preferred-address transport parameter without rolling their own
  multi-socket dispatch. New `quic_zig.PreferredAddressConfig` type
  carries optional IPv4 / IPv6 alt-address pairs; setting
  `Server.Config.preferred_address` plus `stateless_reset_key`
  arms the auto-build path in `openSlotFromInitial`. Per accepted
  Initial the server mints a fresh seq-1 alt-CID via the same
  `mintLocalScid` path as the seq-0 SCID (so QUIC-LB embedders get a
  routing-encoded alt-CID for free), derives the matching stateless-
  reset token via `quic_zig.conn.stateless_reset.derive(key, alt_cid)`,
  stamps both into the outbound transport-parameter blob, and queues
  the matching NEW_CONNECTION_ID(seq=1) on the connection so post-
  migration packets that address the alt-CID authenticate. The
  `runUdpServer` helper consults the same field to bind alt listener
  socket(s) on the configured port(s), poll all bound listeners per
  iteration, track per-slot `last_recv_socket_idx`, and route
  outbound replies through the listener the slot most recently
  received on. `Server.init` rejects misconfigurations
  (`preferred_address` without `stateless_reset_key`,
  `preferred_address` with neither family set) as `InvalidConfig`.
  Embedders driving their own loop still get the codec auto-build —
  only the multi-socket plumbing is loop-helper-specific. New unit
  tests in `src/server.zig` (config-validation negative cases,
  `buildPreferredAddressParam` field mapping, codec round-trip
  through `Params.encode`/`decode`) and `tests/e2e/server_smoke.zig`
  (full handshake with PA: client's `peerTransportParams` surfaces
  the configured address pair + a derived stateless-reset token
  matching `conn.stateless_reset.derive(key, alt_cid)`; server-side
  slot ends up with ≥2 local SCIDs after `openSlotFromInitial`).
  `tests/e2e/server_loop_smoke.zig` covers the alt-listener bind via
  the existing shutdown-flag-already-set pattern. The qns embedder
  (`interop/qns_endpoint.zig`) is refactored onto the same public
  primitives in the follow-up entry below.

- **Server-side RFC 9368 §6 compatible-version-negotiation upgrade** —
  a multi-version `Server.Config.versions` (e.g. `[QUIC_VERSION_2,
  QUIC_VERSION_1]`) now drives an upgrade decision per inbound Initial
  rather than committing unconditionally to the wire version. New
  `wire/vneg_preparse.zig` helpers decrypt a private copy of the
  Initial under wire-version keys, reassemble the single-Initial
  ClientHello from CRYPTO frames, walk TLS extensions for
  `quic_transport_parameters` (codepoint 0x39), pull the
  `version_information` (codepoint 0x11) entry, and intersect the
  client's `available_versions` with `Config.versions` to pick the
  highest-priority overlap. The chosen version is then advertised as
  `chosen_version` in the outbound transport_params (so the EE
  BoringSSL produces during the handshake matches §5), and
  `Connection.applyPendingVersionUpgrade` flips the active version
  after the first wire-version Initial has been opened — so the
  server's first Initial response is sealed under the chosen-version
  keys. Defensive throughout: any pre-parse failure (decrypt auth,
  malformed/fragmented ClientHello, missing extension) falls back to
  the wire version, which is always spec-compliant. Replaces the
  prior `// TODO(B3-followup):` placeholder in
  `src/server.zig:openSlotFromInitial`. New unit tests in
  `src/wire/vneg_preparse.zig` (parser-level coverage) and
  `tests/e2e/quic_v2_handshake.zig` (a `[v2,v1]` server flips to v2
  for a v1-wire ClientHello carrying `version_information=[v1,v2]`,
  and stays on v1 for a legacy v1-only client).
- **QNS endpoint opts in to multi-version on `TESTCASE=versionnegotiation`** —
  `interop/qns_endpoint.zig` now flips its server-role wire-format
  version list to `[QUIC_V2, QUIC_V1]` and its client-role list to
  `[QUIC_V1, QUIC_V2]` when the runner sets
  `TESTCASE=versionnegotiation`. The server runs the RFC 9368 §6
  pre-parse (replicated against the public
  `quic_zig.wire.vneg_preparse` helpers so the qns endpoint stays a
  pure embedder of the library API), advertises the chosen version
  via `params.setCompatibleVersions`, and applies the pending
  upgrade after the first wire-version Initial via
  `Connection.applyPendingVersionUpgrade`. The client offers
  `version_information=[v1, v2]` so a multi-version server can
  upgrade. Two new unit tests pin (a) the per-role version list
  selected for each TESTCASE value and (b) the multi-version
  membership-test the dispatch loop uses to gate Version
  Negotiation responses. The interop matrix's
  `versionnegotiation` cell will only flip PASS once the parallel
  client-side upgrade-consumption branch lands.

- **Multi-Initial fragmented ClientHello reassembly for the §6
  upgrade decision** — when the client's ClientHello spans two or
  more Initial packets (the upper-bound case for a real-world TLS 1.3
  CH that grows past the 1200-byte UDP floor), the server-side §6
  pre-parse no longer falls back to the wire version. New
  `wire.vneg_preparse.ChReassembler` is a streaming, offset-based
  CRYPTO reassembler that accepts fragments in arbitrary order,
  merges overlapping retransmits, and surfaces a contiguous CH the
  moment the declared `[0..total_len)` range is covered. Each new
  slot whose first Initial carried only a CH prefix gets a per-slot
  `PendingUpgradeState` (allocated lazily, freed eagerly) that drives
  the reassembler across subsequent routed Initials; once the CH
  completes the upgrade decision lands and BoringSSL's outbound
  transport_params are updated *before* the EE is serialized, so
  §5's `chosen_version` invariant still holds. DoS-bounded by
  `PendingUpgradeState.max_initial_packets` (4 Initials per slot)
  and `max_client_hello_bytes` (4 KiB per reassembler); any failure
  (decrypt, malformed framing, conflicting overlap, exhausted
  budget) drops the pending state and falls back to the wire
  version. New unit tests in `src/wire/vneg_preparse.zig` cover
  in-order, out-of-order, duplicated, holed, oversized,
  three-fragment, and conflicting-overlap scenarios; the
  `tests/e2e/quic_v2_handshake.zig` end-to-end test exercises the
  wire-up by feeding a hand-crafted, two-Initial fragmented v1
  ClientHello carrying `version_information=[v1,v2]` to a `[v2,v1]`
  server and asserting the slot upgrades to v2 only after the
  second Initial arrives.

### Changed

- **qns endpoint adopts the public-API `PreferredAddressConfig`
  + `conn.stateless_reset.derive`** — `interop/qns_endpoint.zig`
  no longer rolls its own deterministic seq-1 alt-CID + XOR-shaped
  stateless-reset-token derivation for the `connectionmigration`
  testcase. The bespoke `buildPreferredAddress(initial_cid, alt_port)`
  helper that constructed the alt-CID via `cid[7] +%= 1` and the
  per-byte `seq ^ (i * 17) ^ cid[i % cid.len]` token is replaced
  by a thin projection of `quic_zig.PreferredAddressConfig` (built
  once in `runServer` from the runner-bridge IPv4/IPv6 constants)
  plus a per-connection seq-1 CID drawn from the CSPRNG and a
  matching token from `quic_zig.conn.stateless_reset.derive` keyed
  on a new module-level 32-byte `stateless_reset_key`. The seq-1
  alt-CID is cached on `ServerConn.pa_alt_cid` /
  `pa_alt_token` so `queueServerConnectionIds` and the per-Initial
  transport-parameter advertise read from the same source of truth
  (matching what `Server.openSlotFromInitial` does for
  `Server.Config.preferred_address`); the seq-1+ deterministic CID
  branch — used by every non-PA testcase — keeps the
  `cid[7] +%= seq` shape but now derives its stateless-reset token
  via the public HMAC helper too. The single-flag CLI shape
  `-pref-addr [::]:444` is retained: only the literal's port is
  consumed; the v4/v6 advertise + bind addresses come from
  `interop_runner_server_ipv4` / `_ipv6` and the loop binds one
  alt-listener per family (mirroring `runUdpServer`'s pattern in
  `src/transport/udp_server.zig`). The alt-CID changes from a
  deterministic seq-1 byte to CSPRNG, but the runner reads the
  alt-CID off the `preferred_address` transport parameter and
  reuses it as the migration DCID — so the on-wire bytes vary
  across runs without affecting the testcase outcome. New / updated
  unit tests in `interop/qns_endpoint.zig` cover the
  `buildPreferredAddress` projection, RFC 9000 §18.2 sentinel
  semantics for v4-only / v6-only configs, and the codec round-trip
  through `Params.encode` / `Params.decode`.

### Fixed

- **Interop `v2` cell × ngtcp2 (server + client)** — `serverVersionsForTestcase`
  and `clientVersionsForTestcase` in `interop/qns_endpoint.zig` now fire on
  `TESTCASE=v2` in addition to `TESTCASE=versionnegotiation`. The runner's
  compatible-version-negotiation cell ships as `v2` (per
  `quic-interop-runner/testcases_quic.py:TestCaseV2`), but the qns endpoint's
  testcase-name gate previously fired only on the legacy
  `versionnegotiation` value, leaving the multi-version posture
  off and the server replying with a v1 Initial. The runner then
  failed the cell with `Wrong version in server Initial. Expected
  0x6b3343cf, got {'0x1'}` for both `server × ngtcp2 × v2` and
  `client × ngtcp2 × v2`. Fix: extracted a shared
  `isVersionNegotiationTestcase` helper that exact-matches either
  `v2` or `versionnegotiation` (the legacy alias is preserved for
  internal scripts). The underlying RFC 9368 §6 transport machinery —
  server-side upgrade (`5258d56`), client-side consumption
  (`6f74ae3`), downgrade-attack guards on both sides
  (`6f74ae3` + `a3db9da`), and the `[v2,v1]` server e2e in
  `tests/e2e/quic_v2_handshake.zig` — was already correct; this
  patch is purely a one-line gate widening at the qns endpoint
  layer. The unit test "QNS server/client versions follow
  TESTCASE=versionnegotiation" in `interop/qns_endpoint.zig` now
  also covers `TESTCASE=v2` and a defensive `v22`-style substring
  case to lock the exact-equality semantics. The other peer images
  in the matrix (`quic-go`, `quiche`) advertise no v2 support in
  their interop builds, so those `v2` cells stay marked
  `unsupported (peer)` and are excluded from regression tracking.
  **Pending matrix re-run** to confirm the two ngtcp2 cells flip
  FAIL → PASS.

- **Interop server × `connectionmigration` × {quic-go, ngtcp2, quiche}** —
  the qns endpoint (`interop/qns_endpoint.zig`) now advertises a
  `preferred_address` transport parameter (RFC 9000 §18.2) and binds
  a second UDP socket on the alt-port so the runner-driven client can
  migrate to it. A new `-pref-addr [::]:444` server flag (wired in by
  `interop/qns/run_endpoint.sh` only when
  `TESTCASE=connectionmigration`) opts in: when set, the server
  binds a second listener on that port, derives a sequence-1 server
  CID + stateless reset token in lockstep with
  `queueServerConnectionIds` (so the seq-1 NEW_CONNECTION_ID frame
  the server still emits is treated as a duplicate by the client per
  `registerPeerCid`'s idempotent same-tuple branch in
  `src/conn/state.zig`), populates the IPv4 + IPv6 addresses with
  the runner's static `rightnet` assignment, and embeds all six
  fields in the `preferred_address` transport parameter. The recv
  loop polls both sockets per iteration; per-connection
  `last_recv_socket` tracks which listener last received an
  authenticated datagram so the outbound drain routes replies
  through the same socket the client most recently sent on. Three
  new unit tests pin (a) the alignment between `buildPreferredAddress`
  and `queueServerConnectionIds(seq=1)`, (b) the codec round-trip
  via `Params.encode` + `Params.decode`, and (c) the
  `last_recv_socket = 0` default. The runner's
  `connectionmigration` testcase shells through to its
  `TestCasePortRebinding` parent on the wire, so the existing
  server-side peer-migration detection (peer-addr change →
  PATH_CHALLENGE-as-first-frame, fixed in
  `followup-path-challenge-order`) continues to drive the
  `PATH_CHALLENGE` frame on the post-migration path. **Pending
  matrix re-run** to confirm the three CM cells flip
  FAIL → PASS as predicted.
- **Interop client × `rebind-addr` × quiche (second half)** — the qns
  client driver (`interop/qns_endpoint.zig`) now forwards the inbound
  source address to `Connection.handleWithEcn` and uses
  `Connection.pollDatagram` to pick the per-datagram destination
  instead of `conn.poll` + a hardcoded `server_addr`. The previous
  driver passed `null` as the source on every recv, which short-
  circuited `peerAddressChangeCandidate` (`src/conn/state.zig`) and
  left the connection blind to the simulator-rewritten server tuple;
  even when path-migration logic ran, outbound 1-RTT packets continued
  to address the original `connect()` target because the embedder
  ignored the migrated `peer_addr`. With both halves of the contract
  honored, a runner-rewritten server source now arms PATH_CHALLENGE on
  the active path (already wired in core via
  `recordAuthenticatedDatagramAddress` → `handlePeerAddressChange` —
  no role gate, the existing flow already works for the client side
  as long as the embedder feeds it the source) AND the client's
  next datagram lands on the post-rebind tuple. The second arm of
  the `client × {quic-go, quiche} × rebind-addr` failure is closed.
  A new state-tests unit test pins both halves: detection (PATH_CHALLENGE
  queued for the active path) and routing (`pollDatagram.to` reflects
  the new server tuple). A small inverse helper `pathAddressToNetAddress`
  is added next to the existing `netAddressToPathAddress` in the qns
  endpoint module.
- **Interop server × `rebind-addr` × quiche** — the server's packet
  builder now emits `PATH_CHALLENGE` as the FIRST frame of the first
  datagram on a freshly-migrated path (peer-initiated migration). The
  historical drain order in `pollLevelOnPath`
  (`src/conn/state.zig`) placed the probing frame after ACK,
  MAX_DATA, MAX_STREAMS, NEW_CONNECTION_ID, etc. Under quiche's
  tight rebind cadence the per-packet capacity (especially anti-amp-
  clamped on an unvalidated migrated path) occasionally pushed
  `PATH_CHALLENGE` either to a later frame slot or out of the
  packet entirely; quiche's path-validation state machine stalled
  in either case. The fix detects the peer-migration window
  (`pending_migration_reset` + `validator.status == .pending` + a
  queued challenge for the active app path) and writes the 9-byte
  frame BEFORE the ACK block. The same path also now pads the
  resulting datagram to 1200 bytes per RFC 9000 §8.2.1 ¶3 (subject
  to anti-amp). Two new unit tests pin the behavior:
  `peer-initiated migration emits PATH_CHALLENGE as the first frame
  even with backlogged ACKs and MAX_DATA` (positive case) and
  `non-migration polls do not pad short-header datagrams to 1200
  bytes` (regression guard so ordinary heartbeats stay small). The
  interop matrix needs a re-run to confirm the cell flip end-to-end.
- **Interop client × `rebind-addr` × {quic-go, quiche} (partial)** —
  the qns client driver (`interop/qns_endpoint.zig`) now mirrors its
  server-side `queueServerConnectionIds` once the handshake completes:
  a new `queueClientConnectionIds` helper queues a fresh client SCID
  at sequence 1 (with a deterministic stateless reset token, same
  pattern as the server). Without this, the only client-issued CID
  was the initial one (sequence 0), which left the server with no
  fresh DCID to use when it observed the client's source address
  change in the runner's network simulator — quic-go's logs flagged
  it as `skipping validation of new path … since no connection ID
  is available`. The fix is mechanical and matches RFC 9000 §5.1.2 ¶1
  / §9.5; it gates on the peer's `active_connection_id_limit`
  (we advertise 2; the helper no-ops when the budget is saturated)
  and is idempotent across loop iterations. Two unit tests in
  `interop/qns_endpoint.zig` cover the happy path and the
  budget-exhausted no-op. Pre-handshake calls are filtered upstream
  by `runClientConnection`, which only invokes the helper after
  `handshakeDone()` returns true. **Pending follow-up:** the second
  arm of the `rebind-addr` failure — quiche validates the new path
  but quic-zig "keeps sending from the OLD socket" — is unaddressed
  by this commit. The qns client driver does not detect the SIM-side
  source rebind (it has no observability hook for it), and the
  runner's `--rebind-addr` scenario rewrites source addresses
  transparently below the client socket. Fixing that requires
  either a transport-level rebind callback or recognising it
  passively from server-issued PATH_CHALLENGE on the new tuple;
  both are larger pieces of work tracked in `interop/README.md`.

### Interop verification (2026-05-09 follow-up)

The 2026-05-09 post-fix matrix re-run revealed that two of the
three landed interop fixes did NOT flip their predicted cells:

- **Fix #1 (retry IPv4-mapped IPv6)**: verified clean. server ×
  {quic-go, ngtcp2, quiche} × `retry` all flipped FAIL → PASS as
  predicted.
- **Fix #2 (warmup gating)**: the warmup race is gone — handshakes
  now complete cleanly through the rebind window — but
  client × rebind-addr × {quic-go, quiche} still FAIL because of a
  SEPARATE client-side bug. quic-zig's client never delivers a
  NEW_CONNECTION_ID frame for the migrated path (quic-go's logs:
  `skipping validation of new path … since no connection ID is
  available`); quiche's path validation succeeds but the client
  keeps sending from the OLD socket. The warmup fix itself stays
  — it's still the right behavior — but the original CHANGELOG
  claim that it would unlock 2 cells was wrong. The actual gap
  is client-side active migration + per-path NEW_CONNECTION_ID
  issuance, which is a separate piece of work.
- **Fix #3 (`endpoint_bidi_stream_limit` 1000→2500)**: REVERTED
  in this follow-up. The runner's `multiplexing` test explicitly
  validates `initial_max_streams_bidi <= 1000`
  (`testcases_quic.py:286-288`: "Server set a stream limit > 1000."),
  so raising the cap broke 2 previously-passing cells
  (server × {quic-go, ngtcp2} × `multiplexing`). The proper fix
  landed instead: `maybeQueueBatchedMaxStreams` in
  `src/conn/state.zig` now drops the credit-return watermark from
  "1/2 consumed" to "1/4 consumed" so dynamic `MAX_STREAMS`
  issuance reaches the peer before quiche's pipelined burst
  exhausts the 1000-stream initial allotment. Predicts a flip of
  server × quiche × `multiplexing` (FAIL → PASS) on the next
  matrix re-run, with no impact on the quic-go / ngtcp2 cells.

Net interop delta from the recent landed work: **+3 cells**
(retry × 3 peers); 0 regressions; 0 of the 2 rebind-addr cells the
warmup fix was predicted to unlock. The interop README has the
detailed verification table and re-scoped narratives.

Build-infra note (also from the verification): `interop/qns/Dockerfile`
pins `ARG ZIG_VERSION=0.16.0` while `mise.toml` uses `zig = "master"`
(0.17-dev) and HEAD's source needs the latter. Bumping the Dockerfile
pin is a small follow-up; meanwhile, `mise run interop-build-image`
fails and embedders need to host-build `qns-endpoint` and
hand-COPY the binary into the runner image. **Resolved below** — the
pin is now `0.17.0-dev.269+ebff43698`, sourced from `/builds/`.

### Changed

- **interop(qns): pin Dockerfile to current 0.17-dev tarball.**
  `interop/qns/Dockerfile` now pins
  `ARG ZIG_VERSION=0.17.0-dev.269+ebff43698` and downloads from
  `https://ziglang.org/builds/zig-${arch}-${ZIG_VERSION}.tar.xz`
  (dev tarballs are not under `/download/<ver>/`). Unblocks
  `mise run interop-build-image`.

### Added

- **C2 — `quic_zig.transport.runUdpClient`.** Opinionated
  `std.Io`-based UDP client loop that mirrors `runUdpServer`. Takes a
  freshly-constructed `*Client` and a `RunUdpClientOptions` literal
  (target, optional bind, ECN knobs, shutdown flag) and runs the
  `bind` → `advance` → `poll` → `receive` → `handle` → `tick` loop
  on a monotonic clock until the connection closes or the embedder
  flips the shutdown flag. Same threading model as the server side —
  application work runs on a separate thread. `client.zig`'s
  `TODO(api): runUdpClient` is gone. Three shared helpers
  (`monotonicNowUs`, `ipAddressToPathAddress`, `pathAddressToIpAddress`)
  in `src/transport/udp_server.zig` flipped from `fn` to `pub fn` so
  the client loop can reuse them. Six smoke tests in
  `tests/e2e/client_loop_smoke.zig` cover the option-surface defaults,
  malformed-target / malformed-bind / zero-buffer rejection, and the
  pre-set-shutdown-flag fast exit (parallel to the server's
  `server_loop_smoke.zig`).

- **C1 — alt-address reference embedder example.** New
  `examples/alt_addr_embedder.zig` ships three composable types
  embedders can copy or import:
    * `AddressBook` — fixed-capacity (16 entries) keyed-by-tuple
      store of received `ALTERNATIVE_V4/V6_ADDRESS` updates with
      idempotent `apply`, `currentPreferred()`, and an
      `entries_view()` slice for inspection.
    * `MigrationScheduler` — wraps
      `quic_zig.alt_addr.recommendedMigrationDelayMs` to randomize
      the migration window per the §9 thundering-herd guidance
      (default 50..500 ms; embedders pick their own bounds).
    * `Embedder.pump` — drains every `ConnectionEvent`, dispatches
      `alternative_server_address` to the book + scheduler, and
      forwards non-alt-addr events to a caller-supplied callback so
      the example composes with any existing `pollEvent` loop.
  Wired into the build as an `examples` step (`zig build examples`
  installs `alt-addr-embedder-example`); the 9 inline tests run as
  part of `zig build test`. EMBEDDING.md scope row points at the
  example for embedders that want a copy-paste starting point.

### Changed

- **boringssl-zig dep bumped to 0.6.0** (commit `8080b8a`) for
  `Aes128.initDecrypt` / `decryptBlock`, which back LB-6's
  single-pass decoder. Briefly switched to a local `../boringssl-zig`
  path dep during co-development; restored to the URL+hash form
  once 0.6.0 was tagged and pushed.

### Interop

- **External-interop matrix audit, 2026-05-09.** Ran the full
  `core+retry` matrix against quic-go, ngtcp2, and quiche in both
  roles (72 cells, 32 min wall). 58 cells pass; 10 transport
  failures clustered into 5 distinct bugs; 4 cells were peer-side
  "unsupported." Three small fixes landed against the audit
  (re-verification of the matrix is in flight):
  - **`interop/qns_endpoint.zig` `retryAddressContext` —
    drop the IPv6 flow label from the bound retry-token address
    context.** The v6 form was 1+16+2+4 = 23 bytes; that exceeds
    `retry_token.max_address_len = 22`. Once the wrapper inherited
    the binary's `[::]:443` dual-stack default (W2 below), every
    runner peer arrived as IPv4-mapped IPv6, hit the v6 branch,
    and `validateBoundInputs` returned `Error.ContextTooLong` —
    server crashed on every Retry. The flow label adds no useful
    binding (it's an ECMP routing hint, not peer identity); the
    new 19-byte form fits the budget. Expected to unlock
    server × {quic-go, ngtcp2, quiche} × `retry` (3 cells).
  - **`interop/qns_endpoint.zig` 750ms client warmup is now
    gated on `TESTCASE=longrtt`.** The warmup was a workaround
    for a quic-network-simulator bridge / ns-3-boot packet-drop
    race that only matters for `longrtt` (the runner asserts
    ≥2 ClientHellos on the wire). It was unconditionally applied
    on the assumption it was harmless — but for `rebind-addr`
    the warmup pushed the first ClientHello into the runner's
    1s rebind window, stranding the handshake CRYPTO bytes on
    the pre-rebind 4-tuple. Now opt-in via
    `ClientConnectionOptions.apply_simulator_warmup`. Expected to
    unlock client × {quic-go, quiche} × `rebind-addr` (2 cells).
  - **`interop/qns_endpoint.zig` `endpoint_bidi_stream_limit`
    raised from 1000 to 2500.** quiche's `multiplexing` test
    pipelines 2000 streams faster than
    `maybeQueueBatchedMaxStreams` (`src/conn/state.zig`) returns
    credit at the `remaining > batch / 2` watermark, deadlocking
    the connection. quic-go and ngtcp2 don't trip the timing. The
    qns-endpoint-only constant change avoids tuning the core
    watermark for every embedder. Expected to unlock server ×
    quiche × `multiplexing` (1 cell).

  Two transport bugs deferred to a focused follow-up session:
  - **Server-side `preferred_address` advertise** is unwired in
    `interop/qns_endpoint.zig` (the codec at
    `src/tls/transport_params.zig` exists). Blocks server ×
    `connectionmigration` × all three peers (3 cells). Needs an
    alt-port listening socket and runner-IP introspection.
  - **PATH_CHALLENGE-first ordering on a freshly-migrated path**
    fails under quiche's tight rebind cadence. Blocks server ×
    quiche × `rebind-addr` (1 cell). Needs interactive
    packet-order tracing.

  Two interop-wrapper bugs landed alongside the transport-side
  fixes:
  - **W1 — `interop/qns/run_endpoint.sh` TESTCASE allowlist
    expanded** to include `connectionmigration`,
    `amplificationlimit`, `ipv6`, `rebind-addr`, `rebind-port`,
    `crosstraffic`, `versionnegotiation`, `goodput`, `throughput`,
    and `v2`. Previously these all `exit 127`-ed at the wrapper,
    forcing the runner to skip them entirely.
  - **W2 — `interop/qns/run_endpoint.sh` server invocation no
    longer pins `-listen 0.0.0.0:443`**, so the binary's
    `[::]:443` dual-stack default at `interop/qns_endpoint.zig:76`
    finally takes effect. Required for the `ipv6` testcase and
    surfaced the `retryAddressContext` v6 bug above.

  README + EMBEDDING.md interop-claim staleness corrected: the
  previous "✓(H,DC,C20,S,R,Z,M) vs quic-go in both roles" line was
  sourced from a since-deleted `INTEROP_STATUS.md` (last seen at
  commit `7bd187b`, 2026-05-05) and had drifted from on-disk
  evidence. The new bullets reflect actual `interop/results/` +
  `interop/logs/` content as of 2026-05-09.

### Hardening (security-relevant)

- **draft-munizaga-quic-alternative-server-address-00 hardening
  pass.** Three resolutions after a self-audit of the workstream:
  - **0-RTT defense-in-depth.** ALTERNATIVE_V4/V6_ADDRESS frames
    are now in `frameAllowedInEarlyData`'s reject list, so a peer
    that ships them in a 0-RTT packet trips the "forbidden frame
    in 0-RTT" close (clearer diagnostic) at the same time as the
    inner negotiation gate — §4 ¶3 forbids remembering the
    `alternative_address` parameter for 0-RTT, so a server can't
    legally have completed the §4 negotiation by the time a 0-RTT
    packet is processed. New conformance test pins the close
    reason to PROTOCOL_VIOLATION (0x0a).
  - **Sequence-exhaustion fail-closed.** ALT-3 originally
    saturated `next_alternative_address_sequence` at u64::max,
    reusing the maximum value across subsequent advertisements.
    That silently violates §6 ¶5 (monotonically-increasing
    Status Sequence Numbers) — the receiver dedupes equal
    sequence numbers as retransmits and drops the second
    distinct update on the floor.
    `Connection.advertiseAlternative*Address` now returns the
    new `Error.AlternativeAddressSequenceExhausted` once the
    counter hits the cap, matching `next_datagram_id`'s
    fail-closed pattern. The boundary is unreachable in practice
    (2^64 advertise calls per connection), but the wire contract
    can never silently break.
  - **Strict-close on server-authored `alternative_address`.**
    `validatePeerTransportRole`'s client branch closes a
    connection whose server-authored transport-parameter blob
    carries `alternative_address`, regardless of whether the
    local client advertised support. §4 ¶2 only mandates this
    for "supporting" clients; closing on non-supporting clients
    too is the safer of the two spec-conformant choices and is
    documented inline as deliberate.

### Added

- **draft-munizaga-quic-alternative-server-address-00 receive event
  surface + thundering-herd helper + multipath interaction (ALT-4,
  ALT-5).** New `ConnectionEvent.alternative_server_address` variant
  surfaces parsed §6 frames to the embedder via
  `Connection.pollEvent`. The payload is a tagged
  `AlternativeServerAddressEvent { v4: V4Event, v6: V6Event }`
  carrying the address bytes, port, sequence number, and Preferred /
  Retire flag bits; convenience accessors `statusSequenceNumber()`,
  `preferred()`, `retire()` ride on the union for embedders that
  don't want to pattern-match.

  The receive arm in `state.zig` now enforces §6 ¶5 monotonicity:
  events are surfaced only for Status Sequence Numbers strictly
  greater than every previously-seen value. Equal numbers (RFC 9000
  §13.3 retransmits of the same frame) and lower numbers (QUIC's
  app-PN-space packet reordering) are absorbed silently — no
  re-emission, no protocol violation. The high-watermark is exposed
  via `Connection.highestAlternativeAddressSequenceSeen()`.

  The events queue is bounded at `max_alternative_address_events`
  (16, mirroring `max_connection_id_events`) so a misbehaving peer
  can't pin proportional connection memory by spraying updates.

  New `quic_zig.alt_addr` namespace ships
  `recommendedMigrationDelayMs(min_ms, max_ms)`, the §9
  thundering-herd mitigation: a CSPRNG-backed uniform draw embedders
  plug into their migration scheduler so concurrently-notified
  clients don't synchronize their PATH_CHALLENGE probes at the
  victim address. Degenerate / inverted ranges fail soft (return
  `min_ms`) rather than panic.

  Receive integration is composable with multipath (§8): a
  conformance test pairs an `initial_max_path_id`-negotiated
  handshake with an `alternative_address`-supporting client and
  verifies the receive arm + event surfacing behave identically.

  New `Connection` API:
  `handleAlternativeAddressV4` / `handleAlternativeAddressV6`
  (called from the frame dispatcher; pub for direct tests),
  `highestAlternativeAddressSequenceSeen`. New public type
  re-exports at `quic_zig.AlternativeServerAddressEvent` /
  `AlternativeServerAddressV4Event` /
  `AlternativeServerAddressV6Event`. Inline state tests (5)
  cover event delivery, V4/V6 sequence-space sharing,
  idempotent-retransmit dedup, and stale-reorder drop. Conformance
  suite gains 5 tests covering negotiated end-to-end event
  delivery, retransmit dedup over the wire, stale-reorder drop, §8
  multipath composability, and the §9 helper.

- **draft-munizaga-quic-alternative-server-address-00 server emit
  (ALT-3).** New `Connection.advertiseAlternativeV4Address(addr, port, opts)`
  / `advertiseAlternativeV6Address(addr, port, opts)` allocate a
  fresh `Status Sequence Number` from a connection-wide
  monotonically-increasing counter (shared between V4 and V6 per
  §6 ¶5) and queue the §6 frame for transmission at the
  application encryption level. The frame is ack-eliciting (§7)
  and retransmitted on loss with its original sequence number;
  `dispatchLostControlFramesOnPath` requeues a lost frame, and
  `pollLevel` drains the queue one frame per packet (matching the
  NEW_CONNECTION_ID drain pattern). Two embedder gates protect the
  peer: the API returns `Error.NotServerContext` when called on a
  client connection (§4 ¶2 forbids client-side emission), and
  `Error.AlternativeAddressNotNegotiated` when the peer hasn't
  advertised the §4 transport parameter (calling anyway would
  force a peer PROTOCOL_VIOLATION close). The receive arm in
  `state.zig` now accepts the frame as a no-op when the local
  endpoint advertised support — ALT-4 will replace the no-op with
  a typed `ConnectionEvent` and Status-Sequence-Number monotonicity
  enforcement at receive time. Clients now also close with
  TRANSPORT_PARAMETER_ERROR (per §4 ¶2) when the server's
  transport-parameter blob carries `alternative_address`, surfaced
  from `validatePeerTransportRole`. New helpers:
  `Connection.peerSupportsAlternativeAddress` and
  `Connection.localAdvertisedAlternativeAddress`. New retransmit
  variants `RetransmitFrame.alternative_v4_address` /
  `alternative_v6_address`. New pending queue
  `pending_frames.alternative_addresses` (FIFO of
  `PendingAlternativeAddress` tagged unions). Inline state tests
  (6) cover the role gate, negotiation gate, monotonic
  sequence allocation, V4/V6 sequence-space sharing, loss-recovery
  requeue for both frame variants, and saturation at u64 max.
  Conformance suite gains 6 tests (negotiated end-to-end pump,
  server-emit through `step`, role gate, negotiation gate,
  TRANSPORT_PARAMETER_ERROR on a server-authored param, and the
  preserved PROTOCOL_VIOLATION-when-not-negotiated assertion).
  New error codepoints: `Connection.Error.AlternativeAddressNotNegotiated`.

- **draft-munizaga-quic-alternative-server-address-00 codec
  (ALT-1, ALT-2).** New `frame.types.AlternativeV4Address` /
  `AlternativeV6Address` plus encode/decode dispatch wire the §6
  frames (type bytes `0x1d5845e2` / `0x1d5845e3`, both 4-byte
  varints). The flag byte's high bit is `Preferred`, the next bit is
  `Retire`, and the low 6 bits stay unused (zero on encode, ignored
  on decode). The §4 transport parameter `alternative_address`
  (codepoint `0xff0969d85c`) lands as a zero-length flag on
  `transport_params.Params`; `decodeAs` enforces §4 ¶2 by rejecting
  any server-authored blob that carries the parameter
  (`Error.TransportParameterError` → TRANSPORT_PARAMETER_ERROR
  connection close on the client side). The §4 ¶3 0-RTT exclusion
  is anchored by the field's `false` default — embedders that
  resume from cached peer parameters MUST clear it before
  installing them as 0-RTT context. Pinned via
  `quic_zig.alt_server_address_draft_version: u32 = 0`; bumping is
  a deliberate scoped change. New conformance suite at
  `tests/conformance/draft_munizaga_alt_addr_00.zig` (18 tests).
  Receive-side state-machine integration is **not yet wired**: the
  per-frame dispatch in `conn.state` closes the connection with
  PROTOCOL_VIOLATION on receipt today, locked in by a fixture-driven
  test using `_handshake_fixture.injectFrameAtClient`. The follow-up
  drops (ALT-3 server emit, ALT-4 client receive) flip that gate to
  a real `altAddressNegotiated()` predicate.

- **QUIC-LB draft-21 rotation auto-push (LB-4 follow-up).** New
  `Server.Config.stateless_reset_key: ?conn.stateless_reset.Key`
  unlocks server-driven rotation. When set, `installLbConfig`
  automatically walks every live slot via the new
  `Server.rotateLiveSlotCids` and queues a NEW_CONNECTION_ID frame
  with the new factory's CID and an HMAC-derived stateless-reset
  token (`conn.stateless_reset.derive`). `retire_prior_to` is set
  to the next-issued sequence so peers drop every pre-rotation CID
  on their next datagram. Per-slot push failures are swallowed so a
  single bad slot can't abort the rotation; OOM during a per-slot
  push leaves that slot on its old CIDs and the operator can retry
  via `Server.rotateLiveSlotCids` directly. Without
  `stateless_reset_key`, rotation stays lazy and embedders drive
  replenishment through the existing `connection_ids_needed` flow.
  The key bytes get `secureZero`-ed in `Server.deinit` alongside
  the other secret-key fields.
- **QUIC-LB draft-21 nonce-exhaustion auto-fallback.** `Server`'s
  internal SCID minter (`mintLocalScid`, now `pub` so conformance
  can exercise the branch directly) now falls back to
  `lb.mintUnroutable` when the active LB factory's nonce counter
  wraps. The Server keeps minting well-formed CIDs (config_id
  `0b111` with self-encoded length) until the operator rotates to a
  fresh configuration via `installLbConfig`. The fallback is
  conditioned on `local_cid_len >= lb.min_unroutable_cid_len` (8
  octets, per draft §3.1 SHOULD); shorter configurations surface
  `Error.RandFailed` so the surrounding feed/poll loop bails on
  the Initial. New §3 ¶3 / §3.1 conformance tests cover both
  branches.
- **QUIC-LB draft-21 configuration rotation (LB-4).** New
  `Server.installLbConfig(new_cfg)` swaps the active QUIC-LB factory
  in place; the previous factory's key bytes are `secureZero`-ed
  before the swap. Subsequent SCID mints (post-Initial Slot SCIDs
  and Retry SCIDs) use the new configuration; CIDs already in the
  routing table remain valid until peers organically retire them.
  The minimum supports key rotation under a fixed deployment shape:
  `installLbConfig` rejects configurations whose `cidLength` differs
  from the server's existing `local_cid_len`. Pushing
  NEW_CONNECTION_ID frames to live peers is operational and remains
  embedder-driven via the existing `connection_ids_needed` event.
- **QUIC-LB draft-21 unroutable CID fallback (LB-5).** New free
  function `quic_zig.lb.mintUnroutable(dst, len)` writes a §3.1
  unroutable CID: first octet `0b111_xxxxx` with the low 5 bits
  encoding `cid_len - 1`, plus `len - 1` CSPRNG bytes. Length is
  constrained to 8..20 octets to honour the §3.1 SHOULD that
  unroutable CIDs carry at least 7 octets of entropy after the first
  byte. Embedders call this directly when they decide unroutable
  mode is appropriate (rotation gap, nonce exhaustion); the §5.5
  decoder also recognises 0b111 first octets and surfaces them as
  `DecodeError.UnroutableCid`.
- **QUIC-LB draft-21 LB-side decode helper (LB-6, complete).** New
  `quic_zig.lb.decode(cid, cfg) → Decoded { config_id, server_id,
  nonce }` recovers the routing identity from a minted CID. All
  three modes are operational: plaintext (§5.5), single-pass
  AES-128-ECB-decrypt (§5.5.1), and four-pass Feistel (§5.5.2).
  Single-pass decode required `Aes128.initDecrypt` /
  `decryptBlock` from boringssl-zig 0.6.0; quic-zig pins
  boringssl-zig as a local path dep until 0.6.0 ships as a tagged
  release. Round-trip property tests cover every supported
  `(sid_len, nonce_len)` split, plus a byte-exact KAT decoding
  draft Appendix B.2 vector #2.
- **QUIC-LB draft-21 four-pass Feistel encryption (LB-3).** Adds the
  §5.4.2 four-pass mode in a new `quic_zig.lb.feistel` module: when
  the embedder configures `Server.Config.quic_lb` with a 16-byte AES
  key and the plaintext block isn't 16 octets, every minted CID body
  becomes a length-preserving Feistel encryption of `server_id ||
  nonce` over four AES-128-ECB rounds whose distinct inputs come from
  the §5.4.2.2 `expand(combined, pass, half)` function. Odd-length
  plaintexts get the boundary-nibble clearing of §5.4.2.3 so the
  half-byte at the split doesn't appear in both halves. The
  §5.4.2.4 worked example (3+4 server_id/nonce, key
  `fdf726a9893ec05c0632d3956680baf0`) is locked in as a byte-exact
  conformance KAT, plus a length-preservation property test across
  every supported `combined` and an encrypt/decrypt round-trip
  property test. `feistel.decrypt` ships alongside encrypt so
  ops/test tooling and future LB-side decode helpers (LB-6) can
  recover the plaintext. `Server.init` now accepts every valid
  encrypted-mode configuration; the visible-debt skip for §5.4.2 is
  retired.
- **QUIC-LB draft-21 single-pass AES-128-ECB encryption (LB-2).**
  Adds the §5.4.1 single-pass mode to `quic_zig.lb`: when an embedder
  configures `Server.Config.quic_lb` with a 16-byte AES-128 key and
  the plaintext block sums to exactly 16 octets
  (`server_id_len + nonce_len == 16`), every minted CID body becomes
  `AES-128-ECB(key, server_id || nonce)` while the first octet stays
  in the clear. New `lb.NonceCounter` seeds from the CSPRNG and
  advances by one per mint so the same nonce is never reused under
  the same key (§5.4 ¶3); `Factory.mint` returns
  `error.NonceExhausted` on counter wrap. `Factory.deinit`
  `secureZero`s the embedded key and counter buffer; `Server.deinit`
  calls into it. KAT for draft Appendix B.2 vector #2 added to
  `tests/conformance/quic_lb_draft21.zig`. (Four-pass Feistel for
  `combined != 16` followed in LB-3 — see entry above.)
- **QUIC-LB draft-21 server-side, plaintext mode (LB-1).** New
  `quic_zig.lb` module
  ([draft-ietf-quic-load-balancers-21](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/))
  encodes the load-balancer routing identity into every locally-issued
  SCID. Off by default; opt in via `Server.Config.quic_lb`. When set,
  `Server.init` resolves `local_cid_len` from the LB configuration
  (`1 + server_id_len + nonce_len`) and routes both the post-Initial
  Slot SCID and the Retry SCID through `lb.Factory.mint`. Plaintext
  mode (§5.2) auto-enables `disable_active_migration` per draft §3 ¶3
  unless the embedder already set it. Pinned to draft revision 21 via
  `quic_zig.quic_lb_draft_version`. **Hardening note:** opting in
  deliberately inverts the "Server SCIDs are CSPRNG draws" default;
  treat the load balancer as the trust boundary. The Retry Service
  was split into a separate IETF draft and is out of scope here.

- **RFC 9287 — Greasing the QUIC Bit.** New `grease_quic_bit`
  transport parameter (codepoint `0x2ab2`, zero-length flag) lands on
  `tls.TransportParams` with a `false` default; non-empty values on
  the wire reject as `InvalidValue`. New
  `Connection.peerSupportsGreaseQuicBit()` predicate fires only when
  *both* sides advertised the flag, parallel to
  `multipathNegotiated()`. Once it returns true, every outgoing
  long- or short-header packet draws bit 6 of the first byte (the
  QUIC Bit) at random per packet via BoringSSL's `RAND_bytes`; the
  wire decoder has always accepted any value for that bit.
  Long- and short-header structs (`Initial`, `ZeroRtt`, `Handshake`,
  `Retry`, `OneRtt`) and the matching seal-options structs gain a
  `quic_bit: u1 = 1` field; the default reproduces the v1 wire
  exactly, so embedders that don't opt in see no change.
  Conformance: 13 new tests in
  `tests/conformance/rfc9287_grease_quic_bit.zig` covering §3 wire
  format and §6.1 transport parameter.

- **RFC 9368 QUIC v2.** Embedders can now opt into the v2 wire format
  alongside v1. The differences are version-scoped — short headers,
  frame syntax, and the connection-level state machine are
  unchanged from RFC 9000.
    * `quic_zig.QUIC_VERSION_2 = 0x6b3343cf` constant.
    * `wire.initial.deriveInitialKeysFor(version, dcid, is_server)`
      uses the §3.3.1 salt + §3.3.2 HKDF labels (`quicv2 key` / `iv`
      / `hp`) for v2; the existing `deriveInitialKeys(dcid, is_server)`
      stays as a v1 thin wrapper.
    * `wire.header.LongType` is now an abstract enum with
      `longTypeFromBits(version, bits)` / `longTypeToBits(version,
      type)` helpers — RFC 9368 §3.2 v2 rotates the wire bits to
      Initial=0b01, 0-RTT=0b10, Handshake=0b11, Retry=0b00.
    * `wire.long_packet.retryIntegrityTag(version, ...)` and
      `validateRetryIntegrity(...)` use the §3.3.3 v2 AEAD constants
      when the packet's version field is `0x6b3343cf`.
    * `tls.transport_params.Params` learns the §5
      `version_information` parameter (codepoint `0x11`) via
      `setCompatibleVersions(versions)` /
      `compatibleVersions()` — encoded as a list of u32s with the
      sender's chosen version first, decoded into a fixed-size
      inline buffer so `Params` stays a value type.
    * `Server.Config.versions: []const u32 = &.{0x00000001}` — opt
      a server into v2 by adding `0x6b3343cf`. The Version
      Negotiation gate now lists every entry; an inbound Initial
      with a non-listed version earns a VN response listing the
      configured set. The slot's connection adopts the matching
      incoming version, deriving its Initial keys under the right
      salt + label set.
    * `Client.Config.preferred_version: u32 = 0x00000001` and
      `Client.Config.compatible_versions: []const u32 = &.{}` —
      opt a client into v2 by setting `preferred_version =
      0x6b3343cf`. A non-empty `compatible_versions` advertises
      `version_information` for the server's RFC 9368 §6
      compatible-version-negotiation upgrade path.
    * New `tests/conformance/rfc9368_quic_v2.zig` (19 tests)
      covering the §3.2 packet-type rotation, §3.3.1 salt, §3.3.2
      HKDF labels, §3.3.3 Retry tag constants, §5
      transport-parameter codec, and §6 server gating.
    * New `tests/e2e/quic_v2_handshake.zig` (5 tests) drives a real
      Server <-> Client handshake under v2 including the v1
      regression path, the v1+v2-server / v1-client backwards-compat
      path, and the version-information transport-parameter
      visibility.

  Server-driven compatible-version-negotiation upgrade (RFC 9368
  §6) — switching a slot's version mid-handshake based on the
  client's `version_information` set — is tracked as a follow-up
  (`// TODO(B3-followup):` in `src/server.zig`); standalone v2 is
  the more common case in practice. The merge into main also fixed
  a latent v1 dispatch bug in `Connection.handleOnePacket` and
  `shouldDrainTlsAfterPacket` where raw long-header type bits were
  read via the v1 mapping; both now route through
  `wire_header.longTypeFromBits(version, bits)`.

- **B1 — IP ECN signaling (RFC 9000 §13.4 / RFC 3168).** End-to-end
  Explicit Congestion Notification: outgoing 1-RTT and 0-RTT
  packets are marked ECT(0) by default, incoming datagrams have
  their TOS byte parsed off cmsg, the four IETF codepoints
  (`Not-ECT` / `ECT(0)` / `ECT(1)` / `CE`) accumulate into
  per-PN-space `recv_ect0` / `recv_ect1` / `recv_ce` counters, and
  outgoing ACK frames switch to type `0x03` (with the §19.3.2 ECN
  trailer) whenever a level has observed any ECN-marked packet.
  Inbound ACKs are validated per §13.4.2 monotonicity; a CE-count
  bump halves cwnd via the new `NewReno.onCongestionEvent`
  (mirror of `onPacketLost` with no byte budget). A non-monotonic
  ECN report flips the level's `validation` to `failed` and stops
  emitting ECN counts on outbound ACKs from that space.

  Public surface additions:
    * `quic_zig.transport.EcnCodepoint` /
      `setEcnSendMarking` / `setEcnRecvEnabled` /
      `parseEcnFromControl` / `default_cmsg_buffer_bytes`.
    * `Connection.ecn_enabled: bool = true` (kill-switch),
      `Connection.handleWithEcn(bytes, from, ecn, now_us)`.
    * `Server.feedWithEcn(bytes, from, ecn, now_us)`.
    * `RunUdpOptions.enable_ecn: bool = true`,
      `ecn_send_codepoint`, `cmsg_buffer_bytes` — the bundled
      `runUdpServer` loop sets the IP TOS / IPV6 TCLASS sockopts
      and parses cmsgs into the Connection automatically.
    * `PnSpace.recv_ect0` / `recv_ect1` / `recv_ce` /
      `peer_ack_*` / `validation` /
      `onPacketReceivedWithEcn` / `hasObservedEcn`.
    * `AckTracker.toAckFrame*WithEcn` overloads passing through
      the §19.3.2 ECN trailer.
    * `NewReno.onCongestionEvent(ce_packet_sent_time_us)`.

  New conformance suite at `tests/conformance/rfc9000_ecn.zig`
  pins the §19.3.2 wire shape, the §13.4.2 validation /
  CE-bump-fires-onCongestionEvent / non-monotonic-counts-fails
  flow, and the on-by-default policy. Legacy `Connection.handle`
  / `Server.feed` are preserved as `Not-ECT` thunks so embedders
  that haven't plumbed cmsg yet stay source-compatible.

  macOS workarounds shipped: hard-coded `IP_TOS=3` /
  `IPV6_TCLASS=36` constants keyed on `builtin.os.tag` (std
  `posix.IP` / `posix.IPV6` resolve to `void` on Darwin), plus a
  `setsockoptIntChecked` mapping `EINVAL` / `ENOPROTOOPT` /
  `OPNOTSUPP` to `error.Unsupported`. The kqueue I/O backend's
  `netReceive` is `@panic("TODO")` upstream, so the cmsg-aware
  path only runs on the Threaded backend (Linux QNS, `std.testing`
  default). Follow-up: `interop/qns_endpoint.zig` still uses the
  legacy `Connection.handle` and `Server.feed` thunks; pumping
  the qns endpoint through the ECN-aware paths would let the
  runner's `E` testcase exercise them.

- **RFC 8899 DPLPMTUD (Datagram Packetization Layer Path MTU
  Discovery), QUIC profile.** Per-`PathState` probe state machine
  (`PmtudState`: disabled / search / search_complete / error_state),
  plus an embedder configuration knob exposed through
  `Server.Config.pmtud` / `Client.Config.pmtud` (re-exported as
  `quic_zig.conn.PmtudConfig`). The probe scheduler runs in
  `Connection.pollLevelOnPath` (`.application` only): when the active
  path is in `search` and no probe is in flight it builds a
  PADDING+PING packet sized to `pmtu + probe_step`, capped at the
  upper bound or `pmtud_config.max_mtu` (RFC 9000 §14.4 names the
  PADDING+PING shape; RFC 8899 §6 names the QUIC profile). Probe
  outcomes are routed independently of regular ack/loss bookkeeping:
  probe ack lifts `path.pmtu` and either schedules the next step or
  transitions to `search_complete`; probe loss bumps a fail counter
  and — once `probe_threshold` consecutive losses land — records the
  probed size as the upper bound (RFC 8899 §5.1.4). Probe loss MUST
  NOT trigger congestion-control reactions (RFC 8899 §4.4 / §5.1.5);
  the loss-detection paths skip the `LossStats` add for probes while
  still routing any coalesced STREAM / control frames through the
  normal requeue path. `pmtudOnRegularLost` drives §4.4 black-hole
  detection: `probe_threshold` consecutive REGULAR-packet losses at
  the current pmtu halve `path.pmtu` (down to `initial_mtu`) and
  re-enter `search`. New `Connection.pmtu()` getter returns the
  active path's PMTU floor; new `PathStats` fields surface
  `pmtu` / `pmtu_state` / `pmtu_probes_in_flight` / `pmtu_fail_count`
  / `pmtu_upper_bound` for embedder telemetry. `seal1Rtt` gains a
  `pad_to: usize = 0` option mirroring `sealInitial`. The 1-RTT
  plaintext staging buffer grew from 1200 to 4096 bytes
  (`max_recv_plaintext`) to accommodate probes up to 1452+ bytes.
  Defaults: `initial_mtu = 1200`, `max_mtu = 1452`,
  `probe_step = 64`, `probe_threshold = 3`, `enable = true` on the
  embedder-facing `PmtudConfig{}` and on `Server`/`Client` configs;
  `Connection.pmtud_config` defaults to `enable = false` so direct
  `Connection.initClient/initServer` callers (test fixtures) keep
  the historical static-MTU behaviour. Covered by 12 RFC-traceable
  conformance tests in `tests/conformance/rfc8899_dplpmtud.zig` and
  10 inline state-machine tests in `src/conn/path.zig`.

### Hardening (security-relevant)

- **§17.2.1 / §17.3 — Reserved Bits enforced on receive.**
  `Connection.handleInitial` / `handleZeroRtt` / `handleHandshake` /
  `handleShort` now close with `transport_error_protocol_violation`
  when the post-HP first byte carries non-zero Reserved Bits — the
  bits are surfaced through `LongOpenResult.reserved_bits` and
  `Open1RttResult.reserved_bits` after AEAD authenticates the AAD.
  RFC 9000 §17.2.1 ¶17 / §17.3 ¶3 explicitly require this gate;
  previously the wire layer decoded the bits faithfully but no
  caller acted on them.
- **§12.4 — Per-encryption-level allowed-frames table at Initial /
  Handshake.** New `frameAllowedInInitialOrHandshake` whitelist in
  `Connection.dispatchFrames`: only PADDING, PING, ACK, CRYPTO, and
  CONNECTION_CLOSE-0x1c (transport variant) are accepted; anything
  else is treated as PROTOCOL_VIOLATION. Closes the broader RFC 9000
  §12.4 / §17.2 gap that surfaced as the RFC 9221 §4 ¶3 instance
  (DATAGRAM in Initial) plus other latent classes.
- **§19.20 — HANDSHAKE_DONE role gate.** A server receiving
  HANDSHAKE_DONE now closes with PROTOCOL_VIOLATION (the RFC says it
  is a server-only frame; only clients ever legitimately receive it).
- **§7.3 / §18.2 — Role-aware transport-parameter decode.** New
  `transport_params.decodeAs(blob, .{ .role, .server_sent_retry })`
  applies the §7.3 / §18.2 role gates on top of the existing wire
  codec: rejects server-only TPs from a client peer
  (`preferred_address`, `original_destination_connection_id`,
  `retry_source_connection_id`, `stateless_reset_token`), enforces
  `initial_source_connection_id` presence on every endpoint,
  `retry_source_connection_id` presence iff the server actually sent
  Retry, plus universal bound checks (max_udp_payload_size ≥ 1200,
  initial_max_streams_{bidi,uni} ≤ 2^60). The role-agnostic `decode`
  is unchanged for callers that legitimately need the codec primitive.

### Tests

- **+10 conformance tests unskipped** (44 → 34 visible debt).
  Enforcement for the four hardening items above is now exercised
  from the auditor-facing conformance corpus, not just from src/
  unit tests:
    * §17.2.1 long-header Reserved Bits gate (live test)
    * §12.4 Initial-level forbidden-frame gate (live test)
    * RFC 9221 §4 ¶3 DATAGRAM-in-Initial gate (live test)
    * 7 × §7.3 / §18.2 transport-parameter role / bound gates (live)
  The remaining 34 skips are all visible-debt entries documenting
  Connection-level requirements that need a paired-Connection
  conformance fixture (handshake-confirmed, 1-RTT keys, 0-RTT keys);
  none are real implementation gaps.
- **Conformance entry point moved** from `tests/conformance/root.zig`
  to `tests/conformance.zig` (sibling of `tests/root.zig`) so the
  Zig package boundary widens to `tests/` — suites can now
  `@embedFile("../data/test_cert.pem")` for Server-fixture tests.
- **Shared fixture helper** at `tests/conformance/_initial_fixture.zig`
  builds an authentic Initial packet (with caller-controlled Reserved
  Bits and frame payload) and feeds it through `Server.feed`, used by
  the §17.2.1 / §12.4 / RFC 9221 §4 ¶3 receiver-side tests.

### API additions

- `quic-zig.wire.long_packet.LongOpenResult` gains a `reserved_bits: u2`
  field carrying the post-HP, post-AEAD authenticated bits 3-2 of the
  long-header first byte.
- `quic-zig.wire.short_packet.Open1RttResult` gains a `reserved_bits: u2`
  field carrying the post-HP, post-AEAD authenticated bits 4-3 of the
  short-header first byte.
- `quic-zig.wire.long_packet.InitialSealOptions` gains a
  `reserved_bits: u2 = 0` field. Default 0 — production callers
  MUST NOT change it; the field exists only so test fixtures can
  construct malicious-but-authentic packets that exercise the
  receiver-side §17.2.1 ¶17 gate.
- `quic-zig.tls.transport_params.Role`, `DecodeOptions`, `decodeAs`,
  and `Error.TransportParameterError`. Role-aware decode primitive
  for §7.3 / §18.2 validation; the existing role-agnostic `decode`
  is unchanged.

### Tests (continued — original conformance-suite scaffold)

- **RFC-traceable conformance suite under `tests/conformance/`.** 11
  files (one per RFC area), 297 tests + 44 visible-debt skips = 341
  total tests. Every test name pairs a BCP 14 keyword (MUST / MUST
  NOT / SHOULD / MAY / NORMATIVE) with a precise `[RFC#### §X.Y ¶N]`
  citation per the `zspec-rfc-testing.md` grammar. Coverage matrix:

      rfc8999_invariants.zig                 14 tests   (RFC 8999 §4-§6)
      rfc9000_varint.zig                     21 tests   (§16)
      rfc9000_packet_headers.zig             38 tests   (§17, all 5 packet types)
      rfc9000_transport_params.zig           36 tests   (§18, every defined TP)
      rfc9000_frames.zig                     58 tests   (§19, all 18 frame types)
      rfc9000_streams_flow.zig               37 tests   (§3-§5, §10, §10.3 stateless reset)
      rfc9000_negotiation_validation.zig     33 tests   (§6 VN, §8 address validation, §9 migration)
      rfc9000_packetization.zig              21 tests   (§12.3 PN spaces, §13 ACKs, §14 size, §20 errors)
      rfc9001_tls.zig                        36 tests   (§5 keys/HP/AEAD, §5.6 anti-replay, §5.8 retry, §6 KU, §8 ALPN)
      rfc9002_loss_recovery.zig              29 tests   (§5 RTT, §6 loss, §7 cwnd, §B.5/B.6/§7.6.1 NewReno)
      rfc9221_datagram.zig                   18 tests   (§3 TP 0x20, §4 frame types 0x30/0x31)

  Wired as its own `zig build conformance` step using the default Zig
  test runner (no third-party runner dependency). Compile-time filter
  via `-Dconformance-filter='RFC9000 §17'` etc. — Zig's default runner
  has no runtime filter, so the build option participates in the
  compile cache key for fast incremental rebuilds.

  Full test count is now 879 pass + 44 skip across 5 binaries (was
  596 + 10 stub skips). The 44 skips are visible conformance debt,
  each with an inline TODO; most depend on a Connection-level
  conformance fixture that drives `dispatchFrames` without a full TLS
  handshake.

  Real implementation gaps surfaced by the suite (carried forward as
  visible debt rather than fixed in this commit):

  - **§17.2.1 / §17.3 Reserved Bits** — emitted as zero (covered),
    but `Connection` does not yet treat non-zero received Reserved
    Bits as PROTOCOL_VIOLATION.
  - **RFC 9221 §4 ¶3** — DATAGRAM in non-1-RTT/0-RTT packet MUST
    close with PROTOCOL_VIOLATION; `Connection.dispatchFrames` lacks
    a per-encryption-level allowed-frames table for Initial /
    Handshake (broader RFC 9000 §12.4 / §17.2 work).

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
  to `"quic-zig retry token v2"`. Plus `fuzz: retry_token validate
  never panics`. Commit `474a71b`.
- §4.4 — Per-source Version Negotiation rate limit
  (`vn_count` / `vn_window_start_us`, default 8/window) on
  `SourceRateEntry` with independent counter axis from Initial rate
  limit. New `feeds_vn_rate_limited` MetricsSnapshot counter. Commit
  `b22ebee`.
- §4.5 — Server / Retry SCIDs minted directly from BoringSSL CSPRNG
  (`boringssl.crypto.rand.fillBytes`); the seed-once
  `std.Random.DefaultPrng` ceremony is gone. Commit `2137f77`.
- §4.5 — `quic-zig.conn.stateless_reset` default-safe HMAC-SHA256
  derivation helper for stateless-reset tokens (Key /
  derive(key, cid) / generateKey()) with domain separator
  `"quic-zig stateless reset v1"`. Commit `030b9fe`.
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
- §5.2 / RFC 9001 §5.6 — `quic-zig.tls.AntiReplayTracker` primitive:
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
  `quic-zig.conn.new_token` module with AES-GCM-256-sealed token
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
  `quic-zig.MigrationCallback` / `quic-zig.MigrationDecision`.
- `QlogMigrationFailReason` enum (`timeout`, `policy_denied`) and
  matching optional `migration_fail_reason` field on `QlogEvent`.
  Existing `migration_path_failed` emit sites now populate
  `.timeout`; the new `policy_denied` value comes from the
  migration-callback deny path.
- `quic-zig.Server.Slot` distributed-tracing surface for embedders
  building W3C tracecontext / OpenTelemetry pipelines. Each slot now
  carries a server-local monotonic `slot_id: u64` stamped at accept
  time (stable for the slot's lifetime, suitable as the primary key
  in operational logs without depending on peer-chosen CIDs), plus
  optional `trace_id: ?[16]u8` and `parent_span_id: ?[8]u8` fields
  the embedder attaches via the new `Slot.setTraceContext(trace_id,
  parent_span_id)` method. quic-zig treats both as opaque metadata —
  they are never read or forwarded into qlog or onto the wire.
- `quic-zig.Server.replaceTlsContext` — graceful, hot-swappable TLS
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
- `quic-zig.Server` operability surface: a structured logging hook
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
- `quic-zig.Server` production-grade convenience wrapper for embedding
  quic-zig as a UDP server. Owns the TLS context and a CID-to-slot
  routing table; the embedder owns the socket and clock. Config /
  Slot / feed / poll / tick / reap / iterator. The router resyncs
  each slot's CID set from `Connection.localScids` after every
  `feed`, so NEW_CONNECTION_ID-issued SCIDs route from the next
  datagram on (RFC 9000 §5.1.1). Lookup is `std.AutoHashMap` O(1).
  Per-source-address Initial-acceptance rate limiter is opt-in via
  `Config.max_initials_per_source_per_window` and surfaces a
  distinct `FeedOutcome.rate_limited` variant. See `src/server.zig`
  and the `README.md` "Embed quic-zig as a server" section.
- `quic-zig.Server` Version Negotiation and stateless Retry gates,
  surfaced through new `FeedOutcome.version_negotiated` /
  `FeedOutcome.retry_sent` variants and a new
  `Server.drainStatelessResponse` method. Version Negotiation is
  unconditional (RFC 9000 §6 / RFC 8999 §6) — any long-header
  packet with version != `quic-zig.QUIC_VERSION_1` queues a VN
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
- `quic-zig.Client` convenience wrapper for embedding quic-zig as a QUIC
  client. Mirror to `quic-zig.Server`: builds a client-mode TLS
  context, generates the per-connection random initial DCID and
  SCID (RFC 9000 §7.2), and runs `bind` / `setLocalScid` /
  `setInitialDcid` / `setPeerDcid` / `setTransportParams` in the
  right order, returning a heap-allocated `*Connection` ready for
  the first `advance` / `poll`. Optional `Config.session_ticket`
  wires up resumption + 0-RTT in one step. See `src/client.zig` and
  the `README.md` "Embed quic-zig as a client" section.
- `quic-zig.transport.runUdpServer` — opinionated `std.Io`-based UDP
  server loop that binds the socket, applies `SO_RCVBUF` / `SO_SNDBUF`
  tuning, drives the `feed` / `pollDatagram` / `tick` / `reap`
  cadence on a 5 ms heartbeat, and shuts down cleanly when a
  caller-supplied `std.atomic.Value(bool)` flag flips. Intended as
  the fastest path from `quic-zig.Server.init` to a working QUIC
  endpoint. The QNS endpoint and other embedders that need full
  control (Retry, version negotiation, deterministic CIDs) keep
  driving the I/O-agnostic Server interface directly. See
  `src/transport/udp_server.zig` and the README "Embed quic-zig as a
  server" section.
- `Connection.localScidCount`, `Connection.localScids`, and
  `Connection.ownsLocalCid` for embedders that maintain a
  CID-to-connection routing table outside the connection
  (`quic-zig.Server` is the canonical caller).
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
  build quic-zig without a sibling boringssl-zig checkout. Bumping the
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
- quic-zig remains pre-1.0 (`0.0.0` in `build.zig.zon`). The transport is
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
  (`quic-zig.KeylogCallback`) and qlog-style application key-update
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

[Unreleased]: https://github.com/nullstyle/quic-zig/compare/v0.0.0...HEAD
[0.0.0]: https://github.com/nullstyle/quic-zig
