# nullq interop status

Current as of 2026-05-04.

## Verified in this workspace

- `zig build test` in `nullq`: passing, including deterministic
  PTO/loss unit tests, path-aware multipath ACK/PTO tests, duplicate
  per-path Application PN stream tracking, draft-21 nonce/CID limit
  tests, path CID replenishment and abandoned-path retention tests,
  a deterministic two-path concurrent transfer with asymmetric delay,
  reordering, loss, DATAGRAMs, and mid-transfer path abandonment,
  key-update lifecycle tests for previous/current/next read keys,
  3x-PTO previous-key discard, local update ACK gating, multipath ACK
  gating, proactive packet-limit updates, AEAD integrity-limit close
  behavior, AEAD confidentiality-limit close diagnostics, and
  AES-128/AES-256/ChaCha packet-protection round-trips,
  client-side Version Negotiation and Retry integrity/transport
  parameter tests, stateless Retry-token validation and negative-path
  tests, shutdown/stateless-reset edge tests, initial 0-RTT
  packet/receive/rejection/loss unit tests, deterministic
  parser/property fuzz smokes for varints, frames, transport params,
  packet headers, ACK ranges, and CRYPTO/STREAM reassembly, typed
  `preferred_address` transport-parameter codec coverage, duplicate
  transport-parameter rejection, and the 10% simulated-loss stream
  exchange.
- `zig build` in `nullq-peer`: passing.
- `go test ./cmd/quicpeer ./internal/interop` in `go-quic-peer`: passing.
- `go-quic-peer client` against `nullq-peer`: passing for handshake,
  bidi echo, 512 KiB upload, client/server uni streams, DATAGRAM echo,
  RESET_STREAM, and concurrent bidi streams.
- `go-quic-peer client` against `nullq-peer -retry`: passing for a
  server-forced Retry with HMAC-bound token validation, followed by the
  full single-path stream/DATAGRAM/reset scenario.
- `go-quic-peer client -prefer-v2` against `nullq-peer`: passing for
  live Version Negotiation from quic-go's initial QUIC v2 attempt down
  to nullq's supported QUIC v1, followed by the full single-path
  scenario.
- `go-quic-peer client -0rtt=true` against `nullq-peer`: passing,
  including ticket seed, resumed connection, early STREAM request, and
  `Used0RTT == true`.
- `go-quic-peer client -0rtt=true -0rtt-expect rejected` against
  `nullq-peer -reject-0rtt-after 2`: passing; the peer intentionally
  changes the replay context on the resumed connection, quic-go reports
  0-RTT rejection, and the scenario retries the request as 1-RTT.
- `go-quic-peer multipath` against `nullq-peer`: passing for secondary
  socket add, PATH_CHALLENGE/PATH_RESPONSE probe, path switch, echo,
  DATAGRAM after switch, a 1 MiB upload that remains open while the
  active path switches back, explicit upload-window traffic counters on
  both UDP sockets, PATH_ABANDON/secondary close, concurrent bidi
  streams, and DATAGRAM after secondary close. The latest local run
  recorded `primary=951 writes/1068259 bytes` and
  `secondary=34 writes/36339 bytes` during the upload window.
- `zig build qns-endpoint` in `nullq`: passing for the first official
  QUIC interop-runner endpoint binary. The endpoint is currently
  server-side only, speaks HTTP/0.9 ALPN `hq-interop`, serves `/www`,
  loads `/certs` material, supports server-side Retry, and is wrapped
  by the Zig-native `external-interop` helper plus
  `interop/qns/Dockerfile`.
- `zig build external-interop -- preflight` and
  `zig build external-interop -- build-image --dry-run` in `nullq`:
  passing. The helper stages a throwaway Docker context under
  `.zig-cache/` and prints the expected Docker build invocation.

## Production work landed

- Applications can now abort the send half of a stream directly with
  public `Connection.streamReset(stream_id, application_error_code)`.
  The call uses the existing RESET_STREAM ACK/loss machinery, discards
  queued STREAM data, and reports the current written byte count as the
  final size.
- Embedders now get close/error status without reaching into private
  state. `Connection.closeState()` distinguishes open, closing,
  draining, and terminal closed states; `Connection.closeEvent()`
  exposes sticky local, peer, idle-timeout, and stateless-reset close
  metadata; and `Connection.pollEvent()` delivers the same close
  notification once through the public `ConnectionEvent` union.
- Draining is now enforced on the receive side: once close is pending or
  draining, incoming datagrams are ignored instead of mutating path,
  stream, or TLS state. Draining expiration clears recovery timers and
  transitions the public close state to terminal closed.
- Stateless reset detection now compares short-header packet tails
  against peer-issued tokens from transport parameters and
  NEW_CONNECTION_ID/PATH_NEW_CONNECTION_ID. Matching packets enter
  draining without queuing CONNECTION_CLOSE or charging AEAD auth
  failure limits.
- Client-side Version Negotiation now validates the RFC 9000 CID echo
  checks, ignores packets that still advertise QUIC v1, and terminally
  closes with a public close event when no compatible version is
  offered.
- Client-side Retry now validates the RFC 9001 integrity tag, enforces
  the Retry CID constraints, stores the token for the replacement
  Initial, resets Initial packet number/recovery state, and validates
  the peer's original/retry source CID transport parameters.
- Server embedders can write a standards-compliant QUIC v1 Retry packet
  with `Connection.writeRetry`; token contents and acceptance policy
  intentionally remain application-owned.
- A first official QUIC interop-runner gate has landed. `qns-endpoint`
  adapts nullq to the runner's HTTP/0.9 server contract, while
  `zig build external-interop -- ...` builds a local Docker endpoint,
  overlays a `nullq` server entry into a throwaway runner copy, and
  runs nullq-as-server against selected external clients without
  mutating the external checkout.
- The public `retry_token` helper can mint and validate stateless
  HMAC-SHA256 Retry tokens bound to caller-supplied client address
  bytes, original DCID, Retry SCID, QUIC version, issue time, and
  expiry. It has deterministic coverage for changed address/CID replay,
  wrong version, expiry, future tokens, truncation, malformed format,
  and bad MACs.
- Server embedders can write a Version Negotiation packet with
  `Connection.writeVersionNegotiation`, and the peer harness now uses it
  to negotiate quic-go from v2 down to v1.
- Out-of-order CRYPTO receive reassembly remains in place and handles
  the quic-go ClientHello fragmentation shape.
- Sent-packet metadata now records retransmittable control frames
  without inflating every packet slot; outstanding metadata is cleaned
  up on ACK, loss, and connection deinit. STREAM-bearing packets also
  carry a connection-local stream key so duplicate per-path Application
  PNs cannot collide in `SendStream` ACK/loss bookkeeping.
- Loss requeues STREAM data via `SendStream`, CRYPTO bytes at their
  original offsets, and control frames for MAX_DATA, MAX_STREAM_DATA,
  NEW_CONNECTION_ID, STOP_SENDING, PATH_RESPONSE, PATH_CHALLENGE, and
  RESET_STREAM.
- RESET_STREAM now observes ACK/loss outcomes: ACK moves the stream to
  `reset_recvd`, loss clears `queued` so the frame is emitted again.
- DATAGRAM remains unreliable by transport design, but senders can use
  `sendDatagramTracked` and receive `datagram_acked` /
  `datagram_lost` events through `pollEvent` for app-level retry and
  telemetry policy.
- ACK processing now feeds ack-eliciting largest-acked samples into the
  RTT estimator using cached peer ACK-delay transport parameters.
- `Connection.nextTimerDeadline(now_us)` exposes ACK-delay,
  loss-detection, PTO, idle, draining, and abandoned-path retirement
  deadlines. `tick(now_us)` now drives time-threshold loss, PTO
  requeue/probe PINGs, idle close, draining cleanup, and expired
  abandoned-path recovery cleanup.
- PTO is handled per PN space/path: Initial and Handshake remain
  connection-level, while every Application path tracks backoff
  separately and requeues STREAM, CRYPTO, and retransmittable control
  data through the same loss path.
- NewReno congestion control is wired into Application data sending:
  ACKed in-flight bytes grow the congestion window, packet loss reduces
  it, persistent congestion resets it to the minimum window, and
  application data is gated while PTO probes can still escape.
- PTO probe selection now prefers retransmittable STREAM, CRYPTO, and
  control data. Probe PINGs are only armed when a PTO has no useful
  retransmittable data to requeue.
- `PathSet` is now real infrastructure. Path id 0 is the initial path,
  non-zero paths can be opened publicly, and each Application path owns
  PN, ACK, sent-packet, RTT, congestion, validation, PTO, PMTU, and
  anti-amplification state while Initial/Handshake PN spaces remain
  connection-level.
- The public multipath surface now includes `enableMultipath`,
  `openPath`, `setActivePath`, `abandonPath`, `setPathStatus`,
  `setPathBackup`, `markPathValidated`, `setScheduler`, `activePathId`,
  `pathStats`, `pendingPathCidsBlocked`,
  `replenishPathConnectionIds`, `localConnectionIdIssueBudget`, and
  `nextLocalConnectionIdSequence`.
- Draft-21 multipath frame codecs and receive handlers are present for
  PATH_ACK, PATH_ABANDON, PATH_STATUS_BACKUP/AVAILABLE,
  PATH_NEW_CONNECTION_ID, PATH_RETIRE_CONNECTION_ID, MAX_PATH_ID,
  PATHS_BLOCKED, and PATH_CIDS_BLOCKED. PATH_ACK can be emitted from
  non-zero path ACK trackers and can update the indicated Application
  path's sent-packet, RTT, congestion, and PTO state.
- Draft-21 multipath control frames can now be queued for poll-side
  emission and are recorded in sent-packet metadata for loss requeue.
- `Connection.pollDatagram(dst, now_us)` exposes `{ len, to, path_id }`
  and can select non-zero Application paths for ACK/probe/scheduler
  traffic while `poll(dst, now_us)` remains the single-path
  compatibility API.
- A mock multipath transport now exercises two active Application paths
  concurrently with bidirectional STREAM data, DATAGRAMs on both paths,
  asymmetric per-path delay, deterministic reordering/loss, and
  mid-transfer PATH_ABANDON. The surviving primary path carries the
  retransmissions to completion and the abandoned path retires through
  the 3x-PTO cleanup path.
- A mock single-path migration transport now exercises NAT rebinding
  during bidirectional STREAM transfer with deterministic reordering
  and loss of the first rebound datagram. The endpoint validates the
  new 4-tuple, sends to the rebound address, and carries both streams
  to FIN/ACK completion.
- Multipath draft-21 is explicit in the public surface:
  `multipath_draft_version = 21` and transport parameter
  `initial_max_path_id = 0x3e`.
- Negotiated multipath now uses the draft-21 path-ID AEAD nonce for
  every 1-RTT packet, including non-zero Application paths, and includes
  the draft's published nonce vector in the unit suite.
- Application key updates now have an explicit lifecycle: read side
  keeps previous/current/next epochs, old read keys are retained until a
  3x-largest-Application-PTO discard deadline, peer-initiated updates
  trigger matching write-key updates, local updates are public via
  `requestKeyUpdate(now_us)`, ACK of any Application path clears the
  local update gate, and conservative cross-suite AEAD
  packet/authentication limits are counted across all Application paths.
  `keyUpdateStatus()` exposes the current epoch state for embedders and
  tests.
- Packet protection supports all QUIC v1 TLS cipher suites:
  `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and
  `TLS_CHACHA20_POLY1305_SHA256`. Initial packets remain pinned to
  AES-128/HKDF-SHA256 per RFC 9001, while Handshake, 0-RTT, and 1-RTT
  derive AEAD/HP material from the negotiated suite.
- Incoming short-header packets are routed by locally issued CID before
  opening packet protection, so the correct path ID is used for both PN
  reconstruction and the draft-21 nonce.
- CID handling now keeps a local issued-CID registry for
  RETIRE_CONNECTION_ID/PATH_RETIRE_CONNECTION_ID and validates
  peer-issued NEW_CONNECTION_ID/PATH_NEW_CONNECTION_ID per path:
  retire-prior-to bounds, duplicate sequence reuse, cross-path CID
  reuse, active_connection_id_limit, and local MAX_PATH_ID bounds close
  with PROTOCOL_VIOLATION. Locally issued CIDs are also kept unique
  across path IDs/sequences so short-header CID routing cannot become
  ambiguous. PATH_CIDS_BLOCKED and peer CID retirement are surfaced as
  app-visible `connection_ids_needed` events with active count, peer
  limit, issue budget, and next sequence metadata; caller-provided CIDs
  are queued without exceeding the peer's active_connection_id_limit,
  and retired local CIDs are removed from pending advertisements before
  replacements are issued.
- PATH_ABANDON now puts the path into a retiring state with a deadline
  of three times the largest current Application PTO. Recovery, ACK, and
  timer state remain alive until that deadline, then `tick()` clears
  recovery metadata and marks the path failed.
- NAT rebinding keeps the old peer address as rollback/drain metadata
  while the new address is being validated. PATH_RESPONSE frames queued
  for an old-address PATH_CHALLENGE are sent back to that challenge
  address without debiting the new path's anti-amplification budget,
  while the validation PATH_CHALLENGE for the new address remains queued
  for a later datagram.
- Incoming multipath control frames are rejected unless draft-21 was
  negotiated and are checked against the local maximum path ID;
  MAX_PATH_ID cannot reduce the peer's initial limit, and
  PATH_CIDS_BLOCKED cannot skip our next issued CID sequence.
- Initial 0-RTT transport plumbing has landed. Clients can install a
  BoringSSL session, explicitly opt a connection into early data, emit
  STREAM/DATAGRAM bytes as 0-RTT long-header packets in the Application
  PN space, and requeue STREAM/control data if TLS rejects early data.
  Servers can install a canonical QUIC early-data replay context,
  decrypt accepted 0-RTT packets, reject forbidden 0-RTT frames, and
  expose BoringSSL's early-data status/reason.
- The 0-RTT replay-context builder now excludes per-connection
  identifiers/tokens while retaining replay-relevant transport limits,
  so valid resumption does not reject solely because the new Initial
  uses a different original destination CID. It also deliberately
  excludes `preferred_address`, which is a server migration hint rather
  than an early-data send constraint. Incoming streams and DATAGRAMs
  expose `arrived_in_early_data` metadata.
- Transport-parameter parsing now rejects duplicate parameters, even
  for unknown extension IDs, and exposes the full RFC 9000
  `preferred_address` structure as a typed parameter.

## Still not production-grade

1. **Draft multipath is much closer but not complete.** Path
   registration, lifecycle, stats, scheduler selection, path-aware
   polling, per-path Application recovery ownership, draft-21 nonce
   construction, CID-based incoming path mapping, concurrent mock
   transfer under loss/reordering, unused path-ID CID pre-provisioning,
   common path-ID open gating, replacement-CID replenishment events,
   local CID uniqueness, and core CID/limit validation exist. quic-go
   v0.59.0 public-API interop now validates draft-21 path management,
   probing, active-path switching, PATH_ABANDON, and live transfer
   across both UDP sockets during an open upload. Remaining confidence
   work is true external simultaneous multi-active-path transfer against
   a peer with scheduler/distribution controls.
2. **Multipath frame emission is locally complete but needs peer soak.**
   Draft-21 multipath control frames can be queued, coalesced into
   Application packets, ACKed, and requeued on loss, and PATH_ACK is
   generated for non-zero path ACK trackers including retiring paths.
   quic-go interop now covers live PATH_CHALLENGE/PATH_RESPONSE and
   PATH_ABANDON flows with traffic continuity across a path switch.
   Remaining confidence work: pacing behavior under live traffic and a
   true external draft-21 concurrent-transfer peer.
3. **Recovery is path-aware but not fully hardened.** Packet-threshold,
   time-threshold, PTO, ACK-delay, idle, draining, NewReno loss/ACK
   feedback, persistent congestion, and basic PTO probe selection are
   path-owned for Application data. Abandoned multipath paths retain
   peer CIDs and ACK/recovery state until the 3x-largest-PTO drain
   window expires. NAT rebinding resets RTT/congestion after validation
   and keeps old-address PATH_RESPONSE traffic off the new path's
   anti-amplification accounting. A matching PATH_RESPONSE now also
   clears any queued-but-unsent validation PATH_CHALLENGE for that path.
   Local mock transport now covers bidirectional transfer across a
   lossy/reordered NAT rebinding, and unit coverage exercises failed
   rollback, old-address traffic during pending rebinding, old-address
   PATH_RESPONSE routing, and validation cleanup.
   Remaining recovery work: external lossy/reordered interop gates and
   live migration soak. Pacing, ECN, and advanced congestion controllers
   remain out of scope for this push.
4. **Key updates need external soak, not core lifecycle work.** The
   current implementation covers previous/current/next read keys,
   3x-PTO old-key discard, local initiation, ACK gating, and cross-suite
   AEAD packet/authentication limits across all Application paths. Unit
   coverage now confirms proactive packet-limit updates count packets
   emitted on non-zero multipath paths and that confidentiality-limit
   closes are surfaced through the qlog callback. Remaining confidence
   work is external delayed-old-phase interop, long-running packet-limit
   soak with realistic thresholds, and external qlog/keylog trace
   review. nullq now exposes an opt-in qlog-style callback for
   Application key install/update/ACK/discard/AEAD-limit events, and
   re-exports the BoringSSL keylog callback type for TLS-context key
   logging.
5. **0-RTT is implemented but still needs rejection hardening.** The
   landed code covers packet protection, explicit send opt-in,
   server receive validation, early-data context construction, status
   reporting, accepted and rejected go-quic-peer resumption interop,
   application-visible early-data marking on incoming streams/datagrams,
   rejected STREAM/control requeue, and deterministic coverage that
   DATAGRAM remains unreliable across rejection. Ticket export/import is
   now documented through the public `Session.toBytes` /
   `Session.fromBytes` path, replay-context tests cover every
   replay-relevant transport parameter that nullq records, and normal
   0-RTT DATAGRAM ACK/loss paths preserve app-visible early-data
   metadata. Packet-threshold loss also requeues sent 0-RTT STREAM
   bytes. Remaining work: end-to-end peer rejection probes for
   individual transport-parameter changes and broader lossy external
   0-RTT scenarios.
6. **Protocol hardening remains.** Retry and Version Negotiation now
   have deterministic core coverage plus live quic-go interop through
   nullq-peer, and Retry address-validation helpers are reusable nullq
   API. Bounded allocation policy and deterministic parser/property
   smoke coverage have landed. Transport-parameter parsing now includes
   duplicate-parameter rejection plus typed `preferred_address`
   encode/decode/validation. Local endpoint probes now cover
   malformed, replayed-address, replayed-CID, expired, and wrong-version
   Retry tokens; send-side blocked-frame loss requeue now skips stale
   DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED frames after the
   peer raises limits; receive-side MAX_DATA / MAX_STREAM_DATA updates
   are half-window paced; VN negative path vectors cover
   supported-version, wrong CID echo, malformed version-list, and
   server-ignore cases; and shutdown coverage exercises long close
   reason truncation plus stateless-reset false-positive filtering.
   Remaining hardening work: broader shutdown-path interop with external
   peers.
7. **The official interop runner gate is scaffolded, not complete.**
   nullq now has QNS server and client endpoint roles plus a Zig-native
   wrapper for nullq matrices against quic-go, ngtcp2, and quiche. The
   client role covers full-handshake HTTP/0.9 downloads, multiplexed
   requests, QNS resumption, and QNS 0-RTT by capturing a session
   ticket, reconnecting, and sending second-flight requests as early
   data. It still needs actual runner execution in a
   Docker/Wireshark-equipped environment and fixes from the first real
   external traces before it can be called a release gate. The runner
   wrapper invokes upstream Python through `uv run`; repo-local tools
   are declared in `mise.toml`.

Note: the passing mock multipath test validates simultaneous two-path
transfer inside nullq. The passing `go-quic-peer multipath` gate now
validates quic-go public draft-21 path management plus an upload window
with outgoing traffic observed on both client UDP sockets, but quic-go
v0.59.0 still does not expose a public scheduler for true simultaneous
multi-active-path stream/DATAGRAM distribution.

## Useful commands

```sh
cd ~/prj/ai-workspace/nullq
mise run test
mise run qns-endpoint
mise exec -- zig build external-interop -- runner --dry-run

cd ~/prj/ai-workspace/nullq-peer
zig build
./zig-out/bin/nullq-peer server -listen 127.0.0.1:4242

cd ~/prj/ai-workspace/go-quic-peer
go run ./cmd/quicpeer client -addr 127.0.0.1:4242 -insecure -0rtt=false -json -timeout 20s
go run ./cmd/quicpeer client -addr 127.0.0.1:4242 -insecure -0rtt=true -0rtt-expect accepted -json -timeout 30s
go run ./cmd/quicpeer client -addr 127.0.0.1:4242 -insecure -0rtt=true -0rtt-expect rejected -json -timeout 30s
go run ./cmd/quicpeer multipath -addr 127.0.0.1:4242 -insecure -json -timeout 30s -cid-len 8 -upload-size 524288 -concurrent 8
```
