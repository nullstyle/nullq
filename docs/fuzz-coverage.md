# Fuzz and negative-test coverage audit

This document audits nullq against §11 of the security hardening guide.
It enumerates every `std.testing.fuzz` site in `src/`, maps the §11.1
required fuzz targets and §11.2 regression classes onto the codebase,
and ranks the gaps that are highest-leverage to close next.

Scope notes:

- nullq is QUIC v1 transport only. There is no HTTP/3 layer and no
  QPACK layer in this tree (a one-line search confirms: the only
  `qpack`/`http`/`h3` mentions are documentation strings about ALPN).
  Rows in §11.1 / §11.2 that depend on those layers are tagged
  **MISSING (no impl)** to distinguish them from "implementation
  exists but no test".
- nullq uses Zig 0.15.x's structured fuzzer (`std.testing.Smith` +
  `std.testing.fuzz`), not raw libFuzzer. Existing harnesses double as
  unit tests so they always run under `zig build test`; `zig build
  fuzz` runs them under coverage feedback.
- "fuzz_smoke" tests in `tests/fuzz_smoke.zig` are deterministic
  randomized property tests, not coverage-guided fuzzers. They are
  treated below as regression tests, not as fuzz coverage.

## 1. Inventory of `std.testing.fuzz` sites

Verified via `rg "std.testing.fuzz" /Users/nullstyle/prj/ai-workspace/nullq/src`.
Fourteen harnesses across nine files:

| # | File | Test name | Target |
|---|---|---|---|
| 1 | `src/wire/varint.zig:262` | `fuzz: varint decode/encode round-trip` | `varint.decode` / `varint.encodeFixed` round-trip on arbitrary bytes |
| 2 | `src/wire/header.zig:836` | `fuzz: header parse never panics and reports consistent offsets` | `header.parse` on arbitrary bytes with fuzzer-chosen short DCID length; checks `pn_offset <= input.len`, CID-length bounds |
| 3 | `src/frame/decode.zig:632` | `fuzz: frame decode single-frame property` | `frame.decode` on arbitrary bytes; checks `1 <= bytes_consumed <= input.len` |
| 4 | `src/frame/decode.zig:655` | `fuzz: frame decode loop until exhausted` | `frame.decode` driven in a drain loop; cumulative `bytes_consumed` stays inside input, capped at 16k iterations |
| 5 | `src/server.zig:2051` | `fuzz: peekLongHeaderIds never panics` | `peekLongHeaderIds` on arbitrary bytes; checks returned CID slices alias into input |
| 6 | `src/server.zig:2070` | `fuzz: isInitialLongHeader never panics` | `isInitialLongHeader` on arbitrary bytes; bool result, no panic |
| 7 | `src/server.zig:2081` | `fuzz: peekDcidForServer never panics across all CID lengths` | `peekDcidForServer` with fuzzer-chosen `local_cid_len`; returned slice aliases into input |
| 8 | `src/wire/long_packet.zig:973` | `fuzz: coalesced long-header walker terminates with bounded advance` | Structural coalesce walker; bounded iteration, in-bounds advance, terminates on Retry/VN/short |
| 9 | `src/conn/flow_control.zig:264` | `fuzz: flow_control ConnectionData state-machine invariants` | `ConnectionData.recordSent` / `recordPeerSent` / `weCanSend` / `onMaxData` / `raiseLocalMax` driven with arbitrary u64 values; asserts no overflow trap, monotonic limits, `we_sent <= peer_max`, `peer_sent <= local_max`, `weCanSend` agrees with `recordSent`, `allowance` formula |
| 10 | `src/conn/send_stream.zig:815` | `fuzz: send_stream lifecycle invariants` | Mixed `write` / `peekChunk` / `recordSent` / `onPacketAcked` / `onPacketLost` / `finish` / `resetStream` in fuzzer-chosen order; asserts `base_offset <= write_offset`, `bytes.items.len == write_offset - base_offset`, pending/acked range bounds, terminal-state coherence |
| 11 | `src/conn/recv_stream.zig:617` | `fuzz: recv_stream reassembly invariants` | Arbitrary `recv` / `read` / `resetStream` with fuzzer-chosen offset/length/fin; asserts `read_offset` monotonic, sorted-disjoint range list, `bytes.items.len` matches buffered span, no out-of-order delivery past `final_size` |
| 12 | `src/conn/path_validator.zig:176` | `fuzz: path_validator state-machine invariants` | Arbitrary `beginChallenge` / `recordResponse` / `tick` ops with fuzzer-chosen tokens and timestamps; asserts state is one of {idle, pending, validated, failed}, `validated` is terminal across non-`beginChallenge` ops, `recordResponse` outside `pending` returns `NotPending` without state mutation |
| 13 | `src/conn/ack_tracker.zig:512` | `fuzz: ack_tracker range-list invariants` | Arbitrary `add` / `addPacket` / `addPacketDelayed` / `markAckSent` / `promoteDelayedAck` / `toAckFrameLimitedRanges`; asserts `range_count <= max_ranges`, sorted-disjoint intervals with ≥1-PN gaps, `largest >= smallest` per interval, `contains` agrees with linear scan, builder respects `range_count <= self.range_count - 1` |
| 14 | `src/tls/transport_params.zig:619` | `fuzz: transport_params decode never panics and respects RFC bounds` | `Params.decode` on arbitrary bytes; asserts no panic, RFC 9000 §18.2 bounds (`ack_delay_exponent <= 20`, `max_ack_delay_ms < 2^14`, `active_connection_id_limit >= 2`), CID-length caps, encode→decode round-trip preserves scalar fields |

The `tests/fuzz_smoke.zig` harness adds nine deterministic randomized
round-trip tests covering varint, frame, transport-parameter, packet
header, ACK-range iterator, and `RecvStream` reassembly. These are
broad property tests under fixed seeds — high signal for shaking out
encode/decode asymmetry, but not coverage-guided.

## 2. §11.1 required fuzz targets

Status legend:

- **COVERED** — a coverage-guided harness exists and exercises the
  parser surface.
- **PARTIAL** — touched indirectly (e.g. through a higher-level
  harness, or by deterministic property tests in `fuzz_smoke.zig`),
  but no dedicated coverage-guided harness.
- **MISSING** — no fuzz harness, but the implementation exists.
- **MISSING (no impl)** — code path doesn't exist in nullq yet.

| § | Target | Status | Citation / notes |
|---|---|---|---|
| 1 | QUIC varint decoder | COVERED | `src/wire/varint.zig:262` |
| 2 | Long-header parser | COVERED | `src/wire/header.zig:836` (handles all six variants) and `src/server.zig:2051` (peek surface) |
| 3 | Short-header parser | COVERED | `src/wire/header.zig:836` walks short headers under fuzzer-chosen DCID length; `src/server.zig:2081` is the routing-level peek |
| 4 | Coalesced datagram parser | COVERED | `src/wire/long_packet.zig:973` `fuzz: coalesced long-header walker terminates with bounded advance` — structural walker mirrors the receive-path coalesce loop (parse header, advance by `pn_offset + payload_length`); asserts bounded iteration, in-bounds advance, and termination on Retry/VN/short. Plus the original positive `bytes_consumed` test at `src/wire/long_packet.zig:918`. |
| 5 | Transport parameter parser | COVERED | `src/tls/transport_params.zig:619` `fuzz: transport_params decode never panics and respects RFC bounds` — drives `Params.decode` with arbitrary bytes; asserts RFC 9000 §18.2 bounds and encode→decode round-trip stability. Plus the deterministic `tests/fuzz_smoke.zig:217/276` round-trip and malformed-buffer sweeps. |
| 6 | Retry token parser | PARTIAL | `src/conn/retry_token.zig` has 3 negative tests at lines 178, 197, 230 (wrong address, wrong CIDs, wrong version, expired, future, malformed prefix). No fuzzer drives `validate` with arbitrary bytes. |
| 7 | ACK frame parser | COVERED | The ACK frame is decoded inside `frame.decode` (covered). The ACK *range tracker* now has a coverage-guided harness at `src/conn/ack_tracker.zig:512` `fuzz: ack_tracker range-list invariants` — drives `add` / `addPacket` / `addPacketDelayed` / `markAckSent` / `promoteDelayedAck` / `toAckFrameLimitedRanges` with arbitrary u64 PNs; asserts sorted-disjoint range list, `range_count <= max_ranges`, `largest >= smallest` per interval, no overlap. Iterator correctness still backed by `tests/fuzz_smoke.zig:390` and `src/frame/ack_range.zig:127–207`. |
| 8 | CRYPTO frame reassembly | PARTIAL | Reassembly logic has unit tests at `src/conn/state.zig:8667, 8711, 8735` (out-of-order, duplicate, shuffled fragments) and a bound check at `src/conn/state.zig:10139`. No fuzzer drives offsets / overlaps / duplicates against `handleCrypto`. |
| 9 | STREAM frame parser | PARTIAL | The frame-level decoder is in `src/frame/decode.zig` (covered). `RecvStream` reassembly has a deterministic shuffle test in `tests/fuzz_smoke.zig:435` and offset/overlap unit tests in `src/conn/recv_stream.zig`. No dedicated harness on `Connection.handleStream` |
| 10 | HTTP/3 frame parser | MISSING (no impl) | nullq has no HTTP/3 layer. |
| 11 | HTTP/3 SETTINGS parser | MISSING (no impl) | nullq has no HTTP/3 layer. |
| 12 | HTTP/3 request field validator | MISSING (no impl) | nullq has no HTTP/3 layer. |
| 13 | QPACK integer / string / Huffman decoder | MISSING (no impl) | nullq has no QPACK layer. |
| 14 | QPACK encoder stream parser | MISSING (no impl) | nullq has no QPACK layer. |
| 15 | QPACK decoder stream parser | MISSING (no impl) | nullq has no QPACK layer. |
| 16 | QPACK field section decoder | MISSING (no impl) | nullq has no QPACK layer. |
| 17 | Flow-control state machine | COVERED | `src/conn/flow_control.zig:264` `fuzz: flow_control ConnectionData state-machine invariants` — drives `recordSent` / `recordPeerSent` / `weCanSend` / `onMaxData` / `raiseLocalMax` with arbitrary u64s; asserts no overflow trap, monotonic limits, post-state invariants. Plus the deterministic `src/conn/flow_control.zig:198–246` happy-path tests and the connection-level integration coverage at `src/conn/state.zig:10309–10523`. |
| 18 | Stream lifecycle state machine | COVERED | `src/conn/send_stream.zig:815` `fuzz: send_stream lifecycle invariants` and `src/conn/recv_stream.zig:617` `fuzz: recv_stream reassembly invariants` drive randomized op sequences across the full per-stream state machine and assert structural invariants (offset monotonicity, range-list bounds, terminal-state coherence). Deterministic happy-path coverage retained at `src/conn/recv_stream.zig:379–599` and `src/conn/send_stream.zig:441–797`. |
| 19 | Connection ID lifecycle | PARTIAL | `src/conn/state.zig:11487–11904` covers issuance, retirement, retire-prior-to per path, sequence-reuse rejection. No fuzzer drives random `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID` / `PATH_NEW_CONNECTION_ID` interleavings. |
| 20 | Path migration state machine | PARTIAL | `src/conn/path_validator.zig:176` `fuzz: path_validator state-machine invariants` covers the validator state machine (idle/pending/validated/failed transitions, `validated` terminal, `recordResponse` on non-pending). Deterministic coverage at `src/conn/path_validator.zig:92–158` and `src/conn/path.zig:674–750`. Migration callback variants tested at `src/conn/state.zig:12410–12538`. Still missing: a fuzzer that drives random `PATH_CHALLENGE` / `PATH_RESPONSE` / address-rebinding sequences against `Connection.handle` end-to-end. |

## 3. §11.2 regression classes

Status legend matches §2.

| § | Class | Status | Citation / notes |
|---|---|---|---|
| 1 | QPACK header-block expansion DoS | MISSING (no impl) | No QPACK in nullq. |
| 2 | ACK for unsent packet numbers | COVERED | `src/conn/state.zig:9125 ACK with largest_acked >= next_pn is a PROTOCOL_VIOLATION` and `:9179 == next_pn`. Implementation gate at `src/conn/state.zig:7088, 7172`. |
| 3 | Excessive / overlapping ACK ranges | PARTIAL | Output side has `src/conn/state.zig:11026 pollLevel caps ACK ranges to packet budget` and `:11059 application ACK ranges use bounded emission budget`. Input side: `frame.decode` accepts arbitrary `range_count`; no test pumps a 10⁶-range ACK frame through `handleAck` to confirm bounded CPU/memory. |
| 4 | Duplicate SETTINGS | MISSING (no impl) | No HTTP/3 SETTINGS in nullq. (QUIC transport-parameter duplication *is* covered: `src/tls/transport_params.zig:521 decode rejects duplicate transport parameters`.) |
| 5 | SETTINGS not first on control stream | MISSING (no impl) | No HTTP/3 SETTINGS in nullq. |
| 6 | HTTP/2-only settings sent in HTTP/3 | MISSING (no impl) | No HTTP/3 SETTINGS in nullq. |
| 7 | Frame type sent on invalid stream type | MISSING (no impl) | The HTTP/3 framing requirement does not apply; QUIC-level "forbidden frame in 0-RTT" is covered: `src/conn/state.zig:10959 server rejects forbidden frames in 0-RTT`. |
| 8 | HEADERS after trailers | MISSING (no impl) | No HTTP/3 in nullq. |
| 9 | DATA before HEADERS | MISSING (no impl) | No HTTP/3 in nullq. |
| 10 | Duplicate pseudo-headers | MISSING (no impl) | No HTTP/3 in nullq. |
| 11 | Uppercase field names | MISSING (no impl) | No HTTP/3 in nullq. |
| 12 | Forbidden `Connection` header | MISSING (no impl) | No HTTP/3 in nullq. |
| 13 | Invalid `Content-Length` | MISSING (no impl) | No HTTP/3 in nullq. |
| 14 | Excessive unknown frames | PARTIAL | At the QUIC-frame layer, `src/frame/decode.zig:600 decode rejects unknown frame type` covers single-byte rejection; the drain-loop fuzz at `:655` caps iterations at 16k. No regression test drives a packet payload that's all-unknown frames through `handleAtLevel` to confirm the connection closes with `FRAME_ENCODING_ERROR` rather than CPU-spinning. |
| 15 | Excessive unknown settings | MISSING (no impl) | HTTP/3 layer absent; transport-parameter unknowns are silently skipped as required (`src/tls/transport_params.zig:563 decode skips unknown ids`). |
| 16 | Excessive blocked QPACK streams | MISSING (no impl) | No QPACK in nullq. |
| 17 | Dynamic table refs beyond known insert count | MISSING (no impl) | No QPACK in nullq. |
| 18 | Retry token random garbage | COVERED | `tests/e2e/server_smoke.zig:254 Server.feed with retry_token_key issues a Retry then drops a malformed echo` plus negative cases at `src/conn/retry_token.zig:230` (malformed prefix, single-byte flip, wrong tag prefix). |
| 19 | Version Negotiation flood | PARTIAL | `tests/e2e/server_smoke.zig:147 Server.feed with unsupported version queues a Version Negotiation packet` and `:223 without 'from' drops`. The server has a per-source rate limiter that gates Initials (`src/server.zig` source-rate logic); a regression test that confirms VN responses are also rate-limited or that the stateless-response queue has a high-water mark already exists indirectly via `Server metricsSnapshot stateless_queue_high_water is sticky across drains` (`tests/e2e/server_smoke.zig:1137`). No test pumps thousands of VN-eligible Initials and asserts the queue stays bounded. |
| 20 | PATH_CHALLENGE flood | MISSING | nullq queues a `PATH_RESPONSE` for every received `PATH_CHALLENGE` (`src/conn/state.zig:6342`). There is no per-path rate limit and no test confirming a `PATH_CHALLENGE` storm doesn't unbound the pending-frame queue or burn output budget. |
| 21 | Initial datagram below minimum size | MISSING | The constant `min_quic_udp_payload_size = 1200` is defined at `src/conn/state.zig:189` but the Server feed path (`src/server.zig:944`) does not enforce it before opening a slot. RFC 9000 §14 requires the *server* to drop client Initial datagrams smaller than 1200 bytes. Worth confirming on inspection — likely a real bug, not just a test gap. |
| 22 | Migration before handshake confirmation | MISSING | The migration callback hook (`src/conn/state.zig:12410–12538`) lets embedders deny migrations, but there is no test asserting that nullq itself ignores `PATH_CHALLENGE` / source-address changes from packets at Initial / Handshake levels — i.e. before `handshake_done` (`pending_handshake_done` flag at `:1032`). RFC 9000 §9 prohibits migration before handshake confirmation. |

## 4. Top 5 priorities

Ranked by exploit risk × current implementation readiness — i.e. how
much attack surface exists today vs. how much code change a test
would need.

### Priority 1: Initial-datagram-below-1200 enforcement (regression class §11.2.21)

**Risk: high. Readiness: code change required first.** RFC 9000 §14
mandates servers drop short Initial datagrams. nullq has the constant
defined (`src/conn/state.zig:189 min_quic_udp_payload_size`) but the
server-feed gate at `src/server.zig:944` does not enforce it. An
attacker can spray ≤300-byte Initials to abuse the 3× anti-amp
allowance asymmetrically. The fix is one branch in `Server.feed`; the
regression test goes alongside `Server source rate limiter trips after
the configured cap` in `tests/e2e/server_smoke.zig`.

> Note for the implementer: this is a real implementation bug, not
> just a missing test. File the implementation work first, then add
> the regression alongside the fix.

### Priority 2: ACK-frame storm regression (§11.2.3)

**Risk: high. Readiness: ready.** `frame.decode` already accepts ACK
frames with arbitrary `range_count` and arbitrary `ranges_bytes`
length, and `handleAck` walks them via the iterator. There is no test
pumping an ACK with 10⁵+ ranges through `Connection.handle` to confirm
bounded CPU and memory. The harness goes in `src/conn/state.zig`
alongside `ACK with largest_acked >= next_pn is a PROTOCOL_VIOLATION`,
and the assertion is "either the connection closes with
`FRAME_ENCODING_ERROR` or processing returns within a fixed bound".

### Priority 3: Coalesced-datagram fuzz harness (§11.1.4) — DONE

**Landed.** `src/wire/long_packet.zig:973` `fuzz: coalesced
long-header walker terminates with bounded advance`. Structural
walker mirrors the receive-path coalesce loop: parse header, advance
by `pn_offset + payload_length`, repeat until input exhausted or a
Retry/VN/short-header packet (which can't be coalesce-followed) is
parsed. Asserts bounded iteration count (≤256), monotonic advance
(≥1 byte), and in-bounds cumulative offset. Catches malformed
length-field encodings, header parses with inconsistent offsets, and
infinite-loop inputs without needing decryption keys.

### Priority 4: PATH_CHALLENGE flood / migration-before-handshake (§11.2.20 + §11.2.22)

**Risk: medium-high. Readiness: half ready.** nullq queues a
`PATH_RESPONSE` for every received `PATH_CHALLENGE`
(`src/conn/state.zig:6342`) with no per-path rate limit, and accepts
challenges at any encryption level. Two new regression tests in
`src/conn/state.zig` near the existing migration callback tests:

1. Pump 10⁴ `PATH_CHALLENGE` frames in one packet and assert the
   pending-frame queue stays bounded (or only one `PATH_RESPONSE` is
   queued per validator window).
2. Send a `PATH_CHALLENGE` from a new 4-tuple at Handshake encryption
   level, assert it does not start migration.

### Priority 5: Transport-parameter coverage-guided fuzz harness (§11.1.5) — DONE

**Landed.** `src/tls/transport_params.zig:619` `fuzz: transport_params
decode never panics and respects RFC bounds`. Drives `Params.decode`
with arbitrary bytes, asserts the RFC 9000 §18.2 bounds the decoder
enforces (`ack_delay_exponent <= 20`, `max_ack_delay_ms < 2^14`,
`active_connection_id_limit >= 2`), CID-length caps, and an encode→
decode round-trip that catches asymmetric bound errors. Complements
the deterministic sweep at `tests/fuzz_smoke.zig:276`.

## Appendix: out-of-scope rows

The following §11 rows depend on layers that nullq has not implemented
yet and are tracked here only so the audit is exhaustive:

- HTTP/3 frame parser, SETTINGS parser, request field validator
  (§11.1.10–12, §11.2.4–13).
- QPACK integer/string/Huffman decoder, encoder stream parser, decoder
  stream parser, field section decoder (§11.1.13–16, §11.2.1, .16,
  .17).

When the HTTP/3 / QPACK layers land they pull in their own §11
obligations; this audit should be re-run at that point.
