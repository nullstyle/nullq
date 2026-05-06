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
Seven harnesses across four files:

| # | File | Test name | Target |
|---|---|---|---|
| 1 | `src/wire/varint.zig:262` | `fuzz: varint decode/encode round-trip` | `varint.decode` / `varint.encodeFixed` round-trip on arbitrary bytes |
| 2 | `src/wire/header.zig:836` | `fuzz: header parse never panics and reports consistent offsets` | `header.parse` on arbitrary bytes with fuzzer-chosen short DCID length; checks `pn_offset <= input.len`, CID-length bounds |
| 3 | `src/frame/decode.zig:632` | `fuzz: frame decode single-frame property` | `frame.decode` on arbitrary bytes; checks `1 <= bytes_consumed <= input.len` |
| 4 | `src/frame/decode.zig:655` | `fuzz: frame decode loop until exhausted` | `frame.decode` driven in a drain loop; cumulative `bytes_consumed` stays inside input, capped at 16k iterations |
| 5 | `src/server.zig:2051` | `fuzz: peekLongHeaderIds never panics` | `peekLongHeaderIds` on arbitrary bytes; checks returned CID slices alias into input |
| 6 | `src/server.zig:2070` | `fuzz: isInitialLongHeader never panics` | `isInitialLongHeader` on arbitrary bytes; bool result, no panic |
| 7 | `src/server.zig:2081` | `fuzz: peekDcidForServer never panics across all CID lengths` | `peekDcidForServer` with fuzzer-chosen `local_cid_len`; returned slice aliases into input |

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
| 4 | Coalesced datagram parser | MISSING | Only one unit test exercises the coalesced path: `src/wire/long_packet.zig:914` `Initial coalesced with Handshake: bytes_consumed lets us advance`. No fuzz harness drives `Connection.handle` over a mutated coalesced datagram. |
| 5 | Transport parameter parser | PARTIAL | `tests/fuzz_smoke.zig:217` round-trips generated params; `tests/fuzz_smoke.zig:276` deterministically fuzzes malformed buffers. No `std.testing.fuzz` harness — only fixed-seed sweeps. |
| 6 | Retry token parser | PARTIAL | `src/conn/retry_token.zig` has 3 negative tests at lines 178, 197, 230 (wrong address, wrong CIDs, wrong version, expired, future, malformed prefix). No fuzzer drives `validate` with arbitrary bytes. |
| 7 | ACK frame parser | PARTIAL | The ACK frame is decoded inside `frame.decode` (covered) — its parser is exercised. The ACK *range iterator* has deterministic property coverage in `tests/fuzz_smoke.zig:390` plus invariant tests in `src/frame/ack_range.zig:127–207`. No coverage-guided harness on the iterator. |
| 8 | CRYPTO frame reassembly | PARTIAL | Reassembly logic has unit tests at `src/conn/state.zig:8667, 8711, 8735` (out-of-order, duplicate, shuffled fragments) and a bound check at `src/conn/state.zig:10139`. No fuzzer drives offsets / overlaps / duplicates against `handleCrypto`. |
| 9 | STREAM frame parser | PARTIAL | The frame-level decoder is in `src/frame/decode.zig` (covered). `RecvStream` reassembly has a deterministic shuffle test in `tests/fuzz_smoke.zig:435` and offset/overlap unit tests in `src/conn/recv_stream.zig`. No dedicated harness on `Connection.handleStream` |
| 10 | HTTP/3 frame parser | MISSING (no impl) | nullq has no HTTP/3 layer. |
| 11 | HTTP/3 SETTINGS parser | MISSING (no impl) | nullq has no HTTP/3 layer. |
| 12 | HTTP/3 request field validator | MISSING (no impl) | nullq has no HTTP/3 layer. |
| 13 | QPACK integer / string / Huffman decoder | MISSING (no impl) | nullq has no QPACK layer. |
| 14 | QPACK encoder stream parser | MISSING (no impl) | nullq has no QPACK layer. |
| 15 | QPACK decoder stream parser | MISSING (no impl) | nullq has no QPACK layer. |
| 16 | QPACK field section decoder | MISSING (no impl) | nullq has no QPACK layer. |
| 17 | Flow-control state machine | PARTIAL | `src/conn/flow_control.zig:185–229` covers monotonic/refuse cases. `src/conn/state.zig:10309–10523` covers send-side, receive-side, blocked-frame queueing, MAX-update pacing. No fuzzer drives sequences of `MAX_DATA` / `MAX_STREAM_DATA` / `STREAM` against the state machine. |
| 18 | Stream lifecycle state machine | PARTIAL | `src/conn/recv_stream.zig:379–561` and `src/conn/send_stream.zig:411–697` cover happy paths, FIN, RESET, sparse offsets, overflow, duplicates, drain-and-credit, and a 256 KiB stress with random ACK order. No fuzzer drives random orderings of recv/read/reset across the lifecycle enum. |
| 19 | Connection ID lifecycle | PARTIAL | `src/conn/state.zig:11487–11904` covers issuance, retirement, retire-prior-to per path, sequence-reuse rejection. No fuzzer drives random `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID` / `PATH_NEW_CONNECTION_ID` interleavings. |
| 20 | Path migration state machine | PARTIAL | `src/conn/path_validator.zig:92–147` and `src/conn/path.zig:674–750` cover anti-amp, validator transitions, CID retirement. Migration callback variants tested at `src/conn/state.zig:12410–12538`. No fuzzer drives random `PATH_CHALLENGE` / `PATH_RESPONSE` / address rebinding sequences against `Connection.handle`. |

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

### Priority 3: Coalesced-datagram fuzz harness (§11.1.4)

**Risk: high. Readiness: ready.** The coalesced path is server-side
hot — every client first-flight is Initial+Handshake or
Initial+0-RTT. `Connection.handle` walks them via
`bytes_consumed`. The only test today is the single positive case at
`src/wire/long_packet.zig:914`. A `std.testing.fuzz` harness on
`Connection.handle` (or, more practically, on a thin "open then walk
remainder" helper) would cover advancement-past-end, oversize
declared-payload-length, zero-length packets in the middle, and
packets with mismatched DCIDs. Lives next to existing fuzz harnesses
in `src/wire/long_packet.zig` or a new file under `src/conn/`.

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

### Priority 5: Transport-parameter coverage-guided fuzz harness (§11.1.5)

**Risk: medium. Readiness: ready.** Transport parameters are read on
every handshake and decoded with a bespoke parser
(`src/tls/transport_params.zig`). Today's coverage is the deterministic
sweep at `tests/fuzz_smoke.zig:276` — high signal but not
coverage-guided, so it can plateau. A `std.testing.fuzz` harness on
`Params.decode` mirrors the existing `varint` and `header` harnesses
and ought to live in `src/tls/transport_params.zig` itself. Catches
duplicate-id, length-mismatch, and preferred-address-truncation cases
that the deterministic sweep would not minimize.

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
