# quic-zig external interop gate

This directory contains the first quic-zig endpoint for the official
QUIC interop runner.

## Current gate

- Builds `qns-endpoint`, a QNS HTTP/0.9 endpoint that speaks ALPN
  `hq-interop` in both server and client roles.
- Serves runner-mounted files from `/www` over bidirectional streams.
- In client mode, reads QNS `REQUESTS`, downloads each URL over a
  separate bidirectional stream, and writes the results under
  `/downloads`.
- Loads runner-mounted TLS material from `/certs/cert.pem` and
  `/certs/priv.key`.
- Supports server-side Retry when `TESTCASE=retry`.
- Enables session tickets / 0-RTT at the TLS layer so external clients
  can exercise `resumption` and `zerortt`.
- The client role handles normal full-handshake downloads plus QNS
  `resumption` and `zerortt`: it downloads the first request, captures
  a session ticket, reconnects for the remaining requests, and sends
  those second-flight requests as early data for `zerortt`.
- Client downloads are scheduled as peer stream credit becomes
  available, so high-fanout `multiplexing` tests do not fail just
  because the server starts with a smaller bidirectional stream limit.
- Honors the runner's `SSLKEYLOGFILE` and `QLOGDIR` environment
  variables. `SSLKEYLOGFILE` receives Wireshark-compatible TLS secrets;
  `QLOGDIR` receives quic-zig qlog-style key lifecycle JSONL traces.

The default external matrix targets server-side quic-zig against the
current official clients `quic-go`, `ngtcp2`, and `quiche`, using:

```sh
zig build external-interop -- runner --build-image
```

Client-side quic-zig can be exercised by selecting `--role client`, which
injects the local image as a runner client and pairs it with external
servers:

```sh
zig build external-interop -- runner --role client --servers quic-go,ngtcp2,quiche --tests H,D
```

By default that expands to:

```text
handshake,transfer,chacha20,retry,resumption,zerortt,multiplexing
```

The official runner's current abbreviations map as follows:

```text
H=handshake, D=transfer, C=chacha20, S=retry, R=resumption, Z=zerortt, M=multiplexing
```

## Latest local results

**Matrix run, 2026-05-09 (72 cells over 4 runner invocations,
~32 min wall):**

- 58 of 72 cells passed.
- Server role (quic-zig × {quic-go, ngtcp2, quiche} clients):
  - quic-go × {H, DC, C20, R, Z, M, U, LR, B, BA}.
  - ngtcp2 × {H, DC, C20, R, Z, M, U, LR, B, BA}.
  - quiche × {H, DC, R, Z, LR, B}.
- Client role (quic-zig × {quic-go, ngtcp2, quiche} servers):
  - quic-go × {H, DC, C20, S, R, Z, M, U, LR, B}.
  - ngtcp2 × {H, DC, C20, S, R, Z, M, CM, U, LR, B, BA}.
  - quiche × {H, DC, C20, S, R, Z, M, U, LR, B}.

**Verification (2026-05-09 post-fix matrix re-run):**

| Cell | Pre-fix | Predicted | Post-fix | Note |
|---|---|---|---|---|
| server × {3} × retry | FAIL | PASS | **PASS** | Fix #1 verified |
| client × {quic-go, quiche} × rebind-addr | FAIL | PASS | **FAIL** | Fix #2 narrative wrong |
| server × quiche × multiplexing | FAIL | PASS | FAIL | Fix #3 reverted |
| server × {quic-go, ngtcp2} × multiplexing | PASS | PASS | (PASS again after revert) | Fix #3 was a regression |

**Re-scoped fix narratives:**

- **Fix #1 `retryAddressContext`** — verified clean. 3 cells flipped
  FAIL→PASS as predicted.
- **Fix #2 `apply_simulator_warmup` gating** — the warmup race is
  gone (handshake completes cleanly), but the client × rebind-addr
  cells still fail because of a SEPARATE deeper bug: the quic-zig
  client never delivers a NEW_CONNECTION_ID frame for the migrated
  path, and the runner's quic-go server logs `skipping validation
  of new path … since no connection ID is available`. Quiche
  validates the new path successfully but the client keeps sending
  from the OLD socket. Both are client-side active-migration /
  CID-issuance bugs, not warmup-related. The warmup fix itself
  stays — it's still the right behavior — but the CHANGELOG /
  README claim that it would unlock 2 cells was wrong.
- **Fix #3 `endpoint_bidi_stream_limit` 1000→2500** — REVERTED.
  The runner's `multiplexing` testcase explicitly validates
  `initial_max_streams_bidi <= 1000`
  (`testcases_quic.py:286-288`); raising the cap broke 2
  previously-passing cells (server × {quic-go, ngtcp2} ×
  multiplexing). The proper fix is in `maybeQueueBatchedMaxStreams`
  (`src/conn/state.zig`) — lower the credit-return watermark from
  `remaining > batch / 2` to a lower threshold so dynamic
  `MAX_STREAMS` issuance reaches the peer before quiche's pipelined
  burst exhausts the initial allotment.

**Known gaps still open:**

- **Server `M` (multiplexing) × quiche** — original quiche-only
  failure mode reverts to its 2026-05-09 morning state. The core
  watermark fix above is the path forward.
- **Client `BA` (rebind-addr) × {quic-go, quiche}** — both arms now
  addressed; matrix re-run pending. First arm (2026-05-09
  `followup-client-migration-cid`): the qns client driver issues a
  fresh client SCID at sequence 1 via `queueClientConnectionIds`,
  unblocking server-side path validation that previously logged
  `skipping validation of new path … since no connection ID is
  available`. Second arm (2026-05-09 `followup-rebind-detection`):
  the qns client driver now forwards the inbound source address to
  `Connection.handleWithEcn` (was `null`) and switched from
  `conn.poll` to `conn.pollDatagram`, so an embedder-routed
  per-datagram destination follows the migrated `peer_addr` instead
  of the original `connect()` target. The transport core already
  detects peer-side rebind passively in
  `recordAuthenticatedDatagramAddress` (no role gate), so the fix
  was a pure embedder-side change once both inputs were wired.
  A new state-tests unit test (`client peer-address rebind:
  pollDatagram exposes the new server tuple after migration`) pins
  the contract.
- **Server `CM` (connectionmigration) × all three peers** —
  `qns_endpoint.zig` does not advertise `preferred_address` in
  the server's transport-parameter blob; the codec exists in
  `src/tls/transport_params.zig`, the wiring is unfinished.
  **Deferred** to a follow-up session (needs an alt-port
  listening socket and runner-IP introspection).
- **Server `BA` (rebind-addr) × quiche** — fix landed on
  `followup-path-challenge-order` (2026-05-09): the server's
  packet builder now emits `PATH_CHALLENGE` as the FIRST frame of
  the first datagram on a peer-migrated path (and pads the
  datagram to 1200 bytes per RFC 9000 §8.2.1 ¶3, subject to
  anti-amp). The historical drain order placed `PATH_CHALLENGE`
  behind ACK / MAX_DATA / NEW_CONNECTION_ID etc., which under
  quiche's tight rebind cadence occasionally pushed the probing
  frame out of the first packet entirely. Two new unit tests in
  `src/conn/_state_tests.zig` pin the new ordering and the
  non-migration packet-size invariant. **Re-running the interop
  matrix is needed to confirm the cell actually flips PASS.**

**Build infra note**: the qns Dockerfile (`interop/qns/Dockerfile`)
is now pinned to `ARG ZIG_VERSION=0.17.0-dev.269+ebff43698`, matching
the 0.17-dev `mise.toml` `zig = "master"` and HEAD's 0.17-only source
forms. The download URL was switched from
`https://ziglang.org/download/<ver>/...` to
`https://ziglang.org/builds/...` because dev tarballs are not served
under a per-version subdirectory. `mise run interop-build-image` is
unblocked.

Four cells reported "unsupported" by the peer image, not the
quic-zig endpoint, and are excluded from regression tracking:
`quiche × C20 (server-role)`, `quiche × U (server-role)`,
`{quic-go, quiche} × CM (client-role)`.

When both endpoints expose valid keylogs, quic-zig's wrapper merges
them in the throwaway runner overlay before trace analysis. This
keeps 0-RTT decryption clean when the selected client keylog lacks
`CLIENT_EARLY_TRAFFIC_SECRET` but the server keylog has it.

## Requirements

- Docker with the quic-network-simulator base image reachable.
- A checkout of `quic-interop-runner` next to this repo, or
  `--runner-dir /path/to/quic-interop-runner`.
- `mise install` from the repo root to provision Zig, Python 3.12, and
  `uv`.
- Runner Python dependencies are managed by `uv run` inside the
  official runner overlay. quic-zig's wrapper is Zig-native, but the
  upstream runner itself still executes `run.py`. The wrapper defaults
  to `uv run --python 3.12` because the current pyshark stack is not yet
  clean under Python 3.14.
- Wireshark/tshark new enough for the runner's trace checks.

The wrapper creates local throwaway state under `.zig-cache/` and does
not mutate the runner checkout.

## Useful commands

```sh
mise run interop-preflight
mise run interop-build-image
mise exec -- zig build qns-endpoint -Doptimize=ReleaseSafe
mise exec -- zig build external-interop -- runner --dry-run
mise exec -- zig build external-interop -- runner --role client --servers quic-go --tests H,D
mise exec -- zig build external-interop -- runner --clients quic-go --tests H,D,C
mise exec -- zig build external-interop -- runner --clients quic-go --tests H,D --python 3.12
mise exec -- zig build external-interop -- runner --clients quic-go,ngtcp2,quiche --tests core+retry
```

Runner logs land in `interop/logs/`; matrix JSON lands in
`interop/results/quic-zig-server.json` or
`interop/results/quic-zig-client.json`, depending on the selected role.
Both are generated artifacts and are ignored by git.
