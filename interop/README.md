# nullq external interop gate

This directory contains the first nullq endpoint for the official
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
  `QLOGDIR` receives nullq qlog-style key lifecycle JSONL traces.

The default external matrix targets server-side nullq against the
current official clients `quic-go`, `ngtcp2`, and `quiche`, using:

```sh
zig build external-interop -- runner --build-image
```

Client-side nullq can be exercised by selecting `--role client`, which
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

- `quic-go`, `ngtcp2`, and `quiche` all pass nullq-as-server
  handshake and transfer: `✓(H,DC)`.
- `quic-go` passes the feature matrix:
  `✓(H,DC,C20,S,R,Z,M)`.
- `quic-go`, `ngtcp2`, and `quiche` all pass nullq-as-client
  handshake and transfer: `✓(H,DC)`.
- `quic-go` passes nullq-as-client `H,D,S,R,Z,M`:
  `✓(H,DC,S,R,Z,M)`. `C20` remains red because the current
  `boringssl-zig` surface does not expose a C-callable TLS 1.3 client
  cipher-suite preference/override, so the client selects AES-128 on
  AES-capable hosts.
- The runner may print `At least one QUIC packet could not be
  decrypted` during trace processing even when the QNS result is green;
  keep an eye on that warning while expanding the gate.

## Requirements

- Docker with the quic-network-simulator base image reachable.
- A checkout of `quic-interop-runner` next to this repo, or
  `--runner-dir /path/to/quic-interop-runner`.
- `mise install` from the repo root to provision Zig, Python 3.12, and
  `uv`.
- Runner Python dependencies are managed by `uv run` inside the
  official runner overlay. nullq's wrapper is Zig-native, but the
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
`interop/results/nullq-server.json` or
`interop/results/nullq-client.json`, depending on the selected role.
Both are generated artifacts and are ignored by git.
