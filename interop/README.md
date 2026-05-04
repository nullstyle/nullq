# nullq external interop gate

This directory contains the first nullq endpoint for the official
QUIC interop runner.

## Current gate

- Builds `qns-endpoint`, a server-side HTTP/0.9 endpoint that speaks
  ALPN `hq-interop`.
- Serves runner-mounted files from `/www` over bidirectional streams.
- Loads runner-mounted TLS material from `/certs/cert.pem` and
  `/certs/priv.key`.
- Supports server-side Retry when `TESTCASE=retry`.
- Enables session tickets / 0-RTT at the TLS layer so external clients
  can exercise `resumption` and `zerortt`.
- Exits `127` for the official client role. The nullq QNS client is
  still a follow-up.

The default external matrix targets server-side nullq against the
current official clients `quic-go`, `ngtcp2`, and `quiche`, using:

```sh
zig build external-interop -- runner --build-image
```

By default that expands to:

```text
handshake,transfer,chacha20,retry,resumption,zerortt,multiplexing
```

The official runner's current abbreviations map as follows:

```text
H=handshake, D=transfer, C=chacha20, S=retry, R=resumption, Z=zerortt, M=multiplexing
```

## Requirements

- Docker with the quic-network-simulator base image reachable.
- A checkout of `quic-interop-runner` next to this repo, or
  `--runner-dir /path/to/quic-interop-runner`.
- Runner Python dependencies installed for the official runner. nullq's
  wrapper is Zig-native, but the upstream runner itself still executes
  `run.py`.
- Wireshark/tshark new enough for the runner's trace checks.

The wrapper creates local throwaway state under `.zig-cache/` and does
not mutate the runner checkout.

## Useful commands

```sh
zig build external-interop -- preflight
zig build external-interop -- build-image
zig build external-interop -- runner --dry-run
zig build external-interop -- runner --clients quic-go --tests H,D,C
zig build external-interop -- runner --clients quic-go,ngtcp2,quiche --tests core+retry
```

Runner logs land in `interop/logs/`; matrix JSON lands in
`interop/results/nullq-server.json`.
