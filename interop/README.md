# quic-zig external interop

This directory contains quic-zig's endpoint and wrapper for the official
QUIC interop runner.

## Endpoint

`interop/qns_endpoint.zig` builds the `qns-endpoint` binary used inside
the runner container. It supports both server and client roles for the
QNS HTTP/0.9 `hq-interop` protocol.

Server role:

- Loads `/certs/cert.pem` and `/certs/priv.key`.
- Serves runner-mounted files from `/www`.
- Supports Retry, resumption, 0-RTT, Version Negotiation, preferred
  address, key logging, and qlog output when the runner enables those
  testcases.

Client role:

- Reads QNS `REQUESTS`.
- Downloads each URL over a bidirectional stream.
- Writes downloaded bodies under `/downloads`.
- Handles full handshake, resumption, and 0-RTT scheduling.

## Requirements

- Docker with the QUIC network simulator images available.
- A `quic-interop-runner` checkout next to this repository, or an
  explicit `--runner-dir`.
- Tools installed through `mise install`.
- Wireshark/tshark new enough for the runner trace checks.

The wrapper creates throwaway state under `.zig-cache/`, builds the
QNS image from this repository, and writes runner outputs under ignored
`interop/logs*` and `interop/results/` directories. No standalone
`quic-zig-qns` checkout is required.

## Build

```sh
mise install
zig build qns-endpoint -Doptimize=ReleaseSafe
zig build external-interop -- build-image --image quic-zig-qns:local
```

The image build stages the current checkout under
`.zig-cache/interop-docker-context/` and uses the URL+hash pins in
`build.zig.zon` for dependencies. If the host already has a Zig package
cache, the helper stages it into the Docker context as a best-effort
speed and reliability hint; fresh CI machines can still build without
a sibling `boringssl-zig` checkout.

## Run

Server-side quic-zig against external clients:

```sh
zig build external-interop -- runner --clients quic-go,ngtcp2,quiche --tests H,D
```

Client-side quic-zig against external servers:

```sh
zig build external-interop -- runner --role client --servers quic-go,ngtcp2,quiche --tests H,D
```

Dry-run the expanded runner command without launching Docker:

```sh
zig build external-interop -- runner --dry-run --clients quic-go --tests H,D
```

Use a non-adjacent runner checkout:

```sh
zig build external-interop -- runner --runner-dir /path/to/quic-interop-runner --clients quic-go --tests H,D
```

`just` exposes the common local and remote workflows:

```sh
just interop-build-image
just interop
just interop-client
just interop-features
just interop-remote-mainstream
```

The published QNS image workflow lives in
`.github/workflows/qns-image.yml` and publishes
`ghcr.io/nullstyle/quic-zig-qns` with the source commit in the
`commit_id` label.

## Test Selectors

Common runner abbreviations:

```text
H=handshake
D=transfer
C=chacha20
S=retry
R=resumption
Z=zerortt
M=multiplexing
B=blackhole
L1=handshakeloss
L2=transferloss
C1=handshakecorruption
C2=transfercorruption
BP=rebind-port
BA=rebind-addr
CM=connectionmigration
U=keyupdate
LR=longrtt
IPV6=ipv6
E=ecn
A=amplificationlimit
V=v2
```

The official runner's Version Negotiation testcase is named `v2`; the
wrapper keeps `V` as the short selector for that testcase.

The wrapper also accepts grouped selectors such as `core+retry` when
implemented by `tools/external_interop.zig`.

## Generated Artifacts

The runner writes logs, packet captures, TLS key logs, qlog JSONL/SQLOG
files, and result JSON into ignored paths:

```text
interop/logs/
interop/logs.*/
interop/results/
```

These artifacts are local diagnostics and can contain TLS secrets. Do
not commit them.
