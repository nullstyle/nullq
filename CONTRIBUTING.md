# Contributing to nullq

Thanks for your interest in nullq.

## Project status

nullq is **pre-1.0**. It currently completes QUIC v1 handshakes and
passes the official QUIC interop runner against `quic-go`, `quiche`,
and `ngtcp2` for the handshake and transfer matrix, but the public
API may still churn. Treat 0.x releases as potentially breaking.

See [`README.md`](README.md) for an overview, [`CHANGELOG.md`](CHANGELOG.md)
for what has shipped, and [`INTEROP_STATUS.md`](INTEROP_STATUS.md) for
the current external interop matrix.

## Building

nullq pins its toolchain via [`mise`](https://mise.jdx.dev/). The
project file at [`mise.toml`](mise.toml) installs Zig 0.16.0,
Python 3.12, `uv`, and `just`.

```sh
mise install
zig build
```

`zig build` produces `qns-endpoint` (the QUIC interop-runner binary)
and `nullq-external-interop` (the interop gate wrapper).

## Tests

```sh
zig build test
```

This runs the unit, integration, QNS endpoint, and external-interop
test suites, plus deterministic fuzz smokes for varints, frames,
transport parameters, packet headers, ACK ranges, and CRYPTO/STREAM
reassembly.

## Interop

External interop runs the official
[`quic-interop-runner`](https://github.com/quic-interop/quic-interop-runner)
against the `nullq-qns` Docker image:

```sh
# Build the local Docker image (from sibling nullq-qns checkout):
make build-local

# Run the matrix (server role by default):
zig build external-interop -- runner --tests H,DC,M
```

See [`interop/README.md`](interop/README.md) for the full set of flags
and the supported test letters.

## Commits

- One-line summary, imperative mood, ~72 chars or less.
- Optional body explains the *why*, wrapped at ~72 chars.
- Reference issues / RFCs in the body when relevant
  (e.g. `RFC 9000 §17.2.1`).
- Keep one logical change per commit.

## Pull requests

- Open against `main`.
- Make sure `zig build` and `zig build test` are green locally.
- The `test` GitHub workflow must be green before merge. The `interop`
  workflow runs weekly and is informational, not a hard merge gate.
- Touch `CHANGELOG.md` under `[Unreleased]` for any user-visible
  change.
