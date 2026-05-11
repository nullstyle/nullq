# Changelog

All notable changes to quic-zig are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

## [Unreleased]

### Changed

- Reworked the public README and usage docs around stable embedding,
  interop, benchmark, and conformance workflows.
- Removed tracked investigation/status notes that duplicated local
  scratch output or stale matrix history.

## [0.2.0]

### Added

- High-level `Server` and `Client` wrappers around the raw
  `Connection` state machine.
- `transport.runUdpServer` and `transport.runUdpClient` for simple
  `std.Io` UDP loops.
- QUIC v2 compatible Version Negotiation support.
- Retry, NEW_TOKEN, stateless reset token helpers, and key logging
  surfaces.
- 0-RTT session support with anti-replay integration hooks.
- ECN, DPLPMTUD, migration, preferred address, DATAGRAM, and qlog-style
  event surfaces.
- QUIC-LB draft 21 helpers, including plaintext, single-pass AES, and
  four-pass Feistel CID modes plus decode support.
- Alternative Server Address draft 00 codec, emit, receive event, and
  embedder example support.
- RFC-traceable conformance suites and a microbenchmark harness.
- Official QUIC interop-runner endpoint and wrapper.

### Changed

- Public module name is `quic_zig`.
- Production guidance requires `-Doptimize=ReleaseSafe` for
  internet-facing builds.
- Generated interop outputs are ignored under `interop/logs*` and
  `interop/results`.

## [0.1.0]

### Added

- QUIC v1 packet, frame, transport-parameter, stream, loss-recovery,
  and TLS glue foundations.
- BoringSSL-backed TLS 1.3, AEAD, HKDF, and header protection.
- Initial unit and end-to-end smoke tests.

## [0.0.0]

### Added

- Initial repository scaffold.
