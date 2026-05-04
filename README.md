# nullq

A Zig-first IETF QUIC v1 implementation, built from RFCs 8999/9000/9001/9002,
using [`boringssl-zig`](../boringssl-zig) for TLS 1.3 and AEAD/HKDF crypto.

**Status: interop prototype, not production yet.** nullq now completes
QUIC v1 handshakes, streams, DATAGRAMs, RESET_STREAM, CID issuance,
PATH_CHALLENGE/PATH_RESPONSE, timer-driven loss/PTO recovery with
NewReno feedback, path-aware `PathSet` recovery ownership, and
draft-21 multipath nonce/CID routing checks. 0-RTT now has early
STREAM/DATAGRAM transport plumbing plus accepted and rejected
go-quic-peer resumption smokes, while deeper mismatch/loss hardening
still needs work.
go-quic-peer single-path, 0-RTT, and path-switch smoke tests are
maintained as interop gates. See [INTEROP_STATUS.md](INTEROP_STATUS.md)
for the current verification log and remaining production gaps.

```sh
mise install
just test
```

## What this is

- The QUIC **transport**: streams, datagrams, packet protection, loss
  recovery, congestion control. HTTP/3 is **not** part of nullq.
- I/O-decoupled state machine. The library does not own a socket or
  an event loop; the embedder drives `handleIncoming` /
  `pollOutgoing` against a `Clock`.
- Pure Zig for everything that isn't crypto. BoringSSL is called only
  for AEAD seal/open, HKDF, AES block, and TLS 1.3 handshake.

## Scope

In scope for v0.1:
- IETF QUIC v1 transport from RFCs 8999 / 9000 / 9001 / 9002.
- 0-RTT (RFC 9001 §4.5/4.6) — Phase 8, initial implementation landed.
- Connection migration (RFC 9000 §9) — Phase 9.
- Multipath QUIC (draft-ietf-quic-multipath) — Phase 10. Tracks the
  draft-ietf-quic-multipath-21 surface (`initial_max_path_id`,
  `multipath_draft_version = 21`); expect API churn until the spec is
  published as an RFC.

Out of scope: HTTP/3, QPACK, Windows, FIPS, ECN, DPLPMTUD, BBR,
performance optimizations. See the non-goals and Phase 11 sections
of `INITIAL_PROMPT.md`.
