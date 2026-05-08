# quic-zig microbenchmarks

Wire/frame-level microbenchmarks for the hot paths every QUIC packet
exercises. Built and run via:

```sh
zig build bench
```

The build step always pins `ReleaseFast` for the bench binary
(plus a separate ReleaseFast-built BoringSSL link), regardless of
the project's `-Doptimize` flag. Debug-mode numbers are not
useful and would be misleading.

## What's covered

Each benchmark prints one line:

```
name: <ns/op> ns/op (<ops/sec> ops/sec, <iters> iterations)
```

| Benchmark                  | Measures                                                |
| -------------------------- | ------------------------------------------------------- |
| `varint_encode`            | RFC 9000 §16 varint encode, cycling 1/2/4/8-byte inputs |
| `varint_decode`            | Same lengths, decode-only                               |
| `frame_stream_encode_100b` | STREAM frame with 100-byte payload, OFF+LEN flags       |
| `frame_stream_decode_100b` | Decode the same                                         |
| `frame_ack_encode_5ranges` | ACK with 5 subsequent gap/length ranges                 |
| `frame_ack_decode_5ranges` | Decode the same                                         |
| `short_header_encode`      | 1-RTT header, 8-byte DCID, 4-byte PN                    |
| `short_header_decode`      | Parse the same                                          |
| `cid_generate_8bytes`      | `boringssl.crypto.rand.fillBytes` for 8 random bytes    |

Each benchmark auto-tunes its iteration count to roughly 100 ms of
wall time, then reports the average.

## What's not covered (yet)

These need fixtures and AEAD setup that don't exist in the
benchmark harness:

- Initial / Handshake long-header packet build (header + AEAD seal)
- 1-RTT packet protect / unprotect (header protection + AEAD)
- Connection lifecycle (`Connection.handle` / `pollDatagram`)
- TLS handshake throughput (BoringSSL handshake)
- Stream reassembly / send-stream chunking under load

These are listed as TODO in `bench/main.zig` and should land in a
follow-up that builds shared crypto fixtures (Initial keys, packet
keys) so multiple AEAD-touching benchmarks can reuse them.

## Notes

- The bench harness is dependency-free: pure `std.c.clock_gettime`
  for timing, `std.mem.doNotOptimizeAway` to defeat dead-code
  elimination.
- Benchmarks run sequentially, single-threaded, no warmup beyond
  the auto-tuning calibration loop. Run on a quiet machine for
  stable numbers.
