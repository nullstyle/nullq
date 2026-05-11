# quic-zig microbenchmarks

The benchmark harness measures low-level QUIC hot paths that are useful
to track across parser, frame, packet, and crypto-adjacent changes.

```sh
zig build bench
```

The benchmark binary is always built with `ReleaseFast` in an isolated
benchmark-only build. That exception is deliberate: benchmark numbers
from `Debug` are not useful, while production networking builds must use
`ReleaseSafe`.

## Output

Each benchmark prints:

```text
name: <ns/op> ns/op (<ops/sec> ops/sec, <iters> iterations)
```

The harness auto-tunes each benchmark to roughly 100 ms of wall time,
then reports the average.

## Covered

| Benchmark | Measures |
| --- | --- |
| `varint_encode` | RFC 9000 varint encode across 1/2/4/8-byte inputs |
| `varint_decode` | Varint decode across the same lengths |
| `frame_stream_encode_100b` | STREAM frame encode with 100-byte payload |
| `frame_stream_decode_100b` | STREAM frame decode for the same payload |
| `frame_ack_encode_5ranges` | ACK encode with five gap/length ranges |
| `frame_ack_decode_5ranges` | ACK decode for the same ranges |
| `short_header_encode` | 1-RTT short header encode |
| `short_header_decode` | 1-RTT short header parse |
| `cid_generate_8bytes` | 8-byte CSPRNG CID generation |

## Extending

Add benchmarks when a change affects a parser, frame codec, packet
builder, crypto path, stream scheduler, or connection lifecycle path that
is expected to run for most packets. Keep fixtures reusable so AEAD and
packet-key setup can be shared across related benchmarks.

Benchmarks run sequentially and single-threaded. Run on a quiet machine
for stable comparisons.
