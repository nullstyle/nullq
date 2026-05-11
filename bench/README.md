# quic-zig microbenchmarks

The benchmark harness measures low-level QUIC hot paths that are useful
to track across parser, frame, packet, and crypto-adjacent changes.

```sh
zig build bench
```

The benchmark binary is built with `ReleaseSafe` by default in an
isolated benchmark-only build. That keeps benchmark fixtures aligned with
the production safety policy while avoiding `Debug`-mode noise.

For peak-speed comparisons that deliberately disable runtime safety
checks, opt into unsafe `ReleaseFast`:

```sh
zig build bench -Dbench-unsafe-release-fast=true
```

## Output

Each benchmark prints:

```text
name: <ns/op> ns/op (<ops/sec> ops/sec, <iters> iterations)
```

The harness auto-tunes each benchmark to roughly 100 ms of wall time,
then reports the average.

For durable local or CI reports, ask the benchmark binary to write JSON:

```sh
zig build bench -- --json benchmark-report.json
```

For reports that can be rsynced from many machines into one aggregate
directory without name collisions, use directory mode:

```sh
BENCH_MACHINE_ID=workstation-a zig build bench -- --json-dir benchmark-reports
```

Directory mode writes a file named from the generation timestamp, machine
id, commit, and GitHub run id when available. If `BENCH_MACHINE_ID` is
not set, the local hostname is used.

The JSON report includes a stable schema version, toolchain and target
metadata, basic system metadata, GitHub run metadata when available, and
the per-benchmark iteration count, total time, ns/op, and ops/sec values.
The `optimize` field records the actual benchmark build mode and
`bench_unsafe_release_fast` is true only for the explicit unsafe mode.
The `system` block records `machine_id`, hostname, logical CPU count,
total memory, `uname`, and the compile target CPU model. The scheduled
GitHub Actions workflow runs the directory-mode command weekly and on
manual dispatch, then uploads `benchmark-reports/*.json` and
`benchmark-output.txt` as artifacts for trend inspection.

To collect local runs from several machines:

```sh
rsync -a host-a:/path/to/quic-zig/benchmark-reports/ aggregate-benchmarks/
rsync -a host-b:/path/to/quic-zig/benchmark-reports/ aggregate-benchmarks/
```

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
| `hp_mask_aes128_cached` | AES-128 header-protection mask using a cached key schedule |
| `aead_aes128_seal_1200b` | Raw AES-128-GCM seal over a 1200-byte QUIC payload fixture |
| `aead_aes128_open_1200b` | Raw AES-128-GCM open over the same fixture |
| `packet_1rtt_seal_100b_aes128` | Full 1-RTT short-header seal with a 100-byte payload |
| `packet_1rtt_open_100b_aes128` | Full 1-RTT short-header open for the same fixture |
| `packet_initial_seal_1200b_rfc9001` | RFC 9001-derived Initial seal padded to a 1200-byte datagram |
| `packet_initial_open_1200b_rfc9001` | RFC 9001-derived Initial open for the same fixture |
| `stream_send_ack_loss_requeue` | Send-stream ACK, loss, retransmit, and ACK-floor advancement |
| `stream_recv_reassembly_sparse_64k` | Receive-stream sparse 64 KiB reassembly and in-order read |
| `pn_space_record_ack_ranges` | Received-PN insertion, ACK range construction, and ACK range iteration |
| `loss_pto_tick` | ACK processing, threshold loss detection, PTO calculation, and probe selection |
| `connection_ack_loss_dispatch` | Production `Connection.handleAckAtLevel` ACK dispatch and packet-threshold loss detection |
| `conn_datagram_send_ack_loss_events` | DATAGRAM ACK/loss event snapshot and bounded event queue behavior |
| `transport_params_encode_common` | Transport-parameter encode over common QUIC v1 limits |
| `transport_params_decode_common` | Transport-parameter decode over common QUIC v1 limits |
| `transport_params_decode_extensions` | Transport-parameter decode with DATAGRAM, versions, preferred address, multipath, and draft extension flags |
| `retry_token_mint_validate` | Stateless Retry token mint and validation |
| `new_token_mint_validate` | NEW_TOKEN mint and validation |
| `stateless_reset_token_derive` | Stateless reset token derivation over fixed CID fixtures |
| `quic_lb_cid_generate` | QUIC-LB plaintext, AES single-pass, and four-pass CID generation |
| `flow_control_credit_update` | Connection, stream, and stream-count credit update state transitions |
| `path_validator_challenge_response` | PATH_CHALLENGE/PATH_RESPONSE match, stray response, and timeout transitions |
| `path_set_schedule_round_robin` | Public path-set round-robin scheduling with skipped non-sendable paths |

## Extending

Add benchmarks when a change affects a parser, frame codec, packet
builder, crypto path, stream scheduler, recovery primitive, or connection
event path that is expected to run for most packets. Keep fixtures
reusable so AEAD, packet-key, stream, and recovery setup can be shared
across related benchmarks.

Benchmarks run sequentially and single-threaded. Run on a quiet machine
for stable comparisons.

Use `zig build bench-test` to run the benchmark helper fixture tests.
That build step uses the same module wiring as `zig build bench`, so
crypto helpers that depend on BoringSSL's generated C module do not need
ad hoc `zig test` command-line wiring.
