# quic-zig RFC-traceable conformance suites

These are conformance tests, not general behavior tests. Each test names
one normative requirement, uses the BCP 14 keyword from the RFC, and
cites the relevant section in the test name.

## Run

```sh
zig build conformance
zig build conformance -Dconformance-filter='RFC9000 §17'
zig build conformance -Dconformance-filter='MUST NOT'
zig build test
```

`-Dconformance-filter` is a compile-time substring filter. Changing it
participates in Zig's compile cache key, so narrow reruns are still fast.

## Test Name Grammar

```text
<KEYWORD> <observable behavior> [RFC#### §section ¶paragraph]
```

| Keyword | Meaning |
| --- | --- |
| `MUST`, `REQUIRED`, `SHALL` | Non-conformance if this fails |
| `MUST NOT`, `SHALL NOT` | Assert rejection or absence |
| `SHOULD`, `RECOMMENDED` | Test the recommended default and document deviations |
| `SHOULD NOT`, `NOT RECOMMENDED` | Test the avoided behavior and document deviations |
| `MAY`, `OPTIONAL` | Test only when implemented |
| `NORMATIVE` | Normative text that does not use BCP 14 keywords |

Examples:

```zig
test "MUST reject a v1 long-header packet whose Version field is 0 [RFC9000 §17.2.1 ¶1]" {}
test "MUST NOT shorten a validated path's anti-amplification limit on migration [RFC9000 §9.4 ¶2]" {}
test "SHOULD set the Reserved Bits to 0 on transmit [RFC9000 §17.2 ¶8]" {}
test "MAY include the active_connection_id_limit transport parameter [RFC9000 §18.2 ¶12]" {}
```

## Visible Conformance Debt

Skipped requirements must stay visible. Prefix the test name with
`skip_`, cite the requirement, and return `error.SkipZigTest`.

```zig
test "skip_MUST reject unsupported example frames [RFC9000 §X.Y ¶N]" {
    return error.SkipZigTest;
}
```

Never use `skip_` to imply that an optional `MAY` feature is required.

## File Layout

```text
tests/
  conformance.zig
  conformance/
    README.md
    _initial_fixture.zig
    _handshake_fixture.zig
    rfc8999_invariants.zig
    rfc9000_varint.zig
    rfc9000_packet_headers.zig
    rfc9000_transport_params.zig
    rfc9000_frames.zig
    rfc9000_streams_flow.zig
    rfc9000_negotiation_validation.zig
    rfc9000_packetization.zig
    rfc9000_ecn.zig
    rfc9001_tls.zig
    rfc9002_loss_recovery.zig
    rfc9221_datagram.zig
    rfc9287_grease_quic_bit.zig
    rfc9368_quic_v2.zig
    quic_lb_draft21.zig
    draft_munizaga_alt_addr_00.zig
```

The entry point lives at `tests/conformance.zig` so suites can embed
fixtures from `tests/data/`.

## Suite Skeleton

Tests live at file scope. The default Zig test runner only discovers
top-level `test` blocks.

```zig
//! RFC 9000 §17 - Packet formats.
//!
//! Covered:
//!   RFC9000 §17.2.1 ¶1  MUST   reject Version 0 in v1 long header
//!
//! Visible debt:
//!   RFC9000 §X.Y ¶N     MUST   ...
//!
//! Out of scope:
//!   RFC9000 §6 negotiation lives in rfc9000_negotiation_validation.zig

const std = @import("std");
const quic_zig = @import("quic_zig");

test "MUST reject a v1 long-header packet whose Version field is 0 [RFC9000 §17.2.1 ¶1]" {
    _ = quic_zig;
    // Arrange, act, and assert one observable behavior.
}
```

Use local helper functions and `defer` for setup and cleanup.

## Author Checklist

- Every test name starts with a BCP 14 keyword, `NORMATIVE`, or
  `skip_`.
- Keyword strength matches the RFC text.
- Citation is precise enough for an auditor to find the requirement.
- Each test asserts one observable behavior.
- `MUST NOT` tests assert rejection, absence, or a specific error.
- Every non-skipped test exercises a quic-zig surface directly or
  through a fixture.
- File-local raw-byte builders are only fixtures. Feed them through a
  quic-zig parser or state-machine API rather than asserting against the
  builder itself.
- The file-level coverage block lists covered requirements, visible
  debt, and out-of-scope requirements where useful.
- `zig build conformance` passes.
- Narrow filters use
  `zig build conformance -Dconformance-filter='RFC#### §X.Y'`.

## What To Test

Prioritize receive-side parsing and validation, encoding constraints,
state-machine invariants, and bounded-resource limits. Duplicate
important RFC requirements from lower-level unit tests into this suite:
the unit tests are the developer regression net, while the conformance
suite is the auditor-facing artifact.
