# nullq RFC-traceable conformance suites

These suites are **conformance** tests, not behaviour tests. Each test
asserts a specific normative requirement from an RFC, named with the
BCP 14 keyword the RFC uses, and cited back to its section. The shape
follows the [RFC-traceable ZSpec testing
guide](../../../zspec-rfc-testing.md), adapted to plain `std.testing`
(no third-party runner).

## Run

```sh
zig build conformance                                          # whole suite
zig build conformance -Dconformance-filter='RFC9000 §17'       # one section
zig build conformance -Dconformance-filter='MUST NOT'          # one keyword across all RFCs
zig build test                                                 # full suite (also runs conformance)
```

`-Dconformance-filter` is a compile-time substring filter — Zig's
default test runner has no runtime filtering. The filter participates
in the compile cache key, so changing it does a fast incremental rebuild.

## Test-name grammar

```
<KEYWORD> <observable behaviour> [RFC#### §section ¶paragraph]
```

| Keyword                         | Meaning                                                                                               |
| ------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `MUST`, `REQUIRED`, `SHALL`     | Implementation is non-conforming if this fails. Hard pass/fail assertion.                             |
| `MUST NOT`, `SHALL NOT`         | Implementation is non-conforming if it permits this. Assert rejection / absence — never "doesn't crash". |
| `SHOULD`, `RECOMMENDED`         | Test the recommended default; document any accepted deviation alongside.                              |
| `SHOULD NOT`, `NOT RECOMMENDED` | Test the avoided behaviour; deviation needs an explicit reason.                                       |
| `MAY`, `OPTIONAL`               | Only if implemented; also test interop with peers that omit it.                                       |
| `NORMATIVE`                     | Normative RFC text that does **not** use a BCP 14 keyword. Don't fake `MUST`.                         |

Examples:

```zig
test "MUST reject a v1 long-header packet whose Version field is 0 [RFC9000 §17.2.1 ¶1]" {}
test "MUST NOT shorten a 4-tuple-validated path's anti-amplification limit on migration [RFC9000 §9.4 ¶2]" {}
test "SHOULD set the Reserved Bits to 0 on transmit [RFC9000 §17.2 ¶8]" {}
test "MAY include the active_connection_id_limit transport parameter [RFC9000 §18.2 ¶12]" {}
```

### Skipping (visible conformance debt)

Use `skip_` as a name prefix **and** return `error.SkipZigTest` from the
body. The name keeps the gap visible in the test list; the body keeps
the test green:

```zig
test "skip_MUST reject messages signed with a revoked key [RFC9000 §X.Y ¶N]" {
    // TODO(issue-456): revocation list not implemented yet.
    return error.SkipZigTest;
}
```

Never use `skip_` to imply that an optional `MAY` feature is required.

## File layout

```
tests/
  conformance.zig                            # entry point (sibling of tests/root.zig)
  conformance/
    README.md                                # this file
    _initial_fixture.zig                     # shared "send malicious Initial to a Server" helper
    rfc8999_invariants.zig                   # canonical example
    rfc9000_varint.zig                       # §16
    rfc9000_packet_headers.zig               # §17
    rfc9000_transport_params.zig             # §18
    rfc9000_frames.zig                       # §19
    rfc9000_streams_flow.zig                 # §3, §4, §5, §10
    rfc9000_negotiation_validation.zig       # §6, §8, §9
    rfc9000_packetization.zig                # §13, §14, §20
    rfc9001_tls.zig                          # RFC 9001
    rfc9002_loss_recovery.zig                # RFC 9002
    rfc9221_datagram.zig                     # RFC 9221
```

The entry point lives at `tests/conformance.zig` (one level up) instead
of `tests/conformance/root.zig` so the Zig package boundary widens to
`tests/`. Suites that need a real `Server` fixture (for receiver-side
gates that fire post-AEAD, e.g. RFC 9000 §17.2.1 or §12.4) can then
`@embedFile("../data/test_cert.pem")` cleanly. See
`_initial_fixture.zig` for the shared Server-fixture helper.

## Suite skeleton

Tests live at **file scope** (Zig's default test runner only walks
top-level `test` blocks in compiled files; tests nested inside `pub
const Foo = struct {}` are not discovered). Use comment dividers and
the citation in the test name itself for grouping.

```zig
//! RFC 9000 §17 — Packet formats.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9000 §17.2.1 ¶1  MUST   reject Version 0 in v1 long header
//!   ...
//!
//! Visible debt:
//!   RFC9000 §X.Y ¶N     MUST   ...
//!
//! Out of scope here:
//!   RFC9000 §6  negotiation lives in rfc9000_negotiation_validation.zig

const std = @import("std");
const nullq = @import("nullq");

// ---------------------------------------------------------------- §17.2 long header

test "MUST reject a v1 long-header packet whose Version field is 0 [RFC9000 §17.2.1 ¶1]" {
    // ... arrange / act / assert one observable behaviour ...
}

test "skip_MUST <unimplemented requirement> [RFC9000 §X.Y ¶N]" {
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §17.3 short header

test "MUST set the Fixed Bit (bit 6) to 1 on every QUIC v1 short-header packet [RFC9000 §17.3 ¶?]" {
    // ...
}
```

There's no `tests:before/after` hook mechanism in `std.testing`; use
local helper fns and `defer` instead.

## Author checklist (review gate)

- [ ] Every test name starts with a BCP 14 keyword (or `NORMATIVE` /
      `skip_` prefix).
- [ ] Keyword strength matches the RFC — no upgrading `SHOULD` to `MUST`.
- [ ] Citation is precise: `[RFC#### §X.Y ¶N]` or `[RFC#### §X.Y]`.
- [ ] One observable behaviour per test.
- [ ] `MUST NOT` tests assert rejection/absence/error — never just
      "did not crash".
- [ ] Coverage block at the top lists Covered / Visible debt / Out of
      scope (where applicable).
- [ ] Tests run cleanly: `zig build conformance`.
- [ ] `zig build conformance -- --test-filter 'RFC#### §X.Y'` runs a
      meaningful subset.

## What to test

For a clean-room implementation of RFC #### the requirements that
matter most are: receive-side parsing/validation (`MUST reject`,
`MUST NOT accept`), encoding constraints (`MUST set`, `MUST NOT emit`),
state-machine invariants, and bounded-resource limits. Skip purely
internal details (cache shape, struct layout) — they are not RFC
requirements.

When the implementation already enforces a `MUST` via a unit test
inside `src/`, **don't delete it** — duplicate it as a conformance
test here. The conformance suite is the auditor-facing artifact; the
unit tests remain the developer-facing regression net.
