//! RFC-traceable conformance test entry point.
//!
//! Each `_ = @import(...)` below pulls in one suite file. Zig's
//! default test runner discovers each file's top-level `test` blocks
//! automatically when the file is compiled.
//!
//! Conventions every suite MUST follow:
//!   * Test names use BCP 14 keywords literally, end with
//!     `[RFC#### §X.Y ¶N]` (paragraph optional but encouraged).
//!   * One observable behavior per test.
//!   * Tests live at file scope (NOT inside `pub const Foo = struct`)
//!     because Zig's default runner doesn't walk nested-struct tests.
//!   * `skip_` prefix + `return error.SkipZigTest` for visible debt.
//!     Never use it to imply MAY.
//!   * See `tests/conformance/README.md` for the full grammar.
//!
//! This entry-point file lives at `tests/conformance.zig` (sibling of
//! `tests/root.zig`) instead of `tests/conformance/root.zig` so the
//! Zig package boundary for the conformance test binary is `tests/`.
//! Suites that need to `@embedFile("../data/test_cert.pem")` for the
//! Server-fixture path get a valid in-package path that way.
//!
//! Run filtered subsets:
//!     zig build conformance -Dconformance-filter='RFC9000 §17'
//!     zig build conformance -Dconformance-filter='MUST NOT'

test {
    _ = @import("conformance/rfc8999_invariants.zig");
    _ = @import("conformance/rfc9000_varint.zig");
    _ = @import("conformance/rfc9000_packet_headers.zig");
    _ = @import("conformance/rfc9000_transport_params.zig");
    _ = @import("conformance/rfc9000_frames.zig");
    _ = @import("conformance/rfc9000_streams_flow.zig");
    _ = @import("conformance/rfc9000_negotiation_validation.zig");
    _ = @import("conformance/rfc9000_packetization.zig");
    _ = @import("conformance/rfc9000_ecn.zig");
    _ = @import("conformance/rfc9001_tls.zig");
    _ = @import("conformance/rfc9002_loss_recovery.zig");
    _ = @import("conformance/rfc9221_datagram.zig");
    _ = @import("conformance/rfc9287_grease_quic_bit.zig");
    _ = @import("conformance/rfc9368_quic_v2.zig");
    _ = @import("conformance/quic_lb_draft21.zig");
    _ = @import("conformance/draft_munizaga_alt_addr_00.zig");
    // Fixture-internal sanity tests for `_handshake_fixture.zig`.
    // The FIXTURE_SANITY-prefixed tests inside it are not
    // RFC-traceable conformance tests — they are regression coverage
    // for the helper itself. The `_initial_fixture.zig` companion
    // currently has no tests of its own, so it is not imported here.
    _ = @import("conformance/_handshake_fixture.zig");
}
