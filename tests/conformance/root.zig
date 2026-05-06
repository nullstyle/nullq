//! RFC-traceable conformance test entry point.
//!
//! Each `_ = @import(...)` below pulls in one suite file. Tests live
//! inside `pub const` structs that mirror the RFC's section structure,
//! and Zig's default test runner discovers them automatically when
//! the file is compiled.
//!
//! Conventions every suite MUST follow:
//!   * `pub const RFC<NNNN>_<area>` outermost struct, named after the RFC.
//!   * Test names use BCP 14 keywords literally, end with
//!     `[RFC#### §X.Y ¶N]` (paragraph optional but encouraged).
//!   * One observable behavior per test.
//!   * `skip_` prefix + `return error.SkipZigTest` for visible debt.
//!     Never use it to imply MAY.
//!   * See `tests/conformance/README.md` for the full grammar.
//!
//! Run filtered subsets:
//!     zig build conformance -- --test-filter 'RFC9000 §17'
//!     zig build conformance -- --test-filter 'MUST NOT'

test {
    _ = @import("rfc8999_invariants.zig");
    _ = @import("rfc9000_varint.zig");
    _ = @import("rfc9000_packet_headers.zig");
    _ = @import("rfc9000_transport_params.zig");
    _ = @import("rfc9000_frames.zig");
    _ = @import("rfc9000_streams_flow.zig");
    _ = @import("rfc9000_negotiation_validation.zig");
    _ = @import("rfc9000_packetization.zig");
    _ = @import("rfc9001_tls.zig");
    _ = @import("rfc9002_loss_recovery.zig");
    _ = @import("rfc9221_datagram.zig");
}
