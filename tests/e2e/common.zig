//! Shared helpers for the e2e/ test suite.
//!
//! Several smoke tests need the same on-disk PEM fixtures and the
//! same "reasonable defaults" `TransportParams` block. Centralizing
//! them here keeps the per-file boilerplate small and ensures
//! everyone agrees on what "default" means.
//!
//! Tests that need a *different* shape (e.g. raising
//! `initial_max_data` for a 512 KiB upload regression) keep their
//! own inline literal — `defaultParams` is only the baseline, not
//! a constraint.

const nullq = @import("nullq");

/// Self-signed test certificate. Loaded via `@embedFile` so it ships
/// with the test binary instead of being read at runtime.
pub const test_cert_pem = @embedFile("../data/test_cert.pem");

/// Matching private key for `test_cert_pem`.
pub const test_key_pem = @embedFile("../data/test_key.pem");

/// Reasonable defaults for smoke tests that don't care about
/// specific transport-parameter shapes. Mirrors the values the
/// QNS endpoint advertises by default.
pub fn defaultParams() nullq.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
}
