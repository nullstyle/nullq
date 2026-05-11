//! Test root for benchmark helper modules.
//!
//! `zig build bench-test` runs these through the same build graph as
//! `zig build bench`, including BoringSSL's generated C module wiring.

test {
    _ = @import("connection_datagram.zig");
    _ = @import("loss_ack.zig");
    _ = @import("packet_crypto.zig");
    _ = @import("stream_reassembly.zig");
}
