test {
    _ = @import("fuzz_smoke.zig");
    _ = @import("e2e/mock_transport_handshake.zig");
    _ = @import("e2e/mock_transport_packet_keys.zig");
    _ = @import("e2e/mock_transport_stream_exchange.zig");
    _ = @import("e2e/mock_transport_real_handshake.zig");
    _ = @import("e2e/server_smoke.zig");
}
