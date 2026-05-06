test {
    _ = @import("fuzz_smoke.zig");
    _ = @import("e2e/mock_transport_handshake.zig");
    _ = @import("e2e/mock_transport_packet_keys.zig");
    _ = @import("e2e/mock_transport_stream_exchange.zig");
    _ = @import("e2e/mock_transport_real_handshake.zig");
    _ = @import("e2e/server_smoke.zig");
    _ = @import("e2e/server_loop_smoke.zig");
    _ = @import("e2e/client_smoke.zig");
    _ = @import("e2e/server_client_handshake.zig");
    _ = @import("e2e/zero_rtt_replay_smoke.zig");
    _ = @import("e2e/path_challenge_flood_smoke.zig");
    _ = @import("e2e/vn_spoofed_source_smoke.zig");
    _ = @import("e2e/new_token_smoke.zig");
}
