//! Connection-adjacent DATAGRAM event benchmarks.
//!
//! These stay below the UDP/socket layer and exercise the durable
//! ACK/loss notification path that `Connection` uses for RFC 9221
//! DATAGRAM send outcomes.

const quic_zig = @import("quic_zig");

const event_queue = quic_zig.conn.event_queue;
const sent_packets = quic_zig.conn.sent_packets;

const event_count = event_queue.max_datagram_send_events;

pub const DatagramEventCtx = struct {
    packets: [event_count]sent_packets.SentPacket,
};

pub fn initDatagramEventCtx() DatagramEventCtx {
    var ctx: DatagramEventCtx = undefined;
    for (&ctx.packets, 0..) |*packet, idx| {
        packet.* = .{
            .pn = idx,
            .sent_time_us = 10_000 + idx * 100,
            .bytes = 96 + idx,
            .ack_eliciting = true,
            .in_flight = true,
            .datagram = .{
                .id = 1_000 + idx,
                .len = 32 + (idx & 15),
                .path_id = @intCast(idx & 3),
            },
            .is_early_data = (idx & 7) == 0,
        };
    }
    return ctx;
}

fn foldEvent(event: event_queue.StoredDatagramSendEvent) u64 {
    const item = switch (event) {
        .acked => |acked| acked,
        .lost => |lost| lost,
    };
    return item.id +% item.len +% item.path_id +% item.packet_number +%
        item.sent_time_us +% @intFromBool(item.arrived_in_early_data);
}

pub fn runConnDatagramSendAckLossEvents(ctx: *const DatagramEventCtx, iters: u64) u64 {
    var queue: event_queue.EventQueue(
        event_queue.StoredDatagramSendEvent,
        event_queue.max_datagram_send_events,
    ) = .{};
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const packet = &ctx.packets[@intCast(i & (event_count - 1))];
        const event = event_queue.datagramEventFromPacket(packet) orelse unreachable;
        if ((i & 1) == 0) {
            queue.push(.{ .acked = event });
        } else {
            queue.push(.{ .lost = event });
        }
        if (queue.len >= 8) {
            sum +%= foldEvent(queue.pop().?);
        }
    }
    while (queue.pop()) |event| {
        sum +%= foldEvent(event);
    }
    return sum;
}
