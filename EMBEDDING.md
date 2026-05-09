# Embedding quic-zig

quic-zig is a Zig-first IETF QUIC v1 transport library. This guide shows the two
common embed paths (server / client) and the raw `Connection` API for
embedders writing custom event loops.

> **Pre-1.0.** The public API may churn before 1.0. See
> [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CHANGELOG.md`](CHANGELOG.md) for
> migration notes.

## Example 1: server with `transport.runUdpServer`

The fastest path to a working QUIC server. `runUdpServer` binds the UDP
socket, applies `SO_RCVBUF` / `SO_SNDBUF` tuning, drives a 5 ms
receive/feed/poll/tick cadence, and exits cleanly when the supplied
shutdown flag flips.

`runUdpServer` does **not** take an application-level callback (see "API
awkwardness" below). Embedders run their per-stream logic on a separate
thread that walks `server.iterator()`, or hand-roll the loop (next section).

```zig
const std = @import("std");
const quic-zig = @import("quic-zig");

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    cert_pem: []const u8,
    key_pem: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"h3"};

    var retry_key: quic-zig.RetryTokenKey = undefined;
    try std.crypto.random.bytes(&retry_key); // see "Production checklist"

    var server = try quic-zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = cert_pem,
        .tls_key_pem = key_pem,
        .alpn_protocols = &protos,
        .transport_params = .{
            .max_idle_timeout_ms = 30_000,
            .initial_max_data = 16 * 1024 * 1024,
            .initial_max_stream_data_bidi_local = 1 << 20,
            .initial_max_stream_data_bidi_remote = 1 << 20,
            .initial_max_stream_data_uni = 1 << 20,
            .initial_max_streams_bidi = 1000,
            .initial_max_streams_uni = 64,
            .active_connection_id_limit = 4,
        },
        .max_concurrent_connections = 10_000,
        .max_initials_per_source_per_window = 32,
        .retry_token_key = retry_key,
    });
    defer server.deinit();

    // Application logic runs in a separate worker that walks
    // server.iterator() each tick. See "Roll your own loop" if you want
    // ingress and app logic on the same thread.
    try quic-zig.transport.runUdpServer(&server, .{
        .listen = "0.0.0.0:443",
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

## Example 2: client with `Client`

`Client.connect` builds a TLS-1.3-only client context, mints random
DCID/SCID per RFC 9000 §7.2, calls `Connection.initClient`, and hands back
a `*Connection` ready for the first `advance()`. There is no
`runUdpClient` helper today — embedders own the I/O loop.

```zig
const std = @import("std");
const quic-zig = @import("quic-zig");

pub fn dial(
    allocator: std.mem.Allocator,
    sock: anytype, // your UDP socket, already bound
    server_addr: anytype,
    server_name: []const u8,
) !void {
    const protos = [_][]const u8{"h3"};

    var client = try quic-zig.Client.connect(.{
        .allocator = allocator,
        .server_name = server_name,
        .alpn_protocols = &protos,
        .transport_params = .{
            .max_idle_timeout_ms = 30_000,
            .initial_max_data = 16 * 1024 * 1024,
            .initial_max_stream_data_bidi_local = 1 << 20,
            .initial_max_stream_data_bidi_remote = 1 << 20,
            .initial_max_stream_data_uni = 1 << 20,
            .initial_max_streams_bidi = 100,
            .initial_max_streams_uni = 64,
            .active_connection_id_limit = 4,
        },
    });
    defer client.deinit();

    try client.conn.advance(); // emit first Initial

    var rx: [64 * 1024]u8 = undefined;
    var tx: [1500]u8 = undefined;
    var sent_request = false;

    while (!client.conn.isClosed()) {
        const now_us = monotonicNowUs();

        if (try sock.recv(&rx)) |msg| {
            try client.conn.handle(msg.bytes, null, now_us);
        }

        if (client.conn.handshakeDone() and !sent_request) {
            const stream_id: u64 = 0; // first client-initiated bidi
            _ = try client.conn.openBidi(stream_id);
            _ = try client.conn.streamWrite(stream_id, "GET /\r\n");
            try client.conn.streamFinish(stream_id);
            sent_request = true;
        }

        while (try client.conn.poll(&tx, now_us)) |n| {
            try sock.send(server_addr, tx[0..n]);
        }
        try client.conn.tick(now_us);
    }
}
```

## Raw `Connection` API

`Connection` is the I/O-agnostic state machine `Server` and `Client` wrap.
Reach for it directly when you need batched I/O (`recvmmsg`, GSO),
deterministic CIDs, qlog file rotation, or any other custom loop. The
embedder owns the UDP socket *and* the wall clock.

The four-call cycle:

1. **`conn.handle(buf, from, now_us)`** — feed inbound bytes (one UDP
   datagram). Errors are non-fatal at the transport level; closed
   connections are no-ops.
2. **`conn.poll(dst, now_us)`** — drain one outbound packet. Loop until it
   returns `null`.
3. **`conn.tick(now_us)`** — drive PTO, loss detection, and idle timeout.
4. **`conn.nextTimerDeadline(now_us)`** — earliest microsecond your event
   loop should wake at. Park your loop on this between datagrams.

```zig
while (!conn.isClosed()) {
    const now_us = monotonicNowUs();

    if (try sock.recvNonBlocking(&rx)) |msg| {
        try conn.handle(msg.bytes, msg.from, now_us);
    }

    while (try conn.poll(&tx, now_us)) |n| {
        try sock.send(peer_addr, tx[0..n]);
    }
    try conn.tick(now_us);

    // Drain stream / connection events.
    while (conn.pollEvent()) |ev| switch (ev) {
        .close => |c| std.log.info("close: {}", .{c}),
        .flow_blocked => {},
        .connection_ids_needed => {},
        .datagram_acked, .datagram_lost => {},
    };

    // Open or read application streams (here: read every stream that
    // has data).
    var it = conn.streamIterator();
    while (it.next()) |entry| {
        const stream_id = entry.key_ptr.*;
        var buf: [4096]u8 = undefined;
        const n = try conn.streamRead(stream_id, &buf);
        if (n > 0) handleAppData(stream_id, buf[0..n]);
    }

    parkUntil(conn.nextTimerDeadline(now_us));
}
```

This is the same cycle `Server` runs internally per-slot; the QNS endpoint
in `interop/qns_endpoint.zig` is a 3 kLOC bespoke loop over `Connection`.

## Required configuration knobs

`Server.Config` ships secure-by-default for the knobs the hardening guide
calls out, but a handful require explicit values for any internet-facing
deployment:

- **`tls_cert_pem` / `tls_key_pem`** — no defaults. PEM-encoded leaf cert
  chain + matching private key. Owned by the caller; outlive the server.
- **`alpn_protocols`** — required (QUIC mandates ALPN per RFC 9001 §8.1).
  Set per peer expectations, e.g. `&.{ "h3" }` for HTTP/3.
- **`transport_params.max_idle_timeout_ms`** — set explicitly. quic-zig's
  default `0` means no idle timeout, which is rarely what you want;
  30_000 (30 s) is a sensible production value.
- **`retry_token_key: ?RetryTokenKey`** — 32-byte HMAC key for stateless
  Retry (RFC 9000 §8.1.2). Operator MUST randomize at startup
  (`std.crypto.random.bytes`) and persist across restarts so in-flight
  Retries validate after a graceful restart. Without this, every Initial
  earns a slot; with it, peers must echo a token first.
- **`early_data_anti_replay: ?*tls.AntiReplayTracker`** — required if
  `enable_0rtt = true` on the auto-built TLS context. See "0-RTT" below.
- **`max_concurrent_connections: u32 = 1000`** — slot table size. Cap your
  DoS exposure; pair with monitoring on
  `MetricsSnapshot.feeds_table_full`.
- **`max_initials_per_source_per_window: ?u32 = null`** — per-source
  Initial-acceptance cap. Recommended ~32 for open internet. Off by
  default for dev/interop ergonomics.
- **`preferred_address: ?PreferredAddressConfig = null`** — RFC 9000
  §18.2 / §5.1.1 server-preferred-address advertisement. When set,
  every accepted connection's outbound transport parameters carry a
  `preferred_address` value pointing at the configured IPv4 / IPv6
  address pair; the seq-1 alt-CID + matching stateless-reset token
  are minted per-connection through `mintLocalScid` +
  `conn.stateless_reset.derive`. `runUdpServer` consults the same
  field to bind alt listener socket(s) on the configured port(s),
  poll all listeners per iteration, and route outbound replies
  through the listener the slot most recently received on.
  **Requires `stateless_reset_key`** (the deterministic token
  derivation is the only path quic-zig exposes for the seq-1 reset
  token); `Server.init` returns `InvalidConfig` if you forget. At
  least one of `ipv4` / `ipv6` must be non-null. Embedders driving
  their own loop still get the codec auto-build — only the multi-
  socket plumbing is `runUdpServer`-specific.

## 0-RTT security checklist

0-RTT replay protection is the embedder's responsibility. Enabling 0-RTT
without the steps below is a **known security hole** per RFC 9001 §5.6 /
RFC 8446 §8.

- **Instantiate `tls.AntiReplayTracker`** and wire it via
  `Server.Config.early_data_anti_replay`. quic-zig installs the BoringSSL
  `allow_early_data` callback automatically when both `enable_0rtt` and
  this field are set. See `src/tls/anti_replay.zig` for sizing
  (`max_entries`, `max_age_us`).
- **Verify request idempotency at the application layer.** quic-zig labels
  bytes via `Connection.streamArrivedInEarlyData(id)`; treat any non-GET
  / non-idempotent request that arrives `true` as suspect.
- **Persist session tickets only when replay protection is active.** A
  ticket cached on disk without an active tracker is a replay window.
- **Default is OFF.** `Server.Config.enable_0rtt` defaults to `false`.
  Flip it on only after wiring the tracker.

## Production deployment checklist

- **Build with `-Doptimize=ReleaseSafe`** (mandatory). `ReleaseFast` /
  `ReleaseSmall` are forbidden for the network-input parser surface — the
  documented `unreachable` paths in `wire/`, `frame/`, and `conn/` are
  trapped only when runtime safety is on. See the policy block at the top
  of `build.zig`.
- **Tune the UDP socket.** `runUdpServer` does this automatically; raw
  loops should call `transport.applyServerTuning(sock, .{})` after bind.
  See `src/transport/socket_opts.zig` for `SO_RCVBUF` / `SO_SNDBUF`
  sizing.
- **Set up qlog output for incident response** via
  `Connection.setQlogCallback` (or `Server.Config.qlog_callback` to apply
  to every accepted slot). **Known gap:** event coverage is incomplete in
  the current release — packet-level events (sent/received) and many
  recovery transitions are not yet emitted. Treat current qlog output as
  best-effort.
- **Persist `NEW_TOKEN` values across restarts** if you want returning
  clients to skip the Retry round-trip. Set `Config.new_token_key` to a
  stable 32-byte AES-GCM-256 key (distinct from `retry_token_key` —
  different rotation cadences).
- **Persist the stateless-reset key across restarts.** Without it, live
  connections through a restart are inadvertently reset by their old
  CIDs. **TODO:** the stateless-reset key derivation surface is currently
  per-Connection internal; verify the persistence story before relying on
  it in production.

## What's not in this guide

- **HTTP/3 / QPACK.** Out of scope — quic-zig is transport-only. Layer your
  own H3 implementation on top of `Connection` streams.
- **Multipath QUIC.** quic-zig tracks `draft-ietf-quic-multipath-21`; expect
  API churn until the spec is published as an RFC. The draft is in the
  RFC Editor queue (IESG-approved) so the codepoints are stable.
- **Alternative server addresses
  (`draft-munizaga-quic-alternative-server-address-00`).** Codec,
  transport-parameter negotiation, server emit, and a typed receive
  surface ship today via `Connection.advertiseAlternative*Address`,
  `ConnectionEvent.alternative_server_address`, and the `quic_zig.alt_addr`
  helper namespace. The `alt_addr/root.zig` module-level docstring
  walks through the recommended embedder integration shape (address
  book + Preferred-driven migration with the §9 random-delay helper);
  `examples/alt_addr_embedder.zig` ships a runnable reference
  implementation with `AddressBook`, `MigrationScheduler`, and
  `Embedder.pump` types embedders can copy or import. Driver-level
  path-opening on receipt remains embedder policy.
- **QUIC-LB connection-ID generation
  (`draft-ietf-quic-load-balancers-21`).** Server-side helpers ship via
  `quic_zig.lb` and `Server.Config.quic_lb` for embedders deploying
  behind a coordinated load balancer; the IETF draft itself is
  expired and pinned indefinitely at -21, so the codepoints are a
  private agreement between server and LB rather than a path to
  formal IANA allocation.
- **Tuning recv/send buffers for 100k+ connections.** Not yet documented;
  the `transport.ServerTuning` defaults (4 MiB each) target a 10k-conn
  workload.
- **Linux GSO / `recvmmsg` integration.** Not wired into `runUdpServer`
  yet; embedders needing batched I/O hand-roll the loop directly against
  `Connection.handle` / `Connection.pollDatagram`.

## API awkwardness (notes for future smoothing)

- **`runUdpServer` has no application callback.** The embedder runs
  per-stream / per-event logic on a separate thread that walks
  `server.iterator()`, which makes the "minimal complete server" example
  more cognitively expensive than it should be. A `Handler`-style hook
  fired after each `feed`/`poll`/`tick` would close the gap.
- **`runUdpClient` shares `runUdpServer`'s callback-less shape.**
  The opinionated `quic_zig.transport.runUdpClient` is the dialing
  mirror to `runUdpServer`: same `bind` / `tune` / `poll` / `recv` /
  `tick` loop, same threading model, same lack of an application
  callback. Embedders running per-stream logic still drive
  `client.conn` from a separate thread. A `Handler`-style hook
  would close the same gap on both sides.
- **Stream IDs are caller-allocated.** `openBidi(id)` / `openUni(id)`
  require the embedder to track the next legal id for their role per RFC
  9000 §2.1. A `nextLocalBidiId()` / `openNextBidi()` helper would remove
  the bit-fiddling.
- **`Connection.streamIterator` semantics.** Iteration is invalidated by
  any `openBidi` / `openUni` call due to HashMap rehash; an embedder
  reading and writing in the same loop must collect IDs first.
