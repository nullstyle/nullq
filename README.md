# nullq

A Zig-first IETF QUIC v1 implementation, built from RFCs 8999/9000/9001/9002,
using [`boringssl-zig`](../boringssl-zig) for TLS 1.3 and AEAD/HKDF crypto.

**Status: interop prototype, not production yet.** nullq now completes
QUIC v1 handshakes, streams, DATAGRAMs, public send-side `streamReset`,
CID issuance, PATH_CHALLENGE/PATH_RESPONSE, timer-driven loss/PTO
recovery with NewReno feedback, path-aware `PathSet` recovery
ownership, and draft-21 multipath nonce/CID routing checks. Close/error
state is now exposed through `closeState()`, sticky `closeEvent()`
status, and pollable `pollEvent()` notifications; draining suppresses
incoming packet processing and stateless reset tokens close cleanly.
Client-side Version Negotiation and Retry handling now validate CID
echoes, Retry integrity tags, retry transport parameters, and re-arm
Initial CRYPTO with the Retry token; server embedders get
`writeRetry`, `writeVersionNegotiation`, and stateless
`retry_token` HMAC helpers for address-bound Retry validation.
nullq-peer now verifies live quic-go Retry and v2-to-v1 Version
Negotiation scenarios with those helpers. Application key updates now
keep previous/current/next read epochs, discard old keys after 3x-PTO,
support local initiation, and enforce cross-suite AEAD packet/auth
limits across all Application paths. Packet protection now supports all
QUIC v1 TLS suites:
`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and
`TLS_CHACHA20_POLY1305_SHA256`. The receive side now has an explicit
bounded allocation policy for advertised receive windows, stream counts,
path IDs, CID fanout, DATAGRAM queues, CRYPTO gaps, and advisory blocked
frame tracking. `zig build test` also runs deterministic parser/property
fuzz smokes for varints, frames, transport parameters, packet headers,
ACK ranges, and CRYPTO/STREAM reassembly. Transport-parameter handling
now includes typed `preferred_address` codec coverage plus duplicate
parameter rejection. 0-RTT now has early STREAM/DATAGRAM transport
plumbing plus accepted and rejected go-quic-peer resumption smokes,
while deeper mismatch/loss hardening still needs work. Multipath also
has embedder-driven path CID replenishment, abandoned-path 3x-PTO
retention coverage, and a deterministic two-path transfer stress test.
go-quic-peer single-path, 0-RTT, and path-switch smoke tests are
maintained as interop gates. The first official QUIC interop-runner
gate is also scaffolded under `interop/`: `qns-endpoint` is a
server-side HTTP/0.9 `hq-interop` endpoint with Docker/run-wrapper
support for nullq-as-server testing against external clients. See
[INTEROP_STATUS.md](INTEROP_STATUS.md) for the current verification log
and remaining production gaps.

```sh
mise install
just test
```

## Embed nullq as a server

`nullq.Server` is the thinnest convenience wrapper that keeps the
embedder in charge of the UDP socket and the wall clock while
nullq owns the TLS context, the per-connection state, and the
demultiplexing of incoming datagrams. The full lower-level
`Connection` API is fully supported — `Server` just spares you the
boilerplate of writing it yourself for the common case.

### One-liner: `transport.runUdpServer`

The fastest path to a working QUIC server is the opinionated
`std.Io`-based loop bundled with nullq. It binds the UDP socket,
applies `SO_RCVBUF` / `SO_SNDBUF` tuning, drives a 5 ms
receive/feed/poll/tick cadence, and exits cleanly when the supplied
shutdown flag flips. Use this when you want nullq to "just run" and
you don't need Retry, version negotiation, or deterministic CIDs.

```zig
const std = @import("std");
const nullq = @import("nullq");

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    cert_pem: []const u8,
    key_pem: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"hq-interop"};

    var server = try nullq.Server.init(.{
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
    });
    defer server.deinit();

    try nullq.transport.runUdpServer(&server, .{
        .listen = "0.0.0.0:443",
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

The loop ends when `shutdown.load(.acquire)` returns `true`; it
queues `CONNECTION_CLOSE` on every live slot, drains for up to
`shutdown_grace_us` microseconds (default 5 s), and returns. Wire the
flag to a `SIGINT` handler for graceful Ctrl-C.

### Roll your own loop

When you need full control — Retry, version negotiation, deterministic
CIDs, batched I/O via `recvmmsg`, qlog file rotation — drive
`Server.feed` / `slot.conn.pollDatagram` / `slot.conn.tick` yourself:

```zig
const std = @import("std");
const nullq = @import("nullq");

pub fn run(
    allocator: std.mem.Allocator,
    sock: anytype, // your UDP socket
    cert_pem: []const u8,
    key_pem: []const u8,
) !void {
    const protos = [_][]const u8{"hq-interop"};

    var server = try nullq.Server.init(.{
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
    });
    defer server.deinit();

    var rx: [64 * 1024]u8 = undefined;
    var tx: [1350]u8 = undefined;

    while (true) {
        const now_us = monotonicNowUs();
        if (try sock.recv(&rx)) |msg| {
            _ = try server.feed(msg.bytes, msg.from, now_us);
        }
        // Drain any stateless responses (Version Negotiation, Retry)
        // the server queued from the most recent feed. These don't
        // belong to any slot — `feed` returns one of
        // `.version_negotiated` / `.retry_sent` to signal the queue
        // grew, but it's safe to drain unconditionally.
        while (server.drainStatelessResponse()) |resp| {
            try sock.send(resp.dst, resp.slice());
        }
        for (server.iterator()) |slot| {
            // App work goes here: open streams, read data, send
            // datagrams. `slot.conn` is the full `*nullq.Connection`.
            // `pollDatagram` returns the destination address with
            // each outgoing packet so multipath / migration work.
            while (try slot.conn.pollDatagram(&tx, now_us)) |out| {
                try sock.send(out.to.?, tx[0..out.len]);
            }
            try slot.conn.tick(now_us);
        }
        _ = server.reap();
    }
}
```

Set `Config.retry_token_key` to a stable 32-byte HMAC key to
enable stateless Retry-based source validation
(RFC 9000 §8.1.2); first Initials from each peer earn a Retry
challenge instead of a half-allocated `Connection`. Version
Negotiation (RFC 9000 §6) is unconditional. For interop-specific
behavior (deterministic CID prefix, per-testcase wiring), see
`interop/qns_endpoint.zig`.

## Embed nullq as a client

`nullq.Client` is the mirror of `nullq.Server` for the dialing side.
It builds a client-mode TLS context, generates the random initial
DCID and SCID per RFC 9000 §7.2, calls
`bind`/`setLocalScid`/`setInitialDcid`/`setPeerDcid`/`setTransportParams`
in the right order, and hands back a heap-allocated `*Connection`
that's ready for the first scheduler step. The caller still owns
the UDP socket, the wall clock, and the `Connection` lifecycle.

```zig
const std = @import("std");
const nullq = @import("nullq");

pub fn dial(
    allocator: std.mem.Allocator,
    sock: anytype, // your UDP socket, already bound
    server_addr: anytype,
    server_name: []const u8,
) !void {
    const protos = [_][]const u8{"hq-interop"};

    var client = try nullq.Client.connect(.{
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

    // Kick the handshake: emit the first Initial.
    try client.conn.advance();

    var rx: [64 * 1024]u8 = undefined;
    var tx: [1350]u8 = undefined;

    while (!client.conn.isClosed()) {
        const now_us = monotonicNowUs();
        if (try sock.recv(&rx)) |msg| {
            try client.conn.handle(msg.bytes, null, now_us);
        }
        while (try client.conn.poll(&tx, now_us)) |n| {
            try sock.send(server_addr, tx[0..n]);
        }
        try client.conn.tick(now_us);

        // Once the handshake completes, open streams, send
        // datagrams, etc. on `client.conn` directly.
        if (client.conn.handshakeDone()) {
            // ... application logic ...
        }
    }
}
```

For 0-RTT, pass a previously captured ticket via
`Config.session_ticket` (raw bytes from `Session.toBytes`).
`Client.connect` parses it via `Session.fromBytes`, installs it via
`Connection.setSession`, and enables early data on this connection
so the scheduler can emit application data on the first flight.

## 0-RTT Tickets

Session tickets are owned by `boringssl-zig` and re-exported as
`nullq.Session`. Capture them from the client TLS context, serialize
with `Session.toBytes`, then parse with `Session.fromBytes` before the
next client connection:

```zig
var client_ctx = try boringssl.tls.Context.initClient(.{
    .early_data_enabled = true,
});
try client_ctx.setNewSessionCallback(onTicket, store_ptr);

fn onTicket(user_data: ?*anyopaque, session: nullq.Session) void {
    var owned = session;
    defer owned.deinit();
    const bytes = owned.toBytes(allocator) catch return;
    saveTicket(user_data, bytes);
}

var resumed = try nullq.Session.fromBytes(client_ctx, ticket_bytes);
defer resumed.deinit();
try conn.setSession(resumed);
conn.setEarlyDataEnabled(true);
```

Servers that enable early data must bind tickets to replay-relevant
transport and application settings:

```zig
_ = try server_conn.setEarlyDataContextForParams(
    transport_params,
    "hq-interop",
    app_settings_digest,
);
```

## Diagnostics

TLS key logging is opt-in through `boringssl-zig` and re-exported as
`nullq.KeylogCallback`:

```zig
try tls_ctx.setKeylogCallback(onKeylogLine);
```

Application key-update lifecycle events are opt-in through the
connection qlog-style callback:

```zig
conn.setQlogCallback(onQlogEvent, app_state);

fn onQlogEvent(user_data: ?*anyopaque, event: nullq.QlogEvent) void {
    _ = user_data;
    if (event.name == .application_write_update_acked) {
        // Translate to qlog JSON, metrics, or test assertions.
    }
}
```

## What this is

- The QUIC **transport**: streams, datagrams, packet protection, loss
  recovery, congestion control. HTTP/3 is **not** part of nullq.
- I/O-decoupled state machine. The library does not own a socket or
  an event loop; the embedder drives `Connection.handle` /
  `Connection.poll` / `Connection.tick` against a monotonic clock.
- Pure Zig for everything that isn't crypto. BoringSSL is called only
  for AEAD seal/open, HKDF, AES/ChaCha header protection, and TLS 1.3
  handshake.

## Scope

In scope for v0.1:
- IETF QUIC v1 transport from RFCs 8999 / 9000 / 9001 / 9002.
- 0-RTT (RFC 9001 §4.5/4.6) — initial implementation landed; rejection
  hardening still in progress.
- Connection migration (RFC 9000 §9) — landed; broader external soak
  still in progress.
- Multipath QUIC (draft-ietf-quic-multipath) — tracks
  draft-ietf-quic-multipath-21 (`initial_max_path_id`,
  `multipath_draft_version = 21`); expect API churn until the spec is
  published as an RFC.

Out of scope: HTTP/3, QPACK, Windows, FIPS, ECN, DPLPMTUD, BBR,
performance optimizations. See `CHANGELOG.md` for what has shipped
and `CONTRIBUTING.md` for development workflow.
