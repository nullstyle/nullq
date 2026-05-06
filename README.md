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

## Production posture

nullq ships secure-by-default for the `Server.Config` /
`Client.Config` knobs the hardening guide calls out, but a handful of
production-grade limits are off by default so dev / interop / test
runs aren't burdened with rate-limit tuning. This section lists what's
on without config and what you need to wire up before pointing nullq
at the open internet.

### On by default (no config required)

- **0-RTT off.** `Server.Config.enable_0rtt = false` and
  `Client.Config.session_ticket = null` (auto-built TLS context
  follows: `early_data_enabled` is gated on these flags, never
  unconditionally true).
- **CONNECTION_CLOSE reason redacted.** `reveal_close_reason_on_wire
  = false` on both `Server.Config` and `Client.Config` — the wire
  frame carries the error code and space, but the descriptive reason
  text is empty. Local introspection via `closeEvent()` /
  `pollEvent()` still sees the full reason.
- **Server SCIDs are CSPRNG draws.** Every server-issued connection
  ID comes from `boringssl.crypto.rand.fillBytes` — no deployment
  metadata (shard, region, tenant, timestamp) leaks on the wire.
- **Per-stream send queue capped.** `default_max_buffered_send =
  1 MiB` per stream (`src/conn/send_stream.zig`); `write` short-writes
  to apply back-pressure when the cap is hit. Override per-stream via
  `stream.send.max_buffered`.
- **Per-Connection memory cap.** `Server.Config.max_connection_memory`
  defaults to 32 MiB and aggregates peer-driven CRYPTO / STREAM /
  DATAGRAM / pending-frame / ack-tracker buffers — no single peer can
  push a Connection past this bound.
- **Initial-too-small drop.** UDP datagrams carrying a QUIC v1
  Initial below 1200 bytes are dropped at `Server.feed` per RFC 9000
  §14; surfaces as `MetricsSnapshot.feeds_initial_too_small`.
- **ACK range count cap.** Incoming ACK / PATH_ACK frames with
  `range_count > 256` are rejected before iteration
  (`max_incoming_ack_ranges` in `src/frame/decode.zig`); overlapping
  ranges are also rejected.
- **Per-datagram plaintext bound.** `max_recv_plaintext = 4096` —
  oversized post-decryption payloads close the connection with
  PROTOCOL_VIOLATION.
- **Migration safety.** Address migration before handshake
  confirmation is dropped (no anti-amp credit, no validator state).
  PATH_CHALLENGE emission is rate-limited per path
  (`min_path_challenge_interval_us = 100 ms`).
- **Sensitive material zeroed on `deinit`.** Retry-token HMAC key,
  NEW_TOKEN AEAD key, per-level traffic secrets, application
  read/write key epochs, and stateless-reset tokens all go through
  `std.crypto.secureZero` at struct teardown.

### Off by default — opt in for production

Each of these defaults to a value that's fine for `zig build test` /
QNS interop but should be set explicitly before exposing nullq to
arbitrary peers. All are on `Server.Config` unless noted.

- `max_initials_per_source_per_window: ?u32 = null` — per-source
  Initial-acceptance cap. Recommended ~32 for open-internet
  deployments. Window length is `source_rate_window_us` (default 1 s).
- `max_vn_per_source_per_window: ?u32 = 8` — per-source
  Version-Negotiation emission cap. The default is already non-null,
  but tune for your peer mix. Set null to disable (not recommended).
- `max_log_events_per_source_per_window: ?u32 = 16` — per-source cap
  on `LogEvent` deliveries to your `log_callback`. Already non-null;
  null disables.
- `max_datagrams_per_window: ?u32 = null` — global listener
  packet-rate cap (no per-source bookkeeping). Pair with
  `max_bytes_per_window: ?u64 = null` for a byte-rate cap on the same
  window. Both share `listener_rate_window_us` (default 1 s). Scale
  to ~2x peak observed traffic and alert on the
  `feeds_listener_rate_limited` / `feeds_listener_byte_rate_limited`
  metrics.
- `retry_token_key: ?RetryTokenKey = null` — 32-byte key that enables
  stateless Retry (RFC 9000 §8.1.2). When null, every well-formed
  Initial earns a fresh `Connection`; when set, peers must echo a
  valid AEAD-sealed token before slot allocation. Production
  servers behind a CDN that already validates source addresses can
  leave this null.
- `new_token_key: ?NewTokenKey = null` — distinct AES-GCM-256 key
  that enables NEW_TOKEN issuance (RFC 9000 §8.1.3). When null, no
  NEW_TOKEN frames are emitted and returning clients always pay
  the Retry round-trip. Intentionally separate from
  `retry_token_key` so rotation cadences are independent.
- `early_data_anti_replay: ?*tls.AntiReplayTracker = null` — required
  if you flip `enable_0rtt = true` on the auto-built TLS context.
  Wires the BoringSSL pre-accept callback so resumed sessions hash
  to a tracker `Id` and replays return `false` (denied at the TLS
  layer). Override-mode embedders install their own callback.

### Build mode

- `zig build` defaults to `Debug` — fine for development, the test
  suite, and interop fixtures.
- **Production deployments MUST pass `-Doptimize=ReleaseSafe`** to
  keep Zig's runtime safety checks live (integer overflow, bounds,
  optional unwrap, `unreachable`).
- `ReleaseFast` and `ReleaseSmall` are forbidden for the
  network-input parser surface — the residual `unreachable` paths in
  `wire/`, `frame/`, and `conn/` are documented as non-peer-reachable
  invariants but become undefined behavior under those modes. The
  bench harness opts into `ReleaseFast` for itself only because bench
  never touches peer input. See the policy block at the top of
  `build.zig`.

### Things you must wire yourself

Defaults can't fill these in for you — they're application policy:

- A `MigrationCallback` (install via
  `Connection.setMigrationCallback`) if you want to allowlist peer
  addresses for migration. Without one, every probe that survives
  the pre-handshake / rate-limit gates earns a PATH_CHALLENGE.
- An `AntiReplayTracker` (from `nullq.tls.AntiReplayTracker`) if you
  opt into 0-RTT, threaded through
  `Server.Config.early_data_anti_replay`.
- A custom `boringssl.tls.Context` via
  `Server.Config.tls_context_override` /
  `Client.Config.tls_context_override` if you need session-ticket
  callbacks, keylog, custom verify modes, or any other TLS-context
  behavior the auto-built path doesn't expose.

### Pointers for deeper detail

- [`docs/hardening-status.md`](docs/hardening-status.md) — full
  per-§ status against the hardening guide, with commit hashes and
  source citations.
- [`docs/fuzz-coverage.md`](docs/fuzz-coverage.md) — coverage-guided
  fuzz harness inventory (§11.1).
- `hardening-guide.md` — the canonical reference doc nullq is
  hardened against.

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
