# quic-zig

A Zig-first IETF QUIC v1 implementation, built from RFCs 8999/9000/9001/9002,
using [`boringssl-zig`](../boringssl-zig) for TLS 1.3 and AEAD/HKDF crypto.

**Status: interop prototype, not production yet.** quic-zig now completes
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
The `interop/` external runner verifies live quic-go Retry and
v2-to-v1 Version Negotiation scenarios end-to-end with those helpers.
Application key updates now
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
parameter rejection. 0-RTT ships with the §5.2 anti-replay tracker,
ALPN/SNI/early-data-context binding, and accepted-vs-rejected
resumption coverage end-to-end against quic-go (see
`docs/hardening-status.md` §5.2 for the full audit). Multipath also
has embedder-driven path CID replenishment, abandoned-path 3x-PTO
retention coverage, and a deterministic two-path transfer stress test.
go-quic-peer single-path, 0-RTT, and path-switch smoke tests are
maintained as interop gates. The first official QUIC interop-runner
gate is also scaffolded under `interop/`: `qns-endpoint` is a
server-side HTTP/0.9 `hq-interop` endpoint with Docker/run-wrapper
support for quic-zig-as-server testing against external clients. See
[`interop/README.md`](interop/README.md) for the current verification
matrix and remaining production gaps.

```sh
mise install
just test
```

## Embed quic-zig as a server

`quic-zig.Server` is the thinnest convenience wrapper that keeps the
embedder in charge of the UDP socket and the wall clock while
quic-zig owns the TLS context, the per-connection state, and the
demultiplexing of incoming datagrams. The full lower-level
`Connection` API is fully supported — `Server` just spares you the
boilerplate of writing it yourself for the common case.

### One-liner: `transport.runUdpServer`

The fastest path to a working QUIC server is the opinionated
`std.Io`-based loop bundled with quic-zig. It binds the UDP socket,
applies `SO_RCVBUF` / `SO_SNDBUF` tuning, drives a 5 ms
receive/feed/poll/tick cadence, and exits cleanly when the supplied
shutdown flag flips. Use this when you want quic-zig to "just run" and
you don't need Retry, version negotiation, or deterministic CIDs.

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
    const protos = [_][]const u8{"hq-interop"};

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
    });
    defer server.deinit();

    try quic-zig.transport.runUdpServer(&server, .{
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
const quic-zig = @import("quic-zig");

pub fn run(
    allocator: std.mem.Allocator,
    sock: anytype, // your UDP socket
    cert_pem: []const u8,
    key_pem: []const u8,
) !void {
    const protos = [_][]const u8{"hq-interop"};

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
            // datagrams. `slot.conn` is the full `*quic-zig.Connection`.
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

## Embed quic-zig as a client

`quic-zig.Client` is the mirror of `quic-zig.Server` for the dialing side.
It builds a client-mode TLS context, generates the random initial
DCID and SCID per RFC 9000 §7.2, calls
`bind`/`setLocalScid`/`setInitialDcid`/`setPeerDcid`/`setTransportParams`
in the right order, and hands back a heap-allocated `*Connection`
that's ready for the first scheduler step. The caller still owns
the UDP socket, the wall clock, and the `Connection` lifecycle.

```zig
const std = @import("std");
const quic-zig = @import("quic-zig");

pub fn dial(
    allocator: std.mem.Allocator,
    sock: anytype, // your UDP socket, already bound
    server_addr: anytype,
    server_name: []const u8,
) !void {
    const protos = [_][]const u8{"hq-interop"};

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
`quic-zig.Session`. Capture them from the client TLS context, serialize
with `Session.toBytes`, then parse with `Session.fromBytes` before the
next client connection:

```zig
var client_ctx = try boringssl.tls.Context.initClient(.{
    .early_data_enabled = true,
});
try client_ctx.setNewSessionCallback(onTicket, store_ptr);

fn onTicket(user_data: ?*anyopaque, session: quic-zig.Session) void {
    var owned = session;
    defer owned.deinit();
    const bytes = owned.toBytes(allocator) catch return;
    saveTicket(user_data, bytes);
}

var resumed = try quic-zig.Session.fromBytes(client_ctx, ticket_bytes);
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
`quic-zig.KeylogCallback`:

```zig
try tls_ctx.setKeylogCallback(onKeylogLine);
```

Application key-update lifecycle events are opt-in through the
connection qlog-style callback:

```zig
conn.setQlogCallback(onQlogEvent, app_state);

fn onQlogEvent(user_data: ?*anyopaque, event: quic-zig.QlogEvent) void {
    _ = user_data;
    if (event.name == .application_write_update_acked) {
        // Translate to qlog JSON, metrics, or test assertions.
    }
}
```

## Production posture

quic-zig ships secure-by-default for the `Server.Config` /
`Client.Config` knobs the hardening guide calls out, but a handful of
production-grade limits are off by default so dev / interop / test
runs aren't burdened with rate-limit tuning. This section lists what's
on without config and what you need to wire up before pointing quic-zig
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
  Embedders that need LB-routable CIDs can opt into
  draft-ietf-quic-load-balancers-21 via `Server.Config.quic_lb`; see
  the dedicated entry in "Off by default" below for the security
  trade-off this introduces.
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
QNS interop but should be set explicitly before exposing quic-zig to
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
- `quic_lb: ?lb.LbConfig = null` — opts every locally-issued SCID
  into [draft-ietf-quic-load-balancers-21][quic-lb] format so an
  external layer-4 load balancer can decode the routing identity
  from any datagram (including post-migration ones with brand-new
  CIDs). **This deliberately inverts the CSPRNG-by-default
  guarantee above:** every minted CID encodes the configured
  `server_id`, and in plaintext mode (no `LbConfig.key`) any on-path
  observer between client and LB can read it. Treat the load
  balancer as the trust boundary. Plaintext mode also auto-enables
  `disable_active_migration` per draft §3 ¶3 (servers without a key
  SHOULD NOT issue extra CIDs via NEW_CONNECTION_ID, which would
  leak `server_id` further). All three encoder modes are wired:
  §5.2 plaintext (no key), §5.4.1 single-pass AES-128-ECB
  (key configured, `server_id_len + nonce_len == 16`), and §5.4.2
  four-pass Feistel (key configured, any other supported length).
  Encrypted modes use a counter-based nonce seeded from the CSPRNG
  so the same nonce is never reused under the same key. Pinned to
  draft revision 21 via `quic_zig.quic_lb_draft_version`; bumping
  is a deliberate scoped change.

  [quic-lb]: https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/

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
- An `AntiReplayTracker` (from `quic-zig.tls.AntiReplayTracker`) if you
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
- [`tests/conformance/README.md`](tests/conformance/README.md) —
  RFC-traceable conformance suite (BCP 14 keywords, `[RFC#### §X.Y]`
  citations). Run with `zig build conformance` or filter via
  `-Dconformance-filter='RFC9000 §17'`. 297 active tests + 44
  visible-debt skips across RFCs 8999 / 9000 / 9001 / 9002 / 9221.
- `hardening-guide.md` — the canonical reference doc quic-zig is
  hardened against.

## What this is

- The QUIC **transport**: streams, datagrams, packet protection, loss
  recovery, congestion control. HTTP/3 is **not** part of quic-zig.
- I/O-decoupled state machine. The library does not own a socket or
  an event loop; the embedder drives `Connection.handle` /
  `Connection.poll` / `Connection.tick` against a monotonic clock.
- Pure Zig for everything that isn't crypto. BoringSSL is called only
  for AEAD seal/open, HKDF, AES/ChaCha header protection, and TLS 1.3
  handshake.

## Scope

In scope for v0.1:
- IETF QUIC v1 transport from RFCs 8999 / 9000 / 9001 / 9002.
- 0-RTT (RFC 9001 §4.5/4.6) — landed end-to-end. Anti-replay tracker,
  early-data-context binding, accept/reject path coverage; see
  `docs/hardening-status.md` §5.2 for the audit.
- Connection migration (RFC 9000 §9) — landed. External soak against
  ngtcp2 / quiche servers beyond H/D is still ongoing; the
  `interop/` runner is the gate.
- Multipath QUIC (draft-ietf-quic-multipath) — tracks
  draft-ietf-quic-multipath-21 (`initial_max_path_id`,
  `multipath_draft_version = 21`). Draft-21 is in the RFC Editor
  queue (IESG-approved as of early 2026); we'll switch from the
  draft pin to the published RFC once the document is assigned an
  RFC number. Wire-format changes between -21 and the RFC are not
  expected.
- QUIC-LB connection-ID generation (draft-ietf-quic-load-balancers) —
  tracks draft-ietf-quic-load-balancers-21 (`quic_zig.lb`,
  `quic_lb_draft_version = 21`). **The IETF draft expired in early
  2026 without progressing past -21**; quic-zig stays pinned at -21
  indefinitely. Codepoints are provisional and may never be
  formally allocated; deployments using QUIC-LB should treat the
  config as a private agreement between server and load balancer.
  Off by default; opt in via
  `Server.Config.quic_lb`. All three encoder modes ship: §5.2
  plaintext, §5.4.1 single-pass AES-128-ECB (`combined == 16`), and
  §5.4.2 four-pass Feistel (any other supported length). Runtime
  rotation via `Server.installLbConfig` (auto-pushes
  NEW_CONNECTION_ID frames to live peers when
  `Server.Config.stateless_reset_key` is set), the §3.1 unroutable
  fallback via `lb.mintUnroutable` plus auto-fallback on nonce
  exhaustion in `Server.mintLocalScid`, and a complete LB-side
  decoder via `lb.decode` covering all three modes. The Retry
  Service was split into a separate IETF draft and is out of scope.
- Alternative Server Address frames
  (draft-munizaga-quic-alternative-server-address) — tracks
  draft-munizaga-quic-alternative-server-address-00
  (`alt_server_address_draft_version = 0`). Codec, transport-
  parameter negotiation, server emit, and a typed client-side
  receive surface ship today. The §6 ALTERNATIVE_V4_ADDRESS /
  ALTERNATIVE_V6_ADDRESS frames and the §4 `alternative_address`
  transport parameter (codepoint `0xff0969d85c`) round-trip through
  `frame.encode` / `frame.decode` and `transport_params.Params`.
  Server emit lives at `Connection.advertiseAlternativeV4Address` /
  `advertiseAlternativeV6Address` — both allocate a fresh, shared,
  monotonically-increasing Status Sequence Number per §6 ¶5 and
  queue the frame for transmission at the application encryption
  level (§7). The API is gated on server role (§4 ¶2) and on the
  peer having advertised `alternative_address = true` (so a
  mis-call doesn't force a peer PROTOCOL_VIOLATION close). The
  receiver surfaces accepted frames via
  `ConnectionEvent.alternative_server_address`, a tagged V4/V6
  payload with the address, port, sequence number, and flag bits;
  §6 ¶5 monotonicity is enforced (duplicate sequences are absorbed
  silently as retransmits, lower sequences are absorbed as out-of-
  order delivery), and the receive arm closes with
  PROTOCOL_VIOLATION when the connection isn't negotiated.
  Clients also close with TRANSPORT_PARAMETER_ERROR (per §4 ¶2) on
  a server-authored `alternative_address` parameter. Embedders
  MUST clear the `alternative_address` field before installing
  peer transport parameters as a 0-RTT context (§4 ¶3). The
  §9 thundering-herd mitigation is plumbed via
  `quic_zig.alt_addr.recommendedMigrationDelayMs(min_ms, max_ms)`
  — a CSPRNG-backed uniform draw embedders fold into their auto-
  migration scheduler. Composable with multipath (§8): an
  `initial_max_path_id`-negotiated client receiving §6 frames
  surfaces them through the same event channel.

Out of scope: HTTP/3, QPACK, Windows, FIPS, ECN, DPLPMTUD, BBR,
performance optimizations. See `CHANGELOG.md` for what has shipped
and `CONTRIBUTING.md` for development workflow.
