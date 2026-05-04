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
`TLS_CHACHA20_POLY1305_SHA256`. 0-RTT now has early STREAM/DATAGRAM
transport plumbing plus accepted and rejected go-quic-peer resumption
smokes, while deeper mismatch/loss hardening still needs work. Multipath
also has embedder-driven path CID replenishment, abandoned-path 3x-PTO
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
  an event loop; the embedder drives `handleIncoming` /
  `pollOutgoing` against a `Clock`.
- Pure Zig for everything that isn't crypto. BoringSSL is called only
  for AEAD seal/open, HKDF, AES/ChaCha header protection, and TLS 1.3
  handshake.

## Scope

In scope for v0.1:
- IETF QUIC v1 transport from RFCs 8999 / 9000 / 9001 / 9002.
- 0-RTT (RFC 9001 §4.5/4.6) — Phase 8, initial implementation landed.
- Connection migration (RFC 9000 §9) — Phase 9.
- Multipath QUIC (draft-ietf-quic-multipath) — Phase 10. Tracks the
  draft-ietf-quic-multipath-21 surface (`initial_max_path_id`,
  `multipath_draft_version = 21`); expect API churn until the spec is
  published as an RFC.

Out of scope: HTTP/3, QPACK, Windows, FIPS, ECN, DPLPMTUD, BBR,
performance optimizations. See the non-goals and Phase 11 sections
of `INITIAL_PROMPT.md`.
