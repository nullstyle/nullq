# quiche interop notes

Knowledge base for the three quic-zig × quiche cells that fail in the
2026-05-09 verification matrix. Source-code citations point at
`cloudflare/quiche@master` and `quic-interop/quic-interop-runner@master`
as of 2026-05-10. quic-zig citations are absolute paths in this
worktree.

The three failing cells in scope:

1. **`server × quiche × multiplexing`** — quiche client opens 1999
   streams, gets 1977 responses, the next `conn.send()` returns Done
   with stream data still pending, and the connection idle-times out
   after 30s.
2. **`server × quiche × rebind-addr`** — runner rebinds the quiche
   client's source IP. The runner's pcap analyzer rejects our run with
   `First server packet on new path … did not contain a PATH_CHALLENGE
   frame` even though our 1-RTT packet on the new tuple does carry
   PATH_CHALLENGE. The fix that works for `quic-go` and `ngtcp2` does
   not help here.
3. **`client × quiche × rebind-addr`** — quic-zig client connects to
   quiche server, runner rebinds the client's source IP, transfer
   stalls past the 60s test deadline.

---

## 1. quiche topography

quiche is a 9518-line single-file `quiche/src/lib.rs` plus
sibling modules. Path validation lives in `quiche/src/path.rs`
(1373 lines). Stream tracking lives in `quiche/src/stream/mod.rs`.

- `Connection::send` ([lib.rs:3901][q-send]) — public entry; calls
  `send_single` per coalesced packet.
- `Connection::send_single` ([lib.rs:4133][q-send-single]) — builds one
  packet at one encryption level. Stream loop at [lib.rs:5198–5308][q-stream-loop].
- `Connection::recv` ([lib.rs:2856][q-recv]) — public entry; for the
  client, line 2882–2891 silently drops packets from an unknown server
  address.
- `Connection::on_peer_migrated` ([lib.rs:9127][q-on-peer-migrated]) —
  server-side when client migrates.
- `Connection::get_or_create_recv_path_id` ([lib.rs:8963][q-get-or-create-path]) —
  resolves `(info.to, info.from)` to a path id; creates a fresh path
  with `request_validation()` armed when the 4-tuple is unseen.
- `Connection::migrate` ([lib.rs:7191][q-migrate]) — client-side active
  migration; only callable as client.
- `Path::on_response_received` ([path.rs:425][q-on-response]) —
  validates a path. **Requires `max_challenge_size >= MIN_CLIENT_INITIAL_LEN`
  (1200 bytes) before the path is `Validated`.**
  ([lib.rs:443][q-min-initial-len]).
- `MAX_PROBING_TIMEOUTS = 3` ([lib.rs:496][q-max-probe-timeout]) —
  quiche gives up on a path after three lost probes.

[q-send]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L3901
[q-send-single]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L4133
[q-stream-loop]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L5198-L5308
[q-recv]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L2856
[q-on-peer-migrated]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L9127
[q-get-or-create-path]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L8963
[q-migrate]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L7191
[q-on-response]: https://github.com/cloudflare/quiche/blob/master/quiche/src/path.rs#L425
[q-min-initial-len]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L443
[q-max-probe-timeout]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L496

---

## 2. `server × quiche × multiplexing`

### What the matrix shows

- Run dir: `/Users/nullstyle/prj/ai-workspace/quic-zig/interop/logs.server-final2/quic-zig_quiche/multiplexing/`
- Quiche client log (`client/log.txt`):
  - 19 `[ERROR quiche_apps::common] failed to send request Done` warnings
    in the first 200 ms (lines 514, 1612, 3966, …) — these are the
    quiche client app retrying after `stream_send` returned `Done`.
  - 1977 streams reach `quiche_apps::common] stream X has 32 bytes
    (fin? true)` (the 32-byte file body successfully delivered).
  - At line 42905: `idle timeout expired`.
  - Final stats: `recv=2666 sent=3039 lost=232 retrans=232
    sent_bytes=170083 recv_bytes=294917`.

So 22 streams' 32-byte responses never reach the quiche client.

### Quiche's send-side scheduler (what we need to feed)

Quiche keeps two intrusive RBTrees keyed by `StreamPriorityKey`:
**writable** and **flushable**, with `Default::default()` setting
`urgency = 127, incremental = true`
([stream/mod.rs][q-stream-mod]). The flushable set is populated when
`stream.send.write` enqueues bytes ([lib.rs:6112–6119][q-mark-flushable]).

The send loop in `send_single` packs **at most one STREAM frame per
packet**, with a comment that says exactly that
([lib.rs:5198][q-one-stream]):

```rust
// Create a single STREAM frame for the first stream that is flushable.
…
while let Some(priority_key) = self.streams.peek_flushable() {
    …
    if !stream.is_flushable() {
        self.streams.remove_flushable(&priority_key);
    } else if stream.incremental {
        // Shuffle the incremental stream to the back of the queue.
        self.streams.remove_flushable(&priority_key);
        self.streams.insert_flushable(&priority_key);
    }
    …
    break;
}
```

The break on line 5306 is reached unconditionally outside the
`#[cfg(feature = "fuzzing")]` block, so quiche stops at one stream per
packet. With 1999 streams that means quiche needs ≥1999 outbound
packets to drain the GETs.

`Error::Done` is returned by `stream_send` at
[lib.rs:6062–6074][q-done]: it fires when `tx_cap == 0` (the
combination of conn-level flow control and the congestion controller's
`bytes_in_flight`/`cwnd` budget). The quiche client's apps layer
treats `Done` as "retry next tick" ([common.rs:455–462][q-app-done]),
re-attempts on the next loop iteration, and eventually opens 1999
streams.

[q-stream-mod]: https://github.com/cloudflare/quiche/blob/master/quiche/src/stream/mod.rs
[q-mark-flushable]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L6112-L6119
[q-one-stream]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L5198-L5306
[q-done]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L6062-L6074
[q-app-done]: https://github.com/cloudflare/quiche/blob/master/apps/src/common.rs#L455-L462

### What quic-zig is currently doing (server side)

- Stream send loop in `pollLevelOnPath`:
  `src/conn/state.zig:6840–6886` (`// 3b) STREAM frames`).
- Iteration is `var s_it = self.streams.iterator()` — this is
  `std.AutoHashMapUnmanaged.iterator()` over the open-addressing hash
  table. Iteration order is **insertion-order-shuffled** by the hash
  table's slot mapping; for monotonically increasing stream IDs (the
  quiche client opens 0, 4, 8, 12, …, 7996) the order is approximately
  hash-sorted, but stable across calls only as long as the table
  doesn't grow.
- Per-packet cap: `var sent_chunks: [sent_packets_mod.max_stream_keys_per_packet]SentStreamChunk`
  with `max_stream_keys_per_packet = 32`
  (`src/conn/sent_packets.zig:16`). So we pack up to **32 stream
  chunks per packet** vs. quiche's one-per-packet — that's not the
  problem.
- `peekChunk` is `s.send.peekChunk(budget)` returning `?Chunk`
  (`src/conn/send_stream.zig:239`); returns `null` when nothing is
  ready (already FIN'd, flow-control-blocked, etc.). The outer loop
  treats `null` with a `continue`, not a `break`.
- `canSend` in `src/conn/state.zig:5826–5829` walks every stream and
  returns `true` if any has `hasPendingChunk()`, so the connection
  *would* re-poll while data is queued.

### Hypothesised gap

Three plausible causes; the implementation team should test them
in this order:

#### Hypothesis 2A — `streamFlowNewBytes` consumes connection-flow credit it should not

Look at `src/conn/state.zig:6850–6886`:

```zig
var planned_conn_new_bytes: u64 = 0;
if (… (lvl == .application or lvl == .early_data)) {
    var s_it = self.streams.iterator();
    while (s_it.next()) |entry| {
        if (sent_chunk_count >= sent_chunks.len) break;
        const s = entry.value_ptr.*;
        const stream_overhead: usize = 25;
        if (max_payload <= pl_pos + stream_overhead) break;
        const budget = max_payload - pl_pos - stream_overhead;
        const raw_chunk = s.send.peekChunk(budget) orelse continue;
        const chunk = (try self.limitChunkToSendFlowAfterPlanned(
            s, raw_chunk, planned_conn_new_bytes,
        )) orelse continue;
        …
        planned_conn_new_bytes +|= streamFlowNewBytes(s, chunk);
    }
}
```

If `limitChunkToSendFlowAfterPlanned` decides the conn-level send-flow
budget for this packet is exhausted by the previous N streams, **it
returns `null`** and we `continue` — but a `continue` here advances
the iterator past the **current stream**, leaving the chunk on the
stream's send queue. The next packet's iterator starts again from the
hash-table head, which (for an unchanged hash table) is the same head.
Net effect: when the conn-flow budget is regularly tight, the same
"head" streams drain first; "tail" streams (high stream IDs) get
served only when conn-flow opens up faster than head streams can
refill.

This isn't necessarily a quiche-specific bug — it would show on any
flow-tight peer — but quiche's relentless 1999-stream pipeline is the
most aggressive case in the matrix, and our `initial_max_data = 16
MiB` (`endpoint_connection_receive_window` in
`interop/qns_endpoint.zig:60`) is what *we* advertise; what the peer
advertises to us bounds **send-side** flow-control and is what
`limitChunkToSendFlowAfterPlanned` checks.

Quiche's client-side TP block from `client/log.txt:20`:
`initial_max_data: 16777216, initial_max_stream_data_bidi_remote:
16777216`. So conn-flow shouldn't be the constraint — but
`limitChunkToSendFlowAfterPlanned` accounts for **`tx_data` we've
already sent**. After 1977 × ~32 byte responses (~63 KiB) + retransmit
of 232 packets × 1350 bytes (~313 KiB), we have hundreds of KiB
in flight — well below 16 MiB. So flow control alone is unlikely to
strand 22 streams.

#### Hypothesis 2B — congestion-control budget per stream + 32-stream cap interaction

`congestion_blocked` (around `src/conn/state.zig:6851`) gates the
*entire* stream loop. If congestion is blocked we emit zero stream
frames this poll. If congestion clears slowly while the iterator is
biased towards low stream IDs, the high IDs starve.

The quiche client log shows `cwnd=17963, lost=232, retrans=232,
rtt=94ms`. With cwnd ≈ 18 KiB and ~1350 byte MTU, that's 13 packets
in flight at peak. Each STREAM frame has 25-byte overhead + 32 bytes
data = 57 bytes; 23 streams fit per 1350-byte MTU but the per-packet
chunk cap is 32, so realistically 23 × 13 = 299 streams per cwnd.
Over the 30s idle window between the last response and timeout, that's
**plenty of capacity** to drain 22 streams — yet they're stuck.

So congestion control is *not* the wall. The 22 streams are stuck
because the iterator never reaches them, OR because they were never
flushable to begin with.

#### Hypothesis 2C — peer-initiated stream credit return is racy with the 1999-stream burst (most likely)

`maybeQueueBatchedMaxStreams` in `src/conn/state.zig:3560–3584`
fires MAX_STREAMS once the peer has consumed 1/4 of the current
limit (watermark `(current * 3) / 4`). Initial cap is 1000
(`endpoint_bidi_stream_limit` in
`interop/qns_endpoint.zig:76`). So:

- After quiche opens stream 750 of 1000, we queue MAX_STREAMS(1000 +
  batch) where batch = `@max(16, 1000)` = 1000 → MAX_STREAMS(2000).
- That MAX_STREAMS fires from the next `pollLevel` poll. quiche reads
  it, opens streams 1000–1998.
- After quiche opens stream ≥ 1500, we'd queue MAX_STREAMS(2000 +
  1000) = MAX_STREAMS(3000) — **but quiche only opens 1999 streams,
  exactly bounded by the 2000 limit minus its
  `peer_streams_blocked_bidi` rate-limit**.

The 2000-stream limit means streams 0, 4, 8, …, 7996 are valid;
quiche opens 1999 of those (it deliberately doesn't open all 2000 —
see [common.rs:455][q-app-done]). The 22 missing responses are not
about MAX_STREAMS — quiche believed it could open all 1999 it tried.

Under the burst, the quiche client makes 1999 requests with `fin =
true`. Each is one STREAM frame + FIN. quic-zig server gets the
request, opens the stream as peer-initiated, server app responds via
`streamSend(id, body, fin = true)`. **The server-side stream send
queue holds the 32-byte body**. So the question is: does our send
loop visit every one of the 1999 streams before the connection idles?

The likely-stuck path is: after our `pollDatagram` returns null for
30s, quiche's idle timer (30s) fires. That means we returned `null`
from `pollDatagram` while `canSend()` was still `true` (or `canSend`
itself missed something). Look at the iterator: each `pollLevelOnPath`
runs from the beginning of `streams.iterator()`. Hash iteration order
is *deterministic* for a stable hash table, so the same head streams
get visited first every time. If those head streams have nothing
queued (already drained, or peer hasn't closed our recv side yet),
we `continue`. We might continue all the way through the table on
some polls, but only 32 chunks fit per packet. The 22 stranded streams
are likely those whose hash slot fell *after* a "wall of empty heads"
that exhausted our packet budget on a prior poll.

**More likely**: the stuck streams are ones where `peekChunk` returns
null because **the stream's send buffer is empty** — meaning the
server-side application code never queued the response. That points
at a request-handler bug, not a transport bug. Test:

- Add a temporary trace at `src/conn/state.zig:6859` (`peekChunk`
  returned null) tagged with the stream id, run the matrix, and grep
  the qlog for stuck stream IDs to see whether they ever got
  `streamSend` called.

The qns server's request-dispatch path is in
`interop/qns_endpoint.zig` — search for where the HTTP/0.9 GET response
is queued. If the dispatch is single-threaded and serialised on
inbound, with 1999 inbound requests in a single poll cycle, the
dispatch may give up after some bound. Check
`endpoint_request_handler_max_queue_depth` or similar.

#### Open question — fuzzing path

quiche's `#[cfg(feature = "fuzzing")]` at
[lib.rs:5300–5304][q-stream-loop] coalesces multiple streams per
packet:

```rust
#[cfg(feature = "fuzzing")]
// Coalesce STREAM frames when fuzzing.
if left > frame::MAX_STREAM_OVERHEAD {
    continue;
}
```

The interop runner uses release builds without the fuzzing feature, so
this is **not** active in our matrix runs.

### Relevant quiche issues / PRs

- [#2241][i-2241] "stream_writable for new streams" (open) — surfaces
  surrounding behaviour, not a fix.
- [#2455][i-2455] "Fix leaked StreamCtx for bodyless H3 requests"
  (open) — H3-only.
- [#2253][i-2253] "conn.recv() took 90% cpu" (open) — different
  symptom, may share root cause if iteration is degenerate.

No exact-match issue for "send returns Done with flushable streams
remaining". This may be a quic-zig bug, not a quiche-side bug.

[i-2241]: https://github.com/cloudflare/quiche/issues/2241
[i-2455]: https://github.com/cloudflare/quiche/pull/2455
[i-2253]: https://github.com/cloudflare/quiche/issues/2253

---

## 3. `server × quiche × rebind-addr`

### What the matrix shows

- Run dir: `/Users/nullstyle/prj/ai-workspace/quic-zig/interop/logs.server-final2/quic-zig_quiche/rebind-addr/`
- `output.txt` contains the smoking-gun line:

  > `2026-05-09 19:50:41,099 First server packet on new path
  > (('193.167.100.100', 443), ('193.167.0.224', 59022)) did not
  > contain a PATH_CHALLENGE frame`
  > `Layer QUIC: … Packet Type: Handshake (2)`
  > `Destination Connection ID: 653103db193bbcdfd3da2081cddd40f83d3d9d8b`
  > `Payload: ACK Frame Type: ACK …`

- The packet flagged as "first server packet on new path" is a
  **Handshake-level ACK**, not a 1-RTT packet.
- Server-side qlog (`server/qlog/quic-zig-server.jsonl`) has 1
  `migration_path_failed` and 3 `migration_path_validated` events —
  one rebind failed, three later rebinds completed PATH_CHALLENGE/
  PATH_RESPONSE successfully. The failed one is likely the very
  first.
- The same testcase against `quic-go` and `ngtcp2` clients **passes**
  (`logs.server-final2/quic-zig_quic-go/rebind-addr/output.txt`,
  `logs.server-final2/quic-zig_ngtcp2/rebind-addr/output.txt`).

### What the runner is checking

The runner (`quic-interop/quic-interop-runner` master HEAD) implements
the rebind check in
[`testcases_quic.py:996–1057`][r-rebind-check]:

```python
tr_server = self._server_trace()._get_packets(
    self._server_trace()._get_direction_filter(Direction.FROM_SERVER) + " quic"
)
…
for p in tr_server:
    cur = self._path(p)
    if last is None: last = cur; continue
    if last != cur and cur not in paths:
        paths.add(last)
        last = cur
        # Packet on new path, should have a PATH_CHALLENGE frame
        if hasattr(p["quic"], "path_challenge.data") is False:
            …
            return TestResult.FAILED
```

`_get_direction_filter(FROM_SERVER) + " quic"` matches **every** QUIC
packet from the server, including coalesced Handshake-level packets.
`_path(p)` keys on UDP `(srcip, srcport, dstip, dstport)`. So when the
runner sees the **first packet on a new (server-src/dst, client-src/dst)
4-tuple**, that packet must contain `path_challenge.data`.

The runner check is acknowledged as overly strict in
[interop-runner issue #424][r-issue-424] / [PR #426][r-pr-426] (still
open as of 2026-05-10). The proposed fix is "PATH_CHALLENGE before any
non-probing packet", but the master branch the matrix uses still
enforces the strict check.

[r-rebind-check]: https://github.com/quic-interop/quic-interop-runner/blob/master/testcases_quic.py#L996-L1057
[r-issue-424]: https://github.com/quic-interop/quic-interop-runner/issues/424
[r-pr-426]: https://github.com/quic-interop/quic-interop-runner/pull/426

### What quic-zig is currently doing

- `pollDatagram` in `src/conn/state.zig:5850–5907` builds a coalesced
  datagram in level order **Initial → 0-RTT → Handshake → Application**.
- In `pollLevelOnPath` for the application level
  (`src/conn/state.zig:6293–6304`), we explicitly emit PATH_CHALLENGE
  *first* on a freshly-migrated path via the `emit_path_challenge_first`
  flag.
- The PATH_CHALLENGE-first machinery (`src/conn/state.zig:6087–6128`)
  triggers when `pending_migration_reset` AND `validator.status ==
  .pending` AND the queued frame is for THIS app_path.
- The 1-RTT short header MUST be the LAST packet in a coalesced
  datagram per RFC 9000 §12.2 — and it is. So if the server has any
  pending Handshake-level frames (e.g. an ACK for a client's Handshake
  packet that arrived recently), the resulting datagram is
  `[Handshake-ACK][1-RTT-with-PATH_CHALLENGE]`. The runner sees the
  Handshake packet as the first on the new tuple.

### Gap

We do not discard server Handshake keys after handshake confirmation.
A `grep -rE "discardHandshake|drop.*[Hh]andshake.*[Kk]ey"` over
`src/conn/` and `src/tls/` returns zero hits. We only discard Initial
keys (`src/conn/state.zig:8541`, `discardInitialKeys` after
`handshakeDone()`).

Per RFC 9001 §4.9.2 ("Discarding Handshake Keys"), the server SHOULD
discard Handshake keys as soon as it has confirmed the handshake
(server-side: when it receives an acknowledgement of any Handshake
packet, OR upon receiving the first 1-RTT packet from the client).
Discarding them releases the Handshake-level send queue: any pending
Handshake-level ACK is dropped, the next datagram can lead with
the 1-RTT short header, and the runner check passes.

The other passing peers — `quic-go` and `ngtcp2` clients — trigger the
runner-flagged path against our server too, but in those runs our
server has no Handshake-level pending bytes by the time the rebind
fires (client-side ACK timing differs), so the coalesced datagram is
1-RTT-only and PATH_CHALLENGE leads the wire. Quiche's ACK behavior
keeps a Handshake-level ACK pending exactly long enough to land in
the same `pollDatagram` as the PATH_CHALLENGE response.

### Concrete fix candidates (ranked)

1. **Discard Handshake keys after handshake confirmation, server-side
   (RFC 9001 §4.9.2).** Mirrors the existing `discardInitialKeys`
   call site at `src/conn/state.zig:8541`. After the call to
   `discardInitialKeys`, also call a new
   `discardHandshakeKeys` (server-only — clients discard on receipt
   of HANDSHAKE_DONE).
2. **Even with handshake keys present, gate Handshake-level emission
   on a freshly-migrated path.** When `emit_path_challenge_first` is
   true, refuse to emit Handshake-level packets in this datagram —
   only `pollLevel(.application, …)` runs. The Handshake bytes get
   emitted on the *next* datagram. RFC-compatible: the only thing in
   our Handshake send queue post-handshake is an ACK, which is not
   ack-eliciting and may be deferred.
3. **Drain Handshake-level pending state synchronously when we
   transition to "freshly migrated" in `handlePeerAddressChange` /
   `recordAuthenticatedDatagramAddress`.** Force a Handshake-level
   ACK flush before queuing PATH_CHALLENGE so the next poll is
   1-RTT-only. Risky: relies on Handshake-level ACK actually being
   ready to send.

Option (1) is the cleanest and aligns with RFC 9001. Embedders running
quic-zig in production will benefit from key memory reduction too.

---

## 4. `client × quiche × rebind-addr`

### What the matrix shows

- Run dir: `/Users/nullstyle/prj/ai-workspace/quic-zig/interop/logs.client-final2/quiche_quic-zig/rebind-addr/`
- The simulator log shows the client's source IP rotating every 5s:
  `1s: rebinding 193.167.0.100:55730 -> 193.167.0.224:59022`,
  `6s: rebinding 193.167.0.224:59022 -> 193.167.0.71:39968`, etc.
- After the second rebind at 6s, the simulator drops every packet
  destined for the *previous* client binding:
  `unknown binding for destination 193.167.0.71:39968, dropping
  packet`. That's quiche server's old reply path; nothing reaches our
  client.
- Our client (qns) keeps emitting 1-RTT packets to the server (the
  log spam at the top of `output.txt`). Every client outbound becomes
  a probe of the new tuple; quiche server ought to detect and validate.
- The cell exits on the runner's 60s deadline:
  `2026-05-09 20:01:33,578 Test failed: took longer than 60s.`
- Client-side qlog at `client/qlog/quic-zig-client.jsonl` shows the
  same migration-event mix as case 3.

### What quiche server expects

Quiche server's `recv` flow ([lib.rs:2856–2904][q-recv]):

```rust
let recv_pid = self.paths.path_id_from_addrs(&(info.to, info.from));
if let Some(recv_pid) = recv_pid {
    // existing path; bump verified_peer_address budget if not yet validated
} else if !self.is_server {
    // CLIENT-only branch
    return Ok(len);
}
```

Server-side, an unknown `(info.to, info.from)` *falls through* to
`recv_single` → eventually `get_or_create_recv_path_id`
([lib.rs:8963][q-get-or-create-path]):

```rust
let (in_scid_seq, mut in_scid_pid) =
    ids.find_scid_seq(dcid).ok_or(Error::InvalidState)?;
…
// New 4-tuple, CID was used by another path
if let Some(in_scid_pid) = in_scid_pid {
    // notify ReusedSourceConnectionId
}
let mut path = path::Path::new(info.to, info.from, …);
path.max_send_bytes = buf_len * self.max_amplification_factor;
path.active_scid_seq = Some(in_scid_seq);
path.request_validation();              // ← arms PATH_CHALLENGE
let pid = self.paths.insert_path(path, self.is_server)?;
ids.link_scid_to_path_id(in_scid_seq, pid)?;
```

Critical pre-conditions for quiche to **create the new path
successfully**:

1. `find_scid_seq(dcid)` must succeed. The DCID in our outbound packet
   is the server's SCID we last used; quiche's `ids` table maps SCIDs
   to sequence numbers and path ids.
2. The packet must decrypt cleanly with that SCID's keys (1-RTT keys
   are connection-wide, so this works as long as the connection is
   alive).
3. **Anti-amplification**: until path is validated, quiche server can
   send at most `max_send_bytes = buf_len * 3` bytes back. Each fresh
   client datagram refreshes the budget.

After path creation, on the next `send_single` quiche server picks
this new path id (because `request_validation()` set
`probing_required()` true) and emits PATH_CHALLENGE
([lib.rs:9072–9091][q-get-send-path]):

```rust
if self.is_established() {
    let mut probing = self.paths.iter()
        .filter(|(_, p)| from.is_none() || Some(p.local_addr()) == from)
        .filter(|(_, p)| to.is_none() || Some(p.peer_addr()) == to)
        .filter(|(_, p)| p.active_dcid_seq.is_some())
        .filter(|(_, p)| p.probing_required())
        .map(|(pid, _)| pid);
    if let Some(pid) = probing.next() { return Ok(pid); }
}
```

Then `Path::on_response_received` ([path.rs:425–457][q-on-response]):

```rust
self.promote_to(PathState::ValidatingMTU);
if self.max_challenge_size >= crate::MIN_CLIENT_INITIAL_LEN {
    self.promote_to(PathState::Validated);
    return true;
}
self.request_validation();   // re-probe — the response packet was too small
```

[q-get-send-path]: https://github.com/cloudflare/quiche/blob/master/quiche/src/lib.rs#L9072-L9091

So quiche keeps the path in `ValidatingMTU` until it sees a
PATH_RESPONSE from a 1200+ byte datagram. On a path it just probed,
the **first PATH_RESPONSE we send must be in a 1200-byte padded
datagram**. RFC 9000 §8.2.1 ¶3 actually requires this (the *probing*
side pads the PATH_CHALLENGE; we, the *responder*, get to choose, but
quiche treats anything smaller as a non-validation).

### What quic-zig is currently doing (client side)

- `interop/qns_endpoint.zig:1876–1883` — every tick after handshake we
  call `queueClientConnectionIds` to top up our peer-issued SCIDs to
  the server's `active_connection_id_limit`. The fix that worked for
  `quic-go` (per-tick top-up) is already in place.
- The qns client doesn't *actively* trigger `migrate()` for
  `rebind-addr`. The simulator silently rewrites our source IP in
  L3, so our `getsockname()` doesn't change and our connection keeps
  using the same socket. From quic-zig's perspective there is no
  client-side migration event.
- For peer-initiated rebinds quiche server validates the new path via
  PATH_CHALLENGE. We process it in
  `src/conn/state.zig:5136–5210`'s `recordAuthenticatedDatagramAddress`
  → `handlePeerAddressChange` → `queuePathChallengeOnPath`. The
  handler queues a PATH_RESPONSE on the new tuple and emits it on the
  next poll.
- PATH_RESPONSE emission lives in `src/conn/state.zig` (search
  `path_response`); it does NOT go through `emit_path_challenge_first`
  (that's PATH_CHALLENGE only).

### Why the 60s timeout fires

Our client's outbound datagrams **must** reach the server's new path,
the server must reply, and the reply must reach our client. The
simulator's `unknown binding for destination 193.167.0.71:39968`
indicates the sim drops packets destined to the **previous** client
binding *for tens of seconds*. Server replies before its
`get_or_create_recv_path_id` fires are lost.

Once the server's first packet from a *new* `(server_local, our_new_addr)`
is queued, the simulator passes it through to our new addr. Our
client receives it on the same socket fd (the kernel re-routes via the
socket's bound port + the new IP), processes the PATH_CHALLENGE,
emits PATH_RESPONSE.

**The likely failure mode** is one of:

#### Hypothesis 4A — quiche server's PATH_RESPONSE arrives, but we don't echo PATH_CHALLENGE in a 1200-byte packet

Our PATH_RESPONSE emission packs into the smallest packet the layer
can produce. If the runner / quiche pcap shows we replied with a
small (≤200 byte) packet, quiche would re-issue PATH_CHALLENGE and
the path stays in `ValidatingMTU`. The runner doesn't fail this case
explicitly, but the connection stalls because:

- Our server-bound 1-RTT packets continue to use the **active path's**
  destination, which is the OLD server local addr until quiche
  finishes `set_active_path(new_pid, …)`.
- quiche only calls `set_active_path` from `on_peer_migrated`
  (server-side), gated on `recv_pid != active_path_id` AND
  `largest_rx_non_probing_pkt_num == pn` ([lib.rs:3803–3808][q-server-mig]):

  ```rust
  if self.is_server && recv_pid != active_path_id &&
     self.pkt_num_spaces[epoch].largest_rx_non_probing_pkt_num == pn {
      self.on_peer_migrated(recv_pid, self.disable_dcid_reuse, now)?;
  }
  ```

  So the server only flips active path when it receives a
  **non-probing** packet on the new path. Our client's STREAM frames
  on the new path are non-probing → quiche flips. Good.

- But **before** the flip, quiche replies on the OLD path. The sim
  drops those. The timing window where this matters is between
  "first new-tuple packet arrives at server" and "quiche calls
  `set_active_path`". This is ≤ 1 RTT.

#### Hypothesis 4B — quiche server retires our seq=0 SCID and our top-up is too late (most likely after 4A)

Although `endpoint_active_connection_id_limit = 2`
(`interop/qns_endpoint.zig:78`), our client uses 8-byte SCIDs and we
only top up *after* `handshakeDone()`. Looking at the qns client log,
the first `[diag-send] … Hsk` lands at `t=2089416us` with the first
1-RTT at the same timestamp. The first rebind is at 1s of *runner
wallclock*, roughly ~1s after handshake. So the top-up has fired
once by the time of the first rebind, putting seq=1 in our peer-issued
SCID pool.

Quiche server retires seq=0 not eagerly (unlike quic-go) — it has
no `RetireConnectionId{seq=0}` on its first packet. Look for retires:

```text
$ grep -i "retire" interop/logs.client-final2/quiche_quic-zig/rebind-addr/output.txt
(no hits)
```

So the SCID pool isn't the problem in the quiche-server case. But on
the **second** rebind at 6s, quiche server has already used our
seq=1 SCID for path id 1. When we rebind again, the server needs
seq=2. By 6s our top-up has fired enough times to have seq=2 ready
(`endpoint_client_cid_max_lifetime_count = 8`,
`interop/qns_endpoint.zig:104`).

#### Hypothesis 4C — Handshake-level packet stuck on old binding (most likely)

The qns client output shows:

```
client  | [diag-send] t=16814382us len=95 Hsk  b0=0xe9
…
client  | [diag-send] t=31719097us len=95 Hsk  b0=0xe5
```

These are **client-side Handshake-level packets** sent at 16s and 31s
of *test wallclock* (~14s and ~29s after the simulator started). They
are tiny (95 bytes) — almost certainly retransmits of a Handshake
CRYPTO frame or a Handshake-level ACK. The simulator's "unknown
binding" drops are recurrent at every rebind. If one of these
client-side Handshake packets gets stuck at the old binding (because
the kernel routes by socket bind, not by dest), quiche server will
believe the client is still alive on the old tuple, retry there, and
hit the simulator's drop.

The same root cause as case 3: **we never discard Handshake keys
after the handshake confirms**. The client side has a different
trigger (Hsk sends quiche client thinks have to wait for ack), but
both fall to the same fix.

### Concrete fix candidates

1. **Discard Handshake keys after `HANDSHAKE_DONE` (client) /
   acknowledgment of Handshake packet (server).** Eliminates the
   retransmit at 16s / 31s. Once Handshake send queue is empty, the
   only outbound traffic is 1-RTT, which gets sim-rewritten into the
   new client tuple on every send.
2. **Confirm PATH_RESPONSE emission pads to 1200 bytes when echoing
   a probing PATH_CHALLENGE.** RFC 9000 §8.2.1 ¶3 motivates the
   challenge-side pad; the responder *can* echo small, but quiche's
   `MIN_CLIENT_INITIAL_LEN` gate at
   [path.rs:445–453][q-on-response] keeps the path in `ValidatingMTU`
   if our response is small. Padding the response to 1200 bytes makes
   quiche promote to `Validated` on the first PATH_RESPONSE.

Look for our PATH_RESPONSE pad at `src/conn/state.zig`'s `pad_to`
computation in `pollLevelOnPath` (around line 6944):

```zig
.pad_to = if (probe_target_size) |sz| @as(usize, sz)
          else if (emit_path_challenge_first)
              @min(default_mtu, dst.len)
          else 0,
```

The pad is **only** when we lead with PATH_CHALLENGE. When we echo
PATH_RESPONSE, we don't pad. Quiche's
`MIN_CLIENT_INITIAL_LEN` rule means we should — at least when the
incoming PATH_CHALLENGE was on a path quiche treats as un-validated.

3. **Drive an explicit `migrate()` from the qns client when we
   observe the simulator-induced rebind.** Detect via
   `recvfrom` returning packets from an unexpected server-side
   destination, or simply detect via *prolonged* outbound silence with
   no inbound. Then call `beginClientActiveMigration`. This is the
   nuclear option — but the runner explicitly tests *passive*
   rebinding (the client doesn't migrate; the network does), so this
   subverts the test semantics.

Option (1) + (2) are the right fixes.

---

## 5. What quic-zig should change

For the parallel teammate agents picking up each cell:

### Cell A — `server × quiche × multiplexing`

Owner-agent should:

- Add per-stream `peekChunk-returned-null` qlog tracing in
  `src/conn/state.zig:6859`.
- Verify against the qlog whether the 22 stuck stream IDs ever had
  `streamSend` called by the qns server's request handler. If not,
  the bug is in `interop/qns_endpoint.zig`'s request dispatcher (queue
  depth, blocking on a backpressured channel, or single-tick request
  cap).
- If they were sent but stranded: rotate the stream-iterator start
  position by a per-poll cursor (round-robin) so high-id streams
  cannot starve when the iterator caps at 32 chunks/packet AND the
  hash table iteration order is biased.

### Cell B — `server × quiche × rebind-addr`

Owner-agent should:

- Implement `discardHandshakeKeys` (server-side) parallel to the
  existing `discardInitialKeys` at `src/conn/state.zig:8541–8543`.
  Trigger conditions: server has received an ACK acknowledging any
  Handshake-level packet OR has received any 1-RTT packet from the
  client (RFC 9001 §4.9.2). After discard, the Handshake-level
  outbox/`crypto_retx`/`pn_spaces[handshake]` should reject further
  emission.
- Add a regression test in `src/conn/_state_tests.zig` that simulates
  a peer-initiated rebind while a Handshake-level ACK is pending on
  the server, and asserts the next emitted datagram has only a 1-RTT
  packet.

### Cell C — `client × quiche × rebind-addr`

Owner-agent should:

- The same `discardHandshakeKeys` change (now client-side: trigger on
  HANDSHAKE_DONE receipt or first 1-RTT round-trip). This is the
  unblocker.
- Pad PATH_RESPONSE to ≥1200 bytes (`MIN_CLIENT_INITIAL_LEN`) when
  echoing a probing PATH_CHALLENGE on a path the peer hasn't
  validated. Lookup site: the `pad_to` block in `pollLevelOnPath`
  around `src/conn/state.zig:6944`.
- Add a regression test that drives the post-handshake
  client→server flow under simulated source-addr rewrite and
  asserts the connection survives 4 consecutive rebinds.

---

## 6. Cross-cell summary

| Cell | Root cause | Fix focus | File / line |
|---|---|---|---|
| A: server × quiche × multiplexing | Stream iterator starvation OR qns request-dispatch backlog | Per-poll round-robin cursor in stream loop; instrument qns dispatcher | `src/conn/state.zig:6840–6886`, `interop/qns_endpoint.zig` |
| B: server × quiche × rebind-addr | We never discard server Handshake keys; `[Hsk-ACK][1-RTT-PATH_CHALLENGE]` coalesced datagram fails runner check | Implement `discardHandshakeKeys` after handshake confirmation | `src/conn/state.zig:8541` (mirror site) |
| C: client × quiche × rebind-addr | We never discard client Handshake keys + PATH_RESPONSE not padded to 1200 | Same key-discard fix + PATH_RESPONSE pad | `src/conn/state.zig:8541` + `:6944` |

Both rebind cells share the Handshake-key-discard fix. Cell B is
purely the coalescing artifact; Cell C compounds with the
PATH_RESPONSE pad gap.

The runner's `PATH_CHALLENGE-first-on-new-path` check is
acknowledged as too strict
([interop-runner #424][r-issue-424] / [#426][r-pr-426]); upstreaming
the relax is also a long-term option but not actionable inside this
worktree.
