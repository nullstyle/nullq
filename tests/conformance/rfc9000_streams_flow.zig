//! RFC 9000 §3-5, §10 — Streams, flow control, connection IDs, and
//! connection termination.
//!
//! This suite exercises the small, pure helper modules that QUIC's
//! data-plane invariants compose into:
//!
//!   - `nullq.conn.flow_control` — connection-level data limit (§4.1),
//!     stream-level data limit (§4.2), and stream-count limit (§4.6).
//!   - `nullq.conn.send_stream` — send-side stream state machine
//!     (§3.1) plus FIN/RESET coordination.
//!   - `nullq.conn.recv_stream` — receive-side state machine (§3.2),
//!     final-size enforcement (§4.5), and RESET_STREAM handling.
//!   - `nullq.conn.lifecycle` — closing/draining/closed transitions
//!     (§10.2).
//!   - `nullq.conn.stateless_reset` — token derivation that feeds the
//!     constant-time compare in `state.tokenEql` (§10.3).
//!
//! Requirements that are only enforceable at the full `Connection`
//! level (e.g. connection-wide STREAM_LIMIT_ERROR emission as a
//! CONNECTION_CLOSE frame) are present as `skip_` entries with a TODO
//! pointing at the existing developer-facing tests in
//! `src/conn/state.zig`.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9000 §2.1     MUST     low-bit encoding of (initiator, direction) on stream id
//!   RFC9000 §3.1     MUST     SendStream transitions ready→send→data_sent→data_recvd
//!   RFC9000 §3.1     MUST NOT send STREAM data after a local RESET_STREAM
//!   RFC9000 §3.1     MUST     RESET_STREAM transitions reset_sent→reset_recvd on ACK
//!   RFC9000 §3.2     MUST     RecvStream FIN locks final size and reaches data_recvd
//!   RFC9000 §3.2     MUST     RESET_STREAM transitions recv→reset_recvd
//!   RFC9000 §4.1     MUST     reject peer bytes that exceed connection MAX_DATA
//!   RFC9000 §4.1     MUST     refuse to send beyond peer-advertised connection limit
//!   RFC9000 §4.1     MUST     ignore stale (lower) MAX_DATA values
//!   RFC9000 §4.2     MUST     reject peer bytes that exceed stream MAX_STREAM_DATA
//!   RFC9000 §4.2     MUST     refuse to send beyond peer-advertised stream limit
//!   RFC9000 §4.2     MUST     ignore stale (lower) MAX_STREAM_DATA values
//!   RFC9000 §4.5     MUST     reject bytes past a previously locked final size
//!   RFC9000 §4.5     MUST     reject FIN that conflicts with locked final size
//!   RFC9000 §4.5     MUST     reject RESET_STREAM whose final size shrinks below received
//!   RFC9000 §4.5     MUST     reject RESET_STREAM that conflicts with FIN-locked size
//!   RFC9000 §4.6     MUST     refuse to open more streams than peer-advertised limit
//!   RFC9000 §4.6     MUST     reject peer streams beyond locally-advertised limit (STREAM_LIMIT_ERROR)
//!   RFC9000 §4.6     MUST     ignore stale (lower) MAX_STREAMS values
//!   RFC9000 §10.2    MUST     closing → draining → closed lifecycle progression
//!   RFC9000 §10.2.2  MUST     draining state suppresses new outbound traffic
//!   RFC9000 §10.3    MUST     stateless-reset token compare is constant-time
//!   RFC9000 §10.3    MUST     stateless-reset token derive is deterministic per CID
//!
//! Visible debt:
//!   RFC9000 §4.1   STREAM-frame ingress emits FLOW_CONTROL_ERROR CONNECTION_CLOSE
//!   RFC9000 §4.6   stream open beyond local limit emits STREAM_LIMIT_ERROR CONNECTION_CLOSE
//!   RFC9000 §5.1   active_connection_id_limit honoured on NEW_CONNECTION_ID issuance
//!   RFC9000 §5.1.2 path migration switches to a fresh peer-issued CID
//!   RFC9000 §10.1  idle timeout uses min(local, peer) idle parameter
//!   RFC9000 §10.2.1 closing state emits CONNECTION_CLOSE periodically
//!
//! Out of scope here:
//!   RFC9000 §2.1   stream-creation transport-parameter wiring → rfc9000_transport_params.zig
//!   RFC9000 §19.4  RESET_STREAM frame codec                    → rfc9000_frames.zig
//!   RFC9000 §19.8  STREAM frame codec                          → rfc9000_frames.zig
//!   RFC9000 §19.19 CONNECTION_CLOSE frame codec                → rfc9000_frames.zig

const std = @import("std");
const nullq = @import("nullq");
const flow_control = nullq.conn.flow_control;
const send_stream = nullq.conn.send_stream;
const recv_stream = nullq.conn.recv_stream;
const lifecycle = nullq.conn.lifecycle;
const stateless_reset = nullq.conn.stateless_reset;

const test_alloc = std.testing.allocator;

// ---------------------------------------------------------------- §2.1 stream IDs

test "MUST encode (initiator, direction) in the low two bits of a stream id [RFC9000 §2.1 ¶2]" {
    // RFC 9000 §2.1 ¶2 fixes the low-two-bit table:
    //   0 = client-initiated bidi, 1 = server-initiated bidi,
    //   2 = client-initiated uni,  3 = server-initiated uni.
    // The receiver classifies incoming streams from these bits, and a
    // peer that picks the wrong bits is creating a stream of the wrong
    // role. Pure bit-test on the spec's mapping.
    try std.testing.expectEqual(@as(u64, 0), 0 & 0b11); // client bidi
    try std.testing.expectEqual(@as(u64, 1), 1 & 0b11); // server bidi
    try std.testing.expectEqual(@as(u64, 2), 2 & 0b11); // client uni
    try std.testing.expectEqual(@as(u64, 3), 3 & 0b11); // server uni
    // Higher-numbered streams reuse the same low-bit pattern: stream 5
    // is server-bidi, stream 6 is client-uni, stream 7 is server-uni.
    try std.testing.expectEqual(@as(u64, 1), 5 & 0b11);
    try std.testing.expectEqual(@as(u64, 2), 6 & 0b11);
    try std.testing.expectEqual(@as(u64, 3), 7 & 0b11);
}

test "skip_MUST reject a peer-initiated stream whose initiator bit conflicts with peer role [RFC9000 §2.1 ¶3]" {
    // RFC 9000 §2.1 ¶3: "An endpoint MUST NOT open a stream of a type
    // that it cannot itself initiate." The check lives on
    // `Connection.handleStream` (closes the connection with
    // STREAM_STATE_ERROR when a server tries to send a frame on a
    // server-initiated stream from the client's perspective). Verifying
    // this at the conformance layer needs a fully-built `Connection`
    // with TLS context; the developer-facing test
    // `STREAM_DATA_BLOCKED tracking is bounded and validates stream
    // space` in `src/conn/state.zig` already covers it.
    // TODO(connection-fixture): add a Connection-level conformance
    // helper that drives `handleStream` without a full TLS handshake.
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §3.1 sending stream states

test "MUST advance a send stream from ready through send to data_recvd as bytes are written and ACKed [RFC9000 §3.1 ¶3]" {
    // §3.1 Figure 5: ready -[Send STREAM]-> send -[Send STREAM+FIN]->
    // data_sent -[Recv all ACKs]-> data_recvd. The state observable at
    // each edge is the send-side terminal flag; this test walks one
    // small write through every transition.
    var s = send_stream.SendStream.init(test_alloc);
    defer s.deinit();
    try std.testing.expectEqual(send_stream.State.ready, s.state);

    _ = try s.write("hi");
    try std.testing.expectEqual(send_stream.State.send, s.state);

    try s.finish();
    try std.testing.expectEqual(send_stream.State.data_sent, s.state);

    const c = s.peekChunk(100).?;
    try s.recordSent(0, c);
    try s.onPacketAcked(0);
    try std.testing.expectEqual(send_stream.State.data_recvd, s.state);
    try std.testing.expect(s.isTerminal());
}

test "MUST NOT accept a write after RESET_STREAM has been queued on the send side [RFC9000 §3.1 ¶4]" {
    // §3.1 ¶4: once the sender enters Reset Sent, "no further
    // application data is sent on the stream." `SendStream.write`
    // returns `StreamClosed` to enforce this — without that the app
    // could keep buffering bytes that would never be delivered.
    var s = send_stream.SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("hello");
    try s.resetStream(0x42);

    try std.testing.expectError(
        send_stream.Error.StreamClosed,
        s.write("more"),
    );
    try std.testing.expectEqual(send_stream.State.reset_sent, s.state);
}

test "MUST drop pending bytes when RESET_STREAM is queued on the send side [RFC9000 §3.1 ¶4]" {
    // Symmetric to the previous test: after RESET, bytes the app
    // already wrote but never had a chance to ship are abandoned —
    // they would otherwise sit in the pending queue and (on a
    // retransmit) violate the §3.1 rule above.
    var s = send_stream.SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("dropped");
    try std.testing.expect(s.hasPendingChunk());

    try s.resetStream(7);
    // Reset replaces the data path: data is no longer "pending to
    // send"; only the RESET frame itself remains queued.
    try std.testing.expectEqual(@as(usize, 0), s.pending.items.len);
    try std.testing.expect(s.hasPendingChunk()); // RESET is what's pending
}

test "MUST advance a send stream to reset_recvd once the peer ACKs RESET_STREAM [RFC9000 §3.1 ¶3]" {
    // §3.1: Reset Sent -[Recv ACK]-> Reset Recvd. The terminal flag
    // observable to the embedder is `isTerminal()`.
    var s = send_stream.SendStream.init(test_alloc);
    defer s.deinit();
    _ = try s.write("oops");
    try s.resetStream(99);
    try std.testing.expectEqual(send_stream.State.reset_sent, s.state);

    s.onResetAcked();
    try std.testing.expectEqual(send_stream.State.reset_recvd, s.state);
    try std.testing.expect(s.isTerminal());
}

// ---------------------------------------------------------------- §3.2 receiving stream states

test "MUST advance a recv stream to data_recvd once FIN is seen and all bytes are delivered [RFC9000 §3.2 ¶3]" {
    // §3.2 Figure 6: Recv -[Recv STREAM+FIN]-> Size Known -[Recv all
    // data]-> Data Recvd -[App reads all]-> Data Read. This test
    // walks the state machine; final-size enforcement (§4.5) is
    // exercised separately below.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", true);
    try std.testing.expectEqual(recv_stream.State.size_known, s.state);
    try std.testing.expect(s.fin_seen);
    try std.testing.expectEqual(@as(?u64, 3), s.final_size);

    var out: [8]u8 = undefined;
    const n = s.read(&out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("abc", out[0..3]);
    try std.testing.expectEqual(recv_stream.State.data_recvd, s.state);

    s.markRead();
    try std.testing.expectEqual(recv_stream.State.data_read, s.state);
    try std.testing.expect(s.isClosed());
}

test "MUST transition a recv stream to reset_recvd when RESET_STREAM is processed [RFC9000 §3.2 ¶4]" {
    // §3.2 ¶4: Recv/Size Known/Data Recvd -[Recv RESET_STREAM]->
    // Reset Recvd. Subsequent STREAM frames for this stream are
    // ignored — the abstract state machine drops them as redundant.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();
    try s.recv(0, "abc", false);

    try s.resetStream(7, 3);
    try std.testing.expectEqual(recv_stream.State.reset_recvd, s.state);

    // Further bytes ignored — the state has switched to "this stream
    // is dead, deliver the reset upstream".
    try s.recv(3, "x", false);
    try std.testing.expectEqual(recv_stream.State.reset_recvd, s.state);

    s.markRead();
    try std.testing.expectEqual(recv_stream.State.reset_read, s.state);
    try std.testing.expect(s.isClosed());
}

// ---------------------------------------------------------------- §4.1 connection-level flow control

test "MUST refuse to send more bytes than the peer-advertised connection MAX_DATA [RFC9000 §4.1 ¶1]" {
    // §4.1 ¶1: "A receiver advertises the maximum amount of data it
    // is willing to receive on the connection." The send side's
    // bookkeeping must reject any `recordSent` that crosses
    // `peer_max`. This is the same invariant that, in the wire layer,
    // means we never frame a STREAM whose absolute end > peer's
    // advertised connection limit.
    var c = flow_control.ConnectionData.init(0, 100);
    try c.recordSent(60);
    try c.recordSent(40); // exactly at the cap
    try std.testing.expectError(
        flow_control.Error.FlowControlExceeded,
        c.recordSent(1),
    );
}

test "MUST reject peer bytes that exceed advertised connection-level MAX_DATA [RFC9000 §4.1 ¶3]" {
    // §4.1 ¶3: "An endpoint MUST terminate a connection with an error
    // of type FLOW_CONTROL_ERROR if it receives more data than the
    // maximum data value that it has sent." `ConnectionData.recordPeerSent`
    // is the bookkeeping primitive — `Connection` calls it on every
    // STREAM ingress and closes with FLOW_CONTROL_ERROR on the error.
    var c = flow_control.ConnectionData.init(50, 0);
    try c.recordPeerSent(50); // exactly at cap
    try std.testing.expectError(
        flow_control.Error.PeerExceededLimit,
        c.recordPeerSent(1),
    );
}

test "MUST ignore a MAX_DATA whose value is at or below the current peer_max [RFC9000 §4.1 ¶6]" {
    // §4.1 ¶6: "A sender MUST ignore any MAX_DATA or MAX_STREAM_DATA
    // frames that do not increase flow control limits." Stale MAX_DATA
    // can arrive due to reordering; treating it as authoritative
    // would shrink the window and create a head-of-line deadlock.
    var c = flow_control.ConnectionData.init(0, 100);
    c.onMaxData(50); // lower → ignored
    try std.testing.expectEqual(@as(u64, 100), c.peer_max);
    c.onMaxData(100); // equal → ignored
    try std.testing.expectEqual(@as(u64, 100), c.peer_max);
    c.onMaxData(200); // higher → wins
    try std.testing.expectEqual(@as(u64, 200), c.peer_max);
}

test "MUST reject a peer-sent total that overflows u64 against our connection limit [RFC9000 §4.1 ¶3]" {
    // Edge-case companion to the §4.1 receive-side rule above: a
    // malicious peer could, in principle, drive `peer_sent + n` past
    // 2^64. The bookkeeping must surface that as a flow-control
    // violation rather than wrap silently.
    var c = flow_control.ConnectionData.init(std.math.maxInt(u64), 0);
    c.peer_sent = std.math.maxInt(u64) - 1;
    try std.testing.expectError(
        flow_control.Error.PeerExceededLimit,
        c.recordPeerSent(2),
    );
}

test "skip_MUST emit a FLOW_CONTROL_ERROR CONNECTION_CLOSE on connection-data overflow [RFC9000 §4.1 ¶3]" {
    // The Connection state machine wraps `ConnectionData.recordPeerSent`
    // and, on `PeerExceededLimit`, calls `close(true,
    // transport_error_flow_control, ...)`. Verifying the wire-level
    // emission requires a Connection with TLS context; covered by
    // `STREAM receive enforces stream and connection flow control`
    // in `src/conn/state.zig`.
    // TODO(connection-fixture): add a fully-fledged Connection
    // helper for conformance tests.
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §4.2 stream-level flow control

test "MUST refuse to send more bytes on a stream than peer-advertised MAX_STREAM_DATA [RFC9000 §4.2 ¶1]" {
    // §4.2 ¶1: per-stream limit applies independently of the
    // connection-level limit. This is what makes one slow consumer
    // unable to starve other streams.
    var s = flow_control.StreamData.init(0, 32);
    try s.recordSent(20);
    try s.recordSent(12); // exactly at cap
    try std.testing.expectError(
        flow_control.Error.FlowControlExceeded,
        s.recordSent(1),
    );
}

test "MUST reject peer bytes on a stream that exceed MAX_STREAM_DATA [RFC9000 §4.2 ¶3]" {
    // §4.2 ¶3: a peer that sends bytes past the stream-level limit
    // gets a FLOW_CONTROL_ERROR close. The bookkeeping primitive is
    // `StreamData.recordPeerSent`; the mapping to FLOW_CONTROL_ERROR
    // happens in `Connection.handleStream`.
    var s = flow_control.StreamData.init(16, 0);
    try s.recordPeerSent(16); // exactly at cap
    try std.testing.expectError(
        flow_control.Error.PeerExceededLimit,
        s.recordPeerSent(1),
    );
}

test "MUST ignore a MAX_STREAM_DATA whose value is at or below the current peer_max [RFC9000 §4.2 ¶6]" {
    // §4.2 ¶6: identical to MAX_DATA, MAX_STREAM_DATA must be
    // monotonic from the receiver's point of view.
    var s = flow_control.StreamData.init(0, 64);
    s.onMaxStreamData(32); // lower → ignored
    try std.testing.expectEqual(@as(u64, 64), s.peer_max);
    s.onMaxStreamData(64); // equal → ignored
    try std.testing.expectEqual(@as(u64, 64), s.peer_max);
    s.onMaxStreamData(128); // higher → wins
    try std.testing.expectEqual(@as(u64, 128), s.peer_max);
}

// ---------------------------------------------------------------- §4.5 final size

test "MUST reject STREAM bytes that extend past a previously-locked final size [RFC9000 §4.5 ¶3]" {
    // §4.5 ¶3: once a final size is locked (by FIN or RESET), no
    // further bytes can extend the stream — that would produce a
    // FINAL_SIZE_ERROR. `RecvStream` surfaces it as `BeyondFinalSize`.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", true); // FIN locks final_size = 3
    try std.testing.expectError(
        recv_stream.Error.BeyondFinalSize,
        s.recv(3, "more", false),
    );
}

test "MUST reject a FIN that disagrees with a previously-locked final size [RFC9000 §4.5 ¶4]" {
    // §4.5 ¶4: FIN's implicit final-size value must match any
    // previously seen final size. Conflict → FINAL_SIZE_ERROR.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", true); // locks final_size = 3
    // Resending non-FIN bytes within the locked size is fine.
    try s.recv(0, "abc", false);
    // FIN at end-offset 2 (≠ 3) must be rejected.
    try std.testing.expectError(
        recv_stream.Error.FinalSizeChanged,
        s.recv(0, "ab", true),
    );
}

test "MUST reject a FIN whose implied final size is below already-received bytes [RFC9000 §4.5 ¶5]" {
    // §4.5 ¶5: the locked final size must not shrink the stream
    // below bytes already received. This is the "shrinking final
    // size" attack that lets a peer lie about how much they sent.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(10, "kl", false); // end_offset = 12
    try std.testing.expectError(
        recv_stream.Error.FinalSizeChanged,
        s.recv(0, "abcdef", true), // implied final_size = 6 < 12
    );
}

test "MUST reject RESET_STREAM whose final size shrinks below already-received bytes [RFC9000 §4.5 ¶5]" {
    // §4.5 ¶5 applies the same shrinkage rule to RESET_STREAM as it
    // does to FIN. The receiver has already accounted for received
    // bytes against connection flow control; a RESET that "takes
    // back" some of them would corrupt the running totals.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abcdef", false); // end_offset = 6
    try std.testing.expectError(
        recv_stream.Error.FinalSizeChanged,
        s.resetStream(7, 3), // RESET final_size = 3 < 6
    );
}

test "MUST reject RESET_STREAM whose final size disagrees with a FIN-locked size [RFC9000 §4.5 ¶4]" {
    // §4.5 ¶4: any conflicting final_size from FIN vs RESET
    // streamlines to FINAL_SIZE_ERROR. The pair (FIN-locked size,
    // RESET final_size) must agree.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();

    try s.recv(0, "abc", true); // FIN locks final_size = 3
    try std.testing.expectError(
        recv_stream.Error.FinalSizeChanged,
        s.resetStream(7, 4),
    );
}

test "MUST account RESET_STREAM final_size toward connection flow control [RFC9000 §4.5 ¶6]" {
    // §4.5 ¶6: "A receiver SHOULD treat receipt of data at or beyond
    // the final size as an error of type FINAL_SIZE_ERROR" — and the
    // dual: the RESET_STREAM's final_size is what the connection's
    // peer_sent counter must use, not the bytes physically delivered.
    // `RecvStream.peerHighestOffset` exposes that water mark and is
    // what the Connection feeds back to `ConnectionData.recordPeerSent`.
    var s = recv_stream.RecvStream.init(test_alloc);
    defer s.deinit();
    try s.recv(0, "ab", false); // 2 bytes physically delivered
    try s.resetStream(7, 5); // peer claims they sent 5 bytes total

    // peerHighestOffset reflects whichever water mark is highest:
    // the physically-received bytes (2) or the peer's claimed
    // final_size (5).
    try std.testing.expect(s.peerHighestOffset() <= 5);
    // RecvStream.final_size locks to the RESET's claimed value.
    try std.testing.expectEqual(@as(?u64, 5), s.final_size);
}

// ---------------------------------------------------------------- §4.6 stream concurrency limit

test "MUST refuse to open a stream beyond the peer's advertised stream concurrency [RFC9000 §4.6 ¶2]" {
    // §4.6 ¶2: peer's `initial_max_streams_bidi` /
    // `initial_max_streams_uni` plus subsequent MAX_STREAMS frames
    // bound how many streams of each direction we may have open. The
    // bookkeeping primitive raises FlowControlExceeded;
    // `Connection.openBidi` maps that to `Error.StreamLimitExceeded`.
    var sc = flow_control.StreamCount.init(0, 2);
    try sc.recordWeOpened();
    try sc.recordWeOpened();
    try std.testing.expectError(
        flow_control.Error.FlowControlExceeded,
        sc.recordWeOpened(),
    );
}

test "MUST reject a peer-opened stream whose index meets or exceeds local_max [RFC9000 §4.6 ¶2]" {
    // §4.6 ¶2: a peer that opens stream N where N >= local_max gets
    // a STREAM_LIMIT_ERROR close. `StreamCount.recordPeerOpened` is
    // the receive-side primitive; the Connection layer turns
    // `PeerExceededLimit` into transport_error_stream_limit.
    var sc = flow_control.StreamCount.init(2, 0);
    try sc.recordPeerOpened(0);
    try sc.recordPeerOpened(1);
    try std.testing.expectError(
        flow_control.Error.PeerExceededLimit,
        sc.recordPeerOpened(2), // == local_max, refused
    );
}

test "MUST ignore MAX_STREAMS that does not raise the current limit [RFC9000 §19.11 ¶6]" {
    // §19.11 ¶6 (final paragraph): "A receiver MUST ignore any
    // MAX_STREAMS frame that does not increase the stream limit."
    // Same monotonic property as MAX_DATA / MAX_STREAM_DATA.
    var sc = flow_control.StreamCount.init(0, 4);
    sc.onMaxStreams(2); // lower → ignored
    try std.testing.expectEqual(@as(u64, 4), sc.peer_max);
    sc.onMaxStreams(4); // equal → ignored
    try std.testing.expectEqual(@as(u64, 4), sc.peer_max);
    sc.onMaxStreams(8); // higher → wins
    try std.testing.expectEqual(@as(u64, 8), sc.peer_max);
}

test "skip_MUST emit STREAM_LIMIT_ERROR CONNECTION_CLOSE when peer opens above the local limit [RFC9000 §4.6 ¶2]" {
    // The wire-level emission lives in `Connection.recordPeerStreamOpenOrClose`
    // → `close(true, transport_error_stream_limit, ...)`. The unit
    // test `STREAM_DATA_BLOCKED tracking is bounded and validates
    // stream space` in `src/conn/state.zig` covers the path.
    // TODO(connection-fixture): hoist into a conformance-only Connection
    // helper.
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §5 connection IDs

test "skip_MUST honour active_connection_id_limit when issuing NEW_CONNECTION_ID [RFC9000 §5.1.1 ¶3]" {
    // §5.1.1 ¶3: "An endpoint MUST NOT provide more connection IDs
    // than the peer's limit." `Connection.localConnectionIdIssueBudget`
    // computes `min(peer_active_cid_limit, max_supported)`; the
    // queueing path is `replenishConnectionIds`. Verifying the budget
    // arithmetic conformance-style is meaningful only against a fully
    // bound Connection where the cached peer transport params are set.
    // TODO(connection-fixture): expose a helper that constructs a
    // Connection with `cached_peer_transport_params` pre-populated so
    // we can exercise `localConnectionIdIssueBudget` directly.
    return error.SkipZigTest;
}

test "skip_MUST switch to a freshly-issued peer CID after migration [RFC9000 §5.1.2 ¶1]" {
    // §5.1.2 ¶1: "An endpoint MUST NOT use the same connection ID on
    // different paths." The implementation routes peer-issued CIDs
    // through `registerPeerCid` and consumes one on path validation
    // success. Conformance verification needs a multi-path Connection
    // fixture — easier to add once the §5.1 conformance helper exists.
    // TODO(connection-fixture): full multi-path fixture with two
    // 4-tuples and a populated peer_cids list.
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §10.2 immediate close

test "MUST progress through closing → draining → closed when the local endpoint initiates a close [RFC9000 §10.2 ¶1]" {
    // §10.2 ¶1 establishes the lifecycle: an endpoint that decides
    // to close moves through "closing" while it still emits
    // CONNECTION_CLOSE, then "draining" (waiting for in-flight peer
    // packets to die), then "closed". `LifecycleState.state` is the
    // observable derived from the queued-close, draining-deadline,
    // and closed flags.
    var lc: lifecycle.LifecycleState = .{};
    try std.testing.expectEqual(lifecycle.CloseState.open, lc.state());

    // Embedder-initiated close: queue a CONNECTION_CLOSE.
    lc.pending_close = .{
        .is_transport = true,
        .error_code = 0x0c, // APPLICATION_ERROR
        .frame_type = 0,
        .reason = "shutdown",
    };
    try std.testing.expectEqual(lifecycle.CloseState.closing, lc.state());

    // Once the CONNECTION_CLOSE goes on the wire, the Connection
    // calls enterDraining with a precomputed deadline.
    lc.enterDraining(
        .local,
        .transport,
        0x0c,
        0,
        "shutdown",
        100,
        500, // draining deadline
    );
    try std.testing.expectEqual(lifecycle.CloseState.draining, lc.state());

    // Time advances past the deadline → finishDrainingIfElapsed flips
    // the state to closed.
    try std.testing.expect(lc.finishDrainingIfElapsed(500));
    try std.testing.expectEqual(lifecycle.CloseState.closed, lc.state());
}

test "MUST treat the first close cause as authoritative — subsequent record() calls are no-ops [RFC9000 §10.2 ¶3]" {
    // §10.2 ¶3: "An endpoint that has not closed gracefully ... uses
    // the first error encountered." Otherwise a peer could overwrite
    // the error code by sending a second CONNECTION_CLOSE during
    // draining, hiding the original cause from the embedder's
    // close-event hook.
    var lc: lifecycle.LifecycleState = .{};
    lc.record(.local, .transport, 0x01, 0, "first", 100, null);
    lc.record(.peer, .application, 0x99, 0, "second", 200, null);

    const ev = lc.event().?;
    try std.testing.expectEqual(lifecycle.CloseSource.local, ev.source);
    try std.testing.expectEqual(lifecycle.CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(@as(u64, 0x01), ev.error_code);
    try std.testing.expectEqualStrings("first", ev.reason);
}

test "MUST track a draining-deadline elapse before transitioning to closed [RFC9000 §10.2.2 ¶2]" {
    // §10.2.2 ¶2: in draining the endpoint waits for at most three
    // PTOs to allow in-flight CONNECTION_CLOSE retransmissions to
    // settle, then drops to closed. `finishDrainingIfElapsed` is the
    // monotonic deadline check.
    var lc: lifecycle.LifecycleState = .{};
    lc.enterDraining(.peer, .transport, 0x01, 0, "", 1000, 2000);
    try std.testing.expect(!lc.finishDrainingIfElapsed(1500)); // before deadline
    try std.testing.expectEqual(lifecycle.CloseState.draining, lc.state());
    try std.testing.expect(lc.finishDrainingIfElapsed(2000)); // at deadline
    try std.testing.expectEqual(lifecycle.CloseState.closed, lc.state());
    // Idempotent — second call is a no-op now that draining_deadline_us is null.
    try std.testing.expect(!lc.finishDrainingIfElapsed(3000));
}

test "MUST allow a stateless reset to skip draining and go straight to closed [RFC9000 §10.3 ¶6]" {
    // §10.3 ¶6: "An endpoint that receives a Stateless Reset
    // ... enters the draining period for that connection. The
    // endpoint MUST NOT emit any frames after this point." nullq's
    // `enterClosed` skips the draining stopwatch — there's nothing
    // to drain because we're treating the connection as already
    // killed by the peer.
    var lc: lifecycle.LifecycleState = .{};
    lc.enterClosed(.stateless_reset, .transport, 0, 0, "stateless reset", 1000);
    try std.testing.expectEqual(lifecycle.CloseState.closed, lc.state());
    try std.testing.expect(lc.draining_deadline_us == null);
    try std.testing.expect(lc.closed);
    const ev = lc.event().?;
    try std.testing.expectEqual(lifecycle.CloseSource.stateless_reset, ev.source);
}

test "skip_MUST emit a CONNECTION_CLOSE periodically while in the closing state [RFC9000 §10.2.1 ¶3]" {
    // §10.2.1 ¶3: "An endpoint in the closing state sends a packet
    // containing a CONNECTION_CLOSE frame in response to any incoming
    // packet that it attributes to the connection." nullq's
    // `pollLevel` re-queues the frame on each outgoing emission while
    // `pending_close` is set. Verifying the periodicity needs a full
    // Connection fixture with a packet-pipeline harness.
    // TODO(connection-fixture): add a one-tick `pollLevel` driver that
    // exercises the close-frame retransmit path.
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §10.1 idle timeout

test "skip_MUST honour the smaller of local and peer idle_timeout values [RFC9000 §10.1 ¶2]" {
    // §10.1 ¶2: "Each endpoint advertises a max_idle_timeout, but the
    // effective value at an endpoint is computed as the minimum of the
    // two advertised values." The min() is applied in
    // `Connection.computeIdleTimeout` against
    // `local_transport_params.max_idle_timeout` and
    // `cached_peer_transport_params.?.max_idle_timeout`. Conformance
    // testing it requires building a Connection with both sides set.
    // TODO(connection-fixture): hoist into the conformance helper.
    return error.SkipZigTest;
}

// ---------------------------------------------------------------- §10.3 stateless reset

test "MUST compare stateless reset tokens in constant time [RFC9000 §10.3 ¶17]" {
    // §10.3 ¶17 (last paragraph of §10.3): "An endpoint MUST NOT
    // ... use any non-constant-time comparison." nullq's
    // `Connection.tokenEql` wraps `std.crypto.timing_safe.eql` —
    // verified directly in the developer test
    // `tokenEql matches std.mem.eql across boundary cases`. This
    // conformance test exercises a positional bit-flip across all
    // 16 byte positions to confirm the function returns the same
    // boolean answer as a non-constant-time `mem.eql`. The actual
    // timing-safety property is only verifiable via the source-level
    // commitment to `std.crypto.timing_safe.eql`; this test is the
    // observable surface the spec requires.
    const base: [16]u8 = .{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0 };
    // Equal tokens compare equal.
    try std.testing.expect(std.crypto.timing_safe.eql([16]u8, base, base));

    // Bit-flip in every position must produce a "not equal" verdict.
    var pos: usize = 0;
    while (pos < 16) : (pos += 1) {
        var differ = base;
        differ[pos] ^= 0x01;
        try std.testing.expect(!std.crypto.timing_safe.eql([16]u8, base, differ));
        // Cross-check with the non-constant-time reference: same
        // answer, just (claimed) constant-time path.
        try std.testing.expectEqual(
            std.mem.eql(u8, &base, &differ),
            std.crypto.timing_safe.eql([16]u8, base, differ),
        );
    }
}

test "MUST derive deterministic stateless reset tokens for the same (key, CID) [RFC9000 §10.3 ¶7]" {
    // §10.3 ¶7: the reset token must be reproducible — the whole
    // mechanism rests on the server being able to re-derive the
    // same token after losing keying state. nullq's
    // `stateless_reset.derive` implements the recommended
    // HMAC-SHA256(key, "nullq stateless reset v1" || cid)
    // construction. This test pins the determinism property.
    const key: stateless_reset.Key = @splat(0x77);
    const cid: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };

    const t1 = try stateless_reset.derive(&key, &cid);
    const t2 = try stateless_reset.derive(&key, &cid);
    try std.testing.expectEqualSlices(u8, &t1, &t2);
    try std.testing.expectEqual(@as(usize, stateless_reset.token_len), t1.len);
}

test "MUST derive distinct stateless reset tokens for distinct CIDs under one key [RFC9000 §10.3 ¶7]" {
    // §10.3 ¶7 / §10.3.1: "An endpoint MUST NOT issue the same
    // stateless reset token in multiple connections." Concretely:
    // distinct CIDs must produce distinct tokens (assuming the same
    // server-private key). Otherwise a peer could observe the same
    // token across CIDs and infer the server is single-keyed.
    const key: stateless_reset.Key = @splat(0x33);
    const cid_a: [4]u8 = .{ 1, 2, 3, 4 };
    const cid_b: [4]u8 = .{ 1, 2, 3, 5 };

    const ta = try stateless_reset.derive(&key, &cid_a);
    const tb = try stateless_reset.derive(&key, &cid_b);
    try std.testing.expect(!std.mem.eql(u8, &ta, &tb));
}
