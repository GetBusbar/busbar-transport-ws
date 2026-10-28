// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAL'S OPENING AND ITS MESSAGES (busbar ARCHITECT Q-L5B-WS-DIAL 2026-10-03): a dialled
//! connection's upgrade request carries the dial's opening head fields (the handshake's own
//! excepted); a message written before the handshake completes is held and goes out, in order, the
//! moment it does; a message the emit states text (`EMIT_TEXT`) goes out as a text message, any
//! other as binary.

use busbar_contract::transport::wire::WireStatusClass;
use busbar_contract::transport::{ConnFacts, Framed, Framer, FramerOut, HostTime, Side};
use tungstenite::handshake::derive_accept_key;

use crate::transport::{reason_phrase, retry_after};
use crate::WsFramer;
use tungstenite::http::{HeaderMap, HeaderValue};

/// What one framer call produced.
#[derive(Default)]
struct Out {
    sent: Vec<u8>,
    frames: Vec<Vec<u8>>,
    /// Per frame in `frames`: the status it stated, and its class.
    statuses: Vec<Option<(u32, Option<WireStatusClass>)>>,
    /// The frames ended (`end`).
    ended: bool,
}

impl FramerOut for Out {
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        self.frames.push(piece.bytes.to_vec());
        self.statuses
            .push(piece.status_code.map(|code| (code, piece.status)));
    }
    fn end(&mut self) {
        self.ended = true;
    }
    fn now(&self) -> HostTime {
        HostTime::default()
    }
    fn wake_at(&mut self, _: Option<u64>) {}
}

/// The upgrade request's field `name` (case-insensitive), each value it carries.
fn fields_named<'a>(request: &'a str, name: &str) -> Vec<&'a str> {
    request
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect()
}

/// The server's switching-protocols answer to `request`.
fn switching(request: &str) -> Vec<u8> {
    let key = fields_named(request, "sec-websocket-key")[0];
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    )
    .into_bytes()
}

/// The opcode of each WebSocket frame in `wire` (a client's frames: masked).
fn opcodes(wire: &[u8]) -> Vec<u8> {
    let mut at = 0;
    let mut ops = Vec::new();
    while at + 2 <= wire.len() {
        ops.push(wire[at] & 0x0f);
        let masked = wire[at + 1] & 0x80 != 0;
        let mut len = usize::from(wire[at + 1] & 0x7f);
        let mut head = 2;
        if len == 126 {
            len = usize::from(u16::from_be_bytes([wire[at + 2], wire[at + 3]]));
            head = 4;
        } else if len == 127 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&wire[at + 2..at + 10]);
            len = usize::try_from(u64::from_be_bytes(b)).expect("a length");
            head = 10;
        }
        at += head + if masked { 4 } else { 0 } + len;
    }
    ops
}

#[test]
fn a_dial_carries_its_opening_fields_holds_early_messages_and_flags_text() {
    let framer = WsFramer::new(0);
    let fields = vec![
        ("authorization".to_string(), b"Bearer sk-provider".to_vec()),
        ("Host".to_string(), b"evil.test".to_vec()),
        ("sec-websocket-key".to_string(), b"forged".to_vec()),
        ("openai-beta".to_string(), b"realtime=v1".to_vec()),
    ];
    let mut out = Out::default();
    let state = framer
        .open_with(
            Side::Dial,
            "ws://127.0.0.1:9/v1/realtime",
            &fields,
            &mut out,
        )
        .expect("the dial opens");
    let request = String::from_utf8(out.sent.clone()).expect("an upgrade request");
    assert!(request.starts_with("GET /v1/realtime "), "{request}");
    assert_eq!(
        fields_named(&request, "authorization"),
        ["Bearer sk-provider"]
    );
    assert_eq!(fields_named(&request, "openai-beta"), ["realtime=v1"]);
    assert_eq!(
        fields_named(&request, "host"),
        ["127.0.0.1:9"],
        "the handshake's own fields are its own"
    );
    assert_eq!(fields_named(&request, "sec-websocket-key").len(), 1);
    assert_ne!(fields_named(&request, "sec-websocket-key"), ["forged"]);

    // Written before the handshake completed: held, nothing sent.
    let mut early = Out::default();
    framer
        .emit_text(state, br#"{"type":"one"}"#, true, true, &mut early)
        .expect("held");
    framer
        .emit_text(state, b"\x00\x01", true, false, &mut early)
        .expect("held");
    assert!(early.sent.is_empty(), "nothing leaves before the handshake");

    // The handshake completes: the held messages go out, in order, text then binary.
    let mut done = Out::default();
    framer
        .ingest(state, &switching(&request), false, &mut done)
        .expect("the handshake completes");
    assert_eq!(
        opcodes(&done.sent),
        [0x1, 0x2],
        "text, then binary, in order"
    );
    // RED (HEAD-FIELDS): the switching response is handed up as the stream's head, its status
    // stated and its fields (every one of them the handshake's own here) dropped, before any
    // message; on the parent nothing was handed up until the far end spoke.
    assert_eq!(done.frames, [Vec::<u8>::new()], "the head, an empty block");
    assert_eq!(
        done.statuses,
        [Some((101, Some(WireStatusClass::Success)))],
        "carrying the switching status"
    );

    // Once open, a flagged message goes out as text at once.
    let mut open = Out::default();
    framer
        .emit_text(state, br#"{"type":"two"}"#, true, true, &mut open)
        .expect("sent");
    assert_eq!(opcodes(&open.sent), [0x1]);
    // A text message that is not UTF-8 is refused, not sent as something else.
    let mut bad = Out::default();
    assert!(framer
        .emit_text(state, b"\xff\xfe", true, true, &mut bad)
        .is_err());
}

// ── the wire's declarations and its URL reading (from the in-process transport's battery, which
// left with that transport when the crate went door-only) ──────────────────────────────────────

/// `split_ws_url` on the bracketed-IPv6 shapes. A literal address with an explicit port is the one
/// case the bracket rule exists to serve, and it must come back as the address without its brackets
/// and the port the URL spelled — not as an authority that gets a default port stapled onto it.
#[test]
fn a_bracketed_ipv6_authority_parses_with_and_without_a_port() {
    assert_eq!(
        crate::transport::split_ws_url("wss://[::1]:8080/p").unwrap(),
        (true, "::1".to_string(), 8080, "/p".to_string())
    );
    assert_eq!(
        crate::transport::split_ws_url("ws://[::1]/p").unwrap(),
        (false, "::1".to_string(), 80, "/p".to_string())
    );
    // The shapes the existing rule already got right stay right.
    assert_eq!(
        crate::transport::split_ws_url("ws://host:9000/p").unwrap(),
        (false, "host".to_string(), 9000, "/p".to_string())
    );
    assert_eq!(
        crate::transport::split_ws_url("wss://host/p").unwrap(),
        (true, "host".to_string(), 443, "/p".to_string())
    );
}

/// The authority ends at `?`, `#` or `\` as well as `/`, where the handshake's own parser ends it.
/// RED on the `/`-only split, which read `ws://host?x=1` as the host `host?x=1`.
#[test]
fn a_ws_authority_ends_at_a_query_a_fragment_or_a_backslash() {
    assert_eq!(
        crate::transport::split_ws_url("ws://host?x=1").unwrap(),
        (false, "host".to_string(), 80, "/?x=1".to_string())
    );
    assert_eq!(
        crate::transport::split_ws_url("wss://127.0.0.1\\x/").unwrap(),
        (true, "127.0.0.1".to_string(), 443, "/x/".to_string())
    );
    assert_eq!(
        crate::transport::split_ws_url("wss://host:9443#f").unwrap(),
        (true, "host".to_string(), 9443, "/#f".to_string())
    );
    assert!(crate::transport::split_ws_url("wss://u@host/").is_err());
}

/// HELD, AND BOUNDED: a dial whose far end never answers cannot grow the framing without end. A
/// message over the ceiling is refused as a capacity failure, and so is one past the held count.
/// RED before the bound: both were held.
#[test]
fn a_dial_holds_early_messages_only_up_to_the_ceiling_and_the_held_count() {
    let framer = WsFramer::new(8);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut early = Out::default();
    assert!(
        framer
            .emit_text(state, b"0123456789", true, false, &mut early)
            .is_err(),
        "a message over the ceiling is refused while held"
    );
    let unbounded = WsFramer::new(0);
    let state = unbounded
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    for _ in 0..crate::transport::MAX_HELD_MESSAGES {
        unbounded
            .emit_text(state, b"m", true, false, &mut early)
            .expect("held");
    }
    assert!(
        unbounded
            .emit_text(state, b"m", true, false, &mut early)
            .is_err(),
        "one past the held count is refused"
    );
    assert!(early.sent.is_empty(), "nothing leaves before the handshake");
}

/// THE FAR END'S REFUSAL OF THE UPGRADE IS ITS ANSWER (THE DESIGN §5, HEAD-FIELDS: the head is
/// always the first fields piece): a `401` (or `429`, `5xx`) in place of `101` is handed up as ONE
/// head carrying its status, its class and its fields, and the frames end, so the breaker reads the
/// status class. RED before the fix: the answer was discarded as a bare handshake failure.
#[test]
fn a_far_end_that_refuses_the_upgrade_hands_up_its_answer() {
    for (code, class) in [
        (401, WireStatusClass::CallerFault),
        (429, WireStatusClass::CallerFault),
        (503, WireStatusClass::FarEndFault),
    ] {
        let framer = WsFramer::new(0);
        let mut out = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
            .expect("the dial opens");
        let answer = format!(
            "HTTP/1.1 {code} Nope\r\nWWW-Authenticate: Bearer\r\nRetry-After: 7\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let mut heard = Out::default();
        framer
            .ingest(state, answer.as_bytes(), false, &mut heard)
            .expect("the far end answered");
        assert_eq!(heard.frames.len(), 1, "{code}: one head");
        assert_eq!(heard.statuses[0], Some((code, Some(class))), "{code}");
        let head = String::from_utf8(heard.frames[0].clone()).unwrap();
        assert!(
            head.to_ascii_lowercase()
                .contains("www-authenticate: bearer"),
            "{code}: its fields ride the head: {head}"
        );
    }
}

/// A REFUSED UPGRADE'S BODY REACHES THE PLANE (Q128 transport-ws LOW): after its head, the far end's
/// error document is handed up as the stream's body, what came with the head and what arrives
/// after it, up to its declared `Content-Length`; then the frames end. The head's reason phrase is
/// taken for the head's slots. RED before the fix: only the head went up, and no reason was kept.
#[test]
fn a_refused_upgrade_hands_up_its_body_and_its_reason() {
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let body = br#"{"error":"bad key"}"#;
    let answer = format!(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut first = answer.into_bytes();
    first.extend_from_slice(&body[..5]);
    let mut heard = Out::default();
    framer
        .ingest(state, &first, false, &mut heard)
        .expect("the far end answered");
    assert_eq!(
        heard.statuses[0],
        Some((401, Some(WireStatusClass::CallerFault)))
    );
    assert_eq!(
        framer.take_reason(state).as_deref(),
        Some(&b"Unauthorized"[..])
    );
    assert_eq!(framer.take_reason(state), None, "taken once");
    let mut rest = Out::default();
    framer
        .ingest(state, &body[5..], false, &mut rest)
        .expect("the rest of the body");
    let mut got: Vec<u8> = heard.frames[1..].concat();
    got.extend(rest.frames.concat());
    assert_eq!(got, body.to_vec(), "the whole error document, once");
}

/// A REFUSED UPGRADE'S WHOLE BODY, PAST THE MACHINE'S ONE READ (Q128 transport-ws MEDIUM): head and
/// a body larger than the protocol machine's handshake read arrive in ONE chunk, and every byte of
/// it is handed up, then the frames end; with no declared length, the body runs to the carrier's
/// end, and that end is forwarded. RED before the fix: the bytes past the machine's read were
/// dropped, and a carrier that had already ended never ended the frames.
#[test]
fn a_refused_upgrade_hands_up_a_large_body_and_the_carrier_end() {
    let body = vec![b'x'; 9000];
    // Declared length, head and body in one chunk.
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut chunk = format!(
        "HTTP/1.1 503 Busy\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    chunk.extend_from_slice(&body);
    let mut heard = Out::default();
    framer
        .ingest(state, &chunk, false, &mut heard)
        .expect("the far end answered");
    assert_eq!(heard.frames[1..].concat(), body, "the whole body, once");
    assert!(heard.ended, "the declared length is met: the frames end");
    // No declared length; the carrier ended with the chunk.
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut chunk = b"HTTP/1.1 502 Bad Gateway\r\n\r\n".to_vec();
    chunk.extend_from_slice(&body);
    let mut heard = Out::default();
    framer
        .ingest(state, &chunk, true, &mut heard)
        .expect("the far end answered");
    assert_eq!(heard.frames[1..].concat(), body, "the whole body, once");
    assert!(heard.ended, "the carrier ended: the frames end");
}

/// A REFUSED UPGRADE'S CHUNKED BODY IS DECODED BY ITS TRANSFER CODING (Q128 transport-ws LOW, both
/// readers on a5c9118; RFC 9112 §6.3 and §7.1: `Transfer-Encoding: chunked` overrides any
/// `Content-Length`, and the body ends at its last chunk): on a kept-alive connection the plane gets
/// the error document without chunk markers, across pieces split mid-size-line and mid-chunk, and
/// the frames end at the zero-length chunk and its trailers, not at the carrier's end. RED before
/// the fix: the chunk-size lines reached the plane, and the frames never ended.
#[test]
fn a_refused_upgrades_chunked_body_is_decoded_and_ends_at_its_last_chunk() {
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let wire: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\
        Content-Length: 3\r\n\r\n7;ext=1\r\n{\"error\r\nC\r\n\":\"bad key\"}\r\n0\r\nx-trace: 1\r\n\r\n";
    let split = wire
        .windows(2)
        .position(|w| w == b"C\r")
        .expect("the second size line")
        + 1;
    let mut heard = Out::default();
    framer
        .ingest(state, &wire[..split], false, &mut heard)
        .expect("the far end answered");
    assert_eq!(
        heard.statuses[0],
        Some((401, Some(WireStatusClass::CallerFault)))
    );
    assert!(!heard.ended, "the last chunk has not come");
    let mut rest = Out::default();
    framer
        .ingest(state, &wire[split..], false, &mut rest)
        .expect("the rest of the body");
    let mut got: Vec<u8> = heard.frames[1..].concat();
    got.extend(rest.frames.concat());
    assert_eq!(got, br#"{"error":"bad key"}"#.to_vec(), "decoded, once");
    assert!(
        rest.ended,
        "the last chunk ends the frames on a kept-alive carrier"
    );
}

/// THE CEILING HOLDS FOR WHAT AN OPEN CONNECTION WRITES TOO (Q128 transport-ws LOW): a message over
/// the ceiling, whole or gathered from pieces, is refused as a held one is, and one within it goes
/// out. RED before the fix: the open path sent any size (the machine bounds only what it reads).
#[test]
fn an_open_connection_refuses_an_outbound_message_over_the_ceiling() {
    let framer = WsFramer::new(8);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let request = String::from_utf8(out.sent.clone()).expect("an upgrade request");
    let mut opened = Out::default();
    framer
        .ingest(state, &switching(&request), false, &mut opened)
        .expect("the handshake completes");
    let mut w = Out::default();
    assert!(
        framer
            .emit_text(state, b"123456789", true, false, &mut w)
            .is_err(),
        "whole"
    );
    framer
        .emit_text(state, b"12345", false, false, &mut w)
        .expect("a piece within the ceiling");
    assert!(
        framer
            .emit_text(state, b"6789", true, false, &mut w)
            .is_err(),
        "gathered"
    );
    let mut ok = Out::default();
    framer
        .emit_text(state, b"12345678", true, false, &mut ok)
        .expect("within the ceiling");
    assert!(!ok.sent.is_empty(), "the message went out");
}

/// A REFUSED PIECE TAKES ITS MESSAGE'S GATHERED PIECES WITH IT ON A DIAL STILL HANDSHAKING (Q128
/// transport-ws LOW, reader r52 on 3286006), as the open path drops them: the next message is held
/// alone, not glued to the refused one's front. RED before the fix: the refused message's first
/// pieces stayed gathered, so a next message within the ceiling read as over it.
#[test]
fn a_refused_piece_on_a_dial_drops_its_gathered_pieces() {
    let framer = WsFramer::new(8);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut w = Out::default();
    framer
        .emit_text(state, b"12345", false, false, &mut w)
        .expect("a piece within the ceiling");
    assert!(
        framer
            .emit_text(state, b"6789", true, false, &mut w)
            .is_err(),
        "the gathered message is over the ceiling"
    );
    framer
        .emit_text(state, b"1234", true, false, &mut w)
        .expect("a next message within the ceiling is held alone");
}

/// THE DIALLED HEAD'S ORDER IS PINNED (Q128 transport-ws LOW, reader r51 on 3286006): the request
/// line, the machine's handshake lines in their fixed order, then the opening fields (in the
/// request map's own order, a repeated name's lines together and in their order); an opening field
/// of a handshake name is not copied. The doc at `HANDSHAKE_FIELDS` states this order.
#[test]
fn the_dialled_heads_order_is_pinned() {
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let fields = [
        ("authorization".to_string(), b"Bearer k".to_vec()),
        ("x-plane".to_string(), b"1".to_vec()),
        ("host".to_string(), b"elsewhere.test".to_vec()),
        ("authorization".to_string(), b"Second k".to_vec()),
    ];
    framer
        .open_with(Side::Dial, "ws://svc.test:9/x", &fields, &mut out)
        .expect("the dial opens");
    let request = String::from_utf8(out.sent.clone()).expect("an upgrade request");
    let names: Vec<&str> = request
        .split("\r\n")
        .skip(1)
        .take_while(|l| !l.is_empty())
        .map(|l| l.split(':').next().unwrap_or_default())
        .collect();
    assert!(request.starts_with("GET /x HTTP/1.1\r\n"), "{request}");
    assert_eq!(
        names[..5],
        [
            "Host",
            "Connection",
            "Upgrade",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Key",
        ],
        "the handshake's lines lead: {request}"
    );
    // Then the opening fields, each line once, a repeated name's lines together.
    let mut rest = names[5..].to_vec();
    let auth_at = rest
        .iter()
        .position(|n| *n == "authorization")
        .expect("authorization");
    assert_eq!(rest.get(auth_at + 1), Some(&"authorization"), "{request}");
    rest.sort_unstable();
    assert_eq!(
        rest,
        ["authorization", "authorization", "x-plane"],
        "{request}"
    );
    assert!(
        request.contains("Host: svc.test:9\r\n"),
        "the opening host is not copied"
    );
    assert!(
        request.find("Bearer k") < request.find("Second k"),
        "a repeated name's lines keep their order"
    );
}

/// A REFUSED UPGRADE'S BODY CUT SHORT BY THE CARRIER ENDS FAILED (Q128 transport-ws LOW, reader r51
/// on 3286006): a carrier that ends before the declared `Content-Length` (or before the last chunk)
/// ends the frames failed, not whole. RED before the fix: a short body read as a whole one.
#[test]
fn a_refused_upgrades_short_body_ends_failed() {
    for (head, body) in [
        (
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 10\r\n\r\n",
            &b"short"[..],
        ),
        (
            "HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n",
            &b"a\r\nshort"[..],
        ),
    ] {
        let framer = WsFramer::new(0);
        let mut out = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
            .expect("the dial opens");
        let mut wire = head.as_bytes().to_vec();
        wire.extend_from_slice(body);
        let mut heard = Out::default();
        framer
            .ingest(state, &wire, true, &mut heard)
            .expect("the far end answered");
        assert!(heard.ended, "{head}: the frames end");
        assert!(framer.failed(state), "{head}: a short body ends failed");
    }
    // A body the carrier's end does not cut is whole.
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut heard = Out::default();
    framer
        .ingest(
            state,
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\nok",
            true,
            &mut heard,
        )
        .expect("the far end answered");
    assert!(heard.ended && !framer.failed(state));
}

/// A MALFORMED CHUNKED CODING ENDS FAILED (Q128 transport-ws MEDIUM, reader r162 on 0769fe6): a
/// refused upgrade's chunked body whose chunk-size is not hex, or whose chunk data is not followed
/// by its line end, is not a whole body: the frames end, failed. RED before the fix: the decoder
/// stopped there and the body read as whole and cleanly ended.
#[test]
fn a_malformed_chunked_body_ends_failed() {
    for body in [
        &b"zz\r\nhello\r\n0\r\n\r\n"[..],
        &b"5\r\nhelloXX\r\n0\r\n\r\n"[..],
    ] {
        let framer = WsFramer::new(0);
        let mut out = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
            .expect("the dial opens");
        let mut wire = b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        wire.extend_from_slice(body);
        let mut heard = Out::default();
        framer
            .ingest(state, &wire, false, &mut heard)
            .expect("the far end answered");
        assert!(heard.ended, "{body:?}: the frames end");
        assert!(
            framer.failed(state),
            "{body:?}: a malformed coding ends failed"
        );
    }
}

/// A REFUSED UPGRADE'S `Retry-After` IS READ IN BOTH OF RFC 9110's FORMS (Q128 transport-ws LOW,
/// reader r72 on f876543), as the http framer reads it: delay-seconds, and an IMF-fixdate as the
/// seconds left until it (`0` once past). RED before the fix: the HTTP-date form was dropped.
#[test]
fn a_retry_after_is_read_in_both_forms() {
    let mut h = HeaderMap::new();
    h.insert("retry-after", HeaderValue::from_static("7"));
    assert_eq!(retry_after(&h, 0), Some(7));
    // 1445412480 = Wed, 21 Oct 2015 07:28:00 GMT.
    h.insert(
        "retry-after",
        HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
    );
    assert_eq!(retry_after(&h, 1_445_412_470), Some(10));
    assert_eq!(retry_after(&h, 1_445_412_490), Some(0), "past: no wait");
    h.insert("retry-after", HeaderValue::from_static("soon"));
    assert_eq!(retry_after(&h, 0), None);
}

/// A REFUSED UPGRADE WITH A STATUS THAT CARRIES NO BODY ENDS AT ITS HEAD (Q128 transport-ws LOW,
/// reader r72 on f876543; RFC 9112 §6.3: 1xx, 204 and 304 carry none), on a kept-alive carrier.
/// RED before the fix: the frames waited for the carrier to close.
#[test]
fn a_bodiless_refusal_ends_at_its_head() {
    for answer in [
        &b"HTTP/1.1 304 Not Modified\r\n\r\n"[..],
        &b"HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n"[..],
    ] {
        let framer = WsFramer::new(0);
        let mut out = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
            .expect("the dial opens");
        let mut heard = Out::default();
        framer
            .ingest(state, answer, false, &mut heard)
            .expect("the far end answered");
        assert!(
            heard.ended,
            "{}: ended at its head",
            String::from_utf8_lossy(answer)
        );
        assert!(!framer.failed(state));
    }
}

/// A dialled head's reason phrase is the status line's text after its code, once the line is whole.
#[test]
fn a_reason_phrase_is_read_off_a_whole_status_line() {
    assert_eq!(
        reason_phrase(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"),
        Some(b"Switching Protocols".to_vec())
    );
    assert_eq!(
        reason_phrase(b"HTTP/1.1 401 Unauthorized"),
        None,
        "not whole yet"
    );
    assert_eq!(reason_phrase(b"HTTP/1.1 204 \r\n"), None, "no phrase");
}

/// The close code of the first close frame in a client's (masked) `wire`.
fn close_code(wire: &[u8]) -> Option<u16> {
    let mut at = 0;
    while at + 2 <= wire.len() {
        let op = wire[at] & 0x0f;
        let len = usize::from(wire[at + 1] & 0x7f);
        let mask = &wire[at + 2..at + 6];
        let payload = &wire[at + 6..at + 6 + len];
        if op == 0x8 && len >= 2 {
            return Some(u16::from_be_bytes([
                payload[0] ^ mask[0],
                payload[1] ^ mask[1],
            ]));
        }
        at += 6 + len;
    }
    None
}

/// A REFUSAL CLOSES WITH THE CODE ITS NEUTRAL STATUS MAPS TO (the plane seam: a neutral status the
/// transport maps to its wire): 401/403 policy (1008), 413 too big (1009), 429/503 try again later
/// (1013), another 5xx internal error (1011), none stated normal (1000). RED before the fix: every
/// refusal closed 1000.
#[test]
fn a_refusal_closes_with_the_code_its_status_maps_to() {
    for (status, code) in [
        (0, 1000),
        (401, 1008),
        (403, 1008),
        (413, 1009),
        (429, 1013),
        (503, 1013),
        (500, 1011),
    ] {
        let framer = WsFramer::new(0);
        let mut out = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
            .expect("the dial opens");
        let request = String::from_utf8(out.sent.clone()).unwrap();
        framer
            .ingest(state, &switching(&request), false, &mut Out::default())
            .expect("open");
        let mut refused = Out::default();
        framer
            .refusal_with(state, None, b"no", status, &mut refused)
            .expect("refused");
        assert_eq!(close_code(&refused.sent), Some(code), "status {status}");
    }
}

/// A TEXT MESSAGE HELD WHILE THE DIAL'S HANDSHAKE RUNS IS CHECKED AT THE CALL, as the open
/// connection checks it: bytes that are not UTF-8 fail the write, before they are held, so a bad
/// message never tears the connection down later with the good ones queued ahead of it. RED before
/// the fix: the held message was accepted and failed only at the replay.
#[test]
fn a_held_text_message_that_is_not_utf8_fails_at_the_call() {
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut early = Out::default();
    framer
        .emit_text(state, b"fine", true, true, &mut early)
        .expect("a text message is held");
    assert!(
        framer
            .emit_text(state, b"\xff\xfe", true, true, &mut early)
            .is_err(),
        "not UTF-8: refused at the call"
    );
    // The connection lives on: the handshake completes and the good message goes out.
    let request = String::from_utf8(out.sent.clone()).unwrap();
    let mut done = Out::default();
    framer
        .ingest(state, &switching(&request), false, &mut done)
        .expect("the handshake completes");
    assert_eq!(opcodes(&done.sent), [0x1]);
}

/// The payload of the first data frame (text or binary) in a client's (masked) `wire`.
fn first_data_payload(wire: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut at = 0;
    while at + 6 <= wire.len() {
        let op = wire[at] & 0x0f;
        let len = usize::from(wire[at + 1] & 0x7f);
        assert!(len < 126, "short frames only");
        let mask = &wire[at + 2..at + 6];
        let payload: Vec<u8> = wire[at + 6..at + 6 + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        if op == 0x1 || op == 0x2 || op == 0x0 {
            return Some((op, payload));
        }
        at += 6 + len;
    }
    None
}

/// A REFUSAL GOES OUT AS ITS OWN MESSAGE (codeaudit r1 g1): pieces of an unfinished outbound message
/// are dropped, not glued to the refusal's front. RED before the fix: the first data frame carried
/// the half reply followed by the refusal.
#[test]
fn a_refusal_is_not_glued_onto_a_gathered_partial_message() {
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let request = String::from_utf8(out.sent.clone()).unwrap();
    framer
        .ingest(state, &switching(&request), false, &mut Out::default())
        .expect("open");
    framer
        .emit_text(state, b"half a reply", false, true, &mut Out::default())
        .expect("gathered");
    let mut refused = Out::default();
    framer
        .refusal_with(state, None, b"refused", 401, &mut refused)
        .expect("refused");
    let (_, payload) = first_data_payload(&refused.sent).expect("a data frame");
    assert_eq!(payload, b"refused".to_vec());
}

/// A BARE-LF RESPONSE HEAD IS READ AS THE PROTOCOL LIBRARY READS IT (codeaudit r1 g1): the status
/// line ends at the first line feed, and the head at the first empty line, so the reason phrase is
/// just the phrase and the body that arrived with the head is handed up. RED before the fix: the
/// reason phrase spanned header lines and the body was dropped.
#[test]
fn a_bare_lf_response_head_is_read_whole() {
    assert_eq!(
        reason_phrase(b"HTTP/1.1 401 Unauthorized\nX-A: b\n\n"),
        Some(b"Unauthorized".to_vec())
    );
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut heard = Out::default();
    framer
        .ingest(
            state,
            b"HTTP/1.1 401 Unauthorized\nX-A: b\nContent-Length: 5\n\nhello",
            false,
            &mut heard,
        )
        .expect("the far end answered");
    assert_eq!(heard.frames[1..].concat(), b"hello".to_vec());
    assert!(heard.ended && !framer.failed(state));
}

/// Dial, ingest `wire` (the carrier ended or not), and hand back what the framer produced.
fn refused_with(wire: &[u8], carrier_ended: bool) -> (WsFramer, u64, Out) {
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let mut heard = Out::default();
    framer
        .ingest(state, wire, carrier_ended, &mut heard)
        .expect("the far end answered");
    (framer, state, heard)
}

/// `Retry-After` delay-seconds is 1*DIGIT (RFC 9110 §10.2.3): a signed number is not one. RED before
/// the fix: `+30` read as 30.
#[test]
fn a_signed_retry_after_is_not_delay_seconds() {
    let mut h = HeaderMap::new();
    h.insert("retry-after", HeaderValue::from_static("+30"));
    assert_eq!(retry_after(&h, 0), None);
    h.insert("retry-after", HeaderValue::from_static("30"));
    assert_eq!(retry_after(&h, 0), Some(30));
}

/// A chunk-size is 1*HEXDIG (RFC 9112 §7.1): a signed one is malformed. RED before the fix: `+5`
/// was read as a chunk of 5.
#[test]
fn a_signed_chunk_size_is_malformed() {
    let (framer, state, heard) = refused_with(
        b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n",
        false,
    );
    assert!(heard.ended, "the frames end");
    assert!(framer.failed(state), "a signed chunk-size ends failed");
}

/// A `Content-Length` is 1*DIGIT, and every value stated must agree (RFC 9110 §8.6, RFC 9112 §6.3):
/// otherwise the body is failed at once, not read as close-delimited. RED before the fix: `+5` read
/// as 5, a conflict took the first value, a list was not read.
#[test]
fn an_invalid_or_conflicting_content_length_ends_failed() {
    for head in [
        "Content-Length: +5\r\n",
        "Content-Length: 5\r\nContent-Length: 6\r\n",
        "Content-Length: 5, 6\r\n",
        "Content-Length: 5,\r\n",
        "Content-Length: \r\n",
    ] {
        let wire = format!("HTTP/1.1 401 Unauthorized\r\n{head}\r\nhello");
        let (framer, state, heard) = refused_with(wire.as_bytes(), false);
        assert!(heard.ended, "{head:?}: the frames end");
        assert!(framer.failed(state), "{head:?}: ends failed");
    }
    // Agreeing values are one length.
    for head in [
        "Content-Length: 5, 5\r\n",
        "Content-Length: 5\r\nContent-Length: 5\r\n",
    ] {
        let wire = format!("HTTP/1.1 401 Unauthorized\r\n{head}\r\nhelloEXTRA");
        let (framer, state, heard) = refused_with(wire.as_bytes(), false);
        assert!(heard.ended && !framer.failed(state), "{head:?}: whole");
        assert_eq!(heard.frames[1..].concat(), b"hello".to_vec(), "{head:?}");
    }
}

/// A `Transfer-Encoding` whose final coding is not `chunked` leaves the body to run to the carrier's
/// end, `Content-Length` ignored (RFC 9112 §6.3). RED before the fix: the length was honoured.
#[test]
fn a_non_chunked_transfer_encoding_overrides_content_length() {
    let (framer, state, heard) = refused_with(
        b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: gzip\r\nContent-Length: 2\r\n\r\nokmore",
        true,
    );
    assert!(heard.ended && !framer.failed(state));
    assert_eq!(heard.frames[1..].concat(), b"okmore".to_vec());
}

/// AFTER THE PEER'S CLOSE, WHAT ARRIVES IS NOBODY'S (codeaudit r1 g1): the frames ended, the machine
/// no longer reads, so later bytes are not kept. RED before the fix: they were appended to the
/// pipe's inbound without end.
#[test]
fn nothing_is_kept_after_the_peers_close() {
    let upgrade = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\n\
        Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open(Side::Accept, "", &ConnFacts::default(), &mut out)
        .expect("an accepted framing opens");
    framer
        .ingest(state, upgrade, false, &mut out)
        .expect("the upgrade is answered");
    // A client's masked (all-zero key) close frame.
    let mut closed = Out::default();
    framer
        .ingest(state, &[0x88, 0x80, 0, 0, 0, 0], false, &mut closed)
        .expect("the peer closes");
    assert!(closed.ended, "the frames end");
    assert_eq!(framer.inbound_len(state), Some(0));
    for _ in 0..3 {
        framer
            .ingest(state, &[0x81, 0x80, 0, 0, 0, 0], false, &mut Out::default())
            .expect("ingested");
        assert_eq!(framer.inbound_len(state), Some(0), "nobody's bytes");
    }
}
