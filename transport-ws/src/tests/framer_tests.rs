// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::frame::{Framed, FramerOut, HostTime, Side};
use busbar_contract::transport::wire::WireStatusClass;
use tungstenite::handshake::derive_accept_key;

use crate::transport::WsFramer;
use crate::transport::{reason_phrase, retry_after};
use tungstenite::http::{HeaderMap, HeaderValue};

#[path = "reported_finish_tests.rs"]
mod reported_finish_tests;

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

#[test]
fn informational_heads_before_the_upgrade_are_nonterminal_at_every_input_split() {
    for split in 0.. {
        let framer = WsFramer::new(0);
        let mut opening = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/session", &[], &mut opening)
            .unwrap();
        let request = String::from_utf8(opening.sent).unwrap();
        let mut wire =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nX-Hint: present\r\n\r\n"
                .to_vec();
        wire.extend_from_slice(&switching(&request));
        wire.extend_from_slice(b"\x81\x02ok");
        if split > wire.len() {
            break;
        }
        let mut out = Out::default();
        framer
            .emit_text(state, b"queued", true, true, &mut out)
            .unwrap();
        assert!(out.sent.is_empty());
        framer
            .ingest(state, &wire[..split], false, &mut out)
            .unwrap();
        assert!(
            !out.ended,
            "informational response ended the stream at split {split}"
        );
        framer
            .ingest(state, &wire[split..], false, &mut out)
            .unwrap();
        assert_eq!(
            out.statuses,
            [
                Some((100, Some(WireStatusClass::Other))),
                Some((103, Some(WireStatusClass::Other))),
                Some((101, Some(WireStatusClass::Success))),
                None,
            ],
            "split {split}"
        );
        assert_eq!(out.frames.last().unwrap(), b"ok");
        assert!(out.frames[1]
            .windows(b"x-hint".len())
            .any(|w| w == b"x-hint"));
        assert_eq!(
            opcodes(&out.sent),
            [1],
            "the held message is flushed once after validation"
        );
        assert!(!out.ended);
    }
}

#[test]
fn informational_heads_cannot_replace_or_bypass_the_validated_upgrade() {
    for final_head in [
        b"".as_slice(),
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: forged\r\n\r\n".as_slice(),
    ] {
        let framer = WsFramer::new(0);
        let mut opening = Out::default();
        let state = framer.open_with(Side::Dial, "ws://127.0.0.1:9/session", &[], &mut opening).unwrap();
        let mut out = Out::default();
        framer.emit_text(state, b"queued", true, true, &mut out).unwrap();
        let mut wire = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
        wire.extend_from_slice(final_head);
        assert!(framer.ingest(state, &wire, true, &mut out).is_err());
        assert!(out.sent.is_empty(), "no held message leaves before a verified upgrade");
        assert!(!out.statuses.iter().any(|s| s.as_ref().is_some_and(|(code, _)| *code == 101)));
    }
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

    let mut early = Out::default();
    framer
        .emit_text(state, br#"{"type":"one"}"#, true, true, &mut early)
        .expect("held");
    framer
        .emit_text(state, b"\x00\x01", true, false, &mut early)
        .expect("held");
    assert!(early.sent.is_empty(), "nothing leaves before the handshake");

    let mut done = Out::default();
    framer
        .ingest(state, &switching(&request), false, &mut done)
        .expect("the handshake completes");
    assert_eq!(
        opcodes(&done.sent),
        [0x1, 0x2],
        "text, then binary, in order"
    );

    assert_eq!(done.frames, [Vec::<u8>::new()], "the head, an empty block");
    assert_eq!(
        done.statuses,
        [Some((101, Some(WireStatusClass::Success)))],
        "carrying the switching status"
    );

    let mut open = Out::default();
    framer
        .emit_text(state, br#"{"type":"two"}"#, true, true, &mut open)
        .expect("sent");
    assert_eq!(opcodes(&open.sent), [0x1]);

    let mut bad = Out::default();
    assert!(framer
        .emit_text(state, b"\xff\xfe", true, true, &mut bad)
        .is_err());
}

/// `split_ws_url` on the bracketed-IPv6 shapes. A literal address with an explicit port is the one

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

/// A refused upgrade hands the far end's response up unchanged.

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

/// A refused upgrade hands the far end's response body and reason up to the plane.

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
    let reason = framer
        .ingest_head(state, &first, false, &mut heard)
        .expect("the far end answered");
    assert_eq!(
        heard.statuses[0],
        Some((401, Some(WireStatusClass::CallerFault)))
    );
    assert_eq!(reason.as_deref(), Some(&b"Unauthorized"[..]));
    let mut rest = Out::default();
    let reason = framer
        .ingest_head(state, &body[5..], false, &mut rest)
        .expect("the rest of the body");
    assert_eq!(
        reason, None,
        "only the call that handed the head up states it"
    );
    let mut got: Vec<u8> = heard.frames[1..].concat();
    got.extend(rest.frames.concat());
    assert_eq!(got, body.to_vec(), "the whole error document, once");
}

/// A refused upgrade hands up the complete large body and the carrier's end.

#[test]
fn a_refused_upgrade_hands_up_a_large_body_and_the_carrier_end() {
    let body = vec![b'x'; 9000];

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

/// A refused upgrade's chunked body is decoded and ends at its last chunk.

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

/// An open connection refuses an outbound message exceeding its ceiling.

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

/// A refused piece releases its message's gathered pieces while the dial is handshaking.

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

/// A dialed request head preserves its field order.

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

/// A refused upgrade's body cut short by the carrier fails the stream.

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

/// A malformed chunked response body fails the stream.

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

/// `Retry-After` is read in both RFC 9110 forms: delay-seconds and HTTP-date.

#[test]
fn a_retry_after_is_read_in_both_forms() {
    let mut h = HeaderMap::new();
    h.insert("retry-after", HeaderValue::from_static("7"));
    assert_eq!(retry_after(&h, 0), Some(7));

    h.insert(
        "retry-after",
        HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
    );
    assert_eq!(retry_after(&h, 1_445_412_470), Some(10));
    assert_eq!(retry_after(&h, 1_445_412_490), Some(0), "past: no wait");
    h.insert("retry-after", HeaderValue::from_static("soon"));
    assert_eq!(retry_after(&h, 0), None);
}

/// A refused upgrade with a bodiless status ends at its response head.

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

/// A refusal is sent as its own message rather than appended to a partial outbound message.

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

/// The protocol library reads a bare-LF response head as a complete head.

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

/// `Retry-After` delay-seconds follows RFC 9110's `1*DIGIT` grammar without a sign.

#[test]
fn a_signed_retry_after_is_not_delay_seconds() {
    let mut h = HeaderMap::new();
    h.insert("retry-after", HeaderValue::from_static("+30"));
    assert_eq!(retry_after(&h, 0), None);
    h.insert("retry-after", HeaderValue::from_static("30"));
    assert_eq!(retry_after(&h, 0), Some(30));
}

/// Chunk sizes follow RFC 9112's `1*HEXDIG` grammar without a sign.

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

#[test]
fn a_non_chunked_transfer_encoding_overrides_content_length() {
    let (framer, state, heard) = refused_with(
        b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: gzip\r\nContent-Length: 2\r\n\r\nokmore",
        true,
    );
    assert!(heard.ended && !framer.failed(state));
    assert_eq!(heard.frames[1..].concat(), b"okmore".to_vec());
}

/// No further input is retained after the peer's close.

#[test]
fn nothing_is_kept_after_the_peers_close() {
    let upgrade = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\n\
        Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open(Side::Accept, "", &mut out)
        .expect("an accepted framing opens");
    framer
        .ingest(state, upgrade, false, &mut out)
        .expect("the upgrade is answered");

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

/// A successful WebSocket upgrade requires status 101, as RFC 6455 specifies.

#[test]
fn an_upgrade_answered_with_another_2xx_is_no_success() {
    for code in [200, 204, 206] {
        let wire = format!("HTTP/1.1 {code} OK\r\nContent-Length: 0\r\n\r\n");
        let (_, _, heard) = refused_with(wire.as_bytes(), false);
        assert_eq!(
            heard.statuses[0],
            Some((code, Some(WireStatusClass::Other))),
            "{code}"
        );
    }
}

/// A dial requests its subprotocol in the upgrade and checks the response against it.

#[test]
fn a_dials_subprotocol_rides_the_upgrade_and_the_answer_is_held_to_it() {
    let fields = vec![(
        "Sec-WebSocket-Protocol".to_string(),
        b"graphql-transport-ws".to_vec(),
    )];
    for (selected, opens) in [("graphql-transport-ws", true), ("mqtt", false)] {
        let framer = WsFramer::new(0);
        let mut out = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/graphql", &fields, &mut out)
            .expect("the dial opens");
        let request = String::from_utf8(out.sent.clone()).expect("an upgrade request");
        assert_eq!(
            fields_named(&request, "sec-websocket-protocol"),
            ["graphql-transport-ws"],
            "{request}"
        );
        let mut answer = switching(&request);
        answer.truncate(answer.len() - 2);
        answer.extend_from_slice(format!("Sec-WebSocket-Protocol: {selected}\r\n\r\n").as_bytes());
        let mut heard = Out::default();
        let r = framer.ingest(state, &answer, false, &mut heard);
        assert_eq!(r.is_ok(), opens, "{selected}: {r:?}");
        if opens {
            let head = String::from_utf8(heard.frames[0].clone()).unwrap();
            assert_eq!(head, format!("sec-websocket-protocol: {selected}\r\n"));
        }
    }
}

/// URI schemes are read without case sensitivity, as RFC 3986 requires.

#[test]
fn the_scheme_is_read_whatever_its_case() {
    assert_eq!(
        crate::transport::split_ws_url("WSS://host/p").unwrap(),
        (true, "host".to_string(), 443, "/p".to_string())
    );
    assert_eq!(
        crate::transport::split_ws_url("Ws://host:9/p").unwrap(),
        (false, "host".to_string(), 9, "/p".to_string())
    );
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    framer
        .open_with(Side::Dial, "wSs://api.example/v1", &[], &mut out)
        .expect("the dial opens");
    let request = String::from_utf8(out.sent).unwrap();
    assert!(request.starts_with("GET /v1 HTTP/1.1\r\n"), "{request}");
    assert_eq!(fields_named(&request, "host"), ["api.example"]);
}

/// `new(0)` places no outbound ceiling on an open connection.

#[test]
fn no_ceiling_means_no_outbound_ceiling_on_an_open_connection() {
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
        .expect("the dial opens");
    let request = String::from_utf8(out.sent.clone()).unwrap();
    framer
        .ingest(state, &switching(&request), false, &mut Out::default())
        .expect("open");
    let big = vec![b'x'; 64 * 1024 * 1024 + 1];
    let mut sent = Out::default();
    framer
        .emit_text(state, &big, true, false, &mut sent)
        .expect("no outbound ceiling");
    assert!(sent.sent.len() > big.len(), "the message goes out");
}

/// A shipped dial sends a fresh handshake key and masks every frame as RFC 6455 requires.

#[test]
fn a_shipped_dial_sends_a_fresh_key_and_masks_every_frame() {
    let open = || {
        let framer = WsFramer::unseeded(0);
        let mut out = Out::default();
        let state = framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut out)
            .expect("the dial opens");
        let request = String::from_utf8(out.sent).expect("an upgrade request");
        framer
            .ingest(state, &switching(&request), false, &mut Out::default())
            .expect("open");
        let key = fields_named(&request, "sec-websocket-key")[0].to_string();
        (framer, state, key)
    };
    let (framer, state, key) = open();
    let (_, _, other) = open();
    assert_ne!(key, "dGhlIHNhbXBsZSBub25jZQ==", "not the harness's key");
    assert_ne!(key, other, "a fresh key per dial");
    let mut masks = Vec::new();
    for message in [&b"first"[..], b"second", b"third"] {
        let mut sent = Out::default();
        framer
            .emit_text(state, message, true, false, &mut sent)
            .expect("sent");
        assert_ne!(sent.sent[1] & 0x80, 0, "masked");
        masks.push(sent.sent[2..6].to_vec());
        assert_eq!(
            first_data_payload(&sent.sent),
            Some((0x2, message.to_vec())),
            "readable under its mask"
        );
    }
    assert!(
        masks.iter().any(|m| m != &[0, 0, 0, 0]) && masks[0] != masks[1],
        "a fresh mask per frame: {masks:02x?}"
    );
}

/// A chunk-size line exceeding its bound fails the body.

#[test]
fn a_chunk_line_past_its_bound_ends_the_body_failed() {
    let mut wire = b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    wire.extend(std::iter::repeat_n(b'a', 4097));
    let (framer, state, heard) = refused_with(&wire, false);
    assert!(heard.ended, "the frames end at the bound");
    assert!(framer.failed(state), "failed, not whole");
}
