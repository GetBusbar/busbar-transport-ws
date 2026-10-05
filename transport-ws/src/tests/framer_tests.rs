// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAL'S OPENING AND ITS MESSAGES (busbar ARCHITECT Q-L5B-WS-DIAL 2026-10-03): a dialled
//! connection's upgrade request carries the dial's opening head fields (the handshake's own
//! excepted); a message written before the handshake completes is held and goes out, in order, the
//! moment it does; a message the emit states text (`EMIT_TEXT`) goes out as a text message, any
//! other as binary.

use busbar_contract::transport::{Framed, Framer, FramerOut, HostTime, Side};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

use crate::WsFramer;

/// What one framer call produced.
#[derive(Default)]
struct Out {
    sent: Vec<u8>,
    frames: Vec<Vec<u8>>,
}

impl FramerOut for Out {
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        self.frames.push(piece.bytes.to_vec());
    }
    fn end(&mut self) {}
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

#[allow(clippy::assertions_on_constants)]
#[test]
fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::transport::wire::Unit0Trigger;
    use busbar_contract::TransportMeta;
    assert_eq!(<crate::WsFramer as TransportMeta>::KEY, "ws");
    assert!(<crate::WsFramer as TransportMeta>::SESSION);
    assert!(<crate::WsFramer as TransportMeta>::SESSION_BOUND);
    assert_eq!(
        <crate::WsFramer as TransportMeta>::UNIT0_TRIGGER,
        Some(Unit0Trigger::Upgrade)
    );
    // No transport names another: the carrier is the connector's choice and an upgrade is
    // adopted, so ws composes over nothing.
    assert!(<crate::WsFramer as TransportMeta>::COMPOSES_OVER.is_empty());
    assert!(<crate::WsFramer as TransportMeta>::UPGRADES_TO.is_empty());
    assert_eq!(<crate::WsFramer as TransportMeta>::STATUS_CLASS, None);
}

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
