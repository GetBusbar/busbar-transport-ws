// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEXT MESSAGE THAT TURNS INVALID UTF-8 FAILS THE CONNECTION AT THE BAD BYTE (RFC 6455 section

use busbar_contract::transport::wire::CloseReason;

use crate::frame::{Framed, FramerOut, HostTime, Side};

use crate::transport::WsFramer;

const UPGRADE: &[u8] = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const TEXT: u8 = 0x1;
const CONTINUATION: u8 = 0x0;

#[derive(Default)]
struct Out {
    sent: Vec<u8>,
    frames: Vec<Vec<u8>>,
    ended: bool,
}

impl FramerOut for Out {
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        self.frames.push(piece.bytes.to_vec());
    }
    fn end(&mut self) {
        self.ended = true;
    }
    fn now(&self) -> HostTime {
        HostTime::default()
    }
}

/// A masked client frame.
fn client(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut f = vec![(u8::from(fin) << 7) | opcode];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n <= 0xffff => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(k, b)| b ^ mask[k % 4]));
    f
}

fn open(framer: &WsFramer) -> u64 {
    let mut out = Out::default();
    let state = framer.open(Side::Accept, "", &mut out).expect("opens");
    framer
        .ingest(state, UPGRADE, false, &mut out)
        .expect("the upgrade is answered");
    state
}

/// The close code the framing writes when closed (unmasked server close frame).
fn close_code(framer: &WsFramer, state: u64) -> Option<u16> {
    let mut out = Out::default();
    framer.close(state, CloseReason::Normal, &mut out);
    let w = &out.sent;
    (w.len() >= 4 && w[0] & 0x0f == 0x8).then(|| u16::from_be_bytes([w[2], w[3]]))
}

/// Ingest `chops` in order; each must leave the connection alive except the last, which must end

fn fails_at_last(chops: &[Vec<u8>]) {
    let framer = WsFramer::new(0);
    let state = open(&framer);
    let (last, early) = chops.split_last().unwrap();
    for chop in early {
        let mut out = Out::default();
        framer.ingest(state, chop, false, &mut out).unwrap();
        assert!(
            !out.ended && out.frames.is_empty(),
            "alive before the bad byte"
        );
    }
    let mut out = Out::default();
    framer.ingest(state, last, false, &mut out).unwrap();
    assert!(out.ended && out.frames.is_empty(), "failed at the bad byte");
    assert_eq!(close_code(&framer, state), Some(1007));
}

/// An invalid byte in a nonfinal fragment fails before the complete message arrives.

#[test]
fn an_invalid_byte_in_a_non_final_fragment_fails_before_the_message_ends() {
    fails_at_last(&[
        client(false, TEXT, "κόσμε".as_bytes()),
        client(false, CONTINUATION, &[0xf4, 0x90, 0x80, 0x80]),
    ]);
}

/// An invalid continuation across fragments fails at the invalid byte.

#[test]
fn an_invalid_continuation_across_fragments_fails_at_that_byte() {
    fails_at_last(&[
        client(false, TEXT, &[b'a', 0xe1, 0xbd]),
        client(false, CONTINUATION, &[0x41]),
    ]);
}

/// An invalid byte inside a frame fails when the input chunk containing it arrives.

#[test]
fn an_invalid_byte_inside_one_frame_fails_at_its_chop() {
    let mut payload = "κόσμε".as_bytes().to_vec();
    payload.extend_from_slice(&[0xf4, 0x90, 0x80, 0x80]);
    payload.extend_from_slice(b"edited");
    let frame = client(true, TEXT, &payload);
    let head = frame.len() - payload.len();
    let good = head + "κόσμε".len();

    fails_at_last(&[frame[..good].to_vec(), frame[good..good + 4].to_vec()]);
    fails_at_last(&[
        frame[..good].to_vec(),
        frame[good..good + 1].to_vec(),
        frame[good + 1..good + 2].to_vec(),
    ]);
}

/// A code point split across fragments, and a masked frame header split from its payload, are

#[test]
fn a_code_point_split_across_fragments_is_still_accepted() {
    let framer = WsFramer::new(0);
    let state = open(&framer);
    let text = "a\u{00b5}\u{20ac}\u{1f600}z";
    let bytes = text.as_bytes();
    let mut frames = Vec::new();
    for (k, b) in bytes.iter().enumerate() {
        let opcode = if k == 0 { TEXT } else { CONTINUATION };
        let mut out = Out::default();
        framer
            .ingest(
                state,
                &client(k + 1 == bytes.len(), opcode, &[*b]),
                false,
                &mut out,
            )
            .unwrap();
        assert!(!out.ended, "a valid split is no failure");
        frames.extend(out.frames);
    }
    assert_eq!(frames.concat(), bytes);
}

/// Control payloads are octets even while a text code point is unfinished. Splitting each

#[test]
fn split_extended_headers_and_interleaved_controls_preserve_text_state() {
    for len in [126, 65_536] {
        let framer = WsFramer::new(0);
        let state = open(&framer);
        let mut text = vec![b'a'; len - 1];
        text.push(0xe1);
        let first = client(false, TEXT, &text);
        let header = first.len() - text.len();
        for byte in &first[..header] {
            let mut out = Out::default();
            framer.ingest(state, &[*byte], false, &mut out).unwrap();
            assert!(!out.ended && out.frames.is_empty());
        }
        let mut out = Out::default();
        framer
            .ingest(state, &first[header..], false, &mut out)
            .unwrap();
        assert!(!out.ended && out.frames.is_empty());
        for opcode in [0x9, 0xa] {
            let mut out = Out::default();
            framer
                .ingest(state, &client(true, opcode, &[0xff, 0xfe]), false, &mut out)
                .unwrap();
            assert!(!out.ended && out.frames.is_empty());
            if opcode == 0x9 {
                assert_eq!(out.sent, [0x8a, 2, 0xff, 0xfe], "the ping is answered");
            }
        }
        let mut out = Out::default();
        framer
            .ingest(
                state,
                &client(true, CONTINUATION, &[0xbd, 0xb5]),
                false,
                &mut out,
            )
            .unwrap();
        text.extend_from_slice(&[0xbd, 0xb5]);
        assert!(!out.ended);
        assert_eq!(out.frames, [text]);
    }
}

#[test]
fn interleaved_controls_do_not_reset_an_unfinished_text_code_point() {
    fails_at_last(&[
        client(false, TEXT, &[0xe1, 0xbd]),
        client(true, 0x9, &[0xff]),
        client(true, 0xa, &[0xfe]),
        client(false, CONTINUATION, b"A"),
    ]);
}

/// Text scanning starts at the handshake boundary rather than a delimiter inside frame data.

#[test]
fn a_handshake_call_ending_mid_frame_in_crlfcrlf_does_not_arm_the_scan() {
    let mut payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    let split = payload.len();
    payload.extend_from_slice(&[0x81, 0x05, 0xff, 0xfe, 0xfd, 0xfc, 0xfb]);

    let mut frame = vec![0x82, payload.len() as u8];
    frame.extend_from_slice(&payload);
    let at = 2 + split;
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer
        .open(Side::Dial, "ws://svc.test/x", &mut out)
        .expect("the dial opens");
    let request = String::from_utf8(out.sent).expect("an upgrade request");
    let key = request
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .expect("a key");
    let mut first = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        tungstenite::handshake::derive_accept_key(key.as_bytes())
    )
    .into_bytes();
    first.extend_from_slice(&frame[..at]);
    assert!(first.ends_with(b"\r\n\r\n"));
    let mut opened = Out::default();
    framer
        .ingest(state, &first, false, &mut opened)
        .expect("the upgrade completes");
    assert!(!opened.ended, "the session is open");
    let mut rest = Out::default();
    framer
        .ingest(state, &frame[at..], false, &mut rest)
        .expect("the rest of the frame");
    assert!(!rest.ended, "the connection lives");
    assert_eq!(rest.frames, [payload], "the binary message, whole");
    assert!(!framer.failed(state));
}

/// Bytes arriving after the peer's close are not judged as data.

#[test]
fn bytes_after_the_peers_close_are_not_judged() {
    let framer = WsFramer::new(0);
    let state = open(&framer);
    let mut call = client(true, 0x8, &1000_u16.to_be_bytes());
    call.extend(client(true, TEXT, &[0xff, 0xfe]));
    let mut out = Out::default();
    framer.ingest(state, &call, false, &mut out).unwrap();
    assert!(out.ended, "the peer closed");
    assert_eq!(framer.failure(state), None, "cleanly");
}

/// Protocol-invalid frame headers are left to the protocol library rather than judged as text.

#[test]
fn a_frame_that_breaks_the_protocol_is_not_judged_as_text() {
    let unmasked = vec![0x81, 0x05, 0xff, 0xfe, 0xfd, 0xfc, 0xfb];
    let mut reserved = client(true, TEXT, &[0xff, 0xfe, 0xfd, 0xfc, 0xfb]);
    reserved[0] |= 0x40;
    for frame in [unmasked, reserved] {
        let framer = WsFramer::new(0);
        let state = open(&framer);
        let mut out = Out::default();
        framer
            .ingest(state, &frame[..frame.len() - 2], false, &mut out)
            .unwrap();
        assert!(
            !out.ended,
            "{frame:02x?}: nothing is judged before the frame completes"
        );
        framer
            .ingest(state, &frame[frame.len() - 2..], false, &mut out)
            .unwrap();
        assert!(out.ended, "{frame:02x?}: the frame fails the connection");
        assert_eq!(
            framer.failure(state),
            Some("the far end broke the WebSocket protocol"),
            "{frame:02x?}"
        );
        assert_eq!(close_code(&framer, state), Some(1002), "{frame:02x?}");
    }
}

/// An accepted request followed by frame bytes preserves the correct text-scan boundary.

#[test]
fn an_accepted_call_with_frame_bytes_after_a_chunk_sized_request_does_not_arm_the_scan() {
    let head = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Pad: ";
    let mut request = head.to_vec();
    request.resize(4096 - 4, b'p');
    request.extend_from_slice(b"\r\n\r\n");
    assert_eq!(request.len(), 4096);

    let payload = [0xaa, 0xbb, 0x81, 0x82, 0, 0, 0, 0, 0xff, 0xff];
    let mut frame = vec![0x82, 0x80 | payload.len() as u8, 0, 0, 0, 0];
    frame.extend_from_slice(&payload);
    let framer = WsFramer::new(0);
    let mut out = Out::default();
    let state = framer.open(Side::Accept, "", &mut out).expect("opens");
    let mut first = request;
    first.extend_from_slice(&frame[..8]);
    framer
        .ingest(state, &first, false, &mut out)
        .expect("the upgrade is answered");
    assert!(out.sent.starts_with(b"HTTP/1.1 101"), "switching protocols");
    let mut rest = Out::default();
    framer
        .ingest(state, &frame[8..], false, &mut rest)
        .expect("the rest of the frame");
    assert!(!rest.ended, "the connection lives");
    assert_eq!(rest.frames, [payload.to_vec()], "the binary message, whole");
}

/// Invalid text received before the carrier ends remains the reported failure.

#[test]
fn invalid_text_before_the_carriers_end_is_the_stated_failure() {
    let framer = WsFramer::new(0);
    let state = open(&framer);
    let frame = client(true, TEXT, &[0xff, 0xfe, 0xfd]);
    let mut out = Out::default();
    framer.ingest(state, &frame[..7], true, &mut out).unwrap();
    assert!(out.ended);
    assert_eq!(
        framer.failure(state),
        Some("the far end sent a text message that is not UTF-8")
    );
}

/// Out-of-order frames are left to the protocol library rather than judged as text.

#[test]
fn an_out_of_order_frame_inside_a_text_message_is_not_judged_as_text() {
    for opcode in [TEXT, 0x3] {
        let framer = WsFramer::new(0);
        let state = open(&framer);
        let mut first = client(false, TEXT, b"ok");
        let bad = client(true, opcode, &[0xff, 0xfe, 0xfd, 0xfc, 0xfb]);
        first.extend_from_slice(&bad[..bad.len() - 2]);
        let mut out = Out::default();
        framer.ingest(state, &first, false, &mut out).unwrap();
        framer
            .ingest(state, &bad[bad.len() - 2..], false, &mut out)
            .unwrap();
        assert!(out.ended, "{opcode}");
        assert_eq!(
            framer.failure(state),
            Some("the far end broke the WebSocket protocol"),
            "{opcode}"
        );
        assert_eq!(close_code(&framer, state), Some(1002), "{opcode}");
    }
}
