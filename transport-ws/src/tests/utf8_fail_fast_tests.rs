// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEXT MESSAGE THAT TURNS INVALID UTF-8 FAILS THE CONNECTION AT THE BAD BYTE (RFC 6455 section
//! 8.1; Autobahn 6.4.3 and 6.4.4, graded NON-STRICT when the failure waits for the message or the
//! frame to complete): across fragments and inside one frame, the frames end failed (close 1007) on
//! the ingest that carries the first definitely-invalid byte, while a code point split validly
//! across fragments or chops is still accepted.

use busbar_contract::transport::{
    CloseReason, ConnFacts, Framed, Framer, FramerOut, HostTime, Side,
};

use crate::WsFramer;

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
    fn wake_at(&mut self, _: Option<u64>) {}
}

/// A masked client frame.
fn client(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut f = vec![(u8::from(fin) << 7) | opcode];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(k, b)| b ^ mask[k % 4]));
    f
}

fn open(framer: &WsFramer) -> u64 {
    let mut out = Out::default();
    let state = framer
        .open(Side::Accept, "", &ConnFacts::default(), &mut out)
        .expect("opens");
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
/// it with 1007 and hand up no frame.
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

/// RED before the fix: the failure waited for the whole message (Autobahn 6.4.3/6.4.4's
/// fragmented forms), though the second fragment, not yet final, carries an invalid sequence.
#[test]
fn an_invalid_byte_in_a_non_final_fragment_fails_before_the_message_ends() {
    fails_at_last(&[
        client(false, TEXT, "κόσμε".as_bytes()),
        client(false, CONTINUATION, &[0xf4, 0x90, 0x80, 0x80]),
    ]);
}

/// RED before the fix: the sequence is begun in one fragment and its next byte, in the following
/// fragment, is not a continuation byte.
#[test]
fn an_invalid_continuation_across_fragments_fails_at_that_byte() {
    fails_at_last(&[
        client(false, TEXT, &[b'a', 0xe1, 0xbd]),
        client(false, CONTINUATION, &[0x41]),
    ]);
}

/// RED before the fix: one frame, its payload in chops (6.4.3, 6.4.4), fails at the chop that
/// holds the bad byte, not at the frame's end. F4 90 is invalid at the second byte.
#[test]
fn an_invalid_byte_inside_one_frame_fails_at_its_chop() {
    let mut payload = "κόσμε".as_bytes().to_vec();
    payload.extend_from_slice(&[0xf4, 0x90, 0x80, 0x80]);
    payload.extend_from_slice(b"edited");
    let frame = client(true, TEXT, &payload);
    let head = frame.len() - payload.len();
    let good = head + "κόσμε".len();
    // 6.4.3: the chop holding the whole bad sequence; 6.4.4: split inside it.
    fails_at_last(&[frame[..good].to_vec(), frame[good..good + 4].to_vec()]);
    fails_at_last(&[
        frame[..good].to_vec(),
        frame[good..good + 1].to_vec(),
        frame[good + 1..good + 2].to_vec(),
    ]);
}

/// A code point split across fragments, and a masked frame header split from its payload, are
/// valid: nothing fails and the whole message arrives at its end.
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
