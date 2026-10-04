// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `ws` DOOR AGAINST RFC 6455, AS AUTOBAHN|TESTSUITE GRADES IT: the accepted end of the door,
//! driven over the transport kind's table exactly as the connector drives it, with a far end that
//! writes raw client frames (masked, chopped, broken on purpose) and reads the raw frames the door
//! answers. Each case is one the Autobahn measure of the door failed (CONFORMANCE-RIGS, 2026-10-02):
//!
//! * the message KIND: a text message's pieces state `PIECE_TEXT` and a binary one's do not, and an
//!   `emit` stating `EMIT_TEXT` goes out as a text message, any other as binary (Autobahn 1.1.x,
//!   5.x, 6.x, 9.x, 10.1.1: "expected text message, got binary");
//! * the CLOSE: the peer's close code comes back (RFC 6455 §5.5.1), and 1001 is never this end's
//!   answer to a peer that left;
//! * a FAILURE after a message: the message is handed up and answered before the close, and the
//!   close carries the failure's code (Autobahn 3.2-3.4, 4.1.3-5, 4.2.3-5, 5.15: NON-STRICT/FAILED);
//! * a text payload that is not UTF-8 fails the connection as the bad bytes arrive, not when the
//!   frame completes (Autobahn 6.4.3, 6.4.4: NON-STRICT).

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{AbiStr, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::check::check_framer;
use busbar_contract::abi::transport::{
    slot, BeginIn, EmitIn, FinishIn, FramePiece, FramerOut, FramerSink, IngestIn, Ops, CLOSE_DRAIN,
    CLOSE_NORMAL, CLOSE_PEER_CLOSED, EMIT_TEXT, PIECE_END_OF_FRAME, PIECE_TEXT, SIDE_ACCEPT,
    YIELD_ENDED, YIELD_MORE,
};

/// A message's kind as this harness names it: what its pieces state (`PIECE_TEXT` or nothing) and
/// what an `emit` asks for (`EMIT_TEXT` or nothing). The transport ABI states text and nothing
/// else; absent is binary (ARCHITECT, C19-TAIL U5).
const UTF8: u8 = 1;
const OCTETS: u8 = 2;

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I`/`O` lead with their heads.
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*std::ptr::from_mut(o).cast::<OutHead>()).size = size_of::<O>() as u32;
    }
    (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    )
    .outcome()
}

/// What one op answered: the bytes for the far side, the frames for the layer above (each with
/// the kind its first piece stated), whether the stream ended (its empty piece),
/// and whether the connection's frames did.
#[derive(Debug, Default)]
struct Said {
    wire: Vec<u8>,
    frames: Vec<(Vec<u8>, u8)>,
    stream_end: bool,
    ended: bool,
}

/// The host: the linked door's table, an opened instance, and its buffers.
struct Host {
    ops: &'static Ops,
    inst: *mut c_void,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    open: Option<(Vec<u8>, u8)>,
}

const CAP: usize = 64 * 1024;

impl Host {
    fn new() -> Self {
        let d = busbar_transport_ws::door::door();
        // SAFETY: the door's `'static` table.
        let ops: &'static Ops = unsafe { &*(*d).ops.cast::<Ops>() };
        let mut i: OpenIn = z();
        let mut o: OpenOut = z();
        let r = call(
            ops.head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN,
        );
        assert_eq!(r, Outcome::Ready);
        Self {
            ops,
            inst: o.instance,
            wire: vec![0; CAP],
            frame: vec![0; CAP],
            pieces: vec![z(); 64],
            open: None,
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: CAP,
            frame: self.frame.as_mut_ptr(),
            frame_cap: CAP,
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 3_000_000_000,
            now_unix_ns: 1_790_000_000_000_000_000,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// Take one answer into `said`; `true` = call again.
    fn take(&mut self, o: &FramerOut, said: &mut Said) -> bool {
        let n = o.yielded.pieces_len as usize;
        check_framer(
            Outcome::Ready,
            o,
            &self.pieces[..n],
            CAP as u64,
            CAP as u64,
            self.pieces.len() as u64,
        )
        .expect("the answer passes the kind's check");
        said.wire
            .extend_from_slice(&self.wire[..o.yielded.wire_len as usize]);
        for p in &self.pieces[..n] {
            let b = &self.frame[p.offset as usize..(p.offset + p.len) as usize];
            let kind = if p.flags & PIECE_TEXT != 0 {
                UTF8
            } else {
                OCTETS
            };
            let open = self.open.get_or_insert_with(|| (Vec::new(), kind));
            open.0.extend_from_slice(b);
            if p.flags & PIECE_END_OF_FRAME != 0 {
                let (bytes, kind) = self.open.take().expect("a frame");
                // An empty piece is the stream's end (the transport ABI: an empty piece states no
                // kind and completes its frame).
                if bytes.is_empty() {
                    said.stream_end = true;
                } else {
                    said.frames.push((bytes, kind));
                }
            }
        }
        said.ended |= o.yielded.flags & YIELD_ENDED != 0;
        o.yielded.flags & YIELD_MORE != 0
    }

    fn accept(&mut self) -> u64 {
        let mut i: BeginIn = z();
        i.side = SIDE_ACCEPT;
        i.target = AbiStr {
            ptr: [].as_ptr(),
            len: 0,
        };
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN);
        assert_eq!(r, Outcome::Ready);
        let framing = o.framing;
        let said = self.ingest(framing, UPGRADE);
        assert!(
            String::from_utf8_lossy(&said.wire).starts_with("HTTP/1.1 101"),
            "the upgrade is answered"
        );
        framing
    }

    /// `ingest` `bytes`, then the re-calls; answers the outcome of the first call too.
    fn ingest_answer(&mut self, framing: u64, bytes: &[u8]) -> (Outcome, Said) {
        let mut said = Said::default();
        let mut i: IngestIn = z();
        i.framing = framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
        if r != Outcome::Ready {
            return (r, said);
        }
        let mut more = self.take(&o, &mut said);
        while more {
            let mut i: IngestIn = z();
            i.framing = framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
            assert_eq!(r, Outcome::Ready);
            more = self.take(&o, &mut said);
        }
        (r, said)
    }

    fn ingest(&mut self, framing: u64, bytes: &[u8]) -> Said {
        let (r, said) = self.ingest_answer(framing, bytes);
        assert_eq!(r, Outcome::Ready, "ingest answers READY");
        said
    }

    /// `emit` one whole message of `kind` (`UTF8` = `EMIT_TEXT`); answers the outcome and what it said.
    fn emit(&mut self, framing: u64, kind: u8, bytes: &[u8]) -> (Outcome, Said) {
        let mut said = Said::default();
        let mut i: EmitIn = z();
        i.framing = framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = 1;
        i.flags = if kind == UTF8 { EMIT_TEXT } else { 0 };
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
        if r != Outcome::Ready {
            return (r, said);
        }
        let mut more = self.take(&o, &mut said);
        while more {
            let mut i: EmitIn = z();
            i.framing = framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            assert_eq!(
                call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT),
                Outcome::Ready
            );
            more = self.take(&o, &mut said);
        }
        (r, said)
    }

    fn finish(&mut self, framing: u64, reason: u32) -> Said {
        let mut said = Said::default();
        let mut i: FinishIn = z();
        i.framing = framing;
        i.reason = reason;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.finish, self.inst, &mut i, &mut o, slot::FINISH);
        assert_eq!(r, Outcome::Ready);
        self.take(&o, &mut said);
        said
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
    }
}

const UPGRADE: &[u8] = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CONTINUATION: u8 = 0x0;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;

/// One client frame: masked (with a key that is not zero, so unmasking is exercised), `rsv` the
/// three reserved bits.
fn client(fin: bool, rsv: u8, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut f = vec![(u8::from(fin) << 7) | (rsv << 4) | opcode];
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

/// A client close frame carrying `code`.
fn close(code: u16) -> Vec<u8> {
    client(true, 0, CLOSE, &code.to_be_bytes())
}

/// The frames the door wrote (unmasked, as a server writes them): `(opcode, payload)`.
fn server_frames(mut wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while wire.len() >= 2 {
        let opcode = wire[0] & 0x0f;
        let (len, at) = match wire[1] & 0x7f {
            126 => (usize::from(u16::from_be_bytes([wire[2], wire[3]])), 4),
            127 => {
                let mut l = [0_u8; 8];
                l.copy_from_slice(&wire[2..10]);
                (u64::from_be_bytes(l) as usize, 10)
            }
            l => (usize::from(l), 2),
        };
        assert_eq!(wire[1] & 0x80, 0, "a server frame is never masked");
        out.push((opcode, wire[at..at + len].to_vec()));
        wire = &wire[at + len..];
    }
    out
}

/// The code of the close frame among `frames`, if there is one.
fn close_code(frames: &[(u8, Vec<u8>)]) -> Option<u16> {
    frames
        .iter()
        .find(|(op, _)| *op == CLOSE)
        .map(|(_, p)| u16::from_be_bytes([p[0], p[1]]))
}

// ── 1. THE MESSAGE KIND ──────────────────────────────────────────────────────────────────────────

#[test]
fn a_text_message_is_handed_up_as_utf8_and_a_binary_one_as_octets() {
    let mut h = Host::new();
    let f = h.accept();
    let said = h.ingest(f, &client(true, 0, TEXT, "Hello, world!".as_bytes()));
    println!(
        "PROOF kind: a text message is handed up as {:?}",
        said.frames
    );
    assert_eq!(
        said.frames,
        [(b"Hello, world!".to_vec(), UTF8)],
        "a text message's pieces state PIECE_TEXT"
    );
    let said = h.ingest(f, &client(true, 0, BINARY, &[0xfe, 0xff, 0x00]));
    assert_eq!(said.frames, [(vec![0xfe, 0xff, 0x00], OCTETS)]);
    // A text message in two fragments is one frame.
    let mut two = client(false, 0, TEXT, "frag".as_bytes());
    two.extend(client(true, 0, CONTINUATION, "ment".as_bytes()));
    let said = h.ingest(f, &two);
    assert_eq!(said.frames, [(b"fragment".to_vec(), UTF8)]);
}

#[test]
fn an_emit_sends_the_kind_it_states_and_binary_when_it_states_none() {
    let mut h = Host::new();
    let f = h.accept();
    let (r, said) = h.emit(f, UTF8, "Hello, world!".as_bytes());
    assert_eq!(r, Outcome::Ready);
    let frames = server_frames(&said.wire);
    println!(
        "PROOF kind: an EMIT_TEXT emit goes out as opcode {:?}",
        frames
    );
    assert_eq!(
        frames,
        [(TEXT, b"Hello, world!".to_vec())],
        "a text message"
    );
    let (_, said) = h.emit(f, OCTETS, &[1, 2, 3]);
    assert_eq!(server_frames(&said.wire), [(BINARY, vec![1, 2, 3])]);
    // An empty text message.
    let (_, said) = h.emit(f, UTF8, b"");
    assert_eq!(server_frames(&said.wire), [(TEXT, Vec::new())]);
    // Text that is not UTF-8 is refused, and nothing goes out.
    let (r, said) = h.emit(f, UTF8, &[0xce, 0xba, 0xe1, 0xbd]);
    assert_eq!(r, Outcome::Failed, "an EMIT_TEXT emit that is not UTF-8");
    assert!(said.wire.is_empty());
    // The framing still serves.
    let (r, said) = h.emit(f, UTF8, "κόσμε".as_bytes());
    assert_eq!(r, Outcome::Ready);
    assert_eq!(
        server_frames(&said.wire),
        [(TEXT, "κόσμε".as_bytes().to_vec())]
    );
}

// ── 2. THE CLOSE ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_peer_close_is_answered_with_the_peer_code_after_a_message_exchange() {
    for code in [1000_u16, 1001, 3000, 4999] {
        let mut h = Host::new();
        let f = h.accept();
        // A binary exchange: the close is the subject here, not the kind.
        let said = h.ingest(f, &client(true, 0, BINARY, b"Hello"));
        let (bytes, _) = said.frames[0].clone();
        let (_, echo) = h.emit(f, OCTETS, &bytes);
        assert_eq!(server_frames(&echo.wire), [(BINARY, b"Hello".to_vec())]);
        let said = h.ingest(f, &close(code));
        let answered = close_code(&server_frames(&said.wire));
        println!("PROOF close: the peer closed with {code}, the door answered {answered:?}");
        assert_eq!(answered, Some(code), "the peer's own code comes back");
        assert!(said.stream_end && said.ended, "and the frames end");
        let after = h.finish(f, CLOSE_NORMAL);
        assert_eq!(
            close_code(&server_frames(&after.wire)),
            None,
            "the close was answered once"
        );
    }
}

#[test]
fn closing_because_the_peer_left_is_an_orderly_close_never_going_away() {
    let mut h = Host::new();
    let f = h.accept();
    let said = h.finish(f, CLOSE_PEER_CLOSED);
    let code = close_code(&server_frames(&said.wire));
    println!("PROOF close: a close for a peer that left carries {code:?}");
    assert_eq!(
        code,
        Some(1000),
        "1001 is this end going away, not the peer"
    );
}

/// A drain closes with 1012 (Service Restart), as predev does. v1.5.5 had no WebSocket at all (no
/// ws transport, no tungstenite, no oracle cell), so it sent no drain close code; the baseline is
/// current predev (ARCHITECT ruling 2026-10-02: match 1.5.5, which here is nothing to match).
#[test]
fn a_drain_closes_with_1012() {
    let mut h = Host::new();
    let f = h.accept();
    let said = h.finish(f, CLOSE_DRAIN);
    assert_eq!(close_code(&server_frames(&said.wire)), Some(1012));
}

// ── 3. A FAILURE AFTER A MESSAGE ─────────────────────────────────────────────────────────────────

/// The far side sends `bytes` (a valid message, then a violation) in ONE chop: the message is
/// handed up, the frames end, the layer above still answers it, and the close carries `code`.
/// The messages are binary: the order is the subject here, not the kind.
fn answered_then_failed(case: &str, bytes: &[u8], code: u16) {
    let mut h = Host::new();
    let f = h.accept();
    let (r, said) = h.ingest_answer(f, bytes);
    assert_eq!(
        r,
        Outcome::Ready,
        "{case}: the message before the violation is answered"
    );
    let handed: Vec<&[u8]> = said.frames.iter().map(|(b, _)| b.as_slice()).collect();
    assert_eq!(
        handed,
        [b"Hello, world!"],
        "{case}: the message before the violation is handed up"
    );
    assert!(
        said.stream_end && said.ended,
        "{case}: the frames end at the violation"
    );
    let (r, echo) = h.emit(f, OCTETS, b"Hello, world!");
    assert_eq!(
        r,
        Outcome::Ready,
        "{case}: the layer above still answers it"
    );
    let closed = h.finish(f, CLOSE_NORMAL);
    let mut wire = echo.wire;
    wire.extend(closed.wire);
    let frames = server_frames(&wire);
    println!("PROOF strict {case}: the door wrote {frames:?}");
    assert_eq!(
        frames,
        [
            (BINARY, b"Hello, world!".to_vec()),
            (CLOSE, code.to_be_bytes().to_vec())
        ],
        "{case}: the echo, then the close with the failure's code"
    );
}

#[test]
fn a_violation_after_a_message_is_answered_after_the_message() {
    let hello = || client(true, 0, BINARY, b"Hello, world!");
    // Autobahn 3.2: a frame with a reserved bit set.
    let mut b = hello();
    b.extend(client(true, 2, BINARY, b"Hello, world!"));
    b.extend(client(true, 0, PING, b""));
    answered_then_failed("3.2 reserved bit", &b, 1002);
    // Autobahn 4.1.3: a reserved non-control opcode.
    let mut b = hello();
    b.extend(client(true, 0, 5, b""));
    b.extend(client(true, 0, PING, b""));
    answered_then_failed("4.1.3 reserved opcode", &b, 1002);
    // Autobahn 4.2.3: a reserved control opcode.
    let mut b = hello();
    b.extend(client(true, 0, 13, b""));
    b.extend(client(true, 0, PING, b""));
    answered_then_failed("4.2.3 reserved control opcode", &b, 1002);
    // Autobahn 5.15 (shape): a whole message, then a continuation with nothing to continue.
    let mut b = client(false, 0, BINARY, b"Hello, ");
    b.extend(client(true, 0, CONTINUATION, b"world!"));
    b.extend(client(false, 0, CONTINUATION, b"fragment3"));
    b.extend(client(true, 0, BINARY, b"fragment4"));
    answered_then_failed("5.15 continuation with nothing to continue", &b, 1002);
}

#[test]
fn a_violation_alone_ends_the_frames_and_closes_with_1002() {
    let mut h = Host::new();
    let f = h.accept();
    // Autobahn 3.1: a text frame with RSV1 set, no extension negotiated.
    let (r, said) = h.ingest_answer(f, &client(true, 1 << 2, TEXT, b"Hello, world!"));
    assert_eq!(
        r,
        Outcome::Ready,
        "the violation ends the frames, it is no fault"
    );
    assert!(said.frames.is_empty() && said.stream_end && said.ended);
    let closed = h.finish(f, CLOSE_NORMAL);
    assert_eq!(close_code(&server_frames(&closed.wire)), Some(1002));
}

// ── 4. TEXT THAT IS NOT UTF-8 FAILS FAST ─────────────────────────────────────────────────────────

#[test]
fn invalid_utf8_inside_one_frame_fails_the_connection_as_it_arrives() {
    // Autobahn 6.4.3: one text frame sent in three chops; the second chop makes it invalid
    // (F4 90 80 80 is past U+10FFFF). The frame is not complete when the connection must fail.
    let part1 = "κόσμε".as_bytes();
    let part2: &[u8] = &[0xf4, 0x90, 0x80, 0x80];
    let part3: &[u8] = b"edited";
    let mut payload = part1.to_vec();
    payload.extend_from_slice(part2);
    payload.extend_from_slice(part3);
    let frame = client(true, 0, TEXT, &payload);
    let header = frame.len() - payload.len();
    let (a, rest) = frame.split_at(header + part1.len());
    let (b, c) = rest.split_at(part2.len());
    // Autobahn 6.4.4: the second chop only up to the offending octet.
    let (b1, b2) = b.split_at(2);
    for (case, chops) in [("6.4.3", vec![a, b, c]), ("6.4.4", vec![a, b1, b2, c])] {
        let mut h = Host::new();
        let f = h.accept();
        let first = h.ingest(f, chops[0]);
        assert!(!first.ended, "{case}: a valid start waits for the rest");
        let second = h.ingest(f, chops[1]);
        println!(
            "PROOF utf8 {case}: after the offending chop the frames ended={}",
            second.ended
        );
        assert!(
            second.stream_end && second.ended,
            "{case}: the offending chop fails the connection at once"
        );
        let closed = h.finish(f, CLOSE_NORMAL);
        assert_eq!(
            close_code(&server_frames(&closed.wire)),
            Some(1007),
            "{case}: the close says the payload was not UTF-8"
        );
    }
}

#[test]
fn a_code_point_split_across_chops_and_fragments_is_valid() {
    let mut h = Host::new();
    let f = h.accept();
    let text = "Hello-µ@ßöäüàá-UTF-8!!";
    let frame = client(true, 0, TEXT, text.as_bytes());
    // Every byte its own chop: every multi-byte code point is split.
    let mut frames = Vec::new();
    for b in &frame {
        let said = h.ingest(f, std::slice::from_ref(b));
        assert!(!said.ended, "a split code point is no failure");
        frames.extend(said.frames);
    }
    // And fragments of one octet each.
    let bytes = text.as_bytes();
    for (k, b) in bytes.iter().enumerate() {
        let opcode = if k == 0 { TEXT } else { CONTINUATION };
        let said = h.ingest(
            f,
            &client(k + 1 == bytes.len(), 0, opcode, std::slice::from_ref(b)),
        );
        assert!(
            !said.ended,
            "a code point split across fragments is no failure"
        );
        frames.extend(said.frames);
    }
    let handed: Vec<&[u8]> = frames.iter().map(|(b, _)| b.as_slice()).collect();
    assert_eq!(handed, [bytes, bytes], "both arrive whole");
}
