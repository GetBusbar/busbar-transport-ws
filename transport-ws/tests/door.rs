// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `ws` DOOR, ON THE TRANSPORT KIND'S TABLE: the same door, compiled in and dropped in, driven the same way.
//!
//! The test is the HOST, and it holds BOTH ends: one framing dialled and one accepted, on the same
//! door, with the host carrying each one's wire bytes to the other exactly as a connector carries
//! them over a socket. Every answer is judged by the kind's own `check_framer`. The exchange: the
//! upgrade, one message each way, and an orderly close that ends the far side's stream and its
//! connection. It runs through the linked door (the dropped-in cdylib is compared in the plugin crate's conformance),
//! through a roomy sink and through one so small every op is re-called.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::host::service::SCHEME_PLAIN;
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::check::{check_framer, check_framer_fields};
use busbar_contract::abi::transport::fields::lines;
use busbar_contract::abi::transport::{
    slot, AdoptIn, BeginIn, EmitIn, FinishIn, FramePiece, FramerOut, FramerSink, IngestIn, Ops,
    RefuseIn, CLOSE_NORMAL, EMIT_TEXT, PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME,
    PIECE_FIELDS, PIECE_HAS_CODE, PIECE_STREAM_FAILED, PIECE_TEXT, SIDE_ACCEPT, SIDE_DIAL,
    STATUS_SUCCESS, YIELD_ENDED, YIELD_MORE,
};
use tungstenite::handshake::derive_accept_key;

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
    let r = (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    );
    r.outcome()
}

/// One end: its framing, and everything it has said so far.
#[derive(Default)]
struct End {
    framing: u64,
    wire: Vec<u8>,
    frames: Vec<(Vec<u8>, bool)>,
    /// Per frame in `frames`: every piece of it carried `PIECE_TEXT`.
    text: Vec<bool>,
    /// The stream ended whole (`PIECE_END`).
    stream_end: bool,
    /// Each piece that ended the stream FAILED (`PIECE_STREAM_FAILED`): its bytes, the reason.
    failures: Vec<Vec<u8>>,
    ended: bool,
    /// Each field block it heard (`PIECE_FIELDS`), never a message: its bytes, reassembled across
    /// pieces, the code and class its pieces stated (`PIECE_HAS_CODE`), whether it is whole, and
    /// how many pieces carried it.
    heads: Vec<Head>,
    /// Every piece it heard, in order: `true` = a field block's.
    order: Vec<bool>,
}

/// One field block as the host heard it.
#[derive(Debug, Default)]
struct Head {
    block: Vec<u8>,
    code: Option<u32>,
    class: u8,
    whole: bool,
    pieces: usize,
    /// The wait its piece stated (`PIECE_HAS_RETRY_AFTER`).
    retry_after: Option<u64>,
}

struct Host {
    ops: &'static Ops,
    inst: *mut c_void,
    caps: (usize, usize, usize),
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    /// Every frame byte either end answered, in order: the re-call comparison reads it.
    log: Vec<u8>,
}

impl Host {
    fn open(ops: &'static Ops, caps: (usize, usize, usize)) -> Self {
        let mut i: OpenIn = z();
        let mut o: OpenOut = z();
        assert_eq!(
            call(
                ops.head.open,
                std::ptr::null_mut(),
                &mut i,
                &mut o,
                life::OPEN
            ),
            Outcome::Ready
        );
        Self {
            ops,
            inst: o.instance,
            caps,
            wire: vec![0; caps.0],
            frame: vec![0; caps.1],
            pieces: vec![z(); caps.2],
            log: Vec::new(),
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.caps.0,
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.caps.1,
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.caps.2,
            now_monotonic_ns: 3_000_000_000,
            now_unix_ns: 1_790_000_000_000_000_000,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// Take an answer into `end`; `true` = it asked to be called again.
    fn take(&mut self, r: Outcome, o: &FramerOut, end: &mut End) -> bool {
        assert_eq!(r, Outcome::Ready);
        let n = o.yielded.pieces_len as usize;
        check_framer(
            r,
            o,
            &self.pieces[..n],
            self.caps.0 as u64,
            self.caps.1 as u64,
            self.caps.2 as u64,
        )
        .expect("the answer passes the kind's check");
        check_framer_fields(
            &self.pieces[..n],
            &self.frame[..o.yielded.frame_len as usize],
        )
        .expect("no field block carries a pseudo-field");
        end.wire
            .extend_from_slice(&self.wire[..o.yielded.wire_len as usize]);
        for p in &self.pieces[..n] {
            let b = &self.frame[p.offset as usize..(p.offset + p.len) as usize];
            self.log.extend_from_slice(b);
            if p.flags & PIECE_STREAM_FAILED != 0 {
                end.failures.push(b.to_vec());
                continue;
            }
            // The stream's end is said, and is no frame.
            if p.flags & PIECE_END != 0 {
                end.stream_end = true;
                continue;
            }
            end.order.push(p.flags & PIECE_FIELDS != 0);
            // A field block is a head (or trailers), never a message.
            if p.flags & PIECE_FIELDS != 0 {
                let open = matches!(end.heads.last(), Some(h) if !h.whole);
                assert!(
                    open || p.flags & PIECE_CONTINUED == 0,
                    "only a piece of an open block continues a line"
                );
                if !open {
                    end.heads.push(Head::default());
                }
                let head = end.heads.last_mut().expect("a head");
                head.block.extend_from_slice(b);
                head.pieces += 1;
                if p.flags & PIECE_HAS_CODE != 0 {
                    head.code = Some(p.code);
                    head.class = p.status_class;
                }
                if p.flags & busbar_contract::abi::transport::PIECE_HAS_RETRY_AFTER != 0 {
                    head.retry_after = Some(p.retry_after_secs);
                }
                head.whole = p.flags & PIECE_END_OF_FRAME != 0;
                continue;
            }
            match end.frames.last_mut() {
                Some((open, false)) => open.extend_from_slice(b),
                _ => {
                    end.frames.push((b.to_vec(), false));
                    end.text.push(true);
                }
            }
            *end.text.last_mut().expect("a frame") &= p.flags & PIECE_TEXT != 0;
            if p.flags & PIECE_END_OF_FRAME != 0 {
                end.frames.last_mut().expect("a frame").1 = true;
            }
        }
        end.ended |= o.yielded.flags & YIELD_ENDED != 0;
        o.yielded.flags & YIELD_MORE != 0
    }

    fn begin(&mut self, side: u32, target: &'static str) -> End {
        let mut end = End::default();
        let mut i: BeginIn = z();
        i.side = side;
        i.scheme = SCHEME_PLAIN;
        i.target = AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        };
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN);
        end.framing = o.framing;
        let more = self.take(r, &o, &mut end);
        self.again(more, &mut end);
        end
    }

    /// The `YIELD_MORE` re-call: an `ingest` with no new bytes, until the framing has said it all.
    fn again(&mut self, mut more: bool, end: &mut End) {
        let mut calls = 0;
        while more {
            calls += 1;
            assert!(calls < 100_000, "a re-call never ran dry");
            let mut i: IngestIn = z();
            i.framing = end.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
            more = self.take(r, &o, end);
        }
    }

    /// Carry what `from` has written to `to`.
    fn carry(&mut self, from: &mut End, to: &mut End) {
        let bytes = std::mem::take(&mut from.wire);
        self.hear(to, &bytes);
    }

    /// `to` ingests `bytes` off its wire.
    fn hear(&mut self, to: &mut End, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut i: IngestIn = z();
        i.framing = to.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
        let more = self.take(r, &o, to);
        self.again(more, to);
    }

    fn say(&mut self, end: &mut End, message: &'static str) {
        let r = self.emit(end, message.as_bytes(), 0);
        let more = self.take(r.0, &r.1, end);
        self.again(more, end);
    }

    /// One whole message from `end`, its `EmitIn::flags` as given; the raw answer.
    fn emit(&mut self, end: &End, message: &[u8], flags: u32) -> (Outcome, FramerOut) {
        let mut i: EmitIn = z();
        i.framing = end.framing;
        i.bytes = message.as_ptr();
        i.len = message.len();
        i.end_of_frame = 1;
        i.flags = flags;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
        (r, o)
    }

    fn finish(&mut self, end: &mut End) {
        let mut i: FinishIn = z();
        i.framing = end.framing;
        i.reason = CLOSE_NORMAL;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.finish, self.inst, &mut i, &mut o, slot::FINISH);
        let more = self.take(r, &o, end);
        self.again(more, end);
    }

    fn close(self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
    }
}

fn texts(e: &End) -> Vec<String> {
    e.frames
        .iter()
        .filter(|(b, whole)| *whole && !b.is_empty())
        .map(|(b, _)| String::from_utf8_lossy(b).into_owned())
        .collect()
}

/// The whole exchange; answers every frame byte either end said, for the re-call comparison.
fn exchange(label: &str, ops: &'static Ops, caps: (usize, usize, usize)) -> Vec<u8> {
    let mut host = Host::open(ops, caps);
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    assert!(
        String::from_utf8_lossy(&dial.wire).starts_with("GET /stream HTTP/1.1\r\n"),
        "a dialled framing opens with the upgrade request"
    );
    host.carry(&mut dial, &mut accept);
    assert!(String::from_utf8_lossy(&accept.wire).starts_with("HTTP/1.1 101"));
    host.carry(&mut accept, &mut dial);
    host.say(&mut dial, "hello");
    host.carry(&mut dial, &mut accept);
    host.say(&mut accept, "world");
    host.carry(&mut accept, &mut dial);
    println!(
        "PROOF {label}: accepted end heard {:?}, dialled end heard {:?}",
        texts(&accept),
        texts(&dial)
    );
    assert_eq!(texts(&accept), ["hello"]);
    assert_eq!(texts(&dial), ["world"]);
    host.finish(&mut dial);
    host.carry(&mut dial, &mut accept);
    println!(
        "PROOF {label}: after the dialled end's close the accepted end's stream ended={} connection ended={}",
        accept.stream_end,
        accept.ended
    );
    assert!(
        accept.stream_end,
        "the stream ends with its PIECE_END piece"
    );
    assert!(accept.ended, "and the connection with YIELD_ENDED");
    let log = host.log.clone();
    host.close();
    log
}

/// One client message as the wire carries it: FIN, `opcode`, masked with the all-zero key (so the
/// payload is its own masking), a payload under 126 bytes.
fn client_message(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![0x80 | opcode, 0x80 | payload.len() as u8, 0, 0, 0, 0];
    m.extend_from_slice(payload);
    m
}

/// RED (C19-TAIL U5): a TEXT message arrives as text (`PIECE_TEXT` on every piece of it) and a
/// BINARY one as binary. On the parent the door stated no text bit, so a text frame arrived as
/// binary.
fn text_and_binary(label: &str, ops: &'static Ops, caps: (usize, usize, usize)) {
    let mut host = Host::open(ops, caps);
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    host.carry(&mut accept, &mut dial);
    host.hear(&mut accept, &client_message(0x1, b"{\"t\":1}"));
    host.hear(&mut accept, &client_message(0x2, b"\x01\x02\x03"));
    println!(
        "PROOF {label}: frames {:?} text {:?}",
        accept.frames, accept.text
    );
    assert_eq!(
        accept.frames,
        [
            (b"{\"t\":1}".to_vec(), true),
            (b"\x01\x02\x03".to_vec(), true)
        ]
    );
    assert_eq!(
        accept.text,
        [true, false],
        "the text message arrives as text, the binary one as binary"
    );
    host.close();
}

/// RED (C19-TAIL U5 write): a message emitted with `EMIT_TEXT` goes out under the TEXT opcode (the
/// far end hears it as text), one without it as BINARY; text that is not UTF-8 is refused, never
/// sent under a promise it breaks. On the parent every emit went out BINARY.
fn written_as_text(label: &str, ops: &'static Ops, caps: (usize, usize, usize)) {
    let mut host = Host::open(ops, caps);
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    host.carry(&mut accept, &mut dial);
    for (message, flags) in [(&b"{\"t\":1}"[..], EMIT_TEXT), (&b"\x01\x02"[..], 0)] {
        let (r, o) = host.emit(&dial, message, flags);
        let more = host.take(r, &o, &mut dial);
        host.again(more, &mut dial);
        host.carry(&mut dial, &mut accept);
    }
    println!(
        "PROOF {label}: heard {:?} text {:?}",
        accept.frames, accept.text
    );
    assert_eq!(
        accept.frames,
        [(b"{\"t\":1}".to_vec(), true), (b"\x01\x02".to_vec(), true)]
    );
    assert_eq!(accept.text, [true, false], "written as text, heard as text");
    let (r, _) = host.emit(&dial, b"\xff\xfe", EMIT_TEXT);
    assert_ne!(r, Outcome::Ready, "text that is not UTF-8 is refused");
    host.close();
}

#[test]
fn a_message_written_as_text_goes_out_as_text_through_the_door() {
    // The linked door; the dropped-in cdylib is held equal to it by the plugin crate's conformance.
    let ops = linked();
    written_as_text("linked roomy", ops, (64 * 1024, 64 * 1024, 64));
    written_as_text("linked tight", ops, (7, 3, 1));
}

#[test]
fn a_text_message_arrives_as_text_through_the_door() {
    let ops = linked();
    text_and_binary("linked roomy", ops, (64 * 1024, 64 * 1024, 64));
    text_and_binary("linked tight", ops, (7, 3, 1));
}

/// The far end's switching answer to the upgrade request `request`, its own fields `extra`
/// (each `name: value\r\n`) after the handshake's.
fn switching(request: &[u8], extra: &str) -> Vec<u8> {
    let request = String::from_utf8_lossy(request);
    let key = request
        .lines()
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.trim()
                .eq_ignore_ascii_case("sec-websocket-key")
                .then(|| v.trim().to_string())
        })
        .expect("the upgrade request carries its key");
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nConnection: x-hop\r\n\
         Sec-WebSocket-Accept: {}\r\nX-Hop: dropped\r\n{extra}\r\n",
        derive_accept_key(key.as_bytes())
    )
    .into_bytes()
}

/// RED (HEAD-FIELDS, `BUSBAR-1.6.0.md` l.736: a transport always hands the response head up as the
/// first `Fields` piece): a SILENT far end, one that answers the upgrade with `101` and sends no
/// message, has ANSWERED. The dialled end hears the switching response as ONE field block
/// (`PIECE_FIELDS`, `PIECE_HAS_CODE` `101`, `STATUS_SUCCESS`) and no message; its fields cross in
/// the far end's order, a repeated one on its own lines, the hop-by-hop ones (and those its
/// `connection` names) and the handshake's own dropped. The far end's first message, when it
/// comes, follows the head. On the parent the dialled end discarded the response: it heard
/// nothing until the far end spoke, so the layer above never counted the far end as answered.
fn a_silent_upgrade_is_answered(label: &str, ops: &'static Ops, caps: (usize, usize, usize)) {
    let mut host = Host::open(ops, caps);
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let answer = switching(
        &dial.wire,
        "X-Request-Id: req-101\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n",
    );
    dial.wire.clear();
    host.hear(&mut dial, &answer);
    println!(
        "PROOF {label}: the silent far end's 101 heard as heads {:?}, frames {:?}",
        dial.heads, dial.frames
    );
    assert_eq!(
        dial.heads.len(),
        1,
        "the switching response is handed up as the stream's head"
    );
    let head = &dial.heads[0];
    assert!(head.whole, "the head is one whole field block");
    assert_eq!(head.code, Some(101), "carrying the switching status");
    assert_eq!(
        head.class, STATUS_SUCCESS,
        "an upgrade answered is a success"
    );
    assert_eq!(
        lines(&head.block)
            .map(|(n, v)| (
                String::from_utf8_lossy(n).into_owned(),
                String::from_utf8_lossy(v).into_owned()
            ))
            .collect::<Vec<_>>(),
        [
            ("x-request-id".to_string(), "req-101".to_string()),
            ("set-cookie".to_string(), "a=1".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
        ],
        "the far end's own fields, in its order; hop-by-hop and handshake fields dropped"
    );
    assert!(
        dial.frames.is_empty(),
        "no message arrived: the head is no message"
    );
    assert!(!dial.ended, "the connection carries on");

    // The far end speaks at last: its message follows the head.
    let mut message = vec![0x81, 4];
    message.extend_from_slice(b"late");
    host.hear(&mut dial, &message);
    assert_eq!(texts(&dial), ["late"]);
    assert_eq!(dial.heads.len(), 1, "one head per stream");
    let first_message = dial.order.iter().position(|f| !f).expect("a message piece");
    assert!(
        dial.order[..first_message].iter().all(|f| *f),
        "the head precedes the first message: {:?}",
        dial.order
    );
    host.close();
}

#[test]
fn a_silent_far_end_that_answered_the_upgrade_is_answered_through_the_door() {
    let ops = linked();
    a_silent_upgrade_is_answered("linked roomy", ops, (64 * 1024, 64 * 1024, 64));
    // A sink too small for the block: it crosses in pieces, each cut at a line's start or inside
    // a value (`PIECE_CONTINUED`), one piece per answer.
    a_silent_upgrade_is_answered("linked cut", ops, (64, 16, 1));
}

/// The accepting end's own switching answer, carried to the dialled end: its head crosses EMPTY
/// (every field of it hop-by-hop or the handshake's own), framed all the same, with its status.
#[test]
fn an_upgrade_answered_with_no_field_left_is_an_empty_head() {
    let ops = linked();
    for caps in [(64 * 1024, 64 * 1024, 64), (7, 3, 1)] {
        let mut host = Host::open(ops, caps);
        let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
        let mut accept = host.begin(SIDE_ACCEPT, "");
        host.carry(&mut dial, &mut accept);
        host.carry(&mut accept, &mut dial);
        assert_eq!(dial.heads.len(), 1, "{caps:?}: the head is handed up");
        let head = &dial.heads[0];
        assert!(head.whole && head.block.is_empty(), "{caps:?}: {head:?}");
        assert_eq!(head.pieces, 1, "{caps:?}: one empty fields piece");
        assert_eq!(head.code, Some(101), "{caps:?}");
        assert!(dial.frames.is_empty(), "{caps:?}: and no message");
        host.close();
    }
}

fn linked() -> &'static Ops {
    let d = busbar_transport_ws::door::door();
    // SAFETY: the door's `'static` table.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

#[test]
fn a_recalled_exchange_answers_nothing_twice_and_drops_nothing() {
    let l = linked();
    let roomy = exchange("linked roomy", l, (64 * 1024, 64 * 1024, 64));
    let tight = exchange("linked tight", l, (7, 3, 1));
    assert_eq!(
        roomy, tight,
        "a re-call answers nothing twice and drops nothing"
    );
}

/// THE UPGRADE IS STATED ON THE CLAIM ROW (busbar ARCHITECT ruling Q128 U7): the host reads a
/// scheme's upgrade line off its claim row's `unit0_trigger`, never off a layer list, so ws's one
/// claim states `UNIT0_UPGRADE` (as `meta.rs`'s `UNIT0_TRIGGER` does) and composes over nothing.
#[test]
fn the_ws_claim_opens_at_the_upgrade_and_composes_over_nothing() {
    use busbar_contract::abi::transport::{Claim, TransportTail, UNIT0_UPGRADE};
    let st = busbar_transport_ws::door::STATEMENT;
    // SAFETY: the Statement's kind tail is this crate's `'static` `TransportTail`, and its claim
    // rows are `claim_rows_len` `'static` rows.
    let tail = unsafe { &*st.kind_tail.cast::<TransportTail>() };
    let rows: &[Claim] =
        unsafe { std::slice::from_raw_parts(tail.claim_rows, tail.claim_rows_len) };
    assert_eq!(rows.len(), 2, "one entry, two claims: `ws` and `wss`");
    assert!(rows.iter().all(|r| r.unit0_trigger == UNIT0_UPGRADE));
    assert_eq!(tail.composes_over_len, 0);
}

/// A REFUSED UPGRADE'S WAIT CROSSES THE ABI (THE DESIGN §1: the breaker applies to every plane
/// alike; the piece's `retry_after_secs` with `PIECE_HAS_RETRY_AFTER`): a far end answering `429`
/// with `Retry-After: 7` in place of `101` is heard as one head stating `429`, its class, and the
/// seven seconds. RED before the fix: the framer read the wait and the door dropped it.
#[test]
fn a_refused_upgrade_s_retry_after_reaches_the_host() {
    let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 64));
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    dial.wire.clear();
    host.hear(
        &mut dial,
        b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(dial.heads.len(), 1, "one head");
    assert_eq!(dial.heads[0].code, Some(429));
    assert_eq!(dial.heads[0].retry_after, Some(7), "the wait crosses");
    host.close();
}

/// BEGIN REFUSES A TARGET THAT IS NOT TEXT, as `locate` does (codeaudit g2 LOW): it never dials a
/// U+FFFD-repaired address the host did not name. RED before the fix: the dial opened on the
/// repaired target.
#[test]
fn begin_refuses_a_target_that_is_not_text() {
    let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 64));
    let target: &'static [u8] = b"ws://svc.test/\xff\xfe";
    let mut i: BeginIn = z();
    i.side = SIDE_DIAL;
    i.scheme = SCHEME_PLAIN;
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    i.sink = host.sink();
    let mut o: FramerOut = z();
    let r = call(host.ops.begin, host.inst, &mut i, &mut o, slot::BEGIN);
    assert_eq!(r, Outcome::Failed, "a target that is not text is refused");
    // SAFETY: the door's error text, valid until the next call.
    let why = unsafe { std::slice::from_raw_parts(o.head.error.ptr, o.head.error.len) };
    assert_eq!(why, b"begin: the target is not text");
    host.close();
}

/// LOCATE ANSWERS AN ACCEPTING LISTENER'S OFFER (codeaudit g2 LOW; `LocateIn::accept`): a listener
/// names no far end, so the target is empty and the answer is the protocol offer alone, the same
/// `http/1.1` the dial side makes. RED before the fix: the door refused "not a ws or wss URL".
#[test]
fn locate_for_a_listener_answers_the_accepting_offer() {
    use busbar_contract::abi::transport::{LocateIn, LocateOut};
    let host = Host::open(linked(), (1024, 1024, 4));
    let mut alpn = [0_u8; 16];
    let mut i: LocateIn = z();
    i.accept = 1;
    i.alpn_buf = alpn.as_mut_ptr();
    i.alpn_cap = alpn.len();
    let mut o: LocateOut = z();
    let r = call(host.ops.locate, host.inst, &mut i, &mut o, slot::LOCATE);
    assert_eq!(r, Outcome::Ready, "a listener is located");
    assert_eq!((o.authority_written, o.name_written, o.has_name), (0, 0, 0));
    assert_eq!(o.secure, 0);
    assert_eq!(&alpn[..o.alpn_written as usize], b"\x08http/1.1");
    // The short-buffer rule: too small an ALPN buffer is told what it needs.
    i.alpn_cap = 3;
    let mut o: LocateOut = z();
    let r = call(host.ops.locate, host.inst, &mut i, &mut o, slot::LOCATE);
    assert_eq!(r, Outcome::Failed);
    assert_eq!(o.alpn_needed, 9);
    host.close();
}

/// A BODY CEILING OF ZERO IS REFUSED, NOT OPENED WITHOUT AN OUTBOUND CEILING (codeaudit g5 LOW):
/// `validate` (and `open`) answer why. RED before the fix: validate answered Ready.
#[test]
fn a_zero_message_ceiling_is_refused_by_validate_and_open() {
    use busbar_contract::abi::mechanism::call::Blob;
    use busbar_contract::abi::mechanism::lifecycle::ValidateIn;
    let settings = br#"{"limits.request_body_max_bytes": 0}"#;
    let l = linked();
    let mut i: ValidateIn = z();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..z()
    };
    let mut o: OutHead = z();
    let r = call(
        l.head.validate,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::VALIDATE,
    );
    assert_eq!(r, Outcome::Failed, "validate refuses a zero ceiling");
    // SAFETY: the door's error text, valid until the next call.
    let why = unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) };
    assert_eq!(
        why,
        b"settings: limits.request_body_max_bytes must be above 0"
    );
    let mut oi: OpenIn = z();
    oi.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..z()
    };
    let mut oo: OpenOut = z();
    let r = call(
        l.head.open,
        std::ptr::null_mut(),
        &mut oi,
        &mut oo,
        life::OPEN,
    );
    assert_eq!(r, Outcome::Failed, "open refuses a zero ceiling");
}

// ── a refused open says why (codeaudit g5 H) ─────────────────────────────────────────────────────

/// A host that serves `auth_call` and nothing else. Its `ctx.handle` says what the auth does.
mod auth_host {
    use super::*;
    use busbar_contract::abi::auth::{FieldSpan, POINT_PEER};
    use busbar_contract::abi::host::service::{
        AuthAnswer, AuthCallIn, HostSlots, ServiceFn, ServiceOut, UnitRef, FLOW_CONTINUE,
        FLOW_STOP, SERVICES,
    };
    use busbar_contract::abi::mechanism::call::{RawOutcome, Span};
    use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};

    /// The auth call fails (the host declines it).
    pub const FAILS: u64 = 1;
    /// The auth answers stop.
    pub const STOPS: u64 = 2;
    /// The auth answers continue with a line the upgrade cannot carry (`upgrade`).
    pub const BAD_LINE: u64 = 3;

    extern "C" fn auth_call(
        ctx: HostCtx,
        input: *const c_void,
        out: *mut ServiceOut,
    ) -> RawOutcome {
        // SAFETY: the door passes an `AuthCallIn` and a `ServiceOut` of the contract's sizes.
        let (i, out) = unsafe { (&*input.cast::<AuthCallIn>(), &mut *out) };
        out.size = size_of::<ServiceOut>() as u32;
        if ctx.handle == FAILS {
            out.outcome = RawOutcome::of(Outcome::Failed);
            return RawOutcome::of(Outcome::Failed);
        }
        let flow = if ctx.handle == STOPS {
            FLOW_STOP
        } else {
            FLOW_CONTINUE
        };
        let peer = i.point == POINT_PEER;
        // SAFETY: the caller's own answer slot, buffer and spans.
        unsafe {
            *i.answer = AuthAnswer {
                size: size_of::<AuthAnswer>() as u32,
                flow,
                unit: if peer {
                    UnitRef::NONE
                } else {
                    UnitRef { id: 1, mac: 1 }
                },
            };
            if ctx.handle == BAD_LINE && !peer {
                let text = b"upgradewebsocket";
                std::ptr::copy_nonoverlapping(text.as_ptr(), i.buf, text.len());
                *i.spans = FieldSpan {
                    name: Span { offset: 0, len: 7 },
                    value: Span { offset: 7, len: 9 },
                    flags: 0,
                    _reserved: 0,
                };
                out.len = text.len() as u64;
                out.items = 1;
            }
        }
        out.outcome = RawOutcome::of(Outcome::Ready);
        RawOutcome::of(Outcome::Ready)
    }

    /// An instance opened on this host, behaving as `what` says.
    pub fn open(what: u64) -> Host {
        let mut slots: HostSlots = z();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = SERVICES;
        slots.auth_call = Some(auth_call as ServiceFn);
        // The tables outlive the instance: leaked, as a host's are static.
        let slots: &'static HostSlots = Box::leak(Box::new(slots));
        let mut tables: HostTables = z();
        tables.size = size_of::<HostTables>() as u32;
        tables.ctx = HostCtx { handle: what };
        tables.services = slots;
        let tables: &'static HostTables = Box::leak(Box::new(tables));
        let l = linked();
        let mut i: OpenIn = z();
        i.host = tables;
        let mut o: OpenOut = z();
        let r = call(
            l.head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN,
        );
        assert_eq!(r, Outcome::Ready);
        Host {
            ops: l,
            inst: o.instance,
            caps: (64 * 1024, 64 * 1024, 64),
            wire: vec![0; 64 * 1024],
            frame: vec![0; 64 * 1024],
            pieces: vec![z(); 64],
            log: Vec::new(),
        }
    }
}

/// `begin` on `target`, the binding's auth at `points`; the refusal's text.
fn refused_begin(host: &mut Host, target: &'static str, points: u32) -> String {
    let mut i: BeginIn = z();
    i.side = SIDE_DIAL;
    i.scheme = SCHEME_PLAIN;
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    i.points = points;
    i.sink = host.sink();
    let mut o: FramerOut = z();
    let r = call(host.ops.begin, host.inst, &mut i, &mut o, slot::BEGIN);
    assert_eq!(r, Outcome::Failed, "the open is refused");
    // SAFETY: the door's error text, valid until the next call.
    String::from_utf8(
        unsafe { std::slice::from_raw_parts(o.head.error.ptr, o.head.error.len) }.to_vec(),
    )
    .expect("the reason is text")
}

/// EACH REFUSAL SAYS ITS OWN CAUSE: the peer point's and the head point's auth outcomes, and an
/// address the target cannot be dialled at, are told apart. RED before the fix: the head point
/// said one text for all three, the peer point one for a failure and a stop, and an address
/// said "the framing could not be opened".
#[test]
fn a_refused_open_says_why() {
    use busbar_contract::abi::auth::{POINT_HEAD, POINT_PEER};
    let cases: [(u64, u32, &str); 5] = [
        (
            auth_host::FAILS,
            POINT_PEER,
            "begin: the host's auth call failed",
        ),
        (
            auth_host::STOPS,
            POINT_PEER,
            "begin: the binding's auth stopped the connection",
        ),
        (
            auth_host::FAILS,
            POINT_HEAD,
            "begin: the host's auth call failed",
        ),
        (
            auth_host::STOPS,
            POINT_HEAD,
            "begin: the binding's auth stopped the dial",
        ),
        (
            auth_host::BAD_LINE,
            POINT_HEAD,
            "begin: the binding's auth answered a line the upgrade cannot carry",
        ),
    ];
    for (what, point, text) in cases {
        let mut host = auth_host::open(what);
        assert_eq!(refused_begin(&mut host, "ws://svc.test/", point), text);
        host.close();
    }
    let mut host = auth_host::open(0);
    assert_eq!(
        refused_begin(&mut host, "ws://u:p@host/", 0),
        "the target is not a ws:// or wss:// URL"
    );
    host.close();
}

// ── a failed stream's end piece says why (codeaudit g5 G) ────────────────────────────────────────

/// An accepted framing whose far end broke the protocol (a reserved opcode), on a host whose frame
/// buffer holds `frame_cap` bytes: the accepted end, after it has heard the violation.
fn broken_accept(frame_cap: usize) -> (Host, End) {
    let mut host = Host::open(linked(), (64 * 1024, frame_cap, 8));
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    host.carry(&mut accept, &mut dial);
    host.hear(&mut accept, &client_message(0x3, b""));
    (host, accept)
}

/// THE FAILED END PIECE CARRIES THE REASON: the bytes of the piece that ends a stream the far end
/// broke state how it broke it. RED before the fix: the piece was empty.
#[test]
fn a_failed_stream_s_end_piece_says_why() {
    let (host, accept) = broken_accept(64 * 1024);
    assert_eq!(
        accept.failures,
        [b"the far end broke the WebSocket protocol".to_vec()]
    );
    assert!(accept.ended && !accept.stream_end);
    host.close();
}

/// A FAILED PIECE IS NEVER SPLIT: a frame buffer smaller than its reason hands it as ONE piece,
/// flagged failed, its reason cut to the room; never as unflagged payload.
#[test]
fn a_failed_piece_is_never_handed_as_payload() {
    let (host, accept) = broken_accept(5);
    assert!(accept.frames.is_empty(), "no unflagged payload");
    assert_eq!(accept.failures, [b"the f".to_vec()]);
    assert!(accept.ended);
    host.close();
}

// ── a failing op's fate does not depend on the backlog (codeaudit g5 F) ──────────────────────────

/// AN OVER-CEILING EMIT FAILS THE OP, NOT THE CONNECTION, WHATEVER IS QUEUED: with pieces still
/// owed to the host, the refused message is answered `Failed` with its text, the connection is not
/// ended, a later message goes out, and the backlog is still handed over. RED before the fix: a
/// non-empty backlog turned the refusal into the connection's end.
#[test]
fn a_refused_emit_with_a_backlog_fails_the_op_and_keeps_the_connection() {
    // A sink so small every answer leaves pieces queued.
    let mut host = Host::open(linked(), (64 * 1024, 3, 1));
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    host.carry(&mut accept, &mut dial);
    let heard = [
        client_message(0x1, b"hello world"),
        client_message(0x1, b"second"),
    ]
    .concat();
    let mut i: IngestIn = z();
    i.framing = accept.framing;
    i.bytes = heard.as_ptr();
    i.len = heard.len();
    i.sink = host.sink();
    let mut o: FramerOut = z();
    let r = call(host.ops.ingest, host.inst, &mut i, &mut o, slot::INGEST);
    assert!(host.take(r, &o, &mut accept), "pieces are still owed");
    let big = vec![b'x'; 32 * 1024 * 1024 + 1];
    let (r, o) = host.emit(&accept, &big, 0);
    assert_eq!(r, Outcome::Failed, "the refused message fails the op");
    assert!(o.head.error.len > 0, "and says why");
    host.say(&mut accept, "ok");
    host.carry(&mut accept, &mut dial);
    assert_eq!(texts(&dial), ["ok"], "a later message goes out");
    assert_eq!(
        texts(&accept),
        ["hello world", "second"],
        "the backlog is handed over"
    );
    assert!(!accept.ended && !accept.stream_end);
    host.close();
}

// ── an accepted upgrade that is refused is answered (codeaudit g5 A) ─────────────────────────────

/// An upgrade request, its `Sec-WebSocket-Version` and `Sec-WebSocket-Key` lines as given.
fn upgrade_request(version: &str, key: &str) -> Vec<u8> {
    format!(
        "GET /chat HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n{key}{version}\r\n"
    )
    .into_bytes()
}

const KEY: &str = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
const REFUSED_WHY: &[u8] =
    b"the upgrade request is not a WebSocket opening handshake this end can accept";

/// What the accepted end said after being refused: answered on the wire, the stream ended FAILED
/// (never whole), the connection ended.
fn assert_answered(end: &End, status_line: &str) {
    let wire = String::from_utf8_lossy(&end.wire);
    assert!(wire.starts_with(status_line), "the wire answers: {wire:?}");
    assert!(wire.contains("Connection: close\r\n"), "{wire:?}");
    if status_line.contains("426") {
        assert!(wire.contains("Sec-WebSocket-Version: 13\r\n"), "{wire:?}");
    }
    assert_eq!(
        end.failures,
        [REFUSED_WHY.to_vec()],
        "the stream ended failed"
    );
    assert!(!end.stream_end, "never whole");
    assert!(end.ended, "the connection ended");
}

/// A REQUEST FOR A VERSION THIS END DOES NOT SPEAK IS ANSWERED 426 with the version it does (RFC
/// 6455 4.4), and one missing its key 400 (4.2.1); either way the stream ends failed. RED before
/// the fix: nothing was answered and the ingest failed with no HTTP on the wire.
#[test]
fn a_refused_upgrade_request_is_answered() {
    for (request, status) in [
        (
            upgrade_request("Sec-WebSocket-Version: 8\r\n", KEY),
            "HTTP/1.1 426",
        ),
        (
            upgrade_request("Sec-WebSocket-Version: 13\r\n", ""),
            "HTTP/1.1 400",
        ),
    ] {
        let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 8));
        let mut accept = host.begin(SIDE_ACCEPT, "");
        host.hear(&mut accept, &request);
        assert_answered(&accept, status);
        host.close();
    }
}

/// THE SAME REFUSAL THROUGH ADOPT: the request is the connection's leftover; `adopt` answers READY
/// with the 400/426 on the wire and a failed end piece.
#[test]
fn an_adopted_connection_whose_leftover_is_refused_is_answered() {
    for (request, status) in [
        (
            upgrade_request("Sec-WebSocket-Version: 8\r\n", KEY),
            "HTTP/1.1 426",
        ),
        (
            upgrade_request("Sec-WebSocket-Version: 13\r\n", ""),
            "HTTP/1.1 400",
        ),
    ] {
        let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 8));
        let mut accept = End::default();
        let mut i: AdoptIn = z();
        i.side = SIDE_ACCEPT;
        i.leftover = request.as_ptr();
        i.leftover_len = request.len();
        i.sink = host.sink();
        let mut o: FramerOut = z();
        let r = call(host.ops.adopt, host.inst, &mut i, &mut o, slot::ADOPT);
        accept.framing = o.framing;
        let more = host.take(r, &o, &mut accept);
        host.again(more, &mut accept);
        assert_answered(&accept, status);
        host.close();
    }
}

/// AN OP ON A FRAMING THAT WAS ALREADY GONE FAILS THE OP: after a successful `refuse` the state is
/// gone; a later `ingest` answers `Failed` with an explained text, and ends nothing a second time.
/// RED before the fix: it answered READY with a failed end piece reading "Closed".
#[test]
fn an_op_after_a_refuse_fails_and_does_not_end_the_stream_again() {
    let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 8));
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    let mut i: RefuseIn = z();
    i.framing = accept.framing;
    i.sink = host.sink();
    let mut o: FramerOut = z();
    let r = call(host.ops.refuse, host.inst, &mut i, &mut o, slot::REFUSE);
    assert_eq!(r, Outcome::Ready);
    let more = host.take(r, &o, &mut accept);
    host.again(more, &mut accept);
    let before = accept.failures.len();
    let bytes = client_message(0x1, b"late");
    let mut i: IngestIn = z();
    i.framing = accept.framing;
    i.bytes = bytes.as_ptr();
    i.len = bytes.len();
    i.sink = host.sink();
    let mut o: FramerOut = z();
    let r = call(host.ops.ingest, host.inst, &mut i, &mut o, slot::INGEST);
    assert_eq!(r, Outcome::Failed, "the op fails");
    // SAFETY: the door's error text, valid until the next call.
    let why = unsafe { std::slice::from_raw_parts(o.head.error.ptr, o.head.error.len) };
    assert_eq!(why, b"the connection is closed");
    assert_eq!(accept.failures.len(), before);
    host.close();
}

/// A RE-CALLED `refuse` DRAINS: the contract re-calls the same op after READY with `YIELD_MORE`.
/// A refusal larger than the wire buffer removes the framing at the first call (the close), so the
/// re-calls find it gone with bytes still owed: they answer READY and hand over every byte of the
/// refusal and then the close frame. RED before the fix: the re-call answered Failed.
#[test]
fn a_re_called_refuse_hands_over_the_whole_refusal_and_the_close() {
    let mut host = Host::open(linked(), (16, 64 * 1024, 8));
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    accept.wire.clear();
    let body = [b'r'; 100];
    let mut more = true;
    let mut calls = 0;
    while more {
        calls += 1;
        assert!(calls < 1000, "a re-call never ran dry");
        let mut i: RefuseIn = z();
        i.framing = accept.framing;
        i.bytes = body.as_ptr();
        i.len = body.len();
        i.sink = host.sink();
        let mut o: FramerOut = z();
        let r = call(host.ops.refuse, host.inst, &mut i, &mut o, slot::REFUSE);
        assert_eq!(r, Outcome::Ready, "call {calls}");
        more = host.take(r, &o, &mut accept);
    }
    assert!(calls > 1, "the refusal needed re-calls");
    let mut expect = vec![0x82, 100];
    expect.extend_from_slice(&body);
    expect.extend_from_slice(&[0x88, 2, 0x03, 0xE8]);
    assert_eq!(accept.wire, expect, "the refusal and the close, whole");
    host.close();
}
