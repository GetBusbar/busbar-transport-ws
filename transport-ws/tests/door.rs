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
        i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
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
    let (r, o) = host.emit(&dial, b"\xff\xfe", EMIT_TEXT);
    assert_eq!(r, Outcome::Failed, "text that is not UTF-8 is refused");
    assert_eq!(o.yielded.wire_len, 0, "and nothing goes out");
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
    unsafe { &*(*d).ops().cast::<Ops>() }
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
    i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
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

/// A REFUSED UPGRADE'S WAIT, IN ITS HTTP-DATE FORM, CROSSES THE ABI (RFC 9110 §10.2.3): a `503`
/// whose `Retry-After` is an IMF-fixdate 120 s after the sink's unix clock (1790000000 s, so
/// 1790000120 s is Mon, 21 Sep 2026 14:15:20 GMT) is heard as 120 seconds, read against the wall
/// clock and not the monotonic one.
#[test]
fn a_refused_upgrade_s_retry_after_http_date_reaches_the_host() {
    let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 64));
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    dial.wire.clear();
    host.hear(
        &mut dial,
        b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: Mon, 21 Sep 2026 14:15:20 GMT\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(dial.heads.len(), 1, "one head");
    assert_eq!(dial.heads[0].code, Some(503));
    assert_eq!(
        dial.heads[0].retry_after,
        Some(120),
        "the date's wait crosses"
    );
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
        b"settings: limits.request_body_max_bytes must be a count of bytes above 0"
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

/// `begin` dialling `target`; the refusal's text.
fn refused_begin(host: &mut Host, target: &'static str) -> String {
    let mut i: BeginIn = z();
    i.side = SIDE_DIAL;
    i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
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

/// A refused open says its own cause: a target carrying userinfo is refused in those words.
#[test]
fn a_refused_open_says_why() {
    let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 64));
    assert_eq!(
        refused_begin(&mut host, "ws://u:p@host/"),
        "begin: the target carries userinfo; credentials never ride a URL"
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
    assert_eq!(why, b"ingest: the connection is closed");
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

/// NEW INPUT ON A FRAMING A REFUSAL ALREADY CLOSED IS NOT SWALLOWED BY THE DRAIN: an emit with
/// bytes, while the refusal is still owed, answers `Failed` with the closed text, and the refusal
/// and its close still drain in full through the `refuse` re-calls. RED before the fix: the emit
/// answered READY and its data vanished.
#[test]
fn an_emit_after_a_refuse_with_a_backlog_fails_and_the_backlog_still_drains() {
    let mut host = Host::open(linked(), (16, 64 * 1024, 8));
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    accept.wire.clear();
    let body = [b'r'; 100];
    let refuse = |host: &mut Host, accept: &mut End| {
        let mut i: RefuseIn = z();
        i.framing = accept.framing;
        i.bytes = body.as_ptr();
        i.len = body.len();
        i.sink = host.sink();
        let mut o: FramerOut = z();
        let r = call(host.ops.refuse, host.inst, &mut i, &mut o, slot::REFUSE);
        assert_eq!(r, Outcome::Ready);
        host.take(r, &o, accept)
    };
    let mut more = refuse(&mut host, &mut accept);
    assert!(more, "the refusal is still owed");
    let (r, o) = host.emit(&accept, b"new data", 0);
    assert_eq!(r, Outcome::Failed, "new data on a closed framing fails");
    // SAFETY: the door's error text, valid until the next call.
    let why = unsafe { std::slice::from_raw_parts(o.head.error.ptr, o.head.error.len) };
    assert_eq!(why, b"emit: the connection is closed");
    let mut calls = 0;
    while more {
        calls += 1;
        assert!(calls < 1000, "a re-call never ran dry");
        more = refuse(&mut host, &mut accept);
    }
    let mut expect = vec![0x82, 100];
    expect.extend_from_slice(&body);
    expect.extend_from_slice(&[0x88, 2, 0x03, 0xE8]);
    assert_eq!(accept.wire, expect, "the backlog drains in full");
    host.close();
}

// ── settings: the canonical texts (sibling alignment A, E) ───────────────────────────────────────

/// The text an answer's head names.
fn said(error: &AbiStr) -> String {
    if error.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the door's error text, valid until the next call.
    String::from_utf8(unsafe { std::slice::from_raw_parts(error.ptr, error.len) }.to_vec())
        .expect("the reason is text")
}

/// `validate` over `settings`, a reason buffer lent: its outcome and its text.
fn validate(settings: &[u8]) -> (Outcome, String) {
    use busbar_contract::abi::mechanism::call::Blob;
    use busbar_contract::abi::mechanism::lifecycle::ValidateIn;
    let mut buf = [0_u8; 256];
    let mut i: ValidateIn = z();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..z()
    };
    i.err_buf = buf.as_mut_ptr();
    i.err_cap = buf.len();
    let mut o: OutHead = z();
    let r = call(
        linked().head.validate,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::VALIDATE,
    );
    (r, said(&o.error))
}

/// `open` over `settings`, a reason buffer lent: its outcome and its text (the instance, if one
/// opened, is closed).
fn open_with(settings: &[u8]) -> (Outcome, String) {
    use busbar_contract::abi::mechanism::call::Blob;
    let mut buf = [0_u8; 256];
    let mut i: OpenIn = z();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..z()
    };
    i.err_buf = buf.as_mut_ptr();
    i.err_cap = buf.len();
    let mut o: OpenOut = z();
    let r = call(
        linked().head.open,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::OPEN,
    );
    let text = said(&o.head.error);
    if r == Outcome::Ready {
        let mut ci: InHead = z();
        let mut co: OutHead = z();
        call(
            linked().head.close,
            o.instance,
            &mut ci,
            &mut co,
            life::CLOSE,
        );
    } else if !text.is_empty() && o.head.error.ptr == buf.as_ptr() {
        assert_eq!(o.err_len, text.len(), "an open states its reason's length");
    }
    (r, text)
}

/// SETTINGS ARE A JSON OBJECT: a number, an array or a string is refused, by `validate` and `open`.
/// RED before the fix: `5` and `[]` opened with the defaults.
#[test]
fn settings_that_are_not_a_json_object_are_refused() {
    for settings in [&b"5"[..], b"[]", b"\"x\"", b"not json"] {
        for (r, text) in [validate(settings), open_with(settings)] {
            assert_eq!(
                r,
                Outcome::Failed,
                "{:?}",
                String::from_utf8_lossy(settings)
            );
            assert_eq!(text, "settings: must be a JSON object");
        }
    }
    assert_eq!(validate(b"").0, Outcome::Ready, "empty settings are `{{}}`");
    assert_eq!(validate(b"{}").0, Outcome::Ready);
}

/// A KEY THE TRANSPORT DOES NOT DECLARE IS REFUSED BY NAME. RED before the fix: it was ignored.
#[test]
fn an_undeclared_setting_is_refused() {
    let settings = br#"{"limits.request_body_max_bytes": 5, "nope": 1}"#;
    for (r, text) in [validate(settings), open_with(settings)] {
        assert_eq!(r, Outcome::Failed);
        assert_eq!(text, "settings: nope is not a setting this transport reads");
    }
}

/// A CEILING THAT IS NOT A COUNT ABOVE 0 SAYS THE CANONICAL TEXT. RED before the fix: a value of
/// another kind said "a value is not of its declared kind".
#[test]
fn a_bad_message_ceiling_says_the_canonical_text() {
    for value in ["0", "-1", "\"8\"", "1.5", "null", "true"] {
        let settings = format!(r#"{{"limits.request_body_max_bytes": {value}}}"#);
        for (r, text) in [
            validate(settings.as_bytes()),
            open_with(settings.as_bytes()),
        ] {
            assert_eq!(r, Outcome::Failed, "{value}");
            assert_eq!(
                text,
                "settings: limits.request_body_max_bytes must be a count of bytes above 0"
            );
        }
    }
}

/// `refresh` on `inst` with `settings`: its outcome and its text.
fn refresh(inst: *mut c_void, settings: &[u8]) -> (Outcome, String) {
    use busbar_contract::abi::mechanism::call::Blob;
    use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
    let mut i: RefreshIn = z();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..z()
    };
    let mut o: OutHead = z();
    let r = call(linked().head.refresh, inst, &mut i, &mut o, life::REFRESH);
    (r, said(&o.error))
}

/// A connected pair on `host`: the dialled end and the accepted one, past the upgrade.
fn pair(host: &mut Host) -> (End, End) {
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    host.carry(&mut accept, &mut dial);
    (dial, accept)
}

/// REFRESH RE-READS THE SETTINGS: a bad blob is refused with the validate texts and the old ceiling
/// stays; a good one applies to framings begun after it, and one begun before keeps its own. RED
/// before the fix: refresh answered READY to anything and the new ceiling never applied.
#[test]
fn refresh_rereads_the_settings_for_framings_begun_after_it() {
    let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 64));
    let (_, before) = pair(&mut host);
    for (settings, text) in [
        (&b"[]"[..], "settings: must be a JSON object"),
        (
            br#"{"x": 1}"#,
            "settings: x is not a setting this transport reads",
        ),
        (
            br#"{"limits.request_body_max_bytes": 0}"#,
            "settings: limits.request_body_max_bytes must be a count of bytes above 0",
        ),
    ] {
        assert_eq!(
            refresh(host.inst, settings),
            (Outcome::Failed, text.to_owned())
        );
    }
    // The old (default) ceiling stands: a new framing still sends five bytes.
    let (_, kept) = pair(&mut host);
    assert_eq!(host.emit(&kept, b"hello", 0).0, Outcome::Ready);
    assert_eq!(
        refresh(host.inst, br#"{"limits.request_body_max_bytes": 4}"#),
        (Outcome::Ready, String::new())
    );
    let (_, after) = pair(&mut host);
    assert_eq!(
        host.emit(&after, b"hello", 0).0,
        Outcome::Failed,
        "a framing begun after the refresh holds the new ceiling"
    );
    assert_eq!(
        host.emit(&before, b"hello", 0).0,
        Outcome::Ready,
        "a framing begun before keeps its own"
    );
    host.close();
}

// ── role stubs, a missing instance, op-prefixed texts (sibling alignment B, C, D) ────────────────

/// A CARRIER OP IS REFUSED BY NAME: the ws framer serves none of them, and says which op it was
/// asked for. RED before the fix: each answered REFUSED with no text.
#[test]
fn a_carrier_op_is_refused_by_name() {
    use busbar_contract::abi::transport::{
        AcceptIn, AcceptOut, ArrivalIn, ArrivalOut, ConnIn, ConnOut, DialIn, FramingIn, IoOut,
        ListenIn, ListenOut, ReadIn, ShutIn, WriteIn,
    };
    let host = Host::open(linked(), (1024, 1024, 4));
    let ops = host.ops;
    macro_rules! refused {
        ($field:ident, $slot:ident, $in:ty, $out:ty, $text:literal) => {{
            let mut i: $in = z();
            let mut o: $out = z();
            let r = call(ops.$field, host.inst, &mut i, &mut o, slot::$slot);
            // SAFETY: every `out` leads with its head.
            let head = unsafe { &*std::ptr::from_ref(&o).cast::<OutHead>() };
            assert_eq!((r, said(&head.error)), (Outcome::Refused, $text.to_owned()));
        }};
    }
    refused!(
        listen,
        LISTEN,
        ListenIn,
        ListenOut,
        "listen: the ws framer does not serve this op"
    );
    refused!(
        accept,
        ACCEPT,
        AcceptIn,
        AcceptOut,
        "accept: the ws framer does not serve this op"
    );
    refused!(
        dial,
        DIAL,
        DialIn,
        ConnOut,
        "dial: the ws framer does not serve this op"
    );
    refused!(
        read,
        READ,
        ReadIn,
        IoOut,
        "read: the ws framer does not serve this op"
    );
    refused!(
        write,
        WRITE,
        WriteIn,
        IoOut,
        "write: the ws framer does not serve this op"
    );
    refused!(
        flush,
        FLUSH,
        ConnIn,
        OutHead,
        "flush: the ws framer does not serve this op"
    );
    refused!(
        shut,
        SHUT,
        ShutIn,
        OutHead,
        "shut: the ws framer does not serve this op"
    );
    refused!(
        arrival,
        ARRIVAL,
        ArrivalIn,
        ArrivalOut,
        "arrival: the ws framer does not serve this op"
    );
    refused!(
        detach,
        DETACH,
        FramingIn,
        FramerOut,
        "detach: the ws framer does not serve this op"
    );
    host.close();
}

/// AN OP ON NO INSTANCE FAILS BY NAME, never reading through a NULL instance. RED before the fix:
/// the door dereferenced the NULL pointer.
#[test]
fn an_op_with_no_instance_fails_by_name() {
    use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
    use busbar_contract::abi::transport::{FramingIn, LocateIn, LocateOut};
    let ops = linked();
    let none = std::ptr::null_mut();
    macro_rules! failed {
        ($field:ident, $slot:expr, $in:ty, $out:ty, $text:literal) => {{
            let mut i: $in = z();
            let mut o: $out = z();
            let r = call($field, none, &mut i, &mut o, $slot);
            // SAFETY: every `out` leads with its head.
            let head = unsafe { &*std::ptr::from_ref(&o).cast::<OutHead>() };
            assert_eq!((r, said(&head.error)), (Outcome::Failed, $text.to_owned()));
        }};
    }
    let (locate, begin, adopt, ingest) = (ops.locate, ops.begin, ops.adopt, ops.ingest);
    let (emit, refuse, finish, timer) = (ops.emit, ops.refuse, ops.finish, ops.timer);
    let refresh = ops.head.refresh;
    let target = "ws://svc.test/";
    let mut i: LocateIn = z();
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    let mut o: LocateOut = z();
    let r = call(locate, none, &mut i, &mut o, slot::LOCATE);
    assert_eq!(
        (r, said(&o.head.error)),
        (Outcome::Failed, "locate: no open instance".to_owned())
    );
    failed!(
        begin,
        slot::BEGIN,
        BeginIn,
        FramerOut,
        "begin: no open instance"
    );
    failed!(
        adopt,
        slot::ADOPT,
        AdoptIn,
        FramerOut,
        "adopt: no open instance"
    );
    failed!(
        ingest,
        slot::INGEST,
        IngestIn,
        FramerOut,
        "ingest: no open instance"
    );
    failed!(
        emit,
        slot::EMIT,
        EmitIn,
        FramerOut,
        "emit: no open instance"
    );
    failed!(
        refuse,
        slot::REFUSE,
        RefuseIn,
        FramerOut,
        "refuse: no open instance"
    );
    failed!(
        finish,
        slot::FINISH,
        FinishIn,
        FramerOut,
        "finish: no open instance"
    );
    failed!(
        timer,
        slot::TIMER,
        FramingIn,
        FramerOut,
        "timer: no open instance"
    );
    failed!(
        refresh,
        life::REFRESH,
        RefreshIn,
        OutHead,
        "refresh: no open instance"
    );
}

/// A FRAMING THE DOOR DOES NOT HOLD IS NAMED BY ITS OP. RED before the fix: "no such framing".
#[test]
fn an_unknown_framing_fails_by_op() {
    let mut host = Host::open(linked(), (1024, 1024, 4));
    let mut i: IngestIn = z();
    i.framing = 77;
    i.sink = host.sink();
    let mut o: FramerOut = z();
    let r = call(host.ops.ingest, host.inst, &mut i, &mut o, slot::INGEST);
    assert_eq!(
        (r, said(&o.head.error)),
        (Outcome::Failed, "ingest: no such framing".to_owned())
    );
    host.close();
}

/// A TARGET CARRYING USERINFO IS REFUSED SAYING SO, and the text repeats no byte of it. RED before
/// the fix: `locate` said "locate: the target is not a ws or wss URL".
#[test]
fn locate_refuses_a_target_carrying_userinfo() {
    use busbar_contract::abi::transport::{LocateIn, LocateOut};
    let host = Host::open(linked(), (1024, 1024, 4));
    let target = "wss://user:hunter2@svc.test/";
    let (mut auth, mut name) = ([0_u8; 64], [0_u8; 64]);
    let mut i: LocateIn = z();
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    i.authority_buf = auth.as_mut_ptr();
    i.authority_cap = auth.len();
    i.name_buf = name.as_mut_ptr();
    i.name_cap = name.len();
    let mut o: LocateOut = z();
    let r = call(host.ops.locate, host.inst, &mut i, &mut o, slot::LOCATE);
    assert_eq!(
        (r, said(&o.head.error)),
        (
            Outcome::Failed,
            "locate: the target carries userinfo; credentials never ride a URL".to_owned()
        )
    );
    host.close();
}

/// AN UNDECLARED KEY WITH NOWHERE TO PUT ITS NAME SAYS SO IN THE SDK'S WORDS: `validate` and `open`
/// with no reason buffer lent answer the lifecycle SDK's text for a reason that was not kept, as
/// every door on `abi::sdk::life` does. RED before the door moved onto the SDK lifecycle: it said
/// "settings: a key is not a setting this transport reads".
#[test]
fn an_undeclared_key_with_no_reason_buffer_says_the_reason_was_not_kept() {
    use busbar_contract::abi::mechanism::call::Blob;
    use busbar_contract::abi::mechanism::lifecycle::ValidateIn;
    use busbar_contract::abi::sdk::out::NO_REASON_BUFFER;
    let settings = br#"{"nope": 1}"#;
    let blob = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..z()
    };
    let mut vi: ValidateIn = z();
    vi.settings = blob;
    let mut vo: OutHead = z();
    let r = call(
        linked().head.validate,
        std::ptr::null_mut(),
        &mut vi,
        &mut vo,
        life::VALIDATE,
    );
    assert_eq!(
        (r, said(&vo.error)),
        (Outcome::Failed, NO_REASON_BUFFER.to_owned())
    );
    let mut oi: OpenIn = z();
    oi.settings = blob;
    let mut oo: OpenOut = z();
    let r = call(
        linked().head.open,
        std::ptr::null_mut(),
        &mut oi,
        &mut oo,
        life::OPEN,
    );
    assert_eq!(
        (r, said(&oo.head.error)),
        (Outcome::Failed, NO_REASON_BUFFER.to_owned())
    );
}

/// A RELEASE OF A LEASE THE INSTANCE NEVER HANDED OUT IS REFUSED, in the lifecycle SDK's words
/// (`release: no such lease`): the door leases nothing, so every release names a lease it does not
/// hold, a host bug. RED before the door moved onto the SDK lifecycle: it answered READY.
#[test]
fn a_release_of_a_lease_never_handed_out_is_refused() {
    use busbar_contract::abi::mechanism::lifecycle::ReleaseIn;
    use busbar_contract::abi::sdk::life::NO_SUCH_LEASE;
    let host = Host::open(linked(), (1024, 1024, 4));
    let mut i: ReleaseIn = z();
    i.lease = 7;
    let mut o: OutHead = z();
    let r = call(
        host.ops.head.release,
        host.inst,
        &mut i,
        &mut o,
        life::RELEASE,
    );
    assert_eq!(
        (r, said(&o.error)),
        (Outcome::Refused, NO_SUCH_LEASE.to_owned())
    );
    host.close();
}

// ── what an opening field asks that the upgrade cannot carry (codeaudit e916fda) ────────────────

/// `begin` dialling `target` with `fields` (name, value); the refusal's text, or `None` once it
/// opens.
fn begin_with_fields(
    host: &mut Host,
    target: &'static str,
    fields: &[(&[u8], &[u8])],
) -> Option<String> {
    use busbar_contract::abi::mechanism::call::Field;
    let fields: Vec<Field> = fields
        .iter()
        .map(|(n, v)| Field {
            name: AbiStr {
                ptr: n.as_ptr(),
                len: n.len(),
            },
            value: AbiStr {
                ptr: v.as_ptr(),
                len: v.len(),
            },
        })
        .collect();
    let mut i: BeginIn = z();
    i.side = SIDE_DIAL;
    i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    i.fields = fields.as_ptr();
    i.fields_len = fields.len();
    i.sink = host.sink();
    let mut o: FramerOut = z();
    let r = call(host.ops.begin, host.inst, &mut i, &mut o, slot::BEGIN);
    (r == Outcome::Failed).then(|| said(&o.head.error))
}

/// AN EXTENSION IS REFUSED IN WORDS (codeaudit e916fda WS-7; RFC 6455 section 9): this end
/// negotiates no extension, so a dial whose opening fields ask for one is refused at `begin`,
/// saying so, rather than sent without it in silence. RED before the fix: the field was dropped and
/// the dial opened.
#[test]
fn a_dial_asking_for_an_extension_is_refused_in_words() {
    let mut host = Host::open(linked(), (64 * 1024, 64 * 1024, 64));
    assert_eq!(
        begin_with_fields(
            &mut host,
            "ws://svc.test/x",
            &[(b"Sec-WebSocket-Extensions", b"permessage-deflate")]
        )
        .as_deref(),
        Some("begin: the opening field sec-websocket-extensions asks for an extension, and this end supports none")
    );
    host.close();
}
