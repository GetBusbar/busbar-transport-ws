// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's answer filling: a dialled head's reason phrase rides only beside its head's first
//! piece.

use super::*;
use std::cell::RefCell;
use std::ffi::c_void;

use busbar_contract::abi::mechanism::call::InHead;
use busbar_contract::abi::mechanism::lifecycle::{slot as life_slot, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::Entry;
use busbar_contract::abi::transport::{slot, FramePiece, FramerOut as DoorOut, HeadSlots};

use crate::frame::HostTime;

/// What [`Poke`] runs on the instance's state.
type Poked = Box<dyn FnOnce(&Ws)>;

thread_local! {
    /// The queue [`Fill`] hands over, and what [`Poke`] runs on the instance's state.
    static OWED: RefCell<Option<Owed>> = const { RefCell::new(None) };
    static POKE: RefCell<Option<Poked>> = const { RefCell::new(None) };
}

/// A test slot: [`fill`] of the queue in [`OWED`] into the lent sink, as every framer op answers.
struct Fill;
impl SafeSlot for Fill {
    type In = FramingIn;
    type Out = DoorOut;
    type State = Held<Ws>;
    fn call(_: Instance<'_, Held<Ws>>, i: Lent<'_, FramingIn>, mut o: Out<'_, DoorOut>) -> Outcome {
        OWED.with(|c| {
            let mut owed = c.borrow_mut();
            fill(
                owed.as_mut().expect("a queue to fill from"),
                i.field(|x| &x.sink),
                &mut o,
            );
        });
        Outcome::Ready
    }
}

/// A test slot: the closure in [`POKE`], run on the open instance's state.
struct Poke;
impl SafeSlot for Poke {
    type In = FramingIn;
    type Out = DoorOut;
    type State = Held<Ws>;
    fn call(p: Instance<'_, Held<Ws>>, _: Lent<'_, FramingIn>, _: Out<'_, DoorOut>) -> Outcome {
        let ws = p.get().map(Held::life).expect("an open instance");
        POKE.with(|c| c.borrow_mut().take().expect("a closure to run"))(ws);
        Outcome::Ready
    }
}

/// [`fill`] `owed` into `sink`, entered as the trampoline enters a slot: the answer.
fn fill_from(owed: &mut Owed, sink: FramerSink) -> DoorOut {
    OWED.with(|c| *c.borrow_mut() = Some(std::mem::take(owed)));
    // SAFETY: plain C data; all-zero is valid.
    let mut i: FramingIn = unsafe { std::mem::zeroed() };
    i.sink = sink;
    // SAFETY: as above.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: no instance, and the sink's buffers are live for the call.
    let r = unsafe { Safe::<Fill>::enter(std::ptr::null_mut(), slot::TIMER, &i, &mut o) };
    assert_eq!(r, Outcome::Ready);
    *owed = OWED
        .with(|c| c.borrow_mut().take())
        .expect("the queue comes back");
    o
}

/// Run `f` on the state of the open instance `inst`.
fn poke(inst: *mut c_void, f: impl FnOnce(&Ws) + 'static) {
    POKE.with(|c| *c.borrow_mut() = Some(Box::new(f)));
    // SAFETY: plain C data; all-zero is valid.
    let i: FramingIn = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the instance `open` answered, not yet closed; the `in` lends nothing.
    let r = unsafe { Safe::<Poke>::enter(inst, slot::TIMER, &i, &mut o) };
    assert_eq!(r, Outcome::Ready);
}

fn sink(frame: &mut [u8], pieces: &mut [FramePiece], heads: &mut [HeadSlots]) -> FramerSink {
    // SAFETY: plain C data; all-zero is valid.
    let mut s: FramerSink = unsafe { std::mem::zeroed() };
    s.frame = frame.as_mut_ptr();
    s.frame_cap = frame.len();
    s.pieces = pieces.as_mut_ptr();
    s.pieces_cap = pieces.len();
    s.heads = heads.as_mut_ptr();
    s.heads_cap = heads.len();
    s
}

/// A DIALLED HEAD'S REASON GOES ONLY WITH ITS HEAD'S FIRST PIECE, AND NEVER STALLS IT (Q128
/// transport-ws LOW, reader r52 on 3286006; codeaudit g2 MEDIUM; HEAD-FIELDS). The host re-calls
/// `YIELD_MORE` with the same frame buffer, so an EMPTY answer that waited for room beside the
/// phrase would wait for ever: there the head goes WITHOUT its phrase, and the phrase never goes
/// out alone. Where the answer is not empty (another piece took room ahead of the head) the phrase
/// waits, and the next answer carries both. With room for both, the phrase rides beside the head's
/// first piece. RED before the fix: the first answer was 0 pieces with the head still waiting.
#[test]
fn a_reason_rides_only_beside_its_heads_first_piece() {
    let head = |reason: &[u8]| {
        let mut head = Piece::plain(0, b"x-a: 1\r\n".to_vec(), true);
        head.fields = true;
        head.reason = Some(reason.to_vec());
        head
    };
    let run = |owed: &mut Owed, cap: usize| {
        let (mut frame, mut pieces, mut heads) = (
            vec![0_u8; cap],
            unsafe { std::mem::zeroed::<[FramePiece; 4]>() },
            [HeadSlots::default(); 2],
        );
        let o = fill_from(owed, sink(&mut frame, &mut pieces, &mut heads));
        let phrase = (o.yielded.heads_len > 0).then(|| {
            let r = heads[0].reason;
            frame[r.offset as usize..(r.offset + r.len) as usize].to_vec()
        });
        (o.yielded.pieces_len, o.yielded.heads_len, phrase)
    };

    // (a) Room for the phrase (12 bytes) and one byte more, in an empty answer: no cut of the field
    // block fits beside it, so the head goes without it.
    let mut owed = Owed::default();
    owed.pieces.push_back(head(b"Unauthorized"));
    let (pieces, heads, _) = run(&mut owed, 13);
    assert!(pieces >= 1, "the head moves");
    assert_eq!(heads, 0, "without its phrase, which never goes out alone");

    // (b) Another piece took room ahead of the head: nothing of the head fits beside the phrase in
    // this answer, so both wait, and the next (empty) answer carries them together.
    let mut owed = Owed::default();
    owed.pieces
        .push_back(Piece::plain(1, b"0123456789".to_vec(), true));
    owed.pieces.push_back(head(b"Unauthorized"));
    let (pieces, heads, _) = run(&mut owed, 24);
    assert_eq!((pieces, heads), (1, 0), "only the first piece went");
    assert!(owed.pieces[0].reason.is_some(), "the phrase waits");
    let (pieces, heads, phrase) = run(&mut owed, 24);
    assert_eq!((pieces, heads), (1, 1));
    assert_eq!(phrase.as_deref(), Some(&b"Unauthorized"[..]));

    // (c) Room for both: the phrase rides beside the head's first piece.
    let mut owed = Owed::default();
    owed.pieces.push_back(head(b"Unauthorized"));
    let (pieces, heads, phrase) = run(&mut owed, 64);
    assert_eq!((pieces, heads), (1, 1));
    assert_eq!(phrase.as_deref(), Some(&b"Unauthorized"[..]));
}

/// A FRAMING WHOSE OP PANICKED IS GONE ONCE IT IS FINISHED (Q128 transport-ws LOW, reader r52 on
/// 3286006): the finish answers FAILED without reaching the framer, so the framer's state for it is
/// dropped there too, and nothing of it is kept for the life of the instance. RED before the fix:
/// the door's queue went, the framer's state stayed.
#[test]
fn a_panicked_framing_is_forgotten_by_the_framer_at_its_finish() {
    // SAFETY: plain C data; all-zero is valid.
    let oi: OpenIn = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let mut oo: OpenOut = unsafe { std::mem::zeroed() };
    // SAFETY: no instance yet, and an `in` lending nothing.
    let r = unsafe {
        Safe::<life::Open<Ws>>::enter(std::ptr::null_mut(), life_slot::OPEN, &oi, &mut oo)
    };
    assert_eq!(r, Outcome::Ready);
    let p = oo.instance;
    let state = std::rc::Rc::new(std::cell::Cell::new(0));
    let opened = std::rc::Rc::clone(&state);
    poke(p, move |inst| {
        let mut sink_out = Owed::default();
        let mut c = Collect {
            owed: &mut sink_out,
            now: HostTime { unix_nanos: 0 },
            opening: true,
        };
        let state = inst
            .framer
            .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut c)
            .expect("the dial opens");
        opened.set(state);
        let slot: OwedSlot = Arc::new(Mutex::new(Owed::default()));
        inst.queues().insert(state, Arc::clone(&slot));
        // An op on this framing panicked while holding its queue.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = slot.lock();
            panic!("an op panicked");
        }));
        assert!(slot.is_poisoned());
    });
    let state = state.get();
    // SAFETY: plain C data; all-zero is valid.
    let mut i: FinishIn = unsafe { std::mem::zeroed() };
    i.framing = state;
    // SAFETY: as above.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the instance `open` answered; the sink lends nothing.
    let r = unsafe { Safe::<Finish>::enter(p, slot::FINISH, &i, &mut o) };
    assert_eq!(r, Outcome::Failed);
    poke(p, move |inst| {
        assert!(
            !inst.queues().contains_key(&state),
            "the door's queue is gone"
        );
        assert!(!inst.framer.holds(state), "the framer's state is gone too");
    });
    // SAFETY: plain C data; all-zero is valid.
    let ci: InHead = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let mut co: OutHead = unsafe { std::mem::zeroed() };
    // SAFETY: the instance `open` answered, closed once, with no op in flight.
    let r = unsafe { Safe::<life::Close<Ws>>::enter(p, life_slot::CLOSE, &ci, &mut co) };
    assert_eq!(r, Outcome::Ready);
}

/// Hand `owed` over through a sink of the given caps, one fill at a time, until it is dry: every
/// answer's wire run and frame pieces (bytes, flags), in order.
fn drain_owed(
    owed: &mut Owed,
    wire_cap: usize,
    frame_cap: usize,
) -> (Vec<u8>, Vec<(Vec<u8>, u16)>) {
    let (mut wire_out, mut got) = (Vec::new(), Vec::new());
    for _ in 0..1_000_000 {
        let mut wire = vec![0_u8; wire_cap];
        let (mut frame, mut pieces, mut heads) = (
            vec![0_u8; frame_cap],
            vec![unsafe { std::mem::zeroed::<FramePiece>() }; 4],
            [HeadSlots::default(); 1],
        );
        let mut s = sink(&mut frame, &mut pieces, &mut heads);
        s.wire = wire.as_mut_ptr();
        s.wire_cap = wire_cap;
        let o = fill_from(owed, s);
        wire_out.extend_from_slice(&wire[..o.yielded.wire_len as usize]);
        for p in &pieces[..o.yielded.pieces_len as usize] {
            let at = p.offset as usize;
            got.push((frame[at..at + p.len as usize].to_vec(), p.flags));
        }
        if o.yielded.flags & YIELD_MORE == 0 {
            return (wire_out, got);
        }
    }
    panic!("a re-call never ran dry");
}

/// A LARGE PIECE AND A LARGE WIRE ARE HANDED OVER INTACT, IN ORDER, ACROSS RE-CALLS (codeaudit g2
/// MEDIUM): several times the sink's caps, with the end of the frame stated on the last piece only.
#[test]
fn a_large_piece_and_wire_are_handed_over_intact_across_recalls() {
    let message: Vec<u8> = (0..1000_u32).map(|n| (n % 251) as u8).collect();
    let wire_bytes: Vec<u8> = (0..700_u32).map(|n| (n % 241) as u8 + 1).collect();
    let mut owed = Owed::default();
    owed.push(&wire_bytes, true);
    owed.pieces
        .push_back(Piece::plain(7, message.clone(), true));
    let (wire, got) = drain_owed(&mut owed, 100, 64);
    assert_eq!(wire, wire_bytes);
    let joined: Vec<u8> = got.iter().flat_map(|(b, _)| b.clone()).collect();
    assert_eq!(joined, message);
    assert!(got.len() >= 1000 / 64);
    let last = got.len() - 1;
    for (i, (_, flags)) in got.iter().enumerate() {
        assert_eq!(
            flags & PIECE_END_OF_FRAME != 0,
            i == last,
            "the end of the frame is stated on the last piece only"
        );
    }
    assert!(owed.wire.is_empty() && owed.pieces.is_empty());
}

/// HANDING OVER MOVES NO REMAINDER (codeaudit g2 MEDIUM): a piece taken in parts keeps its buffer
/// whole, and the wire keeps its length, while the handed-over bytes are wiped in place. RED before
/// the fix: `drain` and `copy_within` shifted the remainder down on every fill, so the buffers
/// shrank. This pins the offset mechanism.
#[test]
fn handing_over_a_large_piece_or_wire_moves_no_remainder() {
    let mut owed = Owed::default();
    owed.push(&[0xAA; 300], true);
    owed.pieces
        .push_back(Piece::plain(1, vec![0xBB; 500], true));
    let ptr = owed.pieces[0].bytes.as_ptr();
    let (mut frame, mut pieces, mut heads) = (
        [0_u8; 64],
        unsafe { std::mem::zeroed::<[FramePiece; 4]>() },
        [HeadSlots::default(); 1],
    );
    let mut wire = [0_u8; 100];
    let mut s = sink(&mut frame, &mut pieces, &mut heads);
    s.wire = wire.as_mut_ptr();
    s.wire_cap = wire.len();
    let o = fill_from(&mut owed, s);
    assert_eq!(o.yielded.wire_len, 100);
    assert_eq!(wire, [0xAA; 100]);
    assert_eq!(o.yielded.pieces_len, 1);
    assert_eq!(
        owed.pieces[0].bytes.len(),
        500,
        "the piece's buffer is whole"
    );
    assert_eq!(owed.pieces[0].bytes.as_ptr(), ptr);
    assert_eq!(owed.pieces[0].at, 64, "the piece reads on from the offset");
    assert_eq!(owed.wire_at, 100, "the wire reads on from the offset");
    assert_eq!(owed.wire.len(), 300, "the wire's buffer is whole");
    assert!(
        owed.wire[..100].iter().all(|&b| b == 0),
        "the handed-over wire is wiped in place"
    );
    assert!(owed.wire[100..].iter().all(|&b| b == 0xAA));
}

/// THE WIRE'S CAPACITY FOLLOWS ITS BACKLOG, NOT ITS THROUGHPUT (codeaudit g2 review): a wire that
/// never fully drains (each push 101 bytes, each hand-over 100) grows by what is owed, not by
/// doubling the capacity that handed-over bytes still count in. RED before the fix: the capacity
/// doubled at every growth, far past the backlog.
#[test]
fn the_wire_s_capacity_follows_its_backlog_not_its_throughput() {
    let mut owed = Owed::default();
    for _ in 0..500 {
        owed.push(&[0x5A; 101], true);
        owed.consume(100);
        let backlog = owed.wire_owed().len();
        assert!(
            owed.wire.capacity() <= 2 * (backlog + 101),
            "capacity {} for a backlog of {backlog}",
            owed.wire.capacity()
        );
    }
}

/// A KEPT PIECE BUFFER GIVES BACK WHAT ONE LARGE MESSAGE GREW IT PAST [`KEEP_BYTES`]: a framing in
/// steady state holds working-size spares, not its high-water mark eight times over. RED before
/// the fix: a 4 MiB buffer was kept whole.
#[test]
fn a_kept_piece_buffer_is_bounded() {
    let mut owed = Owed::default();
    owed.recycle(vec![7; 4 * 1024 * 1024]);
    owed.recycle(Vec::with_capacity(1024));
    assert_eq!(owed.spare.len(), 2, "both are kept");
    for b in &owed.spare {
        assert!(b.capacity() <= KEEP_BYTES, "kept at {} bytes", b.capacity());
    }
    assert!(
        owed.spare[1].capacity() >= 1024,
        "a working-size buffer is kept whole"
    );
}

/// ONLY THE OPENING IS WIPED (PL10): the bytes a framing's opening owed (a dialled upgrade request
/// carries its auth's credential lines) are wiped as they are handed over and when the buffer
/// outgrows them; the message bytes owed after them are handed over as they are, never wiped.
#[test]
fn only_the_opening_is_wiped_as_it_is_handed_over() {
    let mut owed = Owed::default();
    owed.push(&[0xC5; 40], true);
    owed.push(&[0x11; 10], false);
    owed.consume(30);
    assert!(
        owed.wire[..30].iter().all(|&b| b == 0),
        "the handed-over opening is wiped"
    );
    // Outgrowing the buffer copies the 10 opening bytes still owed and wipes the old buffer.
    let big = vec![0x22; 4 * owed.wire.capacity()];
    owed.push(&big, false);
    assert_eq!(owed.secret, 10, "the opening bytes still owed stay marked");
    owed.consume(15);
    assert!(
        owed.wire[..10].iter().all(|&b| b == 0),
        "the rest of the opening is wiped"
    );
    assert!(
        owed.wire[10..15].iter().all(|&b| b == 0x11),
        "a message byte is handed over as it is"
    );
}

/// A DRAINED WIRE GIVES BACK WHAT ONE LARGE MESSAGE GREW IT PAST [`KEEP_BYTES`] (codeaudit e916fda
/// WS-11), as a kept piece buffer does: an idle framing holds a working-size wire buffer, not twice
/// its largest message. A working-size buffer is kept whole, so steady state allocates nothing.
/// RED before the fix: the drained wire kept its whole high-water capacity.
#[test]
fn a_drained_wire_is_bounded() {
    let mut owed = Owed::default();
    owed.push(&vec![0x33; 4 * 1024 * 1024], false);
    let all = owed.wire_owed().len();
    owed.consume(all);
    assert!(
        owed.wire.capacity() <= KEEP_BYTES,
        "kept at {} bytes",
        owed.wire.capacity()
    );
    let mut owed = Owed::default();
    owed.push(&[0x44; 1024], false);
    let kept = owed.wire.capacity();
    owed.consume(1024);
    assert_eq!(
        owed.wire.capacity(),
        kept,
        "a working-size buffer is kept whole"
    );
}

// ── the door's ops, driven as the host drives them (codeaudit e916fda, tests) ───────────────────

/// One answer's lent buffers.
struct Lend {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
}

impl Lend {
    fn new(wire: usize, frame: usize, pieces: usize, heads: usize) -> Self {
        Self {
            wire: vec![0; wire],
            frame: vec![0; frame],
            // SAFETY: plain C data; all-zero is valid.
            pieces: vec![unsafe { std::mem::zeroed::<FramePiece>() }; pieces],
            heads: vec![HeadSlots::default(); heads],
        }
    }

    fn roomy() -> Self {
        Self::new(64 * 1024, 64 * 1024, 16, 1)
    }

    fn sink(&mut self) -> FramerSink {
        let mut s = sink(&mut self.frame, &mut self.pieces, &mut self.heads);
        s.wire = self.wire.as_mut_ptr();
        s.wire_cap = self.wire.len();
        s
    }
}

/// What one answer said: its outcome, its wire bytes, each piece (bytes, flags), each head's
/// reason phrase, and its yield flags.
struct Said {
    outcome: Outcome,
    wire: Vec<u8>,
    pieces: Vec<(Vec<u8>, u16)>,
    reasons: Vec<Vec<u8>>,
    flags: u32,
}

fn said(r: Outcome, o: &DoorOut, l: &Lend) -> Said {
    use busbar_contract::abi::transport::check::{check_framer, check_head_slots};
    if r == Outcome::Ready {
        let n = o.yielded.pieces_len as usize;
        check_framer(
            r,
            o,
            &l.pieces[..n],
            l.wire.len() as u64,
            l.frame.len() as u64,
            l.pieces.len() as u64,
        )
        .expect("the answer passes the kind's check");
        check_head_slots(o, &l.heads, l.heads.len() as u64).expect("the head slots pass");
    }
    let span = |at: u64, len: u64| l.frame[at as usize..(at + len) as usize].to_vec();
    Said {
        outcome: r,
        wire: l.wire[..o.yielded.wire_len as usize].to_vec(),
        pieces: l.pieces[..o.yielded.pieces_len as usize]
            .iter()
            .map(|p| (span(p.offset, p.len), p.flags))
            .collect(),
        reasons: l.heads[..o.yielded.heads_len as usize]
            .iter()
            .map(|h| span(h.reason.offset, h.reason.len))
            .collect(),
        flags: o.yielded.flags,
    }
}

/// An open instance.
fn instance() -> *mut c_void {
    // SAFETY: plain C data; all-zero is valid.
    let i: OpenIn = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let mut o: OpenOut = unsafe { std::mem::zeroed() };
    // SAFETY: no instance yet, and an `in` lending nothing.
    let r =
        unsafe { Safe::<life::Open<Ws>>::enter(std::ptr::null_mut(), life_slot::OPEN, &i, &mut o) };
    assert_eq!(r, Outcome::Ready);
    o.instance
}

/// Close the instance `p`.
fn shut(p: *mut c_void) {
    // SAFETY: plain C data; all-zero is valid.
    let i: InHead = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let mut o: OutHead = unsafe { std::mem::zeroed() };
    // SAFETY: the instance `open` answered, closed once, with no op in flight.
    let r = unsafe { Safe::<life::Close<Ws>>::enter(p, life_slot::CLOSE, &i, &mut o) };
    assert_eq!(r, Outcome::Ready);
}

/// `begin` on `side` toward `target`, with opening `fields`: the answer and the framing.
fn begin(
    p: *mut c_void,
    side: u32,
    target: &'static str,
    fields: &[(&'static [u8], &'static [u8])],
    l: &mut Lend,
) -> (Said, u64) {
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
    // SAFETY: plain C data; all-zero is valid.
    let mut i: BeginIn = unsafe { std::mem::zeroed() };
    i.side = side;
    i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    i.fields = fields.as_ptr();
    i.fields_len = fields.len();
    i.sink = l.sink();
    // SAFETY: as above.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the open instance; the `in` lends `fields`, `target` and the sink, live for the call.
    let r = unsafe { Safe::<Begin>::enter(p, slot::BEGIN, &i, &mut o) };
    (said(r, &o, l), o.framing)
}

/// `ingest` of `bytes` (`end`: the carrier ended) on framing `token`; no bytes and no end is the
/// `YIELD_MORE` re-call.
fn ingest(p: *mut c_void, token: u64, bytes: &[u8], end: bool, l: &mut Lend) -> Said {
    // SAFETY: plain C data; all-zero is valid.
    let mut i: IngestIn = unsafe { std::mem::zeroed() };
    i.framing = token;
    i.bytes = bytes.as_ptr();
    i.len = bytes.len();
    i.end = u32::from(end);
    i.sink = l.sink();
    // SAFETY: as above.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the open instance; the `in` lends `bytes` and the sink, live for the call.
    let r = unsafe { Safe::<Ingest>::enter(p, slot::INGEST, &i, &mut o) };
    said(r, &o, l)
}

/// `emit` of one whole binary message on framing `token`.
fn emit(p: *mut c_void, token: u64, bytes: &[u8], l: &mut Lend) -> Said {
    // SAFETY: plain C data; all-zero is valid.
    let mut i: EmitIn = unsafe { std::mem::zeroed() };
    i.framing = token;
    i.bytes = bytes.as_ptr();
    i.len = bytes.len();
    i.end_of_frame = 1;
    i.sink = l.sink();
    // SAFETY: as above.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the open instance; the `in` lends `bytes` and the sink, live for the call.
    let r = unsafe { Safe::<Emit>::enter(p, slot::EMIT, &i, &mut o) };
    said(r, &o, l)
}

/// `finish` of framing `token`, an orderly close.
fn finish(p: *mut c_void, token: u64, l: &mut Lend) -> Said {
    // SAFETY: plain C data; all-zero is valid.
    let mut i: FinishIn = unsafe { std::mem::zeroed() };
    i.framing = token;
    i.sink = l.sink();
    // SAFETY: as above.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the open instance; the `in` lends the sink, live for the call.
    let r = unsafe { Safe::<Finish>::enter(p, slot::FINISH, &i, &mut o) };
    said(r, &o, l)
}

const UPGRADE: &[u8] = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

/// An accepted framing past its upgrade, on instance `p`.
fn accepted(p: *mut c_void) -> u64 {
    let (_, token) = begin(p, SIDE_ACCEPT, "", &[], &mut Lend::roomy());
    let up = ingest(p, token, UPGRADE, false, &mut Lend::roomy());
    assert!(up.wire.starts_with(b"HTTP/1.1 101"));
    token
}

/// The far end's switching answer to the upgrade request `request`.
fn switching(request: &[u8]) -> Vec<u8> {
    let request = String::from_utf8_lossy(request);
    let key = request
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .expect("a key");
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        tungstenite::handshake::derive_accept_key(key.as_bytes())
    )
    .into_bytes()
}

/// THE CARRIER'S END REACHES THE MACHINE THROUGH THE DOOR (codeaudit e916fda tests MEDIUM): an
/// `ingest` that carries no bytes but `end` is no re-call; the framer hears the end and the stream
/// ends, FAILED with its reason, and the answer says the connection ended (`YIELD_ENDED`). An
/// accepting framing whose request was cut short by the end has its state ended by the op: the
/// failed end piece says why, and the connection ends with it.
#[test]
fn the_carriers_end_reaches_the_machine_through_the_door() {
    let p = instance();
    let token = accepted(p);
    let end = ingest(p, token, &[], true, &mut Lend::roomy());
    assert_eq!(end.outcome, Outcome::Ready);
    let (why, flags) = end.pieces.last().expect("an end piece");
    assert_ne!(flags & PIECE_STREAM_FAILED, 0, "the stream ends failed");
    assert_eq!(
        why,
        b"the carrier ended with no WebSocket closing handshake"
    );
    assert_ne!(end.flags & YIELD_ENDED, 0, "the connection ended");

    let (_, token) = begin(p, SIDE_ACCEPT, "", &[], &mut Lend::roomy());
    let cut = ingest(
        p,
        token,
        b"GET /echo HTTP/1.1\r\nHost",
        true,
        &mut Lend::roomy(),
    );
    assert_eq!(cut.outcome, Outcome::Ready);
    let (why, flags) = cut.pieces.last().expect("an end piece");
    assert_ne!(flags & PIECE_STREAM_FAILED, 0);
    assert_eq!(why, b"the WebSocket opening handshake failed");
    assert_ne!(cut.flags & YIELD_ENDED, 0);
    shut(p);
}

/// A FINISHED FRAMING IS GONE ONCE WHAT IT OWES IS OUT (codeaudit e916fda tests MEDIUM): a finish
/// that drains removes the framing's door queue and the framer's state; one that leaves a backlog
/// (`YIELD_MORE`) keeps the queue until the re-called finish drains it.
#[test]
fn a_finished_framing_is_gone_once_drained() {
    let p = instance();
    let token = accepted(p);
    let done = finish(p, token, &mut Lend::roomy());
    assert_eq!(done.flags & YIELD_MORE, 0, "drained");
    poke(p, move |inst| {
        assert!(
            !inst.queues().contains_key(&token),
            "the door's queue is gone"
        );
        assert!(!inst.framer.holds(token), "the framer's state is gone");
    });

    let token = accepted(p);
    let first = finish(p, token, &mut Lend::new(1, 64, 4, 1));
    assert_ne!(first.flags & YIELD_MORE, 0, "the close is still owed");
    poke(p, move |inst| {
        assert!(inst.queues().contains_key(&token), "the backlog is kept");
    });
    let rest = finish(p, token, &mut Lend::roomy());
    assert_eq!(rest.flags & YIELD_MORE, 0);
    assert!(!rest.wire.is_empty(), "the rest of the close went out");
    poke(p, move |inst| {
        assert!(!inst.queues().contains_key(&token), "gone once drained");
    });
    shut(p);
}

/// ONLY A DIAL'S OPENING IS MARKED TO BE WIPED, THROUGH THE DOOR (codeaudit e916fda tests MEDIUM,
/// PL10): the upgrade request `begin` owes (its auth's credential among its lines) is marked secret
/// in the framing's queue, and the message bytes a later `emit` owes are not.
#[test]
fn only_a_dials_opening_is_marked_secret_through_the_door() {
    let p = instance();
    let (opened, token) = begin(
        p,
        SIDE_DIAL,
        "ws://svc.test/x",
        &[(b"authorization", b"Bearer sk-door-secret")],
        &mut Lend::new(16, 64, 4, 1),
    );
    assert_ne!(opened.flags & YIELD_MORE, 0, "most of the request is owed");
    poke(p, move |inst| {
        let slot = inst.queues().get(&token).cloned().expect("a queue");
        let owed = slot.lock().expect("unpoisoned");
        assert!(owed.secret > owed.wire_at, "the owed opening is marked");
        assert_eq!(owed.secret, owed.wire.len(), "all of it");
    });
    let mut request = opened.wire;
    loop {
        let more = ingest(p, token, &[], false, &mut Lend::new(16, 64, 4, 1));
        request.extend_from_slice(&more.wire);
        if more.flags & YIELD_MORE == 0 {
            break;
        }
    }
    let mut open = Lend::roomy();
    ingest(p, token, &switching(&request), false, &mut open);
    let sent = emit(p, token, &[0x5A; 64], &mut Lend::new(4, 64, 4, 1));
    assert_ne!(sent.flags & YIELD_MORE, 0, "most of the message is owed");
    poke(p, move |inst| {
        let slot = inst.queues().get(&token).cloned().expect("a queue");
        let owed = slot.lock().expect("unpoisoned");
        assert!(!owed.wire_owed().is_empty());
        assert_eq!(owed.secret, 0, "a message is never marked");
    });
    shut(p);
}

/// A DIALLED HEAD'S REASON REACHES THE HOST'S HEAD SLOTS, BESIDE ITS HEAD (codeaudit e916fda tests
/// LOW): the far end's refusal head `401 Unauthorized` crosses as one field-block piece with the
/// phrase in a head slot, the answer passing the kind's head-slot check.
#[test]
fn a_dialled_heads_reason_reaches_the_head_slots() {
    let p = instance();
    let (_, token) = begin(p, SIDE_DIAL, "ws://svc.test/x", &[], &mut Lend::roomy());
    let heard = ingest(
        p,
        token,
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        false,
        &mut Lend::roomy(),
    );
    assert_eq!(heard.reasons, [b"Unauthorized".to_vec()]);
    assert_ne!(heard.pieces[0].1 & PIECE_FIELDS, 0, "beside the head");
    shut(p);
}

/// THE WIPE IS SEEN (codeaudit e916fda tests LOW): a queue buffer holding owed opening bytes goes
/// back to the allocator wiped, both when the queue outgrows it and when the queue drops.
#[test]
fn an_opening_buffer_goes_back_wiped() {
    use crate::faults_tests::{freed_wiped, watch_free};
    const SECRET: &[u8] = b"Bearer sk-wipe-me";
    let mut owed = Owed::default();
    owed.push(SECRET, true);
    watch_free(owed.wire.as_ptr(), owed.wire.capacity(), SECRET);
    owed.push(&vec![0x22; 4 * owed.wire.capacity()], false);
    assert_eq!(freed_wiped(), Some(true), "outgrown, wiped");
    watch_free(owed.wire.as_ptr(), owed.wire.capacity(), SECRET);
    drop(owed);
    assert_eq!(freed_wiped(), Some(true), "dropped, wiped");
}
