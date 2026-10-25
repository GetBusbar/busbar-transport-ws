// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's answer filling: a dialled head's reason phrase rides only beside its head's first
//! piece.

use super::*;
use busbar_contract::abi::transport::{FramePiece, FramerOut as DoorOut, HeadSlots};

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
        // SAFETY: plain C data; all-zero is valid.
        let mut o: DoorOut = unsafe { std::mem::zeroed() };
        fill(owed, &sink(&mut frame, &mut pieces, &mut heads), &mut o);
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
    let inst = Instance {
        framer: WsFramer::new(0),
        owed: Mutex::new(HashMap::new()),
        services: None,
        refused: Mutex::new(String::new()),
    };
    let mut sink_out = Owed::default();
    let mut c = Collect {
        owed: &mut sink_out,
        now: HostTime {
            monotonic_nanos: 0,
            unix_nanos: 0,
        },
    };
    let state = inst
        .framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut c)
        .expect("the dial opens");
    let slot: OwedSlot = Arc::new(Mutex::new(Owed::default()));
    inst.queues().insert(state, Arc::clone(&slot));
    // An op on this framing panicked while holding its queue.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = slot.lock();
        panic!("an op panicked");
    }));
    assert!(slot.is_poisoned());
    // SAFETY: plain C data; all-zero is valid.
    let mut i: FinishIn = unsafe { std::mem::zeroed() };
    i.framing = state;
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    let p = std::ptr::from_ref(&inst).cast_mut().cast::<c_void>();
    assert_eq!(Finish::call(p, &i, &mut o), Outcome::Failed);
    assert!(
        !inst.queues().contains_key(&state),
        "the door's queue is gone"
    );
    assert!(!inst.framer.holds(state), "the framer's state is gone too");
}

/// THE HOST'S CANCEL RELEASES A DIAL PARKED ON ITS AUTH (Q128 transport-ws LOW, reader r162 on
/// 0769fe6): a `begin` that answered PENDING on its auth call holds its built dial under its
/// ticket; the host's cancel of that ticket drops it (nothing went out, so nothing moved), whether
/// or not the op had a deadline. RED before the fix: cancel ignored the ticket, and the dial stayed
/// parked for the instance's life.
#[test]
fn a_cancel_releases_the_dial_parked_on_its_ticket() {
    let inst = Instance {
        framer: WsFramer::new(0),
        owed: Mutex::new(HashMap::new()),
        services: None,
        refused: Mutex::new(String::new()),
    };
    let parking = crate::transport::Parking {
        ticket: (3, 9),
        deadline: 0,
        now: 0,
    };
    let mut sink_out = Owed::default();
    let mut c = Collect {
        owed: &mut sink_out,
        now: HostTime {
            monotonic_nanos: 0,
            unix_nanos: 0,
        },
    };
    let mut pending = |_: &crate::transport::UpgradeHead<'_>| Poll::Pending;
    assert!(inst
        .framer
        .open_signed(parking, "ws://127.0.0.1:9/x", &[], &mut pending, &mut c)
        .is_pending());
    assert_eq!(inst.framer.parked(), 1);
    // SAFETY: plain C data; all-zero is valid.
    let mut i: CancelIn = unsafe { std::mem::zeroed() };
    i.ticket = Ticket {
        slot: 3,
        generation: 9,
    };
    let mut o: CancelOut = unsafe { std::mem::zeroed() };
    let p = std::ptr::from_ref(&inst).cast_mut().cast::<c_void>();
    assert_eq!(Cancel::call(p, &i, &mut o), Outcome::Ready);
    assert_eq!(o.disposition, CANCEL_NOTHING_MOVED, "nothing went out");
    assert_eq!(inst.framer.parked(), 0, "the parked dial is released");
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
        // SAFETY: plain C data; all-zero is valid.
        let mut o: DoorOut = unsafe { std::mem::zeroed() };
        fill(owed, &s, &mut o);
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
    push_wiped(&mut owed.wire, &mut owed.wire_at, &wire_bytes);
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
    push_wiped(&mut owed.wire, &mut owed.wire_at, &[0xAA; 300]);
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
    // SAFETY: plain C data; all-zero is valid.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    fill(&mut owed, &s, &mut o);
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
        push_wiped(&mut owed.wire, &mut owed.wire_at, &[0x5A; 101]);
        consume_wiped(&mut owed.wire, &mut owed.wire_at, 100);
        let backlog = owed.wire_owed().len();
        assert!(
            owed.wire.capacity() <= 2 * (backlog + 101),
            "capacity {} for a backlog of {backlog}",
            owed.wire.capacity()
        );
    }
}
