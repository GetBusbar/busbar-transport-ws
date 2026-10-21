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

/// A DIALLED HEAD'S REASON GOES ONLY WITH ITS HEAD'S FIRST PIECE (Q128 transport-ws LOW, reader
/// r52 on 3286006; HEAD-FIELDS): an answer with room for the phrase but not for any of the piece
/// beside it hands up neither, and the phrase goes out with the piece in the next answer. RED
/// before the fix: the phrase's slot went alone in the first answer, and the host dropped it.
#[test]
fn a_reason_rides_only_beside_its_heads_first_piece() {
    let mut owed = Owed::default();
    let mut head = Piece::plain(0, Bytes::from_static(b"x-a: 1\r\n"), true);
    head.fields = true;
    head.reason = Some(b"Unauthorized".to_vec());
    owed.pieces.push_back(head);
    // Room for the phrase (12 bytes) and one byte more: no cut of the field block fits beside it.
    let (mut frame, mut pieces, mut heads) = (
        [0_u8; 13],
        unsafe { std::mem::zeroed::<[FramePiece; 4]>() },
        [HeadSlots::default(); 2],
    );
    // SAFETY: plain C data; all-zero is valid.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    fill(
        &mut owed,
        &sink(&mut frame, &mut pieces, &mut heads),
        0,
        &mut o,
    );
    assert_eq!((o.yielded.heads_len, o.yielded.pieces_len), (0, 0));
    assert!(
        owed.pieces[0].reason.is_some(),
        "the phrase waits for its piece"
    );
    let (mut frame, mut pieces, mut heads) = (
        [0_u8; 64],
        unsafe { std::mem::zeroed::<[FramePiece; 4]>() },
        [HeadSlots::default(); 2],
    );
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    fill(
        &mut owed,
        &sink(&mut frame, &mut pieces, &mut heads),
        0,
        &mut o,
    );
    assert_eq!((o.yielded.heads_len, o.yielded.pieces_len), (1, 1));
    let r = heads[0].reason;
    assert_eq!(
        &frame[r.offset as usize..(r.offset + r.len) as usize],
        b"Unauthorized"
    );
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
    };
    let mut sink_out = Owed::default();
    let mut c = Collect {
        owed: &mut sink_out,
        now: HostTime {
            monotonic_nanos: 0,
            unix_nanos: 0,
        },
        sink: None,
        wire_at: 0,
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
        sink: None,
        wire_at: 0,
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

/// Output nobody reads.
struct Quiet;

impl Out for Quiet {
    fn send(&mut self, _: &[u8]) {}
    fn frame(&mut self, _: Framed<'_>) {}
    fn end(&mut self) {}
    fn now(&self) -> HostTime {
        HostTime {
            monotonic_nanos: 0,
            unix_nanos: 0,
        }
    }
    fn wake_at(&mut self, _: Option<u64>) {}
}

/// A REFRESH APPLIES ITS SETTINGS OR REFUSES THEM (audit: refresh answered READY and ignored the
/// settings blob it carries): a blob `open` would refuse is refused, and a new message ceiling
/// holds for what is written after it. RED before the fix: every refresh answered READY, and the
/// ceiling stayed the one `open` read.
#[test]
fn a_refresh_applies_its_ceiling_or_refuses_its_settings() {
    let inst = Instance {
        framer: WsFramer::new(0),
        owed: Mutex::new(HashMap::new()),
        services: None,
    };
    let p = std::ptr::from_ref(&inst).cast_mut().cast::<c_void>();
    let refresh = |settings: &[u8]| {
        // SAFETY: plain C data; all-zero is valid.
        let mut i: RefreshIn = unsafe { std::mem::zeroed() };
        // SAFETY: `settings` outlives the call below; the format and flags stay zero, as the
        // zeroed blob had them.
        i.settings = unsafe { Blob::from_raw_parts(settings.as_ptr(), settings.len(), 0, 0) };
        // SAFETY: plain C data; all-zero is valid.
        let mut o: OutHead = unsafe { std::mem::zeroed() };
        Refresh::call(p, &i, &mut o)
    };
    assert_eq!(
        refresh(b"not json".as_slice()),
        Outcome::Failed,
        "a blob open refuses"
    );
    assert_eq!(
        refresh(br#"{"limits.request_body_max_bytes":"many"}"#.as_slice()),
        Outcome::Failed,
        "a ceiling that is no count"
    );
    let state = inst
        .framer
        .open_with(Side::Dial, "ws://127.0.0.1:9/x", &[], &mut Quiet)
        .expect("the dial opens");
    assert!(
        inst.framer
            .emit_text(state, b"12345", true, false, &mut Quiet)
            .is_ok(),
        "no ceiling yet"
    );
    assert_eq!(
        refresh(br#"{"limits.request_body_max_bytes":4}"#.as_slice()),
        Outcome::Ready
    );
    assert!(
        inst.framer
            .emit_text(state, b"12345", true, false, &mut Quiet)
            .is_err(),
        "the refreshed ceiling holds for what is written after it"
    );
}
