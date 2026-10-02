// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE `ws` DOOR, BOTH WAYS IN**: the linked door (`busbar_transport_ws::linked::door`) and this
//! crate's built cdylib (the same door behind the one `export_door!`), each admitted through the
//! loader's ONE door validation and driven through the ONE dispatcher's crossing, give the same
//! Statement and the same answers. A dialling framing's bytes are random by design (the handshake
//! key, every frame's mask), so the comparison is of what each end HEARD, not of the dialler's wire. Run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused, linked (by the door's
//! own kind) and dropped in (by the stated kind, before `dlopen`). A missing cdylib PANICS: this
//! test IS the dropped-in door's proof, and never skips.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::{
    slot, BeginIn, EmitIn, FinishIn, FramePiece, FramerOut, FramerSink, IngestIn, CLOSE_NORMAL,
    PIECE_END_OF_FRAME, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_MORE,
};
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
    LinkedRow, LoadError, NoSink, Plugin,
};
use busbar_transport_ws_plugin::linked;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_ws_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-transport-ws-plugin cdylib ({file}) is not built"))
}

/// The row a compiled-in build holds for this door.
fn row() -> LinkedRow {
    LinkedRow::of(linked::door).expect("the door states itself")
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn open(p: &Plugin<Transport>) {
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    };
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    assert_eq!(p.call(life::OPEN, &mut f).outcome, Outcome::Ready);
}

/// One end of the exchange: its framing, what it wrote to the wire, what it heard.
#[derive(Default)]
struct End {
    framing: u64,
    wire: Vec<u8>,
    frames: Vec<(Vec<u8>, bool)>,
    ended: bool,
}

/// The host's sink buffers, `caps` = (wire, frame, pieces).
struct Host {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
}

impl Host {
    fn new(caps: (usize, usize, usize)) -> Self {
        Self {
            wire: vec![0; caps.0],
            frame: vec![0; caps.1],
            pieces: vec![z(); caps.2],
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 3_000_000_000,
            now_unix_ns: 1_790_000_000_000_000_000,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// Take an answer into `end`; true = it asked to be called again.
    fn take(&self, o: &FramerOut, end: &mut End) -> bool {
        end.wire
            .extend_from_slice(&self.wire[..o.yielded.wire_len as usize]);
        for p in &self.pieces[..o.yielded.pieces_len as usize] {
            let b = &self.frame[p.offset as usize..(p.offset + p.len) as usize];
            match end.frames.last_mut() {
                Some((open, false)) => open.extend_from_slice(b),
                _ => end.frames.push((b.to_vec(), false)),
            }
            if p.flags & PIECE_END_OF_FRAME != 0 {
                end.frames.last_mut().expect("a frame").1 = true;
            }
        }
        end.ended |= o.yielded.flags & YIELD_ENDED != 0;
        o.yielded.flags & YIELD_MORE != 0
    }

    /// The `YIELD_MORE` re-call: an `ingest` with no new bytes, until the framing has said it all.
    fn again(&mut self, p: &Plugin<Transport>, mut more: bool, end: &mut End) {
        let mut calls = 0;
        while more {
            calls += 1;
            assert!(calls < 100_000, "a re-call never ran dry");
            more = self.ingest(p, &[], end);
        }
    }

    fn ingest(&mut self, p: &Plugin<Transport>, bytes: &[u8], end: &mut End) -> bool {
        let mut i: IngestIn = z();
        i.head = in_head();
        i.framing = end.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        assert_eq!(p.call(slot::INGEST, &mut f).outcome, Outcome::Ready);
        self.take(&f.out, end)
    }

    fn begin(&mut self, p: &Plugin<Transport>, side: u32, target: &'static str) -> End {
        let mut end = End::default();
        let mut i: BeginIn = z();
        i.head = in_head();
        i.side = side;
        i.target = AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        };
        i.sink = self.sink();
        let mut o: FramerOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        assert_eq!(p.call(slot::BEGIN, &mut f).outcome, Outcome::Ready);
        end.framing = f.out.framing;
        let more = self.take(&f.out, &mut end);
        self.again(p, more, &mut end);
        end
    }

    /// Carry what `from` has written to `to`.
    fn carry(&mut self, p: &Plugin<Transport>, from: &mut End, to: &mut End) {
        let bytes = std::mem::take(&mut from.wire);
        if bytes.is_empty() {
            return;
        }
        let more = self.ingest(p, &bytes, to);
        self.again(p, more, to);
    }

    fn say(&mut self, p: &Plugin<Transport>, end: &mut End, message: &'static str) {
        let mut i: EmitIn = z();
        i.head = in_head();
        i.framing = end.framing;
        i.bytes = message.as_ptr();
        i.len = message.len();
        i.end_of_frame = 1;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        assert_eq!(p.call(slot::EMIT, &mut f).outcome, Outcome::Ready);
        let more = self.take(&f.out, end);
        self.again(p, more, end);
    }

    fn finish(&mut self, p: &Plugin<Transport>, end: &mut End) {
        let mut i: FinishIn = z();
        i.head = in_head();
        i.framing = end.framing;
        i.reason = CLOSE_NORMAL;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        assert_eq!(p.call(slot::FINISH, &mut f).outcome, Outcome::Ready);
        let more = self.take(&f.out, end);
        self.again(p, more, end);
    }
}

/// What the exchange left: the upgrade's first lines, what each end heard, whether the far end's
/// stream ended with an empty piece and its connection with `YIELD_ENDED`.
type Script = (bool, bool, Vec<Vec<u8>>, Vec<Vec<u8>>, bool, bool);

/// One exchange through the dispatcher: the upgrade, one message each way, the dialled end's close.
fn script(p: &Plugin<Transport>, caps: (usize, usize, usize)) -> Script {
    let mut host = Host::new(caps);
    let mut dial = host.begin(p, SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(p, SIDE_ACCEPT, "");
    let upgrade = dial.wire.starts_with(b"GET /stream HTTP/1.1\r\n");
    host.carry(p, &mut dial, &mut accept);
    let answered = accept.wire.starts_with(b"HTTP/1.1 101");
    host.carry(p, &mut accept, &mut dial);
    host.say(p, &mut dial, "hello");
    host.carry(p, &mut dial, &mut accept);
    host.say(p, &mut accept, "world");
    host.carry(p, &mut accept, &mut dial);
    host.finish(p, &mut dial);
    host.carry(p, &mut dial, &mut accept);
    let whole = |e: &End| -> Vec<Vec<u8>> {
        e.frames
            .iter()
            .filter(|(b, whole)| *whole && !b.is_empty())
            .map(|(b, _)| b.clone())
            .collect()
    };
    let last = accept.frames.last().expect("frames");
    let stream_end = last.0.is_empty() && last.1;
    (
        upgrade,
        answered,
        whole(&accept),
        whole(&dial),
        stream_end,
        accept.ended,
    )
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_framer() {
    let d = Dispatcher::new(DispatchConfig::default());
    let linked: Plugin<Transport> = load_linked(&row(), bind(&d)).expect("the linked door loads");
    let dropped: Plugin<Transport> =
        load_dropped(&cdylib(), &row().statement, bind(&d)).expect("the dropped-in door loads");
    assert_eq!(linked.name(), linked::KEY);
    assert_eq!(dropped.name(), linked.name());
    open(&linked);
    open(&dropped);

    for caps in [(64 * 1024, 64 * 1024, 64), (7, 3, 1)] {
        let a = script(&linked, caps);
        let b = script(&dropped, caps);
        assert!(a.0, "a dialled framing opens with the upgrade request");
        assert!(a.1, "an accepted framing answers 101");
        assert_eq!(a.2, [b"hello".to_vec()], "the accepted end heard hello");
        assert_eq!(a.3, [b"world".to_vec()], "the dialled end heard world");
        assert!(a.4, "the far side's stream ends with an empty piece");
        assert!(a.5, "and its connection with YIELD_ENDED");
        assert_eq!(a, b, "both doors answer alike");
    }
}

#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let d = Dispatcher::new(DispatchConfig::default());
    let want = (KindCode::Transport, KindCode::Hook);
    match load_linked::<Hook>(&row(), bind(&d)) {
        Err(LoadError::WrongKind { door, want: asked }) => assert_eq!((door, asked), want),
        other => panic!("the linked door loaded as a hook: {:?}", other.err()),
    }
    match load_dropped::<Hook>(&cdylib(), &row().statement, bind(&d)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
        other => panic!("the dropped-in door loaded as a hook: {:?}", other.err()),
    }
}
