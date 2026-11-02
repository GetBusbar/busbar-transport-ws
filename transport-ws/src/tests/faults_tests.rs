// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT'S FAULT EDGES, one binary so one run judges them all:

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem::zeroed;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(target_os = "linux")]
use std::{fs::File, os::unix::fs::FileExt, sync::OnceLock};

use crate::door::{Begin, Emit, Ingest, Ws};
use crate::frame::{Framed, FramerOut, HostTime, Side};
use crate::meta;
use crate::transport::WsFramer;
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::Entry;
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::sdk::Safe;
use busbar_contract::abi::transport::{
    slot, BeginIn, Claim, EmitIn, FramePiece, FramerOut as DoorOut, FramerSink, IngestIn,
    TransportTail, SIDE_ACCEPT, UNIT0_UPGRADE, YIELD_MORE,
};
use tungstenite::protocol::Role;
use tungstenite::{Bytes, Message, WebSocket};

const UPGRADE: &[u8] = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

fn text(s: &AbiStr) -> &'static [u8] {
    if s.len == 0 {
        return &[];
    }
    // SAFETY: the Statement's strings are `'static` plugin data of their stated length.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }
}

fn claims() -> (Vec<String>, &'static [Claim]) {
    let st = crate::door::STATEMENT;
    // SAFETY: the Statement's claim list and kind tail are this crate's `'static` data.
    let names: &[AbiStr] = unsafe { std::slice::from_raw_parts(st.claims, st.claims_len) };
    let tail = unsafe { &*st.kind_tail.cast::<TransportTail>() };
    let rows: &[Claim] =
        unsafe { std::slice::from_raw_parts(tail.claim_rows, tail.claim_rows_len) };
    let names = names
        .iter()
        .map(|n| String::from_utf8_lossy(text(n)).into_owned())
        .collect();
    (names, rows)
}

/// The transport claims both `ws` and `wss`.
#[test]
fn ws_claims_ws_and_wss() {
    let (names, rows) = claims();
    assert_eq!(names, ["ws", "wss"]);
    assert_eq!(rows.len(), names.len(), "one row per claim");
}

/// Every claim row agrees with the transport's declaration.
#[test]
fn every_claim_row_states_the_declaration() {
    const N: usize = meta::SELECTOR_FORMS.len();
    let forms: [u8; N] = form_codes(meta::SELECTOR_FORMS);
    let facts: Vec<&[u8]> = meta::TRANSPORT_FACTS.iter().map(|f| f.as_bytes()).collect();
    let (_, rows) = claims();
    assert!(!rows.is_empty());
    for row in rows {
        assert_eq!(text(&row.selector_forms), forms, "selector forms");
        assert!(
            text(&row.egress_selector_forms).is_empty(),
            "no egress forms"
        );
        // SAFETY: `facts_len` `'static` strings at `facts`.
        let stated: Vec<&[u8]> = if row.facts_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(row.facts, row.facts_len) }
                .iter()
                .map(text)
                .collect()
        };
        assert_eq!(stated, facts, "transport facts");
        assert_eq!(row.session, u8::from(meta::SESSION), "session");
        assert_eq!(
            row.session_bound,
            u8::from(meta::SESSION_BOUND),
            "session_bound"
        );
        assert_eq!(
            row.unit0_trigger, UNIT0_UPGRADE,
            "unit 0 opens at the upgrade"
        );
        assert_eq!(row.status_at, 0, "no status leg");
        assert!(
            text(&row.status_namespace).is_empty(),
            "no status numbering"
        );
    }
}

/// What one framer call said.
#[derive(Default)]
struct Out {
    wire: Vec<u8>,
    frames: Vec<Vec<u8>>,
    ended: bool,
    /// The layer above fails while it takes a frame.
    panics: bool,
}

impl FramerOut for Out {
    fn send(&mut self, bytes: &[u8]) {
        self.wire.extend_from_slice(bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        assert!(!self.panics, "the layer above failed while it took a frame");
        self.frames.push(piece.bytes.to_vec());
    }
    fn end(&mut self) {
        self.ended = true;
    }
    fn now(&self) -> HostTime {
        HostTime { unix_nanos: 1 }
    }
}

/// A client's binary message `hi`, masked with the all-zero key.
const HI: &[u8] = &[0x82, 0x82, 0, 0, 0, 0, b'h', b'i'];

/// An accepted framing past its upgrade.
fn accepted(f: &WsFramer) -> u64 {
    let mut out = Out::default();
    let s = f
        .open(Side::Accept, "", &mut out)
        .expect("an accepted framing opens");
    f.ingest(s, UPGRADE, false, &mut out)
        .expect("the upgrade is answered");
    assert!(out.wire.starts_with(b"HTTP/1.1 101"), "switching protocols");
    s
}

/// What a dial to `target` writes first: its upgrade request.
fn opening(target: &str) -> String {
    let f = WsFramer::new(0);
    let mut out = Out::default();
    let opened = f.open(Side::Dial, target, &mut out);
    assert!(opened.is_ok(), "a dial to {target} opens: {opened:?}");
    String::from_utf8_lossy(&out.wire).into_owned()
}

/// IPv6 literal targets locate with bracketed addresses.
#[test]
fn an_ipv6_literal_target_locates_bracketed() {
    let f = WsFramer::new(0);
    let at = f.locate("ws://[::1]:8080/x").expect("a ws URL locates");
    assert_eq!(at.authority, "[::1]:8080");
    let at = f
        .locate("wss://[2001:db8::1]/x")
        .expect("a wss URL locates");
    assert_eq!(at.authority, "[2001:db8::1]:443");
    assert!(at.secure);
    let at = f.locate("ws://svc.test/x").expect("a name locates");
    assert_eq!(at.authority, "svc.test:80", "a name is never bracketed");
}

/// An IPv6 literal target opens a dial with the expected request and Host field.
#[test]
fn an_ipv6_literal_target_dials() {
    let request = opening("ws://[::1]:8080/x");
    assert!(request.starts_with("GET /x HTTP/1.1\r\n"), "{request}");
    assert!(request.contains("\r\nHost: [::1]:8080\r\n"), "{request}");
}

/// A dial sends the Host field as stated in its target.
#[test]
fn a_dial_sends_the_host_as_the_target_writes_it() {
    let request = opening("wss://api.example/v1/realtime?model=m");
    assert!(
        request.starts_with("GET /v1/realtime?model=m HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nHost: api.example\r\n"), "{request}");
    let request = opening("ws://svc.test:8080/x");
    assert!(request.contains("\r\nHost: svc.test:8080\r\n"), "{request}");
}

/// A carrier ending without a close frame fails the stream.
#[test]
fn a_carrier_end_without_a_close_ends_the_stream_failed() {
    const WHY: &str = "the carrier ended with no WebSocket closing handshake";
    let f = WsFramer::new(0);
    let s = accepted(&f);
    let mut out = Out::default();
    let r = f.ingest(s, HI, true, &mut out);
    assert!(
        r.is_ok(),
        "a dropped connection is not a framing failure: {r:?}"
    );
    assert_eq!(
        out.frames,
        [b"hi".to_vec()],
        "the message before it is handed up"
    );
    assert!(out.ended, "and the stream ends");
    assert_eq!(f.failure(s), Some(WHY), "failed, not whole");

    let s = accepted(&f);
    let mut out = Out::default();
    let r = f.ingest(s, &[], true, &mut out);
    assert!(r.is_ok(), "an end with nothing before it: {r:?}");
    assert!(out.ended);
    assert_eq!(f.failure(s), Some(WHY));

    let s = accepted(&f);
    let mut out = Out::default();
    let r = f.ingest(s, &[0x02, 0x82, 0, 0, 0, 0, b'h', b'i'], true, &mut out);
    assert!(r.is_ok(), "{r:?}");
    assert!(
        out.ended && out.frames.is_empty(),
        "no partial message is handed up"
    );
    assert_eq!(f.failure(s), Some(WHY));
}

/// A panic in one framing leaves other framings usable.
#[test]
fn a_panic_in_one_framing_leaves_the_others_working() {
    let f = WsFramer::new(0);
    let a = accepted(&f);
    let b = f
        .open(Side::Accept, "", &mut Out::default())
        .expect("a second framing opens");
    let mut failing = Out {
        panics: true,
        ..Out::default()
    };
    let hit = catch_unwind(AssertUnwindSafe(|| f.ingest(a, HI, false, &mut failing)));
    assert!(hit.is_err(), "the layer above panicked inside framing a");

    let mut out = Out::default();
    let other = catch_unwind(AssertUnwindSafe(|| f.ingest(b, UPGRADE, false, &mut out)));
    assert!(
        matches!(other, Ok(Ok(()))),
        "framing b still works after framing a panicked"
    );
    assert!(
        out.wire.starts_with(b"HTTP/1.1 101"),
        "and answers its upgrade"
    );
    let later = catch_unwind(AssertUnwindSafe(|| {
        f.emit(
            b,
            busbar_contract::ids::StreamId(0),
            b"ok",
            true,
            false,
            &mut out,
        )
    }));
    assert!(matches!(later, Ok(Ok(()))), "and writes");
}

/// Counts every allocation (and reallocation) the CURRENT thread makes while its count is on, so
struct Counting;

/// An allocation's base, its greatest known initialized prefix, and its secret marker.
type Watch = (usize, usize, &'static [u8]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    #[cfg(target_os = "linux")]
    Wiped,
    #[cfg(target_os = "linux")]
    Unwiped,
    #[cfg(target_os = "linux")]
    Bounds,
    #[cfg(target_os = "linux")]
    MissingReader,
    #[cfg(target_os = "linux")]
    ShortRead,
    #[cfg(target_os = "linux")]
    ReadError,
    #[cfg(target_os = "linux")]
    Reentered,
    #[cfg(not(target_os = "linux"))]
    Unsupported,
}

#[cfg(target_os = "linux")]
static MEMORY: OnceLock<File> = OnceLock::new();

const SECRET_MAX: usize = 128;

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
    static WATCH: Cell<Option<Watch>> = const { Cell::new(None) };
    static WATCHED: Cell<Option<Observation>> = const { Cell::new(None) };
    #[cfg(target_os = "linux")]
    static READING: Cell<bool> = const { Cell::new(false) };
    #[cfg(target_os = "linux")]
    static REENTERED: Cell<bool> = const { Cell::new(false) };
}

/// Watch a live allocation's base and a prefix known to have been initialized, even if its Vec
pub(crate) fn watch_free(ptr: *const u8, len: usize, secret: &'static [u8]) {
    assert!(!ptr.is_null() && len >= secret.len());
    assert!((1..=SECRET_MAX).contains(&secret.len()));
    #[cfg(target_os = "linux")]
    MEMORY.get_or_init(|| File::open("/proc/self/mem").expect("open the Linux wipe observer"));
    WATCHED.with(|w| w.set(None));
    WATCH.with(|w| {
        let len = match w.get() {
            Some((address, prior, marker)) => {
                assert_eq!(
                    address, ptr as usize,
                    "the preceding watched allocation has not freed"
                );
                assert_eq!(marker, secret);
                prior.max(len)
            }
            None => len,
        };
        w.set(Some((ptr as usize, len, secret)));
    });
}

/// Require the actual free on every platform and a complete Linux byte observation. Other
pub(crate) fn assert_freed_wiped() {
    let observed = WATCHED.with(Cell::get);
    assert!(
        observed.is_some(),
        "the watched allocation must actually be freed"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        observed,
        Some(Observation::Wiped),
        "complete pre-free OS observation"
    );
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(observed, Some(Observation::Unsupported));
        eprintln!(
            "wipe-proof gap: matched free only; physical-byte proof requires the Linux observer"
        );
    }
}

#[cfg(target_os = "linux")]
fn read_reentered_allocator() -> bool {
    READING
        .try_with(|reading| {
            if reading.get() {
                let _ = REENTERED.try_with(|flag| flag.set(true));
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn observe((address, len, secret): Watch, allocation_size: usize) -> Observation {
    if len > allocation_size || address.checked_add(len).is_none() {
        return Observation::Bounds;
    }
    let Some(memory) = MEMORY.get() else {
        return Observation::MissingReader;
    };
    let Ok(address) = u64::try_from(address) else {
        return Observation::Bounds;
    };
    let mut chunk = [0_u8; 4096 + SECRET_MAX - 1];
    let (mut offset, mut carried, mut held) = (0, 0, false);
    while offset < len {
        let count = (len - offset).min(4096);
        let Some(at) = address.checked_add(offset as u64) else {
            return Observation::Bounds;
        };
        match memory.read_at(&mut chunk[carried..carried + count], at) {
            Ok(read) if read == count => {}
            Ok(_) => return Observation::ShortRead,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Observation::ReadError,
        }
        let total = carried + count;
        held |= chunk[..total]
            .windows(secret.len())
            .any(|run| run == secret);
        carried = total.min(secret.len() - 1);
        chunk.copy_within(total - carried..total, 0);
        offset += count;
    }
    if held {
        Observation::Unwiped
    } else {
        Observation::Wiped
    }
}

/// The kernel copies only the registered initialized prefix into initialized stack storage,
fn inspect(ptr: *mut u8, allocation_size: usize) {
    let _ = WATCH.try_with(|w| {
        let Some(watch) = w.get().filter(|(at, _, _)| *at == ptr as usize) else {
            return;
        };
        w.set(None);
        #[cfg(target_os = "linux")]
        let observed = READING
            .try_with(|reading| {
                if reading.replace(true) {
                    return Observation::Reentered;
                }
                let _ = REENTERED.try_with(|flag| flag.set(false));
                let observed = observe(watch, allocation_size);
                reading.set(false);
                if REENTERED.try_with(Cell::get).unwrap_or(true) {
                    Observation::Reentered
                } else {
                    observed
                }
            })
            .unwrap_or(Observation::Reentered);
        #[cfg(not(target_os = "linux"))]
        let observed = {
            let _ = (watch, allocation_size);
            Observation::Unsupported
        };
        let _ = WATCHED.try_with(|r| r.set(Some(observed)));
    });
}

fn bump() {
    let _ = COUNT.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
        }
    });
}

// SAFETY: allocation/free layouts are forwarded unchanged to System. A watched realloc uses the
// trait's allocate/copy/free strategy so its old allocation is observed before physical free.
// The watch only asks the kernel to copy a registered, previously initialized prefix to initialized
// stack storage, bounded by the allocator's layout. No Rust source-memory reference is formed.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(target_os = "linux")]
        read_reentered_allocator();
        bump();
        // SAFETY: the caller's layout, passed on.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(target_os = "linux")]
        let reentered = read_reentered_allocator();
        #[cfg(not(target_os = "linux"))]
        let reentered = false;
        if !reentered {
            inspect(ptr, layout.size());
        }
        // SAFETY: as allocated above.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        #[cfg(target_os = "linux")]
        read_reentered_allocator();
        bump();
        let watched = WATCH
            .try_with(|w| w.get().is_some_and(|(at, _, _)| at == ptr as usize))
            .unwrap_or(false);
        if watched {
            // SAFETY: GlobalAlloc's caller guarantees this new layout and nonzero size.
            let next = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
            // SAFETY: allocate/copy/free is GlobalAlloc's default reallocation strategy. Raw
            // copying preserves uninitialized bytes without creating a Rust source reference.
            let grown = unsafe { System.alloc(next) };
            if !grown.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, grown, layout.size().min(new_size));
                }
                unsafe {
                    self.dealloc(ptr, layout);
                }
            }
            return grown;
        }
        // SAFETY: as allocated above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

/// The door's own slots, entered as its trampoline enters them but outside it: the count is the
struct Host {
    inst: *mut c_void,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    framing: u64,
}

impl Host {
    /// An open instance with one accepted framing past its upgrade, and roomy buffers.
    fn accepted() -> Self {
        let i: OpenIn = z();
        let mut o: OpenOut = z();
        // SAFETY: no instance yet, and an `in` lending nothing.
        let r = unsafe {
            Safe::<busbar_contract::abi::sdk::life::Open<Ws>>::enter(
                std::ptr::null_mut(),
                life::OPEN,
                &i,
                &mut o,
            )
        };
        assert_eq!(r, Outcome::Ready);
        let mut host = Host {
            inst: o.instance,
            wire: vec![0; 64 * 1024],
            frame: vec![0; 64 * 1024],
            pieces: vec![z(); 64],
            framing: 0,
        };
        let mut b: BeginIn = z();
        b.side = SIDE_ACCEPT;
        b.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
        b.target = AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        };
        b.sink = host.sink();
        let mut bo: DoorOut = z();
        // SAFETY: the instance `open` answered, and the host's buffers lent in the sink.
        let r = unsafe { Safe::<Begin>::enter(host.inst, slot::BEGIN, &b, &mut bo) };
        assert_eq!(r, Outcome::Ready);
        host.framing = bo.framing;
        let answer = host.ingest(UPGRADE);
        assert!(host.wire[..answer.yielded.wire_len as usize].starts_with(b"HTTP/1.1 101"));
        host
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

    /// One ingest of `bytes` (none: the bare crossing); every answer fits the sink in one call.
    fn ingest(&mut self, bytes: &[u8]) -> DoorOut {
        let mut i: IngestIn = z();
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: DoorOut = z();
        // SAFETY: the instance `open` answered, and the host's buffers lent in the sink.
        let r = unsafe { Safe::<Ingest>::enter(self.inst, slot::INGEST, &i, &mut o) };
        assert_eq!(r, Outcome::Ready);
        assert_eq!(o.yielded.flags & YIELD_MORE, 0, "a roomy sink holds it all");
        o
    }

    /// One whole binary message out.
    fn emit(&mut self, message: &[u8]) -> DoorOut {
        let mut i: EmitIn = z();
        i.framing = self.framing;
        i.bytes = message.as_ptr();
        i.len = message.len();
        i.end_of_frame = 1;
        i.sink = self.sink();
        let mut o: DoorOut = z();
        // SAFETY: the instance `open` answered, and the host's buffers lent in the sink.
        let r = unsafe { Safe::<Emit>::enter(self.inst, slot::EMIT, &i, &mut o) };
        assert_eq!(r, Outcome::Ready);
        assert_eq!(o.yielded.flags & YIELD_MORE, 0, "a roomy sink holds it all");
        o
    }
}

/// The text a client sends, and its frame, masked.
const TEXT: &[u8; 32] = b"a text message of thirty-two b..";

fn text_frame() -> Vec<u8> {
    let key = [0x37, 0xfa, 0x21, 0x3d];
    let mut f = vec![0x81, 0x80 | 32];
    f.extend_from_slice(&key);
    f.extend(TEXT.iter().enumerate().map(|(k, b)| b ^ key[k % 4]));
    f
}

const ROUNDS: usize = 256;

/// Allocations per call of `op`, in steady state, on this thread.
fn per_call<T>(state: &mut T, op: &mut dyn FnMut(&mut T)) -> f64 {
    for _ in 0..64 {
        op(state);
    }
    COUNT.with(|c| c.set(Some(0)));
    for _ in 0..ROUNDS {
        op(state);
    }
    let n = COUNT.with(|c| c.replace(None)).unwrap_or(0);
    n as f64 / ROUNDS as f64
}

/// An in-memory socket for the protocol library alone, read and written as the framer's pipe is.
#[derive(Default)]
struct Socket {
    inbound: VecDeque<u8>,
    outbound: Vec<u8>,
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inbound.is_empty() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(self.inbound.len());
        for (slot, b) in buf.iter_mut().zip(self.inbound.drain(..n)) {
            *slot = b;
        }
        Ok(n)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Steady-state framing adds no allocation of its own per message.
#[test]
fn a_steady_framing_adds_no_allocation_of_its_own_per_message() {
    let mut ws = WebSocket::from_raw_socket(Socket::default(), Role::Server, None);
    let frame = text_frame();
    let library_in = per_call(&mut ws, &mut |ws| {
        ws.get_mut().inbound.extend(&frame);
        assert!(matches!(ws.read(), Ok(Message::Text(_))));
        assert!(ws.read().is_err(), "nothing more yet");
        ws.flush().expect("nothing owed");
    });
    let message = [7_u8; 32];
    let library_out = per_call(&mut ws, &mut |ws| {
        ws.send(Message::Binary(Bytes::copy_from_slice(&message)))
            .expect("the library sends");
        ws.get_mut().outbound.clear();
    });

    let mut host = Host::accepted();

    let crossing = per_call(&mut host, &mut |h| {
        let o = h.ingest(&[]);
        assert_eq!(o.yielded.pieces_len, 0);
    });
    let inbound = per_call(&mut host, &mut |h| {
        let o = h.ingest(&frame);
        assert_eq!(o.yielded.pieces_len, 1, "one message, one piece");
        assert_eq!(&h.frame[..32], TEXT);
    });
    let outbound = per_call(&mut host, &mut |h| {
        let o = h.emit(&message);
        assert!(o.yielded.wire_len > 32, "the message goes out");
    });
    println!(
        "PROOF allocations per call: crossing {crossing}; ingest {inbound} (library {library_in}); \
         emit {outbound} (library {library_out})"
    );
    let slack = 0.1;
    assert!(
        inbound <= crossing + library_in + slack,
        "an inbound message costs {inbound} allocations; the crossing {crossing} and the library {library_in}"
    );
    assert!(
        outbound <= crossing + library_out + slack,
        "an outbound message costs {outbound} allocations; the crossing {crossing} and the library {library_out}"
    );
}

/// A response head arriving in small pieces is not copied on every call.
#[test]
fn a_dribbled_answer_head_is_not_copied_per_call() {
    let f = WsFramer::new(0);
    let mut out = Out::default();
    let s = f
        .open(Side::Dial, "ws://svc.test/x", &mut out)
        .expect("the dial opens");
    let mut dial = (f, s, true);
    let head = b"HTTP/1.1 101 Switching Protocols\r\nX-Pad: ";
    let per = per_call(&mut dial, &mut |(f, s, first)| {
        let chunk: &[u8] = if std::mem::take(first) {
            head
        } else {
            &[b'a'; 130]
        };
        f.ingest(*s, chunk, false, &mut Out::default())
            .expect("the head is not whole yet");
    });
    println!("PROOF allocations per dribbled call: {per}");
    assert!(per < 0.25, "a dribbled call costs {per} allocations");
}

/// Emit after the peer's close reports the connection closed.
#[test]
fn an_emit_after_the_peers_close_finds_the_connection_closed() {
    use busbar_contract::transport::wire::TransportError;
    let f = WsFramer::new(0);
    let mut out = Out::default();
    let s = f
        .open(Side::Dial, "ws://svc.test/x", &mut out)
        .expect("the dial opens");
    let request = String::from_utf8(std::mem::take(&mut out.wire)).expect("a request");
    let key = request
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .expect("a key");
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        tungstenite::handshake::derive_accept_key(key.as_bytes())
    );
    f.ingest(s, answer.as_bytes(), false, &mut out)
        .expect("the upgrade completes");

    let mut closed = Out::default();
    f.ingest(s, &[0x88, 0x02, 0x03, 0xe8], false, &mut closed)
        .expect("the far end closes");
    assert!(closed.ended);
    let r = f.emit(
        s,
        busbar_contract::ids::StreamId(0),
        b"late",
        true,
        false,
        &mut out,
    );
    assert_eq!(r, Err(TransportError::Closed));
}

/// The pipe containing a dial's upgrade request is freed and wiped after handover on Linux.
#[test]
fn the_pipe_that_wrote_the_upgrade_request_is_freed_and_wiped_on_linux() {
    const SECRET: &[u8] = b"Bearer sk-start-secret";
    let f = WsFramer::new(0);
    let mut out = Out::default();
    let s = f
        .open_with(
            Side::Dial,
            "ws://svc.test/x",
            &[("authorization".to_string(), SECRET.to_vec())],
            &mut out,
        )
        .expect("the dial opens");
    assert!(out.wire.windows(SECRET.len()).any(|w| w == SECRET), "sent");
    let (ptr, cap) = f.outbound_block(s).expect("a pipe");

    let initialized = out.wire.len();
    assert!(
        cap >= initialized,
        "the block that held the complete request"
    );
    watch_free(ptr, initialized, SECRET);
    f.forget(s);
    assert_freed_wiped();
}

#[cfg(target_os = "linux")]
#[test]
fn a_wipe_observer_requires_a_real_free_and_complete_read_of_the_initialized_prefix() {
    use zeroize::Zeroize;
    const SECRET: &[u8] = b"observer-secret";
    let mut payload = Vec::with_capacity(16384);
    payload.resize(8193, b'!');
    payload[4090..4090 + SECRET.len()].copy_from_slice(SECRET);
    watch_free(payload.as_ptr(), payload.len(), SECRET);
    assert_eq!(WATCHED.with(Cell::get), None, "registration is not a free");
    payload.zeroize();
    drop(payload);
    assert_freed_wiped();
}

#[cfg(target_os = "linux")]
#[test]
fn an_unwiped_old_secret_is_detected_after_clear_and_a_shorter_initialized_reuse() {
    const SECRET: &[u8] = b"observer-secret";
    let mut payload = Vec::with_capacity(16384);
    payload.resize(8193, b'!');
    payload[4090..4090 + SECRET.len()].copy_from_slice(SECRET);
    watch_free(payload.as_ptr(), payload.len(), SECRET);
    payload.clear();
    payload.extend_from_slice(&[0; 32]);
    watch_free(payload.as_ptr(), payload.len(), SECRET);

    drop(payload);
    assert_eq!(WATCHED.with(Cell::get), Some(Observation::Unwiped));
}

#[cfg(target_os = "linux")]
#[test]
fn a_watched_growth_observes_the_actual_old_free_before_the_new_payload_is_wiped() {
    use zeroize::Zeroize;
    const SECRET: &[u8] = b"observer-secret";
    let mut payload = SECRET.to_vec();
    watch_free(payload.as_ptr(), payload.len(), SECRET);
    payload.reserve(4096);
    assert_eq!(WATCHED.with(Cell::get), Some(Observation::Unwiped));
    watch_free(payload.as_ptr(), payload.len(), SECRET);
    payload.zeroize();
    drop(payload);
    assert_freed_wiped();
}
