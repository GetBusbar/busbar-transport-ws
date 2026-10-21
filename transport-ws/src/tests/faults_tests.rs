// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT'S FAULT EDGES, one binary so one run judges them all:
//!
//! - the claims the door's Statement admits, held to the transport's own declaration;
//! - the framer's own face: where a target is and what a dial asks for, how a carrier that ends
//!   without a closing handshake ends the stream, and that one framing's failure is its alone;
//! - the door's per-message allocations (THE DESIGN §11.2, "no allocation ... on the hot path"): a
//!   framing in steady state, one message in and one out per call, adds no allocation beyond the
//!   door crossing itself and what the protocol library allocates for the message.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem::zeroed;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::door::{Begin, Emit, Ingest, Open};
use crate::WsFramer;
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::Slot;
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::transport::{
    BeginIn, Claim, EmitIn, FramePiece, FramerOut as DoorOut, FramerSink, IngestIn, TransportTail,
    SIDE_ACCEPT, UNIT0_UPGRADE, YIELD_MORE,
};
use busbar_contract::alloc_counter::allocations_of;
use busbar_contract::transport::{ConnFacts, Framed, Framer, FramerOut, HostTime, Side};
use busbar_contract::TransportMeta;
use tungstenite::protocol::Role;
use tungstenite::{Bytes, Message, WebSocket};

const UPGRADE: &[u8] = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

// ── the claims ───────────────────────────────────────────────────────────────────────────────────

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

/// RED (audit: `wss` is not claimed): THE DESIGN §5, "ws claims `ws` and `wss`".
#[test]
fn ws_claims_ws_and_wss() {
    let (names, rows) = claims();
    assert_eq!(names, ["ws", "wss"]);
    assert_eq!(rows.len(), names.len(), "one row per claim");
}

/// RED (audit: the admitted claim row contradicts the transport's own declaration): every row the
/// Statement admits states exactly what `TransportMeta` declares (THE DESIGN §2, "Each fact is
/// declared once; anything derivable is derived").
#[test]
fn every_claim_row_states_the_declaration() {
    const N: usize = <WsFramer as TransportMeta>::SELECTOR_FORMS.len();
    let forms: [u8; N] = form_codes(<WsFramer as TransportMeta>::SELECTOR_FORMS);
    let facts: Vec<&[u8]> = <WsFramer as TransportMeta>::TRANSPORT_FACTS
        .iter()
        .map(|f| f.as_bytes())
        .collect();
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
        assert_eq!(
            row.session,
            u8::from(<WsFramer as TransportMeta>::SESSION),
            "session"
        );
        assert_eq!(
            row.session_bound,
            u8::from(<WsFramer as TransportMeta>::SESSION_BOUND),
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

// ── the framer's face ───────────────────────────────────────────────────────────────────────────

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
        HostTime {
            monotonic_nanos: 1,
            unix_nanos: 1,
        }
    }
    fn wake_at(&mut self, _: Option<u64>) {}
}

/// A client's binary message `hi`, masked with the all-zero key.
const HI: &[u8] = &[0x82, 0x82, 0, 0, 0, 0, b'h', b'i'];

/// An accepted framing past its upgrade.
fn accepted(f: &WsFramer) -> u64 {
    let mut out = Out::default();
    let s = f
        .open(Side::Accept, "", &ConnFacts::default(), &mut out)
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
    let opened = f.open(Side::Dial, target, &ConnFacts::default(), &mut out);
    assert!(opened.is_ok(), "a dial to {target} opens: {opened:?}");
    String::from_utf8_lossy(&out.wire).into_owned()
}

/// RED (audit: an IPv6-literal target cannot be dialled): `locate` answers the connector an
/// authority it can read, the IPv6 literal in its brackets (RFC 3986 section 3.2.2).
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

/// RED (audit: an IPv6-literal target cannot be dialled): a dial to an IPv6 literal opens, and
/// its upgrade request names the bracketed host.
#[test]
fn an_ipv6_literal_target_dials() {
    let request = opening("ws://[::1]:8080/x");
    assert!(request.starts_with("GET /x HTTP/1.1\r\n"), "{request}");
    assert!(request.contains("\r\nHost: [::1]:8080\r\n"), "{request}");
}

/// RED (audit: every dial's Host field gains the default port): the upgrade request's `Host` is
/// the target's host as `dial_authority` serialises it, with the port only where the target spelled
/// one other than the scheme's default.
#[test]
fn a_dial_sends_the_targets_host_and_only_a_spelled_port() {
    let request = opening("wss://api.example/v1/realtime?model=m");
    assert!(
        request.starts_with("GET /v1/realtime?model=m HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nHost: api.example\r\n"), "{request}");
    let request = opening("ws://svc.test:8080/x");
    assert!(request.contains("\r\nHost: svc.test:8080\r\n"), "{request}");
}

/// RED (the dialled authority is busbar 1.5.5's, from the contract's `dial_authority`): an IDN
/// target is dialled at its punycode host and its `Host` carries the punycode; a port other than
/// the scheme's default is dialled and sent; the default port is dialled and never sent. RED before
/// the change: the host went out as the URL reader decoded it (the Unicode spelling), and a spelled
/// default port was stapled onto the `Host`.
#[test]
fn a_dial_goes_to_the_targets_dial_authority() {
    let f = WsFramer::new(0);
    let at = f
        .locate("wss://b\u{fc}cher.example/x")
        .expect("an IDN target locates");
    assert_eq!(at.authority, "xn--bcher-kva.example:443");
    assert_eq!(at.server_name.as_deref(), Some("xn--bcher-kva.example"));
    let request = opening("wss://b\u{fc}cher.example/x");
    assert!(
        request.contains("\r\nHost: xn--bcher-kva.example\r\n"),
        "{request}"
    );

    let at = f.locate("ws://svc.test:8080/x").expect("a ws URL locates");
    assert_eq!(at.authority, "svc.test:8080");
    let request = opening("ws://svc.test:8080/x");
    assert!(request.contains("\r\nHost: svc.test:8080\r\n"), "{request}");

    let at = f.locate("wss://svc.test:443/x").expect("a wss URL locates");
    assert_eq!(at.authority, "svc.test:443");
    let request = opening("wss://svc.test:443/x");
    assert!(
        request.contains("\r\nHost: svc.test\r\n"),
        "the default port is never sent: {request}"
    );
}

/// RED (audit: an upper-case scheme is refused): a URL's scheme is read without case (RFC 3986
/// section 3.1), so `WS://` and `WSS://` locate and dial exactly as `ws://` and `wss://` do.
#[test]
fn a_scheme_is_read_without_case() {
    let f = WsFramer::new(0);
    let at = f
        .locate("WSS://svc.test/x")
        .expect("an upper-case wss URL locates");
    assert!(at.secure, "WSS is the secured scheme");
    assert_eq!(at.authority, "svc.test:443");
    let at = f
        .locate("Ws://svc.test/x")
        .expect("a mixed-case ws URL locates");
    assert!(!at.secure);
    assert_eq!(at.authority, "svc.test:80");
    let request = opening("WS://svc.test:8080/x");
    assert!(request.starts_with("GET /x HTTP/1.1\r\n"), "{request}");
    assert!(request.contains("\r\nHost: svc.test:8080\r\n"), "{request}");
}

/// RED (audit: a connection lost without a closing handshake is reported as a stream that ended
/// whole): a carrier that ends with no closing handshake (a dropped connection) ends the stream
/// FAILED, after every message that arrived whole before it: the connection closed abnormally
/// (RFC 6455 section 7.1.5, code 1006), not cleanly, and it is no protocol violation either.
#[test]
fn a_carrier_end_without_a_close_ends_the_stream_failed() {
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
    assert!(f.failed(s), "failed: no closing handshake ended it");

    let s = accepted(&f);
    let mut out = Out::default();
    let r = f.ingest(s, &[], true, &mut out);
    assert!(r.is_ok(), "an end with nothing before it: {r:?}");
    assert!(out.ended);
    assert!(f.failed(s), "an end with nothing before it is abnormal too");

    // Half a message, then the carrier ends: nothing of it is handed up as a message.
    let s = accepted(&f);
    let mut out = Out::default();
    let half: &[u8] = &[0x02, 0x82, 0, 0, 0, 0, b'h', b'a'];
    let r = f.ingest(s, half, true, &mut out);
    assert!(r.is_ok(), "{r:?}");
    assert!(
        out.frames.is_empty(),
        "a part of a message is never a message"
    );
    assert!(
        out.ended && f.failed(s),
        "the stream ends failed: the part is lost"
    );
}

/// An upgrade request: its request line, `Host`, `Upgrade` and `Connection`, then `fields`.
fn upgrade_with(fields: &str) -> Vec<u8> {
    format!(
        "GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         {fields}\r\n"
    )
    .into_bytes()
}

/// RED (audit: an accepted upgrade request that breaks the handshake rules is answered with
/// nothing): RFC 6455 section 4.2.1 has the server answer a request with no `Sec-WebSocket-Key`,
/// or one that is not a base64-encoded 16-byte nonce, with an HTTP error (`400 Bad Request`), and
/// section 4.4 has it answer a `Sec-WebSocket-Version` it does not speak with `426 Upgrade
/// Required` and a `Sec-WebSocket-Version` field naming 13. The answer goes out on the wire, then
/// the frames end failed; an adopted stream (the upgrade request handed over with the stream)
/// answers the same.
#[test]
fn a_broken_upgrade_request_is_answered_with_its_http_error() {
    let key = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
    let cases = [
        ("no key", "Sec-WebSocket-Version: 13\r\n".to_owned(), 400),
        (
            "a key that is no nonce",
            "Sec-WebSocket-Key: not-a-nonce\r\nSec-WebSocket-Version: 13\r\n".to_owned(),
            400,
        ),
        (
            "another version",
            format!("{key}Sec-WebSocket-Version: 8\r\n"),
            426,
        ),
        ("no version", key.to_owned(), 426),
    ];
    for (case, fields, status) in cases {
        let request = upgrade_with(&fields);
        let f = WsFramer::new(0);
        let s = f
            .open(Side::Accept, "", &ConnFacts::default(), &mut Out::default())
            .expect("an accepted framing opens");
        let mut out = Out::default();
        let r = f.ingest(s, &request, false, &mut out);
        assert!(
            r.is_ok(),
            "{case}: the request is answered, not dropped: {r:?}"
        );
        let wire = String::from_utf8_lossy(&out.wire).to_ascii_lowercase();
        assert!(
            wire.starts_with(&format!("http/1.1 {status} ")),
            "{case}: {wire}"
        );
        assert!(wire.ends_with("\r\n\r\n"), "{case}: a whole head: {wire}");
        if status == 426 {
            assert!(
                wire.contains("\r\nsec-websocket-version: 13\r\n"),
                "{case}: the version this end speaks is named: {wire}"
            );
        }
        assert!(out.frames.is_empty(), "{case}: no message");
        assert!(out.ended && f.failed(s), "{case}: the frames end failed");

        let mut out = Out::default();
        let adopted = f.adopt(Side::Accept, &ConnFacts::default(), &request, &mut out);
        assert!(
            adopted.is_ok(),
            "{case}: the adopted request is answered: {adopted:?}"
        );
        let wire = String::from_utf8_lossy(&out.wire).to_ascii_lowercase();
        assert!(
            wire.starts_with(&format!("http/1.1 {status} ")),
            "{case}: adopted: {wire}"
        );
        assert!(out.ended, "{case}: adopted: the frames end");
    }
}

/// RED (audit: one panic poisons every connection of the instance): a panic while one framing
/// works fails that framing alone; every other framing of the instance carries on.
#[test]
fn a_panic_in_one_framing_leaves_the_others_working() {
    let f = WsFramer::new(0);
    let a = accepted(&f);
    let b = f
        .open(Side::Accept, "", &ConnFacts::default(), &mut Out::default())
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

// ── the allocations ──────────────────────────────────────────────────────────────────────────────

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

/// The door's own slots, called as its trampoline calls them but outside it: the count is the
/// door's and the framer's logic, not the crossing's log capture (whose cost is the SDK's).
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
        assert_eq!(Open::call(std::ptr::null_mut(), &i, &mut o), Outcome::Ready);
        let mut host = Host {
            inst: o.instance,
            wire: vec![0; 64 * 1024],
            frame: vec![0; 64 * 1024],
            pieces: vec![z(); 64],
            framing: 0,
        };
        let mut b: BeginIn = z();
        b.side = SIDE_ACCEPT;
        b.target = AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        };
        b.sink = host.sink();
        let mut bo: DoorOut = z();
        assert_eq!(Begin::call(host.inst, &b, &mut bo), Outcome::Ready);
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
        let r = Ingest::call(self.inst, &i, &mut o);
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
        let r = Emit::call(self.inst, &i, &mut o);
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
    // busbar-contract's counting allocator counts per thread, so the other tests of this binary
    // running side by side never move it.
    let n = allocations_of(|| {
        for _ in 0..ROUNDS {
            op(state);
        }
    });
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

/// RED (audit: several copies and allocations per message on the hot path): a framing in steady
/// state allocates, per message in and per message out, no more than the bare door crossing plus
/// what the protocol library allocates for that message.
#[test]
fn a_steady_framing_adds_no_allocation_of_its_own_per_message() {
    // What the protocol library allocates, alone, to read one such message and to send one.
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
    // The door crossing itself: an ingest that carries nothing.
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
