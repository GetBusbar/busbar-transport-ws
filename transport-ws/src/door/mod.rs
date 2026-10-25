// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `ws` DOOR: this transport's framer ([`WsFramer`], tungstenite over an in-memory pipe) on the
//! transport kind's table (`busbar_contract::abi::transport`), compiled in or dropped in through
//! the one door.
//!
//! Each framer op is the framer's own method, answered into the host's sink. What does not fit the
//! sink waits in the framing's queue and goes out on the `YIELD_MORE` re-call, which carries no new
//! bytes. A WebSocket connection carries one message stream (stream `0`): each message is a frame,
//! and when the connection's frames end the stream ends with its `PIECE_END` piece and the answer carries
//! `YIELD_ENDED`.
//!
//! A DIALLED framing's stream opens with its HEAD (HEAD-FIELDS): the far end's switching-protocols
//! response, the moment it completes the handshake, as ONE `PIECE_FIELDS` frame carrying its status
//! (`PIECE_HAS_CODE`, `101`, `STATUS_SUCCESS`) and the response's field block, framed even when no
//! field is left in it; the messages follow it. A block the sink cannot hold whole is cut only at a
//! line's start or inside a value, the rest marked `PIECE_CONTINUED`.
//!
//! The connector owns the socket and connection security; `locate` tells it where a target is and
//! whether it asks for security (`wss`). Both sides frame: a dialled framing opens with the upgrade
//! request, an accepted one answers it, and `adopt` takes over a stream another framer detached
//! with the upgrade request it held.

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;

use zeroize::Zeroize;

use busbar_contract::abi::auth::{FIELD_QUERY, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{AuthRef, UnitRef, FLOW_CONTINUE};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::{abi_str, statement, Slot};
use busbar_contract::abi::sdk::services::{HeadViewArgs, Services};
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FrameSpan, FramerOut, FramerSink, FramingIn, HeadSlots,
    IngestIn, IoOut, ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, SettingDecl,
    ShutIn, TransportTail, WriteIn, CANCEL_NOTHING_MOVED, CLOSE_CAPACITY_EXHAUSTED, CLOSE_DRAIN,
    CLOSE_PEER_CLOSED, CLOSE_POISONED, CLOSE_REVOKED, CLOSE_TIMEOUT, CLOSE_TRANSPORT_FAILED,
    EMIT_TEXT, FAULT_NONE, FRAME_PIECE_SIZE, FRAMING_STREAM, PIECE_CONTINUED, PIECE_END,
    PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_RETRY_AFTER, PIECE_STREAM_FAILED,
    PIECE_TEXT, ROLE_FRAMER, SETTING_COUNT, SIDE_ACCEPT, SIDE_DIAL, STATUS_CALLER_FAULT,
    STATUS_FAR_END_FAULT, STATUS_NONE, STATUS_OTHER, STATUS_SUCCESS, UNIT0_UPGRADE, YIELD_ENDED,
    YIELD_HAS_DEADLINE, YIELD_MORE,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::registry::DEFAULT_REQUEST_BODY_MAX_BYTES;
use busbar_contract::transport::wire::{
    CloseReason, TransportError, Unit0Trigger, WireStatusClass,
};
use busbar_contract::transport::{
    BytesOut, ConnFacts, Framed, Framer, FramerOut as Out, HostTime, Side,
};
use busbar_contract::TransportMeta;

use crate::transport::{AuthLine, Parking, UpgradeHead, WsFramer};

// This crate's own seal over what the binding's auth answers (`Services::auth_call`): the auth
// fields joining a dialled head are credential material, held as this crate's own secret.
busbar_contract::own_seal!(Own);

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The setting this transport reads, at its 1.5.5 path: the message ceiling.
pub const BODY_MAX_BYTES: &str = "limits.request_body_max_bytes";

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The transport's own key (`meta.rs`).
const KEY: &str = <WsFramer as TransportMeta>::KEY;

/// The secured form of the scheme: a `wss` target is a `ws` one whose bytes the connector secures
/// before they leave (THE DESIGN §5: "ws claims `ws` and `wss`").
pub const SECURE_KEY: &str = "wss";

/// The schemes `ws` claims, by name: the Statement's `claims`, the one place they are stated.
const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY), abi_str(SECURE_KEY)];

const fn bytes_str(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// `names` as host strings, in declared order.
const fn strs<const N: usize>(names: &[&'static str]) -> [AbiStr; N] {
    let mut list = [NONE; N];
    let mut i = 0;
    while i < N {
        list[i] = abi_str(names[i]);
        i += 1;
    }
    list
}

const SELECTOR_CODES: [u8; crate::claims::SELECTOR_FORMS.len()] =
    form_codes(<WsFramer as TransportMeta>::SELECTOR_FORMS);
const EGRESS_SELECTOR_CODES: [u8; crate::claims::EGRESS_SELECTOR_FORMS.len()] =
    form_codes(<WsFramer as TransportMeta>::EGRESS_SELECTOR_FORMS);
const FACT_LIST: [AbiStr; <WsFramer as TransportMeta>::TRANSPORT_FACTS.len()] =
    strs(<WsFramer as TransportMeta>::TRANSPORT_FACTS);
const FACTS: &[AbiStr] = &FACT_LIST;

/// The trigger code of the declared `UNIT0_TRIGGER`: ws opens a unit at the upgrade, and the host
/// reads its upgrade lines off this, never off a layer list (busbar ARCHITECT ruling Q128 U7).
const UNIT0: u8 = match <WsFramer as TransportMeta>::UNIT0_TRIGGER {
    Some(Unit0Trigger::Upgrade) => UNIT0_UPGRADE,
    _ => panic!("ws declares its unit opening at the upgrade"),
};

/// The claim row, RENDERED from the transport's one declaration (`meta.rs`, `claims.rs`; THE
/// DESIGN §2 "Each fact is declared once; anything derivable is derived"). `ws` and `wss` are one
/// wire, so both claims carry it.
const ROW: Claim = Claim {
    selector_forms: bytes_str(&SELECTOR_CODES),
    egress_selector_forms: bytes_str(&EGRESS_SELECTOR_CODES),
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    // The declaration states no status numbering and no status leg (`STATUS_NAMESPACE`,
    // `STATUS_CLASS`): frames after the upgrade carry none.
    status_namespace: NONE,
    session: <WsFramer as TransportMeta>::SESSION as u8,
    session_bound: <WsFramer as TransportMeta>::SESSION_BOUND as u8,
    unit0_trigger: UNIT0,
    status_at: 0,
    _reserved: 0,
};

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`].
const CLAIMS: &[Claim] = &[ROW, ROW];

const _: () = assert!(
    <WsFramer as TransportMeta>::STATUS_NAMESPACE.is_none()
        && <WsFramer as TransportMeta>::STATUS_CLASS.is_none(),
    "the row states no status numbering and no status leg"
);

/// The message ceiling's declared default, as the Statement states it.
const DEFAULT_BODY_MAX: &str = "33554432";

/// `text` read as a decimal count.
const fn count(text: &str) -> usize {
    let b = text.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        n = n * 10 + (b[i] - b'0') as usize;
        i += 1;
    }
    n
}

// The declared default is the default `read_settings` falls back to: one fact, held equal.
const _: () = assert!(count(DEFAULT_BODY_MAX) == DEFAULT_REQUEST_BODY_MAX_BYTES);

const SETTINGS: &[SettingDecl] = &[SettingDecl {
    path: abi_str(BODY_MAX_BYTES),
    kind: SETTING_COUNT,
    _reserved: 0,
    default: abi_str(DEFAULT_BODY_MAX),
}];

const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    // No fact: a dialled head is signed by the binding's auth over exactly the bytes sent, with
    // nothing added after it (ruling 23, `dial_with_auth`), as every framer's is.
    facts: 0,
    handshake_max_steps: 0,
    frame_piece_size: FRAME_PIECE_SIZE,
    _reserved: 0,
    // No transport names another: the carrier is the connector's choice, and an upgrade reaches
    // this framer by `adopt`, never by composition.
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: SETTINGS.as_ptr(),
    settings_len: SETTINGS.len(),
    fault_rows: std::ptr::null(),
    fault_rows_len: 0,
};

// THE TAIL IS THE DECLARATION'S (THE DESIGN §2: each fact declared once): every literal above is
// held equal to the framer's `TransportMeta`, so the two can never drift.
const _: () = {
    assert!(matches!(
        <WsFramer as TransportMeta>::FRAMING,
        busbar_contract::transport::wire::Framing::Stream
    ));
    assert!(TAIL.framing == FRAMING_STREAM);
    assert!(!<WsFramer as TransportMeta>::DECODES_PAYLOAD && TAIL.facts == 0);
    assert!(<WsFramer as TransportMeta>::COMPOSES_OVER.is_empty() && TAIL.composes_over_len == 0);
    assert!(<WsFramer as TransportMeta>::UPGRADES_TO.is_empty() && TAIL.upgrades_to_len == 0);
    assert!(
        <WsFramer as TransportMeta>::HANDOFF.is_none()
            && TAIL.handoff_from.len == 0
            && TAIL.handoff_to.len == 0
            && TAIL.handoff_binding_fact.len == 0
    );
};

/// The door's Statement: the `ws` framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// One frame piece waiting for the host.
struct Piece {
    stream: u64,
    bytes: Vec<u8>,
    /// The bytes before this offset are handed over already: a piece taken in parts moves nothing
    /// down, it reads on from here.
    at: usize,
    end_of_frame: bool,
    /// The bytes belong to a text message (`PIECE_TEXT`).
    text: bool,
    /// The stream's end is a FAILURE (`PIECE_STREAM_FAILED`): the far side broke the protocol, sent
    /// text that is not UTF-8 or a message over the ceiling, sent an upgrade request this end
    /// refused, or ended a refused upgrade's answer short; or an op ended the framing's state.
    /// Only ever the end piece, whose bytes say why; never split.
    failed: bool,
    /// The stream ends WHOLE here (`PIECE_END`): the empty last piece of its frames. An empty
    /// message (`bytes` empty without it) is a message, never the end.
    end: bool,
    /// The bytes are the stream's HEAD, a field block (`PIECE_FIELDS`): the dialled far end's
    /// switching response. Never with `text`, `failed` or `end`.
    fields: bool,
    /// A full sink cut this field block inside a value: `bytes` open by continuing it
    /// (`PIECE_CONTINUED`).
    continued: bool,
    /// The status the piece states (`PIECE_HAS_CODE`): its number and its class (`STATUS_*`).
    status: Option<(u32, u8)>,
    /// The wait the far end asked for (`PIECE_HAS_RETRY_AFTER`), on a refused upgrade's head.
    retry_after: Option<u64>,
    /// The dialled head's reason phrase, as the far end sent it: stated in the head's slots
    /// (`HeadSlots::reason`) beside its first piece.
    reason: Option<Vec<u8>>,
}

impl Piece {
    /// A piece that is no head and states no status.
    fn plain(stream: u64, bytes: Vec<u8>, end_of_frame: bool) -> Self {
        Self {
            stream,
            bytes,
            at: 0,
            end_of_frame,
            text: false,
            failed: false,
            end: false,
            fields: false,
            continued: false,
            status: None,
            retry_after: None,
            reason: None,
        }
    }
}

/// A status class as the piece states it (`STATUS_*`).
fn class_code(class: Option<WireStatusClass>) -> u8 {
    match class {
        None => STATUS_NONE,
        Some(WireStatusClass::Success) => STATUS_SUCCESS,
        Some(WireStatusClass::CallerFault) => STATUS_CALLER_FAULT,
        Some(WireStatusClass::FarEndFault) => STATUS_FAR_END_FAULT,
        Some(WireStatusClass::Other) => STATUS_OTHER,
    }
}

/// How much of a field block's `bytes` a sink with `room` may take: all of it when it fits, else
/// the furthest cut at a line's start or inside a value, so a continued piece always extends a
/// value (the host refuses any other continuation). `in_value`: the bytes open inside a value.
/// `0`: no cut fits.
fn field_cut(bytes: &[u8], room: usize, in_value: bool) -> usize {
    if bytes.len() <= room {
        return bytes.len();
    }
    // 0 = a line's start, 1 = a name, 2 = a value.
    let mut at = if in_value { 2 } else { 0 };
    let mut best = 0;
    for (i, &b) in bytes[..room].iter().enumerate() {
        at = match (at, b) {
            (0 | 1, b':') => 2,
            (0 | 1, _) => 1,
            (_, b'\n') => 0,
            _ => 2,
        };
        if at != 1 {
            best = i + 1;
        }
    }
    best
}

/// How much of a piece's unhanded `rest` a sink with `room` takes. A field block is cut only where
/// the host takes a continuation: at a line's start or inside a value. A name longer than the whole
/// frame buffer (`alone`: nothing else is in the answer) is cut anyway (the host refuses it by
/// name) rather than never moving.
fn take_of(piece: &Piece, rest: &[u8], room: usize, alone: bool) -> usize {
    if piece.fields {
        match field_cut(rest, room, piece.continued) {
            0 if alone => rest.len().min(room),
            cut => cut,
        }
    } else {
        rest.len().min(room)
    }
}

/// What one framing owes the host and has not been able to hand it.
#[derive(Default)]
struct Owed {
    /// Bytes owed to the far side: a dialled upgrade request carries its auth's credential lines,
    /// so every byte leaves this buffer wiped ([`push_wiped`], [`consume_wiped`], and on drop).
    /// The bytes before `wire_at` are handed over already (and wiped); the rest is owed.
    wire: Vec<u8>,
    wire_at: usize,
    pieces: VecDeque<Piece>,
    /// The byte buffers of pieces already handed over, kept for the next pieces: a framing in
    /// steady state queues its messages without allocating.
    spare: Vec<Vec<u8>>,
    ended: bool,
    deadline: Option<u64>,
}

impl Drop for Owed {
    fn drop(&mut self) {
        self.wire.zeroize();
    }
}

/// Append `bytes` to `wire` (whose bytes before `at` are handed over), never leaving a copy behind
/// in a buffer it outgrows.
fn push_wiped(wire: &mut Vec<u8>, at: &mut usize, bytes: &[u8]) {
    if wire.capacity() - wire.len() < bytes.len() {
        let owed = wire.len() - *at;
        let mut grown = Vec::with_capacity((owed + bytes.len()).max(wire.capacity() * 2));
        grown.extend_from_slice(&wire[*at..]);
        wire.zeroize();
        *wire = grown;
        *at = 0;
    }
    wire.extend_from_slice(bytes);
}

/// Mark the next `n` bytes of `wire` (from `at`) handed to the host, wiping them in place; once
/// all are handed over the buffer empties, every byte of it wiped.
fn consume_wiped(wire: &mut Vec<u8>, at: &mut usize, n: usize) {
    wire[*at..*at + n].zeroize();
    *at += n;
    if *at == wire.len() {
        wire.clear();
        *at = 0;
    }
}

/// The most handed-over piece buffers a framing keeps for reuse.
const SPARE_MAX: usize = 8;

impl Owed {
    /// The bytes owed to the far side and not handed over yet.
    fn wire_owed(&self) -> &[u8] {
        &self.wire[self.wire_at..]
    }

    /// A buffer holding `bytes`, a kept one where there is one.
    fn buffer(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut b = self.spare.pop().unwrap_or_default();
        b.clear();
        b.extend_from_slice(bytes);
        b
    }

    /// Keep a handed-over piece's buffer for the next piece.
    fn recycle(&mut self, b: Vec<u8>) {
        if self.spare.len() < SPARE_MAX {
            self.spare.push(b);
        }
    }
}

/// One framing's queue behind its own lock.
type OwedSlot = Arc<Mutex<Owed>>;

/// The framer and what each framing owes. The map's lock is held only to find, add or remove one
/// framing's queue, never across an op, so framings run side by side and a panic in one fails that
/// one alone.
pub struct Instance {
    framer: WsFramer,
    owed: Mutex<HashMap<u64, OwedSlot>>,
    /// The host services `open` was handed (`OpenIn::host`): the binding's auth a dial calls.
    /// `None`: the host offers none, and a dial whose binding has an auth is refused.
    services: Option<Services>,
}

impl Instance {
    /// The map of queues; a poisoned map is read as it stands (no op runs under its lock).
    fn queues(&self) -> MutexGuard<'_, HashMap<u64, OwedSlot>> {
        self.owed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The framer's output for one op, collected before it goes to the sink.
struct Collect<'a> {
    owed: &'a mut Owed,
    now: HostTime,
}

impl Out for Collect<'_> {
    fn send(&mut self, bytes: &[u8]) {
        push_wiped(&mut self.owed.wire, &mut self.owed.wire_at, bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        // The framer states a status on ONE frame only, the dialled stream's head: a message
        // never carries one (`crate::transport`).
        let head = piece.status_code.is_some();
        let bytes = self.owed.buffer(piece.bytes);
        self.owed.pieces.push_back(Piece {
            text: piece.text && !head,
            fields: head,
            status: piece
                .status_code
                .map(|code| (code, class_code(piece.status))),
            retry_after: piece.retry_after_secs.filter(|_| head),
            ..Piece::plain(piece.stream.0, bytes, piece.end_of_frame)
        });
    }
    fn end(&mut self) {
        if !self.owed.ended {
            // The one stream's frames are over: its empty last piece, then the connection's end.
            self.owed.pieces.push_back(Piece {
                end: true,
                ..Piece::plain(0, Vec::new(), true)
            });
        }
        self.owed.ended = true;
    }
    fn now(&self) -> HostTime {
        self.now
    }
    fn wake_at(&mut self, monotonic_nanos: Option<u64>) {
        self.owed.deadline = monotonic_nanos;
    }
}

impl BytesOut for Collect<'_> {
    fn put(&mut self, bytes: &[u8]) {
        push_wiped(&mut self.owed.wire, &mut self.owed.wire_at, bytes);
    }
}

fn read_settings(b: &Blob) -> Result<usize, &'static str> {
    let text: &[u8] = if b.ptr.is_null() || b.len == 0 {
        b"{}"
    } else {
        // SAFETY: the host's blob, valid for the call.
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
    };
    let v: serde_json::Value = serde_json::from_slice(text).map_err(|_| "settings: not JSON")?;
    match v.get(BODY_MAX_BYTES) {
        None => Ok(DEFAULT_REQUEST_BODY_MAX_BYTES),
        Some(x) => {
            let n = x
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("settings: a value is not of its declared kind")?;
            // `WsFramer::new(0)` means the library's inbound default and NO outbound ceiling: refuse
            // rather than open without one.
            if n == 0 {
                return Err("settings: limits.request_body_max_bytes must be above 0");
            }
            Ok(n)
        }
    }
}

fn instance<'a>(p: *mut c_void) -> &'a Instance {
    // SAFETY: the host passes back the pointer `open` answered, until `close`.
    unsafe { &*p.cast::<Instance>() }
}

fn text(s: &AbiStr) -> &[u8] {
    if s.ptr.is_null() {
        return &[];
    }
    // SAFETY: host-borrowed input, valid for the call.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }
}

/// A dial's opening head fields (`BeginIn::fields`), owned.
fn opening_fields(
    p: *const busbar_contract::abi::mechanism::call::Field,
    n: usize,
) -> Vec<(String, Vec<u8>)> {
    if p.is_null() || n == 0 {
        return Vec::new();
    }
    // SAFETY: host-borrowed for the call: `n` fields at `p`.
    let fields = unsafe { std::slice::from_raw_parts(p, n) };
    fields
        .iter()
        .map(|f| {
            (
                String::from_utf8_lossy(text(&f.name)).into_owned(),
                text(&f.value).to_vec(),
            )
        })
        .collect()
}

fn raw<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: host-borrowed for the call.
    unsafe { std::slice::from_raw_parts(p, n) }
}

fn time(sink: &FramerSink) -> HostTime {
    HostTime {
        monotonic_nanos: sink.now_monotonic_ns,
        unix_nanos: sink.now_unix_ns,
    }
}

fn side_of(side: u32) -> Option<Side> {
    match side {
        SIDE_ACCEPT => Some(Side::Accept),
        SIDE_DIAL => Some(Side::Dial),
        _ => None,
    }
}

fn reason_of(code: u32) -> CloseReason {
    match code {
        CLOSE_PEER_CLOSED => CloseReason::PeerClosed,
        CLOSE_DRAIN => CloseReason::Drain,
        CLOSE_POISONED => CloseReason::Poisoned,
        CLOSE_REVOKED => CloseReason::Revoked,
        CLOSE_TIMEOUT => CloseReason::Timeout,
        CLOSE_TRANSPORT_FAILED => CloseReason::TransportFailed,
        CLOSE_CAPACITY_EXHAUSTED => CloseReason::CapacityExhausted,
        _ => CloseReason::Normal,
    }
}

/// The connection-security facts an adopted framing reads: the name offered, the protocol agreed
/// and the claim.
fn facts_of(p: *const busbar_contract::abi::transport::ConnFacts) -> ConnFacts {
    if p.is_null() {
        return ConnFacts::default();
    }
    // SAFETY: host-borrowed for the call.
    let f = unsafe { &*p };
    let s = |a: &AbiStr| (!a.ptr.is_null()).then(|| String::from_utf8_lossy(text(a)).into_owned());
    ConnFacts {
        sni: s(&f.offered_name),
        alpn: s(&f.agreed_protocol),
        claim: s(&f.claim),
        ..ConnFacts::default()
    }
}

// ── the lifecycle ────────────────────────────────────────────────────────────────────────────────

/// `validate`.
pub struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, i: &ValidateIn, o: &mut OutHead) -> Outcome {
        match read_settings(&i.settings) {
            Ok(_) => Outcome::Ready,
            Err(e) => {
                o.error = abi_str(e);
                Outcome::Failed
            }
        }
    }
}

/// `open`.
pub struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, i: &OpenIn, o: &mut OpenOut) -> Outcome {
        match read_settings(&i.settings) {
            Ok(max) => {
                // SAFETY: host-borrowed for the call; NULL when the host hands no tables.
                let services = unsafe { i.host.as_ref() }.and_then(Services::of);
                o.instance = Box::into_raw(Box::new(Instance {
                    framer: WsFramer::new(max),
                    owed: Mutex::new(HashMap::new()),
                    services,
                }))
                .cast();
                Outcome::Ready
            }
            Err(e) => {
                o.head.error = abi_str(e);
                Outcome::Failed
            }
        }
    }
}

/// `close`.
pub struct Close;
impl Slot for Close {
    type In = InHead;
    type Out = OutHead;
    fn call(p: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        if !p.is_null() {
            // SAFETY: `open`'s box, closed once.
            drop(unsafe { Box::from_raw(p.cast::<Instance>()) });
        }
        Outcome::Ready
    }
}

/// `cancel`: the one framer op that pends is a dial's `begin` on its auth call; a cancel of its
/// ticket releases the dial parked there. Nothing of it went out, so nothing moved.
pub struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(p: *mut c_void, i: &CancelIn, o: &mut CancelOut) -> Outcome {
        if !p.is_null() {
            instance(p)
                .framer
                .release((i.ticket.slot, i.ticket.generation));
        }
        o.disposition = CANCEL_NOTHING_MOVED;
        Outcome::Ready
    }
}

macro_rules! answer {
    ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
        #[doc = concat!("`", stringify!($name), "`.")]
        pub struct $name;
        impl Slot for $name {
            type In = $in;
            type Out = $out;
            fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                $outcome
            }
        }
    };
}

answer!(Refresh, RefreshIn, OutHead, Outcome::Ready);
answer!(Retire, GenIn, OutHead, Outcome::Ready);
answer!(Tick, TickIn, TickOut, Outcome::Ready);
answer!(Drive, DriveIn, OutHead, Outcome::Ready);
answer!(Release, ReleaseIn, OutHead, Outcome::Ready);

// A framer is not a carrier: every carrier op is refused. Nothing upgrades out of a WebSocket.
answer!(Listen, ListenIn, ListenOut, Outcome::Refused);
answer!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
answer!(Dial, DialIn, ConnOut, Outcome::Refused);
answer!(Read, ReadIn, IoOut, Outcome::Refused);
answer!(Write, WriteIn, IoOut, Outcome::Refused);
answer!(Flush, ConnIn, OutHead, Outcome::Refused);
answer!(Shut, ShutIn, OutHead, Outcome::Refused);
answer!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);
answer!(Detach, FramingIn, FramerOut, Outcome::Refused);

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`.
pub struct Locate;
impl Slot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    fn call(p: *mut c_void, i: &LocateIn, o: &mut LocateOut) -> Outcome {
        // A LISTENER names no far end (`LocateIn::accept`): the answer is the offer it makes, the
        // version-1.1 upgrade the dial side offers too, with no authority and no name.
        if i.accept != 0 {
            let offer: &[u8] = b"\x08http/1.1";
            if offer.len() > i.alpn_cap {
                o.alpn_needed = offer.len() as u64;
                o.head.error = abi_str("locate: a host buffer is too small");
                return Outcome::Failed;
            }
            // SAFETY: the host's ALPN buffer, of the capacity checked above.
            unsafe { std::ptr::copy_nonoverlapping(offer.as_ptr(), i.alpn_buf, offer.len()) };
            o.alpn_written = offer.len() as u64;
            return Outcome::Ready;
        }
        let Ok(target) = std::str::from_utf8(text(&i.target)) else {
            o.head.error = abi_str("locate: the target is not text");
            return Outcome::Failed;
        };
        let Ok(at) = instance(p).framer.locate(target) else {
            o.head.error = abi_str("locate: the target is not a ws or wss URL");
            return Outcome::Failed;
        };
        let name = at.server_name.clone().unwrap_or_default();
        // The ALPN offer on a secured connection: the opening handshake is a version-1.1 upgrade.
        let offer: &[u8] = if at.secure { b"\x08http/1.1" } else { &[] };
        o.secure = u32::from(at.secure);
        o.has_name = u32::from(at.server_name.is_some());
        if at.authority.len() > i.authority_cap
            || name.len() > i.name_cap
            || offer.len() > i.alpn_cap
        {
            o.authority_needed = at.authority.len() as u64;
            o.name_needed = if at.server_name.is_some() {
                name.len() as u64
            } else {
                0
            };
            o.alpn_needed = offer.len() as u64;
            o.head.error = abi_str("locate: a host buffer is too small");
            return Outcome::Failed;
        }
        // SAFETY: host buffers of the stated capacity, checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(
                at.authority.as_ptr(),
                i.authority_buf,
                at.authority.len(),
            );
            std::ptr::copy_nonoverlapping(name.as_ptr(), i.name_buf, name.len());
            if !offer.is_empty() {
                std::ptr::copy_nonoverlapping(offer.as_ptr(), i.alpn_buf, offer.len());
            }
        }
        o.authority_written = at.authority.len() as u64;
        o.name_written = name.len() as u64;
        o.alpn_written = offer.len() as u64;
        Outcome::Ready
    }
}

/// Why an op failed, said without the op's name (the text is static: nothing allocates).
fn refused(e: &TransportError) -> &'static str {
    match e {
        TransportError::Refused => "the far side refused the connection",
        TransportError::Timeout => "a deadline expired",
        TransportError::Reset => "the connection was reset",
        TransportError::Closed => "the connection is closed",
        TransportError::HandshakeFailed => "the WebSocket opening handshake failed",
        TransportError::KeyUnavailable => "key material is unavailable",
        TransportError::AddressRefused => "the target is not a ws:// or wss:// URL",
        TransportError::Backpressure => "the far side stopped reading and the buffer is full",
        TransportError::Framing => "the bytes broke the WebSocket framing",
        TransportError::HandoffMismatch => "the stream handed over is not one this end can adopt",
    }
}

/// A connection the far side FAILED ends its stream failed, not cleanly: the reader is told
/// (`PIECE_STREAM_FAILED` on the end piece, whose bytes say why), and the close carries the code.
/// `ended_before`: the connection had ended before the call that queued these pieces.
fn end_failed(f: &WsFramer, token: u64, owed: &mut Owed, ended_before: bool) {
    if ended_before || !owed.ended {
        return;
    }
    let Some(why) = f.failure(token) else {
        return;
    };
    if let Some(last) = owed.pieces.back_mut() {
        if last.end {
            last.failed = true;
            // A failed stream ends failed, never whole as well, and says why.
            last.end = false;
            last.bytes.extend_from_slice(why.as_bytes());
        }
    }
}

/// Run a framer method that opens a framing, then answer what it produced.
fn opening(
    p: *mut c_void,
    sink: &FramerSink,
    o: &mut FramerOut,
    open: impl FnOnce(&WsFramer, &mut Collect<'_>) -> Result<u64, TransportError>,
) -> Outcome {
    let inst = instance(p);
    let mut owed = Owed::default();
    let mut c = Collect {
        owed: &mut owed,
        now: time(sink),
    };
    match open(&inst.framer, &mut c) {
        Ok(token) => {
            o.framing = token;
            // An adopted connection's leftover may already have been refused.
            end_failed(&inst.framer, token, &mut owed, false);
            fill(&mut owed, sink, o);
            inst.queues().insert(token, Arc::new(Mutex::new(owed)));
            Outcome::Ready
        }
        Err(e) => {
            o.head.error = abi_str(refused(&e));
            Outcome::Failed
        }
    }
}

/// Run a framer method on framing `token`, then answer what it produced (and what was owed).
/// `fresh`: the call carries new input, so it is not a re-call that only drains.
fn framing(
    p: *mut c_void,
    token: u64,
    sink: &FramerSink,
    o: &mut FramerOut,
    fresh: bool,
    op: impl FnOnce(&WsFramer, &mut Collect<'_>) -> Result<(), TransportError>,
) -> Outcome {
    let inst = instance(p);
    let Some(slot) = inst.queues().get(&token).cloned() else {
        o.head.error = abi_str("no such framing");
        return Outcome::Failed;
    };
    let Ok(mut held) = slot.lock() else {
        // An op on this framing panicked: it is failed, and it alone.
        o.head.error = abi_str("the framing failed");
        return Outcome::Failed;
    };
    let mut c = Collect {
        owed: &mut held,
        now: time(sink),
    };
    let alive = inst.framer.holds(token);
    let done = op(&inst.framer, &mut c);
    let owed = &mut *held;
    if let Err(e) = done {
        let why = refused(&e);
        // A state gone before the op with bytes still owed, and no new input, is a RE-CALL after
        // `YIELD_MORE` (a refusal's close removed the state): it drains, whatever the op said.
        // An op that carried new input fails instead (its data is not taken).
        if !alive && !fresh && (!owed.wire_owed().is_empty() || !owed.pieces.is_empty()) {
            fill(owed, sink, o);
            return Outcome::Ready;
        }
        // The framer still holds the framing, or did not hold it before the op: the op alone
        // failed, whatever is queued, and the queue stays for the next call.
        if inst.framer.holds(token) || !alive {
            o.head.error = abi_str(why);
            return Outcome::Failed;
        }
        // This op ended the state: what it produced still goes out, then the stream ends failed
        // (its end piece says why) and the connection with it.
        if !owed.ended {
            owed.pieces.push_back(Piece {
                failed: true,
                ..Piece::plain(0, why.as_bytes().to_vec(), true)
            });
            owed.ended = true;
        }
    }
    fill(owed, sink, o);
    Outcome::Ready
}

/// `begin`.
pub struct Begin;
impl Slot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &BeginIn, o: &mut FramerOut) -> Outcome {
        let Some(side) = side_of(i.side) else {
            o.head.error = abi_str("begin: the side is neither accept nor dial");
            return Outcome::Failed;
        };
        let Ok(target) = std::str::from_utf8(text(&i.target)).map(str::to_owned) else {
            o.head.error = abi_str("begin: the target is not text");
            return Outcome::Failed;
        };
        let fields = opening_fields(i.fields, i.fields_len);
        if matches!(side, Side::Dial) && i.points != 0 {
            return dial_with_auth(p, i, o, &target, &fields);
        }
        opening(p, &i.sink, o, |f, c| f.open_with(side, &target, &fields, c))
    }
}

/// The auth-call handles a dial's `begin` issues on its ticket: the peer point's, then the head's.
const SEQ_PEER: u32 = 1;
/// See [`SEQ_PEER`].
const SEQ_HEAD: u32 = 2;

/// A DIAL WHOSE BINDING HAS AN AUTH (ruling 23: nothing is added to a head after its auth runs;
/// `BeginIn::points`/`BeginIn::auth`): at [`POINT_PEER`] the auth is called once, before any head,
/// and only a continue goes on; at [`POINT_HEAD`] or [`POINT_HEAD_BODY`] (the upgrade carries no
/// body: an empty one) it is called over the upgrade request exactly as it goes on the wire, and
/// what it answers joins that request last (`WsFramer::open_signed`). A call that is not ready
/// answers PENDING and the dial is parked on the op's ticket; the resumed op re-issues the same
/// handles and reads the stored answers. A point this framer does not serve, a host that serves no
/// auth call, a stop, or an answer the request cannot carry refuses the dial: an unsigned
/// request never leaves.
fn dial_with_auth(
    p: *mut c_void,
    i: &BeginIn,
    o: &mut FramerOut,
    target: &str,
    fields: &[(String, Vec<u8>)],
) -> Outcome {
    let inst = instance(p);
    let refuse = |o: &mut FramerOut, why: &'static str| {
        o.head.error = abi_str(why);
        Outcome::Failed
    };
    if i.points & !(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY) != 0 {
        return refuse(
            o,
            "begin: the binding's auth needs a point this framer does not serve",
        );
    }
    let Some(services) = inst.services.as_ref() else {
        return refuse(
            o,
            "begin: the binding has an auth and the host serves no auth call",
        );
    };
    let ticket: Ticket = i.head.ticket;
    let handle = |seq| CompletionHandle {
        ticket,
        seq,
        _reserved: 0,
    };
    let auth: AuthRef = i.auth;
    if i.points & POINT_PEER != 0 {
        let peer = services.auth_call::<Own>(
            handle(SEQ_PEER),
            auth,
            UnitRef::NONE,
            POINT_PEER,
            0,
            0,
            &HeadViewArgs::default(),
            None,
        );
        match peer {
            Poll::Pending => return Outcome::Pending,
            Poll::Ready(Ok(called)) if called.flow == FLOW_CONTINUE => {}
            Poll::Ready(Ok(_)) => {
                return refuse(o, "begin: the binding's auth stopped the connection")
            }
            Poll::Ready(Err(_)) => return refuse(o, "begin: the host's auth call failed"),
        }
    }
    let (point, body): (u32, Option<&[u8]>) = if i.points & POINT_HEAD_BODY != 0 {
        (POINT_HEAD_BODY, Some(&[]))
    } else if i.points & POINT_HEAD != 0 {
        (POINT_HEAD, None)
    } else {
        // Only the peer point: the head goes out as the plane's.
        return opening(p, &i.sink, o, |f, c| {
            f.open_with(Side::Dial, target, fields, c)
        });
    };
    // What the head point's auth did, said by the closure that calls it.
    let mut why: Option<&'static str> = None;
    let mut signed = false;
    let mut sign = |head: &UpgradeHead<'_>| {
        let view = HeadViewArgs {
            method: "GET",
            target: head.target,
            authority: head.authority,
            query: head.query,
            fields: head.fields,
            scheme: i.scheme,
        };
        match services.auth_call::<Own>(
            handle(SEQ_HEAD),
            auth,
            UnitRef::NONE,
            point,
            0,
            0,
            &view,
            body,
        ) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(called)) if called.flow == FLOW_CONTINUE => {
                signed = true;
                Poll::Ready(Ok(called
                    .fields
                    .into_iter()
                    .map(|f| AuthLine {
                        query: f.flags & FIELD_QUERY != 0,
                        value: zeroize::Zeroizing::new(f.value.expose_own(&Own::here()).clone()),
                        name: f.name,
                    })
                    .collect()))
            }
            Poll::Ready(Ok(_)) => {
                why = Some("begin: the binding's auth stopped the dial");
                Poll::Ready(Err(TransportError::HandshakeFailed))
            }
            Poll::Ready(Err(_)) => {
                why = Some("begin: the host's auth call failed");
                Poll::Ready(Err(TransportError::HandshakeFailed))
            }
        }
    };
    let parking = Parking {
        ticket: (ticket.slot, ticket.generation),
        deadline: i.head.deadline_ns,
        now: i.sink.now_monotonic_ns,
    };
    let mut owed = Owed::default();
    let mut c = Collect {
        owed: &mut owed,
        now: time(&i.sink),
    };
    match inst
        .framer
        .open_signed(parking, target, fields, &mut sign, &mut c)
    {
        Poll::Pending => Outcome::Pending,
        Poll::Ready(Ok(token)) => {
            o.framing = token;
            fill(&mut owed, &i.sink, o);
            inst.queues().insert(token, Arc::new(Mutex::new(owed)));
            Outcome::Ready
        }
        Poll::Ready(Err(e)) => refuse(
            o,
            why.unwrap_or(if signed {
                "begin: the binding's auth answered a line the upgrade cannot carry"
            } else {
                refused(&e)
            }),
        ),
    }
}

/// `adopt`.
pub struct Adopt;
impl Slot for Adopt {
    type In = AdoptIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &AdoptIn, o: &mut FramerOut) -> Outcome {
        let Some(side) = side_of(i.side) else {
            o.head.error = abi_str("adopt: the side is neither accept nor dial");
            return Outcome::Failed;
        };
        let facts = facts_of(i.facts);
        let leftover = raw(i.leftover, i.leftover_len);
        opening(p, &i.sink, o, |f, c| f.adopt(side, &facts, leftover, c))
    }
}

/// `ingest`.
pub struct Ingest;
impl Slot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &IngestIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let end = i.end != 0;
        framing(
            p,
            i.framing,
            &i.sink,
            o,
            !bytes.is_empty() || end,
            |f, c| {
                // A `YIELD_MORE` re-call carries no new bytes: nothing reaches the machine.
                if bytes.is_empty() && !end {
                    return Ok(());
                }
                let ended_before = c.owed.ended;
                f.ingest(i.framing, bytes, end, c)?;
                // THE DIALLED HEAD'S REASON PHRASE rides the head piece this call queued.
                if let Some(reason) = f.take_reason(i.framing) {
                    if let Some(head) = c.owed.pieces.iter_mut().rev().find(|p| p.fields) {
                        head.reason = Some(reason);
                    }
                }
                end_failed(f, i.framing, c.owed, ended_before);
                Ok(())
            },
        )
    }
}

/// `emit`.
pub struct Emit;
impl Slot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &EmitIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let eof = i.end_of_frame != 0;
        framing(
            p,
            i.framing,
            &i.sink,
            o,
            !bytes.is_empty() || eof,
            |f, c| {
                if bytes.is_empty() && !eof {
                    return Ok(());
                }
                f.emit_text(i.framing, bytes, eof, i.flags & EMIT_TEXT != 0, c)
            },
        )
    }
}

/// `refuse`.
pub struct Refuse;
impl Slot for Refuse {
    type In = RefuseIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &RefuseIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let stream = (i.has_stream != 0).then_some(StreamId(i.stream));
        framing(p, i.framing, &i.sink, o, false, |f, c| {
            f.refusal_with(i.framing, stream, bytes, i.status, c)
        })
    }
}

/// `timer`.
pub struct Timer;
impl Slot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FramingIn, o: &mut FramerOut) -> Outcome {
        framing(p, i.framing, &i.sink, o, false, |f, c| f.tick(i.framing, c))
    }
}

/// `finish`: the framer writes its close, and the framing is gone once what it owes is out.
pub struct Finish;
impl Slot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FinishIn, o: &mut FramerOut) -> Outcome {
        let reason = reason_of(i.reason);
        let out = framing(p, i.framing, &i.sink, o, false, |f, c| {
            f.close(i.framing, reason, c);
            c.owed.ended = true;
            Ok(())
        });
        if o.yielded.flags & YIELD_MORE == 0 {
            let inst = instance(p);
            // A framing whose op panicked answered FAILED above without reaching the framer, so
            // its state is closed here too: the framing is gone, and nothing of it is kept for the
            // life of the instance.
            if inst.queues().remove(&i.framing).is_some() && out == Outcome::Failed {
                inst.framer.forget(i.framing);
            }
        }
        out
    }
}

/// `encode`: a WebSocket message is its payload.
pub struct Encode;
impl Slot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    fn call(_: *mut c_void, i: &EncodeIn, o: &mut FramerOut) -> Outcome {
        let body = raw(i.body, i.body_len);
        if body.len() > i.sink.wire_cap {
            o.head.error = abi_str("encode: the message is larger than the wire buffer");
            return Outcome::Failed;
        }
        // SAFETY: the host's wire buffer, of the capacity checked above.
        unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), i.sink.wire, body.len()) };
        o.yielded.wire_len = body.len() as u64;
        Outcome::Ready
    }
}

/// Hand the host what the framing owes it, as far as the sink holds.
fn fill(owed: &mut Owed, sink: &FramerSink, o: &mut FramerOut) {
    let w = owed.wire_owed().len().min(sink.wire_cap);
    // SAFETY: `w <= wire_cap`: the run lands inside the host's wire buffer, which no queue byte
    // overlaps.
    unsafe { std::ptr::copy_nonoverlapping(owed.wire_owed().as_ptr(), sink.wire, w) };
    consume_wiped(&mut owed.wire, &mut owed.wire_at, w);
    let y = &mut o.yielded;
    y.wire_len = w as u64;
    let mut frame_len = 0_usize;
    let mut n = 0_usize;
    let mut heads = 0_usize;
    while n < sink.pieces_cap {
        let Some(piece) = owed.pieces.front_mut() else {
            break;
        };
        // THE HEAD'S SLOTS (HEAD-FIELDS: the dialled side fills `reason`, HTTP/1 as sent): written
        // into the frame buffer ahead of the head's first piece, and ONLY in the answer that also
        // carries that piece (the host reads the phrase beside its head's first piece, and drops
        // one that arrives alone). A piece that does not fit this answer keeps its phrase for the
        // next; a piece that goes out with no room or no slot for the phrase takes the head
        // without it, and so does a head that nothing else shares the answer with and that no cut
        // fits beside its phrase (else it would wait for ever).
        let mut with_reason = piece.reason.as_ref().is_some_and(|r| {
            heads < sink.heads_cap && !sink.heads.is_null() && r.len() < sink.frame_cap - frame_len
        });
        let mut reason_len = if with_reason {
            piece.reason.as_ref().map_or(0, Vec::len)
        } else {
            0
        };
        let mut room = sink.frame_cap - frame_len - reason_len;
        // A failed end piece is never split (its tail would go out as payload): one that does not
        // fit waits for the next answer; one that does not fit an empty answer is cut to the room.
        if piece.failed && piece.bytes.len() - piece.at > room {
            if frame_len > 0 {
                break;
            }
            piece.bytes.truncate(piece.at + room);
        }
        // A field block is cut only where the host takes a continuation: at a line's start or
        // inside a value. A name longer than the whole frame buffer is cut anyway (the host
        // refuses it by name) rather than never moving.
        let rest = &piece.bytes[piece.at..];
        let mut take = take_of(piece, rest, room, frame_len + reason_len == 0);
        // A phrase that leaves no room for a cut of the head, in an answer with nothing else in it,
        // would stall the head for ever (the host re-calls with the same buffer): the head goes
        // without it.
        if take == 0 && reason_len > 0 && frame_len == 0 && piece.fields && !rest.is_empty() {
            with_reason = false;
            reason_len = 0;
            room = sink.frame_cap;
            take = take_of(piece, rest, room, true);
        }
        if take == 0 && !rest.is_empty() {
            break;
        }
        // The piece goes out in this answer: its phrase, when it fits, goes ahead of it.
        if let Some(reason) = piece.reason.take().filter(|_| with_reason) {
            // SAFETY: host buffers of the stated capacities: `reason` fits the frame's room
            // (`reason_len < frame_cap - frame_len`), and `heads < heads_cap`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    reason.as_ptr(),
                    sink.frame.add(frame_len),
                    reason.len(),
                );
                sink.heads.add(heads).write(HeadSlots {
                    stream: piece.stream,
                    reason: FrameSpan {
                        offset: frame_len as u64,
                        len: reason.len() as u64,
                    },
                    ..HeadSlots::default()
                });
            }
            frame_len += reason.len();
            heads += 1;
        }
        let whole = take == rest.len();
        let (code, status_class) = piece.status.unwrap_or((0, STATUS_NONE));
        // SAFETY: host buffers of the stated capacities; `take <= room`, `n < pieces_cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(rest.as_ptr(), sink.frame.add(frame_len), take);
            sink.pieces.add(n).write(FramePiece {
                stream: piece.stream,
                offset: frame_len as u64,
                len: take as u64,
                code,
                status_class,
                flags: if whole && piece.end_of_frame {
                    PIECE_END_OF_FRAME
                } else {
                    0
                } | if piece.text { PIECE_TEXT } else { 0 }
                    | if piece.failed && whole {
                        PIECE_STREAM_FAILED
                    } else {
                        0
                    }
                    | if piece.end && whole { PIECE_END } else { 0 }
                    | if piece.fields { PIECE_FIELDS } else { 0 }
                    | if piece.fields && piece.continued {
                        PIECE_CONTINUED
                    } else {
                        0
                    }
                    | if piece.status.is_some() {
                        PIECE_HAS_CODE
                    } else {
                        0
                    }
                    | if piece.status.is_some() && piece.retry_after.is_some() {
                        PIECE_HAS_RETRY_AFTER
                    } else {
                        0
                    },
                // No fault table: the breaker reads the status by its class, and the far end's
                // wait from `retry_after_secs`.
                fault: FAULT_NONE,
                retry_after_secs: piece.retry_after.unwrap_or(0),
                // A websocket head declares no body length: never `PIECE_HAS_DECLARED_LEN`.
                declared_len: 0,
            });
        }
        frame_len += take;
        n += 1;
        if whole {
            if let Some(done) = owed.pieces.pop_front() {
                owed.recycle(done.bytes);
            }
        } else {
            // The rest of a field block opens mid-line unless what was taken ended one.
            if piece.fields {
                piece.continued = !rest[..take].ends_with(b"\n");
            }
            piece.at += take;
        }
    }
    y.frame_len = frame_len as u64;
    y.pieces_len = n as u32;
    y.heads_len = heads as u32;
    let more = !owed.wire_owed().is_empty() || !owed.pieces.is_empty();
    let mut flags = 0;
    if more {
        flags |= YIELD_MORE;
    } else if owed.ended {
        flags |= YIELD_ENDED;
    }
    if let Some(at) = owed.deadline {
        flags |= YIELD_HAS_DEADLINE;
        y.next_deadline_ns = at;
    }
    y.flags = flags;
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Validate,
        open: Open,
        refresh: Refresh,
        retire: Retire,
        tick: Tick,
        drive: Drive,
        cancel: Cancel,
        release: Release,
        close: Close,
    },
    kind_ops: {
        listen: Listen,
        accept: Accept,
        dial: Dial,
        read: Read,
        write: Write,
        flush: Flush,
        shut: Shut,
        arrival: Arrival,
        locate: Locate,
        begin: Begin,
        ingest: Ingest,
        emit: Emit,
        encode: Encode,
        refuse: Refuse,
        finish: Finish,
        detach: Detach,
        adopt: Adopt,
        timer: Timer,
    },
}

#[cfg(test)]
#[path = "../tests/door_fill_tests.rs"]
mod fill_tests;
