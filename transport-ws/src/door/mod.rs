// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `ws` DOOR: this transport's framer ([`WsFramer`], tungstenite over an in-memory pipe) on the
//! transport kind's table (`busbar_contract::abi::transport`), compiled in or dropped in through
//! the one door. Every slot is the SDK's safe surface: the lifecycle is `abi::sdk::life` over
//! [`Ws`], and each framer op a [`SafeSlot`] over the same state, writing the host's sink through
//! its lent buffers.
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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroize::Zeroize;

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{self, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::transport::{form_codes, settings_reading, DEFAULT_BODY_MAX};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
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
    YIELD_MORE,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::registry::DEFAULT_REQUEST_BODY_MAX_BYTES;
use busbar_contract::transport::wire::{CloseReason, TransportError, WireStatusClass};

use crate::frame::{self, Framed, HostTime, Side};
use crate::meta;

use crate::transport::WsFramer;

/// The setting this transport reads: the message ceiling.
pub const BODY_MAX_BYTES: &str = "limits.request_body_max_bytes";

/// The transport's own key (`meta.rs`).
const KEY: &str = meta::KEY;

/// The secured form of the scheme: a `wss` target is a `ws` one whose bytes the connector secures
/// before they leave (`ws` claims `ws` and `wss`).
pub const SECURE_KEY: &str = "wss";

/// The schemes `ws` claims, by name: the Statement's `claims`, the one place they are stated.
const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY), abi_str(SECURE_KEY)];

/// `names` as host strings, in declared order.
const fn strs<const N: usize>(names: &[&'static str]) -> [AbiStr; N] {
    let mut list = [AbiStr::ABSENT; N];
    let mut i = 0;
    while i < N {
        list[i] = abi_str(names[i]);
        i += 1;
    }
    list
}

const SELECTOR_CODES: [u8; crate::claims::SELECTOR_FORMS.len()] = form_codes(meta::SELECTOR_FORMS);
const EGRESS_SELECTOR_CODES: [u8; crate::claims::EGRESS_SELECTOR_FORMS.len()] =
    form_codes(meta::EGRESS_SELECTOR_FORMS);
const FACTS: [AbiStr; meta::TRANSPORT_FACTS.len()] = strs(meta::TRANSPORT_FACTS);

/// The claim row, rendered from the transport's one declaration (`meta.rs`, `claims.rs`). `ws` and
/// `wss` are one wire, so both claims carry it. No status numbering and no status leg: frames after
/// the upgrade carry none. ws opens a unit at the upgrade, and the host reads its upgrade lines off
/// `unit0_trigger`, never off a layer list.
const ROW: Claim = {
    let mut c = Claim::EMPTY.with_facts(&FACTS);
    c.selector_forms = AbiStr::of_bytes(&SELECTOR_CODES);
    c.egress_selector_forms = AbiStr::of_bytes(&EGRESS_SELECTOR_CODES);
    c.session = meta::SESSION as u8;
    c.session_bound = meta::SESSION_BOUND as u8;
    c.unit0_trigger = UNIT0_UPGRADE;
    c
};

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`].
const CLAIMS: &[Claim] = &[ROW, ROW];

const SETTINGS: &[SettingDecl] = &[SettingDecl {
    path: abi_str(BODY_MAX_BYTES),
    kind: SETTING_COUNT,
    _reserved: 0,
    default: abi_str(DEFAULT_BODY_MAX),
}];

/// No fact: the kernel makes the binding's one outbound auth call before `begin`, and the handshake
/// writes its own lines after it. No transport names another: the carrier is the connector's
/// choice, and an upgrade reaches this framer by `adopt`, never by composition.
const TAIL: TransportTail = {
    let mut t = TransportTail::EMPTY
        .with_claim_rows(CLAIMS)
        .with_settings(SETTINGS);
    t.role = ROLE_FRAMER;
    t.framing = FRAMING_STREAM;
    t.frame_piece_size = FRAME_PIECE_SIZE;
    t
};

/// The door's Statement: the `ws` framer.
pub const STATEMENT: Statement = statement(KEY, env!("CARGO_PKG_VERSION"), 64)
    .with_kind_tail(&TAIL)
    .with_claims(CLAIM_NAMES);

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

    /// Its `PIECE_*` flags, for the part of it ending at `whole` (the rest of it fits).
    fn flags(&self, whole: bool) -> u16 {
        let mut flags = 0;
        if whole && self.end_of_frame {
            flags |= PIECE_END_OF_FRAME;
        }
        if self.text {
            flags |= PIECE_TEXT;
        }
        if self.failed && whole {
            flags |= PIECE_STREAM_FAILED;
        }
        if self.end && whole {
            flags |= PIECE_END;
        }
        if self.fields {
            flags |= PIECE_FIELDS;
            if self.continued {
                flags |= PIECE_CONTINUED;
            }
        }
        if self.status.is_some() {
            flags |= PIECE_HAS_CODE;
            if self.retry_after.is_some() {
                flags |= PIECE_HAS_RETRY_AFTER;
            }
        }
        flags
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
    /// Bytes owed to the far side. The bytes before `wire_at` are handed over already; the rest
    /// is owed.
    wire: Vec<u8>,
    wire_at: usize,
    /// `wire[..secret]` held the framing's opening (a dialled upgrade request carries its auth's
    /// credential lines): each of those bytes is wiped as it is handed over, when the buffer
    /// outgrows them, and on drop. Message bytes after it are not.
    secret: usize,
    pieces: VecDeque<Piece>,
    /// The byte buffers of pieces already handed over, kept for the next pieces: a framing in
    /// steady state queues its messages without allocating.
    spare: Vec<Vec<u8>>,
    ended: bool,
}

impl Drop for Owed {
    fn drop(&mut self) {
        if self.secret > self.wire_at {
            self.wire.zeroize();
        }
    }
}

/// The most handed-over piece buffers a framing keeps for reuse.
const SPARE_MAX: usize = 8;

/// The capacity a kept piece buffer holds at most: what one large message grew it past this is
/// given back, so a framing keeps working-size spares, not its high-water mark (as stdio's
/// `KEEP_BYTES`). A buffer within it is kept whole, so steady state allocates nothing.
const KEEP_BYTES: usize = 256 * 1024;

impl Owed {
    /// The bytes owed to the far side and not handed over yet.
    fn wire_owed(&self) -> &[u8] {
        &self.wire[self.wire_at..]
    }

    /// Owe `bytes` to the far side (`secret`: the framing's opening), never leaving a copy of a
    /// secret byte behind in a buffer it outgrows.
    fn push(&mut self, bytes: &[u8], secret: bool) {
        if self.wire.capacity() - self.wire.len() < bytes.len() {
            let owed = self.wire.len() - self.wire_at;
            let mut grown = Vec::with_capacity(2 * (owed + bytes.len()));
            grown.extend_from_slice(&self.wire[self.wire_at..]);
            if self.secret > self.wire_at {
                self.wire.zeroize();
            }
            self.secret = self.secret.saturating_sub(self.wire_at);
            self.wire = grown;
            self.wire_at = 0;
        }
        self.wire.extend_from_slice(bytes);
        if secret {
            self.secret = self.wire.len();
        }
    }

    /// Mark the next `n` owed bytes handed to the host, wiping the secret ones in place; once all
    /// are handed over the buffer empties.
    fn consume(&mut self, n: usize) {
        let end = self.wire_at + n;
        if self.secret > self.wire_at {
            self.wire[self.wire_at..end.min(self.secret)].zeroize();
        }
        self.wire_at = end;
        if self.wire_at == self.wire.len() {
            self.wire.clear();
            self.wire_at = 0;
            self.secret = 0;
        }
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
            let mut b = b;
            if b.capacity() > KEEP_BYTES {
                b.clear();
                b.shrink_to(KEEP_BYTES);
            }
            self.spare.push(b);
        }
    }
}

/// One framing's queue behind its own lock.
type OwedSlot = Arc<Mutex<Owed>>;

/// THE INSTANCE: the framer and what each framing owes. The map's lock is held only to find, add
/// or remove one framing's queue, never across an op, so framings run side by side and a panic in
/// one fails that one alone.
pub struct Ws {
    framer: WsFramer,
    owed: Mutex<HashMap<u64, OwedSlot>>,
}

impl Ws {
    /// The map of queues; a poisoned map is read as it stands (no op runs under its lock).
    fn queues(&self) -> MutexGuard<'_, HashMap<u64, OwedSlot>> {
        self.owed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The ceiling's one bad-value text: zero, a negative, a fraction or another kind alike.
const BAD_BODY_MAX: &str =
    "settings: limits.request_body_max_bytes must be a count of bytes above 0";

/// The settings blob read: a JSON object (empty bytes = `{}`) whose every key is one this transport
/// declares, its ceiling a count above 0.
fn read_settings(bytes: &[u8]) -> Result<usize, Refusal> {
    let object = settings_reading(bytes, &[BODY_MAX_BYTES])?;
    match object.get(BODY_MAX_BYTES) {
        None => Ok(DEFAULT_REQUEST_BODY_MAX_BYTES),
        // `WsFramer::new(0)` means the library's inbound default and NO outbound ceiling: refuse
        // rather than open without one.
        Some(x) => x
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|&n| n > 0)
            .ok_or_else(|| Refusal::failed(BAD_BODY_MAX)),
    }
}

/// The lifecycle: `validate`, `open` and `refresh` read the settings; a refresh's ceiling applies
/// to framings begun after it (each framing keeps the ceiling it began under). No framer op pends,
/// so a cancel finds nothing in flight and nothing moved.
impl Life for Ws {
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        read_settings(settings).map(drop)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        read_settings(settings).map(|max| Ws {
            framer: WsFramer::new(max),
            owed: Mutex::default(),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        self.framer.set_max(read_settings(settings)?);
        Ok(Refreshed::default())
    }
}

/// `refresh`: the SDK's, and with no instance FAILED by name (the SDK's answers FAULT).
pub(crate) struct Refresh;
impl SafeSlot for Refresh {
    type In = RefreshIn;
    type Out = OutHead;
    type State = Held<Ws>;
    fn call(p: Instance<'_, Held<Ws>>, i: Lent<'_, RefreshIn>, mut o: Out<'_, OutHead>) -> Outcome {
        if p.get().is_none() {
            o.error("refresh: no open instance");
            return Outcome::Failed;
        }
        life::Refresh::<Ws>::call(p, i, o)
    }
}

/// The framer's output for one op, collected before it goes to the sink.
struct Collect<'a> {
    owed: &'a mut Owed,
    now: HostTime,
    /// What is sent is the framing's opening (a dialled upgrade request may carry credentials).
    opening: bool,
}

impl frame::FramerOut for Collect<'_> {
    fn send(&mut self, bytes: &[u8]) {
        self.owed.push(bytes, self.opening);
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
}

/// A dial's opening head fields (`BeginIn::fields`), owned.
fn opening_fields(i: Lent<'_, BeginIn>) -> Vec<(String, Vec<u8>)> {
    i.fields()
        .iter()
        .map(|f| {
            (
                String::from_utf8_lossy(f.field(|x| &x.name).bytes()).into_owned(),
                f.field(|x| &x.value).bytes().to_vec(),
            )
        })
        .collect()
}

fn time(sink: &FramerSink) -> HostTime {
    HostTime {
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

/// The stubs: a framer is not a carrier, so every carrier op is refused, and nothing upgrades out
/// of a WebSocket.
mod stubs {
    use super::{
        AcceptIn, AcceptOut, ArrivalIn, ArrivalOut, ConnIn, ConnOut, DialIn, FramerOut, FramingIn,
        Held, IoOut, ListenIn, ListenOut, OutHead, ReadIn, ShutIn, WriteIn, Ws,
    };
    busbar_contract::not_served! {
        state: Held<Ws>, role: "ws framer";
        Listen(ListenIn => ListenOut) "listen";
        Accept(AcceptIn => AcceptOut) "accept";
        Dial(DialIn => ConnOut) "dial";
        Read(ReadIn => IoOut) "read";
        Write(WriteIn => IoOut) "write";
        Flush(ConnIn => OutHead) "flush";
        Shut(ShutIn => OutHead) "shut";
        Arrival(ArrivalIn => ArrivalOut) "arrival";
        Detach(FramingIn => FramerOut) "detach";
    }
}
use stubs::{Accept, Arrival, Detach, Dial, Flush, Listen, Read, Shut, Write};

/// One framer op on the SDK's safe surface, over [`Ws`].
macro_rules! op {
    ($(#[$doc:meta])* $name:ident($in:ty => $out:ty)
     |$p:pat_param, $i:pat_param, $o:ident| $body:block) => {
        $(#[$doc])*
        pub(crate) struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Held<Ws>;
            fn call($p: Instance<'_, Held<Ws>>, $i: Lent<'_, $in>, mut $o: Out<'_, $out>) -> Outcome
                $body
        }
    };
}

/// The protocol an accepting listener offers, and a secured dial too: the opening handshake is a
/// version-1.1 upgrade.
const OFFER: &[u8] = b"\x08http/1.1";

const SMALL: &str = "locate: a host buffer is too small";

op!(
    /// `locate`. A LISTENER names no far end (`LocateIn::accept`): the answer is the offer it
    /// makes, with no authority and no name.
    Locate(LocateIn => LocateOut) |p, i, o| {
        let Some(inst) = p.get().map(Held::life) else {
            o.error(LOCATE.no_instance);
            return Outcome::Failed;
        };
        if i.accept != 0 {
            let mut alpn = i.alpn_buf();
            alpn.extend(OFFER);
            if !alpn.fits() {
                o.set(|x| &x.alpn_needed, alpn.needed() as u64);
                o.error(SMALL);
                return Outcome::Failed;
            }
            o.set(|x| &x.alpn_written, alpn.written() as u64);
            return Outcome::Ready;
        }
        let Ok(target) = i.field(|x| &x.target).as_str() else {
            o.error("locate: the target is not text");
            return Outcome::Failed;
        };
        let Ok(at) = inst.framer.locate(target) else {
            o.error(if carries_userinfo(target) {
                LOCATE.userinfo
            } else {
                "locate: the target is not a ws or wss URL"
            });
            return Outcome::Failed;
        };
        let name = at.server_name.as_deref().unwrap_or_default();
        let offer: &[u8] = if at.secure { OFFER } else { &[] };
        o.set(|x| &x.secure, u32::from(at.secure));
        o.set(|x| &x.has_name, u32::from(at.server_name.is_some()));
        let (mut a, mut n, mut l) = (i.authority_buf(), i.name_buf(), i.alpn_buf());
        a.extend(at.authority.as_bytes());
        n.extend(name.as_bytes());
        l.extend(offer);
        let short = !(a.fits() && n.fits() && l.fits());
        let (aw, and) = a.settle(short);
        let (nw, nnd) = n.settle(short);
        let (lw, lnd) = l.settle(short);
        o.set(|x| &x.authority_written, aw as u64);
        o.set(|x| &x.authority_needed, and as u64);
        o.set(|x| &x.name_written, nw as u64);
        o.set(|x| &x.name_needed, nnd as u64);
        o.set(|x| &x.alpn_written, lw as u64);
        o.set(|x| &x.alpn_needed, lnd as u64);
        if short {
            o.error(SMALL);
            return Outcome::Failed;
        }
        Outcome::Ready
    }
);

/// Why an op failed, each text opening with `$prefix` (static: nothing allocates).
macro_rules! why {
    ($prefix:expr, $e:expr) => {
        match $e {
            TransportError::Refused => concat!($prefix, "the far side refused the connection"),
            TransportError::Timeout => concat!($prefix, "a deadline expired"),
            TransportError::Reset => concat!($prefix, "the connection was reset"),
            TransportError::Closed => concat!($prefix, "the connection is closed"),
            TransportError::HandshakeFailed => {
                concat!($prefix, "the WebSocket opening handshake failed")
            }
            TransportError::KeyUnavailable => concat!($prefix, "key material is unavailable"),
            TransportError::AddressRefused => {
                concat!($prefix, "the target is not a ws:// or wss:// URL")
            }
            TransportError::Backpressure => concat!(
                $prefix,
                "the far side stopped reading and the buffer is full"
            ),
            TransportError::Framing => concat!($prefix, "the bytes broke the WebSocket framing"),
            TransportError::HandoffMismatch => concat!(
                $prefix,
                "the stream handed over is not one this end can adopt"
            ),
        }
    };
}

/// Why a framing's stream ended failed, as its end piece says it: the stream's reason, not an op's.
fn refused(e: &TransportError) -> &'static str {
    why!("", e)
}

/// One framer op's fixed texts, each opening with the op's name (`<op>: `).
struct OpTexts {
    no_instance: &'static str,
    no_framing: &'static str,
    framing_failed: &'static str,
    userinfo: &'static str,
    why: fn(&TransportError) -> &'static str,
}

macro_rules! op_texts {
    ($op:literal) => {
        OpTexts {
            no_instance: concat!($op, ": no open instance"),
            no_framing: concat!($op, ": no such framing"),
            framing_failed: concat!($op, ": the framing failed"),
            userinfo: concat!(
                $op,
                ": the target carries userinfo; credentials never ride a URL"
            ),
            why: |e| why!(concat!($op, ": "), e),
        }
    };
}

const LOCATE: OpTexts = op_texts!("locate");
const BEGIN: OpTexts = op_texts!("begin");
const ADOPT: OpTexts = op_texts!("adopt");
const INGEST: OpTexts = op_texts!("ingest");
const EMIT: OpTexts = op_texts!("emit");
const REFUSE: OpTexts = op_texts!("refuse");
const TIMER: OpTexts = op_texts!("timer");
const FINISH: OpTexts = op_texts!("finish");

/// The target names a userinfo (`user:pass@`): refused outright, never read on, never echoed.
fn carries_userinfo(target: &str) -> bool {
    busbar_contract::net::parse_url(target).is_ok_and(|u| u.userinfo)
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
    p: &Instance<'_, Held<Ws>>,
    texts: &OpTexts,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    open: impl FnOnce(&WsFramer, &mut Collect<'_>) -> Result<u64, TransportError>,
) -> Outcome {
    let Some(inst) = p.get().map(Held::life) else {
        o.error(texts.no_instance);
        return Outcome::Failed;
    };
    let mut owed = Owed::default();
    let mut c = Collect {
        owed: &mut owed,
        now: time(&sink),
        opening: true,
    };
    match open(&inst.framer, &mut c) {
        Ok(token) => {
            o.set(|x| &x.framing, token);
            // An adopted connection's leftover may already have been refused.
            end_failed(&inst.framer, token, &mut owed, false);
            fill(&mut owed, sink, o);
            inst.queues().insert(token, Arc::new(Mutex::new(owed)));
            Outcome::Ready
        }
        Err(e) => {
            o.error((texts.why)(&e));
            Outcome::Failed
        }
    }
}

/// Run a framer method on framing `token`, then answer what it produced (and what was owed).
/// `fresh`: the call carries new input, so it is not a re-call that only drains.
fn framing(
    p: &Instance<'_, Held<Ws>>,
    texts: &OpTexts,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    fresh: bool,
    op: impl FnOnce(&WsFramer, &mut Collect<'_>) -> Result<(), TransportError>,
) -> Outcome {
    let Some(inst) = p.get().map(Held::life) else {
        o.error(texts.no_instance);
        return Outcome::Failed;
    };
    let Some(slot) = inst.queues().get(&token).cloned() else {
        o.error(texts.no_framing);
        return Outcome::Failed;
    };
    let Ok(mut held) = slot.lock() else {
        // An op on this framing panicked: it is failed, and it alone.
        o.error(texts.framing_failed);
        return Outcome::Failed;
    };
    let mut c = Collect {
        owed: &mut held,
        now: time(&sink),
        opening: false,
    };
    let alive = inst.framer.holds(token);
    let done = op(&inst.framer, &mut c);
    let owed = &mut *held;
    if let Err(e) = done {
        // A state gone before the op with bytes still owed, and no new input, is a RE-CALL after
        // `YIELD_MORE` (a refusal's close removed the state): it drains, whatever the op said, and
        // the connection is over once it has (`YIELD_ENDED`). An op that carried new input fails
        // instead (its data is not taken).
        if !alive && !fresh && (!owed.wire_owed().is_empty() || !owed.pieces.is_empty()) {
            owed.ended = true;
            fill(owed, sink, o);
            return Outcome::Ready;
        }
        // The framer still holds the framing, or did not hold it before the op: the op alone
        // failed, whatever is queued, and the queue stays for the next call.
        if inst.framer.holds(token) || !alive {
            o.error((texts.why)(&e));
            return Outcome::Failed;
        }
        // This op ended the state: what it produced still goes out, then the stream ends failed
        // (its end piece says why) and the connection with it.
        if !owed.ended {
            owed.pieces.push_back(Piece {
                failed: true,
                ..Piece::plain(0, refused(&e).as_bytes().to_vec(), true)
            });
            owed.ended = true;
        }
    }
    fill(owed, sink, o);
    Outcome::Ready
}

op!(
    /// `begin`.
    Begin(BeginIn => FramerOut) |p, i, o| {
        if p.get().is_none() {
            o.error(BEGIN.no_instance);
            return Outcome::Failed;
        }
        let Some(side) = side_of(i.side) else {
            o.error("begin: the side is neither accept nor dial");
            return Outcome::Failed;
        };
        let Ok(target) = i.field(|x| &x.target).as_str() else {
            o.error("begin: the target is not text");
            return Outcome::Failed;
        };
        if matches!(side, Side::Dial) && carries_userinfo(target) {
            o.error(BEGIN.userinfo);
            return Outcome::Failed;
        }
        let fields = opening_fields(i);
        opening(&p, &BEGIN, i.field(|x| &x.sink), &mut o, |f, c| {
            f.open_with(side, target, &fields, c)
        })
    }
);

op!(
    /// `adopt`.
    Adopt(AdoptIn => FramerOut) |p, i, o| {
        let Some(side) = side_of(i.side) else {
            o.error("adopt: the side is neither accept nor dial");
            return Outcome::Failed;
        };
        let leftover = i.leftover();
        opening(&p, &ADOPT, i.field(|x| &x.sink), &mut o, |f, c| {
            f.adopt(side, leftover, c)
        })
    }
);

op!(
    /// `ingest`. A `YIELD_MORE` re-call carries no new bytes: nothing reaches the machine.
    Ingest(IngestIn => FramerOut) |p, i, o| {
        let bytes = i.bytes();
        let (end, token) = (i.end != 0, i.framing);
        framing(
            &p,
            &INGEST,
            token,
            i.field(|x| &x.sink),
            &mut o,
            !bytes.is_empty() || end,
            |f, c| {
                if bytes.is_empty() && !end {
                    return Ok(());
                }
                let ended_before = c.owed.ended;
                // The dialled head's reason phrase rides the head piece this call queued.
                if let Some(reason) = f.ingest_head(token, bytes, end, c)? {
                    if let Some(head) = c.owed.pieces.iter_mut().rev().find(|p| p.fields) {
                        head.reason = Some(reason);
                    }
                }
                end_failed(f, token, c.owed, ended_before);
                Ok(())
            },
        )
    }
);

op!(
    /// `emit`.
    Emit(EmitIn => FramerOut) |p, i, o| {
        let bytes = i.bytes();
        let eof = i.end_of_frame != 0;
        let (token, text) = (i.framing, i.flags & EMIT_TEXT != 0);
        framing(
            &p,
            &EMIT,
            token,
            i.field(|x| &x.sink),
            &mut o,
            !bytes.is_empty() || eof,
            |f, c| {
                if bytes.is_empty() && !eof {
                    return Ok(());
                }
                f.emit_text(token, bytes, eof, text, c)
            },
        )
    }
);

op!(
    /// `refuse`.
    Refuse(RefuseIn => FramerOut) |p, i, o| {
        let bytes = i.bytes();
        let stream = (i.has_stream != 0).then_some(StreamId(i.stream));
        let (token, status) = (i.framing, i.status);
        framing(&p, &REFUSE, token, i.field(|x| &x.sink), &mut o, false, |f, c| {
            f.refusal_with(token, stream, bytes, status, c)
        })
    }
);

op!(
    /// `timer`.
    Timer(FramingIn => FramerOut) |p, i, o| {
        let token = i.framing;
        framing(&p, &TIMER, token, i.field(|x| &x.sink), &mut o, false, |f, c| {
            f.tick(token, c)
        })
    }
);

op!(
    /// `finish`: the framer writes its close, and the framing is gone once what it owes is out.
    Finish(FinishIn => FramerOut) |p, i, o| {
        let (token, reason) = (i.framing, reason_of(i.reason));
        let out = framing(&p, &FINISH, token, i.field(|x| &x.sink), &mut o, false, |f, c| {
            f.close(token, reason, c);
            c.owed.ended = true;
            Ok(())
        });
        let drained = o.get().yielded.flags & YIELD_MORE == 0;
        if let Some(inst) = p.get().map(Held::life).filter(|_| drained) {
            // A framing whose op panicked answered FAILED above without reaching the framer, so
            // its state is closed here too: nothing of it is kept for the life of the instance.
            if inst.queues().remove(&token).is_some() && out == Outcome::Failed {
                inst.framer.forget(token);
            }
        }
        out
    }
);

op!(
    /// `encode`: a WebSocket message is its payload.
    Encode(EncodeIn => FramerOut) |_p, i, o| {
        let body = i.body();
        let mut wire = i.field(|x| &x.sink).wire();
        if body.len() > wire.cap() {
            o.error("encode: the message is larger than the wire buffer");
            return Outcome::Failed;
        }
        wire.extend(body);
        let mut y = o.get().yielded;
        y.wire_len = body.len() as u64;
        o.set(|x| &x.yielded, y);
        Outcome::Ready
    }
);

/// Hand the host what the framing owes it, as far as the sink holds.
fn fill(owed: &mut Owed, sink: Lent<'_, FramerSink>, o: &mut Out<'_, FramerOut>) {
    let mut wire = sink.wire();
    let w = owed.wire_owed().len().min(wire.cap());
    wire.extend(&owed.wire_owed()[..w]);
    owed.consume(w);
    let (mut frame, mut pieces, mut slots) = (sink.frame(), sink.pieces(), sink.heads());
    let frame_cap = frame.cap();
    let mut frame_len = 0_usize;
    let mut n = 0_usize;
    let mut heads = 0_usize;
    while n < pieces.cap() {
        let Some(piece) = owed.pieces.front_mut() else {
            break;
        };
        // The head's slots (the dialled side fills `reason`, HTTP/1 as sent) go into the frame
        // buffer ahead of the head's first piece, and ONLY in the answer that also carries that
        // piece (the host reads the phrase beside it, and drops one that arrives alone). A piece
        // that does not fit this answer keeps its phrase for the next; one that goes out with no
        // room or no slot for the phrase goes without it, and so does a head nothing else shares
        // the answer with and that no cut fits beside its phrase (else it would wait for ever).
        let mut with_reason = piece
            .reason
            .as_ref()
            .is_some_and(|r| heads < slots.cap() && r.len() < frame_cap - frame_len);
        let mut reason_len = if with_reason {
            piece.reason.as_ref().map_or(0, Vec::len)
        } else {
            0
        };
        let mut room = frame_cap - frame_len - reason_len;
        // A failed end piece is never split (its tail would go out as payload): one that does not
        // fit waits for the next answer; one that does not fit an empty answer is cut to the room.
        if piece.failed && piece.bytes.len() - piece.at > room {
            if frame_len > 0 {
                break;
            }
            piece.bytes.truncate(piece.at + room);
        }
        let rest = &piece.bytes[piece.at..];
        let mut take = take_of(piece, rest, room, frame_len + reason_len == 0);
        if take == 0 && reason_len > 0 && frame_len == 0 && piece.fields && !rest.is_empty() {
            with_reason = false;
            reason_len = 0;
            room = frame_cap;
            take = take_of(piece, rest, room, true);
        }
        if take == 0 && !rest.is_empty() {
            break;
        }
        if let Some(reason) = piece.reason.take().filter(|_| with_reason) {
            frame.extend(&reason);
            slots.push(HeadSlots {
                stream: piece.stream,
                reason: FrameSpan {
                    offset: frame_len as u64,
                    len: reason.len() as u64,
                },
                ..HeadSlots::default()
            });
            frame_len += reason.len();
            heads += 1;
        }
        let whole = take == rest.len();
        let (code, status_class) = piece.status.unwrap_or((0, STATUS_NONE));
        frame.extend(&rest[..take]);
        pieces.push(FramePiece {
            stream: piece.stream,
            offset: frame_len as u64,
            len: take as u64,
            code,
            status_class,
            flags: piece.flags(whole),
            // No fault table: the breaker reads the status by its class, and the far end's wait
            // from `retry_after_secs`.
            fault: FAULT_NONE,
            retry_after_secs: piece.retry_after.unwrap_or(0),
            // A websocket head declares no body length: never `PIECE_HAS_DECLARED_LEN`.
            declared_len: 0,
        });
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
    let mut y = o.get().yielded;
    y.wire_len = w as u64;
    y.frame_len = frame_len as u64;
    y.pieces_len = n as u32;
    y.heads_len = heads as u32;
    y.flags = if !owed.wire_owed().is_empty() || !owed.pieces.is_empty() {
        YIELD_MORE
    } else if owed.ended {
        YIELD_ENDED
    } else {
        0
    };
    o.set(|x| &x.yielded, y);
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<life::Validate<Ws>>,
        open: Safe<life::Open<Ws>>,
        refresh: Safe<Refresh>,
        retire: Safe<life::Retire<Ws>>,
        tick: Safe<life::Tick<Ws>>,
        drive: Safe<life::Drive<Ws>>,
        cancel: Safe<life::Cancel<Ws>>,
        release: Safe<life::Release<Ws>>,
        close: Safe<life::Close<Ws>>,
    },
    kind_ops: {
        listen: Safe<Listen>,
        accept: Safe<Accept>,
        dial: Safe<Dial>,
        read: Safe<Read>,
        write: Safe<Write>,
        flush: Safe<Flush>,
        shut: Safe<Shut>,
        arrival: Safe<Arrival>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "../tests/door_fill_tests.rs"]
mod fill_tests;
