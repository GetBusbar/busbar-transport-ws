// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER (TRANSPORT-STACK; #3, #30), as the kind's entry file (`BUSBAR-1.6.0.md` THE DESIGN,
//! §2: meta, claims, and the kind-named entry): `ws` as the contract's [`Framer`], the one
//! implementation the door drives (`crate::door`), linked into a busbar build or exported by the
//! sibling `busbar-transport-ws-plugin` cdylib.
//!
//! SANS-IO. The framer holds no socket, no waker and no clock: core hands it the bytes the carrier
//! read and sends the bytes it answers. Each framing state is the WebSocket protocol machine over an
//! in-memory [`Pipe`] — what arrived waits in the pipe until the machine consumes it, what the
//! machine writes collects in the pipe until the call hands it to core — so the handshake and every
//! frame run exactly as they do over a socket, one call at a time.
//!
//! * The session opens at the upgrade (`Unit0Trigger::Upgrade`): an ACCEPTED connection answers the
//!   upgrade request it ingests with the switching-protocols response; a DIALLED one opens with the
//!   upgrade request for its target and completes when the response arrives.
//! * A WebSocket MESSAGE is the frame unit: each binary or text message ingested is one frame, a text
//!   one stated as text ([`Framed::text`]), and each frame emitted (its last piece marked) goes out
//!   as one message, TEXT when the emit says so (`EMIT_TEXT`), else BINARY.
//! * A DIALLED connection's upgrade request carries the dial's opening head fields (the bound
//!   auth's `Authorization` among them), the WebSocket handshake's own fields excepted; a message
//!   written before the handshake completes is held and goes out, in order, the moment it does.
//! * A DIALLED connection's head yields its reason phrase as the far end sent it (HTTP/1), for the
//!   door's head slots ([`WsFramer::take_reason`]).
//! * A DIALLED connection's switching-protocols response is the far end's ANSWER (HEAD-FIELDS: a
//!   transport always hands the response head up as the stream's first fields frame): the moment
//!   it completes the handshake it is handed up as ONE frame carrying its status (`101`, a
//!   success) and its field block ([`head_block`]), ahead of any message, so a far end that has
//!   answered the upgrade and not yet sent a message has answered. It is the only frame this framer
//!   states a status on: a message never carries one.
//! * A ping is answered with its pong on the next bytes out; a peer's close is answered with the
//!   peer's own code and ends the frames. A carrier that ends with no closing handshake ends them
//!   FAILED (RFC 6455 §7.1.5: the close is abnormal, 1006), and a message it cut short is lost.
//! * An ACCEPTED upgrade request that breaks the handshake rules is answered with its HTTP error
//!   (RFC 6455 §4.2.1: `400` for a missing or malformed `Sec-WebSocket-Key`, or any other broken
//!   rule; §4.4: `426` naming version 13 for a version this end does not speak), and the frames end
//!   failed.
//! * A close this end starts carries the RFC 6455 code its reason names ([`close_code_for`]).
//! * Bytes that break the protocol FAIL the connection (RFC 6455 §7.1.7) the way the RFC orders it:
//!   every message completed before them is handed up first, the frames end, the layer above may
//!   still answer what it was handed, and the close then carries the failure's code (1002 a
//!   protocol error, 1007 a text payload that is not UTF-8, 1009 a message over the ceiling).
//!   The protocol machine judges every frame, text UTF-8 included (as each frame completes); this
//!   framer parses no WebSocket frame of its own (THE DESIGN §2 "Libraries": ONE protocol = ONE
//!   library, the `tungstenite` family).
//! * The message ceiling is the deployment's body cap, for a whole message and for a single frame;
//!   a refresh's ceiling holds for every connection built and every message written after it.
//!
//! ONE COPY OF A MESSAGE (THE DESIGN §11.2): the protocol machine reads the host's ingested bytes
//! where they lie ([`lent`]) into its own buffer, the one copy into this plugin's memory, and the
//! message it completes is handed to the door as that buffer, not copied again; on the way out the
//! machine frames a message into its own buffer and writes it straight into the host's wire buffer.
//! What the host's buffers cannot hold this call waits in plugin memory for the next.
//!
//! The upgrade INTO this framer is [`Framer::adopt`]: another framer gave up the stream with the
//! bytes it held (the upgrade request itself), and this one answers it. Nothing upgrades out of a
//! WebSocket, so [`Framer::detach`] refuses.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;

use busbar_contract::abi::transport::fields::{hop_by_hop, LINE_END, SEPARATOR};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{CloseReason, Encode, TransportError, WireStatusClass};
use busbar_contract::transport::{
    BytesOut, ConnFacts, Framed, Framer, FramerOut, HostTime, Located, Side,
};
use busbar_contract::{AbiVersion, Kind, Plugin};
use tungstenite::client::IntoClientRequest;
use tungstenite::error::ProtocolError;
use tungstenite::handshake::client::ClientHandshake;
use tungstenite::handshake::server::{
    write_response, ErrorResponse, Request as UpgradeRequest, Response as UpgradeResponse,
    ServerHandshake,
};
use tungstenite::handshake::{HandshakeError, MidHandshake};
use tungstenite::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::{Bytes, Error as WsError, Message, Utf8Bytes, WebSocket};
use zeroize::{Zeroize, Zeroizing};

/// THE HOST'S BUFFERS, LENT TO THE PROTOCOL MACHINE FOR ONE CALL: the bytes an ingest carries,
/// read where they lie, and the host's wire buffer, written where it lies, so a message is copied
/// once into this plugin's memory (the machine's own buffer) and never again on its way through.
///
/// A loan is made at the start of one framer call, under that framing's own lock, from buffers
/// that outlive the call, and is ended before the call returns ([`Pipe::settle`], [`drain`]). A
/// call that fails or panics drops or poisons its framing, which is never read again; the loan
/// dies with it, unread.
#[allow(unsafe_code)]
mod lent {
    /// The bytes the host handed one ingest, not yet read by the machine.
    pub(crate) struct Input {
        ptr: *const u8,
        len: usize,
    }

    impl Default for Input {
        fn default() -> Self {
            Self {
                ptr: std::ptr::null(),
                len: 0,
            }
        }
    }

    // SAFETY: the pointer is set only for the length of one framer call, on that call's thread and
    // under the framing's own lock, and is cleared before the call returns (see the module): a
    // pipe that moves to another thread never carries a live loan.
    unsafe impl Send for Input {}

    impl Input {
        /// Lend `bytes` for the call.
        pub(crate) fn lend(&mut self, bytes: &[u8]) {
            self.ptr = bytes.as_ptr();
            self.len = bytes.len();
        }

        /// What the machine has not read yet.
        pub(crate) fn rest(&self) -> &[u8] {
            if self.ptr.is_null() || self.len == 0 {
                return &[];
            }
            // SAFETY: lent by `lend` from a slice that outlives the call, and read only during it;
            // `ptr..ptr + len` stays inside that slice (`advance`).
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }

        /// The machine read `n` bytes.
        pub(crate) fn advance(&mut self, n: usize) {
            let n = n.min(self.len);
            if n == 0 {
                return;
            }
            // SAFETY: `n <= len`: the pointer stays inside the lent slice, or one past its end.
            self.ptr = unsafe { self.ptr.add(n) };
            self.len -= n;
        }

        /// End the loan.
        pub(crate) fn clear(&mut self) {
            *self = Self::default();
        }
    }

    /// The host's wire buffer for one call, past what that call already wrote into it.
    pub(crate) struct Window {
        ptr: *mut u8,
        cap: usize,
        len: usize,
    }

    impl Default for Window {
        fn default() -> Self {
            Self {
                ptr: std::ptr::null_mut(),
                cap: 0,
                len: 0,
            }
        }
    }

    // SAFETY: as `Input`'s: lent for one call under the framing's lock, ended before it returns.
    unsafe impl Send for Window {}

    impl Window {
        /// Lend `buf` for the call; `None` lends nothing.
        pub(crate) fn lend(&mut self, buf: Option<&mut [u8]>) {
            *self = match buf {
                Some(buf) => Self {
                    ptr: buf.as_mut_ptr(),
                    cap: buf.len(),
                    len: 0,
                },
                None => Self::default(),
            };
        }

        /// Write as much of `bytes` as the window still holds; answers how much.
        pub(crate) fn put(&mut self, bytes: &[u8]) -> usize {
            if self.ptr.is_null() {
                return 0;
            }
            let n = bytes.len().min(self.cap - self.len);
            // SAFETY: lent by `lend` from a host buffer of `cap` bytes that outlives the call, and
            // `len + n <= cap`; `bytes` is the machine's own memory, never the host's buffer.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(self.len), n) };
            self.len += n;
            n
        }

        /// End the loan: how many bytes were written into it.
        pub(crate) fn release(&mut self) -> usize {
            let n = self.len;
            *self = Self::default();
            n
        }
    }
}

/// The in-memory stream one framing state's protocol machine reads and writes: the host's bytes
/// lent for this call and what an earlier call left unread, whether the carrier's clean end
/// followed them, the host's wire buffer lent for this call and what did not fit it (or was
/// written with no buffer lent), and what arrived during the handshake.
#[derive(Default)]
pub(crate) struct Pipe {
    /// What an earlier call's bytes left that the machine had not read.
    inbound: VecDeque<u8>,
    /// This call's bytes, read in place.
    lent: lent::Input,
    ended: bool,
    /// The host's wire buffer, written in place while the session runs.
    window: lent::Window,
    /// What the machine wrote that the lent window could not take (or with none lent), in order:
    /// once anything waits here, everything after it waits behind it.
    outbound: Vec<u8>,
    /// Every byte ingested while the opening handshake runs: a dialled head's status line (its
    /// reason phrase) is read from here.
    seen: Vec<u8>,
    /// This end dialled: its frames are masked (RFC 6455 section 5.3). Read only by the test
    /// harness's seed (`test-seeded`), which unmasks a dialled end's frames.
    #[cfg_attr(not(feature = "test-seeded"), allow(dead_code))]
    client: bool,
    /// The handshake completed: what the machine writes now is frames. Read only by the test
    /// harness's seed (`test-seeded`).
    #[cfg_attr(not(feature = "test-seeded"), allow(dead_code))]
    framing: bool,
}

impl Pipe {
    /// End this call's loan of the host's bytes: what the machine did not read is kept, in order,
    /// for the next call (the host's bytes are this call's only).
    fn settle(&mut self) {
        self.inbound.extend(self.lent.rest());
        self.lent.clear();
    }

    /// Nothing ingested is left unread.
    fn drained(&self) -> bool {
        self.inbound.is_empty() && self.lent.rest().is_empty()
    }

    /// Drop everything ingested and not read: past the frames' end it is nobody's.
    fn discard(&mut self) {
        self.inbound.clear();
        self.lent.clear();
    }

    /// Hand `bytes` on: into the lent window while nothing waits ahead of them, the rest after
    /// what waits.
    fn put(&mut self, bytes: &[u8]) {
        let n = if self.outbound.is_empty() {
            self.window.put(bytes)
        } else {
            0
        };
        self.outbound.extend_from_slice(&bytes[n..]);
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.inbound.is_empty() {
            let n = buf.len().min(self.inbound.len());
            let (front, back) = self.inbound.as_slices();
            let a = n.min(front.len());
            buf[..a].copy_from_slice(&front[..a]);
            buf[a..n].copy_from_slice(&back[..n - a]);
            self.inbound.drain(..n);
            return Ok(n);
        }
        let lent = self.lent.rest();
        if !lent.is_empty() {
            let n = buf.len().min(lent.len());
            buf[..n].copy_from_slice(&lent[..n]);
            self.lent.advance(n);
            return Ok(n);
        }
        // Nothing more yet: the machine stops here and resumes on the next ingest. Only the
        // carrier's clean end is the end.
        if self.ended {
            Ok(0)
        } else {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The seeded harness unmasks a dialled end's frames before they leave (whole frames: the
        // machine hands its buffer over whole).
        #[cfg(feature = "test-seeded")]
        if self.client && self.framing {
            let mut frames = buf.to_vec();
            seeded::unmask(&mut frames);
            self.put(&frames);
            return Ok(buf.len());
        }
        self.put(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// THE ACCEPTED UPGRADE REQUEST'S KEY CHECK, run by the protocol machine before it answers `101`
/// (its handshake callback): a `Sec-WebSocket-Key` that is not a base64-encoded 16-byte nonce
/// (RFC 6455 §4.2.1 item 5) is answered `400`.
type KeyCheck = fn(&UpgradeRequest, UpgradeResponse) -> Result<UpgradeResponse, ErrorResponse>;

// The error type is the protocol library's callback shape, not this crate's choice.
#[allow(clippy::result_large_err)]
fn check_key(
    request: &UpgradeRequest,
    response: UpgradeResponse,
) -> Result<UpgradeResponse, ErrorResponse> {
    match request.headers().get("sec-websocket-key") {
        Some(key) if key_is_nonce(key.as_bytes()) => Ok(response),
        _ => Err(handshake_error(StatusCode::BAD_REQUEST)),
    }
}

/// A `Sec-WebSocket-Key` that decodes to 16 bytes (RFC 6455 §4.1 item 7): 22 characters of the
/// base64 alphabet and the `==` padding.
fn key_is_nonce(key: &[u8]) -> bool {
    key.len() == 24
        && key.ends_with(b"==")
        && key[..22]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

/// THE HTTP ERROR AN ACCEPTED UPGRADE REQUEST THAT BREAKS THE HANDSHAKE RULES IS ANSWERED WITH
/// (RFC 6455 §4.2.1, §4.4), the connection closing after it: `426 Upgrade Required` names the one
/// version this end speaks (`Sec-WebSocket-Version: 13`) and the upgrade it requires (RFC 9110
/// §15.5.22); any other status carries no field of its own. No body.
fn handshake_error(status: StatusCode) -> ErrorResponse {
    let mut answer = ErrorResponse::new(None);
    *answer.status_mut() = status;
    let fields = answer.headers_mut();
    if status == StatusCode::UPGRADE_REQUIRED {
        fields.insert("sec-websocket-version", HeaderValue::from_static("13"));
        fields.insert("upgrade", HeaderValue::from_static("websocket"));
        fields.insert("connection", HeaderValue::from_static("Upgrade, close"));
    } else {
        fields.insert("connection", HeaderValue::from_static("close"));
    }
    fields.insert("content-length", HeaderValue::from_static("0"));
    answer
}

/// The status an accepted handshake's failure is answered with; `None` when there is no one to
/// answer (the carrier ended before the request did).
fn handshake_error_status(e: &WsError) -> Option<StatusCode> {
    match e {
        WsError::Protocol(ProtocolError::HandshakeIncomplete) | WsError::Io(_) => None,
        WsError::Protocol(ProtocolError::MissingSecWebSocketVersionHeader) => {
            Some(StatusCode::UPGRADE_REQUIRED)
        }
        // The key check's own answer ([`check_key`]).
        WsError::Http(answer) => Some(answer.status()),
        _ => Some(StatusCode::BAD_REQUEST),
    }
}

/// One framing state behind its own lock; `None` while an op holds it out, or once it failed.
type Conn = Arc<Mutex<Option<Phase>>>;

/// Where one framing state is.
enum Phase {
    /// An accepted connection waiting for (the rest of) the upgrade request.
    Accepting(MidHandshake<ServerHandshake<Pipe, KeyCheck>>),
    /// An accepted connection whose upgrade request broke the handshake rules: its HTTP error
    /// went out ([`handshake_error`]), its frames ended failed, and nothing more is read.
    Refused(Pipe),
    /// A dialled connection waiting for (the rest of) the upgrade response, with the messages
    /// written before it completes (each with its text flag) and the pieces of one not yet marked
    /// complete.
    Dialling {
        mid: MidHandshake<ClientHandshake<Pipe>>,
        held: Vec<(Vec<u8>, bool)>,
        message: Vec<u8>,
    },
    /// The session: the protocol machine, the pieces of an outbound message not yet marked
    /// complete, and the failure that ended the inbound frames (its close code), if the far side
    /// broke the protocol. `lost`: the carrier ended with no closing handshake (RFC 6455 §7.1.5:
    /// an abnormal close, 1006, which no frame ever carries): the frames ended failed.
    Open {
        ws: Box<WebSocket<Pipe>>,
        message: Vec<u8>,
        failed: Option<CloseCode>,
        lost: bool,
    },
    /// A dialled connection the far end answered with something other than `101`: its answer's
    /// head was handed up as the stream's head, then its body: `left` bytes of it still to come
    /// (its declared `Content-Length`), or with none declared, every byte until the carrier ends.
    /// At `Some(0)` its frames have ended and nothing more is read. `chunked`: the body's transfer
    /// coding is `chunked` (RFC 9112 §7.1), decoded here and ended at its last chunk; `left` is then
    /// `None` until it ends.
    ///
    /// `short`: the carrier ended before the body did (short of its declared `Content-Length`, or
    /// of its last chunk): the frames end FAILED, not whole ([`WsFramer::failed`]).
    Answered {
        pipe: Pipe,
        left: Option<u64>,
        chunked: Option<Box<Dechunk>>,
        short: bool,
    },
}

impl Phase {
    /// The session over `ws`, its outbound message starting as `message`.
    fn open(ws: WebSocket<Pipe>, message: Vec<u8>) -> Self {
        Phase::Open {
            ws: Box::new(ws),
            message,
            failed: None,
            lost: false,
        }
    }
}

impl Phase {
    fn pipe(&mut self) -> &mut Pipe {
        match self {
            Phase::Accepting(mid) => mid.get_mut().get_mut(),
            Phase::Dialling { mid, .. } => mid.get_mut().get_mut(),
            Phase::Open { ws, .. } => ws.get_mut(),
            Phase::Answered { pipe, .. } | Phase::Refused(pipe) => pipe,
        }
    }
}

/// Where a dial awaiting its auth's answer is parked: the op's ticket, its deadline and the host
/// clock now (both on the host's monotonic clock; a deadline of `0` is none).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Parking {
    /// The op's ticket (`InHead::ticket`), as `(slot, generation)`.
    pub(crate) ticket: (u32, u32),
    /// The op's deadline.
    pub(crate) deadline: u64,
    /// Now.
    pub(crate) now: u64,
}

/// The most whole messages a dial holds while its handshake has not completed.
pub(crate) const MAX_HELD_MESSAGES: usize = 64;

/// The `ws` framer: its framing states, and the message ceiling every connection is built with.
pub(crate) struct WsFramer {
    /// Every framing state, each behind its own lock: the map's lock is held only to find, add or
    /// remove one, never across a framing's work, so connections run side by side and a panic in
    /// one fails that one alone.
    states: Mutex<HashMap<u64, Conn>>,
    /// Each dialled framing's head reason phrase, from the call that handed the head up until the
    /// door takes it ([`WsFramer::take_reason`]).
    reasons: Mutex<HashMap<u64, Vec<u8>>>,
    /// Dials awaiting their auth's answer, by the op's ticket, each with the op's deadline
    /// ([`WsFramer::open_signed_to`]).
    parked: Mutex<HashMap<(u32, u32), (u64, Phase)>>,
    next: AtomicU64,
    /// The message ceiling (`0` = the protocol library's own default): read when a connection is
    /// built and when a message is written, and set again by a refresh.
    max_message_bytes: AtomicUsize,
}

impl std::fmt::Debug for WsFramer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsFramer")
            .field("max_message_bytes", &self.max_message_bytes)
            .finish_non_exhaustive()
    }
}

/// The RFC 6455 close code a [`CloseReason`] puts on the wire.
///
/// Every arm is a code [`CloseCode::is_allowed`] accepts for sending: the reserved codes (1005
/// Status, 1006 Abnormal, 1015 Tls) describe a condition to a *local* API caller and never appear
/// in a frame an endpoint sends. A distinct code per reason, so a peer can tell the causes apart.
pub(crate) fn close_code_for(reason: CloseReason) -> CloseCode {
    match reason {
        // "An orderly close" is exactly what 1000 means.
        CloseReason::Normal => CloseCode::Normal,
        // THIS endpoint closing because its counterpart is gone. 1001 ("going away") is the code
        // for THIS endpoint itself going away, which a peer leaving is not: the close is an
        // orderly one, 1000. A close the peer started never reaches here: the machine answers the
        // peer's Close frame itself, echoing the peer's own code (RFC 6455 §5.5.1).
        CloseReason::PeerClosed => CloseCode::Normal,
        // Node draining is a deliberate, orderly shutdown: "the server is restarting" is 1012's
        // own definition, reconnect-elsewhere guidance included.
        CloseReason::Drain => CloseCode::Restart,
        // A panic mid-codec is this endpoint's own unexpected condition: 1011.
        CloseReason::Poisoned => CloseCode::Error,
        // Authority withdrawn is an access-control decision: 1008, policy violation.
        CloseReason::Revoked => CloseCode::Policy,
        // No code names "a deadline expired"; 1013 ("Try Again Later") is the closest meaning.
        CloseReason::Timeout => CloseCode::Again,
        // The transport layer failing is, from the wire's perspective, a protocol-level error.
        CloseReason::TransportFailed => CloseCode::Protocol,
        // A resource ceiling was exceeded: 1009 (Message Too Big) is the closest meaning left.
        CloseReason::CapacityExhausted => CloseCode::Size,
    }
}

/// The close code a read failure on a LIVE connection fails it with (RFC 6455 §7.4.1), or `None`
/// when the connection itself is gone and there is no one to tell.
fn failure_code(e: &WsError) -> Option<CloseCode> {
    match e {
        WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => None,
        WsError::Protocol(_) => Some(CloseCode::Protocol),
        WsError::Utf8(_) => Some(CloseCode::Invalid),
        WsError::Capacity(_) => Some(CloseCode::Size),
        _ => None,
    }
}

/// What a failed read of the message stream means to the layer above: bytes that were not
/// WebSocket are a framing failure, a finished closing handshake is the end, anything else is the
/// connection going away underneath.
fn read_error(e: &WsError) -> TransportError {
    match e {
        WsError::Protocol(_) | WsError::Capacity(_) | WsError::Utf8(_) => TransportError::Framing,
        WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::Closed,
        _ => TransportError::Reset,
    }
}

/// The upgrade request's own fields, which the handshake writes itself: an opening field of one of
/// these names is not copied onto it.
///
/// THE ORDER OF THE DIALLED HEAD, as it is written (tungstenite 0.29 `generate_request`): the
/// request line, then the protocol machine's handshake lines (`Host` from the dialled URL,
/// `Connection`, `Upgrade`, `Sec-WebSocket-Version`, `Sec-WebSocket-Key`), then the plane's
/// opening fields in the request map's own iteration order (`http::HeaderMap`, which does not keep
/// the order the fields were added in), a repeated name's lines together and in their own order;
/// then, LAST, what the binding's auth answered ([`signed_request`], ruling 23: the auth is called
/// over exactly the bytes above, the fresh key among them, and nothing is added after it). 1.5.5
/// dialled no WebSocket at all, so this head has no 1.5.5 order to keep, and the handshake lines
/// lead because the machine writes them (`framer_tests::the_dialled_heads_order_is_pinned` pins
/// it; `framer_tests::an_auth_that_signs_the_whole_head_sees_every_byte_on_the_wire` pins the
/// auth's place). An opening field of a handshake name is the machine's to write, so it is not
/// copied, and an auth that answers one refuses the dial.
const HANDSHAKE_FIELDS: &[&str] = &[
    "host",
    "connection",
    "upgrade",
    "content-length",
    "transfer-encoding",
];

/// Whether an opening field may ride the upgrade request.
fn rides_upgrade(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !HANDSHAKE_FIELDS.contains(&lower.as_str()) && !lower.starts_with("sec-websocket-")
}

/// THE ANSWER'S HEAD as a field block (`busbar_contract::abi::transport::fields`): the switching
/// response's fields as the parsed head holds them (`HeaderMap`: names in the order they first
/// appear, a repeated name's values together under its first appearance, in their own order), names
/// lower-case, each value on its own line. Hop-by-hop fields (and every field a `connection` field names) never enter it, nor do
/// the handshake's own fields ([`rides_upgrade`]'s refusals: `content-length` among them, and every
/// `sec-websocket-*` field, which answer this hop's handshake and nothing above it). No field left
/// is the EMPTY block, still handed up: an empty head is a head.
fn head_block(headers: &HeaderMap) -> Vec<u8> {
    let nominated: Vec<&[u8]> = headers
        .get_all("connection")
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let mut block = Vec::new();
    for (name, value) in headers {
        let name = name.as_str();
        if !rides_upgrade(name) || hop_by_hop(name, nominated.iter().copied()) {
            continue;
        }
        block.extend_from_slice(name.as_bytes());
        block.extend_from_slice(SEPARATOR);
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(LINE_END);
    }
    block
}

/// One message as the protocol machine sends it.
fn message_of(bytes: Bytes, text: bool) -> Result<Message, WsError> {
    if text {
        Utf8Bytes::try_from(bytes)
            .map(Message::Text)
            .map_err(|_| WsError::Utf8(String::new()))
    } else {
        Ok(Message::Binary(bytes))
    }
}

/// THE STATUS CLASS of a far end's answer to the upgrade, by its HTTP status.
fn status_class(code: u16) -> WireStatusClass {
    match code {
        200..=299 => WireStatusClass::Success,
        400..=499 => WireStatusClass::CallerFault,
        500..=599 => WireStatusClass::FarEndFault,
        _ => WireStatusClass::Other,
    }
}

/// The `Retry-After` an answer states, in whole seconds from `now_secs` (Unix seconds), in either
/// of RFC 9110's forms, as the http framer reads it: `delay-seconds`, or an IMF-fixdate converted to
/// the seconds left until it (`0` once past). A value read as neither is absent.
pub(crate) fn retry_after(headers: &HeaderMap, now_secs: u64) -> Option<u64> {
    let raw = headers.get("retry-after")?.to_str().ok()?.trim();
    if let Ok(n) = raw.parse::<u64>() {
        return Some(n);
    }
    imf_fixdate_secs(raw).map(|at| at.saturating_sub(now_secs))
}

/// An HTTP-date (RFC 9110 §5.6.7: the IMF-fixdate, and the two obsolete forms a recipient must
/// accept) as Unix seconds, read by the protocol library (`httpdate`).
fn imf_fixdate_secs(s: &str) -> Option<u64> {
    httpdate::parse_http_date(s)
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Whether an answer's body is `chunked` (RFC 9112 §6.1, §6.3: the LAST transfer coding the answer
/// names is `chunked`, which then frames the body whatever `Content-Length` says).
fn is_chunked(headers: &HeaderMap) -> bool {
    headers
        .get_all("transfer-encoding")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .rfind(|c| !c.is_empty())
        .is_some_and(|c| c.eq_ignore_ascii_case("chunked"))
}

/// The longest chunk-size or trailer line a refused upgrade's chunked body may carry; a longer one is
/// malformed, and the frames end there.
const CHUNK_LINE_MAX: usize = 4096;

/// Where a chunked body's decoder stands (RFC 9112 §7.1).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Chunked {
    /// Reading a chunk-size line (its extensions ignored).
    #[default]
    Size,
    /// This many data bytes of the current chunk are still to come.
    Data(u64),
    /// The line end after a chunk's data.
    DataEnd,
    /// The trailer section, after the last chunk: it ends at an empty line.
    Trailer,
    /// The body ended at its last chunk and trailers: nothing more is read.
    Done,
    /// The coding was malformed: the body is not whole, and nothing more is read.
    Malformed,
}

/// A refused upgrade's CHUNKED BODY, decoded as it arrives: the data handed up without its chunk
/// markers, ended at the last chunk and its trailers (which are dropped: the head was handed up
/// already).
#[derive(Debug, Default)]
pub(crate) struct Dechunk {
    state: Chunked,
    line: Vec<u8>,
}

impl Dechunk {
    /// Decode what `inbound` holds into `body`; `Some(whole)` once nothing more is read: `true` at
    /// its last chunk and trailers, `false` at a malformed coding.
    fn feed(&mut self, inbound: &mut VecDeque<u8>, body: &mut Vec<u8>) -> Option<bool> {
        loop {
            match self.state {
                Chunked::Done => return Some(true),
                Chunked::Malformed => return Some(false),
                Chunked::Data(n) => {
                    if inbound.is_empty() {
                        return None;
                    }
                    let take = usize::try_from(n).map_or(inbound.len(), |n| n.min(inbound.len()));
                    body.extend(inbound.drain(..take));
                    let rest = n - take as u64;
                    self.state = if rest == 0 {
                        Chunked::DataEnd
                    } else {
                        Chunked::Data(rest)
                    };
                    continue;
                }
                Chunked::Size | Chunked::DataEnd | Chunked::Trailer => {}
            }
            let b = inbound.pop_front()?;
            if b != b'\n' {
                if self.line.len() >= CHUNK_LINE_MAX {
                    self.state = Chunked::Malformed;
                    return Some(false);
                }
                self.line.push(b);
                continue;
            }
            let mut line = std::mem::take(&mut self.line);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.state = match self.state {
                Chunked::Size => {
                    let size = line.split(|c| *c == b';').next().unwrap_or_default();
                    match std::str::from_utf8(size)
                        .ok()
                        .and_then(|t| u64::from_str_radix(t.trim(), 16).ok())
                    {
                        Some(0) => Chunked::Trailer,
                        Some(n) => Chunked::Data(n),
                        None => Chunked::Malformed,
                    }
                }
                Chunked::DataEnd if line.is_empty() => Chunked::Size,
                Chunked::Trailer if line.is_empty() => Chunked::Done,
                Chunked::Trailer => Chunked::Trailer,
                _ => Chunked::Malformed,
            };
        }
    }
}

/// The `Content-Length` an answer declares.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
}

/// A dialled head's REASON PHRASE (HEAD-FIELDS: the dialled side fills `reason`, HTTP/1 as sent):
/// the status line's text after its code, once the line is whole (`HTTP/1.1 401 Unauthorized` →
/// `Unauthorized`); `None` before the line ends, or for a line with no phrase.
///
/// A line ends at its LF, a CR before it dropped: a bare LF ends a line as the protocol library's
/// parser reads it (RFC 9112 §2.2).
pub(crate) fn reason_phrase(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.iter().position(|b| *b == b'\n')?;
    let line = &seen[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.splitn(3, |b| *b == b' ');
    let (_version, _code) = (parts.next()?, parts.next()?);
    parts.next().filter(|r| !r.is_empty()).map(<[u8]>::to_vec)
}

/// Where a response head ends in `seen`: just past the empty line that closes it, its lines ended
/// by CRLF or by a bare LF, as the protocol library's parser accepts them (RFC 9112 §2.2); every
/// byte from there is the body. `seen.len()` while no empty line has come.
fn head_end(seen: &[u8]) -> usize {
    let crlf = seen.windows(3).position(|w| w == b"\n\r\n").map(|p| p + 3);
    let lf = seen.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => a.min(b),
        (a, b) => a.or(b).unwrap_or(seen.len()),
    }
}

/// A refused upgrade's BODY: frame what the pipe holds, decoded by its transfer coding when it is
/// `chunked` (to its last chunk), otherwise up to the `left` bytes its declared `Content-Length`
/// still owes (or, with none declared, until the carrier ends), and end the frames once they are
/// all handed up or the carrier ended. `first`: the call that handed the head up (a declared length
/// of `0` ends the frames then). Past the end, what arrives is nobody's.
fn answered_body(
    mut pipe: Pipe,
    left: Option<u64>,
    chunked: Option<Box<Dechunk>>,
    first: bool,
    out: &mut dyn Output,
) -> (Phase, bool) {
    if left == Some(0) {
        pipe.inbound.clear();
        let phase = Phase::Answered {
            pipe,
            left,
            chunked: None,
            short: false,
        };
        return (phase, first);
    }
    if let Some(mut decoder) = chunked {
        let mut bytes = Vec::new();
        let fed = decoder.feed(&mut pipe.inbound, &mut bytes);
        let ended = fed.is_some() || (pipe.ended && pipe.inbound.is_empty());
        // The carrier ended before the last chunk, or the coding was malformed: not a whole body.
        let short = ended && fed != Some(true);
        if !bytes.is_empty() || ended {
            out.frame(Framed::plain(StreamId(0), &bytes, ended));
        }
        if ended {
            pipe.inbound.clear();
        }
        let phase = Phase::Answered {
            pipe,
            left: ended.then_some(0),
            chunked: (!ended).then_some(decoder),
            short,
        };
        return (phase, ended);
    }
    let avail = pipe.inbound.len();
    let take = left.map_or(avail, |l| {
        usize::try_from(l).map_or(avail, |l| l.min(avail))
    });
    let bytes: Vec<u8> = pipe.inbound.drain(..take).collect();
    let left = left.map(|l| l - take as u64);
    let ended = left == Some(0) || (pipe.ended && pipe.inbound.is_empty());
    if !bytes.is_empty() || ended {
        out.frame(Framed::plain(StreamId(0), &bytes, ended));
    }
    if ended {
        pipe.inbound.clear();
    }
    // The carrier ended with declared bytes still owed: a short body.
    let short = ended && left.is_some_and(|l| l > 0);
    let left = if ended { Some(0) } else { left };
    let phase = Phase::Answered {
        pipe,
        left,
        chunked: None,
        short,
    };
    (phase, ended)
}

/// THE CLOSE CODE A REFUSAL'S NEUTRAL STATUS MAPS TO (the plane seam: a neutral status the transport
/// maps to its wire; RFC 6455 §7.4.1): the caller's credential refused or a policy, `1008`; too
/// big, `1009`; throttled or unavailable, `1013` (try again later); another server failure, `1011`;
/// none stated (`0`) or any other, the orderly `1000`.
pub(crate) fn close_code_of_status(status: u32) -> CloseCode {
    match status {
        401 | 403 => CloseCode::Policy,
        413 => CloseCode::Size,
        429 | 503 => CloseCode::Again,
        500..=599 => CloseCode::Error,
        _ => CloseCode::Normal,
    }
}

/// WHAT A FRAMER OP HANDS ITS OUTPUT TO, past the contract's [`FramerOut`]: the door's answer
/// lends the host's own wire buffer for the session's frames to be written into in place, takes
/// the bytes waiting in a pipe as they stand, and takes a message's payload as the protocol machine
/// completed it, so nothing of a message is copied again inside this plugin. Off the door
/// ([`Plain`]) each falls back to the contract's own call.
pub(crate) trait Output: FramerOut {
    /// The host's wire buffer past what this answer already wrote into it, for the machine to
    /// write into in place; `None`: none (off the door, or bytes owed from an earlier call go
    /// first).
    fn window(&mut self) -> Option<&mut [u8]> {
        None
    }

    /// `n` bytes were written into the buffer [`Output::window`] lent.
    fn wrote(&mut self, _n: usize) {}

    /// Bytes for the far side, in order, taken as they stand: `bytes` is left empty.
    fn send_owned(&mut self, bytes: &mut Vec<u8>) {
        self.send(bytes.as_slice());
        bytes.clear();
    }

    /// One whole message for the layer above (`text`: a text message), its payload as the
    /// protocol machine completed it.
    fn message(&mut self, payload: Bytes, text: bool) {
        self.frame(Framed::plain(StreamId(0), &payload, true).text(text));
    }
}

/// A contract [`FramerOut`] as an [`Output`]: no buffer is lent, and everything goes through the
/// contract's own calls.
struct Plain<'a>(&'a mut dyn FramerOut);

impl FramerOut for Plain<'_> {
    fn send(&mut self, bytes: &[u8]) {
        self.0.send(bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        self.0.frame(piece);
    }
    fn end(&mut self) {
        self.0.end();
    }
    fn now(&self) -> HostTime {
        self.0.now()
    }
    fn wake_at(&mut self, monotonic_nanos: Option<u64>) {
        self.0.wake_at(monotonic_nanos);
    }
}

impl Output for Plain<'_> {}

/// Hand whatever the machine wrote to core: end the loan of the host's wire buffer (what went
/// into it is told), then hand on what waits in the pipe.
fn drain(phase: &mut Phase, out: &mut dyn Output) {
    let pipe = phase.pipe();
    let wrote = pipe.window.release();
    if wrote > 0 {
        out.wrote(wrote);
    }
    if !pipe.outbound.is_empty() {
        out.send_owned(&mut pipe.outbound);
    }
}

/// Lend the host's wire buffer (when `out` lends one) to a session's machine for this call.
fn lend_window(ws: &mut WebSocket<Pipe>, out: &mut dyn Output) {
    ws.get_mut().window.lend(out.window());
}

/// THE TEST HARNESS'S SEED (`test-seeded`, a dev-dependency feature the published conformance
/// suite builds with; never in a shipped build, where the handshake key and every frame's mask stay
/// random as RFC 6455 section 5.3 requires): a dial's handshake key is fixed, and a dialled end's
/// frames carry the all-zero mask, so the bytes a scripted dial writes are the same every run.
#[cfg(feature = "test-seeded")]
mod seeded {
    /// The handshake key a seeded dial sends (RFC 6455 section 1.3's own example).
    pub(super) const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    /// Rewrite each whole client frame in `wire` to the all-zero mask, its payload unmasked.
    pub(super) fn unmask(wire: &mut [u8]) {
        let mut at = 0;
        while at + 2 <= wire.len() {
            let masked = wire[at + 1] & 0x80 != 0;
            let (len, head) = match wire[at + 1] & 0x7f {
                126 if at + 4 <= wire.len() => (
                    usize::from(u16::from_be_bytes([wire[at + 2], wire[at + 3]])),
                    4,
                ),
                127 if at + 10 <= wire.len() => {
                    let mut l = [0_u8; 8];
                    l.copy_from_slice(&wire[at + 2..at + 10]);
                    (
                        usize::try_from(u64::from_be_bytes(l)).unwrap_or(usize::MAX),
                        10,
                    )
                }
                l @ 0..=125 => (usize::from(l), 2),
                _ => return,
            };
            let key_at = at + head;
            let body = key_at + if masked { 4 } else { 0 };
            if body.saturating_add(len) > wire.len() {
                return;
            }
            if masked {
                let mut key = [0_u8; 4];
                key.copy_from_slice(&wire[key_at..body]);
                for (k, b) in wire[body..body + len].iter_mut().enumerate() {
                    *b ^= key[k % 4];
                }
                wire[key_at..body].fill(0);
            }
            at = body + len;
        }
    }
}

impl WsFramer {
    /// Close `state` with `code` (a connection the far side failed closes with the failure's
    /// code instead), handing what the machine wrote to core, and forget it.
    fn close_with(&self, state: u64, code: CloseCode, out: &mut dyn Output) {
        let Some(conn) = self.map().remove(&state) else {
            return;
        };
        let Ok(mut held) = Self::enter(&conn) else {
            return;
        };
        let Some(mut phase) = held.take() else {
            return;
        };
        if let Phase::Open { ws, failed, .. } = &mut phase {
            lend_window(ws, out);
            // The close frame is a courtesy on a connection already finalised: what the machine
            // could write goes out, and a close it cannot write is not an error anyone can act on.
            // A connection the far side failed closes with the failure's code, whatever the reason
            // this end closes for; one the far side closed already carried the far side's code
            // back (the machine's answer), and the machine writes nothing more here.
            let _ = ws.close(Some(CloseFrame {
                code: failed.unwrap_or(code),
                reason: "".into(),
            }));
            let _ = ws.flush();
        }
        drain(&mut phase, out);
    }

    /// The refusal `bytes`, closing the connection after it; `status` is the refusal's neutral
    /// status (`RefuseIn::status`, `0` = none stated).
    ///
    /// # Errors
    ///
    /// As [`Framer::refusal`].
    pub(crate) fn refusal_with(
        &self,
        state: u64,
        stream: Option<StreamId>,
        bytes: &[u8],
        status: u32,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.refusal_to(state, stream, bytes, status, &mut Plain(out))
    }

    /// [`Self::refusal_with`] into an [`Output`].
    ///
    /// # Errors
    ///
    /// As [`Framer::refusal`].
    pub(crate) fn refusal_to(
        &self,
        state: u64,
        _stream: Option<StreamId>,
        bytes: &[u8],
        status: u32,
        out: &mut dyn Output,
    ) -> Result<(), TransportError> {
        let sent = self.emit_to(state, bytes, true, false, out);
        self.close_with(state, close_code_of_status(status), out);
        sent
    }

    /// [`Framer::close`] into an [`Output`].
    pub(crate) fn close_to(&self, state: u64, reason: CloseReason, out: &mut dyn Output) {
        self.close_with(state, close_code_for(reason), out);
    }

    /// A framer whose messages (and frames) are capped at `max_message_bytes`; `0` = the protocol
    /// library's own default stands.
    #[must_use]
    pub(crate) fn new(max_message_bytes: usize) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            reasons: Mutex::new(HashMap::new()),
            parked: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            max_message_bytes: AtomicUsize::new(max_message_bytes),
        }
    }

    /// THE REFRESHED CEILING: every connection built after this, and every message written after
    /// it, is held to `max_message_bytes` (`0` = the protocol library's own default).
    pub(crate) fn set_max_message_bytes(&self, max_message_bytes: usize) {
        self.max_message_bytes
            .store(max_message_bytes, Ordering::Relaxed);
    }

    /// The message ceiling now.
    fn max_message_bytes(&self) -> usize {
        self.max_message_bytes.load(Ordering::Relaxed)
    }

    fn config(&self) -> Option<WebSocketConfig> {
        let max = self.max_message_bytes();
        (max > 0).then(|| {
            WebSocketConfig::default()
                .max_message_size(Some(max))
                .max_frame_size(Some(max))
        })
    }

    /// [`Framer::open`], a dialled connection's upgrade request carrying `fields` (the dial's
    /// opening head fields, `BeginIn::fields`).
    ///
    /// # Errors
    ///
    /// The target is not a WebSocket URL, or a field is not a valid header.
    pub(crate) fn open_with(
        &self,
        side: Side,
        target: &str,
        fields: &[(String, Vec<u8>)],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        self.open_to(side, target, fields, &mut Plain(out))
    }

    /// [`Self::open_with`] into an [`Output`].
    ///
    /// # Errors
    ///
    /// As [`Self::open_with`].
    pub(crate) fn open_to(
        &self,
        side: Side,
        target: &str,
        fields: &[(String, Vec<u8>)],
        out: &mut dyn Output,
    ) -> Result<u64, TransportError> {
        let phase = self.start(side, target, fields, out)?;
        Ok(self.hold(phase))
    }

    /// [`Self::open_signed_to`] into a contract [`FramerOut`] (the tests' face).
    #[cfg(test)]
    pub(crate) fn open_signed(
        &self,
        parking: Parking,
        target: &str,
        fields: &[(String, Vec<u8>)],
        sign: Signer<'_>,
        out: &mut dyn FramerOut,
    ) -> Poll<Result<u64, TransportError>> {
        self.open_signed_to(parking, target, fields, sign, &mut Plain(out))
    }

    /// [`Self::open_with`] for a dial whose binding has an auth at the head (`BeginIn::points`):
    /// the upgrade request is built whole, `sign` is called over it exactly as it goes on the wire,
    /// and its answer joins it last ([`signed_request`]). A sign that is not ready PARKS the built
    /// dial under the op's `ticket` (its key and its head kept, so the answer that comes back
    /// signs these bytes) until the op resumes on the same ticket, or `deadline` (the op's, on the
    /// host clock, `0` = none) passes; nothing is written meanwhile.
    ///
    /// # Errors
    ///
    /// As [`Self::open_with`]; the auth refused, or answered a line the request cannot carry.
    pub(crate) fn open_signed_to(
        &self,
        parking: Parking,
        target: &str,
        fields: &[(String, Vec<u8>)],
        sign: Signer<'_>,
        out: &mut dyn Output,
    ) -> Poll<Result<u64, TransportError>> {
        let mut phase = match self.unpark(parking) {
            Some(phase) => phase,
            None => match self.dial(target, fields) {
                Ok(phase) => phase,
                Err(e) => return Poll::Ready(Err(e)),
            },
        };
        let signed = signed_request(&phase.pipe().outbound, sign);
        let pipe = phase.pipe();
        match signed {
            Poll::Pending => {
                self.park(parking, phase);
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                pipe.outbound.zeroize();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(signed)) => {
                pipe.outbound.zeroize();
                pipe.outbound = signed;
            }
        }
        drain(&mut phase, out);
        // The upgrade request carries credential lines: what held it is wiped once sent.
        phase.pipe().outbound.zeroize();
        Poll::Ready(Ok(self.hold(phase)))
    }

    /// Park a dial awaiting its auth's answer, and drop every parked dial whose op's deadline has
    /// passed (its op will never resume).
    fn park(&self, parking: Parking, phase: Phase) {
        let mut parked = self.parked.lock().unwrap_or_else(PoisonError::into_inner);
        parked.retain(|_, (deadline, _)| *deadline == 0 || *deadline > parking.now);
        parked.insert(parking.ticket, (parking.deadline, phase));
    }

    /// The dial parked under `parking`'s ticket, taken.
    fn unpark(&self, parking: Parking) -> Option<Phase> {
        self.parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&parking.ticket)
            .map(|(_, phase)| phase)
    }

    /// The host cancelled `ticket`'s op: drop the dial parked under it, if there is one. Nothing of
    /// it went out, so nothing moved.
    pub(crate) fn release(&self, ticket: (u32, u32)) {
        self.parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket);
    }

    /// How many dials are parked (a test reads that a resumed or expired dial is gone).
    #[cfg(test)]
    pub(crate) fn parked(&self) -> usize {
        self.parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// [`Framer::emit`]: with `text` (the emit's `EMIT_TEXT`) the message goes out as a text
    /// message, under the TEXT opcode, which promises UTF-8 (RFC 6455 §8.1): bytes that are not fail
    /// the write rather than go out under a promise they break. On a dialled connection whose
    /// handshake has not completed, the message is held and goes out the moment it does.
    ///
    /// # Errors
    ///
    /// The state is gone, a text message is not UTF-8, or the machine refused it.
    pub(crate) fn emit_text(
        &self,
        state: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.emit_to(state, bytes, end_of_frame, text, &mut Plain(out))
    }

    /// [`Self::emit_text`] into an [`Output`]: the session's frames are written straight into
    /// the host's wire buffer when the door lends it.
    ///
    /// # Errors
    ///
    /// As [`Self::emit_text`].
    pub(crate) fn emit_to(
        &self,
        state: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        out: &mut dyn Output,
    ) -> Result<(), TransportError> {
        let conn = self.conn(state)?;
        let mut guard = Self::enter(&conn)?;
        let max = self.max_message_bytes();
        if let Some(Phase::Dialling { held, message, .. }) = guard.as_mut() {
            // HELD, AND BOUNDED: a message over the ceiling is refused as the open connection
            // would refuse it (a capacity failure), and so is one past the held count, so a dial
            // whose far end never answers cannot grow the framing without end.
            let over = max > 0 && message.len().saturating_add(bytes.len()) > max;
            if over || (end_of_frame && held.len() >= MAX_HELD_MESSAGES) {
                // The refused message's gathered pieces go with it, as the open path drops them:
                // none is sent glued to the front of the next message.
                message.clear();
                return Err(TransportError::Framing);
            }
            message.extend_from_slice(bytes);
            if end_of_frame {
                // A text message is checked at the call, as the open connection checks it: bytes
                // that are not UTF-8 fail the write before they are held, never later at replay.
                if text && std::str::from_utf8(message).is_err() {
                    message.clear();
                    return Err(TransportError::Framing);
                }
                held.push((std::mem::take(message), text));
            }
            return Ok(());
        }
        Self::with_open(guard.as_mut(), out, |ws, message| {
            // THE CEILING, OUTBOUND TOO: the machine bounds only what it reads, so a message this
            // end writes is held to the same ceiling here, as a held one is above (a capacity
            // failure), and its gathered pieces are dropped.
            let size = message.len().saturating_add(bytes.len());
            if max > 0 && size > max {
                message.clear();
                return Err(WsError::Capacity(
                    tungstenite::error::CapacityError::MessageTooLong {
                        size,
                        max_size: max,
                    },
                ));
            }
            if !end_of_frame {
                message.extend_from_slice(bytes);
                return Ok(());
            }
            // A message emitted whole is copied into the payload the machine sends (the machine
            // takes its payload owned, and the host's bytes are lent for this call only); one
            // emitted in pieces is the pieces gathered. The machine frames it into its own buffer
            // and writes that straight into the host's wire buffer.
            let whole = if message.is_empty() {
                Bytes::copy_from_slice(bytes)
            } else {
                message.extend_from_slice(bytes);
                Bytes::from(std::mem::take(message))
            };
            ws.send(message_of(whole, text)?)
        })
    }

    fn hold(&self, phase: Phase) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.map().insert(id, Arc::new(Mutex::new(Some(phase))));
        id
    }

    /// The map of framing states. Its lock guards only the map (no framing's work runs under it),
    /// so a panic cannot leave it half-changed: a poisoned map is read as it stands.
    fn map(&self) -> MutexGuard<'_, HashMap<u64, Conn>> {
        self.states.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The reason phrase of the head framing `state`'s last call handed up (a dialled framing's,
    /// HTTP/1 as sent), taken once: the door states it in the head's slots.
    pub(crate) fn take_reason(&self, state: u64) -> Option<Vec<u8>> {
        self.reasons
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&state)
    }

    /// Drop framing `state` and anything kept for it, writing nothing: the door's finish of a
    /// framing whose op panicked, which never reached the framer to close it.
    pub(crate) fn forget(&self, state: u64) {
        self.map().remove(&state);
        self.reasons
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&state);
    }

    /// Whether framing `state` is still held (a test reads that a finished framing is gone).
    #[cfg(test)]
    pub(crate) fn holds(&self, state: u64) -> bool {
        self.map().contains_key(&state)
    }

    /// Framing `state`'s own lock, found under the map's.
    fn conn(&self, state: u64) -> Result<Conn, TransportError> {
        self.map()
            .get(&state)
            .cloned()
            .ok_or(TransportError::Closed)
    }

    /// Hold one framing's state. A framing whose op panicked is failed: that one, and no other.
    fn enter(conn: &Conn) -> Result<MutexGuard<'_, Option<Phase>>, TransportError> {
        conn.lock().map_err(|_| TransportError::Reset)
    }

    /// A new framing state for `side`, opening toward `target` when it dials.
    fn start(
        &self,
        side: Side,
        target: &str,
        fields: &[(String, Vec<u8>)],
        out: &mut dyn Output,
    ) -> Result<Phase, TransportError> {
        let mut phase = match side {
            Side::Accept => {
                let check: KeyCheck = check_key;
                match tungstenite::accept_hdr_with_config(Pipe::default(), check, self.config()) {
                    Err(HandshakeError::Interrupted(mid)) => Phase::Accepting(mid),
                    // Nothing has been read, so nothing can have completed or failed yet.
                    Ok(_) | Err(HandshakeError::Failure(_)) => {
                        return Err(TransportError::HandshakeFailed)
                    }
                }
            }
            Side::Dial => self.dial(target, fields)?,
        };
        drain(&mut phase, out);
        // The upgrade request may carry credential lines: what held it is wiped once sent.
        phase.pipe().outbound.zeroize();
        Ok(phase)
    }

    /// A dial's upgrade request, built and written into its pipe and not yet handed out: the
    /// protocol machine's handshake lines, then `fields` ([`rides_upgrade`]'s).
    fn dial(&self, target: &str, fields: &[(String, Vec<u8>)]) -> Result<Phase, TransportError> {
        let url = request_url(target)?;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| TransportError::AddressRefused)?;
        for (name, value) in fields.iter().filter(|(n, _)| rides_upgrade(n)) {
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value),
            ) else {
                return Err(TransportError::HandshakeFailed);
            };
            request.headers_mut().append(name, value);
        }
        #[cfg(feature = "test-seeded")]
        request
            .headers_mut()
            .insert("sec-websocket-key", HeaderValue::from_static(seeded::KEY));
        match tungstenite::client::client_with_config(
            request,
            Pipe {
                client: true,
                ..Pipe::default()
            },
            self.config(),
        ) {
            Err(HandshakeError::Interrupted(mid)) => Ok(Phase::Dialling {
                mid,
                held: Vec::new(),
                message: Vec::new(),
            }),
            Ok(_) | Err(HandshakeError::Failure(_)) => Err(TransportError::HandshakeFailed),
        }
    }

    /// Drive `phase` over what its pipe holds: finish the handshake if it can, then hand every
    /// message it completes up as a frame. Answers whether the connection's frames ended, and a
    /// dialled head's reason phrase the moment that head is handed up.
    fn drive(
        phase: Phase,
        out: &mut dyn Output,
    ) -> Result<(Phase, bool, Option<Vec<u8>>), TransportError> {
        let mut phase = match phase {
            Phase::Answered {
                mut pipe,
                left,
                chunked,
                ..
            } => {
                // A refused upgrade's body is read off the pipe's own queue.
                pipe.settle();
                let (phase, ended) = answered_body(pipe, left, chunked, false, out);
                return Ok((phase, ended, None));
            }
            // The error answer went out and the frames ended: what still arrives is nobody's.
            Phase::Refused(mut pipe) => {
                pipe.discard();
                return Ok((Phase::Refused(pipe), false, None));
            }
            phase => phase,
        };
        let shaking = !matches!(phase, Phase::Open { .. });
        // THE DIALLED HEAD'S REASON PHRASE (HEAD-FIELDS: the dialled side fills `reason`, as the
        // far end sent it), read off the status line before the machine takes the head.
        // What the dial's handshake has seen, and whether the carrier ended: a refusal's body is
        // read from here, every byte past the head (the machine reads the wire in chunks and keeps
        // what it read; what it did not read is still here).
        let shaken = match &mut phase {
            Phase::Dialling { mid, .. } => {
                let pipe = mid.get_mut().get_mut();
                Some((pipe.seen.clone(), pipe.ended))
            }
            _ => None,
        };
        let reason = shaken.as_ref().and_then(|(seen, _)| reason_phrase(seen));
        let mut phase = match phase {
            Phase::Accepting(mid) => match mid.handshake() {
                Ok(mut ws) => {
                    ws.get_mut().seen = Vec::new();
                    ws.get_mut().framing = true;
                    Phase::open(ws, Vec::new())
                }
                Err(HandshakeError::Interrupted(mid)) => {
                    return Ok((Phase::Accepting(mid), false, None))
                }
                // THE UPGRADE REQUEST BROKE THE HANDSHAKE RULES (RFC 6455 §4.2.1, §4.4): it is
                // answered with its HTTP error, written by the protocol library's own response
                // writer and handed out as every other byte is, and the frames end (failed). The
                // machine that failed took its stream with it, so the answer is written afresh
                // (the key check's own answer included). A request the carrier cut short has no
                // one to answer.
                Err(HandshakeError::Failure(e)) => {
                    let Some(status) = handshake_error_status(&e) else {
                        return Err(TransportError::HandshakeFailed);
                    };
                    let mut pipe = Pipe::default();
                    if write_response(&mut pipe, &handshake_error(status)).is_err() {
                        return Err(TransportError::HandshakeFailed);
                    }
                    return Ok((Phase::Refused(pipe), true, None));
                }
            },
            Phase::Dialling { mid, held, message } => match mid.handshake() {
                Ok((mut ws, response)) => {
                    ws.get_mut().framing = true;
                    // THE FAR END ANSWERED (HEAD-FIELDS): its switching response is the stream's
                    // head, handed up before anything else, with its status and its field block.
                    // A far end that answered the upgrade and sends nothing more has answered.
                    let block = head_block(response.headers());
                    out.frame(Framed {
                        status: Some(WireStatusClass::Success),
                        status_code: Some(u32::from(response.status().as_u16())),
                        ..Framed::plain(StreamId(0), &block, true)
                    });
                    // What was written before the handshake completed goes out now, in order.
                    for (bytes, text) in held {
                        let m = message_of(Bytes::from(bytes), text).map_err(|e| read_error(&e))?;
                        ws.write(m).map_err(|e| read_error(&e))?;
                    }
                    ws.get_mut().seen = Vec::new();
                    Phase::open(ws, message)
                }
                Err(HandshakeError::Interrupted(mid)) => {
                    return Ok((Phase::Dialling { mid, held, message }, false, None))
                }
                // THE FAR END REFUSED THE UPGRADE (HEAD-FIELDS: the head is always the first
                // fields piece): its answer is handed up as ONE head with its status, its class and
                // its fields, then its body (a far end's error document), and the frames end, so the
                // breaker reads what it answered and the plane sees what it said. The body is every
                // byte past the head (what came with it, then what still arrives) up to its declared
                // `Content-Length`, or with none declared until the carrier ends, unless its
                // transfer coding is `chunked`, which frames it instead (decoded, to its last
                // chunk; RFC 9112 §6.3); then the frames end.
                Err(HandshakeError::Failure(WsError::Http(response))) => {
                    let code = response.status().as_u16();
                    let block = head_block(response.headers());
                    out.frame(Framed {
                        status: Some(status_class(code)),
                        status_code: Some(u32::from(code)),
                        retry_after_secs: retry_after(
                            response.headers(),
                            out.now().unix_nanos / 1_000_000_000,
                        ),
                        ..Framed::plain(StreamId(0), &block, true)
                    });
                    let (seen, carrier_ended) = shaken.unwrap_or_default();
                    let at = head_end(&seen);
                    let pipe = Pipe {
                        inbound: seen[at..].iter().copied().collect(),
                        ended: carrier_ended,
                        ..Pipe::default()
                    };
                    // A status that carries no body (1xx, 204, 304: RFC 9112 §6.3) ends at its
                    // head, whatever its framing fields say.
                    let bodiless = matches!(code, 100..=199 | 204 | 304);
                    let chunked =
                        (!bodiless && is_chunked(response.headers())).then(Box::<Dechunk>::default);
                    let declared = if bodiless {
                        Some(0)
                    } else if chunked.is_some() {
                        None
                    } else {
                        content_length(response.headers())
                    };
                    let (phase, ended) = answered_body(pipe, declared, chunked, true, out);
                    return Ok((phase, ended, reason));
                }
                Err(HandshakeError::Failure(_)) => return Err(TransportError::HandshakeFailed),
            },
            open => open,
        };
        let Phase::Open {
            ws, failed, lost, ..
        } = &mut phase
        else {
            unreachable!("every other phase returned above");
        };
        // The head just handed up carries its reason; an open session's later calls carry none.
        let reason = if shaking { reason } else { None };
        if failed.is_some() || *lost {
            // The frames ended at the failure: what still arrives is nobody's.
            ws.get_mut().discard();
            return Ok((phase, false, None));
        }
        let mut ended = false;
        loop {
            match ws.read() {
                // Each message goes up as the machine completed it: its own buffer, not a copy.
                Ok(Message::Binary(b)) => out.message(b, false),
                Ok(Message::Text(t)) => out.message(Bytes::from(t), true),
                // A ping's pong is queued by the machine and goes out with the next bytes; a pong and
                // a raw frame carry nothing for the layer above.
                Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
                // The peer closed: the machine queued the close answer (the peer's own code), and
                // no frame follows.
                Ok(Message::Close(_)) => {
                    ended = true;
                    break;
                }
                Err(WsError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {
                    ended = true;
                    break;
                }
                // The carrier ended with no closing handshake (a dropped connection, a closed
                // tab): every message completed before it was handed up above, and the frames end
                // here FAILED, never whole: RFC 6455 §7.1.5 names this close 1006, abnormal, and a
                // message it cut short is lost. No close frame can follow (1006 is never sent), and
                // it is no protocol the far side broke.
                Err(WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => {
                    *lost = true;
                    ended = true;
                    break;
                }
                Err(e) => match failure_code(&e) {
                    // The far side broke the protocol on a live connection: the frames end here,
                    // and the close (written when this end closes) carries the failure's code.
                    Some(code) => {
                        *failed = Some(code);
                        break;
                    }
                    None => return Err(read_error(&e)),
                },
            }
        }
        if failed.is_some() {
            ws.get_mut().discard();
            ended = true;
        }
        // Whatever the machine owes the far side (a pong, a close answer) goes out now.
        match ws.flush() {
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {}
            Err(WsError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(read_error(&e)),
        }
        let pipe = ws.get_mut();
        ended |= pipe.ended && pipe.drained();
        Ok((phase, ended, reason))
    }

    /// Run `op` on the open state `state`, handing what it wrote to core.
    fn with_open(
        phase: Option<&mut Phase>,
        out: &mut dyn Output,
        op: impl FnOnce(&mut WebSocket<Pipe>, &mut Vec<u8>) -> Result<(), WsError>,
    ) -> Result<(), TransportError> {
        let phase = phase.ok_or(TransportError::Closed)?;
        let Phase::Open { ws, message, .. } = phase else {
            return Err(TransportError::Closed);
        };
        lend_window(ws, out);
        let done = op(ws, message);
        drain(phase, out);
        done.map_err(|e| match e {
            WsError::Capacity(_) | WsError::Utf8(_) => TransportError::Framing,
            WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::Closed,
            _ => TransportError::Reset,
        })
    }
}

/// One `ws://`/`wss://` URL, read into `(secure, host, port, path)` by the contract's one URL
/// reader ([`busbar_contract::net::parse_url`], WHATWG rules): the scheme is read without case
/// (RFC 3986 §3.1: `WSS://` is `wss://`), and only `ws` or `wss` is taken; the authority ends at
/// `/`, `?`, `#` or `\` exactly where the handshake's parser ends it, the host comes back
/// unbracketed, and a userinfo is refused. The path always opens with `/`.
pub(crate) fn split_ws_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let parts = busbar_contract::net::parse_url(url).map_err(|_| TransportError::AddressRefused)?;
    let secure = match parts.scheme.as_str() {
        "wss" => true,
        "ws" => false,
        _ => return Err(TransportError::AddressRefused),
    };
    if parts.userinfo {
        return Err(TransportError::AddressRefused);
    }
    let port = parts.port.unwrap_or(if secure { 443 } else { 80 });
    Ok((secure, parts.host, port, parts.path))
}

/// THE DIALLED UPGRADE REQUEST AS IT GOES ON THE WIRE (ruling 23: nothing is added to a head after
/// its auth runs): what the binding's auth is called over, borrowed from the bytes that are sent.
pub(crate) struct UpgradeHead<'a> {
    /// The request line's path, as sent.
    pub(crate) target: &'a str,
    /// The request line's query, without `?`; `None` = none.
    pub(crate) query: Option<&'a str>,
    /// The `Host` line's value.
    pub(crate) authority: &'a str,
    /// Every field line, in wire order, names as sent: the handshake's own lines first, then the
    /// plane's.
    pub(crate) fields: &'a [(&'a str, &'a [u8])],
}

/// One line the binding's auth answered: a field line of the head, or (`query`) a key of the
/// target's query. Its value is credential material, wiped when dropped.
pub(crate) struct AuthLine {
    /// The name.
    pub(crate) name: String,
    /// The value.
    pub(crate) value: Zeroizing<Vec<u8>>,
    /// A query key, never a field line.
    pub(crate) query: bool,
}

/// The binding's auth, called once over the upgrade request exactly as it goes on the wire.
/// [`Poll::Pending`]: the auth's answer is not ready (the host stores it on the call's handle); the
/// dial is parked and the same call is made again when the op resumes.
pub(crate) type Signer<'s> =
    &'s mut dyn FnMut(&UpgradeHead<'_>) -> Poll<Result<Vec<AuthLine>, TransportError>>;

/// A query key or value an auth answered: visible ASCII that neither ends the target (`#`, a
/// space) nor splits its pairs (`&`); a key carries no `=`.
fn query_safe(bytes: &[u8], key: bool) -> bool {
    (!key || !bytes.is_empty())
        && bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() && b != b'#' && b != b'&' && !(key && b == b'='))
}

/// THE SIGNED UPGRADE REQUEST (ruling 23, the framer's order): `wire` is the request the protocol
/// machine wrote, the framer's own lines (the handshake's) and the plane's; `sign` is called over
/// exactly those bytes; each field line it answers is appended after every other line, replacing
/// any line of the same name (ASCII case-insensitive), and each query key it answers joins the
/// target's query, replacing any pair of the same key. Nothing is added after. An answer that
/// names a handshake line ([`rides_upgrade`]'s refusals), or a line or key the request cannot
/// carry, refuses the dial.
fn signed_request(wire: &[u8], sign: Signer<'_>) -> Poll<Result<Vec<u8>, TransportError>> {
    match signed_inner(wire, sign) {
        Ok(Some(signed)) => Poll::Ready(Ok(signed)),
        Ok(None) => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

/// `None`: the auth's answer is not ready.
fn signed_inner(wire: &[u8], sign: Signer<'_>) -> Result<Option<Vec<u8>>, TransportError> {
    let broken = || TransportError::HandshakeFailed;
    let head = wire.strip_suffix(b"\r\n\r\n").ok_or_else(broken)?;
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request_line =
        std::str::from_utf8(lines.next().ok_or_else(broken)?).map_err(|_| broken())?;
    let (path, query) = request_line
        .strip_prefix("GET ")
        .and_then(|l| l.rsplit_once(' '))
        .filter(|(_, version)| *version == "HTTP/1.1")
        .map(|(target, _)| {
            target
                .split_once('?')
                .map_or((target, None), |(p, q)| (p, Some(q)))
        })
        .ok_or_else(broken)?;
    let mut fields = Vec::new();
    for line in lines {
        let at = line
            .windows(2)
            .position(|w| w == b": ")
            .ok_or_else(broken)?;
        let name = std::str::from_utf8(&line[..at]).map_err(|_| broken())?;
        fields.push((name, &line[at + 2..]));
    }
    let authority = fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
        .ok_or_else(broken)?;
    let answer = match sign(&UpgradeHead {
        target: path,
        query,
        authority,
        fields: &fields,
    }) {
        Poll::Pending => return Ok(None),
        Poll::Ready(answer) => answer?,
    };

    let mut pairs: Vec<&[u8]> = query
        .map(|q| q.as_bytes().split(|&b| b == b'&').collect())
        .unwrap_or_default();
    for line in &answer {
        let name = line.name.as_bytes();
        if line.query {
            if !query_safe(name, true) || !query_safe(&line.value, false) {
                return Err(broken());
            }
            pairs.retain(|p| p.split(|&b| b == b'=').next() != Some(name));
        } else {
            if HeaderName::from_bytes(name).is_err()
                || HeaderValue::from_bytes(&line.value).is_err()
                || !rides_upgrade(&line.name)
            {
                return Err(broken());
            }
            fields.retain(|(n, _)| !n.eq_ignore_ascii_case(&line.name));
        }
    }

    let mut signed = Vec::with_capacity(
        wire.len()
            + answer
                .iter()
                .map(|l| l.name.len() + l.value.len() + 4)
                .sum::<usize>(),
    );
    signed.extend_from_slice(b"GET ");
    signed.extend_from_slice(path.as_bytes());
    let mut sep = b'?';
    for pair in pairs {
        signed.push(sep);
        signed.extend_from_slice(pair);
        sep = b'&';
    }
    for line in answer.iter().filter(|l| l.query) {
        signed.push(sep);
        signed.extend_from_slice(line.name.as_bytes());
        signed.push(b'=');
        signed.extend_from_slice(&line.value);
        sep = b'&';
    }
    signed.extend_from_slice(b" HTTP/1.1\r\n");
    let own = fields.iter().copied();
    let auth = answer
        .iter()
        .filter(|l| !l.query)
        .map(|l| (l.name.as_str(), l.value.as_slice()));
    for (name, value) in own.chain(auth) {
        signed.extend_from_slice(name.as_bytes());
        signed.extend_from_slice(b": ");
        signed.extend_from_slice(value);
        signed.extend_from_slice(b"\r\n");
    }
    signed.extend_from_slice(b"\r\n");
    Ok(Some(signed))
}

/// A host as an authority spells it: an IPv6 literal in its brackets (RFC 3986 section 3.2.2).
fn authority_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// The upgrade request's URL for a dial to `url`: its scheme (lower-case), its host as the URL
/// reader normalises it (percent-decoded, a trailing dot dropped; an IPv6 literal bracketed), the
/// port only where the target spelled one, and its path. The request's `Host` is that host and
/// port: the target's normalised host, not its authority as written.
fn request_url(url: &str) -> Result<String, TransportError> {
    let (secure, host, _, path) = split_ws_url(url)?;
    let port = busbar_contract::net::parse_url(url)
        .map_err(|_| TransportError::AddressRefused)?
        .port;
    Ok(format!(
        "{}://{}{}{path}",
        if secure { "wss" } else { "ws" },
        authority_host(&host),
        port.map(|p| format!(":{p}")).unwrap_or_default()
    ))
}

impl WsFramer {
    /// Whether the frames of the connection in `state` ended FAILED, not cleanly: the far side
    /// failed it (a protocol violation, text that is not UTF-8, a message over the ceiling), the
    /// carrier ended with no closing handshake, its upgrade request broke the handshake rules, or
    /// a refused upgrade's body was cut short by the carrier's end.
    pub(crate) fn failed(&self, state: u64) -> bool {
        let Ok(conn) = self.conn(state) else {
            return false;
        };
        let Ok(held) = Self::enter(&conn) else {
            return false;
        };
        matches!(
            held.as_ref(),
            Some(
                Phase::Open {
                    failed: Some(_),
                    ..
                } | Phase::Open { lost: true, .. }
                    | Phase::Answered { short: true, .. }
                    | Phase::Refused(_)
            )
        )
    }

    /// [`Framer::ingest`] into an [`Output`]. The machine reads `bytes` where they lie (the host
    /// lends them for this call only) and, on a running session, writes straight into the host's
    /// wire buffer when the door lends it; what it does not read this call is kept for the next.
    ///
    /// # Errors
    ///
    /// As [`Framer::ingest`].
    pub(crate) fn ingest_to(
        &self,
        state: u64,
        bytes: &[u8],
        end: bool,
        out: &mut dyn Output,
    ) -> Result<(), TransportError> {
        let conn = self.conn(state)?;
        let mut held = Self::enter(&conn)?;
        let mut phase = held.take().ok_or(TransportError::Closed)?;
        let dialling = matches!(phase, Phase::Dialling { .. });
        let open = matches!(phase, Phase::Open { .. });
        let pipe = phase.pipe();
        pipe.lent.lend(bytes);
        pipe.ended |= end;
        if open {
            pipe.window.lend(out.window());
        }
        // Only a dialled head is read back off what the handshake saw (its reason phrase, a
        // refusal's body); an accepting handshake keeps no copy.
        if dialling {
            pipe.seen.extend_from_slice(bytes);
        }
        match Self::drive(phase, out) {
            Ok((mut phase, ended, reason)) => {
                if let Some(reason) = reason {
                    self.reasons
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(state, reason);
                }
                drain(&mut phase, out);
                phase.pipe().settle();
                if ended {
                    out.end();
                }
                *held = Some(phase);
                Ok(())
            }
            // A failed state is gone: its connection has nothing more to say.
            Err(e) => {
                drop(held);
                self.map().remove(&state);
                self.take_reason(state);
                Err(e)
            }
        }
    }

    /// [`Framer::adopt`] into an [`Output`].
    ///
    /// # Errors
    ///
    /// As [`Framer::adopt`].
    pub(crate) fn adopt_to(
        &self,
        side: Side,
        _facts: &ConnFacts,
        leftover: &[u8],
        out: &mut dyn Output,
    ) -> Result<u64, TransportError> {
        let state = self.open_to(side, "", &[], out)?;
        self.ingest_to(state, leftover, false, out)?;
        Ok(state)
    }
}

impl Default for WsFramer {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Plugin for WsFramer {
    fn key(&self) -> &'static str {
        <Self as busbar_contract::transport::TransportMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl Framer for WsFramer {
    /// A `ws://` target is reached at its `host:port`; a `wss://` one asks for its bytes to be
    /// secured before they leave, and names the host its certificate is checked against.
    fn locate(&self, target: &str) -> Result<Located, TransportError> {
        let (secure, host, port, _path) = split_ws_url(target)?;
        Ok(Located {
            authority: format!("{}:{port}", authority_host(&host)),
            secure,
            server_name: secure.then_some(host),
        })
    }

    fn open(
        &self,
        side: Side,
        target: &str,
        _facts: &ConnFacts,
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        self.open_with(side, target, &[], out)
    }

    fn ingest(
        &self,
        state: u64,
        bytes: &[u8],
        end: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.ingest_to(state, bytes, end, &mut Plain(out))
    }

    fn emit(
        &self,
        state: u64,
        _stream: StreamId,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.emit_text(state, bytes, end_of_frame, text, out)
    }

    /// A WebSocket message is its payload: the envelope belonged to the upgrade request, which is
    /// long over by the time a message is written.
    fn encode_envelope(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        out: &mut dyn BytesOut,
    ) -> Result<(), Encode> {
        out.put(body);
        Ok(())
    }

    /// A WebSocket connection carries one message stream: the refusal is one message, and the
    /// connection closes after it, with the orderly code.
    fn refusal(
        &self,
        state: u64,
        stream: Option<StreamId>,
        bytes: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.refusal_with(state, stream, bytes, 0, out)
    }

    fn close(&self, state: u64, reason: CloseReason, out: &mut dyn FramerOut) {
        self.close_to(state, reason, &mut Plain(out));
    }

    /// A WebSocket state keeps no deadline of its own (it never states one), so a tick finds nothing
    /// due; an unknown state is closed.
    fn tick(&self, state: u64, _out: &mut dyn FramerOut) -> Result<(), TransportError> {
        if self.map().contains_key(&state) {
            Ok(())
        } else {
            Err(TransportError::Closed)
        }
    }

    /// Nothing upgrades in-band out of a WebSocket (RFC 6455 defines no upgrade out of an
    /// established connection), so there is no stream to hand on: refusing is the protocol's answer.
    fn detach(&self, _state: u64, _out: &mut dyn BytesOut) -> Result<(), TransportError> {
        Err(TransportError::HandoffMismatch)
    }

    /// The upgrade into this framer: the stream another framer gave up, with the bytes it held —
    /// the upgrade request itself, on the accepting side — which this one answers.
    fn adopt(
        &self,
        side: Side,
        facts: &ConnFacts,
        leftover: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        self.adopt_to(side, facts, leftover, &mut Plain(out))
    }
}
