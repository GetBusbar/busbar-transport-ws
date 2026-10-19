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
//!   peer's own code and ends the frames.
//! * A close this end starts carries the RFC 6455 code its reason names ([`close_code_for`]).
//! * Bytes that break the protocol FAIL the connection (RFC 6455 §7.1.7) the way the RFC orders it:
//!   every message completed before them is handed up first, the frames end, the layer above may
//!   still answer what it was handed, and the close then carries the failure's code (1002 a
//!   protocol error, 1007 a text payload that is not UTF-8, 1009 a message over the ceiling).
//!   The protocol machine judges every frame, text UTF-8 included (as each frame completes); this
//!   framer parses no WebSocket frame of its own (THE DESIGN §2 "Libraries": ONE protocol = ONE
//!   library, the `tungstenite` family).
//! * The message ceiling is the deployment's body cap, for a whole message and for a single frame.
//!
//! The upgrade INTO this framer is [`Framer::adopt`]: another framer gave up the stream with the
//! bytes it held (the upgrade request itself), and this one answers it. Nothing upgrades out of a
//! WebSocket, so [`Framer::detach`] refuses.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::transport::fields::{hop_by_hop, LINE_END, SEPARATOR};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{CloseReason, Encode, TransportError, WireStatusClass};
use busbar_contract::transport::{BytesOut, ConnFacts, Framed, Framer, FramerOut, Located, Side};
use busbar_contract::{AbiVersion, Kind, Plugin};
use tungstenite::client::IntoClientRequest;
use tungstenite::error::ProtocolError;
use tungstenite::handshake::client::ClientHandshake;
use tungstenite::handshake::server::{NoCallback, ServerHandshake};
use tungstenite::handshake::{HandshakeError, MidHandshake};
use tungstenite::http::{HeaderMap, HeaderName, HeaderValue};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::{Bytes, Error as WsError, Message, Utf8Bytes, WebSocket};

/// The in-memory stream one framing state's protocol machine reads and writes: what core ingested
/// and the machine has not consumed, whether the carrier's clean end followed it, what the
/// machine wrote and core has not been handed yet, and what arrived during the handshake.
#[derive(Default)]
pub(crate) struct Pipe {
    inbound: VecDeque<u8>,
    ended: bool,
    outbound: Vec<u8>,
    /// Every byte ingested while the opening handshake runs: a dialled head's status line (its
    /// reason phrase) is read from here.
    seen: Vec<u8>,
    /// This end dialled: its frames are masked (RFC 6455 section 5.3). Read only by the test
    /// harness's seed (`test-seeded`), which unmasks a dialled end's frames.
    #[cfg_attr(not(feature = "test-seeded"), allow(dead_code))]
    client: bool,
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inbound.is_empty() {
            // Nothing more yet: the machine stops here and resumes on the next ingest. Only the
            // carrier's clean end is the end.
            return if self.ended {
                Ok(0)
            } else {
                Err(std::io::ErrorKind::WouldBlock.into())
            };
        }
        let n = buf.len().min(self.inbound.len());
        let (front, back) = self.inbound.as_slices();
        let a = n.min(front.len());
        buf[..a].copy_from_slice(&front[..a]);
        buf[a..n].copy_from_slice(&back[..n - a]);
        self.inbound.drain(..n);
        Ok(n)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One framing state behind its own lock; `None` while an op holds it out, or once it failed.
type Conn = Arc<Mutex<Option<Phase>>>;

/// Where one framing state is.
enum Phase {
    /// An accepted connection waiting for (the rest of) the upgrade request.
    Accepting(MidHandshake<ServerHandshake<Pipe, NoCallback>>),
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
    /// broke the protocol.
    Open {
        ws: Box<WebSocket<Pipe>>,
        message: Vec<u8>,
        failed: Option<CloseCode>,
    },
    /// A dialled connection the far end answered with something other than `101`: its answer's
    /// head was handed up as the stream's head, then its body: `left` bytes of it still to come
    /// (its declared `Content-Length`), or with none declared, every byte until the carrier ends.
    /// At `Some(0)` its frames have ended and nothing more is read.
    Answered { pipe: Pipe, left: Option<u64> },
}

impl Phase {
    /// The session over `ws`, its outbound message starting as `message`.
    fn open(ws: WebSocket<Pipe>, message: Vec<u8>) -> Self {
        Phase::Open {
            ws: Box::new(ws),
            message,
            failed: None,
        }
    }
}

impl Phase {
    fn pipe(&mut self) -> &mut Pipe {
        match self {
            Phase::Accepting(mid) => mid.get_mut().get_mut(),
            Phase::Dialling { mid, .. } => mid.get_mut().get_mut(),
            Phase::Open { ws, .. } => ws.get_mut(),
            Phase::Answered { pipe, .. } => pipe,
        }
    }
}

/// The most whole messages a dial holds while its handshake has not completed.
pub const MAX_HELD_MESSAGES: usize = 64;

/// The `ws` framer: its framing states, and the message ceiling every connection is built with.
pub struct WsFramer {
    /// Every framing state, each behind its own lock: the map's lock is held only to find, add or
    /// remove one, never across a framing's work, so connections run side by side and a panic in
    /// one fails that one alone.
    states: Mutex<HashMap<u64, Conn>>,
    /// Each dialled framing's head reason phrase, from the call that handed the head up until the
    /// door takes it ([`WsFramer::take_reason`]).
    reasons: Mutex<HashMap<u64, Vec<u8>>>,
    next: AtomicU64,
    max_message_bytes: usize,
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
/// response's fields in the far end's order, names lower-case, a repeated name's values each on its
/// own line. Hop-by-hop fields (and every field a `connection` field names) never enter it, nor do
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

/// The `Retry-After` an answer states, in whole seconds (its delta-seconds form).
fn retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
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
pub(crate) fn reason_phrase(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(2).position(|w| w == b"\r\n")?;
    let mut parts = seen[..end].splitn(3, |b| *b == b' ');
    let (_version, _code) = (parts.next()?, parts.next()?);
    parts.next().filter(|r| !r.is_empty()).map(<[u8]>::to_vec)
}

/// A refused upgrade's BODY: frame what the pipe holds, up to the `left` bytes its declared
/// `Content-Length` still owes (or, with none declared, until the carrier ends), and end the frames
/// once they are all handed up or the carrier ended. `first`: the call that handed the head up (a
/// declared length of `0` ends the frames then). Past the end, what arrives is nobody's.
fn answered_body(
    mut pipe: Pipe,
    left: Option<u64>,
    first: bool,
    out: &mut dyn FramerOut,
) -> (Phase, bool) {
    if left == Some(0) {
        pipe.inbound.clear();
        return (Phase::Answered { pipe, left }, first);
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
    let left = if ended { Some(0) } else { left };
    (Phase::Answered { pipe, left }, ended)
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

/// Hand whatever the machine wrote to core.
fn drain(phase: &mut Phase, out: &mut dyn FramerOut) {
    #[cfg(feature = "test-seeded")]
    let open = matches!(phase, Phase::Open { .. });
    let pipe = phase.pipe();
    if !pipe.outbound.is_empty() {
        #[cfg(feature = "test-seeded")]
        if open && pipe.client {
            seeded::unmask(&mut pipe.outbound);
        }
        out.send(&pipe.outbound);
        pipe.outbound.clear();
    }
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
    fn close_with(&self, state: u64, code: CloseCode, out: &mut dyn FramerOut) {
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
    pub fn refusal_with(
        &self,
        state: u64,
        _stream: Option<StreamId>,
        bytes: &[u8],
        status: u32,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let sent = self.emit(state, StreamId(0), bytes, true, false, out);
        self.close_with(state, close_code_of_status(status), out);
        sent
    }

    /// A framer whose messages (and frames) are capped at `max_message_bytes`; `0` = the protocol
    /// library's own default stands.
    #[must_use]
    pub fn new(max_message_bytes: usize) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            reasons: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            max_message_bytes,
        }
    }

    fn config(&self) -> Option<WebSocketConfig> {
        (self.max_message_bytes > 0).then(|| {
            WebSocketConfig::default()
                .max_message_size(Some(self.max_message_bytes))
                .max_frame_size(Some(self.max_message_bytes))
        })
    }

    /// [`Framer::open`], a dialled connection's upgrade request carrying `fields` (the dial's
    /// opening head fields, `BeginIn::fields`).
    ///
    /// # Errors
    ///
    /// The target is not a WebSocket URL, or a field is not a valid header.
    pub fn open_with(
        &self,
        side: Side,
        target: &str,
        fields: &[(String, Vec<u8>)],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        let phase = self.start(side, target, fields, out)?;
        Ok(self.hold(phase))
    }

    /// [`Framer::emit`]: with `text` (the emit's `EMIT_TEXT`) the message goes out as a text
    /// message, under the TEXT opcode, which promises UTF-8 (RFC 6455 §8.1): bytes that are not fail
    /// the write rather than go out under a promise they break. On a dialled connection whose
    /// handshake has not completed, the message is held and goes out the moment it does.
    ///
    /// # Errors
    ///
    /// The state is gone, a text message is not UTF-8, or the machine refused it.
    pub fn emit_text(
        &self,
        state: u64,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let conn = self.conn(state)?;
        let mut guard = Self::enter(&conn)?;
        if let Some(Phase::Dialling { held, message, .. }) = guard.as_mut() {
            // HELD, AND BOUNDED: a message over the ceiling is refused as the open connection
            // would refuse it (a capacity failure), and so is one past the held count, so a dial
            // whose far end never answers cannot grow the framing without end.
            let over = self.max_message_bytes > 0
                && message.len().saturating_add(bytes.len()) > self.max_message_bytes;
            if over || (end_of_frame && held.len() >= MAX_HELD_MESSAGES) {
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
        let max = self.max_message_bytes;
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
            // A message emitted whole is copied once, into the payload the machine sends; one
            // emitted in pieces is the pieces gathered.
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
    pub fn take_reason(&self, state: u64) -> Option<Vec<u8>> {
        self.reasons
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&state)
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
        out: &mut dyn FramerOut,
    ) -> Result<Phase, TransportError> {
        let mut phase = match side {
            Side::Accept => {
                match tungstenite::accept_with_config(Pipe::default(), self.config()) {
                    Err(HandshakeError::Interrupted(mid)) => Phase::Accepting(mid),
                    // Nothing has been read, so nothing can have completed or failed yet.
                    Ok(_) | Err(HandshakeError::Failure(_)) => {
                        return Err(TransportError::HandshakeFailed)
                    }
                }
            }
            Side::Dial => {
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
                    Err(HandshakeError::Interrupted(mid)) => Phase::Dialling {
                        mid,
                        held: Vec::new(),
                        message: Vec::new(),
                    },
                    Ok(_) | Err(HandshakeError::Failure(_)) => {
                        return Err(TransportError::HandshakeFailed)
                    }
                }
            }
        };
        drain(&mut phase, out);
        Ok(phase)
    }

    /// Drive `phase` over what its pipe holds: finish the handshake if it can, then hand every
    /// message it completes up as a frame. Answers whether the connection's frames ended, and a
    /// dialled head's reason phrase the moment that head is handed up.
    fn drive(
        phase: Phase,
        out: &mut dyn FramerOut,
    ) -> Result<(Phase, bool, Option<Vec<u8>>), TransportError> {
        let mut phase = match phase {
            Phase::Answered { pipe, left } => {
                let (phase, ended) = answered_body(pipe, left, false, out);
                return Ok((phase, ended, None));
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
                    Phase::open(ws, Vec::new())
                }
                Err(HandshakeError::Interrupted(mid)) => {
                    return Ok((Phase::Accepting(mid), false, None))
                }
                Err(HandshakeError::Failure(_)) => return Err(TransportError::HandshakeFailed),
            },
            Phase::Dialling { mid, held, message } => match mid.handshake() {
                Ok((mut ws, response)) => {
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
                // `Content-Length`, or with none declared until the carrier ends; then the frames
                // end. This framer decodes no other HTTP/1 body framing.
                Err(HandshakeError::Failure(WsError::Http(response))) => {
                    let code = response.status().as_u16();
                    let block = head_block(response.headers());
                    out.frame(Framed {
                        status: Some(status_class(code)),
                        status_code: Some(u32::from(code)),
                        retry_after_secs: retry_after(response.headers()),
                        ..Framed::plain(StreamId(0), &block, true)
                    });
                    let (seen, carrier_ended) = shaken.unwrap_or_default();
                    let at = seen
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map_or(seen.len(), |p| p + 4);
                    let pipe = Pipe {
                        inbound: seen[at..].iter().copied().collect(),
                        ended: carrier_ended,
                        ..Pipe::default()
                    };
                    let declared = content_length(response.headers());
                    let (phase, ended) = answered_body(pipe, declared, true, out);
                    return Ok((phase, ended, reason));
                }
                Err(HandshakeError::Failure(_)) => return Err(TransportError::HandshakeFailed),
            },
            open => open,
        };
        let Phase::Open { ws, failed, .. } = &mut phase else {
            unreachable!("every other phase returned above");
        };
        // The head just handed up carries its reason; an open session's later calls carry none.
        let reason = if shaking { reason } else { None };
        if failed.is_some() {
            // The frames ended at the failure: what still arrives is nobody's.
            ws.get_mut().inbound.clear();
            return Ok((phase, false, None));
        }
        let mut ended = false;
        loop {
            match ws.read() {
                Ok(Message::Binary(b)) => out.frame(Framed::plain(StreamId(0), &b, true)),
                Ok(Message::Text(t)) => {
                    out.frame(Framed::plain(StreamId(0), t.as_bytes(), true).text(true));
                }
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
                // tab): every message completed before it was handed up above, and the stream
                // ends here. That is the connection going away, not a protocol the far side broke.
                Err(WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => {
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
            ws.get_mut().inbound.clear();
            ended = true;
        }
        // Whatever the machine owes the far side (a pong, a close answer) goes out now.
        match ws.flush() {
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {}
            Err(WsError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(read_error(&e)),
        }
        let pipe = ws.get_mut();
        ended |= pipe.ended && pipe.inbound.is_empty();
        Ok((phase, ended, reason))
    }

    /// Run `op` on the open state `state`, handing what it wrote to core.
    fn with_open(
        phase: Option<&mut Phase>,
        out: &mut dyn FramerOut,
        op: impl FnOnce(&mut WebSocket<Pipe>, &mut Vec<u8>) -> Result<(), WsError>,
    ) -> Result<(), TransportError> {
        let phase = phase.ok_or(TransportError::Closed)?;
        let Phase::Open { ws, message, .. } = phase else {
            return Err(TransportError::Closed);
        };
        let done = op(ws, message);
        drain(phase, out);
        done.map_err(|e| match e {
            WsError::Capacity(_) | WsError::Utf8(_) => TransportError::Framing,
            WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::Closed,
            _ => TransportError::Reset,
        })
    }
}

/// One `ws://`/`wss://` URL, read into `(secure, host, port, path)`. Strict over the scheme, with
/// the authority read by the contract's one URL reader ([`busbar_contract::net::parse_url`], WHATWG
/// rules): it ends at `/`, `?`, `#` or `\` exactly where the handshake's parser ends it, the host
/// comes back unbracketed, and a userinfo is refused. The path always opens with `/`.
pub(crate) fn split_ws_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let secure = if url.starts_with("wss://") {
        true
    } else if url.starts_with("ws://") {
        false
    } else {
        return Err(TransportError::AddressRefused);
    };
    let parts = busbar_contract::net::parse_url(url).map_err(|_| TransportError::AddressRefused)?;
    if parts.userinfo {
        return Err(TransportError::AddressRefused);
    }
    let port = parts.port.unwrap_or(if secure { 443 } else { 80 });
    Ok((secure, parts.host, port, parts.path))
}

/// A host as an authority spells it: an IPv6 literal in its brackets (RFC 3986 section 3.2.2).
fn authority_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// The upgrade request's URL for a dial to `url`: its scheme, host (an IPv6 literal bracketed),
/// port only where the target spelled one, and path, so the request's `Host` is the target's
/// authority as written.
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
    /// Whether the far side FAILED the connection in `state` (a protocol violation, text that is
    /// not UTF-8, a message over the ceiling): its frames ended failed, not cleanly.
    pub(crate) fn failed(&self, state: u64) -> bool {
        let Ok(conn) = self.conn(state) else {
            return false;
        };
        let Ok(held) = Self::enter(&conn) else {
            return false;
        };
        matches!(
            held.as_ref(),
            Some(Phase::Open {
                failed: Some(_),
                ..
            })
        )
    }
}

impl Default for WsFramer {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Plugin for WsFramer {
    fn key(&self) -> &'static str {
        crate::linked::KEY
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
        let conn = self.conn(state)?;
        let mut held = Self::enter(&conn)?;
        let mut phase = held.take().ok_or(TransportError::Closed)?;
        let dialling = matches!(phase, Phase::Dialling { .. });
        let pipe = phase.pipe();
        pipe.inbound.extend(bytes);
        pipe.ended |= end;
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
        self.close_with(state, close_code_for(reason), out);
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

    /// Nothing upgrades in-band out of a WebSocket, so there is no stream to hand on.
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
        let state = self.open(side, "", facts, out)?;
        self.ingest(state, leftover, false, out)?;
        Ok(state)
    }
}
