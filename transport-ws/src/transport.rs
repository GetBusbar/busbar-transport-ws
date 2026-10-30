// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `ws` framer the door drives (`crate::door`, the memory-ABI framer door, linked into a busbar
//! build or exported by the sibling `busbar-transport-ws-plugin` cdylib).
//!
//! Sans-IO. The framer holds no socket, no waker and no clock: core hands it the bytes the carrier
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
//!   door's head slots ([`WsFramer::ingest_head`]).
//! * A DIALLED connection's switching-protocols response is the far end's ANSWER (a transport
//!   always hands the response head up as the stream's first fields frame): the moment
//!   it completes the handshake it is handed up as ONE frame carrying its status (`101`, a
//!   success) and its field block ([`head_block`]), ahead of any message, so a far end that has
//!   answered the upgrade and not yet sent a message has answered. It is the only frame this framer
//!   states a status on: a message never carries one.
//! * A ping is answered with its pong on the next bytes out; a peer's close is answered with the
//!   peer's own code and ends the frames. A carrier that ends with no closing handshake ends them
//!   FAILED (RFC 6455 section 7.1.5, `1006`: not closed cleanly), mid-message or not.
//! * A close this end starts carries the RFC 6455 code its reason names ([`close_code_for`]).
//! * Bytes that break the protocol FAIL the connection (RFC 6455 §7.1.7) the way the RFC orders it:
//!   every message completed before them is handed up first, the frames end, the layer above may
//!   still answer what it was handed, and the close then carries the failure's code (1002 a
//!   protocol error, 1007 a text payload that is not UTF-8, 1009 a message over the ceiling).
//!   The protocol machine judges every frame, text UTF-8 included (as each frame completes); this
//!   framer parses no WebSocket frame of its own (one protocol, one library: the `tungstenite`
//!   family).
//! * The message ceiling is the deployment's body cap, for a whole message and for a single frame.
//!
//! The upgrade INTO this framer is [`WsFramer::adopt`]: another framer gave up the stream with the
//! bytes it held (the upgrade request itself), and this one answers it. Nothing upgrades out of a
//! WebSocket, so the door's `detach` refuses.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::transport::fields::{hop_by_hop, LINE_END, SEPARATOR};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{CloseReason, TransportError, WireStatusClass};

use crate::frame::{Framed, FramerOut, Located, Side};
use tungstenite::client::IntoClientRequest;
use tungstenite::error::ProtocolError;
use tungstenite::handshake::client::ClientHandshake;
use tungstenite::handshake::server::{NoCallback, ServerHandshake};
use tungstenite::handshake::{HandshakeError, MidHandshake};
use tungstenite::http::{HeaderMap, HeaderName, HeaderValue};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::{Bytes, Error as WsError, Message, Utf8Bytes, WebSocket};
use zeroize::Zeroize;

/// The in-memory stream one framing state's protocol machine reads and writes: what core ingested
/// and the machine has not consumed, whether the carrier's clean end followed it, what the
/// machine wrote and core has not been handed yet, and what arrived during the handshake.
#[derive(Default)]
pub(crate) struct Pipe {
    inbound: VecDeque<u8>,
    ended: bool,
    outbound: Vec<u8>,
    /// Every byte ingested while a dial's opening handshake runs: its head's status line (its
    /// reason phrase) and a refused upgrade's first body bytes are read from here. Bounded by the
    /// machine's own handshake limit (64 KiB read, or the handshake fails and the state is gone)
    /// plus what the one call that completes the head carries; emptied once the head is read.
    seen: Vec<u8>,
    /// This end dialled: its frames are masked (RFC 6455 section 5.3). Read only by the test
    /// harness's seed (`test-seeded`), which unmasks a dialled end's frames.
    #[cfg_attr(not(feature = "test-seeded"), allow(dead_code))]
    client: bool,
    /// The open session's text payload as it arrives, judged at the first invalid byte
    /// ([`TextScan`]); `None` until a session that began at a frame boundary is open.
    scan: Option<TextScan>,
}

/// RFC 6455 section 8.1 fails a text message at its first invalid UTF-8 byte, mid-frame (Autobahn
/// 6.4.3, 6.4.4). The protocol library judges a frame only as it completes, so this reads the bytes
/// the session ingests: frame headers by the library's own parser, text payload bytes through
/// `Utf8Error::error_len` (`None` = an incomplete tail, carried to the next bytes; `Some` = invalid).
/// It only ever fails EARLIER than the library would; anything it cannot follow switches it off and
/// the library alone judges. A frame whose header already breaks the protocol (RFC 6455 sections
/// 5.1 to 5.5: masked the wrong way for its side, a reserved bit with no extension, a reserved
/// opcode, a fragment out of order, a fragmented or oversized control frame) is the library's to
/// fail with 1002 as it completes, so the scan switches off at its header and never judges it.
#[derive(Default)]
struct TextScan {
    /// The peer's frames are masked: it is the client (RFC 6455 section 5.3).
    masked: bool,
    /// A fragmented message is under way: the next data frame must continue it.
    in_message: bool,
    /// Header bytes of the frame being read (at most 14), and how many.
    head: [u8; 14],
    head_len: usize,
    /// The payload bytes still to come, the mask, and the next payload byte's index.
    left: u64,
    mask: Option<[u8; 4]>,
    at: usize,
    /// Whether the current frame's payload is text (and its message is).
    text: bool,
    /// Whether the current message (across fragments) is text, and the frame is its last.
    in_text: bool,
    fin: bool,
    /// The incomplete UTF-8 sequence ending the text read so far (at most 3 bytes), and its length.
    tail: [u8; 3],
    tail_len: usize,
    /// An invalid byte was read.
    bad: bool,
    /// Switched off: a header the scan cannot follow, or the peer's Close.
    off: bool,
}

impl TextScan {
    fn feed(&mut self, mut bytes: &[u8]) {
        use tungstenite::protocol::frame::coding::{Control, Data, OpCode};
        use tungstenite::protocol::frame::FrameHeader;
        while !(self.bad || self.off) && !bytes.is_empty() {
            if self.left == 0 {
                self.head[self.head_len] = bytes[0];
                self.head_len += 1;
                bytes = &bytes[1..];
                match FrameHeader::parse(&mut std::io::Cursor::new(&self.head[..self.head_len])) {
                    Ok(None) => continue,
                    Ok(Some((header, len))) => {
                        // Nothing after a Close is data (RFC 6455 section 5.5.1): the scan stops
                        // at one, and the machine reads no further either.
                        if matches!(header.opcode, OpCode::Control(Control::Close)) {
                            self.off = true;
                            continue;
                        }
                        let breaks = header.rsv1
                            || header.rsv2
                            || header.rsv3
                            || header.mask.is_some() != self.masked
                            || match header.opcode {
                                OpCode::Data(Data::Continue) => !self.in_message,
                                OpCode::Data(Data::Text | Data::Binary) => self.in_message,
                                OpCode::Control(Control::Ping | Control::Pong) => {
                                    !header.is_final || len > 125
                                }
                                OpCode::Data(Data::Reserved(_)) | OpCode::Control(_) => true,
                            };
                        if breaks {
                            self.off = true;
                            continue;
                        }
                        if matches!(header.opcode, OpCode::Data(_)) {
                            self.in_message = !header.is_final;
                        }
                        // A fragmented message's kind is its first fragment's; a control frame
                        // between fragments carries no text.
                        match header.opcode {
                            OpCode::Data(Data::Text) => self.in_text = true,
                            OpCode::Data(Data::Continue) => {}
                            _ => {
                                self.in_text =
                                    self.in_text && !matches!(header.opcode, OpCode::Data(_))
                            }
                        }
                        self.text = self.in_text && matches!(header.opcode, OpCode::Data(_));
                        self.fin = header.is_final;
                        self.left = len;
                        self.mask = header.mask;
                        self.at = 0;
                        self.head_len = 0;
                    }
                    Err(_) => self.off = true,
                }
            } else {
                let n = usize::try_from(self.left)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                if self.text {
                    self.read_text(&bytes[..n]);
                }
                self.left -= n as u64;
                bytes = &bytes[n..];
            }
            // A text message that ends inside a sequence is invalid too.
            if self.left == 0 && self.text && self.fin {
                self.bad |= self.tail_len != 0;
                self.in_text = false;
            }
        }
    }

    /// Judge `payload` (masked as the frame is) after the incomplete tail, in stack-sized chunks.
    fn read_text(&mut self, payload: &[u8]) {
        for chunk in payload.chunks(64) {
            let mut buf = [0u8; 67];
            buf[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
            let mut n = self.tail_len;
            for (k, b) in chunk.iter().enumerate() {
                buf[n] = self.mask.map_or(*b, |m| b ^ m[(self.at + k) % 4]);
                n += 1;
            }
            self.at += chunk.len();
            match std::str::from_utf8(&buf[..n]) {
                Ok(_) => self.tail_len = 0,
                Err(e) if e.error_len().is_none() => {
                    self.tail_len = n - e.valid_up_to();
                    self.tail[..self.tail_len].copy_from_slice(&buf[e.valid_up_to()..n]);
                }
                Err(_) => {
                    self.bad = true;
                    return;
                }
            }
        }
    }
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
    /// written before it completes (a text one checked once, as it is held) and the pieces of one
    /// not yet marked complete.
    Dialling {
        mid: MidHandshake<ClientHandshake<Pipe>>,
        held: Vec<Message>,
        message: Vec<u8>,
        /// The message ceiling this framing began under (`0` = none): a refresh after it moves
        /// only framings begun later.
        max: usize,
    },
    /// The session: the protocol machine, the pieces of an outbound message not yet marked
    /// complete, and the failure that ended the inbound frames (its close code), if the far side
    /// broke the protocol or the carrier ended with no closing handshake (`1006`, which the
    /// terminated machine never writes).
    Open {
        ws: Box<WebSocket<Pipe>>,
        message: Vec<u8>,
        failed: Option<CloseCode>,
    },
    /// A dialled connection the far end answered with something other than `101`: its answer's
    /// head was handed up as the stream's head, then its body: `left` bytes of it still to come
    /// (its declared `Content-Length`), or with none declared, every byte until the carrier ends.
    /// At `Some(0)` its frames have ended and nothing more is read. `chunked`: the body's transfer
    /// coding is `chunked` (RFC 9112 §7.1), decoded here and ended at its last chunk; `left` is then
    /// `None` until it ends. With a transfer coding whose final coding is not `chunked`,
    /// `Content-Length` is ignored and the body runs to the carrier's end (RFC 9112 §6.3).
    ///
    /// `short`: the carrier ended before the body did (short of its declared `Content-Length`, or
    /// of its last chunk), or the declared `Content-Length` is not a length or disagrees with
    /// itself (RFC 9110 §8.6), which fails the body at once: the frames end FAILED, not whole
    /// ([`WsFramer::failed`]).
    Answered {
        pipe: Pipe,
        left: Option<u64>,
        chunked: Option<Box<Dechunk>>,
        short: bool,
    },
    /// An accepted connection whose upgrade request was refused: the answer (`400`, or `426` for a
    /// version this end does not speak) went out, the frames ended failed, and whatever still
    /// arrives is nobody's ([`WsFramer::failure`]).
    Refused(Pipe),
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
            Phase::Answered { pipe, .. } | Phase::Refused(pipe) => pipe,
        }
    }
}

/// The most whole messages a dial holds while its handshake has not completed.
pub(crate) const MAX_HELD_MESSAGES: usize = 64;

/// The `ws` framer: its framing states, and the message ceiling every connection is built with.
pub(crate) struct WsFramer {
    /// Every framing state, each behind its own lock: the map's lock is held only to find, add or
    /// remove one, never across a framing's work, so connections run side by side and a panic in
    /// one fails that one alone.
    states: Mutex<HashMap<u64, Conn>>,
    next: AtomicU64,
    /// The message ceiling a framing begun now takes (`0` = the library's default and no outbound
    /// ceiling); a refresh moves it ([`WsFramer::set_max`]), and every framing keeps the one it
    /// began under.
    max_message_bytes: AtomicUsize,
}

impl std::fmt::Debug for WsFramer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsFramer")
            .field("max_message_bytes", &self.max())
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
/// The order of the dialled head, as it is written (tungstenite 0.29 `generate_request`): the
/// request line, then the protocol machine's handshake lines (`Host` from the dialled URL,
/// `Connection`, `Upgrade`, `Sec-WebSocket-Version`, `Sec-WebSocket-Key`), then the plane's
/// opening fields in the request map's own iteration order (`http::HeaderMap`, which does not keep
/// the order the fields were added in), a repeated name's lines together and in their own order;
/// the binding's auth fields arrive among the opening fields (the kernel makes the one outbound
/// auth call before `begin`). The handshake lines lead because the machine writes them
/// (`framer_tests::the_dialled_heads_order_is_pinned` pins it). An opening field of a handshake
/// name is the machine's to write, so it is not copied.
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

/// The answer's head as a field block (`busbar_contract::abi::transport::fields`): the switching
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

/// The status class of a far end's REFUSAL of the upgrade, by its HTTP status. Only `101` completes
/// the handshake (RFC 6455 section 4.1), and it never reaches here: any other answer, a `2xx`
/// included, is a refused upgrade, never a success. A status outside the caller's and the far
/// end's fault bands is `Other`.
fn status_class(code: u16) -> WireStatusClass {
    match code {
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
    if let Some(n) = digits(raw, 10) {
        return Some(n);
    }
    imf_fixdate_secs(raw).map(|at| at.saturating_sub(now_secs))
}

/// `s` as a number in `radix` when it is all digits of it and at least one (RFC 9110's `1*DIGIT`,
/// RFC 9112's `1*HEXDIG`): no sign, no space. An overflowing run is no number either.
fn digits(s: &str, radix: u32) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| char::from(b).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(s, radix).ok()
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
                        .and_then(|t| digits(t.trim(), 16))
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

/// The `Content-Length` an answer declares: `Ok(None)` when it states none, and `Err` when what it
/// states is not a length (RFC 9110 §8.6: `1*DIGIT`) or its values disagree (RFC 9112 §6.3: across
/// lines and across a comma-separated list), which leaves the body's end unknowable.
fn content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let mut declared = None;
    for value in headers.get_all("content-length") {
        for member in value.to_str().map_err(|_| ())?.split(',') {
            let n = digits(member.trim(), 10).ok_or(())?;
            if *declared.get_or_insert(n) != n {
                return Err(());
            }
        }
    }
    Ok(declared)
}

/// A dialled head's REASON PHRASE (HEAD-FIELDS: the dialled side fills `reason`, HTTP/1 as sent):
/// the status line's text after its code, once the line is whole (`HTTP/1.1 401 Unauthorized` →
/// `Unauthorized`); `None` before the line ends, or for a line with no phrase.
pub(crate) fn reason_phrase(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.iter().position(|b| *b == b'\n')?;
    let line = &seen[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.splitn(3, |b| *b == b' ');
    let (_version, _code) = (parts.next()?, parts.next()?);
    parts.next().filter(|r| !r.is_empty()).map(<[u8]>::to_vec)
}

/// Where a response head ends in `seen`: just past its first empty line, which the protocol
/// library's parser takes as a bare `\n` or a `\r\n` alike. `None` while the head is not whole.
fn head_end(seen: &[u8]) -> Option<usize> {
    (0..seen.len()).find_map(|i| {
        if seen[i] != b'\n' {
            return None;
        }
        match seen[i + 1..] {
            [b'\n', ..] => Some(i + 2),
            [b'\r', b'\n', ..] => Some(i + 3),
            _ => None,
        }
    })
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
    out: &mut dyn FramerOut,
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

/// The close code a refusal's neutral status maps to (a neutral status the transport maps to its
/// wire; RFC 6455 §7.4.1): the caller's credential refused or a policy, `1008`; too
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

/// The test harness's seed (`test-seeded`, a dev-dependency feature the published conformance
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
    /// The state is closed.
    pub(crate) fn refusal_with(
        &self,
        state: u64,
        _stream: Option<StreamId>,
        bytes: &[u8],
        status: u32,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        // The refusal is its own message: the pieces of an unfinished outbound message are dropped,
        // not sent glued to its front.
        if let Ok(conn) = self.conn(state) {
            if let Ok(mut guard) = Self::enter(&conn) {
                if let Some(Phase::Open { message, .. } | Phase::Dialling { message, .. }) =
                    guard.as_mut()
                {
                    message.clear();
                }
            }
        }
        let sent = self.emit(state, StreamId(0), bytes, true, false, out);
        self.close_with(state, close_code_of_status(status), out);
        sent
    }

    /// A framer whose messages (and frames) are capped at `max_message_bytes`; `0` = the protocol
    /// library's own default stands.
    #[must_use]
    pub(crate) fn new(max_message_bytes: usize) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            max_message_bytes: AtomicUsize::new(max_message_bytes),
        }
    }

    /// The message ceiling a framing begun now takes.
    fn max(&self) -> usize {
        self.max_message_bytes.load(Ordering::Relaxed)
    }

    /// A refresh's new ceiling: framings begun after it take it; those already begun keep theirs.
    pub(crate) fn set_max(&self, max_message_bytes: usize) {
        self.max_message_bytes
            .store(max_message_bytes, Ordering::Relaxed);
    }

    fn config(&self) -> Option<WebSocketConfig> {
        let max = self.max();
        (max > 0).then(|| {
            WebSocketConfig::default()
                .max_message_size(Some(max))
                .max_frame_size(Some(max))
        })
    }

    /// [`WsFramer::open`], a dialled connection's upgrade request carrying `fields` (the dial's
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
        let phase = self.start(side, target, fields, out)?;
        Ok(self.hold(phase))
    }

    /// [`WsFramer::emit`]: with `text` (the emit's `EMIT_TEXT`) the message goes out as a text
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
        let conn = self.conn(state)?;
        let mut guard = Self::enter(&conn)?;
        if let Some(Phase::Dialling {
            held, message, max, ..
        }) = guard.as_mut()
        {
            let max = *max;
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
                let whole = std::mem::take(message);
                held.push(if text {
                    let text = String::from_utf8(whole).map_err(|_| TransportError::Framing)?;
                    Message::Text(text.into())
                } else {
                    Message::Binary(whole.into())
                });
            }
            return Ok(());
        }
        Self::with_open(guard.as_mut(), out, |ws, message| {
            let max = ws.get_config().max_message_size.unwrap_or(0);
            // The ceiling applies outbound too: the machine bounds only what it reads, so a message this
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

    /// Drop framing `state`, writing nothing: the door's finish of a framing whose op panicked,
    /// which never reached the framer to close it.
    pub(crate) fn forget(&self, state: u64) {
        self.map().remove(&state);
    }

    /// Whether framing `state` is still held: an op that failed with its state alive failed that
    /// op alone, one that left it gone ended the connection.
    pub(crate) fn holds(&self, state: u64) -> bool {
        self.map().contains_key(&state)
    }

    /// How many ingested bytes framing `state` holds unread (a test reads that bytes nobody will
    /// read are not kept).
    #[cfg(test)]
    pub(crate) fn inbound_len(&self, state: u64) -> Option<usize> {
        let conn = self.conn(state).ok()?;
        let mut guard = Self::enter(&conn).ok()?;
        guard.as_mut().map(|phase| phase.pipe().inbound.len())
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
        let config = self.config();
        let max = config
            .as_ref()
            .and_then(|c| c.max_message_size)
            .unwrap_or(0);
        match tungstenite::client::client_with_config(
            request,
            Pipe {
                client: true,
                ..Pipe::default()
            },
            config,
        ) {
            Err(HandshakeError::Interrupted(mid)) => Ok(Phase::Dialling {
                mid,
                held: Vec::new(),
                message: Vec::new(),
                max,
            }),
            Ok(_) | Err(HandshakeError::Failure(_)) => Err(TransportError::HandshakeFailed),
        }
    }

    /// Drive `phase` over what its pipe holds: finish the handshake if it can, then hand every
    /// message it completes up as a frame. Answers whether the connection's frames ended, and a
    /// dialled head's reason phrase the moment that head is handed up.
    fn drive(
        phase: Phase,
        out: &mut dyn FramerOut,
    ) -> Result<(Phase, bool, Option<Vec<u8>>), TransportError> {
        let mut phase = match phase {
            Phase::Answered {
                pipe,
                left,
                chunked,
                ..
            } => {
                let (phase, ended) = answered_body(pipe, left, chunked, false, out);
                return Ok((phase, ended, None));
            }
            // An upgrade request that was refused: what arrives now is nobody's.
            Phase::Refused(mut pipe) => {
                pipe.inbound.clear();
                return Ok((Phase::Refused(pipe), false, None));
            }
            phase => phase,
        };
        let shaking = !matches!(phase, Phase::Open { .. });
        // What the dial's handshake has seen, and whether the carrier ended: the dialled head's
        // reason phrase is read off its status line, and a refusal's body is every byte past the
        // head (the machine reads the wire in chunks and keeps what it read; what it did not read
        // is still here). Taken out of the pipe, never copied, and put back while the head is not
        // whole: it is read only on the call that completes the head.
        let shaken = match &mut phase {
            Phase::Dialling { mid, .. } => {
                let pipe = mid.get_mut().get_mut();
                Some((std::mem::take(&mut pipe.seen), pipe.ended))
            }
            _ => None,
        };
        // The dialled head's reason phrase (the dialled side fills `reason`, as the far end sent
        // it), set on the call that hands the head up.
        let mut reason = None;
        let mut phase = match phase {
            Phase::Accepting(mid) => match mid.handshake() {
                Ok(mut ws) => {
                    // The machine refuses any byte after the request (the client waits for the
                    // answer), so the session starts at a frame boundary: the text scan follows
                    // its frames from the next call on.
                    let pipe = ws.get_mut();
                    pipe.seen = Vec::new();
                    pipe.scan = Some(TextScan {
                        masked: true,
                        ..TextScan::default()
                    });
                    Phase::open(ws, Vec::new())
                }
                Err(HandshakeError::Interrupted(mid)) => {
                    return Ok((Phase::Accepting(mid), false, None))
                }
                // A request that is not an upgrade this end accepts is ANSWERED (RFC 6455 4.2.1:
                // 400; a version it does not speak, 4.4: 426 naming the one it does), and the
                // connection's frames end failed. A request still incomplete, or a carrier that
                // broke, has no request to answer.
                Err(HandshakeError::Failure(e)) => {
                    if matches!(
                        e,
                        WsError::Protocol(ProtocolError::HandshakeIncomplete) | WsError::Io(_)
                    ) {
                        return Err(TransportError::HandshakeFailed);
                    }
                    let answer: &[u8] = if matches!(
                        e,
                        WsError::Protocol(ProtocolError::MissingSecWebSocketVersionHeader)
                    ) {
                        b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    } else {
                        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    };
                    out.send(answer);
                    return Ok((Phase::Refused(Pipe::default()), true, None));
                }
            },
            Phase::Dialling {
                mid,
                held,
                message,
                max,
            } => match mid.handshake() {
                Ok((mut ws, response)) => {
                    // The far end answered: its switching response is the stream's
                    // head, handed up before anything else, with its status and its field block.
                    // A far end that answered the upgrade and sends nothing more has answered.
                    let block = head_block(response.headers());
                    out.frame(Framed {
                        status: Some(WireStatusClass::Success),
                        status_code: Some(u32::from(response.status().as_u16())),
                        ..Framed::plain(StreamId(0), &block, true)
                    });
                    reason = shaken.as_ref().and_then(|(seen, _)| reason_phrase(seen));
                    for m in held {
                        ws.write(m).map_err(|e| read_error(&e))?;
                    }
                    // The far end may send its first frames with the head: the session starts at a
                    // frame boundary, and the text scan follows its frames from the next call on,
                    // only when the head ended exactly at the last byte seen (a call that merely
                    // ENDS like a head may end inside a frame's payload).
                    let pipe = ws.get_mut();
                    let seen = shaken.as_ref().map_or(&[][..], |(seen, _)| seen.as_slice());
                    if head_end(seen) == Some(seen.len()) {
                        pipe.scan = Some(TextScan::default());
                    }
                    pipe.seen = Vec::new();
                    Phase::open(ws, message)
                }
                Err(HandshakeError::Interrupted(mut mid)) => {
                    mid.get_mut().get_mut().seen = shaken.map(|(seen, _)| seen).unwrap_or_default();
                    return Ok((
                        Phase::Dialling {
                            mid,
                            held,
                            message,
                            max,
                        },
                        false,
                        None,
                    ))
                }
                // The far end refused the upgrade (the head is always the first fields piece): its
                // answer is handed up as ONE head with its status, its class and
                // its fields, then its body (a far end's error document), and the frames end, so the
                // breaker reads what it answered and the plane sees what it said. The body is every
                // byte past the head (what came with it, then what still arrives) up to its declared
                // `Content-Length`, or with none declared until the carrier ends, unless its
                // transfer coding is `chunked`, which frames it instead (decoded, to its last
                // chunk; RFC 9112 §6.3). With a transfer coding whose final coding is not `chunked`,
                // `Content-Length` is ignored and the body runs to the carrier's end (§6.3); a
                // `Content-Length` that is not a length or disagrees fails the body at once (RFC 9110
                // §8.6); then the frames end.
                Err(HandshakeError::Failure(WsError::Http(response))) => {
                    let reason = shaken.as_ref().and_then(|(seen, _)| reason_phrase(seen));
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
                    let at = head_end(&seen).unwrap_or(seen.len());
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
                    // A transfer coding that does not end in `chunked` leaves the body to the carrier's
                    // end, whatever `Content-Length` says (RFC 9112 §6.3).
                    let declared = if bodiless {
                        Ok(Some(0))
                    } else if chunked.is_some()
                        || response.headers().contains_key("transfer-encoding")
                    {
                        Ok(None)
                    } else {
                        content_length(response.headers())
                    };
                    let Ok(declared) = declared else {
                        // A length that is invalid or in conflict: the body is failed at once.
                        out.frame(Framed::plain(StreamId(0), &[], true));
                        let mut pipe = pipe;
                        pipe.inbound.clear();
                        let phase = Phase::Answered {
                            pipe,
                            left: Some(0),
                            chunked: None,
                            short: true,
                        };
                        return Ok((phase, true, reason));
                    };
                    let (phase, ended) = answered_body(pipe, declared, chunked, true, out);
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
                // ends here, FAILED: the connection was not closed cleanly (RFC 6455 sections
                // 7.1.4, 7.1.5: close code 1006, which no frame ever carries), so the layer above
                // can tell a cut stream from a finished one. It is the connection going away, not
                // a protocol the far side broke, and the machine, terminated, writes no close.
                Err(WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => {
                    *failed = Some(CloseCode::Abnormal);
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
        // Text that turned invalid before its frame completed fails the connection now (RFC 6455
        // section 8.1), as the library fails it when the frame does.
        if failed.is_none() && ws.get_ref().scan.as_ref().is_some_and(|scan| scan.bad) {
            *failed = Some(CloseCode::Invalid);
        }
        if failed.is_some() {
            ended = true;
        }
        if ended {
            // The frames ended (the peer's close, the connection gone, or a failure): the machine
            // reads no more, so what is still in `inbound`, and what arrives later, is nobody's.
            ws.get_mut().inbound.clear();
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
    /// not UTF-8, a message over the ceiling, a carrier end with no closing handshake), an upgrade
    /// request this end refused, or a refused
    /// upgrade's body was cut short by the carrier's end or declared a `Content-Length` that is not
    /// a length or disagrees (RFC 9110 §8.6): its frames ended failed, not cleanly.
    #[cfg(test)]
    pub(crate) fn failed(&self, state: u64) -> bool {
        self.failure(state).is_some()
    }

    /// Why the frames of `state` ended failed ([`Self::failed`]), in words for the end piece.
    pub(crate) fn failure(&self, state: u64) -> Option<&'static str> {
        let conn = self.conn(state).ok()?;
        let held = Self::enter(&conn).ok()?;
        match held.as_ref()? {
            Phase::Open {
                failed: Some(code), ..
            } => Some(match code {
                CloseCode::Invalid => "the far end sent a text message that is not UTF-8",
                CloseCode::Size => "the far end sent a message over the message ceiling",
                CloseCode::Abnormal => "the carrier ended with no WebSocket closing handshake",
                _ => "the far end broke the WebSocket protocol",
            }),
            Phase::Answered { short: true, .. } => {
                Some("the far end's answer body was cut short or declared no valid length")
            }
            Phase::Refused(_) => {
                Some("the upgrade request is not a WebSocket opening handshake this end can accept")
            }
            _ => None,
        }
    }
}

impl Default for WsFramer {
    fn default() -> Self {
        Self::new(0)
    }
}

/// The framer's ops, as the door calls them (`door`): every op answers at once, and nothing here
/// reads a socket or a clock.
impl WsFramer {
    /// A `ws://` target is reached at its `host:port`; a `wss://` one asks for its bytes to be
    /// secured before they leave, and names the host its certificate is checked against.
    pub(crate) fn locate(&self, target: &str) -> Result<Located, TransportError> {
        let (secure, host, port, _path) = split_ws_url(target)?;
        Ok(Located {
            authority: format!("{}:{port}", authority_host(&host)),
            secure,
            server_name: secure.then_some(host),
        })
    }

    pub(crate) fn open(
        &self,
        side: Side,
        target: &str,
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        self.open_with(side, target, &[], out)
    }

    pub(crate) fn ingest(
        &self,
        state: u64,
        bytes: &[u8],
        end: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.ingest_head(state, bytes, end, out).map(drop)
    }

    /// [`WsFramer::ingest`], answering the reason phrase of the head this call handed up (a dialled
    /// framing's, HTTP/1 as sent) for the door's head slots.
    pub(crate) fn ingest_head(
        &self,
        state: u64,
        bytes: &[u8],
        end: bool,
        out: &mut dyn FramerOut,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let conn = self.conn(state)?;
        let mut held = Self::enter(&conn)?;
        let mut phase = held.take().ok_or(TransportError::Closed)?;
        let dialling = matches!(phase, Phase::Dialling { .. });
        let pipe = phase.pipe();
        pipe.inbound.extend(bytes);
        pipe.ended |= end;
        let was_open = matches!(phase, Phase::Open { .. });
        let pipe = phase.pipe();
        if let Some(scan) = pipe.scan.as_mut().filter(|_| was_open) {
            scan.feed(bytes);
        }
        // Only a dialled head is read back off what the handshake saw (its reason phrase, a
        // refusal's body); an accepting handshake keeps no copy.
        if dialling {
            pipe.seen.extend_from_slice(bytes);
        }
        match Self::drive(phase, out) {
            Ok((mut phase, ended, reason)) => {
                drain(&mut phase, out);
                if ended {
                    out.end();
                }
                *held = Some(phase);
                Ok(reason)
            }
            // A failed state is gone: its connection has nothing more to say.
            Err(e) => {
                drop(held);
                self.map().remove(&state);
                Err(e)
            }
        }
    }

    pub(crate) fn emit(
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

    pub(crate) fn close(&self, state: u64, reason: CloseReason, out: &mut dyn FramerOut) {
        self.close_with(state, close_code_for(reason), out);
    }

    /// A WebSocket state keeps no deadline of its own (it never states one), so a tick finds nothing
    /// due; an unknown state is closed.
    pub(crate) fn tick(&self, state: u64, _out: &mut dyn FramerOut) -> Result<(), TransportError> {
        if self.map().contains_key(&state) {
            Ok(())
        } else {
            Err(TransportError::Closed)
        }
    }

    /// The upgrade into this framer: the stream another framer gave up, with the bytes it held —
    /// the upgrade request itself, on the accepting side — which this one answers.
    pub(crate) fn adopt(
        &self,
        side: Side,
        leftover: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        let state = self.open(side, "", out)?;
        self.ingest(state, leftover, false, out)?;
        Ok(state)
    }
}
