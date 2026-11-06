// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `ws` framer the door drives (`crate::door`, the memory-ABI framer door, linked into a
//! busbar build or exported by the sibling `busbar-transport-ws-plugin` cdylib).

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
use tungstenite::handshake::client::{ClientHandshake, Response as UpgradeResponse};
use tungstenite::handshake::machine::{HandshakeMachine, RoundResult, StageResult};
use tungstenite::handshake::server::{NoCallback, Request as UpgradeRequest, ServerHandshake};
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
    /// Consumed informational heads, compacted once per crossing rather than once per head.
    head_at: usize,
    /// Original Connection values when only the library's response validator needed normalization.
    response_connection: Option<Vec<HeaderValue>>,
    /// Capture only the accepted request parser's bounded reads, including its read-ahead tail.
    record_request: bool,
    /// The test harness's seed is on for this dialled end (`test-seeded`): its frames go out under
    /// the all-zero mask ([`seeded::unmask`]).
    #[cfg(feature = "test-seeded")]
    seeded: bool,
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
    close: bool,
    close_code: [u8; 2],
    bad_close: bool,
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
                        let breaks = header.rsv1
                            || header.rsv2
                            || header.rsv3
                            || header.mask.is_some() != self.masked
                            || match header.opcode {
                                OpCode::Data(Data::Continue) => !self.in_message,
                                OpCode::Data(Data::Text | Data::Binary) => self.in_message,
                                OpCode::Control(Control::Ping | Control::Pong | Control::Close) => {
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

                        match header.opcode {
                            OpCode::Data(Data::Text) => self.in_text = true,
                            OpCode::Data(Data::Continue) => {}
                            _ => {
                                self.in_text =
                                    self.in_text && !matches!(header.opcode, OpCode::Data(_))
                            }
                        }
                        self.text = self.in_text && matches!(header.opcode, OpCode::Data(_));
                        self.close = matches!(header.opcode, OpCode::Control(Control::Close));
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
                } else if self.close {
                    for &byte in bytes[..n].iter().take(2usize.saturating_sub(self.at)) {
                        self.close_code[self.at] =
                            byte ^ self.mask.map_or(0, |mask| mask[self.at % 4]);
                        self.at += 1;
                    }
                    if self.at == 2 {
                        self.bad_close =
                            !CloseCode::from(u16::from_be_bytes(self.close_code)).is_allowed();
                        self.off = true;
                    }
                }
                self.left -= n as u64;
                bytes = &bytes[n..];
            }

            if self.left == 0 && self.text && self.fin {
                self.bad |= self.tail_len != 0;
                self.in_text = false;
            }
            if self.left == 0 && self.close {
                self.off = true;
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
        if self.record_request {
            self.seen.extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }
}

impl Drop for Pipe {
    /// The recorded upgrade head can carry credentials (Authorization, Cookie); wipe it, and the
    /// buffered bytes beside it, however the machine holding this pipe ends.
    fn drop(&mut self) {
        self.seen.zeroize();
        // Consumed bytes stay in the ring's spare capacity: wipe the whole allocation.
        let mut inbound: Vec<u8> = std::mem::take(&mut self.inbound).into();
        inbound.zeroize();
        self.outbound.zeroize();
    }
}

impl Pipe {
    fn discard_heads(&mut self) {
        if self.head_at != 0 {
            let remaining = self.seen.split_off(self.head_at);
            self.seen.zeroize();
            self.seen = remaining;
            self.head_at = 0;
        }
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
    /// An accepted connection waiting for (the rest of) the upgrade request, and the
    /// message ceiling it began under (`0` = none).
    Accepting {
        mid: MidHandshake<ServerHandshake<Pipe, NoCallback>>,
        request: Option<HandshakeMachine<Pipe>>,
        max: usize,
    },
    /// A dialled connection waiting for (the rest of) the upgrade response, with the
    /// messages written before it completes (a text one checked once, as it is held) and
    /// the pieces of one not yet marked complete.
    Dialling {
        mid: MidHandshake<ClientHandshake<Pipe>>,
        response: Option<HandshakeMachine<Pipe>>,
        held: Vec<Message>,
        message: Vec<u8>,
        /// The message ceiling this framing began under (`0` = none): a refresh after
        /// it moves only framings begun later.
        max: usize,
    },
    /// The session: the protocol machine, the pieces of an outbound message not yet marked
    /// complete, the message ceiling the framing began under (`0` = none: the library's
    /// inbound default stands, and nothing bounds what this end writes), and the failure
    /// that ended the inbound frames (its close code), if the far side broke the protocol
    /// or the carrier ended with no closing handshake (`1006`, which the terminated machine
    /// never writes).
    Open {
        ws: Box<WebSocket<Pipe>>,
        message: Vec<u8>,
        max: usize,
        failed: Option<CloseCode>,
    },
    /// A dialled connection the far end answered with something other than `101`: its
    /// answer's head was handed up as the stream's head, then its body: `left` bytes of it
    /// still to come (its declared `Content-Length`), or with none declared, every byte
    /// until the carrier ends.
    Answered {
        pipe: Pipe,
        left: Option<u64>,
        chunked: Option<Box<Dechunk>>,
        short: bool,
    },
    /// An accepted connection whose upgrade request was refused: the answer (`400`, or
    /// `426` for a version this end does not speak) went out, the frames ended failed, and
    /// whatever still arrives is nobody's ([`WsFramer::failure`]).
    Refused(Pipe),
}

impl Phase {
    fn input(&mut self) -> &mut Pipe {
        match self {
            Phase::Accepting {
                request: Some(parser),
                ..
            } => parser.get_mut(),
            Phase::Dialling {
                response: Some(parser),
                ..
            } => parser.get_mut(),
            other => other.pipe(),
        }
    }

    /// The session over `ws`, its outbound message starting as `message`, under the ceiling `max`.
    fn open(ws: WebSocket<Pipe>, message: Vec<u8>, max: usize) -> Self {
        Phase::Open {
            ws: Box::new(ws),
            message,
            max,
            failed: None,
        }
    }
}

impl Phase {
    fn pipe(&mut self) -> &mut Pipe {
        match self {
            Phase::Accepting { mid, .. } => mid.get_mut().get_mut(),
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
    /// Every framing state, each behind its own lock: the map's lock is held only to find,
    /// add or remove one, never across a framing's work, so connections run side by side
    /// and a panic in one fails that one alone.
    states: Mutex<HashMap<u64, Conn>>,
    next: AtomicU64,
    /// The message ceiling a framing begun now takes (`0` = the library's default and no
    /// outbound ceiling); a refresh moves it ([`WsFramer::set_max`]), and every framing
    /// keeps the one it began under.
    max_message_bytes: AtomicUsize,
    /// The test harness's seed is on for this framer's dials (`test-seeded`; [`seeded`]).
    #[cfg(feature = "test-seeded")]
    seeded: bool,
}

impl std::fmt::Debug for WsFramer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsFramer")
            .field("max_message_bytes", &self.max())
            .finish_non_exhaustive()
    }
}

/// The RFC 6455 close code a [`CloseReason`] puts on the wire.
pub(crate) fn close_code_for(reason: CloseReason) -> CloseCode {
    match reason {
        CloseReason::Normal | CloseReason::PeerClosed => CloseCode::Normal,
        CloseReason::Drain => CloseCode::Restart,
        CloseReason::Poisoned => CloseCode::Error,
        CloseReason::Revoked => CloseCode::Policy,
        CloseReason::Timeout => CloseCode::Again,
        CloseReason::TransportFailed => CloseCode::Protocol,
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
/// WebSocket are a framing failure, a finished closing handshake is the end, anything else is
/// the connection going away underneath.
fn read_error(e: &WsError) -> TransportError {
    match e {
        WsError::Protocol(_) | WsError::Capacity(_) | WsError::Utf8(_) => TransportError::Framing,
        WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::Closed,
        _ => TransportError::Reset,
    }
}

/// The fields an opening field may not set on the upgrade request: `host`, `connection` and
/// `upgrade`, which the handshake writes itself, and `content-length` and `transfer-encoding`,
/// which the machine never writes and which would frame a body the upgrade request does not
/// have (a plane's `Content-Length` must not ride it).
const HANDSHAKE_FIELDS: &[&str] = &[
    "host",
    "connection",
    "upgrade",
    "content-length",
    "transfer-encoding",
];

/// The one `sec-websocket-*` field that is the layer above's and not this hop's: the subprotocols.
const SUBPROTOCOL: &str = "sec-websocket-protocol";

/// Whether a field rides between this hop and the layer above: an opening field onto the
/// upgrade request, or an answer's field into the head handed up ([`head_block`]).
fn rides_upgrade(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !HANDSHAKE_FIELDS.contains(&lower.as_str())
        && (lower == SUBPROTOCOL || !lower.starts_with("sec-websocket-"))
}

/// Whether every opening field that rides the upgrade request ([`rides_upgrade`]) can be
/// written on it: a valid HTTP field name, and a value with no line break or disallowed control byte.
pub(crate) fn carries_all(fields: &[(String, Vec<u8>)]) -> bool {
    fields
        .iter()
        .filter(|(name, _)| rides_upgrade(name))
        .all(|(name, value)| {
            HeaderName::from_bytes(name.as_bytes()).is_ok()
                && value
                    .iter()
                    .all(|&byte| byte >= 32 && byte != 127 || byte == b'\t')
        })
}

/// Whether a dial's opening `fields` ask for a WebSocket extension (`Sec-WebSocket-Extensions`):
/// this end negotiates none (RFC 6455 section 9), so such a dial is refused, never sent without it.
pub(crate) fn asks_extension(fields: &[(String, Vec<u8>)]) -> bool {
    fields
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-extensions"))
}

/// The answer's validated head as a field block, in its original wire order.
fn head_block(headers: &HeaderMap, seen: &[u8]) -> Result<Vec<u8>, TransportError> {
    let nominated: Vec<&[u8]> = headers
        .get_all("connection")
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let head = status_line_start(seen);
    let first_line = head
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(TransportError::HandshakeFailed)?;
    let mut occurrences = HashMap::<HeaderName, usize>::new();
    let mut block = Vec::new();
    for line in head[first_line + 1..].split(|byte| *byte == b'\n') {
        if line.is_empty() || line == b"\r" {
            break;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(TransportError::HandshakeFailed)?;
        let name =
            HeaderName::from_bytes(&line[..colon]).map_err(|_| TransportError::HandshakeFailed)?;
        let occurrence = occurrences.entry(name.clone()).or_default();
        let value = headers
            .get_all(&name)
            .iter()
            .nth(*occurrence)
            .ok_or(TransportError::HandshakeFailed)?;
        *occurrence += 1;
        let name = name.as_str();
        if !rides_upgrade(name) || hop_by_hop(name, nominated.iter().copied()) {
            continue;
        }
        block.extend_from_slice(name.as_bytes());
        block.extend_from_slice(SEPARATOR);
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(LINE_END);
    }
    Ok(block)
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

/// The status class of a far end's REFUSAL of the upgrade, by its HTTP status.
fn status_class(code: u16) -> WireStatusClass {
    match code {
        400..=499 => WireStatusClass::CallerFault,
        500..=599 => WireStatusClass::FarEndFault,
        _ => WireStatusClass::Other,
    }
}

/// The `Retry-After` an answer states, in whole seconds from `now_secs` (Unix seconds), in
/// either of RFC 9110's forms, as the http framer reads it: `delay-seconds`, or an HTTP-date (any
/// of its three forms) converted to the seconds left until it (`0` once past).
pub(crate) fn retry_after(headers: &HeaderMap, now_secs: u64) -> Option<u64> {
    let raw = headers.get("retry-after")?.to_str().ok()?.trim();
    if let Some(n) = digits(raw, 10) {
        return Some(n);
    }
    imf_fixdate_secs(raw).map(|at| at.saturating_sub(now_secs))
}

/// `s` as a number in `radix` when it is all digits of it and at least one (RFC 9110's
/// `1*DIGIT`, RFC 9112's `1*HEXDIG`): no sign, no space.
fn digits(s: &str, radix: u32) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| char::from(b).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(s, radix).ok()
}

/// An HTTP-date (RFC 9110 5.6.7: the IMF-fixdate, and the two obsolete forms a recipient must
/// accept) as Unix seconds, read by `httpdate`, which accepts all three forms.
fn imf_fixdate_secs(s: &str) -> Option<u64> {
    httpdate::parse_http_date(s)
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Validate the complete transfer-coding sequence before publishing decoded body bytes.
/// This framer decodes only a single chunked coding. Removing Transfer-Encoding while
/// leaving another coding applied would misrepresent the payload handed to the host.
fn transfer_chunked(headers: &HeaderMap) -> Result<bool, TransportError> {
    let mut chunked = false;
    for value in headers.get_all("transfer-encoding") {
        let value = value.to_str().map_err(|_| TransportError::Framing)?;
        for coding in value.split(',') {
            if chunked || !coding.trim().eq_ignore_ascii_case("chunked") {
                return Err(TransportError::Framing);
            }
            chunked = true;
        }
    }
    Ok(chunked)
}

/// The longest chunk-size or trailer line a refused upgrade's chunked body may carry; a longer
/// one is malformed, and the frames end there.
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
    /// Decode what `inbound` holds into `body`; `Some(whole)` once nothing more is read:
    /// `true` at its last chunk and trailers, `false` at a malformed coding.
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

/// The `Content-Length` an answer declares: `Ok(None)` when it states none, and `Err` when what
/// it states is not a length (RFC 9110 §8.6: `1*DIGIT`) or its values disagree (RFC 9112 §6.3:
/// across lines and across a comma-separated list), which leaves the body's end unknowable.
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
    let seen = status_line_start(seen);
    let end = seen.iter().position(|b| *b == b'\n')?;
    let line = &seen[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.splitn(3, |b| *b == b' ');
    let (_version, _code) = (parts.next()?, parts.next()?);
    parts.next().filter(|r| !r.is_empty()).map(<[u8]>::to_vec)
}

/// httparse accepts leading empty lines before a response's status line.
fn status_line_start(mut seen: &[u8]) -> &[u8] {
    loop {
        if let Some(rest) = seen.strip_prefix(b"\r\n") {
            seen = rest;
        } else if let Some(rest) = seen.strip_prefix(b"\n") {
            seen = rest;
        } else {
            return seen;
        }
    }
}

/// Where a response head ends in `seen`: just past its first empty line, which the protocol
/// library's parser takes as a bare `\n` or a `\r\n` alike.
fn head_end(seen: &[u8]) -> Option<usize> {
    let head = status_line_start(seen);
    let skipped = seen.len() - head.len();
    (0..head.len()).find_map(|i| {
        if head[i] != b'\n' {
            return None;
        }
        match head[i + 1..] {
            [b'\n', ..] => Some(skipped + i + 2),
            [b'\r', b'\n', ..] => Some(skipped + i + 3),
            _ => None,
        }
    })
}

/// The library currently compares the whole Connection value with Upgrade.
fn normalized_response(response: &UpgradeResponse, seen: &[u8]) -> Option<Vec<u8>> {
    let values: Vec<_> = response.headers().get_all("connection").iter().collect();
    if values.len() == 1 && values[0].as_bytes().eq_ignore_ascii_case(b"Upgrade") {
        return None;
    }
    if !values.iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"Upgrade"))
    }) {
        return None;
    }
    let start = status_line_start(seen);
    let line = start.get(..start.iter().position(|byte| *byte == b'\n')?)?;
    let mut normalized = Vec::with_capacity(seen.len());
    normalized.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
    normalized.extend_from_slice(b"\r\nConnection: Upgrade\r\n");
    for (name, value) in response.headers() {
        if name == "connection" {
            continue;
        }
        normalized.extend_from_slice(name.as_str().as_bytes());
        normalized.extend_from_slice(b": ");
        normalized.extend_from_slice(value.as_bytes());
        normalized.extend_from_slice(b"\r\n");
    }
    normalized.extend_from_slice(b"\r\n");
    normalized.extend_from_slice(seen.get(head_end(seen)?..)?);
    Some(normalized)
}

/// The values of a repeated field joined with `, ` in order (RFC 9110 5.3); `None` unless the field
/// appears at least twice.
fn joined_values(headers: &HeaderMap, name: &str) -> Option<Vec<u8>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    let second = values.next()?;
    let mut joined = first.as_bytes().to_vec();
    for value in [second].into_iter().chain(values) {
        joined.extend_from_slice(b", ");
        joined.extend_from_slice(value.as_bytes());
    }
    Some(joined)
}

/// RFC 9110 combines repeated Connection fields into one ordered token list.
fn normalized_request(request: &UpgradeRequest, seen: &[u8]) -> Option<Vec<u8>> {
    let joined = joined_values(request.headers(), "connection")?;
    let mut normalized = Vec::with_capacity(seen.len());
    let mut inserted = false;
    for line in seen.split_inclusive(|byte| *byte == b'\n') {
        if line
            .iter()
            .position(|byte| *byte == b':')
            .is_some_and(|at| line[..at].eq_ignore_ascii_case(b"connection"))
        {
            if !inserted {
                normalized.extend_from_slice(b"Connection: ");
                normalized.extend_from_slice(&joined);
                normalized.extend_from_slice(b"\r\n");
                inserted = true;
            }
        } else {
            normalized.extend_from_slice(line);
        }
    }
    Some(normalized)
}

/// Validate required opening fields that the protocol library only checks for presence.
pub(crate) fn valid_opening_fields(request: &UpgradeRequest) -> bool {
    let mut hosts = request.headers().get_all("host").iter();
    let Some(host) = hosts.next() else {
        return false;
    };
    let host = host.as_bytes().trim_ascii();
    if hosts.next().is_some() || host.is_empty() || host.iter().any(u8::is_ascii_whitespace) {
        return false;
    }
    let mut keys = request.headers().get_all("sec-websocket-key").iter();
    let Some(key) = keys.next() else {
        return false;
    };
    let key = key.as_bytes().trim_ascii();
    keys.next().is_none()
        && key.len() == 24
        && key.ends_with(b"==")
        && key[..22]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/".contains(byte))
        && b"AQgw".contains(&key[21])
}

/// The refusal the accept path would give an opening after admission: `None` when acceptable,
/// `Some(true)` for the 426 (unsupported version), `Some(false)` for any other 400. It runs the
/// same checks the legacy path does: repeated Connection fields joined, then the library's.
pub(crate) fn opening_refusal(request: &UpgradeRequest) -> Option<bool> {
    let mut copy = request.clone();
    if let Some(joined) = joined_values(request.headers(), "connection") {
        let joined = HeaderValue::from_bytes(&joined).ok()?;
        copy.headers_mut().insert("connection", joined);
    }
    match tungstenite::handshake::server::create_response(&copy) {
        Ok(_) => None,
        Err(WsError::Protocol(ProtocolError::MissingSecWebSocketVersionHeader)) => Some(true),
        Err(_) => Some(false),
    }
}

/// Answer a malformed accepted upgrade with the same refusal as the server handshake machine.
fn refused_upgrade(
    error: WsError,
    out: &mut dyn FramerOut,
) -> Result<(Phase, bool, Option<Vec<u8>>), TransportError> {
    if matches!(
        error,
        WsError::Protocol(ProtocolError::HandshakeIncomplete) | WsError::Io(_)
    ) {
        return Err(TransportError::HandshakeFailed);
    }
    Ok(refused_opening(
        matches!(
            error,
            WsError::Protocol(ProtocolError::MissingSecWebSocketVersionHeader)
        ),
        out,
    ))
}

fn refused_opening(
    unsupported_version: bool,
    out: &mut dyn FramerOut,
) -> (Phase, bool, Option<Vec<u8>>) {
    let answer: &[u8] = if unsupported_version {
        b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nUpgrade: websocket\r\nConnection: Upgrade, close\r\nContent-Length: 0\r\n\r\n"
    } else {
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    };
    out.send(answer);
    (Phase::Refused(Pipe::default()), true, None)
}

/// A refused upgrade's BODY: frame what the pipe holds, decoded by its transfer coding when it
/// is `chunked` (to its last chunk), otherwise up to the `left` bytes its declared
/// `Content-Length` still owes (or, with none declared, until the carrier ends), and end the
/// frames once they are all handed up or the carrier ended.
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

/// The close code a refusal's neutral status maps to (a neutral status the transport maps to
/// its wire; RFC 6455 §7.4.1): the caller's credential refused or a policy, `1008`; too big,
/// `1009`; throttled or unavailable, `1013` (try again later); another server failure, `1011`;
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
        if open && pipe.seeded {
            seeded::unmask(&mut pipe.outbound);
        }
        out.send(&pipe.outbound);
        pipe.outbound.clear();
    }
}

/// The test harness's seed (`test-seeded`, a dev-dependency feature the published conformance
/// suite builds with; never in a shipped build, where the handshake key and every frame's mask
/// stay random as RFC 6455 section 5.3 requires): a dial's handshake key is fixed, and a
/// dialled end's frames carry the all-zero mask, so the bytes a scripted dial writes are the
/// same every run.
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
    /// Close `state` with `code` (a connection the far side failed closes with the
    /// failure's code instead), handing what the machine wrote to core, and forget it.
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
            let _ = ws.close(Some(CloseFrame {
                code: failed.unwrap_or(code),
                reason: "".into(),
            }));
            let _ = ws.flush();
        }
        drain(&mut phase, out);
    }

    /// The refusal `bytes`, closing the connection after it; `status` is the refusal's
    /// neutral status (`RefuseIn::status`, `0` = none stated).
    pub(crate) fn refusal_with(
        &self,
        state: u64,
        bytes: &[u8],
        status: u32,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        if let Ok(conn) = self.conn(state) {
            if let Ok(mut guard) = Self::enter(&conn) {
                if let Some(Phase::Open { message, .. } | Phase::Dialling { message, .. }) =
                    guard.as_mut()
                {
                    message.clear();
                }
            }
        }
        let sent = self.emit(state, bytes, true, false, out);
        self.close_with(state, close_code_of_status(status), out);
        sent?;
        out.end();
        Ok(())
    }

    /// A framer whose messages (and frames) are capped at `max_message_bytes`; `0` = the
    /// protocol library's own default stands for what is read, and nothing bounds what is
    /// written.
    #[must_use]
    pub(crate) fn new(max_message_bytes: usize) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            max_message_bytes: AtomicUsize::new(max_message_bytes),
            #[cfg(feature = "test-seeded")]
            seeded: true,
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

    /// [`WsFramer::open`], a dialled connection's upgrade request carrying `fields` (the
    /// dial's opening head fields, `BeginIn::fields`).
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

    /// [`WsFramer::emit`]: with `text` (the emit's `EMIT_TEXT`) the message goes out as a
    /// text message, under the TEXT opcode, which promises UTF-8 (RFC 6455 §8.1): bytes
    /// that are not fail the write rather than go out under a promise they break.
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

            let over = max > 0 && message.len().saturating_add(bytes.len()) > max;
            if over || (end_of_frame && held.len() >= MAX_HELD_MESSAGES) {
                message.clear();
                return Err(TransportError::Framing);
            }
            message.extend_from_slice(bytes);
            if end_of_frame {
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
        Self::with_open(guard.as_mut(), out, |ws, message, max| {
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

    /// The map of framing states.
    fn map(&self) -> MutexGuard<'_, HashMap<u64, Conn>> {
        self.states.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drop framing `state`, writing nothing: the door's finish of a framing whose op
    /// panicked, which never reached the framer to close it.
    pub(crate) fn forget(&self, state: u64) {
        self.map().remove(&state);
    }

    /// Whether framing `state` is still held: an op that failed with its state alive failed
    /// that op alone, one that left it gone ended the connection.
    pub(crate) fn holds(&self, state: u64) -> bool {
        self.map().contains_key(&state)
    }

    /// Whether this framing completed its accepted WebSocket handshake.
    pub(crate) fn accepted(&self, state: u64) -> bool {
        let Ok(conn) = self.conn(state) else {
            return false;
        };
        let Ok(held) = Self::enter(&conn) else {
            return false;
        };
        matches!(held.as_ref(), Some(Phase::Open { .. }))
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
                let config = self.config();
                let max = config
                    .as_ref()
                    .and_then(|c| c.max_message_size)
                    .unwrap_or(0);
                match tungstenite::accept_with_config(Pipe::default(), config) {
                    Err(HandshakeError::Interrupted(mid)) => Phase::Accepting {
                        mid,
                        request: Some(HandshakeMachine::start_read({
                            let mut pipe = Pipe::default();
                            pipe.record_request = true;
                            pipe
                        })),
                        max,
                    },

                    Ok(_) | Err(HandshakeError::Failure(_)) => {
                        return Err(TransportError::HandshakeFailed)
                    }
                }
            }
            Side::Dial => self.dial(target, fields)?,
        };
        drain(&mut phase, out);

        phase.pipe().outbound.zeroize();
        Ok(phase)
    }

    /// A dial's upgrade request, built and written into its pipe and not yet handed out:
    /// the protocol machine's handshake lines, then `fields` ([`rides_upgrade`]'s).
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

        let protocols: Vec<_> = request.headers().get_all(SUBPROTOCOL).iter().collect();
        if protocols.len() > 1 {
            let mut joined = Vec::new();
            for value in protocols {
                if !joined.is_empty() {
                    joined.extend_from_slice(b", ");
                }
                joined.extend_from_slice(value.as_bytes());
            }
            let joined =
                HeaderValue::from_bytes(&joined).map_err(|_| TransportError::HandshakeFailed)?;
            request.headers_mut().insert(SUBPROTOCOL, joined);
        }
        #[cfg(feature = "test-seeded")]
        if self.seeded {
            request
                .headers_mut()
                .insert("sec-websocket-key", HeaderValue::from_static(seeded::KEY));
        }
        let config = self.config();
        let max = config
            .as_ref()
            .and_then(|c| c.max_message_size)
            .unwrap_or(0);
        match tungstenite::client::client_with_config(
            request,
            {
                #[allow(unused_mut)]
                let mut pipe = Pipe::default();
                #[cfg(feature = "test-seeded")]
                {
                    pipe.seeded = self.seeded;
                }
                pipe
            },
            config,
        ) {
            Err(HandshakeError::Interrupted(mid)) => Ok(Phase::Dialling {
                mid,
                response: Some(HandshakeMachine::start_read(Pipe::default())),
                held: Vec::new(),
                message: Vec::new(),
                max,
            }),
            Ok(_) | Err(HandshakeError::Failure(_)) => Err(TransportError::HandshakeFailed),
        }
    }

    /// Parse interim response heads with the protocol library's parser and existing
    /// handshake attack checks.
    fn response_heads(phase: &mut Phase, out: &mut dyn FramerOut) -> Result<bool, TransportError> {
        let Phase::Dialling { mid, response, .. } = phase else {
            return Ok(true);
        };
        loop {
            let Some(parser) = response.take() else {
                return Ok(true);
            };
            match parser
                .single_round::<UpgradeResponse>()
                .map_err(|_| TransportError::HandshakeFailed)?
            {
                RoundResult::Incomplete(next) => *response = Some(next),
                RoundResult::WouldBlock(mut next) => {
                    next.get_mut().discard_heads();
                    *response = Some(next);
                    return Ok(false);
                }
                RoundResult::StageFinished(StageResult::DoneReading {
                    result,
                    mut stream,
                    tail,
                }) => {
                    let code = result.status().as_u16();
                    if !(100..200).contains(&code) || code == 101 {
                        stream.discard_heads();
                        if code == 101 && result.headers().contains_key("sec-websocket-extensions")
                        {
                            return Err(TransportError::HandshakeFailed);
                        }
                        let normalized = (code == 101)
                            .then(|| normalized_response(&result, &stream.seen))
                            .flatten();
                        let pipe = mid.get_mut().get_mut();
                        pipe.response_connection = normalized.as_ref().map(|_| {
                            result
                                .headers()
                                .get_all("connection")
                                .iter()
                                .cloned()
                                .collect()
                        });
                        pipe.inbound = normalized
                            .as_deref()
                            .unwrap_or(&stream.seen)
                            .iter()
                            .copied()
                            .collect();
                        pipe.seen = std::mem::take(&mut stream.seen);
                        pipe.ended = stream.ended;
                        return Ok(true);
                    }
                    let block = head_block(result.headers(), &stream.seen[stream.head_at..])?;
                    let reason = reason_phrase(
                        stream
                            .seen
                            .get(stream.head_at..)
                            .ok_or(TransportError::HandshakeFailed)?,
                    );
                    out.frame(Framed {
                        status: Some(status_class(code)),
                        status_code: Some(u32::from(code)),
                        reason: reason.as_deref(),
                        ..Framed::plain(StreamId(0), &block, true)
                    });

                    stream.head_at = stream
                        .seen
                        .len()
                        .checked_sub(stream.inbound.len().saturating_add(tail.len()))
                        .ok_or(TransportError::HandshakeFailed)?;
                    let n = tail.len();
                    stream.inbound.extend(tail);
                    stream.inbound.rotate_right(n);
                    *response = Some(HandshakeMachine::start_read(stream));
                }
                RoundResult::StageFinished(StageResult::DoneWriting(_)) => {
                    return Err(TransportError::HandshakeFailed);
                }
            }
        }
    }

    /// Drive `phase` over what its pipe holds: finish the handshake if it can, then hand
    /// every message it completes up as a frame.
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

            Phase::Refused(mut pipe) => {
                pipe.inbound.clear();
                return Ok((Phase::Refused(pipe), false, None));
            }
            phase => phase,
        };
        if !Self::response_heads(&mut phase, out)? {
            return Ok((phase, false, None));
        }
        let shaking = !matches!(phase, Phase::Open { .. });

        let shaken = match &mut phase {
            Phase::Dialling { mid, .. } => {
                let pipe = mid.get_mut().get_mut();
                Some((std::mem::take(&mut pipe.seen), pipe.ended))
            }
            _ => None,
        };

        let mut reason = None;
        let mut phase = match phase {
            Phase::Accepting {
                mut mid,
                mut request,
                max,
            } => {
                let mut unread = VecDeque::new();
                if let Some(mut parser) = request.take() {
                    loop {
                        match parser.single_round::<UpgradeRequest>() {
                            Ok(RoundResult::Incomplete(next)) => parser = next,
                            Ok(RoundResult::WouldBlock(next)) => {
                                return Ok((
                                    Phase::Accepting {
                                        mid,
                                        request: Some(next),
                                        max,
                                    },
                                    false,
                                    None,
                                ));
                            }
                            Ok(RoundResult::StageFinished(StageResult::DoneReading {
                                result,
                                mut stream,
                                tail,
                            })) => {
                                if !tail.is_empty() {
                                    stream.seen.zeroize();
                                    return refused_upgrade(
                                        WsError::Protocol(ProtocolError::JunkAfterRequest),
                                        out,
                                    );
                                }
                                if !valid_opening_fields(&result) {
                                    stream.seen.zeroize();
                                    return Ok(refused_opening(false, out));
                                }
                                let mut normalized = normalized_request(&result, &stream.seen);
                                let pipe = mid.get_mut().get_mut();
                                pipe.inbound
                                    .extend(normalized.as_deref().unwrap_or(&stream.seen));
                                pipe.ended = stream.ended;
                                unread = std::mem::take(&mut stream.inbound);
                                stream.seen.zeroize();
                                if let Some(bytes) = normalized.as_mut() {
                                    bytes.zeroize();
                                }
                                break;
                            }
                            Ok(RoundResult::StageFinished(StageResult::DoneWriting(_))) => {
                                return Err(TransportError::HandshakeFailed);
                            }
                            Err(error) => return refused_upgrade(error, out),
                        }
                    }
                }
                match mid.handshake() {
                    Ok(mut ws) => {
                        let pipe = ws.get_mut();
                        pipe.inbound.append(&mut unread);
                        pipe.seen = Vec::new();
                        let mut scan = TextScan {
                            masked: true,
                            ..TextScan::default()
                        };
                        let (front, back) = pipe.inbound.as_slices();
                        scan.feed(front);
                        scan.feed(back);
                        pipe.scan = Some(scan);
                        Phase::open(ws, Vec::new(), max)
                    }
                    Err(HandshakeError::Interrupted(mut mid)) => {
                        mid.get_mut().get_mut().inbound.append(&mut unread);
                        return Ok((
                            Phase::Accepting {
                                mid,
                                request: None,
                                max,
                            },
                            false,
                            None,
                        ));
                    }
                    Err(HandshakeError::Failure(error)) => return refused_upgrade(error, out),
                }
            }
            Phase::Dialling {
                mid,
                response,
                held,
                message,
                max,
            } => match mid.handshake() {
                Ok((mut ws, mut response)) => {
                    if let Some(original) = ws.get_mut().response_connection.take() {
                        response.headers_mut().remove("connection");
                        for value in original {
                            response.headers_mut().append("connection", value);
                        }
                    }

                    let block = head_block(
                        response.headers(),
                        shaken.as_ref().map_or(&[][..], |(seen, _)| seen.as_slice()),
                    )?;
                    out.frame(Framed {
                        status: Some(WireStatusClass::Success),
                        status_code: Some(u32::from(response.status().as_u16())),
                        ..Framed::plain(StreamId(0), &block, true)
                    });
                    reason = shaken.as_ref().and_then(|(seen, _)| reason_phrase(seen));
                    for m in held {
                        ws.write(m).map_err(|e| read_error(&e))?;
                    }

                    let pipe = ws.get_mut();
                    let seen = shaken.as_ref().map_or(&[][..], |(seen, _)| seen.as_slice());
                    if let Some(at) = head_end(seen) {
                        let mut scan = TextScan::default();
                        scan.feed(&seen[at..]);
                        pipe.scan = Some(scan);
                    }
                    pipe.seen = Vec::new();
                    Phase::open(ws, message, max)
                }
                Err(HandshakeError::Interrupted(mut mid)) => {
                    mid.get_mut().get_mut().seen = shaken.map(|(seen, _)| seen).unwrap_or_default();
                    return Ok((
                        Phase::Dialling {
                            mid,
                            response,
                            held,
                            message,
                            max,
                        },
                        false,
                        None,
                    ));
                }

                Err(HandshakeError::Failure(WsError::Http(response))) => {
                    let reason = shaken.as_ref().and_then(|(seen, _)| reason_phrase(seen));
                    let code = response.status().as_u16();
                    let bodiless = matches!(code, 100..=199 | 204 | 304);
                    let chunked = if bodiless {
                        None
                    } else {
                        transfer_chunked(response.headers())?.then(Box::<Dechunk>::default)
                    };
                    let block = head_block(
                        response.headers(),
                        shaken.as_ref().map_or(&[][..], |(seen, _)| seen.as_slice()),
                    )?;
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
                    let mut pipe = Pipe::default();
                    pipe.inbound = seen[at..].iter().copied().collect();
                    pipe.ended = carrier_ended;

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

        let reason = if shaking { reason } else { None };
        if failed.is_some() {
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

                Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}

                Ok(Message::Close(_)) => {
                    if ws
                        .get_ref()
                        .scan
                        .as_ref()
                        .is_some_and(|scan| scan.bad_close)
                    {
                        *failed = Some(CloseCode::Protocol);
                    } else {
                        ended = true;
                    }
                    break;
                }
                Err(WsError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {
                    ended = true;
                    break;
                }

                Err(WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => {
                    *failed = Some(CloseCode::Abnormal);
                    break;
                }
                Err(e) => match failure_code(&e) {
                    Some(code) => {
                        *failed = Some(code);
                        break;
                    }
                    None => return Err(read_error(&e)),
                },
            }
        }

        if matches!(failed, None | Some(CloseCode::Abnormal))
            && ws.get_ref().scan.as_ref().is_some_and(|scan| scan.bad)
        {
            *failed = Some(CloseCode::Invalid);
        }
        if failed.is_some() {
            ended = true;
        }
        if ended {
            ws.get_mut().inbound.clear();
        }

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
        op: impl FnOnce(&mut WebSocket<Pipe>, &mut Vec<u8>, usize) -> Result<(), WsError>,
    ) -> Result<(), TransportError> {
        let phase = phase.ok_or(TransportError::Closed)?;
        let Phase::Open {
            ws, message, max, ..
        } = phase
        else {
            return Err(TransportError::Closed);
        };
        let done = op(ws, message, *max);
        drain(phase, out);

        done.map_err(|e| match e {
            WsError::Capacity(_) | WsError::Utf8(_) => TransportError::Framing,
            WsError::ConnectionClosed
            | WsError::AlreadyClosed
            | WsError::Protocol(ProtocolError::SendAfterClosing) => TransportError::Closed,
            _ => TransportError::Reset,
        })
    }
}

/// One `ws://`/`wss://` URL, read into `(secure, host, port, path)`.
pub(crate) fn split_ws_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let scheme = |s: &str| {
        url.get(..s.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(s))
    };
    let secure = if scheme("wss://") {
        true
    } else if scheme("ws://") {
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
    /// Why the frames of `state` ended failed, in words for the end piece.
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

/// The framer's ops, as the door calls them (`door`): every op answers at once, and nothing
/// here reads a socket or a clock.
impl WsFramer {
    /// A `ws://` target is reached at its `host:port`; a `wss://` one asks for its bytes to
    /// be secured before they leave, and names the host its certificate is checked against.
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

    /// [`WsFramer::ingest`], answering the reason phrase of the head this call handed up (a
    /// dialled framing's, HTTP/1 as sent) for the door's head slots.
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
        let was_open = matches!(phase, Phase::Open { .. });
        let pipe = phase.input();
        pipe.inbound.extend(bytes);
        pipe.ended |= end;
        if let Some(scan) = pipe.scan.as_mut().filter(|_| was_open) {
            scan.feed(bytes);
        }

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

    /// A WebSocket state keeps no deadline of its own (it never states one), so a tick
    /// finds nothing due; an unknown state is closed.
    pub(crate) fn tick(&self, state: u64, _out: &mut dyn FramerOut) -> Result<(), TransportError> {
        if self.map().contains_key(&state) {
            Ok(())
        } else {
            Err(TransportError::Closed)
        }
    }

    /// The upgrade into this framer: the stream another framer gave up, with the bytes it
    /// held — the upgrade request itself, on the accepting side — which this one answers.
    pub(crate) fn adopt(
        &self,
        side: Side,
        leftover: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        if side == Side::Dial {
            return Err(TransportError::HandoffMismatch);
        }
        let state = self.open(side, "", out)?;
        self.ingest(state, leftover, false, out)?;
        Ok(state)
    }
}

#[cfg(test)]
#[path = "tests/transport_helpers.rs"]
mod test_helpers;
