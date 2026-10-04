// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER (TRANSPORT-STACK; #3, #30): `ws` as the contract's [`Framer`] — the one implementation
//! both doors drive. A build that links this crate holds a [`WsFramer`] as its `Arc<dyn Framer>`
//! (`crate::linked::framer`); the sibling `busbar-transport-ws-plugin` cdylib exports the door
//! over this same type (`crate::door`).
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
//! * A ping is answered with its pong on the next bytes out; a close is answered and ends the frames.
//! * A close carries the RFC 6455 code its reason names ([`close_code_for`]).
//! * The message ceiling is the deployment's body cap, for a whole message and for a single frame.
//!
//! The upgrade INTO this framer is [`Framer::adopt`]: another framer gave up the stream with the
//! bytes it held (the upgrade request itself), and this one answers it. Nothing upgrades out of a
//! WebSocket, so [`Framer::detach`] refuses.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{CloseReason, Encode, TransportError};
use busbar_contract::transport::{
    BytesOut, ConnFacts, Framed, Framer, FramerOut, Located, Side, TransportSettings,
};
use busbar_contract::{AbiVersion, Kind, Plugin};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::ClientHandshake;
use tokio_tungstenite::tungstenite::handshake::server::{NoCallback, ServerHandshake};
use tokio_tungstenite::tungstenite::handshake::{HandshakeError, MidHandshake};
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message, WebSocket};

use crate::transport::split_ws_url;

/// The in-memory stream one framing state's protocol machine reads and writes: what core ingested
/// and the machine has not consumed, whether the carrier's clean end followed it, and what the
/// machine wrote and core has not been handed yet.
#[derive(Default)]
pub(crate) struct Pipe {
    inbound: VecDeque<u8>,
    ended: bool,
    outbound: Vec<u8>,
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
        for (slot, byte) in buf.iter_mut().zip(self.inbound.drain(..n)) {
            *slot = byte;
        }
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
    /// The session: the protocol machine, and the pieces of a message not yet marked complete.
    Open {
        ws: Box<WebSocket<Pipe>>,
        message: Vec<u8>,
    },
}

impl Phase {
    fn pipe(&mut self) -> &mut Pipe {
        match self {
            Phase::Accepting(mid) => mid.get_mut().get_mut(),
            Phase::Dialling { mid, .. } => mid.get_mut().get_mut(),
            Phase::Open { ws, .. } => ws.get_mut(),
        }
    }
}

/// The `ws` framer: its framing states, and the message ceiling every connection is built with.
pub struct WsFramer {
    states: Mutex<HashMap<u64, Phase>>,
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

/// The RFC 6455 close code a [`CloseReason`] puts on the wire (each a code an endpoint may send).
pub(crate) fn close_code_for(reason: CloseReason) -> CloseCode {
    match reason {
        CloseReason::Normal => CloseCode::Normal,
        CloseReason::PeerClosed => CloseCode::Away,
        CloseReason::Drain => CloseCode::Restart,
        CloseReason::Poisoned => CloseCode::Error,
        CloseReason::Revoked => CloseCode::Policy,
        CloseReason::Timeout => CloseCode::Again,
        CloseReason::TransportFailed => CloseCode::Protocol,
        CloseReason::CapacityExhausted => CloseCode::Size,
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

/// One message as the protocol machine sends it.
fn message_of(bytes: Vec<u8>, text: bool) -> Result<Message, WsError> {
    if text {
        String::from_utf8(bytes)
            .map(|t| Message::Text(t.into()))
            .map_err(|_| WsError::Utf8(String::new()))
    } else {
        Ok(Message::Binary(bytes.into()))
    }
}

/// Hand whatever the machine wrote to core.
fn drain(phase: &mut Phase, out: &mut dyn FramerOut) {
    let pipe = phase.pipe();
    if !pipe.outbound.is_empty() {
        out.send(&std::mem::take(&mut pipe.outbound));
    }
}

impl WsFramer {
    /// A framer whose messages (and frames) are capped at `max_message_bytes`; `0` = the protocol
    /// library's own default stands.
    #[must_use]
    pub fn new(max_message_bytes: usize) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            max_message_bytes,
        }
    }

    /// The linked row's constructor: the deployment's body cap is the message ceiling, because a
    /// message is assembled from frames before anything above the transport sees it.
    #[must_use]
    pub fn built(settings: &TransportSettings) -> Self {
        Self::new(settings.request_body_max_bytes)
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
        {
            let mut states = self.states.lock().expect("framing states poisoned");
            if let Some(Phase::Dialling { held, message, .. }) = states.get_mut(&state) {
                message.extend_from_slice(bytes);
                if end_of_frame {
                    held.push((std::mem::take(message), text));
                }
                return Ok(());
            }
        }
        self.with_open(state, out, |ws, message| {
            message.extend_from_slice(bytes);
            if !end_of_frame {
                return Ok(());
            }
            ws.send(message_of(std::mem::take(message), text)?)
        })
    }

    fn hold(&self, phase: Phase) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.states
            .lock()
            .expect("framing states poisoned")
            .insert(id, phase);
        id
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
                match tokio_tungstenite::tungstenite::accept_with_config(
                    Pipe::default(),
                    self.config(),
                ) {
                    Err(HandshakeError::Interrupted(mid)) => Phase::Accepting(mid),
                    // Nothing has been read, so nothing can have completed or failed yet.
                    Ok(_) | Err(HandshakeError::Failure(_)) => {
                        return Err(TransportError::HandshakeFailed)
                    }
                }
            }
            Side::Dial => {
                let (secure, host, port, path) = split_ws_url(target)?;
                let url = format!(
                    "{}://{host}:{port}{path}",
                    if secure { "wss" } else { "ws" }
                );
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
                match tokio_tungstenite::tungstenite::client::client_with_config(
                    request,
                    Pipe::default(),
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
    /// message it completes up as a frame. Answers whether the connection's frames ended.
    fn drive(phase: Phase, out: &mut dyn FramerOut) -> Result<(Phase, bool), TransportError> {
        let mut phase = match phase {
            Phase::Accepting(mid) => match mid.handshake() {
                Ok(ws) => Phase::Open {
                    ws: Box::new(ws),
                    message: Vec::new(),
                },
                Err(HandshakeError::Interrupted(mid)) => return Ok((Phase::Accepting(mid), false)),
                Err(HandshakeError::Failure(_)) => return Err(TransportError::HandshakeFailed),
            },
            Phase::Dialling { mid, held, message } => match mid.handshake() {
                Ok((mut ws, _response)) => {
                    // What was written before the handshake completed goes out now, in order.
                    for (bytes, text) in held {
                        let m = message_of(bytes, text).map_err(|e| read_error(&e))?;
                        ws.write(m).map_err(|e| read_error(&e))?;
                    }
                    Phase::Open {
                        ws: Box::new(ws),
                        message,
                    }
                }
                Err(HandshakeError::Interrupted(mid)) => {
                    return Ok((Phase::Dialling { mid, held, message }, false))
                }
                Err(HandshakeError::Failure(_)) => return Err(TransportError::HandshakeFailed),
            },
            open => open,
        };
        let Phase::Open { ws, .. } = &mut phase else {
            unreachable!("every other phase returned above");
        };
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
                // The peer closed: the machine queued the close answer, and no frame follows.
                Ok(Message::Close(_)) => {
                    ended = true;
                    break;
                }
                Err(WsError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {
                    ended = true;
                    break;
                }
                Err(e) => return Err(read_error(&e)),
            }
        }
        // Whatever the machine owes the far side (a pong, a close answer) goes out now.
        match ws.flush() {
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {}
            Err(WsError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(read_error(&e)),
        }
        let pipe = ws.get_mut();
        ended |= pipe.ended && pipe.inbound.is_empty();
        Ok((phase, ended))
    }

    /// Run `op` on the open state `state`, handing what it wrote to core.
    fn with_open(
        &self,
        state: u64,
        out: &mut dyn FramerOut,
        op: impl FnOnce(&mut WebSocket<Pipe>, &mut Vec<u8>) -> Result<(), WsError>,
    ) -> Result<(), TransportError> {
        let mut states = self.states.lock().expect("framing states poisoned");
        let phase = states.get_mut(&state).ok_or(TransportError::Closed)?;
        let Phase::Open { ws, message } = phase else {
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
            authority: format!("{host}:{port}"),
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
        let mut states = self.states.lock().expect("framing states poisoned");
        let mut phase = states.remove(&state).ok_or(TransportError::Closed)?;
        let pipe = phase.pipe();
        pipe.inbound.extend(bytes);
        pipe.ended |= end;
        match Self::drive(phase, out) {
            Ok((mut phase, ended)) => {
                drain(&mut phase, out);
                if ended {
                    out.end();
                }
                states.insert(state, phase);
                Ok(())
            }
            // A failed state is gone: its connection has nothing more to say.
            Err(e) => Err(e),
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
        _stream: Option<StreamId>,
        bytes: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let sent = self.emit(state, StreamId(0), bytes, true, false, out);
        self.close(state, CloseReason::Normal, out);
        sent
    }

    fn close(&self, state: u64, reason: CloseReason, out: &mut dyn FramerOut) {
        let Some(mut phase) = self
            .states
            .lock()
            .expect("framing states poisoned")
            .remove(&state)
        else {
            return;
        };
        if let Phase::Open { ws, .. } = &mut phase {
            // The close frame is a courtesy on a connection already finalised: what the machine
            // could write goes out, and a close it cannot write is not an error anyone can act on.
            let _ = ws.close(Some(CloseFrame {
                code: close_code_for(reason),
                reason: "".into(),
            }));
            let _ = ws.flush();
        }
        drain(&mut phase, out);
    }

    /// A WebSocket state keeps no deadline of its own (it never states one), so a tick finds nothing
    /// due; an unknown state is closed.
    fn tick(&self, state: u64, _out: &mut dyn FramerOut) -> Result<(), TransportError> {
        if self
            .states
            .lock()
            .expect("framing states poisoned")
            .contains_key(&state)
        {
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
