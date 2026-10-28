// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the framer hands the door, and what the door hands the framer: the crate's own shapes
//! between `transport` (the RFC 6455 state machine) and `door` (the memory-ABI framer door, the
//! one way this crate reaches the host).

use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;

/// Which end of a connection a framing state is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    /// The end that accepted the connection.
    Accept,
    /// The end that dialled it.
    Dial,
}

/// Where a dial goes, read off its target: the carrier authority, whether the target asks for its
/// bytes to be secured, and the name a presented certificate is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Located {
    /// The carrier authority, `host:port`.
    pub(crate) authority: String,
    /// The target asks for the bytes to be secured before they leave this node.
    pub(crate) secure: bool,
    /// The name a presented certificate is checked against, where the target names one.
    pub(crate) server_name: Option<String>,
}

/// One piece of a frame the framer completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Framed<'a> {
    /// The stream the frame arrived on (`StreamId(0)`: a WebSocket carries one).
    pub(crate) stream: StreamId,
    /// The bytes.
    pub(crate) bytes: &'a [u8],
    /// This piece completes the frame.
    pub(crate) end_of_frame: bool,
    /// The status class the frame carries (a dialled upgrade's answer head).
    pub(crate) status: Option<WireStatusClass>,
    /// The exact status number the frame carries.
    pub(crate) status_code: Option<u32>,
    /// How long the far side asked to be left alone, in seconds.
    pub(crate) retry_after_secs: Option<u64>,
    /// The bytes belong to a TEXT message, not a binary one.
    pub(crate) text: bool,
}

impl<'a> Framed<'a> {
    /// A frame piece with no status: `bytes` on `stream`.
    #[must_use]
    pub(crate) const fn plain(stream: StreamId, bytes: &'a [u8], end_of_frame: bool) -> Self {
        Self {
            stream,
            bytes,
            end_of_frame,
            status: None,
            status_code: None,
            retry_after_secs: None,
            text: false,
        }
    }

    /// The same piece, stated as part of a TEXT message (`true`) or a binary one.
    #[must_use]
    pub(crate) const fn text(mut self, text: bool) -> Self {
        self.text = text;
        self
    }
}

/// The host's clock at a call, as the framer reads it: its wall time (a `Retry-After` date is
/// read against it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HostTime {
    /// The host's wall time, nanoseconds since the Unix epoch.
    pub(crate) unix_nanos: u64,
}

/// Where the framer puts what a call produced: bytes owed to the far side, frame pieces for the
/// layer above, and the end of the connection's frames.
pub(crate) trait FramerOut {
    /// Bytes for the far side, in order.
    fn send(&mut self, bytes: &[u8]);
    /// A frame piece for the layer above, in order.
    fn frame(&mut self, piece: Framed<'_>);
    /// No frame follows on this connection.
    fn end(&mut self);
    /// The host's time at this call.
    fn now(&self) -> HostTime;
}

/// Where the framer puts the bytes a rendering produced.
pub(crate) trait BytesOut {
    /// Bytes, in order.
    fn put(&mut self, bytes: &[u8]);
}

impl BytesOut for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}
