// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The WebSocket transport: duplex message frames over an HTTP upgrade.
//!
//! This crate carries exactly the byte-level behaviour the architecture's ws row names: the
//! session opens at the upgrade (`Unit0Trigger::Upgrade`), frames after the upgrade carry no
//! status leg (`STATUS_CLASS = None`), and text/binary WS messages are the frame unit. It carries
//! no protocol meaning — no verbs, no ids, no JSON. That belongs to whichever plane rides this
//! transport.
//!
//! ## One entry: the door
//!
//! The crate's one entry is its memory-ABI door (`door::door`), the same table compiled in (a busbar
//! build's `transport-door` row) and dropped in (the sibling `busbar-transport-ws-plugin` cdylib),
//! single-entry and door-only as ARCHITECT ruling (A) shaped the stdio row. There is no in-process
//! `Transport`: the host's connector owns the socket and connection security, and frames a ws
//! connection with this door, whether it is accepted on the data listener's upgrade or dialled
//! through `tcp`. No transport encrypts: TLS is core's connection security, applied host-side and
//! never composed as a layer.

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod claims;
mod framer;
// THE ABI BOUNDARY: the door reads and writes the host's C buffers, so it is one of the modules
// this crate's `#![deny(unsafe_code)]` allows; every block in it states the host buffer it relies on.
#[allow(unsafe_code)]
pub mod door;
mod meta;

pub use framer::WsFramer;

/// THE TRANSPORT AXIS ENTRY (#3, #30): what the composition root folds for this wire — its key, the
/// layers it declares, and its door, which the root builds the wire from (the `transport-door`
/// axis) and opens on the one connector (the `connector-door` axis). The root names none of them.
pub mod linked {
    use std::sync::Arc;

    use busbar_contract::transport::{TransportMeta, TransportSettings};

    pub use crate::door::door;

    /// The row's registry key.
    pub const KEY: &str = <crate::WsFramer as TransportMeta>::KEY;
    /// The layers this wire declares it can be built over.
    pub const COMPOSES_OVER: &[&str] = <crate::WsFramer as TransportMeta>::COMPOSES_OVER;
    /// Whether this wire carries sessions.
    pub const SESSION: bool = <crate::WsFramer as TransportMeta>::SESSION;

    /// Every constant this wire declares, as the root reads a row.
    pub const ROW: busbar_contract::transport::TransportRow =
        busbar_contract::transport::TransportRow::of::<crate::WsFramer>();

    /// The framer, built: the deployment's body cap is its message ceiling.
    #[must_use]
    pub fn framer(settings: &TransportSettings) -> Arc<dyn busbar_contract::transport::Framer> {
        Arc::new(crate::WsFramer::built(settings))
    }
}

#[cfg(test)]
#[path = "tests/framer_tests.rs"]
mod framer_tests;
