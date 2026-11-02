// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The WebSocket transport: duplex message frames over an HTTP upgrade.

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod claims;
pub mod door;
mod frame;
mod meta;
mod transport;

/// The transport axis entry the composition root folds for this wire — its key, the layers it

pub mod linked {
    pub use crate::door::{door, MACRO_DOOR};

    /// The row's registry key.
    pub const KEY: &str = crate::meta::KEY;
    /// The layers this wire declares it can be built over.
    pub const COMPOSES_OVER: &[&str] = crate::meta::COMPOSES_OVER;
    /// Whether this wire carries sessions.
    pub const SESSION: bool = crate::meta::SESSION;
}

#[cfg(test)]
#[path = "tests/framer_tests.rs"]
mod framer_tests;

#[cfg(test)]
#[path = "tests/utf8_fail_fast_tests.rs"]
mod utf8_fail_fast_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/faults_tests.rs"]
mod faults_tests;
