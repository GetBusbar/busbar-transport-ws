// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

impl WsFramer {
    /// Use the shipped random handshake key and mask, regardless of test features.
    pub(crate) fn unseeded(max_message_bytes: usize) -> Self {
        Self {
            #[cfg(feature = "test-seeded")]
            seeded: false,
            ..Self::new(max_message_bytes)
        }
    }

    /// Count unread bytes retained by the framing.
    pub(crate) fn inbound_len(&self, state: u64) -> Option<usize> {
        let conn = self.conn(state).ok()?;
        let mut guard = Self::enter(&conn).ok()?;
        guard.as_mut().map(|phase| phase.pipe().inbound.len())
    }

    /// Identify the outbound allocation so tests can observe its release.
    pub(crate) fn outbound_block(&self, state: u64) -> Option<(*const u8, usize)> {
        let conn = self.conn(state).ok()?;
        let mut guard = Self::enter(&conn).ok()?;
        guard.as_mut().map(|phase| {
            let out = &phase.pipe().outbound;
            (out.as_ptr(), out.capacity())
        })
    }

    /// Whether the framing ended with a protocol or handshake failure.
    pub(crate) fn failed(&self, state: u64) -> bool {
        self.failure(state).is_some()
    }
}
