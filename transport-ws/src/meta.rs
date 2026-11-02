// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself, read once by the door's Statement and sealed. Held

use busbar_contract::grammar::SelectorForm;
use busbar_contract::transport::registry::facts as tfacts;

use crate::claims;

/// The registry key.
pub(crate) const KEY: &str = "ws";
/// The selector forms evaluated on arriving bytes.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = claims::SELECTOR_FORMS;
/// The selector forms evaluated when dialling out.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = claims::EGRESS_SELECTOR_FORMS;
/// None: no transport names another. The carrier is the

pub(crate) const COMPOSES_OVER: &[&str] = &[];
/// A WebSocket carries a session, and the session caches its principal.
pub(crate) const SESSION: bool = true;
/// See [`SESSION`].
pub(crate) const SESSION_BOUND: bool = true;
/// The transport fact keys this wire writes.
pub(crate) const TRANSPORT_FACTS: &[&str] = &[tfacts::PATH, tfacts::PEER];
