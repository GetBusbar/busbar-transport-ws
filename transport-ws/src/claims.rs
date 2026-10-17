// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares, as the kind's own file (`BUSBAR-1.6.0.md` THE DESIGN, §2).
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the connection code that never reads it.

use busbar_contract::grammar::SelectorForm;

/// The forms an INGRESS claim over this wire may take.
///
/// A ws session opens on an HTTP upgrade request, so an ingress claim over this wire selects on
/// that request's shape: its path, its fields, and the connection it arrived on. The door renders
/// its claim rows from this list (`crate::door`); it is stated nowhere else.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
    SelectorForm::HeaderExact,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
    SelectorForm::Sni,
    SelectorForm::Alpn,
    SelectorForm::Port,
];

/// The forms an EGRESS claim over this wire may take: none.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
