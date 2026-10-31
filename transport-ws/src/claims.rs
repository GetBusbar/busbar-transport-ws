// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares.
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the connection code that never reads it.

use busbar_contract::grammar::SelectorForm;

/// The forms an INGRESS claim over this wire may take.
///
/// A ws session opens on an HTTP upgrade request, so an ingress claim over this wire selects on
/// that request's shape: its path and its fields. Only the forms something evaluates are declared
/// (busbar e50a03c87d): `route.rs` and the kernel's `guest.rs` evaluate the path forms and the
/// header present/prefix predicates; no route predicate spells an exact header value
/// (`HeaderExact`); nothing matches an arriving connection's `Sni` or `Alpn`; `Port` is honoured
/// only on a carrier (`address_carrier` requires `ROLE_CARRIER && ported`). The door renders its
/// claim rows from this list (`crate::door`); it is stated nowhere else.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
];

/// The forms an EGRESS claim over this wire may take: none.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
