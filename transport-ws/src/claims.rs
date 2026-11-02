// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares.

use busbar_contract::grammar::SelectorForm;

/// The forms an INGRESS claim over this wire may take.
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
