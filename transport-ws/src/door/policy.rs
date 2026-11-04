// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission of a direct accepted upgrade, before tungstenite can answer or read messages.

use super::*;
use busbar_contract::abi::host::service::{
    UnitRef, FLOW_CONTINUE, LINE_NONE, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::services::{HeadViewArgs, RefusalCopy, Services};
use busbar_contract::abi::transport::guest_policy::Policy;
use busbar_contract::abi::transport::route::RouteView;
use tungstenite::handshake::machine::TryParse;
use tungstenite::handshake::server::Request;
use zeroize::Zeroizing;

pub(super) struct Admission {
    loans: Loans,
    selected: Option<Arc<Policy>>,
    unit: UnitRef,
    opening: Zeroizing<Vec<u8>>,
    head_end: Option<usize>,
    line_has_content: bool,
    has_request_line: bool,
    ticket: Option<Ticket>,
    scheme: u8,
    failed: bool,
}

enum Progress {
    Waiting,
    Admitted,
    Refused(RefusalCopy),
}

fn invalid_opening() -> Progress {
    Progress::Refused(RefusalCopy {
        status: 400,
        fields: vec![("connection".into(), b"close".to_vec())],
        body: Vec::new(),
    })
}

impl Admission {
    pub(super) fn new(loans: Loans, scheme: u8) -> Self {
        Self {
            loans,
            selected: None,
            unit: UnitRef::NONE,
            opening: Zeroizing::new(Vec::new()),
            head_end: None,
            line_has_content: false,
            has_request_line: false,
            ticket: None,
            scheme,
            failed: false,
        }
    }

    pub(super) fn admitted(&self) -> bool {
        !self.unit.is_none()
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.opening.capacity() - self.opening.len() < bytes.len() {
            let required = self.opening.len().saturating_add(bytes.len());
            let capacity = required
                .max(self.opening.capacity().saturating_mul(2))
                .max(256);
            let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
            grown.extend_from_slice(&self.opening);
            self.opening = grown;
        }
        let offset = self.opening.len();
        self.opening.extend_from_slice(bytes);
        if self.head_end.is_none() {
            for (index, byte) in bytes.iter().enumerate() {
                if *byte == b'\n' {
                    if !self.line_has_content && self.has_request_line {
                        self.head_end = Some(offset + index + 1);
                        break;
                    }
                    self.has_request_line |= self.line_has_content;
                    self.line_has_content = false;
                } else if *byte != b'\r' {
                    self.line_has_content = true;
                }
            }
        }
    }

    fn complete_opening(&self) -> Option<&[u8]> {
        self.head_end.map(|_| self.opening.as_slice())
    }

    fn hand_in(
        &mut self,
        request: &Request,
        services: &Services,
        ticket: Ticket,
        conn: u64,
    ) -> Result<Option<RefusalCopy>, Refusal> {
        let selected = self
            .selected
            .as_ref()
            .expect("a selected loan precedes admission");
        let fields: Vec<_> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect();
        let view = HeadViewArgs {
            method: request.method().as_str(),
            target: request.uri().path(),
            authority: request.uri().authority().map_or_else(
                || {
                    request
                        .headers()
                        .get("host")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                },
                tungstenite::http::uri::Authority::as_str,
            ),
            query: request.uri().query(),
            fields: &fields,
            scheme: self.scheme,
        };
        let mut method_miss = None;
        let matched = selected.lines.iter().find(|line| {
            let route = RouteView {
                methods: line.methods,
                path_form: line.path_form,
                path: &line.path,
                fields: line
                    .fields
                    .iter()
                    .map(|(op, name, value)| (*op, name.as_str(), value.as_slice()))
                    .collect(),
                rung: line.rung,
            };
            if !route.path_and_fields_match(view.target, view.fields) {
                return false;
            }
            if route.admits(view.method) {
                return true;
            }
            method_miss.get_or_insert(line.line);
            false
        });
        let handle = |seq| CompletionHandle {
            ticket,
            seq,
            _reserved: 0,
        };
        let (unit, cause, line) = if let Some(line) = matched {
            if line.points != 0 {
                return Err(Refusal::refused(
                    "ingest: ws offers no inbound authentication points",
                ));
            }
            let (flow, unit) = services
                .unit_hand_in(
                    handle(1),
                    line.auth,
                    UnitRef::NONE,
                    line.line,
                    conn,
                    0,
                    &view,
                )
                .map_err(|_| Refusal::failed("ingest: the host could not admit the upgrade"))?;
            if flow == FLOW_CONTINUE {
                if unit.is_none() {
                    return Err(Refusal::failed(
                        "ingest: the host returned no admitted session",
                    ));
                }
                self.unit = unit;
                return Ok(None);
            }
            (unit, REFUSE_CHECK_FAILED, line.line)
        } else if let Some(line) = method_miss {
            (UnitRef::NONE, REFUSE_METHOD_MISS, line)
        } else {
            (UnitRef::NONE, REFUSE_NO_ROUTE, LINE_NONE)
        };
        services
            .unit_refuse(handle(2), unit, cause, line, conn, 0, &view)
            .map(Some)
            .map_err(|_| Refusal::failed("ingest: the host could not refuse the upgrade"))
    }
}

/// `None` leaves an already admitted, adopted, dialled, or legacy framing to its usual path.
pub(super) fn ingest(
    p: &Instance<'_, Held<Ws>>,
    input: Lent<'_, IngestIn>,
    out: &mut Out<'_, FramerOut>,
) -> Option<Outcome> {
    let held = p.get()?;
    let inst = held.life();
    let slot = inst.queues().get(&input.framing).cloned()?;
    let Ok(mut owed) = slot.lock() else {
        return Some(out.fail(Refusal::failed(INGEST.framing_failed)));
    };
    if owed.ended {
        return None;
    }
    let admission = owed.policy.as_mut()?;
    if admission.admitted() {
        return None;
    }
    let answer = (|| {
        if admission.failed {
            return Err(Refusal::failed("ingest: the upgrade admission failed"));
        }
        let ticket = input.head.ticket;
        if admission.ticket.is_some_and(|owner| owner != ticket) {
            return Err(Refusal::failed(
                "ingest: another operation owns the upgrade opening",
            ));
        }
        if admission.ticket.is_none() {
            admission.append(input.bytes());
        }

        let Some(opening) = admission.complete_opening() else {
            if input.end != 0 || admission.opening.len() > 65536 {
                return Ok(invalid_opening());
            }
            return Ok(Progress::Waiting);
        };
        if admission.head_end.is_some_and(|length| length > 65536) {
            return Ok(invalid_opening());
        }
        let parsed = match Request::try_parse(opening) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(invalid_opening()),
        };
        let Some((head_len, request)) = parsed else {
            return Ok(invalid_opening());
        };
        if head_len > 65536 || !crate::transport::valid_opening_fields(&request) {
            return Ok(invalid_opening());
        }
        admission.ticket = Some(ticket);
        let selected = admission
            .loans
            .open(
                ticket,
                0,
                input.field(|x| &x.head.extensions).bytes(),
                out,
                held.leases(),
            )
            .map_err(|error| Refusal::failed(format!("ingest: {error}")))?;
        let Some(selected) = selected else {
            return Ok(Progress::Waiting);
        };
        admission.selected = Some(selected);
        let services = held
            .host()
            .and_then(|host| host.services())
            .ok_or_else(|| Refusal::failed("ingest: the host unit services are absent"))?;
        let refused = admission.hand_in(&request, &services, ticket, input.framing)?;
        admission.ticket = None;
        Ok(refused.map_or(Progress::Admitted, Progress::Refused))
    })();
    match answer {
        Ok(Progress::Waiting) => Some(Outcome::Ready),
        Ok(Progress::Refused(refusal)) => {
            admission.failed = true;
            admission.opening.zeroize();
            inst.framer.forget(input.framing);
            let wire = match refusal_wire(refusal) {
                Ok(wire) => wire,
                Err(error) => return Some(out.fail(error)),
            };
            owed.push(&wire, false);
            owed.ended = true;
            owed.pieces.push_back(Piece {
                failed: true,
                ..Piece::plain(0, b"the upgrade was refused".to_vec(), true)
            });
            fill(&mut owed, input.field(|x| &x.sink), out);
            Some(Outcome::Ready)
        }
        Ok(Progress::Admitted) => {
            let bytes = std::mem::take(&mut admission.opening);
            let mut collect = Collect {
                owed: &mut owed,
                now: time(&input.field(|x| &x.sink)),
                opening: false,
            };
            let result =
                inst.framer
                    .ingest_head(input.framing, &bytes, input.end != 0, &mut collect);
            match result {
                Ok(_) => {
                    end_failed(&inst.framer, input.framing, collect.owed, false);
                    fill(collect.owed, input.field(|x| &x.sink), out);
                    Some(Outcome::Ready)
                }
                Err(error) => Some(out.fail(Refusal::failed((INGEST.why)(&error)))),
            }
        }
        Err(error) => {
            admission.failed = true;
            if let Some(ticket) = admission.ticket.take() {
                admission.loans.cancel(ticket);
            }
            admission.opening.zeroize();
            inst.framer.forget(input.framing);
            Some(out.fail(error))
        }
    }
}

fn refusal_wire(refusal: RefusalCopy) -> Result<Vec<u8>, Refusal> {
    use tungstenite::http::{HeaderName, HeaderValue, StatusCode};
    let status = StatusCode::from_u16(refusal.status)
        .map_err(|_| Refusal::failed("ingest: the host refusal has an invalid status"))?;
    let mut wire = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
    .into_bytes();
    let mut length = false;
    for (name, value) in refusal.fields {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Refusal::failed("ingest: the host refusal has an invalid field name"))?;
        let value = HeaderValue::from_bytes(&value)
            .map_err(|_| Refusal::failed("ingest: the host refusal has an invalid field value"))?;
        length |= name == "content-length";
        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    if !length {
        wire.extend_from_slice(format!("content-length: {}\r\n", refusal.body.len()).as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&refusal.body);
    Ok(wire)
}

pub(super) struct Cancel;

impl SafeSlot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    type State = Held<Ws>;

    fn call(
        p: Instance<'_, Self::State>,
        input: Lent<'_, CancelIn>,
        mut out: Out<'_, CancelOut>,
    ) -> Outcome {
        let mut cancelled = Vec::new();
        let mut busy = false;
        if let Some(inst) = p.get().map(Held::life) {
            let queues: Vec<_> = inst
                .queues()
                .iter()
                .map(|(token, queue)| (*token, Arc::clone(queue)))
                .collect();
            for (token, queue) in queues {
                let mut owed = match queue.try_lock() {
                    Ok(owed) => owed,
                    Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        busy = true;
                        continue;
                    }
                };
                if let Some(admission) = &mut owed.policy {
                    if admission.ticket == Some(input.ticket) && !admission.admitted() {
                        admission.loans.cancel(input.ticket);
                        admission.failed = true;
                        admission.opening.zeroize();
                        cancelled.push(token);
                    }
                }
            }
            for token in &cancelled {
                inst.queues().remove(token);
                inst.framer.forget(*token);
            }
        }
        if busy && cancelled.is_empty() {
            return out.fail(Refusal::failed("cancel: framing busy"));
        }
        out.set(
            |value| &value.disposition,
            if cancelled.is_empty() {
                CANCEL_NOTHING_MOVED
            } else {
                CANCEL_PARTIAL
            },
        );
        Outcome::Ready
    }
}

#[cfg(test)]
#[path = "../tests/policy_growth_tests.rs"]
mod tests;
