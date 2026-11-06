// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::service::{
    AuthAnswer, AuthRef, HostSlots, RefusalAnswer, ServiceOut, UnitHandInIn, UnitRef, UnitRefuseIn,
    FLOW_CONTINUE, FLOW_STOP, LINE_NONE, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE,
    SCHEME_PLAIN, SERVICES,
};
use busbar_contract::abi::mechanism::call::{Blob, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::transport::guest_policy::{
    self, GuestLine, Identity, Open, EXT_GUEST_CURRENT, EXT_GUEST_OPEN, EXT_GUEST_POLICY,
};
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
use busbar_contract::abi::transport::{CANCEL_NOTHING_MOVED, CANCEL_PARTIAL};
use std::cell::Cell;
use std::mem::size_of;

thread_local! {
    static HANDED: RefCell<Vec<(u32, u64, u64)>> = const { RefCell::new(Vec::new()) };
    static FLOW: Cell<u32> = const { Cell::new(FLOW_CONTINUE) };
    static FIELDS: RefCell<Vec<(Vec<u8>, Vec<u8>)>> = const { RefCell::new(Vec::new()) };
    /// Each refusal the host was asked to write: its cause and the line it states.
    static REFUSED: RefCell<Vec<(u32, u32)>> = const { RefCell::new(Vec::new()) };
    /// How the host's hand-in misbehaves: `HAND_NO_UNIT` continues without a session,
    /// `HAND_ERROR` fails the service call.
    static HAND: Cell<u8> = const { Cell::new(0) };
    /// The host's refusal service fails.
    static REFUSE_ERROR: Cell<bool> = const { Cell::new(false) };
}

const HAND_NO_UNIT: u8 = 1;
const HAND_ERROR: u8 = 2;

extern "C" fn hand_in(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the host service wrapper lends a complete input and answer for this callback.
    unsafe {
        let input = input.cast::<UnitHandInIn>().read_unaligned();
        HANDED.with(|seen| {
            seen.borrow_mut()
                .push((input.line, input.auth.mac, input.stream))
        });
        FIELDS.with(|seen| {
            let fields = if input.request.fields_len == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(input.request.fields, input.request.fields_len)
            };
            *seen.borrow_mut() = fields
                .iter()
                .map(|field| (field.name.bytes().to_vec(), field.value.bytes().to_vec()))
                .collect();
        });
        if HAND.with(Cell::get) == HAND_ERROR {
            (*out).outcome = RawOutcome::of(Outcome::Failed);
            return RawOutcome::of(Outcome::Failed);
        }
        input.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow: FLOW.with(Cell::get),
            unit: if HAND.with(Cell::get) == HAND_NO_UNIT {
                UnitRef::NONE
            } else {
                UnitRef {
                    id: 17,
                    mac: input.auth.mac,
                }
            },
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn refuse(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the host service wrapper lends a complete input and answer for this callback.
    unsafe {
        let input = input.cast::<UnitRefuseIn>().read_unaligned();
        REFUSED.with(|seen| seen.borrow_mut().push((input.cause, input.line)));
        if REFUSE_ERROR.with(Cell::get) {
            (*out).outcome = RawOutcome::of(Outcome::Failed);
            return RawOutcome::of(Outcome::Failed);
        }
        input.answer.write_unaligned(RefusalAnswer {
            size: size_of::<RefusalAnswer>() as u32,
            status: 403,
            fields: std::ptr::null(),
            fields_len: 0,
            body: Blob::of(b"denied-verbatim"),
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

fn blob(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn masked(bytes: &[u8]) -> Vec<u8> {
    let mask = [1, 2, 3, 4];
    let mut wire = vec![0x82, 0x80 | u8::try_from(bytes.len()).unwrap()];
    wire.extend_from_slice(&mask);
    wire.extend(bytes.iter().enumerate().map(|(i, byte)| byte ^ mask[i % 4]));
    wire
}

fn guest_line(generation: u64, line: u32, methods: u32, path: &str, points: u32) -> GuestLine {
    GuestLine {
        line,
        points,
        auth: AuthRef {
            id: u64::from(line),
            mac: generation,
        },
        body_limit: 0,
        methods,
        path_form: PATH_EXACT,
        path: path.into(),
        fields: Vec::new(),
        rung: 0,
    }
}

fn policy_of(generation: u64, lines: &[GuestLine]) -> Vec<u8> {
    extensions::encode(&[(
        EXT_GUEST_POLICY,
        &guest_policy::encode(7, generation, lines).unwrap(),
    )])
}

fn policy(generation: u64, line: u32) -> Vec<u8> {
    policy_of(
        generation,
        &[guest_line(generation, line, METHOD_GET, "/echo", 0)],
    )
}

struct Host {
    instance: *mut c_void,
    token: u64,
    _tables: Box<HostTables>,
    _slots: Box<HostSlots>,
}

impl Host {
    fn new() -> Self {
        Self::build(true)
    }

    /// A host whose tables state no unit services at all.
    fn without_services() -> Self {
        Self::build(false)
    }

    fn build(services: bool) -> Self {
        HANDED.with(|seen| seen.borrow_mut().clear());
        FIELDS.with(|seen| seen.borrow_mut().clear());
        FLOW.with(|flow| flow.set(FLOW_CONTINUE));
        REFUSED.with(|seen| seen.borrow_mut().clear());
        HAND.with(|mode| mode.set(0));
        REFUSE_ERROR.with(|fail| fail.set(false));
        // SAFETY: these ABI tables are plain C data with valid zero defaults.
        let mut slots: Box<HostSlots> = Box::new(unsafe { std::mem::zeroed() });
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = SERVICES;
        slots.unit_hand_in = Some(hand_in);
        slots.unit_refuse = Some(refuse);
        // SAFETY: as above.
        let mut tables: Box<HostTables> = Box::new(unsafe { std::mem::zeroed() });
        tables.size = size_of::<HostTables>() as u32;
        if services {
            tables.services = &*slots;
        }
        // SAFETY: all-zero is valid for these ABI inputs and outputs.
        let mut input: OpenIn = unsafe { std::mem::zeroed() };
        input.host = &*tables;
        // SAFETY: as above.
        let mut out: OpenOut = unsafe { std::mem::zeroed() };
        // SAFETY: the tables remain live until after this instance closes.
        assert_eq!(
            unsafe {
                Safe::<life::Open<Ws>>::enter(
                    std::ptr::null_mut(),
                    life_slot::OPEN,
                    &input,
                    &mut out,
                )
            },
            Outcome::Ready
        );
        let mut host = Self {
            instance: out.instance,
            token: 0,
            _tables: tables,
            _slots: slots,
        };
        let initial = policy(1, 11);
        // SAFETY: all-zero is valid for this ABI input.
        let mut input: BeginIn = unsafe { std::mem::zeroed() };
        input.side = SIDE_ACCEPT;
        input.scheme = SCHEME_PLAIN;
        input.head.ticket = ticket(1);
        input.head.extensions = blob(&initial);
        let mut lend = Lend::roomy();
        input.sink = lend.sink();
        // SAFETY: all-zero is valid for this ABI output.
        let mut out: DoorOut = unsafe { std::mem::zeroed() };
        // SAFETY: Begin lends no sink data until Ingest has decoded the upgrade.
        assert_eq!(
            unsafe { Safe::<Begin>::enter(host.instance, slot::BEGIN, &input, &mut out) },
            Outcome::Ready
        );
        host.token = out.framing;
        host
    }

    fn ingest(
        &self,
        bytes: &[u8],
        extension: &[u8],
        owner: Ticket,
        lend: &mut Lend,
    ) -> (Said, Option<Open>) {
        self.ingest_ending(bytes, extension, owner, lend, false)
    }

    fn ingest_ending(
        &self,
        bytes: &[u8],
        extension: &[u8],
        owner: Ticket,
        lend: &mut Lend,
        end: bool,
    ) -> (Said, Option<Open>) {
        // SAFETY: all-zero is valid for these ABI inputs and outputs.
        let mut input: IngestIn = unsafe { std::mem::zeroed() };
        input.framing = self.token;
        input.end = u32::from(end);
        input.head.ticket = owner;
        input.head.extensions = blob(extension);
        input.bytes = bytes.as_ptr();
        input.len = bytes.len();
        input.sink = lend.sink();
        // SAFETY: as above.
        let mut out: DoorOut = unsafe { std::mem::zeroed() };
        // SAFETY: the live instance and all input/output bytes remain lent for this call.
        let result =
            unsafe { Safe::<Ingest>::enter(self.instance, slot::INGEST, &input, &mut out) };
        let ext = if out.head.extensions.len == 0 {
            &[][..]
        } else {
            // SAFETY: the answer lease remains owned until the release below.
            unsafe { std::slice::from_raw_parts(out.head.extensions.ptr, out.head.extensions.len) }
        };
        let open = extensions::get(ext, EXT_GUEST_OPEN).map(|bytes| Open::decode(bytes).unwrap());
        let answer = said(result, &out, lend);
        if out.head.lease != 0 {
            // SAFETY: all-zero is valid for these ABI inputs and outputs.
            let mut input: ReleaseIn = unsafe { std::mem::zeroed() };
            input.lease = out.head.lease;
            // SAFETY: as above.
            let mut released: OutHead = unsafe { std::mem::zeroed() };
            // SAFETY: this exact instance owns the returned lease, released once.
            assert_eq!(
                unsafe {
                    Safe::<life::Release<Ws>>::enter(
                        self.instance,
                        life_slot::RELEASE,
                        &input,
                        &mut released,
                    )
                },
                Outcome::Ready
            );
        }
        (answer, open)
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        shut(self.instance);
    }
}

#[test]
fn a_direct_upgrade_selects_its_own_generation_before_answering_or_reading_messages() {
    let host = Host::new();
    let wire = UPGRADE.to_vec();
    let mut lend = Lend::roomy();
    let (waiting, open) = host.ingest(&wire, &[], ticket(2), &mut lend);
    assert_eq!(waiting.outcome, Outcome::Ready);
    assert_eq!(open.unwrap().stream, 0);
    assert!(waiting.wire.is_empty() && waiting.pieces.is_empty());
    assert_ne!(waiting.flags & YIELD_MORE, 0);
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    let (admitted, open) = host.ingest(&wire, &policy(4, 44), ticket(2), &mut lend);
    assert!(open.is_none());
    assert_eq!(admitted.outcome, Outcome::Ready);
    assert!(admitted.wire.starts_with(b"HTTP/1.1 101"));
    assert!(admitted.pieces.is_empty());
    let (first, open) = host.ingest(&masked(b"first"), &[], ticket(3), &mut lend);
    assert!(open.is_none());
    assert_eq!(first.pieces[0].0, b"first");
    HANDED.with(|seen| assert_eq!(seen.borrow().as_slice(), &[(44, 4, 0)]));
    let next = masked(b"second");
    let (_, open) = host.ingest(&next, &policy(9, 99), ticket(4), &mut lend);
    assert!(
        open.is_none(),
        "an admitted session never selects a later generation"
    );
    HANDED.with(|seen| assert_eq!(seen.borrow().len(), 1));
}

#[test]
fn an_initial_generation_ack_uses_the_opening_cache_without_readmitting() {
    let host = Host::new();
    let mut lend = Lend::roomy();
    host.ingest(UPGRADE, &[], ticket(2), &mut lend);
    let current = Identity {
        listener: 7,
        generation: 1,
    }
    .encode()
    .unwrap();
    let ext = extensions::encode(&[(EXT_GUEST_CURRENT, &current)]);
    let (answer, _) = host.ingest(UPGRADE, &ext, ticket(2), &mut lend);
    assert_eq!(answer.outcome, Outcome::Ready);
    HANDED.with(|seen| assert_eq!(seen.borrow().as_slice(), &[(11, 1, 0)]));
}

#[test]
fn a_malformed_policy_reply_fails_before_any_upgrade_or_message_is_published() {
    let host = Host::new();
    let mut lend = Lend::roomy();
    host.ingest(UPGRADE, &[], ticket(2), &mut lend);
    let ext = extensions::encode(&[(EXT_GUEST_POLICY, b"invalid")]);
    let (answer, _) = host.ingest(UPGRADE, &ext, ticket(2), &mut lend);
    assert_eq!(answer.outcome, Outcome::Failed);
    assert!(answer.wire.is_empty() && answer.pieces.is_empty());
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn cancelling_a_direct_upgrade_opening_retires_its_buffer_and_framing() {
    let host = Host::new();
    let mut lend = Lend::roomy();
    let (_, open) = host.ingest(UPGRADE, &[], ticket(2), &mut lend);
    assert!(open.is_some());
    // SAFETY: all-zero is valid for these ABI input and output frames.
    let mut input: CancelIn = unsafe { std::mem::zeroed() };
    input.head.size = size_of::<CancelIn>() as u32;
    input.head.op = life_slot::CANCEL;
    input.ticket = ticket(2);
    // SAFETY: as above.
    let mut out: CancelOut = unsafe { std::mem::zeroed() };
    out.head.size = size_of::<CancelOut>() as u32;
    let door = crate::door::door();
    // SAFETY: this linked door owns its static transport table.
    let ops = unsafe { &*(*door).ops().cast::<Ops>() };
    // SAFETY: the live instance owns this outstanding ticket and the ABI frames stay lent.
    // Older contract snapshots declared this pointer safe; the current ABI requires unsafe.
    #[allow(unused_unsafe)]
    let outcome = unsafe {
        (ops.head.cancel.unwrap())(
            host.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
        .outcome()
    };
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(out.disposition, CANCEL_PARTIAL);
    let token = host.token;
    poke(host.instance, move |inst| {
        assert!(!inst.queues().contains_key(&token));
        assert!(!inst.framer.holds(token));
    });
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn a_host_refusal_is_framed_before_the_websocket_handshake_and_drains() {
    let host = Host::new();
    let mut lend = Lend::roomy();
    host.ingest(UPGRADE, &[], ticket(2), &mut lend);
    FLOW.with(|flow| flow.set(FLOW_STOP));
    let mut lend = Lend::new(3, 32, 2, 1);
    let (mut answer, _) = host.ingest(UPGRADE, &policy(2, 22), ticket(2), &mut lend);
    let mut wire = Vec::new();
    for _ in 0..100 {
        assert_eq!(answer.outcome, Outcome::Ready);
        wire.extend_from_slice(&answer.wire);
        if answer.flags & YIELD_MORE == 0 {
            break;
        }
        answer = host.ingest(&[], &[], ticket(3), &mut lend).0;
    }
    assert!(wire.starts_with(b"HTTP/1.1 403"));
    assert!(wire.ends_with(b"denied-verbatim"));
    assert_eq!(answer.flags & YIELD_ENDED, YIELD_ENDED);
}

#[test]
fn repeated_connection_normalization_happens_after_policy_reads_the_original_fields() {
    let host = Host::new();
    let request = String::from_utf8(UPGRADE.to_vec())
        .unwrap()
        .replace(
            "Connection: Upgrade\r\n",
            "Connection: keep-alive\r\nConnection: Upgrade\r\nX-Policy: original\r\n",
        )
        .into_bytes();
    let mut lend = Lend::roomy();
    let (waiting, open) = host.ingest(&request, &[], ticket(2), &mut lend);
    assert!(waiting.wire.is_empty());
    assert!(open.is_some());
    let (admitted, _) = host.ingest(&request, &policy(4, 44), ticket(2), &mut lend);
    assert!(admitted.wire.starts_with(b"HTTP/1.1 101"));
    FIELDS.with(|seen| {
        let fields = seen.borrow();
        let connection: Vec<_> = fields
            .iter()
            .filter(|(name, _)| name == b"connection")
            .map(|(_, value)| value.as_slice())
            .collect();
        assert_eq!(
            connection,
            [b"keep-alive".as_slice(), b"Upgrade".as_slice()]
        );
        assert!(fields
            .iter()
            .any(|(name, value)| name == b"x-policy" && value == b"original"));
    });
}

#[test]
fn malformed_direct_upgrade_returns_http_error_before_policy_admission() {
    let host = Host::new();
    let mut lend = Lend::new(3, 64, 2, 1);
    let (mut answer, open) = host.ingest(
        b"GET / HTTP/1.1\r\nbad name: value\r\n\r\n",
        &[],
        ticket(2),
        &mut lend,
    );
    assert!(open.is_none());
    let mut wire = Vec::new();
    for _ in 0..100 {
        assert_eq!(answer.outcome, Outcome::Ready);
        wire.extend_from_slice(&answer.wire);
        if answer.flags & YIELD_MORE == 0 {
            break;
        }
        answer = host.ingest(&[], &[], ticket(3), &mut lend).0;
    }
    assert!(wire.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert!(wire.ends_with(b"content-length: 0\r\n\r\n"));
    assert_eq!(answer.flags & YIELD_ENDED, YIELD_ENDED);
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn invalid_nonce_or_missing_host_is_refused_before_policy_hand_in() {
    let valid = String::from_utf8(UPGRADE.to_vec()).unwrap();
    for request in [
        valid.replace("Host: svc.test\r\n", ""),
        valid.replace("Host: svc.test", "Host: bad host"),
        valid.replace("Host: svc.test", "Host: bad\thost"),
        valid.replace("dGhlIHNhbXBsZSBub25jZQ==", "x"),
        valid.replace("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="),
    ] {
        let host = Host::new();
        let mut lend = Lend::roomy();
        let (answer, open) = host.ingest(request.as_bytes(), &[], ticket(2), &mut lend);
        assert!(open.is_none());
        assert_eq!(answer.outcome, Outcome::Ready);
        assert!(answer.wire.starts_with(b"HTTP/1.1 400"));
        assert_ne!(answer.flags & YIELD_ENDED, 0);
        HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    }
}

#[test]
fn opening_without_upgrade_fields_is_refused_before_policy_hand_in() {
    let request =
        "GET /x HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    let host = Host::new();
    let mut lend = Lend::roomy();
    let (answer, open) = host.ingest(request.as_bytes(), &[], ticket(2), &mut lend);
    assert!(open.is_none());
    assert!(answer.wire.starts_with(b"HTTP/1.1 400"));
    assert_ne!(answer.flags & YIELD_ENDED, 0);
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn opening_with_unsupported_version_gets_426_before_policy_hand_in() {
    let request = String::from_utf8(UPGRADE.to_vec())
        .unwrap()
        .replace("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8");
    let host = Host::new();
    let mut lend = Lend::roomy();
    let (answer, open) = host.ingest(request.as_bytes(), &[], ticket(2), &mut lend);
    assert!(open.is_none());
    assert!(
        answer.wire.starts_with(b"HTTP/1.1 426"),
        "{:?}",
        String::from_utf8_lossy(&answer.wire)
    );
    let wire = String::from_utf8_lossy(&answer.wire).to_ascii_lowercase();
    assert!(wire.contains("sec-websocket-version: 13"));
    assert!(wire.contains("upgrade: websocket"));
    assert_ne!(answer.flags & YIELD_ENDED, 0);
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

/// Offer `bytes` as a second chunk of the opening under `policy`, as an admitting call.
fn admit(host: &Host, request: &[u8], policy: &[u8]) -> Said {
    let mut lend = Lend::roomy();
    host.ingest(request, &[], ticket(2), &mut lend);
    host.ingest(request, policy, ticket(2), &mut lend).0
}

fn assert_refused_with(answer: &Said, status: &[u8], cause: u32, line: u32) {
    assert_eq!(answer.outcome, Outcome::Ready);
    assert!(answer.wire.starts_with(status), "{:?}", answer.wire);
    assert!(answer.wire.ends_with(b"denied-verbatim"));
    assert_eq!(answer.flags & YIELD_ENDED, YIELD_ENDED);
    REFUSED.with(|seen| assert_eq!(seen.borrow().as_slice(), &[(cause, line)]));
    HANDED.with(|seen| assert!(seen.borrow().is_empty(), "no session was admitted"));
}

#[test]
fn an_opening_no_route_matches_is_refused_with_no_route_and_no_line() {
    let host = Host::new();
    let other = policy_of(3, &[guest_line(3, 31, METHOD_GET, "/other", 0)]);
    let answer = admit(&host, UPGRADE, &other);
    assert_refused_with(&answer, b"HTTP/1.1 403", REFUSE_NO_ROUTE, LINE_NONE);
}

#[test]
fn a_matching_path_with_the_wrong_method_is_refused_as_a_method_miss_on_that_line() {
    let host = Host::new();
    let post = policy_of(3, &[guest_line(3, 31, METHOD_POST, "/echo", 0)]);
    let answer = admit(&host, UPGRADE, &post);
    assert_refused_with(&answer, b"HTTP/1.1 403", REFUSE_METHOD_MISS, 31);
}

#[test]
fn a_later_line_that_admits_the_method_wins_over_an_earlier_method_miss() {
    let host = Host::new();
    let lines = policy_of(
        3,
        &[
            guest_line(3, 31, METHOD_POST, "/echo", 0),
            guest_line(3, 32, METHOD_GET, "/echo", 0),
        ],
    );
    let answer = admit(&host, UPGRADE, &lines);
    assert!(answer.wire.starts_with(b"HTTP/1.1 101"));
    HANDED.with(|seen| assert_eq!(seen.borrow().as_slice(), &[(32, 3, 0)]));
    REFUSED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn a_host_stop_refuses_with_check_failed_on_the_matched_line() {
    let host = Host::new();
    FLOW.with(|flow| flow.set(FLOW_STOP));
    let answer = admit(&host, UPGRADE, &policy(2, 22));
    assert_eq!(answer.outcome, Outcome::Ready);
    assert!(answer.wire.starts_with(b"HTTP/1.1 403"));
    REFUSED.with(|seen| assert_eq!(seen.borrow().as_slice(), &[(REFUSE_CHECK_FAILED, 22)]));
}

#[test]
fn a_line_demanding_inbound_authentication_points_is_refused_before_the_host_is_asked() {
    let host = Host::new();
    let points = policy_of(3, &[guest_line(3, 31, METHOD_GET, "/echo", 1)]);
    let answer = admit(&host, UPGRADE, &points);
    assert_eq!(answer.outcome, Outcome::Refused);
    assert!(answer.wire.is_empty() && answer.pieces.is_empty());
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    REFUSED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn a_host_that_continues_without_a_session_fails_the_admission() {
    let host = Host::new();
    HAND.with(|mode| mode.set(HAND_NO_UNIT));
    let answer = admit(&host, UPGRADE, &policy(2, 22));
    assert_eq!(answer.outcome, Outcome::Failed);
    assert!(answer.wire.is_empty() && answer.pieces.is_empty());
    HANDED.with(|seen| assert_eq!(seen.borrow().len(), 1, "the host was asked once"));
    // The failed admission stays failed: a later call neither re-asks the host nor answers.
    let (again, _) = host.ingest(UPGRADE, &[], ticket(2), &mut Lend::roomy());
    assert_eq!(again.outcome, Outcome::Failed);
    HANDED.with(|seen| assert_eq!(seen.borrow().len(), 1));
}

#[test]
fn a_failing_hand_in_or_refusal_service_fails_without_publishing_an_answer() {
    let host = Host::new();
    HAND.with(|mode| mode.set(HAND_ERROR));
    let answer = admit(&host, UPGRADE, &policy(2, 22));
    assert_eq!(answer.outcome, Outcome::Failed);
    assert!(answer.wire.is_empty() && answer.pieces.is_empty());
    HANDED.with(|seen| assert_eq!(seen.borrow().len(), 1, "the host was asked to admit"));

    let host = Host::new();
    REFUSE_ERROR.with(|fail| fail.set(true));
    let other = policy_of(3, &[guest_line(3, 31, METHOD_GET, "/other", 0)]);
    let answer = admit(&host, UPGRADE, &other);
    assert_eq!(answer.outcome, Outcome::Failed);
    assert!(answer.wire.is_empty() && answer.pieces.is_empty());
    REFUSED.with(|seen| assert_eq!(seen.borrow().len(), 1, "the host was asked to refuse"));
}

#[test]
fn a_host_without_unit_services_fails_the_admission() {
    let host = Host::without_services();
    let answer = admit(&host, UPGRADE, &policy(2, 22));
    assert_eq!(answer.outcome, Outcome::Failed);
    assert!(answer.wire.is_empty() && answer.pieces.is_empty());
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    REFUSED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn a_second_ticket_cannot_take_over_an_opening_another_one_owns() {
    let host = Host::new();
    let mut lend = Lend::roomy();
    let (waiting, open) = host.ingest(UPGRADE, &[], ticket(2), &mut lend);
    assert_eq!(waiting.outcome, Outcome::Ready);
    assert!(
        open.is_some(),
        "ticket 2 owns the opening and waits for a policy"
    );
    let (stolen, _) = host.ingest(UPGRADE, &policy(4, 44), ticket(3), &mut lend);
    assert_eq!(stolen.outcome, Outcome::Failed);
    assert!(stolen.wire.is_empty());
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
    let (after, _) = host.ingest(UPGRADE, &policy(4, 44), ticket(2), &mut lend);
    assert_eq!(
        after.outcome,
        Outcome::Failed,
        "the admission failed for good"
    );
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

fn assert_bad_request(answer: &Said) {
    assert_eq!(answer.outcome, Outcome::Ready);
    assert!(
        answer.wire.starts_with(b"HTTP/1.1 400"),
        "{:?}",
        answer.wire
    );
    assert_ne!(answer.flags & YIELD_ENDED, 0);
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn an_opening_that_never_completes_within_64_kib_is_a_bad_request() {
    let host = Host::new();
    let mut request = b"GET /echo HTTP/1.1\r\nX: ".to_vec();
    request.resize(65536 + 1, b'a');
    let (answer, open) = host.ingest(&request, &[], ticket(2), &mut Lend::roomy());
    assert!(open.is_none());
    assert_bad_request(&answer);
}

#[test]
fn an_opening_whose_head_ends_past_64_kib_is_a_bad_request() {
    let host = Host::new();
    let mut request = b"GET /echo HTTP/1.1\r\nX: ".to_vec();
    request.resize(65536 + 8, b'a');
    request.extend_from_slice(b"\r\n\r\n");
    let (answer, open) = host.ingest(&request, &[], ticket(2), &mut Lend::roomy());
    assert!(open.is_none());
    assert_bad_request(&answer);
}

#[test]
fn an_opening_the_carrier_ends_before_completing_is_a_bad_request() {
    let host = Host::new();
    let (answer, open) = host.ingest_ending(
        &UPGRADE[..UPGRADE.len() - 2],
        &[],
        ticket(2),
        &mut Lend::roomy(),
        true,
    );
    assert!(open.is_none());
    assert_bad_request(&answer);
}

/// `cancel` of `ticket` on `host`: the outcome and the disposition.
fn cancel(instance: *mut c_void, ticket: Ticket) -> (Outcome, u32) {
    // SAFETY: all-zero is valid for these ABI input and output frames.
    let mut input: CancelIn = unsafe { std::mem::zeroed() };
    input.head.size = size_of::<CancelIn>() as u32;
    input.head.op = life_slot::CANCEL;
    input.ticket = ticket;
    // SAFETY: as above.
    let mut out: CancelOut = unsafe { std::mem::zeroed() };
    out.head.size = size_of::<CancelOut>() as u32;
    let door = crate::door::door();
    // SAFETY: this linked door owns its static transport table.
    let ops = unsafe { &*(*door).ops().cast::<Ops>() };
    // SAFETY: the live instance owns the ticket and the ABI frames stay lent.
    #[allow(unused_unsafe)]
    let outcome = unsafe {
        (ops.head.cancel.unwrap())(
            instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
        .outcome()
    };
    (outcome, out.disposition)
}

#[test]
fn cancelling_a_ticket_that_owns_no_opening_moves_nothing() {
    let host = Host::new();
    let mut lend = Lend::roomy();
    host.ingest(UPGRADE, &[], ticket(2), &mut lend);
    let (outcome, disposition) = cancel(host.instance, ticket(9));
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(disposition, CANCEL_NOTHING_MOVED);
    let token = host.token;
    poke(host.instance, move |inst| {
        assert!(
            inst.queues().contains_key(&token),
            "the owner's queue stays"
        );
    });
    // An admitted framing is no opening to cancel, whoever's ticket it was.
    let (admitted, _) = host.ingest(UPGRADE, &policy(4, 44), ticket(2), &mut lend);
    assert!(admitted.wire.starts_with(b"HTTP/1.1 101"));
    assert_eq!(
        cancel(host.instance, ticket(2)),
        (Outcome::Ready, CANCEL_NOTHING_MOVED)
    );
}

#[test]
fn cancel_fails_busy_while_a_framing_is_held_and_still_cancels_a_poisoned_one() {
    let host = Host::new();
    host.ingest(UPGRADE, &[], ticket(2), &mut Lend::roomy());
    let token = host.token;
    let (instance, owner) = (host.instance, ticket(2));
    poke(instance, move |inst| {
        let slot = inst.queues().get(&token).cloned().unwrap();
        let held = slot.lock().unwrap();
        assert_eq!(cancel(instance, owner).0, Outcome::Failed);
        drop(held);
        // A thread dying with the framing held poisons its queue.
        let poison = Arc::clone(&slot);
        let _ = std::thread::spawn(move || {
            let _held = poison.lock().unwrap();
            panic!("poison the framing's queue");
        })
        .join();
        assert!(slot.is_poisoned());
    });
    let (outcome, disposition) = cancel(instance, owner);
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(disposition, CANCEL_PARTIAL);
    poke(instance, move |inst| {
        assert!(!inst.queues().contains_key(&token));
        assert!(!inst.framer.holds(token));
    });
}

#[test]
fn an_ingest_on_a_poisoned_framing_fails_instead_of_reading_it() {
    let host = Host::new();
    host.ingest(UPGRADE, &[], ticket(2), &mut Lend::roomy());
    let token = host.token;
    poke(host.instance, move |inst| {
        let slot = inst.queues().get(&token).cloned().unwrap();
        let _ = std::thread::spawn(move || {
            let _held = slot.lock().unwrap();
            panic!("poison the framing's queue");
        })
        .join();
    });
    let (answer, _) = host.ingest(UPGRADE, &policy(4, 44), ticket(2), &mut Lend::roomy());
    assert_eq!(answer.outcome, Outcome::Failed);
    assert!(answer.wire.is_empty());
    HANDED.with(|seen| assert!(seen.borrow().is_empty()));
}

#[test]
fn begin_refuses_an_accepting_framing_whose_initial_policy_is_malformed() {
    let host = Host::new();
    let bad = extensions::encode(&[(EXT_GUEST_POLICY, b"invalid")]);
    // SAFETY: all-zero is valid for this ABI input.
    let mut input: BeginIn = unsafe { std::mem::zeroed() };
    input.side = SIDE_ACCEPT;
    input.scheme = SCHEME_PLAIN;
    input.head.ticket = ticket(5);
    input.head.extensions = blob(&bad);
    let mut lend = Lend::roomy();
    input.sink = lend.sink();
    // SAFETY: all-zero is valid for this ABI output.
    let mut out: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the live instance and all buffers stay lent for the call.
    let outcome = unsafe { Safe::<Begin>::enter(host.instance, slot::BEGIN, &input, &mut out) };
    assert_ne!(outcome, Outcome::Ready);
}

#[test]
fn a_message_emitted_before_the_upgrade_is_admitted_is_refused_and_writes_nothing() {
    let host = Host::new();
    let mut lend = Lend::roomy();
    let early = emit(host.instance, host.token, b"early", &mut lend);
    assert_ne!(early.outcome, Outcome::Ready);
    assert!(early.wire.is_empty() && early.pieces.is_empty());
    let (admitted, _) = {
        host.ingest(UPGRADE, &[], ticket(2), &mut lend);
        host.ingest(UPGRADE, &policy(4, 44), ticket(2), &mut lend)
    };
    assert!(admitted.wire.starts_with(b"HTTP/1.1 101"));
    let sent = emit(host.instance, host.token, b"late", &mut lend);
    assert_eq!(sent.outcome, Outcome::Ready);
    assert_eq!(sent.wire, b"\x82\x04late");
}
