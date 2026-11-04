// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::service::{
    AuthAnswer, AuthRef, HostSlots, RefusalAnswer, ServiceOut, UnitHandInIn, UnitRef, UnitRefuseIn,
    FLOW_CONTINUE, FLOW_STOP, SCHEME_PLAIN, SERVICES,
};
use busbar_contract::abi::mechanism::call::{Blob, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::transport::guest_policy::{
    self, GuestLine, Identity, Open, EXT_GUEST_CURRENT, EXT_GUEST_OPEN, EXT_GUEST_POLICY,
};
use busbar_contract::abi::transport::route::{METHOD_GET, PATH_EXACT};
use busbar_contract::abi::transport::CANCEL_PARTIAL;
use std::cell::Cell;
use std::mem::size_of;

thread_local! {
    static HANDED: RefCell<Vec<(u32, u64, u64)>> = const { RefCell::new(Vec::new()) };
    static FLOW: Cell<u32> = const { Cell::new(FLOW_CONTINUE) };
    static FIELDS: RefCell<Vec<(Vec<u8>, Vec<u8>)>> = const { RefCell::new(Vec::new()) };
}

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
        input.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow: FLOW.with(Cell::get),
            unit: UnitRef {
                id: 17,
                mac: input.auth.mac,
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

fn policy(generation: u64, line: u32) -> Vec<u8> {
    let line = GuestLine {
        line,
        points: 0,
        auth: AuthRef {
            id: u64::from(line),
            mac: generation,
        },
        body_limit: 0,
        methods: METHOD_GET,
        path_form: PATH_EXACT,
        path: "/echo".into(),
        fields: Vec::new(),
        rung: 0,
    };
    extensions::encode(&[(
        EXT_GUEST_POLICY,
        &guest_policy::encode(7, generation, &[line]).unwrap(),
    )])
}

struct Host {
    instance: *mut c_void,
    token: u64,
    _tables: Box<HostTables>,
    _slots: Box<HostSlots>,
}

impl Host {
    fn new() -> Self {
        HANDED.with(|seen| seen.borrow_mut().clear());
        FIELDS.with(|seen| seen.borrow_mut().clear());
        FLOW.with(|flow| flow.set(FLOW_CONTINUE));
        // SAFETY: these ABI tables are plain C data with valid zero defaults.
        let mut slots: Box<HostSlots> = Box::new(unsafe { std::mem::zeroed() });
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = SERVICES;
        slots.unit_hand_in = Some(hand_in);
        slots.unit_refuse = Some(refuse);
        // SAFETY: as above.
        let mut tables: Box<HostTables> = Box::new(unsafe { std::mem::zeroed() });
        tables.size = size_of::<HostTables>() as u32;
        tables.services = &*slots;
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
        // SAFETY: all-zero is valid for these ABI inputs and outputs.
        let mut input: IngestIn = unsafe { std::mem::zeroed() };
        input.framing = self.token;
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
    let original = request.clone();
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
    assert_eq!(request, original);
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
