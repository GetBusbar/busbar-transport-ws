// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::transport::adopted_session::{
    AdoptedSession, EXT_ADOPTED_SESSION, SUPPORT_ADOPTED_SESSION,
};

fn context(stream: u64) -> AdoptedSession {
    AdoptedSession {
        stream,
        unit: UnitRef { id: 71, mac: 993 },
    }
}

fn masked(bytes: &[u8]) -> Vec<u8> {
    let mask = [1, 2, 3, 4];
    let mut wire = vec![0x82, 0x80 | u8::try_from(bytes.len()).unwrap()];
    wire.extend_from_slice(&mask);
    wire.extend(bytes.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    wire
}

fn adopt(p: *mut c_void, extension: &[u8], leftover: &[u8], l: &mut Lend) -> (Said, u64) {
    // SAFETY: plain C data; all-zero is valid.
    let mut i: AdoptIn = unsafe { std::mem::zeroed() };
    i.side = SIDE_ACCEPT;
    i.head.extensions = Blob {
        ptr: extension.as_ptr(),
        len: extension.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    i.leftover = leftover.as_ptr();
    i.leftover_len = leftover.len();
    i.sink = l.sink();
    // SAFETY: plain C data; all-zero is valid.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    // SAFETY: the live instance and all input/output buffers remain lent for the call.
    let r = unsafe { Safe::<Adopt>::enter(p, slot::ADOPT, &i, &mut o) };
    (said(r, &o, l), o.framing)
}

fn stream_op(p: *mut c_void, token: u64, stream: u64, refuse: bool, l: &mut Lend) -> Said {
    let bytes = b"ok";
    // SAFETY: plain C data; all-zero is valid.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    let r = if refuse {
        // SAFETY: plain C data; all-zero is valid.
        let mut i: RefuseIn = unsafe { std::mem::zeroed() };
        i.framing = token;
        i.has_stream = 1;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = l.sink();
        // SAFETY: the live instance and all input/output buffers remain lent for the call.
        unsafe { Safe::<Refuse>::enter(p, slot::REFUSE, &i, &mut o) }
    } else {
        // SAFETY: plain C data; all-zero is valid.
        let mut i: EmitIn = unsafe { std::mem::zeroed() };
        i.framing = token;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = 1;
        i.sink = l.sink();
        // SAFETY: the live instance and all input/output buffers remain lent for the call.
        unsafe { Safe::<Emit>::enter(p, slot::EMIT, &i, &mut o) }
    };
    said(r, &o, l)
}

fn streams(l: &Lend, answer: &Said, stream: u64) {
    for piece in &l.pieces[..answer.pieces.len()] {
        assert_eq!(piece.stream, stream);
    }
    for head in &l.heads[..answer.reasons.len()] {
        assert_eq!(head.stream, stream);
    }
}

#[test]
fn adoption_keeps_the_inherited_stream_from_initial_leftovers_through_finish() {
    for stream in [0, 1, 37, u64::MAX] {
        let p = instance();
        let previous = accepted(p);
        let mut extension = extensions::encode(&[(EXT_ADOPTED_SESSION, &context(stream).encode())]);
        let leftover = UPGRADE.to_vec();
        let original = leftover.clone();
        let mut l = Lend::new(1, 3, 1, 1);
        let (mut answer, token) = adopt(p, &extension, &leftover, &mut l);
        assert_eq!(answer.outcome, Outcome::Ready);
        assert_ne!(token, 0, "the framer allocated its own local token");
        assert_ne!(token, previous, "adoption allocated a fresh local token");
        assert_eq!(
            leftover, original,
            "the upgrade and leftover bytes are unchanged"
        );
        extension.fill(0);
        drop(extension);
        drop(leftover);
        let (mut wire, mut payload) = (Vec::new(), Vec::new());
        for _ in 0..1000 {
            assert_eq!(answer.outcome, Outcome::Ready);
            streams(&l, &answer, stream);
            wire.extend_from_slice(&answer.wire);
            for (bytes, _) in &answer.pieces {
                payload.extend_from_slice(bytes);
            }
            if answer.flags & YIELD_MORE == 0 {
                break;
            }
            answer = ingest(p, token, &[], false, &mut l);
        }
        assert_eq!(answer.flags & YIELD_MORE, 0);
        assert!(wire.starts_with(b"HTTP/1.1 101"));
        assert!(
            payload.is_empty(),
            "no message arrives before the 101 is drained"
        );
        let mut initial = masked(b"initial-payload");
        let mut heard = ingest(p, token, &initial, false, &mut l);
        initial.fill(0);
        drop(initial);
        for _ in 0..1000 {
            streams(&l, &heard, stream);
            for (bytes, _) in &heard.pieces {
                payload.extend_from_slice(bytes);
            }
            if heard.flags & YIELD_MORE == 0 {
                break;
            }
            heard = ingest(p, token, &[], false, &mut l);
        }
        assert_eq!(heard.flags & YIELD_MORE, 0);
        assert_eq!(payload, b"initial-payload");

        let mut roomy = Lend::roomy();
        for refuse in [false, true] {
            let wrong = stream_op(p, token, stream.wrapping_add(1), refuse, &mut roomy);
            assert_eq!(wrong.outcome, Outcome::Failed);
            assert!(wrong.wire.is_empty());
            assert!(wrong.pieces.is_empty());
        }
        let valid = stream_op(p, token, stream, false, &mut roomy);
        assert_eq!(valid.outcome, Outcome::Ready);
        assert_eq!(valid.wire, b"\x82\x02ok");
        let heard = ingest(p, token, &masked(b"later"), false, &mut roomy);
        assert_eq!(heard.pieces[0].0, b"later");
        streams(&roomy, &heard, stream);

        let mut done = finish(p, token, &mut l);
        assert_ne!(done.flags & YIELD_MORE, 0, "the close is drained in parts");
        streams(&l, &done, stream);
        for _ in 0..1000 {
            if done.flags & YIELD_MORE == 0 {
                break;
            }
            done = finish(p, token, &mut l);
            streams(&l, &done, stream);
        }
        assert_eq!(done.flags & YIELD_MORE, 0);
        poke(p, move |inst| {
            assert!(!inst.queues().contains_key(&token));
            assert!(!inst.framer.holds(token));
        });
        assert_eq!(
            stream_op(p, token, stream, false, &mut roomy).outcome,
            Outcome::Failed
        );
        finish(p, previous, &mut roomy);
        shut(p);
    }
}

#[test]
fn malformed_session_values_fail_before_opening_and_contextless_adoption_still_works() {
    let p = instance();
    let valid = context(37).encode();
    let mut invalid: Vec<Vec<u8>> = (0..valid.len()).map(|n| valid[..n].to_vec()).collect();
    let mut version = valid;
    version[0] = 2;
    invalid.push(version.to_vec());
    invalid.push(
        AdoptedSession {
            unit: UnitRef::NONE,
            ..context(37)
        }
        .encode()
        .to_vec(),
    );
    let mut trailing = valid.to_vec();
    trailing.push(0);
    invalid.push(trailing);
    for value in invalid {
        let ext = extensions::encode(&[(EXT_ADOPTED_SESSION, &value)]);
        let (answer, token) = adopt(p, &ext, UPGRADE, &mut Lend::roomy());
        assert_eq!(answer.outcome, Outcome::Failed);
        assert_eq!(token, 0);
        assert!(answer.wire.is_empty());
        assert!(answer.pieces.is_empty());
        poke(p, |inst| assert!(inst.queues().is_empty()));
    }
    for ext in [Vec::new(), extensions::encode(&[("future.unknown", b"1")])] {
        let mut l = Lend::roomy();
        let (answer, token) = adopt(p, &ext, UPGRADE, &mut l);
        assert_eq!(answer.outcome, Outcome::Ready);
        let heard = ingest(p, token, &masked(b"contextless"), false, &mut l);
        streams(&l, &heard, 0);
        assert_eq!(heard.pieces[0].0, b"contextless");
        finish(p, token, &mut l);
    }
    shut(p);
}

#[test]
fn an_adopted_head_maps_its_slots_and_piece_to_the_same_external_stream() {
    let p = instance();
    let ext = extensions::encode(&[(EXT_ADOPTED_SESSION, &context(37).encode())]);
    let (_, token) = adopt(p, &ext, UPGRADE, &mut Lend::roomy());

    poke(p, move |inst| {
        let slot = inst.queues().get(&token).cloned().unwrap();
        let mut owed = slot.lock().unwrap();
        let mut head = Piece::plain(0, b"x-adopted: yes\r\n".to_vec(), true);
        head.fields = true;
        head.status = Some((101, STATUS_SUCCESS));
        head.reason = Some(b"Inherited".to_vec());
        owed.pieces.push_back(head);
    });
    let mut l = Lend::roomy();
    let heard = ingest(p, token, &[], false, &mut l);
    assert_eq!(heard.reasons, [b"Inherited".to_vec()]);
    assert_eq!(heard.pieces[0].0, b"x-adopted: yes\r\n");
    streams(&l, &heard, 37);
    finish(p, token, &mut l);
    shut(p);
}

#[test]
fn a_refusal_for_the_inherited_stream_closes_that_session() {
    let p = instance();
    let ext = extensions::encode(&[(EXT_ADOPTED_SESSION, &context(37).encode())]);
    let (_, token) = adopt(p, &ext, UPGRADE, &mut Lend::roomy());
    let mut l = Lend::roomy();
    let refused = stream_op(p, token, 37, true, &mut l);
    assert_eq!(refused.outcome, Outcome::Ready);
    assert!(refused.wire.starts_with(b"\x82\x02ok"));
    assert_ne!(refused.flags & YIELD_ENDED, 0);
    assert!(!refused.pieces.is_empty());
    streams(&l, &refused, 37);
    finish(p, token, &mut l);
    poke(p, move |inst| {
        assert!(!inst.queues().contains_key(&token));
        assert!(!inst.framer.holds(token));
    });
    shut(p);
}

#[test]
fn the_door_advertises_the_shared_adopted_session_capability() {
    let blob = STATEMENT.extensions;
    // SAFETY: the Statement's extension buffer is static data owned by this crate.
    let bytes = if blob.len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(blob.ptr, blob.len) }
    };
    assert_eq!(
        extensions::get(bytes, EXT_ADOPTED_SESSION),
        Some(SUPPORT_ADOPTED_SESSION)
    );
}

/// Begin and HTTP hand-off use the same accepted request validation, at every header split.
#[test]
fn accepted_connection_lists_are_combined_without_changing_original_request_bytes() {
    for connection in [
        "Connection: keep-alive\r\nConnection: Upgrade\r\n",
        "Connection: Upgrade\r\nConnection: keep-alive\r\n",
        "cOnNeCtIoN: keep-alive, X-Hop\r\nconnection: uPgRaDe\r\n",
        "Connection: keep-alive, Upgrade\r\n",
    ] {
        let request = format!("GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\n{connection}Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Hop: untouched\r\nAuthorization: Bearer original\r\n\r\n").into_bytes();
        let original = request.clone();
        for adopted in [false, true] {
            for split in 0..=request.len() {
                let p = instance();
                let mut l = Lend::roomy();
                let ext = extensions::encode(&[(EXT_ADOPTED_SESSION, &context(37).encode())]);
                let (first, token) = if adopted {
                    adopt(p, &ext, &request[..split], &mut l)
                } else {
                    let (_, token) = begin(p, SIDE_ACCEPT, "", &[], &mut l);
                    (ingest(p, token, &request[..split], false, &mut l), token)
                };
                assert_eq!(
                    first.outcome,
                    Outcome::Ready,
                    "adopt {adopted}, split {split}"
                );
                let second = ingest(p, token, &request[split..], false, &mut l);
                assert_eq!(second.outcome, Outcome::Ready);
                let mut wire = first.wire;
                wire.extend_from_slice(&second.wire);
                assert!(
                    wire.starts_with(b"HTTP/1.1 101"),
                    "adopt {adopted}, split {split}: {wire:?}"
                );
                assert!(first.pieces.is_empty() && second.pieces.is_empty());
                let heard = ingest(p, token, &masked(b"after-101"), false, &mut l);
                assert_eq!(heard.pieces[0].0, b"after-101");
                streams(&l, &heard, if adopted { 37 } else { 0 });
                assert_eq!(request, original, "policy and hand-off bytes stay original");
                finish(p, token, &mut l);
                shut(p);
            }
        }
    }
}

#[test]
fn combining_accepted_connection_fields_keeps_every_other_validation_and_early_data_refusal() {
    let request = |connection: &str, upgrade: &str, key: &str, version: &str| {
        format!("GET /echo HTTP/1.1\r\nHost: svc.test\r\n{upgrade}{connection}{key}{version}\r\n")
            .into_bytes()
    };
    let connection = "Connection: keep-alive\r\nConnection: Upgrade\r\n";
    let upgrade = "Upgrade: websocket\r\n";
    let key = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
    let version = "Sec-WebSocket-Version: 13\r\n";
    let mut early = request(connection, upgrade, key, version);
    early.extend_from_slice(&masked(b"too-early"));
    for (bytes, status) in [
        (
            request(
                "Connection: keep-alive\r\nConnection: X-Hop\r\n",
                upgrade,
                key,
                version,
            ),
            400,
        ),
        (request(connection, "Upgrade: other\r\n", key, version), 400),
        (request(connection, "", key, version), 400),
        (request(connection, upgrade, "", version), 400),
        (
            request(connection, upgrade, key, "Sec-WebSocket-Version: 12\r\n"),
            426,
        ),
        (early, 400),
    ] {
        for adopted in [false, true] {
            let p = instance();
            let mut l = Lend::roomy();
            let (answer, token) = if adopted {
                let ext = extensions::encode(&[(EXT_ADOPTED_SESSION, &context(37).encode())]);
                adopt(p, &ext, &bytes, &mut l)
            } else {
                let (_, token) = begin(p, SIDE_ACCEPT, "", &[], &mut l);
                (ingest(p, token, &bytes, false, &mut l), token)
            };
            assert_eq!(answer.outcome, Outcome::Ready);
            assert!(
                answer
                    .wire
                    .starts_with(format!("HTTP/1.1 {status}").as_bytes()),
                "{status}: {:?}",
                answer.wire
            );
            assert_ne!(answer.flags & YIELD_ENDED, 0);
            assert!(answer.pieces.iter().all(|(bytes, _)| bytes != b"too-early"));
            finish(p, token, &mut l);
            shut(p);
        }
    }
}

#[test]
fn connection_normalization_preserves_unread_frames_at_the_original_request_read_boundary() {
    let mut request = b"GET /echo HTTP/1.1\r\nHost: svc.test\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Pad: ".to_vec();
    request.resize(4096 - 4, b'p');
    request.extend_from_slice(b"\r\n\r\n");
    let payload = b"\xaa\xbb\x81\x82\x00\x00\x00\x00\xff\xff";
    let frame = masked(payload);
    request.extend_from_slice(&frame[..8]);
    for adopted in [false, true] {
        let p = instance();
        let mut l = Lend::roomy();
        let (answer, token) = if adopted {
            let ext = extensions::encode(&[(EXT_ADOPTED_SESSION, &context(37).encode())]);
            adopt(p, &ext, &request, &mut l)
        } else {
            let (_, token) = begin(p, SIDE_ACCEPT, "", &[], &mut l);
            (ingest(p, token, &request, false, &mut l), token)
        };
        assert_eq!(answer.outcome, Outcome::Ready);
        assert!(answer.wire.starts_with(b"HTTP/1.1 101"));
        assert!(answer.pieces.is_empty());
        let rest = ingest(p, token, &frame[8..], false, &mut l);
        assert_eq!(rest.outcome, Outcome::Ready);
        assert_eq!(rest.flags & YIELD_ENDED, 0);
        assert_eq!(rest.pieces[0].0, payload);
        streams(&l, &rest, if adopted { 37 } else { 0 });
        finish(p, token, &mut l);
        shut(p);
    }
}

fn prewire_emit(
    p: *mut c_void,
    token: u64,
    status: u32,
    bytes: &[u8],
    end: bool,
    flags: u32,
    l: &mut Lend,
) -> Said {
    // SAFETY: these ABI frames permit all-zero initialization.
    let mut i: EmitIn = unsafe { std::mem::zeroed() };
    i.framing = token;
    i.stream = 37;
    i.status = status;
    i.bytes = bytes.as_ptr();
    i.len = bytes.len();
    i.end_of_frame = u32::from(end);
    i.flags = flags;
    i.sink = l.sink();
    // SAFETY: all buffers and the live instance stay lent for this crossing.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    let r = unsafe { Safe::<Emit>::enter(p, slot::EMIT, &i, &mut o) };
    said(r, &o, l)
}

fn prewire_refuse(
    p: *mut c_void,
    token: u64,
    status: u32,
    bytes: &[u8],
    head_sent: bool,
    l: &mut Lend,
) -> Said {
    // SAFETY: these ABI frames permit all-zero initialization.
    let mut i: RefuseIn = unsafe { std::mem::zeroed() };
    i.framing = token;
    i.stream = 37;
    i.has_stream = 1;
    i.status = status;
    i.head_sent = u32::from(head_sent);
    i.bytes = bytes.as_ptr();
    i.len = bytes.len();
    i.sink = l.sink();
    // SAFETY: all buffers and the live instance stay lent for this crossing.
    let mut o: DoorOut = unsafe { std::mem::zeroed() };
    let r = unsafe { Safe::<Refuse>::enter(p, slot::REFUSE, &i, &mut o) };
    said(r, &o, l)
}

fn prewire_extension() -> Vec<u8> {
    extensions::encode(&[
        (EXT_ADOPTED_SESSION, &context(37).encode()),
        ("session.prewire", b"1"),
    ])
}

fn staged() -> (*mut c_void, u64, Said) {
    let p = instance();
    let ext = prewire_extension();
    let (answer, token) = adopt(p, &ext, UPGRADE, &mut Lend::roomy());
    (p, token, answer)
}

#[test]
fn prewire_success_has_a_typed_inherited_acceptance_marker() {
    let p = instance();
    let ext = prewire_extension();
    let mut l = Lend::new(64 * 1024, 64 * 1024, 16, 0);
    let (answer, token) = adopt(p, &ext, UPGRADE, &mut l);
    assert_eq!(answer.outcome, Outcome::Ready);
    assert_eq!(answer.flags & YIELD_ENDED, 0);
    assert!(answer.wire.starts_with(b"HTTP/1.1 101"));
    assert!(
        answer.reasons.is_empty(),
        "the acceptance marker needs no HeadSlots"
    );
    assert!(l.pieces[..answer.pieces.len()].iter().any(|piece| {
        piece.stream == 37
            && piece.flags & (PIECE_FIELDS | PIECE_HAS_CODE) == PIECE_FIELDS | PIECE_HAS_CODE
            && piece.code == 101
            && piece.status_class == STATUS_SUCCESS
    }));
    finish(p, token, &mut l);
    shut(p);
}

#[test]
fn prewire_malformed_upgrades_end_without_an_acceptance_marker() {
    for (request, status) in [
        (b"GET / HTTP/1.1\r\nhost: svc.test\r\n\r\n".to_vec(), 400),
        (
            String::from_utf8(UPGRADE.to_vec())
                .unwrap()
                .replace("Version: 13", "Version: 12")
                .into_bytes(),
            426,
        ),
    ] {
        let p = instance();
        let ext = prewire_extension();
        let mut l = Lend::roomy();
        let (answer, token) = adopt(p, &ext, &request, &mut l);
        assert_eq!(answer.outcome, Outcome::Ready);
        assert_ne!(answer.flags & YIELD_ENDED, 0);
        assert!(answer
            .wire
            .starts_with(format!("HTTP/1.1 {status}").as_bytes()));
        assert!(!l.pieces[..answer.pieces.len()]
            .iter()
            .any(|piece| piece.code == 101));
        finish(p, token, &mut l);
        shut(p);
    }
}

#[test]
fn prewire_http_refusal_preserves_status_duplicate_headers_and_body() {
    for status in [401, 403, 429, 503] {
        let (p, token, held) = staged();
        assert!(held.wire.starts_with(b"HTTP/1.1 101"));
        let fields = b"www-authenticate: Bearer realm=\"original\"\r\nset-cookie: a=1\r\nset-cookie: b=2\r\nx-binary: caf\xe9\r\ncontent-length: 9\r\n";
        let mut l = Lend::roomy();
        let head = prewire_emit(p, token, status, fields, false, 0, &mut l);
        assert_eq!(head.outcome, Outcome::Ready);
        let body = prewire_emit(p, token, 0, b"no-access", true, 0, &mut l);
        assert_eq!(body.outcome, Outcome::Ready);
        let wire = [head.wire, body.wire].concat();
        assert!(wire.starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
        assert_eq!(
            &wire[wire.windows(2).position(|v| v == b"\r\n").unwrap() + 2..],
            &[fields.as_slice(), b"\r\nno-access"].concat()
        );
        assert!(!wire.windows(12).any(|v| v == b"HTTP/1.1 101"));
        assert_ne!(body.flags & YIELD_ENDED, 0);
        finish(p, token, &mut l);
        shut(p);
    }
}

#[test]
fn prewire_commit_uses_existing_emit_and_postcommit_refusal_stays_websocket() {
    let (p, token, held) = staged();
    let mut l = Lend::roomy();
    let commit = prewire_emit(p, token, 101, &[], true, 0, &mut l);
    assert_eq!(commit.outcome, Outcome::Ready);
    assert!(
        commit.wire.is_empty(),
        "the held 101 is published exactly once"
    );
    assert!(commit.pieces.is_empty());
    assert!(held.wire.starts_with(b"HTTP/1.1 101"));
    let message = prewire_emit(p, token, 0, b"ok", true, 0, &mut l);
    assert_eq!(message.wire, b"\x82\x02ok");
    let refused = prewire_refuse(p, token, 401, b"denied", true, &mut l);
    assert_eq!(refused.outcome, Outcome::Ready);
    assert!(refused.wire.starts_with(b"\x82\x06denied"));
    assert!(!refused.wire.starts_with(b"HTTP/"));
    assert_ne!(refused.flags & YIELD_ENDED, 0);
    finish(p, token, &mut l);
    shut(p);
}

#[test]
fn prewire_refuse_before_head_is_http_and_discards_owed_upgrade_and_frames() {
    let p = instance();
    let ext = prewire_extension();
    let mut l = Lend::new(1, 1, 1, 1);
    let (_, token) = adopt(p, &ext, UPGRADE, &mut l);
    poke(p, move |inst| {
        let slot = inst.queues().get(&token).cloned().unwrap();
        slot.lock()
            .unwrap()
            .pieces
            .push_back(Piece::plain(0, b"private-pending".to_vec(), true));
    });
    let mut roomy = Lend::roomy();
    let refused = prewire_refuse(p, token, 401, b"denied", false, &mut roomy);
    assert_eq!(refused.outcome, Outcome::Ready);
    assert!(refused.wire.starts_with(b"HTTP/1.1 401 "));
    assert!(refused.wire.ends_with(b"\r\n\r\ndenied"));
    assert!(!refused.wire.windows(12).any(|v| v == b"HTTP/1.1 101"));
    assert!(refused.pieces.is_empty());
    assert_ne!(refused.flags & YIELD_ENDED, 0);
    finish(p, token, &mut roomy);
    poke(p, move |inst| {
        assert!(!inst.queues().contains_key(&token));
        assert!(!inst.framer.holds(token));
    });
    shut(p);
}

#[test]
fn prewire_finish_releases_pending_state_without_sending_handshake_or_close() {
    let (p, token, _) = staged();
    let done = finish(p, token, &mut Lend::roomy());
    assert_eq!(done.outcome, Outcome::Ready);
    assert!(done.wire.is_empty());
    poke(p, move |inst| {
        assert!(!inst.queues().contains_key(&token));
        assert!(!inst.framer.holds(token));
    });
    shut(p);
}

#[test]
fn prewire_chunked_refusal_preserves_trailers_and_checks_body_length() {
    use busbar_contract::abi::transport::EMIT_TRAILERS;
    let (p, token, _) = staged();
    let mut l = Lend::roomy();
    let head = prewire_emit(
        p,
        token,
        429,
        b"retry-after: 7\r\ntrailer: x-final\r\n",
        false,
        0,
        &mut l,
    );
    assert_eq!(head.outcome, Outcome::Ready);
    let body = prewire_emit(p, token, 0, b"slow", false, 0, &mut l);
    assert_eq!(body.outcome, Outcome::Ready);
    let trailers = prewire_emit(
        p,
        token,
        0,
        b"x-final: original\r\n",
        true,
        EMIT_TRAILERS,
        &mut l,
    );
    assert_eq!(trailers.outcome, Outcome::Ready);
    let wire = [head.wire, body.wire, trailers.wire].concat();
    assert!(wire.starts_with(b"HTTP/1.1 429 "));
    assert!(wire
        .windows(b"retry-after: 7\r\n".len())
        .any(|v| v == b"retry-after: 7\r\n"));
    assert!(wire
        .windows(b"transfer-encoding: chunked\r\n".len())
        .any(|v| v == b"transfer-encoding: chunked\r\n"));
    assert!(wire.ends_with(b"\r\n\r\n4\r\nslow\r\n0\r\nx-final: original\r\n\r\n"));
    assert_ne!(trailers.flags & YIELD_ENDED, 0);
    finish(p, token, &mut l);
    shut(p);

    let (p, token, _) = staged();
    assert_eq!(
        prewire_emit(p, token, 401, b"content-length: 3\r\n", false, 0, &mut l).outcome,
        Outcome::Ready
    );
    let over = prewire_emit(p, token, 0, b"long", true, 0, &mut l);
    assert_ne!(over.outcome, Outcome::Ready);
    assert!(over.wire.is_empty());
    finish(p, token, &mut l);
    shut(p);
}

#[test]
fn prewire_invalid_modes_and_incomplete_handshakes_never_commit() {
    let p = instance();
    let ext = prewire_extension();
    let mut l = Lend::roomy();
    let (answer, token) = adopt(p, &ext, &UPGRADE[..UPGRADE.len() / 2], &mut l);
    assert_eq!(answer.outcome, Outcome::Ready);
    assert!(answer.wire.is_empty());
    assert!(answer.pieces.is_empty());
    let commit = prewire_emit(p, token, 101, &[], true, 0, &mut l);
    assert_ne!(commit.outcome, Outcome::Ready);
    assert!(commit.wire.is_empty());
    finish(p, token, &mut l);
    shut(p);

    let p = instance();
    for bad in [&b""[..], &b"2"[..], &[1][..]] {
        let ext = extensions::encode(&[
            (EXT_ADOPTED_SESSION, &context(37).encode()),
            ("session.prewire", bad),
        ]);
        let (answer, token) = adopt(p, &ext, UPGRADE, &mut l);
        assert_eq!(answer.outcome, Outcome::Failed);
        assert_eq!(token, 0);
        assert!(answer.wire.is_empty());
    }
    shut(p);
}

#[test]
fn prewire_opt_out_keeps_legacy_adoption_free_of_empty_application_messages() {
    let p = instance();
    let ext = extensions::encode(&[(EXT_ADOPTED_SESSION, &context(37).encode())]);
    let mut l = Lend::roomy();
    let (answer, token) = adopt(p, &ext, UPGRADE, &mut l);
    assert_eq!(answer.outcome, Outcome::Ready);
    assert!(answer.wire.starts_with(b"HTTP/1.1 101"));
    assert!(answer.pieces.is_empty());
    assert!(answer.reasons.is_empty());
    let payload = ingest(p, token, &masked(b"original"), false, &mut l);
    assert_eq!(payload.pieces, [(b"original".to_vec(), PIECE_END_OF_FRAME)]);
    let refused = stream_op(p, token, 37, true, &mut l);
    assert_eq!(refused.outcome, Outcome::Ready);
    assert!(refused.wire.starts_with(b"\x82\x02ok"));
    finish(p, token, &mut l);
    shut(p);
}

#[test]
fn prewire_partial_adoption_marks_acceptance_once_and_blocks_uncommitted_data() {
    let (p, token, _) = staged();
    let mut l = Lend::roomy();
    let early = prewire_emit(p, token, 0, b"early", true, 0, &mut l);
    assert_ne!(early.outcome, Outcome::Ready);
    assert!(early.wire.is_empty());
    finish(p, token, &mut l);
    shut(p);

    let p = instance();
    let ext = prewire_extension();
    let split = UPGRADE.len() / 2;
    let mut l = Lend::new(64 * 1024, 64 * 1024, 16, 0);
    let (pending, token) = adopt(p, &ext, &UPGRADE[..split], &mut l);
    assert_eq!(pending.outcome, Outcome::Ready);
    assert!(pending.wire.is_empty());
    assert!(pending.pieces.is_empty());
    let accepted = ingest(p, token, &UPGRADE[split..], false, &mut l);
    assert_eq!(accepted.outcome, Outcome::Ready);
    assert_eq!(accepted.reasons.len(), 0);
    assert_eq!(accepted.pieces.len(), 1);
    assert_eq!(l.pieces[0].stream, 37);
    assert_eq!(l.pieces[0].code, 101);
    assert_eq!(l.pieces[0].status_class, STATUS_SUCCESS);
    assert_eq!(
        l.pieces[0].flags,
        PIECE_FIELDS | PIECE_HAS_CODE | PIECE_END_OF_FRAME
    );
    assert!(accepted.wire.starts_with(b"HTTP/1.1 101"));
    let again = ingest(p, token, &[], false, &mut l);
    assert!(again.wire.is_empty());
    assert!(again.pieces.is_empty());
    let commit = prewire_emit(p, token, 101, &[], true, 0, &mut l);
    assert_eq!(commit.outcome, Outcome::Ready);
    assert!(commit.wire.is_empty());
    let message = prewire_emit(p, token, 0, b"ok", true, 0, &mut l);
    assert_eq!(message.wire, b"\x82\x02ok");
    finish(p, token, &mut l);
    shut(p);
}

#[test]
fn prewire_bodyless_not_modified_preserves_metadata_length_at_empty_completion() {
    let (p, token, _) = staged();
    let mut l = Lend::roomy();
    let head = prewire_emit(
        p,
        token,
        304,
        b"content-length: 42\r\netag: original\r\n",
        false,
        0,
        &mut l,
    );
    assert_eq!(head.outcome, Outcome::Ready);
    assert!(head
        .wire
        .ends_with(b"content-length: 42\r\netag: original\r\n\r\n"));
    let done = prewire_emit(p, token, 0, &[], true, 0, &mut l);
    assert_eq!(done.outcome, Outcome::Ready);
    assert!(done.wire.is_empty());
    assert_ne!(done.flags & YIELD_ENDED, 0);
    finish(p, token, &mut l);
    shut(p);
}

#[test]
fn prewire_bodyless_metadata_never_generates_chunk_bytes_or_trailers() {
    use busbar_contract::abi::transport::EMIT_TRAILERS;
    for fields in [
        &b"transfer-encoding: chunked\r\n"[..],
        &b"trailer: x-final\r\n"[..],
    ] {
        let (p, token, _) = staged();
        let mut l = Lend::roomy();
        let head = prewire_emit(p, token, 304, fields, false, 0, &mut l);
        assert_eq!(head.outcome, Outcome::Ready);
        let line = head.wire.windows(2).position(|v| v == b"\r\n").unwrap();
        assert_eq!(&head.wire[line + 2..], &[fields, b"\r\n"].concat());
        let trailers = prewire_emit(p, token, 0, &[], true, EMIT_TRAILERS, &mut l);
        assert_ne!(trailers.outcome, Outcome::Ready);
        assert!(trailers.wire.is_empty());
        let body = prewire_emit(p, token, 0, b"forbidden", true, 0, &mut l);
        assert_ne!(body.outcome, Outcome::Ready);
        assert!(body.wire.is_empty());
        finish(p, token, &mut l);
        shut(p);
    }
}

#[test]
fn prewire_bodyless_no_content_rejects_framing_headers_before_output() {
    for fields in [
        &b"content-length: 0\r\n"[..],
        &b"content-length: 5\r\n"[..],
        &b"transfer-encoding: chunked\r\n"[..],
    ] {
        let (p, token, _) = staged();
        let mut l = Lend::roomy();
        let head = prewire_emit(p, token, 204, fields, true, 0, &mut l);
        assert_ne!(head.outcome, Outcome::Ready);
        assert!(head.wire.is_empty());
        finish(p, token, &mut l);
        shut(p);
    }
}

#[test]
fn prewire_bodyless_prehead_no_content_refusal_omits_framing_fields() {
    let (p, token, _) = staged();
    let mut l = Lend::roomy();
    let answer = prewire_refuse(p, token, 204, &[], false, &mut l);
    assert_eq!(answer.outcome, Outcome::Ready);
    assert_eq!(answer.wire, b"HTTP/1.1 204 No Content\r\n\r\n");
    assert_ne!(answer.flags & YIELD_ENDED, 0);
    finish(p, token, &mut l);
    shut(p);
    let (p, token, _) = staged();
    let invalid = prewire_refuse(p, token, 204, b"forbidden", false, &mut l);
    assert_ne!(invalid.outcome, Outcome::Ready);
    assert!(invalid.wire.is_empty());
    finish(p, token, &mut l);
    shut(p);
}
