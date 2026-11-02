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
