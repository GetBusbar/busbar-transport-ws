// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::transport::wire::{CloseReason, TransportError};

fn dial(fields: &[(String, Vec<u8>)]) -> (WsFramer, u64, String) {
    let framer = WsFramer::new(0);
    let mut opening = Out::default();
    let state = framer
        .open_with(Side::Dial, "ws://svc.test/session", fields, &mut opening)
        .unwrap();
    (framer, state, String::from_utf8(opening.sent).unwrap())
}

fn response(request: &str, connection: &str, extra: &str) -> Vec<u8> {
    let key = fields_named(request, "sec-websocket-key")[0];
    format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: {connection}\r\nSec-WebSocket-Accept: {}\r\n{extra}\r\n",
        derive_accept_key(key.as_bytes())).into_bytes()
}

#[test]
fn leading_empty_lines_never_become_a_refused_upgrades_body_or_reason() {
    for prefix in [&b"\r\n\r\n"[..], &b"\n\n"[..], &b"\r\n\n"[..]] {
        let mut wire = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
        wire.extend_from_slice(prefix);
        wire.extend_from_slice(
            b"HTTP/1.1 401 Unauthorized\r\nX-End: yes\r\nContent-Length: 5\r\n\r\nhello",
        );
        for split in 0..=wire.len() {
            let (framer, state, _) = dial(&[]);
            let mut heard = Out::default();
            let first = framer
                .ingest_head(state, &wire[..split], false, &mut heard)
                .unwrap();
            let second = framer
                .ingest_head(state, &wire[split..], false, &mut heard)
                .unwrap();
            assert_eq!(
                first.or(second),
                Some(b"Unauthorized".to_vec()),
                "split {split}"
            );
            let body: Vec<u8> = heard
                .frames
                .iter()
                .zip(&heard.statuses)
                .filter(|(_, status)| status.is_none())
                .flat_map(|(bytes, _)| bytes.iter().copied())
                .collect();
            assert_eq!(body, b"hello", "split {split}: {:?}", heard.frames);
            assert!(heard.ended && !framer.failed(state));
            assert_eq!(
                heard
                    .statuses
                    .iter()
                    .flatten()
                    .map(|(code, _)| *code)
                    .collect::<Vec<_>>(),
                [100, 401]
            );
        }
    }
    assert_eq!(
        reason_phrase(b"\r\n\nHTTP/1.1 401 Unauthorized\r\n\r\n"),
        Some(b"Unauthorized".to_vec())
    );
}

#[test]
fn coalesced_informational_heads_preserve_the_validated_upgrade_and_all_following_bytes() {
    let (framer, state, request) = dial(&[]);
    let mut wire = Vec::new();
    let expected: Vec<_> = (0..128)
        .map(|_| {
            wire.extend_from_slice(b"\r\nHTTP/1.1 103 Early Hints\r\nX-Hint: yes\r\n\r\n");
            103
        })
        .chain(std::iter::once(101))
        .collect();
    wire.extend(response(&request, "Upgrade", ""));
    wire.extend_from_slice(b"\x81\x02ok");
    let mut heard = Out::default();
    assert_eq!(
        framer.ingest_head(state, &wire, false, &mut heard).unwrap(),
        Some(b"Switching Protocols".to_vec())
    );
    assert_eq!(
        heard
            .statuses
            .iter()
            .flatten()
            .map(|(code, _)| *code)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(heard.frames.last().unwrap(), b"ok");
    assert!(!heard.ended && !framer.failed(state));
}

#[test]
fn a_server_cannot_negotiate_an_unoffered_extension() {
    for extra in [
        "Sec-WebSocket-Extensions: permessage-deflate\r\n",
        "Sec-WebSocket-Extensions: \r\n",
    ] {
        let (framer, state, request) = dial(&[]);
        assert!(matches!(
            framer.ingest(
                state,
                &response(&request, "Upgrade", extra),
                false,
                &mut Out::default()
            ),
            Err(TransportError::HandshakeFailed)
        ));
    }
}

#[test]
fn connection_tokens_across_lines_are_validated_without_leaking_nominated_fields() {
    for (connection, extra) in [
        ("keep-alive, UpGrAdE, X-Hop", ""),
        ("keep-alive", "Connection: Upgrade, X-Hop\r\n"),
    ] {
        let (framer, state, request) = dial(&[]);
        let extra = format!("{extra}X-Hop: hidden\r\nX-End: kept\r\n");
        let mut heard = Out::default();
        framer
            .ingest(
                state,
                &response(&request, connection, &extra),
                false,
                &mut heard,
            )
            .expect("Upgrade is a token in the field list");
        assert_eq!(
            heard.statuses,
            [Some((101, Some(WireStatusClass::Success)))]
        );
        assert_eq!(heard.frames, [b"x-end: kept\r\n".to_vec()]);
        let (other, state, request) = dial(&[]);
        let invalid = response(&request, connection, &extra);
        let valid_accept =
            derive_accept_key(fields_named(&request, "sec-websocket-key")[0].as_bytes());
        let invalid = String::from_utf8(invalid)
            .unwrap()
            .replace(&valid_accept, "not-the-accept");
        assert!(
            other
                .ingest(state, invalid.as_bytes(), false, &mut Out::default())
                .is_err(),
            "token normalization never bypasses accept-key validation"
        );
    }
    let (framer, state, request) = dial(&[]);
    assert!(framer
        .ingest(
            state,
            &response(&request, "keep-alive", ""),
            false,
            &mut Out::default()
        )
        .is_err());
}

#[test]
fn every_subprotocol_offer_line_is_part_of_the_validated_offer() {
    let fields = [
        ("Sec-WebSocket-Protocol".to_string(), b"one".to_vec()),
        ("sec-websocket-protocol".to_string(), b"two, three".to_vec()),
    ];
    let (framer, state, request) = dial(&fields);
    let mut heard = Out::default();
    framer
        .ingest(
            state,
            &response(&request, "Upgrade", "Sec-WebSocket-Protocol: two\r\n"),
            false,
            &mut heard,
        )
        .expect("the second line offered two");
    assert_eq!(heard.frames, [b"sec-websocket-protocol: two\r\n".to_vec()]);
    let (framer, state, request) = dial(&fields);
    assert!(framer
        .ingest(
            state,
            &response(&request, "Upgrade", "Sec-WebSocket-Protocol: absent\r\n"),
            false,
            &mut Out::default()
        )
        .is_err());
}

fn frame(opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mut wire = vec![
        0x80 | opcode,
        payload.len() as u8 | if masked { 0x80 } else { 0 },
    ];
    if masked {
        wire.extend_from_slice(&[0; 4]);
    }
    wire.extend_from_slice(payload);
    wire
}

#[test]
fn forbidden_peer_close_codes_fail_but_a_real_protocol_close_remains_clean() {
    for (code, bad) in [
        (0, true),
        (999, true),
        (1004, true),
        (1005, true),
        (1006, true),
        (1015, true),
        (2999, true),
        (5000, true),
        (1000, false),
        (1002, false),
        (1014, false),
        (3000, false),
        (4999, false),
    ] {
        for masked in [false, true] {
            let (framer, state, opening) = if masked {
                let framer = WsFramer::new(0);
                let state = framer.open(Side::Accept, "", &mut Out::default()).unwrap();
                let request = b"GET / HTTP/1.1\r\nHost: svc.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
                framer
                    .ingest(state, request, false, &mut Out::default())
                    .unwrap();
                (framer, state, Vec::new())
            } else {
                let (framer, state, request) = dial(&[]);
                let opening = response(&request, "Upgrade", "");
                (framer, state, opening)
            };
            let mut payload = u16::to_be_bytes(code).to_vec();

            payload.extend_from_slice(b"Protocol violation");
            let mut wire = opening;
            wire.extend(frame(1, b"kept", masked));
            wire.extend(frame(8, &payload, masked));
            wire.extend(frame(1, b"ignored", masked));
            let mut heard = Out::default();
            framer.ingest(state, &wire, false, &mut heard).unwrap();
            assert_eq!(framer.failed(state), bad, "code={code}, masked={masked}");
            assert!(heard.ended);
            let data: Vec<_> = heard
                .frames
                .iter()
                .zip(&heard.statuses)
                .filter(|(_, status)| status.is_none())
                .map(|(bytes, _)| bytes.as_slice())
                .collect();
            assert_eq!(data, [&b"kept"[..]]);
            framer.close(state, CloseReason::Normal, &mut Out::default());
        }
    }
}

#[test]
fn a_peer_close_after_a_chunk_aligned_accepted_head_keeps_its_original_validity() {
    for (code, bad) in [(1005u16, true), (1002, false)] {
        let framer = WsFramer::new(0);
        let state = framer.open(Side::Accept, "", &mut Out::default()).unwrap();
        let mut wire = b"GET / HTTP/1.1\r\nHost: svc.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nX-Pad: ".to_vec();
        wire.resize(4096 - 4, b'p');
        wire.extend_from_slice(b"\r\n\r\n");
        wire.extend(frame(1, b"kept", true));
        wire.extend(frame(8, &code.to_be_bytes(), true));
        let mut heard = Out::default();
        framer.ingest(state, &wire, false, &mut heard).unwrap();
        assert_eq!(heard.frames, [b"kept".to_vec()]);
        assert!(heard.ended);
        assert_eq!(framer.failed(state), bad, "code={code}");
    }
}

#[test]
fn refused_upgrade_status_boundaries_keep_their_existing_classes_and_close_codes() {
    for (code, class) in [
        (301u16, WireStatusClass::Other),
        (399, WireStatusClass::Other),
        (400, WireStatusClass::CallerFault),
        (499, WireStatusClass::CallerFault),
        (500, WireStatusClass::FarEndFault),
        (599, WireStatusClass::FarEndFault),
        (600, WireStatusClass::Other),
    ] {
        let (_, _, heard) = refused_with(
            format!("HTTP/1.1 {code} answer\r\nContent-Length: 0\r\n\r\n").as_bytes(),
            false,
        );
        assert_eq!(heard.statuses, [Some((u32::from(code), Some(class)))]);
    }
    for (status, close) in [
        (301, 1000),
        (404, 1008),
        (401, 1008),
        (403, 1008),
        (413, 1009),
        (429, 1013),
        (503, 1013),
        (500, 1011),
        (502, 1011),
        (504, 1011),
        (599, 1011),
        (600, 1000),
    ] {
        assert_eq!(
            u16::from(crate::transport::close_code_of_status(status)),
            close
        );
    }
}

#[test]
fn oversized_numeric_retry_and_chunk_lengths_are_refused_without_wrapping() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "retry-after",
        HeaderValue::from_static("18446744073709551616"),
    );
    assert_eq!(retry_after(&headers, 0), None);
    headers.insert(
        "retry-after",
        HeaderValue::from_static("18446744073709551615"),
    );
    assert_eq!(retry_after(&headers, 0), Some(u64::MAX));
    let (framer, state, heard) = refused_with(
        b"HTTP/1.1 429 Wait\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n",
        false,
    );
    assert!(heard.ended && framer.failed(state));
    assert!(heard.frames.iter().skip(1).all(Vec::is_empty));
}

#[test]
fn held_capacity_failures_keep_the_existing_framing_error_kind() {
    let framer = WsFramer::new(64);
    let state = framer
        .open(Side::Dial, "ws://svc.test/", &mut Out::default())
        .unwrap();
    assert!(matches!(
        framer.emit_text(state, &[0; 65], true, false, &mut Out::default()),
        Err(TransportError::Framing)
    ));
}
