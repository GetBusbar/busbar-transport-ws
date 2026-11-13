// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// A masked client frame, as Autobahn sends one.
fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37, 0xFA, 0x21, 0x3D];
    let mut f = vec![first];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n <= 0xFFFF => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    f
}

/// Run a session over `input`; the bytes it wrote and how it ended.
fn session(input: &[u8]) -> (Vec<u8>, End) {
    let mut reader = BufReader::new(input);
    let mut out = Vec::new();
    let end = Session::default().run(&mut reader, &mut out);
    (out, end)
}

#[test]
fn sha1_and_the_accept_key_match_the_published_vectors() {
    let hex: String = sha1(b"abc").iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    let hex: String = sha1(b"").iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(accept_key(&sample_key()), sample_accept());
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
}

#[test]
fn utf8_fails_at_the_first_impossible_byte() {
    let text = "κόσμε\u{10FFFF}".as_bytes();
    for cut in 0..text.len() {
        let mut v = Utf8::default();
        assert!(
            v.feed(&text[..cut]) && v.feed(&text[cut..]) && v.complete(),
            "cut {cut}"
        );
    }

    for bad in [[0xED, 0xA0], [0xE0, 0x80], [0xF4, 0x90], [0xC0, 0x80]] {
        let mut v = Utf8::default();
        assert!(!v.feed(&bad), "{bad:02x?}");
    }

    let mut v = Utf8::default();
    assert!(v.feed(&[0xE2, 0x82]) && !v.complete());
}

#[test]
fn a_message_is_echoed_in_kind_and_a_ping_is_answered() {
    let mut input = client_frame(0x81, b"hello");
    input.extend(client_frame(0x89, b"p"));
    input.extend(client_frame(0x82, &[1, 2, 3]));
    input.extend(client_frame(0x88, &1000u16.to_be_bytes()));
    let (out, end) = session(&input);
    assert_eq!(end, End::Closed);
    let mut want = vec![0x81, 5];
    want.extend_from_slice(b"hello");
    want.extend_from_slice(&[0x8A, 1, b'p', 0x82, 3, 1, 2, 3, 0x88, 2, 0x03, 0xE8]);
    assert_eq!(out, want);
}

#[test]
fn a_fragmented_message_is_echoed_whole_and_a_large_one_uses_the_long_length() {
    let mut input = client_frame(0x01, b"ab");
    input.extend(client_frame(0x89, b""));
    input.extend(client_frame(0x80, b"cd"));
    let big = vec![b'x'; 70_000];
    input.extend(client_frame(0x82, &big));
    let (out, end) = session(&input);
    assert_eq!(end, End::Gone);
    assert_eq!(&out[..8], &[0x8A, 0, 0x81, 4, b'a', b'b', b'c', b'd']);
    assert_eq!(&out[8..10], &[0x82, 127]);
    assert_eq!(&out[10..18], &70_000u64.to_be_bytes());
    assert_eq!(out.len(), 18 + 70_000);
}

#[test]
fn a_good_message_ahead_of_a_bad_frame_is_answered_before_the_failure() {
    for bad in [
        client_frame(0xA1, b"x"),
        client_frame(0x85, b"x"),
        client_frame(0x8B, b"x"),
        client_frame(0x00, b"x"),
        client_frame(0x09, b"x"),
        client_frame(0x89, &[0; 126]),
        client_frame(0x88, &[3]),
        client_frame(0x88, &1005u16.to_be_bytes()),
    ] {
        let mut input = client_frame(0x81, b"ok");
        input.extend(bad);
        let (out, end) = session(&input);
        assert_eq!(end, End::Fail(PROTOCOL_ERROR));
        assert_eq!(out, vec![0x81, 2, b'o', b'k']);
    }
}

#[test]
fn invalid_text_fails_1007_before_the_rest_of_the_frame_arrives() {
    let mut f = client_frame(0x81, &[0xCE, 0xBA, 0xED, 0xA0, 0x80]);
    f[1] = 0x80 | 100;
    let (out, end) = session(&f);
    assert!(out.is_empty());
    assert_eq!(end, End::Fail(INVALID_PAYLOAD));

    assert_eq!(
        session(&client_frame(0x81, &[0xE2, 0x82])).1,
        End::Fail(INVALID_PAYLOAD)
    );
    let mut reason = 1000u16.to_be_bytes().to_vec();
    reason.extend_from_slice(&[0xFF]);
    assert_eq!(
        session(&client_frame(0x88, &reason)).1,
        End::Fail(INVALID_PAYLOAD)
    );
}

#[test]
fn an_unmasked_frame_is_a_protocol_error() {
    let mut f = client_frame(0x81, b"x");
    f[1] &= 0x7F;
    assert_eq!(session(&f).1, End::Fail(PROTOCOL_ERROR));
}

#[test]
fn the_handshake_wants_a_version_13_upgrade() {
    let key = sample_key();
    let good = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    assert_eq!(
        read_handshake(&mut BufReader::new(good.as_bytes())).as_deref(),
        Ok(key.as_str())
    );
    let old = good.replace("Version: 13", "Version: 8");
    assert_eq!(
        read_handshake(&mut BufReader::new(old.as_bytes())),
        Err(Refusal::Version)
    );
}

#[test]
fn handshake_line_is_bounded_before_allocation() {
    let input = vec![b'x'; MAX_HEAD * 2];
    let mut reader = std::io::Cursor::new(input);
    assert_eq!(read_handshake(&mut reader), Err(Refusal::Malformed));
    assert_eq!(reader.position(), (MAX_HEAD + 1) as u64);
}

#[test]
fn oversized_message_is_refused_before_reading_payload() {
    let mut input = vec![0x82, 0xff];
    input.extend_from_slice(&((MAX_MESSAGE + 1) as u64).to_be_bytes());
    input.extend_from_slice(&[0; 4]);
    assert_eq!(session(&input).1, End::Fail(1009));
}

#[test]
fn fragmented_message_uses_the_remaining_budget() {
    let mut state = Session {
        open: Some(false),
        message: vec![0; 1],
        ..Session::default()
    };
    let mut input = vec![0x80, 0xff];
    input.extend_from_slice(&(MAX_MESSAGE as u64).to_be_bytes());
    input.extend_from_slice(&[0; 4]);
    assert_eq!(
        state
            .frame(&mut std::io::Cursor::new(input), &mut Vec::new())
            .unwrap(),
        Some(End::Fail(1009))
    );
}

#[test]
fn invalid_opening_requirements_are_refused() {
    let key = sample_key();
    let good = format!("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n");
    assert!(read_handshake(&mut std::io::Cursor::new(good.as_str())).is_ok());
    for bad in [
        good.replace("HTTP/1.1", "HTTP/1.0"),
        good.replace("\r\n\r\n", "\r\n\r"),
        good.replace("HTTP/1.1\r\n", "HTTP/1.1\r\r\n"),
        good.replace("Host: x\r\n", ""),
        good.replace("Connection: keep-alive, Upgrade\r\n", ""),
        good.replace(&key, "x"),
        good.replace("Host: x", "Host : x"),
        good.replace("Host: x", "Host: x\r\nHost: y"),
        good.replace(
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13",
        ),
    ] {
        assert!(read_handshake(&mut std::io::Cursor::new(bad)).is_err());
    }
}

#[test]
fn nonminimal_extended_lengths_are_protocol_errors() {
    for encoded in [
        vec![0x82, 0xfe, 0, 1, 0, 0, 0, 0, b'x'],
        vec![0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, b'x'],
    ] {
        assert_eq!(session(&encoded).1, End::Fail(PROTOCOL_ERROR));
    }
}

#[test]
fn client_fixture_matches_the_published_masked_hello_vector() {
    assert_eq!(
        client_frame(0x81, b"Hello"),
        [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]
    );
}
