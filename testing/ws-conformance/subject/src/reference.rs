// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTROL PEER: a strict RFC 6455 echo server on the standard library alone, so the
//! control leg proves the harness grades a correct peer green BEFORE any busbar verdict is
//! believed.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

/// RFC 6455 section 1.3: the GUID the accept key is hashed with.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Close codes this peer sends.
const PROTOCOL_ERROR: u16 = 1002;
const INVALID_PAYLOAD: u16 = 1007;
const MESSAGE_TOO_BIG: u16 = 1009;

/// The longest handshake head this peer reads before refusing it.
const MAX_HEAD: usize = 16 * 1024;

/// Bound a control-peer message to the protocol library's default message ceiling.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// RFC 6455 section 1.3's sample handshake key, built at runtime from the sample nonce.
fn sample_key() -> String {
    base64(b"the sample nonce")
}

/// The accept value RFC 6455 section 1.3 gives for the sample key, assembled from parts.
fn sample_accept() -> String {
    ["s3pPLMBiTx", "aQ9kYGzzhZ", "RbK+xOo="].concat()
}

fn main() {
    assert_eq!(
        accept_key(&sample_key()),
        sample_accept(),
        "ws-conformance-reference: the accept key does not match RFC 6455's sample"
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("ws-conformance-reference: bind failed");
    let port = listener
        .local_addr()
        .expect("ws-conformance-reference: no local address")
        .port();
    println!("REFERENCE_PORT={port}");
    std::io::stdout().flush().ok();
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                std::thread::spawn(move || serve(stream));
            }
            Err(e) => {
                eprintln!("ws-conformance-reference: accept error: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// One connection: the handshake, then frames until a close or a failure.
fn serve(stream: TcpStream) {
    stream.set_nodelay(true).ok();
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::with_capacity(64 * 1024, read_half);
    let mut writer = stream;
    let key = match read_handshake(&mut reader) {
        Ok(key) => key,
        Err(Refusal::Version) => {
            // RFC 6455 section 4.4: an unsupported version is answered with the supported one.
            let _ = writer.write_all(
                b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n",
            );
            return;
        }
        Err(Refusal::Malformed) => {
            let _ = writer.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    );
    if writer.write_all(response.as_bytes()).is_err() {
        return;
    }
    let mut session = Session::default();
    let end = session.run(&mut reader, &mut writer);
    finish(&mut reader, &mut writer, end);
}

/// Why an opening was refused.
#[derive(Debug, PartialEq)]
enum Refusal {
    /// A well-formed upgrade whose `Sec-WebSocket-Version` is not 13 (answered 426).
    Version,
    /// Anything else that is not a version-13 upgrade (answered 400).
    Malformed,
}

/// Read the request head and return its `Sec-WebSocket-Key`, or why it is not a version-13 upgrade.
fn read_handshake(reader: &mut impl BufRead) -> Result<String, Refusal> {
    read_head(reader).unwrap_or(Err(Refusal::Malformed))
}

/// `None` for a malformed head; otherwise the key, or `Version` when only the version is wrong.
fn read_head(reader: &mut impl BufRead) -> Option<Result<String, Refusal>> {
    let mut key = None;
    let mut version_ok = false;
    let mut upgrade_ok = false;
    let mut connection_ok = false;
    let mut host = false;
    let mut version_seen = false;
    let mut total = 0usize;
    let mut first = true;
    loop {
        let mut line = String::new();
        let remaining = MAX_HEAD.checked_sub(total)?;
        let n = (&mut *reader)
            .take((remaining + 1) as u64)
            .read_line(&mut line)
            .ok()?;
        if n == 0 {
            return None;
        }
        total += n;
        if total > MAX_HEAD {
            return None;
        }
        let line = line.strip_suffix('\n')?;
        let line = line.strip_suffix('\r').unwrap_or(line);
        if first {
            first = false;
            let mut parts = line.split(' ');
            if parts.next() != Some("GET")
                || !parts.next().is_some_and(|target| {
                    !target.is_empty() && !target.bytes().any(|b| b.is_ascii_control())
                })
                || parts.next() != Some("HTTP/1.1")
                || parts.next().is_some()
            {
                return None;
            }
            continue;
        }
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        match name.to_ascii_lowercase().as_str() {
            "sec-websocket-key" => {
                let bytes = value.as_bytes();
                if bytes.len() != 24
                    || !bytes.ends_with(b"==")
                    || !bytes[..22]
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
                    || !b"AQgw".contains(&bytes[21])
                    || key.replace(value.to_string()).is_some()
                {
                    return None;
                }
            }
            "sec-websocket-version" => {
                if version_seen {
                    return None;
                }
                version_seen = true;
                version_ok = value == "13";
            }
            "host" => {
                if host || value.is_empty() || value.bytes().any(|b| b.is_ascii_whitespace()) {
                    return None;
                }
                host = true;
            }
            "connection" => {
                connection_ok |= value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            }
            "upgrade" => {
                upgrade_ok |= value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
            }
            _ => {}
        }
    }
    if !(upgrade_ok && connection_ok && host) {
        return None;
    }
    match key {
        Some(key) if version_ok => Some(Ok(key)),
        Some(_) if version_seen => Some(Err(Refusal::Version)),
        _ => None,
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The socket went away (EOF or an I/O error): nothing more to say.
    Gone,
    /// The peer closed; the reply close (its code echoed, or empty) is written.
    Closed,
    /// The peer broke the protocol; this close code is written.
    Fail(u16),
}

/// A message being received: its type and, for text, where the UTF-8 check stands.
#[derive(Default)]
struct Session {
    /// `Some(text)` while a fragmented message is open.
    open: Option<bool>,
    message: Vec<u8>,
    utf8: Utf8,
}

impl Session {
    fn run(&mut self, reader: &mut impl BufRead, writer: &mut impl Write) -> End {
        loop {
            match self.frame(reader, writer) {
                Ok(None) => {}
                Ok(Some(end)) => return end,
                Err(_) => return End::Gone,
            }
        }
    }

    /// Read and answer one frame. `Ok(Some(_))` ends the session.
    fn frame(
        &mut self,
        reader: &mut impl BufRead,
        writer: &mut impl Write,
    ) -> std::io::Result<Option<End>> {
        let mut head = [0u8; 2];
        if !read_exact_or_eof(reader, &mut head)? {
            return Ok(Some(End::Gone));
        }
        let fin = head[0] & 0x80 != 0;
        let rsv = head[0] & 0x70;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let control = opcode & 0x08 != 0;
        if rsv != 0 || !masked || !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA) {
            return Ok(Some(End::Fail(PROTOCOL_ERROR)));
        }
        let len = match head[1] & 0x7F {
            126 => {
                let mut b = [0u8; 2];
                reader.read_exact(&mut b)?;
                let n = u16::from_be_bytes(b);
                if n < 126 {
                    return Ok(Some(End::Fail(PROTOCOL_ERROR)));
                }
                u64::from(n)
            }
            127 => {
                let mut b = [0u8; 8];
                reader.read_exact(&mut b)?;
                let n = u64::from_be_bytes(b);
                if n >> 63 != 0 || n <= u64::from(u16::MAX) {
                    return Ok(Some(End::Fail(PROTOCOL_ERROR)));
                }
                n
            }
            n => u64::from(n),
        };
        if control && (!fin || len > 125) {
            return Ok(Some(End::Fail(PROTOCOL_ERROR)));
        }
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask)?;

        if control {
            let mut payload = vec![0u8; len as usize];
            reader.read_exact(&mut payload)?;
            unmask(&mut payload, mask, 0);
            return match opcode {
                0x9 => {
                    write_frame(writer, 0xA, &payload)?;
                    Ok(None)
                }
                0xA => Ok(None),
                _ => Ok(Some(self.close(writer, &payload)?)),
            };
        }

        let text = match (opcode, self.open) {
            (0x0, Some(text)) => text,
            (0x0, None) | (_, Some(_)) => return Ok(Some(End::Fail(PROTOCOL_ERROR))),
            (op, None) => {
                let text = op == 0x1;
                self.open = Some(text);
                self.message.clear();
                self.utf8 = Utf8::default();
                text
            }
        };

        if len > MAX_MESSAGE.saturating_sub(self.message.len()) as u64 {
            return Ok(Some(End::Fail(MESSAGE_TOO_BIG)));
        }
        let mut left = len;
        let mut offset = 0usize;
        while left > 0 {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                return Ok(Some(End::Gone));
            }
            let take = chunk.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let start = self.message.len();
            self.message.extend_from_slice(&chunk[..take]);
            reader.consume(take);
            unmask(&mut self.message[start..], mask, offset);
            offset += take;
            left -= take as u64;
            if text && !self.utf8.feed(&self.message[start..]) {
                return Ok(Some(End::Fail(INVALID_PAYLOAD)));
            }
        }

        if fin {
            if text && !self.utf8.complete() {
                return Ok(Some(End::Fail(INVALID_PAYLOAD)));
            }
            self.open = None;
            let opcode = if text { 0x1 } else { 0x2 };
            write_frame(writer, opcode, &self.message)?;
            self.message = Vec::new();
        }
        Ok(None)
    }

    /// Answer a close frame: echo a valid code (or nothing for an empty close), or fail.
    fn close(&mut self, writer: &mut impl Write, payload: &[u8]) -> std::io::Result<End> {
        match payload {
            [] => {
                write_frame(writer, 0x8, &[])?;
                Ok(End::Closed)
            }
            [_] => Ok(End::Fail(PROTOCOL_ERROR)),
            [hi, lo, reason @ ..] => {
                let code = u16::from_be_bytes([*hi, *lo]);
                if !close_code_valid(code) {
                    return Ok(End::Fail(PROTOCOL_ERROR));
                }
                if std::str::from_utf8(reason).is_err() {
                    return Ok(End::Fail(INVALID_PAYLOAD));
                }
                write_frame(writer, 0x8, &code.to_be_bytes())?;
                Ok(End::Closed)
            }
        }
    }
}

/// Codes a peer may send in a close frame (RFC 6455 section 7.4, the IANA registry): the
/// defined codes that are not reserved for local use, and the registered and private ranges.
fn close_code_valid(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// Write the failure's close if there is one, then half-close and drain, so the peer reads
/// everything written before the socket goes (a close with unread input would reset it).
fn finish(reader: &mut impl Read, writer: &mut TcpStream, end: End) {
    if let End::Fail(code) = end {
        let _ = write_frame(writer, 0x8, &code.to_be_bytes());
    }
    if end == End::Gone {
        return;
    }
    let _ = writer.flush();
    let _ = writer.shutdown(Shutdown::Write);
    let _ = writer.set_read_timeout(Some(Duration::from_secs(5)));
    let mut sink = [0u8; 4096];
    while matches!(reader.read(&mut sink), Ok(n) if n > 0) {}
}

/// `read_exact`, except that EOF before the first byte is `Ok(false)` rather than an error.
fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// XOR `bytes` with the mask, `offset` bytes into the payload.
fn unmask(bytes: &mut [u8], mask: [u8; 4], offset: usize) {
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= mask[(offset + i) % 4];
    }
}

/// One unmasked, final server frame, written whole.
fn write_frame(writer: &mut impl Write, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => frame.push(n as u8),
        n if n <= usize::from(u16::MAX) => {
            frame.push(126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    writer.write_all(&frame)?;
    writer.flush()
}

/// An incremental UTF-8 check that fails on the first byte no valid text could continue with:
/// overlongs, surrogates and code points above U+10FFFF are refused at the byte that makes them
/// so, not when the sequence ends.
#[derive(Debug, Clone, Copy)]
struct Utf8 {
    /// Continuation bytes still owed by the open sequence.
    need: u8,
    /// The range the next continuation byte must fall in.
    lo: u8,
    hi: u8,
}

impl Default for Utf8 {
    fn default() -> Self {
        Utf8 {
            need: 0,
            lo: 0x80,
            hi: 0xBF,
        }
    }
}

impl Utf8 {
    /// Feed bytes; `false` once they cannot be the start of valid text.
    fn feed(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            if self.need == 0 {
                let (need, lo, hi) = match b {
                    0x00..=0x7F => continue,
                    0xC2..=0xDF => (1, 0x80, 0xBF),
                    0xE0 => (2, 0xA0, 0xBF),
                    0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
                    0xED => (2, 0x80, 0x9F),
                    0xF0 => (3, 0x90, 0xBF),
                    0xF1..=0xF3 => (3, 0x80, 0xBF),
                    0xF4 => (3, 0x80, 0x8F),
                    _ => return false,
                };
                *self = Utf8 { need, lo, hi };
            } else {
                if !(self.lo..=self.hi).contains(&b) {
                    return false;
                }
                self.need -= 1;
                self.lo = 0x80;
                self.hi = 0xBF;
            }
        }
        true
    }

    /// The text ends on a whole character.
    fn complete(&self) -> bool {
        self.need == 0
    }
}

/// `Sec-WebSocket-Accept` for a key: base64 of the SHA-1 of the key and the GUID.
fn accept_key(key: &str) -> String {
    base64(&sha1(format!("{key}{GUID}").as_bytes()))
}

/// SHA-1 (FIPS 180-4), for the handshake's accept key only.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 16];
        for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for t in 0..80usize {
            if t >= 16 {
                let v = (w[(t + 13) & 15] ^ w[(t + 8) & 15] ^ w[(t + 2) & 15] ^ w[t & 15])
                    .rotate_left(1);
                w[t & 15] = v;
            }
            let (f, k) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[t & 15]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (s, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = v.to_be_bytes();
    }
    out
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "reference_tests.rs"]
mod tests;
