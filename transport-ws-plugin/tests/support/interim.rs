// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::transport::{
    FrameSpan, HeadSlots, PIECE_CONTINUED, PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_DECLARED_LEN,
    PIECE_INTERIM, PIECE_STREAM_FAILED, STATUS_OTHER, STATUS_SUCCESS,
};

#[derive(Debug, Default, PartialEq, Eq)]
struct Block {
    code: u32,
    interim: bool,
    bytes: Vec<u8>,
    whole: bool,
    parts: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Heard {
    blocks: Vec<Block>,
    reasons: Vec<(u32, Vec<u8>)>,
    payload: Vec<u8>,
    ended: bool,
}

struct Sink {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
}

impl Sink {
    fn new(frame: usize, pieces: usize, heads: usize) -> Self {
        Self {
            wire: vec![0; 4096],
            frame: vec![0; frame],
            pieces: vec![z(); pieces],
            heads: vec![z(); heads],
        }
    }

    fn lent(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
            now_monotonic_ns: 3_000_000_000,
            now_unix_ns: 1_790_000_000_000_000_000,
        }
    }

    fn span(&self, span: FrameSpan) -> &[u8] {
        &self.frame[span.offset as usize..(span.offset + span.len) as usize]
    }

    fn take(&self, out: &FramerOut, heard: &mut Heard) -> bool {
        let pieces = &self.pieces[..out.yielded.pieces_len as usize];
        for head in &self.heads[..out.yielded.heads_len as usize] {
            assert_eq!(
                (head.method.len, head.target.len, head.authority.len),
                (0, 0, 0)
            );
            assert_ne!(head.reason.len, 0);
            let first = pieces
                .iter()
                .find(|piece| {
                    piece.stream == head.stream
                        && piece.offset == head.reason.offset + head.reason.len
                        && piece.flags & (PIECE_FIELDS | PIECE_HAS_CODE | PIECE_CONTINUED)
                            == PIECE_FIELDS | PIECE_HAS_CODE
                })
                .expect("a reason is adjacent to its own head's first field piece");
            heard
                .reasons
                .push((first.code, self.span(head.reason).to_vec()));
        }
        for piece in pieces {
            assert_eq!(piece.stream, 0);
            assert_eq!(
                piece.flags & PIECE_STREAM_FAILED,
                0,
                "the upstream answer is valid"
            );
            let bytes = self.span(FrameSpan {
                offset: piece.offset,
                len: piece.len,
            });
            if piece.flags & PIECE_FIELDS != 0 {
                assert_ne!(piece.flags & PIECE_HAS_CODE, 0);
                let interim = matches!(piece.code, 100 | 103);
                assert_eq!(
                    piece.flags & PIECE_INTERIM != 0,
                    interim,
                    "code {}",
                    piece.code
                );
                assert_eq!(piece.flags & (PIECE_END | PIECE_HAS_DECLARED_LEN), 0);
                assert_eq!(
                    piece.status_class,
                    if piece.code == 101 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_OTHER
                    }
                );
                if heard.blocks.last().is_none_or(|block| block.whole) {
                    heard.blocks.push(Block {
                        code: piece.code,
                        interim,
                        ..Block::default()
                    });
                }
                let block = heard.blocks.last_mut().unwrap();
                assert_eq!((block.code, block.interim), (piece.code, interim));
                block.bytes.extend_from_slice(bytes);
                block.parts += 1;
                block.whole = piece.flags & PIECE_END_OF_FRAME != 0;
            } else if piece.flags & PIECE_END == 0 {
                assert_eq!(piece.flags & (PIECE_INTERIM | PIECE_HAS_CODE), 0);
                heard.payload.extend_from_slice(bytes);
            }
        }
        heard.ended |= out.yielded.flags & YIELD_ENDED != 0;
        out.yielded.flags & YIELD_MORE != 0
    }

    fn ingest(
        &mut self,
        plugin: &Plugin<Transport>,
        framing: u64,
        bytes: &[u8],
        heard: &mut Heard,
    ) -> bool {
        let mut input: IngestIn = z();
        input.head = in_head();
        input.framing = framing;
        input.bytes = bytes.as_ptr();
        input.len = bytes.len();
        input.sink = self.lent();
        let mut output: FramerOut = z();
        output.head = out_head();
        let mut frame = Frame::new(input, output);
        assert_eq!(
            plugin.call(slot::INGEST, &mut frame).outcome,
            Outcome::Ready
        );
        self.take(&frame.out, heard)
    }
}

fn answer(
    plugin: &Plugin<Transport>,
    final_code: u32,
    frame_cap: usize,
    pieces: usize,
    heads: usize,
) -> Heard {
    let mut host = Host::new((4096, 4096, 8));
    let mut dial = host.begin(plugin, SIDE_DIAL, "ws://svc.test/interim");
    let mut accept = host.begin(plugin, SIDE_ACCEPT, "");
    host.carry(plugin, &mut dial, &mut accept);
    let upgrade = std::mem::take(&mut accept.wire);
    assert!(upgrade.starts_with(b"HTTP/1.1 101") && upgrade.ends_with(b"\r\n\r\n"));
    let mut wire = b"HTTP/1.1 100 Continue\r\nX-First: one\r\n\r\nHTTP/1.1 103 Early Hints\r\nX-Hint: a-long-field-value-that-is-split-by-the-small-sink\r\n\r\n".to_vec();
    if final_code == 101 {
        wire.extend_from_slice(&upgrade[..upgrade.len() - 2]);
        wire.extend_from_slice(b"X-Final: accepted\r\n\r\n");
        wire.extend_from_slice(b"\x81\x02ok");
    } else {
        wire.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Final: refused\r\n\r\nok",
        );
    }
    let mut sink = Sink::new(frame_cap, pieces, heads);
    let mut heard = Heard::default();
    let mut more = sink.ingest(plugin, dial.framing, &wire, &mut heard);
    let mut recalls = 0;
    while more {
        recalls += 1;
        assert!(recalls < 1000, "the finite response drains");
        more = sink.ingest(plugin, dial.framing, &[], &mut heard);
    }
    assert_eq!(
        heard
            .blocks
            .iter()
            .map(|block| (block.code, block.interim))
            .collect::<Vec<_>>(),
        [(100, true), (103, true), (final_code, false)]
    );
    assert!(heard.blocks.iter().all(|block| block.whole));
    assert_eq!(heard.blocks[0].bytes, b"x-first: one\r\n");
    assert_eq!(
        heard.blocks[1].bytes,
        b"x-hint: a-long-field-value-that-is-split-by-the-small-sink\r\n"
    );
    assert!(heard.blocks[2]
        .bytes
        .windows(b"x-final: ".len())
        .any(|bytes| bytes == b"x-final: "));
    assert_eq!(heard.payload, b"ok");
    assert_eq!(heard.ended, final_code == 200);
    if heads != 0 {
        assert_eq!(
            heard.reasons,
            [
                (100, b"Continue".to_vec()),
                (103, b"Early Hints".to_vec()),
                (
                    final_code,
                    if final_code == 101 {
                        b"Switching Protocols".to_vec()
                    } else {
                        b"OK".to_vec()
                    }
                )
            ]
        );
    }
    if frame_cap < 64 {
        assert!(
            heard.blocks[1].parts > 1,
            "interim survives a field continuation"
        );
    }
    host.finish(plugin, &mut dial);
    host.finish(plugin, &mut accept);
    heard
}

#[test]
fn interim_heads_are_flagged_before_the_final_answer_linked_and_dropped() {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let linked: Plugin<Transport> = load_linked(&row(), bind(&dispatcher)).expect("linked door");
    let dropped: Plugin<Transport> =
        load_dropped(&cdylib(), &row().statement, bind(&dispatcher)).expect("dropped door");
    open(&linked);
    open(&dropped);
    for final_code in [101, 200] {
        for (bytes, pieces, heads) in [(4096, 8, 0), (4096, 8, 8), (32, 1, 1)] {
            assert_eq!(
                answer(&linked, final_code, bytes, pieces, heads),
                answer(&dropped, final_code, bytes, pieces, heads)
            );
        }
    }
}
