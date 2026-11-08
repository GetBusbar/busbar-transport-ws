// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTOBAHN|TESTSUITE SUBJECT: busbar's `ws` door, framed by the connector's own listener,
//! echoing on loopback.

use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;

use busbar_core_connector::compose::{Connection, Failure};
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::listen::{AcceptLimits, Listening};

use busbar_core_connector::doors;

/// A door, admitted through the one dispatcher under its row's name and opened.
fn open(key: &str, door: busbar_contract::abi::mechanism::door::DoorFn) -> Arc<dyn FramerDoor> {
    use busbar_plugin_loader::dispatch::{
        kinds::transport::Transport as TransportKind, load_linked, LinkedRow,
    };
    let bind = doors::row_bind(key)
        .unwrap_or_else(|e| panic!("ws-conformance-subject: the `{key}` row has no bind: {e}"));
    let plugin = LinkedRow::of(door)
        .and_then(|row| load_linked::<TransportKind>(&row, bind))
        .unwrap_or_else(|e| panic!("ws-conformance-subject: the `{key}` door is refused: {e}"));
    Arc::new(
        doors::Dispatched::open(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
        )
        .unwrap_or_else(|e| panic!("ws-conformance-subject: the `{key}` door would not open: {e}")),
    )
}

/// The `ws` door.
fn ws_door() -> Arc<dyn FramerDoor> {
    open("ws", busbar_transport_ws::door)
}

/// The carrier it frames over: the `tcp` door, served from the host's I/O.
fn carrier() -> busbar_core_connector::compose::Via {
    busbar_core_connector::compose::Via {
        door: open("tcp", busbar_transport_tcp::door),
        io: busbar_core_connector::hostio::process(),
    }
}

/// Offer one whole message on `stream`, waiting for the socket to take what the write buffer
/// cannot hold yet.
async fn send(conn: &mut Connection, stream: u64, bytes: &[u8], text: bool) -> Result<(), Failure> {
    let mut off = 0;
    poll_fn(|cx| loop {
        let took = match conn.emit(stream, &bytes[off..], true, text, cx) {
            Ok(n) => n,
            Err(Failure::Pending) => return Poll::Pending,
            Err(f) => return Poll::Ready(Err(f)),
        };
        off += took;
        if off == bytes.len() {
            return Poll::Ready(Ok(()));
        }
        if took == 0 {
            return Poll::Pending;
        }
    })
    .await
}

/// Echo every message on `conn`, whole, on the stream it came on.
async fn echo(mut conn: Connection) {
    let mut message: Vec<u8> = Vec::new();

    let mut text = false;
    loop {
        let piece = match poll_fn(|cx| conn.poll_piece(cx)).await {
            Ok(Some(piece)) => piece,
            Ok(None) => break,
            Err(error) => {
                eprintln!("ws-conformance-subject: poll_piece failed: {error:?}");
                break;
            }
        };
        if piece.fields || piece.failed || piece.ends_stream() {
            continue;
        }
        if message.is_empty() {
            text = piece.text;
        }
        message.extend_from_slice(&piece.bytes);
        if !piece.end_of_frame {
            continue;
        }
        let whole = std::mem::take(&mut message);
        if let Err(error) = send(&mut conn, piece.stream, &whole, text).await {
            eprintln!("ws-conformance-subject: echo failed: {error:?}");
            break;
        }
    }
    conn.close();
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::WARN)
        .with_writer(std::io::stderr)
        .init();
    let worker = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("ws-conformance-subject: no runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&worker, async {
        let mut listener = Listening::bind(
            Some(ws_door()),
            &carrier(),
            "127.0.0.1:0",
            None,
            Vec::new(),
            AcceptLimits::default(),
        )
        .expect("ws-conformance-subject: bind failed");
        println!("WS_SUBJECT_PORT={}", listener.local_addr().port());
        use std::io::Write;
        std::io::stdout().flush().ok();
        loop {
            match poll_fn(|cx| listener.poll_accept(cx)).await {
                Ok(accepted) => {
                    tokio::task::spawn_local(echo(accepted.conn));
                }
                Err(e) => {
                    eprintln!("ws-conformance-subject: accept error: {e:?}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    });
}
