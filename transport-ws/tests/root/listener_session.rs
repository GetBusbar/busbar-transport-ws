// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// The peer is supplied by the assembling host through the transport kind declaration.
fn assembled_http_peer() -> busbar_contract::abi::mechanism::door::DoorFn {
    crate::dist_root_install::install();
    let mut peers = crate::LINKED_TRANSPORT_DOORS
        .iter()
        .filter_map(|(_, door)| {
            let facts = crate::root::loader::dispatch::kinds::transport::stated(*door)
                .expect("assembled transport has a valid kind declaration");
            facts.claims.contains(&"http").then_some(*door)
        });
    let peer = peers.next().expect("the assembly supplies the HTTP peer");
    assert!(peers.next().is_none(), "the HTTP peer claim is unambiguous");
    peer
}

async fn actual_session_framer() -> (
    tokio::sync::MutexGuard<'static, ()>,
    DataFramer,
    Arc<ObservedDoor>,
    Arc<ObservedDoor>,
) {
    use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
    let publishing = anonymous_policy_with_upgrade(Some("ws")).await;
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    assert!(crate::root::inbound::install(&dispatcher));
    let http = ObservedDoor::new(actual_transport_on(
        assembled_http_peer(),
        dispatcher.clone(),
    ));
    #[cfg(feature = "transport-ws")]
    let ws = ObservedDoor::new(actual_transport_on(busbar_transport_ws::door, dispatcher));
    #[cfg(not(feature = "transport-ws"))]
    let ws = {
        use crate::root::loader::dispatch::{
            kinds::transport::Transport, load_dropped, rendering_of_library,
        };
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_WS_CDYLIB")
                .expect("BUSBAR_TEST_WS_CDYLIB names the actual WS product when it is not linked"),
        );
        let statement = rendering_of_library(&path)
            .expect("the actual dropped WS statement reads")
            .expect("the actual dropped WS exports its statement");
        let plugin =
            load_dropped::<Transport>(&path, &statement, crate::root::doors::bind_on(&dispatcher))
                .expect("the actual dropped WS binds through its memory ABI");
        let door: Arc<dyn FramerDoor> = Arc::new(
            crate::root::doors::Dispatched::open_on(
                plugin,
                &busbar_contract::transport::TransportSettings::default(),
                dispatcher,
            )
            .expect("the actual dropped WS opens on the same root host"),
        );
        ObservedDoor::new(door)
    };
    let (http_door, ws_door): (Arc<dyn FramerDoor>, Arc<dyn FramerDoor>) =
        (http.clone(), ws.clone());
    let framer = data_framer(Arc::new(move |scheme| {
        [&http_door, &ws_door]
            .into_iter()
            .find(|door| door.facts().claims.contains(&scheme))
            .cloned()
    }))
    .expect("actual HTTP opens the connection and WS owns its admitted upgrade");
    (publishing, framer, http, ws)
}

const SESSION_REQUEST: &[u8] = b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

#[tokio::test]

async fn a_session_waits_for_its_parked_message_before_emitting_the_next() {
    use busbar_kernel::plane_routes::{FramedSession, SessionOut, SessionPipe};
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            |axum::Extension(session): axum::Extension<FramedSession>| async move {
                assert!(session.admit().await);
                let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                let (outgoing, to_caller) = tokio::sync::mpsc::channel(2);
                outgoing
                    .try_send(SessionOut {
                        bytes: b"first".to_vec(),
                        text: true,
                    })
                    .unwrap();
                outgoing
                    .try_send(SessionOut {
                        bytes: b"second".to_vec(),
                        text: false,
                    })
                    .unwrap();
                drop(outgoing);
                session.put(SessionPipe {
                    from_caller,
                    to_caller,
                });
                axum::http::StatusCode::SWITCHING_PROTOCOLS
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(1);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(SESSION_REQUEST).await.unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            assert_eq!(client.read(&mut byte).await.unwrap(), 1);
            head.push(byte[0]);
            assert!(head.len() < 16 * 1024);
        }
        while ws.count(|call| {
            matches!(
                call,
                ObservedCall::Emit {
                    status: 0,
                    len: 5,
                    ..
                }
            )
        }) == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actual WS message reaches the blocked one-byte pipe");
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut served)
            .await
            .is_err(),
        "wire pressure keeps the queued session alive after its producer closes"
    );
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        for (opcode, expected) in [(1_u8, b"first".as_slice()), (2_u8, b"second".as_slice())] {
            let mut header = [0; 2];
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(
                header[0],
                0x80 | opcode,
                "the actual WS message keeps its frame kind"
            );
            assert_eq!(
                header[1] as usize,
                expected.len(),
                "server frames are complete and unmasked"
            );
            let mut payload = vec![0; expected.len()];
            client.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, expected);
            frames.push(payload);
        }
    })
    .await
    .expect("both messages arrive once and in order after reading resumes");
    assert_eq!(frames, [b"first".to_vec(), b"second".to_vec()]);
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        1,
        "the actual session handshake commits once"
    );
    let _ = stop.send(true);

    let mut close_wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut close_wire))
        .await
        .expect("the real WS close frame drains before the server retires")
        .unwrap();
    assert_eq!(
        close_wire,
        [0x88, 0x02, 0x03, 0xe8],
        "exact unmasked normal WS close"
    );
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

fn held_session_refusal_route() -> (
    Router,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    use busbar_kernel::plane_routes::FramedSession;
    let (entered, admitted) = tokio::sync::oneshot::channel();
    let (release, held) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let held = Arc::new(std::sync::Mutex::new(Some(held)));
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let entered = entered.lock().unwrap().take().unwrap();
                let held = held.lock().unwrap().take().unwrap();
                async move {
                    assert!(session.admit().await, "the typed stage accepts admission");
                    let _ = entered.send(());
                    let _ = held.await;
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::UNAUTHORIZED)
                        .header(
                            axum::http::header::WWW_AUTHENTICATE,
                            "Bearer realm=\"staged\"",
                        )
                        .body(axum::body::Body::from("the staged plane refused"))
                        .unwrap()
                }
            },
        ),
    );
    (router, admitted, release)
}

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn an_ended_session_adoption_refuses_before_any_plane_effect() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (_publishing, framer, http, ws) = actual_session_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let route_effects = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = route_effects.clone();
                async move {
                    if session.admit().await {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));

    client.write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n").await.unwrap();
    let mut wire = read_reply(&mut client, b"").await;
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    drain_reply(&mut client, &mut wire).await;
    assert!(
        wire.starts_with(b"HTTP/1.1 400") || wire.starts_with(b"HTTP/1.1 426"),
        "{wire:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&wire).matches("HTTP/1.1 ").count(),
        1,
        "the actual adoption refusal is preserved without an extractor fallback"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "admission gates every plane effect"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
        0
    );
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Emit { .. })),
        0,
        "no extractor fallback overwrites the stage refusal"
    );
}

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn a_staged_plane_refusal_keeps_its_head_and_body_without_committing_101() {
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let (router, admitted, release) = held_session_refusal_route();
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), admitted)
        .await
        .expect("the real typed stage reaches the route")
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "adoption's 101 bytes stay held while the route decides"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
        0
    );
    release.send(()).unwrap();
    let body = b"the staged plane refused";
    let mut wire = read_reply(&mut client, body).await;
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    drain_reply(&mut client, &mut wire).await;
    let head_end = wire
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8_lossy(&wire[..head_end]).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 401"), "{head}");
    assert!(
        head.contains("www-authenticate: bearer realm=\"staged\""),
        "{head}"
    );
    assert_eq!(
        &wire[head_end + 4..],
        body,
        "the full refusal body is unchanged"
    );
    assert_eq!(
        String::from_utf8_lossy(&wire).matches("HTTP/1.1 ").count(),
        1
    );
    assert!(!wire.windows(12).any(|bytes| bytes == b"HTTP/1.1 101"));
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 401, .. })),
        1
    );
    assert_eq!(ws.count(|call| matches!(call, ObservedCall::Emit { status: 0, end: false, len } if *len == body.len())), 1,
        "the refusal payload reaches the actual adopted transport emitter");
    assert_eq!(
        ws.count(|call| matches!(
            call,
            ObservedCall::Emit {
                status: 0,
                end: true,
                len: 0
            }
        )),
        1,
        "the refusal body is terminated through its actual emitter"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
        3,
        "only the refusal head, body and terminal emit occur; no application frame follows"
    );
}

#[cfg(feature = "transport-ws")]
#[tokio::test(start_paused = true)]
async fn stopping_eof_and_timeout_abandon_uncommitted_sessions_without_wire() {
    for ending in ["stop", "eof", "timeout"] {
        let (_publishing, framer, _http, ws) = actual_session_framer().await;
        let (router, admitted, mut held) = held_session_refusal_route();
        let (mut client, server) = tokio::io::duplex(4096);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let served = tokio::spawn(super::serve(
            server,
            framer,
            router,
            false,
            Duration::from_secs(60),
            stopped,
        ));
        client.write_all(SESSION_REQUEST).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), admitted)
            .await
            .expect("the route holds an admitted but uncommitted stage")
            .unwrap();
        let mut byte = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err(),
            "{ending}: no provisional handshake or application frame reaches the wire"
        );
        match ending {
            "stop" => {
                stop.send(true).unwrap();
            }
            "eof" => {
                client.shutdown().await.unwrap();
            }
            "timeout" => {
                tokio::time::advance(Duration::from_secs(61)).await;
            }
            _ => unreachable!(),
        }
        tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .expect("the abandoned staging actor terminates")
            .unwrap();
        let mut wire = Vec::new();
        drain_reply(&mut client, &mut wire).await;
        assert!(
            wire.is_empty(),
            "{ending}: neither held adoption nor finish wire may leak: {wire:?}"
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
            0,
            "{ending}"
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Finish)),
            1,
            "{ending}: staged framing finishes exactly once"
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
            0,
            "{ending}"
        );
        tokio::time::timeout(Duration::from_secs(1), held.closed())
            .await
            .expect("the abandoned route receiver is cancelled");
        assert!(held.is_closed(), "{ending}: the pending route is cancelled");
    }
}

#[tokio::test]

async fn a_pending_session_adoption_admits_only_after_its_original_ticket_is_ready() {
    use busbar_kernel::plane_routes::{FramedSession, SessionPipe};
    use std::future::Future as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let (entered, pending) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let (release, held) = tokio::sync::oneshot::channel();
    let held = Arc::new(std::sync::Mutex::new(Some(held)));
    let route_effects = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let entered = entered.lock().unwrap().take().unwrap();
                let held = held.lock().unwrap().take().unwrap();
                let effects = route_effects.clone();
                async move {
                    let mut admission = Box::pin(session.admit());
                    std::future::poll_fn(|cx| {
                        assert!(
                            admission.as_mut().poll(cx).is_pending(),
                            "the native admission awaits its actor"
                        );
                        Poll::Ready(())
                    })
                    .await;
                    entered.send(()).unwrap();
                    held.await.unwrap();
                    assert!(
                        admission.await,
                        "the original native admission command acknowledges readiness"
                    );
                    effects.fetch_add(1, Ordering::SeqCst);
                    let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                    let (_outgoing, to_caller) = tokio::sync::mpsc::channel(1);
                    session.put(SessionPipe {
                        from_caller,
                        to_caller,
                    });
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "the uncommitted admission publishes no handshake wire"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "no route effect precedes native readiness"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    release.send(()).unwrap();
    let head = read_reply(&mut client, b"").await;
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        1
    );
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]

async fn a_pending_session_adoption_that_refuses_never_admits_the_route() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, http, ws) = actual_session_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let route_effects = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = route_effects.clone();
                async move {
                    if session.admit().await {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));

    client.write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n").await.unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    client.write_all(b"\r\n").await.unwrap();
    let mut wire = read_reply(&mut client, b"").await;
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    drain_reply(&mut client, &mut wire).await;
    assert!(
        wire.starts_with(b"HTTP/1.1 400") || wire.starts_with(b"HTTP/1.1 426"),
        "{wire:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&wire).matches("HTTP/1.1 ").count(),
        1,
        "the real missing-key refusal is published once"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "refused adoption admits no route effect"
    );
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
}

#[tokio::test]

async fn a_pending_session_commit_holds_wire_and_application_calls_until_ready() {
    use busbar_kernel::plane_routes::{FramedSession, SessionOut, SessionPipe};
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let (entered, admitted) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let (release, held) = tokio::sync::oneshot::channel();
    let held = Arc::new(std::sync::Mutex::new(Some(held)));
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let entered = entered.lock().unwrap().take().unwrap();
                let held = held.lock().unwrap().take().unwrap();
                async move {
                    assert!(session.admit().await);
                    let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                    let (outgoing, to_caller) = tokio::sync::mpsc::channel(1);
                    outgoing
                        .send(SessionOut {
                            bytes: b"after-commit".to_vec(),
                            text: false,
                        })
                        .await
                        .unwrap();
                    session.put(SessionPipe {
                        from_caller,
                        to_caller,
                    });
                    entered.send(()).unwrap();
                    held.await.unwrap();
                    drop(outgoing);
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), admitted)
        .await
        .unwrap()
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "the actual stage holds handshake and queued message while its route decision is pending"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 0, .. })),
        0
    );
    release.send(()).unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            client.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            assert!(head.len() < 16 * 1024);
        }
        let mut frame = [0; 2];
        client.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame, [0x82, 12]);
        let mut body = [0; 12];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"after-commit");
    })
    .await
    .expect("commit publishes one real handshake followed by the queued message");
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        1
    );
    assert_eq!(
        ws.count(|call| matches!(
            call,
            ObservedCall::Emit {
                status: 0,
                len: 12,
                ..
            }
        )),
        1
    );
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]

async fn cancelled_pending_adoption_and_commit_ignore_their_late_wakes() {
    use busbar_kernel::plane_routes::{FramedSession, SessionPipe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for adopting in [true, false] {
        let (_publishing, framer, http, ws) = actual_session_framer().await;
        let effects = Arc::new(AtomicUsize::new(0));
        let route_effects = effects.clone();
        let (entered, mut admitted) = tokio::sync::oneshot::channel();
        let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
        let (release, held) = tokio::sync::oneshot::channel();
        let held = Arc::new(std::sync::Mutex::new(Some(held)));
        let router = Router::new().route(
            "/first",
            axum::routing::get(
                move |axum::Extension(session): axum::Extension<FramedSession>| {
                    let entered = entered.lock().unwrap().take().unwrap();
                    let held = held.lock().unwrap().take().unwrap();
                    let effects = route_effects.clone();
                    async move {
                        assert!(session.admit().await);
                        entered.send(()).unwrap();
                        held.await.unwrap();
                        effects.fetch_add(1, Ordering::SeqCst);
                        let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                        let (_outgoing, to_caller) = tokio::sync::mpsc::channel(1);
                        session.put(SessionPipe {
                            from_caller,
                            to_caller,
                        });
                        axum::http::StatusCode::SWITCHING_PROTOCOLS
                    }
                },
            ),
        );
        let (mut client, server) = tokio::io::duplex(4096);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let served = tokio::spawn(super::serve(
            server,
            framer,
            router,
            false,
            Duration::from_secs(30),
            stopped,
        ));
        if adopting {
            client
                .write_all(&SESSION_REQUEST[..SESSION_REQUEST.len() - 2])
                .await
                .unwrap();
        } else {
            client.write_all(SESSION_REQUEST).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), &mut admitted)
                .await
                .unwrap()
                .unwrap();
        }
        let mut byte = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
            0
        );
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .expect("cancellation closes the actual staged actor")
            .unwrap();
        let before = ws.count(|call| matches!(call, ObservedCall::Emit { .. }));
        let _ = release.send(());
        if adopting {
            let _ = client.write_all(b"\r\n").await;
        }
        tokio::task::yield_now().await;
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        assert!(
            wire.is_empty(),
            "late peer bytes or route readiness cannot publish canceled handshake wire"
        );
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
            before,
            "late readiness cannot emit a message or repeat a commit"
        );
        assert_eq!(
            http.count(|call| matches!(call, ObservedCall::Detach)),
            usize::from(!adopting),
            "only a committed transfer consumes the old HTTP framing"
        );
        assert_eq!(
            http.count(|call| matches!(call, ObservedCall::Finish)),
            usize::from(adopting),
            "cancel before transfer finishes HTTP; terminal detach must not finish its consumed token again"
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Finish)),
            usize::from(!adopting),
            "after transfer the adopted WS framing owns exactly one finish"
        );
        if adopting {
            assert!(
                admitted.await.is_err(),
                "a canceled unparsed head never admits its route"
            );
        }
    }
}

#[tokio::test]
async fn a_dropped_pending_admission_ack_cannot_publish_a_late_acceptance() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::future::Future as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, http, ws) = actual_session_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let route_effects = effects.clone();
    let (dropped, ack_dropped) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(std::sync::Mutex::new(Some(dropped)));
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = route_effects.clone();
                let dropped = dropped.lock().unwrap().take().unwrap();
                async move {
                    let mut admission = Box::pin(session.admit());
                    std::future::poll_fn(|cx| {
                        let result = admission.as_mut().poll(cx);
                        if matches!(result, Poll::Ready(true)) {
                            effects.fetch_add(1, Ordering::SeqCst);
                        }
                        assert!(
                            result.is_pending(),
                            "the real admission command waits for its actor acknowledgement"
                        );
                        Poll::Ready(())
                    })
                    .await;
                    drop(admission);
                    let _ = dropped.send(());

                    axum::http::StatusCode::REQUEST_TIMEOUT
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (_stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), ack_dropped)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("a dropped native acknowledgement abandons the actual stage")
        .unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).await.unwrap();
    assert!(
        wire.is_empty(),
        "a dropped acknowledgement cannot publish held handshake wire"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "no admitted application effect"
    );
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Detach)),
        0,
        "an already cancelled admission never detaches its source framing"
    );
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
}

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn a_plain_request_that_declines_detach_keeps_http_400_and_runs_no_plane_effect() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, http, ws) = actual_session_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let route_effects = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = route_effects.clone();
                async move {
                    if session.admit().await {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    axum::http::StatusCode::FORBIDDEN
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client
        .write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let wire = read_reply(&mut client, b"").await;
    assert!(wire.starts_with(b"HTTP/1.1 400"), "{wire:?}");
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Detach)),
        1,
        "the actual detach refused"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Adopt)),
        0,
        "the WS framer is never adopted"
    );
    assert_eq!(
        http.count(|call| matches!(
            call,
            ObservedCall::Refuse {
                stream: 1,
                status: 400,
                head_sent: false
            }
        )),
        1
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert!(
        http.count(|call| matches!(call, ObservedCall::Emit { .. })) == 0,
        "the route's fallback 403 is suppressed"
    );
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the retained HTTP actor closes normally")
        .unwrap();
    let mut rest = Vec::new();
    drain_reply(&mut client, &mut rest).await;
    assert!(
        rest.is_empty(),
        "there is no duplicate refusal or 101 handshake"
    );
    assert_eq!(http.count(|call| matches!(call, ObservedCall::Finish)), 1);
    assert_eq!(ws.count(|call| matches!(call, ObservedCall::Finish)), 0);
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Cancel))
            + ws.count(|call| matches!(call, ObservedCall::Cancel)),
        0
    );
}

#[cfg(feature = "transport-ws")]
#[path = "listener_real_session_tests.rs"]
mod real_session_tests;
