<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-ws

First-party signed kind:transport plugin cdylib: the ws transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `ws` | `busbar-transport-ws-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-transport-ws/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-ws/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-transport-ws` is a `kind: transport` busbar plugin.

## Config

Configured under the `ws` module name.

The settings object accepts `limits.request_body_max_bytes`, a positive integer byte count. It
bounds both a complete incoming message and an individual frame, and bounds outgoing messages.
An omitted value uses the contract's default. Refresh changes the ceiling for new framings;
existing connections retain the ceiling they opened with.

The plugin negotiates no WebSocket extensions, including permessage-deflate. A dial requesting an
extension, or a server response selecting one, is refused. Accepted upgrades select no subprotocol;
dials carry the offered subprotocols and require the server's selection to be one of them. The
host connector supplies sockets and TLS for `wss`; this plugin frames the bytes.

The Autobahn harness's `--selftest` checks synthetic parser fixtures and builds its subject, so it
requires Node, Cargo and `BUSBAR_CHECKOUT` at the pinned core source. Docker-live control, negative
control and subject legs run through `testing/conformance/ws.sh` in CI. A negative control counts
only when Autobahn records the deliberately broken peer's echo corruption, not an unrelated failure.

## Build

```bash
cargo build --release -p busbar-transport-ws-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
