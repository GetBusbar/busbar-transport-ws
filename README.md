<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
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
