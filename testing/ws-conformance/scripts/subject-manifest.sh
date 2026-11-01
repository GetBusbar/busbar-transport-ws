#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Writes the ws-conformance subject's build tree at RUN TIME, so it builds from THIS repo against busbar at
# $BUSBAR_CHECKOUT (the `.busbar-ref` pin) without any committed override. The subject is not a workspace
# member: this copies it to <dir>, points the busbar crates at the checkout, the ws logic crate at this repo,
# and the tcp carrier at the rev busbar pins, and `[patch]`es the git forms of both so exactly one copy
# of each links.
#
#   subject-manifest.sh <dir>    prints <dir>/Cargo.toml on stdout
set -euo pipefail
dir="${1:?usage: subject-manifest.sh <dir>}"
: "${BUSBAR_CHECKOUT:?BUSBAR_CHECKOUT (busbar at the .busbar-ref pin) is required}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../subject" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
B="$(cd "$BUSBAR_CHECKOUT" && pwd)"
# The plugin pins live in the default distribution's manifest (busbar 1.6.0-dev.1 on); before it, in
# the root manifest.
tcp_source=""
tcp_rev=""
for m in "$B/dist/default/Cargo.toml" "$B/Cargo.toml"; do
  [ -f "$m" ] || continue
  while IFS= read -r dependency; do
    case "$dependency" in
      'busbar-transport-tcp = { git = "'*)
        tcp_source=${dependency#*\"}
        tcp_source=${tcp_source%%\"*}
        tcp_rev=${dependency#*rev = \"}
        tcp_rev=${tcp_rev%%\"*}
        break
        ;;
    esac
  done < "$m"
  [ -n "$tcp_rev" ] && break
done
[ -n "$tcp_rev" ] || { echo "subject-manifest: no busbar-transport-tcp pin in $B/dist/default/Cargo.toml or $B/Cargo.toml" >&2; exit 1; }
mkdir -p "$dir/src"
cp "$here/src/"*.rs "$dir/src/"
cp "$B/crates/busbar/src/root/doors.rs" "$dir/src/doors.rs"
[ -f "$B/Cargo.lock" ] && cp "$B/Cargo.lock" "$dir/Cargo.lock"
cat > "$dir/Cargo.toml" <<TOML
[workspace]

[package]
name = "ws-conformance-subject"
version = "0.0.0"
publish = false
edition = "2021"

[[bin]]
name = "ws-conformance-subject"
path = "src/main.rs"

[[bin]]
name = "ws-conformance-reference"
path = "src/reference.rs"

[dependencies]
busbar-contract = { path = "$B/crates/busbar-contract" }
busbar-core-connector = { path = "$B/crates/busbar-core-connector" }
busbar-plugin-loader = { path = "$B/crates/plugin-loader" }
busbar-kernel = { path = "$B/crates/busbar-kernel", default-features = false }
busbar-transport-ws = { path = "$repo/transport-ws" }
busbar-transport-tcp = { git = "$tcp_source", rev = "$tcp_rev" }
serde_json = "1"
tokio = { version = "1", features = ["rt", "macros", "net", "io-util", "sync", "time"] }
futures = "0.3"

[patch."https://github.com/GetBusbar/busbar"]
busbar-contract = { path = "$B/crates/busbar-contract" }

[patch."https://github.com/GetBusbar/busbar"]
busbar-contract = { path = "$B/crates/busbar-contract" }

[patch."https://github.com/GetBusbar/busbar-transport-ws"]
busbar-transport-ws = { path = "$repo/transport-ws" }
TOML
echo "$dir/Cargo.toml"
