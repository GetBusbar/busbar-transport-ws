# Offline ws conformance tools

The controller stages Autobahn Testsuite 25.10.1 (the existing pinned image), PyPy 2.7, and locked ws 8.21.3 before admitting a candidate. Run this from the reviewed source checkout, with both destinations outside the candidate tree:

```sh
python3 testing/conformance/stage-tools.py --output /controller/tools/ws --cache /controller/public-downloads
```

The stager verifies the immutable public OCI manifests and layers and each NPM lockfile's SHA-512 integrity before unpacking. It executes no downloaded code or package scripts. It writes `ws-inputs.json` beside the bundle using `busbar.native-conformance-inputs/1`: every regular file has a SHA-256 and executable-mode flag, and public input provenance is retained. Symlink and hardlink aliases become separate regular files. Supply this manifest through the controller's protected `BUSBAR_CONFORMANCE_INPUTS` interface; the controller independently verifies the tree and mounts it read-only at `/opt/busbar-conformance/ws`.

The suite executes only that fixed mount. Its subjects and external judges communicate over the candidate's private loopback interface. Missing tools fail the required evaluation. No candidate package manager, Docker socket, host network, shared host IPC, or privilege is used. Existing control, negative-control, and subject grading criteria remain authoritative.

The previous report label `autobahn-testsuite 0.8.2` was stale: the existing image digest `519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074` contains Testsuite 25.10.1. The report now names the actual pinned instrument; the protocol case selection and parser criteria are unchanged.
