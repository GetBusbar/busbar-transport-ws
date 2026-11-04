#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors

"""Run the real driver with controlled compiler/Docker/peer processes; no product grade is forged."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest


HARNESS = Path(__file__).resolve().parents[1]


class Runner(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ws-runner-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.harness = self.root / "harness"
        shutil.copytree(HARNESS, self.harness, ignore=shutil.ignore_patterns("reports", "node_modules", "__pycache__"))
        self.real_node = shutil.which("node")
        self.assertIsNotNone(self.real_node, "Node is required by the existing WebSocket harness")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.executable("cargo", "import sys\nsys.exit(0)\n")
        self.executable("node", """
import os, signal, sys
from pathlib import Path
if len(sys.argv) > 1 and sys.argv[1].endswith('broken-echo-server.mjs'):
    Path(os.environ['PEER_PID']).write_text(str(os.getpid()))
    print('BROKEN_PORT=12345', flush=True)
    while True:
        signal.pause()
os.execv(os.environ['REAL_NODE'], [os.environ['REAL_NODE'], *sys.argv[1:]])
""")
        self.executable("docker", """
import json, os, sys, time
from pathlib import Path
if os.environ.get('BLOCK_DOCKER'):
    Path(os.environ['DOCKER_STARTED']).touch()
    while not Path(os.environ['DOCKER_RELEASE']).exists():
        time.sleep(0.01)
for index, arg in enumerate(sys.argv):
    if arg == '-v' and sys.argv[index + 1].endswith(':/reports'):
        output = Path(sys.argv[index + 1][:-len(':/reports')])
        output.mkdir(parents=True, exist_ok=True)
        (output / 'index.json').write_text(os.environ['CONTROL_REPORT'])
""")
        target = self.root / "target"
        (target / "debug").mkdir(parents=True)
        subject = target / "debug/ws-conformance-subject"
        subject.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        subject.chmod(0o700)
        manifest = self.root / "Cargo.toml"
        manifest.write_text("# The compiler is a controlled process in this driver-only test.\n", encoding="utf-8")
        self.environment = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            REAL_NODE=self.real_node,
            PEER_PID=str(self.root / "peer.pid"),
            DOCKER_STARTED=str(self.root / "docker.started"),
            DOCKER_RELEASE=str(self.root / "docker.release"),
            CONTROL_REPORT=json.dumps({"broken": {"1.1.2": {"behavior": "FAILED"}}}),
            WS_SUBJECT_MANIFEST=str(manifest),
            CARGO_TARGET_DIR=str(target),
        )

    def executable(self, name, source):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + source.lstrip(), encoding="utf-8")
        path.chmod(0o700)

    def run_driver(self, mode):
        # Keep the group leader unreaped until timeout cleanup has signalled the whole owned
        # session. Killing only Bash bypasses its traps and can leave the controlled peer alive.
        with subprocess.Popen(
            ["bash", str(self.harness / "scripts/run.sh"), mode],
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        ) as driver:
            try:
                stdout, stderr = driver.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(driver.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    driver.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(driver.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    driver.communicate()
                raise
            return subprocess.CompletedProcess(driver.args, driver.returncode, stdout, stderr)

    def test_parser_fixture_paths_are_data_even_under_a_quoted_tmpdir(self):
        quoted = self.root / "quoted' temporary path"
        quoted.mkdir()
        self.environment["TMPDIR"] = str(quoted)
        result = self.run_driver("--selftest")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(quoted.iterdir()), [], "owned fixture scratch is removed")

    def test_an_unrelated_red_case_does_not_prove_the_echo_negative_control(self):
        self.environment["CONTROL_REPORT"] = json.dumps({"broken": {"2.1": {"behavior": "FAILED"}}})
        result = self.run_driver("--negative-control")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_recorded_echo_failure_remains_a_successful_negative_control(self):
        result = self.run_driver("--negative-control")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def owned_peer_is_running(self, pid):
        result = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, check=False)
        return result.returncode == 0 and str(self.bin / "node") in result.stdout

    def test_term_reaps_the_started_peer_and_preserves_the_signal_exit(self):
        self.environment["BLOCK_DOCKER"] = "1"
        log = self.root / "driver.log"
        with log.open("w", encoding="utf-8") as output:
            driver = subprocess.Popen(
                ["bash", str(self.harness / "scripts/run.sh"), "--negative-control"],
                env=self.environment, stdout=output, stderr=subprocess.STDOUT,
            )
        peer = None
        try:
            deadline = time.monotonic() + 10
            while not (self.root / "docker.started").exists():
                self.assertIsNone(driver.poll(), log.read_text(encoding="utf-8"))
                self.assertLess(time.monotonic(), deadline, "controlled Docker did not start")
                time.sleep(0.01)
            peer = int((self.root / "peer.pid").read_text(encoding="utf-8"))
            self.assertTrue(self.owned_peer_is_running(peer))
            driver.terminate()
            (self.root / "docker.release").touch()
            self.assertEqual(driver.wait(timeout=10), 143, log.read_text(encoding="utf-8"))
            self.assertFalse(self.owned_peer_is_running(peer), "TERM must reap the driver's own peer")
        finally:
            (self.root / "docker.release").touch()
            if driver.poll() is None:
                driver.kill()
            driver.wait(timeout=10)
            if peer is not None and self.owned_peer_is_running(peer):
                os.kill(peer, signal.SIGTERM)


class Manifest(unittest.TestCase):
    def test_the_subject_preserves_the_core_tcp_source_and_revision(self):
        revision = "de7af6404e1e281841c39a01d48fd2b405e2f1bc"
        for source in [
            "https://github.com/GetBusbar/busbar-transport-tcp",
            "https://github.com/GetBusbar/busbar-transport-tcp",
        ]:
            with self.subTest(source=source), tempfile.TemporaryDirectory(prefix="ws-manifest-") as temporary:
                root = Path(temporary)
                core = root / "core"
                (core / "dist/default").mkdir(parents=True)
                adapter = "// selected core adapter fixture\n"
                (core / "crates/busbar/src/root").mkdir(parents=True)
                (core / "crates/busbar/src/root/doors.rs").write_text(adapter, encoding="utf-8")
                (core / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
                dependency = f'busbar-transport-tcp = {{ git = "{source}", rev = "{revision}" }}'
                (core / "dist/default/Cargo.toml").write_text(dependency + "\n", encoding="utf-8")
                environment = dict(os.environ, BUSBAR_CHECKOUT=str(core))
                result = subprocess.run(
                    ["bash", str(HARNESS / "scripts/subject-manifest.sh"), str(root / "subject")],
                    env=environment, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                manifest = Path(result.stdout.strip()).read_text(encoding="utf-8")
                self.assertEqual((root / "subject/src/doors.rs").read_text(encoding="utf-8"), adapter)
                self.assertIn(dependency, manifest)
                workspace = tomllib.loads((HARNESS.parents[1] / "Cargo.toml").read_text())
                generated = tomllib.loads(manifest)
                self.assertEqual(generated.get("patch", {}).get("crates-io"), workspace["patch"]["crates-io"],
                                 "the conformance subject must use the product's patched protocol library")
                for core_source in [
                    "https://github.com/GetBusbar/busbar",
                    "https://github.com/GetBusbar/busbar",
                ]:
                    self.assertIn(
                        f'[patch."{core_source}"]\nbusbar-contract = {{ path = "{core}/crates/busbar-contract" }}',
                        manifest,
                    )


if __name__ == "__main__":
    unittest.main()
