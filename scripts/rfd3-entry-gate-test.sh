#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$repo_root" <<'PY'
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest


REPO = Path(sys.argv[1])
sys.argv = [sys.argv[0]]
SOURCE = REPO / "poc" / "rfd3-workload" / "main.c"
CAPTURE = REPO / "scripts" / "rfd3-entry-gate.sh"
REQUEST_ID = "request-0000-0123456789abcdef"
PAYLOAD = "00112233445566778899aabbccddeeff"


class EntryGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="simferret-rfd3-entry-")
        cls.root = Path(cls.temporary.name)
        cls.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.server.bind(("127.0.0.1", 0))
        cls.server.settimeout(1)
        port = cls.server.getsockname()[1]
        cls.binary = cls.root / "fixture"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-static",
                "-Os",
                "-Wall",
                "-Wextra",
                "-Werror",
                '-DFIXTURE_PEER_ADDRESS="127.0.0.1"',
                f"-DFIXTURE_TFTP_PORT={port}",
                str(SOURCE),
                "-o",
                str(cls.binary),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.temporary.cleanup()

    def start_fixture(self):
        process = subprocess.Popen(
            [self.binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.stdout.readline(), "ready version=1\n")
        return process

    def close_streams(self, process):
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def serve_response(self, process, payload):
        process.stdin.write(f"fetch {REQUEST_ID} {PAYLOAD}\n")
        process.stdin.flush()
        request, client = self.server.recvfrom(512)
        self.assertEqual(request, b"\x00\x01" + REQUEST_ID.encode() + b"\x00octet\x00")
        contents = f"request_id={REQUEST_ID}\npayload={payload}\n".encode()
        self.server.sendto(b"\x00\x03\x00\x01" + contents, client)
        acknowledgement, source = self.server.recvfrom(512)
        self.assertEqual(source, client)
        self.assertEqual(acknowledgement, b"\x00\x04\x00\x01")

    def test_fetch_accepts_rfd2_payload_and_rejects_corruption(self):
        success = self.start_fixture()
        try:
            self.serve_response(success, PAYLOAD)
            self.assertEqual(
                success.stdout.readline(), f"network state=ok request={REQUEST_ID}\n"
            )
            success.stdin.write("exit\n")
            success.stdin.flush()
            self.assertEqual(success.stdout.readline(), "stopped status=0\n")
            self.assertEqual(success.wait(timeout=1), 0)
        finally:
            if success.poll() is None:
                success.kill()
                success.wait()
            self.close_streams(success)

        corrupt = self.start_fixture()
        try:
            self.serve_response(corrupt, PAYLOAD + "-corrupted")
            self.assertEqual(corrupt.wait(timeout=1), 1)
            self.assertEqual(corrupt.stderr.read(), "fixture: response content mismatch\n")
        finally:
            if corrupt.poll() is None:
                corrupt.kill()
                corrupt.wait()
            self.close_streams(corrupt)

    def matching_processes(self):
        expected = self.binary.resolve()
        matches = set()
        for candidate in Path("/proc").iterdir():
            if not candidate.name.isdigit():
                continue
            try:
                if (candidate / "exe").resolve() == expected:
                    matches.add(int(candidate.name))
            except (FileNotFoundError, PermissionError):
                pass
        return matches

    def test_only_one_escaped_descendant_is_allowed(self):
        baseline = self.matching_processes()
        process = self.start_fixture()
        descendants = set()
        try:
            process.stdin.write("spawn-descendant\n")
            process.stdin.flush()
            self.assertEqual(process.stdout.readline(), "descendant state=escaped\n")
            descendants = self.matching_processes() - baseline - {process.pid}
            self.assertEqual(len(descendants), 1)

            process.stdin.write("spawn-descendant\n")
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=1), 2)
            self.assertEqual(self.matching_processes() - baseline, descendants)
            for descendant in descendants:
                os.kill(descendant, signal.SIGKILL)
            descendants.clear()
            self.assertEqual(process.stderr.read(), "fixture: descendant already spawned\n")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            for descendant in self.matching_processes() - baseline:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.close_streams(process)

    def test_concurrent_captures_publish_distinct_directories(self):
        output = self.root / "captures"
        environment = os.environ | {"SIMFERRET_RFD3_ENTRY_OUTPUT": str(output)}
        processes = [
            subprocess.Popen(
                [CAPTURE],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )
            for _ in range(2)
        ]
        results = [process.communicate(timeout=30) for process in processes]
        for process, (_, stderr) in zip(processes, results):
            self.assertEqual(process.returncode, 0, stderr)
        captures = sorted(output.glob("capture.*"))
        self.assertEqual(len(captures), 2)
        snapshots = [
            {
                path.relative_to(capture): path.read_bytes()
                for path in capture.rglob("*")
                if path.is_file()
            }
            for capture in captures
        ]
        self.assertEqual(snapshots[0], snapshots[1])
        expected = (captures[0] / "capture.json").read_text()
        self.assertEqual([stdout for stdout, _ in results], [expected, expected])


if __name__ == "__main__":
    unittest.main(verbosity=2)
PY
