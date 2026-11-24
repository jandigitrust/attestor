"""Launcher regression tests use disposable listeners, never the deployed service."""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "stop_existing", Path(__file__).resolve().parents[1] / "stop_existing.py"
)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def listener(self, name="attestor-server"):
        binary = Path(self.temp.name) / name
        shutil.copyfile(sys.executable, binary)
        binary.chmod(0o755)
        process = subprocess.Popen(
            [
                str(binary),
                "-c",
                (
                    'import socket,time; s=socket.socket(); s.bind(("0.0.0.0",0)); '
                    "s.listen(); print(s.getsockname()[1],flush=True); time.sleep(60)"
                ),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()

        self.addCleanup(cleanup)
        port = int(process.stdout.readline())
        return process, f"127.0.0.1:{port}"

    def test_other_install_path_and_wildcard_listener(self):
        process, address = self.listener()
        launcher.stop(address)
        self.assertIsNotNone(process.poll())
        self.assertFalse(launcher.listeners(address))

    def test_legacy_collector_can_be_replaced(self):
        process, address = self.listener("confido-server")
        launcher.stop(address)
        self.assertIsNotNone(process.poll())

    def test_systemd_service_stopped_before_it_can_restart(self):
        process, address = self.listener()
        real_run = subprocess.run

        def run_command(command, **kwargs):
            if command[0] == "systemctl":
                process.terminate()
                return subprocess.CompletedProcess(command, 0)
            return real_run(command, **kwargs)

        with (
            patch.object(launcher, "service", return_value="attestor-test.service"),
            patch.object(launcher.subprocess, "run", side_effect=run_command) as run,
        ):
            launcher.stop(address)
        run.assert_any_call(
            ["systemctl", "stop", "attestor-test.service"], check=True, timeout=20
        )
        self.assertFalse(launcher.listeners(address))

    def test_unrelated_listener_is_preserved(self):
        process, address = self.listener("unrelated-server")
        with self.assertRaisesRegex(RuntimeError, "unrelated process"):
            launcher.stop(address)
        self.assertIsNone(process.poll())

    def test_only_direct_service_owner_is_stopped(self):
        with (
            patch.object(
                launcher.Path,
                "read_text",
                return_value="0::/system.slice/attestor.service\n",
            ),
            patch.object(launcher.subprocess, "check_output", return_value="123\n"),
        ):
            self.assertEqual(launcher.service(123), "attestor.service")
            self.assertIsNone(launcher.service(456))

    def run_script(self, fail=False):
        root = Path(self.temp.name)
        (root / "cargo").write_text("#!/bin/sh\nexit 0\n")
        (root / "sudo").write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$LAUNCHER_LOG"\n'
            'case "$*" in *--check-config*) exit "$LAUNCHER_FAIL";; esac\n'
            "exit 0\n"
        )
        for name in ("cargo", "sudo"):
            (root / name).chmod(0o755)
        log = root / "calls"
        env = dict(
            os.environ,
            PATH=str(root) + ":" + os.environ["PATH"],
            LAUNCHER_LOG=str(log),
            LAUNCHER_FAIL="1" if fail else "0",
        )
        result = subprocess.run(
            [
                "bash",
                str(Path(__file__).resolve().parents[1] / "run.sh"),
                "127.0.0.1:18011",
                "/test/certs",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, log.read_text().splitlines()

    def test_certificate_preflight_precedes_stop(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertIn("/test/certs", calls[0])
        self.assertIn("--check-config", calls[0])
        self.assertIn("stop_existing.py", calls[1])

    def test_invalid_certificate_preserves_existing_server(self):
        result, calls = self.run_script(fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("--check-config", calls[0])

    def test_address_matching(self):
        self.assertTrue(launcher.conflicts("127.0.0.1:8001", "0.0.0.0:8001"))
        self.assertTrue(launcher.conflicts("[::1]:8001", "[::]:8001"))
        self.assertFalse(launcher.conflicts("127.0.0.1:8001", "127.0.0.2:8001"))
        self.assertFalse(launcher.conflicts("127.0.0.1:8001", "127.0.0.1:8002"))
        self.assertEqual(launcher.listeners("127.0.0.1:0"), set())


if __name__ == "__main__":
    unittest.main()
