import shutil
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from aegissandbox.backends.container import ContainerBackend
from aegissandbox.policy import SandboxPolicy


class TestContainerBackend(unittest.TestCase):
    def setUp(self):
        self.backend = ContainerBackend()
        self.policy = SandboxPolicy()

    def test_availability(self):
        has_podman = shutil.which("podman") is not None or shutil.which("docker") is not None
        self.assertEqual(self.backend.is_available(), has_podman)

    def test_setup_and_teardown(self):
        self.backend.setup(self.policy)
        self.backend.teardown()

    def test_run_unavailable(self):
        with patch.object(self.backend, "is_available", return_value=False):
            res = self.backend.run(["echo", "hi"], self.policy)
            self.assertEqual(res.returncode, -1)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "missing_dependency")

    def test_run_mocked_success(self):
        mock_proc = MagicMock(returncode=0, stdout="container output\n", stderr="")
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run", return_value=mock_proc
        ):
            res = self.backend.run(["echo", "container output"], self.policy)
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout, "container output\n")
            self.assertFalse(res.violation_detected)

    def test_run_mocked_timeout(self):
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["podman"], timeout=2.0, output=b"", stderr=b"timeout"),
        ):
            res = self.backend.run(["sleep", "10"], self.policy, timeout=2.0)
            self.assertEqual(res.returncode, 124)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "timeout")

    def test_run_mocked_exception(self):
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run", side_effect=RuntimeError("Runtime failure")
        ):
            res = self.backend.run(["echo", "hi"], self.policy)
            self.assertEqual(res.returncode, -1)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "execution_error")

    @unittest.skipUnless(shutil.which("podman") is not None, "podman not installed")
    def test_run_echo_success(self):
        res = self.backend.run(["echo", "container_ok"], self.policy)
        self.assertEqual(res.returncode, 0)
        self.assertIn("container_ok", res.stdout)
        self.assertEqual(res.backend_name, "container")

    @unittest.skipUnless(shutil.which("podman") is not None, "podman not installed")
    def test_read_only_root_in_container(self):
        res = self.backend.run(["touch", "/etc/pwned"], self.policy)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Read-only file system", res.stderr)


if __name__ == "__main__":
    unittest.main()
