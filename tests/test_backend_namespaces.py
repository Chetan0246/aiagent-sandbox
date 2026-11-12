import shutil
import subprocess
import unittest
from unittest.mock import patch

from aegissandbox.backends.namespaces import NamespaceBackend
from aegissandbox.policy import SandboxPolicy


class TestNamespaceBackend(unittest.TestCase):
    def setUp(self):
        self.backend = NamespaceBackend()
        self.policy = SandboxPolicy()

    def test_availability(self):
        has_bwrap = shutil.which("bwrap") is not None
        self.assertEqual(self.backend.is_available(), has_bwrap)

    def test_setup_and_teardown(self):
        self.backend.setup(self.policy)
        self.backend.teardown()

    def test_run_unavailable(self):
        with patch.object(self.backend, "is_available", return_value=False):
            res = self.backend.run(["echo", "hi"], self.policy)
            self.assertEqual(res.returncode, -1)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "missing_dependency")

    def test_run_mocked_timeout(self):
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bwrap"], timeout=1.0, output=b"", stderr=b"timeout"),
        ):
            res = self.backend.run(["sleep", "10"], self.policy, timeout=1.0)
            self.assertEqual(res.returncode, 124)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "timeout")

    def test_run_mocked_exception(self):
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run", side_effect=OSError("OS failure")
        ):
            res = self.backend.run(["echo", "hi"], self.policy)
            self.assertEqual(res.returncode, -1)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "execution_error")

    @unittest.skipUnless(shutil.which("bwrap") is not None, "bwrap not installed")
    def test_run_command_success(self):
        res = self.backend.run(["echo", "sandbox_test"], self.policy)
        self.assertEqual(res.returncode, 0)
        self.assertIn("sandbox_test", res.stdout)
        self.assertEqual(res.backend_name, "namespaces")

    @unittest.skipUnless(shutil.which("bwrap") is not None, "bwrap not installed")
    def test_read_only_root_enforced(self):
        res = self.backend.run(["touch", "/etc/test_file"], self.policy)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Read-only file system", res.stderr)

    @unittest.skipUnless(shutil.which("bwrap") is not None, "bwrap not installed")
    def test_ephemeral_tmp_writable(self):
        res = self.backend.run(
            ["sh", "-c", "echo ok > /tmp/tmp_test && cat /tmp/tmp_test"], self.policy
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("ok", res.stdout)


if __name__ == "__main__":
    unittest.main()
