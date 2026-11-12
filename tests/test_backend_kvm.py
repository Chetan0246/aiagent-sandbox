import shutil
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from aegissandbox.backends.kvm import KvmBackend
from aegissandbox.policy import SandboxPolicy


class TestKvmBackend(unittest.TestCase):
    def setUp(self):
        self.backend = KvmBackend(
            vm_name="debian-minimal", vm_ip="192.168.122.71", user="agentuser"
        )
        self.policy = SandboxPolicy()

    def test_availability_check(self):
        has_virsh = shutil.which("virsh") is not None
        self.assertEqual(self.backend.is_available(), has_virsh)

    def test_command_formatting(self):
        cmd = self.backend._format_ssh_command(["echo", "hello"], self.policy)
        self.assertIn("echo hello", cmd)

    def test_setup_and_teardown(self):
        self.backend.setup(self.policy)
        self.backend.teardown()

    def test_run_unavailable(self):
        with patch.object(self.backend, "is_available", return_value=False):
            res = self.backend.run(["echo", "hi"], self.policy)
            self.assertEqual(res.returncode, -1)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "missing_dependency")

    def test_run_success(self):
        mock_proc = MagicMock(returncode=0, stdout="kvm output\n", stderr="")
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run", return_value=mock_proc
        ):
            res = self.backend.run(["echo", "kvm output"], self.policy)
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout, "kvm output\n")
            self.assertFalse(res.violation_detected)

    def test_run_permission_denied_violation(self):
        mock_proc = MagicMock(returncode=1, stdout="", stderr="bash: /root/secret: Permission denied")
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run", return_value=mock_proc
        ):
            res = self.backend.run(["cat", "/root/secret"], self.policy)
            self.assertEqual(res.returncode, 1)
            self.assertTrue(res.violation_detected)

    def test_run_timeout(self):
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["ssh"], timeout=5.0, output=b"", stderr=b"timeout"),
        ):
            res = self.backend.run(["sleep", "10"], self.policy, timeout=5.0)
            self.assertEqual(res.returncode, 124)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "timeout")

    def test_run_exception(self):
        with patch.object(self.backend, "is_available", return_value=True), patch(
            "subprocess.run", side_effect=OSError("Network is unreachable")
        ):
            res = self.backend.run(["echo", "hi"], self.policy)
            self.assertEqual(res.returncode, -1)
            self.assertTrue(res.violation_detected)
            self.assertEqual(res.violation_reason, "execution_error")


if __name__ == "__main__":
    unittest.main()
