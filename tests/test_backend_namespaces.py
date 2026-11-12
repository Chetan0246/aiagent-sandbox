import unittest
import shutil
from aegissandbox.backends.namespaces import NamespaceBackend
from aegissandbox.policy import SandboxPolicy

class TestNamespaceBackend(unittest.TestCase):

    def setUp(self):
        self.backend = NamespaceBackend()
        self.policy = SandboxPolicy()

    def test_availability(self):
        has_bwrap = shutil.which("bwrap") is not None
        self.assertEqual(self.backend.is_available(), has_bwrap)

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
        res = self.backend.run(["sh", "-c", "echo ok > /tmp/tmp_test && cat /tmp/tmp_test"], self.policy)
        self.assertEqual(res.returncode, 0)
        self.assertIn("ok", res.stdout)

if __name__ == "__main__":
    unittest.main()
