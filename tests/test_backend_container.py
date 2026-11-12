import unittest
import shutil
from aegissandbox.backends.container import ContainerBackend
from aegissandbox.policy import SandboxPolicy

class TestContainerBackend(unittest.TestCase):

    def setUp(self):
        self.backend = ContainerBackend()
        self.policy = SandboxPolicy()

    def test_availability(self):
        has_podman = shutil.which("podman") is not None
        self.assertEqual(self.backend.is_available(), has_podman)

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
