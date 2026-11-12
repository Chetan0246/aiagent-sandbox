import unittest
import shutil
from aegissandbox.backends.kvm import KvmBackend
from aegissandbox.policy import SandboxPolicy

class TestKvmBackend(unittest.TestCase):

    def setUp(self):
        self.backend = KvmBackend(vm_name="debian-minimal", vm_ip="192.168.122.71", user="agentuser")
        self.policy = SandboxPolicy()

    def test_availability_check(self):
        has_virsh = shutil.which("virsh") is not None
        self.assertEqual(self.backend.is_available(), has_virsh)

    def test_command_formatting(self):
        cmd = self.backend._format_ssh_command(["echo", "hello"], self.policy)
        self.assertIn("echo hello", cmd)

if __name__ == "__main__":
    unittest.main()
