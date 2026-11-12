import unittest
from aegissandbox.runner import SandboxRunner
from aegissandbox.policy import SandboxPolicy

class TestRunner(unittest.TestCase):

    def test_runner_namespaces_execution(self):
        policy = SandboxPolicy()
        policy.network.mode = "none"
        runner = SandboxRunner(policy=policy, backend_name="namespaces")
        res = runner.execute(["echo", "runner_test"])
        
        self.assertEqual(res.returncode, 0)
        self.assertIn("runner_test", res.stdout)
        self.assertEqual(res.backend_name, "namespaces")

    def test_runner_read_only_root_enforcement(self):
        policy = SandboxPolicy()
        runner = SandboxRunner(policy=policy, backend_name="namespaces")
        res = runner.execute(["touch", "/etc/runner_blocked"])
        
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Read-only file system", res.stderr)

if __name__ == "__main__":
    unittest.main()
