import unittest

from aegissandbox.policy import SandboxPolicy
from aegissandbox.runner import SandboxRunner


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

    def test_runner_unknown_backend_raises_error(self):
        policy = SandboxPolicy()
        with self.assertRaises(ValueError) as ctx:
            SandboxRunner(policy=policy, backend_name="invalid_backend")
        self.assertIn("Unknown sandbox backend: invalid_backend", str(ctx.exception))

    def test_runner_namespaces_explicit(self):
        policy = SandboxPolicy()
        runner = SandboxRunner(policy=policy, backend_name="namespaces")
        res = runner.execute(["echo", "override_test"])
        self.assertEqual(res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
