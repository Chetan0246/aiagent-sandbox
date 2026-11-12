import unittest

from aegissandbox.backends.base import BaseBackend, ExecutionResult
from aegissandbox.policy import SandboxPolicy


class DummyBackend(BaseBackend):
    @property
    def name(self) -> str:
        return "dummy"

    def is_available(self) -> bool:
        return True

    def setup(self, policy: SandboxPolicy) -> None:
        pass

    def run(self, command, policy, env=None, timeout=None) -> ExecutionResult:
        return ExecutionResult(
            returncode=0, stdout="dummy output", stderr="", duration_ms=10.5, backend_name="dummy"
        )

    def teardown(self) -> None:
        pass


class TestBackendsBase(unittest.TestCase):
    def test_execution_result_contract(self):
        res = ExecutionResult(
            returncode=0, stdout="hello", stderr="", duration_ms=42.0, backend_name="test"
        )
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, "hello")
        self.assertFalse(res.violation_detected)

    def test_dummy_backend_contract(self):
        backend = DummyBackend()
        policy = SandboxPolicy()
        res = backend.run(["echo", "hi"], policy)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.backend_name, "dummy")


if __name__ == "__main__":
    unittest.main()
