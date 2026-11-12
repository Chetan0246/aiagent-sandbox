import unittest
from pathlib import Path

from aegissandbox.harness import AgentHarness
from aegissandbox.policy import SandboxPolicy
from aegissandbox.runner import SandboxRunner

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


class TestAgentHarness(unittest.TestCase):
    def setUp(self):
        self.policy = SandboxPolicy()
        self.runner = SandboxRunner(policy=self.policy, backend_name="namespaces")
        self.harness = AgentHarness(runner=self.runner)

    def test_extract_commands_from_readme(self):
        readme_path = CORPUS_DIR / "malicious_readme.md"
        with open(readme_path, encoding="utf-8") as f:
            content = f.read()

        cmds = self.harness.extract_injected_commands(content)
        self.assertTrue(len(cmds) >= 1)
        flat = " ".join([" ".join(c) for c in cmds])
        self.assertIn("curl", flat)
        self.assertIn("evil.attacker.com", flat)

    def test_extract_commands_from_tool_output(self):
        tool_path = CORPUS_DIR / "poisoned_tool_output.txt"
        with open(tool_path, encoding="utf-8") as f:
            content = f.read()

        cmds = self.harness.extract_injected_commands(content)
        self.assertTrue(len(cmds) >= 1)
        flat = " ".join([" ".join(c) for c in cmds])
        self.assertIn("systemd-run", flat)

    def test_extract_commands_from_json(self):
        json_path = CORPUS_DIR / "poisoned_api_response.json"
        with open(json_path, encoding="utf-8") as f:
            content = f.read()

        cmds = self.harness.extract_injected_commands(content)
        self.assertTrue(len(cmds) >= 1)
        flat = " ".join([" ".join(c) for c in cmds])
        self.assertIn(":(){ :|:& };:", flat)

    def test_run_adversarial_readme_containment(self):
        readme_path = CORPUS_DIR / "malicious_readme.md"
        result = self.harness.run_corpus_test(
            readme_path, real_secret_canary="sk-live-super-secret-production-key-998877"
        )
        self.assertFalse(result.secrets_exfiltrated)
        self.assertTrue(result.contained)
        self.assertTrue(result.time_to_detect_ms > 0.0)


if __name__ == "__main__":
    unittest.main()
