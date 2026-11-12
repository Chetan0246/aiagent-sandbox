import unittest
from pathlib import Path

from aegissandbox.policy import SandboxPolicy


class TestPolicy(unittest.TestCase):
    def test_load_strict_policy(self):
        policy_path = Path("configs/policies/strict.yaml")
        policy = SandboxPolicy.from_yaml(policy_path)

        self.assertEqual(policy.name, "strict-agent-sandbox")
        self.assertEqual(policy.resources.memory_max, "384M")
        self.assertEqual(policy.resources.memory_swap_max, "0")
        self.assertEqual(policy.resources.tasks_max, 100)
        self.assertTrue(policy.security.read_only_root)
        self.assertIn("CAP_SYS_ADMIN", policy.security.drop_capabilities)
        self.assertEqual(policy.network.mode, "allowlist-proxy")
        self.assertIn("api.openai.com", policy.network.allowed_domains)
        self.assertTrue(policy.secrets.broker_enabled)
        self.assertIn("OPENAI_API_KEY", policy.secrets.mapped_tokens)

    def test_load_permissive_policy(self):
        policy = SandboxPolicy.from_yaml("configs/policies/permissive.yaml")
        self.assertEqual(policy.name, "permissive-debug-sandbox")
        self.assertEqual(policy.resources.tasks_max, 1000)
        self.assertEqual(policy.network.mode, "host")
        self.assertFalse(policy.secrets.broker_enabled)

    def test_policy_serialization(self):
        policy = SandboxPolicy()
        d = policy.to_dict()
        self.assertIn("version", d)
        self.assertIn("resources", d)
        self.assertIn("security", d)

        yaml_str = policy.to_yaml()
        self.assertIn("default-sandbox", yaml_str)

    def test_policy_from_dict(self):
        raw = {
            "name": "custom-policy",
            "resources": {"memory_max": "512M", "tasks_max": 50},
            "security": {"read_only_root": False},
        }
        policy = SandboxPolicy.from_dict(raw)
        self.assertEqual(policy.name, "custom-policy")
        self.assertEqual(policy.resources.memory_max, "512M")
        self.assertFalse(policy.security.read_only_root)

    def test_policy_invalid_file(self):
        with self.assertRaises(FileNotFoundError):
            SandboxPolicy.from_yaml("nonexistent_path_12345.yaml")


if __name__ == "__main__":
    unittest.main()
