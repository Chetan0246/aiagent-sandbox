import unittest
from aegissandbox.network.secrets_broker import SecretsBroker

class TestSecretsBroker(unittest.TestCase):

    def setUp(self):
        self.broker = SecretsBroker()
        self.real_key = "sk-live-1234567890-super-secret"
        self.surrogate = self.broker.register_secret("OPENAI_API_KEY", self.real_key, allowed_domains=["api.openai.com"])

    def test_surrogate_generation(self):
        self.assertTrue(self.surrogate.startswith("aegis-surrogate-"))
        self.assertNotEqual(self.surrogate, self.real_key)

    def test_environment_injection_mapping(self):
        env_map = self.broker.get_agent_environment()
        self.assertEqual(env_map["OPENAI_API_KEY"], self.surrogate)
        self.assertNotIn(self.real_key, env_map.values())

    def test_token_swap_success(self):
        swapped = self.broker.swap_authorization_header(
            f"Bearer {self.surrogate}",
            target_domain="api.openai.com"
        )
        self.assertEqual(swapped, f"Bearer {self.real_key}")

    def test_token_swap_domain_mismatch_denied(self):
        # Surrogate token cannot be used against evil.attacker.com
        swapped = self.broker.swap_authorization_header(
            f"Bearer {self.surrogate}",
            target_domain="evil.attacker.com"
        )
        # Should NOT swap to real key
        self.assertNotEqual(swapped, f"Bearer {self.real_key}")
        self.assertEqual(swapped, f"Bearer {self.surrogate}")

if __name__ == "__main__":
    unittest.main()
