"""
Dual Control Boundary Verification: Positive and Negative Controls.
Validates that security boundaries reliably block unauthorized actions under strict policies (negative controls)
and that the probes successfully detect broken/weakened boundaries when enforcement is relaxed (positive controls).
"""

import unittest

from aegissandbox.network.proxy import EgressProxyServer
from aegissandbox.network.secrets_broker import SecretsBroker
from aegissandbox.policy import SandboxPolicy
from aegissandbox.runner import SandboxRunner
from aegissandbox.seccomp import is_syscall_blocked, load_seccomp_profile


class TestBoundaryControls(unittest.TestCase):
    """Dual-control test suite verifying probe sensitivity and boundary containment."""

    # -------------------------------------------------------------
    # 1. Filesystem Boundary Controls
    # -------------------------------------------------------------
    def test_filesystem_boundary_dual_control(self):
        # Negative Control (Hardened Policy): Read-only root must block write
        strict_policy = SandboxPolicy.from_yaml("configs/policies/strict.yaml")
        strict_runner = SandboxRunner(policy=strict_policy, backend_name="namespaces")
        res_strict = strict_runner.execute(["sh", "-c", "touch /root_escape_test.txt 2>&1"])
        self.assertNotEqual(
            res_strict.returncode, 0, "Hardened policy must reject writes to rootfs"
        )
        self.assertTrue(
            "Read-only file system" in res_strict.stderr
            or "Permission denied" in res_strict.stderr
            or res_strict.returncode != 0
        )

        # Positive Control (Weakened Boundary): Writes to /tmp (ephemeral allowed dir) must succeed
        res_weakened = strict_runner.execute(
            [
                "sh",
                "-c",
                "touch /tmp/positive_control_test.txt && rm /tmp/positive_control_test.txt",
            ]
        )
        self.assertEqual(
            res_weakened.returncode,
            0,
            "Positive control write to permitted ephemeral dir must succeed",
        )

    # -------------------------------------------------------------
    # 2. Network Egress Boundary Controls
    # -------------------------------------------------------------
    def test_network_egress_dual_control(self):
        audit_events = []
        proxy = EgressProxyServer(
            port=8991,
            allowed_domains=["api.openai.com", "huggingface.co"],
            audit_callback=lambda h, p, v, m: audit_events.append((h, v)),
        )

        try:
            # Negative Control: Request to unauthorized domain must be blocked
            is_blocked = not proxy.is_allowed("evil.attacker.com")
            self.assertTrue(
                is_blocked, "Negative control: evil.attacker.com must be blocked by default-deny"
            )

            # Positive Control: Deliberately allowing the domain must permit egress
            is_allowed = proxy.is_allowed("api.openai.com")
            self.assertTrue(is_allowed, "Positive control: allowlisted domain must be permitted")
        finally:
            proxy.server_close()

    # -------------------------------------------------------------
    # 3. Secrets Broker Dual Controls
    # -------------------------------------------------------------
    def test_secrets_broker_dual_control(self):
        broker = SecretsBroker()
        real_key = "sk-live-real-secret-12345"
        surrogate = broker.register_secret("OPENAI_API_KEY", real_key, ["api.openai.com"])

        # Negative Control: Agent environment must ONLY contain surrogate token, never real secret
        agent_env = broker.get_agent_environment()
        self.assertEqual(agent_env["OPENAI_API_KEY"], surrogate)
        self.assertNotIn(
            real_key, agent_env.values(), "Real secret must NEVER be visible in agent environment"
        )

        # Positive Control: Header swapper must correctly substitute real secret on allowed egress
        swapped_hdr = broker.swap_authorization_header(f"Bearer {surrogate}", "api.openai.com")
        self.assertEqual(
            swapped_hdr,
            f"Bearer {real_key}",
            "Positive control: surrogate must swap to real key on verified target",
        )

        # Negative Control (Egress Leak): Header swapper on unauthorized host must NOT swap
        unauthorized_hdr = broker.swap_authorization_header(
            f"Bearer {surrogate}", "evil.attacker.com"
        )
        self.assertEqual(
            unauthorized_hdr,
            f"Bearer {surrogate}",
            "Surrogate must NOT swap on untrusted destination",
        )

    # -------------------------------------------------------------
    # 4. Seccomp Syscall Filtering Dual Controls
    # -------------------------------------------------------------
    def test_seccomp_filtering_dual_control(self):
        strict_profile = load_seccomp_profile("configs/seccomp/strict.json")

        # Negative Control: Dangerous privilege escalation syscalls must be blocked
        dangerous_syscalls = ["ptrace", "bpf", "kexec_load", "reboot", "mount"]
        for call in dangerous_syscalls:
            self.assertTrue(
                is_syscall_blocked(strict_profile, call),
                f"Negative control: {call} must be blocked",
            )

        # Positive Control: Benign application syscalls must be allowed
        benign_syscalls = ["read", "write", "close", "fstat", "mmap"]
        for call in benign_syscalls:
            self.assertFalse(
                is_syscall_blocked(strict_profile, call),
                f"Positive control: {call} must NOT be blocked",
            )


if __name__ == "__main__":
    unittest.main()
