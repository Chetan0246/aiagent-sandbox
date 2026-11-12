"""Unit tests for Aegis-Sandbox modules."""

import unittest
from aegissandbox.probes import audit_sensitive_files, check_imds_reachability, check_mount_isolation
from aegissandbox.stress import run_memory_probe, run_concurrency_stress

class TestAegisProbes(unittest.TestCase):

    def test_audit_sensitive_files(self):
        findings = audit_sensitive_files()
        self.assertIsInstance(findings, list)
        self.assertTrue(len(findings) >= 3)
        targets = [f["target"] for f in findings]
        self.assertIn("/etc/shadow", targets)
        self.assertIn("/root", targets)

    def test_imds_probe_format(self):
        imds = check_imds_reachability()
        self.assertIn("reachable", imds)
        self.assertIn("status", imds)

    def test_mount_isolation_format(self):
        mounts = check_mount_isolation()
        self.assertIn("tmp_isolated", mounts)
        self.assertIn("var_tmp_isolated", mounts)

class TestAegisStress(unittest.TestCase):

    def test_safe_memory_probe(self):
        res = run_memory_probe(target_mb=10, hold_seconds=0.1)
        self.assertTrue(res["success"])
        self.assertEqual(res["target_mb"], 10)

    def test_safe_concurrency_stress(self):
        res = run_concurrency_stress(workers=2, duration=0.2)
        self.assertTrue(res["completed"])

if __name__ == "__main__":
    unittest.main()
