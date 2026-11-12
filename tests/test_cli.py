"""Unit and integration tests for Aegis CLI, probes, and stress routines."""

import io
import sys
import unittest
from unittest.mock import patch

from aegissandbox.cli import main, print_badge, print_header
from aegissandbox.probes import (
    audit_sensitive_files,
    check_cgroups,
    check_imds_reachability,
    check_mount_isolation,
    probe_network_gateway,
)
from aegissandbox.stress import (
    run_concurrency_stress,
    run_fork_probe,
    run_memory_probe,
)


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

    def test_check_cgroups(self):
        cg = check_cgroups()
        self.assertIn("cgroup_v2_active", cg)
        self.assertIn("limits", cg)

    def test_probe_network_gateway(self):
        results = probe_network_gateway(gateway_ip="127.0.0.1", ports=[65530])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "CLOSED")


class TestAegisStress(unittest.TestCase):
    def test_safe_memory_probe(self):
        res = run_memory_probe(target_mb=10, hold_seconds=0.1)
        self.assertTrue(res["success"])
        self.assertEqual(res["target_mb"], 10)

    def test_safe_concurrency_stress(self):
        res = run_concurrency_stress(workers=2, duration=0.2)
        self.assertTrue(res["completed"])

    def test_run_fork_probe(self):
        res = run_fork_probe(max_procs=3)
        self.assertIn("successfully_spawned", res)
        self.assertIn("hit_ceiling", res)


class TestAegisCli(unittest.TestCase):
    def test_print_helpers(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_header("Test Header")
            print_badge("Badge", "OK", True)
            print_badge("Badge Fail", "FAIL", False)
        output = buf.getvalue()
        self.assertIn("Aegis :: Test Header", output)
        self.assertIn("Badge", output)

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_audit(self, mock_stdout):
        with patch.object(sys, "argv", ["aegis", "audit"]):
            main()
        self.assertIn("Security Posture & Isolation Audit", mock_stdout.getvalue())

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_probe(self, mock_stdout):
        with patch.object(sys, "argv", ["aegis", "probe", "--gateway", "127.0.0.1"]):
            main()
        self.assertIn("Network & Boundary Probes", mock_stdout.getvalue())

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_stress(self, mock_stdout):
        with patch.object(sys, "argv", ["aegis", "stress", "--memory-mb", "5", "--fork-limit", "3"]):
            main()
        self.assertIn("Controlled Resource Stress Testing", mock_stdout.getvalue())

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_report_json(self, mock_stdout):
        with patch.object(sys, "argv", ["aegis", "report", "--json"]):
            main()
        self.assertIn('"cgroups":', mock_stdout.getvalue())

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_report_text(self, mock_stdout):
        with patch.object(sys, "argv", ["aegis", "report"]):
            main()
        self.assertIn("System Audit Summary", mock_stdout.getvalue())

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_scan(self, mock_stdout):
        with patch.object(sys, "argv", ["aegis", "scan", "--binaries", "echo,ls"]):
            main()
        self.assertIn("GTFOBins Binary Privilege Escalation Audit", mock_stdout.getvalue())

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_run(self, mock_stdout):
        with patch.object(sys, "argv", ["aegis", "run", "--backend", "namespaces", "--", "echo", "cli_run_pass"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)
        self.assertIn("cli_run_pass", mock_stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
