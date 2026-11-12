import unittest
import tempfile
from pathlib import Path
from aegissandbox.scanner import GTFOBinsScanner

SUDOERS_CONFIG_PATH = Path(__file__).resolve().parent.parent / "configs" / "sudoers" / "agentuser.sudoers"


class TestGTFOBinsScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = GTFOBinsScanner()

    def test_detect_gtfobins_binary(self):
        finding = self.scanner.check_binary("/usr/bin/systemd-run")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.binary, "systemd-run")
        self.assertEqual(finding.risk, "CRITICAL")
        self.assertIn("sudo", finding.functions)

        # Benign binary
        benign = self.scanner.check_binary("/usr/bin/uptime")
        self.assertIsNone(benign)

    def test_scan_actual_sudoers_file(self):
        if not SUDOERS_CONFIG_PATH.exists():
            self.skipTest("sudoers file not present")

        report = self.scanner.scan_sudoers_file(SUDOERS_CONFIG_PATH)
        self.assertTrue(report.total_scanned > 0)
        # In agentuser.sudoers, dangerous binaries like systemd-run, nsenter, chroot, unshare are explicitly negated
        for finding in report.findings:
            if finding.binary in ["systemd-run", "nsenter", "unshare", "chroot", "bash", "sh", "su", "tee"]:
                self.assertTrue(finding.mitigated, f"{finding.binary} should be mitigated by negation")

    def test_vulnerable_sudoers_detected(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write("agentuser ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/vim, /usr/bin/cat\n")
            f_path = f.name

        try:
            report = self.scanner.scan_sudoers_file(f_path)
            self.assertFalse(report.passed)
            self.assertTrue(report.high_findings >= 2)
            binaries_flagged = [f.binary for f in report.findings]
            self.assertIn("find", binaries_flagged)
            self.assertIn("vim", binaries_flagged)
        finally:
            Path(f_path).unlink(missing_ok=True)

    def test_scan_path_binaries(self):
        allowlist = ["/usr/bin/cat", "/usr/bin/grep", "/usr/bin/python3", "/usr/bin/curl"]
        report = self.scanner.scan_path_binaries(allowlist)
        self.assertEqual(report.total_scanned, 4)
        self.assertEqual(report.high_findings, 1)  # python3
        self.assertEqual(report.medium_findings, 1)  # curl


if __name__ == "__main__":
    unittest.main()
