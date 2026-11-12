import unittest
import json
import tempfile
from pathlib import Path
from aegissandbox.audit import AuditLogger

class TestAuditLogger(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "audit.jsonl"
        self.logger = AuditLogger(str(self.log_path))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_log_command_event(self):
        self.logger.log_command("echo test", returncode=0, duration_ms=12.5, backend="namespaces")
        self.assertTrue(self.log_path.exists())
        
        with open(self.log_path, "r") as f:
            lines = [json.loads(line) for line in f]
            
        self.assertEqual(len(lines), 1)
        event = lines[0]
        self.assertEqual(event["event_type"], "COMMAND_FINISH")
        self.assertEqual(event["backend"], "namespaces")
        self.assertEqual(event["returncode"], 0)
        self.assertEqual(event["duration_ms"], 12.5)

    def test_log_egress_blocked(self):
        self.logger.log_egress(host="evil.attacker.com", port=443, verdict="BLOCKED", method="CONNECT")
        with open(self.log_path, "r") as f:
            event = json.loads(f.readline())
            
        self.assertEqual(event["event_type"], "EGRESS_BLOCKED")
        self.assertEqual(event["host"], "evil.attacker.com")
        self.assertEqual(event["verdict"], "BLOCKED")

if __name__ == "__main__":
    unittest.main()
