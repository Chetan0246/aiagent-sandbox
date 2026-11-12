import unittest
from unittest.mock import patch

from aegissandbox.stress import (
    _worker_cpu,
    run_concurrency_stress,
    run_fork_probe,
    run_memory_probe,
)


class TestStressProbes(unittest.TestCase):
    def test_worker_cpu(self):
        res = _worker_cpu(0.02)
        self.assertTrue(res)

    def test_run_memory_probe_success(self):
        res = run_memory_probe(target_mb=5, hold_seconds=0.01)
        self.assertTrue(res["success"])
        self.assertEqual(res["target_mb"], 5)
        self.assertEqual(res["error"], "")
        self.assertGreater(res["duration_seconds"], 0)

    def test_run_concurrency_stress(self):
        res = run_concurrency_stress(workers=2, duration=0.05)
        self.assertTrue(res["completed"])
        self.assertEqual(res["workers"], 2)

    def test_run_fork_probe_success(self):
        res = run_fork_probe(max_procs=2)
        self.assertEqual(res["attempted"], 2)
        self.assertFalse(res["hit_ceiling"])

    def test_run_fork_probe_blocking_io_error(self):
        with patch("os.fork", side_effect=BlockingIOError("Resource temporarily unavailable")):
            res = run_fork_probe(max_procs=5)
            self.assertTrue(res["hit_ceiling"])
            self.assertIn("BlockingIOError", res["error"])

    def test_run_fork_probe_os_error(self):
        with patch("os.fork", side_effect=OSError(1, "Operation not permitted")):
            res = run_fork_probe(max_procs=5)
            self.assertTrue(res["hit_ceiling"])
            self.assertIn("OSError", res["error"])

    def test_run_memory_probe_memory_error(self):
        with patch("builtins.bytearray", side_effect=MemoryError("Out of memory")):
            res = run_memory_probe(target_mb=1000)
            self.assertFalse(res["success"])
            self.assertIn("MemoryError", res["error"])

    def test_run_memory_probe_generic_error(self):
        with patch("builtins.bytearray", side_effect=RuntimeError("Generic error")):
            res = run_memory_probe(target_mb=1000)
            self.assertFalse(res["success"])
            self.assertIn("Generic error", res["error"])


if __name__ == "__main__":
    unittest.main()
