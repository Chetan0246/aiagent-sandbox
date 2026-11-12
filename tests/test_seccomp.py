import json
import tempfile
import unittest
from pathlib import Path

from aegissandbox.seccomp import (
    get_blocked_syscalls,
    get_podman_capability_args,
    get_podman_seccomp_args,
    is_syscall_blocked,
    load_seccomp_profile,
)


class TestSeccomp(unittest.TestCase):
    def test_load_strict_profile(self):
        profile = load_seccomp_profile()
        self.assertEqual(profile.get("defaultAction"), "SCMP_ACT_ALLOW")
        self.assertIn("syscalls", profile)
        self.assertTrue(len(profile["syscalls"]) > 0)

    def test_blocked_syscalls_contain_critical_vectors(self):
        profile = load_seccomp_profile()
        blocked = get_blocked_syscalls(profile)

        critical_calls = [
            "ptrace",
            "bpf",
            "reboot",
            "kexec_load",
            "mount",
            "umount2",
            "pivot_root",
            "init_module",
            "keyctl",
        ]
        for call in critical_calls:
            self.assertIn(call, blocked, f"Syscall {call} must be blocked in strict profile")
            self.assertTrue(is_syscall_blocked(profile, call))

    def test_benign_syscalls_not_blocked(self):
        profile = load_seccomp_profile()
        self.assertFalse(is_syscall_blocked(profile, "read"))
        self.assertFalse(is_syscall_blocked(profile, "write"))
        self.assertFalse(is_syscall_blocked(profile, "exit_group"))

    def test_podman_seccomp_args(self):
        args = get_podman_seccomp_args("configs/seccomp/strict.json")
        self.assertEqual(args[0], "--security-opt")
        self.assertTrue(args[1].startswith("seccomp="))

    def test_podman_seccomp_args_nonexistent(self):
        args = get_podman_seccomp_args("nonexistent_path_file.json")
        self.assertEqual(args, [])

    def test_podman_capability_args(self):
        drop_all_args = get_podman_capability_args(drop_all=True)
        self.assertEqual(drop_all_args, ["--cap-drop=ALL"])

        drop_selective = get_podman_capability_args(
            drop_all=False, add_caps=["CAP_NET_BIND_SERVICE"]
        )
        self.assertIn("--cap-drop=sys_admin", drop_selective)
        self.assertIn("--cap-add=net_bind_service", drop_selective)

    def test_seccomp_invalid_path(self):
        with self.assertRaises(FileNotFoundError):
            load_seccomp_profile("nonexistent_profile_9999.json")

    def test_seccomp_invalid_json_type(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
            f.write(json.dumps(["not", "a", "dict"]))
            f_path = f.name
        try:
            with self.assertRaises(ValueError):
                load_seccomp_profile(f_path)
        finally:
            Path(f_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
