import unittest
from pathlib import Path
from aegissandbox.seccomp import (
    load_seccomp_profile,
    get_blocked_syscalls,
    is_syscall_blocked,
    get_podman_seccomp_args,
    get_podman_capability_args,
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

    def test_podman_capability_args(self):
        drop_all_args = get_podman_capability_args(drop_all=True)
        self.assertEqual(drop_all_args, ["--cap-drop=ALL"])

        drop_selective = get_podman_capability_args(drop_all=False, add_caps=["CAP_NET_BIND_SERVICE"])
        self.assertIn("--cap-drop=sys_admin", drop_selective)
        self.assertIn("--cap-add=net_bind_service", drop_selective)


if __name__ == "__main__":
    unittest.main()
