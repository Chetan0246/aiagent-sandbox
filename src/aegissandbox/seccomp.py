"""
Seccomp BPF filtering and Linux capability dropping engine for Aegis Sandbox.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SECCOMP_PATH = Path(__file__).resolve().parent.parent.parent / "configs" / "seccomp" / "strict.json"

# Dangerous Linux capabilities dropped in strict enforcement
DEFAULT_DROPPED_CAPABILITIES: List[str] = [
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_SETUID",
    "CAP_SETGID",
]


def load_seccomp_profile(path: Optional[str | Path] = None) -> Dict[str, Any]:
    """Loads an OCI-compliant seccomp JSON profile."""
    target_path = Path(path) if path else DEFAULT_SECCOMP_PATH
    if not target_path.exists():
        # Fallback to local relative lookup if running from different root
        fallback = Path("configs/seccomp/strict.json")
        if fallback.exists():
            target_path = fallback
        else:
            raise FileNotFoundError(f"Seccomp profile not found at {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def get_blocked_syscalls(profile: Dict[str, Any]) -> List[str]:
    """Extracts all syscall names that are blocked (ERRNO or KILL) in the profile."""
    blocked: List[str] = []
    for entry in profile.get("syscalls", []):
        action = entry.get("action", "")
        if action in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL"):
            for name in entry.get("names", []):
                blocked.append(name)
    return sorted(list(set(blocked)))


def is_syscall_blocked(profile: Dict[str, Any], syscall_name: str) -> bool:
    """Checks whether a specific syscall is blocked under the given seccomp profile."""
    blocked = get_blocked_syscalls(profile)
    return syscall_name in blocked


def get_podman_seccomp_args(profile_path: Optional[str | Path] = None) -> List[str]:
    """Generates Podman/Docker command line arguments to apply the seccomp profile."""
    target_path = Path(profile_path) if profile_path else DEFAULT_SECCOMP_PATH
    abs_path = os.path.abspath(str(target_path))
    return ["--security-opt", f"seccomp={abs_path}"]


def get_podman_capability_args(drop_all: bool = True, add_caps: Optional[List[str]] = None) -> List[str]:
    """Generates capability drop/add arguments for container runtimes."""
    args: List[str] = []
    if drop_all:
        args.append("--cap-drop=ALL")
    else:
        for cap in DEFAULT_DROPPED_CAPABILITIES:
            cap_short = cap.replace("CAP_", "").lower()
            args.append(f"--cap-drop={cap_short}")

    if add_caps:
        for cap in add_caps:
            cap_short = cap.replace("CAP_", "").lower()
            args.append(f"--cap-add={cap_short}")

    return args
