"""Hardware Virtualization KVM/QEMU Backend."""

import os
import shlex
import shutil
import subprocess
import time
from typing import Optional

from ..policy import SandboxPolicy
from .base import BaseBackend, ExecutionResult


class KvmBackend(BaseBackend):
    """Executes untrusted processes inside a dedicated KVM/QEMU virtual machine."""

    def __init__(
        self,
        vm_name: str = "debian-minimal",
        vm_ip: str = "192.168.122.71",
        user: str = "agentuser",
        ssh_key: str = "~/.ssh/id_ed25519",
    ):
        self.vm_name = vm_name
        self.vm_ip = vm_ip
        self.user = user
        self.ssh_key = os.path.expanduser(ssh_key)

    @property
    def name(self) -> str:
        return "kvm"

    def is_available(self) -> bool:
        return shutil.which("virsh") is not None and shutil.which("ssh") is not None

    def _format_ssh_command(
        self, command: list[str], policy: SandboxPolicy, env: Optional[dict[str, str]] = None
    ) -> str:
        env_prefix = ""
        if env:
            env_vars = [f"{k}={shlex.quote(v)}" for k, v in env.items()]
            env_prefix = " ".join(env_vars) + " "

        escaped_cmd = " ".join(shlex.quote(arg) for arg in command)
        return f"{env_prefix}{escaped_cmd}"

    def setup(self, policy: SandboxPolicy) -> None:
        pass

    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        env: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> ExecutionResult:
        if not self.is_available():
            return ExecutionResult(
                returncode=-1,
                stdout="",
                stderr="virsh/ssh not available on host",
                duration_ms=0.0,
                backend_name=self.name,
                violation_detected=True,
                violation_reason="missing_dependency",
            )

        formatted_cmd = self._format_ssh_command(command, policy, env)
        ssh_args = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            "-i",
            self.ssh_key,
            f"{self.user}@{self.vm_ip}",
            formatted_cmd,
        ]

        start_time = time.time()
        try:
            proc = subprocess.run(ssh_args, capture_output=True, text=True, timeout=timeout)
            duration_ms = (time.time() - start_time) * 1000.0
            return ExecutionResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=round(duration_ms, 2),
                backend_name=self.name,
                violation_detected=(proc.returncode != 0 and "Permission denied" in proc.stderr),
            )
        except subprocess.TimeoutExpired as e:
            duration_ms = (time.time() - start_time) * 1000.0
            out_str = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            err_str = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "KVM SSH command timed out")
            return ExecutionResult(
                returncode=124,
                stdout=out_str,
                stderr=err_str,
                duration_ms=round(duration_ms, 2),
                backend_name=self.name,
                violation_detected=True,
                violation_reason="timeout",
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000.0
            return ExecutionResult(
                returncode=-1,
                stdout="",
                stderr=str(e),
                duration_ms=round(duration_ms, 2),
                backend_name=self.name,
                violation_detected=True,
                violation_reason="execution_error",
            )

    def teardown(self) -> None:
        pass
