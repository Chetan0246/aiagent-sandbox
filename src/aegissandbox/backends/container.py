"""Rootless Podman/OCI Container Sandbox Backend."""

import shutil
import subprocess
import time
from typing import Optional

from ..policy import SandboxPolicy
from ..seccomp import get_podman_seccomp_args
from .base import BaseBackend, ExecutionResult


class ContainerBackend(BaseBackend):
    """Executes untrusted processes inside rootless Podman/OCI containers."""

    def __init__(self, image: str = "alpine:latest"):
        self.image = image

    @property
    def name(self) -> str:
        return "container"

    def is_available(self) -> bool:
        return shutil.which("podman") is not None

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
                stderr="podman executable not found on host",
                duration_ms=0.0,
                backend_name=self.name,
                violation_detected=True,
                violation_reason="missing_dependency",
            )

        cmd = ["podman", "run", "--rm"]

        # 1. Cgroup resource limits
        if policy.resources.memory_max and policy.resources.memory_max != "max":
            cmd.extend(["--memory", policy.resources.memory_max])
        if policy.resources.tasks_max:
            cmd.extend(["--pids-limit", str(policy.resources.tasks_max)])

        # 2. Security isolation
        if policy.security.read_only_root:
            cmd.append("--read-only")

        for cap in policy.security.drop_capabilities:
            cmd.extend(["--cap-drop", cap])

        if policy.security.seccomp_profile:
            cmd.extend(get_podman_seccomp_args())

        for eph in policy.security.ephemeral_dirs:
            cmd.extend(["--tmpfs", eph])

        # 3. Network configuration
        if policy.network.mode == "none":
            cmd.append("--network=none")
        elif policy.network.mode == "host":
            cmd.append("--network=host")

        # 4. Environment
        if env:
            for k, v in env.items():
                cmd.extend(["-e", f"{k}={v}"])

        cmd.append(self.image)
        cmd.extend(command)

        start_time = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            duration_ms = (time.time() - start_time) * 1000.0
            return ExecutionResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=round(duration_ms, 2),
                backend_name=self.name,
                violation_detected=(
                    proc.returncode != 0 and "Operation not permitted" in proc.stderr
                ),
            )
        except subprocess.TimeoutExpired as e:
            duration_ms = (time.time() - start_time) * 1000.0
            out_str = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            err_str = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "Container command timed out")
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
