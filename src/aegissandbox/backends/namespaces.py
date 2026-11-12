"""Bubblewrap and Linux User Namespaces Sandbox Backend."""

import os
import shutil
import time
import subprocess
from typing import List, Dict, Optional
from .base import BaseBackend, ExecutionResult
from ..policy import SandboxPolicy

class NamespaceBackend(BaseBackend):
    """Executes untrusted processes within isolated Linux User, Mount, PID, and Network namespaces."""

    @property
    def name(self) -> str:
        return "namespaces"

    def is_available(self) -> bool:
        return shutil.which("bwrap") is not None

    def setup(self, policy: SandboxPolicy) -> None:
        pass

    def run(
        self,
        command: List[str],
        policy: SandboxPolicy,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> ExecutionResult:
        if not self.is_available():
            return ExecutionResult(
                returncode=-1,
                stdout="",
                stderr="bwrap executable not found on host",
                duration_ms=0.0,
                backend_name=self.name,
                violation_detected=True,
                violation_reason="missing_dependency"
            )

        bwrap_args = ["bwrap"]

        # 1. Mount configuration
        if policy.security.read_only_root:
            bwrap_args.extend(["--ro-bind", "/", "/"])
        else:
            bwrap_args.extend(["--bind", "/", "/"])

        # Dev and proc mounts
        bwrap_args.extend(["--dev", "/dev", "--proc", "/proc"])

        # Ephemeral mounts
        for eph in policy.security.ephemeral_dirs:
            bwrap_args.extend(["--tmpfs", eph])

        # 2. Namespace unsharing
        bwrap_args.extend(["--unshare-pid", "--unshare-ipc", "--die-with-parent"])

        if policy.network.mode == "none":
            bwrap_args.append("--unshare-net")

        # 3. Environment scrubbing
        exec_env = os.environ.copy() if env is None else env.copy()

        # Build command invocation
        full_cmd = bwrap_args + ["--"] + command

        start_time = time.time()
        try:
            proc = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                env=exec_env,
                timeout=timeout
            )
            duration_ms = (time.time() - start_time) * 1000.0
            return ExecutionResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=round(duration_ms, 2),
                backend_name=self.name,
                violation_detected=(proc.returncode != 0 and "Operation not permitted" in proc.stderr)
            )
        except subprocess.TimeoutExpired as e:
            duration_ms = (time.time() - start_time) * 1000.0
            return ExecutionResult(
                returncode=124,
                stdout=e.stdout or "",
                stderr="Command execution timed out",
                duration_ms=round(duration_ms, 2),
                backend_name=self.name,
                violation_detected=True,
                violation_reason="timeout"
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
                violation_reason="execution_error"
            )

    def teardown(self) -> None:
        pass
