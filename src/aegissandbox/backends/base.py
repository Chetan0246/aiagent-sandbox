"""Abstract base class and execution data contracts for sandbox backends."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..policy import SandboxPolicy


@dataclass
class ExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    backend_name: str
    peak_memory_bytes: int = 0
    violation_detected: bool = False
    violation_reason: str = ""
    extra_metadata: dict[str, Any] = field(default_factory=dict)


class BaseBackend(ABC):
    """Abstract interface that all sandbox backends must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the backend."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the backend runtime/dependencies are available."""
        pass

    @abstractmethod
    def setup(self, policy: SandboxPolicy) -> None:
        """Prepares any required isolation artifacts or directories."""
        pass

    @abstractmethod
    def run(
        self,
        command: list[str],
        policy: SandboxPolicy,
        env: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> ExecutionResult:
        """Executes an untrusted command inside the configured sandbox."""
        pass

    @abstractmethod
    def teardown(self) -> None:
        """Cleans up ephemeral mounts, cgroups, or temporary namespaces."""
        pass
