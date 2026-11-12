"""Structured JSONL Audit Logger for Autonomous AI Sandboxes."""

import json
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

class AuditLogger:
    """Thread-safe structured audit event logger emitting standard JSON lines."""

    def __init__(self, log_path: str = "audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _emit(self, event_type: str, data: Dict[str, Any]):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **data
        }
        line = json.dumps(record) + "\n"
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)

    def log_command(
        self,
        command: str,
        returncode: int,
        duration_ms: float,
        backend: str,
        violation: bool = False,
        extra: Optional[Dict[str, Any]] = None
    ):
        data = {
            "command": command,
            "returncode": returncode,
            "duration_ms": duration_ms,
            "backend": backend,
            "violation": violation,
            **(extra or {})
        }
        self._emit("COMMAND_FINISH", data)

    def log_egress(self, host: str, port: int, verdict: str, method: str):
        event_type = "EGRESS_BLOCKED" if verdict == "BLOCKED" else "EGRESS_ALLOWED"
        self._emit(event_type, {
            "host": host,
            "port": port,
            "verdict": verdict,
            "method": method
        })

    def log_resource_breach(self, resource_type: str, threshold: str, details: str):
        self._emit("RESOURCE_LIMIT_BREACH", {
            "resource": resource_type,
            "threshold": threshold,
            "details": details
        })
