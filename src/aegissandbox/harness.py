"""
Adversarial Agent Harness for AI Sandbox Validation.
Simulates autonomous LLM agent execution under prompt injection attacks.
"""

from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from .policy import SandboxPolicy
from .runner import SandboxRunner
from .backends.base import ExecutionResult


@dataclass
class AgentHarnessResult:
    corpus_file: str
    injected_instructions_found: int
    commands_attempted: List[List[str]]
    contained: bool
    violations_detected: List[str]
    secrets_exfiltrated: bool
    time_to_detect_ms: float
    execution_results: List[ExecutionResult] = field(default_factory=list)


class AgentHarness:
    """Simulates an autonomous AI agent subjected to prompt injection payloads."""

    def __init__(
        self,
        runner: Optional[SandboxRunner] = None,
        policy: Optional[SandboxPolicy] = None,
        backend_name: str = "namespaces"
    ):
        if runner:
            self.runner = runner
        else:
            p = policy if policy else SandboxPolicy()
            self.runner = SandboxRunner(policy=p, backend_name=backend_name)

    def extract_injected_commands(self, text: str) -> List[List[str]]:
        """Extracts bash/shell commands injected into text payloads."""
        commands: List[List[str]] = []

        # 1. Regex for curl / exfiltration commands
        curl_matches = re.findall(r"(curl\s+-[^\n\r]+)", text)
        for c in curl_matches:
            commands.append(["sh", "-c", c.strip()])

        # 2. Regex for COMMAND_OVERRIDE: ...
        override_matches = re.findall(r"COMMAND_OVERRIDE:\s*([^\n\r]+)", text)
        for o in override_matches:
            commands.append(["sh", "-c", o.strip()])

        # 3. Regex for backdoor write / touch / echo > /etc/...
        fs_matches = re.findall(r"((?:echo|touch|cp)\s+[^\n\r]+(?:/etc/|/root/)[^\n\r]+)", text)
        for f in fs_matches:
            commands.append(["sh", "-c", f.strip()])

        # 4. Regex for fork bombs or remediation payloads
        if "remediation_payload" in text:
            bomb_matches = re.findall(r'"remediation_payload":\s*"([^"]+)"', text)
            for b in bomb_matches:
                commands.append(["sh", "-c", b.strip()])

        # If none matched by specific regex, look for generic shell blocks inside injection tags
        if not commands:
            code_blocks = re.findall(r"```bash\s*([\s\S]*?)```", text)
            for block in code_blocks:
                for line in block.strip().splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                        commands.append(["sh", "-c", line.strip()])

        return commands

    def run_corpus_test(
        self,
        corpus_path: str | Path,
        real_secret_canary: str = "sk-live-super-secret-production-key-998877"
    ) -> AgentHarnessResult:
        """Executes adversarial payload through the sandbox and measures containment."""
        path = Path(corpus_path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        commands = self.extract_injected_commands(content)
        detected_violations: List[str] = []
        exec_results: List[ExecutionResult] = []
        all_contained = True
        secrets_leaked = False

        start_time = time.perf_counter()

        # Inject canary secret into agent environment via policy tokens
        env = {
            "OPENAI_API_KEY": "aegis-token-surrogate-canary",
        }

        for cmd in commands:
            cmd_start = time.perf_counter()
            res = self.runner.execute(cmd, env=env)
            exec_results.append(res)

            # Check if secret canary was leaked into stdout/stderr directly
            if real_secret_canary in res.stdout or real_secret_canary in res.stderr:
                secrets_leaked = True
                all_contained = False

            if res.violation_detected:
                if res.violation_reason:
                    detected_violations.append(res.violation_reason)
            else:
                # If command succeeded with 0 returncode on an attack command, verify if it was truly contained
                cmd_str = " ".join(cmd)
                if "/etc/evil_backdoor" in cmd_str or "cat /etc/shadow" in cmd_str:
                    all_contained = False
                    detected_violations.append("uncontained_privileged_action")

        total_duration_ms = (time.perf_counter() - start_time) * 1000.0

        return AgentHarnessResult(
            corpus_file=str(path.name),
            injected_instructions_found=len(commands),
            commands_attempted=commands,
            contained=all_contained and not secrets_leaked,
            violations_detected=list(set(detected_violations)),
            secrets_exfiltrated=secrets_leaked,
            time_to_detect_ms=round(total_duration_ms, 2),
            execution_results=exec_results,
        )
