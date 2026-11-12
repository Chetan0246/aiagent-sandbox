"""
Automated GTFOBins Security Scanner for AI Agent Sandboxes.
Scans allowlisted binaries, sudoers configurations, and SUID binaries for privilege escalation vectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Curated registry of Unix binaries with known GTFOBins escape vectors
GTFOBINS_REGISTRY: dict[str, dict[str, Any]] = {
    "bash": {
        "functions": ["shell", "sudo", "suid"],
        "risk": "CRITICAL",
        "description": "Interactive shell execution",
    },
    "sh": {
        "functions": ["shell", "sudo", "suid"],
        "risk": "CRITICAL",
        "description": "Interactive shell execution",
    },
    "systemd-run": {
        "functions": ["sudo", "shell"],
        "risk": "CRITICAL",
        "description": "Direct transient service/slice escape",
    },
    "nsenter": {
        "functions": ["sudo", "shell"],
        "risk": "CRITICAL",
        "description": "Mount/PID namespace hopping",
    },
    "unshare": {
        "functions": ["sudo", "shell"],
        "risk": "CRITICAL",
        "description": "Unshared namespace manipulation",
    },
    "chroot": {
        "functions": ["sudo", "shell"],
        "risk": "CRITICAL",
        "description": "Chroot jail manipulation",
    },
    "python": {
        "functions": ["shell", "file_read", "file_write", "sudo"],
        "risk": "HIGH",
        "description": "Arbitrary Python code execution & pty spawn",
    },
    "python3": {
        "functions": ["shell", "file_read", "file_write", "sudo"],
        "risk": "HIGH",
        "description": "Arbitrary Python code execution & pty spawn",
    },
    "perl": {
        "functions": ["shell", "file_read", "file_write", "sudo"],
        "risk": "HIGH",
        "description": "Perl exec escape",
    },
    "ruby": {
        "functions": ["shell", "file_read", "file_write", "sudo"],
        "risk": "HIGH",
        "description": "Ruby exec escape",
    },
    "node": {
        "functions": ["shell", "file_read", "file_write", "sudo"],
        "risk": "HIGH",
        "description": "Node.js child_process escape",
    },
    "find": {
        "functions": ["shell", "sudo", "suid"],
        "risk": "HIGH",
        "description": "-exec parameter spawns arbitrary processes",
    },
    "xargs": {
        "functions": ["shell", "sudo"],
        "risk": "HIGH",
        "description": "Executes input as arbitrary commands",
    },
    "awk": {
        "functions": ["shell", "file_read", "sudo"],
        "risk": "HIGH",
        "description": "awk system() function execution",
    },
    "gawk": {
        "functions": ["shell", "file_read", "sudo"],
        "risk": "HIGH",
        "description": "gawk system() function execution",
    },
    "sed": {
        "functions": ["file_write", "sudo"],
        "risk": "MEDIUM",
        "description": "Arbitrary in-place file write",
    },
    "vim": {
        "functions": ["shell", "file_read", "file_write", "sudo"],
        "risk": "HIGH",
        "description": ":!shell escape and editor write",
    },
    "vi": {
        "functions": ["shell", "file_read", "file_write", "sudo"],
        "risk": "HIGH",
        "description": ":!shell escape",
    },
    "nano": {
        "functions": ["shell", "file_write", "sudo"],
        "risk": "HIGH",
        "description": "Spell checker command execution",
    },
    "less": {
        "functions": ["shell", "file_read", "sudo"],
        "risk": "HIGH",
        "description": "!/bin/sh pager escape",
    },
    "more": {
        "functions": ["shell", "file_read", "sudo"],
        "risk": "HIGH",
        "description": "!/bin/sh pager escape",
    },
    "tar": {
        "functions": ["shell", "sudo"],
        "risk": "HIGH",
        "description": "--checkpoint-action=exec escape",
    },
    "zip": {
        "functions": ["shell", "sudo"],
        "risk": "HIGH",
        "description": "-T -TT command execution",
    },
    "tee": {
        "functions": ["file_write", "sudo"],
        "risk": "HIGH",
        "description": "Arbitrary root file overwrite",
    },
    "dd": {
        "functions": ["file_write", "file_read", "sudo"],
        "risk": "HIGH",
        "description": "Raw disk and file overwrite",
    },
    "cp": {
        "functions": ["file_write", "sudo"],
        "risk": "HIGH",
        "description": "Root file overwrite/replacement",
    },
    "systemctl": {
        "functions": ["sudo"],
        "risk": "HIGH",
        "description": "Service manipulation and pager escape",
    },
    "journalctl": {
        "functions": ["sudo", "shell"],
        "risk": "MEDIUM",
        "description": "!/bin/sh pager escape",
    },
    "apt-get": {
        "functions": ["sudo"],
        "risk": "MEDIUM",
        "description": "Package hook command execution",
    },
    "apt": {
        "functions": ["sudo"],
        "risk": "MEDIUM",
        "description": "Package hook command execution",
    },
    "curl": {
        "functions": ["file_read", "file_write", "network"],
        "risk": "MEDIUM",
        "description": "Remote payload retrieval and file dump",
    },
    "wget": {
        "functions": ["file_write", "network"],
        "risk": "MEDIUM",
        "description": "Remote payload retrieval and file dump",
    },
    "env": {
        "functions": ["shell", "sudo"],
        "risk": "HIGH",
        "description": "Executes target under clean environment",
    },
}


@dataclass
class ScanFinding:
    binary: str
    risk: str
    functions: list[str]
    description: str
    source: str
    mitigated: bool
    mitigation_notes: str = ""


@dataclass
class ScanReport:
    total_scanned: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    passed: bool
    findings: list[ScanFinding] = field(default_factory=list)


class GTFOBinsScanner:
    """Audits configurations and binary paths against GTFOBins attack surfaces."""

    def __init__(self, registry: dict[str, dict[str, Any]] | None = None):
        self.registry = registry if registry is not None else GTFOBINS_REGISTRY

    def check_binary(self, binary_name: str, source: str = "allowlist") -> ScanFinding | None:
        """Checks if a binary is in the GTFOBins registry and evaluates risk."""
        base = Path(binary_name).name
        if base in self.registry:
            meta = self.registry[base]
            return ScanFinding(
                binary=base,
                risk=meta["risk"],
                functions=meta["functions"],
                description=meta["description"],
                source=source,
                mitigated=False,
            )
        return None

    def scan_sudoers_file(self, sudoers_path: str | Path) -> ScanReport:
        """Parses a sudoers file and flags unmitigated GTFOBins commands."""
        path = Path(sudoers_path)
        if not path.exists():
            candidate = Path(__file__).resolve().parent.parent.parent / sudoers_path
            if candidate.exists():
                path = candidate
            else:
                raise FileNotFoundError(f"Sudoers file not found: {sudoers_path}")

        with open(path, encoding="utf-8") as f:
            raw_text = f.read()

        # Normalize line continuations with backslashes
        normalized_text = re.sub(r"\\\s*\n", " ", raw_text)

        denied_commands: set[str] = set()
        allowed_entries: list[str] = []

        for line in normalized_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Look for explicit negation: !/path/to/binary
            negations = re.findall(r"!\s*(/\S+)", line)
            for neg in negations:
                denied_commands.add(Path(neg).name)

            # Look for allowed rules: e.g. agentuser ALL=(ALL) NOPASSWD: /path/cmd1, /path/cmd2
            if "NOPASSWD:" in line:
                after_nopasswd = line.split("NOPASSWD:", 1)[1]
                entries = [e.strip() for e in after_nopasswd.split(",")]
                for entry in entries:
                    if entry.startswith("!"):
                        # Negation in allowlist
                        neg = entry.lstrip("!").strip().split()[0]
                        denied_commands.add(Path(neg).name)
                    elif entry.startswith("/"):
                        allowed_entries.append(entry)

        # Also collect any denied commands evaluated
        findings: list[ScanFinding] = []
        for cmd_entry in allowed_entries:
            parts = cmd_entry.split()
            bin_path = parts[0]
            bin_name = Path(bin_path).name
            finding = self.check_binary(bin_name, source=f"sudoers:{path.name}")
            if finding:
                # Check for argument restrictions (e.g. systemctl is-active / status only)
                if bin_name in denied_commands:
                    finding.mitigated = True
                    finding.mitigation_notes = "Explicitly blocked with ! negation"
                elif (
                    bin_name == "systemctl"
                    and len(parts) > 1
                    and parts[1] in ("is-active", "status")
                ):
                    finding.mitigated = True
                    finding.mitigation_notes = (
                        f"Restricted to safe read-only subcommands: {parts[1]}"
                    )
                elif bin_name == "apt-get" and len(parts) > 1 and parts[1] == "update":
                    finding.mitigated = True
                    finding.mitigation_notes = "Restricted to package index update"
                findings.append(finding)

        # Also report any explicit mitigations for denied dangerous binaries
        for denied in sorted(denied_commands):
            finding = self.check_binary(denied, source=f"sudoers:{path.name}")
            if finding:
                finding.mitigated = True
                finding.mitigation_notes = "Explicitly denied in sudoers configuration (!)"
                findings.append(finding)

        total_scanned = len(allowed_entries) + len(denied_commands)
        crit = sum(1 for f in findings if f.risk == "CRITICAL" and not f.mitigated)
        high = sum(1 for f in findings if f.risk == "HIGH" and not f.mitigated)
        med = sum(1 for f in findings if f.risk == "MEDIUM" and not f.mitigated)

        return ScanReport(
            total_scanned=total_scanned,
            critical_findings=crit,
            high_findings=high,
            medium_findings=med,
            passed=(crit == 0 and high == 0),
            findings=findings,
        )

    def scan_path_binaries(self, binaries: list[str]) -> ScanReport:
        """Scans an arbitrary list of binaries."""
        findings: list[ScanFinding] = []
        for b in binaries:
            f = self.check_binary(b, source="allowlist_manifest")
            if f:
                findings.append(f)

        crit = sum(1 for f in findings if f.risk == "CRITICAL")
        high = sum(1 for f in findings if f.risk == "HIGH")
        med = sum(1 for f in findings if f.risk == "MEDIUM")

        return ScanReport(
            total_scanned=len(binaries),
            critical_findings=crit,
            high_findings=high,
            medium_findings=med,
            passed=(crit == 0 and high == 0),
            findings=findings,
        )
