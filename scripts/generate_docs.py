#!/usr/bin/env python3
"""
Automated Documentation Generator for Aegis Sandbox.
Synchronizes empirical benchmark JSON metrics directly into README.md and WHITE_PAPER.md.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARK_FILE = ROOT_DIR / "benchmark_results.json"
README_FILE = ROOT_DIR / "README.md"
WHITEPAPER_FILE = ROOT_DIR / "docs" / "WHITE_PAPER.md"

START_TAG = "<!-- BENCHMARK_TABLE_START -->"
END_TAG = "<!-- BENCHMARK_TABLE_END -->"


def format_benchmark_markdown(data: Dict[str, Any]) -> str:
    """Generates a GitHub-flavored Markdown table from benchmark JSON data."""
    meta = data.get("metadata", {})
    backends = data.get("backends", {})
    n = data.get("sample_size", 10)

    lines = [
        START_TAG,
        f"### 🔬 Empirical Multi-Backend Performance & Boundary Matrix ($n = {n}$)",
        "",
        f"> **Test Environment**: {meta.get('host_os', 'Linux')} | Kernel `{meta.get('kernel', 'unknown')}` | CPU: `{meta.get('cpu_model', 'unknown')}` ({meta.get('cpu_cores', 1)} vCPUs) | Host RAM: `{meta.get('ram_total_mb', 0)} MB` | Benchmark Date: `{meta.get('timestamp', 'latest')}`",
        "",
        "| Backend Isolation Model | Security Boundary Type | Startup Latency (Median ± $\\sigma$) | Compute Latency (SHA256) | Boundary Trap Latency | Memory Overhead | Containment Rate |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    backend_labels = {
        "namespaces": ("Linux Namespaces (`bwrap`)", "Software User/PID/Mount NS + Read-Only Bind"),
        "container": ("Rootless Podman (OCI)", "Unprivileged UserNS + Seccomp BPF + Cap Drops"),
        "kvm": ("Hardware VM (KVM/QEMU)", "Hardware VT-x/AMD-V + Separate Guest Ring 0"),
    }

    for b_key, (b_title, b_arch) in backend_labels.items():
        if b_key not in backends:
            continue
        b_data = backends[b_key]
        startup = b_data.get("startup_latency_ms", {})
        compute = b_data.get("compute_latency_ms", {})
        fs_trap = b_data.get("fs_violation_block_ms", {})
        mem = b_data.get("memory_overhead_mb", 0.0)
        rate = b_data.get("containment_rate_pct", 100.0)

        startup_str = f"**{startup.get('median', 0.0)} ms** (±{startup.get('stdev', 0.0)} ms)"
        compute_str = f"{compute.get('median', 0.0)} ms"
        trap_str = f"{fs_trap.get('median', 0.0)} ms"
        mem_str = f"~{mem} MB"
        rate_str = f"**{rate}%**"

        lines.append(f"| **{b_title}** | {b_arch} | {startup_str} | {compute_str} | {trap_str} | {mem_str} | {rate_str} |")

    lines.extend([
        "",
        f"*Empirically recorded using `scripts/run_benchmarks.py` across {n} consecutive randomized trials under active enforcement.*",
        END_TAG,
    ])

    return "\n".join(lines)


def update_target_file(file_path: Path, new_table_md: str) -> bool:
    """Replaces or inserts benchmark table between sentinel tags in the target markdown file."""
    if not file_path.exists():
        print(f"[-] File not found: {file_path}")
        return False

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(rf"{re.escape(START_TAG)}[\s\S]*?{re.escape(END_TAG)}")
    if pattern.search(content):
        updated_content = pattern.sub(new_table_md, content)
    else:
        # If tags not found, insert after the Architectural Isolation Matrix section
        insert_marker = "## 📊 Architectural Isolation Matrix: Containers vs. VMs"
        if insert_marker in content:
            updated_content = content.replace(
                insert_marker,
                f"{insert_marker}\n\n{new_table_md}\n"
            )
        else:
            updated_content = content + f"\n\n{new_table_md}\n"

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(updated_content)

    print(f"[+] Successfully synchronized benchmark data into {file_path.name}")
    return True


def main():
    if not BENCHMARK_FILE.exists():
        print(f"[-] Benchmark data file not found at {BENCHMARK_FILE}. Run scripts/run_benchmarks.py first.")
        return

    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    table_md = format_benchmark_markdown(data)

    update_target_file(README_FILE, table_md)
    update_target_file(WHITEPAPER_FILE, table_md)


if __name__ == "__main__":
    main()
