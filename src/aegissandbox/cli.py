"""Aegis-Sandbox CLI: Evaluation and boundary verification tool for AI agents."""

import argparse
import json
import sys

from .probes import (
    audit_sensitive_files,
    check_cgroups,
    check_imds_reachability,
    check_mount_isolation,
    probe_network_gateway,
)
from .stress import run_concurrency_stress, run_fork_probe, run_memory_probe

# ANSI terminal formatting
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_GREEN = "\033[32m"
C_RED = "\033[31m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"
C_GRAY = "\033[90m"


def print_header(title: str) -> None:
    print(f"\n{C_CYAN}{C_BOLD}{'=' * 60}{C_RESET}")
    print(f"{C_BOLD}Aegis :: {title}{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}{'=' * 60}{C_RESET}")


def print_badge(label: str, status: str, ok: bool) -> None:
    color = C_GREEN if ok else C_RED
    symbol = "OK" if ok else "FAIL"
    print(
        f"  [{color}{symbol:^4}{C_RESET}] {C_BOLD}{label:<28}{C_RESET} -> {color}{status}{C_RESET}"
    )


def cmd_audit(args: argparse.Namespace) -> None:
    print_header("Security Posture & Isolation Audit")

    # 1. Cgroups
    print(f"\n{C_BOLD}[1] Cgroup v2 Resource Ceilings:{C_RESET}")
    cg = check_cgroups()
    if "error" in cg:
        print_badge("Cgroups Status", cg["error"], False)
    else:
        for k, v in cg.get("limits", {}).items():
            is_unlimited = v in ["max", "infinity", "1114"]
            status_text = f"{v} (UNCONSTRAINED)" if is_unlimited else f"{v} (HARD LIMIT)"
            print_badge(k, status_text, not is_unlimited)

    # 2. Sensitive Files
    print(f"\n{C_BOLD}[2] Sensitive Filesystem DAC Boundaries:{C_RESET}")
    files = audit_sensitive_files()
    for f in files:
        print_badge(f["target"], f["status"], not f["accessible"])

    # 3. Mount Isolation
    print(f"\n{C_BOLD}[3] Storage Decoupling & Ephemerality:{C_RESET}")
    mounts = check_mount_isolation()
    print_badge(
        "/tmp isolated (tmpfs)",
        mounts.get("tmp_fstype", "unknown"),
        mounts.get("tmp_isolated", False),
    )
    print_badge(
        "/var/tmp isolated (tmpfs)",
        mounts.get("var_tmp_fstype", "unknown"),
        mounts.get("var_tmp_isolated", False),
    )

    # 4. IMDS
    print(f"\n{C_BOLD}[4] Cloud Metadata Service (IMDS) Probe:{C_RESET}")
    imds = check_imds_reachability()
    print_badge(imds["target"], imds["status"], not imds["reachable"])


def cmd_probe(args: argparse.Namespace) -> None:
    print_header("Network & Boundary Probes")
    print(f"\n{C_BOLD}Probing Hypervisor Gateway ({args.gateway}):{C_RESET}")
    results = probe_network_gateway(gateway_ip=args.gateway)
    for r in results:
        print_badge(r["target"], r["status"], r["secure"])


def cmd_stress(args: argparse.Namespace) -> None:
    print_header("Controlled Resource Stress Testing")

    # Memory probe
    print(f"\n{C_BOLD}[1] Probing Memory Allocation ({args.memory_mb} MB):{C_RESET}")
    mem_res = run_memory_probe(target_mb=args.memory_mb)
    print_badge(
        f"Alloc {args.memory_mb} MB",
        "SUCCESS" if mem_res["success"] else f"FAILED: {mem_res['error']}",
        mem_res["success"],
    )

    # Fork probe
    print(f"\n{C_BOLD}[2] Probing Fork Ceiling ({args.fork_limit} attempts):{C_RESET}")
    fork_res = run_fork_probe(max_procs=args.fork_limit)
    status_str = (
        f"Spawned {fork_res['successfully_spawned']} (Hit limit: {fork_res['hit_ceiling']})"
    )
    print_badge("Fork Probe", status_str, True)

    # Concurrency
    print(f"\n{C_BOLD}[3] Multi-Worker CPU Concurrency (3 workers):{C_RESET}")
    conc_res = run_concurrency_stress(workers=3, duration=1.5)
    print_badge(
        "Concurrency Stress",
        f"Completed in {conc_res['total_elapsed_seconds']}s",
        conc_res["completed"],
    )


def cmd_report(args: argparse.Namespace) -> None:
    data = {
        "cgroups": check_cgroups(),
        "sensitive_files": audit_sensitive_files(),
        "mounts": check_mount_isolation(),
        "imds": check_imds_reachability(),
        "gateway": probe_network_gateway(gateway_ip=args.gateway),
    }

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_header("System Audit Summary (JSON Report Available via --json)")
        print(json.dumps(data, indent=2))


def cmd_scan(args: argparse.Namespace) -> None:
    from .scanner import GTFOBinsScanner

    scanner = GTFOBinsScanner()

    print_header("GTFOBins Binary Privilege Escalation Audit")

    if args.sudoers:
        print(f"  {C_BOLD}Target Sudoers:{C_RESET} {args.sudoers}\n")
        report = scanner.scan_sudoers_file(args.sudoers)
    else:
        binaries = [b.strip() for b in args.binaries.split(",") if b.strip()]
        print(f"  {C_BOLD}Target Binaries:{C_RESET} {', '.join(binaries)}\n")
        report = scanner.scan_path_binaries(binaries)

    for finding in report.findings:
        status_color = (
            C_GREEN
            if finding.mitigated
            else (C_RED if finding.risk in ("CRITICAL", "HIGH") else C_YELLOW)
        )
        status_text = "MITIGATED" if finding.mitigated else "EXPOSED"
        print(
            f"  [{status_color}{status_text}{C_RESET}] {C_BOLD}{finding.binary:<14}{C_RESET} Risk: {finding.risk:<8} Vectors: {', '.join(finding.functions)}"
        )
        if finding.mitigation_notes:
            print(f"         ↳ Mitigation: {finding.mitigation_notes}")
        else:
            print(f"         ↳ Danger: {finding.description}")

    print(f"\n{C_CYAN}{'-' * 60}{C_RESET}")
    print_badge("Total Binaries Scanned", str(report.total_scanned), True)
    print_badge(
        "Critical Vulnerabilities", str(report.critical_findings), report.critical_findings == 0
    )
    print_badge("High Risk Vectors", str(report.high_findings), report.high_findings == 0)
    print_badge("GTFOBins Audit Result", "PASSED" if report.passed else "FAILED", report.passed)

    if not report.passed:
        sys.exit(1)


def cmd_run(args: argparse.Namespace) -> None:
    from .policy import SandboxPolicy
    from .runner import SandboxRunner

    policy = SandboxPolicy.from_yaml(args.policy) if args.policy else SandboxPolicy()
    runner = SandboxRunner(policy=policy, backend_name=args.backend)

    print_header(f"Active Enforcement Execution :: {args.backend.upper()}")
    print(f"  {C_BOLD}Policy:{C_RESET}     {policy.name}")
    print(f"  {C_BOLD}Backend:{C_RESET}    {args.backend}")
    print(f"  {C_BOLD}Command:{C_RESET}    {' '.join(args.command)}")
    print(f"{C_CYAN}{'-' * 60}{C_RESET}\n")

    res = runner.execute(args.command)

    if res.stdout:
        print(res.stdout, end="")
    if res.stderr:
        print(f"{C_RED}{res.stderr}{C_RESET}", end="", file=sys.stderr)

    print(f"\n{C_CYAN}{'-' * 60}{C_RESET}")
    print_badge("Exit Code", str(res.returncode), res.returncode == 0)
    print_badge("Duration", f"{res.duration_ms} ms", True)
    if res.violation_detected:
        print_badge("Security Boundary", f"VIOLATION TRAPPED: {res.violation_reason}", False)
    else:
        print_badge("Security Boundary", "CLEAN / CONTAINED", True)

    sys.exit(res.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aegis-sandbox",
        description="Aegis-Sandbox: Autonomous AI Agent Isolation & Security Verification Suite",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run
    run_parser = subparsers.add_parser(
        "run", help="Execute an untrusted command inside the enforced sandbox"
    )
    run_parser.add_argument(
        "--backend",
        choices=["namespaces", "container", "kvm"],
        default="namespaces",
        help="Sandbox isolation backend (default: namespaces)",
    )
    run_parser.add_argument("--policy", default=None, help="Path to declarative YAML policy file")
    run_parser.add_argument(
        "command_args",
        nargs=argparse.REMAINDER,
        help="Command to execute (e.g. -- python3 agent.py)",
    )

    # audit
    subparsers.add_parser("audit", help="Run comprehensive security posture audit")

    # probe
    probe_parser = subparsers.add_parser(
        "probe", help="Probe hypervisor and network boundary ports"
    )
    probe_parser.add_argument(
        "--gateway", default="192.168.122.1", help="Hypervisor gateway IP (default: 192.168.122.1)"
    )

    # stress
    stress_parser = subparsers.add_parser(
        "stress", help="Execute controlled resource limits stress test"
    )
    stress_parser.add_argument(
        "--memory-mb", type=int, default=150, help="Target MB to allocate (default: 150)"
    )
    stress_parser.add_argument(
        "--fork-limit", type=int, default=50, help="Max children to attempt (default: 50)"
    )

    # scan
    scan_parser = subparsers.add_parser(
        "scan", help="Scan binaries and sudoers configs for GTFOBins privilege escalation vectors"
    )
    scan_group = scan_parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument("--sudoers", help="Path to sudoers file to audit")
    scan_group.add_argument(
        "--binaries", help="Comma-separated list of binary names or paths to scan"
    )

    # report
    report_parser = subparsers.add_parser("report", help="Generate machine-readable audit report")
    report_parser.add_argument("--json", action="store_true", help="Output raw JSON format")
    report_parser.add_argument("--gateway", default="192.168.122.1", help="Hypervisor gateway IP")

    args = parser.parse_args()

    if args.command == "run":
        if args.command_args and args.command_args[0] == "--":
            args.command_args = args.command_args[1:]
        if not args.command_args:
            print(f"{C_RED}Error: No command specified to run.{C_RESET}")
            sys.exit(1)
        args.command = args.command_args
        cmd_run(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "probe":
        cmd_probe(args)
    elif args.command == "stress":
        cmd_stress(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
