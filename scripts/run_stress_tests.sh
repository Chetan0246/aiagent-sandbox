#!/usr/bin/env bash
# run_stress_tests.sh - Executes boundary and stress probes inside the sandbox VM
set -euo pipefail

echo "=========================================================="
echo "AI Agent Sandbox Resource & Boundary Verification Suite"
echo "=========================================================="

echo "[1/4] Checking live cgroup limits..."
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/{memory.max,memory.swap.max,pids.max} 2>/dev/null || echo "cgroups not present"

echo "[2/4] Testing POSIX process limits..."
bash -c 'ulimit -u 50; python3 -c "import os; [os.fork() for _ in range(60)]"' 2>&1 || echo "Process limit successfully triggered EAGAIN"

echo "[3/4] Testing memory boundary with stress-ng (400M allocation)..."
stress-ng --vm 1 --vm-bytes 400M --timeout 10s || echo "stress-ng terminated or killed by OOM"

echo "[4/4] Probing gateway network isolation..."
timeout 2 bash -c 'cat < /dev/null > /dev/tcp/192.168.122.1/22' 2>/dev/null && echo "WARNING: Gateway 22 OPEN" || echo "Gateway 22 closed/filtered (BOUNDARY HELD)"

echo "[+] Verification suite finished."
