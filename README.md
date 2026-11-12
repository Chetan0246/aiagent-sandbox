<div align="center">

# 🛡️ Aegis-Sandbox
### *Empirical Isolation, Boundary Enforcement & Stress Testing Suite for Autonomous AI Agents*

[![CI](https://github.com/Chetan0246/aiagent-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Chetan0246/aiagent-sandbox/actions/workflows/ci.yml)
[![Debian](https://img.shields.io/badge/Debian-13.7_Trixie-A81D33?logo=debian&logoColor=white)](https://www.debian.org/)
[![Kernel](https://img.shields.io/badge/Kernel-6.12.x_x86__64-black?logo=linux&logoColor=white)](https://kernel.org/)
[![Hypervisor](https://img.shields.io/badge/Hypervisor-KVM_%2F_QEMU-E66D14?logo=qemu&logoColor=white)](https://www.linux-kvm.org/)
[![Cgroups](https://img.shields.io/badge/Cgroups-v2_Unified-4B8BBE)](https://www.freedesktop.org/software/systemd/man/latest/systemd.slice.html)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[**Read the Research Whitepaper**](docs/WHITE_PAPER.md) • [**View Master Empirical Log**](docs/test_results.md) • [**Explore Hardening Blueprints**](configs/)

</div>

---

## 📌 Table of Contents
- [Executive Summary](#-executive-summary)
- [Why AI Agents Break Traditional Sandboxes](#-why-ai-agents-break-traditional-sandboxes)
- [Architectural Isolation Matrix: Containers vs. VMs](#-architectural-isolation-matrix-containers-vs-vms)
- [Sandbox Architecture & Supervisory Control](#-sandbox-architecture--supervisory-control)
- [Aegis-Sandbox CLI Showcase](#-aegis-sandbox-cli-showcase)
- [Empirical Findings & Vulnerability Deep Dives](#-empirical-findings--vulnerability-deep-dives)
  - [1. The Sudoers Slice-Bypass Trap](#1-the-sudoers-slice-bypass-trap)
  - [2. Default TasksMax Thread Starvation](#2-default-tasksmax-thread-starvation)
  - [3. Swap as a Deceptive OOM Buffer](#3-swap-as-a-deceptive-oom-buffer)
  - [4. Out-of-Band Supervisor Recovery (< 50ms)](#4-out-of-band-supervisor-recovery--50ms)
- [Comprehensive Empirical Test Matrix](#-comprehensive-empirical-test-matrix)
- [The 4-Pillar Production Hardening Framework](#-the-4-pillar-production-hardening-framework)
- [Repository Layout](#-repository-layout)
- [Quickstart & Reproduction Guide](#-quickstart--reproduction-guide)

---

## 🔬 Executive Summary

Autonomous AI agents (e.g., Devin, OpenHands, AutoGPT, Claude Code) represent a paradigm shift in execution security: unlike traditional deterministic software, **agents execute arbitrary bash commands, install system dependencies, self-debug execution failures, and run concurrent sub-agents**. When exposed to untrusted external input (web pages, repositories, APIs), they become vulnerable to **indirect prompt injection**.

**Aegis-Sandbox** is an empirical research suite, hardening blueprint, and automated verification CLI evaluating isolation boundaries, resource exhaustion thresholds, living-off-the-land privilege escalation, and out-of-band recovery under real hardware virtualization (Debian 13 minimal guest under KVM/QEMU).

```
                      ┌────────────────────────────────────────────────────────┐
                      │            Hypervisor Host (Fedora 44)                 │
                      │       QEMU / KVM / Linux 6.12 / virbr0 (192.168.122.1) │
                      └───────────────────────────▲────────────────────────────┘
                                                  │ Hardware VT-x Virtualization Wall
  ┌───────────────────────────────────────────────┴───────────────────────────────────────────────┐
  │ Guest Virtual Machine: debian-minimal (192.168.122.71 / 1 vCPU / 512MB RAM)                   │
  │                                                                                               │
  │   [Administrative Supervisor Domain] (UID 1000: chetan)                                       │
  │     - user-1000.slice (Isolated out-of-band management session)                               │
  │                                                                                               │
  │   [Constrained Agent Domain] (UID 1001: agentuser)                                            │
  │     - user-1001.slice (MemoryMax=448M, MemorySwapMax=128M, TasksMax=256)                      │
  │     ├── Primary Autonomous Agent Session (SSH control loop)                                   │
  │     │      │ (spawns tasks)                                                                   │
  │     │      ▼                                                                                  │
  │     └── Sub-Agents & Child Fork Pools (Subject to shared slice ceiling)                       │
  │            │                                                                                  │
  │            ▼                                                                                  │
  │     [Filesystem Hierarchy]                                                                    │
  │       ├── /tmp     ──▶ 233 MiB tmpfs (ephemeral, memory-backed)                               │
  │       ├── /var/tmp ──▶ 256 MiB tmpfs (shielded mount; prevents root disk fill)                │
  │       └── /        ──▶ 7.4 GiB ext4 root partition (/dev/vda1)                                │
  └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Why AI Agents Break Traditional Sandboxes

Most developer sandbox architectures rely on **shared-kernel containers (Docker/Podman)**. For autonomous LLM agents, containers introduce fatal vulnerabilities:

1. **Shared Ring 0 Attack Surface**: All agent syscalls hit the host kernel. A single kernel vulnerability (e.g., `Dirty Pipe`, eBPF flaw) compromises the physical host.
2. **Sudo / Docker Socket Leakage**: When agents are given `sudo` or Docker access to install dependencies, container breakouts to the host are trivial via device nodes or cgroup release agents.
3. **Hypervisor Hardware Wall**: In a hardware-assisted VM (KVM), privileged CPU instructions trap to the hypervisor (Ring -1). Even if an agent acquires guest `root`, it remains hardware-trapped inside the VM.

---

## 📊 Architectural Isolation Matrix: Containers vs. VMs

| Vector | Container (Docker / Podman) | MicroVM (Firecracker / Kata) | Full Hardware VM (KVM / QEMU) |
| :--- | :--- | :--- | :--- |
| **Kernel Model** | **Shared Host Kernel** | **Dedicated Guest Kernel** | **Full Dedicated Guest Kernel** |
| **Isolation Mechanism** | Namespaces & Cgroups (Software) | Hardware Virtualization (KVM VT-x) | Hardware Virtualization (KVM VT-x) |
| **Agent Acquiring Root** | **Critical Host Compromise Risk** | **Contained** inside MicroVM | **Contained** inside Virtual Machine |
| **Out-of-Band Supervisor Kill** | Partial (shared host resource risks) | Instantaneous (`vmm` terminate) | Instantaneous (`systemctl stop user-$UID.slice`) |
| **Cold Boot Latency** | < 100 ms | 5 ms – 25 ms | 2 s – 6 s |
| **Density & Overhead** | Extremely High | High | Moderate |

---

## 🛠️ Aegis-Sandbox CLI Showcase

The repository includes a modern, modular Python command-line tool (`aegis-sandbox`) providing automated boundary auditing, network probing, and resource stress testing:

```bash
# Install Aegis-Sandbox
pip install .

# 1. Run full security posture and cgroup boundary audit
aegis-sandbox audit

# 2. Probe hypervisor network gateway management ports
aegis-sandbox probe --gateway 192.168.122.1

# 3. Execute safe, self-reaping resource stress tests
aegis-sandbox stress --memory-mb 150 --fork-limit 50

# 4. Generate machine-readable JSON security report
aegis-sandbox report --json
```

```
============================================================
🛡️  Aegis-Sandbox :: Security Posture & Isolation Audit
============================================================

[1] Cgroup v2 Resource Ceilings:
  [✔] memory.max                   -> 469762048 (HARD LIMIT)
  [✔] memory.swap.max              -> 134217728 (HARD LIMIT)
  [✔] pids.max                     -> 256 (HARD LIMIT)

[2] Sensitive Filesystem DAC Boundaries:
  [✔] /etc/shadow                  -> BOUNDARY_HELD
  [✔] /root                        -> BOUNDARY_HELD
  [✔] /proc/1/environ              -> BOUNDARY_HELD

[3] Storage Decoupling & Ephemerality:
  [✔] /tmp isolated (tmpfs)        -> tmpfs
  [✔] /var/tmp isolated (tmpfs)    -> tmpfs

[4] Cloud Metadata Service (IMDS) Probe:
  [✔] 169.254.169.254:80           -> BOUNDARY_HELD
```

---

## 🔍 Empirical Findings & Vulnerability Deep Dives

### 1. The Sudoers Slice-Bypass Trap
```bash
# Executed by agentuser with blanket (ALL) NOPASSWD: ALL
sudo systemd-run --system --scope /bin/true
sudo nsenter --target 1 --mount /bin/true
```
* **Vulnerability**: Standard sudo privileges allow an agent to launch processes inside `system.slice` (via `systemd-run`) or enter PID 1's namespaces (via `nsenter`), **completely bypassing all user slice cgroup caps** (`MemoryMax`, `TasksMax`).
* **Remediation**: Deploy a strict allowlist denying `systemd-run`, `nsenter`, `chroot`, `unshare`, and systemd property editing tools (see [configs/sudoers/agentuser.sudoers](configs/sudoers/agentuser.sudoers)).

### 2. Default TasksMax Thread Starvation
* **Vulnerability**: Systemd sets `TasksMax=1114` by default for user slices. On a 512 MB machine with 1 vCPU, 1,114 tasks cause severe kernel thread-table exhaustion, leading to SSH child fork failures (`sshd-session: fatal: fork of unprivileged child failed`).
* **Remediation**: Hard-cap user slices to `TasksMax=256` or `100` via [override.conf](configs/systemd/user-1001.slice.d/override.conf).

### 3. Swap as a Deceptive OOM Buffer
* **Vulnerability**: Allocating 600 MB on a 512 MB VM failed to trigger the Linux kernel OOM killer because total virtual memory was ~943 MB (464 MB RAM + 479 MB Swap). Swap absorbed the spillover, masking memory exhaustion and causing latency spikes.
* **Remediation**: Bounded swap limits (`MemorySwapMax=0` or `MemorySwapMax=128M`) are mandatory for deterministic memory constraints.

### 4. Out-of-Band Supervisor Recovery (< 50ms)
```bash
# Executed from administrative session (chetan / UID 1000)
sudo systemctl stop user-1001.slice
```
* **Discovery**: When `agentuser` was saturated with 407 runaway sleep processes, issuing a slice stop from the separate administrative session (`chetan`, UID 1000) **instantly reaped all 407 tasks in under 50ms**.
* **Impact**: The host and VM's `sshd` daemon remained 100% active, and a fresh agent login succeeded immediately with clean state.

---

## 📈 Comprehensive Empirical Test Matrix

All 16 test suites were executed sequentially under a strict non-destructive protocol. Detailed logs with exact exit codes and kernel dmesg outputs are preserved in [docs/test_results.md](docs/test_results.md).

| Suite | Category | Applied Stress / Target | Observed Behavior | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| **Phase 1** | Sanity Checks | `whoami`, `uname -a`, storage, SSH, `apt-get` | Debian 13 (Linux 6.12), UID 1001, root ext4 7.4G, RAM 464M. | **PASS** |
| **Phase 2A** | Memory Limits | 600M allocation on 512M VM | Swap absorbed burst; `ulimit -v` and `ulimit -d` enforced `MemoryError`. | **PASS** |
| **Phase 2B** | CPU / Inodes / Disk | 3x `yes > /dev/null`, 50k inodes, `/tmp` fill | 100% CPU on 1 vCPU didn't drop SSH; `/tmp` tmpfs failed at 232MB (`ENOSPC`). | **PASS** |
| **Safe Fork** | Process Caps | `ulimit -u 50` & `TasksMax=30` | Cleanly hit `EAGAIN` (`[Errno 11] Resource temporarily unavailable`). | **PASS** |
| **Phase 3** | Boundary Holds | `/sys/fs/cgroup`, `/dev/vda`, gateway:22 | Write to cgroup denied; raw block write denied; gateway refused connections. | **BOUNDARY HELD** |
| **Phase 4** | Robustness | SSH audit, idempotent apt, live ssh reload | Modern OpenSSH 9.9p1 ciphers; `systemctl restart ssh` maintained live session. | **PASS** |
| **Phase 5** | Sustained Stress | 120s memory loop, 5k race condition lines | 0 OOM kills; 5,000 parallel lines written without 1 corrupted byte; 0 panics. | **PASS** |
| **Hard Limits**| Hard Walls | Real root ext4 fill (`/var/tmp/fill`), 600M OOM | `/var/tmp` triggered real ext4 `ENOSPC` at 6.1GB; `MemorySwapMax=0` triggered instant OOM. | **PASS** |
| **Slice Escape**| Privilege Audit| `sudo systemd-run`, `sudo nsenter` | Unrestricted sudo allowed escaping user slice into `system.slice`. | **CRITICAL FINDING** |
| **Adv. Phase 1**| Secret Bleed | `/etc/shadow`, `/root`, IMDS probe | Permission denied on system files; IMDS connection timed out. | **PASS** |
| **Adv. Phase 2**| Sub-Agent Scope | Spawning background worker sub-agents | Sub-agents placed in parent slice; share identical 256 task pool. | **PASS** |
| **Adv. Phase 3**| GTFOBins Probe | SUID audit, `find -exec` probes | Zero dangerous SUID binaries; `find` abuse blocked by DAC. | **PASS** |
| **Adv. Phase 4**| Network Boundary| Gateway ports (22, 80, 5900, 8080) | All hypervisor management ports CLOSED/FILTERED. | **PASS** |
| **Adv. Phase 5**| Error Drift | Read-only directory write, `fcntl` flock | Cleanly trapped errors; non-blocking lock prevented sub-agent race conditions. | **PASS** |
| **Adv. Phase 6**| Ephemerality | Shell profiles, crontab, `/tmp` sweep | Zero residual files, zero cron entries, zero injected profile hooks. | **PASS** |
| **Phase 7** | Sudoers Lockdown| Probing 5 blocked commands (`systemd-run`, `nsenter`, `tee`)| All 5 escape commands denied with exit 1; allowlisted commands active. | **PASS (ESCAPE CLOSED)** |
| **Phase 8** | Storage Shielding| Mounting `/var/tmp` on `tmpfs` (256M) & disk fill | Fill failed at 256M on `tmpfs`; real root ext4 stayed clean at 18% used. | **PASS** |
| **Phase 9** | Injection Defense| Parameterized `subprocess.run(shell=False)` | Command injection tokens treated as literal bytes; 0 payload execution. | **PASS** |
| **Phase 10** | Multi-Agent Load| 3 concurrent workers (Disk I/O, CPU math, RAM buffer)| CFS scheduler balanced tasks; 0 lock thrashing; SSH responsive. | **PASS** |

---

## 🏛️ The 4-Pillar Production Hardening Framework

```
┌────────────────────────────────────────────────────────────────────────┐
│                   THE 4-PILLAR HARDENING BLUEPRINT                     │
├────────────────────────────────┬───────────────────────────────────────┤
│ Pillar I: Hypervisor Ring 0    │ Hardware VT-x / Dedicated KVM Guest   │
│ Pillar II: Cgroup v2 Limits    │ MemoryMax=448M, Swap=128M, Tasks=256  │
│ Pillar III: Sudoers Jail       │ Explicit deny on systemd-run, nsenter │
│ Pillar IV: Ephemeral Mounts    │ tmpfs on /tmp (233M) & /var/tmp (256M)│
└────────────────────────────────┴───────────────────────────────────────┘
```

### 1. Systemd Slice Enforcement
Deploy to `/etc/systemd/system/user-1001.slice.d/override.conf`:
```ini
[Slice]
# Hard cap on physical RAM
MemoryMax=448M

# Hard cap on swap allocation
MemorySwapMax=128M

# Hard cap on tasks/threads to prevent fork bombs
TasksMax=256

# Restrict CPU utilization
CPUQuota=90%
```

### 2. Sudoers Policy Hardening
Deploy to `/etc/sudoers.d/agentuser`:
```sudoers
# Allow standard inspection commands
agentuser ALL=(ALL) NOPASSWD: \
    /usr/bin/systemctl is-active *, \
    /usr/bin/systemctl status *, \
    /usr/bin/dmesg, \
    /usr/bin/journalctl, \
    /usr/bin/apt-get update, \
    /usr/bin/apt-get install -y *

# Deny slice and namespace breakout vectors
agentuser ALL=(ALL) !/usr/bin/systemd-run, \
    !/usr/bin/nsenter, \
    !/usr/bin/chroot, \
    !/usr/bin/unshare, \
    !/usr/bin/bash, \
    !/usr/bin/sh, \
    !/usr/bin/su, \
    !/usr/bin/tee
```

### 3. Ephemeral Storage Mounts
Decouple persistent storage from temporary file writes in `/etc/fstab`:
```fstab
tmpfs   /tmp       tmpfs   defaults,noatime,nosuid,nodev,size=256M   0   0
tmpfs   /var/tmp   tmpfs   defaults,noatime,nosuid,nodev,size=256M   0   0
```

---

## 📂 Repository Layout

```
├── .github/
│   ├── workflows/ci.yml           # Automated unit testing & sudoers syntax validation
│   └── ISSUE_TEMPLATE/            # Standardized bug and feature issue templates
├── configs/
│   ├── sudoers/
│   │   └── agentuser.sudoers      # Hardened allowlist/deny-list closing slice-escape vectors
│   ├── systemd/
│   │   └── user-1001.slice.d/
│   │       └── override.conf      # Cgroup v2 limits (MemoryMax=448M, Swap=128M, Tasks=256)
│   └── vm/
│       └── debian-minimal.xml     # Full libvirt/KVM domain XML definition
├── docs/
│   ├── WHITE_PAPER.md             # Formal research paper on agent isolation
│   ├── agent_rules.md             # Standard agent operational contract & safety rules
│   ├── phase1_sanity_checks.md    # Dedicated baseline environment verification
│   └── test_results.md            # Master 60 KB empirical test log with verbatim logs
├── scripts/
│   ├── run_stress_tests.sh        # Automated in-sandbox verification & stress probe
│   └── setup_vm.sh                # Unattended KVM/QEMU provisioning script
├── src/aegissandbox/              # Aegis-Sandbox Python CLI & verification library
│   ├── __init__.py
│   ├── cli.py                     # Interactive CLI interface (audit, probe, stress, report)
│   ├── probes.py                  # Cgroup, file permission, IMDS & gateway probes
│   └── stress.py                  # Safe, self-reaping resource stress routines
├── tests/
│   └── test_cli.py                # Unit test suite for Aegis-Sandbox modules
├── CONTRIBUTING.md                # Community contribution guidelines
├── LICENSE                        # MIT License
└── pyproject.toml                 # Modern PEP 517/621 Python package configuration
```

---

## 🚀 Quickstart & Reproduction Guide

### 1. Install Aegis-Sandbox Locally
```bash
git clone https://github.com/Chetan0246/aiagent-sandbox.git
cd aiagent-sandbox
pip install -e .
```

### 2. Provision the KVM Sandbox
```bash
chmod +x scripts/*.sh
./scripts/setup_vm.sh /path/to/debian-13.7.0-amd64-netinst.iso
```

### 3. Deploy Hardening Configurations
```bash
# Inside the VM (as root or administrator)
sudo cp configs/systemd/user-1001.slice.d/override.conf /etc/systemd/system/user-1001.slice.d/
sudo cp configs/sudoers/agentuser.sudoers /etc/sudoers.d/agentuser
sudo chmod 440 /etc/sudoers.d/agentuser
sudo systemctl daemon-reload
```

### 4. Verify Boundaries with the CLI
```bash
# As agentuser inside the sandbox
aegis-sandbox audit
aegis-sandbox probe
```

---

## 📄 License
This repository is open-source and licensed under the [MIT License](LICENSE).
