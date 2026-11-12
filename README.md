# AI Agent Sandbox: Empirical Isolation, Boundary Enforcement & Stress Testing

[![Debian](https://img.shields.io/badge/Debian-13.7_Trixie-A81D33?logo=debian&logoColor=white)](https://www.debian.org/)
[![Kernel](https://img.shields.io/badge/Kernel-6.12.x_x86__64-black?logo=linux&logoColor=white)](https://kernel.org/)
[![Hypervisor](https://img.shields.io/badge/Hypervisor-KVM_%2F_QEMU-E66D14?logo=qemu&logoColor=white)](https://www.linux-kvm.org/)
[![Cgroups](https://img.shields.io/badge/Cgroups-v2_Unified-4B8BBE)](https://www.freedesktop.org/software/systemd/man/latest/systemd.slice.html)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An empirical research and security engineering suite evaluating boundary enforcement, resource exhaustion, privilege delegation, and out-of-band recovery for autonomous AI agent environments.

---

## 📌 Table of Contents
- [Executive Overview](#-executive-overview)
- [Why AI Agents Require Dedicated VM Sandboxing](#-why-ai-agents-require-dedicated-vm-sandboxing)
- [Container vs. Virtual Machine Isolation Matrix](#-container-vs-virtual-machine-isolation-matrix)
- [Sandbox Architecture & Topology](#-sandbox-architecture--topology)
- [Empirical Test Suite & Results Matrix](#-empirical-test-suite--results-matrix)
- [Critical Discoveries & Vulnerability Analyses](#-critical-discoveries--vulnerability-analyses)
  - [1. The Sudoers Slice-Bypass Trap](#1-the-sudoers-slice-bypass-trap)
  - [2. Default TasksMax Thread Starvation](#2-default-tasksmax-thread-starvation)
  - [3. Swap as a Deceptive OOM Buffer](#3-swap-as-a-deceptive-oom-buffer)
  - [4. Out-of-Band Supervisor Kill Efficacy](#4-out-of-band-supervisor-kill-efficacy)
- [Hardening Blueprints](#-hardening-blueprints)
- [Repository Structure](#-repository-structure)
- [Quickstart & Reproduction Guide](#-quickstart--reproduction-guide)

---

## 🔬 Executive Overview

Autonomous AI agents possess capabilities fundamentally different from traditional sandboxed software: they execute arbitrary shell scripts, chain developer tools, generate self-modifying code, spawn child sub-agents, and actively debug permission blocks. When exposed to external input, they can also become subject to **indirect prompt injection**.

This repository documents exhaustive, empirical stress testing and boundary probing performed inside a deliberately constrained **Debian 13 minimal virtual machine** managed by KVM/QEMU, running under a strict operational contract.

```
                      ┌────────────────────────────────────────────────────────┐
                      │            Hypervisor Host (Fedora 44)                 │
                      │       QEMU / KVM / Linux 6.12 / virbr0 (192.168.122.1) │
                      └───────────────────────────▲────────────────────────────┘
                                                  │ Hardware VT-x Virtualization Wall
  ┌───────────────────────────────────────────────┴───────────────────────────────────────────────┐
  │ Guest Virtual Machine: debian-minimal (192.168.122.71 / 1 vCPU / 512MB RAM)                   │
  │                                                                                               │
  │   [Administrative Domain] (UID 1000: chetan)                                                  │
  │     - user-1000.slice (Unconstrained out-of-band supervisor session)                          │
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
  │       └── /var/tmp ──▶ 7.4 GiB ext4 root partition (/dev/vda1)                                │
  └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Why AI Agents Require Dedicated VM Sandboxing

Conventional container runtimes (Docker, Podman, LXC) rely on **shared host Linux kernels** isolated through cgroups and namespaces. While effective for trusted microservices, containers introduce unacceptable risks when executing autonomous LLM workloads:

1. **Shared Ring 0 Attack Surface**: Any kernel vulnerability (e.g., `Dirty Pipe`, eBPF verification bugs, race conditions in `sys_clone`) allows an untrusted agent process to compromise the physical host.
2. **Ambient Authority & Sudo Leaks**: Granting an agent sudo or docker socket access within a container typically leads to instant host root compromise via mount injections or device nodes.
3. **Hypervisor Hardware Boundaries**: In a hardware-assisted VM (KVM), all system calls terminate in the *guest kernel*. Even if the agent gains root privileges inside the guest, it remains hardware-trapped by CPU VT-x/AMD-V virtualization rings.

---

## 📊 Container vs. Virtual Machine Isolation Matrix

| Architectural Vector | Container (Docker / Podman) | MicroVM (Firecracker / Cloud Hypervisor) | Full Virtual Machine (KVM / QEMU) |
| :--- | :--- | :--- | :--- |
| **Kernel Model** | **Shared Host Kernel** | **Dedicated Minimal Guest Kernel** | **Full Dedicated Guest Kernel** |
| **Hypervisor Security Wall** | None (cgroup/namespace boundaries only) | Hardware Virtualization (KVM ring-1) | Hardware Virtualization (KVM / QEMU) |
| **Agent Gaining Root Privileges** | **Critical Risk**: Host escape via `/proc`, `/sys`, or cgroup mounts | **Contained**: Restricted to minimal microVM guest | **Contained**: Restricted entirely to guest VM |
| **Startup Latency** | Milliseconds (< 100ms) | Tens of milliseconds (5ms – 25ms) | Seconds (3s – 12s) |
| **Process Isolation** | Host PID mapping | Independent guest PID space | Independent guest PID space |
| **Out-of-Band Supervisor Kill** | Partial (depends on host cgroup hygiene) | Instantaneous (`vmm` termination) | Instantaneous (`systemctl stop user-$UID.slice` or `virsh destroy`) |

---

## 📈 Empirical Test Suite & Results Matrix

The entire multi-phase battery was executed sequentially under an automated observation protocol. All exit codes, stdout/stderr, and kernel ring logs are preserved in [docs/test_results.md](docs/test_results.md).

| Phase | Test Scope | Applied Stress / Target | Observed Behavior | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| **Phase 1** | Sanity Checks | `whoami`, `uname -a`, storage, SSH, `apt-get` | Debian 13 (Linux 6.12), UID 1001, root ext4 7.4G, RAM 464M available. | **PASS** |
| **Phase 2A** | Memory Limits | 600M allocation on 512M VM | Swap absorbed spillover; `ulimit -v` and `ulimit -d` enforced `MemoryError`. | **PASS** |
| **Phase 2B** | CPU / Inodes / Disk | 3x `yes > /dev/null`, 50k inodes, `/tmp` fill | 100% CPU on 1 vCPU didn't drop SSH; `/tmp` tmpfs failed at 232MB (`ENOSPC`) without touching `/`. | **PASS** |
| **Safe Fork** | Process Caps | `ulimit -u 50` & `TasksMax=30` | Cleanly hit `EAGAIN` (`[Errno 11] Resource temporarily unavailable`) at exact thresholds. | **PASS** |
| **Phase 3** | Boundary Holds | `/sys/fs/cgroup`, `/dev/vda`, gateway:22 | Write to cgroup denied; raw block write denied; hypervisor gateway refused connections. | **BOUNDARY HELD** |
| **Phase 4** | Robustness & Lockout | SSH audit, idempotent apt, live ssh reload | Modern OpenSSH 9.9p1 ciphers; `systemctl restart ssh` maintained live session without drop. | **PASS** |
| **Phase 5** | Sustained Stress | 120s memory loop, 5k race condition lines | 0 OOM kills; 5,000 parallel lines written without 1 corrupted byte; 0 kernel panics. | **PASS** |
| **Hard Limits** | Hard Walls | Real root ext4 fill (`/var/tmp/fill`), 600M OOM | `/var/tmp` triggered real ext4 `ENOSPC` at 6.1GB; `MemorySwapMax=0` triggered instant OOM kill. | **PASS** |
| **Slice Escape** | Privilege Audit | `sudo systemd-run`, `sudo nsenter` | Unrestricted sudo allowed escaping user slice into `system.slice`. | **CRITICAL FINDING** |
| **Adv. Phase 1**| Secret Bleed | `/etc/shadow`, `/root`, IMDS probe | Permission denied on system files; IMDS connection timed out. | **PASS** |
| **Adv. Phase 2**| Sub-Agent Scope | Spawning background worker sub-agents | Sub-agents placed in parent slice; share identical 256 task pool. | **PASS** |
| **Adv. Phase 3**| GTFOBins Probe | SUID audit, `find -exec` probes | Zero dangerous SUID binaries; `find` abuse blocked by DAC. | **PASS** |
| **Adv. Phase 4**| Network Boundary | Gateway ports (22, 80, 5900, 8080) | All hypervisor management ports CLOSED/FILTERED. | **PASS** |
| **Adv. Phase 5**| Error Drift | Read-only directory write, `fcntl` flock | Cleanly trapped errors; non-blocking lock prevented sub-agent race conditions. | **PASS** |
| **Adv. Phase 6**| Ephemerality | Shell profiles, crontab, `/tmp` sweep | Zero residual files, zero cron entries, zero injected profile hooks. | **PASS** |

---

## 🔍 Critical Discoveries & Vulnerability Analyses

### 1. The Sudoers Slice-Bypass Trap
```bash
# Executed by agentuser with (ALL) NOPASSWD: ALL
sudo systemd-run --system --scope /bin/true
sudo nsenter --target 1 --mount /bin/true
```
* **Discovery**: When an agent account is granted blanket sudo rights (`NOPASSWD: ALL`), it can spawn arbitrary workloads inside `system.slice` (via `systemd-run`) or enter PID 1's namespaces (via `nsenter`). This **completely neutralizes all user slice cgroup caps** (`MemoryMax`, `TasksMax`).
* **Mitigation**: Deploy a strict allowlist denying `systemd-run`, `nsenter`, `chroot`, `unshare`, and systemd property editing tools (see [configs/sudoers/agentuser.sudoers](configs/sudoers/agentuser.sudoers)).

### 2. Default TasksMax Thread Starvation
* **Discovery**: Systemd 257 / Debian 13 sets `TasksMax=1114` by default for user slices. On a 512 MB machine with 1 vCPU, 1,114 tasks causes severe kernel thread-table exhaustion, leading to SSH child fork failures (`sshd-session: fatal: fork of unprivileged child failed`).
* **Mitigation**: Hard-cap user slices to `TasksMax=256` or `100` via [override.conf](configs/systemd/user-1001.slice.d/override.conf).

### 3. Swap as a Deceptive OOM Buffer
* **Discovery**: Stressing memory with 600 MB on a 512 MB VM failed to trigger the Linux kernel OOM killer because total virtual memory was ~943 MB (464 MB RAM + 479 MB Swap).
* **Mitigation**: To guarantee deterministic memory testing and prevent thrashing, `MemorySwapMax=0` or `MemorySwapMax=128M` must be explicitly configured.

### 4. Out-of-Band Supervisor Kill Efficacy
```bash
# Executed from administrative session (chetan / UID 1000)
sudo systemctl stop user-1001.slice
```
* **Discovery**: When `agentuser` was saturated with 407 runaway sleep processes, issuing a slice stop from the separate administrative session (`chetan`, UID 1000 in `user-1000.slice`) **instantly reaped all 407 tasks in under 50ms**.
* **Impact**: The host and VM's `sshd` daemon remained 100% active, and a fresh agent login succeeded immediately with clean state.

---

## 🛠️ Hardening Blueprints

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
    !/usr/bin/systemctl set-property *, \
    !/usr/bin/systemctl edit *, \
    !/usr/bin/systemctl stop user-*, \
    !/usr/bin/bash, \
    !/usr/bin/sh, \
    !/usr/bin/su, \
    !/usr/bin/tee /etc/*
```

### 3. Ephemeral Storage Mounts
Protect the root filesystem from disk exhaustion by placing `/var/tmp` on `tmpfs`:
```fstab
# /etc/fstab
tmpfs   /var/tmp   tmpfs   defaults,noatime,nosuid,nodev,size=256M   0   0
```

---

## 📂 Repository Structure

```
├── README.md                      # Primary research & hardening document
├── configs/
│   ├── sudoers/
│   │   └── agentuser.sudoers      # Hardened deny-list closing slice-escape vectors
│   ├── systemd/
│   │   └── user-1001.slice.d/
│   │       └── override.conf      # Hard cgroup v2 resource limits
│   └── vm/
│       └── debian-minimal.xml     # Complete libvirt / KVM domain definition
├── docs/
│   ├── agent_rules.md             # Standard operating contract & reporting schema
│   ├── phase1_sanity_checks.md    # Baseline verification report
│   └── test_results.md            # Master 57 KB test log with verbatim logs
└── scripts/
    ├── run_stress_tests.sh        # In-sandbox automated test suite
    └── setup_vm.sh                # Automated KVM provisioning script
```

---

## 🚀 Quickstart & Reproduction Guide

### 1. Provision the Sandbox
```bash
git clone https://github.com/Chetan0246/aiagent-sandbox.git
cd aiagent-sandbox
chmod +x scripts/*.sh

# Provision KVM VM using libvirt
./scripts/setup_vm.sh /path/to/debian-13.7.0-amd64-netinst.iso
```

### 2. Apply Cgroup Limits
```bash
# Inside the VM (as root or administrator)
sudo cp configs/systemd/user-1001.slice.d/override.conf /etc/systemd/system/user-1001.slice.d/
sudo cp configs/sudoers/agentuser.sudoers /etc/sudoers.d/agentuser
sudo chmod 440 /etc/sudoers.d/agentuser
sudo systemctl daemon-reload
```

### 3. Run the Stress Suite
```bash
# As agentuser inside the sandbox
./scripts/run_stress_tests.sh
```

---

## 📄 License
This repository is open-source and licensed under the [MIT License](LICENSE).
