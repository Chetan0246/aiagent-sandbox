# Aegis-Sandbox Enforcement Runner, Security Broker & Multi-Backend Architecture Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform Aegis-Sandbox from a passive audit tool into an active enforcement execution engine (`aegis run`) featuring declarative YAML policies, multi-backend containment (Namespaces, Podman, KVM), default-deny egress allowlist proxying, scoped secrets brokering, automated GTFOBins sweeping, prompt injection attack harness, and reproducible statistical benchmarking (n ≥ 10).

**Architecture:** A modular backend driver pattern abstracts OS-level containment mechanisms (`bwrap`/namespaces, `podman`/OCI, `kvm`/libvirt) behind an enforcement runner driven by declarative YAML policies. In-flight network calls pass through an asynchronous forwarding HTTP/CONNECT proxy that enforces domain allowlisting and handles secret token swapping, logging every command, file write, and network packet into structured JSONL audit logs. An adversarial corpus tests prompt injection resilience and positive/negative boundary controls.

**Tech Stack:** Python 3.9+, Linux User Namespaces (`bwrap`), Rootless Podman, KVM/QEMU (`virsh`), PyYAML, asyncio HTTP/CONNECT proxy, Seccomp BPF, Systemd Cgroups v2, GitHub Actions.

---

### Task 1: Declarative Policy Schema & Loader
**Files:**
- Create: `src/aegissandbox/policy.py`
- Test: `tests/test_policy.py`
- Create: `configs/policies/strict.yaml`
- Create: `configs/policies/permissive.yaml`

**Step 1: Write the failing test**
```python
import unittest
from aegissandbox.policy import SandboxPolicy

class TestPolicy(unittest.TestCase):
    def test_load_valid_policy(self):
        policy = SandboxPolicy.from_yaml("configs/policies/strict.yaml")
        self.assertEqual(policy.name, "strict-agent-sandbox")
        self.assertEqual(policy.resources.memory_max, "384M")
        self.assertEqual(policy.resources.tasks_max, 100)
        self.assertIn("api.openai.com", policy.network.allowed_domains)
```

**Step 2: Run test to verify it fails**
Run: `python3 -m unittest tests/test_policy.py`
Expected: FAIL (No module named `aegissandbox.policy`)

**Step 3: Implement policy schema and YAML loader**
Implement `SandboxPolicy`, `ResourceConfig`, `SecurityConfig`, `NetworkConfig`, `SecretsConfig` with dataclasses and YAML parsing.

**Step 4: Run test to verify it passes**
Run: `python3 -m unittest tests/test_policy.py`
Expected: PASS

**Step 5: Commit**
```bash
git add src/aegissandbox/policy.py tests/test_policy.py configs/policies/
git commit -m "feat(policy): implement declarative YAML policy loader and schema"
```

---

### Task 2: Abstract Backend Driver Interface
**Files:**
- Create: `src/aegissandbox/backends/__init__.py`
- Create: `src/aegissandbox/backends/base.py`
- Test: `tests/test_backends.py`

**Step 1: Write abstract base class and contract**
Define `BaseBackend` with methods:
- `setup(policy: SandboxPolicy) -> None`
- `run(command: List[str], policy: SandboxPolicy, env: Dict[str, str]) -> ExecutionResult`
- `teardown() -> None`
- `name -> str`

**Step 2: Write tests for execution result data contract**
Assert `ExecutionResult` captures `returncode`, `stdout`, `stderr`, `duration_ms`, `cgroup_peak_memory`, and `violation_detected`.

**Step 3: Commit**
```bash
git add src/aegissandbox/backends/
git commit -m "feat(backends): define abstract backend driver interface and result contract"
```

---

### Task 3: Linux User Namespaces & Bubblewrap Backend
**Files:**
- Create: `src/aegissandbox/backends/namespaces.py`
- Test: `tests/test_backend_namespaces.py`

**Step 1: Write the test**
```python
def test_namespace_execution():
    backend = NamespaceBackend()
    res = backend.run(["whoami"], policy)
    self.assertEqual(res.returncode, 0)
```

**Step 2: Implement `NamespaceBackend`**
Uses `bwrap` to:
- Bind `/` as read-only (`--ro-bind / /`).
- Create ephemeral private `/tmp` (`--tmpfs /tmp`).
- Create new network namespace if `network.mode == "none"` (`--unshare-net`).
- Create new PID and IPC namespaces (`--unshare-pid --unshare-ipc`).
- Drop capabilities.

**Step 3: Run test and verify it passes**
Run: `python3 -m unittest tests/test_backend_namespaces.py`
Expected: PASS

**Step 4: Commit**
```bash
git add src/aegissandbox/backends/namespaces.py tests/test_backend_namespaces.py
git commit -m "feat(backends): implement unprivileged bubblewrap namespace backend"
```

---

### Task 4: Rootless Podman/OCI Container Backend
**Files:**
- Create: `src/aegissandbox/backends/container.py`
- Test: `tests/test_backend_container.py`

**Step 1: Write the test**
Verify container backend compiles command into `podman run --rm --read-only --cap-drop=ALL ...` with appropriate cgroup caps.

**Step 2: Implement `ContainerBackend`**
Executes rootless Podman with `--memory`, `--pids-limit`, `--cap-drop=ALL`, `--network=none` or proxy network, mounting ephemeral tmpfs on `/tmp`.

**Step 3: Run test and verify it passes**
Run: `python3 -m unittest tests/test_backend_container.py`
Expected: PASS

**Step 4: Commit**
```bash
git add src/aegissandbox/backends/container.py tests/test_backend_container.py
git commit -m "feat(backends): implement rootless podman container backend"
```

---

### Task 5: Hardware-Virtual KVM Backend
**Files:**
- Create: `src/aegissandbox/backends/kvm.py`
- Test: `tests/test_backend_kvm.py`

**Step 1: Implement `KvmBackend`**
Executes command inside `debian-minimal` VM over SSH within `user-1001.slice`, enforcing systemd slice overrides and reading live cgroup metrics.

**Step 2: Run test and verify it passes**
Run: `python3 -m unittest tests/test_backend_kvm.py`
Expected: PASS

**Step 3: Commit**
```bash
git add src/aegissandbox/backends/kvm.py tests/test_backend_kvm.py
git commit -m "feat(backends): implement KVM libvirt hardware virtualization backend"
```

---

### Task 6: Forwarding Egress Allowlist Proxy
**Files:**
- Create: `src/aegissandbox/network/__init__.py`
- Create: `src/aegissandbox/network/proxy.py`
- Test: `tests/test_proxy.py`

**Step 1: Write tests for HTTP and HTTPS CONNECT forwarding**
- Allowed domain (`httpbin.org`) -> `200 Connection established`
- Blocked domain (`evil.attacker.com`) -> `403 Forbidden - Aegis Sandbox Egress Blocked`

**Step 2: Implement `EgressProxyServer`**
High-performance asynchronous HTTP/CONNECT proxy supporting domain allowlists, wildcard matching (`*.openai.com`), and audit event logging.

**Step 3: Run test and verify it passes**
Run: `python3 -m unittest tests/test_proxy.py`
Expected: PASS

**Step 4: Commit**
```bash
git add src/aegissandbox/network/ tests/test_proxy.py
git commit -m "feat(network): implement asynchronous egress allowlist proxy"
```

---

### Task 7: Scoped Secrets Broker & Token Swapper
**Files:**
- Create: `src/aegissandbox/network/secrets_broker.py`
- Test: `tests/test_secrets_broker.py`

**Step 1: Write the test**
- Agent sends request with `Authorization: Bearer aegis-token-agentuser-openai`
- Proxy intercepts, validates, replaces with `Authorization: Bearer sk-live-real-secret`
- Agent printing environment variable only sees dummy token.

**Step 2: Implement `SecretsBroker`**
Manages real secrets in-memory in supervisor process, injects scoped surrogate tokens into agent environment, and swaps headers on outbound HTTPS requests.

**Step 3: Run test and verify it passes**
Run: `python3 -m unittest tests/test_secrets_broker.py`
Expected: PASS

**Step 4: Commit**
```bash
git add src/aegissandbox/network/secrets_broker.py tests/test_secrets_broker.py
git commit -m "feat(secrets): implement surrogate token swapping secrets broker"
```

---

### Task 8: Structured JSONL Audit Logger
**Files:**
- Create: `src/aegissandbox/audit.py`
- Test: `tests/test_audit.py`

**Step 1: Implement `AuditLogger`**
Emits structured JSON lines for every command start, completion, egress attempt, block event, and resource threshold breach.

**Step 2: Commit**
```bash
git add src/aegissandbox/audit.py tests/test_audit.py
git commit -m "feat(audit): implement structured JSONL audit logging engine"
```

---

### Task 9: The Enforcement Runner (`aegis run`)
**Files:**
- Create: `src/aegissandbox/runner.py`
- Modify: `src/aegissandbox/cli.py`
- Test: `tests/test_runner.py`

**Step 1: Implement runner orchestrating backend, proxy, broker, and audit**
`aegis run --backend=namespaces --policy=configs/policies/strict.yaml -- python3 -c "print('hello from sandbox')"`

**Step 2: Test CLI integration**
Run: `aegis-sandbox run --backend namespaces -- echo "hello"`
Expected: Output with status header and audit logging.

**Step 3: Commit**
```bash
git add src/aegissandbox/runner.py src/aegissandbox/cli.py tests/test_runner.py
git commit -m "feat(runner): implement aegis run CLI enforcement command"
```

---

### Task 10: Seccomp Profile & Capability Dropping
**Files:**
- Create: `configs/seccomp/strict.json`
- Create: `src/aegissandbox/seccomp.py`
- Test: `tests/test_seccomp.py`

**Step 1: Implement default seccomp profile**
Blocks `ptrace`, `bpf`, `kexec_load`, `reboot`, `mount`, `umount2`, `pivot_root`.

**Step 2: Commit**
```bash
git add configs/seccomp/ src/aegissandbox/seccomp.py tests/test_seccomp.py
git commit -m "feat(security): implement strict BPF seccomp filter and capabilities drops"
```

---

### Task 11: Prompt Injection Adversarial Corpus & Agent Test Harness
**Files:**
- Create: `tests/corpus/malicious_readme.md`
- Create: `tests/corpus/poisoned_tool_output.txt`
- Create: `tests/corpus/poisoned_api_response.json`
- Create: `src/aegissandbox/harness.py`
- Test: `tests/test_harness.py`

**Step 1: Create injection corpus**
Payloads attempting:
1. Data exfiltration of environment tokens to `evil.attacker.com`.
2. Execution of `sudo systemd-run` or `nsenter`.
3. Fork bombs and persistence creation in `~/.bashrc`.

**Step 2: Implement `MockAgentHarness`**
Simulates an LLM agent parsing files and executing tool calls.

**Step 3: Commit**
```bash
git add tests/corpus/ src/aegissandbox/harness.py tests/test_harness.py
git commit -m "feat(testing): add adversarial prompt injection corpus and agent harness"
```

---

### Task 12: Automated GTFOBins Scanner
**Files:**
- Create: `src/aegissandbox/scanner.py`
- Test: `tests/test_scanner.py`

**Step 1: Implement `GTFOBinsScanner`**
Scans all sudoers entries and PATH binaries against GTFOBins privilege escalation signatures.

**Step 2: Commit**
```bash
git add src/aegissandbox/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): add automated GTFOBins binary audit scanner"
```

---

### Task 13: Positive & Negative Control Boundary Probes
**Files:**
- Create: `tests/test_controls.py`

**Step 1: Implement dual control testing**
- Test passes under hardened config.
- Test fails under weakened config (positive control proving the detector works).

**Step 2: Commit**
```bash
git add tests/test_controls.py
git commit -m "test(controls): implement positive and negative control boundary verification"
```

---

### Task 14: Statistical Multi-Backend Benchmark Runner (n ≥ 10)
**Files:**
- Create: `scripts/run_benchmarks.py`
- Output: `benchmark_results.json`

**Step 1: Implement statistical benchmark runner**
- Executes 10 runs per backend (`namespaces`, `container`, `kvm`).
- Measures startup latency, memory overhead, fork ceiling, egress blocking, and recovery time.
- Records median, mean, standard deviation, hardware specs, and kernel version.

**Step 2: Run benchmarks and write `benchmark_results.json`**
Run: `python3 scripts/run_benchmarks.py --runs 10`

**Step 3: Commit**
```bash
git add scripts/run_benchmarks.py benchmark_results.json
git commit -m "feat(benchmarks): add statistical multi-backend benchmark runner (n=10)"
```

---

### Task 15: Automated README Table Generator
**Files:**
- Create: `scripts/generate_docs.py`
- Modify: `README.md`

**Step 1: Implement `generate_docs.py`**
Reads `benchmark_results.json` and updates the markdown tables in `README.md` and `docs/WHITE_PAPER.md`.

**Step 2: Commit**
```bash
git add scripts/generate_docs.py README.md
git commit -m "feat(docs): automate README metrics table generation from benchmark JSON"
```

---

### Task 16: One-Command Reproducibility (IaC & Vagrant)
**Files:**
- Create: `Vagrantfile`
- Create: `scripts/provision.sh`
- Create: `configs/vm/cloud-init.yaml`

**Step 1: Add Vagrant & Cloud-Init provisioning configs**
Allows running `vagrant up` or `./scripts/provision.sh` to spin up the exact Debian 13 KVM sandbox anywhere.

**Step 2: Commit**
```bash
git add Vagrantfile scripts/provision.sh configs/vm/cloud-init.yaml
git commit -m "feat(iac): add Vagrantfile, cloud-init and automated provisioning scripts"
```

---

### Task 17: CI/CD Pipeline & Final Verification
**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Update GitHub Actions workflow**
Runs full unit tests, CLI tests, scanner tests, and mock agent injection harness.

**Step 2: Run full local test suite**
Run: `python3 -m unittest discover -s tests`

**Step 3: Push to GitHub and verify CI passes**
```bash
git push origin main
gh run list --repo Chetan0246/aiagent-sandbox
```
