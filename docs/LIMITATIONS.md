# Technical Limitations and Architectural Trade-Offs

Security engineering requires clear technical boundaries. No isolation system solves all security challenges without operational trade-offs. This document transparently records the architectural boundaries, edge cases, and known limitations of the Aegis sandbox suite.

---

## 1. Shared-Kernel Isolation vs. Hardware Virtualization

Aegis provides both software containment (Linux User Namespaces via Bubblewrap and Rootless OCI Containers via Podman) and hardware containment (Dedicated KVM/QEMU Virtual Machines).

* **Software Isolation Vulnerability Window**:
  Namespaces and containers share the host Linux kernel. While seccomp filters block dangerous system calls (`ptrace`, `bpf`, `kexec_load`, `mount`), the kernel attack surface remains substantial (~450 system calls). Any zero-day vulnerability in kernel subsystems exposed to unprivileged user namespaces (e.g., historical bugs in `io_uring`, `netfilter`, or `overlayfs`) can allow a sophisticated attacker to break out of software containers directly into host Ring 0.
* **Production Recommendation**:
  Software namespaces are optimized for low-latency (< 10 ms), high-density ephemeral tasks where the threat model assumes honest-but-buggy or mildly adversarial agents. For fully untrusted multi-tenant workloads, **only Hardware Virtualization (KVM/QEMU) provides hardware-enforced Ring -1 CPU instruction boundaries**.

---

## 2. Network Proxy and Covert Exfiltration Channels

* **Environment Variable Reliance in Standard Networking**:
  The default-deny egress proxy operates by setting `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` environment variables in the agent workspace. Standard tools (`curl`, `pip`, `npm`, `requests`, `httpx`) respect these variables. However:
  * An attacker who compiles a custom binary or uses raw sockets (`AF_INET`, `SOCK_RAW`) can transmit packets directly without consulting proxy variables unless the network namespace is set to `none` (`policy.network.mode: none`) or bounded by kernel `nftables`/`iptables` redirect rules.
* **TLS Payload Blindness (SNI Only)**:
  The Aegis proxy implements HTTP tunneling via the HTTP `CONNECT` verb. It validates destination hosts at the TCP/SNI handshake level before establishing an end-to-end TLS pipe.
  * **Limitation**: The proxy does not perform Man-in-the-Middle (MITM) deep packet payload inspection because doing so requires injecting a custom trusted Certificate Authority (CA) root into every agent toolchain. As a result, the proxy verifies *where* the agent connects, but cannot inspect encrypted payload bodies transmitted over allowed TLS sessions.
* **DNS and Out-of-Band Tunneling**:
  If DNS resolution (`port 53 UDP`) is permitted on the network interface, an adversary can encode stolen information in DNS query subdomains (e.g., `exfil.<base64-secret>.attacker.com`). Complete exfiltration prevention requires either total network disconnection (`--network=none`) or routing all DNS queries through a logging resolver.

---

## 3. Secrets Broker Scope and Semantic Abuse

* **Surrogate Token Swapping Scope**:
  The secrets broker ensures that real credentials (`sk-live-...`) never enter the agent's process memory or shell environment. Instead, surrogate tokens are provided and swapped in-flight when requests are dispatched to allowed endpoints (e.g., `api.openai.com`).
* **Semantic Data Abuse Limitation**:
  If an adversary compromises an agent and instructs it to send sensitive local source code to an *allowlisted* domain (for example, asking OpenAI to "summarize" stolen proprietary data), the broker permits the request because `api.openai.com` is an allowed destination. The secrets broker prevents *credential theft to third-party infrastructure*; it does not evaluate whether the *content* sent to legitimate APIs constitutes an unauthorized data leak.

---

## 4. Hypervisor Host Proximity on Default Virtual Bridges

* **Virtual Bridge Gateway (`virbr0`)**:
  In libvirt KVM environments utilizing standard NAT networking, the host machine is assigned an internal gateway IP (typically `192.168.122.1`).
* **Risk**:
  Unless explicit host-level firewall rules (`nftables` or `iptables`) are configured on the hypervisor to drop traffic originating from guest interfaces targeting the host loopback or local ports, an agent inside the VM can scan and interact with unauthenticated services listening on `0.0.0.0` on the host machine.
* **Mitigation**:
  Aegis includes automated gateway port probes (`aegis probe --gateway 192.168.122.1`) to audit this boundary, but network administrators must deploy explicit hypervisor filtering rules.

---

## 5. Filesystem Immutability vs. Agent Productivity

* **Read-Only Root Constraints**:
  Enforcing `--read-only` or `--ro-bind / /` guarantees that an agent cannot tamper with system libraries, drop rootkits, or modify login configurations.
* **Trade-Off**:
  Autonomous coding agents frequently need to install build dependencies (e.g., `npm install`, `pip install`, `apt-get`). If an agent requires system package installation, it must be granted either:
  1. An ephemeral copy-on-write `overlayfs` layer that is discarded when the sandbox terminates, or
  2. A pre-baked container image/VM disk containing all required development toolchains.
  Allowing in-place mutable system package installation inherently degrades immutability guarantees.

---

## 6. Performance and Density Overhead

| Backend | Startup Latency | Memory Overhead per Instance | Host Density (16GB RAM Node) |
| :--- | :--- | :--- | :--- |
| **Namespaces (`bwrap`)** | ~7 ms | < 1 MB | ~1,000+ concurrent instances |
| **Containers (`podman`)** | ~160 ms | ~14 MB | ~200 – 400 instances |
| **Hardware VM (`kvm`)** | ~116 ms (warm) / 3 s (cold) | ~180 MB | ~40 – 60 instances |

* **Hardware Cost**: Deploying hardware VMs for millions of micro-agent tasks is economically and computationally prohibitive compared to user namespaces. Security architects must choose the appropriate backend according to workload risk profiles.
