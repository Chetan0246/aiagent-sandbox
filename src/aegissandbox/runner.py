"""Enforcement Sandbox Runner orchestrating Backends, Egress Proxy, Secrets Broker, and Audit Logging."""

import os
import time
from typing import List, Dict, Optional
from .policy import SandboxPolicy
from .backends.base import BaseBackend, ExecutionResult
from .backends.namespaces import NamespaceBackend
from .backends.container import ContainerBackend
from .backends.kvm import KvmBackend
from .network.proxy import EgressProxyServer
from .network.secrets_broker import SecretsBroker
from .audit import AuditLogger

class SandboxRunner:
    """Executes untrusted agent processes inside a strictly enforced boundary."""

    def __init__(
        self,
        policy: Optional[SandboxPolicy] = None,
        backend_name: str = "namespaces"
    ):
        self.policy = policy or SandboxPolicy()
        self.backend_name = backend_name
        self.backend: BaseBackend = self._init_backend(backend_name)
        self.audit_logger = AuditLogger(self.policy.audit.log_path) if self.policy.audit.enabled else None
        self.secrets_broker = SecretsBroker() if self.policy.secrets.broker_enabled else None
        self.proxy: Optional[EgressProxyServer] = None

    def _init_backend(self, name: str) -> BaseBackend:
        if name == "namespaces":
            return NamespaceBackend()
        elif name == "container":
            return ContainerBackend()
        elif name == "kvm":
            return KvmBackend()
        else:
            raise ValueError(f"Unknown sandbox backend: {name}. Choose from 'namespaces', 'container', 'kvm'.")

    def execute(
        self,
        command: List[str],
        timeout: Optional[float] = None
    ) -> ExecutionResult:
        """Executes a command with all isolation layers, network proxy, and secrets brokering active."""
        env: Dict[str, str] = {}

        # 1. Setup Secrets Broker
        if self.secrets_broker and self.policy.secrets.mapped_tokens:
            for env_var, real_val in self.policy.secrets.mapped_tokens.items():
                self.secrets_broker.register_secret(
                    env_var=env_var,
                    real_secret=real_val,
                    allowed_domains=self.policy.network.allowed_domains
                )
            env.update(self.secrets_broker.get_agent_environment())

        # 2. Setup Egress Allowlist Proxy
        proxy_port = self.policy.network.proxy_port or 8080
        if self.policy.network.mode == "allowlist-proxy":
            def audit_cb(host, port, verdict, method):
                if self.audit_logger:
                    self.audit_logger.log_egress(host, port, verdict, method)

            self.proxy = EgressProxyServer(
                port=proxy_port,
                allowed_domains=self.policy.network.allowed_domains,
                audit_callback=audit_cb
            )
            self.proxy.start()
            proxy_url = f"http://127.0.0.1:{proxy_port}"
            env["HTTP_PROXY"] = proxy_url
            env["HTTPS_PROXY"] = proxy_url
            env["http_proxy"] = proxy_url
            env["https_proxy"] = proxy_url
            time.sleep(0.1)

        # 3. Setup and execute inside backend
        try:
            self.backend.setup(self.policy)
            res = self.backend.run(command, self.policy, env=env, timeout=timeout)
        finally:
            if self.proxy:
                self.proxy.stop()
                self.proxy = None
            self.backend.teardown()

        # 4. Record audit event
        if self.audit_logger:
            cmd_str = " ".join(command)
            self.audit_logger.log_command(
                command=cmd_str,
                returncode=res.returncode,
                duration_ms=res.duration_ms,
                backend=self.backend_name,
                violation=res.violation_detected
            )

        return res
