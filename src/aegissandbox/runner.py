"""Enforcement Sandbox Runner orchestrating Backends, Egress Proxy, Secrets Broker, and Audit Logging."""

import time
from typing import Optional

from .audit import AuditLogger
from .backends.base import BaseBackend, ExecutionResult
from .backends.container import ContainerBackend
from .backends.kvm import KvmBackend
from .backends.namespaces import NamespaceBackend
from .network.proxy import EgressProxyServer
from .network.secrets_broker import SecretsBroker
from .policy import SandboxPolicy


class SandboxRunner:
    """Executes untrusted agent processes inside a strictly enforced boundary."""

    def __init__(self, policy: Optional[SandboxPolicy] = None, backend_name: str = "namespaces"):
        self.policy = policy or SandboxPolicy()
        self.backend_name = backend_name
        self.backend: BaseBackend = self._init_backend(backend_name)
        self.audit_logger = (
            AuditLogger(self.policy.audit.log_path) if self.policy.audit.enabled else None
        )
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
            raise ValueError(
                f"Unknown sandbox backend: {name}. Choose from 'namespaces', 'container', 'kvm'."
            )

    def execute(
        self,
        command: list[str],
        timeout: Optional[float] = None,
        env: Optional[dict[str, str]] = None,
    ) -> ExecutionResult:
        """Executes a command with all isolation layers, network proxy, and secrets brokering active."""
        exec_env: dict[str, str] = {}
        if env:
            exec_env.update(env)

        # 1. Setup Secrets Broker
        if self.secrets_broker and self.policy.secrets.mapped_tokens:
            for env_var, real_val in self.policy.secrets.mapped_tokens.items():
                self.secrets_broker.register_secret(
                    env_var=env_var,
                    real_secret=real_val,
                    allowed_domains=self.policy.network.allowed_domains,
                )
            exec_env.update(self.secrets_broker.get_agent_environment())

        # 2. Setup Egress Allowlist Proxy
        proxy_port = self.policy.network.proxy_port or 8080
        if self.policy.network.mode == "allowlist-proxy":

            def audit_cb(host: str, port: int, verdict: str, method: str) -> None:
                if self.audit_logger:
                    self.audit_logger.log_egress(host, port, verdict, method)

            self.proxy = EgressProxyServer(
                port=proxy_port,
                allowed_domains=self.policy.network.allowed_domains,
                audit_callback=audit_cb,
            )
            self.proxy.start()
            proxy_url = f"http://127.0.0.1:{proxy_port}"
            exec_env["HTTP_PROXY"] = proxy_url
            exec_env["HTTPS_PROXY"] = proxy_url
            exec_env["http_proxy"] = proxy_url
            exec_env["https_proxy"] = proxy_url
            time.sleep(0.1)

        # 3. Setup and execute inside backend
        try:
            self.backend.setup(self.policy)
            res = self.backend.run(command, self.policy, env=exec_env, timeout=timeout)
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
                violation=res.violation_detected,
            )

        return res
