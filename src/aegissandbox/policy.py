"""Declarative Sandbox Policy Schema and YAML Loader."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Union
import yaml

@dataclass
class ResourceConfig:
    memory_max: str = "384M"
    memory_swap_max: str = "0"
    tasks_max: int = 100
    cpu_quota: str = "80%"

@dataclass
class SecurityConfig:
    seccomp_profile: str = "strict"
    drop_capabilities: List[str] = field(default_factory=lambda: [
        "CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE"
    ])
    read_only_root: bool = True
    ephemeral_dirs: List[str] = field(default_factory=lambda: ["/tmp", "/var/tmp"])

@dataclass
class NetworkConfig:
    mode: str = "allowlist-proxy"  # "none", "host", "allowlist-proxy"
    proxy_port: int = 8080
    allowed_domains: List[str] = field(default_factory=lambda: [
        "api.openai.com", "api.anthropic.com", "huggingface.co", "deb.debian.org"
    ])

@dataclass
class SecretsConfig:
    broker_enabled: bool = True
    mapped_tokens: Dict[str, str] = field(default_factory=dict)

@dataclass
class AuditConfig:
    enabled: bool = True
    log_path: str = "audit.jsonl"

@dataclass
class SandboxPolicy:
    version: str = "1.0"
    name: str = "default-sandbox"
    description: str = ""
    resources: ResourceConfig = field(default_factory=ResourceConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)

    @classmethod
    def from_yaml(cls, path_or_stream: Union[str, Path]) -> "SandboxPolicy":
        raw = {}
        p = Path(path_or_stream) if isinstance(path_or_stream, (str, Path)) else None
        
        # Check if it is an existing file
        if p and p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    raw = loaded
        elif isinstance(path_or_stream, str):
            # Check if it is a path relative to repository root
            repo_path = Path(__file__).resolve().parent.parent.parent / path_or_stream
            if repo_path.is_file():
                with open(repo_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        raw = loaded
            else:
                loaded = yaml.safe_load(path_or_stream)
                if isinstance(loaded, dict):
                    raw = loaded

        return cls(
            version=str(raw.get("version", "1.0")),
            name=raw.get("name", "unnamed-policy"),
            description=raw.get("description", ""),
            resources=ResourceConfig(**raw.get("resources", {})),
            security=SecurityConfig(**raw.get("security", {})),
            network=NetworkConfig(**raw.get("network", {})),
            secrets=SecretsConfig(**raw.get("secrets", {})),
            audit=AuditConfig(**raw.get("audit", {}))
        )

    def to_yaml(self) -> str:
        data = {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "resources": self.resources.__dict__,
            "security": self.security.__dict__,
            "network": self.network.__dict__,
            "secrets": self.secrets.__dict__,
            "audit": self.audit.__dict__,
        }
        return yaml.dump(data, sort_keys=False)
