"""Scoped Secrets Broker and Header Token Swapper for AI Sandboxes."""

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class BrokeredSecret:
    env_var: str
    real_secret: str
    surrogate_token: str
    allowed_domains: List[str] = field(default_factory=list)

class SecretsBroker:
    """Manages real API keys and injects scoped surrogate tokens into agent sandboxes."""

    def __init__(self):
        self._secrets_by_surrogate: Dict[str, BrokeredSecret] = {}
        self._secrets_by_env: Dict[str, BrokeredSecret] = {}

    def register_secret(
        self,
        env_var: str,
        real_secret: str,
        allowed_domains: Optional[List[str]] = None
    ) -> str:
        """Registers a real secret and generates a cryptographically random surrogate token."""
        random_suffix = secrets.token_hex(16)
        surrogate = f"aegis-surrogate-{env_var.lower()}-{random_suffix}"
        
        record = BrokeredSecret(
            env_var=env_var,
            real_secret=real_secret,
            surrogate_token=surrogate,
            allowed_domains=allowed_domains or []
        )
        self._secrets_by_surrogate[surrogate] = record
        self._secrets_by_env[env_var] = record
        return surrogate

    def get_agent_environment(self) -> Dict[str, str]:
        """Returns environment dictionary containing ONLY surrogate tokens."""
        return {env_var: item.surrogate_token for env_var, item in self._secrets_by_env.items()}

    def swap_authorization_header(self, auth_header_value: str, target_domain: str) -> str:
        """Substitutes a surrogate token with the real secret if the destination domain is authorized."""
        for surrogate, record in self._secrets_by_surrogate.items():
            if surrogate in auth_header_value:
                # Validate domain scope
                if not record.allowed_domains or any(target_domain.endswith(d) for d in record.allowed_domains):
                    return auth_header_value.replace(surrogate, record.real_secret)
        return auth_header_value
