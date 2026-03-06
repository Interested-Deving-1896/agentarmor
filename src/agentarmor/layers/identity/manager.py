"""Layer 8: Identity & Access Security — workload identity, JIT permissions, credential rotation."""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any

from pydantic import BaseModel, Field

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import IdentityConfig
from agentarmor.core.exceptions import AuthenticationError
from agentarmor.core.types import (
    AgentEvent,
    LayerResult,
    SecurityVerdict,
    ThreatLevel,
)


class AgentIdentity(BaseModel):
    """Represents a registered agent's identity."""
    agent_id: str
    agent_type: str = "general"
    owner: str = ""
    created_at: float = Field(default_factory=time.time)
    permissions: set[str] = Field(default_factory=set)
    active_permissions: set[str] = Field(default_factory=set)  # JIT-granted
    jit_expiry: dict[str, float] = Field(default_factory=dict)
    credential_hash: str = ""
    credential_expires_at: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    sbom: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_credential_expired(self) -> bool:
        return self.credential_expires_at > 0 and time.time() > self.credential_expires_at


class PermissionGrant(BaseModel):
    """A just-in-time permission grant."""
    permission: str
    granted_at: float = Field(default_factory=time.time)
    expires_at: float = 0.0
    reason: str = ""
    granted_by: str = ""


class IdentityLayer(SecurityLayer):
    """Layer 8: Manages agent identity, credentials, and just-in-time permissions."""

    name = "L8_identity"

    def __init__(self, config: IdentityConfig | None = None):
        self.config = config or IdentityConfig()
        self._identities: dict[str, AgentIdentity] = {}
        self._audit_log: list[dict[str, Any]] = []

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")

        agent_id = event.agent_id
        identity = self._identities.get(agent_id)

        if not identity:
            return LayerResult(
                layer=self.name, verdict=SecurityVerdict.DENY,
                threat_level=ThreatLevel.HIGH,
                message=f"Unknown agent identity: '{agent_id}'",
            )

        # Credential check
        if identity.is_credential_expired:
            return LayerResult(
                layer=self.name, verdict=SecurityVerdict.DENY,
                threat_level=ThreatLevel.HIGH,
                message=f"Agent '{agent_id}' credentials have expired",
            )

        # Permission check
        required_perm = event.metadata.get("required_permission", event.action)
        if required_perm:
            self._cleanup_expired_jit(identity)
            has_base = required_perm in identity.permissions
            has_jit = required_perm in identity.active_permissions
            has_wildcard = any(
                p.endswith("*") and required_perm.startswith(p[:-1])
                for p in identity.permissions | identity.active_permissions
            )

            if not (has_base or has_jit or has_wildcard):
                if self.config.jit_permissions:
                    return LayerResult(
                        layer=self.name, verdict=SecurityVerdict.ESCALATE,
                        threat_level=ThreatLevel.MEDIUM,
                        message=f"Agent '{agent_id}' needs JIT permission for '{required_perm}'",
                        details={"required_permission": required_perm},
                    )
                return LayerResult(
                    layer=self.name, verdict=SecurityVerdict.DENY,
                    threat_level=ThreatLevel.HIGH,
                    message=f"Agent '{agent_id}' lacks permission '{required_perm}'",
                )

        self._log_access(agent_id, event.action, "allowed")
        return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Identity verified")

    def register_agent(
        self,
        agent_id: str,
        agent_type: str = "general",
        owner: str = "",
        permissions: set[str] | None = None,
        credential_ttl: int | None = None,
        sbom: dict[str, Any] | None = None,
    ) -> tuple[AgentIdentity, str]:
        """Register an agent and return (identity, credential_token)."""
        credential = secrets.token_hex(32)
        credential_hash = hashlib.sha256(credential.encode()).hexdigest()
        ttl = credential_ttl or self.config.credential_ttl_seconds

        identity = AgentIdentity(
            agent_id=agent_id,
            agent_type=agent_type,
            owner=owner,
            permissions=permissions or set(),
            credential_hash=credential_hash,
            credential_expires_at=time.time() + ttl if ttl > 0 else 0,
            sbom=sbom or {},
        )
        self._identities[agent_id] = identity
        self._log_access(agent_id, "register", "registered")
        return identity, credential

    def grant_jit_permission(
        self, agent_id: str, permission: str, ttl_seconds: int = 300, reason: str = ""
    ) -> PermissionGrant:
        """Grant a just-in-time permission to an agent."""
        identity = self._identities.get(agent_id)
        if not identity:
            raise AuthenticationError(f"Unknown agent: {agent_id}")

        identity.active_permissions.add(permission)
        identity.jit_expiry[permission] = time.time() + ttl_seconds

        grant = PermissionGrant(
            permission=permission,
            expires_at=time.time() + ttl_seconds,
            reason=reason,
        )
        self._log_access(agent_id, f"jit_grant:{permission}", reason)
        return grant

    def revoke_jit_permission(self, agent_id: str, permission: str) -> None:
        identity = self._identities.get(agent_id)
        if identity:
            identity.active_permissions.discard(permission)
            identity.jit_expiry.pop(permission, None)
            self._log_access(agent_id, f"jit_revoke:{permission}", "revoked")

    def rotate_credential(self, agent_id: str) -> str:
        """Rotate an agent's credential. Returns the new token."""
        identity = self._identities.get(agent_id)
        if not identity:
            raise AuthenticationError(f"Unknown agent: {agent_id}")

        new_credential = secrets.token_hex(32)
        identity.credential_hash = hashlib.sha256(new_credential.encode()).hexdigest()
        identity.credential_expires_at = time.time() + self.config.credential_ttl_seconds
        self._log_access(agent_id, "credential_rotation", "rotated")
        return new_credential

    def verify_credential(self, agent_id: str, credential: str) -> bool:
        identity = self._identities.get(agent_id)
        if not identity:
            return False
        expected = hashlib.sha256(credential.encode()).hexdigest()
        return secrets.compare_digest(identity.credential_hash, expected)

    def _cleanup_expired_jit(self, identity: AgentIdentity) -> None:
        now = time.time()
        expired = [p for p, exp in identity.jit_expiry.items() if exp < now]
        for p in expired:
            identity.active_permissions.discard(p)
            del identity.jit_expiry[p]

    def _log_access(self, agent_id: str, action: str, detail: str) -> None:
        self._audit_log.append({
            "timestamp": time.time(),
            "agent_id": agent_id,
            "action": action,
            "detail": detail,
        })
