"""Layer 7: Inter-Agent Communication Security — mutual auth, trust scoring, message validation."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any

from pydantic import BaseModel, Field

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import InterAgentConfig
from agentarmor.core.exceptions import AuthenticationError
from agentarmor.core.types import (
    AgentEvent,
    LayerResult,
    SecurityVerdict,
    ThreatLevel,
)


class AgentCredential(BaseModel):
    """Represents an agent's communication credential."""
    agent_id: str
    shared_secret: str = Field(default_factory=lambda: secrets.token_hex(32))
    created_at: float = Field(default_factory=time.time)
    expires_at: float = 0.0
    trust_score: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at


class TrustScorer:
    """Computes and maintains trust scores for agent-to-agent interactions."""

    def __init__(self, min_trust: float = 0.7, decay_rate: float = 0.01):
        self._scores: dict[str, float] = {}
        self._interactions: dict[str, list[dict[str, Any]]] = {}
        self.min_trust = min_trust
        self.decay_rate = decay_rate

    def get_score(self, agent_id: str) -> float:
        return self._scores.get(agent_id, 0.5)  # Default: neutral

    def update(self, agent_id: str, success: bool, details: str = "") -> float:
        current = self._scores.get(agent_id, 0.5)
        if success:
            new_score = min(1.0, current + 0.05)
        else:
            new_score = max(0.0, current - 0.15)
        self._scores[agent_id] = new_score
        self._interactions.setdefault(agent_id, []).append({
            "timestamp": time.time(),
            "success": success,
            "details": details,
            "score_after": new_score,
        })
        return new_score

    def is_trusted(self, agent_id: str) -> bool:
        return self.get_score(agent_id) >= self.min_trust

    def get_history(self, agent_id: str) -> list[dict[str, Any]]:
        return self._interactions.get(agent_id, [])


class MessageAuthenticator:
    """HMAC-based message authentication for inter-agent communication."""

    @staticmethod
    def sign(message: str, secret: str) -> str:
        return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify(message: str, secret: str, signature: str) -> bool:
        expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


class InterAgentLayer(SecurityLayer):
    """Layer 7: Secures agent-to-agent communication with auth, trust, and validation."""

    name = "L7_interagent"

    def __init__(self, config: InterAgentConfig | None = None):
        self.config = config or InterAgentConfig()
        self.trust_scorer = TrustScorer(min_trust=self.config.min_trust_score)
        self.authenticator = MessageAuthenticator()
        self._credentials: dict[str, AgentCredential] = {}

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")

        # Only applies to inter-agent events
        if event.event_type not in ("agent_message", "agent_delegate", "agent_response"):
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Not an inter-agent event")

        target_agent = event.params.get("target_agent", "")
        source_agent = event.agent_id
        findings: list[str] = []

        # Mutual authentication
        if self.config.require_mutual_auth:
            signature = event.metadata.get("signature", "")
            message_body = str(event.input_data or "")

            cred = self._credentials.get(source_agent)
            if not cred:
                return LayerResult(
                    layer=self.name, verdict=SecurityVerdict.DENY,
                    threat_level=ThreatLevel.HIGH,
                    message=f"Unknown agent '{source_agent}' — no registered credentials",
                )

            if cred.is_expired:
                return LayerResult(
                    layer=self.name, verdict=SecurityVerdict.DENY,
                    threat_level=ThreatLevel.HIGH,
                    message=f"Agent '{source_agent}' credentials expired",
                )

            if signature and not self.authenticator.verify(message_body, cred.shared_secret, signature):
                self.trust_scorer.update(source_agent, False, "HMAC verification failed")
                return LayerResult(
                    layer=self.name, verdict=SecurityVerdict.DENY,
                    threat_level=ThreatLevel.CRITICAL,
                    message="Message authentication failed — possible tampering",
                )

        # Trust score check
        if self.config.trust_scoring:
            if not self.trust_scorer.is_trusted(source_agent):
                score = self.trust_scorer.get_score(source_agent)
                return LayerResult(
                    layer=self.name, verdict=SecurityVerdict.DENY,
                    threat_level=ThreatLevel.HIGH,
                    message=f"Agent '{source_agent}' trust score too low: {score:.2f} < {self.config.min_trust_score}",
                )

        # Delegation depth check
        delegation_depth = event.context.get("delegation_depth", 0)
        if delegation_depth > self.config.max_delegation_depth:
            return LayerResult(
                layer=self.name, verdict=SecurityVerdict.DENY,
                threat_level=ThreatLevel.HIGH,
                message=f"Delegation depth {delegation_depth} exceeds max {self.config.max_delegation_depth}",
            )

        # Message content validation
        if self.config.message_validation and event.input_data:
            # Check for injection patterns in inter-agent messages
            msg = str(event.input_data)
            if len(msg) > 100_000:
                findings.append("Oversized inter-agent message — potential DoS")

        self.trust_scorer.update(source_agent, True, "Passed all checks")

        if findings:
            return LayerResult(
                layer=self.name, verdict=SecurityVerdict.AUDIT, threat_level=ThreatLevel.LOW,
                message="; ".join(findings),
            )

        return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Inter-agent check passed")

    def register_agent(self, agent_id: str, ttl_seconds: int = 3600) -> AgentCredential:
        """Register an agent and issue credentials."""
        cred = AgentCredential(
            agent_id=agent_id,
            expires_at=time.time() + ttl_seconds if ttl_seconds > 0 else 0,
        )
        self._credentials[agent_id] = cred
        self.trust_scorer._scores[agent_id] = 0.5
        return cred

    def sign_message(self, agent_id: str, message: str) -> str:
        """Sign a message on behalf of a registered agent."""
        cred = self._credentials.get(agent_id)
        if not cred:
            raise AuthenticationError(f"Agent '{agent_id}' not registered")
        return self.authenticator.sign(message, cred.shared_secret)
