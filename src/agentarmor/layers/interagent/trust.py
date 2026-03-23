"""Layer 7: Inter-Agent Communication Security — mutual auth, trust scoring, message validation."""

from __future__ import annotations

import datetime
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


class TrustRecord(BaseModel):
    """Per-agent trust state with timestamp for decay computation."""

    trust_score: float = 0.5
    last_interaction_timestamp: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    interaction_count: int = 0


class TrustScorer:
    """Computes and maintains trust scores for agent-to-agent interactions.

    Trust decays over time when agents are dormant.  ``get_score`` computes
    the *effective* trust on every read using::

        effective_trust = stored_trust × (decay_rate ** days_since_last_interaction)

    The decayed value is **not** persisted — only actual interactions (via
    ``update``) write to the trust record.
    """

    def __init__(self, min_trust: float = 0.7, decay_rate: float = 0.99):
        self._records: dict[str, TrustRecord] = {}
        self._interactions: dict[str, list[dict[str, Any]]] = {}
        self.min_trust = min_trust
        self.decay_rate = decay_rate

        # Legacy alias kept for backward compatibility with existing tests
        # that directly mutate ``scorer._scores``.
        self._scores: _ScoresProxy = _ScoresProxy(self)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_score(self, agent_id: str) -> float:
        """Return effective trust after applying time-based decay."""
        record = self._records.get(agent_id)
        if record is None:
            return 0.5  # Default: neutral

        days_since = self._days_since_last_interaction(record)
        effective = record.trust_score * (self.decay_rate ** days_since)
        return max(0.0, min(1.0, effective))

    def update(self, agent_id: str, success: bool, details: str = "") -> float:
        """Update trust based on an interaction outcome and refresh the timestamp."""
        record = self._records.get(agent_id)
        if record is None:
            record = TrustRecord()
            self._records[agent_id] = record

        if success:
            new_score = min(1.0, record.trust_score + 0.05)
        else:
            new_score = max(0.0, record.trust_score - 0.15)

        record.trust_score = new_score
        record.last_interaction_timestamp = datetime.datetime.now(datetime.timezone.utc)
        record.interaction_count += 1

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

    def get_trust_debug_info(self, agent_id: str) -> dict[str, Any]:
        """Return a debug / analytics snapshot for *agent_id*."""
        record = self._records.get(agent_id)
        if record is None:
            return {
                "agent_id": agent_id,
                "stored_trust": 0.5,
                "effective_trust": 0.5,
                "days_since_last_interaction": 0,
                "decay_applied": 1.0,
                "interaction_count": 0,
            }
        days_since = self._days_since_last_interaction(record)
        decay_applied = self.decay_rate ** days_since
        return {
            "agent_id": agent_id,
            "stored_trust": record.trust_score,
            "effective_trust": max(0.0, min(1.0, record.trust_score * decay_applied)),
            "days_since_last_interaction": days_since,
            "decay_applied": decay_applied,
            "interaction_count": record.interaction_count,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _days_since_last_interaction(record: TrustRecord) -> int:
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = now - record.last_interaction_timestamp
        return max(0, delta.days)


class _ScoresProxy:
    """Thin proxy so existing code using ``scorer._scores[agent_id] = x`` still works.

    Reads/writes are transparently forwarded to the underlying ``_records``
    dict, creating a ``TrustRecord`` on first write.
    """

    def __init__(self, scorer: TrustScorer):
        self._scorer = scorer

    def __setitem__(self, agent_id: str, value: float) -> None:
        record = self._scorer._records.get(agent_id)
        if record is None:
            record = TrustRecord(trust_score=value)
            self._scorer._records[agent_id] = record
        else:
            record.trust_score = value

    def __getitem__(self, agent_id: str) -> float:
        record = self._scorer._records.get(agent_id)
        if record is None:
            raise KeyError(agent_id)
        return record.trust_score

    def get(self, agent_id: str, default: float = 0.5) -> float:
        record = self._scorer._records.get(agent_id)
        if record is None:
            return default
        return record.trust_score


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
