"""Core type definitions for AgentArmor."""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SecurityVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    ESCALATE = "escalate"
    AUDIT = "audit"


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class ActionCategory(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    TRANSFER = "transfer"
    COMMUNICATE = "communicate"
    ADMIN = "admin"


class AgentEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    agent_id: str
    session_id: str = ""
    layer: str = ""
    event_type: str
    action: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    input_data: Any = None
    output_data: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class LayerResult(BaseModel):
    layer: str
    verdict: SecurityVerdict
    threat_level: ThreatLevel = ThreatLevel.NONE
    message: str = ""
    modified_data: Any = None
    details: dict[str, Any] = Field(default_factory=dict)
    processing_time_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.verdict == SecurityVerdict.DENY

    @property
    def needs_approval(self) -> bool:
        return self.verdict == SecurityVerdict.ESCALATE


class PipelineResult(BaseModel):
    event: AgentEvent
    layer_results: list[LayerResult] = Field(default_factory=list)
    final_verdict: SecurityVerdict = SecurityVerdict.ALLOW
    final_threat_level: ThreatLevel = ThreatLevel.NONE
    blocked_by: str | None = None
    total_processing_time_ms: float = 0.0

    @property
    def is_safe(self) -> bool:
        return self.final_verdict in (SecurityVerdict.ALLOW, SecurityVerdict.MODIFY, SecurityVerdict.AUDIT)
