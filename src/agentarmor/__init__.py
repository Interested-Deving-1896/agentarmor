"""AgentArmor — Comprehensive security framework for agentic AI applications."""

from agentarmor.core.config import ArmorConfig
from agentarmor.core.exceptions import (
    AgentArmorError,
    AuthenticationError,
    EncryptionError,
    PolicyViolationError,
    RateLimitError,
)
from agentarmor.core.types import (
    ActionCategory,
    AgentEvent,
    DataClassification,
    LayerResult,
    PipelineResult,
    SecurityVerdict,
    ThreatLevel,
)
from agentarmor.integrations.mcp import MCPGuard, MCPScanReport
from agentarmor.integrations.mcp.oauth_verifier import OAuthVerifier
from agentarmor.integrations.mcp.tls_validator import TLSValidator
from agentarmor.integrations.openclaw import OpenClawGuard
from agentarmor.pipeline import AgentArmor
from agentarmor.policy.engine import PolicyEngine, SecurityPolicy

__version__ = "0.3.0"

__all__ = [
    "AgentArmor",
    "ArmorConfig",
    "SecurityPolicy",
    "PolicyEngine",
    "AgentEvent",
    "LayerResult",
    "PipelineResult",
    "SecurityVerdict",
    "ThreatLevel",
    "DataClassification",
    "ActionCategory",
    "AgentArmorError",
    "PolicyViolationError",
    "EncryptionError",
    "AuthenticationError",
    "RateLimitError",
    "OpenClawGuard",
    "MCPGuard",
    "MCPScanReport",
    "TLSValidator",
    "OAuthVerifier",
]
