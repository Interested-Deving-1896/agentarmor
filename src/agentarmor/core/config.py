"""Configuration management for AgentArmor."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field


class IngestionConfig(BaseModel):
    enabled: bool = True
    scan_for_injection: bool = True
    max_input_size_bytes: int = 10 * 1024 * 1024
    allowed_sources: list[str] = Field(default_factory=list)
    blocked_patterns: list[str] = Field(default_factory=list)
    injection_detection_model: str = "heuristic"


class StorageConfig(BaseModel):
    enabled: bool = True
    encryption: str = "aes-256-gcm"
    encryption_key_env: str = "AGENTARMOR_ENCRYPTION_KEY"
    classification_required: bool = False
    default_classification: str = "internal"
    ttl_seconds: int | None = None
    allowed_namespaces: list[str] = Field(default_factory=list)
    integrity_check: bool = True


class ContextConfig(BaseModel):
    enabled: bool = True
    enforce_instruction_separation: bool = True
    max_context_tokens: int = 128000
    prompt_hardening: bool = True
    canary_tokens: bool = True


class PlanningConfig(BaseModel):
    enabled: bool = True
    allowed_actions: list[str] = Field(default_factory=list)
    denied_actions: list[str] = Field(default_factory=list)
    max_chain_depth: int = 10
    require_plan_validation: bool = True
    output_schema_enforcement: bool = True


class ExecutionConfig(BaseModel):
    enabled: bool = True
    sandbox_enabled: bool = True
    network_egress_allowed: bool = False
    allowed_hosts: list[str] = Field(default_factory=list)
    max_execution_time_seconds: int = 30
    require_human_approval: list[dict[str, Any]] = Field(default_factory=list)
    rate_limits: dict[str, int] = Field(default_factory=dict)


class OutputConfig(BaseModel):
    enabled: bool = True
    pii_redaction: bool = True
    pii_entities: list[str] = Field(
        default_factory=lambda: [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
            "US_SSN", "IBAN_CODE", "IP_ADDRESS",
        ]
    )
    max_output_tokens: int = 16384
    sensitivity_filtering: bool = True
    blocked_keywords: list[str] = Field(default_factory=list)


class InterAgentConfig(BaseModel):
    enabled: bool = True
    require_mutual_auth: bool = True
    encryption: str = "tls-1.3"
    trust_scoring: bool = True
    min_trust_score: float = 0.7
    message_validation: bool = True
    max_delegation_depth: int = 3


class IdentityConfig(BaseModel):
    enabled: bool = True
    credential_ttl_seconds: int = 3600
    credential_rotation: bool = True
    jit_permissions: bool = True
    require_agent_sbom: bool = False
    attestation_enabled: bool = False


class AuditConfig(BaseModel):
    enabled: bool = True
    log_all_events: bool = True
    tamper_proof: bool = True
    otel_enabled: bool = True
    otel_endpoint: str = "http://localhost:4317"
    retention_days: int = 90


class ArmorConfig(BaseModel):
    version: str = "1.0"
    agent_type: str = "general"
    risk_level: str = "medium"
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    planning: PlanningConfig = Field(default_factory=PlanningConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    interagent: InterAgentConfig = Field(default_factory=InterAgentConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ArmorConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArmorConfig":
        return cls(**data)

    def to_yaml(self, path: str | Path) -> None:
        with open(path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)
