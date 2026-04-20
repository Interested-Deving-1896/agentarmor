"""Layer 4: Reasoning & Planning Security — action plan validation, policy enforcement."""
from __future__ import annotations

from typing import Any

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import PlanningConfig
from agentarmor.core.types import ActionCategory, AgentEvent, LayerResult, RiskScore, SecurityVerdict, ThreatLevel
from agentarmor.layers.planning.target_sensitivity import compute_composite_score, get_target_multiplier

ACTION_RISK_MAP: dict[str, ActionCategory] = {
    "read": ActionCategory.READ, "get": ActionCategory.READ, "list": ActionCategory.READ,
    "search": ActionCategory.READ, "query": ActionCategory.READ, "fetch": ActionCategory.READ,
    "write": ActionCategory.WRITE, "create": ActionCategory.WRITE, "update": ActionCategory.WRITE,
    "insert": ActionCategory.WRITE, "put": ActionCategory.WRITE,
    "delete": ActionCategory.DELETE, "drop": ActionCategory.DELETE,
    "remove": ActionCategory.DELETE, "truncate": ActionCategory.DELETE,
    "execute": ActionCategory.EXECUTE, "run": ActionCategory.EXECUTE,
    "eval": ActionCategory.EXECUTE, "shell": ActionCategory.EXECUTE,
    "send": ActionCategory.TRANSFER, "transfer": ActionCategory.TRANSFER, "pay": ActionCategory.TRANSFER,
    "email": ActionCategory.COMMUNICATE, "message": ActionCategory.COMMUNICATE, "post": ActionCategory.COMMUNICATE,
    "grant": ActionCategory.ADMIN, "revoke": ActionCategory.ADMIN,
    "chmod": ActionCategory.ADMIN, "admin": ActionCategory.ADMIN,
}
CATEGORY_RISK: dict[ActionCategory, int] = {
    ActionCategory.READ: 1, ActionCategory.WRITE: 3, ActionCategory.COMMUNICATE: 4,
    ActionCategory.TRANSFER: 5, ActionCategory.DELETE: 7, ActionCategory.EXECUTE: 8, ActionCategory.ADMIN: 10,
}


class PlanningLayer(SecurityLayer):
    name = "L4_planning"

    def __init__(self, config: PlanningConfig | None = None):
        self.config = config or PlanningConfig()
        self._output_schemas: dict[str, dict] = {}

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")
        action = event.action
        findings: list[str] = []

        if self.config.denied_actions:
            if action in self.config.denied_actions:
                return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.HIGH,
                    message=f"Action '{action}' is explicitly denied")
            for denied in self.config.denied_actions:
                if denied.endswith("*") and action.startswith(denied[:-1]):
                    return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.HIGH,
                        message=f"Action '{action}' matches denied pattern '{denied}'")

        if self.config.allowed_actions:
            allowed = any(
                perm == action or (perm.endswith("*") and action.startswith(perm[:-1]))
                for perm in self.config.allowed_actions
            )
            if not allowed:
                return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.MEDIUM,
                    message=f"Action '{action}' not in allowed list")

        category = self._categorize_action(action)
        verb_score = CATEGORY_RISK.get(category, 5)
        target_multiplier = get_target_multiplier(event.params)
        composite_score = compute_composite_score(verb_score, event.params)
        risk = RiskScore.build(verb_score, target_multiplier)

        event.metadata["action_category"] = category.value
        event.metadata["risk_score"] = verb_score
        event.metadata["composite_score"] = composite_score
        event.metadata["risk_assessment"] = risk.model_dump()

        if composite_score >= 7:
            findings.append(
                f"High-risk action: {category.value} "
                f"(composite={composite_score:.1f}, verb={verb_score}, target_mult={target_multiplier:.1f})"
            )

        chain_depth = event.context.get("chain_depth", 0)
        if chain_depth > self.config.max_chain_depth:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.HIGH,
                message=f"Chain depth {chain_depth} exceeds max {self.config.max_chain_depth}")

        plan = event.context.get("plan", [])
        if self.config.require_plan_validation and plan:
            findings.extend(self._validate_plan(plan))

        verdict = SecurityVerdict.ALLOW
        threat = ThreatLevel.NONE
        if findings:
            if composite_score >= 8:       # High composite — hard deny
                verdict = SecurityVerdict.DENY
                threat = ThreatLevel.HIGH
            elif composite_score >= 7:     # Elevated composite — escalate, require human approval
                verdict = SecurityVerdict.ESCALATE
                threat = ThreatLevel.HIGH
            else:                          # Lower composite — audit trail only
                verdict = SecurityVerdict.AUDIT
                threat = ThreatLevel.MEDIUM

        return LayerResult(layer=self.name, verdict=verdict, threat_level=threat,
            message="; ".join(findings) if findings else "Plan validation passed",
            details={
                "category": category.value,
                "risk_score": verb_score,
                "composite_score": composite_score,
                "target_multiplier": target_multiplier,
                "sensitive_target": risk.sensitive_target,
            })

    def register_output_schema(self, action: str, schema: dict) -> None:
        self._output_schemas[action] = schema

    def _categorize_action(self, action: str) -> ActionCategory:
        action_lower = action.lower()
        for keyword, category in ACTION_RISK_MAP.items():
            if keyword in action_lower:
                return category
        parts = action_lower.replace("_", ".").replace("-", ".").split(".")
        for part in parts:
            if part in ACTION_RISK_MAP:
                return ACTION_RISK_MAP[part]
        return ActionCategory.READ

    def _validate_plan(self, plan: list[dict[str, Any]]) -> list[str]:
        issues = []
        deletes = sum(1 for s in plan if self._categorize_action(s.get("action", "")) == ActionCategory.DELETE)
        transfers = sum(1 for s in plan if self._categorize_action(s.get("action", "")) == ActionCategory.TRANSFER)
        if deletes > 3:
            issues.append(f"Plan has {deletes} delete ops — bulk deletion risk")
        if transfers > 2:
            issues.append(f"Plan has {transfers} transfer ops — bulk transfer risk")
        return issues
