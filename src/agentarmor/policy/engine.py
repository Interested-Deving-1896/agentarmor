"""Policy Engine — Declarative, contextual policy evaluation for agent actions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from agentarmor.core.types import AgentEvent, SecurityVerdict


class PolicyRule(BaseModel):
    """A single policy rule that evaluates conditions and produces a verdict."""
    name: str = ""
    description: str = ""
    action_pattern: str = "*"          # Glob pattern for matching actions
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    verdict: SecurityVerdict = SecurityVerdict.DENY
    priority: int = 0                  # Higher priority rules evaluated first
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityPolicy(BaseModel):
    """A complete security policy document."""
    version: str = "1.0"
    name: str = "default"
    description: str = ""
    agent_type: str = "general"
    risk_level: str = "medium"
    rules: list[PolicyRule] = Field(default_factory=list)
    global_denied_actions: list[str] = Field(default_factory=list)
    global_allowed_actions: list[str] = Field(default_factory=list)
    max_chain_depth: int = 10
    require_human_approval_for: list[str] = Field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> SecurityPolicy:
        with open(path) as f:
            data = yaml.safe_load(f)
        rules_data = data.pop("rules", [])
        rules = [PolicyRule(**r) for r in rules_data]
        return cls(rules=rules, **data)

    def to_yaml(self, path: str | Path) -> None:
        data = self.model_dump()
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)


class ConditionEvaluator:
    """Evaluates policy conditions against agent events."""

    @staticmethod
    def evaluate(conditions: list[dict[str, Any]], event: AgentEvent) -> bool:
        """Evaluate all conditions (AND logic). Returns True if all conditions pass."""
        if not conditions:
            return True
        return all(ConditionEvaluator._evaluate_single(cond, event) for cond in conditions)

    @staticmethod
    def _evaluate_single(condition: dict[str, Any], event: AgentEvent) -> bool:
        field = condition.get("field", "")
        operator = condition.get("operator", "==")
        value = condition.get("value")

        # Resolve the actual value from the event
        actual = ConditionEvaluator._resolve_field(field, event)
        if actual is None:
            return condition.get("default", False)

        try:
            if operator == "==":
                return str(actual) == str(value)
            elif operator == "!=":
                return str(actual) != str(value)
            elif operator == ">":
                return float(actual) > float(value)
            elif operator == "<":
                return float(actual) < float(value)
            elif operator == ">=":
                return float(actual) >= float(value)
            elif operator == "<=":
                return float(actual) <= float(value)
            elif operator == "in":
                return str(actual) in value
            elif operator == "not_in":
                return str(actual) not in value
            elif operator == "contains":
                return str(value) in str(actual)
            elif operator == "matches":
                return bool(re.search(str(value), str(actual)))
            elif operator == "exists":
                return actual is not None
        except (ValueError, TypeError):
            return False
        return False

    @staticmethod
    def _resolve_field(field: str, event: AgentEvent) -> Any:
        """Resolve a dotted field path from an AgentEvent."""
        parts = field.split(".")
        obj: Any = event
        for part in parts:
            if isinstance(obj, dict):
                obj = obj.get(part)
            elif isinstance(obj, BaseModel):
                obj = getattr(obj, part, None)
            else:
                try:
                    obj = getattr(obj, part, None)
                except Exception:
                    return None
            if obj is None:
                return None
        return obj


class PolicyEngine:
    """Evaluates agent events against a set of security policies."""

    def __init__(self, policy: SecurityPolicy | None = None):
        self._policy = policy or SecurityPolicy()
        self._evaluator = ConditionEvaluator()

    @property
    def policy(self) -> SecurityPolicy:
        return self._policy

    def load_policy(self, path: str | Path) -> None:
        self._policy = SecurityPolicy.from_yaml(path)

    def evaluate(self, event: AgentEvent) -> tuple[SecurityVerdict, str]:
        """Evaluate an event against the policy. Returns (verdict, reason)."""
        action = event.action

        # Global denied actions
        for denied in self._policy.global_denied_actions:
            if self._match_pattern(denied, action):
                return SecurityVerdict.DENY, f"Action '{action}' is globally denied"

        # Global allowed actions (if specified, non-listed actions are denied)
        if (self._policy.global_allowed_actions
                and not any(self._match_pattern(a, action) for a in self._policy.global_allowed_actions)):
            return SecurityVerdict.DENY, f"Action '{action}' not in global allow list"

        # Human approval required
        for pattern in self._policy.require_human_approval_for:
            if self._match_pattern(pattern, action):
                return SecurityVerdict.ESCALATE, f"Action '{action}' requires human approval"

        # Evaluate rules (sorted by priority, highest first)
        sorted_rules = sorted(
            [r for r in self._policy.rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

        for rule in sorted_rules:
            if not self._match_pattern(rule.action_pattern, action):
                continue
            if self._evaluator.evaluate(rule.conditions, event):
                return rule.verdict, f"Rule '{rule.name}': {rule.description}"

        return SecurityVerdict.ALLOW, "No policy rule matched — default allow"

    @staticmethod
    def _match_pattern(pattern: str, action: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return action.startswith(pattern[:-1])
        if pattern.startswith("*"):
            return action.endswith(pattern[1:])
        return pattern == action
