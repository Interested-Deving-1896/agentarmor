"""Layer 5: Action Execution Security — sandboxing, rate limiting, human approval gates."""
from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import ExecutionConfig
from agentarmor.core.types import AgentEvent, LayerResult, SecurityVerdict, ThreatLevel


class RateLimiter:
    def __init__(self, limits: dict[str, int] | None = None, window_seconds: int = 60):
        self._limits = limits or {}
        self._window = window_seconds
        self._events: dict[str, list[float]] = defaultdict(list)

    def check(self, action: str) -> bool:
        limit = self._get_limit(action)
        if limit is None:
            return True
        now = time.time()
        events = self._events[action]
        events[:] = [t for t in events if now - t < self._window]
        return len(events) < limit

    def record(self, action: str) -> None:
        self._events[action].append(time.time())

    def _get_limit(self, action: str) -> int | None:
        if action in self._limits:
            return self._limits[action]
        for pattern, limit in self._limits.items():
            if pattern.endswith("*") and action.startswith(pattern[:-1]):
                return limit
        return self._limits.get("*")

    def get_remaining(self, action: str) -> int | None:
        limit = self._get_limit(action)
        if limit is None:
            return None
        now = time.time()
        events = [t for t in self._events[action] if now - t < self._window]
        return max(0, limit - len(events))


class ApprovalGate:
    def __init__(self, rules: list[dict[str, Any]] | None = None):
        self._rules = rules or []
        self._approval_callback: Callable[[AgentEvent], Awaitable[bool]] | None = None

    def set_callback(self, callback: Callable[[AgentEvent], Awaitable[bool]]) -> None:
        self._approval_callback = callback

    def requires_approval(self, event: AgentEvent) -> bool:
        for rule in self._rules:
            rule_action = rule.get("action", "")
            condition = rule.get("condition", "")
            if rule_action and rule_action != event.action:
                if not (rule_action.endswith("*") and event.action.startswith(rule_action[:-1])):
                    continue
            if condition:
                if self._evaluate_condition(condition, event):
                    return True
            elif rule_action:
                return True
        return False

    async def request_approval(self, event: AgentEvent) -> bool:
        if self._approval_callback:
            return await self._approval_callback(event)
        return False

    def _evaluate_condition(self, condition: str, event: AgentEvent) -> bool:
        try:
            parts = condition.split()
            if len(parts) == 3:
                field, op, value = parts
                actual = event.params.get(field, event.context.get(field))
                if actual is None:
                    return False
                if op == ">": return float(actual) > float(value)
                elif op == "<": return float(actual) < float(value)
                elif op == "==": return str(actual) == value
                elif op == "!=": return str(actual) != value
        except (ValueError, TypeError):
            pass
        return False


class NetworkPolicy:
    def __init__(self, egress_allowed: bool = False, allowed_hosts: list[str] | None = None):
        self.egress_allowed = egress_allowed
        self.allowed_hosts = set(allowed_hosts or [])

    def check_url(self, url: str) -> bool:
        if not self.egress_allowed:
            return False
        if not self.allowed_hosts:
            return self.egress_allowed
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            return any(host == a or host.endswith(f".{a}") for a in self.allowed_hosts)
        except Exception:
            return False


class ExecutionLayer(SecurityLayer):
    name = "L5_execution"

    def __init__(self, config: ExecutionConfig | None = None):
        self.config = config or ExecutionConfig()
        self.rate_limiter = RateLimiter(limits=self.config.rate_limits, window_seconds=60)
        self.approval_gate = ApprovalGate(rules=self.config.require_human_approval)
        self.network_policy = NetworkPolicy(egress_allowed=self.config.network_egress_allowed, allowed_hosts=self.config.allowed_hosts)

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")
        if not self.rate_limiter.check(event.action):
            return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.MEDIUM,
                message=f"Rate limit exceeded for '{event.action}'")
        urls = self._extract_urls(event)
        for url in urls:
            if not self.network_policy.check_url(url):
                return LayerResult(layer=self.name, verdict=SecurityVerdict.DENY, threat_level=ThreatLevel.HIGH,
                    message=f"Network egress blocked for URL: {url}")
        if self.approval_gate.requires_approval(event):
            approved = await self.approval_gate.request_approval(event)
            if not approved:
                return LayerResult(layer=self.name, verdict=SecurityVerdict.ESCALATE, threat_level=ThreatLevel.MEDIUM,
                    message=f"Human approval required for '{event.action}'")
        self.rate_limiter.record(event.action)
        return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Execution checks passed")

    def _extract_urls(self, event: AgentEvent) -> list[str]:
        urls = []
        for v in event.params.values():
            if isinstance(v, str) and ("http://" in v or "https://" in v):
                urls.append(v)
        if isinstance(event.input_data, str) and ("http://" in event.input_data or "https://" in event.input_data):
            urls.append(event.input_data)
        return urls
