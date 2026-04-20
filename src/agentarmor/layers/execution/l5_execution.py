"""Layer 5: Execution Security — runtime enforcement and auditing.

Hardened per the AgentArmor L5 Execution Layer Specification.

Five enforcement domains run during and after every tool execution:
  E1. Network Policy — DNS resolution + private IP check + protocol + allowlist/blocklist
  E2. Rate Limiting — Token bucket per tool with circuit breaker on failure streak
  E3. Resource Budget — Execution timeout + input/output size limits
  E4. Output Sanitizer — UTF-8 normalize + binary strip + truncate
  E5. Side-Effect Auditor — Immutable record of what the tool actually did
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import Any
from urllib.parse import urlparse

# =====================================================================
# E1: NETWORK POLICY ENGINE
# =====================================================================

# Private IP ranges that must never be reachable from agent execution
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),           # Loopback
    ipaddress.ip_network("169.254.0.0/16"),         # Link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),          # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),                # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),               # IPv6 unique local
]

# Allowed protocols
ALLOWED_PROTOCOLS = {"https", "http"}

# Blocked protocols — explicitly denied regardless of host
BLOCKED_PROTOCOLS = {
    "file", "gopher", "dict", "ldap", "ldaps", "ftp",
    "sftp", "smb", "data", "javascript", "vbscript",
}


@dataclass
class NetworkPolicy:
    """Per-agent network policy configuration."""
    domain_allowlist: list[str] = field(default_factory=list)
    domain_blocklist: list[str] = field(default_factory=lambda: [
        "metadata.google.internal",
        "metadata.internal",
        "*.internal",
        "*.local",
    ])
    allow_http: bool = False
    max_outbound_payload_bytes: int = 50_000  # 50KB
    dns_rebinding_protection: bool = True


def parse_url_components(url: str) -> tuple[str, str, int]:
    """Extract (protocol, hostname, port) from URL string."""
    parsed = urlparse(url)
    protocol = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if protocol == "https" else 80)
    return protocol, hostname, port


def resolve_and_check_ip(hostname: str) -> tuple[bool, str]:
    """
    DNS-resolve hostname and check if it resolves to a private IP.
    This is the ONLY defense against DNS rebinding SSRF.
    Returns (is_safe, reason).
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return True, f"DNS resolution failed: {e}"

    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for private_range in PRIVATE_RANGES:
                if ip_obj in private_range:
                    return False, f"DNS resolved to private IP {ip_str} in range {private_range}"
        except ValueError:
            continue

    return True, "clean"


def domain_matches_pattern(hostname: str, pattern: str) -> bool:
    """Check if hostname matches a domain pattern (supports wildcards)."""
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname == suffix or hostname.endswith(f".{suffix}")
    return hostname == pattern or hostname.endswith(f".{pattern}")


def enforce_network_policy(url: str, policy: NetworkPolicy, outbound_payload: str = "") -> dict:
    """
    Full network policy enforcement for a given URL.
    Returns an L5 event dict with verdict.
    """
    if not url:
        return {"verdict": "allow", "reason": "no_url"}

    protocol, hostname, port = parse_url_components(url)

    # 1. Protocol check
    if protocol in BLOCKED_PROTOCOLS:
        return {
            "verdict": "block", "threat_level": "critical",
            "reason": f"protocol_blocked:{protocol}",
            "operation": "network_policy",
        }

    if protocol not in ALLOWED_PROTOCOLS:
        return {
            "verdict": "block", "threat_level": "high",
            "reason": f"protocol_not_in_allowlist:{protocol}",
            "operation": "network_policy",
        }

    if protocol == "http" and not policy.allow_http:
        return {
            "verdict": "block", "threat_level": "medium",
            "reason": "http_not_allowed_policy_requires_https",
            "operation": "network_policy",
        }

    # 2. Domain blocklist check
    for blocked_pattern in policy.domain_blocklist:
        if domain_matches_pattern(hostname, blocked_pattern):
            return {
                "verdict": "block", "threat_level": "high",
                "reason": f"domain_blocklisted:{hostname}",
                "operation": "network_policy",
            }

    # 3. Domain allowlist check (only if allowlist is configured)
    if policy.domain_allowlist:
        allowed = any(domain_matches_pattern(hostname, p) for p in policy.domain_allowlist)
        if not allowed:
            return {
                "verdict": "block", "threat_level": "medium",
                "reason": f"domain_not_in_allowlist:{hostname}",
                "operation": "network_policy",
            }

    # 4. DNS Rebinding protection (resolves DNS at runtime)
    if policy.dns_rebinding_protection and hostname:
        is_safe, reason = resolve_and_check_ip(hostname)
        if not is_safe:
            return {
                "verdict": "block", "threat_level": "critical",
                "reason": f"dns_rebinding_ssrf:{reason}",
                "operation": "network_policy",
            }

    # 5. Outbound payload size check (exfiltration prevention)
    if outbound_payload and len(outbound_payload.encode("utf-8", errors="replace")) > policy.max_outbound_payload_bytes:
        payload_kb = len(outbound_payload.encode("utf-8", errors="replace")) / 1024
        limit_kb = policy.max_outbound_payload_bytes // 1024
        return {
            "verdict": "block", "threat_level": "high",
            "reason": f"outbound_payload_too_large:{payload_kb:.1f}KB_exceeds_{limit_kb}KB_limit",
            "operation": "network_policy",
        }

    verdict = "allow"
    if protocol == "http":
        verdict = "audit"  # Allow but log as WARN

    return {
        "verdict": verdict, "threat_level": "none",
        "reason": "clean", "operation": "network_policy",
        "resolved_host": hostname,
    }


# =====================================================================
# E2: TOKEN BUCKET RATE LIMITER + CIRCUIT BREAKER
# =====================================================================

@dataclass
class RateConfig:
    """Rate limiting configuration per tool type."""
    burst_limit: int
    refill_rate: float
    failure_threshold: int = 3
    recovery_timeout: float = 60.0


DEFAULT_RATE_CONFIGS: dict[str, RateConfig] = {
    "tool_web_search":        RateConfig(burst_limit=5,  refill_rate=0.5),
    "tool_web_fetch":         RateConfig(burst_limit=3,  refill_rate=0.2),
    "tool_db_query":          RateConfig(burst_limit=10, refill_rate=1.0),
    "tool_file_read":         RateConfig(burst_limit=20, refill_rate=2.0),
    "tool_file_write":        RateConfig(burst_limit=5,  refill_rate=0.5),
    "tool_file_delete":       RateConfig(burst_limit=2,  refill_rate=0.1),
    "tool_run_code":          RateConfig(burst_limit=3,  refill_rate=0.2, failure_threshold=2),
    "tool_api_call":          RateConfig(burst_limit=5,  refill_rate=0.3),
    "tool_send_email":        RateConfig(burst_limit=2,  refill_rate=0.05, failure_threshold=1),
    "tool_delegate_to_agent": RateConfig(burst_limit=3,  refill_rate=0.2, failure_threshold=2),
    # Non-prefixed names (TOOL_REGISTRY keys)
    "web_search":             RateConfig(burst_limit=5,  refill_rate=0.5),
    "web_fetch":              RateConfig(burst_limit=3,  refill_rate=0.2),
    "db_query":               RateConfig(burst_limit=10, refill_rate=1.0),
    "file_read":              RateConfig(burst_limit=20, refill_rate=2.0),
    "file_write":             RateConfig(burst_limit=5,  refill_rate=0.5),
    "file_delete":            RateConfig(burst_limit=2,  refill_rate=0.1),
    "run_code":               RateConfig(burst_limit=3,  refill_rate=0.2, failure_threshold=2),
    "api_call":               RateConfig(burst_limit=5,  refill_rate=0.3),
    "send_email":             RateConfig(burst_limit=2,  refill_rate=0.05, failure_threshold=1),
    "delegate_to_agent":      RateConfig(burst_limit=3,  refill_rate=0.2, failure_threshold=2),
    "_default":               RateConfig(burst_limit=10, refill_rate=1.0),
}


class TokenBucket:
    """Thread-safe token bucket with circuit breaker."""

    def __init__(self, config: RateConfig, tool_name: str, agent_id: str):
        self._config = config
        self._tool_name = tool_name
        self._agent_id = agent_id
        self._tokens = float(config.burst_limit)
        self._last_refill = time.time()
        self._lock = Lock()
        # Circuit breaker state
        self._failure_count = 0
        self._circuit_open = False
        self._circuit_opened_at: float = 0.0

    def _refill(self):
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._config.burst_limit),
            self._tokens + elapsed * self._config.refill_rate,
        )
        self._last_refill = now

    def try_consume(self) -> tuple[bool, str]:
        """Attempt to consume one token. Returns (allowed, reason). Thread-safe."""
        with self._lock:
            if self._circuit_open:
                recovery_elapsed = time.time() - self._circuit_opened_at
                if recovery_elapsed >= self._config.recovery_timeout:
                    self._circuit_open = False
                    self._failure_count = 0
                else:
                    remaining = self._config.recovery_timeout - recovery_elapsed
                    return False, f"circuit_open:recovers_in_{remaining:.0f}s"

            self._refill()

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True, "ok"
            else:
                tokens_needed = 1.0 - self._tokens
                wait_s = tokens_needed / self._config.refill_rate
                return False, f"rate_limited:retry_in_{wait_s:.1f}s"

    def record_failure(self):
        """Record a tool execution failure for circuit breaker tracking."""
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self._config.failure_threshold:
                self._circuit_open = True
                self._circuit_opened_at = time.time()

    def record_success(self):
        """Reset failure count on success."""
        with self._lock:
            self._failure_count = max(0, self._failure_count - 1)


class RateLimiterRegistry:
    """Manages per-agent, per-tool token buckets."""

    def __init__(self):
        self._buckets: dict[str, dict[str, TokenBucket]] = defaultdict(dict)
        self._lock = Lock()

    def _get_bucket(self, agent_id: str, tool_name: str) -> TokenBucket:
        with self._lock:
            if tool_name not in self._buckets[agent_id]:
                config = DEFAULT_RATE_CONFIGS.get(tool_name, DEFAULT_RATE_CONFIGS["_default"])
                self._buckets[agent_id][tool_name] = TokenBucket(config, tool_name, agent_id)
            return self._buckets[agent_id][tool_name]

    def check_rate_limit(self, agent_id: str, tool_name: str) -> tuple[bool, str]:
        bucket = self._get_bucket(agent_id, tool_name)
        return bucket.try_consume()

    def record_tool_result(self, agent_id: str, tool_name: str, success: bool):
        bucket = self._get_bucket(agent_id, tool_name)
        if success:
            bucket.record_success()
        else:
            bucket.record_failure()

    def get_bucket_status(self, agent_id: str, tool_name: str) -> dict:
        bucket = self._get_bucket(agent_id, tool_name)
        return {
            "tool": tool_name,
            "tokens_remaining": round(bucket._tokens, 2),
            "circuit_open": bucket._circuit_open,
            "failure_count": bucket._failure_count,
        }


# =====================================================================
# E3: RESOURCE BUDGET ENFORCER
# =====================================================================

@dataclass
class ResourceBudget:
    """Per-tool resource limits."""
    execution_timeout_s: float
    max_output_bytes: int
    max_input_bytes: int = 10_000


DEFAULT_RESOURCE_BUDGETS: dict[str, ResourceBudget] = {
    "tool_web_search":       ResourceBudget(execution_timeout_s=15.0,  max_output_bytes=20_000),
    "tool_web_fetch":        ResourceBudget(execution_timeout_s=20.0,  max_output_bytes=50_000),
    "tool_db_query":         ResourceBudget(execution_timeout_s=30.0,  max_output_bytes=100_000),
    "tool_file_read":        ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=200_000),
    "tool_file_write":       ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=1_000),
    "tool_file_delete":      ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=500),
    "tool_run_code":         ResourceBudget(execution_timeout_s=30.0,  max_output_bytes=50_000),
    "tool_api_call":         ResourceBudget(execution_timeout_s=15.0,  max_output_bytes=100_000),
    "tool_send_email":       ResourceBudget(execution_timeout_s=10.0,  max_output_bytes=1_000),
    "tool_knowledge_search": ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=50_000),
    # Non-prefixed names
    "web_search":            ResourceBudget(execution_timeout_s=15.0,  max_output_bytes=20_000),
    "web_fetch":             ResourceBudget(execution_timeout_s=20.0,  max_output_bytes=50_000),
    "db_query":              ResourceBudget(execution_timeout_s=30.0,  max_output_bytes=100_000),
    "file_read":             ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=200_000),
    "file_write":            ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=1_000),
    "file_delete":           ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=500),
    "run_code":              ResourceBudget(execution_timeout_s=30.0,  max_output_bytes=50_000),
    "api_call":              ResourceBudget(execution_timeout_s=15.0,  max_output_bytes=100_000),
    "send_email":            ResourceBudget(execution_timeout_s=10.0,  max_output_bytes=1_000),
    "knowledge_search":      ResourceBudget(execution_timeout_s=5.0,   max_output_bytes=50_000),
    "_default":              ResourceBudget(execution_timeout_s=10.0,  max_output_bytes=50_000),
}


async def execute_with_timeout(
    tool_func: Callable[..., Any],
    tool_name: str,
    tool_args: dict,
    budget: ResourceBudget | None = None,
) -> tuple[Any, bool, str]:
    """
    Execute tool_func within the resource budget.
    Returns (result, success, reason).

    Handles both sync and async tool functions.
    """
    if budget is None:
        budget = DEFAULT_RESOURCE_BUDGETS.get(tool_name, DEFAULT_RESOURCE_BUDGETS["_default"])

    # Validate input size
    args_json = str(tool_args)
    if len(args_json.encode("utf-8", errors="replace")) > budget.max_input_bytes:
        return {
            "error": f"[L5 INPUT_TOO_LARGE] Tool args exceed {budget.max_input_bytes} byte limit"
        }, False, "input_size_exceeded"

    try:
        # Handle both sync and async functions
        if asyncio.iscoroutinefunction(tool_func):
            result = await asyncio.wait_for(
                tool_func(**tool_args),
                timeout=budget.execution_timeout_s,
            )
        else:
            # Wrap sync function in executor to allow timeout
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: tool_func(**tool_args)),
                timeout=budget.execution_timeout_s,
            )
        return result, True, "ok"
    except TimeoutError:
        return {
            "error": f"[L5 TIMEOUT] Tool '{tool_name}' exceeded {budget.execution_timeout_s}s limit. "
                     f"Execution terminated."
        }, False, f"timeout_after_{budget.execution_timeout_s}s"
    except Exception as e:
        return {
            "error": f"[L5 EXECUTION_ERROR] Tool '{tool_name}' raised: {type(e).__name__}: {str(e)[:200]}"
        }, False, f"execution_error:{type(e).__name__}"


# =====================================================================
# E4: OUTPUT SANITIZER
# =====================================================================

def sanitize_tool_output(
    raw_output: Any,
    tool_name: str,
    budget: ResourceBudget | None = None,
) -> tuple[str, list[str]]:
    """
    Sanitize and normalize tool output before returning to context assembler.
    Returns (sanitized_text, list_of_warnings).

    Defends against:
    - Context flooding (oversized output)
    - Binary/non-UTF-8 injection into LLM context
    - JSON serializer crashes from unexpected types
    - Null byte injection
    """
    if budget is None:
        budget = DEFAULT_RESOURCE_BUDGETS.get(tool_name, DEFAULT_RESOURCE_BUDGETS["_default"])

    warnings: list[str] = []

    # 1. Serialize to string
    if isinstance(raw_output, str):
        output_str = raw_output
    elif isinstance(raw_output, (dict, list)):
        try:
            output_str = json.dumps(raw_output, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as e:
            output_str = str(raw_output)
            warnings.append(f"json_serialize_fallback:{e}")
    elif raw_output is None:
        return "[Tool returned no output]", []
    elif isinstance(raw_output, bytes):
        output_str = raw_output.decode("utf-8", errors="replace")
        warnings.append("bytes_decoded")
    else:
        output_str = str(raw_output)

    # 2. UTF-8 normalization
    output_str = output_str.encode("utf-8", errors="replace").decode("utf-8", errors="replace")

    # 3. Null byte removal
    if "\x00" in output_str:
        output_str = output_str.replace("\x00", "")
        warnings.append("null_bytes_stripped")

    # 4. Binary content detection — if >30% non-printable chars, it's probably binary
    sample = output_str[:1000]
    non_printable = sum(1 for c in sample if not c.isprintable() and c not in ('\n', '\r', '\t'))
    if sample and non_printable / len(sample) > 0.30:
        warnings.append("binary_content_detected_stripped")
        return "[L5: Binary content detected and blocked. Tool returned non-text data.]", warnings

    # 5. Size enforcement — truncate to budget
    encoded = output_str.encode("utf-8")
    if len(encoded) > budget.max_output_bytes:
        truncated = encoded[:budget.max_output_bytes].decode("utf-8", errors="ignore")
        last_break = max(truncated.rfind("\n"), truncated.rfind(". "))
        if last_break > budget.max_output_bytes // 2:
            truncated = truncated[:last_break]

        original_kb = len(encoded) / 1024
        budget_kb = budget.max_output_bytes / 1024
        warnings.append(f"output_truncated:{original_kb:.0f}KB->{budget_kb:.0f}KB")
        output_str = truncated + f"\n\n[L5: Output truncated from {original_kb:.0f}KB to {budget_kb:.0f}KB limit]"

    return output_str, warnings


# =====================================================================
# E5: SIDE-EFFECT AUDITOR
# =====================================================================

@dataclass
class SideEffectRecord:
    """Immutable record of what a tool execution actually did."""
    agent_id: str
    session_id: str
    tool_name: str
    tool_args_hash: str
    execution_start: float
    execution_end: float
    execution_success: bool
    output_size_bytes: int
    output_hash: str
    urls_contacted: list[str]
    files_modified: list[str]
    sql_statements: list[str]
    timeout_triggered: bool
    l5_verdicts: list[str]


def create_side_effect_record(
    agent_id: str,
    session_id: str,
    tool_name: str,
    tool_args: dict,
    result: Any,
    start_time: float,
    end_time: float,
    success: bool,
    l5_verdicts: list[str],
) -> SideEffectRecord:
    """Create an immutable side-effect record for the audit trail."""
    args_str = json.dumps(tool_args, sort_keys=True, default=str)
    args_hash = hashlib.sha256(args_str.encode()).hexdigest()

    result_str = json.dumps(result, default=str) if not isinstance(result, str) else result
    output_hash = hashlib.sha256(result_str.encode()).hexdigest()

    urls_contacted: list[str] = []
    files_modified: list[str] = []
    sql_statements: list[str] = []

    if tool_name in ("tool_api_call", "tool_web_fetch", "tool_web_search",
                     "api_call", "web_fetch", "web_search"):
        url = tool_args.get("url", tool_args.get("query", ""))
        if url:
            urls_contacted.append(str(url)[:200])

    if tool_name in ("tool_file_write", "tool_file_delete", "file_write", "file_delete"):
        path = tool_args.get("path", "")
        if path:
            files_modified.append(str(path)[:200])

    if tool_name in ("tool_db_query", "db_query"):
        sql = tool_args.get("sql", tool_args.get("query", ""))[:100]
        if sql:
            sql_statements.append(sql)

    return SideEffectRecord(
        agent_id=agent_id,
        session_id=session_id,
        tool_name=tool_name,
        tool_args_hash=args_hash[:16],
        execution_start=start_time,
        execution_end=end_time,
        execution_success=success,
        output_size_bytes=len(result_str.encode()),
        output_hash=output_hash[:16],
        urls_contacted=urls_contacted,
        files_modified=files_modified,
        sql_statements=sql_statements,
        timeout_triggered=not success and "timeout" in str(l5_verdicts),
        l5_verdicts=l5_verdicts,
    )


# =====================================================================
# F: L5ExecutionLayer CLASS — FULL INTEGRATION
# =====================================================================

class L5ExecutionLayer:
    """
    L5 Execution Layer — runtime enforcement and audit.
    Wraps every tool execution call.
    """

    def __init__(self, agent_id: str, network_policy: NetworkPolicy | None = None):
        self.agent_id = agent_id
        self.network_policy = network_policy or NetworkPolicy()
        self._rate_registry = RateLimiterRegistry()
        self._side_effects: list[SideEffectRecord] = []

    async def execute(
        self,
        tool_name: str,
        tool_args: dict,
        tool_func: Callable,
        session_id: str,
        outbound_url: str = "",
        outbound_payload: str = "",
    ) -> tuple[Any, dict]:
        """
        Full L5 lifecycle for a single tool call.
        Returns (tool_result, l5_event_dict).
        """
        start_time = time.time()
        l5_verdicts: list[str] = []

        # === E1: Network Policy ===
        _network_tools = {
            "tool_web_fetch", "tool_api_call", "tool_web_search",
            "web_fetch", "api_call", "web_search",
        }
        if outbound_url or tool_name in _network_tools:
            url = outbound_url or tool_args.get("url", tool_args.get("query", ""))
            if url and isinstance(url, str) and url.startswith(("http", "https", "file", "ftp", "gopher")):
                net_result = enforce_network_policy(
                    url, self.network_policy, outbound_payload,
                )
                l5_verdicts.append(f"network_policy:{net_result['verdict']}")
                if net_result["verdict"] == "block":
                    return self._make_block_result(
                        tool_name, "network_policy", net_result,
                        start_time, l5_verdicts, session_id, tool_args,
                    )

        # === E2: Rate Limit + Circuit Breaker ===
        rate_ok, rate_reason = self._rate_registry.check_rate_limit(self.agent_id, tool_name)
        l5_verdicts.append(f"rate_limit:{'allow' if rate_ok else 'block'}")
        if not rate_ok:
            return self._make_block_result(
                tool_name, "rate_limit", {"reason": rate_reason},
                start_time, l5_verdicts, session_id, tool_args,
            )

        # === E3: Execute with Resource Budget ===
        budget = DEFAULT_RESOURCE_BUDGETS.get(tool_name, DEFAULT_RESOURCE_BUDGETS["_default"])
        raw_result, exec_success, exec_reason = await execute_with_timeout(
            tool_func, tool_name, tool_args, budget,
        )
        l5_verdicts.append(f"execution:{'ok' if exec_success else exec_reason}")

        # Record failure/success for circuit breaker
        self._rate_registry.record_tool_result(self.agent_id, tool_name, exec_success)

        # === E4: Output Sanitization ===
        sanitized, sanit_warnings = sanitize_tool_output(raw_result, tool_name, budget)
        for w in sanit_warnings:
            l5_verdicts.append(f"output:{w}")

        # === E5: Side-Effect Audit ===
        end_time = time.time()
        side_effect = create_side_effect_record(
            self.agent_id, session_id, tool_name, tool_args,
            raw_result, start_time, end_time, exec_success, l5_verdicts,
        )
        self._side_effects.append(side_effect)

        # Determine threat level from verdicts
        threat_level = "none"
        if any("block" in v for v in l5_verdicts):
            threat_level = "high"
        elif any("truncated" in v or "warn" in v or "binary" in v for v in l5_verdicts):
            threat_level = "low"

        l5_event = {
            "layer": "L5_Execution",
            "tool_name": tool_name,
            "verdict": "allow",
            "threat_level": threat_level,
            "execution_ms": round((end_time - start_time) * 1000, 1),
            "output_size_bytes": side_effect.output_size_bytes,
            "verdicts": l5_verdicts,
            "timeout_triggered": side_effect.timeout_triggered,
            "urls_contacted": side_effect.urls_contacted,
            "files_modified": side_effect.files_modified,
        }

        return sanitized, l5_event

    def _make_block_result(
        self, tool_name: str, domain: str, detail: dict,
        start_time: float, verdicts: list[str], session_id: str, args: dict,
    ) -> tuple[dict, dict]:
        end_time = time.time()
        side_effect = create_side_effect_record(
            self.agent_id, session_id, tool_name, args,
            {"blocked": True}, start_time, end_time, False, verdicts,
        )
        self._side_effects.append(side_effect)

        block_msg = (
            f"[AgentArmor L5 BLOCKED] Tool '{tool_name}' blocked at {domain}. "
            f"Reason: {detail.get('reason', 'policy_violation')}"
        )
        l5_event = {
            "layer": "L5_Execution",
            "tool_name": tool_name,
            "verdict": "block",
            "threat_level": "high",
            "domain": domain,
            "reason": detail.get("reason", ""),
            "verdicts": verdicts,
            "execution_ms": round((end_time - start_time) * 1000, 1),
        }
        return {"error": block_msg, "blocked": True}, l5_event

    def get_session_side_effects(self, session_id: str) -> list[dict]:
        """Return all side-effect records for a session."""
        return [
            {
                "tool": se.tool_name,
                "duration_ms": round((se.execution_end - se.execution_start) * 1000, 1),
                "success": se.execution_success,
                "output_kb": round(se.output_size_bytes / 1024, 1),
                "urls": se.urls_contacted,
                "files": se.files_modified,
                "verdicts": se.l5_verdicts,
            }
            for se in self._side_effects if se.session_id == session_id
        ]

    def get_rate_status(self, tool_name: str) -> dict:
        """Get current rate limiter status for a tool."""
        return self._rate_registry.get_bucket_status(self.agent_id, tool_name)
