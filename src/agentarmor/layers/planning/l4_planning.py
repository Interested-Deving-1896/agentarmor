"""Layer 4: Planning Security — multi-dimensional action authorization gateway.

Hardened per the AgentArmor L4 Planning Layer Specification.

Scores every tool call on five independent dimensions:
  1. Verb Risk — what operation is being performed
  2. Resource Sensitivity — what resource is being targeted
  3. Reversibility — can the operation be undone
  4. Parameter Injection — are the arguments malicious (SQLi, path traversal, SSRF, cmd injection)
  5. Chain Escalation — does the session history show privilege escalation patterns
"""
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, NamedTuple


# =====================================================================
# A1: VERB RISK TABLE
# =====================================================================

VERB_RISK_TABLE: dict[str, float] = {
    # Database verbs
    "select":       0.05,
    "insert":       0.25,
    "update":       0.35,
    "delete":       0.60,
    "drop":         0.90,
    "truncate":     0.85,
    "create":       0.30,
    "alter":        0.45,
    "grant":        0.95,
    "revoke":       0.70,
    "exec":         0.95,
    "execute":      0.95,

    # File system verbs
    "read":         0.10,
    "write":        0.40,
    "delete_file":  0.65,
    "list":         0.05,
    "move":         0.35,
    "copy":         0.20,

    # Network verbs
    "get":          0.10,
    "post":         0.40,
    "put":          0.50,
    "patch":        0.45,
    "delete_http":  0.60,
    "webhook":      0.55,

    # Code execution
    "run":          0.80,
    "execute_code": 0.90,
    "install":      0.85,
    "import":       0.60,

    # Agent delegation
    "delegate":     0.50,
    "spawn":        0.65,
}

# Map tool names to verb classes
_TOOL_VERB_MAP: dict[str, str] = {
    "tool_web_search":       "get",
    "tool_web_fetch":        "get",
    "tool_file_read":        "read",
    "tool_file_write":       "write",
    "tool_file_delete":      "delete_file",
    "tool_run_code":         "execute_code",
    "tool_api_call":         "post",
    "tool_send_email":       "post",
    "tool_knowledge_search": "read",
    "tool_delegate_to_agent": "delegate",
    "tool_db_query":         "select",
    "tool_calendar_create":  "write",
    # Also support non-prefixed names (from TOOL_REGISTRY keys)
    "web_search":            "get",
    "web_fetch":             "get",
    "file_read":             "read",
    "file_write":            "write",
    "file_delete":           "delete_file",
    "run_code":              "execute_code",
    "api_call":              "post",
    "send_email":            "post",
    "knowledge_search":      "read",
    "delegate_to_agent":     "delegate",
    "db_query":              "select",
    "calendar_create":       "write",
}


def get_verb_score(tool_name: str, sql_or_action: str = "") -> float:
    """Extract verb from tool name or SQL statement and return risk score."""
    # For db_query: parse the SQL verb
    if tool_name in ("tool_db_query", "db_query") and sql_or_action:
        sql_upper = sql_or_action.strip().upper()
        for verb in VERB_RISK_TABLE:
            if sql_upper.startswith(verb.upper()):
                return VERB_RISK_TABLE[verb]

    # For other tools: map tool name to verb class
    verb = _TOOL_VERB_MAP.get(tool_name, "get")
    return VERB_RISK_TABLE.get(verb, 0.10)


# =====================================================================
# A2: RESOURCE SENSITIVITY CLASSIFIER
# =====================================================================

RESOURCE_SENSITIVITY_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    # Critical system resources (0.9–1.0)
    (re.compile(r'/etc/(passwd|shadow|sudoers|hosts|crontab)', re.I), 1.0, "OS_credentials"),
    (re.compile(r'/proc/(self|[0-9]+)/(mem|environ|maps)', re.I), 1.0, "process_memory"),
    (re.compile(r'\.\.([\\/]\.\.)+', re.I), 1.0, "path_traversal"),
    (re.compile(r'169\.254\.169\.254', re.I), 1.0, "cloud_metadata_SSRF"),
    (re.compile(r'(localhost|127\.0\.0\.1):(\d+)', re.I), 0.9, "SSRF_internal"),

    # Database privilege tables (0.85–0.95)
    (re.compile(r'(mysql\.user|pg_shadow|sys\.server_principals|information_schema\.user_privileges)', re.I), 0.95, "db_privilege_table"),
    (re.compile(r'(auth_user|django_admin|admin_users|superusers)', re.I), 0.90, "auth_table"),

    # Credential and key patterns in SQL or paths (0.80–0.90)
    (re.compile(r'(password|passwd|pwd|secret|token|api_key|private_key|credential)', re.I), 0.85, "credential_field"),
    (re.compile(r'(\.env|\.pem|\.key|\.p12|\.pfx|id_rsa|id_ed25519)', re.I), 0.90, "key_file"),

    # Security audit and log data (0.60–0.75)
    (re.compile(r'(audit_log|security_event|access_log|auth_log)', re.I), 0.70, "audit_data"),

    # User/PII data tables (0.60–0.75)
    (re.compile(r'(users|customers|patients|employees|accounts)', re.I), 0.65, "PII_table"),
    (re.compile(r'(ssn|social_security|dob|date_of_birth|credit_card)', re.I), 0.80, "PII_field"),

    # Financial data (0.70–0.85)
    (re.compile(r'(payment|transaction|billing|invoice|account_balance)', re.I), 0.75, "financial_data"),

    # Internal admin interfaces and metadata endpoints (0.70–0.85)
    (re.compile(r'(/__admin|/api/admin|/v1/internal|/management)', re.I), 0.80, "admin_endpoint"),
]


def score_resource_sensitivity(args: dict) -> tuple[float, list[str]]:
    """
    Scan all string arguments for sensitive resource patterns.
    Returns (max_score, list_of_matched_categories).
    """
    all_text = " ".join(str(v) for v in args.values())
    max_score = 0.0
    matched: list[str] = []

    for pattern, score, category in RESOURCE_SENSITIVITY_PATTERNS:
        if pattern.search(all_text):
            if score > max_score:
                max_score = score
            matched.append(category)

    return max_score, matched


# =====================================================================
# A3: REVERSIBILITY CLASSIFIER
# =====================================================================

class Reversibility:
    REVERSIBLE = "reversible"
    SEMI_REVERSIBLE = "semi_reversible"
    IRREVERSIBLE = "irreversible"


REVERSIBILITY_MAP: dict[str, tuple[str, float]] = {
    # Irreversible operations
    "tool_send_email":    (Reversibility.IRREVERSIBLE, 1.0),
    "send_email":         (Reversibility.IRREVERSIBLE, 1.0),
    "tool_file_delete":   (Reversibility.IRREVERSIBLE, 1.0),
    "file_delete":        (Reversibility.IRREVERSIBLE, 1.0),
    "drop":               (Reversibility.IRREVERSIBLE, 1.0),
    "truncate":           (Reversibility.IRREVERSIBLE, 1.0),
    "grant":              (Reversibility.SEMI_REVERSIBLE, 0.8),
    "execute_code":       (Reversibility.IRREVERSIBLE, 0.9),
    "run":                (Reversibility.IRREVERSIBLE, 0.9),
    "tool_run_code":      (Reversibility.IRREVERSIBLE, 0.9),
    "run_code":           (Reversibility.IRREVERSIBLE, 0.9),
    "delete":             (Reversibility.SEMI_REVERSIBLE, 0.7),

    # Semi-reversible
    "insert":             (Reversibility.SEMI_REVERSIBLE, 0.3),
    "update":             (Reversibility.SEMI_REVERSIBLE, 0.4),
    "post":               (Reversibility.SEMI_REVERSIBLE, 0.4),
    "write":              (Reversibility.SEMI_REVERSIBLE, 0.4),
    "tool_file_write":    (Reversibility.SEMI_REVERSIBLE, 0.4),
    "file_write":         (Reversibility.SEMI_REVERSIBLE, 0.4),

    # Reversible
    "select":             (Reversibility.REVERSIBLE, 0.0),
    "read":               (Reversibility.REVERSIBLE, 0.0),
    "get":                (Reversibility.REVERSIBLE, 0.0),
    "list":               (Reversibility.REVERSIBLE, 0.0),
    "web_search":         (Reversibility.REVERSIBLE, 0.0),
    "tool_web_search":    (Reversibility.REVERSIBLE, 0.0),
    "tool_web_fetch":     (Reversibility.REVERSIBLE, 0.0),
    "tool_file_read":     (Reversibility.REVERSIBLE, 0.0),
    "file_read":          (Reversibility.REVERSIBLE, 0.0),
    "tool_knowledge_search": (Reversibility.REVERSIBLE, 0.0),
    "knowledge_search":   (Reversibility.REVERSIBLE, 0.0),
}


def score_reversibility(tool_name: str, sql: str = "") -> tuple[str, float]:
    """Return (reversibility_class, score_0_to_1)."""
    # Check SQL verb first
    if sql:
        for verb, (rev_class, score) in REVERSIBILITY_MAP.items():
            if sql.strip().upper().startswith(verb.upper()):
                return rev_class, score

    # Check direct tool name match
    if tool_name in REVERSIBILITY_MAP:
        return REVERSIBILITY_MAP[tool_name]

    # Check tool name contains verb
    for verb, (rev_class, score) in REVERSIBILITY_MAP.items():
        if verb in tool_name.lower():
            return rev_class, score

    return Reversibility.REVERSIBLE, 0.0


# =====================================================================
# B: PARAMETER INJECTION DETECTION ENGINE
# =====================================================================

class InjectionFinding(NamedTuple):
    injection_type: str
    severity: float       # 0.0 – 1.0
    matched_text: str
    parameter_name: str


# SQL Injection patterns
SQL_INJECTION_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r";\s*(drop|delete|truncate|insert|update|grant|revoke|create|alter)\b", re.I), 0.95, "SQLi_stacked_query"),
    (re.compile(r"\bunion\s+(all\s+)?select\b", re.I), 0.95, "SQLi_UNION"),
    (re.compile(r"'[\s]*or[\s]+'?[0-9a-z]+'?\s*=\s*'?[0-9a-z]+'?", re.I), 0.90, "SQLi_boolean_or"),
    (re.compile(r"--[\s]*$|;\s*--", re.M), 0.75, "SQLi_comment_bypass"),
    (re.compile(r"'\s*;\s*exec\b|\bxp_cmdshell\b|\bsp_executesql\b", re.I), 1.0, "SQLi_exec"),
    (re.compile(r"\bwaitfor\s+delay\b|\bsleep\s*\(", re.I), 0.85, "SQLi_time_based"),
    (re.compile(r"information_schema\.(tables|columns|user_privileges)", re.I), 0.80, "SQLi_schema_recon"),
    (re.compile(r"\bcast\s*\(.*\bcharindex\b|\bconvert\s*\(.*\bchar\b", re.I), 0.75, "SQLi_obfuscated"),
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"\.\.[/\\]\.\.[/\\]", re.I), 1.0, "PathTraversal_dotdot"),
    (re.compile(r"%2e%2e[%2f%5c]", re.I), 1.0, "PathTraversal_encoded"),
    (re.compile(r"\.\.[/\\]+(etc|proc|sys|windows|system32)", re.I), 1.0, "PathTraversal_OS"),
    (re.compile(r"^[/\\]+(etc|proc|sys|root|windows)", re.I), 0.90, "AbsPath_sensitive"),
]

# Command Injection patterns
COMMAND_INJECTION_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r";\s*(rm|wget|curl|nc|ncat|bash|sh|cmd|powershell)\b", re.I), 1.0, "CmdInj_shell"),
    (re.compile(r"\$\([^)]+\)|`[^`]+`", re.I), 0.90, "CmdInj_subshell"),
    (re.compile(r"&&\s*(rm|wget|curl|nc|bash)\b|\|\s*(nc|bash|sh)\b", re.I), 0.95, "CmdInj_chained"),
    (re.compile(r"__import__\s*\(\s*['\"]os['\"]", re.I), 0.90, "CmdInj_python_os"),
    (re.compile(r"exec\s*\(|eval\s*\(|compile\s*\(", re.I), 0.85, "CmdInj_eval"),
]

# SSRF patterns
SSRF_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"169\.254\.169\.254", re.I), 1.0, "SSRF_cloud_metadata"),
    (re.compile(r"(^|[/@])127\.|localhost|0\.0\.0\.0", re.I), 0.90, "SSRF_loopback"),
    (re.compile(r"(^|[/@])10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.", re.I), 0.85, "SSRF_private_range"),
    (re.compile(r"file://|gopher://|dict://|ldap://", re.I), 0.95, "SSRF_scheme_abuse"),
]


def detect_parameter_injection(
    tool_name: str, args: dict,
) -> tuple[float, list[InjectionFinding]]:
    """
    Scan all string arguments for injection patterns.
    Returns (max_severity, list_of_findings).
    """
    findings: list[InjectionFinding] = []

    for param_name, param_value in args.items():
        if not isinstance(param_value, str):
            continue

        patterns_to_check: list[tuple[re.Pattern, float, str, str]] = []

        if tool_name in ("tool_db_query", "db_query"):
            patterns_to_check.extend(
                [(p, s, t, "SQL") for p, s, t in SQL_INJECTION_PATTERNS]
            )

        if tool_name in (
            "tool_file_read", "tool_file_write", "tool_file_delete",
            "file_read", "file_write", "file_delete",
        ):
            patterns_to_check.extend(
                [(p, s, t, "PATH") for p, s, t in PATH_TRAVERSAL_PATTERNS]
            )

        if tool_name in ("tool_run_code", "run_code", "tool_api_call"):
            patterns_to_check.extend(
                [(p, s, t, "CMD") for p, s, t in COMMAND_INJECTION_PATTERNS]
            )

        if tool_name in ("tool_api_call", "tool_web_fetch", "api_call", "web_fetch"):
            patterns_to_check.extend(
                [(p, s, t, "SSRF") for p, s, t in SSRF_PATTERNS]
            )

        # Also check all string args for path traversal regardless of tool
        patterns_to_check.extend(
            [(p, s, t, "PATH") for p, s, t in PATH_TRAVERSAL_PATTERNS]
        )

        seen_types: set[str] = set()
        for pattern, severity, injection_type, _ in patterns_to_check:
            if injection_type in seen_types:
                continue
            match = pattern.search(param_value)
            if match:
                seen_types.add(injection_type)
                findings.append(InjectionFinding(
                    injection_type=injection_type,
                    severity=severity,
                    matched_text=match.group()[:100],
                    parameter_name=param_name,
                ))

    max_severity = max((f.severity for f in findings), default=0.0)
    return max_severity, findings


# =====================================================================
# C: ACTION SEQUENCE CHAIN TRACKER
# =====================================================================

@dataclass
class ActionRecord:
    tool_name: str
    verb: str
    resource_category: str
    risk_score: float
    verdict: str
    timestamp: float = field(default_factory=time.time)
    reversibility: str = "reversible"


# Known escalation chain signatures
ESCALATION_CHAIN_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "credential_harvest_and_exfiltrate",
        "description": "Agent reads credentials then makes outbound API call",
        "pattern": [
            {"category_any": ["credential_field", "key_file", "OS_credentials"]},
            {"category_any": ["credential_field", "key_file", "OS_credentials",
                              "db_privilege_table", "PII_table"]},
            {"tool_any": ["tool_api_call", "tool_web_fetch", "tool_send_email",
                          "api_call", "web_fetch", "send_email"]},
        ],
        "severity": 0.95,
    },
    {
        "name": "schema_recon_then_privilege_escalate",
        "description": "Schema exploration followed by privilege grant",
        "pattern": [
            {"category_any": ["db_privilege_table"]},
            {"verb_class": "write"},
        ],
        "severity": 1.0,
    },
    {
        "name": "read_config_create_admin",
        "description": "Read config/env then create new user/role",
        "pattern": [
            {"category_any": ["credential_field", "key_file"], "verb_class": "read"},
            {"category_any": ["auth_table"], "verb_class": "write"},
        ],
        "severity": 0.90,
    },
    {
        "name": "delete_audit_after_write",
        "description": "Suspicious write followed by audit log deletion",
        "pattern": [
            {"verb_class": "write"},
            {"category_any": ["audit_data"], "verb_class": "delete"},
        ],
        "severity": 0.85,
    },
    {
        "name": "progressive_permission_escalation",
        "description": "Session-level risk has been increasing monotonically",
        "pattern": "monotonic_escalation",
        "severity": 0.70,
    },
]


def _verb_to_class(verb: str) -> str:
    """Classify a verb into a broad action class."""
    read_verbs = {"select", "read", "get", "list", "search", "fetch"}
    write_verbs = {"insert", "update", "write", "post", "put", "patch", "create"}
    delete_verbs = {"delete", "drop", "truncate", "remove", "delete_file", "delete_http"}

    verb_lower = verb.lower()
    if verb_lower in read_verbs:
        return "read"
    if verb_lower in write_verbs:
        return "write"
    if verb_lower in delete_verbs:
        return "delete"
    return "execute"


class ActionChainTracker:
    """
    Tracks the sequence of tool calls in a session and detects escalation chains.
    Maintains a rolling window of the last 10 actions.
    """

    def __init__(self, agent_id: str, session_id: str):
        self.agent_id = agent_id
        self.session_id = session_id
        self._history: deque[ActionRecord] = deque(maxlen=10)
        self._session_risk_scores: list[float] = []

    def record_action(self, record: ActionRecord):
        self._history.append(record)
        self._session_risk_scores.append(record.risk_score)

    def compute_chain_score(self) -> tuple[float, list[str]]:
        """
        Scan recent history for chain signatures.
        Returns (max_chain_score, list_of_detected_chain_names).
        """
        if len(self._history) < 2:
            return 0.0, []

        detected_chains: list[str] = []
        max_score = 0.0

        for sig in ESCALATION_CHAIN_SIGNATURES:
            if sig["pattern"] == "monotonic_escalation":
                score = self._check_monotonic_escalation()
                if score > 0:
                    detected_chains.append(sig["name"])
                    max_score = max(max_score, sig["severity"] * score)
            else:
                if self._match_chain_pattern(sig["pattern"]):
                    detected_chains.append(sig["name"])
                    max_score = max(max_score, sig["severity"])

        return min(max_score, 1.0), detected_chains

    def _check_monotonic_escalation(self) -> float:
        """Detect if risk scores have been trending upward over the session."""
        scores = self._session_risk_scores[-6:]
        if len(scores) < 4:
            return 0.0

        increases = sum(1 for i in range(1, len(scores)) if scores[i] > scores[i - 1])
        trend = increases / (len(scores) - 1)
        avg_score = sum(scores) / len(scores)

        if trend >= 0.7 and avg_score >= 0.4:
            return trend * avg_score
        return 0.0

    def _match_chain_pattern(self, pattern: list[dict]) -> bool:
        """
        Check if the action history contains the chain pattern as a subsequence.
        """
        history_list = list(self._history)
        pattern_idx = 0

        for action in history_list:
            if pattern_idx >= len(pattern):
                break

            step = pattern[pattern_idx]
            matched = True

            if "category" in step and action.resource_category != step["category"]:
                matched = False
            if "category_any" in step and action.resource_category not in step["category_any"]:
                matched = False
            if "verb_class" in step:
                verb_class = _verb_to_class(action.verb)
                if verb_class != step["verb_class"]:
                    matched = False
            if "tool_any" in step and action.tool_name not in step["tool_any"]:
                matched = False

            if matched:
                pattern_idx += 1

        return pattern_idx >= len(pattern)

    def get_session_escalation_modifier(self) -> float:
        """
        Returns a [0.0, 0.25] modifier based on session history.
        Sessions with many elevated-risk actions get escalating scrutiny.
        Threshold is 0.35 (audit-level) — individually low-risk actions that
        collectively indicate a pattern of sensitive access.
        """
        if not self._session_risk_scores:
            return 0.0

        recent = self._session_risk_scores[-5:]
        elevated_count = sum(1 for s in recent if s >= 0.35)
        return min(elevated_count * 0.05, 0.25)


# =====================================================================
# D: COMPOSITE RISK SCORER — L4PlanningLayer
# =====================================================================

class L4PlanningLayer:
    """
    L4 Planning Layer — multi-dimensional action authorization gateway.
    Called before every tool execution.
    """

    WEIGHTS = {
        "verb":          0.15,
        "resource":      0.30,
        "reversibility": 0.20,
        "injection":     0.25,
        "chain":         0.10,
    }

    # Hard-block injection types that always result in immediate block
    HARD_BLOCK_INJECTIONS = {
        "SQLi_exec", "SQLi_UNION", "PathTraversal_dotdot",
        "SSRF_cloud_metadata", "CmdInj_shell", "SQLi_stacked_query",
        "PathTraversal_encoded", "PathTraversal_OS",
    }

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._chain_trackers: dict[str, ActionChainTracker] = {}

    def _get_tracker(self, session_id: str) -> ActionChainTracker:
        if session_id not in self._chain_trackers:
            self._chain_trackers[session_id] = ActionChainTracker(
                self.agent_id, session_id,
            )
        return self._chain_trackers[session_id]

    def evaluate(
        self,
        tool_name: str,
        tool_args: dict,
        session_id: str,
        conversation_context: str = "",
    ) -> dict:
        """
        Evaluate a proposed tool call. Returns a full L4 verdict dict.
        Called BEFORE tool execution.
        """
        t_start = time.perf_counter()

        # Extract SQL string if present
        sql = tool_args.get("sql", "") or tool_args.get("query", "")

        # === DIMENSION 1: Verb Risk ===
        verb_score = get_verb_score(tool_name, sql)

        # === DIMENSION 2: Resource Sensitivity ===
        resource_score, resource_categories = score_resource_sensitivity(tool_args)

        # === DIMENSION 3: Reversibility ===
        rev_class, rev_score = score_reversibility(tool_name, sql)

        # === DIMENSION 4: Parameter Injection ===
        inj_score, inj_findings = detect_parameter_injection(tool_name, tool_args)

        # === HARD BLOCK CHECK ===
        hard_blocked = [
            f for f in inj_findings if f.injection_type in self.HARD_BLOCK_INJECTIONS
        ]

        chain_score = 0.0
        chain_names: list[str] = []
        session_modifier = 0.0

        if hard_blocked:
            verdict = "block"
            threat_level = "critical"
            composite_score = 1.0

            # Still record the action for chain history (even if hard-blocked)
            tracker = self._get_tracker(session_id)
            primary_resource = resource_categories[0] if resource_categories else "none"
            verb = sql.split()[0].lower() if sql and sql.strip() else tool_name.replace("tool_", "")
            tracker.record_action(ActionRecord(
                tool_name=tool_name,
                verb=verb,
                resource_category=primary_resource,
                risk_score=composite_score,
                verdict=verdict,
                reversibility=rev_class,
            ))
            chain_score = 0.0
            chain_names = []
            session_modifier = 0.0
        else:
            # Record the current action FIRST so it is included in the chain matching window
            tracker = self._get_tracker(session_id)
            primary_resource = resource_categories[0] if resource_categories else "none"
            verb = sql.split()[0].lower() if sql and sql.strip() else tool_name.replace("tool_", "")

            # Compute a preliminary score for recording (without chain/session contribution)
            prelim_score = (
                self.WEIGHTS["verb"]          * verb_score
                + self.WEIGHTS["resource"]    * resource_score
                + self.WEIGHTS["reversibility"] * rev_score
                + self.WEIGHTS["injection"]   * inj_score
            )

            tracker.record_action(ActionRecord(
                tool_name=tool_name,
                verb=verb,
                resource_category=primary_resource,
                risk_score=prelim_score,
                verdict="pending",
                reversibility=rev_class,
            ))

            # === DIMENSION 5: Chain Escalation (now includes current action) ===
            chain_score, chain_names = tracker.compute_chain_score()
            session_modifier = tracker.get_session_escalation_modifier()

            # === COMPOSITE SCORE ===
            composite_score = (
                self.WEIGHTS["verb"]          * verb_score
                + self.WEIGHTS["resource"]    * resource_score
                + self.WEIGHTS["reversibility"] * rev_score
                + self.WEIGHTS["injection"]   * inj_score
                + self.WEIGHTS["chain"]       * chain_score
            ) + session_modifier

            composite_score = min(composite_score, 1.0)

            # === VERDICT ===
            if composite_score < 0.40:
                verdict, threat_level = "allow", "none"
            elif composite_score < 0.60:
                verdict, threat_level = "audit", "low"
            elif composite_score < 0.80:
                verdict, threat_level = "escalate", "medium"
            else:
                verdict, threat_level = "block", "high"

            # Update the recorded action with the final score and verdict
            tracker._history[-1].risk_score = composite_score
            tracker._history[-1].verdict = verdict
            tracker._session_risk_scores[-1] = composite_score

        latency_ms = (time.perf_counter() - t_start) * 1000

        return {
            "layer": "L4_Planning",
            "tool_name": tool_name,
            "verdict": verdict,
            "threat_level": threat_level,
            "composite_score": round(composite_score, 3),
            "dimensions": {
                "verb_score":          round(verb_score, 3),
                "resource_score":      round(resource_score, 3),
                "reversibility_score": round(rev_score, 3),
                "injection_score":     round(inj_score, 3),
                "chain_score":         round(chain_score, 3),
                "session_modifier":    round(session_modifier, 3),
            },
            "resource_categories": resource_categories,
            "injection_findings": [f._asdict() for f in inj_findings],
            "chain_patterns": chain_names,
            "reversibility": rev_class,
            "hard_block": bool(hard_blocked),
            "latency_ms": round(latency_ms, 2),
        }


# =====================================================================
# HELPER FUNCTIONS FOR SIDECAR WIRING
# =====================================================================

def _describe_block_reason(l4_result: dict) -> str:
    """Human-readable block reason for the agent response."""
    if l4_result.get("hard_block"):
        findings = l4_result.get("injection_findings", [])
        types = [f["injection_type"] for f in findings]
        return f"Critical injection detected: {', '.join(types)}"
    dims = l4_result.get("dimensions", {})
    worst_dim = max(dims, key=lambda k: dims[k])
    return f"Dimension '{worst_dim}' scored {dims[worst_dim]:.2f}"


def _summarize_args(args: dict) -> str:
    """Short human-readable arg summary for event log."""
    parts = []
    for k, v in list(args.items())[:3]:
        v_str = str(v)[:40]
        parts.append(f"{k}={v_str}")
    return ", ".join(parts)
