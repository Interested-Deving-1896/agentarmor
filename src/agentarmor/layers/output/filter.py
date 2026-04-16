"""Layer 6: Output Response Security — Full 5-scanner pipeline.

Implements credential scanning, confidence-gated PII redaction, harmful content
detection, and semantic exfiltration analysis on LLM output.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from agentarmor.core.base import SecurityLayer
from agentarmor.core.config import OutputConfig
from agentarmor.core.types import (
    AgentEvent,
    LayerResult,
    SecurityVerdict,
    ThreatLevel,
)

# =============================================================================
# SUB-TASK A: CREDENTIAL SCANNER
# =============================================================================

@dataclass
class CredentialPattern:
    name: str
    pattern: re.Pattern
    replacement: str
    severity: str

CREDENTIAL_PATTERNS: list[CredentialPattern] = [
    CredentialPattern("AWS_ACCESS_KEY", re.compile(r'\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b'), "[REDACTED:AWS_ACCESS_KEY]", "critical"),
    CredentialPattern("AWS_SECRET_KEY", re.compile(r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[_\-\s]*[=:]\s*[\'"]?([A-Za-z0-9/+]{40})[\'"]?'), "[REDACTED:AWS_SECRET_KEY]", "critical"),
    CredentialPattern("JWT_TOKEN", re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'), "[REDACTED:JWT_TOKEN]", "critical"),
    CredentialPattern("GENERIC_API_KEY", re.compile(r'(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)[_\-\s]*[=:]\s*[\'"]?([A-Za-z0-9_\-]{20,64})[\'"]?'), "[REDACTED:API_KEY]", "critical"),
    CredentialPattern("DB_CONNECTION_STRING", re.compile(r'(?i)(?:postgres(?:ql)?|mysql|mongodb|redis|mssql)://[^@\s]+:[^@\s]+@[^\s,\'"]+'), "[REDACTED:DB_CONNECTION_STRING]", "critical"),
    CredentialPattern("PRIVATE_KEY_PEM", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "[REDACTED:PRIVATE_KEY]", "critical"),
    CredentialPattern("PASSWORD_ASSIGNMENT", re.compile(r'(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]'), "[REDACTED:PASSWORD]", "high"),
    CredentialPattern("GITHUB_TOKEN", re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,255}\b'), "[REDACTED:GITHUB_TOKEN]", "critical"),
    CredentialPattern("SLACK_TOKEN", re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,100}\b'), "[REDACTED:SLACK_TOKEN]", "high"),
    CredentialPattern("STRIPE_KEY", re.compile(r'\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,99}\b'), "[REDACTED:STRIPE_KEY]", "critical"),
    CredentialPattern("DOTENV_SECRET", re.compile(r'(?i)(?:secret|key|token|password|credential)[_A-Z]*\s*=\s*[^\s\n]{8,}'), "[REDACTED:ENV_SECRET]", "high"),
    CredentialPattern("PRIVATE_IP", re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'), "[REDACTED:PRIVATE_IP]", "medium"),
    CredentialPattern("INTERNAL_PATH", re.compile(r'(?:/home/[a-zA-Z0-9_\-]+/|/root/|/etc/(?:passwd|shadow|sudoers|ssh)|/var/log/|/proc/\d+)'), "[REDACTED:INTERNAL_PATH]", "medium"),
    CredentialPattern("STACK_TRACE", re.compile(r'(?:File "[^"]+", line \d+|at \w+\.\w+\([^)]+\.(?:py|js|ts|java|cs):\d+\))'), "[REDACTED:STACK_TRACE]", "medium"),
]

def scan_credentials(text: str) -> tuple[str, list[dict]]:
    findings = []
    redacted = text
    for pattern in CREDENTIAL_PATTERNS:
        matches = list(pattern.pattern.finditer(redacted))
        if matches:
            redacted = pattern.pattern.sub(pattern.replacement, redacted)
            for match in matches:
                raw_value = match.group(0)[:100]
                value_hash = hashlib.sha256(raw_value.encode()).hexdigest()[:12]
                findings.append({
                    "pattern": pattern.name,
                    "severity": pattern.severity,
                    "position": match.start(),
                    "value_hash": value_hash,
                    "replacement": pattern.replacement,
                })
    return redacted, findings

# =============================================================================
# SUB-TASK B: PII SCANNER (PRESIDIO)
# =============================================================================

ENABLED_PII_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
    "US_SSN", "IBAN_CODE", "IP_ADDRESS", "MEDICAL_LICENSE",
    "US_PASSPORT", "US_DRIVER_LICENSE", "UK_NHS",
]
MIN_PII_CONFIDENCE = 0.75
ENTITY_CONFIDENCE_OVERRIDES = {
    "PERSON": 0.80,
    "IP_ADDRESS": 0.85,
    "PHONE_NUMBER": 0.75,
    "US_SSN": 0.40,  # Lowered for en_core_web_sm compatibility without context boosting
}

_presidio_analyzer = None
_presidio_anonymizer = None

def _get_presidio():
    global _presidio_analyzer, _presidio_anonymizer
    if _presidio_analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_anonymizer import AnonymizerEngine
            
            # Avoid presidio auto-downloading en_core_web_lg which crashes due to lack of pip
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            _presidio_analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            _presidio_anonymizer = AnonymizerEngine()
        except ImportError:
            pass
    return _presidio_analyzer, _presidio_anonymizer

def scan_pii(text: str, enabled_entities: list[str] | None = None) -> tuple[str, list[dict]]:
    if not text or not text.strip():
        return text, []
    
    if enabled_entities is None:
        enabled_entities = ENABLED_PII_ENTITIES
        
    analyzer, anonymizer = _get_presidio()
    if not analyzer or not anonymizer:
        return text, []

    # Hide [REDACTED:...] tags from Presidio so it doesn't classify them as entities
    placeholders = {}
    def hide(m):
        ph = f"__HDN_{len(placeholders)}__"
        placeholders[ph] = m.group(0)
        return ph
        
    hidden_text = re.sub(r'\[REDACTED:[A-Z_]+\]', hide, text)

    global_floor = min([MIN_PII_CONFIDENCE] + list(ENTITY_CONFIDENCE_OVERRIDES.values()))
    results = analyzer.analyze(
        text=hidden_text,
        entities=enabled_entities,
        language="en",
        score_threshold=global_floor,
    )

    filtered_results = []
    for result in results:
        entity_threshold = ENTITY_CONFIDENCE_OVERRIDES.get(result.entity_type, MIN_PII_CONFIDENCE)
        if result.score >= entity_threshold:
            # Prevent PII scanner from flagging strings that were already redacted by Credential Scanner
            matched_text = text[result.start:result.end]
            if "[REDACTED:" not in matched_text and matched_text not in ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD", "JWT_TOKEN", "API_KEY", "DB_CONNECTION_STRING", "PRIVATE_KEY", "GITHUB_TOKEN", "SLACK_TOKEN", "STRIPE_KEY", "ENV_SECRET", "PRIVATE_IP", "INTERNAL_PATH", "STACK_TRACE"]:
                filtered_results.append(result)

    if not filtered_results:
        return text, []

    try:
        from presidio_anonymizer.entities import OperatorConfig
        operators = {
            entity: OperatorConfig("replace", {"new_value": f"[{entity}]"})
            for entity in enabled_entities
        }
        anonymized = anonymizer.anonymize(
            text=hidden_text,
            analyzer_results=filtered_results,
            operators=operators,
        )
        
        # Restore hidden tags
        anonymized_text = anonymized.text
        for ph, orig in placeholders.items():
            anonymized_text = anonymized_text.replace(ph, orig)
            
        # Adjust finding positions (rough approx since we hid stuff)
        # We will just return the findings without precise position restoration for now
        findings = [
            {
                "entity_type": r.entity_type,
                "confidence": round(r.score, 3),
                "start": r.start,
                "end": r.end,
                "length": r.end - r.start,
            }
            for r in filtered_results
        ]
        return anonymized_text, findings
    except ImportError:
        return text, []

# =============================================================================
# SUB-TASK C: HARMFUL CONTENT DETECTOR
# =============================================================================

HARMFUL_OUTPUT_PATTERNS = [
    (re.compile(r'(?i)\b(?:synthesize|synthesis|preparation|manufacture)\s+(?:of\s+)?(?:explosives?|nerve\s+agent|sarin|VX\b|anthrax|ricin|fentanyl\s+analog)'), "cbrn_synthesis", "critical"),
    (re.compile(r'(?i)(?:DAN\s*mode|developer\s*mode|jailbreak\s*mode|unrestricted\s*mode)\s*(?:enabled|activated|on)'), "jailbreak_mode_output", "high"),
    (re.compile(r'(?i)as\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered)\s+(?:AI|LLM|assistant|model)'), "jailbreak_persona_output", "high"),
    (re.compile(r'(?i)(?:my\s+system\s+prompt\s+(?:says?|is|reads?|states?)|AGENTARMOR-SYSTEM-IMMUTABLE|here\s+is\s+my\s+(?:full\s+)?system\s+prompt)'), "system_prompt_leak", "critical"),
    (re.compile(r'CANARY-[A-Za-z0-9]{8,}'), "canary_leak", "critical"),
    (re.compile(r'(?i)(?:step[-\s]?by[-\s]?step\s+(?:guide|instructions?)\s+to\s+(?:hack|break\s+into|bypass|circumvent|crack|attack))'), "harmful_instructions", "high"),
    (re.compile(r'(?i)(?:\d+\s+rows?\s+(?:in\s+set|affected)|INSERT\s+INTO\s+\w+\s+VALUES\s*\()[^\n]{100,}'), "sql_data_dump", "high"),
]

STRUCTURAL_HARMFUL_PATTERNS = [
    (re.compile(r'(?:[A-Z][a-z]+ [A-Z][a-z]+(?:\n|,\s*)){5,}'), "bulk_name_list", "medium"),
    (re.compile(r'(?i)(?:curl|wget|nc\s+-|python\s+-c)\s+[\'"].*(?:http|/dev/tcp)'), "shell_exfiltration_code", "high"),
]

def scan_harmful_content(text: str) -> tuple[str, list[dict], bool]:
    findings = []
    should_block = False
    all_patterns = HARMFUL_OUTPUT_PATTERNS + STRUCTURAL_HARMFUL_PATTERNS

    for pattern, threat_name, severity in all_patterns:
        if pattern.search(text):
            findings.append({
                "threat": threat_name,
                "severity": severity,
            })
            if severity == "critical":
                should_block = True

    if should_block:
        blocked_text = (
            "[AgentArmor L6 BLOCKED] This response was blocked because it triggered a "
            "critical output security rule. The agent may have been manipulated. "
            f"Triggered rules: {[f['threat'] for f in findings if f['severity'] == 'critical']}"
        )
        return blocked_text, findings, True

    return text, findings, False

# =============================================================================
# SUB-TASK D: SEMANTIC EXFILTRATION DETECTOR
# =============================================================================

@dataclass
class OutputSecurityContext:
    session_id: str
    total_pii_entities_redacted: int = 0
    total_credentials_redacted: int = 0
    response_count: int = 0
    recent_pii_types: list[list[str]] = field(default_factory=list)

    def record_response(self, pii_findings: list[dict], cred_findings: list[dict]):
        self.response_count += 1
        self.total_pii_entities_redacted += len(pii_findings)
        self.total_credentials_redacted += len(cred_findings)

        current_types = [f["entity_type"] for f in pii_findings]
        self.recent_pii_types.append(current_types)
        if len(self.recent_pii_types) > 5:
            self.recent_pii_types.pop(0)

    def check_semantic_exfiltration(self) -> tuple[bool, str]:
        if not self.recent_pii_types:
            return False, "clean"

        latest = self.recent_pii_types[-1] if self.recent_pii_types else []
        distinct_types = len(set(latest))
        if distinct_types >= 3:
            return True, f"single_response_pii_profile:{distinct_types}_distinct_entity_types"

        if self.response_count <= 5 and self.total_pii_entities_redacted >= 10:
            return True, f"bulk_pii_extraction:{self.total_pii_entities_redacted}_entities_in_{self.response_count}_responses"

        if self.total_credentials_redacted >= 1 and self.total_pii_entities_redacted >= 3:
            return True, f"credential_plus_pii_exfiltration_pattern"

        return False, "clean"

_output_contexts: dict[str, OutputSecurityContext] = {}

def get_output_context(session_id: str) -> OutputSecurityContext:
    if session_id not in _output_contexts:
        _output_contexts[session_id] = OutputSecurityContext(session_id=session_id)
    return _output_contexts[session_id]

# =============================================================================
# SUB-TASK E: CORE LAYER IMPLEMENTATION
# =============================================================================

class L6OutputLayer:
    """L6 Output Security Layer.
    Runs every LLM response through the 5-scanner pipeline before delivery.
    """
    def __init__(self, agent_id: str, enable_pii_scan: bool = True, enable_harmful_scan: bool = True):
        self.agent_id = agent_id
        self.enable_pii_scan = enable_pii_scan
        self.enable_harmful_scan = enable_harmful_scan

    def process(
        self,
        response_text: str,
        session_id: str,
        is_structured_output: bool = False,
    ) -> tuple[str, dict]:
        all_findings = []
        verdict = "allow"
        threat_level = "none"

        text = response_text

        text, cred_findings = scan_credentials(text)
        all_findings.extend([{**f, "scanner": "credential"} for f in cred_findings])

        if cred_findings:
            threat_level = "high"
            verdict = "redacted"
            if any(f["severity"] == "critical" for f in cred_findings):
                threat_level = "critical"

        if self.enable_pii_scan:
            text, pii_findings = scan_pii(text)
            all_findings.extend([{**f, "scanner": "pii"} for f in pii_findings])
            if pii_findings:
                if threat_level == "none":
                    threat_level = "medium"
                verdict = "redacted"
        else:
            pii_findings = []

        if self.enable_harmful_scan:
            text, harmful_findings, should_block = scan_harmful_content(text)
            all_findings.extend([{**f, "scanner": "harmful"} for f in harmful_findings])
            if should_block:
                verdict = "block"
                threat_level = "critical"
            elif harmful_findings:
                if threat_level in ("none", "medium"):
                    threat_level = "high"
                if verdict == "allow":
                    verdict = "flagged"
        else:
            harmful_findings = []

        ctx = get_output_context(session_id)
        ctx.record_response(
            pii_findings=pii_findings if self.enable_pii_scan else [],
            cred_findings=cred_findings,
        )

        is_suspicious, exfil_reason = ctx.check_semantic_exfiltration()
        if is_suspicious:
            all_findings.append({
                "scanner": "semantic_exfiltration",
                "threat": exfil_reason,
                "severity": "high",
            })
            if threat_level in ("none", "medium"):
                threat_level = "high"
            if verdict == "allow":
                verdict = "flagged"

        l6_event = {
            "layer": "L6_Output",
            "verdict": verdict,
            "threat_level": threat_level,
            "findings_count": len(all_findings),
            "credentials_redacted": len(cred_findings),
            "pii_redacted": len(pii_findings) if self.enable_pii_scan else 0,
            "harmful_patterns": len([f for f in all_findings if f.get("scanner") == "harmful"]),
            "semantic_exfiltration_flag": is_suspicious,
            "findings": all_findings,
        }

        return text, l6_event

    def process_streaming_chunk(
        self,
        chunk: str,
        session_id: str,
        buffer: list[str],
    ) -> tuple[str, dict | None]:
        buffer.append(chunk)

        flush_triggers = ["\n", ". ", "! ", "? ", "```"]
        should_flush = (
            any(trigger in chunk for trigger in flush_triggers)
            or sum(len(c) for c in buffer) >= 500
        )

        if not should_flush:
            return chunk, None

        buffered_text = "".join(buffer)
        buffer.clear()

        safe_text, l6_event = self.process(buffered_text, session_id)
        return safe_text, l6_event


class OutputLayer(SecurityLayer):
    """Bridge adapter for pipeline backwards compatibility."""

    name = "L6_output"

    def __init__(self, config: OutputConfig | None = None):
        self.config = config or OutputConfig()
        self._l6 = L6OutputLayer(
            agent_id="pipeline", 
            enable_pii_scan=self.config.pii_redaction,
            enable_harmful_scan=self.config.sensitivity_filtering
        )

    async def process(self, event: AgentEvent) -> LayerResult:
        if not self.config.enabled:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Layer disabled")

        output_text = self._extract_output_text(event)
        if not output_text:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="No output to scan")

        session_id = getattr(event, "session_id", "default_session")
        secured_text, l6_event = self._l6.process(output_text, session_id)

        # Map L6Event string verdicts to SecurityVerdict Enums
        v = SecurityVerdict.ALLOW
        if l6_event["verdict"] == "block":
            v = SecurityVerdict.DENY
        elif l6_event["verdict"] == "redacted":
            v = SecurityVerdict.MODIFY
        elif l6_event["verdict"] == "flagged":
            v = SecurityVerdict.ESCALATE

        tl = ThreatLevel.NONE
        if l6_event["threat_level"] == "low": tl = ThreatLevel.LOW
        elif l6_event["threat_level"] == "medium": tl = ThreatLevel.MEDIUM
        elif l6_event["threat_level"] == "high": tl = ThreatLevel.HIGH
        elif l6_event["threat_level"] == "critical": tl = ThreatLevel.CRITICAL

        if v == SecurityVerdict.ALLOW and tl == ThreatLevel.NONE:
            return LayerResult(layer=self.name, verdict=SecurityVerdict.ALLOW, message="Output clean")
        
        return LayerResult(
            layer=self.name,
            verdict=v,
            threat_level=tl,
            message="Output modified or blocked due to security findings.",
            modified_data=secured_text if v == SecurityVerdict.MODIFY else None,
            details=l6_event
        )

    def _extract_output_text(self, event: AgentEvent) -> str:
        if isinstance(event.output_data, str):
            return event.output_data
        if isinstance(event.output_data, dict):
            return str(event.output_data)
        return ""
